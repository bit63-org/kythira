// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The KMS as a service module, number 7 (.kiro/specs/kms-compatible-api/
// task 5, .kiro/specs/service-colocation/): the catalog group on a
// multi_raft host over the node's transport, the backing store on a
// PKCS#11 token, and the leader's key jobs.
//
// Data directory (the node's kms/ in kythira_node):
//   engine/                 the RocksDB database (the catalog)
//   raft/<group>/           the catalog's Raft log
//   snapshots/              checkpoints and incoming snapshot transfers
//
// Backing keys live on the token KYTHIRA_KMS_TOKEN_LABEL names, reached
// either through the co-located virtual HSM's `hsm.pkcs11` interface, as
// the identity KYTHIRA_KMS_PKCS11_IDENTITY (which the HSM's catalog must
// bind to the token: co-location never widens access), or through a
// PKCS#11 library KYTHIRA_KMS_PKCS11 names, an external HSM. The token may
// be missing or the HSM sealed at start and for any time after: the
// module keeps running, reports it in health(), and every pass of the jobs
// tries again. Requests that need the HSM meanwhile fail with
// KMSInternalException (task 6 on).
//
// The API listener, and with it forwarding a follower's proposals to the
// catalog's leader, arrive with the operations (task 6). Until then only
// the leader writes, which the jobs need: kms_host's forwarder is unset.

#include "kms_config.hpp"

#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_group_state_machine.hpp>
#include <kythira/kms/kms_host.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>
#include <raft/metrics.hpp>
#include <raft/module_interfaces.hpp>
#include <raft/module_registry.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/node_core.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/rocksdb_kv_engine.hpp>
#include <raft/service_module.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::kms_node {

using engine_type = kythira::rocksdb_kv_engine;
using group_sm = kythira::kms::kms_group_state_machine<engine_type>;

/// The KMS's multi_raft types on a node whose transport is `Host`'s.
template<typename Host> struct module_host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = kythira::host_node_id;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    /// Not used by the host: the wire is the node's transport's.
    using serializer_type = kythira::json_rpc_serializer<std::vector<std::byte>>;

    using network_client_type =
        kythira::transport_client_handle<typename Host::client_type, node_id_type>;
    using network_server_type = typename Host::view_type;

    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = group_sm;

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

/// Where the backing store stands, for health() and the metrics.
enum class hsm_state : std::uint8_t {
    unknown,      // no pass has run yet
    available,    // the last call reached the token
    no_token,     // the module has no token with the label
    unavailable,  // sealed, unreachable or the PIN refused
};

template<typename Host> class kms_module final : public service_node::service_module<Host> {
public:
    using types = module_host_types<Host>;
    using raft_host = kythira::multi_raft<types, std::string, std::uint64_t>;
    using raft_config = kythira::multi_raft_config<types, std::string, std::uint64_t>;
    using kms_host = kythira::kms::basic_kms_host<raft_host, engine_type>;
    using catalog_type = typename kms_host::catalog_type;
    using jobs_type = kythira::kms::key_jobs<catalog_type>;

    kms_module() = default;
    kms_module(const kms_module&) = delete;
    auto operator=(const kms_module&) -> kms_module& = delete;
    kms_module(kms_module&&) = delete;
    auto operator=(kms_module&&) -> kms_module& = delete;
    ~kms_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "kms"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return service_node::module_numbers::kms;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override { return "KYTHIRA_KMS_"; }
    /// The HSM first, so its `hsm.pkcs11` answers the lookup.
    [[nodiscard]] auto starts_after() const -> std::vector<std::string> override {
        return {"iam", "hsm"};
    }

    [[nodiscard]] auto configure(const service_node::env_lookup& env)
        -> std::optional<std::string> override {
        try {
            _opt = from_env(composite_env(service_node::module_tuning(env, "KYTHIRA_KMS_")));
            if (_opt.pkcs11 == co_located_hsm && !service_node::co_located(env, "hsm")) {
                return std::string(
                    "KYTHIRA_KMS_PKCS11=hsm needs the HSM co-located (KYTHIRA_SERVICES naming "
                    "hsm); set it to a PKCS#11 library's path to use another HSM");
            }
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        return std::nullopt;
    }

    void register_groups(Host& host, const service_node::group_space& space) override {
        for (const auto* sub : {"engine", "raft", "snapshots"}) {
            std::filesystem::create_directories(_opt.data_dir / sub);
        }
        _ctx = kms_host::make_context();
        _raft = std::make_unique<raft_host>(make_raft_config(host, space));
        typename kms_host::options hopts;
        for (const auto& [id, url] : _opt.api_urls) {
            hopts.members.push_back(id);
        }
        hopts.group = space.to_host(0);
        hopts.propose_timeout = _opt.propose_timeout;
        _host = std::make_unique<kms_host>(*_raft, _ctx, hopts);
        _host->bootstrap();
    }

    void publish(service_node::module_registry& /*registry*/) override {
        // kms.client arrives with the published client (task 12).
    }

    void start(service_node::module_registry& registry) override {
        if (_opt.pkcs11 == co_located_hsm) {
            auto provider = registry.lookup<service_node::pkcs11_provider>(
                std::string(service_node::interface_names::hsm_pkcs11));
            if (!provider) {
                throw std::invalid_argument(
                    "KYTHIRA_KMS_PKCS11=hsm: the HSM module publishes no hsm.pkcs11");
            }
            _backend = provider->backend_for(_opt.pkcs11_identity);
        } else {
            _backend = std::make_shared<kythira::pkcs11::function_list_backend>(_opt.pkcs11);
        }
        _raft->start();
        _driving = true;
        _driver = std::thread([this] {
            while (_driving.load(std::memory_order_acquire)) {
                try {
                    (void)_raft->tick();
                } catch (const std::exception& e) {
                    log(kythira::log_level::error, std::string("kms: tick failed: ") + e.what());
                }
                std::this_thread::sleep_for(_opt.tick_interval);
            }
        });
        _jobs_thread = std::thread([this] { jobs_loop(); });
        _started = true;
        std::cout << "kms " << kythira::host_node_id_text(_opt.node_id)
                  << " ready: members=" << _opt.api_urls.size() << " pkcs11="
                  << (_opt.pkcs11 == co_located_hsm ? std::string("hsm (co-located)") : _opt.pkcs11)
                  << " token=" << _opt.token_label << std::endl;
    }

    void drain() override {}

    void stop() override {
        {
            const std::scoped_lock lock(_jobs_mutex);
            _driving.store(false, std::memory_order_release);
        }
        _jobs_wake.notify_all();
        if (_jobs_thread.joinable()) {
            _jobs_thread.join();
        }
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        _jobs.reset();
        _catalog.reset();
        _store.reset();
        _backend.reset();
        _host.reset();
        _raft.reset();
        _started = false;
    }

    [[nodiscard]] auto health() const -> service_node::module_health override {
        if (!_started) {
            return {false, "not started"};
        }
        // A KMS whose HSM is sealed is up and waiting for the HSM's
        // operators, as a sealed HSM is: healthy, with the reason.
        switch (_hsm.load()) {
            case hsm_state::no_token:
                return {true, "no token '" + _opt.token_label + "' on the PKCS#11 module"};
            case hsm_state::unavailable:
                return {true, "hsm unavailable"};
            default:
                return {true, ""};
        }
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> override {
        if (!_host || !_raft) {
            return {};
        }
        const auto s = _host->stats();
        const std::scoped_lock lock(_report_mutex);
        return {
            {"leader", _host->leads() ? 1.0 : 0.0, {}},
            {"hsm_available", _hsm.load() == hsm_state::available ? 1.0 : 0.0, {}},
            {"job_passes", static_cast<double>(_passes), {}},
            {"keys_completed", static_cast<double>(_total.completed), {}},
            {"keys_abandoned", static_cast<double>(_total.abandoned), {}},
            {"keys_rotated", static_cast<double>(_total.rotated), {}},
            {"keys_deleted", static_cast<double>(_total.deleted), {}},
            {"orphans_destroyed", static_cast<double>(_total.orphans_destroyed), {}},
            {"job_failures", static_cast<double>(_total.failures), {}},
            {"proposals_forwarded", static_cast<double>(s.proposals_forwarded), {}},
            {"proposals_served", static_cast<double>(s.proposals_served), {}},
            {"split_merge_vetoes", static_cast<double>(s.split_merge_vetoes), {}},
            {"raft_term_sum", service_node::raft_term_sum(*_raft), {}},
        };
    }

private:
    auto make_raft_config(Host& host, const service_node::group_space& space) -> raft_config {
        const auto raft_dir = _opt.data_dir / "raft";
        raft_config cfg{
            .node_id = _opt.node_id,
            .network_client = typename types::network_client_type{host.client()},
            .network_server = host.server_for(space),
            .store_factory =
                [raft_dir](const std::uint64_t& group) {
                    return
                        typename types::persistence_engine_type{raft_dir / std::to_string(group)};
                },
        };
        cfg.state_engine = std::make_shared<engine_type>(_opt.data_dir / "engine");
        cfg.state_machine_factory = [ctx = _ctx](const std::uint64_t&) { return group_sm(ctx); };
        cfg.automatic_split_merge_enabled = false;  // the catalog never moves
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.logger = kythira::console_logger{_opt.log_level};
        cfg.logger_factory = [level = _opt.log_level](const std::uint64_t&) {
            return kythira::console_logger{level};
        };
        cfg.config._election_timeout_min = _opt.election_timeout_min;
        cfg.config._election_timeout_max = _opt.election_timeout_max;
        cfg.config._heartbeat_interval = _opt.heartbeat_interval;
        cfg.config._rpc_timeout = _opt.rpc_timeout;
        cfg.config._snapshot_staging_directory = _opt.data_dir / "snapshots";
        return cfg;
    }

    /// One pass every job_interval, on the leader only, once its replica
    /// has applied everything committed (a new leader may lag).
    void jobs_loop() {
        std::unique_lock lock(_jobs_mutex);
        while (_driving.load(std::memory_order_acquire)) {
            lock.unlock();
            try {
                run_jobs_once();
            } catch (const std::exception& e) {
                log(kythira::log_level::error, std::string("kms: jobs: ") + e.what());
            }
            lock.lock();
            _jobs_wake.wait_for(lock, _opt.job_interval,
                                [this] { return !_driving.load(std::memory_order_acquire); });
        }
    }

    void run_jobs_once() {
        if (!_host->leads() || !_host->barrier()) {
            return;
        }
        if (!bind_token()) {
            return;
        }
        if (!_jobs) {
            _catalog = _host->catalog();
            if (!_catalog) {
                return;
            }
            _jobs = std::make_unique<jobs_type>(
                *_catalog, *_store,
                [this](const std::vector<std::byte>& c) { return _host->propose(c); },
                [] {
                    return static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                },
                _opt.grace);
        }
        const auto r = _jobs->run_once();
        // A pass with failures and nothing done is most likely the HSM;
        // the next pass, or a call that reaches the token, says otherwise.
        set_hsm(r.failures > 0 &&
                        r.completed + r.abandoned + r.rotated + r.deleted + r.orphans_destroyed == 0
                    ? probe()
                    : hsm_state::available);
        const std::scoped_lock lock(_report_mutex);
        ++_passes;
        _total.completed += r.completed;
        _total.abandoned += r.abandoned;
        _total.rotated += r.rotated;
        _total.deleted += r.deleted;
        _total.orphans_destroyed += r.orphans_destroyed;
        _total.failures += r.failures;
    }

    /// Finds the token by label and logs in, once; true when the store is
    /// ready.
    auto bind_token() -> bool {
        if (_store) {
            return true;
        }
        std::optional<CK_SLOT_ID> slot;
        try {
            for (const auto& t : _backend->tokens()) {
                if (t.label == _opt.token_label) {
                    slot = t.slot;
                    break;
                }
            }
        } catch (const std::exception& e) {
            set_hsm(hsm_state::unavailable, e.what());
            return false;
        }
        if (!slot) {
            set_hsm(hsm_state::no_token);
            return false;
        }
        _store =
            std::make_unique<kythira::kms::backing_store>(_backend, *slot, read_pin(_opt.pin_file));
        return true;
    }

    /// Whether the token answers now.
    auto probe() -> hsm_state {
        try {
            (void)_store->list();
            return hsm_state::available;
        } catch (const kythira::kms::backing_error& e) {
            return e.which() == kythira::kms::backing_error::kind::unavailable
                       ? hsm_state::unavailable
                       : hsm_state::available;
        }
    }

    void set_hsm(hsm_state s, const std::string& why = {}) {
        const auto was = _hsm.exchange(s);
        if (was == s) {
            return;
        }
        switch (s) {
            case hsm_state::available:
                log(kythira::log_level::info, "kms: the backing token answers");
                break;
            case hsm_state::no_token:
                log(kythira::log_level::warning,
                    "kms: no token '" + _opt.token_label + "' on the PKCS#11 module yet");
                break;
            case hsm_state::unavailable:
                log(kythira::log_level::warning,
                    "kms: the HSM is sealed or unreachable" + (why.empty() ? "" : ": " + why));
                break;
            default:
                break;
        }
    }

    auto log(kythira::log_level level, const std::string& message) const -> void {
        kythira::console_logger logger(_opt.log_level);
        logger.log(level, message, {});
    }

    kms_options _opt;
    std::shared_ptr<typename group_sm::context> _ctx;
    std::unique_ptr<raft_host> _raft;
    std::unique_ptr<kms_host> _host;
    std::shared_ptr<kythira::pkcs11::backend> _backend;
    // The jobs thread's own: the store, the catalog replica the jobs read
    // and the jobs (which remember orphans between passes).
    std::unique_ptr<kythira::kms::backing_store> _store;
    std::shared_ptr<const catalog_type> _catalog;
    std::unique_ptr<jobs_type> _jobs;
    std::atomic<hsm_state> _hsm{hsm_state::unknown};
    mutable std::mutex _report_mutex;
    std::uint64_t _passes = 0;
    kythira::kms::job_report _total;
    std::atomic<bool> _driving{false};
    std::thread _driver;
    std::mutex _jobs_mutex;
    std::condition_variable _jobs_wake;
    std::thread _jobs_thread;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::kms_node
