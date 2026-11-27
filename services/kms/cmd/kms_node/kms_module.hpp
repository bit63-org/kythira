// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The KMS as a service module, number 7 (.kiro/specs/kms-compatible-api/
// tasks 5 and 12, .kiro/specs/service-colocation/): the catalog group on a
// multi_raft host over the node's transport, the backing store on a
// PKCS#11 token, the leader's key jobs, and the KMS API on its own
// listener.
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
// The listener (KYTHIRA_KMS_API_LISTEN, default 8443, TLS) serves AWS's
// KMS JSON 1.1 API at POST / to any client, signed with SigV4 and
// authorized by the co-located IAM module (KYTHIRA_KMS_AUTH=iam), static
// keys (static) or both, and the members' forwarding routes
// (kms_peer.hpp) to verified member certificates only. A member that does
// not lead forwards writes and read barriers to the leader there, so any
// member answers any request.
//
// Layers (.kiro/specs/kms-independent-layers/). KYTHIRA_KMS_ROLES picks
// which of gateway, front end and data this node runs, all three by
// default. A data node holds the catalog and serves it to front ends
// (kms_catalog_api.hpp); a front end without data reads it from them. A
// gateway without its own front end verifies SigV4 and hands each call to
// a front end KYTHIRA_KMS_FRONT_END_URLS lists, on its
// /v1/kms/front-end/call route (kms_front_end_api.hpp). Front ends that
// list each other ask each other's health and share the quotas over the
// live ones. Callers of the internal routes are held to their layer
// identity's roles, or trusted as every layer when listed in
// KYTHIRA_KMS_PEER_IDENTITIES (kms_peer.hpp).

#include "kms_config.hpp"

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog_access.hpp>
#include <kythira/kms/kms_catalog_api.hpp>
#include <kythira/kms/kms_crypto_api.hpp>
#include <kythira/kms/kms_audit.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_front_end_api.hpp>
#include <kythira/kms/kms_grants_api.hpp>
#include <kythira/kms/kms_group_state_machine.hpp>
#include <kythira/kms/kms_host.hpp>
#include <kythira/kms/kms_in_process.hpp>
#include <kythira/kms/kms_keys.hpp>
#include <kythira/kms/kms_peer.hpp>
#include <kythira/kms/kms_signing_api.hpp>

#include <raft/raft_log_kms.hpp>
#include <raft/beast_https_server.hpp>
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
#include <raft/static_keys_file.hpp>
#include <raft/static_or_iam_authorizer.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
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
    using replica_type = typename kms_host::catalog_type;
    /// Handlers and jobs see the catalog only through this
    /// (kms_catalog_access.hpp), whatever the node's layout.
    using catalog_type = kythira::kms::kms_catalog_reader;
    using access_type = kythira::kms::local_catalog_access<replica_type>;
    using role = kythira::layers::role;
    using jobs_type = kythira::kms::key_jobs<catalog_type>;
    using authorizer_type = kythira::aws_auth::static_or_iam_authorizer;
    using front_end_type = kythira::kms::front_end<authorizer_type>;
    using client_type = kythira::kms::in_process_client<front_end_type>;

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
            _peer_policy.identities = _opt.peer_identities;
            _peer_policy.allow_plaintext = _opt.insecure_plaintext;
            _peer_policy.cluster = _opt.cluster;
            if (!runs(role::front_end) && !runs(role::gateway)) {
                return std::nullopt;  // a data node: no authorizer, no HSM client
            }
            if (runs(role::front_end) && _opt.pkcs11 == co_located_hsm &&
                !service_node::co_located(env, "hsm")) {
                return std::string(
                    "KYTHIRA_KMS_PKCS11=hsm needs the HSM co-located (KYTHIRA_SERVICES naming "
                    "hsm); set it to a PKCS#11 library's path to use another HSM");
            }
            if (_opt.auth != kythira::aws_auth::auth_mode::static_keys &&
                !service_node::co_located(env, "iam")) {
                return std::string(
                    "KYTHIRA_KMS_AUTH=iam or both needs the IAM module co-located "
                    "(KYTHIRA_SERVICES naming iam); kms_node runs it");
            }
            _authorizer = std::make_unique<authorizer_type>(
                _opt.static_keys_file.empty()
                    ? std::vector<kythira::aws_auth::static_key>{}
                    : kythira::aws_auth::parse_static_keys(read_file(_opt.static_keys_file)),
                _opt.partition);
            _authorizer->register_service(kythira::kms::kms_static_roles());
            if (_opt.auth == kythira::aws_auth::auth_mode::static_keys) {
                _authorizer->set_mode(_opt.auth, std::nullopt);
            }
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        return std::nullopt;
    }

    void register_groups(Host& host, const service_node::group_space& space) override {
        if (runs(role::data)) {
            open_catalog(host, space);
            _access = _local.get();
        } else if (runs(role::front_end)) {
            open_remote_catalog();
            _access = _remote.get();
        }
        if (runs(role::front_end)) {
            _handler_access = std::make_unique<kythira::kms::bounded_staleness_access>(
                *_access, _opt.bounded_staleness);
            build_api();
        } else if (runs(role::gateway)) {
            build_gateway();
        }
        open_front_end_directory();
    }

    /// kms.client: co-located consumers' calls for their callers, through
    /// the same front end as the listener (kms_in_process.hpp). Front ends
    /// only (Requirement 8.1).
    void publish(service_node::module_registry& registry) override {
        if (_client) {
            registry.publish<service_node::kms_endpoint>(
                std::string(service_node::interface_names::kms_client), _client);
        }
    }

    void start(service_node::module_registry& registry) override {
        if (runs(role::front_end) || runs(role::gateway)) {
            bind_authorizer(registry);
        }
        if (runs(role::front_end)) {
            bind_hsm(registry);
        }
        _driving = true;
        if (_raft) {
            _raft->start();
            _driver = std::thread([this] {
                while (_driving.load(std::memory_order_acquire)) {
                    try {
                        (void)_raft->tick();
                    } catch (const std::exception& e) {
                        log(kythira::log_level::error,
                            std::string("kms: tick failed: ") + e.what());
                    }
                    std::this_thread::sleep_for(_opt.tick_interval);
                }
            });
        }
        if (runs(role::front_end)) {
            _jobs_running = true;
            _jobs_thread = std::thread([this] { jobs_loop(); });
        }
        if (_directory) {
            _probing = true;
            _probe_thread = std::thread([this] { probe_loop(); });
        }

        https::server_config hc;
        hc.bind_address = _opt.api_bind;
        hc.port = _opt.api_port;
        hc.tls_cert_path = _opt.tls_cert;
        hc.tls_key_path = _opt.tls_key;
        hc.client_ca_path = _opt.client_ca;  // asked for, never required
        hc.insecure_plaintext = _opt.insecure_plaintext;
        hc.max_body_bytes = _opt.max_body_bytes;
        hc.max_connections = static_cast<std::size_t>(_opt.max_connections);
        _server = std::make_unique<https::server>(
            hc,
            [this](const https::request& req, const https::request_context& ctx) {
                return handle(req, ctx);
            },
            [this](bool warning, std::string_view message) {
                log(warning ? kythira::log_level::warning : kythira::log_level::info,
                    "kms: listener: " + std::string(message));
            });
        _server->start();
        _started = true;
        std::cout << "kms " << kythira::host_node_id_text(_opt.node_id)
                  << " ready: roles=" << _opt.roles.to_string()
                  << (runs(role::data) ? " members=" : " data_nodes=") << _opt.api_urls.size();
        if (!_opt.front_end_urls.empty()) {
            std::cout << " front_ends=" << _opt.front_end_urls.size();
        }
        std::cout << " api=" << _server->port()
                  << (_opt.insecure_plaintext ? " (http)" : " (https)");
        if (runs(role::front_end)) {
            std::cout << " auth=" << auth_name(_opt.auth) << " pkcs11="
                      << (_opt.pkcs11 == co_located_hsm ? std::string("hsm (co-located)")
                                                        : _opt.pkcs11)
                      << " token=" << _opt.token_label;
        }
        std::cout << std::endl;
    }

    /// No request in flight once the listener has stopped. Calls a gateway
    /// hands this front end meanwhile answer "not executed", so the
    /// gateway takes them elsewhere (Requirement 10.1).
    void drain() override {
        _draining.store(true, std::memory_order_release);
        if (_server) {
            _server->stop();
        }
    }

    void stop() override {
        drain();
        {
            const std::scoped_lock lock(_jobs_mutex);
            _jobs_running.store(false, std::memory_order_release);
        }
        _jobs_wake.notify_all();
        if (_jobs_thread.joinable()) {
            _jobs_thread.join();
        }
        {
            const std::scoped_lock lock(_probe_mutex);
            _probing.store(false, std::memory_order_release);
        }
        _probe_wake.notify_all();
        if (_probe_thread.joinable()) {
            _probe_thread.join();
        }
        // While Raft still ticks: a proposal's commit timeout is checked on
        // the tick, so with the driver stopped a release that cannot
        // commit (the last member stopping) would wait forever.
        release_lease();
        _driving.store(false, std::memory_order_release);
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        // Everything that refers to the host goes before it.
        _server.reset();
        _link.reset();
        _directory.reset();
        _front_end_client.reset();
        if (_client) {
            _client->close();  // consumers stopped first; any late call answers 503
        }
        _signing.reset();
        _crypto.reset();
        _grants.reset();
        _api.reset();
        _front_end.reset();
        _audit.reset();  // writes what is queued
        _jobs.reset();
        _catalog.reset();
        {
            const std::scoped_lock lock(_store_mutex);
            _store.reset();
        }
        _backend.reset();
        _catalog_server = {};
        _handler_access.reset();
        _access = nullptr;
        _remote.reset();
        _catalog_client.reset();
        _local.reset();
        _host.reset();
        _raft.reset();
        _started = false;
    }

    /// The API's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _server ? _server->port() : 0; }

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
        if (!_started) {
            return {};
        }
        auto out = _audit ? _audit->metrics() : std::vector<service_node::module_metric>{};
        if (_quotas) {
            const auto q = _quotas->metrics();
            out.insert(out.end(), q.begin(), q.end());
        }
        std::vector<service_node::module_metric> mine{
            {"requests", static_cast<double>(_requests.load()), {}},
            {"peer_requests", static_cast<double>(_peer_requests.load()), {}},
        };
        if (_host && _raft) {  // data
            const auto s = _host->stats();
            const std::vector<service_node::module_metric> data{
                {"leader", _host->leads() ? 1.0 : 0.0, {}},
                {"proposals_forwarded", static_cast<double>(s.proposals_forwarded), {}},
                {"proposals_served", static_cast<double>(s.proposals_served), {}},
                {"split_merge_vetoes", static_cast<double>(s.split_merge_vetoes), {}},
                {"raft_term_sum", service_node::raft_term_sum(*_raft), {}},
            };
            mine.insert(mine.end(), data.begin(), data.end());
        }
        if (runs(role::front_end)) {
            const std::scoped_lock lock(_report_mutex);
            const std::vector<service_node::module_metric> front_end{
                {"job_lease_holder", _lease_token.load() != 0 ? 1.0 : 0.0, {}},
                {"hsm_available", _hsm.load() == hsm_state::available ? 1.0 : 0.0, {}},
                {"job_passes", static_cast<double>(_passes), {}},
                {"keys_completed", static_cast<double>(_total.completed), {}},
                {"keys_abandoned", static_cast<double>(_total.abandoned), {}},
                {"keys_rotated", static_cast<double>(_total.rotated), {}},
                {"keys_deleted", static_cast<double>(_total.deleted), {}},
                {"orphans_destroyed", static_cast<double>(_total.orphans_destroyed), {}},
                {"job_failures", static_cast<double>(_total.failures), {}},
            };
            mine.insert(mine.end(), front_end.begin(), front_end.end());
        }
        if (_directory) {
            mine.push_back({"front_ends_live", static_cast<double>(_directory->live_count()), {}});
        }
        if (_link) {  // a gateway without its own front end
            const auto c = _link->counters();
            const std::vector<service_node::module_metric> gateway{
                {"calls_handed_over", static_cast<double>(c.handed_over), {}},
                {"calls_not_executed", static_cast<double>(c.not_executed), {}},
                {"calls_outcome_unknown", static_cast<double>(c.outcome_unknown), {}},
                {"calls_without_front_end", static_cast<double>(c.no_front_end), {}},
            };
            mine.insert(mine.end(), gateway.begin(), gateway.end());
        }
        if (_quotas) {
            mine.push_back({"quota_share_members", static_cast<double>(_quotas->members()), {}});
        }
        out.insert(out.end(), mine.begin(), mine.end());
        return out;
    }

private:
    [[nodiscard]] auto runs(role r) const -> bool { return _opt.roles.has(r); }

    /// The client settings for calls to other nodes' listeners: the
    /// listener's own certificate, presented as a client.
    [[nodiscard]] auto node_client_config() const -> kythira::mtls::client_config {
        kythira::mtls::client_config pc;
        pc.cert_path = _opt.tls_cert;
        pc.key_path = _opt.tls_key;
        pc.ca_path = _opt.client_ca;
        pc.plaintext = _opt.insecure_plaintext;
        // A forwarded proposal waits for its commit.
        pc.timeout = _opt.propose_timeout + std::chrono::seconds(2);
        return pc;
    }

    /// The data role: this node's catalog replica and vote.
    void open_catalog(Host& host, const service_node::group_space& space) {
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
        if (_opt.api_urls.size() > 1) {
            _peers = std::make_shared<const kythira::kms::peer_client>(node_client_config());
            hopts.forward.propose = [this](const kythira::host_node_id& leader,
                                           const std::vector<std::byte>& cmd) {
                return from_peer(_peers->propose(url_of(leader), cmd));
            };
            hopts.forward.read_index = [this](const kythira::host_node_id& leader) {
                return from_peer(_peers->read_index(url_of(leader)));
            };
        }
        _host = std::make_unique<kms_host>(*_raft, _ctx, hopts);
        _host->bootstrap();
        _local = std::make_unique<access_type>(access_type::over_host(*_host));
        _catalog_server = kythira::kms::catalog_server_over(*_host, *_local);
    }

    /// A front end without the data role: the catalog through the data
    /// nodes' catalog API, nothing on disk.
    void open_remote_catalog() {
        std::vector<std::string> urls;
        urls.reserve(_opt.api_urls.size());
        for (const auto& [id, url] : _opt.api_urls) {
            urls.push_back(url);
        }
        _catalog_client = std::make_shared<const kythira::mtls::client>(node_client_config());
        _remote = std::make_unique<kythira::kms::remote_catalog_access>(
            std::move(urls), [client = _catalog_client](std::string_view base_url,
                                                        std::string_view target, std::string body) {
                return client->request("POST", base_url, std::string(target), std::move(body),
                                       "application/octet-stream", "kythira-kms-front-end");
            });
    }

    /// IAM's evaluator, which a gateway needs for SigV4 and a front end
    /// for authorization too.
    void bind_authorizer(service_node::module_registry& registry) {
        if (_opt.auth != kythira::aws_auth::auth_mode::static_keys) {
            // IAM starts first (starts_after), so its evaluator answers
            // before the listener opens.
            _iam = registry.lookup<service_node::iam_evaluator>(
                std::string(service_node::interface_names::iam_evaluator));
            if (!_iam) {
                throw std::invalid_argument(
                    "KYTHIRA_KMS_AUTH=iam or both: the IAM module publishes no evaluator");
            }
            _iam->add_actions(kythira::kms::kms_actions());
            _authorizer->set_mode(_opt.auth, _iam->hooks());
            if (const auto clash = _authorizer->conflicting_keys(); !clash.empty()) {
                throw std::invalid_argument(
                    "KYTHIRA_KMS_AUTH=both: IAM also has the static access key " + clash.front());
            }
        }
    }

    /// The front end's PKCS#11 backend. Nothing else in the node holds an
    /// HSM client (Requirement 2.3).
    void bind_hsm(service_node::module_registry& registry) {
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
    }

    [[nodiscard]] static auto auth_name(kythira::aws_auth::auth_mode m) -> std::string_view {
        switch (m) {
            case kythira::aws_auth::auth_mode::static_keys:
                return "static";
            case kythira::aws_auth::auth_mode::iam:
                return "iam";
            case kythira::aws_auth::auth_mode::both:
                return "both";
        }
        return "";
    }

    [[nodiscard]] static auto read_file(const std::filesystem::path& path) -> std::string {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::invalid_argument("kms: cannot read KYTHIRA_KMS_STATIC_KEYS_FILE " +
                                        path.string());
        }
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    [[nodiscard]] auto url_of(const kythira::host_node_id& id) const -> std::string {
        const auto it = _opt.api_urls.find(id);
        return it == _opt.api_urls.end() ? std::string() : it->second;
    }

    /// A member's reply with the leader's id parsed back (an unknown id
    /// reads as no hint).
    [[nodiscard]] static auto from_peer(const kythira::kms::forward_reply<std::string>& r) ->
        typename kms_host::reply_type {
        return kythira::kms::from_wire<kythira::host_node_id>(
            r, [](const std::string& text) -> std::optional<kythira::host_node_id> {
                auto id = kythira::parse_host_peer_node_id(text);
                if (!id) {
                    return std::nullopt;
                }
                return std::move(id).value();
            });
    }

    [[nodiscard]] static auto now_ms() -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

    /// The backing store the API shares with the jobs, bound on first use
    /// (the token may appear after start); null while the HSM has no token
    /// or refuses.
    [[nodiscard]] auto store() -> std::shared_ptr<kythira::kms::backing_store> {
        const std::scoped_lock lock(_store_mutex);
        if (!_store) {
            (void)bind_token_locked();
        }
        return _store;
    }

    /// A gateway without its own front end: a front end with no handlers
    /// that only frames and verifies (front_end::authenticate), its audit
    /// for the requests it refuses, and the link to the front ends.
    void build_gateway() {
        kythira::kms::front_end_config fc;
        fc.region = _opt.region;
        fc.partition = _opt.partition;
        fc.limits.max_body_bytes = static_cast<std::size_t>(_opt.max_body_bytes);
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        _audit = std::make_unique<kythira::kms::request_audit>(_opt.audit, _opt.region);
        _front_end->set_observer(
            [audit = _audit.get()](const kythira::kms::request_record& r) { audit->record(r); });
    }

    /// The front ends this node hands calls to or shares the quotas with,
    /// when KYTHIRA_KMS_FRONT_END_URLS lists them.
    void open_front_end_directory() {
        if (_opt.front_end_urls.empty() || (!runs(role::front_end) && !runs(role::gateway))) {
            return;
        }
        std::vector<kythira::kms::front_end_endpoint> others;
        for (const auto& [id, url] : _opt.front_end_urls) {
            if (id != _opt.node_id) {
                others.push_back({kythira::host_node_id_text(id), url});
            }
        }
        _directory = std::make_unique<kythira::kms::front_end_directory>(
            std::move(others), runs(role::front_end), 3 * _opt.front_end_probe);
        auto pc = node_client_config();
        // A call runs catalog reads and proposals and HSM operations.
        pc.timeout = 2 * _opt.propose_timeout + std::chrono::seconds(2);
        _front_end_client = std::make_shared<const kythira::mtls::client>(pc);
        if (runs(role::gateway) && !runs(role::front_end)) {
            _link = std::make_unique<kythira::kms::front_end_link>(
                *_directory,
                [client = _front_end_client](std::string_view base_url, std::string_view target,
                                             std::string body) {
                    auto a = client->attempt_request("POST", base_url, std::string(target),
                                                     std::move(body), "application/octet-stream",
                                                     "kythira-kms-gateway");
                    return kythira::kms::front_end_attempt{std::move(a.answer), a.may_have_arrived};
                });
        }
    }

    /// Asks each listed front end's health every probe interval, and
    /// shares the quotas over the live ones (Requirement 7.2).
    void probe_loop() {
        auto pc = node_client_config();
        pc.timeout =
            std::min<std::chrono::milliseconds>(_opt.front_end_probe * 2, std::chrono::seconds(5));
        const kythira::mtls::client probe(pc);
        std::unique_lock lock(_probe_mutex);
        while (_probing.load(std::memory_order_acquire)) {
            lock.unlock();
            _directory->probe([&probe](std::string_view url) {
                const auto r = probe.request(
                    "POST", url, std::string(kythira::kms::front_end_api::k_health_path), {},
                    "application/octet-stream", "kythira-kms-probe");
                return r && r->first == kythira::kms::front_end_api::k_ok;
            });
            if (_quotas) {
                _quotas->set_members(_directory->live_count());
            }
            lock.lock();
            _probe_wake.wait_for(lock, _opt.front_end_probe,
                                 [this] { return !_probing.load(std::memory_order_acquire); });
        }
    }

    void build_api() {
        kythira::kms::front_end_config fc;
        fc.region = _opt.region;
        fc.partition = _opt.partition;
        fc.limits.max_body_bytes = static_cast<std::size_t>(_opt.max_body_bytes);
        // Requirement 7.7: on static keys the static roles decide alone.
        fc.evaluate_grants = _opt.auth != kythira::aws_auth::auth_mode::static_keys;
        // ...except for a consumer's own calls as an account's root, which
        // no role names (a co-located DynamoDB opening table keys).
        fc.admit_consumer_root = _opt.auth == kythira::aws_auth::auth_mode::static_keys;
        fc.trusted_services.insert(_opt.trusted_services.begin(), _opt.trusted_services.end());
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        _audit = std::make_unique<kythira::kms::request_audit>(_opt.audit, _opt.region);
        if (_opt.throttling) {
            auto q = _opt.quotas;
            // Each front end's share of the quotas (Requirement 7): over
            // the live front ends when they are listed (the probe loop
            // keeps it current, starting from all of them), else over the
            // catalog members, every one a front end when co-located.
            q.members = std::max<std::size_t>(
                _opt.front_end_urls.empty() ? _opt.api_urls.size() : _opt.front_end_urls.size(), 1);
            _quotas = std::make_shared<kythira::kms::request_quotas>(std::move(q));
            _front_end->set_quotas(_quotas);
        }
        _front_end->set_observer(
            [audit = _audit.get()](const kythira::kms::request_record& r) { audit->record(r); });
        _client = std::make_shared<client_type>(*_front_end);
        const auto propose = [this](const std::vector<std::byte>& c) {
            return _handler_access->propose(c);
        };
        kythira::kms::api_deps<catalog_type> deps{
            .create_key = [this, propose](
                              kythira::kms::key_record k,
                              const kythira::kms::tag_map& tags) -> kythira::kms::key_result {
                auto c = _handler_access->reader();
                auto hsm = store();
                if (!c || !hsm) {
                    return {kythira::kms::key_outcome::unavailable,
                            kythira::kms::catalog_status::ok};
                }
                jobs_type jobs(*c, *hsm, propose, now_ms, _opt.grace);
                return jobs.create_key(std::move(k), tags);
            },
            .clock_ms = now_ms,
            .new_key_id = kythira::kms::random_key_id,
            .rotate = [this, propose](std::string_view id,
                                      kythira::kms::rotation_type t) -> kythira::kms::key_result {
                auto c = _handler_access->reader();
                auto hsm = store();
                if (!c || !hsm) {
                    return {kythira::kms::key_outcome::unavailable,
                            kythira::kms::catalog_status::ok};
                }
                jobs_type jobs(*c, *hsm, propose, now_ms, _opt.grace);
                return jobs.rotate(id, t);
            },
            .ensure_managed = {},
        };
        kythira::kms::fill_catalog_deps(deps, *_handler_access);
        // AWS managed keys on first use (kms_managed.hpp), through the same
        // CreateKey steps.
        kythira::kms::managed_deps<catalog_type> mdeps{
            .create_key = deps.create_key,
            .clock_ms = now_ms,
            .partition = _opt.partition,
            .region = _opt.region,
        };
        kythira::kms::fill_catalog_deps(mdeps, *_handler_access);
        deps.ensure_managed = [mdeps](std::string_view account,
                                      const kythira::kms::managed_service& s) {
            return kythira::kms::ensure_managed_key(mdeps, account, s);
        };
        // Consuming services' owned keys, likewise (Requirement 10.3).
        deps.ensure_owned = [mdeps](std::string_view account,
                                    const kythira::kms::managed_service& s) {
            return kythira::kms::ensure_owned_key(mdeps, account, s);
        };
        _api = std::make_unique<kythira::kms::key_management_api<catalog_type>>(deps);
        _grants = std::make_unique<kythira::kms::grants_api<catalog_type>>(deps);
        kythira::kms::crypto_deps<catalog_type> cdeps{
            .hsm = [this] { return store(); },
            .ensure_managed = deps.ensure_managed,
            .ensure_owned = deps.ensure_owned,
        };
        kythira::kms::fill_catalog_deps(cdeps, *_handler_access);
        _crypto = std::make_unique<kythira::kms::crypto_api<catalog_type>>(cdeps);
        _signing = std::make_unique<kythira::kms::signing_api<catalog_type>>(cdeps);
        _api->register_on(*_front_end);
        _grants->register_on(*_front_end);
        _crypto->register_on(*_front_end);
        _signing->register_on(*_front_end);
    }

    /// One request on the listener: a member's forwarding route, or the
    /// KMS API.
    auto handle(const https::request& req, const https::request_context& ctx) -> https::response {
        namespace http = boost::beast::http;
        https::response res;
        res.version(req.version());
        res.keep_alive(req.keep_alive());
        const std::string_view target(req.target().data(), req.target().size());
        if (!_host &&
            (kythira::kms::is_catalog_path(target) || kythira::kms::is_peer_path(target))) {
            return refuse(res, http::status::not_found, "this node runs no KMS data layer");
        }
        if (kythira::kms::is_catalog_path(target)) {
            // The data layer's catalog API (kms-independent-layers task 3)
            // for front ends without a replica: front ends and data nodes
            // only (Requirement 9.2).
            ++_peer_requests;
            const kythira::kms::peer_caller caller{ctx.tls, ctx.client_verified,
                                                   ctx.client_uri_sans, ctx.client_dns_sans};
            const auto answer = kythira::kms::serve_catalog(
                _catalog_server,
                kythira::kms::admits(_peer_policy, caller, kythira::kms::catalog_route_roles),
                std::string_view(req.method_string()), target, req.body());
            res.result(answer->status);
            res.set(http::field::content_type, "application/octet-stream");
            res.body() = answer->body;
            res.prepare_payload();
            return res;
        }
        if (kythira::kms::is_peer_path(target)) {
            ++_peer_requests;
            const kythira::kms::peer_caller caller{ctx.tls, ctx.client_verified,
                                                   ctx.client_uri_sans, ctx.client_dns_sans};
            const auto answer = kythira::kms::serve_peer(
                *_host, _peer_policy, caller, std::string_view(req.method_string()), target,
                req.body(),
                [](const kythira::host_node_id& id) { return kythira::host_node_id_text(id); });
            res.result(answer->status);
            res.set(http::field::content_type, "application/octet-stream");
            res.body() = answer->body;
            res.prepare_payload();
            return res;
        }
        if (kythira::kms::front_end_api::is_front_end_path(target)) {
            return serve_front_end_api(req, ctx, res, target);
        }
        if (!runs(role::gateway)) {
            return refuse(res, http::status::not_found, "this node runs no KMS gateway");
        }
        ++_requests;
        kythira::kms::front_end_request in;
        in.method = std::string(req.method_string());
        const auto q = target.find('?');
        in.path = std::string(target.substr(0, q));
        in.query = q == std::string_view::npos ? std::string() : std::string(target.substr(q + 1));
        for (const auto& f : req) {
            in.headers.emplace_back(std::string(f.name_string()), std::string(f.value()));
        }
        in.body = req.body();
        in.source_ip = ctx.peer_address;
        in.secure = ctx.tls;
        const auto out = runs(role::front_end) ? _front_end->handle(in) : hand_over(in);
        res.result(out.status);
        for (const auto& [k, v] : out.headers) {
            res.set(k, v);
        }
        res.body() = out.body;
        res.prepare_payload();
        return res;
    }

    /// A gateway without its own front end (task 4, Requirement 6.1):
    /// framing and SigV4 here, the call to a front end on another node,
    /// and its answer passed on unchanged.
    auto hand_over(const kythira::kms::front_end_request& in) -> kythira::aws_json::http_response {
        auto first = _front_end->authenticate(in);
        if (auto* refused = std::get_if<kythira::aws_json::http_response>(&first)) {
            return std::move(*refused);
        }
        const auto& call = std::get<kythira::kms::authenticated_call>(first);
        auto handed = _link->hand_over(call);
        if (auto* res = std::get_if<kythira::aws_json::http_response>(&handed)) {
            return std::move(*res);
        }
        const auto why = std::get<kythira::kms::handoff_failure>(handed);
        log(kythira::log_level::warning,
            std::string("kms: gateway: ") +
                (why == kythira::kms::handoff_failure::no_front_end
                     ? "no front end took " + call.operation + " " + call.request_id
                     : "no answer from the front end for " + call.operation + " " +
                           call.request_id + "; it may have run"));
        return _front_end->fail(call, kythira::kms::front_end_link::error_for(why));
    }

    /// The front-end API (kms_front_end_api.hpp): calls from gateways,
    /// health from gateways and front ends (Requirement 9.1).
    auto serve_front_end_api(const https::request& req, const https::request_context& ctx,
                             https::response& res, std::string_view target) -> https::response {
        namespace fe_api = kythira::kms::front_end_api;
        ++_peer_requests;
        const kythira::kms::peer_caller caller{ctx.tls, ctx.client_verified, ctx.client_uri_sans,
                                               ctx.client_dns_sans};
        const auto roles = target == fe_api::k_health_path ? kythira::kms::front_end_health_roles
                                                           : kythira::kms::front_end_call_roles;
        const bool accepting =
            runs(role::front_end) && _front_end && !_draining.load(std::memory_order_acquire);
        const auto answer =
            fe_api::serve_front_end(kythira::kms::admits(_peer_policy, caller, roles), accepting,
                                    std::string_view(req.method_string()), target, req.body(),
                                    [this](kythira::kms::authenticated_call call) {
                                        return _front_end->execute(std::move(call));
                                    });
        res.result(answer.status);
        res.set(boost::beast::http::field::content_type, "application/octet-stream");
        res.body() = answer.body;
        res.prepare_payload();
        return std::move(res);
    }

    [[nodiscard]] static auto refuse(https::response& res, boost::beast::http::status status,
                                     std::string_view why) -> https::response {
        res.result(status);
        res.set(boost::beast::http::field::content_type, "text/plain");
        res.body() = std::string(why);
        res.prepare_payload();
        return std::move(res);
    }

    auto make_raft_config(Host& host, const service_node::group_space& space) -> raft_config {
        const auto raft_dir = _opt.data_dir / "raft";
        // Sealed at rest when KYTHIRA_RAFT_LOG_KMS says so
        // (.kiro/specs/raft-log-encryption/); one key ring per data dir.
        const auto log_options = kythira::raft_log_options_for(
            _opt.data_dir, kythira::raft_log_encryption_settings::from_environment());
        raft_config cfg{
            .node_id = _opt.node_id,
            .network_client = typename types::network_client_type{host.client()},
            .network_server = host.server_for(space),
            .store_factory =
                [raft_dir, log_options](const std::uint64_t& group) {
                    return typename types::persistence_engine_type{raft_dir / std::to_string(group),
                                                                   log_options};
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

    /// One pass every job_interval; run_jobs_once decides whether this
    /// member runs the jobs (the job lease).
    void jobs_loop() {
        std::unique_lock lock(_jobs_mutex);
        while (_jobs_running.load(std::memory_order_acquire)) {
            lock.unlock();
            try {
                run_jobs_once();
            } catch (const std::exception& e) {
                log(kythira::log_level::error, std::string("kms: jobs: ") + e.what());
            }
            lock.lock();
            _jobs_wake.wait_for(lock, _opt.job_interval,
                                [this] { return !_jobs_running.load(std::memory_order_acquire); });
        }
    }

    /// One pass of the background jobs, on the job lease's holder only
    /// (kms-independent-layers task 2, Requirement 5.1): whichever member
    /// that is, never by virtue of leading the catalog. Only a member that
    /// can reach the HSM token asks for the lease, so a member with a
    /// sealed or missing token never sits on it; one that loses the token
    /// gives it up. Every job command is fenced with the lease's token.
    void run_jobs_once() {
        if (!bind_token()) {
            release_lease();
            return;
        }
        if (!take_lease()) {
            return;
        }
        apply_account_limits();
        if (!_jobs) {
            _catalog = _access->reader();
            if (!_catalog) {
                return;
            }
            _jobs_store = store();
            if (!_jobs_store) {
                return;
            }
            _jobs = std::make_unique<jobs_type>(
                *_catalog, *_jobs_store,
                [this](const std::vector<std::byte>& c) { return propose_fenced(c); },
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

    /// This member's name as a lease holder.
    [[nodiscard]] auto lease_holder() const -> std::string {
        return kythira::host_node_id_text(_opt.node_id);
    }

    /// Takes or renews the job lease (kms_catalog.hpp). True when this
    /// member holds it, as read back from the catalog after the proposal.
    /// A new tenure starts the jobs afresh: what they remembered between
    /// passes (orphans seen once) belongs to the previous one.
    [[nodiscard]] auto take_lease() -> bool {
        const auto holder = lease_holder();
        const auto now = now_ms();
        // Another member's live lease in this replica: no proposal, so
        // members that do not hold it write nothing every pass. The
        // replica may lag, which only delays a takeover by a pass.
        if (const auto mine = _access->reader()) {
            if (const auto l = mine->lease();
                !l.holder.empty() && l.holder != holder && now < l.expiry_ms) {
                lose_lease();
                return false;
            }
        }
        kythira::kms::catalog_status s{};
        try {
            s = _access->propose(kythira::kms::make_acquire_lease_command(
                holder, now, static_cast<std::uint64_t>(_opt.job_lease.count())));
        } catch (const std::exception&) {
            return false;  // no leader, or unknown: try at the next pass
        }
        if (s != kythira::kms::catalog_status::ok) {
            lose_lease();  // another member holds it
            return false;
        }
        const auto c = _access->consistent();
        if (!c) {
            return false;
        }
        const auto l = c->lease();
        if (!l.held_by(holder, now)) {
            lose_lease();
            return false;
        }
        if (_lease_token.exchange(l.token) != l.token) {
            _jobs.reset();
            log(kythira::log_level::info,
                "kms: holding the job lease, token " + std::to_string(l.token));
        }
        return true;
    }

    /// Forgets a lease another member now holds.
    void lose_lease() {
        if (_lease_token.exchange(0) != 0) {
            _jobs.reset();
            log(kythira::log_level::info, "kms: the job lease moved to another member");
        }
    }

    /// Gives the lease up, best effort, so another member takes it now
    /// rather than at expiry (a drain or stop, Requirement 10.2, or a lost
    /// HSM token).
    void release_lease() {
        const auto token = _lease_token.exchange(0);
        if (token == 0 || !_access) {
            return;
        }
        _jobs.reset();
        try {
            (void)_access->propose(kythira::kms::make_release_lease_command(lease_holder(), token));
            log(kythira::log_level::info, "kms: released the job lease");
        } catch (const std::exception&) {
            // It expires on its own.
        }
    }

    /// A job's command, applied only while this member's lease token is
    /// current; stale_lease otherwise, which the jobs count as a failure.
    auto propose_fenced(const std::vector<std::byte>& command) -> kythira::kms::catalog_status {
        const auto token = _lease_token.load();
        if (token == 0) {
            return kythira::kms::catalog_status::stale_lease;
        }
        const auto s = _access->propose(kythira::kms::make_fenced_command(token, command));
        if (s == kythira::kms::catalog_status::stale_lease) {
            _lease_token.store(0);  // the next pass asks again
        }
        return s;
    }

    /// Writes the operator's key and alias limits (KYTHIRA_KMS_ACCOUNT_
    /// LIMITS) where the catalog differs: every lease holder does, so a change
    /// to the setting takes effect at the next pass after a restart.
    void apply_account_limits() {
        if (_opt.account_limits.empty()) {
            return;
        }
        const auto c = _access->reader();
        if (!c) {
            return;
        }
        for (const auto& [account, limits] : _opt.account_limits) {
            if (c->limits(account) == limits) {
                continue;
            }
            try {
                const auto s =
                    propose_fenced(kythira::kms::make_set_account_limits_command(account, limits));
                if (s != kythira::kms::catalog_status::ok) {
                    log(kythira::log_level::warning,
                        "kms: account limits for " + account + " were not written");
                }
            } catch (const std::exception& e) {
                log(kythira::log_level::warning,
                    "kms: account limits for " + account + ": " + e.what());
            }
        }
    }

    /// Finds the token by label and logs in, once; true when the store is
    /// ready.
    auto bind_token() -> bool {
        const std::scoped_lock lock(_store_mutex);
        return bind_token_locked();
    }

    auto bind_token_locked() -> bool {
        if (_store) {
            return true;
        }
        if (!_backend) {
            return false;  // not a front end, or not started
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
            std::make_shared<kythira::kms::backing_store>(_backend, *slot, read_pin(_opt.pin_file));
        return true;
    }

    /// Whether the token answers now.
    auto probe() -> hsm_state {
        try {
            (void)_jobs_store->list();
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
    // The catalog: this node's replica (data), or the data nodes' catalog
    // API (a front end without data). `_access` is whichever it is; the
    // jobs and the lease use it directly, the handlers through
    // `_handler_access` (KYTHIRA_KMS_BOUNDED_STALENESS_MS).
    std::unique_ptr<access_type> _local;
    std::shared_ptr<const kythira::mtls::client> _catalog_client;
    std::unique_ptr<kythira::kms::remote_catalog_access> _remote;
    kythira::kms::kms_catalog_access* _access = nullptr;
    std::unique_ptr<kythira::kms::bounded_staleness_access> _handler_access;
    kythira::kms::catalog_server_deps _catalog_server;
    std::shared_ptr<kythira::pkcs11::backend> _backend;
    // The backing store, shared by the jobs and the API once bound.
    std::mutex _store_mutex;
    std::shared_ptr<kythira::kms::backing_store> _store;
    // The jobs thread's own: its hold on the store, the catalog replica
    // the jobs read and the jobs (which remember orphans between passes).
    std::shared_ptr<kythira::kms::backing_store> _jobs_store;
    std::shared_ptr<const catalog_type> _catalog;
    std::unique_ptr<jobs_type> _jobs;
    // The job lease's token while this member holds it, else 0.
    std::atomic<std::uint64_t> _lease_token{0};
    // Who may call, the API and its listener.
    std::unique_ptr<authorizer_type> _authorizer;
    std::shared_ptr<service_node::iam_evaluator> _iam;
    std::unique_ptr<kythira::kms::request_audit> _audit;
    std::shared_ptr<kythira::kms::request_quotas> _quotas;
    std::unique_ptr<front_end_type> _front_end;
    std::shared_ptr<client_type> _client;
    std::unique_ptr<kythira::kms::key_management_api<catalog_type>> _api;
    std::unique_ptr<kythira::kms::grants_api<catalog_type>> _grants;
    std::unique_ptr<kythira::kms::crypto_api<catalog_type>> _crypto;
    std::unique_ptr<kythira::kms::signing_api<catalog_type>> _signing;
    std::shared_ptr<const kythira::kms::peer_client> _peers;
    kythira::kms::peer_policy _peer_policy;
    std::unique_ptr<https::server> _server;
    // The front ends (task 4): who is live, and a gateway's link to them.
    std::unique_ptr<kythira::kms::front_end_directory> _directory;
    std::shared_ptr<const kythira::mtls::client> _front_end_client;
    std::unique_ptr<kythira::kms::front_end_link> _link;
    std::atomic<bool> _draining{false};
    std::atomic<bool> _probing{false};
    std::mutex _probe_mutex;
    std::condition_variable _probe_wake;
    std::thread _probe_thread;
    std::atomic<std::uint64_t> _requests{0};
    std::atomic<std::uint64_t> _peer_requests{0};
    std::atomic<hsm_state> _hsm{hsm_state::unknown};
    mutable std::mutex _report_mutex;
    std::uint64_t _passes = 0;
    kythira::kms::job_report _total;
    std::atomic<bool> _driving{false};
    std::atomic<bool> _jobs_running{false};
    std::thread _driver;
    std::mutex _jobs_mutex;
    std::condition_variable _jobs_wake;
    std::thread _jobs_thread;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::kms_node
