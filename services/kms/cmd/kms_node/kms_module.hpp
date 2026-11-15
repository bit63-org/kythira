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

#include "kms_config.hpp"

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_crypto_api.hpp>
#include <kythira/kms/kms_audit.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_grants_api.hpp>
#include <kythira/kms/kms_group_state_machine.hpp>
#include <kythira/kms/kms_host.hpp>
#include <kythira/kms/kms_in_process.hpp>
#include <kythira/kms/kms_keys.hpp>
#include <kythira/kms/kms_peer.hpp>
#include <kythira/kms/kms_signing_api.hpp>

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
    using catalog_type = typename kms_host::catalog_type;
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
            if (_opt.pkcs11 == co_located_hsm && !service_node::co_located(env, "hsm")) {
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
            kythira::mtls::client_config pc;
            pc.cert_path = _opt.tls_cert;
            pc.key_path = _opt.tls_key;
            pc.ca_path = _opt.client_ca;
            pc.plaintext = _opt.insecure_plaintext;
            // A forwarded proposal waits for its commit.
            pc.timeout = _opt.propose_timeout + std::chrono::seconds(2);
            _peers = std::make_shared<const kythira::kms::peer_client>(pc);
            hopts.forward.propose = [this](const kythira::host_node_id& leader,
                                           const std::vector<std::byte>& cmd) {
                return from_peer(_peers->propose(url_of(leader), cmd));
            };
            hopts.forward.read_index = [this](const kythira::host_node_id& leader) {
                return from_peer(_peers->read_index(url_of(leader)));
            };
        }
        _peer_policy.identities = _opt.peer_identities;
        _peer_policy.allow_plaintext = _opt.insecure_plaintext;
        _host = std::make_unique<kms_host>(*_raft, _ctx, hopts);
        _host->bootstrap();
        build_api();
    }

    /// kms.client: co-located consumers' calls for their callers, through
    /// the same front end as the listener (kms_in_process.hpp).
    void publish(service_node::module_registry& registry) override {
        registry.publish<service_node::kms_endpoint>(
            std::string(service_node::interface_names::kms_client), _client);
    }

    void start(service_node::module_registry& registry) override {
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
                  << " ready: members=" << _opt.api_urls.size() << " api=" << _server->port()
                  << (_opt.insecure_plaintext ? " (http)" : " (https)")
                  << " auth=" << auth_name(_opt.auth) << " pkcs11="
                  << (_opt.pkcs11 == co_located_hsm ? std::string("hsm (co-located)") : _opt.pkcs11)
                  << " token=" << _opt.token_label << std::endl;
    }

    /// No request in flight once the listener has stopped.
    void drain() override {
        if (_server) {
            _server->stop();
        }
    }

    void stop() override {
        drain();
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
        // Everything that refers to the host goes before it.
        _server.reset();
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
        if (!_host || !_raft) {
            return {};
        }
        const auto s = _host->stats();
        auto out = _audit ? _audit->metrics() : std::vector<service_node::module_metric>{};
        if (_quotas) {
            const auto q = _quotas->metrics();
            out.insert(out.end(), q.begin(), q.end());
        }
        const std::scoped_lock lock(_report_mutex);
        std::vector<service_node::module_metric> mine{
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
            {"requests", static_cast<double>(_requests.load()), {}},
            {"peer_requests", static_cast<double>(_peer_requests.load()), {}},
        };
        out.insert(out.end(), mine.begin(), mine.end());
        return out;
    }

private:
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

    void build_api() {
        kythira::kms::front_end_config fc;
        fc.region = _opt.region;
        fc.partition = _opt.partition;
        fc.limits.max_body_bytes = static_cast<std::size_t>(_opt.max_body_bytes);
        // Requirement 7.7: on static keys the static roles decide alone.
        fc.evaluate_grants = _opt.auth != kythira::aws_auth::auth_mode::static_keys;
        fc.trusted_services.insert(_opt.trusted_services.begin(), _opt.trusted_services.end());
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        _audit = std::make_unique<kythira::kms::request_audit>(_opt.audit, _opt.region);
        if (_opt.throttling) {
            auto q = _opt.quotas;
            q.members = std::max<std::size_t>(_opt.api_urls.size(), 1);
            _quotas = std::make_shared<kythira::kms::request_quotas>(std::move(q));
            _front_end->set_quotas(_quotas);
        }
        _front_end->set_observer(
            [audit = _audit.get()](const kythira::kms::request_record& r) { audit->record(r); });
        _client = std::make_shared<client_type>(*_front_end);
        const auto catalog = [this] { return _host->catalog(); };
        const auto barrier = [this] { return _host->barrier(); };
        const auto propose = [this](const std::vector<std::byte>& c) { return _host->propose(c); };
        kythira::kms::api_deps<catalog_type> deps{
            .catalog = catalog,
            .barrier = barrier,
            .propose = propose,
            .create_key = [this, propose](
                              kythira::kms::key_record k,
                              const kythira::kms::tag_map& tags) -> kythira::kms::key_result {
                auto c = _host->catalog();
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
                auto c = _host->catalog();
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
        // AWS managed keys on first use (kms_managed.hpp), through the same
        // CreateKey steps.
        const kythira::kms::managed_deps<catalog_type> mdeps{
            .catalog = [this]() -> std::shared_ptr<const catalog_type> {
                return _host->barrier() ? _host->catalog() : nullptr;
            },
            .propose = propose,
            .create_key = deps.create_key,
            .clock_ms = now_ms,
            .partition = _opt.partition,
            .region = _opt.region,
        };
        deps.ensure_managed = [mdeps](std::string_view account,
                                      const kythira::kms::managed_service& s) {
            return kythira::kms::ensure_managed_key(mdeps, account, s);
        };
        _api = std::make_unique<kythira::kms::key_management_api<catalog_type>>(deps);
        _grants = std::make_unique<kythira::kms::grants_api<catalog_type>>(deps);
        const kythira::kms::crypto_deps<catalog_type> cdeps{
            .catalog = catalog,
            .barrier = barrier,
            .hsm = [this] { return store(); },
            .ensure_managed = deps.ensure_managed,
        };
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
        const auto out = _front_end->handle(in);
        res.result(out.status);
        for (const auto& [k, v] : out.headers) {
            res.set(k, v);
        }
        res.body() = out.body;
        res.prepare_payload();
        return res;
    }

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
        apply_account_limits();
        if (!bind_token()) {
            return;
        }
        if (!_jobs) {
            _catalog = _host->catalog();
            if (!_catalog) {
                return;
            }
            _jobs_store = store();
            if (!_jobs_store) {
                return;
            }
            _jobs = std::make_unique<jobs_type>(
                *_catalog, *_jobs_store,
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

    /// Writes the operator's key and alias limits (KYTHIRA_KMS_ACCOUNT_
    /// LIMITS) where the catalog differs: every leader does, so a change
    /// to the setting takes effect at the next pass after a restart.
    void apply_account_limits() {
        if (_opt.account_limits.empty()) {
            return;
        }
        const auto c = _host->catalog();
        if (!c) {
            return;
        }
        for (const auto& [account, limits] : _opt.account_limits) {
            if (c->limits(account) == limits) {
                continue;
            }
            try {
                const auto s =
                    _host->propose(kythira::kms::make_set_account_limits_command(account, limits));
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
    std::shared_ptr<kythira::pkcs11::backend> _backend;
    // The backing store, shared by the jobs and the API once bound.
    std::mutex _store_mutex;
    std::shared_ptr<kythira::kms::backing_store> _store;
    // The jobs thread's own: its hold on the store, the catalog replica
    // the jobs read and the jobs (which remember orphans between passes).
    std::shared_ptr<kythira::kms::backing_store> _jobs_store;
    std::shared_ptr<const catalog_type> _catalog;
    std::unique_ptr<jobs_type> _jobs;
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
    std::atomic<std::uint64_t> _requests{0};
    std::atomic<std::uint64_t> _peer_requests{0};
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
