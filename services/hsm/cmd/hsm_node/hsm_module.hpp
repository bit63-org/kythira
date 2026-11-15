// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The virtual HSM as a service module (.kiro/specs/virtual-hsm/ task 6e,
// .kiro/specs/service-colocation/): the catalog and token groups on a
// multi_raft host over the node's transport, the session layer, and one
// HTTPS listener that serves the operator API and the members'
// forwarding routes.
//
// Data directory (the node's hsm/ in kythira_node):
//   engine/                 the RocksDB database (catalog and every token)
//   raft/<group>/           each group's Raft log
//   snapshots/group-<id>/   checkpoints and incoming snapshot transfers
//
// PKCS#11 clients in other processes connect to the client listener
// (mutual TLS, KYTHIRA_HSM_CLIENT_LISTEN) or the Unix socket
// (KYTHIRA_HSM_SOCKET), wire_server.hpp; each connection is an
// application under its certificate's or uid's identity.
//
// Co-located modules reach the HSM in process: the module publishes its
// session layer as "hsm.session_layer", and, for consumers that know only
// core, a PKCS#11 backend factory as "hsm.pkcs11" (module_interfaces.hpp)
// that core's kythira::pkcs11::module wraps (task 13). Either way the
// consumer acts under its own identity, which the catalog's bindings
// authorize like any network client's (Requirement 7.2 of the colocation
// spec: co-location never widens access).
//
// With KYTHIRA_HSM_IAM=true and IAM co-located, an identity that is an IAM
// user or role ARN is authorized by IAM's policies with hsm: actions on
// the token's ARN instead of by the bindings (hsm_iam.hpp, task 14b).
//
// The node starts sealed: until an operator unseals it (task 7), every
// cryptographic call answers CKR_DEVICE_ERROR, and health() says so while
// staying healthy, since a sealed HSM is up and waiting for its operators.

#include "hsm_audit.hpp"
#include "hsm_config.hpp"

#include <kythira/hsm/hsm_admin.hpp>
#include <kythira/hsm/hsm_group_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/hsm_iam.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/node_unseal.hpp>
#include <kythira/hsm/pkcs11_native_backend.hpp>
#include <kythira/hsm/secure_arena.hpp>
#include <kythira/hsm/session_layer.hpp>
#include <kythira/hsm/share_sealers.hpp>
#ifdef KYTHIRA_HSM_TPM2
#include <kythira/hsm/tpm2_key_provider.hpp>
#endif
#include <kythira/hsm/wire_server.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>
#include <raft/kms_key_provider_aws.hpp>
#include <raft/kms_key_provider_azure.hpp>
#include <raft/kms_key_provider_gcp.hpp>
#include <raft/kms_key_provider_pkcs11.hpp>
#include <raft/metrics.hpp>
#include <raft/module_interfaces.hpp>
#include <raft/module_registry.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/node_core.hpp>
#include <raft/rocksdb_kv_engine.hpp>
#include <raft/service_module.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::hsm_node {

using engine_type = kythira::rocksdb_kv_engine;
using group_sm = kythira::hsm::hsm_group_state_machine<engine_type>;

/// The HSM's multi_raft types on a node whose transport is `Host`'s.
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

/// The name co-located modules look the session layer up by.
inline constexpr std::string_view session_layer_interface = "hsm.session_layer";

/// "hsm.pkcs11": a pkcs11_native_backend per consumer identity. Each
/// backend keeps the session layer alive.
class native_pkcs11_provider final : public service_node::pkcs11_provider {
public:
    explicit native_pkcs11_provider(std::shared_ptr<kythira::hsm::session_layer> layer)
        : _layer(std::move(layer)) {}

    [[nodiscard]] auto backend_for(const std::string& identity)
        -> std::shared_ptr<kythira::pkcs11::backend> override {
        struct owning final {
            owning(std::shared_ptr<kythira::hsm::session_layer> l, const std::string& id)
                : layer(std::move(l)), backend(*layer, id) {}
            std::shared_ptr<kythira::hsm::session_layer> layer;
            kythira::hsm::pkcs11_native_backend backend;
        };
        auto holder = std::make_shared<owning>(_layer, identity);
        return {holder, &holder->backend};
    }

private:
    std::shared_ptr<kythira::hsm::session_layer> _layer;
};

/// The co-located IAM evaluator, once the module starts; the session
/// layer's authorizer holds it, since the layer may outlive the module.
class iam_link {
public:
    void set(std::shared_ptr<service_node::iam_evaluator> evaluator) {
        auto hooks = evaluator->hooks();
        const std::scoped_lock lock(_mu);
        _authorize = std::move(hooks.authorize);
        _evaluator = std::move(evaluator);
    }

    [[nodiscard]] auto authorize(const aws_auth::principal_context& who,
                                 const aws_auth::authz_request& r) const
        -> aws_auth::authz_decision {
        decltype(_authorize) f;
        {
            const std::scoped_lock lock(_mu);
            f = _authorize;
        }
        if (!f) {
            aws_auth::authz_decision d;
            d.reason = "IAM has not started";
            return d;
        }
        return f(who, r);
    }

private:
    mutable std::mutex _mu;
    std::function<aws_auth::authz_decision(const aws_auth::principal_context&,
                                           const aws_auth::authz_request&)>
        _authorize;
    std::shared_ptr<service_node::iam_evaluator> _evaluator;
};

template<typename Host> class hsm_module final : public service_node::service_module<Host> {
public:
    using types = module_host_types<Host>;
    using raft_host = kythira::multi_raft<types, std::string, std::uint64_t>;
    using raft_config = kythira::multi_raft_config<types, std::string, std::uint64_t>;
    using hsm_host = kythira::hsm::basic_hsm_host<raft_host, engine_type>;
    using admin_type = kythira::hsm::admin_api<hsm_host>;

    hsm_module() = default;
    hsm_module(const hsm_module&) = delete;
    auto operator=(const hsm_module&) -> hsm_module& = delete;
    hsm_module(hsm_module&&) = delete;
    auto operator=(hsm_module&&) -> hsm_module& = delete;
    ~hsm_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "hsm"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return service_node::module_numbers::hsm;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override { return "KYTHIRA_HSM_"; }
    /// IAM first, so its evaluator answers before a client is served.
    [[nodiscard]] auto starts_after() const -> std::vector<std::string> override { return {"iam"}; }

    [[nodiscard]] auto configure(const service_node::env_lookup& env)
        -> std::optional<std::string> override {
        try {
            _opt = from_env(composite_env(service_node::module_tuning(env, "KYTHIRA_HSM_")));
            // Key memory and the process before anything holds a key:
            // locked pages, no core dumps (Requirement 13.3).
            if (auto r = kythira::hsm::prepare_key_memory(_opt.allow_unlocked_memory); !r) {
                return "hsm: key memory: " +
                       std::string(kythira::hsm::secure_memory_error_message(r.error())) +
                       " (KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY=true starts anyway, for development)";
            }
            if (_opt.iam && !service_node::co_located(env, "iam")) {
                return std::string(
                    "KYTHIRA_HSM_IAM=true needs IAM co-located (KYTHIRA_SERVICES naming iam)");
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
        _ctx = hsm_host::make_context();
        _raft = std::make_unique<raft_host>(make_raft_config(host, space));

        typename hsm_host::options hopts;
        for (const auto& [id, url] : _opt.api_urls) {
            hopts.members.push_back(id);
        }
        hopts.group_base = space.first();
        hopts.group_last = space.last();
        hopts.propose_timeout = _opt.propose_timeout;
        hopts.maintenance_interval = _opt.maintenance_interval;
        kythira::hsm::peer_client_config pc;
        pc.cert_path = _opt.tls_cert;
        pc.key_path = _opt.tls_key;
        pc.ca_path = _opt.client_ca;
        pc.plaintext = _opt.insecure_plaintext;
        pc.timeout = _opt.propose_timeout + std::chrono::seconds{2};
        _peers = std::make_shared<const kythira::hsm::peer_client>(pc);
        hopts.forward.propose = [this](const kythira::host_node_id& leader, std::uint64_t group,
                                       const std::vector<std::byte>& cmd) {
            return from_peer(_peers->propose(url_of(leader), group, cmd));
        };
        hopts.forward.read_index = [this](const kythira::host_node_id& leader,
                                          std::uint64_t group) {
            return from_peer(_peers->read_index(url_of(leader), group));
        };
        _host = std::make_unique<hsm_host>(*_raft, _ctx, hopts);

        // Audit (task 14): the hooks hold the pipeline, since a co-located
        // consumer may keep the session layer past this module.
        _audit = std::make_shared<audit_pipeline>(_opt);
        const kythira::hsm::audit_hook audit = [a = _audit](const kythira::hsm::audit_event& e) {
            a->record(e);
        };
        kythira::hsm::session_options so;
        so.pin_log2_n = _opt.pin_log2_n;
        so.max_login_failures = _opt.max_login_failures;
        so.max_sessions = _opt.max_sessions;
        so.audit = audit;
        so.audit_sample_every = _opt.audit_sample_every;
        if (_opt.iam) {
            // The evaluator is taken at start; until then IAM identities
            // are refused, and no client is served before start anyway.
            _iam = std::make_shared<iam_link>();
            kythira::hsm::iam_token_config ic;
            ic.partition = _opt.iam_partition;
            ic.region = _opt.iam_region;
            ic.cache_ttl = _opt.iam_cache;
            auto authz = std::make_shared<kythira::hsm::iam_token_authorizer>(
                ic, [link = _iam](const aws_auth::principal_context& who,
                                  const aws_auth::authz_request& r) {
                    return link->authorize(who, r);
                });
            so.authorize = [authz](std::string_view identity, std::uint64_t token,
                                   std::string_view action) {
                return (*authz)(identity, token, action);
            };
        }
        _layer = std::make_shared<kythira::hsm::session_layer>(*_host, _vault, so);
        kythira::hsm::admin_policy policy;
        policy.operators = _opt.operators;
        policy.allow_single_share = _opt.allow_single_share;
        policy.unseal_timeout = _opt.unseal_timeout;
        _admin = std::make_unique<admin_type>(*_host, _vault, std::move(policy));
        _admin->set_seal_hook([layer = _layer] { layer->seal(); });
        _admin->set_audit_hook(audit);
        _peer_policy.identities = _opt.peer_identities;
        _peer_policy.allow_plaintext = _opt.insecure_plaintext;
        // Node unseal (task 8): this node's share at rest, and init and
        // rekey handing share i to the i-th member in id order.
        _sealer = make_share_sealer(_opt);
        _shares = std::make_unique<kythira::hsm::share_store>(_opt.data_dir / "shares", *_sealer);
        _node_unseal = std::make_unique<kythira::hsm::node_unseal>(_vault, *_shares);
        kythira::hsm::node_share_delivery delivery;
        delivery.members = _opt.api_urls.size();
        delivery.deliver = [this](std::size_t index, const kythira::hsm::shamir_share& share) {
            auto it = _opt.api_urls.begin();
            std::advance(it, static_cast<std::ptrdiff_t>(index));
            if (it->first == _opt.node_id) {
                try {
                    return _shares->put(share);
                } catch (const std::exception& e) {
                    // A KMS that refuses or is away (task 8b): nothing is
                    // committed, and the operator retries.
                    kythira::console_logger{_opt.log_level}.error(
                        std::string("node unseal: this member's share sealer refused: ") +
                        e.what());
                    return false;
                }
            }
            const auto bin = kythira::hsm::shamir_encode_binary(share);
            std::string body(reinterpret_cast<const char*>(bin.data()), bin.size());
            const bool stored = _peers->deliver_share(it->second, body);
            OPENSSL_cleanse(body.data(), body.size());
            return stored;
        };
        _admin->set_node_share_delivery(std::move(delivery));
        _host->bootstrap();
    }

    void publish(service_node::module_registry& registry) override {
        registry.publish<kythira::hsm::session_layer>(std::string(session_layer_interface), _layer);
        registry.publish<service_node::pkcs11_provider>(
            std::string(service_node::interface_names::hsm_pkcs11),
            std::make_shared<native_pkcs11_provider>(_layer));
    }

    void start(service_node::module_registry& registry) override {
        // Requirement 12.2: no one should mistake this for a hardware
        // boundary.
        log(kythira::log_level::warning,
            "hsm: this is a software HSM: keys are in this host's memory while in use, "
            "readable by root on this host; see doc/hsm.md for what it does and does not "
            "protect against");
        if (_iam) {
            auto iam = registry.lookup<service_node::iam_evaluator>(
                std::string(service_node::interface_names::iam_evaluator));
            if (!iam) {
                throw std::invalid_argument(
                    "KYTHIRA_HSM_IAM=true: the IAM module publishes no evaluator");
            }
            iam->add_actions(kythira::hsm::hsm_actions());
            _iam->set(iam);
        }
        _raft->start();
        _driving = true;
        _driver = std::thread([this] {
            while (_driving.load(std::memory_order_acquire)) {
                try {
                    (void)_raft->tick();
                } catch (const std::exception& e) {
                    log(kythira::log_level::error, std::string("hsm: tick failed: ") + e.what());
                }
                std::this_thread::sleep_for(_opt.tick_interval);
            }
        });
        _host->start();
        // Seals this node once it applies a seal or a rekey, and drops
        // expired partial shares. Its own thread, so a seal waiting for
        // key uses in flight never holds up the Raft tick.
        _warden = std::thread([this] {
            std::unique_lock lock(_warden_mutex);
            while (_driving.load(std::memory_order_acquire)) {
                try {
                    if (_admin->maintain()) {
                        log(kythira::log_level::info,
                            "hsm: sealed (the catalog was sealed or rekeyed)");
                        kythira::hsm::audit_event e;
                        e.action = "sealed";
                        e.identity = "catalog";
                        _audit->record(e);
                    }
                    try_node_unseal();
                } catch (const std::exception& e) {
                    log(kythira::log_level::error, std::string("hsm: warden: ") + e.what());
                }
                _warden_wake.wait_for(lock, _opt.maintenance_interval);
            }
        });

        kythira::https::server_config http;
        http.bind_address = _opt.api_bind;
        http.port = _opt.api_port;
        http.tls_cert_path = _opt.tls_cert;
        http.tls_key_path = _opt.tls_key;
        http.client_ca_path = _opt.client_ca;
        http.insecure_plaintext = _opt.insecure_plaintext;
        http.max_body_bytes = _opt.max_body_bytes;
        http.max_connections = static_cast<std::size_t>(_opt.max_connections);
        _server = std::make_unique<kythira::https::server>(
            http,
            [this](const kythira::https::request& req, const kythira::https::request_context& ctx) {
                return handle(req, ctx);
            },
            [this](bool warning, std::string_view message) {
                log(warning ? kythira::log_level::warning : kythira::log_level::info,
                    std::string(message));
            });
        _server->start();

        kythira::hsm::wire_server_config wc;
        if (_opt.client_listen) {
            wc.bind_address = _opt.client_listen->first;
            wc.tls_port = _opt.client_listen->second;
        } else {
            wc.tls_port.reset();
        }
        wc.cert_path = _opt.tls_cert;
        wc.key_path = _opt.tls_key;
        wc.ca_path = _opt.app_ca;
        wc.socket_path = _opt.socket_path.string();
        wc.socket_allow = _opt.socket_allow;
        wc.max_connections = static_cast<std::size_t>(_opt.client_max_connections);
        wc.idle_timeout = _opt.client_idle_timeout;
        _clients = std::make_unique<kythira::hsm::wire_server>(
            _layer, std::move(wc), [this](bool warning, std::string_view message) {
                log(warning ? kythira::log_level::warning : kythira::log_level::info,
                    std::string(message));
            });
        _clients->start();
        _started = true;
        std::cout << "hsm " << kythira::host_node_id_text(_opt.node_id)
                  << " ready: api=" << _server->port() << " clients="
                  << (_opt.client_listen ? std::to_string(_clients->tls_port()) : "off")
                  << (_opt.socket_path.empty() ? "" : " socket=" + _opt.socket_path.string())
                  << (_opt.insecure_plaintext ? " (PLAINTEXT)" : " (mutual TLS)")
                  << " members=" << _opt.api_urls.size() << " sealed" << std::endl;
    }

    void drain() override {
        if (_clients) {
            _clients->stop();
        }
        if (_server) {
            _server->stop();
        }
    }

    void stop() override {
        drain();
        if (_host) {
            _host->stop();
        }
        {
            const std::scoped_lock lock(_warden_mutex);
            _driving.store(false, std::memory_order_release);
        }
        _warden_wake.notify_all();
        if (_warden.joinable()) {
            _warden.join();
        }
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        if (_layer) {
            _layer->seal();  // the key cache and session objects too
        }
        _vault.seal();
        _clients.reset();
        _admin.reset();
        _layer.reset();
        if (_audit) {
            _audit->flush();
        }
        _audit.reset();
        _host.reset();
        _raft.reset();
        _started = false;
    }

    [[nodiscard]] auto health() const -> service_node::module_health override {
        if (!_started) {
            return {false, "not started"};
        }
        if (!_host->catalog()) {
            return {true, "not initialized"};
        }
        return {true, _vault.sealed() ? "sealed" : ""};
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> override {
        if (!_host) {
            return {};
        }
        const auto s = _host->stats();
        auto out = std::vector<service_node::module_metric>{
            {"sealed", _vault.sealed() ? 1.0 : 0.0, {}},
            {"tokens", static_cast<double>(_host->tokens().size()), {}},
            {"groups_created", static_cast<double>(s.groups_created), {}},
            {"groups_destroyed", static_cast<double>(s.groups_destroyed), {}},
            {"proposals_forwarded", static_cast<double>(s.proposals_forwarded), {}},
            {"read_indexes_forwarded", static_cast<double>(s.read_indexes_forwarded), {}},
            {"proposals_served", static_cast<double>(s.proposals_served), {}},
            {"read_indexes_served", static_cast<double>(s.read_indexes_served), {}},
            {"cached_keys", static_cast<double>(_layer ? _layer->cached_keys() : 0), {}},
            {"client_connections",
             static_cast<double>(_clients ? _clients->active_connections() : 0),
             {}},
            {"client_requests", static_cast<double>(_clients ? _clients->stats().requests : 0), {}},
            {"client_connections_refused",
             static_cast<double>(_clients ? _clients->stats().refused : 0),
             {}},
            {"raft_term_sum", service_node::raft_term_sum(*_raft), {}},
            {"replica_lag_entries", static_cast<double>(s.replica_lag_entries), {}},
            {"replica_wait_seconds_total", static_cast<double>(s.replica_wait_us) / 1e6, {}}};
        if (_audit) {
            auto more = _audit->metrics();
            out.insert(out.end(), std::make_move_iterator(more.begin()),
                       std::make_move_iterator(more.end()));
        }
        return out;
    }

    /// The listener's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _server ? _server->port() : 0; }
    /// The client listener's port once started.
    [[nodiscard]] auto client_port() const -> std::uint16_t {
        return _clients ? _clients->tls_port() : 0;
    }

private:
    /// This node's share sealer (task 8): the key file, or (task 8b) a key
    /// the node's disk does not hold: a KMS key, a PKCS#11 token's, the
    /// TPM's.
    static auto make_share_sealer(const kythira::hsm_node::hsm_options& opt)
        -> std::unique_ptr<kythira::hsm::share_sealer> {
        namespace kp = kythira::kms_provider;
        // Read once at startup: nothing in the process changes its
        // environment.
        const kp::env_lookup env = [](const char* var) {
            const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
            return v != nullptr ? std::string(v) : std::string();
        };
        const auto sealer = [&opt](kp::key_provider provider) {
            return std::make_unique<kythira::hsm::kms_share_sealer>(
                opt.share_sealer, std::move(provider), opt.share_key_id);
        };
#ifdef KYTHIRA_HSM_TPM2
        if (opt.share_sealer == "tpm2") {
            return sealer(
                kp::key_provider(kythira::hsm::tpm2_key_provider(kythira::hsm::tpm2_config{
                    .tcti = opt.share_tpm2_tcti, .pcrs = opt.share_tpm2_pcrs})));
        }
#endif
        if (opt.share_sealer == "azure-key-vault") {
            const std::chrono::milliseconds timeout{5000};
            kp::azure_key_vault_config kc;
            kc._algorithm = opt.share_azure_algorithm;
            kc._ca_path = opt.share_kms_ca;
            kc._timeout = timeout;
            kc._token = kp::azure_default_token_source(
                opt.share_key_id, env,
                kp::cloud_detail::default_transport(opt.share_kms_ca, timeout));
            return sealer(kp::key_provider(kp::azure_key_vault_provider(std::move(kc))));
        }
        if (opt.share_sealer == "gcp-kms") {
            const std::chrono::milliseconds timeout{5000};
            kp::gcp_kms_config kc;
            kc._endpoint = opt.share_kms_endpoint;
            kc._ca_path = opt.share_kms_ca;
            kc._timeout = timeout;
            kc._token = kp::gcp_default_token_source(
                env, kp::cloud_detail::default_transport(opt.share_kms_ca, timeout));
            return sealer(kp::key_provider(kp::gcp_kms_provider(std::move(kc))));
        }
        if (opt.share_sealer == "aws-kms") {
            kp::aws_kms_config kc;
            kc._region = opt.share_kms_region;
            kc._endpoint = opt.share_kms_endpoint;
            kc._ca_path = opt.share_kms_ca;
            kc._credentials = [creds = kp::aws_kms_credentials{
                                   env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"),
                                   env("AWS_SESSION_TOKEN")}] { return creds; };
            return sealer(kp::key_provider(kp::aws_kms_provider(std::move(kc))));
        }
        if (opt.share_sealer == "pkcs11") {
            kp::pkcs11_kms_config kc;
            kc.token = kythira::pkcs11::uri::parse(opt.share_pkcs11_uri);
            kc.oaep = opt.share_pkcs11_oaep == "sha1" ? kythira::pkcs11::hash_algorithm::sha1
                                                      : kythira::pkcs11::hash_algorithm::sha256;
            auto token = kc.token;
            return sealer(kp::key_provider(
                kp::pkcs11_kms_provider(std::move(kc), [token]() -> kythira::pkcs11::module {
                    return kythira::pkcs11::module::load(token);
                })));
        }
        return std::make_unique<kythira::hsm::key_file_sealer>(opt.share_key_file);
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
        cfg.automatic_split_merge_enabled = false;  // HSM groups never move
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

    /// In node mode, a sealed node collects shares from the others, at
    /// most every five seconds so an unreachable quorum is not hammered.
    void try_node_unseal() {
        const auto now = std::chrono::steady_clock::now();
        if (!_vault.sealed() || now < _next_node_unseal) {
            return;
        }
        const auto c = _host->catalog();
        if (!c || c->mode != kythira::hsm::unseal_mode::node_shares) {
            return;
        }
        _next_node_unseal = now + std::chrono::seconds{5};
        if (!_host->catalog_barrier()) {
            return;  // the check value must be current, or old shares would be asked for
        }
        std::vector<kythira::hsm::node_unseal::fetch_fn> peers;
        for (const auto& [id, url] : _opt.api_urls) {
            if (id == _opt.node_id) {
                continue;
            }
            peers.emplace_back([this, url](std::span<const std::uint8_t, 8> check)
                                   -> std::optional<kythira::hsm::secret_bytes> {
                auto body = _peers->request_share(url, check);
                if (!body) {
                    return std::nullopt;
                }
                kythira::hsm::secret_bytes bin(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(body->data()), body->size()));
                OPENSSL_cleanse(body->data(), body->size());
                return bin;
            });
        }
        const auto outcome = _node_unseal->attempt(_host->catalog(), peers);
        if (outcome == kythira::hsm::node_unseal_outcome::unsealed ||
            outcome != _last_node_unseal) {
            kythira::hsm::audit_event e;
            e.action = "node_unseal";
            e.identity = kythira::host_node_id_text(_opt.node_id);
            e.rv = outcome == kythira::hsm::node_unseal_outcome::unsealed ? CKR_OK
                                                                          : CKR_FUNCTION_FAILED;
            _audit->record(e);
        }
        if (outcome == kythira::hsm::node_unseal_outcome::unsealed) {
            log(kythira::log_level::info, "hsm: unsealed with shares from the other members");
        } else if (outcome != _last_node_unseal) {
            log(kythira::log_level::warning,
                std::string("hsm: node unseal: ") +
                    (outcome == kythira::hsm::node_unseal_outcome::no_local_share
                         ? "this node holds no share of the current master key"
                     : outcome == kythira::hsm::node_unseal_outcome::too_few_shares
                         ? "fewer than k members answered; staying sealed"
                         : "the shares did not rebuild the master key"));
        }
        _last_node_unseal = outcome;
    }

    [[nodiscard]] auto url_of(const kythira::host_node_id& id) const -> std::string {
        const auto it = _opt.api_urls.find(id);
        return it == _opt.api_urls.end() ? std::string() : it->second;
    }

    [[nodiscard]] static auto from_peer(const kythira::hsm::forward_reply<std::string>& r)
        -> kythira::hsm::forward_reply<kythira::host_node_id> {
        return kythira::hsm::from_wire<kythira::host_node_id>(
            r, [](const std::string& text) -> std::optional<kythira::host_node_id> {
                auto id = kythira::parse_host_peer_node_id(text);
                return id ? std::optional<kythira::host_node_id>(std::move(id).value())
                          : std::nullopt;
            });
    }

    auto handle(const kythira::https::request& req, const kythira::https::request_context& ctx)
        -> kythira::https::response {
        namespace http = boost::beast::http;
        std::string_view target = req.target();
        target = target.substr(0, target.find('?'));
        kythira::https::response res{http::status::ok, req.version()};
        res.set(http::field::server, "kythira-hsm");
        const kythira::hsm::peer_caller caller{ctx.tls, ctx.client_verified, ctx.client_uri_sans,
                                               ctx.client_dns_sans};
        if (auto share = kythira::hsm::serve_share_peer(*_shares, _peer_policy, caller,
                                                        std::string_view(req.method_string()),
                                                        target, req.body())) {
            res.result(share->status);
            res.set(http::field::content_type, "application/octet-stream");
            res.body() = std::move(share->body);
            res.prepare_payload();
            return res;
        }
        if (auto peer = kythira::hsm::serve_peer(
                *_host, _peer_policy, caller, std::string_view(req.method_string()), target,
                req.body(),
                [](const kythira::host_node_id& id) { return kythira::host_node_id_text(id); })) {
            res.result(peer->status);
            res.set(http::field::content_type, "application/octet-stream");
            res.body() = std::move(peer->body);
            res.prepare_payload();
            return res;
        }
        kythira::hsm::admin_request ar;
        ar.method = std::string(req.method_string());
        ar.path = std::string(target);
        ar.body = req.body();
        if (ctx.tls && ctx.client_verified) {
            ar.identities = ctx.client_uri_sans;
            ar.identities.insert(ar.identities.end(), ctx.client_dns_sans.begin(),
                                 ctx.client_dns_sans.end());
        }
        auto answer = _admin->handle(ar);
        res.result(answer.status);
        res.set(http::field::content_type, "application/json");
        res.body() = std::move(answer.body);
        res.prepare_payload();
        return res;
    }

    auto log(kythira::log_level level, const std::string& message) const -> void {
        kythira::console_logger logger(_opt.log_level);
        logger.log(level, message, {});
    }

    hsm_options _opt;
    kythira::hsm::key_vault _vault;
    std::unique_ptr<kythira::hsm::share_sealer> _sealer;
    std::unique_ptr<kythira::hsm::share_store> _shares;
    std::unique_ptr<kythira::hsm::node_unseal> _node_unseal;
    std::chrono::steady_clock::time_point _next_node_unseal{};
    kythira::hsm::node_unseal_outcome _last_node_unseal{kythira::hsm::node_unseal_outcome::idle};
    std::shared_ptr<typename group_sm::context> _ctx;
    std::unique_ptr<raft_host> _raft;
    std::unique_ptr<hsm_host> _host;
    std::shared_ptr<audit_pipeline> _audit;
    std::shared_ptr<iam_link> _iam;
    std::shared_ptr<kythira::hsm::session_layer> _layer;
    std::unique_ptr<admin_type> _admin;
    std::shared_ptr<const kythira::hsm::peer_client> _peers;
    kythira::hsm::peer_policy _peer_policy;
    std::unique_ptr<kythira::https::server> _server;
    std::unique_ptr<kythira::hsm::wire_server> _clients;
    std::atomic<bool> _driving{false};
    std::thread _driver;
    std::mutex _warden_mutex;
    std::condition_variable _warden_wake;
    std::thread _warden;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::hsm_node
