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
// Co-located modules reach the HSM in process: the module publishes its
// session layer as "hsm.session_layer", and a consumer opens it through a
// native_client under its own identity, which the catalog's bindings
// authorize like any network client's (Requirement 7.2 of the colocation
// spec: co-location never widens access).
//
// The node starts sealed: until an operator unseals it (task 7), every
// cryptographic call answers CKR_DEVICE_ERROR, and health() says so while
// staying healthy, since a sealed HSM is up and waiting for its operators.

#include "hsm_config.hpp"

#include <kythira/hsm/hsm_admin.hpp>
#include <kythira/hsm/hsm_group_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/hsm_peer.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/secure_arena.hpp>
#include <kythira/hsm/session_layer.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>
#include <raft/metrics.hpp>
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

        kythira::hsm::session_options so;
        so.pin_log2_n = _opt.pin_log2_n;
        so.max_login_failures = _opt.max_login_failures;
        so.max_sessions = _opt.max_sessions;
        _layer = std::make_shared<kythira::hsm::session_layer>(*_host, _vault, so);
        _admin = std::make_unique<admin_type>(*_host, _vault,
                                              kythira::hsm::admin_policy{_opt.operators});
        _peer_policy.identities = _opt.peer_identities;
        _peer_policy.allow_plaintext = _opt.insecure_plaintext;
        _host->bootstrap();
    }

    void publish(service_node::module_registry& registry) override {
        registry.publish<kythira::hsm::session_layer>(std::string(session_layer_interface), _layer);
    }

    void start(service_node::module_registry& /*registry*/) override {
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
        _started = true;
        std::cout << "hsm " << kythira::host_node_id_text(_opt.node_id)
                  << " ready: api=" << _server->port()
                  << (_opt.insecure_plaintext ? " (PLAINTEXT)" : " (mutual TLS)")
                  << " members=" << _opt.api_urls.size() << " sealed" << std::endl;
    }

    void drain() override {
        if (_server) {
            _server->stop();
        }
    }

    void stop() override {
        drain();
        if (_host) {
            _host->stop();
        }
        _driving.store(false, std::memory_order_release);
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        _vault.seal();
        _admin.reset();
        _layer.reset();
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
        return {{"sealed", _vault.sealed() ? 1.0 : 0.0, {}},
                {"tokens", static_cast<double>(_host->tokens().size()), {}},
                {"groups_created", static_cast<double>(s.groups_created), {}},
                {"groups_destroyed", static_cast<double>(s.groups_destroyed), {}},
                {"proposals_forwarded", static_cast<double>(s.proposals_forwarded), {}},
                {"read_indexes_forwarded", static_cast<double>(s.read_indexes_forwarded), {}},
                {"proposals_served", static_cast<double>(s.proposals_served), {}},
                {"read_indexes_served", static_cast<double>(s.read_indexes_served), {}},
                {"cached_keys", static_cast<double>(_layer ? _layer->cached_keys() : 0), {}},
                {"raft_term_sum", service_node::raft_term_sum(*_raft), {}}};
    }

    /// The listener's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _server ? _server->port() : 0; }

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
    std::shared_ptr<typename group_sm::context> _ctx;
    std::unique_ptr<raft_host> _raft;
    std::unique_ptr<hsm_host> _host;
    std::shared_ptr<kythira::hsm::session_layer> _layer;
    std::unique_ptr<admin_type> _admin;
    std::shared_ptr<const kythira::hsm::peer_client> _peers;
    kythira::hsm::peer_policy _peer_policy;
    std::unique_ptr<kythira::https::server> _server;
    std::atomic<bool> _driving{false};
    std::thread _driver;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::hsm_node
