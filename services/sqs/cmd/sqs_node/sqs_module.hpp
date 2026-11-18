// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The SQS as a service module, number 9 (.kiro/specs/sqs-compatible-queues/
// task 4, Requirements 1.2 and 5.2): the queues on a multi_raft host over
// the node's Raft transport, kept in the node's key-value engine, and the
// SQS API on its own listener. A send is acknowledged only once its entry
// has committed in its group.
//
// Data directory (the node's sqs/ in kythira_node; the node's own
// directory in sqs_node):
//   engine/                 the key-value engine (catalog and partitions)
//   raft/<group>/           each group's Raft log
//   snapshots/              checkpoints and incoming snapshot transfers
//
// Today the module bootstraps one group over the whole key space with
// every node of KYTHIRA_NODE_PEERS as a voter, and never splits it;
// spreading partitions over groups comes with the independent layers
// (task 12). Any node answers any request: a node that does not lead
// forwards the entry to the leader's SQS listener (sqs_forward.hpp),
// signed with SQS_FORWARD_SECRET, which more than one node requires.
//
// Settings: the SQS_* listener settings of sqs_node_options.hpp, with the
// listener's certificate, key and plaintext switch taken from the node's
// KYTHIRA_NODE_TLS_* and KYTHIRA_NODE_INSECURE_PLAINTEXT when unset, and
//   SQS_PEER_ENDPOINTS  id=scheme://host:port of every node's SQS listener,
//                       where a follower forwards; by default each Raft
//                       peer's host on this node's SQS port
//   SQS_PEER_CA         the CA a forward checks the leader's certificate
//                       against [KYTHIRA_NODE_TLS_CA]
//   SQS_PROPOSE_TIMEOUT_MS  how long a proposal waits to commit [5000]
// and the Raft tuning module_tuning() maps under SQS_ in kythira_node
// (SQS_ELECTION_TIMEOUT_MIN_MS, ...; the bare KYTHIRA_* names in sqs_node).
// The receipt keys must be the same on every node and survive restarts, so
// a durable node needs SQS_RECEIPT_KEYS_FILE or SQS_FORWARD_SECRET.
//
// Layers (task 10, Requirements 11 and 12.1): KYTHIRA_SQS_ROLES picks what
// the node runs, all of gateway, front_end and data by default.
//   - With data, the node holds a replica, runs the leader-side workers,
//     and serves the internal endpoints: propose, named reads, and the
//     availability stream (sqs_availability.hpp).
//   - With front_end (and, on this release, gateway with it), the node
//     serves the SQS API; its handlers reach the data layer through a
//     hybrid_queue_cluster, in-process for the groups held here and over
//     SQS_DATA_ENDPOINTS for the rest. A front end without data follows
//     every data node's availability stream into its long-poll hub.
//   - Without front_end, the listener answers the internal endpoints only.
// A drain ends parked long polls with empty answers before the listener
// stops, so a front end restarts without its clients noticing.

#include <kythira/sqs/sqs_actions.hpp>
#include <kythira/sqs/sqs_availability.hpp>
#include <kythira/sqs/sqs_compat_profile.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_listener.hpp>
#include <kythira/sqs/sqs_long_poll.hpp>
#include <kythira/sqs/sqs_node_options.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>
#include <kythira/sqs/sqs_raft_cluster.hpp>
#include <kythira/sqs/sqs_receipts.hpp>
#include <kythira/sqs/sqs_remote_cluster.hpp>
#include <kythira/sqs/sqs_service.hpp>
#include <kythira/sqs/sqs_workers.hpp>

#include "sns_bridge_setup.hpp"

#include <raft/beast_https_server.hpp>
#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/host_node_id.hpp>
#include <raft/json_serializer.hpp>
#include <raft/metrics.hpp>
#include <raft/module_registry.hpp>
#include <raft/mtls_https_client.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/node_core.hpp>
#include <raft/service_module.hpp>
#include <raft/static_key_authorizer.hpp>
#include <raft/static_keys_file.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::sqs_node {

/// The module's settings beyond the listener's.
struct cluster_options {
    std::filesystem::path _data_dir;
    /// Every node's SQS listener, this one included; empty for one node.
    std::map<kythira::host_node_id, std::string> _peer_endpoints;
    std::vector<kythira::host_node_id> _voters;
    std::string _peer_ca;
    std::chrono::milliseconds _propose_timeout{5000};
    std::chrono::milliseconds _tick_interval{5};
    std::chrono::milliseconds _election_timeout_min{300};
    std::chrono::milliseconds _election_timeout_max{600};
    std::chrono::milliseconds _heartbeat_interval{75};
    std::chrono::milliseconds _rpc_timeout{2000};
    kythira::log_level _log_level{kythira::log_level::info};
};

namespace module_detail {

/// `env`, with the listener's TLS files and plaintext switch falling back
/// to the node's.
[[nodiscard]] inline auto with_node_defaults(service_node::env_lookup env)
    -> service_node::env_lookup {
    return [env = std::move(env)](std::string_view name) -> std::optional<std::string> {
        if (auto v = env(name)) {
            return v;
        }
        if (name == "SQS_TLS_CERT") {
            return env("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "SQS_TLS_KEY") {
            return env("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "SQS_PEER_CA") {
            return env("KYTHIRA_NODE_TLS_CA");
        }
        if (name == "SQS_ALLOW_PLAINTEXT") {
            return env("KYTHIRA_NODE_INSECURE_PLAINTEXT");
        }
        return std::nullopt;
    };
}

[[nodiscard]] inline auto millis(const service_node::env_lookup& env, std::string_view name,
                                 std::chrono::milliseconds fallback) -> std::chrono::milliseconds {
    const auto v = env(name);
    if (!v) {
        return fallback;
    }
    const auto n = sqs::node_options_detail::parse_u64(*v);
    if (!n || *n == 0 || *n > 3'600'000) {
        throw std::invalid_argument(std::string(name) +
                                    " must be 1 to 3600000 milliseconds, got '" + *v + "'");
    }
    return std::chrono::milliseconds(*n);
}

[[nodiscard]] inline auto peer_id(std::string_view what, std::string_view text)
    -> kythira::host_node_id {
    auto id = kythira::parse_host_peer_node_id(text);
    if (!id) {
        throw std::invalid_argument(std::string(what) + ": node id '" + std::string(text) +
                                    "': " + id.error());
    }
    return std::move(id).value();
}

/// `id=url,...`
[[nodiscard]] inline auto parse_endpoints(std::string_view text)
    -> std::map<kythira::host_node_id, std::string> {
    std::map<kythira::host_node_id, std::string> out;
    for (const auto& item : service_node::split_services(std::string(text))) {
        const auto eq = item.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == item.size()) {
            throw std::invalid_argument(
                "SQS_PEER_ENDPOINTS: expected id=scheme://host:port, got '" + item + "'");
        }
        const auto url = item.substr(eq + 1);
        if (!url.starts_with("http://") && !url.starts_with("https://")) {
            throw std::invalid_argument("SQS_PEER_ENDPOINTS: '" + url + "' is not an http(s) URL");
        }
        out[peer_id("SQS_PEER_ENDPOINTS", item.substr(0, eq))] = url;
    }
    return out;
}

[[nodiscard]] inline auto read_file(const std::string& path, std::string_view what) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::invalid_argument("cannot read " + std::string(what) + " " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

[[nodiscard]] inline auto parse_log_level(std::string_view s) -> kythira::log_level {
    if (s == "trace") {
        return kythira::log_level::trace;
    }
    if (s == "debug") {
        return kythira::log_level::debug;
    }
    if (s == "warning" || s == "warn") {
        return kythira::log_level::warning;
    }
    if (s == "error") {
        return kythira::log_level::error;
    }
    return kythira::log_level::info;
}

}  // namespace module_detail

/// The SQS's multi_raft types on a node whose transport is `Host`'s, over
/// the key-value engine `Engine` (RocksDB in production).
template<typename Host, typename Engine> struct module_host_types {
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
    using state_machine_type = sqs::sqs_queue_state_machine<Engine, log_index_type>;

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

template<typename Host, typename Engine>
class sqs_module final : public service_node::service_module<Host> {
public:
    using types = module_host_types<Host, Engine>;
    using raft_host = kythira::multi_raft<types, std::string, std::uint64_t>;
    using raft_config = kythira::multi_raft_config<types, std::string, std::uint64_t>;
    using cluster_type = sqs::raft_queue_cluster<raft_host>;
    using authorizer_type = aws_auth::static_key_authorizer;
    using front_end_type = sqs::sqs_front_end<authorizer_type>;
    using handler_type = sqs::sqs_http_handler<front_end_type>;
    using routed_type = sqs::hybrid_queue_cluster<cluster_type>;
    using service_type = sqs::sqs_service<routed_type>;
    using worker_type = sqs::tick_worker<cluster_type>;
    using mover_type = sqs::move_worker<cluster_type>;
    using grower_type = sqs::grow_worker<cluster_type>;
    using bridge_type = sqs::sns_bridge<service_type>;

    /// The local id of the bootstrap group.
    static constexpr std::uint64_t k_first_group = 1;

    /// @param standalone sqs_node's module: the data directory is the
    ///        node's own and the Raft tuning is read under its bare names.
    explicit sqs_module(bool standalone = false) : _standalone(standalone) {}
    sqs_module(const sqs_module&) = delete;
    auto operator=(const sqs_module&) -> sqs_module& = delete;
    sqs_module(sqs_module&&) = delete;
    auto operator=(sqs_module&&) -> sqs_module& = delete;
    ~sqs_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "sqs"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return service_node::module_numbers::sqs;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override { return "SQS_"; }
    [[nodiscard]] auto data_subdir() const -> std::string override {
        return _standalone ? std::string() : std::string("sqs");
    }

    [[nodiscard]] auto configure(const service_node::env_lookup& raw)
        -> std::optional<std::string> override {
        try {
            const auto env = module_detail::with_node_defaults(
                _standalone ? raw : service_node::module_tuning(raw, "SQS_"));
            auto parsed = sqs::sqs_node_options_from_env(env);
            if (const auto* refused = std::get_if<std::string>(&parsed)) {
                return *refused;
            }
            _opt = std::get<sqs::sqs_node_options>(std::move(parsed));
            auto node = service_node::node_config_from_env(raw);
            if (const auto* refused = std::get_if<std::string>(&node)) {
                return *refused;
            }
            const auto& nc = std::get<service_node::node_config>(node);
            read_cluster_options(env, nc);
            const bool serves_api = _opt.has(layers::role::front_end);
            if (serves_api && _opt._receipt_keys_file.empty() && _opt._forward_secret.empty()) {
                return std::string(
                    "SQS_RECEIPT_KEYS_FILE or SQS_FORWARD_SECRET is required: receipt handles "
                    "must verify on every node and after a restart");
            }
            if (serves_api && _opt._sse_key_file.empty() && _opt._forward_secret.empty()) {
                return std::string(
                    "SQS_SSE_KEY_FILE or SQS_FORWARD_SECRET is required: queues are encrypted "
                    "with SSE-SQS by default and their messages must open on every node and "
                    "after a restart");
            }
            if (_opt.has(layers::role::data) && _cluster_opt._voters.size() > 1 &&
                _opt._forward_secret.empty()) {
                return std::string(
                    "SQS_FORWARD_SECRET is required with more than one node: followers forward "
                    "writes to the leader signed with it");
            }
            const auto profile = sqs::cluster_profile(_opt._compat);
            if (!profile) {
                return "SQS_COMPAT refused: " + profile.error().message.value_or("");
            }
            _service_config._profile = *profile;
            _service_config._receipt_keys =
                !serves_api ? sqs::receipt_key_ring{}
                : _opt._receipt_keys_file.empty()
                    ? sqs::derived_receipt_key(_opt._forward_secret)
                    : sqs::parse_receipt_keys(module_detail::read_file(_opt._receipt_keys_file,
                                                                       "SQS_RECEIPT_KEYS_FILE"));
            if (serves_api) {
                _service_config._sse = sqs::node_sse_keys(
                    _opt._sse_key_file.empty()
                        ? std::string()
                        : module_detail::read_file(_opt._sse_key_file, "SQS_SSE_KEY_FILE"),
                    _opt._forward_secret,
                    _opt._kms == "local"
                        ? std::optional<std::string>(module_detail::read_file(
                              _opt._kms_passphrase_file, "SQS_KMS_PASSPHRASE_FILE"))
                        : std::nullopt);
            }
            _authorizer = std::make_unique<authorizer_type>(
                aws_auth::parse_static_keys(
                    module_detail::read_file(_opt._static_keys_file, "SQS_STATIC_KEYS_FILE")),
                _opt._partition);
            _authorizer->register_service(sqs::sqs_static_roles());
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        return std::nullopt;
    }

    void register_groups(Host& host, const service_node::group_space& space) override {
        _self = host.node_id();
        if (_opt.has(layers::role::data)) {
            register_data(host, space);
        }
        if (!_opt._data_endpoints.empty()) {
            kythira::mtls::client_config dc;
            dc.ca_path = _cluster_opt._peer_ca;
            dc.plaintext = _opt._allow_plaintext;
            dc.client_certificate = false;  // the forwarding HMAC authenticates
            dc.timeout = _cluster_opt._propose_timeout + std::chrono::seconds(2);
            dc.max_body_bytes = _opt._max_body_bytes + 1024;
            _data_client = std::make_shared<kythira::mtls::client>(dc);
            _remote = std::make_unique<sqs::remote_queue_cluster>(
                _opt._data_endpoints, _opt._forward_secret, transport(_data_client));
        }
        if (!_opt.has(layers::role::front_end)) {
            return;
        }
        // One group over the whole key space until task 12: a data node
        // holds every key, so the remote side only serves front ends
        // without the data role.
        _routed = std::make_unique<routed_type>(
            _cluster.get(), _cluster ? nullptr : _remote.get(),
            [this](const std::string&) { return _cluster != nullptr; });
        _service_config._waits = &_hub;
        _service = std::make_unique<service_type>(*_routed, _service_config);
        if (!_cluster) {
            kythira::mtls::client_config fc;
            fc.ca_path = _cluster_opt._peer_ca;
            fc.plaintext = _opt._allow_plaintext;
            fc.client_certificate = false;
            // Longer than the data node holds an availability call.
            fc.timeout = k_feed_wait + std::chrono::seconds(5);
            _feed_client = std::make_shared<kythira::mtls::client>(fc);
            _follower = std::make_unique<sqs::availability_follower>(
                _hub, _opt._data_endpoints, _opt._forward_secret, transport(_feed_client));
        }
    }

    void publish(service_node::module_registry& /*registry*/) override {}

    void start(service_node::module_registry& /*registry*/) override {
        _hub.reopen();
        if (_raft) {
            _feed = std::make_unique<sqs::availability_feed>();
            _feed_ptr.store(_feed.get(), std::memory_order_release);
            _raft->start();
            _worker->start();
            _mover->start();
            _grower->start();
            _driving = true;
            _driver = std::thread([this] {
                while (_driving.load(std::memory_order_acquire)) {
                    try {
                        (void)_raft->tick();
                    } catch (const std::exception& e) {
                        std::cerr << "sqs: tick failed: " << e.what() << std::endl;
                    }
                    std::this_thread::sleep_for(_cluster_opt._tick_interval);
                }
            });
        }
        if (_follower) {
            _follower->start();
        }

        https::server_config hc;
        hc.bind_address = _opt._listen_host;
        hc.port = _opt._listen_port;
        hc.tls_cert_path = _opt._tls_cert_path;
        hc.tls_key_path = _opt._tls_key_path;
        hc.insecure_plaintext = _opt._allow_plaintext;
        hc.max_body_bytes = _opt._max_body_bytes;
        // The front end needs the endpoint, which may need the port the
        // listener picks, so the handler is bound late; a request before
        // it is answered 503.
        _server = std::make_unique<https::server>(
            hc,
            [this](const https::request& req, const https::request_context& ctx) {
                if (auto* h = _handler.load(std::memory_order_acquire)) {
                    ++_requests;
                    return (*h)(req, ctx);
                }
                https::response r{boost::beast::http::status::service_unavailable, req.version()};
                r.prepare_payload();
                return r;
            },
            [](bool warning, std::string_view message) {
                std::cerr << "sqs: listener: " << (warning ? "warning: " : "") << message
                          << std::endl;
            });
        _server->start();
        sqs::sqs_front_end_config fc;
        fc._region = _opt._region;
        fc._partition = _opt._partition;
        fc._limits.max_body_bytes = _opt._max_body_bytes;
        fc._endpoint = _opt._endpoint.empty()
                           ? std::string(_opt._allow_plaintext ? "http" : "https") +
                                 "://localhost:" + std::to_string(_server->port())
                           : _opt._endpoint;
        _front_end = std::make_unique<front_end_type>(fc, *_authorizer);
        if (_service) {
            _service->register_with(*_front_end);
        }
        sqs::local_proposer propose;
        if (_cluster) {
            propose = [this](const std::string& key, std::vector<std::byte> entry) {
                ++_peer_requests;
                return _cluster->propose_local(key, std::move(entry));
            };
        }
        _handler_owner =
            std::make_unique<handler_type>(*_front_end, _opt._forward_secret, std::move(propose));
        _handler_owner->set_client_api(_service != nullptr);
        if (_cluster) {
            _handler_owner->set_local_query([this](const sqs::data_query& q) {
                ++_peer_requests;
                return _cluster->query(q);
            });
            _handler_owner->set_availability_feed(_feed.get(), k_feed_wait);
        }
        if (_opt._sns_bridge && _service) {
            _bridge = std::make_unique<bridge_type>(*_service,
                                                    sqs::sns_bridge_settings(_opt, fc._endpoint));
            _handler_owner->set_sns_bridge(
                [this](std::string_view method, std::string_view path, std::string_view body) {
                    const auto r = _bridge->handle(method, path, body);
                    return std::pair{r._status, r._body};
                });
        }
        _handler.store(_handler_owner.get(), std::memory_order_release);
        _started = true;
        std::cout << "sqs " << kythira::host_node_id_text(_self)
                  << " ready: roles=" << _opt._roles.to_string()
                  << " nodes=" << std::max<std::size_t>(1, _cluster_opt._voters.size())
                  << " api=" << _server->port() << (_opt._allow_plaintext ? " (http)" : " (https)")
                  << " queue URLs on " << fc._endpoint << std::endl;
    }

    /// No request in flight once the listener has stopped. Parked long
    /// polls answer empty first (Requirement 12.1).
    void drain() override {
        _hub.close();
        if (auto* f = _feed_ptr.load(std::memory_order_acquire)) {
            f->close();  // front ends' availability calls answer now
        }
        if (_server) {
            _server->stop();
        }
    }

    void stop() override {
        drain();
        if (_follower) {
            _follower->stop();
        }
        if (_worker) {
            _worker->stop();
        }
        if (_mover) {
            _mover->stop();
        }
        if (_grower) {
            _grower->stop();
        }
        _driving.store(false, std::memory_order_release);
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        // Everything that refers to the host goes before it.
        _handler.store(nullptr, std::memory_order_release);
        _server.reset();
        _handler_owner.reset();
        _front_end.reset();
        _bridge.reset();
        _service.reset();
        _routed.reset();
        _follower.reset();
        _remote.reset();
        _data_client.reset();
        _feed_client.reset();
        _worker_ptr.store(nullptr, std::memory_order_release);
        _worker.reset();
        _mover.reset();
        _grower.reset();
        _cluster.reset();
        _peers.reset();
        _raft.reset();
        _feed_ptr.store(nullptr, std::memory_order_release);
        _feed.reset();
        _started = false;
    }

    /// The API's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _server ? _server->port() : 0; }

    [[nodiscard]] auto health() const -> service_node::module_health override {
        if (!_started) {
            return {false, "not started"};
        }
        return {true, ""};
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> override {
        if (!_started) {
            return {};
        }
        std::vector<service_node::module_metric> out{
            {"requests", static_cast<double>(_requests.load()), {}},
            {"peer_requests", static_cast<double>(_peer_requests.load()), {}},
            {"long_polls_parked", static_cast<double>(_hub.parked()), {}},
            {"long_polls_woken", static_cast<double>(_hub.notified()), {}},
            {"sns_bridge_delivered", static_cast<double>(_bridge ? _bridge->delivered() : 0), {}},
        };
        if (_follower) {
            out.push_back({"availability_batches", static_cast<double>(_follower->batches()), {}});
        }
        if (!_raft || !_cluster) {
            return out;
        }
        for (auto m : std::vector<service_node::module_metric>{
                 {"proposals_forwarded", static_cast<double>(_cluster->forwarded_count()), {}},
                 {"forward_failures", static_cast<double>(_forward_failures.load()), {}},
                 {"ticks_proposed", static_cast<double>(_worker ? _worker->ticks() : 0), {}},
                 {"messages_moved", static_cast<double>(_mover ? _mover->moved() : 0), {}},
                 {"partitions_grown", static_cast<double>(_grower ? _grower->grown() : 0), {}},
                 {"raft_term_sum", service_node::raft_term_sum(*_raft), {}},
             }) {
            out.push_back(std::move(m));
        }
        return out;
    }

private:
    bool _standalone;
    sqs::sqs_node_options _opt;
    cluster_options _cluster_opt;
    sqs::sqs_service_config _service_config;
    kythira::host_node_id _self{};

    std::unique_ptr<authorizer_type> _authorizer;
    std::unique_ptr<raft_host> _raft;
    std::unique_ptr<kythira::mtls::client> _peers;
    std::unique_ptr<cluster_type> _cluster;
    /// The data layer over SQS_DATA_ENDPOINTS, when given.
    std::shared_ptr<kythira::mtls::client> _data_client;
    std::unique_ptr<sqs::remote_queue_cluster> _remote;
    /// What the handlers use: `_cluster` here, `_remote` for the rest.
    std::unique_ptr<routed_type> _routed;
    std::unique_ptr<service_type> _service;
    sqs::availability_hub _hub;
    /// A data node's wake-up stream for front ends without the data role.
    std::unique_ptr<sqs::availability_feed> _feed;
    std::atomic<sqs::availability_feed*> _feed_ptr{nullptr};
    /// A front end without the data role: follows the data nodes' feeds.
    std::shared_ptr<kythira::mtls::client> _feed_client;
    std::unique_ptr<sqs::availability_follower> _follower;
    std::unique_ptr<worker_type> _worker;
    /// For the state machines' listener, which may run before the worker
    /// exists or after it has gone.
    std::atomic<worker_type*> _worker_ptr{nullptr};
    /// Runs the message move tasks of the queues this node leads.
    std::unique_ptr<mover_type> _mover;
    /// Grows standard queues' partition counts with their send rates.
    std::unique_ptr<grower_type> _grower;
    /// Real SNS's HTTPS deliveries, when `SQS_SNS_BRIDGE=on`.
    std::unique_ptr<bridge_type> _bridge;
    std::unique_ptr<front_end_type> _front_end;
    std::unique_ptr<handler_type> _handler_owner;
    std::atomic<handler_type*> _handler{nullptr};
    std::unique_ptr<https::server> _server;

    std::atomic<bool> _driving{false};
    std::thread _driver;
    bool _started = false;
    std::atomic<std::uint64_t> _requests{0};
    std::atomic<std::uint64_t> _peer_requests{0};
    std::atomic<std::uint64_t> _forward_failures{0};

    /// How long a data node holds a front end's availability call.
    static constexpr std::chrono::milliseconds k_feed_wait{10000};

    /// The replica, Raft host and leader-side workers of the data role.
    void register_data(Host& host, const service_node::group_space& space) {
        for (const auto* sub : {"engine", "raft", "snapshots"}) {
            std::filesystem::create_directories(_cluster_opt._data_dir / sub);
        }
        _raft = std::make_unique<raft_host>(make_raft_config(host, space));
        auto voters = _cluster_opt._voters;
        if (voters.empty()) {
            voters.push_back(_self);
        }
        _raft->create_group(space.to_host(k_first_group), voters);

        kythira::mtls::client_config pc;
        pc.ca_path = _cluster_opt._peer_ca;
        pc.plaintext = _opt._allow_plaintext;
        pc.client_certificate = false;  // the forwarding HMAC authenticates
        pc.timeout = _cluster_opt._propose_timeout + std::chrono::seconds(2);
        pc.max_body_bytes = _opt._max_body_bytes + 1024;
        _peers = std::make_unique<kythira::mtls::client>(pc);
        _cluster = std::make_unique<cluster_type>(
            *_raft,
            [this](const kythira::host_node_id& leader, const std::string& key,
                   const std::vector<std::byte>& entry) { return forward(leader, key, entry); },
            _cluster_opt._propose_timeout);
        _worker = std::make_unique<worker_type>(
            *_cluster, [this](const std::string& key) { return _cluster->leads(key); });
        _worker_ptr.store(_worker.get(), std::memory_order_release);
        _mover = std::make_unique<mover_type>(
            *_cluster, [this](const std::string& key) { return _cluster->leads(key); },
            sqs::sqs_arn_queue);
        _grower = std::make_unique<grower_type>(
            *_cluster, [this](const std::string& key) { return _cluster->leads(key); });
    }

    /// Internal calls to the data nodes over `client`.
    [[nodiscard]] static auto transport(std::shared_ptr<kythira::mtls::client> client)
        -> sqs::data_transport {
        return
            [client = std::move(client)](
                const std::string& base, const std::string& path,
                const std::vector<std::pair<std::string, std::string>>& headers, std::string body) {
                return client->request("POST", base, path, std::move(body),
                                       "application/octet-stream", "kythira-sqs", headers);
            };
    }

    void read_cluster_options(const service_node::env_lookup& env,
                              const service_node::node_config& nc) {
        using module_detail::millis;
        _cluster_opt = cluster_options{};
        auto& c = _cluster_opt;
        c._data_dir = nc.data_dir / data_subdir();
        for (const auto& p : nc.peers) {
            c._voters.push_back(module_detail::peer_id("KYTHIRA_NODE_PEERS", p.id));
        }
        if (const auto v = env("SQS_PEER_ENDPOINTS"); v && !v->empty()) {
            c._peer_endpoints = module_detail::parse_endpoints(*v);
        } else if (c._voters.size() > 1) {
            if (_opt._listen_port == 0) {
                throw std::invalid_argument(
                    "SQS_PEER_ENDPOINTS is required when SQS_LISTEN picks its port (0)");
            }
            const std::string scheme = _opt._allow_plaintext ? "http://" : "https://";
            for (std::size_t i = 0; i < nc.peers.size(); ++i) {
                const auto& host = nc.peers[i].host;
                const bool v6 = host.find(':') != std::string::npos;
                c._peer_endpoints[c._voters[i]] = scheme + (v6 ? "[" + host + "]" : host) + ":" +
                                                  std::to_string(_opt._listen_port);
            }
        }
        for (const auto& id : c._voters) {
            if (c._voters.size() > 1 && !c._peer_endpoints.contains(id)) {
                throw std::invalid_argument("SQS_PEER_ENDPOINTS does not name node " +
                                            kythira::host_node_id_text(id));
            }
        }
        c._peer_ca = env("SQS_PEER_CA").value_or("");
        if (!_opt._allow_plaintext && c._voters.size() > 1 && c._peer_ca.empty()) {
            throw std::invalid_argument(
                "SQS_PEER_CA (or KYTHIRA_NODE_TLS_CA) is required to forward over TLS");
        }
        c._propose_timeout = millis(env, "SQS_PROPOSE_TIMEOUT_MS", c._propose_timeout);
        c._tick_interval = millis(env, "KYTHIRA_TICK_INTERVAL_MS", c._tick_interval);
        c._election_timeout_min =
            millis(env, "KYTHIRA_ELECTION_TIMEOUT_MIN_MS", c._election_timeout_min);
        c._election_timeout_max =
            millis(env, "KYTHIRA_ELECTION_TIMEOUT_MAX_MS", c._election_timeout_max);
        if (c._election_timeout_min > c._election_timeout_max) {
            throw std::invalid_argument(
                "the election timeout minimum exceeds its maximum (KYTHIRA_ELECTION_TIMEOUT_*_MS)");
        }
        c._heartbeat_interval = millis(env, "KYTHIRA_HEARTBEAT_INTERVAL_MS", c._heartbeat_interval);
        c._rpc_timeout = millis(env, "KYTHIRA_RPC_TIMEOUT_MS", c._rpc_timeout);
        c._log_level = module_detail::parse_log_level(env("KYTHIRA_LOG_LEVEL").value_or("info"));
    }

    auto make_raft_config(Host& host, const service_node::group_space& space) -> raft_config {
        const auto raft_dir = _cluster_opt._data_dir / "raft";
        raft_config cfg{
            .node_id = _self,
            .network_client = typename types::network_client_type{host.client()},
            .network_server = host.server_for(space),
            .store_factory =
                [raft_dir](const std::uint64_t& group) {
                    return
                        typename types::persistence_engine_type{raft_dir / std::to_string(group)};
                },
        };
        if constexpr (std::is_constructible_v<Engine, std::filesystem::path>) {
            cfg.state_engine = std::make_shared<Engine>(_cluster_opt._data_dir / "engine");
        } else {
            cfg.state_engine = std::make_shared<Engine>();  // memory_kv_engine, in tests
        }
        cfg.state_machine_factory = [this](const std::uint64_t&) {
            typename types::state_machine_type sm;
            sm.set_availability_listener([this](const sqs::queue_target& t, bool visible) {
                if (visible) {
                    const auto key = sqs::queue_keys::partition_prefix(t);
                    _hub.notify(key);
                    if (auto* f = _feed_ptr.load(std::memory_order_acquire)) {
                        f->publish(key);
                    }
                }
                if (auto* w = _worker_ptr.load(std::memory_order_acquire)) {
                    w->wake();
                }
            });
            return sm;
        };
        cfg.automatic_split_merge_enabled = false;  // one group until task 12
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.logger = kythira::console_logger{_cluster_opt._log_level};
        cfg.logger_factory = [level = _cluster_opt._log_level](const std::uint64_t&) {
            return kythira::console_logger{level};
        };
        cfg.config._election_timeout_min = _cluster_opt._election_timeout_min;
        cfg.config._election_timeout_max = _cluster_opt._election_timeout_max;
        cfg.config._heartbeat_interval = _cluster_opt._heartbeat_interval;
        cfg.config._rpc_timeout = _cluster_opt._rpc_timeout;
        cfg.config._snapshot_staging_directory = _cluster_opt._data_dir / "snapshots";
        return cfg;
    }

    /// Sends `entry` to the leader's listener; what it committed, or
    /// nothing (the client retries).
    auto forward(const kythira::host_node_id& leader, const std::string& key,
                 const std::vector<std::byte>& entry) -> std::optional<std::vector<std::byte>> {
        const auto it = _cluster_opt._peer_endpoints.find(leader);
        if (it == _cluster_opt._peer_endpoints.end() || _opt._forward_secret.empty()) {
            ++_forward_failures;
            return std::nullopt;
        }
        auto body = sqs::forward::encode_body({._key = key, ._entry = entry});
        const auto signature =
            sqs::forward::sign(_opt._forward_secret, body, std::chrono::system_clock::now());
        const auto r = _peers->request("POST", it->second, std::string(sqs::forward::k_path),
                                       std::move(body), "application/octet-stream", "kythira-sqs",
                                       {{std::string(sqs::forward::k_header), signature}});
        if (!r || r->first != 200) {
            ++_forward_failures;
            return std::nullopt;
        }
        std::vector<std::byte> out(r->second.size());
        std::memcpy(out.data(), r->second.data(), r->second.size());
        return out;
    }
};

}  // namespace kythira::sqs_node
