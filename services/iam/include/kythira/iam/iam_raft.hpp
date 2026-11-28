// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file iam_raft.hpp
/// @brief IAM's Raft group on a multi-raft host, as iam_node, the IAM
///        module of kythira_node and a front end's embedded read replica
///        all run it (.kiro/specs/service-colocation/ task 8, Requirements
///        5.1-5.3).
///
/// - **The group.** IAM is one Raft group with the IAM state machine,
///   `k_iam_group_id`, in every layout. That id is in IAM's range of a
///   composite node (module 5, `5 << 56`) and is also what stand-alone
///   iam_node uses, so a member's data directory moves between iam_node
///   and kythira_node unchanged, and a read replica joins either without
///   knowing which it is.
/// - **The transport.** `iam_raft_stack`: Boost.Beast with the CBOR wire,
///   as kythira_node's Raft listener. With TLS, both ends present
///   certificates from the Kythira CA.
/// - **Trust.** `iam_raft_trust` binds each certificate to one node id, as
///   iam_node's TCP RPC always did (tls_rpc_trust_policy::peer_node_ids):
///   a certificate the CA chains is a peer only if it carries the reserved
///   peer SAN of a member or registered replica, and speaks only for that
///   node. A replica registered later is added at run time.
///
/// Declarations only: a translation unit that builds an `iam_raft_stack`
/// or a host on it includes raft/beast_http_transport_impl.hpp and
/// raft/multi_raft_impl.hpp, as a composition root (boundary-allow.txt).

#include <kythira/iam/iam_state_machine.hpp>

#include <raft/beast_http_transport.hpp>
#include <raft/binary_file_persistence.hpp>
#include <raft/ca_http_helpers.hpp>
#include <raft/cbor_serializer.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/host_node_id.hpp>
#include <raft/json_serializer.hpp>
#include <raft/membership.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/tls_tcp_rpc.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kythira::iam {

/// IAM's module number in a composite node (service_module.hpp's
/// `module_numbers::iam`, which iam_module.hpp checks against this).
inline constexpr std::uint8_t k_iam_module_number = 5;

/// The IAM group's id on every host: the first id of IAM's composite range.
inline constexpr std::uint64_t k_iam_group_id = (std::uint64_t{k_iam_module_number} << 56) | 1;

/// IAM's multi_raft types over a transport client `Client` and the
/// listener view `Server` its groups receive on.
template<typename Client, typename Server> struct iam_host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = kythira::host_node_id;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    /// Not used by the host: the wire is the transport's.
    using serializer_type = kythira::json_rpc_serializer<std::vector<std::byte>>;

    using network_client_type = kythira::transport_client_handle<Client, node_id_type>;
    using network_server_type = Server;

    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = iam_state_machine;

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

/// Raft timing for the IAM group.
struct iam_raft_timing {
    std::chrono::milliseconds election_timeout_min{500};
    std::chrono::milliseconds election_timeout_max{1000};
    std::chrono::milliseconds heartbeat_interval{100};
    std::chrono::milliseconds rpc_timeout{1000};
};

/// Where a member keeps the IAM group's Raft log and snapshots: under
/// `data_dir`, as `raft/<group id>`.
[[nodiscard]] inline auto iam_raft_dir(const std::filesystem::path& data_dir)
    -> std::filesystem::path {
    return data_dir / "raft";
}

/// The multi_raft settings every IAM host uses: one group, never split or
/// merged, never hibernating (a replica's staleness bound counts on
/// heartbeats), with each group's files in `iam_raft_dir`, opened with
/// `log_options` (a key ring when the node seals its Raft logs at rest,
/// `.kiro/specs/raft-log-encryption/`).
template<typename Types>
[[nodiscard]] auto iam_raft_config(const kythira::host_node_id& self,
                                   typename Types::network_client_type client,
                                   typename Types::network_server_type server,
                                   const std::filesystem::path& data_dir, std::string partition,
                                   const iam_raft_timing& timing, log_level level,
                                   kythira::binary_file_persistence_options log_options = {})
    -> kythira::multi_raft_config<Types, std::string, std::uint64_t> {
    const auto raft_dir = iam_raft_dir(data_dir);
    std::filesystem::create_directories(raft_dir);
    kythira::multi_raft_config<Types, std::string, std::uint64_t> rc{
        .node_id = self,
        .network_client = std::move(client),
        .network_server = std::move(server),
        .store_factory =
            [raft_dir, log_options = std::move(log_options)](const std::uint64_t& group) {
                return typename Types::persistence_engine_type{raft_dir / std::to_string(group),
                                                               log_options};
            },
    };
    rc.state_machine_factory = [partition = std::move(partition)](const std::uint64_t&) {
        return iam_state_machine(iam_config{.partition = partition});
    };
    rc.automatic_split_merge_enabled = false;
    rc.hibernation = kythira::hibernation_mode::off;
    rc.logger = kythira::console_logger{level};
    rc.logger_factory = [level](const std::uint64_t&) { return kythira::console_logger{level}; };
    rc.config._election_timeout_min = timing.election_timeout_min;
    rc.config._election_timeout_max = timing.election_timeout_max;
    rc.config._heartbeat_interval = timing.heartbeat_interval;
    rc.config._rpc_timeout = timing.rpc_timeout;
    return rc;
}

/// The IAM group's descriptor: every key, the voters, and the learners (a
/// read replica names itself).
[[nodiscard]] inline auto iam_group_descriptor(std::vector<kythira::host_node_id> voters,
                                               std::vector<kythira::host_node_id> learners = {})
    -> kythira::shard_descriptor<std::uint64_t, std::string, kythira::host_node_id> {
    return {
        ._group_id = k_iam_group_id,
        ._range = kythira::shard_range<std::string>{._start = std::nullopt, ._end = std::nullopt},
        ._epoch = kythira::shard_epoch{},
        ._voters = std::move(voters),
        ._learners = std::move(learners)};
}

/// Drives a multi_raft host's timers until stopped: every 10 ms, as the
/// other modules' hosts are driven.
class iam_raft_driver {
public:
    iam_raft_driver() = default;
    iam_raft_driver(const iam_raft_driver&) = delete;
    auto operator=(const iam_raft_driver&) -> iam_raft_driver& = delete;
    iam_raft_driver(iam_raft_driver&&) = delete;
    auto operator=(iam_raft_driver&&) -> iam_raft_driver& = delete;
    ~iam_raft_driver() { stop(); }

    template<typename Host> void start(Host& host, std::string log_name) {
        _running.store(true, std::memory_order_release);
        _thread = std::thread([this, &host, log_name = std::move(log_name)] {
            while (_running.load(std::memory_order_acquire)) {
                try {
                    (void)host.tick();
                } catch (const std::exception& e) {
                    console_logger{log_level::error}.log(
                        log_level::error, log_name + ": raft tick failed: " + e.what(), {});
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    void stop() {
        _running.store(false, std::memory_order_release);
        if (_thread.joinable()) {
            _thread.join();
        }
    }

private:
    std::atomic<bool> _running{false};
    std::thread _thread;
};

/// The certificates a member accepts on Raft: chained to the Kythira CA
/// and carrying the reserved peer SAN of a node it knows, each bound to
/// that node. Shared by the listener's binding and the client's check, so
/// a replica added later (`add`) is trusted by both at once.
class iam_raft_trust {
public:
    using node_id_type = kythira::host_node_id;

    /// @param ca_pem the Kythira CA root.
    /// @param nodes the members (and, on a replica, the voters) to trust.
    iam_raft_trust(std::string ca_pem, const std::vector<node_id_type>& nodes)
        : _state(std::make_shared<state>()) {
        _state->ca = std::move(ca_pem);
        for (const auto& id : nodes) {
            _state->ids[raft::testing::peer_identity_name(id)] = id;
        }
        _state->rebuild();
    }

    /// Trusts `id` too, from now on.
    void add(const node_id_type& id) {
        const std::lock_guard lock(_state->mu);
        _state->ids[raft::testing::peer_identity_name(id)] = id;
        _state->rebuild();
    }

    /// For `boost_beast_server::set_peer_binding`: the client certificate
    /// must be a trusted node's and that node must be the sender.
    [[nodiscard]] auto binding() const -> std::function<bool(X509*, const node_id_type&)> {
        return [s = _state](X509* presented, const node_id_type& sender) {
            const std::lock_guard lock(s->mu);
            return s->policy.accepts(presented) && s->policy.binds(presented, sender);
        };
    }

    /// For `boost_beast_client::set_peer_check`: the server certificate
    /// must be the trusted node dialled.
    [[nodiscard]] auto check() const -> std::function<bool(X509*, const node_id_type&)> {
        return binding();
    }

private:
    struct state {
        std::mutex mu;
        std::string ca;
        std::map<std::string, node_id_type> ids;
        kythira::basic_tls_rpc_trust_policy<node_id_type> policy;

        void rebuild() {
            policy = kythira::ca_root_only<node_id_type>(ca).binding_peer_node_ids(ids);
        }
    };
    std::shared_ptr<state> _state;
};

/// The IAM Raft transport's TLS material: this node's certificate (which
/// must carry its reserved peer SAN) and key, and the Kythira CA.
struct iam_raft_tls {
    std::string cert;
    std::string key;
    std::string ca;
};

/// `http://` or `https://` and `host:port`, a bracketed IPv6 literal
/// included, as the transport's client dials a node.
[[nodiscard]] inline auto iam_raft_url(bool tls, const std::string& host, std::uint16_t port)
    -> std::string {
    const bool v6 = host.find(':') != std::string::npos && !host.starts_with('[');
    return std::string(tls ? "https://" : "http://") + (v6 ? "[" + host + "]" : host) + ":" +
           std::to_string(port);
}

/// The whole contents of `path`.
/// @throws std::runtime_error when it cannot be read.
[[nodiscard]] inline auto iam_read_file(const std::string& path) -> std::string {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot read " + path);
    }
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

/// IAM's own Raft transport, where IAM is not on kythira_node's: iam_node
/// and a front end's embedded replica. Boost.Beast with the CBOR wire,
/// mutual TLS bound by `iam_raft_trust` when `tls` is given, plain HTTP
/// otherwise.
class iam_raft_stack {
public:
    using serializer_type = kythira::cbor_rpc_serializer<std::vector<std::byte>>;
    using bundle = kythira::host_transport_types<serializer_type>;
    using client_type = kythira::boost_beast_client<bundle, kythira::host_node_id>;
    using server_type = kythira::boost_beast_server<bundle, kythira::host_node_id>;

    /// The largest Raft request the listener takes: an InstallSnapshot of
    /// the whole IAM state included.
    static constexpr std::size_t k_max_body_bytes = std::size_t{64} * 1024 * 1024;

    /// @param peers each node this one dials, by URL (`iam_raft_url`).
    /// @param trust with `tls`, who is a peer; ignored without.
    iam_raft_stack(const std::string& bind, std::uint16_t port,
                   std::unordered_map<kythira::host_node_id, std::string> peers,
                   const std::optional<iam_raft_tls>& tls, std::shared_ptr<iam_raft_trust> trust)
        : _work(boost::asio::make_work_guard(*_ioc)),
          _server(*_ioc, bind, port, server_config(tls), kythira::noop_metrics{}),
          _client(std::in_place, *_ioc, std::move(peers), client_config(tls),
                  kythira::noop_metrics{}, _ioc) {
        if (tls) {
            if (!trust) {
                throw std::invalid_argument("iam_raft_stack: TLS needs the peers to trust");
            }
            _server.set_peer_binding(trust->binding());
            _client->set_peer_check(trust->check());
        }
        // A peer that speaks to this node tells the client where it is, for
        // names that do not resolve yet (bounded_resolver.hpp).
        _server.set_peer_seen_handler(_client->peer_seen_handler());
        const auto threads = std::max(2U, std::thread::hardware_concurrency() / 4);
        for (unsigned i = 0; i < threads; ++i) {
            _threads.emplace_back([this] { _ioc->run(); });
        }
    }

    iam_raft_stack(const iam_raft_stack&) = delete;
    auto operator=(const iam_raft_stack&) -> iam_raft_stack& = delete;
    iam_raft_stack(iam_raft_stack&&) = delete;
    auto operator=(iam_raft_stack&&) -> iam_raft_stack& = delete;
    ~iam_raft_stack() { shutdown(); }

    [[nodiscard]] auto client() -> client_type& { return *_client; }
    [[nodiscard]] auto server() -> server_type& { return _server; }

    /// Stops the transport, after the host on it has stopped.
    void shutdown() {
        if (_stopped.exchange(true)) {
            return;
        }
        // The client first, while the threads still run: its destructor
        // waits for each RPC in flight to reach its handler, which only
        // these threads run.
        _client.reset();
        _server.stop();
        _work.reset();
        _ioc->stop();
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        _threads.clear();
    }

private:
    static auto server_config(const std::optional<iam_raft_tls>& tls)
        -> kythira::boost_beast_server_config {
        kythira::boost_beast_server_config s;
        s.max_request_body_size = k_max_body_bytes;
        if (tls) {
            s.enable_ssl = true;
            s.ssl_cert_path = tls->cert;
            s.ssl_key_path = tls->key;
            s.ca_cert_path = tls->ca;
            s.require_client_cert = true;
        }
        return s;
    }

    static auto client_config(const std::optional<iam_raft_tls>& tls)
        -> kythira::boost_beast_client_config {
        kythira::boost_beast_client_config c;
        if (tls) {
            c.enable_ssl_verification = true;
            c.ca_cert_path = tls->ca;
            c.client_cert_path = tls->cert;
            c.client_key_path = tls->key;
        }
        return c;
    }

    std::shared_ptr<boost::asio::io_context> _ioc{std::make_shared<boost::asio::io_context>()};
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> _work;
    server_type _server;
    /// Reset by `shutdown`, before the threads stop.
    std::optional<client_type> _client;
    std::vector<std::thread> _threads;
    std::atomic<bool> _stopped{false};
};

}  // namespace kythira::iam
