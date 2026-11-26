// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// The layer migration paths, each walked both ways on a running cluster
/// under a mixed workload (.kiro/specs/redis-general-data-types/ task 20,
/// Requirements 21.5 and 24.1-24.4).
///
/// Six node slots share one in-process Raft fabric and keep their RESP
/// port across restarts, so a role change is what an operator does: drain
/// the node, start it again with a new `KYTHIRA_REDIS_ROLES`. The path:
///
///   co-located 1-3
///   -> data split, stopped and reversed midway, then done (1 -> 4)
///   -> gateway+front end apart from data (2 -> 5, 3 -> 6)
///   -> three-way: gateway 1, front ends 2-3, data 4-6
///   -> and back the same way to co-located 1-3.
///
/// Workers keep writing through whichever nodes serve clients. After every
/// step the checks run: every acknowledged write is readable, every
/// cross-shard MSET and MULTI/EXEC is all-or-nothing (acknowledged or
/// not), and every deadline is intact.
///
/// The workload is the command surface the gateway ships today: SET,
/// SETEX, MSET and MULTI/EXEC across both shards. Counters, `SET NX`
/// locks, hashes, lists, RENAME and a long SCAN join it as their tasks (3,
/// 6, 7, 9, 12) ship; each of those tasks carries that step.

#define BOOST_TEST_MODULE redis_layer_paths_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"
#include "test_ports.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <raft/txn_state_machine.hpp>

#include <kythira/redis/redis_evacuation.hpp>
#include <kythira/redis/redis_gateway_impl.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <boost/asio.hpp>

#include <sys/socket.h>
#include <sys/time.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("redis_layer_paths_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

using namespace std::chrono_literals;

namespace {

namespace ev = kythira::redis_evacuation;
namespace layers = kythira::layers;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

using kv_type = kythira::redis_kv_state_machine<std::uint64_t>;
using txn_sm_type =
    kythira::transactional_state_machine<kv_type, key_type, kythira::redis_kv_partitioner>;

struct host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;
    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;
    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;
    using network_client_type = fabric_client;
    using network_server_type = fabric_server;
    using persistence_engine_type =
        kythira::memory_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = txn_sm_type;
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

using host_type = kythira::multi_raft<host_types, key_type, group_id_type>;
using config_type = kythira::multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = kythira::shard_descriptor<group_id_type, key_type, node_id_t>;
using gateway_type =
    kythira::redis_gateway<host_type, kythira::console_logger, kythira::noop_metrics>;
using controller_type = ev::controller<host_type>;

constexpr std::uint32_t k_kdf_iters = 1000;
constexpr node_id_t k_slots = 6;

const layers::role_set k_all{layers::role::gateway, layers::role::front_end, layers::role::data};
const layers::role_set k_data{layers::role::data};
const layers::role_set k_gw_fe{layers::role::gateway, layers::role::front_end};
const layers::role_set k_fe{layers::role::front_end};
const layers::role_set k_gw{layers::role::gateway};

auto acl_text() -> std::string {
    return "user ops " + kythira::redis_acl::hash_secret("ops-secret", k_kdf_iters) + " admin *\n" +
           "user farm " + kythira::redis_acl::hash_secret("farm-secret", k_kdf_iters) +
           " read_write *\n" + "user kythira-internal " +
           kythira::redis_acl::hash_secret("internal-secret", k_kdf_iters) + " read_write *\n";
}

auto bulk(const std::string& s) -> std::string {
    return "$" + std::to_string(s.size()) + "\r\n" + s + "\r\n";
}

/// A RESP client that gives up on a silent server after `timeout`, so a
/// lost reply is an error, never a hang.
class resp_client {
public:
    explicit resp_client(std::uint16_t port, std::chrono::seconds timeout = 15s) : _socket(_io) {
        _socket.connect({boost::asio::ip::make_address("127.0.0.1"), port});
        timeval tv{};
        tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout.count());
        ::setsockopt(_socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    auto call(const std::vector<std::string>& argv) -> std::string {
        std::string out = "*" + std::to_string(argv.size()) + "\r\n";
        for (const auto& a : argv) {
            out += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
        }
        boost::asio::write(_socket, boost::asio::buffer(out));
        std::size_t len = 0;
        while ((len = kythira::resp_reply_length(_buffer)) == 0) {
            std::array<char, 65536> chunk{};
            boost::system::error_code ec;
            const auto n = _socket.read_some(boost::asio::buffer(chunk), ec);
            if (ec) {
                throw std::runtime_error("connection lost: " + ec.message());
            }
            _buffer.append(chunk.data(), n);
        }
        auto reply = _buffer.substr(0, len);
        _buffer.erase(0, len);
        return reply;
    }

private:
    boost::asio::io_context _io;
    boost::asio::ip::tcp::socket _socket;
    std::string _buffer;
};

/// Six nodes on one fabric. Nodes 1-3 found groups 1 (to "m") and 2 (from
/// "m"); 4-6 hold nothing until a group adds them. Each node keeps its
/// Raft host for the whole case; its gateway is what a restart replaces.
class layout_cluster {
public:
    layout_cluster() {
        _acl.reload(acl_text());
        const auto base = kythira::testing::free_port_block(static_cast<std::uint16_t>(k_slots));
        for (node_id_t id = 1; id <= k_slots; ++id) {
            auto& s = _slots[id - 1];
            s._port = static_cast<std::uint16_t>(base + id - 1);
            s._host = std::make_unique<host_type>(make_config(id));
            if (id <= 3) {
                for (const auto& d : founding_groups()) {
                    s._host->create_group(d);
                }
            }
        }
        for (auto& s : _slots) {
            s._host->start();
        }
        for (node_id_t id = 1; id <= k_slots; ++id) {
            _controllers[id - 1] = make_controller(id);
        }
        _ready = true;
        for (node_id_t id = 1; id <= k_slots; ++id) {
            start_driver(id);
        }
    }

    ~layout_cluster() {
        for (node_id_t id = 1; id <= k_slots; ++id) {
            stop_driver(id);
        }
        for (auto& c : _controllers) {
            c->stop();
        }
        for (node_id_t id = 1; id <= k_slots; ++id) {
            stop(id);
        }
        for (auto& s : _slots) {
            s._host->stop();
        }
    }

    layout_cluster(const layout_cluster&) = delete;
    auto operator=(const layout_cluster&) -> layout_cluster& = delete;

    /// Starts node `id`'s gateway with `roles`, on the node's own port, as
    /// a restart with a new `KYTHIRA_REDIS_ROLES` would. A front end
    /// without data takes the current data nodes as its seeds; a gateway
    /// apart calls the current front ends.
    auto start(node_id_t id, layers::role_set roles) -> void {
        kythira::redis_gateway_config cfg;
        cfg._listen = "127.0.0.1:" + std::to_string(_slots[id - 1]._port);
        cfg._internal_secret = "internal-secret";
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = 5000ms;
        cfg._drain_timeout = 5000ms;
        cfg._allow_plaintext_forwarding = true;
        cfg._insecure_plaintext = true;
        cfg._transactions = true;
        cfg._layer_roles = roles;
        if (roles.has(layers::role::data)) {
            cfg._evacuate = [this, id](const std::vector<std::string>& args, bool internal) {
                return _controllers.at(id - 1)->handle(args, internal);
            };
        } else if (roles.has(layers::role::front_end)) {
            for (const auto d : data_nodes()) {
                cfg._data_nodes.push_back(endpoint(d));
            }
        }
        if (!roles.has(layers::role::front_end)) {
            for (node_id_t other = 1; other <= k_slots; ++other) {
                if (other != id && serving(other, layers::role::front_end)) {
                    cfg._front_ends.push_back(endpoint(other));
                }
            }
        }
        auto gw = std::make_shared<gateway_type>(
            *_slots[id - 1]._host, _acl, _logger, _metrics, cfg,
            [this](const node_id_t& to) -> std::optional<std::string> {
                if (to < 1 || to > k_slots) {
                    return std::nullopt;
                }
                return endpoint(to);
            });
        gw->start();
        std::lock_guard lock(_mu);
        _slots[id - 1]._gateway = std::move(gw);
        _slots[id - 1]._roles = roles;
    }

    /// Drains node `id` (the commands it already received finish) and
    /// stops it.
    auto stop(node_id_t id) -> void {
        std::shared_ptr<gateway_type> gw;
        {
            std::lock_guard lock(_mu);
            gw = std::move(_slots[id - 1]._gateway);
            _slots[id - 1]._roles = {};
        }
        if (gw) {
            gw->drain();
        }
    }

    auto restart(node_id_t id, layers::role_set roles) -> void {
        stop(id);
        start(id, roles);
    }

    /// A restart of a memory-store node whose data role changes: the
    /// process comes back with an empty Raft host, so it holds no stale
    /// replica (leaving `data`) and founds nothing (joining it, as with
    /// `KYTHIRA_REDIS_JOIN=true`). An empty role set leaves it stopped.
    auto restart_empty(node_id_t id, layers::role_set roles) -> void {
        stop(id);
        stop_driver(id);
        _controllers[id - 1]->stop();
        auto& s = _slots[id - 1];
        s._host->stop();
        _controllers[id - 1].reset();
        s._host = std::make_unique<host_type>(make_config(id));
        _controllers[id - 1] = make_controller(id);
        s._host->start();
        start_driver(id);
        if (!roles.empty()) {
            start(id, roles);
        }
    }

    [[nodiscard]] auto port(node_id_t id) const -> std::uint16_t { return _slots[id - 1]._port; }

    [[nodiscard]] auto serving(node_id_t id, layers::role r) -> bool {
        std::lock_guard lock(_mu);
        return _slots[id - 1]._gateway && _slots[id - 1]._roles.has(r);
    }

    /// The nodes clients may connect to: up, with the gateway role.
    [[nodiscard]] auto client_entries() -> std::vector<node_id_t> {
        std::vector<node_id_t> out;
        for (node_id_t id = 1; id <= k_slots; ++id) {
            if (serving(id, layers::role::gateway)) {
                out.push_back(id);
            }
        }
        return out;
    }

    [[nodiscard]] auto data_nodes() -> std::vector<node_id_t> {
        std::vector<node_id_t> out;
        for (node_id_t id = 1; id <= k_slots; ++id) {
            if (serving(id, layers::role::data)) {
                out.push_back(id);
            }
        }
        return out;
    }

    /// The voters of group `g` as its leader sees them.
    [[nodiscard]] auto voters_of(group_id_type g) -> std::vector<node_id_t> {
        for (auto& s : _slots) {
            auto* n = s._host->group_node(g);
            if (n != nullptr && n->is_leader()) {
                auto v = n->current_membership().voters;
                std::sort(v.begin(), v.end());
                return v;
            }
        }
        return {};
    }

    auto await(const std::function<bool()>& f, std::chrono::milliseconds budget) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            if (f()) {
                return true;
            }
            std::this_thread::sleep_for(50ms);
        }
        return f();
    }

    /// Runs an admin command on a node that serves clients and holds data
    /// when there is one (the controller answers there), else on any node
    /// that serves clients (it relays to the data nodes).
    auto admin(const std::vector<std::string>& argv) -> std::string {
        std::optional<node_id_t> pick;
        for (node_id_t id = 1; id <= k_slots && !pick; ++id) {
            if (serving(id, layers::role::gateway) && serving(id, layers::role::data)) {
                pick = id;
            }
        }
        if (!pick) {
            const auto entries = client_entries();
            if (entries.empty()) {
                return "-ERR no node serves clients";
            }
            pick = entries.front();
        }
        try {
            resp_client ops(port(*pick));
            if (ops.call({"AUTH", "ops", "ops-secret"}) != "+OK\r\n") {
                return "-ERR auth";
            }
            return ops.call(argv);
        } catch (const std::exception& e) {
            return std::string("-ERR ") + e.what();
        }
    }

    /// `KYTHIRA.EVACUATE` on the evacuee itself, through its controller
    /// (a data-only node refuses client connections).
    auto on_node(node_id_t id, const std::vector<std::string>& args)
        -> kythira::redis_admin_answer {
        return _controllers.at(id - 1)->handle(args, false);
    }

private:
    struct slot {
        std::uint16_t _port = 0;
        std::unique_ptr<host_type> _host;
        std::shared_ptr<gateway_type> _gateway;
        layers::role_set _roles;
        std::thread _driver;
        std::atomic<bool> _drive{false};
    };

    auto start_driver(node_id_t id) -> void {
        auto& s = _slots[id - 1];
        s._drive = true;
        s._driver = std::thread([&s] {
            while (s._drive.load()) {
                s._host->tick();
                std::this_thread::sleep_for(5ms);
            }
        });
    }

    auto stop_driver(node_id_t id) -> void {
        auto& s = _slots[id - 1];
        s._drive = false;
        if (s._driver.joinable()) {
            s._driver.join();
        }
    }

    auto make_controller(node_id_t id) -> std::unique_ptr<controller_type> {
        controller_type::hooks h;
        h._call = [this, id](const std::string& ep,
                             const std::vector<std::string>& argv) -> std::optional<std::string> {
            auto gw = gateway(id);
            if (!gw) {
                return std::nullopt;
            }
            return gw->data_call(ep, argv);
        };
        h._peers = [this, id] {
            std::vector<std::pair<node_id_t, std::string>> out;
            for (const auto other : data_nodes()) {
                if (other != id) {
                    out.emplace_back(other, endpoint(other));
                }
            }
            return out;
        };
        h._release = [] { return true; };
        h._unrelease = [] {};
        return std::make_unique<controller_type>(*_slots[id - 1]._host, 3, h);
    }

    auto gateway(node_id_t id) -> std::shared_ptr<gateway_type> {
        std::lock_guard lock(_mu);
        return _slots[id - 1]._gateway;
    }

    auto endpoint(node_id_t id) const -> std::string {
        return "127.0.0.1:" + std::to_string(_slots[id - 1]._port);
    }

    static auto founding_groups() -> std::vector<descriptor_type> {
        const std::vector<node_id_t> voters{1, 2, 3};
        return {
            descriptor_type{._group_id = 1,
                            ._range = kythira::shard_range<key_type>{._start = std::nullopt,
                                                                     ._end = key_type{"m"}},
                            ._epoch = kythira::shard_epoch{},
                            ._voters = voters},
            descriptor_type{._group_id = 2,
                            ._range = kythira::shard_range<key_type>{._start = key_type{"m"},
                                                                     ._end = std::nullopt},
                            ._epoch = kythira::shard_epoch{},
                            ._voters = voters},
        };
    }

    auto make_config(node_id_t id) -> config_type {
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = 300ms;
        cfg.config._election_timeout_max = 600ms;
        cfg.config._heartbeat_interval = 50ms;
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.executor_stripes = 2;
        cfg.automatic_split_merge_enabled = false;
        cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
        cfg.unknown_group_lookup_interval = 100ms;
        cfg.logger = kythira::console_logger{kythira::log_level::error};
        cfg.logger_factory = [](const group_id_type&) {
            return kythira::console_logger{kythira::log_level::error};
        };
        cfg.lookup_descriptor = [this,
                                 id](const group_id_type& g) -> std::optional<descriptor_type> {
            auto* controller = _controllers.at(id - 1).get();
            if (!_ready.load() || controller == nullptr) {
                return std::nullopt;
            }
            return controller->lookup_descriptor(g);
        };
        return cfg;
    }

    message_fabric _fabric{8};
    kythira::redis_acl _acl;
    kythira::console_logger _logger{kythira::log_level::error};
    kythira::noop_metrics _metrics;
    std::mutex _mu;
    std::array<slot, k_slots> _slots;
    std::array<std::unique_ptr<controller_type>, k_slots> _controllers;
    std::atomic<bool> _ready{false};
};

// ── the workload ─────────────────────────────────────────────────────────────

/// What a worker tried and what the cluster acknowledged. A write whose
/// reply never came (the connection closed, or the gateway answered that
/// the outcome is unknown) may or may not have applied: it is attempted
/// but not acknowledged, and the checks hold it to atomicity only.
struct ledger {
    enum class kind : std::uint8_t {
        set,
        mset,
        multi,
        setex
    };
    struct op {
        kind _kind;
        bool _acked = false;
    };

    std::mutex _mu;
    std::map<std::uint64_t, op> _ops;
    std::atomic<std::uint64_t> _next{0};
    std::atomic<std::uint64_t> _acked{0};
    std::atomic<std::uint64_t> _unacked{0};
    std::atomic<std::uint64_t> _reconnects{0};

    auto record(std::uint64_t seq, kind k, bool acked) -> void {
        std::lock_guard lock(_mu);
        _ops[seq] = op{k, acked};
        (acked ? _acked : _unacked).fetch_add(1);
    }
};

// Keys: "a/..." lands on group 1, "z/..." on group 2.
auto side(std::uint64_t seq) -> std::string {
    return seq % 2 == 0 ? "a/" : "z/";
}
auto set_key(std::uint64_t seq) -> std::string {
    return side(seq) + "s/" + std::to_string(seq);
}
auto setex_key(std::uint64_t seq) -> std::string {
    return side(seq) + "d/" + std::to_string(seq);
}
auto value(std::uint64_t seq) -> std::string {
    return "v" + std::to_string(seq);
}
auto mset_keys(std::uint64_t seq) -> std::array<std::string, 2> {
    return {"a/p/" + std::to_string(seq), "z/p/" + std::to_string(seq)};
}
auto multi_keys(std::uint64_t seq) -> std::array<std::string, 3> {
    return {"a/t/" + std::to_string(seq), "z/t/" + std::to_string(seq),
            "z/t/ttl/" + std::to_string(seq)};
}

constexpr long k_ttl = 3600;

/// Workers write through whichever nodes serve clients, reconnecting
/// whenever a drain closes their connection.
class workload {
public:
    workload(layout_cluster& c, ledger& l, std::size_t workers) : _cluster(c), _ledger(l) {
        for (std::size_t w = 0; w < workers; ++w) {
            _threads.emplace_back([this, w] { run(w); });
        }
    }
    ~workload() { stop(); }
    workload(const workload&) = delete;
    auto operator=(const workload&) -> workload& = delete;

    auto stop() -> void {
        _stop = true;
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

private:
    auto run(std::size_t w) -> void {
        std::size_t turn = w;
        while (!_stop.load()) {
            const auto entries = _cluster.client_entries();
            if (entries.empty()) {
                std::this_thread::sleep_for(20ms);
                continue;
            }
            const auto entry = entries[turn++ % entries.size()];
            std::unique_ptr<resp_client> client;
            try {
                client = std::make_unique<resp_client>(_cluster.port(entry));
                if (client->call({"AUTH", "farm", "farm-secret"}) != "+OK\r\n") {
                    std::this_thread::sleep_for(20ms);
                    continue;
                }
            } catch (const std::exception&) {
                std::this_thread::sleep_for(20ms);
                continue;
            }
            _ledger._reconnects.fetch_add(1);
            // Each connection does a bounded run, so every entry gets
            // traffic as the layout changes.
            for (int i = 0; i < 200 && !_stop.load(); ++i) {
                const auto seq = _ledger._next.fetch_add(1);
                if (!one(*client, seq)) {
                    break;
                }
            }
        }
    }

    /// One operation; false once the connection is gone.
    auto one(resp_client& c, std::uint64_t seq) -> bool {
        const auto k = static_cast<ledger::kind>(seq % 4);
        try {
            switch (k) {
                case ledger::kind::set: {
                    _ledger.record(seq, k, c.call({"SET", set_key(seq), value(seq)}) == "+OK\r\n");
                    break;
                }
                case ledger::kind::setex: {
                    _ledger.record(seq, k,
                                   c.call({"SETEX", setex_key(seq), std::to_string(k_ttl),
                                           value(seq)}) == "+OK\r\n");
                    break;
                }
                case ledger::kind::mset: {
                    const auto keys = mset_keys(seq);
                    _ledger.record(
                        seq, k,
                        c.call({"MSET", keys[0], value(seq), keys[1], value(seq)}) == "+OK\r\n");
                    break;
                }
                case ledger::kind::multi: {
                    const auto keys = multi_keys(seq);
                    // Queued replies only matter if EXEC answers; a refused
                    // queue makes EXEC refuse too.
                    if (c.call({"MULTI"}) != "+OK\r\n") {
                        _ledger.record(seq, k, false);
                        break;
                    }
                    (void)c.call({"SET", keys[0], value(seq)});
                    (void)c.call({"SET", keys[1], value(seq)});
                    (void)c.call({"SETEX", keys[2], std::to_string(k_ttl), value(seq)});
                    const auto r = c.call({"EXEC"});
                    _ledger.record(seq, k, r == "*3\r\n+OK\r\n+OK\r\n+OK\r\n");
                    if (r.rfind("-ERR", 0) == 0 && r.find("MULTI") != std::string::npos) {
                        // The connection's MULTI state is unknown: start over.
                        return false;
                    }
                    break;
                }
            }
        } catch (const std::exception&) {
            _ledger.record(seq, k, false);
            return false;
        }
        return true;
    }

    layout_cluster& _cluster;
    ledger& _ledger;
    std::vector<std::thread> _threads;
    std::atomic<bool> _stop{false};
};

/// A reader that retries what a moving layout may answer for a moment.
constexpr const char* k_nil = "(nil)";

auto join(const std::vector<std::string>& v) -> std::string {
    std::string out;
    for (const auto& e : v) {
        out += (out.empty() ? "" : " / ") + e;
    }
    return out;
}

class checker {
public:
    explicit checker(layout_cluster& c) : _cluster(c) {}

    auto get(const std::string& key) -> std::string { return call({"GET", key}); }

    /// One MGET, so a transaction's keys are read together. The checker's
    /// connections read at `read_committed_wait`: a transaction whose
    /// coordinator went away mid-commit leaves intents that plain
    /// `read_committed` reads skip (multi-raft-transactions Requirement
    /// 5.1), and only a reader that meets them and waits out their TTL
    /// runs the resolver that makes the transaction whole (5.3, 4.x).
    /// Each element is the value, or `k_nil` for a missing key.
    auto mget(const std::vector<std::string>& keys) -> std::vector<std::string> {
        std::vector<std::string> argv{"MGET"};
        argv.insert(argv.end(), keys.begin(), keys.end());
        const auto r = call(argv);
        std::vector<std::string> out;
        if (r.empty() || r.front() != '*') {
            out.push_back(r.substr(0, r.find('\r')));
            return out;
        }
        std::size_t pos = r.find("\r\n") + 2;
        while (pos < r.size()) {
            const auto eol = r.find("\r\n", pos);
            const auto head = r.substr(pos, eol - pos);
            pos = eol + 2;
            if (head == "$-1" || head == "_") {
                out.push_back(k_nil);
                continue;
            }
            const auto len = std::stoul(head.substr(1));
            out.push_back(r.substr(pos, len));
            pos += len + 2;
        }
        return out;
    }
    auto ttl(const std::string& key) -> long {
        const auto r = call({"TTL", key});
        return r.front() == ':' ? std::stol(r.substr(1)) : -100;
    }

    /// The checks over what the workload did. `full` reads back every
    /// operation; otherwise those since the previous verify plus every
    /// sixteenth older one. Each read is a round trip made while the
    /// workload keeps writing, and reading everything after every step
    /// grew quadratically: on CI runners the reads alone outran the case's
    /// timeout. The older sample still catches a later step losing
    /// earlier writes wholesale, and the final verify is full. Returns the
    /// failures, one line each.
    auto verify(ledger& l, bool full = false) -> std::vector<std::string> {
        std::map<std::uint64_t, ledger::op> ops;
        {
            std::lock_guard lock(l._mu);
            ops = l._ops;
        }
        const auto since = _checked_from;
        if (!ops.empty()) {
            _checked_from = ops.rbegin()->first + 1;
        }
        std::vector<std::string> bad;
        for (const auto& [seq, op] : ops) {
            if (!full && seq < since && seq % 16 != 0) {
                continue;
            }
            const auto v = value(seq);
            switch (op._kind) {
                case ledger::kind::set: {
                    const auto got = get(set_key(seq));
                    if (op._acked && got != bulk(v)) {
                        bad.push_back("lost SET " + set_key(seq) + ": " + got);
                    } else if (!op._acked && got != bulk(v) && got != "$-1\r\n") {
                        bad.push_back("wrong SET " + set_key(seq) + ": " + got);
                    }
                    break;
                }
                case ledger::kind::setex: {
                    const auto got = get(setex_key(seq));
                    if (op._acked && got != bulk(v)) {
                        bad.push_back("lost SETEX " + setex_key(seq) + ": " + got);
                    }
                    if (got == bulk(v)) {
                        const auto t = ttl(setex_key(seq));
                        if (t <= 0 || t > k_ttl) {
                            bad.push_back("deadline of " + setex_key(seq) + ": " +
                                          std::to_string(t));
                        }
                    }
                    break;
                }
                case ledger::kind::mset: {
                    const auto keys = mset_keys(seq);
                    const auto got = mget({keys[0], keys[1]});
                    const bool both = got == std::vector<std::string>{v, v};
                    const bool neither = got == std::vector<std::string>{k_nil, k_nil};
                    if (op._acked ? !both : !(both || neither)) {
                        bad.push_back("MSET " + std::to_string(seq) + " acked " +
                                      std::to_string(op._acked) + ": " + join(got));
                    }
                    break;
                }
                case ledger::kind::multi: {
                    const auto keys = multi_keys(seq);
                    const auto got = mget({keys[0], keys[1], keys[2]});
                    const bool all = got == std::vector<std::string>{v, v, v};
                    const bool none = got == std::vector<std::string>{k_nil, k_nil, k_nil};
                    if (op._acked ? !all : !(all || none)) {
                        bad.push_back("MULTI " + std::to_string(seq) + " acked " +
                                      std::to_string(op._acked) + ": " + join(got));
                    }
                    if (all) {
                        const auto t = ttl(keys[2]);
                        if (t <= 0 || t > k_ttl) {
                            bad.push_back("deadline of " + keys[2] + ": " + std::to_string(t));
                        }
                    }
                    break;
                }
            }
            if (bad.size() > 10) {
                break;
            }
        }
        return bad;
    }

private:
    auto call(const std::vector<std::string>& argv) -> std::string {
        std::string r;
        for (int attempt = 0; attempt < 60; ++attempt) {
            try {
                if (!_client) {
                    const auto entries = _cluster.client_entries();
                    if (entries.empty()) {
                        throw std::runtime_error("no entry");
                    }
                    _client = std::make_unique<resp_client>(
                        _cluster.port(entries[static_cast<std::size_t>(attempt) % entries.size()]));
                    if (_client->call({"AUTH", "farm", "farm-secret"}) != "+OK\r\n" ||
                        _client->call({"KYTHIRA.ISOLATION", "read_committed_wait"}) != "+OK\r\n") {
                        throw std::runtime_error("auth");
                    }
                }
                r = _client->call(argv);
                const bool retry = r.rfind("-TRYAGAIN", 0) == 0 || r.rfind("-LOADING", 0) == 0 ||
                                   (r.front() == '-' && (r.find("retry") != std::string::npos ||
                                                         r.find("timed out") != std::string::npos));
                if (!retry) {
                    return r;
                }
            } catch (const std::exception& e) {
                _client.reset();
                r = std::string("-ERR ") + e.what();
            }
            std::this_thread::sleep_for(50ms);
        }
        return r;
    }

    layout_cluster& _cluster;
    std::unique_ptr<resp_client> _client;
    /// The first sequence number the next verify reads in full.
    std::uint64_t _checked_from = 0;
};

auto evacuation_done(layout_cluster& c) -> bool {
    return c.await(
        [&] {
            return c.admin({"KYTHIRA.EVACUATE", "STATUS"}).find(bulk("done 1")) !=
                   std::string::npos;
        },
        90s);
}

auto as_text(const std::vector<node_id_t>& v) -> std::string {
    std::ostringstream o;
    for (const auto id : v) {
        o << id << ' ';
    }
    return o.str();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(layer_paths)

BOOST_AUTO_TEST_CASE(colocated_to_three_way_and_back_under_writes,
                     *boost::unit_test::timeout(900)) {
    layout_cluster c;
    for (node_id_t id = 1; id <= 3; ++id) {
        c.start(id, k_all);
    }
    BOOST_REQUIRE(c.await([&] { return !c.voters_of(1).empty() && !c.voters_of(2).empty(); }, 20s));

    ledger l;
    checker check(c);
    workload work(c, l, 3);

    // After each step: the workload moved forward through the step, and
    // everything it did holds.
    auto step = [&](const std::string& name, const std::function<void()>& body) {
        BOOST_TEST_MESSAGE("step: " << name);
        const auto before = l._acked.load();
        body();
        // Writes may crawl for a while after a step: transactions whose
        // coordinating front end was drained mid-commit leave intents
        // that later writes to the same keys wait on until they resolve,
        // and under load (a 4-core CI runner running other suites) that
        // took over 30 s in local loops with competing CPU load.
        BOOST_REQUIRE_MESSAGE(c.await([&] { return l._acked.load() > before + 20; }, 90s),
                              name << ": no writes were acknowledged");
        const auto bad = check.verify(l);
        for (const auto& b : bad) {
            BOOST_ERROR(name << ": " << b);
        }
        if (!bad.empty()) {
            for (const auto id : c.client_entries()) {
                try {
                    resp_client probe(c.port(id));
                    (void)probe.call({"AUTH", "farm", "farm-secret"});
                    BOOST_TEST_MESSAGE("node " << id << " GET a/s/0 -> "
                                               << probe.call({"GET", "a/s/0"}) << " GET z/s/1 -> "
                                               << probe.call({"GET", "z/d/3"}));
                } catch (const std::exception& e) {
                    BOOST_TEST_MESSAGE("node " << id << ": " << e.what());
                }
            }
            for (group_id_type g : {1, 2}) {
                BOOST_TEST_MESSAGE("group " << g << " voters " << as_text(c.voters_of(g)));
            }
        }
        BOOST_REQUIRE_MESSAGE(bad.empty(), name);
    };
    auto evacuate = [&](node_id_t from, node_id_t to) {
        BOOST_REQUIRE_EQUAL(
            c.admin({"KYTHIRA.EVACUATE", "START", std::to_string(from), "TO", std::to_string(to)}),
            "+OK\r\n");
        BOOST_REQUIRE(evacuation_done(c));
        for (group_id_type g : {1, 2}) {
            const auto v = c.voters_of(g);
            BOOST_TEST((std::find(v.begin(), v.end(), from) == v.end()), as_text(v));
            BOOST_TEST((std::find(v.begin(), v.end(), to) != v.end()), as_text(v));
        }
    };
    // Removing `data` from a node: evacuate it, release it, restart it.
    auto leave_data = [&](node_id_t from, node_id_t to, layers::role_set roles) {
        evacuate(from, to);
        BOOST_REQUIRE(c.on_node(from, {"RELEASE"})._kind == ev::answer::kind::ok);
        BOOST_REQUIRE_EQUAL(c.admin({"KYTHIRA.EVACUATE", "CANCEL"}), "+OK\r\n");
        c.restart_empty(from, roles);
    };

    step("co-located baseline", [] {});

    // Data split, stopped midway and reversed: node 4 joins, takes one of
    // node 1's groups, and the operator changes their mind.
    step("data split stopped and reversed midway", [&] {
        c.start(4, k_data);
        BOOST_REQUIRE_EQUAL(c.admin({"KYTHIRA.EVACUATE", "START", "1", "TO", "4"}), "+OK\r\n");
        BOOST_REQUIRE(c.await(
            [&] {
                for (group_id_type g : {1, 2}) {
                    const auto v = c.voters_of(g);
                    if (std::find(v.begin(), v.end(), 4) != v.end()) {
                        return true;
                    }
                }
                return false;
            },
            60s));
        BOOST_REQUIRE_EQUAL(c.admin({"KYTHIRA.EVACUATE", "CANCEL"}), "+OK\r\n");
        // Every group still serves with whatever voters it has; now back.
        evacuate(4, 1);
        BOOST_REQUIRE_EQUAL(c.admin({"KYTHIRA.EVACUATE", "CANCEL"}), "+OK\r\n");
        for (group_id_type g : {1, 2}) {
            BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{1, 2, 3}),
                       as_text(c.voters_of(g)));
        }
    });

    step("data split: node 1 becomes a front end without data", [&] { leave_data(1, 4, k_gw_fe); });
    step("data split: nodes 2 and 3 become front ends without data", [&] {
        c.start(5, k_data);
        leave_data(2, 5, k_gw_fe);
        c.start(6, k_data);
        leave_data(3, 6, k_gw_fe);
        for (group_id_type g : {1, 2}) {
            BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{4, 5, 6}),
                       as_text(c.voters_of(g)));
        }
    });
    step("gateway split: three-way", [&] {
        c.restart(2, k_fe);
        c.restart(3, k_fe);
        c.restart(1, k_gw);
        BOOST_TEST((c.client_entries() == std::vector<node_id_t>{1}));
    });

    step("gateway merge", [&] {
        c.restart(2, k_gw_fe);
        c.restart(3, k_gw_fe);
        c.restart(1, k_gw_fe);
    });
    step("data merge: nodes 3 and 2 take the data back", [&] {
        c.restart_empty(3, k_all);
        leave_data(6, 3, {});
        c.restart_empty(2, k_all);
        leave_data(5, 2, {});
    });
    step("data merge: node 1 takes the data back, co-located again", [&] {
        c.restart_empty(1, k_all);
        leave_data(4, 1, {});
        for (group_id_type g : {1, 2}) {
            BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{1, 2, 3}),
                       as_text(c.voters_of(g)));
        }
    });

    work.stop();
    const auto bad = check.verify(l, true);
    for (const auto& b : bad) {
        BOOST_ERROR("final: " << b);
    }
    BOOST_TEST_MESSAGE("acknowledged " << l._acked.load() << ", unacknowledged "
                                       << l._unacked.load() << ", connections "
                                       << l._reconnects.load());
    BOOST_TEST(l._acked.load() > 200U);
}

BOOST_AUTO_TEST_SUITE_END()
