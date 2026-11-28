// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_gateway_txn_test.cpp
/// @brief The Redis gateway's transaction surface
///        (.kiro/specs/multi-raft-transactions/ task 9): three in-process
///        hosts whose KV state machine is wrapped in
///        `transactional_state_machine`, each with a gateway on a real TCP
///        port, `--transactions on`.
///
/// Two shards split at "m", so an `a/...` key and a `z/...` key are always
/// on different shards and every multi-key command here is a two-phase
/// commit. Each case talks to every gateway in turn, so at least one of
/// them leads neither shard and has to reach both over `KYTHIRA.TXN`.
///
/// Today's behaviour with transactions off, and the refusal to start them on
/// an unwrapped host, are in redis_gateway_integration_test.cpp.

#define BOOST_TEST_MODULE redis_gateway_txn_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"
#include "redis_golden_bytes.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <kythira/redis/redis_gateway_impl.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <raft/txn_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("redis_gateway_txn_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using kythira::hibernation_mode;
using kythira::multi_raft;
using kythira::multi_raft_config;
using kythira::redis_acl;
using kythira::redis_gateway;
using kythira::redis_gateway_config;
using kythira::resp_reply_length;
using kythira::shard_descriptor;
using kythira::shard_epoch;
using kythira::shard_range;
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

using host_type = multi_raft<host_types, key_type, group_id_type>;
using config_type = multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = shard_descriptor<group_id_type, key_type, node_id_t>;
using gateway_type = redis_gateway<host_type, kythira::console_logger, kythira::noop_metrics>;

static_assert(gateway_type::k_transactional);

constexpr std::size_t k_node_count = 3;
constexpr std::uint32_t k_kdf_iters = 1000;

auto range_of(std::optional<key_type> start, std::optional<key_type> end) -> shard_range<key_type> {
    return shard_range<key_type>{._start = std::move(start), ._end = std::move(end)};
}

auto acl_text() -> std::string {
    return "user ops " + redis_acl::hash_secret("ops-secret", k_kdf_iters) + " admin *\n" +
           "user farm " + redis_acl::hash_secret("farm-secret", k_kdf_iters) + " read_write a/\n" +
           "user kythira-internal " + redis_acl::hash_secret("internal-secret", k_kdf_iters) +
           " read_write *\n";
}

class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _socket(_io) {
        _socket.connect({boost::asio::ip::make_address("127.0.0.1"), port});
        _socket.set_option(boost::asio::ip::tcp::no_delay(true));
    }

    auto call(const std::vector<std::string>& argv) -> std::string {
        std::string out = "*" + std::to_string(argv.size()) + "\r\n";
        for (const auto& a : argv) {
            out += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
        }
        boost::asio::write(_socket, boost::asio::buffer(out));
        std::size_t len = 0;
        while ((len = resp_reply_length(_buffer)) == 0) {
            std::array<char, 65536> chunk{};
            auto n = _socket.read_some(boost::asio::buffer(chunk));
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

auto bulk(const std::string& s) -> std::string {
    return "$" + std::to_string(s.size()) + "\r\n" + s + "\r\n";
}

auto starts_with(const std::string& s, std::string_view prefix) -> bool {
    return s.rfind(prefix, 0) == 0;
}

class cluster {
public:
    explicit cluster(redis_gateway_config base = {}) {
        _acl.reload(acl_text());
        const std::vector<node_id_t> voters{1, 2, 3};
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
            _hosts.back()->create_group(descriptor_type{._group_id = 1,
                                                        ._range = range_of(std::nullopt, "m"),
                                                        ._epoch = shard_epoch{},
                                                        ._voters = voters});
            _hosts.back()->create_group(descriptor_type{._group_id = 2,
                                                        ._range = range_of("m", std::nullopt),
                                                        ._epoch = shard_epoch{},
                                                        ._voters = voters});
        }
        for (auto& h : _hosts) {
            h->start();
        }
        for (auto& host : _hosts) {
            auto cfg = base;
            cfg._listen = "127.0.0.1:0";
            cfg._internal_secret = "internal-secret";
            cfg._io_threads = 1;
            cfg._worker_threads = 4;
            cfg._command_timeout = std::chrono::milliseconds{5000};
            cfg._allow_plaintext_forwarding = true;
            // Nodes apart join these cases without layer identities.
            cfg._insecure_plaintext = true;
            cfg._transactions = true;
            auto resolver = [this](const node_id_t& to) -> std::optional<std::string> {
                if (to < 1 || to > _gateways.size() || !_gateways[to - 1]) {
                    return std::nullopt;
                }
                return "127.0.0.1:" + std::to_string(_gateways[to - 1]->port());
            };
            _gateways.push_back(
                std::make_unique<gateway_type>(*host, _acl, _logger, _metrics, cfg, resolver));
        }
        for (auto& g : _gateways) {
            g->start();
        }
        _running = true;
        for (auto& host : _hosts) {
            _drivers.emplace_back([this, h = host.get()] {
                while (_running.load()) {
                    h->tick();
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            });
        }
    }

    ~cluster() {
        _running = false;
        for (auto& g : _front_ends) {
            g->stop();
        }
        for (auto& h : _front_end_hosts) {
            h->stop();
        }
        for (auto& t : _drivers) {
            t.join();
        }
        for (auto& g : _gateways) {
            g->stop();
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }
    [[nodiscard]] auto gateway(node_id_t id) -> gateway_type& { return *_gateways.at(id - 1); }
    [[nodiscard]] auto port(node_id_t id) -> std::uint16_t { return _gateways.at(id - 1)->port(); }

    [[nodiscard]] auto leader_of(group_id_type group) -> node_id_t {
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            auto* n = _hosts[id - 1]->group_node(group);
            if (n != nullptr && n->is_leader()) {
                return id;
            }
        }
        return 0;
    }

    auto await_all_leaders(std::chrono::milliseconds budget) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            if (leader_of(1) != 0 && leader_of(2) != 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return false;
    }

    /// A node without the data layer (redis-general-data-types task 16):
    /// its host is in no group; routes and proposals cross KYTHIRA.DATA,
    /// and the coordinator's participant messages cross KYTHIRA.TXN to
    /// the leaders the routes name.
    auto add_front_end() -> gateway_type& {
        const auto id = static_cast<node_id_t>(k_node_count + 1 + _front_end_hosts.size());
        _front_end_hosts.push_back(std::make_unique<host_type>(make_config(id)));
        _front_end_hosts.back()->start();
        redis_gateway_config cfg;
        cfg._listen = "127.0.0.1:0";
        cfg._internal_secret = "internal-secret";
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = std::chrono::milliseconds{5000};
        cfg._allow_plaintext_forwarding = true;
        cfg._insecure_plaintext = true;
        cfg._transactions = true;
        cfg._layer_roles = {kythira::layers::role::gateway, kythira::layers::role::front_end};
        for (node_id_t n = 1; n <= k_node_count; ++n) {
            cfg._data_nodes.push_back("127.0.0.1:" + std::to_string(port(n)));
        }
        _front_ends.push_back(std::make_unique<gateway_type>(
            *_front_end_hosts.back(), _acl, _logger, _metrics, cfg,
            [](const node_id_t&) -> std::optional<std::string> { return std::nullopt; }));
        _front_ends.back()->start();
        return *_front_ends.back();
    }

    /// A gateway without the front end (task 17), calling every node's
    /// front end; the connection state, `MULTI` queue included, is its.
    auto add_gateway(const std::vector<std::uint16_t>& front_end_ports = {}) -> gateway_type& {
        const auto id = static_cast<node_id_t>(k_node_count + 1 + _front_end_hosts.size());
        _front_end_hosts.push_back(std::make_unique<host_type>(make_config(id)));
        _front_end_hosts.back()->start();
        redis_gateway_config cfg;
        cfg._listen = "127.0.0.1:0";
        cfg._internal_secret = "internal-secret";
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = std::chrono::milliseconds{5000};
        cfg._insecure_plaintext = true;
        cfg._layer_roles = {kythira::layers::role::gateway};
        for (node_id_t n = 1; n <= k_node_count; ++n) {
            cfg._front_ends.push_back("127.0.0.1:" + std::to_string(port(n)));
        }
        if (!front_end_ports.empty()) {
            cfg._front_ends.clear();
            for (auto p : front_end_ports) {
                cfg._front_ends.push_back("127.0.0.1:" + std::to_string(p));
            }
        }
        _front_ends.push_back(std::make_unique<gateway_type>(
            *_front_end_hosts.back(), _acl, _logger, _metrics, cfg,
            [](const node_id_t&) -> std::optional<std::string> { return std::nullopt; }));
        _front_ends.back()->start();
        return *_front_ends.back();
    }

private:
    auto make_config(node_id_t id) -> config_type {
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{120};
        cfg.config._election_timeout_max = std::chrono::milliseconds{260};
        cfg.config._heartbeat_interval = std::chrono::milliseconds{25};
        cfg.hibernation = hibernation_mode::off;
        cfg.executor_stripes = 2;
        cfg.partitioner = kythira::make_partitioner<key_type>(kythira::redis_kv_partitioner{});
        return cfg;
    }

    message_fabric _fabric{8};
    redis_acl _acl;
    kythira::console_logger _logger{kythira::log_level::warning};
    kythira::noop_metrics _metrics;
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::unique_ptr<gateway_type>> _gateways;
    std::vector<std::unique_ptr<host_type>> _front_end_hosts;
    std::vector<std::unique_ptr<gateway_type>> _front_ends;
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
};

/// Plant a prepared intent on `key` (its own primary) with the given TTL
/// deadline, as a coordinator that died after its prepare would leave.
auto plant_intent(cluster& c, const std::string& key, std::uint64_t deadline_ms) -> void {
    const auto leader = c.leader_of(1);
    BOOST_REQUIRE_NE(leader, 0u);
    kythira::txn_prepare<std::string> prepare;
    prepare._txn = kythira::txn_id{0xdead, 0xbeef};
    prepare._primary = key;
    prepare._writes = {kythira::txn_write<std::string>{
        key, kythira::encode_redis_kv_command(kythira::redis_kv_set_command{key, {}, 0})}};
    prepare._ttl_deadline_ms = deadline_ms;
    prepare._is_primary = true;
    auto env =
        kythira::encode_txn_envelope<std::string>(kythira::txn_envelope<std::string>{prepare});
    auto f = c.host(leader).submit_txn({key}, env, std::chrono::seconds{5});
    BOOST_REQUIRE(f.wait(std::chrono::seconds{5}));
    std::ignore = std::move(f).get();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_gateway_txn)

BOOST_AUTO_TEST_CASE(mset_mget_and_multi_key_del_span_shards, *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        const auto n = std::to_string(id);
        resp_client client(c.port(id));
        BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"MSET", "a/" + n, "left" + n, "z/" + n, "right" + n}),
                          "+OK\r\n");

        // Every gateway sees both halves.
        for (node_id_t other = 1; other <= k_node_count; ++other) {
            resp_client reader(c.port(other));
            BOOST_REQUIRE_EQUAL(reader.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
            BOOST_CHECK_EQUAL(reader.call({"MGET", "a/" + n, "z/" + n, "a/none"}),
                              "*3\r\n" + bulk("left" + n) + bulk("right" + n) + "$-1\r\n");
            BOOST_CHECK_EQUAL(reader.call({"GET", "z/" + n}), bulk("right" + n));
        }

        BOOST_CHECK_EQUAL(client.call({"DEL", "a/" + n, "z/" + n, "a/none", "a/" + n}), ":2\r\n");
        BOOST_CHECK_EQUAL(client.call({"MGET", "a/" + n, "z/" + n}), "*2\r\n$-1\r\n$-1\r\n");
        BOOST_CHECK_EQUAL(client.call({"DEL", "a/" + n, "z/" + n}), ":0\r\n");
    }
    std::uint64_t committed = 0;
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        committed += c.gateway(id).stats()._txn_committed.load();
        BOOST_CHECK_EQUAL(c.gateway(id).stats()._txn_unknown.load(), 0u);
    }
    BOOST_CHECK_GE(committed, 2 * k_node_count);
    // Two shards over three nodes: some gateway led at most one of them and
    // reached the other's leader over KYTHIRA.TXN.
    std::uint64_t forwards = 0;
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        forwards += c.gateway(id).stats()._forwards.load();
    }
    BOOST_CHECK_GT(forwards, 0u);

    // Arity, and the key scope of the user.
    resp_client farm(c.port(1));
    BOOST_REQUIRE_EQUAL(farm.call({"AUTH", "farm", "farm-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(farm.call({"MSET", "a/1", "x", "a/2"}),
                      "-ERR wrong number of arguments for 'mset' command\r\n");
    BOOST_CHECK_EQUAL(farm.call({"MSET", "a/1", "x", "z/1", "y"}),
                      "-NOPERM No permissions to access a key\r\n");
    BOOST_CHECK_EQUAL(farm.call({"MGET", "a/1", "z/1"}),
                      "-NOPERM No permissions to access a key\r\n");
    BOOST_CHECK_EQUAL(farm.call({"GET", "a/1"}), "$-1\r\n");
}

// redis-general-data-types task 6: keys in one group make one record with
// no transaction (Requirement 6.1); keys in two groups run as a multi-Raft
// transaction (6.2), RENAME and COPY carrying the source's deadline.
BOOST_AUTO_TEST_CASE(multi_key_commands_plan_by_group, *boost::unit_test::timeout(180)) {
    redis_gateway_config cfg;
    cfg._immutable_values = false;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client r(c.port(1));
    BOOST_REQUIRE_EQUAL(r.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(r.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");
    const auto committed = [&] {
        std::uint64_t n = 0;
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            n += c.gateway(id).stats()._txn_committed.load();
        }
        return n;
    };

    // One group: no transaction.
    const auto before = committed();
    BOOST_CHECK_EQUAL(r.call({"MSETNX", "z/a", "1", "z/b", "2"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"RENAME", "z/a", "z/c"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"DEL", "z/b", "z/c", "z/none"}), ":2\r\n");
    BOOST_CHECK_EQUAL(committed(), before);

    // Two groups: one transaction each.
    BOOST_CHECK_EQUAL(r.call({"MSETNX", "a/1", "x", "z/1", "y"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"MSETNX", "a/2", "x", "z/1", "y"}), ":0\r\n");
    BOOST_CHECK_EQUAL(r.call({"GET", "a/2"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(r.call({"SET", "a/t", "v", "PX", "100000"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"RENAME", "a/t", "z/t"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"GET", "z/t"}), bulk("v"));
    BOOST_CHECK_EQUAL(r.call({"EXISTS", "a/t"}), ":0\r\n");
    const auto pttl = r.call({"PTTL", "z/t"});
    BOOST_CHECK_MESSAGE(pttl.starts_with(':') && pttl != ":-1\r\n" && pttl != ":-2\r\n",
                        "PTTL " << pttl);
    BOOST_CHECK_EQUAL(r.call({"RENAME", "a/t", "z/t"}), "-ERR no such key\r\n");
    BOOST_CHECK_EQUAL(r.call({"RENAMENX", "z/t", "a/1"}), ":0\r\n");
    BOOST_CHECK_EQUAL(r.call({"COPY", "z/t", "a/1"}), ":0\r\n");
    BOOST_CHECK_EQUAL(r.call({"COPY", "z/t", "a/1", "REPLACE"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"GET", "a/1"}), bulk("v"));
    BOOST_CHECK_EQUAL(r.call({"DEL", "a/1", "z/1", "z/t", "a/none"}), ":3\r\n");
    BOOST_CHECK_GE(committed(), before + 4);
}

/// redis-general-data-types task 11: typed commands queue in MULTI, run
/// against the transaction's view (reads see its own earlier writes), and
/// commit as the resulting values; multi-key commands on collections cross
/// groups the same way.
BOOST_AUTO_TEST_CASE(typed_commands_in_multi_and_across_groups, *boost::unit_test::timeout(180)) {
    redis_gateway_config cfg;
    cfg._immutable_values = false;
    cluster c(cfg);
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const std::string wrongtype =
        "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n";
    resp_client r(c.port(1));
    BOOST_REQUIRE_EQUAL(r.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_REQUIRE_EQUAL(r.call({"KYTHIRA.FORMAT", "UPGRADE", "3"}), "+OK\r\n");

    // One EXEC over both groups: hashes, lists, sets and strings, each
    // command seeing the ones before it.
    BOOST_CHECK_EQUAL(r.call({"MULTI"}), "+OK\r\n");
    for (const std::vector<std::string>& queued :
         {std::vector<std::string>{"HSET", "a/h", "f", "1", "g", "2"},
          {"HINCRBY", "a/h", "f", "5"},
          {"HGET", "a/h", "f"},
          {"RPUSH", "z/l", "x", "y"},
          {"LPOP", "z/l"},
          {"SADD", "a/s", "m"},
          {"INCR", "z/n"},
          {"EXPIRE", "a/h", "1000"},
          {"TYPE", "a/h"},
          {"GET", "a/h"}}) {
        BOOST_CHECK_EQUAL(r.call(queued), "+QUEUED\r\n");
    }
    BOOST_CHECK_EQUAL(r.call({"EXEC"}), "*10\r\n:2\r\n:6\r\n" + bulk("6") + ":2\r\n" + bulk("x") +
                                            ":1\r\n:1\r\n:1\r\n+hash\r\n" + wrongtype);
    BOOST_CHECK_EQUAL(r.call({"HGETALL", "a/h"}),
                      "*4\r\n" + bulk("f") + bulk("6") + bulk("g") + bulk("2"));
    const auto pttl = r.call({"PTTL", "a/h"});
    BOOST_CHECK_MESSAGE(pttl.starts_with(':') && pttl != ":-1\r\n" && pttl != ":-2\r\n",
                        "PTTL " << pttl);
    BOOST_CHECK_EQUAL(r.call({"LRANGE", "z/l", "0", "-1"}), "*1\r\n" + bulk("y"));
    BOOST_CHECK_EQUAL(r.call({"SMEMBERS", "a/s"}), "*1\r\n" + bulk("m"));
    BOOST_CHECK_EQUAL(r.call({"GET", "z/n"}), bulk("1"));

    // A command's runtime error is its element; the rest commits.
    BOOST_CHECK_EQUAL(r.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"SET", "a/str", "v"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(r.call({"HSET", "a/str", "f", "v"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(r.call({"HLEN", "z/l"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(r.call({"EXEC"}), "*3\r\n+OK\r\n" + wrongtype + wrongtype);
    BOOST_CHECK_EQUAL(r.call({"GET", "a/str"}), bulk("v"));

    // Commands that cannot run inside MULTI, or with the wrong argument
    // count, doom the EXEC.
    BOOST_CHECK_EQUAL(r.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"HDEL", "a/h", "f"}), "+QUEUED\r\n");
    BOOST_CHECK(r.call({"KYTHIRA.FORMAT", "STATUS"}).starts_with("-ERR KYTHIRA.FORMAT is not"));
    BOOST_CHECK_EQUAL(r.call({"HSET", "a/h"}),
                      "-ERR wrong number of arguments for 'hset' command\r\n");
    BOOST_CHECK(r.call({"EXEC"}).starts_with("-EXECABORT"));
    BOOST_CHECK_EQUAL(r.call({"HGET", "a/h", "f"}), bulk("6"));

    // Collections cross groups as whole values, with their deadlines.
    const auto committed = [&] {
        std::uint64_t n = 0;
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            n += c.gateway(id).stats()._txn_committed.load();
        }
        return n;
    };
    const auto before = committed();
    BOOST_CHECK_EQUAL(r.call({"RENAME", "a/h", "z/h"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"TYPE", "a/h"}), "+none\r\n");
    BOOST_CHECK_EQUAL(r.call({"HGET", "z/h", "f"}), bulk("6"));
    const auto moved_pttl = r.call({"PTTL", "z/h"});
    BOOST_CHECK_MESSAGE(
        moved_pttl.starts_with(':') && moved_pttl != ":-1\r\n" && moved_pttl != ":-2\r\n",
        "PTTL " << moved_pttl);
    BOOST_CHECK_EQUAL(r.call({"COPY", "z/h", "a/h2"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"HGET", "a/h2", "g"}), bulk("2"));
    BOOST_CHECK_EQUAL(r.call({"SMOVE", "a/s", "z/s", "m"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"EXISTS", "a/s"}), ":0\r\n");
    BOOST_CHECK_EQUAL(r.call({"SISMEMBER", "z/s", "m"}), ":1\r\n");
    BOOST_CHECK_EQUAL(r.call({"LMOVE", "z/l", "a/l", "LEFT", "RIGHT"}), bulk("y"));
    BOOST_CHECK_EQUAL(r.call({"LRANGE", "a/l", "0", "-1"}), "*1\r\n" + bulk("y"));
    BOOST_CHECK_EQUAL(r.call({"EXISTS", "z/l"}), ":0\r\n");
    BOOST_CHECK_EQUAL(r.call({"RENAME", "z/s", "a/str"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(r.call({"TYPE", "a/str"}), "+set\r\n");
    BOOST_CHECK_GE(committed(), before + 5);

    // The commit's install record is never a client's command.
    BOOST_CHECK_EQUAL(r.call({"KYTHIRA.INSTALL", "a/x", "set", "0", "m"}),
                      "-NOPERM KYTHIRA.INSTALL is internal to the gateways\r\n");
}

BOOST_AUTO_TEST_CASE(mset_keeps_values_immutable, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(1));
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "a/imm", "one"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"MSET", "a/imm", "two", "z/imm", "three"}),
                      "-ERR value conflict for an existing key\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "z/imm"}), "$-1\r\n");
    // The same bytes again are a no-op for that key; the rest still commits.
    BOOST_CHECK_EQUAL(client.call({"MSET", "a/imm", "one", "z/imm", "three"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"MGET", "a/imm", "z/imm"}),
                      "*2\r\n" + bulk("one") + bulk("three"));
}

BOOST_AUTO_TEST_CASE(multi_exec_and_discard, *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    for (node_id_t id = 1; id <= k_node_count; ++id) {
        const auto n = std::to_string(id);
        resp_client client(c.port(id));
        BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"EXEC"}), "-ERR EXEC without MULTI\r\n");
        BOOST_CHECK_EQUAL(client.call({"DISCARD"}), "-ERR DISCARD without MULTI\r\n");

        BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"MULTI"}), "-ERR MULTI calls can not be nested\r\n");
        BOOST_CHECK_EQUAL(client.call({"SET", "a/m" + n, "1"}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"GET", "a/m" + n}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"MSET", "z/m" + n, "2", "z/n" + n, "3"}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"MGET", "a/m" + n, "z/m" + n}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"DEL", "z/n" + n, "a/absent"}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"EXISTS", "z/n" + n}), "+QUEUED\r\n");
        // Nothing has applied yet.
        resp_client peek(c.port(id));
        BOOST_REQUIRE_EQUAL(peek.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(peek.call({"GET", "a/m" + n}), "$-1\r\n");

        // Reads inside the transaction see its own writes.
        BOOST_CHECK_EQUAL(client.call({"EXEC"}), "*6\r\n+OK\r\n" + bulk("1") + "+OK\r\n*2\r\n" +
                                                     bulk("1") + bulk("2") + ":1\r\n:0\r\n");
        BOOST_CHECK_EQUAL(peek.call({"MGET", "a/m" + n, "z/m" + n, "z/n" + n}),
                          "*3\r\n" + bulk("1") + bulk("2") + "$-1\r\n");

        // DISCARD drops the queue.
        BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"DEL", "a/m" + n}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"DISCARD"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"GET", "a/m" + n}), bulk("1"));

        // A refused command dooms the EXEC, and nothing applies.
        BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"DEL", "a/m" + n}), "+QUEUED\r\n");
        BOOST_CHECK(starts_with(client.call({"INFO"}), "-ERR INFO is not supported inside MULTI"));
        BOOST_CHECK_EQUAL(client.call({"SET", "a/x"}),
                          "-ERR wrong number of arguments for 'set' command\r\n");
        BOOST_CHECK_EQUAL(client.call({"EXEC"}),
                          "-EXECABORT Transaction discarded because of previous errors.\r\n");
        BOOST_CHECK_EQUAL(client.call({"GET", "a/m" + n}), bulk("1"));

        // A value conflict is that element's error and writes nothing.
        BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"SET", "a/m" + n, "other"}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"SET", "z/c" + n, "fresh"}), "+QUEUED\r\n");
        BOOST_CHECK_EQUAL(client.call({"EXEC"}),
                          "*2\r\n-ERR value conflict for an existing key\r\n+OK\r\n");
        BOOST_CHECK_EQUAL(client.call({"MGET", "a/m" + n, "z/c" + n}),
                          "*2\r\n" + bulk("1") + bulk("fresh"));
    }
}

BOOST_AUTO_TEST_CASE(isolation_is_per_connection_and_never_downgraded,
                     *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    resp_client client(c.port(1));
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION"}), bulk("read_committed"));
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION", "read-committed-wait"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION"}), bulk("read_committed_wait"));
    auto snapshot = client.call({"KYTHIRA.ISOLATION", "snapshot"});
    BOOST_CHECK(starts_with(snapshot, "-ERR isolation snapshot is not available"));
    BOOST_CHECK(snapshot.find("mvcc::on") != std::string::npos);
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION"}), bulk("read_committed_wait"));
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION", "bogus"}),
                      "-ERR unknown isolation level 'bogus'\r\n");
    BOOST_CHECK(
        starts_with(client.call({"WATCH", "a/w"}), "-ERR WATCH needs a build with mvcc::on"));

    // A second connection still has the gateway's default.
    resp_client other(c.port(1));
    BOOST_REQUIRE_EQUAL(other.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(other.call({"KYTHIRA.ISOLATION"}), bulk("read_committed"));

    // read_committed_wait still commits a plain MSET.
    BOOST_CHECK_EQUAL(client.call({"MSET", "a/w", "1", "z/w", "2"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"MGET", "a/w", "z/w"}), "*2\r\n" + bulk("1") + bulk("2"));
}

BOOST_AUTO_TEST_CASE(kythira_txn_is_internal_only, *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto leader = c.leader_of(1);
    resp_client client(c.port(leader));
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.TXN", "READ", "a/k"}),
                      "-NOPERM KYTHIRA.TXN is internal to the gateways\r\n");

    resp_client internal(c.port(leader));
    BOOST_REQUIRE_EQUAL(internal.call({"AUTH", "kythira-internal", "internal-secret"}), "+OK\r\n");
    // An absent key with no intent: two zero flags.
    BOOST_CHECK_EQUAL(internal.call({"KYTHIRA.TXN", "READ", "a/k"}), bulk(std::string("\0\0", 2)));
    BOOST_CHECK(starts_with(internal.call({"KYTHIRA.TXN", "BOGUS", "x"}),
                            "-ERR unknown KYTHIRA.TXN subcommand"));
    // Not the leader: the retry error, never a second hop.
    const auto follower = leader == 1 ? 2 : 1;
    resp_client internal_follower(c.port(follower));
    BOOST_REQUIRE_EQUAL(internal_follower.call({"AUTH", "kythira-internal", "internal-secret"}),
                        "+OK\r\n");
    BOOST_CHECK_EQUAL(internal_follower.call({"KYTHIRA.TXN", "READ", "a/k"}),
                      "-ERR shard has no reachable leader, retry\r\n");
}

BOOST_AUTO_TEST_CASE(a_plain_write_resolves_an_expired_lock_and_retries_once,
                     *boost::unit_test::timeout(120)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    const auto now = c.host(1).txn_now_ms();

    // A lock whose holder is long gone: SET resolves it (aborting the
    // holder) and then applies.
    plant_intent(c, "a/expired", now - 1000);
    resp_client client(c.port(c.leader_of(1)));
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "a/expired", "mine"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/expired"}), bulk("mine"));

    // A lock still inside its TTL: the write is refused with a retry error
    // naming the holder, and the key is untouched.
    plant_intent(c, "a/held", now + 600000);
    BOOST_CHECK_EQUAL(client.call({"SET", "a/held", "mine"}),
                      "-ERR key is locked by transaction "
                      "000000000000dead000000000000beef, retry\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/held"}), "$-1\r\n");
    // A transaction meeting it conflicts and applies nothing.
    auto conflict = client.call({"MSET", "a/held", "x", "z/held", "y"});
    BOOST_CHECK(starts_with(conflict, "-ERR transaction aborted: write conflict"));
    BOOST_CHECK_EQUAL(client.call({"GET", "z/held"}), "$-1\r\n");
}

// The reply bytes of the transaction commands (CONFIG_REDIS_GATEWAY_TRANSACTIONS),
// pinned before the gateway moves into services/redis/
// (.kiro/specs/redis-gateway-module/ task 1); redis_gateway_integration_test
// pins the rest. Keys are spread over both shards. Regenerate with
// KYTHIRA_UPDATE_GOLDENS=1; a change is a wire change.
BOOST_AUTO_TEST_CASE(txn_resp_replies_match_the_golden_file, *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    using kythira::testing::golden::escape;
    std::string out =
        "# RESP replies of the transaction commands (redis-gateway-module task 1).\n"
        "# One `>` line per command sent, one `<` line per reply, escaped.\n"
        "# Regenerate with KYTHIRA_UPDATE_GOLDENS=1; a change here is a wire change.\n";
    auto record = [&](resp_client& client, const std::string& who,
                      const std::vector<std::string>& argv) {
        std::string line = "> " + who;
        for (const auto& a : argv) {
            line += " " + escape(a);
        }
        out += line + "\n< " + escape(client.call(argv)) + "\n";
    };

    resp_client ops(c.port(c.leader_of(1)));
    record(ops, "ops", {"AUTH", "ops", "ops-secret"});
    out += "## multi-key commands\n";
    record(ops, "ops", {"MSET", "a/1", "left", "z/1", "right"});
    record(ops, "ops", {"MSET", "a/1", "left"});
    record(ops, "ops", {"MSET", "a/1", "other"});
    record(ops, "ops", {"MSET", "a/2"});
    record(ops, "ops", {"MSET"});
    record(ops, "ops", {"MGET", "a/1", "z/1", "a/absent"});
    record(ops, "ops", {"MGET"});
    record(ops, "ops", {"DEL", "a/1", "z/1", "a/absent"});
    record(ops, "ops", {"MGET", "a/1", "z/1"});
    out += "## MULTI / EXEC / DISCARD / WATCH\n";
    record(ops, "ops", {"EXEC"});
    record(ops, "ops", {"DISCARD"});
    record(ops, "ops", {"MULTI"});
    record(ops, "ops", {"MULTI"});
    record(ops, "ops", {"SET", "a/m", "1"});
    record(ops, "ops", {"GET", "a/m"});
    record(ops, "ops", {"MSET", "z/m", "2", "z/n", "3"});
    record(ops, "ops", {"MGET", "a/m", "z/m"});
    record(ops, "ops", {"DEL", "z/n", "a/absent"});
    record(ops, "ops", {"EXISTS", "z/n"});
    record(ops, "ops", {"EXEC"});
    record(ops, "ops", {"MULTI"});
    record(ops, "ops", {"SET", "a/d", "1"});
    record(ops, "ops", {"DISCARD"});
    record(ops, "ops", {"GET", "a/d"});
    record(ops, "ops", {"MULTI"});
    record(ops, "ops", {"GET"});
    record(ops, "ops", {"FLUSHALL"});
    record(ops, "ops", {"EXEC"});
    record(ops, "ops", {"WATCH", "a/m"});
    record(ops, "ops", {"UNWATCH"});
    out += "## isolation and internal commands\n";
    record(ops, "ops", {"KYTHIRA.ISOLATION"});
    record(ops, "ops", {"KYTHIRA.ISOLATION", "read-committed-wait"});
    record(ops, "ops", {"KYTHIRA.ISOLATION"});
    record(ops, "ops", {"KYTHIRA.ISOLATION", "snapshot"});
    record(ops, "ops", {"KYTHIRA.ISOLATION", "bogus"});
    record(ops, "ops", {"KYTHIRA.TXN", "READ", "a/k"});
    // farm may write only under a/: a multi-key command with a key outside
    // its scope is refused as a whole.
    resp_client farm(c.port(c.leader_of(1)));
    record(farm, "farm", {"AUTH", "farm", "farm-secret"});
    record(farm, "farm", {"MSET", "a/f", "1", "z/f", "2"});
    record(farm, "farm", {"MGET", "a/f", "z/f"});
    record(farm, "farm", {"MULTI"});
    record(farm, "farm", {"SET", "z/f", "1"});
    record(farm, "farm", {"EXEC"});

    kythira::testing::golden::check_golden("txn_resp_replies.txt", out);
}

BOOST_AUTO_TEST_SUITE_END()

// A front end without the data layer (.kiro/specs/redis-general-data-types/
// task 16) coordinates cross-shard transactions: it holds no replica, so
// every participant message and transactional read goes to the leader the
// data nodes' routes name, over KYTHIRA.TXN, and the replies are the bytes a
// co-located gateway gives.
BOOST_AUTO_TEST_CASE(a_front_end_without_data_coordinates_transactions,
                     *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto& fe = c.add_front_end();
    resp_client client(fe.port());
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    resp_client peer(c.port(1));
    BOOST_REQUIRE_EQUAL(peer.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");

    BOOST_CHECK_EQUAL(client.call({"MSET", "a/fe", "left", "z/fe", "right"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(peer.call({"MGET", "a/fe", "z/fe", "a/none"}),
                      "*3\r\n" + bulk("left") + bulk("right") + "$-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"MGET", "a/fe", "z/fe", "a/none"}),
                      "*3\r\n" + bulk("left") + bulk("right") + "$-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"MSET", "a/fe", "other", "z/fe2", "x"}),
                      "-ERR value conflict for an existing key\r\n");

    BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "a/fe/m", "1"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/fe/m"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"MSET", "z/fe/m", "2", "z/fe/n", "3"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "z/fe/n", "a/absent"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"EXEC"}), "*4\r\n+OK\r\n" + bulk("1") + "+OK\r\n:1\r\n");
    BOOST_CHECK_EQUAL(peer.call({"MGET", "a/fe/m", "z/fe/m", "z/fe/n"}),
                      "*3\r\n" + bulk("1") + bulk("2") + "$-1\r\n");

    BOOST_CHECK_EQUAL(client.call({"DEL", "a/fe", "z/fe", "a/none"}), ":2\r\n");
    BOOST_CHECK_EQUAL(peer.call({"MGET", "a/fe", "z/fe"}), "*2\r\n$-1\r\n$-1\r\n");

    BOOST_CHECK_GE(fe.stats()._txn_committed.load(), 3u);
    BOOST_CHECK_EQUAL(fe.stats()._txn_unknown.load(), 0u);
}

// A gateway without the front end (.kiro/specs/redis-general-data-types/
// task 17) holds each connection's state: the MULTI queue, sent whole with
// EXEC, and the isolation level. A front end keeps nothing between calls, so
// the queue survives the connection moving to another front end mid-MULTI.
BOOST_AUTO_TEST_CASE(a_gateway_apart_holds_the_connection_state, *boost::unit_test::timeout(180)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto& gw = c.add_gateway();
    resp_client client(gw.port());
    BOOST_REQUIRE_EQUAL(client.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    resp_client peer(c.port(1));
    BOOST_REQUIRE_EQUAL(peer.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");

    BOOST_CHECK_EQUAL(client.call({"EXEC"}), "-ERR EXEC without MULTI\r\n");
    BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"MULTI"}), "-ERR MULTI calls can not be nested\r\n");
    BOOST_CHECK_EQUAL(client.call({"SET", "a/g", "1"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/g"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"MSET", "z/g", "2", "z/h", "3"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(peer.call({"GET", "a/g"}), "$-1\r\n");
    BOOST_CHECK_EQUAL(client.call({"EXEC"}), "*3\r\n+OK\r\n" + bulk("1") + "+OK\r\n");
    BOOST_CHECK_EQUAL(peer.call({"MGET", "a/g", "z/g", "z/h"}),
                      "*3\r\n" + bulk("1") + bulk("2") + bulk("3"));

    BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "a/g"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(client.call({"DISCARD"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/g"}), bulk("1"));

    BOOST_CHECK_EQUAL(client.call({"MULTI"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"DEL", "a/g"}), "+QUEUED\r\n");
    BOOST_CHECK(starts_with(client.call({"INFO"}), "-ERR INFO is not supported inside MULTI"));
    BOOST_CHECK_EQUAL(client.call({"EXEC"}),
                      "-EXECABORT Transaction discarded because of previous errors.\r\n");
    BOOST_CHECK_EQUAL(client.call({"GET", "a/g"}), bulk("1"));

    // The isolation level is the connection's, whichever front end runs it.
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION", "read-committed-wait"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(client.call({"KYTHIRA.ISOLATION"}), bulk("read_committed_wait"));
    resp_client other(gw.port());
    BOOST_REQUIRE_EQUAL(other.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(other.call({"KYTHIRA.ISOLATION"}), bulk("read_committed"));

    BOOST_CHECK_EQUAL(gw.stats()._front_end_lost.load(), 0u);

    // Three layers: this gateway over two front ends without data. The
    // front end its connection is pinned to goes away mid-MULTI; the
    // queue is the gateway's, so EXEC runs it whole on the other.
    std::array<gateway_type*, 2> fes{&c.add_front_end(), &c.add_front_end()};
    auto& apart = c.add_gateway({fes[0]->port(), fes[1]->port()});
    resp_client tx(apart.port());
    BOOST_REQUIRE_EQUAL(tx.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_CHECK_EQUAL(tx.call({"MULTI"}), "+OK\r\n");
    const std::array<std::uint64_t, 2> before{fes[0]->stats()._commands.load(),
                                              fes[1]->stats()._commands.load()};
    BOOST_CHECK_EQUAL(tx.call({"SET", "a/p", "1"}), "+QUEUED\r\n");
    const std::size_t pinned = fes[0]->stats()._commands.load() != before[0] ? 0 : 1;
    fes[pinned]->stop();
    BOOST_CHECK_EQUAL(tx.call({"SET", "z/p", "2"}), "+QUEUED\r\n");
    BOOST_CHECK_EQUAL(tx.call({"EXEC"}), "*2\r\n+OK\r\n+OK\r\n");
    BOOST_CHECK_EQUAL(peer.call({"MGET", "a/p", "z/p"}), "*2\r\n" + bulk("1") + bulk("2"));
    BOOST_CHECK_EQUAL(apart.stats()._front_end_repins.load(), 1u);
    BOOST_CHECK_EQUAL(apart.stats()._front_end_lost.load(), 0u);
}
