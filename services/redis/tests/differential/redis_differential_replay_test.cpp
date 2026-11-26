// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_differential_replay_test.cpp
/// @brief The differential suite without containers
///        (.kiro/specs/redis-general-data-types/ task 14's scaffold): the
///        committed Redis 7.2 and Valkey 8 recordings in recs/ replayed
///        against an in-process three-node gateway cluster.
///
/// The cluster is redis_gateway_snapshot_test.cpp's (multi-versioned KV,
/// oracle group, snapshot isolation, mutable values, `--transactions on`, a gateway per host on a
/// real loopback port), with the shards cut at "e" like the container layout
/// (services/redis/docker/differential/kythira.env), so the generator's
/// a..d and e..h keys land on different shards. Each recorded stream is
/// sent to one gateway in RESP2 and again in RESP3 and every reply is
/// classified with the same rules as the container run. This is the check
/// a phase 1 command PR gets in plain CTest; the container run
/// (redis_differential_test.cpp) adds the daemon, real networking and live
/// reference servers.

#define BOOST_TEST_MODULE redis_differential_replay_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <kythira/redis/redis_gateway_impl.hpp>
#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>
#include <raft/txn_state_machine.hpp>

#include "redis_differential.hpp"

#include <boost/json.hpp>

#include <filesystem>
#include <functional>
#include <fstream>
#include <map>
#include <sstream>

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
        char* argv_data[] = {const_cast<char*>("redis_differential_replay_test"), nullptr};
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
using kythira::shard_descriptor;
using kythira::shard_epoch;
using kythira::shard_range;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

using kv_type = kythira::redis_kv_mvcc_state_machine<std::uint64_t>;
using txn_sm_type =
    kythira::transactional_state_machine<kv_type, key_type, kythira::redis_kv_partitioner,
                                         kythira::mvcc::on>;

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

static_assert(gateway_type::k_snapshot);

constexpr group_id_type k_oracle = 1000;

constexpr std::size_t k_node_count = 3;
constexpr std::uint32_t k_kdf_iters = 1000;

auto range_of(std::optional<key_type> start, std::optional<key_type> end) -> shard_range<key_type> {
    return shard_range<key_type>{._start = std::move(start), ._end = std::move(end)};
}

auto acl_text() -> std::string {
    return "user ops " + redis_acl::hash_secret("ops-secret", k_kdf_iters) + " admin *\n" +
           "user kythira-internal " + redis_acl::hash_secret("internal-secret", k_kdf_iters) +
           " read_write *\n";
}

class cluster {
public:
    cluster() {
        _acl.reload(acl_text());
        const std::vector<node_id_t> voters{1, 2, 3};
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
            _hosts.back()->create_group(descriptor_type{._group_id = 1,
                                                        ._range = range_of(std::nullopt, "e"),
                                                        ._epoch = shard_epoch{},
                                                        ._voters = voters});
            _hosts.back()->create_group(descriptor_type{._group_id = 2,
                                                        ._range = range_of("e", std::nullopt),
                                                        ._epoch = shard_epoch{},
                                                        ._voters = voters});
            _hosts.back()->create_oracle_group(voters);
        }
        for (auto& h : _hosts) {
            h->start();
        }
        for (auto& host : _hosts) {
            auto cfg = gateway_config();
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
            if (leader_of(1) != 0 && leader_of(2) != 0 && leader_of(k_oracle) != 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return false;
    }

    /// A node without the data layer (task 16): its host is in no group;
    /// it reaches the shards over KYTHIRA.DATA, their leaders over
    /// KYTHIRA.TXN, and the oracle by asking the data nodes in turn.
    auto add_front_end() -> gateway_type& {
        const auto id = static_cast<node_id_t>(k_node_count + 1 + _front_end_hosts.size());
        _front_end_hosts.push_back(std::make_unique<host_type>(make_config(id)));
        _front_end_hosts.back()->start();
        auto cfg = gateway_config();
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

private:
    static auto gateway_config() -> redis_gateway_config {
        redis_gateway_config cfg;
        cfg._listen = "127.0.0.1:0";
        cfg._internal_secret = "internal-secret";
        cfg._io_threads = 1;
        cfg._worker_threads = 4;
        cfg._command_timeout = std::chrono::milliseconds{5000};
        cfg._allow_plaintext_forwarding = true;
        cfg._transactions = true;
        // As services/redis/docker/differential/kythira.env sets them.
        cfg._txn_isolation = kythira::txn_isolation::snapshot;
        cfg._immutable_values = false;
        return cfg;
    }

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
        cfg.oracle_group = k_oracle;
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

namespace diff = kythira::redis_diff;

/// A blocking client over the harness's own reply parser.
class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _socket(_io) {
        _socket.connect({boost::asio::ip::make_address("127.0.0.1"), port});
        _socket.set_option(boost::asio::ip::tcp::no_delay(true));
    }

    auto call_raw(const std::vector<std::string>& argv) -> std::string {
        boost::asio::write(_socket, boost::asio::buffer(diff::encode_command(argv)));
        for (;;) {
            std::size_t pos = 0;
            if (diff::parse_reply(_buffer, pos)) {
                auto raw = _buffer.substr(0, pos);
                _buffer.erase(0, pos);
                return raw;
            }
            std::array<char, 65536> chunk{};
            auto n = _socket.read_some(boost::asio::buffer(chunk));
            _buffer.append(chunk.data(), n);
        }
    }

private:
    boost::asio::io_context _io;
    boost::asio::ip::tcp::socket _socket;
    std::string _buffer;
};

auto transient(const diff::reply& r) -> bool {
    return r.kind == diff::reply_kind::error &&
           (r.text.find(", retry") != std::string::npos || r.text.rfind("TRYAGAIN", 0) == 0);
}

auto load_recordings() -> std::map<std::uint64_t, std::map<std::string, diff::recording>> {
    std::map<std::uint64_t, std::map<std::string, diff::recording>> out;
    for (const auto& f : std::filesystem::directory_iterator(KYTHIRA_REDIS_DIFF_RECS_DIR)) {
        if (f.path().extension() != ".json") {
            continue;
        }
        std::ifstream in(f.path());
        std::stringstream text;
        text << in.rdbuf();
        auto rec = diff::recording_from_json(boost::json::parse(text.str()));
        out[rec.seed][rec.server] = std::move(rec);
    }
    return out;
}

}  // namespace

namespace {

/// Every recorded stream, in RESP2 and RESP3, against the gateway on the
/// port `port_for(seed, protocol)` names; every reply classified.
void replay(const std::function<std::uint16_t(std::uint64_t, int)>& port_for) {
    const auto recordings = load_recordings();
    BOOST_REQUIRE(!recordings.empty());

    std::vector<diff::difference_row> rows;
    std::size_t compared = 0;
    std::size_t differs = 0;
    for (const auto& [seed, servers] : recordings) {
        const auto& redis = servers.at("redis");
        const auto& valkey = servers.at("valkey");
        BOOST_REQUIRE_EQUAL(redis.entries.size(), valkey.entries.size());
        for (const int protocol : {2, 3}) {
            resp_client client(port_for(seed, protocol));
            const auto hello = diff::parse_one(
                client.call_raw({"HELLO", std::to_string(protocol), "AUTH", "ops", "ops-secret"}));
            BOOST_REQUIRE(hello.kind != diff::reply_kind::error);
            for (char k = 'a'; k < 'a' + 8; ++k) {
                std::vector<std::string> del{"DEL",
                                             std::string(1, k) + ":s" + std::to_string(seed)};
                for (int i = 0; i < 20 && transient(diff::parse_one(client.call_raw(del))); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                }
            }
            bool in_multi = false;
            for (std::size_t i = 0; i < redis.entries.size(); ++i) {
                const auto& e = redis.entries[i];
                const auto& rraw = protocol == 2 ? e.resp2 : e.resp3;
                const auto& vraw =
                    protocol == 2 ? valkey.entries[i].resp2 : valkey.entries[i].resp3;
                const auto rr = diff::parse_one(rraw);
                const auto vr = diff::parse_one(vraw);
                auto kraw = client.call_raw(e.argv);
                for (int attempt = 0; attempt < 20 && !in_multi && transient(diff::parse_one(kraw));
                     ++attempt) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{100});
                    kraw = client.call_raw(e.argv);
                }
                const auto name = diff::detail::upper(e.argv.front());
                if (name == "MULTI" && rr.kind == diff::reply_kind::simple) {
                    in_multi = true;
                } else if (name == "EXEC" || name == "DISCARD") {
                    in_multi = false;
                }
                const auto kr = diff::parse_one(kraw);
                ++compared;
                const auto v = diff::classify(diff::command{e.argv, e.shape}, rr, vr, kr);
                if (v.result == diff::outcome::same) {
                    continue;
                }
                const bool bad = v.result == diff::outcome::differs;
                differs += bad ? 1 : 0;
                rows.push_back(
                    {seed, protocol, i, e.argv, rr, vr, kr, bad ? std::string("DIFFERS") : v.rule});
            }
        }
    }
    const auto table = diff::render_difference_table(rows);
    BOOST_TEST_MESSAGE(compared << " replies compared, " << differs << " differ\n" << table);
    BOOST_TEST(differs == 0U, "Kythira differs from both references " << differs << " times:\n"
                                                                      << table);
}

}  // namespace

BOOST_AUTO_TEST_CASE(recorded_streams_replay_against_the_gateway, *boost::unit_test::timeout(600)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    replay([&c](std::uint64_t seed, int protocol) {
        return c.port(static_cast<node_id_t>(1 + ((seed + protocol) % k_node_count)));
    });
}

// The same streams through a front end that holds no replica
// (.kiro/specs/redis-general-data-types/ task 16, Requirement 18.6): the
// split layout answers with the bytes the co-located one does.
BOOST_AUTO_TEST_CASE(recorded_streams_replay_through_a_front_end_without_data,
                     *boost::unit_test::timeout(600)) {
    cluster c;
    BOOST_REQUIRE(c.await_all_leaders(std::chrono::seconds{20}));
    auto& fe = c.add_front_end();
    replay([&fe](std::uint64_t, int) { return fe.port(); });
}
