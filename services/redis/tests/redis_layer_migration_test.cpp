// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// Moving the data layer between nodes on a running cluster
/// (.kiro/specs/redis-general-data-types/ task 19, Requirement 21.3-21.4):
/// `KYTHIRA.EVACUATE`'s wire forms, and a cluster that evacuates a founding
/// data node onto a node that joined, then back, while it serves.

#define BOOST_TEST_MODULE redis_layer_migration_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>

#include <kythira/redis/redis_evacuation.hpp>
#include <kythira/redis/redis_gateway_impl.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <boost/asio.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("redis_layer_migration_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

using namespace std::chrono_literals;
namespace ev = kythira::redis_evacuation;

// ── the wire forms ───────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(evacuate_wire)

BOOST_AUTO_TEST_CASE(start_parses_targets_replicas_addresses_and_local) {
    std::string why;
    const auto r = ev::parse_start({"1", "TO", "4", "5", "4", "replicas", "3", "ADDRESS", "5",
                                    "http://n5:7000", "n5:6379", "LOCAL"},
                                   why);
    BOOST_REQUIRE_MESSAGE(r, why);
    BOOST_TEST(r->_node == "1");
    BOOST_TEST((r->_targets == std::vector<std::string>{"4", "5"}));
    BOOST_TEST(r->_replicas == 3U);
    BOOST_REQUIRE_EQUAL(r->_addresses.size(), 1U);
    BOOST_TEST((r->_addresses[0] == ev::target_address{"5", "http://n5:7000", "n5:6379"}));
    BOOST_TEST(r->_local);

    // The fanned-out form reads back as the same job.
    auto argv = ev::to_argv(*r);
    BOOST_TEST(argv[0] == "KYTHIRA.EVACUATE");
    BOOST_TEST(argv[1] == "START");
    argv.erase(argv.begin(), argv.begin() + 2);
    const auto back = ev::parse_start(argv, why);
    BOOST_REQUIRE(back);
    BOOST_TEST((*back == *r));
}

BOOST_AUTO_TEST_CASE(start_refuses_what_it_cannot_run) {
    std::string why;
    BOOST_TEST(!ev::parse_start({}, why));
    BOOST_TEST(!ev::parse_start({"1", "TO"}, why));
    BOOST_TEST(why.find("at least one target") != std::string::npos);
    BOOST_TEST(!ev::parse_start({"1", "TO", "1"}, why));
    BOOST_TEST(why.find("its own target") != std::string::npos);
    BOOST_TEST(!ev::parse_start({"1", "REPLICAS", "0"}, why));
    BOOST_TEST(!ev::parse_start({"1", "REPLICAS", "x"}, why));
    BOOST_TEST(!ev::parse_start({"1", "ADDRESS", "4", "http://n4:7000"}, why));
    BOOST_TEST(!ev::parse_start({"1", "NOW"}, why));
    BOOST_TEST(why.find("NOW") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(a_node_view_round_trips_with_an_error_that_has_spaces) {
    ev::node_view v;
    v._node = "2";
    v._running = true;
    v._evacuee = "1";
    v._held = {"1", "2", "9"};
    v._members = {"2", "3", "4"};
    v._led = {{"1", "add_replica", "4", "not caught up\nyet"}, {"2", "done", "", ""}};
    const auto back = ev::decode_node_view(ev::encode_node_view(v));
    BOOST_REQUIRE(back);
    BOOST_TEST(back->_node == "2");
    BOOST_TEST(back->_running);
    BOOST_TEST(back->_evacuee == "1");
    BOOST_TEST((back->_held == v._held));
    BOOST_TEST((back->_members == v._members));
    BOOST_REQUIRE_EQUAL(back->_led.size(), 2U);
    BOOST_TEST(back->_led[0]._error == "not caught up yet");
    BOOST_TEST(back->_led[0]._node == "4");
    BOOST_TEST(back->_led[1]._node.empty());
    BOOST_TEST(!back->done());

    ev::node_view idle;
    idle._node = "3";
    const auto idle_back = ev::decode_node_view(ev::encode_node_view(idle));
    BOOST_REQUIRE(idle_back);
    BOOST_TEST(!idle_back->_running);
    BOOST_TEST(idle_back->_evacuee.empty());
    BOOST_TEST(idle_back->_held.empty());
    BOOST_TEST(idle_back->_members.empty());
    // A view without the members line (an older node) still reads.
    BOOST_TEST(
        ev::decode_node_view("node 1 running 1 evacuee -\nheld 1\nled 1 done -").has_value());

    BOOST_TEST(!ev::decode_node_view("node 1 running 2 evacuee -\nheld"));
    BOOST_TEST(!ev::decode_node_view("node 1 running 1 evacuee -"));
    BOOST_TEST(!ev::decode_node_view("node 1 running 1 evacuee -\nheld 1\nled 1 done"));
}

BOOST_AUTO_TEST_CASE(the_merge_is_done_only_when_every_held_group_is_led_and_done) {
    auto view = [](std::string node, std::vector<std::string> held,
                   std::vector<ev::led_group> led) {
        ev::node_view v;
        v._node = std::move(node);
        v._running = true;
        v._evacuee = "1";
        v._held = std::move(held);
        v._led = std::move(led);
        return v;
    };
    // Group 2's leader still moves it.
    auto c = ev::merge({view("1", {}, {}), view("2", {"1", "2"}, {{"1", "done", "", ""}}),
                        view("3", {"1", "2"}, {{"2", "remove_replica", "1", ""}})});
    BOOST_TEST(!c._done);
    // Both done.
    c = ev::merge({view("1", {}, {}), view("2", {"1", "2"}, {{"1", "done", "", ""}}),
                   view("3", {"1", "2"}, {{"2", "done", "", ""}})});
    BOOST_TEST(c._done);
    BOOST_TEST(ev::released(c, "1"));
    BOOST_TEST(!ev::released(c, "2"));
    // A group nobody reports leading is not done.
    c = ev::merge({view("2", {"1", "2"}, {{"1", "done", "", ""}})});
    BOOST_TEST(!c._done);
    // A node that did not answer keeps it open while a group counts it...
    ev::node_view gone;
    gone._unreachable = "4@n4:6379";
    auto led_by_2 = view("2", {"1"}, {{"1", "done", "", ""}});
    led_by_2._members = {"2", "3", "4"};
    c = ev::merge({led_by_2, gone});
    BOOST_TEST(!c._done);
    const auto lines = ev::status_lines(c);
    BOOST_TEST(lines.front() == "done 0");
    BOOST_TEST(std::any_of(lines.begin(), lines.end(),
                           [](const std::string& l) { return l == "node 4@n4:6379 unreachable"; }));
    // ...and not once no group does: a failed evacuee, removed everywhere,
    // never answers again, and the job is still done. It has no say in a
    // release either.
    led_by_2._members = {"2", "3", "5"};
    c = ev::merge({led_by_2, gone});
    BOOST_TEST(c._done);
    BOOST_TEST(ev::released(c, "1"));
}

BOOST_AUTO_TEST_SUITE_END()

// ── a cluster that moves its data layer ──────────────────────────────────────

namespace {

using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

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
    using state_machine_type = kythira::redis_kv_state_machine<log_index_type>;
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
constexpr node_id_t k_nodes = 4;

auto acl_text() -> std::string {
    return "user ops " + kythira::redis_acl::hash_secret("ops-secret", k_kdf_iters) + " admin *\n" +
           "user farm " + kythira::redis_acl::hash_secret("farm-secret", k_kdf_iters) +
           " read_write *\n" + "user kythira-internal " +
           kythira::redis_acl::hash_secret("internal-secret", k_kdf_iters) + " read_write *\n";
}

class resp_client {
public:
    explicit resp_client(std::uint16_t port) : _socket(_io) {
        _socket.connect({boost::asio::ip::make_address("127.0.0.1"), port});
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
                throw std::runtime_error("connection closed: " + ec.message());
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

auto bulk(const std::string& s) -> std::string {
    return "$" + std::to_string(s.size()) + "\r\n" + s + "\r\n";
}

/// Nodes 1-3 found two groups split at "m"; node 4 is a data node that
/// joined: it founds nothing and takes groups only when they add it. Every
/// node runs a co-located gateway and an evacuation controller.
/// `silent_peer` adds a peer gateway that never answers (a node that is
/// down, or not started yet) and one whose address another node answers
/// on to every controller's peers.
class data_cluster {
public:
    explicit data_cluster(bool silent_peer = false) {
        _acl.reload(acl_text());
        for (node_id_t id = 1; id <= k_nodes; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
            if (id <= 3) {
                for (const auto& d : founding_groups()) {
                    _hosts.back()->create_group(d);
                }
            }
        }
        for (auto& h : _hosts) {
            h->start();
        }
        for (node_id_t id = 1; id <= k_nodes; ++id) {
            kythira::redis_gateway_config cfg;
            cfg._listen = "127.0.0.1:0";
            cfg._internal_secret = "internal-secret";
            cfg._io_threads = 1;
            cfg._worker_threads = 4;
            cfg._command_timeout = 3000ms;
            cfg._allow_plaintext_forwarding = true;
            cfg._evacuate = [this, id](const std::vector<std::string>& args, bool internal) {
                return _controllers.at(id - 1)->handle(args, internal);
            };
            _gateways.push_back(std::make_unique<gateway_type>(
                *_hosts[id - 1], _acl, _logger, _metrics, cfg,
                [this](const node_id_t& to) -> std::optional<std::string> {
                    if (to < 1 || to > _gateways.size() || !_gateways[to - 1]) {
                        return std::nullopt;
                    }
                    return endpoint(to);
                }));
        }
        for (node_id_t id = 1; id <= k_nodes; ++id) {
            controller_type::hooks h;
            h._call = [this, id](const std::string& ep, const std::vector<std::string>& argv) {
                return _gateways.at(id - 1)->data_call(ep, argv);
            };
            h._peers = [this, id, silent_peer] {
                std::vector<std::pair<node_id_t, std::string>> out;
                for (node_id_t other = 1; other <= k_nodes; ++other) {
                    if (other != id) {
                        out.emplace_back(other, endpoint(other));
                    }
                }
                if (silent_peer) {
                    // Port 1 on loopback refuses at once.
                    out.emplace_back(k_nodes + 1, "127.0.0.1:1");
                    // And an address that now belongs to another node:
                    // node 3 answers there, as itself.
                    out.emplace_back(k_nodes + 2, endpoint(3));
                }
                return out;
            };
            h._release = [this, id] {
                _released[id - 1] = true;
                return true;
            };
            h._unrelease = [this, id] { _released[id - 1] = false; };
            // Node 4 joined: like the daemon, it knows no founding voter
            // count (0) and takes one from the groups it holds.
            _controllers.push_back(
                std::make_unique<controller_type>(*_hosts[id - 1], id <= 3 ? 3 : 0, h));
        }
        for (auto& g : _gateways) {
            g->start();
        }
        _ready = true;
        _running = true;
        for (std::size_t i = 0; i < _hosts.size(); ++i) {
            _drivers.emplace_back([this, i] {
                while (_running.load()) {
                    _hosts[i]->tick();
                    std::this_thread::sleep_for(5ms);
                }
            });
        }
    }

    ~data_cluster() {
        _running = false;
        for (auto& t : _drivers) {
            t.join();
        }
        for (auto& c : _controllers) {
            c->stop();
        }
        for (auto& g : _gateways) {
            g->stop();
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    data_cluster(const data_cluster&) = delete;
    auto operator=(const data_cluster&) -> data_cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }
    [[nodiscard]] auto port(node_id_t id) -> std::uint16_t { return _gateways.at(id - 1)->port(); }
    [[nodiscard]] auto released(node_id_t id) const -> bool { return _released[id - 1]; }

    /// Whether every group has a leader and `id` is not a voter of any.
    [[nodiscard]] auto voters_of(group_id_type g) -> std::vector<node_id_t> {
        for (node_id_t id = 1; id <= k_nodes; ++id) {
            auto* n = _hosts[id - 1]->group_node(g);
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

private:
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

    auto endpoint(node_id_t id) -> std::string {
        return "127.0.0.1:" + std::to_string(_gateways.at(id - 1)->port());
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
        // As the node wires it: a group adding this node is learned from a
        // peer's `KYTHIRA.EVACUATE DESCRIPTOR`.
        cfg.lookup_descriptor = [this,
                                 id](const group_id_type& g) -> std::optional<descriptor_type> {
            if (!_ready.load()) {
                return std::nullopt;
            }
            return _controllers.at(id - 1)->lookup_descriptor(g);
        };
        return cfg;
    }

    message_fabric _fabric{8};
    kythira::redis_acl _acl;
    kythira::console_logger _logger{kythira::log_level::warning};
    kythira::noop_metrics _metrics;
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::unique_ptr<gateway_type>> _gateways;
    std::vector<std::unique_ptr<controller_type>> _controllers;
    std::array<bool, k_nodes> _released{};
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
    std::atomic<bool> _ready{false};
};

/// `KYTHIRA.EVACUATE STATUS` until it reports done.
auto await_done(data_cluster& c, resp_client& ops) -> bool {
    return c.await(
        [&] {
            const auto r = ops.call({"KYTHIRA.EVACUATE", "STATUS"});
            return r.find(bulk("done 1")) != std::string::npos;
        },
        60s);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(evacuation)

BOOST_AUTO_TEST_CASE(a_founding_data_node_moves_to_a_joined_one_and_back_under_writes,
                     *boost::unit_test::timeout(240)) {
    data_cluster c;
    BOOST_REQUIRE(c.await([&] { return !c.voters_of(1).empty() && !c.voters_of(2).empty(); }, 20s));

    resp_client farm(c.port(2));
    BOOST_REQUIRE_EQUAL(farm.call({"AUTH", "farm", "farm-secret"}), "+OK\r\n");
    std::size_t acked = 0;
    auto write_some = [&](std::size_t n) {
        for (std::size_t i = 0; i < n; ++i, ++acked) {
            const auto key = (acked % 2 == 0 ? "a/" : "z/") + std::to_string(acked);
            // A move may answer a retryable error; the write is retried.
            std::string r;
            for (int attempt = 0; attempt < 50; ++attempt) {
                r = farm.call({"SET", key, "v" + std::to_string(acked)});
                if (r == "+OK\r\n") {
                    break;
                }
                std::this_thread::sleep_for(100ms);
            }
            BOOST_REQUIRE_EQUAL(r, "+OK\r\n");
        }
    };
    write_some(20);

    // Only an admin may start one; a client gets NOPERM.
    BOOST_TEST(farm.call({"KYTHIRA.EVACUATE", "STATUS"}).rfind("-NOPERM", 0) == 0);

    resp_client ops(c.port(2));
    BOOST_REQUIRE_EQUAL(ops.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "DESCRIPTOR", "1"}).rfind("-NOPERM", 0) == 0);
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "START"}).rfind("-ERR", 0) == 0);

    // Node 1 out, onto node 4, while writes continue.
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.EVACUATE", "START", "1", "TO", "4"}), "+OK\r\n");
    std::thread writer([&] { write_some(30); });
    BOOST_TEST(await_done(c, ops));
    writer.join();
    for (group_id_type g : {1, 2}) {
        BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{2, 3, 4}));
    }

    // Released on the evacuee once every node agrees.
    resp_client ops1(c.port(1));
    BOOST_REQUIRE_EQUAL(ops1.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_TEST(ops1.call({"KYTHIRA.EVACUATE", "RELEASE"}) == "+OK\r\n");
    BOOST_TEST(c.released(1));
    // Node 2 is no evacuee: it may not call itself released.
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "RELEASE"}).rfind("-ERR", 0) == 0);

    // Every acknowledged write is there, read through the node that joined.
    resp_client reader(c.port(4));
    BOOST_REQUIRE_EQUAL(reader.call({"AUTH", "farm", "farm-secret"}), "+OK\r\n");
    for (std::size_t i = 0; i < acked; ++i) {
        const auto key = (i % 2 == 0 ? "a/" : "z/") + std::to_string(i);
        BOOST_TEST(reader.call({"GET", key}) == bulk("v" + std::to_string(i)), key);
    }

    // And back: node 4 out, onto node 1, which withdraws its release.
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.EVACUATE", "START", "4", "TO", "1"}), "+OK\r\n");
    BOOST_TEST(!c.released(1));
    std::thread writer2([&] { write_some(20); });
    BOOST_TEST(await_done(c, ops));
    writer2.join();
    for (group_id_type g : {1, 2}) {
        BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{1, 2, 3}));
    }
    resp_client back(c.port(1));
    BOOST_REQUIRE_EQUAL(back.call({"AUTH", "farm", "farm-secret"}), "+OK\r\n");
    for (std::size_t i = 0; i < acked; ++i) {
        const auto key = (i % 2 == 0 ? "a/" : "z/") + std::to_string(i);
        BOOST_TEST(back.call({"GET", key}) == bulk("v" + std::to_string(i)), key);
    }
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "CANCEL"}) == "+OK\r\n");
    const auto status = ops.call({"KYTHIRA.EVACUATE", "STATUS"});
    BOOST_TEST(status.find("running 1") == std::string::npos, status);
}

// A data node that does not answer (down for good, or not started yet)
// and is no member of any group neither refuses the START nor keeps STATUS
// short of done. Before, START answered TRYAGAIN naming it for as long as
// it stayed silent, and STATUS never finished.
BOOST_AUTO_TEST_CASE(a_silent_peer_that_is_no_member_holds_nothing_back,
                     *boost::unit_test::timeout(240)) {
    data_cluster c(true);
    BOOST_REQUIRE(c.await([&] { return !c.voters_of(1).empty() && !c.voters_of(2).empty(); }, 20s));
    resp_client ops(c.port(2));
    BOOST_REQUIRE_EQUAL(ops.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    // The joined node holds nothing yet, so it knows no voter count.
    resp_client ops4(c.port(4));
    BOOST_REQUIRE_EQUAL(ops4.call({"AUTH", "ops", "ops-secret"}), "+OK\r\n");
    BOOST_TEST(ops4.call({"KYTHIRA.EVACUATE", "START", "1", "TO", "4"})
                   .rfind("-ERR this node holds no group", 0) == 0);
    BOOST_REQUIRE_EQUAL(ops.call({"KYTHIRA.EVACUATE", "START", "1", "TO", "4"}), "+OK\r\n");
    BOOST_TEST(await_done(c, ops));
    for (group_id_type g : {1, 2}) {
        BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{2, 3, 4}));
    }
    // Neither counts: the silent one is no member, and node 3's answer at
    // node 6's address is not taken for node 6's view.
    const auto status = ops.call({"KYTHIRA.EVACUATE", "STATUS"});
    BOOST_TEST(status.find("node 5@127.0.0.1:1 unreachable") != std::string::npos, status);
    const auto six = status.find("node 6@127.0.0.1:");
    BOOST_TEST((six != std::string::npos &&
                status.substr(six, status.find('\r', six) - six).ends_with(" unreachable")),
               status);
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "CANCEL"}) == "+OK\r\n");

    // Now it holds groups of three voters, and START there keeps three.
    BOOST_REQUIRE_EQUAL(ops4.call({"KYTHIRA.EVACUATE", "START", "4", "TO", "1"}), "+OK\r\n");
    BOOST_TEST(await_done(c, ops));
    for (group_id_type g : {1, 2}) {
        BOOST_TEST((c.voters_of(g) == std::vector<node_id_t>{1, 2, 3}));
    }
    BOOST_TEST(ops.call({"KYTHIRA.EVACUATE", "CANCEL"}) == "+OK\r\n");
}

BOOST_AUTO_TEST_SUITE_END()
