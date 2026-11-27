// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// `append_sink_persistence` under a running three-node cluster
// (.kiro/specs/khold-block-service/ task 3, Requirement 7.4).
//
// Every node's engine is a memory engine wrapped in the adaptor, with a
// sink that keeps payloads beside it. After the leader commits commands
// with payloads larger than any descriptor:
//
//  1. no node's log storage holds a payload: every `normal` entry it
//     stores is a descriptor;
//  2. every node's sink holds every payload, so the followers received the
//     full entries over AppendEntries (the leader's log reads give them
//     back through the sink);
//  3. every node's state machine applied the full commands, in order, so
//     state machines see exactly what they would without a sink;
//  4. a node restarted on the same storage and sink reads its log back with
//     every payload, and its state machine reaches the same state.
//
// The adaptor's own contract (ordering of syncs and barriers, truncation,
// recovery after a crash) is in append_sink_unit_test.cpp.
#define BOOST_TEST_MODULE raft_append_sink_cluster_test
#include <boost/test/unit_test.hpp>
#include <raft/future_default.hpp>

#include <raft/append_sink.hpp>
#include <raft/persistence.hpp>
#include <raft/raft.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
struct FollyInitFixture {
    FollyInitFixture() {
        int argc = 1;
        char* argv0[] = {const_cast<char*>("raft_append_sink_cluster_test"), nullptr};
        char** argv = argv0;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
BOOST_GLOBAL_FIXTURE(FollyInitFixture);
#endif

namespace {

using memory_engine_t = kythira::memory_persistence_engine<>;
using log_entry_t = memory_engine_t::log_entry_t;
using snapshot_t = memory_engine_t::snapshot_t;

constexpr std::byte descriptor_tag{0xDE};
constexpr std::size_t payload_size = 4096;
constexpr std::uint64_t seed_index = 10;
constexpr std::uint64_t seed_term = 1;
constexpr int commands = 12;

auto is_descriptor(const log_entry_t& e) -> bool {
    return e.command().size() == 1 && e.command()[0] == descriptor_tag;
}

// The log storage one node keeps across a restart.
struct shared_store {
    std::mutex mu;
    memory_engine_t state;
};

class shared_engine {
public:
    using log_entry_t = ::log_entry_t;
    using snapshot_t = ::snapshot_t;

    explicit shared_engine(std::shared_ptr<shared_store> s) : _s(std::move(s)) {}

    auto save_current_term(std::uint64_t t) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.save_current_term(t);
    }
    auto load_current_term() -> std::uint64_t {
        const std::lock_guard lock(_s->mu);
        return _s->state.load_current_term();
    }
    auto save_voted_for(std::uint64_t n) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.save_voted_for(n);
    }
    auto load_voted_for() -> std::optional<std::uint64_t> {
        const std::lock_guard lock(_s->mu);
        return _s->state.load_voted_for();
    }
    auto append_log_entry(const log_entry_t& e) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.append_log_entry(e);
    }
    auto get_log_entry(std::uint64_t i) -> std::optional<log_entry_t> {
        const std::lock_guard lock(_s->mu);
        return _s->state.get_log_entry(i);
    }
    auto get_log_entries(std::uint64_t a, std::uint64_t b) -> std::vector<log_entry_t> {
        const std::lock_guard lock(_s->mu);
        return _s->state.get_log_entries(a, b);
    }
    auto get_last_log_index() -> std::uint64_t {
        const std::lock_guard lock(_s->mu);
        return _s->state.get_last_log_index();
    }
    auto truncate_log(std::uint64_t i) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.truncate_log(i);
    }
    auto save_snapshot(const snapshot_t& snap) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.save_snapshot(snap);
    }
    auto load_snapshot() -> std::optional<snapshot_t> {
        const std::lock_guard lock(_s->mu);
        return _s->state.load_snapshot();
    }
    auto delete_log_entries_before(std::uint64_t i) -> void {
        const std::lock_guard lock(_s->mu);
        _s->state.delete_log_entries_before(i);
    }

private:
    std::shared_ptr<shared_store> _s;
};

// Payloads by index; durable on take (the engine has no barrier, so the
// adaptor syncs before every descriptor append).
class payload_sink {
public:
    auto on_append(const log_entry_t& e) -> log_entry_t {
        if (is_descriptor(e)) {
            return e;
        }
        const std::lock_guard lock(_mu);
        _payloads[e.index()] = e.command();
        log_entry_t d = e;
        d._command = {descriptor_tag};
        return d;
    }
    auto has_payload(const log_entry_t& e) -> bool {
        const std::lock_guard lock(_mu);
        return _payloads.contains(e.index());
    }
    auto rehydrate(const log_entry_t& e) -> std::optional<log_entry_t> {
        if (!is_descriptor(e)) {
            return e;
        }
        const std::lock_guard lock(_mu);
        auto it = _payloads.find(e.index());
        if (it == _payloads.end()) {
            return std::nullopt;
        }
        log_entry_t full = e;
        full._command = it->second;
        return full;
    }
    auto sync() -> void { ++_syncs; }
    auto on_truncate(std::uint64_t from) -> void {
        const std::lock_guard lock(_mu);
        _payloads.erase(_payloads.lower_bound(from), _payloads.end());
    }
    auto release_before(std::uint64_t before) -> void {
        const std::lock_guard lock(_mu);
        _payloads.erase(_payloads.begin(), _payloads.lower_bound(before));
    }
    [[nodiscard]] auto payload(std::uint64_t i) -> std::optional<std::vector<std::byte>> {
        const std::lock_guard lock(_mu);
        auto it = _payloads.find(i);
        return it == _payloads.end() ? std::nullopt : std::optional{it->second};
    }

private:
    std::mutex _mu;
    std::map<std::uint64_t, std::vector<std::byte>> _payloads;
    std::atomic<std::size_t> _syncs{0};
};

using sinking_engine = kythira::append_sink_persistence<shared_engine, payload_sink>;

// Records every command it applies, in order, where the test can read it.
struct applied_log {
    std::mutex mu;
    std::vector<std::vector<std::byte>> commands;
    [[nodiscard]] auto size() -> std::size_t {
        const std::lock_guard lock(mu);
        return commands.size();
    }
};

class recording_state_machine {
public:
    recording_state_machine() : _log(std::make_shared<applied_log>()) {}
    explicit recording_state_machine(std::shared_ptr<applied_log> log) : _log(std::move(log)) {}

    auto apply(const std::vector<std::byte>& command, std::uint64_t) -> std::vector<std::byte> {
        const std::lock_guard lock(_log->mu);
        _log->commands.push_back(command);
        return {};
    }
    [[nodiscard]] auto get_state() const -> std::vector<std::byte> { return {}; }
    auto restore_from_snapshot(const std::vector<std::byte>&, std::uint64_t) -> void {}

private:
    std::shared_ptr<applied_log> _log;
};

template<typename NodeId, typename Address> class preset_peer_discovery {
public:
    using node_id_type = NodeId;
    using address_type = Address;
    auto register_node(NodeId, Address) -> kythira::future_default<void> {
        return kythira::future_factory_default::makeFuture();
    }
    [[nodiscard]] auto find_peers(std::chrono::milliseconds) const
        -> kythira::future_default<std::vector<kythira::peer_info<NodeId, Address>>> {
        return kythira::future_factory_default::makeFuture(
            std::vector<kythira::peer_info<NodeId, Address>>{});
    }
};

struct test_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using raft_network_types = kythira::raft_simulator_network_types<std::string>;
    using network_client_type =
        kythira::simulator_network_client<raft_network_types, serializer_type,
                                          serialized_data_type>;
    using network_server_type =
        kythira::simulator_network_server<raft_network_types, serializer_type,
                                          serialized_data_type>;

    using persistence_engine_type = sinking_engine;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = recording_state_machine;
    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type>;
    using install_snapshot_response_type = kythira::install_snapshot_response<term_id_type>;

    using address_type = std::string;
    using peer_discovery_type = preset_peer_discovery<node_id_type, address_type>;
    using cluster_join_request_type = kythira::cluster_join_request<node_id_type, address_type>;
    using cluster_join_response_type = kythira::cluster_join_response<node_id_type, address_type>;
};

static_assert(kythira::raft_types<test_types>);

using node_t = kythira::node<test_types>;
using sim_t = network_simulator::NetworkSimulator<test_types::raft_network_types>;

template<typename Pred>
auto wait_until(Pred pred, std::chrono::milliseconds deadline = std::chrono::milliseconds{8000})
    -> bool {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        if (std::chrono::steady_clock::now() - start > deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    return true;
}

auto make_config(std::uint64_t id) -> kythira::raft_configuration {
    kythira::raft_configuration cfg;
    const bool candidate = id == 1;
    cfg._election_timeout_min = std::chrono::milliseconds{candidate ? 80 : 30000};
    cfg._election_timeout_max = std::chrono::milliseconds{candidate ? 160 : 40000};
    cfg._heartbeat_interval = std::chrono::milliseconds{26};
    cfg._rpc_timeout = std::chrono::milliseconds{200};
    cfg._bootstrap_retry_interval = std::chrono::milliseconds{200};
    cfg._bootstrap_peer_find_timeout = std::chrono::milliseconds{100};
    return cfg;
}

// Command i: a 4 KiB payload whose bytes encode i, so a wrong or truncated
// payload cannot pass for the right one.
auto command(int i) -> std::vector<std::byte> {
    std::vector<std::byte> c(payload_size);
    for (std::size_t b = 0; b < c.size(); ++b) {
        c[b] = std::byte{static_cast<std::uint8_t>((static_cast<std::size_t>(i) * 7U) + b)};
    }
    return c;
}

struct cluster {
    sim_t sim;
    std::vector<std::shared_ptr<shared_store>> stores;
    std::vector<std::shared_ptr<payload_sink>> sinks;
    std::vector<std::shared_ptr<applied_log>> applied;
    std::vector<std::unique_ptr<node_t>> nodes;

    cluster() {
        sim.start();
        for (std::uint64_t from = 1; from <= 3; ++from) {
            for (std::uint64_t to = 1; to <= 3; ++to) {
                if (from != to) {
                    sim.add_edge(std::to_string(from), std::to_string(to),
                                 network_simulator::NetworkEdge{});
                }
            }
        }
        for (std::uint64_t id = 1; id <= 3; ++id) {
            auto store = std::make_shared<shared_store>();
            store->state.save_current_term(seed_term);
            store->state.save_snapshot(snapshot_t{
                ._last_included_index = seed_index,
                ._last_included_term = seed_term,
                ._configuration =
                    kythira::cluster_configuration<std::uint64_t>{{1, 2, 3}, false, std::nullopt},
                ._state_machine_state = {}});
            stores.push_back(store);
            sinks.push_back(std::make_shared<payload_sink>());
            applied.push_back(std::make_shared<applied_log>());
            nodes.push_back(make_node(id));
        }
        for (auto& n : nodes) {
            n->start();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{180});
        nodes[0]->check_election_timeout();
    }

    auto make_node(std::uint64_t id) -> std::unique_ptr<node_t> {
        auto net = sim.create_node(std::to_string(id));
        return std::make_unique<node_t>(kythira::node_config<test_types>{
            .node_id = id,
            .network_client = test_types::network_client_type{net, test_types::serializer_type{}},
            .network_server = test_types::network_server_type{net, test_types::serializer_type{}},
            .persistence = sinking_engine{shared_engine{stores[id - 1]}, sinks[id - 1]},
            .logger = kythira::console_logger{kythira::log_level::error},
            .metrics = test_types::metrics_type{},
            .membership = test_types::membership_manager_type{},
            .state_machine = recording_state_machine{applied[id - 1]},
            .config = make_config(id),
            .self_address = std::to_string(id),
            .peer_discovery = preset_peer_discovery<std::uint64_t, std::string>{}});
    }

    ~cluster() {
        for (auto& n : std::ranges::reverse_view(nodes)) {
            if (n) {
                n->stop();
            }
        }
    }
    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;

    template<typename Pred> auto pump_until(Pred pred) -> bool {
        return wait_until([&] {
            nodes[0]->check_heartbeat_timeout();
            return pred();
        });
    }

    // The payload-carrying commands node `id` applied, in order.
    auto payload_commands(std::uint64_t id) -> std::vector<std::vector<std::byte>> {
        auto& log = *applied[id - 1];
        const std::lock_guard lock(log.mu);
        std::vector<std::vector<std::byte>> out;
        for (const auto& c : log.commands) {
            if (c.size() == payload_size) {
                out.push_back(c);
            }
        }
        return out;
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(raft_append_sink_cluster)

BOOST_AUTO_TEST_CASE(payloads_go_to_the_sink_and_the_log_keeps_descriptors,
                     *boost::unit_test::timeout(60)) {
    cluster c;
    BOOST_REQUIRE(wait_until([&] { return c.nodes[0]->is_leader(); }));

    for (int i = 0; i < commands; ++i) {
        std::move(c.nodes[0]->submit_command(command(i), std::chrono::milliseconds{5000})).get();
    }
    BOOST_REQUIRE(c.pump_until([&] {
        return c.payload_commands(1).size() == commands &&
               c.payload_commands(2).size() == commands && c.payload_commands(3).size() == commands;
    }));

    for (std::uint64_t id = 1; id <= 3; ++id) {
        BOOST_TEST_INFO_SCOPE("node " << id);
        // 3. the state machine applied the full commands, in order.
        const auto cmds = c.payload_commands(id);
        for (int i = 0; i < commands; ++i) {
            BOOST_TEST((cmds[static_cast<std::size_t>(i)] == command(i)));
        }
        // 1 and 2. storage holds descriptors; the sink holds the payloads.
        auto& store = *c.stores[id - 1];
        const std::lock_guard lock(store.mu);
        const auto last = store.state.get_last_log_index();
        std::size_t descriptors = 0;
        for (std::uint64_t i = seed_index + 1; i <= last; ++i) {
            const auto e = store.state.get_log_entry(i);
            BOOST_REQUIRE(e.has_value());
            BOOST_TEST(e->command().size() < payload_size);
            if (e->type() == kythira::entry_type::normal) {
                BOOST_TEST(is_descriptor(*e));
                const auto p = c.sinks[id - 1]->payload(i);
                BOOST_REQUIRE(p.has_value());
                BOOST_TEST(p->size() == payload_size);
                ++descriptors;
            }
        }
        BOOST_TEST(descriptors >= static_cast<std::size_t>(commands));
    }

    // 4. a follower restarted on the same storage and sink reads every
    // payload back and applies the same commands again.
    c.nodes[2]->stop();
    c.nodes[2].reset();
    c.applied[2] = std::make_shared<applied_log>();
    c.nodes[2] = c.make_node(3);
    c.nodes[2]->start();
    BOOST_REQUIRE(c.pump_until([&] { return c.payload_commands(3).size() == commands; }));
    const auto replayed = c.payload_commands(3);
    for (int i = 0; i < commands; ++i) {
        BOOST_TEST((replayed[static_cast<std::size_t>(i)] == command(i)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
