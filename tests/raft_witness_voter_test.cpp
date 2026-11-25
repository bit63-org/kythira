// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Witness voters (.kiro/specs/khold-block-service/ task 4, Requirement
// 5.2) on a three-node cluster over the network simulator: nodes 1 and 2
// hold data, node 3 is a witness. Every engine is an
// append_sink_persistence whose sink can describe entries.
//
//  1. A witness never campaigns and never leads, however long it goes
//     without hearing from a leader, and refuses TimeoutNow and transfer.
//  2. A witness votes and acknowledges: with the other data replica cut
//     off, the leader commits on itself plus the witness. The witness's
//     storage and sink hold descriptors only; no payload reaches it.
//  3. A candidate behind the witness cannot be elected. Writes commit on
//     the leader and the witness while node 2 is cut off; the leader then
//     dies and node 2 comes back. Node 2's log lacks entries the witness
//     has, so the witness refuses its votes and nobody leads: the group
//     stops rather than serve stale data.
//  4. A learner promoted with promote_to_witness() becomes a witness
//     through joint consensus on every member, and from then on receives
//     descriptors.
//  5. Random schedules of partitions, heals, crashes and writes: the
//     witness is never leader, at most one leader leads a term, and every
//     command a leader acknowledged is in the log of every later leader.
#define BOOST_TEST_MODULE raft_witness_voter_test
#include <boost/test/unit_test.hpp>
#include <raft/future_default.hpp>

#include <raft/append_sink.hpp>
#include <raft/persistence.hpp>
#include <raft/raft.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
struct FollyInitFixture {
    FollyInitFixture() {
        int argc = 1;
        char* argv0[] = {const_cast<char*>("raft_witness_voter_test"), nullptr};
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
    auto describe(const log_entry_t& e) -> log_entry_t {
        if (is_descriptor(e)) {
            return e;
        }
        log_entry_t d = e;
        d._command = {descriptor_tag};
        return d;
    }
    auto sync() -> void { ++_syncs; }
    [[nodiscard]] auto payload_count() -> std::size_t {
        const std::lock_guard lock(_mu);
        return _payloads.size();
    }
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

    // A generous single-group topology, so promote_to_witness()'s placement
    // capacity check never blocks these tests.
    using quorum_manager_type =
        kythira::no_op_quorum_manager<node_id_type, address_type, std::string>;
};

static_assert(kythira::raft_types<test_types>);

static_assert(kythira::describing_append_sink<payload_sink, log_entry_t>);

using node_t = kythira::node<test_types>;
using sim_t = network_simulator::NetworkSimulator<test_types::raft_network_types>;

constexpr std::uint64_t witness_id = 3;

template<typename Pred>
auto wait_until(Pred pred, std::chrono::milliseconds deadline = std::chrono::milliseconds{8000})
    -> bool {
    const auto start = std::chrono::steady_clock::now();
    while (!pred()) {
        if (std::chrono::steady_clock::now() - start > deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return true;
}

// Every node can campaign on its own timeout; the tests drive the ticks.
auto make_config() -> kythira::raft_configuration {
    kythira::raft_configuration cfg;
    cfg._election_timeout_min = std::chrono::milliseconds{80};
    cfg._election_timeout_max = std::chrono::milliseconds{160};
    cfg._heartbeat_interval = std::chrono::milliseconds{20};
    cfg._rpc_timeout = std::chrono::milliseconds{100};
    cfg._bootstrap_retry_interval = std::chrono::milliseconds{200};
    cfg._bootstrap_peer_find_timeout = std::chrono::milliseconds{100};
    return cfg;
}

auto command(int i) -> std::vector<std::byte> {
    std::vector<std::byte> c(payload_size);
    for (std::size_t b = 0; b < c.size(); ++b) {
        c[b] = std::byte{static_cast<std::uint8_t>((static_cast<std::size_t>(i) * 7U) + b)};
    }
    return c;
}

auto name(std::uint64_t id) -> std::string {
    return std::to_string(id);
}

// `initial` is the seeded configuration: by default voters {1, 2, 3} with
// 3 a witness.
struct cluster {
    sim_t sim;
    std::vector<std::shared_ptr<shared_store>> stores;
    std::vector<std::shared_ptr<payload_sink>> sinks;
    std::vector<std::shared_ptr<applied_log>> applied;
    std::vector<std::unique_ptr<node_t>> nodes;
    std::set<std::pair<std::uint64_t, std::uint64_t>> cut;

    explicit cluster(kythira::cluster_configuration<std::uint64_t> initial = default_config()) {
        sim.start();
        for (std::uint64_t id = 1; id <= 3; ++id) {
            auto store = std::make_shared<shared_store>();
            store->state.save_current_term(seed_term);
            store->state.save_snapshot(snapshot_t{._last_included_index = seed_index,
                                                  ._last_included_term = seed_term,
                                                  ._configuration = initial,
                                                  ._state_machine_state = {}});
            stores.push_back(store);
            sinks.push_back(std::make_shared<payload_sink>());
            applied.push_back(std::make_shared<applied_log>());
        }
        heal();
        for (std::uint64_t id = 1; id <= 3; ++id) {
            nodes.push_back(make_node(id));
            nodes.back()->start();
        }
    }

    static auto default_config() -> kythira::cluster_configuration<std::uint64_t> {
        kythira::cluster_configuration<std::uint64_t> c{{1, 2, 3}, false, std::nullopt, {}};
        c._witnesses = {witness_id};
        return c;
    }

    auto make_node(std::uint64_t id) -> std::unique_ptr<node_t> {
        auto net = sim.create_node(name(id));
        return std::make_unique<node_t>(kythira::node_config<test_types>{
            .node_id = id,
            .network_client = test_types::network_client_type{net, test_types::serializer_type{}},
            .network_server = test_types::network_server_type{net, test_types::serializer_type{}},
            .persistence = sinking_engine{shared_engine{stores[id - 1]}, sinks[id - 1]},
            .logger = kythira::console_logger{kythira::log_level::error},
            .metrics = test_types::metrics_type{},
            .membership = test_types::membership_manager_type{},
            .state_machine = recording_state_machine{applied[id - 1]},
            .config = make_config(),
            .self_address = name(id),
            .peer_discovery = preset_peer_discovery<std::uint64_t, std::string>{},
            .quorum_manager =
                test_types::quorum_manager_type{kythira::desired_topology<std::string>{
                    .groups = {{.group_id = "", .target_count = 10}}}}});
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

    auto link(std::uint64_t a, std::uint64_t b, bool up) -> void {
        if (up) {
            sim.add_edge(name(a), name(b), network_simulator::NetworkEdge{});
            sim.add_edge(name(b), name(a), network_simulator::NetworkEdge{});
            cut.erase({std::min(a, b), std::max(a, b)});
        } else {
            sim.remove_edge(name(a), name(b));
            sim.remove_edge(name(b), name(a));
            cut.insert({std::min(a, b), std::max(a, b)});
        }
    }
    auto isolate(std::uint64_t id) -> void {
        for (std::uint64_t other = 1; other <= 3; ++other) {
            if (other != id) {
                link(id, other, false);
            }
        }
    }
    auto heal() -> void {
        for (std::uint64_t a = 1; a <= 3; ++a) {
            for (std::uint64_t b = a + 1; b <= 3; ++b) {
                link(a, b, true);
            }
        }
    }

    auto crash(std::uint64_t id) -> void {
        if (nodes[id - 1]) {
            nodes[id - 1]->stop();
            nodes[id - 1].reset();
        }
    }
    auto restart(std::uint64_t id) -> void {
        crash(id);
        nodes[id - 1] = make_node(id);
        nodes[id - 1]->start();
    }

    // One tick on every running node.
    auto tick() -> void {
        for (auto& n : nodes) {
            if (n) {
                n->check_election_timeout();
                n->check_heartbeat_timeout();
            }
        }
    }
    // Ticks for `d`, recording each node seen leading, and its term.
    auto run(std::chrono::milliseconds d,
             std::map<std::uint64_t, std::set<std::uint64_t>>* leaders_by_term = nullptr) -> void {
        const auto end = std::chrono::steady_clock::now() + d;
        while (std::chrono::steady_clock::now() < end) {
            tick();
            for (auto& n : nodes) {
                if (n && n->is_leader()) {
                    BOOST_REQUIRE_MESSAGE(n->get_node_id() != witness_id,
                                          "the witness became leader");
                    if (leaders_by_term != nullptr) {
                        (*leaders_by_term)[n->get_current_term()].insert(n->get_node_id());
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
    }
    auto leader() -> node_t* {
        for (auto& n : nodes) {
            if (n && n->is_leader()) {
                return n.get();
            }
        }
        return nullptr;
    }
    auto elect(std::chrono::milliseconds deadline = std::chrono::milliseconds{8000}) -> node_t* {
        node_t* l = nullptr;
        wait_until(
            [&] {
                tick();
                l = leader();
                return l != nullptr;
            },
            deadline);
        return l;
    }

    // Normal entries node `id` stores past the seed, and how many of them
    // are descriptors.
    struct stored_counts {
        std::size_t normal{0};
        std::size_t descriptors{0};
        std::size_t full{0};
    };
    auto stored(std::uint64_t id) -> stored_counts {
        stored_counts c;
        auto& store = *stores[id - 1];
        const std::lock_guard lock(store.mu);
        const auto last = store.state.get_last_log_index();
        for (std::uint64_t i = seed_index + 1; i <= last; ++i) {
            const auto e = store.state.get_log_entry(i);
            if (e && e->type() == kythira::entry_type::normal) {
                ++c.normal;
                c.descriptors += is_descriptor(*e) ? 1 : 0;
            }
        }
        c.full = c.normal - c.descriptors;
        return c;
    }
    auto payload_commands(std::uint64_t id) -> std::size_t {
        auto& log = *applied[id - 1];
        const std::lock_guard lock(log.mu);
        return static_cast<std::size_t>(std::ranges::count_if(
            log.commands, [](const auto& c) { return c.size() == payload_size; }));
    }
};

// Submits command `i` through `leader`, ticking the cluster while it
// waits (a commit timeout is noticed on a tick); true when it committed.
auto submit(cluster& c, node_t& leader, int i,
            std::chrono::milliseconds timeout = std::chrono::milliseconds{2000}) -> bool {
    auto f = leader.submit_command(command(i), timeout);
    const auto end = std::chrono::steady_clock::now() + timeout + std::chrono::milliseconds{500};
    while (!f.isReady()) {
        if (std::chrono::steady_clock::now() > end) {
            return false;
        }
        c.tick();
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    try {
        std::move(f).get();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(raft_witness_voter)

BOOST_AUTO_TEST_CASE(a_witness_never_campaigns, *boost::unit_test::timeout(60)) {
    cluster c;
    // Alone, the witness waits out many election timeouts and never even
    // becomes a candidate: its term does not move.
    c.isolate(witness_id);
    const auto term = c.nodes[witness_id - 1]->get_current_term();
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds{1500};
    while (std::chrono::steady_clock::now() < end) {
        c.nodes[witness_id - 1]->check_election_timeout();
        BOOST_REQUIRE((c.nodes[witness_id - 1]->get_state() == kythira::server_state::follower));
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    BOOST_TEST(c.nodes[witness_id - 1]->get_current_term() == term);

    // With everyone connected a data node leads, and a transfer to the
    // witness is refused.
    c.heal();
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    BOOST_TEST(l->get_node_id() != witness_id);
    for (std::uint64_t id = 1; id <= 3; ++id) {
        BOOST_TEST(c.nodes[id - 1]->is_witness_member(witness_id));
        BOOST_TEST(c.nodes[id - 1]->is_witness_member(id) == (id == witness_id));
    }
}

BOOST_AUTO_TEST_CASE(a_witness_acknowledges_and_holds_only_descriptors,
                     *boost::unit_test::timeout(60)) {
    cluster c;
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    const auto leader_id = l->get_node_id();
    const auto other = leader_id == 1 ? std::uint64_t{2} : std::uint64_t{1};

    // The other data replica is cut off: commits need the witness's ack.
    c.isolate(other);
    constexpr int writes = 8;
    for (int i = 0; i < writes; ++i) {
        BOOST_REQUIRE_MESSAGE(submit(c, *l, i), "write " << i << " did not commit");
    }
    c.run(std::chrono::milliseconds{200});

    const auto w = c.stored(witness_id);
    BOOST_TEST(w.normal >= static_cast<std::size_t>(writes));
    BOOST_TEST(w.full == 0U);
    BOOST_TEST(c.sinks[witness_id - 1]->payload_count() == 0U);
    // The witness's state machine is handed descriptors, never payloads.
    BOOST_TEST(c.payload_commands(witness_id) == 0U);
    BOOST_TEST(c.payload_commands(leader_id) == static_cast<std::size_t>(writes));

    // Healed, the data follower receives the payloads.
    c.heal();
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.payload_commands(other) == static_cast<std::size_t>(writes);
    }));
    BOOST_TEST(c.sinks[other - 1]->payload_count() >= static_cast<std::size_t>(writes));
}

BOOST_AUTO_TEST_CASE(a_candidate_behind_the_witness_is_not_elected,
                     *boost::unit_test::timeout(60)) {
    cluster c;
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    const auto leader_id = l->get_node_id();
    const auto other = leader_id == 1 ? std::uint64_t{2} : std::uint64_t{1};

    c.isolate(other);
    for (int i = 0; i < 4; ++i) {
        BOOST_REQUIRE(submit(c, *l, i));
    }
    c.run(std::chrono::milliseconds{100});
    c.crash(leader_id);
    c.heal();

    // Two seconds is more than ten election timeouts: node 2 campaigns
    // again and again, the witness refuses every vote, and nobody leads.
    std::map<std::uint64_t, std::set<std::uint64_t>> leaders;
    c.run(std::chrono::milliseconds{2000}, &leaders);
    BOOST_TEST(leaders.empty());
    BOOST_TEST(c.nodes[other - 1]->get_current_term() > seed_term);

    // The old leader returns and the group resumes with every write.
    c.restart(leader_id);
    auto* back = c.elect();
    BOOST_REQUIRE(back != nullptr);
    BOOST_TEST(back->get_node_id() == leader_id);
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.payload_commands(other) == 4U;
    }));
}

BOOST_AUTO_TEST_CASE(a_learner_promoted_to_witness_becomes_one_everywhere,
                     *boost::unit_test::timeout(60)) {
    kythira::cluster_configuration<std::uint64_t> initial{{1, 2}, false, std::nullopt, {3}};
    cluster c{initial};
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    BOOST_TEST(l->get_node_id() != witness_id);
    BOOST_TEST(!l->is_witness_member(witness_id));
    BOOST_REQUIRE(submit(c, *l, 0));

    auto promotion = l->promote_to_witness(witness_id);
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return promotion.isReady();
    }));
    std::move(promotion).get();
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.nodes[0]->is_witness_member(witness_id) &&
               c.nodes[1]->is_witness_member(witness_id) &&
               c.nodes[2]->is_witness_member(witness_id);
    }));

    // From now on the witness gets descriptors: everything past the
    // promotion lands as descriptors, and a commit can use its ack.
    const auto before = c.stored(witness_id);
    const auto leader_id = l->get_node_id();
    c.isolate(leader_id == 1 ? 2 : 1);
    for (int i = 1; i <= 4; ++i) {
        BOOST_REQUIRE(submit(c, *l, i));
    }
    c.run(std::chrono::milliseconds{200});
    const auto after = c.stored(witness_id);
    BOOST_TEST(after.descriptors - before.descriptors >= 4U);
    BOOST_TEST(after.full == before.full);
}

BOOST_AUTO_TEST_CASE(random_schedules_never_elect_the_witness_or_lose_a_write,
                     *boost::unit_test::timeout(300)) {
    std::mt19937_64 rng(0x7769746eULL);
    std::size_t total_acknowledged = 0;
    std::size_t total_terms = 0;
    for (int round = 0; round < 6; ++round) {
        cluster c;
        std::map<std::uint64_t, std::set<std::uint64_t>> leaders;
        std::vector<int> acknowledged;
        int next = 0;
        for (int step = 0; step < 12; ++step) {
            switch (rng() % 6) {
                case 0:
                    c.isolate(1 + (rng() % 3));
                    break;
                case 1:
                    c.heal();
                    break;
                case 2: {
                    const auto id = 1 + (rng() % 3);
                    c.restart(id);
                    break;
                }
                default:
                    if (auto* l = c.leader()) {
                        for (int k = 0; k < 3; ++k) {
                            if (submit(c, *l, next, std::chrono::milliseconds{300})) {
                                acknowledged.push_back(next);
                            }
                            ++next;
                        }
                    }
                    break;
            }
            c.run(std::chrono::milliseconds{250}, &leaders);
        }
        for (const auto& [term, ids] : leaders) {
            BOOST_TEST_INFO("round " << round << " term " << term);
            BOOST_TEST(ids.size() == 1U);
            BOOST_TEST(!ids.contains(witness_id));
        }
        // Healed, a data leader emerges holding every acknowledged write.
        c.heal();
        for (std::uint64_t id = 1; id <= 3; ++id) {
            if (!c.nodes[id - 1]) {
                c.restart(id);
            }
        }
        // A write in the final leader's term commits everything before it.
        // Leadership may still move while the healed cluster settles, so
        // retry on whichever data node leads.
        node_t* l = nullptr;
        bool committed = false;
        for (int attempt = 0; attempt < 10 && !committed; ++attempt) {
            l = c.elect();
            BOOST_REQUIRE(l != nullptr);
            BOOST_TEST(l->get_node_id() != witness_id);
            committed = submit(c, *l, next);
        }
        BOOST_REQUIRE_MESSAGE(committed, "round " << round << ": no write commits once healed");
        const auto lid = l->get_node_id();
        auto& store = *c.stores[lid - 1];
        std::set<std::vector<std::byte>> held;
        {
            const std::lock_guard lock(store.mu);
            const auto last = store.state.get_last_log_index();
            for (std::uint64_t i = seed_index + 1; i <= last; ++i) {
                const auto e = store.state.get_log_entry(i);
                if (e && e->type() == kythira::entry_type::normal) {
                    if (auto p = c.sinks[lid - 1]->payload(i)) {
                        held.insert(*p);
                    }
                }
            }
        }
        for (const int a : acknowledged) {
            BOOST_TEST_INFO("round " << round << " write " << a);
            BOOST_TEST(held.contains(command(a)));
        }
        total_acknowledged += acknowledged.size();
        total_terms += leaders.size();
    }
    // The schedules did exercise something: writes were acknowledged and
    // leadership changed hands.
    BOOST_TEST(total_acknowledged > 0U);
    BOOST_TEST(total_terms > 6U);
}

BOOST_AUTO_TEST_SUITE_END()
