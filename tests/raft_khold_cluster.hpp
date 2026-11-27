// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A three-node cluster over the network simulator for the khold core
// tests (.kiro/specs/khold-block-service/ tasks 4 and 5). Every engine is
// an append_sink_persistence whose sink keeps payloads by index and can
// describe entries, and whose log storage survives a restart. By default
// nodes 1 and 2 hold data and node 3 is a witness; `cluster::tweak`
// adjusts every node's Raft configuration (the commit rule, say).

#include <boost/test/unit_test.hpp>
#include <raft/future_default.hpp>

#include <raft/append_sink.hpp>
#include <raft/persistence.hpp>
#include <raft/raft.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace raft_khold_cluster {

using memory_engine_t = kythira::memory_persistence_engine<>;
using log_entry_t = memory_engine_t::log_entry_t;
using snapshot_t = memory_engine_t::snapshot_t;

inline constexpr std::byte descriptor_tag{0xDE};
inline constexpr std::size_t payload_size = 4096;
inline constexpr std::uint64_t seed_index = 10;
inline constexpr std::uint64_t seed_term = 1;

inline auto is_descriptor(const log_entry_t& e) -> bool {
    return e.command().size() == 1 && e.command()[0] == descriptor_tag;
}

// The log storage one node keeps across a restart.
struct shared_store {
    std::mutex mu;
    memory_engine_t state;
};

class shared_engine {
public:
    using log_entry_t = raft_khold_cluster::log_entry_t;
    using snapshot_t = raft_khold_cluster::snapshot_t;

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
    // Whether this sink holds `cmd` as the payload of any index.
    [[nodiscard]] auto holds(const std::vector<std::byte>& cmd) -> bool {
        const std::lock_guard lock(_mu);
        return std::ranges::any_of(_payloads, [&](const auto& kv) { return kv.second == cmd; });
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

inline constexpr std::uint64_t witness_id = 3;

template<typename Pred>
inline auto wait_until(Pred pred,
                       std::chrono::milliseconds deadline = std::chrono::milliseconds{8000})
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
inline auto make_config() -> kythira::raft_configuration {
    kythira::raft_configuration cfg;
    cfg._election_timeout_min = std::chrono::milliseconds{80};
    cfg._election_timeout_max = std::chrono::milliseconds{160};
    cfg._heartbeat_interval = std::chrono::milliseconds{20};
    cfg._rpc_timeout = std::chrono::milliseconds{100};
    cfg._bootstrap_retry_interval = std::chrono::milliseconds{200};
    cfg._bootstrap_peer_find_timeout = std::chrono::milliseconds{100};
    return cfg;
}

inline auto command(int i) -> std::vector<std::byte> {
    std::vector<std::byte> c(payload_size);
    for (std::size_t b = 0; b < c.size(); ++b) {
        c[b] = std::byte{static_cast<std::uint8_t>((static_cast<std::size_t>(i) * 7U) + b)};
    }
    return c;
}

inline auto name(std::uint64_t id) -> std::string {
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

    std::function<void(kythira::raft_configuration&)> tweak;
    std::set<std::uint64_t> witnesses;

    // `adjust` changes every node's Raft configuration from make_config(),
    // e.g. to pick a commit rule.
    explicit cluster(kythira::cluster_configuration<std::uint64_t> initial = default_config(),
                     std::function<void(kythira::raft_configuration&)> adjust = {})
        : tweak(std::move(adjust)),
          witnesses(initial.witnesses().begin(), initial.witnesses().end()) {
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

    [[nodiscard]] auto configured() const -> kythira::raft_configuration {
        auto cfg = make_config();
        if (tweak) {
            tweak(cfg);
        }
        return cfg;
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
            .config = configured(),
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
                    BOOST_REQUIRE_MESSAGE(!witnesses.contains(n->get_node_id()),
                                          "a witness became leader");
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
inline auto submit(cluster& c, node_t& leader, int i,
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

// Ticks the cluster until `f` settles; true when it succeeded, false when
// it failed, nothing when `timeout` passed first. Settles through a
// detached continuation instead of isReady()/get(): on the stdexec backend
// a chained future (a configuration change's, say) can report ready before
// its promise is fulfilled, and get() would then block the only thread that
// ticks the cluster.
template<typename Future>
inline auto settle(cluster& c, Future f,
                   std::chrono::milliseconds timeout = std::chrono::milliseconds{8000})
    -> std::optional<bool> {
    struct outcome {
        std::atomic<bool> done{false};
        std::atomic<bool> ok{false};
    };
    auto out = std::make_shared<outcome>();
    std::move(f)
        .thenValue([out](auto&&) {
            out->ok = true;
            out->done = true;
        })
        .thenError([out](const std::exception_ptr&) { out->done = true; })
        .detach();
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (!out->done) {
        if (std::chrono::steady_clock::now() > end) {
            return std::nullopt;
        }
        c.tick();
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return out->ok.load();
}

}  // namespace raft_khold_cluster
