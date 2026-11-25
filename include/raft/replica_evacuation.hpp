// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file replica_evacuation.hpp
/// @brief Moving every replica a node holds onto other nodes, over the
///        placement operators a multi-Raft host already has
///        (.kiro/specs/kinesis-independent-layers/ task 13, design
///        "Migration" step 4, Requirement 11.3).
///
/// Evacuating node A from a group is the membership change a host already
/// performs for a failed node, in Raft's safe order:
///
/// 1. add a target as a learner, let it catch up, promote it
///    (`add_server`, which does all three and resumes a learner a failed
///    attempt left behind);
/// 2. if A leads the group, hand leadership to a caught-up voter;
/// 3. remove A.
///
/// `next_evacuation_step` decides the next of these from what the group's
/// leader can see: its configuration and the replication factor to keep.
/// It holds no memory between calls, so a leader that changes mid-move
/// picks up where the last one stopped instead of adding a second
/// replacement: a target already a learner is resumed, and A is removed
/// only once the group has `replicas` voters without it.
///
/// `replica_evacuator` runs those steps on every group a host leads, one
/// configuration change per group at a time, from a pass the caller drives
/// (a maintenance loop). Every host of the cluster runs the same job; each
/// acts only where it leads, so no host needs to reach another's groups.
/// The targets need replicas created for them, which the multi-Raft host's
/// lazy replica creation does once a target learns the group's descriptor
/// (`live_descriptor` is what a lookup should answer with).
///
/// The evacuee keeps its stale replicas until it restarts: removal does not
/// tell it, and destroying them would tombstone the groups, which would
/// stop the same node taking them back in the reverse migration.

#include <raft/shard_placement_driver.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

enum class evacuation_action : std::uint8_t {
    /// The evacuee holds no replica of the group.
    done,
    /// A configuration change is in flight; look again next pass.
    wait,
    /// Add `_node` (learner, catch up, promote).
    add_replica,
    /// Move leadership to `_node`.
    transfer_leader,
    /// Remove the evacuee.
    remove_replica,
    /// No target can take a replica: every target already holds one, or
    /// none was named. The group keeps its replica on the evacuee.
    stuck,
};

[[nodiscard]] inline auto to_string(evacuation_action a) -> const char* {
    switch (a) {
        case evacuation_action::done:
            return "done";
        case evacuation_action::wait:
            return "wait";
        case evacuation_action::add_replica:
            return "add_replica";
        case evacuation_action::transfer_leader:
            return "transfer_leader";
        case evacuation_action::remove_replica:
            return "remove_replica";
        case evacuation_action::stuck:
            return "stuck";
    }
    return "unknown";
}

template<typename NodeId> struct evacuation_step {
    evacuation_action _action = evacuation_action::done;
    std::optional<NodeId> _node{};
};

/// What the group's leader sees.
template<typename NodeId> struct evacuation_view {
    std::vector<NodeId> _voters{};
    std::vector<NodeId> _learners{};
    /// A joint configuration, or a change this host has in flight.
    bool _changing = false;
    NodeId _leader{};
};

namespace detail::evacuation {
template<typename NodeId>
[[nodiscard]] auto contains(const std::vector<NodeId>& v, const NodeId& n) -> bool {
    return std::find(v.begin(), v.end(), n) != v.end();
}
}  // namespace detail::evacuation

/// The next step that moves `evacuee` off one group. `targets` are the
/// nodes that may take its replica, in preference order; `load` ranks
/// targets outside the group (fewest first, ties by order) so replicas
/// spread instead of piling on the first target. `replicas` is how many
/// voters the group keeps.
template<typename NodeId>
[[nodiscard]] auto next_evacuation_step(const evacuation_view<NodeId>& view, const NodeId& evacuee,
                                        const std::vector<NodeId>& targets, std::size_t replicas,
                                        const std::function<std::size_t(const NodeId&)>& load = {})
    -> evacuation_step<NodeId> {
    using detail::evacuation::contains;
    const bool voter = contains(view._voters, evacuee);
    const bool learner = contains(view._learners, evacuee);
    if (!voter && !learner) {
        return {evacuation_action::done, std::nullopt};
    }
    if (view._changing) {
        return {evacuation_action::wait, std::nullopt};
    }
    if (!voter) {
        // A learner counts toward no quorum: it simply goes.
        return {evacuation_action::remove_replica, evacuee};
    }
    if (view._voters.size() > replicas) {
        // Enough voters without the evacuee. The leader leaves last.
        if (view._leader == evacuee) {
            // Prefer a target, then any other voter.
            for (const auto& t : targets) {
                if (t != evacuee && contains(view._voters, t)) {
                    return {evacuation_action::transfer_leader, t};
                }
            }
            for (const auto& v : view._voters) {
                if (v != evacuee) {
                    return {evacuation_action::transfer_leader, v};
                }
            }
        }
        return {evacuation_action::remove_replica, evacuee};
    }
    // A replacement first. A learner target is a move already started.
    for (const auto& t : targets) {
        if (t != evacuee && contains(view._learners, t)) {
            return {evacuation_action::add_replica, t};
        }
    }
    std::optional<NodeId> best;
    std::size_t best_load = 0;
    for (const auto& t : targets) {
        if (t == evacuee || contains(view._voters, t)) {
            continue;
        }
        const auto l = load ? load(t) : 0;
        if (!best || l < best_load) {
            best = t;
            best_load = l;
        }
    }
    if (!best) {
        return {evacuation_action::stuck, std::nullopt};
    }
    return {evacuation_action::add_replica, std::move(best)};
}

/// `host`'s descriptor of `group` with the membership its Raft replica runs
/// under, which is newer than the descriptor the group was created with
/// once replicas have moved. What a lazy replica creation lookup should be
/// answered with: a target sees itself listed as soon as it is a learner.
template<typename Host, typename GroupId>
[[nodiscard]] auto live_descriptor(Host& host, const GroupId& group)
    -> std::optional<typename Host::descriptor_type> {
    auto d = host.local_descriptor(group);
    auto* n = host.group_node(group);
    if (!d || n == nullptr) {
        return d;
    }
    const auto m = n->current_membership();
    if (!m.voters.empty()) {
        d->_voters = m.voters;
        d->_learners = m.learners;
        // A joint configuration's outgoing voters still hold replicas.
        if (m.joint) {
            for (const auto& v : host.local_descriptor(group)->_voters) {
                if (std::find(d->_voters.begin(), d->_voters.end(), v) == d->_voters.end()) {
                    d->_voters.push_back(v);
                }
            }
        }
    }
    return d;
}

/// Where one group stands, as the host that leads it sees it.
template<typename GroupId, typename NodeId> struct evacuation_group_status {
    GroupId _group{};
    evacuation_action _action = evacuation_action::done;
    std::optional<NodeId> _node{};
    /// The last failure of a change on this group, if any.
    std::string _error{};
};

template<typename GroupId, typename NodeId> struct evacuation_pass {
    /// Groups this host leads, with the step taken (or waited on).
    std::vector<evacuation_group_status<GroupId, NodeId>> _led;
    /// Groups this host holds a replica of but does not lead.
    std::size_t _not_led = 0;
    /// Whether every group this host leads is done.
    [[nodiscard]] auto done() const -> bool {
        return std::all_of(_led.begin(), _led.end(),
                           [](const auto& g) { return g._action == evacuation_action::done; });
    }
};

/// Runs evacuation steps on the groups `Host` leads. See the file comment.
/// `pass()` is called from one thread; `start`, `cancel` and `job` from
/// any.
template<typename Host> class replica_evacuator {
public:
    using node_id_type = typename Host::node_id_type;
    using group_id_type = decltype(std::declval<Host&>().group_ids())::value_type;
    using future_type = decltype(std::declval<typename Host::group_node_type&>().remove_server(
        std::declval<node_id_type>()));
    using pass_type = evacuation_pass<group_id_type, node_id_type>;

    struct job {
        node_id_type _evacuee{};
        std::vector<node_id_type> _targets{};
        std::size_t _replicas = 3;
    };

    explicit replica_evacuator(Host& host) : _host(host) {}

    /// Evacuates `j._evacuee`, replacing any job running.
    void start(job j) {
        const std::scoped_lock lock(_mu);
        _job = std::move(j);
    }

    void cancel() {
        const std::scoped_lock lock(_mu);
        _job.reset();
    }

    [[nodiscard]] auto current() const -> std::optional<job> {
        const std::scoped_lock lock(_mu);
        return _job;
    }

    /// One step on each group this host leads; nothing without a job.
    auto pass() -> pass_type {
        pass_type out;
        const auto j = current();
        if (!j) {
            return out;
        }
        // How many replicas each target holds on this host's view, to spread
        // the new ones.
        std::map<node_id_type, std::size_t> held;
        for (const auto& g : _host.group_ids()) {
            if (auto* n = _host.group_node(g)) {
                const auto m = n->current_membership();
                for (const auto& v : m.voters) {
                    ++held[v];
                }
                for (const auto& v : m.learners) {
                    ++held[v];
                }
            }
        }
        for (const auto& g : _host.group_ids()) {
            auto* n = _host.group_node(g);
            if (n == nullptr) {
                continue;
            }
            if (!n->is_leader()) {
                ++out._not_led;
                continue;
            }
            out._led.push_back(step(g, *n, *j, held));
        }
        return out;
    }

private:
    using group_node_type = typename Host::group_node_type;

    struct in_flight {
        future_type _future;
        evacuation_action _action;
    };

    auto step(const group_id_type& g, group_node_type& n, const job& j,
              std::map<node_id_type, std::size_t>& held)
        -> evacuation_group_status<group_id_type, node_id_type> {
        evacuation_group_status<group_id_type, node_id_type> st;
        st._group = g;
        // A change this host started and has not heard back from.
        if (auto it = _flight.find(g); it != _flight.end()) {
            if (!it->second._future.wait(std::chrono::milliseconds{0})) {
                st._action = evacuation_action::wait;
                return st;
            }
            try {
                (void)std::move(it->second._future).get();
                _errors.erase(g);
            } catch (const std::exception& e) {
                _errors[g] = e.what();
                if (it->second._action == evacuation_action::transfer_leader) {
                    // Without TimeoutNow, or a target that lost: the leader
                    // removes itself instead, which Raft allows.
                    _transfer_failed.insert_or_assign(g, true);
                }
            }
            _flight.erase(it);
        }
        const auto m = n.current_membership();
        evacuation_view<node_id_type> view{._voters = m.voters,
                                           ._learners = m.learners,
                                           ._changing = m.joint,
                                           ._leader = _host.node_id()};
        auto next =
            next_evacuation_step<node_id_type>(view, j._evacuee, j._targets, j._replicas,
                                               [&held](const node_id_type& t) { return held[t]; });
        if (next._action == evacuation_action::transfer_leader && _transfer_failed[g]) {
            next = {evacuation_action::remove_replica, j._evacuee};
        }
        st._action = next._action;
        st._node = next._node;
        if (auto e = _errors.find(g); e != _errors.end()) {
            st._error = e->second;
        }
        const auto timeout = std::chrono::milliseconds{5000};
        switch (next._action) {
            case evacuation_action::add_replica:
                ++held[*next._node];
                _flight.insert_or_assign(g, in_flight{n.add_server(*next._node), next._action});
                break;
            case evacuation_action::transfer_leader:
                _flight.insert_or_assign(
                    g, in_flight{n.transfer_leadership(*next._node, timeout), next._action});
                break;
            case evacuation_action::remove_replica: {
                const bool learner = std::find(m.learners.begin(), m.learners.end(), *next._node) !=
                                     m.learners.end();
                _flight.insert_or_assign(g, in_flight{learner ? n.remove_learner(*next._node)
                                                              : n.remove_server(*next._node),
                                                      next._action});
                _transfer_failed.erase(g);
                break;
            }
            case evacuation_action::done:
            case evacuation_action::wait:
            case evacuation_action::stuck:
                break;
        }
        return st;
    }

    Host& _host;
    mutable std::mutex _mu;
    std::optional<job> _job;
    // Touched only by pass(), on one thread.
    std::map<group_id_type, in_flight> _flight;
    std::map<group_id_type, std::string> _errors;
    std::map<group_id_type, bool> _transfer_failed;
};

}  // namespace kythira
