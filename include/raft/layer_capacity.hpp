// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file layer_capacity.hpp
/// @brief Scaling the stateless layers (gateways, front ends) through the
///        elastic capacity controller.
///
/// kinesis-independent-layers task 12, Requirements 10.4 and 10.5. The data
/// layer scales on shards per node. A gateway or front end holds no shard,
/// so it scales on the load its members report to the layer membership
/// group (`layer_membership.hpp`) instead. This header has the three pieces
/// that connect the two:
///
/// - `layer_capacity_snapshot` turns the members of one layer into the
///   `cluster_capacity_snapshot` the controller hands a policy, and
///   `layer_node_report` turns one member into the `node_report` a
///   controller observes. Requests per second become `_read_qps`, bytes
///   served become `_read_bytes_per_sec`, open streams or connections become
///   `_open_streams`, and a member above the CPU overload mark is
///   `_overloaded`.
///
/// Member ids are text in the group. The controller's node id type is the
/// quorum manager's, so every piece takes a `NodeId` (default
/// `std::string`) and converts through `node_id_traits`.
/// - `layer_capacity_policy` is a `capacity_policy` over those signals,
///   with the same paired watermarks, sustained crossings and cooldown as
///   `threshold_capacity_policy`.
/// - `layer_drain_hooks` drains a member through the membership group before
///   the controller decommissions it.
///
/// The controller itself, with its bounds, budget, kill switch, lease and
/// ledger, is unchanged. The membership group's leader runs it, the way a
/// data cluster's capacity controller runs under its lease.

#include <raft/capacity_policy.hpp>
#include <raft/composite_node_id.hpp>
#include <raft/elastic_capacity_controller.hpp>
#include <raft/layer_membership.hpp>
#include <raft/layer_roles.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace kythira::layers {

/// @brief Knobs for `layer_capacity_policy`.
///
/// Off by default, like the data layer's policy: turning scaling on is an
/// operator's decision. The request and byte marks have no figure that is
/// right for every workload, so bytes start disabled and requests start at a
/// conservative pair that an operator is expected to tune.
struct layer_capacity_config {
    bool enabled{false};

    /// Requests per second per serving member.
    capacity_watermark requests_per_member{._high = 2000.0, ._low = 600.0};
    /// Bytes served per second per serving member.
    capacity_watermark bytes_per_member{._high = 0.0, ._low = 0.0, ._enabled = false};
    /// Open streams or client connections per serving member. Off by
    /// default for the same reason as bytes: the right figure depends on
    /// how much each connection costs.
    capacity_watermark connections_per_member{._high = 0.0, ._low = 0.0, ._enabled = false};
    /// Fraction of serving members above `overload_cpu`. Scale out when over
    /// a third are; scale in only when none is.
    capacity_watermark overloaded{._high = 0.34, ._low = 0.0};
    /// CPU share (0..1) at or above which a member counts as overloaded.
    double overload_cpu{0.85};

    /// The low mark must be at most this fraction of the high one.
    double min_hysteresis_margin{0.6};

    /// How long a signal must stay above its high mark before a member is
    /// added. Shorter than the data layer's five minutes, because a stateless
    /// member starts in seconds and moves no data.
    std::chrono::milliseconds sustained_for{std::chrono::minutes{2}};
    /// How long every signal must stay at or below its low mark before a
    /// member is removed.
    std::chrono::milliseconds sustained_for_scale_in{std::chrono::minutes{15}};
    /// Minimum time between this policy's own non-hold decisions.
    std::chrono::milliseconds cooldown{std::chrono::minutes{5}};

    /// Members one scale-out asks for.
    std::size_t scale_out_step{1};
    /// Never remove a member below this many, whatever the controller's own
    /// floor says. Two keeps a layer available through one member's restart.
    std::size_t min_members{2};
};

/// @brief One member as the machine report a capacity controller observes.
///
/// nullopt when the member's id is not a `NodeId` (a text id in a numeric
/// cluster): the controller could neither provision nor decommission it.
template<typename NodeId = std::string>
[[nodiscard]] auto layer_node_report(const layer_member& m, const layer_capacity_config& cfg)
    -> std::optional<node_report<NodeId, std::string>> {
    auto id = node_id_traits<NodeId>::from_text(m.id);
    if (!id) {
        return std::nullopt;
    }
    node_report<NodeId, std::string> r;
    r._node_id = std::move(*id);
    r._read_qps = m.load.requests_per_second;
    r._read_bytes_per_sec = static_cast<double>(m.load.bytes_served_per_second);
    r._open_streams = m.load.open_streams;
    r._overloaded = m.load.cpu >= cfg.overload_cpu;
    if (!m.placement_group.empty()) {
        r._labels.push_back(m.placement_group);
    }
    return r;
}

/// @brief One layer's members as the snapshot a capacity policy reads.
///
/// Members that run none of `roles` are left out, and so are members whose
/// id is not a `NodeId`. A member that has not reported within
/// `stale_after_ms` is kept but marked stale: it may well be running, so it
/// counts towards the layer's size, but its numbers are not a reason to act
/// on. A draining or drained member is marked draining.
///
/// @tparam GroupId The controller's shard group id type. A stateless layer
///                 has no shards, so the type only has to match the
///                 controller's.
/// @tparam Key     The controller's routing key type, for the same reason.
/// @tparam NodeId  The controller's node id type.
template<typename GroupId = std::uint64_t, typename Key = std::string,
         typename NodeId = std::string>
[[nodiscard]] auto layer_capacity_snapshot(const std::vector<layer_member>& members, role_set roles,
                                           std::int64_t now_ms, std::int64_t stale_after_ms,
                                           const layer_capacity_config& cfg)
    -> cluster_capacity_snapshot<NodeId, GroupId, Key, std::string> {
    cluster_capacity_snapshot<NodeId, GroupId, Key, std::string> s;
    s._taken_at = std::chrono::system_clock::time_point{std::chrono::milliseconds{now_ms}};
    std::map<std::string, placement_group_view<std::string>> groups;
    for (const auto& m : members) {
        if (!m.roles.intersects(roles)) {
            continue;
        }
        auto report = layer_node_report<NodeId>(m, cfg);
        if (!report) {
            continue;
        }
        node_capacity_view<NodeId, std::string> v;
        v._report = std::move(*report);
        v._age = std::chrono::milliseconds{std::max<std::int64_t>(0, now_ms - m.reported_at_ms)};
        v._stale = now_ms - m.reported_at_ms > stale_after_ms;
        v._placement_group = m.placement_group;
        v._draining = m.drain != drain_state::serving;

        auto& g = groups[m.placement_group];
        g._group = m.placement_group;
        ++g._known;
        if (!v._stale && !v._draining) {
            ++g._live;
        }
        s._nodes.push_back(std::move(v));
    }
    for (auto& [name, g] : groups) {
        s._groups.push_back(std::move(g));
    }
    return s;
}

/// @brief Scales a stateless layer on the load its members report.
///
/// ### Scaling out
///
/// Any enabled signal that stays above its high mark for `sustained_for`
/// asks for `scale_out_step` more members. The controller chooses the
/// placement group.
///
/// ### Scaling in
///
/// Every enabled signal must stay at or below its low mark for
/// `sustained_for_scale_in`. Even then the policy holds:
///
/// - while any member is draining (one at a time);
/// - at `min_members` or the snapshot's own floor;
/// - when the remaining members' share of the load would cross a high
///   mark, which would be a scale-in that schedules its own scale-out.
///
/// It removes the least loaded serving member of the placement group with
/// the most serving members, so the layer stays spread across groups.
///
/// ### What it will not do
///
/// It never decides on stale numbers. Only fresh, serving members count
/// towards the averages, and with none it holds.
template<typename GroupId = std::uint64_t, typename Key = std::string,
         typename NodeId = std::string>
class layer_capacity_policy {
public:
    using snapshot_type = cluster_capacity_snapshot<NodeId, GroupId, Key, std::string>;
    using decision_type = capacity_decision<std::string, NodeId>;
    using time_point = std::chrono::system_clock::time_point;

    layer_capacity_policy() = default;
    explicit layer_capacity_policy(layer_capacity_config cfg) : _cfg(std::move(cfg)) {}

    [[nodiscard]] auto config() const -> const layer_capacity_config& { return _cfg; }

    [[nodiscard]] auto evaluate(const snapshot_type& s) -> decision_type {
        if (!_cfg.enabled) {
            return decision_type::hold();
        }
        const auto now = s._taken_at;
        const auto signals = measure(s);
        // Every sample moves the crossing clocks, inside the cooldown too:
        // "sustained" means continuously observed.
        for (const auto& m : signals) {
            track(m, now);
        }
        if (_last_decision && now - *_last_decision < _cfg.cooldown) {
            return decision_type::hold();
        }
        auto d = decide(s, signals, now);
        if (!d.is_hold()) {
            _last_decision = now;
            // A decision consumes the crossing that produced it, so the next
            // evaluation after the cooldown waits for fresh evidence.
            _crossing.clear();
        }
        return d;
    }

    [[nodiscard]] auto cooldown() const -> std::chrono::milliseconds { return _cfg.cooldown; }

    [[nodiscard]] auto validate() const -> bool { return get_validation_errors().empty(); }

    /// @brief Every error, not the first.
    [[nodiscard]] auto get_validation_errors() const -> std::vector<std::string> {
        std::vector<std::string> errors;
        if (_cfg.min_hysteresis_margin <= 0.0 || _cfg.min_hysteresis_margin >= 1.0) {
            errors.push_back("min_hysteresis_margin must be in (0, 1)");
        }
        const auto check = [&](const char* name, const capacity_watermark& w) {
            if (!w._enabled) {
                return;
            }
            if (w._high <= 0.0) {
                errors.push_back(std::string{name} + ".high must be positive");
            }
            if (w._low < 0.0) {
                errors.push_back(std::string{name} + ".low must not be negative");
            }
            if (w._low >= w._high) {
                errors.push_back(std::string{name} +
                                 " is inverted: low is not below high, so one reading could "
                                 "ask the layer to grow and to shrink");
            } else if (w._low > w._high * _cfg.min_hysteresis_margin) {
                errors.push_back(std::string{name} +
                                 " is not hysteretic: low must be at most "
                                 "min_hysteresis_margin * high, or adding one member moves "
                                 "the signal under the low mark and the layer oscillates");
            }
        };
        check("requests_per_member", _cfg.requests_per_member);
        check("bytes_per_member", _cfg.bytes_per_member);
        check("connections_per_member", _cfg.connections_per_member);
        check("overloaded", _cfg.overloaded);
        if (_cfg.overloaded._enabled && _cfg.overloaded._high > 1.0) {
            errors.push_back("overloaded.high must be at most 1: it is a fraction of members");
        }
        if (_cfg.overload_cpu <= 0.0 || _cfg.overload_cpu > 1.0) {
            errors.push_back("overload_cpu must be in (0, 1]: it is a share of the CPUs");
        }
        if (!_cfg.requests_per_member._enabled && !_cfg.bytes_per_member._enabled &&
            !_cfg.connections_per_member._enabled && !_cfg.overloaded._enabled) {
            errors.push_back("no signal is enabled, so the policy could never scale");
        }
        if (_cfg.sustained_for <= std::chrono::milliseconds::zero()) {
            errors.push_back(
                "sustained_for must be positive: zero means one report's spike adds a member");
        }
        if (_cfg.sustained_for_scale_in < _cfg.sustained_for) {
            errors.push_back("sustained_for_scale_in must be at least sustained_for");
        }
        if (_cfg.scale_out_step == 0) {
            errors.push_back("scale_out_step must be at least 1");
        }
        if (_cfg.min_members == 0) {
            errors.push_back("min_members must be at least 1: a layer of none serves nobody");
        }
        return errors;
    }

private:
    enum class signal_kind : std::uint8_t {
        requests,
        bytes,
        connections,
        overloaded
    };

    struct measurement {
        signal_kind kind;
        const char* name;
        capacity_reason reason;
        std::optional<double> value;
        const capacity_watermark* mark;
    };

    struct crossing {
        std::optional<time_point> above_since;
        std::optional<time_point> below_since;
    };

    [[nodiscard]] auto measure(const snapshot_type& s) const -> std::vector<measurement> {
        std::vector<measurement> out;
        if (_cfg.requests_per_member._enabled) {
            out.push_back({signal_kind::requests, "requests_per_member", capacity_reason::load,
                           s.fresh_mean([](const auto& r) { return r._read_qps; }),
                           &_cfg.requests_per_member});
        }
        if (_cfg.bytes_per_member._enabled) {
            out.push_back({signal_kind::bytes, "bytes_per_member", capacity_reason::load,
                           s.fresh_mean([](const auto& r) { return r._read_bytes_per_sec; }),
                           &_cfg.bytes_per_member});
        }
        if (_cfg.connections_per_member._enabled) {
            out.push_back(
                {signal_kind::connections, "connections_per_member", capacity_reason::load,
                 s.fresh_mean([](const auto& r) { return static_cast<double>(r._open_streams); }),
                 &_cfg.connections_per_member});
        }
        if (_cfg.overloaded._enabled) {
            out.push_back({signal_kind::overloaded, "overloaded", capacity_reason::overload,
                           s.overloaded_fraction(), &_cfg.overloaded});
        }
        return out;
    }

    auto track(const measurement& m, time_point now) -> void {
        auto& c = _crossing[m.kind];
        if (!m.value) {
            c = {};
            return;
        }
        if (*m.value > m.mark->_high) {
            if (!c.above_since) {
                c.above_since = now;
            }
        } else {
            c.above_since.reset();
        }
        if (*m.value <= m.mark->_low) {
            if (!c.below_since) {
                c.below_since = now;
            }
        } else {
            c.below_since.reset();
        }
    }

    [[nodiscard]] static auto evidence_of(const std::vector<measurement>& signals, std::string note)
        -> capacity_evidence {
        capacity_evidence e;
        for (const auto& m : signals) {
            if (m.value) {
                e._signals.push_back({m.name, *m.value, m.mark->_high});
            }
        }
        e._note = std::move(note);
        return e;
    }

    [[nodiscard]] auto decide(const snapshot_type& s, const std::vector<measurement>& signals,
                              time_point now) -> decision_type {
        if (s.fresh_node_count() == 0) {
            return decision_type::hold();
        }

        // Scale out on the first signal sustained above its high mark.
        for (const auto& m : signals) {
            const auto& c = _crossing[m.kind];
            if (c.above_since && now - *c.above_since >= _cfg.sustained_for) {
                if (s._max_cluster_size != 0 && s.cluster_size() >= s._max_cluster_size) {
                    return decision_type::hold();
                }
                return decision_type::scale_out(
                    _cfg.scale_out_step, m.reason,
                    evidence_of(signals, std::string{m.name} + " above its high mark"));
            }
        }

        // Scale in only when every signal has been low for long enough.
        if (signals.empty()) {
            return decision_type::hold();
        }
        for (const auto& m : signals) {
            const auto& c = _crossing[m.kind];
            if (!c.below_since || now - *c.below_since < _cfg.sustained_for_scale_in) {
                return decision_type::hold();
            }
        }
        const bool any_draining = std::any_of(s._nodes.begin(), s._nodes.end(),
                                              [](const auto& v) { return v._draining; });
        if (any_draining) {
            return decision_type::hold();
        }
        const auto size = s.cluster_size();
        const auto floor = std::max(_cfg.min_members, s._min_cluster_size);
        if (size <= floor) {
            return decision_type::hold();
        }
        // Would the members left behind be pushed over a high mark?
        const auto fresh = s.fresh_node_count();
        if (fresh > 1) {
            const double scale = static_cast<double>(fresh) / static_cast<double>(fresh - 1);
            for (const auto& m : signals) {
                if (m.kind != signal_kind::overloaded && m.value &&
                    *m.value * scale > m.mark->_high) {
                    return decision_type::hold();
                }
            }
        }
        const auto* victim = choose_member_to_remove(s);
        if (victim == nullptr) {
            return decision_type::hold();
        }
        return decision_type::scale_in(victim->_placement_group.value_or(std::string{}),
                                       victim->node_id(), capacity_reason::load,
                                       evidence_of(signals, "every signal below its low mark"));
    }

    /// The least loaded serving member of the placement group with the most
    /// serving members. Ties go to the greatest id, so the choice is stable.
    [[nodiscard]] static auto choose_member_to_remove(const snapshot_type& s) -> const
        typename snapshot_type::node_view_type* {
        std::map<std::string, std::size_t> serving;
        for (const auto& v : s._nodes) {
            if (!v._stale && !v._draining) {
                ++serving[v._placement_group.value_or(std::string{})];
            }
        }
        if (serving.empty()) {
            return nullptr;
        }
        const auto largest =
            std::max_element(serving.begin(), serving.end(), [](const auto& a, const auto& b) {
                return a.second < b.second;
            })->first;
        const typename snapshot_type::node_view_type* best = nullptr;
        for (const auto& v : s._nodes) {
            if (v._stale || v._draining || v._placement_group.value_or(std::string{}) != largest) {
                continue;
            }
            if (best == nullptr || v._report._read_qps < best->_report._read_qps ||
                (v._report._read_qps == best->_report._read_qps && v.node_id() > best->node_id())) {
                best = &v;
            }
        }
        return best;
    }

    layer_capacity_config _cfg;
    std::map<signal_kind, crossing> _crossing;
    std::optional<time_point> _last_decision;
};

static_assert(
    capacity_policy<layer_capacity_policy<>, std::string, std::uint64_t, std::string, std::string>);

/// @brief Drain hooks that drain a member through the membership group.
///
/// - `begin` marks the member draining. It stops taking new work, and the
///   member moves itself to drained once its open streams have closed.
/// - `holds_work` is true while the member is still in the group, still
///   reporting, and not yet drained. A member that left, or stopped
///   reporting for `stale_after_ms`, holds nothing.
/// - `cancel` returns the member to serving.
///
/// `now_ms` is the controller's clock in milliseconds since the epoch.
template<typename NodeId = std::string>
auto layer_drain_hooks(replicated_layer_membership& membership,
                       std::function<std::int64_t()> now_ms, std::int64_t stale_after_ms)
    -> capacity_drain_hooks<NodeId> {
    using traits = node_id_traits<NodeId>;
    capacity_drain_hooks<NodeId> h;
    h.begin = [&membership](const NodeId& id) {
        static_cast<void>(membership.set_drain(traits::to_text(id), drain_state::draining));
    };
    h.holds_work = [&membership, now_ms = std::move(now_ms), stale_after_ms](const NodeId& id) {
        const auto members = membership.members();
        const auto text = traits::to_text(id);
        const auto it = std::find_if(members.begin(), members.end(),
                                     [&](const auto& m) { return m.id == text; });
        if (it == members.end() || it->drain == drain_state::drained) {
            return false;
        }
        return now_ms() - it->reported_at_ms <= stale_after_ms;
    };
    h.cancel = [&membership](const NodeId& id) {
        static_cast<void>(membership.set_drain(traits::to_text(id), drain_state::serving));
    };
    return h;
}

}  // namespace kythira::layers
