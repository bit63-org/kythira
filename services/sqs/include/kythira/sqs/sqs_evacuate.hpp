// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_evacuate.hpp
/// @brief Moving a data replica from one node to another
///        (`.kiro/specs/sqs-compatible-queues/` task 11, Requirement 12.2).
///
/// `evacuate` moves every replica `from` holds to `to` by the membership
/// changes the Raft core already makes, one at a time, on the group's
/// leader:
///
/// 1. add `to` as a learner (it catches up without counting toward quorum);
/// 2. promote it once it is within `max_lag` entries of the leader's log;
/// 3. if `from` leads, hand leadership to `to`;
/// 4. remove `from`.
///
/// `evacuate_step` looks at the group's membership and takes the next of
/// those steps, so the same call carries a move forward from wherever it
/// stands: after a crash, a lost leader or an operator's retry, and back
/// (evacuate `to` to `from` reverses it, from any midway point). Every step
/// is an ordinary configuration change, so the queues' entries, receipt
/// handles and visibility deadlines are untouched: they live in the
/// replicated state, which the new replica receives whole.
///
/// The wire shapes are the admin calls `sqs_node` serves under
/// `/_kythira/sqs/v1/admin/` (`sqs_layers.hpp` opens them to `data`):
/// `peer` tells a node where another node's Raft and SQS listeners are,
/// `evacuate` runs a move to the end, `step` takes one step on the leader.

#include <kythira/sqs/sqs_data_access.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

inline constexpr std::string_view k_admin_prefix = "/_kythira/sqs/v1/admin/";
inline constexpr std::string_view k_admin_peer_path = "/_kythira/sqs/v1/admin/peer";
inline constexpr std::string_view k_admin_evacuate_path = "/_kythira/sqs/v1/admin/evacuate";
inline constexpr std::string_view k_admin_step_path = "/_kythira/sqs/v1/admin/step";

/// What the leader of one group can see and do about its membership.
template<typename NodeId> struct membership_ops {
    std::function<bool()> is_leader;
    std::function<NodeId()> self;
    /// True while a configuration change is still in transit (joint).
    std::function<bool()> changing;
    /// The voters and the learners, as the leader's log has them.
    std::function<std::pair<std::vector<NodeId>, std::vector<NodeId>>()> members;
    /// How far `node` has replicated (nullopt: not tracked yet).
    std::function<std::optional<std::uint64_t>(const NodeId&)> match_index;
    std::function<std::uint64_t()> last_index;
    std::function<void(const NodeId&)> add_learner;
    std::function<void(const NodeId&)> promote;
    std::function<void(const NodeId&)> remove_voter;
    std::function<void(const NodeId&)> remove_learner;
    std::function<void(const NodeId&)> transfer_to;
};

enum class step_kind : std::uint8_t {
    /// `from` holds no replica and `to` votes: nothing is left to do.
    done,
    /// A membership change was started; step again.
    progressed,
    /// `to` is still catching up; step again later.
    waiting,
    /// This node does not lead the group; step on the leader.
    not_leader,
    /// The move cannot be made (the reason says why).
    refused,
};

[[nodiscard]] constexpr auto to_string(step_kind k) noexcept -> std::string_view {
    switch (k) {
        case step_kind::done:
            return "done";
        case step_kind::progressed:
            return "progressed";
        case step_kind::waiting:
            return "waiting";
        case step_kind::not_leader:
            return "not_leader";
        case step_kind::refused:
            return "refused";
    }
    return "refused";
}

[[nodiscard]] inline auto step_kind_from(std::string_view s) -> std::optional<step_kind> {
    for (const auto k : {step_kind::done, step_kind::progressed, step_kind::waiting,
                         step_kind::not_leader, step_kind::refused}) {
        if (to_string(k) == s) {
            return k;
        }
    }
    return std::nullopt;
}

struct step_result {
    step_kind _kind = step_kind::refused;
    /// What was done or why not, for the operator.
    std::string _what;
};

/// The next step of moving `from`'s replica to `to` (see the file comment).
/// `describe` names a node in the answer.
template<typename NodeId>
[[nodiscard]] auto evacuate_step(const membership_ops<NodeId>& ops, const NodeId& from,
                                 const NodeId& to, std::uint64_t max_lag,
                                 const std::function<std::string(const NodeId&)>& describe)
    -> step_result {
    if (from == to) {
        return {step_kind::refused, "cannot evacuate a node to itself"};
    }
    if (!ops.is_leader()) {
        return {step_kind::not_leader, "this node does not lead the group"};
    }
    if (ops.changing && ops.changing()) {
        return {step_kind::waiting, "a membership change is in progress"};
    }
    const auto [voters, learners] = ops.members();
    const auto in = [](const std::vector<NodeId>& v, const NodeId& n) {
        return std::find(v.begin(), v.end(), n) != v.end();
    };
    const bool from_votes = in(voters, from);
    const bool from_learns = in(learners, from);
    if (in(learners, to)) {
        const auto m = ops.match_index(to);
        const auto last = ops.last_index();
        if (!m || (last > *m && last - *m > max_lag)) {
            return {step_kind::waiting, describe(to) + " is catching up (" +
                                            std::to_string(m.value_or(0)) + " of " +
                                            std::to_string(last) + ")"};
        }
        ops.promote(to);
        return {step_kind::progressed, "promoting " + describe(to) + " to voter"};
    }
    if (!in(voters, to)) {
        if (!from_votes && !from_learns) {
            return {step_kind::refused, describe(from) + " holds no replica of the group"};
        }
        ops.add_learner(to);
        return {step_kind::progressed, "adding " + describe(to) + " as a learner"};
    }
    if (from_votes) {
        if (from == ops.self()) {
            ops.transfer_to(to);
            return {step_kind::progressed,
                    "handing leadership from " + describe(from) + " to " + describe(to)};
        }
        ops.remove_voter(from);
        return {step_kind::progressed, "removing " + describe(from)};
    }
    if (from_learns) {
        ops.remove_learner(from);
        return {step_kind::progressed, "removing learner " + describe(from)};
    }
    return {step_kind::done, describe(from) + " evacuated to " + describe(to)};
}

/// `{"from": ..., "to": ...}`: the node ids as `sqs_node` writes them.
struct evacuate_request {
    std::string _from;
    std::string _to;
};

[[nodiscard]] inline auto encode_evacuate(const evacuate_request& r) -> std::string {
    boost::json::object o;
    o["from"] = r._from;
    o["to"] = r._to;
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_evacuate(std::string_view in) -> std::optional<evacuate_request> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    evacuate_request r{data_wire::str(v.as_object(), "from"), data_wire::str(v.as_object(), "to")};
    if (r._from.empty() || r._to.empty()) {
        return std::nullopt;
    }
    return r;
}

/// `{"id": ..., "raft": "<url>", "sqs": "<url>"}`: where a node listens.
struct peer_announcement {
    std::string _id;
    std::string _raft_url;
    std::string _sqs_url;
};

[[nodiscard]] inline auto encode_peer(const peer_announcement& p) -> std::string {
    boost::json::object o;
    o["id"] = p._id;
    o["raft"] = p._raft_url;
    o["sqs"] = p._sqs_url;
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_peer(std::string_view in) -> std::optional<peer_announcement> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    peer_announcement p{data_wire::str(o, "id"), data_wire::str(o, "raft"),
                        data_wire::str(o, "sqs")};
    const auto url = [](std::string_view u) {
        return u.starts_with("http://") || u.starts_with("https://");
    };
    if (p._id.empty() || !url(p._raft_url) || !url(p._sqs_url)) {
        return std::nullopt;
    }
    return p;
}

[[nodiscard]] inline auto encode_step(const step_result& s) -> std::string {
    boost::json::object o;
    o["result"] = to_string(s._kind);
    o["what"] = s._what;
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_step(std::string_view in) -> std::optional<step_result> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto k = step_kind_from(data_wire::str(v.as_object(), "result"));
    if (!k) {
        return std::nullopt;
    }
    return step_result{*k, data_wire::str(v.as_object(), "what")};
}

}  // namespace kythira::sqs
