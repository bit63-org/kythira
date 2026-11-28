// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_membership.hpp
/// @brief Moving the KMS's data role between nodes: the catalog group's
///        membership calls (.kiro/specs/kms-independent-layers/ task 6,
///        Requirement 10.1).
///
/// The data role is the catalog's Raft group. Moving it off a node is the
/// change a multi-Raft host already makes for a failed member, in Raft's
/// safe order (`include/raft/replica_evacuation.hpp`): add a target as a
/// learner, let it catch up and promote it; hand leadership off when the
/// evacuee leads; remove the evacuee. Every data node runs the same job on
/// a timer and only the catalog's leader acts, so a leader that changes
/// mid-move picks up where the last stopped.
///
/// A data node serves these on its KMS listener, to data-role callers
/// (`membership_route_roles`; nodes listed in KYTHIRA_KMS_PEER_IDENTITIES
/// keep every role, which is how an operator's certificate reaches them):
///
/// - `POST /v1/kms/membership/evacuate`
///   `{"node":"1","targets":["4","5"],"replicas":3,"fan_out":true}`:
///   move the catalog replica `node` holds onto one of `targets`. With
///   `fan_out` the node that takes the call passes it, without fan-out, to
///   every other data node it knows, so whichever leads runs it.
/// - `GET /v1/kms/membership/evacuate`: this node's view (`status`).
/// - `POST /v1/kms/membership/cancel`: drop the job here (and fanned out).
/// - `POST /v1/kms/membership/release`: the evacuee's own call once the
///   job is done. It marks the replica released (`left_marker`); at its
///   next start the node discards the old replica and keeps the marker
///   saying it has left, so that if it runs the data role again, even as
///   one of the founding voters, it joins as a learner instead of
///   re-forming the group from its stale membership.
///
/// A data node outside KYTHIRA_KMS_VOTERS (the founding voters) also
/// joins: it creates no group and takes a replica only when an evacuation
/// adds it. A node that still holds a replica (no `left_marker`) refuses
/// to start without the data role, since its stale membership could
/// otherwise come back and vote; KYTHIRA_KMS_DISCARD_CATALOG overrides
/// that for a node whose replica is known to be gone from the group.
///
/// Bodies are JSON from an authenticated peer; the parsers still answer an
/// error rather than throw on any input.

#include <kythira/kms/kms_peer.hpp>

#include <raft/host_node_id.hpp>
#include <raft/layer_roles.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::kms::membership {

/// Why a body did not parse. Returned where std::unexpected would be.
struct failure {
    explicit failure(std::string e) : error(std::move(e)) {}
    std::string error;
};

/// A value or the reason there is none: the `result<T>`
/// these parsers mean, spelled out because clang 18 (a CI compiler and the
/// static-analysis one) does not provide `std::expected` over libstdc++ 13.
/// The member names match it, so moving to `std::expected` later is a type
/// change and nothing else.
template<class T> class result {
public:
    result(T value)
        : _state(std::in_place_index<0>, std::move(value)) {
    }  // NOLINT(google-explicit-constructor): as std::expected's
    result(failure f)
        : _state(std::in_place_index<1>, std::move(f.error)) {
    }  // NOLINT(google-explicit-constructor): as from std::unexpected

    [[nodiscard]] auto has_value() const noexcept -> bool { return _state.index() == 0; }
    explicit operator bool() const noexcept { return has_value(); }

    /// Throws `std::logic_error` when there is no value.
    [[nodiscard]] auto value() const& -> const T& {
        check();
        return std::get<0>(_state);
    }
    [[nodiscard]] auto value() & -> T& {
        check();
        return std::get<0>(_state);
    }
    [[nodiscard]] auto value() && -> T {
        check();
        return std::get<0>(std::move(_state));
    }
    [[nodiscard]] auto operator*() const& -> const T& { return value(); }
    [[nodiscard]] auto operator*() & -> T& { return value(); }
    [[nodiscard]] auto operator->() const -> const T* { return &value(); }
    [[nodiscard]] auto operator->() -> T* { return &value(); }

    /// The reason, or an empty string when there is a value.
    [[nodiscard]] auto error() const -> std::string {
        return has_value() ? std::string{} : std::get<1>(_state);
    }

private:
    void check() const {
        if (!has_value()) {
            throw std::logic_error("kms membership: no value: " + std::get<1>(_state));
        }
    }

    std::variant<T, std::string> _state;
};

/// `result<void>`: success, or the reason.
template<> class result<void> {
public:
    result() = default;
    result(failure f)
        : _error(std::move(f.error)) {
    }  // NOLINT(google-explicit-constructor): as from std::unexpected

    [[nodiscard]] auto has_value() const noexcept -> bool { return !_error.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] auto error() const -> std::string { return _error.value_or(std::string{}); }

private:
    std::optional<std::string> _error;
};

inline constexpr std::string_view k_prefix = "/v1/kms/membership/";
inline constexpr std::string_view k_evacuate_path = "/v1/kms/membership/evacuate";
inline constexpr std::string_view k_cancel_path = "/v1/kms/membership/cancel";
inline constexpr std::string_view k_release_path = "/v1/kms/membership/release";

/// Only data nodes (and operators listed as peers) move the data role.
inline constexpr kythira::layers::role_set membership_route_roles{kythira::layers::role::data};

/// The most targets one call may name, and the replica count's range.
inline constexpr std::size_t k_max_targets = 64;
inline constexpr std::size_t k_max_replicas = 15;
inline constexpr std::size_t k_max_body = 64 * 1024;

[[nodiscard]] inline auto is_membership_path(std::string_view target) -> bool {
    return target.substr(0, target.find('?')).starts_with(k_prefix);
}

/// The file that says this node's catalog replica left the group (see
/// the file comment). It reads `released` from the release call until
/// the next start discards the replica, and `left` from then on.
[[nodiscard]] inline auto left_marker(const std::filesystem::path& data_dir)
    -> std::filesystem::path {
    return data_dir / "catalog-left";
}

inline constexpr std::string_view k_marker_released = "released";
inline constexpr std::string_view k_marker_left = "left";

/// The marker's state: nullopt without one.
[[nodiscard]] inline auto read_marker(const std::filesystem::path& data_dir)
    -> std::optional<std::string> {
    std::ifstream in(left_marker(data_dir));
    if (!in) {
        return std::nullopt;
    }
    std::string word;
    in >> word;
    return word;
}

inline void write_marker(const std::filesystem::path& data_dir, std::string_view state) {
    std::ofstream(left_marker(data_dir), std::ios::trunc) << state << '\n';
}

/// Whether `data_dir` holds a catalog replica: a Raft log or a state
/// engine left by an earlier start with the data role.
[[nodiscard]] inline auto holds_replica(const std::filesystem::path& data_dir) -> bool {
    std::error_code ec;
    for (const auto* sub : {"raft", "engine"}) {
        const auto dir = data_dir / sub;
        if (std::filesystem::is_directory(dir, ec) &&
            std::filesystem::directory_iterator(dir, ec) != std::filesystem::directory_iterator()) {
            return true;
        }
    }
    return false;
}

/// Removes the catalog replica's files and marks the node as having left;
/// what a released node does at start.
inline void discard_replica(const std::filesystem::path& data_dir) {
    std::error_code ec;
    for (const auto* sub : {"raft", "engine", "snapshots"}) {
        std::filesystem::remove_all(data_dir / sub, ec);
    }
    write_marker(data_dir, k_marker_left);
}

struct evacuation_request {
    kythira::host_node_id node{};
    std::vector<kythira::host_node_id> targets;
    /// Voters the catalog keeps.
    std::size_t replicas = 3;
    bool fan_out = true;
    friend auto operator==(const evacuation_request&, const evacuation_request&) -> bool = default;
};

namespace detail {

[[nodiscard]] inline auto id_from(const boost::json::value& v) -> result<kythira::host_node_id> {
    std::string text;
    if (const auto* s = v.if_string()) {
        text = std::string(s->c_str(), s->size());
    } else if (const auto* u = v.if_uint64()) {
        text = std::to_string(*u);
    } else if (const auto* i = v.if_int64(); i != nullptr && *i >= 0) {
        text = std::to_string(*i);
    } else {
        return failure("a node id must be a string or a non-negative number");
    }
    auto id = kythira::parse_host_peer_node_id(text);
    if (!id) {
        return failure("bad node id '" + text + "': " + id.error());
    }
    return std::move(id).value();
}

[[nodiscard]] inline auto object_of(std::string_view body) -> result<boost::json::object> {
    if (body.size() > k_max_body) {
        return failure("the body is too large");
    }
    std::error_code ec;
    auto v = boost::json::parse(body, ec);
    if (ec || !v.is_object()) {
        return failure("the body is not a JSON object");
    }
    return std::move(v.as_object());
}

}  // namespace detail

/// Parses an evacuate body.
[[nodiscard]] inline auto parse_evacuation(std::string_view body) -> result<evacuation_request> {
    auto o = detail::object_of(body);
    if (!o) {
        return failure(o.error());
    }
    evacuation_request r;
    const auto* node = o->if_contains("node");
    if (node == nullptr) {
        return failure("\"node\" is required");
    }
    auto id = detail::id_from(*node);
    if (!id) {
        return failure(id.error());
    }
    r.node = *id;
    const auto* t = o->if_contains("targets");
    const auto* arr = t != nullptr ? t->if_array() : nullptr;
    if (arr == nullptr || arr->empty() || arr->size() > k_max_targets) {
        return failure("\"targets\" must be an array of 1 to " + std::to_string(k_max_targets) +
                       " node ids");
    }
    for (const auto& e : *arr) {
        auto tid = detail::id_from(e);
        if (!tid) {
            return failure(tid.error());
        }
        if (*tid == r.node) {
            return failure("the node being evacuated cannot be its own target");
        }
        if (std::find(r.targets.begin(), r.targets.end(), *tid) == r.targets.end()) {
            r.targets.push_back(std::move(*tid));
        }
    }
    if (const auto* rep = o->if_contains("replicas")) {
        std::int64_t value = -1;
        if (const auto* n = rep->if_int64()) {
            value = *n;
        } else if (const auto* u = rep->if_uint64(); u != nullptr && *u <= k_max_replicas) {
            value = static_cast<std::int64_t>(*u);
        }
        if (value < 1 || value > static_cast<std::int64_t>(k_max_replicas)) {
            return failure("\"replicas\" must be 1 to " + std::to_string(k_max_replicas));
        }
        r.replicas = static_cast<std::size_t>(value);
    }
    if (const auto* f = o->if_contains("fan_out")) {
        if (!f->is_bool()) {
            return failure("\"fan_out\" must be true or false");
        }
        r.fan_out = f->as_bool();
    }
    return r;
}

[[nodiscard]] inline auto to_json(const evacuation_request& r) -> std::string {
    boost::json::array targets;
    for (const auto& t : r.targets) {
        targets.emplace_back(kythira::host_node_id_text(t));
    }
    return boost::json::serialize(boost::json::object{
        {"node", kythira::host_node_id_text(r.node)},
        {"targets", std::move(targets)},
        {"replicas", static_cast<std::uint64_t>(r.replicas)},
        {"fan_out", r.fan_out},
    });
}

/// What a data node sees of the catalog's membership and the job.
struct status {
    kythira::host_node_id self{};
    /// The catalog's configuration as this node's replica holds it; empty
    /// without a replica.
    std::vector<kythira::host_node_id> voters;
    std::vector<kythira::host_node_id> learners;
    bool leader = false;
    /// The job running here; nullopt without one.
    std::optional<evacuation_request> job;
    /// The last step this node took or waited on as leader ("done",
    /// "add_replica", ...), and its last error.
    std::string action;
    std::string error;
    /// The job's evacuee holds no voter or learner seat in `voters` and
    /// `learners` (only meaningful on the leader, whose view is current).
    bool done = false;
};

[[nodiscard]] inline auto to_json(const status& s) -> std::string {
    const auto ids = [](const std::vector<kythira::host_node_id>& v) {
        boost::json::array a;
        for (const auto& id : v) {
            a.emplace_back(kythira::host_node_id_text(id));
        }
        return a;
    };
    boost::json::object o{
        {"node", kythira::host_node_id_text(s.self)},
        {"voters", ids(s.voters)},
        {"learners", ids(s.learners)},
        {"leader", s.leader},
        {"action", s.action},
        {"done", s.done},
    };
    if (!s.error.empty()) {
        o["error"] = s.error;
    }
    if (s.job) {
        std::error_code ec;
        o["job"] = boost::json::parse(to_json(*s.job), ec);
    }
    return boost::json::serialize(o);
}

/// Parses a status body (what an operator's tool or a test reads).
[[nodiscard]] inline auto parse_status(std::string_view body) -> result<status> {
    auto o = detail::object_of(body);
    if (!o) {
        return failure(o.error());
    }
    status s;
    const auto ids = [&](std::string_view key,
                         std::vector<kythira::host_node_id>& out) -> result<void> {
        const auto* v = o->if_contains(key);
        const auto* a = v != nullptr ? v->if_array() : nullptr;
        if (a == nullptr) {
            return failure("\"" + std::string(key) + "\" must be an array");
        }
        for (const auto& e : *a) {
            auto id = detail::id_from(e);
            if (!id) {
                return failure(id.error());
            }
            out.push_back(std::move(*id));
        }
        return {};
    };
    const auto* node = o->if_contains("node");
    if (node == nullptr) {
        return failure("\"node\" is required");
    }
    auto self = detail::id_from(*node);
    if (!self) {
        return failure(self.error());
    }
    s.self = *self;
    if (auto r = ids("voters", s.voters); !r) {
        return failure(r.error());
    }
    if (auto r = ids("learners", s.learners); !r) {
        return failure(r.error());
    }
    const auto flag = [&](std::string_view key) {
        const auto* v = o->if_contains(key);
        return v != nullptr && v->is_bool() && v->as_bool();
    };
    s.leader = flag("leader");
    s.done = flag("done");
    if (const auto* a = o->if_contains("action"); a != nullptr && a->is_string()) {
        s.action = std::string(a->as_string());
    }
    if (const auto* e = o->if_contains("error"); e != nullptr && e->is_string()) {
        s.error = std::string(e->as_string());
    }
    if (const auto* j = o->if_contains("job"); j != nullptr && j->is_object()) {
        auto job = parse_evacuation(boost::json::serialize(*j));
        if (!job) {
            return failure("\"job\": " + job.error());
        }
        s.job = std::move(*job);
    }
    return s;
}

/// A membership route's answer.
struct answer {
    unsigned status = 200;
    std::string body;
};

/// What a data node does for the routes; the module supplies it.
struct handlers {
    std::function<answer(const evacuation_request&)> evacuate;
    std::function<answer()> status;
    std::function<answer(bool fan_out)> cancel;
    std::function<answer()> release;
};

/// Answers one membership request. `admitted` is the caller check
/// (`admits(policy, caller, membership_route_roles)`).
[[nodiscard]] inline auto serve(const handlers& h, bool admitted, std::string_view method,
                                std::string_view target, std::string_view body) -> answer {
    const auto error = [](unsigned code, std::string why) {
        return answer{code, boost::json::serialize(boost::json::object{{"error", std::move(why)}})};
    };
    if (!admitted) {
        return error(403, "the membership routes answer data nodes only");
    }
    const auto path = target.substr(0, target.find('?'));
    if (path == k_evacuate_path && method == "GET") {
        return h.status();
    }
    if (method != "POST") {
        return error(405, "use POST");
    }
    if (path == k_evacuate_path) {
        auto r = parse_evacuation(body);
        if (!r) {
            return error(400, r.error());
        }
        return h.evacuate(*r);
    }
    if (path == k_cancel_path) {
        // The fanned-out copy says so in its query, to stop it travelling
        // further.
        return h.cancel(target.find("fan_out=false") == std::string_view::npos);
    }
    if (path == k_release_path) {
        return h.release();
    }
    return error(404, "no such membership route");
}

}  // namespace kythira::kms::membership
