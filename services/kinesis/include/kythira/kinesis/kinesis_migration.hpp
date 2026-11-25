// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file kinesis_migration.hpp
/// @brief The live migration admin calls' wire forms
///        (.kiro/specs/kinesis-independent-layers/ task 13, Requirements
///        11.3-11.5).
///
/// A data node serves these under `/_kythira/kinesis/v1/admin/`, signed
/// with the forwarding secret like every route between nodes
/// (`admin_signed_text`). Bodies are JSON:
///
/// - `POST evacuate` `{"node":"1","targets":[{"id":"4","raft":"http://...",
///   "gateway":"host:port"}],"replicas":3,"fan_out":true}`: move every
///   replica `node` holds to the targets. Each data node runs the job on
///   the groups it leads; with `fan_out` the node that takes the call
///   passes it on to every peer it knows. A target's Raft URL and gateway
///   address are how the cluster reaches a node its settings do not list.
/// - `GET evacuate`: this node's view, `{"node":..,"done":bool,"led":[...]}`.
/// - `POST evacuate/cancel`.
/// - `POST release`: the evacuee's own call once every group is done: it
///   may now restart without the `data` role (a node holding replicas
///   refuses to, unless told to discard them).
/// - `GET descriptor?group=N`: the group's descriptor with the membership
///   its Raft replica runs under, for a target's lazy replica creation.
/// - `POST store-move` `{"to":"volume","segment_node":"s1"}` or
///   `{"to":"local"}`; `GET store-move` reports the last one.

#include <raft/host_node_id.hpp>
#include <raft/shard_types.hpp>

#include <boost/json.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace kythira::kinesis {

inline constexpr std::string_view k_admin_path_prefix = "/_kythira/kinesis/v1/admin/";

/// What an admin call's signature covers: the method, the path with its
/// query, and the body, so a signed call cannot be replayed as another.
[[nodiscard]] inline auto admin_signed_text(std::string_view method, std::string_view target,
                                            std::string_view body) -> std::string {
    std::string out;
    out.reserve(method.size() + target.size() + body.size() + 2);
    out.append(method).append("\n").append(target).append("\n").append(body);
    return out;
}

/// A node an evacuation may move replicas to.
struct migration_target {
    kythira::host_node_id _id{};
    /// Its Raft base URL; empty when every node already knows it.
    std::string _raft;
    /// Its gateway (internal listener) `host:port`; empty likewise.
    std::string _gateway;
    friend auto operator==(const migration_target&, const migration_target&) -> bool = default;
};

struct evacuation_request {
    kythira::host_node_id _node{};
    std::vector<migration_target> _targets;
    /// Voters each group keeps; 0 means the node's own replication factor.
    std::size_t _replicas = 0;
    bool _fan_out = true;
    friend auto operator==(const evacuation_request&, const evacuation_request&) -> bool = default;
};

namespace migration_detail {

[[nodiscard]] inline auto id_from(const boost::json::value& v, std::string& why)
    -> std::optional<kythira::host_node_id> {
    std::string text;
    if (const auto* s = v.if_string()) {
        text = std::string(s->c_str(), s->size());
    } else if (const auto* u = v.if_uint64()) {
        text = std::to_string(*u);
    } else if (const auto* i = v.if_int64(); i != nullptr && *i >= 0) {
        text = std::to_string(*i);
    } else {
        why = "a node id must be a string or a non-negative number";
        return std::nullopt;
    }
    auto id = kythira::parse_host_peer_node_id(text);
    if (!id) {
        why = "bad node id '" + text + "': " + id.error();
        return std::nullopt;
    }
    return std::move(id).value();
}

[[nodiscard]] inline auto string_at(const boost::json::object& o, std::string_view key)
    -> std::optional<std::string> {
    const auto* v = o.if_contains(key);
    if (v == nullptr) {
        return std::string();
    }
    if (const auto* s = v->if_string()) {
        return std::string(s->c_str(), s->size());
    }
    return std::nullopt;
}

[[nodiscard]] inline auto parse_object(std::string_view body, std::string& why)
    -> std::optional<boost::json::object> {
    std::error_code ec;
    auto v = boost::json::parse(body, ec);
    if (ec || !v.is_object()) {
        why = "the body is not a JSON object";
        return std::nullopt;
    }
    return std::move(v.as_object());
}

}  // namespace migration_detail

/// Parses an evacuate body; nullopt with `why` set when it is malformed.
[[nodiscard]] inline auto parse_evacuation_request(std::string_view body, std::string& why)
    -> std::optional<evacuation_request> {
    namespace d = migration_detail;
    auto o = d::parse_object(body, why);
    if (!o) {
        return std::nullopt;
    }
    evacuation_request r;
    const auto* node = o->if_contains("node");
    if (node == nullptr) {
        why = "\"node\" is required";
        return std::nullopt;
    }
    auto id = d::id_from(*node, why);
    if (!id) {
        return std::nullopt;
    }
    r._node = *id;
    if (const auto* t = o->if_contains("targets")) {
        const auto* arr = t->if_array();
        if (arr == nullptr || arr->size() > 1024) {
            why = "\"targets\" must be an array of at most 1024 nodes";
            return std::nullopt;
        }
        for (const auto& e : *arr) {
            migration_target mt;
            if (const auto* to = e.if_object()) {
                const auto* tid = to->if_contains("id");
                if (tid == nullptr) {
                    why = "each target needs an \"id\"";
                    return std::nullopt;
                }
                auto parsed = d::id_from(*tid, why);
                if (!parsed) {
                    return std::nullopt;
                }
                mt._id = *parsed;
                auto raft = d::string_at(*to, "raft");
                auto gw = d::string_at(*to, "gateway");
                if (!raft || !gw) {
                    why = "a target's \"raft\" and \"gateway\" must be strings";
                    return std::nullopt;
                }
                mt._raft = std::move(*raft);
                mt._gateway = std::move(*gw);
            } else {
                auto parsed = d::id_from(e, why);
                if (!parsed) {
                    return std::nullopt;
                }
                mt._id = *parsed;
            }
            if (mt._id == r._node) {
                why = "the node being evacuated cannot be its own target";
                return std::nullopt;
            }
            r._targets.push_back(std::move(mt));
        }
    }
    if (r._targets.empty()) {
        why = "at least one target is required";
        return std::nullopt;
    }
    if (const auto* rep = o->if_contains("replicas")) {
        const auto* n = rep->if_int64();
        const auto* u = rep->if_uint64();
        const auto value = n != nullptr ? *n : (u != nullptr ? static_cast<std::int64_t>(*u) : -1);
        if (value < 1 || value > 15) {
            why = "\"replicas\" must be 1 to 15";
            return std::nullopt;
        }
        r._replicas = static_cast<std::size_t>(value);
    }
    if (const auto* f = o->if_contains("fan_out")) {
        if (!f->is_bool()) {
            why = "\"fan_out\" must be true or false";
            return std::nullopt;
        }
        r._fan_out = f->as_bool();
    }
    return r;
}

[[nodiscard]] inline auto serialize(const evacuation_request& r) -> std::string {
    boost::json::object o;
    o["node"] = kythira::host_node_id_text(r._node);
    boost::json::array targets;
    for (const auto& t : r._targets) {
        boost::json::object to;
        to["id"] = kythira::host_node_id_text(t._id);
        if (!t._raft.empty()) {
            to["raft"] = t._raft;
        }
        if (!t._gateway.empty()) {
            to["gateway"] = t._gateway;
        }
        targets.push_back(std::move(to));
    }
    o["targets"] = std::move(targets);
    if (r._replicas != 0) {
        o["replicas"] = r._replicas;
    }
    o["fan_out"] = r._fan_out;
    return boost::json::serialize(o);
}

/// Where a store move goes.
struct store_move_request {
    enum class destination : std::uint8_t {
        local,
        volume
    };
    destination _to = destination::local;
    /// For `volume`: the segment node (its KINESIS_SEGMENT_NODES id); empty
    /// lets placement choose.
    std::string _segment_node;
    /// The fence bound in bytes; 0 keeps the default.
    std::uint64_t _max_fence_bytes = 0;
};

[[nodiscard]] inline auto parse_store_move_request(std::string_view body, std::string& why)
    -> std::optional<store_move_request> {
    namespace d = migration_detail;
    auto o = d::parse_object(body, why);
    if (!o) {
        return std::nullopt;
    }
    store_move_request r;
    const auto to = d::string_at(*o, "to");
    if (!to || (*to != "local" && *to != "volume")) {
        why = "\"to\" must be \"local\" or \"volume\"";
        return std::nullopt;
    }
    r._to = *to == "local" ? store_move_request::destination::local
                           : store_move_request::destination::volume;
    const auto node = d::string_at(*o, "segment_node");
    if (!node) {
        why = "\"segment_node\" must be a string";
        return std::nullopt;
    }
    r._segment_node = *node;
    if (!r._segment_node.empty() && r._to == store_move_request::destination::local) {
        why = "\"segment_node\" goes with \"to\":\"volume\"";
        return std::nullopt;
    }
    if (const auto* b = o->if_contains("max_fence_bytes")) {
        const auto* u = b->if_uint64();
        const auto* i = b->if_int64();
        if (u == nullptr && (i == nullptr || *i <= 0)) {
            why = "\"max_fence_bytes\" must be a positive number";
            return std::nullopt;
        }
        r._max_fence_bytes = u != nullptr ? *u : static_cast<std::uint64_t>(*i);
    }
    return r;
}

/// A descriptor as JSON, for `GET descriptor`.
template<typename Descriptor>
[[nodiscard]] auto descriptor_json(const Descriptor& d) -> std::string {
    boost::json::object o;
    o["group"] = d._group_id;
    if (d._range._start) {
        o["start"] = *d._range._start;
    }
    if (d._range._end) {
        o["end"] = *d._range._end;
    }
    o["version"] = d._epoch._version;
    o["conf_version"] = d._epoch._conf_version;
    const auto ids = [](const auto& v) {
        boost::json::array a;
        for (const auto& id : v) {
            a.emplace_back(kythira::host_node_id_text(id));
        }
        return a;
    };
    o["voters"] = ids(d._voters);
    o["learners"] = ids(d._learners);
    return boost::json::serialize(o);
}

/// Reads `descriptor_json` back; nullopt when malformed.
template<typename Descriptor>
[[nodiscard]] auto parse_descriptor_json(std::string_view body, std::string& why)
    -> std::optional<Descriptor> {
    namespace d = migration_detail;
    auto o = d::parse_object(body, why);
    if (!o) {
        return std::nullopt;
    }
    Descriptor out;
    const auto* g = o->if_contains("group");
    if (g == nullptr || !g->is_number()) {
        why = "\"group\" must be a number";
        return std::nullopt;
    }
    std::error_code ec;
    out._group_id = g->template to_number<decltype(out._group_id)>(ec);
    if (ec) {
        why = "\"group\" is out of range";
        return std::nullopt;
    }
    const auto start = d::string_at(*o, "start");
    const auto end = d::string_at(*o, "end");
    if (!start || !end) {
        why = "\"start\" and \"end\" must be strings";
        return std::nullopt;
    }
    if (o->contains("start")) {
        out._range._start = *start;
    }
    if (o->contains("end")) {
        out._range._end = *end;
    }
    for (const auto* key : {"version", "conf_version"}) {
        const auto* v = o->if_contains(key);
        std::uint64_t n = 0;
        if (v != nullptr) {
            n = v->template to_number<std::uint64_t>(ec);
            if (ec) {
                why = std::string("\"") + key + "\" must be a non-negative number";
                return std::nullopt;
            }
        }
        (std::string_view(key) == "version" ? out._epoch._version : out._epoch._conf_version) = n;
    }
    for (const auto* key : {"voters", "learners"}) {
        const auto* v = o->if_contains(key);
        if (v == nullptr) {
            continue;
        }
        const auto* arr = v->if_array();
        if (arr == nullptr || arr->size() > 64) {
            why = std::string("\"") + key + "\" must be an array of at most 64 ids";
            return std::nullopt;
        }
        auto& dst = std::string_view(key) == "voters" ? out._voters : out._learners;
        for (const auto& e : *arr) {
            auto id = d::id_from(e, why);
            if (!id) {
                return std::nullopt;
            }
            dst.push_back(*id);
        }
    }
    if (out._voters.empty()) {
        why = "a descriptor names at least one voter";
        return std::nullopt;
    }
    return out;
}

/// The Raft group directories under `<data_dir>/raft`: the replicas a node
/// holds on disk.
[[nodiscard]] inline auto held_replica_dirs(const std::filesystem::path& data_dir)
    -> std::vector<std::filesystem::path> {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    const auto raft = data_dir / "raft";
    if (data_dir.empty() || !std::filesystem::is_directory(raft, ec)) {
        return out;
    }
    for (const auto& e : std::filesystem::directory_iterator(raft, ec)) {
        if (e.is_directory(ec) && !e.path().filename().string().empty() &&
            e.path().filename().string().find_first_not_of("0123456789") == std::string::npos) {
            out.push_back(e.path());
        }
    }
    return out;
}

/// The marker `POST release` writes once every replica has moved off.
[[nodiscard]] inline auto released_marker(const std::filesystem::path& data_dir)
    -> std::filesystem::path {
    return data_dir / "raft" / "EVACUATED";
}

/// The marker a start without the data role leaves after deleting the
/// replicas: the node left the groups it founded, so it joins (takes
/// replicas only from an evacuation) when it is a data node again, even
/// though KINESIS_VOTERS still names it.
[[nodiscard]] inline auto left_marker(const std::filesystem::path& data_dir)
    -> std::filesystem::path {
    return data_dir / "kinesis-left-groups";
}

}  // namespace kythira::kinesis
