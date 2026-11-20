// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file segment_volume_placement.hpp
/// @brief Which segment node holds each data replica's volume
///        (.kiro/specs/kinesis-independent-layers/ task 10, design "Segment
///        store: a volume per replica", Requirements 9.4, 9.5, 9.8 and 10.6).
///
/// A data node that runs without the `segments` role keeps its record
/// segments in one *volume* on a segment node (`segment_volume_service.hpp`,
/// `remote_segment_store.hpp`). This header decides where those volumes go
/// and names them:
///
/// - **Distinct segment nodes.** Replicas of one group never share a segment
///   node, so losing one segment node loses at most one volume per group and
///   the group keeps its quorum (Requirement 9.4).
/// - **Distinct placement groups where possible.** When the segment layer
///   spans placement groups, a replica's volume goes to a group none of its
///   peers' volumes use, if one has room. It is a preference, not a rule: a
///   segment layer in one placement group still serves.
/// - **Room first.** Among the candidates left, the node with the most
///   available bytes wins, and the lowest id breaks ties, so every node that
///   computes a placement from the same inputs gets the same answer.
/// - **Epochs.** A volume's writer is named by its epoch. Moving a replica's
///   volume, or giving it to a replacement, raises the epoch, so the segment
///   node refuses the old writer (`segment_volume_fenced`).
///
/// Nothing here does I/O. The caller supplies the segment nodes (from
/// configuration or the layer membership group) and the assignments it
/// already holds (from its catalog), and stores what comes back.

#include <boost/json.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira {

/// A segment node as placement sees it.
struct segment_node_info {
    /// The node's id, unique in the segment layer.
    std::string _id;
    /// Where its volume API answers (`host:port`).
    std::string _endpoint;
    /// Its placement group; empty when the layer has only one.
    std::string _placement_group;
    /// Its storage in bytes, as its last `space` answer said; both 0 when
    /// unknown (at first start, from configuration alone).
    std::uint64_t _capacity_bytes = 0;
    std::uint64_t _available_bytes = 0;

    friend auto operator==(const segment_node_info&, const segment_node_info&) -> bool = default;
};

/// One data replica's volume: where it is and which writer owns it.
struct volume_assignment {
    /// The data replica (its node id).
    std::string _replica;
    /// The segment node holding the volume (`segment_node_info::_id`).
    std::string _segment_node;
    /// The volume's id on that node (`volume_id_for`).
    std::string _volume;
    /// The writer epoch; starts at 1 and only rises.
    std::uint64_t _epoch = 0;

    friend auto operator==(const volume_assignment&, const volume_assignment&) -> bool = default;
};

/// The volume id a replica's records use: the service name, a hyphen and
/// the replica id (`kinesis-12`). `segment_volume_service::valid_volume_id`
/// accepts it for the ids Kythira uses: letters, digits, hyphens, dots and
/// underscores. Throws `std::invalid_argument` for an id that could not
/// name a volume.
[[nodiscard]] inline auto volume_id_for(std::string_view service, std::string_view replica)
    -> std::string {
    std::string id;
    id.reserve(service.size() + 1 + replica.size());
    id.append(service).append("-").append(replica);
    const auto allowed = [](char c) noexcept {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_';
    };
    if (service.empty() || replica.empty() || id.size() > 128 || id.front() == '.' ||
        !std::all_of(id.begin(), id.end(), allowed)) {
        throw std::invalid_argument("segment volume: \"" + id + "\" cannot name a volume");
    }
    return id;
}

/// The segment node for `replica`'s volume, given where its peers'
/// volumes already are; `nullopt` when every node is excluded or already
/// holds a peer's volume. `exclude` names nodes that must not be chosen
/// (one that was just lost, or one draining).
[[nodiscard]] inline auto choose_segment_node(const std::vector<volume_assignment>& peers,
                                              const std::vector<segment_node_info>& nodes,
                                              const std::set<std::string>& exclude = {})
    -> std::optional<segment_node_info> {
    std::set<std::string> taken;
    std::set<std::string> taken_groups;
    for (const auto& p : peers) {
        taken.insert(p._segment_node);
        for (const auto& n : nodes) {
            if (n._id == p._segment_node) {
                taken_groups.insert(n._placement_group);
            }
        }
    }
    const segment_node_info* best = nullptr;
    // Smaller is better: a placement group no peer uses, then the most
    // available bytes, then the lowest id.
    const auto rank = [&taken_groups](const segment_node_info& n) {
        return std::tuple(taken_groups.contains(n._placement_group) ? 1 : 0, ~n._available_bytes,
                          std::string_view(n._id));
    };
    for (const auto& n : nodes) {
        if (exclude.contains(n._id) || taken.contains(n._id)) {
            continue;
        }
        if (best == nullptr || rank(n) < rank(*best)) {
            best = &n;
        }
    }
    if (best == nullptr) {
        return std::nullopt;
    }
    return *best;
}

/// The first assignment of every replica in `replicas` (the voters that
/// share one group, or all the data nodes when every group has the same
/// voters), at epoch 1, in the order given. Every node that runs this on
/// the same inputs gets the same result, so a cluster's first start needs
/// no agreement round. Throws `std::invalid_argument` when there are fewer
/// segment nodes than replicas, or a node id repeats.
[[nodiscard]] inline auto initial_volume_assignments(std::string_view service,
                                                     const std::vector<std::string>& replicas,
                                                     const std::vector<segment_node_info>& nodes)
    -> std::vector<volume_assignment> {
    std::set<std::string> seen;
    for (const auto& n : nodes) {
        if (!seen.insert(n._id).second) {
            throw std::invalid_argument("segment volume: segment node " + n._id +
                                        " is listed twice");
        }
    }
    if (nodes.size() < replicas.size()) {
        throw std::invalid_argument("segment volume: " + std::to_string(replicas.size()) +
                                    " data replicas need " + std::to_string(replicas.size()) +
                                    " segment nodes so that no two share one; there are " +
                                    std::to_string(nodes.size()));
    }
    std::vector<volume_assignment> out;
    out.reserve(replicas.size());
    for (const auto& replica : replicas) {
        auto node = choose_segment_node(out, nodes);
        if (!node) {
            throw std::invalid_argument("segment volume: no segment node left for replica " +
                                        replica);
        }
        out.push_back({._replica = replica,
                       ._segment_node = node->_id,
                       ._volume = volume_id_for(service, replica),
                       ._epoch = 1});
    }
    return out;
}

/// A new home for `current`'s volume after its segment node was lost or
/// refused it: another node that holds none of `peers`' volumes, and the
/// next epoch, so the old writer is fenced wherever it still runs. The
/// replica restores into the new volume from a snapshot and its peers
/// (Requirement 9.5). `nullopt` when no node qualifies.
[[nodiscard]] inline auto replace_volume(const volume_assignment& current,
                                         const std::vector<volume_assignment>& peers,
                                         const std::vector<segment_node_info>& nodes)
    -> std::optional<volume_assignment> {
    auto node = choose_segment_node(peers, nodes, {current._segment_node});
    if (!node) {
        return std::nullopt;
    }
    auto next = current;
    next._segment_node = node->_id;
    next._epoch = current._epoch + 1;
    return next;
}

/// The assignment for `replica` in `assignments`, if any.
[[nodiscard]] inline auto assignment_of(const std::vector<volume_assignment>& assignments,
                                        std::string_view replica)
    -> std::optional<volume_assignment> {
    for (const auto& a : assignments) {
        if (a._replica == replica) {
            return a;
        }
    }
    return std::nullopt;
}

/// The segment node `id` in `nodes`, if any.
[[nodiscard]] inline auto segment_node_of(const std::vector<segment_node_info>& nodes,
                                          std::string_view id) -> std::optional<segment_node_info> {
    for (const auto& n : nodes) {
        if (n._id == id) {
            return n;
        }
    }
    return std::nullopt;
}

/// Parses a segment node list: comma-separated `id=host:port`, each with an
/// optional `@placement-group`, as in
/// `11=seg-a:8443@us-east-1a,12=seg-b:8443@us-east-1b`. Throws
/// `std::invalid_argument` naming the bad entry.
[[nodiscard]] inline auto parse_segment_nodes(std::string_view text)
    -> std::vector<segment_node_info> {
    std::vector<segment_node_info> out;
    std::set<std::string> seen;
    while (!text.empty()) {
        const auto comma = text.find(',');
        const auto entry = text.substr(0, comma);
        text = comma == std::string_view::npos ? std::string_view() : text.substr(comma + 1);
        const auto eq = entry.find('=');
        if (eq == std::string_view::npos || eq == 0 || eq + 1 == entry.size()) {
            throw std::invalid_argument("segment node \"" + std::string(entry) +
                                        "\" is not id=host:port[@group]");
        }
        segment_node_info n;
        n._id = std::string(entry.substr(0, eq));
        auto rest = entry.substr(eq + 1);
        if (const auto at = rest.find('@'); at != std::string_view::npos) {
            n._placement_group = std::string(rest.substr(at + 1));
            rest = rest.substr(0, at);
            if (n._placement_group.empty()) {
                throw std::invalid_argument("segment node \"" + std::string(entry) +
                                            "\" names an empty placement group");
            }
        }
        if (rest.empty() || rest.find(':') == std::string_view::npos) {
            throw std::invalid_argument("segment node \"" + std::string(entry) +
                                        "\" is not id=host:port[@group]");
        }
        n._endpoint = std::string(rest);
        if (!seen.insert(n._id).second) {
            throw std::invalid_argument("segment node " + n._id + " is listed twice");
        }
        out.push_back(std::move(n));
    }
    return out;
}

/// An assignment as the JSON a catalog entry holds:
/// `{"replica":..,"segment_node":..,"volume":..,"epoch":..}`.
[[nodiscard]] inline auto encode_volume_assignment(const volume_assignment& a) -> std::string {
    return boost::json::serialize(boost::json::object{
        {"replica", a._replica},
        {"segment_node", a._segment_node},
        {"volume", a._volume},
        {"epoch", a._epoch},
    });
}

/// The inverse of `encode_volume_assignment`; `nullopt` for anything else.
[[nodiscard]] inline auto decode_volume_assignment(std::string_view text)
    -> std::optional<volume_assignment> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(text, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    const auto str = [&o](std::string_view k) -> std::optional<std::string> {
        const auto* f = o.if_contains(k);
        if (f == nullptr || !f->is_string() || f->as_string().empty()) {
            return std::nullopt;
        }
        return std::string(f->as_string());
    };
    // A positive integer, however the parser stored it.
    const auto positive = [](const boost::json::value* v) -> std::optional<std::uint64_t> {
        if (v != nullptr && v->is_uint64() && v->as_uint64() > 0) {
            return v->as_uint64();
        }
        if (v != nullptr && v->is_int64() && v->as_int64() > 0) {
            return static_cast<std::uint64_t>(v->as_int64());
        }
        return std::nullopt;
    };
    auto replica = str("replica");
    auto node = str("segment_node");
    auto volume = str("volume");
    const auto e = positive(o.if_contains("epoch"));
    if (!replica || !node || !volume || !e || o.size() != 4) {
        return std::nullopt;
    }
    return volume_assignment{._replica = std::move(*replica),
                             ._segment_node = std::move(*node),
                             ._volume = std::move(*volume),
                             ._epoch = *e};
}

}  // namespace kythira
