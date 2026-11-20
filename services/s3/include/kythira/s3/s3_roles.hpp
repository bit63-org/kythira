// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_roles.hpp
/// @brief Which S3 layers a node runs (`KYTHIRA_S3_ROLES`), which role sets
///        can serve today, and who may call the internal routes
///        (.kiro/specs/s3-compatible-storage/ task 16; Requirements 14.1,
///        14.5).
///
/// A node runs any non-empty subset of S3's four layers: `gateway` (client
/// protocol, SigV4), `front_end` (authorization, handlers, chunking),
/// `metadata` (the object index groups and the leader-side workers) and
/// `blobs` (a chunk store). Every role is the default: a co-located node.
///
/// The roles are the four the independent-layers specs share
/// (`raft/layer_roles.hpp`) under S3's names: S3's metadata layer is the
/// shared `data` layer (Raft replicas) and its blob layer the shared
/// `segments` layer (bytes outside Raft). Configuration and messages use
/// S3's names; layer identities in certificates (`raft/layer_identity.hpp`)
/// carry the shared ones, so one certificate authority and one route guard
/// serve every service:
///
/// | `KYTHIRA_S3_ROLES` | SAN `roles=` |
/// |---|---|
/// | `gateway` | `gateway` |
/// | `front_end` | `front_end` |
/// | `metadata` | `data` |
/// | `blobs` | `segments` |
///
/// **Layouts that serve today.** `check_layout` refuses, with a message
/// naming what is missing, a role set that has no way to serve:
///
///  - `front_end` without `metadata` needs metadata endpoints
///    (`KYTHIRA_S3_METADATA_ENDPOINTS`): it reaches the index through
///    `remote_metadata`, and writes chunks to the metadata nodes' blob
///    stores, which co-located placement puts them on (Requirement 15.1).
///  - `gateway` without `front_end` hands each authenticated call to a front
///    end over the internal transport, which is task 17's; until then the
///    gateway runs with the front end.
///  - `metadata` without `blobs`, and `blobs` without `metadata`, need a
///    blob pool (the rendezvous placement of task 18): under co-located
///    placement a metadata node holds its groups' chunks itself.
///
/// So task 16 serves the co-located node, a stateless front end (with or
/// without the gateway) over metadata nodes, and a metadata node (with
/// blobs) behind front ends; a node with `front_end` and `metadata` that is
/// also given metadata endpoints runs `hybrid_metadata`.

#include <kythira/s3/s3_placement.hpp>

#include <raft/chunk_service.hpp>
#include <raft/layer_identity.hpp>
#include <raft/layer_roles.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::s3 {

using layers::role;
using layers::role_set;

/// The service name in S3's layer identities.
inline constexpr std::string_view layer_service = "s3";

/// S3's name for one of the shared roles.
[[nodiscard]] constexpr auto s3_role_name(role r) noexcept -> std::string_view {
    switch (r) {
        case role::gateway:
            return "gateway";
        case role::front_end:
            return "front_end";
        case role::data:
            return "metadata";
        case role::segments:
            return "blobs";
    }
    return "";
}

/// The shared role S3 calls `name`; `nullopt` for anything else (names are
/// exact and lower-case).
[[nodiscard]] constexpr auto parse_s3_role(std::string_view name) noexcept -> std::optional<role> {
    for (const auto r : layers::every_role) {
        if (s3_role_name(r) == name) {
            return r;
        }
    }
    return std::nullopt;
}

/// Parses `KYTHIRA_S3_ROLES` ("gateway,front_end", commas, no spaces).
/// Throws `std::invalid_argument` naming an unknown or repeated role, an
/// empty element, or an empty list (unset means every role; set to nothing
/// is a mistake, not a node with no layers).
[[nodiscard]] inline auto parse_s3_roles(std::string_view text) -> role_set {
    if (text.empty()) {
        throw std::invalid_argument("KYTHIRA_S3_ROLES is empty (leave it unset to run every role)");
    }
    role_set out;
    std::size_t start = 0;
    for (;;) {
        const auto comma = text.find(',', start);
        const auto name = text.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        const auto r = parse_s3_role(name);
        if (!r) {
            throw std::invalid_argument("unknown S3 role \"" + std::string(name) +
                                        "\" (expected gateway, front_end, metadata or blobs)");
        }
        if (out.has(*r)) {
            throw std::invalid_argument("S3 role \"" + std::string(name) + "\" is listed twice");
        }
        out.add(*r);
        if (comma == std::string_view::npos) {
            return out;
        }
        start = comma + 1;
    }
}

/// "gateway,front_end,metadata,blobs" order, S3's names.
[[nodiscard]] inline auto s3_roles_string(role_set roles) -> std::string {
    std::string out;
    for (const auto r : layers::every_role) {
        if (roles.has(r)) {
            if (!out.empty()) {
                out.push_back(',');
            }
            out.append(s3_role_name(r));
        }
    }
    return out;
}

/// What a node was given besides its roles.
struct layout {
    role_set roles = role_set::all();
    /// `KYTHIRA_S3_METADATA_ENDPOINTS` names at least one metadata node.
    bool metadata_endpoints = false;
    /// The placement rule chunks are written under.
    placement_rule placement = placement_rule::co_located;
};

/// Why `l` cannot serve, or `nullopt` when it can (Kinesis Requirement 2.4,
/// which S3's Requirement 14 follows).
[[nodiscard]] inline auto check_layout(const layout& l) -> std::optional<std::string> {
    const auto& r = l.roles;
    if (r.empty()) {
        return "a node needs at least one S3 role";
    }
    if (r.has(role::gateway) && !r.has(role::front_end)) {
        return "the gateway role without front_end would hand calls to front ends over the "
               "internal transport, which is not built yet (s3-compatible-storage task 17); run "
               "gateway together with front_end";
    }
    if (r.has(role::front_end) && !r.has(role::data) && !l.metadata_endpoints) {
        return "the front_end role without metadata needs KYTHIRA_S3_METADATA_ENDPOINTS, the "
               "metadata nodes to read and write the object index through";
    }
    if (l.placement == placement_rule::co_located) {
        if (r.has(role::data) && !r.has(role::segments)) {
            return "the metadata role without blobs needs a blob pool (rendezvous placement, "
                   "s3-compatible-storage task 18): co-located placement keeps a group's "
                   "chunks on its metadata nodes";
        }
        if (r.has(role::segments) && !r.has(role::data)) {
            return "the blobs role without metadata holds chunks only under a blob pool "
                   "(rendezvous placement, s3-compatible-storage task 18): co-located placement "
                   "keeps a group's chunks on its metadata nodes";
        }
    }
    return std::nullopt;
}

/// Path prefix of the metadata-layer routes (`s3_remote_metadata.hpp`).
inline constexpr std::string_view metadata_route_prefix = "/_kythira/s3/metadata/v1/";

/// Path prefix of the routes between the members of an index group
/// (`s3_raft_metadata.hpp`): a proposal or a read-index round sent to the
/// leader, and a change log segment fetched from a peer.
inline constexpr std::string_view group_route_prefix = "/_kythira/s3/group/v1/";

/// Who may call S3's internal routes (Requirement 14.5):
///
///  - the metadata routes: front ends, and metadata nodes (a metadata node
///    with a front end on it forwards to the group it does not hold);
///  - the group routes: metadata nodes only (the members of the index
///    groups forward to their leader and fetch segments from each other);
///  - the chunk routes (`raft/chunk_service.hpp`): front ends (object
///    bytes), metadata nodes (the sweeper, placement repair and the tier
///    worker read, write, list and delete chunks) and blob nodes (moves
///    between placements, task 18).
///
/// The gateway calls neither: it reaches the front end only.
[[nodiscard]] inline auto internal_route_rules() -> std::vector<layers::route_rule> {
    return {
        {std::string(metadata_route_prefix), role_set{role::front_end, role::data}},
        {std::string(group_route_prefix), role_set{role::data}},
        {std::string(chunk_service_prefix), role_set{role::front_end, role::data, role::segments}},
    };
}

}  // namespace kythira::s3
