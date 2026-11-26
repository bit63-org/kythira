// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_layer_roles.hpp
/// @brief The Redis module's layer roles: `KYTHIRA_REDIS_ROLES`
///        (.kiro/specs/redis-general-data-types/ Requirement 16, design
///        Component 9 "Roles and composition").
///
/// A Redis node runs a non-empty subset of three of the shared roles
/// (`include/raft/layer_roles.hpp`): `gateway` (RESP, TLS, AUTH/HELLO,
/// connection state), `front_end` (authorization, planning, the
/// transaction coordinator, SCAN cursors) and `data` (the multi-Raft host
/// and its state machines). Redis has no record segments, so `segments` is
/// refused. All three is co-located, the default, and is exactly the node
/// as it was before the layer work.

#include <raft/layer_roles.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kythira {

/// gateway,front_end,data: what a node that sets nothing runs.
inline constexpr layers::role_set k_redis_all_roles{layers::role::gateway, layers::role::front_end,
                                                    layers::role::data};

/// Parses a `KYTHIRA_REDIS_ROLES` value (commas, no spaces).
/// @throws std::invalid_argument for an unknown or repeated role, an empty
///         list, or `segments`, naming the fault.
[[nodiscard]] inline auto parse_redis_roles(std::string_view text) -> layers::role_set {
    const auto roles = layers::role_set::parse(text);
    if (roles.empty()) {
        throw std::invalid_argument(
            "the Redis role set is empty (expected a comma-separated subset of gateway, "
            "front_end, data)");
    }
    if (roles.has(layers::role::segments)) {
        throw std::invalid_argument(
            "the Redis module has no segments layer (expected a comma-separated subset of "
            "gateway, front_end, data)");
    }
    return roles;
}

/// Why this build cannot serve `roles` yet; `nullopt` when it can.
///
/// The layer work lands one task at a time (tasks.md 15-20), and a role set
/// that needs a piece not built yet must stop the node at start, naming
/// what is missing (Requirement 16.3), rather than start a node that cannot
/// answer. Three sets serve:
///
/// - all three, co-located (the default);
/// - `gateway,front_end`: a front end without the data layer, reaching the
///   data nodes over `KYTHIRA.DATA` (task 16; it also needs
///   `KYTHIRA_REDIS_DATA_NODES`);
/// - `data`: a data node, whose listener serves only other nodes' front
///   ends (task 16).
///
/// A `gateway` without `front_end`, or a `front_end` without `gateway`,
/// needs authenticated calls between the two (task 17).
[[nodiscard]] inline auto redis_roles_unservable(layers::role_set roles)
    -> std::optional<std::string> {
    const layers::role_set front_end_only{layers::role::gateway, layers::role::front_end};
    const layers::role_set data_only{layers::role::data};
    if (roles == k_redis_all_roles || roles == front_end_only || roles == data_only) {
        return std::nullopt;
    }
    return "KYTHIRA_REDIS_ROLES=" + roles.to_string() +
           ": a gateway apart from its front end needs authenticated calls between the two, "
           "which this build does not have yet (redis-general-data-types task 17)";
}

}  // namespace kythira
