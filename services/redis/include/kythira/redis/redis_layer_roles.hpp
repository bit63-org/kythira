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
/// answer. Today only the co-located set serves:
///
/// - a `gateway` without `front_end` sends authenticated calls to remote
///   front ends, and a `front_end` without `gateway` accepts them (task 17);
/// - a front end without `data` needs the data-layer API and remote data
///   access (task 16);
/// - `data` alone needs the data-layer API on the internal listener
///   (task 16), so that other nodes' front ends can reach it.
[[nodiscard]] inline auto redis_roles_unservable(layers::role_set roles)
    -> std::optional<std::string> {
    if (roles == k_redis_all_roles) {
        return std::nullopt;
    }
    const auto named = "KYTHIRA_REDIS_ROLES=" + roles.to_string() + ": ";
    if (roles.has(layers::role::gateway) != roles.has(layers::role::front_end)) {
        return named +
               "a gateway apart from its front end needs authenticated calls between the two, "
               "which this build does not have yet (redis-general-data-types task 17)";
    }
    if (!roles.has(layers::role::data)) {
        return named +
               "a front end without the data layer needs the data-layer API and remote data "
               "access, which this build does not have yet (redis-general-data-types task 16)";
    }
    return named +
           "a data node apart from a front end needs the data-layer API on the internal "
           "listener, which this build does not have yet (redis-general-data-types task 16)";
}

}  // namespace kythira
