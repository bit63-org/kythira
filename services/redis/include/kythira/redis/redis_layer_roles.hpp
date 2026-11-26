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

/// Every non-empty role set serves (tasks 16 and 17). What a set without
/// some role needs instead:
///
/// - without `data`: `KYTHIRA_REDIS_DATA_NODES`, reached over
///   `KYTHIRA.DATA` (task 16);
/// - `gateway` without `front_end`: `KYTHIRA_REDIS_FRONT_ENDS`, reached
///   with authenticated calls, `KYTHIRA.CALL` (task 17);
/// - without `gateway`: nothing; the listener then serves only other
///   nodes' calls, never clients.
///
/// A node is co-located when it runs all three. Only co-located nodes
/// accept the internal secret from each other (Requirement 19.3); calls
/// that involve any other node carry layer identities over mutual TLS.
[[nodiscard]] constexpr auto redis_roles_colocated(layers::role_set roles) noexcept -> bool {
    return roles == k_redis_all_roles;
}

}  // namespace kythira
