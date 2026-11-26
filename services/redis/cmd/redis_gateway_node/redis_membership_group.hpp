// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_membership_group.hpp
/// @brief A voter's replica of the layer membership group
///        (.kiro/specs/redis-general-data-types/ task 18, Requirement 20.1).
///
/// The group is one Raft group whose state machine is
/// `layers::layer_membership_state_machine` (include/raft/layer_membership.hpp):
/// a small fixed set of voters (`KYTHIRA_REDIS_MEMBERSHIP`, node ids) holds
/// it, and every other gateway and front end reaches it through a voter's
/// `KYTHIRA.MEMBERS` on the internal link instead of holding a replica, so
/// the stateless layers grow without the group growing. It holds no data:
/// losing it loses only the member list, which members re-announce.
///
/// It runs on its own `multi_raft` host beside the Redis one, on the node's
/// shared Raft client and listener, with the last group id of the module's
/// range (the Redis host takes the rest). Its log is in memory, for the
/// reason above. The host type is instantiated in its own translation units
/// (membership_group_*.cpp), so the Redis node's heaviest ones do not grow.

#include "config.hpp"

#include <raft/layer_membership.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace kythira::redis_node {

class membership_group {
public:
    membership_group() = default;
    membership_group(const membership_group&) = delete;
    auto operator=(const membership_group&) -> membership_group& = delete;
    membership_group(membership_group&&) = delete;
    auto operator=(membership_group&&) -> membership_group& = delete;
    virtual ~membership_group() = default;

    virtual void start() = 0;
    virtual void stop() = 0;
    /// Drives elections and replication; called from the node's driver
    /// thread with the Redis host's tick.
    virtual void tick() = 0;
    /// The state machine's one-byte answer once the command applied, or
    /// nullopt when this replica cannot commit it (not the leader, no
    /// quorum, timeout). A nullopt write may still commit.
    virtual auto propose(std::vector<std::byte> command)
        -> std::optional<std::vector<std::byte>> = 0;
    /// This replica's member list.
    [[nodiscard]] virtual auto read() -> std::vector<layers::layer_member> = 0;
};

/// The group's id in a module's group space: the last one, which the Redis
/// host does not take on a node that holds the group.
[[nodiscard]] inline auto membership_group_id(const service_node::group_space& space)
    -> std::uint64_t {
    return space.last();
}

/// Builds this node's replica on `node`'s transport, listening on `view`
/// (the one id `membership_group_id`).
template<typename Host>
auto make_membership_group(const node_options& opt, Host& node, std::uint64_t group,
                           typename Host::view_type view) -> std::unique_ptr<membership_group>;

}  // namespace kythira::redis_node
