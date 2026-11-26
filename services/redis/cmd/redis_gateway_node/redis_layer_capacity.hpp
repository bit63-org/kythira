// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_layer_capacity.hpp
/// @brief The elastic capacity loop over one stateless layer
///        (.kiro/specs/redis-general-data-types/ task 18, Requirement 20.3).
///
/// Each voter of the layer membership group builds one. It acts only while
/// its replica leads the group: the lease is the group's Raft leadership,
/// fenced by its term, so two voters never provision at once. Every round it
/// reads the member list, hands the controller one report per member of the
/// layer it scales (`KYTHIRA_REDIS_CAPACITY_LAYER`), and steps it. The policy
/// is the shared `layer_capacity_policy` over commands per second, open
/// connections and CPU. A member is drained through the group before the
/// controller decommissions it: the drain hooks mark it draining, gateways
/// stop choosing it, it closes its clients and marks itself drained, and only
/// then does the quorum manager remove the machine.
///
/// The controller's ledger is in memory, like the group's log. A new leader
/// starts with an empty ledger and reconciles from the quorum manager's own
/// view (the docker manager labels what it created), which is the
/// controller's documented recovery path.
///
/// The controller and the quorum manager are instantiated in
/// layer_capacity_docker.cpp, so the Redis node's other units do not grow.

#include "config.hpp"
#include "redis_membership_group.hpp"

#include <memory>

namespace kythira::redis_node {

class layer_capacity_loop {
public:
    layer_capacity_loop() = default;
    layer_capacity_loop(const layer_capacity_loop&) = delete;
    auto operator=(const layer_capacity_loop&) -> layer_capacity_loop& = delete;
    layer_capacity_loop(layer_capacity_loop&&) = delete;
    auto operator=(layer_capacity_loop&&) -> layer_capacity_loop& = delete;
    virtual ~layer_capacity_loop() = default;

    virtual void start() = 0;
    virtual void stop() = 0;
};

/// The loop `opt._capacity` asks for, over `group`, or nullptr when it asks
/// for none. `group` must outlive the loop.
/// @throws std::invalid_argument for settings the controller refuses.
[[nodiscard]] auto make_layer_capacity_loop(const node_options& opt, membership_group& group)
    -> std::unique_ptr<layer_capacity_loop>;

}  // namespace kythira::redis_node
