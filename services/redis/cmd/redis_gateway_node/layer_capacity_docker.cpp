// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file layer_capacity_docker.cpp
/// @brief `make_layer_capacity_loop` with the Docker quorum manager, in a unit
///        of its own so the controller is compiled once per binary.

#include "redis_layer_capacity_impl.hpp"

#include <raft/docker_quorum_manager.hpp>
#include <raft/host_node_id.hpp>

namespace kythira::redis_node {

auto make_layer_capacity_loop(const node_options& opt, membership_group& group)
    -> std::unique_ptr<layer_capacity_loop> {
    const auto& c = opt._capacity;
    if (c._layer.empty()) {
        return nullptr;
    }
    docker_quorum_manager_config d;
    d.daemon_url = c._docker_url;
    d.image = c._docker_image;
    d.network_name = c._docker_network;
    d.cluster_name = c._docker_cluster;
    d.node_port = c._node_port;
    // The layer's one placement group, which members report when
    // KYTHIRA_REDIS_PLACEMENT_GROUP is unset.
    d.group_id = opt._gateway._placement_group.empty() ? "default" : opt._gateway._placement_group;
    d.target_count = c._min_members;
    d.extra_env = c._join_env;
    using manager_type = docker_quorum_manager<kythira::host_node_id, std::string>;
    const auto layer = c._layer == "gateway" ? layers::role_set{layers::role::gateway}
                                             : layers::role_set{layers::role::front_end};
    // The gateways' own mark for a member that stopped reporting.
    const auto stale_after =
        std::chrono::milliseconds{3 * opt._gateway._membership_interval.count() + 2000};
    return std::make_unique<capacity_loop<manager_type>>(manager_type{std::move(d)}, c, layer,
                                                         stale_after, group, opt._log_level);
}

}  // namespace kythira::redis_node
