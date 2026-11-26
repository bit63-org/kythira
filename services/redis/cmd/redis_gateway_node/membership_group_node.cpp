// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The layer membership group's host on kythira_node's transport
// (redis-general-data-types task 18), in a translation unit of its own.

#include "redis_membership_group_impl.hpp"

#include <raft/kythira_node_host.hpp>

namespace kythira::redis_node {

template auto make_membership_group<service_node::kythira_node_host>(
    const node_options&, service_node::kythira_node_host&, std::uint64_t,
    service_node::kythira_node_host::view_type) -> std::unique_ptr<membership_group>;

}  // namespace kythira::redis_node
