// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The layer membership group's host on the stand-alone daemon's transports
// (redis-general-data-types task 18), in a translation unit of its own.

#include "redis_membership_group_impl.hpp"
#include "serving_factories.hpp"

namespace kythira::redis_node {

template auto make_membership_group<cbor_host>(const node_options&, cbor_host&, std::uint64_t,
                                               cbor_host::view_type)
    -> std::unique_ptr<membership_group>;
template auto make_membership_group<json_host>(const node_options&, json_host&, std::uint64_t,
                                               json_host::view_type)
    -> std::unique_ptr<membership_group>;

}  // namespace kythira::redis_node
