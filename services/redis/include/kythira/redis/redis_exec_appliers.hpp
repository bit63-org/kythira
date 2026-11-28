// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_exec_appliers.hpp
/// The whole chain of `exec` appliers (.kiro/specs/redis-general-data-types/
/// design Component 2): the one every store's `apply()` runs, and the one a
/// transaction evaluates its commands with (redis_txn_view.hpp, task 11),
/// so a new command family joins both by joining this list.

#include <kythira/redis/redis_expiry_exec.hpp>
#include <kythira/redis/redis_hash_exec.hpp>
#include <kythira/redis/redis_install_exec.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_list_exec.hpp>
#include <kythira/redis/redis_multi_key_exec.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_set_exec.hpp>
#include <kythira/redis/redis_string_exec.hpp>

#include <cstdint>
#include <optional>

namespace kythira {

/// The reply of exec record `c` at command time `t` against `store`, from
/// whichever applier owns its command id; `nullopt` when none does.
template<typename Store>
auto apply_redis_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    auto reply = apply_redis_string_exec(store, c, t);
    if (!reply) {
        reply = apply_redis_expiry_exec(store, c, t);
    }
    if (!reply) {
        reply = apply_redis_multi_key_exec(store, c, t);
    }
    if (!reply) {
        reply = apply_redis_hash_exec(store, c, t);
    }
    if (!reply) {
        reply = apply_redis_set_exec(store, c, t);
    }
    if (!reply) {
        reply = apply_redis_list_exec(store, c, t);
    }
    if (!reply) {
        reply = apply_redis_install_exec(store, c, t);
    }
    return reply;
}

}  // namespace kythira
