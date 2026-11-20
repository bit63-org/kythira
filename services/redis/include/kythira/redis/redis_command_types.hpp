// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_command_types.hpp
/// The shape of one entry of the Redis command registry
/// (.kiro/specs/redis-general-data-types/ task 1, design Component 2).
///
/// The registry itself, services/redis/tools/redis_commands.yaml, is turned
/// into <kythira/redis/redis_command_ids.hpp> by
/// services/redis/tools/gen_redis_commands.py; this header holds the types
/// that file fills in. Every command the gateway knows, shipped or planned,
/// has a stable 16-bit id there. The id is what a format-`0x03` `exec` log
/// record carries instead of the command's name, so an id is assigned once
/// and never changed or reused: adding a command adds an id, not a record
/// layout (Requirement 14.1).
///
/// Flags, ACL categories and the legacy key triple use Redis's own names
/// and meanings (`COMMAND INFO`), so that `COMMAND` can be answered from the
/// table (Requirement 1.3).

#include <cstdint>
#include <string_view>

namespace kythira {

/// Command flags, as `COMMAND INFO` names them.
namespace redis_command_flag {
inline constexpr std::uint32_t write = 1U << 0U;
inline constexpr std::uint32_t readonly = 1U << 1U;
inline constexpr std::uint32_t denyoom = 1U << 2U;
inline constexpr std::uint32_t admin = 1U << 3U;
inline constexpr std::uint32_t noscript = 1U << 4U;
inline constexpr std::uint32_t loading = 1U << 5U;
inline constexpr std::uint32_t stale = 1U << 6U;
inline constexpr std::uint32_t skip_slowlog = 1U << 7U;
inline constexpr std::uint32_t fast = 1U << 8U;
inline constexpr std::uint32_t no_auth = 1U << 9U;
inline constexpr std::uint32_t movablekeys = 1U << 10U;
inline constexpr std::uint32_t allow_busy = 1U << 11U;
inline constexpr std::uint32_t no_multi = 1U << 12U;
inline constexpr std::uint32_t blocking = 1U << 13U;
}  // namespace redis_command_flag

/// ACL categories, as `ACL CAT` names them (without the `@`).
namespace redis_acl_category {
inline constexpr std::uint32_t keyspace = 1U << 0U;
inline constexpr std::uint32_t read = 1U << 1U;
inline constexpr std::uint32_t write = 1U << 2U;
inline constexpr std::uint32_t set = 1U << 3U;
inline constexpr std::uint32_t list = 1U << 4U;
inline constexpr std::uint32_t hash = 1U << 5U;
inline constexpr std::uint32_t string = 1U << 6U;
inline constexpr std::uint32_t admin = 1U << 7U;
inline constexpr std::uint32_t fast = 1U << 8U;
inline constexpr std::uint32_t slow = 1U << 9U;
inline constexpr std::uint32_t blocking = 1U << 10U;
inline constexpr std::uint32_t dangerous = 1U << 11U;
inline constexpr std::uint32_t connection = 1U << 12U;
inline constexpr std::uint32_t transaction = 1U << 13U;
}  // namespace redis_acl_category

/// How a command reaches data (the design's command tables).
enum class redis_command_path : std::uint8_t {
    read,       ///< R: served from applied state
    write,      ///< W: one log entry on one group
    multi_key,  ///< M: one entry if single-group, else a transaction or -CROSSSLOT
    fan_out,    ///< F: a front-end fan-out across groups
    admin,      ///< A: an admin operation
    local,      ///< answered by the gateway alone (connection, server)
};

/// Whether this build accepts the command yet. A planned command answers
/// `-ERR unknown command` exactly as an unregistered one does
/// (Requirement 1.1); it is registered early only so that its id is fixed.
enum class redis_command_status : std::uint8_t {
    shipped,
    planned,
};

/// One registry entry. `arity` follows Redis: positive is exact, negative
/// is a minimum, both counting the command name. `first_key`, `last_key`
/// and `step` are the legacy key triple (`last_key` -1 is "to the end"; all
/// zero when the command takes no keys or finds them with `movablekeys`).
struct redis_command_info {
    std::string_view name;  ///< upper case, as matched
    std::uint16_t id;
    std::int16_t arity;
    std::uint32_t flags;
    std::uint32_t acl_categories;
    std::int8_t first_key;
    std::int8_t last_key;
    std::int8_t step;
    redis_command_path path;
    redis_command_status status;
    std::string_view group;  ///< `COMMAND DOCS` group: string, generic, hash, ...
    std::string_view since;  ///< the Redis release that introduced it
    std::uint8_t task;       ///< the redis-general-data-types task that ships it (0: earlier spec)
};

/// A command removed after its id was issued. Its id stays taken, so an old
/// log record naming it is recognised and refused rather than applied as
/// another command.
struct redis_retired_command {
    std::string_view name;
    std::uint16_t id;
};

}  // namespace kythira
