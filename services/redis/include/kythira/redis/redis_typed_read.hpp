// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_typed_read.hpp
/// The one entry point for a read of one key, whatever it holds
/// (.kiro/specs/redis-general-data-types/ tasks 7 and 8). It answers
/// `TYPE`, `OBJECT ENCODING`, `EXISTS` and the expiry reads for every type,
/// sends each family's reads to that family's evaluator, and answers
/// `WRONGTYPE` for a read of the wrong type (Requirement 9.1). Absent keys
/// read as empty collections, as in Redis.

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_hash_exec.hpp>
#include <kythira/redis/redis_list_exec.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_set_exec.hpp>
#include <kythira/redis/redis_string_read.hpp>
#include <kythira/redis/redis_value.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace kythira {

namespace redis_typed_read_detail {

/// The type whose family reads `id`, if a collection family does.
[[nodiscard]] inline auto collection_of(redis_command_id id) noexcept
    -> std::optional<redis_value_type> {
    if (redis_hash_detail::is_hash_read(id)) {
        return redis_value_type::hash;
    }
    if (redis_set_detail::is_set_read(id)) {
        return redis_value_type::set;
    }
    if (redis_list_detail::is_list_read(id)) {
        return redis_value_type::list;
    }
    return std::nullopt;
}

/// A collection family's read of an absent key (`nullopt`: not one).
[[nodiscard]] inline auto absent_collection_read(redis_command_id id,
                                                 std::span<const std::string> args)
    -> std::optional<redis_reply> {
    switch (collection_of(id).value_or(redis_value_type::string)) {
        case redis_value_type::hash:
            return evaluate_redis_hash_read(nullptr, id, args);
        case redis_value_type::set:
            return evaluate_redis_set_read(nullptr, id, args);
        case redis_value_type::list:
            return evaluate_redis_list_read(nullptr, id, args);
        default:
            return std::nullopt;
    }
}

}  // namespace redis_typed_read_detail

/// The read of `id` on `entry` (null when absent) at `now_ms`, for every
/// value type. `nullopt` for a command id no read family answers.
template<typename Entry>
auto evaluate_redis_read(const Entry* entry, redis_command_id id, std::span<const std::string> args,
                         std::uint64_t now_ms) -> std::optional<redis_reply> {
    using namespace redis_typed_read_detail;
    const bool present =
        entry != nullptr && (entry->_expire_at_ms == 0 || entry->_expire_at_ms > now_ms);
    const auto type = present ? redis_entry_type(*entry) : redis_value_type::string;
    const auto wrongtype = [] { return redis_reply::error(std::string(k_redis_wrongtype)); };
    if (!present) {
        if (auto r = absent_collection_read(id, args)) {
            return r;
        }
        return evaluate_redis_string_read<Entry>(nullptr, id, args, now_ms);
    }
    if (type == redis_value_type::string) {
        if (collection_of(id)) {
            return wrongtype();
        }
        return evaluate_redis_string_read(entry, id, args, now_ms);
    }
    switch (id) {
        case redis_command_id::exists:
            return redis_reply::integer(1);
        case redis_command_id::type:
            return redis_reply::simple(std::string(redis_value_type_name(type)));
        case redis_command_id::ttl:
        case redis_command_id::pttl:
        case redis_command_id::expiretime:
        case redis_command_id::pexpiretime:
            return redis_expiry_read_reply(id, true, entry->_expire_at_ms, now_ms);
        default:
            break;
    }
    if constexpr (requires {
                      entry->_hash;
                      entry->_set;
                      entry->_list;
                  }) {
        if (type == redis_value_type::hash) {
            if (id == redis_command_id::object) {
                return redis_reply::bulk(redis_hash_encoding(*entry->_hash));
            }
            if (collection_of(id) == redis_value_type::hash) {
                return evaluate_redis_hash_read(entry->_hash.get(), id, args);
            }
        }
        if (type == redis_value_type::set) {
            if (id == redis_command_id::object) {
                return redis_reply::bulk(redis_set_encoding(*entry->_set));
            }
            if (collection_of(id) == redis_value_type::set) {
                return evaluate_redis_set_read(entry->_set.get(), id, args);
            }
        }
        if (type == redis_value_type::list) {
            if (id == redis_command_id::object) {
                return redis_reply::bulk(redis_list_encoding(*entry->_list));
            }
            if (collection_of(id) == redis_value_type::list) {
                return evaluate_redis_list_read(entry->_list.get(), id, args);
            }
        }
    }
    // A string read (GET, STRLEN, GETRANGE, ...) or another type's read on
    // this key; an id no family reads stays unanswered.
    if (collection_of(id) || evaluate_redis_string_read<Entry>(nullptr, id, args, now_ms)) {
        return wrongtype();
    }
    return std::nullopt;
}

/// For a front end over any store: the reply to a read of `entry` when it
/// is a live collection (`nullopt` when absent, expired or a string, which
/// the string path answers). Entries without a type (the build cache's
/// manifests) are always strings.
template<typename Entry>
auto redis_collection_read(const Entry* entry, redis_command_id id,
                           std::span<const std::string> args, std::uint64_t now_ms)
    -> std::optional<redis_reply> {
    if constexpr (requires { entry->_type; }) {
        if (entry != nullptr && redis_entry_type(*entry) != redis_value_type::string &&
            (entry->_expire_at_ms == 0 || entry->_expire_at_ms > now_ms)) {
            return evaluate_redis_read(entry, id, args, now_ms);
        }
    }
    return std::nullopt;
}

}  // namespace kythira
