// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_string_read.hpp
/// Reads of one string key as a pure function of the stored entry
/// (.kiro/specs/redis-general-data-types/ task 3, design Component 2).
///
/// `evaluate_redis_string_read` decides a read's reply on the node that
/// holds the data, from the entry alone and the serving node's clock, and
/// returns a `redis_reply` the gateway renders per connection. A front end
/// without data (task 16) asks a data node to run it and gets the encoded
/// reply back; a co-located front end runs it in-process under the group's
/// lock. Argument checks that need no data (integer parsing, arity) stay on
/// the front end, so arguments arrive valid.
///
/// | command id   | arguments after the key | reply                        |
/// |--------------|-------------------------|------------------------------|
/// | `GET`        |                         | bulk or nil                  |
/// | `STRLEN`     |                         | integer                      |
/// | `GETRANGE`   | start end               | bulk (Redis 7 clamping)      |
/// | `EXISTS`     |                         | 1 or 0                       |
/// | `TTL`        |                         | seconds, -1, or -2           |
/// | `TYPE`       |                         | `string` or `none`           |
/// | `OBJECT`     | (`ENCODING`)            | `int`, `embstr`, `raw`, nil  |

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira {

/// The read of `id` on a string entry. `entry` is the stored entry or null;
/// it must have `_value` (contiguous bytes) and `_expire_at_ms` (0: never).
/// `args` are the arguments after the key. Returns `nullopt` for a command
/// this file does not read.
template<typename Entry>
auto evaluate_redis_string_read(const Entry* entry, redis_command_id id,
                                std::span<const std::string> args, std::uint64_t now_ms)
    -> std::optional<redis_reply> {
    const bool present =
        entry != nullptr && (entry->_expire_at_ms == 0 || entry->_expire_at_ms > now_ms);
    const auto bytes = [&]() -> std::string_view {
        return {reinterpret_cast<const char*>(entry->_value.data()), entry->_value.size()};
    };
    switch (id) {
        case redis_command_id::get:
            return present ? redis_reply::bulk(std::string(bytes())) : redis_reply::null();
        case redis_command_id::strlen:
            return redis_reply::integer(present ? static_cast<std::int64_t>(entry->_value.size())
                                                : 0);
        case redis_command_id::exists:
            return redis_reply::integer(present ? 1 : 0);
        case redis_command_id::type:
            return redis_reply::simple(present ? "string" : "none");
        case redis_command_id::ttl: {
            if (!present) {
                return redis_reply::integer(-2);
            }
            if (entry->_expire_at_ms == 0) {
                return redis_reply::integer(-1);
            }
            // Redis rounds the remaining milliseconds to the nearest second.
            const auto left = entry->_expire_at_ms - now_ms;
            return redis_reply::integer(static_cast<std::int64_t>((left + 500) / 1000));
        }
        case redis_command_id::object: {
            if (!present) {
                return redis_reply::null();
            }
            // D16: the encoding Redis would choose for these bytes.
            const auto size = entry->_value.size();
            if (size <= 20 && redis_string_detail::parse_int64(bytes())) {
                return redis_reply::bulk("int");
            }
            return redis_reply::bulk(size <= 44 ? "embstr" : "raw");
        }
        case redis_command_id::getrange: {
            if (args.size() != 2) {
                return redis_reply::error("ERR syntax error");
            }
            const auto start_arg = redis_string_detail::parse_int64(args[0]);
            const auto end_arg = redis_string_detail::parse_int64(args[1]);
            if (!start_arg || !end_arg) {
                return redis_reply::error("ERR value is not an integer or out of range");
            }
            auto start = *start_arg;
            auto end = *end_arg;
            if (!present || (start < 0 && end < 0 && start > end)) {
                return redis_reply::bulk("");
            }
            const auto len = static_cast<std::int64_t>(entry->_value.size());
            if (start < 0) {
                start = std::max<std::int64_t>(0, len + start);
            }
            if (end < 0) {
                end = std::max<std::int64_t>(0, len + end);
            }
            if (end >= len) {
                end = len - 1;
            }
            if (len == 0 || start > end) {
                return redis_reply::bulk("");
            }
            return redis_reply::bulk(std::string(bytes().substr(
                static_cast<std::size_t>(start), static_cast<std::size_t>(end - start + 1))));
        }
        default:
            return std::nullopt;
    }
}

}  // namespace kythira
