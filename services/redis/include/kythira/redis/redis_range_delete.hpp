// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_range_delete.hpp
/// How every store applies a `range_delete` record (.kiro/specs/
/// redis-general-data-types/ task 13, Requirement 8.1-8.3, design
/// Component 7): `KYTHIRA.DELPREFIX`, `FLUSHDB` and `FLUSHALL` propose one per
/// group, bounded to the part of the range the group owns and to
/// `_max_keys` keys, and propose again from the last key while an entry
/// comes back full.
///
/// The apply result is an encoded `redis_reply`: an array of the number of
/// keys removed and the last key removed (nil when none was). Keys are
/// removed in key order whatever their type or deadline, so a key that had
/// expired and not yet been swept is removed, and counted, too.

#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_value.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

/// Applies `c` through `scan(lo, hi, f)` (a store's `scan_keys`) and
/// `erase(key)`. The keys are collected first so the walk never runs over
/// a map it is changing.
template<typename Scan, typename Erase>
auto apply_redis_range_delete(const redis_kv_range_delete_command& c, Scan&& scan, Erase&& erase)
    -> std::vector<std::byte> {
    std::vector<std::string> keys;
    const std::optional<std::string> hi =
        c._hi.empty() ? std::nullopt : std::optional<std::string>(c._hi);
    if (c._max_keys > 0) {
        scan(c._lo, hi, [&](const std::string& key, std::uint64_t, redis_value_type) {
            keys.push_back(key);
            return keys.size() < c._max_keys;
        });
    }
    for (const auto& key : keys) {
        (void)erase(key);
    }
    return encode_redis_reply(
        redis_reply::array({redis_reply::integer(static_cast<std::int64_t>(keys.size())),
                            keys.empty() ? redis_reply::null() : redis_reply::bulk(keys.back())}));
}

}  // namespace kythira
