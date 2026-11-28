// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_expiry_exec.hpp
/// The expiry family as `exec` records apply them
/// (.kiro/specs/redis-general-data-types/ task 4, Requirements 4.1-4.4).
///
/// `EXPIRE`, `PEXPIRE` and `EXPIREAT` arrive as `PEXPIREAT` with an absolute
/// deadline in milliseconds: the front end checks the options and the
/// integer, scales seconds and adds its clock to a relative time, refusing
/// an overflow as Redis does. The decision (does the key exist, does the
/// condition hold, is the deadline already past) is made here, at the
/// entry's command time `t`, so every replica reaches the same answer:
///
/// | command id   | arguments after the name             | reply  |
/// |--------------|--------------------------------------|--------|
/// | `PEXPIREAT`  | key deadline-ms [NX\|XX\|GT\|LT]     | 1 or 0 |
/// | `PERSIST`    | key                                  | 1 or 0 |
///
/// The deadline is signed: `EXPIRE k -5` is legal and means "now minus five
/// seconds". A deadline at or before `t` deletes the key and answers 1,
/// after the condition has passed, as Redis's `checkAlreadyExpired` does.
/// `GT` treats a key without a deadline as never expiring, so it never
/// passes there; `LT` always passes there.
///
/// Under the immutable-value rule (Requirement 5.2) a key outside the
/// user's mutable prefixes keeps its deadline: a command that passes its
/// condition and would change the deadline answers `ERR value conflict for
/// an existing key` instead. One that fails its condition still answers 0.
///
/// The leader's expiry sweep names each key with the deadline it saw and
/// deletes only on a match, so a sweep built before an `EXPIRE` or
/// `PERSIST` applied leaves the key alone (redis_kv_commands.hpp).

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace kythira {

namespace redis_expiry_detail {

/// The `NX|XX|GT|LT` options of the expiry family as bits.
enum redis_expire_flag : unsigned {
    expire_nx = 1U << 0U,
    expire_xx = 1U << 1U,
    expire_gt = 1U << 2U,
    expire_lt = 1U << 3U,
};

/// Parses one option; `nullopt` when it is none of the four.
[[nodiscard]] inline auto parse_expire_flag(std::string_view text) noexcept
    -> std::optional<unsigned> {
    const auto is = [&](std::string_view name) {
        return std::ranges::equal(text, name,
                                  [](char c, char n) { return static_cast<char>(c & ~0x20) == n; });
    };
    if (is("NX")) {
        return expire_nx;
    }
    if (is("XX")) {
        return expire_xx;
    }
    if (is("GT")) {
        return expire_gt;
    }
    if (is("LT")) {
        return expire_lt;
    }
    return std::nullopt;
}

/// The error Redis gives for a combination it refuses, or empty.
[[nodiscard]] inline auto expire_flags_conflict(unsigned flags) -> std::string_view {
    if ((flags & expire_nx) != 0 && (flags & (expire_xx | expire_gt | expire_lt)) != 0) {
        return "ERR NX and XX, GT or LT options at the same time are not compatible";
    }
    if ((flags & expire_gt) != 0 && (flags & expire_lt) != 0) {
        return "ERR GT and LT options at the same time are not compatible";
    }
    return {};
}

/// Whether a new deadline `when` passes `flags` against the key's current
/// deadline (`current` 0: none), as Redis's `expireGenericCommand` decides.
[[nodiscard]] inline auto expire_condition_holds(unsigned flags, std::int64_t when,
                                                 std::uint64_t current) noexcept -> bool {
    const bool has = current != 0;
    // Deadlines above INT64_MAX never reach a store; clamp for the compare.
    constexpr auto k_max = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    const auto cur = static_cast<std::int64_t>(std::min(current, k_max));
    if ((flags & expire_nx) != 0 && has) {
        return false;
    }
    if ((flags & expire_xx) != 0 && !has) {
        return false;
    }
    if ((flags & expire_gt) != 0 && (!has || when <= cur)) {
        return false;
    }
    if ((flags & expire_lt) != 0 && has && when >= cur) {
        return false;
    }
    return true;
}

}  // namespace redis_expiry_detail

/// Applies one expiry-family `exec` record at command time `t`. `Store` is
/// the same interface `apply_redis_string_exec` takes. Returns `nullopt`
/// for a command id this file does not apply.
template<typename Store>
auto apply_redis_expiry_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_expiry_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    if (id != redis_command_id::pexpireat && id != redis_command_id::persist) {
        return std::nullopt;
    }
    const auto& a = c._args;
    const auto syntax = [] {
        return redis_reply::error(std::string(redis_string_detail::k_syntax));
    };
    if (a.empty()) {
        return syntax();
    }
    const std::string& key = a[0];
    auto live = store.find(key);
    if (live && live->_expire_at_ms != 0 && live->_expire_at_ms <= t) {
        live = nullptr;
    }
    const bool may_mutate = redis_string_detail::may_mutate_key(c, 0);
    const auto conflict = [] {
        return redis_reply::error(std::string(redis_string_detail::k_conflict));
    };

    if (id == redis_command_id::persist) {
        if (a.size() != 1) {
            return syntax();
        }
        if (!live || live->_expire_at_ms == 0) {
            return redis_reply::integer(0);
        }
        if (!may_mutate) {
            return conflict();
        }
        redis_store_put_copy(store, key, *live, 0);
        return redis_reply::integer(1);
    }

    if (a.size() < 2) {
        return syntax();
    }
    const auto when = redis_string_detail::parse_int64(a[1]);
    if (!when) {
        return syntax();
    }
    unsigned flags = 0;
    for (std::size_t i = 2; i < a.size(); ++i) {
        const auto f = parse_expire_flag(a[i]);
        if (!f) {
            return syntax();
        }
        flags |= *f;
    }
    if (!expire_flags_conflict(flags).empty()) {
        return syntax();
    }
    if (!live || !expire_condition_holds(flags, *when, live->_expire_at_ms)) {
        return redis_reply::integer(0);
    }
    if (!may_mutate) {
        return conflict();
    }
    if (*when <= 0 || static_cast<std::uint64_t>(*when) <= t) {
        (void)store.erase(key);
    } else {
        redis_store_put_copy(store, key, *live, static_cast<std::uint64_t>(*when));
    }
    return redis_reply::integer(1);
}

}  // namespace kythira
