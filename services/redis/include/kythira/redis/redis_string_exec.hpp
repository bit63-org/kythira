// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_string_exec.hpp
/// The tier 1 string commands as `exec` records apply them
/// (.kiro/specs/redis-general-data-types/ task 3, design Components 1 and 2).
///
/// A write that depends on the current value (`INCR`, `SET NX`, `APPEND`,
/// ...) is decided in `apply()`, against the state every replica has at that
/// point in the log, at the entry's command time `t`, and its reply comes
/// back from `apply()` as an encoded `redis_reply`. The front end only
/// validates syntax and writes the record's arguments in a normal form, so
/// this file never sees a relative time or an alias:
///
/// | command id     | arguments after the name                         | reply           |
/// |----------------|--------------------------------------------------|-----------------|
/// | `SET`          | key value [NX\|XX] [GET] [PXAT ms\|KEEPTTL]      | OK, nil, or old |
/// | `SETNX`        | key value                                        | 1 or 0          |
/// | `INCRBY`       | key delta (INCR, DECR and DECRBY normalised)     | new integer     |
/// | `INCRBYFLOAT`  | key increment                                    | new value       |
/// | `GETDEL`       | key                                              | old or nil      |
/// | `GETEX`        | key [PXAT ms\|PERSIST]                           | value or nil    |
/// | `APPEND`       | key value max-bytes                              | new length      |
/// | `SETRANGE`     | key offset value max-bytes                       | new length      |
///
/// `SET ... EX|PX|EXAT`, `PSETEX` and `GETSET` arrive as `SET` with `PXAT` or
/// `GET`; `GETEX EX|PX|EXAT` as `PXAT`. A `PXAT` at or before `t` deletes the
/// key, as Redis does for a deadline already past.
///
/// `max-bytes` is the front end's configured value limit, carried in the
/// record so every replica refuses the same oversized result
/// (Requirement 3.8).
///
/// The immutable-value rule (redis-compatible-kv Requirement 11, D11): with
/// the record's `immutable_rule` policy bit set and the key's bit clear in
/// the mutable-key bitmap, a command that would change the bytes of a live
/// value answers `ERR value conflict for an existing key` and changes
/// nothing. Creating a key, rewriting identical bytes, deleting and changing
/// a deadline are allowed, as they are for today's `SET` and `DEL`.

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_float128.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira {

/// Redis's own string limit (`proto-max-bulk-len` default): no value grows
/// past it, whatever `max-bytes` says.
inline constexpr std::size_t k_redis_max_string_bytes = 512U * 1024U * 1024U;

namespace redis_string_detail {

inline constexpr std::string_view k_not_integer = "ERR value is not an integer or out of range";
inline constexpr std::string_view k_not_float = "ERR value is not a valid float";
inline constexpr std::string_view k_overflow = "ERR increment or decrement would overflow";
inline constexpr std::string_view k_too_big =
    "ERR string exceeds maximum allowed size (proto-max-bulk-len)";
inline constexpr std::string_view k_conflict = "ERR value conflict for an existing key";
inline constexpr std::string_view k_syntax = "ERR syntax error";

/// Redis's `string2ll`: an optional `-`, then digits with no leading zero
/// (except `0` itself), no sign on zero, no spaces, fitting in int64.
[[nodiscard]] inline auto parse_int64(std::string_view s) noexcept -> std::optional<std::int64_t> {
    if (s.empty() || s.size() > 20) {
        return std::nullopt;
    }
    if (s == "0") {
        return 0;
    }
    bool negative = false;
    std::size_t i = 0;
    if (s[0] == '-') {
        negative = true;
        i = 1;
        if (s.size() == 1) {
            return std::nullopt;
        }
    }
    if (s[i] < '1' || s[i] > '9') {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return std::nullopt;
        }
        const auto d = static_cast<std::uint64_t>(s[i] - '0');
        if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) {
            return std::nullopt;
        }
        v = v * 10 + d;
    }
    constexpr auto max_pos = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (negative) {
        if (v > max_pos + 1) {
            return std::nullopt;
        }
        return v == max_pos + 1 ? std::numeric_limits<std::int64_t>::min()
                                : -static_cast<std::int64_t>(v);
    }
    if (v > max_pos) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(v);
}

/// A non-negative decimal no larger than `std::uint64_t`.
[[nodiscard]] inline auto parse_u64(std::string_view s) noexcept -> std::optional<std::uint64_t> {
    auto v = parse_int64(s);
    if (!v || *v < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(*v);
}

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    if (!s.empty()) {
        std::memcpy(out.data(), s.data(), s.size());
    }
    return out;
}

[[nodiscard]] inline auto to_string(const std::vector<std::byte>& v) -> std::string {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

[[nodiscard]] inline auto same_bytes(const std::vector<std::byte>& v, std::string_view s) -> bool {
    return v.size() == s.size() && (s.empty() || std::memcmp(v.data(), s.data(), s.size()) == 0);
}

}  // namespace redis_string_detail

/// Applies one tier 1 string `exec` record at command time `t`. `Store`
/// gives the record's group state:
///
/// - `find(key) -> std::shared_ptr<const redis_kv_value_entry>` (null when
///   absent, expired or not included);
/// - `put(key, std::vector<std::byte> value, std::uint64_t expire_at_ms)`;
/// - `erase(key) -> bool`.
///
/// Returns `nullopt` for a command id this file does not apply, so the
/// caller can try the next family.
template<typename Store>
auto apply_redis_string_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_string_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    const auto& a = c._args;
    if (a.empty()) {
        return redis_reply::error(std::string(k_syntax));
    }
    const std::string& key = a[0];

    auto live = store.find(key);
    if (live && live->_expire_at_ms != 0 && live->_expire_at_ms <= t) {
        live = nullptr;
    }
    const bool may_mutate =
        (c._policy & redis_kv_exec_policy::immutable_rule) == 0 ||
        (!c._mutable_keys.empty() && (static_cast<std::uint8_t>(c._mutable_keys[0]) & 0x01U) != 0);
    auto old_value = [&]() -> redis_reply {
        return live ? redis_reply::bulk(to_string(live->_value)) : redis_reply::null();
    };
    auto max_bytes = [&](const std::string& text) {
        auto v = parse_u64(text);
        return std::min<std::uint64_t>(v.value_or(0), k_redis_max_string_bytes);
    };

    switch (id) {
        case redis_command_id::set: {
            if (a.size() < 2) {
                return redis_reply::error(std::string(k_syntax));
            }
            bool nx = false;
            bool xx = false;
            bool get = false;
            bool keepttl = false;
            std::optional<std::uint64_t> pxat;
            for (std::size_t i = 2; i < a.size(); ++i) {
                if (a[i] == "NX") {
                    nx = true;
                } else if (a[i] == "XX") {
                    xx = true;
                } else if (a[i] == "GET") {
                    get = true;
                } else if (a[i] == "KEEPTTL") {
                    keepttl = true;
                } else if (a[i] == "PXAT" && i + 1 < a.size()) {
                    pxat = parse_u64(a[++i]);
                    if (!pxat) {
                        return redis_reply::error(std::string(k_syntax));
                    }
                } else {
                    return redis_reply::error(std::string(k_syntax));
                }
            }
            if ((nx && xx) || (keepttl && pxat)) {
                return redis_reply::error(std::string(k_syntax));
            }
            auto reply = get ? old_value() : redis_reply::simple("OK");
            if ((nx && live) || (xx && !live)) {
                return get ? reply : redis_reply::null();
            }
            if (live && !may_mutate) {
                if (!same_bytes(live->_value, a[1])) {
                    return redis_reply::error(std::string(k_conflict));
                }
                return reply;
            }
            const std::uint64_t expire = pxat ? *pxat : (keepttl && live ? live->_expire_at_ms : 0);
            if (pxat && *pxat <= t) {
                (void)store.erase(key);
            } else {
                store.put(key, to_bytes(a[1]), expire);
            }
            return reply;
        }
        case redis_command_id::setnx: {
            if (a.size() != 2) {
                return redis_reply::error(std::string(k_syntax));
            }
            if (live) {
                return redis_reply::integer(0);
            }
            store.put(key, to_bytes(a[1]), 0);
            return redis_reply::integer(1);
        }
        case redis_command_id::incrby: {
            if (a.size() != 2) {
                return redis_reply::error(std::string(k_syntax));
            }
            const auto delta = parse_int64(a[1]);
            if (!delta) {
                return redis_reply::error(std::string(k_not_integer));
            }
            std::int64_t current = 0;
            if (live) {
                auto parsed = parse_int64(to_string(live->_value));
                if (!parsed) {
                    return redis_reply::error(std::string(k_not_integer));
                }
                current = *parsed;
            }
            if ((*delta > 0 && current > std::numeric_limits<std::int64_t>::max() - *delta) ||
                (*delta < 0 && current < std::numeric_limits<std::int64_t>::min() - *delta)) {
                return redis_reply::error(std::string(k_overflow));
            }
            const auto next = current + *delta;
            if (live && !may_mutate && next != current) {
                return redis_reply::error(std::string(k_conflict));
            }
            store.put(key, to_bytes(std::to_string(next)), live ? live->_expire_at_ms : 0);
            return redis_reply::integer(next);
        }
        case redis_command_id::incrbyfloat: {
            // Binary128 on every architecture (design "Float increments", D1).
            if (a.size() != 2) {
                return redis_reply::error(std::string(k_syntax));
            }
            const auto incr = parse_redis_float128(a[1]);
            if (!incr) {
                return redis_reply::error(std::string(k_not_float));
            }
            redis_float128_native current{};
            if (live) {
                const auto parsed = parse_redis_float128(to_string(live->_value));
                if (!parsed) {
                    return redis_reply::error(std::string(k_not_float));
                }
                current = *parsed;
            }
            const redis_float128_native next = current + *incr;
            if (!is_finite_redis_float128(next)) {
                return redis_reply::error("ERR increment would produce NaN or Infinity");
            }
            auto text = format_redis_float128(next);
            if (live && !may_mutate && !same_bytes(live->_value, text)) {
                return redis_reply::error(std::string(k_conflict));
            }
            store.put(key, to_bytes(text), live ? live->_expire_at_ms : 0);
            return redis_reply::bulk(std::move(text));
        }
        case redis_command_id::getdel: {
            if (a.size() != 1) {
                return redis_reply::error(std::string(k_syntax));
            }
            auto reply = old_value();
            if (live) {
                (void)store.erase(key);
            }
            return reply;
        }
        case redis_command_id::getex: {
            auto reply = old_value();
            if (!live) {
                return reply;
            }
            if (a.size() == 1) {
                return reply;
            }
            if (a.size() == 2 && a[1] == "PERSIST") {
                if (live->_expire_at_ms != 0) {
                    store.put(key, live->_value, 0);
                }
                return reply;
            }
            if (a.size() == 3 && a[1] == "PXAT") {
                const auto pxat = parse_u64(a[2]);
                if (!pxat) {
                    return redis_reply::error(std::string(k_syntax));
                }
                if (*pxat <= t) {
                    (void)store.erase(key);
                } else {
                    store.put(key, live->_value, *pxat);
                }
                return reply;
            }
            return redis_reply::error(std::string(k_syntax));
        }
        case redis_command_id::append: {
            if (a.size() != 3) {
                return redis_reply::error(std::string(k_syntax));
            }
            const std::size_t old_len = live ? live->_value.size() : 0;
            if (old_len + a[1].size() > max_bytes(a[2])) {
                return redis_reply::error(std::string(k_too_big));
            }
            if (live && !may_mutate && !a[1].empty()) {
                return redis_reply::error(std::string(k_conflict));
            }
            if (live && a[1].empty()) {
                return redis_reply::integer(static_cast<std::int64_t>(old_len));
            }
            std::vector<std::byte> next = live ? live->_value : std::vector<std::byte>{};
            const auto tail = to_bytes(a[1]);
            next.insert(next.end(), tail.begin(), tail.end());
            const auto len = next.size();
            store.put(key, std::move(next), live ? live->_expire_at_ms : 0);
            return redis_reply::integer(static_cast<std::int64_t>(len));
        }
        case redis_command_id::setrange: {
            if (a.size() != 4) {
                return redis_reply::error(std::string(k_syntax));
            }
            const auto offset = parse_u64(a[1]);
            if (!offset) {
                return redis_reply::error("ERR offset is out of range");
            }
            const std::size_t old_len = live ? live->_value.size() : 0;
            const auto& piece = a[2];
            if (piece.empty()) {
                return redis_reply::integer(static_cast<std::int64_t>(old_len));
            }
            if (*offset + piece.size() > max_bytes(a[3])) {
                return redis_reply::error(std::string(k_too_big));
            }
            std::vector<std::byte> next = live ? live->_value : std::vector<std::byte>{};
            const auto end = static_cast<std::size_t>(*offset) + piece.size();
            if (next.size() < end) {
                next.resize(end, std::byte{0});
            }
            std::memcpy(next.data() + *offset, piece.data(), piece.size());
            if (live && !may_mutate && next != live->_value) {
                return redis_reply::error(std::string(k_conflict));
            }
            const auto len = next.size();
            store.put(key, std::move(next), live ? live->_expire_at_ms : 0);
            return redis_reply::integer(static_cast<std::int64_t>(len));
        }
        default:
            return std::nullopt;
    }
}

}  // namespace kythira
