// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_scan.hpp
/// The pieces of the SCAN family that do not need a cluster
/// (.kiro/specs/redis-general-data-types/ task 12, Requirement 7, design
/// Component 7):
///
/// - `redis_glob_match`: Redis's glob (`*`, `?`, `[...]`, `\`), as
///   `MATCH` and `KEYS` use it;
/// - `redis_glob_literal_prefix` and `redis_prefix_successor`: the key range
///   a pattern's literal prefix narrows a walk to;
/// - the cursor's layout: `(issuer index : 14) | (cursor id : 50)`;
/// - `redis_scan_page`, one bounded page of a group's keys, and its encoding
///   on the internal hop (`KYTHIRA.DATA PAGE`).

#include <kythira/redis/redis_value.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira {

namespace redis_scan_detail {

inline auto lower(unsigned char c) -> unsigned char {
    return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

/// Whether the token at `p` (one character, `?`, an escape or a class)
/// matches `c`; `p` is moved past the token.
inline auto token_matches(std::string_view pattern, std::size_t& p, unsigned char c, bool nocase)
    -> bool {
    const auto fold = [nocase](unsigned char x) { return nocase ? lower(x) : x; };
    const auto at = [&](std::size_t i) { return static_cast<unsigned char>(pattern[i]); };
    if (pattern[p] == '?') {
        ++p;
        return true;
    }
    if (pattern[p] == '\\' && p + 1 < pattern.size()) {
        const bool same = fold(at(p + 1)) == fold(c);
        p += 2;
        return same;
    }
    if (pattern[p] != '[') {
        const bool same = fold(at(p)) == fold(c);
        ++p;
        return same;
    }
    // A class, as Redis reads it: `^` negates, `\` escapes, `a-z` is a
    // range in either order, and an unterminated class runs to the end.
    ++p;
    const bool negate = p < pattern.size() && pattern[p] == '^';
    if (negate) {
        ++p;
    }
    bool matched = false;
    while (p < pattern.size() && pattern[p] != ']') {
        if (pattern[p] == '\\' && p + 1 < pattern.size()) {
            matched = matched || fold(at(p + 1)) == fold(c);
            p += 2;
        } else if (p + 2 < pattern.size() && pattern[p + 1] == '-' && pattern[p + 2] != ']') {
            auto lo = fold(at(p));
            auto hi = fold(at(p + 2));
            if (lo > hi) {
                std::swap(lo, hi);
            }
            matched = matched || (fold(c) >= lo && fold(c) <= hi);
            p += 3;
        } else {
            matched = matched || fold(at(p)) == fold(c);
            ++p;
        }
    }
    if (p < pattern.size()) {
        ++p;  // the closing ']'
    }
    return negate ? !matched : matched;
}

}  // namespace redis_scan_detail

/// Whether `text` matches the glob `pattern` as Redis's `stringmatchlen`
/// decides it. Linear in practice: on a mismatch only the last `*` is
/// retried, which is enough because every other token matches exactly one
/// byte, so a pattern of many stars cannot make a match exponential.
[[nodiscard]] inline auto redis_glob_match(std::string_view pattern, std::string_view text,
                                           bool nocase = false) -> bool {
    std::size_t p = 0;
    std::size_t t = 0;
    std::optional<std::size_t> star_p;
    std::size_t star_t = 0;
    while (t < text.size()) {
        if (p < pattern.size() && pattern[p] == '*') {
            while (p < pattern.size() && pattern[p] == '*') {
                ++p;
            }
            if (p == pattern.size()) {
                return true;
            }
            star_p = p;
            star_t = t;
            continue;
        }
        if (p < pattern.size()) {
            auto next = p;
            if (redis_scan_detail::token_matches(pattern, next, static_cast<unsigned char>(text[t]),
                                                 nocase)) {
                p = next;
                ++t;
                continue;
            }
        }
        if (!star_p) {
            return false;
        }
        p = *star_p;
        t = ++star_t;
    }
    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

/// The bytes every key matching `pattern` starts with: the pattern up to
/// its first `*`, `?` or `[`, escapes resolved.
[[nodiscard]] inline auto redis_glob_literal_prefix(std::string_view pattern) -> std::string {
    std::string out;
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '*' || c == '?' || c == '[') {
            break;
        }
        if (c == '\\') {
            if (i + 1 == pattern.size()) {
                break;
            }
            out.push_back(pattern[++i]);
        } else {
            out.push_back(c);
        }
    }
    return out;
}

/// The smallest key greater than every key starting with `prefix`, or
/// nothing when there is none (an empty prefix, or all `0xFF`).
[[nodiscard]] inline auto redis_prefix_successor(std::string prefix) -> std::optional<std::string> {
    while (!prefix.empty() && static_cast<unsigned char>(prefix.back()) == 0xFFU) {
        prefix.pop_back();
    }
    if (prefix.empty()) {
        return std::nullopt;
    }
    prefix.back() = static_cast<char>(static_cast<unsigned char>(prefix.back()) + 1U);
    return prefix;
}

/// A cursor: the issuing front end's index (1 to 16383) in the top 14 bits,
/// its id there (1 to 2^50 - 1) below. `0` starts and ends an iteration.
inline constexpr unsigned k_redis_cursor_id_bits = 50;
inline constexpr std::uint64_t k_redis_cursor_id_mask = (std::uint64_t{1} << 50) - 1;
inline constexpr std::uint16_t k_redis_cursor_max_index = (1U << 14U) - 1U;

[[nodiscard]] constexpr auto redis_cursor_make(std::uint16_t index, std::uint64_t id)
    -> std::uint64_t {
    return (static_cast<std::uint64_t>(index) << k_redis_cursor_id_bits) |
           (id & k_redis_cursor_id_mask);
}
[[nodiscard]] constexpr auto redis_cursor_index(std::uint64_t cursor) -> std::uint16_t {
    return static_cast<std::uint16_t>(cursor >> k_redis_cursor_id_bits);
}
[[nodiscard]] constexpr auto redis_cursor_id(std::uint64_t cursor) -> std::uint64_t {
    return cursor & k_redis_cursor_id_mask;
}

/// What a page does with a key: `hidden` (outside the user's ACL scopes:
/// never returned and never counted against `COUNT`), `filtered` (fails
/// `MATCH` or `TYPE`: counted, as Redis counts it, but not returned) or
/// `kept`.
enum class redis_scan_verdict : std::uint8_t {
    hidden,
    filtered,
    kept
};

/// Hidden keys one page passes over before it ends early, so a call by a
/// user who may read few keys of a large keyspace stays bounded.
inline constexpr std::size_t k_redis_scan_hidden_per_page = 10000;

/// What a page keeps: keys matching `pattern` (empty: every key), of type
/// `type` (empty: any; compared as Redis 7.2 does, so an unknown name
/// keeps nothing).
struct redis_scan_filter {
    std::string _pattern;
    std::string _type;

    [[nodiscard]] auto keeps(std::string_view key, redis_value_type type) const -> bool {
        if (!_type.empty()) {
            const auto name = redis_value_type_name(type);
            if (name.size() != _type.size()) {
                return false;
            }
            for (std::size_t i = 0; i < name.size(); ++i) {
                if (redis_scan_detail::lower(static_cast<unsigned char>(name[i])) !=
                    redis_scan_detail::lower(static_cast<unsigned char>(_type[i]))) {
                    return false;
                }
            }
        }
        return _pattern.empty() || _pattern == "*" || redis_glob_match(_pattern, key);
    }
};

/// One page of one group's keys in `[from, to)`: the kept keys, the last
/// key examined (the walk resumes just after it), whether the group has no
/// more keys in the range, where the group's range ends (nothing: the end
/// of the keyspace), and its approximate key count (for `RANDOMKEY`).
struct redis_scan_page {
    std::vector<std::string> _keys;
    /// Live keys examined, kept or filtered (the call's `COUNT` budget);
    /// hidden keys are not counted.
    std::uint64_t _examined = 0;
    std::optional<std::string> _last;
    bool _exhausted = false;
    std::optional<std::string> _range_end;
    std::uint64_t _approximate_keys = 0;
    /// The group's keys with a deadline (`INFO keyspace`'s `expires=`).
    std::uint64_t _expiring_keys = 0;
};

/// The bucket `KYTHIRA.USAGE` counts `key` in (Requirement 8.4): the key up
/// to and including its `depth`-th `delim`, or the whole key when it has
/// fewer. An empty delimiter or a depth of 0 puts every key in one bucket,
/// the empty string.
[[nodiscard]] inline auto redis_usage_bucket(std::string_view key, std::size_t depth,
                                             std::string_view delim) -> std::string {
    if (depth == 0 || delim.empty()) {
        return {};
    }
    std::size_t at = 0;
    for (std::size_t seen = 0; seen < depth; ++seen) {
        const auto found = key.find(delim, at);
        if (found == std::string_view::npos) {
            return std::string(key);
        }
        at = found + delim.size();
    }
    return std::string(key.substr(0, at));
}

/// One page of a group's usage: keys and bytes per bucket, those past the
/// bucket limit in `_other`, and where the walk stopped, as for a SCAN page.
struct redis_usage_page {
    struct tally {
        std::uint64_t _keys = 0;
        std::uint64_t _bytes = 0;
    };
    std::map<std::string, tally> _buckets;
    tally _other;
    std::optional<std::string> _last;
    bool _exhausted = false;
    std::optional<std::string> _range_end;

    /// Adds to `bucket`, or to `_other` once `max_buckets` exist.
    auto add(const std::string& bucket, std::uint64_t keys, std::uint64_t bytes,
             std::size_t max_buckets) -> void {
        auto it = _buckets.find(bucket);
        if (it == _buckets.end()) {
            if (_buckets.size() >= max_buckets) {
                _other._keys += keys;
                _other._bytes += bytes;
                return;
            }
            it = _buckets.emplace(bucket, tally{}).first;
        }
        it->second._keys += keys;
        it->second._bytes += bytes;
    }
};

namespace redis_scan_detail {

inline auto put_u64(std::string& out, std::uint64_t v) -> void {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((v >> shift) & 0xFFU));
    }
}
inline auto put_text(std::string& out, std::string_view s) -> void {
    put_u64(out, s.size());
    out.append(s);
}

class cursor {
public:
    explicit cursor(std::string_view in) : _in(in) {}
    auto u8() -> std::uint8_t { return static_cast<std::uint8_t>(take(1)[0]); }
    auto u64() -> std::uint64_t {
        std::uint64_t v = 0;
        for (char c : take(8)) {
            v = (v << 8) | static_cast<unsigned char>(c);
        }
        return v;
    }
    auto text() -> std::string {
        const auto n = u64();
        return std::string(take(n));
    }
    [[nodiscard]] auto empty() const -> bool { return _in.empty(); }

private:
    auto take(std::uint64_t n) -> std::string_view {
        if (_in.size() < n) {
            throw std::runtime_error("truncated KYTHIRA.DATA reply");
        }
        auto out = _in.substr(0, n);
        _in.remove_prefix(n);
        return out;
    }
    std::string_view _in;
};

}  // namespace redis_scan_detail

/// The `KYTHIRA.DATA PAGE` reply body: flags (bit 0 exhausted, bit 1 a
/// last key, bit 2 a range end), the approximate count, the expiring
/// count, the examined count,
/// the last key and
/// range end when present, the key count and the keys.
[[nodiscard]] inline auto encode_redis_scan_page(const redis_scan_page& p) -> std::string {
    using namespace redis_scan_detail;
    std::string out;
    out.push_back(
        static_cast<char>((p._exhausted ? 1 : 0) | (p._last ? 2 : 0) | (p._range_end ? 4 : 0)));
    put_u64(out, p._approximate_keys);
    put_u64(out, p._expiring_keys);
    put_u64(out, p._examined);
    if (p._last) {
        put_text(out, *p._last);
    }
    if (p._range_end) {
        put_text(out, *p._range_end);
    }
    put_u64(out, p._keys.size());
    for (const auto& k : p._keys) {
        put_text(out, k);
    }
    return out;
}

[[nodiscard]] inline auto decode_redis_scan_page(std::string_view in) -> redis_scan_page {
    redis_scan_detail::cursor c(in);
    redis_scan_page p;
    const auto flags = c.u8();
    p._exhausted = (flags & 1U) != 0;
    p._approximate_keys = c.u64();
    p._expiring_keys = c.u64();
    p._examined = c.u64();
    if ((flags & 2U) != 0) {
        p._last = c.text();
    }
    if ((flags & 4U) != 0) {
        p._range_end = c.text();
    }
    const auto n = c.u64();
    if (n > in.size()) {
        throw std::runtime_error("KYTHIRA.DATA PAGE reply names more keys than it holds");
    }
    p._keys.reserve(n);
    for (std::uint64_t i = 0; i < n; ++i) {
        p._keys.push_back(c.text());
    }
    if (!c.empty()) {
        throw std::runtime_error("trailing bytes after a KYTHIRA.DATA PAGE reply");
    }
    return p;
}

/// The `KYTHIRA.DATA USAGE` reply body: flags (bit 0 exhausted, bit 1 a
/// last key, bit 2 a range end), the other tally, the last key and range
/// end when present, the bucket count, and each bucket with its tally.
[[nodiscard]] inline auto encode_redis_usage_page(const redis_usage_page& p) -> std::string {
    using namespace redis_scan_detail;
    std::string out;
    out.push_back(
        static_cast<char>((p._exhausted ? 1 : 0) | (p._last ? 2 : 0) | (p._range_end ? 4 : 0)));
    put_u64(out, p._other._keys);
    put_u64(out, p._other._bytes);
    if (p._last) {
        put_text(out, *p._last);
    }
    if (p._range_end) {
        put_text(out, *p._range_end);
    }
    put_u64(out, p._buckets.size());
    for (const auto& [bucket, t] : p._buckets) {
        put_text(out, bucket);
        put_u64(out, t._keys);
        put_u64(out, t._bytes);
    }
    return out;
}

[[nodiscard]] inline auto decode_redis_usage_page(std::string_view in) -> redis_usage_page {
    redis_scan_detail::cursor c(in);
    redis_usage_page p;
    const auto flags = c.u8();
    p._exhausted = (flags & 1U) != 0;
    p._other._keys = c.u64();
    p._other._bytes = c.u64();
    if ((flags & 2U) != 0) {
        p._last = c.text();
    }
    if ((flags & 4U) != 0) {
        p._range_end = c.text();
    }
    const auto n = c.u64();
    if (n > in.size()) {
        throw std::runtime_error("KYTHIRA.DATA USAGE reply names more buckets than it holds");
    }
    for (std::uint64_t i = 0; i < n; ++i) {
        auto bucket = c.text();
        redis_usage_page::tally t;
        t._keys = c.u64();
        t._bytes = c.u64();
        p._buckets.insert_or_assign(std::move(bucket), t);
    }
    if (!c.empty()) {
        throw std::runtime_error("trailing bytes after a KYTHIRA.DATA USAGE reply");
    }
    return p;
}

}  // namespace kythira
