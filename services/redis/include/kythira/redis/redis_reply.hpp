// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_reply.hpp
/// The typed reply tree (.kiro/specs/redis-general-data-types/ design
/// Component 2, task 3).
///
/// A command's reply is decided where its data is, on the node serving the
/// read or applying the entry, but its encoding depends on the connection:
/// RESP2 and RESP3 spell maps, sets, doubles, booleans, verbatim strings,
/// big numbers and nulls differently. So the data side produces a
/// `redis_reply` and the gateway renders it with `render_redis_reply` for
/// each connection's protocol version, following Redis's own downgrade
/// rules for RESP2:
///
/// | kind        | RESP3                | RESP2                          |
/// |-------------|----------------------|--------------------------------|
/// | map         | `%n` k v ...         | `*2n` k v ...                  |
/// | set         | `~n` ...             | `*n` ...                       |
/// | double      | `,<text>`            | bulk `<text>`                  |
/// | boolean     | `#t` / `#f`          | `:1` / `:0`                    |
/// | verbatim    | `=len fmt:<text>`    | bulk `<text>`                  |
/// | big number  | `(<digits>`          | bulk `<digits>`                |
/// | null        | `_`                  | `$-1` (null bulk)              |
/// | null array  | `_`                  | `*-1`                          |
///
/// A double carries its text as the command formatted it (Redis formats
/// scores, `INCRBYFLOAT` results and the like each in its own way), so
/// rendering never reformats a number.
///
/// The tree also has a canonical binary encoding, `encode_redis_reply` /
/// `decode_redis_reply`, which a data node uses to send a reply to a front
/// end on another node (task 16, `KYTHIRA.DATA READ`). The decoder never
/// allocates from an untrusted count, bounds nesting, and accepts only the
/// bytes `encode_redis_reply` would write, so two nodes can never read one
/// buffer differently.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

enum class redis_reply_kind : std::uint8_t {
    simple = 1,
    error = 2,
    integer = 3,
    bulk = 4,
    null = 5,
    array = 6,
    map = 7,
    set = 8,
    double_value = 9,
    boolean = 10,
    verbatim = 11,
    big_number = 12,
    null_array = 13,
};

/// One reply value. Which fields matter depends on `_kind`:
/// `_text` for simple, error, bulk, double, verbatim and big number;
/// `_integer` for integer and boolean (0 or 1); `_format` (three bytes) for
/// verbatim; `_elements` for array, set and map (a map's keys and values
/// alternate). The factories keep the unused fields empty, which `==` and
/// the binary encoding rely on.
struct redis_reply {
    redis_reply_kind _kind = redis_reply_kind::null;
    std::int64_t _integer = 0;
    std::string _text;
    std::string _format;
    std::vector<redis_reply> _elements;

    /// `text` must not hold CR or LF.
    [[nodiscard]] static auto simple(std::string text) -> redis_reply {
        return {redis_reply_kind::simple, 0, std::move(text), {}, {}};
    }
    /// `text` includes the error prefix (`ERR ...`, `WRONGTYPE ...`) and must
    /// not hold CR or LF.
    [[nodiscard]] static auto error(std::string text) -> redis_reply {
        return {redis_reply_kind::error, 0, std::move(text), {}, {}};
    }
    [[nodiscard]] static auto integer(std::int64_t v) -> redis_reply {
        return {redis_reply_kind::integer, v, {}, {}, {}};
    }
    [[nodiscard]] static auto bulk(std::string bytes) -> redis_reply {
        return {redis_reply_kind::bulk, 0, std::move(bytes), {}, {}};
    }
    [[nodiscard]] static auto null() -> redis_reply { return {}; }
    [[nodiscard]] static auto null_array() -> redis_reply {
        return {redis_reply_kind::null_array, 0, {}, {}, {}};
    }
    [[nodiscard]] static auto array(std::vector<redis_reply> elements) -> redis_reply {
        return {redis_reply_kind::array, 0, {}, {}, std::move(elements)};
    }
    [[nodiscard]] static auto set(std::vector<redis_reply> elements) -> redis_reply {
        return {redis_reply_kind::set, 0, {}, {}, std::move(elements)};
    }
    /// Keys and values alternate: `{k1, v1, k2, v2, ...}`.
    [[nodiscard]] static auto map(std::vector<redis_reply> keys_and_values) -> redis_reply {
        return {redis_reply_kind::map, 0, {}, {}, std::move(keys_and_values)};
    }
    /// `text` is the number as the command formats it (`inf`, `-inf` and
    /// `nan` included); it must not hold CR or LF.
    [[nodiscard]] static auto double_value(std::string text) -> redis_reply {
        return {redis_reply_kind::double_value, 0, std::move(text), {}, {}};
    }
    [[nodiscard]] static auto boolean(bool v) -> redis_reply {
        return {redis_reply_kind::boolean, v ? 1 : 0, {}, {}, {}};
    }
    /// `format` is three bytes, `txt` or `mkd`.
    [[nodiscard]] static auto verbatim(std::string format, std::string text) -> redis_reply {
        return {redis_reply_kind::verbatim, 0, std::move(text), std::move(format), {}};
    }
    /// `digits` is an optional `-` and decimal digits.
    [[nodiscard]] static auto big_number(std::string digits) -> redis_reply {
        return {redis_reply_kind::big_number, 0, std::move(digits), {}, {}};
    }

    [[nodiscard]] auto is_error() const noexcept -> bool {
        return _kind == redis_reply_kind::error;
    }

    auto operator==(const redis_reply&) const -> bool = default;
};

/// A reply the codec or the renderer cannot carry.
class redis_reply_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace redis_reply_detail {

inline constexpr std::size_t k_max_depth = 32;

[[nodiscard]] inline auto has_line_break(std::string_view s) noexcept -> bool {
    return s.find_first_of("\r\n") != std::string_view::npos;
}

[[nodiscard]] inline auto is_big_number(std::string_view s) noexcept -> bool {
    if (!s.empty() && s[0] == '-') {
        s.remove_prefix(1);
    }
    if (s.empty()) {
        return false;
    }
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

/// The checks every reply must pass to be rendered or encoded: no line
/// breaks in line-framed text, three-byte verbatim formats, booleans 0/1,
/// maps with whole pairs, unused fields empty, nesting bounded.
inline auto validate(const redis_reply& r, std::size_t depth) -> void {
    if (depth > k_max_depth) {
        throw redis_reply_error("redis reply nested too deeply");
    }
    const bool uses_text =
        r._kind == redis_reply_kind::simple || r._kind == redis_reply_kind::error ||
        r._kind == redis_reply_kind::bulk || r._kind == redis_reply_kind::double_value ||
        r._kind == redis_reply_kind::verbatim || r._kind == redis_reply_kind::big_number;
    const bool uses_integer =
        r._kind == redis_reply_kind::integer || r._kind == redis_reply_kind::boolean;
    const bool uses_elements = r._kind == redis_reply_kind::array ||
                               r._kind == redis_reply_kind::set || r._kind == redis_reply_kind::map;
    if (r._kind < redis_reply_kind::simple || r._kind > redis_reply_kind::null_array) {
        throw redis_reply_error("unknown redis reply kind");
    }
    if ((!uses_text && !r._text.empty()) || (!uses_integer && r._integer != 0) ||
        (!uses_elements && !r._elements.empty()) ||
        (r._kind != redis_reply_kind::verbatim && !r._format.empty())) {
        throw redis_reply_error("redis reply carries a field its kind does not use");
    }
    switch (r._kind) {
        case redis_reply_kind::simple:
        case redis_reply_kind::error:
        case redis_reply_kind::double_value:
            if (has_line_break(r._text)) {
                throw redis_reply_error("line break in a line-framed redis reply");
            }
            break;
        case redis_reply_kind::boolean:
            if (r._integer != 0 && r._integer != 1) {
                throw redis_reply_error("redis boolean reply is not 0 or 1");
            }
            break;
        case redis_reply_kind::verbatim:
            if (r._format.size() != 3 || r._format.find(':') != std::string::npos ||
                has_line_break(r._format)) {
                throw redis_reply_error("redis verbatim format is not three bytes");
            }
            break;
        case redis_reply_kind::big_number:
            if (!is_big_number(r._text)) {
                throw redis_reply_error("redis big number is not decimal digits");
            }
            break;
        case redis_reply_kind::map:
            if (r._elements.size() % 2 != 0) {
                throw redis_reply_error("redis map reply with a key and no value");
            }
            break;
        default:
            break;
    }
    for (const auto& e : r._elements) {
        validate(e, depth + 1);
    }
}

inline auto render(const redis_reply& r, int version, std::string& out) -> void {
    const bool v3 = version >= 3;
    auto line = [&out](char type, std::string_view text) {
        out += type;
        out += text;
        out += "\r\n";
    };
    auto blob = [&out](char type, std::string_view text) {
        out += type;
        out += std::to_string(text.size());
        out += "\r\n";
        out += text;
        out += "\r\n";
    };
    auto aggregate = [&](char type, std::size_t n) {
        out += type;
        out += std::to_string(n);
        out += "\r\n";
        for (const auto& e : r._elements) {
            render(e, version, out);
        }
    };
    switch (r._kind) {
        case redis_reply_kind::simple:
            line('+', r._text);
            return;
        case redis_reply_kind::error:
            line('-', r._text);
            return;
        case redis_reply_kind::integer:
            line(':', std::to_string(r._integer));
            return;
        case redis_reply_kind::bulk:
            blob('$', r._text);
            return;
        case redis_reply_kind::null:
            out += v3 ? "_\r\n" : "$-1\r\n";
            return;
        case redis_reply_kind::null_array:
            out += v3 ? "_\r\n" : "*-1\r\n";
            return;
        case redis_reply_kind::array:
            aggregate('*', r._elements.size());
            return;
        case redis_reply_kind::set:
            aggregate(v3 ? '~' : '*', r._elements.size());
            return;
        case redis_reply_kind::map:
            if (v3) {
                aggregate('%', r._elements.size() / 2);
            } else {
                aggregate('*', r._elements.size());
            }
            return;
        case redis_reply_kind::double_value:
            if (v3) {
                line(',', r._text);
            } else {
                blob('$', r._text);
            }
            return;
        case redis_reply_kind::boolean:
            if (v3) {
                out += r._integer != 0 ? "#t\r\n" : "#f\r\n";
            } else {
                out += r._integer != 0 ? ":1\r\n" : ":0\r\n";
            }
            return;
        case redis_reply_kind::verbatim:
            if (v3) {
                blob('=', r._format + ":" + r._text);
            } else {
                blob('$', r._text);
            }
            return;
        case redis_reply_kind::big_number:
            if (v3) {
                line('(', r._text);
            } else {
                blob('$', r._text);
            }
            return;
    }
}

inline auto put_u32(std::vector<std::byte>& out, std::size_t v) -> void {
    if (v > 0xFFFFFFFFU) {
        throw redis_reply_error("redis reply field over 4 GiB");
    }
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((v >> static_cast<unsigned>(shift)) & 0xFFU));
    }
}

inline auto put_bytes(std::vector<std::byte>& out, std::string_view s) -> void {
    put_u32(out, s.size());
    const auto* p = reinterpret_cast<const std::byte*>(s.data());
    out.insert(out.end(), p, p + s.size());
}

inline auto encode(const redis_reply& r, std::vector<std::byte>& out) -> void {
    out.push_back(static_cast<std::byte>(r._kind));
    switch (r._kind) {
        case redis_reply_kind::integer: {
            const auto u = static_cast<std::uint64_t>(r._integer);
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.push_back(static_cast<std::byte>((u >> static_cast<unsigned>(shift)) & 0xFFU));
            }
            return;
        }
        case redis_reply_kind::boolean:
            out.push_back(static_cast<std::byte>(r._integer));
            return;
        case redis_reply_kind::verbatim: {
            const auto* p = reinterpret_cast<const std::byte*>(r._format.data());
            out.insert(out.end(), p, p + 3);
            put_bytes(out, r._text);
            return;
        }
        case redis_reply_kind::simple:
        case redis_reply_kind::error:
        case redis_reply_kind::bulk:
        case redis_reply_kind::double_value:
        case redis_reply_kind::big_number:
            put_bytes(out, r._text);
            return;
        case redis_reply_kind::array:
        case redis_reply_kind::set:
            put_u32(out, r._elements.size());
            break;
        case redis_reply_kind::map:
            put_u32(out, r._elements.size() / 2);
            break;
        case redis_reply_kind::null:
        case redis_reply_kind::null_array:
            return;
    }
    for (const auto& e : r._elements) {
        encode(e, out);
    }
}

class reader {
public:
    explicit reader(std::span<const std::byte> data) : _data(data) {}

    [[nodiscard]] auto remaining() const noexcept -> std::size_t { return _data.size() - _at; }

    auto u8() -> std::uint8_t {
        need(1);
        return static_cast<std::uint8_t>(_data[_at++]);
    }
    auto u32() -> std::uint32_t {
        need(4);
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_data[_at++]);
        }
        return v;
    }
    auto u64() -> std::uint64_t {
        need(8);
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_data[_at++]);
        }
        return v;
    }
    auto bytes(std::size_t n) -> std::string {
        need(n);
        std::string s(reinterpret_cast<const char*>(_data.data() + _at), n);
        _at += n;
        return s;
    }

private:
    auto need(std::size_t n) const -> void {
        if (n > remaining()) {
            throw redis_reply_error("truncated redis reply");
        }
    }

    std::span<const std::byte> _data;
    std::size_t _at = 0;
};

inline auto decode(reader& in, std::size_t depth) -> redis_reply {
    if (depth > k_max_depth) {
        throw redis_reply_error("redis reply nested too deeply");
    }
    const auto kind = static_cast<redis_reply_kind>(in.u8());
    redis_reply r;
    r._kind = kind;
    std::size_t children = 0;
    switch (kind) {
        case redis_reply_kind::integer:
            r._integer = static_cast<std::int64_t>(in.u64());
            break;
        case redis_reply_kind::boolean:
            r._integer = in.u8();
            break;
        case redis_reply_kind::verbatim:
            r._format = in.bytes(3);
            r._text = in.bytes(in.u32());
            break;
        case redis_reply_kind::simple:
        case redis_reply_kind::error:
        case redis_reply_kind::bulk:
        case redis_reply_kind::double_value:
        case redis_reply_kind::big_number:
            r._text = in.bytes(in.u32());
            break;
        case redis_reply_kind::array:
        case redis_reply_kind::set:
            children = in.u32();
            break;
        case redis_reply_kind::map:
            children = std::size_t{in.u32()} * 2;
            break;
        case redis_reply_kind::null:
        case redis_reply_kind::null_array:
            break;
        default:
            throw redis_reply_error("unknown redis reply kind");
    }
    // Every element takes at least one byte, so a count larger than what is
    // left is refused before anything is allocated from it.
    if (children > in.remaining()) {
        throw redis_reply_error("redis reply element count past the end");
    }
    r._elements.reserve(children);
    for (std::size_t i = 0; i < children; ++i) {
        r._elements.push_back(decode(in, depth + 1));
    }
    return r;
}

}  // namespace redis_reply_detail

/// The reply in a connection's protocol version (2 or 3).
/// @throws redis_reply_error for a reply that cannot be framed.
[[nodiscard]] inline auto render_redis_reply(const redis_reply& r, int version) -> std::string {
    redis_reply_detail::validate(r, 0);
    std::string out;
    redis_reply_detail::render(r, version, out);
    return out;
}

/// The canonical binary encoding.
/// @throws redis_reply_error for a reply that cannot be framed.
[[nodiscard]] inline auto encode_redis_reply(const redis_reply& r) -> std::vector<std::byte> {
    redis_reply_detail::validate(r, 0);
    std::vector<std::byte> out;
    redis_reply_detail::encode(r, out);
    return out;
}

/// Decodes exactly one reply filling `data`.
/// @throws redis_reply_error for truncated, trailing, malformed or
///         non-canonical bytes.
[[nodiscard]] inline auto decode_redis_reply(std::span<const std::byte> data) -> redis_reply {
    redis_reply_detail::reader in(data);
    auto r = redis_reply_detail::decode(in, 0);
    if (in.remaining() != 0) {
        throw redis_reply_error("trailing bytes after redis reply");
    }
    redis_reply_detail::validate(r, 0);
    return r;
}

/// Why a read could not produce a reply here, for a front end to redirect or
/// retry without parsing an error string (task 16's `read_op`).
enum class redis_read_status : std::uint8_t {
    ok = 0,
    /// This node does not lead the group and the read needs its leader;
    /// `_hint` names it when known.
    not_leader = 1,
    /// The key belongs to a group with no replica here.
    moved = 2,
    /// Routing or the group is not available yet; retry.
    unavailable = 3,
};

/// A read's result: the reply when `_status` is `ok`, else where to go.
template<typename NodeId> struct redis_read_outcome {
    redis_read_status _status = redis_read_status::ok;
    redis_reply _reply;
    std::optional<NodeId> _hint;
};

}  // namespace kythira
