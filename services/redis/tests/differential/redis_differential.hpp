// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The Redis differential harness (.kiro/specs/redis-general-data-types/
// Requirement 23.2, the scaffold for task 14): one seeded command stream is
// sent to Kythira's gateway and to the reference servers (Redis 7.2 and
// Valkey 8), and every reply is compared.
//
// Everything here is free of I/O so the unit test can check it without
// containers:
//
//   * `reply` and `parse_reply`: a client-side RESP2/RESP3 reply tree. It is
//     deliberately the test's own parser, not the gateway's writer, so a
//     framing bug in the gateway shows up as a difference rather than being
//     parsed the same wrong way on both sides.
//   * `generate`: the seeded command generator. It draws only command shapes
//     the gateway serves today (`k_shapes`); a phase 1 command PR adds its
//     shape there when it ships the command.
//   * `classify`: the comparison. A Kythira reply passes when it equals the
//     reply of either reference server (Redis 7.2 and Valkey 8 disagree in
//     places, and Kythira may follow either), or when a named rule covers it:
//     a harness tolerance (the TTL clock), a design difference D1-D23 from
//     the spec's difference table, or a known gap that names the task that
//     closes it.
//   * `recording`: the recording format from the design's testing strategy
//     (`services/redis/tests/differential/recs/*.json`): one file per server
//     and seed, each entry holding the command and its RESP2 and RESP3 reply.
//   * `render_difference_table`: the Markdown table a run writes.
//
// The generator's output must stay stable for a given seed: recordings and
// golden fingerprints depend on it. It uses its own splitmix64 rather than a
// <random> distribution because the standard distributions are not
// specified bit-for-bit and differ between standard libraries. Changing what
// a seed produces means bumping `k_generator_version` and regenerating
// recs/ (see README.md).

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::redis_diff {

// ── replies ──────────────────────────────────────────────────────────────────

enum class reply_kind {
    simple,      // +
    error,       // - (and RESP3 blob error !)
    integer,     // :
    bulk,        // $ (and RESP3 verbatim = with its "txt:" prefix stripped)
    null,        // $-1, *-1, _
    array,       // *
    map,         // %  items are key, value, key, value ...
    set,         // ~
    push,        // >
    double_,     // ,  text holds the wire form
    boolean,     // #  integer holds 0 or 1
    big_number,  // (  text holds the digits
};

struct reply {
    reply_kind kind = reply_kind::null;
    std::string text;
    std::int64_t integer = 0;
    std::vector<reply> items;

    friend auto operator==(const reply&, const reply&) -> bool = default;
};

namespace detail {

/// The end of the CRLF-terminated line starting at `pos`, or npos.
inline auto line_end(std::string_view in, std::size_t pos) -> std::size_t {
    auto e = in.find("\r\n", pos);
    return e;
}

inline auto parse_int(std::string_view s) -> std::int64_t {
    if (s.empty()) {
        throw std::runtime_error("RESP: empty integer");
    }
    bool neg = s.front() == '-';
    std::size_t i = (neg || s.front() == '+') ? 1 : 0;
    if (i == s.size()) {
        throw std::runtime_error("RESP: bad integer");
    }
    std::int64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            throw std::runtime_error("RESP: bad integer '" + std::string(s) + "'");
        }
        v = v * 10 + (s[i] - '0');
    }
    return neg ? -v : v;
}

}  // namespace detail

/// Parses one reply starting at `pos`. Returns nullopt when `in` holds only
/// part of it (read more and call again with the same `pos`); on success
/// advances `pos` past it. Throws on malformed input.
inline auto parse_reply(std::string_view in, std::size_t& pos) -> std::optional<reply> {
    if (pos >= in.size()) {
        return std::nullopt;
    }
    const char type = in[pos];
    const auto e = detail::line_end(in, pos + 1);
    if (e == std::string_view::npos) {
        return std::nullopt;
    }
    const auto line = in.substr(pos + 1, e - pos - 1);
    std::size_t next = e + 2;
    reply r;
    auto blob = [&](reply_kind kind) -> bool {
        const auto len = detail::parse_int(line);
        if (len < 0) {
            r.kind = reply_kind::null;
            return true;
        }
        const auto n = static_cast<std::size_t>(len);
        if (in.size() < next + n + 2) {
            return false;
        }
        if (in.substr(next + n, 2) != "\r\n") {
            throw std::runtime_error("RESP: blob not CRLF-terminated");
        }
        r.kind = kind;
        r.text = std::string(in.substr(next, n));
        next += n + 2;
        return true;
    };
    auto aggregate = [&](reply_kind kind, std::size_t per_item) -> bool {
        const auto count = detail::parse_int(line);
        if (count < 0) {
            r.kind = reply_kind::null;
            return true;
        }
        r.kind = kind;
        const auto total = static_cast<std::size_t>(count) * per_item;
        r.items.reserve(total);
        for (std::size_t i = 0; i < total; ++i) {
            auto item = parse_reply(in, next);
            if (!item) {
                return false;
            }
            r.items.push_back(std::move(*item));
        }
        return true;
    };
    switch (type) {
        case '+':
            r.kind = reply_kind::simple;
            r.text = std::string(line);
            break;
        case '-':
            r.kind = reply_kind::error;
            r.text = std::string(line);
            break;
        case ':':
            r.kind = reply_kind::integer;
            r.integer = detail::parse_int(line);
            break;
        case '_':
            r.kind = reply_kind::null;
            break;
        case ',':
            r.kind = reply_kind::double_;
            r.text = std::string(line);
            break;
        case '#':
            if (line != "t" && line != "f") {
                throw std::runtime_error("RESP: bad boolean");
            }
            r.kind = reply_kind::boolean;
            r.integer = line == "t" ? 1 : 0;
            break;
        case '(':
            r.kind = reply_kind::big_number;
            r.text = std::string(line);
            break;
        case '$':
            if (!blob(reply_kind::bulk)) {
                return std::nullopt;
            }
            break;
        case '!':
            if (!blob(reply_kind::error)) {
                return std::nullopt;
            }
            break;
        case '=':
            if (!blob(reply_kind::bulk)) {
                return std::nullopt;
            }
            // Verbatim strings carry a three-letter format and a colon.
            if (r.text.size() >= 4 && r.text[3] == ':') {
                r.text.erase(0, 4);
            }
            break;
        case '*':
            if (!aggregate(reply_kind::array, 1)) {
                return std::nullopt;
            }
            break;
        case '~':
            if (!aggregate(reply_kind::set, 1)) {
                return std::nullopt;
            }
            break;
        case '>':
            if (!aggregate(reply_kind::push, 1)) {
                return std::nullopt;
            }
            break;
        case '%':
            if (!aggregate(reply_kind::map, 2)) {
                return std::nullopt;
            }
            break;
        case '|': {
            // An attribute map precedes the reply it annotates; drop it.
            const auto count = detail::parse_int(line);
            for (std::int64_t i = 0; i < count * 2; ++i) {
                if (!parse_reply(in, next)) {
                    return std::nullopt;
                }
            }
            auto annotated = parse_reply(in, next);
            if (!annotated) {
                return std::nullopt;
            }
            r = std::move(*annotated);
            break;
        }
        default:
            throw std::runtime_error(std::string("RESP: unknown type byte '") + type + "'");
    }
    pos = next;
    return r;
}

/// Parses a buffer that must hold exactly one whole reply.
inline auto parse_one(std::string_view in) -> reply {
    std::size_t pos = 0;
    auto r = parse_reply(in, pos);
    if (!r || pos != in.size()) {
        throw std::runtime_error("RESP: expected exactly one reply");
    }
    return std::move(*r);
}

/// A compact one-line rendering for the difference table, in the style of
/// redis-cli: `"OK"` for simple strings, `(error) ...`, `(integer) 5`,
/// `"bytes"`, `(nil)`, `[a, b]`, `{k: v}`, `~{a, b}`.
inline auto display(const reply& r) -> std::string {
    auto quote = [](std::string_view s) {
        std::string out = "\"";
        for (unsigned char c : s) {
            if (c == '"' || c == '\\') {
                out += '\\';
                out += static_cast<char>(c);
            } else if (c < 0x20 || c >= 0x7f) {
                static constexpr char hex[] = "0123456789abcdef";
                out += "\\x";
                out += hex[c >> 4];
                out += hex[c & 15];
            } else {
                out += static_cast<char>(c);
            }
        }
        return out + "\"";
    };
    auto join = [&](const std::vector<reply>& items, std::string_view sep_pair) {
        std::string out;
        for (std::size_t i = 0; i < items.size(); ++i) {
            if (i != 0) {
                out += (!sep_pair.empty() && (i % 2) == 1) ? sep_pair : ", ";
            }
            out += display(items[i]);
        }
        return out;
    };
    switch (r.kind) {
        case reply_kind::simple:
            return "+" + r.text;
        case reply_kind::error:
            return "(error) " + r.text;
        case reply_kind::integer:
            return "(integer) " + std::to_string(r.integer);
        case reply_kind::bulk:
            return quote(r.text);
        case reply_kind::null:
            return "(nil)";
        case reply_kind::array:
            return "[" + join(r.items, "") + "]";
        case reply_kind::push:
            return ">[" + join(r.items, "") + "]";
        case reply_kind::set:
            return "~{" + join(r.items, "") + "}";
        case reply_kind::map:
            return "{" + join(r.items, ": ") + "}";
        case reply_kind::double_:
            return "(double) " + r.text;
        case reply_kind::boolean:
            return r.integer != 0 ? "(true)" : "(false)";
        case reply_kind::big_number:
            return "(big) " + r.text;
    }
    return "?";
}

/// The RESP encoding of a command, as a client sends it.
inline auto encode_command(std::span<const std::string> argv) -> std::string {
    std::string out = "*" + std::to_string(argv.size()) + "\r\n";
    for (const auto& a : argv) {
        out += "$" + std::to_string(a.size()) + "\r\n";
        out += a;
        out += "\r\n";
    }
    return out;
}

// ── generator ────────────────────────────────────────────────────────────────

/// Bumped whenever a seed's output changes; recordings carry it, and the
/// unit test refuses recordings from another version.
inline constexpr int k_generator_version = 2;

/// splitmix64: tiny, fast, and specified bit for bit.
class rng {
public:
    explicit rng(std::uint64_t seed) : _state(seed) {}
    auto next() -> std::uint64_t {
        std::uint64_t z = (_state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27U)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31U);
    }
    /// Uniform in [0, n); the modulo bias is irrelevant at these sizes.
    auto below(std::uint64_t n) -> std::uint64_t { return n == 0 ? 0 : next() % n; }
    auto between(std::int64_t lo, std::int64_t hi) -> std::int64_t {
        return lo + static_cast<std::int64_t>(below(static_cast<std::uint64_t>(hi - lo + 1)));
    }
    auto chance(unsigned percent) -> bool { return below(100) < percent; }

private:
    std::uint64_t _state;
};

struct command {
    std::vector<std::string> argv;
    /// The generator shape that produced it, for the table and filtering.
    std::string shape;

    friend auto operator==(const command&, const command&) -> bool = default;
};

struct generator_options {
    /// Commands to produce (a shape may emit a few at once, so the stream
    /// can run a little past this; it is never cut inside a MULTI block).
    std::size_t length = 600;
    /// Keys are `<letter>:<tag>`; letters a.. for `key_space` keys. The
    /// scenario's gateways cut the key space at "e", so a..d and e..h land
    /// on different shards and multi-key commands cross shards.
    std::size_t key_space = 8;
    /// Distinguishes streams that share a server (seed and protocol).
    std::string tag = "t";
    /// MULTI/EXEC/DISCARD/WATCH blocks, MSET, MGET and multi-key DEL: the
    /// gateway serves these only with KYTHIRA_REDIS_TRANSACTIONS=on.
    bool transactions = true;
};

class stream_builder {
public:
    stream_builder(rng& r, const generator_options& o) : _rng(r), _opt(o) {}

    auto key() -> std::string {
        const auto n = std::max<std::size_t>(1, std::min<std::size_t>(_opt.key_space, 26));
        return std::string(1, static_cast<char>('a' + _rng.below(n))) + ":" + _opt.tag;
    }
    auto distinct_keys(std::size_t n) -> std::vector<std::string> {
        std::vector<std::string> out;
        while (out.size() < n && out.size() < _opt.key_space) {
            auto k = key();
            if (std::find(out.begin(), out.end(), k) == out.end()) {
                out.push_back(std::move(k));
            }
        }
        return out;
    }
    /// Printable ASCII only, so recordings stay plain JSON strings; digits
    /// half the time so later numeric commands find numbers to work on.
    auto value() -> std::string {
        const auto len = _rng.below(13);
        std::string v;
        const bool digits = _rng.chance(50);
        for (std::uint64_t i = 0; i < len; ++i) {
            v += digits ? static_cast<char>('0' + _rng.below(10))
                        : static_cast<char>('!' + _rng.below(94));
        }
        return v;
    }
    auto small_int(std::int64_t lo, std::int64_t hi) -> std::string {
        return std::to_string(_rng.between(lo, hi));
    }
    /// A key of one type family: `<letter>:<kind>:<tag>`, kind `h` (hash),
    /// `s` (set) or `l` (list); strings keep the plain `<letter>:<tag>`.
    /// One time in twelve the key comes from another family, so WRONGTYPE
    /// replies are compared too.
    auto typed_key(char kind) -> std::string {
        static constexpr std::array<char, 4> kinds{'h', 's', 'l', 0};
        if (_rng.below(12) == 0) {
            kind = kinds[_rng.below(kinds.size())];
        }
        const auto n = std::max<std::size_t>(1, std::min<std::size_t>(_opt.key_space, 26));
        const char letter = static_cast<char>('a' + _rng.below(n));
        if (kind == 0) {
            return std::string(1, letter) + ":" + _opt.tag;
        }
        return std::string(1, letter) + ":" + std::string(1, kind) + ":" + _opt.tag;
    }
    /// Distinct keys of one family (no family switching), for commands
    /// that combine several collections.
    auto distinct_typed_keys(char kind, std::size_t n) -> std::vector<std::string> {
        std::vector<std::string> out;
        const auto space = std::max<std::size_t>(1, std::min<std::size_t>(_opt.key_space, 26));
        while (out.size() < n && out.size() < space) {
            auto k = std::string(1, static_cast<char>('a' + _rng.below(space))) + ":" +
                     std::string(1, kind) + ":" + _opt.tag;
            if (std::find(out.begin(), out.end(), k) == out.end()) {
                out.push_back(std::move(k));
            }
        }
        return out;
    }
    /// Hash fields f0..f5.
    auto field() -> std::string { return "f" + std::to_string(_rng.below(6)); }
    /// Set members: small integers half the time (Redis keeps an all-integer
    /// set as an intset), else m0..m7.
    auto member() -> std::string {
        return _rng.chance(50) ? std::to_string(_rng.below(10))
                               : "m" + std::to_string(_rng.below(8));
    }
    /// List elements: few distinct values, so LREM, LPOS and LINSERT find them.
    auto element() -> std::string { return "e" + std::to_string(_rng.below(5)); }
    auto random() -> rng& { return _rng; }
    [[nodiscard]] auto options() const -> const generator_options& { return _opt; }

private:
    rng& _rng;
    const generator_options& _opt;
};

/// One way to generate commands. `emit` returns one or more commands that
/// run back to back (a MULTI block is one shape).
struct shape {
    std::string_view name;
    unsigned weight;
    bool needs_transactions;
    std::function<std::vector<std::vector<std::string>>(stream_builder&)> emit;
};

namespace detail {

/// A single-key command for a MULTI block: strings, counters and each
/// collection type, so a transaction mixes typed writes and reads.
inline auto simple_command(stream_builder& b) -> std::vector<std::string> {
    switch (b.random().below(11)) {
        case 5:
            return {"STRLEN", b.key()};
        case 6:
            return {"INCR", b.key()};
        case 7:
            return {"HSET", b.typed_key('h'), b.field(), b.value()};
        case 8:
            return {"SADD", b.typed_key('s'), b.member()};
        case 9:
            return {"RPUSH", b.typed_key('l'), b.element()};
        case 10:
            return {"LPOP", b.typed_key('l')};
        case 0:
            return {"SET", b.key(), b.value()};
        case 1:
            return {"GET", b.key()};
        case 2:
            return {"DEL", b.key()};
        case 3:
            return {"EXISTS", b.key()};
        default:
            return {"SETEX", b.key(), b.small_int(100, 10000), b.value()};
    }
}

}  // namespace detail

/// Shipped commands the generator leaves out, each with the reason. The
/// unit test checks that every shipped command in the registry has a shape
/// or a line here, so a new command cannot slip past the suite unnoticed.
inline auto excluded_commands() -> const std::map<std::string, std::string, std::less<>>& {
    static const std::map<std::string, std::string, std::less<>> table{
        {"AUTH", "identity: HELLO authenticates each session; replies differ by design (Req 1.5)"},
        {"HELLO", "identity: server name and version differ by design (Req 1.5)"},
        {"CLIENT", "connection-local state, ids differ per server"},
        {"QUIT", "closes the session"},
        {"RESET", "connection-local state"},
        {"COMMAND", "describes the whole server; checked by the registry golden"},
        {"INFO", "describes the whole server"},
        {"DBSIZE", "counts the whole server, which other streams share"},
        {"MEMORY", "byte counts differ by design (Requirement 8.5)"},
        {"SLOWLOG", "timing-dependent"},
        {"RANDOMKEY", "random by definition"},
        {"FLUSHDB", "refused by default (D6), and would empty every stream"},
        {"FLUSHALL", "refused by default (D6), and would empty every stream"},
        {"KYTHIRA.ADVISE", "Kythira only"},
        {"KYTHIRA.ISOLATION", "Kythira only"},
        {"KYTHIRA.TXN", "Kythira only, internal"},
        {"KYTHIRA.FORMAT", "Kythira only; the harness raises the gate before streaming"},
        {"KYTHIRA.DELPREFIX", "Kythira only"},
        {"KYTHIRA.USAGE", "Kythira only"},
        {"KYTHIRA.INSTALL", "Kythira only, internal"},
    };
    return table;
}

/// The command shapes for every shipped command the gateway serves (see
/// excluded_commands() for the rest). SELECT is generated only for database 0 until multi-db lands
/// (phase 3), because a reference server switches database on SELECT 1 and
/// the rest of the stream would then diverge for an uninteresting reason.
/// Order matters: appending keeps every existing seed's output stable only
/// if weights are unchanged, so any edit here bumps k_generator_version.
inline auto shapes() -> const std::vector<shape>& {
    using cmds = std::vector<std::vector<std::string>>;
    static const std::vector<shape> table{
        {"ping", 2, false,
         [](stream_builder& b) -> cmds {
             if (b.random().chance(50)) {
                 return {{"PING"}};
             }
             return {{"PING", b.value()}};
         }},
        {"echo", 2, false, [](stream_builder& b) -> cmds { return {{"ECHO", b.value()}}; }},
        {"select0", 1, false, [](stream_builder&) -> cmds { return {{"SELECT", "0"}}; }},
        {"get", 10, false, [](stream_builder& b) -> cmds { return {{"GET", b.key()}}; }},
        {"exists", 5, false, [](stream_builder& b) -> cmds { return {{"EXISTS", b.key()}}; }},
        {"strlen", 4, false, [](stream_builder& b) -> cmds { return {{"STRLEN", b.key()}}; }},
        {"getrange", 6, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto bound = [&]() -> std::string {
                 if (r.chance(5)) {
                     return r.chance(50) ? "9223372036854775807" : "-9223372036854775808";
                 }
                 return std::to_string(r.between(-15, 15));
             };
             auto start = bound();
             auto end = bound();
             return {{"GETRANGE", b.key(), start, end}};
         }},
        {"getrange_clamp", 2, false,
         [](stream_builder& b) -> cmds {
             // A value that is surely there, then an end index before its
             // start: Redis clamps the end to 0 and returns the first byte.
             auto& r = b.random();
             auto k = b.key();
             std::string v;
             const auto len = r.between(3, 10);
             for (std::int64_t i = 0; i < len; ++i) {
                 v += static_cast<char>('a' + r.below(26));
             }
             return {{"SET", k, v},
                     {"GETRANGE", k, std::to_string(r.between(0, 2)),
                      std::to_string(-(len + 1 + r.between(0, 5)))}};
         }},
        {"getrange_bad_int", 1, false,
         [](stream_builder& b) -> cmds {
             return {{"GETRANGE", b.key(), b.random().chance(50) ? "x" : "1.5", "3"}};
         }},
        {"ttl", 5, false, [](stream_builder& b) -> cmds { return {{"TTL", b.key()}}; }},
        {"set", 12, false, [](stream_builder& b) -> cmds { return {{"SET", b.key(), b.value()}}; }},
        {"setex", 5, false,
         [](stream_builder& b) -> cmds {
             return {{"SETEX", b.key(), b.small_int(100, 10000), b.value()}};
         }},
        {"setex_bad_ttl", 1, false,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<std::string_view, 4> bad{"0", "-5", "ten", ""};
             return {{"SETEX", b.key(), std::string(bad[b.random().below(bad.size())]), b.value()}};
         }},
        {"del", 6, false, [](stream_builder& b) -> cmds { return {{"DEL", b.key()}}; }},
        {"del_multi", 3, true,
         [](stream_builder& b) -> cmds {
             std::vector<std::string> argv{"DEL"};
             for (auto& k : b.distinct_keys(2 + b.random().below(3))) {
                 argv.push_back(std::move(k));
             }
             return {argv};
         }},
        {"mset", 4, true,
         [](stream_builder& b) -> cmds {
             std::vector<std::string> argv{"MSET"};
             for (auto& k : b.distinct_keys(1 + b.random().below(4))) {
                 argv.push_back(std::move(k));
                 argv.push_back(b.value());
             }
             return {argv};
         }},
        {"mget", 5, true,
         [](stream_builder& b) -> cmds {
             std::vector<std::string> argv{"MGET"};
             const auto n = 1 + b.random().below(5);
             for (std::uint64_t i = 0; i < n; ++i) {
                 argv.push_back(b.key());  // repeats allowed, as in Redis
             }
             return {argv};
         }},
        {"multi_exec", 4, true,
         [](stream_builder& b) -> cmds {
             cmds out{{"MULTI"}};
             const auto n = 1 + b.random().below(4);
             for (std::uint64_t i = 0; i < n; ++i) {
                 out.push_back(detail::simple_command(b));
             }
             out.push_back({b.random().chance(85) ? "EXEC" : "DISCARD"});
             return out;
         }},
        {"watch_exec", 3, true,
         [](stream_builder& b) -> cmds {
             // WATCH, maybe touch the watched key on this same connection
             // (which still aborts the EXEC in Redis), then a transaction.
             auto watched = b.key();
             cmds out{{"WATCH", watched}};
             if (b.random().chance(40)) {
                 out.push_back({"SET", watched, b.value()});
             }
             out.push_back({"MULTI"});
             out.push_back({"SET", b.key(), b.value()});
             out.push_back({"GET", watched});
             out.push_back({"EXEC"});
             return out;
         }},
        {"watch_unwatch", 1, true,
         [](stream_builder& b) -> cmds { return {{"WATCH", b.key()}, {"UNWATCH"}}; }},
        {"txn_errors", 1, true,
         [](stream_builder&) -> cmds {
             // EXEC/DISCARD without MULTI, and a nested MULTI.
             return {{"EXEC"}, {"DISCARD"}, {"MULTI"}, {"MULTI"}, {"DISCARD"}};
         }},
        {"wrong_arity", 2, false,
         [](stream_builder& b) -> cmds {
             switch (b.random().below(5)) {
                 case 0:
                     return {{"GET"}};
                 case 1:
                     return {{"SET", b.key()}};
                 case 2:
                     return {{"ECHO", "a", "b"}};
                 case 3:
                     return {{"TTL"}};
                 default:
                     return {{"GETRANGE", b.key(), "0"}};
             }
         }},
        {"unknown_command", 1, false,
         [](stream_builder& b) -> cmds { return {{"KYDIFFNOPE", b.key()}}; }},
        {"lowercase", 2, false,
         [](stream_builder& b) -> cmds {
             // Command names are case-insensitive.
             return {{"set", b.key(), b.value()}, {"get", b.key()}};
         }},
        // ── generator version 2: the phase 1 typed commands ──────────────
        {"counter", 8, false,
         [](stream_builder& b) -> cmds {
             auto k = b.key();
             switch (b.random().below(4)) {
                 case 0:
                     return {{"INCR", k}};
                 case 1:
                     return {{"DECR", k}};
                 case 2:
                     return {{"INCRBY", k, b.small_int(-50, 50)}};
                 default:
                     return {{"DECRBY", k, b.small_int(-50, 50)}};
             }
         }},
        {"counter_overflow", 1, false,
         [](stream_builder& b) -> cmds {
             auto k = b.key();
             return {{"SET", k, "9223372036854775806"},
                     {"INCRBY", k, "2"},
                     {"DECR", k},
                     {"INCRBY", k, "x"}};
         }},
        {"incrbyfloat", 3, false,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<std::string_view, 7> deltas{"1.5", "-0.25", "3e2", "10",
                                                                     "0.1", "abc",   "inf"};
             return {
                 {"INCRBYFLOAT", b.key(), std::string(deltas[b.random().below(deltas.size())])}};
         }},
        {"string_rw", 8, false,
         [](stream_builder& b) -> cmds {
             auto k = b.key();
             switch (b.random().below(6)) {
                 case 0:
                     return {{"SETNX", k, b.value()}};
                 case 1:
                     return {{"GETSET", k, b.value()}};
                 case 2:
                     return {{"GETDEL", k}};
                 case 3:
                     return {{"APPEND", k, b.value()}};
                 case 4:
                     return {{"SETRANGE", k, b.small_int(0, 20), b.value()}};
                 default:
                     return {{"PSETEX", k, b.small_int(100000, 1000000), b.value()}};
             }
         }},
        {"set_options", 5, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             std::vector<std::string> argv{"SET", b.key(), b.value()};
             switch (r.below(3)) {
                 case 0:
                     argv.emplace_back("NX");
                     break;
                 case 1:
                     argv.emplace_back("XX");
                     break;
                 default:
                     break;
             }
             if (r.chance(40)) {
                 argv.emplace_back("GET");
             }
             switch (r.below(4)) {
                 case 0:
                     argv.emplace_back("EX");
                     argv.push_back(b.small_int(100, 10000));
                     break;
                 case 1:
                     argv.emplace_back("PX");
                     argv.push_back(b.small_int(100000, 1000000));
                     break;
                 case 2:
                     argv.emplace_back("KEEPTTL");
                     break;
                 default:
                     break;
             }
             if (r.chance(4)) {
                 argv.emplace_back(r.chance(50) ? "EX" : "NX");  // a syntax error
                 argv.emplace_back("XX");
             }
             return {argv};
         }},
        {"getex", 3, false,
         [](stream_builder& b) -> cmds {
             auto k = b.key();
             switch (b.random().below(4)) {
                 case 0:
                     return {{"GETEX", k}};
                 case 1:
                     return {{"GETEX", k, "EX", b.small_int(100, 10000)}};
                 case 2:
                     return {{"GETEX", k, "PX", b.small_int(100000, 1000000)}};
                 default:
                     return {{"GETEX", k, "PERSIST"}};
             }
         }},
        {"msetnx", 2, true,
         [](stream_builder& b) -> cmds {
             std::vector<std::string> argv{"MSETNX"};
             for (auto& k : b.distinct_keys(1 + b.random().below(3))) {
                 argv.push_back(std::move(k));
                 argv.push_back(b.value());
             }
             return {argv};
         }},
        {"type_of", 4, false,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<char, 4> kinds{'h', 's', 'l', 0};
             return {{"TYPE", b.typed_key(kinds[b.random().below(kinds.size())])}};
         }},
        {"object_encoding", 2, false,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<char, 4> kinds{'h', 's', 'l', 0};
             return {{"OBJECT", "ENCODING", b.typed_key(kinds[b.random().below(kinds.size())])}};
         }},
        {"unlink_touch", 2, true,
         [](stream_builder& b) -> cmds {
             std::vector<std::string> argv{b.random().chance(50) ? "UNLINK" : "TOUCH"};
             for (auto& k : b.distinct_keys(1 + b.random().below(3))) {
                 argv.push_back(std::move(k));
             }
             return {argv};
         }},
        {"expiry", 6, false,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<char, 4> kinds{'h', 's', 'l', 0};
             auto& r = b.random();
             auto k = b.typed_key(kinds[r.below(kinds.size())]);
             switch (r.below(7)) {
                 case 0: {
                     std::vector<std::string> argv{"EXPIRE", k, b.small_int(100, 10000)};
                     static constexpr std::array<std::string_view, 5> flags{"", "NX", "XX", "GT",
                                                                            "LT"};
                     const auto f = flags[r.below(flags.size())];
                     if (!f.empty()) {
                         argv.emplace_back(f);
                     }
                     return {argv};
                 }
                 case 1:
                     return {{"PEXPIRE", k, b.small_int(100000, 1000000)}};
                 case 2:
                     return {{"PERSIST", k}};
                 case 3:
                     return {{"PTTL", k}};
                 case 4:
                     // A time in the past deletes the key at once.
                     return {{"EXPIREAT", k, b.small_int(1, 1000000)}};
                 case 5:
                     return {{"PEXPIREAT", k, b.small_int(1, 1000000)}};
                 default:
                     return {{r.chance(50) ? "EXPIRETIME" : "PEXPIRETIME", k}};
             }
         }},
        {"expire_errors", 1, false,
         [](stream_builder& b) -> cmds {
             switch (b.random().below(3)) {
                 case 0:
                     return {{"EXPIRE", b.key(), "ten"}};
                 case 1:
                     return {{"EXPIRE", b.key(), "100", "NX", "XX"}};
                 default:
                     return {{"EXPIRE", b.key(), "100", "GT", "LT"}};
             }
         }},
        {"rename_copy", 4, true,
         [](stream_builder& b) -> cmds {
             static constexpr std::array<char, 4> kinds{'h', 's', 'l', 0};
             auto& r = b.random();
             const char kind = kinds[r.below(kinds.size())];
             auto keys = kind == 0 ? b.distinct_keys(2) : b.distinct_typed_keys(kind, 2);
             if (keys.size() < 2) {
                 return {{"PING"}};
             }
             switch (r.below(4)) {
                 case 0:
                     return {{"RENAME", keys[0], keys[1]}};
                 case 1:
                     return {{"RENAMENX", keys[0], keys[1]}};
                 case 2:
                     return {{"COPY", keys[0], keys[1]}};
                 default:
                     return {{"COPY", keys[0], keys[1], "REPLACE"}};
             }
         }},
        {"hash_write", 12, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('h');
             switch (r.below(7)) {
                 case 0:
                 case 1: {
                     std::vector<std::string> argv{"HSET", k};
                     const auto n = 1 + r.below(3);
                     for (std::uint64_t i = 0; i < n; ++i) {
                         argv.push_back(b.field());
                         argv.push_back(b.value());
                     }
                     return {argv};
                 }
                 case 2:
                     return {{"HSETNX", k, b.field(), b.value()}};
                 case 3:
                     return {{"HMSET", k, b.field(), b.value(), b.field(), b.value()}};
                 case 4:
                     return {{"HDEL", k, b.field(), b.field()}};
                 case 5:
                     return {{"HINCRBY", k, b.field(), b.small_int(-20, 20)}};
                 default:
                     return {{"HINCRBYFLOAT", k, b.field(),
                              r.chance(80) ? "1.25" : (r.chance(50) ? "x" : "inf")}};
             }
         }},
        {"hash_read", 12, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('h');
             switch (r.below(10)) {
                 case 0:
                 case 1:
                     return {{"HGET", k, b.field()}};
                 case 2:
                     return {{"HMGET", k, b.field(), b.field(), b.field()}};
                 case 3:
                     return {{"HEXISTS", k, b.field()}};
                 case 4:
                     return {{"HLEN", k}};
                 case 5:
                     return {{"HSTRLEN", k, b.field()}};
                 case 6:
                     return {{"HKEYS", k}};
                 case 7:
                     return {{"HVALS", k}};
                 case 8:
                     return {{"HGETALL", k}};
                 default:
                     // A count past the size returns every field once.
                     return {{"HRANDFIELD", k, "100"}};
             }
         }},
        {"set_write", 10, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('s');
             switch (r.below(4)) {
                 case 0:
                 case 1: {
                     std::vector<std::string> argv{"SADD", k};
                     const auto n = 1 + r.below(4);
                     for (std::uint64_t i = 0; i < n; ++i) {
                         argv.push_back(b.member());
                     }
                     return {argv};
                 }
                 case 2:
                     return {{"SREM", k, b.member(), b.member()}};
                 default:
                     // A count past the size pops every member.
                     return {r.chance(70) ? std::vector<std::string>{"SPOP", k, "100"}
                                          : std::vector<std::string>{"SPOP", k, "-1"}};
             }
         }},
        {"set_read", 10, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('s');
             switch (r.below(6)) {
                 case 0:
                 case 1:
                     return {{"SISMEMBER", k, b.member()}};
                 case 2:
                     return {{"SMISMEMBER", k, b.member(), b.member(), b.member()}};
                 case 3:
                     return {{"SMEMBERS", k}};
                 case 4:
                     return {{"SCARD", k}};
                 default:
                     return {{"SRANDMEMBER", k, "100"}};
             }
         }},
        {"set_algebra", 6, true,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto keys = b.distinct_typed_keys('s', 2 + r.below(2));
             static constexpr std::array<std::string_view, 7> ops{
                 "SINTER",      "SUNION",      "SDIFF",     "SINTERCARD",
                 "SINTERSTORE", "SUNIONSTORE", "SDIFFSTORE"};
             const auto op = std::string(ops[r.below(ops.size())]);
             std::vector<std::string> argv{op};
             if (op == "SINTERCARD") {
                 argv.push_back(std::to_string(keys.size()));
             } else if (op.ends_with("STORE")) {
                 argv.push_back(b.distinct_typed_keys('s', 1).front());
             }
             for (auto& k : keys) {
                 argv.push_back(std::move(k));
             }
             if (op == "SINTERCARD" && r.chance(30)) {
                 argv.emplace_back("LIMIT");
                 argv.push_back(b.small_int(0, 3));
             }
             return {argv};
         }},
        {"smove", 2, true,
         [](stream_builder& b) -> cmds {
             auto keys = b.distinct_typed_keys('s', 2);
             if (keys.size() < 2) {
                 return {{"PING"}};
             }
             return {{"SMOVE", keys[0], keys[1], b.member()}};
         }},
        {"list_write", 12, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('l');
             switch (r.below(10)) {
                 case 0:
                 case 1:
                     return {{"LPUSH", k, b.element(), b.element()}};
                 case 2:
                 case 3:
                     return {{"RPUSH", k, b.element()}};
                 case 4:
                     return {{r.chance(50) ? "LPUSHX" : "RPUSHX", k, b.element()}};
                 case 5:
                     return {r.chance(50) ? std::vector<std::string>{"LPOP", k}
                                          : std::vector<std::string>{"RPOP", k, b.small_int(0, 3)}};
                 case 6:
                     return {{"LSET", k, b.small_int(-3, 3), b.element()}};
                 case 7:
                     return {{"LINSERT", k, r.chance(50) ? "BEFORE" : "AFTER", b.element(),
                              b.element()}};
                 case 8:
                     return {{"LREM", k, b.small_int(-2, 2), b.element()}};
                 default:
                     return {{"LTRIM", k, b.small_int(-4, 2), b.small_int(-2, 8)}};
             }
         }},
        {"list_read", 10, false,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto k = b.typed_key('l');
             switch (r.below(5)) {
                 case 0:
                     return {{"LLEN", k}};
                 case 1:
                     return {{"LINDEX", k, b.small_int(-4, 4)}};
                 case 2:
                 case 3:
                     return {{"LRANGE", k, b.small_int(-5, 3), b.small_int(-3, 10)}};
                 default: {
                     std::vector<std::string> argv{"LPOS", k, b.element()};
                     if (r.chance(40)) {
                         argv.emplace_back("RANK");
                         argv.push_back(r.chance(50) ? b.small_int(-2, -1) : b.small_int(1, 2));
                     }
                     if (r.chance(40)) {
                         argv.emplace_back("COUNT");
                         argv.push_back(b.small_int(0, 3));
                     }
                     return {argv};
                 }
             }
         }},
        {"list_move", 4, true,
         [](stream_builder& b) -> cmds {
             auto& r = b.random();
             auto keys = b.distinct_typed_keys('l', 2);
             if (keys.size() < 2) {
                 return {{"PING"}};
             }
             auto side = [&] { return std::string(r.chance(50) ? "LEFT" : "RIGHT"); };
             switch (r.below(3)) {
                 case 0:
                     return {{"LMOVE", keys[0], keys[1], side(), side()}};
                 case 1:
                     return {{"RPOPLPUSH", keys[0], keys[1]}};
                 default: {
                     std::vector<std::string> argv{"LMPOP", "2", keys[0], keys[1], side()};
                     if (r.chance(50)) {
                         argv.emplace_back("COUNT");
                         argv.push_back(b.small_int(1, 3));
                     }
                     return {argv};
                 }
             }
         }},
        {"scan_all", 3, false,
         [](stream_builder& b) -> cmds {
             // One call that covers this stream's whole key space: a COUNT
             // far past its size, so every server answers cursor 0. The
             // order differs by design (D2), the rule compares sets.
             auto& r = b.random();
             const auto pattern = "*:" + b.options().tag;
             switch (r.below(4)) {
                 case 0:
                     return {{"SCAN", "0", "MATCH", pattern, "COUNT", "10000"}};
                 case 1: {
                     static constexpr std::array<std::string_view, 4> types{"string", "hash", "set",
                                                                            "list"};
                     return {{"SCAN", "0", "MATCH", pattern, "COUNT", "10000", "TYPE",
                              std::string(types[r.below(types.size())])}};
                 }
                 case 2:
                     return {{"KEYS", pattern}};
                 default:
                     return {{r.chance(50) ? "HSCAN" : "SSCAN",
                              r.chance(50) ? b.typed_key('h') : b.typed_key('s'), "0", "COUNT",
                              "10000"}};
             }
         }},
        {"typed_errors", 2, false,
         [](stream_builder& b) -> cmds {
             switch (b.random().below(6)) {
                 case 0:
                     return {{"HSET", b.typed_key('h'), "f"}};
                 case 1:
                     return {{"SADD", b.typed_key('s')}};
                 case 2:
                     return {{"LPOP", b.typed_key('l'), "-1"}};
                 case 3:
                     return {{"LINDEX", b.typed_key('l'), "x"}};
                 case 4:
                     return {{"HINCRBY", b.typed_key('h'), b.field(), "1.5"}};
                 default:
                     return {{"SCAN", "x"}};
             }
         }},
    };
    return table;
}

/// The seeded stream. Same seed and options, same commands, on every
/// platform.
inline auto generate(std::uint64_t seed, const generator_options& opt) -> std::vector<command> {
    rng r(seed);
    stream_builder b(r, opt);
    std::vector<const shape*> usable;
    unsigned total = 0;
    for (const auto& s : shapes()) {
        if (!s.needs_transactions || opt.transactions) {
            usable.push_back(&s);
            total += s.weight;
        }
    }
    std::vector<command> out;
    while (out.size() < opt.length) {
        auto pick = r.below(total);
        const shape* chosen = usable.back();
        for (const auto* s : usable) {
            if (pick < s->weight) {
                chosen = s;
                break;
            }
            pick -= s->weight;
        }
        for (auto& argv : chosen->emit(b)) {
            out.push_back(command{std::move(argv), std::string(chosen->name)});
        }
    }
    return out;
}

/// Every key a stream generated with `opt` can name, so each run can start
/// from an empty key space without FLUSHALL (refused by Kythira by default,
/// D6).
inline auto stream_keys(const generator_options& opt) -> std::vector<std::string> {
    std::vector<std::string> out;
    const auto n = std::max<std::size_t>(1, std::min<std::size_t>(opt.key_space, 26));
    for (std::size_t i = 0; i < n; ++i) {
        const std::string letter(1, static_cast<char>('a' + i));
        out.push_back(letter + ":" + opt.tag);
        for (const char* kind : {"h", "s", "l"}) {
            out.push_back(letter + ":" + kind + ":" + opt.tag);
        }
    }
    return out;
}

/// FNV-1a over the encoded stream: a golden fingerprint for the unit test.
inline auto fingerprint(const std::vector<command>& stream) -> std::uint64_t {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (const auto& c : stream) {
        for (unsigned char ch : encode_command(c.argv)) {
            h ^= ch;
            h *= 0x100000001b3ULL;
        }
    }
    return h;
}

// ── comparison ───────────────────────────────────────────────────────────────

enum class outcome {
    same,     // equal to a reference reply
    allowed,  // differs, but a rule covers it
    differs,  // a real difference
};

struct verdict {
    outcome result = outcome::same;
    /// The rule id when `allowed` ("clock", "D2", "G1", ...).
    std::string rule;
};

/// A named reason a Kythira reply may differ from the references.
struct rule {
    /// "clock" for harness tolerances, "D<n>" for the design's difference
    /// table, "G<n>" for known gaps.
    std::string id;
    /// For gaps, the task that closes it; for D rules, the design's row.
    std::string reference;
    std::string description;
    std::function<bool(const command&, const reply& expected, const reply& actual)> covers;
};

namespace detail {

inline auto upper(std::string_view s) -> std::string {
    std::string out(s);
    for (auto& c : out) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return out;
}

/// Sorted copy of an aggregate's items (pairs kept together for maps).
inline auto unordered(const reply& r) -> reply {
    reply out = r;
    if (r.kind == reply_kind::map) {
        std::vector<std::pair<reply, reply>> pairs;
        for (std::size_t i = 0; i + 1 < r.items.size(); i += 2) {
            pairs.emplace_back(r.items[i], r.items[i + 1]);
        }
        auto less = [](const auto& a, const auto& b) {
            return display(a.first) < display(b.first);
        };
        std::sort(pairs.begin(), pairs.end(), less);
        out.items.clear();
        for (auto& [k, v] : pairs) {
            out.items.push_back(std::move(k));
            out.items.push_back(std::move(v));
        }
    } else {
        std::sort(out.items.begin(), out.items.end(),
                  [](const reply& a, const reply& b) { return display(a) < display(b); });
    }
    return out;
}

/// A flat [k1, v1, k2, v2, ...] array (or a map) with its pairs sorted by
/// key, pairs kept together.
inline auto unordered_pairs(const reply& r) -> reply {
    reply out = r;
    std::vector<std::pair<reply, reply>> pairs;
    for (std::size_t i = 0; i + 1 < r.items.size(); i += 2) {
        pairs.emplace_back(r.items[i], r.items[i + 1]);
    }
    std::sort(pairs.begin(), pairs.end(),
              [](const auto& x, const auto& y) { return display(x.first) < display(y.first); });
    out.items.clear();
    for (auto& [k, v] : pairs) {
        out.items.push_back(std::move(k));
        out.items.push_back(std::move(v));
    }
    return out;
}

/// Two decimal renderings within a relative 1e-15 of each other (or equal).
inline auto close_decimals(const std::string& x, const std::string& y) -> bool {
    if (x == y) {
        return true;
    }
    try {
        std::size_t ux = 0;
        std::size_t uy = 0;
        const long double a = std::stold(x, &ux);
        const long double b = std::stold(y, &uy);
        if (ux != x.size() || uy != y.size()) {
            return false;
        }
        const long double scale = std::max<long double>(std::fabs(a), 1.0L);
        return std::fabs(a - b) <= scale * 1e-15L;
    } catch (const std::exception&) {
        return false;
    }
}

/// GETRANGE as Redis 7.2 and Valkey 8 compute it (getrangeCommand): a
/// negative end past the start of the string clamps to 0 and so still
/// returns the first byte.
inline auto redis_getrange(std::string_view v, std::int64_t start, std::int64_t end)
    -> std::string {
    const auto len = static_cast<std::int64_t>(v.size());
    if (start < 0 && end < 0 && start > end) {
        return "";
    }
    if (start < 0) {
        start = len + start;
    }
    if (end < 0) {
        end = len + end;
    }
    start = std::max<std::int64_t>(start, 0);
    end = std::max<std::int64_t>(end, 0);
    if (end >= len) {
        end = len - 1;
    }
    if (start > end || len == 0) {
        return "";
    }
    return std::string(
        v.substr(static_cast<std::size_t>(start), static_cast<std::size_t>(end - start + 1)));
}

}  // namespace detail

/// The rules every comparison applies, in order. Keep the gap list honest:
/// a gap whose task has landed is deleted here in that task's PR, and the
/// unit test's table of gap ids keeps the list from growing silently.
inline auto rules() -> const std::vector<rule>& {
    static const std::vector<rule> table{
        {"clock", "harness",
         "TTL and PTTL are read a few milliseconds apart on each server, and Kythira rounds "
         "the remaining time up where Redis rounds to nearest, so positive TTLs may differ "
         "by up to 2 s (PTTL 2000 ms); an absolute expiry (EXPIRETIME, PEXPIRETIME) depends "
         "on when the stream ran, so positive ones may differ by any amount",
         [](const command& c, const reply& e, const reply& a) {
             const auto name = detail::upper(c.argv.front());
             if (e.kind != reply_kind::integer || a.kind != reply_kind::integer || e.integer < 0 ||
                 a.integer < 0) {
                 return false;
             }
             if (name == "TTL") {
                 return (e.integer > a.integer ? e.integer - a.integer : a.integer - e.integer) <=
                        2;
             }
             if (name == "PTTL") {
                 return (e.integer > a.integer ? e.integer - a.integer : a.integer - e.integer) <=
                        2000;
             }
             return name == "EXPIRETIME" || name == "PEXPIRETIME";
         }},
        {"D1", "design.md difference table D1",
         "INCRBYFLOAT and HINCRBYFLOAT compute in binary128; amd64 Redis uses 80-bit long "
         "double, so the last digits may differ",
         [](const command& c, const reply& e, const reply& a) {
             const auto name = detail::upper(c.argv.front());
             if ((name != "INCRBYFLOAT" && name != "HINCRBYFLOAT") || e.kind != a.kind ||
                 (e.kind != reply_kind::bulk && e.kind != reply_kind::simple)) {
                 return false;
             }
             return detail::close_decimals(e.text, a.text);
         }},
        {"D2", "design.md difference table D2",
         "collections come back in byte order; Redis promises no order",
         [](const command& c, const reply& e, const reply& a) {
             static const std::vector<std::string> unordered_cmds{
                 "HKEYS", "HVALS", "SMEMBERS", "SINTER",      "SUNION",
                 "SDIFF", "KEYS",  "SPOP",     "SRANDMEMBER", "HRANDFIELD"};
             const auto name = detail::upper(c.argv.front());
             if (name == "HGETALL") {
                 return detail::unordered_pairs(e) == detail::unordered_pairs(a);
             }
             if (name == "SCAN" || name == "SSCAN" || name == "HSCAN") {
                 // [cursor, items]: the same cursor and the same items.
                 if (e.items.size() != 2 || a.items.size() != 2 || e.items[0] != a.items[0]) {
                     return false;
                 }
                 return name == "HSCAN"
                            ? detail::unordered_pairs(e.items[1]) ==
                                  detail::unordered_pairs(a.items[1])
                            : detail::unordered(e.items[1]) == detail::unordered(a.items[1]);
             }
             if (std::find(unordered_cmds.begin(), unordered_cmds.end(), name) ==
                 unordered_cmds.end()) {
                 return false;
             }
             return detail::unordered(e) == detail::unordered(a);
         }},
    };
    return table;
}

/// Compares Kythira's reply with the two references'. Either reference may
/// be absent (a run against one server, or a replay of one recording).
inline auto classify(const command& c, const std::optional<reply>& redis,
                     const std::optional<reply>& valkey, const reply& kythira,
                     const std::vector<rule>& extra_rules = {}) -> verdict {
    if ((redis && *redis == kythira) || (valkey && *valkey == kythira)) {
        return {outcome::same, {}};
    }
    auto check = [&](const std::vector<rule>& list) -> std::optional<verdict> {
        for (const auto& r : list) {
            for (const auto* ref : {redis ? &*redis : nullptr, valkey ? &*valkey : nullptr}) {
                if (ref != nullptr && r.covers(c, *ref, kythira)) {
                    return verdict{outcome::allowed, r.id};
                }
            }
        }
        return std::nullopt;
    };
    if (auto v = check(rules())) {
        return *v;
    }
    if (auto v = check(extra_rules)) {
        return *v;
    }
    return {outcome::differs, {}};
}

// ── recordings ───────────────────────────────────────────────────────────────

struct recording_entry {
    std::vector<std::string> argv;
    std::string shape;
    /// Raw RESP reply bytes; empty when that protocol was not run.
    std::string resp2;
    std::string resp3;
};

struct recording {
    /// "redis", "valkey", "kythira", or for the AWS recordings in recs/aws/
    /// (Requirement 25.1) "elasticache-valkey", "elasticache-redis",
    /// "memorydb".
    std::string server;
    std::string version;  // as the server reports it
    std::string date;     // YYYY-MM-DD
    std::uint64_t seed = 0;
    std::size_t length = 0;
    int generator_version = k_generator_version;
    /// The generator's key tag when it is not `s<seed>`. The AWS streams
    /// use `{s<seed>}`, a hash tag, so every key of a stream is in one
    /// cluster slot and a multi-key command is not refused as CROSSSLOT
    /// by ElastiCache Serverless or MemoryDB, which are always clustered.
    std::string tag;
    std::vector<recording_entry> entries;

    [[nodiscard]] auto key_tag() const -> std::string {
        return tag.empty() ? "s" + std::to_string(seed) : tag;
    }
};

inline auto to_json(const recording& r) -> boost::json::object {
    boost::json::array entries;
    for (const auto& e : r.entries) {
        boost::json::array argv;
        for (const auto& a : e.argv) {
            argv.emplace_back(a);
        }
        entries.emplace_back(boost::json::object{
            {"argv", std::move(argv)},
            {"shape", e.shape},
            {"resp2", e.resp2},
            {"resp3", e.resp3},
        });
    }
    boost::json::object o{
        {"format", 1},
        {"server", r.server},
        {"version", r.version},
        {"date", r.date},
        {"seed", r.seed},
        {"length", r.length},
        {"generator_version", r.generator_version},
        {"entries", std::move(entries)},
    };
    if (!r.tag.empty()) {
        o["tag"] = r.tag;
    }
    return o;
}

inline auto recording_from_json(const boost::json::value& v) -> recording {
    const auto& o = v.as_object();
    if (o.at("format").to_number<int>() != 1) {
        throw std::runtime_error("recording: unknown format");
    }
    recording r;
    r.server = std::string(o.at("server").as_string());
    r.version = std::string(o.at("version").as_string());
    r.date = std::string(o.at("date").as_string());
    r.seed = o.at("seed").to_number<std::uint64_t>();
    r.length = o.at("length").to_number<std::size_t>();
    r.generator_version = o.at("generator_version").to_number<int>();
    if (const auto* tag = o.if_contains("tag")) {
        r.tag = std::string(tag->as_string());
    }
    for (const auto& ev : o.at("entries").as_array()) {
        const auto& eo = ev.as_object();
        recording_entry e;
        for (const auto& a : eo.at("argv").as_array()) {
            e.argv.emplace_back(a.as_string());
        }
        e.shape = std::string(eo.at("shape").as_string());
        e.resp2 = std::string(eo.at("resp2").as_string());
        e.resp3 = std::string(eo.at("resp3").as_string());
        r.entries.push_back(std::move(e));
    }
    return r;
}

/// One JSON object per line inside "entries", so a regenerated recording
/// diffs line by line in review.
inline auto serialize(const recording& r) -> std::string {
    auto o = to_json(r);
    std::string out = "{\n";
    for (const auto* key :
         {"format", "server", "version", "date", "seed", "length", "generator_version", "tag"}) {
        if (o.contains(key)) {
            out += "  \"" + std::string(key) + "\": " + boost::json::serialize(o.at(key)) + ",\n";
        }
    }
    out += "  \"entries\": [\n";
    const auto& entries = o.at("entries").as_array();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        out += "    " + boost::json::serialize(entries[i]);
        out += i + 1 < entries.size() ? ",\n" : "\n";
    }
    out += "  ]\n}\n";
    return out;
}

// ── difference table ─────────────────────────────────────────────────────────

struct difference_row {
    std::uint64_t seed = 0;
    int protocol = 2;
    std::size_t index = 0;
    std::vector<std::string> argv;
    std::optional<reply> redis;
    std::optional<reply> valkey;
    std::optional<reply> kythira;
    /// "refs differ" when only the references disagree; otherwise the
    /// verdict's rule id or "DIFFERS".
    std::string note;
};

inline auto render_difference_table(const std::vector<difference_row>& rows) -> std::string {
    auto cell = [](std::string s) {
        std::string out;
        for (char c : s) {
            if (c == '|') {
                out += "\\|";
            } else {
                out += c;
            }
        }
        if (out.size() > 120) {
            out = out.substr(0, 117) + "...";
        }
        return out;
    };
    auto shown = [&](const std::optional<reply>& r) { return r ? cell(display(*r)) : "-"; };
    std::string out =
        "| seed | RESP | # | command | Redis 7.2 | Valkey 8 | Kythira | verdict |\n"
        "|---|---|---|---|---|---|---|---|\n";
    for (const auto& row : rows) {
        std::string cmd;
        for (const auto& a : row.argv) {
            cmd += (cmd.empty() ? "" : " ") + a;
        }
        out += "| " + std::to_string(row.seed) + " | " + std::to_string(row.protocol) + " | " +
               std::to_string(row.index) + " | `" + cell(cmd) + "` | " + shown(row.redis) + " | " +
               shown(row.valkey) + " | " + shown(row.kythira) + " | " + row.note + " |\n";
    }
    return out;
}

}  // namespace kythira::redis_diff
