// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_call_wire.hpp
/// @brief The bytes of an authenticated call from a gateway to a front end
///        (.kiro/specs/redis-general-data-types/ design Component 9
///        "Connection state on a split gateway", Requirement 17.2, task 17).
///
/// A gateway without the `front_end` role keeps every client connection's
/// state itself: protocol, identity, isolation, `MULTI` queue and `WATCH`
/// token. Each command goes to the front end the connection is pinned to as
///
///     KYTHIRA.CALL <state> <command> <arg>...
///
/// and the answer is one bulk string holding the state as the front end
/// left it, whether it queued the command (inside `MULTI`), and the reply
/// bytes in the client's protocol. The front end keeps nothing between
/// calls, so a connection can move to another front end at any command
/// boundary. The `MULTI` queue travels only with `EXEC`: while queuing, the
/// front end checks each command and says whether it queued it, and the
/// gateway keeps the queue.
///
/// The layout reuses the varints and length-prefixed bytes of
/// redis_data_wire.hpp. Decoders refuse a truncated payload, trailing
/// bytes, an unknown format version and flag bits they do not know.

#include <kythira/redis/redis_data_wire.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::redis_call_wire {

/// The first byte of every payload, so the layout can change without a
/// front end misreading a newer gateway's bytes.
inline constexpr std::uint8_t k_format = 1;

/// A client connection's state as the gateway holds it.
struct call_state {
    /// The ACL user the connection authenticated as. The front end looks
    /// its role and key scopes up in its own ACL.
    std::string user;
    /// 2 or 3: the protocol replies are encoded in.
    std::uint8_t resp_version = 2;
    /// `KYTHIRA.ISOLATION`, as the `txn_isolation` value; unset means the
    /// front end's default.
    std::optional<std::uint8_t> isolation;
    bool in_multi = false;
    bool multi_failed = false;
    /// The watch token: the oracle timestamp of the first `WATCH`, and the
    /// keys watched since.
    std::uint64_t watch_ts = 0;
    std::vector<std::string> watched;
    /// The `MULTI` queue, sent only with `EXEC`.
    std::vector<std::vector<std::string>> queued;

    friend auto operator==(const call_state&, const call_state&) -> bool = default;
};

/// What a front end answers a call with.
struct call_answer {
    call_state state;
    /// The command was queued inside `MULTI`: the gateway appends it to its
    /// queue.
    bool queued = false;
    /// The reply, ready for the client's socket.
    std::string reply;

    friend auto operator==(const call_answer&, const call_answer&) -> bool = default;
};

namespace detail {

inline constexpr std::uint8_t k_in_multi = 0x01;
inline constexpr std::uint8_t k_multi_failed = 0x02;
inline constexpr std::uint8_t k_known_flags = k_in_multi | k_multi_failed;

inline void put_state(std::string& out, const call_state& s) {
    namespace d = redis_data_wire::detail;
    out.push_back(static_cast<char>(k_format));
    d::put_bytes(out, s.user);
    out.push_back(static_cast<char>(s.resp_version));
    out.push_back(static_cast<char>(s.isolation ? *s.isolation + 1 : 0));
    std::uint8_t flags = 0;
    flags |= s.in_multi ? k_in_multi : 0;
    flags |= s.multi_failed ? k_multi_failed : 0;
    out.push_back(static_cast<char>(flags));
    d::put_varint(out, s.watch_ts);
    d::put_varint(out, s.watched.size());
    for (const auto& k : s.watched) {
        d::put_bytes(out, k);
    }
    d::put_varint(out, s.queued.size());
    for (const auto& argv : s.queued) {
        d::put_varint(out, argv.size());
        for (const auto& a : argv) {
            d::put_bytes(out, a);
        }
    }
}

[[nodiscard]] inline auto get_state(redis_data_wire::detail::reader& in)
    -> std::optional<call_state> {
    call_state s;
    const auto format = in.byte();
    if (!format || *format != k_format) {
        return std::nullopt;
    }
    auto user = in.bytes();
    const auto resp = in.byte();
    const auto isolation = in.byte();
    const auto flags = in.byte();
    if (!user || !resp || (*resp != 2 && *resp != 3) || !isolation || *isolation > 4 || !flags ||
        (*flags & ~k_known_flags) != 0) {
        return std::nullopt;
    }
    s.user = std::move(*user);
    s.resp_version = *resp;
    if (*isolation != 0) {
        s.isolation = static_cast<std::uint8_t>(*isolation - 1);
    }
    s.in_multi = (*flags & k_in_multi) != 0;
    s.multi_failed = (*flags & k_multi_failed) != 0;
    const auto ts = in.varint();
    const auto watched = in.count();
    if (!ts || !watched) {
        return std::nullopt;
    }
    s.watch_ts = *ts;
    s.watched.reserve(*watched);
    for (std::size_t i = 0; i < *watched; ++i) {
        auto k = in.bytes();
        if (!k) {
            return std::nullopt;
        }
        s.watched.push_back(std::move(*k));
    }
    const auto queued = in.count();
    if (!queued) {
        return std::nullopt;
    }
    s.queued.reserve(*queued);
    for (std::size_t i = 0; i < *queued; ++i) {
        const auto argc = in.count();
        // A command has at least its name.
        if (!argc || *argc == 0) {
            return std::nullopt;
        }
        std::vector<std::string> argv;
        argv.reserve(*argc);
        for (std::size_t j = 0; j < *argc; ++j) {
            auto a = in.bytes();
            if (!a) {
                return std::nullopt;
            }
            argv.push_back(std::move(*a));
        }
        s.queued.push_back(std::move(argv));
    }
    return s;
}

}  // namespace detail

/// The `<state>` argument of `KYTHIRA.CALL`.
[[nodiscard]] inline auto encode_state(const call_state& s) -> std::string {
    std::string out;
    detail::put_state(out, s);
    return out;
}

[[nodiscard]] inline auto decode_state(std::string_view bytes) -> std::optional<call_state> {
    redis_data_wire::detail::reader in(bytes);
    auto s = detail::get_state(in);
    if (!s || !in.done()) {
        return std::nullopt;
    }
    return s;
}

/// The bulk string a front end answers `KYTHIRA.CALL` with. The state's
/// queue is never sent back: the gateway holds it.
[[nodiscard]] inline auto encode_answer(const call_answer& a) -> std::string {
    std::string out;
    auto state = a.state;
    state.queued.clear();
    detail::put_state(out, state);
    out.push_back(a.queued ? '\1' : '\0');
    redis_data_wire::detail::put_bytes(out, a.reply);
    return out;
}

[[nodiscard]] inline auto decode_answer(std::string_view bytes) -> std::optional<call_answer> {
    redis_data_wire::detail::reader in(bytes);
    auto state = detail::get_state(in);
    if (!state || !state->queued.empty()) {
        return std::nullopt;
    }
    const auto queued = in.byte();
    auto reply = in.bytes();
    if (!queued || *queued > 1 || !reply || !in.done()) {
        return std::nullopt;
    }
    return call_answer{std::move(*state), *queued == 1, std::move(*reply)};
}

}  // namespace kythira::redis_call_wire
