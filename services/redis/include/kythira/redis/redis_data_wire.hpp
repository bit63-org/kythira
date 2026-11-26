// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_data_wire.hpp
/// @brief The bytes of the Redis data-layer API
///        (.kiro/specs/redis-general-data-types/ design Component 9
///        "Internal protocol", Requirement 18, task 16).
///
/// The data-layer API is carried as internal RESP commands on the forward
/// link, beside `KYTHIRA.TXN` (Requirement 18.5), so co-located and split
/// nodes share one transport:
///
/// | Command | Answer |
/// |---|---|
/// | `KYTHIRA.DATA ROUTE <key>` | bulk: a routes payload with the key's route |
/// | `KYTHIRA.DATA ROUTES <range>` | bulk: a routes payload for the range |
/// | `KYTHIRA.DATA PROPOSE <group> <version> <conf> <entry>` | bulk: a proposal outcome |
/// | `KYTHIRA.DATA READ <mode> <key>` | bulk: a read outcome |
///
/// Every answer is one bulk string (an error is only for a malformed or
/// refused call), so a reply never needs an error string parsed to find
/// out where to go next. Payloads use varints and length-prefixed bytes,
/// and node ids travel as their text (`node_id_traits`), so numeric and
/// composite ids both work. Decoders refuse truncated or trailing bytes.
///
/// The descriptor layout is the one the DynamoDB layers use for their
/// routes (`services/dynamodb/include/kythira/dynamodb/op_wire.hpp`), so
/// the two can share a core codec later without a format change.

#include <raft/composite_node_id.hpp>
#include <raft/shard_types.hpp>
#include <raft/txn_envelope.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::redis_data_wire {

namespace detail {

inline void put_varint(std::string& out, std::uint64_t v) {
    while (v >= 0x80U) {
        out.push_back(static_cast<char>((v & 0x7FU) | 0x80U));
        v >>= 7U;
    }
    out.push_back(static_cast<char>(v));
}

inline void put_bytes(std::string& out, std::string_view b) {
    put_varint(out, b.size());
    out.append(b);
}

/// Reads what the `put_*` functions wrote; every accessor returns
/// `nullopt` past the end or on a malformed varint.
class reader {
public:
    explicit reader(std::string_view in) noexcept : _in(in) {}

    [[nodiscard]] auto varint() -> std::optional<std::uint64_t> {
        std::uint64_t v = 0;
        for (unsigned shift = 0; shift < 64; shift += 7) {
            if (_pos >= _in.size()) {
                return std::nullopt;
            }
            const auto b = static_cast<std::uint8_t>(_in[_pos++]);
            v |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
            if ((b & 0x80U) == 0) {
                // A last group with bits past 64, or a needless zero
                // continuation, is not the encoding put_varint writes.
                if ((shift == 63 && b > 1) || (shift > 0 && b == 0)) {
                    return std::nullopt;
                }
                return v;
            }
        }
        return std::nullopt;
    }
    [[nodiscard]] auto byte() -> std::optional<std::uint8_t> {
        if (_pos >= _in.size()) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(_in[_pos++]);
    }
    [[nodiscard]] auto bytes() -> std::optional<std::string> {
        const auto n = varint();
        if (!n || *n > _in.size() - _pos) {
            return std::nullopt;
        }
        std::string out(_in.substr(_pos, *n));
        _pos += *n;
        return out;
    }
    /// A count of things each at least one byte long, so a forged huge
    /// count cannot make a decoder reserve memory it will never fill.
    [[nodiscard]] auto count() -> std::optional<std::size_t> {
        const auto n = varint();
        if (!n || *n > _in.size() - _pos) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(*n);
    }
    [[nodiscard]] auto done() const noexcept -> bool { return _pos == _in.size(); }

private:
    std::string_view _in;
    std::size_t _pos = 0;
};

template<typename NodeId> [[nodiscard]] auto node_text(const NodeId& n) -> std::string {
    return node_id_traits<NodeId>::to_text(n);
}

template<typename NodeId> [[nodiscard]] auto get_node(reader& in) -> std::optional<NodeId> {
    const auto text = in.bytes();
    return text ? node_id_traits<NodeId>::from_text(*text) : std::nullopt;
}

}  // namespace detail

// ── ranges and routes ──────────────────────────────────────────────────────

/// A key range: each bound as a presence byte and, when present, its bytes.
inline void put_range(std::string& out, const shard_range<std::string>& r) {
    for (const auto* bound : {&r._start, &r._end}) {
        out.push_back(bound->has_value() ? '\1' : '\0');
        if (bound->has_value()) {
            detail::put_bytes(out, **bound);
        }
    }
}

[[nodiscard]] inline auto get_range(detail::reader& in) -> std::optional<shard_range<std::string>> {
    shard_range<std::string> r;
    for (auto* bound : {&r._start, &r._end}) {
        const auto has = in.byte();
        if (!has || *has > 1) {
            return std::nullopt;
        }
        if (*has == 1) {
            auto b = in.bytes();
            if (!b) {
                return std::nullopt;
            }
            *bound = std::move(*b);
        }
    }
    return r;
}

[[nodiscard]] inline auto encode_range(const shard_range<std::string>& r) -> std::string {
    std::string out;
    put_range(out, r);
    return out;
}

[[nodiscard]] inline auto decode_range(std::string_view bytes)
    -> std::optional<shard_range<std::string>> {
    detail::reader in(bytes);
    auto r = get_range(in);
    if (!r || !in.done()) {
        return std::nullopt;
    }
    return r;
}

/// A route: group, range, epoch, voters, learners, leader hint.
template<typename GroupId, typename NodeId>
void put_route(std::string& out, const shard_descriptor<GroupId, std::string, NodeId>& d) {
    detail::put_varint(out, static_cast<std::uint64_t>(d._group_id));
    put_range(out, d._range);
    detail::put_varint(out, d._epoch._version);
    detail::put_varint(out, d._epoch._conf_version);
    for (const auto* nodes : {&d._voters, &d._learners}) {
        detail::put_varint(out, nodes->size());
        for (const auto& n : *nodes) {
            detail::put_bytes(out, detail::node_text(n));
        }
    }
    out.push_back(d._leader_hint ? '\1' : '\0');
    if (d._leader_hint) {
        detail::put_bytes(out, detail::node_text(*d._leader_hint));
    }
}

template<typename GroupId, typename NodeId>
[[nodiscard]] auto get_route(detail::reader& in)
    -> std::optional<shard_descriptor<GroupId, std::string, NodeId>> {
    shard_descriptor<GroupId, std::string, NodeId> d{};
    const auto group = in.varint();
    if (!group) {
        return std::nullopt;
    }
    d._group_id = static_cast<GroupId>(*group);
    auto range = get_range(in);
    const auto version = range ? in.varint() : std::nullopt;
    const auto conf = version ? in.varint() : std::nullopt;
    if (!conf) {
        return std::nullopt;
    }
    d._range = std::move(*range);
    d._epoch._version = *version;
    d._epoch._conf_version = *conf;
    for (auto* nodes : {&d._voters, &d._learners}) {
        const auto n = in.count();
        if (!n) {
            return std::nullopt;
        }
        for (std::size_t i = 0; i < *n; ++i) {
            auto id = detail::get_node<NodeId>(in);
            if (!id) {
                return std::nullopt;
            }
            nodes->push_back(std::move(*id));
        }
    }
    const auto has_hint = in.byte();
    if (!has_hint || *has_hint > 1) {
        return std::nullopt;
    }
    if (*has_hint == 1) {
        auto id = detail::get_node<NodeId>(in);
        if (!id) {
            return std::nullopt;
        }
        d._leader_hint = std::move(id);
    }
    return d;
}

/// A `ROUTE`/`ROUTES` answer, and the routes a stale proposal is refused
/// with: the rows, and where each node they name takes data-layer calls
/// (`host:port`), for the nodes whose address the answering node knows.
template<typename GroupId, typename NodeId> struct routes_payload {
    std::vector<shard_descriptor<GroupId, std::string, NodeId>> routes;
    std::vector<std::pair<NodeId, std::string>> addresses;
};

template<typename GroupId, typename NodeId>
[[nodiscard]] auto encode_routes(const routes_payload<GroupId, NodeId>& r) -> std::string {
    std::string out;
    detail::put_varint(out, r.routes.size());
    for (const auto& d : r.routes) {
        put_route(out, d);
    }
    detail::put_varint(out, r.addresses.size());
    for (const auto& [node, address] : r.addresses) {
        detail::put_bytes(out, detail::node_text(node));
        detail::put_bytes(out, address);
    }
    return out;
}

template<typename GroupId, typename NodeId>
[[nodiscard]] auto decode_routes(std::string_view bytes)
    -> std::optional<routes_payload<GroupId, NodeId>> {
    detail::reader in(bytes);
    routes_payload<GroupId, NodeId> out;
    const auto n = in.count();
    if (!n) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < *n; ++i) {
        auto d = get_route<GroupId, NodeId>(in);
        if (!d) {
            return std::nullopt;
        }
        out.routes.push_back(std::move(*d));
    }
    const auto m = in.count();
    if (!m) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < *m; ++i) {
        auto node = detail::get_node<NodeId>(in);
        auto address = node ? in.bytes() : std::nullopt;
        if (!address) {
            return std::nullopt;
        }
        out.addresses.emplace_back(std::move(*node), std::move(*address));
    }
    if (!in.done()) {
        return std::nullopt;
    }
    return out;
}

// ── proposals ──────────────────────────────────────────────────────────────

/// How a data node answered `KYTHIRA.DATA PROPOSE`. The values are wire
/// bytes: append only.
enum class propose_status : std::uint8_t {
    /// Applied; the payload is the state machine's result bytes.
    ok = 0,
    /// This replica does not lead the group (and never forwards, so a call
    /// crosses at most one data node, Requirement 18.3); payload: a
    /// presence byte and the leader hint's text.
    not_leader = 1,
    /// The caller's epoch is stale, or the group no longer owns the
    /// entry's key; payload: a routes payload with the current routes.
    stale_route = 2,
    /// This node holds no replica of the group and has no row for it.
    unknown_group = 3,
    /// A transaction holds the key; payload: key, holder (two u64 as
    /// varints), primary key.
    key_locked = 4,
    /// No group owns the entry's key.
    unrouted = 5,
    /// The proposal did not commit within the call's timeout; it may still.
    timeout = 6,
    /// Anything else; payload: the message.
    failed = 7,
};

/// A decoded proposal answer.
template<typename GroupId, typename NodeId> struct propose_outcome {
    propose_status status = propose_status::failed;
    /// `ok`: the result bytes. `failed`: the message.
    std::string payload;
    std::optional<NodeId> leader;            ///< `not_leader`
    routes_payload<GroupId, NodeId> routes;  ///< `stale_route`
    std::string locked_key;                  ///< `key_locked`
    txn_id holder;                           ///< `key_locked`
    std::string primary;                     ///< `key_locked`
};

[[nodiscard]] inline auto encode_propose_ok(std::string_view result) -> std::string {
    std::string out(1, static_cast<char>(propose_status::ok));
    out.append(result);
    return out;
}

template<typename NodeId>
[[nodiscard]] auto encode_propose_not_leader(const std::optional<NodeId>& leader) -> std::string {
    std::string out(1, static_cast<char>(propose_status::not_leader));
    out.push_back(leader ? '\1' : '\0');
    if (leader) {
        detail::put_bytes(out, detail::node_text(*leader));
    }
    return out;
}

template<typename GroupId, typename NodeId>
[[nodiscard]] auto encode_propose_stale(const routes_payload<GroupId, NodeId>& routes)
    -> std::string {
    return std::string(1, static_cast<char>(propose_status::stale_route)) + encode_routes(routes);
}

[[nodiscard]] inline auto encode_propose_locked(std::string_view key, const txn_id& holder,
                                                std::string_view primary) -> std::string {
    std::string out(1, static_cast<char>(propose_status::key_locked));
    detail::put_bytes(out, key);
    detail::put_varint(out, holder._hi);
    detail::put_varint(out, holder._lo);
    detail::put_bytes(out, primary);
    return out;
}

/// `unknown_group`, `unrouted`, `timeout` and `failed`.
[[nodiscard]] inline auto encode_propose_status(propose_status status,
                                                std::string_view message = {}) -> std::string {
    std::string out(1, static_cast<char>(status));
    if (status == propose_status::failed) {
        out.append(message);
    }
    return out;
}

template<typename GroupId, typename NodeId>
[[nodiscard]] auto decode_propose(std::string_view bytes)
    -> std::optional<propose_outcome<GroupId, NodeId>> {
    if (bytes.empty() || static_cast<std::uint8_t>(bytes[0]) > 7) {
        return std::nullopt;
    }
    propose_outcome<GroupId, NodeId> out;
    out.status = static_cast<propose_status>(bytes[0]);
    const auto body = bytes.substr(1);
    detail::reader in(body);
    switch (out.status) {
        case propose_status::ok:
        case propose_status::failed:
            out.payload = std::string(body);
            return out;
        case propose_status::not_leader: {
            const auto has = in.byte();
            if (!has || *has > 1) {
                return std::nullopt;
            }
            if (*has == 1) {
                out.leader = detail::get_node<NodeId>(in);
                if (!out.leader) {
                    return std::nullopt;
                }
            }
            break;
        }
        case propose_status::stale_route: {
            auto routes = decode_routes<GroupId, NodeId>(body);
            if (!routes) {
                return std::nullopt;
            }
            out.routes = std::move(*routes);
            return out;
        }
        case propose_status::key_locked: {
            auto key = in.bytes();
            const auto hi = key ? in.varint() : std::nullopt;
            const auto lo = hi ? in.varint() : std::nullopt;
            auto primary = lo ? in.bytes() : std::nullopt;
            if (!primary) {
                return std::nullopt;
            }
            out.locked_key = std::move(*key);
            out.holder = txn_id{*hi, *lo};
            out.primary = std::move(*primary);
            break;
        }
        case propose_status::unknown_group:
        case propose_status::unrouted:
        case propose_status::timeout:
            break;
    }
    if (!in.done()) {
        return std::nullopt;
    }
    return out;
}

// ── reads ──────────────────────────────────────────────────────────────────

/// Which replica may answer `KYTHIRA.DATA READ`, as the front end's
/// `redis_read_consistency` asks: the argument is the name.
enum class read_mode : std::uint8_t {
    /// Only a leader that has applied every write its predecessor
    /// acknowledged (the default consistency).
    leader,
    /// Any replica, which may lag.
    any_replica,
    /// The leader, after a committed no-op proves its state is current.
    linearizable,
};

[[nodiscard]] inline auto read_mode_name(read_mode m) -> std::string_view {
    switch (m) {
        case read_mode::any_replica:
            return "ANY";
        case read_mode::linearizable:
            return "LINEARIZABLE";
        case read_mode::leader:
            break;
    }
    return "LEADER";
}

/// The mode a `READ` names, upper case only; `nullopt` for anything else.
[[nodiscard]] inline auto parse_read_mode(std::string_view name) -> std::optional<read_mode> {
    for (auto m : {read_mode::leader, read_mode::any_replica, read_mode::linearizable}) {
        if (name == read_mode_name(m)) {
            return m;
        }
    }
    return std::nullopt;
}

/// How a data node answered `KYTHIRA.DATA READ`. The values are wire bytes:
/// append only.
enum class read_status : std::uint8_t {
    /// Read; payload: a presence byte and, for a present key, its deadline
    /// (ms since the Unix epoch, 0 for none) as a varint and its bytes.
    ok = 0,
    /// This replica cannot answer at the mode (not the leader, or a leader
    /// still catching up, or no replica of the key's group here); payload:
    /// a presence byte and the leader hint's text. Never forwarded.
    not_leader = 1,
    /// The value's bytes are not all on this replica yet (the disk-backed
    /// store); payload as `not_leader`, naming the leader that has them.
    not_replicated = 2,
    /// No group owns the key.
    unrouted = 3,
    /// The node is not serving yet.
    loading = 4,
    /// The linearizable read's no-op did not commit.
    barrier_failed = 5,
};

inline constexpr std::uint8_t k_read_status_max = 5;

/// A decoded read answer.
template<typename NodeId> struct read_outcome {
    read_status status = read_status::loading;
    /// `ok`: whether the key exists here.
    bool found = false;
    std::uint64_t expire_at_ms = 0;
    std::string value;
    /// `not_leader`, `not_replicated`.
    std::optional<NodeId> leader;
};

/// `ok` for a present key.
[[nodiscard]] inline auto encode_read_value(std::uint64_t expire_at_ms, std::string_view value)
    -> std::string {
    std::string out{static_cast<char>(read_status::ok), '\1'};
    detail::put_varint(out, expire_at_ms);
    detail::put_bytes(out, value);
    return out;
}

/// `ok` for a missing key.
[[nodiscard]] inline auto encode_read_miss() -> std::string {
    return std::string{static_cast<char>(read_status::ok), '\0'};
}

/// `not_leader` or `not_replicated` with the leader to ask, when known.
template<typename NodeId>
[[nodiscard]] auto encode_read_elsewhere(read_status status, const std::optional<NodeId>& leader)
    -> std::string {
    std::string out(1, static_cast<char>(status));
    out.push_back(leader ? '\1' : '\0');
    if (leader) {
        detail::put_bytes(out, detail::node_text(*leader));
    }
    return out;
}

/// `unrouted`, `loading` and `barrier_failed`.
[[nodiscard]] inline auto encode_read_status(read_status status) -> std::string {
    return std::string(1, static_cast<char>(status));
}

template<typename NodeId>
[[nodiscard]] auto decode_read(std::string_view bytes) -> std::optional<read_outcome<NodeId>> {
    if (bytes.empty() || static_cast<std::uint8_t>(bytes[0]) > k_read_status_max) {
        return std::nullopt;
    }
    read_outcome<NodeId> out;
    out.status = static_cast<read_status>(bytes[0]);
    detail::reader in(bytes.substr(1));
    switch (out.status) {
        case read_status::ok: {
            const auto has = in.byte();
            if (!has || *has > 1) {
                return std::nullopt;
            }
            if (*has == 1) {
                const auto expire = in.varint();
                auto value = expire ? in.bytes() : std::nullopt;
                if (!value) {
                    return std::nullopt;
                }
                out.found = true;
                out.expire_at_ms = *expire;
                out.value = std::move(*value);
            }
            break;
        }
        case read_status::not_leader:
        case read_status::not_replicated: {
            const auto has = in.byte();
            if (!has || *has > 1) {
                return std::nullopt;
            }
            if (*has == 1) {
                out.leader = detail::get_node<NodeId>(in);
                if (!out.leader) {
                    return std::nullopt;
                }
            }
            break;
        }
        case read_status::unrouted:
        case read_status::loading:
        case read_status::barrier_failed:
            break;
    }
    if (!in.done()) {
        return std::nullopt;
    }
    return out;
}

}  // namespace kythira::redis_data_wire
