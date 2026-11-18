// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file op_wire.hpp
/// @brief The op protocol's wire forms and options, shared by the data
///        node's `raft_backend` and the callers in `op_client.hpp`
///        (.kiro/specs/dynamodb-independent-layers/ task 3). Moved out of
///        `raft_backend.hpp` unchanged; that file's table lists the ops.

#include <kythira/dynamodb/backend.hpp>
#include <kythira/dynamodb/capacity.hpp>
#include <kythira/dynamodb/item_codec.hpp>

#include <raft/composite_node_id.hpp>
#include <raft/txn_coordinator.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

/// Timeouts and sizes of a `raft_backend`.
struct raft_backend_options {
    /// One attempt's wait for a commit or a read barrier.
    std::chrono::milliseconds attempt_timeout{5000};
    /// A whole call's budget, across leader changes and hops.
    std::chrono::milliseconds deadline{15000};
    /// The pause before retrying when no node knows the leader.
    std::chrono::milliseconds retry_backoff{20};
    /// How often the catalog leader looks for follow-on work.
    std::chrono::milliseconds settle_interval{200};
    /// The most item bytes one range-read page carries.
    std::size_t page_bytes = std::size_t{1} << 20U;
    /// Hops one call may take before it starts over from this node.
    std::size_t max_hops = 4;
    /// Items deleted per drop step.
    std::uint32_t drop_step_keys = 1000;
    /// How often an item group's leader looks for GSI changes to carry when
    /// the last pass found none, and how many it takes from one group per
    /// pass (task 11).
    std::chrono::milliseconds gsi_interval{20};
    std::size_t gsi_batch = 64;
    /// How long a table looked up by id stays cached for the propagator.
    std::chrono::milliseconds table_cache_ttl{1000};
    /// How long a new GSI waits in CREATING before its backfill starts:
    /// longer than a write can be in flight, so no write that read the
    /// table before the index existed can land after the backfill passed
    /// its item. The default is the call deadline.
    std::chrono::milliseconds gsi_backfill_delay{15000};
    /// Items read and marked per backfill round.
    std::size_t gsi_backfill_batch = 256;
    /// Each transaction's lock TTL and budget (read committed: DynamoDB's
    /// transactions lock every item they touch).
    kythira::txn_options txn{};
    /// This node's part of every capacity limit (task 12, `capacity.hpp`):
    /// 1 enforces each limit whole on every node; `dynamodb_gateway_node`
    /// gives each of N voters 1/N.
    double capacity_share = 1.0;
    /// How often each item group's leader checks its change log for
    /// records past retention (task 16).
    std::chrono::milliseconds change_log_trim_interval{60000};
};

/// A transaction op's keys no longer share one group, or a page op's group
/// no longer holds the range it was sent for; the caller re-resolves and
/// sends again.
class txn_stale_route : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Where an op without a group must go: the key that picks its group, and
/// whether only that group's leader may serve it (writes, consistent
/// reads, the catalog) or any replica (eventually consistent reads).
struct op_route {
    std::string key;
    bool leader = true;
};

namespace raft_backend_detail {

/// The op tags.
enum class op_tag : std::uint8_t {
    catalog = 1,
    write = 2,
    read = 3,
    page = 4,
    describe = 5,
    list = 6,
    drop = 7,
    txn = 8,
    /// An item's pending GSI change, read with the item (task 11).
    pending = 9,
    /// The bytes of a change log segment this node holds (task 15), for a
    /// peer that installed a snapshot naming it.
    segment = 10,
    /// An item group's change log streams, as DynamoDB Streams shards
    /// (task 16).
    shards = 11,
    /// A page of one change log stream's records (task 16).
    changes = 12,
    /// Split a group at a table's boundary (task 27.6).
    isolate = 13,
    /// Remove a group's voters outside a kept set (task 27.6).
    shrink = 14,
    /// The routes of a key range, for a node outside Raft
    /// (.kiro/specs/dynamodb-independent-layers/ task 3): `routes_reply`.
    routes = 15,
    /// Another op with the route its sender used: group, epoch and a key
    /// in the group's range. Served only when that route is current here
    /// (`check_route`); else answered `stale_epoch` or `unknown_group`.
    routed = 16,
};

/// The answer tags.
enum class answer_tag : std::uint8_t {
    ok = 0,
    /// Not served here: retry on the hinted node, or after a pause.
    not_leader = 1,
    /// Failed; the text says why.
    error = 2,
    /// A txn op's keys span groups now (a split or merge): re-partition.
    stale_route = 3,
    /// A routed op's epoch is older than this node's: the payload is the
    /// current route (`put_descriptor`).
    stale_epoch = 4,
    /// A routed op named a group this node does not know: refresh routes.
    unknown_group = 5,
};

inline void put_range(std::string& out, const kythira::key_range& r) {
    detail::put_bytes(out, r.start);
    out.push_back(r.end ? '\1' : '\0');
    if (r.end) {
        detail::put_bytes(out, *r.end);
    }
}

[[nodiscard]] inline auto get_range(detail::reader& in) -> std::optional<kythira::key_range> {
    auto start = in.bytes();
    const auto has_end = in.byte();
    if (!start || !has_end || *has_end > 1) {
        return std::nullopt;
    }
    kythira::key_range r{.start = std::move(*start), .end = std::nullopt};
    if (*has_end == 1) {
        auto end = in.bytes();
        if (!end) {
            return std::nullopt;
        }
        r.end = std::move(*end);
    }
    return r;
}

/// `a ∩ b`.
[[nodiscard]] inline auto intersect(const kythira::key_range& a, const kythira::key_range& b)
    -> kythira::key_range {
    kythira::key_range out{.start = std::max(a.start, b.start), .end = a.end};
    if (b.end && (!out.end || *b.end < *out.end)) {
        out.end = b.end;
    }
    return out;
}

/// One page of a range read.
struct page {
    std::vector<std::pair<std::string, item>> items;
    /// More items remain in the group's part of the range after the last.
    bool more = false;
    /// The part of the asked range this group covers (it is all done when
    /// `more` is false).
    kythira::key_range covered;
    /// Each item's stamp, when the op asked for them (task 22).
    bool stamped = false;
    std::vector<std::optional<replica_stamp>> stamps;
};

[[nodiscard]] inline auto encode_page(const page& p) -> std::string {
    std::string out;
    detail::put_varint(out, p.items.size());
    for (const auto& [key, it] : p.items) {
        detail::put_bytes(out, key);
        detail::put_bytes(out, encode_item(it));
    }
    out.push_back(p.more ? '\1' : '\0');
    put_range(out, p.covered);
    // Stamps follow only when asked for, so a page without them reads as
    // it always did.
    if (p.stamped) {
        for (std::size_t i = 0; i < p.items.size(); ++i) {
            const auto& s = i < p.stamps.size() ? p.stamps[i] : std::nullopt;
            out.push_back(s ? '\1' : '\0');
            if (s) {
                detail::put_varint(out, s->written_ms);
                detail::put_bytes(out, s->region);
            }
        }
    }
    return out;
}

[[nodiscard]] inline auto decode_page(std::string_view bytes) -> std::optional<page> {
    detail::reader in(bytes);
    const auto n = in.count();
    if (!n) {
        return std::nullopt;
    }
    page p;
    for (std::size_t i = 0; i < *n; ++i) {
        auto key = in.bytes();
        auto raw = in.bytes();
        if (!key || !raw) {
            return std::nullopt;
        }
        auto it = decode_item(*raw);
        if (!it) {
            return std::nullopt;
        }
        p.items.emplace_back(std::move(*key), std::move(*it));
    }
    const auto more = in.byte();
    auto covered = get_range(in);
    if (!more || *more > 1 || !covered) {
        return std::nullopt;
    }
    p.more = *more == 1;
    p.covered = std::move(*covered);
    if (!in.done()) {
        p.stamped = true;
        for (std::size_t i = 0; i < p.items.size(); ++i) {
            const auto has = in.byte();
            if (!has || *has > 1) {
                return std::nullopt;
            }
            if (*has == 0) {
                p.stamps.emplace_back();
                continue;
            }
            const auto ms = in.varint();
            auto region = in.bytes();
            if (!ms || !region) {
                return std::nullopt;
            }
            p.stamps.emplace_back(replica_stamp{*ms, std::move(*region)});
        }
        if (!in.done()) {
            return std::nullopt;
        }
    }
    return p;
}

/// A shard descriptor: group, range, epoch, voters, learners and leader
/// hint, node ids as their text.
template<typename Descriptor> void put_descriptor(std::string& out, const Descriptor& d) {
    using node_type = std::remove_cvref_t<decltype(d._voters.front())>;
    using traits = kythira::node_id_traits<node_type>;
    detail::put_varint(out, static_cast<std::uint64_t>(d._group_id));
    for (const auto* bound : {&d._range._start, &d._range._end}) {
        out.push_back(bound->has_value() ? '\1' : '\0');
        if (bound->has_value()) {
            detail::put_bytes(out, **bound);
        }
    }
    detail::put_varint(out, d._epoch._version);
    detail::put_varint(out, d._epoch._conf_version);
    for (const auto* nodes : {&d._voters, &d._learners}) {
        detail::put_varint(out, nodes->size());
        for (const auto& n : *nodes) {
            detail::put_bytes(out, traits::to_text(n));
        }
    }
    out.push_back(d._leader_hint ? '\1' : '\0');
    if (d._leader_hint) {
        detail::put_bytes(out, traits::to_text(*d._leader_hint));
    }
}

template<typename Descriptor>
[[nodiscard]] auto get_descriptor(detail::reader& in) -> std::optional<Descriptor> {
    using node_type = std::remove_cvref_t<decltype(std::declval<Descriptor>()._voters.front())>;
    using group_type = std::remove_cvref_t<decltype(std::declval<Descriptor>()._group_id)>;
    using traits = kythira::node_id_traits<node_type>;
    Descriptor d{};
    const auto group = in.varint();
    if (!group) {
        return std::nullopt;
    }
    d._group_id = static_cast<group_type>(*group);
    for (auto* bound : {&d._range._start, &d._range._end}) {
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
    const auto version = in.varint();
    const auto conf = in.varint();
    if (!version || !conf) {
        return std::nullopt;
    }
    d._epoch._version = *version;
    d._epoch._conf_version = *conf;
    for (auto* nodes : {&d._voters, &d._learners}) {
        const auto n = in.count();
        if (!n) {
            return std::nullopt;
        }
        for (std::size_t i = 0; i < *n; ++i) {
            const auto text = in.bytes();
            auto id = text ? traits::from_text(*text) : std::nullopt;
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
        const auto text = in.bytes();
        auto id = text ? traits::from_text(*text) : std::nullopt;
        if (!id) {
            return std::nullopt;
        }
        d._leader_hint = std::move(id);
    }
    return d;
}

/// A `routes` answer: the routes of the asked range, and where each node
/// they name takes ops ("host:port"), for the nodes whose address the
/// serving node knows.
template<typename Descriptor, typename NodeId> struct routes_payload {
    std::vector<Descriptor> routes;
    std::vector<std::pair<NodeId, std::string>> addresses;
};

template<typename Descriptor, typename NodeId>
[[nodiscard]] auto encode_routes(const routes_payload<Descriptor, NodeId>& r) -> std::string {
    std::string out;
    detail::put_varint(out, r.routes.size());
    for (const auto& d : r.routes) {
        put_descriptor(out, d);
    }
    detail::put_varint(out, r.addresses.size());
    for (const auto& [node, address] : r.addresses) {
        detail::put_bytes(out, kythira::node_id_traits<NodeId>::to_text(node));
        detail::put_bytes(out, address);
    }
    return out;
}

template<typename Descriptor, typename NodeId>
[[nodiscard]] auto decode_routes(std::string_view bytes)
    -> std::optional<routes_payload<Descriptor, NodeId>> {
    detail::reader in(bytes);
    routes_payload<Descriptor, NodeId> out;
    const auto n = in.count();
    if (!n) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < *n; ++i) {
        auto d = get_descriptor<Descriptor>(in);
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
        const auto text = in.bytes();
        auto address = in.bytes();
        auto id = text ? kythira::node_id_traits<NodeId>::from_text(*text) : std::nullopt;
        if (!id || !address) {
            return std::nullopt;
        }
        out.addresses.emplace_back(std::move(*id), std::move(*address));
    }
    if (!in.done()) {
        return std::nullopt;
    }
    return out;
}

/// `op` wrapped as a `routed` op.
template<typename Descriptor>
[[nodiscard]] auto routed_op(const Descriptor& route, std::string_view key, std::string_view op)
    -> std::string {
    std::string out(1, static_cast<char>(op_tag::routed));
    detail::put_varint(out, static_cast<std::uint64_t>(route._group_id));
    detail::put_varint(out, route._epoch._version);
    detail::put_varint(out, route._epoch._conf_version);
    detail::put_bytes(out, key);
    detail::put_bytes(out, op);
    return out;
}

/// The smallest key after `key`.
[[nodiscard]] inline auto just_after(std::string key) -> std::string {
    key.push_back('\0');
    return key;
}

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

[[nodiscard]] inline auto view(const std::vector<std::byte>& b) -> std::string_view {
    return {reinterpret_cast<const char*>(b.data()), b.size()};  // NOLINT
}

}  // namespace raft_backend_detail

}  // namespace kythira::dynamodb
