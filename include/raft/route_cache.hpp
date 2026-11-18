// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file route_cache.hpp
/// @brief Routing for a node that is not a Raft member: routing-key ranges
///        to group, replicas, leader and data-node address
///        (.kiro/specs/kinesis-independent-layers/ task 5, design "Route
///        cache, not a placement service", Requirement 6).
///
/// A front end that holds no replica still has to send each write to its
/// group's leader and each read to a nearby replica. The data nodes already
/// know where everything is (every `multi_raft` host keeps a `shard_map`
/// with leader hints), so a front end asks any data node for the routes of
/// a key range and keeps the answer:
///
///  - `route_cache` is the front end's side. Rows are `shard_descriptor`s,
///    each stamped with its group's epoch, held in a `shard_map`. It is
///    refreshed by a `routes` answer, and corrected by the four signals a
///    call can return: not leader (with a hint), unknown group, a stale
///    epoch (with the current route), and a connection failure (the
///    address becomes suspect for a while and another replica is tried).
///    Data-node names are resolved with `net_resolve` at use, never stored
///    as addresses, so containers that move keep working.
///  - `routes_answer` and `check_route` are the data node's side: the
///    answer to a `routes(range)` call from the host's shard map, and the
///    check an incoming data-layer call's epoch gets before it is served.
///    A call routed with an older epoch, or to a group whose range no
///    longer holds the key, is answered with the current route rather than
///    served.
///
/// This is the region-cache pattern of smart clients; it needs no new
/// replicated service. Nothing here knows about Kinesis: routing keys,
/// group ids and node ids are the `multi_raft` template parameters.
///
/// ## Epoch rules
///
/// `shard_epoch::_version` grows on every range change (a split gives its
/// children `parent + N`, a merge gives the survivor `max + 1`), and
/// `_conf_version` on every membership change. A row from an answer is
/// accepted only when no cached row overlapping it has a higher `_version`
/// and the same group's cached row is not newer, so answers that arrive out
/// of order never move the cache backwards; accepted rows evict the older
/// rows they overlap. An answer for the same epoch only refreshes the
/// leader hint.

#include <raft/bounded_resolver.hpp>
#include <raft/shard_map.hpp>
#include <raft/shard_types.hpp>

#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kythira {

// ---------------------------------------------------------------------------
// Data-node side
// ---------------------------------------------------------------------------

/// Every route overlapping `range` in the host's map, in key order: the
/// answer to a `routes(range)` call.
template<raft_group_id GroupId, shard_key Key, typename NodeId>
[[nodiscard]] auto routes_answer(const shard_map<GroupId, Key, NodeId>& map,
                                 const shard_range<Key>& range)
    -> std::vector<shard_descriptor<GroupId, Key, NodeId>> {
    return map.range_scan(range);
}

/// As above, with each row's leader hint taken from `leader_of` where it
/// knows one: a host knows the current leader of every group it holds a
/// replica of, which is fresher than the hint its map row carries.
template<raft_group_id GroupId, shard_key Key, typename NodeId, typename LeaderOf>
requires std::is_invocable_r_v<std::optional<NodeId>, LeaderOf, const GroupId&>
[[nodiscard]] auto routes_answer(const shard_map<GroupId, Key, NodeId>& map,
                                 const shard_range<Key>& range, LeaderOf&& leader_of)
    -> std::vector<shard_descriptor<GroupId, Key, NodeId>> {
    auto rows = map.range_scan(range);
    for (auto& row : rows) {
        if (auto leader = std::invoke(leader_of, row._group_id)) {
            row._leader_hint = std::move(leader);
        }
    }
    return rows;
}

/// What a data node does with an incoming call routed to `group` at an
/// epoch for `key`.
enum class route_check_kind : std::uint8_t {
    /// The caller's route is current: serve the call.
    current,
    /// The caller's route is older than this node's, or the key is no
    /// longer in the group's range: answer with `route` instead of serving.
    stale,
    /// This node knows no such group (merged away, or never here): answer
    /// unknown group so the caller refreshes.
    unknown_group,
};

template<raft_group_id GroupId, shard_key Key, typename NodeId> struct route_check_result {
    route_check_kind kind = route_check_kind::current;
    /// For `stale`: the route that now owns the key (or the group's current
    /// row when the key is in it).
    std::optional<shard_descriptor<GroupId, Key, NodeId>> route;
};

/// Checks a call's route against the host's map. A caller whose epoch is
/// *newer* than this node's row is served: the row here is a cache of the
/// group's own state and lags it, so refusing would only bounce the call.
template<raft_group_id GroupId, shard_key Key, typename NodeId>
[[nodiscard]] auto check_route(const shard_map<GroupId, Key, NodeId>& map, const GroupId& group,
                               const shard_epoch& caller_epoch, const Key& key)
    -> route_check_result<GroupId, Key, NodeId> {
    route_check_result<GroupId, Key, NodeId> out;
    const auto row = map.find(group);
    if (!row) {
        if (auto owner = map.lookup(key)) {
            out.kind = route_check_kind::stale;
            out.route = std::move(owner);
            return out;
        }
        out.kind = route_check_kind::unknown_group;
        return out;
    }
    if (!row->_range.contains(key)) {
        out.kind = route_check_kind::stale;
        out.route = map.lookup(key);
        if (!out.route) {
            out.kind = route_check_kind::unknown_group;
        }
        return out;
    }
    if (caller_epoch._version < row->_epoch._version ||
        caller_epoch._conf_version < row->_epoch._conf_version) {
        out.kind = route_check_kind::stale;
        out.route = row;
        return out;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Front-end side
// ---------------------------------------------------------------------------

/// "host:port" split at the last colon; "[v6]:port" has its brackets
/// removed. `nullopt` when there is no port.
[[nodiscard]] inline auto split_host_port(const std::string& address)
    -> std::optional<std::pair<std::string, std::string>> {
    const auto colon = address.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 == address.size()) {
        return std::nullopt;
    }
    std::string host = address.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    } else if (host.find(':') != std::string::npos) {
        return std::nullopt;  // an unbracketed IPv6 literal is ambiguous
    }
    auto port = address.substr(colon + 1);
    if (!std::ranges::all_of(port, [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    return std::pair{std::move(host), std::move(port)};
}

struct route_cache_options {
    /// How long an address stays at the back of every order after a
    /// connection to it failed.
    std::chrono::milliseconds suspect_for{std::chrono::seconds(5)};
    /// How long `resolve` waits for a name.
    std::chrono::milliseconds resolve_timeout{std::chrono::seconds(2)};
};

struct route_cache_stats {
    std::uint64_t refreshes = 0;
    std::uint64_t refresh_failures = 0;
    std::uint64_t rows_accepted = 0;
    /// Rows refused because a cached row was newer.
    std::uint64_t rows_ignored_stale = 0;
    std::uint64_t not_leader = 0;
    std::uint64_t stale_epoch = 0;
    std::uint64_t unknown_group = 0;
    std::uint64_t connection_failures = 0;
};

/// The front end's routing table. Thread-safe; the fetcher is called
/// without the lock held.
template<raft_group_id GroupId, shard_key Key, typename NodeId = std::uint64_t>
requires node_id<NodeId>
class route_cache {
public:
    using descriptor_type = shard_descriptor<GroupId, Key, NodeId>;
    using map_type = shard_map<GroupId, Key, NodeId>;
    using clock = std::chrono::steady_clock;

    /// A data node's answer to `routes(range)`: the rows, and where each
    /// node named in them listens ("host:port", a name or a literal).
    struct routes_reply {
        std::vector<descriptor_type> routes;
        std::vector<std::pair<NodeId, std::string>> addresses;
    };

    /// Asks the data node at `address` for the routes of `range`;
    /// `nullopt` when it cannot be reached or refuses.
    using fetcher = std::function<std::optional<routes_reply>(const std::string& address,
                                                              const shard_range<Key>& range)>;

    /// `seeds` are data-node addresses from configuration
    /// (`KINESIS_DATA_NODES`) or the layer membership group, asked when no
    /// known node answers.
    route_cache(std::vector<std::string> seeds, fetcher fetch, route_cache_options options = {})
        : _seeds(std::move(seeds)), _fetch(std::move(fetch)), _options(options) {}

    // ---- queries --------------------------------------------------------

    /// The cached route for `key`.
    [[nodiscard]] auto lookup(const Key& key) const -> std::optional<descriptor_type> {
        const std::lock_guard lock(_mu);
        return _map.lookup(key);
    }

    /// The cached route for `key`, refreshing the range from `key` up when
    /// there is none. `nullopt` when no data node could answer.
    [[nodiscard]] auto ensure(const Key& key) -> std::optional<descriptor_type> {
        if (auto r = lookup(key)) {
            return r;
        }
        refresh(shard_range<Key>{._start = key, ._end = std::nullopt});
        return lookup(key);
    }

    /// Every cached route, in key order.
    [[nodiscard]] auto routes() const -> std::vector<descriptor_type> {
        const std::lock_guard lock(_mu);
        return _map.descriptors();
    }

    [[nodiscard]] auto address_of(const NodeId& node) const -> std::optional<std::string> {
        const std::lock_guard lock(_mu);
        const auto it = _addresses.find(node);
        if (it == _addresses.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] auto suspect(const NodeId& node) const -> bool {
        const std::lock_guard lock(_mu);
        return suspect_locked(node, clock::now());
    }

    /// Where to send a write for `key`, in order: the leader hint, then the
    /// other voters, with suspect nodes moved to the back. A call that gets
    /// not-leader reports it (`on_not_leader`) and asks again. Empty when
    /// the key has no cached route.
    [[nodiscard]] auto write_targets(const Key& key) const -> std::vector<NodeId> {
        const std::lock_guard lock(_mu);
        const auto row = _map.lookup(key);
        if (!row) {
            return {};
        }
        std::vector<NodeId> out;
        if (row->_leader_hint) {
            out.push_back(*row->_leader_hint);
        }
        for (const auto& v : row->_voters) {
            if (std::ranges::find(out, v) == out.end()) {
                out.push_back(v);
            }
        }
        return suspects_last_locked(std::move(out));
    }

    /// Where to send a read for `key`, in order: `self` when it holds a
    /// replica, then replicas in the caller's placement group
    /// (`same_placement`), then the rest, voters before learners within
    /// each, suspect nodes last.
    [[nodiscard]] auto read_targets(
        const Key& key, const std::optional<NodeId>& self = std::nullopt,
        const std::function<bool(const NodeId&)>& same_placement = {}) const
        -> std::vector<NodeId> {
        const std::lock_guard lock(_mu);
        const auto row = _map.lookup(key);
        if (!row) {
            return {};
        }
        std::vector<NodeId> replicas = row->_voters;
        replicas.insert(replicas.end(), row->_learners.begin(), row->_learners.end());
        std::vector<NodeId> out;
        if (self && row->has_replica(*self)) {
            out.push_back(*self);
        }
        if (same_placement) {
            for (const auto& n : replicas) {
                if (same_placement(n) && std::ranges::find(out, n) == out.end()) {
                    out.push_back(n);
                }
            }
        }
        for (const auto& n : replicas) {
            if (std::ranges::find(out, n) == out.end()) {
                out.push_back(n);
            }
        }
        return suspects_last_locked(std::move(out));
    }

    [[nodiscard]] auto stats() const -> route_cache_stats {
        const std::lock_guard lock(_mu);
        return _stats;
    }

    // ---- updates --------------------------------------------------------

    /// Merges a `routes` answer. Returns how many rows were accepted.
    auto learn(const routes_reply& reply) -> std::size_t {
        const std::lock_guard lock(_mu);
        for (const auto& [node, address] : reply.addresses) {
            if (!address.empty()) {
                _addresses[node] = address;
            }
        }
        std::size_t accepted = 0;
        for (const auto& d : reply.routes) {
            if (learn_locked(d)) {
                ++accepted;
            }
        }
        return accepted;
    }

    /// A call to `group` was refused by a node that is not its leader;
    /// `hint` is the leader it named, if any.
    void on_not_leader(const GroupId& group, const std::optional<NodeId>& hint) {
        const std::lock_guard lock(_mu);
        ++_stats.not_leader;
        auto row = _map.find(group);
        if (!row || row->_leader_hint == hint) {
            return;
        }
        row->_leader_hint = hint;
        _map.erase_group(group);
        _map.upsert(*row);
    }

    /// A node answered that it knows no such group: the row is dropped so
    /// the next call refreshes.
    void on_unknown_group(const GroupId& group) {
        const std::lock_guard lock(_mu);
        ++_stats.unknown_group;
        _map.erase_group(group);
    }

    /// A node refused a call whose epoch was stale and sent the current
    /// route.
    void on_stale_epoch(const descriptor_type& current) {
        const std::lock_guard lock(_mu);
        ++_stats.stale_epoch;
        learn_locked(current);
    }

    /// A connection to `node` failed: it goes to the back of every order
    /// for `suspect_for`, a leader hint naming it is dropped, and the name
    /// it resolved to is reported unreachable so the next resolve looks it
    /// up again.
    void on_connection_failure(const NodeId& node) {
        std::optional<std::string> address;
        {
            const std::lock_guard lock(_mu);
            ++_stats.connection_failures;
            _suspect_until[node] = clock::now() + _options.suspect_for;
            for (auto row : _map.descriptors()) {
                if (row._leader_hint == node) {
                    row._leader_hint.reset();
                    _map.erase_group(row._group_id);
                    _map.upsert(row);
                }
            }
            if (const auto it = _addresses.find(node); it != _addresses.end()) {
                address = it->second;
            }
        }
        if (address) {
            if (auto hp = split_host_port(*address)) {
                net_resolve::mark_unreachable(hp->first, hp->second, SOCK_STREAM);
            }
        }
    }

    /// Asks data nodes for the routes of `range`: known nodes that are not
    /// suspect first, then the seeds, then suspect nodes. The first answer
    /// is merged. Returns whether any node answered.
    auto refresh(const shard_range<Key>& range) -> bool {
        std::vector<std::string> order;
        {
            const std::lock_guard lock(_mu);
            ++_stats.refreshes;
            const auto now = clock::now();
            std::vector<std::string> later;
            for (const auto& [node, address] : _addresses) {
                (suspect_locked(node, now) ? later : order).push_back(address);
            }
            for (const auto& s : _seeds) {
                if (std::ranges::find(order, s) == order.end() &&
                    std::ranges::find(later, s) == later.end()) {
                    order.push_back(s);
                }
            }
            order.insert(order.end(), later.begin(), later.end());
        }
        for (const auto& address : order) {
            auto reply = _fetch(address, range);
            if (reply) {
                learn(*reply);
                return true;
            }
        }
        const std::lock_guard lock(_mu);
        ++_stats.refresh_failures;
        return false;
    }

    /// The addresses `node`'s name resolves to now, through `net_resolve`
    /// (names are resolved at use, never pinned). `nullopt` when the node
    /// has no known address or the name does not resolve in time.
    [[nodiscard]] auto resolve(const NodeId& node) const
        -> std::optional<std::vector<net_resolve::resolved_address>> {
        const auto address = address_of(node);
        if (!address) {
            return std::nullopt;
        }
        const auto hp = split_host_port(*address);
        if (!hp) {
            return std::nullopt;
        }
        return net_resolve::resolve(hp->first, hp->second, SOCK_STREAM, _options.resolve_timeout);
    }

private:
    [[nodiscard]] auto suspect_locked(const NodeId& node, clock::time_point now) const -> bool {
        const auto it = _suspect_until.find(node);
        return it != _suspect_until.end() && it->second > now;
    }

    [[nodiscard]] auto suspects_last_locked(std::vector<NodeId> nodes) const
        -> std::vector<NodeId> {
        const auto now = clock::now();
        std::ranges::stable_partition(nodes,
                                      [&](const NodeId& n) { return !suspect_locked(n, now); });
        return nodes;
    }

    /// Accepts `d` unless the cache already knows something newer about its
    /// group or its range.
    auto learn_locked(const descriptor_type& d) -> bool {
        if (d._range.is_empty()) {
            ++_stats.rows_ignored_stale;
            return false;
        }
        if (const auto mine = _map.find(d._group_id)) {
            if (d._epoch < mine->_epoch) {
                ++_stats.rows_ignored_stale;
                return false;
            }
            if (d._epoch == mine->_epoch) {
                // Same generation: only the leader hint can be fresher.
                if (d._leader_hint && d._leader_hint != mine->_leader_hint) {
                    auto row = *mine;
                    row._leader_hint = d._leader_hint;
                    _map.erase_group(row._group_id);
                    _map.upsert(row);
                }
                return false;
            }
        }
        for (const auto& row : _map.range_scan(d._range)) {
            if (row._group_id != d._group_id && row._epoch._version > d._epoch._version) {
                ++_stats.rows_ignored_stale;
                return false;
            }
        }
        // Evict every other overlapping row: `shard_map::upsert` evicts only
        // strictly older versions, and a row overlapping an accepted one at
        // the same version is a leftover of a layout this answer replaces.
        for (const auto& row : _map.range_scan(d._range)) {
            if (row._group_id != d._group_id) {
                _map.erase_group(row._group_id);
            }
        }
        _map.erase_group(d._group_id);
        _map.upsert(d);
        ++_stats.rows_accepted;
        return true;
    }

    mutable std::mutex _mu;
    map_type _map;
    std::unordered_map<NodeId, std::string> _addresses;
    std::unordered_map<NodeId, clock::time_point> _suspect_until;
    std::vector<std::string> _seeds;
    fetcher _fetch;
    route_cache_options _options;
    route_cache_stats _stats;
};

}  // namespace kythira
