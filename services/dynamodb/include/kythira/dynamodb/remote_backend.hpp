// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file remote_backend.hpp
/// @brief `dynamo_backend` for a node without the data role, and the
///        per-op mix of local and remote for a data node in a mixed
///        cluster (.kiro/specs/dynamodb-independent-layers/ task 3,
///        Requirement 3).
///
/// `remote_backend` sends every op (`op_client.hpp`, the same bytes
/// `raft_backend` runs) to a data node and runs none itself. It finds each
/// op's group, leader and replicas in a core `route_cache`, which it fills
/// from data nodes' `routes` answers, starting from the configured data
/// nodes. Every op goes out wrapped as a `routed` op naming the group and
/// epoch it was routed with and a key in that group's range, so a data node
/// whose map is newer answers with the current route instead of serving
/// (Requirement 3.6), and the cache corrects itself:
///
/// | Answer | What the cache does | Then |
/// |---|---|---|
/// | ok, error | nothing | return, throw |
/// | not the leader, try N | leader hint = N | send to N |
/// | stale epoch + route | takes the route | send again |
/// | unknown group | drops the row | refresh, send again |
/// | no answer (connection) | node suspect for a while | next replica |
///
/// A data node never forwards an op from a front end (`raft_backend::serve`
/// only answers "not the leader"), so an op crosses at most one data node
/// (Requirement 3.2). Writes, consistent reads, catalog ops and
/// transactions go to the leader; eventually consistent reads and pages go
/// to the nearest replica, voters before learners (Requirement 3.1). Range
/// reads page through groups with the data node's page bounds
/// (Requirement 3.4). An op aimed at one group (a page, a stream's shards)
/// whose group no longer holds its range throws `txn_stale_route`, which
/// the range read catches and re-resolves, as on a data node.
///
/// `hybrid_backend` is for a node with the data role in a cluster that
/// also has nodes without it: an op whose group this node holds (and
/// leads, when the op needs the leader) runs here through `raft_backend`,
/// any other through `remote_backend`, so the node needs no mode switch
/// (Requirement 3.3). Its leader-side work stays `raft_backend`'s. An
/// all-co-located cluster never builds one: `raft_backend` forwards to its
/// peers itself.

#include <kythira/dynamodb/backend.hpp>
#include <kythira/dynamodb/capacity.hpp>
#include <kythira/dynamodb/op_client.hpp>
#include <kythira/dynamodb/op_wire.hpp>

#include <raft/route_cache.hpp>
#include <raft/shard_types.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

/// The ops of a front end without the data role.
template<typename NodeId = std::uint64_t, typename GroupId = std::uint64_t>
class remote_backend : public op_client<remote_backend<NodeId, GroupId>,
                                        kythira::shard_descriptor<GroupId, std::string, NodeId>> {
public:
    using node_id_type = NodeId;
    using group_id_type = GroupId;
    using descriptor_type = kythira::shard_descriptor<GroupId, std::string, NodeId>;
    using cache_type = kythira::route_cache<GroupId, std::string, NodeId>;
    using clock_fn = std::function<std::uint64_t()>;
    /// Sends an op to the data node at `address` ("host:port") and returns
    /// its answer, or nothing when it cannot be reached. Blocking; must not
    /// throw.
    using sender = std::function<std::optional<std::string>(const std::string& address,
                                                            const std::string& op)>;

private:
    using client = op_client<remote_backend<NodeId, GroupId>, descriptor_type>;
    friend client;

public:
    using client::catalog;
    using client::change_shards;
    using client::describe;
    using client::list_tables;
    using client::read;
    using client::read_changes;
    using client::read_range;
    using client::read_stamped_range;
    using client::settle_item;
    using client::transact;
    using client::write;

    /// @param data_nodes addresses of data nodes to ask for routes first
    ///        (configuration or the layer membership group); the routes
    ///        they answer name the rest.
    remote_backend(std::vector<std::string> data_nodes, sender send,
                   raft_backend_options options = {},
                   clock_fn clock = local_backend<>::system_clock_ms(),
                   kythira::route_cache_options cache_options = {})
        : _send(std::move(send)),
          _options(options),
          _clock(std::move(clock)),
          _throttler(options.capacity_share),
          _routes(
              std::move(data_nodes),
              [this](const std::string& address, const kythira::shard_range<std::string>& r) {
                  return fetch_routes(address, r);
              },
              cache_options),
          _txn(*this) {}

    remote_backend(const remote_backend&) = delete;
    auto operator=(const remote_backend&) -> remote_backend& = delete;
    remote_backend(remote_backend&&) = delete;
    auto operator=(remote_backend&&) -> remote_backend& = delete;
    ~remote_backend() = default;

    auto now_ms() -> std::uint64_t { return _clock(); }

    /// This front end's capacity buckets, holding `capacity_share` of each
    /// limit.
    auto throttler() -> capacity_throttler& { return _throttler; }

    /// The route cache, for metrics and tests.
    [[nodiscard]] auto routes() -> cache_type& { return _routes; }

    /// Runs `op`, aimed at group `desc` when set, else at the group owning
    /// `route.key`, on the data node the routes name, until it is served
    /// or the deadline passes. Public so `hybrid_backend` can hand it ops.
    auto run(const std::string& op, const std::optional<descriptor_type>& desc,
             const op_route& route) -> std::string {
        using raft_backend_detail::answer_tag;
        const auto deadline = std::chrono::steady_clock::now() + _options.deadline;
        std::optional<descriptor_type> aimed = desc;
        std::size_t hops = 0;
        for (;;) {
            // The route: the aimed group's newest known row, else the row
            // owning the key.
            std::optional<descriptor_type> d;
            std::string key = route.key;
            if (aimed) {
                key = aimed->_range._start.value_or(std::string());
                d = aimed;
                if (auto cached = _routes.lookup(key); cached &&
                                                       cached->_group_id == aimed->_group_id &&
                                                       cached->_epoch >= aimed->_epoch) {
                    d = cached;
                }
            } else {
                d = _routes.ensure(key);
            }
            std::vector<NodeId> targets;
            if (d) {
                targets = targets_for(*d, key, route.leader);
            }
            bool retry_now = false;
            for (const auto& node : targets) {
                const auto address = _routes.address_of(node);
                if (!address) {
                    continue;
                }
                const auto answer = _send(*address, raft_backend_detail::routed_op(*d, key, op));
                if (!answer || answer->empty()) {
                    _routes.on_connection_failure(node);
                    continue;
                }
                const auto tag = static_cast<answer_tag>((*answer)[0]);
                const auto body = std::string_view(*answer).substr(1);
                switch (tag) {
                    case answer_tag::ok:
                        return answer->substr(1);
                    case answer_tag::error:
                        throw std::runtime_error("remote_backend: " + std::string(body));
                    case answer_tag::stale_route:
                        throw txn_stale_route("remote_backend: the transaction's keys moved");
                    case answer_tag::not_leader: {
                        const auto hint = decode_hint(body);
                        _routes.on_not_leader(d->_group_id, hint);
                        if (aimed && hint) {
                            aimed->_leader_hint = hint;
                        }
                        if (hint && hint != node && hops < _options.max_hops) {
                            ++hops;
                            retry_now = true;
                        }
                        break;
                    }
                    case answer_tag::stale_epoch: {
                        detail::reader in(body);
                        auto current = raft_backend_detail::get_descriptor<descriptor_type>(in);
                        if (!current) {
                            throw std::runtime_error("remote_backend: unreadable route");
                        }
                        _routes.on_stale_epoch(*current);
                        if (aimed) {
                            if (current->_group_id != aimed->_group_id) {
                                throw txn_stale_route("remote_backend: the group moved");
                            }
                            aimed = std::move(*current);
                        }
                        retry_now = true;
                        break;
                    }
                    case answer_tag::unknown_group:
                        _routes.on_unknown_group(d->_group_id);
                        if (aimed) {
                            throw txn_stale_route("remote_backend: the group is gone");
                        }
                        retry_now = true;
                        break;
                    default:
                        throw std::runtime_error("remote_backend: unknown answer");
                }
                if (retry_now) {
                    break;
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error(
                    "remote_backend: no data node served the op before the deadline");
            }
            if (!retry_now) {
                // No replica answered, or none knows the leader yet (an
                // election): pause, look the routes up again, start over.
                std::this_thread::sleep_for(_options.retry_backoff);
                (void)_routes.refresh(
                    kythira::shard_range<std::string>{._start = key, ._end = std::nullopt});
                hops = 0;
            }
        }
    }

private:
    // -- What op_client needs ------------------------------------------------

    [[nodiscard]] auto options() const -> const raft_backend_options& { return _options; }
    [[nodiscard]] auto txn() -> typename client::txn_client& { return _txn; }
    [[nodiscard]] auto txn_now_ms() -> std::uint64_t { return _clock(); }
    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<descriptor_type> {
        return _routes.ensure(key);
    }

    /// Every cached group overlapping `range`, in key order, refreshed
    /// first when the cache does not cover it without a gap.
    [[nodiscard]] auto groups_in(const kythira::key_range& range) -> std::vector<descriptor_type> {
        auto rows = overlapping(range);
        if (!covers(rows, range)) {
            (void)_routes.refresh(to_shard_range(range));
            rows = overlapping(range);
        }
        return rows;
    }

    [[nodiscard]] auto edge_group(const kythira::key_range& range, bool forward)
        -> std::optional<descriptor_type> {
        const auto rows = groups_in(range);
        if (rows.empty()) {
            return std::nullopt;
        }
        return forward ? rows.front() : rows.back();
    }

    // -- Routing ------------------------------------------------------------

    [[nodiscard]] static auto to_shard_range(const kythira::key_range& r)
        -> kythira::shard_range<std::string> {
        kythira::shard_range<std::string> sr;
        sr._start = r.start;
        sr._end = r.end;
        return sr;
    }

    /// Whether two ranges share a key; a missing start is the lowest key
    /// and a missing end the highest.
    [[nodiscard]] static auto overlap(const kythira::shard_range<std::string>& a,
                                      const kythira::shard_range<std::string>& b) -> bool {
        const auto below = [](const std::optional<std::string>& start,
                              const std::optional<std::string>& end) {
            return !end || !start || *start < *end;
        };
        return below(a._start, b._end) && below(b._start, a._end);
    }

    [[nodiscard]] auto overlapping(const kythira::key_range& range) const
        -> std::vector<descriptor_type> {
        const auto sr = to_shard_range(range);
        std::vector<descriptor_type> out;
        for (auto& d : _routes.routes()) {
            if (overlap(d._range, sr)) {
                out.push_back(std::move(d));
            }
        }
        return out;
    }

    /// Whether `rows` (in key order) cover `range` without a gap.
    [[nodiscard]] static auto covers(const std::vector<descriptor_type>& rows,
                                     const kythira::key_range& range) -> bool {
        if (rows.empty()) {
            return range.empty();
        }
        std::optional<std::string> reached = range.start;
        for (const auto& d : rows) {
            if (d._range._start && reached && *d._range._start > *reached) {
                return false;
            }
            if (!d._range._end) {
                return true;
            }
            reached = d._range._end;
        }
        return range.end && reached && *reached >= *range.end;
    }

    /// The nodes to try for `key` in group row `d`: the leader first for
    /// ops that need it, the nearest replica otherwise; the row's own
    /// members when the cache has no row for the key.
    [[nodiscard]] auto targets_for(const descriptor_type& d, const std::string& key,
                                   bool leader) const -> std::vector<NodeId> {
        auto out = leader ? _routes.write_targets(key) : _routes.read_targets(key);
        const auto cached = _routes.lookup(key);
        if (out.empty() || !cached || cached->_group_id != d._group_id) {
            out.clear();
            if (d._leader_hint) {
                out.push_back(*d._leader_hint);
            }
            for (const auto* nodes : {&d._voters, &d._learners}) {
                for (const auto& n : *nodes) {
                    if (std::find(out.begin(), out.end(), n) == out.end()) {
                        out.push_back(n);
                    }
                }
            }
        }
        return out;
    }

    /// Asks the data node at `address` for the routes of `range`.
    auto fetch_routes(const std::string& address, const kythira::shard_range<std::string>& range)
        -> std::optional<typename cache_type::routes_reply> {
        std::string op(1, static_cast<char>(raft_backend_detail::op_tag::routes));
        raft_backend_detail::put_range(
            op,
            kythira::key_range{.start = range._start.value_or(std::string()), .end = range._end});
        const auto answer = _send(address, op);
        if (!answer || answer->empty() ||
            (*answer)[0] != static_cast<char>(raft_backend_detail::answer_tag::ok)) {
            return std::nullopt;
        }
        auto decoded = raft_backend_detail::decode_routes<descriptor_type, NodeId>(
            std::string_view(*answer).substr(1));
        if (!decoded) {
            return std::nullopt;
        }
        typename cache_type::routes_reply reply;
        reply.routes = std::move(decoded->routes);
        reply.addresses = std::move(decoded->addresses);
        return reply;
    }

    [[nodiscard]] static auto decode_hint(std::string_view body) -> std::optional<NodeId> {
        detail::reader in(body);
        const auto has = in.byte();
        if (!has || *has != 1) {
            return std::nullopt;
        }
        const auto text = in.bytes();
        if (!text) {
            return std::nullopt;
        }
        return kythira::node_id_traits<NodeId>::from_text(*text);
    }

    sender _send;
    raft_backend_options _options;
    clock_fn _clock;
    capacity_throttler _throttler;
    cache_type _routes;
    /// Last, so its send threads are joined before anything they use goes.
    typename client::txn_client _txn;
};

/// The ops of a data node in a cluster that also has nodes without the
/// data role: here when this node holds the group (and leads it, for ops
/// that need the leader), else remote.
template<typename RaftBackend>
class hybrid_backend
    : public op_client<hybrid_backend<RaftBackend>, typename RaftBackend::descriptor_type> {
public:
    using local_type = RaftBackend;
    using node_id_type = typename RaftBackend::node_id_type;
    using group_id_type = typename RaftBackend::group_id_type;
    using descriptor_type = typename RaftBackend::descriptor_type;
    using remote_type = remote_backend<node_id_type, group_id_type>;

private:
    using client = op_client<hybrid_backend<RaftBackend>, descriptor_type>;
    friend client;

public:
    using client::catalog;
    using client::change_shards;
    using client::describe;
    using client::list_tables;
    using client::read;
    using client::read_changes;
    using client::read_range;
    using client::read_stamped_range;
    using client::settle_item;
    using client::transact;
    using client::write;

    hybrid_backend(RaftBackend& local, remote_type& remote, raft_backend_options options = {})
        : _local(local), _remote(remote), _options(options), _txn(*this) {}

    hybrid_backend(const hybrid_backend&) = delete;
    auto operator=(const hybrid_backend&) -> hybrid_backend& = delete;
    hybrid_backend(hybrid_backend&&) = delete;
    auto operator=(hybrid_backend&&) -> hybrid_backend& = delete;
    ~hybrid_backend() = default;

    auto now_ms() -> std::uint64_t { return _local.now_ms(); }
    auto throttler() -> capacity_throttler& { return _local.throttler(); }

    /// The leader-side workers run where this node leads the catalog.
    [[nodiscard]] auto leads_catalog() -> bool { return _local.leads_catalog(); }

    /// Ops peers forward to this node run on the local backend.
    auto serve(std::string_view op) -> std::string { return _local.serve(op); }

    /// Ops this node ran here, and ops it sent to other data nodes.
    [[nodiscard]] auto local_ops() const -> std::uint64_t { return _local_ops.load(); }
    [[nodiscard]] auto remote_ops() const -> std::uint64_t { return _remote_ops.load(); }

    auto run(const std::string& op, const std::optional<descriptor_type>& desc,
             const op_route& route) -> std::string {
        const auto group = desc ? desc : _local.group_of(route.key);
        if (group && holds(*group, route.leader)) {
            try {
                _local_ops.fetch_add(1);
                return _local.run(op, group, route);
            } catch (const txn_stale_route&) {
                throw;
            } catch (const std::exception&) {
                // Leadership moved off this node mid-call: the remote path
                // finds the new leader, wherever it is.
            }
        }
        _remote_ops.fetch_add(1);
        return _remote.run(op, desc, route);
    }

private:
    [[nodiscard]] auto holds(const descriptor_type& d, bool leader) -> bool {
        auto* n = _local.host().group_node(d._group_id);
        return n != nullptr && (!leader || n->is_leader());
    }

    [[nodiscard]] auto options() const -> const raft_backend_options& { return _options; }
    [[nodiscard]] auto txn() -> typename client::txn_client& { return _txn; }
    [[nodiscard]] auto txn_now_ms() -> std::uint64_t { return _local.txn_now_ms(); }
    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<descriptor_type> {
        return _local.group_of(key);
    }
    [[nodiscard]] auto groups_in(const kythira::key_range& range) -> std::vector<descriptor_type> {
        return _local.groups_in(range);
    }
    [[nodiscard]] auto edge_group(const kythira::key_range& range, bool forward)
        -> std::optional<descriptor_type> {
        return _local.edge_group(range, forward);
    }

    RaftBackend& _local;
    remote_type& _remote;
    raft_backend_options _options;
    std::atomic<std::uint64_t> _local_ops{0};
    std::atomic<std::uint64_t> _remote_ops{0};
    /// Last, so its send threads are joined before anything they use goes.
    typename client::txn_client _txn;
};

}  // namespace kythira::dynamodb
