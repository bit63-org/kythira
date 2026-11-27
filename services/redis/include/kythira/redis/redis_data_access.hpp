// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_data_access.hpp
/// @brief How the gateway and front end reach the data layer
///        (.kiro/specs/redis-general-data-types/ Requirement 16.5, design
///        Component 9 "Roles and composition", task 15).
///
/// Everything the command path does to data goes through a data access
/// object rather than straight to the `multi_raft` host: finding the group
/// that owns a key, proposing an entry to it, running a transaction
/// participant message, reading a key at a consistency, and allocating
/// oracle timestamps. These are the operations of the data-layer API
/// (`KYTHIRA.DATA ROUTE|PROPOSE|READ`, `KYTHIRA.TXN`), so that task 16 can
/// add a remote implementation over the internal link beside this local
/// one, and choose between them per call: a node holding a replica of the
/// group goes in-process, as today, and a node without one goes remote.
///
/// `redis_local_data_access` is today's code path, unchanged: the same host
/// calls in the same order, the same exceptions, the same retry hints. It
/// adds no hop, lock or copy, which is what keeps a co-located node's
/// latency where it was (Requirement 24.4).
///
/// Its outcomes are values (`redis_data_status`), not encoded RESP: the
/// caller turns them into wire errors, so a remote implementation reports
/// the same outcomes and the reply bytes stay the same whichever layout
/// serves them (Requirement 18.6). Proposals keep the host's exceptions
/// (`shard_not_leader_exception`, `key_locked_exception`, ...), which the
/// remote implementation will raise from the data node's answer.
///
/// The `local_*` members reach this node's own replicas: the data layer's
/// own jobs (sweeps, evictions, advisories, per-node `INFO` and `DBSIZE`
/// counts, the transaction forwarders) that only a node with `data` runs.

#include <kythira/redis/redis_gateway_value_access.hpp>
#include <kythira/redis/redis_remote_data_access.hpp>
#include <kythira/redis/redis_scan.hpp>
#include <raft/future_default.hpp>
#include <raft/route_cache.hpp>
#include <raft/shard_exceptions.hpp>
#include <raft/txn_state_machine.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira {

namespace redis_gateway_detail {
/// The KV state machine itself, whether or not the host wraps it in
/// `transactional_state_machine`. Intents are invisible to every plain read
/// (multi-raft-transactions Requirement 5.1), so plain reads look here.
template<typename SM> auto kv_of(SM& sm) -> auto& {
    if constexpr (is_transactional_state_machine_v<std::remove_const_t<SM>>) {
        return sm.inner();
    } else {
        return sm;
    }
}

/// The bytes a stored value holds: a typed entry's value or collection, or
/// a disk-backed manifest's length.
template<typename Entry> auto entry_bytes(const Entry& e) -> std::uint64_t {
    if constexpr (requires { redis_entry_bytes(e); }) {
        return redis_entry_bytes(e);
    } else {
        return e._total_len;
    }
}
}  // namespace redis_gateway_detail

/// Why the data layer could not serve a key here. `ok` is served.
enum class redis_data_status : std::uint8_t {
    ok = 0,
    /// The host is not running yet (or any more).
    loading,
    /// No group owns the key.
    unrouted,
    /// The group has no leader this node can serve from; the outcome's
    /// leader, when set, is where to send the command instead.
    no_leader,
    /// The entry's bytes are not all on this node yet (the disk-backed
    /// store); the outcome's leader has them.
    not_replicated,
    /// The read's barrier (the linearizable no-op) failed; the caller's
    /// barrier already said why.
    barrier_failed,
};

/// The data layer through this node's own `multi_raft` host. `Host` is a
/// `multi_raft<Types, std::string, std::uint64_t>` whose state machine
/// `redis_gateway_value_access` can read.
template<typename Host> class redis_local_data_access {
public:
    using node_id_type = typename Host::node_id_type;
    using group_id_type = typename Host::group_id_type;
    using group_node_type = typename Host::group_node_type;
    using state_machine_type = typename Host::types::state_machine_type;
    using value_access = redis_gateway_value_access<state_machine_type>;
    using entry_handle = typename value_access::entry_handle;
    using value_context = typename value_access::context;
    /// A group's routing row: id, key range, epoch, voters, leader hint.
    using route_type = typename decltype(std::declval<Host&>().resolve(
        std::declval<const std::string&>()))::value_type;

    /// A key read: the entry handle (null for a miss) and the context its
    /// bytes are read through, both taken under the group's lock so the
    /// bytes can be read after it is released; or why not.
    struct read_outcome {
        redis_data_status _status{redis_data_status::ok};
        entry_handle _entry;
        value_context _context{};
        /// Where to send the command instead, when known.
        std::optional<node_id_type> _leader;
    };

    /// A page of keys (`KYTHIRA.DATA PAGE`, task 12), or why not.
    struct page_outcome {
        redis_data_status _status{redis_data_status::ok};
        redis_scan_page _page;
        std::optional<node_id_type> _leader;
    };

    explicit redis_local_data_access(Host& host) noexcept : _host(host) {}

    // ── routing (KYTHIRA.DATA ROUTE) ────────────────────────────────────────

    [[nodiscard]] auto running() const -> bool { return _host.is_running(); }
    /// This node's id: a hint naming it is not somewhere else to go.
    [[nodiscard]] auto self() const -> node_id_type { return _host.node_id(); }
    /// The routing row of the group that owns `key`.
    [[nodiscard]] auto route(const std::string& key) const -> std::optional<route_type> {
        return _host.resolve(key);
    }
    /// The group that owns `key`.
    [[nodiscard]] auto group_of(const std::string& key) const -> std::optional<group_id_type> {
        if (auto r = _host.resolve(key)) {
            return r->group_id();
        }
        return std::nullopt;
    }
    /// Every routing row this node's map holds, in key order (empty while
    /// routing is still loading). `KYTHIRA.FORMAT UPGRADE` gates each one.
    [[nodiscard]] auto all_routes() const -> std::vector<route_type> {
        return routes_answer(_host.shard_map_snapshot(), shard_range<std::string>{});
    }
    /// The node to send a command for `key` to: the leader a local replica
    /// knows, else the routing row's hint, else any other voter (which can
    /// say who leads). `nullopt` when there is none.
    [[nodiscard]] auto leader_of(const std::string& key) const -> std::optional<node_id_type> {
        auto r = _host.resolve(key);
        if (!r) {
            return std::nullopt;
        }
        if (auto* node = _host.group_node(r->group_id()); node != nullptr) {
            return leader_seen_by(*node);
        }
        return elsewhere(*r);
    }
    /// The local replica of `key`'s group, or why there is none here. When
    /// the group has no replica on this node, `leader` names where to send
    /// the command: the routing row's leader hint, else another voter.
    [[nodiscard]] auto replica_for(const std::string& key, redis_data_status& status,
                                   std::optional<node_id_type>& leader) -> group_node_type* {
        if (!_host.is_running()) {
            status = redis_data_status::loading;
            return nullptr;
        }
        auto r = _host.resolve(key);
        if (!r) {
            status = redis_data_status::unrouted;
            return nullptr;
        }
        auto* node = _host.group_node(r->group_id());
        if (node == nullptr) {
            if (auto to = elsewhere(*r)) {
                leader = to;
            }
            status = redis_data_status::no_leader;
            return nullptr;
        }
        status = redis_data_status::ok;
        return node;
    }

    /// Every routing row overlapping `range`, in key order, with each row's
    /// leader hint replaced by the leader a local replica knows (fresher
    /// than the map's hint): the `KYTHIRA.DATA ROUTES` answer.
    [[nodiscard]] auto routes(const shard_range<std::string>& range) const {
        return routes_answer(_host.shard_map_snapshot(), range,
                             [this](const group_id_type& g) -> std::optional<node_id_type> {
                                 if (auto* node = _host.group_node(g); node != nullptr) {
                                     return leader_seen_by(*node);
                                 }
                                 return std::nullopt;
                             });
    }
    /// The full routing row (descriptor) that owns `key`, as `routes` gives
    /// it; empty when no group owns it.
    [[nodiscard]] auto route_row(const std::string& key) const {
        return routes(shard_range<std::string>{key, key + std::string(1, '\0')});
    }

    // ── proposals (KYTHIRA.DATA PROPOSE, KYTHIRA.TXN) ───────────────────────

    /// Proposes `entry` to the group owning `key`; the host's future and
    /// exceptions.
    auto propose(const std::string& key, const std::vector<std::byte>& entry,
                 std::chrono::milliseconds timeout) {
        return _host.submit_command(key, entry, timeout);
    }
    /// Proposes `entry`, which names every key in `keys`, to the group
    /// owning all of them; a key a split moved away refuses it with
    /// `shard_epoch_mismatch_exception` (redis_multi_key_exec.hpp).
    auto propose_keys(const std::vector<std::string>& keys, const std::vector<std::byte>& entry,
                      std::chrono::milliseconds timeout) {
        return _host.submit_multi_key_command(keys, entry, timeout);
    }
    /// Proposes `entry` to `group` at `epoch` (a leader's own maintenance).
    template<typename Epoch>
    auto propose_to(const group_id_type& group, const Epoch& epoch,
                    const std::vector<std::byte>& entry, std::chrono::milliseconds timeout) {
        return _host.submit_command(group, epoch, entry, timeout);
    }
    /// A transaction participant message for the group owning `keys`.
    auto propose_txn(const std::vector<std::string>& keys, const std::vector<std::byte>& envelope,
                     std::chrono::milliseconds timeout) {
        return _host.submit_txn(keys, envelope, timeout);
    }
    /// `n` timestamps from the oracle group.
    auto allocate_timestamps(std::size_t n, std::chrono::milliseconds timeout) {
        return _host.allocate_timestamps(n, timeout);
    }
    [[nodiscard]] auto txn_now_ms() const -> std::uint64_t { return _host.txn_now_ms(); }
    /// Takes newer routing rows a refusal carried.
    template<typename Routes> auto learn_routes(const Routes& routes) {
        return _host.learn_descriptors(routes);
    }

    // ── reads (KYTHIRA.DATA READ) ───────────────────────────────────────────

    /// Reads `key` from the local replica. Never `node::read_state()`, which
    /// serialises the whole group to answer one key: the lookup runs under
    /// the node mutex and takes only the shared handle, and everything else
    /// (expiry check, socket write) happens after the lock is released.
    ///
    /// @param any_replica Serve from any replica, which may lag; otherwise
    ///        only from a leader that has applied every write its
    ///        predecessor acknowledged.
    /// @param barrier Called on the leader before the lookup, for the
    ///        linearizable read's no-op; `false` ends the read with
    ///        `barrier_failed`. Pass `nullptr` for none.
    template<typename Barrier>
    auto read(const std::string& key, bool any_replica, Barrier&& barrier) -> read_outcome {
        read_outcome r;
        auto* node = replica_for(key, r._status, r._leader);
        if (node == nullptr) {
            return r;
        }
        if (!any_replica && !node->is_leader()) {
            r._leader = node->known_leader();
            r._status = redis_data_status::no_leader;
            return r;
        }
        if constexpr (!std::is_null_pointer_v<std::remove_cvref_t<Barrier>>) {
            if (!barrier()) {
                r._status = redis_data_status::barrier_failed;
                return r;
            }
        }
        auto lookup = [&key](auto& sm) {
            return std::pair{redis_gateway_detail::kv_of(sm).lookup(key),
                             value_access::context_of(sm)};
        };
        if (any_replica) {
            std::tie(r._entry, r._context) = node->with_state_machine(lookup);
        } else {
            // A leader elected a moment ago may not have applied every write
            // its predecessor acknowledged yet; answering from that state
            // would report an acknowledged SET as missing.
            auto entry = node->with_leader_state_machine(lookup);
            if (!entry) {
                if (!node->is_leader()) {
                    r._leader = node->known_leader();  // stepped down since the check
                }
                r._status = redis_data_status::no_leader;
                return r;
            }
            std::tie(r._entry, r._context) = std::move(*entry);
        }
        // A disk-backed entry whose chunks are not all here yet is
        // unservable on this node. A follower hands the read to the leader;
        // a leader answers it as a miss rather than wait. Every read path
        // goes through here, so EXISTS, STRLEN and TTL agree with GET.
        if (r._entry && !value_access::servable(*r._entry)) {
            if (!node->is_leader()) {
                if (auto leader = node->known_leader()) {
                    r._leader = leader;
                    r._status = redis_data_status::not_replicated;
                    return r;
                }
            }
            r._entry = nullptr;
        }
        return r;
    }
    /// One page of the group owning `from` (design Component 7): its keys
    /// in `[from, to)`, cut at the group's own range end, examining at most
    /// `count` live keys after skipping `skip` of them. `keep(key, type)`
    /// gives a `redis_scan_verdict` on this node (the user's scopes, then
    /// pattern and type), so a filtered key is never returned and a hidden
    /// one is not even counted (Requirement 7.6); at most
    /// `k_redis_scan_hidden_per_page` hidden keys are passed over per page
    /// so that a narrowly scoped user's call stays bounded. Expired keys are
    /// skipped and not examined. Served at the read's consistency: from any replica, or
    /// only from a leader, without a log entry.
    template<typename Keep>
    auto page(const std::string& from, const std::optional<std::string>& to, std::size_t count,
              std::size_t skip, bool any_replica, std::uint64_t now_ms, Keep&& keep)
        -> page_outcome {
        page_outcome out;
        walk_group(from, to, any_replica, out._status, out._leader,
                   [&](auto& kv, const std::optional<std::string>& bound,
                       const std::optional<std::string>& range_end) {
                       auto& p = out._page;
                       p._range_end = range_end;
                       p._approximate_keys = kv.approximate_key_count();
                       p._expiring_keys = kv.expiring_key_count();
                       std::size_t examined = 0;
                       std::size_t skipped = 0;
                       std::size_t hidden = 0;
                       p._exhausted = true;
                       kv.scan_keys(from, bound,
                                    [&](const std::string& key, std::uint64_t expire,
                                        redis_value_type type) {
                                        if (expire != 0 && expire <= now_ms) {
                                            return true;
                                        }
                                        if (skipped < skip) {
                                            ++skipped;
                                            return true;
                                        }
                                        if (examined == count) {
                                            p._exhausted = false;
                                            return false;
                                        }
                                        const redis_scan_verdict verdict = keep(key, type);
                                        if (verdict == redis_scan_verdict::hidden) {
                                            if (hidden == k_redis_scan_hidden_per_page) {
                                                p._exhausted = false;
                                                return false;
                                            }
                                            ++hidden;
                                            p._last = key;
                                            return true;
                                        }
                                        ++examined;
                                        ++p._examined;
                                        p._last = key;
                                        if (verdict == redis_scan_verdict::kept) {
                                            p._keys.push_back(key);
                                        }
                                        return true;
                                    });
                   });
        return out;
    }

    struct usage_outcome {
        redis_data_status _status{redis_data_status::ok};
        redis_usage_page _page;
        std::optional<node_id_type> _leader;
    };

    /// One page of `KYTHIRA.USAGE` over the group owning `from` (task 13,
    /// Requirement 8.4): up to `count` live keys of `[from, to)` the user
    /// may read, added to their buckets (`redis_usage_bucket`), without a
    /// log entry and at the read's consistency. At most `max_buckets`
    /// buckets; keys of any further bucket count as "other".
    template<typename Keep>
    auto usage(const std::string& from, const std::optional<std::string>& to, std::size_t count,
               bool any_replica, std::uint64_t now_ms, std::size_t depth, std::string_view delim,
               std::size_t max_buckets, Keep&& keep) -> usage_outcome {
        usage_outcome out;
        walk_group(from, to, any_replica, out._status, out._leader,
                   [&](auto& kv, const std::optional<std::string>& bound,
                       const std::optional<std::string>& range_end) {
                       auto& p = out._page;
                       p._range_end = range_end;
                       p._exhausted = true;
                       std::size_t examined = 0;
                       kv.scan_keys(
                           from, bound,
                           [&](const std::string& key, std::uint64_t expire, redis_value_type) {
                               if (expire != 0 && expire <= now_ms) {
                                   return true;
                               }
                               if (examined == count) {
                                   p._exhausted = false;
                                   return false;
                               }
                               ++examined;
                               p._last = key;
                               if (!keep(key)) {
                                   return true;
                               }
                               const auto entry = kv.lookup(key);
                               const std::uint64_t bytes =
                                   key.size() +
                                   (entry ? redis_gateway_detail::entry_bytes(*entry) : 0);
                               p.add(redis_usage_bucket(key, depth, delim), 1, bytes, max_buckets);
                               return true;
                           });
                   });
        return out;
    }

    /// Waits until every entry committed before the call is applied on
    /// `key`'s group here (a read index round through the host).
    auto read_barrier(const std::string& key, std::chrono::milliseconds timeout) {
        return _host.read_state(key, timeout);
    }

    // ── this node's own replicas (only a node with `data`) ─────────────────

    [[nodiscard]] auto local_replica(const group_id_type& group) -> group_node_type* {
        return _host.group_node(group);
    }
    [[nodiscard]] auto local_groups() const { return _host.group_ids(); }
    /// False for a group that holds no keys: the snapshot-isolation
    /// build's timestamp oracle group.
    [[nodiscard]] auto holds_keys(const group_id_type& group) const -> bool {
        if constexpr (requires { _host.is_oracle_group(group); }) {
            return !_host.is_oracle_group(group);
        } else {
            return true;
        }
    }
    [[nodiscard]] auto local_route(const group_id_type& group) const {
        return _host.local_descriptor(group);
    }
    template<typename F> auto with_local_state_machine(const group_id_type& group, F&& f) {
        return _host.with_group_state_machine(group, std::forward<F>(f));
    }
    /// The host itself, for wiring the data node's forwarders.
    [[nodiscard]] auto host() noexcept -> Host& { return _host; }

private:
    /// The leader `node` knows: itself when it leads (`known_leader` is the
    /// last leader it heard from, which for a leader is its predecessor),
    /// else the last leader it heard from.
    [[nodiscard]] auto leader_seen_by(group_node_type& node) const -> std::optional<node_id_type> {
        if (node.is_leader()) {
            return _host.node_id();
        }
        return node.known_leader();
    }

    /// Runs `f(kv, bound, range_end)` on the store of the group owning
    /// `from` under its lock: `bound` is `to` cut at the group's range end.
    /// The replica must be here (a leader unless `any_replica`); otherwise
    /// `status` and `leader` say where to go.
    template<typename F>
    auto walk_group(const std::string& from, const std::optional<std::string>& to, bool any_replica,
                    redis_data_status& status, std::optional<node_id_type>& leader, F&& f) -> void {
        auto* node = replica_for(from, status, leader);
        if (node == nullptr) {
            return;
        }
        if (!any_replica && !node->is_leader()) {
            leader = node->known_leader();
            status = redis_data_status::no_leader;
            return;
        }
        const auto group = _host.resolve(from);
        if (!group) {
            status = redis_data_status::unrouted;
            return;
        }
        auto served =
            _host.with_group_state_machine(group->group_id(), [&](auto& sm, const auto& d) -> bool {
                if (!d._range.contains(from)) {
                    return false;  // a split or merge moved it: route again
                }
                std::optional<std::string> bound = to;
                if (d._range._end && (!bound || *d._range._end < *bound)) {
                    bound = d._range._end;
                }
                f(redis_gateway_detail::kv_of(sm), bound, d._range._end);
                return true;
            });
        if (!served || !*served) {
            status = redis_data_status::unrouted;
        }
    }

    /// Another node that can say who leads `r`'s group: its leader hint,
    /// else its first other voter.
    [[nodiscard]] auto elsewhere(const route_type& r) const -> std::optional<node_id_type> {
        if (r.leader_hint() && *r.leader_hint() != _host.node_id()) {
            return r.leader_hint();
        }
        for (const auto& voter : r.voters()) {
            if (voter != _host.node_id()) {
                return voter;
            }
        }
        return std::nullopt;
    }

    Host& _host;
};

/// The data layer as the front end reaches it, choosing per call
/// (Requirement 18.4): a key whose group has a replica on this node goes
/// in-process through `redis_local_data_access`, exactly as before, and a
/// key whose group has none goes to the data nodes over `KYTHIRA.DATA`
/// through `redis_remote_data_access`, once one is attached.
///
/// Only a node without the `data` role attaches one (its host holds no
/// groups, so every call goes remote). A node with `data` never does: a key
/// led elsewhere keeps today's one-hop forward of the whole command, and
/// every call pays one null check for the choice (Requirement 24.4).
///
/// The remote half needs the value's bytes in the answer, so it serves the
/// in-memory and engine stores, whose entries hold their bytes; the
/// disk-backed store's entries name chunks on the data node, and a front
/// end without data is refused for it at start.
template<typename Host> class redis_data_access : public redis_local_data_access<Host> {
public:
    using local_type = redis_local_data_access<Host>;
    using typename local_type::entry_handle;
    using typename local_type::group_id_type;
    using typename local_type::group_node_type;
    using typename local_type::node_id_type;
    using typename local_type::read_outcome;
    using typename local_type::route_type;
    using remote_type = redis_remote_data_access<group_id_type, node_id_type>;
    using future_type = decltype(std::declval<Host&>().submit_command(
        std::declval<const std::string&>(), std::declval<const std::vector<std::byte>&>(),
        std::declval<std::chrono::milliseconds>()));

    /// Whether a remote read can carry this store's entries.
    static constexpr bool k_remote_reads =
        std::is_same_v<entry_handle, std::shared_ptr<const redis_kv_value_entry>>;

    explicit redis_data_access(Host& host) noexcept : local_type(host), _hosted(&host) {}

    /// Sends calls for keys without a local replica to the data nodes at
    /// `seeds` (`host:port`, `KYTHIRA_REDIS_DATA_NODES`) through `call`.
    /// Before the front end serves; never after.
    void attach_remote(std::vector<std::string> seeds, typename remote_type::call_fn call,
                       typename remote_type::options opts = {}) {
        _remote = std::make_unique<remote_type>(std::move(seeds), std::move(call), opts);
    }
    [[nodiscard]] auto remote() noexcept -> remote_type* { return _remote.get(); }
    /// This node's own replicas, never the data nodes: what a data node
    /// answering `KYTHIRA.DATA` uses, so a call crosses one data node.
    [[nodiscard]] auto local() noexcept -> local_type& { return *this; }

    /// Whether a call for `key` goes to the data nodes.
    [[nodiscard]] auto remote_for(const std::string& key) const -> bool {
        if (!_remote) {
            return false;
        }
        auto r = _hosted->resolve(key);
        return !r || _hosted->group_node(r->group_id()) == nullptr;
    }

    /// Where `node` takes data-layer and forwarded calls, as the data
    /// nodes' routes named it; `nullopt` without a remote half.
    [[nodiscard]] auto address_of(const node_id_type& node) const -> std::optional<std::string> {
        return _remote ? _remote->address_of(node) : std::nullopt;
    }

    // ── routing ────────────────────────────────────────────────────────────

    [[nodiscard]] auto route(const std::string& key) const -> std::optional<route_type> {
        if (remote_for(key)) {
            return _remote->route(key);
        }
        return local_type::route(key);
    }
    [[nodiscard]] auto group_of(const std::string& key) const -> std::optional<group_id_type> {
        if (remote_for(key)) {
            return _remote->group_of(key);
        }
        return local_type::group_of(key);
    }
    [[nodiscard]] auto leader_of(const std::string& key) const -> std::optional<node_id_type> {
        if (remote_for(key)) {
            return _remote->leader_of(key);
        }
        return local_type::leader_of(key);
    }
    /// As the local one; a key that goes remote has no replica here, and
    /// `leader` names the data node the routes say leads its group.
    [[nodiscard]] auto replica_for(const std::string& key, redis_data_status& status,
                                   std::optional<node_id_type>& leader) -> group_node_type* {
        if (remote_for(key)) {
            leader = _remote->leader_of(key);
            status = redis_data_status::no_leader;
            return nullptr;
        }
        return local_type::replica_for(key, status, leader);
    }

    // ── proposals ──────────────────────────────────────────────────────────

    /// As the local one: the host's future type, the host's exceptions.
    auto propose(const std::string& key, const std::vector<std::byte>& entry,
                 std::chrono::milliseconds timeout) -> future_type {
        if (!remote_for(key)) {
            return local_type::propose(key, entry, timeout);
        }
        promise_default<std::vector<std::byte>> promise;
        auto result = promise.getFuture();
        try {
            promise.setValue(_remote->propose(key, entry, timeout));
        } catch (...) {
            promise.setException(std::current_exception());
        }
        return result;
    }
    /// As the local one. Keys whose group has no replica here go to the data
    /// node as one proposal for the first key's group: the planner put every
    /// key in that group, and the data node refuses the entry if the group's
    /// version moved since.
    auto propose_keys(const std::vector<std::string>& keys, const std::vector<std::byte>& entry,
                      std::chrono::milliseconds timeout) -> future_type {
        if (keys.empty() || !remote_for(keys.front())) {
            return local_type::propose_keys(keys, entry, timeout);
        }
        return propose(keys.front(), entry, timeout);
    }
    /// A transaction participant message. For a group with no replica here
    /// this raises `unknown_shard_exception`, which sends the coordinator to
    /// the group's leader over `KYTHIRA.TXN`, as it does today for a group
    /// this node does not hold.
    auto propose_txn(const std::vector<std::string>& keys, const std::vector<std::byte>& envelope,
                     std::chrono::milliseconds timeout) {
        if (!keys.empty() && remote_for(keys.front())) {
            throw unknown_shard_exception<group_id_type>(
                _remote->group_of(keys.front()).value_or(group_id_type{}));
        }
        return local_type::propose_txn(keys, envelope, timeout);
    }

    // ── scans (tasks 12-13) ────────────────────────────────────────────────

    /// As the local ones; a range that starts in a group with no replica
    /// here names the data node leading it, so the caller sends it
    /// `KYTHIRA.DATA PAGE` or `USAGE` instead of walking a store it lacks.
    template<typename Keep>
    auto page(const std::string& from, const std::optional<std::string>& to, std::size_t count,
              std::size_t skip, bool any_replica, std::uint64_t now_ms, Keep&& keep) ->
        typename local_type::page_outcome {
        if (remote_for(from)) {
            typename local_type::page_outcome out;
            out._leader = _remote->leader_of(from);
            out._status = redis_data_status::no_leader;
            return out;
        }
        return local_type::page(from, to, count, skip, any_replica, now_ms,
                                std::forward<Keep>(keep));
    }
    template<typename Keep>
    auto usage(const std::string& from, const std::optional<std::string>& to, std::size_t count,
               bool any_replica, std::uint64_t now_ms, std::size_t depth, std::string_view delim,
               std::size_t max_buckets, Keep&& keep) -> typename local_type::usage_outcome {
        if (remote_for(from)) {
            typename local_type::usage_outcome out;
            out._leader = _remote->leader_of(from);
            out._status = redis_data_status::no_leader;
            return out;
        }
        return local_type::usage(from, to, count, any_replica, now_ms, depth, delim, max_buckets,
                                 std::forward<Keep>(keep));
    }

    // ── reads ──────────────────────────────────────────────────────────────

    /// Reads `key` from a data node at `mode`: the local outcome's shape,
    /// with the entry rebuilt from the answer's bytes. A data node that
    /// could not serve it in time is `no_leader` (the retry error).
    auto read_remote(const std::string& key, redis_data_wire::read_mode mode,
                     std::chrono::milliseconds timeout) -> read_outcome {
        read_outcome out;
        out._status = redis_data_status::no_leader;
        if (!_remote) {
            return out;
        }
        if constexpr (k_remote_reads) {
            auto answer = _remote->read(key, mode, timeout);
            if (!answer) {
                return out;
            }
            if (answer->status == redis_data_wire::read_status::unrouted) {
                out._status = redis_data_status::unrouted;
                return out;
            }
            out._status = redis_data_status::ok;
            if (answer->found) {
                auto entry = std::make_shared<redis_kv_value_entry>();
                entry->_value.resize(answer->value.size());
                std::transform(answer->value.begin(), answer->value.end(), entry->_value.begin(),
                               [](char c) { return static_cast<std::byte>(c); });
                entry->_expire_at_ms = answer->expire_at_ms;
                if (answer->type != 0) {
                    try {
                        redis_kv_detail::reader body(
                            std::as_bytes(std::span(answer->body.data(), answer->body.size())));
                        redis_kv_detail::read_collection_body(body, answer->type, *entry);
                    } catch (const std::exception&) {
                        out._status = redis_data_status::no_leader;  // the retry error
                        return out;
                    }
                }
                out._entry = std::move(entry);
            }
        }
        return out;
    }

private:
    Host* _hosted;
    std::unique_ptr<remote_type> _remote;
};

}  // namespace kythira
