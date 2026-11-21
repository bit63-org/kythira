// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_data_access.hpp
/// @brief The data layer as the Kinesis handlers see it: named queries
///        instead of a callback on the live state machine
///        (`.kiro/specs/kinesis-independent-layers/` task 2, design "Named
///        queries replace the state-machine callback", Requirements 1.2,
///        3.1 and 3.3).
///
/// `stream_cluster::read(key, f)` runs `f` on a replica under its lock.
/// That cannot cross a network, so a front end that holds no replica could
/// not serve a single call. The handlers only ever asked the replica a
/// small, closed set of questions; `data_access` names them, and every
/// answer is a value copied out of the state machine:
///
/// - the catalog: one stream by account and name, an account's streams in
///   name order, every stream (optionally of some statuses), one channel by
///   name or catalog id, an account's channels;
/// - one shard's replicated state, and a read of its records as stored
///   (sealed for an encrypted stream: the front end opens them, so keys
///   and plaintext never reach the data layer);
/// - and today's writes: `propose`, `transact`, `group_of`, `leads`,
///   `now_ms`.
///
/// A query that cannot be answered (no local replica of the group, no data
/// node reachable) is `data_error::unreachable`, never an empty answer: the
/// handler fails the call as retryable, as it did when `read` was false.
///
/// `local_data_access<Cluster>` answers over any `stream_cluster` (the
/// daemon's `raft_stream_cluster`, the tests' `local_stream_cluster`) by
/// running each query inside one `read` and copying the result out. Each
/// query costs a virtual call and the copy; most call sites already copied.
/// `remote_data_access` and `hybrid_data_access` (task 6,
/// `kinesis_data_api.hpp`) answer the same queries over the data-layer API.
///
/// The maintenance pass and the on-demand controller act only where their
/// node leads a group, so they always run beside a replica and keep the
/// callback form; so does channel delivery's checkpoint bookkeeping.

#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_records.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>
#include <kythira/kinesis/kinesis_throttle.hpp>

#include <raft/segment_store.hpp>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::kinesis {

/// Why a query has no answer.
enum class data_error : std::uint8_t {
    /// No replica of the group answered: this node holds none, or no data
    /// node could be reached. Retryable.
    unreachable,
};

/// An answer or why there is none: `std::expected<T, data_error>` in
/// spirit, which clang 18 over libstdc++ 13 (the static-analysis setup)
/// does not offer.
template<typename T> class data_result {
public:
    // Implicit both ways, as std::expected is from a value and from an
    // unexpected.
    data_result(T value) : _value(std::move(value)) {}  // NOLINT(google-explicit-constructor)
    data_result(data_error error) : _error(error) {}    // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const noexcept -> bool { return _value.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] auto operator*() & -> T& { return *_value; }
    [[nodiscard]] auto operator*() const& -> const T& { return *_value; }
    [[nodiscard]] auto operator*() && -> T&& { return std::move(*_value); }
    [[nodiscard]] auto operator->() -> T* { return &*_value; }
    [[nodiscard]] auto operator->() const -> const T* { return &*_value; }

    [[nodiscard]] auto value_or(T fallback) const& -> T { return _value ? *_value : fallback; }
    [[nodiscard]] auto value_or(T fallback) && -> T {
        return _value ? std::move(*_value) : std::move(fallback);
    }

    /// Meaningful only without a value.
    [[nodiscard]] auto error() const noexcept -> data_error { return _error; }

private:
    std::optional<T> _value;
    data_error _error = data_error::unreachable;
};

/// `streams(filter)`: the statuses to keep; empty keeps every stream.
using stream_status_filter = std::vector<stream_status>;

/// A read of one shard's records as stored (`read_records`).
struct shard_records {
    /// The replica has the shard. False while it has not applied the
    /// shard's open (a node just restarted, or behind a reshard): the
    /// handler fails the call as retryable, never as a missing shard.
    bool _found = false;
    raw_shard_read _read;
    /// The shard's latest arrival time, for `MillisBehindLatest` when the
    /// read returned nothing.
    std::int64_t _last_arrival_ms = 0;

    friend auto operator==(const shard_records&, const shard_records&) -> bool = default;
};

/// What the handlers ask the data layer. Thread-safe in every
/// implementation; answers are copies.
class data_access {
public:
    data_access() = default;
    data_access(const data_access&) = delete;
    auto operator=(const data_access&) -> data_access& = delete;
    data_access(data_access&&) = delete;
    auto operator=(data_access&&) -> data_access& = delete;
    virtual ~data_access() = default;

    // ---- writes --------------------------------------------------------

    /// `stream_cluster::propose`: the decoded result, or nullopt when it
    /// could not be committed in time (ambiguous: it may still commit).
    virtual auto propose(const std::string& key, std::vector<std::byte> command, admission mode)
        -> std::optional<apply_result> = 0;

    /// Whether `transact` can commit across groups here: false for a
    /// cluster without tier-1 transactions, and resharding is then not
    /// offered.
    [[nodiscard]] virtual auto can_transact() const -> bool = 0;

    /// `transacts::transact`: every write or none. `aborted` when
    /// `can_transact()` is false.
    virtual auto transact(std::vector<txn_write> writes) -> transact_outcome = 0;

    /// The group owning `key` as routed now, or nullopt when unknown (then
    /// each shard of a `PutRecords` is its own proposal).
    [[nodiscard]] virtual auto group_of(const std::string& key) -> std::optional<std::uint64_t> = 0;

    /// Whether this node leads the group owning `key` now.
    [[nodiscard]] virtual auto leads(const std::string& key) -> bool = 0;

    /// The wall clock arrival and creation times are stamped with.
    [[nodiscard]] virtual auto now_ms() -> std::int64_t = 0;

    // ---- catalog -------------------------------------------------------

    [[nodiscard]] virtual auto find_stream(std::string_view account, std::string_view name)
        -> data_result<std::optional<stream_record>> = 0;

    /// One account's streams in name order, after `start_after`, at most
    /// `limit` (0: no limit).
    [[nodiscard]] virtual auto list_streams(std::string_view account, std::string_view start_after,
                                            std::size_t limit)
        -> data_result<std::vector<stream_record>> = 0;

    /// Every account's streams in catalog order, of the statuses in
    /// `filter` (empty: all).
    [[nodiscard]] virtual auto streams(const stream_status_filter& filter)
        -> data_result<std::vector<stream_record>> = 0;

    [[nodiscard]] virtual auto find_channel(std::string_view account, std::string_view name)
        -> data_result<std::optional<channel_record>> = 0;

    [[nodiscard]] virtual auto find_channel_by_id(std::string_view account, std::uint64_t id)
        -> data_result<std::optional<channel_record>> = 0;

    /// One account's channels in name order, after `start_after`, at most
    /// `limit` (0: no limit).
    [[nodiscard]] virtual auto list_channels(std::string_view account, std::string_view start_after,
                                             std::size_t limit)
        -> data_result<std::vector<channel_record>> = 0;

    // ---- shards --------------------------------------------------------

    /// The shard's replicated state; nullopt while the replica has not
    /// applied its open.
    [[nodiscard]] virtual auto shard(const std::string& key)
        -> data_result<std::optional<shard_state>> = 0;

    /// Up to `limits` of the shard's records from counter `from`, those
    /// arriving before `min_timestamp_ms` skipped, as stored. A sealed
    /// segment that cannot be read even after a fresh copy of the state
    /// comes back with `_read._missing`.
    [[nodiscard]] virtual auto read_records(const std::string& key, std::uint64_t from,
                                            std::int64_t min_timestamp_ms,
                                            const segment_read_limits& limits)
        -> data_result<shard_records> = 0;

    /// Bytes of the shard's segments in this node's own store, for
    /// `/metrics`; 0 where the node keeps none.
    [[nodiscard]] virtual auto local_bytes(const std::string& key) -> std::uint64_t = 0;
};

namespace data_access_detail {

[[nodiscard]] inline auto keeps(const stream_status_filter& filter, stream_status s) -> bool {
    return filter.empty() || std::ranges::find(filter, s) != filter.end();
}

[[nodiscard]] inline auto limit_or_all(std::size_t limit) -> std::size_t {
    return limit == 0 ? SIZE_MAX : limit;
}

}  // namespace data_access_detail

/// `data_access` over a `stream_cluster` this node holds replicas of: each
/// query is one `read` of the owning group's replica, its answer copied
/// out. `Cluster` must outlive this object.
template<stream_cluster Cluster> class local_data_access final : public data_access {
public:
    explicit local_data_access(Cluster& cluster) : _cluster(cluster) {}

    auto propose(const std::string& key, std::vector<std::byte> command, admission mode)
        -> std::optional<apply_result> override {
        return _cluster.propose(key, std::move(command), mode);
    }

    [[nodiscard]] auto can_transact() const -> bool override { return transacts_v; }

    auto transact(std::vector<txn_write> writes) -> transact_outcome override {
        if constexpr (transacts_v) {
            return _cluster.transact(std::move(writes));
        } else {
            return transact_outcome::aborted;
        }
    }

    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<std::uint64_t> override {
        if constexpr (groups_keys<Cluster>) {
            return _cluster.group_of(key);
        } else {
            return std::nullopt;
        }
    }

    [[nodiscard]] auto leads(const std::string& key) -> bool override {
        if constexpr (leads_keys<Cluster>) {
            return _cluster.leads(key);
        } else {
            return false;
        }
    }

    [[nodiscard]] auto now_ms() -> std::int64_t override { return _cluster.now_ms(); }

    /// Whether this node holds a replica of the group owning `key`, so a
    /// query for it is answered here.
    [[nodiscard]] auto holds(const std::string& key) -> bool {
        return _cluster.read(key, stream_reader([](const auto&) {}));
    }

    [[nodiscard]] auto find_stream(std::string_view account, std::string_view name)
        -> data_result<std::optional<stream_record>> override {
        return catalog([&](const auto& sm) -> std::optional<stream_record> {
            if (const auto* s = sm.find_stream(account, name)) {
                return *s;
            }
            return std::nullopt;
        });
    }

    [[nodiscard]] auto list_streams(std::string_view account, std::string_view start_after,
                                    std::size_t limit)
        -> data_result<std::vector<stream_record>> override {
        return catalog([&](const auto& sm) {
            std::vector<stream_record> out;
            for (const auto* s :
                 sm.list_streams(account, start_after, data_access_detail::limit_or_all(limit))) {
                out.push_back(*s);
            }
            return out;
        });
    }

    [[nodiscard]] auto streams(const stream_status_filter& filter)
        -> data_result<std::vector<stream_record>> override {
        return catalog([&](const auto& sm) {
            std::vector<stream_record> out;
            const auto prefix = streams_prefix();
            const auto& entries = sm.entries();
            for (auto it = entries.lower_bound(prefix);
                 it != entries.end() && it->first.starts_with(prefix); ++it) {
                if (const auto* r = std::get_if<stream_record>(&it->second);
                    r != nullptr && data_access_detail::keeps(filter, r->_status)) {
                    out.push_back(*r);
                }
            }
            return out;
        });
    }

    [[nodiscard]] auto find_channel(std::string_view account, std::string_view name)
        -> data_result<std::optional<channel_record>> override {
        return catalog([&](const auto& sm) -> std::optional<channel_record> {
            if (const auto* c = sm.find_channel(account, name)) {
                return *c;
            }
            return std::nullopt;
        });
    }

    [[nodiscard]] auto find_channel_by_id(std::string_view account, std::uint64_t id)
        -> data_result<std::optional<channel_record>> override {
        return catalog([&](const auto& sm) -> std::optional<channel_record> {
            if (const auto* c = sm.find_channel_by_id(account, id)) {
                return *c;
            }
            return std::nullopt;
        });
    }

    [[nodiscard]] auto list_channels(std::string_view account, std::string_view start_after,
                                     std::size_t limit)
        -> data_result<std::vector<channel_record>> override {
        return catalog([&](const auto& sm) {
            std::vector<channel_record> out;
            for (const auto* c :
                 sm.list_channels(account, start_after, data_access_detail::limit_or_all(limit))) {
                out.push_back(*c);
            }
            return out;
        });
    }

    [[nodiscard]] auto shard(const std::string& key)
        -> data_result<std::optional<shard_state>> override {
        std::optional<shard_state> out;
        if (!_cluster.read(key, stream_reader([&](const auto& sm) {
                               if (const auto* st = sm.find_shard(key)) {
                                   out = *st;
                               }
                           }))) {
            return data_error::unreachable;
        }
        return out;
    }

    /// The shard's state, store and fetcher are copied under the read; the
    /// store is then read without holding the state machine. A segment can
    /// go missing between the copy and the read (a trim or tiering in
    /// between), so a missing read is tried once more with a fresh copy.
    [[nodiscard]] auto read_records(const std::string& key, std::uint64_t from,
                                    std::int64_t min_timestamp_ms,
                                    const segment_read_limits& limits)
        -> data_result<shard_records> override {
        shard_records out;
        for (int attempt = 0; attempt < 2 && (attempt == 0 || out._read._missing); ++attempt) {
            bool found = false;
            shard_state state;
            segment_store* store = nullptr;
            segment_fetcher fetch;
            if (!_cluster.read(key, stream_reader([&](const auto& sm) {
                                   if (const auto* st = sm.find_shard(key)) {
                                       found = true;
                                       state = *st;
                                   }
                                   store = sm.store();
                                   fetch = sm.fetcher();
                               }))) {
                return data_error::unreachable;
            }
            if (!found || store == nullptr) {
                // Not applied here yet, or a replica without a store: the
                // caller retries.
                return shard_records{};
            }
            out._found = true;
            out._last_arrival_ms = state._last_arrival_ms;
            out._read = read_shard_raw(*store, fetch, key, state, from, min_timestamp_ms, limits);
        }
        return out;
    }

    [[nodiscard]] auto local_bytes(const std::string& key) -> std::uint64_t override {
        segment_store* store = nullptr;
        (void)_cluster.read(key, stream_reader([&](const auto& sm) { store = sm.store(); }));
        if (store == nullptr) {
            return 0;
        }
        std::uint64_t bytes = 0;
        for (const auto& d : store->local_segments(key)) {
            bytes += d._bytes;
        }
        return bytes;
    }

private:
    static constexpr bool transacts_v = kythira::kinesis::transacts<Cluster>;

    /// Runs `f` on the catalog group's replica and returns its answer.
    template<typename F>
    auto catalog(F&& f)
        -> data_result<std::invoke_result_t<F&, const stream_state_machine<std::uint64_t>&>> {
        using answer = std::invoke_result_t<F&, const stream_state_machine<std::uint64_t>&>;
        std::optional<answer> out;
        if (!_cluster.read(next_id_key(),
                           stream_reader([&](const auto& sm) { out.emplace(f(sm)); })) ||
            !out) {
            return data_error::unreachable;
        }
        return std::move(*out);
    }

    Cluster& _cluster;
};

/// What a handler runs over: a `stream_cluster` this node holds replicas
/// of, or any `data_access` (such as the remote one a front end without
/// the data role uses).
template<typename C>
concept data_layer = stream_cluster<C> || std::derived_from<C, data_access>;

/// The `data_access` for a `data_layer`: the object itself when it is one,
/// else a `local_data_access` over it, owned here. `C` must outlive this.
template<data_layer C> class data_access_of {
public:
    explicit data_access_of(C& layer) {
        if constexpr (std::derived_from<C, data_access>) {
            _access = &layer;
        } else {
            _owned = std::make_unique<local_data_access<C>>(layer);
            _access = _owned.get();
        }
    }

    [[nodiscard]] auto get() const noexcept -> data_access& { return *_access; }

private:
    std::unique_ptr<data_access> _owned;
    data_access* _access = nullptr;
};

}  // namespace kythira::kinesis
