// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file table_key_refresh.hpp
/// @brief Fills a node's `table_key_ring` (`item_sealing.hpp`) from the
///        catalog: each sealed table's key, unwrapped by its provider, for
///        the replicas of its groups on this node (KMS task 16).
///
/// A replica never calls a key provider while it applies an entry: the
/// call may block for as long as the KMS takes, and apply runs under the
/// group's lock. It asks the ring, and a miss halts the group until the
/// ring has the key; the miss is remembered, and the next pass here
/// fetches every wanted key at once. A pass with nothing wanted still
/// runs now and then, so a table made on another node has its key here
/// before the first write reaches this node.

#include <kythira/dynamodb/catalog.hpp>
#include <kythira/dynamodb/item_sealing.hpp>
#include <kythira/dynamodb/table_keys.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace kythira::dynamodb {

/// Every key space whose values are sealed under `d`'s table key: the
/// table's own (items and LSI entries), each GSI's, and the key spaces a
/// strongly consistent table took over (task 27).
[[nodiscard]] inline auto sealed_key_spaces(const table_descriptor& d)
    -> std::vector<std::uint64_t> {
    std::vector<std::uint64_t> out{d.table_id};
    for (const auto& g : d.gsis) {
        out.push_back(g.index_id);
    }
    for (const auto& [from, to] : d.retired_ids) {
        out.push_back(from);
        out.push_back(to);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

/// The refresher. `Backend` lists and describes tables (`list_tables`,
/// `describe`). Thread-safe for one caller of `pass` at a time.
template<typename Backend> class table_key_refresher {
public:
    table_key_refresher(Backend& backend, const table_keys& keys,
                        std::shared_ptr<table_key_ring> ring)
        : _backend(backend), _keys(keys), _ring(std::move(ring)) {}

    [[nodiscard]] auto ring() const -> const std::shared_ptr<table_key_ring>& { return _ring; }

    /// One pass: with `all`, every sealed table's key this node lacks;
    /// otherwise only those a replica asked for. Returns how many tables'
    /// keys were added. `now_ms` stamps a table's first failed unwrap.
    auto pass(bool all, std::uint64_t now_ms) -> std::size_t {
        if (!_ring || !_keys.configured()) {
            return 0;
        }
        const auto wanted = _ring->wanted();
        if (!all && wanted.empty()) {
            return 0;
        }
        std::size_t added = 0;
        std::map<std::uint64_t, std::uint64_t> failing;
        for (const auto& name : _backend.list_tables("", SIZE_MAX)) {
            const auto d = _backend.describe(name);
            if (!d || !d->seals_items()) {
                continue;
            }
            const auto spaces = sealed_key_spaces(*d);
            const bool lacking = std::any_of(spaces.begin(), spaces.end(),
                                             [&](std::uint64_t id) { return !_ring->holds(id); });
            const bool asked =
                all || std::any_of(spaces.begin(), spaces.end(),
                                   [&](std::uint64_t id) { return wanted.contains(id); });
            if (!lacking || !asked) {
                continue;
            }
            try {
                auto key = _keys.open(*d, _partition);
                _ring->put(spaces, key);
                OPENSSL_cleanse(key.data(), key.size());
                ++added;
            } catch (const kms_provider::kms_error& e) {
                const std::scoped_lock lock(_mutex);
                const auto it = _failing.find(d->table_id);
                failing[d->table_id] = it == _failing.end() ? now_ms : it->second;
                _last_error[d->table_id] = e.what();
            }
        }
        const std::scoped_lock lock(_mutex);
        // Only tables still failing keep their first failure; a pass that
        // looked at a table and opened it clears it.
        for (auto it = _failing.begin(); it != _failing.end();) {
            if (!failing.contains(it->first) && _ring->holds(it->first)) {
                _last_error.erase(it->first);
                it = _failing.erase(it);
            } else {
                ++it;
            }
        }
        for (const auto& [id, at] : failing) {
            _failing[id] = at;
        }
        return added;
    }

    /// The tables whose key this node could not open, by table id, with
    /// when it first failed (ms since the epoch).
    [[nodiscard]] auto failing() const -> std::map<std::uint64_t, std::uint64_t> {
        const std::scoped_lock lock(_mutex);
        return _failing;
    }

    /// Why the table's key last failed to open, or empty.
    [[nodiscard]] auto last_error(std::uint64_t table_id) const -> std::string {
        const std::scoped_lock lock(_mutex);
        const auto it = _last_error.find(table_id);
        return it == _last_error.end() ? std::string() : it->second;
    }

    auto set_partition(std::string partition) -> void { _partition = std::move(partition); }

private:
    Backend& _backend;
    const table_keys& _keys;
    std::shared_ptr<table_key_ring> _ring;
    std::string _partition = "aws";
    mutable std::mutex _mutex;
    std::map<std::uint64_t, std::uint64_t> _failing;
    std::map<std::uint64_t, std::string> _last_error;
};

/// The catalog leader's watch over sealed tables (KMS task 16), a pass a
/// second from the gateway's worker:
///
/// - Each sealed table's key is opened now and then (`check_interval`).
///   A table whose key has failed to open for `inaccessible_after` goes
///   `INACCESSIBLE_ENCRYPTION_CREDENTIALS` (Requirement 12.6), and back
///   once the key opens again. Kythira never archives a table on its own.
/// - A table whose SSE status is `UPDATING` (a clear table that gained a
///   key) has every value of its key spaces re-sealed through the log,
///   one `reseal` entry per key (Requirement 12.10), then shows `ENABLED`.
///
/// What a pass learns lives in memory: a new leader starts its clocks
/// over, and a table recovered from inaccessible while re-sealing shows
/// `UPDATING` again only on the leader that saw it so.
template<typename Backend> class table_key_watch {
public:
    table_key_watch(Backend& backend, const table_keys& keys, std::shared_ptr<table_key_ring> ring)
        : _backend(backend), _keys(keys), _ring(std::move(ring)) {}

    std::uint64_t check_interval_ms = 60'000;
    std::uint64_t inaccessible_after_ms = 600'000;

    /// One pass. Returns how many tables changed status.
    auto pass(std::uint64_t now_ms) -> std::size_t {
        if (!_keys.configured()) {
            return 0;
        }
        std::size_t changed = 0;
        for (const auto& name : _backend.list_tables("", SIZE_MAX)) {
            auto d = _backend.describe(name);
            if (!d || !d->seals_items() || d->status != table_status::active) {
                continue;
            }
            changed += check(*d, now_ms);
            if (d->sse.status == sse_status::updating) {
                changed += reseal(*d);
            }
        }
        return changed;
    }

private:
    auto check(table_descriptor& d, std::uint64_t now_ms) -> std::size_t {
        auto& w = _watched[d.table_id];
        if (w.checked_ms != 0 && now_ms < w.checked_ms + check_interval_ms) {
            return 0;
        }
        w.checked_ms = now_ms;
        try {
            auto key = _keys.open(d, _partition);
            if (_ring) {
                _ring->put(sealed_key_spaces(d), key);
            }
            OPENSSL_cleanse(key.data(), key.size());
            w.failing_since_ms = 0;
            if (d.sse.status != sse_status::inaccessible) {
                return 0;
            }
            return set_health(d, w.was_updating ? sse_status::updating : sse_status::enabled, 0);
        } catch (const kms_provider::kms_error&) {
            if (w.failing_since_ms == 0) {
                w.failing_since_ms = now_ms;
            }
            if (d.sse.status == sse_status::inaccessible ||
                now_ms < w.failing_since_ms + inaccessible_after_ms) {
                return 0;
            }
            w.was_updating = d.sse.status == sse_status::updating;
            return set_health(d, sse_status::inaccessible, now_ms);
        }
    }

    auto set_health(table_descriptor& d, sse_status status, std::uint64_t inaccessible_ms)
        -> std::size_t {
        catalog_command c;
        c.op = catalog_command::kind::set_sse;
        c.table = d;
        c.table.sse.status = status;
        c.table.sse.inaccessible_ms = inaccessible_ms;
        c.done = true;  // the key's health only
        c.now_ms = _backend.now_ms();
        const auto r = _backend.catalog(c);
        if (!r.ok() || !r.table) {
            return 0;
        }
        const bool moved = r.table->sse.status == status;
        d = *r.table;
        return moved ? 1 : 0;
    }

    auto reseal(table_descriptor& d) -> std::size_t {
        for (const auto space : sealed_key_spaces(d)) {
            std::vector<std::string> keys;
            _backend.read_range(table_range(space), kythira::scan_direction::forward, true,
                                [&](std::string_view key, const item&) {
                                    keys.emplace_back(key);
                                    return true;
                                });
            for (auto& key : keys) {
                item_command c;
                c.op = item_command::kind::reseal;
                c.table_id = d.table_id;
                c.schema = d.schema;
                c.target = std::move(key);
                c.sealed = true;
                const auto r = _backend.write(c);
                if (r.outcome != item_result::status::ok) {
                    return 0;  // the next pass starts over
                }
            }
        }
        _watched[d.table_id].was_updating = false;
        return set_health(d, sse_status::enabled, 0);
    }

    struct watched {
        std::uint64_t checked_ms = 0;
        std::uint64_t failing_since_ms = 0;
        bool was_updating = false;
    };

    Backend& _backend;
    const table_keys& _keys;
    std::shared_ptr<table_key_ring> _ring;
    std::string _partition = "aws";
    std::map<std::uint64_t, watched> _watched;
};

}  // namespace kythira::dynamodb
