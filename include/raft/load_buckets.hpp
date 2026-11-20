// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file load_buckets.hpp
/// @brief Sub-shard load statistics: TiKV RFC 0082's buckets.
///
/// See `.kiro/specs/multi-raft-load-buckets/`. A shard's load is otherwise
/// one number per direction, which says that a shard is busy but not where.
/// A bucket set cuts the shard's range at a handful of boundaries and keeps
/// read and write counters per piece over a sliding window, so a policy can
/// aim a load split at a boundary without waiting for a sampling window, and
/// an operator can see whether a shard's load is spread or sits in a corner.
///
/// Everything here is leader-local. Nothing is replicated or persisted: a new
/// leader starts with an empty window and builds its own boundaries.
///
/// **The request path.** `count()` runs on every keyed request the routing
/// layer serves, so it takes no lock: one atomic load of the layout, one
/// binary search, relaxed `fetch_add`s on the current slot's counters, and
/// one in `_reservoir_stride` requests a store into a bounded reservoir. That
/// is why a layout is immutable once published and replaced whole: a refresh
/// can never race a count into a half-built vector.
///
/// **The policy phase.** `roll()`, `refresh()` and `snapshot()` run once per
/// policy tick, under a mutex the request path never takes.

#include <raft/shard_types.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

/// @brief Knobs for a shard's load buckets.
///
/// Lives on `multi_raft_config::buckets`. Off by default: when off, the
/// routing path pays one predictable branch on this immutable member and
/// nothing else (Requirement 1.2).
struct bucket_config {
    /// @brief Off by default (Requirement 1.1).
    bool _enabled{false};

    /// @brief Buckets per shard; boundaries are one fewer. Clamped to
    ///        `[k_min_target_buckets, k_max_target_buckets]`.
    ///
    /// The upper bound keeps the request path's binary search at eight
    /// comparisons and a shard's counter memory bounded.
    std::size_t _target_buckets{16};

    /// @brief How often a leader re-cuts its boundaries (Requirement 2.3).
    std::chrono::milliseconds _refresh_interval{std::chrono::seconds{60}};

    /// @brief Slots in the sliding window, including the one being filled.
    ///
    /// A rate covers the slots before the current one, so the default six
    /// ten-second slots report the last fifty to sixty seconds. Clamped to at
    /// least two: with one slot there is never a complete one to report.
    std::size_t _window_slots{6};
    std::chrono::milliseconds _slot_duration{std::chrono::seconds{10}};

    /// @brief Keys held for traffic-derived boundaries (Requirement 2.2).
    std::size_t _reservoir_size{1024};
    /// @brief Feed the reservoir one keyed request in this many.
    std::size_t _reservoir_stride{16};

    /// @brief Buckets per shard in a placement-driver report (Requirement 5.2).
    std::size_t _report_top_buckets{4};

    /// Seed for the reservoir's replacement choice. Zero asks the system. A
    /// fixed seed exists for tests, which need the same boundaries twice.
    std::uint64_t _seed{0};

    static constexpr std::size_t k_min_target_buckets = 2;
    static constexpr std::size_t k_max_target_buckets = 256;
    static constexpr std::size_t k_min_window_slots = 2;
    static constexpr std::size_t k_max_window_slots = 64;
    static constexpr std::size_t k_max_reservoir_size = 65536;
};

/// @brief `cfg` with every count clamped into its legal range, or an
///        `std::invalid_argument` for a setting no clamp can repair.
///
/// Counts are clamped rather than refused: "256 buckets" when 1000 were asked
/// for is what the operator meant, and refusing to start a host over it would
/// be worse. A zero or negative duration has no nearby legal value — a zero
/// slot would roll on every tick and report nothing — so an enabled config
/// carrying one is refused. A disabled config is clamped but never refused:
/// a host that never counts must not fail to start over knobs it ignores.
[[nodiscard]] inline auto normalized(bucket_config cfg) -> bucket_config {
    cfg._target_buckets = std::clamp(cfg._target_buckets, bucket_config::k_min_target_buckets,
                                     bucket_config::k_max_target_buckets);
    cfg._window_slots = std::clamp(cfg._window_slots, bucket_config::k_min_window_slots,
                                   bucket_config::k_max_window_slots);
    // A reservoir smaller than the bucket count cannot produce that many
    // distinct quantiles.
    cfg._reservoir_size =
        std::clamp(cfg._reservoir_size, cfg._target_buckets, bucket_config::k_max_reservoir_size);
    cfg._reservoir_stride = std::max<std::size_t>(cfg._reservoir_stride, 1);
    cfg._report_top_buckets = std::min(cfg._report_top_buckets, cfg._target_buckets);

    if (cfg._enabled) {
        if (cfg._slot_duration.count() <= 0) {
            throw std::invalid_argument("bucket_config: _slot_duration must be positive, got " +
                                        std::to_string(cfg._slot_duration.count()) + " ms");
        }
        if (cfg._refresh_interval.count() <= 0) {
            throw std::invalid_argument("bucket_config: _refresh_interval must be positive, got " +
                                        std::to_string(cfg._refresh_interval.count()) + " ms");
        }
    }
    return cfg;
}

/// @brief A bounded uniform sample of keys: Vitter's Algorithm R.
///
/// Not thread-safe. `bucket_set` guards it with a mutex taken one request in
/// `_reservoir_stride`, never on every request.
template<shard_key Key> class key_reservoir {
public:
    explicit key_reservoir(std::size_t capacity, std::uint64_t seed = 0)
        : _capacity(capacity), _rng(seed != 0 ? seed : std::random_device{}()) {
        _keys.reserve(capacity);
    }

    auto offer(const Key& key) -> void {
        ++_seen;
        if (_keys.size() < _capacity) {
            _keys.push_back(key);
            return;
        }
        if (_capacity == 0) {
            return;
        }
        // The n-th key replaces a uniformly chosen held key with probability
        // capacity/n, which keeps the sample uniform over everything offered.
        std::uniform_int_distribution<std::uint64_t> pick{1, _seen};
        const auto slot = pick(_rng);
        if (slot <= _capacity) {
            _keys[static_cast<std::size_t>(slot - 1)] = key;
        }
    }

    /// @brief The keys at `i / parts` of the sorted sample, `i = 1..parts-1`.
    ///
    /// Duplicates are returned as they fall: a reservoir dominated by one key
    /// yields that key several times, and deduplication is the caller's job
    /// (`bucket_set::normalize_boundaries`).
    [[nodiscard]] auto quantiles(std::size_t parts) const -> std::vector<Key> {
        if (_keys.empty() || parts < 2) {
            return {};
        }
        auto sorted = _keys;
        std::sort(sorted.begin(), sorted.end());
        std::vector<Key> out;
        out.reserve(parts - 1);
        for (std::size_t i = 1; i < parts; ++i) {
            out.push_back(sorted[(i * sorted.size()) / parts]);
        }
        return out;
    }

    auto clear() -> void {
        _keys.clear();
        _seen = 0;
    }

    [[nodiscard]] auto size() const -> std::size_t { return _keys.size(); }
    [[nodiscard]] auto seen() const -> std::uint64_t { return _seen; }
    [[nodiscard]] auto capacity() const -> std::size_t { return _capacity; }

private:
    std::size_t _capacity;
    std::mt19937_64 _rng;
    std::vector<Key> _keys;
    std::uint64_t _seen{0};
};

/// @brief Raw counts over one bucket, summed across a window's complete slots.
struct bucket_counts {
    std::uint64_t _reads{0};
    std::uint64_t _writes{0};
    std::uint64_t _read_bytes{0};
    std::uint64_t _write_bytes{0};

    [[nodiscard]] auto requests() const -> std::uint64_t { return _reads + _writes; }

    auto operator+=(const bucket_counts& o) -> bucket_counts& {
        _reads += o._reads;
        _writes += o._writes;
        _read_bytes += o._read_bytes;
        _write_bytes += o._write_bytes;
        return *this;
    }

    [[nodiscard]] auto operator==(const bucket_counts&) const -> bool = default;
};

/// @brief One shard's bucket boundaries, counters and version.
///
/// Thread-safety: `count()` and `add_bytes()` may run on any number of threads
/// at once, and alongside any policy-phase call. The policy-phase calls
/// (`roll`, `refresh`, `snapshot`, the accessors) serialise on an internal
/// mutex that the request path never takes.
///
/// @tparam Key Must satisfy `shard_key`.
template<shard_key Key> class bucket_set {
public:
    using clock = std::chrono::steady_clock;

    /// @param cfg        Normalised here, so a caller cannot hand in 0 slots.
    /// @param range      The shard's range; boundaries are kept strictly
    ///                   inside it.
    /// @param now        Start of the first slot.
    /// @param boundaries Initial cut, typically inherited from a split parent
    ///                   (Requirement 4.2). Normalised like a refresh's.
    /// @param version    Version of the initial layout. A fresh set is 1, so
    ///                   zero stays free to mean "no buckets" in `shard_stats`.
    bucket_set(bucket_config cfg, shard_range<Key> range, clock::time_point now,
               std::vector<Key> boundaries = {}, std::uint64_t version = 1)
        : _cfg(normalized(cfg)),
          _range(std::move(range)),
          _reservoir(_cfg._reservoir_size, _cfg._seed),
          _slot_started(_cfg._window_slots, now) {
        _layout.store(make_layout(
            normalize_boundaries(std::move(boundaries), _range, _cfg._target_buckets - 1),
            version));
    }

    bucket_set(const bucket_set&) = delete;
    auto operator=(const bucket_set&) -> bucket_set& = delete;

    // ── request path ─────────────────────────────────────────────────────────

    /// @brief Count one keyed request against the bucket holding `key`.
    ///
    /// Lock-free except one request in `_reservoir_stride`, which offers the
    /// key to the reservoir under its own mutex.
    auto count(const Key& key, std::uint64_t bytes, bool is_read) -> void {
        add(key, 1, bytes, is_read);
        if (_stride.fetch_add(1, std::memory_order_relaxed) % _cfg._reservoir_stride == 0) {
            std::lock_guard lock(_reservoir_mutex);
            _reservoir.offer(key);
        }
    }

    /// @brief Add bytes to `key`'s bucket without counting a request.
    ///
    /// A read's size is known only once it completes, after `count()` ran at
    /// submission; this attributes it. Never feeds the reservoir, so a read
    /// does not weigh twice in traffic-derived boundaries.
    auto add_bytes(const Key& key, std::uint64_t bytes, bool is_read) -> void {
        add(key, 0, bytes, is_read);
    }

    // ── policy phase ─────────────────────────────────────────────────────────

    /// @brief Start a new slot if the current one has run `_slot_duration`.
    ///
    /// Advances at most one slot per call, and stamps the new slot with
    /// `now`. A policy tick that arrives late therefore lengthens the slot it
    /// closes rather than inventing empty ones, and a rate divides by the
    /// time the slots really covered, so a late tick never skews it.
    ///
    /// @return Whether a slot was started.
    auto roll(clock::time_point now) -> bool {
        std::lock_guard lock(_policy_mutex);
        const auto current = _slot.load(std::memory_order_relaxed);
        if (now - _slot_started[current] < _cfg._slot_duration) {
            return false;
        }
        const auto next = (current + 1) % _cfg._window_slots;
        auto layout = _layout.load();
        // Zeroed BEFORE `_slot` names it: a count that reads the new index
        // then lands on an already-cleared slot. A count still holding the old
        // index lands in the slot just closed, which is where it belongs.
        for (std::size_t b = 0; b < layout->bucket_count; ++b) {
            layout->at(next, b).clear();
        }
        _slot_started[next] = now;
        _slot.store(next, std::memory_order_release);
        _complete = std::min(_complete + 1, _cfg._window_slots - 1);
        return true;
    }

    /// @brief Publish `candidates` as the new boundaries, unless they equal
    ///        the current ones.
    ///
    /// The candidates are normalised first: only keys strictly inside the
    /// shard's range survive, sorted and deduplicated, and at most
    /// `_target_buckets - 1` of them, chosen evenly (Requirement 2.4).
    ///
    /// An equal set keeps the old layout, counters and version (Requirement
    /// 2.3): re-cutting at the same keys would throw away a window of
    /// evidence and bump the version for no change. A different set starts
    /// from empty counters, because counts describe the old ranges and
    /// carrying them over would put one range's load on another.
    ///
    /// @return Whether a new layout was published.
    auto refresh(std::vector<Key> candidates, clock::time_point now) -> bool {
        std::lock_guard lock(_policy_mutex);
        auto boundaries =
            normalize_boundaries(std::move(candidates), _range, _cfg._target_buckets - 1);
        const auto old = _layout.load();
        if (boundaries == old->boundaries) {
            return false;
        }
        _layout.store(make_layout(std::move(boundaries), old->version + 1));
        _slot_started[_slot.load(std::memory_order_relaxed)] = now;
        _complete = 0;
        return true;
    }

    /// @brief Start over on `range` with `boundaries`: version 1, an empty
    ///        window and an empty reservoir.
    ///
    /// What a replica does when it starts leading the shard (Requirement 4.1),
    /// and what a split child or merge survivor does once its range has
    /// changed (Requirements 4.2, 4.3). The set is reused rather than rebuilt
    /// so the host can hold it by plain pointer: the request path then pays
    /// one atomic load (the layout's), not two.
    auto reset(shard_range<Key> range, std::vector<Key> boundaries, clock::time_point now) -> void {
        std::lock_guard lock(_policy_mutex);
        _range = std::move(range);
        _layout.store(make_layout(
            normalize_boundaries(std::move(boundaries), _range, _cfg._target_buckets - 1), 1));
        std::fill(_slot_started.begin(), _slot_started.end(), now);
        _complete = 0;
        std::lock_guard reservoir_lock(_reservoir_mutex);
        _reservoir.clear();
    }

    /// @brief Boundaries cut from the traffic the reservoir has seen: its
    ///        quantiles at `i / _target_buckets`, normalised.
    ///
    /// The fallback when the state machine cannot say where its data is
    /// (Requirement 2.2). Empty until the reservoir holds a key.
    [[nodiscard]] auto reservoir_boundaries() const -> std::vector<Key> {
        std::lock_guard lock(_policy_mutex);
        std::vector<Key> keys;
        {
            std::lock_guard reservoir_lock(_reservoir_mutex);
            keys = _reservoir.quantiles(_cfg._target_buckets);
        }
        return normalize_boundaries(std::move(keys), _range, _cfg._target_buckets - 1);
    }

    /// @brief Per-bucket counts summed over the window's complete slots.
    ///
    /// The slot being filled is left out, so a figure never jumps when a slot
    /// opens. Left to right, one entry per bucket.
    [[nodiscard]] auto window_counts() const -> std::vector<bucket_counts> {
        std::lock_guard lock(_policy_mutex);
        return window_counts_locked(*_layout.load());
    }

    /// @brief How long the window's complete slots cover; zero until the
    ///        first slot has closed since the set was built or re-cut.
    [[nodiscard]] auto window_covered() const -> clock::duration {
        std::lock_guard lock(_policy_mutex);
        return covered_locked();
    }

    /// @brief The buckets as `shard_stats` carries them: bounds and per-second
    ///        rates over the window, left to right, tiling the shard's range.
    ///
    /// Rates are zero until a slot has closed: no evidence reads as no load,
    /// never as a division by zero.
    [[nodiscard]] auto snapshot() const -> std::vector<bucket_stats<Key>> {
        std::lock_guard lock(_policy_mutex);
        const auto layout = _layout.load();
        const auto counts = window_counts_locked(*layout);
        const auto seconds = std::chrono::duration<double>(covered_locked()).count();
        const auto rate = [seconds](std::uint64_t n) {
            return seconds > 0.0 ? static_cast<double>(n) / seconds : 0.0;
        };

        std::vector<bucket_stats<Key>> out;
        out.reserve(layout->bucket_count);
        for (std::size_t b = 0; b < layout->bucket_count; ++b) {
            bucket_stats<Key> s;
            s._start = b == 0 ? _range._start : std::optional<Key>{layout->boundaries[b - 1]};
            s._end = b + 1 == layout->bucket_count ? _range._end
                                                   : std::optional<Key>{layout->boundaries[b]};
            s._read_qps = rate(counts[b]._reads);
            s._write_qps = rate(counts[b]._writes);
            s._read_bytes_per_sec = rate(counts[b]._read_bytes);
            s._write_bytes_per_sec = rate(counts[b]._write_bytes);
            out.push_back(std::move(s));
        }
        return out;
    }

    [[nodiscard]] auto boundaries() const -> std::vector<Key> { return _layout.load()->boundaries; }
    [[nodiscard]] auto version() const -> std::uint64_t { return _layout.load()->version; }
    [[nodiscard]] auto bucket_count() const -> std::size_t { return _layout.load()->bucket_count; }
    [[nodiscard]] auto range() const -> shard_range<Key> {
        std::lock_guard lock(_policy_mutex);
        return _range;
    }
    [[nodiscard]] auto config() const -> const bucket_config& { return _cfg; }

    /// @brief Index of the bucket holding `key`: the number of boundaries at
    ///        or below it. Bucket `i` is `[boundaries[i-1], boundaries[i])`.
    [[nodiscard]] static auto bucket_index(const std::vector<Key>& boundaries, const Key& key)
        -> std::size_t {
        return static_cast<std::size_t>(
            std::upper_bound(boundaries.begin(), boundaries.end(), key) - boundaries.begin());
    }

    /// @brief `keys` as legal boundaries for `range`: strictly inside it,
    ///        sorted, unique, and at most `max_boundaries`, chosen evenly.
    ///
    /// "Strictly inside" is `shard_range::is_interior`: a boundary at the
    /// range's start would make an empty first bucket, and one at or past its
    /// end lies outside the shard.
    [[nodiscard]] static auto normalize_boundaries(std::vector<Key> keys,
                                                   const shard_range<Key>& range,
                                                   std::size_t max_boundaries) -> std::vector<Key> {
        std::erase_if(keys, [&](const Key& k) { return !range.is_interior(k); });
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        if (keys.size() <= max_boundaries) {
            return keys;
        }
        // Take the midpoint of each of `max_boundaries` equal runs: distinct
        // indices because there are more keys than picks, and spread so a
        // trimmed cut keeps its shape rather than its first few keys.
        std::vector<Key> out;
        out.reserve(max_boundaries);
        const auto n = keys.size();
        for (std::size_t i = 0; i < max_boundaries; ++i) {
            out.push_back(std::move(keys[((2 * i + 1) * n) / (2 * max_boundaries)]));
        }
        return out;
    }

    /// @brief Drop boundaries until at most `max_boundaries` remain, each time
    ///        the one whose two adjacent buckets carry the least combined load.
    ///
    /// `loads` has one entry per bucket (`boundaries.size() + 1`). Dropping a
    /// boundary merges its two buckets, so their loads are summed for the
    /// next round. Ties go to the leftmost boundary, which keeps the result
    /// deterministic for a given input.
    [[nodiscard]] static auto trim_by_load(std::vector<Key> boundaries,
                                           std::vector<std::uint64_t> loads,
                                           std::size_t max_boundaries) -> std::vector<Key> {
        loads.resize(boundaries.size() + 1, 0);
        while (boundaries.size() > max_boundaries) {
            std::size_t drop = 0;
            for (std::size_t i = 1; i < boundaries.size(); ++i) {
                if (loads[i] + loads[i + 1] < loads[drop] + loads[drop + 1]) {
                    drop = i;
                }
            }
            loads[drop] += loads[drop + 1];
            loads.erase(loads.begin() + static_cast<std::ptrdiff_t>(drop) + 1);
            boundaries.erase(boundaries.begin() + static_cast<std::ptrdiff_t>(drop));
        }
        return boundaries;
    }

    /// @brief A merge survivor's boundaries (Requirement 4.3).
    ///
    /// The union of the survivor's own boundaries, the absorbed shard's, and
    /// the old bound between the two ranges, trimmed to `max_boundaries` by
    /// least combined load. Only the survivor's own buckets have loads here:
    /// its leader never measured the absorbed shard, so those buckets count
    /// as zero and are coarsened first. The next refresh re-cuts anyway.
    ///
    /// @param merged      The survivor's range after the merge.
    /// @param own_range   The survivor's range before it.
    /// @param own         The survivor's boundaries before it.
    /// @param own_counts  The survivor's window counts, one per own bucket;
    ///                    empty counts as zero load.
    /// @param absorbed    The absorbed shard's boundaries, if this replica
    ///                    knows them; empty otherwise.
    [[nodiscard]] static auto merge_boundaries(const shard_range<Key>& merged,
                                               const shard_range<Key>& own_range,
                                               const std::vector<Key>& own,
                                               const std::vector<bucket_counts>& own_counts,
                                               const std::vector<Key>& absorbed,
                                               std::size_t max_boundaries) -> std::vector<Key> {
        std::vector<Key> keys = own;
        keys.insert(keys.end(), absorbed.begin(), absorbed.end());
        // The old shared bound: whichever of the survivor's old bounds is now
        // strictly inside the merged range.
        if (own_range._start.has_value() && merged.is_interior(*own_range._start)) {
            keys.push_back(*own_range._start);
        }
        if (own_range._end.has_value() && merged.is_interior(*own_range._end)) {
            keys.push_back(*own_range._end);
        }
        // The size is read BEFORE the call: the order in which a call's
        // arguments are evaluated is unspecified, and clang moves `keys` out
        // first, which made the cap zero and every merge lose its cut.
        const auto all = keys.size();
        keys = normalize_boundaries(std::move(keys), merged, all);

        std::vector<std::uint64_t> loads(keys.size() + 1, 0);
        for (std::size_t b = 0; b < loads.size(); ++b) {
            // A bucket inside the survivor's old range is exactly one of its
            // old buckets: the absorbed boundaries and the shared bound all
            // lie outside or on the edge of that range.
            const std::optional<Key> start =
                b == 0 ? merged._start : std::optional<Key>{keys[b - 1]};
            const bool own_side =
                start.has_value() ? own_range.contains(*start) : !own_range._start.has_value();
            if (!own_side) {
                continue;
            }
            const auto i = start.has_value() ? bucket_index(own, *start) : std::size_t{0};
            if (i < own_counts.size()) {
                loads[b] = own_counts[i].requests();
            }
        }
        return trim_by_load(std::move(keys), std::move(loads), max_boundaries);
    }

private:
    struct counters {
        std::atomic<std::uint64_t> reads{0};
        std::atomic<std::uint64_t> writes{0};
        std::atomic<std::uint64_t> read_bytes{0};
        std::atomic<std::uint64_t> write_bytes{0};

        auto clear() -> void {
            reads.store(0, std::memory_order_relaxed);
            writes.store(0, std::memory_order_relaxed);
            read_bytes.store(0, std::memory_order_relaxed);
            write_bytes.store(0, std::memory_order_relaxed);
        }

        [[nodiscard]] auto load() const -> bucket_counts {
            return bucket_counts{._reads = reads.load(std::memory_order_relaxed),
                                 ._writes = writes.load(std::memory_order_relaxed),
                                 ._read_bytes = read_bytes.load(std::memory_order_relaxed),
                                 ._write_bytes = write_bytes.load(std::memory_order_relaxed)};
        }
    };

    /// Immutable once published: boundaries, version and the counter block's
    /// shape never change. Only the counters' values do.
    struct layout {
        std::vector<Key> boundaries;
        std::uint64_t version{0};
        std::size_t bucket_count{1};
        std::unique_ptr<counters[]> slots;  // slot-major: [slot][bucket]

        [[nodiscard]] auto at(std::size_t slot, std::size_t bucket) const -> counters& {
            return slots[slot * bucket_count + bucket];
        }
    };

    [[nodiscard]] auto make_layout(std::vector<Key> boundaries, std::uint64_t version) const
        -> std::shared_ptr<layout> {
        auto l = std::make_shared<layout>();
        l->bucket_count = boundaries.size() + 1;
        l->boundaries = std::move(boundaries);
        l->version = version;
        // Value-initialised: every atomic starts at zero.
        l->slots = std::make_unique<counters[]>(l->bucket_count * _cfg._window_slots);
        return l;
    }

    auto add(const Key& key, std::uint64_t requests, std::uint64_t bytes, bool is_read) -> void {
        const auto layout = _layout.load(std::memory_order_acquire);
        auto& c = layout->at(_slot.load(std::memory_order_acquire),
                             bucket_index(layout->boundaries, key));
        if (is_read) {
            if (requests != 0) {
                c.reads.fetch_add(requests, std::memory_order_relaxed);
            }
            if (bytes != 0) {
                c.read_bytes.fetch_add(bytes, std::memory_order_relaxed);
            }
        } else {
            if (requests != 0) {
                c.writes.fetch_add(requests, std::memory_order_relaxed);
            }
            if (bytes != 0) {
                c.write_bytes.fetch_add(bytes, std::memory_order_relaxed);
            }
        }
    }

    [[nodiscard]] auto window_counts_locked(const layout& l) const -> std::vector<bucket_counts> {
        std::vector<bucket_counts> out(l.bucket_count);
        const auto current = _slot.load(std::memory_order_relaxed);
        const auto slots = _cfg._window_slots;
        for (std::size_t back = 1; back <= _complete; ++back) {
            const auto slot = (current + slots - back) % slots;
            for (std::size_t b = 0; b < l.bucket_count; ++b) {
                out[b] += l.at(slot, b).load();
            }
        }
        return out;
    }

    [[nodiscard]] auto covered_locked() const -> clock::duration {
        if (_complete == 0) {
            return clock::duration::zero();
        }
        const auto current = _slot.load(std::memory_order_relaxed);
        const auto slots = _cfg._window_slots;
        const auto oldest = (current + slots - _complete) % slots;
        return _slot_started[current] - _slot_started[oldest];
    }

    bucket_config _cfg;
    shard_range<Key> _range;

    /// The request path's one shared load. libstdc++ implements it with a
    /// small spin lock; task 8 of the spec measures whether that shows.
    std::atomic<std::shared_ptr<layout>> _layout;
    /// Index of the slot being filled. Written only by `roll()`.
    std::atomic<std::size_t> _slot{0};
    /// Counts keyed requests, to pick the one in `_reservoir_stride` that
    /// feeds the reservoir.
    std::atomic<std::uint64_t> _stride{0};

    mutable std::mutex _reservoir_mutex;
    key_reservoir<Key> _reservoir;

    /// Guards the slot ring's bookkeeping below and serialises the policy
    /// phase. Never taken by `count()`.
    mutable std::mutex _policy_mutex;
    std::vector<clock::time_point> _slot_started;
    /// Complete slots in the window since the layout was published, at most
    /// `_window_slots - 1`.
    std::size_t _complete{0};
};

}  // namespace kythira
