# Design Document — Multi-Raft load buckets

## Overview

Each group a host leads gets a `bucket_set<Key>`: sorted boundaries, one
counter block per bucket, and a version. The routing layer bumps the counter
block for a request's key next to the shard counters it already bumps. The
policy phase refreshes boundaries, rolls the window, copies the buckets into
`shard_stats`, and lets the default policy aim a load split at a boundary.
Nothing is replicated or persisted.

```
route_and_run(key)                       tick(): policy phase (per led group)
  ├─ _reads / _writes++   (today)          ├─ bucket_set.roll(now)
  ├─ sampler.observe(key) (today)          ├─ maybe refresh boundaries
  └─ buckets->count(key, bytes, is_read)   ├─ stats._buckets = snapshot()
       one atomic load of the set,         └─ policy.evaluate(stats)
       one binary search, two relaxed           └─ bucket split proposal (Req 6)
       fetch_adds
```

## Types

```cpp
// shard_types.hpp, beside hot_key_sample
template<shard_key Key> struct bucket_stats {
    std::optional<Key> _start;   // nullopt = the shard's own start
    std::optional<Key> _end;     // nullopt = the shard's own end
    double _read_qps{0.0};
    double _write_qps{0.0};
    double _read_bytes_per_sec{0.0};
    double _write_bytes_per_sec{0.0};
};

// shard_stats gains, at the end so designated initialisers keep compiling:
std::vector<bucket_stats<Key>> _buckets{};
std::uint64_t _buckets_version{0};

// multi_raft.hpp
struct bucket_config {
    bool _enabled{false};
    std::size_t _target_buckets{16};       // clamped to [2, 256]
    std::chrono::milliseconds _refresh_interval{std::chrono::seconds{60}};
    std::size_t _window_slots{6};
    std::chrono::milliseconds _slot_duration{std::chrono::seconds{10}};
    std::size_t _reservoir_size{1024};
    std::size_t _reservoir_stride{16};     // feed 1 in N keyed requests
    std::size_t _report_top_buckets{4};
};
```

Bounds are `std::optional<Key>` for the same reason `shard_range` uses them:
the first and last bucket are open towards the shard's ends, and the shard's
ends move on split and merge.

## `bucket_set<Key>` (new: `include/raft/load_buckets.hpp`)

```cpp
template<shard_key Key> class bucket_set {
    struct counters {                       // one per bucket per slot
        std::atomic<std::uint64_t> reads, writes, read_bytes, write_bytes;
    };
    struct layout {                         // immutable once published
        std::vector<Key> boundaries;        // sorted, strictly inside the range
        std::uint64_t version;
        std::unique_ptr<counters[]> slots;  // (boundaries.size()+1) * window_slots
    };
    std::atomic<std::shared_ptr<layout>> _layout;
    std::atomic<std::size_t> _slot;         // index of the slot being filled
    reservoir<Key> _reservoir;              // Algorithm R, policy-phase only
public:
    auto count(const Key&, std::size_t bytes, bool is_read) -> void;    // request path
    auto roll(clock::time_point) -> void;                               // policy phase
    auto refresh(std::vector<Key> boundaries) -> void;                  // policy phase
    auto snapshot(const shard_range<Key>&) const -> std::vector<bucket_stats<Key>>;
};
```

**Request path.** `count` loads the layout with one atomic `shared_ptr`
load, binary-searches `boundaries` (`std::upper_bound`, at most 8 comparisons
at 256 buckets), and does relaxed `fetch_add`s on the current slot's
counters. No lock. This is why the layout is immutable and swapped whole: a
refresh never races a count into a half-built vector.

**The reservoir** is fed a key on 1 in `_reservoir_stride` requests (default
16) so that keeping it costs the request path one increment and, rarely, a
store into a bounded array guarded by the group's existing `_sampler_mutex`
(the routing layer already takes it when sampling is on). Quantiles are read
only in the policy phase.

**Window.** `roll` advances `_slot` when `_slot_duration` has passed and
zeroes the slot it enters. A rate is the sum over all slots but the one being
filled, divided by the time they cover; the partly filled slot is left out so
a rate never jumps when a slot opens. The ring itself mirrors
`latency_digest` (six sub-windows rotated on the policy tick, multi-raft
design §6.1.4), for the same reason: lifetime averages hide what is happening
now. `latency_digest` merges the current sub-window too, which suits a
percentile; a rate divided by elapsed time would be noisy for the first
seconds of a slot, hence the difference.

**Refresh.** On the policy phase, every `_refresh_interval`:

```
keys = sm has split_policy_state_machine
         ? sm.suggest_split_keys(target - 1) filtered by range and can_split_at
         : {}
if keys.size() < 2: keys = reservoir quantiles at i/target, i = 1..target-1
dedupe, sort, drop keys equal to a range bound
if keys == current boundaries: keep everything (Req 2.3)
else: publish a new layout, version + 1, counters zero
```

`suggest_split_keys` is leader-only and advisory, so calling it here takes
on no determinism obligation (`splittable_state_machine.hpp`: "may consult a
cache, sample, or change their mind between calls"). It runs inside
`with_state_machine`, which is how the shard report reads sizes today.

## Leadership, split, merge

- **Leadership.** The policy phase only runs for led groups. A group that
  stops leading drops its set; one that starts leading builds one on its next
  policy phase (Req 4.1). The window is empty for a minute after a leader
  change, so the bucket split path waits a full `_duration` of window before
  it proposes, exactly as the sampler does.
- **Split.** `apply_split` already builds each child's `group_state`. It
  passes each child the parent's boundaries inside the child's range; the
  child publishes them as version 1 with empty counters (Req 4.2). Keeping
  the boundaries means a hot child can be split again without waiting a
  refresh interval for boundaries.
- **Merge.** The survivor takes both boundary lists plus the old shared bound.
  If that exceeds `_target_buckets`, boundaries are dropped one at a time,
  each time the one whose two adjacent buckets had the least combined load in
  the last window. The survivor's leader knows only its own buckets' loads,
  so the source's buckets count as zero and are coarsened first; the next
  refresh re-cuts by data or traffic anyway. Counters start empty (Req 4.3).

## Policy use (Req 6)

In `threshold_split_merge_policy`, beside the existing hot-key branch:

```
if load_split_enabled and buckets non-empty and window covers >= _duration
   and shard load over the sampler's threshold and not in sampler back-off:
     for each boundary b: left = sum(load of buckets below b), right = rest
     best = boundary minimising |left - right|
     if max(left, right) / (left + right) > one_sided_fraction:
          host.restrict_sampler(group, hottest bucket's range)   // Req 6.2
     else:
          propose split at best, reason read_load / write_load,
          _scatter_children = true
```

The sampler gains `restrict_to(shard_range<Key>)`, which only changes which
keys it admits as candidates. Its one-sided and back-off rules are untouched,
so a single hot key inside the hottest bucket still ends in back-off, and that
back-off also gates the bucket branch (Req 6.4).

The hot-key branch keeps priority: if the sampler has just produced a sample,
it is used, as today. Buckets are the faster first guess, not a replacement.

## Placement driver and metrics

`shard_report` gains `std::vector<bucket_stats<Key>> _hot_buckets`, the top
`_report_top_buckets` by `_read_qps + _write_qps` (Req 5.2). The placement
driver is in-process today (`elastic_shard_placement_driver`,
`cmd/multi_raft_node/capacity_plane.hpp`), so this is a struct field, not a
wire change. A driver may use it to prefer scattering a shard whose load is
spread (a split will divide it) over one whose load is one bucket.

One gauge per shard, `shard_hottest_bucket_share`, through the host's
existing metrics type. Per-bucket series would multiply cardinality by up to
256 per shard.

## Cost

| | disabled | enabled |
|---|---|---|
| request path | one branch | one atomic shared_ptr load, <= 8 key compares, 2 relaxed atomics, 1 in 16 a reservoir store |
| memory per led shard | 0 | (B+1) x slots x 32 bytes: 16 x 6 x 32 = 3 KiB at defaults |
| policy phase | 0 | a roll, a snapshot; a refresh once a minute |

The atomic `shared_ptr` load is the one item to watch: libstdc++'s
`std::atomic<std::shared_ptr>` takes a spin lock. Task 7 measures it; if it
shows, the layout pointer becomes a hazard-free epoch swap (a raw pointer
plus retirement on the policy phase after one full tick, since every request
that loaded the old layout finished inside that tick's routing).

## Testing

- `load_buckets_unit_test`: boundary choice, `can_split_at` filtering, the
  reservoir fallback, the sum rule, window expiry, layout swap under
  concurrent `count`, split inheritance, merge trimming, top-k.
- `load_buckets_property_test`: random boundaries and keys, each key in
  exactly one bucket whose range contains it.
- An integration case in the load-split tests: skewed writes split inside
  the hot quarter sooner than with the sampler alone; a single-key load is
  never split, with buckets on.
- `multi_raft_bench` rows with buckets off and on.
