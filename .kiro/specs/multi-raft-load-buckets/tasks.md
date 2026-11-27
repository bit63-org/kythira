# Implementation Plan — Multi-Raft load buckets

## Status: Complete (all tasks done 2026-11-20; Clark's go 2026-11-20)

Follow-up to `.kiro/specs/multi-raft/` Phase 9 and open question 4.

- [x] 1. Types and config
  - `bucket_stats<Key>` in `shard_types.hpp`; `_buckets` and
    `_buckets_version` appended to `shard_stats`; `bucket_config` in
    `multi_raft_config`, clamped and validated.
  - _Requirements: 1.1, 5.1_

- [x] 2. `bucket_set<Key>` in `include/raft/load_buckets.hpp`
  - Immutable layout swapped whole, lock-free `count`, slot window and
    `roll`, reservoir, `refresh`, `snapshot`.
  - Unit and property tests.
  - Deviation: the reservoir has its own mutex inside the set rather than
    borrowing the host's `_sampler_mutex`, so buckets work with sampling off;
    it is taken one keyed request in `_reservoir_stride`, as designed.
    `add_bytes` attributes a read's size after it completes, without counting
    a second request.
  - _Requirements: 2.3, 2.4, 3.2, 3.3, 7.1, 7.2_

- [x] 3. Count at the routing layer
  - In `route_and_run`, behind one branch on `_cfg.buckets._enabled`, beside
    the existing `_reads` / `_writes` and sampler calls; keyless requests stay
    shard-level only.
  - A read's size reaches its bucket from the read's continuation through
    `add_bytes`, as it reaches `_read_bytes` today.
  - _Requirements: 1.2, 3.1, 3.4_

- [x] 4. Boundaries on the policy phase
  - `suggest_split_keys` filtered by range and `can_split_at`, reservoir
    quantiles as the fallback, refresh interval, equal-set no-op; snapshot
    into `shard_stats`; drop on loss of leadership.
  - `group_state` builds its `bucket_set` once and `reset()`s it on gaining
    leadership or a new range, so the routing path reads it by plain pointer
    and pays one atomic load (the layout's), not two. While the set is still
    one bucket the policy phase re-cuts every tick rather than every refresh
    interval, so a new leader whose reservoir starts empty gets a cut as soon
    as traffic gives one.
  - _Requirements: 2.1, 2.2, 2.5, 4.1, 4.4_

- [x] 5. Split and merge
  - Children inherit inner boundaries; the merge survivor unions and trims by
    least combined load.
  - Inherited boundaries count as a fresh cut (the refresh clock starts at
    the hand-down), so a hot child can be split again at once.
  - Host cases in `multi_raft_load_buckets_test`; the trimming and merge
    rules in `load_buckets_unit_test`.
  - _Requirements: 4.2, 4.3_

- [x] 6. Exposure
  - `shard_report::_hot_buckets` (top k); the `shard_hottest_bucket_share`
    gauge.
  - The gauge is `kythira.multiraft.shard.hottest_bucket_share` (dimension
    `group`), emitted on the policy phase once a slot has closed.
    `best_bucket_cut`, `hottest_bucket_share` and `top_buckets` sit beside
    `bucket_stats` in `shard_types.hpp` so the policy can use them without
    the bucket set's header.
  - _Requirements: 5.2, 5.3_

- [x] 7. Load split from buckets
  - The bucket branch in the default policy; `load_split_sampler::restrict_to`;
    back-off gating; integration test against the sampler alone.
  - Deviations: `shard_stats` also gains `_buckets_window` (how long the
    rates cover; the policy waits for `_load_split_duration` of it) and
    `_load_split_backoff` (the sampler's back-off, Requirement 6.4), since a
    policy sees nothing but its stats. The sampler is narrowed by the host,
    not the policy: the policy stays a pure function, and the host applies
    the same one-sided rule to the same buckets on the policy phase, so the
    two cannot disagree.
  - The integration case shows the gap the spec names first ("a shard that
    cools and heats again pays that window every time"): a skewed load in
    60 ms bursts with idle gaps that span whole policy ticks. The sampler
    alone abandons every window and never splits in 3 s; with buckets the
    window spans the gaps and the split lands inside the hot quarter.
  - _Requirements: 6.1-6.4, 7.3_

- [x] 8. Measure
  - `multi_raft_bench` with buckets off and on; record the routing-path cost
    here, and replace the `std::atomic<std::shared_ptr>` layout pointer if it
    shows.
  - `tests/multi_raft_performance_report.cpp` gains a `load-buckets` axis:
    `fabric/none/128B/16/buckets-off` and `-on` (`kv_cluster_options::
    _buckets`; with buckets on the harness runs the policy phase once a
    second so leaders cut their sets).
  - Measured 2026-11-20 in a 4-core cloud sandbox, g++ 13 -O2, boost
    backend, `std::string` keys. `bucket_set::count` alone, 4M calls:

    | layout pointer | buckets | 1 thread | 4 threads, one shard |
    |---|---|---|---|
    | `std::atomic<std::shared_ptr>` | 2 | 68 ns | 1488 ns |
    | | 16 | 67 ns | 1574 ns |
    | | 256 | 125 ns | 1580 ns |
    | raw pointer + retirement | 2 | 23 ns | 341 ns |
    | | 16 | 28 ns | 172 ns |
    | | 256 | 71 ns | 192 ns |

    (4-thread figures are wall time per call per thread with every thread
    in a tight loop on one set: the worst case, since a routed request does
    microseconds of other work between counts.) The shared pointer showed,
    so it is replaced, as the design allowed: `count()` loads a raw pointer,
    and a replaced layout is freed by a later policy-phase call once it has
    been retired for two slots (at least a second). The reservoir stride
    also moved from a shared atomic to a per-thread counter, the other line
    every routing thread wrote. What remains contended is the counters
    themselves.
  - The fabric write row (3 nodes, 4 groups, closed loop, 16 in flight), 3
    alternating repetitions each: off 1327 / 1592 / 1296 ops/s, on 1639 /
    1263 / 1162 ops/s, p50 9.3-12.9 ms either way. The run-to-run spread
    (about 20%) is far larger than any bucket cost; at roughly 30 ns a count
    against a ~10 ms request, none is visible at the row level.
  - _Requirements: 7.4_

- [x] 9. Documentation
  - Document `bucket_config` beside `load_split_sampler_config` in
    `multi_raft.hpp`'s config reference and in the multi-raft design's §6.3,
    including how the bucket split relates to the sampler.
  - Done as a knob table on `multi_raft_config::buckets` and the multi-raft
    design's new §6.3.1.
  - _Requirements: 1.1_
