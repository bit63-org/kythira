# Implementation Plan — Multi-Raft load buckets

## Status: In progress (tasks 1-5 done; Clark's go 2026-11-20)

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

- [ ] 6. Exposure
  - `shard_report::_hot_buckets` (top k); the `shard_hottest_bucket_share`
    gauge.
  - _Requirements: 5.2, 5.3_

- [ ] 7. Load split from buckets
  - The bucket branch in the default policy; `load_split_sampler::restrict_to`;
    back-off gating; integration test against the sampler alone.
  - _Requirements: 6.1-6.4, 7.3_

- [ ] 8. Measure
  - `multi_raft_bench` with buckets off and on; record the routing-path cost
    here, and replace the `std::atomic<std::shared_ptr>` layout pointer if it
    shows.
  - _Requirements: 7.4_

- [ ] 9. Documentation
  - Document `bucket_config` beside `load_split_sampler_config` in
    `multi_raft.hpp`'s config reference and in the multi-raft design's §6.3,
    including how the bucket split relates to the sampler.
  - _Requirements: 1.1_
