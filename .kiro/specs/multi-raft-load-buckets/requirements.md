# Requirements Document

## Introduction

`.kiro/specs/multi-raft/` deferred one refinement to its Phase 9 and its open
question 4: TiKV RFC 0082's **buckets**, a sub-shard unit of load statistics.
Today a shard's load is one number per direction (`shard_stats::_read_qps`,
`_write_qps`, counted per routed request in `multi_raft::route_and_run`), plus
the load-split sampler's (`include/raft/load_split_sampler.hpp`) single
`hot_key_sample` when it has finished a sampling window. That leaves three
gaps:

1. **The load split is slow to aim.** The sampler starts from zero each time
   a shard crosses its threshold: it picks candidate keys from live traffic
   and counts for `_duration` (ten seconds) before it can say where to cut.
   A shard that cools and heats again pays that window every time.
2. **"Hot" has no location.** A placement driver choosing which shard to
   scatter, or an operator reading the stats, sees that a shard is busy but
   not whether the load is spread over its range or sits in one corner.
3. **"Cold" has no location either.** A merge candidate is judged by size and
   whole-shard qps; a large shard whose traffic all lands in one small part
   looks no colder than one evenly busy.

A bucket is a contiguous key range inside a shard with its own read and write
counters. Boundaries come from the state machine where it can say where its
data is, and from observed traffic where it cannot. Statistics are leader-local
and never replicated, so they add nothing to the log and no obligation to
followers.

`shard_stats` was shaped for this: the design promised buckets could be added
as a field without breaking the policy concept. This spec keeps that promise.

Building this spec needs Clark's call; it is spec only.

## Glossary

- **Bucket**: a half-open key range `[start, end)` inside a shard's range,
  with read and write counters over a sliding window.
- **Bucket boundaries**: the sorted keys that cut a shard's range into
  buckets. `B` boundaries make `B + 1` buckets.
- **Bucket set**: one shard's boundaries, counters and version.
- **Bucket version**: a counter bumped whenever a shard's boundaries change,
  so a consumer can tell a re-cut from a change in load.
- **Host**: `multi_raft<Types, Key, GroupId>`.

## Requirements

### Requirement 1: Off by default, free when off

**User Story:** As an operator, I want buckets to cost nothing unless I turn
them on.

#### Acceptance Criteria

1. `multi_raft_config` SHALL gain a `bucket_config` with `_enabled{false}`.
2. WHEN buckets are disabled, THE routing path SHALL take one predictable
   branch on an immutable config member and no lock, the same rule as the
   load-split sampler (multi-raft Requirement 9.7).
3. WHEN buckets are disabled, `shard_stats::_buckets` SHALL be empty and
   every existing policy SHALL behave exactly as today.

### Requirement 2: Boundaries

**User Story:** As a policy author, I want bucket boundaries that follow where
the data or the traffic actually is.

#### Acceptance Criteria

1. WHEN the state machine satisfies `split_policy_state_machine`, THE leader
   SHALL take boundaries from `suggest_split_keys(_target_buckets - 1)`,
   keeping only keys inside the shard's range and for which `can_split_at`
   is true.
2. WHEN it does not, or returns fewer than two usable keys, THE leader SHALL
   take boundaries from quantiles of a bounded reservoir of keys seen at the
   routing layer (`_reservoir_size`, default 1024).
3. THE leader SHALL refresh boundaries every `_refresh_interval` (default
   60 s) and SHALL keep the old boundaries, counters and version when the new
   set is equal to them.
4. THE number of buckets SHALL never exceed `_target_buckets` (default 16,
   at most 256).
5. Boundary computation SHALL run on the policy phase of `tick()`, never on
   the request path.

### Requirement 3: Counting

**User Story:** As a policy author, I want per-bucket load that means the same
thing as the shard's own load figures.

#### Acceptance Criteria

1. THE routing layer SHALL attribute every keyed read and write it already
   counts in `_reads` / `_writes` to the bucket containing the key, by binary
   search over the boundaries.
2. Each bucket SHALL count reads, writes, read bytes and write bytes over a
   sliding window of `_window_slots` slots of `_slot_duration` each (defaults
   6 x 10 s), so a rate reflects the last minute, never the shard's lifetime.
3. THE sum of the buckets' counts over a window SHALL equal the shard's keyed
   request count over the same window.
4. Requests with no key (whole-shard commands, `submit_command(group, ...)`)
   SHALL be counted only at shard level, as today.

### Requirement 4: Leadership, split and merge

**User Story:** As a maintainer, I want bucket state to stay correct through
the events that change who measures and what range is measured.

#### Acceptance Criteria

1. Bucket sets SHALL be leader-local: a new leader starts with an empty
   window and computes boundaries on its first policy phase.
2. WHEN a split applies, each child SHALL inherit the parent's boundaries
   that fall strictly inside its range, with empty counters and a fresh
   version.
3. WHEN a merge applies, the survivor SHALL take the union of both shards'
   boundaries plus the old boundary key between them, trimmed to
   `_target_buckets` by dropping the boundaries whose adjacent buckets had
   the least combined load, with empty counters.
4. No bucket state SHALL be written to the Raft log or to persistent storage.

### Requirement 5: Exposure

**User Story:** As a policy author and as an operator, I want to read buckets
where I already read shard load.

#### Acceptance Criteria

1. `shard_stats` SHALL gain `std::vector<bucket_stats<Key>> _buckets` and
   `std::uint64_t _buckets_version`, defaulting to empty and zero.
2. `shard_report` SHALL carry at most `_report_top_buckets` (default 4)
   buckets per shard, the busiest by combined qps, so a placement-driver
   heartbeat stays bounded however many shards a host carries.
3. THE host's metrics SHALL expose, per shard, the share of keyed load held
   by its busiest bucket (`shard_hottest_bucket_share`), a number in
   `[0, 1]`; not one series per bucket.

### Requirement 6: Using buckets in the load split

**User Story:** As an operator running load-based split, I want a hot shard
split at the right place sooner, and never split on one hot key.

#### Acceptance Criteria

1. WHEN buckets and load split are both enabled and a shard has held its
   load over the sampler's threshold for a full `_duration`, THE default
   policy SHALL be able to propose a split at the bucket boundary that best
   balances the window's load, without waiting for a new sampling window.
2. THE bucket proposal SHALL apply the sampler's one-sided rule: if every
   boundary leaves more than `_one_sided_fraction` of the load on one side,
   it SHALL NOT propose; instead it SHALL start the sampler with its
   candidates restricted to the hottest bucket's range.
3. A bucket-based proposal SHALL use the existing reasons (`read_load` /
   `write_load`) and SHALL set `_scatter_children`, exactly as a
   sampler-based one (multi-raft Requirement 9.6).
4. The single-hot-key back-off of the sampler SHALL also suppress
   bucket-based proposals for that shard.

### Requirement 7: Tests and measurement

**User Story:** As a maintainer, I want the invariants proved and the claimed
speed-up measured.

#### Acceptance Criteria

1. Unit tests SHALL cover: boundary choice from `suggest_split_keys` and from
   the reservoir; `can_split_at` filtering; the sum rule of Requirement 3.3;
   window expiry; the split and merge rules of Requirement 4; the top-k bound
   of Requirement 5.2; and that the disabled path leaves `_buckets` empty.
2. A property test SHALL check, over random boundary sets and key streams,
   that every key lands in exactly one bucket and the bucket's range contains
   it.
3. An integration test SHALL show a skewed write load (one quarter of the
   range taking 90% of writes) split at a boundary inside that quarter in
   less wall-clock time than the sampler alone needs, and a single-key load
   never split.
4. The routing-path overhead with buckets enabled SHALL be measured with the
   existing `multi_raft_bench` and recorded in the spec's tasks file.
