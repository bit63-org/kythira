# Implementation Plan

## Status: 1/57 tasks complete (phase 1: 1/23, phase 2: 0/14, phase 3: 0/20)

Each task is one PR unless noted. After every task, a cluster that sets
no new option behaves exactly as before: same commands, formats, metrics
and tests. Phase 2 starts when Clark prioritises it; its first task
finishes tier 3 (blocking list commands), as the requirements'
introduction explains. Phase 3 (the rest of Redis) follows phase 2.
Migration to and from real Redis (RDB files, `REPLICAOF`, `PSYNC`, bulk
copy) is its own spec, `.kiro/specs/redis-migration-tooling/`, which
needs only phase 1 and task 43 (the RDB value codec).

The shared layer pieces (layer identity, route cache, layer membership
group, authenticated-call handoff) are built by
`.kiro/specs/kinesis-independent-layers/`. A task here that needs one
before that spec has built it builds it to that spec's design, in core,
so that both services use one implementation.

## Task dependency graph

```
0 ─ 1 ─ 2 ─┬─ 3 ─ 4 ─┬─ 6 ─────────┐
           │         5            │
           ├─ 7 ─ 8 ─ 9 ─ 10 ─ 11 ─┤
           └─ 12 ─ 13 ─────────────┼─ 14 ─────────────┐
15 ─ 16 ─ 17 ─ 18 ─ 19 ─ 20 ───────┴──────────────────┼─ 21 ─ 22
                                                       │
phase 2:  23 ─┬─ 24                                    │
              ├─ 25 ─ 26 ─ 27 ─ 28                      │
              ├─ 29 ─ 30                               │
              ├─ 31                                    │
              └─ 32 ─ 33 ─────────── 34 ─ 35 ─ 36 ──────┘

phase 3:  37 ─ 38   39 ─ 40   41   42   43   44   45 ─ 46   47   48
          49   50   51   52   53 ─── 54 ─ 55 ─ 56
```

Tasks 15-20 (layers) do not depend on 1-14 (commands) and can run in
parallel with them; 20's workload uses whatever commands have merged and
is extended as the rest land.

## Phase 1 — tiers 1 to 3

- [x] 0. Spec, and the earlier spec's non-goals
  - This spec; `redis-compatible-kv` Non-Goals no longer list transactions
    (shipped by `multi-raft-transactions`) and point here for the goals
    this spec takes over
  - _Requirements: introduction_

- [x] 1. Command registry, `exec` record and command time
  - `services/redis/tools/redis_commands.yaml` → generated
    `redis_command_ids.hpp` with a CI freshness check
  - Format `0x03`: `exec`, `range_delete`, `format_gate`,
    `remove_members` records; codec, fuzz target, golden fixtures
  - `_applied_time_ms` in the memory state machine, snapshot marker
    `KRV3`, split/absorb carry it
  - Unit tests: codec round trip, old formats unchanged, monotonic floor
  - Server identity: `server_name:kythira`, `kythira_version`,
    a plain compatibility `redis_version`/`HELLO version` with
    `KYTHIRA_REDIS_COMPAT_VERSION`, `standalone` mode outside the Cluster
    compatibility mode; golden replies updated
  - _Requirements: 1.5-1.7, 2.1-2.6, 14.1, 14.2, 14.6_

- [x] 2. Format level and gate
  - Level in every node's health answer; `KYTHIRA.FORMAT STATUS|UPGRADE`;
    gate apply, inheritance through split, refusal before gate, stop on a
    record above the binary's level
  - In-process test: three nodes, one old-level binary blocks the gate
  - _Requirements: 14.3-14.5_

- [x] 3. Tier 1 string commands (memory store)
  - `INCR` family, `INCRBYFLOAT`/`HINCRBYFLOAT` in binary128 with the
    in-tree decimal conversion and amd64/arm64 golden replies (D1), `SET` options, `SETNX`, `PSETEX`,
    `GETSET`, `GETDEL`, `GETEX`, `APPEND`, `SETRANGE`, `TYPE`, `UNLINK`
    (one key), `TOUCH`, `OBJECT ENCODING`; replies from `apply()`
  - Size limit on resulting value; `COMMAND INFO`/`DOCS` key specs for
    every command so far
  - _Requirements: 1.3, 3.1-3.6, 3.8, 3.9_

- [x] 4. Expiry family
  - `EXPIRE`/`PEXPIRE`/`EXPIREAT`/`PEXPIREAT` with `NX|XX|GT|LT`,
    `PERSIST`, `PTTL`, `EXPIRETIME`, `PEXPIRETIME`; past deadline deletes;
    sweep vs `EXPIRE`/`PERSIST` race test
  - _Requirements: 4.1-4.4_

- [x] 5. Mutability policy and ACL categories
  - ACL file: categories, single commands, `%R~`/`%W~`/`~` scopes,
    mutable prefixes; today's roles as category sets; old lines parse
    identically (golden ACL fixtures)
  - Mutable-key bitmap in `exec`, decided in `apply()`; racing-writer test
  - Rolling-upgrade note in the docs
  - _Requirements: 5.1-5.4, 15.1-15.4_

- [x] 6. Multi-key commands
  - Planner: one group → one `exec`; several → transaction; else
    `-CROSSSLOT`; stale-epoch re-plan
  - `RENAME`, `RENAMENX`, `COPY [REPLACE]`, `MSETNX`, multi-key
    `DEL`/`UNLINK`/`EXISTS`; tests on single-group, cross-group,
    no-transaction builds, and a split between routing and submission
  - _Requirements: 3.7, 6.1-6.6_

- [x] 7. Typed value model and hashes
  - `redis_value` with chunked collections; `WRONGTYPE`; empty collection
    deletes the key; collection limits; incremental size accounting;
    shared-handle reads for `HGETALL`
  - Every hash command; `HSCAN` waits for task 12 (registered then)
  - Determinism test across two replicas on random streams
  - _Requirements: 9.1-9.6, 10.1, 10.2_

- [x] 8. Sets
  - Every set command; `SPOP` as leader-picked `remove_members`;
    multi-key set ops through task 6's planner
  - _Requirements: 9.5, 11.1_

- [ ] 9. Lists (non-blocking)
  - Every non-blocking list command; O(1) ends; `LMOVE`/`RPOPLPUSH`
    through the planner; blocking forms stay unknown
  - _Requirements: 12.1-12.3_

- [ ] 10. Typed values on the engine store
  - Header and element rows, key codec escaping, split/absorb moving a
    key's rows together, snapshot marker; file store refusal and an
    unchanged file-store golden test
  - Engine-chaos scenario gains hashes and lists in its history
  - _Requirements: 13.1-13.3_

- [ ] 11. Typed values in transactions and MVCC
  - Prepare evaluates, intent holds the resulting value, commit installs;
    typed commands in `MULTI`; `WATCH` on typed keys
  - MVCC chunk sharing between versions; GC frees unshared chunks; bank
    and write-skew tests extended with hashes
  - _Requirements: 13.4-13.6_

- [ ] 12. SCAN family
  - Cursor table on the front end, cursor encoding, idle expiry, forward
    to issuer, `invalid cursor`; per-group pages on the data side with
    pattern, type and prefix filtering; literal-prefix narrowing
  - `SCAN`, `HSCAN`, `SSCAN`, `KEYS` (admin, bounded), `RANDOMKEY`
  - Tests: iteration across splits, merges and leader changes returns
    every stable key exactly once; filtered keys never leak
  - _Requirements: 7.1-7.8_

- [ ] 13. Admin tools and introspection
  - `KYTHIRA.DELPREFIX` (bounded range deletes, lock resolution),
    `FLUSHDB`/`FLUSHALL` behind `KYTHIRA_REDIS_ALLOW_FLUSH`,
    `KYTHIRA.USAGE`, `MEMORY USAGE`, exact `DBSIZE`, `INFO keyspace`,
    `commandstats`, `errorstats`, `SLOWLOG`; audit lines
  - _Requirements: 8.1-8.6, 22.1-22.3_

- [ ] 14. Phase 1 conformance suites
  - Seeded command generator and recording format; differential runs
    against Redis 7.2 and Valkey 8 containers in RESP2 and RESP3 with the
    difference table; redis-py, go-redis and ioredis subsets; history
    checker on counters, locks, lists and hashes under kills and
    partitions; rolling-upgrade scenario through the format gate
  - Docker and rootless Podman, service names, `container_runtime()`
  - _Requirements: 1.4, 23.1-23.6_

- [x] 15. Layer roles and the in-process split of the code
  - `KYTHIRA_REDIS_ROLES` parsing and start-time validation, roles in
    `INFO` and metrics, `kythira_node` per-module roles
  - Move dispatch, authorization, planning and the coordinator into
    `redis_front_end` behind `redis_front_end_access`; data access behind
    `redis_data_access` with the local implementation only; co-located
    wiring in `redis_serving.hpp`
  - Baseline measurement of co-located latency and throughput before and
    after; every existing test unchanged
  - _Requirements: 16.1-16.7, 24.4_

- [x] 16. Data-layer API and front ends without data
  - `redis_data_service` on the internal listener (`KYTHIRA.DATA
    PROPOSE|READ|PAGE|ROUTE|ROUTES`), one-hop rule, epochs; route cache;
    `remote_data_access`; `KYTHIRA_REDIS_DATA_NODES` via `net_resolve`
  - Handler tests over local and remote access against an in-process data
    cluster; differential suite in a front-end/data split layout
  - `PAGE` arrives with `SCAN` (task 12), as a `handle_data` subcommand
    beside `READ`; nothing on main pages yet
  - _Requirements: 18.1-18.6_

- [x] 17. Gateway apart from the front end, and layer identities
  - `KYTHIRA.CALL` authenticated calls, connection pinning and re-pinning,
    `MULTI` batches and watch tokens, drain; layer identities and role
    checks on every internal command; internal user only between
    co-located nodes; refuse non-co-located roles without TLS; rotation
  - Revocation lists for layer certificates are not checked yet; the
    Kinesis `route_guard` has the hook, and the RESP link can take it when
    a CRL source lands
  - _Requirements: 17.1-17.4, 19.1-19.5_

- [x] 18. Layer membership group and scaling
  - Gateways and front ends in the shared layer membership group
    (fixed voters, non-voting members); configuration and DNS fallback;
    front-end indexes for cursors; capacity policy over connections,
    commands per second and CPU through `quorum_manager`; drain before
    decommission
  - _Requirements: 20.1-20.3_
  - Status: membership is in (`redis_layer_membership.hpp`, the gateway's
    membership round, `cmd/redis_gateway_node/redis_membership_group.hpp`):
    the group on `KYTHIRA_REDIS_MEMBERSHIP` voters with other members
    reaching it through `KYTHIRA.MEMBERS`, DNS and configuration fallback,
    load reports, drain through `KYTHIRA.LAYERS`, and front-end indexes in
    the group with the cursor layout. The capacity loop is in too
    (`cmd/redis_gateway_node/redis_layer_capacity*.hpp`,
    `KYTHIRA_REDIS_CAPACITY_*`): the group's leader runs the shared
    controller with `layer_capacity_policy` over one layer through the
    Docker quorum manager, and drains a member through the group before
    decommissioning it. Other providers (ASG, MIG, VMSS and the rest) are
    not wired to the Redis settings yet.

- [ ] 19. Migration operations and runbook
  - `KYTHIRA.EVACUATE`, refuse to start without `data` while holding
    replicas, front-end drain waiting for cursors up to a bound, adding
    `data` as learner then promote
  - Runbook for each split and merge, with checks and reversal
  - _Requirements: 21.1-21.6_

- [ ] 20. Layer migration path tests
  - In-process, each path in both directions under the mixed workload
    (counters, `SET NX` locks, hashes, lists, cross-shard `MSET` and
    `RENAME`, a long `SCAN`): gateway split/merge; front-end split/merge;
    data split/merge; gateway+front end vs data; co-located → three-way →
    co-located with a stop and reversal midway
  - Checks: no lost or doubled acknowledged write, exact counter totals,
    transaction atomicity, every `SCAN` complete without duplicates,
    types and deadlines intact
  - docker-chaos scenario of the full path both ways, killing one node per
    layer, on Docker and rootless Podman; co-located measurement row
  - _Requirements: 21.5, 24.1-24.4_

- [ ] 21. Interoperability with ElastiCache and MemoryDB
  - CI (no spend): recorded ElastiCache (Valkey, Redis OSS) and MemoryDB
    transcripts of the generator's streams replayed against co-located
    and three-way layouts; ElastiCache access strings parsed against the
    ACL
  - Real-cloud bundle (dispatch-only, repository-variable switch): the
    smallest ElastiCache serverless cache and MemoryDB cluster with an
    in-VPC runner; re-record transcripts; client suites against AWS and
    Kythira compared; ElastiCache IAM auth tokens against `auth=iam`
    users; cost report; delete everything, including on failure
  - Each real-cloud run needs Clark's go in his own words
  - _Requirements: 25.1-25.3_

- [ ] 22. Phase 1 documentation and default
  - `doc/redis-gateway.md`: command tables, difference table, mutability
    and categories, format gate procedure, layer guide (roles, which
    layer holds which secret, sizing), split/merge runbook link
  - `CONFIG_REDIS_GATEWAY_DATA_TYPES` defaults to `y`; module-off and
    boundary checks pass
  - _Requirements: 37.1-37.4_

## Phase 2 — finishing tier 3, then tiers 4 to 6

- [ ] 23. Catalog group
  - One Redis-module Raft group on data nodes, created by a format gate;
    versioned `KYTHIRA.DATA CATALOG SINCE` watch; cluster settings in it;
    catalog replica moves in the evacuation path
  - _Requirements: 26.1, 26.4, 29.2, 32.1, 33.1_

- [ ] 24. Blocking list commands
  - Key watches with leases on group leaders, wake on push, parked
    clients FIFO per front end, re-registration on route change, pop retry
    after renew; `BLPOP`, `BRPOP`, `BLMOVE`, `BRPOPLPUSH`, `BLMPOP`;
    non-blocking inside `MULTI`; behind `CONFIG_REDIS_GATEWAY_BLOCKING`
  - Tests: leader kill while clients are blocked loses no push
  - _Requirements: 27.1-27.5_

- [x] 25. Lua 5.1 overlay and sandbox
  - `vcpkg-overlays/lua51/` with deterministic number formatting, Redis's
    bundled libraries, licences recorded; sandbox, locked globals,
    instruction and allocation budgets; determinism tests across amd64
    and arm64 CI
  - _Requirements: 30.1-30.5, 37.2_

- [ ] 26. Single-shard scripts
  - `EVAL`, `EVALSHA`, `EVAL_RO`, `EVALSHA_RO`, `SCRIPT
    LOAD|EXISTS|FLUSH`; declared-key rule; `script` record with body and
    seed; `redis.call` on the shared command evaluator; buffered writes;
    `-NOSCRIPT`; behind `CONFIG_REDIS_GATEWAY_SCRIPTING`
  - _Requirements: 28.1-28.3, 28.6, 28.7_

- [ ] 27. Cross-shard scripts
  - Front-end execution inside a multi-Raft transaction, prepare-locked
    reads, buffered intents, retries, wall-time limit and `SCRIPT KILL`;
    `-CROSSSLOT` without transactions
  - _Requirements: 28.4, 28.5, 30.5_

- [ ] 28. Functions
  - `FUNCTION LOAD|DELETE|LIST|FLUSH|DUMP|RESTORE|STATS`, `FCALL`,
    `FCALL_RO`; libraries in the catalog; flags, including
    `allow-cross-slot-keys` selecting the cross-shard path
  - _Requirements: 29.1-29.4_

- [ ] 29. Pub/sub
  - `SUBSCRIBE`, `PSUBSCRIBE`, `PUBLISH`, `PUBSUB …`, RESP2 subscriber
    mode and RESP3 push; interest tables through the layer membership
    group or broadcast; channel ACLs and disconnect on revocation;
    output-buffer bounds; behind `CONFIG_REDIS_GATEWAY_PUBSUB`
  - _Requirements: 31.1-31.3, 31.5, 31.6_

- [ ] 30. Sharded pub/sub and keyspace notifications
  - `SSUBSCRIBE`, `SUNSUBSCRIBE`, `SPUBLISH` via leader fan-out;
    `notify-keyspace-events` in the catalog; leader-only emission
    including sweep and eviction events; zero cost when off
  - _Requirements: 31.4, 32.1-32.4_

- [ ] 31. Replicated ACL
  - `ACL` subcommands over catalog users, PBKDF2 at the front end,
    `#sha256` opt-in, Kythira rules in `SETUSER`, `ACL LOG` from the
    audit stream, file as bootstrap import
  - Tests of file → replicated and replicated → file, on co-located and
    split clusters; behind `CONFIG_REDIS_GATEWAY_REPLICATED_ACL`
  - _Requirements: 33.1-33.6, 35.3_

- [ ] 32. Slot keyspace and the Cluster protocol compatibility mode
  - Second multi-Raft host keyed by slot, slot-aligned splits;
    `CLUSTER …`, `READONLY`, `READWRITE`, `ASKING`; topology mapped to
    gateways; optional `-MOVED`, `-ASK` during range moves; cross-slot
    rule; behind `CONFIG_REDIS_GATEWAY_CLUSTER`
  - Cluster-mode client subsets (redis-py `RedisCluster`, go-redis
    `ClusterClient`, Lettuce)
  - _Requirements: 34.1-34.5, 34.7_

- [ ] 33. Keyspace migration
  - `KYTHIRA.KEYSPACE MIGRATE TO slot|ordered`: catalog state, dual
    reads, transactional writes and batched copy, cut-over; tests in both
    directions under a workload, on co-located and split clusters
  - _Requirements: 34.6, 35.3_

- [ ] 34. Phase 2 layer migration path tests
  - Requirement 24's paths extended, both directions: gateways with live
    subscribers, front ends with blocked clients and cross-shard scripts,
    data nodes during single-shard scripts and notifications, catalog
    replica moves; docker-chaos on Docker and rootless Podman
  - _Requirements: 26.2, 35.1, 35.2_

- [ ] 35. Phase 2 interoperability
  - Recorded transcripts extended with scripts, functions, pub/sub,
    notifications, ACL and cluster topology, replayed in CI
  - Real-cloud bundle adds a cluster-mode ElastiCache cache and MemoryDB
    with ACL users; cluster client suites, the same Lua and function
    libraries and pub/sub fan-out against both, compared; Clark's go each
    run
  - _Requirements: 26.3, 36.1, 36.2_

- [ ] 36. Phase 2 documentation
  - Scripting, pub/sub, notifications, ACL and cluster chapters; phase 2
    Kconfig defaults once each acceptance task merges
  - _Requirements: 26.1, 37.1, 37.4_

## Phase 3 — the rest of Redis

- [ ] 37. Sorted sets
  - `zset` type (score/member chunks plus member index), every `Z*`
    command, blocking `BZPOPMIN`/`BZPOPMAX`/`BZMPOP` on key watches,
    shortest round-trip score printing, engine rows, format gate level
  - _Requirements: 38.1-38.4_

- [ ] 38. Geo
  - Geohash scores over zsets; reads on the serving node;
    `GEOSEARCHSTORE` computed by the front end and proposed as an explicit
    store (D12)
  - _Requirements: 39.1, 39.2_

- [ ] 39. Streams
  - `stream` type, `XADD` IDs from command time, `XRANGE`, `XREVRANGE`,
    `XLEN`, `XDEL`, `XTRIM` (D13), `XSETID`, `XREAD` with `BLOCK`, `XINFO
    STREAM`
  - _Requirements: 40.1-40.3, 40.5-40.7_

- [ ] 40. Stream consumer groups
  - `XGROUP …`, `XREADGROUP`, `XACK`, `XPENDING`, `XCLAIM`, `XAUTOCLAIM`,
    `XINFO GROUPS|CONSUMERS`; PEL with command-time idle; blocking reads
  - _Requirements: 40.2, 40.4, 40.6_

- [ ] 41. Bitmaps, bitfields, HyperLogLog
  - Bit commands on strings; Redis's `HYLL` format byte for byte;
    `PFCOUNT` without write-back (D14); vectors from the reference
    server's test suite
  - _Requirements: 41.1-41.3_

- [ ] 42. `LCS`, hash field expiry, `SORT`
  - `LCS`, `SUBSTR`; field deadlines and per-field sweep; `SORT`/`SORT_RO`
    with the cross-group rule (D15)
  - _Requirements: 42.1, 42.2_

- [ ] 43. RDB codec, `DUMP`/`RESTORE`, `OBJECT`
  - `redis_rdb.hpp` for RDB 9-12 and the `DUMP` envelope; round trips
    against Redis 7.2 and Valkey 8 for every phase 1 type; computed
    `OBJECT ENCODING` (D16), `IDLETIME`/`FREQ`/`REFCOUNT`
  - `MIGRATE` to another Redis-protocol server by `DUMP` + `RESTORE`
  - _Requirements: 44.1-44.3_

- [ ] 44. Multiple databases
  - Key spaces for dbs 1-15, catalog mapping, `SELECT`, `MOVE`, `COPY …
    DB`, `SWAPDB` as one catalog entry, per-db `FLUSHDB`, ACL and `INFO`
  - _Requirements: 43.1-43.4_

- [ ] 45. Server and client surface
  - `CONFIG` with the parameter table (mapped, emulated, inert), `CLIENT`
    subcommands with cluster-wide `LIST`/`KILL`/`PAUSE`, `MONITOR`, `WAIT`
    and `WAITAOF` (D18), `LATENCY`, `MEMORY`, full `INFO`, `ROLE`, `TIME`,
    `SHUTDOWN`, `FAILOVER`, `DEBUG` subset behind its switch (D19);
    `REPLICAOF`/`SYNC`/`PSYNC` stay unknown until the migration spec
  - _Requirements: 45.1, 45.2, 45.4-45.8, 47.2, 47.3_

- [ ] 46. Client-side caching
  - `CLIENT TRACKING` (default, `BCAST`, `OPTIN`, `OPTOUT`, `NOLOOP`,
    `REDIRECT`), RESP3 pushes and the RESP2 channel, flush on leader change
    (D17)
  - _Requirements: 45.3_

- [ ] 47. Memory policies
  - Per-group budgets, `noeviction` `-OOM` in `apply()`, LRU/LFU victim
    selection with follower `touch` reports, `evict` entries, deviations
    documented (D20)
  - _Requirements: 46.1-46.6_

- [ ] 48. Persistence commands
  - `SAVE`, `BGSAVE`, `LASTSAVE`, `BGREWRITEAOF` mapped to snapshots and
    compaction (D21)
  - _Requirements: 47.1_

- [ ] 49. JSON
  - `JSON.*` with JSONPath and legacy paths; copy-on-write tree; RDB
    value codec for RedisJSON values
  - _Requirements: 48.1, 48.5_

- [ ] 50. Probabilistic types
  - `BF.*`, `CF.*`, `CMS.*`, `TOPK.*`, `TDIGEST.*`, deterministic
  - _Requirements: 48.2, 48.5_

- [ ] 51. Vector sets
  - `V*` commands, seeded deterministic HNSW, scalar kernel without FMA
    contraction (D23)
  - _Requirements: 48.3, 48.5_

- [ ] 52. Time series
  - `TS.*`, labels, retention by command time, compaction rules,
    `TS.MRANGE` fan-out
  - _Requirements: 48.4, 48.5_

- [ ] 53. Query engine scoping spec
  - A separate spec for `FT.*` (secondary indexes across groups, full text,
    vector search over hashes and JSON, MemoryDB vector search interop)
  - _Requirements: 48.6_

- [ ] 54. Phase 3 layer migration path tests
  - Requirement 24's paths extended, both directions: gateways with
    tracking clients, front ends during `MONITOR`, `CLIENT PAUSE` and
    `SORT … STORE`, data nodes during consumer-group work, `noeviction`
    pressure, `SWAPDB` and `MOVE`;
    docker-chaos on Docker and rootless Podman
  - _Requirements: 49.1, 49.2_

- [ ] 55. Phase 3 interoperability
  - Differential suite and recorded ElastiCache/MemoryDB transcripts for
    every phase 3 command the engines support (ElastiCache Valkey JSON and
    Bloom included)
  - Real-cloud bundle: phase 3 commands in the client-suite comparison
    against ElastiCache and MemoryDB; Clark's go each run
  - _Requirements: 49.3, 49.4_

- [ ] 56. Phase 3 documentation
  - Command tables and difference rows D12-D23, `CONFIG` parameter table,
    memory policy guide, Kconfig defaults
  - _Requirements: 26.1, 37.4_
