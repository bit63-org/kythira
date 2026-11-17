# Requirements Document — General Redis Data Types, in Splittable Layers

## Introduction

The Redis service (`services/redis/`, `.kiro/specs/redis-compatible-kv/`)
was built for one client: sccache. Its command set is the closure of what
sccache's client stack puts on the wire (`GET`, `SET`, `SETEX`, `DEL`,
`EXISTS`, `STRLEN`, `GETRANGE`, the handshake), plus what
`.kiro/specs/multi-raft-transactions/` added on top (`MSET`, `MGET`,
multi-key `DEL`, `MULTI`/`EXEC`/`DISCARD`, `WATCH`, `KYTHIRA.ISOLATION`).
Values are opaque byte strings, every replica decides expiry against a
deadline the leader stamped, and the default policy refuses to change the
bytes under an existing key, because a compile cache is an
execution-authority store.

That spec is complete and its scope was a decision, recorded in its
Non-Goals. This spec is the follow-on that turns a chosen part of those
non-goals into goals, so that the service is useful to ordinary Redis
applications (counters, locks, rate limiters, sessions, queues, object
caches, invalidation fan-out), and not only to a build cache. The earlier
spec stays the record of the sccache server; nothing here reopens it.

Clark asked for it on 2026-11-17 in two phases, "1-3, then 3-6", over the
six tiers below, and asked that it be built "with multiple optionally
independent layers that can be split and merged".

| Tier | What | Phase |
|---|---|---|
| 1 | String basics: `INCR`/`DECR` family, the `EXPIRE` family, `SET` with `NX`/`XX`/`GET`/`PX`/…, `GETDEL`, `GETEX`, `APPEND`, `SETRANGE`, `RENAME`, `COPY`, `TYPE`, `UNLINK` | 1 |
| 2 | `SCAN`, `KEYS`, prefix delete, `FLUSHDB`, usage reports, `MEMORY USAGE` | 1 |
| 3 | Typed values: hashes, sets, lists (non-blocking first, then blocking) | 1, finishing in 2 |
| 4 | Lua scripts (`EVAL`, `EVALSHA`, `SCRIPT`) and functions (`FUNCTION`, `FCALL`) | 2 |
| 5 | Pub/sub (classic, pattern and sharded) and keyspace notifications | 2 |
| 6 | A replicated ACL (`ACL SETUSER` …), then the Redis Cluster protocol as a compatibility mode | 2 |
| 7-12 | The rest of Redis: sorted sets and geo, streams, bitmaps and HyperLogLog, the server surface, memory policies and RDB, Redis 8's built-in types | 3 |

**How "1-3, then 3-6" is read.** Tier 3 appears in both phases. This spec
reads that as: phase 1 delivers tiers 1, 2 and the non-blocking part of
tier 3 (hashes, sets, lists without blocking pops); phase 2 opens by
finishing tier 3 (the blocking list commands, which need the same
data-node wake-up machinery as pub/sub, and any tier 3 command phase 1
could not close) and then delivers tiers 4 to 6. If phase 1 closes all of
tier 3 except blocking pops, phase 2 is effectively tiers 4 to 6.

**Layers.** Today every `redis_gateway_node` (and the Redis module of
`kythira_node`) runs, in one process, the RESP listener, command dispatch
and the transaction coordinator, and the Raft replicas of the key-value
shards. Following `.kiro/specs/kinesis-independent-layers/` (PR #843) and
Clark's standing rules of 2026-11-17, this spec splits the service into
three layers that can each run on their own processes or clusters:

1. **gateway**: RESP framing, TLS, authentication, connection limits,
   connection state (protocol, `MULTI` queue, subscriptions), and later
   pub/sub fan-out to subscribers;
2. **front end**: authorization, command planning (single-shard, fan-out
   or transaction), the transaction coordinator, `SCAN` cursors, cross-shard
   scripts, and later the cluster topology answers;
3. **data**: the multi-Raft host, the key-value state machines, the
   maintenance sweeps, single-shard script execution, and later the
   catalog group (ACL, function libraries) and the source of keyspace
   notifications.

Co-located operation (all three in one process) stays the default and is
never required to change. Any layer can be **split** out onto its own
nodes, and split layers can be **merged** back, on a running cluster in
both directions. Every migration path has a test task.

**Scope**: the tier 1 to 6 commands; the typed value model, its log and
snapshot formats and the rolling upgrade to them; how each command behaves
on each storage backend and under each transaction build; the three
layers, their roles, internal APIs, authentication, membership and
migrations; interoperability with Redis OSS / Valkey and with AWS
ElastiCache and MemoryDB; tests and documentation.

**Out of scope** (see Non-Goals): loading native modules, AOF/RDB files as
the durability mechanism, the `FT.*` query engine (scoped by phase 3 into
its own spec), migration to and from real Redis (RDB files, `REPLICAOF`,
`PSYNC`, bulk copy, joining a Redis Cluster), which is
`.kiro/specs/redis-migration-tooling/`, and any change to the disk-backed build cache
(`KYTHIRA_CACHE_PERSISTENCE=file`), which stays a string-only store.

**Phase 3** (added at Clark's request the same day) covers the rest of
Redis: tiers 7 to 12 below Requirement 37.

## Glossary

- **Tier**: one row of the table above.
- **Typed value**: the value under a key, now one of `string`, `hash`,
  `set` or `list`. Every value written before this spec is a `string`.
- **Command time**: a wall-clock millisecond instant the leader stamps
  into a log entry when it proposes it, and the only clock `apply()` may
  use (Requirement 2).
- **Format gate**: a log entry, proposed once per group, that turns on a
  newer log-entry and snapshot format for that group after every replica
  has shown it can read it (Requirement 14).
- **Single-shard command**: a command whose keys all route to one group.
- **Cross-shard command**: a multi-key command whose keys route to more
  than one group; it runs as a multi-Raft transaction or is refused.
- **Layer**: gateway, front end or data.
- **Role set**: the layers a process runs, from `KYTHIRA_REDIS_ROLES`.
  A node with all three is **co-located**.
- **Split** a layer: move it off some nodes so it runs on nodes that do
  not run some other layer. **Merge** layers: the reverse.
- **Data-layer API**: the internal calls a data node offers front ends.
- **Authenticated call**: what a gateway hands a front end: the command,
  the verified identity and the connection state the command needs.
- **Layer identity**, **route cache**, **layer membership group**: the
  shared pieces defined by `.kiro/specs/kinesis-independent-layers/`
  (Requirements 6, 7 and 10 there), reused here.
- **Catalog group**: a single Raft group of the Redis module, on data
  nodes, holding replicated service-wide state (phase 2: ACL users,
  function libraries, keyspace mode).
- **Slot keyspace**: phase 2's Redis Cluster keyspace, routed by CRC16
  hash slot instead of by raw key order.
- **Reference server**: Redis OSS 7.2 and Valkey 8, run in containers, that
  differential tests compare replies against.

## Requirements

### Phase 1 — tiers 1 to 3

### Requirement 1: Scope by evidence, as before

**User Story:** As the maintainer, I want "Redis compatible" to keep
meaning a fixed, tested command list, so that the claim stays verifiable.

#### Acceptance Criteria

1. The design SHALL contain one table per tier listing every command and
   option this spec implements, the reference-server behaviour it matches,
   and every deliberate difference. A command not in a table SHALL answer
   `-ERR unknown command …`, exactly as today.
2. The target clients SHALL be named, and their use of each command
   checked against their source rather than the Redis manual: redis-py,
   redis-rs, go-redis, ioredis / node-redis, Jedis / Lettuce, and the
   rate-limiter and lock libraries built on them (redis-py `Lock`,
   Redlock implementations, `redis-cell`-free token buckets written in
   `INCR` + `EXPIRE`).
3. `COMMAND`, `COMMAND COUNT`, `COMMAND INFO` and `COMMAND DOCS` SHALL
   describe exactly the commands a node accepts on its build, with Redis's
   key-specification fields, so that cluster-aware clients can find a
   command's keys without a built-in table.
4. Each command's reply SHALL be byte-identical to the reference server's
   for the same inputs and starting state, in both RESP2 and RESP3, except
   where the design's difference table says otherwise. The differential
   suite (Requirement 23.2) is the proof.
5. **Kythira identifies itself as Kythira**, never as Redis or Valkey
   (Clark, 2026-11-17: "Kythira needs its own name for vendor"), following
   the convention Valkey uses for the same problem:
   - `HELLO`'s map SHALL carry `server` = `kythira` (as today) and an added
     `kythira_version` field with Kythira's own version;
   - `INFO server` SHALL carry `server_name:kythira` and
     `kythira_version:<version>`, where the version is the build's
     (CMake project version plus `git describe`);
   - `redis_version` in `INFO`, and `version` in `HELLO`, SHALL be a plain
     `major.minor.patch` **compatibility level** that clients use to gate
     features (Lettuce, StackExchange.Redis and others parse it). It SHALL
     be the Redis release whose command set this build implements for the
     target clients, set per build and overridable with
     `KYTHIRA_REDIS_COMPAT_VERSION`, and SHALL never carry a vendor suffix,
     because a suffix breaks clients' version parsers.
6. Today the gateway answers `version` `7.0.0-kythira` in `HELLO` and
   `redis_version:7.0.0-kythira` in `INFO`, has no `server_name` or
   `kythira_version`, and reports `mode` `cluster` / `redis_mode:cluster`.
   Phase 1 SHALL change these to Criterion 5's form, and SHALL report
   `mode` `standalone` / `redis_mode:standalone` unless the Cluster
   compatibility mode (Requirement 34) is on, because cluster-aware
   tools treat `cluster` as a promise that `CLUSTER` commands work.
7. Every Kythira-specific command SHALL keep the `KYTHIRA.` prefix, every
   Kythira-specific `INFO` field the `kythira_` prefix, and every
   Kythira-specific error SHALL say Kythira where Redis's wording would
   otherwise name Redis (for example `-LOADING Kythira is loading …`, as
   today).
8. `CLUSTER NODES`/`SHARDS` in the compatibility mode SHALL name Kythira
   gateways with a `kythira-` prefix in the human node name and hostname
   fields, so an operator can tell them from Redis nodes.

### Requirement 2: Deterministic command time

**User Story:** As a replica, I need conditional writes that depend on
expiry to come out the same on every replica, without reading a clock in
`apply()`.

#### Acceptance Criteria

1. Every log entry of the new format that reads or writes expiry state
   (all tier 1 writes, all typed-value writes, `SET … NX`/`XX`, every
   `EXPIRE` variant) SHALL carry a command time stamped by the proposing
   leader.
2. `apply()` SHALL treat a key whose deadline is at or before the entry's
   command time as absent, for that entry. It SHALL NOT read a clock.
3. Each group's state SHALL hold the largest command time it has applied,
   and `apply()` SHALL use `max(entry time, that value)`, so time never
   runs backwards across a leader change between nodes whose clocks
   differ. That value SHALL be in snapshots and `split_state` output.
4. Relative expiry arguments (`EX`, `PX`, `EXPIRE`, `PEXPIRE`, `GETEX EX`)
   SHALL be turned into absolute deadlines from the command time, on the
   leader, before proposing, as `SETEX` is today.
5. Lazy expiry at read time (redis-compatible-kv Requirement 8.3) and the
   leader-proposed sweep (8.4) SHALL be unchanged. The design SHALL state
   the window in which a read on a follower and a write's command time can
   disagree, and why that window is the same clock-skew window the earlier
   spec already documents.
6. A leader whose clock is behind the group's applied command time by more
   than a configurable bound SHALL log a warning and count it, because its
   writes are then being stamped with the group's time rather than its own.

### Requirement 3: String basics (tier 1)

**User Story:** As an application, I want counters, compare-and-set
writes, appends and atomic read-and-delete, so that I can build locks,
rate limiters and sessions.

#### Acceptance Criteria

1. The gateway SHALL implement `INCR`, `DECR`, `INCRBY`, `DECRBY` and
   `INCRBYFLOAT`, evaluated inside `apply()` against the stored value,
   with Redis's errors (`-ERR value is not an integer or out of range`,
   `-ERR increment or decrement would overflow`,
   `-ERR value is not a valid float`) and Redis's rule that a missing key
   counts as `0`.
2. `INCRBYFLOAT` and `HINCRBYFLOAT` SHALL compute in IEEE-754 binary128
   (quad precision) on every platform: native `long double` on arm64
   Linux, `__float128` on amd64 (Clark, 2026-11-17). Parsing the stored
   value and the increment, and printing the result, SHALL use one in-tree
   correctly rounded binary128 decimal conversion on both architectures,
   never the C library's `strtold`/`printf`, so a mixed amd64/arm64 group
   agrees byte for byte. The result SHALL be printed as Redis prints it:
   17 digits after the decimal point, trailing zeros and a trailing point
   removed (Redis's `ld2string` human mode), so `0.1` plus `0.2` replies
   `0.3` and `1.1` plus `2.2` replies `3.3`, as in Redis. A result that is
   NaN or infinite SHALL be refused with Redis's
   `-ERR increment would produce NaN or Infinity`.
3. The reply SHALL equal arm64 Redis's in every case and amd64 Redis's
   except where amd64's 64-bit `long double` mantissa rounds the 17th
   decimal differently from binary128; that residue SHALL be in the
   design's difference table (D1). (Redis replicates `INCRBYFLOAT` as a
   `SET` of its result because of the same platform split.)
4. `SET` SHALL accept `NX`, `XX`, `GET`, `EX`, `PX`, `EXAT`, `PXAT` and
   `KEEPTTL` in any combination Redis accepts, and refuse the combinations
   Redis refuses with Redis's syntax error. `SETNX`, `PSETEX` and `GETSET`
   SHALL be implemented as the aliases Redis defines.
5. `GETDEL`, `GETEX` (with `EX`, `PX`, `EXAT`, `PXAT`, `PERSIST`), `APPEND`
   and `SETRANGE` SHALL be implemented. `GETDEL` and `GETEX` SHALL be log
   entries (they change state), and their reply SHALL be the value as
   `apply()` saw it.
6. `TYPE`, `UNLINK` (as a synonym for `DEL`; the gateway never frees
   memory synchronously anyway), `TOUCH` (reply only; recency stays
   leader-local per redis-compatible-kv Requirement 9.3), and `OBJECT
   ENCODING` SHALL be implemented.
7. `RENAME`, `RENAMENX` and `COPY [REPLACE]` SHALL be implemented as
   multi-key commands under Requirement 6, preserving the value's type and
   deadline.
8. Every new write SHALL respect the value-size limit of
   redis-compatible-kv Requirement 6, checked against the size the value
   **would** have after the command: an `APPEND` or `SETRANGE` that would
   exceed it SHALL be refused by `apply()` with the same error, and SHALL
   change nothing.
9. A write's reply SHALL be produced by `apply()` and returned through the
   proposal's result, so that the reply describes the state the command
   actually changed, not the state the gateway read before proposing.

### Requirement 4: The expiry family

**User Story:** As an application, I want to set, change, inspect and
remove a key's time to live after it was written.

#### Acceptance Criteria

1. `EXPIRE`, `PEXPIRE`, `EXPIREAT` and `PEXPIREAT`, each with `NX`, `XX`,
   `GT` and `LT`, `PERSIST`, `PTTL`, `EXPIRETIME` and `PEXPIRETIME` SHALL
   be implemented, and `TTL` SHALL move from a diagnostic to a supported
   command.
2. A deadline at or before the command time SHALL delete the key, as in
   Redis, and the reply SHALL say the timeout was set.
3. Changing a deadline SHALL be a log entry that names the key and the new
   absolute deadline. The leader's sweep (redis-compatible-kv
   Requirement 8.4) SHALL keep its compare-the-deadline rule, so a sweep
   proposed before an `EXPIRE` or `PERSIST` cannot delete the key after it.
4. Expiry SHALL apply to every value type, and a typed value's deadline
   SHALL survive every element operation that does not delete the key, as
   in Redis.

### Requirement 5: Mutability policy

**User Story:** As an operator who hosts both an sccache prefix and
ordinary applications on one cluster, I want the immutable-value rule to
keep protecting the cache without refusing every counter.

#### Acceptance Criteria

1. The immutable-value rule (redis-compatible-kv Requirement 11.4) SHALL
   stay on by default and SHALL keep today's behaviour for `SET`, `SETEX`
   and `MSET`.
2. The ACL SHALL gain a per-user list of **mutable prefixes**. Under the
   rule, any command that would change an existing key's bytes, type,
   elements or deadline (every tier 1 and tier 3 write, `RENAME`, `COPY
   REPLACE`, the `EXPIRE` family, `GETDEL`, `GETEX`, prefix delete) SHALL
   be refused with `-ERR value conflict for an existing key` unless the key
   is inside one of the user's mutable prefixes. Creating a new key SHALL
   stay allowed.
3. With the rule turned off (`KYTHIRA_REDIS_IMMUTABLE_VALUES=off`), every
   prefix SHALL be mutable.
4. The refusal SHALL be decided in `apply()` against the stored value, not
   in the gateway, so that two racing writers cannot both pass a check
   against a stale read. The policy bit SHALL travel in the log entry.

### Requirement 6: Multi-key commands and shard locality

**User Story:** As an application, I want multi-key commands to be atomic,
fast when the keys share a shard, and refused clearly when the build
cannot make them atomic.

#### Acceptance Criteria

1. A multi-key write (`RENAME`, `RENAMENX`, `COPY`, `MSETNX`, `SMOVE`,
   `LMOVE`, `RPOPLPUSH`, `SINTERSTORE`, `SUNIONSTORE`, `SDIFFSTORE`, and
   multi-key `DEL`/`UNLINK`) whose keys route to one group SHALL be one log
   entry on that group, with no transaction.
2. A multi-key write whose keys route to more than one group SHALL run as a
   multi-Raft transaction (`.kiro/specs/multi-raft-transactions/`) on a
   build and node with transactions on, at the connection's isolation.
3. Without transactions, a cross-shard multi-key write SHALL be refused
   with `-CROSSSLOT Keys in request don't hash to the same slot`, the
   error Redis Cluster clients already handle, and SHALL change nothing.
4. A multi-key read (`MGET`, `EXISTS k1 k2 …`, `SINTER`, `SUNION`,
   `SDIFF`, `SINTERCARD`, `SMISMEMBER` across keys) SHALL read each group
   at the connection's isolation, as `MGET` does today, and SHALL NOT need
   the transaction build for `read_committed`.
5. The design SHALL say, per command, whether a split that happens between
   routing and submission can turn a single-shard command into a
   cross-shard one, and SHALL resolve it with the epoch-checked
   resubmission redis-compatible-kv Requirement 3.5 already uses.
6. `can_split_at` SHALL remain `true` for every key: a key's elements
   never span groups, because a key is the unit of routing.

### Requirement 7: SCAN and cursors (tier 2)

**User Story:** As an operator or an application, I want to list keys
without blocking the server, and to continue a listing on any gateway.

#### Acceptance Criteria

1. `SCAN cursor [MATCH pattern] [COUNT n] [TYPE type]` SHALL be
   implemented, as well as `HSCAN`, `SSCAN` (Requirement 10, 11).
2. A cursor SHALL be a decimal unsigned 64-bit integer, as clients parse
   it, and `0` SHALL start and end an iteration.
3. Iteration SHALL walk the keyspace in key order, group by group, one
   bounded page per call, resuming after the last key returned. Because
   the position is a key rather than a group, splits, merges and leader
   changes during an iteration SHALL NOT cause a key present for the whole
   iteration to be skipped or returned twice, which is stronger than
   Redis's guarantee and SHALL be documented as such.
4. A `MATCH` pattern with a literal prefix SHALL narrow the walk to the
   key range of that prefix, so `SCAN 0 MATCH user:42:*` touches only the
   groups owning `user:42:`.
5. Cursor state SHALL live in a front end with an idle expiry
   (configurable, default 10 minutes). The cursor value SHALL encode the
   issuing front end, and a cursor presented elsewhere SHALL be served by
   forwarding to its issuer. A cursor whose issuer is gone or has expired
   it SHALL answer `-ERR invalid cursor`, and the documentation SHALL tell
   clients to restart the iteration.
6. `SCAN` SHALL be authorized per key: keys outside the user's prefixes
   SHALL be filtered out on the data node, never returned and never
   counted, and a `MATCH` outside every prefix SHALL return nothing rather
   than `-NOPERM`, so the reply leaks nothing.
7. `KEYS pattern` SHALL be refused unless the user has the admin role, and
   SHALL refuse with an error, not a truncated reply, past a configurable
   key limit (default 10 000).
8. `RANDOMKEY` SHALL be implemented with a uniform choice over the
   groups weighted by their approximate key counts.

### Requirement 8: Admin tools (tier 2)

**User Story:** As an operator, I want to delete by prefix, flush a
database and see what is using space, without writing scripts against
`SCAN`.

#### Acceptance Criteria

1. `KYTHIRA.DELPREFIX prefix` SHALL delete every key starting with
   `prefix` by proposing, to each group whose range meets the prefix's
   range, one range-delete entry bounded to that intersection. The reply
   SHALL be the count of keys deleted.
2. Prefix delete SHALL be atomic per group and not across groups, and
   SHALL say so: a key written to the prefix's range after the entry for
   its group applied survives. Each range-delete SHALL be bounded per
   entry (a configurable key count), and a larger range SHALL take several
   entries proposed in order.
3. `FLUSHDB` and `FLUSHALL` (`ASYNC`/`SYNC` accepted, both asynchronous
   in effect) SHALL be range deletes over the whole keyspace, SHALL need
   the admin role, and SHALL be refused unless enabled by
   `KYTHIRA_REDIS_ALLOW_FLUSH=on`, because a typed accident on a shared
   cache is a cluster-wide outage.
4. `KYTHIRA.USAGE [prefix] [DEPTH d] [DELIM c]` SHALL report key count and
   approximate bytes per prefix bucket (the key cut at the `d`-th `c`,
   default depth 1 and delimiter `:`), computed by each group's replica
   over its range without a log entry, and merged by the front end.
5. `MEMORY USAGE key`, `DBSIZE` (exact, summed across groups),
   `OBJECT ENCODING`, and the `keyspace` section of `INFO` SHALL be
   implemented.
6. Every admin command SHALL be audited (redis-compatible-kv
   Requirement 11.8) with the prefix or range it touched and the count.

### Requirement 9: Typed values (tier 3)

**User Story:** As an application, I want hashes, sets and lists stored as
the data types they are, with Redis's type errors.

#### Acceptance Criteria

1. A stored value SHALL carry a type: `string`, `hash`, `set` or `list`.
   A command for one type on a key holding another SHALL answer
   `-WRONGTYPE Operation against a key holding the wrong kind of value`
   and change nothing.
2. A collection emptied by a command SHALL delete its key, as in Redis.
3. Iteration order SHALL be deterministic on every replica: hash fields
   and set members in byte order, lists in list order. Redis does not
   promise an order for `HGETALL` or `SMEMBERS`, so byte order SHALL be
   documented as Kythira's order, not as a difference.
4. Each collection SHALL be bounded by a configurable maximum total size
   (default 64 MiB) and maximum element count (default 4 Mi), refused in
   `apply()` with a dedicated error and no change, because a key cannot be
   split across groups and its whole value is in every snapshot.
5. Random selection (`SPOP`, `SRANDMEMBER`, `HRANDFIELD`) SHALL never run
   in `apply()`: a read picks on the serving node, and `SPOP` is proposed
   by the leader as an explicit remove of the members it picked, which
   `apply()` removes only if still present (the sweep pattern).
6. `approximate_size_bytes()` and `approximate_key_count()` SHALL stay
   incremental with typed values.

### Requirement 10: Hashes

#### Acceptance Criteria

1. `HSET`, `HSETNX`, `HGET`, `HMGET`, `HMSET`, `HDEL`, `HEXISTS`, `HLEN`,
   `HSTRLEN`, `HKEYS`, `HVALS`, `HGETALL`, `HINCRBY`, `HINCRBYFLOAT`
   (Requirement 3.2's binary128 arithmetic), `HRANDFIELD` and `HSCAN` SHALL be
   implemented.
2. A hash read SHALL use the same read path and consistency modes as `GET`
   (redis-compatible-kv Requirement 7): a shared handle under the node
   lock, the bytes encoded after it is released. `HGETALL` on a large hash
   SHALL NOT copy the hash under the lock.

### Requirement 11: Sets

#### Acceptance Criteria

1. `SADD`, `SREM`, `SISMEMBER`, `SMISMEMBER`, `SMEMBERS`, `SCARD`, `SPOP`,
   `SRANDMEMBER`, `SMOVE`, `SINTER`, `SUNION`, `SDIFF`, `SINTERCARD`,
   `SINTERSTORE`, `SUNIONSTORE`, `SDIFFSTORE` and `SSCAN` SHALL be
   implemented, the multi-key ones under Requirement 6.

### Requirement 12: Lists, without blocking

#### Acceptance Criteria

1. `LPUSH`, `RPUSH`, `LPUSHX`, `RPUSHX`, `LPOP` and `RPOP` (with `count`),
   `LLEN`, `LINDEX`, `LRANGE`, `LSET`, `LINSERT`, `LREM`, `LTRIM`, `LPOS`,
   `LMOVE`, `RPOPLPUSH` and `LMPOP` (non-blocking) SHALL be implemented.
2. Pushing or popping at either end SHALL cost O(1) in `apply()` and
   index operations SHALL be bounded by the list's chunking (design), not
   by copying the list.
3. The blocking forms (`BLPOP`, `BRPOP`, `BLMOVE`, `BRPOPLPUSH`, `BLMPOP`)
   SHALL answer `-ERR unknown command` until phase 2 (Requirement 27).

### Requirement 13: Typed values on every store and transaction build

**User Story:** As an operator, I want the new commands on the storage I
already run, or a clear refusal where they cannot work.

#### Acceptance Criteria

1. `KYTHIRA_CACHE_PERSISTENCE=memory` SHALL hold typed values in memory.
2. `engine` (RocksDB) SHALL store a collection as one row per element
   under a composite key that sorts after the key's header row, so that
   an element write does not rewrite the collection and a range of
   elements is a range read.
3. `file` (the disk-backed build cache) SHALL stay string-only: every tier
   3 command and every tier 1 command that is not a plain string write
   SHALL answer `-ERR this command needs KYTHIRA_CACHE_PERSISTENCE=memory
   or engine`, and its formats SHALL NOT change.
4. Under `CONFIG_REDIS_GATEWAY_TRANSACTIONS`, typed commands SHALL be
   allowed inside `MULTI`/`EXEC` and as cross-shard multi-key commands. A
   prepare SHALL evaluate the command against the locked current value and
   hold the resulting value as the intent, so that the reply is known at
   prepare and the commit installs exactly what was evaluated.
5. Under `CONFIG_REDIS_GATEWAY_SNAPSHOT_ISOLATION`, a collection SHALL be
   versioned with structural sharing (design: chunked copy-on-write), so
   that one element write does not copy the whole collection into a new
   version, and garbage collection at the safe point SHALL free unshared
   chunks.
6. `WATCH` SHALL work on typed keys: any change to a key's type, elements
   or deadline counts as a change.

### Requirement 14: Log and snapshot formats, and the rolling upgrade

**User Story:** As an operator, I want to upgrade a running cluster to the
new commands one node at a time, without an older replica failing to
apply an entry it cannot read.

#### Acceptance Criteria

1. The new commands SHALL use a new log-entry format version (`0x03`),
   with one general record (`exec`) carrying a stable command id, the
   command time, the policy bits and a length-prefixed argument list, so
   that adding a command does not add a record layout. Versions `0x01`
   and `0x02` SHALL decode unchanged.
2. The in-memory, engine and multi-version snapshot formats SHALL gain a
   format marker, and a node SHALL read every older snapshot format.
3. A group SHALL write the new log and snapshot formats only after a
   **format gate** entry has applied on it. The gate SHALL be proposed by
   an admin command (`KYTHIRA.FORMAT UPGRADE`) only after every replica of
   every group, and every gateway and front end, has reported the new
   format level; before the gate, new commands SHALL answer `-ERR this
   cluster has not enabled typed values yet (KYTHIRA.FORMAT)`.
4. A binary that meets a gate or a record above its format level SHALL
   stop with a message naming the needed level, rather than skipping the
   entry.
5. The gate SHALL be one-way. The documentation SHALL say that a
   downgrade after the gate needs a restore from a pre-gate snapshot.
6. The golden-bytes test (`services/redis/tests/redis_golden_bytes_test.cpp`)
   SHALL gain fixtures for every new record and snapshot format, and SHALL
   keep the old ones.

### Requirement 15: ACL categories and key permissions

**User Story:** As an operator, I want to grant applications the new
commands by category, and read-only access to some prefixes and
read-write to others, before the ACL becomes replicated in phase 2.

#### Acceptance Criteria

1. The ACL file SHALL accept, besides today's roles, Redis's command
   categories (`+@string`, `+@hash`, `+@set`, `+@list`, `+@keyspace`,
   `+@read`, `+@write`, `+@admin`, `+@dangerous`, …) and single commands
   (`+incr`, `-flushdb`), with Redis's rule that later rules win.
2. It SHALL accept per-prefix read and write scopes (`%R~prefix`,
   `%W~prefix`, `~prefix`) and the mutable-prefix list of Requirement 5.
3. Today's lines SHALL parse to the same permissions as today, and today's
   roles SHALL be documented as category sets.
4. A rolling upgrade SHALL be safe: the documentation SHALL say which new
   syntax an older gateway misreads and how to stage it, as the existing
   `auth=` note does.

### Requirement 16: Layers and roles

**User Story:** As an operator, I want to choose which layers each Redis
process runs, so that I can scale connections, command planning and data
on their own, while a cluster that never sets anything keeps running as
it does today.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_REDIS_ROLES`, a
   comma-separated non-empty subset of `gateway`, `front_end`, `data`;
   default all three. With the default, configuration, data directory,
   ports, wire formats and behaviour SHALL be exactly today's.
2. A node without `data` SHALL NOT be a Raft member of any Redis group,
   SHALL NOT need `KYTHIRA_PEERS` to include itself and SHALL NOT open a
   Raft log or a store.
3. A role set that cannot serve SHALL stop the node at start with a
   message naming what is missing (for example `gateway` alone with no
   front-end endpoints and no membership group).
4. Roles SHALL be per module: in `kythira_node`, `KYTHIRA_REDIS_ROLES`
   affects only the Redis module (service-colocation Requirement 2).
5. The handlers SHALL reach the data layer only through an interface with
   a local implementation (today's in-process path) and a remote one (the
   data-layer API), chosen per call (kinesis-independent-layers
   Requirement 3), so a co-located node in a mixed cluster needs no mode.
6. Every phase 1 and phase 2 feature SHALL work in an all-co-located
   cluster; no feature SHALL require a split.
7. `INFO server` and the metrics SHALL report the role set.

### Requirement 17: Gateway layer

#### Acceptance Criteria

1. A gateway SHALL terminate RESP2/RESP3, TLS and mTLS, run `AUTH`/`HELLO`
   (passwords and IAM tokens), enforce every connection and request limit
   of redis-compatible-kv Requirements 2 and 14, and hold per-connection
   state (protocol, identity, `MULTI` queue, isolation, `WATCH` token,
   and in phase 2 subscriptions and `ASKING`/`READONLY`).
2. A gateway without `front_end` SHALL send each command, or a whole
   `MULTI` batch at `EXEC`, to a front end as an authenticated call, and
   SHALL pin each client connection to one front end, re-pinning to
   another on failure. A command the old front end may have executed SHALL
   answer a retryable error naming the ambiguity, never be replayed.
3. A front end SHALL accept an authenticated call only from a peer whose
   layer identity carries `gateway`.
4. A gateway SHALL support drain: stop accepting, finish in-flight commands
   up to a bound, then close connections, so it can be removed without
   failing commands that were not in flight.

### Requirement 18: Front end and the data-layer API

#### Acceptance Criteria

1. A front end SHALL authorize every command (ACL categories, key scopes,
   mutability) and plan it: single group, fan-out read, or transaction.
   It SHALL hold the transaction coordinator and the `SCAN` cursors.
2. Every data node SHALL offer, on an internal listener, a data-layer API:
   propose a command to a group, run a transaction participant message,
   read a key (or a key's elements) at a consistency mode, read a range
   page (for `SCAN`, usage and prefix delete), and answer `route(key)` and
   `routes(range)` with group epochs.
3. A data node that is not the group's leader SHALL refuse a proposal with
   the leader hint and SHALL NOT forward it again, so a call crosses at
   most one data node, as the forward link's one-hop rule does today
   (redis-compatible-kv Requirement 13.3).
4. A front end without `data` SHALL use the route cache of
   kinesis-independent-layers Requirement 6, finding data nodes from
   `KYTHIRA_REDIS_DATA_NODES` (names resolved at run time with
   `net_resolve`, never static IPs) or the layer membership group.
5. The data-layer API SHALL be carried as internal RESP commands over the
   existing forward link's framing and pool, so the co-located forward
   path and the layered path share one transport. Today's `KYTHIRA.TXN`
   and forwarded commands between co-located nodes SHALL keep working, so
   a co-located cluster's rolling upgrade has no flag day.
6. An answer SHALL be the same whichever layout serves it, byte for byte at
   the RESP wire, except timing. The differential suite SHALL run in both
   layouts.

### Requirement 19: Cross-layer authentication

#### Acceptance Criteria

1. Calls between nodes of different role sets SHALL use mutual TLS with
   layer identities (kinesis-independent-layers Requirement 7) naming the
   cluster, node id and roles, e.g.
   `kythira://redis/<cluster>/<node id>?roles=gateway,front_end`.
2. Each internal endpoint SHALL check the caller's roles: authenticated
   calls need `gateway`; the data-layer API needs `front_end` or `data`;
   transaction participant messages need `front_end` or `data`.
3. The internal user and secret of today's forward link
   (`KYTHIRA_REDIS_INTERNAL_USER`) SHALL stay valid between co-located
   nodes, and SHALL NOT be accepted for a call from a node that is not
   co-located.
4. A node SHALL refuse to start in a non-co-located role set without layer
   TLS unless `KYTHIRA_NODE_INSECURE_PLAINTEXT=1` is set.
5. Certificates SHALL rotate without restart.

### Requirement 20: Layer membership and scaling

#### Acceptance Criteria

1. The gateway and front-end layers MAY run the layer membership group of
   kinesis-independent-layers Requirement 10 (fixed small voter set, every
   other stateless node a non-voting member), holding members, roles,
   addresses, drain state and settings versions.
2. Without the group, membership SHALL come from configuration
   (`KYTHIRA_REDIS_FRONT_ENDS`, `KYTHIRA_REDIS_DATA_NODES`) or DNS peer
   discovery.
3. The group's leader MAY run the elastic capacity loop with a policy
   whose signals are connections, commands per second, pub/sub fan-out
   (phase 2) and CPU, provisioning through the configured
   `quorum_manager`, and SHALL drain a node before decommissioning it.

### Requirement 21: Splitting and merging layers on a running cluster

**User Story:** As an operator, I want to split a co-located cluster into
separate layers, and merge it back, while it serves traffic.

#### Acceptance Criteria

1. Every step of a split or merge SHALL leave a valid mixed deployment, so
   that a migration can stop, pause or reverse at any step.
2. Adding or removing `gateway` or `front_end` on a node SHALL need only a
   drain and a restart with the new role set.
3. Removing `data` from a node SHALL first move every replica it holds to
   other data nodes with the placement operators (add learner, catch up,
   promote, transfer leadership, remove). A node SHALL refuse to start
   without `data` while it still holds replicas unless told to discard
   them, and `KYTHIRA.EVACUATE` (admin, internal) SHALL perform the moves.
4. Adding `data` SHALL add the node as a learner of the groups the
   placement driver assigns it and promote it once caught up.
5. During a migration, no acknowledged write SHALL be lost or applied
   twice, transactions SHALL keep their guarantees, `SCAN` iterations in
   progress SHALL complete or answer `-ERR invalid cursor` (never skip or
   repeat a key), and clients MAY see retryable errors.
6. A runbook SHALL describe each direction step by step, the checks
   between steps and how to reverse each one.

### Requirement 22: Observability

#### Acceptance Criteria

1. Metrics SHALL be emitted per command name for every new command, plus:
   `WRONGTYPE` replies, mutability refusals, collection-limit refusals,
   cross-shard commands by outcome, `CROSSSLOT` refusals, cursors open and
   expired, prefix-delete keys, format level per group, applied command
   time lag per leader, and per-layer call counts and latency.
2. `INFO` SHALL gain `keyspace`, `commandstats` and `errorstats` sections
   in Redis's format.
3. `SLOWLOG` (`GET`, `LEN`, `RESET`) SHALL record commands slower than a
   threshold on the front end, with arguments redacted per
   redis-compatible-kv Requirement 10.7 and values never shown.

### Requirement 23: Phase 1 testing

#### Acceptance Criteria

1. Unit tests SHALL cover each new log record, each command's `apply()`
   (including `WRONGTYPE`, limits, the command-time rule and its monotonic
   floor), `split → absorb` round trips with typed values and the
   snapshot round trip in every store.
2. A **differential suite** SHALL run one generated command stream (seeded,
   recorded) against the reference servers in containers and against a
   Kythira cluster, comparing every reply in RESP2 and RESP3, with the
   difference table as the only allowed exceptions. It SHALL run in CI on
   Docker and rootless Podman.
3. Client library suites SHALL run the parts of redis-py's, go-redis's and
   ioredis's own test suites that cover the implemented commands, against
   a containerized cluster.
4. A linearizability check (the existing history checker used by the
   engine-chaos scenario) SHALL cover `INCR`, `SET NX`, `GETDEL`, `LPUSH` /
   `RPOP` and hash fields under leader kills and partitions.
5. A rolling-upgrade scenario SHALL run a mixed old/new cluster, show new
   commands refused before the gate and accepted after it, and show an old
   binary refusing to start after the gate with the documented message.
6. Every container scenario SHALL follow the container-runtime rules of
   `CLAUDE.md`: service names, no static IPs, `container_runtime()` and
   `compose_prefix()`, no privileged or host-network features.

### Requirement 24: Layer migration tests

**User Story:** As Clark, I want every migration path tested, both ways.

#### Acceptance Criteria

1. There SHALL be one in-process test per path, each run in **both
   directions**, under a mixed workload (counters, `SET NX` locks, hashes,
   lists, cross-shard `MSET` and `RENAME` transactions, a long `SCAN`):
   - split the gateway layer off co-located nodes, and merge it back;
   - split the front-end layer, and merge it back;
   - split the data layer (evacuate replicas off nodes that keep
     gateway/front end), and merge it back (add `data`, promote);
   - gateway and front end merged on one set of nodes, data on another,
     and back;
   - the whole path from co-located to fully three-way and back, with a
     stop and a reversal midway.
2. Each SHALL check: no acknowledged write lost or applied twice, counter
   totals exact, transactions atomic at their isolation, every `SCAN`
   complete without duplicates or an `invalid cursor` answer, and every
   key's type and deadline intact.
3. A docker-chaos scenario SHALL run the full path both ways while killing
   one node of each layer, on Docker and rootless Podman.
4. A measurement SHALL compare co-located latency and throughput before and
   after the layer work, and co-located SHALL NOT regress by more than
   measurement noise.

### Requirement 25: Interoperability with AWS ElastiCache and MemoryDB

**User Story:** As Clark, I want evidence that applications written for
AWS's managed Redis work against Kythira, without paying for AWS on every
CI run.

#### Acceptance Criteria

1. CI (no spend) SHALL replay **recorded** ElastiCache (Valkey and Redis
   OSS engines) and MemoryDB transcripts of the differential command
   stream against Kythira, comparing replies with the difference table as
   the only exceptions. The recordings SHALL be checked in, with the
   engine, version and date that produced them.
2. A real-cloud bundle SHALL be **dispatch-only**, behind a repository
   variable, and SHALL need Clark's go in his own words each run. It SHALL:
   create the smallest ElastiCache serverless cache and MemoryDB cluster
   (with an in-VPC runner, since both are VPC-only), re-record the
   transcripts, run the client library suites against AWS and Kythira
   and compare, authenticate a client with ElastiCache's IAM auth token
   generator against both (Kythira's `auth=iam` users), report its cost
   and delete everything it made, including on failure.
3. The ACL categories of Requirement 15 SHALL be checked against
   ElastiCache's user access strings (`on ~app:* +@string -@dangerous`),
   and an access string valid on ElastiCache SHALL parse to the same
   permissions.

### Phase 2 — finishing tier 3, then tiers 4 to 6

### Requirement 26: Phase 2 rules

#### Acceptance Criteria

1. Each phase 2 feature SHALL be behind its own Kconfig symbol, default
   off until its acceptance task is merged, and SHALL change nothing when
   off.
2. Each SHALL say which layer runs each part, SHALL work co-located, and
   SHALL add its paths to the migration tests of Requirement 24.
3. Each SHALL extend the differential suite and the AWS interop task.
4. Each new log record or snapshot field SHALL go behind a new format gate
   level (Requirement 14).

### Requirement 27: Blocking list commands (finishing tier 3)

#### Acceptance Criteria

1. `BLPOP`, `BRPOP`, `BLMOVE`, `BRPOPLPUSH` and `BLMPOP` SHALL be
   implemented with Redis's timeouts, including `0` (forever).
2. The gateway SHALL park the client, the front end SHALL register a
   **key watch** with each key's group leader (soft state with a lease),
   and the leader SHALL notify on any push to a watched key; the front end
   then proposes the pop. A pop that loses a race SHALL re-park, never
   return an empty reply before the timeout.
3. Clients blocked on one key SHALL be served in arrival order per front
   end, and the design SHALL state the cross-front-end fairness (none
   guaranteed) as a difference.
4. A leader change, front-end loss or watch lease expiry SHALL re-register
   the watch; it SHALL never lose a push (the pop rereads the list).
5. A blocking command inside `MULTI` SHALL behave as Redis: non-blocking.

### Requirement 28: Scripts (tier 4)

**User Story:** As an application, I want `EVAL` for atomic
read-modify-write logic, fast on one shard and correct across shards.

#### Acceptance Criteria

1. `EVAL`, `EVALSHA`, `EVAL_RO`, `EVALSHA_RO`, `SCRIPT LOAD`, `SCRIPT
   EXISTS`, `SCRIPT FLUSH` and `SCRIPT KILL` (for scripts on the front end
   only) SHALL be implemented with Lua 5.1 semantics and Redis's bundled
   libraries (`cjson`, `cmsgpack`, `bit`, `struct`) and `redis.call`,
   `redis.pcall`, `redis.error_reply`, `redis.status_reply`,
   `redis.sha1hex`, `redis.log`, `redis.setresp`.
2. A script SHALL declare its keys in `KEYS`. A `redis.call` on a key not
   in `KEYS` SHALL fail the script with Redis Cluster's error, in every
   mode. This SHALL be documented as stricter than standalone Redis.
3. **Single-shard scripts**: when every declared key routes to one group,
   the script SHALL run inside `apply()` on every replica (verbatim
   replication), and SHALL therefore be deterministic (Requirement 30).
   The log entry SHALL carry the script body, not only its SHA, so a
   replica never depends on a script cache to apply it.
4. **Cross-shard scripts**: when declared keys route to more than one
   group, the front end SHALL run the script **once**, reading declared
   keys through a multi-Raft transaction's prepare (keys locked) and
   buffering writes, then commit the writes in that transaction. Such a
   script need not be deterministic (it runs once), and SHALL need the
   transaction build; without it, it SHALL answer `-CROSSSLOT`.
5. A cross-shard script that conflicts with another writer SHALL be retried
   from the start up to `KYTHIRA_REDIS_TXN_MAX_RETRIES`, and SHALL answer
   the transaction-aborted error after that; a script whose writes were
   visible to the client before the abort is impossible by construction,
   because replies are only sent after commit.
6. The script cache for `EVALSHA` SHALL be per front end (as Redis's is per
   node) and `-NOSCRIPT` SHALL be answered on a miss; clients already
   retry with `EVAL`.
7. `_RO` variants and scripts with the `no-writes` flag SHALL be readable
   from replicas at the connection's consistency mode, without a log
   entry.

### Requirement 29: Functions (tier 4)

#### Acceptance Criteria

1. `FUNCTION LOAD [REPLACE]`, `FUNCTION DELETE`, `FUNCTION LIST`,
   `FUNCTION FLUSH`, `FUNCTION DUMP`, `FUNCTION RESTORE`, `FUNCTION STATS`,
   `FCALL` and `FCALL_RO` SHALL be implemented.
2. Libraries SHALL be stored in the catalog group and cached by every
   front end and data node with the catalog's version; a `FUNCTION LOAD`
   SHALL be visible to every node before it replies.
3. `FCALL` SHALL follow Requirement 28's single-shard and cross-shard
   split, with the library body and version carried in a single-shard log
   entry.
4. Function flags (`no-writes`, `allow-oom`, `allow-stale`,
   `no-cluster`) SHALL be honoured where they apply, and `allow-cross-slot-keys`
   SHALL select the cross-shard path rather than being refused.

### Requirement 30: Script determinism and sandbox

#### Acceptance Criteria

1. The Lua interpreter SHALL be Lua 5.1.5 built as a vcpkg overlay port
   (MIT licence, recorded in the overlay), with number-to-string
   conversion replaced by a shortest-round-trip formatter so amd64 and
   arm64 replicas print numbers identically.
2. In `apply()`, scripts SHALL NOT reach any clock, random source, file,
   socket or environment. `redis.call('TIME')`, `RANDOMKEY`, `SRANDMEMBER`,
   `SPOP`, `HRANDFIELD` and `math.random` SHALL be refused or (for
   `math.random`) seeded from the entry's index and term, so every replica
   gets the same sequence.
3. A script in `apply()` SHALL be bounded by a **deterministic** budget —
   a Lua instruction count and an allocation cap — never by wall time, so
   every replica stops it at the same instruction. Over budget, the entry
   SHALL apply as an error with no writes (writes are buffered until the
   script ends).
4. Globals SHALL be locked as in Redis (no global writes), and the sandbox
   SHALL remove `loadstring`, `dofile`, `io`, `os` (except `os.clock` on the
   front end only) and `debug`.
5. Front-end scripts SHALL have a wall-time limit and `SCRIPT KILL`, as
   Redis does.

### Requirement 31: Pub/sub (tier 5)

**User Story:** As an application, I want pub/sub for cache invalidation
and chat-style fan-out, without paying for Raft on every message.

#### Acceptance Criteria

1. `SUBSCRIBE`, `UNSUBSCRIBE`, `PSUBSCRIBE`, `PUNSUBSCRIBE`, `PUBLISH`,
   `PUBSUB CHANNELS|NUMSUB|NUMPAT|SHARDCHANNELS|SHARDNUMSUB`, `SSUBSCRIBE`,
   `SUNSUBSCRIBE` and `SPUBLISH` SHALL be implemented, in RESP2
   subscriber mode and RESP3 push messages.
2. Messages SHALL NOT go through Raft. Delivery SHALL be at most once, as
   in Redis.
3. Subscriptions SHALL live on the gateway holding the connection.
   `PUBLISH` SHALL be fanned out to every gateway that has a matching
   subscription, using a subscription-interest table spread through the
   layer membership group (or, without it, broadcast to every known
   gateway), and the reply SHALL count local receivers as Redis Cluster's
   does.
4. `SPUBLISH` SHALL route by channel name to the data node leading the
   channel's group, which fans out to gateways registered for that
   channel, so sharded channels scale with the data layer.
5. The ACL SHALL gate channels (`&pattern`, `allchannels`) and the
   `@pubsub` category, and a subscriber whose permission is revoked SHALL
   be disconnected, as in Redis 7.
6. Slow subscribers SHALL be bounded by the existing output buffer limit
   and disconnected past it.

### Requirement 32: Keyspace notifications (tier 5)

#### Acceptance Criteria

1. `CONFIG SET notify-keyspace-events` (and its config-file setting) SHALL
   enable Redis's `__keyspace@<db>__:` and `__keyevent@<db>__:` events
   with Redis's flag letters, stored in the catalog group so every node
   agrees.
2. Events SHALL be emitted by the **leader** replica as it applies each
   entry (followers never emit), including expired (`x`) events from the
   sweep and evicted (`e`) events, and published as sharded messages by
   key, so the subscriber's gateway receives them without a broadcast.
3. Delivery SHALL be at most once. A leader change can drop events emitted
   between the old leader's last send and the new leader's first, and the
   documentation SHALL say so (Redis loses events on failover too).
4. Notifications SHALL cost nothing when disabled: no per-apply work beyond
   one flag check.

### Requirement 33: Replicated ACL (tier 6)

#### Acceptance Criteria

1. `ACL SETUSER`, `DELUSER`, `GETUSER`, `LIST`, `USERS`, `WHOAMI`, `CAT`,
   `GENPASS`, `LOG`, `DRYRUN`, `SAVE` and `LOAD` SHALL be implemented over
   users stored in the catalog group, and every gateway and front end
   SHALL apply a change before `ACL SETUSER` replies.
2. Secrets SHALL keep redis-compatible-kv Requirement 10.5's storage:
   `>password` SHALL be hashed with PBKDF2 on the front end before it is
   proposed, so a plaintext secret never enters the log. Redis's
   `#<sha256>` form SHALL be refused unless
   `KYTHIRA_REDIS_ACL_ALLOW_SHA256=on`, because a bare digest is weaker
   than the stored format.
3. The ACL file SHALL become a bootstrap import: on first start of a
   cluster with an empty catalog it SHALL be loaded; afterwards
   `ACL LOAD` imports it explicitly and a changed file alone SHALL change
   nothing, with a log line saying so.
4. `auth=iam`, `cert=`, mutable prefixes and categories SHALL all be
   expressible through `ACL SETUSER` (Kythira-specific rules prefixed so
   Redis's parser would reject them rather than misread them).
5. `ACL LOG` SHALL be fed by the audit stream, bounded per front end.
6. Moving from a file-based ACL to the replicated one, and back (export to
   a file, switch the node setting) SHALL each be tested.

### Requirement 34: Redis Cluster protocol as a compatibility mode (tier 6)

**User Story:** As an application configured for cluster mode (an
ElastiCache cluster-mode endpoint, Lettuce or redis-py cluster clients),
I want Kythira to answer the Cluster protocol, so that my client connects
at all, and so that it can send each command straight to a gateway near
the owning group.

**What this is not.** Kythira does not need the Cluster protocol to scale:
it already shards by key range and any gateway answers any key behind one
endpoint (redis-compatible-kv Requirement 13). The protocol is a
**compatibility mode** for clients that will not connect without
`CLUSTER SLOTS` and `MOVED`, with optional client-side routing that skips
the forwarding hop. It does not move data between Kythira and real Redis;
that is the job of the separate migration tooling spec,
`.kiro/specs/redis-migration-tooling/`.

#### Acceptance Criteria

1. A **slot keyspace** SHALL route a key by `CRC16(hashtag(key)) mod 16384`
   followed by the key, so a contiguous slot range is a contiguous routing
   range and `{tag}` keys share a group. It SHALL be a second multi-Raft
   key space of the Redis module, not a change to the existing one.
2. In the slot keyspace, group splits SHALL happen only at slot
   boundaries, so each slot belongs to exactly one group.
3. `CLUSTER SLOTS`, `CLUSTER SHARDS`, `CLUSTER NODES`, `CLUSTER MYID`,
   `CLUSTER INFO`, `CLUSTER KEYSLOT`, `CLUSTER COUNTKEYSINSLOT`,
   `CLUSTER GETKEYSINSLOT`, `READONLY`, `READWRITE` and `ASKING` SHALL be
   implemented. Each slot range's primary endpoint SHALL be a gateway
   co-located with (or, when split, nearest to) the group's leader, and
   its replicas gateways near the followers.
4. A gateway SHALL still answer any key (redis-compatible-kv
   Requirement 13); it SHALL answer `-MOVED` only when configured to
   (`KYTHIRA_REDIS_CLUSTER_REDIRECTS=on`), and `-ASK` during a slot range's
   move between groups, so clients converge on the right gateway.
5. `-CROSSSLOT` SHALL apply to multi-key commands across slots unless the
   transaction build is on and `KYTHIRA_REDIS_CLUSTER_CROSS_SLOT=allow`.
6. Existing data SHALL move between the ordered keyspace and the slot
   keyspace with an online copy (`KYTHIRA.KEYSPACE MIGRATE`): dual reads,
   batched copy in transactions, a cut-over recorded in the catalog group,
   and a reverse migration by the same tool. Both directions SHALL be
   tested under a workload.
7. ElastiCache cluster-mode clients (redis-py `RedisCluster`, go-redis
   `ClusterClient`, Lettuce cluster) SHALL pass their cluster test subsets.

### Requirement 35: Phase 2 layers and migration tests

#### Acceptance Criteria

1. The design SHALL place each phase 2 part: subscriptions and push
   delivery on gateways; key watches, cross-shard scripts, cursor state
   and cluster topology answers on front ends; single-shard scripts,
   notification emission, sharded publish fan-out and the catalog group on
   data nodes.
2. The migration tests of Requirement 24 SHALL gain, in both directions:
   splitting gateways with live subscribers (subscribers reconnect and
   resubscribe; a resubscribed client receives messages published after
   it resubscribed), splitting front ends with blocked `BLPOP` clients and
   running cross-shard scripts, splitting data nodes during single-shard
   scripts and notification streams, and moving the catalog group's
   replicas.
3. The keyspace migration (34.6) and the ACL migration (33.6) SHALL each run
   in both directions on a co-located and a split cluster.

### Requirement 36: Phase 2 interoperability

#### Acceptance Criteria

1. The recorded ElastiCache/MemoryDB transcripts SHALL be extended with
   scripts, functions, pub/sub, keyspace notifications, ACL commands and
   cluster-mode topology, and replayed in CI.
2. The real-cloud bundle (25.2) SHALL add a cluster-mode-enabled ElastiCache
   cache and a MemoryDB cluster with ACL users, and SHALL run the
   cluster-mode client suites, the same Lua and function libraries, and
   pub/sub fan-out against AWS and Kythira, compared.

### Requirement 37: Build options and documentation

#### Acceptance Criteria

1. Phase 1 SHALL be behind `CONFIG_REDIS_GATEWAY_DATA_TYPES` (default `y`
   once the phase 1 acceptance task merges) and the layer roles behind no
   option (default all roles is today's behaviour). Phase 2 options:
   `CONFIG_REDIS_GATEWAY_BLOCKING`, `CONFIG_REDIS_GATEWAY_SCRIPTING`,
   `CONFIG_REDIS_GATEWAY_PUBSUB`, `CONFIG_REDIS_GATEWAY_REPLICATED_ACL`,
   `CONFIG_REDIS_GATEWAY_CLUSTER`.
2. The only new third-party dependency SHALL be Lua 5.1.5 (phase 2,
   scripting only). Everything else uses what the tree already links.
3. `configs/ci_no_redis_defconfig` and the module boundary check SHALL keep
   passing, and the module-off build SHALL be unchanged.
4. `doc/redis-gateway.md` SHALL gain the command tables, the difference
   table, the layer guide (roles, which layer holds which secret, sizing),
   the split/merge runbook, the format-gate procedure and, in phase 2, the
   scripting, pub/sub, ACL and cluster chapters.

### Phase 3 — the rest of Redis

Clark asked on 2026-11-17 for a third phase that "captures the rest of
Redis behaviour". Phase 3 covers every command group of Redis OSS 7.4 and
Valkey 8 that phases 1 and 2 leave out, plus the data types Redis 8
made built-in. Where Redis behaviour cannot hold on a replicated,
deterministic, sharded store, or conflicts with a decision of the earlier
specs (RDB/AOF, Redis's eviction), this phase specifies the **closest
compatible behaviour** and lists the deviation in the design's difference
table (D12 onwards). Requirement 26's rules (Kconfig symbol per feature,
layer placement, migration tests, differential and AWS interop
extension, format gate) apply to every phase 3 requirement.

| Tier | What |
|---|---|
| 7 | Sorted sets and geo |
| 8 | Streams and consumer groups |
| 9 | Bitmaps, bitfields, HyperLogLog, `LCS`, hash field expiry, `SORT` |
| 10 | Server and keyspace surface: multiple databases, `DUMP`/`RESTORE`/`MIGRATE`/`MOVE`/`SWAPDB`, `OBJECT`, `CONFIG`, `CLIENT` (with tracking), `MONITOR`, `WAIT`, `LATENCY`, `MEMORY`, `DEBUG` subset, `SHUTDOWN`/`FAILOVER` |
| 11 | Memory policies and persistence compatibility: `maxmemory` policies, `SAVE`/`BGSAVE`/`LASTSAVE`/`BGREWRITEAOF` (RDB files and `REPLICAOF`/`PSYNC` are in the migration tooling spec) |
| 12 | Redis 8 built-in types: JSON, probabilistic (Bloom, Cuckoo, Count-Min, Top-K, t-digest), vector sets, time series; the query engine scoped into its own spec |

### Requirement 38: Sorted sets (tier 7)

#### Acceptance Criteria

1. A `zset` value type SHALL be added, ordered by (score, member) with an
   index by member, chunked like Requirement 9's collections.
2. Every sorted-set command of Redis 7.4 SHALL be implemented: `ZADD`
   (`NX|XX`, `GT|LT`, `CH`, `INCR`), `ZINCRBY`, `ZREM`, `ZCARD`, `ZCOUNT`,
   `ZLEXCOUNT`, `ZSCORE`, `ZMSCORE`, `ZRANK`/`ZREVRANK` (`WITHSCORE`),
   `ZRANGE` (`BYSCORE|BYLEX`, `REV`, `LIMIT`, `WITHSCORES`), the legacy
   `ZRANGEBYSCORE`/`ZREVRANGEBYSCORE`/`ZRANGEBYLEX`/`ZREVRANGEBYLEX`/
   `ZREVRANGE`, `ZRANGESTORE`, `ZREMRANGEBYRANK|SCORE|LEX`, `ZPOPMIN`,
   `ZPOPMAX`, `ZMPOP`, `ZRANDMEMBER`, `ZSCAN`, `ZINTER`, `ZUNION`,
   `ZDIFF`, their `STORE` forms and `ZINTERCARD`, and the blocking
   `BZPOPMIN`, `BZPOPMAX`, `BZMPOP` on phase 2's key watches.
3. Scores SHALL be binary64 with Redis's `inf`/`-inf` handling and `NaN`
   refusal, and SHALL be printed with the shortest round-trip form Redis
   7.2+ uses for doubles, so replies match without a deviation.
4. `ZINCRBY` and `ZADD INCR` SHALL compute in binary64 in `apply()`
   (deterministic on every IEEE platform), matching Redis.

### Requirement 39: Geo (tier 7)

#### Acceptance Criteria

1. `GEOADD`, `GEODIST`, `GEOHASH`, `GEOPOS`, `GEOSEARCH`,
   `GEOSEARCHSTORE` and the deprecated `GEORADIUS*` family SHALL be
   implemented over sorted sets with Redis's 52-bit geohash scores, so a
   geo set is readable with `Z*` commands as in Redis.
2. Distance and area computations use `libm` trigonometry, whose last-bit
   results can differ between platforms. They SHALL therefore never run in
   `apply()`: reads compute on the serving node, and `GEOSEARCHSTORE` is
   computed once by the front end and proposed as an explicit store of the
   members and scores it found (deviation D12: a `GEOSEARCHSTORE` result
   reflects the front end's read at its consistency mode, not a point in
   the log, unless the snapshot build reads at one timestamp).

### Requirement 40: Streams and consumer groups (tier 8)

#### Acceptance Criteria

1. A `stream` value type SHALL be added, holding entries by ID in a
   chunked, append-optimised structure with Redis's radix-tree semantics
   (ordered IDs, field/value pairs, tombstones for `XDEL`), and consumer
   groups with their pending entries lists (PEL) and consumers.
2. `XADD` (`NOMKSTREAM`, `MAXLEN|MINID` with `=`/`~` and `LIMIT`, explicit,
   partial `ms-*` and `*` IDs), `XRANGE`, `XREVRANGE`, `XLEN`, `XDEL`,
   `XTRIM`, `XSETID`, `XREAD` (`COUNT`, `BLOCK`, `$` and `+`), `XGROUP
   CREATE|CREATECONSUMER|DELCONSUMER|DESTROY|SETID`, `XREADGROUP`
   (`NOACK`, `>` and history), `XACK`, `XPENDING` (summary and extended,
   `IDLE`), `XCLAIM` (all options), `XAUTOCLAIM`, `XINFO
   STREAM|GROUPS|CONSUMERS` SHALL be implemented.
3. An auto-generated ID SHALL take its millisecond part from the entry's
   command time (Requirement 2) and keep Redis's rule that IDs only grow,
   so every replica assigns the same ID.
4. Idle times, delivery counts and `XAUTOCLAIM`'s min-idle test SHALL use
   the command time in `apply()` and the serving node's clock on reads.
5. Approximate trimming (`~`) SHALL trim at chunk boundaries
   deterministically; the reply SHALL say how many entries were removed,
   which may differ from Redis's node-size-dependent count (D13).
6. Blocking `XREAD`/`XREADGROUP` SHALL use phase 2's key watches.
7. A stream SHALL be bounded by Requirement 9.4's collection limits. The
   design SHALL say how a very large stream could later keep sealed chunks
   in the core record segment store (as Kinesis does), without making that
   part of this phase.

### Requirement 41: Bitmaps, bitfields and HyperLogLog (tier 9)

#### Acceptance Criteria

1. `SETBIT`, `GETBIT`, `BITCOUNT` (`BYTE|BIT`), `BITPOS`, `BITOP`
   (`AND|OR|XOR|NOT|DIFF|DIFF1|ANDOR|ONE` as the reference server
   supports), `BITFIELD` (all types, `OVERFLOW WRAP|SAT|FAIL`) and
   `BITFIELD_RO` SHALL operate on string values exactly as Redis does.
2. `PFADD`, `PFCOUNT` and `PFMERGE` SHALL use Redis's HyperLogLog
   representation byte for byte (the `HYLL` header, sparse and dense
   encodings, MurmurHash64A), so a value moved by `DUMP`/`RESTORE` or RDB
   is valid on either side.
3. Redis caches a cardinality inside the value on `PFCOUNT`, which makes a
   read a write. Kythira SHALL compute `PFCOUNT` on the serving node
   without writing, keeping only a node-local cache, and the stored bytes
   SHALL be those of a value whose cache is marked stale (D14). The
   sparse-to-dense promotion SHALL follow Redis's thresholds in `apply()`.

### Requirement 42: Strings, hashes and keys: the remainder (tier 9)

#### Acceptance Criteria

1. `LCS` (`LEN`, `IDX`, `MINMATCHLEN`, `WITHMATCHLEN`), `SUBSTR`, and the
   Redis 7.4/8 hash field expiry commands (`HEXPIRE`, `HPEXPIRE`,
   `HEXPIREAT`, `HPEXPIREAT`, `HTTL`, `HPTTL`, `HEXPIRETIME`,
   `HPEXPIRETIME`, `HPERSIST`, `HGETDEL`, `HGETEX`, `HSETEX`) SHALL be
   implemented. Field deadlines SHALL use the command time and be reclaimed
   by the leader's sweep with the compare-the-deadline rule per field.
2. `SORT` and `SORT_RO` (`BY`, `LIMIT`, `GET`, `ASC|DESC`, `ALPHA`,
   `STORE`) SHALL be implemented. `BY` and `GET` patterns that name other
   keys are undeclared key access: they SHALL be allowed only when the
   pattern's keys route to the sorted key's group, or with transactions on
   (read at the connection's isolation), and otherwise refused with
   `-CROSSSLOT`, as Redis Cluster refuses them (D15).

### Requirement 43: Multiple databases (tier 10)

#### Acceptance Criteria

1. `SELECT 0`-`SELECT 15` (count configurable, as `databases`) SHALL work
   in the ordered keyspace. Database 0 SHALL stay the existing key space;
   each other database SHALL be its own multi-Raft key space of the Redis
   module (the mechanism of Requirement 34.1), created on first use.
2. `MOVE key db`, `COPY … DB n`, `SWAPDB` and `FLUSHDB` per database SHALL
   be implemented. `SWAPDB` SHALL swap the database-to-key-space mapping
   in the catalog group, which is atomic and O(1) as in Redis; `MOVE` is a
   cross-key-space transaction.
3. In the slot keyspace only database 0 SHALL exist, as in Redis Cluster.
4. ACL key scopes and `INFO keyspace` SHALL be per database.

### Requirement 44: Value serialization and key migration (tier 10)

#### Acceptance Criteria

1. `DUMP` and `RESTORE` (`REPLACE`, `ABSTTL`, `IDLETIME`, `FREQ`) SHALL
   use Redis's RDB value serialization (type byte, encoding, RDB version,
   CRC64 trailer) for every type Kythira holds, readable by and from the
   reference servers at the RDB versions they write.
2. `MIGRATE` (`COPY`, `REPLACE`, `AUTH`, `AUTH2`, `KEYS`) SHALL move keys
   to another Redis-protocol server, Kythira or not, by `DUMP` +
   `RESTORE`. A `MIGRATE` from Kythira to Kythira inside one cluster SHALL
   be refused as pointless (the keyspace is shared).
3. `OBJECT ENCODING` SHALL report the encoding Redis would use for the
   value at Redis's default thresholds (`listpack`, `quicklist`,
   `hashtable`, `intset`, `skiplist`, `embstr`, `int`, `raw`, `stream`),
   so tools that branch on it work (D16: it is computed, not Kythira's
   real layout). `OBJECT IDLETIME`, `FREQ` and `REFCOUNT` SHALL be
   answered from leader-local access statistics (Requirement 47).

### Requirement 45: Server and client surface (tier 10)

#### Acceptance Criteria

1. `CONFIG GET|SET|RESETSTAT|REWRITE` SHALL be implemented over a
   parameter table in the design. Each Redis parameter SHALL be one of:
   **mapped** to a Kythira setting (stored in the catalog group, so a `SET`
   reaches every node), **emulated** (accepted, stored, and honoured
   where it has a meaning, such as `notify-keyspace-events`,
   `maxmemory-policy`, `slowlog-log-slower-than`), or **inert** (accepted
   and reported but without effect, such as `appendfsync`, `save`,
   `activedefrag`), with the class shown in the table and in
   `CONFIG GET` documentation. `CONFIG REWRITE` SHALL persist mapped and
   emulated values in the catalog, not in a file.
2. `CLIENT ID|INFO|LIST|KILL|SETNAME|GETNAME|SETINFO|NO-EVICT|NO-TOUCH|
   PAUSE|UNPAUSE|REPLY|UNBLOCK|GETREDIR|TRACKING|TRACKINGINFO|CACHING`
   SHALL be implemented. `CLIENT LIST` and `KILL` SHALL span every gateway
   (fan-out through the layer membership group), and `CLIENT PAUSE`
   SHALL pause writes or all commands cluster-wide.
3. Client-side caching (`CLIENT TRACKING` default, `BCAST`, `OPTIN`,
   `OPTOUT`, `NOLOOP`, `REDIRECT`, RESP3 invalidation pushes and the RESP2
   `__redis__:invalidate` channel) SHALL be built on keyspace notification
   emission (Requirement 32), with the tracking table kept by the front
   end for its gateways' connections. A leader change SHALL make the front
   end invalidate every key it was tracking on that group (flush), so a
   client never keeps a stale entry silently (D17).
4. `MONITOR` SHALL stream every command executed by every front end to the
   monitoring connection, with secrets redacted, and SHALL need the admin
   role.
5. `WAIT numreplicas timeout` SHALL return how many replicas of the
   connection's last write's group have applied that write's log index
   (from the leader's match index), and `WAITAOF numlocal numreplicas
   timeout` SHALL return the counts that have fsynced it, which Raft
   commit already guarantees for a quorum (D18: counts are per group, and
   a write is already on a quorum before its reply).
6. `LATENCY LATEST|HISTORY|RESET|GRAPH|DOCTOR|HISTOGRAM`, `MEMORY
   STATS|DOCTOR|MALLOC-STATS|PURGE`, `INFO` (every section Redis has, with
   Kythira's values or Redis's zero values where a field has no meaning),
   `ROLE`, `TIME`, `LASTSAVE`, `LOLWUT` SHALL be implemented.
7. `SHUTDOWN [NOSAVE|SAVE] [NOW] [FORCE] [ABORT]` SHALL drain and stop the
   node that received it (admin), and `FAILOVER` SHALL transfer leadership
   of every group the node leads to other replicas.
8. `DEBUG` SHALL accept the subcommands client test suites use (`SLEEP`,
   `OBJECT`, `SET-ACTIVE-EXPIRE`, `JMAP`-style no-ops,
   `QUICKLIST-PACKED-THRESHOLD` and similar as inert), admin only and off
   unless `KYTHIRA_REDIS_ENABLE_DEBUG=on`, as Redis 7's
   `enable-debug-command`; any subcommand that would corrupt state on
   purpose (`DEBUG RELOAD`, `DEBUG CHANGE-REPL-ID`, `DEBUG SEGFAULT`) SHALL
   be refused (D19).

### Requirement 46: Memory policies (tier 11)

**User Story:** As an application written for Redis as a cache, I want
`maxmemory` and `maxmemory-policy` to behave as I expect, as closely as
a replicated store can.

#### Acceptance Criteria

1. `maxmemory` SHALL set a per-node budget for Redis data, split among the
   groups that node leads in proportion to their size, and
   `maxmemory-policy` SHALL accept every Redis value: `noeviction`,
   `allkeys-lru`, `allkeys-lfu`, `allkeys-random`, `volatile-lru`,
   `volatile-lfu`, `volatile-random`, `volatile-ttl` (and Redis 8's
   `allkeys-lrm`/`volatile-lrm` if the reference server has them).
2. Under `noeviction`, a write that would grow a group past its budget
   SHALL be refused with `-OOM command not allowed when used memory >
   'maxmemory'.`, decided in `apply()` against the replicated size, so
   every replica refuses the same entries.
3. Under the other policies, the leader SHALL pick victims with the
   policy from leader-local statistics and propose them as today's
   `evict` entries (redis-compatible-kv Requirement 9.2), so selection is
   free to be approximate while application is deterministic.
4. LRU/LFU statistics SHALL include reads served by followers, reported to
   the leader in batches with the existing advisory `touch` opcode, and
   `CLIENT NO-TOUCH` and `OBJECT FREQ` SHALL use them.
5. Deviations SHALL be stated (D20): the budget is per group, not per
   process; eviction runs on the policy tick, so a burst can exceed the
   budget briefly where Redis would evict synchronously; and LFU counters
   decay on the leader's clock.
6. The redis-compatible-kv rule that over-budget writes keep being
   accepted (Requirement 9.5) SHALL remain the behaviour of the build
   cache and of any cluster that sets no `maxmemory-policy`.

### Requirement 47: Persistence and replication commands (tier 11)

#### Acceptance Criteria

1. `SAVE` and `BGSAVE` SHALL take a Raft snapshot of every group (`SAVE`
   waits for all, `BGSAVE` returns at once; `BGSAVE SCHEDULE` accepted),
   `LASTSAVE` SHALL return the oldest of the groups' last snapshot times,
   and `BGREWRITEAOF` SHALL trigger log compaction on every group. Durability
   stays the Raft log (D21: no `dump.rdb` or AOF file is written by these
   commands).
2. `REPLICAOF`, `SLAVEOF`, `SYNC`, `PSYNC`, `REPLCONF` and RDB file
   import and export are specified by the separate migration tooling spec,
   `.kiro/specs/redis-migration-tooling/` (Clark, 2026-11-17: "Add another
   spec for migration tooling"). This spec provides what that one builds
   on: the RDB value codec and `DUMP`/`RESTORE` (Requirement 44), `MIGRATE`
   (44.2), keyspace notifications (Requirement 32) and multiple databases
   (Requirement 43). Until that spec lands, those commands SHALL answer
   `-ERR unknown command`.
3. `INFO replication` and `ROLE` SHALL report a primary with no external
   replicas until then.

### Requirement 48: Redis 8 built-in types (tier 12)

#### Acceptance Criteria

1. **JSON**: the `JSON.*` commands of Redis 8 / RedisJSON 2 (`JSON.SET`,
   `GET`, `MGET`, `MSET`, `DEL`, `TYPE`, `NUMINCRBY`, `NUMMULTBY`,
   `STRAPPEND`, `STRLEN`, `ARRAPPEND`, `ARRINDEX`, `ARRINSERT`, `ARRLEN`,
   `ARRPOP`, `ARRTRIM`, `OBJKEYS`, `OBJLEN`, `CLEAR`, `TOGGLE`, `MERGE`,
   `RESP`, `DEBUG MEMORY`, `FORGET`) with JSONPath and legacy paths,
   applied in `apply()` with RedisJSON's arithmetic (int64, else binary64,
   which is deterministic on every IEEE platform).
2. **Probabilistic**: Bloom (`BF.*`), Cuckoo (`CF.*`), Count-Min sketch
   (`CMS.*`), Top-K (`TOPK.*`) and t-digest (`TDIGEST.*`), with hash
   functions and layouts chosen to match the reference module's results
   for the same inputs where the reference documents them, and
   deterministic in `apply()` (no randomness; t-digest compression
   deterministic for one input order).
3. **Vector sets** (`VADD`, `VREM`, `VSIM`, `VCARD`, `VDIM`, `VEMB`,
   `VGETATTR`, `VSETATTR`, `VINFO`, `VLINKS`, `VRANDMEMBER`): the HNSW
   graph build uses randomness and float arithmetic, so inserts SHALL use a
   seed derived from the log entry and a fixed float evaluation order
   (no FMA contraction, scalar fallback) so every replica builds the same
   graph; `VSIM` results SHALL equal the reference server's only up to
   ties and approximate-search recall (D23).
4. **Time series** (`TS.*`): series, labels, retention by command time,
   compaction rules, `TS.RANGE`/`MRANGE` with aggregations computed on
   read; `TS.MRANGE` across groups is a front-end fan-out.
5. Each of the four SHALL be its own Kconfig option and format gate level.
6. The **query engine** (`FT.*`: secondary indexes, full text, vector
   search over hashes and JSON) SHALL NOT be built in this phase. Phase 3
   SHALL instead produce its scoping spec (secondary indexes across groups
   are a different problem from everything here). That is the only Redis 8
   built-in this spec does not implement.

### Requirement 49: Phase 3 layers, migrations and interop

#### Acceptance Criteria

1. The design SHALL place each phase 3 part: tracking tables, `MONITOR`
   fan-in, `CLIENT LIST`/`KILL` fan-out, `GEOSEARCHSTORE` and `SORT`
   planning on front ends; connection-level tracking state and
   invalidation pushes on gateways; stream consumer groups, eviction,
   `noeviction` refusal and every new type's `apply()` on data nodes;
   database mapping
   and `CONFIG` in the catalog group.
2. The layer migration tests (Requirements 24, 35) SHALL gain, both ways:
   splitting gateways with tracking clients (every client gets its
   invalidations or a flush), splitting front ends during `MONITOR`,
   `CLIENT PAUSE` and `SORT … STORE`, and splitting data nodes during
   stream consumer-group work (no entry lost or delivered outside the PEL
   rules) and under `noeviction` pressure. `SWAPDB` and `MOVE` SHALL run
   during the database-node split.
3. The differential suite and the recorded ElastiCache/MemoryDB transcripts
   SHALL cover every phase 3 command the AWS engine supports (ElastiCache
   Valkey's JSON and Bloom support included; MemoryDB's vector search
   noted as an `FT.*` surface for the query-engine scoping spec).
4. The real-cloud bundle SHALL add the phase 3 commands to its client
   suite comparison against ElastiCache and MemoryDB; Clark's go each run,
   cost reported, everything deleted. Migration between ElastiCache and
   Kythira is tested by the migration tooling spec.

## Non-Goals

Phase 3 takes up most of what earlier drafts listed here (streams, sorted
sets, RDB, eviction policies, client-side caching, hash field expiry,
`WAIT`, multiple databases). What remains out of scope:

- **Loading native modules** (`MODULE LOAD`, `MODULE LOADEX`). A shared
  object running inside `apply()` could not be held to determinism or the
  sandbox. `MODULE LIST` answers the built-in types of Requirement 48 so
  clients that probe for them work.
- **AOF and RDB files as the durability mechanism.** Durability is the Raft
  log; RDB files are an import/export format, handled by
  `.kiro/specs/redis-migration-tooling/`.
- **`DEBUG` subcommands that corrupt or crash on purpose** (D19).
- **The query engine (`FT.*`)** in this spec; Requirement 48.6 scopes it.
- **Typed values in the disk-backed build cache** (Requirement 13.3).
