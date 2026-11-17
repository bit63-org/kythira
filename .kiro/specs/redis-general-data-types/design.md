# Design Document — General Redis Data Types, in Splittable Layers

## Overview

This design grows the sccache-scoped Redis service into a general Redis
service in two phases, and splits it into three layers that can run
together (the default) or apart. It builds on, and does not change the
decisions of:

- `.kiro/specs/redis-compatible-kv/` — RESP codec, deterministic expiry
  (leader-stamped deadlines, lazy read-time expiry, compare-the-deadline
  sweep), immutable-value rule, ACL, one-hop forwarding;
- `.kiro/specs/multi-raft-transactions/` — the transaction wrapper, the
  timestamp oracle, the multi-version state machine and `MULTI`/`EXEC`;
- `.kiro/specs/redis-gateway-module/` — the module layout under
  `services/redis/` and its boundary check;
- `.kiro/specs/kinesis-independent-layers/` (PR #843) — the shared layer
  pieces: per-node roles, layer identities, route cache with epochs, layer
  membership group, authenticated calls, evacuation and migration rules.

```
                 clients (RESP2/RESP3, TLS, cluster-aware or not)
                                   │
            ┌──────────────────────▼───────────────────────┐
  gateway   │ RESP framing · TLS · AUTH/HELLO · limits      │
            │ connection state · MULTI queue · subscribers  │
            └──────────────────────┬───────────────────────┘
                 authenticated call │ (in-process when co-located)
            ┌──────────────────────▼───────────────────────┐
  front end │ authorize · plan (one group / fan-out / txn)  │
            │ txn coordinator · SCAN cursors · key watches  │
            │ cross-shard scripts · cluster topology        │
            └──────────────────────┬───────────────────────┘
                   data-layer API   │ (in-process when local)
            ┌──────────────────────▼───────────────────────┐
  data      │ multi-Raft host · redis KV state machines     │
            │ sweeps/evictions · single-shard scripts       │
            │ catalog group · notification emission         │
            └───────────────────────────────────────────────┘
```

Everything a command does to data happens in `apply()` on the data layer,
from a log entry carrying every input it needs, including the time.

## Command tables

The tables are the scope (Requirement 1). "Path" says how a command
reaches data: **R** a read served from applied state, **W** one log entry
on one group, **M** multi-key (one entry if single-group, else a
transaction or `-CROSSSLOT`), **F** a front-end fan-out across groups,
**A** an admin operation.

### Tier 1 — strings and keys

| Command | Path | Notes |
|---|---|---|
| `INCR` `DECR` `INCRBY` `DECRBY` | W | int64 in `apply()` |
| `INCRBYFLOAT` | W | binary128 + in-tree decimal conversion, Redis's print format (D1) |
| `SET … [NX\|XX] [GET] [EX\|PX\|EXAT\|PXAT\|KEEPTTL]` | W | today's plain `SET` keeps record `0x01` |
| `SETNX` `PSETEX` `GETSET` | W | aliases |
| `GETDEL` `GETEX` `APPEND` `SETRANGE` | W | |
| `EXPIRE` `PEXPIRE` `EXPIREAT` `PEXPIREAT` `[NX\|XX\|GT\|LT]` | W | |
| `PERSIST` | W | |
| `TTL` `PTTL` `EXPIRETIME` `PEXPIRETIME` `TYPE` `OBJECT ENCODING` | R | |
| `TOUCH` | R | leader-local recency only |
| `UNLINK` `DEL` (n keys) | M | |
| `RENAME` `RENAMENX` `COPY [REPLACE]` `MSETNX` | M | |

### Tier 2 — keyspace and admin

| Command | Path | Notes |
|---|---|---|
| `SCAN` | F | cursor in front end |
| `KEYS` | F | admin, bounded |
| `RANDOMKEY` | F | weighted by group key counts |
| `DBSIZE` | F | exact sum |
| `KYTHIRA.DELPREFIX` `FLUSHDB` `FLUSHALL` | A | range deletes per group |
| `KYTHIRA.USAGE` `MEMORY USAGE` | F/R | |
| `INFO keyspace\|commandstats\|errorstats` `SLOWLOG` | local | |

### Tier 3 — typed values

| Type | Commands |
|---|---|
| hash | `HSET` `HSETNX` `HMSET` `HGET` `HMGET` `HDEL` `HEXISTS` `HLEN` `HSTRLEN` `HKEYS` `HVALS` `HGETALL` `HINCRBY` `HINCRBYFLOAT` `HRANDFIELD` `HSCAN` |
| set | `SADD` `SREM` `SISMEMBER` `SMISMEMBER` `SMEMBERS` `SCARD` `SPOP` `SRANDMEMBER` `SMOVE` `SINTER` `SUNION` `SDIFF` `SINTERCARD` `SINTERSTORE` `SUNIONSTORE` `SDIFFSTORE` `SSCAN` |
| list | `LPUSH` `RPUSH` `LPUSHX` `RPUSHX` `LPOP` `RPOP` `LLEN` `LINDEX` `LRANGE` `LSET` `LINSERT` `LREM` `LTRIM` `LPOS` `LMOVE` `RPOPLPUSH` `LMPOP`; phase 2: `BLPOP` `BRPOP` `BLMOVE` `BRPOPLPUSH` `BLMPOP` |

### Differences from the reference servers

| Id | Difference | Why |
|---|---|---|
| D1 | `INCRBYFLOAT`/`HINCRBYFLOAT` compute in binary128 everywhere; amd64 Redis uses 80-bit `long double`, so in rare cases its 17th decimal differs (arm64 Redis matches exactly) | mixed amd64/arm64 groups must agree byte for byte |
| D2 | `HGETALL`, `HKEYS`, `SMEMBERS`, `SCAN` return byte order | determinism; Redis promises no order, so clients cannot depend on one |
| D3 | `SCAN` never returns a key twice and survives resharding | position is a key, not a hash-table bucket |
| D4 | `SCAN` cursors expire (`-ERR invalid cursor`) | cursor state lives on a front end |
| D5 | scripts may touch only declared keys, even without cluster mode | the gateway must know the groups before running |
| D6 | `FLUSHDB`/`FLUSHALL` need `KYTHIRA_REDIS_ALLOW_FLUSH=on`; prefix delete is atomic per group only | safety on shared clusters; groups commit independently |
| D7 | `KEYS` admin-only and bounded | a full listing of a large cluster is an outage |
| D8 | blocked clients are FIFO per front end, not globally | key watches are per front end |
| D9 | `#<sha256>` ACL secrets refused by default | weaker than the stored PBKDF2 format |
| D10 | `-MOVED` is off by default in cluster mode | every gateway can serve every key |
| D11 | the immutable-value rule refuses mutations outside mutable prefixes | compile-cache poisoning defence (redis-compatible-kv Req 11) |
| D12 | `GEOSEARCHSTORE` stores what the front end read, not a log-point result | `libm` trigonometry is not bit-identical across platforms, so it cannot run in `apply()` |
| D13 | approximate stream trimming (`~`) trims at Kythira's chunk boundaries | Redis trims at its radix-tree node boundaries; both are "at least N" |
| D14 | `PFCOUNT` never writes its cached cardinality back | a read that writes would need a log entry per count |
| D15 | `SORT … BY/GET` with patterns across groups needs transactions or answers `-CROSSSLOT` | undeclared keys on other groups |
| D16 | `OBJECT ENCODING` reports the encoding Redis would choose, not Kythira's layout | tools branch on Redis's names |
| D17 | client tracking flushes a group's tracked keys on a leader change | notifications are at most once; a flush is the safe answer to a possible gap |
| D18 | `WAIT`/`WAITAOF` count replicas of the write's group; a reply already implies a quorum | Raft commits before replying |
| D19 | `DEBUG` is off by default and refuses deliberate corruption or crashes | a replicated store cannot reload or crash one node "for testing" safely |
| D20 | `maxmemory` is a per-group share of a per-node budget; eviction is on the policy tick | eviction must be a leader-proposed entry |
| D21 | `SAVE`/`BGSAVE`/`BGREWRITEAOF` snapshot and compact Raft groups; no `dump.rdb`/AOF file | durability is the Raft log; RDB is an export format |
| D23 | vector-set search results match the reference up to ties and HNSW recall | approximate search; graphs are built deterministically but not with Redis's random choices |

## Component 1: Command time

The leader's proposal path (`redis_gateway_impl.hpp` write path today, the
data node's propose handler after the split) stamps `now_ms` from the
leader's wall clock into every format-`0x03` entry. Each group's state
gains `_applied_time_ms`. `apply()` computes

```
t = max(entry.now_ms, _applied_time_ms); _applied_time_ms = t
```

and uses `t` for every "is this key live?" question in that entry. The
value is part of `get_state()` (after the format marker) and is copied to
both halves by `split_state`; `absorb` takes the larger.

Why not have the gateway check expiry before proposing: the check would be
against applied state that does not yet include entries in flight, so two
`SET NX` on an expiring key could both pass. The log is the only place
every replica sees in the same order.

Reads keep using the serving node's clock (lazy expiry). A follower whose
clock is ahead may report a key absent that a write a moment later still
sees live (the write uses the leader's time). That is the skew window
redis-compatible-kv Requirement 8.3 already documents; it cannot make
replicas diverge, because only `apply()` changes state.

### Float increments

`INCRBYFLOAT` and `HINCRBYFLOAT` must print what Redis prints, and must
agree byte for byte on amd64 and arm64. Redis computes in `long double`,
which is an 80-bit x87 value (64-bit mantissa) on amd64 and IEEE binary128
(113-bit mantissa) on arm64 Linux, and prints `%.17Lf` with trailing zeros
removed. Plain binary64 would print `0.30000000000000004` for `0.1 + 0.2`
where Redis prints `0.3`, so it was rejected; `long double` itself differs
between the two architectures.

The design uses binary128 on both: `long double` on arm64, `__float128`
on amd64 (GCC and Clang both provide it; the arithmetic is libgcc's or
compiler-rt's soft-float, which is IEEE correctly rounded, so `a + b` is
the same bits on both). Parsing and printing do **not** use `strtold`,
`printf` or libquadmath, because that would be two implementations of
the conversion: `services/redis/include/kythira/redis/redis_float128.hpp`
holds one correctly rounded decimal-to-binary128 parser and one
binary128-to-`%.17f` formatter (exact big-integer arithmetic on the
113-bit significand, a few hundred lines), compiled on both. No new
dependency. Golden tests pin replies for a table of inputs, including the
reference server's own test vectors, and run on the amd64 and arm64 CI
legs.

Residual difference (D1): where amd64 Redis's 64-bit mantissa rounds the
17th decimal differently from binary128, Kythira matches arm64 Redis and
not amd64 Redis. The differential suite records which cases those are.

## Component 2: Log-entry format `0x03`

```
byte 0     0x03
byte 1     0x08 (exec)
u16 BE     command id        (stable registry: services/redis/tools/redis_commands.yaml,
                              generated header redis_command_ids.hpp, freshness-checked
                              in CI like kinesis_actions.hpp)
u64 BE     now_ms            (Component 1)
u8         policy bits       bit0 immutable-rule on; bit1 key in mutable prefix (per key, see below)
u32 BE     argc
argc ×     { u32 BE len, bytes }     — exactly the RESP arguments after normalisation:
                                       relative TTLs already absolute, aliases resolved
u32 BE     mutable-key bitmap length, bitmap  (one bit per key argument, Requirement 5)
```

Other `0x03` records:

| Opcode | Record | Used by |
|---|---|---|
| `0x09` | `range_delete { u32 lo len, lo, u32 hi len, hi, u32 max keys }` | prefix delete, flush |
| `0x0A` | `format_gate { u16 level }` | Component 8 |
| `0x0B` | `remove_members { key, u32 n, n × member }` | `SPOP` (leader-picked) |
| `0x0C` | `script { now_ms, u32 body len, body, keys, args, u64 seed }` | phase 2 |

Records `0x01`–`0x07` keep versions `0x01`/`0x02`. A plain `SET` without
options still writes `0x01`, so the sccache workload's log stays
byte-identical and the golden fixtures for it do not change.

The reply produced by `apply()` is encoded as a RESP value (the bytes the
client will see, minus RESP2/RESP3 differences, which are carried as a
small typed reply tree and rendered by the gateway per connection).

## Component 3: Typed value model

```cpp
struct redis_value {
    std::uint64_t _expire_at_ms;                  // 0 = never
    std::variant<shared_bytes,                    // string (today's representation)
                 redis_hash,                      // chunked ordered map field→bytes
                 redis_set,                       // chunked ordered set
                 redis_list> _v;                  // chunked deque
};
```

All three collections are **chunked**: a vector of `shared_ptr<const
chunk>`, each chunk holding up to 128 elements (lists) or a contiguous
byte-ordered run of up to 128 entries (hash, set), plus a small index of
chunk first-keys. This gives:

- O(log n) element lookup, O(1) list end operations;
- copy-on-write per chunk, used both by the MVCC store (Component 6) and by
  the read path: a reader takes a `shared_ptr` to the collection's chunk
  vector under the node lock and encodes after releasing it
  (redis-compatible-kv Requirement 7.3 extended), while a writer replaces
  only the chunks it touches;
- deterministic iteration (byte order; list order).

Size accounting adds each element's bytes plus a fixed per-element
overhead, maintained incrementally in `apply()`.

`WRONGTYPE` is decided in `apply()` for writes and on the serving node for
reads.

## Component 4: Mutability policy

The front end resolves, per key argument, whether the key is inside one of
the user's mutable prefixes, and sets the bitmap in the entry. `apply()`
refuses a mutation of an **existing** key when the immutable bit is on and
the key's mutable bit is off. Deciding in `apply()` closes the race in
which two writers both see "absent" at the gateway. A forged bitmap is not
a concern because only front ends and data nodes (mutual TLS, Component 9)
can propose.

## Component 5: Multi-key planning

The front end routes every key, then:

1. one group → one `exec` entry on that group (it carries every key);
2. several groups, transactions on → a multi-Raft transaction. Each
   participant's prepare evaluates its part against locked state:
   `RENAME a b` is `{read+delete a}` on a's group and `{write b := value}`
   on b's group, the value flowing through the coordinator; `SMOVE` and
   `LMOVE` likewise; `SINTERSTORE` reads its sources at the transaction's
   start timestamp (snapshot build) or under read locks (tier-1 build) and
   writes the destination;
3. several groups, transactions off → `-CROSSSLOT`.

If an `exec` entry reaches a group that, after a split, no longer owns all
its keys, `apply()` refuses it with the existing stale-epoch result and the
front end re-plans (it may become case 2).

**Transactions with typed commands.** Today's transaction intents carry a
replacement value or a tombstone. A typed command in a transaction is
evaluated at prepare against the locked value; the intent holds the
resulting whole value (for collections, the new chunk vector, sharing
unchanged chunks) and the reply. Commit installs the intent. Because the
key is locked from prepare to commit, evaluation at prepare equals
evaluation at commit.

## Component 6: Stores

| Store | Strings | Collections |
|---|---|---|
| `memory` (`redis_kv_state_machine`) | as today | Component 3 in memory |
| `engine` (`persistent_kv_state_machine`, RocksDB) | as today | header row `k\x00` (type, deadline, count, bytes) + element rows `k\x00\x01<field>` (hash/set) or `k\x00\x02<u64 seq>` (list, with head/tail seqs in the header) |
| `file` (`cache_kv_state_machine`) | as today | refused (Requirement 13.3) |
| MVCC (`redis_kv_mvcc_state_machine`) | versions as today | each version holds a chunk vector; unchanged chunks are shared between versions; GC drops versions, and chunks die with their last reference |

The engine's composite keys sort each collection's rows directly after its
header and before the next user key (`\x00` separator; user keys that
contain `\x00` are escaped by the engine key codec, which already has to
round-trip arbitrary bytes). `split_state` for the engine store moves
header and element rows together because the split cut is a user key, and
all of a key's rows sort between the key and its successor.

Snapshots gain a leading marker `KRV3` + `u16 level`. A reader without the
marker parses the old format.

## Component 7: SCAN cursors, prefix delete, usage

**Cursors.** A cursor is `u64 = (front-end index : 14) | (cursor id : 50)`.
The front-end index comes from the layer membership group (or the
configured front-end list); `0` is reserved for "start/done". The front end
keeps `{last key, pattern, type, user, expiry}`. Each call asks the group
owning the next key for one page: up to `COUNT` keys strictly after the
last key, filtered on the data node by pattern, type and the user's
prefixes, and stops at the group's range end; the front end moves on to
the next range only when the page came back short. Pages are read from a
replica at the connection's consistency mode, without a log entry.

A literal prefix in `MATCH` gives a key range `[prefix, prefix+1)`; the walk
starts and ends there.

A cursor presented to another front end is forwarded to its issuer over
the internal link. A dead issuer means `-ERR invalid cursor` (D4).

**Prefix delete.** For each group whose range meets `[prefix, prefix+1)`,
propose `range_delete` bounded to the intersection and `max keys`. `apply()`
deletes up to `max keys` keys in the range in key order and returns the
count and the last key; the front end proposes again from there until a
short count. Deadlines and types do not matter to a range delete. Under the
transaction wrapper, a locked key in the range makes the entry stop before
it and report it; the front end resolves the lock as a plain `DEL` does,
then continues.

**Usage.** A read-only data-layer call over a range returns
`{bucket → (keys, bytes)}` for buckets cut at the requested delimiter and
depth, bounded by a bucket limit (the rest reported as `other`).

## Component 8: Format gate and rolling upgrade

Each binary has a `redis_format_level` (today's level is 2: records
`0x01`–`0x07`; phase 1 is 3; each phase 2 feature with a new record or
field bumps it). Every node reports its level in its health answer and in
the layer membership group.

`KYTHIRA.FORMAT UPGRADE <level>` (admin) on a front end:

1. reads the level of every data node holding a replica of any Redis group
   (from the host's membership) and of every gateway and front end; refuses
   if any is lower, naming the nodes;
2. proposes `format_gate{level}` to every group (and the catalog group in
   phase 2), retrying until each applies;
3. records the level in a cluster setting that front ends read before
   accepting commands that need it.

`apply()` of a gate records the level in the group's state (and
snapshot). A group refuses an `0x03` entry before its gate, which can only
happen through a bug, and a binary whose level is below a gate or record
it meets **stops** with "this log needs Redis format level N; run a newer
build", so an old binary started on a new data directory fails loudly.

New groups created by split inherit the parent's level through
`split_state`.

## Component 9: Layers

### Roles and composition

`KYTHIRA_REDIS_ROLES` parses into a role set; `redis_serving.hpp`
(the daemon's composition root) builds:

- **data**: the multi-Raft host and state machines (today's code), plus a
  `redis_data_service` exposing the data-layer API on the internal listener;
- **front_end**: `redis_front_end` — today's dispatch, authorization,
  planning and transaction coordinator, moved out of `redis_gateway_impl`
  and parameterised on a `redis_data_access` with `local_data_access`
  (in-process host calls, today's code path) and `remote_data_access`
  (route cache + internal link) implementations, chosen per call;
- **gateway**: `redis_gateway` keeps RESP, TLS, auth and connection state,
  and calls a `redis_front_end_access` that is either the in-process front
  end or a pinned remote front end.

A co-located node wires all three in-process: no extra hop, no extra
serialisation. That is what Requirement 16.1 and the measurement of
Requirement 24.4 hold to.

### Internal protocol

The forward link (`redis_forward_link.hpp`) already carries RESP commands
between gateways with a pooled, authenticated connection and the one-hop
rule. The data-layer API and authenticated calls are new internal commands
on the same link:

| Command | Caller roles | What |
|---|---|---|
| `KYTHIRA.CALL <identity> <conn-state> <cmd…>` | gateway | authenticated call to a front end |
| `KYTHIRA.DATA PROPOSE <group> <epoch> <entry>` | front_end, data | propose; not-leader → `-KYTHIRA.MOVED <leader> <epoch>` |
| `KYTHIRA.DATA READ <key> <mode> <op…>` | front_end, data | key or element read |
| `KYTHIRA.DATA PAGE <lo> <hi> <after> <count> <filters>` | front_end, data | SCAN / usage / prefix-delete page |
| `KYTHIRA.DATA ROUTE <key>` / `ROUTES <lo> <hi>` | front_end, data | routes with epochs |
| `KYTHIRA.TXN …` (exists) | front_end, data | transaction participant messages |
| `KYTHIRA.CURSOR <cursor> …` | front_end | forwarded SCAN continuation |

The caller's roles come from its layer identity (mutual TLS SAN
`kythira://redis/<cluster>/<node>?roles=…`). Between co-located nodes
without TLS, today's internal user and secret remain valid and imply the
`data` role only, so they cannot make an authenticated call.

### Connection state on a split gateway

The gateway pins a connection to a front end chosen by affinity
(hash of connection id over live front ends). `MULTI` queues on the
gateway and is sent whole at `EXEC`; `WATCH` sends `KYTHIRA.CALL WATCH` and
keeps the returned watch token in the connection state, which accompanies
the `EXEC`. If the pinned front end fails, the gateway re-pins; a command
that was in flight answers `-ERR outcome unknown, front end lost; it may
have applied`, as the transaction path already does for lost commits.

### Membership and routing

Front ends without `data` use the shared route cache (route = group, key
range, replicas, leader, data-layer addresses, epoch). Data nodes are found
from `KYTHIRA_REDIS_DATA_NODES` (names resolved with `net_resolve`) or the
layer membership group. A stale epoch is answered with the current route.

### Split and merge procedures

| Step | Mechanism |
|---|---|
| split gateway off node N | start gateway-only nodes; drain N's gateway; restart N with `front_end,data` |
| merge gateway back | restart N with all roles; drain and stop gateway-only nodes |
| split front end | start front-end-only nodes (join membership group); drain N's front end; restart N without `front_end` (its gateway now uses remote front ends) |
| split data off node N | `KYTHIRA.EVACUATE N`: per replica add learner elsewhere, catch up, promote, transfer leadership, remove N; restart N without `data` |
| merge data onto node N | restart N with `data`; placement driver adds it as learner of assigned groups; promote |

Each row's reverse is the row read the other way, and every intermediate
state is a valid mixed deployment because the access objects choose local
or remote per call. A `SCAN` cursor survives a front-end drain only if the
drained front end stays reachable until its cursors expire; the drain
waits up to the cursor idle expiry (configurable bound) and then answers
`invalid cursor` for the rest (Requirement 21.5).

## Component 10: Observability

New metric names follow `redis.<thing>` with a `command` dimension where
it applies: `redis.wrongtype`, `redis.mutability_refusals`,
`redis.collection_limit_refusals`, `redis.cross_shard{outcome}`,
`redis.crossslot_refusals`, `redis.cursors_open`, `redis.cursors_expired`,
`redis.prefix_delete_keys`, `redis.format_level{group}`,
`redis.command_time_lag_ms`, `redis.layer_calls{from,to,op}` and their
latency histograms. `INFO commandstats`/`errorstats` are computed from the
same counters per node.

## Component 11: Error table (additions)

| Condition | Wire error |
|---|---|
| wrong type | `-WRONGTYPE Operation against a key holding the wrong kind of value` |
| not an integer / overflow | `-ERR value is not an integer or out of range` / `-ERR increment or decrement would overflow` |
| not a float | `-ERR value is not a valid float` |
| value would exceed max | `-ERR value exceeds the configured maximum of <n> bytes` (existing) |
| collection over limit | `-ERR collection exceeds the configured maximum of <n> <bytes\|elements>` |
| immutable rule | `-ERR value conflict for an existing key` (existing) |
| cross-shard without txn | `-CROSSSLOT Keys in request don't hash to the same slot` |
| cursor gone | `-ERR invalid cursor` |
| before format gate | `-ERR this cluster has not enabled typed values yet (KYTHIRA.FORMAT)` |
| file store | `-ERR this command needs KYTHIRA_CACHE_PERSISTENCE=memory or engine` |
| flush disabled | `-ERR FLUSHDB is disabled on this cluster (KYTHIRA_REDIS_ALLOW_FLUSH)` |
| front end lost mid-command | `-ERR outcome unknown, front end lost; it may have applied` |
| undeclared key in script | `-ERR Script attempted to access a non local key in a cluster node script` (phase 2, Redis's text) |
| missing script | `-NOSCRIPT No matching script. Please use EVAL.` |

## Phase 2

### Component 12: Blocking list commands

The gateway parks the connection (it already handles a connection whose
reply is pending). The front end registers `KYTHIRA.DATA WATCH <key>
<lease>` with the leader of each key's group; the leader keeps a soft
`key → {front end, lease}` table, not replicated. On applying any entry
that pushes to a watched key, the leader sends `KYTHIRA.WOKEN <key>` to the
watching front ends. The front end proposes the pop for its oldest parked
client on that key; an empty result re-parks. Leader change: the new
leader has no table, so front ends renew watches on a route change and on
lease timer; after renewing they also re-try a pop once, so a push that
landed during the gap is not missed.

### Component 13: Scripts and functions

- Lua 5.1.5 vcpkg overlay port `vcpkg-overlays/lua51/`, built with
  `LUA_NUMBER` binary64 and a replaced `lua_number2str` using
  `std::to_chars` (shortest round trip), plus Redis's `cjson`, `cmsgpack`,
  `bit` and `struct` libraries (MIT/BSD, recorded).
- **Single-shard** (`script` record `0x0C`): the front end resolves
  `EVALSHA`/`FCALL` to the body, checks all declared keys route to one
  group, and proposes the body, keys, args, `now_ms` and a seed derived from
  the entry. `apply()` runs the script in a fresh sandbox with
  `redis.call` bound to the state machine's own command evaluator (the
  same code `exec` uses), writes buffered in an overlay and committed only
  on success. Budget: `lua_sethook` count hook every 1000 instructions
  against a fixed instruction budget, and a counting allocator with a
  fixed cap; both deterministic.
- **Cross-shard**: the front end opens a transaction, runs the script with
  `redis.call` bound to a transactional context: reads go through prepare
  (locks), writes are buffered as intents; at script end the coordinator
  commits. Retries re-run from scratch.
- Function libraries live in the catalog group (Component 15); front ends
  and data nodes cache them by catalog version. A single-shard `FCALL`
  entry carries the library body and version (so `apply()` never depends
  on catalog state that could differ between replicas).

### Component 14: Pub/sub and keyspace notifications

- Classic channels: each gateway publishes its channel and pattern
  interest (bloom filter + exact set when small) into the layer membership
  group as soft state; `PUBLISH` on any gateway sends the message over the
  internal link to gateways whose interest matches (or to all gateways
  without the group). No Raft.
- Sharded channels: the channel name routes like a key. Gateways register
  `KYTHIRA.DATA SUBSCRIBE <channel> <lease>` with the group leader; the
  leader keeps a soft table and fans `SPUBLISH` out to registered gateways.
- Keyspace notifications: when enabled (setting in the catalog group,
  read into each data node), the leader's apply loop enqueues events after
  applying each entry, and a sender thread publishes them as sharded
  messages on `__keyspace@0__:<key>` / `__keyevent@0__:<event>`; the
  latter are classic channels and go through the classic path.

### Component 15: Catalog group and replicated ACL

One Raft group of the Redis module (fixed id inside the module's group
range, service-colocation Requirement 4) on data nodes, created by the
format gate that enables it. State: users (Requirement 33), function
libraries, notification flags, keyspace mode and migration state, cluster
settings. Front ends and gateways watch it through a versioned
`KYTHIRA.DATA CATALOG SINCE <version>` long poll. The file-based ACL
loader becomes the bootstrap importer.

### Component 16: Slot keyspace and the Cluster protocol compatibility mode

The Cluster protocol exists for clients that will not connect without it
and for optional client-side routing; Kythira's scaling does not depend on
it (Requirement 34).

A second multi-Raft host of the Redis module (its own sub-range of the
module's group ids), whose routing key is `u16 BE slot || key`. Its
split policy rounds every cut down to a slot boundary. The front end
answers `CLUSTER SLOTS`/`SHARDS`/`NODES` by mapping each group's slot range
to gateways: in a co-located layout, the gateway on the leader's node is
primary and gateways on follower nodes are replicas; in a split layout,
the gateways in the leader's placement group. Node ids in `CLUSTER NODES`
are stable 40-hex ids derived from Kythira node ids.

Keyspace migration (`KYTHIRA.KEYSPACE MIGRATE TO slot|ordered`): the
catalog records `migrating`; front ends read from the target first, then
the source; writes go to the target and delete from the source in one
transaction; a background copier moves keys in batches in transactions;
when the source is empty the catalog records the cut-over. The reverse is
the same procedure with the roles swapped.

## Phase 3

### Component 17: New value types

`zset`, `stream`, and the Redis 8 types join `redis_value`'s variant, each
chunked and copy-on-write like Component 3:

- **zset**: chunks ordered by (score, member) plus a member→score index
  (an ordered map of member to chunk position), so `ZSCORE` is O(log n) and
  rank queries walk chunk counts kept in the chunk index.
- **stream**: chunks of up to 128 entries in ID order with tombstones;
  consumer groups hold `last_delivered_id`, a PEL ordered by ID
  (`{id → consumer, delivery time, delivery count}`) and per-consumer
  PEL views; delivery times are command times.
- **HyperLogLog** and **bitmaps** stay `string` values in Redis's own byte
  formats; their commands are string commands.
- **JSON**: a tree with copy-on-write nodes; **Bloom/Cuckoo/CMS/Top-K/t-digest**:
  fixed layouts as strings-with-type; **vector sets**: HNSW graph with a
  per-insert seed; **time series**: chunks of (timestamp, value) with
  labels in a per-group label index, compaction rules as series metadata.

The engine store gets a row layout per type (header row + element rows, as
Component 6), and each type adds a format gate level.

### Component 18: Databases and key spaces

The Redis module's group range is divided into key spaces: ordered db 0
(today's), ordered dbs 1-15 created on first `SELECT`, and the slot keyspace
(Component 16). The catalog group holds `db index → key space id`.
`SWAPDB a b` swaps two catalog entries in one catalog entry; front ends
read the mapping by catalog version and refuse to route a command with a
mapping older than one they have seen. `MOVE` is a transaction across two
key spaces' groups.

### Component 19: RDB value codec

`redis_rdb.hpp` reads and writes the RDB value encodings of RDB versions
9-12 (Redis 7.0-7.4, Valkey 8): strings (raw, int-encoded, LZF), listpack,
quicklist 2, intset, hash/zset/set listpacks, stream listpacks v3, and
refuses module type `0x07` except Requirement 48's types. `DUMP` and
`RESTORE` wrap one value with the 2-byte RDB version and CRC64 footer, and
`MIGRATE` sends `RESTORE` to the target. Whole-file RDB reading and
writing, `REPLICAOF` and serving `PSYNC` are built on this codec by
`.kiro/specs/redis-migration-tooling/`.

### Component 20: Memory policies

Each data node divides `maxmemory` among the groups it leads by their
`approximate_size_bytes()`. `noeviction` is evaluated in `apply()`: an
entry that would grow its group past the group's budget, recorded in the
group state by a leader-proposed `budget` entry when it changes, applies
as `-OOM` with no change. The other policies run on the leader's policy
tick: victims come from leader-local LRU clocks and LFU counters (Redis's
logarithmic counter and decay), fed by the leader's own reads and by
followers' batched `touch` reports, and are proposed as `evict` entries.

### Component 21: Server surface

`CONFIG` parameters live in a generated table
(`services/redis/tools/redis_config_params.yaml`: name, class
mapped/emulated/inert, type, default, Kythira setting); `CONFIG SET` of a
mapped or emulated parameter is a catalog entry. `CLIENT LIST|KILL|PAUSE`
fan out to gateways through the layer membership group. Tracking: the
front end keeps `key → {gateway, client ids}` for default mode and prefix
lists for `BCAST`, subscribes to sharded notifications for tracked keys,
and pushes invalidations through the client's gateway; on a route change
for a group it sends a flush (`null` invalidation) to every client tracking
keys of that group. `MONITOR` connections register with every front end,
which stream redacted command lines.

### Component 22: Redis 8 types

Each type is a command family registered in the command registry with its
own record arguments, so all go through `exec`. Vector set inserts carry
`seed = H(group, index)` and use a scalar distance kernel compiled with
`-ffp-contract=off`; the graph's level draws use the seed. Time series
retention is applied by the leader's sweep with the compare-the-deadline
rule per chunk.

## Testing strategy

| Layer | Tests |
|---|---|
| codec | golden bytes for every record and snapshot format; fuzzing the `exec` decoder |
| state machine | per-command `apply()` tests; command-time floor; determinism (two replicas, random streams, identical `get_state()`); split/absorb with collections; MVCC chunk sharing and GC |
| gateway/front end | in-process cluster tests for each command; multi-key single/cross group; CROSSSLOT; cursors across splits; prefix delete with locks |
| differential | seeded command generator → Redis 7.2 and Valkey 8 containers and Kythira; compare replies (RESP2/RESP3) modulo D1–D11 |
| clients | redis-py, go-redis, ioredis test subsets in containers |
| linearizability | history checker on counters, locks, lists, hashes under kills and partitions |
| upgrade | mixed-version cluster; format gate; old binary refusal |
| layers | migration path tests (Requirement 24), docker-chaos full path, co-located measurement |
| AWS | recorded ElastiCache/MemoryDB transcripts in CI; dispatch-only real-cloud bundle |
| migration in/out | in `.kiro/specs/redis-migration-tooling/` |

The command generator is shared by the differential suite, the
linearizability check and the AWS recordings, so one recording format
(`services/redis/tests/differential/recs/*.json`, command, RESP2 reply,
RESP3 reply, server, version, date) serves all three.

## Decisions and trade-offs

- **Verbatim replication with command time**, rather than effects
  replication. Effects would need the leader to evaluate against state
  that includes in-flight entries, which Kythira's apply model does not
  expose. Command time keeps `apply()` pure at the cost of one u64 per
  entry.
- **One general `exec` record** rather than a record per command: one
  decoder, one golden format, and new commands need only a registry entry.
  The cost is a few bytes of argc/lengths per entry.
- **Chunked collections** rather than plain `std::map`: one structure
  serves copy-free reads under the node lock, MVCC sharing and transaction
  intents.
- **Cursor state on the front end** rather than encoding the position in
  the cursor: clients parse cursors as integers, and a key does not fit in
  64 bits. The price is D4.
- **Layers over the forward link** rather than a new RPC stack: the link
  already has pooling, limits, auth and the one-hop rule, and keeping one
  transport is what lets co-located and split nodes mix.
- **Lua 5.1 overlay** rather than vcpkg's `lua` (5.4) or LuaJIT: Redis
  scripts depend on 5.1 semantics, and LuaJIT's JIT makes the instruction
  budget non-deterministic.
