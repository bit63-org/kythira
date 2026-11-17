# Design Document — Migration Between Real Redis and Kythira

## Overview

```
          real Redis / Valkey / ElastiCache / MemoryDB
              │ RDB file    │ PSYNC stream   │ SCAN+DUMP/RESTORE   │ cluster bus
              ▼             ▼                ▼                     ▼
   ┌──────────────────────────────────────────────────┐   ┌───────────────────┐
   │ migration worker (front end, or `migration` role, │   │ Kythira members   │
   │ or the stand-alone kythira-redis-migrate tool)    │   │ (phase B, on      │
   │  rdb_reader/rdb_writer · psync_client · feed_     │   │  gateways)        │
   │  server · bulk_copier · verifier · job state      │   └─────────┬─────────┘
   └───────────────┬──────────────────────────────────┘             │
                   │ data-layer API / client writes                 │
                   ▼                                                ▼
             Kythira data layer (groups, change feeds, slot keyspace, catalog)
```

All four kinds of path share three pieces: the RDB codec, a key writer
that turns decoded values into batched Kythira writes, and job state in
the catalog group. Phase A is the RDB, replication and bulk-copy paths.
Phase B is cluster membership.

## Component 1: RDB codec (whole files)

`services/redis/include/kythira/redis/redis_rdb_file.hpp` extends the
value codec of `redis-general-data-types` (Component 19 there) to whole
files: the `REDIS00vv` header, opcodes (`AUX`, `SELECTDB`, `RESIZEDB`,
`EXPIRETIME_MS`, `EXPIRETIME`, `FREQ`, `IDLE`, `FUNCTION2`, `MODULE_AUX`,
`EOF`), and the CRC64-Jones trailer. Reading is a pull parser over a byte
source (file, object-store ranged reads, or a socket during `PSYNC`);
writing is a push encoder to a sink (file, multipart upload, or a
socket). LZF and CRC64 are written in-tree (each well under 300 lines).
A version table maps each target version to the encodings it accepts, and
the writer downgrades encodings (for example listpack to ziplist-era
forms is **not** attempted; a type the version cannot hold is reported).

## Component 2: Key writer

Takes `(db, key, value, deadline)` tuples and writes them:

- route each key; group tuples by group; flush a batch at a key count or
  byte limit;
- with transactions on, one transaction per batch across groups,
  otherwise one `exec` (`RESTORE` command id) entry per group batch;
- apply `ON-CONFLICT` and the immutable-value rule in `apply()`;
- report refusals; record the checkpoint after each acknowledged batch.

The same writer serves import, inbound replication's full sync, bulk copy
into Kythira and phase B's slot imports.

## Component 3: Inbound replication

`psync_client` runs `AUTH`, `REPLCONF listening-port <gateway port>`,
`REPLCONF capa eof capa psync2`, `PSYNC <replid|?> <offset|-1>`. On
`+FULLRESYNC` it streams the RDB (disk-less `EOF:` mark or `$len`) into the
key writer, then reads the command stream: each command goes through the
front end as an internal replication identity, in order, one in flight
per group and pipelined across groups only when the commands are known
not to conflict (different keys, no `MULTI`). `REPLCONF GETACK` is
answered with the offset applied. The catalog records
`{replid, offset}` every batch; a worker taking the job over resumes with
`PSYNC`. A cluster flag in the catalog puts gateways in read-only mode and
pauses sweeps while the job is in `copying` or `catching_up`.

For a source Redis Cluster, one `psync_client` per primary, each carrying
only its slots' keys; Kythira's ordered (or slot) keyspace takes all.

## Component 4: Change feed and outbound replication

Each data leader keeps a ring buffer of `{log index, effects}` built from
`apply()` results (the state machine already returns a reply; it now also
returns normalised effects when a feed consumer is registered).
Effects for complex results (a `SINTERSTORE`, a script) are a `RESTORE …
ABSTTL REPLACE` of the resulting value. A follower that becomes leader
rebuilds its ring from its log between the snapshot index and its applied
index, so a resume across a leader change works while the log still holds
the entries.

`feed_server` answers an external replica's `PSYNC`:

1. take per-group indexes `I_g` (one oracle timestamp on the snapshot
   build), export the RDB at those indexes to the socket;
2. stream each group's effects after `I_g`, interleaved in arrival order;
3. a transaction's parts are held until all its groups have produced them,
   then sent as one `MULTI`/`EXEC`;
4. offset = bytes sent; the server stores `offset → {I_g}` checkpoints
   every few MB so `PSYNC <replid> <offset>` can resume from the nearest
   checkpoint at or before it (resending a few already-applied idempotent
   effects, which a replica tolerates because they are absolute writes).

## Component 5: Bulk copier

Per source shard: `SCAN` with `COUNT`, then a pipeline of `TYPE`, `PTTL`,
`DUMP` per key; on the target `RESTORE key ttl payload ABSTTL REPLACE` (or
the type-specific fallback with temp-name-then-`RENAME`). Keyspace
notifications (`__keyspace@*__:*`) are subscribed before the first `SCAN`;
changed keys are queued and recopied in the catch-up loop. The copier
throttles to configured rates and backs off on `-BUSY`, `-LOADING` or
latency rises.

## Component 6: Jobs and the migration role

Job state in the catalog: `{id, kind, direction, endpoints, credentials
ref, options, state, checkpoint, lease}`. A worker claims a job with a
fenced lease (lease epoch in every write it makes for the job). Workers
run on front ends by default; nodes with `KYTHIRA_REDIS_ROLES=migration`
run only workers. Draining a worker releases its leases; another claims
and resumes. The stand-alone `kythira-redis-migrate` binary runs the same
job code with a local checkpoint file and RESP connections to both sides.

## Component 7: Verifier

For each key on either side: `TYPE`, `PTTL`, and a canonical digest
(SHA-256 over the type-specific canonical encoding: strings as bytes,
hashes and sets sorted, lists in order, zsets by member with scores as
shortest round-trip text, streams by ID). Kythira computes digests on
data nodes; for the other side the verifier pulls `DUMP` and decodes.
`SAMPLE n` picks keys by `SCAN` with a random start on both sides.

## Component 8: Cluster membership (phase B)

### Protocol surface

`redis_cluster_bus.hpp` implements the cluster bus message header (`RCmb`
signature, version, sender's node id, config epoch, offset, slot bitmap,
flags, state) and the messages `PING`, `PONG`, `MEET`, `FAIL`, `PUBLISH`,
`PUBLISHSHARD`, `FAILOVER_AUTH_REQUEST`, `FAILOVER_AUTH_ACK`, `UPDATE`,
`MFSTART`, `MODULE` (ignored), and the ping extensions (hostname,
human nodename, forgotten node, shard id) of the pinned versions.

#### How stable the bus is (checked 2026-11-17)

Read from `src/cluster.h` / `src/cluster_legacy.h` at each release tag of
redis/redis and valkey-io/valkey:

- **`CLUSTER_PROTO_VER`** was `0` in Redis 3.0 and 3.2 and became `1` in
  Redis 4.0 (2017). It is still `1` in Redis 7.0, 7.2, 7.4, 8.0, 8.4 and
  `unstable`, and in Valkey 7.2, 8.0, 8.1, 9.0 and `unstable`. There has
  been one breaking bump, nine years ago.
- **Message types**: eleven (`PING` … `PUBLISHSHARD`, the last added in
  Redis 7.0), unchanged since in both projects. Valkey `unstable` adds a
  twelfth, `FAILOVER_AUTH_NACK`, sent only to nodes that advertise a new
  flag bit (`CLUSTER_NODE_FAILOVER_AUTH_NACK_SUPPORTED`).
- **Ping extensions** grow additively, about one release in two:

  | Ext id | Redis | Valkey |
  |---|---|---|
  | 0 hostname | 7.0+ | 7.2+ |
  | 1 human nodename | 7.2+ | 7.2+ |
  | 2 forgotten node | 7.2+ | 7.2+ |
  | 3 shard id | 7.2+ | 7.2+ |
  | 4 | `INTERNALSECRET` (8.0+) | `CLIENT_IPV4` (9.0+) |
  | 5-7 | none | `CLIENT_IPV6`, `CLIENT_PORT`, `CLIENT_TLS_PORT` (9.0+) |
  | 8-9 | none | `AVAILABILITY_ZONE`, `REPLICA_PRIORITY` (`unstable`) |

- **Valkey 8.0** added a "light" header for pub/sub messages (type bit
  `0x8000`), sent only to nodes that advertise
  `CLUSTER_NODE_LIGHT_HDR_SUPPORTED`.
- **Unknown extensions** are skipped and logged by both projects
  (`Received unknown extension type`), and new message forms are gated
  on flag bits, so an older peer keeps working.

So the protocol is stable in its core and changes additively, but the two
projects have **diverged**: extension id 4 means different things in Redis
8 and Valkey 9. Kythira must therefore know which project and version each
peer runs (from `INFO server`: `redis_version`, or `valkey_version` and
`server_name`) and decode extensions per flavour, and it must not
advertise flag bits for features it does not implement.

#### Pinned versions

| Server | Versions | Extensions Kythira sends | Extensions it must read |
|---|---|---|---|
| Redis | 7.2, 7.4 | 0-3 | 0-3 |
| Redis | 8.0, 8.2, 8.4 | 0-3 | 0-3, 4 (`INTERNALSECRET`) |
| Valkey | 7.2, 8.0, 8.1 | 0-3 | 0-3 (light header not advertised) |
| Valkey | 9.0 | 0-3 | 0-7 |

`unstable` branches are not pinned. A new release is added by a task that
captures its traffic, updates this table and runs the membership tests.

Unknown extensions are skipped by length, as Redis does; an unknown bus
version refuses the join.

### Members

A member is `{node id (40 hex), announced ip/port/bus port, config epoch,
slots, flags}` in the catalog. The gateway holding the member's lease
listens on its bus port and its client port, runs the gossip timers, and
answers client commands for the member's slots with Kythira's normal
command path over the slot keyspace. Losing the lease holder: another
gateway claims the lease, announces the new address in its next `PING`s
(Redis nodes update a known node id's address from gossip), within a
configured bound below `cluster-node-timeout`.

Failover votes: a member votes as a primary would (one vote per epoch,
for a replica whose primary is `FAIL`, not within `2 × node timeout` of a
previous vote for that primary). Its vote state is in the catalog so a
lease change cannot vote twice in an epoch.

### Slot moves

Import of slot `s` from Redis node `R` to member `M`:
`CLUSTER SETSLOT s IMPORTING R` on `M` (Kythira-internal), `CLUSTER
SETSLOT s MIGRATING M` on `R`, then loop `CLUSTER GETKEYSINSLOT s 100` on
`R` and `MIGRATE M.host M.port "" 0 timeout KEYS …` from `R` (Kythira sends
the command to `R`; `R` pushes to `M`, which answers `RESTORE-ASKING`),
then `CLUSTER SETSLOT s NODE M` on `M`, `R` and the others, bumping `M`'s
epoch. Export reverses roles, with Kythira's gateway acting as `MIGRATE`
sender. Per-slot progress is a checkpoint in the job.

### Licence position

The bus is implemented from the Redis Cluster specification (published
documentation) and from captured traffic between pinned versions, without
copying Redis or Valkey source. Valkey is BSD; Redis 7.2 is BSD; later
Redis versions are under RSALv2/SSPLv1/AGPLv3, which is why behaviour,
not code, is the reference.

## Deviations

| Id | Deviation |
|---|---|
| M1 | As a replication primary, Kythira orders the stream per group (per key), not globally |
| M2 | A `PSYNC` resume may resend a few idempotent absolute writes |
| M3 | Exports without the snapshot build are consistent per group, not across groups |
| M4 | A Kythira member is a primary with no replicas; Kythira keeps it available internally instead |
| M5 | Bulk copy without keyspace notifications needs writes stopped for an exact final state |

## Testing strategy

| Area | Tests |
|---|---|
| codec | golden RDB files from Redis 7.0-7.4, Valkey 7.2/8.0/8.1, ElastiCache and MemoryDB backups; fuzzing the parser; write-then-`redis-server --test-rdb`-style load check in a container |
| paths | Requirement 13's six container tests, round trips, interruption tests |
| layers | job moves between front end and `migration` node; Kythira layer split/merge during replication |
| membership | Requirement 15.10 against every pinned version |
| AWS | checked-in backup files in CI; dispatch-only real-cloud bundle |
