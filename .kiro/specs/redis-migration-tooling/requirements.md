# Requirements Document — Migration Between Real Redis and Kythira

## Introduction

Kythira's Redis service (`services/redis/`) is growing into a general
Redis service (`.kiro/specs/redis-general-data-types/`). Adopting it is
only safe if it is reversible: an operator must be able to move an
application's data from real Redis into Kythira, and back out again,
without writing their own scripts.

Clark asked on 2026-11-17 for this to be its own spec ("Add another spec
for migration tooling"), after agreeing that the Redis Cluster protocol is
a compatibility mode for cluster-only clients and does not itself move
data. It covers Redis only; migration from AWS DynamoDB, Kinesis or S3 to
Kythira's counterparts would be separate specs.

"Real Redis" means:

- self-managed Redis OSS 7.x and Valkey 7.2/8, standalone or cluster mode;
- AWS ElastiCache (Redis OSS and Valkey engines), cluster mode on or off;
- AWS MemoryDB.

The managed services do not let an outside server replicate from them or
to them (`PSYNC`, `REPLICAOF` and `SYNC` are blocked), so the tooling has
three kinds of path, and each works in both directions:

| Path | Into Kythira | Out of Kythira | Works with |
|---|---|---|---|
| **RDB file** (offline) | import a `dump.rdb` or an ElastiCache/MemoryDB backup exported to S3 | export an RDB that `redis-server`, Valkey or ElastiCache restore-from-S3 load | everything |
| **Replication** (live) | Kythira replicates from a Redis primary (`REPLICAOF`) | a Redis replica replicates from Kythira (`PSYNC`) | self-managed Redis/Valkey |
| **Bulk copy** (live, then catch-up) | `SCAN` + `DUMP` on the source, `RESTORE` into Kythira, then a final pass | the reverse | everything, including ElastiCache and MemoryDB |

**Builds on** (from `redis-general-data-types`): the typed values of phase
1 (strings, hashes, sets, lists), the RDB value codec and `DUMP`/`RESTORE`
(its Requirement 44, task 43), `MIGRATE`, multiple databases
(Requirement 43), keyspace notifications (Requirement 32) and, for the
outbound feed, the leader apply hooks those use. Types from that spec's
later phases join each path as they land. This spec owns the
`REPLICAOF`, `SLAVEOF`, `SYNC`, `PSYNC` and `REPLCONF` commands that the
data-types spec defers here (its Requirement 47.2).

A fourth kind, added at Clark's request the same day, is **cluster
membership**: Kythira joins a self-managed Redis or Valkey Cluster as a
member on the cluster bus, takes slots over one at a time with Redis's own
`MIGRATING`/`IMPORTING` and `ASK` machinery, and can hand them back the
same way. It gives per-slot moves with no downtime and no client
repointing, at the cost of speaking Redis's internal cluster bus protocol,
which changes between versions. It is **phase B** of this spec; the three
paths above are **phase A** and do not wait for it.

**Scope**: whole-file RDB reading and writing; import and export
commands and a stand-alone tool; inbound and outbound replication; bulk
copy with catch-up; joining a Redis Cluster as a member (phase B);
verification; cut-over and rollback runbooks; where
the migration work runs (co-located or independent); tests in both
directions, including real ElastiCache and MemoryDB.

**Out of scope**: migrating other AWS services; module data types beyond
the Redis 8 types `redis-general-data-types` implements; continuous
two-way (active-active) replication; Redis Enterprise's proprietary
replication (CRDB/Active-Active).

## Glossary

- **Source** / **target**: the side data leaves / arrives at.
- **Migration job**: one run of one path, with an id, its configuration,
  progress checkpoint and state (`planned`, `copying`, `catching_up`,
  `ready_to_cut_over`, `cut_over`, `failed`, `cancelled`).
- **Migration worker**: the code that runs jobs. It runs on front ends
  (co-located, the default) or on nodes with the `migration` role.
- **Cut-over**: stopping writes to the source, waiting for the target to
  have every write, and pointing clients at the target.
- **Final pass**: the catch-up step of a bulk copy that recopies keys that
  changed after the copy read them.
- **Change feed**: the per-group stream of applied effects that data
  leaders keep for outbound replication.
- **Reference servers**: Redis 7.2 and Valkey 8 in containers.
- **Cluster bus**: the binary node-to-node protocol of Redis Cluster
  (port + 10000): `MEET`, `PING`/`PONG` gossip, `FAIL`, `UPDATE`,
  `PUBLISH`, failover auth messages, and their extensions.
- **Kythira member**: a cluster-bus identity (node id, address, slots)
  that Kythira presents to a Redis Cluster; served by a gateway, backed by
  the whole Kythira cluster.

## Requirements

### Requirement 1: Every path, both directions

**User Story:** As an operator, I want to move data into Kythira and back
out by the same family of tools, so that trying Kythira is not a one-way
door.

#### Acceptance Criteria

1. The tooling SHALL provide the six paths of the introduction's table
   (three kinds, two directions each).
2. Every path SHALL carry, for every key, its type, value, deadline (to
   the millisecond) and database, and SHALL carry function libraries
   (`FUNCTION DUMP`/`RESTORE`, RDB `FUNCTION2`) when both sides support
   them.
3. Every path SHALL report each key it could not carry (a module type the
   target lacks, a value over the target's limit, a key the target's ACL
   or immutable-value rule refused) by name, count it, and continue,
   never drop it silently. A `--strict` option SHALL stop the job at the
   first such key instead.
4. Every path SHALL be restartable: a job interrupted by a crash, a node
   loss or a cancel SHALL resume from its last checkpoint rather than from
   the start, without duplicating effects (re-writing a key with the same
   value and deadline is allowed).
5. Every path SHALL detect what the other side is before it starts:
   **Redis** (`INFO server` with no `server_name`, or `server_name:redis`;
   `HELLO` `server` `redis`), **Valkey** (`server_name:valkey`,
   `valkey_version`) or **Kythira** (`server_name:kythira`,
   `kythira_version`), with its version, and SHALL pick its behaviour
   from that: RDB versions, which commands are blocked (ElastiCache and
   MemoryDB are recognised by their `INFO` fields and refused commands),
   and, for cluster membership, how to decode ping extensions. Kythira
   SHALL identify itself as Kythira to the other side in every handshake
   (`CLIENT SETINFO LIB-NAME kythira-migrate`, `REPLCONF` and `INFO`), never
   as Redis or Valkey.
6. Kythira-to-Kythira jobs SHALL be supported too (for example between two
   Kythira clusters, or between the ordered and slot keyspaces of one,
   which reuse the same copy machinery as `KYTHIRA.KEYSPACE MIGRATE`).

### Requirement 2: RDB files

#### Acceptance Criteria

1. Kythira SHALL read RDB files of versions 9 to 12 (Redis 7.0-7.4,
   Valkey 7.2-8) and the versions ElastiCache and MemoryDB backups use,
   including `AUX` fields, `SELECTDB`, `RESIZEDB`, millisecond expiry,
   `FUNCTION2`, LZF-compressed strings, every value encoding, stream
   consumer groups, and the CRC64 trailer (verified; a mismatch fails the
   job).
2. Kythira SHALL write RDB files at a chosen version (default: the
   newest the target is declared to read), so an export restores into an
   older Redis or ElastiCache engine; a type the chosen version cannot
   represent SHALL be reported per Requirement 1.3.
3. Reading and writing SHALL stream: memory use SHALL be bounded by the
   largest single value plus a fixed buffer, not by file size.
4. Sources and destinations SHALL be a local path or an object-store URL
   (S3, GCS, Azure Blob, OSS, OCI) through the clients Kythira already has,
   with multipart upload for export.

### Requirement 3: Import from an RDB file

#### Acceptance Criteria

1. `KYTHIRA.RDB IMPORT <source> [DB n|ALL] [PREFIX old new] [ON-CONFLICT
   replace|skip|fail] [DRYRUN]` (admin) and `kythira-redis-migrate import`
   SHALL load an RDB file into the cluster.
2. `DRYRUN` SHALL parse the whole file and report counts per type and
   database and every key that would be refused, without writing.
3. Keys SHALL be written in batches routed per group; with transactions
   on, each batch SHALL be one multi-Raft transaction, otherwise per-group
   batches. The checkpoint (file offset and last key) SHALL be recorded
   after each acknowledged batch.
4. A key whose deadline has already passed SHALL be skipped and counted,
   as Redis does when loading.
5. The import SHALL honour the target cluster's limits and immutable-value
   rule and report refusals per Requirement 1.3.

### Requirement 4: Export to an RDB file

#### Acceptance Criteria

1. `KYTHIRA.RDB EXPORT <destination> [DB n|ALL] [VERSION v]` (admin) and
   `kythira-redis-migrate export` SHALL write an RDB file of the chosen
   databases.
2. On the snapshot-isolation build the export SHALL read every group at
   one oracle timestamp, so the file is one point in time. Otherwise it
   SHALL read each group at its own applied index, record those indexes
   in an `AUX` field, and say in its result that the file is consistent
   per group, not across groups.
3. The output SHALL load in `redis-server` and Valkey of the chosen
   version, and in ElastiCache's and MemoryDB's restore-from-S3. The
   documentation SHALL give the S3 bucket policy each service needs to
   read it.

### Requirement 5: Replicating into Kythira from a Redis primary

#### Acceptance Criteria

1. `REPLICAOF host port` / `SLAVEOF` SHALL make the cluster an inbound
   replica: the worker connects, authenticates (password, ACL user, TLS
   with optional client certificate), sends `REPLCONF listening-port`,
   `capa eof psync2`, and `PSYNC ? -1` (or `PSYNC <replid> <offset>` to
   resume), loads the RDB through Requirement 3's importer, then applies
   the command stream.
2. The stream SHALL be applied as writes under an internal replication
   identity: `SELECT` switches database, `MULTI`/`EXEC` blocks apply as one
   transaction (or `-CROSSSLOT`-style refusal recorded and the job failed
   if transactions are off and the block spans groups), and every other
   write applies as the command it is.
3. The worker SHALL record the primary's replication id and offset in the
   catalog group after each applied batch, and a new worker (after a
   front-end loss or a role change) SHALL resume with `PSYNC <replid>
   <offset>`, falling back to a full sync when the primary refuses.
4. While replicating, Kythira SHALL refuse client writes with `-READONLY
   You can't write against a read only replica.`, SHALL hide expired keys
   on read but SHALL NOT sweep them (the primary's `DEL`s remove them, as
   on a Redis replica), and SHALL answer `REPLCONF ACK` with its applied
   offset.
5. `INFO replication` and `ROLE` SHALL report `slave`, the primary,
   `master_link_status`, `master_last_io_seconds_ago`, the offset and the
   lag.
6. `REPLICAOF NO ONE` SHALL stop replication after the last applied batch,
   restart sweeps, and make the cluster writable.

### Requirement 6: Replicating out of Kythira to a Redis replica

#### Acceptance Criteria

1. An external Redis or Valkey replica SHALL be able to `REPLICAOF` a
   Kythira gateway endpoint: `SYNC` and `PSYNC` SHALL be answered with
   `+FULLRESYNC <replid> <offset>`, an RDB (Requirement 4) taken at known
   per-group indexes, then a stream of every write Kythira applies after
   those indexes.
2. Each data leader SHALL keep a **change feed**: the effects of each
   applied entry (normalised to Redis commands: `SET … PXAT`, `DEL`,
   `HSET`, `RESTORE … ABSTTL` for complex results, `PEXPIREAT`), by
   group log index, bounded by a configurable backlog size, produced from
   `apply()`'s results so it is the same on every replica that leads.
3. The serving worker SHALL merge the groups' feeds into one RESP stream.
   Order SHALL be preserved per group, and therefore per key, but not
   across groups (deviation: a Redis replica of Kythira may briefly show a
   cross-group write order no Kythira reader could see). A multi-group
   transaction SHALL be sent as one `MULTI`/`EXEC` block once all its
   groups' parts are in the feed.
4. The replication offset SHALL map to the vector of per-group indexes the
   stream has reached; the worker SHALL store that map so a replica's
   `PSYNC <replid> <offset>` resumes when every group's feed still holds
   its index, and answers `+FULLRESYNC` otherwise.
5. Sweeps and evictions SHALL appear in the feed as `DEL`, as a Redis
   primary propagates expiry.
6. `INFO replication` SHALL list connected external replicas, their
   offsets and lag; `WAIT` SHALL count them as Redis does.
7. The change feed SHALL cost nothing while no outbound replica or job
   uses it.

### Requirement 7: Bulk copy for servers that refuse replication

#### Acceptance Criteria

1. `KYTHIRA.MIGRATE FROM <endpoint> …` and `KYTHIRA.MIGRATE TO <endpoint>
   …` (admin) and `kythira-redis-migrate copy` SHALL copy every key by
   `SCAN` and `DUMP` + `PTTL` on the source and `RESTORE … ABSTTL REPLACE`
   on the target, in pipelined batches.
2. For a cluster-mode source or target (ElastiCache cluster mode,
   MemoryDB, self-managed cluster), the tool SHALL discover shards with
   `CLUSTER SHARDS` (or `CLUSTER SLOTS`) and copy from or to each shard's
   primary, following `MOVED`/`ASK`.
3. If the other side refuses `DUMP` or `RESTORE` (or their RDB versions are
   incompatible), the tool SHALL fall back to type-specific reads and
   writes (`GET`/`SET`, `HGETALL`/`HSET`, `SMEMBERS`/`SADD`,
   `LRANGE`/`RPUSH`, `ZRANGE … WITHSCORES`/`ZADD`, `XRANGE`/`XADD`, and so
   on), recreating each key under a temporary name and renaming it into
   place so a reader never sees a half-built collection.
4. **Final pass**: before the copy starts, the tool SHALL subscribe to the
   source's keyspace notifications when they are enabled (or can be: it
   SHALL say which ElastiCache parameter enables them) and record changed
   keys; after the copy it SHALL recopy them until the set of changed keys
   is empty or below a threshold. Without notifications it SHALL do a
   second full pass and say that writes during that pass need a cut-over
   with writes stopped.
5. The job SHALL rate-limit itself (keys per second and bytes per second)
   so a production source is not overloaded, and SHALL report progress.

### Requirement 8: Where migration work runs

**User Story:** As an operator, I want migration jobs to run where they
fit, without dedicated machines unless I want them.

#### Acceptance Criteria

1. By default the migration worker SHALL run on front ends (co-located with
   the rest of the Redis layers).
2. A node MAY run a `migration` role (`KYTHIRA_REDIS_ROLES` gains
   `migration`), so that jobs run on separate processes that hold no data
   and serve no clients; such nodes use the data-layer API and layer
   identities of `redis-general-data-types` Requirements 18 and 19, and a
   `migration` identity is required for job control calls.
3. Job state SHALL live in the catalog group, so any worker can take over a
   job: a job SHALL move between a co-located front end and a migration
   node, in both directions, by draining the worker running it and letting
   another claim it under a fenced lease.
4. `kythira-redis-migrate` SHALL also run as a stand-alone command-line
   tool, outside any Kythira cluster, speaking only RESP to both sides,
   for the RDB-file and bulk-copy paths; it keeps its checkpoint in a
   local file.
5. No path SHALL require the `migration` role.

### Requirement 9: Verification

#### Acceptance Criteria

1. `KYTHIRA.MIGRATE VERIFY <endpoint> [SAMPLE n|FULL]` and
   `kythira-redis-migrate verify` SHALL compare both sides key by key:
   type, a digest of the value in canonical order, and deadline within a
   configurable tolerance.
2. It SHALL report missing, extra and differing keys, by name up to a limit
   and by count beyond it.
3. Every job SHALL be able to finish with a verification, and the
   cut-over runbook SHALL require a full verification with writes stopped.

### Requirement 10: Credentials and security

#### Acceptance Criteria

1. Every migration command SHALL need the admin role (or a `migration`
   ACL category) on Kythira.
2. Credentials for the other side (password, ACL user, client certificate,
   ElastiCache IAM auth token generated from AWS credentials) SHALL be
   passed by reference (a file path, an environment variable name, or a
   secret in the catalog encrypted with the cluster's KMS provider), never
   as a command argument that appears in `MONITOR`, `SLOWLOG`, logs or the
   audit stream.
3. Connections to the other side SHALL use TLS when the endpoint is
   `rediss://` and SHALL verify its certificate unless an `INSECURE` option
   is given, which SHALL be logged at every use.

### Requirement 11: Cut-over and rollback

#### Acceptance Criteria

1. A runbook SHALL cover each path in each direction: preparation (sizes,
   limits, ACL, types), copy or sync, catch-up, verification, stopping
   writes (`CLIENT PAUSE WRITE` on whichever side supports it), final
   check, repointing clients, and resuming.
2. Each runbook SHALL give the rollback: the reverse path to run if the
   application must go back after cut-over, and SHALL say how long the
   source should be kept.
3. `KYTHIRA.MIGRATE STATUS|PAUSE|RESUME|CANCEL <job>` SHALL control jobs.

### Requirement 12: Observability

#### Acceptance Criteria

1. Metrics per job: state, keys and bytes copied, keys refused by reason,
   replication lag (seconds and offset), final-pass remaining keys, rate
   limit hits, verification differences.
2. `INFO replication` and a `KYTHIRA.MIGRATE STATUS` reply SHALL show the
   same numbers.
3. Each state change SHALL be logged and audited with the job id, the
   endpoint (without credentials) and the operator.

### Requirement 13: Migration path tests

**User Story:** As Clark, I want every migration path tested in both
directions.

#### Acceptance Criteria

1. For each of the six paths, a container test SHALL migrate a dataset
   with every type both sides support, multiple databases, deadlines and
   function libraries, under a concurrent write workload where the path is
   live, and SHALL end with a full verification showing no difference:
   - RDB: Redis 7.2 and Valkey 8 `dump.rdb` → Kythira; Kythira export →
     `redis-server` and Valkey;
   - replication: Redis/Valkey primary → Kythira; Kythira → Redis/Valkey
     replica;
   - bulk copy: Redis/Valkey standalone and cluster-mode → Kythira, and
     back, with the `DUMP`/`RESTORE` path and the type-specific fallback.
2. A round trip (Redis → Kythira → Redis, by each kind of path) SHALL end
   byte-identical in `DUMP` output for every key, except encodings the
   difference table of `redis-general-data-types` allows.
3. Interruption tests SHALL kill the worker, a data leader, and the
   source or target connection mid-job, for every path, and SHALL show the
   job resuming from its checkpoint without loss.
4. Layer tests SHALL move a running job, both ways, between a co-located
   front end and a `migration` node, and SHALL split and merge the
   Kythira cluster's layers (`redis-general-data-types` Requirement 24)
   while an inbound and an outbound replication run.
5. Container scenarios SHALL follow `CLAUDE.md`'s container-runtime rules
   and run on Docker and rootless Podman.

### Requirement 14: Interoperability with real ElastiCache and MemoryDB

#### Acceptance Criteria

1. CI (no spend) SHALL include RDB files produced by ElastiCache (Redis OSS
   and Valkey engines) and MemoryDB backups, checked in with the engine,
   version and date, and SHALL import them and verify against recorded key
   listings.
2. A real-cloud bundle SHALL be dispatch-only, behind a repository
   variable, and SHALL need Clark's go in his own words each run. It SHALL
   use the smallest ElastiCache cache (cluster mode off and on) and
   MemoryDB cluster with an in-VPC runner, and SHALL: export an
   ElastiCache and a MemoryDB backup to S3 and import it into Kythira;
   export from Kythira to S3 and restore it into a new cache and cluster;
   bulk copy from a live cache into Kythira and back under a write
   workload, with IAM-token authentication; verify every run; report the
   cost; and delete everything it made, including on failure.

### Requirement 15: Joining a Redis Cluster as a member (phase B)

**User Story:** As an operator of a self-managed Redis Cluster, I want to
move it into Kythira, and back, one hash slot at a time with no downtime
and without repointing clients.

#### Acceptance Criteria

1. `KYTHIRA.CLUSTER JOIN <seed host:port> [MEMBERS n]` (admin) SHALL
   create `n` Kythira members (default 1) and `CLUSTER MEET` them into the
   Redis Cluster. Each member SHALL speak the cluster bus on its own port,
   gossip its slots, config epoch and flags, mark and clear failures as a
   primary does, answer `CLUSTER` commands consistently with the Redis
   nodes, and vote in replica failover elections (`FAILOVER_AUTH_REQUEST`
   / `ACK`) by Redis's rules.
2. Kythira members SHALL serve their slots from the slot keyspace of
   `redis-general-data-types` Requirement 34, so a slot owned by a member
   is stored, replicated and split like any other Kythira data, and every
   Kythira gateway can serve it.
3. A Kythira member SHALL be a primary with no Redis replicas. It SHALL
   stay reachable when the gateway serving it fails: another gateway SHALL
   take over its node id under a fenced lease and announce the new address
   through gossip, faster than `cluster-node-timeout`, so the Redis nodes
   never mark it `FAIL`. If it is marked `FAIL` anyway, no Redis replica can
   take its slots (it has none), and the tooling SHALL clear the flag once
   it is reachable, as Redis does for a primary without replicas.
4. **Slots into Kythira**: `KYTHIRA.CLUSTER IMPORT <slot range>` SHALL, per
   slot, set it `IMPORTING` on the member and `MIGRATING` on the owning
   Redis node, move its keys with `MIGRATE` (driven by Kythira against the
   Redis node, so `ASK` redirects keep clients correct during the move),
   then `CLUSTER SETSLOT … NODE` on every node and bump the epoch. One slot
   at a time by default, rate-limited, restartable per slot.
5. **Slots out of Kythira**: `KYTHIRA.CLUSTER EXPORT <slot range> TO
   <node id>` SHALL do the reverse: the member is `MIGRATING`, the Redis
   node `IMPORTING`, Kythira sends `MIGRATE` (`RESTORE-ASKING`) to the
   Redis node, then reassigns the slot.
6. `KYTHIRA.CLUSTER LEAVE` SHALL refuse while a member owns slots, and
   otherwise `CLUSTER FORGET` its members on every node.
7. **Version coupling**: the cluster bus is internal to Redis and changes
   between versions (checked 2026-11-17: the bus version has been `1`
   since Redis 4.0 in both projects, with additive, flag-gated extensions,
   but Redis 8 and Valkey 9 assign the same extension id to different
   things). Kythira members SHALL name themselves `kythira-<n>` in the
   human nodename and hostname extensions so operators can tell them from
   Redis nodes; the bus has no vendor field. Supported versions SHALL be pinned in a table in the design
   (initially Redis 7.2, 7.4, 8.0, 8.2 and 8.4; Valkey 7.2, 8.0, 8.1 and
   9.0), extensions SHALL be decoded per server flavour, JOIN
   SHALL read each node's `INFO server` and refuse a version not in the
   table, and CI SHALL run the membership tests against every pinned
   version. Adding a version SHALL be a task with its own tests.
8. Managed services (ElastiCache, MemoryDB) do not admit outside members;
   phase B SHALL say so and point to phase A's paths for them.
9. The implementation SHALL be written from the published Redis Cluster
   specification and observed behaviour, not by copying Redis source,
   and its licence position SHALL be stated in the design.
10. **Tests**: against containerised Redis and Valkey clusters of each
    pinned version (three primaries, one replica each): join; import every
    slot into Kythira under a cluster-client workload (redis-py
    `RedisCluster`, go-redis `ClusterClient`) with no client error beyond
    `ASK`/`MOVED` handling and no lost write; export every slot back;
    leave; kill the gateway serving a member mid-migration and during
    gossip; a Redis primary failover while Kythira members vote; and
    Kythira layer splits and merges while members own slots. Docker and
    rootless Podman.

### Requirement 16: Build and documentation

#### Acceptance Criteria

1. The tooling SHALL be behind `CONFIG_REDIS_MIGRATION` (default `n`
   until its acceptance tasks merge), and cluster membership behind
   `CONFIG_REDIS_CLUSTER_MEMBER`, and add no third-party dependency
   (LZF and CRC64 are small and written in-tree).
2. `doc/redis-migration.md` SHALL describe every path, the runbooks, the
   ElastiCache/MemoryDB specifics (blocked commands, S3 permissions,
   notification parameters, IAM auth), cluster membership and its
   supported versions, and the deviations.
