# Implementation Plan

## Status: 0/16 tasks complete (phase A: 0/11, phase B: 0/5)

Each task is one PR unless noted. Needs `redis-general-data-types`
phase 1 and its task 43 (RDB value codec, `DUMP`/`RESTORE`, `MIGRATE`).
Phase B also needs that spec's tasks 23 (catalog group) and 32 (slot
keyspace). Phase A comes first; nothing in it waits for phase B.

## Phase A — RDB files, replication, bulk copy

- [ ] 1. Whole-file RDB codec
  - Header, opcodes, CRC64, LZF, version table; streaming reader and
    writer over file, object-store and socket sources/sinks; golden files
    from every reference version and from ElastiCache/MemoryDB backups;
    fuzz target
  - _Requirements: 2.1-2.4, 14.1_

- [ ] 2. Key writer and job state
  - Batched per-group / transactional writes, conflicts, refusals report,
    checkpoints; job records and fenced leases in the catalog;
    `KYTHIRA.MIGRATE STATUS|PAUSE|RESUME|CANCEL`
  - _Requirements: 1.2-1.4, 11.3, 12.1-12.3_

- [ ] 3. RDB import
  - `KYTHIRA.RDB IMPORT` with `DB`, `PREFIX`, `ON-CONFLICT`, `DRYRUN`;
    expired keys skipped; tests from Redis/Valkey `dump.rdb` files
  - _Requirements: 3.1-3.5_

- [ ] 4. RDB export
  - `KYTHIRA.RDB EXPORT` at one timestamp (snapshot build) or per-group
    indexes recorded in `AUX`; version choice; load tests in
    `redis-server` and Valkey; S3 policy docs for ElastiCache/MemoryDB
  - _Requirements: 4.1-4.3_

- [ ] 5. Inbound replication
  - `REPLICAOF`/`SLAVEOF`, `psync_client`, full sync through the key
    writer, command stream, `MULTI` blocks, offsets in the catalog and
    resume, read-only mode and paused sweeps, `INFO replication`, `ROLE`,
    `REPLICAOF NO ONE`; cluster-mode sources
  - _Requirements: 5.1-5.6_

- [ ] 6. Change feed and outbound replication
  - Effects ring on data leaders (rebuilt on leader change), zero cost
    without consumers; `feed_server` for `SYNC`/`PSYNC`, transaction
    blocks, offset checkpoints and resume (M1, M2); `WAIT` counts
    external replicas
  - _Requirements: 6.1-6.7_

- [ ] 7. Bulk copy
  - `KYTHIRA.MIGRATE FROM|TO`, `SCAN`+`DUMP`/`RESTORE`, cluster-mode
    discovery, type-specific fallback with temp-name rename, keyspace
    notification catch-up or second pass (M5), rate limits
  - _Requirements: 7.1-7.5_

- [ ] 8. Stand-alone tool, migration role, verification, credentials
  - `kythira-redis-migrate import|export|copy|verify` with local
    checkpoints; `migration` role and identity; job hand-over between
    workers; `KYTHIRA.MIGRATE VERIFY`; credentials by reference, TLS and
    IAM tokens
  - Peer detection (Redis, Valkey, ElastiCache, MemoryDB, Kythira) and
    Kythira self-identification in every handshake
  - _Requirements: 1.5, 8.1-8.5, 9.1-9.3, 10.1-10.3_

- [ ] 9. Migration path tests
  - The six container tests with every type, several databases,
    deadlines and functions, under writes where live; round trips;
    interruption tests per path; job moves between a front end and a
    `migration` node both ways; Kythira layer split and merge during an
    inbound and an outbound replication; Docker and rootless Podman
  - _Requirements: 13.1-13.5_

- [ ] 10. Interoperability with real ElastiCache and MemoryDB
  - CI: checked-in backup files imported and verified
  - Real-cloud bundle (dispatch-only, Clark's go each run): backups via S3
    into Kythira; Kythira exports restored into new caches; bulk copy
    both ways under writes with IAM auth; verification; cost report;
    cleanup on failure too
  - _Requirements: 14.1, 14.2_

- [ ] 11. Phase A documentation
  - `doc/redis-migration.md`: paths, runbooks with rollback, ElastiCache
    and MemoryDB specifics, deviations M1-M3 and M5
  - _Requirements: 11.1, 11.2, 16.2_

## Phase B — joining a Redis Cluster as a member

- [ ] 12. Cluster bus codec
  - Header and every message type, ping extensions of the pinned
    versions, captured-traffic golden tests per pinned version, version
    refusal
  - _Requirements: 15.1, 15.7, 15.9_

- [ ] 13. Members: join, gossip, failure detection, votes, leave
  - `KYTHIRA.CLUSTER JOIN|LEAVE`, member records and leases, gossip
    timers, address takeover by another gateway, `FAIL` handling, vote
    state in the catalog (M4)
  - _Requirements: 15.1-15.3, 15.6, 15.8_

- [ ] 14. Slot import and export
  - `KYTHIRA.CLUSTER IMPORT|EXPORT` with `MIGRATING`/`IMPORTING`,
    `MIGRATE` driven from Kythira, `RESTORE-ASKING`, `SETSLOT NODE`,
    epochs, per-slot checkpoints and rate limits
  - _Requirements: 15.4, 15.5_

- [ ] 15. Cluster membership tests
  - Against each pinned Redis and Valkey version: join, import every slot
    under cluster-client workloads, export back, leave; gateway kills
    during moves and gossip; Redis failover while members vote; Kythira
    layer split/merge while members own slots; Docker and rootless Podman
  - _Requirements: 15.10_

- [ ] 16. Phase B documentation and defaults
  - Membership guide with the version table and its upgrade rule;
    `CONFIG_REDIS_CLUSTER_MEMBER` default once task 15 merges
  - _Requirements: 15.7, 16.1, 16.2_
