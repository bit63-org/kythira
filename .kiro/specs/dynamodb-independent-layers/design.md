# Design Document

## Overview

```
 clients (SDK, CLI, KCL 3.x, lock client, Terraform)
        │ HTTPS, AWS JSON 1.0, SigV4
        ▼
 gateway     framing, limits, SigV4, DescribeEndpoints, health, drain
        │ authenticated call (mTLS, role=gateway)
        ▼
 front end   authorization, dynamo_expr / PartiQL compile, handlers,
             capacity_throttler (share = 1 / live front ends)
        │ ops (catalog, write, read, page, describe, list, drop, txn,
        │      changes, stamped page) over the route cache
        ▼
 data        multi_raft host, item state machine on RocksDB, catalog,
             transaction wrapper, table keys (KMS), leader-side workers:
             catalog jobs, GSI propagator, TTL sweeper, Kinesis publisher,
             global-table replicator, PITR archiver, backups, strong host
        │ volume API (mTLS, role=data, volume epoch)
        ▼
 segments    change-log volumes, one per data replica
```

Shared core pieces come from `.kiro/specs/kinesis-independent-layers/`
design: layer identity, route cache, `segment_store` and the volume
service, the layer membership group. This document covers only what is
DynamoDB's own.

## Key design decisions

### The op is already the data-layer API

`raft_backend` turns every backend call into an op and runs it here or on
a peer. The remote backend is that code with the local attempt removed and
the peer chosen from the route cache instead of the voter list. The data
node's `serve(op)` is unchanged; it gains an epoch check and an op for each
backend call that does not have one yet (`change_shards`, `read_changes`
outside the `segment` op, `read_stamped_range`).

So the handlers do not change at all: `gateway<Backend>` is instantiated
with `remote_backend` on a front end without `data`, `hybrid_backend` on a
co-located node in a mixed cluster, and `raft_backend` (or
`routed_backend` with a strong host) where it is today. Unlike Kinesis,
there is no callback API to replace.

`hybrid_backend` decides per op: local when the node holds the group (and
leads it, for ops that need the leader), else remote. In an all-co-located
cluster it is never constructed; `raft_backend` keeps its own forwarding.

### Workers stay with leadership

Every DynamoDB background task already gates itself on leading something
(`leads_catalog()` or a base group). They all move to the data role.
The TTL sweeper is the one that lives in `gateway.hpp` today; it moves
into the data role's composition without changing its logic. A front end
runs no workers, so front ends can be added and removed freely, and the
places where object-store, Kinesis and peer-region credentials are needed
are only the data nodes.

### Capacity: share, not affinity

Kinesis routes each shard's reads to one front end because its limits are
per shard and small. DynamoDB's table limits are large and a hot table
must spread over every front end, so affinity would cap a table at one
front end's throughput. The existing share model stays, with the
denominator changed from voters to live front ends. The layer membership
group (or configuration) supplies the count; on a change each front end
rescales its buckets within one refresh interval.

### Table keys live on data nodes

The KMS design seals item values in the state machine so conditions and
updates evaluate on plaintext in `apply()`. That puts table keys on data
nodes. The front end never sees item plaintext at rest and never needs
KMS for items. Change-log records are sealed before `append`, so a
remote volume holds ciphertext. The documentation states which layer
holds which secret.

### Per-voter split ranges and migration

DynamoDB gives each voter a split id range (`(ordinal + 1) << 48`) so
voters can allocate group ids without coordination. A data node that is
evacuated keeps its range reserved until every group it created has other
replicas; a new data node gets an unused ordinal. Ranges are never reused,
so ids stay unique across any sequence of migrations.

### Strong host and global tables

Multi-region strong consistency runs a second multi-raft host spanning
three regions, and the global-table replicator talks to peer regions.
Both are data-node concerns and keep their own peer authentication. A
front end reaches strong-table items through the same remote backend:
`routed_backend`'s table-id rule picks the host, and the route cache holds
routes for both hosts' ranges.

## Components

| Component | Location | Notes |
|---|---|---|
| `remote_backend`, `hybrid_backend` | `services/dynamodb/include/kythira/dynamodb/` | ops over the route cache |
| op additions and epoch check | `raft_backend.hpp` | changes, stamped pages |
| authenticated-call handoff | `front_end.hpp` and the shared Kinesis-spec helper | gateway verifies SigV4 |
| role wiring | `cmd/dynamodb_gateway_node/` | `KYTHIRA_DYNAMODB_ROLES`, validation, worker placement |
| capacity denominator | `capacity.hpp`, `run_cluster.hpp` | live front ends |
| change-log volumes | `change_log.hpp` | `segment_store*` |
| docs and runbook | `services/dynamodb/doc/independent-layers.md` | |

## Error handling

- A front end that cannot reach a group's leader answers
  `InternalServerError` (retryable) for writes and consistent reads, and
  tries another replica for eventually consistent reads.
- An op with a stale epoch is answered with the current route and retried
  once.
- A transaction whose outcome a front end could not learn is answered as
  today (500, client retries with its token).

## Testing strategy

Handler tests over the remote and hybrid backends; a four-service compose
scenario on Docker and rootless Podman; one migration path test per path
in both directions, plus the full path under docker-chaos; a measurement
row comparing layouts.

## Open questions

1. Should eventually consistent reads prefer a replica in the front end's
   placement group even when the leader is closer? The design takes
   nearest replica by placement group first.
