# Design Document

## Overview

```
 AWS CLI / SDKs / rclone / Mountpoint / Spark / Terraform / Kythira itself
        │ HTTPS REST-XML, SigV4 (header, query, chunked + trailers), POST
        ▼
 gateway     addressing, limits, SigV4 incl. streaming chunk signatures,
             100-continue, streams bodies through
        │ authenticated call + body stream (mTLS, role=gateway)
        ▼
 front end   authorization (IAM, bucket policy, ownership/ACL, BPA),
             handlers, chunking + SHA-256, checksums, SSE seal/open,
             conditional logic setup, prefix rate buckets
        │ chunk writes ───────────────► blob stores (placement)
        │ manifest commit / metadata reads (route cache)
        ▼
 metadata    multi_raft, object index state machine on RocksDB:
             buckets, versions + manifests, uploads, ACLs, policies,
             locks, chunk refcounts, placement map; change log;
             workers: lifecycle, notifications, replication, sweeps,
             placement repair
        │
        ▼
 blobs       core chunk store (from cache_chunk_store): large chunks as
             files, small ones in packs; SHA-256 named; peer fetch
                   │ tiering (lifecycle transitions)
                   ▼
             cloud object storage (existing object-store clients)
```

## Key design decisions

### Object bytes never go through Raft

The build cache puts value bytes in Raft entries and lets replicas fetch
what they lack. That is fine for build artifacts; for multi-gigabyte
objects it would write every byte twice on every replica (log and chunk)
and bound PUT throughput by one group's log. So the front end cuts the
body into chunks (8 MiB by default, the multipart part size where one is
given), hashes each, writes it to its placement, waits for a write quorum
of fsynced copies, and only then proposes a manifest of hashes. `apply()`
records the manifest and increments the chunks' reference counts. Raft
carries kilobytes per object.

Ordering gives the invariant: no committed manifest names a chunk that is
not durable (Requirement 10.2). The opposite failure, a durable chunk no
manifest names, is what the orphan sweep and reference-count grace period
handle (10.3, 10.4).

### Content-addressed chunks, refcounts in the state machine

Naming chunks by SHA-256 makes writes idempotent (a retried chunk write is
a no-op), copies free (`CopyObject` and `UploadPartCopy` commit a manifest
that reuses hashes), verification trivial, and moving chunks safe. The
store itself knows nothing of objects; reference counts live in the
metadata state machine, which is how the build cache already splits it
(`cache_chunk_store.hpp`). The chunk store moves to core
(`include/raft/chunk_store.hpp`) so the build cache and S3 share it.

Encrypted objects seal chunks under the object's data key before hashing,
so identical plaintext under different keys is different chunks and a
blob store holds only ciphertext.

### Placement: co-located replicas, or a blob pool

Co-located, the natural placement is "the nodes holding the metadata
replicas": a three-replica group's objects have three copies, on the same
machines, which is what an operator running three nodes expects. With blob
nodes, chunks are spread by rendezvous hashing over the pool, across
placement groups, with a copy count and write quorum.

This differs from Kinesis's per-replica volumes on purpose. Kinesis
segments are mutable, append-only logs tied to one replica's apply loop,
so each replica owns its files. S3 chunks are immutable and
content-addressed, so one pool with its own copy count is simpler,
deduplicates across replicas, and decouples blob capacity from the
metadata replica count.

Both placements are expressed the same way, a placement map in the
catalog with an epoch. "Co-located" is the map whose members are the
metadata nodes and whose rule is "replicas of the owning group". Migration
is a change of map, followed by a background move (Requirement 15.4).

### Strong consistency from the metadata layer

Every read of an object first reads its current version from the metadata
layer (a leader read, or a follower read at a read index), then fetches
chunks, which are immutable and so need no consistency of their own.
Listings are range reads over the index. That gives S3's
read-after-write and list-after-write consistency without coordination in
the blob layer.

### Index layout

| Key space | Key | Value |
|---|---|---|
| Catalog | `\0meta/s3/bucket/<name>` | bucket descriptor (id, owner, config) |
| Placement | `\0meta/s3/placement` | placement map and epoch |
| Object | `o/<bucket id>/<key>\0<inverted version stamp>` | manifest or delete marker |
| Upload | `u/<bucket id>/<key>\0<upload id>` | parts and their manifests |
| Refcount | `c/<sha256>` | count and zero-since time |
| Lifecycle | `l/<bucket id>/<due time>/<key>` | derived index |

Keys sort so a listing is one forward range read and a key's versions are
contiguous, newest first. Groups split on object-key boundaries; a hot
prefix splits like any hot range.

Reference counts under `c/` live in a separate range from the objects
that reference them, so a manifest commit that touches counts in another
group runs as a tier-1 transaction (`multi-raft-transactions`), batched
per commit.

### Streaming through the gateway

Bodies are not buffered: the gateway checks SigV4 chunk signatures as it
streams (`sigv4_chunk_decoder.hpp`) and forwards the body to the front end
on the same internal call; a co-located node does this in-process. A
chunk signature failure aborts the upload before any manifest commit.

### Notifications and replication from a change log

The metadata state machine appends a change record per committed version
or delete to the group's change log in the core record segment store, as
DynamoDB's change log does. Leader-side workers tail it: one publishes
event notifications, one replicates. Both are at least once and resume
from a position kept in the group's state, so a leader change neither
loses nor reorders events per key.

### Layers

Roles follow the Kinesis independent-layers design: `KYTHIRA_S3_ROLES`,
layer identities, route cache, authenticated call, optional layer
membership group for the stateless layers. The metadata layer has the
local, remote and hybrid access implementations; the blob layer is reached
by chunk reads and writes over the internal transport, or in-process when
the chunk is local.

## Components

| Component | Location | Notes |
|---|---|---|
| Chunk store (core) | `include/raft/chunk_store.hpp` | moved from the build cache |
| Model and coverage | `services/s3/include/kythira/s3/model/` | pinned botocore `s3` |
| REST-XML codec | core `include/raft/aws_rest_xml_protocol.hpp` | S3 first; others later |
| Object index state machine | `s3_index_state_machine.hpp` | manifests, versions, locks, refcounts |
| Handlers | `s3_service.hpp` | per operation family |
| Authorizer glue | `s3_actions.hpp`, `s3_access.hpp` | actions, policies, ownership, BPA |
| Placement | `s3_placement.hpp` | map, rendezvous, move, repair |
| Workers | `s3_lifecycle.hpp`, `s3_notifications.hpp`, `s3_replication.hpp`, `s3_sweeps.hpp` | |
| Daemon | `cmd/s3_gateway_node/` | roles, TLS, endpoints |

## Error handling

- A chunk write that cannot reach its write quorum fails the request with
  `503 SlowDown` (retryable) and commits nothing.
- A chunk failing its SHA-256 on read is retried from another copy and
  repaired; if no copy is good the read fails with `InternalError` and an
  alert fires. A bad chunk is never served.
- A conditional write whose condition fails answers `412
  PreconditionFailed` from `apply()`; a concurrent conflicting conditional
  write answers `409 ConditionalRequestConflict` as S3 does.

## Testing strategy

Unit and property tests per component; Ceph `s3-tests` and MinIO `mint`
in CI with a shrinking expected-failure list, on co-located and split
layouts; client suites (CLI, SDKs, rclone, Mountpoint, Kythira's own S3
client); migration path tests both ways plus docker-chaos; recorded S3
fixtures; a dispatch-only real-S3 bundle; a measurement row by object
size.

## Open questions

1. Erasure coding for the blob pool (say 6+3) instead of three copies:
   worth a follow-up once the pool exists?
2. Per-account bucket namespaces on by default, or one cluster-wide
   namespace like S3's global one? The design takes cluster-wide by
   default with the DynamoDB-style option.
3. Access Points next, or Multi-Region Access Points with replication?
