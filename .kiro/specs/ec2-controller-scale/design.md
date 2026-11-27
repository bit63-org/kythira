# Design Document

## Overview

```
 front end ── ClientToken groups (hash(account, token))          [Req 5]
     │
 data layer
   network group n/<vni> ──► VPC stream: coalesce → delta → sign once → commit
   server group  s/<id>  ──► outbox: commands, per-server frames, stream refs
                  │  inventory → capacity index buckets                 [Req 6]
   catalog (allocator blocks, key table, types: read-mostly)
   signer: single (envelopes) | batch Merkle (per-server frames)        [Req 2]
   per-cell PD for the module's own shards                              [Req 9]
     │
 fleet layer
   link server ── stream refs resolved to bytes, FrameNotice for large  [Req 1, 3]
   frame store ── GET /v1/frames/<digest>, /v1/lookup/...               [Req 3]
   report path: state → commit; usage → usage stream → hourly totals    [Req 7]
   silence tracker → per-cell rate limit / mass silence                 [Req 8]
```

## Decisions

- **Store a VPC's state once, reference it per server.** Today a frame
  is copied into each server's outbox because each copy carries its own
  signature. With VPC-scoped signatures (antikythera
  `fleet-scale-networking` Requirement 4) every server receives the same
  bytes, so the outbox needs a position, not a copy. Fan-out cost becomes
  O(servers) 24-byte references plus one delta, instead of O(servers)
  full frames and signatures.
- **Coalesce in the network group, not the fleet.** Coalescing must keep
  workflow order (subnet, then NIC, then addresses), and only the group
  that commits the changes knows it. A delta is cut when the window
  closes or when a workflow asks for a barrier.
- **Batch-sign with a Merkle tree, keep the key in KMS.** Requirement 6.1
  of the EC2 spec forbids holding the signing key in the module, which
  rules out signing locally. A Merkle root signed once per batch keeps
  the key where it is and divides the signer's load by the batch size.
  Proofs are at most 12 hashes (4,096 leaves), 384 bytes, which every
  per-server link frame can carry; mailbox slots cannot, so envelopes
  stay single.
- **Derived indexes are disposable.** The capacity index and the frame
  store cache are rebuilt from authoritative groups. Neither is consulted
  for safety: a reservation still commits in the server's group, and a
  frame is still checked by digest and signature at the receiver.
- **Billing data does not need consensus to be durable.** Usage readings
  are monotonic counters keyed by series; any durable, deduplicating log
  keeps "a lost or replayed report only delays or repeats a reading". So
  they leave Raft, and only hourly totals enter it.
- **When many servers fall silent at once, believe the control plane
  broke.** A partition of one server and a crash of the fleet tier look
  the same from the data layer; the difference is how many. Rate limits
  and a mass-silence brake turn a correlated control-plane failure into
  a pause instead of a stampede.

## VPC streams in the network group

The network group already holds everything a VPC's frames carry. It
gains:

```
vpc_stream {
  vni, incarnation, vpc_id
  sequence u64                     // last committed delta
  snapshot_sequence u64            // newest materialized snapshot
  pending: change list             // since the last cut, in commit order
  mode: frames | stream            // per VPC (Req 1.5)
  lookup: bool                     // antikythera lookup VNI
}
```

1. A committed change appends typed records (antikythera
   `fleet-scale-networking` design "VPC streams" table) to `pending`.
2. The leader cuts a delta when the window (100 ms default) closes, when
   `pending` reaches 4,096 records, or at a workflow barrier. Cutting is
   a commit: the delta's records, `from`/`to` sequence and digest.
3. The leader signs the delta (single signature: one per VPC per window,
   a few thousand a second region-wide at peak) and commits the
   signature. The signed bytes go to the frame store keyed by digest.
4. For each server hosting the VPC, the leader commits a stream
   reference `(vni, incarnation, to_sequence, digest)` to the server's
   outbox; references for one VNI coalesce (newest wins) like frames do
   today. These are cross-group writes, batched per server group per
   window as one tier-1 append.
5. Snapshots are built from committed state, every N deltas (default
   1,024) or on a `need_snapshot` report, as parts of at most 295,032
   bytes, signed and stored the same way.

The fleet node sending a server's outbox sends a reference as the delta
itself (inline if under 16 KiB) or as a `FrameNotice` when the server's
bulk channel is up. A server that reports a gap gets a snapshot
reference.

`ec2-compatible-api`'s rule "the outbox delivers in commit order, so a
VpcConfig naming a subnet precedes the MapUpdate naming a NIC in it"
holds within a stream by construction: both are records of the same
ordered sequence.

## Batch signing

```
leaf_i  = SHA-256(0x00 | frame_i bytes up to the batch trailer)
node    = SHA-256(0x01 | left | right)
root    = tree over up to 4,096 leaves (odd node promoted)
trailer = batch_root [32] | leaf_index u16 | depth u8 | rsvd u8 | proof [32 x depth]
          | signature [64] over ("ak batch v1" | key_id | root)
```

The frame's own `version` field (or a new flag bit where the format has
one) says which form it uses. The signer worker on each data-node leader
collects frames from that leader's groups, closes a batch at 4,096
frames or 20 ms, makes one KMS `Sign` call over the root, and commits
each frame with its trailer. Verifiers are antikythera's
(`fleet-scale-networking`, and the codecs of `InstanceMetadata`,
`VolumeLayout` and `MapEntry`); task 3 here adds the verifier to
antikythera's `src/proto/` with vectors.

## Frame store

A fleet-layer HTTP/1.1 service over TLS 1.3. It accepts client
certificates issued by the storage CA's `net` role profile for servers
it knows, so a lost server's certificate stops working with its
revocation.

- `GET /v1/frames/<sha256>`: reads the bytes from the network group (or
  any group the digest's notice came from) through the data-layer API,
  caches them in memory by digest (LRU, default 4 GiB per node), serves
  them with `Content-Length` and no transformation.
- `GET /v1/lookup/<vni>/<incarnation>/<family>/<address>`: reads the
  VPC's committed bindings, builds a `MapEntry` (positive or negative),
  signs it in the next batch, caches it until the VPC's next delta
  touches its key or its `not_after`.
- Per-server token buckets on requests and bytes; a server over its
  bucket gets 429 and retries.

Co-located, the frame store is part of each fleet node; split, it runs
on its own nodes behind the same addresses. The tests run both and move
between them.

## Credentials, revocations and edge groups

- **Credentials.** The server group answers `credential_request` with a
  `VtepCredential` signed in a batch. Serial numbers come from a per-cell
  counter in allocator blocks. Revocations are committed in a per-cell
  list record in the catalog of the cell; an entry is dropped after its
  credential's `not_after`.
- **TunnelPeers retirement.** The network group tracks, per VNI, whether
  every hosting VTEP's inventory sets the `certified` bit; it stops
  emitting `TunnelPeers` for the VNI's servers when all do and resumes
  when one stops.
- **Edge groups.** An `edge` group kind (`e/<cell>/<group>`) holds the
  group's edge roles, hosts and prefixes. Host assignment is by cell
  (one or more edge groups per cell); prefixes are assigned by the
  operator. Each group's edge-table slice is a stream like a VPC's, with
  the antikythera `EdgeMapping` container and `edge_group_id`.

## Reusable VNIs and MACs

- **VNI allocator** (catalog): a free list plus quarantine records
  `(vni, freed_at, servers_pending)`. `DeleteVpc` moves the VNI to
  quarantine with the set of servers that held it; inventories that no
  longer list the VNI remove servers from the set; when the set is empty
  and 24 hours have passed, the VNI returns to the free list with
  `incarnation + 1`. A lost server (declared lost) leaves every set.
- **MACs** move into the network group: each VPC allocates from the
  configured prefix with its own counter and free list, so uniqueness is
  per VPC and a busy VPC never touches the catalog.

## ClientToken groups

Group kind `t/<hash(account, token)>`, holding `(account, token) →
(action, parameter digest, result, expires)`. The front end writes the
token record in the same tier-1 transaction that creates the workflow
record in the resource's group, so a retry finds either both or neither.
Retention follows EC2 (at least 24 hours), with expiry swept by the
group leader.

## Capacity index

```
bucket key = (cell, failure_domain, instance_family, free_band)
free_band  = floor(log2(free whole cores + 1)) and
             floor(log2(free 1 GiB pages + 1)), and free function counts by type
```

- Server groups emit an index update when a committed inventory or a
  reservation moves a server to another bucket. Updates go to index
  groups `x/<cell>/<family>`; each holds bucket → server set, plus
  counts.
- Placement walks buckets from the best-fitting band upward, filtered by
  the request's constraints, samples `k` servers from the first bucket
  that has any, applies per-candidate checks (local volume pins,
  multicast flood-list cap, spread), takes the best by the existing
  "most free whole cores" rule, and reserves in that server's group.
  A reservation that fails (stale index) retries with a new sample, at
  most 8 times, then widens the band.
- After an index group loss the index is rebuilt by scanning the cell's
  server groups; placement falls back to sampling server groups at
  random while it rebuilds.

## Usage stream

Usage reports go from the fleet node to the usage stream, partitioned by
`server_id`, with `(server_id, boot_id, report_seq)` as the dedup key;
the fleet node acknowledges helm once the stream confirms the write.
A metering worker per partition range reads the stream, keeps the last
reading per series in its own checkpointed state, computes deltas
(readings below the previous one recorded as faults and billed as zero,
as today), and commits per `(account, hour, meter)` totals to the
account's group every minute. Exports read the totals.

Where the Kinesis-compatible module is enabled, the usage stream is a
Kythira stream with one shard per few thousand servers; otherwise it is
an append-only segment log on the data nodes (the module's own
`usage_log`), with the same interface.

Inventory digests: the server group keeps the SHA-256 of the committed
inventory body; an incoming inventory with the same digest is
acknowledged without a commit. This makes a reconnect storm cost
handshakes and reads, not writes.

## Silence tracker

Per cell, the fleet layer reports connection state to a silence tracker
on the cell's catalog leader: a sliding 60 s window of servers that went
silent. Every silence-driven action asks the tracker for a token from
the cell's bucket (1% of servers per minute); in mass silence (5% of
servers silent in the window) the tracker refuses all tokens, the
actions wait in their workflows, and an alarm fires. The tracker leaves
mass silence when the silent fraction falls below 2.5% or an operator
resumes. khold's own rule (act only when group members also lose the
server) still applies first.

## Placement driver

The module runs `kythira_pd` (a `shard_placement_driver` model) on each
cell's catalog leader: data nodes send batched shard and node heartbeats
every 10 s; the driver issues operators to keep shard and leader counts
within ±10% of the cell mean, transfers leaders off hot load buckets
(`multi-raft-load-buckets`), and lets size and load policies split.
Operators are advisory and epoch-checked, as the multi-raft design
requires.

## hold cap and khold measurement

- The volume groups count hold volumes per cell; at the cap, `CreateVolume`
  for a class whose backend is hold places on khold if the class allows
  both, else refuses with `VolumeLimitExceeded` and an alarm.
- `tests/khold_scale_bench` runs 5,000 groups on one storage node with
  the multi-Raft host (hibernation on, 20% of groups active at a fixed
  write rate), recording CPU, memory, heartbeat traffic and p99 write
  latency; the CI row fails if any regresses by more than 20%.

## Scale harness

`ec2_sim_fleet` gains a multi-process mode: each process runs up to
25,000 simulated helms (link codecs, inventory, report sequences, a
model network role that applies streams and reports sequences), all
connecting to a real module deployment. Scenarios are YAML files listing
the VPC size distribution, launch and terminate rates, failure events
and duration. The harness writes a JSON result that the CI scale job
compares with the stored baseline.

## Testing strategy

- Property tests: stream cutting preserves workflow order and never
  loses a change across leader changes; batch trailers verify and any
  tampered leaf fails; the capacity index converges to a full scan's
  answer; VNI quarantine never frees a VNI a server still holds;
  ClientToken idempotency across failover.
- Migration tests both ways: frames ↔ streams per VPC; frame store
  co-located ↔ split; usage via Raft ↔ usage stream; TunnelPeers ↔
  certified peers.
- docker-chaos: fleet tier killed (mass silence entered, nothing failed
  over, resumed), frame store killed mid-fetch, signer slowed.
- Scale harness scenarios as Requirement 11.3 lists.

## Open questions

1. Should the coalescing window adapt to VPC size (shorter for small
   VPCs, longer for very large ones)? The design fixes it per deployment.
2. Is a usage stream on the module's own log worth building, or should
   usage-on-a-stream require the Kinesis module? The design keeps both.
