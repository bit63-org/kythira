# Requirements Document

## Introduction

The EC2 module (`.kiro/specs/ec2-compatible-api/`) is the controller for
antikythera servers. Its partitioning already scales out: instances,
volumes, VPCs, servers and images live in hash-sharded Raft groups that
split and merge. The 2026-11-27 scaling analysis
(`/mnt/project-files/audits/antikythera-scaling-limits-2026-11-27.md`)
found where it still breaks as one availability zone grows toward a
million servers:

- **Per-server signatures on VPC-wide frames.** A VPC change becomes one
  signed, committed frame per server hosting the VPC. At a million
  servers that is about 400k KMS signatures and 20 GB/s of committed
  outbox payload at peak, and a single 4,000-NIC autoscaling VPC can
  produce 20k signatures a second by itself.
- **One catalog group on the launch path.** The ClientToken index lives
  with the allocators and the signing key table, so every idempotent
  create writes one Raft group.
- **Placement by scan.** "Most free whole cores" needs an order over
  every server record.
- **Usage readings committed to Raft.** `nat_usage` every 10 s from every
  host, `group_usage`, `edge_usage`: up to ~100k commits/s of data that
  only billing reads.
- **Silence-driven actions with no brake.** A fleet-tier outage looks
  like a million silent servers.
- **hold's per-volume lease traffic,** 3-4 messages per volume per second
  into volume-group leaders.
- **Never-reused VNIs and MACs,** which cap lifetime creations.
- **No placement driver** for the module's own shards, and no measured
  limit for khold's groups per storage host.

This spec fixes those in the controller. Antikythera's
`fleet-scale-networking` spec defines the frames, credentials and
channels this spec produces; `fleet-cells` (this repository) partitions
the zone into cells and supplies the delegated keys and capacity
summaries that this spec uses inside a cell. Every requirement here
works unchanged in a deployment with a single cell.

Clark's independent-layers rule applies: each new piece (the frame
store, the usage stream, the placement index) runs co-located with the
data layer or on its own nodes, never requires the split, and both
migration directions are tested.

### What this spec does not cover

- Cells, the cell router and delegated keys: `fleet-cells`.
- The network role and helm sides of the new frames:
  antikythera `fleet-scale-networking`.
- Billing exports beyond what `ec2-compatible-api` Requirement 12
  already defines.

## Glossary

- **VPC stream** — antikythera's ordered snapshot-and-delta frames for
  one VPC's network state (`fleet-scale-networking` Requirement 5).
- **Frame store** — a read-only, content-addressed HTTP endpoint on the
  fleet layer that serves signed frames and mapping lookups by digest.
- **Batch signature** — one KMS or HSM signature over the Merkle root of
  many frames, each frame carrying its inclusion proof.
- **Capacity index** — buckets of servers grouped by cell, failure
  domain, instance family and free-capacity band, kept current from
  inventories.
- **Usage stream** — an append-only, partitioned log that usage reports
  are written to before helm is acknowledged.
- **Mass silence** — more than a configured fraction of a cell's servers
  going silent within a short window.

## Requirements

### Requirement 1: Sign VPC state once per change

**User Story:** As an operator, I want a VPC change to cost one signature
and one small committed record, whatever the number of servers hosting
the VPC.

#### Acceptance Criteria

1. The network group SHALL produce each VPC change as one VPC stream
   delta, signed once, committed once in the VPC's network group, and
   SHALL produce a snapshot from committed state on demand.
2. Server outboxes SHALL hold references to VPC stream positions
   (`vni`, incarnation, sequence), never per-server copies of VPC-wide
   frames; a fleet node SHALL resolve each reference to the frame bytes
   when it sends.
3. Changes to one VPC SHALL be coalesced over a configurable window
   (default 100 ms, at most 1 s) into one delta, without reordering
   changes that a workflow orders (a subnet before the first NIC in it,
   a NIC before its addresses).
4. A workflow SHALL be able to wait until a change is live on every
   server hosting the VPC, from the servers' reported stream sequences
   (`fleet-scale-networking` Requirement 9.3).
5. Snapshot frames (`MapUpdate`, `VpcConfig`, `SecurityPolicy`,
   `GroupPolicy`, `GroupMembers`) SHALL remain available per VPC, and
   the controller SHALL choose frames or streams per VPC, moving either
   way while the VPC carries traffic.
6. The KMS or HSM key rules of `ec2-compatible-api` Requirement 6 SHALL
   hold unchanged: the signing key never enters the module's memory.

### Requirement 2: Batch signatures for per-server frames

**User Story:** As an operator, I want per-server frames to be signed in
batches, so that the signer's rate does not cap how fast the fleet can be
told things.

#### Acceptance Criteria

1. Per-server link frames with room for a proof (`InstanceMetadata`,
   `VolumeLayout`, `VtepCredential`, `MapEntry` lookup records) SHALL be
   signable as a batch: one signature over a Merkle root of the frames'
   hashes, the frame carrying the root, its index and its proof.
2. A batch SHALL close at a size or time bound (defaults 4,096 frames
   or 20 ms), so batching adds at most that much latency.
3. Mailbox envelopes SHALL stay individually signed: their 256-byte slot
   has no room for a proof and their rate is per launch, not per fan-out.
4. A frame signed singly SHALL stay valid; a verifier SHALL accept either
   form.

### Requirement 3: Frame store and lookups

**User Story:** As a network role, I want to fetch the frames I am told
about and look up mappings over Ethernet from the controller's edge.

#### Acceptance Criteria

1. The fleet layer SHALL serve `GET /v1/frames/<sha256>` for every frame
   a server has been sent a notice for, and `GET /v1/lookup/...` for
   `lookup` VNIs (`fleet-scale-networking` design "Lookups"), over mutual
   TLS that accepts only role certificates of this deployment's servers.
2. The frame store SHALL hold no signing rights and serve only committed,
   signed bytes; it SHALL cache by digest and SHALL bound the bytes and
   requests each server may take per second.
3. The controller SHALL send a `FrameNotice` instead of the frame for
   any frame above the configured inline size when the server reports its
   bulk channel up.
4. Lookup records SHALL be produced from committed network-group state,
   signed (Requirement 2), and SHALL name the stream sequence they are
   current at.
5. The frame store SHALL run in the fleet role or on its own nodes, with
   tests for both and for moving between them.

### Requirement 4: Credentials, edge groups and reusable handles

**User Story:** As the controller, I want to issue what antikythera's
fleet-scale networking needs and to reuse wire handles safely.

#### Acceptance Criteria

1. The controller SHALL answer `credential_request` reports with
   `VtepCredential`s (24-hour default lifetime) and SHALL keep a signed
   revocation list per cell, revoking a server's credentials when it is
   declared lost, drained for decommission or its key rotated.
2. The controller SHALL stop sending `TunnelPeers` for a VNI once every
   VTEP hosting it advertises certified peers, and SHALL resume if any
   stops advertising it.
3. VNIs SHALL be freed only after every server has reported not holding
   the VNI and a quarantine (default 24 hours) has passed; each reuse
   SHALL raise the VNI's incarnation. VPC IDs SHALL stay 64-bit and never
   reused, decoupled from the VNI.
4. MACs SHALL be allocated per VPC from the configured locally
   administered space, unique within the VPC including its gateway MAC,
   and freed with the NIC.
5. The controller SHALL assign edge groups to hosts and prefixes to edge
   groups, build per-group edge-table slices and `EdgeGroup` frames, and
   SHALL move hosts and prefixes between groups in the order antikythera
   specifies (put, wait for `edge_applied`, switch, remove).
6. `ec2-compatible-api` Requirement 4.2 and its design "Identifiers"
   SHALL be amended to match.

### Requirement 5: Idempotency off the catalog

**User Story:** As an operator, I want idempotent creates not to write a
single regional group, so that launches scale with the data layer.

#### Acceptance Criteria

1. ClientToken records SHALL live in groups keyed by a hash of
   `(account, token)`, which split and merge like other groups.
2. A retry with the same token and parameters SHALL return the original
   result, and with other parameters `IdempotentParameterMismatch`, as
   today, across leader changes and front-end failover.
3. The catalog group SHALL be written only for allocator block grants,
   instance-type changes and signing-key rotations, and its write rate
   SHALL be reported.

### Requirement 6: Placement by capacity index

**User Story:** As an operator, I want placement to cost the same at a
thousand servers and at a million.

#### Acceptance Criteria

1. Server groups SHALL publish each server's free capacity to a capacity
   index, bucketed by cell, failure domain, instance family and
   free-capacity band, whenever a committed inventory or reservation
   moves the server between buckets.
2. Placement SHALL pick a bucket that fits the request and its
   constraints, then choose among `k` random servers of the bucket
   (default `k` = 2) by the existing policy, then reserve in the server's
   group as today; a lost race SHALL retry with another sample.
3. Placement constraints (spread across failure domains, local volumes
   pinning a server, the multicast flood-list cap, device functions)
   SHALL be expressible as bucket filters or per-candidate checks.
4. Placement SHALL sustain 2,000 placements a second per cell with a p99
   under 50 ms in the scale harness (Requirement 11).
5. The index SHALL be derived state: rebuilt from server groups after a
   loss, never the source of truth for a reservation.

### Requirement 7: Usage reports on a stream

**User Story:** As an operator, I want usage readings to be durable
without passing through consensus, so that metering does not set the
controller's size.

#### Acceptance Criteria

1. Usage reports (`group_usage`, `nat_usage`, `edge_usage` and later
   usage kinds) SHALL be acknowledged to helm once durable in the usage
   stream, partitioned by server, with the series key and
   `(boot_id, report_seq)` kept so replays deduplicate.
2. A metering worker SHALL compute per-account, per-hour totals from the
   stream with `ec2-compatible-api` Requirement 12's delta rules, commit
   only the totals, and export them as today.
3. State reports (`command_outcome`, `map_applied`, `stream_status`,
   inventory, faults, replica and group status) SHALL still be committed.
4. An inventory whose content equals the committed one (by digest) SHALL
   be acknowledged without a new commit.
5. The usage stream SHALL be Kythira's Kinesis-compatible service where
   it is enabled, and the module's own append-only log otherwise.

### Requirement 8: Brakes on silence-driven actions

**User Story:** As an operator, I want a control-plane failure that makes
many servers look silent to do nothing, so that a fleet-tier outage does
not become a data-plane outage.

#### Acceptance Criteria

1. Every action the controller takes because a server went silent (hold
   failover, instance status changes, khold resync windows, declaring a
   server lost) SHALL pass a per-cell rate limit (default at most 1% of
   the cell's servers per minute).
2. When more than a configured fraction of a cell's servers (default 5%)
   go silent within a window (default 60 s), the controller SHALL enter
   mass silence for that cell: it SHALL suspend those actions, raise an
   alarm, and resume only when the silent fraction falls back below
   half the threshold or an operator resumes it.
3. A planned fleet drain SHALL keep using its reconnection deadline
   (`ec2-compatible-api` design "Planned fleet moves").
4. Mass silence SHALL be reported in describe calls and metrics, with
   the servers whose actions are pending.

### Requirement 9: A placement driver for the module's shards

**User Story:** As an operator, I want the controller's own Raft groups
balanced and split automatically at large scale.

#### Acceptance Criteria

1. The module SHALL run a `shard_placement_driver` (multi-raft design §7)
   per cell, not `no_op_shard_placement_driver`, issuing add, remove,
   leader-transfer, split and merge operators from batched heartbeats.
2. The driver SHALL keep each data node within configured bounds on
   shard count, leader count and load-bucket heat.
3. The driver SHALL be tested at 100,000 shards in the scale harness with
   leader changes and node loss.

### Requirement 10: Backend scale guards

**User Story:** As an operator, I want to know the volume backends' limits
before the fleet reaches them.

#### Acceptance Criteria

1. hold volumes SHALL be capped per cell (configurable, default 50,000),
   with an alarm at 80%; beyond the cap new volumes SHALL go to khold,
   since hold's lease path costs controller traffic per volume.
2. No new volume backend SHALL depend on per-volume heartbeats to the
   controller.
3. The multi-Raft host SHALL be measured at 5,000 khold groups per
   storage node with 20% active, and the result recorded with a CI scale
   row that fails on regression.

### Requirement 11: Scale harness

**User Story:** As a developer, I want to measure the controller at fleet
scale without a fleet.

#### Acceptance Criteria

1. `ec2_sim_fleet` SHALL simulate at least 100,000 helms across a few
   processes over the real link codecs, with configurable VPC size
   distributions, launch rates and failure injection.
2. The harness SHALL report, per run: signatures per second, committed
   bytes per second, frame-store bytes, placements per second and
   latency, catalog writes, usage stream throughput, and time for a
   change to be live everywhere.
3. A recorded baseline SHALL set regression thresholds for each number,
   and the scenarios SHALL include a 4,000-NIC autoscaling VPC, a fleet
   tier restart and mass silence.
