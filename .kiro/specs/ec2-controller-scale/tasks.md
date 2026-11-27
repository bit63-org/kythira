# Implementation Plan

Each task is one PR unless noted. Tasks marked **(antikythera)** land in
`bit63-org/antikythera`; the rest land here. This spec builds on the EC2
module (`ec2-compatible-api`), so its tasks start once that module's
data layer, fleet layer and network group exist (its tasks 1-9 and the
VPC tasks). Antikythera's `fleet-scale-networking` defines the frames;
a task here that needs one of its codecs consumes it through the overlay
port once that spec's codec task has landed.

Order: 1 first (the harness measures everything after it); 2-4 for
streams; 5-6 for credentials and handles; 7-9 for the launch path;
10-11 for reports and silence; 12-13 for shards and backends; 14 for
edge groups; 15 closes.

## Tasks

- [ ] 1. Scale harness: multi-process `ec2_sim_fleet` (25,000 helms per
  process, model network role), YAML scenarios, JSON results, a CI scale
  job comparing with a stored baseline; first baseline recorded on the
  current design (per-server frames). _Requirements: 11.1-11.3_

- [ ] 2. VPC streams in the network group: `vpc_stream` state, record
  generation from committed changes, cutting with window, size and
  barrier, single signature per delta, snapshot building, per-VPC
  frames/stream mode; property tests for order across leader changes.
  _Requirements: 1.1, 1.3, 1.5, 1.6_

- [ ] 3. Stream references in outboxes and the frame store: batched
  cross-group reference appends, fleet nodes resolving references
  (inline or `FrameNotice`), the frame store service (frames by digest,
  per-server buckets), co-located and split with a migration test both
  ways; "live everywhere" waits from `stream_status`.
  _Requirements: 1.2, 1.4, 3.1-3.3, 3.5_

- [ ] 4. Batch signing: Merkle batches on data-node leaders (4,096 frames
  or 20 ms), trailers on `InstanceMetadata`, `VolumeLayout`,
  `VtepCredential` and `MapEntry`; and **(antikythera)** the batch
  verifier in `src/proto/` with vectors, accepted beside single
  signatures. _Requirements: 2.1-2.4_

- [ ] 5. Credentials: `credential_request` handling, per-cell serials,
  revocation list record and its triggers (lost, decommission, rotation),
  `TunnelPeers` retirement per VNI and resumption; tests with the
  harness's model role. _Requirements: 4.1, 4.2_

- [ ] 6. Reusable VNIs and per-VPC MACs: quarantine records cleared by
  inventories, incarnations, MAC allocation moved to the network group;
  `ec2-compatible-api` Requirement 4.2 and design "Identifiers" amended.
  _Requirements: 4.3, 4.4, 4.6_

- [ ] 7. Lookups: `MapEntry` building from committed bindings, negative
  answers, cache invalidation by delta, `lookup` VNI selection policy
  (by NIC count, default above 4,096) with interest-set records.
  _Requirements: 3.4_

- [ ] 8. ClientToken groups: `t/` group kind, tier-1 write with the
  workflow record, retention sweep, migration of existing tokens out of
  the catalog; catalog write-rate metric. _Requirements: 5.1-5.3_

- [ ] 9. Capacity index and sampled placement: bucket updates from server
  groups, index groups per cell and family, bucket walk with constraint
  filters, `k`-sample choice, retry and widen, rebuild after loss;
  property test against a full scan; 2,000 placements/s in the harness.
  _Requirements: 6.1-6.5_

- [ ] 10. Usage stream: usage reports acknowledged after the stream
  write, metering worker computing hourly totals, inventory digest
  short-circuit; the Kinesis-backed and own-log variants; a migration
  test from Raft-committed usage to the stream and back.
  _Requirements: 7.1-7.5_

- [ ] 11. Silence tracker: per-cell windows, tokens for every
  silence-driven action, mass silence with alarm and resume, describe
  and metrics; docker-chaos case killing the fleet tier.
  _Requirements: 8.1-8.4_

- [ ] 12. Placement driver: `kythira_pd` per cell with batched
  heartbeats, count and heat balancing, split policies; 100,000 shards in
  the harness with leader changes and node loss. _Requirements: 9.1-9.3_

- [ ] 13. Backend guards: the hold cap with alarm and khold overflow;
  `khold_scale_bench` at 5,000 groups per node with its CI row.
  _Requirements: 10.1-10.3_

- [ ] 14. Edge groups: `e/` group kind, host and prefix assignment,
  per-group edge-table streams, `EdgeGroup` frames, moving hosts and
  prefixes in antikythera's order; harness scenario with two groups.
  _Requirements: 4.5_

- [ ] 15. Close-out: harness results for every scenario recorded in this
  design with the baseline from task 1 beside them; `doc/TODO.md` row
  updated. _Requirements: 11.2, 11.3_
