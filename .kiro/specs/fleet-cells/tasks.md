# Implementation Plan

Each task is one PR unless noted. Tasks marked **(antikythera)** land in
`bit63-org/antikythera`; the rest land here. Cells build on the EC2
module (`ec2-compatible-api`) and on `ec2-controller-scale` (streams,
capacity index, silence tracker); antikythera's `fleet-scale-networking`
provides the network side. The boot tasks follow the provisioning specs
(kythira `metal-host-lifecycle`, antikythera `server-provisioning`) once
they land.

Order: 1-2 first (the cell model and its one-cell default); 3-4 for keys
and certificates; 5-7 for routing, placement and VPCs; 8 for edge; 9-10
for boot; 11 for image caching; 12 for telemetry; 13 for rollouts; 14-15
for live update; 16-17 for lifecycle; 18 closes.

## Tasks

- [ ] 1. Cell model: `cell_id` in server records and provisioning
  identity, cell-scoped group kinds, the one-cell default (`cell_id` 0)
  with regional and cell roles in the same processes; no behaviour change
  for existing deployments. _Requirements: 1.1, 1.2, 1.5_

- [ ] 2. Regional layer split: regional and cell role sets for the EC2
  module (independent-layers style, `KYTHIRA_EC2_ROLES`), ID blocks
  granted to cells, the `id_range → cell` map, front-end routing by ID and
  parallel describe fan-out; cells keep running with the regional layer
  down. _Requirements: 2.1-2.4_

- [ ] 3. **(antikythera)** `CellKeyCertificate` and `CellKeyRevocations`
  codecs with vectors and fuzz targets; hull's key table with root and
  certified keys and the per-cell acceptance rule; helm pushing
  certificates to hull and roles. _Requirements: 5.1, 5.2, 5.4_

- [ ] 4. Cell signers and CA hierarchy: per-cell signer with a
  certified KMS key, the regional network key, rotation and revocation
  workflows; root and per-cell intermediates in the Kythira CA, leaf
  lifetimes, storage-role key rotation; migration from the single key
  table to delegated keys and back with servers running.
  _Requirements: 5.3-5.5, 6.1-6.4_

- [ ] 5. Cell router: `CellSummary` publishing, scoring, ordered
  candidates with hand-back, ClientToken binding, placement-group rules.
  _Requirements: 3.1-3.4_

- [ ] 6. Two-level placement: router then the cell's capacity index; an
  instance's volumes placed in its cell. _Requirements: 1.3, 3.2_

- [ ] 7. VPCs across cells: NIC changes from cells to the regional
  network group, per-cell fan-out of stream references, each cell's frame
  store fetching once, `lookup` eligibility for many-cell VPCs; a test
  with one cell down and its NICs kept. _Requirements: 4.1-4.4_

- [ ] 8. Edge groups per cell: regional prefix plan record, per-cell edge
  groups, EIP allocation from the cell's prefixes, cross-cell moves.
  _Requirements: 7.1, 7.2_

- [ ] 9. **(antikythera)** Host images as `AKIMAGE`: `ak-image-pack` for
  UKI plus root, the signed `HostRelease` record, a boot loader that
  verifies the release and every chunk and measures into the TPM.
  _Requirements: 8.1_

- [ ] 10. Cell boot servers and rack boot caches: DHCP relay and
  proxyDHCP config, HTTP boot service, read-through rack caches with miss
  coalescing; seed boots only cell control planes; boot-storm harness and
  the 15-minute measurement. _Requirements: 8.2-8.5, 13.4_

- [ ] 11. Chunk cache: per-cell Range-GET cache keyed by manifest and
  chunk, miss coalescing, popular-image pre-warm, snapshot hydration
  through it; **(antikythera)** oar-blk cache endpoints with fallback.
  _Requirements: 9.1-9.5_

- [ ] 12. Telemetry: OTLP protobuf encoding in the exporter, per-cell
  collectors and regional rollups, series budgets, on-demand full logs;
  **(antikythera)** helm and board pre-aggregation.
  _Requirements: 10.1-10.5_

- [ ] 13. Release controller: waves with bake times and alarm stops,
  resume and reverse; per-server frame version canaries.
  _Requirements: 11.1-11.4_

- [ ] 14. **(antikythera)** hull `LIVE_UPDATE`: pause, handover area,
  kexec, resume, VFIO kept bound; pause measured. _Requirements: 12.1_
  (tikhov for the nested-KVM test)

- [ ] 15. Live update in rollouts: controller workflow, fallback to drain
  and scheduled events, per-server path and pause reporting.
  _Requirements: 12.2, 12.3_

- [ ] 16. Cell lifecycle: create, move a server, retire; split and merge
  with instances running, tested both ways in the multi-cell
  `ec2_sim_fleet` and docker-chaos. _Requirements: 13.1, 13.2_

- [ ] 17. Isolation tests: a cell control plane killed with other cells
  and every data plane checked; the regional layer killed with cells
  placing in-cell. _Requirements: 13.3_

- [ ] 18. Harbor end to end (tikhov, Clark's go): two nested cells, a
  cross-cell VPC, a live update with a running guest; results recorded.
  _Requirements: 13.4_
