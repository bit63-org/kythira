# Design Document

## Overview

```
                     regional layer (one per zone)
  EC2 API front end ── IAM ── KMS/HSM (root keys, regional network key)
  accounts ── VPC network groups (VPC streams) ── ID block allocator
  cell router (capacity summaries) ── public prefix plan ── root CA
  release controller (waves)
        │ ID blocks, cached reads,      │ VPC streams        │ placement
        │ cell key certificates         │ (regionally signed)│ requests
        ▼                               ▼                    ▼
 ┌─ cell 1 ──────────────────────┐ ┌─ cell 2 ───────┐   ┌─ cell C ───────┐
 │ EC2 data layer: server,       │ │                │ … │                │
 │  instance, volume, index,     │ │                │   │                │
 │  edge, catalog-of-cell groups │ │                │   │                │
 │ fleet tier + frame store      │ │                │   │                │
 │ cell signer (cell key in KMS) │ │                │   │                │
 │ CA intermediates              │ │                │   │                │
 │ PD, khold controller          │ │                │   │                │
 │ edge group(s)                 │ │                │   │                │
 │ boot servers, rack boot caches│ │                │   │                │
 │ chunk cache, OTel collectors  │ │                │   │                │
 │ 10k-25k servers               │ │                │   │                │
 └───────────────────────────────┘ └────────────────┘   └────────────────┘
```

A cell is a complete EC2 controller for its servers, minus the things
that must be the same zone-wide. The regional layer is a set of Kythira
multi-Raft services with low write rates.

## Decisions

- **Cells own servers, instances and volumes; the region owns VPCs.**
  Tenants see VPCs and subnets as zone-wide, and an instance's network
  identity must be reachable from every cell, so VPC state cannot be
  partitioned by cell. Instances and their volumes have no such need, and
  they carry nearly all the write load, so they are what cells partition.
- **One signature per VPC change, regionally.** With VPC streams
  (`ec2-controller-scale` Requirement 1) a VPC change costs one delta and
  one signature, a few thousand a second zone-wide at peak, which a
  regional network key in the HSM can carry. Signing VPC state per cell
  would let one compromised cell rewrite another cell's view of a shared
  VPC; a regional key cannot be used by a cell at all.
- **Delegation by certificate, not by key table.** A server learns its
  cell at provisioning and trusts only root keys. A cell key is accepted
  because a root-signed certificate says it belongs to that cell, so
  adding, rotating or revoking cell keys never touches servers' trust
  configuration. The format is the same compact Ed25519 record style as
  the other frames (no X.509 in hull).
- **Content addressing everywhere bulk data moves.** Host images, machine
  images and snapshots already have (or get) manifests of chunk digests,
  so every cache tier is untrusted and every peer can serve. This is what
  lets a rack cache or a chunk cache sit on an ordinary server.
- **One cell is not a special case.** `cell_id` 0 means "no cells": the
  regional and cell roles run in the same processes, the existing key
  table is the cell key, and nothing waits on a cell router. Splitting
  and merging are operations on a running deployment, not a reinstall.

## Regional and cell components

| Component | Regional | Per cell | Notes |
|---|---|---|---|
| EC2 API front end, IAM, KMS | ✓ | | front ends route cell-scoped calls by resource ID's cell bits |
| Accounts, ClientToken groups | ✓ | | ClientToken groups (`ec2-controller-scale` Req 5) record the chosen cell |
| VPC network groups, VPC streams | ✓ | | NIC changes arrive from cells |
| ID blocks | allocator | cache | IDs encode nothing about the cell; a lookup group maps ID ranges to cells |
| Cell router | ✓ | summaries | |
| Public prefix plan, edge-group assignment | ✓ | edge groups | |
| Root keys, root CA, regional network key | ✓ | | HSM, tight key policy |
| Server, instance, volume, index, edge groups | | ✓ | |
| Fleet tier, frame store, usage stream | | ✓ | regional VPC frames fetched once per cell, then served locally |
| Signer, CA intermediates, PD, khold controller | | ✓ | |
| Boot servers, rack boot caches, chunk cache, OTel collectors | | ✓ | |

**Routing calls to cells.** Resource IDs stay opaque 64-bit counters
(`ec2-compatible-api` "Identifiers"). ID blocks are granted to cells, and
a regional `id_range → cell` map (small: one row per block) lets a front
end send `DescribeInstances i-…` or `TerminateInstances` to the right
cell. Describe calls without IDs fan out to cells in parallel and merge.

## Cell router

Cells push summaries every 10 s:

```
CellSummary { cell_id, as_of, per (instance_family, failure_domain):
              free_whole_cores_by_band[], free_pages, servers_with_room,
              reserved_rate }
```

`RunInstances` asks the router for an ordered list of candidate cells:
filter by the subnet (every cell can host every subnet; a subnet is
zone-wide), placement-group constraints and family, score by free
capacity weighted against recent reservations (so two front ends do not
pile onto the same cell), and try the first. The cell answers placed or
"no room", and the router tries the next. The chosen cell is written to
the ClientToken record, so a retry goes back to it.

## VPCs across cells

```
cell A NIC attach ──► A's server group commits the attachment
                 └──► tier-1 append to VPC network group n/<vni> (regional):
                      record "NIC binding, owner_vtep" → pending → cut delta
                      → regional network key signs → commit
VPC network group ──► per cell hosting the VPC: one reference per cell
cell A, B fleet   ──► fetch the delta once per cell, store in the cell's
                      frame store, reference it in each hosting server's outbox
```

Each cell's catalog keeps "which of my servers host VNI V", so the
regional group fans out per cell (tens) instead of per server
(thousands). A cell that is down misses deltas and catches up from a
snapshot when it returns; other cells are unaffected. A cell's NICs stay
in the stream while the cell is down: removing them would break their
traffic the moment the cell returned, and they are still where the
mapping says.

## Keys and certificates

```
CellKeyCertificate {          // signed by a root key; antikythera src/proto/
  magic 'AKCK', version (1), root_key_id u16, cell_id u32,
  cell_key_id u16, purpose u8 (1 commands+per-server frames, 2 regional network),
  rsvd [5], public_key [32], not_before u64, not_after u64, serial u64,
  signature [64]
}
```

- hull's key table becomes "root keys" plus "certified keys": hull
  accepts a slot signed by `key_id` K if K is a root key (one-cell
  deployments) or a certified key whose certificate names hull's cell
  and is valid. helm pushes certificates to hull with a mailbox command
  carrying the certificate (antikythera task), and to roles over OarLink.
- The regional network key has purpose 2 and no cell; every server
  accepts it for VPC streams and edge prefix plans only.
- Revocation: a root-signed `CellKeyRevocations` list, small, pushed to
  every server; a revoked cell key's commands are refused at once.
- Rotation: certify the new key, push certificates, switch the cell
  signer, wait for every server's `last_command_seq` under the new key,
  retire the old certificate.
- CA: the existing Kythira CA (`certificate-authority`) runs the root
  offline-ish (HSM, issuing only intermediates) and an intermediate per
  cell and purpose. Leaf lifetimes as Requirement 6.3; storage role keys
  rotate every 30 days by issuing the CSR for a fresh key.

## Edge groups per cell

Each cell has at least one edge group; large cells have several, with
hosts assigned by rack. The regional prefix plan assigns prefixes to
edge groups and is distributed as a regionally signed record. EIPs are
allocated from the instance's cell's prefixes; moving one across cells
uses antikythera's forward or re-home mode.

## Host boot

```
seed (outside the fleet) ──► cell control plane nodes + cell boot servers
cell boot servers ──► rack boot caches ──► hosts
                    (chunks by digest)   (DHCP relay → proxyDHCP, iPXE/UEFI HTTP boot)
```

- **Image format.** A host image is a UKI plus an initramfs root, packed
  with `ak-image-pack` into `AKIMAGE` chunks (1 MiB) with a manifest. The
  release key signs the manifest digest in a small `HostRelease` record
  (release ID, manifest digest, minimum firmware, rollout channel).
- **Boot path.** The host's firmware gets a boot loader from its rack's
  DHCP relay and proxyDHCP; the loader fetches the `HostRelease` for its
  channel, verifies it, then fetches chunks from the rack cache
  (falling back to the cell boot servers), verifying each digest, and
  measures the result into the TPM for enrollment.
- **Rack caches** run on a few servers per rack (a small service in the
  storage hosts' or a designated host's image, or on switches that can
  run containers): read-through to the cell boot servers, coalescing
  misses, LRU on a RAM or disk budget.
- **Math for the 15-minute target.** 25,000 hosts × 0.5 GB is 12.5 TB per
  cell, but with ~625 racks of 40 the cell boot servers send each chunk
  once per rack: 625 × 0.5 GB = 312 GB, about 4 minutes at 10 Gbit/s
  aggregate. Each rack cache then serves 20 GB to its rack at 25 Gbit/s
  in about 7 s. DHCP and enrollment dominate, which is why both are per
  cell and measured.

## Chunk cache for machine images and snapshots

A cell service speaking the same Range-GET subset oar-blk already uses
(`S3ObjectStore`), keyed by `(manifest name, chunk index)` and validated
by digest at the reader:

- Miss coalescing: one object-store fetch per chunk per cell, however
  many servers ask.
- Popular images: a `popular` tag on an image makes the regional layer
  ask every cell to pre-warm its first N MiB (boot working set) or all of
  it.
- Snapshot hydration reads through the same cache, so many volumes
  restored from one snapshot cost one fetch per chunk per cell.
- oar-blk takes a list of cache endpoints ahead of the object store and
  falls back on error or timeout.

## Telemetry

- Kythira's `otlp_http_batch_exporter` gains a protobuf encoder (OTLP's
  proto definitions are vendored as generated code; kythira already
  builds protobuf for its gRPC transport), selected per deployment.
- helm and boards keep counters and fixed-bucket histograms and export
  per interval (default 30 s) to the cell's collectors; per-event logs
  go to a local ring and are exported above `warning` by default, in full
  when an operator enables a server or role for up to an hour.
- Collectors aggregate across servers and forward per-cell rollups
  regionally; per-series budgets are enforced at the exporter.
- Billing never rides telemetry (`ec2-controller-scale` Requirement 7).

## Staged rollouts

A regional release controller runs waves:

| Wave | Scope | Bake |
|---|---|---|
| 0 | canary servers (1%) of the canary cell | 1 h |
| 1 | the canary cell | 4 h |
| 2 | 10% of cells | 12 h |
| 3+ | doubling sets of cells | 12 h each |

The same machinery carries control-plane builds, host images and frame
versions. A wave stops when any of its cells' alarms fire. Frame and
record versions are switched on per server: the cell sends the new
version to canaries, waits for their `stream_status` to show it applied
without refusals, then widens.

## Host live update

hull (antikythera task) adds `LIVE_UPDATE`: pause every VM (Cloud
Hypervisor pause), write VM configurations, device assignments and
memory locations to a handover area preserved across kexec (guest memory
stays in place in its 1 GiB pages), kexec into the new verified UKI,
whose hull reads the handover and resumes the VMs. VFIO functions stay
bound across the handover; boards keep running, since they are separate
machines. The pause target is under 2 s; the controller drives it as a
workflow with the rollout, falling back to drain and scheduled events
when hull refuses.

## Cell lifecycle

- **Create**: register the cell (ID, ID blocks, key certificate, CA
  intermediates, prefix assignment), start its control plane from the
  seed, then enroll servers into it.
- **Move a server**: drain it (instances stopped or migrated, volumes
  moved off by live moves), decommission from the old cell, re-enroll
  into the new one.
- **Split** (one cell into two): choose the servers for the new cell
  (whole racks); create the new cell; for each chosen server, move its
  server group rows, the instance and volume groups of its instances
  (instances whose volumes span both halves are moved with their
  volumes, and volumes are live-moved to the right side first), its edge
  assignment, then switch its trust to the new cell key with a
  certificate push; the old cell stops managing it only after the new
  cell has its first inventory.
- **Merge**: the reverse, into the surviving cell.
- **Retire**: drain every server, then delete the cell's records.

## Testing strategy

- Unit and property: cell router scoring, ID-range map, key certificate
  chains (hull's and roles' acceptance rules), split/merge row moves
  preserving every invariant of `ec2-compatible-api`'s property tests.
- `ec2_sim_fleet` multi-cell: several cells with the regional layer,
  cross-cell VPCs, a cell control plane killed (other cells unaffected),
  the regional layer killed (cells keep running and placing in-cell).
- Migration both ways: one cell → two → one with instances running;
  single key table → delegated keys → single.
- Boot storm: simulated hosts (containers running the boot loader logic)
  against real boot servers and rack caches; reduced scale in CI, a full
  25,000-host run on demand.
- Chunk cache: hot-image launch burst with and without the cache, object
  store request counts compared.
- Harbor (tikhov, Clark's go): two small cells of nested servers, a
  cross-cell VPC, live update of one host with a running guest.

## Open questions

1. Should cell IDs be visible to tenants (like AWS's cell-based
   availability, hidden) or only to operators? The design keeps them
   operator-only.
2. Rack caches on storage hosts or on designated diskless hosts? The
   provisioning specs' storage/diskless split decides.
3. Should a VPC's NIC changes from a cell go to the regional group
   synchronously (simpler) or through a per-cell queue (survives a
   regional outage for longer)? The design uses tier-1 appends; a queue
   is the fallback if the measurements say so.
