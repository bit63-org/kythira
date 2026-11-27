# Requirements Document

## Introduction

Every scaling wall in the 2026-11-27 analysis
(`/mnt/project-files/audits/antikythera-scaling-limits-2026-11-27.md`)
gets worse with one number: how many servers one control plane, one key,
one table or one boot server has to cover. Today that number is the
whole region, because the region has one zone and the zone has one of
everything: one controller deployment, one signing key table, one storage
CA, one edge table, one catalog group, one seed that boots every host.
That is also the blast radius: a bad deploy, a stolen key or a stalled
group reaches every host at once.

This spec splits an availability zone into **cells**: independent slices
of roughly 10,000-25,000 servers, each with its own controller data layer,
fleet tier, delegated signing key, CA intermediates, edge group, boot and
image caches and telemetry collectors. A thin regional layer keeps what
is truly regional (accounts, IAM, KMS, VPC objects, ID blocks, the public
prefix plan, the cell router) and stays off the data path.

It also covers the fleet operations that only become problems at cell
scale: netbooting and rolling out host images to tens of thousands of
servers, serving popular machine images and snapshots without hot
objects, telemetry volume, staged deploys, and patching hosts without
stopping guests.

A deployment with one cell is the default and must stay a full, tested
configuration: Clark's home lab and every CI test run that way. Moving
from one cell to several and back is supported and tested, following the
independent-layers rule.

Companion specs: `ec2-controller-scale` (this repository) for what each
cell's controller does at scale, antikythera `fleet-scale-networking` for
the network frames, credentials and edge groups, and the provisioning
specs (kythira `metal-host-lifecycle`, antikythera
`server-provisioning`, drafts) for host enrollment and power, whose boot
path this spec scales out.

### What this spec does not cover

- Multiple availability zones per region. Cells are inside one zone; a
  later zones spec can reuse the regional/cell split.
- The network role, helm and hull formats beyond the key and certificate
  chains named here (antikythera specs own those).
- Cross-region anything.

## Glossary

- **Cell** — a set of servers plus the control plane that alone manages
  them; identified by a 32-bit `cell_id` (0 means "no cells").
- **Regional layer** — the services shared by every cell of a zone.
- **Cell router** — the regional component that maps a request (account,
  subnet, instance type) to a cell.
- **Cell key** — a cell's Ed25519 command and frame signing key, held in
  KMS or the HSM, certified by a regional root key for that cell only.
- **Root key** — a regional Ed25519 key that signs cell key certificates
  and regional frames, kept offline or in the HSM with tight policy.
- **Boot cache** — a per-cell or per-rack service that serves host image
  chunks by content digest.
- **Chunk cache** — a per-cell read-through cache of machine image and
  snapshot chunks keyed by digest.
- **Wave** — one step of a staged rollout: a set of cells (or a fraction
  of one) that receives a change before the next.

## Requirements

### Requirement 1: Cells as a deployment unit

**User Story:** As an operator, I want to grow a zone by adding cells,
so that no control-plane component's load grows with the zone.

#### Acceptance Criteria

1. Every server SHALL belong to exactly one cell, recorded in its server
   record and in its provisioning identity, and SHALL be managed only by
   its cell's control plane.
2. A cell SHALL run its own EC2 data layer (server, instance, volume,
   capacity-index and edge groups), fleet tier, frame store, placement
   driver, khold controller, signer, CA intermediates, boot and chunk
   caches and telemetry collectors.
3. An instance's local and network volumes SHALL be placed in the
   instance's cell, so volume placement, khold rebuilds and live moves
   stay inside one cell.
4. Cell size SHALL be operator-configured, with defaults sized so that
   no limit in `ec2-controller-scale` or `fleet-scale-networking` is
   reached inside one cell (target 10,000-25,000 servers).
5. A one-cell deployment SHALL need no regional components beyond what
   runs today, and SHALL be the default.

### Requirement 2: A thin regional layer

**User Story:** As an operator, I want the regional layer small and off
the data path, so that a regional failure stops only regional operations.

#### Acceptance Criteria

1. The regional layer SHALL hold only: the EC2 API front end, IAM, KMS,
   accounts, VPC objects (blocks, subnets, route tables, security groups,
   gateways), ID block allocation, the public prefix plan, the cell
   router, root keys and the root CA.
2. Cells SHALL receive ID blocks in advance and cache what they need from
   the regional layer, so that running instances, network and storage
   traffic, failover and cell-local operations already accepted continue
   when the regional layer is unavailable.
3. Requests that need the regional layer (new VPC objects, cross-cell
   placement decisions) SHALL fail with retryable errors while it is
   unavailable, never block cell work.
4. Every regional component SHALL be a Kythira multi-Raft service with
   the same layer split options as the cells' components.

### Requirement 3: Cell router and two-level placement

**User Story:** As a tenant, I want launches to land where there is room
without knowing cells exist.

#### Acceptance Criteria

1. Each cell SHALL publish a capacity summary (free capacity per instance
   family and failure domain, from its capacity index) to the cell router
   at least every 10 s.
2. `RunInstances` SHALL pick a cell from the summaries that fits the
   request and its constraints (subnet, placement group, spread, dedicated
   capacity), then place inside the cell with `ec2-controller-scale`
   Requirement 6; a cell that cannot place SHALL hand the request back and
   the router SHALL try the next.
3. A placement group with the `cluster` strategy SHALL stay in one cell;
   `spread` and `partition` MAY span cells.
4. The router's choice SHALL be idempotent with the request's
   ClientToken, so a retry goes to the same cell.

### Requirement 4: VPCs across cells

**User Story:** As a tenant, I want one VPC to span as many cells as my
instances need, with no difference in behaviour.

#### Acceptance Criteria

1. A VPC's network state SHALL be produced once, regionally, as its VPC
   stream (antikythera `fleet-scale-networking` Requirement 5), signed
   with a regional network key, and consumed by every cell hosting the
   VPC.
2. Each cell SHALL report its NIC changes for a VPC to the VPC's regional
   network group, which orders them into the stream; a cell SHALL deliver
   the stream to its servers through its own fleet tier and frame store.
3. VPCs with NICs in many cells SHALL be eligible for `lookup` mode, so a
   server holds only the entries it needs.
4. A cell failure SHALL NOT change another cell's view of a VPC except
   for the failed cell's NICs, whose entries remain until the controller
   removes them.

### Requirement 5: Delegated cell keys

**User Story:** As an operator, I want a stolen or misused key to command
one cell at most.

#### Acceptance Criteria

1. Each cell SHALL sign commands and per-server frames with its own cell
   key, certified by a regional root key in a `CellKeyCertificate` naming
   the cell ID, the key ID, the public key and a validity window.
2. hull, helm and the network and storage roles SHALL trust root keys
   from their provisioned configuration and SHALL accept a cell key only
   with a valid certificate for their own cell.
3. Regional frames (VPC streams, edge prefix plans) SHALL be signed by a
   regional network key that is itself certified by a root key, so no
   cell key can forge another cell's network view.
4. Cell keys SHALL rotate without downtime (new certificate first, then
   switch, then retire), and the root SHALL be able to revoke a cell key
   with a signed list every server accepts.
5. The existing single key table SHALL keep working for a one-cell
   deployment, and a deployment SHALL be able to move to delegated keys
   and back with servers running.

### Requirement 6: Certificate hierarchy

**User Story:** As an operator, I want each cell to issue its own
certificates, so that the CA's blast radius and load are per cell.

#### Acceptance Criteria

1. A regional root CA SHALL issue per-cell intermediates for server mTLS,
   storage and network role certificates, and VTEP credentials.
2. Certificates SHALL name the cell; a verifier in one cell SHALL refuse
   leaf certificates from another cell's intermediate where only
   same-cell peers are expected (storage roles), and accept them where
   cross-cell peers are expected (VTEPs).
3. Leaf lifetimes SHALL be short enough that revocation lists stay small
   (defaults: server mTLS 7 days, role certificates 3 days, VTEP
   credentials 24 hours), with renewal at a third of the lifetime left.
4. Storage role keys SHALL rotate on renewal at a configured interval
   (default every 30 days), closing the "key never changes on renewal"
   gap in block-volume-service.

### Requirement 7: Edge groups per cell

**User Story:** As an operator, I want each cell's internet edge sized to
the cell.

#### Acceptance Criteria

1. Each cell SHALL have at least one edge group (antikythera
   `fleet-scale-networking` Requirement 8) serving its hosts, and the
   regional prefix plan SHALL assign public prefixes to edge groups.
2. Elastic IPs SHALL be allocated from the prefixes of the instance's
   cell by default, and moving one to another cell SHALL use forward or
   re-home mode as the pool is configured.

### Requirement 8: Host boot at cell scale

**User Story:** As an operator, I want a whole cell to boot after a power
event in minutes, and the seed to bootstrap only cell control planes.

#### Acceptance Criteria

1. Host images SHALL be content-addressed: a manifest of SHA-256 chunk
   digests in antikythera's `AKIMAGE` format, signed by the release key,
   so any cache or peer can serve chunks without being trusted.
2. Each cell SHALL run boot servers (DHCP proxy or relay, iPXE/UEFI HTTP
   boot) that serve its hosts, and each rack SHALL have a boot cache (a
   service on one or more of its servers, or the top-of-rack switch where
   it can run one) that fetches each chunk once and serves the rack.
3. The seed control plane SHALL boot cell control planes and boot servers
   only; hosts SHALL boot from their cell.
4. A cell of 25,000 hosts SHALL be able to cold boot from its boot
   servers in under 15 minutes in the boot-storm test (Requirement 13),
   with DHCP, image transfer and enrollment each measured.
5. Enrollment and certificate issuance SHALL be served by the cell and
   SHALL sustain the cell's whole population within that window.

### Requirement 9: Machine image and snapshot caching

**User Story:** As an operator, I want a popular machine image launched
thousands of times a minute not to melt the object store.

#### Acceptance Criteria

1. Each cell SHALL run a chunk cache that oar-blk's `LazyImageBackend`
   and snapshot hydration read through, keyed by chunk digest from the
   image or snapshot manifest, so the cache need not be trusted.
2. The cache SHALL fetch a chunk from the object store at most once per
   cell while it is resident, coalescing concurrent misses.
3. Encrypted images and snapshots SHALL be cached as stored
   (ciphertext); the cache SHALL hold no keys.
4. An image or snapshot marked popular SHALL be pre-warmed into every
   cell's cache.
5. A server SHALL fall back to the object store when its cell's cache is
   unavailable.

### Requirement 10: Telemetry per cell

**User Story:** As an operator, I want metrics and logs from every server
without a single collector or exporter becoming the bottleneck.

#### Acceptance Criteria

1. Each cell SHALL run OpenTelemetry collectors that its servers and
   control-plane nodes export to; the collectors SHALL forward rollups
   regionally.
2. Kythira's OTLP exporter SHALL gain OTLP/HTTP protobuf encoding beside
   JSON, and fleet services SHALL use it.
3. helm and the boards SHALL pre-aggregate counters and histograms per
   export interval, never exporting per event.
4. Each role SHALL have a series budget; series beyond it SHALL be
   dropped and counted, not exported.
5. Logs SHALL be exported above a configured level by default and in
   full on demand for a server or role for a bounded time.

### Requirement 11: Staged rollouts and canaries

**User Story:** As an operator, I want a bad release to stop at the first
cell it breaks.

#### Acceptance Criteria

1. Control-plane releases, host images and frame format changes SHALL
   roll out in waves: a canary fraction of one cell, then one cell, then
   growing sets of cells, with a bake time per wave.
2. Each wave SHALL stop automatically when its cells' alarms fire
   (error rates, refused frames, stream gaps, silence, launch failures),
   and the rollout SHALL be resumable or reversible by the operator.
3. A new frame or record version SHALL be sent to canary servers first,
   and to the rest only after the canaries report applying it without
   refusals.
4. At no time SHALL more than one wave's cells run an unbaked release.

### Requirement 12: Patching hosts without stopping guests

**User Story:** As a tenant, I want routine host updates not to stop my
instances.

#### Acceptance Criteria

1. hull SHALL support a live update: pause the guests, hand their VM
   state and device assignments to a new kernel and hull through kexec,
   and resume them, within a pause budget (target under 2 s).
2. Where live update is not possible (firmware, board replacement), the
   controller SHALL issue EC2 scheduled-event notices and drain the
   server, as `ec2-compatible-api` already allows.
3. A host image rollout SHALL use live update by default and report per
   server which path it took and the pause measured.

### Requirement 13: Cell lifecycle and migration

**User Story:** As an operator, I want to create, grow, split, merge and
retire cells while tenants keep running.

#### Acceptance Criteria

1. An operator SHALL be able to create a cell, move servers into it (a
   drained server re-enrolls into the new cell), and retire a cell by
   draining it.
2. Splitting a one-cell deployment into two cells, and merging two cells
   back into one, SHALL work with instances running, moving server
   records, instance and volume groups, edge-group assignments and keys
   in a defined order, and SHALL be tested both ways.
3. A cell failure (its whole control plane down) SHALL leave other cells'
   control planes and every data plane running, and SHALL be tested.
4. A multi-cell simulation (`ec2_sim_fleet` with several cells) and a
   boot-storm test with simulated hosts against real boot servers and
   caches SHALL run in CI at reduced scale, and at full cell scale on
   demand.
