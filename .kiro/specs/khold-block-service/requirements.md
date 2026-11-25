# Requirements Document

## Introduction

Antikythera's network volumes (the EBS counterpart, antikythera
`.kiro/specs/block-volume-service/`, "block-volume" below) are served
today by **hold**: one primary hold role per volume orders every write
and copies it to one or more secondaries, and a separate controller
(`ak_hold_master`, later the volume master of
`.kiro/specs/ec2-compatible-api/`) promotes primaries, raises epochs and
grants read leases. The guest's disk is a virtio-blk function served by
**oar-blk** on the compute server, whose initiator encrypts every block
before it leaves the server and speaks the hold wire protocol to the
primary.

This spec adds **khold**, a Kythira service that stores the same network
volumes in Kythira Raft groups. It speaks the protocol oar-blk speaks,
extended to a version 2, and it is driven by the same controller. The
differences that matter:

- **Leader election inside the group.** A failed leader is replaced by
  Raft in about a second, without a controller round trip and without
  waiting out a controller-granted lease. The controller still owns
  membership; Raft only picks which member leads.
- **Volumes are striped.** A volume is spread over several Raft groups,
  each placed on its own servers, so one leader's disk, CPU and network
  port do not cap a volume, noisy neighbours average out, and a lost
  server is rebuilt many-to-many.
- **Thin provisioning.** Space is allocated when it is written and freed
  on discard. The controller reserves the provisioned size by default and
  can overcommit when the operator turns it on.
- **Disk errors fail over.** hold today never fails over a primary whose
  disk returns EIO (`/mnt/project-files/explainers/antikythera-block-serving-2026-11-25.md`,
  "Gaps worth tracking" 1). khold treats a media error as a failure of
  that replica from the first release.

khold runs **beside hold**, chosen per volume class, with live moves
between the two in both directions while a volume is attached. **hold is
retired once khold reaches feature and testing parity with it**
(Requirement 19). It follows Clark's decisions of 2026-11-25 in the
"Spec the khold block server" thread:

1. A new service named khold, beside hold, with the expectation that hold
   is retired at parity.
2. A hold wire protocol version 2, spoken by oar-blk next to version 1.
3. The controller owns membership, attachments, generations, keys and
   QoS; Raft only chooses the leader among the members it was given.
4. The `general` class keeps two data replicas plus a log-only witness;
   the `provisioned` class has three data replicas.
5. Volumes are thin-provisioned, with optional overcommit.
6. The design is bandwidth-agnostic from 1 GbE to 200 GbE, measured on
   1 GbE and on 25 GbE hardware Clark will have.

It also follows Clark's rules of 2026-11-17 for new Kythira services:

- **Independent layers** (`.kiro/specs/kinesis-independent-layers/`):
  each layer can run as its own process or cluster, co-located operation
  is the default and is never required, and a running deployment can
  migrate from co-located to independent and back.
- **Migration tests**: tasks that test every migration path, both ways.

### Layers

1. **Gateway**: terminates initiator sessions: TLS, `HELLO`, attachment
   and generation checks, per-attachment QoS, splitting requests at
   stripe boundaries, hold wire version 1 translation, and forwarding to
   group leaders.
2. **Data**: the multi-Raft host running the stripe groups, the block
   store beside each group's log, per-group fencing and QoS, scrub, and
   rebuild.

The volume controller (placement, layouts, reservations, replacement,
moves, migrations between backends, scrub scheduling) is a library this
spec ships, `khold_controller`. It runs inside the EC2 module's data
layer, as `ak_hold_master` does for hold, and inside a test controller.
It is not a khold layer.

### What this spec does not cover

- Snapshots, restore, clones and hydration from images are **phase 2**
  of this spec (Requirement 17). hold has not built them either
  (block-volume tasks 21-23).
- RDMA (NVMe-oF over RoCEv2) is a later option (design "Later options").
  Phase 1 runs TLS over TCP.
- Serving hosts outside antikythera (NBD, NVMe/TCP, iSCSI front ends).
- The EC2 API mapping. It is unchanged: `ec2-compatible-api`
  Requirement 9 maps EBS calls to volume classes, and the class decides
  the backend.
- Integrity against a malicious storage node (per-block MACs and
  rollback detection), deferred as in block-volume design "Integrity".
- Retiring hold itself. That is an antikythera change, made after
  Requirement 19 is met.

## Glossary

The block-volume glossary and the Kinesis independent-layers glossary
apply. In addition:

- **khold**: this service. **hold**: antikythera's existing block service.
- **Backend**: what stores a network volume: `hold` or `khold`.
- **Stripe group**: one Raft group that stores one stripe column of one
  volume.
- **Stripe unit** (`SU`): the run of consecutive bytes of the volume that
  map to one stripe group before the next unit maps to the next group.
- **Stripe width** (`G`): the number of stripe groups of a volume.
- **Data replica**: a voting member of a stripe group that stores block
  data.
- **Witness**: a voting member of a stripe group that stores the log's
  entry descriptors (LBAs, block counts, CRCs, terms) but no block data,
  and can never lead.
- **Learner**: a non-voting member catching up before promotion.
- **Lagging**: a data replica that missed the member deadline and that
  the leader has recorded, through a committed log entry, as not required
  for commit until it catches up.
- **Volume layout**: the controller's signed, full description of one
  khold volume at one epoch: size, block size, `SU`, `G`, QoS, flags,
  attachments, every stripe group's members, and the endpoints that
  initiators use.
- **Block store**: the per-replica on-disk store of block data, CRCs and
  written bits beside the group's Raft log.
- **Reservation**: the space the controller sets aside on a server's
  drive for one replica, the provisioned size divided by `G`, unless
  overcommit is on.
- **Overcommit ratio**: the operator's limit on reservations as a
  multiple of a storage pool's physical capacity; 1.0 means none.
- **Mirror migration**: moving a volume between backends (or between
  khold layouts) while attached: the initiator writes both, a copier
  fills the target, and the controller cuts over.

## Requirements

### Requirement 1: Opt-in module

#### Acceptance Criteria

1. The service SHALL live under `services/khold/`, be built only with a
   Kconfig option `KHOLD` (default off), include only core public
   headers, and leave every existing target unchanged when off.
2. It SHALL be a service module with module number 12, runnable in
   `kythira_node` and as a stand-alone `khold_node`.
3. A path-filtered `.github/workflows/khold-module.yml` SHALL build and
   test it under Docker and rootless Podman.
4. Antikythera's `src/proto/` codecs (hold wire versions 1 and 2, the
   volume layout, reports) SHALL be consumed through the pinned,
   header-only overlay port that `ec2-compatible-api` task 1 adds, and
   the module's tests SHALL reproduce antikythera's test vectors for them
   byte for byte.

### Requirement 2: The guest sees an ordinary network volume

**User Story:** As a tenant, I want a khold volume to look and behave
exactly like any other network volume.

#### Acceptance Criteria

1. A khold volume SHALL be presented to the guest by oar-blk as an
   ordinary virtio-blk function, bootable, hot-pluggable and detachable
   as block-volume Requirements 1-3 state, indistinguishable from a hold
   volume except in performance.
2. khold SHALL see only ciphertext: the initiator encrypts with the
   volume key (block-volume Requirement 1.2); no khold node, log, store,
   report or metric SHALL carry key material, plaintext or tenant
   identity beyond opaque volume and attachment IDs.
3. Volume sizes SHALL range from 1 GiB to at least 16 TiB in 1 GiB
   steps, with a logical block size of 512 bytes or 4 KiB chosen at
   creation.
4. Every write SHALL be acknowledged only once it is on persistent media
   on every data replica of its stripe group that is not lagging
   (Requirement 7), so FLUSH and FUA are satisfied by every completed
   write.
5. Reads SHALL return the most recently acknowledged write to each block
   (per-block linearizability) across leader changes, member changes,
   moves, mirror migrations and multi-attach (block-volume Requirements
   1.6 and 4.2).
6. A read SHALL never return data from a write that could still be
   rolled back.

### Requirement 3: Striping

**User Story:** As a tenant who pays for provisioned IOPS and throughput,
I want them delivered even when one storage server could not deliver
them alone.

#### Acceptance Criteria

1. Every khold volume SHALL be striped over `G` stripe groups with stripe
   unit `SU`, both fixed at creation: `SU` a power of two from 64 KiB to
   4 MiB (default 1 MiB), `G` from 1 to 64.
2. The controller SHALL choose `G` from the class's ceiling for IOPS and
   throughput and the capacity reports of the servers it can place on
   (Requirement 12), so that the volume's ceiling fits within the sum of
   its groups' budgets; it SHALL place the groups so that no server leads
   more of one volume's groups than the layout needs.
3. An initiator SHALL split every request at stripe unit boundaries and
   send each part to its group; a write that spans groups is that many
   independent writes, as parts over 4 MiB already are in hold.
4. Within one stripe group the per-block ordering rules of hold SHALL
   hold: an initiator never sends a write while an earlier overlapping
   write is unacknowledged, so resends are idempotent.
5. Changing a volume's `G` or `SU` (re-striping) SHALL be done by a mirror
   migration to a new layout (Requirement 15), in phase 2.

### Requirement 4: Thin provisioning and overcommit

**User Story:** As the operator, I want space used only by what tenants
write, and the option to sell more than I have.

#### Acceptance Criteria

1. A khold volume's stripe groups SHALL be created at `CreateVolume`, and
   SHALL consume no block-store space until written; a block never
   written SHALL read as zeros with a CRC of 0, as in hold.
2. `DISCARD` and `WRITE_ZEROES` SHALL be served and SHALL free the space
   of the whole file-system blocks they cover; the initiator SHALL offer
   virtio-blk's discard and write-zeroes features for khold volumes.
3. The controller SHALL reserve each replica's share of the provisioned
   size on the drive it places it on, and SHALL refuse a placement that
   does not fit; with the default overcommit ratio of 1.0 a write SHALL
   never fail for lack of space.
4. The operator SHALL be able to set an overcommit ratio per storage
   pool, from 1.0 to a configured maximum, with a warning and a refusal
   watermark on physical use (defaults 80 % and 90 %); above the refusal
   watermark the controller SHALL place nothing new on that drive and
   SHALL move groups off it.
5. IF a drive with overcommit runs out of space THEN a write that needs
   new space SHALL fail with `no_space` (the guest gets an I/O error for
   that write only), writes to already allocated blocks SHALL still
   succeed, the volume's status SHALL become `warning` with a reason,
   and an alarm SHALL be raised. No acknowledged write SHALL be lost.
6. Allocated and reserved bytes SHALL be reported per replica, per drive
   and per pool.

### Requirement 5: Replica counts and the witness

#### Acceptance Criteria

1. A stripe group of the `general` class SHALL have two data replicas and
   one witness; a group of the `provisioned` class SHALL have three data
   replicas. Up to five voters SHALL be allowed for other classes.
2. A witness SHALL vote and store entry descriptors, SHALL never store
   block data, and SHALL never become leader.
3. A group's members SHALL be on different servers, and in different
   failure domains when the inventory reports racks or power domains
   (block-volume Requirement 5.2); the witness SHALL not share a failure
   domain with a data replica of its group.
4. Within a server, the controller SHALL spread its replicas across the
   server's drives.
5. The design SHALL state the annual failure rate for each class and the
   rebuild-time assumption behind it, against block-volume
   Requirement 5.3's targets.

### Requirement 6: Authority, layouts and fencing

#### Acceptance Criteria

1. The controller SHALL be the only authority over a volume's layout:
   members and their kinds, attachments, generations, size, QoS and
   flags. No khold node or initiator SHALL add, remove or change the kind
   of a member on its own.
2. Raft SHALL choose a group's leader among its data replicas only, and
   MAY transfer leadership within them without the controller.
3. Every volume layout SHALL be signed with Ed25519 by the controller's
   key, and every khold node SHALL verify the signature itself before
   applying it, with the controller keys it was started with.
4. A stripe group SHALL apply a new layout by committing it through its
   own log (joint consensus when its voters change), so a layout change
   is ordered with the writes around it.
5. Every data-path request SHALL carry the layout epoch, attachment ID
   and generation; a node SHALL refuse a lower epoch than its group has
   applied and a retired generation (`fenced`), and an attach or detach
   SHALL not be reported complete until every stripe group of the volume
   has committed the layout that grants or retires it.
6. A khold node SHALL accept Raft traffic for a group only from members
   of that group's applied layout, authenticated by their certificates.
7. A compute server partitioned from the controller SHALL NOT be able to
   write to a volume that has since been attached elsewhere
   (block-volume Requirement 6.9).

### Requirement 7: Writes, commit and lagging replicas

#### Acceptance Criteria

1. The leader SHALL commit a write when it is durable on a majority of
   voters that includes every data replica not recorded as lagging, and
   on at least one data replica in all cases.
2. A data replica that does not acknowledge within the member deadline
   (default 1 s) SHALL be recorded as lagging by the leader through a
   committed log entry before any write is committed without it, and
   SHALL be required again once it has caught up.
3. A lagging replica SHALL be reported to the controller, which SHALL
   replace it if it has not caught up within the resync window (default
   15 minutes).
4. The Raft log SHALL carry entry descriptors (LBA range, CRCs, term,
   index), and block payloads SHALL be written once, to the block store;
   the log SHALL NOT store block payloads on disk.
5. A write SHALL pause for at most the member deadline plus one commit
   when a data replica fails, and SHALL not pause when the witness fails.
6. An operator MAY set a class's commit rule to `majority` (commit on a
   majority of voters without waiting for every non-lagging data
   replica); the default SHALL be `all_in_sync`, matching hold.

### Requirement 8: Reads and leader leases

#### Acceptance Criteria

1. Only a stripe group's leader SHALL serve reads in phase 1, and only
   while it holds a Raft leader lease confirmed by a quorum within the
   lease time, or after a ReadIndex round when the lease has lapsed or
   the group was hibernating.
2. The leader lease SHALL be shorter than the minimum election timeout by
   at least the configured clock-drift bound, measured on monotonic
   clocks, so two leaders never serve reads at once.
3. A read that overlaps an uncommitted write SHALL wait for that write's
   commit.
4. Every block's CRC SHALL be checked on read by the leader and by the
   initiator; a mismatch SHALL be repaired from another data replica and
   never returned to the guest; a block no replica can mend SHALL be
   reported `checksum_unrepairable` and fail that read only.

### Requirement 9: Failure detection and failover

**User Story:** As a tenant, I want a storage failure to cost my VM a
short pause, never a split brain, a silent rollback, or an endless run of
I/O errors.

#### Acceptance Criteria

1. WHEN a leader fails THEN the group's data replicas SHALL elect a new
   leader without the controller, and initiators SHALL find it through a
   `REDIRECT` carrying the new leader from any member, and resend every
   unacknowledged part.
2. A single replica failure SHALL pause a stripe group's I/O for at most
   3 seconds in the reference configuration (hold's target is 10).
3. WHEN a data replica's block store returns an I/O error on a write or on
   its metadata THEN that replica SHALL stop acknowledging writes, SHALL
   transfer leadership if it leads, SHALL report `media_error`, and the
   guest SHALL see at most a failover pause, never a run of I/O errors.
4. WHEN a read hits an I/O error on one block THEN the leader SHALL treat
   it as a checksum failure and repair it from another data replica.
5. A data replica whose disk is persistently slow (fail-slow: its
   durable-write latency stays above a configured multiple of its peers'
   for a configured window) SHALL be marked lagging if a follower and
   SHALL transfer leadership if the leader, and SHALL be reported.
6. A server that is silent to the controller but whose groups' other
   members still report it reachable SHALL NOT have its replicas
   replaced until the resync window passes; the controller SHALL record
   it as `unreachable_from_controller`.
7. A controller outage SHALL NOT stop I/O or failover; only membership
   changes, attaches and detaches wait for it.
8. IF no data replica that holds every committed entry survives in a
   stripe group THEN the group SHALL refuse I/O, the volume SHALL become
   `impaired` with I/O suspended, and only an explicit `EnableVolumeIO`
   SHALL resume it from the most complete surviving replica, recording
   possible loss (block-volume Requirement 6.8).
9. Initiator faults (timeouts, checksum mismatches, refusals) SHALL be
   reported to the controller through helm, closing hold's
   `take_faults()` gap; an initiator's report alone SHALL never cause a
   membership change.

### Requirement 10: Resync, rebuild and moves

#### Acceptance Criteria

1. A lagging replica that returns within the resync window SHALL catch up
   from the leader: by log replay while the leader still holds the
   payloads, otherwise by a region copy of the blocks written since its
   last acknowledged index, sent on the same ordered stream as new
   writes.
2. A replacement replica SHALL join as a learner, receive the allocated
   regions of the block store streamed from disk (never the whole store
   in memory) and then the log, and SHALL be promoted only once it holds
   every committed write; the old member SHALL leave only after.
3. Rebuild and region-copy traffic SHALL be rate-limited per server and
   per volume and SHALL yield to tenant I/O; the controller SHALL rebuild
   the groups with the fewest up-to-date data replicas first and spread
   the rebuilds after a server loss across many sources and targets.
4. The design SHALL bring a 1 TiB volume back to full redundancy within
   30 minutes after a server loss on the reference 25 GbE hardware when
   it is otherwise idle.
5. A replica SHALL be movable to another server while attached, with no
   guest I/O error; a move of a leader SHALL transfer leadership first,
   pausing I/O for at most 1 second.
6. A storage server SHALL be drainable: every replica moves off it while
   each group keeps its replica count, and the controller reports when
   it is empty.

### Requirement 11: Hold wire protocol version 2

**User Story:** As the oar-blk maintainer, I want one initiator that
speaks to both backends, with a protocol change small enough to review.

#### Acceptance Criteria

1. Hold wire version 2 SHALL be specified and codec'd in antikythera's
   `src/proto/` beside version 1, strict, little-endian, pinned by test
   vectors and fuzzed; version 1 SHALL keep working unchanged for hold.
2. Version 2 SHALL add to every request the stripe group ID and the
   sender's last known term for it, and to `REDIRECT` the leader's
   server ID, endpoint and term; it SHALL add a `not_leader` and a
   `no_space` status and a `lagging` report.
3. The initiator SHALL keep a map from stripe group to leader, seeded
   from the volume layout, and SHALL follow a `REDIRECT` only to a member
   of the group in its current signed layout.
4. An initiator SHALL keep one session per stripe group leader it uses
   (or one per gateway in a split layout) and SHALL bound its sessions
   and in-flight parts per volume.
5. The volume layout SHALL be a new signed frame (`VolumeLayout`) relayed
   by helm byte for byte, as `ReplicaConfig` is.

### Requirement 12: Hardware range and capacity reports

**User Story:** As someone running khold on hardware from 1 GbE hobby
boxes to 200 GbE servers, I want the service to promise only what the
hardware can deliver.

#### Acceptance Criteria

1. Every storage server SHALL report in its inventory its storage link
   speed, each drive's capacity, and measured random 4 KiB read and write
   IOPS and sequential throughput, refreshed by a short self-test at
   enrollment and on demand.
2. The controller SHALL derive each server's and each group's budgets
   from those reports and SHALL refuse a `CreateVolume` or `ModifyVolume`
   whose IOPS or throughput the placed groups cannot deliver, with a
   clear error, rather than accept it and fail under load.
3. Nothing in khold SHALL assume a link speed; the design SHALL work from
   1 GbE to 200 GbE, and SHALL be measured at 1 GbE (the floor) and at
   25 GbE (Requirement 20.6).
4. The data path SHALL avoid per-byte copies on khold nodes (scatter-
   gather I/O through `io_uring` or equivalent, no bounce buffers) and
   SHALL use kernel TLS, with NIC offload where the card offers it, when
   available.

### Requirement 13: QoS

#### Acceptance Criteria

1. Each volume's IOPS and throughput limits SHALL be enforced at the
   initiator, at the gateway per attachment, and at each stripe group
   per volume (the volume's limit divided by `G`, times a configured skew
   allowance, default 2), because an initiator is untrusted; I/O SHALL be
   counted in units of up to 256 KiB.
2. Each khold node SHALL fair-queue across volumes, and tenant I/O SHALL
   have priority over rebuild, region copy, scrub and migration copy.
3. A volume's class, IOPS and throughput SHALL be changeable while
   attached within the class's ceiling for the volume's `G`; beyond it,
   phase 2 re-stripes (Requirement 3.5).

### Requirement 14: Independent layers

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_KHOLD_ROLES`, a
   non-empty subset of `gateway` and `data`; default both. No deployment
   SHALL require a split.
2. Co-located, an initiator SHALL connect to the node leading each stripe
   group, and the gateway function on that node SHALL hand requests to
   the group in-process, with no extra hop.
3. Split, the layout SHALL name gateway endpoints; initiators SHALL
   connect to a gateway, which forwards each part to the group leader
   over internal version 2 sessions authenticated with layer identities
   (`khold` service, per-route role checks).
4. A gateway SHALL hold no durable state and no Raft membership; it SHALL
   find leaders through a route cache refreshed by `REDIRECT`s.
5. Gateways SHALL be able to serve hold wire version 1 initiators, which
   see one primary endpoint per volume, by translating to version 2.

### Requirement 15: Live migrations

**User Story:** As the operator, I want to change how khold is laid out,
and which backend a volume lives on, while volumes stay attached.

#### Acceptance Criteria

1. **Layout, co-located to split and back.** Gateways SHALL be added or
   removed under a running deployment by publishing layouts that name or
   drop gateway endpoints; initiators SHALL move sessions with every
   unacknowledged part resent, and no guest SHALL see an error.
2. **Data role.** Replicas SHALL move between servers through learner,
   promote, leadership transfer and remove, and an `evacuate` admin call
   SHALL empty a node (Requirement 10.5-10.6).
3. **Backend, hold to khold and back.** A volume SHALL move between
   backends while attached or detached by a mirror migration: the
   controller creates the target, the initiator writes to both, a copier
   fills the target with hydrate writes that never overwrite a block the
   guest has written, and the controller cuts over at a new epoch once
   the copy is complete, then fences and deletes the source.
4. **Initiator protocol, version 1 to version 2 and back.** A volume SHALL
   be served to a version 1 initiator through a gateway and to a version
   2 initiator directly, and SHALL switch between them on re-attach.
5. During any migration no acknowledged write SHALL be lost, every read
   SHALL stay linearizable (Requirement 2.5), no epoch SHALL go
   backwards, no two leaders of a group SHALL serve reads at once, and
   a migration stopped or reversed midway SHALL leave the volume served
   by exactly one backend or layout.

### Requirement 16: Security and isolation

#### Acceptance Criteria

1. khold on antikythera SHALL run as a storage role launched by helm on
   the storage segment of the management fabric (block-volume
   Requirement 13), with a certificate issued by the controller's storage
   CA through the existing `cert_request` flow and naming its server.
2. A khold node SHALL accept a data-path session for a volume only from a
   member of the volume's layout, a gateway it names, or a server
   holding a current attachment.
3. Every parser of storage traffic, layouts and reports SHALL return
   `std::expected`, have unit tests, and have a fuzz target.
4. A compromised khold node SHALL be able to corrupt, withhold or roll
   back the blocks of groups it is a member of, and nothing else: it
   SHALL NOT forge layouts, learn keys, or reach helm's controller link.

### Requirement 17: Phase 2: snapshots, hydration and re-striping

#### Acceptance Criteria

1. khold SHALL implement block-volume Requirement 11 (crash-consistent and
   multi-volume snapshots in image format v2, restore with hydration on
   first read and in the background, fast snapshot restore, clones,
   creation from public images, snapshot deletion) with a cut that
   commits one marker entry per stripe group under a volume-wide barrier
   held for at most 100 ms.
2. Hydration SHALL use version 2's hydrate writes and the block store's
   written bits, so a hydrated block never overwrites a guest write.
3. Re-striping SHALL be a khold-to-khold mirror migration (Requirement
   15.3) to a layout with the new `G` or `SU`.

### Requirement 18: Controller library

#### Acceptance Criteria

1. `khold_controller` SHALL be single-threaded, deterministic, take time
   as input, act only through an abstract transport, and export and
   restore its state, so the EC2 module can run it on each volume
   group's Raft leader over committed state (`ec2-compatible-api` design
   "The volume master runs on the volume group's leader").
2. It SHALL implement placement with capacity and reservations, stripe
   width selection, layouts and epochs, attachments and generations,
   replacement and rebuild ordering, moves and drains, mirror migrations
   between backends, scrub scheduling, and lineage key erasure, and SHALL
   report every decision it wants committed before acting on it.
3. The operator SHALL choose each volume class's backend (`hold` or
   `khold`); the default SHALL stay `hold` until Requirement 19 is met.

### Requirement 19: Parity and the retirement of hold

**User Story:** As the owner of both repositories, I want hold retired as
soon as khold can do everything hold does, and proven so.

#### Acceptance Criteria

1. `services/khold/doc/hold-parity.md` SHALL map every block-volume
   requirement and acceptance criterion, and every hold unit, simulation
   and harbor test, to its khold equivalent and its status.
2. khold SHALL be declared at parity when every row is met or explicitly
   waived by Clark, every khold test in the table passes in CI and in
   harbor, and the khold simulation has run its nightly seed budget for
   14 consecutive nights without a failure.
3. After parity, the default backend for every class SHALL become `khold`,
   and the controller SHALL offer a bulk mirror migration of every hold
   volume to khold, paced and resumable.
4. hold's retirement (removing the role, its codecs and its tests from
   antikythera) SHALL wait until no hold volume remains and Clark gives
   his go.

### Requirement 20: Testing

#### Acceptance Criteria

1. A deterministic in-process simulation SHALL run khold nodes, a
   reference initiator built from antikythera's version 2 codecs, and
   `khold_controller` on a simulated clock, with crashes that drop
   unsynced data, partitions (including asymmetric ones), message loss,
   delay and reordering, injected EIO and slow disks on any replica,
   clock drift within the configured bound, and space exhaustion; it
   SHALL check every history for per-block linearizability, no lost
   acknowledged write, and no two leaders serving reads at once. ctest
   SHALL run a few hundred seeds; a nightly job SHALL run many more.
2. Every failure case in design "Failure cases" SHALL be a named
   simulation case or test.
3. Unit tests and fuzz targets SHALL cover every codec of
   Requirement 16.3, and crash-consistency tests SHALL drop unsynced
   writes at every step of the block store.
4. Every migration path of Requirement 15 SHALL have its own test in
   both directions, under a mixed read and write load with a stop and a
   reversal midway, checking Requirement 15.5; and a docker-chaos run of
   the co-located to split path and back killing one node per layer, on
   Docker and rootless Podman, wired by service name with no static
   addresses.
5. In antikythera, the real oar-blk initiator SHALL be tested against a
   real `khold_node`, and harbor SHALL repeat block-volume
   Requirement 15.3's scenarios on khold volumes plus a disk EIO on a
   leader and a hold-to-khold mirror migration under load (runs on
   tikhov need Clark's go).
6. Measurement rows SHALL record random 4 KiB read and write IOPS,
   sequential throughput, and p50/p99 latency at queue depths 1 and 32,
   for one volume and for many, co-located and split, on loopback in
   CI, and on 1 GbE and 25 GbE hardware when available; and khold against
   hold on the same hardware. Each hardware run needs Clark's go.

### Requirement 21: Documentation

#### Acceptance Criteria

1. `services/khold/doc/` SHALL cover configuration, the layers and
   sizing, striping and its choice of `G`, thin provisioning and the
   overcommit settings and alarms, capacity reports, failure handling,
   the migration runbooks (layouts, backends, protocol versions), the
   parity table, and the measured rows.
