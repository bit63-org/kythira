# Design Document

## Overview

khold stores antikythera network volumes in Kythira Raft groups. Each
volume is striped over `G` **stripe groups**; each group is a Raft group
of two data replicas and a witness (`general`) or three data replicas
(`provisioned`), placed on different servers. The guest, oar-blk's
encryption, the controller's authority and the EC2 API are unchanged:

```
 compute server                               storage servers (khold nodes, helm storage role)
 ┌─────────────────────────────────┐
 │ guest ── virtio-blk ──┐         │          group g0: ┌ leader (data) ┐ ┌ data ┐ ┌ witness ┐
 │ oar-blk  XTS(K)       ▼         │  v2      ──────────►  block store   ─► store   ─► log only
 │   NetworkVolumeBackend v2       │ ─────┐   group g1:   ┌ data ┐ ┌ leader (data) ┐ ┌ witness ┐
 │   stripe map: LBA → group       │      └──────────────────────────►
 │   leader cache, per-group       │  ...     group gG-1 ...
 │   sessions, resend, CRCs        │
 └─────────────────────────────────┘          each node: gateway function (sessions, fencing,
          ▲ VolumeLayout, VolumeKey              QoS) + data function (multi-Raft host,
          │                                      block store, scrub, rebuild)
        helm ◄──── controller link ────► EC2 module data layer
                                          khold_controller (placement, layouts,
                                          reservations, replacement, migrations)
```

Split layout: initiators connect to gateway nodes instead, which forward
each part to the group leader over internal v2 sessions.

khold runs beside hold. The operator picks a backend per volume class,
volumes move between the backends while attached (mirror migration), and
hold is retired once khold reaches parity (Requirement 19).

## Key design decisions

### Raft groups instead of a primary-backup set

hold's primary-backup design needs an external authority for every
leadership change: a failed primary stays failed until the controller
notices (2 s detection), waits out the primary's read lease (up to
4.4 s) and publishes a new epoch through helm. That is also why a primary
whose disk fails is never replaced today: nobody inside the replica set
may decide it.

In khold, the members of a stripe group elect a leader among themselves.
Failover costs an election timeout (randomised 1-2 s by default) plus one
commit, with the controller not involved, and a data replica that sees
its own disk fail simply stops leading. The controller keeps what it
must own for safety and for the EC2 API: who the members are,
attachments and generations, keys, size and QoS (Clark, 3A).

### Striping

A volume of capacity `C` with stripe unit `SU` and width `G` maps byte
offset `x` to

```
unit   = x / SU
group  = unit mod G
offset = (unit / G) * SU + x mod SU      // within the group's store
```

so group `g` stores a sparse "column" of `C / G` bytes. Sequential I/O
moves to the next group every `SU` bytes, and random I/O spreads
uniformly. A request that crosses a unit boundary is split by the
initiator (or the gateway). With `SU` = 1 MiB and hold's 4 MiB part
limit, a large write becomes up to four parts on four groups.

**Choosing `G`.** Per server, the controller knows the storage link
speed and each drive's measured IOPS and throughput (Requirement 12).
For a class ceiling `(iops_max, mibs_max)` it computes each candidate
leader's budget: for throughput `link_out / max(1, data_replicas − 1)`,
because the leader sends each write to every other data replica and
serves every read from the same port, and for IOPS a share of its drive's
measured IOPS. A server's budget is shared by every leader placed on it,
so placement subtracts what earlier volumes reserved. It then takes

```
G = clamp(ceil(headroom × max(mibs_max / leader_mibs,
                               iops_max / leader_iops)),
          G_min, 64)
```

with `headroom` 1.5 and `G_min` 2 by default (two groups give rebuild
spread even when one would carry the load). `G` is fixed at creation;
changing it is a re-stripe (phase 2). Worked numbers, ignoring protocol
overhead:

| Link | Usable | `general` 1,000 MiB/s (leader sends ×1) | `provisioned` 2,000 MiB/s (×2) |
|---|---|---|---|
| 1 GbE | ~117 MiB/s | `G` 13+, and gp3's 125 MiB/s baseline alone needs 2 | `G` 52+, beyond hobby hardware: refused (Req 12.2) |
| 25 GbE | ~2,900 MiB/s | `G` 2 (`G_min`) | 4,000 MiB/s out of one leader is too much: `G` 3 with headroom |
| 200 GbE | ~23,000 MiB/s | `G` 2 | `G` 2; disks and CPU bound first |

The 25 GbE `provisioned` row is the case the benchmark task checks:
one leader cannot carry it, three or more can.

**Placement.** Stripe groups of one volume are placed so their leaders
land on different servers (preferred leaders, enforced by leadership
transfer when a server leads more than its share); data replicas and the
witness obey failure-domain rules (Requirement 5.3).

### Thin provisioning and reservations

Groups are created at `CreateVolume` but hold no data: the block store is
a sparse file, a never-written block reads as zeros with CRC 0, and
`DISCARD`/`WRITE_ZEROES` punch holes (whole file-system blocks; partial
blocks are written as zeros) and clear the blocks' written bits and
CRCs. Groups are not created lazily on first write: in a multi-attach
volume, an initiator that believes a group does not exist would answer
zeros locally while another attachment's write creates it, which breaks
linearizability for no gain (an empty group costs a few kilobytes and,
hibernated, no traffic).

The controller's placement accounts two numbers per drive:

- **reserved**: the sum of the replicas' shares (`C / G` each), checked
  against `capacity × overcommit_ratio`;
- **used**: physical bytes reported by the node.

With the default ratio 1.0, reserved ≤ capacity, so a write never meets
a full drive. With overcommit on, the controller watches used against the
warning (80 %) and refusal (90 %) watermarks: at warning it alarms; at
refusal it places nothing new there and moves groups off, largest
allocated first. If a drive still fills, the block store refuses writes
that need new space with `no_space`: the initiator fails that one
request with an I/O error (no retry; it is not transient), the volume
reports `warning` with reason `no_space`, and writes to allocated blocks
continue. `no_space` is checked before an entry is appended, so a
refused write never enters the log.

### The log carries descriptors; payloads are written once

A Raft entry for a write carries `(lba, blocks, op, CRC per block)` and,
on the wire only, the payload. On a data replica, appending an entry
writes the payload in place into the block store and the descriptor into
the log, then makes both durable together (one group commit per batch;
the multi-Raft host already batches fsyncs across groups). The witness
writes the descriptor only. Nothing is written twice.

Writing in place before commit is hold's model, and it needs hold's
answer to roll-back, here in Raft terms:

- **Reads wait for commit.** A read overlapping an uncommitted entry waits
  for it, so no read returns data that could still be rolled back.
- **Suspect ranges.** When a replica truncates entries (a new leader's
  log conflicts with its suffix) or restarts with entries past its
  durable apply mark, it records the LBA ranges of those entries as
  *suspect* in its block-store metadata, durably, before acknowledging
  anything else. Those ranges may hold bytes no committed entry wrote.
- **Reconcile on election.** A new leader collects the suspect ranges of
  its followers and the witness (the witness has the descriptors of every
  entry it truncated) together with its own uncommitted suffix, and
  before serving those ranges it re-proposes its own current content of
  their union as ordinary write entries. Every replica then holds the
  leader's bytes there, committed. Unacknowledged writes may be kept or
  lost, as in hold, but replicas always converge and nothing
  acknowledged is lost.
- **Torn writes.** A crash can tear a payload whose descriptor is in the
  log. On restart, ranges past the apply mark are suspect, CRC
  mismatches inside them are expected and repaired from the leader, and
  only mismatches outside them count as corruption.

The leader keeps recent payloads in memory (a bounded window, default
256 MiB per node) for followers that are slightly behind. A follower
behind that window catches up by **region copy**: the leader reads the
current content of every range written since the follower's match index
(from the descriptors still in its log, or from a changed-region bitmap
kept per member once the log is compacted) and sends it as `sync` entries
on the same ordered stream as new writes, as hold's `SYNC_DATA` does.

Log compaction: descriptors are kept until every non-lagging data
replica has applied them durably, and for lagging members until the
resync window ends, after which the bitmap stands in for them. Raft
snapshots are never byte images of the store; a learner receives the
store by region copy streamed from disk (`file-install-snapshot`'s
streaming sender, with sparse ranges skipped).

Core changes this needs, built as general multi-Raft features:

1. an **append sink** on the log persistence engine, so a state machine
   can take an entry's payload at append time, before commit, and the
   log stores only the descriptor;
2. **witness** voters: vote, store descriptors, never campaign, never
   receive payloads;
3. per-group **commit predicates**, so khold's commit rule (below) can
   replace "majority".

### Commit rule and lagging replicas

```
commit(i) ⇔ durable on a majority of voters
            ∧ durable on every data replica not recorded as lagging
            ∧ durable on ≥ 1 data replica
```

With all members healthy this is hold's rule (every in-sync replica has
it). When a data follower misses the member deadline (1 s), the leader
proposes `lagging(member)`; that entry commits on the remaining majority
(for `general`, leader plus witness), and from then on writes commit
without it. When it catches up, `in_sync(member)` restores it. The
controller is told in both cases and replaces a member still lagging at
the end of the resync window.

Why the witness keeps this safe: if the leader dies while the other data
replica is lagging, the witness's log holds entries the lagging replica
lacks, so Raft's election restriction stops the lagging replica from
winning. The group stops instead of serving stale data, and the volume
goes `impaired` (Requirement 9.8), which is exactly hold's "no in-sync
replica" case.

`majority` (Requirement 7.6) drops the second clause for classes that
prefer tail latency over the extra copy; it is never the default.

### Reads, leases and hibernation

Reads go to the leader. An active leader serves reads under a leader
lease: it holds one while a quorum acknowledged its heartbeats within
`lease = election_timeout_min − drift_bound` (defaults 1,000 ms and
100 ms, so 900 ms), measured on monotonic clocks from when it sent them.
Followers do not vote for another candidate within the minimum election
timeout of hearing from a leader (check-quorum and leader stickiness), so
a new leader cannot exist while the old one's lease runs. A hibernating
group (multi-raft Requirement 5) has no running lease; its first read
does a ReadIndex round, which also wakes it. Follower reads are a later
option.

### Layouts, authority and fencing

The controller describes each khold volume by one signed frame:

```
VolumeLayout {
  magic "AKVLAY\0\0", version u16 = 1, key_id u16, server_id u64
  volume_id u64, epoch u64, lineage_id u64
  capacity_blocks u64, block_size u32, stripe_unit u32, stripe_width u16,
  commit_rule u8, flags u32           // multi_attach, io_suspended, impaired,
                                      // mirror_source, mirror_target, no_space_warning
  qos { iops, mib_per_s, burst_iops, burst_mib, group_skew_pct }
  timings { member_deadline_ms, election_min_ms, resync_window_s }
  groups [G] { group_id u64,
               members [] { server_id, endpoint [16], port, kind (data | witness |
                            learner), drive u8 } }
  gateways [] { server_id, endpoint, port }      // empty: co-located
  attachments [] { attachment_id u64, generation u32, server_id u64, mode u8 }
  mirror { peer_backend u8, peer_volume u64, phase u8 }   // during a migration
  source { ... }                                 // phase 2: snapshot or image
  signature [64]
}
```

One frame per recipient server (its `server_id` is signed). The codec
lives in antikythera's `src/proto/` with the hold codecs. The size is
bounded by `G ≤ 64` and five members per group.

A khold node verifies the signature and the epoch order, then the leader
of each affected group proposes the layout into that group's log; a
change of voters goes through joint consensus (`membership-change`), a
new member joins as a learner (`non-voting-nodes`). The group applies the
layout at commit, so attaching, detaching and fencing are ordered with
the writes around them, and "generation fenced" means "every group of
the volume has committed a layout without it". Requests carry the layout
epoch, attachment and generation. A node that has applied a newer epoch
refuses the older one (`stale_epoch`, with the newer epoch in the
response), and one that has not yet applied the request's epoch holds
the request briefly and then answers `stale_epoch` too, so the sender
waits for its helm.

Lease grants from the controller do not exist for khold; the EC2
module's lease path keeps serving hold volumes only.

### Hold wire protocol version 2

Version 2 keeps version 1's frame discipline (fixed header with its own
CRC32C, strict payloads, block data as CRCs then blocks, no copies on
decode) and adds:

- `group_id u64` and `term u64` (the sender's last known leader term) in
  the header; version 1 fields keep their meaning;
- `REDIRECT` with `leader_server u64 | endpoint [16] | port u16 | term
  u64`, sent by any member that is not the leader;
- statuses `not_leader` (with a redirect payload), `no_space`,
  `repairing` (the range is being reconciled; retry shortly);
- `hydrate` writes from the mirror copier and phase 2 hydration, which
  fill only blocks whose written bit is clear;
- `DISCARD` and `WRITE_ZEROES` as real operations.

The initiator follows a redirect only to a member of the group in its
current signed layout, so a compromised node can delay it but cannot
steer it outside the group. Layout epoch, attachment generation and term
together fence: the epoch for membership and attachments, the generation
for detached compute servers, the term for stale leaders.

### Gateway and the co-located path

The gateway function terminates an initiator session: TLS 1.3 with the
storage CA's certificates, `HELLO` with the attachment and generation,
the per-attachment QoS buckets, splitting at stripe boundaries, and
per-volume fair queueing. Co-located (the default), each node's gateway
function hands parts for groups it leads straight to the group's
in-process interface; initiators open sessions to the leaders they need.

Split, the layout names gateway endpoints and initiators open one
session per gateway; the gateway forwards each part to the group leader
over internal version 2 sessions authenticated with layer identities
(`kinesis-independent-layers` Requirement 7), finding leaders through a
route cache that `REDIRECT`s refresh. Reasons to split: serving version
1 initiators (the gateway presents one primary endpoint per volume and
translates), moving TLS and splitting CPU off storage nodes, and keeping
storage nodes off the compute-facing segment. The cost is one extra
network hop per request and twice the gateway's bandwidth; the
measurement rows record it.

### Mirror migration between backends

Moving a volume from hold to khold (or back, or from one khold layout to
another) while attached:

1. **Prepare.** The controller creates the target volume (same lineage,
   key, size, block size) and publishes both layouts with `mirror` set;
   the target is fenced to the copier and the volume's attachments.
2. **Mirror.** The initiator holds both backends. Writes go to both and
   complete when both acknowledge; reads go to the source. A failure on
   either side fails the write as it would on one backend (retries,
   then I/O error at the deadline), so the guest never sees an
   acknowledged write that only one side holds.
3. **Copy.** A copier (a gateway function, or the controller's test
   copier) reads the source's allocated regions and writes them to the
   target as `hydrate` writes, which fill only blocks the guest has not
   written. A guest write that races the copy therefore always wins,
   whichever order the two arrive in.
4. **Cut over.** When the copy reports complete, the controller commits
   a new epoch in which the target is the only backend; the initiator
   moves reads and writes to it and drops the source session; the source
   is fenced (its generation retired), then deleted.
5. **Stop or reverse.** Until cut-over, dropping `mirror` returns to the
   source alone and the target is deleted; after it, the same procedure
   runs the other way.

Detached volumes skip step 2. hold needs the `hydrate` write it already
has (`HYDRATE` flag) and written bits per block, which its store keeps
per chunk; the hold side of this is an antikythera task.

### Failure detection inputs

- **Members**: Raft heartbeats and the member deadline. A follower that
  misses it becomes lagging; a leader that loses quorum stops serving
  reads at lease end and steps down at check-quorum.
- **Media errors**: the block store maps EIO on a payload write, a
  metadata write, an fsync or a log write to *store failed*: the replica
  stops acknowledging, transfers leadership if it leads (or simply stops
  heartbeating, so the others elect), reports `media_error`, and refuses
  every request with `not_leader` plus a redirect. EIO on a read of one
  block is a checksum failure and is repaired from a peer; repeated read
  errors past a threshold also fail the store.
- **Fail-slow**: each leader tracks its followers' durable-ack latency
  and its own fsync latency; a member whose p99 stays above `slow_factor`
  (default 4) times the median of its peers for `slow_window` (default
  60 s) is marked lagging (follower) or transfers leadership (leader),
  and is reported.
- **Initiator faults** go to helm and on to the controller (closing hold's
  `take_faults()` gap); they are evidence for the controller's view, never
  a trigger for a membership change on their own.
- **Server silence** to the controller starts the resync window only when
  the groups' other members also report the server unreachable; a server
  that only lost its controller link keeps its replicas.

### Running on antikythera

khold runs as a storage role that helm launches on storage servers, like
hold: on the storage segment, enrolled through `cert_request` (role
`khold`) for a certificate naming its server and storage endpoints, fed
`VolumeLayout` and `VolumeKey`-free control frames by helm's sideband,
reporting through helm's acknowledged report queue (`group_status`,
`volume_fault`, `capacity`). It uses no secure element and holds no key.
Outside antikythera (Kythira CI, docker-chaos), `khold_node` runs with
static certificates and a test controller.

Antikythera-side work: helm's role type and relay for `VolumeLayout`,
inventory capacity fields and the self-test, oar-blk's version 2
initiator, mirror backend and fault forwarding, hold's mirror source
side, and harbor scenarios. Those are listed as antikythera tasks below.

### Data path performance

- Payloads move by scatter-gather from the socket into the block store
  (`io_uring` with registered buffers where available, `preadv`/`pwritev`
  otherwise); CRCs are computed with the hardware instruction on the
  initiator and checked on the receive path without another copy.
- Kernel TLS (`SSL_OP_ENABLE_KTLS`) with NIC TLS offload where present;
  user-space TLS otherwise.
- Replication pipelines: the leader writes locally and sends to
  followers in parallel; followers ack after their group commit.
- Each node's groups are spread over its drives; one fsync batch per
  drive per tick (multi-raft batching).
- Hibernation keeps idle groups free; load buckets (`multi-raft-load-buckets`)
  report hot groups to the controller's placement.

### Durability model

Assume independent replica failures at rate λ per year (a drive plus its
server share; 2 %/year is conservative for enterprise NVMe) and a group
rebuild time `T`. Striping multiplies the number of groups per volume by
`G` and divides each group's rebuild size by about `G`, and rebuilds run
many-to-many, so `T` for a 1 TiB volume at 25 GbE is under 30 minutes
(Requirement 10.4).

- `general` (two data replicas): loss needs the second data replica to
  fail during the first's rebuild: per group ≈ 2λ² T / 8760, so per
  volume ≈ G · 2λ² T / 8760. With λ = 0.02, T = 0.5 h, G = 8:
  ≈ 3.7 × 10⁻⁷ per year (0.00004 %), well inside 0.1 %.
- `provisioned` (three data replicas): ≈ G · 6λ³ T² / 8760², negligible
  against 0.001 %.

Correlated failures (a rack, a power domain, a firmware bug) dominate
both in practice; failure-domain placement is the defence, and the
design states the numbers only for independent failures, as hold's does.

## Failure cases

"Pause" is guest-visible I/O delay with requests held, not failed, while
they are within the 30 s deadline. Defaults: election timeout 1-2 s,
member deadline 1 s, lease 900 ms, resync window 15 min.

| Failure | Detected by | What happens | Guest sees | Test |
|---|---|---|---|---|
| Leader crashes | followers' election timeout | Data replicas elect; new leader reconciles suspect ranges, commits a no-op; initiators get `REDIRECT`/`not_leader` from any member, or time out and try the next member, and resend unacked parts | pause ≤ 3 s on that group only | sim `leader_crash` |
| Data follower crashes | member deadline | Leader commits `lagging`, writes continue; returns within window → log or region catch-up; else controller adds a learner elsewhere, promotes, removes | write pause ≤ 1 s + one commit | sim `follower_crash`, `follower_returns`, `follower_replaced` |
| Witness crashes | heartbeat | Both data replicas still form a majority; nothing pauses; controller replaces the witness | nothing | sim `witness_crash` |
| Leader disk EIO on write, metadata or fsync | block store | Store failed: replica stops acking and leading, reports `media_error`; election as for a crash; controller replaces it | pause ≤ 3 s | sim `leader_eio_write` (closes hold's gap) |
| Leader disk EIO on a read | block store | Treated as a bad block: repaired from a peer and served | nothing | sim `leader_eio_read` |
| Follower disk EIO | block store | Follower stops acking → lagging → replaced | write pause ≤ 1 s | sim `follower_eio` |
| Whole drive lost | many stores fail at once | Every replica on it as above, many groups at once; rebuilds spread many-to-many | pauses ≤ 3 s per affected group | sim `drive_loss` |
| Whole server lost | heartbeats; controller silence confirmed by peers | Every group it led elects; every replica it held is lagging, then replaced after the window or at once if the operator declares the server lost | pause ≤ 3 s per group it led | sim `server_loss` |
| Fail-slow disk or NIC | latency tracking | Follower marked lagging; leader transfers leadership; reported | brief latency, then normal | sim `slow_disk_follower`, `slow_disk_leader` |
| Server cut off from the controller only | controller silence, peers say reachable | Nothing changes in the data path; controller records `unreachable_from_controller`; replacement waits for the window | nothing | sim `controller_link_cut` |
| Controller down | — | I/O and failover continue; attaches, detaches and replacements wait | nothing unless an attach is pending | sim `controller_outage` |
| Leader isolated from its followers, reachable by initiators | check-quorum | Leader's lease expires (reads stop), it steps down; followers elect; initiators' requests to it get `not_leader` or time out | pause ≤ 3 s | sim `asymmetric_leader_cut` |
| Initiator ↔ leader partition, rest healthy | initiator timeout | Initiator retries other members, which redirect it back; requests older than 30 s fail; fault reported to the controller, which never acts on it alone | latency, then I/O errors for old requests | sim `initiator_cut` |
| Gateway crashes (split) | initiator timeout | Initiator moves to another gateway in the layout and resends | pause ≈ initiator timeout | sim `gateway_crash`, docker-chaos |
| Initiator holds an old layout | `stale_epoch` | Waits for its helm's newer layout; resends | pause | sim `stale_layout` |
| Compute server dies | controller | Generation retired in every group before attaching elsewhere; late requests `fenced` | guest gone | sim `compute_loss_fenced` |
| Power loss on all replicas of a group | restart | Descriptors past apply marks → suspect ranges; election; reconcile; no acknowledged write lost | pause until servers return | sim `all_crash` |
| Torn write | restart | Suspect ranges absorb expected CRC mismatches; repaired from the leader | nothing | store crash tests |
| No data replica holds every committed entry | election cannot succeed | Group refuses I/O; volume `impaired`, I/O suspended; `EnableVolumeIO` resumes from the most complete replica, recording possible loss | I/O errors after 30 s until an operator acts | sim `no_up_to_date_replica` |
| Latent bad block | read CRC, scrub | Repaired from a peer; unrepairable → `checksum_unrepairable`, replica replaced (follower) or leadership moved (leader) | nothing, or an error on that read | sim `bit_rot`, `scrub_mends` |
| Drive full under overcommit | block store | `no_space` for writes that need space; volume `warning`; controller moves groups off | I/O error on those writes only | sim `overcommit_full` |
| Raft log device full | log append | Treated as a store failure for that replica | pause ≤ 3 s | sim `log_full` |
| Clock jump on a leader | monotonic clocks | Leases use monotonic time; wall-clock jumps change nothing; drift beyond the bound is a configuration error the self-test checks | nothing | sim `clock_drift_bound` |
| Hibernating group woken by a read | ReadIndex | One quorum round before the first read | sub-millisecond to milliseconds | sim `hibernate_wake` |
| helm restarts on a storage server | — | khold keeps running; helm replays the newest layouts; reports are acknowledged so none is lost | nothing | unit + sim `helm_restart` |
| khold process restarts | peers | Reopens stores, suspect ranges from the log, rejoins as follower | pause if it led | sim `process_restart` |
| Mirror migration: source fails | initiator, copier | Source failover as for its backend; migration resumes; if the source becomes impaired the controller may cut over only once the copy is complete | as for that failure | sim `mirror_source_failover` |
| Mirror migration: target fails | initiator, copier | Target failover; copy resumes from its progress mark; on target impairment the migration is abandoned and the source stays | as for that failure | sim `mirror_target_failover` |
| Mirror migration: controller crash at cut-over | — | Cut-over is one committed epoch; the new leader republishes; initiators see either the mirror epoch or the cut-over epoch, never neither | nothing | sim `mirror_cutover_leader_change` |
| Compromised khold node | — | Can corrupt or withhold its groups' blocks (CRCs and XTS catch accidents, not tampering); cannot forge layouts or steer initiators outside the group | possible corruption, never disclosure | codec fuzzing, redirect tests |
| Compromised initiator | — | Group-side QoS (skew-bounded) and fair queueing; `ro` enforced in the group | — | QoS tests |

## Components

| Component | Location | Notes |
|---|---|---|
| Module, config, roles | `services/khold/cmd/khold_node/` | `KHOLD`, module 12, `KYTHIRA_KHOLD_ROLES` |
| Block store | `services/khold/include/kythira/khold/block_store.hpp` | sparse data per drive, meta (CRCs, written bits, suspect ranges, apply mark), punch, crash injection layer |
| Stripe group state machine | `stripe_group.hpp` | append sink, apply, layouts, fencing, reconcile, lagging, region copy |
| Gateway | `gateway.hpp` | sessions, QoS, splitting, v1 translation, route cache |
| Wire | antikythera `src/proto/hold_wire_v2.hpp`, `volume_layout.hpp` | consumed via the overlay port |
| Controller library | `services/khold/include/kythira/khold/controller/` | `khold_controller`, transport interface, export/restore |
| Test controller | `services/khold/cmd/khold_testctl/` | drives clusters for CI, docker-chaos and harbor |
| Simulation | `services/khold/tests/khold_sim/` | simulated clock, net, disks; reference initiator; linearizability checker |
| Core additions | `include/raft/` | append sink, witness voters, commit predicates |

## Error handling

| Status | Meaning | Initiator action |
|---|---|---|
| `not_leader` + redirect | another member leads | follow if the target is in the layout; else try the next member |
| `stale_epoch` | layout epoch mismatch | wait for helm's layout; resend |
| `fenced` | generation retired | fail the attachment's requests; report |
| `read_only` | `ro` attachment wrote | I/O error |
| `throttled` | QoS | back off per the bucket hint |
| `repairing` | range under reconcile | retry after a short backoff |
| `no_space` | drive full under overcommit | I/O error for that request |
| `checksum` | unrepairable block | I/O error for that read |
| `io_suspended` | volume impaired | retry with backoff until the deadline |
| `range` | outside capacity | I/O error |

## Testing strategy

- **Simulation** (`khold_sim`): khold nodes, the reference initiator and
  `khold_controller` on one thread and a simulated clock, with seeded
  network faults, disk crashes, EIO, slow disks, space exhaustion and
  clock drift. Each run records every guest operation and checks
  per-block linearizability (a register per block, Wing-Gong search, as
  antikythera's `hold_sim_test`), no lost acknowledged write, no two
  leaders serving reads, and convergence of all replicas after the run
  quiesces. Every row of "Failure cases" is a named case. ctest runs a
  few hundred seeds within its time budget; nightly runs thousands.
- **Block store**: crash-consistency tests that drop unsynced writes at
  every step, including mid-punch and mid-reconcile.
- **Codecs**: antikythera's vectors reproduced; fuzz targets in both
  repositories.
- **Migration paths**, each both ways with a stop and a reversal midway,
  under load: gateway added and removed (co-located ↔ split), data
  replica moved and node evacuated, hold → khold → hold mirror
  migrations attached and detached, v1 ↔ v2 initiator through the
  gateway. Plus a docker-chaos run of the full layout path killing one
  node per layer, on Docker and rootless Podman.
- **Antikythera**: real `InitiatorCore` v2 against `khold_node`; harbor on
  tikhov (Clark's go) with block-volume Requirement 15.3's scenarios on
  khold volumes, a leader EIO, and a mirror migration under load.
- **Measurement**: loopback rows in CI; 1 GbE and 25 GbE hardware rows
  when Clark's hardware is ready (his go per run); khold beside hold on
  the same machines.

## Later options

- **RDMA**: NVMe-oF over RoCEv2 between initiators and gateways or
  leaders, for 100-200 GbE where TCP and TLS cost too much CPU. Most
  25 GbE NICs (ConnectX-4 Lx and later) support RoCEv2, so Clark's
  hardware could test it. It needs switch configuration (PFC/ECN) and
  does not fit the rootless-container test rule, so it stays out of
  phase 1.
- **Follower reads** with ReadIndex, to spread read load within a group.
- **NVMe/TCP or NBD front ends** for hosts outside antikythera, over the
  same gateway.

## Open questions

1. Default stripe unit: 1 MiB (fewer parts, better sequential) or
   256 KiB (better spread of mid-size random I/O)? The design takes
   1 MiB; the measurement task decides.
2. Should the witness store per-block CRCs in its descriptors? Reconcile
   needs only ranges; CRCs would let a witness arbitrate a disputed
   block. The design leaves them out.
3. khold on a storage board or in a storage manager VM (block-volume's
   open question applies unchanged).
4. Should `G_min` be 2 or 4? More groups spread rebuilds further but cost
   more Raft groups per volume; 2 is the starting point.
