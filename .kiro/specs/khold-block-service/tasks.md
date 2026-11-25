# Implementation Plan

Each task is one PR unless noted. Tasks marked **(antikythera)** land in
`bit63-org/antikythera`; the rest land here. khold depends on the
multi-raft host (hibernation, batching, load buckets), `membership-change`,
`non-voting-nodes`, `file-install-snapshot`, the service module interface,
the shared core pieces of `.kiro/specs/kinesis-independent-layers/`
(layer identity, route cache), and `ec2-compatible-api` task 1's overlay
port for antikythera's `src/proto/` (a task that needs one of these first
builds it to that spec's design).

Order: 1-5 first (2 and 3-5 in parallel); 6 and 7 need 3-5; 8 needs 2
and 7; 9-12 need 8; 13 needs 9 and 11; 14-15 need 13; 16-17 need 2 and
can start at once in antikythera; 18-20 need 11, 13 and 16; 21 needs
`ec2-compatible-api` task 9; 22 needs 13, 16 and 17; 23-24 need 13; 25
and 26 run alongside. Phase 2 (27-29) follows phase 1. 30-31 close the
spec.

## Phase 1: khold serves network volumes

- [x] 1. Module skeleton
  - `KHOLD` Kconfig option (default off), `services/khold/`, module
    number 12 in `module_numbers`, boundary list,
    `configs/ci_no_khold_defconfig`, `khold-module.yml` (Docker and
    rootless Podman, path-filtered)
  - Consume antikythera's `src/proto/` through the overlay port; a test
    reproducing its hold wire and report vectors byte for byte
  - Done: `vcpkg-overlays/antikythera-proto` pins antikythera after
    bit63-org/antikythera#117; `khold_proto_vectors_test` reproduces
    vectors 4 and 6-11. khold builds only where `std::expected` compiles
    (GCC 13+, Clang 19+), so the Clang 18 legs and clang-tidy skip it
    (`services/khold/README.md`)
  - _Requirements: 1.1-1.4_

- [x] 2. **(antikythera)** Hold wire version 2 and `VolumeLayout` codecs
  - `src/proto/hold_wire_v2.hpp` beside version 1: group ID and term in
    the header, `REDIRECT` with leader, endpoint and term, statuses
    `not_leader`, `no_space`, `repairing`, real `DISCARD` and
    `WRITE_ZEROES`, `hydrate` writes
  - `src/proto/volume_layout.hpp`: the signed frame of design "Layouts,
    authority and fencing", decoder rules (stripe width 1-64, five
    members per group, at most one witness, data members ≥ 1, unique
    attachments, `multi_attach` for more than one rw attachment)
  - Reports: `group_status`, `capacity`, `lagging` and `media_error`
    faults
  - Test vectors, fuzz targets, version 1 unchanged
  - Done in bit63-org/antikythera#117: the faults are a `group_fault`
    report kind (lagging, caught_up, media_error, fail_slow, no_space,
    checksum_unrepairable) rather than new volume fault kinds, so hold's
    exhaustive fault switch is untouched; vectors 6-11
  - _Requirements: 11.1, 11.2, 11.5, 16.3_

- [x] 3. Core: append sink on log persistence
  - A persistence-engine hook that hands a state machine an entry's
    payload at append time, before commit, and stores only the
    descriptor in the log; the durable point covers both
  - Unchanged behaviour for every existing state machine; a benchmark
    row shows append cost unchanged without a sink
  - Done: `include/raft/append_sink.hpp`, a persistence-engine adaptor
    (`append_sink_persistence`) rather than a change to `node`: reads
    rehydrate payloads through the sink, so the node, replication and
    `apply` see full entries; a barrier syncs the sink first; start-up
    recovery truncates descriptors whose payload a crash lost
  - _Requirements: 7.4_

- [x] 4. Core: witness voters
  - A member kind that votes and stores descriptors, never campaigns,
    never receives payloads; joint consensus and learner promotion
    handle it
  - Raft property tests: no election of a candidate behind the witness,
    no witness leadership under any schedule
  - Done: `cluster_configuration::witnesses()`, a subset of the voters
    carried in configuration entries and snapshots (omitted when empty,
    so stores without witnesses are byte for byte unchanged);
    `node::promote_to_witness` promotes a learner through the same joint
    path as `promote_to_voter`; a witness never starts an election,
    refuses TimeoutNow and transfers, never serves catch-up, and is sent
    descriptors only (`describing_append_sink::describe`)
  - _Requirements: 5.2_

- [x] 5. Core: commit predicates and lagging entries
  - Per-group commit predicate replacing "majority"; khold's predicate
    (majority, every non-lagging data replica, at least one data
    replica), `lagging(member)` and `in_sync(member)` entries, the member
    deadline, the `majority` option
  - Property tests with crashes and partitions at every step
  - Done: `raft_configuration::_commit_rule` (`majority`, the default,
    or `all_in_sync`) and `_member_deadline`; the lagging marks are
    `cluster_configuration::lagging()`, set and cleared by plain
    configuration entries the leader appends from the heartbeat tick, so
    they revert on truncation and ride in snapshots. Each index is judged
    by the configuration in force at it, so a write before a marker
    commits only with the marker. Reporting a lagging member to the
    controller (7.3) is the stripe group's, task 7
  - _Requirements: 7.1-7.3, 7.5, 7.6_

- [ ] 6. Block store
  - Sparse data per replica on its assigned drive, meta with CRC32C per
    block, written bits, suspect ranges and the apply mark; punch for
    `DISCARD`/`WRITE_ZEROES`; `no_space` before append; EIO mapped to
    store failure (writes, metadata, fsync, log) or bad block (reads)
  - A file layer with crash and EIO injection; crash-consistency tests
    dropping unsynced writes at every step, mid-punch included
  - _Requirements: 2.4, 4.1, 4.2, 4.5, 8.4, 9.3, 9.4, 20.3_

- [ ] 7. Stripe group state machine
  - Append sink into the block store; apply; leader lease and ReadIndex
    reads; reads wait for overlapping uncommitted entries; suspect
    ranges and reconcile on election; layouts committed through the log
    with joint consensus; epoch, generation and term fencing; per-group
    QoS with the skew allowance
  - _Requirements: 2.5, 2.6, 6.2-6.6, 8.1-8.3, 13.1_

- [ ] 8. Simulation
  - `khold_sim`: simulated clock, network (loss, delay, reordering,
    symmetric and asymmetric partitions), disks (crash drops unsynced
    data, EIO, slow), clock drift within the bound; a reference
    initiator from antikythera's version 2 codecs; per-block
    linearizability (Wing-Gong), no lost acknowledged write, no two
    leaders serving reads, replica convergence at quiescence
  - First named cases: `leader_crash`, `follower_crash`, `witness_crash`,
    `all_crash`, `asymmetric_leader_cut`, `no_up_to_date_replica`
  - ctest runs a few hundred seeds in its budget; a nightly job runs more
  - _Requirements: 20.1, 20.2_

- [ ] 9. Gateway function, co-located
  - Sessions, `HELLO`, attachment checks, per-attachment QoS, splitting
    at stripe units, per-volume fair queueing, `REDIRECT`s only to layout
    members, in-process hand-off to led groups
  - _Requirements: 11.3, 11.4, 13.1, 13.2, 14.2, 16.4_

- [ ] 10. Failure handling and rebuild
  - Store failure → stop acking, leadership transfer, `media_error`;
    fail-slow detection; region copy for lagging members (payload window,
    changed-region bitmap after compaction); learner rebuild streamed
    from disk with sparse ranges skipped; paced rebuild traffic;
    leadership transfer for moves; `evacuate`
  - Sim cases: every row of design "Failure cases" not covered by task 8,
    including `leader_eio_write`, `leader_eio_read`, `follower_eio`,
    `drive_loss`, `server_loss`, `slow_disk_*`, `controller_link_cut`,
    `controller_outage`, `log_full`
  - Measured: 1 TiB volume back to full redundancy after a server loss
    (loopback and, later, task 23's hardware)
  - _Requirements: 9.1-9.8, 10.1-10.6_

- [ ] 11. `khold_controller` and the test controller
  - Deterministic library: placement with failure domains, drives,
    reservations and overcommit watermarks; stripe width selection from
    capacity reports; layouts and epochs; attachments and generations;
    lagging and replacement ordering (fewest up-to-date first, spread);
    moves and drains; scrub scheduling; lineage key erasure hooks;
    export/restore; decisions reported before acting
  - `khold_testctl` drives clusters for CI, docker-chaos and harbor
  - Sim cases: `overcommit_full`, `compute_loss_fenced`, `stale_layout`
  - _Requirements: 2.3, 3.1, 3.2, 4.3, 4.4, 4.6, 5.1, 5.3-5.5, 6.1, 6.7, 9.6, 12.2, 13.3, 18.1, 18.2_

- [ ] 12. Scrub
  - Every replica scrubbed at least every 14 days, paced, one per drive
    at once; repair from peers; `checksum_unrepairable` handling
  - Sim cases: `bit_rot`, `scrub_mends`
  - _Requirements: 8.4_

- [ ] 13. `khold_node` and the co-located cluster
  - Daemon, `KYTHIRA_KHOLD_ROLES` (default `gateway,data`), TLS
    identities (storage CA certificates on antikythera, static in CI),
    controller keys, Raft traffic accepted only from layout members,
    `kythira_node` module registration, `/healthz` and `/metrics`
  - Container test of a co-located cluster under load, Docker and
    rootless Podman, wired by service name
  - _Requirements: 1.2, 2.2, 6.3, 14.1, 16.1-16.3_

- [ ] 14. Split layout
  - Gateway-only nodes, layer identities (`khold` service, per-route role
    checks), route cache refreshed by `REDIRECT`s, layouts naming gateway
    endpoints, version 1 initiators served by translation
  - _Requirements: 14.1, 14.3-14.5_

- [ ] 15. Migration tests: layouts and data role
  - Co-located → split → co-located with a stop and a reversal midway,
    under mixed load, checking Requirement 15.5
  - Replica move and node evacuation, leader and follower, both ways
  - docker-chaos: the full layout path killing one node per layer, on
    Docker and rootless Podman
  - _Requirements: 15.1, 15.2, 15.5, 20.4_

- [ ] 16. **(antikythera)** oar-blk initiator version 2
  - Stripe map, per-group sessions (or per-gateway), leader cache,
    redirects only to layout members, resend of unacknowledged parts,
    splitting at stripe units, `no_space` and `repairing` handling,
    virtio-blk discard and write-zeroes for khold volumes
  - Forward `take_faults()` to helm as `volume_fault` reports (also for
    hold volumes)
  - _Requirements: 3.3, 3.4, 4.2, 9.9, 11.3, 11.4_

- [ ] 17. **(antikythera)** helm and inventory for khold
  - Storage role type `khold`: launch, `cert_request` with role `khold`,
    `VolumeLayout` relay and replay byte for byte, acknowledged reports
  - Inventory: storage link speed, per-drive capacity and measured
    IOPS and throughput from a short self-test at enrollment and on
    demand
  - _Requirements: 12.1, 16.1_

- [ ] 18. Mirror migration, khold and controller side
  - Controller: prepare, mirror, copy, cut-over, stop and reverse as one
    committed state machine per migration; copier with progress marks;
    `hydrate` writes honoured by the block store's written bits
  - Sim cases: `mirror_source_failover`, `mirror_target_failover`,
    `mirror_cutover_leader_change`
  - _Requirements: 15.3, 15.5_

- [ ] 19. **(antikythera)** Mirror migration, oar-blk and hold side
  - oar-blk mirror backend (writes to both, reads from the source,
    cut-over on the new epoch)
  - hold as a mirror source and target: per-block written bits for
    `hydrate`, the copier's reads
  - _Requirements: 15.3_

- [ ] 20. Migration tests: backends and protocol versions
  - hold → khold → hold, attached and detached, with a stop and a
    reversal midway, under mixed load, checking Requirement 15.5
  - Version 1 initiator through a gateway ↔ version 2 initiator direct,
    on re-attach, both ways
  - _Requirements: 15.3-15.5, 20.4_

- [ ] 21. EC2 module integration
  - Class → backend configuration (default `hold`); the EC2 data layer
    runs `khold_controller` beside the hold volume master on each volume
    group's leader over committed state; khold volumes skip the hold
    lease path; `DescribeVolumes` unchanged
  - _Requirements: 18.1, 18.3_

- [ ] 22. **(antikythera)** Interop and harbor
  - CI: real `InitiatorCore` version 2 against a real `khold_node`
  - harbor (tikhov, Clark's go): block-volume Requirement 15.3's
    scenarios on khold volumes, a leader disk EIO under load, and a
    hold → khold mirror migration under load
  - _Requirements: 2.1, 20.5_

- [ ] 23. Measurement
  - Rows for random 4 KiB read and write IOPS, sequential throughput,
    p50/p99 at queue depths 1 and 32, one volume and many, co-located
    and split, khold beside hold: loopback in CI; 1 GbE and 25 GbE
    hardware when ready (Clark's go per run)
  - Settle the default stripe unit (design open question 1) and the
    25 GbE `provisioned` case (one leader cannot carry it; `G` ≥ 3 can)
  - _Requirements: 12.3, 20.6_

- [ ] 24. Data path performance
  - Scatter-gather I/O with `io_uring` (fallback `preadv`/`pwritev`),
    kernel TLS with NIC offload where present, pipelined replication;
    before and after rows from task 23's harness
  - _Requirements: 12.4_

- [ ] 25. Documentation
  - `services/khold/doc/`: configuration, layers and sizing, striping and
    `G`, thin provisioning, overcommit settings and alarms, capacity
    reports, failure handling, migration runbooks, measured rows
  - _Requirements: 21.1_

- [ ] 26. Parity table
  - `services/khold/doc/hold-parity.md`: every block-volume requirement
    and criterion, and every hold unit, simulation and harbor test,
    mapped to khold's equivalent and status; kept current by each task
  - _Requirements: 19.1_

## Phase 2: snapshots, hydration and re-striping

- [ ] 27. Snapshots
  - Crash-consistent cut: a volume-wide barrier (at most 100 ms) and a
    marker entry per stripe group; changed-chunk tracking per group;
    upload in image format v2 from the leaders; multi-volume cuts;
    deletion freeing unreferenced chunks
  - _Requirements: 17.1_

- [ ] 28. Restore, hydration and clones
  - Volumes from snapshots and public images, hydrated on first read and
    in the background through `hydrate` writes; fast snapshot restore;
    clones of the same lineage
  - _Requirements: 17.1, 17.2_

- [ ] 29. Re-striping
  - khold → khold mirror migration to a layout with a new `G` or `SU`;
    `ModifyVolume` beyond the current `G`'s ceiling triggers it
  - _Requirements: 3.5, 13.3, 17.3_

## Parity and retirement

- [ ] 30. Declare parity and migrate
  - Check Requirement 19.2 (every parity row met or waived by Clark,
    tests green in CI and harbor, 14 clean nightly simulation runs);
    switch every class's default backend to `khold`; paced, resumable
    bulk mirror migration of every hold volume
  - _Requirements: 19.2, 19.3_

- [ ] 31. **(antikythera)** Retire hold
  - With no hold volume left and Clark's go: remove the hold role, its
    store, its codecs' use in oar-blk, `ak_hold_master` and their tests;
    keep the version 1 codec only while any gateway still translates it
  - _Requirements: 19.4_
