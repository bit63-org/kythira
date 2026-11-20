# Implementation Plan

Each task is one PR unless noted. Co-located behaviour must be unchanged
after every task (Requirement 1); each task's tests include the existing
Kinesis and DynamoDB suites. Tasks 1 and 2 come first; 3-5 can then go in
any order; 6 needs 2, 4 and 5; 7 needs 6; 8 needs 3 and 6; 9-11 need 1 and
4; 12, 13, 15 and 16 need the rest of their layer; 14 needs 13 and
every role (7, 8, 10).

- [x] 1. `segment_store` interface in core
  - `include/raft/segment_store.hpp`: abstract class with the store's
    write and read sides; `record_segment_store` derives from it
  - Kinesis `stream_state_machine`, DynamoDB `item_state_machine`,
    `raft_backend` and `change_log` take `segment_store*`
  - No behaviour, layout or test change; a benchmark row shows append and
    barrier cost unchanged
  - _Requirements: 9.1, 12.1_

- [ ] 2. Named data-layer queries and `data_access`
  - `kinesis_data_access.hpp`: the concept (propose, transact, group_of,
    leads, now_ms, shard_state, read_records, find_stream, list_streams,
    leases, catalog id) and `local_data_access<Host>` over
    `raft_stream_cluster`
  - Move `kinesis_service` and `lease_api` off `stream_cluster::read`
    callbacks onto the queries; maintenance and on-demand keep callbacks
  - Measure the local path against main before merging (Requirement 1.2)
  - _Requirements: 1.2, 3.1, 3.3_

- [ ] 3. Layer identity
  - `include/raft/layer_identity.hpp`: role set in the SAN URI, issued by
    the CA (`issuing_tls_material_source`) or supplied; per-route role
    checks on the Beast server; reload without restart
  - `kythira_node` and `kinesis_gateway_node` load it; HMAC forward secret
    still accepted between co-located data nodes without TLS
  - Status: the core pieces are on `main` (`include/raft/layer_roles.hpp`,
    `include/raft/layer_identity.hpp`, the Beast server's `tls_source`
    rotation, `tests/layer_identity_test.cpp`); loading it in the two nodes
    lands with task 4, after the channel delivery PRs that edit the
    Kinesis node's configuration
  - _Requirements: 7.1-7.5_

- [ ] 4. `KINESIS_ROLES` and role validation
  - Config, aliases in `kythira_node`, start-time validation with messages
    naming what is missing, `KYTHIRA_PEERS` may omit self without `data`,
    no Raft log or store opened without `data`, roles in `/healthz` and
    `/metrics`
  - Relax service colocation's same-module-set check to Raft members of a
    module's groups
  - _Requirements: 2.1-2.6, 1.5_
  - Status: `KINESIS_ROLES` is parsed and checked at start. A set this
    build cannot serve stops the node, naming the task it waits on. All
    four roles and `data,segments` are served. A `data,segments` node
    keeps the internal endpoints, `/healthz` and `/metrics`, and answers
    the Kinesis API, the Lease API and `SubscribeToShard` with a 404
    naming its roles. The roles appear in `describe`, in an
    `x-kythira-roles` header, and as `kythira_kinesis_role{role=...}`.
    Still open:
    - roles in `/healthz` through `module_health::roles` (it comes with
      the DynamoDB layers' #863);
    - `KYTHIRA_PEERS` without self, and no Raft log without `data`, which
      only become reachable with task 6;
    - relaxing service colocation's same-module-set check.

- [x] 5. Route cache in core
  - `include/raft/route_cache.hpp`: range map with epochs, leader hints,
    suspect addresses, refresh on stale epoch, not-leader, unknown group
    and connection failure; `net_resolve` for names
  - The `multi_raft` side: a `routes(range)` answer from the shard map and
    leader hints, and a stale-epoch check on incoming data-layer calls
  - Unit tests for splits, merges, leader changes and replica moves
  - _Requirements: 6.1-6.5_

- [ ] 6. Data-layer API and `remote_data_access`
  - `kinesis_data_api.hpp`: `/_kythira/kinesis/v2/` routes on the internal
    listener (`KINESIS_INTERNAL_LISTEN`, default the gateway listener) and
    their client; propose without onward forwarding, consistent reads for
    the Lease API, ciphertext `read_records` with today's limits
  - `remote_data_access` and `hybrid_data_access` (local first, then
    remote, per call)
  - In-process test: a front-end-only node over two layouts of data nodes
  - _Requirements: 3.2, 5.1-5.6_

- [ ] 7. Front end without the data role
  - Wire `remote_data_access` into the module when the node lacks `data`;
    `KINESIS_DATA_NODES`; the whole API served from a front-end-only node
  - Run the in-process service tests parameterised over layouts
    (co-located, front end apart, mixed)
  - _Requirements: 2.3, 3.4, 15.1_

- [ ] 8. Gateway apart from the front end
  - `kinesis_authenticated_call.hpp`: the SigV4-verified handoff (CBOR),
    the front end's role check and trust of the asserted principal; the
    core `sigv4_verifier` entry point that returns principal and context
    keys without dispatching
  - `kinesis_affinity.hpp`: rendezvous hashing by shard and account,
    failover only for calls not executed
  - EFO over a streaming internal call; Lease API and `/metrics` through
    the gateway; drain
  - _Requirements: 4.1-4.7, 8.2-8.5, 12.5_

- [x] 9. Volume service and `remote_segment_store`
  - `include/raft/segment_volume_service.hpp` (one `record_segment_store`
    per volume under `<data_dir>/volumes/`) and `remote_segment_store`
    (pipelined appends, coalesced remote barrier, epoch on every write)
  - Restart, torn-tail truncation, `truncate_after` and `drop_stream`
    remotely; byte-identical files checked against a local store fed the
    same appends
  - Built: each append is one request (it must return the segments that
    rolled, and predicting rolls on the data node would re-implement the
    file format), with no fsync until the coalesced barrier; the volume API
    is served by `segment_volume_service::handle()` over a caller-supplied
    transport, which task 10 puts on the internal listener
  - _Requirements: 9.1-9.3, 9.6, 9.7_

- [ ] 10. Segment-store role and volume assignment
  - The `segments` role; volume assignment in the catalog
    (`\0meta/kinesis/volumes/`), placement on distinct segment nodes and
    placement groups; a data node without `segments` opens its volume from
    the assignment
  - A lost or refused volume stops the replica and triggers replacement;
    test that acknowledged writes survive losing one segment node
  - Segment free space reported to the data layer's capacity policy
  - Status: placement, the segment node and data nodes on volumes are on
    `main`. `include/raft/segment_volume_placement.hpp` places each
    replica's volume on a distinct segment node (placement groups spread,
    most room first, epoch raised on replacement);
    `KINESIS_SEGMENT_NODES` names the segment layer; `KINESIS_ROLES=segments`
    is a segment node serving `POST /_kythira/kinesis/v1/volume`, and
    `KINESIS_ROLES=data` (or with gateway and front end) keeps its segments
    on the volume placed for it. The volume API's `space` op feeds the data
    node's `capacity_probe` and disk guard. A lost volume halts the
    replica's apply (the store throws) and fails `/healthz`; the
    lose-one-segment-node case is `kinesis_stream_state_machine_test`'s
    `segment_layer` suite. First placement comes from the settings, the
    same on every node. Left for the rest of this task: the assignment
    replicated in the catalog (`\0meta/kinesis/volumes/<node id>`) so a
    replacement's new epoch reaches every node through Raft, and the
    replacement triggered by placement when a replica stops
  - _Requirements: 9.4, 9.5, 9.8, 9.9, 10.6, 13.4_

- [ ] 11. Layer membership group
  - `include/raft/layer_membership.hpp`: single Raft group, fixed voters,
    every other stateless node a learner; members, roles, drain state,
    load reports, shared settings version
  - Affinity and data-node discovery from it, or from configuration and
    DNS discovery when it is off
  - Status: the core is on `main` (`include/raft/layer_membership.hpp`:
    the state machine, `member_directory` with its configuration and
    replicated forms, and a three-voter-plus-learner group test); running
    the group inside the gateway and front-end processes lands with tasks 7
    and 8, which consume the directory
  - _Requirements: 10.1-10.3_

- [ ] 12. Stateless-layer scaling through `quorum_manager`
  - A `capacity_policy` over layer load signals, run by the membership
    group's leader with elastic shard capacity's control loop, bounds,
    budget, kill switch and ledger; drain before `decommission_node`
  - Docker quorum manager test that scales front ends up and down under
    load without failed requests
  - _Requirements: 10.4, 10.5_

- [ ] 13. Live migration operations
  - `evacuate` admin call over the placement operators; refuse to start
    without `data` while holding replicas
  - In-place store move (copy sealed, copy active prefix, bounded fence,
    switch, assignment through Raft) with its pause measured
  - Unit and in-process tests of each operation on its own
  - _Requirements: 11.2-11.5_

- [ ] 14. Migration path tests
  - One in-process test per path, each run in both directions and each
    under a producer and a GetRecords/EFO consumer, checking no lost or
    duplicated acknowledged record, per-shard order and sequence numbers,
    iterators issued before the step still valid, and KCL leases kept:
    - gateway role split off and folded back (drain, restart)
    - front-end role split off and folded back
    - data role evacuated to data-only nodes and back to co-located nodes
    - segments moved local to volume and back by replica replacement
    - segments moved local to volume and back by in-place store move
    - full co-located to four-way split and four-way split back to
      co-located, stopping and reversing at a middle step
  - docker-chaos scenario: the full path both ways under a KPL producer
    and KCL 2.x consumer, killing one node per layer along the way, on
    Docker and rootless Podman
  - A CI job runs the in-process path tests on every Kinesis change; the
    docker-chaos path runs in the Kinesis module workflow
  - _Requirements: 11.1, 11.6, 11.7, 13.1-13.3, 15.4, 15.7_

- [ ] 15. Compose layout, differential and measurement
  - Four-service compose file wired by service name, Docker and rootless
    Podman; SDK, KPL, KCL 2.x and 3.x against it; DynamoDB destination
    with and without a co-located Kinesis gateway
  - The differential suite against the four-way split
  - Measurement row: co-located vs split latency percentiles and
    throughput, co-located against today's row
  - _Requirements: 12.3, 12.4, 15.2, 15.3, 15.5, 15.6_

- [ ] 16. Interoperability with real AWS
  - CI (no spend): the recorded AWS Kinesis fixtures replayed against the
    four-way split layout, through the differential harness
  - Real-cloud bundle (dispatch-only, enabled by a repo variable rather
    than a new workflow input): the split layout with the `aws` KMS
    provider for stream encryption; KCL 3.x with its lease table in real
    AWS DynamoDB; the SDK, KPL and KCL suite run against real AWS Kinesis
    and against the split layout with the observed results compared
  - Each run needs Clark's go in his own words, reports its cost and
    deletes the streams, tables and keys it made
  - _Requirements: 15.8_

- [ ] 17. Observability and documentation
  - Per-role metrics, request id across layers in logs and OTLP traces,
    admin listing of nodes, roles and volumes
  - `services/kinesis/doc/independent-layers.md`: layers, settings,
    identities, sizing, trade-offs, migration runbook both ways; pointer
    from the Kinesis design
  - _Requirements: 11.8, 14.1-14.3, 16.1-16.3_
