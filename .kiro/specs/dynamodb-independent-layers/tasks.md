# Implementation Plan

Each task is one PR unless noted. Co-located behaviour must be unchanged
after every task. The shared core pieces (layer identity, route cache,
`segment_store` and the volume service, the layer membership group) are
built by `.kiro/specs/kinesis-independent-layers/` tasks 1, 3, 5, 9 and
11; a task here that needs one first builds it to that spec's design.

- [x] 1. `KYTHIRA_DYNAMODB_ROLES` and role validation
  - Config, `kythira_node` aliases, start-time validation, no engine or
    Raft log without `data`, roles in health and metrics
  - _Requirements: 1.1, 2.1-2.4_
  - Built with the role set from the Kinesis spec's task 3
    (`include/raft/layer_roles.hpp`). Until the remote backend (task 4),
    the handoff (task 5) and remote volumes (task 6) exist, the node
    serves all four roles or `data,segments` and refuses every other set
    at start, naming the missing part; each of those tasks lifts its
    refusal. A `data,segments` voter keeps the gateway's listener for
    forwarded ops and answers clients 404.

- [x] 2. Leader-side workers in the data role
  - Move the TTL sweeper out of the gateway composition; place catalog
    jobs, propagator, publisher, replicator, PITR, backups and exports in
    the data role; tests that a front-end-only node starts none
  - _Requirements: 6.1-6.4_
  - Built as `data_workers.hpp`: the gateway's one-second worker loop
    (TTL sweeper, backups, PITR, exports and imports, bulk puts, vector
    indexes, strong tables, the replicator and the Kinesis publisher),
    built only when the node has the data role. The GSI propagator and
    the catalog jobs were already `raft_backend`'s own. The gateway
    still constructs `data_workers` because the vector worker shares the
    vector API's registry and the strong-table worker waits for the
    gateway's settled table names; a node without a front end (a data
    node) still has the gateway object for its forward listener.

- [x] 3. Op additions, epochs and `remote_backend`
  - Ops for `change_shards`, `read_changes` and `read_stamped_range`;
    route epoch on every op; `remote_backend` and `hybrid_backend` over
    the route cache
  - Handler tests over both backends against an in-process data cluster
  - _Requirements: 3.1-3.6, 7.3, 12.1_
  - Built as `op_wire.hpp` (the op protocol, moved out of
    `raft_backend.hpp`, plus the `routes` and `routed` ops and the
    `stale_epoch` and `unknown_group` answers), `op_client.hpp` (the
    client half of `raft_backend` as a CRTP base, so the three backends
    share one encoding of every call) and `remote_backend.hpp`
    (`remote_backend` and `hybrid_backend`). The three ops named above
    already existed as forwarded ops; what was missing was a way to run
    them on a node with no replica. A data node checks a routed op's
    epoch with the core `check_route` and answers a stale one with the
    current route. Tests in `dynamodb_raft_backend_test.cpp`: the
    handler stack over a `remote_backend` through a split, a
    cross-group transaction and a leader loss; an old-layout routed op;
    a `hybrid_backend` on a follower.

- [x] 4. Front end without the data role
  - Wire `remote_backend` when the node lacks `data`; capacity share over
    live front ends; `DescribeEndpoints` names the gateway layer
  - _Requirements: 4.3, 5.1-5.4_
  - Built as `front_end_node` (`run_cluster.hpp`) and the module's
    `front_end_serving`: `KYTHIRA_DYNAMODB_ROLES=gateway,front_end` with
    `KYTHIRA_DYNAMODB_DATA_NODES` (seed gateways), the forward secret and
    no `PEERS`. Ops go over the existing authenticated forward channel
    (`forward_client::send_to`); data nodes answer routes naming each
    voter's gateway. The live front-end count is configuration for now
    (`KYTHIRA_DYNAMODB_FRONT_ENDS`, also on voters, replacing one over
    the voters when set); following the layer membership group within a
    refresh interval comes with the membership group (Kinesis
    independent-layers task 11). `DescribeEndpoints` already answered
    the node's own advertised endpoint, which is the gateway's; the
    cluster test checks it on a front-end-only node.

- [ ] 5. Gateway apart from the front end
  - The authenticated-call handoff (shared with Kinesis), drain, role
    checks on internal routes, forward secret only from data nodes
  - _Requirements: 4.1, 4.2, 4.4, 8.1-8.3_

- [ ] 6. Change log on remote volumes
  - `change_log` on `segment_store*`; DynamoDB volume assignment in its
    catalog; records sealed before append for encrypted tables
  - _Requirements: 7.1, 7.2, 9.1-9.3_

- [ ] 7. Migration operations
  - `evacuate` for the data role with per-voter range handling; in-place
    store move for the change log; refuse to start without `data` while
    holding replicas
  - _Requirements: 11.1, 11.2_

- [ ] 8. Migration path tests
  - One in-process test per path, each in both directions, under a
    conditional-write, transaction and Streams workload: gateway role,
    front-end role, data role (with per-voter ranges), change log by
    replica replacement, change log by in-place store move, and the whole
    co-located to four-way path and back with a stop and reversal midway
  - Each checks no lost acknowledged write, transaction and condition
    guarantees, every stream record in order per shard, GSI convergence
  - docker-chaos scenario of the full path both ways, killing one node per
    layer, on Docker and rootless Podman
  - _Requirements: 11.3, 11.4, 12.3, 12.5_

- [ ] 9. Compose layout, Kinesis interaction and measurement
  - Four-service compose file wired by name; SDK, KCL 3.x and lock-client
    suites; Kinesis destination with and without co-located Kinesis
    gateway roles; measurement row against today's
  - _Requirements: 10.1, 10.2, 12.2, 12.4_

- [ ] 10. Interoperability with real AWS
  - CI (no spend): recorded AWS DynamoDB fixtures replayed against the
    four-way split layout
  - Real-cloud bundle (dispatch-only, repo-variable switch): Kinesis
    destination to real AWS Kinesis from the split layout; `aws` KMS
    provider for table keys; KCL 3.x reading real AWS Kinesis with leases
    on the split layout; SDK and lock-client suites against real AWS
    DynamoDB and the split layout, results compared
  - Each run needs Clark's go, reports cost, deletes what it made
  - _Requirements: 12.6_

- [ ] 11. Documentation
  - Layers, roles, which layer holds which secret, sizing, runbook
  - _Requirements: 13.1_
