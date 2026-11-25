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

- [x] 2. Named data-layer queries and `data_access`
  - `kinesis_data_access.hpp`: the concept (propose, transact, group_of,
    leads, now_ms, shard_state, read_records, find_stream, list_streams,
    leases, catalog id) and `local_data_access<Host>` over
    `raft_stream_cluster`
  - Move `kinesis_service` and `lease_api` off `stream_cluster::read`
    callbacks onto the queries; maintenance and on-demand keep callbacks
  - Measure the local path against main before merging (Requirement 1.2)
  - _Requirements: 1.2, 3.1, 3.3_
  - Status: `data_access` is an abstract class (the hybrid access picks
    local or remote per call at run time, which a concept cannot):
    `find_stream`, `list_streams`, `streams(filter)`, `find_channel`,
    `find_channel_by_id`, `list_channels`, `shard`, `read_records` (as
    stored, opened on the front end), `local_bytes`, plus `propose`,
    `transact`, `can_transact`, `group_of`, `leads`, `now_ms`. Leases need
    no query: every lease read is already a proposal. The catalog id is
    the catalog group's routing key, not a query.
    `local_data_access<Cluster>` takes any `stream_cluster`, and the
    service and the Lease API take any `data_layer` (a `stream_cluster`,
    wrapped, or a `data_access`). Local path against main, median of five
    runs, g++-13 -O2, `local_stream_cluster` with a segment store:

    | Call | main | task 2 |
    |---|---|---|
    | PutRecords (10 records) | 32.8 us | 32.9 us |
    | GetRecords (100 records) | 145.3 us | 146.9 us |
    | DescribeStreamSummary | 5.44 us | 5.70 us |
    | ListShards | 10.49 us | 10.55 us |

    Within run-to-run noise except DescribeStreamSummary, which now
    copies the account's channels to count them (+0.26 us).

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

- [x] 6. Data-layer API and `remote_data_access`
  - `kinesis_data_api.hpp`: `/_kythira/kinesis/v2/` routes on the internal
    listener (`KINESIS_INTERNAL_LISTEN`, default the gateway listener) and
    their client; propose without onward forwarding, consistent reads for
    the Lease API, ciphertext `read_records` with today's limits
  - `remote_data_access` and `hybrid_data_access` (local first, then
    remote, per call)
  - In-process test: a front-end-only node over two layouts of data nodes
  - _Requirements: 3.2, 5.1-5.6_
  - Built: six routes (`propose`, `transact`, `catalog`, `shard`, `read`,
    `routes`), each signed with the forward secret over path and body or
    admitted by the layer route guard. A data node proposes with
    `propose_here` (never forwards) and answers 409 with a leader hint,
    421 for a stale route epoch, 404 when it holds no replica. Reads ship
    segment records still sealed; the front end opens them. A write that
    got 503 is never retried (its outcome is unknown). The routes are on
    the gateway listener unless `KINESIS_INTERNAL_LISTEN` names its own
    port. Wiring the remote side into a node without `data` is task 7.

- [x] 7. Front end without the data role
  - Wire `remote_data_access` into the module when the node lacks `data`;
    `KINESIS_DATA_NODES`; the whole API served from a front-end-only node
  - Run the in-process service tests parameterised over layouts
    (co-located, front end apart, mixed)
  - _Requirements: 2.3, 3.4, 15.1_
  - Built: `KINESIS_ROLES=gateway,front_end` with `KINESIS_DATA_NODES`
    (`host:port,...` of data nodes' internal listeners, the route cache's
    seeds) builds the same front end, service, Lease API and gateway as a
    data node over `remote_data_access`, and opens no Raft group, store,
    data directory or internal listener. `KYTHIRA_PEERS` may leave it out
    or be unset (Requirement 2.2); it needs the forward secret, which signs
    its data-layer calls and derives the iterator key every front end
    shares. `KINESIS_DATA_NODES` on a node with `data` is refused. Its
    `/metrics` counts data-layer calls, not-leader and stale-route answers,
    and unreachable calls. `front_end` without `gateway` (and the reverse)
    still waits on task 8.
  - Nine in-process suites (service, reads, reshard, throttle, leases,
    tags, channels, encryption, fan-out) run three times from one binary,
    `KINESIS_TEST_LAYOUT` unset, `front_end_apart` and `mixed`
    (`tests/kinesis_layouts.hpp`): apart is `remote_data_access` over the
    peer client and a data node's gateway on loopback; mixed is a hybrid
    front end holding only the catalog group. `kinesis_layouts_test` moves
    one client's writes, iterators and leases co-located to apart and
    back, apart to co-located and back, and through mixed in the middle,
    checking every acknowledged record is read once in order and every
    lease holds (the front-end role's migration both ways, ahead of task
    14's chaos runs). Running them found that the internal listener must
    take a whole `PutRecords` command (`KINESIS_MAX_BODY_BYTES`, as the
    module already sets it).

- [x] 8. Gateway apart from the front end
  - `kinesis_authenticated_call.hpp`: the SigV4-verified handoff (CBOR),
    the front end's role check and trust of the asserted principal; the
    core `sigv4_verifier` entry point that returns principal and context
    keys without dispatching
  - `kinesis_affinity.hpp`: rendezvous hashing by shard and account,
    failover only for calls not executed
  - EFO over a streaming internal call; Lease API and `/metrics` through
    the gateway; drain
  - _Requirements: 4.1-4.7, 8.2-8.5, 12.5_
  - Built: `front_end` splits into `authenticate` (framing, SigV4, decode,
    STS `GetCallerIdentity`) and `execute` (stream check, authorization,
    handler); `handle` is both, so a co-located node is unchanged. The
    entry point that verifies without dispatching already existed:
    `aws_request_authorizer::authenticate`, so `sigv4_verifier.hpp` is
    untouched (Requirement 12.5). `authenticate_lease_request` and
    `lease_api::execute` split the Lease API the same way.
  - The handoff: five routes under `/_kythira/kinesis/fe/v1/` (`call`,
    `subscribe`, `pull`, `cancel`, `metrics`) on every node with
    `front_end`, co-located ones included, so gateways can be put in front
    of an existing cluster. The wire is the catalog codec the data-layer
    API uses, with the input as its JSON text, not CBOR: one binary codec
    for every internal route. A front end admits a caller signing with the
    forward secret over path and body, or a layer identity with `gateway`
    when a route guard is set; anything else is 403 before the call is
    read. The answer is the client's HTTP response, already in the
    client's encoding.
  - Affinity: rendezvous hashing (stable FNV-1a + SplitMix64) of
    (account, stream name, shard ordinal) for `GetRecords` (read from the
    iterator without its MAC), `GetShardIterator` and `SubscribeToShard`;
    of the account for the control plane; writes and leases in turn. The
    design keys by stream id, which a gateway cannot know without the
    catalog; the name in its account names the same stream. A front end
    that could not be reached, or answered 503 `x-kythira-not-executed`
    (draining, not a front end), goes to the back of every order for two
    seconds and the call tries the next one once; a call sent without an
    answer is not retried and answers InternalFailure. `peer_client` gained
    `exchange`, which says whether the request was written.
  - EFO: `subscribe` executes the call and keeps the `event_source` as a
    session; the gateway long-polls `pull` (up to 64 messages per answer)
    and relays messages unparsed. A failed pull or a lost session ends the
    client's stream with `InternalFailureException`; an unpulled session
    is cancelled after 30 s. A sequence of long polls rather than one
    chunked response, because the internal client is one request, one
    response.
  - Roles: `gateway` alone needs `KINESIS_FRONT_ENDS` and the forward
    secret, and keeps nothing on disk; `front_end` without `gateway`
    serves only gateways; `gateway,data[,segments]` hands its calls on.
    The in-process producer is published only with both `gateway` and
    `front_end` (Requirement 12.3).
  - Drain: `POST /_kythira/kinesis/v1/drain` (signed) or SIGTERM: the
    listener stops accepting (`https::server::stop_accepting`, new),
    `/healthz` answers 503, answers close their connections, event streams
    end with the retryable error, and calls in flight get up to
    `KINESIS_DRAIN_TIMEOUT_MS` (10 s); a front end answers new calls as
    not executed. `/metrics` on a gateway alone is one front end's, then
    the gateway's own handoff counters.
  - Tests: `kinesis_gateway_apart_test` (affinity, wire, trust, failover,
    unanswered calls, Lease API, EFO relay and restart, drain, metrics);
    `kinesis_layouts_test` moves one client onto gateways in front of a
    co-located, an apart and a mixed front end and back off, both ways
    (the gateway role's migration paths, ahead of task 14); config cases;
    `kin-gw` in the container scenario. Layer identities are checked when
    a route guard is set; the daemon wires none yet (TLS identities are
    task 3's).

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
    same on every node. The catalog holds each replica's assignment
    (`\0meta/kinesis/volumes/<node id>`, `volume_assignment_command`, an
    epoch compare-and-set); `kinesis_volume_keeper.hpp` on the catalog
    leader seeds it from the settings' placement and, when a segment node
    has not answered `space` for a minute, moves each volume on it to a
    segment node that answers at the next epoch. The volume API's `assign`
    op lets a data node create its volume at the catalog's epoch on a
    segment node that never held it. A data node whose record moved saves
    it to `volume-assignment.json`, reports unhealthy and opens the new
    volume on restart, restoring from its snapshot and peers. Left: a
    container test of a replacement end to end (with task 7's scale test)
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
  - Status: the core is in `include/raft/layer_capacity.hpp`:
    `layer_capacity_snapshot`, `layer_capacity_policy` and
    `layer_drain_hooks`. It also adds `capacity_drain_hooks` to the
    controller, so a member that holds no replica is decommissioned only
    after its own work drains. Running the controller on the membership
    group's leader, and the Docker test, land with task 7, which is the
    first task with front-end-only nodes to scale.

- [x] 13. Live migration operations
  - `evacuate` admin call over the placement operators; refuse to start
    without `data` while holding replicas
  - In-place store move (copy sealed, copy active prefix, bounded fence,
    switch, assignment through Raft) with its pause measured
  - Unit and in-process tests of each operation on its own
  - _Requirements: 11.2-11.5_
  - Status: done.
    - Evacuation: `include/raft/replica_evacuation.hpp` is a stateless
      planner (`next_evacuation_step`: add the target as a learner, resume
      it, promote, hand leadership off, remove the evacuee) and
      `replica_evacuator`, which each group's leader runs one change at a
      time. `tests/replica_evacuation_test.cpp` covers the planner and
      moves every replica off a node and back on a four-host fabric under
      writes, none lost.
    - The admin calls are under `/_kythira/kinesis/v1/admin/`, signed with
      the forwarding secret (`kinesis_migration.hpp`,
      `cmd/kinesis_gateway_node/migration_admin.hpp`): `evacuate` (fanned
      out to every data node), its status merged across them, `cancel`,
      `release`, `descriptor` (what a joining node's lazy replica
      creation asks its peers) and `store-move`.
      `kinesis_gateway_node --admin` makes one call.
    - `KINESIS_VOTERS` names the founding voters, and a data node left out
      joins as an evacuation target. A node holding replicas refuses to
      start without `data` until it was released (or
      `KINESIS_DISCARD_REPLICAS`); a released node that later starts as a
      data node joins rather than re-forming its groups.
    - The store move: `include/raft/segment_store_move.hpp`
      (`movable_segment_store::move_to`) copies in rounds, takes the
      fence once the tail is under `_max_fence_bytes`, appends the tail,
      checks the copy, switches and reports the pause. Segments above
      `_max_call_bytes` are copied as batched appends, because a segment
      node's gateway caps request bodies. The node saves the new
      assignment under the fence and then writes it to the catalog at the
      next epoch, since proposing under the fence could stall the apply
      loop. `keep_volumes` republishes a saved record newer than the
      catalog's. `tests/segment_store_move_test.cpp` moves local to
      volume and back under a writer and checks the files are byte
      identical. The move tests found a `record_segment_store::read` bug,
      fixed with a conformance case: a byte limit reached inside a
      segment skipped the rest of it.
    - Checked against real daemons on loopback: four nodes evacuating
      node 1 to node 4, restarting node 1 without `data` and back, then
      evacuating node 4 to node 1, with 4,019 acknowledged writes all read
      back. One data node and one segment node moving local to volume,
      back, and to the volume again (48 MB of active segments) under
      writes, with pauses of 9 to 52 ms, restarting on the volume, and
      all 24,065 writes read back.
    - Left for task 14: the store move's in-process migration test and
      the container scenario. Known limitation: until a restart, the disk
      guard and capacity probe keep following the store the node started
      with.

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
  - Status: the in-process paths are `kinesis_migration_test`, which the
    Kinesis module workflow runs with the rest of the `kinesis` label on
    every Kinesis change. Each path runs both ways under a producer, a
    GetRecords consumer and a SubscribeToShard consumer, and checks every
    acknowledged record is read once and in order by both, sequence
    numbers only rise, TRIM_HORIZON and LATEST iterators issued before
    each step work after it, and every lease taken stays held. Covered:
    the gateway role (with a drain and a front-end restart), the front-end
    role, the data role evacuated to data-only nodes and back, segments to
    volumes and back by replica replacement and by the in-place store move
    (each replica's store is a `movable_segment_store`, moved under
    traffic), and the whole way to the four-way split and back, reversing
    half way. The data layer is one
    hand-played Raft group whose replicas move as a learner (sealed
    segments copied under traffic, then a fence for the snapshot and the
    active prefix); `tests/kinesis_cluster_handle.hpp` lets the compiled
    layouts run over it. Left: the docker-chaos scenario
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
