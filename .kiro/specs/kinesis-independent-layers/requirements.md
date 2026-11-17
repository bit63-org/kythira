# Requirements Document

## Introduction

The Kinesis service (`.kiro/specs/kinesis-compatible-streams/`) is built
from five layers:

1. the **gateway**: the AWS JSON 1.1 and CBOR protocols, SigV4, STS
   `GetCallerIdentity`, the HTTP/2 event stream of enhanced fan-out (EFO);
2. the **front end**: the operation handlers, shard routing (partition key
   to hash key to open shard to routing key), the KCL lease API, iterators
   and rate limiting;
3. **multi-Raft routing**: the `multi_raft` host that maps a routing key to
   a group and a group to its leader;
4. the **stream state machine**: the catalog, per-shard counters and the
   segment index;
5. the **record segment store**: the core component that keeps record
   bytes in segment files outside the Raft snapshot, shared with DynamoDB's
   change log.

Layers 3 and 4 cannot be separated: the state machine is what the Raft
groups replicate. This spec treats them as one **data layer**, so there are
four layers: gateway, front end, data, and segment store.

Today every `kinesis_gateway_node` runs all four in one process
(co-located):

- `KYTHIRA_PEERS` must include the node's own id
  (`cmd/kinesis_gateway_node/config.cpp`), so every process that answers
  clients is a Raft voter, and adding client capacity means adding voters.
- The front end is transport-free and reads through `stream_cluster::read`,
  a callback on the **local** replica's state machine
  (`kinesis_cluster.hpp`, `kinesis_service.hpp` `read_shard_state` and
  `read_catalog`). `GetRecords`, `Describe*`, `ListShards` and
  `SubscribeToShard` are answered only from a local replica, and record
  bytes are read straight from the local `record_segment_store`.
- A write whose group this node does not lead is forwarded to the leader's
  gateway (`POST /_kythira/kinesis/v1/propose`, `kinesis_forward.hpp`),
  found through the `shard_not_leader` hint, and authenticated with an
  HMAC under a secret every gateway shares (`KINESIS_FORWARD_SECRET`).
  Segment fetch and transaction ops use the same secret.
- Write admission (the per-shard write buckets) happens where a command is
  proposed, on the group leader. Read and control-plane buckets live on the
  node that serves the call.
- Raft RPC in the stand-alone daemon is plaintext and needs
  `KYTHIRA_ALLOW_PLAINTEXT_RAFT` off loopback; `kythira_node` speaks mutual
  TLS (`include/raft/kythira_node_host.hpp`).
- The segment store is a directory on the node's disk, written in
  `apply()`, and its `barrier()` is a local fsync.

This spec lets each of the four layers run as its own process or cluster,
sized and scaled on its own, while **co-located operation stays the default
and is never required to change**. A deployment can also move from
co-located to independent operation and back **while it serves traffic**.

It follows Clark's request of 2026-11-17 ("Write a spec that allows these 4
layers to run independently of each other, but the spec shouldn't require
it either. If possible, it should be able to migrate from co-located
operation to independent operation and back") and his agreement that the
gateway layer may have its own independent Raft membership for scaling.

**Scope**: per-node layer roles; a data-layer API reachable over the
network (proposals, reads, catalog queries, routing); remote reads and
subscriptions; a route cache; cross-layer authentication; where each kind
of rate limit lives; the segment store as a remote service and its
durability; an optional membership group for the stateless layers, scaled
through `quorum_manager`; live migration in both directions; the effect on
DynamoDB; observability; tests and documentation.

**Out of scope**: splitting DynamoDB, Redis, the ledger or IAM into layers
(the core pieces are reusable, but each service needs its own spec);
changing the Kinesis wire API or its semantics; replacing Raft replication
of the data layer with replication inside the segment store; running the
layers under one supervisor process.

## Glossary

- **Layer**: one of gateway, front end, data, segment store.
- **Role**: a layer a given process runs. A node's **role set** is any
  non-empty subset of the four layers. A node with all four is
  **co-located**, today's model.
- **Independent operation**: at least one layer runs on processes that do
  not run some other layer. Any mix of co-located and single-role nodes is
  a valid deployment.
- **Data node**: a node with the data role. Only data nodes are Raft
  members of Kinesis's groups.
- **Stateless layers**: the gateway and the front end. They hold caches and
  token buckets, never durable state.
- **Data-layer API**: the internal API a data node offers to front ends:
  propose, transact, shard reads, record reads, catalog queries and routes.
- **Route**: for a routing key, the owning group, its key range, its
  replicas, its leader (when known) and each replica's data-layer address.
- **Segment node**: a node with the segment-store role.
- **Volume**: one data replica's private segment store on a segment node,
  holding exactly the files the local store would hold.
- **Layer identity**: an X.509 certificate that names the node's id,
  cluster and role set, used for mutual TLS between layers.
- **Layer membership group**: an optional single Raft group the stateless
  layers use for membership, shared settings and capacity decisions.
- **Affinity**: the rule that sends each shard's reads, and each account's
  control-plane calls, to one front end.

## Requirements

### Requirement 1: Co-located operation stays the default

**User Story:** As an operator running Kinesis today, I want nothing to
change unless I ask for independent layers.

#### Acceptance Criteria

1. With no new setting, a node SHALL run all four roles, and its
   configuration, data directory, ports, wire formats and observable API
   behaviour SHALL be exactly today's.
2. A co-located node SHALL serve local reads and local-leader writes
   in-process, without a network hop or a serialisation step beyond
   today's, so co-located latency and throughput do not regress by more
   than measurement noise (Requirement 15.5).
3. Every existing Kinesis test, compose file and docker-chaos scenario
   SHALL pass unchanged.
4. Independent operation SHALL never be required by any feature: every
   feature of the Kinesis spec SHALL work in a cluster of co-located nodes.
5. `kythira_node` and the stand-alone `kinesis_gateway_node` SHALL offer
   the same roles, since the latter is a one-module `kythira_node`
   (`.kiro/specs/service-colocation/` Requirement 3).

### Requirement 2: Layer roles

**User Story:** As an operator, I want to choose which layers each process
runs, so I can size each layer on its own.

#### Acceptance Criteria

1. A node SHALL take its role set from `KINESIS_ROLES`, a comma-separated
   subset of `gateway`, `front_end`, `data`, `segments`; default all four.
   (The name avoids `KINESIS_TIER_*`, which configures object-storage
   tiering.)
2. A node without the `data` role SHALL NOT be a Raft member of any Kinesis
   group, SHALL NOT need `KYTHIRA_PEERS` to include its own id, and SHALL
   NOT open a Raft log or a record segment store.
3. A node with `gateway` but not `front_end` SHALL send every decoded,
   authenticated call to a front end (Requirement 4). A node with
   `front_end` but not `data` SHALL use the data-layer API of data nodes
   (Requirement 5). A node with `data` but not `segments` SHALL keep its
   segments on segment nodes (Requirement 9).
4. A role set with no way to serve its role SHALL stop the node at start
   with a message naming what is missing: for example `gateway` alone with
   no front-end endpoints or membership group, or `data` without
   `segments` with no segment-node assignment.
5. Roles SHALL be per module: in `kythira_node`, `KINESIS_ROLES` affects
   only the Kinesis module. Service-colocation's rule that every node runs
   the same module set SHALL apply only to the nodes that are Raft members
   of that module's groups, so a gateway-only Kinesis node does not have to
   be a DynamoDB or IAM voter.
6. A node's `/healthz` and `/metrics` SHALL report its role set.

### Requirement 3: One code path for local and remote

**User Story:** As a maintainer, I want the co-located and independent
modes to run the same handlers, so the mode does not fork the service.

#### Acceptance Criteria

1. The operation handlers (`kinesis_service`), the lease API, the
   maintenance pass and the on-demand controller SHALL reach the data layer
   only through an interface that has a local implementation (today's
   `raft_stream_cluster` and the local store) and a remote implementation
   (the data-layer API), selected per call.
2. The selection SHALL be per call, not per cluster: a front end with a
   local replica of a key's group reads it locally; a front end that leads
   a key's group proposes locally; otherwise it goes remote. A
   co-located node in a cluster that also has single-role nodes therefore
   needs no mode switch.
3. `stream_cluster::read`'s callback on a live state machine SHALL be
   replaced, for the handlers' purposes, by named queries that return
   values (shard state, stream records, stream listings, leases, the
   iterator and catalog entries the handlers read today), so the same
   query can be answered by a remote data node. The callback form MAY
   remain for code that runs only on a data node.
4. An answer SHALL be the same in both modes, byte for byte at the AWS API,
   except for request ids and timing. The differential suite SHALL run in
   both modes (Requirement 15.2).

### Requirement 4: Gateway layer

**User Story:** As an operator, I want a gateway layer that terminates
client connections, TLS, SigV4 and EFO streams, so connection count and
protocol work scale apart from the data.

#### Acceptance Criteria

1. The gateway SHALL frame and decode requests (JSON 1.1 and CBOR),
   enforce request limits, verify SigV4 and answer STS
   `GetCallerIdentity`, then hand the front end an **authenticated call**:
   the operation, the decoded input, the verified principal, the encoding
   to answer in, and the request context keys IAM conditions read (source
   IP, secure transport, request tags, current time).
2. Authorization SHALL stay in the front end, which holds the resource
   lookups it needs (stream tags, resource policies). A gateway SHALL NOT
   need catalog access.
3. A front end SHALL accept an authenticated call only from a peer whose
   layer identity carries the `gateway` role (Requirement 7). A principal
   asserted by any other caller SHALL be refused.
4. The gateway SHALL choose a front end per call by affinity
   (Requirement 8.3), falling back to another front end when the chosen one
   is unreachable, and SHALL retry a call only when the front end says it
   was not executed.
5. `SubscribeToShard` SHALL be terminated by the gateway: it holds the
   client's HTTP/2 stream and pulls event-stream messages from the front
   end over a streaming internal call. When the front end goes away the
   gateway SHALL end the client stream with the error event AWS uses for a
   retryable failure, so the client resubscribes with its continuation
   sequence number, as it does today when a replica is removed.
6. The Lease API (`/v1/leases/…`) and `/metrics` SHALL be served by the
   gateway in the same way: authenticated at the gateway, executed by the
   front end.
7. A gateway SHALL accept a drain request: it stops accepting new
   connections, finishes in-flight calls up to a bound, and ends EFO
   streams with the retryable error, so it can be restarted or removed
   without failing requests that were not already in flight.

### Requirement 5: Data-layer API

**User Story:** As a front end without a local replica, I want to read and
write the data layer over the network with the same guarantees as a
co-located node.

#### Acceptance Criteria

1. Every data node SHALL offer, on an internal listener:
   - `propose(key, command, admission)` and `transact(writes)`, answered by
     the group's leader, with the same result types and the same
     ambiguity rules as today (a timeout may still commit);
   - `shard_state(key)`: the shard's state as this replica has it,
     including the segment index;
   - `read_records(key, from counter, min timestamp, limits)`: the sealed
     (still encrypted) record bytes and their counters and arrival times,
     read from this replica's store;
   - the catalog queries of Requirement 3.3;
   - `route(key)` and `routes(range)`: Requirement 6;
   - `now_ms()` and the node's applied index for each group it holds.
2. A follower SHALL answer reads from its replica, as today's replica reads
   do. A call MAY ask for a leader read (`consistent`) where the handlers
   need one today (the Lease API's linearizable `GET`); the data node then
   serves it through the leader's read path or refuses it with a route
   hint.
3. A data node that does not lead a key's group SHALL answer `propose` with
   a not-leader error and the leader hint, never forward it again (the rule
   `propose_local` keeps today), so a call crosses at most one data node.
4. `read_records` SHALL return ciphertext for encrypted streams. Record
   sealing and opening, and so KMS access, SHALL stay in the front end, so
   a data node or segment node never needs a stream's data key.
5. A record read SHALL be bounded by the same limits as today's
   (`segment_read_limits`) so one call cannot pin a data node's memory, and
   a missing segment SHALL be fetched (peer, then object store) exactly as
   today before the call answers.
6. Today's `POST /_kythira/kinesis/v1/propose`, segment fetch and `txn`
   endpoints SHALL keep working between co-located nodes, so a rolling
   upgrade of a co-located cluster needs no flag day.

### Requirement 6: Routing without Raft membership

**User Story:** As a front end that is not a Raft member, I want to know
which data node to send each call to.

#### Acceptance Criteria

1. A front end SHALL keep a route cache: routing-key ranges to group,
   replicas, leader and data-layer addresses, filled from any data node's
   `routes` answer and refreshed on a not-leader error, an unknown-group
   error, a connection failure, or an epoch newer than its own.
2. Routes SHALL carry the group's configuration epoch, so a stale route is
   detected by the data node that receives it and answered with the current
   route rather than served.
3. A write SHALL go to the leader in the route; a read SHALL go to the
   nearest replica the route names (the same node when it is local, else a
   replica in the front end's own placement group when one exists), then
   any other replica.
4. The front end SHALL find data nodes from `KINESIS_DATA_NODES` (names,
   resolved at run time with `net_resolve`, never static IPs) or from the
   layer membership group (Requirement 10), and SHALL learn the rest from
   `routes` answers.
5. A Kinesis shard is a routing key, not a group (Kinesis design), so
   resharding a stream changes no route; a group split, merge or replica
   move changes routes and SHALL be picked up through 6.1 without any
   client-visible error beyond a retryable one.

### Requirement 7: Cross-layer authentication

**User Story:** As a security reviewer, I want every call between layers
authenticated and every layer limited to the calls its role needs.

#### Acceptance Criteria

1. Calls between nodes of different roles, and Raft RPC between data nodes
   that run alongside any single-role node, SHALL use mutual TLS with
   layer identities issued by Kythira's certificate authority
   (`.kiro/specs/certificate-authority/`, `issuing_tls_material_source`)
   or supplied by the operator.
2. A layer identity SHALL name the cluster, the node id and the role set
   (a SAN URI such as `kythira://kinesis/<cluster>/<node id>?roles=...`).
   Each internal endpoint SHALL check the caller's roles:
   authenticated calls need `gateway`; the data-layer API needs `front_end`
   or `data`; volume calls need `data`; segment fetch needs `data` or
   `front_end`.
3. A node SHALL refuse to start in a non-co-located role set without
   layer TLS, unless `KYTHIRA_NODE_INSECURE_PLAINTEXT=1` (already the
   composite node's explicit opt-out) is set, which tests on loopback may
   use.
4. Today's HMAC forward secret SHALL remain valid between co-located nodes
   that run without TLS, and SHALL NOT be accepted for any call whose
   caller is not a data node.
5. Certificates SHALL rotate without restart (the TLS reload path of
   `.kiro/specs/grpc-tls-reload/`), and a revoked or expired identity SHALL
   stop being accepted at the next handshake.

### Requirement 8: Where rate limits live

**User Story:** As an operator, I want AWS's throughput limits to hold no
matter how the layers are split.

#### Acceptance Criteria

1. Write admission (per-shard write buckets) SHALL stay on the data-layer
   leader that proposes the command, as today, in every role layout. A
   front end SHALL pass the admission mode through `propose`.
2. Read buckets, `GetShardIterator` buckets, per-account control-plane
   buckets and EFO per-consumer buckets SHALL live in the front end that
   serves the call.
3. The gateway SHALL route by affinity: a shard's reads, iterator calls
   and subscriptions to one front end chosen by rendezvous hashing of
   `(stream id, shard ordinal)` over the live front ends; an account's
   control-plane calls by `(account)`; everything else to any front end.
   Then each bucket has one owner and a consumer meets AWS's limit even
   when its calls land on different gateways.
4. When the set of front ends changes, buckets that move SHALL start full,
   which can admit up to one extra bucket's worth of traffic, the same
   tolerance the Kinesis design accepts on leader change; the docs SHALL
   say so.
5. Gateways SHALL enforce only connection and request-size limits
   (`aws_json::request_limits`, the HTTP server request limits). They
   SHALL NOT keep Kinesis buckets.

### Requirement 9: Segment store as a remote layer

**User Story:** As an operator, I want record bytes on storage nodes sized
for capacity while the data nodes are sized for Raft, without weakening
durability.

#### Acceptance Criteria

1. The stream state machine and DynamoDB's change log SHALL use the
   segment store through an interface with two implementations: the local
   `record_segment_store` (default) and a remote client to a volume on a
   segment node.
2. Each data replica SHALL have its own volume, and a volume SHALL have
   exactly one writer (the replica that owns it). A segment node SHALL
   check the writer's identity and a volume **epoch** on every write, so a
   replica that was replaced cannot write to the volume of its successor.
3. The durability rule SHALL be unchanged: `apply()` does not return for
   an entry the node acknowledges until the segment bytes it wrote are
   durable. With a remote volume, `barrier()` SHALL return only after the
   segment node has fsynced every write the barrier covers, coalescing
   concurrent barriers into one round trip as the local store coalesces
   fsyncs.
4. Replication stays Raft's: three data replicas write three volumes. The
   volume assignment SHALL put a group's volumes on distinct segment nodes,
   and on distinct placement groups when the segment layer spans them, so
   losing one segment node loses at most one replica's volume per group.
5. Losing a volume SHALL be handled like losing a replica's disk: the
   replica stops applying, is removed from its groups, and a replacement
   replica is added that restores from a snapshot and fetches segments
   from peers or the object store (the existing restore path). No data
   acknowledged to a client SHALL be lost while a quorum of replicas keeps
   its volumes.
6. Open, restart and torn-tail truncation SHALL behave as on a local disk:
   the remote store SHALL verify CRCs on open and truncate only bytes no
   barrier covered, and `truncate_after` and `drop_stream` SHALL work
   remotely.
7. Determinism SHALL be kept: a volume's files SHALL be byte-identical to
   what the local store would write, so peer fetch, SHA-256 checks and
   object-store tiering are unchanged and a segment can move between a
   local store and a volume by copying.
8. The volume assignment (replica to segment node and volume epoch) SHALL
   be replicated in the Kinesis catalog, so every data node and front end
   agrees on it and a restarted replica finds its volume.
9. Tiering to object storage, retention trim and seal SHALL stay
   leader-proposed entries applied by every replica, whichever store the
   replica uses.

### Requirement 10: Layer membership and scaling

**User Story:** As an operator, I want the stateless layers to scale
themselves, without making their processes Raft members of the data.

#### Acceptance Criteria

1. The gateway and front-end layers MAY run a **layer membership group**:
   one small Raft group of their own, separate from the data layer's
   groups and not counted in its quorum. Its state SHALL hold the live
   members and their roles and addresses, their drain state, and the
   version of the shared settings (iterator key ids, compatibility profile
   defaults).
2. Without the group, membership SHALL come from configuration
   (`KINESIS_FRONT_ENDS`, `KINESIS_DATA_NODES`) or DNS peer discovery
   (`.kiro/specs/dns-peer-discovery/`), and affinity SHALL use that list.
3. The group SHALL have a small fixed voter set (three or five) and admit
   every other stateless node as a non-voting member
   (`.kiro/specs/non-voting-nodes/`), so the layer can grow to many nodes
   without growing its quorum.
4. The group's leader SHALL run the capacity loop of
   `.kiro/specs/elastic-shard-capacity/` with a `capacity_policy` whose
   signals are layer load (requests per second, open EFO streams, CPU,
   bytes served) instead of shards per node, and SHALL provision and
   decommission nodes through the configured `quorum_manager`
   (`include/raft/quorum_management.hpp`), with the same bounds, budget,
   kill switch and single-writer control.
5. Decommissioning a stateless node SHALL drain it first
   (Requirement 4.7) and only then call `decommission_node`.
6. The data layer SHALL keep its own capacity loop from the elastic shard
   capacity spec. The segment layer SHALL report free space per node, and
   the data layer's capacity policy SHALL count it, so a split that cannot
   get volumes is gated like one that cannot get disk.

### Requirement 11: Live migration between layouts

**User Story:** As an operator, I want to move a running cluster from
co-located to independent layers and back without downtime or data loss.

#### Acceptance Criteria

1. Every step of a migration SHALL leave a valid mixed deployment
   (Requirement 3.2), so a migration can stop, pause or reverse at any
   step.
2. Adding or removing the gateway or front-end role on a node SHALL need
   only a drain and a restart of that node with the new role set.
3. Removing the data role from a node SHALL first move every replica it
   holds to other data nodes through the existing placement operators
   (add learner, catch up, promote, transfer leadership, remove replica). A
   node SHALL refuse to start without the data role while it still holds
   replicas, unless told to discard them, and an `evacuate` admin call
   SHALL perform the moves.
4. Adding the data role SHALL add the node as a learner of the groups the
   placement driver assigns it and promote it once caught up, as for any
   new data node.
5. Moving a replica's segments between its local store and a volume SHALL
   be possible in two ways: replica replacement (add a replica that uses
   the other store, then remove the old one), which needs nothing new; and
   an in-place **store move** that copies sealed segments, then the active
   segment's prefix, then fences the replica's apply loop for the final
   tail and switches stores, with the pause bounded and measured.
6. The reverse direction (independent to co-located) SHALL use the same
   operations in the other order, and SHALL be tested.
7. During a migration, no acknowledged write SHALL be lost or duplicated,
   per-shard order and sequence numbers SHALL be unchanged, iterators
   issued before a step SHALL stay valid after it, and KCL consumers SHALL
   keep their leases. Clients MAY see retryable errors.
8. A runbook SHALL describe each direction step by step, with the checks
   to run between steps and how to reverse each one.

### Requirement 12: Effect on DynamoDB

**User Story:** As the DynamoDB maintainer, I want this work to leave
DynamoDB's behaviour unchanged and its own split possible later.

#### Acceptance Criteria

1. The segment store interface (Requirement 9.1) SHALL be in core and
   DynamoDB's change log and state machines SHALL compile against it with
   the local store and no change in behaviour, on-disk layout or tests.
2. The core pieces this spec adds (layer identities, the route cache, the
   volume service and client, the layer membership group) SHALL carry no
   Kinesis types, so DynamoDB can adopt them in a later spec.
3. DynamoDB's Kinesis streaming destination SHALL use the in-process
   `kinesis.put_records` interface only where the node runs the Kinesis
   `gateway` and `front_end` roles, and otherwise its network client, which
   is what a registry miss already does. A test SHALL cover both.
4. KCL 3.x lease tables in Kythira's DynamoDB SHALL be unaffected by the
   Kinesis layout.
5. Changes to shared protocol code (`aws_json_protocol.hpp`,
   `aws_eventstream.hpp`, `sigv4_verifier.hpp`) needed for the
   authenticated-call handoff SHALL keep DynamoDB's tests passing
   unchanged.

### Requirement 13: Failure handling

**User Story:** As an operator, I want each layer's failure to stay in that
layer.

#### Acceptance Criteria

1. Losing a gateway SHALL fail only its in-flight calls and EFO streams;
   clients reconnect to another gateway.
2. Losing a front end SHALL make gateways send its affinity share to the
   next front end in rendezvous order within one failure-detection
   interval.
3. Losing a data node SHALL behave as today (elections, re-routing), with
   front ends refreshing routes.
4. Losing a segment node SHALL stop the replicas whose volumes it held
   (Requirement 9.5) and trigger their replacement; groups keep serving on
   their remaining quorum.
5. A partition between layers SHALL surface as retryable errors
   (`InternalFailure`, as AWS words it), never a
   wrong answer: a front end that cannot reach a data node does not serve
   from a cache of state.

### Requirement 14: Observability

**User Story:** As an operator, I want to see each layer's health and the
cost of every hop.

#### Acceptance Criteria

1. Each node SHALL export per-role metrics: gateway (connections, EFO
   streams, calls per front end), front end (calls by operation, local vs
   remote data calls, route-cache hits and refreshes, bucket counts), data
   (data-layer API calls by kind), segment store (volumes, barrier latency,
   bytes, free space).
2. Every internal call SHALL carry the client request id, so one request
   can be followed across layers in logs and OTLP traces
   (`.kiro/specs/otlp-telemetry-backend/`).
3. The admin API SHALL list the cluster's nodes with their roles, and the
   volume assignment.

### Requirement 15: Testing and acceptance

**User Story:** As a maintainer, I want each layout tested and the
migration proved under load.

#### Acceptance Criteria

1. In-process tests SHALL run each layer as a separate object joined by the
   real internal transport over loopback, in every role layout of interest:
   all co-located; gateway+front end apart from data+segments; all four
   apart; and a mix.
2. The Kinesis differential suite SHALL run against the all-four-apart
   layout and give the same answers as the co-located layout.
3. A compose scenario SHALL run the four layers as separate services, wired
   by service name, under Docker and rootless Podman (no static IPs, no
   privileged containers), and run the SDK, KPL and KCL 2.x and 3.x
   clients against it.
4. A docker-chaos scenario SHALL migrate co-located to independent and
   back under a continuous KPL producer and KCL consumer, killing one node
   of each layer along the way, and SHALL check that no acknowledged record
   is lost or duplicated, per-shard order holds, and every lease survives.
5. A measurement row SHALL compare co-located and independent layouts
   (latency percentiles for `PutRecords`, `GetRecords` and EFO delivery,
   and throughput) and show co-located unchanged against today's row.
6. Unit tests SHALL cover the route cache (stale epochs, leader changes,
   splits), affinity under membership change, volume epochs and fencing,
   remote barrier coalescing, and role-set validation.
7. Every migration path SHALL have its own test, run in both directions:
   splitting off and folding back the gateway role, the front-end role,
   the data role (evacuation), and the segment store (by replica
   replacement and by in-place store move), and the whole co-located to
   four-way path and back, including stopping and reversing at a middle
   step. Each checks the guarantees of Requirement 11.7.
8. Interoperability with real AWS SHALL be tested in the four-way split
   layout, as far as AWS allows: the recorded AWS Kinesis fixtures of the
   Kinesis spec replayed against it; stream encryption through the `aws`
   KMS provider (data keys from real AWS KMS, used by front ends); KCL 3.x
   consumers keeping their leases in real AWS DynamoDB; and the same
   producer and consumer suite run once against real AWS Kinesis and once
   against the split layout, comparing what the clients observe. Runs that
   spend money on AWS are dispatch-only, need Clark's go in his own words
   each time, and delete what they create.

### Requirement 16: Documentation

**User Story:** As an operator, I want to know when splitting helps and how
to do it.

#### Acceptance Criteria

1. `services/kinesis/doc/` SHALL describe the four layers, each role's
   settings, the identity and certificate setup, sizing guidance for each
   layer, and the trade-offs (an extra hop per call, a network round trip
   per barrier with remote volumes).
2. The migration runbook of Requirement 11.8 SHALL be part of it.
3. The Kinesis design SHALL point to this spec where it describes the
   single-process gateway.
