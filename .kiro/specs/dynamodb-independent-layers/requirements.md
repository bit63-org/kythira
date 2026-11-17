# Requirements Document

## Introduction

This spec does for the DynamoDB-compatible service
(`.kiro/specs/dynamodb-compatible-api/`) what
`.kiro/specs/kinesis-independent-layers/` does for Kinesis: each layer can
run as its own process or cluster, co-located operation stays the default
and is never required to change, and a running deployment can move from
co-located to independent operation and back. It follows Clark's request
of 2026-11-17 ("Do the same for DDB, KMS, and HSM").

It reuses the shared pieces the Kinesis spec puts in core rather than
defining them again: per-node roles, layer identities (mutual TLS with
roles in the certificate), the route cache, the `segment_store` interface
and volume service, the layer membership group and its capacity loop.
Where a requirement below names one of them, the Kinesis spec's design is
the definition. Whichever spec reaches a shared piece first builds it to
that design.

### DynamoDB's layers

Read from the design and from `services/dynamodb/` on main:

1. **Gateway**: AWS JSON 1.0 framing, request limits, SigV4
   (`front_end.hpp` steps 1-3), `DescribeEndpoints`, the `GET /` health
   answer.
2. **Front end**: authorization with resource tags and policies
   (`front_end.hpp` step 4 and `call_context::authorize`), expression and
   PartiQL parsing into `dynamo_expr` trees, the handlers (`table_api`,
   `item_api`, `query_api`, `batch_api`, `txn_api`, Streams, backups,
   exports, insights), and capacity admission (`capacity_throttler`).
3. **Data**: the `multi_raft` host, `dynamo_item_state_machine` on its
   `kv_engine` (RocksDB), the catalog, the transaction wrapper, and the
   leader-side workers: catalog jobs, the GSI propagator, the TTL sweeper,
   the Kinesis streaming destination publisher, the global-table
   replicator, the PITR archiver, and the strong host for multi-region
   strong consistency. The engine is the state machine's state, so it
   cannot be separated from the groups, as Kinesis's stream state machine
   cannot.
4. **Change-log segment store**: the core `record_segment_store` each
   group's change log appends to.

### What exists today

- Every `dynamodb_gateway_node` runs all four. Each node is a voter
  (`KYTHIRA_DYNAMODB_PEERS`), and its capacity share is one over the
  voters (`run_cluster.hpp`).
- The handlers already reach the data through a value-returning concept,
  `dynamo_backend` (plus `change_feed_backend` and `replica_backend`), and
  `raft_backend` already turns each call into an **op** (`catalog`,
  `write`, `read`, `page`, `describe`, `list`, `drop`, `txn`, `segment`)
  that runs locally or on a peer through a forwarder, with "not the
  leader, try N" answers. This is most of a data-layer API already. The
  gap is that the caller is always a data node: it runs the op locally
  first to learn the leader, and peers are found from the voter list.
- Forwarding between gateways is authenticated with an HMAC under
  `KYTHIRA_DYNAMODB_FORWARD_SECRET`, over TLS when the gateways use it.
- With KMS-backed encryption (`.kiro/specs/kms-compatible-api/` design,
  "DynamoDB: seal what is stored"), item values are sealed inside the item
  state machine, so the **data** layer needs the table key, unlike
  Kinesis, where the front end seals.

**Scope**: roles, a remote backend for front ends, routing without Raft
membership, the gateway handoff, where capacity admission lives, where
the leader-side workers run, the change log on remote volumes, migration
both ways, Kinesis and KMS interactions, observability and tests.

**Out of scope**: separating the `kv_engine` from the item state machine
(a remote engine would put every apply behind a network call and is a
different product); changes to the DynamoDB API or its semantics.

## Glossary

The Kinesis spec's glossary applies (layer, role, role set, data node,
stateless layers, route, segment node, volume, layer identity, layer
membership group, affinity). In addition:

- **Op**: a `raft_backend` operation in its wire form (tag byte and
  payload), as `raft_backend.hpp` defines it.
- **Remote backend**: a `dynamo_backend` that sends every op to a data
  node and runs none locally.
- **Leader-side worker**: a background task that acts only where its node
  leads a group (the catalog or a base group).

## Requirements

### Requirement 1: Co-located operation stays the default

**User Story:** As an operator running DynamoDB today, I want nothing to
change unless I ask for independent layers.

#### Acceptance Criteria

1. With no new setting a node SHALL run all four roles, with today's
   configuration, data directory, ports, wire and behaviour.
2. A co-located node SHALL run ops it can serve locally without a network
   hop, so co-located latency and throughput do not regress beyond noise
   (Requirement 12.4).
3. Every existing DynamoDB test, compose file and docker-chaos scenario
   SHALL pass unchanged.
4. No DynamoDB feature SHALL require independent operation.

### Requirement 2: Roles

**User Story:** As an operator, I want to choose which DynamoDB layers
each process runs.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_DYNAMODB_ROLES`, a subset of
   `gateway`, `front_end`, `data`, `segments`; default all four. In
   `kythira_node` it affects only the DynamoDB module.
2. A node without `data` SHALL NOT be a Raft member of DynamoDB's groups,
   SHALL NOT need to be in `KYTHIRA_DYNAMODB_PEERS`, and SHALL NOT open an
   engine, a Raft log or a change log.
3. A role set the node cannot serve SHALL stop it at start with the reason,
   as Kinesis Requirement 2.4.
4. The strong host (multi-region strong consistency) and the global-table
   replicator SHALL run only on data nodes.

### Requirement 3: Remote backend

**User Story:** As a front end without a local replica, I want the same
backend calls with the same guarantees.

#### Acceptance Criteria

1. A `remote_backend` SHALL satisfy `dynamo_backend`, `change_feed_backend`
   and `replica_backend` by sending ops to data nodes, using the route
   cache to pick the leader (writes, consistent reads, catalog, drop, txn)
   or the nearest replica (eventually consistent reads and pages).
2. A data node SHALL serve ops from a front end exactly as from a peer
   gateway, and a non-leader SHALL answer "not the leader, try N" without
   forwarding further, so an op crosses at most one data node.
3. A `hybrid_backend` SHALL run an op locally when the node holds the group
   (and leads it, where the op needs the leader), otherwise remotely, so a
   co-located node in a mixed cluster needs no mode switch.
4. Range reads (`Query`, `Scan`, parallel scan segments) SHALL page through
   groups with the same page bounds as today, so one call cannot pin a data
   node's memory.
5. Every op's answer SHALL be the same in all layouts. The handlers SHALL
   NOT change.
6. Ops SHALL carry the route epoch; a data node that sees a stale epoch
   SHALL answer with the current route instead of serving.

### Requirement 4: Gateway layer

**User Story:** As an operator, I want client connections, TLS and SigV4
handled apart from the handlers.

#### Acceptance Criteria

1. The gateway SHALL frame requests, enforce request limits, verify SigV4,
   answer `DescribeEndpoints` and health, and hand the front end an
   authenticated call as Kinesis Requirement 4.1 defines it.
2. Authorization SHALL stay in the front end (it needs table and stream
   tags and resource policies).
3. `DescribeEndpoints` SHALL name the gateway layer's advertised endpoint,
   never a data node.
4. The gateway SHALL accept a drain request, as Kinesis Requirement 4.7.

### Requirement 5: Capacity admission

**User Story:** As an operator, I want provisioned and on-demand limits to
hold however the layers are split.

#### Acceptance Criteria

1. Capacity admission SHALL stay in the node that takes the request: the
   front end.
2. Each front end's share of every limit SHALL be one over the live front
   ends (from the layer membership group, configuration or DNS discovery),
   replacing today's one over the voters, and SHALL follow membership
   changes within one refresh interval.
3. The documentation SHALL keep today's statement: exact when clients
   spread requests over the gateways, stricter when they do not.
4. Affinity routing SHALL NOT be used for DynamoDB capacity: a hot table
   must be served by every front end.

### Requirement 6: Leader-side workers

**User Story:** As a maintainer, I want every background task to run in
exactly one well-defined place in every layout.

#### Acceptance Criteria

1. Catalog jobs, the GSI propagator, the TTL sweeper, the Kinesis
   destination publisher, the global-table replicator and the PITR
   archiver SHALL run on data nodes, gated by group leadership as today,
   using the local backend.
2. A worker that today runs in the gateway process (the TTL sweeper in
   `gateway.hpp`) SHALL move to the data role without changing what it
   does.
3. Backup, export and import jobs SHALL run on the catalog leader's data
   node; their object-store credentials SHALL be configured on data nodes.
4. A front end SHALL never run a worker.

### Requirement 7: Change log on remote volumes

**User Story:** As an operator, I want the change log on segment nodes
like Kinesis's records.

#### Acceptance Criteria

1. The change log SHALL use the `segment_store` interface, with the local
   store by default and a volume on a segment node when the node lacks the
   `segments` role, with the durability, fencing and loss handling of
   Kinesis Requirement 9.
2. DynamoDB SHALL keep its own volume assignment in its catalog, and MAY
   share segment nodes with Kinesis (volumes are per replica and per
   service).
3. Streams reads from a front end SHALL go through `read_changes` on a data
   replica, which reads its store or volume.

### Requirement 8: Cross-layer authentication

**User Story:** As a security reviewer, I want DynamoDB's internal calls
held to the same rules as Kinesis's.

#### Acceptance Criteria

1. Internal calls SHALL use layer identities and per-route role checks as
   Kinesis Requirement 7 defines them, with `dynamodb` as the service in the
   identity.
2. `KYTHIRA_DYNAMODB_FORWARD_SECRET` SHALL stay valid between co-located
   data nodes and SHALL NOT be accepted from a node without the `data`
   role.
3. Global-table and strong-host peers in other regions SHALL keep their
   existing authentication.

### Requirement 9: Encryption and KMS

**User Story:** As a security reviewer, I want to know which layer holds
table keys.

#### Acceptance Criteria

1. Table keys SHALL be held only by data nodes, which seal and open item
   values in the state machine as the KMS design specifies. Front ends and
   gateways SHALL NOT need KMS access for item data.
2. Change-log records on a remote volume SHALL be sealed before they leave
   the data node, so a segment node holds only ciphertext for an encrypted
   table.
3. A front end SHALL still reach KMS for operations whose answers need it
   (`DescribeTable`'s `SSEDescription` comes from the catalog and does not).

### Requirement 10: Kinesis interactions

**User Story:** As an operator running DynamoDB and Kinesis together, I
want both to keep working in every combination of layouts.

#### Acceptance Criteria

1. The Kinesis destination publisher (a data-node worker) SHALL use the
   in-process `kinesis.put_records` only when its node runs the Kinesis
   gateway and front-end roles, otherwise the network client.
2. KCL 3.x lease tables on Kythira's DynamoDB SHALL be unaffected by either
   service's layout.

### Requirement 11: Live migration

**User Story:** As an operator, I want to move a running DynamoDB cluster
between layouts in both directions.

#### Acceptance Criteria

1. Migration SHALL use the steps of Kinesis Requirement 11: drain and
   restart for stateless roles, `evacuate` through the placement operators
   for the data role, replica replacement or an in-place store move for
   the change log.
2. DynamoDB's per-voter split ranges (`(ordinal + 1) << 48`) SHALL keep
   working when voters change: a data node that leaves SHALL release its
   range only after its replicas have moved.
3. During a migration no acknowledged write SHALL be lost, conditional
   writes and transactions SHALL keep their guarantees, Streams readers
   SHALL see every change in order per shard, and GSIs SHALL converge.
4. Both directions SHALL be tested under load (Requirement 12.3).

### Requirement 12: Testing

**User Story:** As a maintainer, I want each layout tested.

#### Acceptance Criteria

1. Handler tests SHALL run over `remote_backend` and `hybrid_backend`
   against an in-process data cluster over loopback.
2. A compose scenario SHALL run the four layers as separate services wired
   by name, under Docker and rootless Podman, and run the existing SDK,
   KCL 3.x and lock-client suites against it.
3. A docker-chaos scenario SHALL migrate co-located to independent and back
   under a conditional-write and transaction workload, checking no lost
   acknowledged write, no lost or reordered stream record, and GSI
   convergence.
4. A measurement row SHALL compare layouts, with co-located against
   today's row.
5. Every migration path SHALL have its own test, run in both directions:
   the gateway role, the front-end role, the data role (evacuation,
   including per-voter split ranges), and the change log (replica
   replacement and in-place store move), and the whole co-located to
   four-way path and back with a stop and reversal midway. Each checks the
   guarantees of Requirement 11.3.
6. Interoperability with real AWS SHALL be tested in the four-way split
   layout, as far as AWS allows: the DynamoDB spec's recorded AWS fixtures
   replayed against it; the Kinesis streaming destination delivering to
   real AWS Kinesis from data nodes; table encryption through the `aws`
   KMS provider (table keys from real AWS KMS, held by data nodes); KCL
   3.x consuming real AWS Kinesis with its lease table on the split
   layout; and the SDK and lock-client suites run against real AWS
   DynamoDB and the split layout with the observed results compared.
   Spending runs are dispatch-only, need Clark's go in his own words each
   time, and delete what they create.

### Requirement 13: Documentation

**User Story:** As an operator, I want to know when splitting DynamoDB
helps and how to do it.

#### Acceptance Criteria

1. `services/dynamodb/doc/` SHALL describe the layers, roles, which layer
   holds which secret (table keys on data nodes; SigV4 lookups on
   gateways), sizing, and the migration runbook.
