# Design Document

## Overview

```
                 clients (SDK, CLI, KPL, KCL, EFO, Flink)
                         │ HTTPS JSON 1.1 / CBOR, SigV4, HTTP/2 EFO
                         ▼
 gateway        framing, request limits, SigV4, STS GetCallerIdentity,
 (stateless)    EFO stream termination, drain
                         │ authenticated call (mTLS, role=gateway)
                         │ affinity: rendezvous((stream, shard)) / (account)
                         ▼
 front end      authorization, kinesis_service handlers, lease API,
 (stateless)    iterators, KMS seal/open, read/control/EFO buckets,
                route cache
                         │ data-layer API (mTLS, role=front_end)
                         │ propose → leader; reads → nearest replica
                         ▼
 data           multi_raft host + stream_state_machine + catalog,
 (Raft groups)  write buckets on the leader, maintenance, on-demand,
                resharding transactions, volume assignment
                         │ volume API (mTLS, role=data, volume epoch)
                         ▼
 segment store  one volume per data replica, byte-identical files,
                remote barrier = fsync on the segment node
                         │
                         ▼  tiering (leader-proposed, unchanged)
                object storage
```

A co-located node runs all four boxes in one process and every arrow is a
function call, as today. Any box can instead run in its own processes, and
any node can run any subset. The arrows that cross a process boundary use
the internal transport and are authenticated by layer identity.

The layer membership group (optional) sits beside the two stateless layers:

```
 gateways + front ends ── layer membership group (3 or 5 voters, the rest
                          learners): members, roles, drain state, shared
                          settings version; its leader runs
                          capacity_policy → quorum_manager
```

## Key design decisions

### Roles per node, not a cluster mode

The layout is a property of each node (`KINESIS_ROLES`), never a cluster
switch. Every handler asks the same question per call: "do I hold this
locally?" A front end with a local replica of a group reads it in-process;
a front end that leads a group proposes in-process; otherwise it calls a
data node. The same is true one layer down: a data replica writes its local
store or its volume through one interface.

This is what makes migration possible without a flag day. A cluster
moving from co-located to independent passes through states where some
nodes have all four roles and some have one, and every such state is
already a supported layout, because no node assumes anything about the
others' roles. It is also why Requirement 1.2 costs nothing: the local
branch is today's code.

The trade is that every handler call site goes through an interface that
can be remote. The cost of that indirection on the local path is a virtual
call and, for reads, returning values instead of borrowing references into
the state machine; task 2 measures it before anything else lands.

### Named queries replace the state-machine callback

`stream_cluster::read(key, f)` runs `f` on the live state machine under its
lock. That cannot cross a network. The handlers use it for a small, closed
set of things (from `kinesis_service.hpp`, `kinesis_lease_api.hpp`,
`kinesis_maintenance.hpp` and `kinesis_on_demand.hpp` on main):

- the state of one shard, its segment index, the store and the fetcher
  (`read_shard_state`);
- one stream record by account and name or ARN (`find_stream`, 13 sites);
- stream listings, optionally filtered by status (`list_streams`, and the
  `entries()` prefix scans of 3 sites);
- leases by application and prefix (Lease API);
- the catalog's next-id key.

`data_access` (new, `services/kinesis/include/kythira/kinesis/
kinesis_data_access.hpp`) is a concept with those queries, plus
`propose`, `transact`, `group_of`, `leads` and `now_ms` from today's
`stream_cluster`, and a `read_records` that returns sealed record bytes.
Its two implementations:

- `local_data_access<Host>`: today's `raft_stream_cluster` plus the local
  store, answering queries by running them inside `with_group_state_machine`
  and copying the result out (most sites already copy).
- `remote_data_access`: the data-layer API client with the route cache.

and a third, `hybrid_data_access`, that a front end on a data node uses: it
tries local first and falls back to remote per call. A co-located-only
cluster never constructs the remote half.

Maintenance and the on-demand controller only run on data nodes (they act
where the node leads), so they keep the callback form.

### Gateway hands over an authenticated call, not the signed request

Two ways to split gateway from front end were considered:

1. **Pass-through**: the gateway forwards the client's signed request, and
   the front end verifies SigV4 again. No new trust, but the gateway saves
   the front end nothing except TLS and connection handling, and SigV4
   verification (a credential lookup and an HMAC chain) happens twice.
2. **Authenticated call**: the gateway verifies SigV4 and sends the decoded
   operation with the verified principal and the request's condition keys.
   The front end trusts the principal because the caller presents a
   `gateway` layer identity.

The design takes (2). It puts all protocol work in one layer, which is the
point of having one, and the trust it adds is the same trust co-location
already has between the front end and its in-process caller. Authorization
stays in the front end, because it needs resource lookups (tags, stream and
consumer policies) that come from the catalog; the gateway then needs no
catalog access at all and can sit in a DMZ.

The authenticated call carries: operation name, input as the codec's
`boost::json::value` (encoding-neutral; CBOR input is decoded at the
gateway), answer encoding, principal (account, ARN, session tags, source
identity), context keys (`aws:SourceIp`, `aws:SecureTransport`,
`aws:CurrentTime`, `aws:RequestTag/*`, `aws:TagKeys`), and the client
request id. The answer is an `aws_json::result` the gateway encodes in the
client's encoding. The wire is CBOR, which the tree already has.

Both layers need IAM: the gateway for SigV4 credential lookup, the front
end for policy evaluation. Each uses the in-process `iam.evaluator` when
IAM is co-located with it, else IAM's network client, as service
colocation already arranges.

### EFO across the gateway

`SubscribeToShard` holds an HTTP/2 stream for up to five minutes, which is
the gateway's job (connection fan-in). The gateway opens a streaming
internal call to the shard's affinity front end, which runs today's
`event_source` (per-consumer buckets, record reads, KMS open) and pushes
whole event-stream messages back. The gateway relays them without parsing.
If the internal call breaks, the gateway ends the client stream with
`InternalFailureException`, the event AWS sends for a retryable failure;
KCL and the SDK resubscribe from their continuation sequence number, which
is today's behaviour when a replica is removed.

### Data-layer API on the existing internal listener

Data nodes already expose `/_kythira/kinesis/v1/{propose,segment,txn}` on
the gateway listener. The data-layer API extends that family
(`/_kythira/kinesis/v2/...`) with `shard_state`, `read_records`, catalog
queries, `routes` and `now`, all CBOR. A data node that runs no gateway
still opens the listener for internal calls only, on `KINESIS_INTERNAL_LISTEN`
(default: the gateway listener when the node has both roles, so co-located
nodes open no new port).

`propose` from a front end differs from today's gateway-to-gateway forward
in one way: the front end is not a Raft member, so it never proposes
itself. It sends to the leader in its route; a non-leader answers with a
not-leader error and hint (never forwards), the front end refreshes its
route and retries once within the command timeout. Today's
non-leader-to-leader forward between co-located gateways stays as it is.

### Route cache, not a placement service

A front end needs key to group to leader to address. The data nodes
already know: every `multi_raft` host has the shard map and leader hints.
So the route cache asks any data node (`routes(range)`) and keeps the
answer, keyed by routing-key range, each entry stamped with the group's
configuration epoch. A data node that receives a call with a stale epoch
answers with the current route instead of serving; a not-leader answer
carries the hint; a connection failure marks the address suspect and tries
another replica. This is the region-cache pattern of smart clients and
needs no new replicated service.

Because a Kinesis shard is a routing key and not a group, resharding a
stream changes no route. Only Kythira's own group splits, merges and
replica moves do, and those are rare and self-correcting through the
epoch check.

### Affinity keeps each bucket in one place

Reads, iterators and EFO are rate-limited per shard; control-plane calls
per account. With one front end that is exact; with N, a consumer whose
calls spread over N front ends could read N times AWS's rate. The gateway
therefore picks the front end for a call by rendezvous (highest random
weight) hashing:

- `GetRecords`, `GetShardIterator`, `SubscribeToShard`: key
  `(stream id, shard ordinal)`. `GetRecords` is routed by the shard named
  inside its iterator, which the gateway reads without verifying (the
  front end verifies it); a malformed iterator goes anywhere and fails
  there.
- control-plane operations: key `(account)`.
- writes and everything else: any front end (writes are admitted on the
  data-layer leader).

Rendezvous hashing moves only the departing node's share when membership
changes. Moved buckets start full; the extra burst is bounded by one bucket,
the tolerance the Kinesis design already accepts on leader change.

Write buckets do not move: they stay on the data-layer leader, so a write
meets one set of buckets in every layout.

### Segment store: a volume per replica

Three designs were considered for record bytes on separate nodes:

1. **One volume per replica** (chosen). Each data replica writes its own
   volume on a segment node, exactly as it writes its local directory now.
   Raft still provides replication (three replicas, three volumes on three
   segment nodes). `barrier()` becomes a round trip that returns after the
   segment node's fsync. Restart, torn-tail truncation and restore are
   unchanged in meaning. The segment layer needs no consensus of its own.
2. **Shared content-addressed store**: segments are byte-identical across
   replicas, so the segment layer could keep one copy (or its own
   replicated copies) and every replica points at it. It saves 2/3 of the
   bytes for sealed segments but moves durability out of Raft's hands into
   the segment layer's replication, and the active segment still needs
   per-replica writes. It is left as an open question.
3. **Object storage as the store**: the existing tiering already does this
   for cold segments; the active segment needs low-latency fsync, which
   object stores do not offer.

The volume protocol is a direct remoting of the store's write side:
`open(volume, epoch)`, `append(stream, records)`, `barrier()`,
`seal(stream)`, `trim_before`, `remove_segment`, `install_segment`,
`truncate_after`, `drop_stream`, `streams()`, `describe`, plus the read
side (`read`, `read_segment_bytes`). The segment node runs an ordinary
`record_segment_store` per volume under `<data_dir>/volumes/<volume id>/`,
so the bytes on disk are what a local store would write, and moving a
segment between local and remote is a file copy (Requirement 9.7).

**Interface.** `segment_store` becomes an abstract class in
`include/raft/segment_store.hpp`; `record_segment_store` and
`remote_segment_store` derive from it. The stream state machine,
DynamoDB's `item_state_machine`, `raft_backend` and `change_log` change
their pointer type from `record_segment_store*` to `segment_store*`. A
virtual interface was chosen over a concept because those classes store a
pointer and are not templated on the store; a concept would template three
DynamoDB classes for no runtime gain. A virtual call per append is noise
next to the I/O behind it.

**Writer fencing.** A volume belongs to one replica, identified by
`(node id, group id range, volume epoch)`. The volume assignment lives in
the catalog (`\0meta/kinesis/volumes/<node id>`) and is changed only by
committed entries. A replacement replica gets a new epoch; the segment node
refuses writes with an older epoch, so a replica that was removed while
partitioned cannot write into its successor's files. Reads are not fenced:
segment bytes are checked against their SHA-256 anyway.

**Barrier cost.** A local barrier coalesces concurrent `apply()` callers
onto one round of fsyncs. The remote barrier coalesces the same callers
onto one request carrying the writes since the last barrier (appends are
pipelined ahead of it), and the segment node runs the local barrier and
answers. The added latency per acknowledged write is one data-to-segment
round trip; the measurement row (Requirement 15.5) states it.

**Losing a volume.** The replica treats an unreachable or refused volume
like a failed disk: it stops applying (a skipped append would diverge),
reports itself unhealthy, and the data layer's placement replaces it. The
replacement restores from a snapshot and fetches segments from peers and
the object store, the restore path that exists for a new replica now.

### Layer membership group

The stateless layers need a member list for affinity and a leader to make
scaling decisions. Clark agreed they may have their own Raft membership.
The design gives them one single-group Raft (a plain `node`, not a
multi-raft host) with three or five voters; every other gateway and front
end joins as a non-voting member, so its quorum does not grow with the
layer. Its state machine holds members (id, roles, addresses, placement
group, drain state, last load report) and a version number for the shared
settings each front end must agree on (iterator key ids, compatibility
defaults). It holds no Kinesis data, and a total loss of the group loses
nothing but the member list, which members re-announce on restart.

Its leader runs elastic shard capacity's control loop with a different
`capacity_policy`: signals are requests per second, open EFO streams, CPU
and bytes served per node, and the action is `provision_node` or
`decommission_node` on the layer's `quorum_manager` (ASG, MIG, VMSS,
Docker, ...). The bounds, budget, kill switch, provisioning ledger and
single-writer rules come from that spec unchanged. Scale-in drains first.

The group is optional. A small deployment lists its front ends and data
nodes in configuration or finds them through DNS discovery.

### Authentication between layers

Raft between data nodes already has mutual TLS in `kythira_node`. The same
node identity, extended with a role set, authenticates every internal
call. The CA issues a certificate whose SAN URI names cluster, node id and
roles; each internal route declares which roles may call it (Requirement
7.2). The stand-alone `kinesis_gateway_node`'s plaintext Raft and HMAC
forward secret stay valid for an all-co-located cluster without TLS, so no
existing deployment breaks; any single-role node requires TLS unless the
composite node's existing insecure opt-out is set.

### Migration

Because every intermediate state is a supported layout, a migration is a
sequence of ordinary operations:

**Co-located (A, B, C all roles) to independent:**

1. Issue layer identities with roles to A, B, C; rolling restart onto TLS.
2. Start gateway-only and front-end-only nodes (G*, F*), pointed at A, B,
   C as data nodes; shift client DNS or the load balancer to G*.
3. Start segment nodes (S1..S3) and data-only nodes (D1..D3) configured
   to use volumes.
4. `evacuate` A: the placement driver adds D1 as a learner of A's groups,
   promotes it, transfers leadership away from A, removes A. Repeat for B
   and C. Each step is the membership change the multi-raft host already
   performs for a failed node.
5. Restart A, B, C without the data and segments roles, or retire them.

**Independent back to co-located:** the same in reverse: start nodes with
all roles and a local store, add them as learners, promote, evacuate the
data-only nodes, shift clients back, retire G*, F*, S*.

**In-place store move** (local directory to volume or back, without
replacing the replica): copy sealed segments (verified by SHA-256), copy
the active segment's prefix, then pause the replica's apply loop at an
entry boundary, copy the tail written since, switch the state machine's
`segment_store*`, write the new volume assignment through Raft, and resume.
The pause is bounded by the tail written during the copy; the task that
builds it measures it and refuses to fence if the tail is above a bound.
Replica replacement is preferred for the documented runbook because it
needs nothing new; the in-place move exists for clusters that cannot add a
node.

### DynamoDB

DynamoDB shares three things with Kinesis that this spec touches:

- the record segment store (its change log): it moves to the
  `segment_store` interface with the local implementation and no change in
  behaviour (task 1);
- the AWS protocol pieces and `sigv4_verifier`: the authenticated-call
  handoff adds an entry point that returns the verified principal and
  context keys without dispatching, which DynamoDB does not have to call;
- the in-process `kinesis.put_records` interface used by its Kinesis
  streaming destination: published only by a node that runs the Kinesis
  gateway and front-end roles, so on other nodes the registry misses and
  DynamoDB uses its network client, as designed.

Everything new in core is free of Kinesis types so a later
"DynamoDB independent layers" spec can reuse it: `segment_store` and the
volume service, `layer_identity`, the route cache, and the layer membership
group.

## Components

| Component | Location | Notes |
|---|---|---|
| `segment_store` interface | core `include/raft/segment_store.hpp` | `record_segment_store` derives; Kinesis and DynamoDB take `segment_store*` |
| Volume service and client | core `include/raft/segment_volume_service.hpp`, `remote_segment_store.hpp` | epochs, remote barrier, CBOR over the internal transport |
| Layer identity | core `include/raft/layer_identity.hpp` | SAN URI roles, per-route role checks, reload |
| Route cache | core `include/raft/route_cache.hpp` | range map, epochs, hints, suspect addresses |
| Layer membership group | core `include/raft/layer_membership.hpp` | single Raft group, learners, load reports, capacity hook |
| Data access | `kinesis_data_access.hpp` | concept, local, remote, hybrid |
| Data-layer API | `kinesis_data_api.hpp` | server routes and client, `/_kythira/kinesis/v2/` |
| Authenticated call | `kinesis_authenticated_call.hpp` | gateway encode, front-end decode and trust check |
| Affinity router | `kinesis_affinity.hpp` | rendezvous hashing over live front ends |
| Role wiring | `cmd/kinesis_gateway_node/kinesis_module.hpp`, `config.cpp` | `KINESIS_ROLES`, validation, what each role constructs |
| Segment node | `cmd/kinesis_gateway_node` role `segments` | volumes under `<data_dir>/volumes/` |
| Docs and runbook | `services/kinesis/doc/independent-layers.md` | layouts, sizing, migration |

## Error handling

- A front end that cannot reach any replica of a group answers
  `InternalFailure`, which every Kinesis client retries, never an answer
  from cached state.
- A gateway whose affinity front end refuses or is unreachable tries the
  next in rendezvous order once, and only for calls the front end did not
  execute (connection refused, or an explicit not-executed answer). A
  timeout on a write is ambiguous and is answered to the client as today's
  timeouts are.
- A route with a stale epoch is refreshed and the call retried once.
- A volume write refused for its epoch stops the replica (it has been
  replaced); a volume unreachable past the barrier timeout stops it too.
- A node started with a role set it cannot serve, or without the data role
  while still holding replicas, refuses to start with the reason.

## Testing strategy

- Unit: route cache, affinity, volume epochs, remote barrier coalescing,
  role validation, authenticated-call encode/decode and trust checks.
- In-process: the existing service tests parameterised over layouts
  (all co-located, two-way split, four-way split, mixed), each layer a
  separate object over loopback with the real internal transport.
- Differential: the Kinesis differential suite against the four-way split.
- Compose: four services wired by name, Docker and rootless Podman, SDK,
  KPL, KCL 2.x and 3.x.
- docker-chaos: migrate co-located to independent and back under load,
  killing one node per layer; check acknowledged records, order and leases.
- Measurement: co-located versus split latency and throughput, and the
  co-located row against today's.

## Open questions

1. Shared content-addressed storage for sealed segments (design option 2):
   worth a follow-up spec once volumes are measured, if storage cost
   dominates?
2. Should front ends keep a read cache of sealed segments (verified by
   SHA-256, so untrusted sources are fine) to offload hot fan-out reads
   from data nodes? Not needed for correctness; a measurement after task 7
   decides.
3. Does the layer membership group serve both stateless layers as one
   group, or one group per layer? The design assumes one group with roles
   per member; separate groups only matter if the two layers scale under
   different `quorum_manager`s, which the per-member role already allows.
