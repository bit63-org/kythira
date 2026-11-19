# Layers and sizing

`.kiro/specs/sqs-compatible-queues/` Requirement 14.1. How to choose a
layout for `sqs_node`, what each layer holds, and what to size it by. The
settings themselves are in [configuration.md](configuration.md#layers);
moving a running cluster between layouts is [migration.md](migration.md).

## Co-located or split

Every node runs all three layers unless `KYTHIRA_SQS_ROLES` says
otherwise, and that is the layout to start with:

| | Co-located (3 or 5 nodes) | Split (gateways, front ends, data nodes) |
|---|---|---|
| Nodes | 3 or 5, all alike | 3 or 5 data nodes, plus 2 or more front ends and 2 or more gateways |
| Hops per call | client, node, leader (one forward when the node is a follower) | client, gateway, front end, data leader |
| Scales by | bigger nodes | adding front ends and gateways, independently of the data nodes |
| Certificates | one identity per node | an identity per node naming its roles ([configuration.md](configuration.md#layer-identities)) |
| Choose it when | the API traffic fits on the data nodes | signature checking, long polls or the FIFO per-front-end limit outgrow the data nodes, or the data nodes must sit off the client network |

Neither layout is permanent: [migration.md](migration.md) moves a running
cluster from co-located to split and back without stopping clients or
invalidating receipt handles, and the container scenario
(`../tests/docker/`) walks both directions with a node killed in every
layer.

## What each layer holds

| Layer | State | Lost when a node goes | Grows with |
|---|---|---|---|
| gateway | none (the static keys file) | nothing; clients retry the 503 on the next gateway | request rate and signature checks |
| front end | parked long polls, its FIFO send counters | parked polls answer empty and clients poll again | request rate, open long polls, FIFO send rate |
| data | a replica of every queue (RocksDB under `multi_raft`) | nothing while a majority of voters remains | messages stored, write rate |

Gateways and front ends are stateless: put any number behind a load
balancer or in each other's endpoint lists, and replace them freely.
Stopping a front end drains it first, so a planned stop shows clients
only empty receives.

## The data layer

All queues live in **one Raft group**. Queues spread over partitions
inside that group, which spreads the work of the leader-side workers, but
every send, receive, delete and visibility change is a Raft write
committed by the group's one leader. So:

- **Throughput is bounded by the leader.** Adding data nodes adds
  replicas, not write capacity, and each extra voter adds replication
  work. Run 3 voters (one failure tolerated) or 5 (two); more buys
  nothing. Size the data nodes for the leader's load, since any of them
  may become leader.
- **A receive is a write.** It records the new visibility deadline and
  receipt, so receive-heavy loads cost the leader as much as sends.
  Batching (`SendMessageBatch`, receives of up to ten, `DeleteMessageBatch`)
  divides the number of commits, and is the cheapest capacity there is.
- **Reads go to the leader too.** A front end tries the data nodes in
  turn and only the leader answers, so a client always reads its own
  writes.
- **Latency is a commit.** Each call costs one round trip from the leader
  to a majority and an fsync there. Keep the voters within one region's
  latency of each other and on local disks.

### Disk

What a data node stores is roughly the messages waiting in every queue:

```
disk ≈ Σ over queues (send rate × average body size × time a message waits)
       + Raft log since the last snapshot
```

- A message body is at most `MaximumMessageSize`, 1 MiB here by default
  (SQS's current limit), plus its attributes. SSE-SQS adds a few dozen
  bytes per message.
- A message waits until it is deleted or its queue's
  `MessageRetentionPeriod` expires: 4 days by default, 14 at most. Plan
  for consumers stopping for the whole retention period on the queues
  that matter, not for the steady state.
- Deleted and expired messages leave RocksDB at compaction; leave
  headroom of about the same size again for compaction and snapshots.
- Every voter stores the full set, so the cluster's total is the per-node
  figure times the voters.

### Memory

The data nodes keep RocksDB's block cache and memtables, plus the
in-flight index: each in-flight message (received, not yet deleted or
returned) is tracked until its visibility timeout ends. The per-queue
in-flight limit is 120,000, SQS's, and the `inflight-standard` and
`inflight-fifo` compatibility settings change it. Size memory for the
in-flight messages you expect across all queues, plus the block cache.

## Front ends

- **Long polls.** A `ReceiveMessage` with `WaitTimeSeconds` parks on the
  front end that took it, for up to 20 seconds, and is woken by the data
  nodes' availability stream; nothing polls the data layer meanwhile. A
  parked poll costs a connection and a little memory, so the number of
  consumers waiting at once (each SDK consumer thread is one) sizes a
  front end's connection limits more than its CPU does.
- **FIFO request limit.** SQS allows 300 requests a second per FIFO
  queue for each of send, receive and delete (a batch is one request),
  and that much per partition in high-throughput mode. Each front end
  counts its own requests ([unsupported.md](unsupported.md)), so a
  cluster's limit is 300 times its front ends; with one front end it is
  SQS's exactly. The `kythira:compat:fifo-throughput=off` queue tag turns
  the limit off.
- **CPU.** A front end runs the handlers, authorization and SSE
  encryption. It scales horizontally: add front ends to
  `SQS_FRONT_END_ENDPOINTS` on the gateways.

## Gateways

A gateway checks SigV4 signatures and hands the request to a front end in
turn. It is the cheapest layer per request; size it for TLS termination
and request rate, and run at least two behind the load balancer clients
use. The front ends' `SQS_ENDPOINT` must name that load balancer, because
queue URLs are minted there.

## Starting points

Until a production-hardware row is in [measurements.md](measurements.md),
these are starting points to measure from, not guarantees:

| Load | Layout |
|---|---|
| Development, client tests | one in-memory node |
| Up to a few hundred calls a second, mostly batched | co-located, 3 nodes |
| Many concurrent long polls, many FIFO senders on one queue, or clients on another network | split: 3 data nodes, 2+ front ends, 2+ gateways |
| Needs to survive two failures | 5 voters in either layout |

Measure with `../tools/sqs_load.py` against the layout and hardware you
mean to run, with your message sizes and batching, before relying on it.
The rows in [measurements.md](measurements.md) come from one development
container and say how the layouts compare, not what they sustain.
