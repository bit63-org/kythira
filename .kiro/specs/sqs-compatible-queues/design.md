# Design Document

## Overview

```
 SDKs / CLI / JMS / Spring / Celery / Extended Client     real SNS (HTTPS)
        │ HTTPS, AWS JSON 1.0 or query, SigV4                │
        ▼                                                    ▼
 gateway     framing (both protocols), limits, SigV4     SNS bridge
        │ authenticated call
        ▼
 front end   authorization, handlers, MD5, SSE seal/open, batching,
             long-poll parking (woken by data-node notifications)
        │ send / receive / delete / visibility (route cache)
        ▼
 data        multi_raft, queue state machine on RocksDB:
             q/<queue>/<partition>/... messages, visibility index,
             FIFO group heads, dedup records, counts; catalog;
             workers: move tasks, retention, dedup cleanup
```

## Key design decisions

### A receive is a write

Visibility, receive counts and FIFO group locking all change on receive,
so a receive is a committed entry carrying the leader's timestamp, the
batch size and the visibility timeout. The entry picks messages in
`apply()` (deterministic on every replica), marks them invisible until
`now + timeout`, and returns them. That costs one Raft round trip per
receive batch, the same as a send, and gives exact semantics: no
replica's clock is read, a leader change never double-delivers a message
that was received before it, and FIFO groups are never handed out twice.

### Partitions

A queue's messages live under routing keys
`q/<queue id>/<partition>`. A standard queue starts with a few partitions
and adds more as its rate grows (an entry in the catalog; new sends spread
over all of them, old partitions drain). A receive targets the partitions
in rotation, so consumers draw from all of them. A FIFO queue hashes the
message group id to a partition; in high-throughput mode it uses many
partitions, otherwise one, matching SQS's per-queue FIFO limits. Each
partition's state is self-contained, so a partition never needs a
cross-group transaction except dead-letter moves.

### Receipt handles

A receipt handle is `HMAC(cluster key, queue id, partition, message id,
receive sequence, deadline)`, base64. Delete and change visibility present
it; `apply()` accepts it only while that receive is the message's latest.
No handle state is stored beyond the message's receive sequence, which
the message already has. The key is sealed and rotated like Kinesis's
iterator key.

### Long polling without polling

A front end that finds nothing parks the request and subscribes to the
queue's partitions on the data nodes that hold them. A data node's state
machine knows when a partition gains visible messages (a send applied, a
visibility deadline passed, a delay ended) and sends a one-byte "ready"
on the subscription; the front end then proposes a receive. Deadline
expiry is driven by a per-partition timer on the leader, which proposes a
no-op tick when the earliest deadline passes, so the "visible again"
moment is a committed fact every replica agrees on. Co-located, the
subscription is an in-process callback.

### Encryption at the front end

Bodies and attributes are sealed in the front end with the queue's data
key, so the data layer never needs KMS and Raft carries ciphertext. MD5
digests are computed by the front end over plaintext before sealing and
stored with the message, which is what clients check.

### Dead-letter moves are transactions

A message whose receive count passes `maxReceiveCount` moves to the
dead-letter queue in the same entry that would have delivered it; when
the dead-letter queue is in another group, the move is a tier-1
transaction, so the message is in exactly one queue at every point.

### Layers

Roles, identities, route cache, authenticated call and the optional layer
membership group follow the Kinesis independent-layers design, with
`KYTHIRA_SQS_ROLES`. The availability subscription is the one SQS-specific
internal stream.

## Components

| Component | Location | Notes |
|---|---|---|
| Model and coverage | `services/sqs/include/kythira/sqs/model/` | pinned botocore `sqs` |
| Queue state machine | `sqs_queue_state_machine.hpp` | messages, visibility, FIFO, dedup |
| Receipt handles | `sqs_receipts.hpp` | HMAC tokens, key rotation |
| Handlers | `sqs_service.hpp` | both protocols through the codecs |
| Long poll | `sqs_long_poll.hpp` | parking, subscriptions |
| Workers | `sqs_workers.hpp` | move tasks, retention, ticks |
| SNS bridge | `sqs_sns_bridge.hpp` | confirm, verify, enqueue |
| Daemon | `cmd/sqs_node/` | roles, TLS |

## Error handling

- A send that cannot commit in time answers a retryable `InternalError`
  (the send may have committed; FIFO dedup ids make retries safe).
- A receipt handle that is malformed answers `ReceiptHandleIsInvalid`; one
  that is stale is accepted and ignored for delete, as SQS does.
- A long poll whose subscriptions break is answered empty; the client polls
  again.

## Testing strategy

State-machine property tests with leader changes injected; client suites on
co-located and split layouts; migration path tests both ways plus
docker-chaos; recorded SQS fixtures; a dispatch-only real-SQS and real-SNS
bundle; a measurement row.

## Open questions

1. How many partitions should a new standard queue start with, and what
   rate adds one? The design starts with four and adds by observed send
   rate, like Kinesis on-demand.
