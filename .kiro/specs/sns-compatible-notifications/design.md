# Design Document

## Overview

```
 SDKs / CLI
        │ HTTPS, AWS query, SigV4
        ▼
 gateway     framing, limits, SigV4, SigningCertURL, confirm links
        │ authenticated call
        ▼
 front end   authorization, handlers, validation, SSE seal, throttling
        │ publish (route cache) / topic and subscription changes
        ▼
 data        multi_raft, topic state machine: topics, subscriptions,
             FIFO dedup, delivery partitions, leases, cursors, retry state
        │ publish log appends (apply)          ▲ cursors, retries, DLQ
        ▼                                      │
 segments    publish log per topic partition ──┤ reads
             (record segment store; archive tiered to object storage)
                                               │
 delivery    leased workers: read log, open, filter, deliver
             ├─► Kythira SQS (in-process or API)
             ├─► real Amazon SQS (configured credentials)
             ├─► HTTP/HTTPS endpoints (signed, retry policy)
             └─► SMTP relay (email, email-json)
```

## Key design decisions

### Publish commits to a log; delivery reads it

A publish is one Raft entry in the topic partition's group; `apply()`
appends the message to the partition's publish log in the record segment
store and returns the message id. The publish answer never waits for
delivery, as on SNS. Delivery is a separate consumer of the log, like a
Kinesis consumer, which makes it restartable (cursors), replayable
(archive), and separable onto its own nodes.

Using the record segment store gives SNS the Kinesis machinery for free:
retention trim, tiering for FIFO archives (up to 365 days), peer fetch,
and the volume service when segments run on their own nodes.

### Delivery partitions and leases

A topic can have millions of subscriptions. The work is cut into delivery
partitions: (log partition, subscription range). Each partition is owned
by one delivery worker under a lease in the topic state, with a fencing
token on every cursor and retry commit, so a stalled worker cannot commit
after losing its lease. A worker reads a batch from the log, evaluates
each subscription's filter, delivers, and commits the cursor once every
matching delivery in the batch has succeeded or been handed to retry
state. Retry state (message, subscription, attempt, next time) is
committed so a new owner resumes the backoff schedule; exhausted messages
go to the subscription's dead-letter queue.

Co-located, every node runs delivery for the partitions whose log it
holds locally, so a three-node cluster delivers from local disk.

### FIFO

A FIFO topic hashes message group ids to log partitions. A worker delivers
a group's messages to each subscription in order, one in flight per
(group, subscription), so a slow subscriber holds back only its own
groups. Deduplication records live in the topic state, as in SQS.

### Signatures

SNS signs each message; validators fetch `SigningCertURL` and check the
host is SNS's. Kythira serves its certificate from the gateway and lets
the host be configured, and documents how to point each SDK's validator
at it. The signing key is sealed at bootstrap and rotated with an overlap.

### Encryption

The front end seals messages with the topic's data key before publishing,
and delivery workers open them, so data nodes and segment stores never
hold plaintext or need KMS.

### Layers

Five roles (`KYTHIRA_SNS_ROLES`), with layer identities, route cache,
authenticated call and the layer membership group from the Kinesis
independent-layers design. Delivery is the one stateless layer whose
capacity tracks backlog rather than request rate, so its capacity policy
uses backlog and delivery latency as signals.

## Components

| Component | Location | Notes |
|---|---|---|
| Model and coverage | `services/sns/include/kythira/sns/model/` | pinned botocore `sns` |
| Topic state machine | `sns_topic_state_machine.hpp` | topics, subscriptions, FIFO, leases, cursors |
| Filter policies | `sns_filter_policy.hpp` | attribute and payload scopes |
| Delivery | `sns_delivery.hpp`, `sns_targets.hpp` | workers, retries, targets |
| Signatures | `sns_signing.hpp` | v1 and v2, cert serving, rotation |
| Handlers | `sns_service.hpp` | query protocol |
| Daemon | `cmd/sns_node/` | roles, TLS, SMTP and AWS credentials |

## Error handling

- A publish that cannot commit in time answers `InternalError`
  (retryable; FIFO dedup makes retries safe).
- An HTTP endpoint that fails is retried by the delivery policy; an SQS
  target that refuses for permissions is a non-retryable failure sent to
  the dead-letter queue, as SNS does.
- A worker that loses its lease stops at its next commit, which is
  refused.

## Testing strategy

Property tests of the topic state machine; filter policies against SNS's
documented examples; client suites with SNS to SQS fan-out on co-located
and split layouts; migration path tests both ways plus docker-chaos;
recorded SNS fixtures; a dispatch-only real-SNS and real-SQS bundle; a
measurement row by fan-out.

## Open questions

1. Should email delivery ship in the first version, or wait for a user who
   needs it? The design includes it behind a configured SMTP relay.
