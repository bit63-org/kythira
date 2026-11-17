# Requirements Document

## Introduction

This spec adds an **Amazon SQS-compatible message queue service** to
Kythira. Unmodified AWS SDKs, the AWS CLI, the SQS Java Messaging Library
(JMS), Spring Cloud AWS, Celery and Kombu, the SQS Extended Client
(payloads in S3) and other SQS tools point their endpoint at a Kythira
cluster and work.

It follows Clark's request of 2026-11-17 ("Then build specs for S3, SNS,
and SQS following the rules"), which applies the rules he set that day:

- **Independent layers** (`.kiro/specs/kinesis-independent-layers/`): each
  layer can run as its own process or cluster, co-located operation is the
  default and is never required, and a running deployment can migrate from
  co-located to independent and back. This service is layered from the
  start and reuses that spec's shared core pieces.
- **Migration tests**: tasks that test every migration path.
- **Interoperability**: tasks that test interoperability with real Amazon
  SQS as far as AWS allows.

It follows the module conventions of the DynamoDB and Kinesis specs
(opt-in module, pinned botocore model with a coverage test, compatibility
profile, SigV4 and IAM, the shared `kms_key_provider`).

There is no queue service in the tree today.

### Layers

1. **Gateway**: AWS JSON 1.0 (`X-Amz-Target: AmazonSQS.<Action>`, what
   current SDKs send) and the older AWS query protocol, TLS, request
   limits, SigV4.
2. **Front end**: authorization (IAM and queue policies), handlers,
   MD5 digests of bodies and attributes, long-poll waiting, batching,
   throttling.
3. **Data**: the multi-Raft host and the queue state machine on the
   persistent `kv_engine`: queue catalog, messages, visibility, receive
   counts, FIFO groups and deduplication, delay, dead-letter redrive.

SQS has no layer that needs the record segment store: messages are deleted
one by one in any order, which suits the key-value engine rather than an
append-only log.

**Scope**: standard and FIFO queues (including high-throughput FIFO),
fair queues, every message operation and its batch form, visibility
timeouts, long polling, delay queues and message timers, dead-letter
queues with redrive policies and message move tasks, attributes and system
attributes, queue policies, tags, SSE-SQS and SSE-KMS, the layers and
their migration, an inbound bridge for SNS HTTPS deliveries, and tests.

**Out of scope**: Lambda event source mappings, EventBridge Pipes,
CloudWatch metrics as an API (metrics are Prometheus, as for the other
services).

## Glossary

The Kinesis independent-layers glossary applies. In addition:

- **Pinned model**: the botocore `sqs` `service-2.json` at a pinned
  version.
- **Partition**: one routing key of a queue's messages,
  `q/<queue id>/<partition>`; a standard queue has many, a FIFO queue
  maps each message group to one by hash.
- **Receipt handle**: an opaque, HMAC-signed token naming the queue, the
  message and the receive that produced it.
- **Receive**: a committed change that makes a message invisible until a
  deadline and returns it with a receipt handle.

## Requirements

### Requirement 1: Opt-in module

#### Acceptance Criteria

1. The service SHALL live under `services/sqs/`, be built only with a
   Kconfig option `SQS` (default off), include only core public headers,
   and leave every existing target unchanged when off.
2. It SHALL be a service module with module number 9, runnable in
   `kythira_node` and as a stand-alone `sqs_node`.
3. A path-filtered `.github/workflows/sqs-module.yml` SHALL build and test
   it under Docker and rootless Podman.

### Requirement 2: Coverage and compatibility

#### Acceptance Criteria

1. Every operation in the pinned model SHALL be implemented or listed in
   `services/sqs/doc/unsupported.md` with its error; a generated test SHALL
   fail on an operation that is neither.
2. The `aws` profile SHALL be the default and reproduce SQS's limits and
   errors, both protocols' error shapes included.
3. Switches settable per cluster and per queue (a `kythira:compat:*` tag):
   message size (the pinned model's limit, 1 MiB when written), retention
   bounds (60 s to 14 days), batch size (10), in-flight limits (120,000
   standard, 120,000 FIFO), FIFO throughput limits, long-poll maximum
   (20 s), and queue-deletion and purge cool-downs (60 s).

### Requirement 3: Protocols and authentication

#### Acceptance Criteria

1. The gateway SHALL accept AWS JSON 1.0 and the AWS query protocol (core
   `aws_query_protocol.hpp`), answering in the protocol of the request,
   and queue URLs of AWS's shape on the configured endpoint.
2. Every request SHALL be authenticated with SigV4 through core
   `sigv4_verifier`.
3. Authorization SHALL go through `aws_request_authorizer` with an `sqs`
   action table, queue policies evaluated with identity policies, and
   static keys without IAM.

### Requirement 4: Queues

#### Acceptance Criteria

1. Create (idempotent on identical attributes, `QueueAlreadyExists`
   otherwise), delete, get URL, list (prefix, pagination), get and set
   attributes, purge, tag operations and the dead-letter source listing
   SHALL behave as SQS.
2. Queue ids SHALL never be reused; a queue recreated after deletion SHALL
   see no old message.
3. Approximate counts (`ApproximateNumberOfMessages`, `...NotVisible`,
   `...Delayed`) SHALL be maintained by the state machine, approximate as
   SQS documents.

### Requirement 5: Messages

#### Acceptance Criteria

1. Send, send batch, receive, delete, delete batch, change visibility and
   its batch SHALL behave as SQS, with per-entry results in batches.
2. A sent message SHALL be acknowledged only after it is committed through
   Raft.
3. Message attributes and system attributes (`AWSTraceHeader`) SHALL be
   stored and returned, with MD5 digests computed as SQS computes them, so
   SDKs that check digests accept them.
4. Visibility timeouts (0 s to 12 h), per-message delays and queue delays
   (up to 15 min), and retention SHALL be enforced from leader-stamped
   times in committed entries, never a replica's clock.
5. A receive SHALL be a committed entry: it makes the messages invisible,
   increments their receive counts and returns receipt handles. A receipt
   handle SHALL be valid only for its receive, so a delete with the handle
   of an earlier receive does not delete a message received again since,
   as SQS documents for expired handles.
6. Standard queues SHALL deliver at least once, in best-effort order. FIFO
   queues SHALL deliver in order within a message group and SHALL not
   return a group's next message while an earlier one is in flight.
7. FIFO deduplication (explicit ids and content-based, 5-minute window)
   SHALL hold across leader changes, because the dedup records are in the
   replicated state.
8. Fair queues SHALL behave as SQS: on a standard queue, a message group
   id spreads delivery across groups so one noisy group does not starve
   the others.

### Requirement 6: Long polling

#### Acceptance Criteria

1. `WaitTimeSeconds` and `ReceiveMessageWaitTimeSeconds` SHALL hold the
   request in the front end until messages are available or the wait
   ends, without the front end polling the data layer in a loop.
2. Data nodes SHALL notify waiting front ends when a partition gains
   visible messages (a send, an expired visibility, an ended delay), and a
   front end SHALL then try a receive.
3. A long poll SHALL consider all of a standard queue's partitions, as
   SQS's long polling queries all servers.

### Requirement 7: Dead-letter queues and redrive

#### Acceptance Criteria

1. A redrive policy (`maxReceiveCount`, target) SHALL move a message to its
   dead-letter queue on the receive that exceeds the count, as one
   committed change (a tier-1 transaction when the queues are in different
   groups), so it is never in both or neither.
2. Redrive allow policies SHALL be enforced.
3. `StartMessageMoveTask`, `ListMessageMoveTasks` and
   `CancelMessageMoveTask` SHALL move messages back with the rate limit
   given, run by a leader-side worker that resumes after a leader change.

### Requirement 8: Encryption

#### Acceptance Criteria

1. SSE-SQS (the default for new queues, as on SQS) and SSE-KMS SHALL
   encrypt message bodies and attributes at rest through the shared
   `kms_key_provider`, with SQS's data key reuse period.
2. Bodies SHALL be sealed by the front end before they are proposed, so
   data nodes, Raft logs and snapshots hold only ciphertext; the data key
   is held by front ends.

### Requirement 9: Throughput

#### Acceptance Criteria

1. A standard queue SHALL spread messages over partitions so its
   throughput grows with the cluster, as SQS's is effectively unlimited.
2. A FIFO queue SHALL meet SQS's per-queue limits by default, and in
   high-throughput mode SHALL spread message groups over partitions.
3. Throttling where SQS throttles SHALL return SQS's errors.

### Requirement 10: SNS HTTPS bridge

**User Story:** As a user of real Amazon SNS, I want a topic to deliver to
a Kythira queue.

#### Acceptance Criteria

1. An optional inbound endpoint SHALL accept SNS HTTP/HTTPS deliveries for
   a queue configured to take them: it SHALL confirm subscriptions, verify
   each message's SNS signature against the signing certificate (from an
   allowed host list, `sns.<region>.amazonaws.com` by default), and enqueue
   the message as SNS's SQS delivery would (raw or wrapped).
2. Kythira's own SNS SHALL deliver to Kythira SQS directly, not through
   this bridge.

### Requirement 11: Independent layers

**User Story:** As an operator, I want each layer runnable on its own, and
co-located by default.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_SQS_ROLES`, a subset of
   `gateway`, `front_end`, `data`; default all three.
2. Handlers SHALL reach the data layer only through a value-returning
   interface with local, remote and hybrid implementations, chosen per
   call; the route cache SHALL find partitions' groups.
3. The gateway SHALL verify SigV4 and hand front ends an authenticated
   call; internal calls SHALL use layer identities with `sqs` as the
   service and per-route role checks.
4. The availability notifications of Requirement 6.2 SHALL work across
   layers as a streaming internal call from data nodes to front ends.
5. Leader-side workers (redrive moves, retention expiry, dedup window
   cleanup) SHALL run on data nodes.
6. A co-located node SHALL serve local operations in-process.

### Requirement 12: Live migration

#### Acceptance Criteria

1. Stateless roles SHALL move with a drain and a restart; a draining front
   end SHALL end its long polls early with empty answers, which SQS
   clients treat as normal.
2. The data role SHALL move through learner, promote, leadership transfer
   and remove, and an `evacuate` admin call.
3. During a migration no acknowledged message SHALL be lost, FIFO order
   and deduplication SHALL hold, visibility timeouts SHALL keep their
   deadlines, and receipt handles issued before a step SHALL work after
   it.

### Requirement 13: Testing and conformance

#### Acceptance Criteria

1. Unit, property and in-process cluster tests SHALL cover visibility,
   receipt handles, FIFO order and dedup, delays, redrive and counts, with
   leader changes injected at every step.
2. The AWS CLI, boto3, aws-sdk-java-v2, aws-sdk-go-v2, aws-sdk-js-v3 (both
   protocols where an SDK still speaks query), the JMS library, Spring
   Cloud AWS, Celery/Kombu and the Extended Client (with Kythira S3 when
   built, else a stub) SHALL run in CI against co-located and split
   layouts.
3. Every migration path SHALL have its own test in both directions:
   gateway role, front-end role (with long polls in flight), data role, and
   the whole co-located to split path and back with a stop and reversal
   midway, under standard and FIFO producer and consumer load, checking
   Requirement 12.3; and a docker-chaos run of the full path killing one
   node per layer, on Docker and rootless Podman.
4. Interoperability with real Amazon SQS SHALL be tested as far as AWS
   allows: recorded SQS responses replayed in CI as differential fixtures;
   and a dispatch-only real-cloud bundle that runs the same client suite
   against SQS and Kythira and compares what the clients observe, runs the
   Extended Client with real S3 against Kythira SQS, and subscribes a
   Kythira queue to a real SNS topic through the bridge. Each run needs
   Clark's go in his own words, reports its cost and deletes what it made.
5. A measurement row SHALL record send and receive throughput and latency
   for standard and FIFO queues, co-located and split.

### Requirement 14: Documentation

#### Acceptance Criteria

1. `services/sqs/doc/` SHALL cover configuration, the layers and sizing,
   delivery semantics and clocks, encryption, the bridge, unsupported
   operations and the migration runbook.
