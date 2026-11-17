# Requirements Document

## Introduction

This spec adds an **Amazon SNS-compatible publish/subscribe service** to
Kythira. Unmodified AWS SDKs, the AWS CLI and SNS tools create topics,
subscribe SQS queues and HTTP endpoints, and publish, against a Kythira
cluster.

It follows Clark's request of 2026-11-17 ("Then build specs for S3, SNS,
and SQS following the rules"), which applies the rules he set that day:

- **Independent layers** (`.kiro/specs/kinesis-independent-layers/`): each
  layer can run as its own process or cluster, co-located operation is the
  default and is never required, and a running deployment can migrate from
  co-located to independent and back. This service is layered from the
  start and reuses that spec's shared core pieces.
- **Migration tests**: tasks that test every migration path.
- **Interoperability**: tasks that test interoperability with real Amazon
  SNS (and SQS) as far as AWS allows.

It follows the module conventions of the other AWS-compatible services and
depends on `.kiro/specs/sqs-compatible-queues/` for its main delivery
target.

There is no notification service in the tree today.

### Layers

1. **Gateway**: the AWS query protocol (SNS's only protocol), TLS, request
   limits, SigV4.
2. **Front end**: authorization (IAM and topic policies), handlers,
   message validation, subscription confirmation endpoints, throttling.
3. **Data**: the multi-Raft host and the topic state machine: topics,
   subscriptions and their attributes, FIFO ordering and deduplication,
   delivery cursors and leases.
4. **Segment store**: the publish log of each topic in the core record
   segment store (append-only, trimmed by retention; the FIFO archive is
   its long-retention form). Same layer, interface and volume service as
   Kinesis's.
5. **Delivery**: workers that read the publish log, evaluate filter
   policies, and deliver to each subscription with retries, backoff and
   dead-letter queues.

**Scope**: standard and FIFO topics; subscriptions to Kythira SQS, real
Amazon SQS, HTTP/HTTPS, email and email-JSON (through a configured SMTP
relay); raw message delivery; attribute and payload filter policies;
delivery retry policies; subscription dead-letter queues; FIFO message
archiving and replay; `PublishBatch`; message signatures (versions 1 and
2); topic policies; tags; SSE through `kms_key_provider`; data protection
policies stored but not enforced; the layers and their migration; tests.

**Out of scope**: SMS, mobile push (platform applications and endpoints),
Lambda and Firehose subscriptions (no Kythira counterpart), CloudWatch
delivery-status logging as an API (metrics are Prometheus).

## Glossary

The Kinesis independent-layers glossary applies. In addition:

- **Pinned model**: the botocore `sns` `service-2.json` at a pinned version.
- **Publish log**: a topic's committed messages, in the record segment
  store, under routing keys `t/<topic id>/<partition>`.
- **Delivery partition**: a slice of a topic's subscriptions and log
  partitions that one delivery worker owns under a lease.
- **Cursor**: a subscription's committed position in a log partition.

## Requirements

### Requirement 1: Opt-in module

#### Acceptance Criteria

1. The service SHALL live under `services/sns/`, be built only with a
   Kconfig option `SNS` (default off), include only core public headers,
   and leave every existing target unchanged when off.
2. It SHALL be a service module with module number 10, runnable in
   `kythira_node` and as a stand-alone `sns_node`.
3. A path-filtered `.github/workflows/sns-module.yml` SHALL build and test
   it under Docker and rootless Podman.

### Requirement 2: Coverage and compatibility

#### Acceptance Criteria

1. Every operation in the pinned model SHALL be implemented or listed in
   `services/sns/doc/unsupported.md` with its error (SMS and mobile push
   operations among the listed); a generated test SHALL fail on an
   operation that is neither.
2. The `aws` profile SHALL be the default and reproduce SNS's limits,
   errors and XML shapes.
3. Switches settable per cluster and per topic (a `kythira:compat:*` tag):
   message size (AWS's documented limit when the model is pinned),
   publish rates, subscription counts, FIFO throughput limits, the
   signing certificate host.

### Requirement 3: Protocol and authentication

#### Acceptance Criteria

1. The gateway SHALL accept the AWS query protocol (core
   `aws_query_protocol.hpp`) and answer in SNS's XML.
2. Requests SHALL be authenticated with SigV4; authorization SHALL use an
   `sns` action table with topic policies evaluated with identity policies,
   and static keys without IAM.

### Requirement 4: Topics and subscriptions

#### Acceptance Criteria

1. Create (idempotent on identical attributes), delete, list, get and set
   attributes for topics and subscriptions, subscribe, confirm,
   unsubscribe, list subscriptions (by topic, pagination), tags and
   permission operations SHALL behave as SNS.
2. HTTP/HTTPS and email subscriptions SHALL need confirmation through the
   token SNS sends; SQS subscriptions in the same account SHALL not, as on
   SNS.
3. Topic ids SHALL never be reused.

### Requirement 5: Publishing

#### Acceptance Criteria

1. `Publish` and `PublishBatch` (up to 10) SHALL return a message id only
   after the message is committed to the topic's publish log through Raft.
2. Message attributes, message structure `json` (per-protocol bodies) and
   subjects SHALL behave as SNS.
3. FIFO topics SHALL keep order per message group and deduplicate (explicit
   and content-based, 5-minute window) across leader changes, and deliver
   only to FIFO queues, as SNS does.
4. Publish SHALL not wait for delivery.

### Requirement 6: Delivery

#### Acceptance Criteria

1. Delivery SHALL be at least once to every subscription whose filter
   policy matches, after the message commits.
2. Filter policies SHALL support SNS's attribute and payload scopes and
   operators (exact, prefix, suffix, anything-but, numeric, exists,
   IP address, `$or`, wildcard), evaluated by delivery workers.
3. SQS delivery SHALL use Kythira SQS in-process when co-located with its
   front end, else its API, and real Amazon SQS with configured
   credentials; the message SHALL be SNS's envelope, or the raw body with
   raw delivery.
4. HTTP/HTTPS delivery SHALL follow SNS's request format and headers, sign
   each message (signature version 1 or 2 per topic), and retry by the
   delivery policy (SNS's default backoff phases and the configurable
   `healthyRetryPolicy` and throttling).
5. Email delivery SHALL go through a configured SMTP relay, and SHALL be
   off when none is configured.
6. A subscription's dead-letter queue (an SQS queue) SHALL receive messages
   whose retries are exhausted or whose endpoint is unreachable as SNS
   documents.
7. A FIFO topic SHALL deliver each group in order to each subscription.

### Requirement 7: Message signatures

#### Acceptance Criteria

1. Messages SHALL be signed with a cluster key whose certificate is served
   at `SigningCertURL` on the gateway.
2. AWS's message validators accept only certificates from
   `sns.<region>.amazonaws.com`; the documentation SHALL say so and show
   how each SDK's validator is pointed at a Kythira host, and the
   compatibility profile SHALL let the URL host be configured.
3. The signing key SHALL be rotated with an overlap window, and old
   certificates served until their messages' retries end.

### Requirement 8: Archive and replay

#### Acceptance Criteria

1. FIFO topics SHALL support `ArchivePolicy` retention (up to 365 days) in
   the publish log, tiered to object storage like Kinesis segments.
2. A subscription's `ReplayPolicy` SHALL redeliver archived messages from a
   point in time, as SNS does, with replay status attributes.

### Requirement 9: Encryption

#### Acceptance Criteria

1. SSE through the shared `kms_key_provider` SHALL encrypt messages at
   rest: front ends seal before publishing to the log, delivery workers
   open before delivering, so data nodes and segment stores hold only
   ciphertext.
2. Delivery to an encrypted SQS queue SHALL work as SNS documents (the
   queue's key policy allows the topic).

### Requirement 10: Independent layers

**User Story:** As an operator, I want each of SNS's five layers runnable
on its own, and co-located by default.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_SNS_ROLES`, a subset of
   `gateway`, `front_end`, `data`, `segments`, `delivery`; default all
   five.
2. Handlers SHALL reach the data layer through local, remote and hybrid
   implementations chosen per call; the publish log SHALL use the
   `segment_store` interface and volumes exactly as Kinesis Requirement 9
   specifies.
3. Delivery workers SHALL own delivery partitions under fenced leases in
   the topic state, read the log from data replicas (or segment nodes) and
   commit cursors and retry state through the data layer, so any number of
   delivery nodes share the work and a lost one's partitions move to
   another.
4. Delivery capacity SHALL scale through the layer membership group and
   `quorum_manager` (by backlog and delivery latency), as the Kinesis
   spec's stateless layers do.
5. Internal calls SHALL use layer identities with `sns` as the service and
   per-route role checks; delivery nodes SHALL hold the credentials for
   real AWS SQS and SMTP, and no other layer SHALL need them.
6. A co-located node SHALL deliver from its local replica in-process.

### Requirement 11: Live migration

#### Acceptance Criteria

1. Gateway, front-end and delivery roles SHALL move with a drain and a
   restart; a draining delivery node SHALL release its leases after
   committing its cursors.
2. The data role SHALL move through learner, promote, leadership transfer
   and remove, and the segment store by replica replacement or in-place
   store move, as in the Kinesis spec.
3. During a migration no committed message SHALL go undelivered to a
   matching subscription, FIFO order per group and subscription SHALL
   hold, duplicates SHALL stay within at-least-once, and confirmation
   tokens and signing certificates SHALL stay valid.

### Requirement 12: Testing and conformance

#### Acceptance Criteria

1. Unit, property and in-process cluster tests SHALL cover the topic state
   machine, filter policies (against SNS's documented examples), delivery
   leases and cursors, retries and dead-letter queues, with leader and
   worker failures injected.
2. The AWS CLI, boto3, aws-sdk-java-v2, aws-sdk-go-v2 and aws-sdk-js-v3
   SHALL run in CI, with SNS to SQS fan-out end to end against Kythira SQS,
   on co-located and five-way split layouts.
3. Every migration path SHALL have its own test in both directions:
   gateway, front-end, delivery and data roles, the publish log by replica
   replacement and by in-place store move, and the whole co-located to
   five-way path and back with a stop and reversal midway, under standard
   and FIFO publish load with SQS and HTTP subscribers, checking
   Requirement 11.3; and a docker-chaos run of the full path killing one
   node per layer, on Docker and rootless Podman.
4. Interoperability with real AWS SHALL be tested as far as AWS allows:
   recorded SNS responses replayed in CI as differential fixtures; and a
   dispatch-only real-cloud bundle where a Kythira topic delivers to a real
   SQS queue (raw and wrapped, standard and FIFO), a real SNS topic and a
   Kythira topic deliver the same messages to the same HTTP endpoint and
   the received requests are compared field by field, a real SNS topic
   delivers to a Kythira queue through the SQS bridge, and the SDKs'
   message validators verify Kythira signatures with the host configured.
   Each run needs Clark's go in his own words, reports its cost and
   deletes what it made.
5. A measurement row SHALL record publish latency and delivery latency and
   throughput by fan-out, co-located and split.

### Requirement 13: Documentation

#### Acceptance Criteria

1. `services/sns/doc/` SHALL cover configuration, the five layers and
   sizing, delivery semantics, signatures and validators, encryption,
   unsupported protocols and operations, and the migration runbook.
