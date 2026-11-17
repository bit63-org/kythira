# Implementation Plan

Depends on IAM (SigV4, authorizer), service colocation, the shared
`kms_key_provider`, the core record segment store, `.kiro/specs/
sqs-compatible-queues/` (tasks 1-4 for SQS delivery) and the shared core
pieces of `.kiro/specs/kinesis-independent-layers/` (a task that needs one
first builds it to that design). Each task is one PR unless noted.

- [ ] 1. Module skeleton and evidence
  - `SNS` Kconfig option, `services/sns/`, module number 10, boundary
    list, `sns-module.yml`; pinned model and coverage test; recorded wire
    evidence from the CLI and SDKs; recorded SNS HTTP deliveries
  - _Requirements: 1.1-1.3, 2.1_

- [ ] 2. Topic state machine and publish log
  - Topics, subscriptions, FIFO dedup, publish into the record segment
    store, delivery partitions, leases with fencing, cursors and retry
    state; property tests
  - _Requirements: 4.3, 5.1, 5.3_

- [ ] 3. Gateway, protocol and authorization
  - Query codec, SigV4, `sns` action table, topic policies, static keys,
    compatibility profile
  - _Requirements: 2.2, 2.3, 3.1, 3.2_

- [ ] 4. Topic, subscription and publish API
  - Operations, confirmation tokens, attributes, message structure,
    `PublishBatch`
  - _Requirements: 4.1, 4.2, 5.1-5.4_

- [ ] 5. Filter policies
  - _Requirements: 6.2_

- [ ] 6. Delivery workers and targets
  - Leased workers; Kythira SQS, real SQS, HTTP/HTTPS with retry policies,
    SMTP; raw delivery; dead-letter queues; FIFO ordering per group and
    subscription
  - _Requirements: 6.1, 6.3-6.7_

- [ ] 7. Message signatures
  - v1 and v2, certificate serving, configurable host, rotation
  - _Requirements: 7.1-7.3_

- [ ] 8. Archive, replay and encryption
  - FIFO archive retention and tiering, replay policies; SSE sealing in
    the front end, opening in delivery
  - _Requirements: 8.1, 8.2, 9.1, 9.2_

- [ ] 9. Independent layers
  - `KYTHIRA_SNS_ROLES`; local, remote and hybrid data access; publish log
    on volumes; delivery nodes apart with leases over the network;
    delivery scaling through the membership group; credentials only on
    delivery nodes
  - _Requirements: 10.1-10.6_

- [ ] 10. Migration operations and path tests
  - Drain for gateway, front-end and delivery roles (leases released after
    cursor commit); `evacuate` for data; segment moves as in Kinesis
  - One test per path in both directions under standard and FIFO load with
    SQS and HTTP subscribers: gateway, front-end, delivery and data roles,
    publish log by replica replacement and by in-place store move, and the
    whole co-located to five-way path and back with a stop and reversal
    midway; each checks Requirement 11.3
  - docker-chaos scenario of the full path killing one node per layer,
    Docker and rootless Podman
  - _Requirements: 11.1-11.3, 12.3_

- [ ] 11. Client suites in CI
  - CLI and SDKs with SNS to SQS fan-out on co-located and split layouts
  - _Requirements: 12.1, 12.2_

- [ ] 12. Interoperability with real AWS
  - CI (no spend): recorded SNS responses replayed as differential fixtures
  - Real-cloud bundle (dispatch-only, repo-variable switch): Kythira topic
    to a real SQS queue (raw, wrapped, standard, FIFO); a real SNS topic
    and a Kythira topic delivering to one HTTP endpoint, requests compared
    field by field; a real SNS topic to a Kythira queue through the SQS
    bridge; SDK validators checking Kythira signatures
  - Each run needs Clark's go, reports cost, deletes what it made
  - _Requirements: 12.4_

- [ ] 13. Measurement and documentation
  - _Requirements: 12.5, 13.1_
