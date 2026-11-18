# Implementation Plan

Depends on IAM (SigV4, authorizer), service colocation (module interface),
the shared `kms_key_provider`, multi-raft transactions (dead-letter moves)
and the shared core pieces of `.kiro/specs/kinesis-independent-layers/`
(a task that needs one first builds it to that design). Each task is one
PR unless noted.

- [x] 1. Module skeleton and evidence
  - `SQS` Kconfig option, `services/sqs/`, module number 9, boundary list,
    `sqs-module.yml`; pinned model and coverage test; recorded wire
    evidence from the CLI, SDKs (JSON and query), JMS, Spring and Kombu
  - _Requirements: 1.1-1.3, 2.1_
  - Part done (November 18, 2026): the module skeleton (`SQS`, CMake,
    empty boundary allow list, `sqs_node` placeholder with `--self-test`),
    `configs/ci_no_sqs_defconfig` and `sqs-module.yml` (boundary, module-on
    tests, module-off assertion), the pinned model (botocore 1.43.100, 23
    operations), the generated operation table with its `--check` test, and
    the coverage test with every operation listed in
    `services/sqs/doc/unsupported.md` against its task.
  - Done (November 18, 2026): the recording stub and wire evidence in
    `services/sqs/tests/evidence/` (AWS CLI v2, boto3 on JSON and on the
    query protocol, aws-sdk-java-v2, the JMS library and Kombu), checked
    by `sqs_wire_evidence`. Spring Cloud AWS, the Extended Client and
    aws-sdk-java v1 move to task 12 (README there says why). Findings for
    task 3: every JSON client sends `x-amzn-query-mode: true`, so errors
    need the query code in `x-amzn-query-error`; `ReceiveMessage` must
    accept both `AttributeNames` and `MessageSystemAttributeNames`. The
    module registers with `module_registry` (module 9) when the daemon
    first serves requests (task 3); until then there is nothing to run in
    `kythira_node`.

- [x] 2. Queue state machine
  - Messages, visibility index, receipt sequence, counts, delays,
    retention, FIFO group heads and dedup, partitions; property tests with
    leader changes
  - _Requirements: 4.2, 4.3, 5.2, 5.4-5.8_
  - Done (November 18, 2026): `sqs_queue_commands.hpp` (the entries and
    replies, versioned and bounded) and `sqs_queue_state_machine.hpp`, a
    `persistent_staged_state_machine` on the `kv_engine`: messages,
    visible and pending indexes, retention index, FIFO group heads,
    deduplication records with their expiry index, per-partition counts;
    receives as committed entries with receipt sequences; housekeeping at
    each entry's leader-stamped time, bounded per entry; splits only at
    partition routing keys. `sqs_queue_state_machine_test` adds a seeded
    model check against a plain reference model, with replicas restarted
    or rebuilt from a snapshot mid-run. Fair queues (5.8) are not in this
    task: they need the per-group spreading of task 8, where standard-queue
    partitions are chosen, and are moved there.

- [ ] 3. Gateway, protocols and authorization
  - JSON 1.0 and query codecs, SigV4, `sqs` action table, queue policies,
    static keys, compatibility profile
  - _Requirements: 2.2, 2.3, 3.1-3.3_

- [ ] 4. Queue and message API
  - Queue operations; send, receive, delete, visibility and batches;
    attributes and MD5; receipt handles
  - _Requirements: 4.1, 5.1, 5.3, 5.5_

- [ ] 5. Long polling
  - Parking, availability subscriptions, leader deadline ticks
  - _Requirements: 6.1-6.3_

- [ ] 6. Dead-letter queues and move tasks
  - _Requirements: 7.1-7.3_

- [ ] 7. Encryption
  - SSE-SQS default and SSE-KMS through `kms_key_provider`, sealing in the
    front end
  - _Requirements: 8.1, 8.2_

- [ ] 8. Partitioning and throughput
  - Partition growth for standard queues, FIFO high-throughput mode,
    throttling; fair queues (moved here from task 2)
  - _Requirements: 5.8, 9.1-9.3_

- [ ] 9. SNS HTTPS bridge
  - Subscription confirmation, signature verification with the host
    allow list, raw and wrapped enqueue
  - _Requirements: 10.1, 10.2_

- [ ] 10. Independent layers
  - `KYTHIRA_SQS_ROLES`; local, remote and hybrid data access;
    authenticated call; cross-layer availability stream; workers on data
    nodes only; drain that ends long polls early
  - _Requirements: 11.1-11.6, 12.1_

- [ ] 11. Migration operations and path tests
  - `evacuate` for the data role
  - One test per path in both directions under standard and FIFO load:
    gateway role, front-end role with long polls in flight, data role,
    and the whole co-located to split path and back with a stop and
    reversal midway; each checks Requirement 12.3
  - docker-chaos scenario of the full path killing one node per layer,
    Docker and rootless Podman
  - _Requirements: 12.2, 12.3, 13.3_

- [ ] 12. Client suites in CI
  - CLI, SDKs, JMS, Spring Cloud AWS, Celery/Kombu, Extended Client, on
    co-located and split layouts
  - _Requirements: 13.1, 13.2_

- [ ] 13. Interoperability with real Amazon SQS
  - CI (no spend): recorded SQS responses replayed as differential fixtures
  - Real-cloud bundle (dispatch-only, repo-variable switch): the client
    suite against SQS and Kythira compared; Extended Client with real S3
    on Kythira SQS; a real SNS topic delivering to a Kythira queue through
    the bridge
  - Each run needs Clark's go, reports cost, deletes what it made
  - _Requirements: 13.4_

- [ ] 14. Measurement and documentation
  - _Requirements: 13.5, 14.1_
