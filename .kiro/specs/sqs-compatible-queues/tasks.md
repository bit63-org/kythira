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

- [x] 3. Gateway, protocols and authorization
  - JSON 1.0 and query codecs, SigV4, `sqs` action table, queue policies,
    static keys, compatibility profile
  - _Requirements: 2.2, 2.3, 3.1-3.3_
  - Progress: the protocol half is done. `sqs_codec.hpp` reads both
    protocols into one JSON object in the model's names and answers in the
    request's protocol; query names and error codes come from the pinned
    query-era model (`model/query/`). `sqs_codec_test` replays every
    recorded request: JSON ones validate, query ones decode to exactly the
    JSON body botocore built them from. The replay showed that clients put
    message system attribute names in ReceiveMessage's `AttributeNames`,
    whose model enum lists queue attributes only, so that member is
    checked as a string list and left to the handler. The action table,
    each operation's authorizing action and the static-key roles are
    generated from AWS's service reference; ReceiveMessage counts as a
    write (it is a committed entry) and is outside read-only. The
    compatibility profile covers every switch of 2.3. The front end
    (`sqs_front_end.hpp`) authenticates with SigV4 in the request's
    protocol (JSON wording plus `x-amzn-query-error`, or query wording),
    resolves the queue from `QueueUrl`, `QueueName` or `SourceArn`, and
    authorizes the operation's primary action on the queue's ARN with its
    tags and `Policy` from a queue lookup, so queue policies are evaluated
    with identity policies, cross-account included. Static keys use core's
    `static_key_authorizer` with the generated roles. `sqs_queue_policy.hpp`
    holds the AddPermission/RemovePermission policy edits; their handlers
    move to task 4 with the queue catalog they write to, and the HTTP
    listener and daemon wiring come with task 4's handlers (nothing to
    serve before then).

- [x] 4. Queue and message API
  - Queue operations; send, receive, delete, visibility and batches;
    attributes and MD5; receipt handles
  - AddPermission and RemovePermission over `sqs_queue_policy.hpp`; the
    HTTP listener on the shared Beast host and the `sqs_node` wiring
    (static keys from core's `static_keys_file.hpp`), moved here from
    task 3 so they arrive with handlers to serve
  - Done: message attributes, MD5 and receipt handles
    (`sqs_messages.hpp`, `sqs_receipts.hpp`); queue attributes
    (`sqs_queue_attributes.hpp`); the catalog in the queue state machine
    (`sqs_catalog.hpp`); every queue and message handler including
    AddPermission and RemovePermission (`sqs_service.hpp`) over
    `queue_cluster`; `raft_queue_cluster` and leader forwarding; the
    listener (`sqs_listener.hpp`); the service module, number 9, on
    `multi_raft` (`cmd/sqs_node/sqs_module.hpp`), registered for
    kythira_node and run alone by `sqs_node` when `KYTHIRA_NODE_DATA_DIR`
    is set, so a send is acknowledged only once committed (Requirement
    5.2); `sqs_node`'s in-memory development mode otherwise. Checked end
    to end with AWS CLI v2 in both modes, across a restart. One group
    holds every queue until the independent layers (task 12) spread
    partitions over groups
  - _Requirements: 1.2, 4.1, 5.1, 5.2, 5.3, 5.5_

- [x] 5. Long polling
  - Parking, availability subscriptions, leader deadline ticks
  - Done: `sqs_long_poll.hpp` (the availability hub: a parked receive
    subscribes to every partition of its queue before its first pass, so
    no notification is lost; a drain answers parked receives empty);
    the state machine's availability listener, called after each commit;
    `sqs_workers.hpp` (the tick worker on each partition group's leader,
    woken by the earliest deadline and by every commit, idle-capped at
    1 s); wired into the module and both `sqs_node` modes. Co-located
    only: the notifications cross layers as a stream with task 12
  - _Requirements: 6.1-6.3_

- [x] 6. Dead-letter queues and move tasks
  - Done: a receive carries its queue's redrive target, and a message
    already received `maxReceiveCount` times moves to the dead-letter
    queue in the same entry (one queue at every point; FIFO groups keep
    their order); `DeadLetterQueueSourceArn`; redrive allow policies;
    `ListDeadLetterSourceQueues`; move tasks (`StartMessageMoveTask`,
    `ListMessageMoveTasks`, `CancelMessageMoveTask`) as catalog records,
    run by `sqs_workers.hpp`'s move worker on the catalog leader at the
    task's rate with one `move` entry per partition. Every operation of
    the pinned model is now implemented. Moves stay within the one group
    until task 12 makes cross-group moves transactions
  - _Requirements: 7.1-7.3_

- [x] 7. Encryption
  - SSE-SQS default and SSE-KMS through `kms_key_provider`, sealing in the
    front end
  - Done: `sqs_sse.hpp`. The front end seals body and attributes with
    AES-256-GCM before proposing (digests and the dedup hash over the
    plaintext first), so logs, engines and snapshots hold ciphertext.
    Envelope data keys per queue, reused for
    `KmsDataKeyReusePeriodSeconds`; each sealed message carries its
    wrapped key, so it opens on any front end, after a move to another
    queue, and after the queue's encryption changes. Provider failures
    answer as `Kms*` errors. Providers: SSE-SQS wraps under a cluster
    master key (`SQS_SSE_KEY_FILE`, else derived from
    `SQS_FORWARD_SECRET`); SSE-KMS through `SQS_KMS=local` (passphrase).
    The provider interface has the shape of the shared `kms_key_provider`;
    the `kythira` and `aws` providers come when the KMS spec's task 16
    moves that library out of Kinesis
  - _Requirements: 8.1, 8.2_

- [x] 8. Partitioning and throughput
  - Partition growth for standard queues, FIFO high-throughput mode,
    throttling; fair queues (moved here from task 2)
  - Done: fair queues in the state machine (a standard partition indexes
    visible messages by message group and a receive takes one from each
    group in turn, the turn carried across receives); `grow_worker`
    doubling a standard queue's partitions (4 up to 64) when its send rate
    passes 500 a second per partition, through a catalog `grow`;
    high-throughput FIFO (16 partitions) only with SQS's pair of settings,
    a FIFO count fixed at creation; FIFO request rates (`RequestThrottled`,
    per front end) and in-flight limits (`OverLimit` for standard, no
    messages for FIFO). The one deliberate difference from SQS is listed
    in `doc/unsupported.md`. Growth stays within the one group until
    task 12 spreads partitions over groups
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
