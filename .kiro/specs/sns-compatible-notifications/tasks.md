# Implementation Plan

Depends on IAM (SigV4, authorizer), service colocation, the shared
`kms_key_provider`, the core record segment store, `.kiro/specs/
sqs-compatible-queues/` (tasks 1-4 for SQS delivery) and the shared core
pieces of `.kiro/specs/kinesis-independent-layers/` (a task that needs one
first builds it to that design). Each task is one PR unless noted.

- [x] 1. Module skeleton and evidence
  - `SNS` Kconfig option, `services/sns/`, module number 10, boundary
    list, `sns-module.yml`; pinned model and coverage test; recorded wire
    evidence from the CLI and SDKs; recorded SNS HTTP deliveries
  - _Requirements: 1.1-1.3, 2.1_
  - Part done (November 18, 2026): the module skeleton (`SNS`, CMake,
    empty boundary allow list, `sns_node` placeholder with `--self-test`),
    `module_numbers::sns = 10` in core, `ci_full` and its verbatim copies
    turning it on, `configs/ci_no_sns_defconfig` and `sns-module.yml`
    (boundary, module-on tests, module-off assertion), the pinned model
    (botocore 1.43.126, 42 operations, 34 error shapes), the generated
    operation table (with each error's query code and HTTP status) and its
    `--check` test, and the coverage test: 21 operations planned in task 4,
    21 SMS and mobile push operations listed as out of scope, all answered
    with `InvalidAction` until implemented.
  - Part done (November 18, 2026): the recording stub
    (`tests/evidence/recorder.py`) and checked-in wire evidence from the
    AWS CLI v2, boto3 and the Java, JS and Go SDKs running one 21-request
    scenario; `sns_wire_evidence` decodes every recording as the query
    codec must and requires all five to agree.
  - Done (November 18, 2026): real SNS HTTP deliveries,
    `tests/evidence/deliveries/` (one run on Clark's machine, under
    $0.01, nothing left behind). 14 deliveries: confirmations and
    notifications for wrapped and raw subscriptions, SignatureVersion 1 and
    2, subject, String/Number/Binary attributes, `MessageStructure` json
    and `PublishBatch`. `sns_real_deliveries` checks headers against bodies
    and verifies all 9 signatures by the documented strings. Finding: SNS
    sent no `UnsubscribeConfirmation` within a minute of the topic owner's
    `Unsubscribe` on either of two runs, although the documentation lists
    one; task 6 follows the recording.

- [x] 2. Topic state machine and publish log
  - Topics, subscriptions, FIFO dedup, publish into the record segment
    store, delivery partitions, leases with fencing, cursors and retry
    state; property tests
  - _Requirements: 4.3, 5.1, 5.3_
  - Done (November 18, 2026): `sns_topic_state_machine.hpp` and
    `sns_codec.hpp`. Topic ids come from a counter and are never reused;
    `CreateTopic` and `Subscribe` are idempotent on identical attributes;
    a publish (up to ten entries) appends to `t/<topic id>/<partition>`
    and barriers before `apply()` returns; FIFO dedup records (five
    minutes of leader time) are in the state and its snapshots; a
    delivery partition is (topic, log partition, subscription bucket)
    under a lease whose token fences cursor and retry commits. The
    snapshot carries segment descriptors, never message bytes, and a
    restore truncates a tail past it and fetches the active segment it
    lacks. `sns_topic_state_machine_test` runs random command mixes
    through two replicas, and through a replica restored midway, and
    requires identical results, state and logs. Splitting a topic's
    state across groups (task 9) is not done yet.

- [x] 3. Gateway, protocol and authorization
  - Query codec, SigV4, `sns` action table, topic policies, static keys,
    compatibility profile
  - _Requirements: 2.2, 2.3, 3.1, 3.2_
  - Done: `sns_front_end.hpp` takes a transport-free request through
    framing (form POST or GET), SigV4 (`sns`, query-protocol errors),
    the form (MissingAction, InvalidAction for an unknown version,
    operation or one with no handler), admission, the topic the request
    names (`TopicArn`, `ResourceArn`, the topic in `SubscriptionArn`, or
    CreateTopic's `Name`), and authorization of the operation's `sns:`
    action with the topic policy and tags, `aws:SourceOwner`,
    Subscribe's `sns:Protocol` and `sns:Endpoint`, and the extra
    actions CreateTopic needs for tags and a data protection policy.
    `sns_actions.hpp` is generated from AWS's pinned service reference
    (with the static-key roles), `sns_query.hpp` reads attribute maps,
    message attributes, tags and batches by name in any order,
    `sns_topic_policy.hpp` has the default topic policy, AddPermission
    and RemovePermission, and `sns_compat_profile.hpp` the five
    `kythira:compat:*` switches and SNS's documented limits by region.
    Static keys are core's `static_keys_file.hpp` with
    `sns_static_roles()`. The daemon mounts the front end on the Beast
    host with task 4's handlers; the rate limiter that uses the profile's
    rates plugs into the admission hook there too.

- [x] 4. Topic, subscription and publish API
  - Operations, confirmation tokens, attributes, message structure,
    `PublishBatch`
  - _Requirements: 4.1, 4.2, 5.1-5.4_
  - Part done (November 19, 2026): `sns_service.hpp` with the 12 topic
    operations (CreateTopic, DeleteTopic, Get/SetTopicAttributes,
    ListTopics, Tag/Untag/ListTagsForResource, Add/RemovePermission,
    Get/PutDataProtectionPolicy) over a `topic_store` (a local one over a
    single state machine; routing topics to groups is task 9), and
    `sns_service_test` through the front end.
  - Part done (November 19, 2026): the 7 subscription operations.
    HTTP/HTTPS, email and cross-account SQS subscriptions wait for a
    256-hex-character token valid three days; same-account SQS, Lambda
    and Firehose do not (Requirement 4.2). Sending the confirmation
    message is delivery's (task 6). Subscription ARNs end in the topic and
    subscription ids in UUID form, so they are never reused.
  - Done (November 19, 2026): Publish and PublishBatch. A message id is
    answered after the publish command commits (Requirement 5.1) and
    never waits for delivery (5.4); subject, `MessageStructure` json and
    message attributes are checked as SNS does and kept in the record
    (`sns_message.hpp`, 5.2); FIFO topics need a group id, deduplicate on
    an explicit id or the body's SHA-256 for five minutes, and hash groups
    to log partitions (5.3). PublishBatch reports each entry. The daemon
    serving these handlers comes with the gateway work of task 6 or 9.

- [x] 5. Filter policies
  - _Requirements: 6.2_
  - Done (November 19, 2026): `sns_filter_policy.hpp` parses a policy for
    its scope and matches message attributes or a JSON body: exact
    strings, numbers, booleans and null, `prefix`, `suffix`,
    `equals-ignore-case`, `wildcard`, `anything-but` (values, prefix,
    suffix), `numeric`, `exists`, `cidr` (IPv4 and IPv6) and `$or` at
    any level, with arrays matching on any element and SNS's typing of
    attribute data types (Binary ignored). Limits: 5 keys on any path,
    150 combinations, 256 KiB, and 200 filtered subscriptions per topic
    (`FilterPolicyLimitExceeded`). Subscribe and SetSubscriptionAttributes
    check the policy in its scope, so changing the scope cannot strand a
    nested policy. Error wording beyond the known SNS strings, and which
    body a `MessageStructure=json` message is filtered on, wait on task
    12's recordings. Delivery (task 6) calls `filter_policy::matches`.

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
