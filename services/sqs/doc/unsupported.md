# SQS operations not implemented

`.kiro/specs/sqs-compatible-queues/` Requirement 2.1: every operation in the
pinned model (`../model/service-2.json`, botocore 1.43.100) is either
implemented, and then listed in `../implemented-operations.txt`, or listed
here with its reason and the exact error it returns.
`tools/check_coverage.py` (the ctest `sqs_model_coverage`) fails when an
operation is in neither list, so a model upgrade that adds one fails until it
is placed.

Until the gateway exists (task 3) no request is served at all. Once it does,
an operation listed here is answered like an action the model does not have:
`UnknownOperationException` with HTTP status 400 on AWS JSON 1.0 (with the
query-compatible code in `x-amzn-query-error`), and `InvalidAction` with HTTP
status 400 on the query protocol. Task 13's recorded SQS responses pin the
exact bodies.

Every operation in the model is planned; none is left out of the spec.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `AddPermission` | task 3 | Not built yet (queue policies and authorization). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `CancelMessageMoveTask` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ChangeMessageVisibility` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ChangeMessageVisibilityBatch` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `CreateQueue` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `DeleteMessage` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `DeleteMessageBatch` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `DeleteQueue` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `GetQueueAttributes` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `GetQueueUrl` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListDeadLetterSourceQueues` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListMessageMoveTasks` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListQueueTags` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListQueues` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `PurgeQueue` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ReceiveMessage` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `RemovePermission` | task 3 | Not built yet (queue policies and authorization). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `SendMessage` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `SendMessageBatch` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `SetQueueAttributes` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `StartMessageMoveTask` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `TagQueue` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `UntagQueue` | task 4 | Not built yet (queue and message API). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
