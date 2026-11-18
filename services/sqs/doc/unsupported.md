# SQS operations not implemented

`.kiro/specs/sqs-compatible-queues/` Requirement 2.1: every operation in the
pinned model (`../model/service-2.json`, botocore 1.43.100) is either
implemented, and then listed in `../implemented-operations.txt`, or listed
here with its reason and the exact error it returns.
`tools/check_coverage.py` (the ctest `sqs_model_coverage`) fails when an
operation is in neither list, so a model upgrade that adds one fails until it
is placed.

An operation listed here is answered like an action the model does not have:
`UnknownOperationException` with HTTP status 400 on AWS JSON 1.0 (with the
query-compatible code in `x-amzn-query-error`), and `InvalidAction` with HTTP
status 400 on the query protocol. Task 13's recorded SQS responses pin the
exact bodies.

Every operation in the model is planned; none is left out of the spec.

| Operation | Planned | Reason | Error |
|---|---|---|---|
| `CancelMessageMoveTask` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListDeadLetterSourceQueues` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `ListMessageMoveTasks` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
| `StartMessageMoveTask` | task 6 | Not built yet (dead-letter queues and move tasks). | `UnknownOperationException` (JSON) or `InvalidAction` (query), HTTP 400 |
