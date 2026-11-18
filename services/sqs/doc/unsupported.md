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

Every operation in the pinned model is implemented today, so the table is
empty. A model upgrade that adds an operation adds its row here until a task
builds it.

| Operation | Planned | Reason | Error |
|---|---|---|---|

## Behaviour that differs from SQS

| Behaviour | SQS | Kythira | Why |
|---|---|---|---|
| `DeduplicationScope` back to `queue` on a high-throughput FIFO queue | allowed (with `FifoThroughputLimit` back to `perQueue`) | `InvalidAttributeValue` | A high-throughput queue spans 16 partitions, each with its own deduplication records, and a group always maps to one partition. Queue-wide deduplication would need the records in one place; moving groups would break their order. Create a new queue instead. |
| FIFO request rates (300 a second per action, per partition in high-throughput mode) | per queue | per queue on each front end | Each front end counts its own requests, so Kythira never refuses a request SQS would take but may take some SQS would refuse. `kythira:compat:fifo-throughput=off` turns the limit off. |
