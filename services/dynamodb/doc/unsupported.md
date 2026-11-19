# Unsupported operations

Every operation in the pinned models (`model/`) that this module does not
implement yet, with why and what it returns
(`.kiro/specs/dynamodb-compatible-api/` Requirement 2.1). An implemented
operation is named in `include/kythira/dynamodb/operations.hpp` instead;
`dynamodb_model_coverage_test` fails if an operation is in neither place,
in both, or listed here but missing from the models (Requirement 2.2).

Since task 23 the only rows allowed are out-of-scope ones, each saying why;
`dynamodb_model_coverage_test` checks that too.

Every operation below answers HTTP 400 with
`{"__type":"com.amazon.coral.service#UnknownOperationException"}`, which
is what the module's `aws_json::dispatcher` sends for a modeled operation
with no handler, and what AWS sends for an operation it does not know. The
test reads the table rows: keep one operation per row, in the
`` | Service | `Operation` | Why | `` form.

| Service | Operation | Why |
|---|---|---|
| DynamoDB | `CreateGlobalTable` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `DescribeGlobalTable` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `DescribeGlobalTableSettings` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `ListGlobalTables` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `UpdateGlobalTable` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `UpdateGlobalTableSettings` | out of scope: global tables version 2017.11.29 (legacy), which AWS asks new tables not to use; version 2019.11.21 works through `UpdateTable` and `DescribeTable` (task 22), and AWS's legacy calls do not see those tables either (task 23's decision) |
| DynamoDB | `DescribeTableReplicaAutoScaling` | out of scope: Application Auto Scaling is a separate AWS service (Introduction, "Out of scope") |
| DynamoDB | `UpdateTableReplicaAutoScaling` | out of scope: Application Auto Scaling is a separate AWS service (Introduction, "Out of scope") |

## Global tables: what `ReplicaUpdates` does not do

Version 2019.11.21 global tables (task 22) take `Create`, `Update` and
`Delete` replica updates with the per-replica overrides
(`KMSMasterKeyId`, `ProvisionedThroughputOverride`,
`OnDemandThroughputOverride`, `GlobalSecondaryIndexes` and
`TableClassOverride`), and `DeleteTable` of one replica. These parts of
the API answer `ValidationException` ("Kythira does not support ...
yet"), or differ, as listed:

- An override changes only the replica it names. Changes to the table's
  own settings in one region (its capacity, class or maximums) are not
  copied to the other replicas, which keep theirs.
- An `Update` that the replica's region refuses leaves the replica
  ACTIVE with the reason in `ReplicaStatusDescription`, since AWS has no
  failed state for an update.
- `DeleteTable` of a replica asks one ACTIVE replica to drop it before
  deleting. When none can be reached it answers `InternalServerError`
  and keeps the table, so the caller can try again.
- On multi-region strongly consistent tables (task 27), as on AWS:
  replicas cannot be added after creation, transactions, TTL and LSIs
  are refused, and a single replica or the witness cannot be deleted
  alone. Kythira's own rule: the `UpdateTable` that deletes the other
  two members goes to the region that keeps the table. A region without
  a quorum answers `InternalServerError`, since AWS's error for that
  case is not documented.
- `DeleteTable` of a multi-region strongly consistent table with
  replicas is refused: delete the other members with `ReplicaUpdates`
  first, as above.
- `ReplicaUpdates` cannot be combined with other `UpdateTable` changes in
  one request, and a table changes one replica at a time.
- A table need not have a DynamoDB stream to become global: replication
  reads Kythira's change log.
