# Channels

A channel delivers the records of one or more of an account's streams to a
general purpose S3 bucket, or to Apache Iceberg tables on S3 Tables
(`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement 18). The
five calls are `CreateChannel`, `DescribeChannel`, `ListChannels`,
`UpdateChannel` and `DeleteChannel`, with the pinned model's shapes.

**Status: delivery to general purpose S3 and to S3 Tables (or any Iceberg
REST catalog) works.** A channel can be created, described, listed,
updated, tagged and deleted, and it keeps its source streams from being
deleted. An S3 channel's records reach its bucket as described under
[Delivery to S3](#delivery-to-s3); an S3 Tables channel's records are
appended to its Iceberg table as described under
[Delivery to S3 Tables](#delivery-to-s3-tables).

## What the API checks

These are the rules the model's documentation states, enforced as AWS
describes them:

- Exactly one destination: `S3DestinationConfiguration` or
  `S3TablesDestinationConfiguration` (`InvalidArgumentException`
  otherwise).
- Every source stream is in the caller's account and region, is listed
  once, exists (`ResourceNotFoundException`), is ACTIVE or UPDATING
  (`ResourceInUseException`) and is in on-demand mode
  (`InvalidArgumentException`).
- Record formats by destination: `GSR_JSON` only to S3 Tables, `STRING`
  and `BYTE_ARRAY` only to S3, `JSON` to both. S3 Tables needs a
  `GSRSchemaARN`; S3 refuses one.
- `EncryptionConfiguration` cannot name the AWS managed key
  (`alias/aws/kinesis`).
- At most 50 tags; a channel name in use is `ResourceInUseException`.
- `UpdateChannel` changes only the data freshness of the channel's own
  destination type and the logging configuration; anything else is
  delete and create again.
- `DeleteStream` refuses a stream that feeds a channel
  (`ResourceInUseException`). `DescribeStreamSummary`'s `ChannelCount`
  counts them.
- Each call is held to 5 a second per account, as AWS documents, unless
  the control-plane rates are switched off.

## Identifiers

A channel's id comes from the catalog's id counter, which streams share,
so ids are never reused. `ChannelId` is that id in a UUID's shape
(`00000000-0000-4000-8000-<12 hex digits>`), and the ARN is
`arn:<partition>:kinesis:<region>:<account>:channel/<ChannelId>`, the form
the IAM action table uses. A channel deleted and created again under the
same name gets another id and another ARN; the old ARN answers
`ResourceNotFoundException`.

Each source is pinned to the stream's id at creation, so a stream deleted
and created again under the same name is not a deleted channel's source.

## Authorization

`DescribeChannel`, `UpdateChannel` and `DeleteChannel` are authorized on
the channel ARN, and tag calls on a channel ARN on that ARN. A channel's
ARN is known only once the create commits, so `CreateChannel` is
authorized as `kinesis:CreateChannel` (and `kinesis:TagResource` with
tags) on `arn:...:channel/*`, `kinesis:AssociateStreamsWithChannel` on
each source stream's ARN, and `iam:PassRole` on the service execution role. On a node
authenticating with static keys there is no IAM to check a role against,
so only `admin` keys may create a channel.

## Delivery to S3

Every `kinesis_gateway_node` runs delivery on its maintenance pass
(`KINESIS_MAINTENANCE_INTERVAL_MS`, a minute by default). For each ACTIVE
S3 channel, the node that leads a source shard's group delivers that
shard:

- It starts from the channel's checkpoint for the shard, a catalog entry
  holding the next record to deliver. A new channel starts with the
  records that arrive once it exists; what the stream held before is not
  delivered.
- It writes an object once the oldest undelivered record is
  `DataFreshnessInSeconds` old, once the batch reaches 64 MiB, or when a
  shard closed by a reshard has been read to its end.
- After the object is written it moves the checkpoint, as a
  compare-and-set from where it read. If two nodes both believed they led
  the shard, one commits and the other's object is a duplicate written to
  the same key.
- A child shard is delivered only once its parents have been delivered to
  their ends, so a partition key's records arrive in order across a
  reshard.

Delivery is at least once, and in sequence order within a shard.

**Object keys.** `OutputKeyTemplate`, or
`!{kinesis:stream-name}/!{timestamp:yyyy/MM/dd/HH}/` when left out, then
`<channel>-<shard id>-<first sequence number>-<last sequence number>` and
the compression's extension (`.gz`, `.zst`). The template takes
`!{timestamp:...}` with `yyyy`, `MM`, `dd`, `HH` and `mm` (UTC, from the
batch's first record's arrival time), `!{kinesis:stream-name}`,
`!{kinesis:shard-id}` and `!{kinesis:channel-name}`; anything else is
copied as written. The key depends only on the batch, so a batch retried
after a lost checkpoint overwrites the same object.

**Storage class and bucket owner.** Each object is written with the
destination's `StorageClass` (S3's default when left out) and its
`ExpectedBucketOwner`, so S3 refuses the write when the bucket has
changed hands; the batch stays undelivered and is retried on the next
pass. Dead letters keep the default storage class and are checked against
the dead-letter configuration's own `ExpectedBucketOwner`.

**Object body.** One record per line: the record's bytes for `JSON` and
`STRING`, base64 for `BYTE_ARRAY`.

**Dead letters.** A `JSON` record whose bytes do not parse as JSON goes to
the dead-letter location instead: the `DeadLetterQueueS3Configuration`
bucket under its `ErrorOutputPrefix`, or the destination bucket under
`errors/` when there is none, as AWS documents. Each is one JSON line with
`errorCode`, `errorMessage`, `sequenceNumber`, `partitionKey`,
`approximateArrivalTimestamp` and `rawData` (base64), in an object named
like the batch with `.json`.

**Compression.** `NONE`, `GZIP` when the build found zlib and `ZSTD` when
it found libzstd (vcpkg builds have both). A node that cannot write the
compression a channel asks for sets the channel to FAILED with a reason
naming it, rather than leaving it ACTIVE and silently idle.

**Node settings.**

| Variable | Default | Meaning |
|---|---|---|
| `KINESIS_CHANNEL_DELIVERY` | `true` | Deliver channels from this node |
| `KINESIS_CHANNEL_S3_REGION` | `KINESIS_REGION` | Region of the destination buckets |
| `KINESIS_CHANNEL_S3_ENDPOINT` | AWS's | An S3-compatible endpoint (MinIO, Kythira's own S3) |
| `KINESIS_CHANNEL_MAX_DELAY_MS` | `0` | When set (1000 to 900000), write a batch once it is this old even inside the channel's freshness window: seconds-scale delivery for tests and demos |
| `KINESIS_CHANNEL_ROLE` | `node` | `node` writes with this node's own credentials; `assume` writes each channel's objects as its `ServiceExecutionRoleARN` |
| `KINESIS_CHANNEL_STS_ENDPOINT` | AWS's, in `KINESIS_CHANNEL_S3_REGION` | STS's URL for `assume` (Kythira's IAM service answers `AssumeRole` too) |
| `KINESIS_CHANNEL_CA_FILE` | the system store | The CA bundle the STS and Iceberg catalog endpoints' certificates chain to |
| `KINESIS_CHANNEL_ICEBERG_URI` | S3 Tables' Iceberg endpoint in the table bucket's region | The Iceberg REST catalog's base URL, e.g. a local catalog for tests |
| `KINESIS_CHANNEL_ICEBERG_WAREHOUSE` | the table bucket ARN | The `warehouse` passed to `GET /v1/config` |
| `KINESIS_CHANNEL_ICEBERG_SIGV4` | `true` | Sign catalog requests with SigV4 (service `s3tables`); `false` for a catalog that takes a bearer token or nothing |
| `KINESIS_CHANNEL_ICEBERG_TOKEN` | none | A bearer token for a catalog that is not signed with SigV4 |

The container scenario (`services/kinesis/tests/docker/`) delivers a
channel to its S3 mock with a five-second delay while every node is
killed in turn, and checks that every record reaches the bucket in order
under each key within a shard.

Credentials come from the AWS SDK's usual chain. A build without the AWS
SDK's s3 component logs at start that it does not deliver channels.

## Delivery to S3 Tables

An S3 Tables channel is delivered by the same pass, with the same shard
ownership, checkpoints, freshness rule and reshard ordering as an S3
channel. What differs is where a batch goes: it is appended to the
configured table as one Iceberg snapshot.

- The node loads the table from the Iceberg REST catalog. For S3 Tables
  that is `https://s3tables.<region>.amazonaws.com/iceberg` with the table
  bucket ARN as the warehouse, signed with SigV4 as the node or, with
  `KINESIS_CHANNEL_ROLE=assume`, as the channel's execution role.
- Each record is parsed as JSON and mapped onto the table's current
  schema by column name. The rows are grouped by the table's partition
  spec and written as Parquet data files under the table's location
  (`<location>/data/<partition path>/`), with the destination's
  `CompressionType` (`NONE`, `SNAPPY`, or `ZSTD` when the build found
  libzstd).
- It writes a manifest and a manifest list (Avro, format version 2), then
  commits `add-snapshot` and `set-snapshot-ref main`, requiring the
  table's UUID and the `main` branch's current snapshot. The snapshot's
  id is derived from the table and the batch, and its summary carries
  `kythira.channel-batch` = `<ChannelId>/<shard>/<first>-<last>`.
- If another writer committed first (409) or the catalog failed (5xx), the
  node loads the table again. If the batch's snapshot is already there the
  batch is done; otherwise it rebuilds the manifest list on the new parent
  and commits again, up to four times a pass. Delivery is therefore exactly
  once per batch in the table, even across a lost checkpoint or a node
  killed between commit and checkpoint.

**Column types.** `boolean`, `int`, `long`, `float`, `double`, `string`,
`binary` (base64 in the record), `date` (days, or `yyyy-MM-dd`), `time`
(microseconds, or `HH:mm:ss[.ffffff]`), `timestamp` and `timestamptz`
(milliseconds since the epoch, or ISO 8601), `uuid`, and nested `struct`
and `list` columns of those. A missing optional column is null; a missing
required column refuses the record. A table with a `decimal`, `fixed` or
`map` column, or a format version other than 2, sets the channel to
FAILED with a reason naming the column.

**Partition transforms.** `identity`, `year`, `month`, `day`, `hour`,
`bucket[N]`, `truncate[W]` and `void`, computed as the Iceberg
specification defines them. When the channel's `PartitionSpec` asks for
`TIME_HOUR` on a column, the table's spec must have `hour(<column>)`, or
the channel is set to FAILED.

**Dead letters.** A record that is not JSON (`InvalidJson`), or that does
not fit the table's schema (`SchemaMismatch`: a wrong type, a missing
required column), goes to the destination's
`DeadLetterQueueS3Configuration` in the same JSON-lines form as an S3
channel's dead letters; the rest of the batch is committed.

**The table must exist.** The node does not create the namespace or the
table. While the catalog answers 404 (or refuses the role), the batch
stays undelivered, the pass's log line says why (`last_failure=`), and the
channel stays ACTIVE.

The container scenario (`services/kinesis/tests/docker/`) runs the
Apache Iceberg REST catalog fixture over its S3 mock, writes JSON records
through an S3 Tables channel while every node is killed in turn, and reads
the table back with pyiceberg: every record is a row, and no batch was
committed twice or overlaps another in its shard. The unit tests export a
table that `services/kinesis/tests/iceberg/read_exported_table.py` reads
back with pyiceberg, including partition pruning.

## Execution role

AWS writes a channel's objects as the channel's `ServiceExecutionRoleARN`,
so the role's policies and the bucket's policy decide what a channel can
reach. With `KINESIS_CHANNEL_ROLE=assume` a node does the same:

- Before writing for a channel it calls STS `AssumeRole` on the role, with
  its own credentials from the AWS SDK's usual chain, as the session
  `kythira-channel-<ChannelId>`, so CloudTrail and server access logs name
  the channel. The role's trust policy must let the node's identity assume
  it.
- It keeps the temporary credentials (an hour) per role and channel, and
  asks again five minutes before they expire. If STS refuses a refresh
  while the old set is still valid, the old set is used.
- A refusal (`AccessDenied`, an unknown role) leaves the batch undelivered:
  the next pass retries it, STS is asked at most every 30 seconds per
  channel, and the node's log line for the pass carries STS's code and the
  role (`last_failure=`). The channel stays ACTIVE, as AWS's does while a
  role is misconfigured.

`CreateChannel` already checks `iam:PassRole` on the role for the caller,
so only a caller allowed to hand the role over can create a channel that
writes as it.

## Limits and differences

- A channel is ACTIVE as soon as `CreateChannel` answers, and an update
  applies at once, so the CREATING and UPDATING states are never shown.
  Clients that wait for ACTIVE work unchanged.
- `DataFreshnessInSeconds` is 300 to 900 seconds, 300 when left out, as
  the model documents; an S3 Tables channel names exactly one table, the
  only case the model says AWS supports today.
- `aws:ResourceTag` conditions are not evaluated for channel ARNs.
- Delivered objects are not yet encrypted with the channel's
  `EncryptionConfiguration`.
- An S3 Tables channel validates records against the table's schema; the
  `GSRSchemaARN` is checked to be present but its schema is not fetched
  from Glue. Parquet files carry no column statistics yet, so engines
  prune by partition but not by min/max.
- A node writes with its own credentials unless `KINESIS_CHANNEL_ROLE`
  is `assume` (see [Execution role](#execution-role)). The default stays
  `node` so a deployment writing to MinIO or Kythira's own S3 with static
  keys, which has no STS to ask, keeps working.

## Not yet checked against AWS

The error type AWS returns for a provisioned
source or a cross-account stream, and the exact ARN form have not been
recorded against AWS; the differential test does not cover channels yet.
S3 Tables delivery has been checked against pyiceberg and the Apache
Iceberg REST catalog fixture, not against S3 Tables itself: the SigV4 signing name and
the warehouse prefix follow AWS's documentation.
