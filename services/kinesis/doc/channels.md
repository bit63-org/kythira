# Channels

A channel delivers the records of one or more of an account's streams to a
general purpose S3 bucket, or to Apache Iceberg tables on S3 Tables
(`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement 18). The
five calls are `CreateChannel`, `DescribeChannel`, `ListChannels`,
`UpdateChannel` and `DeleteChannel`, with the pinned model's shapes.

**Status: delivery to general purpose S3 works; S3 Tables does not yet.**
A channel can be created, described, listed, updated, tagged and deleted,
and it keeps its source streams from being deleted. An S3 channel's
records reach its bucket as described under [Delivery to S3](#delivery-to-s3).
An S3 Tables channel is accepted and kept but delivers nothing until the
Iceberg commit path lands; do not rely on one to move data yet.

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

The container scenario (`services/kinesis/tests/docker/`) delivers a
channel to its S3 mock with a five-second delay while every node is
killed in turn, and checks that every record reaches the bucket in order
under each key within a shard.

Credentials come from the AWS SDK's usual chain. A build without the AWS
SDK's s3 component logs at start that it does not deliver channels.

## Limits and differences

- A channel is ACTIVE as soon as `CreateChannel` answers, and an update
  applies at once, so the CREATING and UPDATING states are never shown.
  Clients that wait for ACTIVE work unchanged.
- `DataFreshnessInSeconds` is 300 to 900 seconds, 300 when left out, as
  the model documents; an S3 Tables channel names exactly one table, the
  only case the model says AWS supports today.
- `aws:ResourceTag` conditions are not evaluated for channel ARNs.
- `StorageClass` and `ExpectedBucketOwner` are kept but not yet passed on
  the write, and delivered objects are not yet encrypted with the
  channel's `EncryptionConfiguration`.
- The channel's service execution role is not assumed: the node writes
  with its own credentials.

## Not yet checked against AWS

The error type AWS returns for a provisioned
source or a cross-account stream, and the exact ARN form have not been
recorded against AWS; the differential test does not cover channels yet.
