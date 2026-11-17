# Channels

A channel delivers the records of one or more of an account's streams to a
general purpose S3 bucket, or to Apache Iceberg tables on S3 Tables
(`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement 18). The
five calls are `CreateChannel`, `DescribeChannel`, `ListChannels`,
`UpdateChannel` and `DeleteChannel`, with the pinned model's shapes.

**Status: the catalog and the API are in; delivery is not yet.** A channel
can be created, described, listed, updated, tagged and deleted, and it
keeps its source streams from being deleted, but no records reach the
destination until task 19's delivery worker lands. Do not rely on a
Kythira channel to move data yet.

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

## Limits and differences

- A channel is ACTIVE as soon as `CreateChannel` answers, and an update
  applies at once, so the CREATING and UPDATING states are never shown.
  Clients that wait for ACTIVE work unchanged.
- `DataFreshnessInSeconds` is 300 to 900 seconds, 300 when left out, as
  the model documents; an S3 Tables channel names exactly one table, the
  only case the model says AWS supports today.
- `aws:ResourceTag` conditions are not evaluated for channel ARNs.

## Not yet checked against AWS

The error type AWS returns for a provisioned
source or a cross-account stream, and the exact ARN form have not been
recorded against AWS; the differential test does not cover channels yet.
