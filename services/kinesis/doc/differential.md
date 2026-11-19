# Differential test against AWS Kinesis

Task 17 of `.kiro/specs/kinesis-compatible-streams/` (Requirement 17.1)
compares Kythira's answers with AWS Kinesis's. There is no emulator in the
loop: a seeded operation mix was run once against real AWS and its
normalised answers are checked in as recordings. The same mix is replayed
against Kythira and compared step by step.

The tool is `tests/differential/kinesis_differential.py`. The recordings
and the list of accepted differences are in `tests/differential/recordings/`.

## What the mix does

Each run creates its own stream (`kythira-diff-<seed>-<hex>`) and, chosen
by a seeded random generator, puts records (with `ExplicitHashKey` and
`SequenceNumberForOrdering`), reads shards with every iterator type and
pages to the tip, lists and describes shards, changes tags and retention,
reshards (`SplitShard`, `MergeShards`, `UpdateShardCount`, at most 4 open
shards) and makes deliberate errors. It deletes its stream at the end, even
after a failure. It leaves out enhanced fan-out, on-demand mode and KMS
encryption, which cost by the hour on AWS or need other services.

The mix's choices depend only on the seed and on normalised answers, so two
services that answer alike get the same requests.

## What is compared

Before comparing, each run's answers are normalised:

- Sequence numbers become tokens in order of first appearance. The test
  compares which numbers are equal and in what order they appeared, not
  their digits.
- Shard iterators, paging tokens, timestamps, `MillisBehindLatest` and
  `StreamId` become placeholders.
- The account, region and stream name are replaced in every string.
- Record data compares byte for byte.
- An error compares as its type and HTTP status. Its message is printed as
  a note, and fails the test only with `--strict-messages`.

A comparison stops at the first step whose request differs, since every
step after it diverges.

## Running it

```
# Two Kythira endpoints must answer alike (no AWS involved).
kinesis_differential.py self-check --endpoints http://a:4567,http://b:4567

# Replay the recordings against one endpoint.
kinesis_differential.py compare --endpoint http://a:4567 \
    --recording tests/differential/recordings/ \
    --allow tests/differential/recordings/allow.json
```

The container scenario's `differential_replay_matches_the_aws_recordings`
case does both against the three-node cluster. `kinesis_differential_tool`
in ctest unit-tests the normaliser and the comparison offline.

## Channels against the service model

`kinesis_differential.py channels --endpoint URL` (task 19) runs a fixed
sequence on an on-demand stream of its own: `CreateChannel` with tags,
`DescribeChannel`, `ListChannels` with a stream filter,
`DescribeStreamSummary` (`ChannelCount`), `UpdateChannel`, the tag calls on
the channel ARN, the errors the model documents (a name in use, `GSR_JSON`
to S3, no destination, an unknown ARN, `DeleteStream` of a source) and
`DeleteChannel`. It deletes the channel and the stream at the end, even
after a failure.

Every answer is checked against the botocore service model the client
pins, from the raw JSON body rather than the parsed one (botocore's parser
drops members it does not know):

- A success must fit the operation's output shape: required members
  present, no members the shape does not have, enum values, string
  lengths, integer bounds, epoch-second timestamps and base64 blobs.
- An error's `__type` must be one the operation declares.

This check found that an S3 channel created without a dead-letter
configuration was described without one, although the model's
`S3DestinationDescription` requires it; it is now described as the
destination bucket under `errors/`, where delivery writes dead letters.

`--out FILE` writes the normalised steps (channel names and ids, the role
and the bucket become placeholders) and `--recording FILE` compares a run
with one, as `compare` does. There is no AWS recording of channels yet: one
needs a role and a bucket (`--role-arn`, `--bucket`) and Clark's go. The
container scenario's differential case runs the model check against the
cluster.

A new recording runs against real AWS and costs money, so it needs Clark's
go each time. See `tests/differential/recordings/README.md`.
