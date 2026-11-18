# Differential test against Amazon SQS

Task 13 of `.kiro/specs/sqs-compatible-queues/` (Requirement 13.4), the
part that costs nothing in CI. A seeded operation mix runs once against
real SQS and its normalised answers are checked in as recordings; CI
replays the same mix against `sqs_node` and compares step by step. There
is no emulator in the loop. The design follows the Kinesis differential
(`services/kinesis/doc/differential.md`).

The tool is `tests/differential/sqs_differential.py`; recordings and the
accepted differences live in `tests/differential/recordings/`.

## What the mix does

Each run makes three queues, a standard one, a FIFO one and a dead-letter
target, named `kythira-diff-<seed>-<hex>-…`, and chooses moves with a
seeded random generator:

- single messages on the standard queue with random typed attributes:
  send, receive, sometimes make visible again and receive a second time
  (then try the first, now stale, handle), delete;
- batches of 1 to 10, sometimes with an entry SQS refuses on its own,
  drained and deleted in a batch;
- FIFO sends over up to three groups, with retries inside the
  deduplication window, drained and deleted;
- queue attributes set to edge values on both sides of each limit, then
  restored, then read back;
- a redrive policy set, the dead-letter sources listed, the policy
  cleared;
- tags added, removed and listed;
- deliberate errors: a missing queue, `MaxNumberOfMessages` 11, malformed
  receipt handles, empty, oversized and duplicate-id batches, FIFO sends
  without a group or deduplication id, a delay past 15 minutes, a
  reserved attribute name;
- a final pair of purges, the second inside the cool-down.

It deletes its queues at the end, even after a failure.

## Keeping the answers comparable

SQS leaves a lot open: a standard queue samples its servers, and any
receive may return fewer messages than asked. The mix therefore only asks
questions with one right answer:

- When a single receive is compared, the standard queue holds one visible
  message. Batches are collected by a macro step that receives until every
  message is back; its answer is the set, sorted by body.
- FIFO answers are compared per message group, in order.
- Message ids, receipt handles, timestamps, approximate counts, sender ids
  and request ids become placeholders, and so does any receipt handle or
  message id quoted in an error message. The endpoint, account, region and
  queue-name prefix are replaced in every string.
- MD5 digests are compared: they depend only on what was sent.
- A batch answer's `Successful` and `Failed` entries are compared as sets
  sorted by `Id`: SQS lists them in no particular order.
- An error compares as its code and HTTP status. Its message is printed as
  a note and fails only with `--strict-messages`, which `run_replay.sh`
  passes.

A comparison stops at the first step whose request differs, since every
later step diverges.

## Running it

```
# The mix twice against Kythira; both runs must answer alike.
sqs_differential.py self-check --endpoints http://a:9324,http://a:9324

# Replay the recordings against one endpoint.
sqs_differential.py compare --endpoint http://a:9324 \
    --recording tests/differential/recordings/ \
    --allow tests/differential/recordings/allow.json
```

`tests/differential/run_replay.sh` does both against a fresh in-memory
`sqs_node` at SQS's default limits; `sqs-module.yml`'s client job runs it.
The ctest `sqs_differential_tool` unit-tests the normaliser and the
comparison offline.

## Recordings

A recording touches a real AWS account, so each one needs Clark's go. A
run is a few hundred requests, inside SQS's free tier. See
`tests/differential/recordings/README.md`.

Seeds 1, 2 and 3 were recorded on 2026-11-18. Their first replay found
217 differences, now all fixed, with nothing in `allow.json`:

| SQS does | Kythira did |
|---|---|
| accepts ChangeMessageVisibility with a handle from an earlier receive | InvalidParameterValue; now accepted, and like a stale delete it changes nothing |
| answers an unknown SetQueueAttributes name with InvalidAttributeName, "Unknown Attribute X." | the model validator's enum error |
| answers ReceiptHandleIsInvalid with HTTP 404 | 400 (no model gives the status) |
| leaves an empty `Successful` or `Failed` list out of a batch answer | `[]` |
| lists batch entries in any order | request order (a comparison change, not a fix) |
| words five errors its own way | other wordings, now SQS's |

The rest of task 13, the dispatch-only real-cloud bundle (client suite
against SQS and Kythira, the Extended Client on real S3, a real SNS topic
through the bridge), is not built yet.
