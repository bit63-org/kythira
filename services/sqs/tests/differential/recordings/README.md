# Amazon SQS recordings

Each `aws-seed-N.json` is one run of `../sqs_differential.py run --real-aws`
against real Amazon SQS in us-east-1: the seeded operation mix and SQS's
normalised answers. `sqs-module.yml`'s client job replays each one against
`sqs_node` and fails on any difference `allow.json` does not list.

The three checked in were recorded on 2026-11-18 from Clark's machine with
his go (seeds 1, 2 and 3, 150 steps each, 153 to 156 recorded as a move
finishes past the limit; botocore 1.43.100). No queue was left behind, and
neither the account id nor `amazonaws.com` appears in them. A recording
touches a real AWS account, so each new one needs Clark's go in his own
words. A run is a few hundred requests, inside SQS's free tier (first
million requests a month), and deletes the queues it made even when it
fails. To record:

```
AWS_PROFILE=<profile> python3 sqs_differential.py run --real-aws \
    --region us-east-1 --seed N --steps 150 --out recordings/aws-seed-N.json
```

Check the file for anything account-specific the normaliser missed before
committing it (the account id and endpoint should appear only as
`<account>` and `<endpoint>`).

`allow.json` lists `{op, path, why}` entries for known, accepted
differences; `[n]` indexes in a path are written `[*]`. It is empty: the
first replay found 217 differences, every one fixed in Kythira (or, for
the order of batch entries, which SQS does not keep, in the comparison).
`run_replay.sh` compares error messages too (`--strict-messages`).
