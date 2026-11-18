# Amazon SQS recordings

Each `aws-seed-N.json` is one run of `../sqs_differential.py run --real-aws`
against real Amazon SQS in us-east-1: the seeded operation mix and SQS's
normalised answers. `sqs-module.yml`'s client job replays each one against
`sqs_node` and fails on any difference `allow.json` does not list.

None is checked in yet: a recording touches a real AWS account, so each one
needs Clark's go in his own words. A run is a few hundred requests, inside
SQS's free tier (first million requests a month), and deletes the queues it
made even when it fails. To record:

```
AWS_PROFILE=<profile> python3 sqs_differential.py run --real-aws \
    --region us-east-1 --seed N --steps 150 --out recordings/aws-seed-N.json
```

Check the file for anything account-specific the normaliser missed before
committing it (the account id and endpoint should appear only as
`<account>` and `<endpoint>`).

`allow.json` lists `{op, path, why}` entries for known, accepted
differences; `[n]` indexes in a path are written `[*]`. Error messages are
compared only with `--strict-messages`; otherwise they are printed as notes.
