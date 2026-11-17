# AWS KMS recordings

`aws-us-east-1.json` is one run of `../kms_differential.py run --real-aws`
against real AWS KMS in us-east-1 (recorded 2026-11-17): every case of the
tool's list with AWS's normalised answer. `kms_node_cluster_test`'s
`differential_replay_matches_the_aws_recording` case runs the same cases
against a three-member cluster and fails on any difference that `allow.json`
does not list. `test_kms_differential.py` checks offline that the recording
still matches the tool's case list, so adding or renaming a case means
recording again.

A recording makes four KMS keys, an alias and a grant, and schedules the keys
for deletion after 7 days however it ends: under $1 on AWS. It needs Clark's
go each time. To record, with credentials for the account in the
environment:

```
python3 kms_differential.py run --real-aws --region us-east-1 \
    --out recordings/aws-us-east-1.json
```

`allow.json` lists `{case, path, why}` entries for accepted differences.
Error messages are not compared unless `--strict-messages` is given; the
replay prints them as notes.
