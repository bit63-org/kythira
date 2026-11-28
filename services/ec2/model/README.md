# Pinned botocore model

The Amazon EC2 service model this module answers to
(`.kiro/specs/ec2-compatible-api/` Requirement 2). The set of operations and
their request and response shapes are taken from this file and nothing else.

| File | Source | SHA-256 |
|---|---|---|
| `service-2.json` | botocore `1.43.126`, `botocore/data/ec2/2016-11-15/service-2.json` | `442433e85066484814197a9b56427ca5955c0517a55ffd2c063699f7a43a0c60` |

It is an Apache-2.0 data file from the botocore project
(<https://github.com/boto/botocore>), copied byte for byte; `LICENSE` and
`NOTICE` are botocore's. 1.43.126 is the pin the S3, SQS and SNS modules use.

The EC2 model has no error shapes: EC2 answers every error with a code in
`<Response><Errors><Error><Code>`, and the codes are documented outside the
model. The task 2 codec takes them from the recorded evidence instead.

## Upgrading

An upgrade is a reviewed change:

1. Set `BOTOCORE_VERSION` in `tools/gen_operations.py` to the new tag, then
   run `tools/fetch_model.sh <botocore version>`. It downloads the model,
   regenerates `include/kythira/ec2/model/operations.hpp` and prints the
   SHA-256; update the table above. Keep the header's diff in the pull
   request: it shows every added or removed operation and every change to
   which operations take `ClientToken`, `DryRun`, filters or paging.
2. A new operation fails `ec2_model_coverage` until it is implemented or
   listed in `doc/unsupported.md` (Requirement 2.1). EC2 adds operations
   often, so expect rows to add on every upgrade.
