# Pinned botocore model

The Amazon S3 service model this module answers to
(`.kiro/specs/s3-compatible-storage/` Requirement 2). The set of operations,
their HTTP bindings, shapes and error shapes are taken from this file and
nothing else.

| File | Source | SHA-256 |
|---|---|---|
| `s3-2006-03-01.json` | botocore `1.43.126`, `botocore/data/s3/2006-03-01/service-2.json` | `84c3a4e6ac1c80ed49cb1ddf1f548ea7f51d8a41acbfa0f198b9ba0028d784e8` |

It is an Apache-2.0 data file from the botocore project
(<https://github.com/boto/botocore>), copied byte for byte; `LICENSE` and
`NOTICE` are botocore's. The pin is the one the DynamoDB module uses.

## Upgrading

An upgrade is a reviewed change (Requirement 2.3):

1. Set `BOTOCORE_VERSION` in `tools/gen_operations.py` to the new tag, then
   run `tools/fetch_model.sh <botocore version>`. It downloads the model,
   regenerates `include/kythira/s3/model/operations.hpp` and prints the
   SHA-256; update the table above. Keep the header's diff in the pull
   request: it shows every added, removed or rebound operation.
2. A new operation fails `s3_model_coverage` until it is implemented or
   listed in `doc/unsupported.md` (Requirement 2.2).
