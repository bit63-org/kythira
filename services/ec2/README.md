# EC2 module

An Amazon EC2-compatible compute API for Kythira, and antikythera's
controller. The AWS CLI, the AWS SDKs, Terraform's AWS provider and Kythira's
own EC2 clients point their EC2 endpoint at a Kythira cluster to launch,
stop, start and terminate instances, create and attach EBS-style volumes,
take snapshots and make VPCs and network interfaces. The instances run on
antikythera servers (`bit63-org/antikythera`): every VM, device, volume and
VPC change originates here and reaches a server's helm as a signed command or
frame over a mutually authenticated link. The spec is
`.kiro/specs/ec2-compatible-api/`; this directory follows
`services/README.md`.

Built when `CONFIG_EC2=y` (`services/ec2/Kconfig`, off by default).
`configs/ci_full_defconfig` turns it on, so ci.yml builds and tests it;
`configs/ci_no_ec2_defconfig` is the module-off configuration
`.github/workflows/ec2-module.yml` checks. Its module number is 11.

## What is here

| Path | What | Task |
|---|---|---|
| `model/service-2.json` | the pinned botocore `ec2` model (botocore 1.43.126, unchanged; version, source and SHA-256 in `model/README.md`; Apache-2.0, `model/LICENSE` and `model/NOTICE` are botocore's) | 1 |
| `tools/gen_operations.py`, `tools/fetch_model.sh` | generate `include/kythira/ec2/model/operations.hpp` from the model (`--check` fails when the header is stale), and fetch a new model | 1 |
| `include/kythira/ec2/model/operations.hpp` | the generated operation table: all 811 names, and which take `ClientToken`, `DryRun`, a `Filter.N` list and `NextToken` paging (checked in, so a model upgrade shows its diff) | 1 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with the task that takes it (or the Requirement 14 refusal, or out of scope), the reason and the exact error it returns | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.1) and its fixture tests | 1 |
| `tests/evidence/` | the recording stub and checked-in wire evidence from the AWS CLI v2, boto3 and the Java, JS and Go SDKs, with what the gateway must accept (`tests/evidence/README.md`) | 1 |
| `cmd/ec2_node/` | the daemon; a placeholder whose `--self-test` checks the operation table, until the gateway serves requests | 1 |

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers; from task 2 the query codec beside `aws_query_protocol.hpp`, later SigV4, the authorizer and the multi-raft host |
| `OpenSSL::Crypto` | SigV4, the link's TLS |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## What a split into its own repository would still need

Nothing beyond the other modules' list (services/README.md): the module
includes only core public headers, and the boundary list is empty.

## Tests

Every module test carries the labels `ec2` and `ec2-module`:

```
ctest --test-dir build -L '^ec2$' --output-on-failure
```
