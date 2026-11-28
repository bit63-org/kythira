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
| `tests/ec2_protocol_evidence_test.cpp` | every recorded request through the core EC2 query codec (`include/raft/aws_ec2_protocol.hpp`, with its own `aws_ec2_protocol_test` and fuzz target in `tests/`) | 2 |
| `tools/ec2-service-reference.json`, `tools/gen_ec2_actions.py`, `include/kythira/ec2/ec2_actions.hpp` | AWS's Service Authorization Reference entry for `ec2` (v1.5, fetched 2026-11-27, unchanged, SHA-256 `18154e8e8044206cc9c169041db5bd0ee87d980a645e15eacf1851659869d678`), and generated from it: every resource type with its ARN format, every condition key, every action with its resource types and keys, the operation-to-action map (with `iam:PassRole` for instance profiles) and the static-key roles; `ec2_actions_up_to_date` fails when the header is stale | 3 |
| `include/kythira/ec2/ec2_front_end.hpp` | the front end: framing, SigV4, the codec's errors, `UnsupportedOperation` for unimplemented operations, admission, authorization on every resource EC2 checks (tagging on create, `iam:PassRole`), `DryRun`, encoded authorization messages, dispatch | 3 |
| `include/kythira/ec2/ec2_throttle.hpp` | EC2's request token buckets (by category, per uncategorized action, filtered describes) and its resource buckets for RunInstances, StartInstances, StopInstances and TerminateInstances, per account | 3 |
| `include/kythira/ec2/ec2_profile.hpp` | the `aws` profile and the switches set per cluster and per account: throttling, instance, vCPU, volume and snapshot quotas, terminated-instance and ClientToken retention | 3 |
| `tests/ec2_front_end_test.cpp`, `tests/ec2_gateway_inputs_test.cpp` | the front end with real SigV4 and a recording authorizer; the action table, throttling and profile | 3 |
| `cmd/ec2_node/` | the daemon; a placeholder whose `--self-test` checks the operation table, until the gateway serves requests | 1 |

## Upgrading the authorization reference

Like the model, an upgrade is a reviewed change: replace
`tools/ec2-service-reference.json` with the current
`https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json` byte for
byte, rerun `tools/gen_ec2_actions.py tools/ec2-service-reference.json
include/kythira/ec2/ec2_actions.hpp`, and update the version, date and
SHA-256 above. The header's diff shows every action, resource type and
condition key that changed.

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers; `aws_ec2_protocol.hpp` (the EC2 query codec, task 2) over `aws_query_protocol.hpp`; later SigV4, the authorizer and the multi-raft host |
| `aws_request_authorizer.hpp`, `sigv4_verifier.hpp`, `static_key_authorizer.hpp` | authentication and authorization in the front end (task 3) |
| `OpenSSL::Crypto` | SigV4, request ids, the link's TLS |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## What a split into its own repository would still need

Nothing beyond the other modules' list (services/README.md): the module
includes only core public headers, and the boundary list is empty.

## Tests

Every module test carries the labels `ec2` and `ec2-module`:

```
ctest --test-dir build -L '^ec2$' --output-on-failure
```
