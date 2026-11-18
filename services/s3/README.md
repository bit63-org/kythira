# S3 module

An Amazon S3-compatible object storage service for Kythira. Unmodified AWS
SDKs, the AWS CLI, `rclone`, Mountpoint for Amazon S3 and other S3 tools
point their endpoint at a Kythira cluster. Object metadata (buckets,
versions, manifests, uploads, policies) lives in Kythira's Raft groups;
object bytes live in content-addressed chunks outside the Raft log, so Raft
carries kilobytes per object whatever its size. The spec is
`.kiro/specs/s3-compatible-storage/`; this directory follows
`services/README.md`. It is service module number 8
(`.kiro/specs/service-colocation/`).

Built when `CONFIG_S3=y` (`services/s3/Kconfig`, off by default).
`configs/ci_full_defconfig` turns it on, so ci.yml builds and tests it;
`configs/ci_no_s3_defconfig` is the module-off configuration
`.github/workflows/s3-module.yml` checks.

This module is Kythira **offering** S3. The S3 code elsewhere in the tree
(`aws_s3_client.hpp`, the object-store and backup specs) is Kythira
**using** S3 for its own storage; those clients become one of this
module's consumers (Requirement 17.3).

## What is here

| Path | What | Task |
|---|---|---|
| `model/s3-2006-03-01.json` | the pinned botocore `s3` model (botocore 1.43.126, unchanged; Apache-2.0, `model/LICENSE` and `model/NOTICE` are botocore's); `model/README.md` records its SHA-256 and how to upgrade it | 1 |
| `tools/gen_operations.py` | generates `include/kythira/s3/model/operations.hpp` from the model; `--check` fails when the header is stale | 1 |
| `tools/fetch_model.sh` | downloads the model at a botocore tag and regenerates the header | 1 |
| `include/kythira/s3/model/operations.hpp` | the generated operation table: name, HTTP method, request URI with its distinguishing query keys, success status, streaming body flags, checksum requirement, deprecation (checked in, so a model upgrade shows its diff) | 1 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with its planned task, reason and the exact error it returns (`NotImplemented`, 501) | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.2) and its fixture tests | 1 |
| `cmd/s3_gateway_node/` | the daemon; a placeholder with `--help` and `--self-test` until tasks 5-7 | 1 |

## Core targets and variables used

This is the list a split into its own repository would need a Kythira
package to export.

| From core | Used for |
|---|---|
| `kythira_core_headers` | `include/` and `generated/`, through `kythira_s3` |
| `OpenSSL::SSL`, `OpenSSL::Crypto` | SigV4, chunk digests and server-side encryption, through `kythira_s3` |
| `Python3_EXECUTABLE` | the coverage and generated-header tests |
| `kythira_test_pch` | the guard the tests are entered under |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts` |

## What a split would still need

Nothing beyond the table above: the module includes no core header yet.
