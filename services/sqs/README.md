# SQS module

An Amazon SQS-compatible message queue service for Kythira. Unmodified AWS
SDKs, the AWS CLI, the SQS Java Messaging Library, Spring Cloud AWS, Celery
and Kombu point their endpoint at a Kythira cluster. A queue's messages live
under routing keys in Kythira's Raft groups, in a queue state machine on the
persistent key-value engine; a receive is a committed entry, so visibility,
receive counts and FIFO groups agree on every replica. The spec is
`.kiro/specs/sqs-compatible-queues/`; this directory follows
`services/README.md`.

Built when `CONFIG_SQS=y` (`services/sqs/Kconfig`, off by default).
`configs/ci_full_defconfig` turns it on, so ci.yml builds and tests it;
`configs/ci_no_sqs_defconfig` is the module-off configuration
`.github/workflows/sqs-module.yml` checks.

## What is here

| Path | What | Task |
|---|---|---|
| `model/service-2.json` | the pinned botocore `sqs` model (botocore 1.43.100, unchanged; Apache-2.0, `model/LICENSE` and `model/NOTICE` are botocore's) | 1 |
| `tools/gen_operations.py` | generates `include/kythira/sqs/sqs_operations.hpp` from the model; `--check` fails when the header is stale | 1 |
| `include/kythira/sqs/sqs_operations.hpp` | the generated operation table: names, which are batch forms, the error shapes each may return (checked in, so a model upgrade shows its diff) | 1 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with its planned task, reason and the exact error it returns | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.1) and its fixture tests | 1 |
| `cmd/sqs_node/` | the daemon; a placeholder whose `--self-test` checks the operation table until tasks 3 and 4 | 1 |

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers (later: multi-raft host, SigV4 verifier, authorizer, AWS JSON and query codecs) |
| `OpenSSL::Crypto` | SigV4, MD5 digests of bodies and attributes, receipt-handle HMACs |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## Tests

Every module test carries the labels `sqs` and `sqs-module`:

```
ctest --test-dir build -L '^sqs$' --output-on-failure
```
