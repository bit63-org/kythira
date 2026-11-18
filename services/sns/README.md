# SNS module

An Amazon SNS-compatible publish/subscribe service for Kythira. Unmodified
AWS SDKs and the AWS CLI point their endpoint at a Kythira cluster to create
topics, subscribe SQS queues, HTTP/HTTPS endpoints and email addresses, and
publish. A publish is one Raft entry in the topic partition's group; applying
it appends the message to the topic's publish log in the core record segment
store, and leased delivery workers read that log, evaluate filter policies
and deliver. The spec is `.kiro/specs/sns-compatible-notifications/`; this
directory follows `services/README.md`.

Built when `CONFIG_SNS=y` (`services/sns/Kconfig`, off by default).
`configs/ci_full_defconfig` turns it on, so ci.yml builds and tests it;
`configs/ci_no_sns_defconfig` is the module-off configuration
`.github/workflows/sns-module.yml` checks.

## What is here

| Path | What | Task |
|---|---|---|
| `model/service-2.json` | the pinned botocore `sns` model (botocore 1.43.126, `botocore/data/sns/2010-03-31/service-2.json`, unchanged, SHA-256 `ffae4c31269cebee8af4027927b31f9fbc9df574fb971ad3764cd71199f93988`; Apache-2.0, `model/LICENSE` and `model/NOTICE` are botocore's) | 1 |
| `tools/gen_operations.py` | generates `include/kythira/sns/sns_operations.hpp` from the model; `--check` fails when the header is stale | 1 |
| `include/kythira/sns/sns_operations.hpp` | the generated operation table: names, which are batch forms, the error shapes each may return, and each error's query code and HTTP status (checked in, so a model upgrade shows its diff) | 1 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with its planned task (or out of scope: SMS and mobile push), reason and the exact error it returns | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.1) and its fixture tests | 1 |
| `tests/evidence/` | the recording stub and checked-in wire evidence from the AWS CLI v2, boto3 and the Java, JS and Go SDKs, with what the gateway must accept (`tests/evidence/README.md`) | 1 |
| `include/kythira/sns/sns_topic_state_machine.hpp`, `sns_codec.hpp` | the replicated topic state: topics, subscriptions, the publish log in the record segment store, FIFO dedup, delivery leases with fencing, cursors and retry state | 2 |
| `cmd/sns_node/` | the daemon; a placeholder whose `--self-test` checks the operation table until tasks 3 and 4 | 1 |

## Upgrading the model

An upgrade is a reviewed change. Set `BOTOCORE_VERSION` in
`tools/gen_operations.py`, replace `model/service-2.json` with that release's
`botocore/data/sns/2010-03-31/service-2.json` byte for byte, rerun the
generator, and update the version and SHA-256 above. Keep the header's diff
in the pull request: it shows every added or removed operation and error. A
new operation fails `sns_model_coverage` until it is implemented or listed in
`doc/unsupported.md`.

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers: `record_segment_store.hpp` (the publish log), `types.hpp` (the state machine concept); later the multi-raft host, SigV4 verifier, authorizer and AWS query codec |
| `OpenSSL::Crypto` | SigV4, message signatures (versions 1 and 2) |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## Tests

Every module test carries the labels `sns` and `sns-module`:

```
ctest --test-dir build -L '^sns$' --output-on-failure
```
