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
| `tools/sns-service-reference.json`, `tools/gen_sns_actions.py`, `include/kythira/sns/sns_actions.hpp` | AWS's Service Authorization Reference entry for `sns` (v1.5, fetched 2026-11-18, unchanged, SHA-256 `36396847c543959df076d04811fa0fc7895a19ab31d946b3aacd0464c4433ed3`), and the action table, operation-to-action map and static-key roles generated from it | 3 |
| `include/kythira/sns/sns_front_end.hpp` | the front end: framing, SigV4, the query codec, authorization on the topic with its policy, and dispatch to handlers | 3 |
| `include/kythira/sns/sns_query.hpp`, `sns_errors.hpp` | query inputs (attribute maps, message attributes, batches, tags) and SNS's errors in the query protocol | 3 |
| `include/kythira/sns/sns_topic_policy.hpp` | topic and subscription ARNs, the default topic policy, AddPermission and RemovePermission | 3 |
| `include/kythira/sns/sns_compat_profile.hpp` | the `kythira:compat:*` switches and SNS's documented limits per region | 3 |
| `include/kythira/sns/sns_service.hpp` | the operation handlers over a `topic_store` (one in-process state machine for now): topics, attributes, tags, permissions, data protection policies and subscriptions | 4 |
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
| `kythira_core_headers` | the public headers: `record_segment_store.hpp` (the publish log), `types.hpp` (the state machine concept), `sigv4_verifier.hpp`, `aws_request_authorizer.hpp`, `static_key_authorizer.hpp` and `aws_query_protocol.hpp` (the front end); later the multi-raft host |
| `OpenSSL::Crypto` | SigV4, request ids, message signatures (versions 1 and 2) |
| `boost_json` | topic policy documents |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## Tests

Every module test carries the labels `sns` and `sns-module`:

```
ctest --test-dir build -L '^sns$' --output-on-failure
```
