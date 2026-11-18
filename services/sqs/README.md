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
| `tests/evidence/` | the recording stub, the clients and the checked-in wire evidence (AWS CLI v2, boto3 on JSON and query, Java SDK v2, JMS, Kombu); `sqs_wire_evidence` checks it | 1 |
| `include/kythira/sqs/sqs_queue_commands.hpp` | the queue state machine's Raft entries and replies (send, receive, delete, change visibility, purge, drop, tick), versioned binary forms | 2 |
| `include/kythira/sqs/sqs_queue_state_machine.hpp` | the replicated state of queue partitions on the `kv_engine`: key layout, receives as committed entries, receipt sequences, FIFO group heads, deduplication, retention, counts, splits at partition routing keys | 2 |
| `model/query/service-2.json` | the last query-era botocore `sqs` model (botocore 1.31.40, unchanged; same licence), the source of the query protocol's names and error codes | 3 |
| `tools/gen_query_names.py` | generates `include/kythira/sqs/model/sqs_query_names.hpp`: every structure member's query names (flattening, list items, map entries) and every exception's query code, status and fault | 3 |
| `include/kythira/sqs/model/sqs_model.hpp` | the JSON model's shapes for core's `aws_json` codec and validator, from `scripts/gen_aws_json_shapes.py` | 3 |
| `tools/sqs-service-reference.json`, `tools/gen_sqs_actions.py` | AWS's Service Authorization Reference for `sqs` (v1.5) and the generator of `include/kythira/sqs/sqs_actions.hpp`: the action table, each operation's authorizing action and whether it writes, the static-key roles | 3 |
| `include/kythira/sqs/sqs_codec.hpp` | both wire protocols over one model: JSON 1.0 through core's codec, query forms read and XML written through the query names; queue URLs given as the request path | 3 |
| `include/kythira/sqs/sqs_errors.hpp` | errors in both protocols, `x-amzn-query-error` for query-compatible JSON clients | 3 |
| `include/kythira/sqs/sqs_compat_profile.hpp` | the AWS-behaviour switches (message size, retention, batch size, in-flight, FIFO throughput, long-poll maximum, cool-downs), per cluster and per queue tag | 3 |
| `include/kythira/sqs/sqs_front_end.hpp` | the transport-free front end: SigV4 in the request's protocol, queue resolution (QueueUrl, QueueName, SourceArn), authorization of each operation's primary action on the queue with its tags and policy, dispatch to handlers | 3 |
| `include/kythira/sqs/sqs_queue_policy.hpp` | queue-policy edits as AddPermission and RemovePermission make them | 3 |
| `include/kythira/sqs/sqs_messages.hpp` | message bodies and attributes: validation, the MD5 digests SDKs check, stored encodings, attribute selection on receive | 4 |
| `include/kythira/sqs/sqs_receipts.hpp` | stateless HMAC-SHA256 receipt handles, the receipt key ring (`SQS_RECEIPT_KEYS_FILE` or derived from the forwarding secret) | 4 |
| `include/kythira/sqs/sqs_queue_attributes.hpp` | queue settings at SQS's defaults, CreateQueue/SetQueueAttributes checks against the compatibility profile, GetQueueAttributes rendering | 4 |
| `include/kythira/sqs/sqs_catalog.hpp` | the queue catalog's keys, records and entries, applied by the queue state machine: never-reused ids, the deletion and purge cool-downs, compare-and-set settings changes; message move task records | 4, 6 |
| `include/kythira/sqs/sqs_cluster.hpp` | `queue_cluster`, what the handlers need from the data layer, and `local_queue_cluster` over one in-process state machine | 4 |
| `include/kythira/sqs/sqs_service.hpp` | the queue and message handlers: queue lifecycle, attributes, permissions, tags, purge; send, receive, delete and visibility with batches; partition choice; receipt handles; dead-letter redrive and move tasks | 4, 6 |
| `include/kythira/sqs/sqs_raft_cluster.hpp`, `include/kythira/sqs/sqs_forward.hpp` | `queue_cluster` over a `multi_raft` host, and node-to-node forwarding of entries to a group's leader (HMAC over the cluster's forwarding secret) | 4 |
| `include/kythira/sqs/sqs_listener.hpp` | the API and the forwarding endpoint as a handler for core's Beast HTTPS server | 4 |
| `include/kythira/sqs/sqs_node_options.hpp` | `sqs_node`'s settings from `SQS_*` variables | 4 |
| `include/kythira/sqs/sqs_long_poll.hpp` | where long polls park: subscriptions to a queue's partitions, woken when a committed entry leaves one with visible messages, closed by a drain | 5 |
| `include/kythira/sqs/sqs_workers.hpp` | the leader's tick worker: proposes a `tick` when a partition's earliest deadline passes, so ended delays and visibility timeouts become committed facts that wake long polls; the move worker, which runs message move tasks at their rate on the catalog leader | 5, 6 |
| `cmd/sqs_node/sqs_module.hpp`, `cmd/sqs_node/sqs_module_registrar.cpp` | the service module, number 9: the queues on a `multi_raft` host in the node's engine (RocksDB), one group over every node of `KYTHIRA_NODE_PEERS`, followers forwarding to the leader's listener; registered for `kythira_node` (`KYTHIRA_SERVICES=sqs`) | 4 |
| `cmd/sqs_node/` | the daemon: with `KYTHIRA_NODE_DATA_DIR` set, the module alone on a node (durable, one or more nodes); otherwise one node with its queues in memory, for development (`SQS_LISTEN`, `SQS_STATIC_KEYS_FILE`, ...); `--self-test` checks the operation table | 1, 4 |

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers: `aws_json_protocol.hpp` (codec, validator), `aws_query_protocol.hpp` (forms, XML), `aws_request_authorizer.hpp` and `static_key_authorizer.hpp` (action and role tables); later the multi-raft host and SigV4 verifier |
| `boost_json` | request and response objects of both protocols |
| `KYTHIRA_AWS_JSON_SHAPES_GENERATOR` | regenerates and checks `sqs_model.hpp` |
| `OpenSSL::Crypto` | SigV4, MD5 digests of bodies and attributes, receipt-handle HMACs |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts()` |

## Tests

Every module test carries the labels `sqs` and `sqs-module`:

```
ctest --test-dir build -L '^sqs$' --output-on-failure
```
