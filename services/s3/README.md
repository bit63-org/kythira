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
| `include/kythira/s3/model/operations.hpp` | the generated operation table: name, HTTP method, request URI with its distinguishing query keys, success status, streaming body flags, checksum requirement, deprecation, required query parameters and headers (checked in, so a model upgrade shows its diff) | 1, 3 |
| `include/kythira/s3/s3_index_records.hpp`, `s3_index_state_machine.hpp` | the object index: key layout and record encoding, and the persistent state machine for buckets, versions, uploads and reference counts; `s3_index_state_machine_test` | 4 |
| `include/kythira/s3/s3_placement.hpp`, `s3_data_path.hpp` | where a chunk's copies live (co-located on the owning group's replicas, or rendezvous over blob nodes), and the front end's write path (chunking, SHA-256, write quorum, commit only after durability) and read path (verified reads, repair of missing or corrupt copies); `s3_data_path_test` | 5 |
| `tools/s3-service-reference.json`, `tools/gen_s3_actions.py`, `include/kythira/s3/s3_actions.hpp` | AWS's Service Authorization Reference for `s3` (v1.5, pinned byte for byte, SHA-256 `42a0406559f357e77fad1e4a77c1d3d9aa62bc90da4dd990c13149ae92147c6d`, from `https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json`) and the generated action table, operation-to-action map and static-key roles; `s3_actions_up_to_date` fails when stale | 6 |
| `include/kythira/s3/s3_authz.hpp` | the actions, resources and condition keys each request asks the authorizer for; `s3_authz_test` | 6 |
| `include/kythira/s3/s3_auth.hpp` | SigV4 authentication with S3's rules (header and presigned, every payload mode; SigV2 and SigV4a refused) and the body reader that checks a hashed payload or decodes `aws-chunked` streams; `s3_auth_test` | 6 |
| `include/kythira/s3/s3_access.hpp` | Object Ownership, ACLs (canned, header and XML), Block Public Access, policy publicness, and the access decision combining the authorizer, ACLs and anonymous access; `s3_access_test` | 6 |
| `include/kythira/s3/s3_post_policy.hpp` | browser POST uploads: streaming multipart/form-data parser, policy document and conditions, policy signature; `s3_post_policy_test` | 6 |
| `include/kythira/s3/s3_http.hpp` | the request and response the handlers see (pull body source, streamed response bodies) | 7 |
| `include/kythira/s3/s3_metadata.hpp` | `metadata_access`, what handlers need of the metadata layer, and `local_metadata` in process | 7 |
| `include/kythira/s3/s3_compat.hpp` | the compatibility profile and its `kythira:compat:*` bucket tags | 7 |
| `include/kythira/s3/s3_context.hpp` | service options, handler context, a bucket's access state from its stored config | 7 |
| `include/kythira/s3/s3_buckets.hpp` | bucket operations and the access, tagging, logging and default-encryption sub-resources | 6, 7, 11 |
| `include/kythira/s3/s3_objects.hpp` | object put, get/head (ranges, `partNumber`, overrides, conditions), delete, copy (re-encrypting when keys differ), attributes, tagging, ACLs, stored checksums, SSE | 6, 7, 8, 11 |
| `include/kythira/s3/s3_listings.hpp` | ListObjects V1/V2 and DeleteObjects | 7, 8 |
| `include/kythira/s3/s3_checksums.hpp` | additional checksums (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256): streaming, CRC combination for full-object multipart checksums, composite checksums, what a request asks for and its verification against a header or trailer; `s3_checksums_test` | 8 |
| `include/kythira/s3/s3_multipart.hpp` | multipart upload: create, parts and part copies, listings, complete with checksums and conditions, abort, and the stale-upload sweep | 9 |
| `include/kythira/s3/s3_object_lock.hpp` | object lock on the write path: lock headers, default retention, the lock headers a read returns | 10 |
| `include/kythira/s3/s3_versioning.hpp` | bucket versioning, ListObjectVersions, object lock configuration, retention and legal hold | 10 |
| `include/kythira/s3/s3_chunk_cipher.hpp`, `s3_encryption.hpp`, `s3_kms_provider.hpp` | server-side encryption: AES-256-GCM chunk sealing with derived nonces (dedup within a data key), key providers (local passphrase-sealed; Kythira or AWS KMS over their JSON API), the SSE headers, bucket default encryption, per-object data keys for SSE-S3, SSE-KMS with bucket keys and SSE-C (salted HMAC only, never the key); `s3_encryption_test` | 11 |
| `include/kythira/s3/s3_rates.hpp` | per-prefix request rates: token buckets per bucket, prefix (key up to its last `/`) and reads or writes, `503 SlowDown` past the profile's rates, hot-prefix reports | 12 |
| `include/kythira/s3/s3_sweeps.hpp` | the chunk sweeper: deletes collected chunks from every node, finds and deletes chunks no commit names (two sweeps a grace period apart), restores missing copies of live chunks; `s3_sweeps_test` | 12 |
| `include/kythira/s3/s3_lifecycle_rules.hpp` | lifecycle configurations: the rule model (filters by prefix, tags and size; expiration, noncurrent expiration, delete markers, aborted uploads, transitions), its XML with S3's checks, due dates rounded to midnight, the 128 KiB transition minimum, archive classes and restore state; `s3_lifecycle_test` | 13 |
| `include/kythira/s3/s3_lifecycle.hpp` | Put/Get/DeleteBucketLifecycle(Configuration), RestoreObject, and the lifecycle worker that applies every bucket's rules once a lifecycle day; `s3_lifecycle_test` | 13 |
| `include/kythira/s3/s3_tiers.hpp` | the archive tier: GLACIER and DEEP_ARCHIVE bytes moved to a cloud object store, restores brought back to the blob stores, removed versions' cloud copies deleted (`tier_worker`); `s3_service_test` | 13 |
| `include/kythira/s3/s3_change_log.hpp` | the change log: one record per object change (S3's event names), kept per index group in a core `segment_store` written in apply, with per-consumer cursors (`notifications`, `replication`) that bound trimming; only buckets with a notification or replication configuration log; `s3_index_state_machine_test` | 14 |
| `include/kythira/s3/s3_event_sinks.hpp` | notification destinations: SQS `SendMessage`, SNS `Publish` and Kinesis `PutRecord` built in each service's own protocol and sent through a transport function (co-located module in process, or SigV4 to another cluster or AWS); `s3_notifications_test` | 14 |
| `include/kythira/s3/s3_notifications.hpp` | Put/Get BucketNotificationConfiguration and the deprecated BucketNotification forms (S3's checks, destination TestEvents, Kythira's `KinesisStreamConfiguration`), the event JSON, and the notification worker over the change log; `s3_notifications_test` | 14 |
| `include/kythira/s3/s3_replication_rules.hpp`, `s3_replication.hpp` | replication configurations (both schemas, S3's checks), Put/Get/DeleteBucketReplication, `x-amz-replication-status` on writes, and the replication worker that copies new versions and client delete markers, in log order, to Kythira or Amazon S3 destinations; `s3_service_test` | 14 |
| `include/kythira/s3/s3_cors_rules.hpp`, `s3_cors.hpp` | CORS configurations (S3's checks), Put/Get/DeleteBucketCors, rule matching for preflights (`OPTIONS`, unauthenticated) and the `Access-Control-*` headers on every answer from a bucket with CORS; `s3_website_rules_test`, `s3_service_test` | 15 |
| `include/kythira/s3/s3_website_rules.hpp`, `s3_website.hpp` | website configurations (S3's checks), Put/Get/DeleteBucketWebsite, and the website endpoint (`<bucket>.<website domain>`): anonymous reads, index and error documents, routing rules, redirects, S3's HTML error pages; `s3_website_rules_test`, `s3_service_test` | 15 |
| `include/kythira/s3/s3_service.hpp` | the request pipeline and browser POST uploads; `s3_service_test` | 6-14 |
| `include/kythira/s3/s3_routes.hpp` | the operation table as routes for core's REST-XML router, and `route_request` (addressing, query, operation); `s3_routing_test` routes every recorded client request | 3 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with its planned task, reason and the exact error it returns (`NotImplemented`, 501) | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.2) and its fixture tests | 1 |
| `tests/evidence/` | the recording stub, the client scenarios (AWS CLI v2, boto3, Java, Go and JS SDKs, rclone, Mountpoint) and the checked-in wire evidence with what it means for the gateway; `s3_wire_evidence` checks the files | 1 |
| `include/kythira/s3/s3_roles.hpp` | `KYTHIRA_S3_ROLES` (gateway, front_end, metadata, blobs, mapped onto the shared layer roles), the layouts that serve today, and who may call the metadata and chunk routes; `s3_layers_test` | 16 |
| `include/kythira/s3/s3_remote_metadata.hpp` | the metadata layer over the internal transport: the wire, `metadata_server`, `remote_metadata`, the failover `endpoint_transport`, and `hybrid_metadata`, which picks local or remote per call; `s3_layers_test` | 16 |
| `include/kythira/s3/s3_raft_metadata.hpp` | the object index on Raft: `raft_metadata`, `metadata_access` over a `multi_raft` index group (followers forward entries and read barriers to the leader), `group_server` and `make_group_forwarder` for the member-to-member routes, and the change log segment fetcher for snapshots; `s3_raft_metadata_test` | 16a |
| `include/kythira/s3/s3_workers.hpp` | `worker_runner`: the leader-side workers on a schedule, on metadata nodes only, gated by leadership; `s3_layers_test` | 16 |
| `include/kythira/s3/s3_outbound.hpp` | SigV4-signed requests to KMS, SQS, SNS, Kinesis and S3 (endpoints, credentials, the principal forwarded to a Kythira KMS) behind the module's transport functions; `s3_layers_test` | 16 |
| `include/kythira/s3/s3_node_config.hpp` | the daemon's `KYTHIRA_S3_*` settings and the checks that stop a node that cannot serve; `s3_layers_test` | 16 |
| `cmd/s3_gateway_node/` | the daemon: the roles `KYTHIRA_S3_ROLES` names, the API, website and internal (mutual TLS, layer identities) listeners, the chunk store, the workers and the outbound transports; `--help` lists every setting, `--self-test` checks the operation table; `s3_gateway_node_test` runs it co-located and split | 1, 16 |

## Core targets and variables used

This is the list a split into its own repository would need a Kythira
package to export.

| From core | Used for |
|---|---|
| `kythira_core_headers` | `include/` and `generated/`, through `kythira_s3` |
| `OpenSSL::SSL`, `OpenSSL::Crypto` | SigV4, chunk digests and server-side encryption, through `kythira_s3` |
| `Python3_EXECUTABLE` | the coverage and generated-header tests |
| `kythira_test_pch` | the guard the tests are entered under |
| `Boost::unit_test_framework`, `boost_json` (or `Boost::json`) | `s3_routing_test`, which reads the evidence files, and the tests of headers that parse JSON (bucket policies, KMS encryption contexts) |
| `include/raft/aws_rest_xml_protocol.hpp` (and `aws_query_protocol.hpp`, its XML writer) | routing, addressing, request XML and response documents |
| `include/raft/chunk_store.hpp`, `chunk_service.hpp` | object bytes and chunk reads and writes between nodes (used from task 5); the index's `chunk_sha` |
| `include/raft/persistent_state_machine.hpp`, `memory_kv_engine.hpp` | the index's state machine contract and its test engine |
| `add_raft_completion_test` (`kythira_test_pch`) | `s3_index_state_machine_test` |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts` |
| `network_simulator`, `KYTHIRA_FUTURE_BACKEND_AVAILABLE`, `Boost_FOUND` | the future backend the persistence headers need, for `s3_gateway_node`, which is not built without them |
| `include/raft/beast_https_server.hpp`, `mtls_https_client.hpp` | the daemon's listeners and its internal and outbound HTTPS client |
| `include/raft/layer_roles.hpp`, `layer_identity.hpp` | roles, layer identities in certificates, and the internal route guard |
| `include/raft/static_key_authorizer.hpp`, `static_keys_file.hpp` | the daemon's access keys |
| `include/raft/record_segment_store.hpp` | the daemon's change log store |
| `include/raft/kms_forwarding.hpp`, `sigv4_verifier.hpp` | signing outbound requests and forwarding the caller to a Kythira KMS |

## What a split would still need

The core headers in the table above: they are header-only and depend on
OpenSSL and Boost.Beast, so a Kythira package exporting `kythira_core_headers`
covers them.
