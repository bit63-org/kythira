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
| `include/kythira/s3/s3_buckets.hpp` | bucket operations and the access, tagging and logging sub-resources | 6, 7 |
| `include/kythira/s3/s3_objects.hpp` | object put, get/head (ranges, `partNumber`, overrides, conditions), delete, copy, attributes, tagging, ACLs, stored checksums | 6, 7, 8 |
| `include/kythira/s3/s3_listings.hpp` | ListObjects V1/V2 and DeleteObjects | 7, 8 |
| `include/kythira/s3/s3_checksums.hpp` | additional checksums (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256): streaming, CRC combination for full-object multipart checksums, composite checksums, what a request asks for and its verification against a header or trailer; `s3_checksums_test` | 8 |
| `include/kythira/s3/s3_multipart.hpp` | multipart upload: create, parts and part copies, listings, complete with checksums and conditions, abort, and the stale-upload sweep | 9 |
| `include/kythira/s3/s3_service.hpp` | the request pipeline and browser POST uploads; `s3_service_test` | 6-9 |
| `include/kythira/s3/s3_routes.hpp` | the operation table as routes for core's REST-XML router, and `route_request` (addressing, query, operation); `s3_routing_test` routes every recorded client request | 3 |
| `implemented-operations.txt` | operations the gateway implements | 1 onward |
| `doc/unsupported.md` | every other operation, with its planned task, reason and the exact error it returns (`NotImplemented`, 501) | 1 onward |
| `tools/check_coverage.py`, `tools/test_check_coverage.py` | the coverage check (Requirement 2.2) and its fixture tests | 1 |
| `tests/evidence/` | the recording stub, the client scenarios (AWS CLI v2, boto3, Java, Go and JS SDKs, rclone, Mountpoint) and the checked-in wire evidence with what it means for the gateway; `s3_wire_evidence` checks the files | 1 |
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
| `Boost::unit_test_framework`, `boost_json` (or `Boost::json`) | `s3_routing_test`, which reads the evidence files |
| `include/raft/aws_rest_xml_protocol.hpp` (and `aws_query_protocol.hpp`, its XML writer) | routing, addressing, request XML and response documents |
| `include/raft/chunk_store.hpp`, `chunk_service.hpp` | object bytes and chunk reads and writes between nodes (used from task 5); the index's `chunk_sha` |
| `include/raft/persistent_state_machine.hpp`, `memory_kv_engine.hpp` | the index's state machine contract and its test engine |
| `add_raft_completion_test` (`kythira_test_pch`) | `s3_index_state_machine_test` |
| `cmake/kythira_test_helpers.cmake` | `kythira_scale_test_timeouts` |

## What a split would still need

The core headers in the table above: they are header-only and depend on
OpenSSL and Boost.Beast, so a Kythira package exporting `kythira_core_headers`
covers them.
