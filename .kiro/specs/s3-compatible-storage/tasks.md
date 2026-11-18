# Implementation Plan

Depends on `.kiro/specs/iam-compatible-auth/` (SigV4, authorizer),
`.kiro/specs/service-colocation/` (module interface),
`.kiro/specs/kms-compatible-api/`'s shared `kms_key_provider` (for SSE-KMS;
`aws` and `local` providers suffice to start), and the shared core pieces
of `.kiro/specs/kinesis-independent-layers/` (a task that needs one first
builds it to that design). Each task is one PR unless noted.

### Phase 0: evidence

- [x] 1. Module skeleton and evidence
  - `S3` Kconfig option (default off), `services/s3/`, boundary list,
    path-filtered `s3-module.yml`; module number 8
  - Pinned botocore `s3` model, generated operation list, coverage test
  - Recording stub and checked-in wire evidence for the CLI, boto3, the
    Java, Go and JS SDKs, rclone and Mountpoint (addressing, payload
    signing modes, checksums, 100-continue)
  - _Requirements: 1.1-1.5, 2.1-2.3_
  - Done: `CONFIG_S3`, `services/s3/` with `kythira_s3` and the
    `s3_gateway_node` placeholder (`--self-test`), an empty boundary
    list, `module_numbers::s3 = 8` in core, `ci_full` and its verbatim
    copies turning it on, `ci_no_s3_defconfig`, and `s3-module.yml`
    (boundary check, module-on build and tests, module-off assertion).
    botocore 1.43.126's `s3` model (116 operations) pinned in `model/`;
    `tools/gen_operations.py` generates
    `include/kythira/s3/model/operations.hpp` (method, request URI,
    status, streaming and checksum flags), checked by
    `s3_operations_up_to_date`; `s3_model_coverage` places every
    operation: 75 planned in tasks 6-15, 41 out of scope or open
    questions (annotations, bucket ABAC, `UpdateObjectEncryption`).
    `tests/evidence/`: an HTTPS recording stub and checked-in evidence
    from the AWS CLI v2, boto3, the Java, Go and JS SDKs, rclone and
    Mountpoint, checked by `s3_wire_evidence`. Findings for later tasks
    are in its README (every upload but the JS SDK's is `aws-chunked`
    with an unsigned checksum trailer; five checksum algorithms; boto3's
    default presigned URLs are SigV2; `x-id` and `?uploads=` query
    forms). The container job joins with the first daemon that serves
    requests.

### Phase 1: core pieces

- [x] 2. Chunk store in core
  - Move `cache_chunk_store` to `include/raft/chunk_store.hpp`, build cache
    unchanged; add chunk read/write over the internal transport
  - _Requirements: 10.5_
  - Done: the store is `kythira::chunk_store` in core, its test
    `tests/chunk_store_test.cpp`; `<kythira/redis/cache_chunk_store.hpp>`
    keeps the build cache's names as aliases and its fault points keep
    their names, so the cache is unchanged. New
    `chunk_store::ensure_durable`: a `put` that finds the chunk already
    held does not mean it is on disk (another writer's deferred put), and
    a remote write is acknowledged as durable. `include/raft/chunk_service.hpp`:
    the `chunk_access` concept with `local_chunk_access` (function calls)
    and `remote_chunk_access` (one mTLS request through
    `mtls_https_client.hpp`), and `chunk_service`, the
    `/_kythira/chunks/v1/<sha>` PUT and GET routes for the internal
    listener. Both ends hash-check (400 on a body that does not match,
    500 for a corrupt copy here, which the client also reports for bytes
    damaged on the way); 413 over the largest chunk; 503 on I/O failure.
    Callers need a cluster certificate (`require_verified_client`) until
    layer identity adds role checks. `tests/chunk_service_test.cpp` runs
    the remote access against a real listener.

- [x] 3. REST-XML codec
  - `aws_rest_xml_protocol.hpp`: request routing by method, path, query
    and headers; XML bodies and errors; virtual-hosted and path style
  - _Requirements: 4.1, 4.4, 4.5_
  - Done: core `include/raft/aws_rest_xml_protocol.hpp`: `parse_query`
    (`?uploads` and `?uploads=` alike), `parse_resource` (virtual-hosted
    under configured domains, path style otherwise; S3's bucket-name rules
    and 1024-byte keys), a `router` over a service's route table (method,
    path kind, literal query keys, required query parameters and headers;
    most specific wins, deprecated twins lose, `x-id` ignored, an unused
    sub-resource is MethodNotAllowed), a strict XML reader (no DTDs, only
    predefined entities and character references, depth and element
    bounds, UTF-8), S3's error document, namespaced response documents,
    both timestamp formats and `encoding-type=url` keys. The generator now
    emits each operation's required query parameters and headers, and
    `services/s3/include/kythira/s3/s3_routes.hpp` turns the model table
    into routes. `s3_routing_test` routes all 172 recorded client requests
    to the recorded operation and addressing style. `Expect: 100-continue`
    and the size limits stay with `https::server` (`limits` names S3's).

### Phase 2: the object store

- [x] 4. Object index state machine
  - Buckets, versions, manifests, delete markers, uploads, refcounts with
    grace, conditions in apply; property tests for replicas and snapshots
  - _Requirements: 6.3, 7.2, 7.3, 8.1, 10.2, 10.3_
  - Done: `s3_index_records.hpp` (key layout, records, binary codec) and
    `s3_index_state_machine.hpp`, a `persistent_state_machine` over the
    node's `kv_engine`. Keys carry an `s3/` prefix in front of the
    design's `o/`, `u/`, `c/` so modules sharing an engine cannot collide
    (HSM already uses `c/`), plus `s3/z/`, a zero-count index ordered by
    time so collection never scans every count. Entries carry the
    proposer's clock and the bucket's id, versioning state and object lock
    flag, so applying needs no catalog read. Version and upload ids are
    the log index raised past the key's newest stamp. A failed condition
    or an entry writing outside the group's range changes nothing but the
    applied index. Until task 18 spreads key spaces over groups, the
    catalog, objects, uploads and counts share one group, and
    `delete_bucket` checks emptiness only in its own range. Tests: S3's
    behaviour for each versioning state, conditions, copy-source rules,
    multipart (order, ETags, minimum size, S3's multipart ETag), listings
    with prefixes and markers, collection after the grace period; and
    randomized runs (20 seeds of 300 entries reaching every entry kind)
    in which two replicas agree, a checkpoint restores the same state and
    continues identically, and every count equals a recount of the
    manifests.

- [ ] 5. Write and read path
  - Chunking, SHA-256, write quorum, manifest commit, chunk verification
    and repair on read; co-located placement
  - _Requirements: 7.1, 10.1, 10.2, 10.5, 15.1_

- [ ] 6. Gateway, authentication and authorization
  - SigV4 in headers, query and streaming chunks with trailers, POST
    policy uploads, `s3` action table, bucket policies, Object Ownership
    and ACLs, Block Public Access, static keys
  - _Requirements: 4.2, 4.3, 5.1-5.6_

- [ ] 7. Buckets and objects API
  - Bucket operations and sub-resources; object put/get/head/delete,
    multi-delete, copy, attributes, listings; ranges; conditional reads
    and writes; metadata and ETags; the compatibility profile and its
    per-bucket tags
  - _Requirements: 3.1-3.3, 6.1, 6.2, 7.1-7.4_

- [ ] 8. Checksums
  - CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, full-object and composite,
    trailing checksums
  - _Requirements: 7.4_

- [ ] 9. Multipart upload
  - All operations, part copy, complete with checksums and conditions,
    abort and stale-upload sweep
  - _Requirements: 9.1-9.3_

- [ ] 10. Versioning and object lock
  - _Requirements: 8.1, 8.2_

- [ ] 11. Encryption
  - SSE-S3 default, SSE-KMS with bucket keys, SSE-C; chunk sealing in the
    front end
  - _Requirements: 11.1-11.3_

- [ ] 12. Orphan sweep, placement repair and request rates
  - Sweep of uncommitted chunks; repair to the copy count; per-prefix
    rate buckets with `SlowDown`; hot-prefix splits
  - _Requirements: 10.4, 10.6, 13.1, 13.2_

- [ ] 13. Lifecycle and storage classes
  - Rules, the worker, transitions to cloud tiers, restore
  - _Requirements: 7.5, 12.1_

- [ ] 14. Change log, notifications and replication
  - Change log per group; notifications to SQS, SNS and Kinesis; bucket
    replication to Kythira and to real S3
  - _Requirements: 12.2, 12.3_

- [ ] 15. CORS and website hosting
  - _Requirements: 12.4_

### Phase 3: independent layers

- [ ] 16. Roles and metadata access
  - `KYTHIRA_S3_ROLES`; local, remote and hybrid metadata access; workers
    on metadata nodes only
  - _Requirements: 14.1, 14.2, 14.6, 14.7_

- [ ] 17. Gateway and front end apart
  - Authenticated call with body streaming; prefix-affinity routing; role
    checks on internal routes
  - _Requirements: 13.2, 14.3-14.5_

- [ ] 18. Blob nodes and placement changes
  - `blobs` role; placement map with epoch; rendezvous placement with copy
    count and write quorum; background moves with read fallback
  - _Requirements: 15.2-15.5_

- [ ] 19. Migration operations
  - `evacuate` for metadata; placement switch co-located to pool and back
  - _Requirements: 16.1-16.3_

- [ ] 20. Migration path tests
  - One test per path in both directions under PUT, GET, multipart and
    list load: gateway role, front-end role, metadata role, blobs to the
    pool and back, and the whole co-located to four-way path and back
    with a stop and reversal midway; each checks Requirement 16.4
  - docker-chaos scenario of the full path killing one node per layer,
    Docker and rootless Podman
  - _Requirements: 16.4, 17.4_

### Phase 4: conformance and interoperability

- [ ] 21. Conformance suites and clients in CI
  - Ceph `s3-tests` and MinIO `mint` on co-located and split layouts with
    a shrinking expected-failure list; CLI, SDK, rclone, Mountpoint and
    Kythira's own S3 client suites
  - _Requirements: 17.1-17.3_

- [ ] 22. Interoperability with real Amazon S3
  - CI (no spend): recorded S3 responses replayed as differential fixtures
  - Real-cloud bundle (dispatch-only, repo-variable switch): `s3-tests`
    against S3 and Kythira compared; `aws s3 sync` both ways with
    checksums and metadata checked; replication to a real S3 bucket;
    SSE-KMS with real AWS KMS keys; notifications to a real SQS queue
  - Each run needs Clark's go, reports cost, deletes buckets, queues and
    schedules key deletion
  - _Requirements: 17.5_

- [ ] 23. Measurement and documentation
  - Throughput and latency by object size, co-located and split; docs and
    runbook
  - _Requirements: 17.6, 18.1_
