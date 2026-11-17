# Implementation Plan

Depends on `.kiro/specs/iam-compatible-auth/` (SigV4, authorizer),
`.kiro/specs/service-colocation/` (module interface),
`.kiro/specs/kms-compatible-api/`'s shared `kms_key_provider` (for SSE-KMS;
`aws` and `local` providers suffice to start), and the shared core pieces
of `.kiro/specs/kinesis-independent-layers/` (a task that needs one first
builds it to that design). Each task is one PR unless noted.

### Phase 0: evidence

- [ ] 1. Module skeleton and evidence
  - `S3` Kconfig option (default off), `services/s3/`, boundary list,
    path-filtered `s3-module.yml`; module number 8
  - Pinned botocore `s3` model, generated operation list, coverage test
  - Recording stub and checked-in wire evidence for the CLI, boto3, the
    Java, Go and JS SDKs, rclone and Mountpoint (addressing, payload
    signing modes, checksums, 100-continue)
  - _Requirements: 1.1-1.5, 2.1-2.3_

### Phase 1: core pieces

- [ ] 2. Chunk store in core
  - Move `cache_chunk_store` to `include/raft/chunk_store.hpp`, build cache
    unchanged; add chunk read/write over the internal transport
  - _Requirements: 10.5_

- [ ] 3. REST-XML codec
  - `aws_rest_xml_protocol.hpp`: request routing by method, path, query
    and headers; XML bodies and errors; virtual-hosted and path style
  - _Requirements: 4.1, 4.4, 4.5_

### Phase 2: the object store

- [ ] 4. Object index state machine
  - Buckets, versions, manifests, delete markers, uploads, refcounts with
    grace, conditions in apply; property tests for replicas and snapshots
  - _Requirements: 6.3, 7.2, 7.3, 8.1, 10.2, 10.3_

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
