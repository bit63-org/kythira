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

- [x] 5. Write and read path
  - Chunking, SHA-256, write quorum, manifest commit, chunk verification
    and repair on read; co-located placement
  - _Requirements: 7.1, 10.1, 10.2, 10.5, 15.1_
  - Done: `s3_placement.hpp` (one `placement_map` with an epoch for both
    rules: co-located copies are the owning group's replicas with a
    majority quorum; rendezvous is weighted rendezvous hashing over blob
    nodes, one copy per placement group first, so task 18 only has to
    replicate and move between maps) and `s3_data_path.hpp`. A body is cut
    into 8 MiB chunks as it streams, each hashed and written to all of its
    placement's copies in parallel; a chunk counts at a write quorum of
    durable answers, and `put_object` calls the commit only after every
    chunk has its quorum. A missed quorum is `503 SlowDown` and commits
    nothing; a refused chunk is `500` (configuration, not load). The body's
    MD5 is the single-part ETag. Reads fetch only the chunks a range
    overlaps, take the first copy whose bytes hash to the name, rewrite
    the missing or corrupt copies read before it and report each; no good
    copy is `500 InternalError` and nothing bad is served. A node drops a
    corrupt copy of its own as it reads it (`local_chunk_access`), so the
    repair write stores the good bytes instead of being answered
    `present`. The write waits for every copy, not just the quorum, since
    the bytes are the caller's; acknowledging at quorum is left for
    measurement. Wiring into handlers is task 7.

- [x] 6. Gateway, authentication and authorization
  - SigV4 in headers, query and streaming chunks with trailers, POST
    policy uploads, `s3` action table, bucket policies, Object Ownership
    and ACLs, Block Public Access, static keys
  - _Requirements: 4.2, 4.3, 5.1-5.6_
  - Done: `s3_auth.hpp` authenticates header and presigned SigV4 with
    S3's rules and every payload mode, refusing SigV2 and SigV4a with
    S3's `InvalidRequest`; its `payload_reader` checks a hashed body or
    decodes `aws-chunked` (signed chunks verified, trailers kept for
    task 8). Core `aws_claim_resolver` lets a front end resolve a
    claim's signing key (static keys, IAM, and the static-or-IAM
    switch all implement it), which signed streaming and POST uploads
    need. `s3_actions.hpp` is generated from the pinned Service
    Authorization Reference; `s3_authz.hpp` turns a request into the
    checks it needs (primary action, version twins, ACL/tagging/lock
    extras, the copy source). `s3_access.hpp` decides: authorizer with
    the bucket policy, then ACLs only when Object Ownership allows,
    Block Public Access (account OR bucket, on by default) and
    anonymous access through IAM's new `authorize_anonymous` or an
    AllUsers grant. `s3_post_policy.hpp` parses POST forms as they
    stream, checks the policy and verifies its signature through the
    same key resolution. Canonical ids are account ids; email grants
    are refused as in post-2019 regions. Wiring into the listener comes
    with the handlers in task 7.

- [x] 7. Buckets and objects API
  - Bucket operations and sub-resources; object put/get/head/delete,
    multi-delete, copy, attributes, listings; ranges; conditional reads
    and writes; metadata and ETags; the compatibility profile and its
    per-bucket tags
  - _Requirements: 3.1-3.3, 6.1, 6.2, 7.1-7.4_
  - Done: `s3_service.hpp` is the pipeline (route, SigV4, payload
    check, bucket lookup, access check per `s3_authz`/`s3_access`,
    handler); `s3_buckets.hpp`, `s3_objects.hpp` and `s3_listings.hpp`
    are the handlers for 37 operations (the access sub-resources task 6
    planned, plus this task's), moved to `implemented-operations.txt`.
    The front end reaches metadata through the `metadata_access`
    concept (`s3_metadata.hpp`; `local_metadata` in process until task
    16). The index gained `set_object_metadata` (object tags and ACLs in
    place), a create-time config map (new buckets never exist without
    their ownership and Block Public Access), and copy overrides (a
    copy's ACL is never the source's; tagging REPLACE). Compatibility
    profile in `s3_compat.hpp` with `kythira:compat:*` bucket tags;
    per-account bucket namespaces as an option. Checksums stay with
    task 8 (DeleteObjects accepts a checksum header in place of
    Content-MD5 but verifies only MD5), SSE-KMS/SSE-C requests answer
    `NotImplemented` until task 11.

- [x] 8. Checksums
  - CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, full-object and composite,
    trailing checksums
  - _Requirements: 7.4_
  - Done: `s3_checksums.hpp` has the five algorithms (CRCs from
    Boost.CRC, SHAs from OpenSSL EVP), streaming, base64 wire values,
    CRC combination (zlib's GF(2) method) so task 9 can derive a
    multipart upload's full-object CRC from its parts, and composite
    `<b64>-N` checksums. `requested()` reads what a request asks for
    (one `x-amz-checksum-*` header, or `x-amz-trailer` with
    `x-amz-sdk-checksum-algorithm`; CRC64NVME when nothing is named)
    and `verify()` checks the computed value against the header or the
    aws-chunked trailer (`BadDigest`, or `InvalidRequest` for a missing
    trailer). PutObject stores and returns the checksum; GET/HEAD return
    it under `x-amz-checksum-mode: ENABLED` on whole-object reads only;
    GetObjectAttributes reports it; CopyObject keeps it (also under
    `REPLACE`); DeleteObjects accepts a checksum header in place of
    `Content-MD5`. Tests: `s3_checksums_test` (published check values,
    combination, composites, header parsing) and
    `checksums_are_verified_stored_and_returned` in `s3_service_test`
    (header, trailer, mismatch, checksum mode, range, copy, attributes,
    DeleteObjects).

- [x] 9. Multipart upload
  - All operations, part copy, complete with checksums and conditions,
    abort and stale-upload sweep
  - _Requirements: 9.1-9.3_
  - Done: `s3_multipart.hpp` serves CreateMultipartUpload, UploadPart,
    UploadPartCopy, ListParts, ListMultipartUploads (delimiter, markers,
    `encoding-type`), CompleteMultipartUpload and AbortMultipartUpload.
    Parts are stored as chunks as they arrive and Complete commits one
    manifest naming them (no bytes copied); UploadPartCopy streams the
    source range into a new part (content addressing dedupes whole
    chunks). Checksums follow S3 since 2025: CRC64NVME full-object by
    default, a named algorithm COMPOSITE unless CRC64NVME; Complete
    derives the object's value (CRC combination or `-N` composite),
    checks a value the request names (`BadDigest`) and the parts'
    checksums in its body (`InvalidPart`, and `InvalidRequest` when a
    named algorithm's part checksum is missing), plus
    `x-amz-mp-object-size` and `If-Match`/`If-None-Match`. The bucket's
    profile sets part count, minimum part size (the index command now
    carries both), part and object size. `sweep_stale_uploads` aborts
    uploads past an age (9.3); lifecycle's abort rule is task 13 and
    will call the same abort. The index's complete merges the front
    end's checksum into the object (an empty value erases the upload's
    open-state keys). Tests: two cases in `s3_service_test` and new
    index assertions.

- [x] 10. Versioning and object lock
  - _Requirements: 8.1, 8.2_
  - Done: `s3_versioning.hpp` serves Get/PutBucketVersioning,
    ListObjectVersions, Get/PutObjectLockConfiguration,
    Get/PutObjectRetention and Get/PutObjectLegalHold over the index's
    versioning states (task 4). The index enforces the lock: a version's
    retention and legal hold are stored headers, every removal passes
    `lock_refuses` (legal hold, COMPLIANCE, or GOVERNANCE without
    `x-amz-bypass-governance-retention`), and the new `set_object_lock`
    command never weakens COMPLIANCE and weakens GOVERNANCE only with
    the bypass. `s3_object_lock.hpp` gives a new version its lock from
    the request's headers or the bucket's default retention (PUT, copy,
    browser POST, multipart: explicit at create, default at complete); a
    copy never inherits its source's lock. MFA delete is refused with
    `NotImplemented`. Lifecycle (task 13) will remove versions through
    the same index path, so it can never expire a locked one. Tests:
    `object_lock_protects_versions` and the extended versioning case in
    `s3_service_test`, `object_lock_is_enforced_on_every_removal` in
    the index test.

- [x] 11. Encryption
  - SSE-S3 default, SSE-KMS with bucket keys, SSE-C; chunk sealing in the
    front end
  - _Requirements: 11.1-11.3_
  - Done: every new object gets its own data key, from its SSE headers,
    the bucket's default encryption (Get/Put/DeleteBucketEncryption) or
    SSE-S3, and the data path seals each chunk with AES-256-GCM under it
    before hashing (`s3_chunk_cipher.hpp`); manifests keep plaintext
    sizes. Nonces are HMAC-derived from the chunk, so deduplication works
    within a key and only there. Data keys are stored wrapped
    (`s3_encryption.hpp`): SSE-S3 by the endpoint's S3-managed provider,
    SSE-KMS by `GenerateDataKey` as the caller (reads `Decrypt` as the
    reader, so `kms:Decrypt` is enforced), bucket keys cached per node and
    wrapping each object's key locally, SSE-C as a salted HMAC only. The
    `kms_key_provider` library has not moved out of Kinesis yet
    (kms-compatible-api task 16), so S3 has its own provider concept of the
    same shape: `local_key_provider` and `kms_api_provider` (Kythira or
    AWS KMS over the JSON API; the daemon hands it a transport in task 16).
    Copies share chunks only between SSE-S3 objects and re-encrypt through
    the front end otherwise (new index field `new_bytes`); multipart
    uploads keep their key with the upload. DSSE-KMS answers
    `NotImplemented`. Tests: `s3_encryption_test`, five encryption cases
    in `s3_service_test`, `a_re_encrypted_copy_takes_its_own_chunks_and_keys`
    in the index test.

- [x] 12. Orphan sweep, placement repair and request rates
  - Sweep of uncommitted chunks; repair to the copy count; per-prefix
    rate buckets with `SlowDown`; hot-prefix splits
  - _Requirements: 10.4, 10.6, 13.1, 13.2_
  - Done: `chunk_service` lists a node's chunks in hash order a page at a
    time and deletes one (`GET /_kythira/chunks/v1/?after=&limit=`,
    `DELETE .../<sha>`). `chunk_sweeper` (`s3_sweeps.hpp`) merges every
    node's listing, deletes chunks whose count has been zero a grace
    period, claims and deletes chunks with no index record that it saw a
    grace period earlier (uncommitted writes), and copies live chunks to
    reachable placement nodes that lack them. Deleting safely needed new
    index states: collected and claimed chunks stay *collecting* until
    every node has answered the delete, then keep a *deleted* tombstone
    for a grace period, and a reference to either from a write that began
    before the deletion (plus a 5 s clock allowance, `written_ms` on the
    entry) is refused with `SlowDown`; the front end refuses writes that
    take longer than `max_write_ms`, and the sweeper checks the grace
    period exceeds it. Per-prefix token buckets (`s3_rates.hpp`) answer
    `SlowDown` past the profile's `put-rate` / `get-rate` (bucket tags; 0
    turns them off). Hot prefixes are reported once per window through
    `on_hot_prefix` and counted; splitting a range has nothing to act on
    while one metadata group holds a bucket (task 17 makes it real, with
    prefix-affinity routing, so until then the limit is per front end).
    The sweeper's daemon wiring is task 16's. Tests: `s3_sweeps_test`,
    four collection cases in the index test, the listing and delete cases
    in `chunk_service_test`, rate and slow-write cases in
    `s3_service_test`.

- [x] 13. Lifecycle and storage classes
  - Rules, the worker, transitions to cloud tiers, restore
  - _Requirements: 7.5, 12.1_
  - Done: lifecycle configurations (`s3_lifecycle_rules.hpp`; Put, Get
    and Delete, old and new forms, S3's checks, the 128 KiB transition
    minimum header) and the worker (`lifecycle_worker`: expiration with
    markers in versioned buckets, noncurrent expiration with
    `NewerNoncurrentVersions`, lone delete markers, aborted uploads,
    transitions to the coldest due class, ended restores; every change
    pinned to the judged version's stamp). Archive classes answer GET and
    copies with `InvalidObjectState` until `RestoreObject`; a copy may
    change only the storage class; GET, HEAD and PUT carry
    `x-amz-expiration`. `s3_tiers.hpp` maps GLACIER and DEEP_ARCHIVE (only
    those, since the rest must stay readable) to a `cloud_tier` over any
    core `key_object_store`; `tier_worker` copies their chunks there, as
    stored, under per-version keys and drops the version's references on
    the blob stores. A restore of a tiered version is pending (`s3/r/`,
    `ongoing-request="true"`, a repeat answers
    `RestoreAlreadyInProgress`) until the worker brings the chunks back,
    verified, and the version takes references again until the restore
    ends. Removing a tiered version leaves an `s3/g/` entry, and the
    worker deletes its cloud copies. Per-version keys keep reference
    counts out of the tier at the cost of no dedup there; a copy orphaned
    by a version removed mid-upload waits for a tier listing sweep that
    is not built. Daemon wiring (leader only) is task 16's. Tests:
    `s3_lifecycle_test`, the lifecycle, archive and tier cases in
    `s3_service_test`, the tier reference case in the index test.

- [x] 14. Change log, notifications and replication
  - Change log per group; notifications to SQS, SNS and Kinesis; bucket
    replication to Kythira and to real S3
  - _Requirements: 12.2, 12.3_
  - Done: the change log (`s3_change_log.hpp`): the index state machine
    appends one record per object change to a core `segment_store` in
    apply (barrier before the engine write, truncated to the engine on
    open, active segment carried in checkpoints like DynamoDB's change
    log), only for buckets with a notification or replication
    configuration. Consumers keep cursors in the index
    (`advance_change_log`), and the log is trimmed below the lowest.
    Notifications (`s3_notifications.hpp`): the current and deprecated
    configuration forms with S3's checks (events, filters, overlapping
    rules, unique ids, destination TestEvents unless
    `x-amz-skip-destination-validation`), queue, topic and Kythira's
    `KinesisStreamConfiguration`; Lambda is refused (`InvalidArgument`)
    and EventBridge answers 501. The worker sends S3's event JSON (2.1,
    or 2.3 for the newer event types) in log order, at least once,
    holding back on a transient failure and dropping a delivery the
    destination refuses for good or after `max_attempts`.
    `s3_event_sinks.hpp` builds SQS, SNS and Kinesis API requests over a
    transport function, so a co-located module and AWS look alike.
    `sourceIPAddress` is empty (the index does not keep it). Replication
    (`s3_replication_rules.hpp`, `s3_replication.hpp`): both schemas with
    S3's checks, versioning required on source and local destination and
    kept on while configured, `PENDING` set at write time (copies decide
    afresh), and a worker that PUTs each new version (bytes, metadata,
    tags, lock, storage class) with `x-amz-replication-status: REPLICA`,
    sends client delete markers where the rule says, and sets `COMPLETED`
    or `FAILED`. Replica writes need `s3:ReplicateObject` /
    `s3:ReplicateDelete` and are never replicated on. Not built:
    `ExistingObjectReplication` (501), replicating SSE-C objects (as on
    S3) and later tag or ACL changes, and keeping the source's version
    ids at a destination (only S3's internal path can). Daemon wiring
    (leader only, transports) is task 16's. Tests:
    `s3_notifications_test`, the change log cases in the index test, the
    notification and replication cases in `s3_service_test`.

- [x] 15. CORS and website hosting
  - _Requirements: 12.4_
  - Done: CORS (`s3_cors_rules.hpp`, `s3_cors.hpp`): Put/Get/Delete
    BucketCors with S3's checks (1-100 rules, an origin and a method per
    rule, only GET/PUT/POST/DELETE/HEAD, one wildcard per origin or
    allowed header, none in exposed headers, Content-MD5 required).
    Preflights (`OPTIONS`) are never authenticated and answer from the
    catalog entry alone: the first rule whose origin (case-sensitive),
    method and every requested header (case-insensitive) match, with S3's
    `BadRequest` and `AccessForbidden` "CORSResponse" errors otherwise.
    Every other answer from a bucket with CORS, errors and browser POST
    uploads included, carries the matching rule's headers and `Vary`.
    Website (`s3_website_rules.hpp`, `s3_website.hpp`): Put/Get/Delete
    BucketWebsite with S3's checks (index suffix without `/`,
    `RedirectAllRequestsTo` alone, up to 50 routing rules, 3XX redirect
    codes, 4XX/5XX conditions, one key replacement). The website endpoint
    is `<bucket>.<domain>` for `service_options::website_domains` (no
    path style, as on S3): GET and HEAD only, every read checked as the
    anonymous principal, redirect-all, routing rules before the read and
    after an error, index documents, `302` from `k` to `k/` when
    `k/<suffix>` exists, `x-amz-website-redirect-location`, `404` or
    `403` for a missing key by whether anyone may list, then the error
    document (served whole, with the error's status) or S3's HTML error
    page. CORS preflights work there too. Website redirects use the
    listener's scheme (`secure_transport`); the daemon's website listener
    and domain flags are task 16's. Tests: `s3_website_rules_test`, the
    CORS and website cases in `s3_service_test`.

### Phase 3: independent layers

- [x] 16. Roles and metadata access
  - `KYTHIRA_S3_ROLES`; local, remote and hybrid metadata access; workers
    on metadata nodes only
  - _Requirements: 14.1, 14.2, 14.6, 14.7_
  - Done: `s3_roles.hpp` parses `KYTHIRA_S3_ROLES` (`gateway`,
    `front_end`, `metadata`, `blobs`; all four by default) onto the shared
    layer roles, so certificates carry `data` for metadata and `segments`
    for blobs, and refuses at start, naming what is missing, a role set
    that cannot serve yet: a front end without metadata endpoints, the
    gateway without the front end (task 17), and metadata or blobs alone
    (a blob pool, task 18). `internal_route_rules()` opens the metadata
    routes to front ends and metadata nodes and the chunk routes to those
    and blob nodes; the gateway calls neither. `s3_remote_metadata.hpp`:
    every `metadata_access` call (and the workers' calls) as
    `POST /_kythira/s3/metadata/v1/<call>` in the index's own record
    encoding, `metadata_server` over the local group (503 when it may not
    answer), `remote_metadata`, an `endpoint_transport` that fails over on
    no answer or 503, and `hybrid_metadata`, which asks a `metadata_choice`
    about each call. A remote layer that does not answer throws
    `metadata_unavailable`, which the pipeline answers `503
    ServiceUnavailable`. `s3_workers.hpp`'s `worker_runner` runs the
    workers on a schedule only on nodes with the metadata role and only
    while `is_leader`, counting and logging failures without stopping
    other jobs. Daemon wiring (the leftovers of tasks 11-15):
    `s3_gateway_node` reads `KYTHIRA_S3_*` (`s3_node_config.hpp`, `--help`)
    and runs the API listener, the website listener (plain HTTP, as S3's,
    for `KYTHIRA_S3_WEBSITE_DOMAINS`), the internal listener (mutual TLS,
    route guard on layer identities), the chunk store, the lifecycle, tier,
    notification and replication workers and the chunk sweeper, and SigV4
    transports to KMS (forwarding the caller to a Kythira KMS), SQS, SNS,
    Kinesis and S3 (`s3_outbound.hpp`). The core HTTPS server now keeps a
    HEAD answer's Content-Length. Not built: the index on Raft. A metadata
    node holds its group in process and in memory, so a split layout has
    one metadata node, several metadata endpoints or a metadata node given
    endpoints (hybrid in the daemon) are refused, and nothing in the index
    survives a restart (as `dynamodb_gateway_node` without peers); the
    leadership gate is always open until then. Also not here: IAM
    authentication in the daemon (static keys; anonymous access through
    AllUsers grants only), cloud tiers in the daemon (the tier worker runs
    with none), streaming bodies (whole bodies up to
    `KYTHIRA_S3_MAX_REQUEST_BYTES` until task 17), and the container job,
    which joins with task 20's docker-chaos scenario. Tests:
    `s3_layers_test`, `s3_gateway_node_test` (co-located with a website;
    split over mutual TLS with layer identity certificates, a wrong-role
    caller refused, 503 once the metadata node is gone).

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
