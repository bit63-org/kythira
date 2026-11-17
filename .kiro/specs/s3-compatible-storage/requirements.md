# Requirements Document

## Introduction

This spec adds an **Amazon S3-compatible object storage service** to
Kythira. Unmodified AWS SDKs, the AWS CLI, `rclone`, `s3fs`, Mountpoint for
Amazon S3, Spark and Trino's S3 connectors, Terraform's S3 backend and other
S3 tools point their endpoint at a Kythira cluster and work.

It follows Clark's request of 2026-11-17 ("Then build specs for S3, SNS,
and SQS following the rules"), which applies the rules he set for every
service spec that day:

- **Independent layers** (`.kiro/specs/kinesis-independent-layers/`): each
  layer can run as its own process or cluster, co-located operation is the
  default and is never required, and a running deployment can migrate from
  co-located to independent and back. This service is specified layered
  from the start and reuses that spec's shared core pieces (roles, layer
  identities, route cache, layer membership group, authenticated call).
- **Migration tests**: tasks that test every migration path.
- **Interoperability**: tasks that test interoperability with real Amazon
  S3 as far as AWS allows.

It also follows the module conventions the DynamoDB and Kinesis specs set:
an opt-in module under `services/`, a pinned botocore model with a coverage
test, a compatibility profile defaulting to AWS behaviour, SigV4 and IAM
authorization through core, and the shared `kms_key_provider` for
encryption.

There is no S3 service in the tree today. The existing S3 work
(`cloud-object-persistence`, `object-backup-s3-endpoint`, the object-store
specs) is Kythira **using** S3 for its own storage; this spec makes Kythira
**offer** S3, and those clients become one of its consumers.

### Layers

1. **Gateway**: the S3 REST protocol (path-style and virtual-hosted-style
   addressing, REST-XML), TLS, request limits, SigV4 in headers, query
   strings (presigned URLs) and streaming chunked payloads with trailing
   checksums (core `sigv4_chunk_decoder.hpp`), browser POST uploads.
2. **Front end**: authorization (IAM, bucket policies, ACLs under Object
   Ownership, Block Public Access), the operation handlers, multipart
   orchestration, conditional requests, checksums, server-side encryption,
   range reads, request-rate throttling, event-notification publishing.
3. **Metadata** (the data layer): the multi-Raft host and the object index
   state machine on the persistent `kv_engine`: buckets, object versions
   and manifests, multipart uploads, tags, ACLs, policies, lifecycle and
   object-lock state, chunk reference counts.
4. **Blob store**: content-addressed chunks of object bytes, generalised
   from the build cache's `cache_chunk_store` into core.

**Scope**: buckets, objects, versioning, multipart upload, copy,
conditional writes and reads, checksums, ACLs and Object Ownership, bucket
policies, Block Public Access, CORS, lifecycle (expiration, noncurrent
versions, aborting uploads, transitions to tiers), object lock, tagging,
server-side encryption (SSE-S3, SSE-KMS, SSE-C), presigned URLs and POST
uploads, event notifications to Kythira's SQS, SNS and Kinesis, bucket
replication, static website hosting, the layers and their migration, and
the tests.

**Out of scope**: S3 Express One Zone directory buckets, S3 Tables and
S3 Vectors as APIs (Kinesis Channels' S3 Tables delivery is its own
concern), S3 Select, Storage Lens, Inventory, Analytics, Batch Operations,
Object Lambda, Access Points and Multi-Region Access Points (a follow-up
spec), Transfer Acceleration, Requester Pays, SigV2.

## Glossary

The Kinesis independent-layers glossary applies. In addition:

- **Pinned model**: the botocore `s3` `service-2.json` at a pinned version.
- **Manifest**: an object version's list of chunks (SHA-256, length) and
  its metadata, stored in the metadata layer.
- **Chunk**: an immutable run of object bytes, named by its SHA-256.
- **Blob node**: a node with the `blobs` role.
- **Placement**: which blob stores hold each chunk.
- **Compatibility profile**: the behaviour switches of Requirement 3.

## Requirements

### Requirement 1: Opt-in module

**User Story:** As a maintainer, I want S3 built only when asked for and
kept separable from the core.

#### Acceptance Criteria

1. The service SHALL live under `services/s3/`, follow `services/README.md`,
   and be built only with a Kconfig option `S3` (default off).
2. Module code SHALL include only core public headers, enforced by
   `scripts/check_module_boundaries.py`.
3. With the option off no existing target, test or binary SHALL change.
4. It SHALL be a service module (`.kiro/specs/service-colocation/`) with
   module number 8, runnable in `kythira_node` and as a stand-alone
   `s3_gateway_node`.
5. A path-filtered `.github/workflows/s3-module.yml` SHALL build and test
   it under Docker and rootless Podman.

### Requirement 2: Coverage of the API

**User Story:** As a user, I want every S3 call my tools make to work or
fail in a documented way.

#### Acceptance Criteria

1. Every operation in the pinned model SHALL be implemented or listed in
   `services/s3/doc/unsupported.md` with the error it returns
   (`NotImplemented`, 501, as S3 answers).
2. A generated test SHALL fail if the pinned model gains an operation that
   is neither implemented nor listed.
3. Upgrading the pinned model SHALL be a reviewed change.

### Requirement 3: Compatibility profile

**User Story:** As an operator, I want AWS behaviour by default and the
choice to relax limits.

#### Acceptance Criteria

1. The `aws` profile SHALL be the default and reproduce S3's behaviour,
   limits and error shapes (XML `Error` with `Code`, `Message`,
   `RequestId`, `HostId`, and AWS's HTTP statuses).
2. Switches settable per cluster and per bucket (a `kythira:compat:*` bucket
   tag, the bucket value winning): per-prefix request rates and `SlowDown`;
   object and part size limits (5 TiB object, 5 GiB single PUT, 10,000
   parts, 5 MiB minimum part); bucket count per account; the default
   Object Ownership (`BucketOwnerEnforced`) and Block Public Access
   (on) for new buckets.
3. Error codes, messages and statuses SHALL always match S3.

### Requirement 4: Protocol and addressing

**User Story:** As a user, I want my clients' wire format accepted as it
is.

#### Acceptance Criteria

1. The gateway SHALL accept path-style (`/bucket/key`) and
   virtual-hosted-style (`bucket.<endpoint>`) requests, with the endpoint
   domains configured, and reject bucket names S3 rejects.
2. Authentication SHALL be SigV4 through core `sigv4_verifier` in the
   `Authorization` header and in query strings (presigned URLs, up to 7
   days), including `UNSIGNED-PAYLOAD`,
   `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
   `STREAMING-UNSIGNED-PAYLOAD-TRAILER` and
   `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with trailing checksums.
   SigV4a and SigV2 SHALL be refused with S3's error.
3. Browser POST uploads with a signed policy document SHALL be accepted.
4. `Expect: 100-continue` SHALL be honoured before the body is read.
5. Request limits SHALL follow `http-server-request-limits`, no lower than
   S3's.

### Requirement 5: Authorization

**User Story:** As a security reviewer, I want S3's access model, with
public access off by default.

#### Acceptance Criteria

1. Authorization SHALL go through `aws_request_authorizer` with an `s3`
   action table (actions, bucket and object ARNs, condition keys such as
   `s3:prefix`, `s3:x-amz-server-side-encryption`, `aws:SecureTransport`).
2. Bucket policies SHALL be evaluated with identity policies as IAM does.
3. ACLs SHALL be honoured only when a bucket's Object Ownership allows
   them; `BucketOwnerEnforced` (the default) disables them as S3 does.
4. Block Public Access (account and bucket) SHALL be enforced and on by
   default.
5. Anonymous requests SHALL be allowed only where a policy or ACL grants
   public access and Block Public Access permits it.
6. Without IAM, a static access-key table with roles SHALL be available,
   as the other services offer.

### Requirement 6: Buckets

#### Acceptance Criteria

1. Bucket create, delete (empty only), head, list (with pagination and
   prefix), location, and the bucket sub-resources (versioning, policy,
   ACL, ownership controls, public access block, CORS, lifecycle,
   encryption, tagging, notification, replication, website, object lock
   configuration, logging configuration accepted and stored) SHALL behave
   as S3.
2. Bucket names SHALL be unique per cluster (S3's global namespace scaled
   to one cluster), with an option for per-account namespaces as DynamoDB
   offers.
3. Bucket ids SHALL never be reused, so a recreated bucket sees no old
   object.

### Requirement 7: Objects

#### Acceptance Criteria

1. Put, get (with ranges, `partNumber`, response header overrides), head,
   delete, delete-multiple (up to 1,000), copy (including metadata and
   tagging directives, and conditional copy), restore of tiered objects,
   attributes (`GetObjectAttributes`) and the list operations (V1, V2 with
   delimiter, start-after, continuation; object versions) SHALL behave as
   S3.
2. Reads SHALL be strongly consistent: a successful write or delete is
   visible to every following read and listing, as S3 has been since 2020.
3. Conditional reads (`If-Match`, `If-None-Match`, `If-Modified-Since`,
   `If-Unmodified-Since`) and conditional writes (`If-None-Match: *`,
   `If-Match` on PUT, complete-multipart and copy) SHALL behave as S3, with
   the condition checked in the metadata layer's `apply()`.
4. Checksums SHALL be computed, stored and verified for CRC32, CRC32C,
   CRC64NVME, SHA-1 and SHA-256, full-object and composite, and returned
   when asked, as S3 does; ETags SHALL match S3's (MD5 for single-part
   unencrypted objects, the multipart form otherwise).
5. User metadata, system metadata and storage classes SHALL be stored and
   returned. Storage classes SHALL map to Kythira tiers (local blobs, or
   tiered to a cloud object store), with archive classes needing
   `RestoreObject` before a read.

### Requirement 8: Versioning and object lock

#### Acceptance Criteria

1. Unversioned, enabled and suspended versioning SHALL behave as S3,
   including delete markers, `null` versions and version listing order.
2. Object lock (governance and compliance retention, legal hold, default
   retention, `x-amz-bypass-governance-retention`) SHALL be enforced in
   the metadata layer so no layer can delete a locked version, and
   lifecycle SHALL never expire one.

### Requirement 9: Multipart upload

#### Acceptance Criteria

1. Create, upload part, upload part copy, list parts, list uploads,
   complete (with checksums and conditions) and abort SHALL behave as S3.
2. Parts SHALL be stored as chunks as they arrive; complete SHALL commit a
   manifest referencing them without copying bytes.
3. Parts never completed SHALL be removed by abort, by lifecycle's
   abort rule, or by a sweep after a configured age.

### Requirement 10: Write durability

**User Story:** As a user, I want a successful PUT to survive node loss.

#### Acceptance Criteria

1. A write SHALL be acknowledged only after every chunk it adds is durable
   (fsynced) on at least a write quorum of its placement, and its manifest
   is committed through Raft.
2. The manifest SHALL be committed only after its chunks are durable, so no
   committed object names a chunk that is nowhere.
3. Chunk reference counts SHALL live in the metadata state machine; a chunk
   SHALL be deleted only when its count has been zero for a grace period
   longer than any in-flight write, so a concurrent PUT of the same bytes
   cannot lose them.
4. Chunks written but never committed (a failed or abandoned PUT) SHALL be
   found and deleted by an orphan sweep.
5. Every chunk read SHALL be checked against its SHA-256; a bad copy SHALL
   be repaired from another and reported.
6. Placement repair SHALL restore the configured copy count after a blob
   store is lost.

### Requirement 11: Encryption

#### Acceptance Criteria

1. SSE-S3 (the default for new objects, as on S3 since 2023), SSE-KMS
   (with bucket keys) and SSE-C SHALL behave as S3, through the shared
   `kms_key_provider` (`kythira`, `aws` or `local`).
2. Chunks of an encrypted object SHALL be sealed with AES-256-GCM under the
   object's data key before they leave the front end, so blob stores and
   metadata nodes hold only ciphertext; deduplication SHALL then only
   apply within a data key.
3. An SSE-C key SHALL never be stored; only its salted HMAC, to check a
   later request.

### Requirement 12: Lifecycle, notifications, replication, website

#### Acceptance Criteria

1. Lifecycle rules (filters by prefix, tags and size; expiration;
   noncurrent version expiration; abort incomplete uploads; transitions)
   SHALL be applied by a leader-side worker, with S3's documented daily
   evaluation semantics (and a faster test interval).
2. Event notifications SHALL deliver S3's event JSON to Kythira SQS and SNS
   (in-process when co-located, else their APIs) and to Kythira Kinesis,
   at least once, from a leader-side worker reading a change log of the
   bucket's groups (the core record segment store).
3. Replication rules SHALL copy new versions to a destination bucket on
   another Kythira cluster or on real Amazon S3, with replication status
   on the source, at least once, in version order per key.
4. Static website hosting (index and error documents, redirects, routing
   rules) SHALL be served on a website endpoint.

### Requirement 13: Request rates

#### Acceptance Criteria

1. In the `aws` profile, request rates SHALL be limited per prefix (3,500
   writes and 5,500 reads per second) with `503 SlowDown`, and a hot
   prefix's metadata range SHALL split so rates scale as S3's do.
2. Rate buckets SHALL live in the front end, routed by prefix affinity as
   Kinesis Requirement 8.3 routes by shard.

### Requirement 14: Independent layers

**User Story:** As an operator, I want each layer runnable on its own, and
co-located by default.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_S3_ROLES`, a subset of
   `gateway`, `front_end`, `metadata`, `blobs`; default all four.
2. Handlers SHALL reach metadata only through a value-returning interface
   with local, remote and hybrid implementations, chosen per call, as
   Kinesis Requirement 3 requires.
3. Front ends SHALL find metadata groups through the route cache and blob
   stores through the placement map (Requirement 15).
4. The gateway SHALL verify SigV4 (including chunked payload signatures,
   which it checks as it streams) and hand front ends an authenticated
   call; object bodies SHALL stream through without being buffered whole.
5. Internal calls SHALL use layer identities with `s3` as the service and
   per-route role checks.
6. Leader-side workers (lifecycle, notifications, replication, sweeps,
   placement repair) SHALL run on metadata nodes, gated by leadership.
7. A co-located node SHALL serve local operations in-process with no extra
   hop.

### Requirement 15: Blob placement

**User Story:** As an operator, I want object bytes on nodes sized for
capacity, with the same durability co-located or apart.

#### Acceptance Criteria

1. Co-located, each metadata replica's node SHALL hold the chunks of the
   objects its groups own, so the copy count equals the replica count.
2. With blob nodes, chunks SHALL be placed by rendezvous hashing of the
   chunk's SHA-256 over the blob nodes, across placement groups, with a
   configured copy count (default 3) and write quorum (default 2 of 3).
3. The placement map (blob nodes, their placement groups, weights and a
   placement epoch) SHALL be replicated in the S3 catalog.
4. A placement change SHALL move chunks in the background, by copying and
   verifying the SHA-256 before the old copy is released, and reads SHALL
   try the new placement first, then the old, until the move is done.
5. Erasure coding is not required; the design SHALL leave room for it.

### Requirement 16: Live migration

**User Story:** As an operator, I want to move a running S3 cluster between
layouts in both directions without downtime or data loss.

#### Acceptance Criteria

1. Stateless roles SHALL move with a drain and a restart.
2. The metadata role SHALL move through learner, promote, leadership
   transfer and remove, and an `evacuate` admin call.
3. Blob storage SHALL move from co-located stores to blob nodes, and back,
   through placement changes (Requirement 15.4), with no object
   unreadable at any point.
4. During a migration no acknowledged write SHALL be lost, reads SHALL stay
   strongly consistent, multipart uploads in progress SHALL complete, and
   presigned URLs issued before a step SHALL work after it.

### Requirement 17: Testing and conformance

#### Acceptance Criteria

1. Unit, property and in-process cluster tests SHALL cover the object
   index, versioning, multipart, conditions, checksums, locks, chunk
   reference counts and sweeps.
2. Open-source S3 conformance suites (Ceph `s3-tests` and MinIO `mint`)
   SHALL run in CI against co-located and four-way split layouts, with a
   checked-in list of expected failures that only shrinks.
3. The AWS CLI, boto3, aws-sdk-java-v2, aws-sdk-go-v2, aws-sdk-js-v3,
   `rclone`, Mountpoint for Amazon S3 and Kythira's own S3 object-store
   client (`aws_s3_client.hpp`, pointed at Kythira S3) SHALL run in CI.
4. Every migration path SHALL have its own test in both directions:
   gateway role, front-end role, metadata role, blob storage moved to blob
   nodes and back, and the whole co-located to four-way path and back with
   a stop and reversal midway, under a PUT, GET, multipart and list
   workload, checking Requirement 16.4; and a docker-chaos run of the full
   path killing one node per layer, on Docker and rootless Podman.
5. Interoperability with real Amazon S3 SHALL be tested as far as AWS
   allows: recorded S3 responses replayed in CI as differential fixtures;
   and a dispatch-only real-cloud bundle that runs `s3-tests` against S3
   and against Kythira and compares the results, syncs objects both ways
   with `aws s3 sync` and checks checksums and metadata survive, replicates
   a Kythira bucket to a real S3 bucket, uses SSE-KMS with real AWS KMS
   keys, and delivers event notifications to a real SQS queue. Each run
   needs Clark's go in his own words, reports its cost and deletes what it
   made.
6. A measurement row SHALL record PUT and GET throughput and latency by
   object size, co-located and split.

### Requirement 18: Documentation

#### Acceptance Criteria

1. `services/s3/doc/` SHALL cover configuration, the layers and sizing,
   durability and placement, encryption, the compatibility profile,
   unsupported operations, and the migration runbook.
