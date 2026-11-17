# Requirements Document

## Introduction

This spec gives the KMS-compatible service
(`.kiro/specs/kms-compatible-api/`) the layering rules
`.kiro/specs/kinesis-independent-layers/` sets for Kinesis: each layer can
run as its own process or cluster, co-located operation stays the default
and is never required to change, and a running deployment can move from
co-located to independent operation and back. It follows Clark's request
of 2026-11-17 ("Do the same for DDB, KMS, and HSM"), and his rules that
every spec tests its migration paths and, as far as possible, its
interoperability with the real AWS service.

The KMS is not built yet (its tasks are all open), so this spec mostly
constrains how it is built: the layers below are drawn from its design,
and its tasks should build each layer behind the seam named here, so that
independence costs no rewrite later.

The shared core pieces come from the Kinesis spec and are not redefined:
per-node roles, layer identities (mutual TLS with roles), the route cache,
the layer membership group and its capacity loop, and the authenticated
call from gateway to front end.

### KMS's layers

1. **Gateway**: AWS JSON 1.1 framing, request limits, SigV4.
2. **Front end**: authorization (IAM evaluator plus grants), the operation
   handlers, the ciphertext blob and AAD canonicalization, throttling, and
   every call to the HSM. It holds the PIN of the HSM's `kms` token.
3. **Data**: the KMS catalog, one Raft group: keys, versions (backing
   object ids), aliases, policies, grants, tags, and job state.

The HSM is the key backend. It is a separate service with its own layers
(`.kiro/specs/hsm-independent-layers/`), reached in-process through
`hsm.client` when co-located with an HSM crypto node, else through the
PKCS#11 network client. It is not a KMS layer. The KMS has no record
segment store.

**Scope**: roles, a catalog interface with local and remote
implementations, consistent metadata reads from a front end, where jobs
run, throttling, the in-process `kms.client` in split layouts, migration
both ways, tests including real-AWS interoperability.

**Out of scope**: anything the KMS spec leaves out (custom key stores,
imported material, multi-Region keys).

## Glossary

The Kinesis spec's glossary applies. In addition:

- **Catalog access**: the interface through which handlers and jobs read
  and write the KMS catalog.
- **Job lease**: a catalog record naming the one front end that runs
  background jobs, with an expiry and a fencing token.

## Requirements

### Requirement 1: Co-located operation stays the default

**User Story:** As an operator, I want a KMS that runs as the KMS spec
describes unless I ask for independent layers.

#### Acceptance Criteria

1. With no new setting a KMS node SHALL run all three roles, and `kms_node`
   and `kythira_node` SHALL behave as the KMS spec specifies.
2. A co-located node SHALL read and write its catalog replica in-process.
3. No KMS feature SHALL require independent operation.

### Requirement 2: Roles

**User Story:** As an operator, I want to scale cryptographic traffic
without adding catalog voters.

#### Acceptance Criteria

1. A node SHALL take its role set from `KYTHIRA_KMS_ROLES`, a subset of
   `gateway`, `front_end`, `data`; default all three.
2. A node without `data` SHALL NOT be a member of the KMS catalog group.
3. A node without `front_end` SHALL NOT hold the HSM token PIN or any HSM
   client, so data nodes and gateways cannot make HSM calls.
4. A role set the node cannot serve SHALL stop it at start with the reason.

### Requirement 3: Catalog access

**User Story:** As a maintainer, I want KMS handlers written once for
every layout.

#### Acceptance Criteria

1. KMS handlers and jobs SHALL reach the catalog only through a
   value-returning `kms_catalog_access` interface (key by id, ARN or alias;
   listings; grants for a key and grantee; policy; propose a command),
   with a local implementation over the catalog replica and a remote one
   over the data-layer API.
2. The KMS spec's tasks SHALL build the handlers against that interface
   from the start (its task 4 onwards).
3. Answers SHALL be the same in every layout.

### Requirement 4: Consistent metadata from a front end

**User Story:** As a security reviewer, I want a disabled key, a revoked
grant or a narrowed policy to take effect for split front ends exactly as
for co-located nodes.

#### Acceptance Criteria

1. A cryptographic operation SHALL read the key's metadata (state,
   versions, policy, grants) at a read-index point of the catalog, as the
   KMS design requires. A remote front end SHALL get it through a
   `consistent` read served by the catalog leader after a read-index
   round, or by a follower that has applied past it.
2. A front end MAY cache metadata only under a compatibility-profile
   switch (`bounded_staleness`, default off) with a stated bound, since
   AWS documents KMS as eventually consistent. With the switch off, every
   operation does the read of 4.1.
3. When the catalog cannot be reached at a read-index point the front end
   SHALL answer `KMSInternalException` and SHALL NOT use cached metadata.

### Requirement 5: Jobs

**User Story:** As a security reviewer, I want HSM credentials only where
cryptographic calls are made.

#### Acceptance Criteria

1. Rotation, deletion, the orphan sweep and managed-key creation SHALL run
   on one front end holding the job lease, not on the catalog leader,
   because they call the HSM and data nodes hold no HSM credentials
   (Requirement 2.3).
2. The lease SHALL be a catalog record with an expiry and a fencing token;
   every job command SHALL carry the token and the catalog SHALL refuse a
   command whose token is not current, so two front ends never both act.
3. In a co-located node the lease holder is a co-located node, so the
   behaviour matches the KMS spec's "catalog leader" wording; the KMS
   spec's design SHALL be updated to say "lease holder".

### Requirement 6: Gateway and authorization

**User Story:** As an operator, I want SigV4 and connections handled apart
from cryptographic work.

#### Acceptance Criteria

1. The gateway SHALL verify SigV4 and hand the front end an authenticated
   call, as Kinesis Requirement 4 defines it.
2. Authorization (IAM evaluator, key policy, grants, `kms:ViaService`) SHALL
   stay in the front end.
3. Signed envelopes from consumers on other clusters
   (`KYTHIRA_KMS_TRUSTED_SERVICES`) SHALL be accepted by front ends, and a
   gateway SHALL pass them through unchanged.

### Requirement 7: Throttling

**User Story:** As an operator, I want AWS's KMS quotas to hold in every
layout.

#### Acceptance Criteria

1. Throttling SHALL happen in front ends, each holding one over the live
   front ends of every quota, as the KMS design's per-node scaling does
   with serving nodes.
2. The live count SHALL come from the layer membership group,
   configuration or DNS discovery.

### Requirement 8: In-process consumers

**User Story:** As a Kinesis or DynamoDB operator, I want encryption to
work whichever KMS layers sit beside my service.

#### Acceptance Criteria

1. `kms.client` SHALL be published in-process only by a node with the KMS
   `front_end` role. Elsewhere consumers SHALL use the HTTPS client, which a
   registry miss already selects.
2. DynamoDB data nodes (which hold table keys) and Kinesis front ends
   (which seal records) SHALL each be tested against a co-located and a
   remote KMS front end.

### Requirement 9: Authentication between layers

**User Story:** As a security reviewer, I want the KMS's internal calls
held to the same rules as the other services'.

#### Acceptance Criteria

1. Internal calls SHALL use layer identities with `kms` as the service and
   per-route role checks, as Kinesis Requirement 7 defines them.
2. The data-layer API SHALL accept only `front_end` and `data` callers.

### Requirement 10: Live migration

**User Story:** As an operator, I want to move a running KMS between
layouts in both directions.

#### Acceptance Criteria

1. Moving a stateless role SHALL need a drain and a restart; moving the
   data role SHALL use learner, promote, leadership transfer and remove on
   the catalog group.
2. The job lease SHALL move with its holder's drain: a draining front end
   releases it, and another takes it.
3. During a migration no committed key, version, grant or policy change
   SHALL be lost; a ciphertext made before any step SHALL decrypt after it;
   a disabled key SHALL never be used after its disable committed.

### Requirement 11: Testing

**User Story:** As a maintainer, I want every layout, every migration path
and real-AWS interoperability tested.

#### Acceptance Criteria

1. The KMS spec's CLI, boto3 and Encryption SDK suites SHALL run against a
   split layout (gateway, front end and data apart).
2. Every migration path SHALL have its own test in both directions:
   gateway role, front-end role (with the job lease), data role, and the
   whole co-located to split path and back with a stop and reversal
   midway, under an encrypt/decrypt and key-administration workload,
   checking Requirement 10.3.
3. A docker-chaos scenario SHALL run the full path both ways with HSM and
   KMS faults, on Docker and rootless Podman.
4. Interoperability with real AWS SHALL be tested as far as AWS allows:
   the KMS spec's recorded AWS KMS fixtures replayed against the split
   layout; the AWS Encryption SDK with a multi-keyring of a Kythira KMS
   key and a real AWS KMS key, where a message encrypted by either side
   decrypts through the other keyring; and Kinesis and DynamoDB switching
   between the `kythira` and `aws` providers on a split layout without
   losing access to data written under the other. Spending runs are
   dispatch-only, need Clark's go in his own words each time, and
   schedule deletion of every AWS key they create.
5. The KMS spec's plaintext scan SHALL also cover gateway and data-node
   directories in the split layout, and SHALL find no HSM PIN there.

### Requirement 12: Documentation

**User Story:** As an operator, I want to know which KMS layer holds
which secret and how to migrate.

#### Acceptance Criteria

1. `services/kms/doc/` SHALL describe the layers, which layer holds which
   secret (the HSM PIN only on front ends; no key material anywhere in the
   KMS), sizing, and the migration runbook.
