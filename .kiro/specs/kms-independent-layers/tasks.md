# Implementation Plan

These tasks interleave with `.kiro/specs/kms-compatible-api/` tasks. Task
1 lands before that spec's task 5 (its first handler). The shared core
pieces (layer identity, route cache, layer membership group, the
authenticated call) come from `.kiro/specs/kinesis-independent-layers/`;
a task that needs one first builds it to that spec's design.

- [x] 1. `kms_catalog_access` and the local implementation
  - The interface and a local implementation over the catalog replica;
    the KMS spec's tasks build handlers against it
  - _Requirements: 3.1-3.3_

- [x] 2. Job lease
  - Lease record and fencing token in the catalog state machine; jobs run
    on the holder; KMS spec design updated to say "lease holder"
  - _Requirements: 5.1-5.3_

- [x] 3. Roles and remote catalog access
  - `KYTHIRA_KMS_ROLES`, validation, no HSM client without `front_end`;
    remote catalog access with consistent reads; bounded-staleness switch
  - _Requirements: 1.1-1.3, 2.1-2.4, 4.1-4.3_

- [x] 4. Gateway apart from the front end; throttling share
  - Authenticated-call handoff, trusted-service envelopes passed through,
    role checks; throttling share over live front ends
  - Built as `kms_front_end_api.hpp`: `front_end::authenticate` (framing
    and SigV4) on the gateway and `front_end::execute` on the front end,
    the client's request carried whole so envelopes pass unchanged; the
    gateway retries elsewhere only on "not executed" (503) or a failed
    dial; live front ends come from `KYTHIRA_KMS_FRONT_END_URLS` and
    health probes; `kms_peer.hpp`'s `admits` checks layer identities per
    route, members listed in `KYTHIRA_KMS_PEER_IDENTITIES` keep every
    layer
  - _Requirements: 6.1-6.3, 7.1, 7.2, 9.1, 9.2_

- [ ] 5. In-process consumers in split layouts
  - `kms.client` published only by front-end nodes; DynamoDB and Kinesis
    tests against a co-located and a remote KMS front end
  - _Requirements: 8.1, 8.2_

- [ ] 6. Migration path tests
  - One test per path in both directions under an encrypt/decrypt and
    key-administration workload: gateway role, front-end role with the
    job lease, data role, and the whole co-located to split path and back
    with a stop and reversal midway; each checks Requirement 10.3
  - docker-chaos scenario of the full path both ways with HSM and KMS
    faults, Docker and rootless Podman
  - _Requirements: 10.1-10.3, 11.2, 11.3_

- [ ] 7. Interoperability with real AWS
  - CI (no spend): recorded AWS KMS fixtures replayed against the split
    layout; the KMS suites against it
  - Real-cloud bundle (dispatch-only, repo-variable switch): Encryption
    SDK multi-keyring of a Kythira key and a real AWS KMS key, each side
    decrypting the other's messages; Kinesis and DynamoDB moving between
    the `kythira` and `aws` providers on a split layout with old data
    still readable
  - Each run needs Clark's go, reports cost, schedules deletion of every
    AWS key it made
  - _Requirements: 11.1, 11.4_

- [ ] 8. Plaintext scan and documentation
  - Scan gateway and data-node directories; docs with the secrets-by-layer
    table and the runbook
  - _Requirements: 11.5, 12.1_
