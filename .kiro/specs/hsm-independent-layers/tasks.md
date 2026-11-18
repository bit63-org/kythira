# Implementation Plan

Builds on `.kiro/specs/virtual-hsm/` (tasks 6 and 8 done first). The shared
core pieces (layer identity, route cache) come from
`.kiro/specs/kinesis-independent-layers/`; a task that needs one first
builds it to that spec's design. Each task is one PR unless noted.

- [ ] 1. Roles and validation
  - `KYTHIRA_HSM_ROLES`; no vault, unseal or share without `crypto`; no
    engine or groups without `store`; start-time validation
  - _Requirements: 1.1, 2.1-2.5_

- [x] 2. Crypto member list
  - Catalog field and admin commands; co-located clusters seed it from
    the store members; node unseal checks it and the `crypto` role; init
    and rekey hand shares to crypto members only; removal completes with a
    rekey in `hsm_ctl` and the admin API
  - _Requirements: 1.2, 5.1-5.5, 7.2_

- [ ] 3. Remote store with seal-carrying barriers
  - `remote_hsm_store` over an extended `hsm_peer` store API; reads with
    the barrier; seal state on every answer and an idle watch; proposals
    without onward forwarding
  - Session-layer tests over the remote store, including a seal and a
    destroy committed between two uses
  - _Requirements: 3.1-3.4, 4.1-4.4, 7.1_

- [x] 4. Endpoint relay
  - L4 relay role: pin to an unsealed, healthy crypto node, drain, close on
    crypto failure; `libkythira_pkcs11` reconnect test through it
  - Relay core in `endpoint_relay.hpp`; starting it as the `endpoint` role
    of `hsm_node` lands with task 1's roles wiring
  - _Requirements: 6.1-6.5_

- [ ] 5. Consumers in split layouts
  - `hsm.client` only from crypto nodes; KMS, CA, Kinesis and IAM tests
    against co-located and remote crypto nodes
  - _Requirements: 8.1, 8.2, 10.1_

- [ ] 6. Migration path tests
  - One test per path in both directions under a sign/decrypt and
    key-administration workload: store split off and back, crypto split
    off and back (with rekey), endpoint added and removed, and the whole
    path both ways with a stop and reversal midway; each checks
    Requirement 9.4 and that no share reached a non-crypto node
  - docker-chaos scenario of the full path both ways with kills of each
    layer and a seal mid-path, Docker and rootless Podman
  - _Requirements: 9.1-9.4, 10.2, 10.3_

- [ ] 7. Per-role plaintext scan
  - Scan store and endpoint nodes after every split-layout test run
  - _Requirements: 10.4_

- [ ] 8. Interoperability with AWS CloudHSM
  - Dispatch-only real-cloud bundle (repo-variable switch): a CloudHSM
    cluster with one HSM; the consumer suite through
    `kythira::pkcs11::module` against CloudHSM's PKCS#11 library and
    against the split virtual HSM, differing only in configuration;
    cross-verification of signatures with exported public keys
  - Each run needs Clark's go, reports the HSM-hours billed, and deletes
    the cluster and its backups
  - _Requirements: 10.5_

- [ ] 9. Documentation
  - Exposure-by-role table, crypto member list, rekey on removal, runbook
  - _Requirements: 11.1_
