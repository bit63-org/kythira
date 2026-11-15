# Implementation Plan

Depends on `.kiro/specs/service-colocation/` tasks 1-3 (the service module
interface and `kythira_node`) for task 6 on, and on the persistent state
machine for the Raft groups. Tasks 1-5 need neither and can start now. Each
task is one PR unless noted.

- [x] 1. Module skeleton and vendored headers
  - `KYTHIRA_HSM` Kconfig option (default off), `services/hsm/` layout per
    `services/README.md`, boundary check coverage
  - OASIS PKCS#11 v3.0 headers vendored unchanged under
    `services/hsm/third_party/pkcs11/`, with their licence
  - Off-by-default build proved unchanged
  - _Requirements: 1.1-1.4_
  - Done: the Kconfig symbol is `HSM` (`CONFIG_HSM`, CMake
    `KYTHIRA_BUILD_HSM`), like every other module's. The headers come from
    the OASIS TC's repository (`published/3-00/`), checksums in
    `third_party/pkcs11/README.md`; `<kythira/hsm/pkcs11.hpp>` is the only
    includer. `ci_full_defconfig` and its copies turn the module on;
    `ci_no_hsm_defconfig` and `hsm-module.yml` prove the module-off build
    has no HSM target or test. `docker/` and `pkcs11/`'s target arrive with
    the tasks that fill them (11 and 10).

- [x] 2. Shamir secret sharing and share encoding
  - GF(2^8) split and combine, share format with checksum and MK check
    value, property tests (any `k` rebuild, `k - 1` reveal nothing
    testable, corruption rejected)
  - _Requirements: 4.1, 4.2, 13.1_
  - Done: `<kythira/hsm/shamir.hpp>`. Field arithmetic is branch-free over
    the AES polynomial, so timing does not depend on secret bytes. A
    share is version, `k`, `n`, index, length, bytes, an 8-byte MK check
    value (HMAC-SHA256 of a fixed label under the MK) and a 4-byte
    SHA-256 checksum; the text form is `khs1-` plus hex, whitespace and
    case ignored. The checksum is checked before any field is trusted, so
    a typo is `bad_checksum`; shares from different splits are
    `mixed_shares` or, when `k`/`n` happen to match, `check_value_mismatch`
    after combining. `k = 1` needs `allow_single` (the development flag).
    "`k - 1` reveal nothing" is tested as: for a fixed set of `k - 1`
    shares, every one of the 256 possible values of the next share yields
    a different, valid secret. The secure arena of task 3 replaces
    `secret_bytes`' heap storage.

- [x] 3. Secure memory
  - `secure_arena` (mlock, `MADV_DONTDUMP`, zeroize), `PR_SET_DUMPABLE`
    and `RLIMIT_CORE` on load, startup error on lock failure unless
    allowed
  - _Requirements: 12.3, 12.4_
  - Done: `<kythira/hsm/secure_arena.hpp>`. Chunks (64 KiB by default)
    are anonymous mappings, `mlock`ed, `MADV_DONTDUMP`, and
    `MADV_WIPEONFORK` where the kernel has it; blocks are first fit in
    32-byte granules, wiped on release, and each chunk is wiped before
    it is unmapped (the first is kept, so the lock is proven once).
    `secret_bytes` now allocates from `process_arena()` through
    `secure_allocator`, which propagates on move so a moved key is never
    copied. The process arena starts best-effort so tools and tests run
    anywhere; `prepare_key_memory(allow_unlocked)` hardens the process
    and calls `require_locking()`, which fails with `lock_failed` unless
    the flag is set. `hsm_node --self-test` runs it today, with
    `--allow-unlocked-memory` as the flag; the service module's startup
    (task 6) calls it too. The real-limit test drops `CAP_IPC_LOCK` in a forked
    child, since root with it ignores `RLIMIT_MEMLOCK`. Task 2's note that
    the arena replaces `secret_bytes`' heap storage is done here.

- [x] 4. Mechanisms and attribute policy
  - OpenSSL 3 EVP implementations for every key type and mechanism in
    6.1-6.2; `attribute_policy` with one function and one test per rule in
    6.3-6.4; excluded functions and mechanisms answer as 6.5
  - _Requirements: 6.1-6.5, 13.3_
  - Done: `mechanisms.hpp` (single-part operations over key material;
    task 6 adds handles and multi-part buffering), `attribute_policy.hpp`
    and `attributes.hpp`. Choices the requirement left open:
    PKCS#1 v1.5 is offered for signatures only, since v1.5 decryption is
    a padding oracle and OAEP covers encryption; OAEP may use SHA-1
    (6.5 excludes SHA-1 only for signatures); AES-GCM tags are 96 to
    128 bits; key wrap mechanisms are refused for `C_Encrypt` so wrapping
    always goes through the wrap checks; ECDH1 supports `CKD_NULL` only
    (HKDF after it covers KDFs); HKDF's `CKF_HKDF_SALT_KEY` waits for
    the session layer, which resolves handles; EdDSA is pure Ed25519 (no
    pre-hash or context). New keys default to sensitive and not
    extractable, the values PKCS#11 leaves to the token. Anything
    outside the mechanism table answers `CKR_MECHANISM_INVALID`;
    `unsupported_functions()` lists what the library (task 10) answers
    `CKR_FUNCTION_NOT_SUPPORTED`.

- [x] 5. Token and catalog state machines
  - `hsm_catalog_state_machine` (tokens, client bindings, wrapped TKs,
    unseal mode) and `token_state_machine` (objects, attributes, sealed
    material, scrypt PIN verifiers, login counters) on the persistent
    concept; leader-side generation with wrapped material in the entry
  - Plaintext-scan test over data directory, log and snapshots
  - _Requirements: 3.1-3.3, 7.1, 7.2, 7.4, 13.4_
  - Done: `catalog_state_machine.hpp`, `token_state_machine.hpp` (both
    on `persistent_group.hpp`, satisfying `persistent_state_machine`),
    `sealing.hpp` and `key_store.hpp`. TKs are sealed under the MK with
    the MK generation in the AD, so a rekey (one entry re-sealing every
    TK, refused unless it names every token) retires the old MK. Object
    material is sealed under the TK with token, handle and attribute
    digest as AD; `C_SetAttributeValue` re-seals on the leader. Handles
    are chosen by the leader (random, below 2^31) and versions guard
    every update and destroy; a taken handle or stale version is
    `CKR_FUNCTION_REJECTED`, meaning read again and retry. PIN checks
    run on the serving node and only the outcome is replicated, so
    failures count cluster-wide; locking reports the `CKF_*_PIN_*`
    flags. scrypt is N=2^15, r=8, p=1, stored per verifier. The
    plaintext scan covers every engine key and value, every command and
    both groups' checkpoint files, looking for the MK, TK, shares, PINs,
    each key's value and each private scalar; it uses the memory engine,
    which writes checkpoints uncompressed (a compressing engine could
    hide plaintext from a byte search). The scan over a real node's data
    directory and Raft log comes with the cluster tests of task 11.

- [ ] 6. HSM service module and session layer
  - `hsm_module` on the service module interface: groups on the node's
    multi-raft host, data directory, admin API (init, unseal, seal,
    status, tokens)
  - Session layer: logins, sessions, op state, read-index check before
    use, key cache by `(handle, version)`
  - `native_client` for co-located modules
  - _Requirements: 2.1-2.3, 3.4, 3.5, 7.3_
  - [x] 6a. Key vault, store interface, session layer and native client
    - Done: `key_vault.hpp` holds the MK (taken only when its check
      value is the catalog's) and the token keys opened with it, and
      remembers the MK generation; a key sealed under another
      generation does not open. `hsm_store.hpp` is the session layer's
      view of the replicated store (this replica's reads, proposals and
      a read-index barrier), so every PKCS#11 rule is tested on a store
      applied to directly. `session_layer.hpp` keeps applications
      (identity, logins per application and token), sessions, session
      objects and multi-part state on the node; a token the identity
      is not bound to answers `CKR_TOKEN_NOT_PRESENT` whether or not it
      exists. PINs are checked on the serving node and every outcome,
      success included, is proposed, so the lock is decided in log
      order. Each use of a token key runs a read-index round first and
      re-checks the object and its usage flag; opened keys are cached
      by handle, version and sealed bytes. Multi-part operations buffer
      input (bounded) and run the one-shot mechanism at the final call.
      A sealed node answers `CKR_DEVICE_ERROR` to every cryptographic
      call. `native_client.hpp` is one application in process.
      `key_store.hpp` gains `build_secret_key` / `build_key_pair` so
      session objects and token objects share one construction.
  - [x] 6b. `C_CreateObject`, `C_CopyObject`, `C_WrapKey`,
    `C_UnwrapKey` and `C_DeriveKey` in the session layer
    - Done: `object_import.hpp` builds the record and the material
      for each import path, so create, unwrap and derive share one set
      of checks. RSA private keys need every CRT component, EC private
      keys get their public point computed from the scalar, AES keys
      must be 16, 24 or 32 bytes. Data objects keep their value sealed
      like a key; certificates (X.509 only) keep it public. A copy
      keeps the material and may change only TOKEN, PRIVATE, LABEL,
      ID, MODIFIABLE, DESTROYABLE and the one-way SENSITIVE and
      EXTRACTABLE flags; `CKA_COPYABLE` false refuses it. Wrapping
      needs `CKA_WRAP` on the wrapping key and `CKA_EXTRACTABLE` on the
      target, and private keys wrap as PKCS#8. `CKM_HKDF_DATA` gives a
      data object, every other derivation a secret key.
  - [x] 6c. The group state machine and host on the node's multi-raft
    host, with proposals and read-index rounds forwarded from a follower
    to the group's leader
    - Done: `hsm_group_state_machine` opens the catalog on `c/` and
      token `t` on `t/<t>/` (decimal, so the namespaces are prefix-free)
      and vetoes every split. `hsm_host` implements `hsm_store`: the
      catalog is local group 0 and token `t` local group `t`, offset by
      the module's group base, and every member votes in every group.
      Members create a token's group once their catalog replica names
      it and destroy it once the catalog records the delete; the catalog
      now keeps a tombstone per deleted token and refuses to reuse its
      id, since multi_raft tombstones the group id. A member that does
      not lead a group forwards proposals and read-index rounds through
      a `forwarder` the module supplies; the leader answers its applied
      index and the member waits until it has applied as far, so a
      write through a follower is visible there when the call returns.
      A `not_leader` answer is retried (nothing was submitted); any
      other failure answers `CKR_DEVICE_ERROR`, since the entry may
      have committed. `C_Login` and `C_OpenSession` on a token this
      replica has not seen initialized now pass a read barrier first.
  - [x] 6d. Forwarding between members over the network, and the
    operator API
    - Done: `hsm_peer.hpp` carries `hsm_host`'s forwarder as
      `POST /v1/peer/propose/<group>` and `/v1/peer/read-index/<group>`
      on the module's listener. A proposal can change any token, so
      `serve_peer` answers only a verified certificate whose URI or DNS
      SAN is a member's, and refuses before the host is asked;
      `peer_client` presents this node's certificate, requires TLS 1.3
      and checks the leader's certificate against the members' CA and
      the host dialled. Every client failure answers `unavailable`, so
      the member never resends a proposal that may have committed.
      Plaintext works only when both sides ask for it (tests).
      `hsm_admin.hpp` is the operator API: status, and creating,
      deleting, binding and unbinding tokens; only the configured
      operator identities may call it. Init, unseal, seal and rekey stay
      with task 7.
  - [x] 6e. `hsm_module`: configuration, the listener, the network
    forwarder, the in-process interface for co-located modules, and the
    `kythira_node` registrar with the composite cluster test
    - Done: `cmd/hsm_node/hsm_config.hpp` reads `KYTHIRA_HSM_*`, falling
      back to the node's TLS files and plaintext switch (`composite_env`);
      the data directory is always the node's `hsm/`. The API URLs must
      name this node, operators and member identities may not overlap,
      and every refusal names its variable. `hsm_module` (number
      `module_numbers::hsm`) locks key memory in `configure`, registers
      the catalog and token groups on RocksDB with the network forwarder,
      publishes the session layer as `hsm.session_layer` for co-located
      modules, and serves the peer routes and then the operator API on one
      mTLS listener. Health stays up while sealed; the detail says
      `sealed` or `not initialized`. The module is built where RocksDB,
      the CA library and the Beast transport are, so `ci_dynamodb` has it
      and `ci_full` does not. `kythira_node_cluster_test` checks the
      status on every node, a non-operator's 403, a peer route refusing an
      operator's certificate and answering a member's. Checked by hand
      with three nodes: one catalog leader, a new one after killing it,
      and the `kythira_hsm_*` metrics.

- [ ] 7. Operator unseal, init, seal and rekey
  - `hsm_ctl init|unseal|seal|rekey|status`; partial shares in memory with
    timeout; rekey in one entry
  - _Requirements: 4.1, 4.3, 4.5-4.7_

- [ ] 8. Node unseal
  - Share sealing backends: key file, TPM 2.0, AWS KMS, Azure Key Vault,
    GCP KMS; peer share exchange over mTLS checked against catalog
    membership; stays sealed below `k`
  - _Requirements: 4.4, 4.8, 13.5_

- [ ] 9. Wire protocol and remote access
  - Framed protobuf protocol over TLS 1.3 with client certificates and
    over a Unix socket with `SO_PEERCRED` allow list; identity-to-token
    bindings; hidden tokens answer `CKR_TOKEN_NOT_PRESENT`
  - _Requirements: 2.4, 8.1-8.3_

- [ ] 10. `libkythira_pkcs11.so`
  - PKCS#11 v3.0 entry points, config file, static deps with a version
    script, OS locking, failover and re-login, slot and token info
  - `pkcs11test`, `pkcs11-tool`, OpenSSL `pkcs11-provider` (including a
    TLS handshake with a token key), p11-kit, Go and Java smoke tests in CI
  - _Requirements: 5.1-5.7, 13.2_

- [ ] 11. `hsm_node`, cluster tests and docker-chaos
  - Stand-alone daemon (`kythira_node` with only the HSM module), cluster
    tests with kills during generation and rekey
  - docker-chaos scenario stand-alone and co-located, Docker and rootless
    Podman, service-name addressing
  - _Requirements: 2.1, 2.5, 13.5, 13.6_

- [ ] 12. Consumer wrapper and external modules
  - Core `kythira::pkcs11::module` (dlopen or native client, RFC 7512 URI
    lookup); documented YubiHSM 2 / CloudHSM common subset; consumer tests
    against SoftHSM2; `hsm_ctl migrate`
  - _Requirements: 9.1-9.4_

- [ ] 13. Consumers
  - Cluster CA signing key on a token; Kinesis `pkcs11` key provider; IAM
    OIDC/STS signing keys on a token; each opt-in, defaults unchanged
  - _Requirements: 10.1-10.4_

- [ ] 14. Audit, metrics and IAM authorization
  - Audit log with optional ledger sink; metrics per 11.3; `hsm:` actions
    on token ARNs when IAM is present
  - _Requirements: 8.4, 11.1-11.3_

- [ ] 15. Documentation
  - `services/hsm/README.md` and `doc/hsm.md` opening with the threat model
    table; startup log line; operator guide for both unseal modes and for
    moving to an external module
  - _Requirements: 4.8, 12.1, 12.2_
