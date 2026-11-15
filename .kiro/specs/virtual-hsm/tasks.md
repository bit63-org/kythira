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
    the tasks that fill them (11 and 10). Task 12 moved the headers to the top-level
    `third_party/pkcs11/`, included through core's `<raft/pkcs11.hpp>`,
    since core's consumer wrapper needs them.

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
    hide plaintext from a byte search). The scan over real nodes' data
    directories and Raft logs is `hsm_node_cluster_test`'s
    `no_secret_reaches_a_data_directory` (task 11): three stopped
    `hsm_node` members after keys were used everywhere and the master
    key rekeyed, with a token label as the control that must be found.

- [x] 6. HSM service module and session layer
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

- [x] 7. Operator unseal, init, seal and rekey
  - `hsm_ctl init|unseal|seal|rekey|status`; partial shares in memory with
    timeout; rekey in one entry
  - _Requirements: 4.1, 4.3, 4.5-4.7_
  - Done: the operator API gains `POST /v1/init`, `POST|DELETE
    /v1/unseal`, `POST /v1/seal` and `POST /v1/rekey`, and `hsm_ctl` makes
    each one request with the operator's certificate. Init generates the
    MK, records its check value and answers the n shares once; no node is
    left unsealed. `operator_unseal` (`unseal.hpp`) checks each share on
    arrival (checksum, the catalog's k, n and check value, duplicates)
    after a catalog barrier, holds the set in memory only, and drops it
    once the first share is older than `KYTHIRA_HSM_UNSEAL_TIMEOUT_S`.
    Seal is a catalog entry bumping a seal epoch; the vault records the
    epoch and generation it unsealed under, and the module's warden seals
    a node whose catalog has moved past either (`key_vault::enforce`), so
    every node drops its keys within a maintenance pass. Rekey re-seals
    every token key and carries the new mode, k and n in one entry (the
    separate set-mode command is gone: a mode switch without a re-split
    would strand the shares, requirement 4.5); the rekeying node takes the
    new MK and the others seal. Init and rekey answer the shares even when
    the commit is uncertain (503), since dropping them could lose every
    key. k = 1 needs `KYTHIRA_HSM_ALLOW_SINGLE_SHARE`.
    `kythira_node_cluster_test` runs init, unseal on all three nodes, a
    token created through a follower and a cluster-wide seal; checked by
    hand with `hsm_ctl` on three nodes, including a rekey to 3 of 5.

- [ ] 8. Node unseal
  - Share sealing backends: key file, TPM 2.0, AWS KMS, Azure Key Vault,
    GCP KMS; peer share exchange over mTLS checked against catalog
    membership; stays sealed below `k`
  - _Requirements: 4.4, 4.8, 13.5_
  - [x] 8a. Node unseal with the key-file sealer and the peer exchange
    - Done: `node_unseal.hpp`. Init and rekey in node mode (n must be the
      member count) hand share i to the i-th member in id order, every
      delivery before the catalog entry is proposed, so a member that
      cannot take its share commits nothing; the operator sees no shares.
      Each member keeps its share in `shares/share-<check value>.sealed`,
      AES-256-GCM under a 32-byte key in an owner-only file (refused if
      group or others can read it), bound to the key's check value. A
      share is never overwritten, and older files are pruned only once the
      member unseals with a newer one, so a rekey's shares survive until
      it commits. A sealed member's warden (every 5 s at most, after a
      catalog barrier) asks the others over `POST /v1/peer/share-request`;
      peers answer a member's certificate only, sealed or not, and bad
      answers are skipped; with fewer than k shares it stays sealed. The
      README states what node mode trades (requirement 4.8). Checked by
      hand on three nodes: init in node mode unseals all three, and a
      member restarted with another down unseals from the third.
  - [ ] 8b. TPM 2.0 (`tpm2-tss`) and cloud KMS (AWS KMS, Azure Key Vault,
    GCP KMS through the existing cloud clients) share sealers behind
    `share_sealer`, chosen with `KYTHIRA_HSM_SHARE_SEALER`. Scheduled
    after the KMS-compatible API (`.kiro/specs/kms-compatible-api/`)
    makes `kms_key_provider` a shared library, so the cloud sealers
    reuse it rather than growing their own clients.

- [x] 9. Wire protocol and remote access
  - Framed protocol (the module's codec; design "Wire protocol" says why
    not protobuf) over TLS 1.3 with client certificates and over a Unix
    socket with an `SO_PEERCRED` allow list; identity-to-token bindings;
    hidden tokens answer `CKR_TOKEN_NOT_PRESENT`
  - `wire.hpp`, `wire_server.hpp`, `wire_client.hpp`; `hsm_wire_test`;
    every node's client listener in `kythira_node_cluster_test`
  - _Requirements: 2.4, 8.1-8.3_

- [x] 10. `libkythira_pkcs11.so`
  - [x] 10a. The library: PKCS#11 v3.0 entry points, config file, static
    deps with a version script, OS locking, failover and re-login, slot
    and token info; a dlopen test against wire servers
    (`hsm_pkcs11_library_test`)
  - [x] 10b. `pkcs11test`, `pkcs11-tool`, OpenSSL `pkcs11-provider`
    (including a TLS handshake with a token key), p11-kit, Go and Java
    smoke tests in CI
  - _Requirements: 5.1-5.7, 13.2_

- [x] 11. `hsm_node`, cluster tests and docker-chaos
  - [x] 11a. Stand-alone daemon (`kythira_node` with only the HSM module,
    in the module's group space and data directory), cluster tests with
    kills during generation and rekey (`hsm_node_cluster_test`, the
    cluster job of `hsm-module.yml`); the operator API applies a seal or
    rekey before answering, so no status reports a stale vault unsealed
  - [x] 11b. docker-chaos scenario stand-alone and co-located, Docker and
    rootless Podman, service-name addressing (`hsm_chaos_test`,
    `docker-hsm-chaos-tests`, the container job of `hsm-module.yml`):
    the token leader killed and partitioned during key generation, the
    catalog leader killed during rekeys, in `hsm_node` and in
    `kythira_node` beside Redis
  - _Requirements: 2.1, 2.5, 13.5, 13.6_

- [x] 12. Consumer wrapper and external modules
  - Core `kythira::pkcs11::module` (dlopen or native client, RFC 7512 URI
    lookup); documented YubiHSM 2 / CloudHSM common subset; consumer tests
    against SoftHSM2; `hsm_ctl migrate`
  - _Requirements: 9.1-9.4_
  - [x] 12a. The wrapper: `include/raft/pkcs11_uri.hpp` (RFC 7512 parse,
    text form without the PIN, pin-value and pin-source) and
    `include/raft/pkcs11_module.hpp` (a `backend` interface;
    `function_list_backend` dlopens any library; `session` offers only
    the common subset, `unrestricted()` the rest for operator tools);
    `pkcs11_native_backend.hpp` binds it in process, with CK_INFO and
    token strings shared with `libkythira_pkcs11.so` so one URI matches
    both. The common subset, checked against the YubiHSM 2 and CloudHSM
    SDK 5 documentation, turned out narrower than the design first said:
    no AES-GCM and no standard AES wrap (design.md corrected), so it is
    EC/RSA key pairs, digest signing (ECDSA, PKCS#1 v1.5, PSS) and
    RSA-OAEP decryption, with verification and encryption in software.
    Key generation states every usage attribute, because SoftHSM2 turns
    on the ones left out. SoftHSM2 2.6's OAEP takes SHA-1 only, so SHA-1
    is allowed for OAEP and refused for signing. Tests: `pkcs11_uri_test`
    (core) and `hsm_pkcs11_module_test` (one scenario in process, through
    the dlopen'd library and on SoftHSM2, which `hsm-module.yml` now
    installs).
  - [x] 12b. `hsm_ctl migrate --from URI --to URI` (`migrate.hpp`): the
    target makes (or names) an RSA transport key, its public half is
    imported into the source, a session AES-256 key goes across under
    RSA-OAEP (SHA-256, else SHA-1 for SoftHSM2), and every extractable
    key follows under RFC 5649 key wrap, landing sensitive and, unless
    `--keep-extractable`, not extractable; public halves and certificates
    are created as they are. Non-extractable keys are reported
    `needs_reissue`, data objects `skipped`, objects already on the
    target `exists` (so a failed run can be repeated), and `--dry-run`
    changes nothing. The target's RFC 5649 mechanism is
    `CKM_AES_KEY_WRAP_KWP` or, as SoftHSM2 names it,
    `CKM_AES_KEY_WRAP_PAD`; a target with neither (the YubiHSM 2, which
    has only its own AES-CCM wrap) is refused before anything moves, as
    is a source without KWP. `hsm_pkcs11_module_test` copies AES, EC and
    RSA keys and a certificate to SoftHSM2, checks the copies are the
    same keys and no longer extractable, repeats the run, and runs
    `hsm_ctl migrate` itself through `libkythira_pkcs11.so`.

- [x] 13. Consumers
  - Cluster CA signing key on a token; Kinesis `pkcs11` key provider; IAM
    OIDC/STS signing keys on a token; each opt-in, defaults unchanged
  - _Requirements: 10.1-10.4_
  - [x] 13a. Kinesis `KINESIS_KMS=pkcs11`: core
    `include/raft/pkcs11_envelope.hpp` seals a short secret for a binding
    under an RSA key pair on a token (OAEP over the secret and a SHA-256
    of the binding, sealing in software, opening on the token; the OAEP
    hash is recorded so SHA-1 seals made for SoftHSM2 still open);
    `kinesis_kms_pkcs11.hpp` is the provider, naming keys by label or by
    a `pkcs11:` URI on the configured token and binding the key id and
    encryption context, opening the module on first use and a new
    session once when the old one is gone. `KINESIS_KMS_PKCS11_URI`
    names the token; with `module-path` it loads that library, otherwise
    the co-located virtual HSM, which now publishes `hsm.pkcs11`
    (`service_node::pkcs11_provider`), serves it as the application
    `KINESIS_KMS_PKCS11_IDENTITY` (default `kinesis`), so bindings and
    the PIN apply exactly as for a network client. Tests:
    `kinesis_kms_pkcs11_test` (a software token) and the envelope cases
    of `hsm_pkcs11_module_test` (native, the .so and SoftHSM2).
  - [x] 13b. The cluster CA's root key on a token: core
    `certificate_authority::from_external` takes an `external_ca_key`
    (sign a SHA-256, or SHA-384 for P-384, digest) and signs every
    certificate and CRL through it, checking each signature against the
    CA certificate; `make_external_root` self-signs a root for a token
    key. OpenSSL has no setter for a CRL's inner AlgorithmIdentifier, so
    a throwaway local key of the same type signs first and its signature
    is replaced. `include/raft/pkcs11_signing_key.hpp` is a token signing
    key (EC P-256/P-384 or RSA PKCS#1 v1.5, reopening a lost session once)
    and its public key as PEM. `ca_cluster_node --ca-key-uri` (or
    `CA_CLUSTER_CA_KEY_URI`): the bootstrapping node makes the root on the
    token and the log records `pkcs11:` and the key's URI without library
    or PIN where the sealed key would be; a leader signs on the token, a
    node without the flag exits rather than lead, and a token that cannot
    sign yet is retried. Tests: `hsm_pkcs11_module_test` (the CA on every
    signing key type, native, the .so and SoftHSM2) and
    `hsm_ca_cluster_test` (three nodes on one SoftHSM2 token across a
    leader kill).
  - [x] 13c. The OIDC issuer's signing keys on a token, and the unseal
    passphrase sealed under one:
    `ca_cluster_node --oidc-key-uri` (or `CA_CLUSTER_OIDC_KEY_URI`) names
    a token; the leader makes each rotation's key pair there
    (`signing_key::generate`, RSA 2048 for RS256, P-256 for ES256,
    labelled `oidc-` and random hex) and records `pkcs11:` and its URI
    in place of the sealed key; the token endpoint signs records so
    marked through `signing_key` (`jose::sign_compact` and `mint_token`
    over a `digest_signer`) with the node's own library and PIN. Every
    signing key on one library shares a single load (`shared_module`),
    so no key finalizes the library under another's session. Tests:
    `hsm_pkcs11_module_test` (RS256 and ES256 on three backends) and
    `hsm_ca_cluster_test` (a token over mTLS verified under the JWKS,
    the key found on the token, nothing private in the data directory).
    IAM's STS keys are AES-256-GCM and the CA's peer enrollment key an
    HMAC key, outside the common subset, so the passphrase both derive
    from is protected instead: `hsm_ctl seal-secret` seals it with
    RSA-OAEP under a decryption key on a token
    (`include/raft/pkcs11_sealed_secret.hpp`; the file names the key,
    library and PIN file, never the PIN), and `ca_cluster_node`,
    `iam_node` and every embedded IAM replica open such an unseal key
    file on the token at startup; a plain file reads as before. The docs
    say so plainly: the token protects the passphrase at rest, the keys
    derived from it are in memory while the node runs. Tests: the
    `sealed_secret_file_on_softhsm2` case (the command, owner-only and
    never overwriting, tampering, no PIN in the file, plain files), and
    the OIDC cluster case starting its node from a sealed unseal file.

- [x] 14. Audit, metrics and IAM authorization
  - Audit log with optional ledger sink; metrics per 11.3; `hsm:` actions
    on token ARNs when IAM is present
  - _Requirements: 8.4, 11.1-11.3_
  - [x] 14a. The audit log and metrics: the session layer reports every
    login, PIN change, token initialization, object creation, attribute
    change, destruction and wrap as an `audit_event`
    (`include/kythira/hsm/audit.hpp`), counts signing, verification,
    encryption and decryption per client, token, key and operation and
    reports the first call and one in every `KYTHIRA_HSM_AUDIT_SAMPLE_EVERY`
    (1000) with the calls it stands for, and reports every refusal; the
    operator API reports every change and every refusal, and the module
    the vault sealing and a node unseal. Events name who, the token, the
    object's handle and label, the mechanism and the result, never a key,
    PIN, share or data. `cmd/hsm_node/hsm_audit.hpp` formats each as one
    JSON line (`audit_json.hpp`) and queues it on the bounded
    `kythira::audit_log` (moved from IAM to `include/raft/audit_log.hpp`,
    which now also hands batches and appends a dropped-lines record) for
    stderr, `file:PATH` or `off` (`KYTHIRA_HSM_AUDIT`), and, with
    `KYTHIRA_HSM_AUDIT_LEDGER_URL`, a verifiable ledger
    (`audit_ledger.hpp`: one transaction per batch, one document per line,
    the table made on first use, lines kept while the ledger is down and a
    `ledger_dropped` document recording any gap). Every event, sampled or
    not, feeds the metrics: operations by action, mechanism and result,
    latency, failed logins, refusals for a locked PIN, audit lines
    dropped and ledger lines pending, beside the host's replica lag and
    read-index wait. Tests: `hsm_audit_test`, and audit cases in
    `hsm_session_layer_test` and `hsm_admin_test`.
  - [x] 14b. `hsm:` actions on token ARNs: with `KYTHIRA_HSM_IAM=true`
    and IAM co-located, a client whose identity (its certificate's first
    URI SAN) is an IAM user or role ARN is authorized by IAM's policies
    instead of by the bindings (`include/kythira/hsm/hsm_iam.hpp`): the
    module registers the `hsm` action table with the IAM module's
    evaluator, and the session layer asks `hsm:OpenToken` to list or open
    a token and one action per call that makes, changes, destroys or uses
    a key (`hsm:GenerateKey`, `hsm:Sign`, `hsm:Decrypt`, ...), on
    `arn:<partition>:hsm:<region>:<account>:token/<id>` in the principal's
    account, refusing with `CKR_ACTION_PROHIBITED`. A role ARN acts as a
    session of the role, a user ARN as the user; every other identity
    keeps its bindings, and the PIN is still required. Decisions are kept
    for `KYTHIRA_HSM_IAM_CACHE_MS` (10 s). A stand-alone `hsm_node` has no
    IAM to ask and refuses the setting. Tests: `hsm_iam_test` (which ARNs
    are principals, the action table, the request, the cache), a session
    layer case (an authorizer deciding call by call over the bindings),
    and `kythira_node_cluster_test` (a client named by an IAM role sees a
    token only once a role policy grants `hsm:OpenToken` on its ARN).

- [x] 15. Documentation
  - `services/hsm/README.md` and `doc/hsm.md` opening with the threat model
    table; startup log line; operator guide for both unseal modes and for
    moving to an external module
  - _Requirements: 4.8, 12.1, 12.2_
  - Done: both open with the same table (stolen disks, backups and
    snapshots, a lost node, consumers that should not read keys, PIN
    guessing, silent changes; against root on a serving host, a
    hypervisor, memory dumps, side channels, a compromised co-located
    service, a member's certificate in node mode). `doc/hsm.md` is the
    operator guide: running a cluster, choosing an unseal mode (with the
    Requirement 4.8 statement), operator and node unseal step by step,
    sealing and rekeying, tokens, bindings and PINs, audit, backups and
    which share set they need, and moving consumers and keys to an
    external module. Every node logs a warning at start that it is a
    software HSM with keys in host memory; `hsm_node_cluster_test`
    checks each member's log for it.
