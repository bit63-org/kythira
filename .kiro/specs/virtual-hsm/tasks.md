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
