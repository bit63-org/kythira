# Implementation Plan

Depends on `.kiro/specs/virtual-hsm/` tasks 1-6 (the HSM module, its
token store and native client) and `.kiro/specs/service-colocation/`
tasks 1-3 and 8 (the service module interface, `kythira_node`, and IAM on
the multi-raft host). Tasks 1-4 need neither and can start now. Each task
is one PR unless noted.

- [x] 1. Module skeleton and model
  - `KYTHIRA_KMS` Kconfig option (default off, depends on `KYTHIRA_HSM`
    and `KYTHIRA_IAM`), `services/kms/` layout, boundary check coverage
  - Pinned botocore `kms` model, generated operation and shape tables, a
    coverage check listing every operation as served or refused, as the
    DynamoDB and Kinesis modules do
  - Off-by-default build proved unchanged
  - _Requirements: 1.1-1.4, 3.1_
  - Done: Kconfig symbol `KMS` (the repo's symbols carry no `KYTHIRA_`
    prefix), botocore 1.43.100's model with 54 operations, all listed
    in `services/kms/doc/unsupported.md` until their task serves them;
    `kms_node` is a placeholder with `--self-test` until task 12.
    `DeriveSharedSecret` and `GetKeyLastUsage` are in the model but in
    no task: refused for now, an open question for the owner.
    `kms-module.yml` builds the module on and configures it off
    (`configs/ci_no_kms_defconfig`).

- [x] 2. `kms` action table and IAM condition keys
  - `kms_actions.hpp` with every action, the `key` and `alias` resource
    ARN formats and the condition keys of 7.4, generated from AWS's
    service authorization reference and pinned
  - IAM policy corpus cases for KMS: default key policy delegation, key
    policy without delegation, cross-account, `kms:ViaService`,
    `kms:EncryptionContext:*`, `kms:CallerAccount`
  - _Requirements: 7.3, 7.4, 7.6_
  - Done: `tools/gen_kms_actions.py` over the pinned reference (v1.5)
    makes `kms_actions.hpp`: 58 actions, the operation map (ReEncrypt
    checks ReEncryptFrom and ReEncryptTo) and the static roles of 7.7.
    30 cases in `services/iam/tests/corpus/evaluate/kms_key_policies.json`.
    Grant cases are the KMS's own (task 9): IAM's evaluator never sees a
    grant, because the KMS checks grants before asking IAM.

- [x] 3. Ciphertext format
  - `kms_ciphertext.hpp`: blob encoding, AAD canonicalization of the key
    ARN, backing version and encryption context; tamper, wrong context
    and wrong key tests; a fuzz target for the decoder
  - _Requirements: 5.2, 5.3, 14.1_
  - Done: the layout of design.md, big-endian, with the AAD prefixed by
    a `kythira-kms` domain tag and the blob version. The decoder takes
    only version 1, UUID key ids and blobs up to AWS's 6144 bytes. The
    "fuzz target" is a seeded mutation test (as DynamoDB's expression
    fuzz test is), so it runs in ctest and under the sanitizer legs.

- [x] 4. KMS catalog state machine
  - Keys, versions, aliases, policies, grants, tags, jobs; command format
    with a version byte; `Creating` and `PendingDeletion` states and
    tombstones; per-account key and alias limits
  - Property tests: replicas and snapshot restores agree; no key material
    can be represented in a command
  - _Requirements: 3.3-3.5, 6.1, 6.2, 8.1, 9.4, 13.4_
  - Done: `kms_catalog.hpp`. Jobs are not records of their own: the
    key's state, deletion time and next rotation time are the job, and
    the catalog answers `creating_keys()`, `due_deletions(now)` and
    `due_rotations(now)` for the leader. A rotation must name exactly the
    next version, which makes a retried rotation a no-op. The codec has
    no byte fields at all (integers and UTF-8 text), which is how "no key
    material can be represented in a command" holds by construction; the
    property test feeds random 32-byte keys to every text field.

- [x] 5. KMS service module and HSM binding
  - The module on the multi-raft host (module 7), `hsm.client` use for
    backing keys on the `kms` token, two-step key creation with the orphan
    sweep, the sealed-HSM error path
  - Plaintext scan test over the KMS group's log and snapshots
  - _Requirements: 2.1, 4.1-4.5_
  - 5a done: `kms_backing.hpp` (backing keys through core's
    `pkcs11::backend`) and `kms_keys.hpp` (two-step creation, sweep,
    rotation and deletion jobs), with the plaintext scan in
    `kms_keys_test`. Deviation: a key a dead leader left Creating with
    no backing key is destroyed, not made: its CreateKey already failed
    for the client, and making it would leave a second key behind a
    retried CreateKey.
  - 5b done: `kms_group_state_machine.hpp` and `kms_host.hpp` (the catalog
    as the module's one multi-raft group, with forwarding hooks), and
    `cmd/kms_node/kms_module.hpp` (module 7 in kythira_node: the token
    bound by label through `hsm.pkcs11` or a PKCS#11 library, PIN from
    `KYTHIRA_KMS_PIN_FILE`, the leader's jobs every
    `KYTHIRA_KMS_JOB_INTERVAL_MS`, health saying when the HSM is sealed
    or the token missing). Tests: `kms_host_test` (three members on the
    message fabric) and `kythira_node_kms_test` (the process over
    SoftHSM2). The design's `hsm.client` is core's `hsm.pkcs11`, which
    the HSM module publishes. Forwarding a follower's proposals over the
    network needs the API listener and arrives with it in task 12.

- [x] 6. Key management operations
  - `CreateKey`, `DescribeKey`, `ListKeys`, `EnableKey`, `DisableKey`,
    `UpdateKeyDescription`, `ScheduleKeyDeletion`, `CancelKeyDeletion`,
    aliases and tags, alias resolution everywhere AWS takes one
  - _Requirements: 3.1-3.6, 6.1-6.3_
  - Done: `kms_errors.hpp`, `kms_front_end.hpp` (framing, SigV4, the
    authorization guard) and `kms_api.hpp` (the fifteen operations over
    `api_deps`: the catalog replica, a read barrier, proposals and
    CreateKey's two steps), tested by `kms_api_test` through signed
    requests. The module serves them once task 12 adds the listener.

- [x] 7. Symmetric cryptographic operations
  - `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey`,
    `GenerateDataKeyWithoutPlaintext`, `GenerateRandom`; read-index
    serving on any replica
  - _Requirements: 5.1-5.3, 5.6_
  - Done: `kms_crypto_api.hpp` over `crypto_deps` (the catalog replica,
    a read-index barrier and the bound backing store), AES-GCM and
    random bytes in `backing_store`, and `generate_random` added to
    core's `pkcs11::backend` (C_GenerateRandom) so data keys, nonces and
    GenerateRandom come from the token. Tests: `kms_crypto_test`, and an
    AES-GCM case in `kms_backing_softhsm_test`. SoftHSM2 2.6 answers a
    failed tag with CKR_GENERAL_ERROR, so a decrypt failure on a session
    that still answers counts as a bad ciphertext. Asymmetric keys
    answer UnsupportedOperationException until task 8.

- [x] 8. Asymmetric and HMAC operations
  - RSA and ECC keys: `Encrypt`/`Decrypt` with RSA-OAEP, `Sign`/`Verify`
    (RAW and DIGEST), `GetPublicKey`, `GenerateDataKeyPair` and its
    without-plaintext form; HMAC keys: `GenerateMac`, `VerifyMac`
  - OpenSSL cross-checks of every signature and public key
  - _Requirements: 3.2, 5.1, 5.4, 5.5_
  - Done: `kms_signing_api.hpp`, RSA-OAEP and data key pairs in
    `kms_crypto_api.hpp`, `kms_public_key.hpp` (OpenSSL work on public
    keys), and signing, RSA decryption and public keys in
    `backing_store`. Tests: `kms_asymmetric_test` over the fake token's
    real key pairs, and a SoftHSM2 case for the mechanisms. What depends
    on the backing module: SoftHSM2 2.6 does RSA-OAEP with SHA-1 only,
    and the virtual HSM refuses SHA-224 and has no secp256k1, so on it
    `HMAC_SHA_224` MACs and `ECC_SECG_P256K1` keys answer
    UnsupportedOperationException.

- [x] 9. Key policies and authorization
  - `GetKeyPolicy`, `PutKeyPolicy`, `ListKeyPolicies`, default key policy,
    lockout safety check; every handler authorized through IAM with the
    key policy; static-roles mode with IAM off
  - _Requirements: 7.1-7.3, 7.5, 7.7_
  - Done: the three operations in `kms_api.hpp` (policy name `default`
    only; a marker past it ends `ListKeyPolicies`). The lockout check asks
    the authorizer for `kms:PutKeyPolicy` with the new policy in place,
    on `PutKeyPolicy` and on `CreateKey` with a caller-supplied policy,
    and refuses with `MalformedPolicyDocumentException` unless
    `BypassPolicyLockoutSafetyCheck` is true. Every handler already
    authorizes on the key ARN with the key policy as a `key` resource
    policy (task 6); choosing IAM or static keys is the composition
    root's (task 12). The static roles ignore key policies, as the README
    says. `kms_policy_test`.

- [x] 10. Grants
  - `CreateGrant`, `ListGrants`, `ListRetirableGrants`, `RetireGrant`,
    `RevokeGrant`; grant evaluation with encryption context constraints;
    grant tokens
  - _Requirements: 8.1-8.4_
  - Done: `kms_grants.hpp` (evaluation) and `kms_grants_api.hpp` (the
    five operations). A grant allows what IAM refused without an explicit
    deny, through `api_common::authorize_with_grants`, which every
    key-authorized handler now uses. Operations are checked per key type,
    constraints only on symmetric encryption keys, grants made under a
    grant may not widen it, `Name` makes CreateGrant idempotent, and
    RetireGrant is decided by the grant (retiring principal, grantee with
    RetireGrant, issuing account's root). Grants are in force once
    committed; tokens are checked but carry no authority. Grants on AWS
    managed keys carry `kms:GrantIsForAWSResource` true. With static keys
    `front_end_config::evaluate_grants` is off (Requirement 7.7), which
    the composition root sets in task 12. Root-principal grantees are not
    delegated through IAM (doc/unsupported.md). `kms_grants_test`.

- [x] 11. Rotation and deletion jobs
  - Scheduled and on-demand rotation, `ListKeyRotations`, deletion at the
    end of the window, idempotent across leader changes
  - _Requirements: 9.1-9.4_
  - Done: the five rotation operations in `kms_api.hpp` over the jobs of
    task 5 (symmetric keys only, AWS's ten on-demand rotations per key,
    disabled keys DisabledException, AWS managed keys refused).
    `key_jobs::run_once` no longer ends a pass when a scheduled rotation's
    proposal throws, so deletions and the orphan sweep still run.
    `kms_rotation_test`.

- [x] 12. `kms_node`, the published client and co-location
  - `kms_node` (KMS, HSM, IAM replica), `KYTHIRA_KMS_*` settings, the API
    listener; `kms.client` in-process and over HTTPS with forwarded
    principals and `KYTHIRA_KMS_TRUSTED_SERVICES`; `kms` in
    `KYTHIRA_SERVICES`
  - 12a: `kms_node`, the API listener with `KYTHIRA_KMS_AUTH`, and
    forwarding to the leader over mutual TLS (`kms_peer.hpp`,
    `kms_node_cluster_test`). 12b: `kms.client` (`kms_in_process.hpp`),
    core's `kms_https_endpoint` and `kms_forwarding.hpp`,
    `KYTHIRA_KMS_TRUSTED_SERVICES` (`kms_client_test`)
  - _Requirements: 2.2-2.5_

- [x] 13. AWS managed and owned keys
  - First-use creation of `alias/aws/<service>` per account with the
    `kms:ViaService` policy, yearly rotation, customer changes refused;
    owned keys per consumer and account
  - Done: managed keys (`kms_managed.hpp`, `kms_managed_test`). Owned
    keys (10.3) moved to task 16: DynamoDB's default table encryption is
    their only consumer, and the consumer's own principal they are
    authorized for only exists once a consumer calls `kms.client`
  - _Requirements: 10.1-10.2 (10.3 in task 16)_

- [x] 14. Audit, metrics and quotas
  - CloudTrail-shaped audit records through IAM's audit sink, Prometheus
    metrics, per-account request quotas with operator overrides
  - _Requirements: 13.1-13.3_
  - Done: audit records and metrics (`kms_audit.hpp`, `KYTHIRA_KMS_AUDIT`),
    on core's bounded audit log (`raft/audit_log.hpp`), the queue IAM's
    authorizer and the HSM write through; context keys only, never
    values. Quotas in `kms_quotas.hpp` (`KYTHIRA_KMS_THROTTLING`,
    `KYTHIRA_KMS_QUOTAS`, `KYTHIRA_KMS_ACCOUNT_QUOTAS`), key and alias
    limits by `KYTHIRA_KMS_ACCOUNT_LIMITS`, which the leader writes.

- [ ] 15. Kinesis integration
  - `kythira` `kms_key_provider` over `kms.client` with the caller's
    principal, the default when the KMS runs in the same deployment;
    provider tag on wrapped generations; `alias/aws/kinesis`
  - `StartStreamEncryption` and `StopStreamEncryption` resolving every
    `KeyId` form through the KMS; `kms:GenerateDataKey` for producers and
    `kms:Decrypt` for consumers authorized through IAM; disabled and
    rotated keys; error mapping
  - Integration tests co-located and stand-alone, including an IAM case
    where the key policy denies a role that the stream policy allows
  - _Requirements: 11.1-11.8, 14.4_

- [ ] 16. DynamoDB table keys and `SSESpecification` (two PRs)
  - `SSESpecification` on `CreateTable`, `UpdateTable` and restores;
    `SSEDescription`; table key made and re-wrapped through `kms.client`;
    owned key default with `KYTHIRA_DYNAMODB_ENCRYPT_AT_REST` (the KMS's
    owned keys, Requirement 10.3, moved here from task 13); catalog
    format bump
  - Item value sealing in the item state machine with derived, stored
    nonces; `INACCESSIBLE_ENCRYPTION_CREDENTIALS`; background
    re-encryption of existing tables; item format bump
  - The shared `kms_key_provider` library (moved from Kinesis) with the
    `kythira`, `aws` and `local` providers and `KYTHIRA_DYNAMODB_KMS`;
    provider tag on table keys
  - _Requirements: 12.1-12.7, 12.10-12.12_

- [ ] 17. DynamoDB archives and replicas
  - Sealing of change log records, backups, PITR archives and exports;
    `S3SseKmsKeyId` for Kythira stores and passed through for AWS buckets;
    `KMSMasterKeyId` per replica in `ReplicaUpdates`
  - Remove the matching lines from `services/dynamodb/doc/unsupported.md`
  - _Requirements: 12.3, 12.8, 12.9_

- [ ] 18. Client suites and differential fixtures
  - AWS CLI v2, boto3 and AWS Encryption SDK suites in CI against
    `kms_node`
  - Differential fixtures from real AWS KMS for request validation and
    errors (needs the maintainer's approval of the spend before
    recording; CI replays the fixtures)
  - _Requirements: 14.2, 14.3_

- [ ] 19. docker-chaos and plaintext scan
  - A scenario killing and partitioning KMS and HSM nodes under encrypted
    DynamoDB and Kinesis writes, on Docker and rootless Podman; no lost
    acknowledged writes; the plaintext scan over every data directory
  - _Requirements: 14.5_

- [ ] 20. Documentation
  - `doc/kms.md` (deployment in both layouts, the AWS CLI walkthrough,
    authorization, the honest limits), module README, updates to
    `doc/dynamodb.md` (what is visible on disk) and the Kinesis encryption
    doc
  - _Requirements: 1.2, 7.7, 12.3_
