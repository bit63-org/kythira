# Implementation Plan

- [x] 1. Key ring and record cipher in core
  - `include/raft/raft_log_encryption.hpp`: `raft_log_key_source`,
    `raft_log_key_ring` (file format, unwrap once, rotate, prune, wipe),
    `raft_log_cipher` (HKDF per log, AES-256-GCM seal and open)
  - `tests/raft_log_encryption_unit_test.cpp`
  - _Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.4, 5.1_

- [x] 2. Sealed records and snapshot in `binary_file_persistence_engine`
  - Options `_key_ring` and `_encryption` (`seal`, `decrypt_only`); `log-id`
  - Flagged records, decryption in `read_locked`, fatal authentication
    failures, refusal without a key ring
  - Snapshot format version 2, version 1 still read
  - Engine tests re-run with a key ring, plus the no-plaintext scan
  - _Requirements: 1.1-1.6, 2.1, 2.2, 3.5, 4.1-4.3_

- [ ] 3. Migration both ways and rotation
  - `rewrite_records()`, crash-safe, with fault points at each step
  - `lowest_live_generation()` and key ring pruning
  - Tests: plaintext to sealed, sealed to plaintext (through
    `decrypt_only`), rotation then rewrite then prune, a crash at each
    rewrite step (done, `raft_log_encryption_unit_test`)
  - [ ] A three-node cluster with mixed modes through a leader change
    (with task 5, where a service node is the natural fixture)
  - _Requirements: 4.4-4.6, 5.1, 5.2_

- [x] 4. KMS adapter (needs the shared `kms_key_provider`, PR #837)
  - `include/raft/raft_log_kms.hpp`: `from_kms(key_provider, key_id, node)`
  - Tests with the local provider and a fake per-caller provider
  - _Requirements: 3.3_

- [ ] 5. Service node wiring
  - [x] `KYTHIRA_RAFT_LOG_KMS` / `KYTHIRA_RAFT_LOG_KMS_KEY_ID` read once
    per node; one key ring per data directory passed to every group's
    engine: DynamoDB, Kinesis, the KMS and the HSM
  - [x] `kythira` needs an endpoint (a KMS cannot seal its own log)
  - [x] Operator docs (`doc/kms.md`, "Raft logs at rest")
  - [ ] The ledger, IAM and Redis modules
  - _Requirements: 6.1_

- [x] 6. Chaos scan without the Raft-log exception
  - Turn on log encryption in `encrypted_services_in_kythira_node`'s
    layouts and remove its `is_raft_log` exception, failing on any value
  - _Requirements: 6.2_

- [ ] 7. Measure the overhead
  - Persistence benchmark rows with and without sealing; record the numbers
  - _Requirements: 6.3_
