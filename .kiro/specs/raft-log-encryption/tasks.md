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

- [x] 3. Migration both ways and rotation
  - `rewrite_records()`, crash-safe, with fault points at each step
  - `lowest_live_generation()` and key ring pruning
  - Tests: plaintext to sealed, sealed to plaintext (through
    `decrypt_only`), rotation then rewrite then prune, a crash at each
    rewrite step (done, `raft_log_encryption_unit_test`)
  - [x] A three-node cluster with mixed modes through a leader change
    (`raft_log_encryption_cluster_test`: plaintext, sealed and
    decrypt-only nodes through two leader changes that make a new leader
    ship entries from its own log; then one node rewritten in the clear
    offline and restarted with no key ring while another turns sealing on;
    a byte scan of each node's files after every phase. In-process hosts
    rather than service nodes: the property is the engine's and the wire's,
    and the service wiring is the same `raft_log_options_for` call each)
  - _Requirements: 4.4-4.6, 5.1, 5.2_

- [x] 4. KMS adapter (needs the shared `kms_key_provider`, PR #837)
  - `include/raft/raft_log_kms.hpp`: `from_kms(key_provider, key_id, node)`
  - Tests with the local provider and a fake per-caller provider
  - _Requirements: 3.3_

- [x] 5. Service node wiring
  - [x] `KYTHIRA_RAFT_LOG_KMS` / `KYTHIRA_RAFT_LOG_KMS_KEY_ID` read once
    per node; one key ring per data directory passed to every group's
    engine: DynamoDB, Kinesis, the KMS and the HSM
  - [x] `kythira` needs an endpoint (a KMS cannot seal its own log)
  - [x] Operator docs (`doc/kms.md`, "Raft logs at rest")
  - [x] The ledger, IAM and Redis modules (IAM through `iam_raft_config`,
    so the replica a Redis gateway embeds and `--convert-data-dir` seal
    too; Redis's disk and RocksDB layouts, not the in-memory cache)
  - _Requirements: 6.1_

- [x] 6. Chaos scan without the Raft-log exception
  - Turn on log encryption in `encrypted_services_in_kythira_node`'s
    layouts and remove its `is_raft_log` exception, failing on any value
  - _Requirements: 6.2_

- [x] 7. Measure the overhead
  - `tests/raft_log_encryption_bench.cpp`: appends each followed by their
    barrier, then reads, plain against sealed, per command size
  - Measured 2026-11-18 in a 4-vCPU cloud sandbox (OpenSSL 3.0, -O2,
    2000 appends per row, 200 at 256 KiB; two runs, the second shown):

    | command | appends/s plain | sealed | p99 us plain | sealed | reads/s plain | sealed |
    |---|---|---|---|---|---|---|
    | 64 B | 6648 | 6725 | 384 | 367 | 1 598 876 | 428 557 |
    | 1 KiB | 4987 | 5278 | 651 | 451 | 249 580 | 277 643 |
    | 16 KiB | 2935 | 2543 | 1192 | 1210 | 25 656 | 18 366 |

  - Appends: no measurable cost; the fsync per barrier dominates, and the
    run-to-run spread (about 15%) is larger than any difference. Reads of
    small entries: about 3-4x fewer per second, because each open builds
    an `EVP_CIPHER_CTX` (about 1.5 us). Still over 400 000 reads/s, far
    above what a Raft group reads back (catch-up and apply), so no context
    cache was added; add one per cipher if a profile ever shows it
  - _Requirements: 6.3_
