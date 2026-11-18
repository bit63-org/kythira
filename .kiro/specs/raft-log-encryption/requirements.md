# Requirements Document

## Introduction

Kythira's services seal their data before it reaches disk, but the Raft log
that carries each write does not. `binary_file_persistence_engine` (the
engine every service node uses for its Raft groups: DynamoDB, Kinesis, the
KMS, the HSM, IAM, the ledger and Redis) writes each entry's command into its
`log.<n>` segment exactly as it was proposed. Where a service encrypts at
apply time rather than before proposing, the log holds the plaintext until
compaction removes it. DynamoDB is that case: it seals a value when it applies
the write, because an `UpdateItem`'s result is known only then, so the log
entry that carries the write holds the value in the clear. The docker-chaos
scenario `encrypted_services_in_kythira_node` (`services/hsm/tests/docker/`)
therefore searches every file but DynamoDB's Raft logs for written values, and
only reports what it finds there. The snapshot file next to the log has the
same gap for any state machine whose snapshot carries values.

This spec closes the gap at the storage layer: the engine seals each record
and the snapshot under a data key the node's configured key provider wraps
(`kms_key_provider`: Kythira's KMS, AWS KMS, a PKCS#11 token, or the local
passphrase-sealed provider), so no service has to change how it proposes.

**Scope**: `binary_file_persistence_engine`'s segments and snapshot file, the
node's key ring for them, turning encryption on and off for an existing data
directory, rotating the key, and wiring it into the service nodes.

**Out of scope**: `file_persistence_engine` (JSON lines, used by `chaos_node`
and tests), the in-memory engine, the object-store persistence tiers (they
have their own bucket encryption), RocksDB state-machine files (each service
already decides what it seals there), and traffic on the wire (TLS covers it).

## Glossary

- **Data key**: a random 256-bit key, held in memory only, that seals records.
- **Key ring**: a node's data keys by generation, each stored on disk only
  wrapped by the key provider.
- **Generation**: the number of a data key in the key ring; a sealed record
  names the generation that sealed it.
- **Sealed record**: a log record or snapshot whose payload is AES-256-GCM
  ciphertext.

## Requirements

### Requirement 1: Sealed log records

**User Story:** As an operator, I want every Raft log record a node writes
sealed, so that a copy of its disk does not reveal what clients wrote.

#### Acceptance Criteria

1. WHEN an engine has a key ring, THE engine SHALL write every new log record's
   command as AES-256-GCM ciphertext under the newest data key, with a fresh
   random 96-bit nonce per record.
2. THE engine SHALL bind each sealed record's index, term, entry type and
   generation as additional authenticated data, so that a record moved to
   another index, term or log fails to open.
3. Each log SHALL seal under its own key, derived from the data key and a
   random identifier the log keeps beside its segments, so that records copied
   between groups or nodes fail to open.
4. THE record framing (length prefix and CRC-32) SHALL stay as it is, so that
   a torn tail is still found and cut by the CRC before any decryption.
5. A sealed record that fails authentication SHALL be a fatal
   `persistence_exception` naming the segment and offset, never a torn tail
   and never silently skipped.
6. Commands SHALL NOT be cached in memory in the clear beyond the read that
   asked for them (the engine keeps only locations in RAM today).

### Requirement 2: Sealed snapshot file

1. WHEN an engine has a key ring, THE engine SHALL seal the snapshot file's
   configuration and state bytes, binding the last included index and term.
2. THE snapshot SHALL be readable whether it was written sealed or not.

### Requirement 3: Key ring and key providers

**User Story:** As an operator, I want the log's keys under the same key
provider the rest of the node uses, so that one KMS key governs access.

#### Acceptance Criteria

1. THE key ring SHALL store each data key only wrapped, with the provider's
   key id, in one file per node, written atomically.
2. THE key ring SHALL unwrap every generation once at start, so a node makes
   one provider call per generation per start, not one per group or record.
3. THE key ring SHALL take any provider through a narrow interface (generate a
   wrapped key, unwrap one) that `kms_provider::key_provider` adapts to, with
   an encryption context naming the purpose (`kythira:purpose=raft-log`).
4. Plaintext data keys SHALL be wiped (`OPENSSL_cleanse`) when the key ring
   is destroyed.
5. WHEN the provider cannot unwrap a generation the log still needs, THE node
   SHALL refuse to start with a message naming the generation and key id,
   rather than start with a log it cannot read.

### Requirement 4: Migration in both directions

**User Story:** As an operator, I want to turn encryption on for an existing
cluster and off again, a node at a time, without losing the log.

#### Acceptance Criteria

1. Every record SHALL say whether it is sealed, so one log can hold both.
2. AN engine with a key ring SHALL read plaintext records written before it
   had one; AN engine in decrypt-only mode SHALL read sealed records and
   write plaintext ones.
3. AN engine with no key ring that meets a sealed record SHALL refuse to load
   with a message saying a key ring is needed.
4. THE engine SHALL offer a rewrite of its live records and snapshot under its
   current mode (seal, unseal, or re-seal under the newest generation), done
   segment by segment so that a crash leaves a loadable log.
5. Nodes with and without encryption SHALL replicate with each other: sealing
   is local to each node's disk and never changes what goes on the wire.
6. Tests SHALL cover plaintext to sealed, sealed to plaintext, and a mixed
   cluster through a leader change.

### Requirement 5: Key rotation

1. THE key ring SHALL add a generation on request; new records use it at once.
2. A generation SHALL be dropped from the key ring only once no live record
   or snapshot of any log on the node names it.

### Requirement 6: Service nodes

1. Every service node that uses `binary_file_persistence_engine` SHALL turn on
   log encryption from one setting (`KYTHIRA_RAFT_LOG_KMS`, the same
   `kythira|aws|local` choice as the services' own KMS setting, with a key id).
2. THE docker-chaos scan SHALL search DynamoDB's Raft logs like every other
   file once nodes seal their logs, and fail on any written value it finds.
3. THE overhead SHALL be measured: append throughput and p99 with and without
   sealing in the persistence benchmark.
