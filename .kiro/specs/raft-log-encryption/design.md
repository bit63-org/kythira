# Design Document

## Overview

Seal Raft log records and the snapshot file inside
`binary_file_persistence_engine`, under data keys a per-node key ring holds and
the node's `kms_key_provider` wraps. Services keep proposing plaintext
commands; only the bytes on disk change.

## Components

| Component | File | Role |
|---|---|---|
| `raft_log_key_source` | `include/raft/raft_log_encryption.hpp` | Two callbacks: make a wrapped data key, unwrap one. No KMS dependency in core. |
| `raft_log_key_ring` | same | The node's generations: loads `raft-log-keys`, unwraps each once, adds generations, wipes keys on destruction. Shared by every engine on the node. |
| `raft_log_cipher` | same | Per-log AES-256-GCM: derives the log's key with HKDF-SHA256 from a generation's data key and the log's id; seals and opens payloads. |
| engine changes | `include/raft/binary_file_persistence.hpp` | `binary_file_persistence_options::_key_ring` and `_encryption` mode; sealed records and snapshot; `rewrite_records()`. |
| KMS adapter | `include/raft/raft_log_kms.hpp` | `kms_provider::key_provider` to `raft_log_key_source` (after the shared provider lands, `.kiro/specs/kms-compatible-api/` task 16). |
| service wiring | each `*_module.hpp` / `iam_raft.hpp` / `redis_serving.hpp` | Build one key ring at start from `KYTHIRA_RAFT_LOG_KMS` and pass it in every group's options. |

## On-disk format

### Log records

The record framing is unchanged:

```
u64 index, u64 term, u8 type, u32 len, bytes[len], u32 crc
```

A sealed record sets bit 7 of `type` (`entry_type` values are all below 0x80)
and its `bytes` are:

```
u32 generation, u8 nonce[12], ciphertext[len - 32], u8 tag[16]
```

The additional data is the 21-byte header as written (index, term, flagged
type, len) followed by the generation. The CRC still covers the whole record,
so a torn tail is cut on load exactly as before, without touching a key; an
authentication failure on a record with a good CRC is tampering or a wrong key
and is fatal.

The load path does not decrypt: it reads headers and checks CRCs as today, and
records the flag and generation with each entry's location. Decryption
happens in `read_locked`, the only place a command leaves the engine.

### Log identity

`log-id` beside `meta`: 16 random bytes, magic, version and CRC, written
atomically the first time an engine with a key ring opens the directory. The
log's key for generation `g` is
`HKDF-SHA256(ikm = data_key[g], salt = log_id, info = "kythira raft log v1")`.
Records copied into another group's directory fail to open, and so does a
whole directory copied to a node with another key ring. Derived keys are
cached per generation in the engine and wiped with it.

Random 96-bit nonces stay well inside GCM's bound (2^32 messages per key) for
any log, because each log has its own key per generation and rotation adds
generations.

### Snapshot

The snapshot file moves to format version 2 when sealed: after the header,
`u8 sealed`; if set, `u32 generation, nonce, ciphertext, tag` over everything
the plaintext version holds after the last-included index and term, with the
magic, version, index and term as additional data. Version 1 files still load.

### Key ring file

`DATA_DIR/raft-log-keys`, atomically replaced:

```
magic "KRLK", u32 version, u32 count,
{ u32 generation, str key_id, str wrapped }*, u32 crc
```

## Modes

| Mode | Writes | Reads sealed | Reads plaintext |
|---|---|---|---|
| no key ring | plaintext | refuses to load | yes |
| `seal` | sealed (newest generation) | yes | yes |
| `decrypt_only` | plaintext | yes | yes |

Turning encryption on is a restart with a key ring; old records stay plaintext
until compaction or `rewrite_records()`. Turning it off is a restart in
`decrypt_only`, then `rewrite_records()` (or compaction), then a restart with
no key ring. A node refuses to drop the key ring while a sealed record is
live, because the load fails.

`rewrite_records()` runs under the engine mutex and is crash-safe through a
`rewrite` marker file beside `meta`:

1. write the marker as `pending, from N` (N = the next segment number);
2. write every live record into new segments numbered N and up, under the
   current mode, and sync them and the directory;
3. replace the marker with `committed, from N`;
4. remove every segment below N, sync the directory, remove the marker.

A load that finds `pending` deletes segments N and up (the old run is whole);
one that finds `committed` deletes segments below N (the new run is whole and
synced). The snapshot is rewritten separately through `atomic_replace`.

## Rotation and pruning

`raft_log_key_ring::rotate()` wraps a new data key, appends the generation
and rewrites the file; engines pick it up for the next append. Each engine
reports the lowest generation any of its live records or its snapshot names;
the ring drops generations below the minimum across the node's engines when
asked (`prune(min_generation)`), never automatically at start.

## Key provider adapter

```cpp
raft_log_key_source from_kms(kms_provider::key_provider p, std::string key_id,
                             std::string node_name);
```

Encryption context `{kythira:purpose: raft-log, kythira:node: <name>}`. The
per-caller providers (Kythira's KMS) are called with an empty caller, as the
node's own principal; the KMS module's key policy must grant the node
`kms:GenerateDataKey` and `kms:Decrypt` on the log key.

A node whose own KMS runs inside it cannot use that KMS for its own Raft logs
(the KMS needs its log to answer). Such nodes use `aws`, a PKCS#11 token, or
`local`; the setting refuses `kythira` when the KMS module is co-located and
its catalog group would be sealed by itself.

## Testing

- Unit (`tests/raft_log_encryption_unit_test.cpp`): seal and open, every AAD
  field tampered, wrong log id, wrong generation, key ring round trip,
  rotation, wiping.
- Engine (`tests/binary_file_persistence_unit_test.cpp`): the existing cases
  re-run with a key ring; no command bytes in any file; torn sealed tail cut;
  bit flip in a sealed body with a fixed CRC is fatal; plaintext to sealed and
  back across reloads; `rewrite_records()` with a crash at each step (fault
  points); snapshot sealed and version 1 compatibility.
- Cluster: a three-node in-process cluster with one plaintext node, one
  sealed node and one decrypt-only node through a leader change.
- Service: `encrypted_services_in_kythira_node` scans every file and fails on
  any value.
