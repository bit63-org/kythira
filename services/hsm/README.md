# HSM module

A virtual HSM for Kythira: a software token that keeps its keys in Kythira
Raft groups, sealed under a master key split with Shamir's scheme, and serves
them through PKCS#11. Consumers (the CA, Kinesis, IAM, and anything that loads
a PKCS#11 module) see only the PKCS#11 interface, so moving them to a
YubiHSM 2 or CloudHSM is a configuration change. Keys are in host memory while
they are in use: this is not a hardware boundary, and the documentation says
so. The spec is `.kiro/specs/virtual-hsm/`; this directory follows
`services/README.md`.

Built when `CONFIG_HSM=y` (`services/hsm/Kconfig`, off by default, needs
OpenSSL 3). `configs/ci_full_defconfig` turns it on, so ci.yml builds and
tests it; `configs/ci_no_hsm_defconfig` is the module-off configuration
`.github/workflows/hsm-module.yml` checks.

## What is here

| Path | What | Task |
|---|---|---|
| `third_party/pkcs11/` | the OASIS PKCS#11 v3.0 headers, unchanged, with their licence and checksums (`third_party/pkcs11/README.md`) | 1 |
| `include/kythira/hsm/pkcs11.hpp` | the only way Kythira code includes PKCS#11: the five platform macros, then `pkcs11.h` | 1 |
| `include/kythira/hsm/shamir.hpp` | Shamir sharing over GF(2^8) (constant-time arithmetic, AES polynomial), the share format (version, `k`, `n`, index, check value, checksum) and its `khs1-` text form | 2 |
| `include/kythira/hsm/secret_bytes.hpp` | a move-only byte buffer in the secure arena, wiped on release, and `constant_time_equal` | 2, 3 |
| `include/kythira/hsm/secure_arena.hpp` | locked (`mlock`), `MADV_DONTDUMP` and `MADV_WIPEONFORK` key memory wiped on release; `harden_process()` (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`); `prepare_key_memory()`, where a lock failure is a startup error unless explicitly allowed | 3 |
| `include/kythira/hsm/attributes.hpp` | `attribute_map`: PKCS#11 attribute values as replicable bytes, with template attributes flattened | 4 |
| `include/kythira/hsm/mechanisms.hpp` | every key type and mechanism of requirement 6.1-6.2 on OpenSSL 3 EVP (AES-GCM/CBC-PAD/KW/KWP, SHA-2 and HMAC, RSA v1.5/PSS/OAEP, ECDSA on P-256/384/521, Ed25519, ECDH, HKDF), the mechanism table, and the exclusions of 6.5 | 4 |
| `include/kythira/hsm/attribute_policy.hpp` | the attribute rules of 6.3-6.4, one function each (table at the top of the file) | 4 |
| `include/kythira/hsm/sealing.hpp` | AES-256-GCM sealing with the binding additional data (MK over token keys, TK over objects: token, handle, attribute digest), and scrypt PIN verifiers | 5 |
| `include/kythira/hsm/catalog_state_machine.hpp` | the catalog group: tokens and their sealed keys, client bindings, MK check value and generation, unseal mode | 5 |
| `include/kythira/hsm/token_state_machine.hpp` | a token group: token record, PIN verifiers, replicated login counters, objects with sealed material and versions | 5 |
| `include/kythira/hsm/key_store.hpp` | the leader's side: generate or re-seal material and build the entry that carries it, sealed | 5 |
| `include/kythira/hsm/persistent_group.hpp`, `codec.hpp` | the engine plumbing both groups share, and the command and record encoding | 5 |
| `include/kythira/hsm/key_vault.hpp` | what an unsealed node holds: the MK (accepted only when its check value is the catalog's) and the token keys opened with it; `seal()` wipes both | 6 |
| `include/kythira/hsm/hsm_store.hpp` | the interface the session layer reads and proposes through: this replica's catalog and token groups, proposals, and the read-index barrier | 6 |
| `include/kythira/hsm/session_layer.hpp` | PKCS#11 applications, logins, sessions, session objects and multi-part operations on this node; a read-index round before every use of a token key; opened keys cached by handle and version | 6 |
| `include/kythira/hsm/native_client.hpp` | the in-process PKCS#11 client co-located modules use, authorized by the catalog's bindings like any other | 6 |
| `include/kythira/hsm/object_import.hpp` | builds objects from a `C_CreateObject` template, an unwrapped key or a derived value: RSA, EC and Ed25519 keys from their components, secret keys, data objects (value sealed) and X.509 certificates (value public) | 6 |
| `include/kythira/hsm/hsm_group_state_machine.hpp` | the one state machine type multi_raft builds for every HSM group: the catalog on `c/`, token `t` on `t/<t>/`; never splits | 6 |
| `include/kythira/hsm/hsm_host.hpp` | `hsm_store` on the node's multi-raft host: the catalog and every token group on every member, created and destroyed from the catalog; proposals and read-index rounds forwarded from a follower to the leader | 6 |
| `cmd/hsm_node/` | the daemon; a placeholder (`--help`, `--self-test [--allow-unlocked-memory]`, which also prepares key memory) until task 11 | 1, 3 |
| `tests/` | `hsm_pkcs11_headers_test` (the vendored headers' version, ABI types and 3.0 function table) and `hsm_node_self_test`; `hsm_shamir_test` (split and combine properties, encoding and every refusal); `hsm_secure_arena_test` (smaps flags, wiping, lock failures under a real zero `RLIMIT_MEMLOCK`, hardening); `hsm_mechanisms_test` (published vectors, round trips, tampering, exclusions); `hsm_attribute_policy_test` (one test per rule); `hsm_key_store_test` (both state machines, persistence, the no-plaintext scan); `hsm_session_layer_test` (the vault, bindings, session states, replicated PIN counters, read-index checks against a destroy or narrowing elsewhere, the key cache, sealing, multi-part operations); `hsm_object_import_test` (create, copy, wrap and unwrap rules, ECDH on both sides, the RFC 5869 HKDF vector); `hsm_host_test` (three members on the in-process fabric: groups on every member, forwarding, a destroy seen everywhere, a partitioned member answering `CKR_DEVICE_ERROR`, a leader change, deleted token ids); `hsm_test_node.hpp` and `hsm_test_store.hpp` are the shared fixtures | 1-6 |
| `pkcs11/` | `libkythira_pkcs11.so`, the PKCS#11 client library, as its own target (`pkcs11/README.md`) | 10 |

The service module and its admin API, unseal, the wire protocol, the client library,
consumers and audit follow in tasks 6 to 15 (`.kiro/specs/virtual-hsm/tasks.md`).

## Core targets and variables used

This is the list a split into its own repository would need a Kythira
package to export.

| From core | Used for |
|---|---|
| `kythira_core_headers` | `include/` and `generated/`, through `kythira_hsm` |
| `OpenSSL::Crypto` | every mechanism, through `kythira_hsm` |
| `kythira_test_pch` | the guard the tests are entered under, and what the C++ tests link |
| `cmake/kythira_test_helpers.cmake` | `add_raft_completion_test`, `kythira_scale_test_timeouts` |

## What a split would still need

Nothing beyond the table above yet. The module includes no core
`*_impl.hpp` header (`boundary-allow.txt` is empty) and no other module.
