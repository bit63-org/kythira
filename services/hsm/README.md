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
| `cmd/hsm_node/` | the daemon; a placeholder (`--help`, `--self-test [--allow-unlocked-memory]`, which also prepares key memory) until task 11 | 1, 3 |
| `tests/` | `hsm_pkcs11_headers_test` (the vendored headers' version, ABI types and 3.0 function table) and `hsm_node_self_test`; `hsm_shamir_test` (split and combine properties, encoding and every refusal); `hsm_secure_arena_test` (smaps flags, wiping, lock failures under a real zero `RLIMIT_MEMLOCK`, hardening); `hsm_mechanisms_test` (published vectors, round trips, tampering, exclusions); `hsm_attribute_policy_test` (one test per rule) | 1-4 |
| `pkcs11/` | `libkythira_pkcs11.so`, the PKCS#11 client library, as its own target (`pkcs11/README.md`) | 10 |

The catalog and token state
machines, the service module, unseal, the wire protocol, the client library,
consumers and audit follow in tasks 5 to 15 (`.kiro/specs/virtual-hsm/tasks.md`).

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
