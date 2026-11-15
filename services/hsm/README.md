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
| `include/kythira/hsm/secret_bytes.hpp` | a move-only byte buffer wiped with `OPENSSL_cleanse`, and `constant_time_equal` | 2 |
| `cmd/hsm_node/` | the daemon; a placeholder (`--help`, `--self-test`) until task 11 | 1 |
| `tests/` | `hsm_pkcs11_headers_test` (the vendored headers' version, ABI types and 3.0 function table) and `hsm_node_self_test`; `hsm_shamir_test` (split and combine properties, encoding and every refusal) | 1, 2 |
| `pkcs11/` | `libkythira_pkcs11.so`, the PKCS#11 client library, as its own target (`pkcs11/README.md`) | 10 |

Secure memory, mechanisms, the catalog and token state
machines, the service module, unseal, the wire protocol, the client library,
consumers and audit follow in tasks 3 to 15 (`.kiro/specs/virtual-hsm/tasks.md`).

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
