# khold module

khold is Kythira's block server for antikythera network volumes. Each
volume is striped over Raft stripe groups. A `general` group holds two data
replicas and one log-only witness. khold speaks hold wire version 2 to
antikythera's oar-blk initiator and runs beside antikythera's hold per volume
class, with live moves both ways, until it reaches feature and testing
parity. After that, hold is retired. The spec is
`.kiro/specs/khold-block-service/`, and this directory follows
`services/README.md`.

The module is built when `CONFIG_KHOLD=y` (`services/khold/Kconfig`), which is
off by default. `configs/ci_full_defconfig` turns it on, so ci.yml's GCC legs
build and test it. `configs/ci_no_khold_defconfig` is the module-off
configuration that `.github/workflows/khold-module.yml` checks.

## Toolchain

The module includes antikythera's `src/proto/` headers, and those use
`std::expected`. libstdc++ provides `std::expected` with GCC 13 and newer,
and with Clang 19 and newer. Kythira's Clang 18 legs and clang-tidy run over
libstdc++ 13, which hides it from that compiler. On those legs the top-level
`CMakeLists.txt` checks that `std::expected` compiles, and when it does not,
it skips the module with a status line instead of failing a strict
configure. The missing piece there is the compiler, not a package vcpkg
could supply. As a result:

- khold-module.yml builds with g++-13;
- clang-tidy does not see this module until the clang legs move to Clang
  19 or newer.

## What is here

| Path | What | Task |
|---|---|---|
| `Kconfig` | `CONFIG_KHOLD` | 1 |
| `boundary-allow.txt` | core headers the module may include beyond the public surface (none) | 1 |
| `include/kythira/khold/khold_proto.hpp` | antikythera's wire formats (hold wire v1 and v2, `VolumeLayout`, reports) and the module-level helpers on top of them: telling a hold frame's version before decoding it, and classifying a stripe group's shape | 1 |
| `cmd/khold_node/` | the daemon. Until tasks 7 and 13 it is a placeholder whose `--self-test` round-trips a hold v2 frame and a `general` volume layout | 1 |
| `tests/khold_proto_vectors_test.cpp` | antikythera's test vectors reproduced byte for byte through the overlay port: replica config 4, volume layout 6, hold v2 frames 7 to 9, reports 10 and 11 | 1 |

The service module number is 12 (`include/raft/service_module.hpp`).

## antikythera's wire formats

The codecs belong to antikythera. kythira gets them through the
`vcpkg-overlays/antikythera-proto` overlay port, which installs
antikythera's `src/proto/` at a pinned commit, and links them as
`antikythera::proto`. A module file includes them exactly as antikythera
does, for example `#include "proto/volume_layout.hpp"`.

A change to a wire format lands in antikythera first, with new test vectors.
The kythira pull request then moves the port's `REF` and updates
`khold_proto_vectors_test` in the same change. If the pin moves without that
test change, the test fails.

## Core pieces used

| From core | Used for |
|---|---|
| `kythira_core_headers` | the public headers. Later this means the multi-raft host, the Raft append sink, witness voters and commit predicates (tasks 3 to 5) |
| `antikythera::proto` | the wire formats above |
| `OpenSSL::Crypto` | Ed25519 in the vectors test (verifying layout and replica config signatures) |
| `cmake/kythira_test_helpers.cmake` | `add_raft_completion_test`, `kythira_scale_test_timeouts()` |

## Tests

Every module test carries the labels `khold` and `khold-module`:

```
ctest --test-dir build -L '^khold$' --output-on-failure
```

The core suites the module builds on (tasks 3 to 5) carry `khold` without
`khold-module`, because they exist even with the module off.
