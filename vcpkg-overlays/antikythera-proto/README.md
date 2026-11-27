# antikythera-proto overlay port

Antikythera's header-only wire formats, from
[bit63-org/antikythera](https://github.com/bit63-org/antikythera) at a pinned
commit, exported as `antikythera::proto`. kythira's khold module
(`services/khold/`, `.kiro/specs/khold-block-service/` Requirement 1.4)
consumes it for hold wire versions 1 and 2, the signed `VolumeLayout`, the
reports and the signing test vectors; the EC2 module
(`.kiro/specs/ec2-compatible-api/` task 1) is meant to use the same port.

## What it installs

- `include/antikythera/proto/*.hpp`: every header of antikythera's
  `src/proto/`.
- `include/antikythera/common/{wire,crc32c}.hpp`: the two helpers those
  headers include.
- `share/antikythera-proto/antikythera-proto-config.cmake`: the
  `antikythera::proto` interface target, whose include directory is
  `include/antikythera`, so a consumer writes `#include "proto/volume_layout.hpp"`
  exactly as antikythera does.

Nothing is compiled. The headers depend only on the standard library (and
`<nmmintrin.h>` on x86, for the SSE4.2 CRC32C path, which they enable per
function with `target("sse4.2")`).

## Why a port and not a copy

The codecs are antikythera's: its CI fuzzes them and its roles speak them.
A copy in kythira would drift. A pinned port keeps one source of truth, and
kythira's khold tests reproduce antikythera's test vectors
(`proto/test_vectors.hpp`) byte for byte, so a pin that changes a wire
format without a matching kythira change fails in kythira's CI.

It is a default dependency in `vcpkg.json` rather than a feature: it
installs in seconds, and a default dependency is in every cached
`vcpkg_installed` tree.

## Toolchain

The headers use `std::expected`, which libstdc++ provides only when the
compiler reports `__cpp_concepts >= 202002L`: GCC 13 and newer, Clang 19 and
newer. Clang 18 over libstdc++ 13, which kythira's clang legs and
clang-tidy use, does not. The top-level `CMakeLists.txt` probes for it and
builds khold only where it compiles; see `services/khold/README.md`.

## Moving the pin

Change `REF` in `portfile.cmake` to a commit on antikythera's `main` (the
full 40-character id) and run khold's tests
(`ctest -L khold-module`). A wire change in antikythera needs the matching
khold change in the same kythira pull request. The licence is
antikythera's Apache-2.0, installed as the port's copyright file.
