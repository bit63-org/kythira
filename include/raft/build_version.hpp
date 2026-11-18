// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file build_version.hpp
/// The build's own version, for programs that report it (the Redis
/// gateway's `kythira_version`, .kiro/specs/redis-general-data-types/
/// Requirement 1.5). Defined in the generated
/// `<build>/generated/kythira_build_version.cpp` of the
/// `kythira_build_version` library, which cmake/kythira_build_version.cmake
/// rewrites at build time, only when the value changes, so a new commit
/// recompiles that one file and relinks; nothing else is rebuilt.

namespace kythira {

/// `<CMake project version>+<git describe --tags --always --dirty>`, for
/// example `0.1.0+a746630` or `0.1.0+nightly-20261118-a746630-3-g1b2c3d4-dirty`;
/// just the project version when the source tree is not a git checkout.
[[nodiscard]] auto build_version() noexcept -> const char*;

}  // namespace kythira
