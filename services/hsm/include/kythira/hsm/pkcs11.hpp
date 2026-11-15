// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PKCS#11 for the virtual HSM: the vendored OASIS v3.0 headers through
// core's <raft/pkcs11.hpp>, which defines the platform macros, so the
// module, libkythira_pkcs11.so and core's consumer wrapper see the same
// definitions.

#include <raft/pkcs11.hpp>

namespace kythira::hsm {

/// The Cryptoki version the vendored headers declare, which is the version
/// the module reports in CK_INFO and the 3.0 interface it implements.
inline constexpr CK_VERSION cryptoki_version{CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR};

}  // namespace kythira::hsm
