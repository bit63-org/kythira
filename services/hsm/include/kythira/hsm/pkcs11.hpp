// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The OASIS PKCS#11 v3.0 headers (services/hsm/third_party/pkcs11/, vendored
// unchanged), with the five platform macros the specification requires the
// includer to define before pkcs11.h. Every Kythira file includes PKCS#11
// through this header, never pkcs11.h directly, so the definitions are the
// same in libkythira_pkcs11.so, the HSM module and its consumers.
//
// The values are the ones the specification gives for a Unix-like platform
// (pkcs11.h, "Before including this file"): plain pointers, functions with
// default visibility and calling convention. The function-pointer macros
// expand inside declarations, where a parenthesised return type would not
// parse, hence the bugprone-macro-parentheses suppressions.

#ifndef CK_PTR
#define CK_PTR *
#endif

#ifndef CK_DECLARE_FUNCTION
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
// NOLINTNEXTLINE(bugprone-macro-parentheses): expands in a declaration
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#endif

#ifndef CK_CALLBACK_FUNCTION
// NOLINTNEXTLINE(bugprone-macro-parentheses): expands in a declaration
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#endif

#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include <pkcs11.h>

namespace kythira::hsm {

/// The Cryptoki version the vendored headers declare, which is the version
/// the module reports in CK_INFO and the 3.0 interface it implements.
inline constexpr CK_VERSION cryptoki_version{CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR};

}  // namespace kythira::hsm
