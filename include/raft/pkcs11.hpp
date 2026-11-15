// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The OASIS PKCS#11 v3.0 headers (third_party/pkcs11/, vendored unchanged),
// with the five platform macros the specification requires the includer to
// define before pkcs11.h. Every Kythira file includes PKCS#11 through this
// header, never pkcs11.h directly, so the definitions are the same in core
// (the consumer wrapper, raft/pkcs11_module.hpp), the virtual HSM module
// and libkythira_pkcs11.so.
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
