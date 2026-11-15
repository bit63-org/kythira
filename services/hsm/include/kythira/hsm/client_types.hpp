// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The values PKCS#11 calls return that are not plain handles or bytes,
// shared by the session layer, the native client and the wire client
// (task 9), so the wire client does not include the session layer.

#include <kythira/hsm/pkcs11.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kythira::hsm {

struct token_info {
    std::string label;
    CK_FLAGS flags = 0;
    CK_ULONG session_count = 0;
    CK_ULONG rw_session_count = 0;

    auto operator==(const token_info&) const -> bool = default;
};

struct session_info {
    CK_SLOT_ID slot = 0;
    CK_STATE state = CKS_RO_PUBLIC_SESSION;
    CK_FLAGS flags = 0;

    auto operator==(const session_info&) const -> bool = default;
};

/// One attribute of C_GetAttributeValue: its value, or why there is none
/// (CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID).
struct attribute_value {
    CK_ATTRIBUTE_TYPE type = 0;
    std::optional<std::vector<std::uint8_t>> value;
    CK_RV rv = CKR_OK;

    auto operator==(const attribute_value&) const -> bool = default;
};

}  // namespace kythira::hsm
