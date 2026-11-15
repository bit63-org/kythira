// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The values PKCS#11 calls return that are not plain handles or bytes,
// shared by the session layer, the native client and the wire client
// (task 9), so the wire client does not include the session layer.

#include <kythira/hsm/pkcs11.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

// What a PKCS#11 caller sees of the virtual HSM in CK_INFO, CK_SLOT_INFO
// and CK_TOKEN_INFO, the same through libkythira_pkcs11.so and the
// in-process backend (pkcs11_native_backend.hpp), so an RFC 7512 URI
// written for one matches the other.
inline constexpr CK_VERSION client_library_version{1, 0};
inline constexpr std::string_view client_manufacturer = "Kythira";
inline constexpr std::string_view client_library_description = "Kythira virtual HSM client";
// CK_TOKEN_INFO's model is 16 bytes: with the manufacturer "Kythira",
// "virtual HSM" says the token is software (requirement 5.7).
inline constexpr std::string_view client_token_model = "virtual HSM";

[[nodiscard]] inline auto client_slot_description(CK_SLOT_ID slot) -> std::string {
    return std::string(client_token_model) + " slot " + std::to_string(slot);
}

/// The token's serial number: its slot (token id) in 16 hex digits.
[[nodiscard]] inline auto client_token_serial(CK_SLOT_ID slot) -> std::string {
    std::array<char, 17> serial{};
    std::snprintf(serial.data(), serial.size(), "%016llx", static_cast<unsigned long long>(slot));
    return serial.data();
}

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
