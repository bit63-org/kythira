// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The symmetric ciphertext blob and its additional authenticated data
// (.kiro/specs/kms-compatible-api/ design "Ciphertext blob", task 3,
// Requirement 5.2, 5.3).
//
// AWS's blob is undocumented and opaque, so the format is Kythira's own:
//
//   u8 version (1) | u8 key-id length | key id (UUID text)
//   | u32 backing version | 12-byte nonce | ciphertext | 16-byte tag
//
// Integers are big-endian. The blob names the key, so Decrypt needs no
// KeyId (5.3), and the backing version, so a rotated key still decrypts
// what its older versions made.
//
// The AES-GCM additional data binds what the blob alone does not prove:
//
//   "kythira-kms" | u8 version | u32 len | key ARN | u32 backing version
//   | u32 pair count | (u32 len | key | u32 len | value)...
//
// with the encryption context's pairs sorted by key, byte by byte, so the
// same context gives the same bytes whatever order the request listed it
// in. Every field is length-prefixed, so no two different contexts (or a
// context and an ARN) can encode alike. A change to the ciphertext, the
// tag, the context, the key or its version fails the tag check
// (InvalidCiphertextException). The HSM computes the tag
// (CKM_AES_GCM with this as pAAD); this file only lays out bytes, and
// holds no key material.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kms {

/// The blob version this file writes and the only one it reads.
inline constexpr std::uint8_t k_ciphertext_version = 1;
inline constexpr std::size_t k_gcm_nonce_size = 12;
inline constexpr std::size_t k_gcm_tag_size = 16;
/// AWS's limit on CiphertextBlob (the model's CiphertextType).
inline constexpr std::size_t k_max_ciphertext_blob = 6144;

/// An encryption context: string pairs, held sorted by key.
using encryption_context = std::map<std::string, std::string, std::less<>>;

struct ciphertext_blob {
    std::string key_id;  // a key's UUID, lower case
    std::uint32_t backing_version = 0;
    std::array<std::uint8_t, k_gcm_nonce_size> nonce{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, k_gcm_tag_size> tag{};

    auto operator==(const ciphertext_blob&) const -> bool = default;
};

namespace detail {

inline void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 24U));
    out.push_back(static_cast<std::uint8_t>(v >> 16U));
    out.push_back(static_cast<std::uint8_t>(v >> 8U));
    out.push_back(static_cast<std::uint8_t>(v));
}

inline void put_bytes(std::vector<std::uint8_t>& out, std::string_view s) {
    put_u32(out, static_cast<std::uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

[[nodiscard]] inline auto get_u32(std::span<const std::uint8_t> in, std::size_t at)
    -> std::uint32_t {
    return (std::uint32_t{in[at]} << 24U) | (std::uint32_t{in[at + 1]} << 16U) |
           (std::uint32_t{in[at + 2]} << 8U) | std::uint32_t{in[at + 3]};
}

}  // namespace detail

/// True for a key id the KMS makes: a UUID in lower-case hex,
/// 8-4-4-4-12.
[[nodiscard]] inline auto is_key_id(std::string_view id) -> bool {
    if (id.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < id.size(); ++i) {
        const char c = id[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') {
                return false;
            }
        } else if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
            return false;
        }
    }
    return true;
}

/// The blob's bytes. The caller keeps the blob within
/// k_max_ciphertext_blob (Encrypt's 4096-byte plaintext limit does).
[[nodiscard]] inline auto encode_ciphertext(const ciphertext_blob& b) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    out.reserve(2 + b.key_id.size() + 4 + k_gcm_nonce_size + b.ciphertext.size() + k_gcm_tag_size);
    out.push_back(k_ciphertext_version);
    out.push_back(static_cast<std::uint8_t>(b.key_id.size()));
    out.insert(out.end(), b.key_id.begin(), b.key_id.end());
    detail::put_u32(out, b.backing_version);
    out.insert(out.end(), b.nonce.begin(), b.nonce.end());
    out.insert(out.end(), b.ciphertext.begin(), b.ciphertext.end());
    out.insert(out.end(), b.tag.begin(), b.tag.end());
    return out;
}

/// The blob in `in`, or nullopt when it is not one this KMS made: another
/// version, a key id that is not a UUID, too short or too long. Decrypt
/// answers nullopt with InvalidCiphertextException, as it answers a bad
/// tag, so a caller learns nothing about which check failed.
[[nodiscard]] inline auto decode_ciphertext(std::span<const std::uint8_t> in)
    -> std::optional<ciphertext_blob> {
    if (in.size() < 2 || in.size() > k_max_ciphertext_blob || in[0] != k_ciphertext_version) {
        return std::nullopt;
    }
    const std::size_t id_len = in[1];
    const std::size_t fixed = 2 + id_len + 4 + k_gcm_nonce_size + k_gcm_tag_size;
    if (in.size() < fixed) {
        return std::nullopt;
    }
    ciphertext_blob b;
    b.key_id.assign(in.begin() + 2, in.begin() + static_cast<std::ptrdiff_t>(2 + id_len));
    if (!is_key_id(b.key_id)) {
        return std::nullopt;
    }
    std::size_t at = 2 + id_len;
    b.backing_version = detail::get_u32(in, at);
    at += 4;
    std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(at), k_gcm_nonce_size, b.nonce.begin());
    at += k_gcm_nonce_size;
    const std::size_t body = in.size() - fixed;
    b.ciphertext.assign(in.begin() + static_cast<std::ptrdiff_t>(at),
                        in.begin() + static_cast<std::ptrdiff_t>(at + body));
    at += body;
    std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(at), k_gcm_tag_size, b.tag.begin());
    return b;
}

/// The encryption context as length-prefixed pairs in key order.
[[nodiscard]] inline auto canonical_context(const encryption_context& context)
    -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    detail::put_u32(out, static_cast<std::uint32_t>(context.size()));
    for (const auto& [k, v] : context) {
        detail::put_bytes(out, k);
        detail::put_bytes(out, v);
    }
    return out;
}

/// The AES-GCM additional data for a blob of `key_arn`'s
/// `backing_version` under `context`.
[[nodiscard]] inline auto ciphertext_aad(std::string_view key_arn, std::uint32_t backing_version,
                                         const encryption_context& context)
    -> std::vector<std::uint8_t> {
    static constexpr std::string_view domain = "kythira-kms";
    std::vector<std::uint8_t> out(domain.begin(), domain.end());
    out.push_back(k_ciphertext_version);
    detail::put_bytes(out, key_arn);
    detail::put_u32(out, backing_version);
    const auto ctx = canonical_context(context);
    out.insert(out.end(), ctx.begin(), ctx.end());
    return out;
}

}  // namespace kythira::kms
