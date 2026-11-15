// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AES-256-GCM over OpenSSL for the ciphertext tests: what the HSM's
// CKM_AES_GCM does with the KMS's additional data, so the tests can show
// that the blob and its AAD detect tampering end to end.

#include <kythira/kms/kms_ciphertext.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace kythira::kms::test {

using aes_key = std::array<std::uint8_t, 32>;

inline auto random_key() -> aes_key {
    aes_key k{};
    if (RAND_bytes(k.data(), static_cast<int>(k.size())) != 1) {
        throw std::runtime_error("RAND_bytes");
    }
    return k;
}

/// Encrypts `plaintext` into a blob of `key_id` version `version`.
inline auto seal(const aes_key& key, std::string_view key_id, std::string_view key_arn,
                 std::uint32_t version, const encryption_context& context,
                 std::span<const std::uint8_t> plaintext) -> ciphertext_blob {
    ciphertext_blob b;
    b.key_id = std::string(key_id);
    b.backing_version = version;
    if (RAND_bytes(b.nonce.data(), static_cast<int>(b.nonce.size())) != 1) {
        throw std::runtime_error("RAND_bytes");
    }
    const auto aad = ciphertext_aad(key_arn, version, context);
    const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                              EVP_CIPHER_CTX_free);
    int len = 0;
    b.ciphertext.resize(plaintext.size());
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), b.nonce.data()) !=
            1 ||
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) !=
            1 ||
        EVP_EncryptUpdate(ctx.get(), b.ciphertext.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), nullptr, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(b.tag.size()),
                            b.tag.data()) != 1) {
        throw std::runtime_error("AES-GCM encrypt");
    }
    return b;
}

/// The plaintext, or nullopt when the tag does not check.
inline auto open(const aes_key& key, std::string_view key_arn, const encryption_context& context,
                 const ciphertext_blob& b) -> std::optional<std::vector<std::uint8_t>> {
    const auto aad = ciphertext_aad(key_arn, b.backing_version, context);
    const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                              EVP_CIPHER_CTX_free);
    std::vector<std::uint8_t> out(b.ciphertext.size());
    auto tag = b.tag;
    int len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), b.nonce.data()) !=
            1 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) !=
            1 ||
        EVP_DecryptUpdate(ctx.get(), out.data(), &len, b.ciphertext.data(),
                          static_cast<int>(b.ciphertext.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            tag.data()) != 1) {
        return std::nullopt;
    }
    if (EVP_DecryptFinal_ex(ctx.get(), nullptr, &len) != 1) {
        return std::nullopt;
    }
    return out;
}

}  // namespace kythira::kms::test
