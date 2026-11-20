// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_chunk_cipher.hpp
/// @brief Sealing an encrypted object's chunks in the front end
///        (.kiro/specs/s3-compatible-storage/ task 11, Requirement 11.2).
///
/// An encrypted object's chunks are sealed with AES-256-GCM under the
/// object's data key before they leave the front end, so blob stores, the
/// network between nodes and the metadata layer only ever see ciphertext.
/// A sealed chunk is
///
///     12-byte nonce | ciphertext | 16-byte tag
///
/// and its name is the SHA-256 of those bytes, so a blob store checks it
/// like any other chunk. The manifest keeps each chunk's **plaintext**
/// size: an object's size, ranges and part sizes stay what the client
/// wrote, and the data path checks a sealed chunk is exactly
/// `overhead` bytes longer.
///
/// The nonce is derived, not random: the first 96 bits of
/// HMAC-SHA256(nonce key, plaintext). Equal plaintext under one data key
/// is then the same sealed chunk, so deduplication still works within a
/// key (and only within one, as 11.2 says), and two different chunks
/// under one key get different nonces unless HMAC-SHA256 collides in 96
/// bits. This is the synthetic-IV construction: what it reveals beyond
/// random nonces is that two chunks under one key are equal, which the
/// shared chunk name reveals anyway. The GCM key and the nonce key are
/// derived from the data key with HMAC-SHA256 under fixed labels, so the
/// data key itself is never used directly by either primitive.
///
/// The additional data is a fixed format label, so a chunk sealed by a
/// later format does not open as this one.

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::s3 {

/// AES-256-GCM over chunks under one object's data key.
class chunk_cipher {
public:
    static constexpr std::size_t key_bytes = 32;
    static constexpr std::size_t nonce_bytes = 12;
    static constexpr std::size_t tag_bytes = 16;
    /// How much longer a sealed chunk is than its plaintext.
    static constexpr std::size_t overhead = nonce_bytes + tag_bytes;

    /// @throws std::invalid_argument unless `data_key` is 32 bytes.
    explicit chunk_cipher(std::string_view data_key) {
        if (data_key.size() != key_bytes) {
            throw std::invalid_argument("s3 chunk cipher: a data key is 32 bytes");
        }
        derive(data_key, "kythira-s3 chunk encryption v1", _enc);
        derive(data_key, "kythira-s3 chunk nonce v1", _nonce);
    }

    chunk_cipher(const chunk_cipher&) = default;
    auto operator=(const chunk_cipher&) -> chunk_cipher& = default;
    chunk_cipher(chunk_cipher&&) = default;
    auto operator=(chunk_cipher&&) -> chunk_cipher& = default;
    ~chunk_cipher() {
        ::OPENSSL_cleanse(_enc.data(), _enc.size());
        ::OPENSSL_cleanse(_nonce.data(), _nonce.size());
    }

    /// The sealed form of `plain`: deterministic for one key and plaintext.
    [[nodiscard]] auto seal(std::span<const std::byte> plain) const -> std::vector<std::byte> {
        std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
        unsigned int mac_len = 0;
        if (::HMAC(::EVP_sha256(), _nonce.data(), static_cast<int>(_nonce.size()),
                   reinterpret_cast<const unsigned char*>(plain.data()), plain.size(), mac.data(),
                   &mac_len) == nullptr) {
            throw std::runtime_error("s3 chunk cipher: HMAC failed");
        }
        std::vector<std::byte> out(plain.size() + overhead);
        auto* o = reinterpret_cast<unsigned char*>(out.data());
        std::copy_n(mac.data(), nonce_bytes, o);
        const ctx c;
        int n = 0;
        if (::EVP_EncryptInit_ex(c.get(), ::EVP_aes_256_gcm(), nullptr, _enc.data(), o) != 1 ||
            ::EVP_EncryptUpdate(c.get(), nullptr, &n,
                                reinterpret_cast<const unsigned char*>(aad().data()),
                                static_cast<int>(aad().size())) != 1) {
            throw std::runtime_error("s3 chunk cipher: seal init failed");
        }
        if (!plain.empty() &&
            ::EVP_EncryptUpdate(c.get(), o + nonce_bytes, &n,
                                reinterpret_cast<const unsigned char*>(plain.data()),
                                static_cast<int>(plain.size())) != 1) {
            throw std::runtime_error("s3 chunk cipher: seal failed");
        }
        const int written = plain.empty() ? 0 : n;
        if (::EVP_EncryptFinal_ex(c.get(), o + nonce_bytes + written, &n) != 1 ||
            ::EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_bytes),
                                  o + nonce_bytes + plain.size()) != 1) {
            throw std::runtime_error("s3 chunk cipher: seal final failed");
        }
        return out;
    }

    /// The plaintext of a sealed chunk, or nothing when it does not open
    /// under this key (another key, truncated, or altered).
    [[nodiscard]] auto open(std::span<const std::byte> sealed) const
        -> std::optional<std::vector<std::byte>> {
        if (sealed.size() < overhead) {
            return std::nullopt;
        }
        const auto* s = reinterpret_cast<const unsigned char*>(sealed.data());
        const std::size_t len = sealed.size() - overhead;
        std::vector<std::byte> out(len);
        const ctx c;
        int n = 0;
        if (::EVP_DecryptInit_ex(c.get(), ::EVP_aes_256_gcm(), nullptr, _enc.data(), s) != 1 ||
            ::EVP_DecryptUpdate(c.get(), nullptr, &n,
                                reinterpret_cast<const unsigned char*>(aad().data()),
                                static_cast<int>(aad().size())) != 1) {
            return std::nullopt;
        }
        if (len > 0 && ::EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char*>(out.data()),
                                           &n, s + nonce_bytes, static_cast<int>(len)) != 1) {
            return std::nullopt;
        }
        std::array<unsigned char, tag_bytes> tag{};
        std::copy_n(s + nonce_bytes + len, tag_bytes, tag.data());
        if (::EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_bytes),
                                  tag.data()) != 1) {
            return std::nullopt;
        }
        std::array<unsigned char, 16> tail{};
        if (::EVP_DecryptFinal_ex(c.get(), tail.data(), &n) != 1) {
            return std::nullopt;
        }
        return out;
    }

private:
    struct free_ctx {
        void operator()(EVP_CIPHER_CTX* p) const noexcept { ::EVP_CIPHER_CTX_free(p); }
    };
    class ctx {
    public:
        ctx() : _p(::EVP_CIPHER_CTX_new()) {
            if (!_p) {
                throw std::runtime_error("s3 chunk cipher: no cipher context");
            }
        }
        [[nodiscard]] auto get() const -> EVP_CIPHER_CTX* { return _p.get(); }

    private:
        std::unique_ptr<EVP_CIPHER_CTX, free_ctx> _p;
    };

    [[nodiscard]] static auto aad() -> std::string_view { return "kythira-s3-chunk-v1"; }

    static void derive(std::string_view key, std::string_view label,
                       std::array<unsigned char, key_bytes>& out) {
        unsigned int len = 0;
        if (::HMAC(::EVP_sha256(), key.data(), static_cast<int>(key.size()),
                   reinterpret_cast<const unsigned char*>(label.data()), label.size(), out.data(),
                   &len) == nullptr ||
            len != key_bytes) {
            throw std::runtime_error("s3 chunk cipher: key derivation failed");
        }
    }

    std::array<unsigned char, key_bytes> _enc{};
    std::array<unsigned char, key_bytes> _nonce{};
};

}  // namespace kythira::s3
