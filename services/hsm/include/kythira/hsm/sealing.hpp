// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// How key material is stored (requirement 3.2, design "Two key layers under
// the master key"): every secret at rest is sealed with AES-256-GCM under
// the key one layer up, with a random 96-bit nonce and additional data that
// names exactly what the sealed value is.
//
//   MK (never stored) ── seals ──► TK per token, AD = token_key_ad(token, gen)
//   TK                ── seals ──► object material, AD = object_ad(token,
//                                   handle, attributes)
//
// Binding the token, the handle and a digest of the attributes into the AD
// means a sealed value copied to another object, another token or next to
// different attributes fails its tag instead of yielding a key with the
// wrong policy. A sealed value is: version (1) | nonce (12) | ciphertext |
// tag (16).
//
// PIN verifiers (requirement 7.1) are scrypt hashes; the PIN itself is
// never stored or logged.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/secret_bytes.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

inline constexpr std::size_t sealing_key_size = 32;
inline constexpr std::size_t seal_nonce_size = 12;
inline constexpr std::size_t seal_tag_size = 16;
inline constexpr std::uint8_t seal_version = 1;
/// Bytes a sealed value adds to its plaintext.
inline constexpr std::size_t seal_overhead = 1 + seal_nonce_size + seal_tag_size;

using sealed_bytes = std::vector<std::uint8_t>;

namespace detail {

struct gcm_ctx_free {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};

inline void append(std::vector<std::uint8_t>& out, std::string_view s) {
    out.insert(out.end(), s.begin(), s.end());
}

inline void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
    }
}

}  // namespace detail

/// AES-256-GCM under `key` with additional data `ad`. Throws only if
/// OpenSSL fails, which is not a caller error.
[[nodiscard]] inline auto seal(std::span<const std::uint8_t> key, std::span<const std::uint8_t> ad,
                               std::span<const std::uint8_t> plain) -> sealed_bytes {
    if (key.size() != sealing_key_size) {
        throw std::invalid_argument("seal: key must be 32 bytes");
    }
    sealed_bytes out(seal_overhead + plain.size());
    out[0] = seal_version;
    std::uint8_t* nonce = out.data() + 1;
    std::uint8_t* body = nonce + seal_nonce_size;
    std::uint8_t* tag = body + plain.size();
    std::unique_ptr<EVP_CIPHER_CTX, detail::gcm_ctx_free> ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    if (RAND_bytes(nonce, static_cast<int>(seal_nonce_size)) != 1 || !ctx ||
        EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), key.data(), nonce, nullptr) != 1 ||
        (!ad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, ad.data(),
                                          static_cast<int>(ad.size())) != 1) ||
        (!plain.empty() && EVP_EncryptUpdate(ctx.get(), body, &len, plain.data(),
                                             static_cast<int>(plain.size())) != 1) ||
        EVP_EncryptFinal_ex(ctx.get(), tag, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(seal_tag_size),
                            tag) != 1) {
        throw std::runtime_error("seal: AES-256-GCM failed");
    }
    return out;
}

/// The plaintext, or nothing when the version, length or tag is wrong
/// (wrong key, wrong additional data, or tampering).
[[nodiscard]] inline auto unseal(std::span<const std::uint8_t> key,
                                 std::span<const std::uint8_t> ad,
                                 std::span<const std::uint8_t> sealed)
    -> std::optional<secret_bytes> {
    if (key.size() != sealing_key_size || sealed.size() < seal_overhead ||
        sealed[0] != seal_version) {
        return std::nullopt;
    }
    const std::uint8_t* nonce = sealed.data() + 1;
    const std::uint8_t* body = nonce + seal_nonce_size;
    const std::size_t body_len = sealed.size() - seal_overhead;
    std::array<std::uint8_t, seal_tag_size> tag{};
    std::copy_n(body + body_len, seal_tag_size, tag.begin());
    secret_bytes out(body_len);
    std::unique_ptr<EVP_CIPHER_CTX, detail::gcm_ctx_free> ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    std::array<std::uint8_t, 16> scratch{};
    if (!ctx ||
        EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), key.data(), nonce, nullptr) != 1 ||
        (!ad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, ad.data(),
                                          static_cast<int>(ad.size())) != 1) ||
        (body_len != 0 &&
         EVP_DecryptUpdate(ctx.get(), out.data(), &len, body, static_cast<int>(body_len)) != 1) ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(seal_tag_size),
                            tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), scratch.data(), &len) != 1) {
        return std::nullopt;  // `out` is wiped by its destructor
    }
    return out;
}

/// Additional data for a token key sealed under the MK. `generation` is the
/// MK generation (bumped by rekey), so a TK sealed under a retired MK
/// generation cannot be replayed into the catalog after a rekey.
[[nodiscard]] inline auto token_key_ad(std::uint64_t token_id, std::uint32_t generation)
    -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> ad;
    detail::append(ad, "kythira-hsm token key v1");
    detail::append_u64(ad, token_id);
    detail::append_u64(ad, generation);
    return ad;
}

/// SHA-256 of an attribute map's canonical encoding.
[[nodiscard]] inline auto attributes_digest(const attribute_map& attrs)
    -> std::array<std::uint8_t, 32> {
    const auto bytes = attrs.encode();
    std::array<std::uint8_t, 32> out{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), out.data(), &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("attributes_digest: SHA-256 failed");
    }
    return out;
}

/// Additional data for an object's material sealed under its token's TK.
[[nodiscard]] inline auto object_ad(std::uint64_t token_id, std::uint64_t handle,
                                    const attribute_map& attrs) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> ad;
    detail::append(ad, "kythira-hsm object v1");
    detail::append_u64(ad, token_id);
    detail::append_u64(ad, handle);
    const auto digest = attributes_digest(attrs);
    ad.insert(ad.end(), digest.begin(), digest.end());
    return ad;
}

// --- PIN verifiers ----------------------------------------------------------

/// scrypt cost: N = 2^15, r = 8, p = 1 (32 MiB, tens of milliseconds), the
/// interactive-login parameters of the scrypt paper. Tests pass a lower
/// log2(N) to stay fast; the value is stored in the verifier.
inline constexpr std::uint8_t default_pin_log2_n = 15;

struct pin_verifier {
    std::uint8_t log2_n = default_pin_log2_n;
    std::uint32_t r = 8;
    std::uint32_t p = 1;
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 32> hash{};

    [[nodiscard]] auto encode() const -> std::vector<std::uint8_t> {
        byte_writer w;
        w.u8(1).u8(log2_n).u32(r).u32(p).bytes(salt).bytes(hash);
        auto raw = w.take();
        std::vector<std::uint8_t> out(raw.size());
        for (std::size_t i = 0; i < raw.size(); ++i) {
            out[i] = static_cast<std::uint8_t>(raw[i]);
        }
        return out;
    }

    [[nodiscard]] static auto decode(std::span<const std::uint8_t> in)
        -> std::optional<pin_verifier> {
        try {
            byte_reader rd(std::span(reinterpret_cast<const std::byte*>(in.data()), in.size()));
            if (rd.u8() != 1) {
                return std::nullopt;
            }
            pin_verifier v;
            v.log2_n = rd.u8();
            v.r = rd.u32();
            v.p = rd.u32();
            auto salt = rd.bytes();
            auto hash = rd.bytes();
            rd.finish();
            if (salt.size() != v.salt.size() || hash.size() != v.hash.size() || v.log2_n < 1 ||
                v.log2_n > 24 || v.r == 0 || v.r > 32 || v.p == 0 || v.p > 16) {
                return std::nullopt;
            }
            std::ranges::copy(salt, v.salt.begin());
            std::ranges::copy(hash, v.hash.begin());
            return v;
        } catch (const std::invalid_argument&) {
            return std::nullopt;
        }
    }
};

namespace detail {

[[nodiscard]] inline auto scrypt(std::string_view pin, const pin_verifier& params,
                                 std::span<std::uint8_t> out) -> bool {
    return EVP_PBE_scrypt(pin.data(), pin.size(), params.salt.data(), params.salt.size(),
                          std::uint64_t{1} << params.log2_n, params.r, params.p,
                          std::uint64_t{1} << 30U, out.data(), out.size()) == 1;
}

}  // namespace detail

/// A new verifier for `pin` with a random salt.
[[nodiscard]] inline auto make_pin_verifier(std::string_view pin,
                                            std::uint8_t log2_n = default_pin_log2_n)
    -> pin_verifier {
    pin_verifier v;
    v.log2_n = log2_n;
    if (RAND_bytes(v.salt.data(), static_cast<int>(v.salt.size())) != 1 ||
        !detail::scrypt(pin, v, v.hash)) {
        throw std::runtime_error("make_pin_verifier: scrypt failed");
    }
    return v;
}

/// True when `pin` matches, compared in constant time.
[[nodiscard]] inline auto check_pin(const pin_verifier& v, std::string_view pin) -> bool {
    std::array<std::uint8_t, 32> got{};
    if (!detail::scrypt(pin, v, got)) {
        return false;
    }
    const bool ok = CRYPTO_memcmp(got.data(), v.hash.data(), got.size()) == 0;
    OPENSSL_cleanse(got.data(), got.size());
    return ok;
}

}  // namespace kythira::hsm
