// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Envelope encryption under a key on a PKCS#11 token, in the common subset
// (raft/pkcs11_module.hpp; .kiro/specs/virtual-hsm/ task 13, Requirement
// 10.2): how a consumer protects a short secret, such as a stream's data
// key, with a token it may later swap for a YubiHSM 2 or CloudHSM.
//
// Neither of those offers AES-GCM or a standard AES key wrap to every
// caller, so the key on the token is an RSA key pair made for decryption.
// Sealing needs only its public half and runs in software; opening is one
// RSA-OAEP decryption on the token. What is encrypted is the secret
// followed by SHA-256 of a caller's binding (the key's name and the
// context it was made for), so a sealed secret opened under another
// binding is refused; OAEP is non-malleable, so the digest cannot be
// edited inside the ciphertext.
//
// A sealed secret is
//
//     "KP" | version 1 | OAEP hash (1 SHA-1, 2 SHA-256) | RSA-OAEP ciphertext
//
// The hash is recorded so a secret sealed for a module that takes only
// SHA-1 (SoftHSM2 2.6) still opens after a move to one that takes both.

#include <raft/pkcs11.hpp>
#include <raft/pkcs11_module.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace kythira::pkcs11 {

/// One decryption key pair on a token, for sealing short secrets.
class envelope_key {
public:
    /// `key` is the private half of an RSA pair made to decrypt (the
    /// public half is read from it); `oaep` the hash new seals use
    /// (SHA-256, or SHA-1 for SoftHSM2). `s` must outlive this.
    envelope_key(session& s, CK_OBJECT_HANDLE key, hash_algorithm oaep = hash_algorithm::sha256)
        : _session(&s), _key(key), _oaep(oaep) {
        if (oaep != hash_algorithm::sha1 && oaep != hash_algorithm::sha256) {
            throw error("envelope_key: OAEP with SHA-1 or SHA-256", CKR_MECHANISM_PARAM_INVALID);
        }
        const auto pub = s.public_key(key);
        if (pub.key_type != CKK_RSA) {
            throw error("envelope_key: the key is not RSA", CKR_KEY_TYPE_INCONSISTENT);
        }
        _public = rsa_public(pub);
        _modulus_bytes = pub.modulus.size();
        while (_modulus_bytes > 0 && pub.modulus[pub.modulus.size() - _modulus_bytes] == 0) {
            --_modulus_bytes;
        }
    }

    /// The longest secret this key seals.
    [[nodiscard]] auto max_secret() const noexcept -> std::size_t {
        const auto overhead = (2 * digest_length(_oaep)) + 2 + k_binding_len;
        return _modulus_bytes > overhead ? _modulus_bytes - overhead : 0;
    }

    /// Seals `secret` for `binding`, in software.
    [[nodiscard]] auto seal(std::span<const std::uint8_t> secret,
                            std::span<const std::uint8_t> binding) const -> bytes {
        if (secret.empty() || secret.size() > max_secret()) {
            throw error("envelope_key: the secret is empty or too long for the key",
                        CKR_DATA_LEN_RANGE);
        }
        bytes plain(secret.begin(), secret.end());
        const auto digest = sha256(binding);
        plain.insert(plain.end(), digest.begin(), digest.end());
        std::unique_ptr<EVP_PKEY_CTX, ctx_free> ctx(EVP_PKEY_CTX_new(_public.get(), nullptr));
        const EVP_MD* md = _oaep == hash_algorithm::sha1 ? EVP_sha1() : EVP_sha256();
        std::size_t n = 0;
        const bool ok = ctx && EVP_PKEY_encrypt_init(ctx.get()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) == 1 &&
                        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md) == 1 &&
                        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md) == 1 &&
                        EVP_PKEY_encrypt(ctx.get(), nullptr, &n, plain.data(), plain.size()) == 1;
        bytes out{'K', 'P', k_version, hash_byte(_oaep)};
        const auto header = out.size();
        out.resize(header + n);
        const bool sealed = ok && EVP_PKEY_encrypt(ctx.get(), out.data() + header, &n, plain.data(),
                                                   plain.size()) == 1;
        OPENSSL_cleanse(plain.data(), plain.size());
        if (!sealed) {
            throw error("envelope_key: RSA-OAEP encryption failed", CKR_FUNCTION_FAILED);
        }
        out.resize(header + n);
        return out;
    }

    /// Opens a sealed secret on the token. One sealed for another binding
    /// is CKR_ENCRYPTED_DATA_INVALID. One sealed for another key, or
    /// altered, fails the token's OAEP check: CKR_ENCRYPTED_DATA_INVALID
    /// on most modules, whatever the module answers otherwise (SoftHSM2:
    /// CKR_GENERAL_ERROR).
    [[nodiscard]] auto open(std::span<const std::uint8_t> sealed,
                            std::span<const std::uint8_t> binding) const -> bytes {
        if (sealed.size() <= 4 || sealed[0] != 'K' || sealed[1] != 'P' || sealed[2] != k_version ||
            (sealed[3] != hash_byte(hash_algorithm::sha1) &&
             sealed[3] != hash_byte(hash_algorithm::sha256))) {
            throw error("envelope_key: not a sealed secret", CKR_ENCRYPTED_DATA_INVALID);
        }
        const auto hash = sealed[3] == hash_byte(hash_algorithm::sha1) ? hash_algorithm::sha1
                                                                       : hash_algorithm::sha256;
        bytes plain;
        try {
            plain = _session->decrypt_oaep(_key, hash, sealed.subspan(4));
        } catch (const error& e) {
            // A ciphertext for another key fails OAEP's check on the token.
            if (e.rv() == CKR_ENCRYPTED_DATA_INVALID || e.rv() == CKR_ENCRYPTED_DATA_LEN_RANGE ||
                e.rv() == CKR_FUNCTION_FAILED) {
                throw error("envelope_key: the secret was not sealed for this key",
                            CKR_ENCRYPTED_DATA_INVALID);
            }
            throw;
        }
        const auto digest = sha256(binding);
        if (plain.size() <= k_binding_len ||
            CRYPTO_memcmp(plain.data() + plain.size() - k_binding_len, digest.data(),
                          k_binding_len) != 0) {
            OPENSSL_cleanse(plain.data(), plain.size());
            throw error("envelope_key: the secret was sealed for another binding",
                        CKR_ENCRYPTED_DATA_INVALID);
        }
        OPENSSL_cleanse(plain.data() + plain.size() - k_binding_len, k_binding_len);
        plain.resize(plain.size() - k_binding_len);
        return plain;
    }

private:
    static constexpr std::uint8_t k_version = 1;
    static constexpr std::size_t k_binding_len = 32;

    struct pkey_free {
        void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    };
    struct ctx_free {
        void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    };

    [[nodiscard]] static constexpr auto hash_byte(hash_algorithm h) noexcept -> std::uint8_t {
        return h == hash_algorithm::sha1 ? 1 : 2;
    }

    [[nodiscard]] static auto sha256(std::span<const std::uint8_t> in)
        -> std::array<std::uint8_t, k_binding_len> {
        std::array<std::uint8_t, k_binding_len> out{};
        unsigned n = 0;
        if (EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha256(), nullptr) != 1) {
            throw error("envelope_key: SHA-256 failed", CKR_FUNCTION_FAILED);
        }
        return out;
    }

    [[nodiscard]] static auto rsa_public(const public_key_info& k)
        -> std::unique_ptr<EVP_PKEY, pkey_free> {
        std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> bld(OSSL_PARAM_BLD_new(),
                                                                            &OSSL_PARAM_BLD_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> n(
            BN_bin2bn(k.modulus.data(), static_cast<int>(k.modulus.size()), nullptr), &BN_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> e(
            BN_bin2bn(k.public_exponent.data(), static_cast<int>(k.public_exponent.size()),
                      nullptr),
            &BN_free);
        if (!bld || !n || !e ||
            OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) != 1 ||
            OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) != 1) {
            throw error("envelope_key: bad RSA public key", CKR_KEY_TYPE_INCONSISTENT);
        }
        std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
            OSSL_PARAM_BLD_to_param(bld.get()), &OSSL_PARAM_free);
        std::unique_ptr<EVP_PKEY_CTX, ctx_free> ctx(
            EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
        EVP_PKEY* raw = nullptr;
        if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
            EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
            throw error("envelope_key: bad RSA public key", CKR_KEY_TYPE_INCONSISTENT);
        }
        return std::unique_ptr<EVP_PKEY, pkey_free>(raw);
    }

    session* _session;
    CK_OBJECT_HANDLE _key;
    hash_algorithm _oaep;
    std::unique_ptr<EVP_PKEY, pkey_free> _public;
    std::size_t _modulus_bytes = 0;
};

}  // namespace kythira::pkcs11
