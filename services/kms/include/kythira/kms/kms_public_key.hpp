// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Public-key work that needs no secret (.kiro/specs/kms-compatible-api/
// task 8, Requirements 5.4 and 5.5), over OpenSSL 3: building a
// SubjectPublicKeyInfo from a token's public key attributes, hashing a
// message, DER-encoding an ECDSA signature the token returned as r || s,
// verifying a signature and RSA-OAEP encryption against a public key, and
// making a data key pair for GenerateDataKeyPair.
//
// Private keys and HMAC keys stay on the token: signing, MACs and RSA
// decryption happen there (kms_backing.hpp). Verification and RSA
// encryption use only the public key, which AWS also hands to anyone who
// may call GetPublicKey, so doing them here changes no trust boundary. A
// data key pair's private key is generated here, as plaintext the caller
// receives anyway, and sealed under a symmetric KMS key on the token.

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

namespace kythira::kms {

using der_bytes = std::vector<std::uint8_t>;

/// A hash function AWS names in an algorithm.
enum class hash_alg : std::uint8_t {
    sha1,
    sha256,
    sha384,
    sha512
};

[[nodiscard]] constexpr auto hash_size(hash_alg h) -> std::size_t {
    switch (h) {
        case hash_alg::sha1:
            return 20;
        case hash_alg::sha256:
            return 32;
        case hash_alg::sha384:
            return 48;
        case hash_alg::sha512:
            return 64;
    }
    return 0;
}

namespace public_key_detail {

struct pkey_free {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct pkey_ctx_free {
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct bld_free {
    void operator()(OSSL_PARAM_BLD* p) const { OSSL_PARAM_BLD_free(p); }
};
struct params_free {
    void operator()(OSSL_PARAM* p) const { OSSL_PARAM_free(p); }
};
struct bn_free {
    void operator()(BIGNUM* p) const { BN_free(p); }
};
struct sig_free {
    void operator()(ECDSA_SIG* p) const { ECDSA_SIG_free(p); }
};
struct octets_free {
    void operator()(ASN1_OCTET_STRING* p) const { ASN1_OCTET_STRING_free(p); }
};

using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free>;

[[nodiscard]] inline auto md_of(hash_alg h) -> const EVP_MD* {
    switch (h) {
        case hash_alg::sha1:
            return EVP_sha1();
        case hash_alg::sha256:
            return EVP_sha256();
        case hash_alg::sha384:
            return EVP_sha384();
        case hash_alg::sha512:
            return EVP_sha512();
    }
    return nullptr;
}

[[nodiscard]] inline auto spki_of(EVP_PKEY* k) -> der_bytes {
    const int n = i2d_PUBKEY(k, nullptr);
    if (n <= 0) {
        throw std::runtime_error("kms: cannot encode a public key");
    }
    der_bytes out(static_cast<std::size_t>(n));
    unsigned char* p = out.data();
    i2d_PUBKEY(k, &p);
    return out;
}

[[nodiscard]] inline auto from_params(const char* type, OSSL_PARAM_BLD* bld) -> pkey_ptr {
    const std::unique_ptr<OSSL_PARAM, params_free> params(OSSL_PARAM_BLD_to_param(bld));
    const pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    EVP_PKEY* k = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &k, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        return nullptr;
    }
    return pkey_ptr(k);
}

[[nodiscard]] inline auto parse_spki(std::span<const std::uint8_t> spki) -> pkey_ptr {
    const unsigned char* p = spki.data();
    return pkey_ptr(d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size())));
}

}  // namespace public_key_detail

/// The OpenSSL group name for a DER-encoded curve OID (CKA_EC_PARAMS), or
/// empty for a curve the KMS does not use.
[[nodiscard]] inline auto curve_name(std::span<const std::uint8_t> oid) -> std::string_view {
    static constexpr std::array<std::uint8_t, 10> p256{0x06, 0x08, 0x2A, 0x86, 0x48,
                                                       0xCE, 0x3D, 0x03, 0x01, 0x07};
    static constexpr std::array<std::uint8_t, 7> p384{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    static constexpr std::array<std::uint8_t, 7> p521{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
    static constexpr std::array<std::uint8_t, 7> k1{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
    const auto is = [&](std::span<const std::uint8_t> want) {
        return oid.size() == want.size() && std::equal(oid.begin(), oid.end(), want.begin());
    };
    if (is(p256)) {
        return "prime256v1";
    }
    if (is(p384)) {
        return "secp384r1";
    }
    if (is(p521)) {
        return "secp521r1";
    }
    if (is(k1)) {
        return "secp256k1";
    }
    return {};
}

/// The SubjectPublicKeyInfo of an RSA public key (CKA_MODULUS,
/// CKA_PUBLIC_EXPONENT, big-endian).
[[nodiscard]] inline auto rsa_spki(std::span<const std::uint8_t> modulus,
                                   std::span<const std::uint8_t> exponent) -> der_bytes {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    const std::unique_ptr<BIGNUM, bn_free> n(
        BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr));
    const std::unique_ptr<BIGNUM, bn_free> e(
        BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr));
    const std::unique_ptr<OSSL_PARAM_BLD, bld_free> bld(OSSL_PARAM_BLD_new());
    if (!n || !e || !bld ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get()) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()) != 1) {
        throw std::runtime_error("kms: bad RSA public key");
    }
    const auto k = from_params("RSA", bld.get());
    if (!k) {
        throw std::runtime_error("kms: bad RSA public key");
    }
    return spki_of(k.get());
}

/// The SubjectPublicKeyInfo of an EC public key: the curve's OID
/// (CKA_EC_PARAMS) and the point (CKA_EC_POINT), which PKCS#11 wraps in a
/// DER OCTET STRING; a module that returns the bare point is accepted too.
[[nodiscard]] inline auto ec_spki(std::span<const std::uint8_t> params,
                                  std::span<const std::uint8_t> point) -> der_bytes {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    const auto group = curve_name(params);
    if (group.empty()) {
        throw std::runtime_error("kms: unsupported curve");
    }
    der_bytes raw(point.begin(), point.end());
    {
        const unsigned char* p = point.data();
        const std::unique_ptr<ASN1_OCTET_STRING, octets_free> o(
            d2i_ASN1_OCTET_STRING(nullptr, &p, static_cast<long>(point.size())));
        if (o && p == point.data() + point.size() && ASN1_STRING_length(o.get()) > 0 &&
            ASN1_STRING_get0_data(o.get())[0] == 0x04) {
            const auto* d = ASN1_STRING_get0_data(o.get());
            raw.assign(d, d + ASN1_STRING_length(o.get()));
        }
    }
    const std::string name(group);
    const std::unique_ptr<OSSL_PARAM_BLD, bld_free> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, name.c_str(), 0) !=
            1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, raw.data(),
                                         raw.size()) != 1) {
        throw std::runtime_error("kms: bad EC public key");
    }
    const auto k = from_params("EC", bld.get());
    if (!k) {
        throw std::runtime_error("kms: bad EC public key");
    }
    return spki_of(k.get());
}

/// The digest of `message`.
[[nodiscard]] inline auto digest(hash_alg h, std::span<const std::uint8_t> message) -> der_bytes {
    der_bytes out(EVP_MAX_MD_SIZE);
    unsigned int n = 0;
    if (EVP_Digest(message.data(), message.size(), out.data(), &n, public_key_detail::md_of(h),
                   nullptr) != 1) {
        throw std::runtime_error("kms: digest failed");
    }
    out.resize(n);
    return out;
}

/// The DER DigestInfo prefix PKCS#1 v1.5 signing puts before a digest
/// (RFC 8017 section 9.2, note 1); CKM_RSA_PKCS signs prefix || digest.
[[nodiscard]] inline auto digest_info_prefix(hash_alg h) -> der_bytes {
    switch (h) {
        case hash_alg::sha256:
            return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        case hash_alg::sha384:
            return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
        case hash_alg::sha512:
            return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        case hash_alg::sha1:
            return {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    }
    return {};
}

/// An ECDSA signature as PKCS#11 returns it (r || s, each half the
/// length) in the DER form AWS returns (and OpenSSL verifies).
[[nodiscard]] inline auto ecdsa_der(std::span<const std::uint8_t> raw) -> der_bytes {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    if (raw.empty() || raw.size() % 2 != 0) {
        throw std::runtime_error("kms: bad ECDSA signature from the token");
    }
    const auto half = static_cast<int>(raw.size() / 2);
    std::unique_ptr<ECDSA_SIG, sig_free> sig(ECDSA_SIG_new());
    BIGNUM* r = BN_bin2bn(raw.data(), half, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + half, half, nullptr);
    if (!sig || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("kms: bad ECDSA signature from the token");
    }
    const int n = i2d_ECDSA_SIG(sig.get(), nullptr);
    der_bytes out(static_cast<std::size_t>(n));
    unsigned char* p = out.data();
    i2d_ECDSA_SIG(sig.get(), &p);
    return out;
}

/// How a signature is made: PKCS#1 v1.5, PSS (salt the digest's length,
/// MGF1 with the same hash, as AWS uses), or ECDSA.
enum class sig_scheme : std::uint8_t {
    pkcs1,
    pss,
    ecdsa
};

/// Whether `signature` is valid for `digest_value` under the public key.
[[nodiscard]] inline auto verify_digest(std::span<const std::uint8_t> spki, sig_scheme scheme,
                                        hash_alg h, std::span<const std::uint8_t> digest_value,
                                        std::span<const std::uint8_t> signature) -> bool {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    const auto k = parse_spki(spki);
    if (!k) {
        return false;
    }
    const pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(k.get(), nullptr));
    if (!ctx || EVP_PKEY_verify_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_signature_md(ctx.get(), md_of(h)) != 1) {
        return false;
    }
    if (scheme == sig_scheme::pkcs1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1) {
        return false;
    }
    if (scheme == sig_scheme::pss &&
        (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) != 1 ||
         EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(h)) != 1 ||
         EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), static_cast<int>(hash_size(h))) != 1)) {
        return false;
    }
    return EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), digest_value.data(),
                           digest_value.size()) == 1;
}

/// RSA-OAEP of `plain` under the public key (MGF1 with the same hash, as
/// AWS uses), or nullopt when the plaintext is too long for the key.
[[nodiscard]] inline auto oaep_encrypt(std::span<const std::uint8_t> spki, hash_alg h,
                                       std::span<const std::uint8_t> plain)
    -> std::optional<der_bytes> {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    const auto k = parse_spki(spki);
    if (!k) {
        throw std::runtime_error("kms: bad RSA public key");
    }
    const auto max = static_cast<std::size_t>(EVP_PKEY_get_size(k.get())) - 2 * hash_size(h) - 2;
    if (plain.size() > max) {
        return std::nullopt;
    }
    const pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(k.get(), nullptr));
    std::size_t n = 0;
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md_of(h)) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md_of(h)) != 1 ||
        EVP_PKEY_encrypt(ctx.get(), nullptr, &n, plain.data(), plain.size()) != 1) {
        throw std::runtime_error("kms: RSA-OAEP failed");
    }
    der_bytes out(n);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &n, plain.data(), plain.size()) != 1) {
        throw std::runtime_error("kms: RSA-OAEP failed");
    }
    out.resize(n);
    return out;
}

/// A data key pair: the private key as PKCS#8 DER (wiped by the caller)
/// and the public key as SubjectPublicKeyInfo DER.
struct data_key_pair {
    der_bytes private_pkcs8;
    der_bytes public_spki;
};

/// A fresh key pair: RSA of `rsa_bits`, or EC on `curve` (an OpenSSL group
/// name) when `rsa_bits` is 0.
[[nodiscard]] inline auto generate_key_pair(unsigned rsa_bits, std::string_view curve)
    -> data_key_pair {
    using namespace public_key_detail;  // NOLINT(google-build-using-namespace)
    pkey_ptr k;
    if (rsa_bits != 0) {
        k.reset(EVP_RSA_gen(rsa_bits));
    } else {
        const std::string name(curve);
        k.reset(EVP_EC_gen(name.c_str()));
    }
    if (!k) {
        throw std::runtime_error("kms: key pair generation failed");
    }
    data_key_pair out;
    out.public_spki = spki_of(k.get());
    PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(k.get());
    if (p8 == nullptr) {
        throw std::runtime_error("kms: cannot encode a private key");
    }
    const int n = i2d_PKCS8_PRIV_KEY_INFO(p8, nullptr);
    out.private_pkcs8.resize(static_cast<std::size_t>(n));
    unsigned char* p = out.private_pkcs8.data();
    i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return out;
}

}  // namespace kythira::kms
