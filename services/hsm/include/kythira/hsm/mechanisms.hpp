// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The virtual HSM's cryptography (requirement 6.1, 6.2 and 6.5): every key
// type and mechanism the token offers, on OpenSSL 3 EVP, as single-part
// operations over key material. The session layer (task 6) adds handles,
// multi-part buffering and the attribute checks in attribute_policy.hpp;
// nothing here looks at attributes.
//
// Key material: a secret key's raw value, or a private key as PKCS#8
// PrivateKeyInfo DER, always in secret_bytes (the secure arena); a public
// key as SubjectPublicKeyInfo DER. OpenSSL key objects are made from those
// bytes for one call and freed at its end, so OpenSSL's own copies of a key
// live only for the operation (design, "Memory hygiene").
//
// Anything not in supported_mechanisms() answers CKR_MECHANISM_INVALID.
// That covers the exclusions of 6.5 (DES and 3DES, MD5, SHA-1 signatures,
// DSA, RSA without padding); excluded_mechanisms() lists them for the tests
// and the docs. PKCS#1 v1.5 is offered for signatures only, not encryption:
// v1.5 decryption is a padding oracle (Bleichenbacher) that a network
// service should not expose, and OAEP covers every encryption need.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/secret_bytes.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

using bytes = std::vector<std::uint8_t>;

/// A key as the mechanisms see it.
struct key_material {
    CK_OBJECT_CLASS object_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    /// The raw value (secret keys) or PKCS#8 DER (private keys).
    secret_bytes secret;
    /// SubjectPublicKeyInfo DER (public keys, and private keys' public half).
    bytes public_der;
};

/// A generated or inspected key pair: the private key, its public half and
/// the public attributes PKCS#11 shows on both objects.
struct key_pair {
    CK_KEY_TYPE key_type = CKK_RSA;
    secret_bytes private_pkcs8;
    bytes public_spki;
    /// CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT (RSA) or
    /// CKA_EC_PARAMS, CKA_EC_POINT (EC and Ed25519).
    attribute_map public_attributes;
};

struct mechanism_entry {
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_INFO info;
};

// --- Supported and excluded mechanisms (6.2, 6.5) --------------------------

namespace detail {

inline constexpr CK_FLAGS sign_verify = CKF_SIGN | CKF_VERIFY;
inline constexpr CK_FLAGS enc_dec = CKF_ENCRYPT | CKF_DECRYPT;
inline constexpr CK_FLAGS wrap_unwrap = CKF_WRAP | CKF_UNWRAP;
inline constexpr CK_FLAGS ec_flags = CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;

inline constexpr std::array<mechanism_entry, 33> mechanism_table{{
    // Key generation (6.1). AES and generic secret sizes are in bytes, RSA
    // in bits, EC in bits of the field.
    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_GENERIC_SECRET_KEY_GEN, {1, 512, CKF_GENERATE}},
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {2048, 4096, CKF_GENERATE_KEY_PAIR}},
    {CKM_EC_KEY_PAIR_GEN, {256, 521, CKF_GENERATE_KEY_PAIR | ec_flags}},
    {CKM_EC_EDWARDS_KEY_PAIR_GEN, {255, 255, CKF_GENERATE_KEY_PAIR}},
    // AES.
    {CKM_AES_GCM, {16, 32, enc_dec | wrap_unwrap}},
    {CKM_AES_CBC_PAD, {16, 32, enc_dec | wrap_unwrap}},
    {CKM_AES_KEY_WRAP, {16, 32, wrap_unwrap}},
    {CKM_AES_KEY_WRAP_KWP, {16, 32, wrap_unwrap}},
    // Digests and HMACs.
    {CKM_SHA256, {0, 0, CKF_DIGEST}},
    {CKM_SHA384, {0, 0, CKF_DIGEST}},
    {CKM_SHA512, {0, 0, CKF_DIGEST}},
    {CKM_SHA256_HMAC, {1, 512, sign_verify}},
    {CKM_SHA384_HMAC, {1, 512, sign_verify}},
    {CKM_SHA512_HMAC, {1, 512, sign_verify}},
    // RSA.
    {CKM_RSA_PKCS, {2048, 4096, sign_verify}},
    {CKM_SHA256_RSA_PKCS, {2048, 4096, sign_verify}},
    {CKM_SHA384_RSA_PKCS, {2048, 4096, sign_verify}},
    {CKM_SHA512_RSA_PKCS, {2048, 4096, sign_verify}},
    {CKM_RSA_PKCS_PSS, {2048, 4096, sign_verify}},
    {CKM_SHA256_RSA_PKCS_PSS, {2048, 4096, sign_verify}},
    {CKM_SHA384_RSA_PKCS_PSS, {2048, 4096, sign_verify}},
    {CKM_SHA512_RSA_PKCS_PSS, {2048, 4096, sign_verify}},
    {CKM_RSA_PKCS_OAEP, {2048, 4096, enc_dec | wrap_unwrap}},
    // EC.
    {CKM_ECDSA, {256, 521, sign_verify | ec_flags}},
    {CKM_ECDSA_SHA256, {256, 521, sign_verify | ec_flags}},
    {CKM_ECDSA_SHA384, {256, 521, sign_verify | ec_flags}},
    {CKM_ECDSA_SHA512, {256, 521, sign_verify | ec_flags}},
    {CKM_EDDSA, {255, 255, sign_verify}},
    {CKM_ECDH1_DERIVE, {256, 521, CKF_DERIVE | ec_flags}},
    // Key derivation.
    {CKM_HKDF_DERIVE, {1, 512, CKF_DERIVE}},
    {CKM_HKDF_KEY_GEN, {1, 512, CKF_GENERATE}},
    {CKM_HKDF_DATA, {1, 512, CKF_DERIVE}},
}};

inline constexpr std::array<CK_MECHANISM_TYPE, 26> excluded_table{{
    CKM_DES_KEY_GEN,
    CKM_DES_ECB,
    CKM_DES_CBC,
    CKM_DES_CBC_PAD,
    CKM_DES3_KEY_GEN,
    CKM_DES3_ECB,
    CKM_DES3_CBC,
    CKM_DES3_CBC_PAD,
    CKM_MD5,
    CKM_MD5_HMAC,
    CKM_MD5_RSA_PKCS,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_ECDSA_SHA1,
    CKM_SHA_1_HMAC,
    CKM_DSA,
    CKM_DSA_SHA1,
    CKM_DSA_SHA256,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_RSA_X_509,
    CKM_RSA_9796,
    CKM_RSA_X9_31,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA_1,
    CKM_SHA224,
    CKM_ECDSA_SHA224,
}};

}  // namespace detail

[[nodiscard]] inline auto supported_mechanisms() noexcept -> std::span<const mechanism_entry> {
    return detail::mechanism_table;
}

/// Mechanisms 6.5 names as excluded (and close relatives a client might
/// try); every one answers CKR_MECHANISM_INVALID.
[[nodiscard]] inline auto excluded_mechanisms() noexcept -> std::span<const CK_MECHANISM_TYPE> {
    return detail::excluded_table;
}

[[nodiscard]] inline auto mechanism_info(CK_MECHANISM_TYPE type) -> ck_result<CK_MECHANISM_INFO> {
    for (const auto& e : detail::mechanism_table) {
        if (e.type == type) {
            return e.info;
        }
    }
    return unexpected(CKR_MECHANISM_INVALID);
}

/// The PKCS#11 3.0 functions this token does not implement (6.5); the
/// library answers each with CKR_FUNCTION_NOT_SUPPORTED.
[[nodiscard]] inline auto unsupported_functions() noexcept -> std::span<const std::string_view> {
    static constexpr std::array<std::string_view, 18> names{
        "C_SignRecoverInit",     "C_SignRecover",         "C_VerifyRecoverInit",
        "C_VerifyRecover",       "C_GetOperationState",   "C_SetOperationState",
        "C_MessageEncryptInit",  "C_EncryptMessage",      "C_EncryptMessageBegin",
        "C_EncryptMessageNext",  "C_MessageEncryptFinal", "C_MessageDecryptInit",
        "C_DecryptMessage",      "C_DecryptMessageBegin", "C_DecryptMessageNext",
        "C_MessageDecryptFinal", "C_MessageSignInit",     "C_MessageVerifyInit",
    };
    return names;
}

// --- OpenSSL plumbing -------------------------------------------------------

namespace detail {

struct pkey_free {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct pkey_ctx_free {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct md_ctx_free {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct cipher_ctx_free {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
struct cipher_free {
    void operator()(EVP_CIPHER* p) const noexcept { EVP_CIPHER_free(p); }
};
struct kdf_free {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
struct kdf_ctx_free {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};
struct bn_free {
    void operator()(BIGNUM* p) const noexcept { BN_free(p); }
};
struct ecdsa_sig_free {
    void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};
struct encoder_ctx_free {
    void operator()(OSSL_ENCODER_CTX* p) const noexcept { OSSL_ENCODER_CTX_free(p); }
};
struct param_bld_free {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct params_free {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};

using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free>;

inline auto fail() -> unexpected<CK_RV> {
    return unexpected(CKR_FUNCTION_FAILED);
}

/// Reads a mechanism parameter of exactly type P.
template<class P> [[nodiscard]] auto param_as(const CK_MECHANISM& m) -> ck_result<const P*> {
    if (m.pParameter == nullptr || m.ulParameterLen != sizeof(P)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    return static_cast<const P*>(m.pParameter);
}

[[nodiscard]] inline auto no_param(const CK_MECHANISM& m) -> bool {
    return m.pParameter == nullptr && m.ulParameterLen == 0;
}

[[nodiscard]] inline auto span_of(const CK_BYTE* p, CK_ULONG n)
    -> ck_result<std::span<const std::uint8_t>> {
    if (p == nullptr && n != 0) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    return std::span<const std::uint8_t>(p, static_cast<std::size_t>(n));
}

/// The OpenSSL digest name for a PKCS#11 hash mechanism (SHA-2 only, plus
/// SHA-1 where `allow_sha1`, which only OAEP passes).
[[nodiscard]] inline auto digest_name(CK_MECHANISM_TYPE hash, bool allow_sha1 = false) -> const
    char* {
    switch (hash) {
        case CKM_SHA256:
            return "SHA256";
        case CKM_SHA384:
            return "SHA384";
        case CKM_SHA512:
            return "SHA512";
        case CKM_SHA_1:
            return allow_sha1 ? "SHA1" : nullptr;
        default:
            return nullptr;
    }
}

[[nodiscard]] inline auto mgf_for(CK_MECHANISM_TYPE hash) -> CK_RSA_PKCS_MGF_TYPE {
    switch (hash) {
        case CKM_SHA256:
            return CKG_MGF1_SHA256;
        case CKM_SHA384:
            return CKG_MGF1_SHA384;
        case CKM_SHA512:
            return CKG_MGF1_SHA512;
        case CKM_SHA_1:
            return CKG_MGF1_SHA1;
        default:
            return 0;
    }
}

[[nodiscard]] inline auto load_private(const key_material& k) -> ck_result<pkey_ptr> {
    if (k.object_class != CKO_PRIVATE_KEY || k.secret.empty()) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    const unsigned char* p = k.secret.data();
    pkey_ptr key(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(k.secret.size())));
    if (!key) {
        return fail();
    }
    return key;
}

[[nodiscard]] inline auto load_public(const key_material& k) -> ck_result<pkey_ptr> {
    if (k.object_class == CKO_SECRET_KEY || k.public_der.empty()) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    const unsigned char* p = k.public_der.data();
    pkey_ptr key(d2i_PUBKEY(nullptr, &p, static_cast<long>(k.public_der.size())));
    if (!key) {
        return fail();
    }
    return key;
}

/// Checks that `k` is a key of type `type` (any class).
[[nodiscard]] inline auto require_type(const key_material& k, CK_KEY_TYPE type) -> ck_result<void> {
    if (k.key_type != type) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    return {};
}

[[nodiscard]] inline auto require_secret(const key_material& k, CK_KEY_TYPE type)
    -> ck_result<void> {
    if (k.object_class != CKO_SECRET_KEY || k.key_type != type) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    return {};
}

[[nodiscard]] inline auto digest_bytes(const char* name, std::span<const std::uint8_t> data)
    -> ck_result<bytes> {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    std::size_t len = 0;
    if (EVP_Q_digest(nullptr, name, nullptr, data.data(), data.size(), md.data(), &len) != 1) {
        return fail();
    }
    return bytes(md.begin(), md.begin() + static_cast<std::ptrdiff_t>(len));
}

/// DER OCTET STRING around `in` (CKA_EC_POINT's encoding).
[[nodiscard]] inline auto der_octet_string(std::span<const std::uint8_t> in) -> bytes {
    bytes out{0x04};
    if (in.size() < 0x80) {
        out.push_back(static_cast<std::uint8_t>(in.size()));
    } else if (in.size() <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(in.size()));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(in.size() >> 8U));
        out.push_back(static_cast<std::uint8_t>(in.size()));
    }
    out.insert(out.end(), in.begin(), in.end());
    return out;
}

/// The contents of a DER OCTET STRING, or the input unchanged when it is not
/// one (PKCS#11 clients pass EC points both ways).
[[nodiscard]] inline auto strip_octet_string(std::span<const std::uint8_t> in)
    -> std::span<const std::uint8_t> {
    if (in.size() < 2 || in[0] != 0x04) {
        return in;
    }
    std::size_t len = in[1];
    std::size_t header = 2;
    if (len == 0x81 && in.size() >= 3) {
        len = in[2];
        header = 3;
    } else if (len == 0x82 && in.size() >= 4) {
        len = (std::size_t{in[2]} << 8U) | in[3];
        header = 4;
    } else if (len >= 0x80) {
        return in;
    }
    if (header + len != in.size()) {
        return in;  // a raw uncompressed point also starts with 0x04
    }
    return in.subspan(header);
}

struct curve {
    const char* group;
    std::span<const std::uint8_t> oid_der;
    CK_KEY_TYPE key_type;
};

inline constexpr std::array<std::uint8_t, 10> oid_p256{0x06, 0x08, 0x2A, 0x86, 0x48,
                                                       0xCE, 0x3D, 0x03, 0x01, 0x07};
inline constexpr std::array<std::uint8_t, 7> oid_p384{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
inline constexpr std::array<std::uint8_t, 7> oid_p521{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
inline constexpr std::array<std::uint8_t, 5> oid_ed25519{0x06, 0x03, 0x2B, 0x65, 0x70};
// PKCS#11 3.0 also allows the curve's name as a PrintableString.
inline constexpr std::array<std::uint8_t, 14> name_ed25519{0x13, 0x0C, 'e', 'd', 'w', 'a', 'r',
                                                           'd',  's',  '2', '5', '5', '1', '9'};

[[nodiscard]] inline auto curve_from_params(std::span<const std::uint8_t> params)
    -> std::optional<curve> {
    auto is = [&](std::span<const std::uint8_t> oid) { return std::ranges::equal(params, oid); };
    if (is(oid_p256)) {
        return curve{"P-256", oid_p256, CKK_EC};
    }
    if (is(oid_p384)) {
        return curve{"P-384", oid_p384, CKK_EC};
    }
    if (is(oid_p521)) {
        return curve{"P-521", oid_p521, CKK_EC};
    }
    if (is(oid_ed25519) || is(name_ed25519)) {
        return curve{"ED25519", oid_ed25519, CKK_EC_EDWARDS};
    }
    return std::nullopt;
}

[[nodiscard]] inline auto curve_from_group(std::string_view group) -> std::optional<curve> {
    if (group == "prime256v1" || group == "P-256") {
        return curve{"P-256", oid_p256, CKK_EC};
    }
    if (group == "secp384r1" || group == "P-384") {
        return curve{"P-384", oid_p384, CKK_EC};
    }
    if (group == "secp521r1" || group == "P-521") {
        return curve{"P-521", oid_p521, CKK_EC};
    }
    return std::nullopt;
}

[[nodiscard]] inline auto group_name(EVP_PKEY* key) -> std::string {
    std::array<char, 64> name{};
    std::size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, name.data(), name.size(),
                                       &len) != 1) {
        return {};
    }
    return {name.data(), len};
}

[[nodiscard]] inline auto bn_param(EVP_PKEY* key, const char* name) -> ck_result<bytes> {
    BIGNUM* raw = nullptr;
    if (EVP_PKEY_get_bn_param(key, name, &raw) != 1) {
        return fail();
    }
    std::unique_ptr<BIGNUM, bn_free> bn(raw);
    bytes out(static_cast<std::size_t>(BN_num_bytes(bn.get())));
    BN_bn2bin(bn.get(), out.data());
    return out;
}

/// PKCS#8 PrivateKeyInfo DER of `key`, straight into the secure arena.
[[nodiscard]] inline auto encode_pkcs8(EVP_PKEY* key) -> ck_result<secret_bytes> {
    std::unique_ptr<OSSL_ENCODER_CTX, encoder_ctx_free> enc(OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_ALL, "DER", "PrivateKeyInfo", nullptr));
    if (!enc) {
        return fail();
    }
    unsigned char* data = nullptr;
    std::size_t len = 0;
    if (OSSL_ENCODER_to_data(enc.get(), &data, &len) != 1) {
        return fail();
    }
    secret_bytes out(std::span<const std::uint8_t>(data, len));
    OPENSSL_clear_free(data, len);
    return out;
}

[[nodiscard]] inline auto encode_spki(EVP_PKEY* key) -> ck_result<bytes> {
    const int len = i2d_PUBKEY(key, nullptr);
    if (len <= 0) {
        return fail();
    }
    bytes out(static_cast<std::size_t>(len));
    unsigned char* p = out.data();
    if (i2d_PUBKEY(key, &p) != len) {
        return fail();
    }
    return out;
}

/// The public half and attributes of an OpenSSL private key.
[[nodiscard]] inline auto describe(EVP_PKEY* key) -> ck_result<key_pair> {
    key_pair out;
    auto spki = encode_spki(key);
    if (!spki) {
        return unexpected(spki.error());
    }
    out.public_spki = std::move(*spki);
    if (EVP_PKEY_is_a(key, "RSA") == 1) {
        out.key_type = CKK_RSA;
        auto n = bn_param(key, OSSL_PKEY_PARAM_RSA_N);
        auto e = bn_param(key, OSSL_PKEY_PARAM_RSA_E);
        if (!n || !e) {
            return fail();
        }
        out.public_attributes.set_bytes(CKA_MODULUS, *n);
        out.public_attributes.set_ulong(CKA_MODULUS_BITS,
                                        static_cast<CK_ULONG>(EVP_PKEY_get_bits(key)));
        out.public_attributes.set_bytes(CKA_PUBLIC_EXPONENT, *e);
        return out;
    }
    std::array<unsigned char, 160> point{};
    std::size_t point_len = 0;
    // EC keys give their uncompressed point; Ed25519 its 32 raw bytes.
    const char* point_param = EVP_PKEY_is_a(key, "ED25519") == 1
                                  ? OSSL_PKEY_PARAM_PUB_KEY
                                  : OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY;
    if (EVP_PKEY_get_octet_string_param(key, point_param, point.data(), point.size(), &point_len) !=
        1) {
        return fail();
    }
    std::optional<curve> c;
    if (EVP_PKEY_is_a(key, "ED25519") == 1) {
        c = curve{"ED25519", oid_ed25519, CKK_EC_EDWARDS};
    } else if (EVP_PKEY_is_a(key, "EC") == 1) {
        c = curve_from_group(group_name(key));
    }
    if (!c) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    out.key_type = c->key_type;
    out.public_attributes.set_bytes(CKA_EC_PARAMS, c->oid_der);
    out.public_attributes.set_bytes(CKA_EC_POINT,
                                    der_octet_string(std::span(point.data(), point_len)));
    return out;
}

}  // namespace detail

// --- Randomness and key generation (6.1, 6.2) -------------------------------

[[nodiscard]] inline auto generate_random(std::span<std::uint8_t> out) -> ck_result<void> {
    if (!out.empty() && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        return unexpected(CKR_FUNCTION_FAILED);
    }
    return {};
}

/// CKM_AES_KEY_GEN (16, 24 or 32 bytes), CKM_GENERIC_SECRET_KEY_GEN and
/// CKM_HKDF_KEY_GEN (1 to 512 bytes).
[[nodiscard]] inline auto generate_secret_key(const CK_MECHANISM& m, CK_ULONG len)
    -> ck_result<secret_bytes> {
    if (!detail::no_param(m)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    switch (m.mechanism) {
        case CKM_AES_KEY_GEN:
            if (len != 16 && len != 24 && len != 32) {
                return unexpected(CKR_KEY_SIZE_RANGE);
            }
            break;
        case CKM_GENERIC_SECRET_KEY_GEN:
        case CKM_HKDF_KEY_GEN:
            if (len < 1 || len > 512) {
                return unexpected(CKR_KEY_SIZE_RANGE);
            }
            break;
        default:
            return unexpected(CKR_MECHANISM_INVALID);
    }
    secret_bytes key(static_cast<std::size_t>(len));
    if (auto r = generate_random(key.span()); !r) {
        return unexpected(r.error());
    }
    return key;
}

/// What a key pair generation needs from the public key template.
struct key_pair_request {
    CK_ULONG modulus_bits = 0;  // RSA: CKA_MODULUS_BITS
    bytes public_exponent;      // RSA: CKA_PUBLIC_EXPONENT, empty = 65537
    bytes ec_params;            // EC, Ed25519: CKA_EC_PARAMS
};

[[nodiscard]] inline auto generate_key_pair(const CK_MECHANISM& m, const key_pair_request& req)
    -> ck_result<key_pair> {
    if (!detail::no_param(m)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    detail::pkey_ptr key;
    switch (m.mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: {
            if (req.modulus_bits != 2048 && req.modulus_bits != 3072 && req.modulus_bits != 4096) {
                return unexpected(CKR_KEY_SIZE_RANGE);
            }
            detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
            if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), static_cast<int>(req.modulus_bits)) !=
                    1) {
                return detail::fail();
            }
            if (!req.public_exponent.empty()) {
                std::unique_ptr<BIGNUM, detail::bn_free> e(
                    BN_bin2bn(req.public_exponent.data(),
                              static_cast<int>(req.public_exponent.size()), nullptr));
                // Only odd exponents of at least 65537 (FIPS 186-5).
                if (!e || BN_is_odd(e.get()) == 0 || BN_num_bits(e.get()) < 17 ||
                    BN_num_bits(e.get()) > 256) {
                    return unexpected(CKR_TEMPLATE_INCONSISTENT);
                }
                if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.get(), e.get()) != 1) {
                    return detail::fail();
                }
            }
            EVP_PKEY* raw = nullptr;
            if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
                return detail::fail();
            }
            key.reset(raw);
            break;
        }
        case CKM_EC_KEY_PAIR_GEN:
        case CKM_EC_EDWARDS_KEY_PAIR_GEN: {
            auto c = detail::curve_from_params(req.ec_params);
            const CK_KEY_TYPE want = m.mechanism == CKM_EC_KEY_PAIR_GEN ? CKK_EC : CKK_EC_EDWARDS;
            if (!c || c->key_type != want) {
                return unexpected(CKR_CURVE_NOT_SUPPORTED);
            }
            key.reset(want == CKK_EC ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", c->group)
                                     : EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
            if (!key) {
                return detail::fail();
            }
            break;
        }
        default:
            return unexpected(CKR_MECHANISM_INVALID);
    }
    auto pair = detail::describe(key.get());
    if (!pair) {
        return unexpected(pair.error());
    }
    auto pkcs8 = detail::encode_pkcs8(key.get());
    if (!pkcs8) {
        return unexpected(pkcs8.error());
    }
    pair->private_pkcs8 = std::move(*pkcs8);
    return pair;
}

/// The key type, public half and public attributes of a PKCS#8 private key
/// (an unwrapped or imported one). Unsupported algorithms and curves are
/// CKR_KEY_TYPE_INCONSISTENT; RSA keys outside 2048-4096 bits are
/// CKR_KEY_SIZE_RANGE.
[[nodiscard]] inline auto inspect_private_key(std::span<const std::uint8_t> pkcs8)
    -> ck_result<key_pair> {
    const unsigned char* p = pkcs8.data();
    detail::pkey_ptr key(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(pkcs8.size())));
    if (!key || p != pkcs8.data() + pkcs8.size()) {
        return unexpected(CKR_WRAPPED_KEY_INVALID);
    }
    if (EVP_PKEY_is_a(key.get(), "RSA") == 1) {
        const int bits = EVP_PKEY_get_bits(key.get());
        if (bits < 2048 || bits > 4096) {
            return unexpected(CKR_KEY_SIZE_RANGE);
        }
    }
    auto pair = detail::describe(key.get());
    if (!pair) {
        return unexpected(pair.error());
    }
    pair->private_pkcs8 = secret_bytes(pkcs8);
    return pair;
}

// --- Digests ----------------------------------------------------------------

[[nodiscard]] inline auto digest(const CK_MECHANISM& m, std::span<const std::uint8_t> data)
    -> ck_result<bytes> {
    if (!detail::no_param(m)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    const char* name = detail::digest_name(m.mechanism);
    if (name == nullptr) {
        return unexpected(CKR_MECHANISM_INVALID);
    }
    return detail::digest_bytes(name, data);
}

// --- Signatures -------------------------------------------------------------

namespace detail {

[[nodiscard]] inline auto hmac_digest(CK_MECHANISM_TYPE m) -> const char* {
    switch (m) {
        case CKM_SHA256_HMAC:
            return "SHA256";
        case CKM_SHA384_HMAC:
            return "SHA384";
        case CKM_SHA512_HMAC:
            return "SHA512";
        default:
            return nullptr;
    }
}

/// The hash a combined sign mechanism applies first, or CKM_VENDOR_DEFINED
/// for mechanisms that sign their input as given.
[[nodiscard]] inline auto prehash_of(CK_MECHANISM_TYPE m) -> CK_MECHANISM_TYPE {
    switch (m) {
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_ECDSA_SHA256:
            return CKM_SHA256;
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_ECDSA_SHA384:
            return CKM_SHA384;
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
        case CKM_ECDSA_SHA512:
            return CKM_SHA512;
        default:
            return CKM_VENDOR_DEFINED;
    }
}

[[nodiscard]] inline auto hmac(const CK_MECHANISM& m, const key_material& k,
                               std::span<const std::uint8_t> data) -> ck_result<bytes> {
    if (!no_param(m)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (k.object_class != CKO_SECRET_KEY ||
        (k.key_type != CKK_GENERIC_SECRET && k.key_type != CKK_SHA256_HMAC &&
         k.key_type != CKK_SHA384_HMAC && k.key_type != CKK_SHA512_HMAC)) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
    std::size_t len = 0;
    const char* md = hmac_digest(m.mechanism);
    if (EVP_Q_mac(nullptr, "HMAC", nullptr, md, nullptr, k.secret.data(), k.secret.size(),
                  data.data(), data.size(), out.data(), out.size(), &len) == nullptr) {
        return fail();
    }
    return bytes(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(len));
}

/// Applies a mechanism's RSA padding (and PSS parameters) to a sign/verify
/// context; `hash` is the hash of the input (CKM_VENDOR_DEFINED for
/// CKM_RSA_PKCS, which pads a DigestInfo the caller made).
[[nodiscard]] inline auto rsa_setup(EVP_PKEY_CTX* ctx, const CK_MECHANISM& m,
                                    CK_MECHANISM_TYPE hash, std::size_t input_len)
    -> ck_result<void> {
    const bool pss = m.mechanism == CKM_RSA_PKCS_PSS || m.mechanism == CKM_SHA256_RSA_PKCS_PSS ||
                     m.mechanism == CKM_SHA384_RSA_PKCS_PSS ||
                     m.mechanism == CKM_SHA512_RSA_PKCS_PSS;
    if (!pss) {
        if (!no_param(m)) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
            return fail();
        }
        if (hash != CKM_VENDOR_DEFINED &&
            EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(digest_name(hash))) != 1) {
            return fail();
        }
        return {};
    }
    auto params = param_as<CK_RSA_PKCS_PSS_PARAMS>(m);
    if (!params) {
        return unexpected(params.error());
    }
    const auto& pp = **params;
    const char* md = digest_name(pp.hashAlg);
    if (md == nullptr || pp.mgf != mgf_for(pp.hashAlg) ||
        (hash != CKM_VENDOR_DEFINED && hash != pp.hashAlg)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    // CKM_RSA_PKCS_PSS signs a hash the caller computed with hashAlg.
    if (hash == CKM_VENDOR_DEFINED &&
        input_len != static_cast<std::size_t>(EVP_MD_get_size(EVP_get_digestbyname(md)))) {
        return unexpected(CKR_DATA_LEN_RANGE);
    }
    if (pp.sLen > 512) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(md)) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_get_digestbyname(md)) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, static_cast<int>(pp.sLen)) != 1) {
        return fail();
    }
    return {};
}

[[nodiscard]] inline auto is_rsa_sign(CK_MECHANISM_TYPE m) -> bool {
    switch (m) {
        case CKM_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline auto is_ecdsa(CK_MECHANISM_TYPE m) -> bool {
    return m == CKM_ECDSA || m == CKM_ECDSA_SHA256 || m == CKM_ECDSA_SHA384 ||
           m == CKM_ECDSA_SHA512;
}

[[nodiscard]] inline auto ec_field_bytes(EVP_PKEY* key) -> std::size_t {
    return (static_cast<std::size_t>(EVP_PKEY_get_bits(key)) + 7U) / 8U;
}

/// The input a pre-hashing mechanism signs: the hash of `data`, or `data`.
[[nodiscard]] inline auto signing_input(CK_MECHANISM_TYPE m, std::span<const std::uint8_t> data)
    -> ck_result<bytes> {
    const CK_MECHANISM_TYPE hash = prehash_of(m);
    if (hash == CKM_VENDOR_DEFINED) {
        return bytes(data.begin(), data.end());
    }
    return digest_bytes(digest_name(hash), data);
}

[[nodiscard]] inline auto eddsa_params_ok(const CK_MECHANISM& m) -> bool {
    if (no_param(m)) {
        return true;
    }
    auto p = param_as<CK_EDDSA_PARAMS>(m);
    // Pure Ed25519 only: no pre-hash, no context.
    return p && (*p)->phFlag == CK_FALSE && (*p)->ulContextDataLen == 0;
}

}  // namespace detail

[[nodiscard]] inline auto sign(const CK_MECHANISM& m, const key_material& k,
                               std::span<const std::uint8_t> data) -> ck_result<bytes> {
    if (detail::hmac_digest(m.mechanism) != nullptr) {
        return detail::hmac(m, k, data);
    }
    if (detail::is_rsa_sign(m.mechanism)) {
        if (auto t = detail::require_type(k, CKK_RSA); !t) {
            return unexpected(t.error());
        }
        auto key = detail::load_private(k);
        if (!key) {
            return unexpected(key.error());
        }
        auto input = detail::signing_input(m.mechanism, data);
        if (!input) {
            return unexpected(input.error());
        }
        detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) != 1) {
            return detail::fail();
        }
        if (auto s =
                detail::rsa_setup(ctx.get(), m, detail::prehash_of(m.mechanism), input->size());
            !s) {
            return unexpected(s.error());
        }
        const auto mod = static_cast<std::size_t>(EVP_PKEY_get_size(key->get()));
        if (m.mechanism == CKM_RSA_PKCS && input->size() > mod - 11) {
            return unexpected(CKR_DATA_LEN_RANGE);
        }
        bytes sig(mod);
        std::size_t len = sig.size();
        if (EVP_PKEY_sign(ctx.get(), sig.data(), &len, input->data(), input->size()) != 1) {
            return detail::fail();
        }
        sig.resize(len);
        return sig;
    }
    if (detail::is_ecdsa(m.mechanism)) {
        if (!detail::no_param(m)) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        if (auto t = detail::require_type(k, CKK_EC); !t) {
            return unexpected(t.error());
        }
        auto key = detail::load_private(k);
        if (!key) {
            return unexpected(key.error());
        }
        auto input = detail::signing_input(m.mechanism, data);
        if (!input) {
            return unexpected(input.error());
        }
        detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) != 1) {
            return detail::fail();
        }
        std::size_t der_len = 0;
        if (EVP_PKEY_sign(ctx.get(), nullptr, &der_len, input->data(), input->size()) != 1) {
            return detail::fail();
        }
        bytes der(der_len);
        if (EVP_PKEY_sign(ctx.get(), der.data(), &der_len, input->data(), input->size()) != 1) {
            return detail::fail();
        }
        // PKCS#11 signatures are r || s, each the field's width.
        const unsigned char* p = der.data();
        std::unique_ptr<ECDSA_SIG, detail::ecdsa_sig_free> sig(
            d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_len)));
        if (!sig) {
            return detail::fail();
        }
        const std::size_t w = detail::ec_field_bytes(key->get());
        bytes out(2 * w);
        if (BN_bn2binpad(ECDSA_SIG_get0_r(sig.get()), out.data(), static_cast<int>(w)) < 0 ||
            BN_bn2binpad(ECDSA_SIG_get0_s(sig.get()), out.data() + w, static_cast<int>(w)) < 0) {
            return detail::fail();
        }
        return out;
    }
    if (m.mechanism == CKM_EDDSA) {
        if (!detail::eddsa_params_ok(m)) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        if (auto t = detail::require_type(k, CKK_EC_EDWARDS); !t) {
            return unexpected(t.error());
        }
        auto key = detail::load_private(k);
        if (!key) {
            return unexpected(key.error());
        }
        std::unique_ptr<EVP_MD_CTX, detail::md_ctx_free> md(EVP_MD_CTX_new());
        bytes sig(64);
        std::size_t len = sig.size();
        if (!md ||
            EVP_DigestSignInit_ex(md.get(), nullptr, nullptr, nullptr, nullptr, key->get(),
                                  nullptr) != 1 ||
            EVP_DigestSign(md.get(), sig.data(), &len, data.data(), data.size()) != 1) {
            return detail::fail();
        }
        sig.resize(len);
        return sig;
    }
    return unexpected(CKR_MECHANISM_INVALID);
}

/// CKR_OK as an empty value, CKR_SIGNATURE_INVALID or CKR_SIGNATURE_LEN_RANGE
/// when the signature does not verify, or another CK_RV for a bad call.
[[nodiscard]] inline auto verify(const CK_MECHANISM& m, const key_material& k,
                                 std::span<const std::uint8_t> data,
                                 std::span<const std::uint8_t> signature) -> ck_result<void> {
    if (detail::hmac_digest(m.mechanism) != nullptr) {
        auto expect = detail::hmac(m, k, data);
        if (!expect) {
            return unexpected(expect.error());
        }
        if (signature.size() != expect->size()) {
            return unexpected(CKR_SIGNATURE_LEN_RANGE);
        }
        if (!constant_time_equal(*expect, signature)) {
            return unexpected(CKR_SIGNATURE_INVALID);
        }
        return {};
    }
    // A private key object verifies with its public half.
    auto public_of = [&]() -> ck_result<detail::pkey_ptr> {
        if (k.object_class == CKO_SECRET_KEY) {
            return unexpected(CKR_KEY_TYPE_INCONSISTENT);
        }
        key_material pub;
        pub.object_class = CKO_PUBLIC_KEY;
        pub.public_der = k.public_der;
        return detail::load_public(pub);
    };
    if (detail::is_rsa_sign(m.mechanism)) {
        if (auto t = detail::require_type(k, CKK_RSA); !t) {
            return unexpected(t.error());
        }
        auto key = public_of();
        if (!key) {
            return unexpected(key.error());
        }
        auto input = detail::signing_input(m.mechanism, data);
        if (!input) {
            return unexpected(input.error());
        }
        detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
        if (!ctx || EVP_PKEY_verify_init(ctx.get()) != 1) {
            return detail::fail();
        }
        if (auto s =
                detail::rsa_setup(ctx.get(), m, detail::prehash_of(m.mechanism), input->size());
            !s) {
            return unexpected(s.error());
        }
        if (signature.size() != static_cast<std::size_t>(EVP_PKEY_get_size(key->get()))) {
            return unexpected(CKR_SIGNATURE_LEN_RANGE);
        }
        if (EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), input->data(),
                            input->size()) != 1) {
            return unexpected(CKR_SIGNATURE_INVALID);
        }
        return {};
    }
    if (detail::is_ecdsa(m.mechanism)) {
        if (!detail::no_param(m)) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        if (auto t = detail::require_type(k, CKK_EC); !t) {
            return unexpected(t.error());
        }
        auto key = public_of();
        if (!key) {
            return unexpected(key.error());
        }
        const std::size_t w = detail::ec_field_bytes(key->get());
        if (signature.size() != 2 * w) {
            return unexpected(CKR_SIGNATURE_LEN_RANGE);
        }
        auto input = detail::signing_input(m.mechanism, data);
        if (!input) {
            return unexpected(input.error());
        }
        std::unique_ptr<ECDSA_SIG, detail::ecdsa_sig_free> sig(ECDSA_SIG_new());
        BIGNUM* r = BN_bin2bn(signature.data(), static_cast<int>(w), nullptr);
        BIGNUM* s = BN_bin2bn(signature.data() + w, static_cast<int>(w), nullptr);
        if (!sig || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
            BN_free(r);
            BN_free(s);
            return detail::fail();
        }
        const int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
        bytes der(static_cast<std::size_t>(std::max(der_len, 0)));
        unsigned char* p = der.data();
        if (der_len <= 0 || i2d_ECDSA_SIG(sig.get(), &p) != der_len) {
            return detail::fail();
        }
        detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
        if (!ctx || EVP_PKEY_verify_init(ctx.get()) != 1) {
            return detail::fail();
        }
        if (EVP_PKEY_verify(ctx.get(), der.data(), der.size(), input->data(), input->size()) != 1) {
            return unexpected(CKR_SIGNATURE_INVALID);
        }
        return {};
    }
    if (m.mechanism == CKM_EDDSA) {
        if (!detail::eddsa_params_ok(m)) {
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
        if (auto t = detail::require_type(k, CKK_EC_EDWARDS); !t) {
            return unexpected(t.error());
        }
        auto key = public_of();
        if (!key) {
            return unexpected(key.error());
        }
        if (signature.size() != 64) {
            return unexpected(CKR_SIGNATURE_LEN_RANGE);
        }
        std::unique_ptr<EVP_MD_CTX, detail::md_ctx_free> md(EVP_MD_CTX_new());
        if (!md || EVP_DigestVerifyInit_ex(md.get(), nullptr, nullptr, nullptr, nullptr, key->get(),
                                           nullptr) != 1) {
            return detail::fail();
        }
        if (EVP_DigestVerify(md.get(), signature.data(), signature.size(), data.data(),
                             data.size()) != 1) {
            return unexpected(CKR_SIGNATURE_INVALID);
        }
        return {};
    }
    return unexpected(CKR_MECHANISM_INVALID);
}

// --- Encryption and key wrapping --------------------------------------------

namespace detail {

[[nodiscard]] inline auto aes_name(std::size_t key_len, std::string_view mode) -> std::string {
    return "AES-" + std::to_string(key_len * 8) + "-" + std::string(mode);
}

[[nodiscard]] inline auto fetch_cipher(const std::string& name)
    -> std::unique_ptr<EVP_CIPHER, cipher_free> {
    return std::unique_ptr<EVP_CIPHER, cipher_free>(
        EVP_CIPHER_fetch(nullptr, name.c_str(), nullptr));
}

[[nodiscard]] inline auto aes_key_ok(const key_material& k) -> ck_result<void> {
    if (auto r = require_secret(k, CKK_AES); !r) {
        return r;
    }
    if (k.secret.size() != 16 && k.secret.size() != 24 && k.secret.size() != 32) {
        return unexpected(CKR_KEY_SIZE_RANGE);
    }
    return {};
}

[[nodiscard]] inline auto aes_gcm(bool enc, const CK_MECHANISM& m, const key_material& k,
                                  std::span<const std::uint8_t> in) -> ck_result<bytes> {
    auto params = param_as<CK_GCM_PARAMS>(m);
    if (!params) {
        return unexpected(params.error());
    }
    const auto& gp = **params;
    auto iv = span_of(gp.pIv, gp.ulIvLen);
    auto aad = span_of(gp.pAAD, gp.ulAADLen);
    // 96 to 128-bit tags only (SP 800-38D's shorter tags need extra limits).
    if (!iv || !aad || iv->empty() || iv->size() > 128 || gp.ulTagBits < 96 || gp.ulTagBits > 128 ||
        gp.ulTagBits % 8 != 0) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    const std::size_t tag_len = gp.ulTagBits / 8;
    if (!enc && in.size() < tag_len) {
        return unexpected(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    auto cipher = fetch_cipher(aes_name(k.secret.size(), "GCM"));
    std::unique_ptr<EVP_CIPHER_CTX, cipher_ctx_free> ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx ||
        EVP_CipherInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, enc ? 1 : 0, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv->size()),
                            nullptr) != 1 ||
        EVP_CipherInit_ex2(ctx.get(), nullptr, k.secret.data(), iv->data(), enc ? 1 : 0, nullptr) !=
            1) {
        return fail();
    }
    int len = 0;
    if (!aad->empty() && EVP_CipherUpdate(ctx.get(), nullptr, &len, aad->data(),
                                          static_cast<int>(aad->size())) != 1) {
        return fail();
    }
    const std::size_t body = enc ? in.size() : in.size() - tag_len;
    bytes out(body + (enc ? tag_len : 0));
    if (body != 0 &&
        EVP_CipherUpdate(ctx.get(), out.data(), &len, in.data(), static_cast<int>(body)) != 1) {
        return fail();
    }
    if (!enc) {
        bytes tag(in.end() - static_cast<std::ptrdiff_t>(tag_len), in.end());
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                                tag.data()) != 1) {
            return fail();
        }
    }
    std::array<unsigned char, 16> scratch{};
    if (EVP_CipherFinal_ex(ctx.get(), scratch.data(), &len) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        return unexpected(enc ? CKR_FUNCTION_FAILED : CKR_ENCRYPTED_DATA_INVALID);
    }
    if (enc && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_len),
                                   out.data() + body) != 1) {
        return fail();
    }
    return out;
}

[[nodiscard]] inline auto aes_cbc_pad(bool enc, const CK_MECHANISM& m, const key_material& k,
                                      std::span<const std::uint8_t> in) -> ck_result<bytes> {
    if (m.pParameter == nullptr || m.ulParameterLen != 16) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (!enc && (in.empty() || in.size() % 16 != 0)) {
        return unexpected(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    auto cipher = fetch_cipher(aes_name(k.secret.size(), "CBC"));
    std::unique_ptr<EVP_CIPHER_CTX, cipher_ctx_free> ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx ||
        EVP_CipherInit_ex2(ctx.get(), cipher.get(), k.secret.data(),
                           static_cast<const unsigned char*>(m.pParameter), enc ? 1 : 0,
                           nullptr) != 1) {
        return fail();
    }
    bytes out(in.size() + 16);
    int len = 0;
    int fin = 0;
    if (EVP_CipherUpdate(ctx.get(), out.data(), &len, in.data(), static_cast<int>(in.size())) !=
        1) {
        return fail();
    }
    if (EVP_CipherFinal_ex(ctx.get(), out.data() + len, &fin) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        return unexpected(enc ? CKR_FUNCTION_FAILED : CKR_ENCRYPTED_DATA_INVALID);
    }
    out.resize(static_cast<std::size_t>(len) + static_cast<std::size_t>(fin));
    return out;
}

/// RFC 3394 (CKM_AES_KEY_WRAP) and RFC 5649 (CKM_AES_KEY_WRAP_KWP), with
/// the default IVs only.
[[nodiscard]] inline auto aes_kw(bool enc, bool pad, const CK_MECHANISM& m, const key_material& k,
                                 std::span<const std::uint8_t> in) -> ck_result<bytes> {
    if (!no_param(m)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (enc && (pad ? in.empty() : (in.size() < 16 || in.size() % 8 != 0))) {
        return unexpected(CKR_DATA_LEN_RANGE);
    }
    if (!enc && (in.size() < 16 || in.size() % 8 != 0)) {
        return unexpected(CKR_WRAPPED_KEY_LEN_RANGE);
    }
    auto cipher = fetch_cipher(aes_name(k.secret.size(), pad ? "WRAP-PAD" : "WRAP"));
    std::unique_ptr<EVP_CIPHER_CTX, cipher_ctx_free> ctx(EVP_CIPHER_CTX_new());
    if (!cipher || !ctx) {
        return fail();
    }
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_CipherInit_ex2(ctx.get(), cipher.get(), k.secret.data(), nullptr, enc ? 1 : 0,
                           nullptr) != 1) {
        return fail();
    }
    bytes out(in.size() + 16);
    int len = 0;
    if (EVP_CipherUpdate(ctx.get(), out.data(), &len, in.data(), static_cast<int>(in.size())) !=
            1 ||
        len < 0) {
        OPENSSL_cleanse(out.data(), out.size());
        return unexpected(enc ? CKR_FUNCTION_FAILED : CKR_WRAPPED_KEY_INVALID);
    }
    out.resize(static_cast<std::size_t>(len));
    return out;
}

[[nodiscard]] inline auto oaep_setup(EVP_PKEY_CTX* ctx, const CK_MECHANISM& m) -> ck_result<void> {
    auto params = param_as<CK_RSA_PKCS_OAEP_PARAMS>(m);
    if (!params) {
        return unexpected(params.error());
    }
    const auto& op = **params;
    // SHA-1 is allowed here: OAEP-SHA1 is still sound and is many
    // clients' default; 6.5 excludes SHA-1 only for signatures.
    const char* md = digest_name(op.hashAlg, true);
    if (md == nullptr || op.mgf != mgf_for(op.hashAlg)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (op.source != 0 && op.source != CKZ_DATA_SPECIFIED) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    auto label = span_of(static_cast<const CK_BYTE*>(op.pSourceData), op.ulSourceDataLen);
    if (!label) {
        return unexpected(label.error());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_get_digestbyname(md)) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_get_digestbyname(md)) != 1) {
        return fail();
    }
    if (!label->empty()) {
        // set0 takes ownership of an OPENSSL_malloc'd copy.
        auto* copy = static_cast<unsigned char*>(OPENSSL_memdup(label->data(), label->size()));
        if (copy == nullptr ||
            EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, static_cast<int>(label->size())) != 1) {
            OPENSSL_free(copy);
            return fail();
        }
    }
    return {};
}

[[nodiscard]] inline auto rsa_oaep(bool enc, const CK_MECHANISM& m, const key_material& k,
                                   std::span<const std::uint8_t> in, CK_RV bad_input)
    -> ck_result<bytes> {
    if (auto t = require_type(k, CKK_RSA); !t) {
        return unexpected(t.error());
    }
    auto key = enc ? load_public(k) : load_private(k);
    if (!key) {
        return unexpected(key.error());
    }
    detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
    if (!ctx || (enc ? EVP_PKEY_encrypt_init(ctx.get()) : EVP_PKEY_decrypt_init(ctx.get())) != 1) {
        return fail();
    }
    if (auto s = oaep_setup(ctx.get(), m); !s) {
        return unexpected(s.error());
    }
    bytes out(static_cast<std::size_t>(EVP_PKEY_get_size(key->get())));
    std::size_t len = out.size();
    if (!enc && in.size() != out.size()) {
        return unexpected(bad_input == CKR_ENCRYPTED_DATA_INVALID ? CKR_ENCRYPTED_DATA_LEN_RANGE
                                                                  : CKR_WRAPPED_KEY_LEN_RANGE);
    }
    const int ok = enc ? EVP_PKEY_encrypt(ctx.get(), out.data(), &len, in.data(), in.size())
                       : EVP_PKEY_decrypt(ctx.get(), out.data(), &len, in.data(), in.size());
    if (ok != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        return unexpected(enc ? CKR_DATA_LEN_RANGE : bad_input);
    }
    out.resize(len);
    return out;
}

[[nodiscard]] inline auto cipher(bool enc, bool wrapping, const CK_MECHANISM& m,
                                 const key_material& k, std::span<const std::uint8_t> in)
    -> ck_result<bytes> {
    const CK_RV bad_input = wrapping ? CKR_WRAPPED_KEY_INVALID : CKR_ENCRYPTED_DATA_INVALID;
    switch (m.mechanism) {
        case CKM_AES_GCM:
        case CKM_AES_CBC_PAD: {
            if (auto r = aes_key_ok(k); !r) {
                return unexpected(r.error());
            }
            auto out =
                m.mechanism == CKM_AES_GCM ? aes_gcm(enc, m, k, in) : aes_cbc_pad(enc, m, k, in);
            if (!out && wrapping && !enc &&
                (out.error() == CKR_ENCRYPTED_DATA_INVALID ||
                 out.error() == CKR_ENCRYPTED_DATA_LEN_RANGE)) {
                return unexpected(out.error() == CKR_ENCRYPTED_DATA_INVALID
                                      ? CKR_WRAPPED_KEY_INVALID
                                      : CKR_WRAPPED_KEY_LEN_RANGE);
            }
            return out;
        }
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_KWP:
            if (!wrapping) {
                // PKCS#11 allows C_Encrypt with key wrap mechanisms; this token
                // keeps them for wrapping, where the attribute policy applies.
                return unexpected(CKR_MECHANISM_INVALID);
            }
            if (auto r = aes_key_ok(k); !r) {
                return unexpected(r.error());
            }
            return aes_kw(enc, m.mechanism == CKM_AES_KEY_WRAP_KWP, m, k, in);
        case CKM_RSA_PKCS_OAEP:
            return rsa_oaep(enc, m, k, in, bad_input);
        default:
            return unexpected(CKR_MECHANISM_INVALID);
    }
}

}  // namespace detail

/// C_Encrypt: CKM_AES_GCM (ciphertext || tag), CKM_AES_CBC_PAD,
/// CKM_RSA_PKCS_OAEP with a public key.
[[nodiscard]] inline auto encrypt(const CK_MECHANISM& m, const key_material& k,
                                  std::span<const std::uint8_t> plain) -> ck_result<bytes> {
    return detail::cipher(true, false, m, k, plain);
}

/// C_Decrypt. A failed GCM tag, CBC padding or OAEP decoding is
/// CKR_ENCRYPTED_DATA_INVALID, with nothing returned.
[[nodiscard]] inline auto decrypt(const CK_MECHANISM& m, const key_material& k,
                                  std::span<const std::uint8_t> ct) -> ck_result<secret_bytes> {
    auto out = detail::cipher(false, false, m, k, ct);
    if (!out) {
        return unexpected(out.error());
    }
    secret_bytes plain(*out);
    OPENSSL_cleanse(out->data(), out->size());
    return plain;
}

/// The cryptographic half of C_WrapKey: encrypts a key's bytes (a secret
/// key's value or a private key's PKCS#8) under the wrapping key. The
/// attribute policy (CKA_EXTRACTABLE, CKA_WRAP, CKA_WRAP_WITH_TRUSTED,
/// CKA_WRAP_TEMPLATE) is checked before this is called.
[[nodiscard]] inline auto wrap(const CK_MECHANISM& m, const key_material& wrapping_key,
                               std::span<const std::uint8_t> key_bytes) -> ck_result<bytes> {
    return detail::cipher(true, true, m, wrapping_key, key_bytes);
}

/// The cryptographic half of C_UnwrapKey. Any authentication or padding
/// failure is CKR_WRAPPED_KEY_INVALID.
[[nodiscard]] inline auto unwrap(const CK_MECHANISM& m, const key_material& unwrapping_key,
                                 std::span<const std::uint8_t> wrapped) -> ck_result<secret_bytes> {
    auto out = detail::cipher(false, true, m, unwrapping_key, wrapped);
    if (!out) {
        return unexpected(out.error());
    }
    secret_bytes key(*out);
    OPENSSL_cleanse(out->data(), out->size());
    return key;
}

// --- Key derivation ---------------------------------------------------------

namespace detail {

[[nodiscard]] inline auto ecdh(const CK_MECHANISM& m, const key_material& k, CK_ULONG out_len)
    -> ck_result<secret_bytes> {
    auto params = param_as<CK_ECDH1_DERIVE_PARAMS>(m);
    if (!params) {
        return unexpected(params.error());
    }
    const auto& ep = **params;
    // Only the raw shared secret: KDFs belong to HKDF, applied after.
    if (ep.kdf != CKD_NULL || ep.ulSharedDataLen != 0) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    auto peer_point = span_of(ep.pPublicData, ep.ulPublicDataLen);
    if (!peer_point || peer_point->empty()) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (auto t = require_type(k, CKK_EC); !t) {
        return unexpected(t.error());
    }
    auto key = load_private(k);
    if (!key) {
        return unexpected(key.error());
    }
    const auto point = strip_octet_string(*peer_point);
    const std::string group = group_name(key->get());
    std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, group.c_str(), 0) !=
            1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                         point.size()) != 1) {
        return fail();
    }
    std::unique_ptr<OSSL_PARAM, params_free> ossl_params(OSSL_PARAM_BLD_to_param(bld.get()));
    pkey_ctx_ptr from(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY* raw_peer = nullptr;
    if (!ossl_params || !from || EVP_PKEY_fromdata_init(from.get()) != 1 ||
        EVP_PKEY_fromdata(from.get(), &raw_peer, EVP_PKEY_PUBLIC_KEY, ossl_params.get()) != 1) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    pkey_ptr peer(raw_peer);
    // A point not on the curve is refused by the public key check.
    pkey_ctx_ptr check(EVP_PKEY_CTX_new_from_pkey(nullptr, peer.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key->get(), nullptr));
    std::size_t len = 0;
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) {
        return fail();
    }
    secret_bytes z(len);
    if (EVP_PKEY_derive(ctx.get(), z.data(), &len) != 1) {
        return fail();
    }
    if (out_len == 0 || out_len == len) {
        return z;
    }
    if (out_len > len) {
        return unexpected(CKR_KEY_SIZE_RANGE);
    }
    // CKD_NULL with a shorter CKA_VALUE_LEN keeps the leading bytes.
    return secret_bytes(z.view().first(static_cast<std::size_t>(out_len)));
}

[[nodiscard]] inline auto hkdf(const CK_MECHANISM& m, const key_material& k, CK_ULONG out_len)
    -> ck_result<secret_bytes> {
    auto params = param_as<CK_HKDF_PARAMS>(m);
    if (!params) {
        return unexpected(params.error());
    }
    const auto& hp = **params;
    const char* md = digest_name(hp.prfHashMechanism);
    if (md == nullptr || (hp.bExtract == CK_FALSE && hp.bExpand == CK_FALSE)) {
        return unexpected(CKR_MECHANISM_PARAM_INVALID);
    }
    if (k.object_class != CKO_SECRET_KEY ||
        (k.key_type != CKK_GENERIC_SECRET && k.key_type != CKK_HKDF && k.key_type != CKK_AES)) {
        return unexpected(CKR_KEY_TYPE_INCONSISTENT);
    }
    std::span<const std::uint8_t> salt;
    if (hp.bExtract != CK_FALSE) {
        if (hp.ulSaltType == CKF_HKDF_SALT_DATA) {
            auto s = span_of(hp.pSalt, hp.ulSaltLen);
            if (!s || s->empty()) {
                return unexpected(CKR_MECHANISM_PARAM_INVALID);
            }
            salt = *s;
        } else if (hp.ulSaltType != CKF_HKDF_SALT_NULL) {
            // CKF_HKDF_SALT_KEY names a key handle; the session layer
            // resolves handles, and no consumer needs it yet.
            return unexpected(CKR_MECHANISM_PARAM_INVALID);
        }
    }
    auto info = span_of(hp.pInfo, hp.ulInfoLen);
    if (!info) {
        return unexpected(info.error());
    }
    const auto hash_len = static_cast<std::size_t>(EVP_MD_get_size(EVP_get_digestbyname(md)));
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    std::size_t len = out_len;
    if (hp.bExpand == CK_FALSE) {
        mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        if (len == 0) {
            len = hash_len;
        }
        if (len != hash_len) {
            return unexpected(CKR_KEY_SIZE_RANGE);
        }
    } else {
        if (hp.bExtract == CK_FALSE) {
            mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        }
        if (len == 0 || len > 255 * hash_len) {
            return unexpected(CKR_KEY_SIZE_RANGE);
        }
    }
    std::unique_ptr<EVP_KDF, kdf_free> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    std::unique_ptr<EVP_KDF_CTX, kdf_ctx_free> ctx(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr);
    if (!ctx) {
        return fail();
    }
    std::array<OSSL_PARAM, 6> ps{};
    std::size_t n = 0;
    std::string md_name(md);
    ps.at(n++) = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name.data(), 0);
    ps.at(n++) = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    ps.at(n++) = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(k.secret.data()), k.secret.size());
    if (!salt.empty()) {
        ps.at(n++) = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()), salt.size());
    }
    if (!info->empty()) {
        ps.at(n++) = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t*>(info->data()), info->size());
    }
    ps.at(n) = OSSL_PARAM_construct_end();
    secret_bytes out(len);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), ps.data()) != 1) {
        return fail();
    }
    return out;
}

}  // namespace detail

/// C_DeriveKey's cryptography: CKM_ECDH1_DERIVE (CKD_NULL) and
/// CKM_HKDF_DERIVE / CKM_HKDF_DATA. `out_len` is the new key's
/// CKA_VALUE_LEN (0 = the mechanism's natural length).
[[nodiscard]] inline auto derive(const CK_MECHANISM& m, const key_material& base, CK_ULONG out_len)
    -> ck_result<secret_bytes> {
    switch (m.mechanism) {
        case CKM_ECDH1_DERIVE:
            return detail::ecdh(m, base, out_len);
        case CKM_HKDF_DERIVE:
        case CKM_HKDF_DATA:
            return detail::hkdf(m, base, out_len);
        default:
            return unexpected(CKR_MECHANISM_INVALID);
    }
}

}  // namespace kythira::hsm
