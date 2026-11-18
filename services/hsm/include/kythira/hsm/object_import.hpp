// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Objects that arrive from outside the token or are made from another key
// (requirement 6.1, 6.3): C_CreateObject, C_UnwrapKey and C_DeriveKey's
// new objects, built the way key_store.hpp builds generated ones: the
// final attributes in an object record, and the secret part (a secret
// key's value, a private key's PKCS#8, a data object's value) apart from
// them, to be sealed for a token object or kept in memory for a session
// object. No secret attribute is ever left in the record: the record is
// what the Raft log and snapshots hold.
//
// Private keys are given as PKCS#11 has them (RSA's modulus, exponents,
// primes and CRT values; an EC or Ed25519 key's CKA_EC_PARAMS and
// CKA_VALUE) and stored as PKCS#8, which is what the mechanisms load.
// Public keys are given as components and stored as SubjectPublicKeyInfo.
// Certificates are public and keep CKA_VALUE in the record.
//
// The caller has applied the session rules (check_new_object in
// session_layer.hpp) and, for unwrap and derive, the source key's
// template; these functions check what the object itself must satisfy.

#include <kythira/hsm/attribute_policy.hpp>
#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/mechanisms.hpp>
#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/secret_bytes.hpp>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>

namespace kythira::hsm {

namespace detail {

struct ec_group_free {
    void operator()(EC_GROUP* p) const noexcept { EC_GROUP_free(p); }
};
struct ec_point_free {
    void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); }
};
struct bn_ctx_free {
    void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); }
};
struct bn_clear_free {
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
using bn_secret = std::unique_ptr<BIGNUM, bn_clear_free>;

[[nodiscard]] inline auto bn_of(std::span<const std::uint8_t> v) -> bn_secret {
    return bn_secret(BN_bin2bn(v.data(), static_cast<int>(v.size()), nullptr));
}

/// An EVP_PKEY of `name` from `params` (`selection` as for
/// EVP_PKEY_fromdata).
[[nodiscard]] inline auto pkey_from_params(const char* name, OSSL_PARAM_BLD* bld, int selection)
    -> ck_result<pkey_ptr> {
    std::unique_ptr<OSSL_PARAM, params_free> params(OSSL_PARAM_BLD_to_param(bld));
    std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, name, nullptr));
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, selection, params.get()) != 1) {
        return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    return pkey_ptr(raw);
}

/// The attribute, or CKR_TEMPLATE_INCOMPLETE.
[[nodiscard]] inline auto required(const attribute_map& t, CK_ATTRIBUTE_TYPE type)
    -> ck_result<std::span<const std::uint8_t>> {
    auto v = t.bytes(type);
    if (!v || v->empty()) {
        return unexpected(CKR_TEMPLATE_INCOMPLETE);
    }
    return *v;
}

/// The uncompressed point of `priv` on `group` (OpenSSL does not derive
/// it when an EC key is built from its scalar alone).
[[nodiscard]] inline auto ec_public_point(const char* group, const BIGNUM* priv)
    -> ck_result<bytes> {
    const int nid = OBJ_sn2nid(group) != NID_undef ? OBJ_sn2nid(group) : EC_curve_nist2nid(group);
    std::unique_ptr<EC_GROUP, ec_group_free> g(EC_GROUP_new_by_curve_name(nid));
    std::unique_ptr<BN_CTX, bn_ctx_free> bctx(BN_CTX_new());
    if (!g || !bctx) {
        return fail();
    }
    std::unique_ptr<EC_POINT, ec_point_free> pt(EC_POINT_new(g.get()));
    if (!pt || EC_POINT_mul(g.get(), pt.get(), priv, nullptr, nullptr, bctx.get()) != 1) {
        return fail();
    }
    const std::size_t len = EC_POINT_point2oct(g.get(), pt.get(), POINT_CONVERSION_UNCOMPRESSED,
                                               nullptr, 0, bctx.get());
    bytes out(len);
    if (len == 0 || EC_POINT_point2oct(g.get(), pt.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(),
                                       out.size(), bctx.get()) != len) {
        return fail();
    }
    return out;
}

/// A private key from its PKCS#11 components.
[[nodiscard]] inline auto private_key_from(CK_KEY_TYPE type, const attribute_map& t)
    -> ck_result<pkey_ptr> {
    switch (type) {
        case CKK_RSA: {
            std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
            if (!bld) {
                return fail();
            }
            std::vector<bn_secret> keep;
            struct component {
                CK_ATTRIBUTE_TYPE attr;
                const char* param;
                bool needed;
            };
            for (const auto& c :
                 {component{CKA_MODULUS, OSSL_PKEY_PARAM_RSA_N, true},
                  component{CKA_PUBLIC_EXPONENT, OSSL_PKEY_PARAM_RSA_E, true},
                  component{CKA_PRIVATE_EXPONENT, OSSL_PKEY_PARAM_RSA_D, true},
                  component{CKA_PRIME_1, OSSL_PKEY_PARAM_RSA_FACTOR1, false},
                  component{CKA_PRIME_2, OSSL_PKEY_PARAM_RSA_FACTOR2, false},
                  component{CKA_EXPONENT_1, OSSL_PKEY_PARAM_RSA_EXPONENT1, false},
                  component{CKA_EXPONENT_2, OSSL_PKEY_PARAM_RSA_EXPONENT2, false},
                  component{CKA_COEFFICIENT, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, false}}) {
                auto v = t.bytes(c.attr);
                if (!v || v->empty()) {
                    if (c.needed) {
                        return unexpected(CKR_TEMPLATE_INCOMPLETE);
                    }
                    continue;
                }
                keep.push_back(bn_of(*v));
                if (!keep.back() ||
                    OSSL_PARAM_BLD_push_BN(bld.get(), c.param, keep.back().get()) != 1) {
                    return fail();
                }
            }
            auto key = pkey_from_params("RSA", bld.get(), EVP_PKEY_KEYPAIR);
            if (key) {
                const int bits = EVP_PKEY_get_bits(key->get());
                if (bits < 2048 || bits > 4096) {
                    return unexpected(CKR_KEY_SIZE_RANGE);
                }
            }
            return key;
        }
        case CKK_EC: {
            auto params = required(t, CKA_EC_PARAMS);
            auto value = required(t, CKA_VALUE);
            if (!params || !value) {
                return unexpected(CKR_TEMPLATE_INCOMPLETE);
            }
            auto c = curve_from_params(*params);
            if (!c || c->key_type != CKK_EC) {
                return unexpected(CKR_CURVE_NOT_SUPPORTED);
            }
            auto priv = bn_of(*value);
            if (!priv) {
                return fail();
            }
            auto point = ec_public_point(c->group, priv.get());
            if (!point) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
            if (!bld ||
                OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, c->group,
                                                0) != 1 ||
                OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv.get()) != 1 ||
                OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point->data(),
                                                 point->size()) != 1) {
                return fail();
            }
            return pkey_from_params("EC", bld.get(), EVP_PKEY_KEYPAIR);
        }
        case CKK_EC_EDWARDS: {
            auto params = required(t, CKA_EC_PARAMS);
            auto value = required(t, CKA_VALUE);
            if (!params || !value) {
                return unexpected(CKR_TEMPLATE_INCOMPLETE);
            }
            auto c = curve_from_params(*params);
            if (!c || c->key_type != CKK_EC_EDWARDS) {
                return unexpected(CKR_CURVE_NOT_SUPPORTED);
            }
            pkey_ptr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, value->data(),
                                                      value->size()));
            if (!key) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            return key;
        }
        default:
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
}

/// A public key from its PKCS#11 components.
[[nodiscard]] inline auto public_key_from(CK_KEY_TYPE type, const attribute_map& t)
    -> ck_result<pkey_ptr> {
    switch (type) {
        case CKK_RSA: {
            auto n = required(t, CKA_MODULUS);
            auto e = required(t, CKA_PUBLIC_EXPONENT);
            if (!n || !e) {
                return unexpected(CKR_TEMPLATE_INCOMPLETE);
            }
            auto bn_n = bn_of(*n);
            auto bn_e = bn_of(*e);
            std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
            if (!bld || !bn_n || !bn_e ||
                OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get()) != 1 ||
                OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get()) != 1) {
                return fail();
            }
            return pkey_from_params("RSA", bld.get(), EVP_PKEY_PUBLIC_KEY);
        }
        case CKK_EC:
        case CKK_EC_EDWARDS: {
            auto params = required(t, CKA_EC_PARAMS);
            auto point = required(t, CKA_EC_POINT);
            if (!params || !point) {
                return unexpected(CKR_TEMPLATE_INCOMPLETE);
            }
            auto c = curve_from_params(*params);
            if (!c || c->key_type != type) {
                return unexpected(CKR_CURVE_NOT_SUPPORTED);
            }
            const auto raw = ec_point_contents(*point, *c);
            if (type == CKK_EC_EDWARDS) {
                pkey_ptr key(
                    EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw.data(), raw.size()));
                if (!key) {
                    return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
                }
                return key;
            }
            std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
            if (!bld ||
                OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, c->group,
                                                0) != 1 ||
                OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, raw.data(),
                                                 raw.size()) != 1) {
                return fail();
            }
            return pkey_from_params("EC", bld.get(), EVP_PKEY_PUBLIC_KEY);
        }
        default:
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
}

/// Every attribute that may hold secret material, out of `t`.
inline void strip_secret_attributes(attribute_map& t) {
    for (CK_ATTRIBUTE_TYPE type : {CKA_VALUE, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
                                   CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT}) {
        t.erase(type);
    }
}

[[nodiscard]] inline auto class_of(const attribute_map& t) -> ck_result<CK_OBJECT_CLASS> {
    auto cls = t.get_ulong(CKA_CLASS);
    if (!cls) {
        return unexpected(cls.error());
    }
    if (!*cls) {
        return unexpected(CKR_TEMPLATE_INCOMPLETE);
    }
    return **cls;
}

[[nodiscard]] inline auto key_type_of(const attribute_map& t) -> ck_result<CK_KEY_TYPE> {
    auto type = t.get_ulong(CKA_KEY_TYPE);
    if (!type) {
        return unexpected(type.error());
    }
    if (!*type) {
        return unexpected(CKR_TEMPLATE_INCOMPLETE);
    }
    return **type;
}

/// A secret key's length rule: AES is 16, 24 or 32 bytes; generic and
/// HKDF secrets 1 to 512.
[[nodiscard]] inline auto check_secret_length(CK_KEY_TYPE type, std::size_t len)
    -> ck_result<void> {
    switch (type) {
        case CKK_AES:
            if (len != 16 && len != 24 && len != 32) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            return {};
        case CKK_GENERIC_SECRET:
        case CKK_HKDF:
            if (len == 0 || len > 512) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            return {};
        default:
            return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
}

/// A secret key record around `value`, with CKA_VALUE_LEN set from it.
[[nodiscard]] inline auto secret_key_object(attribute_map t, secret_bytes value, key_origin origin,
                                            const attribute_map* base) -> ck_result<built_object> {
    auto type = key_type_of(t);
    if (!type) {
        return unexpected(type.error());
    }
    if (auto r = check_secret_length(*type, value.size()); !r) {
        return unexpected(r.error());
    }
    auto given = t.get_ulong(CKA_VALUE_LEN);
    if (!given) {
        return unexpected(given.error());
    }
    if (*given && **given != value.size()) {
        return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
    strip_secret_attributes(t);
    t.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    t.set_ulong(CKA_VALUE_LEN, static_cast<CK_ULONG>(value.size()));
    apply_key_defaults(t);
    set_origin_flags(t, origin, base);
    built_object out;
    out.record.attributes = std::move(t);
    out.material = std::move(value);
    return out;
}

/// A private key record from an OpenSSL key: its PKCS#8 as the material,
/// and the public attributes and SPKI the mechanisms and callers need.
[[nodiscard]] inline auto private_key_object(attribute_map t, EVP_PKEY* key, key_origin origin)
    -> ck_result<built_object> {
    auto pair = describe(key);
    if (!pair) {
        return unexpected(pair.error());
    }
    auto pkcs8 = encode_pkcs8(key);
    if (!pkcs8) {
        return unexpected(pkcs8.error());
    }
    auto type = t.get_ulong(CKA_KEY_TYPE);
    if (!type) {
        return unexpected(type.error());
    }
    if (*type && **type != pair->key_type) {
        return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
    strip_secret_attributes(t);
    for (CK_ATTRIBUTE_TYPE a : {CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS}) {
        if (auto v = pair->public_attributes.bytes(a)) {
            t.set_bytes(a, *v);
        }
    }
    t.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    t.set_ulong(CKA_KEY_TYPE, pair->key_type);
    apply_key_defaults(t);
    set_origin_flags(t, origin);
    built_object out;
    out.record.attributes = std::move(t);
    out.record.public_der = std::move(pair->public_spki);
    out.material = std::move(*pkcs8);
    return out;
}

}  // namespace detail

/// C_CreateObject: a secret, private or public key, a data object or an
/// X.509 certificate from the caller's template.
[[nodiscard]] inline auto build_created_object(const attribute_map& tmpl)
    -> ck_result<built_object> {
    if (auto r = check_caller_settable(tmpl); !r) {
        return unexpected(r.error());
    }
    auto cls = detail::class_of(tmpl);
    if (!cls) {
        return unexpected(cls.error());
    }
    switch (*cls) {
        case CKO_SECRET_KEY: {
            auto value = detail::required(tmpl, CKA_VALUE);
            if (!value) {
                return unexpected(value.error());
            }
            return detail::secret_key_object(tmpl, secret_bytes(*value), key_origin::created,
                                             nullptr);
        }
        case CKO_PRIVATE_KEY: {
            auto type = detail::key_type_of(tmpl);
            if (!type) {
                return unexpected(type.error());
            }
            auto key = detail::private_key_from(*type, tmpl);
            if (!key) {
                return unexpected(key.error());
            }
            return detail::private_key_object(tmpl, key->get(), key_origin::created);
        }
        case CKO_PUBLIC_KEY: {
            auto type = detail::key_type_of(tmpl);
            if (!type) {
                return unexpected(type.error());
            }
            auto key = detail::public_key_from(*type, tmpl);
            if (!key) {
                return unexpected(key.error());
            }
            auto spki = detail::encode_spki(key->get());
            if (!spki) {
                return unexpected(spki.error());
            }
            built_object out;
            out.record.attributes = tmpl;
            out.record.attributes.set_bool(CKA_LOCAL, false);
            detail::apply_public_defaults(out.record.attributes);
            out.record.public_der = std::move(*spki);
            return out;
        }
        case CKO_DATA: {
            built_object out;
            auto value = tmpl.bytes(CKA_VALUE);
            out.material = value ? secret_bytes(*value) : secret_bytes{};
            out.record.attributes = tmpl;
            out.record.attributes.erase(CKA_VALUE);
            return out;
        }
        case CKO_CERTIFICATE: {
            auto type = tmpl.get_ulong(CKA_CERTIFICATE_TYPE);
            if (!type) {
                return unexpected(type.error());
            }
            if (!*type || !detail::required(tmpl, CKA_VALUE)) {
                return unexpected(CKR_TEMPLATE_INCOMPLETE);
            }
            if (**type != CKC_X_509) {
                return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            built_object out;
            out.record.attributes = tmpl;
            return out;
        }
        default:
            return unexpected(CKR_ATTRIBUTE_VALUE_INVALID);
    }
}

/// C_UnwrapKey's new key: `key_bytes` is a secret key's value or a private
/// key's PKCS#8. `tmpl` already carries the unwrapping key's template.
[[nodiscard]] inline auto build_unwrapped_key(const attribute_map& tmpl, secret_bytes key_bytes)
    -> ck_result<built_object> {
    if (auto r = check_caller_settable(tmpl); !r) {
        return unexpected(r.error());
    }
    auto cls = detail::class_of(tmpl);
    if (!cls) {
        return unexpected(cls.error());
    }
    if (*cls == CKO_SECRET_KEY) {
        return detail::secret_key_object(tmpl, std::move(key_bytes), key_origin::unwrapped,
                                         nullptr);
    }
    if (*cls != CKO_PRIVATE_KEY) {
        return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
    const unsigned char* p = key_bytes.data();
    detail::pkey_ptr key(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(key_bytes.size())));
    if (!key || p != key_bytes.data() + key_bytes.size()) {
        return unexpected(CKR_WRAPPED_KEY_INVALID);
    }
    return detail::private_key_object(tmpl, key.get(), key_origin::unwrapped);
}

/// C_DeriveKey's new object: a secret key, or a data object for
/// CKM_HKDF_DATA. `tmpl` already carries the base key's template.
[[nodiscard]] inline auto build_derived_object(const attribute_map& tmpl, secret_bytes value,
                                               const attribute_map& base)
    -> ck_result<built_object> {
    if (auto r = check_caller_settable(tmpl); !r) {
        return unexpected(r.error());
    }
    auto cls = detail::class_of(tmpl);
    if (!cls) {
        return unexpected(cls.error());
    }
    if (*cls == CKO_DATA) {
        built_object out;
        out.record.attributes = tmpl;
        out.record.attributes.erase(CKA_VALUE);
        out.material = std::move(value);
        return out;
    }
    if (*cls != CKO_SECRET_KEY) {
        return unexpected(CKR_TEMPLATE_INCONSISTENT);
    }
    attribute_map t = tmpl;
    if (!t.has(CKA_KEY_TYPE)) {
        t.set_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    }
    return detail::secret_key_object(std::move(t), std::move(value), key_origin::derived, &base);
}

/// Whether an object of this class keeps sealed material in its record.
[[nodiscard]] constexpr auto has_material(CK_OBJECT_CLASS cls) noexcept -> bool {
    return cls == CKO_SECRET_KEY || cls == CKO_PRIVATE_KEY || cls == CKO_DATA;
}

}  // namespace kythira::hsm
