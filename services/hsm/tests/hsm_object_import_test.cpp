// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 6b, requirements 6.1, 6.3, 6.4 and 3.2: objects that come from
// outside the token or from another key, through the session layer:
// C_CreateObject for every class, C_CopyObject, C_WrapKey, C_UnwrapKey and
// C_DeriveKey, with their attribute rules, and no secret part ever in an
// entry or the engine.

#define BOOST_TEST_MODULE hsm_object_import_test
#include <boost/test/unit_test.hpp>

#include "hsm_test_node.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

struct pkey_free {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using pkey = std::unique_ptr<EVP_PKEY, pkey_free>;

auto bn_bytes(EVP_PKEY* key, const char* name) -> hsm::bytes {
    BIGNUM* bn = nullptr;
    BOOST_REQUIRE(EVP_PKEY_get_bn_param(key, name, &bn) == 1);
    hsm::bytes out(static_cast<std::size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, out.data());
    BN_clear_free(bn);
    return out;
}

auto octets(EVP_PKEY* key, const char* name) -> hsm::bytes {
    std::array<unsigned char, 256> buf{};
    std::size_t len = 0;
    BOOST_REQUIRE(EVP_PKEY_get_octet_string_param(key, name, buf.data(), buf.size(), &len) == 1);
    return {buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(len)};
}

auto contains(std::span<const std::uint8_t> hay, std::span<const std::uint8_t> needle) -> bool {
    return std::ranges::search(hay, needle).begin() != hay.end();
}

/// No entry the node proposed and no engine value holds `secret`.
void expect_nowhere(node& n, std::span<const std::uint8_t> secret) {
    for (const auto& entry : n.store.log) {
        BOOST_TEST(!contains(
            std::span(reinterpret_cast<const std::uint8_t*>(entry.data()), entry.size()), secret));
    }
    n.store.engine().scan(
        kythira::column_family::data, kythira::key_range{"", std::nullopt},
        kythira::scan_direction::forward, [&](std::string_view, std::string_view v) {
            BOOST_TEST(!contains(
                std::span(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()), secret));
            return true;
        });
}

auto aes_object(std::span<const std::uint8_t> value, bool token = true) -> hsm::attribute_map {
    hsm::attribute_map t;
    t.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    t.set_ulong(CKA_KEY_TYPE, CKK_AES);
    t.set_bool(CKA_TOKEN, token);
    t.set_bool(CKA_ENCRYPT, true);
    t.set_bool(CKA_DECRYPT, true);
    t.set_bytes(CKA_VALUE, value);
    return t;
}

auto gcm_encrypt(node& n, CK_OBJECT_HANDLE key, std::string_view msg) -> hsm::bytes {
    std::array<std::uint8_t, 12> iv{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    CK_GCM_PARAMS gcm{iv.data(), iv.size(), 96, nullptr, 0, 128};
    const CK_MECHANISM mech{CKM_AES_GCM, &gcm, sizeof gcm};
    BOOST_REQUIRE(rv(n.client->encrypt_init(n.session, mech, key)) == CKR_OK);
    auto ct = n.client->encrypt(n.session, data(msg));
    BOOST_REQUIRE(ct.has_value());
    return *ct;
}

auto attr(node& n, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_TYPE type) -> hsm::attribute_value {
    auto v = n.client->get_attribute_value(n.session, o, std::array<CK_ATTRIBUTE_TYPE, 1>{type});
    BOOST_REQUIRE(v.has_value());
    return (*v)[0];
}

auto flag(node& n, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_TYPE type) -> bool {
    auto v = attr(n, o, type);
    BOOST_REQUIRE(v.value.has_value());
    return !v.value->empty() && (*v.value)[0] != CK_FALSE;
}

}  // namespace

BOOST_AUTO_TEST_CASE(secret_keys_are_created_sealed_and_usable) {
    node n;
    hsm::bytes value(32, 0x5A);
    auto key = n.client->create_object(n.session, aes_object(value));
    BOOST_REQUIRE(key.has_value());
    auto stored = n.store.object(k_token, *key);
    BOOST_REQUIRE(stored.has_value());
    BOOST_TEST(!stored->attributes.has(CKA_VALUE));
    BOOST_TEST(!stored->sealed.empty());
    BOOST_TEST(*stored->attributes.get_ulong(CKA_VALUE_LEN).value() == 32U);
    // Created keys have been outside the token.
    BOOST_TEST(!flag(n, *key, CKA_LOCAL));
    BOOST_TEST(!flag(n, *key, CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(flag(n, *key, CKA_SENSITIVE));
    expect_nowhere(n, value);

    // The same value as a session object encrypts identically.
    auto twin = n.client->create_object(n.session, aes_object(value, false));
    BOOST_REQUIRE(twin.has_value());
    BOOST_TEST(gcm_encrypt(n, *key, "same") == gcm_encrypt(n, *twin, "same"));

    hsm::bytes bad(20, 1);
    BOOST_TEST(rv(n.client->create_object(n.session, aes_object(bad))) ==
               CKR_ATTRIBUTE_VALUE_INVALID);
    auto no_value = aes_object(value);
    no_value.erase(CKA_VALUE);
    BOOST_TEST(rv(n.client->create_object(n.session, no_value)) == CKR_TEMPLATE_INCOMPLETE);
    auto wrong_len = aes_object(value);
    wrong_len.set_ulong(CKA_VALUE_LEN, 16);
    BOOST_TEST(rv(n.client->create_object(n.session, wrong_len)) == CKR_TEMPLATE_INCONSISTENT);
    hsm::attribute_map no_class;
    BOOST_TEST(rv(n.client->create_object(n.session, no_class)) == CKR_TEMPLATE_INCOMPLETE);
    // Token-set attributes are not the caller's to give.
    auto local = aes_object(value);
    local.set_bool(CKA_LOCAL, true);
    BOOST_TEST(rv(n.client->create_object(n.session, local)) == CKR_ATTRIBUTE_READ_ONLY);
}

BOOST_AUTO_TEST_CASE(ec_keys_are_created_from_their_components) {
    node n;
    pkey key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    BOOST_REQUIRE(key);
    const auto scalar = bn_bytes(key.get(), OSSL_PKEY_PARAM_PRIV_KEY);
    const auto point = octets(key.get(), OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    hsm::attribute_map priv;
    priv.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    priv.set_ulong(CKA_KEY_TYPE, CKK_EC);
    priv.set_bool(CKA_TOKEN, true);
    priv.set_bool(CKA_SIGN, true);
    priv.set_bytes(CKA_EC_PARAMS, k_p256);
    priv.set_bytes(CKA_VALUE, scalar);
    auto h_priv = n.client->create_object(n.session, priv);
    BOOST_REQUIRE(h_priv.has_value());

    hsm::attribute_map pub;
    pub.set_ulong(CKA_CLASS, CKO_PUBLIC_KEY);
    pub.set_ulong(CKA_KEY_TYPE, CKK_EC);
    pub.set_bool(CKA_TOKEN, true);
    pub.set_bool(CKA_VERIFY, true);
    pub.set_bytes(CKA_EC_PARAMS, k_p256);
    pub.set_bytes(CKA_EC_POINT, point);  // raw form; the DER form works too
    auto h_pub = n.client->create_object(n.session, pub);
    BOOST_REQUIRE(h_pub.has_value());

    auto sig = n.sign(*h_priv, "imported");
    BOOST_REQUIRE(sig.has_value());
    BOOST_REQUIRE(rv(n.client->verify_init(n.session, k_ecdsa, *h_pub)) == CKR_OK);
    BOOST_TEST(rv(n.client->verify(n.session, data("imported"), *sig)) == CKR_OK);

    auto stored = n.store.object(k_token, *h_priv);
    BOOST_REQUIRE(stored.has_value());
    BOOST_TEST(!stored->attributes.has(CKA_VALUE));
    BOOST_TEST(stored->attributes.has(CKA_EC_PARAMS));
    BOOST_TEST(!stored->public_der.empty());
    expect_nowhere(n, scalar);

    auto other_curve = priv;
    other_curve.set_bytes(CKA_EC_PARAMS, hsm::bytes{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A});
    BOOST_TEST(rv(n.client->create_object(n.session, other_curve)) == CKR_CURVE_NOT_SUPPORTED);
    auto mismatched = priv;
    mismatched.set_ulong(CKA_KEY_TYPE, CKK_RSA);
    BOOST_TEST(rv(n.client->create_object(n.session, mismatched)) == CKR_TEMPLATE_INCOMPLETE);
}

BOOST_AUTO_TEST_CASE(rsa_and_ed25519_keys_are_created_from_their_components) {
    node n;
    pkey rsa(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", std::size_t{2048}));
    BOOST_REQUIRE(rsa);
    hsm::attribute_map priv;
    priv.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    priv.set_ulong(CKA_KEY_TYPE, CKK_RSA);
    priv.set_bool(CKA_SIGN, true);
    for (const auto& [type, name] :
         {std::pair{CKA_MODULUS, OSSL_PKEY_PARAM_RSA_N},
          std::pair{CKA_PUBLIC_EXPONENT, OSSL_PKEY_PARAM_RSA_E},
          std::pair{CKA_PRIVATE_EXPONENT, OSSL_PKEY_PARAM_RSA_D},
          std::pair{CKA_PRIME_1, OSSL_PKEY_PARAM_RSA_FACTOR1},
          std::pair{CKA_PRIME_2, OSSL_PKEY_PARAM_RSA_FACTOR2},
          std::pair{CKA_EXPONENT_1, OSSL_PKEY_PARAM_RSA_EXPONENT1},
          std::pair{CKA_EXPONENT_2, OSSL_PKEY_PARAM_RSA_EXPONENT2},
          std::pair{CKA_COEFFICIENT, OSSL_PKEY_PARAM_RSA_COEFFICIENT1}}) {
        priv.set_bytes(type, bn_bytes(rsa.get(), name));
    }
    auto h_priv = n.client->create_object(n.session, priv);
    BOOST_REQUIRE(h_priv.has_value());
    hsm::attribute_map pub;
    pub.set_ulong(CKA_CLASS, CKO_PUBLIC_KEY);
    pub.set_ulong(CKA_KEY_TYPE, CKK_RSA);
    pub.set_bool(CKA_VERIFY, true);
    pub.set_bytes(CKA_MODULUS, bn_bytes(rsa.get(), OSSL_PKEY_PARAM_RSA_N));
    pub.set_bytes(CKA_PUBLIC_EXPONENT, bn_bytes(rsa.get(), OSSL_PKEY_PARAM_RSA_E));
    auto h_pub = n.client->create_object(n.session, pub);
    BOOST_REQUIRE(h_pub.has_value());
    const CK_MECHANISM rsa_sign{CKM_SHA256_RSA_PKCS, nullptr, 0};
    BOOST_REQUIRE(rv(n.client->sign_init(n.session, rsa_sign, *h_priv)) == CKR_OK);
    auto sig = n.client->sign(n.session, data("rsa"));
    BOOST_REQUIRE(sig.has_value());
    BOOST_REQUIRE(rv(n.client->verify_init(n.session, rsa_sign, *h_pub)) == CKR_OK);
    BOOST_TEST(rv(n.client->verify(n.session, data("rsa"), *sig)) == CKR_OK);
    // The private exponent never reaches the store; the modulus is public.
    expect_nowhere(n, bn_bytes(rsa.get(), OSSL_PKEY_PARAM_RSA_D));
    BOOST_TEST(attr(n, *h_priv, CKA_PRIVATE_EXPONENT).rv == CKR_ATTRIBUTE_SENSITIVE);
    BOOST_TEST(attr(n, *h_priv, CKA_MODULUS).value.has_value());

    pkey small(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", std::size_t{1024}));
    auto weak = priv;
    weak.set_bytes(CKA_MODULUS, bn_bytes(small.get(), OSSL_PKEY_PARAM_RSA_N));
    weak.set_bytes(CKA_PUBLIC_EXPONENT, bn_bytes(small.get(), OSSL_PKEY_PARAM_RSA_E));
    weak.set_bytes(CKA_PRIVATE_EXPONENT, bn_bytes(small.get(), OSSL_PKEY_PARAM_RSA_D));
    weak.erase(CKA_PRIME_1);
    weak.erase(CKA_PRIME_2);
    weak.erase(CKA_EXPONENT_1);
    weak.erase(CKA_EXPONENT_2);
    weak.erase(CKA_COEFFICIENT);
    BOOST_TEST(rv(n.client->create_object(n.session, weak)) == CKR_KEY_SIZE_RANGE);

    pkey ed(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    BOOST_REQUIRE(ed);
    const hsm::bytes ed_params{0x06, 0x03, 0x2B, 0x65, 0x70};
    hsm::attribute_map ed_priv;
    ed_priv.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    ed_priv.set_ulong(CKA_KEY_TYPE, CKK_EC_EDWARDS);
    ed_priv.set_bool(CKA_SIGN, true);
    ed_priv.set_bytes(CKA_EC_PARAMS, ed_params);
    ed_priv.set_bytes(CKA_VALUE, octets(ed.get(), OSSL_PKEY_PARAM_PRIV_KEY));
    hsm::attribute_map ed_pub;
    ed_pub.set_ulong(CKA_CLASS, CKO_PUBLIC_KEY);
    ed_pub.set_ulong(CKA_KEY_TYPE, CKK_EC_EDWARDS);
    ed_pub.set_bool(CKA_VERIFY, true);
    ed_pub.set_bytes(CKA_EC_PARAMS, ed_params);
    ed_pub.set_bytes(CKA_EC_POINT, octets(ed.get(), OSSL_PKEY_PARAM_PUB_KEY));
    auto e_priv = n.client->create_object(n.session, ed_priv);
    auto e_pub = n.client->create_object(n.session, ed_pub);
    BOOST_REQUIRE(e_priv.has_value());
    BOOST_REQUIRE(e_pub.has_value());
    const CK_MECHANISM eddsa{CKM_EDDSA, nullptr, 0};
    BOOST_REQUIRE(rv(n.client->sign_init(n.session, eddsa, *e_priv)) == CKR_OK);
    auto esig = n.client->sign(n.session, data("ed"));
    BOOST_REQUIRE(esig.has_value());
    BOOST_REQUIRE(rv(n.client->verify_init(n.session, eddsa, *e_pub)) == CKR_OK);
    BOOST_TEST(rv(n.client->verify(n.session, data("ed"), *esig)) == CKR_OK);
}

BOOST_AUTO_TEST_CASE(data_objects_are_sealed_and_certificates_are_public) {
    node n;
    const auto secret = data("a data object's private value");
    hsm::attribute_map d;
    d.set_ulong(CKA_CLASS, CKO_DATA);
    d.set_bool(CKA_TOKEN, true);
    d.set_bool(CKA_PRIVATE, true);
    d.set_bytes(CKA_APPLICATION, data("tests"));
    d.set_bytes(CKA_VALUE, secret);
    auto h = n.client->create_object(n.session, d);
    BOOST_REQUIRE(h.has_value());
    auto v = attr(n, *h, CKA_VALUE);
    BOOST_REQUIRE(v.value.has_value());
    BOOST_TEST(*v.value == secret);
    expect_nowhere(n, secret);
    // Data objects default to public.
    hsm::attribute_map plain;
    plain.set_ulong(CKA_CLASS, CKO_DATA);
    auto ph = n.client->create_object(n.session, plain);
    BOOST_REQUIRE(ph.has_value());
    BOOST_TEST(!flag(n, *ph, CKA_PRIVATE));
    BOOST_TEST(attr(n, *ph, CKA_VALUE).value->empty());

    const auto der = data("not really DER, but opaque to the token");
    hsm::attribute_map cert;
    cert.set_ulong(CKA_CLASS, CKO_CERTIFICATE);
    cert.set_ulong(CKA_CERTIFICATE_TYPE, CKC_X_509);
    cert.set_bool(CKA_TOKEN, true);
    cert.set_bytes(CKA_VALUE, der);
    auto ch = n.client->create_object(n.session, cert);
    BOOST_REQUIRE(ch.has_value());
    BOOST_TEST(n.store.object(k_token, *ch)->attributes.has(CKA_VALUE));
    BOOST_TEST(n.store.object(k_token, *ch)->sealed.empty());
    auto other = cert;
    other.set_ulong(CKA_CERTIFICATE_TYPE, CKC_WTLS);
    BOOST_TEST(rv(n.client->create_object(n.session, other)) == CKR_ATTRIBUTE_VALUE_INVALID);
}

BOOST_AUTO_TEST_CASE(copies_keep_the_material_and_change_only_what_is_allowed) {
    node n;
    hsm::bytes value(32, 0x11);
    auto key = n.client->create_object(n.session, aes_object(value));
    BOOST_REQUIRE(key.has_value());
    hsm::attribute_map to_session;
    to_session.set_bool(CKA_TOKEN, false);
    to_session.set_bytes(CKA_LABEL, data("copy"));
    auto copy = n.client->copy_object(n.session, *key, to_session);
    BOOST_REQUIRE(copy.has_value());
    BOOST_TEST(*copy >= hsm::first_session_object_handle);
    BOOST_TEST(gcm_encrypt(n, *key, "x") == gcm_encrypt(n, *copy, "x"));
    // And back to a token object, sealed again under a new handle.
    hsm::attribute_map to_token;
    to_token.set_bool(CKA_TOKEN, true);
    auto back = n.client->copy_object(n.session, *copy, to_token);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(*back <= hsm::max_token_object_handle);
    BOOST_TEST(gcm_encrypt(n, *back, "x") == gcm_encrypt(n, *key, "x"));

    hsm::attribute_map change_class;
    change_class.set_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    BOOST_TEST(rv(n.client->copy_object(n.session, *key, change_class)) == CKR_ATTRIBUTE_READ_ONLY);
    hsm::attribute_map unsensitive;
    unsensitive.set_bool(CKA_SENSITIVE, false);
    BOOST_TEST(rv(n.client->copy_object(n.session, *key, unsensitive)) == CKR_ATTRIBUTE_READ_ONLY);
    auto fixed = aes_object(value);
    fixed.set_bool(CKA_COPYABLE, false);
    auto no_copy = n.client->create_object(n.session, fixed);
    BOOST_REQUIRE(no_copy.has_value());
    BOOST_TEST(rv(n.client->copy_object(n.session, *no_copy, {})) == CKR_ACTION_PROHIBITED);
    hsm::attribute_map new_value;
    new_value.set_bytes(CKA_VALUE, hsm::bytes(32, 0x22));
    BOOST_TEST(rv(n.client->copy_object(n.session, *key, new_value)) == CKR_ATTRIBUTE_READ_ONLY);
}

BOOST_AUTO_TEST_CASE(a_data_object_copy_may_take_a_new_value_sealed_like_the_first) {
    node n;
    hsm::attribute_map d;
    d.set_ulong(CKA_CLASS, CKO_DATA);
    d.set_bool(CKA_TOKEN, true);
    d.set_bytes(CKA_VALUE, data("first value"));
    auto h = n.client->create_object(n.session, d);
    BOOST_REQUIRE(h.has_value());
    const auto second = data("second, longer value");
    hsm::attribute_map change;
    change.set_bytes(CKA_VALUE, second);
    change.set_bytes(CKA_APPLICATION, data("copier"));
    auto copy = n.client->copy_object(n.session, *h, change);
    BOOST_REQUIRE(copy.has_value());
    BOOST_TEST(*attr(n, *copy, CKA_VALUE).value == second);
    BOOST_TEST(*attr(n, *h, CKA_VALUE).value == data("first value"));
    BOOST_TEST(!n.store.object(k_token, *copy)->attributes.has(CKA_VALUE));
    expect_nowhere(n, second);
}

BOOST_AUTO_TEST_CASE(wrap_and_unwrap_follow_the_rules) {
    node n;
    hsm::attribute_map kek_t = aes_template(true);
    kek_t.set_bool(CKA_WRAP, true);
    kek_t.set_bool(CKA_UNWRAP, true);
    auto kek = n.client->generate_key(n.session, k_aes_gen, kek_t);
    BOOST_REQUIRE(kek.has_value());
    auto movable_t = aes_template(true);
    movable_t.set_bool(CKA_EXTRACTABLE, true);
    auto movable = n.client->generate_key(n.session, k_aes_gen, movable_t);
    BOOST_REQUIRE(movable.has_value());
    const auto stuck = n.aes_key();

    const CK_MECHANISM kwp{CKM_AES_KEY_WRAP_KWP, nullptr, 0};
    auto wrapped = n.client->wrap_key(n.session, kwp, *kek, *movable);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(rv(n.client->wrap_key(n.session, kwp, *kek, stuck)) == CKR_KEY_UNEXTRACTABLE);
    BOOST_TEST(rv(n.client->wrap_key(n.session, kwp, stuck, *movable)) ==
               CKR_KEY_FUNCTION_NOT_PERMITTED);
    BOOST_TEST(rv(n.client->wrap_key(n.session, kwp, 4242, *movable)) ==
               CKR_WRAPPING_KEY_HANDLE_INVALID);

    hsm::attribute_map back;
    back.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    back.set_ulong(CKA_KEY_TYPE, CKK_AES);
    back.set_bool(CKA_TOKEN, true);
    back.set_bool(CKA_ENCRYPT, true);
    auto unwrapped = n.client->unwrap_key(n.session, kwp, *kek, *wrapped, back);
    BOOST_REQUIRE(unwrapped.has_value());
    BOOST_TEST(gcm_encrypt(n, *unwrapped, "w") == gcm_encrypt(n, *movable, "w"));
    BOOST_TEST(!flag(n, *unwrapped, CKA_LOCAL));
    BOOST_TEST(!flag(n, *unwrapped, CKA_NEVER_EXTRACTABLE));
    auto tampered = *wrapped;
    tampered[3] ^= 1U;
    BOOST_TEST(rv(n.client->unwrap_key(n.session, kwp, *kek, tampered, back)) ==
               CKR_WRAPPED_KEY_INVALID);
    BOOST_TEST(rv(n.client->unwrap_key(n.session, kwp, 4242, *wrapped, back)) ==
               CKR_UNWRAPPING_KEY_HANDLE_INVALID);

    // A wrapping key's templates bind what it wraps and unwraps.
    hsm::attribute_map strict_t = kek_t;
    hsm::attribute_map want;
    want.set_bool(CKA_TRUSTED, true);
    strict_t.set_template(CKA_WRAP_TEMPLATE, want);
    hsm::attribute_map unwrap_rule;
    unwrap_rule.set_bool(CKA_ENCRYPT, false);
    strict_t.set_template(CKA_UNWRAP_TEMPLATE, unwrap_rule);
    auto strict = n.client->generate_key(n.session, k_aes_gen, strict_t);
    BOOST_REQUIRE(strict.has_value());
    BOOST_TEST(rv(n.client->wrap_key(n.session, kwp, *strict, *movable)) == CKR_KEY_NOT_WRAPPABLE);
    auto w2 = n.client->wrap_key(n.session, kwp, *kek, *movable);
    BOOST_REQUIRE(w2.has_value());
    BOOST_TEST(rv(n.client->unwrap_key(n.session, kwp, *strict, *w2, back)) ==
               CKR_TEMPLATE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(private_keys_wrap_as_pkcs8_and_sign_after_unwrap) {
    node n;
    hsm::attribute_map kek_t = aes_template(true);
    kek_t.set_bool(CKA_WRAP, true);
    kek_t.set_bool(CKA_UNWRAP, true);
    auto kek = n.client->generate_key(n.session, k_aes_gen, kek_t);
    BOOST_REQUIRE(kek.has_value());
    hsm::attribute_map pub;
    pub.set_bool(CKA_TOKEN, true);
    pub.set_bytes(CKA_EC_PARAMS, k_p256);
    pub.set_bool(CKA_VERIFY, true);
    hsm::attribute_map priv;
    priv.set_bool(CKA_TOKEN, true);
    priv.set_bool(CKA_SIGN, true);
    priv.set_bool(CKA_EXTRACTABLE, true);
    auto pair = n.client->generate_key_pair(n.session, k_ec_gen, pub, priv);
    BOOST_REQUIRE(pair.has_value());
    const CK_MECHANISM kwp{CKM_AES_KEY_WRAP_KWP, nullptr, 0};
    auto wrapped = n.client->wrap_key(n.session, kwp, *kek, pair->second);
    BOOST_REQUIRE(wrapped.has_value());
    hsm::attribute_map t;
    t.set_ulong(CKA_CLASS, CKO_PRIVATE_KEY);
    t.set_ulong(CKA_KEY_TYPE, CKK_EC);
    t.set_bool(CKA_SIGN, true);
    auto again = n.client->unwrap_key(n.session, kwp, *kek, *wrapped, t);
    BOOST_REQUIRE(again.has_value());
    auto sig = n.sign(*again, "moved");
    BOOST_REQUIRE(sig.has_value());
    BOOST_REQUIRE(rv(n.client->verify_init(n.session, k_ecdsa, pair->first)) == CKR_OK);
    BOOST_TEST(rv(n.client->verify(n.session, data("moved"), *sig)) == CKR_OK);
    auto wrong_type = t;
    wrong_type.set_ulong(CKA_KEY_TYPE, CKK_RSA);
    BOOST_TEST(rv(n.client->unwrap_key(n.session, kwp, *kek, *wrapped, wrong_type)) ==
               CKR_TEMPLATE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(ecdh_derives_the_same_key_on_both_sides) {
    node n;
    auto pair_t = [&] {
        hsm::attribute_map pub;
        pub.set_bool(CKA_TOKEN, true);
        pub.set_bytes(CKA_EC_PARAMS, k_p256);
        hsm::attribute_map priv;
        priv.set_bool(CKA_TOKEN, true);
        priv.set_bool(CKA_DERIVE, true);
        auto p = n.client->generate_key_pair(n.session, k_ec_gen, pub, priv);
        BOOST_REQUIRE(p.has_value());
        return *p;
    };
    const auto a = pair_t();
    const auto b = pair_t();
    auto derive = [&](CK_OBJECT_HANDLE self, CK_OBJECT_HANDLE peer_pub) {
        auto point = attr(n, peer_pub, CKA_EC_POINT);
        BOOST_REQUIRE(point.value.has_value());
        CK_ECDH1_DERIVE_PARAMS ep{CKD_NULL, 0, nullptr, static_cast<CK_ULONG>(point.value->size()),
                                  point.value->data()};
        const CK_MECHANISM m{CKM_ECDH1_DERIVE, &ep, sizeof ep};
        hsm::attribute_map t = aes_template(false);
        t.set_ulong(CKA_KEY_TYPE, CKK_AES);
        auto k = n.client->derive_key(n.session, m, self, t);
        BOOST_REQUIRE(k.has_value());
        return *k;
    };
    const auto ab = derive(a.second, b.first);
    const auto ba = derive(b.second, a.first);
    BOOST_TEST(gcm_encrypt(n, ab, "agree") == gcm_encrypt(n, ba, "agree"));
    // Derived from a generated, always-sensitive base: still always
    // sensitive, but not local.
    BOOST_TEST(flag(n, ab, CKA_ALWAYS_SENSITIVE));
    BOOST_TEST(!flag(n, ab, CKA_LOCAL));
    // A key without CKA_DERIVE derives nothing.
    hsm::bytes dummy(65, 4);
    CK_ECDH1_DERIVE_PARAMS ep{CKD_NULL, 0, nullptr, static_cast<CK_ULONG>(dummy.size()),
                              dummy.data()};
    const CK_MECHANISM m{CKM_ECDH1_DERIVE, &ep, sizeof ep};
    const auto [pub, signer] = n.ec_pair();
    BOOST_TEST(rv(n.client->derive_key(n.session, m, signer, aes_template(false))) ==
               CKR_KEY_FUNCTION_NOT_PERMITTED);
}

BOOST_AUTO_TEST_CASE(hkdf_data_gives_a_data_object_with_the_rfc_5869_output) {
    node n;
    hsm::attribute_map ikm;
    ikm.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    ikm.set_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    ikm.set_bool(CKA_DERIVE, true);
    ikm.set_bytes(CKA_VALUE, hsm::bytes(22, 0x0b));
    auto base = n.client->create_object(n.session, ikm);
    BOOST_REQUIRE(base.has_value());
    hsm::bytes salt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    hsm::bytes info{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    CK_HKDF_PARAMS p{CK_TRUE,     CK_TRUE, CKM_SHA256,  CKF_HKDF_SALT_DATA, salt.data(),
                     salt.size(), 0,       info.data(), info.size()};
    const CK_MECHANISM m{CKM_HKDF_DATA, &p, sizeof p};
    hsm::attribute_map t;
    t.set_ulong(CKA_VALUE_LEN, 42);
    auto out = n.client->derive_key(n.session, m, *base, t);
    BOOST_REQUIRE(out.has_value());
    const CK_OBJECT_CLASS data_class = CKO_DATA;
    const auto* class_bytes = reinterpret_cast<const std::uint8_t*>(&data_class);
    BOOST_TEST(*attr(n, *out, CKA_CLASS).value ==
               hsm::bytes(class_bytes, class_bytes + sizeof data_class));
    const hsm::bytes okm{0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
                         0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
                         0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
                         0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    auto value = attr(n, *out, CKA_VALUE);
    BOOST_REQUIRE(value.value.has_value());
    BOOST_TEST(*value.value == okm);
    t.set_ulong(CKA_CLASS, CKO_SECRET_KEY);
    BOOST_TEST(rv(n.client->derive_key(n.session, m, *base, t)) == CKR_TEMPLATE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(imports_need_an_unsealed_node) {
    node n;
    n.layer.seal();
    BOOST_TEST(rv(n.client->create_object(n.session, aes_object(hsm::bytes(16, 1)))) ==
               CKR_DEVICE_ERROR);
}
