// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 4, requirements 6.1, 6.2 and 6.5: every key type and mechanism, with
// published test vectors where one exists (FIPS 180, RFC 4231, RFC 3394,
// RFC 5649, RFC 5869) and round trips plus tamper checks elsewhere; and the
// excluded mechanisms answering CKR_MECHANISM_INVALID.

#define BOOST_TEST_MODULE hsm_mechanisms_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/mechanisms.hpp>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace hsm = kythira::hsm;

namespace {

auto hex(std::string_view h) -> hsm::bytes {
    hsm::bytes out;
    std::string digits;
    for (char c : h) {
        if (c != ' ') {
            digits.push_back(c);
        }
    }
    for (std::size_t i = 0; i + 1 < digits.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(digits.substr(i, 2), nullptr, 16)));
    }
    return out;
}

auto text(std::string_view s) -> hsm::bytes {
    return {s.begin(), s.end()};
}

auto mech(CK_MECHANISM_TYPE type) -> CK_MECHANISM {
    return CK_MECHANISM{type, nullptr, 0};
}

template<class P> auto mech(CK_MECHANISM_TYPE type, P& params) -> CK_MECHANISM {
    return CK_MECHANISM{type, &params, sizeof(P)};
}

auto secret_key(CK_KEY_TYPE type, const hsm::bytes& value) -> hsm::key_material {
    hsm::key_material k;
    k.object_class = CKO_SECRET_KEY;
    k.key_type = type;
    k.secret = hsm::secret_bytes(std::span<const std::uint8_t>(value));
    return k;
}

auto private_key(const hsm::key_pair& pair) -> hsm::key_material {
    hsm::key_material k;
    k.object_class = CKO_PRIVATE_KEY;
    k.key_type = pair.key_type;
    k.secret = pair.private_pkcs8.clone();
    k.public_der = pair.public_spki;
    return k;
}

auto public_key(const hsm::key_pair& pair) -> hsm::key_material {
    hsm::key_material k;
    k.object_class = CKO_PUBLIC_KEY;
    k.key_type = pair.key_type;
    k.public_der = pair.public_spki;
    return k;
}

auto rsa_pair() -> const hsm::key_pair& {
    static const hsm::key_pair pair = [] {
        hsm::key_pair_request req;
        req.modulus_bits = 2048;
        auto m = mech(CKM_RSA_PKCS_KEY_PAIR_GEN);
        auto p = hsm::generate_key_pair(m, req);
        BOOST_REQUIRE(p.has_value());
        return std::move(*p);
    }();
    return pair;
}

auto ec_pair(const hsm::bytes& params, CK_MECHANISM_TYPE gen = CKM_EC_KEY_PAIR_GEN)
    -> hsm::key_pair {
    hsm::key_pair_request req;
    req.ec_params = params;
    auto m = mech(gen);
    auto p = hsm::generate_key_pair(m, req);
    BOOST_REQUIRE(p.has_value());
    return std::move(*p);
}

const hsm::bytes p256 = hex("06082A8648CE3D030107");
const hsm::bytes p384 = hex("06052B81040022");
const hsm::bytes p521 = hex("06052B81040023");
const hsm::bytes ed25519 = hex("06032B6570");

auto flip(hsm::bytes b, std::size_t i = 0) -> hsm::bytes {
    b.at(i) ^= 0x01U;
    return b;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_mechanism_table_and_exclusions_agree) {
    std::set<CK_MECHANISM_TYPE> supported;
    for (const auto& e : hsm::supported_mechanisms()) {
        BOOST_TEST(supported.insert(e.type).second);  // no duplicates
        BOOST_TEST(hsm::mechanism_info(e.type).has_value());
        BOOST_TEST(e.info.flags != 0U);
    }
    for (auto m : hsm::excluded_mechanisms()) {
        BOOST_TEST_INFO("mechanism 0x" << std::hex << m);
        BOOST_TEST(!supported.contains(m));
        auto info = hsm::mechanism_info(m);
        BOOST_REQUIRE(!info.has_value());
        BOOST_TEST(info.error() == CKR_MECHANISM_INVALID);
    }
    BOOST_TEST(!hsm::unsupported_functions().empty());
    BOOST_TEST(
        std::ranges::count(hsm::unsupported_functions(), std::string_view("C_SignRecover")) == 1);
    BOOST_TEST(std::ranges::count(hsm::unsupported_functions(),
                                  std::string_view("C_GetOperationState")) == 1);
}

BOOST_AUTO_TEST_CASE(excluded_mechanisms_are_refused_by_every_operation) {
    auto aes = secret_key(CKK_AES, hsm::bytes(32, 7));
    for (auto type : hsm::excluded_mechanisms()) {
        const auto m = mech(type);
        BOOST_TEST_INFO("mechanism 0x" << std::hex << type);
        BOOST_TEST(hsm::sign(m, aes, text("x")).error() == CKR_MECHANISM_INVALID);
        BOOST_TEST(hsm::encrypt(m, aes, text("x")).error() == CKR_MECHANISM_INVALID);
        BOOST_TEST(hsm::digest(m, text("x")).error() == CKR_MECHANISM_INVALID);
        BOOST_TEST(hsm::generate_secret_key(m, 16).error() == CKR_MECHANISM_INVALID);
        BOOST_TEST(hsm::derive(m, aes, 16).error() == CKR_MECHANISM_INVALID);
    }
}

BOOST_AUTO_TEST_CASE(secret_key_generation_respects_sizes) {
    auto aes = mech(CKM_AES_KEY_GEN);
    for (CK_ULONG len : {16UL, 24UL, 32UL}) {
        auto k = hsm::generate_secret_key(aes, len);
        BOOST_REQUIRE(k.has_value());
        BOOST_TEST(k->size() == len);
    }
    BOOST_TEST(hsm::generate_secret_key(aes, 20).error() == CKR_KEY_SIZE_RANGE);
    auto generic = mech(CKM_GENERIC_SECRET_KEY_GEN);
    BOOST_TEST(hsm::generate_secret_key(generic, 64)->size() == 64U);
    BOOST_TEST(hsm::generate_secret_key(generic, 0).error() == CKR_KEY_SIZE_RANGE);
    auto a = hsm::generate_secret_key(aes, 32);
    auto b = hsm::generate_secret_key(aes, 32);
    BOOST_TEST(!hsm::constant_time_equal(a->view(), b->view()));
}

BOOST_AUTO_TEST_CASE(sha2_digests_match_fips_180) {
    const auto abc = text("abc");
    BOOST_TEST(*hsm::digest(mech(CKM_SHA256), abc) ==
                   hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
               boost::test_tools::per_element());
    BOOST_TEST(hsm::digest(mech(CKM_SHA384), abc)->size() == 48U);
    BOOST_TEST(*hsm::digest(mech(CKM_SHA512), abc) ==
                   hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
               boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(hmac_matches_rfc_4231_and_verifies) {
    auto key = secret_key(CKK_GENERIC_SECRET, text("Jefe"));
    const auto data = text("what do ya want for nothing?");
    const auto m = mech(CKM_SHA256_HMAC);
    auto mac = hsm::sign(m, key, data);
    BOOST_REQUIRE(mac.has_value());
    BOOST_TEST(*mac == hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
               boost::test_tools::per_element());
    BOOST_TEST(hsm::verify(m, key, data, *mac).has_value());
    BOOST_TEST(hsm::verify(m, key, data, flip(*mac)).error() == CKR_SIGNATURE_INVALID);
    BOOST_TEST(hsm::verify(m, key, data, hsm::bytes(mac->begin(), mac->end() - 1)).error() ==
               CKR_SIGNATURE_LEN_RANGE);
    BOOST_TEST(hsm::sign(mech(CKM_SHA384_HMAC), key, data)->size() == 48U);
    BOOST_TEST(hsm::sign(mech(CKM_SHA512_HMAC), key, data)->size() == 64U);
    auto aes = secret_key(CKK_AES, hsm::bytes(16, 1));
    BOOST_TEST(hsm::sign(m, aes, data).error() == CKR_KEY_TYPE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(aes_key_wrap_matches_rfc_3394) {
    auto kek = secret_key(CKK_AES, hex("000102030405060708090A0B0C0D0E0F"));
    const auto m = mech(CKM_AES_KEY_WRAP);
    auto wrapped = hsm::wrap(m, kek, hex("00112233445566778899AABBCCDDEEFF"));
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(*wrapped == hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
               boost::test_tools::per_element());
    auto back = hsm::unwrap(m, kek, *wrapped);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::constant_time_equal(back->view(), hex("00112233445566778899AABBCCDDEEFF")));
    BOOST_TEST(hsm::unwrap(m, kek, flip(*wrapped, 5)).error() == CKR_WRAPPED_KEY_INVALID);
    BOOST_TEST(hsm::wrap(m, kek, hsm::bytes(20, 1)).error() == CKR_DATA_LEN_RANGE);
    // Key wrap mechanisms are for C_WrapKey only.
    BOOST_TEST(hsm::encrypt(m, kek, hsm::bytes(16, 1)).error() == CKR_MECHANISM_INVALID);
}

BOOST_AUTO_TEST_CASE(aes_key_wrap_with_padding_matches_rfc_5649) {
    auto kek = secret_key(CKK_AES, hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
    const auto m = mech(CKM_AES_KEY_WRAP_KWP);
    const auto key = hex("c37b7e6492584340bed12207808941155068f738");
    auto wrapped = hsm::wrap(m, kek, key);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(*wrapped == hex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"),
               boost::test_tools::per_element());
    auto back = hsm::unwrap(m, kek, *wrapped);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(hsm::constant_time_equal(back->view(), key));
    BOOST_TEST(hsm::unwrap(m, kek, flip(*wrapped, 9)).error() == CKR_WRAPPED_KEY_INVALID);
}

BOOST_AUTO_TEST_CASE(aes_gcm_round_trips_and_detects_tampering) {
    auto key = secret_key(CKK_AES, hsm::bytes(32, 0x42));
    hsm::bytes iv(12, 0x24);
    auto aad = text("header");
    CK_GCM_PARAMS gp{iv.data(), iv.size(), iv.size() * 8, aad.data(), aad.size(), 128};
    const auto m = mech(CKM_AES_GCM, gp);
    const auto plain = text("attack at dawn, bring snacks");
    auto ct = hsm::encrypt(m, key, plain);
    BOOST_REQUIRE(ct.has_value());
    BOOST_TEST(ct->size() == plain.size() + 16);
    auto pt = hsm::decrypt(m, key, *ct);
    BOOST_REQUIRE(pt.has_value());
    BOOST_TEST(hsm::constant_time_equal(pt->view(), plain));
    BOOST_TEST(hsm::decrypt(m, key, flip(*ct, 3)).error() == CKR_ENCRYPTED_DATA_INVALID);
    BOOST_TEST(hsm::decrypt(m, key, flip(*ct, ct->size() - 1)).error() ==
               CKR_ENCRYPTED_DATA_INVALID);
    auto other_aad = text("Header");
    CK_GCM_PARAMS gp2{iv.data(), iv.size(), iv.size() * 8, other_aad.data(), other_aad.size(), 128};
    BOOST_TEST(hsm::decrypt(mech(CKM_AES_GCM, gp2), key, *ct).error() ==
               CKR_ENCRYPTED_DATA_INVALID);
    CK_GCM_PARAMS short_tag{iv.data(), iv.size(), iv.size() * 8, nullptr, 0, 64};
    BOOST_TEST(hsm::encrypt(mech(CKM_AES_GCM, short_tag), key, plain).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(hsm::encrypt(mech(CKM_AES_GCM), key, plain).error() == CKR_MECHANISM_PARAM_INVALID);
    // A GCM-wrapped key that fails its tag is a bad wrapped key.
    BOOST_TEST(hsm::unwrap(m, key, flip(*ct, 0)).error() == CKR_WRAPPED_KEY_INVALID);
    auto generic = secret_key(CKK_GENERIC_SECRET, hsm::bytes(32, 1));
    BOOST_TEST(hsm::encrypt(m, generic, plain).error() == CKR_KEY_TYPE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(aes_cbc_pad_round_trips_every_length) {
    auto key = secret_key(CKK_AES, hsm::bytes(16, 0x11));
    hsm::bytes iv(16, 0x22);
    CK_MECHANISM m{CKM_AES_CBC_PAD, iv.data(), iv.size()};
    for (std::size_t n = 0; n <= 40; ++n) {
        hsm::bytes plain(n, static_cast<std::uint8_t>(n));
        auto ct = hsm::encrypt(m, key, plain);
        BOOST_REQUIRE(ct.has_value());
        BOOST_TEST(ct->size() == (n / 16 + 1) * 16);
        auto pt = hsm::decrypt(m, key, *ct);
        BOOST_REQUIRE(pt.has_value());
        BOOST_TEST(hsm::constant_time_equal(pt->view(), plain));
    }
    BOOST_TEST(hsm::decrypt(m, key, hsm::bytes(15, 0)).error() == CKR_ENCRYPTED_DATA_LEN_RANGE);
    CK_MECHANISM short_iv{CKM_AES_CBC_PAD, iv.data(), 8};
    BOOST_TEST(hsm::encrypt(short_iv, key, text("x")).error() == CKR_MECHANISM_PARAM_INVALID);
}

BOOST_AUTO_TEST_CASE(rsa_generation_sets_public_attributes) {
    const auto& pair = rsa_pair();
    BOOST_TEST(pair.key_type == CKK_RSA);
    BOOST_TEST(pair.public_attributes.get_ulong(CKA_MODULUS_BITS).value().value() == 2048U);
    BOOST_TEST(pair.public_attributes.bytes(CKA_MODULUS)->size() == 256U);
    auto e = pair.public_attributes.bytes(CKA_PUBLIC_EXPONENT);
    BOOST_TEST(hsm::bytes(e->begin(), e->end()) == hex("010001"), boost::test_tools::per_element());
    auto again = hsm::inspect_private_key(pair.private_pkcs8.view());
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(again->public_spki == pair.public_spki, boost::test_tools::per_element());

    hsm::key_pair_request small;
    small.modulus_bits = 1024;
    BOOST_TEST(hsm::generate_key_pair(mech(CKM_RSA_PKCS_KEY_PAIR_GEN), small).error() ==
               CKR_KEY_SIZE_RANGE);
    hsm::key_pair_request e3;
    e3.modulus_bits = 2048;
    e3.public_exponent = hex("03");
    BOOST_TEST(hsm::generate_key_pair(mech(CKM_RSA_PKCS_KEY_PAIR_GEN), e3).error() ==
               CKR_TEMPLATE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(rsa_signatures_verify_and_reject_tampering) {
    const auto priv = private_key(rsa_pair());
    const auto pub = public_key(rsa_pair());
    const auto data = text("sign me");
    for (auto type : {CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS}) {
        const auto m = mech(type);
        auto sig = hsm::sign(m, priv, data);
        BOOST_REQUIRE(sig.has_value());
        BOOST_TEST(sig->size() == 256U);
        BOOST_TEST(hsm::verify(m, pub, data, *sig).has_value());
        BOOST_TEST(hsm::verify(m, priv, data, *sig).has_value());  // private object verifies too
        BOOST_TEST(hsm::verify(m, pub, text("sign mE"), *sig).error() == CKR_SIGNATURE_INVALID);
        BOOST_TEST(hsm::verify(m, pub, data, flip(*sig, 100)).error() == CKR_SIGNATURE_INVALID);
        BOOST_TEST(hsm::verify(m, pub, data, hsm::bytes(255, 0)).error() ==
                   CKR_SIGNATURE_LEN_RANGE);
    }
    // CKM_RSA_PKCS pads the DigestInfo the caller built; it equals
    // CKM_SHA256_RSA_PKCS over the same data (v1.5 is deterministic).
    auto info = hex("3031300d060960864801650304020105000420");
    auto h = hsm::digest(mech(CKM_SHA256), data);
    info.insert(info.end(), h->begin(), h->end());
    auto raw = hsm::sign(mech(CKM_RSA_PKCS), priv, info);
    BOOST_REQUIRE(raw.has_value());
    BOOST_TEST(*raw == *hsm::sign(mech(CKM_SHA256_RSA_PKCS), priv, data),
               boost::test_tools::per_element());
    BOOST_TEST(hsm::verify(mech(CKM_RSA_PKCS), pub, info, *raw).has_value());
    BOOST_TEST(hsm::sign(mech(CKM_RSA_PKCS), priv, hsm::bytes(250, 1)).error() ==
               CKR_DATA_LEN_RANGE);
    // Signing needs the private key.
    BOOST_TEST(hsm::sign(mech(CKM_SHA256_RSA_PKCS), pub, data).error() ==
               CKR_KEY_TYPE_INCONSISTENT);
}

BOOST_AUTO_TEST_CASE(rsa_pss_checks_its_parameters) {
    const auto priv = private_key(rsa_pair());
    const auto pub = public_key(rsa_pair());
    const auto data = text("pss");
    CK_RSA_PKCS_PSS_PARAMS pp{CKM_SHA256, CKG_MGF1_SHA256, 32};
    for (auto type : {CKM_SHA256_RSA_PKCS_PSS}) {
        const auto m = mech(type, pp);
        auto sig = hsm::sign(m, priv, data);
        BOOST_REQUIRE(sig.has_value());
        BOOST_TEST(hsm::verify(m, pub, data, *sig).has_value());
        BOOST_TEST(hsm::verify(m, pub, data, flip(*sig, 7)).error() == CKR_SIGNATURE_INVALID);
    }
    // CKM_RSA_PKCS_PSS signs a hash computed with hashAlg.
    auto h = hsm::digest(mech(CKM_SHA256), data);
    auto sig = hsm::sign(mech(CKM_RSA_PKCS_PSS, pp), priv, *h);
    BOOST_REQUIRE(sig.has_value());
    BOOST_TEST(hsm::verify(mech(CKM_SHA256_RSA_PKCS_PSS, pp), pub, data, *sig).has_value());
    BOOST_TEST(hsm::sign(mech(CKM_RSA_PKCS_PSS, pp), priv, data).error() == CKR_DATA_LEN_RANGE);
    // hashAlg must match the mechanism's hash, mgf must match hashAlg, and
    // SHA-1 is excluded for signatures.
    BOOST_TEST(hsm::sign(mech(CKM_SHA384_RSA_PKCS_PSS, pp), priv, data).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    CK_RSA_PKCS_PSS_PARAMS mixed{CKM_SHA256, CKG_MGF1_SHA512, 32};
    BOOST_TEST(hsm::sign(mech(CKM_SHA256_RSA_PKCS_PSS, mixed), priv, data).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    CK_RSA_PKCS_PSS_PARAMS sha1{CKM_SHA_1, CKG_MGF1_SHA1, 20};
    BOOST_TEST(hsm::sign(mech(CKM_RSA_PKCS_PSS, sha1), priv, hsm::bytes(20, 1)).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(hsm::sign(mech(CKM_SHA256_RSA_PKCS_PSS), priv, data).error() ==
               CKR_MECHANISM_PARAM_INVALID);
}

BOOST_AUTO_TEST_CASE(rsa_oaep_encrypts_and_wraps) {
    const auto priv = private_key(rsa_pair());
    const auto pub = public_key(rsa_pair());
    auto label = text("label");
    CK_RSA_PKCS_OAEP_PARAMS op{CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, label.data(),
                               label.size()};
    const auto m = mech(CKM_RSA_PKCS_OAEP, op);
    auto ct = hsm::encrypt(m, pub, text("secret"));
    BOOST_REQUIRE(ct.has_value());
    BOOST_TEST(ct->size() == 256U);
    auto pt = hsm::decrypt(m, priv, *ct);
    BOOST_REQUIRE(pt.has_value());
    BOOST_TEST(hsm::constant_time_equal(pt->view(), text("secret")));
    BOOST_TEST(hsm::decrypt(m, priv, flip(*ct, 50)).error() == CKR_ENCRYPTED_DATA_INVALID);
    auto other = text("lab3l");
    CK_RSA_PKCS_OAEP_PARAMS op2{CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, other.data(),
                                other.size()};
    BOOST_TEST(hsm::decrypt(mech(CKM_RSA_PKCS_OAEP, op2), priv, *ct).error() ==
               CKR_ENCRYPTED_DATA_INVALID);
    // OAEP with SHA-1 is allowed (it is not a signature).
    CK_RSA_PKCS_OAEP_PARAMS sha1{CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nullptr, 0};
    auto ct1 = hsm::encrypt(mech(CKM_RSA_PKCS_OAEP, sha1), pub, text("x"));
    BOOST_REQUIRE(ct1.has_value());
    BOOST_TEST(hsm::decrypt(mech(CKM_RSA_PKCS_OAEP, sha1), priv, *ct1).has_value());
    // Wrapping an AES key, and a bad wrapped key.
    const auto aes = hsm::bytes(32, 0x5A);
    auto wrapped = hsm::wrap(m, pub, aes);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST(hsm::constant_time_equal(hsm::unwrap(m, priv, *wrapped)->view(), aes));
    BOOST_TEST(hsm::unwrap(m, priv, flip(*wrapped, 1)).error() == CKR_WRAPPED_KEY_INVALID);
    BOOST_TEST(hsm::unwrap(m, priv, hsm::bytes(10, 0)).error() == CKR_WRAPPED_KEY_LEN_RANGE);
}

BOOST_AUTO_TEST_CASE(ec_keys_on_every_curve_sign_and_verify) {
    struct curve_case {
        hsm::bytes params;
        std::size_t point_len;  // uncompressed point
        std::size_t sig_len;
    };
    for (const auto& c :
         {curve_case{p256, 65, 64}, curve_case{p384, 97, 96}, curve_case{p521, 133, 132}}) {
        auto pair = ec_pair(c.params);
        BOOST_TEST(pair.key_type == CKK_EC);
        auto params = pair.public_attributes.bytes(CKA_EC_PARAMS);
        BOOST_TEST(hsm::bytes(params->begin(), params->end()) == c.params,
                   boost::test_tools::per_element());
        auto point = pair.public_attributes.bytes(CKA_EC_POINT);
        BOOST_REQUIRE(point.has_value());
        const auto inner = hsm::detail::strip_octet_string(*point);
        BOOST_TEST(inner.size() == c.point_len);
        BOOST_TEST(inner[0] == 0x04U);
        const auto priv = private_key(pair);
        const auto pub = public_key(pair);
        const auto data = text("ecdsa");
        for (auto type : {CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512}) {
            auto sig = hsm::sign(mech(type), priv, data);
            BOOST_REQUIRE(sig.has_value());
            BOOST_TEST(sig->size() == c.sig_len);
            BOOST_TEST(hsm::verify(mech(type), pub, data, *sig).has_value());
            BOOST_TEST(hsm::verify(mech(type), pub, data, flip(*sig, 2)).error() ==
                       CKR_SIGNATURE_INVALID);
            BOOST_TEST(hsm::verify(mech(type), pub, data, hsm::bytes(c.sig_len - 1, 1)).error() ==
                       CKR_SIGNATURE_LEN_RANGE);
        }
        // CKM_ECDSA signs a hash the caller made.
        auto h = hsm::digest(mech(CKM_SHA256), data);
        auto raw = hsm::sign(mech(CKM_ECDSA), priv, *h);
        BOOST_REQUIRE(raw.has_value());
        BOOST_TEST(hsm::verify(mech(CKM_ECDSA_SHA256), pub, data, *raw).has_value());
    }
}

BOOST_AUTO_TEST_CASE(ed25519_signs_and_rejects_prehash_and_context) {
    auto by_oid = ec_pair(ed25519, CKM_EC_EDWARDS_KEY_PAIR_GEN);
    auto by_name = ec_pair(hex("130C656477617264733235353139"), CKM_EC_EDWARDS_KEY_PAIR_GEN);
    BOOST_TEST(by_name.key_type == CKK_EC_EDWARDS);
    BOOST_TEST(by_oid.key_type == CKK_EC_EDWARDS);
    auto point = by_oid.public_attributes.bytes(CKA_EC_POINT);
    BOOST_TEST(point->size() == 34U);  // OCTET STRING of 32 bytes
    const auto priv = private_key(by_oid);
    const auto pub = public_key(by_oid);
    const auto data = text("eddsa");
    auto sig = hsm::sign(mech(CKM_EDDSA), priv, data);
    BOOST_REQUIRE(sig.has_value());
    BOOST_TEST(sig->size() == 64U);
    BOOST_TEST(hsm::verify(mech(CKM_EDDSA), pub, data, *sig).has_value());
    BOOST_TEST(hsm::verify(mech(CKM_EDDSA), pub, data, flip(*sig, 40)).error() ==
               CKR_SIGNATURE_INVALID);
    CK_EDDSA_PARAMS pure{CK_FALSE, 0, nullptr};
    BOOST_TEST(hsm::sign(mech(CKM_EDDSA, pure), priv, data).has_value());
    CK_EDDSA_PARAMS ph{CK_TRUE, 0, nullptr};
    BOOST_TEST(hsm::sign(mech(CKM_EDDSA, ph), priv, data).error() == CKR_MECHANISM_PARAM_INVALID);
    // An Ed25519 key is not an ECDSA key, and an EC curve is not Edwards.
    BOOST_TEST(hsm::sign(mech(CKM_ECDSA_SHA256), priv, data).error() == CKR_KEY_TYPE_INCONSISTENT);
    hsm::key_pair_request wrong;
    wrong.ec_params = p256;
    BOOST_TEST(hsm::generate_key_pair(mech(CKM_EC_EDWARDS_KEY_PAIR_GEN), wrong).error() ==
               CKR_CURVE_NOT_SUPPORTED);
}

BOOST_AUTO_TEST_CASE(unsupported_curves_are_refused) {
    hsm::key_pair_request k1;
    k1.ec_params = hex("06052B8104000A");  // secp256k1
    BOOST_TEST(hsm::generate_key_pair(mech(CKM_EC_KEY_PAIR_GEN), k1).error() ==
               CKR_CURVE_NOT_SUPPORTED);
}

BOOST_AUTO_TEST_CASE(ecdh_agrees_and_checks_the_peer_point) {
    auto a = ec_pair(p256);
    auto b = ec_pair(p256);
    auto point_of = [](const hsm::key_pair& p) {
        auto pt = p.public_attributes.bytes(CKA_EC_POINT);
        return hsm::bytes(pt->begin(), pt->end());
    };
    auto derive = [](const hsm::key_pair& self, hsm::bytes peer, CK_ULONG len) {
        CK_ECDH1_DERIVE_PARAMS ep{CKD_NULL, 0, nullptr, static_cast<CK_ULONG>(peer.size()),
                                  peer.data()};
        return hsm::derive(mech(CKM_ECDH1_DERIVE, ep), private_key(self), len);
    };
    const auto bp = point_of(b);
    const auto ap = point_of(a);
    auto ab = derive(a, bp, 0);                                    // DER OCTET STRING form
    auto ba = derive(b, hsm::bytes(ap.begin() + 2, ap.end()), 0);  // raw point form
    BOOST_REQUIRE(ab.has_value());
    BOOST_REQUIRE(ba.has_value());
    BOOST_TEST(ab->size() == 32U);
    BOOST_TEST(hsm::constant_time_equal(ab->view(), ba->view()));
    auto short_key = derive(a, bp, 16);
    BOOST_TEST(hsm::constant_time_equal(short_key->view(), ab->view().first(16)));
    BOOST_TEST(derive(a, bp, 33).error() == CKR_KEY_SIZE_RANGE);
    auto off_curve = bp;
    off_curve.back() ^= 0x01U;
    BOOST_TEST(derive(a, off_curve, 0).error() == CKR_MECHANISM_PARAM_INVALID);
    hsm::bytes peer = bp;
    CK_ECDH1_DERIVE_PARAMS with_kdf{CKD_SHA256_KDF, 0, nullptr, static_cast<CK_ULONG>(peer.size()),
                                    peer.data()};
    BOOST_TEST(hsm::derive(mech(CKM_ECDH1_DERIVE, with_kdf), private_key(a), 0).error() ==
               CKR_MECHANISM_PARAM_INVALID);
}

BOOST_AUTO_TEST_CASE(hkdf_matches_rfc_5869_case_1) {
    auto ikm = secret_key(CKK_GENERIC_SECRET, hsm::bytes(22, 0x0b));
    auto salt = hex("000102030405060708090a0b0c");
    auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    const auto okm =
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    const auto prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    CK_HKDF_PARAMS both{CK_TRUE,     CK_TRUE, CKM_SHA256,  CKF_HKDF_SALT_DATA, salt.data(),
                        salt.size(), 0,       info.data(), info.size()};
    auto out = hsm::derive(mech(CKM_HKDF_DERIVE, both), ikm, 42);
    BOOST_REQUIRE(out.has_value());
    BOOST_TEST(hsm::constant_time_equal(out->view(), okm));
    CK_HKDF_PARAMS extract{
        CK_TRUE, CK_FALSE, CKM_SHA256, CKF_HKDF_SALT_DATA, salt.data(), salt.size(), 0, nullptr, 0};
    auto p = hsm::derive(mech(CKM_HKDF_DERIVE, extract), ikm, 0);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(hsm::constant_time_equal(p->view(), prk));
    auto prk_key = secret_key(CKK_HKDF, prk);
    CK_HKDF_PARAMS expand{CK_FALSE, CK_TRUE, CKM_SHA256,  CKF_HKDF_SALT_NULL, nullptr,
                          0,        0,       info.data(), info.size()};
    auto e = hsm::derive(mech(CKM_HKDF_DATA, expand), prk_key, 42);
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST(hsm::constant_time_equal(e->view(), okm));
    CK_HKDF_PARAMS salt_key{CK_TRUE, CK_TRUE, CKM_SHA256, CKF_HKDF_SALT_KEY, nullptr, 0,
                            1,       nullptr, 0};
    BOOST_TEST(hsm::derive(mech(CKM_HKDF_DERIVE, salt_key), ikm, 32).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    CK_HKDF_PARAMS sha1{CK_TRUE, CK_TRUE, CKM_SHA_1, CKF_HKDF_SALT_NULL, nullptr, 0, 0, nullptr, 0};
    BOOST_TEST(hsm::derive(mech(CKM_HKDF_DERIVE, sha1), ikm, 32).error() ==
               CKR_MECHANISM_PARAM_INVALID);
    BOOST_TEST(hsm::derive(mech(CKM_HKDF_DERIVE, both), ikm, 255 * 32 + 1).error() ==
               CKR_KEY_SIZE_RANGE);
}

BOOST_AUTO_TEST_CASE(private_keys_wrap_and_unwrap_as_pkcs8) {
    auto kek = secret_key(CKK_AES, hsm::bytes(32, 0x33));
    const auto m = mech(CKM_AES_KEY_WRAP_KWP);
    for (const auto* params : {&p256, &p521}) {
        auto pair = ec_pair(*params);
        auto wrapped = hsm::wrap(m, kek, pair.private_pkcs8.view());
        BOOST_REQUIRE(wrapped.has_value());
        auto back = hsm::unwrap(m, kek, *wrapped);
        BOOST_REQUIRE(back.has_value());
        auto inspected = hsm::inspect_private_key(back->view());
        BOOST_REQUIRE(inspected.has_value());
        BOOST_TEST(inspected->key_type == CKK_EC);
        BOOST_TEST(inspected->public_spki == pair.public_spki, boost::test_tools::per_element());
    }
    BOOST_TEST(hsm::inspect_private_key(hsm::bytes(40, 0x30)).error() == CKR_WRAPPED_KEY_INVALID);
}

BOOST_AUTO_TEST_CASE(random_bytes_differ) {
    hsm::bytes a(32);
    hsm::bytes b(32);
    BOOST_TEST(hsm::generate_random(a).has_value());
    BOOST_TEST(hsm::generate_random(b).has_value());
    BOOST_TEST(a != b);
}
