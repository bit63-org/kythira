// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 5 (Requirements 4.1-4.3): backing keys of every key spec on a real
// PKCS#11 module, SoftHSM2 standing in for an external one (registered
// when the build finds SoftHSM2; kms-module.yml installs it). Each is a
// token object, sensitive and not extractable, whose value the module
// will not reveal; it is found again by label, listed, and destroyed.

#define BOOST_TEST_MODULE kms_backing_softhsm_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>

#include <raft/pkcs11_module.hpp>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace kms = kythira::kms;
namespace p11 = kythira::pkcs11;

namespace {

/// A SoftHSM2 token store of its own, with one token initialized.
struct softhsm_token {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / ("kms-softhsm-" + std::to_string(::getpid()));

    softhsm_token() {
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir / "tokens");
        const auto conf = dir / "softhsm2.conf";
        std::ofstream(conf) << "directories.tokendir = " << (dir / "tokens").string() << "\n"
                            << "objectstore.backend = file\nlog.level = ERROR\n";
        ::setenv("SOFTHSM2_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
        const std::string init = std::string(KYTHIRA_SOFTHSM2_UTIL) +
                                 " --init-token --free --label kms --so-pin 5678 --pin 1234"
                                 " > /dev/null";
        BOOST_REQUIRE(std::system(init.c_str()) == 0);  // NOLINT(concurrency-mt-unsafe)
    }
    softhsm_token(const softhsm_token&) = delete;
    auto operator=(const softhsm_token&) -> softhsm_token& = delete;
    softhsm_token(softhsm_token&&) = delete;
    auto operator=(softhsm_token&&) -> softhsm_token& = delete;
    ~softhsm_token() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

auto bool_attr(p11::backend& b, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_TYPE t)
    -> std::optional<bool> {
    const std::array<CK_ATTRIBUTE_TYPE, 1> types{t};
    const auto v = b.get_attributes(s, o, types);
    if (v.empty() || !v[0] || v[0]->size() != 1) {
        return std::nullopt;
    }
    return (*v[0])[0] == CK_TRUE;
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_key_spec_is_a_non_extractable_token_object) {
    const softhsm_token token;
    auto backend = std::make_shared<p11::function_list_backend>(KYTHIRA_SOFTHSM2_LIBRARY);
    CK_SLOT_ID slot = 0;
    for (const auto& t : backend->tokens()) {
        if (t.label == "kms") {
            slot = t.slot;
        }
    }
    kms::backing_store store(backend, slot, "1234");

    std::vector<kms::backing_ref> made;
    int n = 0;
    for (const auto& info : kms::k_key_specs) {
        std::vector<kms::key_usage> usages{info.usages[0]};
        if (info.usages[1] != info.usages[0]) {
            usages.push_back(info.usages[1]);
        }
        for (const auto usage : usages) {
            const std::string id = "key-" + std::to_string(n++);
            BOOST_TEST_CONTEXT(info.name << " usage " << static_cast<int>(usage)) {
                std::uint64_t h = 0;
                try {
                    h = store.generate(id, 1, info.spec, usage);
                } catch (const kms::backing_error& e) {
                    // SoftHSM2 is built without some curves on some
                    // distributions; that is the module lacking the
                    // mechanism (Requirement 4.3), never a failure.
                    BOOST_TEST_MESSAGE(info.name << ": " << e.what());
                    BOOST_TEST((e.which() == kms::backing_error::kind::unsupported));
                    continue;
                }
                made.push_back({id, 1});
                BOOST_TEST((store.find(id, 1) == std::optional<std::uint64_t>(h)));
                store.with_session([&](CK_SESSION_HANDLE s) {
                    auto& b = store.backend();
                    BOOST_TEST((bool_attr(b, s, h, CKA_TOKEN) == std::optional(true)));
                    BOOST_TEST((bool_attr(b, s, h, CKA_SENSITIVE) == std::optional(true)));
                    BOOST_TEST((bool_attr(b, s, h, CKA_EXTRACTABLE) == std::optional(false)));
                    BOOST_TEST((bool_attr(b, s, h, CKA_NEVER_EXTRACTABLE) == std::optional(true)));
                    // The module refuses to reveal the value.
                    const std::array<CK_ATTRIBUTE_TYPE, 2> secret{CKA_VALUE, CKA_PRIVATE_EXPONENT};
                    for (const auto& v : b.get_attributes(s, h, secret)) {
                        BOOST_TEST(!v.has_value());
                    }
                    return 0;
                });
            }
        }
    }
    // 15 spec and usage pairs; only secp256k1 may be missing from a
    // distribution's SoftHSM2.
    BOOST_TEST(made.size() >= 14U);
    std::ranges::sort(made);
    BOOST_TEST((store.list() == made));

    for (const auto& r : made) {
        store.destroy(r.key_id, r.version);
        BOOST_TEST(!store.find(r.key_id, r.version).has_value());
    }
    BOOST_TEST(store.list().empty());
    // Destroying what is gone already is not an error.
    store.destroy("key-0", 1);
}

BOOST_AUTO_TEST_CASE(a_wrong_pin_is_the_hsm_unavailable) {
    const softhsm_token token;
    auto backend = std::make_shared<p11::function_list_backend>(KYTHIRA_SOFTHSM2_LIBRARY);
    CK_SLOT_ID slot = 0;
    for (const auto& t : backend->tokens()) {
        if (t.label == "kms") {
            slot = t.slot;
        }
    }
    kms::backing_store store(backend, slot, "wrong");
    try {
        (void)store.generate("k", 1, kms::key_spec::symmetric_default,
                             kms::key_usage::encrypt_decrypt);
        BOOST_FAIL("generated without logging in");
    } catch (const kms::backing_error& e) {
        BOOST_TEST((e.which() == kms::backing_error::kind::unavailable));
    }
}

// Task 7, Requirement 5.2: AES-256-GCM with additional data on a real
// module, the nonce from the token's generator; a changed byte, tag, nonce
// or additional data is refused as the tag, not as a device fault.
BOOST_AUTO_TEST_CASE(aes_gcm_round_trips_and_detects_changes) {
    const softhsm_token token;
    auto backend = std::make_shared<p11::function_list_backend>(KYTHIRA_SOFTHSM2_LIBRARY);
    CK_SLOT_ID slot = 0;
    for (const auto& t : backend->tokens()) {
        if (t.label == "kms") {
            slot = t.slot;
        }
    }
    kms::backing_store store(backend, slot, "1234");
    (void)store.generate("k", 1, kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt);
    const std::vector<std::uint8_t> plain{'s', 'e', 'c', 'r', 'e', 't'};
    const std::vector<std::uint8_t> aad{'a', 'a', 'd'};
    const auto sealed = store.gcm_encrypt("k", 1, plain, aad);
    BOOST_TEST(sealed.ciphertext.size() == plain.size());
    BOOST_TEST((sealed.ciphertext != plain));
    BOOST_TEST((store.gcm_decrypt("k", 1, sealed, aad) == plain));
    // A fresh nonce each time.
    BOOST_TEST((store.gcm_encrypt("k", 1, plain, aad).nonce != sealed.nonce));

    auto bad = sealed;
    bad.ciphertext[0] ^= 1U;
    BOOST_TEST(!store.gcm_decrypt("k", 1, bad, aad).has_value());
    bad = sealed;
    bad.tag[15] ^= 1U;
    BOOST_TEST(!store.gcm_decrypt("k", 1, bad, aad).has_value());
    bad = sealed;
    bad.nonce[0] ^= 1U;
    BOOST_TEST(!store.gcm_decrypt("k", 1, bad, aad).has_value());
    const std::vector<std::uint8_t> other{'a', 'a', 'e'};
    BOOST_TEST(!store.gcm_decrypt("k", 1, sealed, other).has_value());

    BOOST_TEST(store.random(1024).size() == 1024U);
    // A version with no backing key is a failure, not a tag mismatch.
    BOOST_CHECK_THROW((void)store.gcm_encrypt("k", 2, plain, aad), kms::backing_error);
    // After destruction the remembered handle is forgotten.
    store.destroy("k", 1);
    BOOST_CHECK_THROW((void)store.gcm_decrypt("k", 1, sealed, aad), kms::backing_error);
}

// Task 8, Requirements 5.4 and 5.5: the signing, RSA-OAEP and HMAC
// mechanisms as a real module takes them, each checked against the public
// key the token reports, with OpenSSL.
BOOST_AUTO_TEST_CASE(signatures_oaep_and_macs_on_a_real_module) {
    const softhsm_token token;
    auto backend = std::make_shared<p11::function_list_backend>(KYTHIRA_SOFTHSM2_LIBRARY);
    CK_SLOT_ID slot = 0;
    for (const auto& t : backend->tokens()) {
        if (t.label == "kms") {
            slot = t.slot;
        }
    }
    kms::backing_store store(backend, slot, "1234");
    const std::vector<std::uint8_t> message{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    const auto h = kms::digest(kms::hash_alg::sha256, message);

    (void)store.generate("rs", 1, kms::key_spec::rsa_2048, kms::key_usage::sign_verify);
    const auto rsa_pub = store.public_key("rs", 1);
    CK_RSA_PKCS_PSS_PARAMS pss{CKM_SHA256, CKG_MGF1_SHA256, 32};
    const CK_MECHANISM pss_m{CKM_RSA_PKCS_PSS, &pss, sizeof pss};
    const auto pss_sig = store.sign("rs", 1, CKO_PRIVATE_KEY, pss_m, h);
    BOOST_TEST(
        kms::verify_digest(rsa_pub, kms::sig_scheme::pss, kms::hash_alg::sha256, h, pss_sig));
    auto info = kms::digest_info_prefix(kms::hash_alg::sha256);
    info.insert(info.end(), h.begin(), h.end());
    const CK_MECHANISM pkcs1_m{CKM_RSA_PKCS, nullptr, 0};
    const auto pkcs1_sig = store.sign("rs", 1, CKO_PRIVATE_KEY, pkcs1_m, info);
    BOOST_TEST(
        kms::verify_digest(rsa_pub, kms::sig_scheme::pkcs1, kms::hash_alg::sha256, h, pkcs1_sig));
    BOOST_TEST(
        !kms::verify_digest(rsa_pub, kms::sig_scheme::pss, kms::hash_alg::sha256, h, pkcs1_sig));

    (void)store.generate("ec", 1, kms::key_spec::ecc_nist_p256, kms::key_usage::sign_verify);
    const CK_MECHANISM ecdsa_m{CKM_ECDSA, nullptr, 0};
    const auto ec_sig = kms::ecdsa_der(store.sign("ec", 1, CKO_PRIVATE_KEY, ecdsa_m, h));
    BOOST_TEST(kms::verify_digest(store.public_key("ec", 1), kms::sig_scheme::ecdsa,
                                  kms::hash_alg::sha256, h, ec_sig));

    (void)store.generate("re", 1, kms::key_spec::rsa_2048, kms::key_usage::encrypt_decrypt);
    // SoftHSM2 2.6 takes RSA-OAEP with SHA-1 only (anything else is
    // CKR_ARGUMENTS_BAD); RSAES_OAEP_SHA_256 needs a module that has it.
    const auto ct = kms::oaep_encrypt(store.public_key("re", 1), kms::hash_alg::sha1, message);
    BOOST_REQUIRE(ct.has_value());
    CK_RSA_PKCS_OAEP_PARAMS oaep{CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nullptr, 0};
    const CK_MECHANISM oaep_m{CKM_RSA_PKCS_OAEP, &oaep, sizeof oaep};
    BOOST_TEST((store.private_decrypt("re", 1, oaep_m, *ct) == message));
    auto bad = *ct;
    bad[5] ^= 1U;
    BOOST_TEST(!store.private_decrypt("re", 1, oaep_m, bad).has_value());

    (void)store.generate("hm", 1, kms::key_spec::hmac_256, kms::key_usage::generate_verify_mac);
    const CK_MECHANISM hmac_m{CKM_SHA256_HMAC, nullptr, 0};
    const auto mac = store.sign("hm", 1, CKO_SECRET_KEY, hmac_m, message);
    BOOST_TEST(mac.size() == 32U);
    BOOST_TEST((store.sign("hm", 1, CKO_SECRET_KEY, hmac_m, message) == mac));
}
