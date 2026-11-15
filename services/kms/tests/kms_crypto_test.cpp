// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 7 (Requirements 5.1-5.3 and 5.6): Encrypt, Decrypt, ReEncrypt,
// GenerateDataKey, GenerateDataKeyWithoutPlaintext and GenerateRandom
// through signed requests, over a catalog replica and the fake token's
// AES-GCM: round trips, tampering, wrong keys and contexts, key states,
// rotation, the HSM being away, DryRun, and what the authorizer is asked.

#define BOOST_TEST_MODULE kms_crypto_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_ciphertext.hpp>

#include <raft/aws_json_protocol.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

namespace aj = kythira::aws_json;

auto b64(std::string_view s) -> std::string {
    return aj::base64_encode(std::as_bytes(std::span(s.data(), s.size())));
}

auto unb64(const std::string& s) -> std::vector<std::uint8_t> {
    const auto raw = aj::base64_decode(s);
    BOOST_REQUIRE(raw.has_value());
    std::vector<std::uint8_t> out;
    for (const auto b : *raw) {
        out.push_back(std::to_integer<std::uint8_t>(b));
    }
    return out;
}

auto rebase(const std::vector<std::uint8_t>& v) -> std::string {
    return aj::base64_encode(std::as_bytes(std::span(v)));
}

auto encrypt(fixture& f, std::string_view key, std::string_view text,
             const std::string& context = "{}") -> reply {
    return f.call("Encrypt", R"({"KeyId":")" + std::string(key) + R"(","Plaintext":")" + b64(text) +
                                 R"(","EncryptionContext":)" + context + "}");
}

auto decrypt(fixture& f, const std::string& blob, const std::string& context = "{}",
             const std::string& extra = "", std::string_view akid = "AKIDADMIN") -> reply {
    return f.call(
        "Decrypt",
        R"({"CiphertextBlob":")" + blob + R"(","EncryptionContext":)" + context + extra + "}",
        akid);
}

auto text_of(const reply& r) -> std::string {
    const auto v = unb64(r.str("Plaintext"));
    return {v.begin(), v.end()};
}

auto asked_has(const az::authz_request& r, std::string_view key, std::string_view value) -> bool {
    for (const auto& [k, v] : r.keys) {
        if (k == key && std::find(v.begin(), v.end(), value) != v.end()) {
            return true;
        }
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_CASE(encrypt_and_decrypt_round_trip) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/app","TargetKeyId":")" + id + R"("})")
            .status == 200U);
    const std::string context = R"({"tenant":"acme","purpose":"test"})";
    const auto e = encrypt(f, "alias/app", "attack at dawn", context);
    BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
    BOOST_TEST(e.str("KeyId") == fixture::arn(id));
    BOOST_TEST(e.str("EncryptionAlgorithm") == "SYMMETRIC_DEFAULT");

    // The blob names the key and its backing version, and carries no
    // plaintext.
    const auto raw = unb64(e.str("CiphertextBlob"));
    const auto blob = kms::decode_ciphertext(raw);
    BOOST_REQUIRE(blob.has_value());
    BOOST_TEST(blob->key_id == id);
    BOOST_TEST(blob->backing_version == 1U);
    const std::string secret = "attack at dawn";
    BOOST_TEST((std::search(raw.begin(), raw.end(), secret.begin(), secret.end()) == raw.end()));

    // Decrypt needs no KeyId, and the context's order does not matter.
    const auto d = decrypt(f, e.str("CiphertextBlob"), R"({"purpose":"test","tenant":"acme"})");
    BOOST_REQUIRE_MESSAGE(d.status == 200U, d.type() + ": " + d.message());
    BOOST_TEST(text_of(d) == secret);
    BOOST_TEST(d.str("KeyId") == fixture::arn(id));
    BOOST_TEST(d.str("EncryptionAlgorithm") == "SYMMETRIC_DEFAULT");

    // A KeyId naming the same key, by id, ARN or alias, is fine...
    for (const auto& name : {id, fixture::arn(id), std::string("alias/app")}) {
        BOOST_TEST(
            decrypt(f, e.str("CiphertextBlob"), context, R"(,"KeyId":")" + name + R"(")").status ==
                200U,
            name);
    }
    // ...one naming another key is IncorrectKeyException (5.3).
    const auto other = f.create();
    BOOST_TEST(
        decrypt(f, e.str("CiphertextBlob"), context, R"(,"KeyId":")" + other + R"(")").type() ==
        "IncorrectKeyException");

    // Two encryptions of the same plaintext differ (fresh nonces).
    BOOST_TEST(encrypt(f, id, "attack at dawn", context).str("CiphertextBlob") !=
               e.str("CiphertextBlob"));
}

BOOST_AUTO_TEST_CASE(any_change_fails_as_invalid_ciphertext) {
    fixture f;
    const auto id = f.create();
    const auto e = encrypt(f, id, "payload", R"({"k":"v"})");
    BOOST_REQUIRE(e.status == 200U);
    const auto raw = unb64(e.str("CiphertextBlob"));

    // Every byte of the blob matters.
    for (std::size_t i = 0; i < raw.size(); ++i) {
        auto bad = raw;
        bad[i] ^= 0x01U;
        BOOST_TEST(decrypt(f, rebase(bad), R"({"k":"v"})").type() == "InvalidCiphertextException",
                   "byte " << i);
    }
    // So does the context: changed, extended, dropped.
    for (const auto* ctx : {R"({"k":"w"})", R"({"k":"v","x":"y"})", "{}"}) {
        BOOST_TEST(decrypt(f, e.str("CiphertextBlob"), ctx).type() == "InvalidCiphertextException",
                   ctx);
    }
    // Not a blob at all, a truncated one, and a blob naming a backing
    // version the key does not have.
    BOOST_TEST(decrypt(f, b64("not a kms blob")).type() == "InvalidCiphertextException");
    BOOST_TEST(decrypt(f, rebase({raw.begin(), raw.begin() + 20})).type() ==
               "InvalidCiphertextException");
    auto b = kms::decode_ciphertext(raw).value();
    b.backing_version = 9;
    BOOST_TEST(decrypt(f, rebase(kms::encode_ciphertext(b)), R"({"k":"v"})").type() ==
               "InvalidCiphertextException");
    // A blob naming a key that does not exist reads the same.
    b = kms::decode_ciphertext(raw).value();
    b.key_id = "00000000-0000-4000-8000-000000000000";
    BOOST_TEST(decrypt(f, rebase(kms::encode_ciphertext(b)), R"({"k":"v"})").type() ==
               "InvalidCiphertextException");
}

BOOST_AUTO_TEST_CASE(key_state_usage_and_algorithm) {
    fixture f;
    const auto id = f.create();
    const auto e = encrypt(f, id, "x");
    BOOST_REQUIRE(e.status == 200U);

    BOOST_REQUIRE(f.call("DisableKey", kid(id)).status == 200U);
    BOOST_TEST(encrypt(f, id, "x").type() == "DisabledException");
    BOOST_TEST(decrypt(f, e.str("CiphertextBlob")).type() == "DisabledException");
    BOOST_REQUIRE(f.call("EnableKey", kid(id)).status == 200U);
    BOOST_REQUIRE(f.call("ScheduleKeyDeletion", kid(id)).status == 200U);
    BOOST_TEST(encrypt(f, id, "x").type() == "KMSInvalidStateException");
    BOOST_TEST(decrypt(f, e.str("CiphertextBlob")).type() == "KMSInvalidStateException");

    const auto mac = f.create(R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})");
    BOOST_TEST(encrypt(f, mac, "x").type() == "InvalidKeyUsageException");
    const auto rsa = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    BOOST_TEST(encrypt(f, rsa, "x").type() == "ValidationException");

    const auto good = f.create();
    BOOST_TEST(f.call("Encrypt", R"({"KeyId":")" + good + R"(","Plaintext":")" + b64("x") +
                                     R"(","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"})")
                   .type() == "InvalidKeyUsageException");
    // The model's limits: 1 to 4096 bytes of plaintext.
    BOOST_TEST(encrypt(f, good, std::string(4096, 'a')).status == 200U);
    BOOST_TEST(encrypt(f, good, std::string(4097, 'a')).type() == "ValidationException");
    BOOST_TEST(f.call("Encrypt", R"({"KeyId":")" + good + R"(","Plaintext":""})").type() ==
               "ValidationException");
    BOOST_TEST(encrypt(f, "alias/none", "x").type() == "NotFoundException");
}

BOOST_AUTO_TEST_CASE(an_older_backing_version_still_decrypts) {
    fixture f;
    const auto id = f.create();
    const auto before = encrypt(f, id, "old");
    BOOST_REQUIRE(before.status == 200U);
    BOOST_REQUIRE(f.jobs.rotate(id, kms::rotation_type::on_demand).ok());
    BOOST_TEST(f.sm.key(id)->current_version == 2U);
    const auto after = encrypt(f, id, "new");
    BOOST_TEST(kms::decode_ciphertext(unb64(after.str("CiphertextBlob")))->backing_version == 2U);
    BOOST_TEST(text_of(decrypt(f, before.str("CiphertextBlob"))) == "old");
    BOOST_TEST(text_of(decrypt(f, after.str("CiphertextBlob"))) == "new");
}

BOOST_AUTO_TEST_CASE(re_encrypt_moves_a_ciphertext_between_keys) {
    fixture f;
    const auto a = f.create();
    const auto b = f.create();
    const auto e = encrypt(f, a, "moving", R"({"from":"a"})");
    BOOST_REQUIRE(e.status == 200U);
    f.auth.asked.clear();
    const auto r = f.call("ReEncrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") +
                                           R"(","SourceEncryptionContext":{"from":"a"},)"
                                           R"("DestinationKeyId":")" +
                                           b + R"(","DestinationEncryptionContext":{"to":"b"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("SourceKeyId") == fixture::arn(a));
    BOOST_TEST(r.str("KeyId") == fixture::arn(b));
    BOOST_TEST(r.str("SourceEncryptionAlgorithm") == "SYMMETRIC_DEFAULT");
    BOOST_TEST(r.str("DestinationEncryptionAlgorithm") == "SYMMETRIC_DEFAULT");
    BOOST_REQUIRE(f.auth.asked.size() == 2U);
    BOOST_TEST(f.auth.asked[0].action == "kms:ReEncryptTo");
    BOOST_TEST(f.auth.asked[0].resource == fixture::arn(b));
    BOOST_TEST(asked_has(f.auth.asked[0], "kms:EncryptionContext:to", "b"));
    BOOST_TEST(f.auth.asked[1].action == "kms:ReEncryptFrom");
    BOOST_TEST(f.auth.asked[1].resource == fixture::arn(a));
    BOOST_TEST(asked_has(f.auth.asked[1], "kms:EncryptionContext:from", "a"));

    BOOST_TEST(text_of(decrypt(f, r.str("CiphertextBlob"), R"({"to":"b"})")) == "moving");
    BOOST_TEST(decrypt(f, r.str("CiphertextBlob"), R"({"from":"a"})").type() ==
               "InvalidCiphertextException");
    // The wrong source context fails as the ciphertext.
    BOOST_TEST(f.call("ReEncrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") +
                                       R"(","DestinationKeyId":")" + b + R"("})")
                   .type() == "InvalidCiphertextException");
    // A SourceKeyId naming another key.
    BOOST_TEST(
        f.call("ReEncrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") +
                                R"(","SourceEncryptionContext":{"from":"a"},"SourceKeyId":")" + b +
                                R"(","DestinationKeyId":")" + b + R"("})")
            .type() == "IncorrectKeyException");
}

BOOST_AUTO_TEST_CASE(data_keys_and_random_bytes) {
    fixture f;
    const auto id = f.create();
    const auto dk =
        f.call("GenerateDataKey",
               R"({"KeyId":")" + id + R"(","KeySpec":"AES_256","EncryptionContext":{"s":"1"}})");
    BOOST_REQUIRE_MESSAGE(dk.status == 200U, dk.type() + ": " + dk.message());
    BOOST_TEST(dk.str("KeyId") == fixture::arn(id));
    const auto key = unb64(dk.str("Plaintext"));
    BOOST_TEST(key.size() == 32U);
    // The blob decrypts to the plaintext key.
    const auto d = decrypt(f, dk.str("CiphertextBlob"), R"({"s":"1"})");
    BOOST_TEST((unb64(d.str("Plaintext")) == key));

    BOOST_TEST(unb64(f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","KeySpec":"AES_128"})")
                         .str("Plaintext"))
                   .size() == 16U);
    BOOST_TEST(unb64(f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","NumberOfBytes":7})")
                         .str("Plaintext"))
                   .size() == 7U);
    BOOST_TEST(f.call("GenerateDataKey", R"({"KeyId":")" + id + R"("})").type() ==
               "ValidationException");
    BOOST_TEST(f.call("GenerateDataKey",
                      R"({"KeyId":")" + id + R"(","KeySpec":"AES_256","NumberOfBytes":32})")
                   .type() == "ValidationException");
    BOOST_TEST(
        f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","NumberOfBytes":1025})").type() ==
        "ValidationException");

    const auto wp = f.call("GenerateDataKeyWithoutPlaintext",
                           R"({"KeyId":")" + id + R"(","KeySpec":"AES_256"})");
    BOOST_REQUIRE(wp.status == 200U);
    BOOST_TEST(!wp.body.contains("Plaintext"));
    BOOST_TEST(unb64(decrypt(f, wp.str("CiphertextBlob")).str("Plaintext")).size() == 32U);

    f.auth.asked.clear();
    const auto r = f.call("GenerateRandom", R"({"NumberOfBytes":1024})");
    BOOST_REQUIRE(r.status == 200U);
    BOOST_TEST(unb64(r.str("Plaintext")).size() == 1024U);
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    BOOST_TEST(f.auth.asked[0].action == "kms:GenerateRandom");
    BOOST_TEST(f.auth.asked[0].resource == "*");
    BOOST_TEST(f.call("GenerateRandom", R"({"NumberOfBytes":0})").type() == "ValidationException");
    BOOST_TEST(f.call("GenerateRandom", R"({"NumberOfBytes":1025})").type() ==
               "ValidationException");
    BOOST_TEST(f.call("GenerateRandom", "{}").type() == "ValidationException");
    BOOST_TEST(f.call("GenerateRandom", R"({"NumberOfBytes":8,"CustomKeyStoreId":)"
                                        R"("cks-1234567890abcdef0"})")
                   .type() == "UnsupportedOperationException");
}

BOOST_AUTO_TEST_CASE(the_hsm_away_and_no_leader) {
    fixture f;
    const auto id = f.create();
    const auto e = encrypt(f, id, "x");
    BOOST_REQUIRE(e.status == 200U);

    f.hsm_bound = false;
    for (const auto& r : {encrypt(f, id, "x"), decrypt(f, e.str("CiphertextBlob")),
                          f.call("GenerateRandom", R"({"NumberOfBytes":8})")}) {
        BOOST_TEST(r.status == 500U);
        BOOST_TEST(r.type() == "KMSInternalException");
    }
    f.hsm_bound = true;
    f.hsm_backend->sealed = true;
    BOOST_TEST(encrypt(f, id, "x").type() == "KMSInternalException");
    BOOST_TEST(decrypt(f, e.str("CiphertextBlob")).type() == "KMSInternalException");
    f.hsm_backend->sealed = false;
    BOOST_TEST(decrypt(f, e.str("CiphertextBlob")).status == 200U);

    f.leaderless = true;
    BOOST_TEST(encrypt(f, id, "x").type() == "DependencyTimeoutException");
}

BOOST_AUTO_TEST_CASE(dry_run_authorizes_and_stops) {
    fixture f;
    const auto id = f.create();
    const auto e = encrypt(f, id, "x");
    const auto calls = f.hsm_backend->crypto_calls;
    const auto dry = f.call(
        "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":")" + b64("x") + R"(","DryRun":true})");
    BOOST_TEST(dry.status == 412U);
    BOOST_TEST(dry.type() == "DryRunOperationException");
    BOOST_TEST(decrypt(f, e.str("CiphertextBlob"), "{}", R"(,"DryRun":true)").type() ==
               "DryRunOperationException");
    BOOST_TEST(
        f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","KeySpec":"AES_256","DryRun":true})")
            .type() == "DryRunOperationException");
    BOOST_TEST(f.hsm_backend->crypto_calls == calls);
    // A caller who may not encrypt is refused, not told it would succeed.
    BOOST_TEST(
        f.call("Encrypt",
               R"({"KeyId":")" + id + R"(","Plaintext":")" + b64("x") + R"(","DryRun":true})",
               "AKIDREAD")
            .type() == "AccessDeniedException");
}

BOOST_AUTO_TEST_CASE(what_the_authorizer_is_asked) {
    fixture f;
    const auto id = f.create();
    f.auth.asked.clear();
    const auto e = encrypt(f, id, "x", R"({"dept":"eng","app":"web"})");
    BOOST_REQUIRE(e.status == 200U);
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    const auto& r = f.auth.asked[0];
    BOOST_TEST(r.action == "kms:Encrypt");
    BOOST_TEST(r.resource == fixture::arn(id));
    BOOST_TEST((r.resource_kind == az::resource_policy_kind::key));
    BOOST_TEST(r.resource_policy.value_or("") == f.sm.key(id)->policy);
    BOOST_TEST(asked_has(r, "kms:EncryptionContext:dept", "eng"));
    BOOST_TEST(asked_has(r, "kms:EncryptionContextKeys", "app"));
    BOOST_TEST(asked_has(r, "kms:EncryptionContextKeys", "dept"));
    BOOST_TEST(asked_has(r, "kms:EncryptionAlgorithm", "SYMMETRIC_DEFAULT"));

    // The read-only key may not encrypt or decrypt; the refusal carries
    // no plaintext.
    BOOST_TEST(encrypt(f, id, "x").status == 200U);
    const auto denied =
        decrypt(f, e.str("CiphertextBlob"), R"({"dept":"eng","app":"web"})", "", "AKIDREAD");
    BOOST_TEST(denied.type() == "AccessDeniedException");
    BOOST_TEST(!denied.body.contains("Plaintext"));
    // Another account holding the blob is asked about the key's account,
    // and static keys refuse it.
    f.auth.asked.clear();
    const auto stranger =
        decrypt(f, e.str("CiphertextBlob"), R"({"dept":"eng","app":"web"})", "", "AKIDOTHER");
    BOOST_TEST(stranger.type() == "AccessDeniedException");
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    BOOST_TEST(f.auth.asked[0].resource_account == k_account);
    BOOST_TEST(f.auth.asked[0].action == "kms:Decrypt");
}

BOOST_AUTO_TEST_CASE(every_crypto_operation_is_registered) {
    fixture f;
    for (const auto op : kms::crypto_api<catalog_t>::k_operations) {
        BOOST_TEST(f.fe.handles(op), op);
    }
}
