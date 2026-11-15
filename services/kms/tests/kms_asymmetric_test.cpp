// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 8 (Requirements 3.2, 5.1, 5.4 and 5.5): RSA-OAEP encryption, Sign
// and Verify (RAW and DIGEST) for every RSA and ECC key spec and
// algorithm, GetPublicKey, GenerateDataKeyPair, and HMAC keys'
// GenerateMac and VerifyMac, through signed requests over the fake
// token's real key pairs. Every signature, public key and data key pair
// is checked independently with OpenSSL.

#define BOOST_TEST_MODULE kms_asymmetric_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_public_key.hpp>

#include <raft/aws_json_protocol.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

namespace aj = kythira::aws_json;

struct pkey_free {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using pkey = std::unique_ptr<EVP_PKEY, pkey_free>;

auto b64(std::span<const std::uint8_t> v) -> std::string {
    return aj::base64_encode(std::as_bytes(v));
}

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

auto public_key_of(fixture& f, const std::string& id) -> pkey {
    const auto r = f.call("GetPublicKey", kid(id));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto der = unb64(r.str("PublicKey"));
    const unsigned char* p = der.data();
    pkey k(d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size())));
    BOOST_REQUIRE(k);
    return k;
}

auto md_named(std::string_view alg) -> const EVP_MD* {
    if (alg.ends_with("384")) {
        return EVP_sha384();
    }
    if (alg.ends_with("512")) {
        return EVP_sha512();
    }
    return EVP_sha256();
}

/// OpenSSL's own verdict on a signature over `message`.
auto openssl_verifies(EVP_PKEY* k, std::string_view alg, std::span<const std::uint8_t> message,
                      std::span<const std::uint8_t> sig) -> bool {
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                      &EVP_MD_CTX_free);
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(ctx.get(), &pctx, md_named(alg), nullptr, k) != 1) {
        return false;
    }
    if (alg.starts_with("RSASSA_PSS")) {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), message.data(), message.size()) == 1;
}

auto sign_request(const std::string& id, std::string_view alg, const std::string& message,
                  std::string_view type = "RAW") -> std::string {
    return R"({"KeyId":")" + id + R"(","Message":")" + message + R"(","SigningAlgorithm":")" +
           std::string(alg) + R"(","MessageType":")" + std::string(type) + R"("})";
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

BOOST_AUTO_TEST_CASE(rsa_oaep_round_trips_and_matches_openssl) {
    fixture f;
    const auto id = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    for (const std::string& alg :
         std::vector<std::string>{"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"}) {
        BOOST_TEST_CONTEXT(alg) {
            const auto e =
                f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":")" + b64("rsa secret") +
                                      R"(","EncryptionAlgorithm":")" + alg + R"("})");
            BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
            BOOST_TEST(e.str("EncryptionAlgorithm") == alg);
            BOOST_TEST(unb64(e.str("CiphertextBlob")).size() == 256U);
            const auto d = f.call("Decrypt", R"({"KeyId":")" + id + R"(","CiphertextBlob":")" +
                                                 e.str("CiphertextBlob") +
                                                 R"(","EncryptionAlgorithm":")" + alg + R"("})");
            BOOST_REQUIRE_MESSAGE(d.status == 200U, d.type() + ": " + d.message());
            const auto plain = unb64(d.str("Plaintext"));
            BOOST_TEST(std::string(plain.begin(), plain.end()) == "rsa secret");
            BOOST_TEST(d.str("EncryptionAlgorithm") == alg);
        }
    }
    // OpenSSL encrypts against GetPublicKey's answer; the KMS decrypts.
    const auto k = public_key_of(f, id);
    const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(k.get(), nullptr), &EVP_PKEY_CTX_free);
    const std::string msg = "from openssl";
    std::size_t n = 0;
    BOOST_REQUIRE(EVP_PKEY_encrypt_init(ctx.get()) == 1);
    EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());
    const auto* in = reinterpret_cast<const unsigned char*>(msg.data());  // NOLINT
    EVP_PKEY_encrypt(ctx.get(), nullptr, &n, in, msg.size());
    std::vector<std::uint8_t> ct(n);
    BOOST_REQUIRE(EVP_PKEY_encrypt(ctx.get(), ct.data(), &n, in, msg.size()) == 1);
    const auto d = f.call("Decrypt", R"({"KeyId":")" + id + R"(","CiphertextBlob":")" + b64(ct) +
                                         R"(","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"})");
    BOOST_TEST(unb64(d.str("Plaintext")) == std::vector<std::uint8_t>(msg.begin(), msg.end()));

    // Without KeyId an RSA ciphertext is not a blob; the wrong hash or a
    // changed byte fails as the ciphertext.
    BOOST_TEST(f.call("Decrypt", R"({"CiphertextBlob":")" + b64(ct) + R"("})").type() ==
               "InvalidCiphertextException");
    BOOST_TEST(f.call("Decrypt", R"({"KeyId":")" + id + R"(","CiphertextBlob":")" + b64(ct) +
                                     R"(","EncryptionAlgorithm":"RSAES_OAEP_SHA_1"})")
                   .type() == "InvalidCiphertextException");
    ct[10] ^= 1U;
    BOOST_TEST(f.call("Decrypt", R"({"KeyId":")" + id + R"(","CiphertextBlob":")" + b64(ct) +
                                     R"(","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"})")
                   .type() == "InvalidCiphertextException");

    // The algorithm is required, a context is refused, and 2048-bit
    // OAEP-SHA-256 carries at most 190 bytes.
    const auto enc = [&](const std::string& extra, std::size_t len) {
        return f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":")" +
                                     b64(std::string(len, 'p')) + R"(")" + extra + "}");
    };
    BOOST_TEST(enc("", 10).type() == "ValidationException");
    BOOST_TEST(enc(R"(,"EncryptionAlgorithm":"SYMMETRIC_DEFAULT")", 10).type() ==
               "InvalidKeyUsageException");
    BOOST_TEST(
        enc(R"(,"EncryptionAlgorithm":"RSAES_OAEP_SHA_256","EncryptionContext":{"a":"b"})", 10)
            .type() == "ValidationException");
    BOOST_TEST(enc(R"(,"EncryptionAlgorithm":"RSAES_OAEP_SHA_256")", 190).status == 200U);
    BOOST_TEST(enc(R"(,"EncryptionAlgorithm":"RSAES_OAEP_SHA_256")", 191).type() ==
               "ValidationException");
    // Data keys are sealed only under symmetric keys.
    BOOST_TEST(
        f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","KeySpec":"AES_256"})").type() ==
        "InvalidKeyUsageException");
}

BOOST_AUTO_TEST_CASE(re_encrypt_from_rsa_to_symmetric) {
    fixture f;
    const auto rsa = f.create(R"({"KeySpec":"RSA_3072","KeyUsage":"ENCRYPT_DECRYPT"})");
    const auto sym = f.create();
    const auto e = f.call("Encrypt", R"({"KeyId":")" + rsa + R"(","Plaintext":")" + b64("hop") +
                                         R"(","EncryptionAlgorithm":"RSAES_OAEP_SHA_1"})");
    BOOST_REQUIRE(e.status == 200U);
    const auto r = f.call("ReEncrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") +
                                           R"(","SourceKeyId":")" + rsa +
                                           R"(","SourceEncryptionAlgorithm":"RSAES_OAEP_SHA_1",)"
                                           R"("DestinationKeyId":")" +
                                           sym + R"("})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("SourceEncryptionAlgorithm") == "RSAES_OAEP_SHA_1");
    BOOST_TEST(r.str("DestinationEncryptionAlgorithm") == "SYMMETRIC_DEFAULT");
    const auto d = f.call("Decrypt", R"({"CiphertextBlob":")" + r.str("CiphertextBlob") + R"("})");
    BOOST_TEST(unb64(d.str("Plaintext")) == std::vector<std::uint8_t>({'h', 'o', 'p'}));
}

BOOST_AUTO_TEST_CASE(every_signing_algorithm_verifies_with_openssl) {
    fixture f;
    struct cs {
        std::string spec;
        std::vector<std::string> algs;
    };
    const std::vector<cs> cases{
        {"RSA_2048",
         {"RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_384", "RSASSA_PSS_SHA_512",
          "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PKCS1_V1_5_SHA_512"}},
        {"ECC_NIST_P256", {"ECDSA_SHA_256"}},
        {"ECC_NIST_P384", {"ECDSA_SHA_384"}},
        {"ECC_NIST_P521", {"ECDSA_SHA_512"}},
        {"ECC_SECG_P256K1", {"ECDSA_SHA_256"}},
    };
    const std::string text = "the message to sign";
    const std::vector<std::uint8_t> message(text.begin(), text.end());
    for (const auto& c : cases) {
        const auto id = f.create(R"({"KeySpec":")" + c.spec + R"(","KeyUsage":"SIGN_VERIFY"})");
        const auto k = public_key_of(f, id);
        for (const auto& alg : c.algs) {
            BOOST_TEST_CONTEXT(c.spec << " " << alg) {
                const auto s = f.call("Sign", sign_request(id, alg, b64(message)));
                BOOST_REQUIRE_MESSAGE(s.status == 200U, s.type() + ": " + s.message());
                BOOST_TEST(s.str("SigningAlgorithm") == alg);
                const auto sig = unb64(s.str("Signature"));
                BOOST_TEST(openssl_verifies(k.get(), alg, message, sig));

                // DIGEST: the caller hashes; the same signature verifies.
                const auto h = kms::digest(alg.ends_with("384")   ? kms::hash_alg::sha384
                                           : alg.ends_with("512") ? kms::hash_alg::sha512
                                                                  : kms::hash_alg::sha256,
                                           message);
                const auto ds = f.call("Sign", sign_request(id, alg, b64(h), "DIGEST"));
                BOOST_REQUIRE(ds.status == 200U);
                BOOST_TEST(openssl_verifies(k.get(), alg, message, unb64(ds.str("Signature"))));

                // The KMS's own Verify, and a refusal for a changed message.
                const auto v =
                    f.call("Verify", R"({"KeyId":")" + id + R"(","Message":")" + b64(message) +
                                         R"(","Signature":")" + s.str("Signature") +
                                         R"(","SigningAlgorithm":")" + alg + R"("})");
                BOOST_TEST(v.status == 200U, v.type() + ": " + v.message());
                BOOST_TEST(v.body.at("SignatureValid").as_bool());
                const auto bad = f.call("Verify", R"({"KeyId":")" + id + R"(","Message":")" +
                                                      b64("another message") +
                                                      R"(","Signature":")" + s.str("Signature") +
                                                      R"(","SigningAlgorithm":")" + alg + R"("})");
                BOOST_TEST(bad.type() == "KMSInvalidSignatureException");
                BOOST_TEST(f.call("Verify", R"({"KeyId":")" + id + R"(","Message":")" + b64(h) +
                                                R"(","MessageType":"DIGEST","Signature":")" +
                                                ds.str("Signature") + R"(","SigningAlgorithm":")" +
                                                alg + R"("})")
                               .status == 200U);
                // A DIGEST of the wrong length.
                BOOST_TEST(f.call("Sign", sign_request(id, alg, b64("short"), "DIGEST")).type() ==
                           "ValidationException");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(signing_refusals) {
    fixture f;
    const auto ec = f.create(R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"})");
    const auto enc = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    const auto sym = f.create();
    BOOST_TEST(f.call("Sign", sign_request(ec, "ECDSA_SHA_384", b64("m"))).type() ==
               "InvalidKeyUsageException");
    BOOST_TEST(f.call("Sign", sign_request(ec, "RSASSA_PSS_SHA_256", b64("m"))).type() ==
               "InvalidKeyUsageException");
    BOOST_TEST(f.call("Sign", sign_request(enc, "RSASSA_PSS_SHA_256", b64("m"))).type() ==
               "InvalidKeyUsageException");
    BOOST_TEST(f.call("Sign", sign_request(sym, "RSASSA_PSS_SHA_256", b64("m"))).type() ==
               "InvalidKeyUsageException");
    BOOST_REQUIRE(f.call("DisableKey", kid(ec)).status == 200U);
    BOOST_TEST(f.call("Sign", sign_request(ec, "ECDSA_SHA_256", b64("m"))).type() ==
               "DisabledException");
    BOOST_TEST(f.call("GetPublicKey", kid(ec)).type() == "DisabledException");
    BOOST_TEST(f.call("GetPublicKey", kid(sym)).type() == "UnsupportedOperationException");

    // The authorizer sees the algorithm and message type.
    const auto ec2 = f.create(R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"})");
    f.auth.asked.clear();
    BOOST_REQUIRE(f.call("Sign", sign_request(ec2, "ECDSA_SHA_256", b64("m"))).status == 200U);
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    BOOST_TEST(f.auth.asked[0].action == "kms:Sign");
    BOOST_TEST(asked_has(f.auth.asked[0], "kms:SigningAlgorithm", "ECDSA_SHA_256"));
    BOOST_TEST(asked_has(f.auth.asked[0], "kms:MessageType", "RAW"));
    // The read-only key may get the public key, not sign.
    BOOST_TEST(f.call("GetPublicKey", kid(ec2), "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("Sign", sign_request(ec2, "ECDSA_SHA_256", b64("m")), "AKIDREAD").type() ==
               "AccessDeniedException");
}

BOOST_AUTO_TEST_CASE(get_public_key_describes_the_key) {
    fixture f;
    const auto id = f.create(R"({"KeySpec":"RSA_4096","KeyUsage":"ENCRYPT_DECRYPT"})");
    const auto r = f.call("GetPublicKey", kid(id));
    BOOST_REQUIRE(r.status == 200U);
    BOOST_TEST(r.str("KeyId") == fixture::arn(id));
    BOOST_TEST(r.str("KeySpec") == "RSA_4096");
    BOOST_TEST(r.str("KeyUsage") == "ENCRYPT_DECRYPT");
    BOOST_TEST(r.body.at("EncryptionAlgorithms").as_array().size() == 2U);
    BOOST_TEST(!r.body.contains("SigningAlgorithms"));
    BOOST_TEST(EVP_PKEY_get_bits(public_key_of(f, id).get()) == 4096);
    const auto ec = f.create(R"({"KeySpec":"ECC_SECG_P256K1","KeyUsage":"SIGN_VERIFY"})");
    const auto e = f.call("GetPublicKey", kid(ec));
    BOOST_TEST(e.body.at("SigningAlgorithms").as_array().size() == 1U);
    BOOST_TEST(EVP_PKEY_get_bits(public_key_of(f, ec).get()) == 256);
}

BOOST_AUTO_TEST_CASE(hmac_keys_generate_and_verify_macs) {
    fixture f;
    for (const std::string& bits : std::vector<std::string>{"224", "256", "384", "512"}) {
        BOOST_TEST_CONTEXT(bits) {
            const auto id =
                f.create(R"({"KeySpec":"HMAC_)" + bits + R"(","KeyUsage":"GENERATE_VERIFY_MAC"})");
            const auto alg = "HMAC_SHA_" + bits;
            const auto m =
                f.call("GenerateMac", R"({"KeyId":")" + id + R"(","Message":")" + b64("mac me") +
                                          R"(","MacAlgorithm":")" + alg + R"("})");
            BOOST_REQUIRE_MESSAGE(m.status == 200U, m.type() + ": " + m.message());
            BOOST_TEST(unb64(m.str("Mac")).size() == std::stoul(bits) / 8);
            BOOST_TEST(m.str("MacAlgorithm") == alg);
            const auto again =
                f.call("GenerateMac", R"({"KeyId":")" + id + R"(","Message":")" + b64("mac me") +
                                          R"(","MacAlgorithm":")" + alg + R"("})");
            BOOST_TEST(again.str("Mac") == m.str("Mac"));
            const auto v = f.call("VerifyMac", R"({"KeyId":")" + id + R"(","Message":")" +
                                                   b64("mac me") + R"(","Mac":")" + m.str("Mac") +
                                                   R"(","MacAlgorithm":")" + alg + R"("})");
            BOOST_TEST(v.status == 200U);
            BOOST_TEST(v.body.at("MacValid").as_bool());
            BOOST_TEST(f.call("VerifyMac", R"({"KeyId":")" + id + R"(","Message":")" +
                                               b64("mac you") + R"(","Mac":")" + m.str("Mac") +
                                               R"(","MacAlgorithm":")" + alg + R"("})")
                           .type() == "KMSInvalidMacException");
        }
    }
    const auto id = f.create(R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})");
    BOOST_TEST(f.call("GenerateMac", R"({"KeyId":")" + id + R"(","Message":")" + b64("m") +
                                         R"(","MacAlgorithm":"HMAC_SHA_512"})")
                   .type() == "InvalidKeyUsageException");
    const auto sym = f.create();
    BOOST_TEST(f.call("GenerateMac", R"({"KeyId":")" + sym + R"(","Message":")" + b64("m") +
                                         R"(","MacAlgorithm":"HMAC_SHA_256"})")
                   .type() == "InvalidKeyUsageException");
    f.auth.asked.clear();
    (void)f.call("GenerateMac", R"({"KeyId":")" + id + R"(","Message":")" + b64("m") +
                                    R"(","MacAlgorithm":"HMAC_SHA_256"})");
    BOOST_REQUIRE(!f.auth.asked.empty());
    BOOST_TEST(asked_has(f.auth.asked[0], "kms:MacAlgorithm", "HMAC_SHA_256"));
}

BOOST_AUTO_TEST_CASE(data_key_pairs_are_real_and_sealed) {
    fixture f;
    const auto id = f.create();
    for (const std::string& spec :
         std::vector<std::string>{"RSA_2048", "ECC_NIST_P256", "ECC_SECG_P256K1"}) {
        BOOST_TEST_CONTEXT(spec) {
            f.auth.asked.clear();
            const auto r =
                f.call("GenerateDataKeyPair", R"({"KeyId":")" + id + R"(","KeyPairSpec":")" + spec +
                                                  R"(","EncryptionContext":{"use":"pair"}})");
            BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
            BOOST_TEST(r.str("KeyPairSpec") == spec);
            BOOST_TEST(asked_has(f.auth.asked.at(0), "kms:DataKeyPairSpec", spec));
            // The private key parses and its public half is PublicKey.
            const auto priv = unb64(r.str("PrivateKeyPlaintext"));
            const unsigned char* p = priv.data();
            PKCS8_PRIV_KEY_INFO* p8 =
                d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(priv.size()));
            BOOST_REQUIRE(p8 != nullptr);
            const pkey k(EVP_PKCS82PKEY(p8));
            PKCS8_PRIV_KEY_INFO_free(p8);
            BOOST_REQUIRE(k);
            const int n = i2d_PUBKEY(k.get(), nullptr);
            std::vector<std::uint8_t> spki(static_cast<std::size_t>(n));
            unsigned char* sp = spki.data();
            i2d_PUBKEY(k.get(), &sp);
            BOOST_TEST(spki == unb64(r.str("PublicKey")));
            // The ciphertext blob decrypts to the private key.
            const auto d =
                f.call("Decrypt", R"({"CiphertextBlob":")" + r.str("PrivateKeyCiphertextBlob") +
                                      R"(","EncryptionContext":{"use":"pair"}})");
            BOOST_TEST(unb64(d.str("Plaintext")) == priv);
        }
    }
    const auto wp = f.call("GenerateDataKeyPairWithoutPlaintext",
                           R"({"KeyId":")" + id + R"(","KeyPairSpec":"ECC_NIST_P384"})");
    BOOST_REQUIRE(wp.status == 200U);
    BOOST_TEST(!wp.body.contains("PrivateKeyPlaintext"));
    BOOST_TEST(wp.body.contains("PublicKey"));
    BOOST_TEST(
        f.call("GenerateDataKeyPair", R"({"KeyId":")" + id + R"(","KeyPairSpec":"SM2"})").type() ==
        "UnsupportedOperationException");
    const auto rsa = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    BOOST_TEST(
        f.call("GenerateDataKeyPair", R"({"KeyId":")" + rsa + R"(","KeyPairSpec":"ECC_NIST_P256"})")
            .type() == "InvalidKeyUsageException");
}

BOOST_AUTO_TEST_CASE(every_signing_operation_is_registered) {
    fixture f;
    for (const auto op : kms::signing_api<catalog_t>::k_operations) {
        BOOST_TEST(f.fe.handles(op), op);
    }
}
