// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Decrypt's Kythira recipient (.kiro/specs/ec2-compatible-api/ task 8,
// Requirements 10.2-10.3): HPKE base mode with DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and AES-256-GCM against the CFRG test vector
// for the suite and a VolumeKey frame made by antikythera's own code, then
// Decrypt with KYTHIRA_HPKE_X25519_SHA256_AES256GCM through signed
// requests: what it returns and what it never returns, the condition key
// it adds, and the requests it refuses.

#define BOOST_TEST_MODULE kms_recipient_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_hpke.hpp>

#include <raft/aws_json_protocol.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kms::hpke {
inline auto operator<<(std::ostream& os, error e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace kythira::kms::hpke

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

namespace aj = kythira::aws_json;
namespace hpke = kythira::kms::hpke;
using bytes = std::vector<std::byte>;

auto hex(std::string_view s) -> bytes {
    const auto nibble = [](char c) -> unsigned {
        return c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
    };
    bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>((nibble(s[i]) << 4U) | nibble(s[i + 1])));
    }
    return out;
}

template<std::size_t N> auto fixed(std::string_view s) -> std::array<std::byte, N> {
    const auto b = hex(s);
    BOOST_TEST_REQUIRE(b.size() == N);
    std::array<std::byte, N> out{};
    std::ranges::copy(b, out.begin());
    return out;
}

auto as_bytes(std::string_view s) -> std::span<const std::byte> {
    return std::as_bytes(std::span{s.data(), s.size()});
}

auto b64(std::span<const std::byte> b) -> std::string {
    return aj::base64_encode(b);
}

auto unb64(const std::string& s) -> bytes {
    auto raw = aj::base64_decode(s);
    BOOST_REQUIRE(raw.has_value());
    return {raw->begin(), raw->end()};
}

// The CFRG vector: draft-irtf-cfrg-hpke test-vectors.json, mode 0, kem
// 0x20, kdf 1, aead 2, sequence number 0.
const auto info = hex("4f6465206f6e2061204772656369616e2055726e");
const auto ikm_e = fixed<32>("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9");
const auto pk_em = fixed<32>("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
const auto sk_em = hex("179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11");
const auto ikm_r = hex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
const auto pk_rm = fixed<32>("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
const auto sk_rm = fixed<32>("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
const auto aad0 = hex("436f756e742d30");
const auto pt = hex("4265617574792069732074727574682c20747275746820626561757479");
const auto ct0 = hex(
    "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a");

// SHA-256 of pk_rm, lower-case hex: the condition key's value.
constexpr std::string_view pk_rm_sha256 =
    "69df8d73e7407153d44babaf63e78f7a37ea1cb4f043588b75b51b02f8f9ddc3";

// A VolumeKey frame (antikythera src/proto/volume_key.hpp) made by
// antikythera's helm/hpke.cpp and proto::encode_volume_key at main
// 99e1a5e: recipient pk_rm, server 7, volume 0x5001, attachment 0x9001,
// generation 3, data key bytes 0x00..0x3f, ephemeral ikm 0x10..0x2f, info
// "antikythera volume key v1". The AAD is the frame's first 0x28 bytes.
constexpr std::string_view volume_key_info = "antikythera volume key v1";
const auto volume_key_aad =
    hex("414b564b010000000700000000000000015000000000000001900000000000000300000000000000");
const auto volume_key_enc =
    fixed<32>("1d682f8bb8b6fea684a63bd478009bc62050d365c18a68803261a055b162925e");
const auto volume_key_wrapped = hex(
    "f9c35709f543456f94efa6a89cbf63ab2d680374b22ed40d618e61e58ea3e199a934a350781873a62c83dffc42ac7f"
    "e6e1c89c19301958ca8bbd4688cfbc96056b0561db3a39277039c352656b576436");

auto counting(std::size_t n, unsigned first) -> bytes {
    bytes out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::byte>(first + i);
    }
    return out;
}

auto asked_has(const az::authz_request& r, std::string_view key, std::string_view value) -> bool {
    return std::ranges::any_of(r.keys, [&](const auto& kv) {
        return kv.first == key && std::ranges::find(kv.second, value) != kv.second.end();
    });
}

}  // namespace

BOOST_AUTO_TEST_CASE(derive_key_pair_matches_the_vector) {
    const auto r = hpke::derive_key_pair(ikm_r);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((r->public_key_bytes == pk_rm));
    const auto rs = r->private_key.span();
    BOOST_TEST((bytes(rs.begin(), rs.end()) == bytes(sk_rm.begin(), sk_rm.end())));
    const auto e = hpke::derive_key_pair(ikm_e);
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST((e->public_key_bytes == pk_em));
    const auto es = e->private_key.span();
    BOOST_TEST((bytes(es.begin(), es.end()) == sk_em));
}

BOOST_AUTO_TEST_CASE(seal_and_open_match_the_vector) {
    const auto s = hpke::seal(pk_rm, info, aad0, pt, ikm_e);
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST((s->enc == pk_em));
    BOOST_TEST((s->ciphertext == ct0));
    bytes out(pt.size());
    BOOST_REQUIRE(hpke::open(sk_rm, pk_em, info, aad0, ct0, out).has_value());
    BOOST_TEST((out == pt));
}

BOOST_AUTO_TEST_CASE(any_change_fails_to_open_and_leaves_no_plaintext) {
    bytes out(pt.size(), std::byte{0x55});
    const auto zeroed = [&] {
        return std::ranges::all_of(out, [](std::byte b) { return b == std::byte{0}; });
    };
    auto bad_ct = ct0;
    bad_ct[3] ^= std::byte{1};
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, aad0, bad_ct, out).error() ==
               hpke::error::open_failed);
    BOOST_TEST(zeroed());
    auto bad_aad = aad0;
    bad_aad.back() = std::byte{'1'};
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, bad_aad, ct0, out).error() ==
               hpke::error::open_failed);
    BOOST_TEST(hpke::open(sk_rm, pk_em, {}, aad0, ct0, out).error() == hpke::error::open_failed);
    auto other = sk_rm;
    other[0] ^= std::byte{0x40};
    BOOST_TEST(hpke::open(other, pk_em, info, aad0, ct0, out).error() == hpke::error::open_failed);
    BOOST_TEST(hpke::open(sk_rm, pk_em, info, aad0, std::span{ct0}.first(10), out).error() ==
               hpke::error::bad_size);
    // A low-order point: refused, never a zero shared secret.
    const std::array<std::byte, 32> zero_point{};
    BOOST_TEST(hpke::open(sk_rm, zero_point, info, aad0, ct0, out).error() ==
               hpke::error::bad_public_key);
    BOOST_TEST(hpke::seal(zero_point, info, aad0, pt).error() == hpke::error::bad_public_key);
    BOOST_TEST(zeroed());
}

BOOST_AUTO_TEST_CASE(random_seals_round_trip_and_differ) {
    const auto a = hpke::seal(pk_rm, info, aad0, pt);
    const auto b = hpke::seal(pk_rm, info, aad0, pt);
    BOOST_REQUIRE((a.has_value() && b.has_value()));
    BOOST_TEST((a->enc != b->enc));
    bytes out(pt.size());
    BOOST_REQUIRE(hpke::open(sk_rm, a->enc, info, aad0, a->ciphertext, out).has_value());
    BOOST_TEST((out == pt));
}

// antikythera's helm opens what this seals: the same inputs give
// antikythera's VolumeKey bytes exactly.
BOOST_AUTO_TEST_CASE(seal_reproduces_antikythera_volume_key_frame) {
    const auto key = counting(64, 0x00);
    const auto ikm = counting(32, 0x10);
    const auto s = hpke::seal(pk_rm, as_bytes(volume_key_info), volume_key_aad, key,
                              std::span<const std::byte, 32>{ikm.data(), 32});
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST((s->enc == volume_key_enc));
    BOOST_TEST((s->ciphertext == volume_key_wrapped));
    bytes out(64);
    BOOST_REQUIRE(hpke::open(sk_rm, volume_key_enc, as_bytes(volume_key_info), volume_key_aad,
                             volume_key_wrapped, out)
                      .has_value());
    BOOST_TEST((out == key));
}

namespace {

/// A Kythira Recipient member, in JSON, with `extra` members appended.
auto recipient_json(std::span<const std::byte> key, std::span<const std::byte> aad,
                    std::string_view info_text, const std::string& extra = "") -> std::string {
    return R"(,"Recipient":{"KeyEncryptionAlgorithm":"KYTHIRA_HPKE_X25519_SHA256_AES256GCM",)"
           R"("KythiraPublicKey":")" +
           b64(key) + R"(","KythiraAssociatedData":")" + b64(aad) + R"(","KythiraInfo":")" +
           b64(as_bytes(info_text)) + "\"" + extra + "}";
}

const std::string lineage_context = R"({"aws:ec2:lineage":"lin-0000000000000001"})";

/// A 64-byte data key under a new key, as the EC2 controller makes one
/// per lineage: the wrapped blob only.
auto wrapped_data_key(fixture& f, std::string& key_id) -> std::string {
    key_id = f.create();
    const auto g =
        f.call("GenerateDataKeyWithoutPlaintext",
               R"({"KeyId":")" + key_id + R"(","NumberOfBytes":64,"EncryptionContext":)" +
                   lineage_context + "}");
    BOOST_REQUIRE_MESSAGE(g.status == 200U, g.type() + ": " + g.message());
    return g.str("CiphertextBlob");
}

auto decrypt(fixture& f, const std::string& blob, const std::string& extra,
             std::string_view akid = "AKIDADMIN") -> reply {
    return f.call("Decrypt",
                  R"({"CiphertextBlob":")" + blob + R"(","EncryptionContext":)" + lineage_context +
                      extra + "}",
                  akid);
}

}  // namespace

BOOST_AUTO_TEST_CASE(decrypt_seals_the_plaintext_to_the_recipient) {
    fixture f;
    std::string id;
    const auto blob = wrapped_data_key(f, id);
    // What a plain Decrypt returns, to compare with.
    const auto plain = decrypt(f, blob, "");
    BOOST_REQUIRE(plain.status == 200U);
    const auto data_key = unb64(plain.str("Plaintext"));
    BOOST_REQUIRE(data_key.size() == 64U);

    f.auth.asked.clear();
    const auto d = decrypt(f, blob, recipient_json(pk_rm, volume_key_aad, volume_key_info));
    BOOST_REQUIRE_MESSAGE(d.status == 200U, d.type() + ": " + d.message());
    BOOST_TEST(d.str("KeyId") == fixture::arn(id));
    BOOST_TEST(d.str("EncryptionAlgorithm") == "SYMMETRIC_DEFAULT");
    // The caller gets no plaintext, and no KeyMaterialId (AWS leaves it out
    // with a Recipient too).
    BOOST_TEST(!d.body.contains("Plaintext"));
    BOOST_TEST(!d.body.contains("KeyMaterialId"));

    // CiphertextForRecipient is the encapsulation, then ciphertext and
    // tag: a VolumeKey's hpke_enc and wrapped_key, which only the holder
    // of sk_rm opens, and only with the same AAD and info.
    const auto sealed = unb64(d.str("CiphertextForRecipient"));
    BOOST_REQUIRE(sealed.size() == hpke::enc_size + 64U + hpke::tag_size);
    const std::span<const std::byte> s{sealed};
    const auto enc = s.first<hpke::enc_size>();
    bytes out(64);
    BOOST_REQUIRE(hpke::open(sk_rm, enc, as_bytes(volume_key_info), volume_key_aad,
                             s.subspan(hpke::enc_size), out)
                      .has_value());
    BOOST_TEST((out == data_key));
    auto other_aad = volume_key_aad;
    other_aad[0x20] ^= std::byte{1};  // another generation
    BOOST_TEST(
        hpke::open(sk_rm, enc, as_bytes(volume_key_info), other_aad, s.subspan(hpke::enc_size), out)
            .error() == hpke::error::open_failed);
    BOOST_TEST(hpke::open(sk_rm, enc, as_bytes("antikythera image key v1"), volume_key_aad,
                          s.subspan(hpke::enc_size), out)
                   .error() == hpke::error::open_failed);

    // Authorized as Decrypt with the lineage's context and the recipient's
    // key, so a key policy can allow only enrolled transport keys.
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    const auto& r = f.auth.asked[0];
    BOOST_TEST(r.action == "kms:Decrypt");
    BOOST_TEST(asked_has(r, "kms:EncryptionContext:aws:ec2:lineage", "lin-0000000000000001"));
    BOOST_TEST(asked_has(r, "kms:KythiraRecipientPublicKeySha256", pk_rm_sha256));
    BOOST_TEST(kythira::kms::recipient_key_sha256(pk_rm) == pk_rm_sha256);
}

BOOST_AUTO_TEST_CASE(a_refused_caller_gets_nothing_sealed) {
    fixture f;
    std::string id;
    const auto blob = wrapped_data_key(f, id);
    const auto extra = recipient_json(pk_rm, volume_key_aad, volume_key_info);
    const auto denied = decrypt(f, blob, extra, "AKIDREAD");
    BOOST_TEST(denied.type() == "AccessDeniedException");
    BOOST_TEST(!denied.body.contains("CiphertextForRecipient"));
    // The wrong context is refused like any Decrypt.
    const auto wrong =
        f.call("Decrypt", R"({"CiphertextBlob":")" + blob +
                              R"(","EncryptionContext":{"aws:ec2:lineage":"x"})" + extra + "}");
    BOOST_TEST(wrong.type() == "InvalidCiphertextException");
    BOOST_TEST(!wrong.body.contains("CiphertextForRecipient"));
    // DryRun authorizes and stops.
    const auto calls = f.hsm_backend->crypto_calls;
    BOOST_TEST(decrypt(f, blob, extra + R"(,"DryRun":true)").type() == "DryRunOperationException");
    BOOST_TEST(f.hsm_backend->crypto_calls == calls);
}

BOOST_AUTO_TEST_CASE(malformed_recipients_are_refused) {
    fixture f;
    std::string id;
    const auto blob = wrapped_data_key(f, id);
    const auto type_of = [&](const std::string& extra) { return decrypt(f, blob, extra).type(); };

    // AWS's Nitro form is still not supported.
    const std::array<std::byte, 4> doc{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    BOOST_TEST(type_of(R"(,"Recipient":{"KeyEncryptionAlgorithm":"RSAES_OAEP_SHA_256",)"
                       R"("AttestationDocument":")" +
                       b64(doc) + R"("})") == "UnsupportedOperationException");
    BOOST_TEST(type_of(R"(,"Recipient":{})") == "UnsupportedOperationException");
    // Kythira members need the Kythira algorithm, and the Nitro document
    // does not go with it.
    BOOST_TEST(type_of(R"(,"Recipient":{"KythiraPublicKey":")" + b64(pk_rm) + R"("})") ==
               "ValidationException");
    BOOST_TEST(type_of(recipient_json(pk_rm, volume_key_aad, volume_key_info,
                                      R"(,"AttestationDocument":")" + b64(doc) + "\"")) ==
               "ValidationException");
    // Every Kythira member is required.
    BOOST_TEST(type_of(R"(,"Recipient":{"KeyEncryptionAlgorithm":)"
                       R"("KYTHIRA_HPKE_X25519_SHA256_AES256GCM","KythiraPublicKey":")" +
                       b64(pk_rm) + R"(","KythiraAssociatedData":")" + b64(volume_key_aad) +
                       R"("})") == "ValidationException");
    // The model checks the key's length and refuses unknown members and
    // algorithms.
    BOOST_TEST(type_of(recipient_json(std::span{pk_rm}.first(31), volume_key_aad,
                                      volume_key_info)) == "ValidationException");
    BOOST_TEST(type_of(recipient_json(pk_rm, volume_key_aad, volume_key_info,
                                      R"(,"KythiraSomethingElse":"AA==")")) ==
               "ValidationException");
    BOOST_TEST(type_of(R"(,"Recipient":{"KeyEncryptionAlgorithm":"KYTHIRA_ROT13"})") ==
               "ValidationException");
    // A low-order point is refused, and nothing is returned.
    const std::array<std::byte, 32> zero_point{};
    const auto low = decrypt(f, blob, recipient_json(zero_point, volume_key_aad, volume_key_info));
    BOOST_TEST(low.type() == "ValidationException");
    BOOST_TEST(!low.body.contains("CiphertextForRecipient"));
    BOOST_TEST(!low.body.contains("Plaintext"));
}

BOOST_AUTO_TEST_CASE(the_action_table_lists_the_condition_key) {
    const auto table = kythira::kms::kms_actions();
    const auto it =
        std::ranges::find_if(table.actions, [](const auto& a) { return a.name == "Decrypt"; });
    BOOST_REQUIRE(it != table.actions.end());
    BOOST_TEST(std::ranges::count(it->condition_keys, "kms:KythiraRecipientPublicKeySha256") == 1);
}
