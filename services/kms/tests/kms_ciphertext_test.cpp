// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 3 (Requirement 5.2, 5.3, 14.1): the ciphertext blob's layout, the
// additional data's canonical form, and that AES-GCM over them refuses any
// change to the ciphertext, the context, the key or its version.

#define BOOST_TEST_MODULE kms_ciphertext_test

#include <boost/test/unit_test.hpp>

#include "kms_gcm_test_util.hpp"

#include <kythira/kms/kms_ciphertext.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;

namespace {

constexpr std::string_view key_id = "1234abcd-12ab-34cd-56ef-1234567890ab";
constexpr std::string_view key_arn =
    "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

auto bytes(std::string_view s) -> std::vector<std::uint8_t> {
    return {s.begin(), s.end()};
}

auto sample() -> kms::ciphertext_blob {
    kms::ciphertext_blob b;
    b.key_id = std::string(key_id);
    b.backing_version = 0x01020304;
    for (std::size_t i = 0; i < b.nonce.size(); ++i) {
        b.nonce[i] = static_cast<std::uint8_t>(0xa0 + i);
    }
    b.ciphertext = bytes("secret");
    for (std::size_t i = 0; i < b.tag.size(); ++i) {
        b.tag[i] = static_cast<std::uint8_t>(0xc0 + i);
    }
    return b;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_blob_is_laid_out_as_designed) {
    const auto b = sample();
    const auto wire = kms::encode_ciphertext(b);
    BOOST_REQUIRE(wire.size() == 2 + 36 + 4 + 12 + 6 + 16);
    BOOST_TEST(wire[0] == 1);
    BOOST_TEST(wire[1] == 36);
    BOOST_TEST(std::string(wire.begin() + 2, wire.begin() + 38) == key_id);
    BOOST_TEST(wire[38] == 0x01);  // big-endian version
    BOOST_TEST(wire[41] == 0x04);
    BOOST_TEST(wire[42] == 0xa0);  // nonce
    BOOST_TEST(std::string(wire.begin() + 54, wire.begin() + 60) == "secret");
    BOOST_TEST(wire[60] == 0xc0);  // tag
    const auto back = kms::decode_ciphertext(wire);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == b));

    // An empty ciphertext body is still a blob (GCM of zero bytes).
    auto empty = b;
    empty.ciphertext.clear();
    BOOST_TEST((kms::decode_ciphertext(kms::encode_ciphertext(empty)) == std::optional(empty)));
}

BOOST_AUTO_TEST_CASE(blobs_this_kms_did_not_make_are_refused) {
    const auto good = kms::encode_ciphertext(sample());
    auto other_version = good;
    other_version[0] = 2;
    BOOST_TEST(!kms::decode_ciphertext(other_version).has_value());

    for (std::size_t n = 0; n < 2 + 36 + 4 + 12 + 16; ++n) {
        const std::vector<std::uint8_t> cut(good.begin(),
                                            good.begin() + static_cast<std::ptrdiff_t>(n));
        BOOST_TEST(!kms::decode_ciphertext(cut).has_value(), n);
    }

    auto too_long = sample();
    too_long.ciphertext.assign(kms::k_max_ciphertext_blob, 0);
    BOOST_TEST(!kms::decode_ciphertext(kms::encode_ciphertext(too_long)).has_value());
    too_long.ciphertext.resize(kms::k_max_ciphertext_blob - (2 + 36 + 4 + 12 + 16));
    BOOST_TEST(kms::decode_ciphertext(kms::encode_ciphertext(too_long)).has_value());

    for (const auto* id :
         {"1234ABCD-12ab-34cd-56ef-1234567890ab", "1234abcd-12ab-34cd-56ef-1234567890a",
          "1234abcd_12ab-34cd-56ef-1234567890ab", "mrk-1234abcd12ab34cd56ef1234567890ab",
          "1234abcd-12ab-34cd-56ef-1234567890ag", ""}) {
        auto b = sample();
        b.key_id = id;
        BOOST_TEST(!kms::decode_ciphertext(kms::encode_ciphertext(b)).has_value(), id);
    }
    // A key-id length byte that runs into the version: the id read is not
    // a UUID.
    auto shifted = good;
    shifted[1] = 37;
    BOOST_TEST(!kms::decode_ciphertext(shifted).has_value());
}

BOOST_AUTO_TEST_CASE(the_context_is_canonical_and_unambiguous) {
    const kms::encryption_context a{{"b", "2"}, {"a", "1"}};
    kms::encryption_context b;
    b.emplace("a", "1");
    b.emplace("b", "2");
    BOOST_TEST((kms::canonical_context(a) == kms::canonical_context(b)));

    // Length prefixes keep different contexts apart.
    BOOST_TEST((kms::canonical_context({{"a", "bc"}}) != kms::canonical_context({{"ab", "c"}})));
    BOOST_TEST((kms::canonical_context({}) != kms::canonical_context({{"", ""}})));
    BOOST_TEST(
        (kms::canonical_context({{"a", "1"}}) != kms::canonical_context({{"a", "1"}, {"b", ""}})));
    // Keys are case-sensitive, as AWS's encryption context is.
    BOOST_TEST(
        (kms::canonical_context({{"Dept", "IT"}}) != kms::canonical_context({{"dept", "IT"}})));

    // The AAD binds the ARN and the version besides the context.
    const auto aad = kms::ciphertext_aad(key_arn, 7, a);
    BOOST_TEST((aad != kms::ciphertext_aad(key_arn, 8, a)));
    BOOST_TEST((aad != kms::ciphertext_aad("arn:aws:kms:us-east-1:444455556666:key/"
                                           "1234abcd-12ab-34cd-56ef-1234567890ab",
                                           7, a)));
    BOOST_TEST(std::string(aad.begin(), aad.begin() + 11) == "kythira-kms");
}

BOOST_AUTO_TEST_CASE(aes_gcm_refuses_tamper_wrong_context_and_wrong_key) {
    const auto key = kt::random_key();
    const kms::encryption_context ctx{{"Department", "IT"}, {"Project", "unicorn"}};
    const auto plaintext = bytes("attack at dawn");
    const auto blob = kt::seal(key, key_id, key_arn, 3, ctx, plaintext);

    // Through the wire and back, then open.
    const auto wire = kms::encode_ciphertext(blob);
    const auto parsed = kms::decode_ciphertext(wire);
    BOOST_REQUIRE(parsed.has_value());
    const auto opened = kt::open(key, key_arn, ctx, *parsed);
    BOOST_REQUIRE(opened.has_value());
    BOOST_TEST((*opened == plaintext));

    // Every byte after the key id: version, nonce, ciphertext, tag.
    for (std::size_t i = 2 + 36; i < wire.size(); ++i) {
        auto bad = wire;
        bad[i] ^= 0x01;
        const auto p = kms::decode_ciphertext(bad);
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST(!kt::open(key, key_arn, ctx, *p).has_value(), i);
    }

    // Wrong context: a changed value, a missing pair, an extra pair, none.
    for (const auto& other : std::vector<kms::encryption_context>{
             {{"Department", "Finance"}, {"Project", "unicorn"}},
             {{"Department", "IT"}},
             {{"Department", "IT"}, {"Project", "unicorn"}, {"Owner", "alice"}},
             {}}) {
        BOOST_TEST(!kt::open(key, key_arn, other, *parsed).has_value());
    }

    // Wrong key: another key's material, or the right material bound to
    // another key's ARN.
    BOOST_TEST(!kt::open(kt::random_key(), key_arn, ctx, *parsed).has_value());
    BOOST_TEST(!kt::open(key,
                         "arn:aws:kms:us-east-1:111122223333:key/"
                         "00000000-12ab-34cd-56ef-1234567890ab",
                         ctx, *parsed)
                    .has_value());

    // A blob relabelled with another backing version.
    auto relabelled = *parsed;
    relabelled.backing_version = 4;
    BOOST_TEST(!kt::open(key, key_arn, ctx, relabelled).has_value());
}
