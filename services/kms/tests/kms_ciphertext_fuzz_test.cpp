// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 3 (Requirement 5.2, 14.1): seeded mutations of real blobs through
// the decoder. Every input decodes or is refused without reading out of
// bounds (the sanitizer legs run this test), a blob that decodes encodes
// back to the same bytes (one encoding per blob), and no mutation of a
// sealed blob opens. KYTHIRA_KMS_FUZZ_ITERATIONS overrides the count.

#define BOOST_TEST_MODULE kms_ciphertext_fuzz_test

#include <boost/test/unit_test.hpp>

#include "kms_gcm_test_util.hpp"

#include <kythira/kms/kms_ciphertext.hpp>

#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;

namespace {

constexpr std::string_view key_id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
constexpr std::string_view arn_prefix = "arn:aws:kms:us-east-1:111122223333:key/";
const std::string key_arn = std::string(arn_prefix) + std::string(key_id);

auto iterations() -> int {
    if (const char* v = std::getenv("KYTHIRA_KMS_FUZZ_ITERATIONS")) {
        return std::atoi(v);
    }
    return 100000;
}

// One random mutation: flip a bit, set a byte, cut, insert, or splice a
// random run in place of a range.
auto mutate(std::vector<std::uint8_t> in, std::mt19937_64& rng) -> std::vector<std::uint8_t> {
    auto pick = [&](std::size_t n) {
        return n == 0 ? std::size_t{0} : std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
    };
    auto byte = [&] { return static_cast<std::uint8_t>(rng()); };
    switch (pick(5)) {
        case 0:
            if (!in.empty()) {
                in[pick(in.size())] ^= static_cast<std::uint8_t>(1U << pick(8));
            }
            break;
        case 1:
            if (!in.empty()) {
                in[pick(in.size())] = byte();
            }
            break;
        case 2:
            in.resize(pick(in.size() + 1));
            break;
        case 3: {
            const auto at = pick(in.size() + 1);
            const auto n = 1 + pick(64);
            for (std::size_t i = 0; i < n; ++i) {
                in.insert(in.begin() + static_cast<std::ptrdiff_t>(at), byte());
            }
            break;
        }
        default: {
            const auto at = pick(in.size() + 1);
            const auto len = pick(in.size() - at + 1);
            std::vector<std::uint8_t> run(pick(32));
            for (auto& c : run) {
                c = byte();
            }
            in.erase(in.begin() + static_cast<std::ptrdiff_t>(at),
                     in.begin() + static_cast<std::ptrdiff_t>(at + len));
            in.insert(in.begin() + static_cast<std::ptrdiff_t>(at), run.begin(), run.end());
            break;
        }
    }
    return in;
}

}  // namespace

BOOST_AUTO_TEST_CASE(mutated_blobs_decode_canonically_and_never_open) {
    std::mt19937_64 rng(0x6b6d73);  // fixed seed: a failure reproduces
    const auto key = kt::random_key();
    const kms::encryption_context ctx{{"bucket", "b1"}, {"path", "/a/b"}};
    std::vector<std::vector<std::uint8_t>> seeds;
    for (const std::size_t n : {0U, 1U, 15U, 16U, 17U, 255U, 4096U}) {
        const std::vector<std::uint8_t> plaintext(n, 0x5a);
        seeds.push_back(kms::encode_ciphertext(kt::seal(key, key_id, key_arn, 1, ctx, plaintext)));
    }

    int decoded = 0;
    int refused = 0;
    const int n = iterations();
    for (int i = 0; i < n; ++i) {
        const auto& seed = seeds[static_cast<std::size_t>(i) % seeds.size()];
        auto in = mutate(seed, rng);
        if (rng() % 4 == 0) {
            in = mutate(std::move(in), rng);  // sometimes two mutations
        }
        const auto blob = kms::decode_ciphertext(in);
        if (!blob) {
            ++refused;
            continue;
        }
        ++decoded;
        if (kms::encode_ciphertext(*blob) != in) {
            BOOST_FAIL("blob " << i << " decodes but does not encode back to its bytes");
        }
        // The KMS opens a blob with the ARN of the key the blob names, so
        // a changed key id is a changed ARN.
        const auto arn = std::string(arn_prefix) + blob->key_id;
        if (in != seed && kt::open(key, arn, ctx, *blob).has_value()) {
            BOOST_FAIL("mutated blob " << i << " opened");
        }
    }
    BOOST_TEST_MESSAGE(decoded << " decoded, " << refused << " refused");
    // Both paths ran: the mutations are neither all fatal nor all benign.
    BOOST_TEST(decoded > n / 10);
    BOOST_TEST(refused > n / 10);
}

BOOST_AUTO_TEST_CASE(random_bytes_are_refused_or_decode_canonically) {
    std::mt19937_64 rng(0x636970);
    const int n = iterations();
    int checked = 0;
    for (int i = 0; i < n; ++i) {
        std::vector<std::uint8_t> in(rng() % 160);
        for (auto& c : in) {
            c = static_cast<std::uint8_t>(rng());
        }
        if (!in.empty() && rng() % 2 == 0) {
            in[0] = kms::k_ciphertext_version;
        }
        if (const auto blob = kms::decode_ciphertext(in);
            blob && kms::encode_ciphertext(*blob) != in) {
            BOOST_FAIL("random input " << i << " decodes but does not encode back");
        }
        ++checked;
    }
    BOOST_TEST(checked == n);
}
