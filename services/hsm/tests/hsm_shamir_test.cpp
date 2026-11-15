// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Shamir sharing of the master key (.kiro/specs/virtual-hsm/ task 2,
// Requirements 4.1, 4.2 and 13.1): the GF(2^8) arithmetic against its
// definition, any k shares rebuilding the secret, k - 1 shares consistent
// with every secret, the share encodings, and every corruption or misuse
// refused with its own error. The randomized cases use a fixed seed, printed
// on failure, so a failure replays.

#define BOOST_TEST_MODULE hsm_shamir_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/shamir.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <numeric>
#include <ostream>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace kythira::hsm {

// Boost.Test prints both sides of a failed BOOST_TEST(a == b).
auto operator<<(std::ostream& out, shamir_error e) -> std::ostream& {
    return out << shamir_error_message(e);
}

}  // namespace kythira::hsm

namespace hsm = kythira::hsm;
namespace gf = kythira::hsm::gf256;

namespace {

constexpr std::uint32_t k_seed = 0x5eed4a51U;

auto random_bytes(std::mt19937& rng, std::size_t n) -> std::vector<std::uint8_t> {
    std::uniform_int_distribution<int> byte(0, 255);
    std::vector<std::uint8_t> out(n);
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(byte(rng));
    }
    return out;
}

/// A random_source drawing from `rng`, so a split replays from the seed.
auto seeded_source(std::mt19937& rng) -> hsm::random_source {
    return [&rng](std::span<std::uint8_t> out) {
        std::uniform_int_distribution<int> byte(0, 255);
        for (auto& b : out) {
            b = static_cast<std::uint8_t>(byte(rng));
        }
    };
}

auto split_or_fail(std::span<const std::uint8_t> secret, unsigned k, unsigned n,
                   const hsm::random_source& rnd = hsm::openssl_random)
    -> std::vector<hsm::shamir_share> {
    auto r = hsm::shamir_split(secret, k, n, false, rnd);
    BOOST_REQUIRE(r.has_value());
    return std::move(*r);
}

auto same_bytes(const hsm::secret_bytes& a, std::span<const std::uint8_t> b) -> bool {
    return std::equal(a.view().begin(), a.view().end(), b.begin(), b.end());
}

/// Slow reference multiplication: shift-and-add with explicit reduction.
auto reference_mul(unsigned a, unsigned b) -> std::uint8_t {
    unsigned p = 0;
    for (int i = 0; i < 8; ++i) {
        if (((b >> i) & 1U) != 0U) {
            p ^= a << i;
        }
    }
    for (int bit = 14; bit >= 8; --bit) {
        if (((p >> bit) & 1U) != 0U) {
            p ^= 0x11BU << (bit - 8);
        }
    }
    return static_cast<std::uint8_t>(p);
}

/// The value at `x` of the polynomial through `points` (Lagrange).
auto interpolate_at(const std::vector<std::pair<std::uint8_t, std::uint8_t>>& points,
                    std::uint8_t x) -> std::uint8_t {
    std::uint8_t y = 0;
    for (std::size_t i = 0; i < points.size(); ++i) {
        std::uint8_t num = 1;
        std::uint8_t den = 1;
        for (std::size_t m = 0; m < points.size(); ++m) {
            if (m != i) {
                num = gf::mul(num, points[m].first ^ x);
                den = gf::mul(den, points[m].first ^ points[i].first);
            }
        }
        y ^= gf::mul(points[i].second, gf::mul(num, gf::inv(den)));
    }
    return y;
}

}  // namespace

// -- GF(2^8) -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(gf_mul_matches_the_reference_on_every_pair) {
    for (unsigned a = 0; a < 256; ++a) {
        for (unsigned b = 0; b < 256; ++b) {
            BOOST_REQUIRE_EQUAL(static_cast<int>(gf::mul(static_cast<std::uint8_t>(a),
                                                         static_cast<std::uint8_t>(b))),
                                static_cast<int>(reference_mul(a, b)));
        }
    }
    // FIPS 197 section 4.2: {57} * {83} = {c1}.
    BOOST_TEST(gf::mul(0x57, 0x83) == 0xC1);
}

BOOST_AUTO_TEST_CASE(gf_inv_is_the_inverse_of_every_nonzero_element) {
    BOOST_TEST(gf::inv(0) == 0);
    for (unsigned a = 1; a < 256; ++a) {
        BOOST_REQUIRE_EQUAL(static_cast<int>(gf::mul(static_cast<std::uint8_t>(a),
                                                     gf::inv(static_cast<std::uint8_t>(a)))),
                            1);
    }
}

// -- Split and combine -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(any_k_shares_rebuild_the_secret) {
    BOOST_TEST_MESSAGE("seed " << k_seed);
    std::mt19937 rng(k_seed);
    for (unsigned n = 2; n <= hsm::shamir_max_shares; ++n) {
        for (unsigned k = 2; k <= n; ++k) {
            const auto secret = random_bytes(rng, 32);
            const auto shares = split_or_fail(secret, k, n, seeded_source(rng));
            BOOST_REQUIRE_EQUAL(shares.size(), n);
            // Several random k-subsets in random order, plus all n shares.
            for (int trial = 0; trial < 8; ++trial) {
                std::vector<std::size_t> order(n);
                std::iota(order.begin(), order.end(), 0);
                std::shuffle(order.begin(), order.end(), rng);
                std::vector<hsm::shamir_share> subset;
                for (unsigned i = 0; i < k; ++i) {
                    const auto& s = shares[order[i]];
                    hsm::shamir_share copy;
                    copy.k = s.k;
                    copy.n = s.n;
                    copy.index = s.index;
                    copy.bytes = s.bytes.clone();
                    copy.check_value = s.check_value;
                    subset.push_back(std::move(copy));
                }
                auto rebuilt = hsm::shamir_combine(subset);
                BOOST_REQUIRE_MESSAGE(rebuilt.has_value(), "k=" << k << " n=" << n);
                BOOST_REQUIRE(same_bytes(*rebuilt, secret));
            }
            auto all = hsm::shamir_combine(shares);
            BOOST_REQUIRE(all.has_value());
            BOOST_REQUIRE(same_bytes(*all, secret));
        }
    }
}

BOOST_AUTO_TEST_CASE(every_k_subset_of_a_small_split_rebuilds_it) {
    // Exhaustive for k = 3, n = 6: all 20 subsets.
    const std::vector<std::uint8_t> secret{0x00, 0x01, 0x7f, 0x80, 0xff, 0x42};
    const auto shares = split_or_fail(secret, 3, 6);
    for (unsigned a = 0; a < 6; ++a) {
        for (unsigned b = a + 1; b < 6; ++b) {
            for (unsigned c = b + 1; c < 6; ++c) {
                std::vector<hsm::shamir_share> subset;
                for (const unsigned i : {c, a, b}) {
                    hsm::shamir_share s;
                    s.k = 3;
                    s.n = 6;
                    s.index = shares[i].index;
                    s.bytes = shares[i].bytes.clone();
                    s.check_value = shares[i].check_value;
                    subset.push_back(std::move(s));
                }
                auto rebuilt = hsm::shamir_combine(subset);
                BOOST_REQUIRE(rebuilt.has_value());
                BOOST_REQUIRE(same_bytes(*rebuilt, secret));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(k_minus_one_shares_are_consistent_with_every_secret) {
    // For any k - 1 shares and every candidate secret byte s, exactly one
    // degree k - 1 polynomial passes through (0, s) and the shares' points,
    // and the completions differ for different s (they are a bijection on
    // the value at any further x). So the k - 1 shares leave every secret
    // equally possible: there is nothing in them to test for.
    std::mt19937 rng(k_seed + 1);
    for (unsigned k = 2; k <= 6; ++k) {
        const auto secret = random_bytes(rng, 16);
        const auto shares = split_or_fail(secret, k, k + 2, seeded_source(rng));
        const auto unused_x =
            static_cast<std::uint8_t>(k + 2);  // an index not among the first k - 1
        for (std::size_t j = 0; j < secret.size(); ++j) {
            std::set<std::uint8_t> completions;
            for (unsigned s = 0; s < 256; ++s) {
                std::vector<std::pair<std::uint8_t, std::uint8_t>> points{
                    {0, static_cast<std::uint8_t>(s)}};
                for (unsigned i = 0; i + 1 < k; ++i) {
                    points.emplace_back(shares[i].index, shares[i].bytes[j]);
                }
                completions.insert(interpolate_at(points, unused_x));
            }
            BOOST_REQUIRE_EQUAL(completions.size(), 256U);
        }
    }
}

BOOST_AUTO_TEST_CASE(a_single_share_is_uniform_whatever_the_secret) {
    // With k = 2, one share byte is secret ^ a_1 * x for a uniform a_1, so
    // it is uniform. Split an all-zero and an all-0xff secret many times and
    // check share 1's bytes against the uniform distribution (chi-square,
    // 255 degrees of freedom; 400 is far past the 0.9999 quantile, ~340).
    for (const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xff}}) {
        std::array<unsigned, 256> counts{};
        const std::vector<std::uint8_t> secret(64, fill);
        constexpr int splits = 1024;
        for (int t = 0; t < splits; ++t) {
            const auto shares = split_or_fail(secret, 2, 3);
            for (const auto b : shares[0].bytes.view()) {
                ++counts[b];
            }
        }
        const double expected = splits * 64.0 / 256.0;
        double chi = 0;
        for (const auto c : counts) {
            chi += (c - expected) * (c - expected) / expected;
        }
        BOOST_TEST(chi < 400.0, "fill " << static_cast<int>(fill) << " chi-square " << chi);
    }
}

BOOST_AUTO_TEST_CASE(fewer_than_k_shares_are_refused) {
    const std::vector<std::uint8_t> secret(32, 0x5a);
    auto shares = split_or_fail(secret, 3, 5);
    shares.resize(2);
    const auto r = hsm::shamir_combine(shares);
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error() == hsm::shamir_error::not_enough_shares);
    BOOST_TEST(hsm::shamir_combine(std::span<const hsm::shamir_share>{}).error() ==
               hsm::shamir_error::not_enough_shares);
}

BOOST_AUTO_TEST_CASE(parameters_are_bounded_as_requirement_4_1_says) {
    const std::vector<std::uint8_t> secret(32, 1);
    using hsm::shamir_error;
    BOOST_TEST(hsm::shamir_split(secret, 1, 3).error() == shamir_error::bad_parameters);
    BOOST_TEST(hsm::shamir_split(secret, 0, 3, true).error() == shamir_error::bad_parameters);
    BOOST_TEST(hsm::shamir_split(secret, 4, 3).error() == shamir_error::bad_parameters);
    BOOST_TEST(hsm::shamir_split(secret, 2, 17).error() == shamir_error::bad_parameters);
    BOOST_TEST(hsm::shamir_split({}, 2, 3).error() == shamir_error::bad_parameters);
    BOOST_TEST(hsm::shamir_split(secret, 16, 16).has_value());
    // k = 1 only with the development flag; every share is then the secret.
    auto single = hsm::shamir_split(secret, 1, 2, true);
    BOOST_REQUIRE(single.has_value());
    for (const auto& s : *single) {
        BOOST_TEST(same_bytes(s.bytes, secret));
    }
}

// -- Encoding and rejection --------------------------------------------------------

BOOST_AUTO_TEST_CASE(text_form_round_trips_and_tolerates_whitespace_and_case) {
    const std::vector<std::uint8_t> secret(32, 0xa5);
    const auto shares = split_or_fail(secret, 2, 3);
    std::vector<hsm::shamir_share> parsed;
    for (const auto& s : shares) {
        const auto text = hsm::shamir_encode_text(s);
        BOOST_TEST(text.starts_with("khs1-"));
        // 6 header + 32 bytes + 8 check + 4 checksum, two digits each.
        BOOST_TEST(text.size() == 5 + (2 * (6 + 32 + 8 + 4)));
        std::string mangled;
        for (std::size_t i = 0; i < text.size(); ++i) {
            mangled.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(text[i]))));
            if (i % 8 == 7) {
                mangled += (i % 16 == 15) ? "\n" : " ";
            }
        }
        auto back = hsm::shamir_decode_text(mangled);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST(back->index == s.index);
        BOOST_TEST(back->k == 2);
        BOOST_TEST(back->n == 3);
        BOOST_TEST(back->check_value == s.check_value);
        BOOST_TEST(same_bytes(back->bytes, s.bytes.view()));
        parsed.push_back(std::move(*back));
    }
    auto rebuilt = hsm::shamir_combine(parsed);
    BOOST_REQUIRE(rebuilt.has_value());
    BOOST_TEST(same_bytes(*rebuilt, secret));
}

BOOST_AUTO_TEST_CASE(every_single_bit_flip_in_a_share_is_rejected) {
    const std::vector<std::uint8_t> secret(32, 0x3c);
    const auto shares = split_or_fail(secret, 2, 2);
    const auto bin = hsm::shamir_encode_binary(shares[0]);
    for (std::size_t byte = 0; byte < bin.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            auto bad = bin.clone();
            bad[byte] ^= static_cast<std::uint8_t>(1U << bit);
            const auto r = hsm::shamir_decode_binary(bad.view());
            BOOST_REQUIRE_MESSAGE(!r.has_value(), "flip at byte " << byte << " bit " << bit);
            BOOST_REQUIRE(r.error() == hsm::shamir_error::bad_checksum);
        }
    }
}

BOOST_AUTO_TEST_CASE(truncated_mistyped_and_foreign_text_is_rejected) {
    const std::vector<std::uint8_t> secret(32, 0x11);
    const auto shares = split_or_fail(secret, 2, 3);
    const auto text = hsm::shamir_encode_text(shares[1]);
    using hsm::shamir_error;
    BOOST_TEST(hsm::shamir_decode_text("").error() == shamir_error::bad_encoding);
    BOOST_TEST(hsm::shamir_decode_text("khs2-00").error() == shamir_error::bad_encoding);
    BOOST_TEST(hsm::shamir_decode_text(text.substr(0, text.size() - 1)).error() ==
               shamir_error::bad_encoding);  // odd number of digits
    BOOST_TEST(hsm::shamir_decode_text(text.substr(0, text.size() - 2)).error() ==
               shamir_error::bad_checksum);  // one byte short
    auto typo = text;
    typo[20] = typo[20] == 'a' ? 'b' : 'a';
    BOOST_TEST(hsm::shamir_decode_text(typo).error() == shamir_error::bad_checksum);
    auto not_hex = text;
    not_hex[20] = 'g';
    BOOST_TEST(hsm::shamir_decode_text(not_hex).error() == shamir_error::bad_encoding);
}

BOOST_AUTO_TEST_CASE(shares_of_different_splits_do_not_combine) {
    const std::vector<std::uint8_t> secret_a(32, 0xaa);
    const std::vector<std::uint8_t> secret_b(32, 0xbb);
    const auto a = split_or_fail(secret_a, 2, 3);
    const auto b = split_or_fail(secret_b, 2, 3);
    std::vector<hsm::shamir_share> mixed;
    for (const auto* s : {&a[0], &b[1]}) {
        hsm::shamir_share c;
        c.k = s->k;
        c.n = s->n;
        c.index = s->index;
        c.bytes = s->bytes.clone();
        c.check_value = s->check_value;
        mixed.push_back(std::move(c));
    }
    BOOST_TEST(hsm::shamir_combine(mixed).error() == hsm::shamir_error::mixed_shares);

    // The same secret split twice: same check value, different polynomials.
    // The fields agree, so only the rebuilt secret's check catches it.
    const auto a2 = split_or_fail(secret_a, 2, 3);
    std::vector<hsm::shamir_share> resplit;
    for (const auto* s : {&a[0], &a2[1]}) {
        hsm::shamir_share c;
        c.k = s->k;
        c.n = s->n;
        c.index = s->index;
        c.bytes = s->bytes.clone();
        c.check_value = s->check_value;
        resplit.push_back(std::move(c));
    }
    BOOST_TEST(hsm::shamir_combine(resplit).error() == hsm::shamir_error::check_value_mismatch);
}

BOOST_AUTO_TEST_CASE(a_repeated_share_is_refused) {
    const std::vector<std::uint8_t> secret(32, 0x77);
    const auto shares = split_or_fail(secret, 2, 3);
    std::vector<hsm::shamir_share> twice;
    for (int i = 0; i < 2; ++i) {
        hsm::shamir_share c;
        c.k = shares[0].k;
        c.n = shares[0].n;
        c.index = shares[0].index;
        c.bytes = shares[0].bytes.clone();
        c.check_value = shares[0].check_value;
        twice.push_back(std::move(c));
    }
    BOOST_TEST(hsm::shamir_combine(twice).error() == hsm::shamir_error::duplicate_index);
}

BOOST_AUTO_TEST_CASE(a_share_altered_after_decoding_fails_the_check_value) {
    // A share whose bytes changed in memory (or a checksum-valid forgery)
    // rebuilds a wrong secret, which the check value refuses.
    const std::vector<std::uint8_t> secret(32, 0x99);
    auto shares = split_or_fail(secret, 2, 3);
    shares[0].bytes[5] ^= 0x01;
    BOOST_TEST(hsm::shamir_combine(std::span(shares).first(2)).error() ==
               hsm::shamir_error::check_value_mismatch);
}

BOOST_AUTO_TEST_CASE(every_error_has_a_message) {
    using hsm::shamir_error;
    for (const auto e :
         {shamir_error::bad_parameters, shamir_error::bad_encoding,
          shamir_error::unsupported_version, shamir_error::bad_checksum, shamir_error::bad_index,
          shamir_error::mixed_shares, shamir_error::duplicate_index,
          shamir_error::not_enough_shares, shamir_error::check_value_mismatch}) {
        BOOST_TEST(hsm::shamir_error_message(e).size() > 10U);
    }
}

BOOST_AUTO_TEST_CASE(secret_bytes_wipes_on_move_and_cannot_copy) {
    static_assert(!std::is_copy_constructible_v<hsm::secret_bytes>);
    static_assert(!std::is_copy_assignable_v<hsm::secret_bytes>);
    hsm::secret_bytes a(std::vector<std::uint8_t>{1, 2, 3});
    hsm::secret_bytes b(std::move(a));
    BOOST_TEST(a.empty());  // NOLINT(bugprone-use-after-move): the point of the test
    BOOST_TEST(b.size() == 3U);
    b.wipe();
    BOOST_TEST(b.empty());
}
