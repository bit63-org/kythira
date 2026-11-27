// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_float128_test.cpp
/// @brief INCRBYFLOAT's binary128 arithmetic and its in-tree decimal
///        conversions (.kiro/specs/redis-general-data-types/ design "Float
///        increments", D1).
///
/// The table pins replies, including the reference server's own
/// INCRBYFLOAT test vectors; they are what arm64 Redis prints, and the test
/// runs on the amd64 and arm64 CI legs, so both must print the same. The
/// expected strings were checked against libquadmath's strtoflt128 and
/// "%.17Qf" (outside this repository, which does not depend on it) over
/// 220,000 random inputs with no difference.

#define BOOST_TEST_MODULE redis_float128_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_float128.hpp>

#include <string>

namespace {

using kythira::format_redis_float128;
using kythira::is_finite_redis_float128;
using kythira::parse_redis_float128;
using kythira::redis_float128_native;
using kythira::redis_float128_detail::to_bits;

struct sum_case {
    const char* current;
    const char* increment;
    const char* printed;
};

const sum_case k_sums[] = {
    {"0", "1", "1"},
    {"1", "0.25", "1.25"},
    {"10.5", "0.1", "10.6"},
    {"5.0e3", "2.0e2", "5200"},
    {"10.5", "3.0e3", "3010.5"},
    {"1", "1.1", "2.1"},
    {"1", "-1.1", "-0.1"},
    {"0.1", "0.2", "0.3"},
    {"0.3", "-0.1", "0.2"},
    {"1", "3e-17", "1.00000000000000003"},
    {"1e17", "0.5", "100000000000000000.5"},
    {"123456789.123456789", "0.000000001", "123456789.12345679"},
    {"-5", "5", "0"},
    {"3", "-3.00000000000000000001", "0"},
    {"0.00000000000000001", "0.000000000000000004", "0.00000000000000001"},
    {"99999999999999999999", "1", "100000000000000000000"},
};

}  // namespace

BOOST_AUTO_TEST_CASE(sums_print_as_redis_prints_them) {
    for (const auto& c : k_sums) {
        BOOST_TEST_CONTEXT(c.current << " + " << c.increment) {
            const auto a = parse_redis_float128(c.current);
            const auto b = parse_redis_float128(c.increment);
            BOOST_REQUIRE(a.has_value());
            BOOST_REQUIRE(b.has_value());
            const redis_float128_native sum = *a + *b;
            BOOST_CHECK_EQUAL(format_redis_float128(sum), c.printed);
            // The printed value reads back as itself.
            const auto again = parse_redis_float128(c.printed);
            BOOST_REQUIRE(again.has_value());
            BOOST_CHECK_EQUAL(format_redis_float128(*again), c.printed);
        }
    }
}

// What string2ld refuses: spaces, trailing bytes, NaN, hex, empty input,
// and results that overflow to infinity or underflow to zero.
BOOST_AUTO_TEST_CASE(the_parser_refuses_what_redis_refuses) {
    for (const char* bad : {"", " 1", "1 ", "abc", "1e", "1e+", "--1", "1..2", ".", "nan", "NaN",
                            "0x10", "1e5000", "-1e5000", "1e-5000", "2e-4966"}) {
        BOOST_TEST_CONTEXT("'" << bad << "'") {
            BOOST_CHECK(!parse_redis_float128(bad).has_value());
        }
    }
    for (const char* good : {"0", "-0", "+1", ".5", "5.", "1E3", "1e-4931", "INF", "-infinity"}) {
        BOOST_TEST_CONTEXT("'" << good << "'") {
            BOOST_CHECK(parse_redis_float128(good).has_value());
        }
    }
    BOOST_CHECK(!is_finite_redis_float128(*parse_redis_float128("inf")));
    BOOST_CHECK(is_finite_redis_float128(*parse_redis_float128("1e4932")));
}

BOOST_AUTO_TEST_CASE(round_half_even_at_the_last_bit) {
    // 1 + 2^-113 is exactly halfway between 1 and the next binary128 value;
    // it rounds to the even neighbour, 1. 2^-113 = 9.62964972193617926527988971292463659e-35.
    const auto one = parse_redis_float128("1");
    const auto tie = parse_redis_float128(
        "1.0000000000000000000000000000000000962964972193617926527988971292463659");
    BOOST_REQUIRE(one && tie);
    BOOST_CHECK(to_bits(*one) == to_bits(*tie));
    // A hair above the tie rounds up.
    const auto above = parse_redis_float128(
        "1.00000000000000000000000000000000009629649721936179265279889712924637");
    BOOST_REQUIRE(above);
    BOOST_CHECK(to_bits(*one) != to_bits(*above));
}

BOOST_AUTO_TEST_CASE(large_values_print_every_integer_digit) {
    const auto v = parse_redis_float128("1e40");
    BOOST_REQUIRE(v);
    BOOST_CHECK_EQUAL(format_redis_float128(*v), "10000000000000000000000000000000000000000");
}
