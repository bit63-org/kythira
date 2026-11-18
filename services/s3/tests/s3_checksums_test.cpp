// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_checksums_test.cpp
/// @brief S3's additional checksums (`s3_checksums.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 8, Requirement 7.4):
///        published check values for every algorithm, streaming, CRC
///        combination for multipart full-object checksums, composite
///        checksums, and what a request's headers ask for.

#define BOOST_TEST_MODULE s3_checksums_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_checksums.hpp>

#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace s3 = kythira::s3;
using s3::checksum_algorithm;

auto hex(std::string_view raw) -> std::string {
    static constexpr std::string_view d = "0123456789abcdef";
    std::string out;
    for (unsigned char c : raw) {
        out.push_back(d[c >> 4U]);
        out.push_back(d[c & 0xFU]);
    }
    return out;
}

auto raw_of(checksum_algorithm a, std::string_view data) -> std::string {
    s3::checksummer c(a);
    c.update(data);
    return c.raw();
}

}  // namespace

BOOST_AUTO_TEST_CASE(check_values) {
    const std::string check = "123456789";
    BOOST_TEST(hex(raw_of(checksum_algorithm::crc32, check)) == "cbf43926");
    BOOST_TEST(hex(raw_of(checksum_algorithm::crc32c, check)) == "e3069283");
    BOOST_TEST(hex(raw_of(checksum_algorithm::crc64nvme, check)) == "ae8b14860a799888");
    BOOST_TEST(hex(raw_of(checksum_algorithm::sha1, "abc")) ==
               "a9993e364706816aba3e25717850c26c9cd0d89d");
    BOOST_TEST(hex(raw_of(checksum_algorithm::sha256, "abc")) ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // Wire form: base64 of the big-endian digest; the empty body's CRC32
    // is zero, as S3 answers for an empty object.
    BOOST_TEST(s3::checksum_of(checksum_algorithm::crc32, "") == "AAAAAA==");
    BOOST_TEST(s3::checksum_of(checksum_algorithm::crc32, check) == "y/Q5Jg==");
}

BOOST_AUTO_TEST_CASE(streaming_matches_one_shot) {
    std::string data(10'000, '\0');
    std::mt19937 rng(7);
    for (auto& c : data) {
        c = static_cast<char>(rng());
    }
    for (auto a : s3::all_checksum_algorithms) {
        s3::checksummer c(a);
        for (std::size_t i = 0; i < data.size(); i += 333) {
            c.update(std::string_view(data).substr(i, 333));
        }
        BOOST_TEST(c.value() == s3::checksum_of(a, data), s3::to_string(a));
    }
}

BOOST_AUTO_TEST_CASE(crcs_combine_across_parts) {
    std::mt19937 rng(11);
    for (auto a :
         {checksum_algorithm::crc32, checksum_algorithm::crc32c, checksum_algorithm::crc64nvme}) {
        for (int trial = 0; trial < 20; ++trial) {
            std::vector<std::string> parts;
            std::string whole;
            const auto n = 1 + rng() % 5;
            for (std::size_t i = 0; i < n; ++i) {
                std::string p(rng() % 3000, '\0');
                for (auto& c : p) {
                    c = static_cast<char>(rng());
                }
                whole += p;
                parts.push_back(std::move(p));
            }
            std::vector<std::pair<std::string, std::uint64_t>> sums;
            for (const auto& p : parts) {
                sums.emplace_back(s3::checksum_of(a, p), p.size());
            }
            BOOST_TEST(s3::combine_full_object(a, sums).value_or("") == s3::checksum_of(a, whole),
                       s3::to_string(a) << " trial " << trial);
        }
    }
    BOOST_CHECK_THROW((void)s3::crc_combine(checksum_algorithm::sha1, 0, 0, 1),
                      std::invalid_argument);
    BOOST_TEST(!s3::combine_full_object(checksum_algorithm::crc32, {{"bad", 1}}).has_value());
}

BOOST_AUTO_TEST_CASE(composite_checksums) {
    const auto p1 = s3::checksum_of(checksum_algorithm::sha256, "part one");
    const auto p2 = s3::checksum_of(checksum_algorithm::sha256, "part two");
    const auto expected = [&] {
        s3::checksummer c(checksum_algorithm::sha256);
        c.update(*s3::decode_checksum(checksum_algorithm::sha256, p1));
        c.update(*s3::decode_checksum(checksum_algorithm::sha256, p2));
        return c.value() + "-2";
    }();
    BOOST_TEST(s3::composite_checksum(checksum_algorithm::sha256, {p1, p2}).value_or("") ==
               expected);
    BOOST_TEST(!s3::composite_checksum(checksum_algorithm::sha256, {"zz"}).has_value());
}

BOOST_AUTO_TEST_CASE(names_round_trip) {
    for (auto a : s3::all_checksum_algorithms) {
        BOOST_TEST((s3::parse_checksum_algorithm(s3::to_string(a)) == a));
        BOOST_TEST((s3::algorithm_of_header(s3::checksum_header(a)) == a));
    }
    BOOST_TEST(s3::checksum_header(checksum_algorithm::crc64nvme) == "x-amz-checksum-crc64nvme");
    BOOST_TEST(s3::checksum_element(checksum_algorithm::crc32c) == "ChecksumCRC32C");
    BOOST_TEST(!s3::parse_checksum_algorithm("MD5").has_value());
}

BOOST_AUTO_TEST_CASE(what_a_request_asks_for) {
    using headers = std::vector<std::pair<std::string, std::string>>;
    const auto code = [](const auto& r) { return r ? std::string{} : r.error().code; };

    auto none = s3::requested({});
    BOOST_TEST_REQUIRE(none.has_value());
    BOOST_TEST(none->defaulted);
    BOOST_TEST((none->algorithm == checksum_algorithm::crc64nvme));

    const auto crc = s3::checksum_of(checksum_algorithm::crc32, "x");
    auto header = s3::requested(headers{{"X-Amz-Checksum-Crc32", crc}});
    BOOST_TEST_REQUIRE(header.has_value());
    BOOST_TEST(!header->defaulted);
    BOOST_TEST(header->value.value_or("") == crc);

    auto trailer = s3::requested(headers{{"x-amz-trailer", "x-amz-checksum-crc32c"},
                                         {"x-amz-sdk-checksum-algorithm", "CRC32C"}});
    BOOST_TEST_REQUIRE(trailer.has_value());
    BOOST_TEST(trailer->trailer);
    BOOST_TEST((trailer->algorithm == checksum_algorithm::crc32c));

    BOOST_TEST(code(s3::requested(headers{
                   {"x-amz-checksum-crc32", crc},
                   {"x-amz-checksum-sha1", s3::checksum_of(checksum_algorithm::sha1, "x")}})) ==
               "InvalidRequest");
    BOOST_TEST(code(s3::requested(headers{{"x-amz-checksum-crc32", "nope"}})) == "InvalidRequest");
    BOOST_TEST(code(s3::requested(headers{{"x-amz-sdk-checksum-algorithm", "CRC32"}})) ==
               "InvalidRequest");
    BOOST_TEST(code(s3::requested(headers{{"x-amz-sdk-checksum-algorithm", "MD5"}})) ==
               "InvalidRequest");

    // Verification against a header, a trailer, and a missing trailer.
    const auto right = s3::checksum_of(checksum_algorithm::crc32, "body");
    s3::requested_checksum want;
    want.algorithm = checksum_algorithm::crc32;
    want.defaulted = false;
    want.value = right;
    BOOST_TEST(!s3::verify(want, right, {}).has_value());
    want.value = crc;
    BOOST_TEST(s3::verify(want, right, {})->code == "BadDigest");
    want.value.reset();
    want.trailer = true;
    BOOST_TEST(!s3::verify(want, right, {{"x-amz-checksum-crc32", right}}).has_value());
    BOOST_TEST(s3::verify(want, right, {{"x-amz-checksum-crc32", crc}})->code == "BadDigest");
    BOOST_TEST(s3::verify(want, right, {})->code == "InvalidRequest");
}
