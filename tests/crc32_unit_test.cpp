// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// include/raft/crc32.hpp computes CRC-32 eight bytes at a time (GitHub
// issue 942). The pack records and binary log segments already on disk
// were written by the one-byte-at-a-time form, so the two must agree on
// every input: these cases compare it against a bitwise reference over
// every alignment and every length around the eight-byte step, and pin the
// standard check value at compile time.

#define BOOST_TEST_MODULE crc32_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/crc32.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <string_view>
#include <vector>

namespace {

/// The polynomial division itself, a bit at a time: no tables to share a
/// mistake with the code under test.
auto reference_crc32(std::span<const std::byte> bytes) -> std::uint32_t {
    std::uint32_t crc = ~0U;
    for (const std::byte b : bytes) {
        crc ^= static_cast<std::uint32_t>(b);
        for (int k = 0; k < 8; ++k) {
            crc = (crc & 1U) != 0 ? 0xEDB88320U ^ (crc >> 1U) : crc >> 1U;
        }
    }
    return ~crc;
}

constexpr auto check_value() -> std::uint32_t {
    constexpr std::string_view digits = "123456789";
    std::array<std::byte, digits.size()> bytes{};
    for (std::size_t i = 0; i < digits.size(); ++i) {
        bytes[i] = static_cast<std::byte>(digits[i]);
    }
    return kythira::crc32(bytes);
}

// The CRC-32/ISO-HDLC check value, and still usable in a constant
// expression.
static_assert(check_value() == 0xCBF43926U);
static_assert(kythira::crc32(std::span<const std::byte>{}) == 0U);

auto random_bytes(std::size_t n, std::uint32_t seed) -> std::vector<std::byte> {
    std::mt19937 gen(seed);
    std::vector<std::byte> out(n);
    for (auto& b : out) {
        b = static_cast<std::byte>(gen() & 0xFFU);
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(matches_the_bitwise_reference_at_every_alignment_and_length) {
    const auto data = random_bytes(4096, 942);
    const std::span<const std::byte> all(data);
    for (std::size_t offset = 0; offset < 16; ++offset) {
        for (std::size_t len = 0; len <= 64; ++len) {
            const auto piece = all.subspan(offset, len);
            BOOST_TEST_REQUIRE(kythira::crc32(piece) == reference_crc32(piece),
                               "offset " << offset << " length " << len);
        }
    }
    for (const std::size_t len : {1000U, 4093U, 4080U}) {
        const auto piece = all.subspan(3, len);
        BOOST_TEST(kythira::crc32(piece) == reference_crc32(piece));
    }
}

BOOST_AUTO_TEST_CASE(updating_in_pieces_equals_one_pass) {
    const auto data = random_bytes(1 << 20, 7);
    const std::span<const std::byte> all(data);
    const auto whole = kythira::crc32(all);
    BOOST_TEST(whole == reference_crc32(all));
    // Split points that leave both pieces off the eight-byte grid.
    for (const std::size_t cut : {1U, 7U, 9U, 4097U, (1U << 20) - 3}) {
        auto crc = kythira::crc32_update(0, all.first(cut));
        crc = kythira::crc32_update(crc, all.subspan(cut));
        BOOST_TEST(crc == whole, "cut at " << cut);
    }
}

BOOST_AUTO_TEST_CASE(all_ones_and_all_zeros) {
    // Inputs where a slicing table indexed by the wrong byte would still
    // look plausible on random data.
    for (const auto fill : {std::byte{0x00}, std::byte{0xFF}}) {
        const std::vector<std::byte> bytes(1027, fill);
        BOOST_TEST(kythira::crc32(bytes) == reference_crc32(bytes));
    }
}
