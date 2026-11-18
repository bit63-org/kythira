// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_rdb_crc64.hpp
/// @brief The CRC64 Redis and Valkey put at the end of an RDB file and of a
///        `DUMP` payload (.kiro/specs/redis-migration-tooling/ task 1,
///        design Component 1).
///
/// The variant is CRC-64/Jones as Redis's `crc64.c` computes it: polynomial
/// 0xad93d23594c935a9, reflected input and output, initial value 0, no final
/// xor. Its check value (the CRC of "123456789") is 0xe9c6d914c4b8d9ca. The
/// table-driven loop below is the reflected form, so the table is built
/// from the bit-reversed polynomial 0x95ac9329ac4bc9b5.
///
/// An RDB file stores the CRC of every byte from the magic through the EOF
/// opcode as 8 little-endian bytes; a `DUMP` payload stores the CRC of the
/// type byte, value and 2-byte version the same way. A stored 0 means the
/// writer ran with `rdbchecksum no`, and loaders skip the check.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace kythira {

namespace rdb_crc64_detail {

inline constexpr std::uint64_t reflected_poly = 0x95ac9329ac4bc9b5ULL;

constexpr auto make_table() -> std::array<std::uint64_t, 256> {
    std::array<std::uint64_t, 256> t{};
    for (std::uint64_t i = 0; i < 256; ++i) {
        std::uint64_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1U) != 0 ? (c >> 1U) ^ reflected_poly : c >> 1U;
        }
        t[i] = c;
    }
    return t;
}

inline constexpr auto table = make_table();

}  // namespace rdb_crc64_detail

/// Continue a CRC over `bytes`. Start with `crc = 0`.
[[nodiscard]] constexpr auto rdb_crc64(std::uint64_t crc,
                                       std::span<const std::uint8_t> bytes) noexcept
    -> std::uint64_t {
    for (const std::uint8_t b : bytes) {
        crc = rdb_crc64_detail::table[(crc ^ b) & 0xffU] ^ (crc >> 8U);
    }
    return crc;
}

[[nodiscard]] constexpr auto rdb_crc64(std::uint64_t crc, std::string_view bytes) noexcept
    -> std::uint64_t {
    for (const char ch : bytes) {
        const auto b = static_cast<std::uint8_t>(ch);
        crc = rdb_crc64_detail::table[(crc ^ b) & 0xffU] ^ (crc >> 8U);
    }
    return crc;
}

static_assert(rdb_crc64(0, std::string_view{"123456789"}) == 0xe9c6d914c4b8d9caULL,
              "CRC-64/Jones check value");

}  // namespace kythira
