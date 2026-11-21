// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file crc32.hpp
/// @brief CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), the checksum
///        the disk-backed build cache's pack records and binary log segments
///        carry (.kiro/specs/disk-backed-build-cache/ design Components 1a
///        and 4).
///
/// A CRC here detects torn writes and bit rot, not tampering: every chunk is
/// also named by its SHA-256, which is what reads are checked against. The
/// table is built at compile time so the header has no dependency beyond the
/// standard library; zlib's `crc32` computes the same function and would only
/// add a link dependency for a few kilobytes of code.
///
/// **Slicing-by-8.** Every 4 MiB chunk entry is checksummed when the log
/// appends it, again when the chunk store packs or reads it, and on every
/// replica, so this loop sits on the cache's write path several times per
/// byte. One table lookup per byte ran at well under 1 GB/s and showed up
/// as the hottest instruction in a profile of a three-node write run
/// (GitHub issue 942). Eight tables let the loop fold eight bytes per step
/// with independent lookups, several times faster, and give bit-identical
/// results, so nothing on disk changes. It stays `constexpr` and portable:
/// the eight bytes are assembled one by one, which compilers turn into a
/// single load.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace kythira {

namespace detail {

[[nodiscard]] constexpr auto make_crc32_tables() noexcept
    -> std::array<std::array<std::uint32_t, 256>, 8> {
    std::array<std::array<std::uint32_t, 256>, 8> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1U) != 0 ? 0xEDB88320U ^ (c >> 1U) : c >> 1U;
        }
        t[0][i] = c;
    }
    // t[k][i]: the CRC contribution of byte i followed by k zero bytes.
    for (std::size_t k = 1; k < 8; ++k) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            const auto prev = t[k - 1][i];
            t[k][i] = t[0][prev & 0xFFU] ^ (prev >> 8U);
        }
    }
    return t;
}

inline constexpr auto crc32_tables = make_crc32_tables();

/// The one-table form, kept for anyone who wants a byte at a time.
inline constexpr auto crc32_table = crc32_tables[0];

}  // namespace detail

[[nodiscard]] constexpr auto crc32_update(std::uint32_t crc,
                                          std::span<const std::byte> bytes) noexcept
    -> std::uint32_t {
    const auto& t = detail::crc32_tables;
    crc = ~crc;
    const std::byte* p = bytes.data();
    std::size_t n = bytes.size();
    const auto u = [](std::byte b) { return static_cast<std::uint32_t>(b); };
    while (n >= 8) {
        const std::uint32_t lo =
            crc ^ (u(p[0]) | (u(p[1]) << 8U) | (u(p[2]) << 16U) | (u(p[3]) << 24U));
        const std::uint32_t hi = u(p[4]) | (u(p[5]) << 8U) | (u(p[6]) << 16U) | (u(p[7]) << 24U);
        crc = t[7][lo & 0xFFU] ^ t[6][(lo >> 8U) & 0xFFU] ^ t[5][(lo >> 16U) & 0xFFU] ^
              t[4][lo >> 24U] ^ t[3][hi & 0xFFU] ^ t[2][(hi >> 8U) & 0xFFU] ^
              t[1][(hi >> 16U) & 0xFFU] ^ t[0][hi >> 24U];
        p += 8;
        n -= 8;
    }
    for (; n != 0; --n, ++p) {
        crc = t[0][(crc ^ u(*p)) & 0xFFU] ^ (crc >> 8U);
    }
    return ~crc;
}

[[nodiscard]] constexpr auto crc32(std::span<const std::byte> bytes) noexcept -> std::uint32_t {
    return crc32_update(0, bytes);
}

}  // namespace kythira
