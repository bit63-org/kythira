// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_snappy.hpp
/// @brief The Snappy block format (google/snappy `format_description.txt`),
///        compressed and decompressed, for Avro's `snappy` codec in the
///        channel S3 Tables destination (`kinesis_avro.hpp`).
///
/// Snappy is the only compression an S3 Tables channel can ask for that the
/// build has no library for, and its block format is small: a varint of the
/// uncompressed length, then literals and back-references. The compressor
/// is the usual greedy one (a hash of each 4-byte sequence, copies of up to
/// 64 bytes within 64 KiB); its output is not byte-identical to libsnappy's
/// but any Snappy decoder reads it. The decompressor accepts every element
/// the format defines, so it reads libsnappy's output too.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace kythira::kinesis::snappy {

namespace detail {

inline auto put_varint(std::string& out, std::uint64_t v) -> void {
    while (v >= 0x80U) {
        out.push_back(static_cast<char>((v & 0x7FU) | 0x80U));
        v >>= 7U;
    }
    out.push_back(static_cast<char>(v));
}

inline auto put_literal(std::string& out, std::string_view lit) -> void {
    while (!lit.empty()) {
        // One element holds at most 2^32 bytes; 64 KiB pieces keep it simple.
        const auto n = std::min<std::size_t>(lit.size(), 65536);
        const auto len = n - 1;
        if (len < 60) {
            out.push_back(static_cast<char>(len << 2U));
        } else if (len < 0x100) {
            out.push_back(static_cast<char>(60U << 2U));
            out.push_back(static_cast<char>(len));
        } else {
            out.push_back(static_cast<char>(61U << 2U));
            out.push_back(static_cast<char>(len & 0xFFU));
            out.push_back(static_cast<char>(len >> 8U));
        }
        out.append(lit.substr(0, n));
        lit.remove_prefix(n);
    }
}

/// A copy with a two-byte offset: 1 to 64 bytes from up to 65535 back.
inline auto put_copy(std::string& out, std::size_t offset, std::size_t len) -> void {
    while (len > 0) {
        const auto n = std::min<std::size_t>(len, 64);
        out.push_back(static_cast<char>(((n - 1) << 2U) | 2U));
        out.push_back(static_cast<char>(offset & 0xFFU));
        out.push_back(static_cast<char>((offset >> 8U) & 0xFFU));
        len -= n;
    }
}

[[nodiscard]] inline auto load32(const char* p) -> std::uint32_t {
    std::uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

}  // namespace detail

[[nodiscard]] inline auto compress(std::string_view in) -> std::string {
    std::string out;
    out.reserve(in.size() + in.size() / 6 + 16);
    detail::put_varint(out, in.size());
    constexpr unsigned k_bits = 14;
    std::array<std::uint32_t, std::size_t{1} << k_bits> table{};  // position + 1, 0 = empty
    const auto hash = [](std::uint32_t v) { return (v * 0x1E35A7BDU) >> (32U - k_bits); };
    std::size_t literal_from = 0;
    std::size_t i = 0;
    while (in.size() >= 4 && i + 4 <= in.size()) {
        const auto v = detail::load32(in.data() + i);
        auto& slot = table[hash(v)];
        const auto candidate = static_cast<std::size_t>(slot);
        slot = static_cast<std::uint32_t>(i + 1);
        if (candidate == 0 || i - (candidate - 1) > 65535 ||
            detail::load32(in.data() + candidate - 1) != v) {
            ++i;
            continue;
        }
        const auto from = candidate - 1;
        std::size_t len = 4;
        while (i + len < in.size() && in[from + len] == in[i + len]) {
            ++len;
        }
        detail::put_literal(out, in.substr(literal_from, i - literal_from));
        detail::put_copy(out, i - from, len);
        i += len;
        literal_from = i;
    }
    detail::put_literal(out, in.substr(literal_from));
    return out;
}

/// nullopt when `in` is not a valid Snappy block.
[[nodiscard]] inline auto decompress(std::string_view in) -> std::optional<std::string> {
    std::size_t at = 0;
    std::uint64_t size = 0;
    for (unsigned shift = 0;; shift += 7) {
        if (at >= in.size() || shift > 35) {
            return std::nullopt;
        }
        const auto b = static_cast<unsigned char>(in[at++]);
        size |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
        if ((b & 0x80U) == 0) {
            break;
        }
    }
    std::string out;
    out.reserve(size);
    auto read_le = [&](std::size_t n) -> std::optional<std::size_t> {
        if (n > in.size() - at) {
            return std::nullopt;
        }
        std::size_t v = 0;
        for (std::size_t k = 0; k < n; ++k) {
            v |= static_cast<std::size_t>(static_cast<unsigned char>(in[at + k])) << (8 * k);
        }
        at += n;
        return v;
    };
    while (at < in.size()) {
        const auto tag = static_cast<unsigned char>(in[at++]);
        const auto kind = tag & 3U;
        if (kind == 0) {
            std::size_t len = tag >> 2U;
            if (len >= 60) {
                const auto extra = read_le(len - 59);
                if (!extra) {
                    return std::nullopt;
                }
                len = *extra;
            }
            ++len;
            if (len > in.size() - at) {
                return std::nullopt;
            }
            out.append(in.substr(at, len));
            at += len;
            continue;
        }
        std::size_t len = 0;
        std::size_t offset = 0;
        if (kind == 1) {
            len = ((tag >> 2U) & 7U) + 4;
            const auto lo = read_le(1);
            if (!lo) {
                return std::nullopt;
            }
            offset = (static_cast<std::size_t>(tag >> 5U) << 8U) | *lo;
        } else {
            len = (tag >> 2U) + 1;
            const auto o = read_le(kind == 2 ? 2 : 4);
            if (!o) {
                return std::nullopt;
            }
            offset = *o;
        }
        if (offset == 0 || offset > out.size()) {
            return std::nullopt;
        }
        // Byte by byte: a copy may overlap what it is writing.
        const auto from = out.size() - offset;
        for (std::size_t k = 0; k < len; ++k) {
            out.push_back(out[from + k]);
        }
    }
    if (out.size() != size) {
        return std::nullopt;
    }
    return out;
}

}  // namespace kythira::kinesis::snappy
