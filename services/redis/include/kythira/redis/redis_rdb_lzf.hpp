// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_rdb_lzf.hpp
/// @brief LZF, the compression Redis and Valkey apply to long strings in RDB
///        files and `DUMP` payloads (.kiro/specs/redis-migration-tooling/
///        task 1, design Component 1: written in-tree).
///
/// The format is a sequence of runs, each starting with a control byte `c`:
///
/// - `c < 32`: a literal run; the next `c + 1` bytes are copied as they are.
/// - otherwise a back reference: `len = c >> 5` (7 means "7 plus the next
///   byte"), then one more byte; the reference starts
///   `((c & 0x1f) << 8) + that byte + 1` bytes back in the output, and
///   `len + 2` bytes are copied from it (the copy may overlap itself, which
///   is how runs of one byte compress).
///
/// So a reference reaches at most 8192 bytes back and copies 3 to 264 bytes.
///
/// The decompressor checks every bound, so a corrupt or hostile input is
/// refused, never read or written out of range. The compressor is a plain
/// greedy matcher with a 14-bit hash of the next three bytes. Its output is
/// valid LZF, so Redis and Valkey load it, but it is not byte-identical to
/// liblzf's: an RDB file re-encoded by Kythira can differ from the server's
/// in compressed strings while decoding to the same values.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira {

/// The largest output one input byte of LZF can produce: a 3-byte back
/// reference copies at most 264 bytes. A stored uncompressed length above
/// `compressed * rdb_lzf_max_ratio` cannot be honest, so the RDB reader
/// refuses it before allocating anything.
inline constexpr std::uint64_t rdb_lzf_max_ratio = 88;

/// Decompress `in` into exactly `out_len` bytes. Returns nullopt if the
/// input is corrupt or does not produce exactly `out_len` bytes.
[[nodiscard]] inline auto rdb_lzf_decompress(std::span<const std::uint8_t> in, std::size_t out_len)
    -> std::optional<std::string> {
    if (out_len > 0 && static_cast<std::uint64_t>(out_len) / rdb_lzf_max_ratio > in.size()) {
        return std::nullopt;
    }
    std::string out;
    out.resize(out_len);
    std::size_t ip = 0;
    std::size_t op = 0;
    while (ip < in.size()) {
        const std::size_t ctrl = in[ip++];
        if (ctrl < 32) {
            const std::size_t n = ctrl + 1;
            if (ip + n > in.size() || op + n > out_len) {
                return std::nullopt;
            }
            std::copy_n(in.data() + ip, n, reinterpret_cast<std::uint8_t*>(out.data()) + op);
            ip += n;
            op += n;
            continue;
        }
        std::size_t len = ctrl >> 5U;
        if (len == 7) {
            if (ip >= in.size()) {
                return std::nullopt;
            }
            len += in[ip++];
        }
        if (ip >= in.size()) {
            return std::nullopt;
        }
        const std::size_t back = ((ctrl & 0x1fU) << 8U) + in[ip++] + 1;
        len += 2;
        if (back > op || op + len > out_len) {
            return std::nullopt;
        }
        // Byte by byte on purpose: the source may overlap the destination.
        for (std::size_t i = 0; i < len; ++i) {
            out[op + i] = out[op - back + i];
        }
        op += len;
    }
    if (op != out_len) {
        return std::nullopt;
    }
    return out;
}

/// Compress `in`. Returns nullopt unless the result is at least `min_saving`
/// bytes shorter than the input, which is the only case in which the RDB
/// writer uses it (Redis needs a saving of at least 4 bytes, the cost of
/// the two extra lengths, before it stores the compressed form).
[[nodiscard]] inline auto rdb_lzf_compress(std::string_view in, std::size_t min_saving = 1)
    -> std::optional<std::string> {
    constexpr std::size_t hash_bits = 14;
    constexpr std::size_t max_back = 8192;
    constexpr std::size_t max_match = 264;
    constexpr std::size_t max_literal = 32;
    const std::size_t n = in.size();
    if (n < 4 || min_saving >= n) {
        return std::nullopt;
    }
    const std::size_t limit = n - min_saving;
    const auto* p = reinterpret_cast<const std::uint8_t*>(in.data());
    std::vector<std::size_t> table(std::size_t{1} << hash_bits, SIZE_MAX);
    std::string out;
    out.reserve(n);
    std::size_t lit_start = 0;
    auto flush_literals = [&](std::size_t end) {
        while (lit_start < end) {
            const std::size_t run = std::min(max_literal, end - lit_start);
            out.push_back(static_cast<char>(run - 1));
            out.append(in.substr(lit_start, run));
            lit_start += run;
        }
    };
    std::size_t i = 0;
    while (i + 3 <= n) {
        const std::uint32_t v =
            (std::uint32_t{p[i]} << 16U) | (std::uint32_t{p[i + 1]} << 8U) | p[i + 2];
        const std::size_t h =
            ((v * 2654435761U) >> (32 - hash_bits)) & ((std::size_t{1} << hash_bits) - 1);
        const std::size_t ref = table[h];
        table[h] = i;
        if (ref != SIZE_MAX && i - ref <= max_back && p[ref] == p[i] && p[ref + 1] == p[i + 1] &&
            p[ref + 2] == p[i + 2]) {
            const std::size_t room = std::min(max_match, n - i);
            std::size_t len = 3;
            while (len < room && p[ref + len] == p[i + len]) {
                ++len;
            }
            flush_literals(i);
            const std::size_t back = i - ref - 1;
            const std::size_t l = len - 2;
            if (l < 7) {
                out.push_back(static_cast<char>((l << 5U) | (back >> 8U)));
            } else {
                out.push_back(static_cast<char>((7U << 5U) | (back >> 8U)));
                out.push_back(static_cast<char>(l - 7));
            }
            out.push_back(static_cast<char>(back & 0xffU));
            i += len;
            lit_start = i;
        } else {
            ++i;
        }
        if (out.size() > limit) {
            return std::nullopt;
        }
    }
    flush_literals(n);
    if (out.size() > limit) {
        return std::nullopt;
    }
    return out;
}

}  // namespace kythira
