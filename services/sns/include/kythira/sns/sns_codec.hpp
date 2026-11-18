// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file sns_codec.hpp
/// @brief The byte codec of the SNS module's Raft commands, apply results,
///        snapshots and stored messages
///        (.kiro/specs/sns-compatible-notifications/ task 2).
///
/// Big-endian fixed-width integers and `u32 length + bytes` strings. A
/// decoder throws `sns_codec_error` on truncation, an out-of-range
/// enumeration or a malformed boolean, and a caller checks `expect_end`
/// where trailing bytes would be an error. Nothing here depends on the host
/// byte order, so every replica encodes the same bytes.

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sns {

/// A command, result, snapshot or stored message that cannot be decoded.
class sns_codec_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace codec {

class writer {
public:
    auto u8(std::uint8_t v) -> writer& {
        _out.push_back(static_cast<std::byte>(v));
        return *this;
    }
    auto u16(std::uint16_t v) -> writer& { return be(v, 2); }
    auto u32(std::uint32_t v) -> writer& { return be(v, 4); }
    auto u64(std::uint64_t v) -> writer& { return be(v, 8); }
    auto i64(std::int64_t v) -> writer& { return be(static_cast<std::uint64_t>(v), 8); }
    auto boolean(bool v) -> writer& { return u8(v ? 1 : 0); }
    auto str(std::string_view s) -> writer& {
        u32(static_cast<std::uint32_t>(s.size()));
        for (const char c : s) {
            _out.push_back(static_cast<std::byte>(c));
        }
        return *this;
    }
    auto bytes(std::span<const std::byte> b) -> writer& {
        u32(static_cast<std::uint32_t>(b.size()));
        return raw(b);
    }
    auto raw(std::span<const std::byte> b) -> writer& {
        _out.insert(_out.end(), b.begin(), b.end());
        return *this;
    }
    /// A string map in key order, so equal maps encode to equal bytes.
    auto strings(const std::map<std::string, std::string, std::less<>>& m) -> writer& {
        u32(static_cast<std::uint32_t>(m.size()));
        for (const auto& [k, v] : m) {
            str(k).str(v);
        }
        return *this;
    }

    [[nodiscard]] auto take() -> std::vector<std::byte> { return std::move(_out); }

private:
    auto be(std::uint64_t v, int n) -> writer& {
        for (int i = n - 1; i >= 0; --i) {
            _out.push_back(static_cast<std::byte>((v >> (static_cast<unsigned>(i) * 8U)) & 0xFFU));
        }
        return *this;
    }
    std::vector<std::byte> _out{};
};

class reader {
public:
    explicit reader(std::span<const std::byte> in) : _in(in) {}

    auto u8() -> std::uint8_t { return static_cast<std::uint8_t>(be(1)); }
    auto u16() -> std::uint16_t { return static_cast<std::uint16_t>(be(2)); }
    auto u32() -> std::uint32_t { return static_cast<std::uint32_t>(be(4)); }
    auto u64() -> std::uint64_t { return be(8); }
    auto i64() -> std::int64_t { return static_cast<std::int64_t>(be(8)); }
    auto boolean() -> bool {
        const auto v = u8();
        if (v > 1) {
            throw sns_codec_error("sns codec: bad boolean");
        }
        return v == 1;
    }
    auto str() -> std::string {
        auto b = take(u32());
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }
    auto bytes() -> std::vector<std::byte> {
        auto b = take(u32());
        return {b.begin(), b.end()};
    }
    auto strings() -> std::map<std::string, std::string, std::less<>> {
        std::map<std::string, std::string, std::less<>> out;
        const auto n = u32();
        for (std::uint32_t i = 0; i < n; ++i) {
            auto k = str();
            auto v = str();
            out.insert_or_assign(std::move(k), std::move(v));
        }
        return out;
    }
    auto take(std::size_t n) -> std::span<const std::byte> {
        need(n);
        auto b = _in.subspan(0, n);
        _in = _in.subspan(n);
        return b;
    }
    template<typename E> auto enumeration(std::uint8_t max) -> E {
        const auto v = u8();
        if (v > max) {
            throw sns_codec_error("sns codec: enum value out of range");
        }
        return static_cast<E>(v);
    }
    /// A count of items each at least `min_item_bytes` long, refused when the
    /// input cannot hold that many, so a corrupt count cannot make a decoder
    /// reserve or loop for billions of items.
    auto count(std::size_t min_item_bytes) -> std::uint32_t {
        const auto n = u32();
        if (min_item_bytes > 0 && n > _in.size() / min_item_bytes) {
            throw sns_codec_error("sns codec: count larger than the input");
        }
        return n;
    }

    [[nodiscard]] auto remaining() const noexcept -> std::size_t { return _in.size(); }
    /// What is left, for a nested decoder that advances a span itself.
    [[nodiscard]] auto rest() -> std::span<const std::byte>& { return _in; }
    auto expect_end(std::string_view what) const -> void {
        if (!_in.empty()) {
            throw sns_codec_error("sns codec: trailing bytes after " + std::string(what));
        }
    }

private:
    auto need(std::size_t n) const -> void {
        if (_in.size() < n) {
            throw sns_codec_error("sns codec: truncated");
        }
    }
    auto be(std::size_t n) -> std::uint64_t {
        need(n);
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_in[i]);
        }
        _in = _in.subspan(n);
        return v;
    }
    std::span<const std::byte> _in;
};

}  // namespace codec

}  // namespace kythira::sns
