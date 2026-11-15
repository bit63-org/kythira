// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The byte encoding of the KMS catalog's commands, replies and records:
// big-endian integers and length-prefixed UTF-8 text. There is no field
// for raw bytes, and text that is not valid UTF-8 is refused on both
// writing and reading, so nothing in the catalog's log or snapshots can
// carry binary key material (.kiro/specs/kms-compatible-api/ task 4,
// Requirement 3.5). A reader that runs short, finds trailing bytes or
// finds bad UTF-8 throws std::invalid_argument, as the other persistent
// state machines treat a malformed command: only a bug in this module's
// leader can make one.

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kms {

/// True when `s` is well-formed UTF-8: no overlong forms, no surrogates,
/// nothing above U+10FFFF.
[[nodiscard]] inline auto valid_utf8(std::string_view s) -> bool {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        std::size_t n = 0;
        std::uint32_t cp = 0;
        if (c < 0x80) {
            ++i;
            continue;
        }
        if ((c & 0xE0U) == 0xC0U) {
            n = 1;
            cp = c & 0x1FU;
        } else if ((c & 0xF0U) == 0xE0U) {
            n = 2;
            cp = c & 0x0FU;
        } else if ((c & 0xF8U) == 0xF0U) {
            n = 3;
            cp = c & 0x07U;
        } else {
            return false;
        }
        if (s.size() - i <= n) {
            return false;
        }
        for (std::size_t k = 1; k <= n; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0U) != 0x80U) {
                return false;
            }
            cp = (cp << 6U) | (cc & 0x3FU);
        }
        static constexpr std::uint32_t min_for[] = {0, 0x80, 0x800, 0x10000};
        if (cp < min_for[n] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

class byte_writer {
public:
    auto u8(std::uint8_t v) -> byte_writer& {
        _out.push_back(static_cast<std::byte>(v));
        return *this;
    }
    auto u16(std::uint16_t v) -> byte_writer& {
        return u8(static_cast<std::uint8_t>(v >> 8U)).u8(static_cast<std::uint8_t>(v));
    }
    auto u32(std::uint32_t v) -> byte_writer& {
        for (int shift = 24; shift >= 0; shift -= 8) {
            u8(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
        return *this;
    }
    auto u64(std::uint64_t v) -> byte_writer& {
        for (int shift = 56; shift >= 0; shift -= 8) {
            u8(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
        return *this;
    }
    auto boolean(bool v) -> byte_writer& { return u8(v ? 1 : 0); }
    /// UTF-8 text; throws std::invalid_argument for anything else.
    auto str(std::string_view v) -> byte_writer& {
        if (v.size() > UINT32_MAX) {
            throw std::length_error("kms codec: field too long");
        }
        if (!valid_utf8(v)) {
            throw std::invalid_argument("kms codec: text is not UTF-8");
        }
        u32(static_cast<std::uint32_t>(v.size()));
        for (char c : v) {
            u8(static_cast<std::uint8_t>(c));
        }
        return *this;
    }

    [[nodiscard]] auto take() -> std::vector<std::byte> { return std::move(_out); }

    /// The bytes as a std::string, for engine values.
    [[nodiscard]] auto take_string() -> std::string {
        std::string s(_out.size(), '\0');
        for (std::size_t i = 0; i < _out.size(); ++i) {
            s[i] = static_cast<char>(_out[i]);
        }
        _out.clear();
        return s;
    }

private:
    std::vector<std::byte> _out;
};

class byte_reader {
public:
    explicit byte_reader(std::span<const std::byte> in) : _in(in) {}
    explicit byte_reader(std::string_view in)
        : _in(reinterpret_cast<const std::byte*>(in.data()), in.size()) {}

    auto u8() -> std::uint8_t {
        need(1);
        return static_cast<std::uint8_t>(_in[_at++]);
    }
    auto u16() -> std::uint16_t {
        const auto hi = u8();
        return static_cast<std::uint16_t>((hi << 8U) | u8());
    }
    auto u32() -> std::uint32_t {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | u8();
        }
        return v;
    }
    auto u64() -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8U) | u8();
        }
        return v;
    }
    auto boolean() -> bool {
        const auto v = u8();
        if (v > 1) {
            throw std::invalid_argument("kms codec: bad boolean");
        }
        return v == 1;
    }
    auto str() -> std::string {
        const std::uint32_t n = u32();
        need(n);
        std::string out(n, '\0');
        for (std::uint32_t i = 0; i < n; ++i) {
            out[i] = static_cast<char>(_in[_at++]);
        }
        if (!valid_utf8(out)) {
            throw std::invalid_argument("kms codec: text is not UTF-8");
        }
        return out;
    }

    [[nodiscard]] auto done() const noexcept -> bool { return _at == _in.size(); }

    /// Throws unless every byte was read.
    void finish() const {
        if (!done()) {
            throw std::invalid_argument("kms codec: trailing bytes");
        }
    }

private:
    void need(std::size_t n) const {
        if (_in.size() - _at < n) {
            throw std::invalid_argument("kms codec: truncated");
        }
    }

    std::span<const std::byte> _in;
    std::size_t _at = 0;
};

}  // namespace kythira::kms
