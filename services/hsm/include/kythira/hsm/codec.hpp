// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The byte encoding of the HSM's Raft commands, replies and stored records:
// big-endian integers and length-prefixed byte strings. A reader that runs
// short or finds trailing bytes throws std::invalid_argument, the same way
// the other persistent state machines treat a malformed command (it can only
// come from a bug, since every command is built by this module's leader).

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

class byte_writer {
public:
    /// Room for `n` bytes, so a buffer that will hold a secret is not
    /// reallocated (leaving a copy behind) while it is written.
    auto reserve(std::size_t n) -> byte_writer& {
        _out.reserve(n);
        return *this;
    }
    auto u8(std::uint8_t v) -> byte_writer& {
        _out.push_back(static_cast<std::byte>(v));
        return *this;
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
    auto bytes(std::span<const std::uint8_t> v) -> byte_writer& {
        if (v.size() > UINT32_MAX) {
            throw std::length_error("hsm codec: field too long");
        }
        u32(static_cast<std::uint32_t>(v.size()));
        for (auto b : v) {
            u8(b);
        }
        return *this;
    }
    auto str(std::string_view v) -> byte_writer& {
        return bytes(std::span(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()));
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
    auto bytes() -> std::vector<std::uint8_t> {
        const std::uint32_t n = u32();
        need(n);
        std::vector<std::uint8_t> out(n);
        for (std::uint32_t i = 0; i < n; ++i) {
            out[i] = static_cast<std::uint8_t>(_in[_at++]);
        }
        return out;
    }
    auto str() -> std::string {
        auto b = bytes();
        return {b.begin(), b.end()};
    }

    [[nodiscard]] auto done() const noexcept -> bool { return _at == _in.size(); }

    /// Throws unless every byte was read.
    void finish() const {
        if (!done()) {
            throw std::invalid_argument("hsm codec: trailing bytes");
        }
    }

private:
    void need(std::size_t n) const {
        if (_in.size() - _at < n) {
            throw std::invalid_argument("hsm codec: truncated");
        }
    }

    std::span<const std::byte> _in;
    std::size_t _at = 0;
};

}  // namespace kythira::hsm
