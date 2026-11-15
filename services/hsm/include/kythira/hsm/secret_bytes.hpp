// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A buffer for secret bytes (a master key, a share, a key being unwrapped)
// that lives in the secure arena (locked, non-dumpable pages; see
// secure_arena.hpp), is wiped when it is destroyed, resized or moved from,
// and cannot be copied by accident.

#include <kythira/hsm/secure_arena.hpp>

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace kythira::hsm {

class secret_bytes {
public:
    secret_bytes() = default;
    explicit secret_bytes(std::size_t size) : _bytes(size) {}
    explicit secret_bytes(std::span<const std::uint8_t> bytes)
        : _bytes(bytes.begin(), bytes.end()) {}

    secret_bytes(const secret_bytes&) = delete;
    auto operator=(const secret_bytes&) -> secret_bytes& = delete;

    secret_bytes(secret_bytes&& other) noexcept : _bytes(std::move(other._bytes)) {
        other._bytes.clear();
    }
    auto operator=(secret_bytes&& other) noexcept -> secret_bytes& {
        if (this != &other) {
            wipe();
            _bytes = std::move(other._bytes);
            other._bytes.clear();
        }
        return *this;
    }

    ~secret_bytes() { wipe(); }

    /// An explicit copy, for the few places a second holder is meant.
    [[nodiscard]] auto clone() const -> secret_bytes { return secret_bytes(view()); }

    [[nodiscard]] auto view() const noexcept -> std::span<const std::uint8_t> { return _bytes; }
    [[nodiscard]] auto span() noexcept -> std::span<std::uint8_t> { return _bytes; }
    [[nodiscard]] auto data() noexcept -> std::uint8_t* { return _bytes.data(); }
    [[nodiscard]] auto data() const noexcept -> const std::uint8_t* { return _bytes.data(); }
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _bytes.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return _bytes.empty(); }
    auto operator[](std::size_t i) noexcept -> std::uint8_t& { return _bytes[i]; }
    auto operator[](std::size_t i) const noexcept -> std::uint8_t { return _bytes[i]; }

    /// Wipes the contents and leaves the buffer empty.
    void wipe() noexcept {
        if (!_bytes.empty()) {
            OPENSSL_cleanse(_bytes.data(), _bytes.size());
            _bytes.clear();
        }
    }

private:
    std::vector<std::uint8_t, secure_allocator<std::uint8_t>> _bytes;
};

/// Constant-time equality of two byte strings of the same length; strings of
/// different lengths compare unequal (their lengths are not secret).
[[nodiscard]] inline auto constant_time_equal(std::span<const std::uint8_t> a,
                                              std::span<const std::uint8_t> b) noexcept -> bool {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace kythira::hsm
