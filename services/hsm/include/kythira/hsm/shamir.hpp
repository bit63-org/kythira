// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Shamir secret sharing of the HSM master key over GF(2^8)
// (.kiro/specs/virtual-hsm/ Requirements 4.1, 4.2 and 13.1; design, "Shamir
// over the MK only").
//
// The secret is split byte by byte: for each byte a random polynomial of
// degree k - 1 whose constant term is that byte is evaluated at x = 1..n,
// and share i holds the n-th evaluations at x = i. Any k shares rebuild the
// secret by Lagrange interpolation at x = 0; k - 1 shares are consistent
// with every possible secret, one completion each, so they say nothing
// about it. The field is GF(2^8) with the AES polynomial x^8 + x^4 + x^3 +
// x + 1, and multiplication and inversion are branch- and table-free, so
// their timing does not depend on share or secret bytes.
//
// A share is
//
//     version (1) | k (1) | n (1) | index (1) | length (2, big-endian)
//     | bytes (length) | check value (8) | checksum (4)
//
// where the check value is the first 8 bytes of
// HMAC-SHA256(secret, "kythira-hsm master key check v1"), the same in every
// share of one split, and the checksum is the first 4 bytes of SHA-256 over
// everything before it. The checksum catches a mistyped or truncated share;
// the check value catches a share from another split (or another master
// key) and, after combination, confirms the rebuilt secret. It is an HMAC
// rather than PKCS#11's encrypt-a-zero-block check value so that it is not
// a known plaintext under the master key. Shares are handed out as text,
// "khs1-" followed by the share's bytes in lowercase hex; parsing ignores
// whitespace and case.
//
// Everything that could be secret lives in secret_bytes and is wiped when
// dropped. Randomness comes from OpenSSL's RAND_bytes unless a test passes
// its own source.

#include <kythira/hsm/secret_bytes.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <kythira/hsm/expected.hpp>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm {

// -- GF(2^8) -------------------------------------------------------------------

namespace gf256 {

/// a * b in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, in constant time.
[[nodiscard]] constexpr auto mul(std::uint8_t a, std::uint8_t b) noexcept -> std::uint8_t {
    unsigned p = 0;
    unsigned x = a;
    unsigned y = b;
    for (int i = 0; i < 8; ++i) {
        p ^= x & (0U - (y & 1U));
        const unsigned carry = 0U - ((x >> 7U) & 1U);
        x = ((x << 1U) ^ (0x1BU & carry)) & 0xFFU;
        y >>= 1U;
    }
    return static_cast<std::uint8_t>(p);
}

/// a^-1 in GF(2^8) as a^254 (Fermat), in constant time; inv(0) is 0.
[[nodiscard]] constexpr auto inv(std::uint8_t a) noexcept -> std::uint8_t {
    // 254 = 0b11111110: square-and-multiply with a fixed sequence.
    std::uint8_t a2 = mul(a, a);    // a^2
    std::uint8_t r = a2;            // a^2
    std::uint8_t sq = mul(a2, a2);  // a^4
    for (int i = 0; i < 6; ++i) {   // a^4, a^8, ..., a^128
        r = mul(r, sq);
        sq = mul(sq, sq);
    }
    return r;  // a^(2+4+...+128) = a^254
}

}  // namespace gf256

// -- Shares ------------------------------------------------------------------

/// Why a split, a share or a combination was refused. Each has a message
/// (shamir_error_message) an operator can act on.
enum class shamir_error {
    bad_parameters,        ///< k or n out of range, or an empty secret
    bad_encoding,          ///< not "khs1-" and hex, or the wrong length
    unsupported_version,   ///< a share format this build does not read
    bad_checksum,          ///< mistyped, truncated or corrupted
    bad_index,             ///< index 0 or above n
    mixed_shares,          ///< shares from different splits
    duplicate_index,       ///< the same share given twice
    not_enough_shares,     ///< fewer than k distinct shares
    check_value_mismatch,  ///< the shares rebuild a secret that fails the check
};

[[nodiscard]] inline auto shamir_error_message(shamir_error e) -> std::string_view {
    switch (e) {
        case shamir_error::bad_parameters:
            return "threshold and share count must satisfy 1 <= k <= n <= 16 (k >= 2 unless "
                   "single-share development mode is allowed), and the secret must not be empty";
        case shamir_error::bad_encoding:
            return "not a share: expected \"khs1-\" followed by hex digits of the right length";
        case shamir_error::unsupported_version:
            return "share format version not supported by this build";
        case shamir_error::bad_checksum:
            return "share checksum does not match: the share was mistyped, truncated or corrupted";
        case shamir_error::bad_index:
            return "share index is 0 or greater than the share count";
        case shamir_error::mixed_shares:
            return "shares come from different splits (threshold, count, length or master key "
                   "check value differ)";
        case shamir_error::duplicate_index:
            return "the same share was given more than once";
        case shamir_error::not_enough_shares:
            return "fewer distinct shares than the threshold";
        case shamir_error::check_value_mismatch:
            return "the shares do not rebuild the master key they were split from";
    }
    return "unknown share error";
}

/// One share of a split, decoded.
struct shamir_share {
    static constexpr std::uint8_t format_version = 1;

    std::uint8_t version = format_version;
    std::uint8_t k = 0;
    std::uint8_t n = 0;
    std::uint8_t index = 0;
    secret_bytes bytes;
    std::array<std::uint8_t, 8> check_value{};
};

/// Limits from Requirement 4.1.
inline constexpr unsigned shamir_max_shares = 16;
/// The longest secret a share can carry (the length field is 16 bits).
inline constexpr std::size_t shamir_max_secret = 0xFFFF;

/// Where split() gets its randomness: fills the span or throws.
using random_source = std::function<void(std::span<std::uint8_t>)>;

/// RAND_bytes, throwing if OpenSSL's generator fails.
inline void openssl_random(std::span<std::uint8_t> out) {
    if (out.empty()) {
        return;
    }
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("shamir: RAND_bytes failed");
    }
}

namespace shamir_detail {

inline constexpr std::string_view text_prefix = "khs1-";
inline constexpr std::string_view check_label = "kythira-hsm master key check v1";
inline constexpr std::size_t header_size = 6;
inline constexpr std::size_t checksum_size = 4;

[[nodiscard]] inline auto check_value_of(std::span<const std::uint8_t> secret)
    -> std::array<std::uint8_t, 8> {
    std::array<std::uint8_t, 32> mac{};
    std::size_t mac_len = 0;
    if (EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, secret.data(), secret.size(),
                  reinterpret_cast<const unsigned char*>(check_label.data()), check_label.size(),
                  mac.data(), mac.size(), &mac_len) == nullptr ||
        mac_len != mac.size()) {
        throw std::runtime_error("shamir: HMAC-SHA256 failed");
    }
    std::array<std::uint8_t, 8> out{};
    std::copy_n(mac.begin(), out.size(), out.begin());
    OPENSSL_cleanse(mac.data(), mac.size());
    return out;
}

[[nodiscard]] inline auto checksum_of(std::span<const std::uint8_t> body)
    -> std::array<std::uint8_t, checksum_size> {
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
    unsigned digest_len = 0;
    if (EVP_Digest(body.data(), body.size(), digest.data(), &digest_len, EVP_sha256(), nullptr) !=
        1) {
        throw std::runtime_error("shamir: SHA-256 failed");
    }
    std::array<std::uint8_t, checksum_size> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    return out;
}

[[nodiscard]] inline auto valid_parameters(unsigned k, unsigned n, std::size_t length,
                                           bool allow_single) -> bool {
    return length > 0 && length <= shamir_max_secret && k >= 1 && k <= n &&
           n <= shamir_max_shares && (k >= 2 || allow_single);
}

}  // namespace shamir_detail

/// Splits `secret` into n shares with threshold k. `allow_single` permits
/// k = 1, which Requirement 4.1 keeps behind an explicit development flag.
[[nodiscard]] inline auto shamir_split(std::span<const std::uint8_t> secret, unsigned k, unsigned n,
                                       bool allow_single = false,
                                       const random_source& random = openssl_random)
    -> expected<std::vector<shamir_share>, shamir_error> {
    if (!shamir_detail::valid_parameters(k, n, secret.size(), allow_single)) {
        return unexpected(shamir_error::bad_parameters);
    }
    const auto check = shamir_detail::check_value_of(secret);
    // Coefficients a_1..a_{k-1} for every byte, row c holding a_c.
    secret_bytes coefficients((k - 1) * secret.size());
    random(coefficients.span());

    std::vector<shamir_share> shares;
    shares.reserve(n);
    for (unsigned i = 1; i <= n; ++i) {
        shamir_share s;
        s.k = static_cast<std::uint8_t>(k);
        s.n = static_cast<std::uint8_t>(n);
        s.index = static_cast<std::uint8_t>(i);
        s.check_value = check;
        s.bytes = secret_bytes(secret.size());
        const auto x = static_cast<std::uint8_t>(i);
        for (std::size_t j = 0; j < secret.size(); ++j) {
            // Horner: ((a_{k-1} x + a_{k-2}) x + ...) x + a_0.
            std::uint8_t y = 0;
            for (unsigned c = k - 1; c >= 1; --c) {
                y = gf256::mul(y, x) ^ coefficients[((c - 1) * secret.size()) + j];
            }
            s.bytes[j] = gf256::mul(y, x) ^ secret[j];
        }
        shares.push_back(std::move(s));
    }
    return shares;
}

/// Rebuilds the secret from at least k distinct shares of one split. Every
/// share's fields are checked before any arithmetic; the result must match
/// the shares' check value.
[[nodiscard]] inline auto shamir_combine(std::span<const shamir_share> shares)
    -> expected<secret_bytes, shamir_error> {
    if (shares.empty()) {
        return unexpected(shamir_error::not_enough_shares);
    }
    const auto& first = shares.front();
    for (const auto& s : shares) {
        if (s.version != shamir_share::format_version) {
            return unexpected(shamir_error::unsupported_version);
        }
        if (!shamir_detail::valid_parameters(s.k, s.n, s.bytes.size(), true)) {
            return unexpected(shamir_error::bad_parameters);
        }
        if (s.index == 0 || s.index > s.n) {
            return unexpected(shamir_error::bad_index);
        }
        if (s.k != first.k || s.n != first.n || s.bytes.size() != first.bytes.size() ||
            s.check_value != first.check_value) {
            return unexpected(shamir_error::mixed_shares);
        }
    }
    // The first k distinct indexes; a repeated index is refused rather than
    // skipped, since it means an operator entered the same share twice.
    std::vector<const shamir_share*> chosen;
    std::array<bool, 256> seen{};
    for (const auto& s : shares) {
        if (seen[s.index]) {
            return unexpected(shamir_error::duplicate_index);
        }
        seen[s.index] = true;
        if (chosen.size() < first.k) {
            chosen.push_back(&s);
        }
    }
    if (chosen.size() < first.k) {
        return unexpected(shamir_error::not_enough_shares);
    }

    // Lagrange at 0: s = sum_i y_i * prod_{m != i} x_m / (x_m - x_i); in
    // GF(2^8) subtraction is xor.
    secret_bytes out(first.bytes.size());
    for (std::size_t i = 0; i < chosen.size(); ++i) {
        std::uint8_t num = 1;
        std::uint8_t den = 1;
        for (std::size_t m = 0; m < chosen.size(); ++m) {
            if (m == i) {
                continue;
            }
            num = gf256::mul(num, chosen[m]->index);
            den = gf256::mul(den, chosen[m]->index ^ chosen[i]->index);
        }
        const std::uint8_t basis = gf256::mul(num, gf256::inv(den));
        for (std::size_t j = 0; j < out.size(); ++j) {
            out[j] ^= gf256::mul(chosen[i]->bytes[j], basis);
        }
    }
    const auto check = shamir_detail::check_value_of(out.view());
    if (!constant_time_equal(check, first.check_value)) {
        return unexpected(shamir_error::check_value_mismatch);
    }
    return out;
}

/// The share's binary form (see the header comment), checksum included.
[[nodiscard]] inline auto shamir_encode_binary(const shamir_share& s) -> secret_bytes {
    const std::size_t len = s.bytes.size();
    secret_bytes out(shamir_detail::header_size + len + s.check_value.size() +
                     shamir_detail::checksum_size);
    out[0] = s.version;
    out[1] = s.k;
    out[2] = s.n;
    out[3] = s.index;
    out[4] = static_cast<std::uint8_t>((len >> 8U) & 0xFFU);
    out[5] = static_cast<std::uint8_t>(len & 0xFFU);
    std::size_t at = shamir_detail::header_size;
    for (std::size_t j = 0; j < len; ++j) {
        out[at++] = s.bytes[j];
    }
    for (const auto b : s.check_value) {
        out[at++] = b;
    }
    const auto sum = shamir_detail::checksum_of(out.view().first(at));
    for (const auto b : sum) {
        out[at++] = b;
    }
    return out;
}

/// Decodes and verifies a share's binary form. The checksum is checked
/// before any field is trusted.
[[nodiscard]] inline auto shamir_decode_binary(std::span<const std::uint8_t> in)
    -> expected<shamir_share, shamir_error> {
    constexpr std::size_t fixed = shamir_detail::header_size + 8 + shamir_detail::checksum_size;
    if (in.size() < fixed) {
        return unexpected(shamir_error::bad_encoding);
    }
    const std::size_t len = (static_cast<std::size_t>(in[4]) << 8U) | in[5];
    if (in.size() != fixed + len) {
        // A length that disagrees with the size is as likely a typo in the
        // length bytes as a truncation; the checksum would fail either way.
        return unexpected(shamir_error::bad_checksum);
    }
    const auto body = in.first(in.size() - shamir_detail::checksum_size);
    const auto sum = shamir_detail::checksum_of(body);
    if (!constant_time_equal(sum, in.last(shamir_detail::checksum_size))) {
        return unexpected(shamir_error::bad_checksum);
    }
    if (in[0] != shamir_share::format_version) {
        return unexpected(shamir_error::unsupported_version);
    }
    shamir_share s;
    s.version = in[0];
    s.k = in[1];
    s.n = in[2];
    s.index = in[3];
    if (!shamir_detail::valid_parameters(s.k, s.n, len, true)) {
        return unexpected(shamir_error::bad_parameters);
    }
    if (s.index == 0 || s.index > s.n) {
        return unexpected(shamir_error::bad_index);
    }
    s.bytes = secret_bytes(in.subspan(shamir_detail::header_size, len));
    std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(shamir_detail::header_size + len),
                s.check_value.size(), s.check_value.begin());
    return s;
}

/// "khs1-" and the binary form in lowercase hex. The string is the share:
/// the caller wipes it when done.
[[nodiscard]] inline auto shamir_encode_text(const shamir_share& s) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    const auto bin = shamir_encode_binary(s);
    std::string out(shamir_detail::text_prefix);
    out.reserve(out.size() + (2 * bin.size()));
    for (const auto b : bin.view()) {
        out.push_back(digits[b >> 4U]);
        out.push_back(digits[b & 0x0FU]);
    }
    return out;
}

/// Parses a share's text form. Whitespace anywhere and the case of the
/// prefix and digits are ignored, so a share read back from paper or split
/// across lines still parses.
[[nodiscard]] inline auto shamir_decode_text(std::string_view text)
    -> expected<shamir_share, shamir_error> {
    std::string compact;
    compact.reserve(text.size());
    for (const char c : text) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        compact.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c));
    }
    auto wipe_compact = [&compact] { OPENSSL_cleanse(compact.data(), compact.size()); };
    const auto prefix = shamir_detail::text_prefix;
    if (compact.size() < prefix.size() ||
        std::string_view(compact).substr(0, prefix.size()) != prefix ||
        (compact.size() - prefix.size()) % 2 != 0) {
        wipe_compact();
        return unexpected(shamir_error::bad_encoding);
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return -1;
    };
    secret_bytes bin((compact.size() - prefix.size()) / 2);
    for (std::size_t i = 0; i < bin.size(); ++i) {
        const int hi = nibble(compact[prefix.size() + (2 * i)]);
        const int lo = nibble(compact[prefix.size() + (2 * i) + 1]);
        if (hi < 0 || lo < 0) {
            wipe_compact();
            return unexpected(shamir_error::bad_encoding);
        }
        bin[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    wipe_compact();
    return shamir_decode_binary(bin.view());
}

}  // namespace kythira::hsm
