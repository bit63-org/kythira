// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_float128.hpp
/// IEEE binary128 arithmetic for `INCRBYFLOAT` and `HINCRBYFLOAT`, with one
/// decimal parser and one formatter used on every architecture
/// (.kiro/specs/redis-general-data-types/ design "Float increments", D1).
///
/// Redis computes these increments in `long double`: 80-bit x87 on amd64,
/// IEEE binary128 on arm64 Linux. A Raft group may mix both, and every
/// replica must store the same bytes, so Kythira computes in binary128
/// everywhere: `long double` on aarch64, `__float128` on x86-64. Addition is
/// the platform's IEEE correctly rounded operation, so `a + b` gives the same
/// bits on both.
///
/// Conversions do not use `strtold`, `printf` or libquadmath, which would be
/// two implementations: `parse_redis_float128` is a correctly rounded
/// (round-half-even) decimal-to-binary128 parser, and
/// `format_redis_float128` prints Redis's `ld2string` human form, `%.17Lf`
/// with trailing zeros (and a trailing `.`) removed and `-0` printed as `0`,
/// from the exact binary value. Both work on the significand with exact
/// big-integer arithmetic.
///
/// What the parser accepts follows Redis's `string2ld` over glibc's
/// `strtold` for decimal input: an optional sign, digits with an optional
/// `.` and fraction, an optional exponent, or `inf`/`infinity`; no leading
/// space, nothing after the number, no NaN, and no result that overflows to
/// infinity or underflows to zero. Hexadecimal floats, which `strtold` also
/// reads, are refused.

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

namespace kythira {

#if defined(__aarch64__) && defined(__linux__)
using redis_float128_native = long double;
#elif (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
using redis_float128_native = __float128;
#else
#error "redis_float128.hpp needs an IEEE binary128 type (aarch64 long double or x86 __float128)"
#endif

static_assert(sizeof(redis_float128_native) == 16, "binary128 is 16 bytes");

namespace redis_float128_detail {

using u128 = unsigned __int128;

inline constexpr int k_mantissa_bits = 112;  // stored fraction bits
inline constexpr int k_precision = 113;      // with the implicit bit
inline constexpr int k_exponent_bias = 16383;
inline constexpr int k_max_exponent = 16383;   // largest unbiased exponent of a finite value
inline constexpr int k_min_exponent = -16382;  // smallest normal exponent

/// Little-endian magnitude in 32-bit limbs.
class big {
public:
    big() = default;
    explicit big(u128 v) {
        while (v != 0) {
            _l.push_back(static_cast<std::uint32_t>(v));
            v >>= 32U;
        }
    }

    [[nodiscard]] auto is_zero() const noexcept -> bool { return _l.empty(); }

    [[nodiscard]] auto bit_length() const noexcept -> int {
        if (_l.empty()) {
            return 0;
        }
        return static_cast<int>((_l.size() - 1) * 32) + std::bit_width(_l.back());
    }

    [[nodiscard]] auto bit(int i) const noexcept -> bool {
        const auto limb = static_cast<std::size_t>(i) / 32;
        return limb < _l.size() && ((_l[limb] >> (static_cast<unsigned>(i) % 32U)) & 1U) != 0;
    }

    /// True when any bit below `i` is set.
    [[nodiscard]] auto any_below(int i) const noexcept -> bool {
        const auto whole = std::min(static_cast<std::size_t>(i) / 32, _l.size());
        for (std::size_t k = 0; k < whole; ++k) {
            if (_l[k] != 0) {
                return true;
            }
        }
        const auto rest = static_cast<unsigned>(i) % 32U;
        return whole < _l.size() && rest != 0 && (_l[whole] & ((1U << rest) - 1U)) != 0;
    }

    /// Bits [i, i + n) as an integer, n <= 128.
    [[nodiscard]] auto bits(int i, int n) const noexcept -> u128 {
        u128 v = 0;
        for (int k = n - 1; k >= 0; --k) {
            v = (v << 1U) | static_cast<u128>(bit(i + k) ? 1 : 0);
        }
        return v;
    }

    auto mul_small(std::uint32_t m) -> void {
        std::uint64_t carry = 0;
        for (auto& limb : _l) {
            const std::uint64_t p = (static_cast<std::uint64_t>(limb) * m) + carry;
            limb = static_cast<std::uint32_t>(p);
            carry = p >> 32U;
        }
        if (carry != 0) {
            _l.push_back(static_cast<std::uint32_t>(carry));
        }
    }

    auto add_small(std::uint32_t a) -> void {
        std::uint64_t carry = a;
        for (auto& limb : _l) {
            if (carry == 0) {
                return;
            }
            const std::uint64_t s = static_cast<std::uint64_t>(limb) + carry;
            limb = static_cast<std::uint32_t>(s);
            carry = s >> 32U;
        }
        if (carry != 0) {
            _l.push_back(static_cast<std::uint32_t>(carry));
        }
    }

    /// Divides in place; returns the remainder.
    auto div_small(std::uint32_t d) -> std::uint32_t {
        std::uint64_t rem = 0;
        for (auto& limb : std::ranges::reverse_view(_l)) {
            const std::uint64_t cur = (rem << 32U) | limb;
            limb = static_cast<std::uint32_t>(cur / d);
            rem = cur % d;
        }
        trim();
        return static_cast<std::uint32_t>(rem);
    }

    auto shift_left(int n) -> void {
        if (_l.empty() || n == 0) {
            return;
        }
        const auto limbs = static_cast<std::size_t>(n) / 32;
        const auto rest = static_cast<unsigned>(n) % 32U;
        if (rest != 0) {
            std::uint32_t carry = 0;
            for (auto& limb : _l) {
                const auto next = limb >> (32U - rest);
                limb = (limb << rest) | carry;
                carry = next;
            }
            if (carry != 0) {
                _l.push_back(carry);
            }
        }
        _l.insert(_l.begin(), limbs, 0U);
    }

    auto shift_right(int n) -> void {
        const auto limbs = static_cast<std::size_t>(n) / 32;
        if (limbs >= _l.size()) {
            _l.clear();
            return;
        }
        _l.erase(_l.begin(), _l.begin() + static_cast<std::ptrdiff_t>(limbs));
        const auto rest = static_cast<unsigned>(n) % 32U;
        if (rest != 0) {
            for (std::size_t k = 0; k < _l.size(); ++k) {
                const std::uint32_t hi = k + 1 < _l.size() ? _l[k + 1] << (32U - rest) : 0U;
                _l[k] = (_l[k] >> rest) | hi;
            }
        }
        trim();
    }

    /// `*this / d`, with `*this % d` left in `rem`. Schoolbook long division
    /// one bit at a time: slow, but the operands are a few thousand bits at
    /// most and only on the parse path.
    [[nodiscard]] auto div(const big& d, big& rem) const -> big {
        big q;
        rem = big{};
        for (int i = bit_length() - 1; i >= 0; --i) {
            rem.shift_left(1);
            if (bit(i)) {
                if (rem._l.empty()) {
                    rem._l.push_back(1);
                } else {
                    rem._l[0] |= 1U;
                }
            }
            if (rem.compare(d) >= 0) {
                rem.sub(d);
                q.set_bit(i);
            }
        }
        q.trim();
        return q;
    }

    [[nodiscard]] auto compare(const big& o) const noexcept -> int {
        if (_l.size() != o._l.size()) {
            return _l.size() < o._l.size() ? -1 : 1;
        }
        for (std::size_t k = _l.size(); k-- > 0;) {
            if (_l[k] != o._l[k]) {
                return _l[k] < o._l[k] ? -1 : 1;
            }
        }
        return 0;
    }

    /// Decimal digits, most significant first ("0" for zero).
    [[nodiscard]] auto decimal() const -> std::string {
        if (_l.empty()) {
            return "0";
        }
        big v = *this;
        std::string out;
        while (!v.is_zero()) {
            auto chunk = v.div_small(1000000000U);
            for (int k = 0; k < 9; ++k) {
                out.push_back(static_cast<char>('0' + (chunk % 10)));
                chunk /= 10;
                if (v.is_zero() && chunk == 0) {
                    break;
                }
            }
        }
        while (out.size() > 1 && out.back() == '0') {
            out.pop_back();
        }
        std::reverse(out.begin(), out.end());
        return out;
    }

private:
    auto set_bit(int i) -> void {
        const auto limb = static_cast<std::size_t>(i) / 32;
        if (_l.size() <= limb) {
            _l.resize(limb + 1, 0U);
        }
        _l[limb] |= 1U << (static_cast<unsigned>(i) % 32U);
    }

    /// `*this -= o`, with `*this >= o`.
    auto sub(const big& o) -> void {
        std::int64_t borrow = 0;
        for (std::size_t k = 0; k < _l.size(); ++k) {
            std::int64_t d = static_cast<std::int64_t>(_l[k]) - borrow -
                             (k < o._l.size() ? static_cast<std::int64_t>(o._l[k]) : 0);
            borrow = d < 0 ? 1 : 0;
            if (d < 0) {
                d += std::int64_t{1} << 32;
            }
            _l[k] = static_cast<std::uint32_t>(d);
        }
        trim();
    }

    auto trim() -> void {
        while (!_l.empty() && _l.back() == 0) {
            _l.pop_back();
        }
    }

    std::vector<std::uint32_t> _l;
};

[[nodiscard]] inline auto pow10(int n) -> big {
    big v(1);
    for (; n >= 9; n -= 9) {
        v.mul_small(1000000000U);
    }
    for (; n > 0; --n) {
        v.mul_small(10U);
    }
    return v;
}

[[nodiscard]] inline auto to_bits(redis_float128_native v) noexcept -> u128 {
    u128 b = 0;
    std::memcpy(&b, &v, sizeof b);
    return b;
}

[[nodiscard]] inline auto from_bits(u128 b) noexcept -> redis_float128_native {
    redis_float128_native v{};
    std::memcpy(&v, &b, sizeof b);
    return v;
}

inline constexpr u128 k_fraction_mask = (static_cast<u128>(1) << k_mantissa_bits) - 1;

/// Rounds `n * 2^scale` (n > 0) to binary128, round half to even. Returns
/// the bits without a sign, or nullopt when it overflows to infinity or
/// underflows to zero (`string2ld` refuses both).
[[nodiscard]] inline auto round_to_binary128(const big& n, int scale) -> std::optional<u128> {
    const int len = n.bit_length();
    int exponent = len - 1 + scale;  // of the leading bit
    // How many of n's bits the result keeps: 113 for a normal number, fewer
    // for a subnormal one.
    int keep = k_precision;
    if (exponent < k_min_exponent) {
        keep = k_precision - (k_min_exponent - exponent);
        if (keep < 0) {
            return std::nullopt;  // below half the smallest subnormal
        }
    }
    const int drop = len - keep;  // low bits of n rounded away (may be negative)
    u128 m = 0;
    if (drop <= 0) {
        m = n.bits(0, len) << static_cast<unsigned>(-drop);
    } else {
        m = n.bits(drop, keep);
        const bool half = n.bit(drop - 1);
        const bool sticky = n.any_below(drop - 1);
        if (half && (sticky || (m & 1U) != 0)) {
            ++m;
        }
    }
    if (exponent < k_min_exponent) {
        // Subnormal: m holds `keep` bits; a carry may make it the smallest
        // normal, which the encoding below handles by the implicit bit.
        if (m == 0) {
            return std::nullopt;
        }
        return m;  // biased exponent 0 (or 1 after a carry into bit 112)
    }
    if (m >> static_cast<unsigned>(k_precision) != 0) {  // carry out of the top
        m >>= 1U;
        ++exponent;
    }
    if (exponent > k_max_exponent) {
        return std::nullopt;
    }
    const auto biased = static_cast<u128>(static_cast<unsigned>(exponent + k_exponent_bias));
    return (biased << static_cast<unsigned>(k_mantissa_bits)) | (m & k_fraction_mask);
}

}  // namespace redis_float128_detail

/// The decimal (or `inf`) text as binary128, or nullopt when `string2ld`
/// would refuse it.
[[nodiscard]] inline auto parse_redis_float128(std::string_view s)
    -> std::optional<redis_float128_native> {
    using namespace redis_float128_detail;
    if (s.empty() || s.size() >= 5 * 1024) {
        return std::nullopt;
    }
    std::size_t i = 0;
    bool negative = false;
    if (s[i] == '+' || s[i] == '-') {
        negative = s[i] == '-';
        ++i;
    }
    auto lower_rest = std::string(s.substr(i));
    for (auto& c : lower_rest) {
        c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    if (lower_rest == "inf" || lower_rest == "infinity") {
        constexpr u128 inf = static_cast<u128>(0x7FFF) << static_cast<unsigned>(k_mantissa_bits);
        const u128 sign = negative ? static_cast<u128>(1) << 127U : 0;
        return from_bits(inf | sign);
    }
    big digits;
    int exp10 = 0;
    bool any_digit = false;
    bool nonzero = false;
    for (; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i) {
        any_digit = true;
        nonzero = nonzero || s[i] != '0';
        digits.mul_small(10);
        digits.add_small(static_cast<std::uint32_t>(s[i] - '0'));
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        for (; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i) {
            any_digit = true;
            nonzero = nonzero || s[i] != '0';
            digits.mul_small(10);
            digits.add_small(static_cast<std::uint32_t>(s[i] - '0'));
            --exp10;
        }
    }
    if (!any_digit) {
        return std::nullopt;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        bool eneg = false;
        if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
            eneg = s[i] == '-';
            ++i;
        }
        if (i >= s.size()) {
            return std::nullopt;
        }
        long e = 0;
        for (; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i) {
            e = std::min<long>((e * 10) + (s[i] - '0'), 1000000);
        }
        exp10 += static_cast<int>(eneg ? -e : e);
    }
    if (i != s.size()) {
        return std::nullopt;
    }
    const u128 sign = negative ? static_cast<u128>(1) << 127U : 0;
    if (!nonzero) {
        return from_bits(sign);  // an exact zero, no ERANGE
    }
    // Far outside binary128's range either way (|x| < 2^-16494 or > 2^16384).
    const int magnitude = exp10 + static_cast<int>(digits.decimal().size());
    if (magnitude > 4934) {
        return std::nullopt;
    }
    if (magnitude < -4966) {
        return std::nullopt;
    }
    std::optional<u128> bits;
    if (exp10 >= 0) {
        big n = digits;
        for (int k = exp10; k >= 9; k -= 9) {
            n.mul_small(1000000000U);
        }
        for (int k = exp10 % 9; k > 0; --k) {
            n.mul_small(10U);
        }
        bits = round_to_binary128(n, 0);
    } else {
        // digits / 10^-e: scale the numerator so the quotient has at least
        // 113 + 2 bits, then fold the remainder into the sticky bit.
        const big denominator = pow10(-exp10);
        int shift = std::max(0, denominator.bit_length() - digits.bit_length() + k_precision + 2);
        big numerator = digits;
        numerator.shift_left(shift);
        big rem;
        big q = numerator.div(denominator, rem);
        if (!rem.is_zero()) {
            // A sticky bit below every kept bit.
            q.shift_left(1);
            q.add_small(1);
            ++shift;
        }
        bits = round_to_binary128(q, -shift);
    }
    if (!bits) {
        return std::nullopt;
    }
    return from_bits(*bits | sign);
}

/// Redis's `ld2string(..., LD_STR_HUMAN)`: `%.17Lf` with trailing zeros and a
/// trailing decimal point removed, and `-0` printed as `0`. `v` must be finite.
[[nodiscard]] inline auto format_redis_float128(redis_float128_native v) -> std::string {
    using namespace redis_float128_detail;
    const u128 b = to_bits(v);
    const bool negative = (b >> 127U) != 0;
    const int biased = static_cast<int>((b >> static_cast<unsigned>(k_mantissa_bits)) & 0x7FFFU);
    u128 m = b & k_fraction_mask;
    int e2 = 0;  // value = m * 2^e2
    if (biased == 0) {
        e2 = k_min_exponent - k_mantissa_bits;
    } else {
        m |= static_cast<u128>(1) << static_cast<unsigned>(k_mantissa_bits);
        e2 = biased - k_exponent_bias - k_mantissa_bits;
    }
    // q = round_half_even(|v| * 10^17)
    big q(m);
    for (int k = 0; k < 17; ++k) {
        q.mul_small(10);
    }
    if (e2 >= 0) {
        q.shift_left(e2);
    } else {
        const int s = -e2;
        const bool half = q.bit(s - 1);
        const bool sticky = q.any_below(s - 1);
        big shifted = q;
        shifted.shift_right(s);
        const bool odd = shifted.bit(0);
        if (half && (sticky || odd)) {
            shifted.add_small(1);
        }
        q = shifted;
    }
    std::string digits = q.decimal();
    if (digits.size() < 18) {
        digits.insert(0, 18 - digits.size(), '0');
    }
    std::string out = digits.substr(0, digits.size() - 17);
    std::string frac = digits.substr(digits.size() - 17);
    while (!frac.empty() && frac.back() == '0') {
        frac.pop_back();
    }
    if (!frac.empty()) {
        out += '.';
        out += frac;
    }
    if (negative && out != "0") {
        out.insert(0, 1, '-');
    }
    return out;
}

/// True for a finite value (not infinity or NaN).
[[nodiscard]] inline auto is_finite_redis_float128(redis_float128_native v) noexcept -> bool {
    using namespace redis_float128_detail;
    const auto biased =
        static_cast<int>((to_bits(v) >> static_cast<unsigned>(k_mantissa_bits)) & 0x7FFFU);
    return biased != 0x7FFF;
}

}  // namespace kythira
