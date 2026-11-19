// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Lua's number-to-string conversion (lua_number2str in luaconf.h, as
// patched by 0001-deterministic-numbers.patch). Stock Lua calls
// sprintf("%.14g"), whose output depends on the C library and on the
// process locale's decimal point. std::to_chars with chars_format::general
// and precision 14 is specified to produce exactly what printf("%.14g")
// produces in the C locale, from the correctly rounded decimal value, so
// the text matches Redis's while depending on neither. NaN is the one
// deliberate difference: every NaN prints "nan". x86-64 makes 0/0 a NaN
// with the sign bit set ("-nan" from glibc), arm64 makes it positive, and
// a replicated script must print the same thing on both.

#include <charconv>
#include <cmath>
#include <cstring>
#include <system_error>

extern "C" int kythira_lua_number2str(char* s, double n) {
    if (std::isnan(n)) {
        std::memcpy(s, "nan", 4);
        return 3;
    }
    // LUAI_MAXNUMBER2STR is 32: the longest %.14g text is 21 characters
    // ("-1.2345678901234e-308"), plus the terminator.
    constexpr int buffer_size = 32;
    auto [end, ec] = std::to_chars(s, s + buffer_size - 1, n, std::chars_format::general, 14);
    if (ec != std::errc{}) {
        // Cannot happen with this precision and buffer; keep the string valid.
        std::memcpy(s, "nan", 4);
        return 3;
    }
    *end = '\0';
    return static_cast<int>(end - s);
}
