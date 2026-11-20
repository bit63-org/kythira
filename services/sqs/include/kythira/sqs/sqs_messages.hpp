// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_messages.hpp
/// @brief Message bodies and attributes as SQS checks, digests and stores
///        them (`.kiro/specs/sqs-compatible-queues/` Requirement 5.3).
///
/// MD5 digests are what SDKs recompute and compare (the Java SDK checks all
/// three; task 1 evidence), so they follow SQS exactly:
///
///  - `MD5OfMessageBody`: MD5 of the body's UTF-8 bytes, lower-case hex.
///  - `MD5OfMessageAttributes` and `MD5OfMessageSystemAttributes`: for each
///    attribute, sorted by name, the name, the data type and the value, each
///    as a 4-byte big-endian length and its bytes, with a transport byte (1
///    for String and Number, 2 for Binary) before the value. Absent when
///    there are no attributes. List values (`StringListValues`,
///    `BinaryListValues`) are reserved by SQS and refused here, so they
///    never reach a digest.
///
/// The checks are SQS's documented ones: at most 10 attributes; names of
/// at most 256 characters from `[A-Za-z0-9_.-]`, not starting with `AWS.`
/// or `Amazon.` (any case), with no leading, trailing or doubled period;
/// data types `String`, `Number` or `Binary` with an optional `.custom`
/// suffix, 256 characters in all; a non-empty value of the right kind;
/// numbers of at most 38 significant digits between -10^128 and 10^126;
/// bodies only of the characters XML 1.0 allows (`InvalidMessageContents`
/// otherwise). The only system attribute is `AWSTraceHeader`, a String.
/// The size a message counts against `MaximumMessageSize` is its body plus
/// every attribute's name, data type and value. Error texts are this
/// file's own until task 13 records SQS's.
///
/// Attributes are stored with the message as the JSON object of the
/// request (`encode_attributes`), so a receive returns exactly what was
/// sent; the state machine treats them as opaque bytes.

#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>

#include <openssl/evp.h>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

inline constexpr std::size_t k_max_message_attributes = 10;
inline constexpr std::size_t k_max_attribute_name = 256;
inline constexpr std::size_t k_max_attribute_type = 256;

/// Lower-case hex MD5 of `bytes`.
[[nodiscard]] inline auto md5_hex(std::string_view bytes) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &len, EVP_md5(), nullptr) != 1) {
        return {};
    }
    static constexpr std::string_view k_hex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned i = 0; i < len; ++i) {
        out += k_hex[digest.at(i) >> 4U];
        out += k_hex[digest.at(i) & 0xFU];
    }
    return out;
}

namespace message_detail {

[[nodiscard]] inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// The base type of a data type (`Number` of `Number.float`).
[[nodiscard]] inline auto base_type(std::string_view data_type) -> std::string_view {
    return data_type.substr(0, data_type.find('.'));
}

inline void put_field(std::string& out, std::string_view bytes) {
    const auto n = static_cast<std::uint32_t>(bytes.size());
    out += static_cast<char>((n >> 24U) & 0xFFU);
    out += static_cast<char>((n >> 16U) & 0xFFU);
    out += static_cast<char>((n >> 8U) & 0xFFU);
    out += static_cast<char>(n & 0xFFU);
    out += bytes;
}

[[nodiscard]] inline auto bad_attribute(std::string_view text) -> aws_json::error {
    return make_error(k_validation_error, std::string(text));
}

/// The code points of `s` when it is well-formed UTF-8.
[[nodiscard]] inline auto code_points(std::string_view s) -> std::optional<std::vector<char32_t>> {
    std::vector<char32_t> out;
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        char32_t cp = 0;
        std::size_t len = 0;
        if (c < 0x80U) {
            cp = c;
            len = 1;
        } else if ((c & 0xE0U) == 0xC0U) {
            cp = c & 0x1FU;
            len = 2;
        } else if ((c & 0xF0U) == 0xE0U) {
            cp = c & 0x0FU;
            len = 3;
        } else if ((c & 0xF8U) == 0xF0U) {
            cp = c & 0x07U;
            len = 4;
        } else {
            return std::nullopt;
        }
        if (i + len > s.size()) {
            return std::nullopt;
        }
        for (std::size_t k = 1; k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0U) != 0x80U) {
                return std::nullopt;
            }
            cp = (cp << 6U) | (cc & 0x3FU);
        }
        const bool overlong =
            (len == 2 && cp < 0x80U) || (len == 3 && cp < 0x800U) || (len == 4 && cp < 0x10000U);
        if (overlong || cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU)) {
            return std::nullopt;
        }
        out.push_back(cp);
        i += len;
    }
    return out;
}

/// A decimal number SQS's Number type takes: optional sign, digits with an
/// optional fraction and exponent; at most 38 significant digits; between
/// -10^128 and 10^126.
[[nodiscard]] inline auto valid_number(std::string_view s) -> bool {
    std::size_t i = 0;
    bool negative = false;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
        negative = s[i] == '-';
        ++i;
    }
    std::string digits;
    long long point_shift = 0;  // digits after the point
    bool seen_digit = false;
    bool seen_point = false;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        if (c >= '0' && c <= '9') {
            seen_digit = true;
            digits += c;
            if (seen_point) {
                ++point_shift;
            }
        } else if (c == '.' && !seen_point) {
            seen_point = true;
        } else {
            break;
        }
    }
    if (!seen_digit) {
        return false;
    }
    long long exponent = 0;
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        bool exp_negative = false;
        if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
            exp_negative = s[i] == '-';
            ++i;
        }
        if (i == s.size()) {
            return false;
        }
        for (; i < s.size(); ++i) {
            if (s[i] < '0' || s[i] > '9' || exponent > 100000) {
                return false;
            }
            exponent = exponent * 10 + (s[i] - '0');
        }
        if (exp_negative) {
            exponent = -exponent;
        }
    }
    if (i != s.size()) {
        return false;
    }
    // Significant digits: strip leading zeros, then trailing zeros (which
    // only scale).
    const auto first = digits.find_first_not_of('0');
    if (first == std::string::npos) {
        return true;  // zero
    }
    auto sig = digits.substr(first);
    const auto last = sig.find_last_not_of('0');
    const auto trailing = static_cast<long long>(sig.size() - last - 1);
    sig.resize(last + 1);
    if (sig.size() > 38) {
        return false;
    }
    // value = sig * 10^(magnitude - sig.size() + 1), with `magnitude` the
    // power of ten of the leading digit.
    const long long magnitude =
        static_cast<long long>(sig.size()) - 1 + trailing - point_shift + exponent;
    return negative ? magnitude < 128 || (magnitude == 128 && sig == "1")
                    : magnitude < 126 || (magnitude == 126 && sig == "1");
}

}  // namespace message_detail

/// Whether every character of `body` is one SQS accepts: #x9, #xA, #xD,
/// #x20-#xD7FF, #xE000-#xFFFD, #x10000-#x10FFFF, in well-formed UTF-8.
[[nodiscard]] inline auto valid_body(std::string_view body) -> bool {
    const auto cps = message_detail::code_points(body);
    if (!cps) {
        return false;
    }
    return std::all_of(cps->begin(), cps->end(), [](char32_t c) {
        return c == 0x9U || c == 0xAU || c == 0xDU || (c >= 0x20U && c <= 0xD7FFU) ||
               (c >= 0xE000U && c <= 0xFFFDU) || (c >= 0x10000U && c <= 0x10FFFFU);
    });
}

/// SQS's digest of a `MessageAttributes` or `MessageSystemAttributes`
/// object, or empty when there are none. Assumes `check_attributes` passed.
[[nodiscard]] inline auto md5_of_attributes(const boost::json::object& attrs) -> std::string {
    if (attrs.empty()) {
        return {};
    }
    std::vector<std::string_view> names;
    names.reserve(attrs.size());
    for (const auto& kv : attrs) {
        names.push_back(kv.key());
    }
    std::sort(names.begin(), names.end());
    std::string buf;
    for (const auto name : names) {
        const auto& a = attrs.at(name).as_object();
        const std::string_view type = a.at("DataType").as_string();
        message_detail::put_field(buf, name);
        message_detail::put_field(buf, type);
        if (message_detail::base_type(type) == "Binary") {
            buf += '\x02';
            const auto bytes = aws_json::base64_decode(a.at("BinaryValue").as_string());
            message_detail::put_field(
                buf, bytes
                         ? std::string_view(reinterpret_cast<const char*>(bytes->data()),  // NOLINT
                                            bytes->size())
                         : std::string_view());
        } else {
            buf += '\x01';
            message_detail::put_field(buf, a.at("StringValue").as_string());
        }
    }
    return md5_hex(buf);
}

/// The bytes `attrs` count against the message size: each attribute's
/// name, data type and value (binary values decoded).
[[nodiscard]] inline auto attributes_size(const boost::json::object& attrs) -> std::size_t {
    std::size_t n = 0;
    for (const auto& kv : attrs) {
        const auto& a = kv.value().as_object();
        n += kv.key().size() + a.at("DataType").as_string().size();
        if (const auto* s = a.if_contains("StringValue"); s != nullptr && s->is_string()) {
            n += s->get_string().size();
        }
        if (const auto* b = a.if_contains("BinaryValue"); b != nullptr && b->is_string()) {
            n += aws_json::base64_decode(b->get_string()).value_or(std::vector<std::byte>{}).size();
        }
    }
    return n;
}

/// Checks a `MessageAttributes` object (`system == false`) or a
/// `MessageSystemAttributes` object (`system == true`). The codec has
/// already checked the shape (strings where strings belong, base64 blobs).
[[nodiscard]] inline auto check_attributes(const boost::json::object& attrs, bool system)
    -> std::optional<aws_json::error> {
    using message_detail::bad_attribute;
    const std::string_view what = system ? "Message system attribute" : "Message (user) attribute";
    if (!system && attrs.size() > k_max_message_attributes) {
        return bad_attribute("Number of message attributes [" + std::to_string(attrs.size()) +
                             "] exceeds the allowed maximum [" +
                             std::to_string(k_max_message_attributes) + "].");
    }
    for (const auto& kv : attrs) {
        const std::string_view name = kv.key();
        const auto quoted = std::string(what) + " '" + std::string(name) + "'";
        if (system) {
            if (name != "AWSTraceHeader") {
                return bad_attribute(quoted + " is not supported.");
            }
        } else {
            const auto lname = message_detail::lower(name);
            const bool chars_ok = std::all_of(name.begin(), name.end(), [](char c) {
                return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '-' ||
                       c == '.';
            });
            if (lname.starts_with("aws.") || lname.starts_with("amazon.")) {
                // SQS's text (task 13's recordings, seed 1 step 107).
                return bad_attribute(
                    "You can't use message attribute names beginning with "
                    "'AWS.' or 'Amazon'. These strings are reserved for "
                    "internal use.");
            }
            if (name.empty() || name.size() > k_max_attribute_name || !chars_ok ||
                name.front() == '.' || name.back() == '.' ||
                name.find("..") != std::string_view::npos) {
                return bad_attribute(quoted + " has an invalid name.");
            }
        }
        if (!kv.value().is_object()) {
            return bad_attribute(quoted + " must have a value.");
        }
        const auto& a = kv.value().as_object();
        const auto* t = a.if_contains("DataType");
        if (t == nullptr || !t->is_string() || t->get_string().empty()) {
            return bad_attribute(quoted + " must contain a non-empty message attribute type.");
        }
        const std::string_view type = t->get_string();
        const auto base = message_detail::base_type(type);
        const auto suffix = type.substr(base.size());
        if (type.size() > k_max_attribute_type ||
            (base != "String" && base != "Number" && base != "Binary") ||
            (system && type != "String") || suffix == ".") {
            return bad_attribute(quoted + " has an invalid message attribute type '" +
                                 std::string(type) + "'.");
        }
        if (a.contains("StringListValues") || a.contains("BinaryListValues")) {
            return bad_attribute(quoted +
                                 ": StringListValues and BinaryListValues are not "
                                 "supported.");
        }
        const bool binary = base == "Binary";
        const auto* s = a.if_contains("StringValue");
        const auto* b = a.if_contains("BinaryValue");
        const bool has_string = s != nullptr && s->is_string() && !s->get_string().empty();
        const bool has_binary = b != nullptr && b->is_string() && !b->get_string().empty();
        if (binary ? (!has_binary || s != nullptr) : (!has_string || b != nullptr)) {
            // SQS's text (task 13's recording, seed 3 step 57).
            return bad_attribute(quoted + " must contain a non-empty value of type '" +
                                 std::string(type) + "'.");
        }
        if (has_string && !valid_body(s->get_string())) {
            return make_error(k_validation_error, quoted + " contains invalid characters.");
        }
        if (base == "Number" && !message_detail::valid_number(s->get_string())) {
            return bad_attribute("Can't cast the value of " + quoted + " to a number.");
        }
    }
    return std::nullopt;
}

/// How attributes are stored with a message: the request's JSON object,
/// serialized; empty for none.
[[nodiscard]] inline auto encode_attributes(const boost::json::object& attrs) -> std::string {
    return attrs.empty() ? std::string() : boost::json::serialize(attrs);
}

/// The attributes `encode_attributes` stored, or an empty object.
[[nodiscard]] inline auto decode_attributes(std::string_view stored) -> boost::json::object {
    if (stored.empty()) {
        return {};
    }
    boost::system::error_code ec;
    auto v = boost::json::parse(stored, ec);
    return !ec && v.is_object() ? std::move(v.as_object()) : boost::json::object{};
}

/// The attributes of `attrs` a receive asked for by name: `All` or `.*`
/// selects every one, `prefix.*` those starting with `prefix.`, any other
/// name itself.
[[nodiscard]] inline auto select_attributes(const boost::json::object& attrs,
                                            const std::vector<std::string>& wanted)
    -> boost::json::object {
    boost::json::object out;
    for (const auto& kv : attrs) {
        const std::string_view name = kv.key();
        const bool pick = std::any_of(wanted.begin(), wanted.end(), [name](const std::string& w) {
            if (w == "All" || w == ".*") {
                return true;
            }
            if (w.size() > 2 && w.ends_with(".*")) {
                return name.starts_with(std::string_view(w).substr(0, w.size() - 1));
            }
            return name == w;
        });
        if (pick) {
            out[name] = kv.value();
        }
    }
    return out;
}

}  // namespace kythira::sqs
