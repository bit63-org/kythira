// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// PKCS#11 URIs (RFC 7512), the way Kythira's key consumers name a token and
// a key (.kiro/specs/virtual-hsm/ Requirement 9.1):
//
//   pkcs11:token=ca;object=issuing;type=private?pin-source=/run/secrets/pin
//
// The path names the library, slot, token and object; the query carries how
// to log in (pin-value or pin-source) and which library to load
// (module-path, module-name). Every attribute is optional, at most once.
//
// Values are percent-decoded when parsed. `id` is raw bytes (CKA_ID); the
// others are UTF-8 text compared exactly, after the blank padding of the
// CK_*_INFO fields is trimmed (raft/pkcs11_module.hpp does that).
//
// Vendor attributes (`x-...`) and attributes this parser does not know are
// refused rather than ignored: RFC 7512 section 2.3 lets a consumer refuse
// a URI it does not fully understand, and ignoring a path attribute would
// widen the match to a key the URI's author did not mean.
//
// No PKCS#11 types here, so a configuration loader can parse a URI without
// the PKCS#11 headers.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::pkcs11 {

/// A URI this parser refuses, with the reason.
class uri_error : public std::invalid_argument {
public:
    using std::invalid_argument::invalid_argument;
};

/// RFC 7512 `type`.
enum class object_type : std::uint8_t {
    public_key,
    private_key,
    certificate,
    secret_key,
    data
};

struct version_number {
    unsigned major = 0;
    unsigned minor = 0;

    auto operator==(const version_number&) const -> bool = default;
};

struct uri {
    // Path: library.
    std::optional<std::string> library_manufacturer;
    std::optional<std::string> library_description;
    std::optional<version_number> library_version;
    // Path: slot.
    std::optional<std::string> slot_description;
    std::optional<std::string> slot_manufacturer;
    std::optional<unsigned long> slot_id;  // NOLINT(google-runtime-int): CK_SLOT_ID
    // Path: token.
    std::optional<std::string> token;
    std::optional<std::string> manufacturer;
    std::optional<std::string> serial;
    std::optional<std::string> model;
    // Path: object.
    std::optional<std::string> object;
    std::optional<object_type> type;
    std::optional<std::vector<std::uint8_t>> id;
    // Query.
    std::optional<std::string> pin_source;
    std::optional<std::string> pin_value;
    std::optional<std::string> module_name;
    std::optional<std::string> module_path;

    auto operator==(const uri&) const -> bool = default;

    /// Parses `text`; throws uri_error.
    [[nodiscard]] static auto parse(std::string_view text) -> uri;

    /// The URI as text, attributes in RFC 7512's order. pin-value is left
    /// out unless asked for, so the text can go to a log.
    [[nodiscard]] auto to_string(bool with_pin_value = false) const -> std::string;

    /// The PIN the URI gives: pin-value, else the contents of pin-source (a
    /// path or a `file:` URI) up to the first newline, else none. Throws
    /// uri_error when pin-source cannot be read.
    [[nodiscard]] auto pin() const -> std::optional<std::string>;
};

namespace detail {

[[nodiscard]] inline auto hex_value(char c) -> int {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/// RFC 3986 unreserved characters plus the ones RFC 7512 allows unencoded
/// in a value of the path (`pk11-pchar`) or of the query (`pk11-qchar`).
[[nodiscard]] inline auto allowed_raw(char c, bool query) -> bool {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return true;
    }
    switch (c) {
        case '-':
        case '.':
        case '_':
        case '~':
        case ':':
        case '[':
        case ']':
        case '@':
        case '!':
        case '$':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case '=':
            return true;
        case '&':
            return !query;
        case '/':
        case '?':
        case '|':
            return query;
        default:
            return false;
    }
}

[[nodiscard]] inline auto decode(std::string_view in, bool query, std::string_view name)
    -> std::string {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size()) {
                throw uri_error("pkcs11 URI: truncated percent escape in " + std::string(name));
            }
            const int hi = hex_value(in[i + 1]);
            const int lo = hex_value(in[i + 2]);
            if (hi < 0 || lo < 0) {
                throw uri_error("pkcs11 URI: bad percent escape in " + std::string(name));
            }
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
            continue;
        }
        if (!allowed_raw(c, query)) {
            throw uri_error("pkcs11 URI: character '" + std::string(1, c) + "' must be " +
                            "percent-encoded in " + std::string(name));
        }
        out.push_back(c);
    }
    return out;
}

[[nodiscard]] inline auto encode(std::string_view in, bool query) -> std::string {
    static constexpr std::string_view digits = "0123456789ABCDEF";
    std::string out;
    for (const char c : in) {
        // '=' and ',' are legal but encoded anyway, so the text reads back
        // the same under any parser.
        if (allowed_raw(c, query) && c != '=' && c != '&' && c != ';') {
            out.push_back(c);
        } else {
            const auto b = static_cast<unsigned char>(c);
            out.push_back('%');
            out.push_back(digits.at(b >> 4U));
            out.push_back(digits.at(b & 0x0FU));
        }
    }
    return out;
}

[[nodiscard]] inline auto split(std::string_view s, char sep) -> std::vector<std::string_view> {
    std::vector<std::string_view> out;
    if (s.empty()) {
        return out;
    }
    std::size_t start = 0;
    while (true) {
        const auto pos = s.find(sep, start);
        out.push_back(s.substr(start, pos == std::string_view::npos ? pos : pos - start));
        if (pos == std::string_view::npos) {
            return out;
        }
        start = pos + 1;
    }
}

template<class T> void set_once(std::optional<T>& field, T value, std::string_view name) {
    if (field) {
        throw uri_error("pkcs11 URI: " + std::string(name) + " given twice");
    }
    field = std::move(value);
}

[[nodiscard]] inline auto parse_unsigned(const std::string& s, std::string_view name)
    -> unsigned long {  // NOLINT(google-runtime-int): CK_SLOT_ID's type
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos || s.size() > 19) {
        throw uri_error("pkcs11 URI: " + std::string(name) + " is not a decimal number");
    }
    return std::strtoul(s.c_str(), nullptr, 10);
}

[[nodiscard]] inline auto type_name(object_type t) -> std::string_view {
    switch (t) {
        case object_type::public_key:
            return "public";
        case object_type::private_key:
            return "private";
        case object_type::certificate:
            return "cert";
        case object_type::secret_key:
            return "secret-key";
        case object_type::data:
            return "data";
    }
    return "data";
}

}  // namespace detail

inline auto uri::parse(std::string_view text) -> uri {
    constexpr std::string_view scheme = "pkcs11:";
    if (text.size() < scheme.size() ||
        !std::equal(scheme.begin(), scheme.end(), text.begin(), [](char a, char b) {
            return a == (b >= 'A' && b <= 'Z' ? static_cast<char>(b - 'A' + 'a') : b);
        })) {
        throw uri_error("pkcs11 URI: must start with 'pkcs11:'");
    }
    text.remove_prefix(scheme.size());
    const auto q = text.find('?');
    const auto path = text.substr(0, q);
    const auto query = q == std::string_view::npos ? std::string_view() : text.substr(q + 1);

    uri u;
    for (const auto attr : detail::split(path, ';')) {
        const auto eq = attr.find('=');
        if (eq == std::string_view::npos || eq == 0) {
            throw uri_error("pkcs11 URI: path attribute '" + std::string(attr) +
                            "' is not name=value");
        }
        const auto name = attr.substr(0, eq);
        auto value = detail::decode(attr.substr(eq + 1), false, name);
        if (name == "token") {
            detail::set_once(u.token, std::move(value), name);
        } else if (name == "manufacturer") {
            detail::set_once(u.manufacturer, std::move(value), name);
        } else if (name == "serial") {
            detail::set_once(u.serial, std::move(value), name);
        } else if (name == "model") {
            detail::set_once(u.model, std::move(value), name);
        } else if (name == "library-manufacturer") {
            detail::set_once(u.library_manufacturer, std::move(value), name);
        } else if (name == "library-description") {
            detail::set_once(u.library_description, std::move(value), name);
        } else if (name == "library-version") {
            const auto dot = value.find('.');
            version_number v;
            v.major = static_cast<unsigned>(detail::parse_unsigned(value.substr(0, dot), name));
            if (dot != std::string::npos) {
                v.minor =
                    static_cast<unsigned>(detail::parse_unsigned(value.substr(dot + 1), name));
            }
            if (v.major > 255 || v.minor > 255) {
                throw uri_error("pkcs11 URI: library-version parts must be at most 255");
            }
            detail::set_once(u.library_version, v, name);
        } else if (name == "slot-description") {
            detail::set_once(u.slot_description, std::move(value), name);
        } else if (name == "slot-manufacturer") {
            detail::set_once(u.slot_manufacturer, std::move(value), name);
        } else if (name == "slot-id") {
            detail::set_once(u.slot_id, detail::parse_unsigned(value, name), name);
        } else if (name == "object") {
            detail::set_once(u.object, std::move(value), name);
        } else if (name == "type") {
            object_type t{};
            if (value == "public") {
                t = object_type::public_key;
            } else if (value == "private") {
                t = object_type::private_key;
            } else if (value == "cert") {
                t = object_type::certificate;
            } else if (value == "secret-key") {
                t = object_type::secret_key;
            } else if (value == "data") {
                t = object_type::data;
            } else {
                throw uri_error("pkcs11 URI: unknown type '" + value + "'");
            }
            detail::set_once(u.type, t, name);
        } else if (name == "id") {
            detail::set_once(u.id, std::vector<std::uint8_t>(value.begin(), value.end()), name);
        } else {
            throw uri_error("pkcs11 URI: unsupported path attribute '" + std::string(name) + "'");
        }
    }
    for (const auto attr : detail::split(query, '&')) {
        const auto eq = attr.find('=');
        if (eq == std::string_view::npos || eq == 0) {
            throw uri_error("pkcs11 URI: query attribute '" + std::string(attr) +
                            "' is not name=value");
        }
        const auto name = attr.substr(0, eq);
        auto value = detail::decode(attr.substr(eq + 1), true, name);
        if (name == "pin-value") {
            detail::set_once(u.pin_value, std::move(value), name);
        } else if (name == "pin-source") {
            detail::set_once(u.pin_source, std::move(value), name);
        } else if (name == "module-name") {
            detail::set_once(u.module_name, std::move(value), name);
        } else if (name == "module-path") {
            detail::set_once(u.module_path, std::move(value), name);
        } else {
            throw uri_error("pkcs11 URI: unsupported query attribute '" + std::string(name) + "'");
        }
    }
    if (u.pin_value && u.pin_source) {
        throw uri_error("pkcs11 URI: pin-value and pin-source are exclusive");
    }
    return u;
}

inline auto uri::to_string(bool with_pin_value) const -> std::string {
    std::vector<std::string> path;
    const auto text = [&](std::string_view name, const std::optional<std::string>& v) {
        if (v) {
            path.push_back(std::string(name) + "=" + detail::encode(*v, false));
        }
    };
    text("library-manufacturer", library_manufacturer);
    text("library-description", library_description);
    if (library_version) {
        path.push_back("library-version=" + std::to_string(library_version->major) + "." +
                       std::to_string(library_version->minor));
    }
    text("slot-description", slot_description);
    text("slot-manufacturer", slot_manufacturer);
    if (slot_id) {
        path.push_back("slot-id=" + std::to_string(*slot_id));
    }
    text("token", token);
    text("manufacturer", manufacturer);
    text("serial", serial);
    text("model", model);
    text("object", object);
    if (type) {
        path.push_back("type=" + std::string(detail::type_name(*type)));
    }
    if (id) {
        static constexpr std::string_view digits = "0123456789ABCDEF";
        std::string s = "id=";
        for (const auto b : *id) {
            s.push_back('%');
            s.push_back(digits.at(b >> 4U));
            s.push_back(digits.at(b & 0x0FU));
        }
        path.push_back(std::move(s));
    }
    std::vector<std::string> query;
    const auto qtext = [&](std::string_view name, const std::optional<std::string>& v) {
        if (v) {
            query.push_back(std::string(name) + "=" + detail::encode(*v, true));
        }
    };
    qtext("pin-source", pin_source);
    if (with_pin_value) {
        qtext("pin-value", pin_value);
    }
    qtext("module-name", module_name);
    qtext("module-path", module_path);

    std::string out = "pkcs11:";
    for (std::size_t i = 0; i < path.size(); ++i) {
        out += (i == 0 ? "" : ";") + path[i];
    }
    for (std::size_t i = 0; i < query.size(); ++i) {
        out += (i == 0 ? "?" : "&") + query[i];
    }
    return out;
}

inline auto uri::pin() const -> std::optional<std::string> {
    if (pin_value) {
        return pin_value;
    }
    if (!pin_source) {
        return std::nullopt;
    }
    std::string path = *pin_source;
    if (path.starts_with("file://")) {
        path.erase(0, 7);
    } else if (path.starts_with("file:")) {
        path.erase(0, 5);
    }
    if (path.empty() || path.front() != '/') {
        throw uri_error("pkcs11 URI: pin-source must be an absolute path or file: URI");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw uri_error("pkcs11 URI: cannot read pin-source " + path);
    }
    std::string pin((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (const auto nl = pin.find_first_of("\r\n"); nl != std::string::npos) {
        pin.resize(nl);
    }
    return pin;
}

}  // namespace kythira::pkcs11
