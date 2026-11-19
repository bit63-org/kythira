// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_cors_rules.hpp
/// @brief A bucket's CORS configuration: S3's XML both ways, S3's checks
///        on it, and which rule answers a cross-origin request
///        (.kiro/specs/s3-compatible-storage/ task 15, Requirement 6.1).
///
/// A configuration holds 1 to 100 `CORSRule`s. Each names at least one
/// `AllowedOrigin` and one `AllowedMethod` (`GET`, `PUT`, `POST`,
/// `DELETE` or `HEAD`), and may add `AllowedHeader`s, `ExposeHeader`s,
/// `MaxAgeSeconds` and an `ID`. An origin or allowed header may carry
/// one `*` wildcard; an exposed header none, as on S3.
///
/// The first rule, in document order, whose origin, method and (for a
/// preflight) every requested header match is the one that answers, as S3
/// documents. Origins match case-sensitively, headers case-insensitively.

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

struct cors_rule {
    std::string id;
    std::vector<std::string> allowed_methods;
    std::vector<std::string> allowed_origins;
    std::vector<std::string> allowed_headers;
    std::vector<std::string> expose_headers;
    std::optional<std::uint32_t> max_age_seconds;
};

struct cors_configuration {
    std::vector<cors_rule> rules;
};

namespace cors_detail {

inline constexpr std::size_t max_rules = 100;
inline constexpr std::array<std::string_view, 5> methods{"GET", "PUT", "POST", "DELETE", "HEAD"};

[[nodiscard]] inline auto invalid_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

[[nodiscard]] inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    std::ranges::transform(out, out.begin(), aws_rest_xml::detail::ascii_lower);
    return out;
}

[[nodiscard]] inline auto trim(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

/// `value` against `pattern`, which holds at most one `*` standing for
/// any run of characters (none included).
[[nodiscard]] inline auto wildcard_match(std::string_view pattern, std::string_view value) -> bool {
    const auto star = pattern.find('*');
    if (star == std::string_view::npos) {
        return pattern == value;
    }
    const auto head = pattern.substr(0, star);
    const auto tail = pattern.substr(star + 1);
    return value.size() >= head.size() + tail.size() && value.starts_with(head) &&
           value.ends_with(tail);
}

[[nodiscard]] inline auto is_method(std::string_view m) -> bool {
    return std::ranges::find(methods, m) != methods.end();
}

[[nodiscard]] inline auto parse_rule(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<cors_rule> {
    cors_rule r;
    for (const auto& c : e.children) {
        if (c.name == "ID") {
            r.id = c.text;
        } else if (c.name == "AllowedMethod") {
            r.allowed_methods.push_back(c.text);
        } else if (c.name == "AllowedOrigin") {
            r.allowed_origins.push_back(c.text);
        } else if (c.name == "AllowedHeader") {
            r.allowed_headers.push_back(c.text);
        } else if (c.name == "ExposeHeader") {
            r.expose_headers.push_back(c.text);
        } else if (c.name == "MaxAgeSeconds") {
            const auto& t = c.text;
            std::uint64_t v = 0;
            if (t.empty() || t.size() > 10 ||
                !std::ranges::all_of(t, [](char ch) { return ch >= '0' && ch <= '9'; })) {
                return aws_rest_xml::errors::malformed_xml("MaxAgeSeconds is not an integer");
            }
            for (const char ch : t) {
                v = v * 10 + static_cast<std::uint64_t>(ch - '0');
            }
            if (v > 0x7fffffffU) {
                return aws_rest_xml::errors::malformed_xml("MaxAgeSeconds is too large");
            }
            r.max_age_seconds = static_cast<std::uint32_t>(v);
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown CORSRule element " + c.name);
        }
    }
    if (r.allowed_methods.empty() || r.allowed_origins.empty()) {
        return aws_rest_xml::errors::malformed_xml(
            "a CORSRule needs an AllowedMethod and an AllowedOrigin");
    }
    if (r.id.size() > 255) {
        return aws_rest_xml::errors::malformed_xml("a CORSRule ID is at most 255 characters");
    }
    for (const auto& m : r.allowed_methods) {
        if (!is_method(m)) {
            return invalid_request(
                "Found unsupported HTTP method in CORS config. Unsupported method is " + m);
        }
    }
    for (const auto& o : r.allowed_origins) {
        if (std::ranges::count(o, '*') > 1) {
            return invalid_request("AllowedOrigin \"" + o +
                                   "\" can not have more than one wildcard.");
        }
    }
    for (const auto& h : r.allowed_headers) {
        if (std::ranges::count(h, '*') > 1) {
            return invalid_request("AllowedHeader \"" + h +
                                   "\" can not have more than one wildcard.");
        }
    }
    for (const auto& h : r.expose_headers) {
        if (h.find('*') != std::string::npos) {
            return invalid_request("ExposeHeader \"" + h +
                                   "\" contains wildcard. We currently do not support wildcard "
                                   "for ExposeHeader.");
        }
    }
    return r;
}

}  // namespace cors_detail

/// S3's checks on a `PutBucketCors` body.
[[nodiscard]] inline auto parse_cors_configuration(std::string_view xml)
    -> aws_rest_xml::result<cors_configuration> {
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "CORSConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected CORSConfiguration");
    }
    cors_configuration out;
    for (const auto& c : doc->children) {
        if (c.name != "CORSRule") {
            return aws_rest_xml::errors::malformed_xml("unknown CORSConfiguration element " +
                                                       c.name);
        }
        auto r = cors_detail::parse_rule(c);
        if (!r) {
            return r.error();
        }
        out.rules.push_back(std::move(*r));
    }
    if (out.rules.empty()) {
        return aws_rest_xml::errors::malformed_xml("a CORSConfiguration needs a CORSRule");
    }
    if (out.rules.size() > cors_detail::max_rules) {
        return aws_rest_xml::errors::malformed_xml("a CORSConfiguration holds at most 100 rules");
    }
    return out;
}

/// The configuration as `GetBucketCors` answers it.
[[nodiscard]] inline auto cors_xml(const cors_configuration& c) -> std::string {
    auto w = aws_rest_xml::document("CORSConfiguration");
    for (const auto& r : c.rules) {
        w.open("CORSRule");
        if (!r.id.empty()) {
            w.element("ID", r.id);
        }
        for (const auto& h : r.allowed_headers) {
            w.element("AllowedHeader", h);
        }
        for (const auto& m : r.allowed_methods) {
            w.element("AllowedMethod", m);
        }
        for (const auto& o : r.allowed_origins) {
            w.element("AllowedOrigin", o);
        }
        for (const auto& h : r.expose_headers) {
            w.element("ExposeHeader", h);
        }
        if (r.max_age_seconds) {
            w.element("MaxAgeSeconds", std::to_string(*r.max_age_seconds));
        }
        w.close();
    }
    w.close();
    return w.str();
}

/// A bucket's stored configuration; none when absent or unreadable.
[[nodiscard]] inline auto load_cors(std::string_view stored) -> std::optional<cors_configuration> {
    auto c = parse_cors_configuration(stored);
    if (!c) {
        return std::nullopt;
    }
    return std::move(*c);
}

/// The names in an `Access-Control-Request-Headers` value, trimmed, in
/// order, empty entries dropped.
[[nodiscard]] inline auto split_header_list(std::string_view value) -> std::vector<std::string> {
    std::vector<std::string> out;
    while (!value.empty()) {
        const auto comma = value.find(',');
        const auto item = cors_detail::trim(value.substr(0, comma));
        if (!item.empty()) {
            out.emplace_back(item);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return out;
}

/// The rule that answers `origin` asking for `method` with the request
/// headers `headers` (none for an actual request); null when none does.
[[nodiscard]] inline auto match_cors_rule(const cors_configuration& c, std::string_view origin,
                                          std::string_view method,
                                          const std::vector<std::string>& headers = {})
    -> const cors_rule* {
    using cors_detail::wildcard_match;
    for (const auto& r : c.rules) {
        const bool origin_ok = std::ranges::any_of(
            r.allowed_origins, [&](const std::string& o) { return wildcard_match(o, origin); });
        if (!origin_ok || std::ranges::find(r.allowed_methods, method) == r.allowed_methods.end()) {
            continue;
        }
        const bool headers_ok = std::ranges::all_of(headers, [&](const std::string& h) {
            const auto name = cors_detail::lower(h);
            return std::ranges::any_of(r.allowed_headers, [&](const std::string& allowed) {
                return wildcard_match(cors_detail::lower(allowed), name);
            });
        });
        if (headers_ok) {
            return &r;
        }
    }
    return nullptr;
}

/// The `Access-Control-*` headers for an answer under `rule`. `requested`
/// is the preflight's `Access-Control-Request-Headers` (echoed in
/// `Access-Control-Allow-Headers`); none for an actual request.
[[nodiscard]] inline auto cors_headers(const cors_rule& rule, std::string_view origin,
                                       const std::optional<std::vector<std::string>>& requested)
    -> std::vector<std::pair<std::string, std::string>> {
    const auto join = [](const std::vector<std::string>& items) {
        std::string out;
        for (const auto& i : items) {
            out += (out.empty() ? "" : ", ") + i;
        }
        return out;
    };
    const bool any_origin =
        std::ranges::find(rule.allowed_origins, "*") != rule.allowed_origins.end();
    std::vector<std::pair<std::string, std::string>> out;
    out.emplace_back("Access-Control-Allow-Origin", any_origin ? "*" : std::string(origin));
    out.emplace_back("Access-Control-Allow-Methods", join(rule.allowed_methods));
    if (requested && !requested->empty()) {
        std::vector<std::string> names;
        names.reserve(requested->size());
        for (const auto& h : *requested) {
            names.push_back(cors_detail::lower(h));
        }
        out.emplace_back("Access-Control-Allow-Headers", join(names));
    }
    if (!rule.expose_headers.empty()) {
        out.emplace_back("Access-Control-Expose-Headers", join(rule.expose_headers));
    }
    if (rule.max_age_seconds) {
        out.emplace_back("Access-Control-Max-Age", std::to_string(*rule.max_age_seconds));
    }
    if (!any_origin) {
        out.emplace_back("Access-Control-Allow-Credentials", "true");
    }
    return out;
}

/// The `Vary` value S3 sends on every answer from a bucket with CORS.
inline constexpr std::string_view cors_vary =
    "Origin, Access-Control-Request-Headers, Access-Control-Request-Method";

}  // namespace kythira::s3
