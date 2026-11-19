// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_website_rules.hpp
/// @brief A bucket's website configuration: S3's XML both ways, S3's
///        checks on it, routing rules and redirects, and the HTML error
///        pages of the website endpoint
///        (.kiro/specs/s3-compatible-storage/ task 15, Requirement 12.4).
///
/// A configuration either sends every request elsewhere
/// (`RedirectAllRequestsTo`) or serves the bucket: an `IndexDocument`
/// suffix (required; no `/`), an optional `ErrorDocument` key and up to 50
/// `RoutingRules`. A rule's `Condition` (a key prefix, an HTTP error code,
/// or both; no condition matches every request) picks a `Redirect`
/// (host, protocol, a 3XX code, and a replacement key or key prefix).
/// The serving itself, which needs the bucket's objects and the access
/// check, is `s3_website.hpp`'s.

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

struct website_redirect {
    std::string host_name;
    std::string protocol;  ///< `http`, `https`, or empty (the request's)
    std::optional<unsigned> http_redirect_code;
    std::optional<std::string> replace_key_prefix_with;
    std::optional<std::string> replace_key_with;
};

struct website_routing_rule {
    /// No `Condition` element: the rule matches every request.
    bool has_condition = false;
    std::optional<std::string> key_prefix_equals;
    std::optional<unsigned> http_error_code_returned_equals;
    website_redirect redirect;
};

struct website_configuration {
    /// `RedirectAllRequestsTo`: when set, nothing below applies.
    std::optional<website_redirect> redirect_all;
    std::string index_suffix;
    std::optional<std::string> error_document;
    std::vector<website_routing_rule> routing_rules;
};

namespace website_detail {

inline constexpr std::size_t max_routing_rules = 50;

[[nodiscard]] inline auto invalid_argument(std::string message, std::string_view argument = {},
                                           std::string_view value = {}) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
    if (!argument.empty()) {
        e.extra.emplace_back("ArgumentName", std::string(argument));
        e.extra.emplace_back("ArgumentValue", std::string(value));
    }
    return e;
}

[[nodiscard]] inline auto invalid_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

[[nodiscard]] inline auto parse_code(std::string_view text) -> std::optional<unsigned> {
    if (text.size() != 3 ||
        !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    return static_cast<unsigned>(((text[0] - '0') * 100) + ((text[1] - '0') * 10) +
                                 (text[2] - '0'));
}

[[nodiscard]] inline auto check_protocol(std::string_view p) -> std::optional<aws_rest_xml::error> {
    if (p == "http" || p == "https") {
        return std::nullopt;
    }
    return invalid_argument(
        "Invalid protocol, protocol can be http or https. If not defined the protocol will be "
        "selected automatically.",
        "Protocol", p);
}

[[nodiscard]] inline auto parse_redirect_all(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<website_redirect> {
    website_redirect r;
    for (const auto& c : e.children) {
        if (c.name == "HostName") {
            r.host_name = c.text;
        } else if (c.name == "Protocol") {
            r.protocol = c.text;
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown RedirectAllRequestsTo element " +
                                                       c.name);
        }
    }
    if (r.host_name.empty()) {
        return aws_rest_xml::errors::malformed_xml("RedirectAllRequestsTo needs a HostName");
    }
    if (e.child("Protocol") != nullptr) {
        if (auto err = check_protocol(r.protocol)) {
            return *err;
        }
    }
    return r;
}

[[nodiscard]] inline auto parse_redirect(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<website_redirect> {
    website_redirect r;
    for (const auto& c : e.children) {
        if (c.name == "HostName") {
            r.host_name = c.text;
        } else if (c.name == "Protocol") {
            if (auto err = check_protocol(c.text)) {
                return *err;
            }
            r.protocol = c.text;
        } else if (c.name == "HttpRedirectCode") {
            const auto code = parse_code(c.text);
            if (!code || *code < 301 || *code > 399) {
                return invalid_argument("The provided HTTP redirect code (" + c.text +
                                            ") is not valid. Valid codes are 3XX except 300.",
                                        "HttpRedirectCode", c.text);
            }
            r.http_redirect_code = code;
        } else if (c.name == "ReplaceKeyPrefixWith") {
            r.replace_key_prefix_with = c.text;
        } else if (c.name == "ReplaceKeyWith") {
            r.replace_key_with = c.text;
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown Redirect element " + c.name);
        }
    }
    if (e.children.empty()) {
        return invalid_request("Redirect cannot be empty.");
    }
    if (r.replace_key_prefix_with && r.replace_key_with) {
        return invalid_request("You can only define ReplaceKeyPrefix or ReplaceKey but not both.");
    }
    return r;
}

[[nodiscard]] inline auto parse_routing_rule(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<website_routing_rule> {
    website_routing_rule out;
    const aws_rest_xml::xml_element* redirect = nullptr;
    for (const auto& c : e.children) {
        if (c.name == "Condition") {
            out.has_condition = true;
            for (const auto& k : c.children) {
                if (k.name == "KeyPrefixEquals") {
                    out.key_prefix_equals = k.text;
                } else if (k.name == "HttpErrorCodeReturnedEquals") {
                    const auto code = parse_code(k.text);
                    if (!code || *code < 400 || *code > 599) {
                        return invalid_argument("The provided HTTP error code (" + k.text +
                                                    ") is not valid. Valid codes are 4XX or 5XX.",
                                                "HttpErrorCodeReturnedEquals", k.text);
                    }
                    out.http_error_code_returned_equals = code;
                } else {
                    return aws_rest_xml::errors::malformed_xml("unknown Condition element " +
                                                               k.name);
                }
            }
            if (c.children.empty()) {
                return invalid_request(
                    "Condition cannot be empty. To redirect all requests without a condition, the "
                    "condition element shouldn't be present.");
            }
        } else if (c.name == "Redirect") {
            redirect = &c;
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown RoutingRule element " + c.name);
        }
    }
    if (redirect == nullptr) {
        return aws_rest_xml::errors::malformed_xml("a RoutingRule needs a Redirect");
    }
    auto r = parse_redirect(*redirect);
    if (!r) {
        return r.error();
    }
    out.redirect = std::move(*r);
    return out;
}

}  // namespace website_detail

/// S3's checks on a `PutBucketWebsite` body.
[[nodiscard]] inline auto parse_website_configuration(std::string_view xml)
    -> aws_rest_xml::result<website_configuration> {
    using namespace website_detail;
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "WebsiteConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected WebsiteConfiguration");
    }
    website_configuration out;
    const aws_rest_xml::xml_element* index = nullptr;
    const aws_rest_xml::xml_element* error = nullptr;
    const aws_rest_xml::xml_element* rules = nullptr;
    const aws_rest_xml::xml_element* all = nullptr;
    for (const auto& c : doc->children) {
        if (c.name == "IndexDocument") {
            index = &c;
        } else if (c.name == "ErrorDocument") {
            error = &c;
        } else if (c.name == "RoutingRules") {
            rules = &c;
        } else if (c.name == "RedirectAllRequestsTo") {
            all = &c;
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown WebsiteConfiguration element " +
                                                       c.name);
        }
    }
    if (all != nullptr) {
        if (index != nullptr || error != nullptr || rules != nullptr) {
            return invalid_request(
                "RedirectAllRequestsTo cannot be provided in conjunction with other Routing "
                "Rules.");
        }
        auto r = parse_redirect_all(*all);
        if (!r) {
            return r.error();
        }
        out.redirect_all = std::move(*r);
        return out;
    }
    if (index == nullptr) {
        return invalid_argument(
            "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty",
            "IndexDocument", "");
    }
    out.index_suffix = index->child_text("Suffix").value_or("");
    if (out.index_suffix.empty() || out.index_suffix.find('/') != std::string::npos) {
        return invalid_argument("The IndexDocument Suffix is not well formed", "IndexDocument",
                                out.index_suffix);
    }
    if (error != nullptr) {
        const auto key = error->child_text("Key").value_or("");
        if (key.empty()) {
            return invalid_argument("The ErrorDocument Key is not well formed", "ErrorDocument",
                                    key);
        }
        out.error_document = key;
    }
    if (rules != nullptr) {
        for (const auto& c : rules->children) {
            if (c.name != "RoutingRule") {
                return aws_rest_xml::errors::malformed_xml("unknown RoutingRules element " +
                                                           c.name);
            }
            auto r = parse_routing_rule(c);
            if (!r) {
                return r.error();
            }
            out.routing_rules.push_back(std::move(*r));
        }
        if (out.routing_rules.empty()) {
            return aws_rest_xml::errors::malformed_xml("RoutingRules needs a RoutingRule");
        }
        if (out.routing_rules.size() > max_routing_rules) {
            return invalid_request("The number of routing rules must not exceed 50.");
        }
    }
    return out;
}

/// The configuration as `GetBucketWebsite` answers it.
[[nodiscard]] inline auto website_xml(const website_configuration& c) -> std::string {
    auto w = aws_rest_xml::document("WebsiteConfiguration");
    if (c.redirect_all) {
        w.open("RedirectAllRequestsTo").element("HostName", c.redirect_all->host_name);
        if (!c.redirect_all->protocol.empty()) {
            w.element("Protocol", c.redirect_all->protocol);
        }
        w.close().close();
        return w.str();
    }
    w.open("IndexDocument").element("Suffix", c.index_suffix).close();
    if (c.error_document) {
        w.open("ErrorDocument").element("Key", *c.error_document).close();
    }
    if (!c.routing_rules.empty()) {
        w.open("RoutingRules");
        for (const auto& r : c.routing_rules) {
            w.open("RoutingRule");
            if (r.has_condition) {
                w.open("Condition");
                if (r.http_error_code_returned_equals) {
                    w.element("HttpErrorCodeReturnedEquals",
                              std::to_string(*r.http_error_code_returned_equals));
                }
                if (r.key_prefix_equals) {
                    w.element("KeyPrefixEquals", *r.key_prefix_equals);
                }
                w.close();
            }
            w.open("Redirect");
            const auto& d = r.redirect;
            if (!d.host_name.empty()) {
                w.element("HostName", d.host_name);
            }
            if (d.http_redirect_code) {
                w.element("HttpRedirectCode", std::to_string(*d.http_redirect_code));
            }
            if (!d.protocol.empty()) {
                w.element("Protocol", d.protocol);
            }
            if (d.replace_key_prefix_with) {
                w.element("ReplaceKeyPrefixWith", *d.replace_key_prefix_with);
            }
            if (d.replace_key_with) {
                w.element("ReplaceKeyWith", *d.replace_key_with);
            }
            w.close().close();
        }
        w.close();
    }
    w.close();
    return w.str();
}

/// A bucket's stored configuration; none when absent or unreadable.
[[nodiscard]] inline auto load_website(std::string_view stored)
    -> std::optional<website_configuration> {
    auto c = parse_website_configuration(stored);
    if (!c) {
        return std::nullopt;
    }
    return std::move(*c);
}

/// The first routing rule for `key`: before the object is read
/// (`error_code` none) only rules without an error-code condition count;
/// after an error, only rules whose error code is that one.
[[nodiscard]] inline auto match_routing_rule(const website_configuration& c, std::string_view key,
                                             std::optional<unsigned> error_code)
    -> const website_routing_rule* {
    for (const auto& r : c.routing_rules) {
        if (r.http_error_code_returned_equals.has_value() != error_code.has_value()) {
            continue;
        }
        if (error_code && *r.http_error_code_returned_equals != *error_code) {
            continue;
        }
        if (r.key_prefix_equals && !key.starts_with(*r.key_prefix_equals)) {
            continue;
        }
        return &r;
    }
    return nullptr;
}

/// A key as a URL path: every byte but unreserved characters and `/`
/// percent-encoded (a space is `%20`, never `+`, in a path).
[[nodiscard]] inline auto website_path(std::string_view key) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(key.size() + 1);
    out += '/';
    for (const char ch : key) {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~' || c == '/') {
            out += ch;
        } else {
            out += '%';
            out += hex[c >> 4U];
            out += hex[c & 0x0FU];
        }
    }
    return out;
}

/// Where a routing rule sends a request for `key`. `request_host` and
/// `request_protocol` fill what the redirect leaves out.
[[nodiscard]] inline auto routing_location(const website_routing_rule& rule, std::string_view key,
                                           std::string_view request_host,
                                           std::string_view request_protocol) -> std::string {
    const auto& d = rule.redirect;
    std::string new_key(key);
    if (d.replace_key_with) {
        new_key = *d.replace_key_with;
    } else if (d.replace_key_prefix_with) {
        const auto prefix = rule.key_prefix_equals.value_or("");
        new_key = *d.replace_key_prefix_with + std::string(key.substr(prefix.size()));
    }
    const std::string protocol = d.protocol.empty() ? std::string(request_protocol) : d.protocol;
    const std::string host = d.host_name.empty() ? std::string(request_host) : d.host_name;
    return protocol + "://" + host + website_path(new_key);
}

namespace website_detail {

[[nodiscard]] inline auto html_escape(std::string_view s) -> std::string {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            default:
                out += c;
        }
    }
    return out;
}

[[nodiscard]] inline auto reason_phrase(unsigned status) -> std::string_view {
    switch (status) {
        case 400:
            return "Bad Request";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 412:
            return "Precondition Failed";
        case 416:
            return "Requested Range Not Satisfiable";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 503:
            return "Service Unavailable";
        default:
            return status < 500 ? "Client Error" : "Server Error";
    }
}

inline void html_items(std::string& out, const aws_rest_xml::error& e,
                       std::string_view request_id) {
    out += "<ul>\n";
    out += "<li>Code: " + html_escape(e.code) + "</li>\n";
    out += "<li>Message: " + html_escape(e.message) + "</li>\n";
    for (const auto& [k, v] : e.extra) {
        if (k != "Detail") {
            out += "<li>" + html_escape(k) + ": " + html_escape(v) + "</li>\n";
        }
    }
    out += "<li>RequestId: " + html_escape(request_id) + "</li>\n";
    out += "<li>HostId: " + html_escape(request_id) + "</li>\n";
    out += "</ul>\n";
}

}  // namespace website_detail

/// The website endpoint's HTML page for `e`. `document_error` is what went
/// wrong fetching the custom error document, if one was configured.
[[nodiscard]] inline auto website_error_html(
    const aws_rest_xml::error& e, std::string_view request_id,
    const std::optional<aws_rest_xml::error>& document_error = std::nullopt) -> std::string {
    using namespace website_detail;
    const auto title = std::to_string(e.status) + " " + std::string(reason_phrase(e.status));
    std::string out =
        "<html>\n<head><title>" + title + "</title></head>\n<body>\n<h1>" + title + "</h1>\n";
    html_items(out, e, request_id);
    if (document_error) {
        out += "<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n";
        html_items(out, *document_error, request_id);
    }
    out += "<hr/>\n</body>\n</html>\n";
    return out;
}

}  // namespace kythira::s3
