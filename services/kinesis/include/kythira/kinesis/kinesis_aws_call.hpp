// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_aws_call.hpp
/// @brief SigV4-signed calls to an AWS-shaped HTTP API, for the channel
///        delivery's own clients (`.kiro/specs/kinesis-compatible-streams/`
///        task 19): STS `AssumeRole` for the service execution role and the
///        Iceberg REST catalog of S3 Tables.
///
/// The signing follows the SigV4 rules `raft/sigv4_verifier.hpp` checks on
/// the server side (the tests sign here and verify there), so a call is
/// accepted by AWS and by Kythira's own services alike. A call is one
/// blocking exchange through `peer_client`, or through a transport a test
/// puts in its place.

#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <raft/sigv4_verifier.hpp>

#include <boost/beast/http/verb.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

/// A set of AWS credentials; `_expires_ms` is 0 for long-lived keys.
struct sigv4_credentials {
    std::string _access_key_id;
    std::string _secret_access_key;
    std::string _session_token;
    std::int64_t _expires_ms = 0;

    [[nodiscard]] auto empty() const -> bool {
        return _access_key_id.empty() || _secret_access_key.empty();
    }
};

/// Where an API lives: `https://host[:port][/base/path]`.
struct aws_endpoint {
    bool _tls = true;
    /// "host:port", what `peer_client` dials.
    std::string _host_port;
    /// The Host header: the host, with the port only when it is not the
    /// scheme's default, as SDKs send it.
    std::string _host;
    /// The path the API's own paths go under, without a trailing slash ("" or
    /// "/iceberg").
    std::string _base_path;
};

/// `url` split into an endpoint; nullopt when it is not http(s)://host...
[[nodiscard]] inline auto parse_aws_endpoint(std::string_view url) -> std::optional<aws_endpoint> {
    aws_endpoint e;
    if (url.starts_with("https://")) {
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        e._tls = false;
        url.remove_prefix(7);
    } else {
        return std::nullopt;
    }
    const auto slash = url.find('/');
    const auto authority = url.substr(0, slash);
    if (slash != std::string_view::npos) {
        auto path = url.substr(slash);
        while (path.ends_with('/')) {
            path.remove_suffix(1);
        }
        e._base_path = std::string(path);
    }
    if (authority.empty()) {
        return std::nullopt;
    }
    const auto default_port = e._tls ? std::string_view("443") : std::string_view("80");
    // A port is present when the last colon follows any IPv6 bracket.
    const auto colon = authority.rfind(':');
    const auto bracket = authority.rfind(']');
    const bool has_port =
        colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket);
    if (has_port) {
        e._host_port = std::string(authority);
        e._host = authority.substr(colon + 1) == default_port
                      ? std::string(authority.substr(0, colon))
                      : std::string(authority);
    } else {
        e._host_port = std::string(authority) + ":" + std::string(default_port);
        e._host = std::string(authority);
    }
    if (!split_host_port(e._host_port)) {
        return std::nullopt;
    }
    return e;
}

/// One signed request: what goes on the wire.
struct aws_request {
    boost::beast::http::verb _method = boost::beast::http::verb::get;
    /// The path as sent (already percent-encoded where it needs to be).
    std::string _path = "/";
    /// The query as sent, without '?'.
    std::string _query;
    std::vector<std::pair<std::string, std::string>> _headers;
    std::string _body;

    [[nodiscard]] auto target() const -> std::string {
        return _query.empty() ? _path : _path + "?" + _query;
    }
};

/// One exchange: (endpoint, request) to the answer, nullopt when there was
/// none. The default dials through `peer_client`.
using aws_transport =
    std::function<std::optional<peer_response>(const aws_endpoint&, const aws_request&)>;

[[nodiscard]] inline auto peer_transport(std::string ca_path, std::chrono::milliseconds timeout)
    -> aws_transport {
    return [ca_path = std::move(ca_path), timeout](const aws_endpoint& e, const aws_request& r) {
        const peer_client client(
            peer_client_config{._tls = e._tls, ._ca_path = ca_path, ._timeout = timeout});
        return client.request(e._host_port, r._method, r.target(), r._headers, r._body);
    };
}

/// Signs `req` for `service` in `region`: adds `Host`, `x-amz-date`,
/// `x-amz-content-sha256`, `x-amz-security-token` (with a session token) and
/// `Authorization`. Every header already on the request is signed too.
inline auto sign_aws_request(aws_request& req, const aws_endpoint& endpoint,
                             const sigv4_credentials& creds, std::string_view region,
                             std::string_view service, std::chrono::sys_seconds now) -> void {
    namespace sd = sigv4::detail;
    const auto amz_date = sd::format_amz_date(now);
    const sigv4::credential_scope scope{.date = amz_date.substr(0, 8),
                                        .region = std::string(region),
                                        .service = std::string(service)};
    const auto payload = sd::sha256_hex(req._body);
    std::vector<std::pair<std::string, std::string>> h;
    for (const auto& [k, v] : req._headers) {
        h.emplace_back(sd::lower(k), std::string(sd::canonical_header_value(v)));
    }
    h.emplace_back("host", endpoint._host);
    h.emplace_back("x-amz-content-sha256", payload);
    h.emplace_back("x-amz-date", amz_date);
    if (!creds._session_token.empty()) {
        h.emplace_back("x-amz-security-token", creds._session_token);
    }
    std::ranges::sort(h);
    std::string canonical = std::string(boost::beast::http::to_string(req._method));
    canonical += "\n";
    canonical += sigv4::canonical_uri(req._path, service == "s3");
    canonical += "\n";
    canonical += sigv4::canonical_query(req._query, false);
    canonical += "\n";
    std::string names;
    for (const auto& [k, v] : h) {
        canonical += k + ":" + v + "\n";
        names += (names.empty() ? "" : ";") + k;
    }
    canonical += "\n" + names + "\n" + payload;
    const auto to_sign = std::string(sigv4::k_algorithm) + "\n" + amz_date + "\n" + scope.text() +
                         "\n" + sd::sha256_hex(canonical);
    const auto key = sigv4::derive_signing_key(creds._secret_access_key, scope);
    const auto signature = sd::to_hex(sd::hmac_sha256(key, to_sign));
    req._headers.emplace_back("Host", endpoint._host);
    req._headers.emplace_back("x-amz-content-sha256", payload);
    req._headers.emplace_back("x-amz-date", amz_date);
    if (!creds._session_token.empty()) {
        req._headers.emplace_back("x-amz-security-token", creds._session_token);
    }
    req._headers.emplace_back("Authorization", std::string(sigv4::k_algorithm) +
                                                   " Credential=" + creds._access_key_id + "/" +
                                                   scope.text() + ", SignedHeaders=" + names +
                                                   ", Signature=" + signature);
}

/// `application/x-www-form-urlencoded` / query-string encoding of one value
/// (RFC 3986 unreserved characters kept), as SigV4 canonicalizes it.
[[nodiscard]] inline auto aws_form_encode(std::string_view v) -> std::string {
    return sigv4::detail::uri_encode(v, /*keep_slash=*/false);
}

/// The text between `<tag>` and `</tag>`, the first occurrence after `from`;
/// nullopt when absent. Enough for the flat answers of query-protocol APIs.
[[nodiscard]] inline auto xml_text(std::string_view xml, std::string_view tag, std::size_t from = 0)
    -> std::optional<std::string> {
    const auto open = "<" + std::string(tag) + ">";
    const auto close = "</" + std::string(tag) + ">";
    const auto a = xml.find(open, from);
    if (a == std::string_view::npos) {
        return std::nullopt;
    }
    const auto b = xml.find(close, a + open.size());
    if (b == std::string_view::npos) {
        return std::nullopt;
    }
    std::string out;
    const auto body = xml.substr(a + open.size(), b - a - open.size());
    // The five predefined entities; nothing an STS answer carries needs more.
    for (std::size_t i = 0; i < body.size(); ++i) {
        if (body[i] != '&') {
            out.push_back(body[i]);
            continue;
        }
        static constexpr std::pair<std::string_view, char> entities[] = {
            {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}};
        bool matched = false;
        for (const auto& [name, ch] : entities) {
            if (body.substr(i, name.size()) == name) {
                out.push_back(ch);
                i += name.size() - 1;
                matched = true;
                break;
            }
        }
        if (!matched) {
            out.push_back('&');
        }
    }
    return out;
}

/// ISO 8601 `yyyy-mm-ddThh:mm:ss[.fff]Z` to milliseconds since the epoch;
/// nullopt when malformed.
[[nodiscard]] inline auto parse_iso8601_ms(std::string_view s) -> std::optional<std::int64_t> {
    if (s.size() < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s.back() != 'Z') {
        return std::nullopt;
    }
    auto num = [&](std::size_t at, std::size_t n) -> std::optional<int> {
        int v = 0;
        for (std::size_t i = at; i < at + n; ++i) {
            if (s[i] < '0' || s[i] > '9') {
                return std::nullopt;
            }
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    const auto y = num(0, 4);
    const auto mo = num(5, 2);
    const auto d = num(8, 2);
    const auto h = num(11, 2);
    const auto mi = num(14, 2);
    const auto se = num(17, 2);
    if (!y || !mo || !d || !h || !mi || !se || *mo < 1 || *mo > 12 || *d < 1 || *d > 31) {
        return std::nullopt;
    }
    const std::chrono::year_month_day ymd{std::chrono::year{*y},
                                          std::chrono::month{static_cast<unsigned>(*mo)},
                                          std::chrono::day{static_cast<unsigned>(*d)}};
    if (!ymd.ok()) {
        return std::nullopt;
    }
    const auto days = std::chrono::sys_days{ymd}.time_since_epoch().count();
    return ((static_cast<std::int64_t>(days) * 24 + *h) * 60 + *mi) * 60000 +
           static_cast<std::int64_t>(*se) * 1000;
}

}  // namespace kythira::kinesis
