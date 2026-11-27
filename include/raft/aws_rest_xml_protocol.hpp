// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file aws_rest_xml_protocol.hpp
/// @brief The AWS REST-XML protocol, as S3 speaks it
///        (.kiro/specs/s3-compatible-storage/ task 3; Requirements 4.1, 4.4
///        and 4.5).
///
/// REST-XML puts an operation's inputs in the method, the path, the query
/// string, headers and an XML body, and its outputs in the status, headers
/// and an XML body. This file has the pieces every handler needs and no
/// knowledge of any one service's operations:
///
///  - `parse_query`: the query string, percent-decoded, with a flag
///    sub-resource read the same with or without `=` (`?uploads` and
///    `?uploads=`; the Go and JS SDKs and rclone send the second).
///  - `parse_resource`: bucket and key from `Host` and the path, for both
///    addressing styles. A `Host` of `<bucket>.<domain>` for a configured
///    endpoint domain is virtual-hosted; anything else (the domain itself,
///    an IP address, `localhost`) is path style. Bucket names are checked
///    against S3's rules for new buckets, keys against its 1024-byte limit.
///  - `router`: picks the operation from a table the service supplies (S3's
///    comes from its pinned model). It matches the method, whether the path
///    names a bucket and a key, the literal query keys of the operation's
///    `requestUri`, and its required query parameters and headers; the most
///    specific match wins. `x-id`, which SDKs add to name the operation,
///    never routes.
///  - `parse_xml`: a small, strict XML reader for request bodies. It refuses
///    DTDs (so no external entities and no entity expansion), knows only
///    the five predefined entities and character references, bounds depth
///    and element count, and checks UTF-8.
///  - Response helpers: an XML document with S3's namespace, S3's error
///    document, the two timestamp formats S3 uses, and key encoding for
///    `encoding-type=url`.
///
/// Errors carry S3's code and HTTP status (`error`), so a handler returns
/// them as they are. `Expect: 100-continue` and the request size limits
/// (Requirements 4.4, 4.5) are the listener's: `https::server` answers 100
/// after the headers and before the body, and its `server_config` limits
/// are where the gateway sets S3's (`limits` below names them).
///
/// Plain functions over strings, so it has no Raft or S3 dependency; the
/// other REST-XML services (SNS's and SQS's legacy forms, CloudFront) can
/// use it.

#include <raft/aws_query_protocol.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <functional>
#include <initializer_list>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::aws_rest_xml {

/// S3's XML namespace, on the root of every response document but errors.
inline constexpr std::string_view s3_namespace = "http://s3.amazonaws.com/doc/2006-03-01/";

/// S3's request limits, for the gateway's listener configuration and its
/// own checks (Requirement 4.5: never lower than S3's).
struct limits {
    /// Object keys are at most 1024 bytes of UTF-8.
    static constexpr std::size_t max_key_bytes = 1024;
    /// User metadata (`x-amz-meta-*` names and values) is at most 2 KB.
    static constexpr std::size_t max_user_metadata_bytes = 2048;
    /// S3 accepts request headers up to 8 KB in total; the listener's
    /// header limit must be at least this.
    static constexpr std::size_t min_header_bytes = 8 * 1024;
    /// The largest single PUT is 5 GiB.
    static constexpr std::uint64_t max_put_bytes = std::uint64_t{5} * 1024 * 1024 * 1024;
};

/// An S3 error: what the response's status and `<Code>` say.
struct error {
    unsigned status = 400;
    std::string code;
    std::string message;
    /// Further `<Error>` members after `<Message>`, in order (`BucketName`,
    /// `Key`, `ArgumentName`, ...).
    std::vector<std::pair<std::string, std::string>> extra;
};

/// The errors this layer raises. Handlers build their own the same way.
namespace errors {

[[nodiscard]] inline auto make(unsigned status, std::string code, std::string message) -> error {
    return error{status, std::move(code), std::move(message), {}};
}
[[nodiscard]] inline auto invalid_bucket_name(std::string_view bucket) -> error {
    auto e = make(400, "InvalidBucketName", "The specified bucket is not valid.");
    e.extra.emplace_back("BucketName", std::string(bucket));
    return e;
}
[[nodiscard]] inline auto invalid_uri(std::string message) -> error {
    return make(400, "InvalidURI", std::move(message));
}
[[nodiscard]] inline auto key_too_long() -> error {
    return make(400, "KeyTooLongError", "Your key is too long");
}
[[nodiscard]] inline auto method_not_allowed() -> error {
    return make(405, "MethodNotAllowed",
                "The specified method is not allowed against this resource.");
}
[[nodiscard]] inline auto malformed_xml(std::string detail) -> error {
    // S3's message is fixed; the detail helps whoever reads the log.
    auto e = make(400, "MalformedXML",
                  "The XML you provided was not well-formed or did not validate against our "
                  "published schema");
    if (!detail.empty()) {
        e.extra.emplace_back("Detail", std::move(detail));
    }
    return e;
}

}  // namespace errors

/// A value or the S3 error to answer with (`aws_json::result`'s shape; see
/// there for why not `std::expected`).
template<typename T> class result {
public:
    result(T value)
        : _v(std::in_place_index<0>, std::move(value)) {}  // NOLINT(google-explicit-constructor)
    result(aws_rest_xml::error e)
        : _v(std::in_place_index<1>, std::move(e)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const noexcept -> bool { return _v.index() == 0; }
    explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] auto value() & -> T& { return std::get<0>(_v); }
    [[nodiscard]] auto value() const& -> const T& { return std::get<0>(_v); }
    [[nodiscard]] auto operator*() & -> T& { return value(); }
    [[nodiscard]] auto operator*() const& -> const T& { return value(); }
    [[nodiscard]] auto operator->() -> T* { return &value(); }
    [[nodiscard]] auto operator->() const -> const T* { return &value(); }
    /// The error. Only meaningful when `!has_value()`.
    [[nodiscard]] auto error() const& -> const aws_rest_xml::error& { return std::get<1>(_v); }

private:
    std::variant<T, aws_rest_xml::error> _v;
};

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

namespace detail {

[[nodiscard]] constexpr auto ascii_lower(char c) noexcept -> char {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] inline auto iequals(std::string_view a, std::string_view b) noexcept -> bool {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return ascii_lower(x) == ascii_lower(y);
           });
}

/// Split "a,b,c" (the model table's lists); an empty string is no items.
[[nodiscard]] inline auto split_list(std::string_view s) -> std::vector<std::string_view> {
    std::vector<std::string_view> out;
    while (!s.empty()) {
        const auto comma = s.find(',');
        out.push_back(s.substr(0, comma));
        if (comma == std::string_view::npos) {
            break;
        }
        s.remove_prefix(comma + 1);
    }
    return out;
}

/// Append code point `cp` as UTF-8.
inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80U) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800U) {
        out += static_cast<char>(0xC0U | (cp >> 6U));
        out += static_cast<char>(0x80U | (cp & 0x3FU));
    } else if (cp < 0x10000U) {
        out += static_cast<char>(0xE0U | (cp >> 12U));
        out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU));
        out += static_cast<char>(0x80U | (cp & 0x3FU));
    } else {
        out += static_cast<char>(0xF0U | (cp >> 18U));
        out += static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU));
        out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU));
        out += static_cast<char>(0x80U | (cp & 0x3FU));
    }
}

}  // namespace detail

/// Whether `s` is well-formed UTF-8: no overlong forms, no surrogates,
/// nothing above U+10FFFF.
[[nodiscard]] inline auto valid_utf8(std::string_view s) noexcept -> bool {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80U) {
            ++i;
            continue;
        }
        std::size_t len = 0;
        std::uint32_t cp = 0;
        std::uint32_t min = 0;
        if (c >= 0xC2U && c <= 0xDFU) {
            len = 2;
            cp = c & 0x1FU;
            min = 0x80U;
        } else if (c >= 0xE0U && c <= 0xEFU) {
            len = 3;
            cp = c & 0x0FU;
            min = 0x800U;
        } else if (c >= 0xF0U && c <= 0xF4U) {
            len = 4;
            cp = c & 0x07U;
            min = 0x10000U;
        } else {
            return false;
        }
        if (i + len > s.size()) {
            return false;
        }
        for (std::size_t k = 1; k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0U) != 0x80U) {
                return false;
            }
            cp = (cp << 6U) | (cc & 0x3FU);
        }
        if (cp < min || cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU)) {
            return false;
        }
        i += len;
    }
    return true;
}

/// Percent-decoding. `plus_is_space` for query strings, where S3 reads '+'
/// as a space (form encoding); never for paths, where '+' is a '+'. A '%'
/// without two hex digits after it is an error.
[[nodiscard]] inline auto percent_decode(std::string_view in, bool plus_is_space)
    -> std::optional<std::string> {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size()) {
                return std::nullopt;
            }
            const int hi = aws_query::detail::hex_digit(in[i + 1]);
            const int lo = aws_query::detail::hex_digit(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            out += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else if (c == '+' && plus_is_space) {
            out += ' ';
        } else {
            out += c;
        }
    }
    return out;
}

/// A key for a listing with `encoding-type=url`: percent-encoding of every
/// byte but the unreserved characters and '/', with a space as '+' (and so
/// '+' itself as %2B), which is how S3 encodes them and what botocore's
/// `unquote_plus` and the other SDKs decode.
[[nodiscard]] inline auto url_encode_key(std::string_view key) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(key.size());
    for (const char ch : key) {
        const auto c = static_cast<unsigned char>(ch);
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                                c == '~' || c == '/';
        if (unreserved) {
            out += ch;
        } else if (c == ' ') {
            out += '+';
        } else {
            out += '%';
            out += hex[c >> 4U];
            out += hex[c & 0x0FU];
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Query string
// ---------------------------------------------------------------------------

/// A decoded query string, in request order. A key without `=` has an
/// empty value, the same as `key=`: S3 does not tell them apart.
class query {
public:
    query() = default;
    explicit query(std::vector<std::pair<std::string, std::string>> params)
        : _params(std::move(params)) {}

    [[nodiscard]] auto has(std::string_view key) const -> bool { return find(key) != nullptr; }
    /// The first value of `key`.
    [[nodiscard]] auto get(std::string_view key) const -> std::optional<std::string> {
        if (const auto* v = find(key)) {
            return *v;
        }
        return std::nullopt;
    }
    [[nodiscard]] auto params() const noexcept
        -> const std::vector<std::pair<std::string, std::string>>& {
        return _params;
    }
    [[nodiscard]] auto empty() const noexcept -> bool { return _params.empty(); }

private:
    [[nodiscard]] auto find(std::string_view key) const -> const std::string* {
        for (const auto& [k, v] : _params) {
            if (k == key) {
                return &v;
            }
        }
        return nullptr;
    }

    std::vector<std::pair<std::string, std::string>> _params;
};

/// Decode a query string (without the '?'). Empty pieces (`a=1&&b=2`) are
/// skipped. Query keys are case-sensitive, as on S3.
[[nodiscard]] inline auto parse_query(std::string_view raw) -> result<query> {
    std::vector<std::pair<std::string, std::string>> params;
    while (!raw.empty()) {
        const auto amp = raw.find('&');
        const auto piece = raw.substr(0, amp);
        raw = amp == std::string_view::npos ? std::string_view{} : raw.substr(amp + 1);
        if (piece.empty()) {
            continue;
        }
        const auto eq = piece.find('=');
        auto key = percent_decode(piece.substr(0, eq), true);
        auto value = eq == std::string_view::npos ? std::optional<std::string>{std::string{}}
                                                  : percent_decode(piece.substr(eq + 1), true);
        if (!key || !value) {
            return errors::invalid_uri("Couldn't parse the specified URI.");
        }
        params.emplace_back(std::move(*key), std::move(*value));
    }
    return query{std::move(params)};
}

// ---------------------------------------------------------------------------
// Addressing
// ---------------------------------------------------------------------------

/// Whether `name` is a bucket name S3 accepts for a new bucket (general
/// purpose buckets, "Bucket naming rules"): 3 to 63 characters of
/// lower-case letters, digits, '.' and '-'; a letter or digit at each end;
/// no ".." and no '.' next to '-' (so it is a valid DNS name); not an IPv4
/// address; none of S3's reserved prefixes and suffixes.
[[nodiscard]] inline auto valid_bucket_name(std::string_view name) noexcept -> bool {
    if (name.size() < 3 || name.size() > 63) {
        return false;
    }
    auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!alnum(name.front()) || !alnum(name.back())) {
        return false;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        if (!alnum(c) && c != '.' && c != '-') {
            return false;
        }
        if (c == '.' && i + 1 < name.size()) {
            const char n = name[i + 1];
            if (n == '.' || n == '-') {
                return false;
            }
        }
        if (c == '-' && i + 1 < name.size() && name[i + 1] == '.') {
            return false;
        }
    }
    // An IPv4 address in dotted form: four all-digit labels.
    {
        int labels = 0;
        bool all_digits = true;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= name.size(); ++i) {
            if (i == name.size() || name[i] == '.') {
                ++labels;
                for (std::size_t k = start; k < i; ++k) {
                    all_digits = all_digits && name[k] >= '0' && name[k] <= '9';
                }
                start = i + 1;
            }
        }
        if (labels == 4 && all_digits) {
            return false;
        }
    }
    static constexpr std::array<std::string_view, 4> prefixes{"xn--", "sthree-", "amzn-s3-demo-",
                                                              "sthree-configurator"};
    static constexpr std::array<std::string_view, 5> suffixes{"-s3alias", "--ol-s3", ".mrap",
                                                              "--x-s3", "--table-s3"};
    return std::none_of(prefixes.begin(), prefixes.end(),
                        [&](std::string_view p) { return name.starts_with(p); }) &&
           std::none_of(suffixes.begin(), suffixes.end(),
                        [&](std::string_view s) { return name.ends_with(s); });
}

enum class addressing_style : std::uint8_t {
    /// `/bucket/key` on the endpoint's own name, an IP address, or any host
    /// that is not `bucket.domain`.
    path,
    /// `bucket.<domain>/key`.
    virtual_hosted,
};

/// Bucket and key a request names. Both empty: the service (ListBuckets).
/// A bucket and an empty key: the bucket.
struct resource {
    std::string bucket;
    std::string key;
    addressing_style style = addressing_style::path;
};

/// The endpoint domains virtual-hosted requests are recognised under, e.g.
/// `s3.example.com` (so `photos.s3.example.com` is bucket `photos`).
/// Matching is case-insensitive and ignores a port.
struct addressing_config {
    std::vector<std::string> domains;
};

/// Bucket and key from the `Host` header and the request path (target
/// without its query). The key is percent-decoded ('+' stays '+'), must be
/// valid UTF-8 and at most 1024 bytes. A path-style `/bucket/` names the
/// bucket, as on S3.
[[nodiscard]] inline auto parse_resource(std::string_view host, std::string_view path,
                                         const addressing_config& config) -> result<resource> {
    // The host without a port (an IPv6 literal keeps its brackets).
    if (const auto colon = host.rfind(':');
        colon != std::string_view::npos && host.find(']', colon) == std::string_view::npos) {
        host = host.substr(0, colon);
    }
    while (host.ends_with('.')) {
        host.remove_suffix(1);  // a fully-qualified "bucket.s3.example.com."
    }
    if (!path.starts_with('/')) {
        return errors::invalid_uri("Couldn't parse the specified URI.");
    }
    path.remove_prefix(1);

    resource out;
    std::string_view raw_key;
    std::optional<std::string> vhost_bucket;
    for (const auto& domain : config.domains) {
        if (host.size() > domain.size() + 1 &&
            detail::iequals(host.substr(host.size() - domain.size()), domain) &&
            host[host.size() - domain.size() - 1] == '.') {
            std::string bucket(host.substr(0, host.size() - domain.size() - 1));
            std::transform(bucket.begin(), bucket.end(), bucket.begin(), detail::ascii_lower);
            vhost_bucket = std::move(bucket);
            break;
        }
    }
    if (vhost_bucket) {
        out.style = addressing_style::virtual_hosted;
        out.bucket = std::move(*vhost_bucket);
        raw_key = path;
    } else {
        out.style = addressing_style::path;
        const auto slash = path.find('/');
        auto bucket = percent_decode(path.substr(0, slash), false);
        if (!bucket) {
            return errors::invalid_uri("Couldn't parse the specified URI.");
        }
        out.bucket = std::move(*bucket);
        raw_key = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);
    }
    if (!out.bucket.empty() && !valid_bucket_name(out.bucket)) {
        return errors::invalid_bucket_name(out.bucket);
    }
    auto key = percent_decode(raw_key, false);
    if (!key || !valid_utf8(*key)) {
        return errors::invalid_uri("Couldn't parse the specified URI.");
    }
    if (key->size() > limits::max_key_bytes) {
        return errors::key_too_long();
    }
    out.key = std::move(*key);
    return out;
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// One operation as the router sees it: the fields of a service's model
/// table (S3's `model::operation_info`) that routing needs.
struct route {
    std::string_view name;
    std::string_view method;
    /// `/`, `/{Bucket}` or `/{Bucket}/{Key+}`, then optionally `?` and the
    /// literal query keys, '&'-separated, each with an optional `=value`.
    std::string_view request_uri;
    /// Required query parameters and headers by wire name, comma-separated.
    std::string_view required_query;
    std::string_view required_headers;
    bool deprecated = false;
};

/// What a request's path names, for matching against `/{Bucket}/{Key+}`.
enum class path_kind : std::uint8_t {
    service,
    bucket,
    object
};

[[nodiscard]] inline auto kind_of(const resource& r) noexcept -> path_kind {
    if (r.bucket.empty()) {
        return path_kind::service;
    }
    return r.key.empty() ? path_kind::bucket : path_kind::object;
}

/// Picks an operation for a request from a service's route table.
///
/// A route matches when its method and path kind are the request's, every
/// literal query key of its `request_uri` is present (with the value, where
/// the URI gives one: `list-type=2`), and every required query parameter
/// and header is present. Of the matches the most specific wins: more
/// literal keys, then more required members, then not deprecated (S3's
/// deprecated operations share their replacement's wire form, and S3
/// answers with the replacement); remaining ties go to the earlier route.
///
/// A request with a query key that is some route's literal sub-resource
/// (`uploads`, `tagging`, `acl`, ...) but which the winning route does not
/// use is refused with MethodNotAllowed, as `PUT /bucket?uploads` is on
/// S3, rather than quietly served as the plainer operation
/// (CreateBucket). `x-id`, which the Go and JS SDKs and rclone add, takes no
/// part in routing.
class router {
public:
    /// `routes` must outlive the router. Routes named in `unrouted` are
    /// never chosen: operations whose wire form only another endpoint tells
    /// apart (S3's ListDirectoryBuckets is ListBuckets on a zonal endpoint;
    /// WriteGetObjectResponse lives on an Object Lambda host). Any other
    /// route whose path is not one of the three forms throws.
    explicit router(std::span<const route> routes,
                    std::initializer_list<std::string_view> unrouted = {}) {
        const std::set<std::string_view> skip(unrouted.begin(), unrouted.end());
        for (const auto& r : routes) {
            if (skip.contains(r.name)) {
                continue;
            }
            compiled c;
            c._route = &r;
            const auto q = r.request_uri.find('?');
            const auto path = r.request_uri.substr(0, q);
            if (path == "/") {
                c._kind = path_kind::service;
            } else if (path == "/{Bucket}") {
                c._kind = path_kind::bucket;
            } else if (path == "/{Bucket}/{Key+}") {
                c._kind = path_kind::object;
            } else {
                throw std::invalid_argument("aws_rest_xml::router: unsupported request URI " +
                                            std::string(r.request_uri) + " for " +
                                            std::string(r.name));
            }
            if (q != std::string_view::npos) {
                std::string_view lits = r.request_uri.substr(q + 1);
                while (!lits.empty()) {
                    const auto amp = lits.find('&');
                    const auto lit = lits.substr(0, amp);
                    lits =
                        amp == std::string_view::npos ? std::string_view{} : lits.substr(amp + 1);
                    const auto eq = lit.find('=');
                    literal l;
                    l._key = lit.substr(0, eq);
                    if (eq != std::string_view::npos) {
                        l._value = lit.substr(eq + 1);
                    }
                    if (l._key == "x-id") {
                        continue;  // names the operation; never routes
                    }
                    _sub_resources.insert(std::string(l._key));
                    c._literals.push_back(l);
                }
            }
            c._query = detail::split_list(r.required_query);
            c._headers = detail::split_list(r.required_headers);
            _routes.push_back(std::move(c));
        }
    }

    /// Looks a header up by name, case-insensitively, in whatever the
    /// caller holds the request in.
    using header_fn = std::function<bool(std::string_view name)>;

    /// The operation for a request, or MethodNotAllowed.
    [[nodiscard]] auto match(std::string_view method, path_kind kind, const query& q,
                             const header_fn& has_header) const -> result<const route*> {
        const compiled* best = nullptr;
        std::array<int, 3> best_score{-1, -1, -1};
        for (const auto& c : _routes) {
            if (c._kind != kind || c._route->method != method) {
                continue;
            }
            const bool literals_ok =
                std::all_of(c._literals.begin(), c._literals.end(), [&](const literal& l) {
                    auto v = q.get(l._key);
                    return v && (!l._value || *v == *l._value);
                });
            const bool query_ok = std::all_of(c._query.begin(), c._query.end(),
                                              [&](std::string_view k) { return q.has(k); });
            const bool headers_ok = std::all_of(c._headers.begin(), c._headers.end(),
                                                [&](std::string_view h) { return has_header(h); });
            if (!literals_ok || !query_ok || !headers_ok) {
                continue;
            }
            const std::array<int, 3> score{static_cast<int>(c._literals.size()),
                                           static_cast<int>(c._query.size() + c._headers.size()),
                                           c._route->deprecated ? 0 : 1};
            if (score > best_score) {
                best_score = score;
                best = &c;
            }
        }
        if (best == nullptr) {
            return errors::method_not_allowed();
        }
        for (const auto& [k, v] : q.params()) {
            if (_sub_resources.contains(k) &&
                std::none_of(best->_literals.begin(), best->_literals.end(),
                             [&](const literal& l) { return l._key == k; })) {
                return errors::method_not_allowed();
            }
        }
        return best->_route;
    }

    /// The literal sub-resource keys of every route (`uploads`, `tagging`,
    /// `list-type`, ...): what SigV2-era tooling called sub-resources.
    [[nodiscard]] auto sub_resources() const noexcept -> const std::set<std::string, std::less<>>& {
        return _sub_resources;
    }

private:
    struct literal {
        std::string_view _key;
        std::optional<std::string_view> _value;
    };
    struct compiled {
        const route* _route = nullptr;
        path_kind _kind = path_kind::service;
        std::vector<literal> _literals;
        std::vector<std::string_view> _query;
        std::vector<std::string_view> _headers;
    };

    std::vector<compiled> _routes;
    std::set<std::string, std::less<>> _sub_resources;
};

// ---------------------------------------------------------------------------
// XML reading
// ---------------------------------------------------------------------------

/// One element of a parsed document. Names are local names: a namespace
/// prefix is dropped (`<s3:Key>` is `Key`), and `xmlns` attributes are kept
/// with the others. S3's schemas use a default namespace or none, so
/// handlers match by local name.
struct xml_element {
    std::string name;
    std::vector<std::pair<std::string, std::string>> attributes;
    /// The element's character data, entities decoded, CDATA included,
    /// whitespace kept. For an element with children it is whatever text
    /// sits between them (usually indentation).
    std::string text;
    std::vector<xml_element> children;

    /// The first child named `local_name`, or null.
    [[nodiscard]] auto child(std::string_view local_name) const -> const xml_element* {
        for (const auto& c : children) {
            if (c.name == local_name) {
                return &c;
            }
        }
        return nullptr;
    }
    /// The text of the first child named `local_name`.
    [[nodiscard]] auto child_text(std::string_view local_name) const -> std::optional<std::string> {
        if (const auto* c = child(local_name)) {
            return c->text;
        }
        return std::nullopt;
    }
    /// Every child named `local_name`, in document order.
    [[nodiscard]] auto children_named(std::string_view local_name) const
        -> std::vector<const xml_element*> {
        std::vector<const xml_element*> out;
        for (const auto& c : children) {
            if (c.name == local_name) {
                out.push_back(&c);
            }
        }
        return out;
    }
    [[nodiscard]] auto attribute(std::string_view name_) const -> std::optional<std::string> {
        for (const auto& [k, v] : attributes) {
            if (k == name_) {
                return v;
            }
        }
        return std::nullopt;
    }
};

/// Bounds on what `parse_xml` will build. The body size is the caller's
/// (the listener's body limit, or a per-operation one).
struct xml_limits {
    std::size_t max_depth = 32;
    std::size_t max_elements = 100'000;
};

namespace detail {

class xml_parser {
public:
    xml_parser(std::string_view doc, const xml_limits& lim) : _s(doc), _lim(lim) {}

    auto parse() -> result<xml_element> {
        if (!valid_utf8(_s)) {
            return fail("not UTF-8");
        }
        if (_s.starts_with("\xEF\xBB\xBF")) {
            _p = 3;
        }
        if (looking_at("<?xml") && _p + 5 < _s.size() && is_space(_s[_p + 5])) {
            if (!skip_past("?>")) {
                return fail("unterminated XML declaration");
            }
        }
        if (!misc()) {
            return fail(_why);
        }
        if (looking_at("<!DOCTYPE") || looking_at("<!doctype")) {
            return fail("document type declarations are not accepted");
        }
        if (!looking_at("<")) {
            return fail("no root element");
        }
        xml_element root;
        if (!element(root, 1)) {
            return fail(_why);
        }
        if (!misc()) {
            return fail(_why);
        }
        if (_p != _s.size()) {
            return fail("content after the root element");
        }
        return root;
    }

private:
    [[nodiscard]] static auto is_space(char c) noexcept -> bool {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }
    [[nodiscard]] static auto name_start(char c) noexcept -> bool {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == ':' ||
               static_cast<unsigned char>(c) >= 0x80U;
    }
    [[nodiscard]] static auto name_char(char c) noexcept -> bool {
        return name_start(c) || (c >= '0' && c <= '9') || c == '-' || c == '.';
    }
    [[nodiscard]] auto looking_at(std::string_view t) const noexcept -> bool {
        return _s.substr(_p).starts_with(t);
    }
    auto skip_past(std::string_view t) -> bool {
        const auto at = _s.find(t, _p);
        if (at == std::string_view::npos) {
            return false;
        }
        _p = at + t.size();
        return true;
    }
    void skip_space() {
        while (_p < _s.size() && is_space(_s[_p])) {
            ++_p;
        }
    }
    auto fail_bool(std::string why) -> bool {
        _why = std::move(why);
        return false;
    }
    [[nodiscard]] auto fail(std::string why) const -> error {
        return errors::malformed_xml(std::move(why));
    }

    /// Whitespace, comments and processing instructions.
    auto misc() -> bool {
        while (true) {
            skip_space();
            if (looking_at("<!--")) {
                if (!skip_past("-->")) {
                    return fail_bool("unterminated comment");
                }
            } else if (looking_at("<?")) {
                if (!skip_past("?>")) {
                    return fail_bool("unterminated processing instruction");
                }
            } else {
                return true;
            }
        }
    }

    auto name(std::string& out) -> bool {
        if (_p >= _s.size() || !name_start(_s[_p])) {
            return fail_bool("expected a name");
        }
        const auto start = _p;
        while (_p < _s.size() && name_char(_s[_p])) {
            ++_p;
        }
        out.assign(_s.substr(start, _p - start));
        return true;
    }

    /// Character data up to `stop`, entities decoded and line ends
    /// normalised, appended to `out`.
    auto chars(std::string& out, char stop) -> bool {
        while (_p < _s.size() && _s[_p] != stop) {
            const char c = _s[_p];
            if (c == '<' && stop != '<') {
                return fail_bool("'<' in an attribute value");
            }
            if (c == '&') {
                if (!entity(out)) {
                    return false;
                }
                continue;
            }
            if (c == '\r') {
                out += '\n';
                ++_p;
                if (_p < _s.size() && _s[_p] == '\n') {
                    ++_p;
                }
                continue;
            }
            if (static_cast<unsigned char>(c) < 0x20U && c != '\t' && c != '\n') {
                return fail_bool("a control character");
            }
            out += c;
            ++_p;
        }
        return true;
    }

    auto entity(std::string& out) -> bool {
        const auto semi = _s.find(';', _p);
        if (semi == std::string_view::npos || semi - _p > 12) {
            return fail_bool("an unterminated entity reference");
        }
        const auto ref = _s.substr(_p + 1, semi - _p - 1);
        _p = semi + 1;
        if (ref == "lt") {
            out += '<';
        } else if (ref == "gt") {
            out += '>';
        } else if (ref == "amp") {
            out += '&';
        } else if (ref == "quot") {
            out += '"';
        } else if (ref == "apos") {
            out += '\'';
        } else if (ref.starts_with('#')) {
            std::uint32_t cp = 0;
            const bool hex = ref.size() > 1 && ref[1] == 'x';
            const auto digits = ref.substr(hex ? 2 : 1);
            if (digits.empty() || digits.size() > 8) {
                return fail_bool("a bad character reference");
            }
            for (const char d : digits) {
                const int v =
                    hex ? aws_query::detail::hex_digit(d) : (d >= '0' && d <= '9' ? d - '0' : -1);
                if (v < 0) {
                    return fail_bool("a bad character reference");
                }
                cp = cp * (hex ? 16U : 10U) + static_cast<std::uint32_t>(v);
            }
            const bool allowed =
                cp == 0x9U || cp == 0xAU || cp == 0xDU || (cp >= 0x20U && cp <= 0xD7FFU) ||
                (cp >= 0xE000U && cp <= 0xFFFDU) || (cp >= 0x10000U && cp <= 0x10FFFFU);
            if (!allowed) {
                return fail_bool("a character reference to a character XML cannot carry");
            }
            append_utf8(out, cp);
        } else {
            return fail_bool("an undefined entity");
        }
        return true;
    }

    [[nodiscard]] static auto local(std::string_view qname) -> std::string {
        const auto colon = qname.find(':');
        return std::string(colon == std::string_view::npos ? qname : qname.substr(colon + 1));
    }

    auto element(xml_element& el, std::size_t depth) -> bool {
        if (depth > _lim.max_depth) {
            return fail_bool("nested too deeply");
        }
        if (++_elements > _lim.max_elements) {
            return fail_bool("too many elements");
        }
        ++_p;  // '<'
        std::string qname;
        if (!name(qname)) {
            return false;
        }
        el.name = local(qname);
        // Attributes.
        while (true) {
            const auto before = _p;
            skip_space();
            if (looking_at("/>")) {
                _p += 2;
                return true;
            }
            if (looking_at(">")) {
                ++_p;
                break;
            }
            if (_p == before) {
                return fail_bool("expected whitespace before an attribute");
            }
            std::string attr;
            if (!name(attr)) {
                return false;
            }
            skip_space();
            if (!looking_at("=")) {
                return fail_bool("an attribute without a value");
            }
            ++_p;
            skip_space();
            if (_p >= _s.size() || (_s[_p] != '"' && _s[_p] != '\'')) {
                return fail_bool("an unquoted attribute value");
            }
            const char quote = _s[_p++];
            std::string value;
            if (!chars(value, quote) || _p >= _s.size()) {
                return _why.empty() ? fail_bool("an unterminated attribute value") : false;
            }
            ++_p;  // closing quote
            for (const auto& [k, v] : el.attributes) {
                if (k == attr) {
                    return fail_bool("a repeated attribute");
                }
            }
            el.attributes.emplace_back(std::move(attr), std::move(value));
        }
        // Content.
        while (true) {
            if (_p >= _s.size()) {
                return fail_bool("unterminated element " + qname);
            }
            if (looking_at("</")) {
                _p += 2;
                std::string end;
                if (!name(end)) {
                    return false;
                }
                skip_space();
                if (end != qname || !looking_at(">")) {
                    return fail_bool("mismatched end tag " + end + " for " + qname);
                }
                ++_p;
                return true;
            }
            if (looking_at("<!--")) {
                if (!skip_past("-->")) {
                    return fail_bool("unterminated comment");
                }
            } else if (looking_at("<![CDATA[")) {
                const auto start = _p + 9;
                const auto end = _s.find("]]>", start);
                if (end == std::string_view::npos) {
                    return fail_bool("unterminated CDATA section");
                }
                el.text.append(_s.substr(start, end - start));
                _p = end + 3;
            } else if (looking_at("<?")) {
                if (!skip_past("?>")) {
                    return fail_bool("unterminated processing instruction");
                }
            } else if (looking_at("<!")) {
                return fail_bool("a declaration inside an element");
            } else if (looking_at("<")) {
                el.children.emplace_back();
                if (!element(el.children.back(), depth + 1)) {
                    return false;
                }
            } else if (!chars(el.text, '<')) {
                return false;
            }
        }
    }

    std::string_view _s;
    std::size_t _p = 0;
    xml_limits _lim;
    std::size_t _elements = 0;
    std::string _why;
};

}  // namespace detail

/// Parse a request body. Any problem is S3's MalformedXML, with what was
/// wrong in a `Detail` member.
[[nodiscard]] inline auto parse_xml(std::string_view doc, const xml_limits& lim = {})
    -> result<xml_element> {
    return detail::xml_parser(doc, lim).parse();
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// The declaration every S3 XML response starts with.
inline constexpr std::string_view xml_declaration = R"(<?xml version="1.0" encoding="UTF-8"?>)";

/// A response document: the declaration and `root` opened with S3's
/// namespace. Write the members, then `close()` the root.
[[nodiscard]] inline auto document(std::string_view root, std::string_view ns = s3_namespace)
    -> aws_query::xml_writer {
    aws_query::xml_writer w;
    w.raw(xml_declaration);
    w.open(root, ns);
    return w;
}

/// S3's error document: `<Error><Code/><Message/>...extra...<RequestId/>
/// <HostId/></Error>`, with no namespace. A HEAD response carries none
/// (the status says it all).
[[nodiscard]] inline auto error_xml(const error& e, std::string_view request_id,
                                    std::string_view host_id = {}) -> std::string {
    aws_query::xml_writer w;
    w.raw(xml_declaration);
    w.open("Error");
    w.element("Code", e.code);
    w.element("Message", e.message);
    for (const auto& [k, v] : e.extra) {
        w.element(k, v);
    }
    w.element("RequestId", request_id);
    if (!host_id.empty()) {
        w.element("HostId", host_id);
    }
    w.close();
    return w.str();
}

/// `2009-10-12T17:50:30.000Z`: timestamps inside S3's XML (LastModified,
/// Initiated, CreationDate).
[[nodiscard]] inline auto iso8601_ms(std::chrono::system_clock::time_point t) -> std::string {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch());
    auto secs = static_cast<std::time_t>(std::chrono::floor<std::chrono::seconds>(ms).count());
    const auto frac = static_cast<int>(ms.count() - (static_cast<std::int64_t>(secs) * 1000));
    std::tm tm{};
    ::gmtime_r(&secs, &tm);
    std::array<char, 32> buf{};
    const auto n = std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%S", &tm);
    std::array<char, 8> tail{};
    std::snprintf(tail.data(), tail.size(), ".%03dZ", frac);
    return std::string(buf.data(), n) + tail.data();
}

/// `Mon, 12 Oct 2009 17:50:30 GMT`: timestamps in S3's headers
/// (Last-Modified, Expires, x-amz-restore). Always the C locale's names.
[[nodiscard]] inline auto http_date(std::chrono::system_clock::time_point t) -> std::string {
    static constexpr std::array<std::string_view, 7> days{"Sun", "Mon", "Tue", "Wed",
                                                          "Thu", "Fri", "Sat"};
    static constexpr std::array<std::string_view, 12> months{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    auto secs = std::chrono::system_clock::to_time_t(std::chrono::floor<std::chrono::seconds>(t));
    std::tm tm{};
    ::gmtime_r(&secs, &tm);
    std::array<char, 40> buf{};
    std::snprintf(buf.data(), buf.size(), "%s, %02d %s %04d %02d:%02d:%02d GMT",
                  days.at(static_cast<std::size_t>(tm.tm_wday)).data(), tm.tm_mday,
                  months.at(static_cast<std::size_t>(tm.tm_mon)).data(), tm.tm_year + 1900,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf.data();
}

}  // namespace kythira::aws_rest_xml
