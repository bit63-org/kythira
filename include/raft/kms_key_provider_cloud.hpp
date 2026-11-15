// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_key_provider_cloud.hpp
/// @brief What the Azure Key Vault and GCP Cloud KMS key providers share
///        (kms_key_provider_azure.hpp, kms_key_provider_gcp.hpp): an HTTP
///        transport by URL, OAuth 2.0 bearer tokens cached until shortly
///        before they expire, base64 in both alphabets, and the encoding
///        that binds a data key to its encryption context.
///
/// Neither cloud's key service takes an encryption context as AWS KMS
/// does. GCP Cloud KMS takes additional authenticated data, and the
/// providers pass `context_binding(context)` there; Azure Key Vault's
/// wrapKey takes nothing, so its provider wraps the data key together with
/// a digest of the binding and checks the digest on unwrap. Either way a
/// data key wrapped under one context does not unwrap under another.

#include <raft/https_peer_client.hpp>
#include <raft/kms_key_provider.hpp>

#include <boost/json.hpp>

#include <openssl/evp.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kms_provider {

/// One HTTP exchange: (method, "https://host[:port]/path?query", headers,
/// body) to the answer, nullopt when nothing answered. Tests put a fake
/// cloud here.
using http_transport = std::function<std::optional<https_peer::peer_response>(
    boost::beast::http::verb method, const std::string& url,
    const https_peer::peer_client::headers& headers, std::string body)>;

/// An OAuth 2.0 access token and when it stops working.
struct access_token {
    std::string _value;
    /// `time_point::max()` for a token whose lifetime is not known.
    std::chrono::system_clock::time_point _expires = std::chrono::system_clock::time_point::max();
};

namespace cloud_detail {

struct parsed_url {
    bool _tls = true;
    std::string _host_port;
    std::string _target;
};

/// "https://host[:port][/path]" (or http) split; the port defaults by
/// scheme. nullopt for anything else.
[[nodiscard]] inline auto parse_url(std::string_view url) -> std::optional<parsed_url> {
    parsed_url out;
    if (url.starts_with("https://")) {
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        out._tls = false;
        url.remove_prefix(7);
    } else {
        return std::nullopt;
    }
    const auto slash = url.find('/');
    auto authority = url.substr(0, slash);
    out._target = slash == std::string_view::npos ? "/" : std::string(url.substr(slash));
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        return std::nullopt;
    }
    const auto close = authority.rfind(']');
    const auto colon = authority.rfind(':');
    const bool has_port =
        colon != std::string_view::npos && (close == std::string_view::npos || colon > close);
    out._host_port =
        has_port ? std::string(authority) : std::string(authority) + (out._tls ? ":443" : ":80");
    return out;
}

/// The default transport: core's `peer_client`, HTTPS against the system
/// store or `ca_path`, plain HTTP only where the URL says so (the clouds'
/// metadata services).
[[nodiscard]] inline auto default_transport(const std::string& ca_path,
                                            std::chrono::milliseconds timeout) -> http_transport {
    const https_peer::peer_client tls(https_peer::peer_client_config{
        ._tls = true, ._ca_path = ca_path, ._timeout = timeout, ._max_body_bytes = 1024 * 1024});
    const https_peer::peer_client plain(https_peer::peer_client_config{
        ._tls = false, ._ca_path = {}, ._timeout = timeout, ._max_body_bytes = 1024 * 1024});
    return [tls, plain](boost::beast::http::verb method, const std::string& url,
                        const https_peer::peer_client::headers& headers,
                        std::string body) -> std::optional<https_peer::peer_response> {
        const auto u = parse_url(url);
        if (!u) {
            return std::nullopt;
        }
        // The Host header without the default port, as clients send it.
        auto h = headers;
        auto host = u->_host_port;
        if ((u->_tls && host.ends_with(":443")) || (!u->_tls && host.ends_with(":80"))) {
            host.resize(host.rfind(':'));
        }
        h.emplace_back("Host", host);
        return (u->_tls ? tls : plain)
            .request(u->_host_port, method, u->_target, h, std::move(body));
    };
}

[[nodiscard]] inline auto base64_encode(std::string_view in) -> std::string {
    std::string out(4 * ((in.size() + 2) / 3), '\0');
    const auto n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(in.data()),
                                   static_cast<int>(in.size()));
    out.resize(static_cast<std::size_t>(n));
    return out;
}

/// Standard or URL-safe base64, padded or not; nullopt when malformed.
[[nodiscard]] inline auto base64_decode(std::string_view in) -> std::optional<std::string> {
    std::string s(in);
    for (auto& c : s) {
        if (c == '-') {
            c = '+';
        } else if (c == '_') {
            c = '/';
        }
    }
    while (s.size() % 4 != 0) {
        s.push_back('=');
    }
    std::string out(3 * (s.size() / 4), '\0');
    const auto n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(s.data()),
                                   static_cast<int>(s.size()));
    if (n < 0) {
        return std::nullopt;
    }
    std::size_t pad = 0;
    if (!s.empty() && s.back() == '=') {
        pad = s.size() >= 2 && s[s.size() - 2] == '=' ? 2 : 1;
    }
    out.resize(static_cast<std::size_t>(n) - pad);
    return out;
}

/// URL-safe base64 without padding (RFC 7515), which Azure Key Vault and
/// JWTs use.
[[nodiscard]] inline auto base64url_encode(std::string_view in) -> std::string {
    auto out = base64_encode(in);
    while (!out.empty() && out.back() == '=') {
        out.pop_back();
    }
    for (auto& c : out) {
        if (c == '+') {
            c = '-';
        } else if (c == '/') {
            c = '_';
        }
    }
    return out;
}

/// application/x-www-form-urlencoded escaping of one value.
[[nodiscard]] inline auto form_escape(std::string_view in) -> std::string {
    static constexpr std::string_view k_hex = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(k_hex[c >> 4U]);
            out.push_back(k_hex[c & 0x0FU]);
        }
    }
    return out;
}

/// The bytes that bind a data key to its encryption context:
/// "kythira-kms-context-v1" then each (key, value), in key order, as
/// u32 length | bytes. Distinct contexts give distinct bytes.
[[nodiscard]] inline auto context_binding(const encryption_context& context) -> std::string {
    std::string out = "kythira-kms-context-v1";
    const auto put = [&out](std::string_view s) {
        const auto n = static_cast<std::uint32_t>(s.size());
        for (int shift = 24; shift >= 0; shift -= 8) {
            out.push_back(static_cast<char>((n >> static_cast<unsigned>(shift)) & 0xFFU));
        }
        out.append(s);
    };
    for (const auto& [k, v] : context) {
        put(k);
        put(v);
    }
    return out;
}

/// A JSON object body, or an empty object when the body is not one.
[[nodiscard]] inline auto parse_object(const std::string& body) -> boost::json::object {
    try {
        auto v = boost::json::parse(body);
        if (v.is_object()) {
            return std::move(v.get_object());
        }
    } catch (const std::exception&) {
        // Judged by the caller from the status alone.
    }
    return {};
}

[[nodiscard]] inline auto string_field(const boost::json::object& o, std::string_view name)
    -> std::optional<std::string> {
    const auto* v = o.if_contains(name);
    if (v == nullptr || !v->is_string()) {
        return std::nullopt;
    }
    return std::string(v->get_string());
}

/// `expires_in` as a number or (Azure's metadata service) a string of
/// digits; nullopt when absent or malformed.
[[nodiscard]] inline auto expires_in(const boost::json::object& o) -> std::optional<long long> {
    const auto* v = o.if_contains("expires_in");
    if (v == nullptr) {
        return std::nullopt;
    }
    if (v->is_int64()) {
        return v->get_int64();
    }
    if (v->is_uint64()) {
        return static_cast<long long>(v->get_uint64());
    }
    if (v->is_string()) {
        try {
            return std::stoll(std::string(v->get_string()));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

/// An OAuth token endpoint's answer: `access_token` and `expires_in`.
[[nodiscard]] inline auto token_from(const std::optional<https_peer::peer_response>& res,
                                     std::string_view who) -> access_token {
    if (!res) {
        throw kms_error(kms_failure::unavailable, std::string(who) + " did not answer.");
    }
    const auto o = parse_object(res->_body);
    if (res->_status != 200) {
        auto why =
            string_field(o, "error_description")
                .value_or(
                    string_field(o, "error").value_or("status " + std::to_string(res->_status)));
        throw kms_error(res->_status >= 500 ? kms_failure::unavailable : kms_failure::access_denied,
                        std::string(who) + " refused a token: " + why);
    }
    auto value = string_field(o, "access_token");
    if (!value || value->empty()) {
        throw kms_error(kms_failure::access_denied,
                        std::string(who) + " answered without an access token.");
    }
    access_token out{._value = std::move(*value)};
    if (const auto secs = expires_in(o); secs && *secs > 0) {
        out._expires = std::chrono::system_clock::now() + std::chrono::seconds(*secs);
    }
    return out;
}

}  // namespace cloud_detail

/// Caches a token source's tokens until five minutes before they expire,
/// so that every key call does not fetch a token. Thread-safe; copies
/// share the cache.
class token_cache {
public:
    token_cache() = default;
    explicit token_cache(std::function<access_token()> fetch)
        : _state(std::make_shared<state>(std::move(fetch))) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return _state != nullptr && static_cast<bool>(_state->_fetch);
    }

    /// The bearer token; throws `kms_error` when the source fails.
    [[nodiscard]] auto get() const -> std::string {
        if (!*this) {
            throw kms_error(kms_failure::access_denied, "No credentials for the key service.");
        }
        const std::scoped_lock lock(_state->_mutex);
        const auto now = std::chrono::system_clock::now();
        if (!_state->_token ||
            (_state->_token->_expires != std::chrono::system_clock::time_point::max() &&
             _state->_token->_expires - std::chrono::minutes(5) <= now)) {
            _state->_token = _state->_fetch();
        }
        return _state->_token->_value;
    }

private:
    struct state {
        explicit state(std::function<access_token()> fetch) : _fetch(std::move(fetch)) {}
        std::function<access_token()> _fetch;
        std::mutex _mutex;
        std::optional<access_token> _token;
    };
    std::shared_ptr<state> _state;
};

/// Reads an environment variable (tests pass a map instead of the
/// process's environment).
using env_lookup = std::function<std::string(const char*)>;

}  // namespace kythira::kms_provider
