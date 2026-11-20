// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_outbound.hpp
/// @brief The requests S3 sends to other services, addressed and signed with
///        SigV4: KMS for SSE-KMS data keys, SQS, SNS and Kinesis for event
///        notifications, and S3 for replication
///        (.kiro/specs/s3-compatible-storage/ task 16, the daemon wiring
///        tasks 11 and 14 left to it).
///
/// Each consumer in the module takes a transport function and knows nothing
/// of addresses, credentials or sockets (`kms_call` in `s3_kms_provider.hpp`,
/// `event_api_call` in `s3_event_sinks.hpp`, `replication_call` in
/// `s3_replication.hpp`). This header builds those functions from:
///
///  - `service_endpoints`: where each service is. A service with no entry
///    is AWS's regional endpoint, `https://<service>.<region>.amazonaws.com`,
///    so the same daemon talks to Kythira's own services or to AWS.
///  - `aws_credentials`: what the requests are signed as (the daemon's own
///    identity, from its environment).
///  - `http_send`: one request, one answer (the daemon's HTTPS client; a
///    test's in-process server).
///
/// KMS calls forward the principal S3 is serving in Kythira's two signed
/// headers (`raft/kms_forwarding.hpp`), so a Kythira KMS that trusts S3
/// checks `kms:GenerateDataKey` and `kms:Decrypt` as the caller and the
/// reader (task 11). AWS KMS ignores the headers and decides as S3's own
/// identity.
///
/// Replication sends each object as a path-style `PUT /<bucket>/<key>` with
/// the body read whole: the core HTTPS client sends whole bodies, so the
/// largest object replicated is bounded by memory until the client streams.

#include <kythira/s3/s3_encryption.hpp>
#include <kythira/s3/s3_event_sinks.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_kms_provider.hpp>
#include <kythira/s3/s3_replication.hpp>

#include <raft/kms_forwarding.hpp>
#include <raft/sigv4_verifier.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

struct aws_credentials {
    std::string access_key_id;
    std::string secret_access_key;
    std::string session_token;

    [[nodiscard]] auto empty() const noexcept -> bool {
        return access_key_id.empty() || secret_access_key.empty();
    }
};

/// One request to another service.
struct outbound_request {
    std::string method = "POST";
    /// "https://host:port", no path.
    std::string url;
    /// Path and query, as sent and signed.
    std::string target = "/";
    header_list headers;
    std::string body;
};

/// Sends one request: the status and body, or nothing when there was no
/// answer.
using http_send =
    std::function<std::optional<std::pair<unsigned, std::string>>(const outbound_request&)>;

/// Where each service is: "sqs" to "https://sqs.kythira.test:9324", say.
struct service_endpoints {
    std::map<std::string, std::string, std::less<>> by_service;

    [[nodiscard]] auto url(std::string_view service, std::string_view region) const -> std::string {
        if (auto it = by_service.find(service); it != by_service.end()) {
            return it->second;
        }
        return "https://" + std::string(service) + "." + std::string(region) + ".amazonaws.com";
    }
};

namespace outbound_detail {

/// "host:port" of "https://host:port/": what `Host` carries and SigV4 signs.
[[nodiscard]] inline auto host_of(std::string_view url) -> std::string {
    for (const std::string_view scheme : {"https://", "http://"}) {
        if (url.starts_with(scheme)) {
            url.remove_prefix(scheme.size());
            break;
        }
    }
    url = url.substr(0, url.find('/'));
    return std::string(url);
}

/// S3's key encoding for a path: every byte but the unreserved ones and
/// '/', as `%XX`.
[[nodiscard]] inline auto encode_key(std::string_view key) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    for (const char ch : key) {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4U]);
            out.push_back(hex[c & 0xFU]);
        }
    }
    return out;
}

[[nodiscard]] inline auto lower(std::string s) -> std::string {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

}  // namespace outbound_detail

/// Signs `r` for `service` in `region` at `now`: sets `Host`, `X-Amz-Date`,
/// `X-Amz-Content-Sha256` (on every request; S3 requires it), the session
/// token when there is one, and `Authorization`, signing every header the
/// request carries. Throws `std::invalid_argument` when it cannot.
inline void sign_outbound(outbound_request& r, std::string_view service, std::string_view region,
                          const aws_credentials& creds, std::chrono::system_clock::time_point now) {
    if (creds.empty()) {
        throw std::invalid_argument("s3 outbound: no credentials to sign with");
    }
    const auto t = std::chrono::floor<std::chrono::seconds>(now);
    const auto date = sigv4::detail::format_amz_date(t);
    std::erase_if(r.headers, [](const auto& h) {
        const auto n = outbound_detail::lower(h.first);
        return n == "host" || n == "x-amz-date" || n == "authorization" ||
               n == "x-amz-content-sha256" || n == "x-amz-security-token";
    });
    r.headers.emplace_back("Host", outbound_detail::host_of(r.url));
    r.headers.emplace_back("X-Amz-Date", date);
    r.headers.emplace_back("X-Amz-Content-Sha256", sigv4::detail::sha256_hex(r.body));
    if (!creds.session_token.empty()) {
        r.headers.emplace_back("X-Amz-Security-Token", creds.session_token);
    }
    std::vector<std::string> names;
    names.reserve(r.headers.size());
    for (const auto& [k, v] : r.headers) {
        names.push_back(outbound_detail::lower(k));
    }
    std::ranges::sort(names);
    names.erase(std::unique(names.begin(), names.end()), names.end());
    std::string signed_names;
    for (const auto& n : names) {
        if (!signed_names.empty()) {
            signed_names.push_back(';');
        }
        signed_names += n;
    }
    const sigv4::credential_scope scope{date.substr(0, 8), std::string(region),
                                        std::string(service)};
    r.headers.emplace_back("Authorization", "AWS4-HMAC-SHA256 Credential=" + creds.access_key_id +
                                                "/" + scope.text() +
                                                ", SignedHeaders=" + signed_names +
                                                ", Signature=" + std::string(64, '0'));
    sigv4::service_rules rules;
    rules.service = std::string(service);
    rules.s3_path_rules = service == "s3";
    rules.protocol = service == "s3" ? sigv4::error_protocol::s3 : sigv4::error_protocol::json;
    const std::string_view target(r.target);
    const auto q = target.find('?');
    const auto parsed = sigv4::parse(
        sigv4::request{r.method, target.substr(0, q),
                       q == std::string_view::npos ? std::string_view{} : target.substr(q + 1),
                       r.headers, r.body},
        rules, t);
    if (!parsed) {
        throw std::invalid_argument("s3 outbound: cannot sign: " + parsed.error().message);
    }
    const auto sig = sigv4::compute_signature(
        *parsed, sigv4::derive_signing_key(creds.secret_access_key, scope));
    auto& auth = r.headers.back().second;
    auth.replace(auth.size() - 64, 64, sig);
}

/// Everything the transports below share.
struct outbound_options {
    service_endpoints endpoints;
    aws_credentials credentials;
    /// The region of services whose region nothing else names (KMS, a
    /// replication destination: bucket ARNs carry none).
    std::string region = "us-east-1";
    http_send send;
    /// The clock, for tests; the system clock when empty.
    std::function<std::chrono::system_clock::time_point()> clock;

    [[nodiscard]] auto now() const -> std::chrono::system_clock::time_point {
        return clock ? clock() : std::chrono::system_clock::now();
    }
};

/// SQS, SNS and Kinesis for event notifications. Throws when no answer
/// comes back, as `event_api_call` asks.
[[nodiscard]] inline auto make_event_api_call(outbound_options o) -> event_api_call {
    if (!o.send) {
        throw std::invalid_argument("s3 outbound: needs a sender");
    }
    return [o = std::move(o)](const event_api_request& req) -> event_api_answer {
        outbound_request r;
        r.url = o.endpoints.url(req.service, req.region);
        r.body = req.body;
        r.headers.emplace_back("Content-Type", req.content_type);
        if (!req.target.empty()) {
            r.headers.emplace_back("X-Amz-Target", req.target);
        }
        sign_outbound(r, req.service, req.region, o.credentials, o.now());
        auto res = o.send(r);
        if (!res) {
            throw std::runtime_error(req.service + " at " + r.url + " did not answer");
        }
        return {static_cast<int>(res->first), std::move(res->second)};
    };
}

/// KMS, forwarding the principal S3 serves. No answer is a 503, which the
/// provider reports as a dependency timeout.
[[nodiscard]] inline auto make_kms_call(outbound_options o) -> kms_call {
    if (!o.send) {
        throw std::invalid_argument("s3 outbound: needs a sender");
    }
    return [o = std::move(o)](const std::string& operation, const std::string& body,
                              const kms_caller& who) -> kms_answer {
        outbound_request r;
        r.url = o.endpoints.url("kms", o.region);
        r.body = body;
        r.headers.emplace_back("Content-Type", "application/x-amz-json-1.1");
        r.headers.emplace_back("X-Amz-Target", "TrentService." + operation);
        if (who.principal) {
            r.headers.emplace_back(std::string(kms_forwarding::principal_header),
                                   kms_forwarding::encode_principal(*who.principal));
            r.headers.emplace_back(std::string(kms_forwarding::via_service_header), "s3");
        }
        sign_outbound(r, "kms", o.region, o.credentials, o.now());
        auto res = o.send(r);
        if (!res) {
            return {503,
                    R"({"__type":"DependencyTimeoutException","message":"KMS did not answer"})"};
        }
        return {static_cast<int>(res->first), std::move(res->second)};
    };
}

/// S3 for replication, path style. Throws when no answer comes back.
[[nodiscard]] inline auto make_replication_call(outbound_options o, std::size_t max_body_bytes)
    -> replication_call {
    if (!o.send) {
        throw std::invalid_argument("s3 outbound: needs a sender");
    }
    return [o = std::move(o), max_body_bytes](replication_request& req) -> replication_answer {
        outbound_request r;
        r.method = req.method;
        r.url = o.endpoints.url("s3", o.region);
        r.target = "/" + req.bucket + "/" + outbound_detail::encode_key(req.key);
        r.headers = req.headers;
        if (req.method == "PUT" && req.body) {
            auto body = read_all(
                req.body, max_body_bytes,
                aws_rest_xml::errors::make(400, "EntityTooLarge", "too large to replicate"));
            if (!body) {
                throw std::runtime_error("replication body: " + body.error().message);
            }
            r.body = std::move(*body);
        }
        sign_outbound(r, "s3", o.region, o.credentials, o.now());
        auto res = o.send(r);
        if (!res) {
            throw std::runtime_error("s3 at " + r.url + " did not answer");
        }
        return {static_cast<int>(res->first), std::move(res->second)};
    };
}

}  // namespace kythira::s3
