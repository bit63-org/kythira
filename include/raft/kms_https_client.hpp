// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_https_client.hpp
/// @brief A consuming service's KMS client for a KMS on another cluster
///        (kms-compatible-api task 12, Requirement 2.4): the same
///        `kms_endpoint` the co-located module publishes as `kms.client`,
///        over HTTPS with SigV4.
///
/// The service signs with its own credentials and forwards the principal
/// it is serving in two signed headers (raft/kms_forwarding.hpp), which
/// the KMS honours only from a principal it trusts.

#include <raft/kms_forwarding.hpp>
#include <raft/module_interfaces.hpp>
#include <raft/mtls_https_client.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::service_node {

/// Where a consuming service reaches a KMS on another cluster, and as whom.
struct kms_https_config {
    /// "https://host:port" of any member's KMS API listener.
    std::string endpoint;
    /// The KMS's region, for the SigV4 scope.
    std::string region = "us-east-1";
    /// The service's own credentials; its principal must be one of the
    /// KMS's KYTHIRA_KMS_TRUSTED_SERVICES.
    std::string access_key_id;
    std::string secret_access_key;
    std::string session_token;
    /// TLS: the CA the KMS's certificate chains to; a client certificate
    /// only when the deployment wants one (`client_certificate`).
    mtls::client_config tls;
};

/// The headers and body of one signed KMS request.
struct kms_signed_request {
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

/// `kms_endpoint` over HTTPS with SigV4 (Requirement 2.4).
class kms_https_endpoint final : public kms_endpoint {
public:
    explicit kms_https_endpoint(kms_https_config config)
        : _config(std::move(config)), _client(_config.tls) {}

    /// `request` signed at `now` as this service, with the principal it
    /// serves forwarded. Every header the KMS reads is signed. Exposed so
    /// tests can hand the result to a front end without a network.
    [[nodiscard]] auto sign(const kms_request& request, std::chrono::system_clock::time_point now,
                            std::string_view host) const -> kms_signed_request {
        const auto t = std::chrono::floor<std::chrono::seconds>(now);
        const auto date = sigv4::detail::format_amz_date(t);
        kms_signed_request out;
        out.body = request.body;
        out.headers = {
            {"Host", std::string(host)},
            {"Content-Type", "application/x-amz-json-1.1"},
            {"X-Amz-Date", date},
            {"X-Amz-Target", "TrentService." + request.operation},
            {std::string(kms_forwarding::principal_header),
             kms_forwarding::encode_principal(request.principal)},
            {std::string(kms_forwarding::via_service_header), request.via_service},
        };
        std::string signed_names = "content-type;host;x-amz-date;x-amz-target";
        if (!_config.session_token.empty()) {
            out.headers.emplace_back("X-Amz-Security-Token", _config.session_token);
            signed_names += ";x-amz-security-token";
        }
        signed_names += ";x-kythira-principal;x-kythira-via-service";
        const sigv4::credential_scope scope{date.substr(0, 8), _config.region, "kms"};
        out.headers.emplace_back("Authorization",
                                 "AWS4-HMAC-SHA256 Credential=" + _config.access_key_id + "/" +
                                     scope.text() + ", SignedHeaders=" + signed_names +
                                     ", Signature=" + std::string(64, '0'));
        sigv4::service_rules rules;
        rules.service = "kms";
        rules.protocol = sigv4::error_protocol::json;
        const auto parsed =
            sigv4::parse(sigv4::request{"POST", "/", "", out.headers, out.body}, rules, t);
        if (!parsed) {
            throw std::invalid_argument("kms_https_endpoint: cannot sign: " +
                                        parsed.error().message);
        }
        const auto sig = sigv4::compute_signature(
            *parsed, sigv4::derive_signing_key(_config.secret_access_key, scope));
        auto& auth = out.headers.back().second;
        auth.replace(auth.size() - 64, 64, sig);
        return out;
    }

    [[nodiscard]] auto call(const caller& /*who*/, const kms_request& request)
        -> aws_json_response override {
        if (!kms_forwarding::is_service_operation(request.operation)) {
            return refusal(400, "UnsupportedOperationException",
                           request.operation + " is not taken through a service");
        }
        const auto host = host_of(_config.endpoint);
        kms_signed_request r;
        try {
            r = sign(request, std::chrono::system_clock::now(), host);
        } catch (const std::exception& e) {
            return refusal(500, "KMSInternalException", e.what());
        }
        std::vector<std::pair<std::string, std::string>> extra;
        for (auto& [k, v] : r.headers) {
            if (k != "Host" && k != "Content-Type") {
                extra.emplace_back(k, v);
            }
        }
        const auto res = _client.request("POST", _config.endpoint, "/", std::move(r.body),
                                         "application/x-amz-json-1.1", "kythira-kms-client", extra);
        if (!res) {
            return refusal(503, "DependencyTimeoutException",
                           "The KMS at " + _config.endpoint + " did not answer.");
        }
        return {static_cast<int>(res->first), res->second};
    }

private:
    /// "host:port" of "https://host:port", as the Host header carries it
    /// and the KMS's SigV4 check signs it.
    [[nodiscard]] static auto host_of(std::string_view url) -> std::string {
        for (const std::string_view scheme : {"https://", "http://"}) {
            if (url.starts_with(scheme)) {
                url.remove_prefix(scheme.size());
            }
        }
        while (url.ends_with('/')) {
            url.remove_suffix(1);
        }
        return std::string(url);
    }

    [[nodiscard]] static auto refusal(int status, std::string_view type, const std::string& message)
        -> aws_json_response {
        return {status, boost::json::serialize(
                            boost::json::object{{"__type", type}, {"message", message}})};
    }

    kms_https_config _config;
    mtls::client _client;
};

}  // namespace kythira::service_node
