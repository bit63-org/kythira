// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_forwarding.hpp
/// @brief How a consuming service forwards the principal it serves to a
///        KMS on another cluster (kms-compatible-api task 12): two signed
///        headers on an otherwise ordinary SigV4 request,
///
///   X-Kythira-Principal    base64 of the principal as JSON
///   X-Kythira-Via-Service  the service ("kinesis"), for kms:ViaService
///
/// which the KMS honours only when both are among the signed headers and
/// the signer is one of the principals it trusts
/// (`KYTHIRA_KMS_TRUSTED_SERVICES`): Kythira's equivalent of AWS's service
/// principals. In core so the KMS's front end and its consumers'
/// `kms_https_endpoint` (raft/kms_https_client.hpp) share it without
/// either including the other, and without the front end pulling in a
/// network client.

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms_forwarding {

inline constexpr std::string_view principal_header = "x-kythira-principal";
inline constexpr std::string_view via_service_header = "x-kythira-via-service";

/// The operations a service may make for its callers (`kms_endpoint`).
inline constexpr std::array<std::string_view, 6> service_operations = {
    "Decrypt",  "DescribeKey", "Encrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
    "ReEncrypt"};

[[nodiscard]] inline auto is_service_operation(std::string_view op) -> bool {
    for (const auto o : service_operations) {
        if (o == op) {
            return true;
        }
    }
    return false;
}

/// A service name as `kms:ViaService` takes it: lower-case letters, digits
/// and hyphens, as AWS's service prefixes are.
[[nodiscard]] inline auto valid_service_name(std::string_view s) -> bool {
    if (s.empty() || s.size() > 64) {
        return false;
    }
    for (const char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

namespace detail {

[[nodiscard]] inline auto to_ms(std::chrono::system_clock::time_point t) -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

[[nodiscard]] inline auto strings(const std::vector<std::string>& v) -> boost::json::array {
    boost::json::array out;
    for (const auto& s : v) {
        out.emplace_back(s);
    }
    return out;
}

}  // namespace detail

/// `p` for X-Kythira-Principal: every field the authorizer reads, so the
/// KMS decides exactly as it would for the principal itself (session
/// policies and expiry included).
[[nodiscard]] inline auto encode_principal(const aws_auth::principal_context& p) -> std::string {
    boost::json::object o{
        {"type", std::string(aws_auth::to_string(p.type))},
        {"account", p.account},
        {"arn", p.arn},
        {"userid", p.userid},
        {"username", p.username},
        {"access_key_id", p.access_key_id},
        {"role_arn", p.role_arn},
        {"role_name", p.role_name},
        {"session_name", p.session_name},
        {"user_arn", p.user_arn},
        {"source_identity", p.source_identity},
        {"session_policies", detail::strings(p.session_policies)},
        {"transitive_tag_keys", detail::strings(p.transitive_tag_keys)},
        {"session_token", p.session_token},
    };
    boost::json::array tags;
    for (const auto& [k, v] : p.tags) {
        tags.emplace_back(boost::json::array{boost::json::string(k), boost::json::string(v)});
    }
    o["tags"] = std::move(tags);
    if (p.token_issue_time) {
        o["token_issue_time_ms"] = detail::to_ms(*p.token_issue_time);
    }
    if (p.expires) {
        o["expires_ms"] = detail::to_ms(*p.expires);
    }
    const auto text = boost::json::serialize(o);
    return aws_json::base64_encode(std::as_bytes(std::span(text.data(), text.size())));
}

/// The principal in an X-Kythira-Principal value, or nothing when it does
/// not decode.
[[nodiscard]] inline auto decode_principal(std::string_view header)
    -> std::optional<aws_auth::principal_context> {
    const auto bytes = aws_json::base64_decode(header);
    if (!bytes) {
        return std::nullopt;
    }
    try {
        const std::string_view text(reinterpret_cast<const char*>(bytes->data()),  // NOLINT
                                    bytes->size());
        const auto v = boost::json::parse(text);
        const auto& o = v.as_object();
        const auto str = [&](std::string_view k) { return std::string(o.at(k).as_string()); };
        const auto list = [&](std::string_view k) {
            std::vector<std::string> out;
            for (const auto& e : o.at(k).as_array()) {
                out.emplace_back(e.as_string());
            }
            return out;
        };
        aws_auth::principal_context p;
        const auto type = str("type");
        if (type == "Account") {
            p.type = aws_auth::principal_type::root;
        } else if (type == "User") {
            p.type = aws_auth::principal_type::user;
        } else if (type == "AssumedRole") {
            p.type = aws_auth::principal_type::assumed_role;
        } else if (type == "FederatedUser") {
            p.type = aws_auth::principal_type::federated_user;
        } else {
            return std::nullopt;
        }
        p.account = str("account");
        p.arn = str("arn");
        p.userid = str("userid");
        p.username = str("username");
        p.access_key_id = str("access_key_id");
        p.role_arn = str("role_arn");
        p.role_name = str("role_name");
        p.session_name = str("session_name");
        p.user_arn = str("user_arn");
        p.source_identity = str("source_identity");
        p.session_policies = list("session_policies");
        p.transitive_tag_keys = list("transitive_tag_keys");
        p.session_token = o.at("session_token").as_bool();
        for (const auto& t : o.at("tags").as_array()) {
            const auto& pair = t.as_array();
            if (pair.size() != 2) {
                return std::nullopt;
            }
            p.tags.emplace_back(std::string(pair[0].as_string()), std::string(pair[1].as_string()));
        }
        const auto time =
            [&](std::string_view k) -> std::optional<std::chrono::system_clock::time_point> {
            const auto* t = o.if_contains(k);
            if (t == nullptr) {
                return std::nullopt;
            }
            return std::chrono::system_clock::time_point(std::chrono::milliseconds(t->as_int64()));
        };
        p.token_issue_time = time("token_issue_time_ms");
        p.expires = time("expires_ms");
        if (p.account.empty() || p.arn.empty()) {
            return std::nullopt;
        }
        return p;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

/// Whether `name` (any case) is among the request's SigV4 signed headers,
/// from its Authorization header. A request signed in the query string
/// has none, so it cannot forward a principal.
[[nodiscard]] inline auto header_is_signed(
    const std::vector<std::pair<std::string, std::string>>& headers, std::string_view name)
    -> bool {
    for (const auto& [k, v] : headers) {
        if (sigv4::detail::lower(k) != "authorization") {
            continue;
        }
        const auto at = v.find("SignedHeaders=");
        if (at == std::string::npos) {
            return false;
        }
        auto list = std::string_view(v).substr(at + 14);
        list = list.substr(0, list.find_first_of(", "));
        const auto want = sigv4::detail::lower(name);
        for (const auto part : sigv4::detail::split(list, ';')) {
            if (part == want) {
                return true;
            }
        }
        return false;
    }
    return false;
}

}  // namespace kythira::kms_forwarding
