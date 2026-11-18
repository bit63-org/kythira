// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_node_options.hpp
/// @brief `sqs_node`'s settings from its environment
///        (`.kiro/specs/sqs-compatible-queues/` task 4).
///
// clang-format off
/// | Variable | Default | Meaning |
/// |---|---|---|
/// | `SQS_LISTEN` | `0.0.0.0:9324` | the API listener, `host:port` (port 0 picks one) |
/// | `SQS_TLS_CERT`, `SQS_TLS_KEY` | | the listener's certificate chain and key |
/// | `SQS_ALLOW_PLAINTEXT` | off | serve HTTP instead of HTTPS (development only) |
/// | `SQS_ENDPOINT` | `http(s)://localhost:<port>` | the scheme and host queue URLs are minted on |
/// | `SQS_REGION` | `us-east-1` | the region SigV4 scopes and ARNs name |
/// | `SQS_PARTITION` | `aws` | the ARN partition |
/// | `SQS_STATIC_KEYS_FILE` | required | static access keys (core's `static_keys_file.hpp`) |
/// | `SQS_RECEIPT_KEYS_FILE` | | receipt-handle keys (`sqs_receipts.hpp`) |
/// | `SQS_FORWARD_SECRET` | | the cluster's shared secret: node-to-node forwarding, and the receipt and SSE-SQS keys when no key file is given |
/// | `SQS_SSE_KEY_FILE` | | the SSE-SQS master secret, at least 16 bytes (`sqs_sse.hpp`) |
/// | `SQS_KMS` | `none` | the SSE-KMS key provider: `none` (KMS-encrypted queues refuse sends with KmsNotFound) or `local` |
/// | `SQS_KMS_PASSPHRASE_FILE` | | `local`'s passphrase; every node needs the same one |
/// | `SQS_COMPAT` | | compatibility switches, `name=value` comma-separated (`sqs_compat_profile.hpp`) |
/// | `SQS_MAX_BODY_BYTES` | 4194304 | the largest request body the listener reads |
// clang-format on
///
/// Everything is checked here, before a port is bound; a refusal names the
/// variable.

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::sqs {

struct sqs_node_options {
    std::string _listen_host = "0.0.0.0";
    std::uint16_t _listen_port = 9324;
    std::string _tls_cert_path;
    std::string _tls_key_path;
    bool _allow_plaintext = false;
    /// Empty: derived from the listener once its port is known.
    std::string _endpoint;
    std::string _region = "us-east-1";
    std::string _partition = "aws";
    std::string _static_keys_file;
    std::string _receipt_keys_file;
    std::string _forward_secret;
    std::string _sse_key_file;
    /// `none` or `local`.
    std::string _kms = "none";
    std::string _kms_passphrase_file;
    std::vector<std::pair<std::string, std::string>> _compat;
    std::uint64_t _max_body_bytes = std::uint64_t{4} * 1024 * 1024;
};

/// Reads one variable; nullopt when unset.
using sqs_env = std::function<std::optional<std::string>(std::string_view)>;

namespace node_options_detail {

[[nodiscard]] inline auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > 19) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return v;
}

[[nodiscard]] inline auto parse_flag(std::string_view s) -> std::optional<bool> {
    if (s == "1" || s == "true" || s == "on" || s == "yes") {
        return true;
    }
    if (s.empty() || s == "0" || s == "false" || s == "off" || s == "no") {
        return false;
    }
    return std::nullopt;
}

}  // namespace node_options_detail

/// The options, or the refusal to print.
[[nodiscard]] inline auto sqs_node_options_from_env(const sqs_env& env)
    -> std::variant<sqs_node_options, std::string> {
    using namespace node_options_detail;
    sqs_node_options o;
    const auto get = [&](std::string_view name) { return env(name); };
    if (const auto v = get("SQS_LISTEN")) {
        const auto colon = v->rfind(':');
        const auto port = colon == std::string::npos
                              ? std::nullopt
                              : parse_u64(std::string_view(*v).substr(colon + 1));
        if (colon == std::string::npos || colon == 0 || !port || *port > 65535) {
            return std::string("SQS_LISTEN must be host:port, got '" + *v + "'");
        }
        o._listen_host = v->substr(0, colon);
        if (o._listen_host.size() > 2 && o._listen_host.front() == '[' &&
            o._listen_host.back() == ']') {
            o._listen_host = o._listen_host.substr(1, o._listen_host.size() - 2);
        }
        o._listen_port = static_cast<std::uint16_t>(*port);
    }
    if (const auto v = get("SQS_ALLOW_PLAINTEXT")) {
        const auto f = parse_flag(*v);
        if (!f) {
            return std::string("SQS_ALLOW_PLAINTEXT must be on or off");
        }
        o._allow_plaintext = *f;
    }
    o._tls_cert_path = get("SQS_TLS_CERT").value_or("");
    o._tls_key_path = get("SQS_TLS_KEY").value_or("");
    if (!o._allow_plaintext && (o._tls_cert_path.empty() || o._tls_key_path.empty())) {
        return std::string(
            "SQS_TLS_CERT and SQS_TLS_KEY are required unless SQS_ALLOW_PLAINTEXT=on");
    }
    o._endpoint = get("SQS_ENDPOINT").value_or("");
    if (!o._endpoint.empty() &&
        (o._endpoint.find("://") == std::string::npos || o._endpoint.ends_with("/"))) {
        return std::string("SQS_ENDPOINT must be scheme://host[:port] with no trailing slash");
    }
    o._region = get("SQS_REGION").value_or(o._region);
    o._partition = get("SQS_PARTITION").value_or(o._partition);
    if (o._region.empty() || o._partition.empty()) {
        return std::string("SQS_REGION and SQS_PARTITION must not be empty");
    }
    o._static_keys_file = get("SQS_STATIC_KEYS_FILE").value_or("");
    if (o._static_keys_file.empty()) {
        return std::string("SQS_STATIC_KEYS_FILE is required");
    }
    o._receipt_keys_file = get("SQS_RECEIPT_KEYS_FILE").value_or("");
    o._forward_secret = get("SQS_FORWARD_SECRET").value_or("");
    if (!o._forward_secret.empty() && o._forward_secret.size() < 16) {
        return std::string("SQS_FORWARD_SECRET must be at least 16 bytes");
    }
    o._sse_key_file = get("SQS_SSE_KEY_FILE").value_or("");
    o._kms = get("SQS_KMS").value_or(o._kms);
    if (o._kms != "none" && o._kms != "local") {
        return std::string("SQS_KMS must be none or local");
    }
    o._kms_passphrase_file = get("SQS_KMS_PASSPHRASE_FILE").value_or("");
    if (o._kms == "local" && o._kms_passphrase_file.empty()) {
        return std::string("SQS_KMS=local needs SQS_KMS_PASSPHRASE_FILE");
    }
    if (const auto v = get("SQS_COMPAT"); v && !v->empty()) {
        std::string_view rest = *v;
        while (!rest.empty()) {
            const auto comma = rest.find(',');
            const auto item = rest.substr(0, comma);
            rest = comma == std::string_view::npos ? std::string_view() : rest.substr(comma + 1);
            const auto eq = item.find('=');
            if (eq == std::string_view::npos || eq == 0) {
                return std::string("SQS_COMPAT items must be name=value");
            }
            o._compat.emplace_back(std::string(item.substr(0, eq)),
                                   std::string(item.substr(eq + 1)));
        }
    }
    if (const auto v = get("SQS_MAX_BODY_BYTES")) {
        const auto n = parse_u64(*v);
        if (!n || *n < 1024) {
            return std::string("SQS_MAX_BODY_BYTES must be a number of at least 1024");
        }
        o._max_body_bytes = *n;
    }
    return o;
}

}  // namespace kythira::sqs
