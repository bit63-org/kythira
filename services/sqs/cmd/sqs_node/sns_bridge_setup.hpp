// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_bridge_setup.hpp
/// @brief The SNS bridge's settings for `sqs_node` and the module
///        (`.kiro/specs/sqs-compatible-queues/` task 9): the HTTPS GET it
///        fetches signing certificates and subscribe URLs with.

#include <kythira/sqs/sqs_node_options.hpp>
#include <kythira/sqs/sqs_sns_bridge.hpp>

#include <raft/mtls_https_client.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace kythira::sqs {

/// One HTTPS GET with the system's (or `ca_path`'s) roots, no client
/// certificate: the body on a 2xx answer.
[[nodiscard]] inline auto sns_https_fetch(const std::string& ca_path)
    -> std::function<std::optional<std::string>(const std::string&)> {
    mtls::client_config cc;
    cc.ca_path = ca_path;
    cc.client_certificate = false;
    cc.timeout = std::chrono::seconds(10);
    cc.max_body_bytes = std::uint64_t{1} << 20U;
    auto client = std::make_shared<mtls::client>(cc);
    return [client](const std::string& url) -> std::optional<std::string> {
        const auto u = sns_detail::parse_https(url);
        if (!u) {
            return std::nullopt;
        }
        const auto r = client->request("GET", "https://" + u->_host + ":443", u->_path, "", "",
                                       "kythira-sqs-sns-bridge");
        if (!r || r->first / 100 != 2) {
            return std::nullopt;
        }
        return r->second;
    };
}

/// The bridge's configuration from a node's settings.
[[nodiscard]] inline auto sns_bridge_settings(const sqs_node_options& o, std::string endpoint)
    -> sns_bridge_config {
    sns_bridge_config c;
    c._region = o._region;
    c._partition = o._partition;
    c._endpoint = std::move(endpoint);
    c._hosts = o._sns_cert_hosts;
    c._fetch = sns_https_fetch(o._sns_ca);
    return c;
}

}  // namespace kythira::sqs
