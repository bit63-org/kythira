// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_admin_client.hpp
/// @brief The caller's side of the live migration admin calls
///        (`.kiro/specs/kinesis-independent-layers/` task 13,
///        `kinesis_migration.hpp`): one signed request to a node's gateway.
///
/// Apart from the gateway so the daemon's `--admin` command can make the
/// call without compiling the gateway.

#include <kythira/kinesis/kinesis_forward.hpp>
#include <kythira/kinesis/kinesis_migration.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <boost/beast/http/verb.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kinesis {

/// One live migration admin call to the node at `host_port`, signed with
/// `secret`; nullopt when it cannot be reached or there is no secret.
/// `op` is the path after `k_admin_path_prefix`, with any query.
[[nodiscard]] inline auto admin_request(
    const peer_client& client, std::string_view secret, const std::string& host_port,
    boost::beast::http::verb method, std::string_view op, std::string body = {},
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now())
    -> std::optional<kythira::https_peer::peer_response> {
    if (secret.empty()) {
        return std::nullopt;
    }
    const auto target = std::string(k_admin_path_prefix) + std::string(op);
    const auto signature = forward::sign(
        secret,
        admin_signed_text(std::string_view(boost::beast::http::to_string(method)), target, body),
        now);
    return client.request(
        host_port, method, target,
        {{std::string(forward::k_header), signature}, {"Content-Type", "application/json"}},
        std::move(body));
}

}  // namespace kythira::kinesis
