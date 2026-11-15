// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_peer_client.hpp
/// @brief One blocking HTTP(S) request to another gateway of the cluster
///        (`.kiro/specs/kinesis-compatible-streams/` task 6): how a write
///        reaches its group's leader and how a replica fetches a segment.
///        The client is core's (raft/https_peer_client.hpp), where it moved
///        when DynamoDB's key provider needed it.

#include <raft/https_peer_client.hpp>

namespace kythira::kinesis {

using https_peer::peer_client;
using https_peer::peer_client_config;
using https_peer::peer_response;
using https_peer::split_host_port;

/// The gateways' own user agent.
inline constexpr std::string_view k_peer_user_agent = "kythira-kinesis-gateway";

}  // namespace kythira::kinesis
