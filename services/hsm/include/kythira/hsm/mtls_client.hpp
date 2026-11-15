// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM's names for core's mutual TLS client (raft/mtls_https_client.hpp),
// which began here (.kiro/specs/virtual-hsm/ tasks 6d and 7): how a member
// forwards to the leader (hsm_peer.hpp) and how hsm_ctl reaches a node's
// operator API.

#include <raft/mtls_https_client.hpp>

namespace kythira::hsm {

using peer_client_config = kythira::mtls::client_config;
using mtls_client = kythira::mtls::client;

}  // namespace kythira::hsm
