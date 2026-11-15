// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The HSM module's configuration (.kiro/specs/virtual-hsm/ task 6e), read
// from the environment: KYTHIRA_HSM_* for the module, the node-wide
// KYTHIRA_NODE_* settings where the module's are unset (composite_env), and
// the Raft tuning names module_tuning() maps. usage_text() documents every
// variable.

#include <raft/console_logger.hpp>
#include <raft/host_node_id.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace kythira::hsm_node {

struct hsm_options {
    kythira::host_node_id node_id{kythira::host_node_id_from_number(1)};

    // -- Members and the listener ---------------------------------------------
    /// Every member's HSM listener ("https://host:port"), this node
    /// included: the voters of every HSM group, and where a follower
    /// forwards to.
    std::map<kythira::host_node_id, std::string> api_urls;
    std::string api_bind{"0.0.0.0"};
    std::uint16_t api_port{9443};
    std::string tls_cert;
    std::string tls_key;
    /// The CA both the members' and the operators' certificates chain to.
    std::string client_ca;
    /// Plaintext listener and forwarding (tests only).
    bool insecure_plaintext{false};
    /// The members' certificate identities (URI or DNS SANs).
    std::set<std::string> peer_identities;
    /// The operators' certificate identities.
    std::set<std::string> operators;
    std::uint64_t max_body_bytes{std::uint64_t{1} << 20U};
    std::uint64_t max_connections{256};

    // -- Keys and sessions -----------------------------------------------------
    std::filesystem::path data_dir;
    /// Start even where key memory cannot be locked (development only).
    bool allow_unlocked_memory{false};
    std::uint32_t max_login_failures{10};
    std::uint32_t max_sessions{4096};
    /// scrypt cost of new PIN verifiers, as log2(N).
    std::uint8_t pin_log2_n{15};
    /// Permit k = 1 at init and rekey (development only).
    bool allow_single_share{false};
    /// How long partial operator shares are held.
    std::chrono::seconds unseal_timeout{600};

    // -- Raft, timing and logs -------------------------------------------------
    std::chrono::milliseconds tick_interval{5};
    std::chrono::milliseconds election_timeout_min{300};
    std::chrono::milliseconds election_timeout_max{600};
    std::chrono::milliseconds heartbeat_interval{75};
    std::chrono::milliseconds rpc_timeout{2000};
    std::chrono::milliseconds propose_timeout{5000};
    std::chrono::milliseconds maintenance_interval{500};
    kythira::log_level log_level{kythira::log_level::info};
};

/// Reads one variable; nothing when unset.
using env_fn = std::function<std::optional<std::string>(std::string_view)>;

/// `env` for the module in kythira_node: every variable from `env`, with
/// the TLS files and the plaintext switch filled in from the node's
/// KYTHIRA_NODE_TLS_* and KYTHIRA_NODE_INSECURE_PLAINTEXT when unset. The
/// data directory is always the node's hsm/.
[[nodiscard]] auto composite_env(env_fn env) -> env_fn;

/// The options from `env`. Throws std::invalid_argument naming the
/// variable at fault.
[[nodiscard]] auto from_env(const env_fn& env) -> hsm_options;

[[nodiscard]] auto usage_text() -> std::string_view;

}  // namespace kythira::hsm_node
