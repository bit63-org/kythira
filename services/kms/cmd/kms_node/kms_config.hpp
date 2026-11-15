// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The KMS module's configuration (.kiro/specs/kms-compatible-api/ tasks 5
// and 12), read from the environment: KYTHIRA_KMS_* for the module, the
// node-wide KYTHIRA_NODE_* settings where the module's are unset
// (composite_env), and the Raft tuning names module_tuning() maps.
// usage_text() documents every variable.

#include <raft/console_logger.hpp>
#include <raft/host_node_id.hpp>
#include <raft/static_or_iam_authorizer.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace kythira::kms_node {

/// The co-located virtual HSM (`hsm.pkcs11`), as KYTHIRA_KMS_PKCS11 names it.
inline constexpr std::string_view co_located_hsm = "hsm";

struct kms_options {
    kythira::host_node_id node_id{kythira::host_node_id_from_number(1)};

    /// Every member's KMS API URL, this node included: the catalog's
    /// voters, and where a follower forwards.
    std::map<kythira::host_node_id, std::string> api_urls;
    std::filesystem::path data_dir;

    // -- The API listener (Requirement 2.5) -------------------------------------
    std::string api_bind{"0.0.0.0"};
    std::uint16_t api_port{8443};
    std::string tls_cert;
    std::string tls_key;
    /// The CA the members' certificates chain to: the listener asks for
    /// (never requires) a client certificate, and forwarding presents one.
    std::string client_ca;
    /// Plaintext listener and forwarding (tests only).
    bool insecure_plaintext{false};
    /// The members' certificate identities (URI or DNS SANs): who may
    /// forward a proposal.
    std::set<std::string> peer_identities;
    std::uint64_t max_body_bytes{std::uint64_t{1} << 20U};
    std::uint64_t max_connections{256};
    /// The principals (user or role ARNs) of consuming services on other
    /// clusters whose requests may carry the caller they serve
    /// (raft/kms_forwarding.hpp). Empty: none may.
    std::set<std::string> trusted_services;

    // -- Who may call (Requirement 7) -------------------------------------------
    /// static: the key file's static roles alone (key policies and grants
    /// are not evaluated); iam: the co-located IAM module; both: a key in
    /// the file is static, any other IAM's.
    kythira::aws_auth::auth_mode auth{kythira::aws_auth::auth_mode::iam};
    std::filesystem::path static_keys_file;
    std::string region{"us-east-1"};
    std::string partition{"aws"};

    // -- Audit (Requirement 13) ----------------------------------------------------
    /// Where request records go: stderr, off or file:<path>.
    std::string audit{"stderr"};

    // -- The backing store (Requirement 4) -------------------------------------
    /// "hsm" for the co-located virtual HSM, else the path of a PKCS#11
    /// library (an external HSM, or the virtual HSM's client library).
    std::string pkcs11{co_located_hsm};
    /// The identity the KMS acts as on the co-located HSM, which the HSM's
    /// catalog binds to the token.
    std::string pkcs11_identity{"kms"};
    std::string token_label{"kms"};
    /// The token's user PIN, read from this file (trailing newline
    /// ignored); never from the environment, which other users of the host
    /// may read.
    std::filesystem::path pin_file;

    // -- The leader's key jobs --------------------------------------------------
    std::chrono::milliseconds job_interval{10000};
    /// How long a Creating key or an unaccounted backing key is left alone
    /// before the jobs settle it.
    std::chrono::milliseconds grace{std::chrono::minutes(5)};

    // -- Raft, timing and logs -------------------------------------------------
    std::chrono::milliseconds tick_interval{5};
    std::chrono::milliseconds election_timeout_min{300};
    std::chrono::milliseconds election_timeout_max{600};
    std::chrono::milliseconds heartbeat_interval{75};
    std::chrono::milliseconds rpc_timeout{2000};
    std::chrono::milliseconds propose_timeout{5000};
    kythira::log_level log_level{kythira::log_level::info};
};

/// Reads one variable; nothing when unset.
using env_fn = std::function<std::optional<std::string>(std::string_view)>;

/// `env` for the module in kythira_node: every variable from `env`, with
/// the TLS files and the plaintext switch filled in from the node's
/// KYTHIRA_NODE_TLS_* and KYTHIRA_NODE_INSECURE_PLAINTEXT when unset. The
/// data directory is always the node's kms/.
[[nodiscard]] auto composite_env(env_fn env) -> env_fn;

/// The options from `env`. Throws std::invalid_argument naming the
/// variable at fault.
[[nodiscard]] auto from_env(const env_fn& env) -> kms_options;

/// The PIN in `path`, without a trailing newline. Throws
/// std::invalid_argument when it cannot be read or is empty.
[[nodiscard]] auto read_pin(const std::filesystem::path& path) -> std::string;

[[nodiscard]] auto usage_text() -> std::string_view;

}  // namespace kythira::kms_node
