// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The KMS module's configuration (.kiro/specs/kms-compatible-api/ tasks 5
// and 12), read from the environment: KYTHIRA_KMS_* for the module, the
// node-wide KYTHIRA_NODE_* settings where the module's are unset
// (composite_env), and the Raft tuning names module_tuning() maps.
// usage_text() documents every variable.

#include <kythira/kms/kms_quotas.hpp>

#include <raft/console_logger.hpp>
#include <raft/host_node_id.hpp>
#include <raft/layer_identity_uri.hpp>
#include <raft/layer_roles.hpp>
#include <raft/static_or_iam_authorizer.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <string_view>

namespace kythira::kms_node {

/// The co-located virtual HSM (`hsm.pkcs11`), as KYTHIRA_KMS_PKCS11 names it.
inline constexpr std::string_view co_located_hsm = "hsm";

/// The layers a KMS node can run (.kiro/specs/kms-independent-layers/,
/// Requirement 2.1): `segments` is Kinesis's.
inline constexpr kythira::layers::role_set kms_roles{
    kythira::layers::role::gateway, kythira::layers::role::front_end, kythira::layers::role::data};

struct kms_options {
    kythira::host_node_id node_id{kythira::host_node_id_from_number(1)};

    /// The layers this node runs (KYTHIRA_KMS_ROLES): all three unless
    /// asked otherwise, which is the KMS spec's co-located node.
    kythira::layers::role_set roles{kms_roles};

    /// Every catalog member's (data node's) KMS API URL: the catalog's
    /// voters, where a follower forwards, and where a front end without
    /// the data role reads and proposes. This node is listed exactly when
    /// it runs `data`.
    std::map<kythira::host_node_id, std::string> api_urls;
    std::filesystem::path data_dir;

    // -- Moving the data role (kms-independent-layers task 6) ----------------------
    /// The catalog's founding voters (KYTHIRA_KMS_VOTERS; the data nodes
    /// in api_urls by default). A data node outside them joins: it creates
    /// no group and takes a replica only when an evacuation adds it.
    std::vector<kythira::host_node_id> voters;
    /// Discard a catalog replica left on disk when starting without the
    /// data role (KYTHIRA_KMS_DISCARD_CATALOG); otherwise such a node
    /// refuses to start until the replica was evacuated and released.
    bool discard_catalog = false;

    // -- Front ends (kms-independent-layers task 4) -------------------------------
    /// Every front end's KMS API URL (KYTHIRA_KMS_FRONT_END_URLS): where a
    /// gateway without its own front end hands calls, and, on a front end,
    /// who shares the quotas (the live ones). Empty on a co-located
    /// deployment, where every catalog member is a front end.
    std::map<kythira::host_node_id, std::string> front_end_urls;
    /// How often each front end's health is asked; one that has not
    /// answered for three of these is not live.
    std::chrono::milliseconds front_end_probe{1000};
    /// The cluster named in this KMS's layer identities
    /// (kythira://kms/<cluster>/<node id>?roles=...): KYTHIRA_KMS_CLUSTER,
    /// else KYTHIRA_CLUSTER.
    std::string cluster{"default"};

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
    /// forward a proposal and, on a data node, which front ends without a
    /// replica may use the catalog API.
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

    // -- Quotas (Requirement 13.3 and 13.4) -----------------------------------------
    /// AWS's request quotas, answering ThrottlingException (on by default).
    bool throttling = true;
    /// The shared cryptographic quotas, by default and per account; the
    /// module sets `members`.
    kythira::kms::quota_config quotas;
    /// Per-account key and alias count limits the leader writes to the
    /// catalog; an account not listed keeps AWS's.
    std::map<std::string, kythira::kms::account_limits> account_limits;

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

    // -- The key jobs, on the job lease's holder --------------------------------------------------
    std::chrono::milliseconds job_interval{10000};
    /// How long the job lease lasts without renewal (every pass renews it):
    /// how long jobs wait when its holder dies without releasing it.
    /// Longer than job_interval.
    std::chrono::milliseconds job_lease{30000};
    /// How long a Creating key or an unaccounted backing key is left alone
    /// before the jobs settle it.
    std::chrono::milliseconds grace{std::chrono::minutes(5)};

    // -- Metadata freshness (Requirement 4.2) -----------------------------------------
    /// 0 (default): every operation reads the catalog at a read-index
    /// point. Otherwise a read-index point at most this old may serve, as
    /// AWS's eventually consistent KMS would.
    std::chrono::milliseconds bounded_staleness{0};

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
/// variable at fault, or the role set the node cannot serve
/// (Requirement 2.4).
[[nodiscard]] auto from_env(const env_fn& env) -> kms_options;

/// The PIN in `path`, without a trailing newline. Throws
/// std::invalid_argument when it cannot be read or is empty.
[[nodiscard]] auto read_pin(const std::filesystem::path& path) -> std::string;

[[nodiscard]] auto usage_text() -> std::string_view;

}  // namespace kythira::kms_node
