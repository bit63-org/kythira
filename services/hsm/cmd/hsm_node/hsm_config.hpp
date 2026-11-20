// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// The HSM module's configuration (.kiro/specs/virtual-hsm/ task 6e), read
// from the environment: KYTHIRA_HSM_* for the module, the node-wide
// KYTHIRA_NODE_* settings where the module's are unset (composite_env), and
// the Raft tuning names module_tuning() maps. usage_text() documents every
// variable.

#include <kythira/hsm/hsm_roles.hpp>

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
#include <utility>
#include <vector>

namespace kythira::hsm_node {

struct hsm_options {
    kythira::host_node_id node_id{kythira::host_node_id_from_number(1)};

    // -- Layers (hsm-independent-layers task 1) --------------------------------
    /// KYTHIRA_HSM_ROLES: the layers this node runs (hsm_roles.hpp); all
    /// three unless set.
    kythira::layers::role_set roles{kythira::hsm::all_hsm_roles()};
    /// KYTHIRA_HSM_RELAY_BACKENDS: the crypto nodes' client listeners an
    /// endpoint without the crypto role relays to.
    std::vector<std::pair<std::string, std::uint16_t>> relay_backends;
    /// Per relay backend, its HSM listener's URL for the unsealed check, or
    /// empty (connect-only).
    std::vector<std::string> relay_health_urls;
    /// KYTHIRA_HSM_STORE_CLIENTS: crypto identities that may use this
    /// store member's store API without being members (peer_policy).
    std::set<std::string> store_clients;
    /// KYTHIRA_HSM_CRYPTO_URLS: identity -> HSM listener URL of every crypto
    /// node, for init and rekey to hand shares to the catalog's crypto
    /// member list and for node unseal to ask them; when unset the members
    /// (KYTHIRA_HSM_API_URLS) are the crypto nodes, as before.
    std::map<std::string, std::string> crypto_urls;

    // -- Members and the listener ---------------------------------------------
    /// Every member's HSM listener ("https://host:port"), this node
    /// included when it has the store role: the voters of every HSM
    /// group, and where a follower forwards to.
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

    // -- PKCS#11 clients (task 9) ----------------------------------------------
    /// The mutual TLS client listener; none when unset (off, or plaintext).
    std::optional<std::pair<std::string, std::uint16_t>> client_listen{{"0.0.0.0", 9444}};
    /// The CA application certificates chain to (default: client_ca).
    std::string app_ca;
    /// The Unix socket; none when empty.
    std::filesystem::path socket_path;
    /// uid -> the identity that uid's socket connections act as.
    std::map<std::uint32_t, std::string> socket_allow;
    std::uint64_t client_max_connections{256};
    std::chrono::seconds client_idle_timeout{3600};

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
    /// Where audit lines go (task 14): "stderr", "off" or "file:<path>".
    std::string audit{"stderr"};
    /// A counted operation is logged on its first call and once in this
    /// many after.
    std::uint64_t audit_sample_every{1000};
    /// A verifiable ledger that also receives every audit line, as
    /// https://host:port; empty for none. Its client certificate, key and
    /// CA default to this node's TLS files.
    std::string audit_ledger_url;
    std::string audit_ledger{"hsm_audit"};
    std::string audit_ledger_table{"audit"};
    std::string audit_ledger_cert;
    std::string audit_ledger_key;
    std::string audit_ledger_ca;
    /// IAM authorization for tokens (task 14b): an identity that is an IAM
    /// user or role ARN is authorized with hsm: actions on the token's ARN
    /// (hsm_iam.hpp) instead of by the bindings.
    bool iam{false};
    std::string iam_partition{"aws"};
    std::string iam_region{"local"};
    std::chrono::milliseconds iam_cache{10000};
    /// Node unseal (task 8): how this node's share is sealed at rest
    /// ("file"; "aws-kms", "pkcs11", "azure-key-vault", "gcp-kms" or "tpm2",
    /// task 8b) and, for "file", the key's
    /// path (default data_dir/share.key).
    std::string share_sealer{"file"};
    std::filesystem::path share_key_file;
    /// The key a KMS sealer wraps share data keys under: an AWS KMS key id,
    /// ARN or alias; a PKCS#11 RSA key's label; an Azure key's URL; a GCP
    /// crypto key's resource name; a TPM's "owner" or persistent handle.
    std::string share_key_id;
    /// aws-kms: the region, and the endpoint (host:port, default AWS's)
    /// with the CA its certificate chains to (default the system store).
    /// gcp-kms takes the endpoint as an https:// URL; both clouds take
    /// the CA.
    std::string share_kms_region;
    std::string share_kms_endpoint;
    std::string share_kms_ca;
    /// pkcs11: the token, a pkcs11: URI naming the library (module-path),
    /// the token and its PIN source; and RSA-OAEP's hash for new seals.
    std::string share_pkcs11_uri;
    std::string share_pkcs11_oaep{"sha256"};
    /// azure-key-vault: Key Vault's wrapping algorithm for new seals.
    std::string share_azure_algorithm{"RSA-OAEP-256"};
    /// tpm2: tpm2-tss's TCTI for the TPM, and the PCRs new seals are bound
    /// to ("sha256:0,2,4,7"; empty binds none).
    std::string share_tpm2_tcti{"device:/dev/tpmrm0"};
    std::string share_tpm2_pcrs;

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
