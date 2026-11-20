// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file config.hpp
/// @brief `kinesis_gateway_node`'s configuration, read from the environment
///        (`.kiro/specs/kinesis-compatible-streams/` task 6, Requirement
///        16.1: "following redis_gateway_node for flags, TLS, forwarding and
///        health").
///
/// The Raft-side variables are `redis_gateway_node`'s, with the same names
/// and defaults. The Kinesis side is `KINESIS_*`. Secrets come from the
/// environment or a file, never from `argv`. A missing required variable or
/// a malformed one is an `std::invalid_argument` naming it.

#include <raft/host_node_id.hpp>
#include <raft/layer_roles.hpp>
#include <raft/logger.hpp>
#include <raft/service_module.hpp>
#include <raft/static_or_iam_authorizer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis_node {

struct node_options {
    // ── the Raft side (redis_gateway_node's variables) ───────────────────────
    kythira::host_node_id _node_id{kythira::host_node_id_from_number(1)};
    std::string _bind_address{"0.0.0.0"};
    std::uint16_t _raft_port{7000};
    bool _allow_plaintext_raft{false};
    /// Every voter's Raft base URL, this node included.
    std::map<kythira::host_node_id, std::string> _peers;
    std::vector<std::string> _shard_cuts;
    std::chrono::milliseconds _tick_interval{2};
    std::chrono::milliseconds _election_timeout_min{150};
    std::chrono::milliseconds _election_timeout_max{300};
    std::chrono::milliseconds _heartbeat_interval{50};
    std::chrono::milliseconds _rpc_timeout{1000};
    std::chrono::milliseconds _policy_interval{10000};
    std::size_t _executor_stripes{4};
    log_level _log_level{log_level::info};

    // ── the Kinesis side ─────────────────────────────────────────────────────
    /// `KINESIS_LISTEN`: host:port of the API (and internal) listener.
    std::string _listen_host{"0.0.0.0"};
    std::uint16_t _listen_port{4567};
    std::string _tls_cert_path;
    std::string _tls_key_path;
    /// `KINESIS_ALLOW_PLAINTEXT`: serve HTTP, and forward to peers over HTTP.
    bool _allow_plaintext{false};
    std::string _region{"us-east-1"};
    std::string _partition{"aws"};
    /// `KINESIS_AUTH`: `static` keys (the default), Kythira `iam`, or
    /// `both` (static_or_iam_authorizer.hpp).
    kythira::aws_auth::auth_mode _auth{kythira::aws_auth::auth_mode::static_keys};
    /// `KINESIS_STATIC_KEYS_FILE` (kinesis_static_keys.hpp): required with
    /// `static` and `both`, refused with `iam`.
    std::string _static_keys_file;
    /// `KINESIS_FORWARD_SECRET` or `KINESIS_FORWARD_SECRET_FILE`: what the
    /// gateways sign forwarded writes and segment fetches with. Required
    /// with more than one voter.
    std::string _forward_secret;
    /// `KINESIS_ITERATOR_KEYS_FILE` (kinesis_iterators.hpp); empty derives
    /// the iterator key from the forwarding secret, or, on a lone node
    /// without one, makes a random key per process.
    std::string _iterator_keys_file;
    /// Every voter's gateway `host:port`. Defaults to the Raft URL's host
    /// with this node's own listen port.
    std::map<kythira::host_node_id, std::string> _peer_gateways;
    /// CA bundle the peers' gateway certificates chain to; the system store
    /// when empty.
    std::string _peer_ca_path;
    /// Raft state under `raft/<group>`, record segments under `segments/`.
    std::filesystem::path _data_dir;
    /// `KINESIS_COMPAT`: cluster compatibility settings, `k=v,k=v`
    /// (kinesis_compat_profile.hpp).
    std::vector<std::pair<std::string, std::string>> _compat;
    std::uint64_t _max_body_bytes{std::uint64_t{8} * 1024 * 1024};
    /// Concurrent API connections, each served on its own thread: the cap
    /// on Kinesis's request threads (service-colocation Requirement 6.1).
    std::size_t _max_connections{256};
    std::chrono::milliseconds _command_timeout{5000};

    // ── retention and tiering (task 10) ──────────────────────────────────────
    /// `KINESIS_DISK_FLOOR_BYTES`: refuse writes below this much free space
    /// on the segment disk; 0 turns the guard off.
    std::uint64_t _disk_floor_bytes{std::uint64_t{1} << 30U};
    /// `KINESIS_METRICS`: serve per-stream and per-shard metrics on
    /// `GET /metrics` (unauthenticated; it names streams and accounts).
    bool _metrics{false};
    /// `KINESIS_ROLES`: the layers this node runs, a comma-separated subset
    /// of gateway, front_end, data and segments (all four by default).
    /// kinesis-independent-layers task 4. Only for the Kinesis module:
    /// `composite_env` never fills it in.
    kythira::layers::role_set _roles{kythira::layers::role_set::all()};
    /// `KINESIS_KMS`: the key provider encrypted streams use (task 14):
    /// `off` (StartStreamEncryption refused), `local` (data keys wrapped
    /// under `KINESIS_KMS_PASSPHRASE[_FILE]`, the same on every node) or
    /// `aws` (AWS KMS in `KINESIS_KMS_REGION`, default the region above, at
    /// `KINESIS_KMS_ENDPOINT` host:port, default AWS's; credentials from
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
    /// or `pkcs11` (keys on the PKCS#11 token `KINESIS_KMS_PKCS11_URI`
    /// names: through its `module-path`, or the co-located virtual HSM as
    /// `KINESIS_KMS_PKCS11_IDENTITY`; RSA-OAEP with
    /// `KINESIS_KMS_PKCS11_OAEP`, sha256 or sha1).
    ///
    /// `kythira` is Kythira's KMS (kms-compatible-api task 15): the
    /// co-located KMS module's `kms.client` in kythira_node, the default
    /// there when the KMS module runs and `KINESIS_KMS` is unset; or, with
    /// `KINESIS_KMS_ENDPOINT`, a KMS on another cluster over HTTPS, signed
    /// with `AWS_ACCESS_KEY_ID` and friends (a principal the KMS lists in
    /// `KYTHIRA_KMS_TRUSTED_SERVICES`) and verified against
    /// `KINESIS_KMS_CA`. Each call is made for the request's own caller.
    std::string _kms{"off"};
    /// `KINESIS_KMS_PREVIOUS`: a provider this node no longer wraps with
    /// but whose data keys it still opens (off, local, aws, pkcs11 or
    /// kythira, with that provider's settings): a stream keeps reading
    /// after a move between providers. Data keys from before providers
    /// were recorded count as this one's.
    std::string _kms_previous{"off"};
    /// Whether `KINESIS_KMS` was set (so kythira_node may default it).
    bool _kms_set{false};
    std::string _kms_ca;
    /// `KINESIS_KMS_CALLER_TTL_MS`: how long one caller's KMS answer for a
    /// stream stands (kythira only).
    std::chrono::milliseconds _kms_caller_ttl{300000};
    std::string _kms_passphrase;
    std::string _kms_region;
    std::string _kms_endpoint;
    std::string _kms_pkcs11_uri;
    std::string _kms_pkcs11_identity;
    std::string _kms_pkcs11_oaep{"sha256"};
    /// `KINESIS_MAINTENANCE_INTERVAL_MS`: how often a node runs the
    /// retention and tiering pass.
    std::chrono::milliseconds _maintenance_interval{60000};
    /// `KINESIS_TIER_AFTER_HOURS`, or `KINESIS_TIER_AFTER_MS` when set
    /// (seconds-scale tiering for tests and demos): tier sealed segments
    /// whose last record is this old; 0 never tiers. Needs the tier
    /// store settings below.
    std::int64_t _tier_after_ms{0};
    /// `KINESIS_TIER_PROVIDER`: `s3` (default; any S3-compatible store with
    /// an endpoint), `azure-blob`, `gcs`, `oci-objectstorage` or `oss`.
    std::string _tier_provider{"s3"};
    /// `KINESIS_TIER_BUCKET` (the container, for Azure) and
    /// `KINESIS_TIER_PREFIX`; `KINESIS_TIER_S3_BUCKET` and `_S3_PREFIX` are
    /// the older spellings and still accepted.
    std::string _tier_bucket;
    std::string _tier_prefix;
    /// `KINESIS_TIER_S3_REGION` (S3 only; default: the region above).
    std::string _tier_region;
    /// `KINESIS_TIER_ENDPOINT` (or `KINESIS_TIER_S3_ENDPOINT`): the S3
    /// endpoint, or the Azure or GCS endpoint override (Azurite, a GCS
    /// emulator); the provider's own when empty. OCI and OSS take theirs
    /// from `KYTHIRA_OCI_*` and `KYTHIRA_ALIBABA_*`.
    std::string _tier_endpoint;
    /// `KINESIS_TIER_AZURE_ACCOUNT`, default `KYTHIRA_AZURE_STORAGE_ACCOUNT`.
    std::string _tier_azure_account;
    /// `GOOGLE_CLOUD_PROJECT`, for GCS.
    std::string _tier_gcs_project;

    // ── channel delivery (task 19) ───────────────────────────────────────────
    /// `KINESIS_CHANNEL_DELIVERY`: deliver ACTIVE channels to S3 on the
    /// maintenance pass (default on; needs the AWS SDK's s3 component, and
    /// a build without it logs that channels are not delivered).
    bool _channel_delivery{true};
    /// `KINESIS_CHANNEL_S3_REGION` (default: the region above) and
    /// `KINESIS_CHANNEL_S3_ENDPOINT` (an S3-compatible endpoint; AWS's when
    /// empty): where channel destination buckets are written.
    std::string _channel_s3_region;
    std::string _channel_s3_endpoint;
    /// `KINESIS_CHANNEL_MAX_DELAY_MS`: when set, write a batch once its
    /// oldest record is this old, even inside the channel's
    /// `DataFreshnessInSeconds` (seconds-scale delivery for tests and
    /// demos); 0, the default, keeps each channel's own.
    std::int64_t _channel_max_delay_ms{0};
    /// `KINESIS_CHANNEL_ROLE`: `node` (the default) writes channel objects
    /// with this node's own credentials; `assume` writes each channel's
    /// objects as its `ServiceExecutionRoleARN`, through STS `AssumeRole`,
    /// as AWS does.
    bool _channel_assume_role{false};
    /// `KINESIS_CHANNEL_ENCRYPTION`: how a channel's
    /// `EncryptionConfiguration` is carried out on general purpose S3
    /// destinations. `envelope` (the default) seals each object on the node
    /// under a data key from `KINESIS_KMS`, asked for as the channel's
    /// execution role; `sse-kms` asks S3 for SSE-KMS under the channel's
    /// key instead. S3 Tables destinations always ask for SSE-KMS.
    bool _channel_sse_kms{false};
    /// `KINESIS_CHANNEL_STS_ENDPOINT`: STS's URL for `assume` (AWS's in the
    /// channel S3 region when empty; Kythira's IAM service also answers).
    std::string _channel_sts_endpoint;
    /// `KINESIS_CHANNEL_CA_FILE`: the CA bundle the STS endpoint's
    /// certificate chains to; the system store when empty.
    std::string _channel_ca_file;
    /// `KINESIS_CHANNEL_ICEBERG_URI`: the Iceberg REST catalog S3 Tables
    /// channels commit through; empty is S3 Tables' own,
    /// `https://s3tables.<region>.amazonaws.com/iceberg` in the table
    /// bucket's region.
    std::string _channel_iceberg_uri;
    /// `KINESIS_CHANNEL_ICEBERG_WAREHOUSE`: the warehouse asked of the
    /// catalog; empty is the channel's table bucket ARN, as S3 Tables
    /// expects.
    std::string _channel_iceberg_warehouse;
    /// `KINESIS_CHANNEL_ICEBERG_SIGV4` (default true): sign catalog calls
    /// with SigV4 as `s3tables`; a local catalog usually wants false.
    bool _channel_iceberg_sigv4{true};
    /// `KINESIS_CHANNEL_ICEBERG_TOKEN`: a bearer token for a catalog that
    /// takes one (only when not signing).
    std::string _channel_iceberg_token;
};

/// Whether this build can tier to `provider`, and if not, what would
/// enable it; `_needs` is empty for a name that is no provider at all.
struct tier_support {
    bool _available{false};
    std::string_view _needs;
};
[[nodiscard]] auto tier_provider_support(std::string_view provider) -> tier_support;

/// Looks a variable up; nullptr when unset. `std::getenv` in the daemon.
using env_lookup = std::function<const char*(const char*)>;

/// @throws std::invalid_argument naming the variable that is missing or
///         malformed.
[[nodiscard]] auto from_env(const env_lookup& env) -> node_options;

/// `from_env` over the module interface's lookup, which says nothing for
/// an unset or empty variable.
[[nodiscard]] auto from_env(const service_node::env_lookup& env) -> node_options;

/// The process environment, as the module interface reads it.
[[nodiscard]] auto process_env() -> service_node::env_lookup;

/// The variables the Kinesis module reads in `kythira_node`
/// (.kiro/specs/service-colocation/ task 5, Requirement 8.1), over `env`:
///
/// - `KINESIS_DATA_DIR` is always the node's data directory's `kinesis/`.
/// - Any other variable set in `env` is taken as it is.
/// - Otherwise the node's settings fill in: `KYTHIRA_PEERS` from
///   `KYTHIRA_NODE_PEERS` (`id=host:port` with the scheme added),
///   `KYTHIRA_RAFT_BIND` and `_PORT` from the node's, the API's
///   certificate and key from `KYTHIRA_NODE_TLS_CERT` and `_KEY`, the peer
///   gateways' CA from `KYTHIRA_NODE_TLS_CA`, and
///   `KINESIS_ALLOW_PLAINTEXT` from `KYTHIRA_NODE_INSECURE_PLAINTEXT=1`.
/// - `KYTHIRA_ALLOW_PLAINTEXT_RAFT` is true: Raft is the node's shared
///   listener, which speaks mutual TLS unless the node is plaintext, so the
///   stand-alone daemon's plaintext-Raft guard does not apply.
[[nodiscard]] auto composite_env(service_node::env_lookup env) -> service_node::env_lookup;

[[nodiscard]] auto is_loopback_address(const std::string& address) -> bool;

/// Why this build cannot serve `roles`, naming what is missing; nullopt
/// when it can. All four roles, and `data,segments` (a voter that serves
/// only the internal endpoints), are served today. The other sets need the
/// later tasks of kinesis-independent-layers.
[[nodiscard]] auto unserved_roles(kythira::layers::role_set roles) -> std::optional<std::string>;

/// One line per setting, secrets elided: what `--check-config` prints.
[[nodiscard]] auto describe(const node_options& o) -> std::string;

[[nodiscard]] auto usage() -> std::string;

}  // namespace kythira::kinesis_node
