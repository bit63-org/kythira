// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file config.hpp
/// @brief `redis_gateway_node`'s configuration, read from the environment
///        (.kiro/specs/redis-compatible-kv/ design Component 9).
///
/// The convention is `cmd/chaos_node/config.hpp`'s: every knob is an
/// environment variable, a missing required one is an `std::invalid_argument`
/// naming it, and the process never reads a secret from `argv` — a command
/// line is world-readable in `ps`, the environment of another user's process
/// is not.

#include <raft/host_node_id.hpp>
#include <raft/logger.hpp>
#include <raft/service_module.hpp>
#include <kythira/redis/redis_gateway.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace kythira::redis_node {

enum class wire_serializer : std::uint8_t {
    json = 0,
    cbor = 1,
};

/// `KYTHIRA_CACHE_PERSISTENCE`: where values and Raft state live.
enum class cache_persistence : std::uint8_t {
    /// Values in RAM, Raft state in RAM: the gateway as it was before the
    /// disk-backed cache, for deployments that want exactly that.
    memory = 0,
    /// Values in the chunk store under `KYTHIRA_CACHE_DATA_DIR`, Raft state
    /// in the binary segmented engine beside it.
    file = 1,
    /// Values in a RocksDB database under `KYTHIRA_CACHE_DATA_DIR/engine`,
    /// one per node, run by `persistent_kv_state_machine`; Raft logs in
    /// `raft/<group>` and snapshot transfers staged in `snapshots/` beside it
    /// (.kiro/specs/persistent-state-machine/ task 7). Needs a build with
    /// `CONFIG_REDIS_GATEWAY_ENGINE=y`.
    engine = 2,
};

/// The disk-backed cache's knobs (.kiro/specs/disk-backed-build-cache/
/// design "Configuration"). Only `_persistence` applies in memory mode;
/// the rest are refused there.
struct cache_options {
    cache_persistence _persistence{cache_persistence::file};
    std::filesystem::path _data_dir;
    std::size_t _chunk_bytes{std::size_t{4} * 1024 * 1024};
    std::uint64_t _max_value_bytes{std::uint64_t{2} * 1024 * 1024 * 1024};
    std::uint64_t _max_disk_bytes{0};
    std::uint64_t _min_free_bytes{std::uint64_t{1} * 1024 * 1024 * 1024};
    std::uint64_t _min_free_inodes{10000};
    std::size_t _pack_threshold_bytes{std::size_t{64} * 1024};
    std::uint64_t _orphan_grace_entries{100000};
    std::uint64_t _fetch_bytes_per_sec{50000000};
    /// Raft log bytes between snapshots. The log carries chunk bytes, so
    /// Raft's 10 MB default would snapshot every few uploads.
    std::size_t _snapshot_threshold_bytes{std::size_t{256} * 1024 * 1024};
    /// Engine mode only: snapshot bytes per second this node sends to
    /// followers it catches up, across every shard. 0 is unlimited.
    std::uint64_t _snapshot_bytes_per_sec{0};
    std::string _http_listen;
    std::string _https_listen;
    bool _allow_plaintext_http{false};
    std::string _tls_cert_path;
    std::string _tls_key_path;
    std::chrono::seconds _auth_cache_ttl{300};
    /// Every voter's HTTP front end `host:port`, for chunk fetches and
    /// relayed writes. Defaults to the peer's host with this node's own
    /// HTTPS port when forwarding over TLS, else its HTTP port.
    std::map<kythira::host_node_id, std::string> _peer_http;
};

/// The elastic capacity loop over one stateless layer (redis-general-data-types
/// task 18, Requirement 20.3). The membership group's leader runs it; plain
/// numbers here so this header stays free of the controller's.
struct capacity_options {
    /// `gateway` or `front_end`; empty runs no loop.
    std::string _layer;
    /// The quorum manager that adds and removes machines. `docker` for now.
    std::string _provider{"docker"};
    /// Decide, log and count, but call no provider (the controller's first
    /// step of adoption). On unless KYTHIRA_REDIS_CAPACITY_DRY_RUN=false.
    bool _dry_run{true};
    bool _scale_in{true};
    std::size_t _min_members{2};
    /// 0: three times the first size the loop sees.
    std::size_t _max_members{0};
    /// Requests per second per serving member; 0 turns the signal off.
    double _requests_high{2000.0};
    double _requests_low{600.0};
    /// Open connections per serving member; 0 (the default) turns it off.
    double _connections_high{0.0};
    double _connections_low{0.0};
    /// CPU share at which a member counts as overloaded; 0 turns it off.
    double _overload_cpu{0.85};
    std::chrono::milliseconds _sustained{std::chrono::minutes{2}};
    std::chrono::milliseconds _scale_in_sustained{std::chrono::minutes{15}};
    std::chrono::milliseconds _cooldown{std::chrono::minutes{5}};
    std::chrono::milliseconds _drain_deadline{std::chrono::minutes{10}};
    std::chrono::milliseconds _interval{std::chrono::seconds{5}};
    // ── docker ───────────────────────────────────────────────────────────────
    std::string _docker_url{"unix:///var/run/docker.sock"};
    std::string _docker_image;
    std::string _docker_network;
    std::string _docker_cluster;
    /// The new machines' Raft port; 0 means this node's own.
    std::uint16_t _node_port{0};
    /// `KEY=VALUE` entries every new machine gets, after KYTHIRA_NODE_ID.
    std::vector<std::string> _join_env;
};

struct node_options {
    // ── the Raft side ────────────────────────────────────────────────────────
    /// `kythira::host_node_id`: a number, or canonical composite text in a
    /// `KYTHIRA_NODE_ID_KIND=text` build.
    kythira::host_node_id _node_id{kythira::host_node_id_from_number(1)};
    std::string _bind_address{"0.0.0.0"};
    std::uint16_t _raft_port{7000};
    /// Raft RPC here is plain, unauthenticated HTTP. A non-loopback
    /// `_bind_address` needs this explicit opt-in (KYTHIRA_ALLOW_PLAINTEXT_RAFT).
    bool _allow_plaintext_raft{false};
    /// Every voter's Raft base URL, this node included: `id=http://host:port`.
    std::map<kythira::host_node_id, std::string> _peers;
    /// Every voter's gateway `host:port`, for forwarding. Defaults to the
    /// peer's host with this node's own plaintext listen port.
    std::map<kythira::host_node_id, std::string> _peer_gateways;
    /// The layer membership group's voters (`KYTHIRA_REDIS_MEMBERSHIP`;
    /// redis-general-data-types task 18), each one of `_peers`. A node
    /// listed here holds a replica of the group; empty runs no group.
    std::vector<kythira::host_node_id> _membership_voters;
    /// The capacity loop a voter runs while it leads the group.
    capacity_options _capacity;
    /// A data node that founds no group (`KYTHIRA_REDIS_JOIN`; task 19): it
    /// takes replicas only when a group adds it (`KYTHIRA.EVACUATE ... TO`
    /// it), learning each group from a peer. Also implied by the marker a
    /// start without `data` leaves after discarding its replicas.
    bool _join{false};
    /// Start without `data` even though the data directory still holds Raft
    /// replicas, deleting them (`KYTHIRA_REDIS_DISCARD_REPLICAS`). Without
    /// it such a start refuses, unless `KYTHIRA.EVACUATE RELEASE` marked the
    /// node released.
    bool _discard_replicas{false};
    /// The voters a group keeps through an evacuation that names none
    /// (`KYTHIRA_REDIS_REPLICAS`); 0 keeps as many as the node founded
    /// groups with (`KYTHIRA_PEERS`).
    std::size_t _replicas{0};
    /// Where the replicas are held on disk: `KYTHIRA_CACHE_DATA_DIR`,
    /// read for the check even on an in-memory store.
    std::filesystem::path _replica_dir;
    /// Keys the initial shard map is cut at; empty means one shard covering
    /// the whole key space, from which the split policy takes over.
    std::vector<std::string> _shard_cuts;
    std::chrono::milliseconds _tick_interval{2};
    std::chrono::milliseconds _election_timeout_min{150};
    std::chrono::milliseconds _election_timeout_max{300};
    std::chrono::milliseconds _heartbeat_interval{50};
    std::chrono::milliseconds _rpc_timeout{1000};
    std::chrono::milliseconds _policy_interval{10000};
    std::size_t _executor_stripes{4};
    wire_serializer _serializer{wire_serializer::cbor};
    /// Applied to the host's logger, every group's logger and the gateway's.
    /// `info` by default: a healthy server is quiet, and the Raft core's
    /// debug stream is a heartbeat every 50 ms per follower per group.
    log_level _log_level{log_level::info};

    // ── the gateway side ─────────────────────────────────────────────────────
    std::string _acl_file;
    redis_gateway_config _gateway;

    // ── the disk-backed cache ────────────────────────────────────────────────
    cache_options _cache;
};

/// The marker `KYTHIRA.EVACUATE RELEASE` leaves in the data directory.
[[nodiscard]] auto released_marker(const std::filesystem::path& data_dir) -> std::filesystem::path;
/// The marker a start without `data` leaves after deleting its replicas:
/// the node left the groups it founded, so it joins when it is a data node
/// again.
[[nodiscard]] auto left_marker(const std::filesystem::path& data_dir) -> std::filesystem::path;
/// The Raft group directories under `<data_dir>/raft`.
[[nodiscard]] auto held_replica_dirs(const std::filesystem::path& data_dir)
    -> std::vector<std::filesystem::path>;

/// Task 19 (Requirement 21.3): what a start does with the replicas in the
/// data directory. Without `data`, replicas held on disk refuse the start
/// unless the node was released or `_discard_replicas` is set; then they
/// are deleted and the left marker written. Returns whether a data node
/// joins (founds no group).
/// @throws std::runtime_error for a start that would drop replicas.
auto settle_held_replicas(const node_options& o) -> bool;

/// Read every variable in design Component 9's table, plus the Raft ones.
/// @throws std::invalid_argument naming the variable that is missing or malformed.
[[nodiscard]] auto from_env() -> node_options;

/// The same, through a module interface's lookup: the process environment
/// stand-alone (`process_env()`), the node's view of it in kythira_node
/// (`composite_env()`).
[[nodiscard]] auto from_env(const service_node::env_lookup& env) -> node_options;

/// The process environment as a module interface's lookup. A variable set
/// to the empty string is set, as `from_env()` reads it.
[[nodiscard]] auto process_env() -> service_node::env_lookup;

/// The variables the Redis module reads in kythira_node
/// (.kiro/specs/service-colocation/ task 7, Requirement 8.1).
///
/// - KYTHIRA_CACHE_DATA_DIR is the node's data directory's redis/, except
///   in memory mode, which has none.
/// - KYTHIRA_ALLOW_PLAINTEXT_RAFT is true and KYTHIRA_WIRE_SERIALIZER is
///   cbor: Raft is the node's listener and wire.
/// - Any other variable set in `env` is taken as it is.
/// - KYTHIRA_REDIS_ROLES is never filled in: the role set is the module's
///   own (redis-general-data-types Requirement 16.4), all three unless set,
///   whatever roles other modules on the node run.
/// - Otherwise the node's settings fill in: KYTHIRA_PEERS from
///   KYTHIRA_NODE_PEERS (`id=host:port`, with the scheme added),
///   KYTHIRA_RAFT_BIND and _PORT from the node's, and the RESP TLS
///   listener's certificate and key and the forwarding CA from
///   KYTHIRA_NODE_TLS_*. KYTHIRA_NODE_ID is the same variable in both.
[[nodiscard]] auto composite_env(service_node::env_lookup env) -> service_node::env_lookup;

/// True when every address `address` binds is loopback: 127.0.0.0/8, ::1, or a
/// name such as "localhost" that /etc/hosts maps only to those.
[[nodiscard]] auto is_loopback_address(const std::string& address) -> bool;

[[nodiscard]] auto usage() -> std::string;

}  // namespace kythira::redis_node
