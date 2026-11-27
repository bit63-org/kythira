// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_gateway.hpp
/// @brief The Redis-compatible front end over `multi_raft`
///        (.kiro/specs/redis-compatible-kv/ design Components 5-9).
///
/// A `redis_gateway` owns the listening sockets, the per-connection RESP
/// state, authentication/authorization, the read and write paths onto a
/// `multi_raft<Types, std::string, std::uint64_t>` host, expiry and
/// eviction proposals, and one-hop forwarding to the shard leader's gateway.
/// It changes nothing in the consensus core: every write is a
/// `submit_command`, every read is a `with_state_machine`.
///
/// Threading model. Boost.Asio drives the sockets on `_io_threads` threads.
/// Command execution blocks — a write waits for commit, a forward waits for
/// the peer — so it never runs on an I/O thread: each connection hands its
/// queued commands to a worker pool, one job per connection at a time, which
/// keeps replies in command order and lets an I/O thread keep reading other
/// connections while a worker waits on Raft. Backpressure is the queue depth:
/// past `_max_inflight_per_connection` the connection simply stops reading.
///
/// Definitions live in redis_gateway_impl.hpp, this tree's convention.

#include <kythira/redis/redis_acl.hpp>
#include <kythira/redis/redis_auth_limiter.hpp>
#include <kythira/redis/redis_call_wire.hpp>
#include <kythira/redis/redis_format_level.hpp>
#include <kythira/redis/redis_forward_link.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_data_access.hpp>
#include <kythira/redis/redis_data_wire.hpp>
#include <kythira/redis/redis_gateway_value_access.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>
#include <kythira/redis/redis_server_identity.hpp>
#include <kythira/redis/redis_layer_membership.hpp>
#include <kythira/redis/redis_layer_roles.hpp>
#include <kythira/redis/resp_protocol.hpp>
#include <raft/credential_verifier.hpp>
#include <raft/future_default.hpp>
#include <raft/layer_identity_uri.hpp>
#include <raft/raft_timestamp_oracle.hpp>
#include <raft/shard_exceptions.hpp>
#include <raft/txn_coordinator.hpp>
#include <raft/txn_envelope.hpp>
#include <raft/txn_state_machine.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kythira {

enum class redis_read_consistency : std::uint8_t {
    /// Serve from the shard leader's applied state; forward otherwise.
    leader,
    /// Serve from whichever local replica has the shard, leader or not.
    any_replica,
    /// Propose a no-op through the log first, then read the leader's state.
    linearizable,
};

[[nodiscard]] inline auto parse_redis_read_consistency(std::string_view s)
    -> std::optional<redis_read_consistency> {
    if (s == "leader") {
        return redis_read_consistency::leader;
    }
    if (s == "any_replica" || s == "any-replica") {
        return redis_read_consistency::any_replica;
    }
    if (s == "linearizable") {
        return redis_read_consistency::linearizable;
    }
    return std::nullopt;
}

/// `--txn-isolation` and `KYTHIRA.ISOLATION` spellings: the level names of
/// `to_string(txn_isolation)`, with `-` accepted for `_`.
[[nodiscard]] inline auto parse_txn_isolation(std::string_view s) -> std::optional<txn_isolation> {
    std::string norm(s);
    for (auto& c : norm) {
        c = c == '-' ? '_' : static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    for (auto level : {txn_isolation::read_committed, txn_isolation::read_committed_wait,
                       txn_isolation::snapshot, txn_isolation::serializable}) {
        if (norm == to_string(level)) {
            return level;
        }
    }
    return std::nullopt;
}

/// Everything the daemon's `from_env()` fills in (design Component 9).
struct redis_gateway_config {
    /// Plaintext listener, `host:port`. Empty disables it.
    std::string _listen = "0.0.0.0:6379";
    /// TLS listener, `host:port`. Empty disables it.
    std::string _tls_listen;
    std::string _tls_cert_path;
    std::string _tls_key_path;
    std::string _tls_ca_path;
    bool _require_client_cert = false;

    /// Only honoured when the ACL is empty; warns at every startup.
    bool _allow_anonymous = false;
    redis_read_consistency _read_consistency = redis_read_consistency::leader;
    std::size_t _max_value_bytes = 8u * 1024u * 1024u;
    std::size_t _max_clients = 1024;
    std::chrono::milliseconds _idle_timeout{300000};
    std::chrono::milliseconds _command_timeout{5000};
    std::size_t _max_shard_bytes = 1024u * 1024u * 1024u;
    std::size_t _sweep_batch = 1024;
    bool _immutable_values = true;
    bool _forwarding = true;

    /// Identity forwarded commands authenticate as on the peer gateway. A
    /// command arriving on a connection authenticated as this user is never
    /// forwarded again (one hop). The user must exist in the ACL with a role
    /// of at least read_write and scope `*`; the daemon creates it.
    std::string _internal_user = "kythira-internal";
    std::string _internal_secret;

    /// Forward over TLS, to the peers' TLS listeners. Forwarding sends
    /// `AUTH <_internal_user> <_internal_secret>` to the peer, and that
    /// identity can read and write every key, so the internal connection is
    /// TLS unless `_allow_plaintext_forwarding` says otherwise. The peer's
    /// certificate must chain to the forwarding CA and name the host its
    /// endpoint is dialled by (a DNS SAN, or an IP SAN for an address).
    bool _forward_tls = false;
    /// CA bundle peer gateways' certificates must chain to. Empty means
    /// `_tls_ca_path`; forwarding over TLS with neither set refuses to start.
    std::string _forward_tls_ca_path;
    /// Client certificate and key presented to peers whose TLS listener asks
    /// for one. Empty means the listener's own `_tls_cert_path` and
    /// `_tls_key_path`, which then need the clientAuth key usage (or none).
    std::string _forward_tls_cert_path;
    std::string _forward_tls_key_path;
    /// Forward over plaintext TCP, sending the internal secret in the clear.
    /// Off by default: with neither this nor `_forward_tls`, a command for a
    /// shard led elsewhere is answered with the retry error instead.
    bool _allow_plaintext_forwarding = false;

    std::size_t _io_threads = 2;
    std::size_t _worker_threads = 8;
    std::size_t _max_inflight_per_connection = 128;
    /// Bytes of queued-but-unexecuted command arguments across all
    /// connections; past this, new commands are answered with a retryable
    /// error instead of being queued.
    std::size_t _max_inflight_bytes = 256u * 1024u * 1024u;
    /// Auth failures per source (IPv4 address or IPv6 /64) per window before
    /// AUTH is refused without running the KDF. An attempt counts against
    /// this from the moment it starts, so concurrent guesses cannot exceed it.
    std::size_t _auth_failure_limit = 10;
    std::chrono::seconds _auth_failure_window{60};
    /// PBKDF2 derivations allowed in flight across the gateway; AUTH past it
    /// is refused with a retryable error. 0 means half the worker pool (at
    /// least one), which keeps the rest free for authenticated commands.
    std::size_t _max_concurrent_auth = 0;
    /// Reply bytes a connection may have queued for its socket before the
    /// gateway stops executing its commands (and so, via the in-flight queue,
    /// stops reading from it) until the client drains them. Redis's
    /// client-output-buffer-limit, but as backpressure rather than a
    /// disconnect. One reply may overshoot it; the next waits.
    std::size_t _max_output_buffer_bytes = 32u * 1024u * 1024u;
    /// The same before the connection has authenticated. Pre-auth replies are
    /// a few bytes each, so this only ever stops a client that pipelines
    /// junk and never reads.
    std::size_t _pre_auth_output_buffer_bytes = 64u * 1024u;
    /// Log every command at debug level. Off by default: at sccache rates it
    /// is a firehose.
    bool _log_commands = false;

    /// The layers this node runs (`KYTHIRA_REDIS_ROLES`,
    /// .kiro/specs/redis-general-data-types/ Requirement 16), reported as
    /// `INFO`'s `kythira_roles:` (Requirement 16.7). Every role, the default,
    /// is the gateway as it has always been.
    layers::role_set _layer_roles = k_redis_all_roles;
    /// Data nodes a front end without the `data` role asks for routes
    /// (`KYTHIRA_REDIS_DATA_NODES`, `host:port` each, names resolved when
    /// used; task 16). Commands then reach the data layer over
    /// `KYTHIRA.DATA` on the forward link, which therefore needs the
    /// internal secret and TLS (or plaintext forwarding allowed). Ignored by
    /// a node with `data`; required, non-empty, by one without.
    std::vector<std::string> _data_nodes;
    /// Front ends a gateway without the `front_end` role sends commands to
    /// (`KYTHIRA_REDIS_FRONT_ENDS`, `host:port` each, names resolved when
    /// used; task 17), as authenticated calls (`KYTHIRA.CALL`,
    /// redis_call_wire.hpp) over the forward link. Each connection is
    /// pinned to one, chosen by affinity, and moves to another when it
    /// fails. Ignored by a node with `front_end`; required by one without
    /// that has `gateway`.
    std::vector<std::string> _front_ends;
    /// The cluster named in layer identities,
    /// `kythira://redis/<cluster>/<node>?roles=...`
    /// (`KYTHIRA_REDIS_CLUSTER`; Requirement 19.1). A peer certificate
    /// naming another cluster carries no identity here.
    std::string _layer_cluster = "default";
    /// `KYTHIRA_NODE_INSECURE_PLAINTEXT=1`: a node that is not co-located
    /// may run without layer identities, and the internal secret then
    /// stands in for every role (Requirement 19.4). Also allows plaintext
    /// forwarding. For tests and isolated networks only.
    bool _insecure_plaintext = false;
    /// How long `drain()` lets commands already received finish before it
    /// closes the connections (`KYTHIRA_REDIS_DRAIN_TIMEOUT_MS`;
    /// Requirement 17.4).
    std::chrono::milliseconds _drain_timeout{10000};
    /// How often the TLS certificate, key and CA files are checked for a
    /// change. A change is picked up for new connections without a restart
    /// (Requirement 19.5); 0 checks on every new connection.
    std::chrono::milliseconds _tls_reload_interval{1000};

    // ---- layer membership (task 18, Requirement 20) ------------------------
    /// Front ends found by DNS (`KYTHIRA_REDIS_FRONT_ENDS_DNS`, one
    /// `name:port`): every address the name resolves to is a front end,
    /// re-resolved every `_discovery_interval`. Used instead of
    /// `_front_ends` when set.
    std::string _front_ends_dns;
    std::chrono::milliseconds _discovery_interval{5000};
    /// The layer membership group's voters (`KYTHIRA_REDIS_MEMBERSHIP`, the
    /// `host:port` each one's gateway listens on). With voters, or with
    /// `_membership_local`, this node announces itself to the group,
    /// reports its load, follows its drain state, and a gateway without
    /// `front_end` calls the group's serving front ends (falling back to
    /// `_front_ends` while the group names none).
    std::vector<std::string> _membership_voters;
    /// Set on a node that holds a replica of the group: proposes a
    /// membership command and returns the state machine's one-byte answer,
    /// or nullopt when it could not commit here (not the leader, no
    /// quorum); and reads this replica's member list. This node then
    /// answers `KYTHIRA.MEMBERS` for the others.
    struct membership_replica {
        std::function<std::optional<std::vector<std::byte>>(std::vector<std::byte>)> _propose;
        std::function<std::vector<layers::layer_member>()> _read;
    };
    std::optional<membership_replica> _membership_local;
    /// How often a member refreshes the list, re-announces when the group
    /// lost it, and reports its load. Members silent for three intervals
    /// are not called.
    std::chrono::milliseconds _membership_interval{1000};
    /// This node in the group: its id (default: the Raft node id), the
    /// address other layers reach it on (`KYTHIRA_REDIS_ADVERTISE`;
    /// default: the host name and the TLS port, else the plaintext one) and
    /// its placement group (`KYTHIRA_REDIS_PLACEMENT_GROUP`).
    std::string _member_id;
    std::string _advertise_address;
    std::string _placement_group;
    /// The 14-bit number in the `SCAN` cursors this front end issues
    /// (`KYTHIRA_REDIS_FRONT_END_INDEX`, 1-16383; default: the node id when
    /// it is such a number), published in the group so a cursor can find
    /// its issuer.
    std::uint32_t _front_end_index = 0;

    resp_parser_limits _parser_limits{};

    /// Multi-key commands as cross-shard transactions
    /// (.kiro/specs/multi-raft-transactions/ task 9): `MSET`, multi-key
    /// `DEL`, `MGET` and `MULTI`/`EXEC`/`DISCARD`. Off by default, and
    /// refused at `start()` unless the host's state machine is wrapped in
    /// `transactional_state_machine` (Requirement 11.1). Off, those commands
    /// keep today's behaviour (Requirement 11.2).
    bool _transactions = false;
    /// A connection's isolation until it sends `KYTHIRA.ISOLATION`. A level
    /// the build cannot give is refused at `start()`, never downgraded.
    txn_isolation _txn_isolation = txn_isolation::read_committed;
    /// How long a prepared intent lives without a heartbeat before any party
    /// may abort its transaction.
    std::chrono::milliseconds _txn_lock_ttl{3000};
    /// Automatic retries of a transaction that met a conflict.
    std::size_t _txn_max_retries = 2;

    /// The authentication seam (.kiro/specs/redis-gateway-module/
    /// Requirement 6): something outside the gateway that can vouch for a
    /// credential a password check cannot, such as an IAM token. `AUTH` and
    /// `HELLO ... AUTH` for a user `_credential_verifier_users` selects go to
    /// it instead of the ACL's password check; every other user, and every
    /// user while either field is empty, authenticates exactly as without
    /// them. An accepted credential takes the ACL user's role and key
    /// prefixes, and its expiry closes the connection.
    ///
    /// redis_gateway_node sets both when built with
    /// `CONFIG_REDIS_GATEWAY_IAM` (IAM task 21): the verifier is IAM's, and
    /// the predicate selects the ACL's `auth=iam` and `auth=both` users. A
    /// `both` user the verifier refuses is then checked against its
    /// password in the same admission slot.
    credential_verifier_fn _credential_verifier;
    std::function<bool(std::string_view user)> _credential_verifier_users;

    /// Server identity (.kiro/specs/redis-general-data-types/ Requirement
    /// 1.5-1.6, kythira/redis/redis_server_identity.hpp). `HELLO`'s
    /// `kythira_version` and `INFO`'s `kythira_version:`.
    /// The build's version (kythira::build_version(), linked through
    /// kythira_redis); tests that pin reply bytes set a fixed one.
    std::string _kythira_version{kythira::build_version()};
    /// `HELLO`'s `version` and `INFO`'s `redis_version:`: a plain
    /// `major.minor.patch`, checked at `start()`.
    std::string _redis_compat_version{k_redis_compat_version};
    /// The Redis Cluster protocol compatibility mode (Requirement 34, phase
    /// 2). Until it is on, `HELLO` and `INFO` report `standalone`, because
    /// cluster-aware tools treat `cluster` as a promise that `CLUSTER`
    /// commands work.
    bool _cluster_compat_mode = false;
    /// The Redis format level this node reports to `KYTHIRA.FORMAT`
    /// (redis-general-data-types task 2). 0, the default, is the build's
    /// own; the in-process rolling-upgrade tests set a lower one to stand
    /// for a node still running an older binary.
    std::uint16_t _reported_format_level = 0;
};

/// Counters the gateway keeps for INFO and for the metrics back-end.
struct redis_gateway_stats {
    std::atomic<std::uint64_t> _hits{0};
    std::atomic<std::uint64_t> _misses{0};
    std::atomic<std::uint64_t> _writes{0};
    std::atomic<std::uint64_t> _deletes{0};
    std::atomic<std::uint64_t> _bytes_in{0};
    std::atomic<std::uint64_t> _bytes_out{0};
    std::atomic<std::uint64_t> _oversize_rejections{0};
    std::atomic<std::uint64_t> _value_conflicts{0};
    std::atomic<std::uint64_t> _evictions{0};
    std::atomic<std::uint64_t> _expirations{0};
    std::atomic<std::uint64_t> _auth_failures{0};
    /// AUTHs refused because too many KDFs were already running.
    std::atomic<std::uint64_t> _auth_busy{0};
    /// Connections closed, or commands refused, because the credential the
    /// connection authenticated with had expired.
    std::atomic<std::uint64_t> _credential_expiries{0};
    std::atomic<std::uint64_t> _authz_denials{0};
    std::atomic<std::uint64_t> _forwards{0};
    std::atomic<std::uint64_t> _forward_failures{0};
    /// A gateway without `front_end` (task 17): calls sent, connections
    /// moved to another front end, and calls whose front end was lost
    /// after the request left (answered with the ambiguity error).
    std::atomic<std::uint64_t> _front_end_calls{0};
    std::atomic<std::uint64_t> _front_end_repins{0};
    std::atomic<std::uint64_t> _front_end_lost{0};
    /// Layer membership (task 18): announcements and load reports the group
    /// committed, and refreshes or proposals that failed.
    std::atomic<std::uint64_t> _membership_announces{0};
    std::atomic<std::uint64_t> _membership_reports{0};
    std::atomic<std::uint64_t> _membership_failures{0};
    /// `KYTHIRA.CALL`s this front end is running now, and has run.
    std::atomic<std::uint64_t> _calls_in_flight{0};
    std::atomic<std::uint64_t> _front_end_calls_served{0};
    std::atomic<std::uint64_t> _connections_accepted{0};
    std::atomic<std::uint64_t> _connections_rejected{0};
    std::atomic<std::uint64_t> _connections_current{0};
    std::atomic<std::uint64_t> _commands{0};
    std::atomic<std::uint64_t> _shed{0};
    /// Times a connection stopped executing because its client was not
    /// reading replies (`_max_output_buffer_bytes`).
    std::atomic<std::uint64_t> _output_stalls{0};
    std::atomic<std::uint64_t> _over_budget_ticks{0};
    /// Writes refused because this node or a voter of the shard is below a
    /// free-space or free-inode floor (cache hooks, Requirement 6.6).
    std::atomic<std::uint64_t> _space_refusals{0};
    /// `KYTHIRA.ADVISE` batches sent to shard leaders, and received.
    std::atomic<std::uint64_t> _advisories_sent{0};
    std::atomic<std::uint64_t> _advisory_failures{0};
    std::atomic<std::uint64_t> _advisories_received{0};
    /// Follower-served reads dropped because a shard's touch queue was full.
    std::atomic<std::uint64_t> _touches_dropped{0};
    /// Transactions by outcome (task 9).
    std::atomic<std::uint64_t> _txn_committed{0};
    std::atomic<std::uint64_t> _txn_aborted{0};
    std::atomic<std::uint64_t> _txn_unknown{0};
    /// Plain writes that met a transaction's lock and resolved it.
    std::atomic<std::uint64_t> _txn_lock_resolves{0};
};

/// What a disk-backed node adds to the gateway
/// (.kiro/specs/disk-backed-build-cache/ task 7). Every hook is optional;
/// with none set the gateway behaves as it always has.
///
/// Reads a follower serves are queued per shard and sent to the shard's
/// leader once per `run_maintenance()`, as a `KYTHIRA.ADVISE` command on the
/// forwarding link, so eviction is not blind to traffic that never reached
/// the leader (Requirement 6.2). The same message carries `_advisory()`'s
/// payload, which in the daemon is this node's free space (Requirement 6.6).
/// It is sent to every leader of a shard this node follows, even with no
/// reads to report, and only internal connections may send it.
template<typename NodeId, typename GroupId> struct redis_gateway_cache_hooks {
    /// Why a write to `group`, whose voters are given, must be refused with
    /// a retryable error; `nullopt` lets it go ahead. Asked on the leader,
    /// just before it proposes a `SET`. `DEL` is never refused: it frees
    /// space.
    std::function<std::optional<std::string>(const GroupId&, const std::vector<NodeId>&)>
        _write_refusal;
    /// Bytes to free for `group`'s voters to fit the node disk budget. A
    /// non-zero answer makes the leader evict that much from the shard's
    /// least-recently-read keys, as an over-budget shard does.
    std::function<std::uint64_t(const GroupId&, const std::vector<NodeId>&)> _excess_bytes;
    /// The payload this node sends with each advisory.
    std::function<std::string()> _advisory;
    /// A payload a peer sent.
    std::function<void(std::string_view)> _on_advisory;
    /// Appended to `INFO`: whole `# Section\r\n` blocks.
    std::function<std::string()> _info;
};

/// Resolves a peer node id to the `host:port` of that node's gateway for
/// forwarding. Supplied by the daemon from its membership/peer-discovery
/// view; the in-process tests supply a map.
template<typename NodeId>
using redis_endpoint_resolver = std::function<std::optional<std::string>(const NodeId&)>;

namespace redis_gateway_detail {
template<typename SM, bool = is_transactional_state_machine_v<SM>>
struct is_mvcc : std::false_type {};
template<typename SM> struct is_mvcc<SM, true> : std::bool_constant<SM::k_mvcc == mvcc::on> {};
template<typename SM> inline constexpr bool is_mvcc_v = is_mvcc<SM>::value;
}  // namespace redis_gateway_detail

/// The front-end layer (.kiro/specs/redis-general-data-types/ design
/// Component 9): authorization, planning (one group, a fan-out, or a
/// transaction), the transaction coordinator, and every command handler
/// past authentication, reaching data through `redis_data_access`. Its
/// definitions are in redis_front_end_impl.hpp.
///
/// `redis_gateway` (below) is the gateway layer on top of it: listeners,
/// TLS, connection state, `AUTH`/`HELLO`/`CLIENT`/`QUIT`/`RESET`. A
/// co-located node runs both in one object, with no hop or copy between
/// them; a gateway without the `front_end` role sends its commands to a
/// remote front end instead (task 17).
///
/// `Host` is a `multi_raft<Types, std::string, std::uint64_t>` whose state
/// machine is `redis_kv_state_machine` (values in RAM) or
/// `cache_kv_state_machine` (values in the node's chunk store); the front
/// end reads it through `redis_gateway_value_access`. `Logger` and `Metrics`
/// satisfy the project's `logger` and `metrics` concepts.
template<typename Host, typename Logger, typename Metrics> class redis_front_end {
public:
    using node_id_type = typename Host::node_id_type;
    using group_id_type = typename Host::group_id_type;
    using group_node_type = typename Host::group_node_type;
    using endpoint_resolver = redis_endpoint_resolver<node_id_type>;
    using state_machine_type = typename Host::types::state_machine_type;
    using value_access = redis_gateway_value_access<state_machine_type>;
    using entry_handle = typename value_access::entry_handle;
    using entry_type = typename value_access::entry_type;
    using value_context = typename value_access::context;
    using cache_hooks = redis_gateway_cache_hooks<node_id_type, group_id_type>;

    /// Whether the host's state machine takes part in transactions; decided
    /// by the build, as the snapshot format follows it.
    static constexpr bool k_transactional = is_transactional_state_machine_v<state_machine_type>;
    /// Whether the wrapped state machine keeps versions (`mvcc::on`,
    /// CONFIG_REDIS_GATEWAY_SNAPSHOT_ISOLATION): then the gateway offers
    /// `snapshot`, and every write takes an oracle timestamp.
    static constexpr bool k_snapshot = redis_gateway_detail::is_mvcc_v<state_machine_type>;
    /// The store under the transaction wrapper, if any.
    using kv_store_type = std::remove_cvref_t<decltype(redis_gateway_detail::kv_of(
        std::declval<state_machine_type&>()))>;
    /// The Redis format level this node reports (redis-general-data-types
    /// Requirement 14.3): the binary's level when its store reads the newer
    /// formats, else the base level, so a cluster whose store does not
    /// (the engine and multi-version stores until tasks 10 and 11) can
    /// never pass the gate.
    static constexpr std::uint16_t k_node_format_level = requires(const kv_store_type& kv) {
        kv.format_level();
    } ? k_redis_format_level : k_redis_base_format_level;

    redis_front_end(Host& host, redis_acl& acl, Logger& logger, Metrics& metrics,
                    redis_gateway_config config, endpoint_resolver resolver);

    redis_front_end(const redis_front_end&) = delete;
    auto operator=(const redis_front_end&) -> redis_front_end& = delete;
    redis_front_end(redis_front_end&&) = delete;
    auto operator=(redis_front_end&&) -> redis_front_end& = delete;

    /// Leader-side maintenance: propose a bounded `sweep` of expired keys and,
    /// when a shard is over budget, a bounded `evict`. Meant to be called from
    /// the host's driver thread after a `tick()` whose policy phase ran, so
    /// the gateway adds no thread of its own (Requirement 6.3). Returns the
    /// number of proposals made.
    auto run_maintenance() -> std::size_t;

    /// Install the disk-backed node's hooks. Call before `start()`.
    auto set_cache_hooks(cache_hooks hooks) -> void { _cache_hooks = std::move(hooks); }

    /// A read or write of `key` that reached its shard without this gateway
    /// (the cache HTTP front end): it moves the key in the least-recently-
    /// read order as a RESP access would, and on a follower is queued for
    /// the leader's. Without it a key only HTTP clients touch would never
    /// enter the order and never be evicted.
    auto note_access(const std::string& key) -> void;
    /// `key` was deleted without this gateway: drop it from the order.
    auto note_removed(const std::string& key) -> void;

    /// Most keys a shard's follower-read queue holds between advisories.
    static constexpr std::size_t max_queued_touches = 4096;
    /// One eviction pass looks at most this many times `_sweep_batch` keys,
    /// passing over those whose eviction would free nothing on disk.
    static constexpr std::size_t evict_scan_factor = 16;

    [[nodiscard]] auto stats() const noexcept -> const redis_gateway_stats& { return _stats; }
    [[nodiscard]] auto config() const noexcept -> const redis_gateway_config& { return _config; }
    /// The Redis format level this node reports to `KYTHIRA.FORMAT`, `INFO`
    /// and the health metrics (redis-general-data-types Requirement 14.3).
    [[nodiscard]] auto format_level() const noexcept -> std::uint16_t {
        return reported_format_level();
    }

    /// Sends `argv` to the gateway listening at `endpoint` (`host:port`)
    /// over the forward link, authenticated as the internal identity, and
    /// returns its whole RESP reply; `nullopt` when forwarding is not set up
    /// or the peer could not be reached in time. The `call_fn` of a
    /// `redis_remote_data_access` (task 16).
    auto data_call(const std::string& endpoint, const std::vector<std::string>& argv)
        -> std::optional<std::string>;

protected:
    ~redis_front_end() = default;

    /// Per-connection protocol state that is independent of the socket.
    struct session {
        resp_parser _parser;
        resp_writer _writer{2};
        std::optional<redis_identity> _identity;
        /// Authenticated as `_internal_user`: never forward again.
        bool _internal = false;
        std::string _source;
        /// Remote IPv4 address or IPv6 /64 — the AUTH rate-limit key
        /// (redis_auth_limiter::rate_key). `_source` keeps the port for logs,
        /// but keying the limit on ip:port made it a no-op: every reconnect
        /// gets a fresh source port, so a guesser just opened a new
        /// connection per attempt.
        std::string _rate_key;
        /// When the credential this session authenticated with stops being
        /// good: set only by a credential verifier's acceptance, cleared by
        /// a password AUTH and by RESET. The connection's idle timer closes
        /// the connection at this time, and a command after it is refused.
        std::optional<std::chrono::system_clock::time_point> _expires;
        std::string _client_name;
        std::string _lib_name;
        std::string _lib_version;
        bool _closing = false;
        /// `KYTHIRA.ISOLATION`; unset means the configured default.
        std::optional<txn_isolation> _isolation;
        /// Inside `MULTI`: commands queued for `EXEC`.
        bool _in_multi = false;
        /// A command was refused while queuing, so `EXEC` aborts (Redis's
        /// EXECABORT).
        bool _multi_failed = false;
        std::vector<resp_command> _queued;
        /// `WATCH` (snapshot build): the keys, and the oracle timestamp the
        /// first `WATCH` took. `EXEC` validates them from that timestamp;
        /// `EXEC`, `DISCARD` and `UNWATCH` clear them.
        std::set<std::string> _watched;
        std::uint64_t _watch_ts{0};
        /// The roles of the node on the other end of an internal session:
        /// from its layer identity (mutual TLS), or implied by the
        /// internal secret. Unset on a client session.
        std::optional<layers::role_set> _peer_roles;
        /// A gateway without `front_end`: the connection's number, which
        /// its front-end affinity hashes, and the front end it is pinned
        /// to (empty until the first call).
        std::uint64_t _conn_id = 0;
        std::string _pinned;
    };

    /// The coordinator's view of the shards (`txn_participant_client`):
    /// sends go to the local replica when it leads, and otherwise over the
    /// forward link to the leader's gateway as `KYTHIRA.TXN`. Every send
    /// blocks on the calling worker thread and returns a ready future, so
    /// a multi-shard prepare runs shard by shard; the protocol does not
    /// depend on the prepares overlapping.
    class txn_client {
    public:
        using group_id_type = typename Host::group_id_type;
        using send_future = future_default<std::vector<std::byte>>;

        explicit txn_client(redis_front_end& front_end) : _front_end(front_end) {}

        [[nodiscard]] auto resolve(const std::string& key) -> std::optional<group_id_type>;
        [[nodiscard]] auto send(const std::vector<std::string>& keys,
                                const std::vector<std::byte>& envelope,
                                std::chrono::milliseconds timeout) -> send_future;
        [[nodiscard]] auto refresh(std::exception_ptr error) -> bool;
        [[nodiscard]] auto read(const std::string& key, std::chrono::milliseconds timeout)
            -> txn_read_result<std::string>;
        [[nodiscard]] auto now_ms() const -> std::uint64_t;
        /// Tier 2 (task 14): the oracle, and a read at a timestamp, through
        /// this gateway or the leader's over `KYTHIRA.TXN TS` / `READAT`.
        [[nodiscard]] auto allocate_timestamps(std::size_t n, std::chrono::milliseconds timeout)
            -> timestamp_range
        requires k_snapshot;
        [[nodiscard]] auto read_at(const std::string& key, std::uint64_t ts,
                                   std::chrono::milliseconds timeout)
            -> txn_read_result<std::string>
        requires k_snapshot;

    private:
        redis_front_end& _front_end;
    };
    friend class txn_client;
    using coordinator_type = transaction_coordinator<txn_client, std::string>;

    // ---- command dispatch ----------------------------------------------------
    /// Every command past the gateway's authentication checks: the
    /// transaction surface, then the per-command handlers. `upper` is the
    /// command name in upper case. Returns the encoded reply.
    auto execute_command(session& s, std::string_view upper, const resp_command& cmd)
        -> std::string;
    auto handle_get(session& s, const resp_command& cmd) -> std::string;
    auto handle_exists(session& s, const resp_command& cmd) -> std::string;
    auto handle_strlen(session& s, const resp_command& cmd) -> std::string;
    auto handle_getrange(session& s, const resp_command& cmd) -> std::string;

    // ---- tier 1 strings (redis-general-data-types task 3) ------------------

    /// Proposes an `exec` record for `key` (design Component 2) on its
    /// group's leader, forwarding `cmd` when the leader is elsewhere, and
    /// renders the reply `apply()` decided. `args` are the record's
    /// arguments in normal form (redis_string_exec.hpp).
    auto propose_exec(session& s, const resp_command& cmd, const std::string& key,
                      redis_command_id id, std::vector<std::string> args, bool may_grow)
        -> std::string;
    /// SET with options, SETNX, PSETEX, GETSET, the INCR family, GETDEL,
    /// GETEX, APPEND and SETRANGE: syntax checks and normal form.
    auto handle_string_write(session& s, std::string_view upper, const resp_command& cmd)
        -> std::string;
    /// TYPE, TOUCH and OBJECT ENCODING.
    auto handle_key_read(session& s, std::string_view upper, const resp_command& cmd)
        -> std::string;
    auto handle_ttl(session& s, const resp_command& cmd) -> std::string;
    auto handle_set(session& s, const resp_command& cmd, bool with_expiry) -> std::string;
    auto handle_del(session& s, const resp_command& cmd) -> std::string;
    auto handle_info(session& s) -> std::string;
    /// `HELLO`'s `mode` and `INFO`'s `redis_mode`: `cluster` only in the
    /// Cluster protocol compatibility mode (redis-general-data-types
    /// Requirement 1.6).
    [[nodiscard]] auto server_mode() const noexcept -> const char* {
        return _config._cluster_compat_mode ? "cluster" : "standalone";
    }
    /// `INFO`'s `kythira_membership`: where front ends come from.
    [[nodiscard]] auto membership_mode_name() const noexcept -> const char* {
        switch (_membership_mode.load()) {
            case membership_mode::dns:
                return "dns";
            case membership_mode::group:
                return "group";
            case membership_mode::config:
                break;
        }
        return "config";
    }
    auto handle_command(session& s, const resp_command& cmd) -> std::string;
    auto handle_dbsize(session& s) -> std::string;

    // ---- transactions (multi-raft-transactions task 9) -------------------------
    /// Whether a command is one the transaction surface owns. Off, they fall
    /// through to today's dispatch (unknown command, or single-key only).
    [[nodiscard]] auto is_txn_command(std::string_view upper, const resp_command& cmd) const
        -> bool;
    auto execute_txn_command(session& s, std::string_view upper, const resp_command& cmd)
        -> std::string;
    auto handle_mset(session& s, const resp_command& cmd) -> std::string;
    auto handle_mget(session& s, const resp_command& cmd) -> std::string;
    auto handle_multi_del(session& s, const resp_command& cmd) -> std::string;
    auto handle_exec(session& s) -> std::string;
    auto handle_isolation(session& s, const resp_command& cmd) -> std::string;
    auto handle_watch(session& s, const resp_command& cmd) -> std::string;
    auto handle_internal_txn(session& s, const resp_command& cmd) -> std::string;
    /// `KYTHIRA.DATA ROUTE|ROUTES|PROPOSE`: the data-layer API a front end
    /// without a replica of a key's group calls (redis_data_wire.hpp).
    auto handle_data(session& s, const resp_command& cmd) -> std::string;
    /// `KYTHIRA.DATA PROPOSE`'s answer bytes.
    auto data_propose(const resp_command& cmd) -> std::string;
    /// `KYTHIRA.DATA READ`'s answer bytes, from this node's own replica.
    auto data_read(redis_data_wire::read_mode mode, const std::string& key) -> std::string;
    /// Why this front end cannot serve with its layer roles and store, or
    /// `nullopt`; checked at `start()`.
    [[nodiscard]] auto layer_refusal() const -> std::optional<std::string>;
    /// Whether this node runs no gateway: client sessions are refused,
    /// internal ones served.
    [[nodiscard]] auto serves_no_clients() const noexcept -> bool {
        return !_config._layer_roles.has(layers::role::gateway);
    }
    /// Whether commands go to remote front ends (a gateway without
    /// `front_end`, task 17).
    [[nodiscard]] auto remote_front_ends() const noexcept -> bool {
        return _config._layer_roles.has(layers::role::gateway) &&
               !_config._layer_roles.has(layers::role::front_end);
    }
    /// Whether calls between this node and others need layer identities:
    /// it is not co-located, or it holds a layer identity of its own.
    [[nodiscard]] auto layer_tls_required() const noexcept -> bool {
        return !redis_roles_colocated(_config._layer_roles) && !_config._insecure_plaintext;
    }
    /// Whether the forward link can reach other nodes at all: something to
    /// authenticate with (the internal secret, or a layer identity) over
    /// TLS, or plaintext explicitly allowed.
    [[nodiscard]] auto can_call_peers() const -> bool;
    /// `KYTHIRA.CALL <state> <command> <arg>...` from a gateway: runs the
    /// command as the connection the state describes and answers with
    /// what the call wire says (redis_call_wire.hpp).
    auto handle_call(session& s, const resp_command& cmd) -> std::string;
    /// The roles an internal session's caller has, checked against what
    /// `upper` needs (Requirement 19.2); the refusal, or nullopt.
    auto peer_role_refusal(session& s, std::string_view upper) -> std::optional<std::string>;
    /// This node's layer identity: the URI SAN of its forwarding client
    /// certificate naming this cluster, if it has one.
    [[nodiscard]] auto own_identity() const -> std::optional<layers::identity>;
    /// The client TLS context for the forward link, rebuilt when its files
    /// change (Requirement 19.5); null when forwarding is plaintext.
    auto forward_tls_context() -> std::shared_ptr<boost::asio::ssl::context>;

    /// One request/reply on the forward link, telling apart a request that
    /// never left from one whose answer was lost (Requirement 17.2).
    struct exchange_result {
        enum class kind : std::uint8_t {
            not_sent,
            lost,
            answered
        };
        kind _kind = kind::not_sent;
        std::string _reply;
        std::string _error;
    };
    /// `budget` bounds the whole exchange; zero means the command timeout.
    auto exchange(const std::vector<std::string>& argv, const std::string& endpoint,
                  std::chrono::milliseconds budget = std::chrono::milliseconds{0})
        -> exchange_result;
    /// `routes` with the addresses of every node they name.
    auto data_routes_payload(std::vector<typename Host::descriptor_type> routes)
        -> redis_data_wire::routes_payload<group_id_type, node_id_type>;
    /// Queue one command inside `MULTI`, or refuse it (and doom the `EXEC`).
    auto queue_in_multi(session& s, std::string_view upper, const resp_command& cmd) -> std::string;
    [[nodiscard]] auto isolation_of(const session& s) const -> txn_isolation;
    [[nodiscard]] auto make_options(const session& s) const -> txn_options;
    /// Reply for a commit that did not commit, or empty when it did.
    auto outcome_error(session& s, const txn_outcome<std::string>& outcome) -> std::string;
    /// A `SET` command for `value`, with SETEX's deadline resolved now.
    [[nodiscard]] auto set_command(const std::string& key, std::string_view value,
                                   std::uint64_t expire_at_ms) const -> std::vector<std::byte>;
    /// Send one envelope to the shard owning `keys`; the encoded result.
    auto txn_send(const std::vector<std::string>& keys, const std::vector<std::byte>& envelope,
                  std::chrono::milliseconds timeout) -> std::vector<std::byte>;
    auto txn_read(const std::string& key, std::chrono::milliseconds timeout)
        -> txn_read_result<std::string>;
    /// The read on this replica, or nullopt when it does not lead the shard.
    auto txn_read_local(const std::string& key) -> std::optional<txn_read_result<std::string>>;
    /// `n` timestamps from the host's oracle, or from the oracle leader's
    /// gateway over `KYTHIRA.TXN TS` (tier 2).
    auto txn_allocate_timestamps(std::size_t n, std::chrono::milliseconds timeout)
        -> timestamp_range;
    /// The newest version of `key` at or below `ts`, and any intent, from
    /// the shard leader after a read-index round (tier 2).
    /// @throws snapshot_too_old_exception below the shard's safe point.
    auto txn_read_at(const std::string& key, std::uint64_t ts, std::chrono::milliseconds timeout)
        -> txn_read_result<std::string>;
    /// That read on this replica, or nullopt when it does not lead the
    /// shard (or lost it, or the key moved, during the read).
    auto txn_read_at_local(const std::string& key, std::uint64_t ts,
                           std::chrono::milliseconds timeout)
        -> std::optional<txn_read_result<std::string>>;
    /// Who to ask about `key`'s shard when this replica does not lead it.
    auto txn_leader_of(const std::string& key) -> std::optional<node_id_type>;
    /// A plain write met `holder`'s lock: finish that transaction if its
    /// time is up. True when the key may now be free.
    auto resolve_lock(const std::string& key, const txn_id& holder, const std::string& primary)
        -> bool;

    // ---- read/write plumbing ---------------------------------------------------
    /// Outcome of a local lookup: the handle, or a reason it could not be
    /// served here (in which case `_forward_to` may name a leader). The
    /// context, taken under the same lock, lets the bytes be read after it is
    /// released.
    struct read_result {
        entry_handle _entry;
        value_context _context{};
        std::string _error;  ///< encoded reply if the read failed
        std::optional<node_id_type> _forward_to;
    };
    auto read_local(session& s, const std::string& key) -> read_result;
    /// `result`, when given, receives the entry's apply result.
    auto submit(session& s, const std::string& key, const std::vector<std::byte>& command,
                std::string& error_reply, std::optional<node_id_type>& forward_to,
                std::vector<std::byte>* result = nullptr) -> bool;
    auto forward(session& s, const resp_command& cmd, const node_id_type& to)
        -> std::optional<std::string>;
    /// The forward link itself, with none of `forward()`'s one-hop and
    /// session checks: `KYTHIRA.TXN` is one hop by construction, as the
    /// receiving gateway never forwards it again.
    auto forward_argv(const std::vector<std::string>& argv, const node_id_type& to,
                      std::string_view what) -> std::optional<std::string>;
    auto forward_endpoint(const node_id_type& to) -> std::optional<std::string>;
    /// `forward_argv` to a resolved `host:port`.
    auto forward_to_endpoint(const std::vector<std::string>& argv, const std::string& endpoint,
                             std::string_view what) -> std::optional<std::string>;
    auto locate(const std::string& key, std::string& error_reply,
                std::optional<node_id_type>& forward_to) -> group_node_type*;
    [[nodiscard]] static auto data_error(redis_data_status status) -> std::string;
    auto authorize(session& s, std::string_view upper, const std::vector<std::string_view>& keys)
        -> std::optional<std::string>;
    auto audit(session& s, std::string_view command, std::string_view outcome) -> void;
    auto emit(std::string_view name, std::string_view command, std::int64_t count = 1) -> void;
    auto emit_duration(std::string_view name, std::string_view command, std::chrono::nanoseconds d)
        -> void;
    [[nodiscard]] static auto now_ms() -> std::uint64_t;
    [[nodiscard]] auto is_expired(const entry_type& e) const -> bool;
    auto touch_lru(group_id_type group, const std::string& key) -> void;
    auto forget_lru(group_id_type group, const std::string& key) -> void;
    auto handle_advise(session& s, const resp_command& cmd) -> std::string;

    // ---- format level and gate (redis-general-data-types task 2) ----------

    /// `KYTHIRA.FORMAT STATUS | LEVEL | UPGRADE <level>`.
    auto handle_format(session& s, const resp_command& cmd) -> std::string;
    /// `KYTHIRA.FORMAT UPGRADE <level>`: check every node, then gate every
    /// group (design Component 8).
    auto format_upgrade(session& s, std::uint16_t level) -> std::string;
    /// A peer's format level over the forwarding link, or `nullopt` when it
    /// cannot be asked or does not answer.
    auto peer_format_level(const node_id_type& node) -> std::optional<std::uint16_t>;
    /// The level this node reports: `_reported_format_level`, else
    /// `k_node_format_level`.
    [[nodiscard]] auto reported_format_level() const noexcept -> std::uint16_t {
        return _config._reported_format_level != 0 ? _config._reported_format_level
                                                   : k_node_format_level;
    }
    /// Sends `argv` to `node`'s gateway on the internal link and returns the
    /// raw reply, or `nullopt` when there is no link or no answer in time.
    auto call_peer(const node_id_type& node, const std::vector<std::string>& argv)
        -> std::optional<std::string>;
    /// The format level `key`'s group has passed a gate for, when this node
    /// holds a replica of it; `nullopt` otherwise (the group's own apply
    /// then refuses a typed record before its gate).
    auto group_format_level(const std::string& key) -> std::optional<std::uint16_t>;
    /// The gate refusal for a command that needs `level` on `key`, if the
    /// local replica of its group has not passed that gate.
    auto format_refusal(session& s, const std::string& key, std::uint16_t level)
        -> std::optional<std::string>;

    /// Send each shard leader the reads this node served for it and the
    /// cache hooks' advisory payload.
    auto send_advisories() -> void;
    /// The write refusal for the shard owning `key`, if any.
    auto space_refusal(const std::string& key) -> std::optional<std::string>;

    auto build_forward_ssl_context() -> boost::asio::ssl::context;

    struct forward_pool {
        std::mutex _mutex;
        std::vector<std::unique_ptr<redis_forward_link>> _idle;
    };
    auto forward_socket(const std::string& endpoint, std::chrono::steady_clock::time_point deadline)
        -> std::unique_ptr<redis_forward_link>;
    auto return_forward_socket(const std::string& endpoint,
                               std::unique_ptr<redis_forward_link> sock) -> void;

    /// The data layer (redis_data_access.hpp). Every command reaches data
    /// through it, never through the host directly (Requirement 16.5).
    redis_data_access<Host> _data;
    redis_acl& _acl;
    Logger& _logger;
    Metrics& _metrics;
    redis_gateway_config _config;
    endpoint_resolver _resolver;
    redis_gateway_stats _stats;
    std::mutex _metrics_mutex;
    /// Client side of forwarding over TLS; null when forwarding is plaintext.
    std::shared_ptr<boost::asio::ssl::context> _forward_ssl_ctx;
    std::atomic<bool> _running{false};
    std::chrono::steady_clock::time_point _started_at{};

    /// Leader-local advisory LRU per shard: never replicated, rebuilt lazily
    /// after a leadership change from whatever the shard holds.
    struct lru_state {
        std::list<std::string> _order;  // front = most recent
        std::unordered_map<std::string, std::list<std::string>::iterator> _index;
    };
    std::mutex _lru_mutex;
    std::map<group_id_type, lru_state> _lru;
    /// Keys this node served as a follower, per shard, for its leader.
    std::map<group_id_type, std::set<std::string>> _remote_touches;

    cache_hooks _cache_hooks;

    std::mutex _forward_mutex;
    std::unordered_map<std::string, std::shared_ptr<forward_pool>> _forward_pools;

    /// Certificate rotation (Requirement 19.5): what the TLS files looked
    /// like when a context was built, and when they were last looked at.
    struct tls_files {
        std::vector<std::pair<std::string, std::string>> _stamps;
        std::chrono::steady_clock::time_point _checked{};
    };
    [[nodiscard]] static auto stamp_files(const std::vector<std::string>& paths)
        -> std::vector<std::pair<std::string, std::string>>;
    mutable std::mutex _tls_mutex;
    tls_files _forward_tls_files;
    std::optional<layers::identity> _own_identity;

    /// Where the gateway finds front ends, and this node's drain state in
    /// the group (task 18), for `INFO`.
    enum class membership_mode : std::uint8_t {
        config,
        dns,
        group
    };
    std::atomic<membership_mode> _membership_mode{membership_mode::config};
    std::atomic<layers::drain_state> _member_drain{layers::drain_state::serving};
};

/// The gateway layer over an in-process front end (see `redis_front_end`).
template<typename Host, typename Logger, typename Metrics>
class redis_gateway : public redis_front_end<Host, Logger, Metrics> {
    using front_end = redis_front_end<Host, Logger, Metrics>;

public:
    using front_end::k_snapshot;
    using front_end::k_transactional;
    using typename front_end::endpoint_resolver;
    using typename front_end::group_id_type;
    using typename front_end::node_id_type;

    redis_gateway(Host& host, redis_acl& acl, Logger& logger, Metrics& metrics,
                  redis_gateway_config config, endpoint_resolver resolver);
    ~redis_gateway();

    redis_gateway(const redis_gateway&) = delete;
    auto operator=(const redis_gateway&) -> redis_gateway& = delete;
    redis_gateway(redis_gateway&&) = delete;
    auto operator=(redis_gateway&&) -> redis_gateway& = delete;

    /// Bind the listeners and start the I/O and worker threads. Throws on a
    /// bind failure or an ACL/anonymous misconfiguration.
    auto start() -> void;
    /// Close listeners, drain connections, join threads. Idempotent.
    auto stop() -> void;
    [[nodiscard]] auto is_running() const noexcept -> bool { return this->_running.load(); }

    /// Bound port of the plaintext listener (0 if none / not started).
    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return _port; }
    [[nodiscard]] auto tls_port() const noexcept -> std::uint16_t { return _tls_port; }

    /// Requirement 17.4: stop accepting connections, let the commands
    /// already received finish (up to `_drain_timeout`), then stop. A
    /// gateway can then be removed without failing a command that was not
    /// in flight. Idempotent, like stop().
    auto drain() -> void;

    /// Tests only: execute one command as if it arrived on an authenticated
    /// connection, without a socket. Returns the encoded reply.
    auto execute_for_test(const resp_command& cmd, const std::optional<redis_identity>& identity,
                          bool internal) -> std::string;

    class connection;
    friend class connection;

private:
    using front_end::_acl;
    using front_end::_config;
    using front_end::_data;
    using front_end::_forward_mutex;
    using front_end::_forward_pools;
    using front_end::_forward_ssl_ctx;
    using front_end::_logger;
    using front_end::_running;
    using front_end::_started_at;
    using front_end::_stats;
    using front_end::_tls_mutex;
    using front_end::audit;
    using front_end::authorize;
    using front_end::build_forward_ssl_context;
    using front_end::emit;
    using front_end::emit_duration;
    using front_end::server_mode;
    using front_end::txn_allocate_timestamps;
    using front_end::txn_send;
    using typename front_end::coordinator_type;
    using typename front_end::session;

    struct queued_command {
        resp_command _cmd;
        std::size_t _bytes = 0;
        /// A pre-built reply (the shed error) that replaces execution.
        std::string _prebuilt;
    };

    // ---- connection commands -------------------------------------------------
    /// The whole command: the pre-authentication surface (`AUTH`, `HELLO`,
    /// `QUIT`, `RESET`), the credential checks, `CLIENT`, then the front end.
    auto execute(session& s, const resp_command& cmd) -> std::string;
    auto handle_auth(session& s, const resp_command& cmd) -> std::string;
    /// Admission for one AUTH attempt (redis_auth_limiter). Returns the
    /// refusal to send, or nullopt when the attempt may proceed, in which
    /// case `_auth_limiter.finish()` must follow.
    auto admit_auth(session& s) -> std::optional<std::string>;
    /// `handle_auth` for a user the credential verifier vouches for.
    auto auth_with_verifier(session& s, const std::string& user, const std::string& credential)
        -> std::string;
    auto handle_hello(session& s, const resp_command& cmd) -> std::string;
    auto handle_client(session& s, const resp_command& cmd) -> std::string;
    /// The internal user's AUTH: only between co-located nodes, unless the
    /// node runs insecure plaintext (Requirement 19.3).
    auto internal_auth_refusal(const session& s) -> std::optional<std::string>;
    /// A verified peer certificate's layer identity: the session becomes
    /// internal with that identity's roles.
    auto accept_layer_identity(session& s, X509* cert) -> bool;

    // ---- remote front ends (task 17) ----------------------------------------
    /// Send the command to the connection's front end as `KYTHIRA.CALL`,
    /// re-pinning while the request has not left, and answering the
    /// ambiguity error when it may have run (Requirement 17.2).
    auto call_front_end(session& s, std::string_view upper, const resp_command& cmd) -> std::string;
    /// The front end for a connection: rendezvous hashing of its number
    /// over the front ends not recently failed.
    auto pick_front_end(const session& s) -> std::optional<std::string>;
    auto mark_front_end_down(const std::string& endpoint) -> void;
    std::mutex _front_end_mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> _front_end_down;
    std::atomic<std::uint64_t> _next_conn_id{1};

    // ---- layer membership (task 18) -----------------------------------------
    /// Chooses where front ends come from (group, DNS, configuration) and
    /// starts the thread that keeps the list, announces this node, reports
    /// its load and follows its drain state.
    auto start_membership() -> void;
    auto stop_membership() -> void;
    auto membership_loop() -> void;
    /// One round of `membership_loop`.
    auto membership_tick() -> void;
    /// The group's member list: this node's replica, or a voter's answer to
    /// `KYTHIRA.MEMBERS LIST`.
    auto fetch_members() -> std::optional<std::vector<layers::layer_member>>;
    /// A membership command, through this node's replica or a voter.
    auto propose_membership(std::vector<std::byte> command)
        -> std::optional<std::vector<std::byte>>;
    [[nodiscard]] auto self_member() const -> layers::layer_member;
    /// Acts on this node's drain state as the group has it.
    auto follow_drain(layers::drain_state state) -> void;
    /// Whether this node has no work in flight: no client command running
    /// and no `KYTHIRA.CALL`.
    [[nodiscard]] auto nothing_in_flight() -> bool;
    /// `KYTHIRA.MEMBERS PROPOSE|LIST` from another member (internal).
    auto handle_members(session& s, const resp_command& cmd) -> std::string;
    /// `KYTHIRA.LAYERS [LIST | DRAIN <id> | SERVE <id>]` from an admin.
    auto handle_layers(session& s, const resp_command& cmd) -> std::string;
    /// The addresses of the front ends calls may go to now.
    auto front_end_candidates() -> std::vector<std::string>;

    std::shared_ptr<layers::member_directory> _directory;
    std::unique_ptr<layers::replicated_layer_membership> _group;
    std::shared_ptr<layers::static_member_directory> _configured_front_ends;
    std::mutex _members_mutex;
    std::vector<layers::layer_member> _members_cache;
    std::thread _membership_thread;
    std::mutex _membership_wake_mutex;
    std::condition_variable _membership_wake;
    bool _membership_stopping = false;
    // Touched by the membership thread only.
    redis_membership::load_meter _load_meter;
    std::chrono::steady_clock::time_point _next_discovery{};
    std::optional<std::chrono::steady_clock::time_point> _idle_since;
    std::chrono::steady_clock::time_point _drain_started{};
    bool _listeners_closed = false;

    /// The listener's TLS context, rebuilt when its files change.
    auto server_tls_context() -> std::shared_ptr<boost::asio::ssl::context>;
    typename front_end::tls_files _server_tls_files;

    // ---- networking ------------------------------------------------------------
    auto accept_loop(std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor, bool tls) -> void;
    auto build_ssl_context() -> boost::asio::ssl::context;
    auto register_connection(const std::shared_ptr<connection>& c) -> void;
    auto unregister_connection(connection* c) -> void;

    boost::asio::io_context _io;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> _work;
    // One acceptor per address the listen host resolves to (net_bind.hpp),
    // all on the same port.
    std::vector<std::shared_ptr<boost::asio::ip::tcp::acceptor>> _acceptors;
    std::vector<std::shared_ptr<boost::asio::ip::tcp::acceptor>> _tls_acceptors;
    std::shared_ptr<boost::asio::ssl::context> _ssl_ctx;
    std::vector<std::thread> _io_threads;
    std::optional<boost::asio::thread_pool> _workers;
    std::uint16_t _port = 0;
    std::uint16_t _tls_port = 0;

    std::mutex _connections_mutex;
    std::unordered_map<connection*, std::weak_ptr<connection>> _connections;
    std::atomic<std::size_t> _inflight_bytes{0};

    redis_auth_limiter _auth_limiter;
};

}  // namespace kythira
