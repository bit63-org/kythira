// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <kythira/redis/redis_server_identity.hpp>
#include <raft/layer_identity_uri.hpp>
#include <raft/net_bind.hpp>
#include <raft/route_cache.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string_view>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace kythira::redis_node {

namespace {

/// The lookup the current from_env(env) reads through, or null for the
/// process environment. One per thread, so two nodes in one test process
/// can read their settings at once.
thread_local const service_node::env_lookup* t_env =
    nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

/// A variable's value; set but empty counts as set, as getenv has it.
auto env_get(const char* name) -> std::optional<std::string> {
    if (t_env != nullptr) {
        return (*t_env)(name);
    }
    const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read at start
    return v != nullptr ? std::optional<std::string>(v) : std::nullopt;
}

auto get_opt(const char* name, const char* def) -> std::string {
    return env_get(name).value_or(def);
}

auto get_required(const char* name) -> std::string {
    auto v = env_get(name);
    if (!v || v->empty()) {
        throw std::invalid_argument(std::string("redis_gateway_node: missing required env var ") +
                                    name);
    }
    return *v;
}

auto to_bool(const char* name, const std::string& v) -> bool {
    if (v == "1" || v == "true" || v == "yes" || v == "on") {
        return true;
    }
    if (v == "0" || v == "false" || v == "no" || v == "off") {
        return false;
    }
    throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                " must be true or false, got '" + v + "'");
}

auto to_u64(const char* name, const std::string& v) -> std::uint64_t {
    try {
        std::size_t used = 0;
        auto n = std::stoull(v, &used);
        if (used != v.size()) {
            throw std::invalid_argument(v);
        }
        return n;
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                    " must be an integer, got '" + v + "'");
    }
}

auto to_ms(const char* name, const std::string& v) -> std::chrono::milliseconds {
    return std::chrono::milliseconds{static_cast<std::int64_t>(to_u64(name, v))};
}

auto to_double(const char* name, const std::string& v) -> double {
    try {
        std::size_t used = 0;
        const auto d = std::stod(v, &used);
        if (used != v.size() || !(d >= 0.0)) {
            throw std::invalid_argument(v);
        }
        return d;
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                    " must be a number of at least 0, got '" + v + "'");
    }
}

/// A peer's node id. Canonical composite text holds no `=` or `,`, so the
/// `id=value` split below is unambiguous in either id kind.
auto to_peer_id(const char* name, const std::string& v) -> kythira::host_node_id {
    auto id = kythira::parse_host_peer_node_id(v);
    if (!id) {
        throw std::invalid_argument(std::string("redis_gateway_node: ") + name + ": " + id.error());
    }
    return std::move(id).value();
}

/// `id=value,id=value,...`
auto parse_id_map(const char* name, const std::string& text)
    -> std::map<kythira::host_node_id, std::string> {
    std::map<kythira::host_node_id, std::string> out;
    std::string tok;
    for (char c : text + ',') {
        if (c != ',') {
            tok += c;
            continue;
        }
        if (tok.empty()) {
            continue;
        }
        auto eq = tok.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == tok.size()) {
            throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                        " expects id=value[,id=value...], got token '" + tok + "'");
        }
        out[to_peer_id(name, tok.substr(0, eq))] = tok.substr(eq + 1);
        tok.clear();
    }
    if (out.empty()) {
        throw std::invalid_argument(std::string("redis_gateway_node: ") + name + " is empty");
    }
    return out;
}

/// Host portion of `http://host:port/...` or `host:port`.
auto host_of(const std::string& url) -> std::string {
    auto s = url;
    if (auto p = s.find("://"); p != std::string::npos) {
        s = s.substr(p + 3);
    }
    if (auto p = s.find('/'); p != std::string::npos) {
        s = s.substr(0, p);
    }
    if (!s.empty() && s.front() == '[') {
        auto close = s.find(']');
        return close == std::string::npos ? s : s.substr(0, close + 1);
    }
    if (auto p = s.rfind(':'); p != std::string::npos) {
        s = s.substr(0, p);
    }
    return s;
}

auto port_of(const std::string& listen) -> std::string {
    auto p = listen.rfind(':');
    return p == std::string::npos ? "6379" : listen.substr(p + 1);
}

auto is_set(const char* name) -> bool {
    const auto v = env_get(name);
    return v && !v->empty();
}

/// `KYTHIRA_CACHE_PERSISTENCE=engine` (.kiro/specs/persistent-state-machine/
/// task 7): values in the node's RocksDB database. The data directory and
/// the disk budget mean what they mean in file mode; the chunk store's and
/// the HTTP front end's variables have nothing to apply to, so they are
/// refused rather than ignored.
void read_engine_options(node_options& o) {
#if !defined(KYTHIRA_REDIS_GATEWAY_ENGINE)
    (void)o;
    throw std::invalid_argument(
        "redis_gateway_node: KYTHIRA_CACHE_PERSISTENCE=engine needs a build with "
        "CONFIG_REDIS_GATEWAY_ENGINE=y");
#else
    auto& c = o._cache;
    c._persistence = cache_persistence::engine;
    if (o._serializer != wire_serializer::cbor) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_PERSISTENCE=engine needs "
            "KYTHIRA_WIRE_SERIALIZER=cbor");
    }
    for (const char* name :
         {"KYTHIRA_CACHE_HTTP_LISTEN", "KYTHIRA_CACHE_HTTPS_LISTEN", "KYTHIRA_CACHE_PEER_HTTP",
          "KYTHIRA_CACHE_CHUNK_BYTES", "KYTHIRA_CACHE_MAX_VALUE_BYTES",
          "KYTHIRA_CACHE_PACK_THRESHOLD_BYTES", "KYTHIRA_CACHE_ORPHAN_GRACE_ENTRIES",
          "KYTHIRA_CACHE_FETCH_BYTES_PER_SEC"}) {
        if (is_set(name)) {
            throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                        " needs KYTHIRA_CACHE_PERSISTENCE=file");
        }
    }
    c._data_dir = get_required("KYTHIRA_CACHE_DATA_DIR");
    c._max_disk_bytes =
        to_u64("KYTHIRA_CACHE_MAX_DISK_BYTES", get_required("KYTHIRA_CACHE_MAX_DISK_BYTES"));
    if (c._max_disk_bytes == 0) {
        throw std::invalid_argument("redis_gateway_node: KYTHIRA_CACHE_MAX_DISK_BYTES must be > 0");
    }
    c._min_free_bytes = to_u64("KYTHIRA_CACHE_MIN_FREE_BYTES",
                               get_opt("KYTHIRA_CACHE_MIN_FREE_BYTES", "1073741824"));
    c._min_free_inodes =
        to_u64("KYTHIRA_CACHE_MIN_FREE_INODES", get_opt("KYTHIRA_CACHE_MIN_FREE_INODES", "10000"));
    c._snapshot_threshold_bytes =
        to_u64("KYTHIRA_CACHE_SNAPSHOT_THRESHOLD_BYTES",
               get_opt("KYTHIRA_CACHE_SNAPSHOT_THRESHOLD_BYTES", "268435456"));
    c._snapshot_bytes_per_sec = to_u64("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC",
                                       get_opt("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC", "0"));
    // As in file mode, the disk budget bounds the values, so the memory
    // mode's per-shard RAM bound applies only when set explicitly.
    if (!is_set("KYTHIRA_REDIS_MAX_SHARD_BYTES")) {
        o._gateway._max_shard_bytes = std::numeric_limits<std::size_t>::max();
    }
#endif
}

/// `KYTHIRA_CACHE_*` (.kiro/specs/disk-backed-build-cache/ design
/// "Configuration"). Runs after the gateway's own variables, whose TLS and
/// forwarding choices it follows.
void read_cache_options(node_options& o) {
    auto& c = o._cache;
    const auto mode = get_opt("KYTHIRA_CACHE_PERSISTENCE", "file");
    // Snapshot pacing is the engine's catch-up path (file-install-snapshot
    // task 6); file mode catches a follower up by fetching chunks, which
    // KYTHIRA_CACHE_FETCH_BYTES_PER_SEC already limits.
    if (mode != "engine" && is_set("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC")) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC needs "
            "KYTHIRA_CACHE_PERSISTENCE=engine");
    }
    if (mode == "memory") {
        c._persistence = cache_persistence::memory;
        // Requirement 5.4's old deployment, exactly. Anything that needs a
        // data directory is a sign the operator meant `file`.
        for (const char* name :
             {"KYTHIRA_CACHE_DATA_DIR", "KYTHIRA_CACHE_MAX_DISK_BYTES", "KYTHIRA_CACHE_HTTP_LISTEN",
              "KYTHIRA_CACHE_HTTPS_LISTEN", "KYTHIRA_CACHE_PEER_HTTP"}) {
            if (is_set(name)) {
                throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                            " needs KYTHIRA_CACHE_PERSISTENCE=file");
            }
        }
        return;
    }
    if (mode == "engine") {
        read_engine_options(o);
        return;
    }
    if (mode != "file") {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_PERSISTENCE must be file, engine or memory, got '" +
            mode + "'");
    }
    c._persistence = cache_persistence::file;
    if (o._serializer != wire_serializer::cbor) {
        // One multi_raft stack per translation unit; the disk-backed one is
        // built for the default wire only.
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_PERSISTENCE=file needs "
            "KYTHIRA_WIRE_SERIALIZER=cbor");
    }
    c._data_dir = get_required("KYTHIRA_CACHE_DATA_DIR");
    c._max_disk_bytes =
        to_u64("KYTHIRA_CACHE_MAX_DISK_BYTES", get_required("KYTHIRA_CACHE_MAX_DISK_BYTES"));
    if (c._max_disk_bytes == 0) {
        throw std::invalid_argument("redis_gateway_node: KYTHIRA_CACHE_MAX_DISK_BYTES must be > 0");
    }
    constexpr std::uint64_t max_chunk = std::uint64_t{16} * 1024 * 1024;
    c._chunk_bytes =
        to_u64("KYTHIRA_CACHE_CHUNK_BYTES", get_opt("KYTHIRA_CACHE_CHUNK_BYTES", "4194304"));
    if (c._chunk_bytes == 0 || c._chunk_bytes > max_chunk) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_CHUNK_BYTES must be between 1 and 16777216");
    }
    c._max_value_bytes = to_u64("KYTHIRA_CACHE_MAX_VALUE_BYTES",
                                get_opt("KYTHIRA_CACHE_MAX_VALUE_BYTES", "2147483648"));
    c._min_free_bytes = to_u64("KYTHIRA_CACHE_MIN_FREE_BYTES",
                               get_opt("KYTHIRA_CACHE_MIN_FREE_BYTES", "1073741824"));
    c._min_free_inodes =
        to_u64("KYTHIRA_CACHE_MIN_FREE_INODES", get_opt("KYTHIRA_CACHE_MIN_FREE_INODES", "10000"));
    c._pack_threshold_bytes = to_u64("KYTHIRA_CACHE_PACK_THRESHOLD_BYTES",
                                     get_opt("KYTHIRA_CACHE_PACK_THRESHOLD_BYTES", "65536"));
    if (c._pack_threshold_bytes > max_chunk) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_PACK_THRESHOLD_BYTES must be at most 16777216");
    }
    c._orphan_grace_entries = to_u64("KYTHIRA_CACHE_ORPHAN_GRACE_ENTRIES",
                                     get_opt("KYTHIRA_CACHE_ORPHAN_GRACE_ENTRIES", "100000"));
    c._fetch_bytes_per_sec = to_u64("KYTHIRA_CACHE_FETCH_BYTES_PER_SEC",
                                    get_opt("KYTHIRA_CACHE_FETCH_BYTES_PER_SEC", "50000000"));
    c._snapshot_threshold_bytes =
        to_u64("KYTHIRA_CACHE_SNAPSHOT_THRESHOLD_BYTES",
               get_opt("KYTHIRA_CACHE_SNAPSHOT_THRESHOLD_BYTES", "268435456"));
    c._auth_cache_ttl = std::chrono::seconds{static_cast<std::int64_t>(to_u64(
        "KYTHIRA_CACHE_AUTH_CACHE_SECONDS", get_opt("KYTHIRA_CACHE_AUTH_CACHE_SECONDS", "300")))};

    // A RESP SET is one log entry and lands as one chunk.
    if (o._gateway._max_value_bytes > max_chunk) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_MAX_VALUE_BYTES must be at most 16777216 with "
            "KYTHIRA_CACHE_PERSISTENCE=file (a SET is stored as one chunk); larger values go "
            "over HTTP");
    }

    // Values live on disk here, and the disk budget is what bounds them
    // (Requirement 6.1). KYTHIRA_REDIS_MAX_SHARD_BYTES is the memory mode's
    // RAM bound; left at its 1 GiB default it evicted a shard's keys once
    // its values passed 1 GiB, whatever KYTHIRA_CACHE_MAX_DISK_BYTES said.
    // Two 500 MB vcpkg archives were enough. So in file mode it applies
    // only when set explicitly.
    if (!is_set("KYTHIRA_REDIS_MAX_SHARD_BYTES")) {
        o._gateway._max_shard_bytes = std::numeric_limits<std::size_t>::max();
    }

    c._http_listen = get_opt("KYTHIRA_CACHE_HTTP_LISTEN", "");
    c._https_listen = get_opt("KYTHIRA_CACHE_HTTPS_LISTEN", "");
    c._allow_plaintext_http = to_bool("KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP",
                                      get_opt("KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP", "false"));
    if (!c._http_listen.empty() && !c._allow_plaintext_http) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_HTTP_LISTEN serves credentials and values "
            "unencrypted; set KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP=true to allow it, or use "
            "KYTHIRA_CACHE_HTTPS_LISTEN");
    }
    c._tls_cert_path = get_opt("KYTHIRA_CACHE_HTTPS_CERT", o._gateway._tls_cert_path.c_str());
    c._tls_key_path = get_opt("KYTHIRA_CACHE_HTTPS_KEY", o._gateway._tls_key_path.c_str());
    if (!c._https_listen.empty() && (c._tls_cert_path.empty() || c._tls_key_path.empty())) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_CACHE_HTTPS_LISTEN needs KYTHIRA_CACHE_HTTPS_CERT and "
            "KYTHIRA_CACHE_HTTPS_KEY (or KYTHIRA_REDIS_TLS_CERT and KYTHIRA_REDIS_TLS_KEY)");
    }
    if (auto ph = get_opt("KYTHIRA_CACHE_PEER_HTTP", ""); !ph.empty()) {
        c._peer_http = parse_id_map("KYTHIRA_CACHE_PEER_HTTP", ph);
    } else {
        // Each peer's front end of the kind this node forwards over.
        const auto& listener = o._gateway._forward_tls ? c._https_listen : c._http_listen;
        if (!listener.empty()) {
            for (const auto& [id, url] : o._peers) {
                c._peer_http[id] = host_of(url) + ":" + port_of(listener);
            }
        }
    }
}

}  // namespace

auto is_loopback_address(const std::string& address) -> bool {
    // Same resolver the Raft listener binds with, so "localhost" counts and
    // the check can't disagree with what is actually bound.
    return kythira::net_bind::is_loopback_bind_address(address);
}

auto from_env() -> node_options {
    node_options o;
    // The layers this node runs (redis-general-data-types Requirement 16).
    // Read first: a malformed role set stops the node before anything else
    // is checked or bound.
    if (auto roles = env_get("KYTHIRA_REDIS_ROLES")) {
        try {
            o._gateway._layer_roles = parse_redis_roles(*roles);
        } catch (const std::invalid_argument& e) {
            throw std::invalid_argument(std::string("redis_gateway_node: KYTHIRA_REDIS_ROLES: ") +
                                        e.what());
        }
    }
    // Numeric or canonical composite text by `KYTHIRA_NODE_ID_KIND`; a text
    // build also takes `metadata:<provider>` and asks the instance metadata
    // service.
    if (auto id = kythira::parse_host_node_id(get_required("KYTHIRA_NODE_ID")); id) {
        o._node_id = std::move(id).value();
    } else {
        throw std::invalid_argument("redis_gateway_node: KYTHIRA_NODE_ID: " + id.error());
    }
    o._bind_address = get_opt("KYTHIRA_RAFT_BIND", "0.0.0.0");
    o._raft_port = static_cast<std::uint16_t>(
        to_u64("KYTHIRA_RAFT_PORT", get_opt("KYTHIRA_RAFT_PORT", "7000")));
    // Raft RPC has no TLS here, so anyone who can reach the port can drive
    // every group. Off loopback that has to be asked for explicitly.
    o._allow_plaintext_raft =
        to_bool("KYTHIRA_ALLOW_PLAINTEXT_RAFT", get_opt("KYTHIRA_ALLOW_PLAINTEXT_RAFT", "false"));
    if (!o._allow_plaintext_raft && !is_loopback_address(o._bind_address)) {
        throw std::invalid_argument(
            "redis_gateway_node: refusing to serve plaintext, unauthenticated Raft RPC on "
            "KYTHIRA_RAFT_BIND=" +
            o._bind_address +
            " (set KYTHIRA_RAFT_BIND to a loopback address, or "
            "KYTHIRA_ALLOW_PLAINTEXT_RAFT=true on a network you trust)");
    }
    o._peers = parse_id_map("KYTHIRA_PEERS", get_required("KYTHIRA_PEERS"));
    if (!o._peers.contains(o._node_id) && env_get("KYTHIRA_REDIS_ROLES") &&
        !o._gateway._layer_roles.has(layers::role::data)) {
        // A node without data holds no replica of the data groups, so the
        // voters never dial it: it may be one a capacity loop just created,
        // which no fixed list could have named. It still needs its own
        // entry, at the address it listens on.
        std::string host = o._bind_address;
        if (host.empty() || host == "0.0.0.0" || host == "::") {
            char name[256] = {};
            host = ::gethostname(name, sizeof(name) - 1) == 0 ? name : "localhost";
        }
        o._peers[o._node_id] = "http://" + host + ":" + std::to_string(o._raft_port);
    }
    if (!o._peers.contains(o._node_id)) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_PEERS must include this node's own id " +
            kythira::host_node_id_text(o._node_id));
    }
    o._tick_interval = to_ms("KYTHIRA_TICK_INTERVAL_MS", get_opt("KYTHIRA_TICK_INTERVAL_MS", "2"));
    o._election_timeout_min =
        to_ms("KYTHIRA_ELECTION_TIMEOUT_MIN_MS", get_opt("KYTHIRA_ELECTION_TIMEOUT_MIN_MS", "150"));
    o._election_timeout_max =
        to_ms("KYTHIRA_ELECTION_TIMEOUT_MAX_MS", get_opt("KYTHIRA_ELECTION_TIMEOUT_MAX_MS", "300"));
    o._heartbeat_interval =
        to_ms("KYTHIRA_HEARTBEAT_INTERVAL_MS", get_opt("KYTHIRA_HEARTBEAT_INTERVAL_MS", "50"));
    o._rpc_timeout = to_ms("KYTHIRA_RPC_TIMEOUT_MS", get_opt("KYTHIRA_RPC_TIMEOUT_MS", "1000"));
    o._policy_interval =
        to_ms("KYTHIRA_POLICY_INTERVAL_MS", get_opt("KYTHIRA_POLICY_INTERVAL_MS", "10000"));
    o._executor_stripes =
        to_u64("KYTHIRA_EXECUTOR_STRIPES", get_opt("KYTHIRA_EXECUTOR_STRIPES", "4"));
    {
        auto s = get_opt("KYTHIRA_WIRE_SERIALIZER", "cbor");
        if (s == "cbor") {
            o._serializer = wire_serializer::cbor;
        } else if (s == "json") {
            o._serializer = wire_serializer::json;
        } else {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_WIRE_SERIALIZER must be cbor or json, got '" + s +
                "'");
        }
    }
    {
        auto s = get_opt("KYTHIRA_LOG_LEVEL", "info");
        static const std::map<std::string, log_level> levels{
            {"trace", log_level::trace}, {"debug", log_level::debug},
            {"info", log_level::info},   {"warning", log_level::warning},
            {"error", log_level::error}, {"critical", log_level::critical},
        };
        auto it = levels.find(s);
        if (it == levels.end()) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_LOG_LEVEL must be "
                "trace|debug|info|warning|error|critical, got '" +
                s + "'");
        }
        o._log_level = it->second;
    }
    {
        auto cuts = get_opt("KYTHIRA_SHARD_CUTS", "");
        std::string tok;
        for (char c : cuts + ',') {
            if (c == ',') {
                if (!tok.empty()) {
                    o._shard_cuts.push_back(tok);
                }
                tok.clear();
            } else {
                tok += c;
            }
        }
    }

    auto& g = o._gateway;
    g._listen = get_opt("KYTHIRA_REDIS_LISTEN", "0.0.0.0:6379");
    g._tls_listen = get_opt("KYTHIRA_REDIS_TLS_LISTEN", "");
    g._tls_cert_path = get_opt("KYTHIRA_REDIS_TLS_CERT", "");
    g._tls_key_path = get_opt("KYTHIRA_REDIS_TLS_KEY", "");
    g._tls_ca_path = get_opt("KYTHIRA_REDIS_TLS_CA", "");
    g._require_client_cert = to_bool("KYTHIRA_REDIS_REQUIRE_CLIENT_CERT",
                                     get_opt("KYTHIRA_REDIS_REQUIRE_CLIENT_CERT", "false"));
    if (!g._tls_listen.empty() && (g._tls_cert_path.empty() || g._tls_key_path.empty())) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_TLS_LISTEN needs KYTHIRA_REDIS_TLS_CERT and "
            "KYTHIRA_REDIS_TLS_KEY");
    }
    if (g._require_client_cert && g._tls_ca_path.empty()) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_REQUIRE_CLIENT_CERT needs KYTHIRA_REDIS_TLS_CA to "
            "verify against");
    }
    g._allow_anonymous =
        to_bool("KYTHIRA_REDIS_ALLOW_ANONYMOUS", get_opt("KYTHIRA_REDIS_ALLOW_ANONYMOUS", "false"));
    // Requirement 10.1: the ACL file is required. The one way out is the
    // explicit anonymous opt-out, which start() warns about every time.
    if (is_set("KYTHIRA_REDIS_ACL_FILE")) {
        o._acl_file = get_opt("KYTHIRA_REDIS_ACL_FILE", "");
    } else if (!g._allow_anonymous) {
        throw std::invalid_argument(
            "redis_gateway_node: missing required env var KYTHIRA_REDIS_ACL_FILE "
            "(set KYTHIRA_REDIS_ALLOW_ANONYMOUS=true to run an open cache on purpose)");
    }
    {
        auto rc = get_opt("KYTHIRA_REDIS_READ_CONSISTENCY", "leader");
        auto parsed = parse_redis_read_consistency(rc);
        if (!parsed) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_READ_CONSISTENCY must be leader, any_replica or "
                "linearizable, got '" +
                rc + "'");
        }
        g._read_consistency = *parsed;
    }
    // Cross-shard transactions (multi-raft-transactions task 9). The state
    // machine's type, and so its snapshot format, is fixed by the build;
    // asking a build without the adapter for them fails here, before a port
    // is bound, rather than at the gateway's start().
    g._transactions =
        to_bool("KYTHIRA_REDIS_TRANSACTIONS", get_opt("KYTHIRA_REDIS_TRANSACTIONS", "off"));
#if !defined(KYTHIRA_REDIS_GATEWAY_TRANSACTIONS)
    if (g._transactions) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_TRANSACTIONS=on needs a build with "
            "CONFIG_REDIS_GATEWAY_TRANSACTIONS=y");
    }
#endif
    {
        auto level = get_opt("KYTHIRA_REDIS_TXN_ISOLATION", "read_committed");
        auto parsed = parse_txn_isolation(level);
        if (!parsed) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_TXN_ISOLATION must be read_committed, "
                "read_committed_wait, snapshot or serializable, got '" +
                level + "'");
        }
        g._txn_isolation = *parsed;
    }
    g._txn_lock_ttl =
        to_ms("KYTHIRA_REDIS_TXN_LOCK_TTL_MS", get_opt("KYTHIRA_REDIS_TXN_LOCK_TTL_MS", "3000"));
    g._txn_max_retries =
        to_u64("KYTHIRA_REDIS_TXN_MAX_RETRIES", get_opt("KYTHIRA_REDIS_TXN_MAX_RETRIES", "2"));
    g._max_value_bytes = to_u64("KYTHIRA_REDIS_MAX_VALUE_BYTES",
                                get_opt("KYTHIRA_REDIS_MAX_VALUE_BYTES", "8388608"));
    g._max_collection_bytes = to_u64("KYTHIRA_REDIS_MAX_COLLECTION_BYTES",
                                     get_opt("KYTHIRA_REDIS_MAX_COLLECTION_BYTES", "67108864"));
    g._max_collection_elements =
        to_u64("KYTHIRA_REDIS_MAX_COLLECTION_ELEMENTS",
               get_opt("KYTHIRA_REDIS_MAX_COLLECTION_ELEMENTS", "4194304"));
    g._cursor_idle =
        to_ms("KYTHIRA_REDIS_CURSOR_IDLE_MS", get_opt("KYTHIRA_REDIS_CURSOR_IDLE_MS", "600000"));
    g._max_cursors =
        to_u64("KYTHIRA_REDIS_MAX_CURSORS", get_opt("KYTHIRA_REDIS_MAX_CURSORS", "100000"));
    g._keys_limit =
        to_u64("KYTHIRA_REDIS_KEYS_LIMIT", get_opt("KYTHIRA_REDIS_KEYS_LIMIT", "10000"));
    g._max_clients =
        to_u64("KYTHIRA_REDIS_MAX_CLIENTS", get_opt("KYTHIRA_REDIS_MAX_CLIENTS", "1024"));
    g._idle_timeout =
        to_ms("KYTHIRA_REDIS_IDLE_TIMEOUT_MS", get_opt("KYTHIRA_REDIS_IDLE_TIMEOUT_MS", "300000"));
    g._command_timeout = to_ms("KYTHIRA_REDIS_COMMAND_TIMEOUT_MS",
                               get_opt("KYTHIRA_REDIS_COMMAND_TIMEOUT_MS", "5000"));
    g._max_shard_bytes = to_u64("KYTHIRA_REDIS_MAX_SHARD_BYTES",
                                get_opt("KYTHIRA_REDIS_MAX_SHARD_BYTES", "1073741824"));
    g._sweep_batch =
        to_u64("KYTHIRA_REDIS_SWEEP_BATCH", get_opt("KYTHIRA_REDIS_SWEEP_BATCH", "1024"));
    g._immutable_values = to_bool("KYTHIRA_REDIS_IMMUTABLE_VALUES",
                                  get_opt("KYTHIRA_REDIS_IMMUTABLE_VALUES", "true"));
    g._forwarding =
        to_bool("KYTHIRA_REDIS_FORWARDING", get_opt("KYTHIRA_REDIS_FORWARDING", "true"));
    g._internal_user = get_opt("KYTHIRA_REDIS_INTERNAL_USER", "kythira-internal");
    g._internal_secret = get_opt("KYTHIRA_REDIS_INTERNAL_SECRET", "");
    // Forwarding carries the internal secret, so it follows the listener: a
    // node with a TLS listener forwards to its peers' TLS listeners unless
    // told otherwise. Plaintext forwarding is an explicit opt-in.
    g._forward_tls =
        to_bool("KYTHIRA_REDIS_FORWARD_TLS",
                get_opt("KYTHIRA_REDIS_FORWARD_TLS", g._tls_listen.empty() ? "false" : "true"));
    g._forward_tls_ca_path = get_opt("KYTHIRA_REDIS_FORWARD_TLS_CA", "");
    g._forward_tls_cert_path = get_opt("KYTHIRA_REDIS_FORWARD_TLS_CERT", "");
    g._forward_tls_key_path = get_opt("KYTHIRA_REDIS_FORWARD_TLS_KEY", "");
    g._allow_plaintext_forwarding =
        to_bool("KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING",
                get_opt("KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING", "false"));
    // Layer identities (redis-general-data-types Requirement 19): the
    // cluster their URIs name, and the insecure escape hatch for nodes that
    // are not co-located.
    const auto cluster_default = get_opt("KYTHIRA_CLUSTER", "default");
    g._layer_cluster = get_opt("KYTHIRA_REDIS_CLUSTER", cluster_default.c_str());
    if (!layers::valid_identity_part(g._layer_cluster)) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_CLUSTER must be 1-128 letters, digits, '-', '.', "
            "'_' or '~' (got '" +
            g._layer_cluster + "')");
    }
    g._insecure_plaintext = get_opt("KYTHIRA_NODE_INSECURE_PLAINTEXT", "") == "1";
    if (g._insecure_plaintext) {
        g._allow_plaintext_forwarding = true;
    }
    g._drain_timeout = std::chrono::milliseconds{to_u64(
        "KYTHIRA_REDIS_DRAIN_TIMEOUT_MS", get_opt("KYTHIRA_REDIS_DRAIN_TIMEOUT_MS", "10000"))};
    if (g._forward_tls && g._forward_tls_ca_path.empty() && g._tls_ca_path.empty()) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_FORWARD_TLS needs KYTHIRA_REDIS_FORWARD_TLS_CA or "
            "KYTHIRA_REDIS_TLS_CA to verify peer gateways against");
    }
    if (g._forward_tls_cert_path.empty() != g._forward_tls_key_path.empty()) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_FORWARD_TLS_CERT and KYTHIRA_REDIS_FORWARD_TLS_KEY "
            "go together");
    }
    g._io_threads = to_u64("KYTHIRA_REDIS_IO_THREADS", get_opt("KYTHIRA_REDIS_IO_THREADS", "2"));
    g._worker_threads =
        to_u64("KYTHIRA_REDIS_WORKER_THREADS", get_opt("KYTHIRA_REDIS_WORKER_THREADS", "8"));
    g._log_commands =
        to_bool("KYTHIRA_REDIS_LOG_COMMANDS", get_opt("KYTHIRA_REDIS_LOG_COMMANDS", "false"));
    // Server identity (redis-general-data-types Requirement 1.5): the Redis
    // compatibility level clients gate features on, which must stay a plain
    // major.minor.patch. kythira_version is the build's (the config default).
    g._redis_compat_version =
        get_opt("KYTHIRA_REDIS_COMPAT_VERSION", kythira::k_redis_compat_version.data());
    if (!kythira::is_plain_redis_version(g._redis_compat_version)) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_COMPAT_VERSION must be a plain "
            "major.minor.patch such as 7.0.0, with no suffix (got '" +
            g._redis_compat_version + "')");
    }

    if (auto pg = get_opt("KYTHIRA_REDIS_PEER_GATEWAYS", ""); !pg.empty()) {
        o._peer_gateways = parse_id_map("KYTHIRA_REDIS_PEER_GATEWAYS", pg);
    } else {
        // Each peer's listener of the kind this node forwards over.
        const auto& listener = g._forward_tls ? g._tls_listen : g._listen;
        for (const auto& [id, url] : o._peers) {
            o._peer_gateways[id] = host_of(url) + ":" + port_of(listener);
        }
    }
    read_cache_options(o);
    // A front end without the data layer (redis-general-data-types task 16)
    // asks these data nodes for routes; their gateways' addresses, by name
    // or literal, resolved when used (never static IPs).
    const auto host_ports = [](const char* name, const std::string& text) {
        std::vector<std::string> out;
        std::size_t start = 0;
        while (!text.empty() && start <= text.size()) {
            const auto comma = std::min(text.find(',', start), text.size());
            auto item = text.substr(start, comma - start);
            if (item.empty() || !kythira::split_host_port(item)) {
                throw std::invalid_argument(std::string("redis_gateway_node: ") + name +
                                            " must be a comma-separated list of host:port (got '" +
                                            text + "')");
            }
            out.push_back(std::move(item));
            start = comma + 1;
        }
        return out;
    };
    g._data_nodes = host_ports("KYTHIRA_REDIS_DATA_NODES", get_opt("KYTHIRA_REDIS_DATA_NODES", ""));
    // A gateway without the front end (task 17) calls these front ends'
    // listeners, by name or literal, resolved when used.
    // Entries may name the front end: id=host:port.
    {
        std::vector<std::string> entries;
        const auto text = get_opt("KYTHIRA_REDIS_FRONT_ENDS", "");
        for (auto& item : host_ports("KYTHIRA_REDIS_FRONT_ENDS", text)) {
            const auto eq = item.find('=');
            if (eq != std::string::npos &&
                (eq == 0 || !kythira::split_host_port(item.substr(eq + 1)))) {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_FRONT_ENDS entries are host:port or "
                    "id=host:port (got '" +
                    item + "')");
            }
            entries.push_back(std::move(item));
        }
        g._front_ends = std::move(entries);
    }
    // Layer membership (task 18, Requirement 20): DNS discovery of front
    // ends, or the layer membership group, whose voters are named by node
    // id and reached on their gateway addresses.
    g._front_ends_dns = get_opt("KYTHIRA_REDIS_FRONT_ENDS_DNS", "");
    if (!g._front_ends_dns.empty() && !kythira::split_host_port(g._front_ends_dns)) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_FRONT_ENDS_DNS must be one name:port (got '" +
            g._front_ends_dns + "')");
    }
    g._discovery_interval =
        std::chrono::milliseconds{to_u64("KYTHIRA_REDIS_DISCOVERY_INTERVAL_MS",
                                         get_opt("KYTHIRA_REDIS_DISCOVERY_INTERVAL_MS", "5000"))};
    g._membership_interval =
        std::chrono::milliseconds{to_u64("KYTHIRA_REDIS_MEMBERSHIP_INTERVAL_MS",
                                         get_opt("KYTHIRA_REDIS_MEMBERSHIP_INTERVAL_MS", "1000"))};
    if (g._membership_interval.count() == 0 || g._discovery_interval.count() == 0) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_MEMBERSHIP_INTERVAL_MS and "
            "KYTHIRA_REDIS_DISCOVERY_INTERVAL_MS must be above 0");
    }
    o._membership_voters.clear();
    if (const auto voters = get_opt("KYTHIRA_REDIS_MEMBERSHIP", ""); !voters.empty()) {
        std::size_t start = 0;
        while (start <= voters.size()) {
            const auto comma = std::min(voters.find(',', start), voters.size());
            const auto item = voters.substr(start, comma - start);
            const auto id = to_peer_id("KYTHIRA_REDIS_MEMBERSHIP", item);
            if (!o._peers.contains(id)) {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_MEMBERSHIP names node " + item +
                    ", which KYTHIRA_PEERS does not list");
            }
            if (std::find(o._membership_voters.begin(), o._membership_voters.end(), id) !=
                o._membership_voters.end()) {
                throw std::invalid_argument("redis_gateway_node: KYTHIRA_REDIS_MEMBERSHIP lists " +
                                            item + " twice");
            }
            o._membership_voters.push_back(id);
            start = comma + 1;
        }
        if (o._membership_voters.size() % 2 == 0) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_MEMBERSHIP needs an odd number of voters "
                "(1, 3 or 5)");
        }
        g._membership_voters.clear();
        for (const auto& id : o._membership_voters) {
            g._membership_voters.push_back(o._peer_gateways.at(id));
        }
    }
    g._advertise_address = get_opt("KYTHIRA_REDIS_ADVERTISE", "");
    if (!g._advertise_address.empty() && !kythira::split_host_port(g._advertise_address)) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_ADVERTISE must be host:port (got '" +
            g._advertise_address + "')");
    }
    g._placement_group = get_opt("KYTHIRA_REDIS_PLACEMENT_GROUP", "");
    {
        std::ostringstream id;
        id << o._node_id;
        g._member_id = id.str();
        const auto index = get_opt("KYTHIRA_REDIS_FRONT_END_INDEX", "");
        g._front_end_index =
            index.empty()
                ? kythira::redis_membership::default_front_end_index(id.str())
                : static_cast<std::uint32_t>(to_u64("KYTHIRA_REDIS_FRONT_END_INDEX", index));
        if (g._front_end_index > kythira::redis_membership::k_max_front_end_index) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_FRONT_END_INDEX must be 1-16383");
        }
    }
    {
        auto& c = o._capacity;
        c._layer = get_opt("KYTHIRA_REDIS_CAPACITY_LAYER", "");
        if (!c._layer.empty() && c._layer != "gateway" && c._layer != "front_end") {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_LAYER must be gateway or front_end "
                "(got '" +
                c._layer + "')");
        }
        c._provider = get_opt("KYTHIRA_REDIS_CAPACITY_PROVIDER", "docker");
        c._dry_run = to_bool("KYTHIRA_REDIS_CAPACITY_DRY_RUN",
                             get_opt("KYTHIRA_REDIS_CAPACITY_DRY_RUN", "true"));
        c._scale_in = to_bool("KYTHIRA_REDIS_CAPACITY_SCALE_IN",
                              get_opt("KYTHIRA_REDIS_CAPACITY_SCALE_IN", "true"));
        c._min_members = to_u64("KYTHIRA_REDIS_CAPACITY_MIN_MEMBERS",
                                get_opt("KYTHIRA_REDIS_CAPACITY_MIN_MEMBERS", "2"));
        c._max_members = to_u64("KYTHIRA_REDIS_CAPACITY_MAX_MEMBERS",
                                get_opt("KYTHIRA_REDIS_CAPACITY_MAX_MEMBERS", "0"));
        c._requests_high = to_double("KYTHIRA_REDIS_CAPACITY_REQUESTS_HIGH",
                                     get_opt("KYTHIRA_REDIS_CAPACITY_REQUESTS_HIGH", "2000"));
        c._requests_low = to_double("KYTHIRA_REDIS_CAPACITY_REQUESTS_LOW",
                                    get_opt("KYTHIRA_REDIS_CAPACITY_REQUESTS_LOW", "600"));
        c._connections_high = to_double("KYTHIRA_REDIS_CAPACITY_CONNECTIONS_HIGH",
                                        get_opt("KYTHIRA_REDIS_CAPACITY_CONNECTIONS_HIGH", "0"));
        c._connections_low = to_double("KYTHIRA_REDIS_CAPACITY_CONNECTIONS_LOW",
                                       get_opt("KYTHIRA_REDIS_CAPACITY_CONNECTIONS_LOW", "0"));
        c._overload_cpu = to_double("KYTHIRA_REDIS_CAPACITY_OVERLOAD_CPU",
                                    get_opt("KYTHIRA_REDIS_CAPACITY_OVERLOAD_CPU", "0.85"));
        c._sustained = to_ms("KYTHIRA_REDIS_CAPACITY_SUSTAINED_MS",
                             get_opt("KYTHIRA_REDIS_CAPACITY_SUSTAINED_MS", "120000"));
        c._scale_in_sustained =
            to_ms("KYTHIRA_REDIS_CAPACITY_SCALE_IN_SUSTAINED_MS",
                  get_opt("KYTHIRA_REDIS_CAPACITY_SCALE_IN_SUSTAINED_MS", "900000"));
        c._cooldown = to_ms("KYTHIRA_REDIS_CAPACITY_COOLDOWN_MS",
                            get_opt("KYTHIRA_REDIS_CAPACITY_COOLDOWN_MS", "300000"));
        c._drain_deadline = to_ms("KYTHIRA_REDIS_CAPACITY_DRAIN_DEADLINE_MS",
                                  get_opt("KYTHIRA_REDIS_CAPACITY_DRAIN_DEADLINE_MS", "600000"));
        c._interval = to_ms("KYTHIRA_REDIS_CAPACITY_INTERVAL_MS",
                            get_opt("KYTHIRA_REDIS_CAPACITY_INTERVAL_MS", "5000"));
        c._docker_url = get_opt("KYTHIRA_REDIS_CAPACITY_DOCKER_URL", "unix:///var/run/docker.sock");
        c._docker_image = get_opt("KYTHIRA_REDIS_CAPACITY_DOCKER_IMAGE", "");
        c._docker_network = get_opt("KYTHIRA_REDIS_CAPACITY_DOCKER_NETWORK", "");
        c._docker_cluster = get_opt("KYTHIRA_REDIS_CAPACITY_DOCKER_CLUSTER", "");
        const auto port = to_u64("KYTHIRA_REDIS_CAPACITY_NODE_PORT",
                                 get_opt("KYTHIRA_REDIS_CAPACITY_NODE_PORT", "0"));
        if (port > 65535) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_NODE_PORT must be a port");
        }
        c._node_port = port == 0 ? o._raft_port : static_cast<std::uint16_t>(port);
        c._join_env.clear();
        // `;`-separated, since a value (a peer list) holds commas.
        const auto env = get_opt("KYTHIRA_REDIS_CAPACITY_JOIN_ENV", "");
        for (std::size_t start = 0; start < env.size();) {
            const auto semi = std::min(env.find(';', start), env.size());
            const auto item = env.substr(start, semi - start);
            if (!item.empty()) {
                if (item.find('=') == std::string::npos || item.starts_with("KYTHIRA_NODE_ID=")) {
                    throw std::invalid_argument(
                        "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_JOIN_ENV entries are "
                        "KEY=VALUE, and KYTHIRA_NODE_ID is the provider's to set (got '" +
                        item + "')");
                }
                c._join_env.push_back(item);
            }
            start = semi + 1;
        }
        if (!c._layer.empty()) {
            if (o._membership_voters.empty()) {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_LAYER needs the layer membership "
                    "group (KYTHIRA_REDIS_MEMBERSHIP): its leader runs the loop, on the load "
                    "the members report to it");
            }
            if (c._provider != "docker") {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_PROVIDER must be docker (got '" +
                    c._provider + "')");
            }
            if (c._docker_image.empty() || c._docker_network.empty() || c._docker_cluster.empty()) {
                throw std::invalid_argument(
                    "redis_gateway_node: the docker capacity provider needs "
                    "KYTHIRA_REDIS_CAPACITY_DOCKER_IMAGE, _DOCKER_NETWORK and _DOCKER_CLUSTER");
            }
            if (c._min_members == 0 || (c._max_members != 0 && c._max_members < c._min_members)) {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_MIN_MEMBERS must be at least 1 "
                    "and at most KYTHIRA_REDIS_CAPACITY_MAX_MEMBERS");
            }
            if (c._requests_high == 0.0 && c._connections_high == 0.0 && c._overload_cpu == 0.0) {
                throw std::invalid_argument(
                    "redis_gateway_node: the capacity loop needs at least one signal: "
                    "KYTHIRA_REDIS_CAPACITY_REQUESTS_HIGH, _CONNECTIONS_HIGH or _OVERLOAD_CPU");
            }
            if (c._interval.count() == 0) {
                throw std::invalid_argument(
                    "redis_gateway_node: KYTHIRA_REDIS_CAPACITY_INTERVAL_MS must be above 0");
            }
        }
    }
    if (g._layer_roles.has(layers::role::gateway) && !g._layer_roles.has(layers::role::front_end) &&
        g._front_ends.empty() && g._front_ends_dns.empty() && g._membership_voters.empty()) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_ROLES=" + g._layer_roles.to_string() +
            ": a gateway without the front end needs KYTHIRA_REDIS_FRONT_ENDS, "
            "KYTHIRA_REDIS_FRONT_ENDS_DNS or the layer membership group "
            "(KYTHIRA_REDIS_MEMBERSHIP) to find the front ends");
    }
    if (g._layer_roles.has(layers::role::front_end) && !g._layer_roles.has(layers::role::data)) {
        if (g._data_nodes.empty()) {
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_ROLES=" + g._layer_roles.to_string() +
                ": a front end without the data layer needs KYTHIRA_REDIS_DATA_NODES, the data "
                "nodes' gateway addresses");
        }
        if (o._cache._persistence == cache_persistence::file) {
            // The disk-backed store's entries name chunks held on the data
            // nodes, which a remote read cannot carry.
            throw std::invalid_argument(
                "redis_gateway_node: KYTHIRA_REDIS_ROLES=" + g._layer_roles.to_string() +
                ": a front end without the data layer needs KYTHIRA_CACHE_PERSISTENCE=memory or "
                "engine");
        }
    }
    if (!kythira::redis_roles_colocated(g._layer_roles) && !g._insecure_plaintext &&
        !g._forward_tls) {
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_ROLES=" + g._layer_roles.to_string() +
            ": a node that is not co-located calls the other layers over mutual TLS with layer "
            "identities; set KYTHIRA_REDIS_TLS_LISTEN and certificates naming "
            "kythira://redis/" +
            g._layer_cluster + "/<node id>?roles=" + g._layer_roles.to_string() +
            ", or KYTHIRA_NODE_INSECURE_PLAINTEXT=1 on an isolated network");
    }
    if (g._transactions && o._cache._persistence == cache_persistence::file) {
        // The disk-backed cache's state machine is not wrapped for
        // transactions (its chunk-referencing snapshots are untested under
        // the intent layer). The in-memory and engine stores offer them.
        throw std::invalid_argument(
            "redis_gateway_node: KYTHIRA_REDIS_TRANSACTIONS=on needs "
            "KYTHIRA_CACHE_PERSISTENCE=memory or engine");
    }
    return o;
}

auto from_env(const service_node::env_lookup& env) -> node_options {
    struct scope {
        explicit scope(const service_node::env_lookup* e) : _prev(t_env) { t_env = e; }
        scope(const scope&) = delete;
        auto operator=(const scope&) -> scope& = delete;
        scope(scope&&) = delete;
        auto operator=(scope&&) -> scope& = delete;
        ~scope() { t_env = _prev; }
        const service_node::env_lookup* _prev;
    };
    const scope s(&env);
    return from_env();
}

auto process_env() -> service_node::env_lookup {
    return [](std::string_view name) -> std::optional<std::string> {
        // Read at startup, before the node starts a thread. Set but empty
        // stays set, as from_env() has always read it.
        const char* v = std::getenv(std::string(name).c_str());  // NOLINT(concurrency-mt-unsafe)
        return v != nullptr ? std::optional<std::string>(v) : std::nullopt;
    };
}

auto composite_env(service_node::env_lookup env) -> service_node::env_lookup {
    return [env = std::move(env)](std::string_view name) -> std::optional<std::string> {
        const auto node = [&env](const char* n) {
            auto v = env(n);
            return v && !v->empty() ? v : std::nullopt;
        };
        const bool plaintext = node("KYTHIRA_NODE_INSECURE_PLAINTEXT").value_or("") == "1";
        if (name == "KYTHIRA_CACHE_DATA_DIR") {
            // Memory mode refuses a data directory; every other mode keeps
            // its files in the node's redis/.
            if (env("KYTHIRA_CACHE_PERSISTENCE").value_or("file") == "memory") {
                return std::nullopt;
            }
            auto dir = node("KYTHIRA_NODE_DATA_DIR");
            if (!dir) {
                return std::nullopt;
            }
            return (std::filesystem::path(*dir) / "redis").string();
        }
        if (name == "KYTHIRA_ALLOW_PLAINTEXT_RAFT") {
            // Raft is the node's listener, which speaks mutual TLS unless
            // the whole node is plaintext.
            return std::string("true");
        }
        if (name == "KYTHIRA_WIRE_SERIALIZER") {
            // The node's wire, whatever the module was told.
            return std::string("cbor");
        }
        if (auto v = env(name)) {
            return v;
        }
        if (name == "KYTHIRA_PEERS") {
            // id=host:port,... as id=scheme://host:port,...
            const auto peers = node("KYTHIRA_NODE_PEERS");
            if (!peers) {
                return std::nullopt;
            }
            std::string out;
            std::string tok;
            for (const char c : *peers + ',') {
                if (c != ',') {
                    if (c != ' ') {
                        tok += c;
                    }
                    continue;
                }
                if (!tok.empty()) {
                    const auto eq = tok.find('=');
                    out += (out.empty() ? "" : ",") +
                           (eq == std::string::npos
                                ? tok  // from_env names the fault
                                : tok.substr(0, eq + 1) + (plaintext ? "http://" : "https://") +
                                      tok.substr(eq + 1));
                }
                tok.clear();
            }
            return out;
        }
        if (name == "KYTHIRA_RAFT_BIND") {
            return node("KYTHIRA_NODE_RAFT_BIND");
        }
        if (name == "KYTHIRA_RAFT_PORT") {
            return node("KYTHIRA_NODE_RAFT_PORT").value_or("7400");  // node_config's default
        }
        // The RESP TLS listener, when one is asked for, and forwarding to
        // the peers' TLS listeners, use the node's certificate and CA.
        if (name == "KYTHIRA_REDIS_TLS_CERT" && !plaintext) {
            return node("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "KYTHIRA_REDIS_TLS_KEY" && !plaintext) {
            return node("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "KYTHIRA_REDIS_FORWARD_TLS_CA" && !plaintext) {
            return node("KYTHIRA_NODE_TLS_CA");
        }
        return std::nullopt;
    };
}

auto usage() -> std::string {
    std::ostringstream out;
    out << "redis_gateway_node — a Redis-compatible cache front end over Kythira multi-Raft\n"
           "\n"
           "usage: redis_gateway_node               run the daemon (configured by environment)\n"
           "       redis_gateway_node --hash-secret [iterations]\n"
           "                                        read a secret from stdin, print an ACL record\n"
           "       redis_gateway_node --help\n"
           "\n"
           "Raft side (environment):\n"
           "  KYTHIRA_NODE_ID                  this node's id (required): "
        << (kythira::host_node_id_is_text
                ? "decimal, canonical composite text, or metadata:<provider>"
                : "decimal")
        << "\n"
           "  KYTHIRA_PEERS                   id=http://host:port,... for every voter, self "
           "included (required)\n"
           "  KYTHIRA_RAFT_BIND                bind address for Raft RPCs             [0.0.0.0]\n"
           "  KYTHIRA_RAFT_PORT                Raft RPC port                          [7000]\n"
           "  KYTHIRA_ALLOW_PLAINTEXT_RAFT     allow plaintext Raft RPC off loopback  [false]\n"
           "                                   (required unless KYTHIRA_RAFT_BIND is loopback)\n"
           "  KYTHIRA_WIRE_SERIALIZER          cbor | json                            [cbor]\n"
           "  KYTHIRA_LOG_LEVEL                trace|debug|info|warning|error|critical [info]\n"
           "  KYTHIRA_SHARD_CUTS               comma-separated initial shard boundaries [none: one "
           "shard]\n"
           "  KYTHIRA_TICK_INTERVAL_MS, KYTHIRA_ELECTION_TIMEOUT_MIN_MS, "
           "KYTHIRA_ELECTION_TIMEOUT_MAX_MS,\n"
           "  KYTHIRA_HEARTBEAT_INTERVAL_MS, KYTHIRA_RPC_TIMEOUT_MS, KYTHIRA_POLICY_INTERVAL_MS,\n"
           "  KYTHIRA_EXECUTOR_STRIPES\n"
           "\n"
           "Gateway side (environment; design.md Component 9):\n"
           "  KYTHIRA_REDIS_ROLES              layers this node runs, a subset of "
           "gateway,front_end,data [all]\n"
           "  KYTHIRA_REDIS_DATA_NODES         host:port,... of data nodes (a front end without "
           "data)\n"
           "  KYTHIRA_REDIS_FRONT_ENDS         host:port,... of front ends (a gateway without "
           "front_end)\n"
           "  KYTHIRA_REDIS_FRONT_ENDS_DNS     name:port; every address is a front end "
           "(re-resolved)\n"
           "  KYTHIRA_REDIS_DISCOVERY_INTERVAL_MS  how often that name is resolved [5000]\n"
           "  KYTHIRA_REDIS_MEMBERSHIP         node ids of the layer membership group's voters "
           "(1, 3 or 5)\n"
           "  KYTHIRA_REDIS_MEMBERSHIP_INTERVAL_MS  announce, report load, read the list "
           "[1000]\n"
           "  KYTHIRA_REDIS_ADVERTISE          host:port other layers reach this node on "
           "[hostname:port]\n"
           "  KYTHIRA_REDIS_PLACEMENT_GROUP    placement group reported to the group  [none]\n"
           "  KYTHIRA_REDIS_FRONT_END_INDEX    1-16383, names this front end in SCAN cursors "
           "[node id]\n"
           "  KYTHIRA_REDIS_CAPACITY_LAYER     gateway or front_end: the group's leader scales "
           "it  [off]\n"
           "  KYTHIRA_REDIS_CAPACITY_DRY_RUN   decide and log, add and remove nothing  [true]\n"
           "  KYTHIRA_REDIS_CAPACITY_SCALE_IN  remove members, not only add them  [true]\n"
           "  KYTHIRA_REDIS_CAPACITY_MIN_MEMBERS / _MAX_MEMBERS  bounds  [2 / 3x first size]\n"
           "  KYTHIRA_REDIS_CAPACITY_REQUESTS_HIGH / _LOW  commands/s per member  [2000 / 600]\n"
           "  KYTHIRA_REDIS_CAPACITY_CONNECTIONS_HIGH / _LOW  connections per member  [off]\n"
           "  KYTHIRA_REDIS_CAPACITY_OVERLOAD_CPU  CPU share that counts as overloaded  [0.85]\n"
           "  KYTHIRA_REDIS_CAPACITY_SUSTAINED_MS / _SCALE_IN_SUSTAINED_MS / _COOLDOWN_MS  "
           "[120000 / 900000 / 300000]\n"
           "  KYTHIRA_REDIS_CAPACITY_DRAIN_DEADLINE_MS  longest drain before decommission "
           "[600000]\n"
           "  KYTHIRA_REDIS_CAPACITY_INTERVAL_MS  how often the loop runs  [5000]\n"
           "  KYTHIRA_REDIS_CAPACITY_PROVIDER  docker  [docker]\n"
           "  KYTHIRA_REDIS_CAPACITY_DOCKER_URL / _DOCKER_IMAGE / _DOCKER_NETWORK / "
           "_DOCKER_CLUSTER\n"
           "  KYTHIRA_REDIS_CAPACITY_NODE_PORT  new members' Raft port  [this node's]\n"
           "  KYTHIRA_REDIS_CAPACITY_JOIN_ENV  KEY=VALUE;... every new member gets\n"
           "  KYTHIRA_REDIS_CLUSTER            cluster named in layer identities  [KYTHIRA_CLUSTER "
           "or default]\n"
           "  KYTHIRA_NODE_INSECURE_PLAINTEXT  1: split layers without TLS identities  [unset]\n"
           "  KYTHIRA_REDIS_DRAIN_TIMEOUT_MS   SIGTERM: finish in-flight commands for up to "
           "[10000]\n"
           "  KYTHIRA_REDIS_LISTEN             plaintext RESP listener                "
           "[0.0.0.0:6379]\n"
           "  KYTHIRA_REDIS_TLS_LISTEN         TLS listener (needs _TLS_CERT and _TLS_KEY)\n"
           "  KYTHIRA_REDIS_TLS_CERT / _KEY / _CA\n"
           "  KYTHIRA_REDIS_REQUIRE_CLIENT_CERT                                       [false]\n"
           "  KYTHIRA_REDIS_ACL_FILE           ACL file (required unless ALLOW_ANONYMOUS)\n"
           "  KYTHIRA_REDIS_ALLOW_ANONYMOUS    run with no ACL; warns at every start  [false]\n"
           "  KYTHIRA_REDIS_READ_CONSISTENCY   leader | any_replica | linearizable    [leader]\n"
           "  KYTHIRA_REDIS_TRANSACTIONS       MSET/MGET/multi-key DEL/MULTI as transactions "
           "[off]\n"
           "                                   (needs CONFIG_REDIS_GATEWAY_TRANSACTIONS=y)\n"
           "  KYTHIRA_REDIS_TXN_ISOLATION      default level; KYTHIRA.ISOLATION per connection "
           "[read_committed]\n"
           "                                   (snapshot needs "
           "CONFIG_REDIS_GATEWAY_SNAPSHOT_ISOLATION=y)\n"
           "  KYTHIRA_REDIS_TXN_LOCK_TTL_MS    an unheartbeated intent's lifetime      [3000]\n"
           "  KYTHIRA_REDIS_TXN_MAX_RETRIES    automatic retries after a conflict      [2]\n"
           "  KYTHIRA_REDIS_MAX_VALUE_BYTES                                            [8388608]\n"
           "  KYTHIRA_REDIS_MAX_CLIENTS                                                [1024]\n"
           "  KYTHIRA_REDIS_IDLE_TIMEOUT_MS                                            [300000]\n"
           "  KYTHIRA_REDIS_COMMAND_TIMEOUT_MS                                         [5000]\n"
           "  KYTHIRA_REDIS_MAX_SHARD_BYTES    memory mode; file mode only if set     "
           "[1073741824]\n"
           "  KYTHIRA_REDIS_SWEEP_BATCH                                                [1024]\n"
           "  KYTHIRA_REDIS_IMMUTABLE_VALUES                                           [true]\n"
           "  KYTHIRA_REDIS_FORWARDING                                                 [true]\n"
           "  KYTHIRA_REDIS_INTERNAL_USER      ACL user forwarded commands run as     "
           "[kythira-internal]\n"
           "  KYTHIRA_REDIS_INTERNAL_SECRET    that user's secret; empty disables forwarding\n"
           "  KYTHIRA_REDIS_FORWARD_TLS        forward to peers' TLS listeners  [true if "
           "TLS_LISTEN]\n"
           "  KYTHIRA_REDIS_FORWARD_TLS_CA     CA peers must chain to                 [TLS_CA]\n"
           "  KYTHIRA_REDIS_FORWARD_TLS_CERT / _KEY  client cert for peers  [TLS_CERT / TLS_KEY]\n"
           "  KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING  send the internal secret unencrypted "
           "[false]\n"
           "  KYTHIRA_REDIS_PEER_GATEWAYS      id=host:port,... of every peer's gateway [peer host "
           "+ LISTEN port, or TLS_LISTEN port when forwarding over TLS]\n"
           "  KYTHIRA_REDIS_IO_THREADS, KYTHIRA_REDIS_WORKER_THREADS, KYTHIRA_REDIS_LOG_COMMANDS\n"
           "  KYTHIRA_REDIS_COMPAT_VERSION     redis_version / HELLO version, plain x.y.z [7.0.0]\n"
           "\n"
           "\n"
           "Disk-backed cache (environment; .kiro/specs/disk-backed-build-cache/):\n"
           "  KYTHIRA_CACHE_PERSISTENCE        file | engine (RocksDB, needs "
           "CONFIG_REDIS_GATEWAY_ENGINE=y) | memory (values and Raft state in RAM) [file]\n"
           "  KYTHIRA_CACHE_DATA_DIR           chunk store or engine, and Raft state (required "
           "for file and engine)\n"
           "  KYTHIRA_CACHE_MAX_DISK_BYTES     store budget per node; evicts above it "
           "(required for file and engine)\n"
           "  KYTHIRA_CACHE_MIN_FREE_BYTES     refuse writes below this free space   "
           "[1073741824]\n"
           "  KYTHIRA_CACHE_MIN_FREE_INODES    refuse writes below this many inodes  [10000]\n"
           "  KYTHIRA_CACHE_CHUNK_BYTES        at most 16777216                      [4194304]\n"
           "  KYTHIRA_CACHE_MAX_VALUE_BYTES    largest value over HTTP               "
           "[2147483648]\n"
           "  KYTHIRA_CACHE_PACK_THRESHOLD_BYTES  smaller chunks go to pack files   [65536]\n"
           "  KYTHIRA_CACHE_ORPHAN_GRACE_ENTRIES  log entries an unbound chunk lives [100000]\n"
           "  KYTHIRA_CACHE_FETCH_BYTES_PER_SEC   peer chunk fetch rate              "
           "[50000000]\n"
           "  KYTHIRA_CACHE_SNAPSHOT_THRESHOLD_BYTES  Raft log bytes per snapshot    "
           "[268435456]\n"
           "  KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC  engine only: snapshot send rate "
           "to lagging followers, node-wide, 0 = unlimited [0]\n"
           "  KYTHIRA_CACHE_HTTPS_LISTEN       HTTP/WebDAV front end over TLS\n"
           "  KYTHIRA_CACHE_HTTPS_CERT / _KEY                        [REDIS_TLS_CERT / _KEY]\n"
           "  KYTHIRA_CACHE_HTTP_LISTEN        plaintext front end; needs the opt-in below\n"
           "  KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP                                     [false]\n"
           "  KYTHIRA_CACHE_AUTH_CACHE_SECONDS successful-auth cache lifetime         [300]\n"
           "  KYTHIRA_CACHE_PEER_HTTP          id=host:port,... of every peer's front end [peer "
           "host + this node's front-end port]\n"
           "\n"
           "ACL file lines: user <name> <pbkdf2-record|nopass|disabled> "
           "<read_only|read_write|admin> [prefix...|*] "
           "[cert=<subject>]\n";
    return out.str();
}

}  // namespace kythira::redis_node
