// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// redis_gateway_node's environment parsing, for the rules that are security
// boundaries: Raft RPC has no TLS, so a non-loopback KYTHIRA_RAFT_BIND needs
// the explicit KYTHIRA_ALLOW_PLAINTEXT_RAFT opt-in; and forwarding carries the
// internal secret, so it is TLS whenever a TLS listener is configured and
// plaintext only by KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING. Also the
// disk-backed cache's KYTHIRA_CACHE_* variables
// (.kiro/specs/disk-backed-build-cache/ task 7), and the module's settings in
// kythira_node, the node's KYTHIRA_NODE_* filling in what the module's own
// variables leave unset (.kiro/specs/service-colocation/ task 7).

#define BOOST_TEST_MODULE redis_gateway_node_config_unit_test
#include <boost/test/unit_test.hpp>

#include "config.hpp"

#include <raft/build_version.hpp>

#include <cstdlib>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

using kythira::redis_node::from_env;
using kythira::redis_node::is_loopback_address;

// Sets the minimum environment from_env() requires and clears the variables
// under test, restoring a clean slate on destruction.
struct gateway_env {
    gateway_env() {
        ::setenv("KYTHIRA_NODE_ID", "1", 1);
        ::setenv("KYTHIRA_PEERS", "1=http://127.0.0.1:7000", 1);
        ::setenv("KYTHIRA_REDIS_ALLOW_ANONYMOUS", "true", 1);
        for (const char* v : k_cleared) {
            ::unsetenv(v);
        }
        // The tests that predate the disk-backed cache run the deployment
        // they were written for; the cache tests switch to file.
        ::setenv("KYTHIRA_CACHE_PERSISTENCE", "memory", 1);
    }
    ~gateway_env() {
        for (const char* v :
             {"KYTHIRA_NODE_ID", "KYTHIRA_PEERS", "KYTHIRA_REDIS_ALLOW_ANONYMOUS"}) {
            ::unsetenv(v);
        }
        for (const char* v : k_cleared) {
            ::unsetenv(v);
        }
    }
    static constexpr const char* k_cleared[] = {
        "KYTHIRA_RAFT_BIND",
        "KYTHIRA_ALLOW_PLAINTEXT_RAFT",
        "KYTHIRA_REDIS_TLS_LISTEN",
        "KYTHIRA_REDIS_TLS_CERT",
        "KYTHIRA_REDIS_TLS_KEY",
        "KYTHIRA_REDIS_TLS_CA",
        "KYTHIRA_REDIS_FORWARD_TLS",
        "KYTHIRA_REDIS_FORWARD_TLS_CA",
        "KYTHIRA_REDIS_FORWARD_TLS_CERT",
        "KYTHIRA_REDIS_FORWARD_TLS_KEY",
        "KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING",
        "KYTHIRA_REDIS_PEER_GATEWAYS",
        "KYTHIRA_REDIS_MAX_VALUE_BYTES",
        "KYTHIRA_WIRE_SERIALIZER",
        "KYTHIRA_CACHE_PERSISTENCE",
        "KYTHIRA_CACHE_DATA_DIR",
        "KYTHIRA_CACHE_MAX_DISK_BYTES",
        "KYTHIRA_CACHE_CHUNK_BYTES",
        "KYTHIRA_REDIS_MAX_SHARD_BYTES",
        "KYTHIRA_CACHE_HTTP_LISTEN",
        "KYTHIRA_CACHE_HTTPS_LISTEN",
        "KYTHIRA_CACHE_HTTPS_CERT",
        "KYTHIRA_CACHE_HTTPS_KEY",
        "KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP",
        "KYTHIRA_CACHE_PEER_HTTP",
        "KYTHIRA_CACHE_MIN_FREE_BYTES",
        "KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC",
        "KYTHIRA_REDIS_TRANSACTIONS",
        "KYTHIRA_REDIS_TXN_ISOLATION",
        "KYTHIRA_REDIS_TXN_LOCK_TTL_MS",
        "KYTHIRA_REDIS_TXN_MAX_RETRIES",
        "KYTHIRA_REDIS_COMPAT_VERSION",
        "KYTHIRA_REDIS_ROLES",
        "KYTHIRA_REDIS_DATA_NODES",
        "KYTHIRA_REDIS_FRONT_ENDS",
        "KYTHIRA_REDIS_CLUSTER",
        "KYTHIRA_CLUSTER",
        "KYTHIRA_NODE_INSECURE_PLAINTEXT",
        "KYTHIRA_REDIS_DRAIN_TIMEOUT_MS",
    };
    gateway_env(const gateway_env&) = delete;
    auto operator=(const gateway_env&) -> gateway_env& = delete;
};

}  // namespace

BOOST_AUTO_TEST_CASE(loopback_addresses) {
    BOOST_TEST(is_loopback_address("127.0.0.1"));
    BOOST_TEST(is_loopback_address("127.1.2.3"));
    BOOST_TEST(is_loopback_address("::1"));
    BOOST_TEST(!is_loopback_address("0.0.0.0"));
    BOOST_TEST(!is_loopback_address("::"));
    BOOST_TEST(!is_loopback_address("10.0.0.1"));
    BOOST_TEST(!is_loopback_address("128.0.0.1"));
    BOOST_TEST(is_loopback_address("localhost"));
    BOOST_TEST(!is_loopback_address("*"));
    BOOST_TEST(!is_loopback_address(""));
}

// The default bind is 0.0.0.0, so with no opt-in the daemon must refuse.
BOOST_AUTO_TEST_CASE(default_bind_without_opt_in_is_refused) {
    gateway_env env;
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(wildcard_bind_with_opt_in_is_allowed) {
    gateway_env env;
    ::setenv("KYTHIRA_ALLOW_PLAINTEXT_RAFT", "true", 1);
    auto opt = from_env();
    BOOST_TEST(opt._allow_plaintext_raft);
    BOOST_TEST(opt._bind_address == "0.0.0.0");
}

BOOST_AUTO_TEST_CASE(opt_in_false_is_refused) {
    gateway_env env;
    ::setenv("KYTHIRA_ALLOW_PLAINTEXT_RAFT", "false", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(malformed_opt_in_is_refused) {
    gateway_env env;
    ::setenv("KYTHIRA_ALLOW_PLAINTEXT_RAFT", "maybe", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(loopback_bind_needs_no_opt_in) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    auto opt = from_env();
    BOOST_TEST(!opt._allow_plaintext_raft);
    BOOST_TEST(opt._bind_address == "127.0.0.1");
}

BOOST_AUTO_TEST_CASE(localhost_bind_needs_no_opt_in) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "localhost", 1);
    auto opt = from_env();
    BOOST_TEST(!opt._allow_plaintext_raft);
    BOOST_TEST(opt._bind_address == "localhost");
}

// The server identity (redis-general-data-types Requirement 1.5): the build's
// own version, and a Redis compatibility level that defaults to the build's
// and may be overridden, but only with a plain major.minor.patch.
BOOST_AUTO_TEST_CASE(server_identity_settings) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    {
        auto opt = from_env();
        BOOST_TEST(opt._gateway._redis_compat_version == "7.0.0");
        BOOST_TEST(opt._gateway._kythira_version == std::string(kythira::build_version()));
        BOOST_TEST(!opt._gateway._kythira_version.empty());
        BOOST_TEST(!opt._gateway._cluster_compat_mode);
    }
    ::setenv("KYTHIRA_REDIS_COMPAT_VERSION", "7.2.4", 1);
    BOOST_TEST(from_env()._gateway._redis_compat_version == "7.2.4");
    for (const char* bad : {"7.2.4-kythira", "7.2", "seven", ""}) {
        ::setenv("KYTHIRA_REDIS_COMPAT_VERSION", bad, 1);
        BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    }
}

// A plaintext-only node neither forwards over TLS nor, without the opt-in,
// over plaintext: the gateway answers with the retry error instead.
BOOST_AUTO_TEST_CASE(plaintext_forwarding_is_off_by_default) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_PEERS", "1=http://127.0.0.1:7000,2=http://10.0.0.2:7000", 1);
    auto opt = from_env();
    BOOST_TEST(!opt._gateway._forward_tls);
    BOOST_TEST(!opt._gateway._allow_plaintext_forwarding);
    BOOST_TEST(opt._peer_gateways.at(2) == "10.0.0.2:6379");
}

BOOST_AUTO_TEST_CASE(plaintext_forwarding_opt_in) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_ALLOW_PLAINTEXT_FORWARDING", "true", 1);
    auto opt = from_env();
    BOOST_TEST(opt._gateway._allow_plaintext_forwarding);
    BOOST_TEST(!opt._gateway._forward_tls);
}

// A TLS listener turns on TLS forwarding, and the derived peer endpoints
// point at the peers' TLS listeners rather than their plaintext ones.
BOOST_AUTO_TEST_CASE(tls_listener_forwards_over_tls_to_tls_ports) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_PEERS", "1=http://127.0.0.1:7000,2=http://kv2:7000", 1);
    ::setenv("KYTHIRA_REDIS_TLS_LISTEN", "0.0.0.0:6380", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CERT", "/etc/kythira/kv.crt", 1);
    ::setenv("KYTHIRA_REDIS_TLS_KEY", "/etc/kythira/kv.key", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CA", "/etc/kythira/ca.crt", 1);
    auto opt = from_env();
    BOOST_TEST(opt._gateway._forward_tls);
    BOOST_TEST(opt._peer_gateways.at(2) == "kv2:6380");
}

BOOST_AUTO_TEST_CASE(tls_forwarding_can_be_turned_off) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_PEERS", "1=http://127.0.0.1:7000,2=http://kv2:7000", 1);
    ::setenv("KYTHIRA_REDIS_TLS_LISTEN", "0.0.0.0:6380", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CERT", "/etc/kythira/kv.crt", 1);
    ::setenv("KYTHIRA_REDIS_TLS_KEY", "/etc/kythira/kv.key", 1);
    ::setenv("KYTHIRA_REDIS_FORWARD_TLS", "false", 1);
    auto opt = from_env();
    BOOST_TEST(!opt._gateway._forward_tls);
    BOOST_TEST(opt._peer_gateways.at(2) == "kv2:6379");
}

// Without a CA the client could only trust every certificate, which hands
// the internal secret to whoever answers.
BOOST_AUTO_TEST_CASE(tls_forwarding_without_a_ca_is_refused) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_TLS_LISTEN", "0.0.0.0:6380", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CERT", "/etc/kythira/kv.crt", 1);
    ::setenv("KYTHIRA_REDIS_TLS_KEY", "/etc/kythira/kv.key", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_REDIS_FORWARD_TLS_CA", "/etc/kythira/peers.crt", 1);
    auto opt = from_env();
    BOOST_TEST(opt._gateway._forward_tls_ca_path == "/etc/kythira/peers.crt");
}

BOOST_AUTO_TEST_CASE(half_a_forwarding_client_certificate_is_refused) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_FORWARD_TLS_CERT", "/etc/kythira/client.crt", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

// ── the disk-backed cache ───────────────────────────────────────────────────

namespace {

/// The least a file-mode node needs on top of `gateway_env`.
void file_mode() {
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_CACHE_PERSISTENCE", "file", 1);
    ::setenv("KYTHIRA_CACHE_DATA_DIR", "/var/lib/kythira", 1);
    ::setenv("KYTHIRA_CACHE_MAX_DISK_BYTES", "107374182400", 1);
}

}  // namespace

// Requirement 5.4: file is the default, and it needs a data directory and a
// budget, so a deployment that sets neither fails at start-up rather than
// filling a disk.
BOOST_AUTO_TEST_CASE(file_persistence_is_the_default_and_needs_a_data_dir_and_budget) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::unsetenv("KYTHIRA_CACHE_PERSISTENCE");
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_DATA_DIR", "/var/lib/kythira", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_MAX_DISK_BYTES", "0", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_MAX_DISK_BYTES", "107374182400", 1);
    auto opt = from_env();
    BOOST_TEST((opt._cache._persistence == kythira::redis_node::cache_persistence::file));
    BOOST_TEST(opt._cache._data_dir == "/var/lib/kythira");
    BOOST_TEST(opt._cache._max_disk_bytes == 107374182400ULL);
    BOOST_TEST(opt._cache._chunk_bytes == 4U * 1024U * 1024U);
    BOOST_TEST(opt._cache._min_free_inodes == 10000U);
}

BOOST_AUTO_TEST_CASE(memory_persistence_refuses_disk_variables) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    auto opt = from_env();
    BOOST_TEST((opt._cache._persistence == kythira::redis_node::cache_persistence::memory));
    ::setenv("KYTHIRA_CACHE_DATA_DIR", "/var/lib/kythira", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::unsetenv("KYTHIRA_CACHE_DATA_DIR");
    ::setenv("KYTHIRA_CACHE_HTTPS_LISTEN", "0.0.0.0:8443", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::unsetenv("KYTHIRA_CACHE_HTTPS_LISTEN");
    ::setenv("KYTHIRA_CACHE_PERSISTENCE", "disk", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

// Snapshot pacing is the engine's catch-up path; file mode's is chunk
// fetching, with its own rate. Set anywhere else, the variable would be
// silently ignored, so it is refused.
BOOST_AUTO_TEST_CASE(snapshot_pacing_needs_engine_persistence) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC", "1048576", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);  // memory
    ::setenv("KYTHIRA_CACHE_PERSISTENCE", "file", 1);
    ::setenv("KYTHIRA_CACHE_DATA_DIR", "/var/lib/kythira", 1);
    ::setenv("KYTHIRA_CACHE_MAX_DISK_BYTES", "107374182400", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::unsetenv("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC");
    BOOST_CHECK_NO_THROW((void)from_env());

    ::setenv("KYTHIRA_CACHE_PERSISTENCE", "engine", 1);
#if defined(KYTHIRA_REDIS_GATEWAY_ENGINE)
    BOOST_TEST(from_env()._cache._snapshot_bytes_per_sec == 0U);  // unlimited
    ::setenv("KYTHIRA_CACHE_SNAPSHOT_BYTES_PER_SEC", "1048576", 1);
    BOOST_TEST(from_env()._cache._snapshot_bytes_per_sec == 1048576U);
#else
    // A build without the engine refuses the mode itself.
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
#endif
}

BOOST_AUTO_TEST_CASE(chunk_size_and_resp_values_are_bounded_by_one_chunk) {
    gateway_env env;
    file_mode();
    ::setenv("KYTHIRA_CACHE_CHUNK_BYTES", "16777217", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_CHUNK_BYTES", "0", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_CHUNK_BYTES", "16777216", 1);
    BOOST_TEST(from_env()._cache._chunk_bytes == 16777216U);
    // A SET is one log entry stored as one chunk.
    ::setenv("KYTHIRA_REDIS_MAX_VALUE_BYTES", "33554432", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

// Requirement 6.1: in file mode the disk budget bounds the values, not the
// memory mode's per-shard budget, unless the operator sets that too.
BOOST_AUTO_TEST_CASE(the_memory_shard_budget_applies_in_file_mode_only_when_set) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    BOOST_TEST(from_env()._gateway._max_shard_bytes == 1073741824U);
    file_mode();
    BOOST_TEST(from_env()._gateway._max_shard_bytes == std::numeric_limits<std::size_t>::max());
    ::setenv("KYTHIRA_REDIS_MAX_SHARD_BYTES", "2147483648", 1);
    BOOST_TEST(from_env()._gateway._max_shard_bytes == 2147483648U);
}

BOOST_AUTO_TEST_CASE(file_persistence_needs_the_cbor_wire) {
    gateway_env env;
    file_mode();
    ::setenv("KYTHIRA_WIRE_SERIALIZER", "json", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

// Requirement 8.5: the plaintext front end carries credentials in the clear.
BOOST_AUTO_TEST_CASE(plaintext_http_needs_its_opt_in) {
    gateway_env env;
    file_mode();
    ::setenv("KYTHIRA_CACHE_HTTP_LISTEN", "127.0.0.1:8080", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_CACHE_ALLOW_PLAINTEXT_HTTP", "true", 1);
    auto opt = from_env();
    BOOST_TEST(opt._cache._allow_plaintext_http);
    BOOST_TEST(opt._cache._peer_http.at(1) == "127.0.0.1:8080");
}

BOOST_AUTO_TEST_CASE(https_takes_the_resp_certificate_by_default) {
    gateway_env env;
    file_mode();
    ::setenv("KYTHIRA_PEERS", "1=http://127.0.0.1:7000,2=http://kv2:7000", 1);
    ::setenv("KYTHIRA_CACHE_HTTPS_LISTEN", "0.0.0.0:8443", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::setenv("KYTHIRA_REDIS_TLS_LISTEN", "0.0.0.0:6380", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CERT", "/etc/kythira/kv.crt", 1);
    ::setenv("KYTHIRA_REDIS_TLS_KEY", "/etc/kythira/kv.key", 1);
    ::setenv("KYTHIRA_REDIS_TLS_CA", "/etc/kythira/ca.crt", 1);
    auto opt = from_env();
    BOOST_TEST(opt._cache._tls_cert_path == "/etc/kythira/kv.crt");
    BOOST_TEST(opt._cache._tls_key_path == "/etc/kythira/kv.key");
    // Forwarding is over TLS, so peers' front ends are their HTTPS ones.
    BOOST_TEST(opt._cache._peer_http.at(2) == "kv2:8443");
}

// multi-raft-transactions task 9: the transaction knobs. This test links
// config.cpp without the adapter, so asking for transactions is refused.
BOOST_AUTO_TEST_CASE(transaction_settings) {
    gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    auto defaults = from_env();
    BOOST_TEST(!defaults._gateway._transactions);
    BOOST_TEST((defaults._gateway._txn_isolation == kythira::txn_isolation::read_committed));
    BOOST_TEST(defaults._gateway._txn_lock_ttl.count() == 3000);
    BOOST_TEST(defaults._gateway._txn_max_retries == 2u);

    ::setenv("KYTHIRA_REDIS_TXN_ISOLATION", "read-committed-wait", 1);
    ::setenv("KYTHIRA_REDIS_TXN_LOCK_TTL_MS", "750", 1);
    auto set = from_env();
    BOOST_TEST((set._gateway._txn_isolation == kythira::txn_isolation::read_committed_wait));
    BOOST_TEST(set._gateway._txn_lock_ttl.count() == 750);

    ::setenv("KYTHIRA_REDIS_TXN_ISOLATION", "eventual", 1);
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    ::unsetenv("KYTHIRA_REDIS_TXN_ISOLATION");

    ::setenv("KYTHIRA_REDIS_TRANSACTIONS", "on", 1);
#if defined(KYTHIRA_REDIS_GATEWAY_TRANSACTIONS)
    BOOST_TEST(from_env()._gateway._transactions);
#else
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
#endif
    // Only the in-memory store is wrapped for transactions.
    file_mode();
    BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
}

// ── kythira_node (service-colocation task 7) ─────────────────────────────────

namespace {

namespace sn = kythira::service_node;

auto lookup(std::map<std::string, std::string> vars) -> sn::env_lookup {
    return [vars = std::move(vars)](std::string_view name) -> std::optional<std::string> {
        const auto it = vars.find(std::string(name));
        if (it == vars.end()) {
            return std::nullopt;
        }
        return it->second;
    };
}

auto node_vars() -> std::map<std::string, std::string> {
    return {
        {"KYTHIRA_NODE_ID", "2"},
        {"KYTHIRA_NODE_PEERS", "1=10.0.0.1:7400,2=10.0.0.2:7400,3=[fd00::3]:7400"},
        {"KYTHIRA_NODE_DATA_DIR", "/var/lib/kythira"},
        {"KYTHIRA_NODE_RAFT_BIND", "0.0.0.0"},
        {"KYTHIRA_NODE_TLS_CERT", "/etc/kythira/node.pem"},
        {"KYTHIRA_NODE_TLS_KEY", "/etc/kythira/node.key"},
        {"KYTHIRA_NODE_TLS_CA", "/etc/kythira/ca.pem"},
        {"KYTHIRA_REDIS_ALLOW_ANONYMOUS", "true"},
        {"KYTHIRA_CACHE_MAX_DISK_BYTES", "1073741824"},
    };
}

auto composite(std::map<std::string, std::string> vars) -> kythira::redis_node::node_options {
    return kythira::redis_node::from_env(
        kythira::redis_node::composite_env(lookup(std::move(vars))));
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_node_settings_fill_in) {
    const auto o = composite(node_vars());
    BOOST_TEST(kythira::host_node_id_text(o._node_id) == "2");
    BOOST_TEST(o._peers.size() == 3U);
    BOOST_TEST(o._peers.at(o._node_id) == "https://10.0.0.2:7400");
    BOOST_TEST(o._raft_port == 7400);
    // Raft is the node's mutually authenticated listener: the plaintext
    // guard is off, even bound off loopback.
    BOOST_TEST(o._bind_address == "0.0.0.0");
    BOOST_TEST(o._allow_plaintext_raft);
    BOOST_TEST(o._cache._data_dir.string() == "/var/lib/kythira/redis");
    BOOST_TEST((o._serializer == kythira::redis_node::wire_serializer::cbor));
    // The RESP TLS certificate is there for a TLS listener, if one is
    // asked for; none is by default.
    BOOST_TEST(o._gateway._tls_cert_path == "/etc/kythira/node.pem");
    BOOST_TEST(o._gateway._tls_listen.empty());
    // Every peer's gateway on its Raft host and this node's RESP port.
    BOOST_TEST(o._peer_gateways.at(o._node_id) == "10.0.0.2:6379");
}

BOOST_AUTO_TEST_CASE(the_module_variables_win_but_not_the_data_directory_or_wire) {
    auto vars = node_vars();
    vars["KYTHIRA_PEERS"] = "1=http://r1:7000,2=http://r2:7000";
    vars["KYTHIRA_CACHE_DATA_DIR"] = "/somewhere/else";
    vars["KYTHIRA_WIRE_SERIALIZER"] = "json";
    vars["KYTHIRA_REDIS_TLS_LISTEN"] = "0.0.0.0:6380";
    vars["KYTHIRA_REDIS_TLS_CERT"] = "/etc/redis/api.pem";
    vars["KYTHIRA_REDIS_TLS_KEY"] = "/etc/redis/api.key";
    const auto o = composite(vars);
    BOOST_TEST(o._peers.size() == 2U);
    BOOST_TEST(o._cache._data_dir.string() == "/var/lib/kythira/redis");
    BOOST_TEST((o._serializer == kythira::redis_node::wire_serializer::cbor));
    BOOST_TEST(o._gateway._tls_cert_path == "/etc/redis/api.pem");
    // Forwarding follows the TLS listener, verified against the node's CA.
    BOOST_TEST(o._gateway._forward_tls);
    BOOST_TEST(o._gateway._forward_tls_ca_path == "/etc/kythira/ca.pem");
}

BOOST_AUTO_TEST_CASE(a_memory_cache_has_no_data_directory) {
    auto vars = node_vars();
    vars.erase("KYTHIRA_CACHE_MAX_DISK_BYTES");
    vars["KYTHIRA_CACHE_PERSISTENCE"] = "memory";
    const auto o = composite(vars);
    BOOST_TEST((o._cache._persistence == kythira::redis_node::cache_persistence::memory));
    BOOST_TEST(o._cache._data_dir.empty());
}

BOOST_AUTO_TEST_CASE(a_plaintext_node_names_http_peers) {
    auto vars = node_vars();
    vars.erase("KYTHIRA_NODE_TLS_CERT");
    vars.erase("KYTHIRA_NODE_TLS_KEY");
    vars.erase("KYTHIRA_NODE_TLS_CA");
    vars["KYTHIRA_NODE_INSECURE_PLAINTEXT"] = "1";
    const auto o = composite(vars);
    for (const auto& [id, url] : o._peers) {
        BOOST_TEST(url.starts_with("http://"));
    }
    BOOST_TEST(o._gateway._tls_cert_path.empty());
}

BOOST_AUTO_TEST_CASE(stand_alone_reads_through_a_lookup_as_from_the_process) {
    // The module's stand-alone lookup: no KYTHIRA_NODE_* fallback, and the
    // plaintext guard as the daemon always had it.
    BOOST_CHECK_THROW(kythira::redis_node::from_env(lookup({
                          {"KYTHIRA_NODE_ID", "1"},
                          {"KYTHIRA_PEERS", "1=http://10.0.0.1:7000"},
                          {"KYTHIRA_REDIS_ALLOW_ANONYMOUS", "true"},
                          {"KYTHIRA_CACHE_PERSISTENCE", "memory"},
                          {"KYTHIRA_NODE_DATA_DIR", "/ignored"},
                      })),
                      std::invalid_argument);
    const auto o = kythira::redis_node::from_env(lookup({
        {"KYTHIRA_NODE_ID", "1"},
        {"KYTHIRA_PEERS", "1=http://127.0.0.1:7000"},
        {"KYTHIRA_RAFT_BIND", "127.0.0.1"},
        {"KYTHIRA_REDIS_ALLOW_ANONYMOUS", "true"},
        {"KYTHIRA_CACHE_PERSISTENCE", "memory"},
    }));
    BOOST_TEST(o._raft_port == 7000);
    BOOST_TEST(!o._allow_plaintext_raft);
}

// ── layer roles (.kiro/specs/redis-general-data-types/ task 15) ─────────────

BOOST_AUTO_TEST_CASE(a_node_that_sets_no_roles_runs_all_three) {
    // Requirement 16.1: the default is today's node.
    const gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    const auto o = from_env();
    BOOST_TEST(o._gateway._layer_roles.to_string() == "gateway,front_end,data");
    BOOST_TEST((o._gateway._layer_roles == kythira::k_redis_all_roles));
}

BOOST_AUTO_TEST_CASE(all_three_roles_named_in_any_order_serve) {
    const gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_ROLES", "data,gateway,front_end", 1);
    const auto o = from_env();
    BOOST_TEST((o._gateway._layer_roles == kythira::k_redis_all_roles));
}

namespace {
// The message from_env() stops the node with for KYTHIRA_REDIS_ROLES=roles.
auto refusal(const char* roles) -> std::string {
    const gateway_env env;
    ::setenv("KYTHIRA_REDIS_ROLES", roles, 1);
    try {
        (void)from_env();
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return {};
}
}  // namespace

BOOST_AUTO_TEST_CASE(a_malformed_role_set_names_the_variable_and_the_fault) {
    for (const char* bad : {"", "gateway,,data", "gateway,gateway", "Gateway", "front-end",
                            "gateway,front_end,data,segments", "segments"}) {
        const auto why = refusal(bad);
        BOOST_TEST_INFO("KYTHIRA_REDIS_ROLES=" << bad);
        BOOST_TEST(why.find("KYTHIRA_REDIS_ROLES") != std::string::npos);
    }
    BOOST_TEST(refusal("").find("empty") != std::string::npos);
    BOOST_TEST(refusal("gateway,gateway").find("twice") != std::string::npos);
    BOOST_TEST(refusal("segments").find("no segments layer") != std::string::npos);
}

// ── every role set serves (tasks 16, 17) ────────────────────────────────────

namespace {
// from_env() for KYTHIRA_REDIS_ROLES=roles with `extra` set, or why not.
auto start_with(const std::string& roles, const std::map<std::string, std::string>& extra)
    -> std::string {
    const gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_ROLES", roles.c_str(), 1);
    for (const auto& [k, v] : extra) {
        ::setenv(k.c_str(), v.c_str(), 1);
    }
    try {
        (void)from_env();
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return {};
}
}  // namespace

BOOST_AUTO_TEST_CASE(every_role_set_serves_with_what_it_needs) {
    const std::map<std::string, std::string> insecure{{"KYTHIRA_NODE_INSECURE_PLAINTEXT", "1"}};
    auto with = [&](std::map<std::string, std::string> more) {
        more.insert(insecure.begin(), insecure.end());
        return more;
    };
    const std::map<std::string, std::string> data_nodes{{"KYTHIRA_REDIS_DATA_NODES", "d-1:6379"}};
    const std::map<std::string, std::string> front_ends{{"KYTHIRA_REDIS_FRONT_ENDS", "fe-1:6380"}};
    for (const std::string roles : {"data", "front_end,data", "gateway,data"}) {
        BOOST_TEST_INFO("KYTHIRA_REDIS_ROLES=" << roles);
        BOOST_TEST(start_with(roles, with(front_ends)) == "");
    }
    BOOST_TEST(start_with("front_end", with(data_nodes)) == "");
    BOOST_TEST(start_with("gateway,front_end", with(data_nodes)) == "");
    // A gateway without the front end needs the front ends to call.
    const auto no_front_ends = start_with("gateway", insecure);
    BOOST_TEST(no_front_ends.find("KYTHIRA_REDIS_FRONT_ENDS") != std::string::npos);
    BOOST_TEST(start_with("gateway", with(front_ends)) == "");
    for (const char* bad : {"fe-1", "fe-1:6380,", "fe-1:port"}) {
        BOOST_TEST_INFO("KYTHIRA_REDIS_FRONT_ENDS=" << bad);
        BOOST_TEST(start_with("gateway", with({{"KYTHIRA_REDIS_FRONT_ENDS", bad}}))
                       .find("KYTHIRA_REDIS_FRONT_ENDS") != std::string::npos);
    }
    // Without insecure plaintext a node apart needs layer TLS (19.4); a
    // co-located node does not.
    const auto plain = start_with("gateway", front_ends);
    BOOST_TEST(plain.find("mutual TLS") != std::string::npos);
    BOOST_TEST(plain.find("kythira://redis/default/") != std::string::npos);
    BOOST_TEST(start_with("gateway,front_end,data", {}) == "");
}

BOOST_AUTO_TEST_CASE(layer_identity_settings) {
    {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        const auto o = from_env();
        BOOST_TEST(o._gateway._layer_cluster == "default");
        BOOST_TEST(!o._gateway._insecure_plaintext);
        BOOST_TEST(o._gateway._drain_timeout.count() == 10000);
        BOOST_TEST(o._gateway._front_ends.empty());
    }
    {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_CLUSTER", "qt", 1);
        BOOST_TEST(from_env()._gateway._layer_cluster == "qt");
        ::setenv("KYTHIRA_REDIS_CLUSTER", "cache-a", 1);
        BOOST_TEST(from_env()._gateway._layer_cluster == "cache-a");
        ::setenv("KYTHIRA_REDIS_CLUSTER", "a/b", 1);
        BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    }
    {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_REDIS_ROLES", "gateway", 1);
        ::setenv("KYTHIRA_REDIS_FRONT_ENDS", "fe-1:6380,[::1]:6381,10.0.0.9:6380", 1);
        ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
        ::setenv("KYTHIRA_REDIS_DRAIN_TIMEOUT_MS", "2500", 1);
        const auto o = from_env();
        const std::vector<std::string> want{"fe-1:6380", "[::1]:6381", "10.0.0.9:6380"};
        BOOST_TEST(o._gateway._front_ends == want, boost::test_tools::per_element());
        BOOST_TEST(o._gateway._insecure_plaintext);
        // Insecure plaintext lets the secret cross plaintext links too.
        BOOST_TEST(o._gateway._allow_plaintext_forwarding);
        BOOST_TEST(o._gateway._drain_timeout.count() == 2500);
    }
}

// ── front ends without data and data nodes (task 16) ───────────────────────

BOOST_AUTO_TEST_CASE(a_data_node_serves_alone) {
    const gateway_env env;
    ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
    ::setenv("KYTHIRA_REDIS_ROLES", "data", 1);
    ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
    const auto o = from_env();
    BOOST_TEST(o._gateway._layer_roles.to_string() == "data");
}

BOOST_AUTO_TEST_CASE(a_front_end_without_data_needs_the_data_nodes) {
    {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_REDIS_ROLES", "gateway,front_end", 1);
        ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
        try {
            (void)from_env();
            BOOST_FAIL("a front end without data started with no data nodes");
        } catch (const std::invalid_argument& e) {
            BOOST_TEST(std::string(e.what()).find("KYTHIRA_REDIS_DATA_NODES") != std::string::npos);
        }
    }
    {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_REDIS_ROLES", "front_end,gateway", 1);
        ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
        ::setenv("KYTHIRA_REDIS_DATA_NODES", "data-1:6379,[::1]:6380,10.0.0.7:6379", 1);
        const auto o = from_env();
        BOOST_TEST(o._gateway._layer_roles.to_string() == "gateway,front_end");
        const std::vector<std::string> want{"data-1:6379", "[::1]:6380", "10.0.0.7:6379"};
        BOOST_TEST(o._gateway._data_nodes == want, boost::test_tools::per_element());
    }
    for (const char* bad : {"data-1", "data-1:6379,", ",data-1:6379", "data-1:port"}) {
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_REDIS_ROLES", "gateway,front_end", 1);
        ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
        ::setenv("KYTHIRA_REDIS_DATA_NODES", bad, 1);
        BOOST_TEST_INFO("KYTHIRA_REDIS_DATA_NODES=" << bad);
        BOOST_CHECK_THROW((void)from_env(), std::invalid_argument);
    }
    {
        // The disk-backed store keeps a value's chunks on the data nodes.
        const gateway_env env;
        ::setenv("KYTHIRA_RAFT_BIND", "127.0.0.1", 1);
        ::setenv("KYTHIRA_REDIS_ROLES", "gateway,front_end", 1);
        ::setenv("KYTHIRA_NODE_INSECURE_PLAINTEXT", "1", 1);
        ::setenv("KYTHIRA_REDIS_DATA_NODES", "data-1:6379", 1);
        ::setenv("KYTHIRA_CACHE_PERSISTENCE", "file", 1);
        ::setenv("KYTHIRA_CACHE_DATA_DIR", "/tmp/kythira-fe-without-data", 1);
        ::setenv("KYTHIRA_CACHE_MAX_DISK_BYTES", "1000000000", 1);
        try {
            (void)from_env();
            BOOST_FAIL("a front end without data started on the disk-backed store");
        } catch (const std::invalid_argument& e) {
            BOOST_TEST(std::string(e.what()).find("KYTHIRA_CACHE_PERSISTENCE") !=
                       std::string::npos);
        }
    }
}

BOOST_AUTO_TEST_CASE(kythira_node_never_fills_in_the_role_set) {
    // Requirement 16.4: roles are per module. A node-wide setting, or
    // another module's, does not reach the Redis module; its own does.
    auto vars = node_vars();
    vars["KYTHIRA_DYNAMODB_ROLES"] = "data,segments";
    vars["KINESIS_ROLES"] = "gateway";
    const auto o = composite(vars);
    BOOST_TEST((o._gateway._layer_roles == kythira::k_redis_all_roles));
    const auto env = kythira::redis_node::composite_env(lookup(node_vars()));
    BOOST_TEST(!env("KYTHIRA_REDIS_ROLES").has_value());
    vars["KYTHIRA_REDIS_ROLES"] = "gateway";
    BOOST_CHECK_THROW(composite(vars), std::invalid_argument);
}
