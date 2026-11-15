// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hsm_config.hpp"

#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>

namespace kythira::hsm_node {

namespace {

auto fail(const std::string& what) -> std::invalid_argument {
    return std::invalid_argument("hsm: " + what);
}

auto get_opt(const env_fn& env, const char* name, const std::string& def = {}) -> std::string {
    auto v = env(name);
    return v && !v->empty() ? *v : def;
}

auto get_required(const env_fn& env, const char* name) -> std::string {
    auto v = get_opt(env, name);
    if (v.empty()) {
        throw fail(std::string("missing required env var ") + name);
    }
    return v;
}

auto to_u64(const char* name, const std::string& v) -> std::uint64_t {
    try {
        std::size_t used = 0;
        const auto n = std::stoull(v, &used);
        if (used != v.size() || v.starts_with('-')) {
            throw std::invalid_argument(v);
        }
        return n;
    } catch (const std::exception&) {
        throw fail(std::string(name) + " must be a non-negative integer, got '" + v + "'");
    }
}

auto u64_opt(const env_fn& env, const char* name, std::uint64_t def) -> std::uint64_t {
    const auto v = get_opt(env, name);
    return v.empty() ? def : to_u64(name, v);
}

auto ms_opt(const env_fn& env, const char* name, std::chrono::milliseconds def)
    -> std::chrono::milliseconds {
    return std::chrono::milliseconds{
        static_cast<std::int64_t>(u64_opt(env, name, static_cast<std::uint64_t>(def.count())))};
}

auto bool_opt(const env_fn& env, const char* name, bool def) -> bool {
    const auto v = get_opt(env, name);
    if (v.empty()) {
        return def;
    }
    if (v == "1" || v == "true" || v == "yes" || v == "on") {
        return true;
    }
    if (v == "0" || v == "false" || v == "no" || v == "off") {
        return false;
    }
    throw fail(std::string(name) + " must be true or false, got '" + v + "'");
}

auto port_of(const char* name, const std::string& v) -> std::uint16_t {
    const auto n = to_u64(name, v);
    if (n > 65535) {
        throw fail(std::string(name) + " must be a port number, got '" + v + "'");
    }
    return static_cast<std::uint16_t>(n);
}

/// `host:port` or `[v6]:port`; port 0 picks a free one (tests).
auto split_listen(const char* name, const std::string& v) -> std::pair<std::string, std::uint16_t> {
    const auto colon = v.rfind(':');
    if (colon == std::string::npos || colon == 0) {
        throw fail(std::string(name) + " must be host:port, got '" + v + "'");
    }
    std::string host = v.substr(0, colon);
    if (host.starts_with('[') && host.ends_with(']')) {
        host = host.substr(1, host.size() - 2);
    }
    return {host, port_of(name, v.substr(colon + 1))};
}

/// `a,b,c` without empty items or surrounding spaces.
auto list_of(const std::string& text) -> std::set<std::string> {
    std::set<std::string> out;
    std::string tok;
    for (const char c : text + ',') {
        if (c != ',') {
            tok += c;
            continue;
        }
        const auto first = tok.find_first_not_of(' ');
        if (first != std::string::npos) {
            out.insert(tok.substr(first, tok.find_last_not_of(' ') - first + 1));
        }
        tok.clear();
    }
    return out;
}

/// `id=url,id=url,...`
auto id_map(const char* name, const std::string& text)
    -> std::map<kythira::host_node_id, std::string> {
    std::map<kythira::host_node_id, std::string> out;
    std::string tok;
    for (const char c : text + ',') {
        if (c != ',') {
            if (c != ' ') {
                tok += c;
            }
            continue;
        }
        if (tok.empty()) {
            continue;
        }
        const auto eq = tok.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == tok.size()) {
            throw fail(std::string(name) + " expects id=url[,id=url...], got '" + tok + "'");
        }
        auto id = kythira::parse_host_peer_node_id(tok.substr(0, eq));
        if (!id) {
            throw fail(std::string(name) + ": " + id.error());
        }
        out[std::move(id).value()] = tok.substr(eq + 1);
        tok.clear();
    }
    if (out.empty()) {
        throw fail(std::string(name) + " is empty");
    }
    return out;
}

}  // namespace

auto composite_env(env_fn env) -> env_fn {
    return [env = std::move(env)](std::string_view name) -> std::optional<std::string> {
        if (name == "KYTHIRA_HSM_DATA_DIR") {
            auto dir = env("KYTHIRA_NODE_DATA_DIR");
            if (!dir) {
                return std::nullopt;
            }
            return (std::filesystem::path(*dir) / "hsm").string();
        }
        if (auto v = env(name); v && !v->empty()) {
            return v;
        }
        if (name == "KYTHIRA_HSM_TLS_CERT") {
            return env("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "KYTHIRA_HSM_TLS_KEY") {
            return env("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "KYTHIRA_HSM_CLIENT_CA") {
            return env("KYTHIRA_NODE_TLS_CA");
        }
        if (name == "KYTHIRA_HSM_INSECURE_PLAINTEXT") {
            return env("KYTHIRA_NODE_INSECURE_PLAINTEXT");
        }
        return std::nullopt;
    };
}

auto from_env(const env_fn& env) -> hsm_options {
    hsm_options o;
    if (auto id = kythira::parse_host_node_id(get_required(env, "KYTHIRA_NODE_ID")); id) {
        o.node_id = std::move(id).value();
    } else {
        throw fail("KYTHIRA_NODE_ID: " + id.error());
    }
    o.data_dir = get_required(env, "KYTHIRA_HSM_DATA_DIR");
    o.share_sealer = env("KYTHIRA_HSM_SHARE_SEALER").value_or("file");
    if (o.share_sealer != "file") {
        throw fail("KYTHIRA_HSM_SHARE_SEALER must be \"file\"");
    }
    o.share_key_file =
        env("KYTHIRA_HSM_SHARE_KEY_FILE").value_or((o.data_dir / "share.key").string());

    o.insecure_plaintext = bool_opt(env, "KYTHIRA_HSM_INSECURE_PLAINTEXT", false);
    o.api_urls = id_map("KYTHIRA_HSM_API_URLS", get_required(env, "KYTHIRA_HSM_API_URLS"));
    if (!o.api_urls.contains(o.node_id)) {
        throw fail("KYTHIRA_HSM_API_URLS must include this node's own id " +
                   kythira::host_node_id_text(o.node_id));
    }
    const std::string scheme = o.insecure_plaintext ? "http://" : "https://";
    for (const auto& [id, url] : o.api_urls) {
        if (!url.starts_with(scheme)) {
            throw fail("KYTHIRA_HSM_API_URLS: " + url + " is not an " + scheme +
                       " URL (plaintext only with KYTHIRA_HSM_INSECURE_PLAINTEXT)");
        }
    }
    const auto listen = split_listen("KYTHIRA_HSM_API_LISTEN",
                                     get_opt(env, "KYTHIRA_HSM_API_LISTEN", "0.0.0.0:9443"));
    o.api_bind = listen.first;
    o.api_port = listen.second;
    if (!o.insecure_plaintext) {
        o.tls_cert = get_required(env, "KYTHIRA_HSM_TLS_CERT");
        o.tls_key = get_required(env, "KYTHIRA_HSM_TLS_KEY");
        o.client_ca = get_required(env, "KYTHIRA_HSM_CLIENT_CA");
        o.peer_identities = list_of(get_required(env, "KYTHIRA_HSM_PEER_IDENTITIES"));
        if (o.peer_identities.empty()) {
            throw fail("KYTHIRA_HSM_PEER_IDENTITIES lists no identity");
        }
    }
    o.operators = list_of(get_required(env, "KYTHIRA_HSM_OPERATORS"));
    if (o.operators.empty()) {
        throw fail("KYTHIRA_HSM_OPERATORS lists no identity");
    }
    for (const auto& id : o.operators) {
        if (o.peer_identities.contains(id)) {
            throw fail("KYTHIRA_HSM_OPERATORS and KYTHIRA_HSM_PEER_IDENTITIES share " + id +
                       ": a member's certificate must not administer the HSM");
        }
    }
    o.max_body_bytes = u64_opt(env, "KYTHIRA_HSM_MAX_BODY_BYTES", o.max_body_bytes);
    o.max_connections = u64_opt(env, "KYTHIRA_HSM_MAX_CONNECTIONS", o.max_connections);
    if (o.max_connections == 0) {
        throw fail("KYTHIRA_HSM_MAX_CONNECTIONS must be at least 1");
    }

    o.allow_unlocked_memory = bool_opt(env, "KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY", false);
    o.allow_single_share = bool_opt(env, "KYTHIRA_HSM_ALLOW_SINGLE_SHARE", false);
    o.unseal_timeout = std::chrono::seconds{
        u64_opt(env, "KYTHIRA_HSM_UNSEAL_TIMEOUT_S", static_cast<std::uint64_t>(600))};
    if (o.unseal_timeout.count() == 0) {
        throw fail("KYTHIRA_HSM_UNSEAL_TIMEOUT_S must be at least 1");
    }
    o.max_login_failures = static_cast<std::uint32_t>(
        u64_opt(env, "KYTHIRA_HSM_MAX_LOGIN_FAILURES", o.max_login_failures));
    if (o.max_login_failures == 0) {
        throw fail("KYTHIRA_HSM_MAX_LOGIN_FAILURES must be at least 1");
    }
    o.max_sessions =
        static_cast<std::uint32_t>(u64_opt(env, "KYTHIRA_HSM_MAX_SESSIONS", o.max_sessions));
    if (o.max_sessions == 0) {
        throw fail("KYTHIRA_HSM_MAX_SESSIONS must be at least 1");
    }
    const auto cost = u64_opt(env, "KYTHIRA_HSM_PIN_COST_LOG2", o.pin_log2_n);
    if (cost < 10 || cost > 20) {
        throw fail("KYTHIRA_HSM_PIN_COST_LOG2 must be between 10 and 20");
    }
    o.pin_log2_n = static_cast<std::uint8_t>(cost);

    o.tick_interval = ms_opt(env, "KYTHIRA_TICK_INTERVAL_MS", o.tick_interval);
    o.election_timeout_min = ms_opt(env, "KYTHIRA_ELECTION_TIMEOUT_MIN_MS", o.election_timeout_min);
    o.election_timeout_max = ms_opt(env, "KYTHIRA_ELECTION_TIMEOUT_MAX_MS", o.election_timeout_max);
    if (o.election_timeout_max <= o.election_timeout_min) {
        throw fail("KYTHIRA_ELECTION_TIMEOUT_MAX_MS must exceed KYTHIRA_ELECTION_TIMEOUT_MIN_MS");
    }
    o.heartbeat_interval = ms_opt(env, "KYTHIRA_HEARTBEAT_INTERVAL_MS", o.heartbeat_interval);
    o.rpc_timeout = ms_opt(env, "KYTHIRA_RPC_TIMEOUT_MS", o.rpc_timeout);
    o.propose_timeout = ms_opt(env, "KYTHIRA_HSM_PROPOSE_TIMEOUT_MS", o.propose_timeout);
    if (o.propose_timeout.count() <= 0) {
        throw fail("KYTHIRA_HSM_PROPOSE_TIMEOUT_MS must be positive");
    }
    o.maintenance_interval =
        ms_opt(env, "KYTHIRA_HSM_MAINTENANCE_INTERVAL_MS", o.maintenance_interval);

    static const std::map<std::string, kythira::log_level> levels{
        {"trace", kythira::log_level::trace}, {"debug", kythira::log_level::debug},
        {"info", kythira::log_level::info},   {"warning", kythira::log_level::warning},
        {"error", kythira::log_level::error}, {"critical", kythira::log_level::critical},
    };
    const auto level = get_opt(env, "KYTHIRA_LOG_LEVEL", "info");
    const auto it = levels.find(level);
    if (it == levels.end()) {
        throw fail("KYTHIRA_LOG_LEVEL must be trace, debug, info, warning, error or critical");
    }
    o.log_level = it->second;
    return o;
}

auto usage_text() -> std::string_view {
    return R"(The HSM module (KYTHIRA_SERVICES=hsm):

  KYTHIRA_NODE_ID                    this node's id (required)
  KYTHIRA_HSM_API_URLS               id=https://host:port for every member, this
                                     node included (required): the voters of
                                     every HSM group and where followers forward
  KYTHIRA_HSM_API_LISTEN             host:port of the HSM listener (0.0.0.0:9443)
  KYTHIRA_HSM_TLS_CERT, _TLS_KEY     the listener's certificate and key, also
                                     presented when forwarding (default: the
                                     node's KYTHIRA_NODE_TLS_CERT and _KEY)
  KYTHIRA_HSM_CLIENT_CA              the CA members' and operators' certificates
                                     chain to (default: KYTHIRA_NODE_TLS_CA)
  KYTHIRA_HSM_PEER_IDENTITIES        the members' certificate SANs, comma
                                     separated (required with TLS)
  KYTHIRA_HSM_OPERATORS              the operators' certificate SANs, comma
                                     separated (required); never a member's
  KYTHIRA_HSM_INSECURE_PLAINTEXT     plaintext listener and forwarding, for tests
                                     only (default: KYTHIRA_NODE_INSECURE_PLAINTEXT)
  KYTHIRA_HSM_DATA_DIR               state (the node's hsm/ in kythira_node)
  KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY  start where key memory cannot be locked
                                     (development only; false)
  KYTHIRA_HSM_MAX_LOGIN_FAILURES     failed logins before a PIN locks (10)
  KYTHIRA_HSM_ALLOW_SINGLE_SHARE     permit k = 1 at init and rekey
                                     (development only)
  KYTHIRA_HSM_UNSEAL_TIMEOUT_S       seconds partial operator shares are
                                     held before they are discarded (600)
  KYTHIRA_HSM_SHARE_SEALER           how this node's node-unseal share is
                                     sealed at rest: file (default)
  KYTHIRA_HSM_SHARE_KEY_FILE         the file sealer's key, created 0600 on
                                     first use (data dir/share.key)
  KYTHIRA_HSM_MAX_SESSIONS           open PKCS#11 sessions on this node (4096)
  KYTHIRA_HSM_PIN_COST_LOG2          scrypt cost of new PIN verifiers, 10-20 (15)
  KYTHIRA_HSM_PROPOSE_TIMEOUT_MS     one proposal or read barrier (5000)
  KYTHIRA_HSM_MAINTENANCE_INTERVAL_MS  token group reconciliation (500)
  KYTHIRA_HSM_MAX_BODY_BYTES, KYTHIRA_HSM_MAX_CONNECTIONS  listener limits
  KYTHIRA_HSM_ELECTION_TIMEOUT_MIN_MS and the other KYTHIRA_HSM_ Raft tuning
                                     names override the node's KYTHIRA_ ones
  KYTHIRA_LOG_LEVEL                  trace|debug|info|warning|error|critical
)";
}

}  // namespace kythira::hsm_node
