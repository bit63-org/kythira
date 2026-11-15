// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "kms_config.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <set>
#include <utility>

namespace kythira::kms_node {

namespace {

auto fail(const std::string& what) -> std::invalid_argument {
    return std::invalid_argument("kms: " + what);
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

auto ms_opt(const env_fn& env, const char* name, std::chrono::milliseconds def)
    -> std::chrono::milliseconds {
    const auto v = get_opt(env, name);
    if (v.empty()) {
        return def;
    }
    try {
        std::size_t used = 0;
        const auto n = std::stoull(v, &used);
        if (used != v.size() || v.starts_with('-') || n > 86'400'000ULL * 365) {
            throw std::invalid_argument(v);
        }
        return std::chrono::milliseconds{static_cast<std::int64_t>(n)};
    } catch (const std::exception&) {
        throw fail(std::string(name) + " must be a number of milliseconds, got '" + v + "'");
    }
}

auto u64_opt(const env_fn& env, const char* name, std::uint64_t def) -> std::uint64_t {
    const auto v = get_opt(env, name);
    if (v.empty()) {
        return def;
    }
    try {
        std::size_t used = 0;
        const auto n = std::stoull(v, &used);
        if (used != v.size() || v.starts_with('-')) {
            throw std::invalid_argument(v);
        }
        return n;
    } catch (const std::exception&) {
        throw fail(std::string(name) + " must be a number, got '" + v + "'");
    }
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
    const auto port = v.substr(colon + 1);
    try {
        std::size_t used = 0;
        const auto n = std::stoul(port, &used);
        if (used != port.size() || n > 65535) {
            throw std::invalid_argument(port);
        }
        return {host, static_cast<std::uint16_t>(n)};
    } catch (const std::exception&) {
        throw fail(std::string(name) + " must be host:port, got '" + v + "'");
    }
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
        if (name == "KYTHIRA_KMS_DATA_DIR") {
            auto dir = env("KYTHIRA_NODE_DATA_DIR");
            if (!dir) {
                return std::nullopt;
            }
            return (std::filesystem::path(*dir) / "kms").string();
        }
        if (auto v = env(name)) {
            return v;
        }
        if (name == "KYTHIRA_KMS_TLS_CERT") {
            return env("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "KYTHIRA_KMS_TLS_KEY") {
            return env("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "KYTHIRA_KMS_TLS_CA") {
            return env("KYTHIRA_NODE_TLS_CA");
        }
        if (name == "KYTHIRA_KMS_INSECURE_PLAINTEXT") {
            return env("KYTHIRA_NODE_INSECURE_PLAINTEXT");
        }
        return std::nullopt;
    };
}

auto from_env(const env_fn& env) -> kms_options {
    kms_options o;
    if (auto id = kythira::parse_host_node_id(get_required(env, "KYTHIRA_NODE_ID")); id) {
        o.node_id = std::move(id).value();
    } else {
        throw fail("KYTHIRA_NODE_ID: " + id.error());
    }
    o.data_dir = get_required(env, "KYTHIRA_KMS_DATA_DIR");
    o.api_urls = id_map("KYTHIRA_KMS_API_URLS", get_required(env, "KYTHIRA_KMS_API_URLS"));
    if (!o.api_urls.contains(o.node_id)) {
        throw fail("KYTHIRA_KMS_API_URLS must include this node's own id " +
                   kythira::host_node_id_text(o.node_id));
    }

    o.insecure_plaintext = bool_opt(env, "KYTHIRA_KMS_INSECURE_PLAINTEXT", false);
    const std::string scheme = o.insecure_plaintext ? "http://" : "https://";
    for (const auto& [id, url] : o.api_urls) {
        if (!url.starts_with(scheme)) {
            throw fail("KYTHIRA_KMS_API_URLS: " + url + " is not an " + scheme +
                       " URL (plaintext only with KYTHIRA_KMS_INSECURE_PLAINTEXT)");
        }
    }
    const auto listen = split_listen("KYTHIRA_KMS_API_LISTEN",
                                     get_opt(env, "KYTHIRA_KMS_API_LISTEN", "0.0.0.0:8443"));
    o.api_bind = listen.first;
    o.api_port = listen.second;
    if (!o.insecure_plaintext) {
        o.tls_cert = get_required(env, "KYTHIRA_KMS_TLS_CERT");
        o.tls_key = get_required(env, "KYTHIRA_KMS_TLS_KEY");
        o.client_ca = get_required(env, "KYTHIRA_KMS_TLS_CA");
        if (o.api_urls.size() > 1) {
            o.peer_identities = list_of(get_required(env, "KYTHIRA_KMS_PEER_IDENTITIES"));
            if (o.peer_identities.empty()) {
                throw fail("KYTHIRA_KMS_PEER_IDENTITIES lists no identity");
            }
        }
    }
    o.max_body_bytes = u64_opt(env, "KYTHIRA_KMS_MAX_BODY_BYTES", o.max_body_bytes);
    o.max_connections = u64_opt(env, "KYTHIRA_KMS_MAX_CONNECTIONS", o.max_connections);
    if (o.max_body_bytes == 0 || o.max_connections == 0) {
        throw fail("KYTHIRA_KMS_MAX_BODY_BYTES and KYTHIRA_KMS_MAX_CONNECTIONS must be positive");
    }

    const auto auth = get_opt(env, "KYTHIRA_KMS_AUTH", "iam");
    if (auth == "static") {
        o.auth = kythira::aws_auth::auth_mode::static_keys;
    } else if (auth == "iam") {
        o.auth = kythira::aws_auth::auth_mode::iam;
    } else if (auth == "both") {
        o.auth = kythira::aws_auth::auth_mode::both;
    } else {
        throw fail("KYTHIRA_KMS_AUTH must be static, iam or both, got '" + auth + "'");
    }
    o.static_keys_file = get_opt(env, "KYTHIRA_KMS_STATIC_KEYS_FILE");
    if (o.auth != kythira::aws_auth::auth_mode::iam && o.static_keys_file.empty()) {
        throw fail("KYTHIRA_KMS_AUTH=" + auth + " needs KYTHIRA_KMS_STATIC_KEYS_FILE");
    }
    o.region = get_opt(env, "KYTHIRA_KMS_REGION", o.region);
    o.partition = get_opt(env, "KYTHIRA_KMS_PARTITION", o.partition);

    o.pkcs11 = get_opt(env, "KYTHIRA_KMS_PKCS11", o.pkcs11);
    if (o.pkcs11 != co_located_hsm && !std::filesystem::path(o.pkcs11).is_absolute()) {
        throw fail("KYTHIRA_KMS_PKCS11 must be \"hsm\" or the absolute path of a PKCS#11 library");
    }
    o.pkcs11_identity = get_opt(env, "KYTHIRA_KMS_PKCS11_IDENTITY", o.pkcs11_identity);
    o.token_label = get_opt(env, "KYTHIRA_KMS_TOKEN_LABEL", o.token_label);
    if (o.token_label.size() > 32) {
        throw fail("KYTHIRA_KMS_TOKEN_LABEL is longer than a PKCS#11 label (32 bytes)");
    }
    o.pin_file = get_required(env, "KYTHIRA_KMS_PIN_FILE");
    (void)read_pin(o.pin_file);  // fail at start, not at the first job

    o.job_interval = ms_opt(env, "KYTHIRA_KMS_JOB_INTERVAL_MS", o.job_interval);
    if (o.job_interval.count() == 0) {
        throw fail("KYTHIRA_KMS_JOB_INTERVAL_MS must be at least 1");
    }
    o.grace = ms_opt(env, "KYTHIRA_KMS_GRACE_MS", o.grace);

    o.tick_interval = ms_opt(env, "KYTHIRA_TICK_INTERVAL_MS", o.tick_interval);
    o.election_timeout_min = ms_opt(env, "KYTHIRA_ELECTION_TIMEOUT_MIN_MS", o.election_timeout_min);
    o.election_timeout_max = ms_opt(env, "KYTHIRA_ELECTION_TIMEOUT_MAX_MS", o.election_timeout_max);
    if (o.election_timeout_max <= o.election_timeout_min) {
        throw fail("KYTHIRA_ELECTION_TIMEOUT_MAX_MS must exceed KYTHIRA_ELECTION_TIMEOUT_MIN_MS");
    }
    o.heartbeat_interval = ms_opt(env, "KYTHIRA_HEARTBEAT_INTERVAL_MS", o.heartbeat_interval);
    o.rpc_timeout = ms_opt(env, "KYTHIRA_RPC_TIMEOUT_MS", o.rpc_timeout);
    o.propose_timeout = ms_opt(env, "KYTHIRA_KMS_PROPOSE_TIMEOUT_MS", o.propose_timeout);
    if (o.propose_timeout.count() == 0) {
        throw fail("KYTHIRA_KMS_PROPOSE_TIMEOUT_MS must be positive");
    }

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

auto read_pin(const std::filesystem::path& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw fail("cannot read the PIN file " + path.string());
    }
    std::string pin{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
        pin.pop_back();
    }
    if (pin.empty()) {
        throw fail("the PIN file " + path.string() + " is empty");
    }
    return pin;
}

auto usage_text() -> std::string_view {
    return R"(The KMS module (KYTHIRA_SERVICES=kms):

  KYTHIRA_NODE_ID                    this node's id (required)
  KYTHIRA_KMS_API_URLS               id=https://host:port for every member, this
                                     node included (required): the catalog's
                                     voters
  KYTHIRA_KMS_DATA_DIR               state (the node's kms/ in kythira_node)
  KYTHIRA_KMS_API_LISTEN             host:port of the KMS API (0.0.0.0:8443): AWS
                                     clients, and members forwarding to the
                                     leader
  KYTHIRA_KMS_TLS_CERT, _TLS_KEY     the listener's certificate and key, also
                                     presented when forwarding (default: the
                                     node's KYTHIRA_NODE_TLS_CERT and _KEY)
  KYTHIRA_KMS_TLS_CA                 the CA the members' certificates chain to
                                     (default: KYTHIRA_NODE_TLS_CA)
  KYTHIRA_KMS_PEER_IDENTITIES        the members' certificate URI or DNS SANs,
                                     comma-separated: who may forward
                                     (required with more than one member)
  KYTHIRA_KMS_INSECURE_PLAINTEXT     plaintext listener and forwarding, for tests
                                     only (default: KYTHIRA_NODE_INSECURE_PLAINTEXT)
  KYTHIRA_KMS_MAX_BODY_BYTES         largest request body (1048576)
  KYTHIRA_KMS_MAX_CONNECTIONS        concurrent connections (256)
  KYTHIRA_KMS_AUTH                   static|iam|both (iam): iam and both need the
                                     IAM module co-located; with static the
                                     static roles decide alone, and key policies
                                     and grants are not evaluated
  KYTHIRA_KMS_STATIC_KEYS_FILE       the static keys (access-key-id secret account
                                     name role per line), for static and both
  KYTHIRA_KMS_REGION                 the region in key ARNs and SigV4 (us-east-1)
  KYTHIRA_KMS_PARTITION              the partition in ARNs (aws)
  KYTHIRA_KMS_PKCS11                 where backing keys live: hsm (default) for
                                     the co-located virtual HSM, or the
                                     absolute path of a PKCS#11 library
  KYTHIRA_KMS_PKCS11_IDENTITY        the identity the KMS acts as on the
                                     co-located HSM, which its catalog must
                                     bind to the token (kms)
  KYTHIRA_KMS_TOKEN_LABEL            the token holding backing keys (kms)
  KYTHIRA_KMS_PIN_FILE               a file holding the token's user PIN
                                     (required)
  KYTHIRA_KMS_JOB_INTERVAL_MS        the leader's key jobs: settling, rotation,
                                     deletion, orphan sweep (10000)
  KYTHIRA_KMS_GRACE_MS               a Creating key or an unaccounted backing
                                     key is left this long first (300000)
  KYTHIRA_KMS_PROPOSE_TIMEOUT_MS     one proposal or read barrier (5000)
  KYTHIRA_KMS_ELECTION_TIMEOUT_MIN_MS and the other KYTHIRA_KMS_ Raft tuning
                                     names override the node's KYTHIRA_ ones
  KYTHIRA_LOG_LEVEL                  trace|debug|info|warning|error|critical
)";
}

}  // namespace kythira::kms_node
