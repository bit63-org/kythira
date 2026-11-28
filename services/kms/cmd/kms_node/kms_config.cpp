// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "kms_config.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
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

/// `account=value,...` with each account twelve digits.
auto per_account(const std::string& name, const std::string& text, const std::string& shape)
    -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    for (const auto& item : list_of(text)) {
        const auto eq = item.find('=');
        const auto account = item.substr(0, eq);
        const bool digits =
            account.size() == 12 && account.find_first_not_of("0123456789") == std::string::npos;
        if (eq == std::string::npos || !digits || eq + 1 == item.size()) {
            throw fail(name + ": expected account=" + shape + ", got '" + item + "'");
        }
        out[account] = item.substr(eq + 1);
    }
    return out;
}

auto quotas_of(const std::string& name, const std::string& text) -> kythira::kms::shared_quotas {
    const auto q = kythira::kms::parse_shared_quotas(text);
    if (!q) {
        throw fail(name + ": expected symmetric:rsa:ecc requests per second, got '" + text + "'");
    }
    return *q;
}

/// "keys:aliases", each a positive count.
auto limits_of(const std::string& text) -> std::optional<kythira::kms::account_limits> {
    const auto colon = text.find(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    const auto count = [](const std::string& t) -> std::uint32_t {
        if (t.empty() || t.size() > 9 || t.find_first_not_of("0123456789") != std::string::npos) {
            return 0;
        }
        return static_cast<std::uint32_t>(std::stoul(t));
    };
    kythira::kms::account_limits l;
    l.max_keys = count(text.substr(0, colon));
    l.max_aliases = count(text.substr(colon + 1));
    if (l.max_keys == 0 || l.max_aliases == 0) {
        return std::nullopt;
    }
    return l;
}

/// KYTHIRA_KMS_ROLES (Requirement 2.1 and 2.4): all three when unset.
auto roles_of(const std::string& text) -> kythira::layers::role_set {
    if (text.empty()) {
        return kms_roles;
    }
    kythira::layers::role_set roles;
    try {
        roles = kythira::layers::role_set::parse(text);
    } catch (const std::invalid_argument& e) {
        throw fail(std::string("KYTHIRA_KMS_ROLES: ") + e.what());
    }
    if (!kms_roles.contains(roles)) {
        throw fail("KYTHIRA_KMS_ROLES=" + text +
                   ": the KMS's layers are gateway, front_end and data (segments is Kinesis's)");
    }
    if (roles.empty()) {
        throw fail("KYTHIRA_KMS_ROLES is empty: name at least one of gateway, front_end, data");
    }
    return roles;
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
    o.roles = roles_of(get_opt(env, "KYTHIRA_KMS_ROLES"));
    const bool data = o.roles.has(kythira::layers::role::data);
    const bool front_end = o.roles.has(kythira::layers::role::front_end);
    const bool gateway = o.roles.has(kythira::layers::role::gateway);
    // A gateway alone reaches no catalog: only front ends and data nodes
    // need the data nodes' URLs.
    if (data || front_end) {
        o.api_urls = id_map("KYTHIRA_KMS_API_URLS", get_required(env, "KYTHIRA_KMS_API_URLS"));
    } else if (const auto urls = get_opt(env, "KYTHIRA_KMS_API_URLS"); !urls.empty()) {
        o.api_urls = id_map("KYTHIRA_KMS_API_URLS", urls);
    }
    if (data && !o.api_urls.contains(o.node_id)) {
        throw fail("KYTHIRA_KMS_API_URLS must include this node's own id " +
                   kythira::host_node_id_text(o.node_id));
    }
    if (!data && o.api_urls.contains(o.node_id)) {
        // Requirement 2.2: only data nodes are catalog members.
        throw fail("KYTHIRA_KMS_API_URLS lists this node's id " +
                   kythira::host_node_id_text(o.node_id) +
                   ", but a node without the data role is not a catalog member; list the data "
                   "nodes only");
    }

    // Task 6: the founding voters; a data node outside them joins.
    if (const auto v = get_opt(env, "KYTHIRA_KMS_VOTERS"); !v.empty()) {
        for (const auto& item : list_of(v)) {
            auto id = kythira::parse_host_peer_node_id(item);
            if (!id) {
                throw fail("KYTHIRA_KMS_VOTERS: " + id.error());
            }
            if (std::find(o.voters.begin(), o.voters.end(), *id) == o.voters.end()) {
                o.voters.push_back(std::move(id).value());
            }
        }
        if (o.voters.empty()) {
            throw fail("KYTHIRA_KMS_VOTERS is empty");
        }
    } else {
        for (const auto& [id, url] : o.api_urls) {
            o.voters.push_back(id);
        }
    }
    o.discard_catalog = bool_opt(env, "KYTHIRA_KMS_DISCARD_CATALOG", false);

    o.insecure_plaintext = bool_opt(env, "KYTHIRA_KMS_INSECURE_PLAINTEXT", false);
    const std::string scheme = o.insecure_plaintext ? "http://" : "https://";
    for (const auto& [id, url] : o.api_urls) {
        if (!url.starts_with(scheme)) {
            throw fail("KYTHIRA_KMS_API_URLS: " + url + " is not an " + scheme +
                       " URL (plaintext only with KYTHIRA_KMS_INSECURE_PLAINTEXT)");
        }
    }
    // Task 4: the front ends a gateway hands calls to and front ends count
    // to share the quotas.
    if (const auto fe = get_opt(env, "KYTHIRA_KMS_FRONT_END_URLS"); !fe.empty()) {
        o.front_end_urls = id_map("KYTHIRA_KMS_FRONT_END_URLS", fe);
        for (const auto& [id, url] : o.front_end_urls) {
            if (!url.starts_with(scheme)) {
                throw fail("KYTHIRA_KMS_FRONT_END_URLS: " + url + " is not an " + scheme +
                           " URL (plaintext only with KYTHIRA_KMS_INSECURE_PLAINTEXT)");
            }
        }
        if (front_end && !o.front_end_urls.contains(o.node_id)) {
            throw fail("KYTHIRA_KMS_FRONT_END_URLS must include this front end's own id " +
                       kythira::host_node_id_text(o.node_id) +
                       ": the list is every front end, and the live ones share the quotas");
        }
        if (!front_end && o.front_end_urls.contains(o.node_id)) {
            throw fail("KYTHIRA_KMS_FRONT_END_URLS lists this node's id " +
                       kythira::host_node_id_text(o.node_id) +
                       ", but it runs no front end; list the front ends only");
        }
    } else if (gateway && !front_end) {
        throw fail("KYTHIRA_KMS_ROLES=" + o.roles.to_string() +
                   " needs KYTHIRA_KMS_FRONT_END_URLS: a gateway without its own front end "
                   "hands every call to one of those");
    }
    o.front_end_probe = ms_opt(env, "KYTHIRA_KMS_FRONT_END_PROBE_MS", o.front_end_probe);
    if (o.front_end_probe.count() == 0) {
        throw fail("KYTHIRA_KMS_FRONT_END_PROBE_MS must be at least 1");
    }
    o.cluster = get_opt(env, "KYTHIRA_KMS_CLUSTER", get_opt(env, "KYTHIRA_CLUSTER", o.cluster));
    if (!kythira::layers::valid_identity_part(o.cluster)) {
        throw fail("KYTHIRA_KMS_CLUSTER: '" + o.cluster +
                   "' cannot be part of a layer identity (letters, digits, '-', '_', '.')");
    }
    const auto listen = split_listen("KYTHIRA_KMS_API_LISTEN",
                                     get_opt(env, "KYTHIRA_KMS_API_LISTEN", "0.0.0.0:8443"));
    o.api_bind = listen.first;
    o.api_port = listen.second;
    if (!o.insecure_plaintext) {
        o.tls_cert = get_required(env, "KYTHIRA_KMS_TLS_CERT");
        o.tls_key = get_required(env, "KYTHIRA_KMS_TLS_KEY");
        o.client_ca = get_required(env, "KYTHIRA_KMS_TLS_CA");
        o.peer_identities = list_of(get_opt(env, "KYTHIRA_KMS_PEER_IDENTITIES"));
        if (data && o.api_urls.size() > 1 && o.peer_identities.empty()) {
            throw fail(
                "missing required env var KYTHIRA_KMS_PEER_IDENTITIES (more than one "
                "member)");
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
    if (const auto trusted = get_opt(env, "KYTHIRA_KMS_TRUSTED_SERVICES"); !trusted.empty()) {
        o.trusted_services = list_of(trusted);
        for (const auto& arn : o.trusted_services) {
            if (!arn.starts_with("arn:")) {
                throw fail("KYTHIRA_KMS_TRUSTED_SERVICES lists '" + arn +
                           "', which is not a user or role ARN");
            }
        }
    }
    o.region = get_opt(env, "KYTHIRA_KMS_REGION", o.region);
    o.partition = get_opt(env, "KYTHIRA_KMS_PARTITION", o.partition);
    const auto throttling = get_opt(env, "KYTHIRA_KMS_THROTTLING", "on");
    if (throttling != "on" && throttling != "off") {
        throw fail("KYTHIRA_KMS_THROTTLING must be on or off");
    }
    o.throttling = throttling == "on";
    if (const auto q = get_opt(env, "KYTHIRA_KMS_QUOTAS"); !q.empty()) {
        o.quotas.defaults = quotas_of("KYTHIRA_KMS_QUOTAS", q);
    }
    for (const auto& [account, q] :
         per_account("KYTHIRA_KMS_ACCOUNT_QUOTAS", get_opt(env, "KYTHIRA_KMS_ACCOUNT_QUOTAS"),
                     "symmetric:rsa:ecc")) {
        o.quotas.accounts[account] = quotas_of("KYTHIRA_KMS_ACCOUNT_QUOTAS", q);
    }
    for (const auto& [account, l] :
         per_account("KYTHIRA_KMS_ACCOUNT_LIMITS", get_opt(env, "KYTHIRA_KMS_ACCOUNT_LIMITS"),
                     "keys:aliases")) {
        const auto limits = limits_of(l);
        if (!limits) {
            throw fail("KYTHIRA_KMS_ACCOUNT_LIMITS: expected account=keys:aliases, got '" +
                       account + "=" + l + "'");
        }
        o.account_limits[account] = *limits;
    }
    o.audit = get_opt(env, "KYTHIRA_KMS_AUDIT", o.audit);
    if (o.audit != "stderr" && o.audit != "off" &&
        (!o.audit.starts_with("file:") || o.audit.size() == 5)) {
        throw fail("KYTHIRA_KMS_AUDIT must be stderr, off or file:<path>");
    }

    o.pkcs11 = get_opt(env, "KYTHIRA_KMS_PKCS11", o.pkcs11);
    if (o.pkcs11 != co_located_hsm && !std::filesystem::path(o.pkcs11).is_absolute()) {
        throw fail("KYTHIRA_KMS_PKCS11 must be \"hsm\" or the absolute path of a PKCS#11 library");
    }
    o.pkcs11_identity = get_opt(env, "KYTHIRA_KMS_PKCS11_IDENTITY", o.pkcs11_identity);
    o.token_label = get_opt(env, "KYTHIRA_KMS_TOKEN_LABEL", o.token_label);
    if (o.token_label.size() > 32) {
        throw fail("KYTHIRA_KMS_TOKEN_LABEL is longer than a PKCS#11 label (32 bytes)");
    }
    if (front_end) {
        o.pin_file = get_required(env, "KYTHIRA_KMS_PIN_FILE");
        (void)read_pin(o.pin_file);  // fail at start, not at the first job
    } else if (!get_opt(env, "KYTHIRA_KMS_PIN_FILE").empty()) {
        // Requirement 2.3: HSM credentials live in the front-end layer only.
        throw fail(
            "KYTHIRA_KMS_PIN_FILE is set, but a node without the front_end role holds no "
            "HSM PIN; unset it");
    }

    o.job_interval = ms_opt(env, "KYTHIRA_KMS_JOB_INTERVAL_MS", o.job_interval);
    if (o.job_interval.count() == 0) {
        throw fail("KYTHIRA_KMS_JOB_INTERVAL_MS must be at least 1");
    }
    o.job_lease =
        ms_opt(env, "KYTHIRA_KMS_JOB_LEASE_MS", std::max(o.job_lease, 3 * o.job_interval));
    if (o.job_lease <= o.job_interval) {
        throw fail("KYTHIRA_KMS_JOB_LEASE_MS must be longer than KYTHIRA_KMS_JOB_INTERVAL_MS");
    }
    o.grace = ms_opt(env, "KYTHIRA_KMS_GRACE_MS", o.grace);
    o.bounded_staleness = ms_opt(env, "KYTHIRA_KMS_BOUNDED_STALENESS_MS", o.bounded_staleness);
    if (o.bounded_staleness.count() != 0 && !front_end) {
        throw fail(
            "KYTHIRA_KMS_BOUNDED_STALENESS_MS is set, but only a front end reads key "
            "metadata for requests; unset it on a node without the front_end role");
    }

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
  KYTHIRA_KMS_ROLES                  the layers this node runs, comma-separated
                                     from gateway, front_end, data (all three):
                                     only data nodes are catalog members, only
                                     front ends hold the HSM PIN and run the
                                     key jobs, and a gateway without front_end
                                     hands each call it authenticated to a
                                     front end on another node
  KYTHIRA_KMS_API_URLS               id=https://host:port for every catalog
                                     member (data node), this node included
                                     exactly when it runs data (required on
                                     data nodes and front ends): the catalog's
                                     voters, and where a front end without
                                     data reads and proposes
  KYTHIRA_KMS_FRONT_END_URLS         id=https://host:port for every front end,
                                     this node included exactly when it runs
                                     front_end: where a gateway without
                                     front_end hands calls (required there),
                                     and on a front end who shares the quotas
                                     (the live ones; unset: every catalog
                                     member, the co-located layout)
  KYTHIRA_KMS_FRONT_END_PROBE_MS     how often each front end's health is
                                     asked; three missed answers and it is not
                                     live (1000)
  KYTHIRA_KMS_CLUSTER                the cluster in this KMS's layer identities,
                                     kythira://kms/<cluster>/<id>?roles=...
                                     (default: KYTHIRA_CLUSTER, else default)
  KYTHIRA_KMS_DATA_DIR               state (the node's kms/ in kythira_node)
  KYTHIRA_KMS_API_LISTEN             host:port of the KMS API (0.0.0.0:8443): AWS
                                     clients, and members forwarding to the
                                     leader
  KYTHIRA_KMS_TLS_CERT, _TLS_KEY     the listener's certificate and key, also
                                     presented when forwarding (default: the
                                     node's KYTHIRA_NODE_TLS_CERT and _KEY)
  KYTHIRA_KMS_TLS_CA                 the CA the members' certificates chain to
                                     (default: KYTHIRA_NODE_TLS_CA)
  KYTHIRA_KMS_PEER_IDENTITIES        the nodes' certificate URI or DNS SANs,
                                     comma-separated, trusted as every layer:
                                     who may forward, use the catalog API and
                                     hand front ends calls (required on a data
                                     node with more than one member). A
                                     certificate holding a KMS layer identity
                                     needs no entry and is held to its roles:
                                     data for forwarding, front_end or data
                                     for the catalog API, gateway for calls
  KYTHIRA_KMS_INSECURE_PLAINTEXT     plaintext listener and forwarding, for tests
                                     only (default: KYTHIRA_NODE_INSECURE_PLAINTEXT)
  KYTHIRA_KMS_MAX_BODY_BYTES         largest request body (1048576)
  KYTHIRA_KMS_MAX_CONNECTIONS        concurrent connections (256)
  KYTHIRA_KMS_AUTH                   static|iam|both (iam): iam and both need the
                                     IAM module co-located; with static the
                                     static roles decide alone, and key policies
                                     and grants are not evaluated (a co-located
                                     consumer's own calls as an account's root
                                     are allowed on that account's keys)
  KYTHIRA_KMS_STATIC_KEYS_FILE       the static keys (access-key-id secret account
                                     name role per line), for static and both
  KYTHIRA_KMS_TRUSTED_SERVICES       user or role ARNs, comma-separated, of
                                     consuming services on other clusters that
                                     may forward the caller they serve (with
                                     kms:ViaService); none by default
  KYTHIRA_KMS_REGION                 the region in key ARNs and SigV4 (us-east-1)
  KYTHIRA_KMS_PARTITION              the partition in ARNs (aws)
  KYTHIRA_KMS_THROTTLING             on|off (on): AWS's per-account request
                                     quotas, answering ThrottlingException
  KYTHIRA_KMS_QUOTAS                 symmetric:rsa:ecc shared cryptographic
                                     requests per second per account
                                     (100000:1000:1000, AWS's in us-east-1)
  KYTHIRA_KMS_ACCOUNT_QUOTAS         account=symmetric:rsa:ecc,... per account
  KYTHIRA_KMS_ACCOUNT_LIMITS         account=keys:aliases,... raised (or
                                     lowered) key and alias counts
                                     (AWS's 100000 keys, 50000 aliases)
  KYTHIRA_KMS_AUDIT                  where request records (CloudTrail-shaped
                                     JSON lines) go: stderr (default), off, or
                                     file:<path>
  KYTHIRA_KMS_PKCS11                 where backing keys live: hsm (default) for
                                     the co-located virtual HSM, or the
                                     absolute path of a PKCS#11 library
  KYTHIRA_KMS_PKCS11_IDENTITY        the identity the KMS acts as on the
                                     co-located HSM, which its catalog must
                                     bind to the token (kms)
  KYTHIRA_KMS_TOKEN_LABEL            the token holding backing keys (kms)
  KYTHIRA_KMS_PIN_FILE               a file holding the token's user PIN
                                     (required on a front end, refused
                                     elsewhere)
  KYTHIRA_KMS_JOB_INTERVAL_MS        the key jobs, on the front end holding
                                     the job lease: settling, rotation,
                                     deletion, orphan sweep (10000)
  KYTHIRA_KMS_JOB_LEASE_MS           how long the job lease lasts unrenewed
                                     (the larger of 30000 and three intervals)
  KYTHIRA_KMS_GRACE_MS               a Creating key or an unaccounted backing
                                     key is left this long first (300000)
  KYTHIRA_KMS_BOUNDED_STALENESS_MS   0 (default): every request reads key
                                     metadata at a read-index point of the
                                     catalog; else a point at most this old
                                     may serve (AWS's eventual consistency)
  KYTHIRA_KMS_VOTERS                 the catalog's founding voters, ids
                                     comma-separated (the data nodes in
                                     KYTHIRA_KMS_API_URLS); a data node not
                                     listed joins when an evacuation adds it
                                     (POST /v1/kms/membership/evacuate)
  KYTHIRA_KMS_DISCARD_CATALOG        true: a node starting without the data
                                     role discards a catalog replica it still
                                     holds instead of refusing to start (false)
  KYTHIRA_KMS_PROPOSE_TIMEOUT_MS     one proposal or read barrier (5000)
  KYTHIRA_KMS_ELECTION_TIMEOUT_MIN_MS and the other KYTHIRA_KMS_ Raft tuning
                                     names override the node's KYTHIRA_ ones
  KYTHIRA_LOG_LEVEL                  trace|debug|info|warning|error|critical
)";
}

}  // namespace kythira::kms_node
