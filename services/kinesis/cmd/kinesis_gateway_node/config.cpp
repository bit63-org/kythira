// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <kythira/kinesis/kinesis_aws_call.hpp>
#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_compat_profile.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>

#include <raft/net_bind.hpp>
#include <raft/pkcs11_uri.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace kythira::kinesis_node {

namespace {

constexpr std::string_view k_prog = "kinesis_gateway_node: ";

[[noreturn]] void fail(const std::string& message) {
    throw std::invalid_argument(std::string(k_prog) + message);
}

struct reader {
    const env_lookup& _env;

    [[nodiscard]] auto opt(const char* name, const char* def) const -> std::string {
        const char* v = _env(name);
        return v != nullptr ? v : def;
    }

    [[nodiscard]] auto required(const char* name) const -> std::string {
        const char* v = _env(name);
        if (v == nullptr || *v == '\0') {
            fail(std::string("missing required env var ") + name);
        }
        return v;
    }

    [[nodiscard]] auto set(const char* name) const -> bool {
        const char* v = _env(name);
        return v != nullptr && *v != '\0';
    }

    [[nodiscard]] auto flag(const char* name, const char* def) const -> bool {
        const auto v = opt(name, def);
        if (v == "1" || v == "true" || v == "yes" || v == "on") {
            return true;
        }
        if (v == "0" || v == "false" || v == "no" || v == "off") {
            return false;
        }
        fail(std::string(name) + " must be true or false, got '" + v + "'");
    }

    [[nodiscard]] auto u64(const char* name, const char* def) const -> std::uint64_t {
        const auto v = opt(name, def);
        try {
            std::size_t used = 0;
            const auto n = std::stoull(v, &used);
            if (used == v.size() && !v.empty() && v.front() != '-') {
                return n;
            }
        } catch (const std::exception&) {
        }
        fail(std::string(name) + " must be a non-negative integer, got '" + v + "'");
    }

    [[nodiscard]] auto ms(const char* name, const char* def) const -> std::chrono::milliseconds {
        return std::chrono::milliseconds{static_cast<std::int64_t>(u64(name, def))};
    }
};

auto to_peer_id(const char* name, const std::string& v) -> kythira::host_node_id {
    auto id = kythira::parse_host_peer_node_id(v);
    if (!id) {
        fail(std::string(name) + ": " + id.error());
    }
    return std::move(id).value();
}

/// `id=value,id=value,...`
auto parse_id_map(const char* name, const std::string& text)
    -> std::map<kythira::host_node_id, std::string> {
    std::map<kythira::host_node_id, std::string> out;
    std::string tok;
    for (const char c : text + ',') {
        if (c != ',') {
            tok += c;
            continue;
        }
        if (tok.empty()) {
            continue;
        }
        const auto eq = tok.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == tok.size()) {
            fail(std::string(name) + " expects id=value[,id=value...], got token '" + tok + "'");
        }
        out[to_peer_id(name, tok.substr(0, eq))] = tok.substr(eq + 1);
        tok.clear();
    }
    if (out.empty()) {
        fail(std::string(name) + " is empty");
    }
    return out;
}

/// `a,b,c` without empty items.
auto split_list(const std::string& text) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::string tok;
    for (const char c : text + ',') {
        if (c == ',') {
            if (!tok.empty()) {
                out.push_back(tok);
            }
            tok.clear();
        } else {
            tok += c;
        }
    }
    return out;
}

/// The host of `http://host:port/...` or `host:port`, brackets kept on an
/// IPv6 literal.
auto host_of(const std::string& url) -> std::string {
    auto s = url;
    if (const auto p = s.find("://"); p != std::string::npos) {
        s = s.substr(p + 3);
    }
    if (const auto p = s.find('/'); p != std::string::npos) {
        s = s.substr(0, p);
    }
    if (!s.empty() && s.front() == '[') {
        const auto close = s.find(']');
        return close == std::string::npos ? s : s.substr(0, close + 1);
    }
    if (const auto p = s.rfind(':'); p != std::string::npos) {
        s = s.substr(0, p);
    }
    return s;
}

auto read_secret_file(const std::string& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        fail("cannot read KINESIS_FORWARD_SECRET_FILE " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    auto s = buf.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }
    return s;
}

/// `KINESIS_ROLES`, read first: a segment node is held to fewer of the
/// Raft settings. Whether the set can be served is checked once the
/// segment layer is known (`read_segment_layer`).
void read_roles(const reader& r, node_options& o) {
    try {
        o._roles = kythira::layers::role_set::parse(
            r.opt("KINESIS_ROLES", "gateway,front_end,data,segments"));
    } catch (const std::invalid_argument& e) {
        fail("KINESIS_ROLES: " + std::string(e.what()));
    }
}

/// `KINESIS_SEGMENT_NODES` and the role set against it (task 10).
void read_segment_layer(const reader& r, node_options& o) {
    try {
        o._segment_nodes = kythira::parse_segment_nodes(r.opt("KINESIS_SEGMENT_NODES", ""));
    } catch (const std::invalid_argument& e) {
        fail("KINESIS_SEGMENT_NODES: " + std::string(e.what()));
    }
    const auto text = r.opt("KINESIS_ROLES", "gateway,front_end,data,segments");
    // The data layer a front end without `data` reaches (task 7).
    o._data_nodes = split_list(r.opt("KINESIS_DATA_NODES", ""));
    for (const auto& n : o._data_nodes) {
        if (!kinesis::split_host_port(n)) {
            fail("KINESIS_DATA_NODES: '" + n + "' is not host:port");
        }
    }
    // The front ends a gateway without its own hands calls to (task 8).
    o._front_ends = split_list(r.opt("KINESIS_FRONT_ENDS", ""));
    for (const auto& n : o._front_ends) {
        if (!kinesis::split_host_port(n)) {
            fail("KINESIS_FRONT_ENDS: '" + n + "' is not host:port");
        }
    }
    if (const auto gap = unserved_roles(o._roles, !o._segment_nodes.empty(), !o._data_nodes.empty(),
                                        !o._front_ends.empty())) {
        fail("KINESIS_ROLES=" + text + ": " + *gap);
    }
    using kythira::layers::role;
    if (!o._data_nodes.empty() && o._roles.has(role::data)) {
        fail("KINESIS_DATA_NODES is for a front end without the data role; KINESIS_ROLES=" + text +
             " has data, and a data node reaches its peers through KYTHIRA_PEERS");
    }
    if (!o._data_nodes.empty() && !o._roles.has(role::front_end)) {
        fail("KINESIS_DATA_NODES is for a front end; KINESIS_ROLES=" + text +
             " has no front_end, and a gateway reaches the data layer only through the front "
             "ends in KINESIS_FRONT_ENDS");
    }
    if (!o._front_ends.empty() && o._roles.has(role::front_end)) {
        fail("KINESIS_FRONT_ENDS is for a gateway without the front_end role; KINESIS_ROLES=" +
             text + " has front_end, which executes this node's calls itself");
    }
    if (!o._front_ends.empty() && !o._roles.has(role::gateway)) {
        fail("KINESIS_FRONT_ENDS is for a gateway; KINESIS_ROLES=" + text + " has no gateway");
    }
    if (is_front_end_node(o._roles) && o._forward_secret.size() < 16) {
        fail(
            "KINESIS_FORWARD_SECRET (or _FILE) of at least 16 bytes is required without the data "
            "role: the front end signs its data-layer calls with it, and its shard iterators "
            "must verify on every node");
    }
    if (o._roles.has(role::gateway) != o._roles.has(role::front_end) &&
        o._forward_secret.size() < 16) {
        fail(
            "KINESIS_FORWARD_SECRET (or _FILE) of at least 16 bytes is required when the "
            "gateway and front_end roles are on different nodes: it signs the authenticated "
            "call a gateway hands a front end, which a front end accepts only from a gateway");
    }
    o._drain_timeout = r.ms("KINESIS_DRAIN_TIMEOUT_MS", "10000");
    o._discard_replicas = r.flag("KINESIS_DISCARD_REPLICAS", "false");
    if (r.set("KINESIS_VOTERS")) {
        for (const auto& id : split_list(r.required("KINESIS_VOTERS"))) {
            const auto v = to_peer_id("KINESIS_VOTERS", id);
            if (!o._peers.empty() && !o._peers.contains(v)) {
                fail("KINESIS_VOTERS: " + id + " is not in KYTHIRA_PEERS");
            }
            o._voters.push_back(v);
        }
        if (o._voters.empty()) {
            fail("KINESIS_VOTERS is empty");
        }
    } else {
        for (const auto& [id, url] : o._peers) {
            o._voters.push_back(id);
        }
    }
    const auto self = kythira::host_node_id_text(o._node_id);
    if (is_segment_node(o._roles) && !kythira::segment_node_of(o._segment_nodes, self)) {
        fail("KINESIS_ROLES=" + text + ": a segment node must be listed in KINESIS_SEGMENT_NODES " +
             "under its own id " + self);
    }
    const bool uses_layer = !o._roles.has(kythira::layers::role::segments) ||
                            kythira::segment_node_of(o._segment_nodes, self).has_value();
    if (!o._segment_nodes.empty() && uses_layer) {
        // Volume calls are signed like forwarded writes.
        if (o._forward_secret.size() < 16) {
            fail(
                "KINESIS_FORWARD_SECRET (or _FILE) of at least 16 bytes is required with "
                "KINESIS_SEGMENT_NODES: data nodes sign their volume calls with it");
        }
        try {
            (void)volume_assignments(o);
        } catch (const std::invalid_argument& e) {
            fail("KINESIS_SEGMENT_NODES: " + std::string(e.what()));
        }
    }
}

void read_raft_side(const reader& r, node_options& o) {
    if (auto id = kythira::parse_host_node_id(r.required("KYTHIRA_NODE_ID")); id) {
        o._node_id = std::move(id).value();
    } else {
        fail("KYTHIRA_NODE_ID: " + id.error());
    }
    o._bind_address = r.opt("KYTHIRA_RAFT_BIND", "0.0.0.0");
    const auto raft_port = r.u64("KYTHIRA_RAFT_PORT", "7000");
    if (raft_port == 0 || raft_port > 65535) {
        fail("KYTHIRA_RAFT_PORT must be between 1 and 65535");
    }
    o._raft_port = static_cast<std::uint16_t>(raft_port);
    // Raft RPC has no TLS here; off loopback that has to be asked for. A
    // node without the data role (a segment node, a front end) is in no
    // Raft group.
    o._allow_plaintext_raft = r.flag("KYTHIRA_ALLOW_PLAINTEXT_RAFT", "false");
    const bool segment_node = is_segment_node(o._roles);
    const bool voter = o._roles.has(kythira::layers::role::data);
    if (voter && !o._allow_plaintext_raft && !is_loopback_address(o._bind_address)) {
        fail("refusing to serve plaintext, unauthenticated Raft RPC on KYTHIRA_RAFT_BIND=" +
             o._bind_address +
             " (set KYTHIRA_RAFT_BIND to a loopback address, or "
             "KYTHIRA_ALLOW_PLAINTEXT_RAFT=true on a network you trust)");
    }
    // A segment node is not a voter: KYTHIRA_PEERS names the data voters
    // whose volumes it holds. A front end without data needs none
    // (Requirement 2.2): KINESIS_DATA_NODES names its data layer; nor does
    // a gateway without a front end, which reaches only KINESIS_FRONT_ENDS.
    const bool stateless_node = !voter && !segment_node;
    if (!stateless_node || r.set("KYTHIRA_PEERS")) {
        o._peers = parse_id_map("KYTHIRA_PEERS", r.required("KYTHIRA_PEERS"));
    }
    if (voter && !o._peers.contains(o._node_id)) {
        fail("KYTHIRA_PEERS must include this node's own id " +
             kythira::host_node_id_text(o._node_id));
    }
    o._shard_cuts = split_list(r.opt("KYTHIRA_SHARD_CUTS", ""));
    o._tick_interval = r.ms("KYTHIRA_TICK_INTERVAL_MS", "2");
    o._election_timeout_min = r.ms("KYTHIRA_ELECTION_TIMEOUT_MIN_MS", "150");
    o._election_timeout_max = r.ms("KYTHIRA_ELECTION_TIMEOUT_MAX_MS", "300");
    if (o._election_timeout_min > o._election_timeout_max) {
        fail("KYTHIRA_ELECTION_TIMEOUT_MIN_MS exceeds KYTHIRA_ELECTION_TIMEOUT_MAX_MS");
    }
    o._heartbeat_interval = r.ms("KYTHIRA_HEARTBEAT_INTERVAL_MS", "50");
    o._rpc_timeout = r.ms("KYTHIRA_RPC_TIMEOUT_MS", "1000");
    o._policy_interval = r.ms("KYTHIRA_POLICY_INTERVAL_MS", "10000");
    o._executor_stripes = r.u64("KYTHIRA_EXECUTOR_STRIPES", "4");
    static const std::map<std::string, log_level> levels{
        {"trace", log_level::trace}, {"debug", log_level::debug},
        {"info", log_level::info},   {"warning", log_level::warning},
        {"error", log_level::error}, {"critical", log_level::critical},
    };
    const auto level = r.opt("KYTHIRA_LOG_LEVEL", "info");
    const auto it = levels.find(level);
    if (it == levels.end()) {
        fail("KYTHIRA_LOG_LEVEL must be trace|debug|info|warning|error|critical, got '" + level +
             "'");
    }
    o._log_level = it->second;
}

// The tier store's settings (task 10). KINESIS_TIER_BUCKET, _PREFIX and
// _ENDPOINT were KINESIS_TIER_S3_* while S3 was the only provider; those
// spellings still work, and setting both to different values is refused
// rather than one silently winning.
[[nodiscard]] auto tier_setting(const reader& r, const char* name, const char* old_name)
    -> std::string {
    const auto now = r.opt(name, "");
    const auto before = r.opt(old_name, "");
    if (!now.empty() && !before.empty() && now != before) {
        fail(std::string(name) + " and " + old_name + " are both set and differ; set one");
    }
    return now.empty() ? before : now;
}

void read_tier_store(const reader& r, node_options& o) {
    o._tier_provider = r.opt("KINESIS_TIER_PROVIDER", "s3");
    o._tier_bucket = tier_setting(r, "KINESIS_TIER_BUCKET", "KINESIS_TIER_S3_BUCKET");
    o._tier_prefix = tier_setting(r, "KINESIS_TIER_PREFIX", "KINESIS_TIER_S3_PREFIX");
    o._tier_endpoint = tier_setting(r, "KINESIS_TIER_ENDPOINT", "KINESIS_TIER_S3_ENDPOINT");
    o._tier_region = r.opt("KINESIS_TIER_S3_REGION", o._region.c_str());
    const auto& provider = o._tier_provider;
    const auto support = tier_provider_support(provider);
    if (!support._available && support._needs.empty()) {
        fail("KINESIS_TIER_PROVIDER: '" + provider +
             "' is not one of s3, azure-blob, gcs, oci-objectstorage, oss");
    }
    if (o._tier_after_ms > 0 && o._tier_bucket.empty()) {
        fail("KINESIS_TIER_AFTER_HOURS (or _MS) needs KINESIS_TIER_BUCKET");
    }
    if (o._tier_bucket.empty()) {
        return;
    }
    if (!support._available) {
        fail("KINESIS_TIER_BUCKET is set for provider " + provider +
             ", but this kinesis_gateway_node was built without it (needs " +
             std::string(support._needs) + ")");
    }
    if (provider != "s3" && r.set("KINESIS_TIER_S3_REGION")) {
        fail("KINESIS_TIER_S3_REGION applies only to KINESIS_TIER_PROVIDER=s3");
    }
    // OCI and OSS take their endpoint with their credentials
    // (KYTHIRA_OCI_*, KYTHIRA_ALIBABA_*), as everywhere else in Kythira.
    if ((provider == "oci-objectstorage" || provider == "oss") && !o._tier_endpoint.empty()) {
        fail("KINESIS_TIER_ENDPOINT does not apply to " + provider +
             "; its endpoint comes from its own settings");
    }
    if (provider == "azure-blob") {
        o._tier_azure_account = r.opt("KINESIS_TIER_AZURE_ACCOUNT", "");
        if (o._tier_azure_account.empty()) {
            o._tier_azure_account = r.opt("KYTHIRA_AZURE_STORAGE_ACCOUNT", "");
        }
        if (o._tier_azure_account.empty() && o._tier_endpoint.empty()) {
            fail(
                "KINESIS_TIER_PROVIDER=azure-blob needs KINESIS_TIER_AZURE_ACCOUNT (or "
                "KYTHIRA_AZURE_STORAGE_ACCOUNT), the storage account; KINESIS_TIER_BUCKET "
                "names the container");
        }
    }
    if (provider == "gcs") {
        o._tier_gcs_project = r.opt("GOOGLE_CLOUD_PROJECT", "");
    }
}

void read_kinesis_side(const reader& r, node_options& o) {
    const auto listen = r.opt("KINESIS_LISTEN", "0.0.0.0:4567");
    const auto hp = kinesis::split_host_port(listen);
    if (!hp) {
        fail("KINESIS_LISTEN must be host:port, got '" + listen + "'");
    }
    o._listen_host = hp->first;
    o._listen_port = static_cast<std::uint16_t>(std::stoul(hp->second));
    if (r.set("KINESIS_INTERNAL_LISTEN")) {
        const auto internal = r.required("KINESIS_INTERNAL_LISTEN");
        const auto ihp = kinesis::split_host_port(internal);
        if (!ihp || std::stoul(ihp->second) == 0 || std::stoul(ihp->second) > 65535) {
            fail("KINESIS_INTERNAL_LISTEN must be host:port, got '" + internal + "'");
        }
        o._internal_host = ihp->first;
        o._internal_port = static_cast<std::uint16_t>(std::stoul(ihp->second));
        if (o._internal_port == o._listen_port &&
            (o._internal_host == o._listen_host || o._listen_host == "0.0.0.0")) {
            // The same socket: one listener, as when unset.
            o._internal_host.clear();
            o._internal_port = 0;
        }
    }
    o._tls_cert_path = r.opt("KINESIS_TLS_CERT", "");
    o._tls_key_path = r.opt("KINESIS_TLS_KEY", "");
    o._allow_plaintext = r.flag("KINESIS_ALLOW_PLAINTEXT", "false");
    if (o._tls_cert_path.empty() != o._tls_key_path.empty()) {
        fail("KINESIS_TLS_CERT and KINESIS_TLS_KEY go together");
    }
    if (o._tls_cert_path.empty() && !o._allow_plaintext) {
        fail(
            "KINESIS_TLS_CERT and KINESIS_TLS_KEY are required: the API carries signed "
            "requests and record data (set KINESIS_ALLOW_PLAINTEXT=true to serve HTTP on a "
            "network you trust)");
    }
    if (!o._tls_cert_path.empty() && o._allow_plaintext) {
        fail("KINESIS_ALLOW_PLAINTEXT and KINESIS_TLS_CERT are exclusive");
    }
    o._region = r.opt("KINESIS_REGION", "us-east-1");
    o._partition = r.opt("KINESIS_PARTITION", "aws");
    if (o._region.empty() || o._partition.empty()) {
        fail("KINESIS_REGION and KINESIS_PARTITION must not be empty");
    }
    using kythira::aws_auth::auth_mode;
    const auto auth = r.opt("KINESIS_AUTH", "static");
    if (auth == "static") {
        o._auth = auth_mode::static_keys;
    } else if (auth == "iam") {
        o._auth = auth_mode::iam;
    } else if (auth == "both") {
        o._auth = auth_mode::both;
    } else {
        fail("KINESIS_AUTH: static, iam or both, not '" + auth + "'");
    }
    if (o._auth == auth_mode::iam) {
        if (r.set("KINESIS_STATIC_KEYS_FILE")) {
            fail("KINESIS_AUTH=iam takes no KINESIS_STATIC_KEYS_FILE: use both, or unset it");
        }
    } else {
        o._static_keys_file = r.required("KINESIS_STATIC_KEYS_FILE");
    }
    // A front end or a gateway without data keeps nothing on disk.
    o._data_dir = is_front_end_node(o._roles) || is_gateway_node(o._roles)
                      ? r.opt("KINESIS_DATA_DIR", "")
                      : r.required("KINESIS_DATA_DIR");

    if (r.set("KINESIS_FORWARD_SECRET") && r.set("KINESIS_FORWARD_SECRET_FILE")) {
        fail("set KINESIS_FORWARD_SECRET or KINESIS_FORWARD_SECRET_FILE, not both");
    }
    o._forward_secret = r.set("KINESIS_FORWARD_SECRET_FILE")
                            ? read_secret_file(r.required("KINESIS_FORWARD_SECRET_FILE"))
                            : r.opt("KINESIS_FORWARD_SECRET", "");
    if (o._peers.size() > 1 && o._forward_secret.size() < 16) {
        fail(
            "KINESIS_FORWARD_SECRET (or _FILE) of at least 16 bytes is required with more than "
            "one voter: the gateways sign forwarded writes and segment fetches with it");
    }
    o._iterator_keys_file = r.opt("KINESIS_ITERATOR_KEYS_FILE", "");
    if (r.set("KINESIS_PEER_GATEWAYS")) {
        o._peer_gateways =
            parse_id_map("KINESIS_PEER_GATEWAYS", r.required("KINESIS_PEER_GATEWAYS"));
    } else {
        for (const auto& [id, url] : o._peers) {
            o._peer_gateways[id] =
                host_of(url) + ":" +
                std::to_string(o._internal_port != 0 ? o._internal_port : o._listen_port);
        }
    }
    for (const auto& [id, gw] : o._peer_gateways) {
        if (!kinesis::split_host_port(gw)) {
            fail("KINESIS_PEER_GATEWAYS: '" + gw + "' is not host:port");
        }
    }
    o._peer_ca_path = r.opt("KINESIS_PEER_CA", "");

    for (const auto& item : split_list(r.opt("KINESIS_COMPAT", ""))) {
        const auto eq = item.find('=');
        if (eq == std::string::npos || eq == 0) {
            fail("KINESIS_COMPAT expects k=v[,k=v...], got '" + item + "'");
        }
        o._compat.emplace_back(item.substr(0, eq), item.substr(eq + 1));
    }
    if (auto p = kinesis::cluster_profile(o._compat); !p) {
        fail("KINESIS_COMPAT: " + p.error().message.value_or(p.error().type));
    }
    o._max_body_bytes = r.u64("KINESIS_MAX_BODY_BYTES", "8388608");
    if (o._max_body_bytes < std::uint64_t{1024} * 1024) {
        fail("KINESIS_MAX_BODY_BYTES must be at least 1048576");
    }
    o._max_connections = r.u64("KINESIS_MAX_CONNECTIONS", "256");
    if (o._max_connections == 0) {
        fail("KINESIS_MAX_CONNECTIONS must be at least 1");
    }
    o._command_timeout = r.ms("KINESIS_COMMAND_TIMEOUT_MS", "5000");

    o._disk_floor_bytes = r.u64("KINESIS_DISK_FLOOR_BYTES", "1073741824");
    o._metrics = r.flag("KINESIS_METRICS", "false");
    read_segment_layer(r, o);
    o._kms = r.opt("KINESIS_KMS", "off");
    o._kms_set = r.set("KINESIS_KMS");
    if (o._kms != "off" && o._kms != "local" && o._kms != "aws" && o._kms != "pkcs11" &&
        o._kms != "kythira") {
        fail("KINESIS_KMS must be off, local, aws, pkcs11 or kythira");
    }
    o._kms_previous = r.opt("KINESIS_KMS_PREVIOUS", "off");
    if (o._kms_previous != "off" && o._kms_previous != "local" && o._kms_previous != "aws" &&
        o._kms_previous != "pkcs11" && o._kms_previous != "kythira") {
        fail("KINESIS_KMS_PREVIOUS must be off, local, aws, pkcs11 or kythira");
    }
    if (o._kms_previous != "off" && o._kms_previous == o._kms) {
        fail("KINESIS_KMS_PREVIOUS must differ from KINESIS_KMS");
    }
    const auto uses = [&o](std::string_view name) {
        return o._kms == name || o._kms_previous == name;
    };
    if (uses("aws") && uses("kythira") && r.set("KINESIS_KMS_ENDPOINT")) {
        fail("KINESIS_KMS_ENDPOINT cannot serve both aws and kythira");
    }
    o._kms_ca = r.opt("KINESIS_KMS_CA", "");
    o._kms_caller_ttl = r.ms("KINESIS_KMS_CALLER_TTL_MS", "300000");
    if (o._kms_caller_ttl.count() < 1) {
        fail("KINESIS_KMS_CALLER_TTL_MS must be at least 1");
    }
    if (r.set("KINESIS_KMS_PASSPHRASE") && r.set("KINESIS_KMS_PASSPHRASE_FILE")) {
        fail("set KINESIS_KMS_PASSPHRASE or KINESIS_KMS_PASSPHRASE_FILE, not both");
    }
    if (uses("local")) {
        o._kms_passphrase = r.set("KINESIS_KMS_PASSPHRASE_FILE")
                                ? read_secret_file(r.required("KINESIS_KMS_PASSPHRASE_FILE"))
                                : r.opt("KINESIS_KMS_PASSPHRASE", "");
        if (o._kms_passphrase.size() < 16) {
            fail(
                "KINESIS_KMS(_PREVIOUS)=local needs KINESIS_KMS_PASSPHRASE (or _FILE) of at least "
                "16 bytes");
        }
    }
    o._kms_region = r.opt("KINESIS_KMS_REGION", o._region.c_str());
    o._kms_endpoint = r.opt("KINESIS_KMS_ENDPOINT", "");
    if (!o._kms_endpoint.empty() && !kinesis::split_host_port(o._kms_endpoint)) {
        fail("KINESIS_KMS_ENDPOINT: '" + o._kms_endpoint + "' is not host:port");
    }
    if (uses("pkcs11")) {
        o._kms_pkcs11_uri = r.required("KINESIS_KMS_PKCS11_URI");
        try {
            const auto u = pkcs11::uri::parse(o._kms_pkcs11_uri);
            if (!u.token && !u.serial) {
                fail("KINESIS_KMS_PKCS11_URI must name the token (token= or serial=)");
            }
            if (!u.pin_source && !u.pin_value) {
                fail("KINESIS_KMS_PKCS11_URI needs pin-source (or pin-value)");
            }
            o._kms_pkcs11_identity = r.opt("KINESIS_KMS_PKCS11_IDENTITY", "kinesis");
            if (!u.module_path && o._kms_pkcs11_identity.empty()) {
                fail("KINESIS_KMS_PKCS11_IDENTITY must not be empty");
            }
        } catch (const pkcs11::uri_error& e) {
            fail(std::string("KINESIS_KMS_PKCS11_URI: ") + e.what());
        }
        o._kms_pkcs11_oaep = r.opt("KINESIS_KMS_PKCS11_OAEP", "sha256");
        if (o._kms_pkcs11_oaep != "sha256" && o._kms_pkcs11_oaep != "sha1") {
            fail("KINESIS_KMS_PKCS11_OAEP must be sha256 or sha1");
        }
    }
    o._maintenance_interval = r.ms("KINESIS_MAINTENANCE_INTERVAL_MS", "60000");
    if (o._maintenance_interval.count() < 100) {
        fail("KINESIS_MAINTENANCE_INTERVAL_MS must be at least 100");
    }
    const auto tier_after = r.u64("KINESIS_TIER_AFTER_HOURS", "0");
    if (tier_after > kinesis::k_max_retention_hours) {
        fail("KINESIS_TIER_AFTER_HOURS must be at most 8760");
    }
    constexpr std::uint64_t ms_per_hour = 3600U * 1000U;
    o._tier_after_ms = static_cast<std::int64_t>(tier_after * ms_per_hour);
    // Milliseconds win when set, so a test or demo can watch a segment tier
    // within seconds without a separate build. A second is the floor: below
    // it a segment would tier while it is still being written.
    if (r.set("KINESIS_TIER_AFTER_MS")) {
        const auto ms = r.u64("KINESIS_TIER_AFTER_MS", "0");
        if (ms != 0 && ms < 1000) {
            fail("KINESIS_TIER_AFTER_MS must be 0 or at least 1000");
        }
        if (ms > std::uint64_t{kinesis::k_max_retention_hours} * ms_per_hour) {
            fail("KINESIS_TIER_AFTER_MS must be at most 8760 hours");
        }
        o._tier_after_ms = static_cast<std::int64_t>(ms);
    }
    read_tier_store(r, o);
    o._channel_delivery = r.flag("KINESIS_CHANNEL_DELIVERY", "true");
    o._channel_s3_region = r.opt("KINESIS_CHANNEL_S3_REGION", o._region.c_str());
    o._channel_s3_endpoint = r.opt("KINESIS_CHANNEL_S3_ENDPOINT", "");
    const auto max_delay = r.u64("KINESIS_CHANNEL_MAX_DELAY_MS", "0");
    if (max_delay != 0 && max_delay < 1000) {
        fail("KINESIS_CHANNEL_MAX_DELAY_MS must be 0 or at least 1000");
    }
    if (max_delay > std::uint64_t{900} * 1000U) {
        fail("KINESIS_CHANNEL_MAX_DELAY_MS must be at most 900000");
    }
    o._channel_max_delay_ms = static_cast<std::int64_t>(max_delay);
    const auto role = r.opt("KINESIS_CHANNEL_ROLE", "node");
    if (role != "node" && role != "assume") {
        fail("KINESIS_CHANNEL_ROLE must be node or assume");
    }
    o._channel_assume_role = role == "assume";
    const auto encryption = r.opt("KINESIS_CHANNEL_ENCRYPTION", "envelope");
    if (encryption != "envelope" && encryption != "sse-kms") {
        fail("KINESIS_CHANNEL_ENCRYPTION must be envelope or sse-kms");
    }
    o._channel_sse_kms = encryption == "sse-kms";
    o._channel_sts_endpoint = r.opt("KINESIS_CHANNEL_STS_ENDPOINT", "");
    if (!o._channel_sts_endpoint.empty() && !kinesis::parse_aws_endpoint(o._channel_sts_endpoint)) {
        fail("KINESIS_CHANNEL_STS_ENDPOINT must be an http:// or https:// URL");
    }
    o._channel_ca_file = r.opt("KINESIS_CHANNEL_CA_FILE", "");
    o._channel_iceberg_uri = r.opt("KINESIS_CHANNEL_ICEBERG_URI", "");
    if (!o._channel_iceberg_uri.empty() && !kinesis::parse_aws_endpoint(o._channel_iceberg_uri)) {
        fail("KINESIS_CHANNEL_ICEBERG_URI must be an http:// or https:// URL");
    }
    o._channel_iceberg_warehouse = r.opt("KINESIS_CHANNEL_ICEBERG_WAREHOUSE", "");
    o._channel_iceberg_sigv4 = r.flag("KINESIS_CHANNEL_ICEBERG_SIGV4", "true");
    o._channel_iceberg_token = r.opt("KINESIS_CHANNEL_ICEBERG_TOKEN", "");
}

}  // namespace

auto tier_provider_support(std::string_view provider) -> tier_support {
    if (provider == "s3") {
#ifdef KYTHIRA_KINESIS_TIER_S3
        return {true, {}};
#else
        return {false, "the AWS SDK's s3 component"};
#endif
    }
    if (provider == "azure-blob") {
#ifdef KYTHIRA_KINESIS_TIER_AZURE
        return {true, {}};
#else
        return {false, "CONFIG_AZURE_BLOB_PERSISTENCE=y and the Azure SDK"};
#endif
    }
    if (provider == "gcs") {
#ifdef KYTHIRA_KINESIS_TIER_GCS
        return {true, {}};
#else
        return {false, "CONFIG_GCP_STORAGE_PERSISTENCE=y and vcpkg's `gcp` feature"};
#endif
    }
    if (provider == "oci-objectstorage") {
#ifdef KYTHIRA_KINESIS_TIER_OCI
        return {true, {}};
#else
        return {false, "CONFIG_OCI_OBJECT_PERSISTENCE=y"};
#endif
    }
    if (provider == "oss") {
#ifdef KYTHIRA_KINESIS_TIER_OSS
        return {true, {}};
#else
        return {false, "CONFIG_ALIBABA_OSS_PERSISTENCE=y"};
#endif
    }
    return {false, {}};
}

auto is_loopback_address(const std::string& address) -> bool {
    return kythira::net_bind::is_loopback_bind_address(address);
}

auto from_env(const env_lookup& env) -> node_options {
    node_options o;
    const reader r{env};
    read_roles(r, o);
    read_raft_side(r, o);
    read_kinesis_side(r, o);
    return o;
}

auto from_env(const service_node::env_lookup& env) -> node_options {
    // The reader wants C strings that live as long as the read: each
    // variable is looked up once and kept here.
    std::map<std::string, std::optional<std::string>, std::less<>> seen;
    const env_lookup lookup = [&env, &seen](const char* name) -> const char* {
        auto it = seen.find(std::string_view(name));
        if (it == seen.end()) {
            it = seen.emplace(name, env(name)).first;
        }
        return it->second ? it->second->c_str() : nullptr;
    };
    return from_env(lookup);
}

auto process_env() -> service_node::env_lookup {
    return [](std::string_view name) -> std::optional<std::string> {
        // Read at startup, before the node starts a thread.
        const char* v = std::getenv(std::string(name).c_str());  // NOLINT(concurrency-mt-unsafe)
        if (v == nullptr || *v == '\0') {
            return std::nullopt;
        }
        return std::string(v);
    };
}

auto composite_env(service_node::env_lookup env) -> service_node::env_lookup {
    return [env = std::move(env)](std::string_view name) -> std::optional<std::string> {
        const bool plaintext = env("KYTHIRA_NODE_INSECURE_PLAINTEXT").value_or("") == "1";
        if (name == "KINESIS_DATA_DIR") {
            auto dir = env("KYTHIRA_NODE_DATA_DIR");
            if (!dir) {
                return std::nullopt;
            }
            return (std::filesystem::path(*dir) / "kinesis").string();
        }
        if (auto v = env(name)) {
            return v;
        }
        if (name == "KYTHIRA_PEERS") {
            // id=host:port,... as id=scheme://host:port,...
            const auto peers = env("KYTHIRA_NODE_PEERS");
            if (!peers) {
                return std::nullopt;
            }
            std::string out;
            for (const auto& tok : split_list(*peers)) {
                const auto eq = tok.find('=');
                if (eq == std::string::npos) {
                    out += (out.empty() ? "" : ",") + tok;  // from_env names the fault
                    continue;
                }
                out += (out.empty() ? "" : ",") + tok.substr(0, eq + 1) +
                       (plaintext ? "http://" : "https://") + tok.substr(eq + 1);
            }
            return out;
        }
        if (name == "KYTHIRA_ALLOW_PLAINTEXT_RAFT") {
            return std::string("true");
        }
        if (name == "KYTHIRA_RAFT_BIND") {
            return env("KYTHIRA_NODE_RAFT_BIND");
        }
        if (name == "KYTHIRA_RAFT_PORT") {
            return env("KYTHIRA_NODE_RAFT_PORT").value_or("7400");  // node_config's default
        }
        if (name == "KINESIS_ALLOW_PLAINTEXT") {
            return plaintext ? std::optional<std::string>("true") : std::nullopt;
        }
        if (name == "KINESIS_TLS_CERT" && !plaintext) {
            return env("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "KINESIS_TLS_KEY" && !plaintext) {
            return env("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "KINESIS_PEER_CA") {
            return env("KYTHIRA_NODE_TLS_CA");
        }
        return std::nullopt;
    };
}

auto is_segment_node(kythira::layers::role_set roles) -> bool {
    using kythira::layers::role;
    return roles.has(role::segments) && !roles.has(role::data);
}

auto volume_assignments(const node_options& o) -> std::vector<kythira::volume_assignment> {
    if (o._segment_nodes.empty()) {
        return {};
    }
    std::vector<std::string> replicas;
    replicas.reserve(o._peers.size());
    for (const auto& [id, url] : o._peers) {
        replicas.push_back(kythira::host_node_id_text(id));
    }
    return kythira::initial_volume_assignments("kinesis", replicas, o._segment_nodes);
}

auto is_front_end_node(kythira::layers::role_set roles) -> bool {
    using kythira::layers::role;
    return roles.has(role::front_end) && !roles.has(role::data);
}

auto is_gateway_node(kythira::layers::role_set roles) -> bool {
    using kythira::layers::role;
    return roles.has(role::gateway) && !roles.has(role::front_end) && !roles.has(role::data) &&
           !roles.has(role::segments);
}

auto unserved_roles(kythira::layers::role_set roles, bool segment_layer, bool data_layer,
                    bool front_end_layer) -> std::optional<std::string> {
    using kythira::layers::role;
    if (roles.empty()) {
        return "names no role; a node runs at least one of gateway, front_end, data, segments";
    }
    if (roles == kythira::layers::role_set{role::segments}) {
        if (!segment_layer) {
            return "a segment node holds volumes for the data nodes listed with it in "
                   "KINESIS_SEGMENT_NODES, which is not set";
        }
        return std::nullopt;
    }
    if (roles.has(role::gateway) && !roles.has(role::front_end) && !front_end_layer) {
        return "a gateway without front_end hands each call to a front end on another node, "
               "listed in KINESIS_FRONT_ENDS, which is not set; list the front ends' listeners "
               "there, or add front_end";
    }
    if (!roles.has(role::data)) {
        if (roles.has(role::segments)) {
            return "segments without data makes a segment node, which runs no other role; "
                   "drop segments, or add data";
        }
        if (roles.has(role::front_end) && !data_layer) {
            return "a front end without the data role reaches the data layer through the "
                   "data nodes listed in KINESIS_DATA_NODES, which is not set; list their "
                   "internal listeners there, or add data";
        }
        return std::nullopt;
    }
    if (!roles.has(role::segments) && !segment_layer) {
        return "data without segments keeps its record segments on a volume on a segment "
               "node, and KINESIS_SEGMENT_NODES names none; list the segment nodes there or "
               "add segments";
    }
    return std::nullopt;
}

auto describe(const node_options& o) -> std::string {
    std::ostringstream out;
    out << "node_id=" << kythira::host_node_id_text(o._node_id) << '\n'
        << "roles=" << o._roles.to_string() << '\n'
        << "raft=" << o._bind_address << ':' << o._raft_port
        << (o._allow_plaintext_raft ? " (plaintext allowed)" : "") << '\n'
        << "voters=" << (o._roles.has(kythira::layers::role::data) ? o._voters.size() : 0);
    if (o._roles.has(kythira::layers::role::data) && o._voters.size() != o._peers.size()) {
        // KINESIS_VOTERS names fewer than the peers: list them, and say
        // whether this node joins as an evacuation target.
        out << " (";
        for (std::size_t i = 0; i < o._voters.size(); ++i) {
            out << (i == 0 ? "" : ",") << kythira::host_node_id_text(o._voters[i]);
        }
        out << ')';
        if (std::ranges::find(o._voters, o._node_id) == o._voters.end()) {
            out << " joining";
        }
    }
    if (o._discard_replicas) {
        out << " discard_replicas";
    }
    out << '\n'
        << "shards=" << (o._shard_cuts.size() + 1) << '\n'
        << "listen=" << o._listen_host << ':' << o._listen_port
        << (o._allow_plaintext ? " http" : " https") << '\n';
    if (o._internal_port != 0) {
        out << "internal=" << o._internal_host << ':' << o._internal_port << '\n';
    }
    out << "region=" << o._region << " partition=" << o._partition << '\n'
        << "data_dir=" << o._data_dir.string() << '\n'
        << "auth="
        << (o._auth == kythira::aws_auth::auth_mode::iam    ? "iam"
            : o._auth == kythira::aws_auth::auth_mode::both ? "both"
                                                            : "static")
        << '\n'
        << "static_keys_file=" << o._static_keys_file << '\n'
        << "forward_secret=" << (o._forward_secret.empty() ? "unset" : "set") << '\n'
        << "iterator_keys="
        << (!o._iterator_keys_file.empty() ? o._iterator_keys_file
            : o._forward_secret.empty()    ? std::string("random (this process only)")
                                           : std::string("derived from the forward secret"))
        << '\n';
    for (const auto& [id, gw] : o._peer_gateways) {
        out << "peer_gateway " << kythira::host_node_id_text(id) << '=' << gw << '\n';
    }
    for (const auto& n : o._data_nodes) {
        out << "data_node " << n << '\n';
    }
    for (const auto& n : o._front_ends) {
        out << "front_end " << n << '\n';
    }
    out << "drain_timeout_ms=" << o._drain_timeout.count() << '\n';
    for (const auto& n : o._segment_nodes) {
        out << "segment_node " << n._id << '=' << n._endpoint
            << (n._placement_group.empty() ? std::string() : " group=" + n._placement_group)
            << '\n';
    }
    for (const auto& a : volume_assignments(o)) {
        out << "volume " << a._volume << " on segment_node " << a._segment_node
            << " epoch=" << a._epoch << '\n';
    }
    out << "disk_floor_bytes=" << o._disk_floor_bytes << '\n'
        << "maintenance_interval_ms=" << o._maintenance_interval.count() << '\n'
        << "metrics=" << (o._metrics ? "on (GET /metrics)" : "off") << '\n'
        << "kms=" << o._kms
        << (o._kms == "kythira" ? (o._kms_endpoint.empty() ? std::string(" (co-located)")
                                                           : " endpoint=" + o._kms_endpoint)
                                : std::string())
        << (o._kms == "aws" ? " region=" + o._kms_region +
                                  (o._kms_endpoint.empty() ? "" : " endpoint=" + o._kms_endpoint)
                            : std::string())
        << (o._kms_previous != "off" ? " previous=" + o._kms_previous : std::string())
        << (o._kms == "pkcs11" ? " token=" + pkcs11::uri::parse(o._kms_pkcs11_uri).to_string() +
                                     " oaep=" + o._kms_pkcs11_oaep
                               : std::string())
        << '\n';
    if (o._tier_after_ms > 0) {
        out << "tier=s3://" << o._tier_bucket << '/' << o._tier_prefix << " after "
            << o._tier_after_ms << "ms region=" << o._tier_region
            << (o._tier_endpoint.empty() ? "" : " endpoint=" + o._tier_endpoint) << '\n';
    } else {
        out << "tier=off\n";
    }
    out << "channel_delivery="
        << (o._channel_delivery
                ? "on region=" + o._channel_s3_region +
                      (o._channel_s3_endpoint.empty() ? std::string()
                                                      : " endpoint=" + o._channel_s3_endpoint) +
                      (o._channel_max_delay_ms > 0
                           ? " max_delay=" + std::to_string(o._channel_max_delay_ms) + "ms"
                           : std::string()) +
                      (o._channel_assume_role
                           ? " role=assume" + (o._channel_sts_endpoint.empty()
                                                   ? std::string()
                                                   : " sts=" + o._channel_sts_endpoint)
                           : std::string(" role=node")) +
                      (o._channel_sse_kms ? " encryption=sse-kms" : " encryption=envelope") +
                      (o._channel_iceberg_uri.empty()
                           ? std::string()
                           : " iceberg=" + o._channel_iceberg_uri +
                                 (o._channel_iceberg_sigv4 ? " (sigv4)" : ""))
                : std::string("off"))
        << '\n';
    for (const auto& [k, v] : o._compat) {
        out << "compat " << k << '=' << v << '\n';
    }
    return out.str();
}

auto usage() -> std::string {
    return "usage: kinesis_gateway_node [--help | --self-test | --check-config |\n"
           "                            --admin METHOD OP [BODY]]\n"
           "\n"
           "The Kythira Kinesis Data Streams-compatible daemon. Configured from the\n"
           "environment; stopped by SIGINT or SIGTERM.\n"
           "\n"
           "  --help          print this text\n"
           "  --self-test     check the generated tables, then exit\n"
           "  --check-config  read the environment, print the settings, then exit\n"
           "  --admin METHOD OP [BODY]\n"
           "                  one live migration call to this node's gateway, signed\n"
           "                  with KINESIS_FORWARD_SECRET: POST evacuate '{\"node\":\"1\",\n"
           "                  \"targets\":[{\"id\":\"4\"}]}', GET evacuate, POST\n"
           "                  evacuate/cancel, POST release, GET|POST store-move\n"
           "                  ('{\"to\":\"volume\"}' or '{\"to\":\"local\"}'); the gateway\n"
           "                  is on loopback unless KINESIS_ADMIN_TARGET=host:port\n"
           "\n"
           "Raft (as redis_gateway_node):\n"
           "  KYTHIRA_NODE_ID                  this node's id (required)\n"
           "  KYTHIRA_PEERS                    id=http://host:port,... for every voter, self "
           "included (required)\n"
           "  KYTHIRA_RAFT_BIND, KYTHIRA_RAFT_PORT   Raft listener (0.0.0.0, 7000)\n"
           "  KYTHIRA_ALLOW_PLAINTEXT_RAFT     required off loopback: Raft RPC is plaintext\n"
           "  KYTHIRA_SHARD_CUTS               initial group boundaries, comma-separated\n"
           "  KYTHIRA_TICK_INTERVAL_MS, KYTHIRA_ELECTION_TIMEOUT_{MIN,MAX}_MS,\n"
           "  KYTHIRA_HEARTBEAT_INTERVAL_MS, KYTHIRA_RPC_TIMEOUT_MS, KYTHIRA_POLICY_INTERVAL_MS,\n"
           "  KYTHIRA_EXECUTOR_STRIPES, KYTHIRA_LOG_LEVEL\n"
           "\n"
           "Kinesis:\n"
           "  KINESIS_LISTEN                   API listener host:port (0.0.0.0:4567)\n"
           "  KINESIS_INTERNAL_LISTEN          host:port for the routes between nodes\n"
           "                                   only (unset: they share KINESIS_LISTEN)\n"
           "  KINESIS_TLS_CERT, KINESIS_TLS_KEY     PEM chain and key (required unless\n"
           "  KINESIS_ALLOW_PLAINTEXT=true)\n"
           "  KINESIS_REGION, KINESIS_PARTITION     us-east-1, aws\n"
           "  KINESIS_AUTH                     static, iam or both (static): sign in by\n"
           "                                   the keys file, Kythira IAM (KYTHIRA_IAM_*),\n"
           "                                   or the file's keys first and IAM for the rest\n"
           "  KINESIS_STATIC_KEYS_FILE         access keys: id secret account name role\n"
           "                                   (required with static and both)\n"
           "  KINESIS_DATA_DIR                 Raft state and record segments (required\n"
           "                                   with the data or segments role)\n"
           "  KINESIS_FORWARD_SECRET[_FILE]    shared by the gateways; required with >1 voter\n"
           "  KINESIS_ITERATOR_KEYS_FILE       shard-iterator keys: id secret, first signs\n"
           "                                   (default: derived from the forward secret)\n"
           "  KINESIS_PEER_GATEWAYS            id=host:port,... (default: Raft host, own port)\n"
           "  KINESIS_PEER_CA                  CA bundle for peer gateways (system store)\n"
           "  KINESIS_COMPAT                   cluster compatibility settings, k=v,...\n"
           "  KINESIS_MAX_BODY_BYTES           request body limit (8388608)\n"
           "  KINESIS_MAX_CONNECTIONS          concurrent API connections, a thread each (256)\n"
           "  KINESIS_COMMAND_TIMEOUT_MS       commit timeout per write (5000)\n"
           "  KINESIS_METRICS                  serve Prometheus metrics on GET /metrics,\n"
           "                                   unauthenticated (false)\n"
           "  KINESIS_ROLES                    layers this node runs, a subset of gateway,\n"
           "                                   front_end, data, segments (all four);\n"
           "                                   data,segments serves only peers; data alone\n"
           "                                   keeps segments on a segment node, segments\n"
           "                                   alone is one (both need KINESIS_SEGMENT_NODES);\n"
           "                                   front_end without data holds no replica\n"
           "                                   (needs KINESIS_DATA_NODES); gateway without\n"
           "                                   front_end hands calls on (needs\n"
           "                                   KINESIS_FRONT_ENDS)\n"
           "  KINESIS_SEGMENT_NODES            the segment layer: id=host:port[@group],...\n"
           "  KINESIS_DATA_NODES               a front end's data layer: host:port,... of\n"
           "                                   data nodes' internal listeners\n"
           "  KINESIS_FRONT_ENDS               a gateway's front ends: host:port,... of\n"
           "                                   their listeners\n"
           "  KINESIS_DRAIN_TIMEOUT_MS         how long a stopping gateway lets calls in\n"
           "                                   flight finish (10000)\n"
           "  KINESIS_VOTERS                   ids that formed the groups (every KYTHIRA_PEERS\n"
           "                                   id); a data node not listed joins as an\n"
           "                                   evacuation target\n"
           "  KINESIS_DISCARD_REPLICAS         start without data although Raft replicas are\n"
           "                                   on disk, deleting them (false)\n"
           "  KINESIS_KMS                      key provider for encrypted streams: off, local,\n"
           "                                   aws, pkcs11 or kythira (off; kythira_node:\n"
           "                                   kythira when the KMS module runs)\n"
           "  KINESIS_KMS_PASSPHRASE[_FILE]    local: wraps data keys, same on every node\n"
           "  KINESIS_KMS_REGION               aws: KMS region (default: KINESIS_REGION)\n"
           "  KINESIS_KMS_ENDPOINT             aws: KMS host:port (default: AWS); kythira: a\n"
           "                                   KMS on another cluster, over HTTPS\n"
           "  KINESIS_KMS_PREVIOUS             a provider whose data keys this node still opens\n"
           "                                   after a move (off)\n"
           "  KINESIS_KMS_CA                   kythira over HTTPS: the CA its listener chains to\n"
           "  KINESIS_KMS_CALLER_TTL_MS        kythira: how long a caller's KMS answer stands\n"
           "                                   (300000)\n"
           "  KINESIS_KMS_PKCS11_URI           pkcs11: the token, pkcs11:token=...;pin-source=...\n"
           "                                   (module-path= when the HSM is not co-located)\n"
           "  KINESIS_KMS_PKCS11_IDENTITY      pkcs11: co-located HSM application (kinesis)\n"
           "  KINESIS_KMS_PKCS11_OAEP          pkcs11: RSA-OAEP hash, sha256 or sha1 (sha256)\n"
           "\n"
           "Retention and tiering:\n"
           "  KINESIS_DISK_FLOOR_BYTES         refuse writes below this free space (1073741824;\n"
           "                                   0 = off)\n"
           "  KINESIS_MAINTENANCE_INTERVAL_MS  retention and tiering pass interval (60000)\n"
           "  KINESIS_TIER_AFTER_HOURS         tier segments this old (0 = never)\n"
           "  KINESIS_TIER_AFTER_MS            the same in milliseconds (>= 1000); wins when set\n"
           "  KINESIS_TIER_PROVIDER            s3 (default), azure-blob, gcs, oci-objectstorage, "
           "oss\n"
           "  KINESIS_TIER_BUCKET              bucket (Azure: container) for tiered segments\n"
           "  KINESIS_TIER_PREFIX              key prefix in the bucket\n"
           "  KINESIS_TIER_ENDPOINT            S3-compatible endpoint, or Azure/GCS endpoint "
           "override\n"
           "  KINESIS_TIER_S3_REGION           S3 bucket region (default: KINESIS_REGION)\n"
           "  KINESIS_TIER_AZURE_ACCOUNT       Azure storage account (default:\n"
           "                                   KYTHIRA_AZURE_STORAGE_ACCOUNT)\n"
           "  (KINESIS_TIER_S3_BUCKET, _PREFIX and _ENDPOINT are accepted for the three above;\n"
           "   GCS reads GOOGLE_CLOUD_PROJECT, OCI KYTHIRA_OCI_*, OSS KYTHIRA_ALIBABA_*)\n";
}

}  // namespace kythira::kinesis_node
