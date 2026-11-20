// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_node_config.hpp
/// @brief `s3_gateway_node`'s settings, read from the environment
///        (.kiro/specs/s3-compatible-storage/ task 16).
///
/// Every setting is a `KYTHIRA_S3_*` variable; `node_env_help` is what
/// `--help` prints and lists them all. `node_config_from_env` checks them
/// together, so a node that cannot serve stops at start with a message
/// naming the variable (Kinesis Requirement 2.4):
///
///  - the role set must be one `check_layout` (`s3_roles.hpp`) accepts;
///  - a node with the front end needs an API listener's TLS material, or
///    `KYTHIRA_S3_INSECURE_PLAINTEXT=1` (tests only);
///  - a node with the metadata role that other nodes reach, and every node
///    that reaches one, needs the internal listener's mutual-TLS material:
///    internal calls are authenticated by layer identity
///    (`raft/layer_identity.hpp`), never in plaintext;
///  - the website listener needs its domains.
///
/// **The index on Raft** (task 16a). With `KYTHIRA_S3_RAFT_PEERS` (every
/// metadata node's Raft address, this one's included) a metadata node runs
/// the index group on Raft with the others, keeps it in RocksDB under
/// `KYTHIRA_S3_DATA_DIR`, and survives a restart; `--help` says whether the
/// binary was built with it. Its `KYTHIRA_S3_METADATA_ENDPOINTS` then name
/// every member's internal listener (the members forward to their leader
/// and copy chunks to each other there), so a node with the front end and
/// the metadata role uses the group in process and reaches the others
/// through it (hybrid). Without peers a metadata node holds its group in
/// process and in memory, alone: it may not be given endpoints, and
/// nothing in its index survives a restart.

#include <kythira/s3/s3_outbound.hpp>
#include <kythira/s3/s3_roles.hpp>

#include <raft/static_keys_file.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::s3 {

/// Reads one environment variable.
using env_lookup = std::function<std::optional<std::string>(std::string_view)>;

/// An address to listen on.
struct listen_address {
    std::string bind = "0.0.0.0";
    std::uint16_t port = 0;
};

struct tls_files {
    std::string cert;
    std::string key;
    /// The bundle peers' certificates chain to (internal listener only).
    std::string ca;
};

struct node_config {
    role_set roles = role_set::all();
    /// This node in layer identities and in co-located placement.
    std::string node_id = "1";
    /// The cluster name in layer identities.
    std::string cluster = "default";
    std::string region = "us-east-1";
    std::string partition = "aws";

    /// The S3 API (front end): HTTPS, or plaintext for tests.
    listen_address api{"0.0.0.0", 9000};
    tls_files api_tls;
    bool insecure_plaintext = false;
    /// Virtual-hosted addressing domains (`<bucket>.<domain>`).
    std::vector<std::string> domains;
    /// The largest request body the API listener reads (bodies are read
    /// whole until the gateway streams, task 17).
    std::uint64_t max_request_bytes = std::uint64_t{256} * 1024 * 1024;

    /// The website endpoint: plain HTTP, as S3's website endpoints are.
    std::optional<listen_address> website;
    std::vector<std::string> website_domains;

    /// The internal listener (metadata and chunk routes), mutual TLS.
    std::optional<listen_address> internal;
    tls_files internal_tls;

    /// The metadata nodes' internal listeners, (node id,
    /// "https://host:port"): the ones a front end without the metadata
    /// role uses, and on a Raft member every member, this one included.
    std::vector<std::pair<std::string, std::string>> metadata_endpoints;

    /// The index group's members, (node id, "host:port" of its Raft
    /// listener), this node included: the index on Raft. Empty: the group
    /// in process and in memory.
    std::vector<std::pair<std::string, std::string>> raft_peers;
    /// This node's Raft listener (default: all addresses, at its own
    /// entry's port in `raft_peers`). Mutual TLS with the internal
    /// listener's material.
    listen_address raft_listen;

    [[nodiscard]] auto raft() const noexcept -> bool { return !raft_peers.empty(); }

    /// Where this node's chunk store lives (blobs role).
    std::filesystem::path data_dir = "s3-data";

    std::vector<aws_auth::static_key> keys;
    bool account_namespaces = false;
    /// SSE-S3's local key provider; empty stores SSE-S3 objects
    /// unencrypted.
    std::string sse_passphrase;

    /// Other services (`kms`, `sqs`, `sns`, `kinesis`, `s3`), and what to
    /// sign requests to them as. Without credentials nothing is sent:
    /// SSE-KMS is refused, notifications and replication are not run.
    service_endpoints endpoints;
    aws_credentials outbound;
    /// The CA bundle outbound HTTPS checks servers against.
    std::string outbound_ca = "/etc/ssl/certs/ca-certificates.crt";

    /// How often each worker runs (metadata nodes only).
    std::chrono::seconds worker_interval{60};
    /// How long a chunk stays unreferenced before the sweeper deletes it.
    std::chrono::seconds sweep_grace{3600};
};

inline constexpr std::string_view node_env_help =
    "  KYTHIRA_S3_ROLES               gateway,front_end,metadata,blobs (all four)\n"
    "  KYTHIRA_S3_NODE_ID             this node's id (1)\n"
    "  KYTHIRA_S3_CLUSTER             cluster name in layer identities (default)\n"
    "  KYTHIRA_S3_REGION              region (us-east-1)\n"
    "  KYTHIRA_S3_PARTITION           ARN partition (aws)\n"
    "  KYTHIRA_S3_LISTEN              API listener, host:port (0.0.0.0:9000)\n"
    "  KYTHIRA_S3_TLS_CERT            API certificate chain, leaf first (PEM)\n"
    "  KYTHIRA_S3_TLS_KEY             API private key (PEM)\n"
    "  KYTHIRA_S3_INSECURE_PLAINTEXT  1 serves the API over plain HTTP (tests only)\n"
    "  KYTHIRA_S3_DOMAINS             virtual-hosted domains, ','-separated\n"
    "  KYTHIRA_S3_MAX_REQUEST_BYTES   largest request body read (268435456)\n"
    "  KYTHIRA_S3_WEBSITE_LISTEN      website endpoint, host:port (none)\n"
    "  KYTHIRA_S3_WEBSITE_DOMAINS     website domains, ','-separated: a Host of\n"
    "                                 <bucket>.<domain> is served as a website\n"
    "  KYTHIRA_S3_INTERNAL_LISTEN     internal listener, host:port (none)\n"
    "  KYTHIRA_S3_INTERNAL_TLS_CERT   this node's certificate, with its layer\n"
    "                                 identity kythira://s3/<cluster>/<id>?roles=..\n"
    "  KYTHIRA_S3_INTERNAL_TLS_KEY    its private key\n"
    "  KYTHIRA_S3_INTERNAL_TLS_CA     the cluster CA bundle\n"
    "  KYTHIRA_S3_METADATA_ENDPOINTS  id=https://host:port,... of the metadata\n"
    "                                 nodes' internal listeners (on a Raft member:\n"
    "                                 every member, this node included)\n"
    "  KYTHIRA_S3_RAFT_PEERS          id=host:port,... of every metadata node's\n"
    "                                 Raft listener, this one included: the index\n"
    "                                 on Raft, kept in RocksDB (none: in process\n"
    "                                 and in memory, one metadata node)\n"
    "  KYTHIRA_S3_RAFT_LISTEN         Raft listener, host:port (0.0.0.0 at this\n"
    "                                 node's port in KYTHIRA_S3_RAFT_PEERS)\n"
    "  KYTHIRA_S3_DATA_DIR            chunks, and on a Raft member the index,\n"
    "                                 its Raft logs and change log (s3-data)\n"
    "  KYTHIRA_S3_STATIC_KEYS_FILE    access keys, one per line:\n"
    "                                 access-key-id secret account name role\n"
    "  KYTHIRA_S3_ACCOUNT_NAMESPACES  1 gives each account its own bucket names\n"
    "  KYTHIRA_S3_SSE_PASSPHRASE_FILE SSE-S3 key-encryption passphrase (none:\n"
    "                                 SSE-S3 objects are stored unencrypted)\n"
    "  KYTHIRA_S3_SERVICE_ENDPOINTS   service=url,... for kms, sqs, sns, kinesis\n"
    "                                 and s3 (none: AWS's regional endpoints)\n"
    "  KYTHIRA_S3_OUTBOUND_ACCESS_KEY_ID      what calls to them are signed as\n"
    "  KYTHIRA_S3_OUTBOUND_SECRET_ACCESS_KEY  (none: SSE-KMS, notifications and\n"
    "  KYTHIRA_S3_OUTBOUND_SESSION_TOKEN       replication are off)\n"
    "  KYTHIRA_S3_OUTBOUND_CA         CA bundle for outbound HTTPS\n"
    "                                 (/etc/ssl/certs/ca-certificates.crt)\n"
    "  KYTHIRA_S3_WORKER_INTERVAL_SECONDS  how often each worker runs (60)\n"
    "  KYTHIRA_S3_SWEEP_GRACE_SECONDS      unreferenced chunk grace (3600)\n";

namespace node_config_detail {

[[nodiscard]] inline auto split(std::string_view text, char sep) -> std::vector<std::string> {
    std::vector<std::string> out;
    while (!text.empty()) {
        const auto at = text.find(sep);
        auto part = text.substr(0, at);
        while (!part.empty() && part.front() == ' ') {
            part.remove_prefix(1);
        }
        while (!part.empty() && part.back() == ' ') {
            part.remove_suffix(1);
        }
        if (!part.empty()) {
            out.emplace_back(part);
        }
        text = at == std::string_view::npos ? std::string_view{} : text.substr(at + 1);
    }
    return out;
}

[[nodiscard]] inline auto parse_listen(std::string_view text) -> std::optional<listen_address> {
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos || colon == 0) {
        return std::nullopt;
    }
    listen_address out;
    out.bind = std::string(text.substr(0, colon));
    if (out.bind.size() > 2 && out.bind.front() == '[' && out.bind.back() == ']') {
        out.bind = out.bind.substr(1, out.bind.size() - 2);
    }
    const auto port = text.substr(colon + 1);
    unsigned value = 0;
    const auto [p, ec] = std::from_chars(port.data(), port.data() + port.size(), value);
    if (ec != std::errc{} || p != port.data() + port.size() || value > 65535) {
        return std::nullopt;
    }
    out.port = static_cast<std::uint16_t>(value);
    return out;
}

[[nodiscard]] inline auto parse_count(std::string_view text) -> std::optional<std::uint64_t> {
    std::uint64_t value = 0;
    const auto [p, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || p != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] inline auto truthy(const std::optional<std::string>& v) -> bool {
    return v && (*v == "1" || *v == "true" || *v == "yes");
}

[[nodiscard]] inline auto read_file(const std::string& path) -> std::optional<std::string> {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

[[nodiscard]] inline auto is_url(std::string_view u) -> bool {
    return u.starts_with("https://") || u.starts_with("http://");
}

}  // namespace node_config_detail

/// The settings, or the message naming the first one that is wrong.
[[nodiscard]] inline auto node_config_from_env(const env_lookup& env)
    -> std::variant<node_config, std::string> {
    namespace d = node_config_detail;
    node_config c;
    const auto get = [&](std::string_view name) { return env(name); };

    if (auto v = get("KYTHIRA_S3_ROLES")) {
        try {
            c.roles = parse_s3_roles(*v);
        } catch (const std::invalid_argument& e) {
            return std::string("KYTHIRA_S3_ROLES: ") + e.what();
        }
    }
    c.node_id = get("KYTHIRA_S3_NODE_ID").value_or(c.node_id);
    c.cluster = get("KYTHIRA_S3_CLUSTER").value_or(c.cluster);
    if (!layers::valid_identity_part(c.node_id)) {
        return "KYTHIRA_S3_NODE_ID: must be 1-128 letters, digits, '-', '.', '_' or '~'";
    }
    if (!layers::valid_identity_part(c.cluster)) {
        return "KYTHIRA_S3_CLUSTER: must be 1-128 letters, digits, '-', '.', '_' or '~'";
    }
    c.region = get("KYTHIRA_S3_REGION").value_or(c.region);
    c.partition = get("KYTHIRA_S3_PARTITION").value_or(c.partition);

    if (auto v = get("KYTHIRA_S3_LISTEN")) {
        auto a = d::parse_listen(*v);
        if (!a) {
            return "KYTHIRA_S3_LISTEN: expected host:port, got '" + *v + "'";
        }
        c.api = *a;
    }
    c.api_tls.cert = get("KYTHIRA_S3_TLS_CERT").value_or("");
    c.api_tls.key = get("KYTHIRA_S3_TLS_KEY").value_or("");
    c.insecure_plaintext = d::truthy(get("KYTHIRA_S3_INSECURE_PLAINTEXT"));
    if (auto v = get("KYTHIRA_S3_DOMAINS")) {
        c.domains = d::split(*v, ',');
    }
    if (auto v = get("KYTHIRA_S3_MAX_REQUEST_BYTES")) {
        auto n = d::parse_count(*v);
        if (!n || *n == 0) {
            return "KYTHIRA_S3_MAX_REQUEST_BYTES: expected a positive byte count";
        }
        c.max_request_bytes = *n;
    }

    if (auto v = get("KYTHIRA_S3_WEBSITE_LISTEN")) {
        auto a = d::parse_listen(*v);
        if (!a) {
            return "KYTHIRA_S3_WEBSITE_LISTEN: expected host:port, got '" + *v + "'";
        }
        c.website = *a;
    }
    if (auto v = get("KYTHIRA_S3_WEBSITE_DOMAINS")) {
        c.website_domains = d::split(*v, ',');
    }

    if (auto v = get("KYTHIRA_S3_INTERNAL_LISTEN")) {
        auto a = d::parse_listen(*v);
        if (!a) {
            return "KYTHIRA_S3_INTERNAL_LISTEN: expected host:port, got '" + *v + "'";
        }
        c.internal = *a;
    }
    c.internal_tls.cert = get("KYTHIRA_S3_INTERNAL_TLS_CERT").value_or("");
    c.internal_tls.key = get("KYTHIRA_S3_INTERNAL_TLS_KEY").value_or("");
    c.internal_tls.ca = get("KYTHIRA_S3_INTERNAL_TLS_CA").value_or("");

    if (auto v = get("KYTHIRA_S3_METADATA_ENDPOINTS")) {
        for (const auto& item : d::split(*v, ',')) {
            const auto eq = item.find('=');
            if (eq == std::string::npos || eq == 0 || !d::is_url(item.substr(eq + 1))) {
                return "KYTHIRA_S3_METADATA_ENDPOINTS: expected id=https://host:port, got '" +
                       item + "'";
            }
            c.metadata_endpoints.emplace_back(item.substr(0, eq), item.substr(eq + 1));
        }
    }
    if (auto v = get("KYTHIRA_S3_RAFT_PEERS")) {
        for (const auto& item : d::split(*v, ',')) {
            const auto eq = item.find('=');
            if (eq == std::string::npos || eq == 0 ||
                !d::parse_listen(std::string_view(item).substr(eq + 1))) {
                return "KYTHIRA_S3_RAFT_PEERS: expected id=host:port, got '" + item + "'";
            }
            c.raft_peers.emplace_back(item.substr(0, eq), item.substr(eq + 1));
        }
        if (c.raft_peers.empty()) {
            return std::string("KYTHIRA_S3_RAFT_PEERS: names no member");
        }
    }
    if (auto v = get("KYTHIRA_S3_RAFT_LISTEN")) {
        auto a = d::parse_listen(*v);
        if (!a) {
            return "KYTHIRA_S3_RAFT_LISTEN: expected host:port, got '" + *v + "'";
        }
        c.raft_listen = *a;
    } else {
        for (const auto& [id, addr] : c.raft_peers) {
            if (id == c.node_id) {
                c.raft_listen.port = d::parse_listen(addr)->port;
            }
        }
    }
    if (auto v = get("KYTHIRA_S3_DATA_DIR")) {
        c.data_dir = *v;
    }

    if (auto path = get("KYTHIRA_S3_STATIC_KEYS_FILE")) {
        auto text = d::read_file(*path);
        if (!text) {
            return "KYTHIRA_S3_STATIC_KEYS_FILE: cannot read '" + *path + "'";
        }
        try {
            c.keys = aws_auth::parse_static_keys(*text);
        } catch (const std::invalid_argument& e) {
            return std::string("KYTHIRA_S3_STATIC_KEYS_FILE: ") + e.what();
        }
    }
    c.account_namespaces = d::truthy(get("KYTHIRA_S3_ACCOUNT_NAMESPACES"));
    if (auto path = get("KYTHIRA_S3_SSE_PASSPHRASE_FILE")) {
        auto text = d::read_file(*path);
        if (!text) {
            return "KYTHIRA_S3_SSE_PASSPHRASE_FILE: cannot read '" + *path + "'";
        }
        while (!text->empty() && (text->back() == '\n' || text->back() == '\r')) {
            text->pop_back();
        }
        if (text->empty()) {
            return "KYTHIRA_S3_SSE_PASSPHRASE_FILE: the passphrase is empty";
        }
        c.sse_passphrase = std::move(*text);
    }

    if (auto v = get("KYTHIRA_S3_SERVICE_ENDPOINTS")) {
        for (const auto& item : d::split(*v, ',')) {
            const auto eq = item.find('=');
            const auto service = item.substr(0, eq == std::string::npos ? 0 : eq);
            if (eq == std::string::npos ||
                (service != "kms" && service != "sqs" && service != "sns" && service != "kinesis" &&
                 service != "s3") ||
                !d::is_url(item.substr(eq + 1))) {
                return "KYTHIRA_S3_SERVICE_ENDPOINTS: expected kms|sqs|sns|kinesis|s3=url, got '" +
                       item + "'";
            }
            c.endpoints.by_service[service] = item.substr(eq + 1);
        }
    }
    c.outbound.access_key_id = get("KYTHIRA_S3_OUTBOUND_ACCESS_KEY_ID").value_or("");
    c.outbound.secret_access_key = get("KYTHIRA_S3_OUTBOUND_SECRET_ACCESS_KEY").value_or("");
    c.outbound.session_token = get("KYTHIRA_S3_OUTBOUND_SESSION_TOKEN").value_or("");
    if (c.outbound.access_key_id.empty() != c.outbound.secret_access_key.empty()) {
        return "KYTHIRA_S3_OUTBOUND_ACCESS_KEY_ID and KYTHIRA_S3_OUTBOUND_SECRET_ACCESS_KEY go "
               "together";
    }
    c.outbound_ca = get("KYTHIRA_S3_OUTBOUND_CA").value_or(c.outbound_ca);

    for (const auto& [name, field] : {std::pair<std::string_view, std::chrono::seconds*>{
                                          "KYTHIRA_S3_WORKER_INTERVAL_SECONDS", &c.worker_interval},
                                      {"KYTHIRA_S3_SWEEP_GRACE_SECONDS", &c.sweep_grace}}) {
        if (auto v = get(name)) {
            auto n = d::parse_count(*v);
            if (!n || *n == 0) {
                return std::string(name) + ": expected a positive number of seconds";
            }
            *field = std::chrono::seconds(*n);
        }
    }

    // What the settings add up to.
    const bool front = c.roles.has(role::front_end);
    const bool meta = c.roles.has(role::data);
    if (auto why = check_layout({c.roles, !c.metadata_endpoints.empty()})) {
        return "KYTHIRA_S3_ROLES=" + s3_roles_string(c.roles) + ": " + *why;
    }
    if (c.raft()) {
        if (!meta) {
            return std::string("KYTHIRA_S3_RAFT_PEERS: only metadata nodes run the index group");
        }
        std::vector<std::string> ids;
        for (const auto& [id, addr] : c.raft_peers) {
            if (std::find(ids.begin(), ids.end(), id) != ids.end()) {
                return "KYTHIRA_S3_RAFT_PEERS: member " + id + " is named twice";
            }
            ids.push_back(id);
            const bool has_url =
                std::any_of(c.metadata_endpoints.begin(), c.metadata_endpoints.end(),
                            [&](const auto& e) { return e.first == id; });
            if (!has_url) {
                return "KYTHIRA_S3_METADATA_ENDPOINTS: has no internal listener for member " + id +
                       " of KYTHIRA_S3_RAFT_PEERS (members forward to their leader there)";
            }
        }
        if (std::find(ids.begin(), ids.end(), c.node_id) == ids.end()) {
            return "KYTHIRA_S3_RAFT_PEERS must include this node's own id " + c.node_id;
        }
        for (const auto& [id, url] : c.metadata_endpoints) {
            if (std::find(ids.begin(), ids.end(), id) == ids.end()) {
                return "KYTHIRA_S3_METADATA_ENDPOINTS: " + id +
                       " is not a member in KYTHIRA_S3_RAFT_PEERS; a Raft member's endpoints are "
                       "the group's members";
            }
        }
        if (!c.internal) {
            return std::string(
                "KYTHIRA_S3_INTERNAL_LISTEN: the index group's members reach each other on the "
                "internal listener");
        }
    } else if (meta && !c.metadata_endpoints.empty()) {
        return "KYTHIRA_S3_METADATA_ENDPOINTS: a metadata node without KYTHIRA_S3_RAFT_PEERS "
               "holds its own index group alone; set KYTHIRA_S3_RAFT_PEERS to run it with other "
               "metadata nodes";
    }
    if (front && !c.insecure_plaintext && (c.api_tls.cert.empty() || c.api_tls.key.empty())) {
        return "KYTHIRA_S3_TLS_CERT and KYTHIRA_S3_TLS_KEY are required (or "
               "KYTHIRA_S3_INSECURE_PLAINTEXT=1, for tests only)";
    }
    if (front && c.keys.empty()) {
        return "KYTHIRA_S3_STATIC_KEYS_FILE: the front end needs at least one access key";
    }
    if (c.website && !front) {
        return "KYTHIRA_S3_WEBSITE_LISTEN: the website endpoint is served by the front end";
    }
    if (c.website && c.website_domains.empty()) {
        return "KYTHIRA_S3_WEBSITE_DOMAINS: the website listener needs at least one domain";
    }
    const bool needs_internal_tls = c.internal.has_value() || !c.metadata_endpoints.empty();
    if (needs_internal_tls &&
        (c.internal_tls.cert.empty() || c.internal_tls.key.empty() || c.internal_tls.ca.empty())) {
        return "KYTHIRA_S3_INTERNAL_TLS_CERT, KYTHIRA_S3_INTERNAL_TLS_KEY and "
               "KYTHIRA_S3_INTERNAL_TLS_CA are required for internal calls, which are "
               "authenticated by layer identity";
    }
    if (!front && !c.internal) {
        return "KYTHIRA_S3_INTERNAL_LISTEN: a node without the front end serves only internal "
               "calls, so it needs the internal listener";
    }
    return c;
}

}  // namespace kythira::s3
