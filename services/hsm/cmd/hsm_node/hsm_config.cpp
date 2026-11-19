// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hsm_config.hpp"

#include <pwd.h>
#include <unistd.h>

#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

/// `who=identity,...`, where `who` is a uid or a user name.
auto socket_allow_of(const char* name, const std::string& text)
    -> std::map<std::uint32_t, std::string> {
    std::map<std::uint32_t, std::string> out;
    for (const auto& item : list_of(text)) {
        const auto eq = item.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == item.size()) {
            throw fail(std::string(name) + " expects user=identity[,user=identity...], got '" +
                       item + "'");
        }
        const auto who = item.substr(0, eq);
        std::uint32_t uid = 0;
        if (who.find_first_not_of("0123456789") == std::string::npos) {
            const auto n = to_u64(name, who);
            if (n > UINT32_MAX) {
                throw fail(std::string(name) + ": uid " + who + " is out of range");
            }
            uid = static_cast<std::uint32_t>(n);
        } else {
            passwd pw{};
            passwd* found = nullptr;
            std::vector<char> buf(16384);
            if (::getpwnam_r(who.c_str(), &pw, buf.data(), buf.size(), &found) != 0 ||
                found == nullptr) {
                throw fail(std::string(name) + ": no user " + who);
            }
            uid = static_cast<std::uint32_t>(found->pw_uid);
        }
        if (!out.emplace(uid, item.substr(eq + 1)).second) {
            throw fail(std::string(name) + " names uid " + std::to_string(uid) + " twice");
        }
    }
    return out;
}

/// `host:port,host:port,...`
auto endpoints_of(const char* name, const std::string& text)
    -> std::vector<std::pair<std::string, std::uint16_t>> {
    std::vector<std::pair<std::string, std::uint16_t>> out;
    for (const auto& item : list_of(text)) {
        out.push_back(split_listen(name, item));
    }
    return out;
}

/// `identity=url,...`. An identity (a URI SAN) may itself hold '=', so the
/// split is at the "=http" that starts the URL.
auto identity_urls_of(const char* name, const std::string& text)
    -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    for (const auto& item : list_of(text)) {
        const auto eq = item.rfind("=http");
        if (eq == std::string::npos || eq == 0) {
            throw fail(std::string(name) + " expects identity=https://host:port[,...], got '" +
                       item + "'");
        }
        if (!out.emplace(item.substr(0, eq), item.substr(eq + 1)).second) {
            throw fail(std::string(name) + " names " + item.substr(0, eq) + " twice");
        }
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
    o.share_sealer = get_opt(env, "KYTHIRA_HSM_SHARE_SEALER", "file");
    o.share_key_file =
        env("KYTHIRA_HSM_SHARE_KEY_FILE").value_or((o.data_dir / "share.key").string());
    o.share_key_id = get_opt(env, "KYTHIRA_HSM_SHARE_KEY_ID");
    o.share_kms_region = get_opt(env, "KYTHIRA_HSM_SHARE_KMS_REGION");
    o.share_kms_endpoint = get_opt(env, "KYTHIRA_HSM_SHARE_KMS_ENDPOINT");
    o.share_kms_ca = get_opt(env, "KYTHIRA_HSM_SHARE_KMS_CA");
    o.share_pkcs11_uri = get_opt(env, "KYTHIRA_HSM_SHARE_PKCS11_URI");
    o.share_pkcs11_oaep = get_opt(env, "KYTHIRA_HSM_SHARE_PKCS11_OAEP", "sha256");
    if (o.share_sealer == "aws-kms") {
        if (o.share_key_id.empty() || o.share_kms_region.empty()) {
            throw fail(
                "KYTHIRA_HSM_SHARE_SEALER=aws-kms needs KYTHIRA_HSM_SHARE_KEY_ID and "
                "KYTHIRA_HSM_SHARE_KMS_REGION");
        }
    } else if (o.share_sealer == "pkcs11") {
        // The co-located HSM cannot seal its own share: the token it would
        // use opens only once the HSM is unsealed.
        if (o.share_key_id.empty() ||
            o.share_pkcs11_uri.find("module-path=") == std::string::npos) {
            throw fail(
                "KYTHIRA_HSM_SHARE_SEALER=pkcs11 needs KYTHIRA_HSM_SHARE_KEY_ID and a "
                "KYTHIRA_HSM_SHARE_PKCS11_URI naming its library (module-path=)");
        }
        if (o.share_pkcs11_oaep != "sha256" && o.share_pkcs11_oaep != "sha1") {
            throw fail("KYTHIRA_HSM_SHARE_PKCS11_OAEP must be sha256 or sha1");
        }
    } else if (o.share_sealer == "azure-key-vault") {
        if (!o.share_key_id.starts_with("https://") ||
            o.share_key_id.find("/keys/") == std::string::npos) {
            throw fail(
                "KYTHIRA_HSM_SHARE_SEALER=azure-key-vault needs KYTHIRA_HSM_SHARE_KEY_ID, the "
                "key's URL (https://<vault>.vault.azure.net/keys/<name>)");
        }
        o.share_azure_algorithm = get_opt(env, "KYTHIRA_HSM_SHARE_AZURE_ALGORITHM", "RSA-OAEP-256");
        if (o.share_azure_algorithm != "RSA-OAEP-256" && o.share_azure_algorithm != "A256KW") {
            throw fail("KYTHIRA_HSM_SHARE_AZURE_ALGORITHM must be RSA-OAEP-256 or A256KW");
        }
    } else if (o.share_sealer == "gcp-kms") {
        if (!o.share_key_id.starts_with("projects/") ||
            o.share_key_id.find("/cryptoKeys/") == std::string::npos) {
            throw fail(
                "KYTHIRA_HSM_SHARE_SEALER=gcp-kms needs KYTHIRA_HSM_SHARE_KEY_ID, the crypto "
                "key's name (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>)");
        }
    } else if (o.share_sealer == "tpm2") {
#ifdef KYTHIRA_HSM_TPM2
        if (o.share_key_id.empty()) {
            o.share_key_id = "owner";
        }
        o.share_tpm2_tcti = get_opt(env, "KYTHIRA_HSM_SHARE_TPM2_TCTI", "device:/dev/tpmrm0");
        o.share_tpm2_pcrs = get_opt(env, "KYTHIRA_HSM_SHARE_TPM2_PCRS");
        if (o.share_key_id != "owner" && !o.share_key_id.starts_with("0x81")) {
            throw fail(
                "KYTHIRA_HSM_SHARE_KEY_ID for tpm2 is owner (default) or a persistent handle "
                "(0x81xxxxxx)");
        }
#else
        throw fail("KYTHIRA_HSM_SHARE_SEALER=tpm2: this build has no TPM support (tpm2-tss)");
#endif
    } else if (o.share_sealer != "file") {
        throw fail(
            "KYTHIRA_HSM_SHARE_SEALER must be file, aws-kms, pkcs11, azure-key-vault, gcp-kms "
            "or tpm2");
    }

    o.insecure_plaintext = bool_opt(env, "KYTHIRA_HSM_INSECURE_PLAINTEXT", false);
    if (const auto roles = env("KYTHIRA_HSM_ROLES")) {
        o.roles = kythira::hsm::parse_hsm_roles(*roles);
    }
    const kythira::hsm::hsm_role_plan plan{o.roles};
    o.api_urls = id_map("KYTHIRA_HSM_API_URLS", get_required(env, "KYTHIRA_HSM_API_URLS"));
    if (plan.runs_store() && !o.api_urls.contains(o.node_id)) {
        throw fail("KYTHIRA_HSM_API_URLS must include this node's own id " +
                   kythira::host_node_id_text(o.node_id));
    }
    if (!plan.runs_store() && o.api_urls.contains(o.node_id)) {
        throw fail(
            "KYTHIRA_HSM_API_URLS lists this node, but without the store role it is "
            "no member of the HSM's groups (KYTHIRA_HSM_ROLES=" +
            kythira::hsm::hsm_role_names(o.roles) + ")");
    }
    const std::string scheme = o.insecure_plaintext ? "http://" : "https://";
    for (const auto& [id, url] : o.api_urls) {
        if (!url.starts_with(scheme)) {
            throw fail("KYTHIRA_HSM_API_URLS: " + url + " is not an " + scheme +
                       " URL (plaintext only with KYTHIRA_HSM_INSECURE_PLAINTEXT)");
        }
    }
    o.relay_backends =
        endpoints_of("KYTHIRA_HSM_RELAY_BACKENDS", get_opt(env, "KYTHIRA_HSM_RELAY_BACKENDS"));
    if (!o.relay_backends.empty() && !plan.relays_clients()) {
        throw fail(
            "KYTHIRA_HSM_RELAY_BACKENDS is set, but only an endpoint without the crypto "
            "role relays (KYTHIRA_HSM_ROLES=" +
            kythira::hsm::hsm_role_names(o.roles) + ")");
    }
    o.store_clients = list_of(get_opt(env, "KYTHIRA_HSM_STORE_CLIENTS"));
    o.crypto_urls =
        identity_urls_of("KYTHIRA_HSM_CRYPTO_URLS", get_opt(env, "KYTHIRA_HSM_CRYPTO_URLS"));
    for (const auto& [identity, url] : o.crypto_urls) {
        if (!url.starts_with(scheme)) {
            throw fail("KYTHIRA_HSM_CRYPTO_URLS: " + url + " is not an " + scheme + " URL");
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

    const auto client_listen = get_opt(env, "KYTHIRA_HSM_CLIENT_LISTEN", "0.0.0.0:9444");
    if (plan.relays_clients()) {
        // An endpoint without crypto relays this listener at layer 4 and
        // never sees the TLS inside, plaintext or not (hsm-independent-
        // layers Requirement 6).
        if (client_listen == "off") {
            throw fail(
                "KYTHIRA_HSM_CLIENT_LISTEN is off, but an endpoint without the crypto "
                "role relays clients on it");
        }
        o.client_listen = split_listen("KYTHIRA_HSM_CLIENT_LISTEN", client_listen);
    } else if (client_listen == "off" || o.insecure_plaintext) {
        // Plaintext has no client identity to bind tokens to: the socket
        // is the only way in then.
        o.client_listen.reset();
    } else {
        o.client_listen = split_listen("KYTHIRA_HSM_CLIENT_LISTEN", client_listen);
    }
    o.app_ca = get_opt(env, "KYTHIRA_HSM_APP_CA", o.client_ca);
    o.socket_path = get_opt(env, "KYTHIRA_HSM_SOCKET");
    if (!o.socket_path.empty() && !plan.runs_crypto()) {
        throw fail(
            "KYTHIRA_HSM_SOCKET: the Unix socket serves clients on this host from its "
            "own crypto layer, and KYTHIRA_HSM_ROLES=" +
            kythira::hsm::hsm_role_names(o.roles) + " has none");
    }
    o.socket_allow =
        socket_allow_of("KYTHIRA_HSM_SOCKET_ALLOW", get_opt(env, "KYTHIRA_HSM_SOCKET_ALLOW"));
    if (!o.socket_path.empty() && o.socket_allow.empty()) {
        throw fail(
            "KYTHIRA_HSM_SOCKET needs KYTHIRA_HSM_SOCKET_ALLOW: with no uid allowed, "
            "the socket would serve nobody");
    }
    o.client_max_connections =
        u64_opt(env, "KYTHIRA_HSM_CLIENT_MAX_CONNECTIONS", o.client_max_connections);
    if (o.client_max_connections == 0) {
        throw fail("KYTHIRA_HSM_CLIENT_MAX_CONNECTIONS must be at least 1");
    }
    o.client_idle_timeout =
        std::chrono::seconds{u64_opt(env, "KYTHIRA_HSM_CLIENT_IDLE_TIMEOUT_S",
                                     static_cast<std::uint64_t>(o.client_idle_timeout.count()))};
    if (o.client_idle_timeout.count() == 0) {
        throw fail("KYTHIRA_HSM_CLIENT_IDLE_TIMEOUT_S must be at least 1");
    }

    o.allow_unlocked_memory = bool_opt(env, "KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY", false);
    o.allow_single_share = bool_opt(env, "KYTHIRA_HSM_ALLOW_SINGLE_SHARE", false);
    o.unseal_timeout = std::chrono::seconds{
        u64_opt(env, "KYTHIRA_HSM_UNSEAL_TIMEOUT_S", static_cast<std::uint64_t>(600))};
    if (o.unseal_timeout.count() == 0) {
        throw fail("KYTHIRA_HSM_UNSEAL_TIMEOUT_S must be at least 1");
    }
    o.audit = get_opt(env, "KYTHIRA_HSM_AUDIT", o.audit);
    const bool audit_file = o.audit.starts_with("file:") && o.audit.size() > 5;
    if (o.audit != "stderr" && o.audit != "off" && !audit_file) {
        throw fail("KYTHIRA_HSM_AUDIT must be stderr, off or file:<path>");
    }
    o.audit_sample_every = u64_opt(env, "KYTHIRA_HSM_AUDIT_SAMPLE_EVERY", o.audit_sample_every);
    if (o.audit_sample_every == 0) {
        throw fail("KYTHIRA_HSM_AUDIT_SAMPLE_EVERY must be at least 1");
    }
    o.audit_ledger_url = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER_URL");
    const bool ledger_plaintext = o.insecure_plaintext && o.audit_ledger_url.starts_with("http://");
    if (!o.audit_ledger_url.empty() && !o.audit_ledger_url.starts_with("https://") &&
        !ledger_plaintext) {
        throw fail("KYTHIRA_HSM_AUDIT_LEDGER_URL must be an https:// URL");
    }
    o.audit_ledger = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER", o.audit_ledger);
    o.audit_ledger_table = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER_TABLE", o.audit_ledger_table);
    o.audit_ledger_cert = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER_CERT", o.tls_cert);
    o.audit_ledger_key = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER_KEY", o.tls_key);
    o.audit_ledger_ca = get_opt(env, "KYTHIRA_HSM_AUDIT_LEDGER_CA", o.client_ca);
    o.iam = bool_opt(env, "KYTHIRA_HSM_IAM", o.iam);
    o.iam_partition = get_opt(env, "KYTHIRA_HSM_IAM_PARTITION", o.iam_partition);
    o.iam_region = get_opt(env, "KYTHIRA_HSM_IAM_REGION", o.iam_region);
    if (o.iam_partition.empty() || o.iam_region.empty() ||
        o.iam_partition.find(':') != std::string::npos ||
        o.iam_region.find(':') != std::string::npos) {
        throw fail("KYTHIRA_HSM_IAM_PARTITION and _REGION must be non-empty and hold no ':'");
    }
    o.iam_cache = std::chrono::milliseconds{
        u64_opt(env, "KYTHIRA_HSM_IAM_CACHE_MS", static_cast<std::uint64_t>(o.iam_cache.count()))};
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

    kythira::hsm::hsm_role_inputs in;
    in.roles = o.roles;
    in.has_store_urls = !o.api_urls.empty();
    in.has_relay_backends = !o.relay_backends.empty();
    // The TLS files are required above unless KYTHIRA_HSM_INSECURE_PLAINTEXT
    // (tests), which covers every listener.
    in.has_peer_tls = true;
    in.has_raft_peers = plan.runs_store();  // checked above: this node is among them
    if (auto why = kythira::hsm::check_hsm_roles(in)) {
        throw fail(*why);
    }
    if (plan.uses_remote_store()) {
        throw fail("KYTHIRA_HSM_ROLES=" + kythira::hsm::hsm_role_names(o.roles) +
                   ": a crypto node without the store role (remote_hsm_store) is not wired "
                   "into hsm_node yet; add store");
    }
    return o;
}

auto usage_text() -> std::string_view {
    return R"(The HSM module (KYTHIRA_SERVICES=hsm):

  KYTHIRA_NODE_ID                    this node's id (required)
  KYTHIRA_HSM_ROLES                  the layers this node runs: endpoint,
                                     crypto, store (all three). Without crypto
                                     it is never unsealed, holds no share and
                                     serves no PKCS#11 client; without store
                                     it is no group member
  KYTHIRA_HSM_API_URLS               id=https://host:port for every member, this
                                     node included when it has the store role
                                     (required): the voters of every HSM group
                                     and where followers forward
  KYTHIRA_HSM_RELAY_BACKENDS         host:port,... : the crypto nodes' client
                                     listeners an endpoint without crypto
                                     relays KYTHIRA_HSM_CLIENT_LISTEN to
  KYTHIRA_HSM_STORE_CLIENTS          crypto identities that may use this
                                     member's store API without membership
  KYTHIRA_HSM_CRYPTO_URLS            identity=https://host:port,... for every
                                     crypto node, once the catalog's crypto
                                     member list is seeded: where init and
                                     rekey deliver shares and node unseal
                                     asks for them; the seed is these
                                     identities (else the members')
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
  KYTHIRA_HSM_CLIENT_LISTEN          host:port of the PKCS#11 clients' mutual
                                     TLS listener, or off (0.0.0.0:9444; off
                                     with plaintext)
  KYTHIRA_HSM_APP_CA                 the CA client certificates chain to
                                     (default: KYTHIRA_HSM_CLIENT_CA); a
                                     client is its first URI SAN, else its
                                     first DNS SAN
  KYTHIRA_HSM_SOCKET                 a Unix socket for clients on this host
  KYTHIRA_HSM_SOCKET_ALLOW           user=identity,... : the uids (or user
                                     names) the socket serves, and the
                                     identity each acts as
  KYTHIRA_HSM_CLIENT_MAX_CONNECTIONS client connections at once (256)
  KYTHIRA_HSM_CLIENT_IDLE_TIMEOUT_S  an idle client connection is closed (3600)
  KYTHIRA_HSM_DATA_DIR               state (the node's hsm/ in kythira_node)
  KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY  start where key memory cannot be locked
                                     (development only; false)
  KYTHIRA_HSM_MAX_LOGIN_FAILURES     failed logins before a PIN locks (10)
  KYTHIRA_HSM_ALLOW_SINGLE_SHARE     permit k = 1 at init and rekey
                                     (development only)
  KYTHIRA_HSM_UNSEAL_TIMEOUT_S       seconds partial operator shares are
                                     held before they are discarded (600)
  KYTHIRA_HSM_AUDIT                  audit lines to stderr (default), off, or
                                     file:<path> (appended)
  KYTHIRA_HSM_AUDIT_SAMPLE_EVERY     signing, verification and encryption are
                                     counted per client and key; one call in
                                     this many is logged (1000)
  KYTHIRA_HSM_AUDIT_LEDGER_URL       also append every audit line to this
                                     verifiable ledger (https://host:port)
  KYTHIRA_HSM_AUDIT_LEDGER           its ledger name (hsm_audit); _TABLE the
                                     table (audit); _CERT, _KEY and _CA the
                                     client TLS files (the node's own)
  KYTHIRA_HSM_IAM                    authorize clients whose identity is an IAM
                                     user or role ARN with hsm: actions on
                                     arn:<partition>:hsm:<region>:<account>:
                                     token/<id> (needs IAM co-located; false)
  KYTHIRA_HSM_IAM_PARTITION          the ARN's partition (aws); _REGION its
                                     region (local); _CACHE_MS how long a
                                     decision is kept (10000)
  KYTHIRA_HSM_SHARE_SEALER           how this node's node-unseal share is
                                     sealed at rest: file (default), aws-kms,
                                     pkcs11 (an external token),
                                     azure-key-vault, gcp-kms or tpm2
  KYTHIRA_HSM_SHARE_KEY_FILE         the file sealer's key, created 0600 on
                                     first use (data dir/share.key)
  KYTHIRA_HSM_SHARE_KEY_ID           aws-kms: the KMS key (id, ARN or alias);
                                     pkcs11: the RSA key's label;
                                     azure-key-vault: the key's URL;
                                     gcp-kms: projects/.../cryptoKeys/<k>;
                                     tpm2: owner (default) or 0x81xxxxxx
  KYTHIRA_HSM_SHARE_KMS_REGION       aws-kms: the region (required); _ENDPOINT
                                     host:port (AWS's); _CA its CA (system);
                                     credentials from AWS_ACCESS_KEY_ID,
                                     AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
                                     (_ENDPOINT and _CA also serve gcp-kms,
                                     an https:// URL, and _CA azure-key-vault)
  KYTHIRA_HSM_SHARE_AZURE_ALGORITHM  azure-key-vault: RSA-OAEP-256 (default)
                                     or A256KW (a Managed HSM's AES key);
                                     token from AZURE_ACCESS_TOKEN, else
                                     AZURE_TENANT_ID + AZURE_CLIENT_ID +
                                     AZURE_CLIENT_SECRET, else the managed
                                     identity
                                     gcp-kms: token from
                                     GOOGLE_OAUTH_ACCESS_TOKEN, else
                                     GOOGLE_APPLICATION_CREDENTIALS (a
                                     service account key), else the
                                     metadata server
  KYTHIRA_HSM_SHARE_TPM2_TCTI        tpm2: the TPM (device:/dev/tpmrm0)
  KYTHIRA_HSM_SHARE_TPM2_PCRS        tpm2: PCRs new seals are bound to, e.g.
                                     sha256:0,2,4,7 (none)
  KYTHIRA_HSM_SHARE_PKCS11_URI       pkcs11: pkcs11:token=...;module-path=...
                                     ?pin-source=... (required)
  KYTHIRA_HSM_SHARE_PKCS11_OAEP      pkcs11: sha256 (default) or sha1
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
