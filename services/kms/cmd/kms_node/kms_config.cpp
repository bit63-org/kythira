// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "kms_config.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
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
        return env(name);
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
