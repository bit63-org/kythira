// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// IAM authorization for tokens (.kiro/specs/virtual-hsm/ task 14b,
// Requirement 8.4): when IAM is co-located or reachable, a client whose
// identity is an IAM user or role ARN is authorized by IAM policy instead
// of by the catalog's bindings, with `hsm:` actions on the token's ARN
//
//   arn:<partition>:hsm:<region>:<account>:token/<id>
//
// where <account> is the principal's own, so a policy in account A grants
// A's principals tokens by id. The identity is what the transport proved:
// a client certificate's first URI SAN (wire_server.hpp), so the CA the
// node trusts for clients vouches for the ARN exactly as it vouches for
// any other name a binding could use. A role ARN acts as a session of
// that role named `hsm`; a user ARN as that user. Every other identity
// (a SPIFFE name, a DNS name, a socket uid's name, a co-located module)
// stays with the bindings.
//
// Decisions are kept for `cache_ttl` (10 s by default), so a signing loop
// does not evaluate policy on every call and a policy change takes effect
// within that time.

#include <raft/aws_request_authorizer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::hsm {

/// The `hsm` actions, for `iam_evaluator::add_actions`. Each acts on a
/// token; there are no service condition keys.
[[nodiscard]] inline auto hsm_actions() -> aws_auth::aws_action_table {
    static constexpr std::string_view token =
        "arn:${Partition}:hsm:${Region}:${Account}:token/${TokenId}";
    aws_auth::aws_action_table t;
    t.service_prefix = "hsm";
    for (const auto* name :
         {"OpenToken", "InitToken", "InitPIN", "SetPIN", "GenerateKey", "CreateObject",
          "CopyObject", "DeriveKey", "WrapKey", "UnwrapKey", "DestroyObject", "SetAttributeValue",
          "Sign", "Verify", "Encrypt", "Decrypt"}) {
        t.actions.push_back({name, {std::string(token)}, {}});
    }
    return t;
}

/// The principal an identity names when it is an IAM user or role ARN
/// (`arn:P:iam::A:user/...` or `arn:P:iam::A:role/...`); nullopt for any
/// other identity.
[[nodiscard]] inline auto iam_principal(std::string_view identity)
    -> std::optional<aws_auth::principal_context> {
    // arn : partition : iam : (empty region) : account : resource
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    for (int i = 0; i < 5; ++i) {
        const auto colon = identity.find(':', start);
        if (colon == std::string_view::npos) {
            return std::nullopt;
        }
        parts.push_back(identity.substr(start, colon - start));
        start = colon + 1;
    }
    const auto resource = identity.substr(start);
    if (parts[0] != "arn" || parts[1].empty() || parts[2] != "iam" || !parts[3].empty() ||
        parts[4].size() != 12 ||
        parts[4].find_first_not_of("0123456789") != std::string_view::npos) {
        return std::nullopt;
    }
    const auto slash = resource.rfind('/');
    if (slash == std::string_view::npos || slash + 1 == resource.size()) {
        return std::nullopt;
    }
    const auto name = resource.substr(slash + 1);
    aws_auth::principal_context p;
    p.account = std::string(parts[4]);
    if (resource.starts_with("user/")) {
        p.type = aws_auth::principal_type::user;
        p.arn = std::string(identity);
        p.username = std::string(name);
        return p;
    }
    if (resource.starts_with("role/")) {
        p.type = aws_auth::principal_type::assumed_role;
        p.role_arn = std::string(identity);
        p.role_name = std::string(name);
        p.session_name = "hsm";
        p.arn = "arn:" + std::string(parts[1]) + ":sts::" + p.account + ":assumed-role/" +
                std::string(name) + "/hsm";
        return p;
    }
    return std::nullopt;
}

struct iam_token_config {
    std::string partition = "aws";
    std::string region = "local";
    std::chrono::milliseconds cache_ttl{10000};
    /// Decisions kept; the cache is emptied when it is full.
    std::size_t max_cached = 65536;
};

/// The session layer's token_authorizer over IAM's policy evaluation.
class iam_token_authorizer {
public:
    using authorize_fn = std::function<aws_auth::authz_decision(const aws_auth::principal_context&,
                                                                const aws_auth::authz_request&)>;
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    iam_token_authorizer(iam_token_config config, authorize_fn authorize, clock_fn clock = {})
        : _cfg(std::move(config)),
          _authorize(std::move(authorize)),
          _clock(clock ? std::move(clock) : [] { return std::chrono::steady_clock::now(); }) {}

    /// The token's ARN in `account`.
    [[nodiscard]] auto token_arn(std::string_view account, std::uint64_t token) const
        -> std::string {
        return "arn:" + _cfg.partition + ":hsm:" + _cfg.region + ":" + std::string(account) +
               ":token/" + std::to_string(token);
    }

    /// True or false for an IAM identity; nullopt for any other.
    [[nodiscard]] auto operator()(std::string_view identity, std::uint64_t token,
                                  std::string_view action) -> std::optional<bool> {
        auto who = iam_principal(identity);
        if (!who) {
            return std::nullopt;
        }
        const auto now = _clock();
        auto key = std::make_tuple(std::string(identity), token, std::string(action));
        {
            const std::scoped_lock lock(_mu);
            if (const auto it = _cache.find(key); it != _cache.end() && now < it->second.second) {
                return it->second.first;
            }
        }
        aws_auth::authz_request r;
        r.action = std::string(action);
        r.resource = token_arn(who->account, token);
        r.region = _cfg.region;
        const bool allowed = _authorize(*who, r).allowed;
        const std::scoped_lock lock(_mu);
        if (_cache.size() >= _cfg.max_cached) {
            _cache.clear();
        }
        _cache[std::move(key)] = {allowed, now + _cfg.cache_ttl};
        return allowed;
    }

private:
    iam_token_config _cfg;
    authorize_fn _authorize;
    clock_fn _clock;
    std::mutex _mu;
    std::map<std::tuple<std::string, std::uint64_t, std::string>,
             std::pair<bool, std::chrono::steady_clock::time_point>>
        _cache;
};

}  // namespace kythira::hsm
