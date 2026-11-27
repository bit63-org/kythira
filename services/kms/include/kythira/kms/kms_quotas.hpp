// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AWS's per-account KMS request quotas (.kiro/specs/kms-compatible-api/
// task 14, Requirement 13.3), answering ThrottlingException.
//
// As on AWS, the quotas throttle the account that makes the request, not
// the account that owns the key, and they are independent of each other:
//
//   - the shared cryptographic operation quotas, by the key's type:
//     symmetric (with HMAC, and GenerateRandom, which names no key), RSA
//     and ECC. Encrypt, Decrypt, ReEncrypt, GenerateDataKey(WithoutPlain-
//     text), GenerateMac, VerifyMac, Sign and Verify count against the
//     quota of the key they use, once per request (ReEncrypt counts the
//     source key, the first one it authorizes);
//   - GenerateDataKeyPair(WithoutPlaintext), by the pair's spec, outside
//     the shared quotas;
//   - each other operation's own rate (DescribeKey 2000/s, CreateKey 5/s
//     and so on).
//
// The defaults are AWS's in us-east-1; regions with lower defaults, and
// any account an operator raises or lowers, are set by override
// (KYTHIRA_KMS_QUOTAS, KYTHIRA_KMS_ACCOUNT_QUOTAS).
//
// No Raft write happens on the hot path, so the counters are per member:
// each refills at the account's rate divided by the serving members and
// holds up to one second of the account's whole rate. A client spread
// evenly over the members is held to the quota; one that bursts to every
// member at once can briefly reach the quota times the member count.

#include <kythira/kms/kms_catalog.hpp>

#include <raft/service_module.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// The shared cryptographic operation quotas, requests per second.
struct shared_quotas {
    double symmetric = 100000;
    double rsa = 1000;
    double ecc = 1000;

    auto operator==(const shared_quotas&) const -> bool = default;
};

/// Each other operation's own default rate, as AWS lists them.
struct operation_rate {
    std::string_view operation;
    double per_second;
};

inline constexpr std::array<operation_rate, 43> k_operation_rates = {{
    {"DescribeKey", 2000},
    {"GetPublicKey", 2000},
    {"ListResourceTags", 2000},
    {"GetKeyPolicy", 1000},
    {"GetKeyRotationStatus", 1000},
    {"ListAliases", 500},
    {"ListKeys", 500},
    {"ListGrants", 100},
    {"ListKeyPolicies", 100},
    {"ListKeyRotations", 100},
    {"ListRetirableGrants", 100},
    {"CreateGrant", 50},
    {"RetireGrant", 50},
    {"RevokeGrant", 50},
    {"DeleteAlias", 15},
    {"DeleteImportedKeyMaterial", 15},
    {"EnableKeyRotation", 15},
    {"ImportKeyMaterial", 15},
    {"PutKeyPolicy", 15},
    {"ScheduleKeyDeletion", 15},
    {"TagResource", 10},
    {"CreateKey", 5},
    {"CreateAlias", 5},
    {"UpdateAlias", 5},
    {"ReplicateKey", 5},
    {"EnableKey", 5},
    {"DisableKey", 5},
    {"DisableKeyRotation", 5},
    {"CancelKeyDeletion", 5},
    {"UpdateKeyDescription", 5},
    {"UpdatePrimaryRegion", 5},
    {"RotateKeyOnDemand", 5},
    {"UntagResource", 5},
    {"CreateCustomKeyStore", 5},
    {"ConnectCustomKeyStore", 5},
    {"DeleteCustomKeyStore", 5},
    {"DescribeCustomKeyStores", 5},
    {"DisconnectCustomKeyStore", 5},
    {"UpdateCustomKeyStore", 5},
    {"GetParametersForImport", 1},
    // GenerateDataKeyPair's own quota, by the pair's spec (below); these
    // two entries only mark the operations as counted here.
    {"GenerateDataKeyPair", 0},
    {"GenerateDataKeyPairWithoutPlaintext", 0},
    // GenerateRandom names no key: it counts against the symmetric quota.
    {"GenerateRandom", 0},
}};

/// GenerateDataKeyPair's rate for a pair spec.
[[nodiscard]] inline auto data_key_pair_rate(std::string_view spec) -> double {
    if (spec == "RSA_2048") {
        return 20;
    }
    if (spec == "RSA_3072") {
        return 4;
    }
    if (spec == "RSA_4096") {
        return 1;
    }
    return 100;  // the ECC specs
}

/// The operations that count against the quota of the key they use.
[[nodiscard]] inline auto is_shared_crypto_operation(std::string_view op) -> bool {
    constexpr std::array<std::string_view, 10> ops = {"Decrypt",
                                                      "Encrypt",
                                                      "GenerateDataKey",
                                                      "GenerateDataKeyWithoutPlaintext",
                                                      "GenerateMac",
                                                      "ReEncrypt",
                                                      "Sign",
                                                      "Verify",
                                                      "VerifyMac",
                                                      "DeriveSharedSecret"};
    return std::find(ops.begin(), ops.end(), op) != ops.end();
}

struct quota_config {
    shared_quotas defaults;
    /// Per-account overrides of the shared quotas.
    std::map<std::string, shared_quotas, std::less<>> accounts;
    /// The members serving requests; each holds 1/members of the rate.
    std::size_t members = 1;
};

/// "sym:rsa:ecc" (each a positive number of requests per second).
[[nodiscard]] inline auto parse_shared_quotas(std::string_view text)
    -> std::optional<shared_quotas> {
    std::array<double, 3> v{};
    for (std::size_t i = 0; i < v.size(); ++i) {
        const auto colon = text.find(':');
        const auto part = text.substr(0, colon);
        if (part.empty() || (i < 2) != (colon != std::string_view::npos)) {
            return std::nullopt;
        }
        std::size_t used = 0;
        try {
            v.at(i) = std::stod(std::string(part), &used);
        } catch (const std::exception&) {
            return std::nullopt;
        }
        if (used != part.size() || !(v.at(i) > 0)) {
            return std::nullopt;
        }
        text = colon == std::string_view::npos ? std::string_view() : text.substr(colon + 1);
    }
    return shared_quotas{v[0], v[1], v[2]};
}

/// The per-member counters. Thread-safe.
class request_quotas {
public:
    using clock_ms = std::function<std::int64_t()>;

    explicit request_quotas(quota_config config, clock_ms now = steady_ms)
        : _config(std::move(config)), _now(std::move(now)) {
        _config.members = std::max<std::size_t>(_config.members, 1);
        _members.store(_config.members);
    }

    /// Changes how many members share the quotas (at least one): the live
    /// front ends, as their count changes (kms-independent-layers task 4,
    /// Requirement 7). Buckets keep their tokens; only the refill rate
    /// changes.
    void set_members(std::size_t n) { _members.store(std::max<std::size_t>(n, 1)); }

    [[nodiscard]] auto members() const -> std::size_t { return _members.load(); }

    /// Admits `op` by `account` before its handler runs: false when its
    /// own quota is spent. A shared cryptographic operation is admitted
    /// later, by admit_key_use, once its key is known.
    [[nodiscard]] auto admit_operation(std::string_view account, std::string_view op,
                                       const boost::json::object& body) -> bool {
        if (op == "GenerateRandom") {
            return take(account, "symmetric", shared(account).symmetric);
        }
        if (op == "GenerateDataKeyPair" || op == "GenerateDataKeyPairWithoutPlaintext") {
            std::string spec;
            if (const auto* s = body.if_contains("KeyPairSpec"); s != nullptr && s->is_string()) {
                spec = std::string(s->get_string());
            }
            return take(account, "GenerateDataKeyPair:" + spec, data_key_pair_rate(spec));
        }
        for (const auto& r : k_operation_rates) {
            if (r.operation == op) {
                return take(account, std::string(op), r.per_second);
            }
        }
        return true;
    }

    /// Admits a shared cryptographic operation on a key of `spec`.
    [[nodiscard]] auto admit_key_use(std::string_view account, std::string_view op, key_spec spec)
        -> bool {
        if (!is_shared_crypto_operation(op)) {
            return true;
        }
        const auto q = shared(account);
        switch (spec) {
            case key_spec::rsa_2048:
            case key_spec::rsa_3072:
            case key_spec::rsa_4096:
                return take(account, "rsa", q.rsa);
            case key_spec::ecc_nist_p256:
            case key_spec::ecc_nist_p384:
            case key_spec::ecc_nist_p521:
            case key_spec::ecc_secg_p256k1:
                return take(account, "ecc", q.ecc);
            default:
                return take(account, "symmetric", q.symmetric);
        }
    }

    /// Throttled requests by account and quota, as module metrics.
    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> {
        std::vector<service_node::module_metric> out;
        const std::scoped_lock lock(_mu);
        for (const auto& [k, n] : _throttled) {
            out.push_back({"throttled_requests",
                           static_cast<double>(n),
                           {{"account", k.first}, {"quota", k.second}}});
        }
        return out;
    }

    [[nodiscard]] static auto steady_ms() -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

private:
    struct bucket {
        double tokens = 0;
        std::int64_t at_ms = 0;
    };

    [[nodiscard]] auto shared(std::string_view account) const -> shared_quotas {
        const auto it = _config.accounts.find(account);
        return it == _config.accounts.end() ? _config.defaults : it->second;
    }

    /// One request against `account`'s `quota` at `rate` per second.
    auto take(std::string_view account, const std::string& quota, double rate) -> bool {
        const auto now = _now();
        const auto per_member = rate / static_cast<double>(_members.load());
        const std::scoped_lock lock(_mu);
        auto key = std::make_pair(std::string(account), quota);
        auto [it, fresh] = _buckets.try_emplace(key, bucket{rate, now});
        auto& b = it->second;
        if (!fresh && now > b.at_ms) {
            b.tokens =
                std::min(rate, b.tokens + per_member * static_cast<double>(now - b.at_ms) / 1000.0);
            b.at_ms = now;
        }
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return true;
        }
        ++_throttled[std::move(key)];
        return false;
    }

    quota_config _config;
    std::atomic<std::size_t> _members{1};
    clock_ms _now;
    mutable std::mutex _mu;
    std::map<std::pair<std::string, std::string>, bucket> _buckets;
    std::map<std::pair<std::string, std::string>, std::uint64_t> _throttled;
};

}  // namespace kythira::kms
