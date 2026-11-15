// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AWS managed keys (.kiro/specs/kms-compatible-api/ task 13, Requirements
// 10.1 and 10.2): `alias/aws/kinesis` and `alias/aws/dynamodb`, made in an
// account the first time a request names them, as AWS makes its managed
// keys on first use (DescribeKey on the alias included).
//
// A managed key has AWS's managed key policy: the account's principals
// may use it only through its service (kms:ViaService and
// kms:CallerAccount), and the account may read its metadata. The catalog
// marks it KeyManager AWS, which refuses every change a customer could
// ask for, never deletes it, and rotates it yearly from the moment it is
// complete.
//
// Making one is idempotent across members and leader changes: the key id
// is derived from the account and service, so two first uses at once
// propose the same key and one CreateKey is rejected as already made; the
// alias, made last, is what makes the key visible under its name. A
// derived id whose creation failed is tombstoned like any other, so the
// next attempt number derives the next id.

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kms {

/// The Kythira services that have an AWS managed key, by the name in
/// `alias/aws/<service>` and in kms:ViaService.
struct managed_service {
    std::string_view name;
    /// As AWS names the service in the key's description and policy.
    std::string_view display;
};

inline constexpr std::array<managed_service, 2> k_managed_services = {{
    {"dynamodb", "Amazon DynamoDB"},
    {"kinesis", "Amazon Kinesis"},
}};

inline constexpr std::string_view k_managed_alias_prefix = "alias/aws/";

/// How many derived ids are tried before giving up.
inline constexpr unsigned k_managed_attempts = 8;

/// The service `alias` (`alias/aws/<service>`) is the managed key of, or
/// nothing.
[[nodiscard]] inline auto managed_service_of(std::string_view alias)
    -> std::optional<managed_service> {
    if (!alias.starts_with(k_managed_alias_prefix)) {
        return std::nullopt;
    }
    const auto name = alias.substr(k_managed_alias_prefix.size());
    for (const auto& s : k_managed_services) {
        if (s.name == name) {
            return s;
        }
    }
    return std::nullopt;
}

/// The key id of `service`'s managed key in `account` on try `attempt`: a
/// UUID (version 8) from SHA-256, so every member derives the same one.
[[nodiscard]] inline auto managed_key_id(std::string_view account, std::string_view service,
                                         unsigned attempt) -> std::string {
    std::string in = "kythira-kms-managed-key";
    in.push_back('\0');
    in.append(account);
    in.push_back('\0');
    in.append(service);
    in.push_back('\0');
    in.append(std::to_string(attempt));
    std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
    SHA256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d.data());  // NOLINT
    d[6] = static_cast<unsigned char>((d[6] & 0x0FU) | 0x80U);
    d[8] = static_cast<unsigned char>((d[8] & 0x3FU) | 0x80U);
    std::array<char, 37> out{};
    std::snprintf(out.data(), out.size(),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", d[0],
                  d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13],
                  d[14], d[15]);
    return out.data();
}

/// AWS's managed key policy for `service` in `account`: use only through
/// the service by the account's principals, and the account's direct
/// access to the key's metadata.
[[nodiscard]] inline auto managed_key_policy(std::string_view partition, std::string_view region,
                                             std::string_view account,
                                             const managed_service& service) -> std::string {
    const std::string acct(account);
    const std::string svc(service.name);
    std::string actions = R"("kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*",)"
                          R"("kms:DescribeKey")";
    if (service.name == "dynamodb") {
        actions += R"(,"kms:CreateGrant")";  // as AWS's alias/aws/dynamodb policy
    }
    return R"({"Version":"2012-10-17","Id":"auto-)" + svc +
           R"(-2","Statement":[{"Sid":"Allow access through )" + std::string(service.display) +
           R"( for all principals in the account that are authorized to use )" +
           std::string(service.display) +
           R"(","Effect":"Allow","Principal":{"AWS":"*"},"Action":[)" + actions +
           R"(],"Resource":"*","Condition":{"StringEquals":{"kms:ViaService":")" + svc + "." +
           std::string(region) + R"(.amazonaws.com","kms:CallerAccount":")" + acct +
           R"("}}},{"Sid":"Allow direct access to key metadata to the account","Effect":"Allow",)"
           R"("Principal":{"AWS":"arn:)" +
           std::string(partition) + ":iam::" + acct +
           R"(:root"},"Action":["kms:Describe*","kms:Get*","kms:List*","kms:RevokeGrant"],)"
           R"("Resource":"*"}]})";
}

/// What making a managed key needs from the module.
template<typename Catalog> struct managed_deps {
    /// This replica after a read barrier, or null when none answered.
    std::function<std::shared_ptr<const Catalog>()> catalog;
    /// A catalog proposal's status; throws when the outcome is unknown.
    std::function<catalog_status(const std::vector<std::byte>&)> propose;
    /// CreateKey's two steps (key_jobs::create_key).
    std::function<key_result(key_record, const tag_map&)> create_key;
    std::function<std::uint64_t()> clock_ms;
    std::string partition = "aws";
    std::string region = "us-east-1";
};

/// Makes `alias/aws/<service>` in `account` unless it exists.
template<typename Catalog>
[[nodiscard]] auto ensure_managed_key(const managed_deps<Catalog>& d, std::string_view account,
                                      const managed_service& service) -> key_result {
    const std::string alias = std::string(k_managed_alias_prefix) + std::string(service.name);
    for (unsigned attempt = 0; attempt < k_managed_attempts; ++attempt) {
        auto c = d.catalog();
        if (!c) {
            return {key_outcome::unavailable, catalog_status::ok};
        }
        if (c->alias(account, alias)) {
            return {};
        }
        const auto id = managed_key_id(account, service.name, attempt);
        if (c->tombstoned(id)) {
            continue;
        }
        if (!c->key(id)) {
            key_record k;
            k.key_id = id;
            k.account = std::string(account);
            k.description = "Default key that protects my " +
                            std::string(service.display.substr(service.display.find(' ') + 1)) +
                            " data when no other key is defined";
            k.manager = key_manager::aws;
            k.policy = managed_key_policy(d.partition, d.region, account, service);
            const auto made = d.create_key(k, {});
            const bool raced =
                made.outcome == key_outcome::catalog && made.status == catalog_status::rejected;
            if (!made.ok() && !raced) {
                return made;
            }
            c = d.catalog();
            if (!c) {
                return {key_outcome::unavailable, catalog_status::ok};
            }
        }
        const auto k = c->key(id);
        if (!k) {
            continue;  // tombstoned by a creation that failed
        }
        if (k->account != account || k->manager != key_manager::aws) {
            return {key_outcome::catalog, catalog_status::rejected};
        }
        if (k->state == key_state::creating) {
            // Another member is making it; its alias follows.
            return {key_outcome::catalog, catalog_status::invalid_state};
        }
        const auto s = d.propose(make_create_alias_command(account, alias, id, true, d.clock_ms()));
        if (s == catalog_status::ok || s == catalog_status::already_exists) {
            return {};
        }
        return {key_outcome::catalog, s};
    }
    return {key_outcome::catalog, catalog_status::rejected};
}

}  // namespace kythira::kms
