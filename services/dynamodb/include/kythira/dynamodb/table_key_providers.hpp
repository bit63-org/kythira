// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file table_key_providers.hpp
/// @brief The key providers `KYTHIRA_DYNAMODB_KMS` names, made from the
///        settings (`encryption_settings`, `table_keys.hpp`): what the
///        daemon and kythira_node's module hand the gateway as
///        `gateway_config::encryption`. Kept apart from `table_keys.hpp`
///        so the handlers and their tests need no HTTPS client.

#include <kythira/dynamodb/table_keys.hpp>

#include <raft/kms_https_client.hpp>
#include <raft/kms_key_provider.hpp>
#include <raft/kms_key_provider_aws.hpp>
#include <raft/kms_key_provider_kythira.hpp>
#include <raft/module_interfaces.hpp>

#include <cstdlib>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace kythira::dynamodb {

/// The service name Kythira's KMS sees (`kms:ViaService`), and the one
/// whose owned key a table names no key gets.
inline constexpr std::string_view k_kms_service = "dynamodb";

/// The KMS client a co-located KMS module publishes, found at start: a
/// slot the providers read on each call, filled before serving.
using kms_endpoint_slot = std::shared_ptr<std::shared_ptr<service_node::kms_endpoint>>;

namespace table_key_providers_detail {

[[nodiscard]] inline auto env_or_empty(const char* var) -> std::string {
    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe): read at start
    return v != nullptr ? std::string(v) : std::string();
}

/// The provider `name`. Throws std::invalid_argument on settings that
/// cannot make it.
[[nodiscard]] inline auto make_provider(const std::string& name, const encryption_settings& s,
                                        const std::string& region, const kms_endpoint_slot& slot)
    -> kms_provider::key_provider {
    if (name == "local") {
        return kms_provider::key_provider(kms_provider::local_kms_provider(s.passphrase));
    }
    if (name == "aws") {
        kms_provider::aws_kms_config kc;
        kc._region = region;
        kc._endpoint = s.endpoint;
        kc._ca_path = s.ca;
        // Read once at startup: nothing in the process changes its
        // environment.
        kc._credentials = [creds = kms_provider::aws_kms_credentials{
                               env_or_empty("AWS_ACCESS_KEY_ID"),
                               env_or_empty("AWS_SECRET_ACCESS_KEY"),
                               env_or_empty("AWS_SESSION_TOKEN")}] { return creds; };
        return kms_provider::key_provider(kms_provider::aws_kms_provider(std::move(kc)));
    }
    if (name == "kythira") {
        std::function<std::shared_ptr<service_node::kms_endpoint>()> endpoint;
        if (!s.endpoint.empty()) {
            // A KMS on another cluster: signed as this gateway, which the
            // KMS trusts to forward the caller it serves.
            service_node::kms_https_config kc;
            kc.endpoint = "https://" + s.endpoint;
            kc.region = region;
            kc.access_key_id = env_or_empty("AWS_ACCESS_KEY_ID");
            kc.secret_access_key = env_or_empty("AWS_SECRET_ACCESS_KEY");
            kc.session_token = env_or_empty("AWS_SESSION_TOKEN");
            kc.tls.ca_path = s.ca;
            kc.tls.client_certificate = false;
            auto client = std::make_shared<service_node::kms_https_endpoint>(std::move(kc));
            endpoint = [client]() -> std::shared_ptr<service_node::kms_endpoint> { return client; };
        } else {
            endpoint = [slot]() -> std::shared_ptr<service_node::kms_endpoint> {
                return slot ? *slot : nullptr;
            };
        }
        return kms_provider::key_provider(
            kms_provider::kythira_kms_provider(std::move(endpoint), std::string(k_kms_service)));
    }
    throw std::invalid_argument("KYTHIRA_DYNAMODB_KMS: no provider named '" + name + "'");
}

}  // namespace table_key_providers_detail

/// The table keys' configuration from `s`. `provider` is the provider
/// to use (the settings' or the default the caller chose); `region` the
/// gateway's; `slot` the co-located KMS's client once found (kythira
/// without an endpoint).
[[nodiscard]] inline auto make_table_key_config(const encryption_settings& s,
                                                const std::string& provider,
                                                const std::string& gateway_region,
                                                kms_endpoint_slot slot = {}) -> table_key_config {
    table_key_config c;
    if (provider.empty() || provider == "off") {
        return c;
    }
    const auto region = s.region.empty() ? gateway_region : s.region;
    c.provider_name = provider;
    c.provider = table_key_providers_detail::make_provider(provider, s, region, slot);
    if (!s.kms_previous.empty()) {
        c.previous.emplace(s.kms_previous, table_key_providers_detail::make_provider(
                                               s.kms_previous, s, region, slot));
    }
    c.at_rest = s.at_rest == "off" ? at_rest_mode::off : at_rest_mode::owned;
    if (provider == "kythira") {
        c.owned_key_id = "alias/aws/dynamodb/owned";
    } else if (provider == "aws") {
        c.owned_key_id = s.owned_key;
    } else {
        c.owned_key_id = "dynamodb-owned";
        c.customer_keys = false;
    }
    return c;
}

}  // namespace kythira::dynamodb
