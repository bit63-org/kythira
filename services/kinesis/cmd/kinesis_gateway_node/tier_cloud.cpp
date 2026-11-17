// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The tier stores other than S3 (tier.hpp): Azure Blob, GCS, OCI Object
// Storage and Alibaba OSS, each through core's client for it and each
// compiled only when CMake set its KYTHIRA_KINESIS_TIER_* macro. They read
// their credentials where `raft_object_backup` and the CA's OIDC publisher
// do: the SDK default chains for Azure and GCS, KYTHIRA_OCI_* and
// KYTHIRA_ALIBABA_* for OCI and OSS.

#include "tier.hpp"

#ifdef KYTHIRA_KINESIS_TIER_AZURE
#include <raft/azure_blob_client.hpp>
#endif
#ifdef KYTHIRA_KINESIS_TIER_GCS
#include <raft/gcp_gcs_client.hpp>
#endif
#ifdef KYTHIRA_KINESIS_TIER_OCI
#include <raft/oci_client_config_env.hpp>
#include <raft/oci_object_storage_client.hpp>
#endif
#ifdef KYTHIRA_KINESIS_TIER_OSS
#include <raft/alibaba_client_config_env.hpp>
#include <raft/alibaba_oss_client.hpp>
#endif
#if defined(KYTHIRA_KINESIS_TIER_OCI) || defined(KYTHIRA_KINESIS_TIER_OSS)
#include <raft/env_config_result.hpp>
#endif

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kinesis_node {

namespace {

template<typename Client, typename Config>
[[nodiscard]] auto client_tier_of(Config cfg, const node_options& opt)
    -> std::unique_ptr<object_tier> {
    return std::make_unique<tier_detail::client_tier>(kinesis::make_tier_store<Client>(
        std::make_shared<const Client>(std::move(cfg)), opt._tier_bucket, opt._tier_prefix));
}

#if defined(KYTHIRA_KINESIS_TIER_OCI) || defined(KYTHIRA_KINESIS_TIER_OSS)
template<typename Config>
[[nodiscard]] auto config_or_throw(kythira::env_config_result<Config> result,
                                   std::string_view provider) -> Config {
    if (!result.ok()) {
        std::string msg = "kinesis tier store (" + std::string(provider) + "):";
        for (const auto& e : result.errors) {
            msg += " " + e + ";";
        }
        throw std::runtime_error(msg);
    }
    return std::move(result.config);
}
#endif

}  // namespace

#ifdef KYTHIRA_KINESIS_TIER_AZURE
auto tier_detail::make_azure_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    kythira::azure_blob_config cfg;
    cfg.account = opt._tier_azure_account;
    cfg.endpoint_override = opt._tier_endpoint;
    return client_tier_of<kythira::azure_blob_client>(std::move(cfg), opt);
}
#endif

#ifdef KYTHIRA_KINESIS_TIER_GCS
auto tier_detail::make_gcs_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    kythira::gcp_client_config cfg;
    cfg.project_id = opt._tier_gcs_project;
    cfg.endpoint_override = opt._tier_endpoint;
    return client_tier_of<kythira::gcp_gcs_client>(std::move(cfg), opt);
}
#endif

#ifdef KYTHIRA_KINESIS_TIER_OCI
auto tier_detail::make_oci_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    return client_tier_of<kythira::oci_object_storage_client>(
        config_or_throw(kythira::oci_object_storage_config_from_env(kythira::process_env_lookup()),
                        "oci-objectstorage"),
        opt);
}
#endif

#ifdef KYTHIRA_KINESIS_TIER_OSS
auto tier_detail::make_oss_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    return client_tier_of<kythira::alibaba_oss_client>(
        config_or_throw(kythira::alibaba_client_config_from_env(kythira::process_env_lookup()),
                        "oss"),
        opt);
}
#endif

}  // namespace kythira::kinesis_node
