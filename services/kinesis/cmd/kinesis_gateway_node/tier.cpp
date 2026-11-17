// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Picks the tier store's provider (tier.hpp). Compiled in every build; it
// calls only the factories of the providers this build carries.

#include "tier.hpp"

#include <stdexcept>
#include <string>

namespace kythira::kinesis_node {

auto make_object_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    const auto& p = opt._tier_provider;
#ifdef KYTHIRA_KINESIS_TIER_S3
    if (p == "s3") {
        return tier_detail::make_s3_tier(opt);
    }
#endif
#ifdef KYTHIRA_KINESIS_TIER_AZURE
    if (p == "azure-blob") {
        return tier_detail::make_azure_tier(opt);
    }
#endif
#ifdef KYTHIRA_KINESIS_TIER_GCS
    if (p == "gcs") {
        return tier_detail::make_gcs_tier(opt);
    }
#endif
#ifdef KYTHIRA_KINESIS_TIER_OCI
    if (p == "oci-objectstorage") {
        return tier_detail::make_oci_tier(opt);
    }
#endif
#ifdef KYTHIRA_KINESIS_TIER_OSS
    if (p == "oss") {
        return tier_detail::make_oss_tier(opt);
    }
#endif
    // from_env refuses this before anything starts.
    throw std::runtime_error("kinesis_gateway_node: no tier provider '" + p + "' in this build");
}

auto make_channel_destinations(const node_options& opt) -> std::unique_ptr<channel_destinations> {
#ifdef KYTHIRA_KINESIS_TIER_S3
    return tier_detail::make_s3_channel_destinations(opt);
#else
    (void)opt;
    return nullptr;
#endif
}

}  // namespace kythira::kinesis_node
