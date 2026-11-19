// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file tier.hpp
/// @brief The object store `kinesis_gateway_node` tiers sealed segments to
///        (task 10, Requirement 11.3), behind an interface so no other
///        translation unit parses a cloud SDK header.
///
/// `KINESIS_TIER_PROVIDER` picks the store: `s3` (the default, also any
/// S3-compatible endpoint), `azure-blob`, `gcs`, `oci-objectstorage` or
/// `oss`, the names `raft_object_backup --provider` takes. Each provider
/// is compiled in only when its client's dependency was found (and, for
/// all but S3, its persistence Kconfig gate is on): `tier_s3.cpp` with the
/// AWS SDK's s3 component (`KYTHIRA_KINESIS_TIER_S3`), `tier_cloud.cpp`
/// for the rest (`KYTHIRA_KINESIS_TIER_AZURE`, `_GCS`, `_OCI`, `_OSS`).
/// `from_env` refuses a provider this build lacks, naming what would
/// enable it, so `make_object_tier` meets one only through a bug.

#include "config.hpp"

#include <kythira/kinesis/kinesis_channel_delivery.hpp>
#include <kythira/kinesis/kinesis_tiering.hpp>

#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace kythira::kinesis_node {

/// A tier store and whatever its client needs alive (the AWS SDK's
/// initialisation, for S3), destroyed together.
class object_tier {
public:
    virtual ~object_tier() = default;
    object_tier() = default;
    object_tier(const object_tier&) = delete;
    auto operator=(const object_tier&) -> object_tier& = delete;
    object_tier(object_tier&&) = delete;
    auto operator=(object_tier&&) -> object_tier& = delete;

    /// Valid while this object lives.
    [[nodiscard]] virtual auto store() const -> const kinesis::tier_store& = 0;
};

/// Channel destination buckets (task 19): a tier store for any bucket,
/// through one client and whatever it needs alive.
class channel_destinations {
public:
    virtual ~channel_destinations() = default;
    channel_destinations() = default;
    channel_destinations(const channel_destinations&) = delete;
    auto operator=(const channel_destinations&) -> channel_destinations& = delete;
    channel_destinations(channel_destinations&&) = delete;
    auto operator=(channel_destinations&&) -> channel_destinations& = delete;

    /// Writes to `bucket`'s root on behalf of `access`'s channel (as its
    /// execution role when the node assumes roles); valid while this object
    /// lives.
    [[nodiscard]] virtual auto bucket(const std::string& bucket,
                                      const kinesis::channel_access& access) const
        -> std::optional<kinesis::channel_bucket> = 0;
};

/// S3 in `_channel_s3_region` at `_channel_s3_endpoint` (as each channel's
/// execution role with `_channel_assume_role`), or nullptr when
/// this build has no S3 client (`KYTHIRA_KINESIS_TIER_S3`).
[[nodiscard]] auto make_channel_destinations(const node_options& opt)
    -> std::unique_ptr<channel_destinations>;

/// The provider, bucket and prefix from `opt` (and for S3 its region and
/// endpoint; the other providers read their credentials where
/// `raft_object_backup` does).
/// @throws std::runtime_error when the provider is not in this build or
///         its credentials are incomplete.
[[nodiscard]] auto make_object_tier(const node_options& opt) -> std::unique_ptr<object_tier>;

namespace tier_detail {

/// One per provider, defined only where that provider is compiled in.
[[nodiscard]] auto make_s3_tier(const node_options& opt) -> std::unique_ptr<object_tier>;
[[nodiscard]] auto make_azure_tier(const node_options& opt) -> std::unique_ptr<object_tier>;
[[nodiscard]] auto make_gcs_tier(const node_options& opt) -> std::unique_ptr<object_tier>;
[[nodiscard]] auto make_oci_tier(const node_options& opt) -> std::unique_ptr<object_tier>;
[[nodiscard]] auto make_oss_tier(const node_options& opt) -> std::unique_ptr<object_tier>;
[[nodiscard]] auto make_s3_channel_destinations(const node_options& opt)
    -> std::unique_ptr<channel_destinations>;

/// An object_tier whose client needs nothing beyond what the store's
/// functions hold (every provider but S3).
class client_tier final : public object_tier {
public:
    explicit client_tier(kinesis::tier_store store) : _store(std::move(store)) {}
    [[nodiscard]] auto store() const -> const kinesis::tier_store& override { return _store; }

private:
    kinesis::tier_store _store;
};

}  // namespace tier_detail

}  // namespace kythira::kinesis_node
