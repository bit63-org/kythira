// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "tier.hpp"

#include <raft/aws_client_config.hpp>
#include <raft/aws_s3_client.hpp>

#include <aws/core/Aws.h>

#include <memory>
#include <mutex>
#include <utility>

namespace kythira::kinesis_node {

namespace {

/// One Aws::InitAPI for the process while the tier or the channel
/// destinations need the SDK, and the matching ShutdownAPI after the last
/// of them is gone.
class aws_sdk_scope {
public:
    aws_sdk_scope() {
        const std::lock_guard lock(mutex());
        if (users()++ == 0) {
            Aws::InitAPI(options());
        }
    }
    aws_sdk_scope(const aws_sdk_scope&) = delete;
    aws_sdk_scope(aws_sdk_scope&&) = delete;
    auto operator=(const aws_sdk_scope&) -> aws_sdk_scope& = delete;
    auto operator=(aws_sdk_scope&&) -> aws_sdk_scope& = delete;
    ~aws_sdk_scope() {
        const std::lock_guard lock(mutex());
        if (--users() == 0) {
            Aws::ShutdownAPI(options());
        }
    }

private:
    static auto mutex() -> std::mutex& {
        static std::mutex m;
        return m;
    }
    static auto users() -> int& {
        static int n = 0;
        return n;
    }
    static auto options() -> Aws::SDKOptions& {
        static Aws::SDKOptions o;
        return o;
    }
};

class s3_tier_impl final : public object_tier {
public:
    explicit s3_tier_impl(const node_options& opt) {
        kythira::aws_client_config cfg;
        cfg.region = opt._tier_region;
        cfg.endpoint_override = opt._tier_endpoint;
        _store = kinesis::make_tier_store<kythira::aws_s3_client>(
            std::make_shared<const kythira::aws_s3_client>(std::move(cfg)), opt._tier_bucket,
            opt._tier_prefix);
    }

    // The client (in _store) goes before the SDK scope does.
    ~s3_tier_impl() override = default;

    s3_tier_impl(const s3_tier_impl&) = delete;
    auto operator=(const s3_tier_impl&) -> s3_tier_impl& = delete;
    s3_tier_impl(s3_tier_impl&&) = delete;
    auto operator=(s3_tier_impl&&) -> s3_tier_impl& = delete;

    [[nodiscard]] auto store() const -> const kinesis::tier_store& override { return _store; }

private:
    aws_sdk_scope _sdk;
    kinesis::tier_store _store;
};

class s3_channel_destinations final : public channel_destinations {
public:
    explicit s3_channel_destinations(const node_options& opt) {
        kythira::aws_client_config cfg;
        cfg.region = opt._channel_s3_region;
        cfg.endpoint_override = opt._channel_s3_endpoint;
        _client = std::make_shared<const kythira::aws_s3_client>(std::move(cfg));
    }

    ~s3_channel_destinations() override = default;
    s3_channel_destinations(const s3_channel_destinations&) = delete;
    auto operator=(const s3_channel_destinations&) -> s3_channel_destinations& = delete;
    s3_channel_destinations(s3_channel_destinations&&) = delete;
    auto operator=(s3_channel_destinations&&) -> s3_channel_destinations& = delete;

    [[nodiscard]] auto bucket(const std::string& bucket) const
        -> std::optional<kinesis::tier_store> override {
        if (bucket.empty()) {
            return std::nullopt;
        }
        return kinesis::make_tier_store<kythira::aws_s3_client>(_client, bucket, "");
    }

private:
    aws_sdk_scope _sdk;
    std::shared_ptr<const kythira::aws_s3_client> _client;
};

}  // namespace

auto tier_detail::make_s3_tier(const node_options& opt) -> std::unique_ptr<object_tier> {
    return std::make_unique<s3_tier_impl>(opt);
}

auto tier_detail::make_s3_channel_destinations(const node_options& opt)
    -> std::unique_ptr<channel_destinations> {
    return std::make_unique<s3_channel_destinations>(opt);
}

}  // namespace kythira::kinesis_node
