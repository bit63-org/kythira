// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "tier.hpp"

#include <raft/aws_client_config.hpp>
#include <raft/aws_s3_client.hpp>

#include <kythira/kinesis/kinesis_channel_role.hpp>

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/utils/DateTime.h>

#include <chrono>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
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

/// Hands the SDK a channel role's temporary credentials, from the cache
/// that refreshes them before they expire. The SDK asks on every signed
/// request and does not expect a throw: a refusal gives empty credentials,
/// and the write fails as unauthenticated. `put` asks the cache first, so
/// the delivery worker records STS's own reason instead.
class role_credentials_provider final : public Aws::Auth::AWSCredentialsProvider {
public:
    role_credentials_provider(std::shared_ptr<kinesis::channel_role_credentials> cache,
                              std::string role, std::string session)
        : _cache(std::move(cache)), _role(std::move(role)), _session(std::move(session)) {}

    auto GetAWSCredentials() -> Aws::Auth::AWSCredentials override {
        try {
            namespace d = kythira::aws_s3_detail;
            const auto c = _cache->get(_role, _session);
            return Aws::Auth::AWSCredentials(
                d::to_aws(c._access_key_id), d::to_aws(c._secret_access_key),
                d::to_aws(c._session_token), Aws::Utils::DateTime(c._expires_ms));
        } catch (const std::exception&) {
            return {};
        }
    }

private:
    std::shared_ptr<kinesis::channel_role_credentials> _cache;
    std::string _role;
    std::string _session;
};

/// `AddProvider` is protected on the chain, which is the type
/// `aws_client_config` takes.
class single_provider_chain final : public Aws::Auth::AWSCredentialsProviderChain {
public:
    explicit single_provider_chain(const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>& p) {
        AddProvider(p);
    }
};

class s3_channel_destinations final : public channel_destinations {
public:
    explicit s3_channel_destinations(const node_options& opt) : _opt(opt) {
        _client = std::make_shared<const kythira::aws_s3_client>(client_config());
        if (!opt._channel_assume_role) {
            return;
        }
        // The node's own credentials, from the SDK's usual chain, sign the
        // AssumeRole calls.
        auto chain = std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>();
        auto sts = std::make_shared<kinesis::sts_client>(
            kinesis::sts_config{._region = opt._channel_s3_region,
                                ._endpoint = opt._channel_sts_endpoint,
                                ._credentials =
                                    [chain] {
                                        namespace d = kythira::aws_s3_detail;
                                        const auto c = chain->GetAWSCredentials();
                                        return kinesis::sigv4_credentials{
                                            ._access_key_id = d::from_aws(c.GetAWSAccessKeyId()),
                                            ._secret_access_key = d::from_aws(c.GetAWSSecretKey()),
                                            ._session_token = d::from_aws(c.GetSessionToken()),
                                            ._expires_ms = 0};
                                    },
                                ._clock = {},
                                ._duration_seconds = 3600},
            kinesis::peer_transport(opt._channel_ca_file, std::chrono::milliseconds{10000}));
        _roles = std::make_shared<kinesis::channel_role_credentials>(
            [sts](std::string_view role, std::string_view session) {
                return sts->assume_role(role, session);
            });
    }

    ~s3_channel_destinations() override = default;
    s3_channel_destinations(const s3_channel_destinations&) = delete;
    auto operator=(const s3_channel_destinations&) -> s3_channel_destinations& = delete;
    s3_channel_destinations(s3_channel_destinations&&) = delete;
    auto operator=(s3_channel_destinations&&) -> s3_channel_destinations& = delete;

    [[nodiscard]] auto bucket(const std::string& bucket,
                              const kinesis::channel_access& access) const
        -> std::optional<kinesis::channel_bucket> override {
        if (bucket.empty()) {
            return std::nullopt;
        }
        auto client = _client;
        std::function<void()> authorize;
        if (_roles) {
            const auto session = kinesis::channel_role_session(access._channel_id);
            client = role_client(access._role_arn, session);
            authorize = [roles = _roles, role = access._role_arn, session] {
                // Throws STS's refusal, naming the role.
                (void)roles->get(role, session);
            };
        }
        kinesis::channel_bucket b;
        b._put = [client, bucket, authorize](const std::string& key, std::string_view bytes,
                                             const kinesis::channel_put_options& o) {
            if (authorize) {
                authorize();
            }
            (void)client->put_object_with(
                bucket, key, bytes,
                kythira::s3_put_options{.storage_class = o._storage_class,
                                        .expected_bucket_owner = o._expected_owner,
                                        .content_type = {}});
        };
        return b;
    }

private:
    aws_sdk_scope _sdk;
    node_options _opt;
    std::shared_ptr<const kythira::aws_s3_client> _client;
    std::shared_ptr<kinesis::channel_role_credentials> _roles;
    mutable std::mutex _mutex;
    /// One client per (role, session), each signing with that role's
    /// credentials.
    mutable std::map<std::pair<std::string, std::string>,
                     std::shared_ptr<const kythira::aws_s3_client>>
        _role_clients;

    [[nodiscard]] auto client_config() const -> kythira::aws_client_config {
        kythira::aws_client_config cfg;
        cfg.region = _opt._channel_s3_region;
        cfg.endpoint_override = _opt._channel_s3_endpoint;
        return cfg;
    }

    [[nodiscard]] auto role_client(const std::string& role, const std::string& session) const
        -> std::shared_ptr<const kythira::aws_s3_client> {
        const std::lock_guard lock(_mutex);
        auto& c = _role_clients[{role, session}];
        if (!c) {
            auto cfg = client_config();
            cfg.credentials_provider = std::make_shared<single_provider_chain>(
                std::make_shared<role_credentials_provider>(_roles, role, session));
            c = std::make_shared<const kythira::aws_s3_client>(std::move(cfg));
        }
        return c;
    }
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
