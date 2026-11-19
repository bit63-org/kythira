// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "tier.hpp"

#include <raft/aws_client_config.hpp>
#include <raft/aws_s3_client.hpp>

#include <kythira/kinesis/kinesis_channel_role.hpp>
#include <kythira/kinesis/kinesis_iceberg_rest.hpp>

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/utils/DateTime.h>

#include <chrono>
#include <exception>
#include <functional>
#include <map>
#include <vector>
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
        auto chain = _node_chain;
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
        b._get = [client, bucket, authorize](const std::string& key) -> std::optional<std::string> {
            if (authorize) {
                authorize();
            }
            auto got = client->get_object(bucket, key);
            if (!got) {
                return std::nullopt;
            }
            return std::move(got->body);
        };
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

    [[nodiscard]] auto tables(const std::string& table_bucket_arn,
                              const kinesis::channel_access& access) const
        -> std::optional<kinesis::iceberg_catalog> override {
        // arn:<partition>:s3tables:<region>:<account>:bucket/<name>
        std::vector<std::string> parts;
        std::size_t from = 0;
        for (int i = 0; i < 5; ++i) {
            const auto colon = table_bucket_arn.find(':', from);
            if (colon == std::string::npos) {
                return std::nullopt;
            }
            parts.push_back(table_bucket_arn.substr(from, colon - from));
            from = colon + 1;
        }
        const auto& region = parts[3];
        const auto session = kinesis::channel_role_session(access._channel_id);
        const auto role = _roles ? access._role_arn : std::string();
        std::shared_ptr<kinesis::iceberg_rest_client> client;
        {
            const std::lock_guard lock(_mutex);
            auto& c = _catalogs[{table_bucket_arn, role + "\n" + session}];
            if (!c) {
                std::function<kinesis::sigv4_credentials()> creds;
                if (_roles) {
                    creds = [roles = _roles, role, session] { return roles->get(role, session); };
                } else {
                    creds = [chain = _node_chain] {
                        namespace d = kythira::aws_s3_detail;
                        const auto k = chain->GetAWSCredentials();
                        return kinesis::sigv4_credentials{
                            ._access_key_id = d::from_aws(k.GetAWSAccessKeyId()),
                            ._secret_access_key = d::from_aws(k.GetAWSSecretKey()),
                            ._session_token = d::from_aws(k.GetSessionToken()),
                            ._expires_ms = 0};
                    };
                }
                c = std::make_shared<kinesis::iceberg_rest_client>(
                    kinesis::iceberg_rest_config{
                        ._uri = _opt._channel_iceberg_uri.empty()
                                    ? "https://s3tables." + region + ".amazonaws.com/iceberg"
                                    : _opt._channel_iceberg_uri,
                        ._warehouse = _opt._channel_iceberg_warehouse.empty()
                                          ? table_bucket_arn
                                          : _opt._channel_iceberg_warehouse,
                        ._sigv4 = _opt._channel_iceberg_sigv4,
                        ._region = region,
                        ._signing_name = "s3tables",
                        ._credentials = std::move(creds),
                        ._token = _opt._channel_iceberg_token,
                        ._clock = {}},
                    kinesis::peer_transport(_opt._channel_ca_file,
                                            std::chrono::milliseconds{30000}));
            }
            client = c;
        }
        kinesis::iceberg_catalog out;
        out._load = [client](const std::string& ns, const std::string& table) {
            try {
                return client->load_table(ns, table);
            } catch (const kinesis::channel_role_error& e) {
                return std::optional<kinesis::peer_response>(role_refusal(e));
            }
        };
        out._commit = [client](const std::string& ns, const std::string& table, std::string body) {
            try {
                return client->commit(ns, table, std::move(body));
            } catch (const kinesis::channel_role_error& e) {
                return std::optional<kinesis::peer_response>(role_refusal(e));
            }
        };
        return out;
    }

private:
    aws_sdk_scope _sdk;
    node_options _opt;
    std::shared_ptr<const kythira::aws_s3_client> _client;
    std::shared_ptr<kinesis::channel_role_credentials> _roles;
    /// The node's own credentials, for catalog calls when roles are not
    /// assumed (and to sign AssumeRole when they are).
    std::shared_ptr<Aws::Auth::AWSCredentialsProviderChain> _node_chain =
        std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>();
    mutable std::mutex _mutex;
    /// One catalog client per (table bucket, role and session).
    mutable std::map<std::pair<std::string, std::string>,
                     std::shared_ptr<kinesis::iceberg_rest_client>>
        _catalogs;

    /// A refused role as the catalog answer the delivery worker logs.
    [[nodiscard]] static auto role_refusal(const kinesis::channel_role_error& e)
        -> kinesis::peer_response {
        boost::json::object err{{"message", e.what()}, {"type", e.code()}, {"code", 403}};
        return kinesis::peer_response{
            ._status = 403, ._body = boost::json::serialize(boost::json::object{{"error", err}})};
    }
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
