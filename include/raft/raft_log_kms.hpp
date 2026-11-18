// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file raft_log_kms.hpp
/// @brief A node's Raft log key ring under a KMS key
///        (.kiro/specs/raft-log-encryption/ tasks 4 and 5).
///
/// `raft_log_key_source_from_kms` adapts the services' shared
/// `kms_provider::key_provider` to the key ring's two callbacks, with the
/// encryption context `kythira:purpose=raft-log`, so a data key wrapped for
/// a Raft log never unwraps as a table or stream key, or the other way.
///
/// `raft_log_encryption_settings` is what a service node reads from its
/// environment, once at start:
///
/// | Variable | Meaning |
/// |---|---|
/// | `KYTHIRA_RAFT_LOG_KMS` | `off` (default), `local`, `aws` or `kythira` |
/// | `KYTHIRA_RAFT_LOG_KMS_KEY_ID` | the KMS key that wraps the data keys (`aws`, `kythira`) |
/// | `KYTHIRA_RAFT_LOG_PASSPHRASE` | `local`: every node's shared passphrase |
/// | `KYTHIRA_RAFT_LOG_KMS_ENDPOINT` | `aws`: a KMS other than the region's; `kythira`: required,
/// `host:port` of a KMS on another cluster | | `KYTHIRA_RAFT_LOG_KMS_REGION` | the KMS's region
/// (default `AWS_REGION`, then `us-east-1`) | | `KYTHIRA_RAFT_LOG_KMS_CA` | the CA the KMS's
/// certificate chains to | | `KYTHIRA_RAFT_LOG_ENCRYPTION` | `seal` (default) or `decrypt_only`,
/// the step on the way off |
///
/// `kythira` needs an endpoint: a node cannot seal its Raft logs under the
/// KMS it runs itself, because that KMS needs its own Raft log to answer.
///
/// `raft_log_options_for` opens (once per process and key ring file) the
/// ring for a module's data directory and returns the engine options every
/// group of that module takes.

#include <raft/binary_file_persistence.hpp>
#include <raft/kms_https_client.hpp>
#include <raft/kms_key_provider.hpp>
#include <raft/kms_key_provider_aws.hpp>
#include <raft/kms_key_provider_kythira.hpp>
#include <raft/raft_log_encryption.hpp>

#include <cstdlib>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace kythira {

/// The encryption context every Raft log data key is wrapped under.
[[nodiscard]] inline auto raft_log_encryption_context(const std::string& node)
    -> kms_provider::encryption_context {
    kms_provider::encryption_context c{{"kythira:purpose", "raft-log"}};
    if (!node.empty()) {
        c.emplace("kythira:node", node);
    }
    return c;
}

/// `provider` as a key ring's key source: data keys made and unwrapped
/// under `key_id`, as the node itself (no end caller).
[[nodiscard]] inline auto raft_log_key_source_from_kms(kms_provider::key_provider provider,
                                                       std::string key_id, std::string node = {})
    -> raft_log_key_source {
    if (!provider) {
        throw std::invalid_argument("raft log key source: no key provider");
    }
    auto shared = std::make_shared<kms_provider::key_provider>(std::move(provider));
    auto context = raft_log_encryption_context(node);
    raft_log_key_source s;
    s._generate = [shared, key_id, context]() {
        auto g = shared->generate_data_key(key_id, context);
        raft_log_data_key out;
        out._plaintext = g._plaintext;
        OPENSSL_cleanse(g._plaintext.data(), g._plaintext.size());
        out._wrapped = std::move(g._wrapped);
        if (g._key_id.empty()) {
            out._key_id = key_id;
        } else {
            out._key_id = std::move(g._key_id);
        }
        return out;
    };
    s._unwrap = [shared, context](const std::string& id, const std::string& wrapped) {
        return shared->decrypt_data_key(id, wrapped, context);
    };
    return s;
}

struct raft_log_encryption_settings {
    std::string provider = "off";
    std::string key_id;
    std::string passphrase;
    std::string endpoint;
    std::string region = "us-east-1";
    std::string ca;
    log_encryption_mode mode = log_encryption_mode::seal;

    [[nodiscard]] auto enabled() const -> bool { return provider != "off"; }

    /// Read the settings through `get` (the environment by default).
    /// Throws std::invalid_argument naming the variable that is wrong.
    [[nodiscard]] static auto from(const std::function<std::string(const char*)>& get)
        -> raft_log_encryption_settings {
        raft_log_encryption_settings s;
        if (auto v = get("KYTHIRA_RAFT_LOG_KMS"); !v.empty()) {
            s.provider = v;
        }
        s.key_id = get("KYTHIRA_RAFT_LOG_KMS_KEY_ID");
        s.passphrase = get("KYTHIRA_RAFT_LOG_PASSPHRASE");
        s.endpoint = get("KYTHIRA_RAFT_LOG_KMS_ENDPOINT");
        s.ca = get("KYTHIRA_RAFT_LOG_KMS_CA");
        if (auto v = get("KYTHIRA_RAFT_LOG_KMS_REGION"); !v.empty()) {
            s.region = v;
        } else if (auto r = get("AWS_REGION"); !r.empty()) {
            s.region = r;
        }
        const auto mode = get("KYTHIRA_RAFT_LOG_ENCRYPTION");
        if (mode == "decrypt_only") {
            s.mode = log_encryption_mode::decrypt_only;
        } else if (!mode.empty() && mode != "seal") {
            throw std::invalid_argument(
                "KYTHIRA_RAFT_LOG_ENCRYPTION: expected seal or "
                "decrypt_only, not '" +
                mode + "'");
        }
        if (s.provider == "off") {
            return s;
        }
        if (s.provider == "local") {
            if (s.passphrase.empty()) {
                throw std::invalid_argument(
                    "KYTHIRA_RAFT_LOG_KMS=local needs KYTHIRA_RAFT_LOG_PASSPHRASE");
            }
            if (s.key_id.empty()) {
                s.key_id = "raft-log";
            }
        } else if (s.provider == "aws" || s.provider == "kythira") {
            if (s.key_id.empty()) {
                throw std::invalid_argument("KYTHIRA_RAFT_LOG_KMS=" + s.provider +
                                            " needs KYTHIRA_RAFT_LOG_KMS_KEY_ID");
            }
            if (s.provider == "kythira" && s.endpoint.empty()) {
                throw std::invalid_argument(
                    "KYTHIRA_RAFT_LOG_KMS=kythira needs KYTHIRA_RAFT_LOG_KMS_ENDPOINT: a node "
                    "cannot seal its Raft logs under a KMS whose own log they include");
            }
        } else {
            throw std::invalid_argument(
                "KYTHIRA_RAFT_LOG_KMS: expected off, local, aws or "
                "kythira, not '" +
                s.provider + "'");
        }
        return s;
    }

    [[nodiscard]] static auto from_environment() -> raft_log_encryption_settings {
        return from([](const char* var) {
            const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe): read at start
            return v != nullptr ? std::string(v) : std::string();
        });
    }
};

namespace detail::raft_log_kms {

[[nodiscard]] inline auto env_or_empty(const char* var) -> std::string {
    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe): read at start
    return v != nullptr ? std::string(v) : std::string();
}

[[nodiscard]] inline auto make_provider(const raft_log_encryption_settings& s)
    -> kms_provider::key_provider {
    if (s.provider == "local") {
        return kms_provider::key_provider(kms_provider::local_kms_provider(s.passphrase));
    }
    if (s.provider == "aws") {
        kms_provider::aws_kms_config kc;
        kc._region = s.region;
        kc._endpoint = s.endpoint;
        kc._ca_path = s.ca;
        kc._credentials = [creds = kms_provider::aws_kms_credentials{
                               env_or_empty("AWS_ACCESS_KEY_ID"),
                               env_or_empty("AWS_SECRET_ACCESS_KEY"),
                               env_or_empty("AWS_SESSION_TOKEN")}] { return creds; };
        return kms_provider::key_provider(kms_provider::aws_kms_provider(std::move(kc)));
    }
    // kythira, on another cluster: signed as this node's service principal.
    service_node::kms_https_config kc;
    kc.endpoint = "https://" + s.endpoint;
    kc.region = s.region;
    kc.access_key_id = env_or_empty("AWS_ACCESS_KEY_ID");
    kc.secret_access_key = env_or_empty("AWS_SECRET_ACCESS_KEY");
    kc.session_token = env_or_empty("AWS_SESSION_TOKEN");
    kc.tls.ca_path = s.ca;
    kc.tls.client_certificate = false;
    auto client = std::make_shared<service_node::kms_https_endpoint>(std::move(kc));
    return kms_provider::key_provider(kms_provider::kythira_kms_provider(
        [client]() -> std::shared_ptr<service_node::kms_endpoint> { return client; }, "raft-log"));
}

}  // namespace detail::raft_log_kms

/// The engine options for every Raft group a module keeps under
/// `data_dir`: no key ring when sealing is off, else the ring in
/// `data_dir/raft-log-keys`, opened once per process however many groups
/// and modules ask. `provider` replaces the settings' provider (tests).
[[nodiscard]] inline auto raft_log_options_for(const std::filesystem::path& data_dir,
                                               const raft_log_encryption_settings& settings,
                                               binary_file_persistence_options base = {},
                                               kms_provider::key_provider provider = {})
    -> binary_file_persistence_options {
    if (!settings.enabled()) {
        return base;
    }
    static std::mutex mu;
    static std::map<std::filesystem::path, std::weak_ptr<raft_log_key_file_ring>> rings;
    const auto file = std::filesystem::absolute(data_dir / "raft-log-keys").lexically_normal();
    std::shared_ptr<raft_log_key_file_ring> ring;
    {
        const std::lock_guard lock(mu);
        ring = rings[file].lock();
        if (!ring) {
            auto p = provider ? std::move(provider) : detail::raft_log_kms::make_provider(settings);
            ring = raft_log_key_file_ring::open(
                file, raft_log_key_source_from_kms(std::move(p), settings.key_id));
            rings[file] = ring;
        }
    }
    base._key_ring = std::move(ring);
    base._encryption = settings.mode;
    return base;
}

}  // namespace kythira
