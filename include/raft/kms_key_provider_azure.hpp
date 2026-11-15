// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_key_provider_azure.hpp
/// @brief A `kms_key_provider` over Azure Key Vault (or Managed HSM).
///
/// The key id is the key's URL, `https://<vault>.vault.azure.net/keys/<name>`
/// with or without a version. A data key is 32 random bytes from this
/// process; Key Vault's `wrapkey` wraps it (RSA-OAEP-256 by default, or
/// A256KW for a Managed HSM's AES key) together with SHA-256 of the
/// encryption context's binding (kms_key_provider_cloud.hpp), and
/// `unwrapkey` gives both back, the digest checked. The resolved key id is
/// the versioned `kid` Key Vault answers with, so rotating the key later
/// does not strand data keys wrapped under an older version. The wrapped
/// key stores the algorithm, so changing the configured one later does not
/// strand them either.
///
/// Errors map onto `kms_failure`: a message naming a disabled key to
/// `disabled`; 401 and 403 to `access_denied`; 404 to `not_found`; 429 to
/// `throttling`; 5xx and no answer to `unavailable`; anything else to
/// `invalid_state`.
///
/// Tokens come from a `token_cache`; `azure_default_token_source` reads
/// the usual environment: `AZURE_ACCESS_TOKEN` (a token, used as given),
/// else `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` (a
/// service principal's client credentials, `AZURE_AUTHORITY_HOST` for a
/// sovereign cloud), else the VM's managed identity (`AZURE_CLIENT_ID`
/// picks a user-assigned one).

#include <raft/kms_key_provider.hpp>
#include <raft/kms_key_provider_cloud.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kms_provider {

struct azure_key_vault_config {
    /// RSA-OAEP-256 (an RSA key) or A256KW (a Managed HSM's AES key).
    std::string _algorithm = "RSA-OAEP-256";
    std::string _api_version = "7.4";
    std::string _ca_path;
    std::chrono::milliseconds _timeout{5000};
    token_cache _token;
};

namespace azure_detail {

/// The token audience for a vault URL: its host without the vault's own
/// label ("https://v.vault.azure.net/..." -> "https://vault.azure.net"),
/// which also gives sovereign clouds and Managed HSM their own.
[[nodiscard]] inline auto resource_of(std::string_view key_url) -> std::string {
    const auto u = cloud_detail::parse_url(key_url);
    if (!u) {
        return "https://vault.azure.net";
    }
    auto host = std::string_view(u->_host_port);
    host = host.substr(0, host.rfind(':'));
    const auto dot = host.find('.');
    return dot == std::string_view::npos ? "https://vault.azure.net"
                                         : "https://" + std::string(host.substr(dot + 1));
}

[[nodiscard]] inline auto digest(std::string_view in) -> std::array<unsigned char, 32> {
    std::array<unsigned char, 32> out{};
    unsigned int n = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha256(), nullptr) != 1) {
        throw kms_error(kms_failure::invalid_state, "SHA-256 failed.");
    }
    return out;
}

}  // namespace azure_detail

class azure_key_vault_provider {
public:
    explicit azure_key_vault_provider(azure_key_vault_config config, http_transport transport = {})
        : _config(std::move(config)), _transport(std::move(transport)) {
        if (_config._algorithm.empty() || _config._algorithm.size() > 255) {
            throw std::invalid_argument("azure_key_vault_provider: an algorithm is required");
        }
        if (!_transport) {
            _transport = cloud_detail::default_transport(_config._ca_path, _config._timeout);
        }
    }

    [[nodiscard]] auto generate_data_key(const std::string& key_id,
                                         const encryption_context& context) const
        -> generated_data_key {
        data_key_bytes plain{};
        if (RAND_bytes(plain.data(), static_cast<int>(plain.size())) != 1) {
            throw kms_error(kms_failure::unavailable, "No random bytes for a data key.");
        }
        auto out = wrap_data_key(key_id, plain, context);
        OPENSSL_cleanse(plain.data(), plain.size());
        return out;
    }

    [[nodiscard]] auto wrap_data_key(const std::string& key_id, const data_key_bytes& plaintext,
                                     const encryption_context& context) const
        -> generated_data_key {
        const auto bound = azure_detail::digest(cloud_detail::context_binding(context));
        std::string payload(plaintext.begin(), plaintext.end());
        payload.append(bound.begin(), bound.end());
        const boost::json::object req{{"alg", _config._algorithm},
                                      {"value", cloud_detail::base64url_encode(payload)}};
        OPENSSL_cleanse(payload.data(), payload.size());
        const auto res = call(key_id, "wrapkey", req);
        const auto wrapped = blob(res);
        generated_data_key out;
        out._plaintext = plaintext;
        out._wrapped.push_back(static_cast<char>(_config._algorithm.size()));
        out._wrapped += _config._algorithm;
        out._wrapped += wrapped;
        out._key_id = cloud_detail::string_field(res, "kid").value_or(key_id);
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context) const -> data_key_bytes {
        const auto n = wrapped.empty() ? std::size_t{0} : static_cast<unsigned char>(wrapped[0]);
        if (n == 0 || wrapped.size() <= 1 + n) {
            throw kms_error(kms_failure::invalid_state, "A malformed wrapped data key.");
        }
        const boost::json::object req{
            {"alg", wrapped.substr(1, n)},
            {"value", cloud_detail::base64url_encode(std::string_view(wrapped).substr(1 + n))}};
        const auto res = call(key_id, "unwrapkey", req);
        auto plain = blob(res);
        data_key_bytes out{};
        const auto bound = azure_detail::digest(cloud_detail::context_binding(context));
        const bool ok = plain.size() == out.size() + bound.size() &&
                        CRYPTO_memcmp(plain.data() + out.size(), bound.data(), bound.size()) == 0;
        if (ok) {
            std::memcpy(out.data(), plain.data(), out.size());
        }
        OPENSSL_cleanse(plain.data(), plain.size());
        if (!ok) {
            throw kms_error(kms_failure::invalid_state,
                            "The data key was wrapped for another encryption context.");
        }
        return out;
    }

private:
    azure_key_vault_config _config;
    http_transport _transport;

    [[nodiscard]] static auto blob(const boost::json::object& res) -> std::string {
        const auto v = cloud_detail::string_field(res, "value");
        auto decoded = v ? cloud_detail::base64_decode(*v) : std::nullopt;
        if (!decoded) {
            throw kms_error(kms_failure::invalid_state, "Key Vault answered without a value.");
        }
        return std::move(*decoded);
    }

    [[nodiscard]] auto call(const std::string& key_id, std::string_view op,
                            const boost::json::object& req) const -> boost::json::object {
        const auto u = cloud_detail::parse_url(key_id);
        if (!u || !u->_tls || u->_target.find("/keys/") != 0 ||
            u->_target.find('?') != std::string::npos) {
            throw kms_error(kms_failure::not_found,
                            "An Azure key id is the key's https URL: " + key_id);
        }
        auto url = key_id;
        while (url.ends_with('/')) {
            url.pop_back();
        }
        url += "/" + std::string(op) + "?api-version=" + _config._api_version;
        const https_peer::peer_client::headers headers{
            {"Authorization", "Bearer " + _config._token.get()},
            {"Content-Type", "application/json"}};
        const auto res =
            _transport(boost::beast::http::verb::post, url, headers, boost::json::serialize(req));
        if (!res) {
            throw kms_error(kms_failure::unavailable, "Key Vault did not answer.");
        }
        auto parsed = cloud_detail::parse_object(res->_body);
        if (res->_status == 200) {
            return parsed;
        }
        std::string message = "Key Vault answered " + std::to_string(res->_status);
        if (const auto* e = parsed.if_contains("error"); e != nullptr && e->is_object()) {
            message = cloud_detail::string_field(e->get_object(), "message").value_or(message);
        }
        throw kms_error(failure_of(res->_status, message), message);
    }

    [[nodiscard]] static auto failure_of(unsigned status, std::string_view message) -> kms_failure {
        if (message.find("disabled") != std::string_view::npos) {
            return kms_failure::disabled;
        }
        if (status == 401 || status == 403) {
            return kms_failure::access_denied;
        }
        if (status == 404) {
            return kms_failure::not_found;
        }
        if (status == 429) {
            return kms_failure::throttling;
        }
        if (status >= 500) {
            return kms_failure::unavailable;
        }
        return kms_failure::invalid_state;
    }
};

static_assert(kms_key_provider<azure_key_vault_provider>);
static_assert(wrapping_kms_key_provider<azure_key_vault_provider>);

/// Tokens for Key Vault from the environment, as described above.
/// `key_url` gives the audience (a vault, a sovereign cloud's vault, a
/// Managed HSM).
[[nodiscard]] inline auto azure_default_token_source(const std::string& key_url,
                                                     const env_lookup& env,
                                                     http_transport transport) -> token_cache {
    if (auto token = env("AZURE_ACCESS_TOKEN"); !token.empty()) {
        return token_cache([token = std::move(token)] { return access_token{._value = token}; });
    }
    const auto resource = azure_detail::resource_of(key_url);
    auto tenant = env("AZURE_TENANT_ID");
    auto client = env("AZURE_CLIENT_ID");
    auto secret = env("AZURE_CLIENT_SECRET");
    if (!tenant.empty() && !client.empty() && !secret.empty()) {
        auto authority = env("AZURE_AUTHORITY_HOST");
        if (authority.empty()) {
            authority = "https://login.microsoftonline.com";
        }
        while (authority.ends_with('/')) {
            authority.pop_back();
        }
        auto url = authority + "/" + cloud_detail::form_escape(tenant) + "/oauth2/v2.0/token";
        auto body = "grant_type=client_credentials&client_id=" + cloud_detail::form_escape(client) +
                    "&client_secret=" + cloud_detail::form_escape(secret) +
                    "&scope=" + cloud_detail::form_escape(resource + "/.default");
        OPENSSL_cleanse(secret.data(), secret.size());
        return token_cache(
            [transport = std::move(transport), url = std::move(url), body = std::move(body)] {
                return cloud_detail::token_from(
                    transport(boost::beast::http::verb::post, url,
                              {{"Content-Type", "application/x-www-form-urlencoded"}}, body),
                    "Microsoft Entra ID");
            });
    }
    auto url =
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
        "&resource=" +
        cloud_detail::form_escape(resource);
    if (!client.empty()) {
        url += "&client_id=" + cloud_detail::form_escape(client);
    }
    return token_cache([transport = std::move(transport), url = std::move(url)] {
        return cloud_detail::token_from(
            transport(boost::beast::http::verb::get, url, {{"Metadata", "true"}}, {}),
            "The Azure instance metadata service");
    });
}

}  // namespace kythira::kms_provider
