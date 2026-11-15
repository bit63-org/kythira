// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kms_key_provider_gcp.hpp
/// @brief A `kms_key_provider` over GCP Cloud KMS.
///
/// The key id is the crypto key's resource name,
/// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`, a symmetric
/// ENCRYPT_DECRYPT key (software or HSM protection level). A data key is
/// 32 random bytes from this process; Cloud KMS's `:encrypt` wraps it with
/// the encryption context's binding (kms_key_provider_cloud.hpp) as
/// additional authenticated data, and `:decrypt` unwraps it with the same.
/// The ciphertext names the key version itself, so rotating the key does
/// not strand data keys; the resolved key id is the crypto key's name (a
/// version name, which `:decrypt` does not take, is cut back to it).
///
/// Errors map onto `kms_failure` by the answer's `status`:
/// PERMISSION_DENIED and UNAUTHENTICATED to `access_denied`, NOT_FOUND to
/// `not_found`, FAILED_PRECONDITION (a disabled or destroyed version) to
/// `disabled`, RESOURCE_EXHAUSTED to `throttling`, UNAVAILABLE, 5xx and no
/// answer to `unavailable`, anything else to `invalid_state`.
///
/// Tokens come from a `token_cache`; `gcp_default_token_source` reads the
/// usual environment: `GOOGLE_OAUTH_ACCESS_TOKEN` (a token, used as
/// given), else `GOOGLE_APPLICATION_CREDENTIALS` (a service account key
/// file: a JWT signed with its key, exchanged at its `token_uri`), else
/// the instance metadata server (`GCE_METADATA_HOST` to move it).

#include <raft/kms_key_provider.hpp>
#include <raft/kms_key_provider_cloud.hpp>

#include <boost/json.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::kms_provider {

struct gcp_kms_config {
    /// "https://host[:port]"; empty is https://cloudkms.googleapis.com.
    std::string _endpoint;
    std::string _ca_path;
    std::chrono::milliseconds _timeout{5000};
    token_cache _token;
};

namespace gcp_detail {

/// The crypto key a name belongs to: a version name cut back, anything
/// else as given.
[[nodiscard]] inline auto crypto_key_of(std::string_view name) -> std::string {
    if (const auto at = name.find("/cryptoKeyVersions/"); at != std::string_view::npos) {
        name = name.substr(0, at);
    }
    return std::string(name);
}

[[nodiscard]] inline auto valid_key_name(std::string_view name) -> bool {
    return name.starts_with("projects/") && name.find("/cryptoKeys/") != std::string_view::npos &&
           name.find_first_of("?#% ") == std::string_view::npos &&
           name.find("..") == std::string_view::npos;
}

/// A service account key's JWT for the token endpoint (RFC 7523), signed
/// RS256 with its private key.
[[nodiscard]] inline auto service_account_assertion(const boost::json::object& key,
                                                    std::chrono::sys_seconds now) -> std::string {
    const auto email = cloud_detail::string_field(key, "client_email");
    const auto pem = cloud_detail::string_field(key, "private_key");
    const auto token_uri = cloud_detail::string_field(key, "token_uri")
                               .value_or("https://oauth2.googleapis.com/token");
    if (!email || !pem) {
        throw kms_error(kms_failure::access_denied,
                        "The service account key has no client_email or private_key.");
    }
    boost::json::object header{{"alg", "RS256"}, {"typ", "JWT"}};
    if (auto kid = cloud_detail::string_field(key, "private_key_id")) {
        header["kid"] = *kid;
    }
    const auto iat = now.time_since_epoch().count();
    const boost::json::object claims{{"iss", *email},
                                     {"scope", "https://www.googleapis.com/auth/cloudkms"},
                                     {"aud", token_uri},
                                     {"iat", iat},
                                     {"exp", iat + 3600}};
    const auto signing_input = cloud_detail::base64url_encode(boost::json::serialize(header)) +
                               "." + cloud_detail::base64url_encode(boost::json::serialize(claims));
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem->data(), static_cast<int>(pem->size())), &BIO_free);
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr,
        &EVP_PKEY_free);
    if (!pkey) {
        throw kms_error(kms_failure::access_denied,
                        "The service account key's private_key does not parse.");
    }
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(),
                                                                     &EVP_MD_CTX_free);
    std::size_t len = 0;
    if (!md || EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1 ||
        EVP_DigestSign(md.get(), nullptr, &len,
                       reinterpret_cast<const unsigned char*>(signing_input.data()),
                       signing_input.size()) != 1) {
        throw kms_error(kms_failure::access_denied, "Signing the service account JWT failed.");
    }
    std::string sig(len, '\0');
    if (EVP_DigestSign(md.get(), reinterpret_cast<unsigned char*>(sig.data()), &len,
                       reinterpret_cast<const unsigned char*>(signing_input.data()),
                       signing_input.size()) != 1) {
        throw kms_error(kms_failure::access_denied, "Signing the service account JWT failed.");
    }
    sig.resize(len);
    return signing_input + "." + cloud_detail::base64url_encode(sig);
}

[[nodiscard]] inline auto failure_of(unsigned http_status, std::string_view status) -> kms_failure {
    if (status == "PERMISSION_DENIED" || status == "UNAUTHENTICATED" || http_status == 401 ||
        http_status == 403) {
        return kms_failure::access_denied;
    }
    if (status == "NOT_FOUND" || http_status == 404) {
        return kms_failure::not_found;
    }
    if (status == "FAILED_PRECONDITION") {
        return kms_failure::disabled;
    }
    if (status == "RESOURCE_EXHAUSTED" || http_status == 429) {
        return kms_failure::throttling;
    }
    if (status == "UNAVAILABLE" || http_status >= 500) {
        return kms_failure::unavailable;
    }
    return kms_failure::invalid_state;
}

}  // namespace gcp_detail

class gcp_kms_provider {
public:
    explicit gcp_kms_provider(gcp_kms_config config, http_transport transport = {})
        : _config(std::move(config)), _transport(std::move(transport)) {
        if (_config._endpoint.empty()) {
            _config._endpoint = "https://cloudkms.googleapis.com";
        }
        while (_config._endpoint.ends_with('/')) {
            _config._endpoint.pop_back();
        }
        if (!cloud_detail::parse_url(_config._endpoint)) {
            throw std::invalid_argument("gcp_kms_provider: the endpoint is not a URL");
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
        const auto key = gcp_detail::crypto_key_of(key_id);
        auto plain_b64 = cloud_detail::base64_encode(
            std::string_view(reinterpret_cast<const char*>(plaintext.data()), plaintext.size()));
        const boost::json::object req{
            {"plaintext", plain_b64},
            {"additionalAuthenticatedData",
             cloud_detail::base64_encode(cloud_detail::context_binding(context))}};
        OPENSSL_cleanse(plain_b64.data(), plain_b64.size());
        const auto res = call(key, "encrypt", req);
        generated_data_key out;
        out._plaintext = plaintext;
        out._wrapped = blob(res, "ciphertext");
        out._key_id =
            gcp_detail::crypto_key_of(cloud_detail::string_field(res, "name").value_or(key));
        return out;
    }

    [[nodiscard]] auto decrypt_data_key(const std::string& key_id, const std::string& wrapped,
                                        const encryption_context& context) const -> data_key_bytes {
        const boost::json::object req{
            {"ciphertext", cloud_detail::base64_encode(wrapped)},
            {"additionalAuthenticatedData",
             cloud_detail::base64_encode(cloud_detail::context_binding(context))}};
        const auto res = call(gcp_detail::crypto_key_of(key_id), "decrypt", req);
        auto plain = blob(res, "plaintext");
        data_key_bytes out{};
        const bool ok = plain.size() == out.size();
        if (ok) {
            std::memcpy(out.data(), plain.data(), out.size());
        }
        OPENSSL_cleanse(plain.data(), plain.size());
        if (!ok) {
            throw kms_error(kms_failure::invalid_state,
                            "Cloud KMS returned a data key of the wrong size.");
        }
        return out;
    }

private:
    gcp_kms_config _config;
    http_transport _transport;

    [[nodiscard]] static auto blob(const boost::json::object& res, std::string_view name)
        -> std::string {
        const auto v = cloud_detail::string_field(res, name);
        auto decoded = v ? cloud_detail::base64_decode(*v) : std::nullopt;
        if (!decoded) {
            throw kms_error(kms_failure::invalid_state,
                            "Cloud KMS answered without " + std::string(name) + ".");
        }
        return std::move(*decoded);
    }

    [[nodiscard]] auto call(const std::string& key, std::string_view op,
                            const boost::json::object& req) const -> boost::json::object {
        if (!gcp_detail::valid_key_name(key)) {
            throw kms_error(kms_failure::not_found,
                            "A GCP key id is projects/.../cryptoKeys/<key>: " + key);
        }
        const auto url = _config._endpoint + "/v1/" + key + ":" + std::string(op);
        const https_peer::peer_client::headers headers{
            {"Authorization", "Bearer " + _config._token.get()},
            {"Content-Type", "application/json"}};
        const auto res =
            _transport(boost::beast::http::verb::post, url, headers, boost::json::serialize(req));
        if (!res) {
            throw kms_error(kms_failure::unavailable, "Cloud KMS did not answer.");
        }
        auto parsed = cloud_detail::parse_object(res->_body);
        if (res->_status == 200) {
            return parsed;
        }
        std::string message = "Cloud KMS answered " + std::to_string(res->_status);
        std::string status;
        if (const auto* e = parsed.if_contains("error"); e != nullptr && e->is_object()) {
            message = cloud_detail::string_field(e->get_object(), "message").value_or(message);
            status = cloud_detail::string_field(e->get_object(), "status").value_or("");
        }
        throw kms_error(gcp_detail::failure_of(res->_status, status), message);
    }
};

static_assert(kms_key_provider<gcp_kms_provider>);
static_assert(wrapping_kms_key_provider<gcp_kms_provider>);

/// Tokens for Cloud KMS from the environment, as described above.
[[nodiscard]] inline auto gcp_default_token_source(const env_lookup& env, http_transport transport)
    -> token_cache {
    if (auto token = env("GOOGLE_OAUTH_ACCESS_TOKEN"); !token.empty()) {
        return token_cache([token = std::move(token)] { return access_token{._value = token}; });
    }
    if (const auto path = env("GOOGLE_APPLICATION_CREDENTIALS"); !path.empty()) {
        std::ifstream in(path);
        std::stringstream text;
        text << in.rdbuf();
        auto key = cloud_detail::parse_object(text.str());
        if (!in || cloud_detail::string_field(key, "type").value_or("") != "service_account") {
            throw std::invalid_argument(
                "GOOGLE_APPLICATION_CREDENTIALS is not a service account "
                "key file: " +
                path);
        }
        auto token_uri = cloud_detail::string_field(key, "token_uri")
                             .value_or("https://oauth2.googleapis.com/token");
        // A bad key fails here, at startup, rather than at the first seal.
        (void)gcp_detail::service_account_assertion(
            key, std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
        return token_cache([transport = std::move(transport), key = std::move(key),
                            token_uri = std::move(token_uri)] {
            const auto jwt = gcp_detail::service_account_assertion(
                key, std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
            return cloud_detail::token_from(
                transport(
                    boost::beast::http::verb::post, token_uri,
                    {{"Content-Type", "application/x-www-form-urlencoded"}},
                    "grant_type=" +
                        cloud_detail::form_escape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
                        "&assertion=" + jwt),
                "Google's token endpoint");
        });
    }
    auto host = env("GCE_METADATA_HOST");
    if (host.empty()) {
        host = "metadata.google.internal";
    }
    auto url = "http://" + host + "/computeMetadata/v1/instance/service-accounts/default/token";
    return token_cache([transport = std::move(transport), url = std::move(url)] {
        return cloud_detail::token_from(
            transport(boost::beast::http::verb::get, url, {{"Metadata-Flavor", "Google"}}, {}),
            "The GCP metadata server");
    });
}

}  // namespace kythira::kms_provider
