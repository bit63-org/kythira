// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The Azure Key Vault and GCP Cloud KMS key providers that the HSM's share
// sealers use (.kiro/specs/virtual-hsm/ task 8b), against fake clouds: the
// requests each makes, the context binding, the resolved key ids, error
// mapping, the token sources and their cache, and a share sealed and
// opened through each.

#define BOOST_TEST_MODULE hsm_cloud_kms_providers_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/share_sealers.hpp>

#include <raft/kms_key_provider_azure.hpp>
#include <raft/kms_key_provider_gcp.hpp>

#include <boost/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace hsm = kythira::hsm;
namespace kp = kythira::kms_provider;
namespace cd = kythira::kms_provider::cloud_detail;
namespace http = boost::beast::http;
namespace fs = std::filesystem;
using kythira::https_peer::peer_response;
using headers_t = kythira::https_peer::peer_client::headers;

constexpr std::array<std::uint8_t, 8> k_check{1, 2, 3, 4, 5, 6, 7, 8};
constexpr std::array<std::uint8_t, 5> k_secret{0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

auto header(const headers_t& h, const std::string& name) -> std::string {
    for (const auto& [k, v] : h) {
        if (k == name) {
            return v;
        }
    }
    return {};
}

auto random_id() -> std::string {
    std::array<unsigned char, 12> b{};
    BOOST_REQUIRE(RAND_bytes(b.data(), static_cast<int>(b.size())) == 1);
    return {b.begin(), b.end()};
}

auto reply(unsigned status, const boost::json::value& body) -> std::optional<peer_response> {
    return peer_response{._status = status, ._body = boost::json::serialize(body)};
}

auto error_body(const std::string& code, const std::string& message, const std::string& status = "")
    -> boost::json::object {
    boost::json::object e{{"code", code}, {"message", message}};
    if (!status.empty()) {
        e["status"] = status;
    }
    return {{"error", e}};
}

/// A fake Key Vault: wrapkey keeps the value under a fresh opaque blob
/// and answers with the key's current version; unwrapkey gives it back
/// to any version of the same key. `fail` answers every call with the
/// given status and body instead.
struct fake_vault {
    std::map<std::string, std::string> blobs;
    std::vector<std::string> urls;
    std::vector<std::string> algs;
    std::string version = "v1";
    std::string token = "vault-token";
    std::optional<std::pair<unsigned, boost::json::object>> fail;
    bool silent = false;

    auto transport() -> kp::http_transport {
        return [this](http::verb method, const std::string& url, const headers_t& h,
                      std::string body) -> std::optional<peer_response> {
            urls.push_back(url);
            if (silent) {
                return std::nullopt;
            }
            BOOST_TEST((method == http::verb::post));
            BOOST_TEST(header(h, "Authorization") == "Bearer " + token);
            if (fail) {
                return reply(fail->first, fail->second);
            }
            const auto req = cd::parse_object(body);
            algs.push_back(*cd::string_field(req, "alg"));
            const auto value = cd::base64_decode(*cd::string_field(req, "value"));
            BOOST_REQUIRE(value.has_value());
            const std::string base = "https://unit.vault.azure.net/keys/share";
            BOOST_REQUIRE(url.starts_with(base));
            if (url.ends_with("/wrapkey?api-version=7.4")) {
                const auto id = random_id();
                blobs[id] = *value;
                return reply(200,
                             {{"kid", base + "/" + version}, {"value", cd::base64url_encode(id)}});
            }
            BOOST_REQUIRE(url.ends_with("/unwrapkey?api-version=7.4"));
            const auto it = blobs.find(*value);
            if (it == blobs.end()) {
                return reply(400, error_body("BadParameter", "The ciphertext does not unwrap."));
            }
            return reply(
                200, {{"kid", base + "/" + version}, {"value", cd::base64url_encode(it->second)}});
        };
    }

    auto provider() -> kp::azure_key_vault_provider {
        kp::azure_key_vault_config c;
        c._token = kp::token_cache([t = token] { return kp::access_token{._value = t}; });
        return kp::azure_key_vault_provider(std::move(c), transport());
    }
};

/// A fake Cloud KMS: encrypt keeps (plaintext, aad) under a fresh blob,
/// decrypt checks the aad as Cloud KMS does.
struct fake_cloud_kms {
    struct entry {
        std::string plain;
        std::string aad;
    };
    std::map<std::string, entry> blobs;
    std::vector<std::string> urls;
    std::optional<std::pair<unsigned, boost::json::object>> fail;

    auto transport() -> kp::http_transport {
        return [this](http::verb, const std::string& url, const headers_t& h,
                      std::string body) -> std::optional<peer_response> {
            urls.push_back(url);
            BOOST_TEST(header(h, "Authorization") == "Bearer gcp-token");
            if (fail) {
                return reply(fail->first, fail->second);
            }
            const auto req = cd::parse_object(body);
            const auto aad =
                cd::base64_decode(*cd::string_field(req, "additionalAuthenticatedData"));
            BOOST_REQUIRE(aad.has_value());
            const std::string key = "projects/p/locations/global/keyRings/r/cryptoKeys/share";
            if (url == "https://cloudkms.googleapis.com/v1/" + key + ":encrypt") {
                const auto plain = cd::base64_decode(*cd::string_field(req, "plaintext"));
                const auto id = random_id();
                blobs[id] = {*plain, *aad};
                return reply(200, {{"name", key + "/cryptoKeyVersions/3"},
                                   {"ciphertext", cd::base64_encode(id)}});
            }
            BOOST_REQUIRE(url == "https://cloudkms.googleapis.com/v1/" + key + ":decrypt");
            const auto ct = cd::base64_decode(*cd::string_field(req, "ciphertext"));
            const auto it = blobs.find(*ct);
            if (it == blobs.end() || it->second.aad != *aad) {
                return reply(400, error_body("400", "Decryption failed", "INVALID_ARGUMENT"));
            }
            return reply(200, {{"plaintext", cd::base64_encode(it->second.plain)}});
        };
    }

    auto provider() -> kp::gcp_kms_provider {
        kp::gcp_kms_config c;
        c._token = kp::token_cache([] { return kp::access_token{._value = "gcp-token"}; });
        return kp::gcp_kms_provider(std::move(c), transport());
    }
};

auto failure_of(const auto& f) -> std::optional<kp::kms_failure> {
    try {
        f();
    } catch (const kp::kms_error& e) {
        return e.failure();
    }
    return std::nullopt;
}

const kp::encryption_context k_ctx{{"kythira:hsm:share", "0102030405060708"}};
const kp::encryption_context k_other_ctx{{"kythira:hsm:share", "0807060504030201"}};
const std::string k_vault_key = "https://unit.vault.azure.net/keys/share";
const std::string k_gcp_key = "projects/p/locations/global/keyRings/r/cryptoKeys/share";

}  // namespace

BOOST_AUTO_TEST_CASE(key_vault_wraps_bound_to_the_context_and_resolves_the_version) {
    fake_vault vault;
    const auto p = vault.provider();
    const auto made = p.generate_data_key(k_vault_key, k_ctx);
    BOOST_TEST(made._key_id == k_vault_key + "/v1");
    BOOST_TEST(vault.urls.back() == k_vault_key + "/wrapkey?api-version=7.4");
    BOOST_TEST(vault.algs.back() == "RSA-OAEP-256");
    // The data key and the context's digest go to the vault together.
    BOOST_TEST(vault.blobs.begin()->second.size() == 64U);
    // The key rotates: the stored versioned kid still opens it.
    vault.version = "v2";
    const auto back = p.decrypt_data_key(made._key_id, made._wrapped, k_ctx);
    BOOST_TEST((back == made._plaintext));
    BOOST_TEST(vault.urls.back() == k_vault_key + "/v1/unwrapkey?api-version=7.4");
    // Another context opens nothing, though the vault unwraps the blob.
    BOOST_TEST((failure_of([&] {
                    (void)p.decrypt_data_key(made._key_id, made._wrapped, k_other_ctx);
                }) == kp::kms_failure::invalid_state));
    // The algorithm travels with the wrapped key, so changing the
    // configured one later strands nothing.
    kp::azure_key_vault_config c;
    c._algorithm = "A256KW";
    c._token = kp::token_cache([] { return kp::access_token{._value = "vault-token"}; });
    const kp::azure_key_vault_provider aes(std::move(c), vault.transport());
    BOOST_TEST((aes.decrypt_data_key(made._key_id, made._wrapped, k_ctx) == made._plaintext));
    BOOST_TEST(vault.algs.back() == "RSA-OAEP-256");
    // Malformed wrapped keys never reach the vault.
    const auto calls = vault.urls.size();
    for (const auto& bad : {std::string(), std::string(1, '\0'), std::string("\x05RSA")}) {
        BOOST_TEST((failure_of([&] { (void)p.decrypt_data_key(made._key_id, bad, k_ctx); }) ==
                    kp::kms_failure::invalid_state));
    }
    BOOST_TEST(vault.urls.size() == calls);
}

BOOST_AUTO_TEST_CASE(key_vault_errors_map_onto_kms_failures) {
    fake_vault vault;
    const auto p = vault.provider();
    const auto gen = [&] { (void)p.generate_data_key(k_vault_key, k_ctx); };
    const std::vector<std::tuple<unsigned, std::string, kp::kms_failure>> cases{
        {403, "Operation wrapKey is not allowed on a disabled key.", kp::kms_failure::disabled},
        {403, "The user does not have keys wrapKey permission.", kp::kms_failure::access_denied},
        {401, "AKV10000: Request is missing a Bearer.", kp::kms_failure::access_denied},
        {404, "A key with (name/id) share was not found.", kp::kms_failure::not_found},
        {429, "Too many requests.", kp::kms_failure::throttling},
        {503, "Service unavailable.", kp::kms_failure::unavailable},
        {400, "Bad parameter.", kp::kms_failure::invalid_state},
    };
    for (const auto& [status, message, want] : cases) {
        vault.fail = {status, error_body("Code", message)};
        BOOST_TEST((failure_of(gen) == want), status << " " << message);
    }
    vault.fail.reset();
    vault.silent = true;
    BOOST_TEST((failure_of(gen) == kp::kms_failure::unavailable));
    // A key id that is not a vault key URL is refused before any call.
    vault.silent = false;
    const auto calls = vault.urls.size();
    for (const char* bad : {"share", "http://unit.vault.azure.net/keys/share",
                            "https://unit.vault.azure.net/secrets/x",
                            "https://unit.vault.azure.net/keys/share?x=1"}) {
        BOOST_TEST((failure_of([&] { (void)p.generate_data_key(bad, k_ctx); }) ==
                    kp::kms_failure::not_found),
                   bad);
    }
    BOOST_TEST(vault.urls.size() == calls);
}

BOOST_AUTO_TEST_CASE(azure_tokens_come_from_the_environment_and_are_cached) {
    std::vector<std::pair<std::string, std::string>> calls;
    unsigned expires = 3600;
    const kp::http_transport token_server = [&](http::verb, const std::string& url,
                                                const headers_t& h, std::string body) {
        calls.emplace_back(url, body);
        if (url.starts_with("http://169.254.169.254/")) {
            BOOST_TEST(header(h, "Metadata") == "true");
            // The metadata service sends expires_in as a string.
            return reply(200,
                         {{"access_token", "mi-token"}, {"expires_in", std::to_string(expires)}});
        }
        BOOST_TEST(header(h, "Content-Type") == "application/x-www-form-urlencoded");
        return reply(200, {{"access_token", "sp-token"}, {"expires_in", expires}});
    };
    std::map<std::string, std::string> env;
    const kp::env_lookup lookup = [&env](const char* v) {
        const auto it = env.find(v);
        return it == env.end() ? std::string() : it->second;
    };

    // A token as given.
    env["AZURE_ACCESS_TOKEN"] = "given";
    BOOST_TEST(kp::azure_default_token_source(k_vault_key, lookup, token_server).get() == "given");
    BOOST_TEST(calls.empty());

    // A service principal: one fetch serves calls until near expiry.
    env.erase("AZURE_ACCESS_TOKEN");
    env["AZURE_TENANT_ID"] = "tenant";
    env["AZURE_CLIENT_ID"] = "client";
    env["AZURE_CLIENT_SECRET"] = "s3cret&=";
    auto sp = kp::azure_default_token_source(k_vault_key, lookup, token_server);
    BOOST_TEST(sp.get() == "sp-token");
    BOOST_TEST(sp.get() == "sp-token");
    BOOST_REQUIRE(calls.size() == 1U);
    BOOST_TEST(calls[0].first == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token");
    BOOST_TEST(calls[0].second ==
               "grant_type=client_credentials&client_id=client&client_secret=s3cret%26%3D"
               "&scope=https%3A%2F%2Fvault.azure.net%2F.default");
    // A token within five minutes of expiry is fetched again.
    expires = 60;
    auto short_lived = kp::azure_default_token_source(k_vault_key, lookup, token_server);
    (void)short_lived.get();
    (void)short_lived.get();
    BOOST_TEST(calls.size() == 3U);

    // Managed identity, user-assigned; a Managed HSM's audience.
    env.erase("AZURE_TENANT_ID");
    env.erase("AZURE_CLIENT_SECRET");
    expires = 3600;
    auto mi = kp::azure_default_token_source("https://pool.managedhsm.azure.net/keys/k", lookup,
                                             token_server);
    BOOST_TEST(mi.get() == "mi-token");
    BOOST_TEST(calls.back().first ==
               "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
               "&resource=https%3A%2F%2Fmanagedhsm.azure.net&client_id=client");

    // A refusal is access denied; no answer is unavailable.
    const kp::http_transport refusing = [](http::verb, const std::string&, const headers_t&,
                                           std::string) {
        return reply(400, {{"error", "invalid_client"}, {"error_description", "bad secret"}});
    };
    env["AZURE_TENANT_ID"] = "tenant";
    env["AZURE_CLIENT_SECRET"] = "x";
    auto refused = kp::azure_default_token_source(k_vault_key, lookup, refusing);
    BOOST_TEST((failure_of([&] { (void)refused.get(); }) == kp::kms_failure::access_denied));
    auto away = kp::azure_default_token_source(
        k_vault_key, lookup,
        [](http::verb, const std::string&, const headers_t&,
           std::string) -> std::optional<peer_response> { return std::nullopt; });
    BOOST_TEST((failure_of([&] { (void)away.get(); }) == kp::kms_failure::unavailable));
}

BOOST_AUTO_TEST_CASE(cloud_kms_wraps_with_the_context_as_aad) {
    fake_cloud_kms kms;
    const auto p = kms.provider();
    const auto made = p.generate_data_key(k_gcp_key, k_ctx);
    // A version name is cut back to the crypto key, which decrypt takes.
    BOOST_TEST(made._key_id == k_gcp_key);
    BOOST_TEST((p.decrypt_data_key(made._key_id, made._wrapped, k_ctx) == made._plaintext));
    BOOST_TEST((p.decrypt_data_key(k_gcp_key + "/cryptoKeyVersions/3", made._wrapped, k_ctx) ==
                made._plaintext));
    BOOST_TEST((failure_of([&] {
                    (void)p.decrypt_data_key(made._key_id, made._wrapped, k_other_ctx);
                }) == kp::kms_failure::invalid_state));
    BOOST_TEST(cd::context_binding(k_ctx) != cd::context_binding(k_other_ctx));
    BOOST_TEST(cd::context_binding({{"ab", "c"}}) != cd::context_binding({{"a", "bc"}}));

    const auto gen = [&] { (void)p.generate_data_key(k_gcp_key, k_ctx); };
    const std::vector<std::tuple<unsigned, std::string, kp::kms_failure>> cases{
        {403, "PERMISSION_DENIED", kp::kms_failure::access_denied},
        {401, "UNAUTHENTICATED", kp::kms_failure::access_denied},
        {404, "NOT_FOUND", kp::kms_failure::not_found},
        {400, "FAILED_PRECONDITION", kp::kms_failure::disabled},
        {429, "RESOURCE_EXHAUSTED", kp::kms_failure::throttling},
        {503, "UNAVAILABLE", kp::kms_failure::unavailable},
        {400, "INVALID_ARGUMENT", kp::kms_failure::invalid_state},
    };
    for (const auto& [status, name, want] : cases) {
        kms.fail = {status, error_body(std::to_string(status), "no", name)};
        BOOST_TEST((failure_of(gen) == want), name);
    }
    kms.fail.reset();
    const auto calls = kms.urls.size();
    for (const char* bad : {"share", "projects/p/keyRings/r", "projects/p/cryptoKeys/k?x",
                            "projects/../cryptoKeys/k"}) {
        BOOST_TEST((failure_of([&] { (void)p.generate_data_key(bad, k_ctx); }) ==
                    kp::kms_failure::not_found),
                   bad);
    }
    BOOST_TEST(kms.urls.size() == calls);
}

BOOST_AUTO_TEST_CASE(gcp_tokens_come_from_the_environment) {
    // A service account key file, signed with a fresh RSA key.
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_RSA_gen(2048),
                                                                   &EVP_PKEY_free);
    BOOST_REQUIRE(pkey != nullptr);
    const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    BOOST_REQUIRE(PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr,
                                           nullptr) == 1);
    char* pem_data = nullptr;
    const auto pem_len = BIO_get_mem_data(bio.get(), &pem_data);
    const std::string pem(pem_data, static_cast<std::size_t>(pem_len));
    std::random_device rd;
    const auto key_file = fs::temp_directory_path() / ("gcp-sa-" + std::to_string(rd()) + ".json");
    {
        std::ofstream out(key_file);
        out << boost::json::serialize(
            boost::json::object{{"type", "service_account"},
                                {"client_email", "sealer@p.iam.gserviceaccount.com"},
                                {"private_key_id", "kid1"},
                                {"private_key", pem},
                                {"token_uri", "https://oauth2.example.test/token"}});
    }

    std::vector<std::string> urls;
    const kp::http_transport token_server = [&](http::verb, const std::string& url,
                                                const headers_t& h, std::string body) {
        urls.push_back(url);
        if (url.starts_with("http://")) {
            BOOST_TEST(header(h, "Metadata-Flavor") == "Google");
            return reply(200, {{"access_token", "md-token"}, {"expires_in", 3599}});
        }
        const std::string prefix =
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
        BOOST_REQUIRE(body.starts_with(prefix));
        const auto jwt = body.substr(prefix.size());
        const auto dot1 = jwt.find('.');
        const auto dot2 = jwt.rfind('.');
        const auto head = cd::parse_object(*cd::base64_decode(jwt.substr(0, dot1)));
        const auto claims =
            cd::parse_object(*cd::base64_decode(jwt.substr(dot1 + 1, dot2 - dot1 - 1)));
        BOOST_TEST(*cd::string_field(head, "alg") == "RS256");
        BOOST_TEST(*cd::string_field(head, "kid") == "kid1");
        BOOST_TEST(*cd::string_field(claims, "iss") == "sealer@p.iam.gserviceaccount.com");
        BOOST_TEST(*cd::string_field(claims, "aud") == "https://oauth2.example.test/token");
        BOOST_TEST(*cd::string_field(claims, "scope") ==
                   "https://www.googleapis.com/auth/cloudkms");
        // The signature verifies under the key's public half.
        const auto sig = *cd::base64_decode(jwt.substr(dot2 + 1));
        const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(),
                                                                         &EVP_MD_CTX_free);
        BOOST_REQUIRE(EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) ==
                      1);
        BOOST_TEST(EVP_DigestVerify(md.get(), reinterpret_cast<const unsigned char*>(sig.data()),
                                    sig.size(), reinterpret_cast<const unsigned char*>(jwt.data()),
                                    dot2) == 1);
        return reply(200, {{"access_token", "sa-token"}, {"expires_in", 3599}});
    };
    std::map<std::string, std::string> env;
    const kp::env_lookup lookup = [&env](const char* v) {
        const auto it = env.find(v);
        return it == env.end() ? std::string() : it->second;
    };
    env["GOOGLE_OAUTH_ACCESS_TOKEN"] = "given";
    BOOST_TEST(kp::gcp_default_token_source(lookup, token_server).get() == "given");
    env.erase("GOOGLE_OAUTH_ACCESS_TOKEN");
    env["GOOGLE_APPLICATION_CREDENTIALS"] = key_file.string();
    BOOST_TEST(kp::gcp_default_token_source(lookup, token_server).get() == "sa-token");
    BOOST_TEST(urls.back() == "https://oauth2.example.test/token");
    env.erase("GOOGLE_APPLICATION_CREDENTIALS");
    env["GCE_METADATA_HOST"] = "169.254.169.254";
    BOOST_TEST(kp::gcp_default_token_source(lookup, token_server).get() == "md-token");
    BOOST_TEST(urls.back() ==
               "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token");
    // A file that is not a service account key fails at startup.
    {
        std::ofstream out(key_file);
        out << R"({"type":"authorized_user"})";
    }
    env["GOOGLE_APPLICATION_CREDENTIALS"] = key_file.string();
    BOOST_CHECK_THROW((void)kp::gcp_default_token_source(lookup, token_server),
                      std::invalid_argument);
    std::error_code ec;
    fs::remove(key_file, ec);
}

BOOST_AUTO_TEST_CASE(a_share_round_trips_through_each_cloud) {
    fake_vault vault;
    fake_cloud_kms kms;
    hsm::kms_share_sealer azure("azure-key-vault", kp::key_provider(vault.provider()), k_vault_key);
    hsm::kms_share_sealer gcp("gcp-kms", kp::key_provider(kms.provider()), k_gcp_key);
    for (auto* sealer : {&azure, &gcp}) {
        const auto sealed = sealer->seal(k_secret, k_check);
        const auto back = sealer->unseal(sealed, k_check);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST(hsm::constant_time_equal(back->view(), k_secret));
        // Bound to the check value through the provider too.
        constexpr std::array<std::uint8_t, 8> other{8, 7, 6, 5, 4, 3, 2, 1};
        BOOST_TEST(!sealer->unseal(sealed, other).has_value());
    }
    // Each names its own sealer: one cloud's share is not handed to the
    // other.
    BOOST_TEST(!gcp.unseal(azure.seal(k_secret, k_check), k_check).has_value());
    BOOST_TEST(gcp.last_error().find("azure-key-vault") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(urls_parse_with_default_ports) {
    const auto a = cd::parse_url("https://v.vault.azure.net/keys/k");
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST(a->_host_port == "v.vault.azure.net:443");
    BOOST_TEST(a->_target == "/keys/k");
    const auto b = cd::parse_url("http://[::1]:8080");
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(!b->_tls);
    BOOST_TEST(b->_host_port == "[::1]:8080");
    BOOST_TEST(b->_target == "/");
    BOOST_TEST(cd::parse_url("http://[::1]/x")->_host_port == "[::1]:80");
    BOOST_TEST(!cd::parse_url("ftp://x").has_value());
    BOOST_TEST(!cd::parse_url("https://user@host/").has_value());
    BOOST_TEST(!cd::parse_url("https:///x").has_value());
    BOOST_TEST(cd::base64url_encode("\xfb\xff") == "-_8");
    BOOST_TEST(*cd::base64_decode("-_8") == "\xfb\xff");
}
