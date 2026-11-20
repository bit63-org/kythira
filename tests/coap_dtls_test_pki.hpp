// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Real certificate material and a real DTLS handshake for the CoAP DTLS
// property tests (coap_dtls_handshake_property_test,
// coap_cipher_suite_property_test).
//
// Those tests used to point cert_file/key_file/ca_file at paths that did not
// exist, catch whatever the constructor threw as "expected if certificate
// files don't exist (stub implementation)", and pass with BOOST_CHECK(true).
// Nothing they ran could fail. This header gives them a CA, server and client
// certificates of either key type, a second unrelated CA, and an expired
// server certificate, all generated with OpenSSL into a temporary directory,
// plus a helper that runs one client handshake against a coap_server bound to
// an ephemeral port.

#include <raft/coap_transport.hpp>
#include <raft/coap_transport_impl.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>

#include <boost/test/unit_test.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace kythira::testing::coap_dtls {

// Runs on every future backend, unlike test_types.hpp's
// test_transport_types, which needs Folly.
using dtls_test_types =
    kythira::default_transport_types<kythira::future_default<kythira::request_vote_response<>>,
                                     kythira::json_rpc_serializer<std::vector<std::byte>>,
                                     kythira::noop_metrics, kythira::console_logger>;

/// The seed for one property test's generator: $KYTHIRA_COAP_DTLS_SEED when
/// set, so a failure can be replayed, otherwise a fresh one. Logged either way.
[[nodiscard]] inline auto property_seed() -> std::uint32_t {
    std::uint32_t seed = std::random_device{}();
    if (const char* env = std::getenv("KYTHIRA_COAP_DTLS_SEED"); env != nullptr && *env != '\0') {
        seed = static_cast<std::uint32_t>(std::strtoul(env, nullptr, 10));
    }
    BOOST_TEST_MESSAGE("KYTHIRA_COAP_DTLS_SEED=" << seed);
    return seed;
}

enum class key_type {
    ec,
    rsa
};

[[nodiscard]] inline auto to_string(key_type type) -> const char* {
    return type == key_type::ec ? "ec" : "rsa";
}

/// Whether a certificate with a `type` key can authenticate `suite` (an IANA
/// name): ECDSA suites need an EC key, RSA ones (ECDHE_RSA, DHE_RSA, static
/// RSA) an RSA key.
[[nodiscard]] inline auto suite_fits_key(const std::string& suite, key_type type) -> bool {
    if (type == key_type::ec) {
        return suite.find("_ECDSA_") != std::string::npos;
    }
    return suite.find("_RSA_") != std::string::npos;
}

namespace detail {

struct pkey_deleter {
    auto operator()(EVP_PKEY* key) const -> void { EVP_PKEY_free(key); }
};
struct x509_deleter {
    auto operator()(X509* cert) const -> void { X509_free(cert); }
};
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;

inline auto make_key(key_type type) -> pkey_ptr {
    pkey_ptr key(type == key_type::ec ? EVP_EC_gen("P-256") : EVP_RSA_gen(2048));
    BOOST_REQUIRE(key != nullptr);
    return key;
}

inline auto add_extension(X509* cert, X509* issuer, int nid, const char* value) -> void {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    BOOST_REQUIRE(ext != nullptr);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

// `issuer == nullptr` makes a self-signed CA. `not_before`/`not_after` are
// seconds from now.
inline auto make_cert(const char* common_name, long serial, EVP_PKEY* subject_key, X509* issuer,
                      EVP_PKEY* issuer_key, long not_before, long not_after) -> x509_ptr {
    x509_ptr cert(X509_new());
    BOOST_REQUIRE(cert != nullptr);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), not_before);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), not_after);
    X509_set_pubkey(cert.get(), subject_key);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name);
    if (issuer == nullptr) {
        add_extension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE");
        add_extension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_extension(cert.get(), issuer, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    }
    BOOST_REQUIRE(X509_sign(cert.get(), issuer_key, EVP_sha256()) > 0);
    return cert;
}

}  // namespace detail

/// A CA with a server and a client certificate of one key type, a second CA
/// that signed neither, a server certificate that CA *did* sign, and an
/// expired server certificate from the real CA. Files live until destruction.
class test_pki {
public:
    explicit test_pki(key_type type) : _type(type) {
        _dir = std::filesystem::temp_directory_path() /
               std::format("coap_dtls_test_pki_{}_{}", to_string(type), std::random_device{}());
        std::filesystem::create_directories(_dir);

        constexpr long day = 60L * 60L * 24L;
        auto ca_key = detail::make_key(type);
        auto ca =
            detail::make_cert("kythira-test-ca", 1, ca_key.get(), nullptr, ca_key.get(), -60, day);
        auto server_key = detail::make_key(type);
        auto server =
            detail::make_cert("localhost", 2, server_key.get(), ca.get(), ca_key.get(), -60, day);
        auto client_key = detail::make_key(type);
        auto client =
            detail::make_cert("client", 3, client_key.get(), ca.get(), ca_key.get(), -60, day);
        auto expired_key = detail::make_key(type);
        auto expired = detail::make_cert("localhost", 4, expired_key.get(), ca.get(), ca_key.get(),
                                         -2 * day, -day);
        auto other_ca_key = detail::make_key(type);
        auto other_ca = detail::make_cert("kythira-other-ca", 5, other_ca_key.get(), nullptr,
                                          other_ca_key.get(), -60, day);
        auto stranger_key = detail::make_key(type);
        auto stranger = detail::make_cert("localhost", 6, stranger_key.get(), other_ca.get(),
                                          other_ca_key.get(), -60, day);

        ca_file = write_cert("ca.pem", ca.get());
        server_cert_file = write_cert("server.pem", server.get());
        server_key_file = write_key("server.key", server_key.get());
        client_cert_file = write_cert("client.pem", client.get());
        client_key_file = write_key("client.key", client_key.get());
        expired_cert_file = write_cert("expired.pem", expired.get());
        expired_key_file = write_key("expired.key", expired_key.get());
        other_ca_file = write_cert("other-ca.pem", other_ca.get());
        stranger_cert_file = write_cert("stranger.pem", stranger.get());
        stranger_key_file = write_key("stranger.key", stranger_key.get());
    }

    ~test_pki() {
        std::error_code ec;
        std::filesystem::remove_all(_dir, ec);
    }

    test_pki(const test_pki&) = delete;
    auto operator=(const test_pki&) -> test_pki& = delete;
    test_pki(test_pki&&) = delete;
    auto operator=(test_pki&&) -> test_pki& = delete;

    [[nodiscard]] auto type() const -> key_type { return _type; }
    [[nodiscard]] auto dir() const -> const std::filesystem::path& { return _dir; }

    /// Mutual-authentication server configuration restricted to `suites`.
    [[nodiscard]] auto server_config(std::vector<std::string> suites = {}) const
        -> coap_server_config {
        coap_server_config config;
        config.enable_dtls = true;
        config.cert_file = server_cert_file;
        config.key_file = server_key_file;
        config.ca_file = ca_file;
        config.verify_peer_cert = true;
        config.cipher_suites = std::move(suites);
        return config;
    }

    /// Mutual-authentication client configuration restricted to `suites`.
    [[nodiscard]] auto client_config(std::vector<std::string> suites = {}) const
        -> coap_client_config {
        coap_client_config config;
        config.enable_dtls = true;
        config.cert_file = client_cert_file;
        config.key_file = client_key_file;
        config.ca_file = ca_file;
        config.verify_peer_cert = true;
        config.cipher_suites = std::move(suites);
        return config;
    }

    std::string ca_file;
    std::string server_cert_file, server_key_file;
    std::string client_cert_file, client_key_file;
    std::string expired_cert_file, expired_key_file;
    std::string other_ca_file;
    std::string stranger_cert_file, stranger_key_file;

private:
    auto write_cert(const char* name, X509* cert) const -> std::string {
        const auto path = (_dir / name).string();
        FILE* f = std::fopen(path.c_str(), "w");
        BOOST_REQUIRE(f != nullptr);
        const int ok = PEM_write_X509(f, cert);
        std::fclose(f);
        BOOST_REQUIRE(ok == 1);
        return path;
    }

    auto write_key(const char* name, EVP_PKEY* key) const -> std::string {
        const auto path = (_dir / name).string();
        FILE* f = std::fopen(path.c_str(), "w");
        BOOST_REQUIRE(f != nullptr);
        const int ok = PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(f);
        BOOST_REQUIRE(ok == 1);
        return path;
    }

    key_type _type;
    std::filesystem::path _dir;
};

/// A started DTLS coap_server on an ephemeral port, stopped on destruction.
class running_server {
public:
    explicit running_server(coap_server_config config)
        : _server("127.0.0.1", 0, std::move(config), _metrics) {
        _server.start();
    }
    ~running_server() { _server.stop(); }

    running_server(const running_server&) = delete;
    auto operator=(const running_server&) -> running_server& = delete;
    running_server(running_server&&) = delete;
    auto operator=(running_server&&) -> running_server& = delete;

    [[nodiscard]] auto endpoint() const -> std::string {
        return std::format("coaps://127.0.0.1:{}", _server.bound_port());
    }

private:
    dtls_test_types::metrics_type _metrics;
    coap_server<dtls_test_types> _server;
};

/// Whether one client handshake with `endpoint` completes.
inline auto handshake_with(const std::string& endpoint, coap_client_config config) -> bool {
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> client({{1, endpoint}}, std::move(config), metrics);
    return client.initiate_dtls_handshake(endpoint) && client.complete_dtls_handshake(endpoint);
}

/// Whether a client configured with `client` completes a handshake with a
/// fresh server configured with `server`.
inline auto handshake(coap_server_config server, coap_client_config client) -> bool {
    running_server peer(std::move(server));
    return handshake_with(peer.endpoint(), std::move(client));
}

}  // namespace kythira::testing::coap_dtls
