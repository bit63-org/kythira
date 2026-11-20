// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/**
 * **Feature: coap-transport, Property 35: Complete DTLS handshake implementation**
 *
 * The CoAP transport completes real DTLS handshakes with certificate and PSK
 * authentication, refuses the ones whose credentials do not check out, and
 * rejects invalid DTLS configurations at construction.
 *
 * These cases used to construct a client and a server and stop there, with
 * nonexistent certificate paths, and accept any coap_security_error as
 * "expected if certificate files don't exist (stub implementation)". Each
 * check was BOOST_CHECK(true), so nothing they ran could fail. Every case
 * below now asserts an outcome: a handshake against a live coap_server that
 * must complete or must be refused, or a constructor that must throw or must
 * not.
 *
 * **Validates: Requirements 6.1, 6.2, 6.3**
 */
#define BOOST_TEST_MODULE coap_dtls_handshake_property_test
#include <boost/test/unit_test.hpp>

#include "coap_dtls_test_pki.hpp"
#include "test_timeout_scale.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

using namespace kythira;
using namespace kythira::testing::coap_dtls;

namespace {

// Each iteration is a real handshake, so this is far fewer than the 100
// construct-only iterations the cases used to run, and still covers every
// configuration variant several times over per key type.
constexpr std::size_t handshake_iterations = 12;
constexpr std::size_t validation_iterations = 200;

const std::vector<std::string> mixed_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};

const std::vector<std::string> modern_suites = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"};

// Both key types' material, generated once per process: RSA key generation
// is the slowest thing these cases do.
auto pki_for(key_type type) -> const test_pki& {
    static const test_pki ec(key_type::ec);
    static const test_pki rsa(key_type::rsa);
    return type == key_type::ec ? ec : rsa;
}

auto random_identity(std::mt19937& gen, std::size_t length) -> std::string {
    std::uniform_int_distribution<int> letter('a', 'z');
    std::string identity(length, 'a');
    for (auto& c : identity) {
        c = static_cast<char>(letter(gen));
    }
    return identity;
}

auto random_key(std::mt19937& gen, std::size_t length) -> std::vector<std::byte> {
    std::uniform_int_distribution<int> byte(0, 255);
    std::vector<std::byte> key(length);
    for (auto& b : key) {
        b = static_cast<std::byte>(byte(gen));
    }
    return key;
}

auto psk_client(std::string identity, std::vector<std::byte> key) -> coap_client_config {
    coap_client_config config;
    config.enable_dtls = true;
    config.psk_identity = std::move(identity);
    config.psk_key = std::move(key);
    return config;
}

auto psk_server(std::string identity, std::vector<std::byte> key) -> coap_server_config {
    coap_server_config config;
    config.enable_dtls = true;
    config.psk_identity = std::move(identity);
    config.psk_key = std::move(key);
    return config;
}

auto constructs(const coap_client_config& config) -> bool {
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> client({{1, "coaps://127.0.0.1:5684"}}, config, metrics);
    return true;
}

auto constructs(const coap_server_config& config) -> bool {
    dtls_test_types::metrics_type metrics;
    coap_server<dtls_test_types> server("127.0.0.1", 0, config, metrics);
    return true;
}

}  // namespace

/**
 * Property 35, configuration validation (Requirements 6.1, 6.3): a DTLS
 * configuration with no credentials, a PSK outside 16..64 bytes, or a PSK
 * identity over 128 characters is refused with coap_security_error by both
 * the client and the server constructor; every other PSK length/identity
 * combination constructs. Needs no network, so it also holds on the stub
 * (no libcoap) build.
 */
BOOST_AUTO_TEST_CASE(test_dtls_configuration_validation,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> key_length_dist(0, 100);
    std::uniform_int_distribution<std::size_t> identity_length_dist(1, 200);

    for (std::size_t iteration = 0; iteration < validation_iterations; ++iteration) {
        const auto key_length = key_length_dist(gen);
        const auto identity_length = identity_length_dist(gen);
        const bool valid = key_length >= coap_min_psk_key_length &&
                           key_length <= coap_max_psk_key_length && identity_length <= 128;
        const auto identity = random_identity(gen, identity_length);
        const auto key = random_key(gen, key_length);

        BOOST_TEST_CONTEXT("key " << key_length << " bytes, identity " << identity_length
                                  << " characters") {
            if (valid) {
                BOOST_CHECK_NO_THROW(constructs(psk_client(identity, key)));
                BOOST_CHECK_NO_THROW(constructs(psk_server(identity, key)));
            } else {
                BOOST_CHECK_THROW(constructs(psk_client(identity, key)), coap_security_error);
                BOOST_CHECK_THROW(constructs(psk_server(identity, key)), coap_security_error);
            }
        }
    }

    // DTLS with no credentials at all, or only half of either kind.
    const auto& pki = pki_for(key_type::ec);
    coap_client_config no_auth;
    no_auth.enable_dtls = true;
    BOOST_CHECK_THROW(constructs(no_auth), coap_security_error);
    coap_server_config server_no_auth;
    server_no_auth.enable_dtls = true;
    BOOST_CHECK_THROW(constructs(server_no_auth), coap_security_error);

    auto key_only = no_auth;
    key_only.psk_key = std::vector<std::byte>(16, std::byte{0x01});
    BOOST_CHECK_THROW(constructs(key_only), coap_security_error);
    auto identity_only = no_auth;
    identity_only.psk_identity = "identity";
    BOOST_CHECK_THROW(constructs(identity_only), coap_security_error);
    auto cert_only = no_auth;
    cert_only.cert_file = pki.client_cert_file;
    BOOST_CHECK_THROW(constructs(cert_only), coap_security_error);

    // A complete certificate configuration constructs on both sides, and
    // with DTLS off no credentials are needed.
    BOOST_CHECK_NO_THROW(constructs(pki.client_config()));
    BOOST_CHECK_NO_THROW(constructs(pki.server_config()));
    BOOST_CHECK_NO_THROW(constructs(coap_client_config{}));
}

#ifdef LIBCOAP_AVAILABLE

/**
 * Property 35, certificate authentication (Requirements 6.1, 6.3): for
 * either key type, mutual certificate authentication completes a handshake
 * with the standard configuration, with a restricted cipher-suite list that
 * fits the key, with peer verification off and no CA on either side, and
 * with session resumption off.
 */
BOOST_AUTO_TEST_CASE(test_dtls_handshake_certificate_authentication,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> variant_dist(0, 3);

    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        for (std::size_t iteration = 0; iteration < handshake_iterations; ++iteration) {
            const auto variant = variant_dist(gen);
            auto server = pki.server_config();
            auto client = pki.client_config();
            switch (variant) {
                case 0:  // standard mutual authentication
                    break;
                case 1:  // custom cipher suites on both sides
                    client.cipher_suites = mixed_suites;
                    server.cipher_suites = mixed_suites;
                    break;
                case 2:  // no verification and no CA on either side
                    client.verify_peer_cert = false;
                    client.ca_file.clear();
                    server.verify_peer_cert = false;
                    server.ca_file.clear();
                    break;
                case 3:  // session resumption disabled
                    client.enable_session_resumption = false;
                    server.enable_session_resumption = false;
                    break;
                default:
                    break;
            }
            BOOST_TEST_CONTEXT("key " << to_string(type) << ", variant " << variant) {
                BOOST_TEST(handshake(server, client));
            }
        }
    }
}

/**
 * Property 35, certificate validation failures (Requirements 6.1, 6.2): a
 * handshake is refused when the server's certificate is from a CA the client
 * does not trust, or has expired; when the client trusts only some other CA;
 * when the client's certificate is from an untrusted CA or has expired; when
 * a key does not match its certificate; and when the certificate file does
 * not exist. Each refusal is paired with the control that differs only in
 * the one thing being checked, so a handshake that fails for an unrelated
 * reason cannot pass the case.
 */
BOOST_AUTO_TEST_CASE(test_dtls_certificate_validation_failures_refuse_the_handshake,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        BOOST_TEST_CONTEXT("key " << to_string(type)) {
            // Control: the unmodified pair connects.
            BOOST_TEST(handshake(pki.server_config(), pki.client_config()));

            // Server certificates the client must reject. The server does not
            // check the client here, so only the client's verdict counts.
            auto stranger_server = pki.server_config();
            stranger_server.cert_file = pki.stranger_cert_file;
            stranger_server.key_file = pki.stranger_key_file;
            stranger_server.verify_peer_cert = false;
            BOOST_TEST(!handshake(stranger_server, pki.client_config()));
            auto unverifying_client = pki.client_config();
            unverifying_client.verify_peer_cert = false;
            unverifying_client.ca_file.clear();
            BOOST_TEST(handshake(stranger_server, unverifying_client));

            auto expired_server = pki.server_config();
            expired_server.cert_file = pki.expired_cert_file;
            expired_server.key_file = pki.expired_key_file;
            expired_server.verify_peer_cert = false;
            BOOST_TEST(!handshake(expired_server, pki.client_config()));

            auto other_ca_client = pki.client_config();
            other_ca_client.ca_file = pki.other_ca_file;
            BOOST_TEST(!handshake(pki.server_config(), other_ca_client));

            // Client certificates the server must reject.
            auto stranger_client = pki.client_config();
            stranger_client.cert_file = pki.stranger_cert_file;
            stranger_client.key_file = pki.stranger_key_file;
            BOOST_TEST(!handshake(pki.server_config(), stranger_client));
            auto unverifying_server = pki.server_config();
            unverifying_server.verify_peer_cert = false;
            BOOST_TEST(handshake(unverifying_server, stranger_client));

            auto expired_client = pki.client_config();
            expired_client.cert_file = pki.expired_cert_file;
            expired_client.key_file = pki.expired_key_file;
            BOOST_TEST(!handshake(pki.server_config(), expired_client));

            // A private key that does not belong to the certificate.
            auto mismatched_client = pki.client_config();
            mismatched_client.key_file = pki.server_key_file;
            BOOST_TEST(!handshake(pki.server_config(), mismatched_client));

            // A certificate path that does not exist. Construction accepts it
            // (detail::set_coap_pki_key() falls back to the path so the
            // mistake surfaces at handshake time); the handshake must not
            // then succeed on anything else.
            auto missing_client = pki.client_config();
            missing_client.cert_file = (pki.dir() / "missing.pem").string();
            BOOST_TEST(!handshake(pki.server_config(), missing_client));
        }
    }
}

/**
 * Property 35, PSK authentication (Requirements 6.1, 6.3): any identity of
 * 1..128 characters with any key of 16..64 bytes completes a handshake when
 * both sides hold the same pair, and a client presenting an identity the
 * server does not know, or the right identity with the wrong key, is
 * refused.
 */
BOOST_AUTO_TEST_CASE(test_dtls_handshake_psk_authentication,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(120))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> key_length_dist(coap_min_psk_key_length,
                                                               coap_max_psk_key_length);
    std::uniform_int_distribution<std::size_t> identity_length_dist(1, 128);

    for (std::size_t iteration = 0; iteration < 2 * handshake_iterations; ++iteration) {
        const auto identity = random_identity(gen, identity_length_dist(gen));
        const auto key = random_key(gen, key_length_dist(gen));
        BOOST_TEST_CONTEXT("identity " << identity.size() << " characters, key " << key.size()
                                       << " bytes") {
            auto stranger = identity;
            stranger.back() = stranger.back() == 'a' ? 'b' : 'a';
            running_server server(psk_server(identity, key));
            BOOST_TEST(handshake_with(server.endpoint(), psk_client(identity, key)));
            BOOST_TEST(!handshake_with(server.endpoint(), psk_client(stranger, key)));
        }
    }

    // A wrong key is only discovered at the client's Finished, which the
    // server drops without an alert, so the client waits out its whole
    // handshake timeout (dtls_handshake_timeout, 10 s). Once is enough.
    const auto key = random_key(gen, 16);
    auto wrong_key = key;
    wrong_key[0] ^= std::byte{0xFF};
    running_server server(psk_server("node-1", key));
    BOOST_TEST(!handshake_with(server.endpoint(), psk_client("node-1", wrong_key)));
}

/**
 * Property 35, session resumption setting (Requirements 6.1, 6.3): with
 * enable_session_resumption on or off, a client completes a handshake with
 * every one of several servers, and a second client then reaches the first
 * of them again, over both PSK and certificates.
 *
 * enable_session_resumption is only logged today; libcoap is not asked to
 * resume sessions. So this pins that the setting is harmless either way,
 * not that a session is actually resumed.
 */
BOOST_AUTO_TEST_CASE(test_dtls_session_resumption,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> server_count_dist(1, 3);
    const auto& pki = pki_for(key_type::ec);
    const auto psk_key = std::vector<std::byte>(16, std::byte{0x5A});

    for (std::size_t iteration = 0; iteration < handshake_iterations; ++iteration) {
        const bool resumption = iteration % 2 == 0;
        const bool use_psk = (iteration / 2) % 2 == 0;
        const auto server_count = server_count_dist(gen);

        auto server_config =
            use_psk ? psk_server("test_session_resumption", psk_key) : pki.server_config();
        auto client_config =
            use_psk ? psk_client("test_session_resumption", psk_key) : pki.client_config();
        server_config.enable_session_resumption = resumption;
        server_config.max_concurrent_sessions = server_count * 2;
        client_config.enable_session_resumption = resumption;
        client_config.max_sessions = server_count * 2;

        BOOST_TEST_CONTEXT((use_psk ? "psk" : "certificate")
                           << ", resumption " << (resumption ? "on" : "off") << ", " << server_count
                           << " servers") {
            std::vector<std::unique_ptr<running_server>> servers;
            std::unordered_map<std::uint64_t, std::string> endpoints;
            for (std::size_t i = 0; i < server_count; ++i) {
                servers.push_back(std::make_unique<running_server>(server_config));
                endpoints[i + 1] = servers.back()->endpoint();
            }
            dtls_test_types::metrics_type metrics;
            coap_client<dtls_test_types> client(endpoints, client_config, metrics);
            for (const auto& [id, endpoint] : endpoints) {
                BOOST_TEST(client.initiate_dtls_handshake(endpoint));
                BOOST_TEST(client.complete_dtls_handshake(endpoint));
            }
            BOOST_TEST(handshake_with(endpoints.at(1), client_config));
        }
    }
}

/**
 * Property 35, cipher-suite configuration (Requirements 6.1, 6.4): with both
 * sides restricted to the same random subset of the modern ECDHE suites, the
 * handshake completes exactly when the subset holds a suite the key type can
 * authenticate (an ECDSA suite for an EC certificate, an RSA one for RSA).
 * An empty list keeps the defaults and always connects.
 */
BOOST_AUTO_TEST_CASE(test_dtls_cipher_suite_configuration,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> count_dist(1, 3);

    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        for (std::size_t iteration = 0; iteration < 2 * handshake_iterations; ++iteration) {
            auto pool = modern_suites;
            std::shuffle(pool.begin(), pool.end(), gen);
            pool.resize(count_dist(gen));
            const bool expect = std::ranges::any_of(
                pool, [type](const std::string& suite) { return suite_fits_key(suite, type); });

            std::string described;
            for (const auto& suite : pool) {
                described += suite + " ";
            }
            BOOST_TEST_CONTEXT("key " << to_string(type) << ", suites " << described) {
                BOOST_TEST(handshake(pki.server_config(pool), pki.client_config(pool)) == expect);
            }
        }
        BOOST_TEST(handshake(pki.server_config(), pki.client_config()));
    }
}

#else

BOOST_AUTO_TEST_CASE(test_dtls_handshakes_require_libcoap) {
    BOOST_TEST_MESSAGE("libcoap not available; only configuration validation was checked");
}

#endif  // LIBCOAP_AVAILABLE
