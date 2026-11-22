// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/**
 * **Feature: coap-transport, Property 9: DTLS connection establishment**
 *
 * For any CoAPS endpoint, coap_client::establish_dtls_connection() completes
 * a DTLS connection when the peer's credentials check out (certificates of
 * either key type, or a PSK), refuses one when they do not, gives up on an
 * endpoint nobody answers, and rejects malformed endpoints before touching
 * the network.
 *
 * These cases used to point cert_file/key_file/ca_file at /tmp paths that
 * did not exist and dial random fixed ports in 5684..6000 where nothing
 * listened, then accept a handshake timeout or any coap_security_error as
 * the "expected" outcome. So no connection was ever established, and a
 * transport that could not establish one would have passed. They now dial a
 * live coap_server on an ephemeral port with material from the test PKI
 * (coap_dtls_test_pki.hpp) and assert the connection is made, or refused,
 * as the credentials say it must be.
 *
 * **Validates: Requirements 1.4, 6.1, 6.3**
 */
#define BOOST_TEST_MODULE coap_dtls_connection_establishment_property_test
#include <boost/test/unit_test.hpp>

#include "coap_dtls_test_pki.hpp"
#include "test_ports.hpp"
#include "test_timeout_scale.hpp"

#include <chrono>
#include <cstddef>
#include <format>
#include <random>
#include <string>
#include <vector>

using namespace kythira;
using namespace kythira::testing::coap_dtls;

namespace {

// Each iteration makes two real connections (one certificate, one PSK);
// each costs the handshake plus the one second establish_dtls_connection()
// gives its confirmation ping.
constexpr std::size_t property_test_iterations = 6;

// How long a refusal may take. A failed handshake ends with the peer's alert
// within milliseconds; establish_dtls_connection()'s own budget is 10 s, so
// anything near it means the failure went unnoticed until the deadline.
constexpr auto refusal_budget = std::chrono::milliseconds(5000);

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

auto psk_client_config(std::string identity, std::vector<std::byte> key) -> coap_client_config {
    coap_client_config config;
    config.enable_dtls = true;
    config.psk_identity = std::move(identity);
    config.psk_key = std::move(key);
    return config;
}

auto psk_server_config(std::string identity, std::vector<std::byte> key) -> coap_server_config {
    coap_server_config config;
    config.enable_dtls = true;
    config.psk_identity = std::move(identity);
    config.psk_key = std::move(key);
    return config;
}

// Whether establish_dtls_connection() with `endpoint` succeeds. It reports
// failure by throwing, never by returning false; a `false` fails the check
// that uses this, so a change to that contract is noticed.
auto establishes(const std::string& endpoint, coap_client_config config) -> bool {
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> client({{1, endpoint}}, std::move(config), metrics);
    BOOST_REQUIRE(client.is_dtls_enabled());
    try {
        const bool established = client.establish_dtls_connection(endpoint);
        BOOST_CHECK_MESSAGE(established,
                            "establish_dtls_connection returned false instead of throwing");
        return established;
    } catch (const coap_security_error& e) {
        BOOST_TEST_MESSAGE("refused: " << e.what());
    } catch (const coap_timeout_error& e) {
        BOOST_TEST_MESSAGE("timed out: " << e.what());
    }
    return false;
}

// Asserts that establish_dtls_connection() with `endpoint` is refused with
// coap_security_error: the peer turned the credentials down, so the client
// must say so as soon as the handshake fails, not wait out its budget and
// report a timeout.
auto check_refused(const std::string& endpoint, coap_client_config config) -> void {
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> client({{1, endpoint}}, std::move(config), metrics);
    const auto started = std::chrono::steady_clock::now();
    bool refused = false;
    try {
        client.establish_dtls_connection(endpoint);
    } catch (const coap_security_error& e) {
        refused = true;
        BOOST_TEST_MESSAGE("refused: " << e.what());
    } catch (const coap_timeout_error& e) {
        BOOST_TEST_MESSAGE("timed out instead of being refused: " << e.what());
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    BOOST_TEST(refused);
    BOOST_TEST(elapsed.count() < refusal_budget.count(),
               "refusal took " << elapsed.count() << " ms");
}

}  // namespace

BOOST_AUTO_TEST_SUITE(coap_dtls_connection_establishment_property_tests)

#ifdef LIBCOAP_AVAILABLE

/**
 * Property 9 (Requirements 1.4, 6.1, 6.3): a client with the test CA's
 * client certificate establishes a connection with a server holding the
 * CA's server certificate, for either key type and with the client's peer
 * verification on or off (the server always verifies the client); a client
 * and server sharing a random PSK identity and key (1..128 characters,
 * 16..64 bytes) establish one too. A client presenting a certificate from a
 * CA the server does not trust, or a PSK identity the server does not know,
 * is refused with coap_security_error as soon as the server turns it down.
 */
BOOST_AUTO_TEST_CASE(property_dtls_connection_establishment,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(120))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<int> coin(0, 1);
    std::uniform_int_distribution<std::size_t> key_length(coap_min_psk_key_length,
                                                          coap_max_psk_key_length);
    std::uniform_int_distribution<std::size_t> identity_length(1, 128);

    for (std::size_t iteration = 0; iteration < property_test_iterations; ++iteration) {
        const auto type = coin(gen) == 1 ? key_type::ec : key_type::rsa;
        const auto& pki = pki_for(type);
        const bool verify_server = coin(gen) == 1;

        BOOST_TEST_CONTEXT("iteration " << iteration << ", key " << to_string(type)
                                        << ", client verifies server " << verify_server) {
            running_server server(pki.server_config());
            auto client = pki.client_config();
            client.verify_peer_cert = verify_server;
            if (!verify_server) {
                client.ca_file.clear();
            }
            BOOST_TEST(establishes(server.endpoint(), client));
        }

        const auto identity = random_identity(gen, identity_length(gen));
        const auto key = random_key(gen, key_length(gen));
        BOOST_TEST_CONTEXT("iteration " << iteration << ", psk identity " << identity.size()
                                        << " characters, key " << key.size() << " bytes") {
            running_server server(psk_server_config(identity, key));
            BOOST_TEST(establishes(server.endpoint(), psk_client_config(identity, key)));
        }
    }

    // Refusals, each beside the control above that differs only in the
    // credential being checked.
    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        BOOST_TEST_CONTEXT("key " << to_string(type) << ", client certificate from another ca") {
            running_server server(pki.server_config());
            auto stranger = pki.client_config();
            stranger.cert_file = pki.stranger_cert_file;
            stranger.key_file = pki.stranger_key_file;
            check_refused(server.endpoint(), stranger);
        }
    }
    {
        const auto key = random_key(gen, key_length(gen));
        running_server server(psk_server_config("known-identity", key));
        BOOST_TEST_CONTEXT("psk identity the server does not know") {
            check_refused(server.endpoint(), psk_client_config("stranger", key));
        }
    }
}

/**
 * Property 9, an endpoint nobody answers (Requirement 1.4): dialling a
 * loopback port where no server listens throws coap_timeout_error or
 * coap_security_error rather than reporting a connection.
 */
BOOST_AUTO_TEST_CASE(test_unanswered_endpoint_is_not_established,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    const auto& pki = pki_for(key_type::ec);
    const auto endpoint = std::format("coaps://127.0.0.1:{}", kythira::testing::free_port());
    BOOST_TEST(!establishes(endpoint, pki.client_config()));
}

#endif  // LIBCOAP_AVAILABLE

/**
 * Property 9, malformed endpoints (Requirement 1.4): an empty endpoint, an
 * unknown scheme, a coap:// endpoint on a DTLS client, a coaps:// endpoint
 * with no host, and text that is not a URI are rejected with
 * coap_network_error or coap_security_error before any connection is
 * attempted. Holds without libcoap too.
 */
BOOST_AUTO_TEST_CASE(test_malformed_endpoints_are_rejected,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    const auto& pki = pki_for(key_type::ec);
    const auto port = kythira::testing::free_port();
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> client({{1, std::format("coaps://127.0.0.1:{}", port)}},
                                        pki.client_config(), metrics);

    const std::vector<std::string> malformed = {
        "",
        std::format("invalid://127.0.0.1:{}", port),
        std::format("coap://127.0.0.1:{}", port),
        "coaps://",
        "not_a_url",
    };
    for (const auto& endpoint : malformed) {
        BOOST_TEST_CONTEXT("endpoint '" << endpoint << "'") {
            bool rejected = false;
            try {
                client.establish_dtls_connection(endpoint);
            } catch (const coap_network_error& e) {
                rejected = true;
                BOOST_TEST_MESSAGE("rejected: " << e.what());
            } catch (const coap_security_error& e) {
                rejected = true;
                BOOST_TEST_MESSAGE("rejected: " << e.what());
            }
            BOOST_TEST(rejected);
        }
    }
    BOOST_CHECK_THROW(client.establish_dtls_connection(std::format("coap://127.0.0.1:{}", port)),
                      coap_security_error);
}

/**
 * Property 9, configuration (Requirements 6.1, 6.3): a DTLS client or server
 * built with complete certificate or PSK credentials reports DTLS enabled; a
 * PSK key outside 16..64 bytes, a PSK identity over 128 characters, or DTLS
 * with no credentials at all is refused with coap_security_error at
 * construction. Needs no network, so it also holds without libcoap.
 */
BOOST_AUTO_TEST_CASE(test_dtls_configuration_validation,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    const std::string endpoint = "coaps://127.0.0.1:5684";  // parsed, never dialled
    dtls_test_types::metrics_type metrics;

    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        BOOST_TEST_CONTEXT("key " << to_string(type)) {
            coap_client<dtls_test_types> client({{1, endpoint}}, pki.client_config(), metrics);
            BOOST_TEST(client.is_dtls_enabled());
            coap_server<dtls_test_types> server("127.0.0.1", 0, pki.server_config(), metrics);
            BOOST_TEST(server.is_dtls_enabled());
        }
    }
    {
        const std::vector<std::byte> key(16, std::byte{0x01});
        coap_client<dtls_test_types> client({{1, endpoint}}, psk_client_config("id", key), metrics);
        BOOST_TEST(client.is_dtls_enabled());
        coap_server<dtls_test_types> server("127.0.0.1", 0, psk_server_config("id", key), metrics);
        BOOST_TEST(server.is_dtls_enabled());
    }

    const auto refused = [&](coap_client_config client_config, coap_server_config server_config) {
        BOOST_CHECK_THROW(coap_client<dtls_test_types>({{1, endpoint}}, client_config, metrics),
                          coap_security_error);
        BOOST_CHECK_THROW(coap_server<dtls_test_types>("127.0.0.1", 0, server_config, metrics),
                          coap_security_error);
    };
    BOOST_TEST_CONTEXT("psk key too short") {
        const std::vector<std::byte> key(2, std::byte{0x01});
        refused(psk_client_config("test", key), psk_server_config("test", key));
    }
    BOOST_TEST_CONTEXT("psk key too long") {
        const std::vector<std::byte> key(100, std::byte{0xFF});
        refused(psk_client_config("test", key), psk_server_config("test", key));
    }
    BOOST_TEST_CONTEXT("psk identity too long") {
        const std::vector<std::byte> key(16, std::byte{0x01});
        refused(psk_client_config(std::string(200, 'x'), key),
                psk_server_config(std::string(200, 'x'), key));
    }
    BOOST_TEST_CONTEXT("no credentials") {
        coap_client_config client_config;
        client_config.enable_dtls = true;
        coap_server_config server_config;
        server_config.enable_dtls = true;
        refused(client_config, server_config);
    }
}

BOOST_AUTO_TEST_SUITE_END()
