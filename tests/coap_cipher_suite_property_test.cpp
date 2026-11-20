// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/**
 * **Feature: coap-transport, Property 36: Proper cipher suite configuration**
 *
 * The certificate cases here used to point at nonexistent /tmp/test_*.pem
 * files, accept any coap_security_error as "expected if certificate files
 * don't exist (stub implementation)", and pass with BOOST_CHECK(true); none
 * of them ever ran a handshake. They now run real handshakes against a live
 * coap_server with generated certificates and check that the configured
 * lists decide what can be negotiated. The DTLS-PSK cases, which already
 * asserted that a PSK configuration with cipher_suites is refused, are kept.
 *
 * **Validates: Requirements 6.4**
 */
#define BOOST_TEST_MODULE coap_cipher_suite_property_test
#include <boost/test/unit_test.hpp>

#include "coap_dtls_test_pki.hpp"
#include "test_timeout_scale.hpp"

#include <algorithm>
#include <chrono>
#include <random>
#include <string>
#include <vector>

using namespace kythira;
using namespace kythira::testing::coap_dtls;

namespace {
constexpr std::size_t test_iterations = 100;
// Iterations that each run a real handshake.
constexpr std::size_t handshake_iterations = 40;
constexpr const char* test_bind_address = "127.0.0.1";
using test_types = dtls_test_types;

// Standard secure cipher suites for testing
const std::vector<std::string> secure_cipher_suites = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",           "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"};

// Legacy/insecure cipher suites that should be avoided
const std::vector<std::string> legacy_cipher_suites = {
    "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"};

// cipher_suites restricts certificate-based DTLS only. The cases below that
// configure DTLS-PSK expect a non-empty list to be refused at construction
// (it could not be honoured on every backend, and used to be silently
// ignored), and an empty one to keep the defaults and construct normally.
template<typename Make>
auto check_psk_cipher_config(bool has_cipher_suites, Make&& make, const std::string& what) -> void {
    if (has_cipher_suites) {
        BOOST_CHECK_THROW(make(), coap_security_config_error);
        return;
    }
    try {
        make();
    } catch (const std::exception& e) {
        BOOST_FAIL(what + " should not throw: " + std::string(e.what()));
    }
}

// Both key types' material, generated once per process.
auto pki_for(key_type type) -> const test_pki& {
    static const test_pki ec(key_type::ec);
    static const test_pki rsa(key_type::rsa);
    return type == key_type::ec ? ec : rsa;
}

auto random_subset(const std::vector<std::string>& from, std::size_t count, std::mt19937& gen)
    -> std::vector<std::string> {
    auto pool = from;
    std::shuffle(pool.begin(), pool.end(), gen);
    pool.resize(std::min(count, pool.size()));
    return pool;
}

auto any_fits(const std::vector<std::string>& suites, key_type type) -> bool {
    return std::ranges::any_of(
        suites, [type](const std::string& suite) { return suite_fits_key(suite, type); });
}

auto describe(const std::vector<std::string>& suites) -> std::string {
    if (suites.empty()) {
        return "(defaults)";
    }
    std::string text;
    for (const auto& suite : suites) {
        text += suite + " ";
    }
    return text;
}
}  // namespace

/**
 * **Feature: coap-transport, Property 36: Proper cipher suite configuration**
 *
 * With certificates, a client and server restricted to the same random
 * subset of the secure suites complete a handshake exactly when the subset
 * holds a suite the certificate's key can authenticate; with no list both
 * keep their defaults and connect. DHE_RSA suites count: with an RSA
 * certificate a DHE-only list must connect too (it never did before the
 * servers were given DH parameters). With DTLS-PSK a non-empty list is
 * refused at construction on both sides and an empty one constructs.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_secure_cipher_suite_configuration,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> cipher_count_dist(0, 4);
    std::uniform_int_distribution<int> key_dist(0, 1);
    std::uniform_int_distribution<int> psk_dist(0, 3);

    for (std::size_t iteration = 0; iteration < handshake_iterations; ++iteration) {
        const auto selected = random_subset(secure_cipher_suites, cipher_count_dist(gen), gen);

        if (psk_dist(gen) == 0) {
            coap_client_config client_config;
            client_config.enable_dtls = true;
            client_config.psk_identity = "test_cipher_suite";
            client_config.psk_key = std::vector<std::byte>(16, std::byte{0x01});
            client_config.cipher_suites = selected;
            coap_server_config server_config;
            server_config.enable_dtls = true;
            server_config.psk_identity = client_config.psk_identity;
            server_config.psk_key = client_config.psk_key;
            server_config.cipher_suites = selected;
            test_types::metrics_type metrics;
            check_psk_cipher_config(
                !selected.empty(),
                [&] {
                    coap_client<test_types> client({{1, "coaps://127.0.0.1:5684"}}, client_config,
                                                   metrics);
                },
                "PSK client with " + describe(selected));
            check_psk_cipher_config(
                !selected.empty(),
                [&] {
                    coap_server<test_types> server(test_bind_address, 0, server_config, metrics);
                },
                "PSK server with " + describe(selected));
            continue;
        }

#ifdef LIBCOAP_AVAILABLE
        const auto type = key_dist(gen) == 0 ? key_type::ec : key_type::rsa;
        const auto& pki = pki_for(type);
        const bool expect = selected.empty() || any_fits(selected, type);
        BOOST_TEST_CONTEXT("key " << to_string(type) << ", suites " << describe(selected)) {
            BOOST_TEST(handshake(pki.server_config(selected), pki.client_config(selected)) ==
                       expect);
        }
#endif
    }

#ifdef LIBCOAP_AVAILABLE
    // Each DHE_RSA suite on its own, which an RSA server can only choose with
    // DH parameters.
    for (const auto* suite :
         {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"}) {
        const auto& pki = pki_for(key_type::rsa);
        BOOST_TEST_CONTEXT(suite) {
            BOOST_TEST(handshake(pki.server_config({suite}), pki.client_config({suite})));
        }
    }
#endif
}

/**
 * **Feature: coap-transport, Property 36: Cipher suite compatibility with certificates**
 *
 * A client and a server restricted to independent random subsets (either may
 * be empty, meaning the defaults) complete a handshake exactly when the two
 * restrictions share a suite the certificate's key can authenticate. This is
 * what shows each side enforces its own list: were either list ignored, a
 * disjoint pair would still connect over the other side's choice.
 *
 * **Validates: Requirements 6.4**
 */
#ifdef LIBCOAP_AVAILABLE
BOOST_AUTO_TEST_CASE(test_certificate_cipher_suite_compatibility,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(90))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<std::size_t> cipher_count_dist(0, 3);
    // The ECDHE suites. DHE is left to test_secure_cipher_suite_configuration,
    // where both sides name it: whether a side's defaults offer it is up to
    // the backend's built-in list.
    const std::vector<std::string> ecdhe_suites(secure_cipher_suites.begin(),
                                                secure_cipher_suites.begin() + 6);

    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        for (std::size_t iteration = 0; iteration < handshake_iterations / 2; ++iteration) {
            const auto client_suites = random_subset(ecdhe_suites, cipher_count_dist(gen), gen);
            const auto server_suites = random_subset(ecdhe_suites, cipher_count_dist(gen), gen);

            std::vector<std::string> shared;
            if (client_suites.empty()) {
                shared = server_suites;
            } else if (server_suites.empty()) {
                shared = client_suites;
            } else {
                std::ranges::copy_if(
                    client_suites, std::back_inserter(shared), [&](const std::string& suite) {
                        return std::ranges::find(server_suites, suite) != server_suites.end();
                    });
            }
            const bool expect =
                (client_suites.empty() && server_suites.empty()) || any_fits(shared, type);

            BOOST_TEST_CONTEXT("key " << to_string(type) << ", client " << describe(client_suites)
                                      << ", server " << describe(server_suites)) {
                BOOST_TEST(handshake(pki.server_config(server_suites),
                                     pki.client_config(client_suites)) == expect);
            }
        }
    }
}
#endif  // LIBCOAP_AVAILABLE

/**
 * **Feature: coap-transport, Property 36: Cipher suite validation and filtering**
 *
 * This property validates that the CoAP transport properly validates
 * cipher suite configurations and filters out insecure options.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_cipher_suite_validation_and_filtering,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(30))) {
    // Test data generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> mix_ratio_dist(1, 3);

    for (std::size_t iteration = 0; iteration < test_iterations; ++iteration) {
        std::size_t mix_ratio = mix_ratio_dist(gen);

        // Create mixed cipher suite list (secure + legacy)
        std::vector<std::string> mixed_ciphers;

        // Add some secure cipher suites
        for (std::size_t i = 0; i < mix_ratio && i < secure_cipher_suites.size(); ++i) {
            mixed_ciphers.push_back(secure_cipher_suites[i]);
        }

        // Add some legacy cipher suites
        for (std::size_t i = 0; i < mix_ratio && i < legacy_cipher_suites.size(); ++i) {
            mixed_ciphers.push_back(legacy_cipher_suites[i]);
        }

        // Shuffle the mixed list
        std::shuffle(mixed_ciphers.begin(), mixed_ciphers.end(), gen);

        // Create client configuration with mixed cipher suites
        coap_client_config client_config;
        client_config.enable_dtls = true;
        client_config.psk_identity = "test_validation";
        client_config.psk_key = std::vector<std::byte>(16, std::byte{0x01});
        client_config.cipher_suites = mixed_ciphers;

        // Create test types and client
        test_types::metrics_type metrics;

        std::unordered_map<std::uint64_t, std::string> node_endpoints = {
            {1, "coaps://127.0.0.1:5684"}};

        // Test 1: a mixed list with PSK is refused, not silently ignored
        check_psk_cipher_config(
            true, [&] { coap_client<test_types> client(node_endpoints, client_config, metrics); },
            "Mixed cipher suite configuration");

        // Test 2: Test with only secure cipher suites
        client_config.cipher_suites.clear();
        for (std::size_t i = 0; i < mix_ratio && i < secure_cipher_suites.size(); ++i) {
            client_config.cipher_suites.push_back(secure_cipher_suites[i]);
        }

        check_psk_cipher_config(
            true,
            [&] { coap_client<test_types> secure_client(node_endpoints, client_config, metrics); },
            "Secure-only cipher suite configuration");

        // Test 3: Test with empty cipher suite list (should use defaults)
        client_config.cipher_suites.clear();

        BOOST_CHECK_NO_THROW(coap_client<test_types>(node_endpoints, client_config, metrics));
    }
}

/**
 * **Feature: coap-transport, Property 36: Legacy cipher suites with certificates**
 *
 * With certificates, a list that names a suite this OpenSSL cannot negotiate
 * over DTLS 1.2 is refused at construction, naming that suite, on both
 * sides, rather than the suite being dropped silently. A legacy suite that
 * is available is honoured as configured: a server restricted to legacy
 * suites serves a client restricted to the same ones, and refuses a client
 * restricted to the secure suites, which never falls back to a legacy one.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_certificate_cipher_suite_filtering,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    const auto& pki = pki_for(key_type::rsa);
    test_types::metrics_type metrics;
    std::vector<std::string> available_legacy;

    for (const auto& suite : legacy_cipher_suites) {
        bool available = true;
        try {
            static_cast<void>(kythira::detail::dtls_cipher_list({suite}));
        } catch (const coap_security_config_error&) {
            available = false;
        }
        BOOST_TEST_MESSAGE(suite << (available ? " is" : " is not") << " available");
        const std::vector<std::string> list = {secure_cipher_suites[1], suite};
        BOOST_TEST_CONTEXT(suite) {
            if (available) {
                available_legacy.push_back(suite);
                BOOST_CHECK_NO_THROW(coap_client<test_types>({{1, "coaps://127.0.0.1:5684"}},
                                                             pki.client_config(list), metrics));
                BOOST_CHECK_NO_THROW(coap_server<test_types>(test_bind_address, 0,
                                                             pki.server_config(list), metrics));
                continue;
            }
            for (const bool client_side : {true, false}) {
                try {
                    if (client_side) {
                        coap_client<test_types> client({{1, "coaps://127.0.0.1:5684"}},
                                                       pki.client_config(list), metrics);
                    } else {
                        coap_server<test_types> server(test_bind_address, 0,
                                                       pki.server_config(list), metrics);
                    }
                    BOOST_ERROR((client_side ? "client" : "server")
                                << " accepted a list naming an unavailable suite");
                } catch (const coap_security_config_error& e) {
                    BOOST_TEST(std::string(e.what()).find(suite) != std::string::npos,
                               "error names the suite: " << e.what());
                }
            }
        }
    }

#ifdef LIBCOAP_AVAILABLE
    BOOST_REQUIRE_MESSAGE(!available_legacy.empty(),
                          "no legacy suite is available in this OpenSSL to run the handshakes");
    const std::vector<std::string> secure_rsa = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                 "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                 "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"};
    BOOST_TEST(handshake(pki.server_config(available_legacy), pki.client_config(available_legacy)));
    BOOST_TEST(!handshake(pki.server_config(available_legacy), pki.client_config(secure_rsa)));
#endif
}

/**
 * **Feature: coap-transport, Property 36: Cipher suite compatibility testing**
 *
 * This property validates that the CoAP transport properly handles
 * cipher suite compatibility between client and server configurations.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_cipher_suite_compatibility,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(30))) {
    // Test data generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> compatibility_scenario_dist(0, 4);

    for (std::size_t iteration = 0; iteration < test_iterations; ++iteration) {
        std::size_t compatibility_scenario = compatibility_scenario_dist(gen);

        // Create test types
        test_types::metrics_type client_metrics, server_metrics;

        std::unordered_map<std::uint64_t, std::string> node_endpoints = {
            {1, "coaps://127.0.0.1:5684"}};

        coap_client_config client_config;
        coap_server_config server_config;

        // Configure both for DTLS with PSK
        client_config.enable_dtls = true;
        client_config.psk_identity = "compatibility_test";
        client_config.psk_key = std::vector<std::byte>(16, std::byte{0x01});

        server_config.enable_dtls = true;
        server_config.psk_identity = client_config.psk_identity;
        server_config.psk_key = client_config.psk_key;

        // Set up different compatibility scenarios
        switch (compatibility_scenario) {
            case 0:  // Identical cipher suites
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};
                server_config.cipher_suites = client_config.cipher_suites;
                break;

            case 1:  // Overlapping cipher suites
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};
                server_config.cipher_suites = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                               "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"};
                break;

            case 2:  // Client subset of server
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"};
                server_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};
                break;

            case 3:  // Server subset of client
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};
                server_config.cipher_suites = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};
                break;

            case 4:  // NOLINT(bugprone-branch-clone) - default case is identical by design
                // Leave both cipher_suites empty for default behavior
                break;

            default:
                break;
        }

        const auto scenario = std::to_string(compatibility_scenario);

        // Test 1: Client creation with compatibility scenario
        check_psk_cipher_config(
            !client_config.cipher_suites.empty(),
            [&] { coap_client<test_types> client(node_endpoints, client_config, client_metrics); },
            "Client creation in compatibility scenario " + scenario);

        // Test 2: Server creation with compatibility scenario
        check_psk_cipher_config(
            !server_config.cipher_suites.empty(),
            [&] {
                coap_server<test_types> server(test_bind_address, 0, server_config, server_metrics);
            },
            "Server creation in compatibility scenario " + scenario);

        // Test 3: in the default scenario, the only one that constructs under
        // PSK, the pair completes a real handshake on the defaults.
        if (!client_config.cipher_suites.empty() || !server_config.cipher_suites.empty()) {
            continue;
        }
#ifdef LIBCOAP_AVAILABLE
        BOOST_TEST(handshake(server_config, client_config),
                   "PSK handshake in compatibility scenario " << scenario);
#endif
    }
}

/**
 * **Feature: coap-transport, Property 36: Cipher suite security enforcement**
 *
 * This property validates that the CoAP transport enforces security
 * requirements for cipher suite selection and configuration.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_cipher_suite_security_enforcement,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(30))) {
    // Test data generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> security_level_dist(0, 3);

    for (std::size_t iteration = 0; iteration < test_iterations; ++iteration) {
        std::size_t security_level = security_level_dist(gen);

        // Create test types
        test_types::metrics_type metrics;

        std::unordered_map<std::uint64_t, std::string> node_endpoints = {
            {1, "coaps://127.0.0.1:5684"}};

        coap_client_config client_config;
        client_config.enable_dtls = true;
        client_config.psk_identity = "security_test";
        client_config.psk_key = std::vector<std::byte>(16, std::byte{0x01});

        // Configure different security levels
        switch (security_level) {
            case 0:  // High security - only AEAD cipher suites
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                               "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                               "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"};
                break;

            case 1:  // Medium security - modern cipher suites
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"};
                break;

            case 2:  // Mixed security - some legacy allowed
                client_config.cipher_suites = {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                               "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"};
                break;

            case 3:  // NOLINT(bugprone-branch-clone) - default case is identical by design
                // Leave cipher_suites empty
                break;

            default:
                break;
        }

        const bool has_cipher_suites = !client_config.cipher_suites.empty();
        const auto level = std::to_string(security_level);

        // Test 1: Client creation with security level
        check_psk_cipher_config(
            has_cipher_suites,
            [&] { coap_client<test_types> client(node_endpoints, client_config, metrics); },
            "Client at security level " + level);

        // Test 2: the server side reaches the same verdict. That the list is
        // actually enforced in a handshake is covered over certificate-based
        // DTLS by coap_dtls_cipher_suites_test.

        coap_server_config server_config;
        server_config.enable_dtls = true;
        server_config.psk_identity = client_config.psk_identity;
        server_config.psk_key = client_config.psk_key;
        server_config.cipher_suites = client_config.cipher_suites;

        check_psk_cipher_config(
            has_cipher_suites,
            [&] { coap_server<test_types> server(test_bind_address, 0, server_config, metrics); },
            "Server at security level " + level);
    }
}

/**
 * **Feature: coap-transport, Property 36: Cipher suite performance impact**
 *
 * This property validates that cipher suite configuration does not
 * significantly impact the performance of DTLS setup operations.
 *
 * **Validates: Requirements 6.4**
 */
BOOST_AUTO_TEST_CASE(test_cipher_suite_performance_impact,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(30))) {
    // Test data generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> cipher_count_dist(1, 8);

    for (std::size_t iteration = 0; iteration < test_iterations; ++iteration) {
        std::size_t cipher_count = cipher_count_dist(gen);

        // Create large cipher suite list
        std::vector<std::string> large_cipher_list;
        for (std::size_t i = 0; i < cipher_count && i < secure_cipher_suites.size(); ++i) {
            large_cipher_list.push_back(secure_cipher_suites[i]);
        }

        // Create test types
        test_types::metrics_type metrics;

        std::unordered_map<std::uint64_t, std::string> node_endpoints = {
            {1, "coaps://127.0.0.1:5684"}};

        // Test 1: Measure client creation time with large cipher suite list
        coap_client_config client_config;
        client_config.enable_dtls = true;
        client_config.psk_identity = "performance_test";
        client_config.psk_key = std::vector<std::byte>(16, std::byte{0x01});
        client_config.cipher_suites = large_cipher_list;

        auto start_time = std::chrono::steady_clock::now();

        // Under PSK the list is refused; checking it must still be quick.
        check_psk_cipher_config(
            true, [&] { coap_client<test_types> client(node_endpoints, client_config, metrics); },
            "Client creation with large cipher suite list");
        BOOST_CHECK_LT(std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start_time)
                           .count(),
                       1000);

        // Test 2: Compare with default cipher suite configuration
        client_config.cipher_suites.clear();  // Use defaults

        start_time = std::chrono::steady_clock::now();

        try {
            coap_client<test_types> default_client(node_endpoints, client_config, metrics);

            auto end_time = std::chrono::steady_clock::now();
            auto duration =
                std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

            // Default configuration should also complete quickly
            BOOST_CHECK_LT(duration.count(), 1000);

        } catch (const std::exception& e) {
            BOOST_FAIL("Client creation with default cipher suites should not throw: " +
                       std::string(e.what()));
        }

        // Test 3: Server performance with large cipher suite list
        coap_server_config server_config;
        server_config.enable_dtls = true;
        server_config.psk_identity = client_config.psk_identity;
        server_config.psk_key = client_config.psk_key;
        server_config.cipher_suites = large_cipher_list;

        start_time = std::chrono::steady_clock::now();

        check_psk_cipher_config(
            true,
            [&] { coap_server<test_types> server(test_bind_address, 0, server_config, metrics); },
            "Server creation with large cipher suite list");
        BOOST_CHECK_LT(std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start_time)
                           .count(),
                       1000);
    }
}