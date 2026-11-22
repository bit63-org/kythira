// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/**
 * **Feature: coap-transport, Property 10: Certificate validation failure handling**
 *
 * For any invalid certificate a peer presents, the CoAP transport refuses
 * it: coap_client::validate_peer_certificate() and
 * coap_server::validate_client_certificate() (the checks the DTLS verify
 * callbacks run on every certificate in the peer's chain) throw
 * coap_security_error, and a handshake against a peer holding such a
 * certificate does not complete.
 *
 * These cases used to configure cert_file/key_file/ca_file as /tmp paths
 * that did not exist, so no trust anchor was ever loaded and the chain,
 * expiry and issuer checks never ran; and every case caught a
 * coap_security_error from construction as "acceptable" and moved on without
 * counting it. The only certificates they rejected were malformed text,
 * which the format check catches before any of that. They now use a real
 * test PKI (coap_dtls_test_pki.hpp): each refusal is paired with a control
 * that differs only in the certificate under test, so a refusal for some
 * unrelated reason cannot pass.
 *
 * **Validates: Requirements 6.2**
 */
#define BOOST_TEST_MODULE coap_certificate_validation_failure_property_test
#include <boost/test/unit_test.hpp>

#include "coap_dtls_test_pki.hpp"
#include "test_timeout_scale.hpp"

#include <cstddef>
#include <fstream>
#include <iterator>
#include <random>
#include <format>
#include <string>
#include <string_view>
#include <vector>

using namespace kythira;
using namespace kythira::testing::coap_dtls;

namespace {

constexpr std::size_t property_test_iterations = 100;
constexpr std::size_t handshake_iterations = 6;

// Both key types' material, generated once per process: RSA key generation
// is the slowest thing these cases do.
auto pki_for(key_type type) -> const test_pki& {
    static const test_pki ec(key_type::ec);
    static const test_pki rsa(key_type::rsa);
    return type == key_type::ec ? ec : rsa;
}

auto read_file(const std::string& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    BOOST_REQUIRE(in.good());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

auto write_file(const std::string& path, const std::string& content) -> void {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    BOOST_REQUIRE(out.good());
    out << content;
}

// Overwrites 1..10 positions of `pem`'s base64 body (never its BEGIN/END
// lines) with characters base64 does not use, so neither the PEM nor the DER
// parse can succeed and the format check, not chance, decides the outcome.
auto corrupt_pem_body(std::string pem, std::mt19937& gen) -> std::string {
    constexpr std::string_view begin_marker = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view end_marker = "-----END CERTIFICATE-----";
    const auto begin = pem.find(begin_marker);
    const auto end = pem.find(end_marker);
    BOOST_REQUIRE(begin != std::string::npos && end != std::string::npos);
    const auto body_start = begin + begin_marker.size() + 1;  // past the newline
    BOOST_REQUIRE(end > body_start);

    static constexpr std::string_view not_base64 = "@#$%^&*()!~";
    std::uniform_int_distribution<std::size_t> position(body_start, end - 2);
    std::uniform_int_distribution<std::size_t> character(0, not_base64.size() - 1);
    std::uniform_int_distribution<std::size_t> count(1, 10);
    for (std::size_t n = count(gen); n > 0; --n) {
        auto at = position(gen);
        while (pem[at] == '\n') {
            at = position(gen);
        }
        pem[at] = not_base64[character(gen)];
    }
    return pem;
}

// Text that is not a certificate at all. Every build refuses these, with or
// without libcoap/OpenSSL.
const std::vector<std::string> malformed_certificates = {
    "INVALID CERTIFICATE DATA",
    "-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/heBjcOu",
    "MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOu\n-----END CERTIFICATE-----",
    "-----BEGIN PRIVATE KEY-----\nMIIDXTCCAkWgAwIBAgIJAKoK/heBjcOu\n-----END PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----\n" + std::string(2000, 'A') + "\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n\n\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n@#$%^&*()\n-----END CERTIFICATE-----"};

/// What a peer may present, and whether a verifying transport must accept it.
struct candidate {
    std::string description;
    std::string pem;
    bool valid;
};

// The certificates a client checking a server (or, with `client_side`, a
// server checking a client) can be shown: the genuine leaf and the CA that
// signed it, which the verify callback also passes at depth 1; then an
// expired leaf from the same CA, a leaf from a CA the verifier does not
// trust, that CA itself, a corrupted copy of the genuine leaf, and
// malformed text.
auto candidates(const test_pki& pki, bool client_side, std::mt19937& gen)
    -> std::vector<candidate> {
    const auto leaf = read_file(client_side ? pki.client_cert_file : pki.server_cert_file);
    std::vector<candidate> all = {
        {"genuine leaf", leaf, true},
        {"trusted ca", read_file(pki.ca_file), true},
        {"expired leaf", read_file(pki.expired_cert_file), false},
        {"leaf from an untrusted ca", read_file(pki.stranger_cert_file), false},
        {"untrusted ca", read_file(pki.other_ca_file), false},
        {"corrupted leaf", corrupt_pem_body(leaf, gen), false},
    };
    std::uniform_int_distribution<std::size_t> pick(0, malformed_certificates.size() - 1);
    all.push_back({"malformed text", malformed_certificates[pick(gen)], false});
    return all;
}

// Whether a candidate is refused on a build without OpenSSL, whose stub
// validator checks only the PEM framing and base64 alphabet: expiry and
// issuer go unchecked there.
auto refused_without_openssl(const candidate& c) -> bool {
    return c.description == "corrupted leaf" || c.description == "malformed text";
}

// Whether `validate` accepts `pem`: true, or false for a coap_security_error.
// Any other exception, or a plain `false`, fails the check that uses it, so a
// validator that stops throwing and starts returning false is noticed.
template<typename Validate> auto accepts(Validate&& validate, const std::string& pem) -> bool {
    try {
        const bool accepted = validate(pem);
        BOOST_CHECK_MESSAGE(accepted, "validator returned false instead of throwing");
        return accepted;
    } catch (const coap_security_error& e) {
        BOOST_TEST_MESSAGE("refused: " << e.what());
        return false;
    }
}

auto expected_acceptance(const candidate& c) -> bool {
#ifdef LIBCOAP_AVAILABLE
    return c.valid;
#else
    return !refused_without_openssl(c);
#endif
}

}  // namespace

BOOST_AUTO_TEST_SUITE(coap_certificate_validation_failure_property_tests)

/**
 * Property 10 (Requirement 6.2): a client verifying its peer against the
 * test CA accepts the server's genuine certificate and the CA itself, and
 * refuses an expired certificate, one from another CA, that other CA, a
 * corrupted copy of the genuine certificate and malformed text; so does a
 * server verifying a client. Without libcoap only the format refusals apply,
 * and the case checks that the stub validator still makes those.
 */
BOOST_AUTO_TEST_CASE(property_certificate_validation_failure_handling,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(120))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<int> coin(0, 1);

    for (std::size_t iteration = 0; iteration < property_test_iterations; ++iteration) {
        const auto type = coin(gen) == 1 ? key_type::ec : key_type::rsa;
        const auto& pki = pki_for(type);
        dtls_test_types::metrics_type metrics;

        coap_client<dtls_test_types> client({{1, "coaps://127.0.0.1:5684"}}, pki.client_config(),
                                            metrics);
        coap_server<dtls_test_types> server("127.0.0.1", 0, pki.server_config(), metrics);
        BOOST_REQUIRE(client.is_dtls_enabled());
        BOOST_REQUIRE(server.is_dtls_enabled());

        for (const auto& c : candidates(pki, false, gen)) {
            BOOST_TEST_CONTEXT("iteration " << iteration << ", key " << to_string(type)
                                            << ", client shown " << c.description) {
                BOOST_TEST(accepts(
                               [&](const std::string& pem) {
                                   return client.validate_peer_certificate(pem);
                               },
                               c.pem) == expected_acceptance(c));
            }
        }
        for (const auto& c : candidates(pki, true, gen)) {
            BOOST_TEST_CONTEXT("iteration " << iteration << ", key " << to_string(type)
                                            << ", server shown " << c.description) {
                BOOST_TEST(accepts(
                               [&](const std::string& pem) {
                                   return server.validate_client_certificate(pem);
                               },
                               c.pem) == expected_acceptance(c));
            }
        }
    }
}

/**
 * Property 10, the switches (Requirement 6.2): with verify_peer_cert off,
 * certificates that fail verification (expired, from an untrusted CA) are
 * accepted, while the same transport with it on refuses them; with DTLS off
 * there is nothing to verify and any certificate text is accepted. An empty
 * certificate is refused whenever verification is on.
 */
BOOST_AUTO_TEST_CASE(test_verification_switches,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(60))) {
    for (const auto type : {key_type::ec, key_type::rsa}) {
        const auto& pki = pki_for(type);
        dtls_test_types::metrics_type metrics;
        const auto expired = read_file(pki.expired_cert_file);
        const auto stranger = read_file(pki.stranger_cert_file);

        BOOST_TEST_CONTEXT("key " << to_string(type)) {
            auto unverifying_client_config = pki.client_config();
            unverifying_client_config.verify_peer_cert = false;
            coap_client<dtls_test_types> unverifying_client({{1, "coaps://127.0.0.1:5684"}},
                                                            unverifying_client_config, metrics);
            BOOST_TEST(unverifying_client.validate_peer_certificate(expired));
            BOOST_TEST(unverifying_client.validate_peer_certificate(stranger));

            auto unverifying_server_config = pki.server_config();
            unverifying_server_config.verify_peer_cert = false;
            coap_server<dtls_test_types> unverifying_server("127.0.0.1", 0,
                                                            unverifying_server_config, metrics);
            BOOST_TEST(unverifying_server.validate_client_certificate(expired));
            BOOST_TEST(unverifying_server.validate_client_certificate(stranger));

            coap_client<dtls_test_types> client({{1, "coaps://127.0.0.1:5684"}},
                                                pki.client_config(), metrics);
            coap_server<dtls_test_types> server("127.0.0.1", 0, pki.server_config(), metrics);
            BOOST_CHECK_THROW(client.validate_peer_certificate(""), coap_security_error);
            BOOST_CHECK_THROW(server.validate_client_certificate(""), coap_security_error);
#ifdef LIBCOAP_AVAILABLE
            BOOST_CHECK_THROW(client.validate_peer_certificate(expired), coap_security_error);
            BOOST_CHECK_THROW(client.validate_peer_certificate(stranger), coap_security_error);
            BOOST_CHECK_THROW(server.validate_client_certificate(expired), coap_security_error);
            BOOST_CHECK_THROW(server.validate_client_certificate(stranger), coap_security_error);
#endif
        }
    }

    coap_client_config plain_client_config;
    plain_client_config.enable_dtls = false;
    dtls_test_types::metrics_type metrics;
    coap_client<dtls_test_types> plain_client({{1, "coap://127.0.0.1:5683"}}, plain_client_config,
                                              metrics);
    coap_server_config plain_server_config;
    plain_server_config.enable_dtls = false;
    coap_server<dtls_test_types> plain_server("127.0.0.1", 0, plain_server_config, metrics);
    for (const auto& text : malformed_certificates) {
        BOOST_TEST_CONTEXT("dtls off, shown " << text.substr(0, 40)) {
            BOOST_TEST(plain_client.validate_peer_certificate(text));
            BOOST_TEST(plain_server.validate_client_certificate(text));
        }
    }
    BOOST_TEST(plain_client.validate_peer_certificate(""));
    BOOST_TEST(plain_server.validate_client_certificate(""));
}

#ifdef LIBCOAP_AVAILABLE

/**
 * Property 10 over the wire (Requirement 6.2): a server whose certificate
 * file was corrupted on disk, or a client whose file was, never completes a
 * handshake with a verifying peer, whichever key type; the same pair with the
 * intact file connects. Construction accepts PKI files it cannot use (see
 * detail::set_coap_pki_key()), so it is the handshake that has to refuse.
 * The other refusals (expired, untrusted CA, mismatched key, missing file)
 * are covered handshake by handshake in coap_dtls_handshake_property_test.
 */
BOOST_AUTO_TEST_CASE(test_corrupted_certificate_files_refuse_the_handshake,
                     *boost::unit_test::timeout(kythira::testing::scaled_timeout(120))) {
    std::mt19937 gen(property_seed());
    std::uniform_int_distribution<int> coin(0, 1);

    for (std::size_t iteration = 0; iteration < handshake_iterations; ++iteration) {
        const auto type = coin(gen) == 1 ? key_type::ec : key_type::rsa;
        const bool corrupt_server = coin(gen) == 1;
        const auto& pki = pki_for(type);

        const auto corrupted = (pki.dir() / std::format("corrupted-{}.pem", iteration)).string();
        write_file(corrupted, corrupt_pem_body(read_file(corrupt_server ? pki.server_cert_file
                                                                        : pki.client_cert_file),
                                               gen));
        auto server = pki.server_config();
        auto client = pki.client_config();
        (corrupt_server ? server.cert_file : client.cert_file) = corrupted;

        BOOST_TEST_CONTEXT("iteration " << iteration << ", key " << to_string(type) << ", "
                                        << (corrupt_server ? "server" : "client")
                                        << " certificate corrupted") {
            BOOST_TEST(handshake(pki.server_config(), pki.client_config()));
            bool connected = false;
            try {
                connected = handshake(server, client);
            } catch (const coap_transport_error& e) {
                BOOST_TEST_MESSAGE("refused: " << e.what());
            }
            BOOST_TEST(!connected);
        }
    }
}

#endif  // LIBCOAP_AVAILABLE

BOOST_AUTO_TEST_SUITE_END()
