// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// libkythira_pkcs11.so under the consumers requirement 5.6 names
// (.kiro/specs/virtual-hsm/ task 10b): pkcs11-tool, OpenSSL's
// pkcs11-provider (including a TLS handshake with a token key), p11-kit
// and GnuTLS, Go's crypto11, Java's SunPKCS11 and Google's pkcs11test.
// This binary is the node: one node fixture behind a wire server with
// mutual TLS and a Unix socket. Each case runs one consumer through
// services/hsm/pkcs11/tests/consumers.sh against it.
//
// The tools are not on every CI runner, so the test is registered only
// with KYTHIRA_HSM_CONSUMER_TESTS (hsm-module.yml's consumers job, which
// installs them).

#define BOOST_TEST_MODULE hsm_pkcs11_consumers_test
#include "hsm_test_node.hpp"
#include "hsm_test_pki.hpp"

#include <kythira/hsm/wire_server.hpp>

#include <boost/test/unit_test.hpp>

#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>

#ifndef KYTHIRA_PKCS11_LIBRARY
#define KYTHIRA_PKCS11_LIBRARY "libkythira_pkcs11.so"
#endif
#ifndef KYTHIRA_HSM_CONSUMERS_SCRIPT
#define KYTHIRA_HSM_CONSUMERS_SCRIPT "consumers.sh"
#endif

namespace hsm = kythira::hsm;
using namespace kythira::hsm::test;  // NOLINT(google-build-using-namespace)

namespace {

constexpr const char* k_app = "spiffe://test/app";

/// The node, its listeners, and the two configuration files: one for
/// mutual TLS, one for the socket.
struct served_node {
    node n;
    test_pki pki;
    std::filesystem::path work;
    std::unique_ptr<hsm::wire_server> server;
    std::string tls_conf;
    std::string socket_conf;

    served_node() {
        std::random_device rd;
        work = std::filesystem::temp_directory_path() / ("kythira-p11c-" + std::to_string(rd()));
        std::filesystem::create_directories(work);
        BOOST_REQUIRE(n.propose_catalog(hsm::make_bind_command(k_app, k_token)) == CKR_OK);
        const auto node_files = pki.issue("node", "DNS:localhost,IP:127.0.0.1");
        const auto app_files = pki.issue("app", std::string("URI:") + k_app);

        hsm::wire_server_config cfg;
        cfg.tls_port = 0;
        cfg.bind_address = "127.0.0.1";
        cfg.cert_path = node_files.cert;
        cfg.key_path = node_files.key;
        cfg.ca_path = pki.ca_path();
        cfg.socket_path = (work / "hsm.sock").string();
        cfg.socket_allow = {{static_cast<std::uint32_t>(::getuid()), k_app}};
        server = std::make_unique<hsm::wire_server>(
            std::shared_ptr<hsm::session_layer>(&n.layer, [](hsm::session_layer*) {}), cfg);
        server->start();

        tls_conf = (work / "tls.conf").string();
        std::ofstream(tls_conf) << "endpoint = 127.0.0.1:" << server->tls_port() << "\n"
                                << "cert = " << app_files.cert << "\n"
                                << "key = " << app_files.key << "\n"
                                << "ca = " << pki.ca_path() << "\n";
        socket_conf = (work / "socket.conf").string();
        std::ofstream(socket_conf) << "socket = " << cfg.socket_path << "\n";
    }
    served_node(const served_node&) = delete;
    auto operator=(const served_node&) -> served_node& = delete;
    served_node(served_node&&) = delete;
    auto operator=(served_node&&) -> served_node& = delete;
    ~served_node() {
        server.reset();
        std::error_code ec;
        std::filesystem::remove_all(work, ec);
    }

    /// Runs `consumer` from consumers.sh with `conf`; its exit status.
    auto run(const std::string& consumer, const std::string& conf) -> int {
        const auto dir = work / consumer;
        std::filesystem::create_directories(dir);
        const std::string cmd =
            std::string("env KYTHIRA_PKCS11_CONF='") + conf + "' KYTHIRA_PKCS11_MODULE='" +
            KYTHIRA_PKCS11_LIBRARY + "' P11_TOKEN_LABEL=alpha P11_SLOT=" + std::to_string(k_token) +
            " P11_USER_PIN='" + k_user_pin + "' P11_SO_PIN='" + k_so_pin + "' P11_WORK='" +
            dir.string() + "' bash '" + KYTHIRA_HSM_CONSUMERS_SCRIPT + "' " + consumer;
        const int status = std::system(cmd.c_str());  // NOLINT(cert-env33-c,concurrency-mt-unsafe)
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    }
};

}  // namespace

// A fresh node for each consumer.
BOOST_FIXTURE_TEST_SUITE(consumers, served_node)

BOOST_AUTO_TEST_CASE(pkcs11_tool) {
    BOOST_TEST(run("pkcs11_tool", tls_conf) == 0);
}

BOOST_AUTO_TEST_CASE(openssl_pkcs11_provider_and_a_tls_handshake) {
    BOOST_TEST(run("openssl_provider", tls_conf) == 0);
}

BOOST_AUTO_TEST_CASE(p11_kit_and_gnutls) {
    BOOST_TEST(run("p11_kit", socket_conf) == 0);
}

BOOST_AUTO_TEST_CASE(go_crypto11) {
    BOOST_TEST(run("go_crypto11", tls_conf) == 0);
}

BOOST_AUTO_TEST_CASE(java_sunpkcs11) {
    BOOST_TEST(run("java_sunpkcs11", socket_conf) == 0);
}

BOOST_AUTO_TEST_CASE(google_pkcs11test) {
    BOOST_TEST(run("pkcs11test", tls_conf) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
