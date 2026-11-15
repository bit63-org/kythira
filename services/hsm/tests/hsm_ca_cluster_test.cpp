// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The cluster CA with its root key on a PKCS#11 token
// (`.kiro/specs/virtual-hsm/` task 13b, Requirement 10.1): three
// ca_cluster_node processes started with --ca-key-uri naming one SoftHSM2
// token, as an external HSM would be shared. The bootstrapping node makes
// the root by signing it on the token, the replicated state records only
// the key's URI, certificates issued before and after a leader is killed
// verify against that root, and no node's data directory holds a private
// key.

#define BOOST_TEST_MODULE hsm_ca_cluster_test

#include "ca_cluster_node_harness.hpp"
#include "test_ports.hpp"

#include <raft/certificate_authority.hpp>
#include <raft/certificate_provider.hpp>
#include <raft/pkcs11_module.hpp>
#include <raft/pkcs11_signing_key.hpp>
#include <raft/pkcs11_uri.hpp>

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace p11 = kythira::pkcs11;
namespace rt = raft::testing;
using namespace ca_cluster_harness;  // NOLINT(google-build-using-namespace)

namespace {

constexpr const char* k_auth_token = "hsm-ca-cluster-token";
constexpr const char* k_pin = "246810";
constexpr const char* k_so_pin = "13579135";

auto x509_of(const std::string& pem) -> std::unique_ptr<X509, decltype(&X509_free)> {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    return {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free};
}

auto pubkey_pem_of(X509* cert) -> std::string {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    BOOST_REQUIRE(PEM_write_bio_PUBKEY(bio.get(), X509_get0_pubkey(cert)) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {data, static_cast<std::size_t>(len)};
}

/// A SoftHSM2 store with one token holding an EC P-256 CA key.
struct softhsm_ca_token {
    std::filesystem::path dir;
    std::string key_uri;
    std::string public_pem;

    explicit softhsm_ca_token(const std::filesystem::path& root) : dir(root / "softhsm") {
        std::filesystem::create_directories(dir / "tokens");
        const auto conf = dir / "softhsm2.conf";
        std::ofstream(conf) << "directories.tokendir = " << (dir / "tokens").string() << "\n"
                            << "objectstore.backend = file\nlog.level = ERROR\n";
        // The nodes inherit it.
        ::setenv("SOFTHSM2_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
        const std::string init = std::string(KYTHIRA_SOFTHSM2_UTIL) +
                                 " --init-token --free --label ca --so-pin " + k_so_pin +
                                 " --pin " + k_pin + " > /dev/null";
        BOOST_REQUIRE(std::system(init.c_str()) ==
                      0);  // NOLINT(cert-env33-c,concurrency-mt-unsafe)

        const auto m = p11::module::load(KYTHIRA_SOFTHSM2_LIBRARY);
        auto s = m.open(p11::uri::parse("pkcs11:token=ca"), k_pin);
        const std::array<std::uint8_t, 2> id{0xca, 0x01};
        (void)s.generate_key_pair(p11::key_spec::ec_p256, p11::key_usage::sign, "ca-root", id);
        auto u = p11::uri::parse("pkcs11:token=ca;object=ca-root");
        u.module_path = KYTHIRA_SOFTHSM2_LIBRARY;
        u.pin_value = k_pin;
        key_uri = u.to_string(/*with_pin_value=*/true);
        public_pem = p11::public_key_pem(s.public_key(s.find(u)));
    }
};

auto find_leader(const std::vector<std::unique_ptr<cluster_node_process>>& nodes,
                 std::chrono::seconds timeout)
    -> std::optional<std::pair<std::size_t, std::string>> {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            if (!nodes[i]->is_running()) {
                continue;
            }
            httplib::Client c("127.0.0.1", nodes[i]->http_port);
            c.set_connection_timeout(1, 0);
            c.set_read_timeout(10, 0);
            auto res =
                c.Get("/v1/root-ca",
                      httplib::Headers{{"Authorization", std::string("Bearer ") + k_auth_token}});
            if (res && res->status == 200 && !res->body.empty()) {
                return std::pair{i, res->body};
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    return std::nullopt;
}

/// Issues a certificate for a fresh CSR through whichever node leads,
/// retrying while a new leader readies its signer.
auto issue(const std::vector<std::unique_ptr<cluster_node_process>>& nodes, const std::string& name)
    -> std::string {
    rt::leaf_certificate_options lo;
    lo.dns_names = {name};
    const auto csr = rt::generate_key_and_csr(lo);
    boost::json::object body;
    body["csr_pem"] = csr.csr_pem;
    body["dns_names"] = boost::json::array{boost::json::string(name)};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto leader = find_leader(nodes, std::chrono::seconds(30));
        if (!leader) {
            continue;
        }
        httplib::Client c("127.0.0.1", nodes[leader->first]->http_port);
        c.set_connection_timeout(5, 0);
        c.set_read_timeout(65, 0);
        auto res =
            c.Post("/v1/certificates",
                   httplib::Headers{{"Authorization", std::string("Bearer ") + k_auth_token}},
                   boost::json::serialize(body), "application/json");
        if (res && res->status == 200) {
            return std::string(boost::json::parse(res->body).at("certificate_pem").as_string());
        }
        BOOST_TEST_MESSAGE("issue " << name << ": "
                                    << (res ? std::to_string(res->status) + " " + res->body
                                            : std::string("no response")));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    BOOST_FAIL("no certificate issued for " << name);
    return {};
}

/// A file's bytes followed by every base64 run in it decoded: the Raft log
/// and snapshots store commands and state as base64 inside JSON.
auto file_text(const std::filesystem::path& p) -> std::string {
    std::ifstream in(p, std::ios::binary);
    std::string raw{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    std::string out = raw;
    static const std::regex run("[A-Za-z0-9+/]{16,}={0,2}");
    for (std::sregex_iterator it(raw.begin(), raw.end(), run), end; it != end; ++it) {
        auto b64 = it->str();
        b64.resize(b64.size() - (b64.size() % 4));
        std::string decoded(b64.size(), '\0');
        const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()),
                                      reinterpret_cast<const unsigned char*>(b64.data()),
                                      static_cast<int>(b64.size()));
        if (n > 0) {
            out += '\n';
            out.append(decoded.data(), static_cast<std::size_t>(n));
        }
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_cluster_ca_signs_on_a_shared_token, *boost::unit_test::timeout(600)) {
    const auto root_dir = std::filesystem::temp_directory_path() /
                          ("hsm_ca_cluster_test_" + std::to_string(::getpid()));
    std::filesystem::remove_all(root_dir);
    std::filesystem::create_directories(root_dir);
    const softhsm_ca_token token(root_dir);
    const auto unseal = (root_dir / "unseal.key").string();
    std::ofstream(unseal) << "hsm-ca-cluster-unseal-passphrase\n";

    struct info {
        std::uint64_t id;
        int rpc_port;
        int http_port;
    };
    std::vector<info> infos;
    for (std::uint64_t id = 1; id <= 3; ++id) {
        infos.push_back({id, kythira::testing::free_port(), kythira::testing::free_port()});
    }
    std::ostringstream peers;
    for (std::size_t i = 0; i < infos.size(); ++i) {
        peers << (i > 0 ? "," : "") << infos[i].id << ":127.0.0.1:" << infos[i].rpc_port
              << "@http://127.0.0.1:" << infos[i].http_port;
    }
    std::vector<std::unique_ptr<cluster_node_process>> nodes;
    for (std::size_t i = 0; i < infos.size(); ++i) {
        nodes.push_back(std::make_unique<cluster_node_process>(
            infos[i].id, infos[i].rpc_port, infos[i].http_port,
            (root_dir / ("node" + std::to_string(infos[i].id))).string(), unseal, k_auth_token,
            peers.str(), /*bootstrap=*/i == 0,
            std::vector<std::string>{"--rpc-address", "127.0.0.1", "--http-address", "127.0.0.1",
                                     "--ca-key-uri", token.key_uri}));
    }

    const auto leader = find_leader(nodes, std::chrono::seconds(90));
    BOOST_REQUIRE_MESSAGE(leader.has_value(), "no leader served a root");
    const auto root = x509_of(leader->second);
    BOOST_REQUIRE(root);
    // The root is the token key's, self-signed through it.
    BOOST_TEST(pubkey_pem_of(root.get()) == token.public_pem);
    EVP_PKEY* root_key = X509_get0_pubkey(root.get());
    BOOST_TEST(X509_verify(root.get(), root_key) == 1);

    const auto before = issue(nodes, "before.example");
    BOOST_TEST(X509_verify(x509_of(before).get(), root_key) == 1);

    // Another node takes over and signs on the same token.
    const auto old_leader = leader->first;
    nodes[old_leader]->kill_hard();
    const auto next = find_leader(nodes, std::chrono::seconds(90));
    BOOST_REQUIRE_MESSAGE(next.has_value(), "no new leader after the kill");
    BOOST_TEST(next->first != old_leader);
    BOOST_TEST(next->second == leader->second);
    const auto after = issue(nodes, "after.example");
    BOOST_TEST(X509_verify(x509_of(after).get(), root_key) == 1);

    // The log records the key's URI, never a key: no data directory holds
    // a private key or the PIN.
    for (const auto& n : nodes) {
        n->stop();
    }
    bool saw_uri = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root_dir)) {
        if (!entry.is_regular_file() ||
            entry.path().string().find("softhsm") != std::string::npos) {
            continue;
        }
        const auto text = file_text(entry.path());
        BOOST_TEST_CONTEXT(entry.path()) {
            BOOST_TEST(text.find("PRIVATE KEY") == std::string::npos);
            BOOST_TEST(text.find(k_pin) == std::string::npos);
        }
        saw_uri = saw_uri || text.find("object=ca-root") != std::string::npos;
    }
    BOOST_TEST(saw_uri);
    std::filesystem::remove_all(root_dir);
}
