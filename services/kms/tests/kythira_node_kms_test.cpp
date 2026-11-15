// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The KMS as a module of kythira_node (.kiro/specs/kms-compatible-api/
// task 5, Requirements 2.1 and 4.1-4.5), as a process: one kythira_node
// running the KMS module over a PKCS#11 library, SoftHSM2 standing in for
// an external HSM. The catalog elects, the leader's jobs bind the token by
// label and log in, and a backing key no catalog entry accounts for (what
// a rotation or deletion that never committed leaves) is destroyed once
// the grace period passes. With the wrong PIN the node stays up, healthy,
// and says the HSM is unavailable.
//
// The co-located path (KYTHIRA_KMS_PKCS11=hsm) needs an initialized and
// unsealed virtual HSM with a bound token; kms_node_cluster_test runs the
// daemon over SoftHSM2 as the shared HSM (task 12).

#define BOOST_TEST_MODULE kythira_node_kms_test

#include <boost/test/unit_test.hpp>

#include "test_ports.hpp"

#include <kythira/kms/kms_backing.hpp>

#include <raft/pkcs11_module.hpp>

#ifndef KYTHIRA_NODE_PATH
#error "KYTHIRA_NODE_PATH must be defined"
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
namespace kms = kythira::kms;
namespace p11 = kythira::pkcs11;

namespace {

constexpr std::string_view k_orphan = "0000aaaa-3333-4000-8000-000000000000";

/// A SoftHSM2 token store of its own, with one token initialized, and a
/// directory for the node.
struct workspace {
    fs::path dir = fs::temp_directory_path() / ("kythira-node-kms-" + std::to_string(::getpid()));
    fs::path conf = dir / "softhsm2.conf";

    workspace() {
        fs::remove_all(dir);
        fs::create_directories(dir / "tokens");
        std::ofstream(conf) << "directories.tokendir = " << (dir / "tokens").string() << "\n"
                            << "objectstore.backend = file\nlog.level = ERROR\n";
        ::setenv("SOFTHSM2_CONF", conf.c_str(), 1);  // NOLINT(concurrency-mt-unsafe)
        const std::string init = std::string(KYTHIRA_SOFTHSM2_UTIL) +
                                 " --init-token --free --label kms --so-pin 5678 --pin 1234"
                                 " > /dev/null";
        BOOST_REQUIRE(std::system(init.c_str()) == 0);  // NOLINT(concurrency-mt-unsafe)
    }
    workspace(const workspace&) = delete;
    auto operator=(const workspace&) -> workspace& = delete;
    workspace(workspace&&) = delete;
    auto operator=(workspace&&) -> workspace& = delete;
    ~workspace() {
        if (std::getenv("KYTHIRA_NODE_KMS_TEST_KEEP") == nullptr) {
            std::error_code ec;
            fs::remove_all(dir, ec);
        }
    }

    /// The token, through the library as the node reaches it.
    [[nodiscard]] auto store() const -> std::unique_ptr<kms::backing_store> {
        auto backend = std::make_shared<p11::function_list_backend>(KYTHIRA_SOFTHSM2_LIBRARY);
        std::optional<CK_SLOT_ID> slot;
        for (const auto& t : backend->tokens()) {
            if (t.label == "kms") {
                slot = t.slot;
            }
        }
        BOOST_REQUIRE(slot.has_value());
        return std::make_unique<kms::backing_store>(backend, *slot, "1234");
    }
};

/// One GET to 127.0.0.1:`port`; the body, or nothing when no answer.
auto http_get(std::uint16_t port, const std::string& path) -> std::optional<std::string> {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return std::nullopt;
    }
    const std::string req =
        "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if (::send(fd, req.data(), req.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(req.size())) {
        ::close(fd);
        return std::nullopt;
    }
    std::string out;
    std::array<char, 4096> buf{};
    for (ssize_t n = 0; (n = ::recv(fd, buf.data(), buf.size(), 0)) > 0;) {
        out.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(fd);
    const auto body = out.find("\r\n\r\n");
    return body == std::string::npos ? std::nullopt : std::optional(out.substr(body + 4));
}

/// The value of metric `name` in a Prometheus text body.
auto metric(const std::string& body, const std::string& name) -> std::optional<double> {
    std::istringstream in(body);
    for (std::string line; std::getline(in, line);) {
        if (line.starts_with(name + " ")) {
            return std::stod(line.substr(name.size() + 1));
        }
    }
    return std::nullopt;
}

/// kythira_node with the KMS module alone, over SoftHSM2.
class node {
public:
    node(const workspace& w, const std::string& pin)
        : _metrics(kythira::testing::free_port()), _pid(spawn(w, pin, _metrics)) {}
    node(const node&) = delete;
    auto operator=(const node&) -> node& = delete;
    node(node&&) = delete;
    auto operator=(node&&) -> node& = delete;
    ~node() { stop(); }

    /// SIGTERM, and the exit status.
    auto stop() -> int {
        if (_pid <= 0) {
            return 0;
        }
        ::kill(_pid, SIGTERM);
        int status = 0;
        ::waitpid(_pid, &status, 0);
        _pid = -1;
        return status;
    }

    /// Waits until `pred` holds of the /metrics body.
    auto await_metrics(const std::function<bool(const std::string&)>& pred) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{60};
        while (std::chrono::steady_clock::now() < deadline) {
            if (const auto body = http_get(_metrics, "/metrics"); body && pred(*body)) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        return false;
    }

    [[nodiscard]] auto healthz() const -> std::string {
        return http_get(_metrics, "/healthz").value_or("");
    }

private:
    static auto spawn(const workspace& w, const std::string& pin, std::uint16_t metrics) -> pid_t {
        const auto raft = kythira::testing::free_port();
        const auto pin_file = w.dir / "pin";
        std::ofstream(pin_file) << pin << "\n";
        // Static authentication: the node runs no IAM module. The API
        // listener is idle here; it needs a port of its own.
        const auto keys_file = w.dir / "keys";
        std::ofstream(keys_file) << "AKIDNODETEST secret 111122223333 tester admin\n";
        const auto api = kythira::testing::free_port();
        const std::vector<std::string> env{
            "KYTHIRA_SERVICES=kms",
            "KYTHIRA_NODE_ID=1",
            "KYTHIRA_NODE_DATA_DIR=" + (w.dir / "data").string(),
            "KYTHIRA_NODE_PEERS=1=127.0.0.1:" + std::to_string(raft),
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + std::to_string(raft),
            "KYTHIRA_NODE_INSECURE_PLAINTEXT=1",
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(metrics),
            "KYTHIRA_KMS_API_URLS=1=http://127.0.0.1:" + std::to_string(api),
            "KYTHIRA_KMS_API_LISTEN=127.0.0.1:" + std::to_string(api),
            "KYTHIRA_KMS_AUTH=static",
            "KYTHIRA_KMS_STATIC_KEYS_FILE=" + keys_file.string(),
            std::string("KYTHIRA_KMS_PKCS11=") + KYTHIRA_SOFTHSM2_LIBRARY,
            "KYTHIRA_KMS_PIN_FILE=" + pin_file.string(),
            "KYTHIRA_KMS_JOB_INTERVAL_MS=200",
            "KYTHIRA_KMS_GRACE_MS=1000",
            "SOFTHSM2_CONF=" + w.conf.string(),
            "PATH=/usr/bin:/bin",
        };
        const auto log = (w.dir / "node.log").string();
        const pid_t pid = ::fork();
        BOOST_REQUIRE(pid >= 0);
        if (pid == 0) {
            const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            ::dup2(fd, 1);
            ::dup2(fd, 2);
            std::vector<char*> envp;
            envp.reserve(env.size() + 1);
            for (const auto& e : env) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                envp.push_back(const_cast<char*>(e.c_str()));
            }
            envp.push_back(nullptr);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            std::array<char*, 2> argv{const_cast<char*>(KYTHIRA_NODE_PATH), nullptr};
            ::execve(argv[0], argv.data(), envp.data());
            ::_exit(127);
        }
        return pid;
    }

    std::uint16_t _metrics;
    pid_t _pid = -1;
};

}  // namespace

BOOST_AUTO_TEST_CASE(the_leader_binds_the_token_and_sweeps_an_orphan,
                     *boost::unit_test::timeout(180)) {
    const workspace w;
    {
        // What a rotation that never committed leaves behind.
        auto s = w.store();
        (void)s->generate(std::string(k_orphan), 2, kms::key_spec::symmetric_default,
                          kms::key_usage::encrypt_decrypt);
    }
    node n(w, "1234");
    BOOST_TEST(n.await_metrics([](const std::string& m) {
        return metric(m, "kythira_kms_leader") == 1.0 &&
               metric(m, "kythira_kms_orphans_destroyed").value_or(0) >= 1.0 &&
               metric(m, "kythira_kms_hsm_available") == 1.0;
    }));
    const auto health = n.healthz();
    BOOST_TEST(health.find(R"("kms":{"healthy":true})") != std::string::npos, health);
    BOOST_TEST(n.stop() == 0);
    BOOST_TEST(!w.store()->find(std::string(k_orphan), 2).has_value());
    BOOST_TEST(w.store()->list().empty());
}

BOOST_AUTO_TEST_CASE(a_wrong_pin_leaves_the_node_up_and_says_why, *boost::unit_test::timeout(180)) {
    const workspace w;
    {
        auto s = w.store();
        (void)s->generate(std::string(k_orphan), 1, kms::key_spec::symmetric_default,
                          kms::key_usage::encrypt_decrypt);
    }
    node n(w, "4321");
    BOOST_TEST(n.await_metrics([](const std::string& m) {
        return metric(m, "kythira_kms_leader") == 1.0 &&
               metric(m, "kythira_kms_job_passes").value_or(0) >= 3.0;
    }));
    const auto health = n.healthz();
    BOOST_TEST(
        health.find(R"("kms":{"healthy":true,"detail":"hsm unavailable"})") != std::string::npos,
        health);
    BOOST_TEST(n.await_metrics([](const std::string& m) {
        return metric(m, "kythira_kms_hsm_available") == 0.0 &&
               metric(m, "kythira_kms_orphans_destroyed") == 0.0;
    }));
    BOOST_TEST(n.stop() == 0);
    // Nothing was destroyed without a login.
    BOOST_TEST(w.store()->find(std::string(k_orphan), 1).has_value());
}
