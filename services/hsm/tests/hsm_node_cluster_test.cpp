// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Three hsm_node processes (.kiro/specs/virtual-hsm/ task 11, requirements
// 2.1 and 13.5): the stand-alone daemon, mutual TLS everywhere, an operator
// who initializes, unseals and rekeys over the HTTPS API, and an
// application on the PKCS#11 wire protocol. The scenarios are
// hsm_test_cluster.hpp's, which the docker-chaos scenario runs too:
//
//   * kills during key generation: two clients generate token key pairs
//     through the followers while the token group's leader is SIGKILLed
//     and started again. Afterwards every replica lists the same keys,
//     every generation that answered CKR_OK is among them, every key is a
//     whole pair, and every pair signs on one node and verifies on another.
//
//   * kills during rekey: a rekey is sent to a follower and the catalog's
//     leader is SIGKILLed as it runs, at a different moment each round.
//     The follower's answer carries the new shares whether or not the
//     commit was certain; once the cluster settles every node agrees on one
//     generation, the shares of that generation unseal every node, and
//     every key still works.
//
// (Node unseal staying sealed with only k - 1 reachable members is
// hsm_node_unseal_test's.)

#define BOOST_TEST_MODULE hsm_node_cluster_test
#include "hsm_test_cluster.hpp"
#include "hsm_test_pki.hpp"
#include "test_ports.hpp"

#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef HSM_NODE_PATH
#define HSM_NODE_PATH "hsm_node"
#endif

namespace hsm = kythira::hsm;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

auto slurp(const fs::path& p) -> std::string {
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

struct member {
    std::uint16_t raft = 0;
    std::uint16_t api = 0;
    std::uint16_t clients = 0;
    std::uint16_t metrics = 0;
    pid_t pid = -1;
    hsm::test::test_pki::files tls;
};

/// The PKI, as a base so it exists before cluster_driver issues from it.
struct pki_holder {
    hsm::test::test_pki pki;
};

/// Three hsm_node processes on loopback.
class process_cluster : private pki_holder, public hsm::test::cluster_driver {
public:
    process_cluster() : cluster_driver(pki) {
        std::random_device rd;
        _dir = fs::temp_directory_path() / ("kythira-hsm-cluster-" + std::to_string(rd()));
        fs::create_directories(_dir);
        const auto base = kythira::testing::free_port_block(12);
        for (std::size_t i = 0; i < 3; ++i) {
            member m;
            const auto b = static_cast<std::uint16_t>(base + 4 * i);
            m.raft = b;
            m.api = b + 1;
            m.clients = b + 2;
            m.metrics = b + 3;
            m.tls = pki.issue("node-" + std::to_string(i + 1),
                              "DNS:localhost,IP:127.0.0.1,URI:" + hsm::test::member_identity(i));
            _members.push_back(m);
        }
        for (std::size_t i = 0; i < _members.size(); ++i) {
            start(i);
        }
        initialize();
    }

    process_cluster(const process_cluster&) = delete;
    auto operator=(const process_cluster&) -> process_cluster& = delete;
    process_cluster(process_cluster&&) = delete;
    auto operator=(process_cluster&&) -> process_cluster& = delete;

    ~process_cluster() override {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            dump_logs();
        }
        for (auto& m : _members) {
            stop(m);
        }
        if (std::getenv("KYTHIRA_HSM_CLUSTER_TEST_KEEP") == nullptr) {
            std::error_code ec;
            fs::remove_all(_dir, ec);
        }
    }

    [[nodiscard]] auto size() const -> std::size_t override { return _members.size(); }

    [[nodiscard]] auto api_url(std::size_t i) const -> std::string override {
        return "https://localhost:" + std::to_string(_members[i].api);
    }

    [[nodiscard]] auto client_at(std::size_t i) const -> endpoint override {
        return {"127.0.0.1", _members[i].clients};
    }

    [[nodiscard]] auto running(std::size_t i) const -> bool override { return _members[i].pid > 0; }

    void start(std::size_t i) override {
        auto& m = _members[i];
        const auto list = [&](const std::string& prefix, auto port_of) {
            std::string out;
            for (std::size_t q = 0; q < _members.size(); ++q) {
                out += (out.empty() ? "" : ",") + std::to_string(q + 1) + "=" + prefix +
                       std::to_string(port_of(_members[q]));
            }
            return out;
        };
        std::string peers;
        for (std::size_t q = 0; q < _members.size(); ++q) {
            peers += (peers.empty() ? "" : ",") + hsm::test::member_identity(q);
        }
        const auto dir = _dir / ("node-" + std::to_string(i + 1));
        fs::create_directories(dir);
        const std::vector<std::string> env{
            "KYTHIRA_NODE_ID=" + std::to_string(i + 1),
            "KYTHIRA_NODE_DATA_DIR=" + (dir / "data").string(),
            "KYTHIRA_NODE_PEERS=" + list("127.0.0.1:", [](const auto& q) { return q.raft; }),
            "KYTHIRA_NODE_RAFT_BIND=127.0.0.1",
            "KYTHIRA_NODE_RAFT_PORT=" + std::to_string(m.raft),
            "KYTHIRA_NODE_TLS_CERT=" + m.tls.cert,
            "KYTHIRA_NODE_TLS_KEY=" + m.tls.key,
            "KYTHIRA_NODE_TLS_CA=" + pki.ca_path(),
            "KYTHIRA_NODE_METRICS_BIND=127.0.0.1",
            "KYTHIRA_NODE_METRICS_PORT=" + std::to_string(m.metrics),
            "KYTHIRA_HSM_API_LISTEN=127.0.0.1:" + std::to_string(m.api),
            "KYTHIRA_HSM_API_URLS=" +
                list("https://localhost:", [](const auto& q) { return q.api; }),
            "KYTHIRA_HSM_PEER_IDENTITIES=" + peers,
            std::string("KYTHIRA_HSM_OPERATORS=") + hsm::test::k_cluster_operator,
            "KYTHIRA_HSM_CLIENT_LISTEN=127.0.0.1:" + std::to_string(m.clients),
            // CI runners cap RLIMIT_MEMLOCK; cheap PIN verifiers keep the
            // logins of many short sessions fast.
            "KYTHIRA_HSM_ALLOW_UNLOCKED_MEMORY=true",
            "KYTHIRA_HSM_PIN_COST_LOG2=10",
            "PATH=/usr/bin:/bin",
        };
        const auto log = (dir / "node.log").string();
        const pid_t pid = ::fork();
        BOOST_REQUIRE(pid >= 0);
        if (pid == 0) {
            const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            ::dup2(fd, 1);
            ::dup2(fd, 2);
            std::vector<char*> envp;
            envp.reserve(env.size() + 1);
            for (const auto& e : env) {
                envp.push_back(
                    const_cast<char*>(e.c_str()));  // NOLINT(cppcoreguidelines-pro-type-const-cast)
            }
            envp.push_back(nullptr);
            std::array<char*, 2> argv{
                const_cast<char*>(HSM_NODE_PATH),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
                nullptr};
            ::execve(argv[0], argv.data(), envp.data());
            ::_exit(127);
        }
        m.pid = pid;
    }

    void kill(std::size_t i) override {
        auto& m = _members[i];
        if (m.pid <= 0) {
            return;
        }
        ::kill(m.pid, SIGKILL);
        int status = 0;
        ::waitpid(m.pid, &status, 0);
        m.pid = -1;
    }

private:
    void stop(member& m) {
        if (m.pid <= 0) {
            return;
        }
        ::kill(m.pid, SIGTERM);
        const auto deadline = std::chrono::steady_clock::now() + 30s;
        int status = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (::waitpid(m.pid, &status, WNOHANG) == m.pid) {
                m.pid = -1;
                return;
            }
            std::this_thread::sleep_for(20ms);
        }
        BOOST_ERROR("an hsm_node ignored SIGTERM; killing it");
        ::kill(m.pid, SIGKILL);
        ::waitpid(m.pid, &status, 0);
        m.pid = -1;
    }

    void dump_logs() const {
        for (std::size_t i = 0; i < _members.size(); ++i) {
            const auto log = slurp(_dir / ("node-" + std::to_string(i + 1)) / "node.log");
            const auto tail = log.size() > 6000 ? log.substr(log.size() - 6000) : log;
            BOOST_TEST_MESSAGE("---- hsm_node " << i + 1 << " log tail ----\n" << tail);
        }
    }

    fs::path _dir;
    std::vector<member> _members;
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(the_token_leader_killed_during_key_generation, process_cluster) {
    hsm::test::keygen_under_leader_kill(*this);
}

BOOST_FIXTURE_TEST_CASE(the_catalog_leader_killed_during_rekey, process_cluster) {
    hsm::test::rekey_under_leader_kill(*this, {0ms, 15ms, 40ms, 120ms});
}
