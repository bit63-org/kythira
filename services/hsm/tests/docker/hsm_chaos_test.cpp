// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The virtual HSM under kills and partitions, in containers
// (.kiro/specs/virtual-hsm/ task 11b, Requirement 13.6).
// services/hsm/docker/hsm-chaos-compose.yml starts three members addressed
// by service name, with Raft, the operator API and the PKCS#11 listener
// all on mutual TLS, in each layout:
//
//   * stand-alone: `hsm_node`, the HSM module alone;
//   * co-located: `kythira_node` running the HSM beside the Redis module,
//     sharing each node's process, Raft listener and data directory.
//
// In each layout, as an operator and an application would from outside
// (hsm_test_cluster.hpp, the scenarios hsm_node_cluster_test runs on
// processes):
//
//   * the token group's leader is SIGKILLed while two clients generate key
//     pairs through the followers, then started and unsealed;
//   * the token group's leader is cut off the network while they generate,
//     then joined again (it must step down and catch up, keeping nothing
//     the new leader overwrote);
//   * the catalog's leader is SIGKILLed while a follower rekeys the master
//     key, at two moments;
//
// and after each, every member lists the same whole key pairs, every
// acknowledged generation is among them, and every pair signs on one
// member and verifies on another.
//
// Not registered in CTest: it needs Docker or rootless Podman and runs
// through the docker-hsm-chaos-tests target.

#define BOOST_TEST_MODULE hsm_chaos_test
#include "hsm_test_cluster.hpp"
#include "hsm_test_pki.hpp"
#include "os_faults.hpp"
#include "test_ports.hpp"

#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <initializer_list>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace hsm = kythira::hsm;
namespace os = docker_chaos::os;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

constexpr std::array<const char*, 3> k_containers{"kythira-hsm-chaos-1", "kythira-hsm-chaos-2",
                                                  "kythira-hsm-chaos-3"};
constexpr std::array<const char*, 3> k_services{"hsm-1", "hsm-2", "hsm-3"};
constexpr const char* k_network = "kythira_hsm_chaos_net";

auto compose_file() -> std::string {
    const char* env = std::getenv("KYTHIRA_HSM_CHAOS_COMPOSE_FILE");
    if (env != nullptr && *env != 0) {
        return env;
    }
    return "services/hsm/docker/hsm-chaos-compose.yml";
}

auto compose_cmd(std::initializer_list<std::string> args) -> std::vector<std::string> {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args);
    return cmd;
}

/// The other module of the co-located layout (the docker-hsm-chaos-tests
/// target passes it); "none" runs the HSM alone in kythira_node, for a
/// kythira_node built with no other module.
auto colocated_with() -> std::string {
    const char* env = std::getenv("KYTHIRA_HSM_CHAOS_COLOCATE");
    return env != nullptr && *env != 0 ? std::string(env) : std::string("redis");
}

enum class layout {
    stand_alone,
    co_located
};

/// The PKI, as a base so it exists before cluster_driver issues from it.
struct pki_holder {
    hsm::test::test_pki pki;
};

/// Three members from the compose file, in one layout.
class container_cluster : private pki_holder, public hsm::test::cluster_driver {
public:
    explicit container_cluster(layout l) : cluster_driver(pki) {
        for (std::size_t i = 0; i < 3; ++i) {
            (void)pki.issue("node-" + std::to_string(i + 1),
                            std::string("DNS:") + k_services[i] +
                                ",DNS:localhost,IP:127.0.0.1,URI:" + hsm::test::member_identity(i));
        }
        // uid 10001 reads the PKI in every container, which owns none of it
        // under Docker or rootless Podman. Throwaway test keys.
        fs::permissions(pki.dir(), fs::perms::owner_all | fs::perms::group_read |
                                       fs::perms::group_exec | fs::perms::others_read |
                                       fs::perms::others_exec);
        for (const auto& f : fs::directory_iterator(pki.dir())) {
            fs::permissions(f.path(), fs::perms::owner_read | fs::perms::owner_write |
                                          fs::perms::group_read | fs::perms::others_read);
        }
        const auto base = kythira::testing::free_port_block(6);
        for (std::size_t i = 0; i < 3; ++i) {
            _api[i] = static_cast<std::uint16_t>(base + i);
            _clients[i] = static_cast<std::uint16_t>(base + 3 + i);
            ::setenv(("KYTHIRA_HSM_CHAOS_API_" + std::to_string(i + 1)).c_str(),
                     std::to_string(_api[i]).c_str(), 1);
            ::setenv(("KYTHIRA_HSM_CHAOS_CLIENTS_" + std::to_string(i + 1)).c_str(),
                     std::to_string(_clients[i]).c_str(), 1);
        }
        ::setenv("KYTHIRA_HSM_CHAOS_PKI_DIR", pki.dir().c_str(), 1);
        if (l == layout::co_located) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            const auto other = colocated_with();
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES",
                     (other == "none" ? std::string("hsm") : "hsm," + other).c_str(), 1);
        } else {
            ::unsetenv("KYTHIRA_HSM_CHAOS_DAEMON");
            ::unsetenv("KYTHIRA_HSM_CHAOS_SERVICES");
        }
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d"}));
        _up = {true, true, true};
        initialize(180s);
    }

    container_cluster(const container_cluster&) = delete;
    auto operator=(const container_cluster&) -> container_cluster& = delete;
    container_cluster(container_cluster&&) = delete;
    auto operator=(container_cluster&&) -> container_cluster& = delete;

    ~container_cluster() override {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            for (const auto* c : k_containers) {
                std::cerr << "── " << c << " ──\n"
                          << os::real_exec(os::docker_logs_cmd(c, 300)).out;
            }
        }
        try {
            os::real_exec(compose_cmd({"down", "-v", "--remove-orphans"}));
        } catch (...) {
        }
    }

    [[nodiscard]] auto size() const -> std::size_t override { return 3; }

    [[nodiscard]] auto api_url(std::size_t i) const -> std::string override {
        return "https://localhost:" + std::to_string(_api.at(i));
    }

    [[nodiscard]] auto client_at(std::size_t i) const -> endpoint override {
        return {"127.0.0.1", _clients.at(i)};
    }

    [[nodiscard]] auto running(std::size_t i) const -> bool override { return _up.at(i); }

    // A kill that fails means the container was not running: it exited on
    // its own, which is the failure worth reporting.
    void kill(std::size_t i) override {
        BOOST_TEST_MESSAGE("SIGKILL " << k_containers.at(i));
        const auto r = os::real_exec(os::docker_kill_cmd(k_containers.at(i)));
        BOOST_REQUIRE_MESSAGE(r.code == 0, k_containers.at(i) << " was not running: " << r.out);
        _up.at(i) = false;
    }

    void start(std::size_t i) override {
        BOOST_TEST_MESSAGE("start " << k_containers.at(i));
        const auto r = os::real_exec(os::docker_start_cmd(k_containers.at(i)));
        BOOST_REQUIRE_MESSAGE(r.code == 0, "start " << k_containers.at(i) << " failed: " << r.out);
        _up.at(i) = true;
    }

    void isolate(std::size_t i) {
        BOOST_TEST_MESSAGE("isolate " << k_containers.at(i));
        os::checked_exec(os::real_exec, os::network_disconnect_cmd(k_network, k_containers.at(i)));
        _up.at(i) = false;  // its published ports go with the network
    }

    void rejoin(std::size_t i) {
        BOOST_TEST_MESSAGE("rejoin " << k_containers.at(i));
        os::checked_exec(os::real_exec,
                         os::network_connect_cmd(k_network, k_containers.at(i), k_services.at(i)));
        _up.at(i) = true;
    }

private:
    std::array<std::uint16_t, 3> _api{};
    std::array<std::uint16_t, 3> _clients{};
    std::array<bool, 3> _up{};
};

void run_scenarios(container_cluster& cl) {
    BOOST_TEST_CHECKPOINT("kill the token leader during key generation");
    hsm::test::keygen_under_leader_kill(cl);
    BOOST_TEST_CHECKPOINT("cut the token leader off during key generation");
    hsm::test::keygen_under_leader_fault(
        cl, [&](std::size_t i) { cl.isolate(i); }, [&](std::size_t i) { cl.rejoin(i); }, 5s);
    BOOST_TEST_CHECKPOINT("kill the catalog leader during rekey");
    hsm::test::rekey_under_leader_kill(cl, {15ms, 120ms});
}

}  // namespace

BOOST_AUTO_TEST_CASE(stand_alone_hsm_node) {
    container_cluster cl(layout::stand_alone);
    run_scenarios(cl);
}

BOOST_AUTO_TEST_CASE(co_located_in_kythira_node) {
    container_cluster cl(layout::co_located);
    run_scenarios(cl);
}
