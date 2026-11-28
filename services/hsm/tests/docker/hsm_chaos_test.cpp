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
//     sharing each node's process, Raft listener and data directory;
//   * encrypted services (.kiro/specs/kms-compatible-api/ task 19,
//     Requirement 14.5): `kythira_node` running the HSM, the KMS (its
//     backing keys on the HSM's token), DynamoDB and Kinesis (encrypting
//     through the co-located KMS);
//   * KMS layers (.kiro/specs/kms-independent-layers/ task 6, Requirement
//     11.3): `kythira_node` running the HSM and the KMS, joined by a KMS
//     data node, a lone gateway and a lone front end on
//     libkythira_pkcs11.so, while the KMS moves from co-located to split
//     and back (run_kms_layers below).
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
// In the encrypted-services layout, an encrypted table and an encrypted
// stream take writes, and the KMS hands out data keys, while one member is
// SIGKILLed (the HSM catalog's leader; started and unsealed again) and
// another is cut off the network and joined again. Every acknowledged
// item and record must then read back, and once the members stop, no data
// key the KMS returned and no plaintext the test encrypted may appear in
// any member's data directory. Item and record values are searched for
// too, in every file. DynamoDB seals a value only when it applies the
// write (an UpdateItem's result is known only then), so this layout seals
// every module's Raft logs at rest (KYTHIRA_RAFT_LOG_KMS=local,
// .kiro/specs/raft-log-encryption/): without that, the log entry carrying
// a write would hold its value in the clear until compaction. Item keys
// stay in the clear by design (the engine orders by them), so only values
// carry the searched-for text.
//
// A case whose kythira_node modules are missing (KYTHIRA_HSM_CHAOS_MODULES)
// is skipped, naming the module.
//
// Not registered in CTest: it needs Docker or rootless Podman and runs
// through the docker-hsm-chaos-tests target.

#define BOOST_TEST_MODULE hsm_chaos_test
#include "hsm_test_cluster.hpp"
#include "hsm_test_pki.hpp"
#include "os_faults.hpp"
#include "test_ports.hpp"

#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <functional>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

namespace hsm = kythira::hsm;
namespace os = docker_chaos::os;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

// The HSM members, then the KMS-layers layout's KMS-only nodes (the
// compose file's `kms-layers` profile).
constexpr std::array<const char*, 6> k_containers{"kythira-hsm-chaos-1",  "kythira-hsm-chaos-2",
                                                  "kythira-hsm-chaos-3",  "kythira-kms-layers-4",
                                                  "kythira-kms-layers-5", "kythira-kms-layers-6"};
constexpr std::array<const char*, 6> k_services{"hsm-1", "hsm-2", "hsm-3",
                                                "kms-4", "kms-5", "kms-6"};
constexpr const char* k_kms_profile = "kms-layers";
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

/// A Boost.Test precondition: kythira_node has every module in `needed`
/// (KYTHIRA_HSM_CHAOS_MODULES, the docker-hsm-chaos-tests target's list;
/// unset runs every case).
auto has_modules(std::initializer_list<std::string_view> needed)
    -> std::function<boost::test_tools::assertion_result(boost::unit_test::test_unit_id)> {
    std::vector<std::string> want(needed.begin(), needed.end());
    return [want](boost::unit_test::test_unit_id) -> boost::test_tools::assertion_result {
        const char* env = std::getenv("KYTHIRA_HSM_CHAOS_MODULES");
        if (env == nullptr) {
            return true;
        }
        const auto list = "," + std::string(env) + ",";
        for (const auto& m : want) {
            if (list.find("," + m + ",") == std::string::npos) {
                boost::test_tools::assertion_result r(false);
                r.message() << "kythira_node has no " << m << " module (has: " << env << ")";
                return r;
            }
        }
        return true;
    };
}

enum class layout {
    stand_alone,
    co_located,
    encrypted_services,
    kms_layers
};

/// "https://<service>:8443" of node i, as the other containers dial its KMS.
auto kms_url_in_network(std::size_t i) -> std::string {
    return std::string("https://") + k_services.at(i) + ":8443";
}

/// The one static key the KMS, DynamoDB and Kinesis accept, an
/// administrator of the account the scenario works in.
constexpr const char* k_access_key = "AKIAHSMCHAOS00000001";
constexpr const char* k_secret_key = "hsm-chaos-static-secret-0001";
constexpr const char* k_account = "111122223333";
constexpr const char* k_region = "us-east-1";

/// The PKI, as a base so it exists before cluster_driver issues from it.
struct pki_holder {
    hsm::test::test_pki pki;
};

/// Three members from the compose file, in one layout.
class container_cluster : private pki_holder, public hsm::test::cluster_driver {
public:
    explicit container_cluster(layout l) : cluster_driver(pki) {
        // The KMS-layers layout's nodes 4-6 need certificates too.
        const std::size_t nodes = l == layout::kms_layers ? k_containers.size() : 3;
        for (std::size_t i = 0; i < nodes; ++i) {
            _node_tls.push_back(
                pki.issue("node-" + std::to_string(i + 1),
                          std::string("DNS:") + k_services.at(i) +
                              ",DNS:localhost,IP:127.0.0.1,URI:" + hsm::test::member_identity(i)));
        }
        // libkythira_pkcs11.so's configuration on the KMS-layers layout's
        // lone front end: every member's PKCS#11 listener, as the
        // application the token binds.
        std::ofstream(pki.dir() / "pkcs11.conf")
            << "endpoint = hsm-1:9444, hsm-2:9444, hsm-3:9444\n"
            << "cert = /pki/app.pem\nkey = /pki/app.key\nca = /pki/ca.pem\ntimeout_s = 10\n";
        // The services' static key (the KMS and Kinesis read blank-separated
        // fields, DynamoDB ':'-separated ones) and the token's user PIN, for
        // the KMS's session on the co-located HSM.
        std::ofstream(pki.dir() / "keys")
            << k_access_key << ' ' << k_secret_key << ' ' << k_account << " tester admin\n";
        std::ofstream(pki.dir() / "ddb-keys")
            << k_access_key << ':' << k_secret_key << ':' << k_account << ":tester:admin\n";
        std::ofstream(pki.dir() / "kms-pin") << hsm::test::k_cluster_user_pin;
        // uid 10001 reads the PKI in every container, which owns none of it
        // under Docker or rootless Podman. Throwaway test keys.
        fs::permissions(pki.dir(), fs::perms::owner_all | fs::perms::group_read |
                                       fs::perms::group_exec | fs::perms::others_read |
                                       fs::perms::others_exec);
        for (const auto& f : fs::directory_iterator(pki.dir())) {
            fs::permissions(f.path(), fs::perms::owner_read | fs::perms::owner_write |
                                          fs::perms::group_read | fs::perms::others_read);
        }
        // Every layout publishes all five ports; only the encrypted-services
        // layout serves the last three. The KMS-layers layout serves the
        // first two and the KMS, and three more KMS ports on nodes 4-6.
        const auto base = kythira::testing::free_port_block(18);
        const std::array<std::array<std::uint16_t, 3>*, 5> ports{&_api, &_clients, &_kms3, &_ddb,
                                                                 &_kinesis};
        const std::array<const char*, 5> names{"API", "CLIENTS", "KMS", "DDB", "KINESIS"};
        for (std::size_t p = 0; p < ports.size(); ++p) {
            for (std::size_t i = 0; i < 3; ++i) {
                (*ports[p])[i] = static_cast<std::uint16_t>(base + (3 * p) + i);
                ::setenv(std::format("KYTHIRA_HSM_CHAOS_{}_{}", names[p], i + 1).c_str(),
                         std::to_string((*ports[p])[i]).c_str(), 1);
            }
        }
        for (std::size_t i = 0; i < _kms.size(); ++i) {
            _kms.at(i) = i < 3 ? _kms3.at(i) : static_cast<std::uint16_t>(base + 15 + (i - 3));
            ::setenv(std::format("KYTHIRA_HSM_CHAOS_KMS_{}", i + 1).c_str(),
                     std::to_string(_kms.at(i)).c_str(), 1);
        }
        set_kms_layers_env(l);
        ::setenv("KYTHIRA_HSM_CHAOS_PKI_DIR", pki.dir().c_str(), 1);
        if (l == layout::co_located) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            const auto other = colocated_with();
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES",
                     (other == "none" ? std::string("hsm") : "hsm," + other).c_str(), 1);
        } else if (l == layout::encrypted_services) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES", "hsm,kms,dynamodb,kinesis", 1);
        } else if (l == layout::kms_layers) {
            ::setenv("KYTHIRA_HSM_CHAOS_DAEMON", "/usr/local/bin/kythira_node", 1);
            ::setenv("KYTHIRA_HSM_CHAOS_SERVICES", "hsm,kms", 1);
        } else {
            ::unsetenv("KYTHIRA_HSM_CHAOS_DAEMON");
            ::unsetenv("KYTHIRA_HSM_CHAOS_SERVICES");
        }
        _layout = l;
        os::try_exec(os::real_exec, down_cmd());
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d"}));
        _up = {true, true, true, false, false, false};
        initialize(180s);
    }

    container_cluster(const container_cluster&) = delete;
    auto operator=(const container_cluster&) -> container_cluster& = delete;
    container_cluster(container_cluster&&) = delete;
    auto operator=(container_cluster&&) -> container_cluster& = delete;

    ~container_cluster() override {
        const auto id = boost::unit_test::framework::current_test_case().p_id;
        if (!boost::unit_test::results_collector.results(id).passed()) {
            const std::size_t n = _layout == layout::kms_layers ? k_containers.size() : 3;
            for (std::size_t i = 0; i < n; ++i) {
                std::cerr << "── " << k_containers.at(i) << " ──\n" << log_digest(logs_of(i));
            }
        }
        try {
            os::real_exec(down_cmd());
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

    /// Node i's published KMS port: the members' (0-2), then nodes 4-6's.
    [[nodiscard]] auto kms_port(std::size_t i) const -> std::uint16_t { return _kms.at(i); }
    [[nodiscard]] auto ddb_port(std::size_t i) const -> std::uint16_t { return _ddb.at(i); }
    [[nodiscard]] auto kinesis_port(std::size_t i) const -> std::uint16_t { return _kinesis.at(i); }
    [[nodiscard]] auto ca_path() const -> const std::string& { return pki.ca_path(); }

    /// Stops every member, keeping its data, and copies each one's data
    /// directory out to `into`/<container>.
    void stop_and_copy_data(const fs::path& into) {
        os::checked_exec(os::real_exec, compose_cmd({"stop"}));
        _up = {};
        for (std::size_t i = 0; i < 3; ++i) {
            const auto* c = k_containers.at(i);
            // Into a directory made first, by "/data/.": Docker and
            // Podman differ on what a copy to a missing path makes.
            const auto dest = into / c;
            fs::create_directories(dest);
            os::checked_exec(os::real_exec,
                             std::vector<std::string>{os::container_runtime(), "cp",
                                                      std::string(c) + ":/data/.", dest.string()});
        }
    }

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

    // ---- the KMS-layers layout ------------------------------------------

    /// The KMS roles node i (0-5) runs; "" is all three.
    [[nodiscard]] auto kms_roles(std::size_t i) const -> const std::string& { return _roles.at(i); }

    /// Recreates member i (0-2) with KMS roles `roles` (its HSM, sealed
    /// again, and its /data volume carry over), every node's view of the
    /// layout recomputed as a fresh container would read it, and unseals
    /// its HSM. Like a restart under a new configuration in production:
    /// the other running containers keep the configuration they started
    /// with.
    void recreate_member(std::size_t i, const std::string& roles) {
        BOOST_TEST_MESSAGE("recreate " << k_containers.at(i) << " with KMS roles '" << roles
                                       << "'");
        _roles.at(i) = roles;
        export_layout();
        _up.at(i) = false;
        os::checked_exec(os::real_exec, compose_cmd({"up", "-d", "--no-deps", "--force-recreate",
                                                     k_services.at(i)}));
        _up.at(i) = true;
        BOOST_REQUIRE(hsm::test::eventually([&] { return status(i).has_value(); }, 120s));
        BOOST_REQUIRE_MESSAGE(unseal(i, current, 120s), k_containers.at(i) << " stayed sealed");
    }

    /// Starts the KMS-only nodes `nodes` (3-5) for the first time.
    void start_kms_nodes(const std::vector<std::size_t>& nodes) {
        export_layout();
        auto cmd = os::compose_prefix();
        cmd.insert(cmd.end(),
                   {"-f", compose_file(), "--profile", k_kms_profile, "up", "-d", "--no-deps"});
        for (const auto i : nodes) {
            BOOST_TEST_MESSAGE("start " << k_containers.at(i));
            cmd.emplace_back(k_services.at(i));
        }
        os::checked_exec(os::real_exec, cmd);
        for (const auto i : nodes) {
            _up.at(i) = true;
        }
    }

    /// Everything node i has logged.
    [[nodiscard]] auto logs_of(std::size_t i) const -> std::string {
        return os::real_exec(os::container_logs_all_cmd(k_containers.at(i))).out;
    }

    /// The last 300 lines of a log that are not KMS audit records (which
    /// would crowd out everything else), and how many audit records failed.
    [[nodiscard]] static auto log_digest(const std::string& log) -> std::string {
        std::vector<std::string> kept;
        std::size_t audit_errors = 0;
        std::istringstream lines(log);
        for (std::string line; std::getline(lines, line);) {
            if (line.starts_with(R"({"eventVersion")")) {
                audit_errors += line.find(R"("errorCode")") != std::string::npos ? 1 : 0;
                continue;
            }
            kept.push_back(std::move(line));
        }
        std::string out;
        for (auto i = kept.size() > 300 ? kept.size() - 300 : 0; i < kept.size(); ++i) {
            out += kept[i] + "\n";
        }
        return out + "(" + std::to_string(audit_errors) + " KMS audit records with an error)\n";
    }

    /// Stops node i (SIGTERM, then the drain), keeping its container.
    void stop_node(std::size_t i) {
        BOOST_TEST_MESSAGE("stop " << k_containers.at(i));
        os::checked_exec(os::real_exec, os::docker_stop_cmd(k_containers.at(i), 30));
        _up.at(i) = false;
    }

    /// A call to node i's KMS listener presenting node `as`'s certificate
    /// (a peer identity), as the membership routes need.
    [[nodiscard]] auto as_node(std::size_t i, std::size_t as, const std::string& method,
                               const std::string& path, const std::string& body = {}) const
        -> std::optional<std::pair<int, std::string>> {
        httplib::SSLClient cli("localhost", _kms.at(i), _node_tls.at(as).cert,
                               _node_tls.at(as).key);
        cli.set_ca_cert_path(pki.ca_path());
        cli.enable_server_certificate_verification(true);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(20, 0);
        auto r = method == "GET" ? cli.Get(path) : cli.Post(path, body, "application/json");
        if (!r) {
            return std::nullopt;
        }
        return std::pair{r->status, r->body};
    }

private:
    [[nodiscard]] static auto down_cmd() -> std::vector<std::string> {
        // The profile's nodes too, whichever layout ran.
        auto cmd = os::compose_prefix();
        cmd.insert(cmd.end(), {"-f", compose_file(), "--profile", k_kms_profile, "down", "-v",
                               "--remove-orphans"});
        return cmd;
    }

    /// The KMS-layers layout's starting point: members 1-3 with every KMS
    /// layer, node 4 a data node, 5 a gateway, 6 a front end. Any other
    /// layout clears what an earlier case left in the environment.
    void set_kms_layers_env(layout l) {
        static constexpr std::array<const char*, 7> k_vars{
            "KYTHIRA_HSM_CHAOS_PEERS",          "KYTHIRA_HSM_CHAOS_KMS_URLS",
            "KYTHIRA_HSM_CHAOS_KMS_IDENTITIES", "KYTHIRA_HSM_CHAOS_KMS_VOTERS",
            "KYTHIRA_HSM_CHAOS_KMS_ROLES_1",    "KYTHIRA_HSM_CHAOS_KMS_ROLES_2",
            "KYTHIRA_HSM_CHAOS_KMS_ROLES_3"};
        for (const auto* v : k_vars) {
            ::unsetenv(v);
        }
        for (std::size_t i = 0; i < k_containers.size(); ++i) {
            ::unsetenv(std::format("KYTHIRA_HSM_CHAOS_KMS_FRONT_ENDS_{}", i + 1).c_str());
        }
        if (l != layout::kms_layers) {
            return;
        }
        _roles = {"", "", "", "data", "gateway", "front_end"};
        std::string peers;
        std::string identities;
        for (std::size_t i = 0; i < k_containers.size(); ++i) {
            peers += std::format("{}{}={}:7100", i == 0 ? "" : ",", i + 1, k_services.at(i));
            identities += (i == 0 ? "" : ",") + hsm::test::member_identity(i);
        }
        ::setenv("KYTHIRA_HSM_CHAOS_PEERS", peers.c_str(), 1);
        ::setenv("KYTHIRA_HSM_CHAOS_KMS_IDENTITIES", identities.c_str(), 1);
        // The catalog's founding voters stay members 1-3 whatever data nodes
        // the layout later lists.
        ::setenv("KYTHIRA_HSM_CHAOS_KMS_VOTERS", "1,2,3", 1);
        export_layout();
    }

    /// What a container created now reads (kms_process_cluster.hpp's
    /// rules): the catalog's data nodes, and on every node running a
    /// gateway or front end, the front ends (every node running one).
    void export_layout() const {
        const auto runs = [](const std::string& roles, std::string_view role) {
            return roles.empty() || roles.find(role) != std::string::npos;
        };
        std::string urls;
        std::string front_ends;
        for (std::size_t i = 0; i < _roles.size(); ++i) {
            const auto entry = std::format("{}={}", i + 1, kms_url_in_network(i));
            if (runs(_roles.at(i), "data")) {
                urls += (urls.empty() ? "" : ",") + entry;
            }
            if (runs(_roles.at(i), "front_end")) {
                front_ends += (front_ends.empty() ? "" : ",") + entry;
            }
        }
        ::setenv("KYTHIRA_HSM_CHAOS_KMS_URLS", urls.c_str(), 1);
        for (std::size_t i = 0; i < _roles.size(); ++i) {
            const auto var = std::format("KYTHIRA_HSM_CHAOS_KMS_FRONT_ENDS_{}", i + 1);
            const auto& r = _roles.at(i);
            if (runs(r, "front_end") || runs(r, "gateway")) {
                ::setenv(var.c_str(), front_ends.c_str(), 1);
            } else {
                ::unsetenv(var.c_str());
            }
        }
        for (std::size_t i = 0; i < 3; ++i) {
            ::setenv(std::format("KYTHIRA_HSM_CHAOS_KMS_ROLES_{}", i + 1).c_str(),
                     _roles.at(i).c_str(), 1);
        }
    }

    layout _layout = layout::stand_alone;
    std::vector<hsm::test::test_pki::files> _node_tls;
    std::array<std::string, 6> _roles{};
    std::array<std::uint16_t, 3> _api{};
    std::array<std::uint16_t, 3> _clients{};
    std::array<std::uint16_t, 3> _kms3{};
    std::array<std::uint16_t, 6> _kms{};
    std::array<std::uint16_t, 3> _ddb{};
    std::array<std::uint16_t, 3> _kinesis{};
    std::array<bool, 6> _up{};
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

// ---- the encrypted-services layout (KMS task 19) ---------------------------

namespace json = boost::json;
namespace sv4 = kythira::sigv4;

auto base64(std::string_view in) -> std::string {
    std::string out(4 * ((in.size() + 2) / 3), '\0');
    const auto n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(in.data()),
                                   static_cast<int>(in.size()));
    out.resize(static_cast<std::size_t>(n));
    return out;
}

auto unbase64(std::string_view in) -> std::string {
    std::string out(3 * (in.size() / 4), '\0');
    const auto n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                   reinterpret_cast<const unsigned char*>(in.data()),
                                   static_cast<int>(in.size()));
    if (n < 0) {
        return {};
    }
    out.resize(static_cast<std::size_t>(n));
    // EVP_DecodeBlock counts the '=' padding as zero bytes.
    for (auto it = in.rbegin(); it != in.rend() && *it == '='; ++it) {
        out.pop_back();
    }
    return out;
}

auto random_bytes(std::size_t n) -> std::string {
    std::string out(n, '\0');
    BOOST_REQUIRE(RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(n)) ==
                  1);
    return out;
}

struct aws_reply {
    int status = 0;
    json::object body;
};

/// One AWS JSON protocol (X-Amz-Target) service on the members' published
/// ports, signed with SigV4 under the static key, over TLS checked against
/// the scenario's CA (each member's certificate names localhost).
class aws_service {
public:
    aws_service(std::string service, std::string target_prefix, std::string content_type,
                std::string ca)
        : _service(std::move(service)),
          _prefix(std::move(target_prefix)),
          _content_type(std::move(content_type)),
          _ca(std::move(ca)) {}

    [[nodiscard]] auto call(std::uint16_t port, std::string_view op, const json::object& in) const
        -> std::optional<aws_reply> {
        const auto body = json::serialize(in);
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        const auto amz_date = std::format("{:%Y%m%dT%H%M%SZ}", now);
        const auto host = "localhost:" + std::to_string(port);
        const auto target = _prefix + "." + std::string(op);
        const sv4::credential_scope scope{amz_date.substr(0, 8), k_region, _service};
        const auto canonical = "POST\n/\n\ncontent-type:" + _content_type + "\nhost:" + host +
                               "\nx-amz-date:" + amz_date + "\nx-amz-target:" + target +
                               "\n\ncontent-type;host;x-amz-date;x-amz-target\n" +
                               sv4::detail::sha256_hex(body);
        const auto to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope.text() + "\n" +
                             sv4::detail::sha256_hex(canonical);
        const auto key = sv4::derive_signing_key(k_secret_key, scope);
        const auto sig = sv4::detail::to_hex(sv4::detail::hmac_sha256(key, to_sign));

        httplib::SSLClient cli("localhost", port);
        cli.set_ca_cert_path(_ca);
        cli.enable_server_certificate_verification(true);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(20, 0);
        cli.set_write_timeout(10, 0);
        const httplib::Headers headers{
            {"X-Amz-Date", amz_date},
            {"X-Amz-Target", target},
            {"Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(k_access_key) + "/" +
                                  scope.text() +
                                  ", SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
                                  "Signature=" +
                                  sig}};
        auto r = cli.Post("/", headers, body, _content_type);
        if (!r) {
            return std::nullopt;
        }
        aws_reply out;
        out.status = r->status;
        try {
            auto v = json::parse(r->body);
            if (v.is_object()) {
                out.body = std::move(v.as_object());
            }
        } catch (const std::exception&) {
            out.body["raw"] = r->body;
        }
        return out;
    }

private:
    std::string _service;
    std::string _prefix;
    std::string _content_type;
    std::string _ca;
};

/// The three services, each called on any running member, retried until
/// one answers 200 or `timeout` passes.
struct encrypted_services {
    container_cluster& cl;
    aws_service kms{"kms", "TrentService", "application/x-amz-json-1.1", cl.ca_path()};
    aws_service ddb{"dynamodb", "DynamoDB_20120810", "application/x-amz-json-1.0", cl.ca_path()};
    aws_service kinesis{"kinesis", "Kinesis_20131202", "application/x-amz-json-1.1", cl.ca_path()};

    using port_of = std::uint16_t (container_cluster::*)(std::size_t) const;

    [[nodiscard]] auto until_ok(const aws_service& svc, port_of port, std::string_view op,
                                const json::object& in, std::chrono::seconds timeout = 120s) const
        -> json::object {
        std::optional<aws_reply> last;
        const bool ok = hsm::test::eventually(
            [&] {
                for (std::size_t i = 0; i < cl.size(); ++i) {
                    if (!cl.running(i)) {
                        continue;
                    }
                    last = svc.call((cl.*port)(i), op, in);
                    if (last && last->status == 200) {
                        return true;
                    }
                }
                return false;
            },
            timeout);
        BOOST_REQUIRE_MESSAGE(
            ok, op << " never succeeded; last answer "
                   << (last ? std::to_string(last->status) + " " + json::serialize(last->body)
                            : std::string("none")));
        return last->body;
    }
};

auto str(const json::object& o, std::string_view k) -> std::string {
    const auto* v = o.if_contains(k);
    return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
}

/// Every file under `root`, read whole.
auto files_under(const fs::path& root) -> std::vector<std::pair<fs::path, std::string>> {
    std::vector<std::pair<fs::path, std::string>> out;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (!e.is_regular_file()) {
            continue;
        }
        std::ifstream in(e.path(), std::ios::binary);
        out.emplace_back(e.path(), std::string(std::istreambuf_iterator<char>(in), {}));
    }
    return out;
}

void run_encrypted_writes(container_cluster& cl) {
    // A TLS write to a member killed mid-request must fail the call, not
    // end the test with SIGPIPE.
    (void)std::signal(SIGPIPE, SIG_IGN);
    encrypted_services s{cl};
    auto kms_port = &container_cluster::kms_port;
    auto ddb_port = &container_cluster::ddb_port;
    auto kinesis_port = &container_cluster::kinesis_port;

    BOOST_TEST_CHECKPOINT("a KMS key on the HSM's token");
    const auto key =
        s.until_ok(s.kms, kms_port, "CreateKey",
                   {{"Description", "hsm chaos"}, {"KeyUsage", "ENCRYPT_DECRYPT"}}, 180s);
    const auto key_arn = str(key.at("KeyMetadata").as_object(), "Arn");
    BOOST_REQUIRE(!key_arn.empty());

    BOOST_TEST_CHECKPOINT("an encrypted table and an encrypted stream");
    (void)s.until_ok(
        s.ddb, ddb_port, "CreateTable",
        {{"TableName", "chaos"},
         {"AttributeDefinitions", json::array{{{"AttributeName", "pk"}, {"AttributeType", "S"}}}},
         {"KeySchema", json::array{{{"AttributeName", "pk"}, {"KeyType", "HASH"}}}},
         {"BillingMode", "PAY_PER_REQUEST"},
         {"SSESpecification",
          {{"Enabled", true}, {"SSEType", "KMS"}, {"KMSMasterKeyId", key_arn}}}});
    BOOST_REQUIRE(hsm::test::eventually(
        [&] {
            const auto d = s.until_ok(s.ddb, ddb_port, "DescribeTable", {{"TableName", "chaos"}});
            const auto& t = d.at("Table").as_object();
            const auto* sse = t.if_contains("SSEDescription");
            return str(t, "TableStatus") == "ACTIVE" && sse != nullptr &&
                   str(sse->as_object(), "Status") == "ENABLED";
        },
        120s));
    (void)s.until_ok(s.kinesis, kinesis_port, "CreateStream",
                     {{"StreamName", "chaos"}, {"ShardCount", 2}});
    const auto stream_status = [&] {
        const auto d =
            s.until_ok(s.kinesis, kinesis_port, "DescribeStreamSummary", {{"StreamName", "chaos"}});
        return d.at("StreamDescriptionSummary").as_object();
    };
    BOOST_REQUIRE(hsm::test::eventually(
        [&] { return str(stream_status(), "StreamStatus") == "ACTIVE"; }, 120s));
    (void)s.until_ok(s.kinesis, kinesis_port, "StartStreamEncryption",
                     {{"StreamName", "chaos"}, {"EncryptionType", "KMS"}, {"KeyId", key_arn}});
    BOOST_REQUIRE(hsm::test::eventually(
        [&] {
            const auto d = stream_status();
            return str(d, "StreamStatus") == "ACTIVE" && str(d, "EncryptionType") == "KMS";
        },
        120s));

    // Values carry a random tag so that a match on disk can only be this
    // run's write.
    const auto nonce = random_bytes(8);
    const auto tag = sv4::detail::to_hex(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size()));
    std::atomic<bool> stop{false};
    std::mutex mu;
    const auto item_value = [&](const std::string& k) { return "hsm-chaos-item-" + tag + "-" + k; };
    std::set<std::string> items;       // acknowledged PutItem keys
    std::set<std::string> records;     // acknowledged PutRecord data
    std::vector<std::string> secrets;  // data keys and encrypted plaintexts
    std::atomic<unsigned> uncertain{0};

    const auto writer = [&](auto&& one) {
        return std::thread([&, one] {
            for (unsigned n = 0; !stop.load(); ++n) {
                bool done = false;
                for (std::size_t i = 0; i < cl.size() && !done; ++i) {
                    const auto m = (n + i) % cl.size();
                    if (cl.running(m)) {
                        done = one(m, n);
                    }
                }
                if (!done) {
                    uncertain.fetch_add(1);
                    std::this_thread::sleep_for(100ms);
                }
            }
        });
    };
    std::vector<std::thread> writers;
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        // Keys stay in the clear (the engine orders by them; doc/kms.md),
        // so only the value carries the searched-for prefix.
        const auto k = std::format("item-{:06}", n);
        const auto r = s.ddb.call(cl.ddb_port(m), "PutItem",
                                  {{"TableName", "chaos"},
                                   {"Item", {{"pk", {{"S", k}}}, {"v", {{"S", item_value(k)}}}}}});
        if (r && r->status == 200) {
            const std::lock_guard lock(mu);
            items.insert(k);
            return true;
        }
        return false;
    }));
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        const auto v = std::format("hsm-chaos-record-{}-{:06}", tag, n);
        const auto r = s.kinesis.call(
            cl.kinesis_port(m), "PutRecord",
            {{"StreamName", "chaos"}, {"Data", base64(v)}, {"PartitionKey", std::to_string(n)}});
        if (r && r->status == 200) {
            const std::lock_guard lock(mu);
            records.insert(v);
            return true;
        }
        return false;
    }));
    writers.push_back(writer([&](std::size_t m, unsigned n) {
        std::optional<aws_reply> r;
        std::string secret;
        if (n % 2 == 0) {
            r = s.kms.call(cl.kms_port(m), "GenerateDataKey",
                           {{"KeyId", key_arn}, {"KeySpec", "AES_256"}});
            if (r && r->status == 200) {
                secret = unbase64(str(r->body, "Plaintext"));
            }
        } else {
            secret = random_bytes(32);
            r = s.kms.call(cl.kms_port(m), "Encrypt",
                           {{"KeyId", key_arn}, {"Plaintext", base64(secret)}});
        }
        if (r && r->status == 200 && secret.size() == 32) {
            const std::lock_guard lock(mu);
            secrets.push_back(secret);
            return true;
        }
        return false;
    }));

    std::this_thread::sleep_for(3s);
    const auto killed = cl.leader();
    BOOST_REQUIRE(killed.has_value());
    BOOST_TEST_CHECKPOINT("kill the HSM catalog leader under encrypted writes");
    cl.kill(*killed);
    std::this_thread::sleep_for(4s);
    cl.start(*killed);
    BOOST_REQUIRE(hsm::test::eventually([&] { return cl.status(*killed).has_value(); }, 90s));
    BOOST_REQUIRE(cl.unseal(*killed, cl.current));
    std::this_thread::sleep_for(4s);
    const auto cut = (*killed + 1) % cl.size();
    BOOST_TEST_CHECKPOINT("cut a member off under encrypted writes");
    cl.isolate(cut);
    std::this_thread::sleep_for(6s);
    cl.rejoin(cut);
    std::this_thread::sleep_for(4s);
    stop.store(true);
    for (auto& t : writers) {
        t.join();
    }
    BOOST_TEST_MESSAGE(items.size() << " items, " << records.size() << " records, "
                                    << secrets.size() << " data keys and plaintexts acknowledged, "
                                    << uncertain.load() << " uncertain");
    BOOST_TEST(items.size() >= 20U, "DynamoDB wrote around the faults");
    BOOST_TEST(records.size() >= 20U, "Kinesis wrote around the faults");
    BOOST_TEST(secrets.size() >= 20U, "the KMS answered around the faults");

    BOOST_TEST_CHECKPOINT("every acknowledged item reads back");
    std::size_t missing_items = 0;
    for (const auto& k : items) {
        const auto r = s.until_ok(
            s.ddb, ddb_port, "GetItem",
            {{"TableName", "chaos"}, {"Key", {{"pk", {{"S", k}}}}}, {"ConsistentRead", true}});
        const auto* item = r.if_contains("Item");
        if (item == nullptr || str(item->as_object().at("v").as_object(), "S") != item_value(k)) {
            ++missing_items;
            BOOST_TEST_MESSAGE("lost item " << k);
        }
    }
    BOOST_TEST(missing_items == 0U);

    BOOST_TEST_CHECKPOINT("every acknowledged record reads back");
    std::set<std::string> read;
    const auto shards =
        s.until_ok(s.kinesis, kinesis_port, "ListShards", {{"StreamName", "chaos"}});
    for (const auto& sh : shards.at("Shards").as_array()) {
        auto it = str(s.until_ok(s.kinesis, kinesis_port, "GetShardIterator",
                                 {{"StreamName", "chaos"},
                                  {"ShardId", str(sh.as_object(), "ShardId")},
                                  {"ShardIteratorType", "TRIM_HORIZON"}}),
                      "ShardIterator");
        for (unsigned empty = 0; !it.empty() && empty < 3;) {
            const auto g = s.until_ok(s.kinesis, kinesis_port, "GetRecords",
                                      {{"ShardIterator", it}, {"Limit", 1000}});
            const auto& recs = g.at("Records").as_array();
            empty = recs.empty() ? empty + 1 : 0;
            for (const auto& rec : recs) {
                BOOST_TEST(str(rec.as_object(), "EncryptionType") == "KMS");
                read.insert(unbase64(str(rec.as_object(), "Data")));
            }
            it = str(g, "NextShardIterator");
        }
    }
    std::size_t missing_records = 0;
    for (const auto& v : records) {
        if (!read.contains(v)) {
            ++missing_records;
            BOOST_TEST_MESSAGE("lost record " << v);
        }
    }
    BOOST_TEST(missing_records == 0U);

    BOOST_TEST_CHECKPOINT("no key material or value on disk");
    const auto scan =
        fs::temp_directory_path() / ("kythira-hsm-chaos-scan-" + std::to_string(::getpid()));
    fs::remove_all(scan);
    fs::create_directories(scan);
    cl.stop_and_copy_data(scan);
    const auto files = files_under(scan);
    BOOST_TEST_MESSAGE("scanning " << files.size() << " files");
    BOOST_TEST(!files.empty());
    std::size_t leaked_secrets = 0;
    std::size_t leaked_values = 0;
    std::vector<std::string> needles;
    for (const std::string prefix : {"hsm-chaos-item-", "hsm-chaos-record-"}) {
        const auto value = prefix + tag;
        needles.push_back(value);
        needles.push_back(base64(value.substr(0, value.size() / 3 * 3)));
    }
    for (const auto& [path, bytes] : files) {
        for (const auto& secret : secrets) {
            if (bytes.find(secret) != std::string::npos) {
                ++leaked_secrets;
                BOOST_TEST_MESSAGE("a data key or plaintext is in " << path);
                break;
            }
        }
        // Every value written starts with this run's prefix; a JSON
        // encoding carries it in base64, whose first 44 characters encode
        // the first 33 bytes whatever follows.
        for (const auto& needle : needles) {
            if (bytes.find(needle) == std::string::npos) {
                continue;
            }
            ++leaked_values;
            BOOST_TEST_MESSAGE("a written value is in " << path);
            break;
        }
    }
    BOOST_TEST(leaked_secrets == 0U);
    BOOST_TEST(leaked_values == 0U);
    fs::remove_all(scan);
}

// ---- the KMS-layers layout (KMS independent layers, task 6) ----------------

/// Calls node `via`'s KMS until it answers 200 (or, with `want_type`, an
/// error of that type), across the faults the scenario injects; fails the
/// test after `timeout`.
auto kms_until(const container_cluster& cl, const aws_service& kms, std::size_t via,
               std::string_view op, const json::object& in, std::string_view step,
               std::string_view want_type = {}, std::chrono::seconds timeout = 120s)
    -> json::object {
    std::optional<aws_reply> last;
    const bool ok = hsm::test::eventually(
        [&] {
            last = kms.call(cl.kms_port(via), op, in);
            if (!last) {
                return false;
            }
            if (want_type.empty()) {
                return last->status == 200;
            }
            return str(last->body, "__type") == want_type;
        },
        timeout);
    BOOST_REQUIRE_MESSAGE(
        ok, step << ": " << op << " through node " << via + 1
                 << " never answered as expected; last "
                 << (last ? std::to_string(last->status) + " " + json::serialize(last->body)
                          : std::string("none")));
    return last->body;
}

/// Requirement 10.3's workload (kms_node_migration_test.cpp's, over the
/// published ports): keys with a committed description change and a
/// ciphertext each, and one key disabled before any step.
class layers_workload {
public:
    layers_workload(container_cluster& cl, const aws_service& kms) : _cl(cl), _kms(kms) {}

    void add(std::size_t via, const std::string& label) {
        const auto k = kms_until(_cl, _kms, via, "CreateKey", {{"Description", label}}, label);
        entry e;
        e.id = str(k.at("KeyMetadata").as_object(), "KeyId");
        e.ciphertext = str(kms_until(_cl, _kms, via, "Encrypt",
                                     {{"KeyId", e.id}, {"Plaintext", "bWlncmF0aW9u"}}, label),
                           "CiphertextBlob");
        e.description = label + " (updated)";
        (void)kms_until(_cl, _kms, via, "UpdateKeyDescription",
                        {{"KeyId", e.id}, {"Description", e.description}}, label);
        _keys.push_back(std::move(e));
        if (_disabled.empty()) {
            const auto d =
                kms_until(_cl, _kms, via, "CreateKey", {{"Description", "disabled"}}, label);
            _disabled = str(d.at("KeyMetadata").as_object(), "KeyId");
            (void)kms_until(_cl, _kms, via, "DisableKey", {{"KeyId", _disabled}}, label);
        }
    }

    void check(std::size_t via, const std::string& step) {
        BOOST_TEST_CONTEXT("after " << step << ", through node " << via + 1) {
            for (const auto& e : _keys) {
                const auto d = kms_until(_cl, _kms, via, "DescribeKey", {{"KeyId", e.id}}, step);
                BOOST_TEST(str(d.at("KeyMetadata").as_object(), "Description") == e.description);
                const auto p =
                    kms_until(_cl, _kms, via, "Decrypt", {{"CiphertextBlob", e.ciphertext}}, step);
                BOOST_TEST(str(p, "Plaintext") == "bWlncmF0aW9u");
            }
            if (!_disabled.empty()) {
                (void)kms_until(_cl, _kms, via, "Encrypt",
                                {{"KeyId", _disabled}, {"Plaintext", "eA=="}}, step,
                                "DisabledException");
            }
        }
    }

private:
    struct entry {
        std::string id;
        std::string description;
        std::string ciphertext;
    };

    container_cluster& _cl;
    const aws_service& _kms;
    std::vector<entry> _keys;
    std::string _disabled;
};

/// The catalog's membership as data node `via` reports it.
auto membership_of(const container_cluster& cl, std::size_t via) -> std::optional<json::object> {
    const auto r = cl.as_node(via, via, "GET", "/v1/kms/membership/evacuate");
    if (!r || r->first != 200) {
        return std::nullopt;
    }
    try {
        auto v = json::parse(r->second);
        if (v.is_object()) {
            return std::move(v.as_object());
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

/// The voter ids (1-based) in a membership status.
auto voters_in(const json::object& st) -> std::set<std::string> {
    std::set<std::string> out;
    if (const auto* v = st.if_contains("voters"); v != nullptr && v->is_array()) {
        for (const auto& id : v->as_array()) {
            out.insert(id.is_string() ? std::string(id.as_string())
                                      : std::to_string(id.to_number<std::uint64_t>()));
        }
    }
    return out;
}

/// Moves node `evacuee`'s (0-based) catalog seat onto `target`, asking data
/// node `via`, and waits until the catalog's leader among `data_nodes`
/// reports the job done.
void move_seat(const container_cluster& cl, std::size_t via, std::size_t evacuee,
               std::size_t target, const std::vector<std::size_t>& data_nodes) {
    const auto body =
        std::format(R"({{"node":"{}","targets":["{}"],"replicas":3}})", evacuee + 1, target + 1);
    std::optional<std::pair<int, std::string>> r;
    BOOST_REQUIRE_MESSAGE(
        hsm::test::eventually(
            [&] {
                r = cl.as_node(via, via, "POST", "/v1/kms/membership/evacuate", body);
                return r && r->first == 200;
            },
            120s),
        "evacuate " << evacuee + 1 << ": " << (r ? r->second : std::string("no answer")));
    BOOST_REQUIRE_MESSAGE(hsm::test::eventually(
                              [&] {
                                  for (const auto i : data_nodes) {
                                      if (!cl.running(i)) {
                                          continue;
                                      }
                                      const auto st = membership_of(cl, i);
                                      if (!st) {
                                          continue;
                                      }
                                      const auto* job = st->if_contains("job");
                                      const bool ours = job != nullptr && job->is_object() &&
                                                        str(job->as_object(), "node") ==
                                                            std::to_string(evacuee + 1);
                                      const auto* leader = st->if_contains("leader");
                                      const auto* done = st->if_contains("done");
                                      if (ours && leader != nullptr && leader->as_bool() &&
                                          done != nullptr && done->as_bool()) {
                                          return true;
                                      }
                                  }
                                  return false;
                              },
                              180s),
                          "node " << evacuee + 1 << " still holds a catalog seat");
}

/// Releases node i's replica (it must not lead the catalog); retried while
/// leadership settles away from it.
void release(const container_cluster& cl, std::size_t i) {
    std::optional<std::pair<int, std::string>> r;
    BOOST_REQUIRE_MESSAGE(hsm::test::eventually(
                              [&] {
                                  r = cl.as_node(i, i, "POST", "/v1/kms/membership/release");
                                  return r && r->first == 200;
                              },
                              60s),
                          "release " << i + 1 << ": " << (r ? r->second : std::string("none")));
}

/// How many Encrypt and Decrypt calls node i's front end answered without
/// an error, by its audit records (CloudTrail-shaped lines on stderr).
auto crypto_served(const container_cluster& cl, std::size_t i) -> std::size_t {
    std::size_t n = 0;
    std::istringstream lines(cl.logs_of(i));
    for (std::string line; std::getline(lines, line);) {
        const bool crypto = line.find(R"("eventName":"Encrypt")") != std::string::npos ||
                            line.find(R"("eventName":"Decrypt")") != std::string::npos;
        if (crypto && line.find(R"("errorCode")") == std::string::npos) {
            ++n;
        }
    }
    return n;
}

/// Encryption the whole time the layout moves: Encrypt through every node
/// running a gateway in turn, keeping what was acknowledged, so that at the
/// end every acknowledged ciphertext must decrypt.
class background_traffic {
public:
    background_traffic(container_cluster& cl, const aws_service& kms, std::string key)
        : _cl(cl), _kms(kms), _key(std::move(key)) {
        _thread = std::thread([this] { run(); });
    }

    background_traffic(const background_traffic&) = delete;
    auto operator=(const background_traffic&) -> background_traffic& = delete;
    background_traffic(background_traffic&&) = delete;
    auto operator=(background_traffic&&) -> background_traffic& = delete;

    ~background_traffic() { stop(); }

    void stop() {
        _stop.store(true);
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /// Plaintext and ciphertext of every acknowledged Encrypt.
    [[nodiscard]] auto acknowledged() const
        -> const std::vector<std::pair<std::string, std::string>>& {
        return _acked;
    }
    [[nodiscard]] auto failures() const -> unsigned { return _failures; }

private:
    void run() {
        // Members 1-3 and node 5 run a gateway at every step but their own
        // restarts.
        constexpr std::array<std::size_t, 4> k_gateways{0, 1, 2, 4};
        for (unsigned n = 0; !_stop.load(); ++n) {
            const auto via = k_gateways.at(n % k_gateways.size());
            if (!_cl.running(via)) {
                std::this_thread::sleep_for(50ms);
                continue;
            }
            const auto plain = base64(std::format("layers-{:06}", n));
            const auto r =
                _kms.call(_cl.kms_port(via), "Encrypt", {{"KeyId", _key}, {"Plaintext", plain}});
            if (r && r->status == 200) {
                _acked.emplace_back(plain, str(r->body, "CiphertextBlob"));
            } else {
                ++_failures;
                std::this_thread::sleep_for(100ms);
            }
        }
    }

    container_cluster& _cl;
    const aws_service& _kms;
    std::string _key;
    std::atomic<bool> _stop{false};
    std::vector<std::pair<std::string, std::string>> _acked;
    unsigned _failures = 0;
    std::thread _thread;
};

// Requirement 11.3: the whole co-located to split path and back, as
// kms_node_migration_test's the_full_path_stops_midway_and_reverses walks
// it, with the HSM behind the KMS and faults in both:
//
//   * the new layers join: node 4 a catalog data node, 5 a gateway alone,
//     6 a front end alone on the HSM's PKCS#11 library; the HSM's token
//     leader is then SIGKILLed while the remote front end serves;
//   * member 1 hands its catalog seat to node 4 (learner, promote,
//     leadership transfer, remove), is released and recreated as a
//     gateway and front end over the data nodes;
//   * midway, the data node is cut off the network (members 2 and 3 keep
//     a quorum) and the lone front end is SIGKILLed (the gateway fails over
//     to the members' front ends);
//   * reversed: member 1 runs every layer again and takes its seat back,
//     node 4 is released and stopped, and the gateway and front end stop.
//
// After every step the workload checks Requirement 10.3, and an Encrypt
// stream runs throughout; every ciphertext it was handed must decrypt.
void run_kms_layers(container_cluster& cl) {
    (void)std::signal(SIGPIPE, SIG_IGN);
    const aws_service kms{"kms", "TrentService", "application/x-amz-json-1.1", cl.ca_path()};
    layers_workload w(cl, kms);

    BOOST_TEST_CHECKPOINT("the co-located KMS serves");
    w.add(0, "before any step");
    const auto stream_key =
        str(kms_until(cl, kms, 1, "CreateKey", {{"Description", "background"}}, "background key")
                .at("KeyMetadata")
                .as_object(),
            "KeyId");
    background_traffic traffic(cl, kms, stream_key);

    BOOST_TEST_CHECKPOINT("the new layers join");
    cl.start_kms_nodes({3, 4, 5});
    BOOST_REQUIRE_MESSAGE(
        hsm::test::eventually([&] { return membership_of(cl, 3).has_value(); }, 180s),
        "data node 4 never served its membership routes");
    (void)kms_until(cl, kms, 4, "ListKeys", {}, "the gateway joined", {}, 180s);
    w.add(4, "through the lone gateway");
    w.check(1, "the new layers joined");
    // The lone front end serves through the library (the gateway hands
    // calls round robin over the live front ends).
    BOOST_TEST(cl.logs_of(5).find("pkcs11=/usr/local/lib/libkythira_pkcs11.so") !=
               std::string::npos);
    BOOST_REQUIRE_MESSAGE(hsm::test::eventually([&] { return crypto_served(cl, 5) > 0; }, 60s),
                          "front end 6 never answered an Encrypt or Decrypt:\n"
                              << container_cluster::log_digest(cl.logs_of(5)));

    BOOST_TEST_CHECKPOINT("kill the HSM token leader under the remote front end");
    const auto token_leader = cl.leader(hsm::test::k_cluster_token);
    BOOST_REQUIRE(token_leader.has_value());
    cl.kill(*token_leader);
    // The gateway's front ends: the members still running, and node 6,
    // whose PKCS#11 library fails over to another member's listener.
    w.check(4, "the HSM token leader was killed");
    // ... and keeps serving with that member down.
    const auto served = crypto_served(cl, 5);
    BOOST_REQUIRE_MESSAGE(
        hsm::test::eventually([&] { return crypto_served(cl, 5) > served; }, 60s),
        "front end 6 stopped serving with HSM member " << *token_leader + 1 << " down");
    cl.start(*token_leader);
    BOOST_REQUIRE(hsm::test::eventually([&] { return cl.status(*token_leader).has_value(); }, 90s));
    BOOST_REQUIRE(cl.unseal(*token_leader, cl.current, 120s));

    BOOST_TEST_CHECKPOINT("member 1 hands its catalog seat to node 4");
    const std::vector<std::size_t> all_data{0, 1, 2, 3};
    move_seat(cl, 3, 0, 3, all_data);
    release(cl, 0);
    cl.recreate_member(0, "gateway,front_end");
    w.add(0, "midway");
    w.check(4, "midway");

    BOOST_TEST_CHECKPOINT("cut the data node off midway");
    cl.isolate(3);
    w.add(1, "the data node cut off");
    w.check(0, "the data node cut off");
    cl.rejoin(3);

    BOOST_TEST_CHECKPOINT("kill the lone front end midway");
    cl.kill(5);
    w.check(4, "the lone front end was killed");
    cl.start(5);
    w.check(4, "the lone front end started again");

    BOOST_TEST_CHECKPOINT("reverse: member 1 takes its seat back");
    cl.recreate_member(0, "");
    move_seat(cl, 3, 3, 0, all_data);
    release(cl, 3);
    cl.stop_node(3);
    w.check(0, "member 1 took its seat back");
    cl.stop_node(4);
    cl.stop_node(5);
    w.add(1, "co-located again");
    for (std::size_t m = 0; m < 3; ++m) {
        w.check(m, "the reversal");
        std::optional<json::object> st;
        BOOST_REQUIRE(hsm::test::eventually(
            [&] {
                st = membership_of(cl, m);
                return st && voters_in(*st) == std::set<std::string>{"1", "2", "3"};
            },
            60s));
    }

    BOOST_TEST_CHECKPOINT("every acknowledged ciphertext decrypts");
    traffic.stop();
    BOOST_TEST_MESSAGE(traffic.acknowledged().size()
                       << " Encrypts acknowledged, " << traffic.failures() << " failed");
    BOOST_TEST(traffic.acknowledged().size() >= 20U, "the KMS encrypted around the moves");
    std::size_t wrong = 0;
    for (std::size_t n = 0; n < traffic.acknowledged().size(); ++n) {
        const auto& [plain, blob] = traffic.acknowledged()[n];
        const auto p = kms_until(cl, kms, n % 3, "Decrypt", {{"CiphertextBlob", blob}},
                                 "the stream's ciphertexts");
        if (str(p, "Plaintext") != plain) {
            ++wrong;
        }
    }
    BOOST_TEST(wrong == 0U);
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

BOOST_AUTO_TEST_CASE(encrypted_services_in_kythira_node,
                     *boost::unit_test::precondition(has_modules({"kms", "dynamodb", "kinesis"}))) {
    container_cluster cl(layout::encrypted_services);
    run_encrypted_writes(cl);
}

BOOST_AUTO_TEST_CASE(kms_layers_move_in_kythira_node,
                     *boost::unit_test::precondition(has_modules({"kms"}))) {
    container_cluster cl(layout::kms_layers);
    run_kms_layers(cl);
}
