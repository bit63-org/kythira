// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The composite cluster in containers (.kiro/specs/service-colocation/
// task 10, Requirements 9.2 and 10.3). docker/kythira-node-compose.yml
// starts three kythira_node containers, kn-1..kn-3, each with the DynamoDB,
// Kinesis and IAM modules on one Raft listener, addressed by service name
// only. Under whichever runtime the harness selects (Docker or rootless
// Podman) the case shows that:
//
//   * IAM's group elects a leader and an account made with `kythira-iam`
//     reaches every node;
//   * a user and key IAM issues are accepted by DynamoDB and Kinesis at
//     once, through each node's in-process evaluator;
//   * a mixed workload (docker/kythira_node_clients/mixed_workload.py) of
//     PutItem, PutRecord and CreateUser keeps being served while the IAM
//     leader's node is killed and restarted and then another node is cut
//     off the network and reconnected, and every write any node
//     acknowledged is there afterwards, read back through the nodes;
//   * the killed and the partitioned node both rejoin IAM's group.
//
// Each node's own /healthz (`kythira-iam health`, never redirected) is the
// IAM probe; the workload is the probe for the other two.

#define BOOST_TEST_MODULE kythira_node_scenario_test
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include "os_faults.hpp"

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <future>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
namespace os = docker_chaos::os;

namespace {

constexpr const char* k_network = "kythira_node_scenario_net";
constexpr const char* k_nodes = "kn-1,kn-2,kn-3";

std::string compose_file() {
    const char* env = std::getenv("KYTHIRA_NODE_COMPOSE_FILE");
    if ((env != nullptr) && (*env != 0)) {
        return env;
    }
    return "docker/kythira-node-compose.yml";
}

std::vector<std::string> compose_cmd(std::initializer_list<std::string> args) {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file()});
    cmd.insert(cmd.end(), args);
    return cmd;
}

std::string service(int n) {
    return "kn-" + std::to_string(n);
}

std::string container(int n) {
    return "kythira-node-kn-" + std::to_string(n);
}

/// `kythira-iam` run inside `on`, talking to `target`'s IAM API.
os::CmdResult iam_cli(int on, int target, std::initializer_list<std::string> args,
                      int wait_secs = 30) {
    auto cmd = compose_cmd({"exec", "-T", service(on), "kythira-iam", "--endpoint",
                            "https://" + service(target) + ":8443", "--wait-secs",
                            std::to_string(wait_secs)});
    cmd.insert(cmd.end(), args);
    return os::real_exec(cmd);
}

/// The workload, in a fresh `workload` container, with `env` set.
os::CmdResult workload(const std::vector<std::string>& env, const std::vector<std::string>& args) {
    auto cmd = compose_cmd({"--profile", "clients", "run", "--rm", "-T"});
    for (const auto& e : env) {
        cmd.insert(cmd.end(), {"-e", e});
    }
    cmd.emplace_back("workload");
    cmd.insert(cmd.end(), args.begin(), args.end());
    return os::real_exec(cmd);
}

/// The last JSON object `out` prints, or an empty one.
boost::json::object last_json(const std::string& out) {
    const auto brace = out.rfind("\n{");
    const auto start = brace == std::string::npos ? out.find('{') : brace + 1;
    if (start == std::string::npos) {
        return {};
    }
    const auto end = out.find('\n', start);
    const auto len = end == std::string::npos ? std::string::npos : end - start;
    boost::system::error_code ec;
    auto v = boost::json::parse(out.substr(start, len), ec);
    return (!ec && v.is_object()) ? v.as_object() : boost::json::object{};
}

std::string text_of(const boost::json::object& o, const char* key) {
    const auto* v = o.if_contains(key);
    return (v != nullptr && v->is_string()) ? std::string(v->as_string()) : std::string{};
}

std::int64_t int_of(const boost::json::object& o, const char* key) {
    const auto* v = o.if_contains(key);
    return (v != nullptr && v->is_int64()) ? v->as_int64() : -1;
}

/// The value after `name = ` in an INI file's text.
std::string ini_value(const std::string& ini, const std::string& name) {
    const auto at = ini.find(name + " = ");
    if (at == std::string::npos) {
        return {};
    }
    const auto start = at + name.size() + 3;
    const auto end = ini.find_first_of("\r\n", start);
    return ini.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

/// Node `n`'s own IAM /healthz, or nullopt if it cannot be read.
std::optional<boost::json::object> health(int n) {
    auto r = iam_cli(n, n, {"health"}, 5);
    if (r.code != 0) {
        return std::nullopt;
    }
    const auto brace = r.out.find('{');
    if (brace == std::string::npos) {
        return std::nullopt;
    }
    boost::system::error_code ec;
    auto v = boost::json::parse(r.out.substr(brace), ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    return v.as_object();
}

bool eventually(const std::function<bool()>& pred, std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(1s);
    }
    return pred();
}

/// The node IAM's group on all of `among` agrees leads, or 0.
int agreed_leader(std::initializer_list<int> among) {
    int leader = 0;
    for (int n : among) {
        auto h = health(n);
        if (!h) {
            return 0;
        }
        const int l = std::atoi(text_of(*h, "leader").c_str());
        if (l < 1 || l > 3 || (leader != 0 && l != leader)) {
            return 0;
        }
        leader = l;
    }
    return leader;
}

bool accounts_on(int n, std::int64_t want) {
    auto h = health(n);
    return h && int_of(*h, "accounts") == want;
}

void dump_logs() {
    auto r = os::real_exec(compose_cmd({"logs", "--no-color", "--tail", "200"}));
    std::cerr << "---- compose logs ----\n" << r.out << "\n----------------------\n";
}

struct stack_fixture {
    stack_fixture() {
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        try {
            os::checked_exec(os::real_exec, compose_cmd({"up", "-d"}));
        } catch (...) {
            dump_logs();
            throw;
        }
    }
    ~stack_fixture() {
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
    }
    stack_fixture(const stack_fixture&) = delete;
    stack_fixture& operator=(const stack_fixture&) = delete;
};

struct logs_on_failure {
    logs_on_failure() = default;
    ~logs_on_failure() {
        const auto& results = boost::unit_test::results_collector.results(
            boost::unit_test::framework::current_test_case().p_id);
        if (!results.passed() || std::getenv("KYTHIRA_NODE_KEEP_LOGS") != nullptr) {
            dump_logs();
        }
    }
    logs_on_failure(const logs_on_failure&) = delete;
    logs_on_failure& operator=(const logs_on_failure&) = delete;
};

}  // namespace

BOOST_TEST_GLOBAL_FIXTURE(stack_fixture);

// One case on purpose: each step builds on the state the last one left.
BOOST_AUTO_TEST_CASE(mixed_workload_through_a_kill_and_a_partition) {
    const logs_on_failure logs;

    // 1. IAM's group elects a leader on the shared listener.
    int leader = 0;
    BOOST_REQUIRE_MESSAGE(eventually(
                              [&] {
                                  leader = agreed_leader({1, 2, 3});
                                  return leader != 0;
                              },
                              180s),
                          "the three nodes never agreed on an IAM leader");
    BOOST_TEST_MESSAGE("IAM leader is " << service(leader));

    // 2. An account, through any node (the CLI follows the redirect).
    auto created = iam_cli(1, 1,
                           {"create-account", "--alias", "colocation", "--account-id",
                            "111122223333", "--root-key-file", "/tmp/root.ini"});
    BOOST_REQUIRE_MESSAGE(created.code == 0, "create-account failed:\n" << created.out);
    const auto ini =
        os::real_exec(compose_cmd({"exec", "-T", service(1), "cat", "/tmp/root.ini"})).out;
    const auto root_id = ini_value(ini, "aws_access_key_id");
    const auto root_secret = ini_value(ini, "aws_secret_access_key");
    BOOST_REQUIRE_MESSAGE(!root_id.empty() && !root_secret.empty(), "root key file: " << ini);
    for (int n : {1, 2, 3}) {
        BOOST_TEST(eventually([&] { return accounts_on(n, 1); }, 60s),
                   service(n) << " never applied the account");
    }

    // 3. A user and key, a table and a stream: the key IAM issued is good
    //    on DynamoDB and Kinesis through the in-process evaluator.
    auto setup = workload({"ROOT_KEY_ID=" + root_id, "ROOT_SECRET=" + root_secret},
                          {"setup", "--nodes", k_nodes});
    BOOST_REQUIRE_MESSAGE(setup.code == 0, "workload setup failed:\n" << setup.out);
    const auto key = last_json(setup.out);
    const std::vector<std::string> app{"APP_KEY_ID=" + text_of(key, "key_id"),
                                       "APP_SECRET=" + text_of(key, "secret")};
    BOOST_REQUIRE_MESSAGE(!text_of(key, "key_id").empty(), "no key in:\n" << setup.out);

    // 4. With every node up.
    auto calm = workload(app, {"run", "--nodes", k_nodes, "--seconds", "15", "--tag", "calm"});
    BOOST_REQUIRE_MESSAGE(calm.code == 0, "calm workload failed:\n" << calm.out);
    BOOST_TEST_MESSAGE("calm: " << boost::json::serialize(last_json(calm.out)));

    // 5. The same workload through a kill of IAM's leader's node, its
    //    restart, then a partition of another node and its return.
    auto chaos = std::async(std::launch::async, [&] {
        return workload(app, {"run", "--nodes", k_nodes, "--seconds", "100", "--tag", "chaos"});
    });
    std::this_thread::sleep_for(10s);
    const int killed = leader;
    BOOST_TEST_MESSAGE("SIGKILL " << container(killed));
    BOOST_TEST(os::real_exec(os::docker_kill_cmd(container(killed))).code == 0);
    std::this_thread::sleep_for(20s);
    BOOST_TEST(os::real_exec(os::docker_start_cmd(container(killed))).code == 0);
    std::this_thread::sleep_for(15s);
    const int cut = killed % 3 + 1;
    BOOST_TEST_MESSAGE("partition " << container(cut));
    BOOST_TEST(os::real_exec(os::network_disconnect_cmd(k_network, container(cut))).code == 0);
    std::this_thread::sleep_for(25s);
    BOOST_TEST(
        os::real_exec(os::network_connect_cmd(k_network, container(cut), service(cut))).code == 0);
    auto ran = chaos.get();
    BOOST_REQUIRE_MESSAGE(ran.code == 0, "chaos workload failed:\n" << ran.out);
    BOOST_TEST_MESSAGE("chaos: " << boost::json::serialize(last_json(ran.out)));

    // 6. Both nodes back in IAM's group, with the users the workload made.
    BOOST_TEST(eventually([&] { return agreed_leader({1, 2, 3}) != 0; }, 120s),
               "IAM's group never agreed on a leader again");

    // 7. Every acknowledged write is there, before and during the faults.
    for (const auto* tag : {"calm", "chaos"}) {
        auto v = workload(app, {"verify", "--nodes", k_nodes, "--tag", tag});
        BOOST_TEST(v.code == 0, tag << " verify failed:\n" << v.out);
        BOOST_TEST_MESSAGE(tag << " verify: " << boost::json::serialize(last_json(v.out)));
    }
}
