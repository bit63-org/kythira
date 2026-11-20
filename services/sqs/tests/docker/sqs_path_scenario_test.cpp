// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The migration path in containers (.kiro/specs/sqs-compatible-queues/
// task 11, Requirements 12.1-12.3). services/sqs/tests/docker/compose.yml
// starts three co-located sqs_node containers, addressed by service name
// only. Under whichever runtime the harness selects (Docker or rootless
// Podman), with a standard and a FIFO producer and consumer running
// throughout (sqs_path_load.py) and one message held by its receipt handle
// from start to end, the case walks doc/migration.md's whole path:
//
//   * co-located to split: three data nodes join and the co-located nodes'
//     replicas are evacuated to them, two front ends and two gateways start,
//     and the co-located nodes stop, leaving clients on the gateways;
//   * split to co-located: three new co-located nodes join, the data
//     nodes' replicas are evacuated to them, and the split layers stop;
//
// killing one node of every layer on the way with SIGKILL: a data node
// between evacuations, a front end and a gateway while clients go through
// them, and on the way back a new co-located node. Each comes back and the
// path carries on. At the end every acknowledged message has been
// received, each FIFO group in order, and the held receipt handle still
// deletes its message.

#define BOOST_TEST_MODULE sqs_path_scenario_test
#include <boost/test/results_collector.hpp>
#include <boost/test/unit_test.hpp>

#include "os_faults.hpp"

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
namespace os = docker_chaos::os;

namespace {

constexpr const char* k_load = "kythira-sqs-scenario-load";

std::string compose_file() {
    const char* env = std::getenv("KYTHIRA_SQS_COMPOSE_FILE");
    if ((env != nullptr) && (*env != 0)) {
        return env;
    }
    return "services/sqs/tests/docker/compose.yml";
}

std::vector<std::string> compose_cmd(std::initializer_list<std::string> args) {
    auto cmd = os::compose_prefix();
    cmd.insert(cmd.end(), {"-f", compose_file(), "--profile", "split", "--profile", "back",
                           "--profile", "clients"});
    cmd.insert(cmd.end(), args);
    return cmd;
}

std::string service(int n) {
    return "sqs-" + std::to_string(n);
}

std::string url(const std::string& svc) {
    return "http://" + svc + ":9324";
}

std::string url(int n) {
    return url(service(n));
}

std::string run_checked(const std::vector<std::string>& cmd) {
    return os::checked_exec(os::real_exec, cmd);
}

/// A one-off command in the clients image.
os::CmdResult client(std::initializer_list<std::string> args) {
    auto cmd = compose_cmd({"run", "--rm", "-T", "clients"});
    cmd.insert(cmd.end(), args);
    return os::real_exec(cmd);
}

void up(std::initializer_list<std::string> services) {
    auto cmd = compose_cmd({"up", "-d", "--no-deps"});
    cmd.insert(cmd.end(), services);
    run_checked(cmd);
}

void stop(std::initializer_list<std::string> services) {
    auto cmd = compose_cmd({"stop", "-t", "40"});
    cmd.insert(cmd.end(), services);
    run_checked(cmd);
}

/// Waits until each of `urls` answers the API.
void wait_for(const std::vector<std::string>& urls) {
    auto cmd =
        compose_cmd({"run", "--rm", "-T", "clients", "/usr/local/bin/sqs_path_load.py", "wait"});
    cmd.insert(cmd.end(), urls.begin(), urls.end());
    const auto r = os::real_exec(cmd);
    BOOST_TEST_REQUIRE(r.code == 0, "nodes not answering: " << r.out);
}

/// SIGKILL, a pause, and a start: the node comes back from its volume.
void kill_and_restart(const std::string& svc, std::chrono::seconds down = 5s) {
    BOOST_TEST_MESSAGE("killing " << svc);
    run_checked(compose_cmd({"kill", "-s", "SIGKILL", svc}));
    std::this_thread::sleep_for(down);
    run_checked(compose_cmd({"start", svc}));
}

/// Tells every data node in `data` where node `id` listens.
void announce(int id, const std::vector<int>& data) {
    std::vector<std::string> cmd =
        compose_cmd({"run", "--rm", "-T", "clients", "/usr/local/bin/sqs_admin.py", "peer"});
    for (const int d : data) {
        cmd.push_back(url(d));
    }
    cmd.insert(cmd.end(), {"--id", std::to_string(id), "--raft", "http://" + service(id) + ":7000",
                           "--sqs", url(id)});
    // A node just started may not listen yet: try for a minute.
    os::CmdResult r;
    for (int i = 0; i < 30; ++i) {
        r = os::real_exec(cmd);
        if (r.code == 0) {
            return;
        }
        std::this_thread::sleep_for(2s);
    }
    BOOST_TEST_REQUIRE(r.code == 0, "announcing " << id << ": " << r.out);
}

/// Evacuates `from` to `to` through node `via`, retrying a call that ends
/// without an answer (a node of the group killed meanwhile).
void evacuate(int via, int from, int to) {
    os::CmdResult r;
    for (int i = 0; i < 3; ++i) {
        r = client({"/usr/local/bin/sqs_admin.py", "evacuate", url(via), "--from",
                    std::to_string(from), "--to", std::to_string(to)});
        if (r.code == 0) {
            BOOST_TEST_MESSAGE("evacuated " << from << " to " << to << ":\n" << r.out);
            return;
        }
        std::this_thread::sleep_for(5s);
    }
    BOOST_TEST_REQUIRE(r.code == 0, "evacuating " << from << " to " << to << ": " << r.out);
}

void let_run(std::chrono::seconds s) {
    std::this_thread::sleep_for(s);
}

void dump_logs() {
    const auto r = os::real_exec(compose_cmd({"logs", "--no-color", "--tail", "100"}));
    std::cerr << "---- compose logs ----\n" << r.out << "\n----------------------\n";
    const auto l = os::real_exec({os::container_runtime(), "logs", "--tail", "50", k_load});
    std::cerr << "---- load ----\n" << l.out << "\n--------------\n";
}

struct stack_fixture {
    stack_fixture() {
        os::try_exec(os::real_exec, {os::container_runtime(), "rm", "-f", k_load});
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
        try {
            up({"sqs-1", "sqs-2", "sqs-3"});
        } catch (...) {
            dump_logs();
            throw;
        }
    }
    ~stack_fixture() {
        const auto& results = boost::unit_test::results_collector.results(
            boost::unit_test::framework::current_test_case().p_id);
        if (!results.passed() || std::getenv("KYTHIRA_SQS_KEEP_LOGS") != nullptr) {
            dump_logs();
        }
        os::try_exec(os::real_exec, {os::container_runtime(), "rm", "-f", k_load});
        os::try_exec(os::real_exec, compose_cmd({"down", "-v", "--remove-orphans"}));
    }
    stack_fixture(const stack_fixture&) = delete;
    stack_fixture& operator=(const stack_fixture&) = delete;
    stack_fixture(stack_fixture&&) = delete;
    stack_fixture& operator=(stack_fixture&&) = delete;
};

/// The load's summary line, after a SIGTERM and its drain.
boost::json::object stop_load() {
    run_checked({os::container_runtime(), "kill", "-s", "TERM", k_load});
    const auto code = os::real_exec({os::container_runtime(), "wait", k_load});
    const auto logs = os::real_exec({os::container_runtime(), "logs", k_load});
    BOOST_TEST_MESSAGE("load exited " << code.out << logs.out);
    const auto at = logs.out.rfind("{\"sent_standard\"");
    BOOST_TEST_REQUIRE(at != std::string::npos, "no summary from the load: " << logs.out);
    const auto end = logs.out.find('\n', at);
    boost::system::error_code ec;
    auto v = boost::json::parse(logs.out.substr(at, end == std::string::npos ? end : end - at), ec);
    BOOST_TEST_REQUIRE((!ec && v.is_object()), "unreadable summary: " << logs.out.substr(at));
    return v.as_object();
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_whole_path_survives_a_node_kill_in_every_layer) {
    stack_fixture stack;
    wait_for({url(1), url(2), url(3)});

    // The load runs from here to the end, on whichever nodes answer.
    run_checked(compose_cmd(
        {"run", "-d", "--name", k_load, "clients", "/usr/local/bin/sqs_path_load.py", "run"}));
    for (int i = 0;; ++i) {
        const auto l = os::real_exec({os::container_runtime(), "logs", k_load});
        if (l.out.find("ready") != std::string::npos) {
            break;
        }
        BOOST_TEST_REQUIRE(i < 60, "the load did not start: " << l.out);
        std::this_thread::sleep_for(1s);
    }
    let_run(10s);

    // ---- Co-located to split -------------------------------------------
    up({"sqs-4", "sqs-5", "sqs-6"});
    for (const int id : {4, 5, 6}) {
        announce(id, {1, 2, 3, 4, 5, 6});
    }
    up({"fe-1", "fe-2", "gw-1", "gw-2"});
    wait_for({url("gw-1"), url("gw-2")});

    evacuate(2, 1, 4);
    // The data layer: a new replica, a voter now, killed and restarted.
    kill_and_restart(service(4));
    let_run(10s);
    evacuate(3, 2, 5);
    // The front-end layer, with gateways relaying to it.
    kill_and_restart("fe-1");
    let_run(10s);
    evacuate(4, 3, 6);

    stop({"sqs-1", "sqs-2", "sqs-3"});
    // Only the gateways serve clients now: the gateway layer.
    let_run(10s);
    kill_and_restart("gw-1");
    let_run(10s);
    kill_and_restart("fe-2");
    let_run(10s);

    // ---- Split back to co-located --------------------------------------
    up({"sqs-7", "sqs-8", "sqs-9"});
    for (const int id : {7, 8, 9}) {
        announce(id, {4, 5, 6, 7, 8, 9});
    }
    evacuate(5, 4, 7);
    // A new co-located node, voting now.
    kill_and_restart(service(7));
    let_run(10s);
    evacuate(6, 5, 8);
    evacuate(7, 6, 9);
    wait_for({url(7), url(8), url(9)});

    stop({"gw-1", "gw-2"});
    let_run(10s);
    stop({"fe-1", "fe-2", "sqs-4", "sqs-5", "sqs-6"});
    let_run(15s);

    const auto summary = stop_load();
    BOOST_TEST_MESSAGE("summary: " << boost::json::serialize(summary));
    BOOST_TEST(summary.at("problems").as_array().empty());
    // Enough traffic that every step ran under load.
    BOOST_TEST(summary.at("sent_standard").to_number<std::int64_t>() > 500);
    BOOST_TEST(summary.at("sent_fifo").to_number<std::int64_t>() > 500);
}
