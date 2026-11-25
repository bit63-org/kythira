// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file main.cpp
/// @brief `kinesis_gateway_node`: a Kinesis Data Streams-compatible front
///        end over a Kythira multi-Raft cluster
///        (`.kiro/specs/kinesis-compatible-streams/` task 6).
///
/// Configured entirely from the environment (`config.hpp`); stopped by
/// SIGINT or SIGTERM. `--check-config` reads the environment and prints
/// the settings without binding anything, and `--self-test` checks the
/// generated tables, so both work in a build tree with no cluster.
/// `--admin METHOD OP [BODY]` makes one live migration admin call
/// (`kinesis_migration.hpp`) to this node's own gateway with the same
/// environment, and prints the answer.

#include "config.hpp"
#include "stop_signal.hpp"
#ifdef KYTHIRA_KINESIS_GATEWAY_IAM
#include "iam_auth.hpp"
#endif

#include <kythira/kinesis/kinesis_actions.hpp>
#include <kythira/kinesis/kinesis_admin_client.hpp>
#include <kythira/kinesis/kinesis_operations.hpp>

#include <raft/process_init.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>

namespace kythira::kinesis_node {

namespace {
std::atomic<bool> g_stop{false};
std::mutex g_stop_mu;
std::condition_variable g_stop_cv;
}  // namespace

void on_signal(int) {
    g_stop.store(true);
    g_stop_cv.notify_all();
}

void wait_for_stop() {
    std::unique_lock lock(g_stop_mu);
    g_stop_cv.wait(lock, [] { return g_stop.load(); });
}

}  // namespace kythira::kinesis_node

namespace {

auto self_test() -> int {
    namespace k = kythira::kinesis;
    const auto& ops = k::operations;
    const bool sorted = std::is_sorted(
        ops.begin(), ops.end(), [](const auto& a, const auto& b) { return a._name < b._name; });
    if (!sorted) {
        std::fputs("self-test: operation table is not sorted\n", stderr);
        return 1;
    }
    const auto* subscribe = std::find_if(
        ops.begin(), ops.end(), [](const auto& o) { return o._name == "SubscribeToShard"; });
    if (subscribe == ops.end() || !subscribe->_event_stream) {
        std::fputs("self-test: SubscribeToShard missing or not an event stream\n", stderr);
        return 1;
    }
    // Every operation has its IAM actions.
    for (const auto& o : ops) {
        if (k::find_operation_actions(o._name) == nullptr) {
            std::fprintf(stderr, "self-test: no IAM actions for %.*s\n",
                         static_cast<int>(o._name.size()), o._name.data());
            return 1;
        }
    }
    const auto streams =
        std::count_if(ops.begin(), ops.end(), [](const auto& o) { return o._event_stream; });
    std::printf(
        "self-test ok: %zu operations (%td event stream), target prefix %.*s, botocore %.*s\n",
        ops.size(), streams, static_cast<int>(k::target_prefix.size()), k::target_prefix.data(),
        static_cast<int>(k::botocore_version.size()), k::botocore_version.data());
    return 0;
}

auto env(const char* name) -> const char* {
    return std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read before any thread starts
}

/// `--admin METHOD OP [BODY]`: one signed admin call to this node's
/// gateway (its internal listener when it has one), addressed on loopback
/// when it listens on every address, or at KINESIS_ADMIN_TARGET. Prints
/// the status and body; exits 0 on a 2xx answer, 1 otherwise.
auto admin_command(const kythira::kinesis_node::node_options& opt, std::string_view method,
                   std::string_view op, std::string body) -> int {
    namespace k = kythira::kinesis;
    namespace http = boost::beast::http;
    const auto verb = http::string_to_verb(method);
    if (verb != http::verb::get && verb != http::verb::post) {
        std::cerr << "kinesis_gateway_node: --admin: METHOD is GET or POST, not " << method << "\n";
        return 2;
    }
    std::string target;
    if (const char* t = env("KINESIS_ADMIN_TARGET"); t != nullptr && *t != '\0') {
        target = t;
    } else {
        const bool internal = opt._internal_port != 0;
        std::string host = internal ? opt._internal_host : opt._listen_host;
        if (host.empty() || host == "0.0.0.0" || host == "::" || host == "[::]") {
            host = "127.0.0.1";
        }
        target = host + ":" + std::to_string(internal ? opt._internal_port : opt._listen_port);
    }
    const k::peer_client client(k::peer_client_config{
        ._tls = !opt._allow_plaintext,
        ._ca_path = opt._peer_ca_path,
        ._timeout = std::chrono::milliseconds{10000},
        ._user_agent = std::string(k::k_peer_user_agent),
    });
    const auto res =
        k::admin_request(client, opt._forward_secret, target, verb, op, std::move(body));
    if (!res) {
        std::cerr << "kinesis_gateway_node: --admin: no answer from " << target
                  << (opt._forward_secret.empty() ? " (KINESIS_FORWARD_SECRET is not set)" : "")
                  << "\n";
        return 1;
    }
    std::cout << res->_status << "\n" << res->_body << "\n";
    return res->_status >= 200 && res->_status < 300 ? 0 : 1;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    namespace kn = kythira::kinesis_node;
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    const bool admin = arg == "--admin";
    if (admin ? (argc < 4 || argc > 5) : argc > 2) {
        std::cerr << kn::usage();
        return 2;
    }
    if (arg == "--help" || arg == "-h") {
        std::cout << kn::usage();
#ifdef KYTHIRA_KINESIS_GATEWAY_IAM
        std::cout << kn::iam_auth_usage();
#endif
        return 0;
    }
    if (arg == "--self-test") {
        return self_test();
    }
    if (!arg.empty() && arg != "--check-config" && !admin) {
        std::cerr << "kinesis_gateway_node: unknown argument " << arg << "\n" << kn::usage();
        return 2;
    }

    kn::node_options opt;
    try {
        opt = kn::from_env(env);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }
    if (arg == "--check-config") {
        std::cout << kn::describe(opt);
        return 0;
    }
    if (admin) {
        return admin_command(opt, argv[2], argv[3],
                             argc > 4 ? std::string(argv[4]) : std::string());
    }

    const kythira::process_init process_init(argv[0]);
    if (!kn::is_loopback_address(opt._bind_address)) {
        std::cerr << "kinesis_gateway_node: WARNING: Raft RPC is PLAINTEXT and UNAUTHENTICATED on "
                  << opt._bind_address << ":" << opt._raft_port
                  << " (KYTHIRA_ALLOW_PLAINTEXT_RAFT)\n";
    }
    std::signal(SIGINT, kn::on_signal);
    std::signal(SIGTERM, kn::on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    try {
        // The module starts IAM's replica for KINESIS_AUTH=iam or both
        // (kinesis_module.hpp), and refuses them in a build without it.
        return kn::run(opt);
    } catch (const std::exception& e) {
        std::cerr << "kinesis_gateway_node: " << e.what() << "\n";
        return 1;
    }
}
