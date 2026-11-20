// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm_node: the virtual HSM on its own cluster (.kiro/specs/virtual-hsm/
// task 11, Requirement 2.1): kythira_node with only the HSM module.
//
// It is the same node as kythira_node (cmd/kythira_node/main.cpp): the
// same KYTHIRA_NODE_* settings, Raft listener, metrics and health
// endpoint, and the module's KYTHIRA_HSM_* settings, from one catalog
// holding only the HSM. Its group space and data directory
// (KYTHIRA_NODE_DATA_DIR/hsm) are those the module has in kythira_node,
// so an HSM cluster moves between the two layouts in place (whole-cluster
// stop, same node ids and data directories; doc/colocation.md). Stand-alone
// is the recommendation for production secrets (Requirement 2.5): no other
// service shares the process that holds the keys.
//
// Where the module cannot be built (no RocksDB, OpenSSL or Beast
// transport) it is the self-test only.

#if defined(KYTHIRA_HSM_NODE_DAEMON)
#include "hsm_module.hpp"

#include <raft/kythira_node_host.hpp>
#include <raft/module_registry.hpp>
#include <raft/node_core.hpp>
#include <raft/node_endpoint.hpp>

// Before the first future: Folly's timekeeper is a Folly singleton.
#include <raft/process_init.hpp>
#endif

#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/secure_arena.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace {

auto self_test(bool allow_unlocked) -> int {
    const auto v = kythira::hsm::cryptoki_version;
    if (v.major != 3 || v.minor != 0) {
        std::fprintf(stderr, "self-test: PKCS#11 headers declare %u.%u, expected 3.0\n",
                     static_cast<unsigned>(v.major), static_cast<unsigned>(v.minor));
        return 1;
    }
    if (auto ready = kythira::hsm::prepare_key_memory(allow_unlocked); !ready) {
        const auto why = kythira::hsm::secure_memory_error_message(ready.error());
        std::fprintf(stderr, "self-test: %.*s\n", static_cast<int>(why.size()), why.data());
        return 1;
    }
    const auto stats = kythira::hsm::process_arena().stats();
    std::printf("self-test ok: PKCS#11 %u.%u headers, key memory %s\n",
                static_cast<unsigned>(v.major), static_cast<unsigned>(v.minor),
                allow_unlocked ? "not required to be locked"
                               : (stats.unlocked_chunks == 0 ? "locked" : "UNLOCKED"));
    return 0;
}

constexpr std::string_view self_test_usage =
    "  --help       print this text\n"
    "  --self-test  check the vendored PKCS#11 headers and prepare key memory\n"
    "               (no core dumps, no ptrace attach, locked pages), then exit\n"
    "  --allow-unlocked-memory\n"
    "               with --self-test: carry on when key memory cannot be\n"
    "               locked (RLIMIT_MEMLOCK too low and no CAP_IPC_LOCK); for\n"
    "               development only\n";

#if defined(KYTHIRA_HSM_NODE_DAEMON)

namespace sn = kythira::service_node;
using host_type = sn::kythira_node_host;

auto env_lookup() -> sn::env_lookup {
    return [](std::string_view name) -> std::optional<std::string> {
        const char* v = std::getenv(std::string(name).c_str());  // NOLINT(concurrency-mt-unsafe)
        if (v == nullptr || *v == '\0') {
            return std::nullopt;
        }
        return std::string(v);
    };
}

/// The catalog hsm_node plans from: the HSM module and nothing else.
auto hsm_catalog() -> const sn::module_catalog<host_type>& {
    static const sn::module_catalog<host_type> catalog = [] {
        sn::module_catalog<host_type> c;
        c.add("hsm", [] { return std::make_unique<kythira::hsm_node::hsm_module<host_type>>(); });
        return c;
    }();
    return catalog;
}

auto usage() -> std::string {
    return std::string(
               "usage: hsm_node [--help | --self-test [--allow-unlocked-memory]]\n"
               "\n"
               "The Kythira virtual HSM on its own cluster: kythira_node with only\n"
               "the HSM module. KYTHIRA_SERVICES is not needed (\"hsm\" if set).\n"
               "\n") +
           std::string(self_test_usage) + "\nNode settings:\n" + sn::node_config_usage() +
           "\nHSM settings:\n" + std::string(kythira::hsm_node::usage_text());
}

/// One line per event on stderr, as kythira_node logs.
auto stderr_log() -> sn::log_sink {
    auto mutex = std::make_shared<std::mutex>();
    return [mutex](bool warning, std::string_view line) {
        const std::lock_guard lock(*mutex);
        std::cerr << (warning ? "level=warn " : "level=info ") << line << '\n';
    };
}

auto run() -> int {
    const auto log = stderr_log();
    const auto env = env_lookup();
    if (const auto services = env("KYTHIRA_SERVICES"); services && *services != "hsm") {
        std::cerr << "hsm_node: KYTHIRA_SERVICES is '" << *services
                  << "'; hsm_node runs only the HSM (kythira_node co-locates services)\n";
        return 2;
    }
    auto parsed = sn::node_config_from_env(env);
    if (auto* e = std::get_if<std::string>(&parsed)) {
        std::cerr << "hsm_node: " << *e << '\n';
        return 2;
    }
    auto config = std::get<sn::node_config>(std::move(parsed));
    // The composite group space: the module's ids in kythira_node, so the
    // data directory serves either layout.
    auto planned = sn::plan_modules(hsm_catalog(), {"hsm"}, true);
    if (auto* e = std::get_if<std::string>(&planned)) {
        std::cerr << "hsm_node: " << *e << '\n';
        return 2;
    }
    const auto id = kythira::parse_host_node_id(config.node_id);
    if (!id) {
        std::cerr << "hsm_node: KYTHIRA_NODE_ID: " << id.error() << '\n';
        return 2;
    }

    // Before any thread starts, so every thread inherits the mask.
    sn::block_stop_signals();

    sn::kythira_node_stack stack(config);
    host_type host(config, id.value(), stack.client(), stack.server());
    sn::node_runner<host_type> runner(std::get<sn::module_plan<host_type>>(std::move(planned)),
                                      config, log);
    sn::node_endpoint<host_type> endpoint(runner, log);
    try {
        runner.start(host, env);
        endpoint.start();
    } catch (const std::exception& e) {
        log(true, std::string("service=node stopping: ") + e.what());
        runner.stop([&stack] { stack.shutdown(); });
        return 1;
    }
    log(false, "service=node serving the HSM; metrics on port " + std::to_string(endpoint.port()));

    const int sig = sn::wait_for_stop_signal();
    log(false, "service=node signal " + std::to_string(sig) + ", stopping");
    endpoint.stop();
    runner.stop([&stack] { stack.shutdown(); });
    return 0;
}

#else

auto usage() -> std::string {
    return std::string(
               "usage: hsm_node [--help | --self-test [--allow-unlocked-memory]]\n"
               "\n"
               "The Kythira virtual HSM daemon. This build has the self-test only:\n"
               "the daemon needs RocksDB (CONFIG_ENGINE_ROCKSDB), OpenSSL and the\n"
               "Boost.Beast transport.\n"
               "\n") +
           std::string(self_test_usage);
}

#endif

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (arg == "--self-test" && argc <= 3) {
        const std::string_view flag = argc == 3 ? std::string_view(argv[2]) : std::string_view();
        if (argc == 2 || flag == "--allow-unlocked-memory") {
            return self_test(argc == 3);
        }
    }
    if (argc == 2 && (arg == "--help" || arg == "-h")) {
        std::cout << usage();
        return 0;
    }
#if defined(KYTHIRA_HSM_NODE_DAEMON)
    if (argc == 1) {
        const kythira::process_init process_init(argv[0]);
        try {
            return run();
        } catch (const std::exception& e) {
            std::cerr << "hsm_node: " << e.what() << '\n';
            return 1;
        }
    }
#endif
    std::cerr << usage();
    return 2;
}
