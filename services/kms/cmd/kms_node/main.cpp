// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kms_node: the KMS-compatible service on its own cluster
// (.kiro/specs/kms-compatible-api/ task 12): kythira_node with the KMS
// module and, where they are compiled in, the HSM module holding the key
// material and an IAM replica deciding key policies.
//
// It is the same node as kythira_node (cmd/kythira_node/main.cpp): the
// same KYTHIRA_NODE_* settings, Raft listener, metrics and health
// endpoint, each module's own settings, and the modules from the global
// catalog that the build links whole-archive (services/kms/cmd/
// CMakeLists.txt). KYTHIRA_SERVICES picks among kms, hsm and iam and must
// name kms; left unset it is every one of them compiled in. Group spaces
// and data directories are those the modules have in kythira_node, so a
// KMS cluster moves between the two layouts in place (whole-cluster stop,
// doc/colocation.md).
//
// Where the module cannot be built it is the self-test only.

#if defined(KYTHIRA_KMS_NODE_DAEMON)
#include <raft/kythira_node_host.hpp>
#include <raft/module_registry.hpp>
#include <raft/node_core.hpp>
#include <raft/node_endpoint.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
// Before the first future: Folly's timekeeper is a Folly singleton.
#include <folly/init/Init.h>
#endif

#include <cstdlib>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <variant>
#include <vector>
#endif

#include <kythira/kms/model/kms_model.hpp>

#include <raft/aws_json_protocol.hpp>

#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>

namespace {

auto self_test() -> int {
    namespace km = kythira::kms::kms_model;
    if (km::k_model.target_prefix != "TrentService" ||
        km::k_model.find_operation("CreateKey") == nullptr) {
        std::fputs("self-test: the generated KMS model is not TrentService\n", stderr);
        return 1;
    }
    const kythira::aws_json::shape_validator validator(km::k_model);
    std::printf("self-test ok: KMS model with %zu operations, %zu shapes\n",
                km::k_model.operations.size(), km::k_model.shapes.size());
    return 0;
}

constexpr std::string_view self_test_usage =
    "  --help       print this text\n"
    "  --self-test  check the generated KMS model, then exit\n";

#if defined(KYTHIRA_KMS_NODE_DAEMON)

namespace sn = kythira::service_node;
using host_type = sn::kythira_node_host;

/// The services kms_node may run, in the order they are listed.
constexpr std::string_view k_services[] = {"iam", "hsm", "kms"};

auto process_env() -> sn::env_lookup {
    return [](std::string_view name) -> std::optional<std::string> {
        const char* v = std::getenv(std::string(name).c_str());  // NOLINT(concurrency-mt-unsafe)
        if (v == nullptr || *v == '\0') {
            return std::nullopt;
        }
        return std::string(v);
    };
}

/// Every service kms_node may run that this build links.
auto compiled_in() -> std::string {
    const auto names = sn::module_catalog<host_type>::global().names();
    std::string out;
    for (const auto s : k_services) {
        for (const auto& n : names) {
            if (n == s) {
                out += (out.empty() ? "" : ",") + n;
            }
        }
    }
    return out;
}

auto usage() -> std::string {
    std::string out =
        "usage: kms_node [--help | --self-test]\n"
        "\n"
        "The Kythira KMS-compatible service on its own cluster: kythira_node\n"
        "with the KMS module, the HSM module and an IAM replica.\n"
        "\n" +
        std::string(self_test_usage) +
        "\n  KYTHIRA_SERVICES                 kms, optionally with hsm and iam\n"
        "                                   (default: those compiled in: " +
        compiled_in() + ")\n" + "\nNode settings:\n" + sn::node_config_usage() +
        "\nCompiled-in services and their settings:\n";
    auto& catalog = sn::module_catalog<host_type>::global();
    for (const auto& name : catalog.names()) {
        const auto m = catalog.make(name);
        out += "  " + name + "  (" + std::string(m->env_prefix()) + "*)\n";
    }
    return out;
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
    const auto base = process_env();
    // The services, checked here, and seen by the modules (their
    // co_located checks) through KYTHIRA_SERVICES as if it had been set.
    const auto services = base("KYTHIRA_SERVICES").value_or(compiled_in());
    const auto names = sn::split_services(services);
    bool has_kms = false;
    for (const auto& n : names) {
        has_kms = has_kms || n == "kms";
        bool allowed = false;
        for (const auto s : k_services) {
            allowed = allowed || n == s;
        }
        if (!allowed) {
            std::cerr << "kms_node: KYTHIRA_SERVICES names '" << n
                      << "'; kms_node runs kms, hsm and iam only (kythira_node co-locates "
                         "other services)\n";
            return 2;
        }
    }
    if (!has_kms) {
        std::cerr << "kms_node: KYTHIRA_SERVICES must name kms\n";
        return 2;
    }
    const sn::env_lookup env = [base, services](std::string_view name) {
        return name == "KYTHIRA_SERVICES" ? std::optional<std::string>(services) : base(name);
    };

    auto parsed = sn::node_config_from_env(env);
    if (auto* e = std::get_if<std::string>(&parsed)) {
        std::cerr << "kms_node: " << *e << '\n';
        return 2;
    }
    auto config = std::get<sn::node_config>(std::move(parsed));
    auto planned = sn::plan_modules(sn::module_catalog<host_type>::global(), names, true);
    if (auto* e = std::get_if<std::string>(&planned)) {
        std::cerr << "kms_node: " << *e << '\n';
        return 2;
    }
    const auto id = kythira::parse_host_node_id(config.node_id);
    if (!id) {
        std::cerr << "kms_node: KYTHIRA_NODE_ID: " << id.error() << '\n';
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
    log(false, "service=node serving " + services + "; metrics on port " +
                   std::to_string(endpoint.port()));

    const int sig = sn::wait_for_stop_signal();
    log(false, "service=node signal " + std::to_string(sig) + ", stopping");
    endpoint.stop();
    runner.stop([&stack] { stack.shutdown(); });
    return 0;
}

#else

auto usage() -> std::string {
    return std::string(
               "usage: kms_node [--help | --self-test]\n"
               "\n"
               "The Kythira KMS-compatible service daemon. This build has the\n"
               "self-test only: the daemon needs RocksDB (CONFIG_ENGINE_ROCKSDB),\n"
               "OpenSSL, Boost.JSON and the Boost.Beast transport.\n"
               "\n") +
           std::string(self_test_usage);
}

#endif

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
    if (argc == 2 && (arg == "--help" || arg == "-h")) {
        std::cout << usage();
        return 0;
    }
#if defined(KYTHIRA_KMS_NODE_DAEMON)
    if (argc == 1) {
#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
        const folly::Init folly_init(&argc, &argv);
#endif
        try {
            return run();
        } catch (const std::exception& e) {
            std::cerr << "kms_node: " << e.what() << '\n';
            return 1;
        }
    }
#endif
    std::cerr << usage();
    return 2;
}
