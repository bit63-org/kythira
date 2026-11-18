// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// sqs_node: the Amazon SQS-compatible daemon
// (.kiro/specs/sqs-compatible-queues/).
//
// Two modes, the same API and settings (`sqs_node_options.hpp`):
// - durable, when KYTHIRA_NODE_DATA_DIR is set: the SQS module of
//   kythira_node (sqs_module.hpp) alone on a node, its queues in RocksDB
//   under multi_raft, one or more nodes (KYTHIRA_NODE_*), a send
//   acknowledged once committed. Built where the module is
//   (KYTHIRA_SQS_NODE_DURABLE).
// - in memory otherwise: one node keeping its queues in
//   `local_queue_cluster`, for development and client suites. Queues and
//   messages are lost when it stops.
//
// --self-test checks the generated operation table and exits; it is all a
// build without the listener (no Boost.Beast or OpenSSL TLS) offers.

#include <kythira/sqs/sqs_operations.hpp>

#ifdef KYTHIRA_SQS_NODE_SERVE
#include <kythira/sqs/sqs_actions.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_compat_profile.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_listener.hpp>
#include <kythira/sqs/sqs_long_poll.hpp>
#include <kythira/sqs/sqs_node_options.hpp>
#include <kythira/sqs/sqs_receipts.hpp>
#include <kythira/sqs/sqs_service.hpp>
#include <kythira/sqs/sqs_workers.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/static_key_authorizer.hpp>
#include <raft/static_keys_file.hpp>

#ifdef KYTHIRA_SQS_NODE_DURABLE
#include "sqs_module.hpp"

#include <raft/kythira_node_host.hpp>
#include <raft/node_core.hpp>
#include <raft/rocksdb_kv_engine.hpp>
#endif

#include <openssl/rand.h>

#include <pthread.h>

#include <csignal>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <variant>
#endif

#include <algorithm>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: sqs_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon SQS-compatible daemon. With no argument it serves the SQS\n"
    "API on SQS_LISTEN until SIGINT or SIGTERM. Settings come from the\n"
    "environment: SQS_LISTEN, SQS_TLS_CERT, SQS_TLS_KEY, SQS_ALLOW_PLAINTEXT,\n"
    "SQS_ENDPOINT, SQS_REGION, SQS_PARTITION, SQS_STATIC_KEYS_FILE (required),\n"
    "SQS_RECEIPT_KEYS_FILE, SQS_FORWARD_SECRET, SQS_SSE_KEY_FILE, SQS_KMS\n"
    "(none or local), SQS_KMS_PASSPHRASE_FILE, SQS_COMPAT, SQS_MAX_BODY_BYTES.\n"
    "\n"
    "With KYTHIRA_NODE_DATA_DIR set (in builds with the durable module) the\n"
    "queues are kept on disk under Raft, on one node or several: KYTHIRA_NODE_ID,\n"
    "KYTHIRA_NODE_PEERS, KYTHIRA_NODE_RAFT_BIND, KYTHIRA_NODE_RAFT_PORT,\n"
    "KYTHIRA_NODE_TLS_CERT, _TLS_KEY, _TLS_CA, KYTHIRA_NODE_INSECURE_PLAINTEXT,\n"
    "plus SQS_PEER_ENDPOINTS, SQS_PEER_CA and SQS_PROPOSE_TIMEOUT_MS; a durable\n"
    "node needs SQS_RECEIPT_KEYS_FILE or SQS_FORWARD_SECRET, SQS_SSE_KEY_FILE or\n"
    "SQS_FORWARD_SECRET (SSE-SQS is on by default), and more than one\n"
    "node needs SQS_FORWARD_SECRET. Without it, one node keeps its queues in\n"
    "memory and loses them when it stops.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the generated operation table, then exit\n";

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

auto self_test() -> int {
    namespace s = kythira::sqs;
    const auto& ops = s::operations;
    const auto by_name = [](const auto& a, const auto& b) { return a._name < b._name; };
    if (!std::is_sorted(ops.begin(), ops.end(), by_name)) {
        return fail("operation table is not sorted");
    }
    if (!std::is_sorted(s::error_shapes.begin(), s::error_shapes.end())) {
        return fail("error shape table is not sorted");
    }
    // Every batch operation has its single-entry form beside it.
    std::size_t batches = 0;
    for (const auto& op : ops) {
        if (!op._batch) {
            continue;
        }
        ++batches;
        const std::string single(
            op._name.substr(0, op._name.size() - std::string_view("Batch").size()));
        const bool found =
            std::any_of(ops.begin(), ops.end(), [&](const auto& o) { return o._name == single; });
        if (!found) {
            return fail("a batch operation has no single-entry form");
        }
    }
    if (batches == 0) {
        return fail("no batch operation in the table");
    }
    // Every operation names at least one error, and only known ones.
    for (const auto& op : ops) {
        if (op._errors == 0 || (op._errors >> s::error_shapes.size()) != 0) {
            return fail("an operation's error mask is empty or out of range");
        }
    }
    if (!s::aws_query_compatible) {
        return fail("the pinned model is no longer awsQueryCompatible");
    }
    std::printf(
        "self-test ok: %zu operations (%zu batch), %zu error shapes, target prefix %.*s, botocore "
        "%.*s\n",
        ops.size(), batches, s::error_shapes.size(), static_cast<int>(s::target_prefix.size()),
        s::target_prefix.data(), static_cast<int>(s::botocore_version.size()),
        s::botocore_version.data());
    return 0;
}

#ifdef KYTHIRA_SQS_NODE_SERVE

auto read_file(const std::string& path, std::string_view what) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read " + std::string(what) + " " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

/// The receipt keys: the key file, else derived from the forwarding
/// secret, else a random key (a lone in-memory node: its handles die with
/// its messages anyway).
auto receipt_keys(const kythira::sqs::sqs_node_options& o) -> kythira::sqs::receipt_key_ring {
    namespace s = kythira::sqs;
    if (!o._receipt_keys_file.empty()) {
        return s::parse_receipt_keys(read_file(o._receipt_keys_file, "SQS_RECEIPT_KEYS_FILE"));
    }
    if (!o._forward_secret.empty()) {
        return s::derived_receipt_key(o._forward_secret);
    }
    std::string secret(32, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(secret.data()),  // NOLINT
                   static_cast<int>(secret.size())) != 1) {
        throw std::runtime_error("no randomness for a receipt key");
    }
    s::receipt_key_ring ring;
    ring._keys.push_back({._id = 0, ._secret = std::move(secret)});
    return ring;
}

auto wait_for_signal() -> void {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    int sig = 0;
    (void)sigwait(&set, &sig);
}

auto serve() -> int {
    namespace s = kythira::sqs;
    namespace az = kythira::aws_auth;
    // Block the stop signals before any thread starts, so only sigwait
    // takes them.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);

    auto parsed =
        s::sqs_node_options_from_env([](std::string_view name) -> std::optional<std::string> {
            const auto* v = std::getenv(std::string(name).c_str());
            return v == nullptr ? std::nullopt : std::optional<std::string>(v);
        });
    if (const auto* refused = std::get_if<std::string>(&parsed)) {
        std::cerr << "sqs_node: " << *refused << std::endl;
        return 2;
    }
    const auto opt = std::get<s::sqs_node_options>(parsed);
    try {
        az::static_key_authorizer auth(
            az::parse_static_keys(read_file(opt._static_keys_file, "SQS_STATIC_KEYS_FILE")),
            opt._partition);
        auth.register_service(s::sqs_static_roles());
        const auto profile = s::cluster_profile(opt._compat);
        if (!profile) {
            std::cerr << "sqs_node: SQS_COMPAT refused: " << profile.error().message.value_or("")
                      << std::endl;
            return 2;
        }

        s::local_queue_cluster cluster;
        // Long polls park on the hub; the state machine tells it which
        // partitions have visible messages, and the worker commits the
        // ticks that end delays and visibility timeouts.
        s::availability_hub hub;
        s::tick_worker<s::local_queue_cluster> worker(cluster,
                                                      [](const std::string&) { return true; });
        cluster.set_availability_listener([&hub, &worker](const s::queue_target& t, bool visible) {
            if (visible) {
                hub.notify(s::queue_keys::partition_prefix(t));
            }
            worker.wake();
        });
        worker.start();
        // Message move tasks (StartMessageMoveTask).
        s::move_worker<s::local_queue_cluster> mover(
            cluster, [](const std::string&) { return true; }, s::sqs_arn_queue);
        mover.start();
        s::sqs_service_config sc;
        sc._receipt_keys = receipt_keys(opt);
        sc._sse = s::node_sse_keys(
            opt._sse_key_file.empty() ? std::string()
                                      : read_file(opt._sse_key_file, "SQS_SSE_KEY_FILE"),
            opt._forward_secret,
            opt._kms == "local" ? std::optional<std::string>(read_file(opt._kms_passphrase_file,
                                                                       "SQS_KMS_PASSPHRASE_FILE"))
                                : std::nullopt);
        sc._profile = *profile;
        sc._waits = &hub;
        s::sqs_service<s::local_queue_cluster> service(cluster, sc);

        kythira::https::server_config hc;
        hc.bind_address = opt._listen_host;
        hc.port = opt._listen_port;
        hc.tls_cert_path = opt._tls_cert_path;
        hc.tls_key_path = opt._tls_key_path;
        hc.insecure_plaintext = opt._allow_plaintext;
        hc.max_body_bytes = opt._max_body_bytes;

        // The front end needs the endpoint, which may need the port the
        // listener picked: the handler is bound late through this pointer.
        std::unique_ptr<s::sqs_front_end<az::static_key_authorizer>> front_end;
        std::unique_ptr<s::sqs_http_handler<s::sqs_front_end<az::static_key_authorizer>>> handler;
        kythira::https::server server(
            hc,
            [&handler](const kythira::https::request& req,
                       const kythira::https::request_context& ctx) { return (*handler)(req, ctx); },
            [](bool warning, std::string_view message) {
                std::cerr << "sqs_node: " << (warning ? "warning: " : "") << message << std::endl;
            });

        s::sqs_front_end_config fc;
        fc._region = opt._region;
        fc._partition = opt._partition;
        fc._limits.max_body_bytes = opt._max_body_bytes;
        // Bind first when the port is chosen by the system, so the URL
        // names it; otherwise build everything before the first request.
        if (opt._listen_port == 0) {
            server.start();
        }
        const auto port = opt._listen_port == 0 ? server.port() : opt._listen_port;
        fc._endpoint = opt._endpoint.empty()
                           ? std::string(opt._allow_plaintext ? "http" : "https") +
                                 "://localhost:" + std::to_string(port)
                           : opt._endpoint;
        front_end = std::make_unique<s::sqs_front_end<az::static_key_authorizer>>(fc, auth);
        service.register_with(*front_end);
        handler =
            std::make_unique<s::sqs_http_handler<s::sqs_front_end<az::static_key_authorizer>>>(
                *front_end, opt._forward_secret,
                [&cluster](const std::string& key, std::vector<std::byte> entry) {
                    return cluster.propose(key, std::move(entry));
                });
        if (opt._listen_port != 0) {
            server.start();
        }
        std::cout << "sqs_node ready: " << (opt._allow_plaintext ? "http" : "https") << " port "
                  << server.port() << ", queue URLs on " << fc._endpoint
                  << " (single node, queues kept in memory)" << std::endl;
        wait_for_signal();
        hub.close();  // parked long polls answer empty before the listener stops
        server.stop();
        worker.stop();
        cluster.set_availability_listener({});
        std::cout << "sqs_node stopped" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "sqs_node: " << e.what() << std::endl;
        return 1;
    }
}

#endif

#ifdef KYTHIRA_SQS_NODE_DURABLE

auto process_env(std::string_view name) -> std::optional<std::string> {
    const auto* v = std::getenv(std::string(name).c_str());
    return v == nullptr || *v == '\0' ? std::nullopt : std::optional<std::string>(v);
}

/// The SQS module alone on a node: kythira_node's transport and host, the
/// module in a stand-alone group space (no id offset or key prefix).
auto serve_durable() -> int {
    namespace sn = kythira::service_node;
    using host_type = sn::kythira_node_host;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);

    auto parsed = sn::node_config_from_env(process_env);
    if (const auto* refused = std::get_if<std::string>(&parsed)) {
        std::cerr << "sqs_node: " << *refused << std::endl;
        return 2;
    }
    const auto config = std::get<sn::node_config>(parsed);
    int status = 0;
    try {
        sn::kythira_node_stack stack(config);
        host_type host(config, sn::kythira_node_stack::parse_id(config.node_id), stack.client(),
                       stack.server());
        sn::module_plan<host_type> plan;
        plan.modules.push_back(
            std::make_unique<kythira::sqs_node::sqs_module<host_type, kythira::rocksdb_kv_engine>>(
                true));
        plan.spaces.push_back(sn::group_space::standalone(sn::module_numbers::sqs));
        sn::node_runner<host_type> runner(
            std::move(plan), config, [](bool error, std::string_view line) {
                std::cerr << "sqs_node: " << (error ? "error: " : "") << line << std::endl;
            });
        try {
            runner.start(host, process_env);
            wait_for_signal();
        } catch (const std::invalid_argument& e) {
            std::cerr << "sqs_node: " << e.what() << std::endl;
            status = 2;
        } catch (const std::exception& e) {
            std::cerr << "sqs_node: " << e.what() << std::endl;
            status = 1;
        }
        // The module closes its listener and stops its groups before the
        // transport goes.
        runner.stop([&stack] { stack.shutdown(); });
    } catch (const std::exception& e) {
        std::cerr << "sqs_node: " << e.what() << std::endl;
        return 1;
    }
    if (status == 0) {
        std::cout << "sqs_node stopped" << std::endl;
    }
    return status;
}

#endif

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
#ifdef KYTHIRA_SQS_NODE_DURABLE
    if (argc == 1 && process_env("KYTHIRA_NODE_DATA_DIR")) {
        return serve_durable();
    }
#endif
#ifdef KYTHIRA_SQS_NODE_SERVE
    if (argc == 1) {
        return serve();
    }
#endif
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
