// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// sqs_node: the Amazon SQS-compatible daemon
// (.kiro/specs/sqs-compatible-queues/).
//
// Today a single node that keeps its queues in memory
// (`local_queue_cluster`): the whole API on one listener, for development
// and for client suites, with settings from the environment
// (`sqs_node_options.hpp`). Queues and messages are lost when it stops.
// The durable multi-node form, the kythira_node module on multi_raft
// (`sqs_raft_cluster.hpp`, `sqs_forward.hpp`), replaces the in-memory
// cluster without changing anything a client sees.
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
#include <kythira/sqs/sqs_node_options.hpp>
#include <kythira/sqs/sqs_receipts.hpp>
#include <kythira/sqs/sqs_service.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/static_key_authorizer.hpp>
#include <raft/static_keys_file.hpp>

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
    "API on SQS_LISTEN until SIGINT or SIGTERM, keeping queues in memory (a\n"
    "single development node). Settings come from the environment: SQS_LISTEN,\n"
    "SQS_TLS_CERT, SQS_TLS_KEY, SQS_ALLOW_PLAINTEXT, SQS_ENDPOINT, SQS_REGION,\n"
    "SQS_PARTITION, SQS_STATIC_KEYS_FILE (required), SQS_RECEIPT_KEYS_FILE,\n"
    "SQS_FORWARD_SECRET, SQS_COMPAT, SQS_MAX_BODY_BYTES.\n"
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
        s::sqs_service_config sc;
        sc._receipt_keys = receipt_keys(opt);
        sc._profile = *profile;
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
        server.stop();
        std::cout << "sqs_node stopped" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "sqs_node: " << e.what() << std::endl;
        return 1;
    }
}

#endif

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
#ifdef KYTHIRA_SQS_NODE_SERVE
    if (argc == 1) {
        return serve();
    }
#endif
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
