// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// s3_gateway_node: the Amazon S3-compatible daemon
// (.kiro/specs/s3-compatible-storage/ tasks 16 and 16a).
//
// Reads its settings from the environment (s3_node_config.hpp lists them;
// --help prints them) and runs the layers KYTHIRA_S3_ROLES names
// (s3_node.hpp):
//
//  - blobs: a chunk store under KYTHIRA_S3_DATA_DIR.
//  - metadata: the object index group, the metadata routes for front ends
//    on other nodes, and the leader-side workers (lifecycle, tiers,
//    notifications, replication, the chunk sweeper) on a schedule
//    (s3_workers.hpp). With KYTHIRA_S3_RAFT_PEERS the group runs on Raft
//    with the other metadata nodes and is kept in RocksDB (the S3 module,
//    s3_module.hpp, over this node's own Raft listener, run_raft.cpp);
//    without, it is in process and in memory, on this node alone.
//  - front_end (with gateway): the S3 API listener, and the website
//    listener when KYTHIRA_S3_WEBSITE_LISTEN is set. Without the metadata
//    role it reaches the metadata nodes through remote_metadata and writes
//    chunks to their blob stores.
//
// The internal listener (KYTHIRA_S3_INTERNAL_LISTEN) serves the metadata,
// group and chunk routes over mutual TLS, each route open to the roles
// internal_route_rules() names (s3_roles.hpp).
//
// What is not here yet: the gateway apart from the front end and streaming
// bodies (task 17), blob pools and several index groups (task 18), cloud
// tiers (the tier worker runs with none configured) and IAM authentication
// (static keys only).

#include "s3_node.hpp"

#if defined(KYTHIRA_S3_RAFT_DAEMON)
#include "run_raft.hpp"
#endif

#include <kythira/s3/model/operations.hpp>
#include <kythira/s3/s3_node_config.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
// The Folly backend (the default, which defines no macro of its own) needs
// folly::Init before the first future: its timekeeper is a Folly singleton.
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {

namespace s3 = kythira::s3;
using kythira::s3_node::log_line;

constexpr std::string_view k_usage =
    "usage: s3_gateway_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon S3-compatible daemon. Point the AWS CLI, an AWS SDK,\n"
    "rclone or Mountpoint at it with an endpoint URL. Settings come from the\n"
    "environment:\n"
    "\n";

using kythira::s3::model::operation_info;

auto find_operation(std::string_view name) -> const operation_info* {
    const auto& ops = kythira::s3::model::operations;
    const auto* it =
        std::find_if(ops.begin(), ops.end(), [&](const auto& o) { return o._name == name; });
    return it == ops.end() ? nullptr : it;
}

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

/// Checks the generated operation table (task 1), without starting anything.
auto self_test() -> int {
    namespace m = kythira::s3::model;
    const auto& ops = m::operations;
    if (!std::is_sorted(ops.begin(), ops.end(),
                        [](const auto& a, const auto& b) { return a._name < b._name; })) {
        return fail("operation table is not sorted");
    }
    constexpr std::array<std::string_view, 5> methods{"GET", "HEAD", "PUT", "POST", "DELETE"};
    for (const auto& op : ops) {
        if (std::find(methods.begin(), methods.end(), op._method) == methods.end()) {
            return fail("an operation has an unknown HTTP method");
        }
        if (!op._request_uri.starts_with('/')) {
            return fail("an operation's request URI does not start with '/'");
        }
    }
    const auto* put = find_operation("PutObject");
    if (put == nullptr || put->_method != "PUT" || !put->_streaming_input) {
        return fail("PutObject missing, not a PUT, or not a streaming upload");
    }
    const auto* part = find_operation("UploadPart");
    if (part == nullptr || !part->_streaming_input) {
        return fail("UploadPart missing or not a streaming upload");
    }
    const auto* get = find_operation("GetObject");
    if (get == nullptr || get->_method != "GET" || !get->_streaming_output) {
        return fail("GetObject missing, not a GET, or not a streaming download");
    }
    const auto* v2 = find_operation("ListObjectsV2");
    if (v2 == nullptr || v2->_request_uri != "/{Bucket}?list-type=2") {
        return fail("ListObjectsV2 missing or not told apart by ?list-type=2");
    }
    const auto* del = find_operation("DeleteObjects");
    if (del == nullptr || !del->_checksum_required) {
        return fail("DeleteObjects missing or not marked as needing a checksum");
    }
    const auto streaming = std::count_if(ops.begin(), ops.end(), [](const auto& o) {
        return o._streaming_input || o._streaming_output;
    });
    const auto deprecated =
        std::count_if(ops.begin(), ops.end(), [](const auto& o) { return o._deprecated; });
    std::printf(
        "self-test ok: %zu operations (%td streaming, %td deprecated), %.*s, botocore %.*s\n",
        ops.size(), streaming, deprecated, static_cast<int>(m::protocol.size()), m::protocol.data(),
        static_cast<int>(m::botocore_version.size()), m::botocore_version.data());
    return 0;
}

auto wait_for_signal() -> int {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    int sig = 0;
    sigwait(&set, &sig);
    return sig;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    if (argc > 1) {
        const std::string_view arg(argv[1]);
        if (argc == 2 && arg == "--self-test") {
            return self_test();
        }
        const bool help = argc == 2 && arg == "--help";
        std::FILE* out = help ? stdout : stderr;
        std::fputs(k_usage.data(), out);
        std::fwrite(s3::node_env_help.data(), 1, s3::node_env_help.size(), out);
#if defined(KYTHIRA_S3_RAFT_DAEMON)
        std::fputs("\nThis build runs the index on Raft (KYTHIRA_S3_RAFT_PEERS).\n", out);
#else
        std::fputs(
            "\nThis build has no RocksDB, so it cannot run the index on Raft: "
            "KYTHIRA_S3_RAFT_PEERS is refused.\n",
            out);
#endif
        return help ? 0 : 2;
    }

    // Block the stop signals in every thread, so sigwait() below receives
    // them; the listeners' threads inherit the mask.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
    const folly::Init folly_init(&argc, &argv);
#endif

    const s3::env_lookup env = [](std::string_view name) -> std::optional<std::string> {
        const std::string n(name);
        const char* v = std::getenv(n.c_str());  // NOLINT(concurrency-mt-unsafe): before threads
        return v == nullptr ? std::nullopt : std::optional<std::string>(v);
    };
    auto parsed = s3::node_config_from_env(env);
    if (auto* e = std::get_if<std::string>(&parsed)) {
        std::cerr << "s3_gateway_node: " << *e << "\n";
        return 2;
    }
    const auto& cfg = std::get<s3::node_config>(parsed);

    if (cfg.raft()) {
#if defined(KYTHIRA_S3_RAFT_DAEMON)
        return kythira::s3_node::run_raft(env, cfg, [] {
            const int sig = wait_for_signal();
            log_line(false, "signal " + std::to_string(sig) + ", stopping");
        });
#else
        std::cerr << "s3_gateway_node: KYTHIRA_S3_RAFT_PEERS: this build has no RocksDB, so it "
                     "cannot keep the index on Raft (build with CONFIG_ENGINE_ROCKSDB)\n";
        return 2;
#endif
    }

    int status = 0;
    {
        kythira::s3_node::node n(cfg);
        try {
            n.start();
            const int sig = wait_for_signal();
            log_line(false, "signal " + std::to_string(sig) + ", stopping");
        } catch (const std::invalid_argument& e) {
            std::cerr << "s3_gateway_node: " << e.what() << "\n";
            status = 2;
        } catch (const std::exception& e) {
            std::cerr << "s3_gateway_node: " << e.what() << "\n";
            status = 1;
        }
        n.stop();
    }
    return status;
}
