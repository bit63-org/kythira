// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ec2_node: the Amazon EC2-compatible daemon and antikythera's controller
// (.kiro/specs/ec2-compatible-api/).
//
// A placeholder until the gateway (task 3) and the data and fleet layers
// (tasks 4 onward) arrive. Today it only links the module, so the target,
// its build flags and the module boundary are exercised from task 1 on, and
// it reports what it is when asked.

#include <kythira/ec2/model/operations.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: ec2_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon EC2-compatible daemon (antikythera's controller). Not\n"
    "implemented yet: the server arrives with .kiro/specs/ec2-compatible-api/\n"
    "tasks 3 onward.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the generated operation table, then exit\n";

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

auto find(std::string_view name) -> const kythira::ec2::model::operation_info* {
    const auto& ops = kythira::ec2::model::operations;
    const auto* it =
        std::lower_bound(ops.begin(), ops.end(), name,
                         [](const auto& op, std::string_view n) { return op._name < n; });
    return it != ops.end() && it->_name == name ? it : nullptr;
}

auto self_test() -> int {
    namespace m = kythira::ec2::model;
    const auto& ops = m::operations;
    // Strictly sorted: the front end looks operations up by binary search.
    const auto not_before = [](const auto& a, const auto& b) { return a._name >= b._name; };
    if (std::adjacent_find(ops.begin(), ops.end(), not_before) != ops.end()) {
        return fail("operation table is not strictly sorted");
    }
    // The operations the spec builds first, with the members it relies on
    // (Requirements 3.4, 4.3 and 4.5).
    const auto* run = find("RunInstances");
    const auto* describe = find("DescribeInstances");
    const auto* volume = find("CreateVolume");
    if (run == nullptr || describe == nullptr || volume == nullptr) {
        return fail("RunInstances, DescribeInstances or CreateVolume is missing");
    }
    if (!run->_client_token || !run->_dry_run || !volume->_client_token) {
        return fail("RunInstances or CreateVolume lost ClientToken or DryRun");
    }
    if (!describe->_filters || !describe->_paged || !describe->_dry_run) {
        return fail("DescribeInstances lost its filters, paging or DryRun");
    }
    std::size_t tokens = 0;
    std::size_t paged = 0;
    for (const auto& op : ops) {
        tokens += op._client_token ? 1U : 0U;
        paged += op._paged ? 1U : 0U;
    }
    if (m::signing_name != "ec2" || m::api_version != "2016-11-15") {
        return fail("the pinned model no longer signs as ec2 at API version 2016-11-15");
    }
    std::printf(
        "self-test ok: %zu operations (%zu take ClientToken, %zu page), API version %.*s, "
        "botocore %.*s\n",
        ops.size(), tokens, paged, static_cast<int>(m::api_version.size()), m::api_version.data(),
        static_cast<int>(m::botocore_version.size()), m::botocore_version.data());
    return 0;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
