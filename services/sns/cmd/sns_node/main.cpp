// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// sns_node: the Amazon SNS-compatible daemon
// (.kiro/specs/sns-compatible-notifications/).
//
// A placeholder until the gateway (task 3) and the topic, subscription and
// publish API (task 4) arrive. Today it only links the module, so the
// target, its build flags and the module boundary are exercised from task 1
// on, and it reports what it is when asked.

#include <kythira/sns/sns_operations.hpp>

#include <algorithm>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: sns_node [--help | --self-test]\n"
    "\n"
    "The Kythira Amazon SNS-compatible daemon. Not implemented yet: the server\n"
    "arrives with .kiro/specs/sns-compatible-notifications/ tasks 3 and 4.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the generated operation table, then exit\n";

auto fail(const char* what) -> int {
    std::fprintf(stderr, "self-test: %s\n", what);
    return 1;
}

auto self_test() -> int {
    namespace s = kythira::sns;
    const auto& ops = s::operations;
    const auto& errors = s::error_shapes;
    const auto by_name = [](const auto& a, const auto& b) { return a._name < b._name; };
    if (!std::is_sorted(ops.begin(), ops.end(), by_name)) {
        return fail("operation table is not sorted");
    }
    const auto by_shape = [](const auto& a, const auto& b) { return a._shape < b._shape; };
    if (!std::is_sorted(errors.begin(), errors.end(), by_shape)) {
        return fail("error shape table is not sorted");
    }
    // Every error is answered with a query code and a 4xx or 5xx status,
    // and a 5xx is never the sender's fault.
    for (const auto& e : errors) {
        if (e._code.empty() || e._http_status < 400 || e._http_status > 599 ||
            (e._http_status >= 500 && e._sender_fault)) {
            return fail("an error shape has no code or an impossible status");
        }
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
        if (op._errors == 0 || (errors.size() < 64 && (op._errors >> errors.size()) != 0)) {
            return fail("an operation's error mask is empty or out of range");
        }
    }
    if (s::signing_name != "sns") {
        return fail("the pinned model no longer signs as sns");
    }
    std::printf(
        "self-test ok: %zu operations (%zu batch), %zu error shapes, API version %.*s, "
        "botocore %.*s\n",
        ops.size(), batches, errors.size(), static_cast<int>(s::api_version.size()),
        s::api_version.data(), static_cast<int>(s::botocore_version.size()),
        s::botocore_version.data());
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
