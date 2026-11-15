// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// kms_node: the KMS-compatible service on its own cluster
// (.kiro/specs/kms-compatible-api/).
//
// A placeholder until task 12, which makes it a node with the KMS module,
// the HSM module and an IAM replica. Today it only links the module, so the
// target, its build flags and the module boundary are exercised from task 1
// on, and it checks the generated model when asked.

#include <kythira/kms/model/kms_model.hpp>

#include <raft/aws_json_protocol.hpp>

#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: kms_node [--help | --self-test]\n"
    "\n"
    "The Kythira KMS-compatible service daemon. Not implemented yet: the\n"
    "server arrives with .kiro/specs/kms-compatible-api/ tasks 5-12.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the generated KMS model, then exit\n";

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

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (argc == 2 && arg == "--self-test") {
        return self_test();
    }
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
