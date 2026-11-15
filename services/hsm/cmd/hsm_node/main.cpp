// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm_node: the virtual HSM on its own cluster (.kiro/specs/virtual-hsm/).
//
// A placeholder until task 11, which makes it kythira_node with only the HSM
// module. Today it only links the module, so the target, its build flags and
// the module boundary are exercised from task 1 on, and it reports what it is
// when asked.

#include <kythira/hsm/pkcs11.hpp>

#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: hsm_node [--help | --self-test]\n"
    "\n"
    "The Kythira virtual HSM daemon. Not implemented yet: the server arrives\n"
    "with .kiro/specs/virtual-hsm/ tasks 6-11.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the vendored PKCS#11 headers, then exit\n";

auto self_test() -> int {
    const auto v = kythira::hsm::cryptoki_version;
    if (v.major != 3 || v.minor != 0) {
        std::fprintf(stderr, "self-test: PKCS#11 headers declare %u.%u, expected 3.0\n",
                     static_cast<unsigned>(v.major), static_cast<unsigned>(v.minor));
        return 1;
    }
    std::printf("self-test ok: PKCS#11 %u.%u headers\n", static_cast<unsigned>(v.major),
                static_cast<unsigned>(v.minor));
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
