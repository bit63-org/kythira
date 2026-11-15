// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// hsm_node: the virtual HSM on its own cluster (.kiro/specs/virtual-hsm/).
//
// A placeholder until task 11, which makes it kythira_node with only the HSM
// module. Today it only links the module, so the target, its build flags and
// the module boundary are exercised from task 1 on, and it reports what it is
// when asked.

#include <kythira/hsm/pkcs11.hpp>
#include <kythira/hsm/secure_arena.hpp>

#include <cstdio>
#include <string_view>

namespace {

constexpr std::string_view usage =
    "usage: hsm_node [--help | --self-test [--allow-unlocked-memory]]\n"
    "\n"
    "The Kythira virtual HSM daemon. Not implemented yet: the server arrives\n"
    "with .kiro/specs/virtual-hsm/ tasks 6-11.\n"
    "\n"
    "  --help       print this text\n"
    "  --self-test  check the vendored PKCS#11 headers and prepare key memory\n"
    "               (no core dumps, no ptrace attach, locked pages), then exit\n"
    "  --allow-unlocked-memory\n"
    "               carry on when key memory cannot be locked (RLIMIT_MEMLOCK\n"
    "               too low and no CAP_IPC_LOCK); for development only\n";

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

}  // namespace

auto main(int argc, char** argv) -> int {
    const std::string_view arg = argc > 1 ? std::string_view(argv[1]) : std::string_view();
    if (arg == "--self-test" && argc <= 3) {
        const std::string_view flag = argc == 3 ? std::string_view(argv[2]) : std::string_view();
        if (argc == 2 || flag == "--allow-unlocked-memory") {
            return self_test(argc == 3);
        }
    }
    std::fputs(usage.data(), argc == 2 && arg == "--help" ? stdout : stderr);
    return argc == 2 && arg == "--help" ? 0 : 2;
}
