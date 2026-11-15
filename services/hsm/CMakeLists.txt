# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The virtual HSM module (.kiro/specs/virtual-hsm/, services/README.md):
# the header-only library, its kythira_node module, the stand-alone
# hsm_node, hsm_ctl, libkythira_pkcs11.so and the tests.
#
# Entered from the top level only when KYTHIRA_BUILD_HSM is on (CONFIG_HSM,
# services/hsm/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and variables
# this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/hsm/...>, and the vendored OASIS headers,
# which only <kythira/hsm/pkcs11.hpp> includes. Header-only for now. OpenSSL
# for every mechanism (KYTHIRA_BUILD_HSM requires it), and its TLS library
# for forwarding between members (hsm_peer.hpp).
set(KYTHIRA_HSM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_HSM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_hsm INTERFACE)
target_include_directories(kythira_hsm INTERFACE "${KYTHIRA_HSM_INCLUDE_DIR}")
# SYSTEM: third-party headers, kept out of the warning flags and clang-tidy.
target_include_directories(kythira_hsm SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pkcs11")
target_link_libraries(kythira_hsm INTERFACE kythira_core_headers OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(kythira_hsm INTERFACE cxx_std_23)

# hsm_node (the daemon, task 11) and the module, before the tests,
# which run it.
add_subdirectory(cmd)

# libkythira_pkcs11.so (task 10), before the tests, which load it.
add_subdirectory(pkcs11)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
