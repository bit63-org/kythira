# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Amazon SNS-compatible module: the operation table from the pinned
# botocore model, sns_node, and later the gateway, front end, topic state
# machine and delivery workers (.kiro/specs/sns-compatible-notifications/,
# services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_SNS is on (CONFIG_SNS,
# services/sns/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and variables
# this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/sns/...>. Header-only, like the other
# modules. OpenSSL for SigV4 and message signatures (KYTHIRA_BUILD_SNS
# requires it).
set(KYTHIRA_SNS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_SNS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_sns INTERFACE)
target_include_directories(kythira_sns INTERFACE "${KYTHIRA_SNS_INCLUDE_DIR}")
target_link_libraries(kythira_sns INTERFACE kythira_core_headers OpenSSL::Crypto)
target_compile_features(kythira_sns INTERFACE cxx_std_23)

# sns_node (task 1 placeholder; the daemon grows from task 3 on), before the
# tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
