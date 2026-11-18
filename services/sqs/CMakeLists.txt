# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Amazon SQS-compatible module: the operation table from the pinned
# botocore model, sqs_node, and later the gateway, front end and queue state
# machine (.kiro/specs/sqs-compatible-queues/, services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_SQS is on (CONFIG_SQS,
# services/sqs/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and variables
# this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/sqs/...>. Header-only, like the other
# modules. OpenSSL for SigV4, MD5 digests and receipt-handle HMACs
# (KYTHIRA_BUILD_SQS requires it).
set(KYTHIRA_SQS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_SQS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_sqs INTERFACE)
target_include_directories(kythira_sqs INTERFACE "${KYTHIRA_SQS_INCLUDE_DIR}")
target_link_libraries(kythira_sqs INTERFACE kythira_core_headers OpenSSL::Crypto)
target_compile_features(kythira_sqs INTERFACE cxx_std_23)

# sqs_node (task 1 placeholder; the daemon grows from task 3 on), before the
# tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
