# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Amazon EC2-compatible module: the operation table from the pinned
# botocore model, ec2_node, and later the gateway, front end, data-layer
# state machines, workflows and the fleet link to antikythera's helm
# (.kiro/specs/ec2-compatible-api/, services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_EC2 is on (CONFIG_EC2,
# services/ec2/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and variables
# this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/ec2/...>. Header-only, like the other
# modules. OpenSSL for SigV4 and the link's TLS (KYTHIRA_BUILD_EC2 requires
# it).
set(KYTHIRA_EC2_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_EC2_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_ec2 INTERFACE)
target_include_directories(kythira_ec2 INTERFACE "${KYTHIRA_EC2_INCLUDE_DIR}")
target_link_libraries(kythira_ec2 INTERFACE kythira_core_headers OpenSSL::Crypto)
target_compile_features(kythira_ec2 INTERFACE cxx_std_23)

# ec2_node (task 1 placeholder; the daemon grows from task 3 on), before the
# tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
