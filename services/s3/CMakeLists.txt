# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Amazon S3-compatible module: the operation table from the pinned
# botocore model, s3_gateway_node, and later the gateway, front end, object
# index and blob store (.kiro/specs/s3-compatible-storage/,
# services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_S3 is on (CONFIG_S3,
# services/s3/Kconfig), after the core targets and tests/, so every core
# target and helper used here already exists. The core targets and
# variables this file and its subdirectories use are listed in README.md.

# The module's headers, as <kythira/s3/...>. Header-only, like the other
# modules. OpenSSL for SigV4, chunk digests and server-side encryption
# (KYTHIRA_BUILD_S3 requires it).
set(KYTHIRA_S3_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_S3_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_s3 INTERFACE)
target_include_directories(kythira_s3 INTERFACE "${KYTHIRA_S3_INCLUDE_DIR}")
target_link_libraries(kythira_s3 INTERFACE kythira_core_headers OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(kythira_s3 INTERFACE cxx_std_23)

# s3_gateway_node (task 1 placeholder), before the tests, which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
