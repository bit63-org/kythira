# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The KMS-compatible module: so far the pinned botocore model, its generated
# shape tables, the coverage check and the kms_node placeholder; the
# catalog, the HSM binding and the API follow
# (.kiro/specs/kms-compatible-api/, services/README.md).
#
# Entered from the top level only when KYTHIRA_BUILD_KMS is on (CONFIG_KMS,
# services/kms/Kconfig), after the core targets, tests/ and the HSM and IAM
# modules it depends on, so every target and helper used here already
# exists. The core targets and variables this file and its subdirectories
# use are listed in README.md.

# The module's headers, as <kythira/kms/...>. Header-only for now. Boost.JSON
# for the model's codec (raft/aws_json_protocol.hpp).
set(KYTHIRA_KMS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KYTHIRA_KMS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(kythira_kms INTERFACE)
target_include_directories(kythira_kms INTERFACE "${KYTHIRA_KMS_INCLUDE_DIR}")
# ${CMAKE_DL_LIBS}: core's pkcs11::function_list_backend dlopens an external
# PKCS#11 module (Requirement 4.3).
target_link_libraries(kythira_kms INTERFACE kythira_core_headers boost_json OpenSSL::Crypto
    ${CMAKE_DL_LIBS})
target_compile_features(kythira_kms INTERFACE cxx_std_23)

# kms_node (task 1 placeholder; the daemon is task 12), before the tests,
# which run it.
add_subdirectory(cmd)

# The tests, under the guard the top level enters tests/ with. tests/
# defines kythira_test_pch, which add_raft_completion_test links, so its
# presence is the check.
if(TARGET kythira_test_pch)
    add_subdirectory(tests)
endif()
