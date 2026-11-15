# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The KMS module's composition root (.kiro/specs/kms-compatible-api/).
# kms_node is a placeholder until task 12 makes it the daemon (the KMS and
# HSM modules with an IAM replica in one node, .kiro/specs/service-colocation/).
# Like the other module daemons it runs from the build tree and is in no
# install target.

add_executable(kms_node kms_node/main.cpp)
target_link_libraries(kms_node PRIVATE kythira_kms)
target_compile_features(kms_node PRIVATE cxx_std_23)
set_target_properties(kms_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
