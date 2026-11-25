# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The khold module's composition root (.kiro/specs/khold-block-service/).
# khold_node is a placeholder until the stripe group state machine (task 7)
# and the co-located cluster (task 13) make it the daemon. Like the other
# module daemons it runs from the build tree and is in no install target.

add_executable(khold_node khold_node/main.cpp)
target_link_libraries(khold_node PRIVATE kythira_khold)
target_compile_features(khold_node PRIVATE cxx_std_23)
set_target_properties(khold_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
