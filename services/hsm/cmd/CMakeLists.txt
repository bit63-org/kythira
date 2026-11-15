# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The HSM module's composition root (.kiro/specs/virtual-hsm/). hsm_node is a
# placeholder until task 11 makes it the daemon (the HSM module alone in a
# node, .kiro/specs/service-colocation/). Like the other module daemons it
# runs from the build tree and is in no install target.

add_executable(hsm_node hsm_node/main.cpp)
target_link_libraries(hsm_node PRIVATE kythira_hsm)
target_compile_features(hsm_node PRIVATE cxx_std_23)
set_target_properties(hsm_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
