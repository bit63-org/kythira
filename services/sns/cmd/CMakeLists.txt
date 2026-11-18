# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SNS module's composition root (.kiro/specs/sns-compatible-notifications/).
# sns_node is a placeholder until the gateway (task 3) and the topic API
# (task 4) make it the daemon. Like the other module daemons it runs from the build
# tree and is in no install target.

add_executable(sns_node sns_node/main.cpp)
target_link_libraries(sns_node PRIVATE kythira_sns)
target_compile_features(sns_node PRIVATE cxx_std_23)
set_target_properties(sns_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
