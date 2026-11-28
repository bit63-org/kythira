# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The EC2 module's composition root (.kiro/specs/ec2-compatible-api/).
# ec2_node is a placeholder until the gateway (task 3) and the data and fleet
# layers make it the daemon. Like the other module daemons it runs from the
# build tree and is in no install target.

add_executable(ec2_node ec2_node/main.cpp)
target_link_libraries(ec2_node PRIVATE kythira_ec2)
target_compile_features(ec2_node PRIVATE cxx_std_23)
set_target_properties(ec2_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
