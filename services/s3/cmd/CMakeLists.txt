# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The S3 module's composition root (.kiro/specs/s3-compatible-storage/).
# s3_gateway_node is a placeholder until the gateway (task 6) and the data
# path (task 5) make it the daemon. Like the other module daemons it runs
# from the build tree and is in no install target.

add_executable(s3_gateway_node s3_gateway_node/main.cpp)
target_link_libraries(s3_gateway_node PRIVATE kythira_s3)
target_compile_features(s3_gateway_node PRIVATE cxx_std_23)
set_target_properties(s3_gateway_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
