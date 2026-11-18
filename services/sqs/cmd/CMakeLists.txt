# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS module's composition root (.kiro/specs/sqs-compatible-queues/).
# sqs_node is a placeholder until the gateway (task 3) and queue API (task 4)
# make it the daemon. Like the other module daemons it runs from the build
# tree and is in no install target.

add_executable(sqs_node sqs_node/main.cpp)
target_link_libraries(sqs_node PRIVATE kythira_sqs)
target_compile_features(sqs_node PRIVATE cxx_std_23)
set_target_properties(sqs_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
