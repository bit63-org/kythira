# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS module's composition root (.kiro/specs/sqs-compatible-queues/).
# sqs_node serves the whole API on core's Beast HTTPS server, a single node
# with its queues in memory until the multi_raft module arrives
# (KYTHIRA_SQS_NODE_SERVE); --self-test runs in every build. Like the other
# module daemons it runs from the build tree and is in no install target.
# The module requires OpenSSL and Boost (KYTHIRA_BUILD_SQS), which is all
# the listener needs besides threads.

find_package(Threads REQUIRED)
add_executable(sqs_node sqs_node/main.cpp)
# network_simulator in both modes: the queue state machine is built on core's
# kv engines, whose headers include the future backend (Folly, and with it
# glog's compile definitions, or Boost.Thread).
target_link_libraries(sqs_node PRIVATE kythira_sqs network_simulator OpenSSL::SSL Threads::Threads)
target_compile_definitions(sqs_node PRIVATE KYTHIRA_SQS_NODE_SERVE=1)
target_compile_features(sqs_node PRIVATE cxx_std_23)
set_target_properties(sqs_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
