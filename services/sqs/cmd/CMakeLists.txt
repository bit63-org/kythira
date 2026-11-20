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

# The durable module on multi_raft (task 4, Requirements 1.2 and 5.2),
# where the node's stack can be built: a future backend (network_simulator),
# the Beast transport, and RocksDB for the engine (raft_rocksdb_engine,
# CONFIG_ENGINE_ROCKSDB). kythira_sqs_module registers it for kythira_node
# (KYTHIRA_SERVICES=sqs), linked whole-archive through KYTHIRA_NODE_MODULES;
# sqs_node runs the same module stand-alone when KYTHIRA_NODE_DATA_DIR is
# set (KYTHIRA_SQS_NODE_DURABLE). Elsewhere sqs_node keeps its in-memory
# development mode only.
set(KYTHIRA_SQS_MODULE_AVAILABLE OFF PARENT_SCOPE)
if(TARGET raft_rocksdb_engine AND TARGET network_simulator AND TARGET kythira_host_node_id
   AND KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT AND KYTHIRA_FUTURE_BACKEND_AVAILABLE
   AND NOT ENABLE_COVERAGE)
    add_library(kythira_sqs_node_common INTERFACE)
    target_include_directories(kythira_sqs_node_common INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/sqs_node")
    target_link_libraries(kythira_sqs_node_common INTERFACE
        kythira_sqs
        raft_rocksdb_engine     # the engine
        network_simulator       # the future backend, Boost.Thread
        kythira_host_node_id    # KYTHIRA_NODE_ID_KIND
        boost_json
        OpenSSL::SSL            # the listener and forwarding
        Threads::Threads)

    add_library(kythira_sqs_module STATIC sqs_node/sqs_module_registrar.cpp)
    target_link_libraries(kythira_sqs_module PUBLIC kythira_sqs_node_common)
    target_compile_features(kythira_sqs_module PUBLIC cxx_std_23)
    set_target_properties(kythira_sqs_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_sqs_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES sqs)

    target_link_libraries(sqs_node PRIVATE kythira_sqs_node_common)
    target_compile_definitions(sqs_node PRIVATE KYTHIRA_SQS_NODE_DURABLE=1)
    set_target_properties(sqs_node PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set(KYTHIRA_SQS_MODULE_AVAILABLE ON PARENT_SCOPE)
    message(STATUS "sqs_node: durable (multi_raft on RocksDB) and in-memory modes")
else()
    message(STATUS "sqs_node: in-memory mode only (the durable module needs RocksDB, a future "
                   "backend, the Beast transport and a non-coverage build)")
endif()
