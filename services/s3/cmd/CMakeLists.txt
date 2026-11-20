# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The S3 module's composition roots (.kiro/specs/s3-compatible-storage/):
# s3_gateway_node, the daemon (tasks 16 and 16a), and the S3 module for
# kythira_node (task 16a). Like the other module daemons they run from the
# build tree and are in no install target.
#
# The object index includes the core persistence headers, which need a
# future backend: network_simulator carries the selected one (Folly, stdexec
# or Boost.Thread). The listeners are core's Beast host
# (raft/beast_https_server.hpp), header-only over Boost.Asio and OpenSSL.
# Without either the daemon is not built, and the tests that run it are not
# registered (../tests/CMakeLists.txt).
#
# The index on Raft (KYTHIRA_S3_RAFT_PEERS; s3_module.hpp, run_raft.cpp)
# keeps the group's state in RocksDB (raft_rocksdb_engine,
# CONFIG_ENGINE_ROCKSDB) and runs over the Beast Raft transport, as the
# ledger and HSM modules do; certificate_authority carries
# KYTHIRA_HAS_OPENSSL. Without them the daemon serves the index in process
# and in memory only, refuses KYTHIRA_S3_RAFT_PEERS, and kythira_node is
# not offered S3.

if(NOT KYTHIRA_FUTURE_BACKEND_AVAILABLE OR NOT Boost_FOUND)
    message(STATUS "s3_gateway_node: skipped (needs a future backend and Boost)")
    return()
endif()

find_package(Threads REQUIRED)
set(_s3_raft OFF)
if(TARGET raft_rocksdb_engine AND TARGET certificate_authority
   AND KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT)
    set(_s3_raft ON)
endif()

if(_s3_raft)
    add_executable(s3_gateway_node s3_gateway_node/main.cpp s3_gateway_node/run_raft.cpp)
else()
    add_executable(s3_gateway_node s3_gateway_node/main.cpp)
endif()
target_link_libraries(s3_gateway_node PRIVATE
    kythira_s3          # <kythira/s3/...>, the core headers, OpenSSL
    network_simulator   # the future backend
    Threads::Threads
)
if(TARGET boost_json)
    target_link_libraries(s3_gateway_node PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_gateway_node PRIVATE Boost::json)
endif()
target_compile_features(s3_gateway_node PRIVATE cxx_std_23)
set_target_properties(s3_gateway_node PROPERTIES
    JOB_POOL_COMPILE heavy_tu
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

if(_s3_raft)
    target_link_libraries(s3_gateway_node PRIVATE
        raft_rocksdb_engine     # the engine
        certificate_authority   # KYTHIRA_HAS_OPENSSL
        kythira_host_node_id)   # KYTHIRA_NODE_ID_KIND
    target_compile_definitions(s3_gateway_node PRIVATE KYTHIRA_S3_RAFT_DAEMON=1)
    message(STATUS "s3_gateway_node: the index on Raft (RocksDB, mutual TLS Raft)")

    # The S3 module for kythira_node: its registrar, linked whole-archive
    # through KYTHIRA_NODE_MODULES (cmd/kythira_node/CMakeLists.txt). The
    # module itself is the header s3_gateway_node/s3_module.hpp.
    add_library(kythira_s3_module STATIC s3_gateway_node/s3_module_registrar.cpp)
    target_include_directories(kythira_s3_module PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/s3_gateway_node")
    target_link_libraries(kythira_s3_module PUBLIC
        kythira_s3
        raft_rocksdb_engine
        certificate_authority
        kythira_host_node_id
        Threads::Threads)
    if(TARGET boost_json)
        target_link_libraries(kythira_s3_module PUBLIC boost_json)
    endif()
    target_compile_features(kythira_s3_module PUBLIC cxx_std_23)
    set_target_properties(kythira_s3_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_s3_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES s3)
else()
    message(STATUS "s3_gateway_node: the index in memory only (the index on Raft needs "
                   "RocksDB, certificate_authority and the Beast transport)")
endif()

# --help documents every setting the daemon reads.
add_test(NAME s3_gateway_node_help COMMAND s3_gateway_node --help)
set_tests_properties(s3_gateway_node_help PROPERTIES
    PASS_REGULAR_EXPRESSION "KYTHIRA_S3_WEBSITE_DOMAINS"
    LABELS "unit;s3;s3-module" TIMEOUT 30)
