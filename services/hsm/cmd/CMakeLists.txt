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

# The HSM module for kythira_node (task 6e): its configuration and its
# registrar, linked whole-archive through KYTHIRA_NODE_MODULES
# (cmd/kythira_node/CMakeLists.txt). The module itself is the header
# hsm_node/hsm_module.hpp, over the node's Beast transport. Its groups keep
# their state in RocksDB (raft_rocksdb_engine, CONFIG_ENGINE_ROCKSDB), and
# certificate_authority carries KYTHIRA_HAS_OPENSSL and the future backend,
# as for the ledger module; without them the module is not offered.
if(TARGET raft_rocksdb_engine AND TARGET certificate_authority
   AND KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT)
    find_package(Threads REQUIRED)
    add_library(kythira_hsm_node_common STATIC hsm_node/hsm_config.cpp)
    target_include_directories(kythira_hsm_node_common PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/hsm_node")
    target_link_libraries(kythira_hsm_node_common PUBLIC
        kythira_hsm
        raft_rocksdb_engine     # the engine, and network_simulator (future backend)
        certificate_authority   # KYTHIRA_HAS_OPENSSL
        kythira_host_node_id    # KYTHIRA_NODE_ID_KIND
        Threads::Threads)
    target_compile_features(kythira_hsm_node_common PUBLIC cxx_std_23)
    if(TARGET boost_json)
        target_link_libraries(kythira_hsm_node_common PUBLIC boost_json)  # the admin API
    endif()

    add_library(kythira_hsm_module STATIC hsm_node/hsm_module_registrar.cpp)
    target_link_libraries(kythira_hsm_module PUBLIC kythira_hsm_node_common)
    set_target_properties(kythira_hsm_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_hsm_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES hsm)
endif()

# hsm_ctl (task 7): the operator's command line, one HTTPS request per
# command to a node's operator API with the operator's certificate. It
# needs only the HSM headers (the mutual-TLS client in mtls_client.hpp),
# OpenSSL and Boost.JSON.
if(TARGET boost_json)
    find_package(Threads REQUIRED)
    add_executable(hsm_ctl hsm_ctl/main.cpp)
    target_link_libraries(hsm_ctl PRIVATE kythira_hsm boost_json Threads::Threads)
    target_compile_features(hsm_ctl PRIVATE cxx_std_23)
    set_target_properties(hsm_ctl PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
