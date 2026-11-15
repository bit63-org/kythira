# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The KMS module's composition roots (.kiro/specs/kms-compatible-api/).
# kms_node is a placeholder until task 12 makes it the daemon (the KMS and
# HSM modules with an IAM replica in one node, .kiro/specs/service-colocation/).
# Like the other module daemons it runs from the build tree and is in no
# install target.

# The KMS module for kythira_node (task 5): its configuration and its
# registrar, linked whole-archive through KYTHIRA_NODE_MODULES
# (cmd/kythira_node/CMakeLists.txt). The module itself is the header
# kms_node/kms_module.hpp, over the node's Beast transport. The catalog
# keeps its state in RocksDB (raft_rocksdb_engine, CONFIG_ENGINE_ROCKSDB),
# and certificate_authority carries KYTHIRA_HAS_OPENSSL and the future
# backend, as for the HSM module; without them the module is not offered.
if(TARGET raft_rocksdb_engine AND TARGET certificate_authority
   AND KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT)
    find_package(Threads REQUIRED)
    add_library(kythira_kms_node_common STATIC kms_node/kms_config.cpp)
    target_include_directories(kythira_kms_node_common PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/kms_node")
    target_link_libraries(kythira_kms_node_common PUBLIC
        kythira_kms
        raft_rocksdb_engine     # the engine, and network_simulator (future backend)
        certificate_authority   # KYTHIRA_HAS_OPENSSL
        kythira_host_node_id    # KYTHIRA_NODE_ID_KIND
        Threads::Threads)
    target_compile_features(kythira_kms_node_common PUBLIC cxx_std_23)

    add_library(kythira_kms_module STATIC kms_node/kms_module_registrar.cpp)
    target_link_libraries(kythira_kms_module PUBLIC kythira_kms_node_common)
    set_target_properties(kythira_kms_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_kms_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES kms)
endif()

add_executable(kms_node kms_node/main.cpp)
target_link_libraries(kms_node PRIVATE kythira_kms)
target_compile_features(kms_node PRIVATE cxx_std_23)
set_target_properties(kms_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
