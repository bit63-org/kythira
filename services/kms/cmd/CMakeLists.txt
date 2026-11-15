# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The KMS module's composition roots (.kiro/specs/kms-compatible-api/).
# kms_node is the daemon (the KMS and HSM modules with an IAM replica in
# one node, .kiro/specs/service-colocation/).
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
        OpenSSL::SSL            # the API listener (beast_https_server.hpp)
        Threads::Threads)
    target_compile_features(kythira_kms_node_common PUBLIC cxx_std_23)

    add_library(kythira_kms_module STATIC kms_node/kms_module_registrar.cpp)
    target_link_libraries(kythira_kms_module PUBLIC kythira_kms_node_common)
    set_target_properties(kythira_kms_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_kms_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES kms)
endif()

# kms_node (task 12): kythira_node with the KMS module and, when they are
# built, the HSM module and an IAM replica, all from the global catalog
# (services/hsm and services/iam are entered before this directory, so
# their module targets exist here). Linked whole-archive, as kythira_node
# links them, where the node's stack can be built (a future backend,
# Boost, OpenSSL, the Beast transport; not a coverage build). Elsewhere it
# is the self-test only, so the target, its flags and the module boundary
# are exercised wherever the KMS builds.
add_executable(kms_node kms_node/main.cpp)
target_compile_features(kms_node PRIVATE cxx_std_23)
set_target_properties(kms_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(KYTHIRA_KMS_NODE_DAEMON OFF PARENT_SCOPE)
if(TARGET kythira_kms_module AND TARGET boost_json AND NOT ENABLE_COVERAGE
   AND KYTHIRA_FUTURE_BACKEND_AVAILABLE AND Boost_FOUND AND OpenSSL_FOUND)
    target_link_libraries(kms_node PRIVATE
        kythira_kms_node_common
        kythira_core_headers
        boost_json
        OpenSSL::SSL
        OpenSSL::Crypto)
    foreach(_m IN ITEMS kythira_kms_module kythira_hsm_module kythira_iam_module)
        if(TARGET ${_m})
            if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
                target_link_libraries(kms_node PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,${_m}>")
            else()
                target_link_libraries(kms_node PRIVATE
                    -Wl,--whole-archive ${_m} -Wl,--no-whole-archive)
            endif()
        endif()
    endforeach()
    target_compile_definitions(kms_node PRIVATE KYTHIRA_KMS_NODE_DAEMON=1)
    set_target_properties(kms_node PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set(KYTHIRA_KMS_NODE_DAEMON ON PARENT_SCOPE)
    message(STATUS "kms_node: the daemon (kythira_node with the KMS, HSM and IAM modules)")
else()
    target_link_libraries(kms_node PRIVATE kythira_kms)
    message(STATUS "kms_node: self-test only (the daemon needs the KMS module, a future "
                   "backend, Boost, OpenSSL and a non-coverage build)")
endif()
