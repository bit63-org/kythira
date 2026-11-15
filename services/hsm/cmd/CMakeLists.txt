# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The HSM module's composition roots (.kiro/specs/virtual-hsm/). Like the
# other module daemons they run from the build tree and are in no install
# target.

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

# hsm_node (task 11): kythira_node with only the HSM module, where the
# module and kythira_node's stack can both be built (a future backend,
# Boost, OpenSSL, the Beast transport; not a coverage build, as for
# kythira_node). Elsewhere it is the self-test only, so the target, its
# flags and the module boundary are exercised wherever the HSM builds.
add_executable(hsm_node hsm_node/main.cpp)
target_compile_features(hsm_node PRIVATE cxx_std_23)
set_target_properties(hsm_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(KYTHIRA_HSM_NODE_DAEMON OFF PARENT_SCOPE)
if(TARGET kythira_hsm_node_common AND TARGET boost_json AND NOT ENABLE_COVERAGE
   AND KYTHIRA_FUTURE_BACKEND_AVAILABLE AND Boost_FOUND AND OpenSSL_FOUND)
    target_link_libraries(hsm_node PRIVATE
        kythira_hsm_node_common
        kythira_core_headers
        boost_json
        OpenSSL::SSL
        OpenSSL::Crypto)
    target_compile_definitions(hsm_node PRIVATE KYTHIRA_HSM_NODE_DAEMON=1)
    set_target_properties(hsm_node PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set(KYTHIRA_HSM_NODE_DAEMON ON PARENT_SCOPE)
    message(STATUS "hsm_node: the daemon (kythira_node with only the HSM module)")
else()
    target_link_libraries(hsm_node PRIVATE kythira_hsm)
    message(STATUS "hsm_node: self-test only (the daemon needs the HSM module, a future "
                   "backend, Boost, OpenSSL and a non-coverage build)")
endif()

# hsm_ctl (task 7): the operator's command line, one HTTPS request per
# command to a node's operator API with the operator's certificate, and
# migrate (task 12b), which dlopens two PKCS#11 modules. It needs only the
# HSM headers (the mutual-TLS client in mtls_client.hpp, migrate.hpp),
# core's PKCS#11 wrapper, OpenSSL, Boost.JSON and libdl.
if(TARGET boost_json)
    find_package(Threads REQUIRED)
    add_executable(hsm_ctl hsm_ctl/main.cpp)
    target_link_libraries(hsm_ctl PRIVATE kythira_hsm boost_json Threads::Threads ${CMAKE_DL_LIBS})
    target_compile_features(hsm_ctl PRIVATE cxx_std_23)
    set_target_properties(hsm_ctl PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
