# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Kinesis module's composition root
# (.kiro/specs/kinesis-compatible-streams/ task 6): kinesis_gateway_node,
# the daemon, and the module kythira_node runs it as
# (.kiro/specs/service-colocation/ task 5). Like the other module daemons
# it runs from the build tree and is in no install target. Its core
# *_impl.hpp includes are listed in ../boundary-allow.txt.
#
# It hosts a multi-raft cluster over Boost.Beast, so it needs what
# redis_gateway_node needs: a future backend (through network_simulator),
# Boost and OpenSSL. Not Folly: main() initialises it through
# raft/process_init.hpp only where it is linked. Not built for coverage, like
# redis_gateway_node: the instantiation is heavy and its logic is covered by
# the module's tests through the in-process cluster.

if(ENABLE_COVERAGE OR NOT KYTHIRA_FUTURE_BACKEND_AVAILABLE
   OR NOT Boost_FOUND OR NOT OpenSSL_FOUND)
    message(STATUS "kinesis_gateway_node: skipped (needs a future backend, Boost and "
                   "OpenSSL, and a non-coverage build)")
    return()
endif()

# What the daemon and the module share: the configuration, IAM's replica
# and the tier stores, with the compile definitions saying which of them
# are in, so both see one kinesis_module.hpp.
add_library(kythira_kinesis_node_common STATIC kinesis_gateway_node/config.cpp)
target_include_directories(kythira_kinesis_node_common PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/kinesis_gateway_node")
target_link_libraries(kythira_kinesis_node_common PUBLIC
    kythira_kinesis        # <kythira/kinesis/...> and the core headers
    network_simulator      # the future backend (and Folly where found), Boost::system/thread
    boost_json
    OpenSSL::SSL
    OpenSSL::Crypto
    kythira_host_node_id   # KYTHIRA_NODE_ID_KIND
)
target_compile_definitions(kythira_kinesis_node_common PUBLIC KYTHIRA_BENCH_HAS_BEAST)
target_compile_features(kythira_kinesis_node_common PUBLIC cxx_std_23)

# One multi_raft stack per translation unit: run_host.cpp alone holds it.
add_executable(kinesis_gateway_node
    kinesis_gateway_node/main.cpp
    kinesis_gateway_node/run_host.cpp
)
target_link_libraries(kinesis_gateway_node PRIVATE kythira_kinesis_node_common)
set_target_properties(kinesis_gateway_node PROPERTIES
    JOB_POOL_COMPILE heavy_tu
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# IAM authentication (DynamoDB spec task 28, KINESIS_AUTH=iam|both): the
# composition root wires in the IAM module's embedded replica and
# authorizer, as redis_gateway_node and dynamodb_gateway_node do. Without
# CONFIG_KINESIS_GATEWAY_IAM the daemon has no IAM code, documents no
# KYTHIRA_IAM_* variables, and refuses iam and both at start.
set(_KINESIS_GATEWAY_IAM OFF)
if(KCONFIG_KINESIS_GATEWAY_IAM AND KYTHIRA_BUILD_IAM AND TARGET certificate_authority)
    set(_KINESIS_GATEWAY_IAM ON)
    target_sources(kythira_kinesis_node_common PRIVATE kinesis_gateway_node/iam_auth.cpp)
    target_compile_definitions(kythira_kinesis_node_common PUBLIC KYTHIRA_KINESIS_GATEWAY_IAM)
    # kythira_iam is defined by services/iam/, which the top level may enter
    # after this module; CMake resolves the name when it generates.
    target_link_libraries(kythira_kinesis_node_common PUBLIC kythira_iam certificate_authority)
endif()
add_test(NAME kinesis_gateway_node_iam_switch COMMAND kinesis_gateway_node --help)
if(_KINESIS_GATEWAY_IAM)
    set_tests_properties(kinesis_gateway_node_iam_switch PROPERTIES
        PASS_REGULAR_EXPRESSION "KYTHIRA_IAM_VOTERS")
else()
    set_tests_properties(kinesis_gateway_node_iam_switch PROPERTIES
        FAIL_REGULAR_EXPRESSION "KYTHIRA_IAM_")
endif()
set_tests_properties(kinesis_gateway_node_iam_switch PROPERTIES
    LABELS "unit;kinesis;kinesis-module" TIMEOUT 30)

# Tiering (task 10), tier.hpp: tier.cpp picks the provider named by
# KINESIS_TIER_PROVIDER from those compiled in, and the clients sit in
# tier_s3.cpp and tier_cloud.cpp alone so no other unit parses an SDK
# header. A provider is in when its dependency was found and, for all but
# S3, its persistence Kconfig gate is on, the conditions ca_cluster_node's
# --oidc-publish-url and raft_object_backup use. S3 keeps its original
# condition, the AWS SDK's s3 component, so builds that tiered before
# still do. The daemon refuses KINESIS_TIER_BUCKET at startup for a
# provider it lacks, naming what would enable it, and keeps every segment
# on disk.
target_sources(kythira_kinesis_node_common PRIVATE kinesis_gateway_node/tier.cpp)
if(AWSSDK_FOUND)
    find_package(AWSSDK QUIET COMPONENTS core s3)
endif()
set(_KINESIS_TIER_PROVIDERS "")
if(AWSSDK_FOUND)
    list(FIND AWSSDK_LINK_LIBRARIES aws-cpp-sdk-s3 _KINESIS_S3_LIB)
    if(NOT _KINESIS_S3_LIB EQUAL -1)
        target_sources(kythira_kinesis_node_common PRIVATE kinesis_gateway_node/tier_s3.cpp)
        target_link_libraries(kythira_kinesis_node_common PUBLIC ${AWSSDK_LINK_LIBRARIES})
        target_compile_definitions(kythira_kinesis_node_common PUBLIC KYTHIRA_KINESIS_TIER_S3)
        list(APPEND _KINESIS_TIER_PROVIDERS s3)
    endif()
endif()
set(_KINESIS_TIER_CLOUD FALSE)
if(azure-core-cpp_FOUND AND azure-identity-cpp_FOUND AND _KYTHIRA_GATE_AZURE_BLOB_PERSISTENCE)
    target_compile_definitions(kythira_kinesis_node_common PUBLIC
        KYTHIRA_KINESIS_TIER_AZURE KYTHIRA_HAS_AZURE_SDK)
    target_link_libraries(kythira_kinesis_node_common PUBLIC
        Azure::azure-core Azure::azure-identity)
    list(APPEND _KINESIS_TIER_PROVIDERS azure-blob)
    set(_KINESIS_TIER_CLOUD TRUE)
endif()
if(TARGET google-cloud-cpp::storage AND _KYTHIRA_GATE_GCP_STORAGE_PERSISTENCE)
    target_compile_definitions(kythira_kinesis_node_common PUBLIC
        KYTHIRA_KINESIS_TIER_GCS KYTHIRA_HAS_GCP_STORAGE)
    target_link_libraries(kythira_kinesis_node_common PUBLIC google-cloud-cpp::storage)
    list(APPEND _KINESIS_TIER_PROVIDERS gcs)
    set(_KINESIS_TIER_CLOUD TRUE)
endif()
if(KYTHIRA_OCI_SHARED AND _KYTHIRA_GATE_OCI_OBJECT_PERSISTENCE)
    target_compile_definitions(kythira_kinesis_node_common PUBLIC KYTHIRA_KINESIS_TIER_OCI)
    list(APPEND _KINESIS_TIER_PROVIDERS oci-objectstorage)
    set(_KINESIS_TIER_CLOUD TRUE)
endif()
if(KYTHIRA_ALIBABA_SHARED AND _KYTHIRA_GATE_ALIBABA_OSS_PERSISTENCE)
    target_compile_definitions(kythira_kinesis_node_common PUBLIC KYTHIRA_KINESIS_TIER_OSS)
    list(APPEND _KINESIS_TIER_PROVIDERS oss)
    set(_KINESIS_TIER_CLOUD TRUE)
endif()
if(_KINESIS_TIER_CLOUD)
    target_sources(kythira_kinesis_node_common PRIVATE kinesis_gateway_node/tier_cloud.cpp)
    target_link_libraries(kythira_kinesis_node_common PUBLIC httplib::httplib)
endif()
if(_KINESIS_TIER_PROVIDERS)
    list(JOIN _KINESIS_TIER_PROVIDERS ", " _KINESIS_TIER_TEXT)
    message(STATUS "kinesis_gateway_node: tiering to ${_KINESIS_TIER_TEXT}")
else()
    message(STATUS "kinesis_gateway_node: tiering unavailable (no object store client in this build)")
endif()

# The Kinesis module for kythira_node (.kiro/specs/service-colocation/
# task 5): its registrar, linked whole-archive through KYTHIRA_NODE_MODULES
# (cmd/kythira_node/CMakeLists.txt). It instantiates the module over the
# node's Beast transport.
if(KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT)
    add_library(kythira_kinesis_module STATIC kinesis_gateway_node/kinesis_module_registrar.cpp)
    target_link_libraries(kythira_kinesis_module PUBLIC kythira_kinesis_node_common)
    set_target_properties(kythira_kinesis_module PROPERTIES JOB_POOL_COMPILE heavy_tu)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_kinesis_module)
    set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES kinesis)
endif()
