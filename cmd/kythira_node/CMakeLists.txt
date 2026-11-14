# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# kythira_node, the composite daemon (.kiro/specs/service-colocation/
# task 3): the services named in KYTHIRA_SERVICES, from those compiled in,
# on one Beast Raft listener. Entered from the top level after every
# services/ module, so each module's library exists when it is linked.
#
# A module joins the node by appending its library to the global property
# KYTHIRA_NODE_MODULES:
#
#   set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULES kythira_<m>_module)
#   set_property(GLOBAL APPEND PROPERTY KYTHIRA_NODE_MODULE_NAMES <m>)
#
# The second names the service as KYTHIRA_SERVICES does, so a test below
# checks that the linked node really offers it.
#
# The library holds the module's adapter and its one
# module_registrar<kythira_node_host> (include/raft/kythira_node_host.hpp).
# It is linked whole-archive, because nothing in the node names the
# registrar and the linker would otherwise drop it; so adding a module
# changes nothing here (Requirement 1.3).

if(ENABLE_COVERAGE OR NOT KYTHIRA_FUTURE_BACKEND_AVAILABLE OR NOT Boost_FOUND
   OR NOT OpenSSL_FOUND OR NOT KYTHIRA_BUILD_BOOST_BEAST_TRANSPORT)
    message(STATUS "kythira_node: skipped (needs a future backend, Boost, OpenSSL, the Beast "
                   "transport and a non-coverage build)")
    return()
endif()

add_executable(kythira_node main.cpp)
target_link_libraries(kythira_node PRIVATE
    kythira_core_headers
    network_simulator      # Folly, boost_context, Boost::system/thread
    boost_json
    OpenSSL::SSL
    OpenSSL::Crypto
    kythira_host_node_id   # KYTHIRA_NODE_ID_KIND
)
get_property(_kythira_node_modules GLOBAL PROPERTY KYTHIRA_NODE_MODULES)
foreach(_m IN LISTS _kythira_node_modules)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
        target_link_libraries(kythira_node PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,${_m}>")
    else()
        target_link_libraries(kythira_node PRIVATE -Wl,--whole-archive ${_m} -Wl,--no-whole-archive)
    endif()
endforeach()
target_compile_features(kythira_node PRIVATE cxx_std_23)
set_target_properties(kythira_node PROPERTIES
    JOB_POOL_COMPILE heavy_tu
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
if(TARGET host_binaries)
    add_dependencies(host_binaries kythira_node)
endif()

# Requirement 2.1: --help lists the compiled-in services, and naming one
# that is not compiled in is a startup error that lists them.
add_test(NAME kythira_node_help COMMAND kythira_node --help)
set_tests_properties(kythira_node_help PROPERTIES
    PASS_REGULAR_EXPRESSION "Compiled-in services"
    TIMEOUT 30 LABELS "unit;node")
add_test(NAME kythira_node_unknown_service COMMAND kythira_node)
set_tests_properties(kythira_node_unknown_service PROPERTIES
    ENVIRONMENT "KYTHIRA_SERVICES=no-such-service;KYTHIRA_NODE_ID=1;KYTHIRA_NODE_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/unknown-service;KYTHIRA_NODE_INSECURE_PLAINTEXT=1"
    PASS_REGULAR_EXPRESSION "service 'no-such-service' is not compiled in; compiled in: "
    TIMEOUT 30 LABELS "unit;node")
get_property(_kythira_node_module_names GLOBAL PROPERTY KYTHIRA_NODE_MODULE_NAMES)
foreach(_name IN LISTS _kythira_node_module_names)
    add_test(NAME kythira_node_offers_${_name} COMMAND kythira_node --help)
    set_tests_properties(kythira_node_offers_${_name} PROPERTIES
        PASS_REGULAR_EXPRESSION "\n  ${_name}  \\("
        TIMEOUT 30 LABELS "unit;node")
endforeach()

# IAM as a module beside Kinesis (.kiro/specs/service-colocation/ task 8):
# three kythira_node processes, Kinesis authorizing through the IAM
# module's in-process evaluator. Registered here, after every service
# directory, because it needs both modules' targets and this binary.
if(TARGET kythira_iam_module AND TARGET kythira_kinesis_module AND TARGET iam_node  # module-hook
   AND TARGET kythira-iam)  # module-hook: the node test needs IAM's tools
    add_raft_completion_test(kythira_node_iam_test
        "${PROJECT_SOURCE_DIR}/services/iam/tests/kythira_node_iam_test.cpp")
    target_include_directories(kythira_node_iam_test PRIVATE
        "${PROJECT_SOURCE_DIR}/services/iam/tests")
    target_link_libraries(kythira_node_iam_test PRIVATE
        kythira_iam kythira_test_support certificate_authority kythira_host_node_id)  # module-hook
    target_compile_definitions(kythira_node_iam_test PRIVATE
        IAM_NODE_PATH="$<TARGET_FILE:iam_node>"  # module-hook
        KYTHIRA_IAM_PATH="$<TARGET_FILE:kythira-iam>"  # module-hook
        KYTHIRA_NODE_PATH="$<TARGET_FILE:kythira_node>")
    add_dependencies(kythira_node_iam_test kythira_node)
    set_target_properties(kythira_node_iam_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(kythira_node_iam_test PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "integration;iam;iam-module;node" TIMEOUT 600)
endif()

# Every compiled-in module on one three-node cluster (.kiro/specs/
# service-colocation/ task 11, Requirement 10.1): each service's smoke test
# against the same kythira_node processes. The test reads the module list
# from `kythira_node --help`, so it runs in any build with the IAM module,
# which issues its test PKI and authorizes Kinesis and DynamoDB, so its
# source lives with IAM's tests, beside kythira_node_iam_test; a module test
# may include no other module, so the Kinesis, DynamoDB, Redis and ledger
# checks speak each wire directly.
if(TARGET kythira_iam_module AND TARGET iam_node AND TARGET kythira-iam)  # module-hook
    add_raft_completion_test(kythira_node_cluster_test
        "${PROJECT_SOURCE_DIR}/services/iam/tests/kythira_node_cluster_test.cpp")
    target_include_directories(kythira_node_cluster_test PRIVATE
        "${PROJECT_SOURCE_DIR}/services/iam/tests")
    target_link_libraries(kythira_node_cluster_test PRIVATE
        kythira_iam kythira_test_support certificate_authority kythira_host_node_id)  # module-hook
    target_compile_definitions(kythira_node_cluster_test PRIVATE
        IAM_NODE_PATH="$<TARGET_FILE:iam_node>"  # module-hook
        KYTHIRA_IAM_PATH="$<TARGET_FILE:kythira-iam>"  # module-hook
        KYTHIRA_NODE_PATH="$<TARGET_FILE:kythira_node>")
    add_dependencies(kythira_node_cluster_test kythira_node)
    set_target_properties(kythira_node_cluster_test PROPERTIES
        JOB_POOL_COMPILE heavy_tu
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(kythira_node_cluster_test PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "integration;node" TIMEOUT 900)
endif()

# The kythira_node image and the composite cluster's container scenario
# (.kiro/specs/service-colocation/ task 10, Requirements 9 and 10.3):
# docker/kythira_node/Dockerfile carries kythira_node with every module this
# build linked, plus IAM's admin CLI and test PKI tool when the IAM module
# is built; docker/kythira-node-compose.yml runs three nodes with DynamoDB,
# Kinesis and IAM, and kythira_node_scenario_test drives a mixed workload
# through a node kill and a partition. Like every container scenario it is
# not registered in CTest: it needs Docker or rootless Podman at run time
# and runs through its custom target, docker-kythira-node-tests.
if(httplib_FOUND)
    include(kythira_test_helpers)
    kythira_detect_container_runtime()
    add_docker_chaos_scenario_test(kythira_node_scenario_test
        "${CMAKE_CURRENT_SOURCE_DIR}/kythira_node_scenario_test.cpp")
    set_target_properties(kythira_node_scenario_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/docker_chaos")

    set(_KN_DIST "${PROJECT_SOURCE_DIR}/docker/kythira_node/dist")
    set(_KN_COMPOSE_FILE "${PROJECT_SOURCE_DIR}/docker/kythira-node-compose.yml")
    # The IAM tools ride along when the IAM module is built; the dist
    # directory is emptied first so the image never carries a stale one.
    set(_KN_STAGE_DEPS kythira_node)
    set(_KN_STAGE_COPIES)
    foreach(_tool kythira-iam iam_test_certs)  # module-hook: IAM's tools
        if(TARGET ${_tool})
            list(APPEND _KN_STAGE_DEPS ${_tool})
            list(APPEND _KN_STAGE_COPIES
                COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${_tool}>" "${_KN_DIST}/${_tool}")
        endif()
    endforeach()
    if(_RUNTIME_EXE)
        add_custom_target(docker-kythira-node-image
            DEPENDS ${_KN_STAGE_DEPS}
            COMMAND ${CMAKE_COMMAND} -E rm -rf "${_KN_DIST}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${_KN_DIST}"
            COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:kythira_node>"
                    "${_KN_DIST}/kythira_node"
            ${_KN_STAGE_COPIES}
            COMMAND ${_RUNTIME_EXE} build ${_IMAGE_FORMAT_ARGS}
                    --file "${PROJECT_SOURCE_DIR}/docker/kythira_node/Dockerfile"
                    --tag kythira-node:dev
                    "${KYTHIRA_IMAGE_CONTEXT}"
            COMMAND ${_RUNTIME_EXE} build ${_IMAGE_FORMAT_ARGS}
                    --file "${PROJECT_SOURCE_DIR}/docker/kythira_node_clients/Dockerfile"
                    --tag kythira-node-clients:dev
                    "${KYTHIRA_IMAGE_CONTEXT}"
            COMMENT "Staging kythira_node (and IAM's tools) and building the kythira-node and kythira-node-clients :dev images"
            WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
        )
        # The scenario needs the three modules it drives.
        set(_KN_SCENARIO_MODULES iam kinesis dynamodb)
        set(_KN_SCENARIO_OK TRUE)
        foreach(_m IN LISTS _KN_SCENARIO_MODULES)
            if(NOT _m IN_LIST _kythira_node_module_names)
                set(_KN_SCENARIO_OK FALSE)
            endif()
        endforeach()
        if(_KN_SCENARIO_OK AND TARGET iam_test_certs AND TARGET kythira-iam)  # module-hook
            add_custom_target(docker-kythira-node-tests
                COMMAND ${CMAKE_COMMAND} -E env
                        ${_RT_ENV}
                        KYTHIRA_NODE_COMPOSE_FILE=${_KN_COMPOSE_FILE}
                        $<TARGET_FILE:kythira_node_scenario_test>
                        --log_level=message
                DEPENDS docker-kythira-node-image kythira_node_scenario_test
                COMMENT "Running the composite cluster container scenario (runtime: ${CONTAINER_RUNTIME})"
                WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
            )
        else()
            add_custom_target(docker-kythira-node-tests
                COMMAND ${CMAKE_COMMAND} -E echo
                        "'docker-kythira-node-tests' requires the iam, kinesis and dynamodb modules in kythira_node (compiled in: ${_kythira_node_module_names})"
                COMMAND ${CMAKE_COMMAND} -E false
            )
        endif()
    else()
        foreach(_t docker-kythira-node-image docker-kythira-node-tests)
            add_custom_target(${_t}
                COMMAND ${CMAKE_COMMAND} -E echo "'${_t}' requires docker or podman on PATH"
                COMMAND ${CMAKE_COMMAND} -E false
            )
        endforeach()
    endif()
endif()
