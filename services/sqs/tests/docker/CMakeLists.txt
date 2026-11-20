# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS migration path in containers
# (.kiro/specs/sqs-compatible-queues/ task 11): sqs_node containers from
# compose.yml walking from three co-located nodes to three layers and back,
# with one node of every layer killed on the way, driven by
# sqs_path_scenario_test. Like every container scenario it is not
# registered in CTest: it needs Docker or rootless Podman at run time and is
# run through its custom target, docker-sqs-node-tests.

if(NOT Boost_FOUND OR NOT httplib_FOUND)
    message(STATUS "SQS container scenario skipped: requires Boost and httplib")
    return()
endif()

include(kythira_test_helpers)
kythira_detect_container_runtime()

find_package(Threads REQUIRED)

add_docker_chaos_scenario_test(sqs_path_scenario_test
    "${CMAKE_CURRENT_SOURCE_DIR}/sqs_path_scenario_test.cpp")
set_target_properties(sqs_path_scenario_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/docker_chaos")

set(_SQS_DOCKER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../docker")
set(_SQS_NODE_DIST "${_SQS_DOCKER_DIR}/sqs_node/dist")
set(_SQS_COMPOSE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/compose.yml")

if(_RUNTIME_EXE)
    # The node image is staged from the host build, as the Kinesis node's
    # is. The scenario needs the durable sqs_node, which the including
    # directory only enters this file with (KYTHIRA_SQS_MODULE_AVAILABLE,
    # never a coverage build).
    add_custom_target(docker-sqs-node-image
        DEPENDS sqs_node
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_SQS_NODE_DIST}"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:sqs_node>" "${_SQS_NODE_DIST}/sqs_node"
        COMMAND ${_RUNTIME_EXE} build ${_IMAGE_FORMAT_ARGS}
                --file "${_SQS_DOCKER_DIR}/sqs_node/Dockerfile"
                --tag kythira-sqs-node:dev
                "${KYTHIRA_IMAGE_CONTEXT}"
        COMMAND ${_RUNTIME_EXE} build ${_IMAGE_FORMAT_ARGS}
                --file "${_SQS_DOCKER_DIR}/sqs_clients/Dockerfile"
                --tag kythira-sqs-clients:dev
                "${KYTHIRA_IMAGE_CONTEXT}"
        COMMENT "Staging sqs_node and building the kythira-sqs-node and -clients :dev images"
        WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
    )

    add_custom_target(docker-sqs-node-tests
        COMMAND ${CMAKE_COMMAND} -E env
                ${_RT_ENV}
                KYTHIRA_SQS_COMPOSE_FILE=${_SQS_COMPOSE_FILE}
                $<TARGET_FILE:sqs_path_scenario_test>
                --log_level=message
        DEPENDS docker-sqs-node-image sqs_path_scenario_test
        COMMENT "Running the SQS migration-path container scenario (runtime: ${CONTAINER_RUNTIME})"
        WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
    )
    message(STATUS "Container runtime: docker-sqs-node-image, docker-sqs-node-tests targets available")
else()
    foreach(_t docker-sqs-node-image docker-sqs-node-tests)
        add_custom_target(${_t}
            COMMAND ${CMAKE_COMMAND} -E echo "'${_t}' requires docker or podman on PATH"
            COMMAND ${CMAKE_COMMAND} -E false
        )
    endforeach()
endif()
