# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The virtual HSM's container scenario (.kiro/specs/virtual-hsm/ task 11b,
# Requirement 13.6): three members from
# services/hsm/docker/hsm-chaos-compose.yml, stand-alone (hsm_node) and
# co-located (kythira_node with the HSM and Redis modules), under kills and
# partitions, driven by hsm_chaos_test (docker-hsm-chaos-tests).
#
# Like every container scenario it is not registered in CTest: it needs
# Docker or rootless Podman at run time and is run through its custom
# target. Entered only where hsm_node is the daemon, which needs what
# kythira_node needs, so kythira_node (defined after the services) exists
# too; it is named only in generator expressions.

include(kythira_test_helpers)
kythira_detect_container_runtime()

find_package(Threads REQUIRED)

add_docker_chaos_scenario_test(hsm_chaos_test "${CMAKE_CURRENT_SOURCE_DIR}/hsm_chaos_test.cpp")
target_include_directories(hsm_chaos_test PRIVATE "${KYTHIRA_HSM_SOURCE_DIR}/tests")
# kythira_test_support: tests/test_ports.hpp, for the published ports.
target_link_libraries(hsm_chaos_test PRIVATE kythira_hsm kythira_test_support boost_json)
set_target_properties(hsm_chaos_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/docker_chaos")

set(_HSM_CHAOS_DOCKERFILE   "${KYTHIRA_HSM_SOURCE_DIR}/docker/hsm-chaos/Dockerfile")
set(_HSM_CHAOS_DIST         "${KYTHIRA_HSM_SOURCE_DIR}/docker/hsm-chaos/dist")
set(_HSM_CHAOS_COMPOSE_FILE "${KYTHIRA_HSM_SOURCE_DIR}/docker/hsm-chaos-compose.yml")

# The co-located layout runs the HSM beside Redis; without the Redis module
# in kythira_node only the stand-alone case could run, so the target says so.
get_property(_hsm_chaos_modules GLOBAL PROPERTY KYTHIRA_NODE_MODULE_NAMES)

if(_RUNTIME_EXE AND "redis" IN_LIST _hsm_chaos_modules)
    add_custom_target(docker-hsm-chaos-image
        DEPENDS hsm_node kythira_node
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${_HSM_CHAOS_DIST}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_HSM_CHAOS_DIST}"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:hsm_node>" "${_HSM_CHAOS_DIST}/hsm_node"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:kythira_node>"
                "${_HSM_CHAOS_DIST}/kythira_node"
        COMMAND ${_RUNTIME_EXE} build ${_IMAGE_FORMAT_ARGS}
                --file "${_HSM_CHAOS_DOCKERFILE}"
                --tag kythira-hsm-chaos:dev
                "${KYTHIRA_IMAGE_CONTEXT}"
        COMMENT "Staging hsm_node and kythira_node and building kythira-hsm-chaos:dev"
        WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
    )
    add_custom_target(docker-hsm-chaos-tests
        COMMAND ${CMAKE_COMMAND} -E env
                ${_RT_ENV}
                KYTHIRA_HSM_CHAOS_COMPOSE_FILE=${_HSM_CHAOS_COMPOSE_FILE}
                KYTHIRA_HSM_CHAOS_COLOCATE=redis
                $<TARGET_FILE:hsm_chaos_test>
                --log_level=message
        DEPENDS docker-hsm-chaos-image hsm_chaos_test
        COMMENT "Running the virtual HSM chaos container scenario (runtime: ${CONTAINER_RUNTIME})"
        WORKING_DIRECTORY "${KYTHIRA_IMAGE_CONTEXT}"
    )
    message(STATUS "Container runtime: docker-hsm-chaos-image, docker-hsm-chaos-tests targets available")
else()
    if(_RUNTIME_EXE)
        set(_hsm_chaos_why "needs the redis module in kythira_node (compiled in: ${_hsm_chaos_modules})")
    else()
        set(_hsm_chaos_why "requires docker or podman on PATH")
    endif()
    foreach(_t docker-hsm-chaos-image docker-hsm-chaos-tests)
        add_custom_target(${_t}
            COMMAND ${CMAKE_COMMAND} -E echo "'${_t}' ${_hsm_chaos_why}"
            COMMAND ${CMAKE_COMMAND} -E false
        )
    endforeach()
endif()
