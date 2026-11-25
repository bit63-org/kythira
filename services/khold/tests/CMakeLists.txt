# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The khold module's tests (.kiro/specs/khold-block-service/).
#
# Every module test carries `khold` and `khold-module`. `khold` alone is
# kept for core suites the module builds on (the Raft append sink, witness
# voters and commit predicates of tasks 3 to 5), which rightly exist with
# the module off; khold-module.yml asserts that no `khold-module` test
# exists in a module-off build.

include(kythira_test_helpers)

# Task 1: khold_node links and runs.
add_test(NAME khold_node_self_test COMMAND khold_node --self-test)
set_tests_properties(khold_node_self_test PROPERTIES
    LABELS "unit;khold;khold-module" TIMEOUT 60)

# A C++ module test: Boost.Test through add_raft_completion_test, linked to
# the module's headers.
function(kythira_khold_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_khold ${ARGN})
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "unit;khold;khold-module"
        TIMEOUT 120)
endfunction()

# Task 1, Requirements 1.4 and 11.5: antikythera's test vectors (replica
# config 4, volume layout 6, hold wire v2 frames 7 to 9, reports 10 and 11)
# reproduce byte for byte through the overlay port, signed with OpenSSL.
kythira_khold_test(khold_proto_vectors_test khold_proto_vectors_test.cpp OpenSSL::Crypto)

kythira_scale_test_timeouts()
