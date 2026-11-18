# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SNS module's tests (.kiro/specs/sns-compatible-notifications/).
#
# Every module test carries `sns` and `sns-module`. `sns` alone is kept for
# core suites the module builds on, which rightly exist with the module off;
# sns-module.yml asserts that no `sns-module` test exists in a module-off
# build.

include(kythira_test_helpers)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# The module root, set by ../CMakeLists.txt.
set(_sns_dir "${KYTHIRA_SNS_SOURCE_DIR}/")

# Task 1, Requirement 2.1: every operation of the pinned model is implemented
# or listed in doc/unsupported.md.
add_test(NAME sns_model_coverage
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tools/check_coverage.py"
            "${_sns_dir}model/service-2.json"
            "${_sns_dir}implemented-operations.txt"
            "${_sns_dir}doc/unsupported.md")
add_test(NAME sns_model_coverage_checker
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tools/test_check_coverage.py")

# Task 1: the checked-in operation table matches the model, so a model
# upgrade carries its regenerated header in the same change.
add_test(NAME sns_operations_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tools/gen_operations.py"
            "${_sns_dir}model/service-2.json"
            "${_sns_dir}include/kythira/sns/sns_operations.hpp" --check)

# Task 1: the checked-in wire evidence (evidence/README.md) is well formed,
# and every client's recording decodes to the same scenario.
add_test(NAME sns_wire_evidence
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tests/evidence/check_evidence.py"
            "${_sns_dir}model/service-2.json"
            "${_sns_dir}tests/evidence/data")

# Task 1: the real SNS HTTP deliveries (evidence/deliveries/README.md):
# headers agree with bodies and every signature verifies against the saved
# certificate. The checker's self-test signs with a throwaway key.
add_test(NAME sns_real_deliveries
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tests/evidence/deliveries/check_deliveries.py"
            "${_sns_dir}tests/evidence/deliveries/deliveries.json")
add_test(NAME sns_real_deliveries_checker
    COMMAND "${Python3_EXECUTABLE}" "${_sns_dir}tests/evidence/deliveries/check_deliveries.py"
            --self-test)

# Task 1: sns_node links and runs.
add_test(NAME sns_node_self_test COMMAND sns_node --self-test)

set_tests_properties(
    sns_model_coverage
    sns_model_coverage_checker
    sns_operations_up_to_date
    sns_wire_evidence
    sns_real_deliveries
    sns_real_deliveries_checker
    sns_node_self_test
    PROPERTIES LABELS "unit;sns;sns-module" TIMEOUT 60)

# A C++ module test: Boost.Test through add_raft_completion_test, linked to
# the module's headers.
function(kythira_sns_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_sns)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "unit;sns;sns-module"
        TIMEOUT 120)
endfunction()

# Task 2: the topic state machine (topics, subscriptions, the publish log in
# the record segment store, FIFO dedup, leases with fencing, cursors and
# retry state; property tests across replicas and a snapshot restore).
kythira_sns_test(sns_topic_state_machine_test sns_topic_state_machine_test.cpp)

kythira_scale_test_timeouts()
