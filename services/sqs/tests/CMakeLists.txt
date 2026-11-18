# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The SQS module's tests (.kiro/specs/sqs-compatible-queues/).
#
# Every module test carries `sqs` and `sqs-module`. `sqs` alone is kept for
# core suites the module builds on, which rightly exist with the module off;
# sqs-module.yml asserts that no `sqs-module` test exists in a module-off
# build.

include(kythira_test_helpers)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# The module root, set by ../CMakeLists.txt.
set(_sqs_dir "${KYTHIRA_SQS_SOURCE_DIR}/")

# add_raft_completion_test plus the module's headers. Binaries and working
# directories go to build/tests/, which the coverage job collects test
# binaries from, as the other modules' do.
function(kythira_sqs_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_sqs)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "unit;sqs;sqs-module" TIMEOUT 120)
endfunction()

# Task 1, Requirement 2.1: every operation of the pinned model is implemented
# or listed in doc/unsupported.md.
add_test(NAME sqs_model_coverage
    COMMAND "${Python3_EXECUTABLE}" "${_sqs_dir}tools/check_coverage.py"
            "${_sqs_dir}model/service-2.json"
            "${_sqs_dir}implemented-operations.txt"
            "${_sqs_dir}doc/unsupported.md")
add_test(NAME sqs_model_coverage_checker
    COMMAND "${Python3_EXECUTABLE}" "${_sqs_dir}tools/test_check_coverage.py")

# Task 1: the checked-in operation table matches the model, so a model
# upgrade carries its regenerated header in the same change.
add_test(NAME sqs_operations_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_sqs_dir}tools/gen_operations.py"
            "${_sqs_dir}model/service-2.json"
            "${_sqs_dir}include/kythira/sqs/sqs_operations.hpp" --check)

# Task 1: the checked-in wire evidence (evidence/README.md) is well formed,
# names only model operations and shows every scenario finishing.
add_test(NAME sqs_wire_evidence
    COMMAND "${Python3_EXECUTABLE}" "${_sqs_dir}tests/evidence/check_evidence.py"
            "${_sqs_dir}model/service-2.json"
            "${_sqs_dir}tests/evidence/data")

# Task 1: sqs_node links and runs.
add_test(NAME sqs_node_self_test COMMAND sqs_node --self-test)

set_tests_properties(
    sqs_model_coverage
    sqs_model_coverage_checker
    sqs_operations_up_to_date
    sqs_wire_evidence
    sqs_node_self_test
    PROPERTIES LABELS "unit;sqs;sqs-module" TIMEOUT 60)

# Task 2: the queue state machine (Requirements 4.2, 4.3, 5.2, 5.4-5.7) on
# memory_kv_engine, with a seeded model check that rebuilds replicas mid-run.
kythira_sqs_test(sqs_queue_state_machine_test sqs_queue_state_machine_test.cpp)

kythira_scale_test_timeouts()
