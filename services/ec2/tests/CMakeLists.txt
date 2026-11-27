# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The EC2 module's tests (.kiro/specs/ec2-compatible-api/).
#
# Every module test carries `ec2` and `ec2-module`. `ec2` alone is kept for
# core suites the module builds on, which rightly exist with the module off;
# ec2-module.yml asserts that no `ec2-module` test exists in a module-off
# build.

include(kythira_test_helpers)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# The module root, set by ../CMakeLists.txt.
set(_ec2_dir "${KYTHIRA_EC2_SOURCE_DIR}/")

# Task 1, Requirement 2.1: every operation of the pinned model is implemented
# or listed in doc/unsupported.md.
add_test(NAME ec2_model_coverage
    COMMAND "${Python3_EXECUTABLE}" "${_ec2_dir}tools/check_coverage.py"
            "${_ec2_dir}model/service-2.json"
            "${_ec2_dir}implemented-operations.txt"
            "${_ec2_dir}doc/unsupported.md")
add_test(NAME ec2_model_coverage_checker
    COMMAND "${Python3_EXECUTABLE}" "${_ec2_dir}tools/test_check_coverage.py")

# Task 1: the checked-in operation table matches the model, so a model
# upgrade carries its regenerated header in the same change.
add_test(NAME ec2_operations_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_ec2_dir}tools/gen_operations.py"
            "${_ec2_dir}model/service-2.json"
            "${_ec2_dir}include/kythira/ec2/model/operations.hpp" --check)

# Task 3: the action table matches the pinned Service Authorization
# Reference entry, so a reference upgrade carries its regenerated header.
add_test(NAME ec2_actions_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_ec2_dir}tools/gen_ec2_actions.py"
            "${_ec2_dir}tools/ec2-service-reference.json"
            "${_ec2_dir}include/kythira/ec2/ec2_actions.hpp" --check)

# Task 1: the recorded wire evidence (tests/evidence/README.md) is
# well-formed, uses only model actions, and decodes to one scenario across
# every client.
add_test(NAME ec2_wire_evidence
    COMMAND "${Python3_EXECUTABLE}" "${_ec2_dir}tests/evidence/check_evidence.py"
            "${_ec2_dir}model/service-2.json"
            "${_ec2_dir}tests/evidence/data")

# Task 1: ec2_node links and runs.
add_test(NAME ec2_node_self_test COMMAND ec2_node --self-test)

set_tests_properties(
    ec2_model_coverage
    ec2_model_coverage_checker
    ec2_operations_up_to_date
    ec2_actions_up_to_date
    ec2_wire_evidence
    ec2_node_self_test
    PROPERTIES LABELS "unit;ec2;ec2-module" TIMEOUT 60)

# A C++ module test: Boost.Test through add_raft_completion_test, linked to
# the module's headers.
function(kythira_ec2_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_ec2)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "unit;ec2;ec2-module"
        TIMEOUT 120)
endfunction()

# Task 2, Requirement 3.1: every recorded client request through the core
# EC2 query codec (include/raft/aws_ec2_protocol.hpp), which must decode them
# all to one scenario.
kythira_ec2_test(ec2_protocol_evidence_test ec2_protocol_evidence_test.cpp)
target_compile_definitions(ec2_protocol_evidence_test PRIVATE
    KYTHIRA_EC2_EVIDENCE_DIR="${_ec2_dir}tests/evidence/data")

# Task 3, Requirements 2.2, 2.3 and 3.2-3.5: the front end (SigV4, the
# codec's errors, authorization on every resource, DryRun, encoded
# authorization messages, admission) and what it is configured with (the
# action table, throttling buckets, the aws profile).
kythira_ec2_test(ec2_front_end_test ec2_front_end_test.cpp)
kythira_ec2_test(ec2_gateway_inputs_test ec2_gateway_inputs_test.cpp)

kythira_scale_test_timeouts()
