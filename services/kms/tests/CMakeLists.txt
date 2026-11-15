# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The KMS module's tests (.kiro/specs/kms-compatible-api/).
#
# Every module test carries `kms` and `kms-module`; kms-module.yml checks
# that no `kms-module` test exists with the module off.

include(kythira_test_helpers)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# add_raft_completion_test plus the module's headers. Binaries and working
# directories go to build/tests/, which the coverage job collects test
# binaries from, as the other modules' do.
function(kythira_kms_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_kms)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endfunction()

# Task 1, Requirement 3.1: every operation of the pinned model is
# implemented or listed in doc/unsupported.md, and the checker itself
# fails on its fixtures.
add_test(NAME kms_model_coverage
    COMMAND "${Python3_EXECUTABLE}" tools/check_coverage.py
            model/service-2.json implemented-operations.txt doc/unsupported.md
    WORKING_DIRECTORY "${KYTHIRA_KMS_SOURCE_DIR}")
add_test(NAME kms_model_coverage_checker
    COMMAND "${Python3_EXECUTABLE}" tools/test_check_coverage.py
    WORKING_DIRECTORY "${KYTHIRA_KMS_SOURCE_DIR}")

# The checked-in shape tables are what core's scripts/gen_aws_json_shapes.py
# (KYTHIRA_AWS_JSON_SHAPES_GENERATOR) makes of the pinned model, so a model
# upgrade carries its regenerated header and its diff.
add_test(NAME kms_model_header_fresh
    COMMAND "${Python3_EXECUTABLE}" "${KYTHIRA_AWS_JSON_SHAPES_GENERATOR}"
            model/service-2.json
            include/kythira/kms/model/kms_model.hpp
            --namespace kythira::kms::kms_model
            --label services/kms/model/service-2.json
            --check
    WORKING_DIRECTORY "${KYTHIRA_KMS_SOURCE_DIR}")
set_tests_properties(kms_model_coverage kms_model_coverage_checker kms_model_header_fresh
    PROPERTIES LABELS "unit;kms;kms-module" TIMEOUT 60)

# Task 1: the shape tables compile and validate requests.
kythira_kms_test(kms_model_test kms_model_test.cpp)
set_tests_properties(kms_model_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

# Task 2, Requirement 7.4 and 7.7: the `kms` action table, the operation
# map and the static-key roles, and that the header is what
# tools/gen_kms_actions.py makes of the pinned service reference.
kythira_kms_test(kms_actions_test kms_actions_test.cpp)
add_test(NAME kms_actions_header_fresh
    COMMAND "${Python3_EXECUTABLE}" tools/gen_kms_actions.py
            tools/kms-service-reference.json
            include/kythira/kms/kms_actions.hpp --check
    WORKING_DIRECTORY "${KYTHIRA_KMS_SOURCE_DIR}")
set_tests_properties(kms_actions_test kms_actions_header_fresh PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

# Task 1: kms_node links and checks its model.
add_test(NAME kms_node_self_test COMMAND kms_node --self-test)
set_tests_properties(kms_node_self_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

kythira_scale_test_timeouts()
