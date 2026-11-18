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

# Task 1: sqs_node links and runs.
add_test(NAME sqs_node_self_test COMMAND sqs_node --self-test)

set_tests_properties(
    sqs_model_coverage
    sqs_model_coverage_checker
    sqs_operations_up_to_date
    sqs_node_self_test
    PROPERTIES LABELS "unit;sqs;sqs-module" TIMEOUT 60)

kythira_scale_test_timeouts()
