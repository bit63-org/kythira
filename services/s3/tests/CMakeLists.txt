# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The S3 module's tests (.kiro/specs/s3-compatible-storage/).
#
# Every module test carries `s3` and `s3-module`. `s3` alone will also mark
# core suites the module builds on (the chunk store from task 2, the
# REST-XML codec from task 3), which rightly exist with the module off;
# s3-module.yml asserts that no `s3-module` test exists in a module-off
# build.

include(kythira_test_helpers)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# The module root, set by ../CMakeLists.txt.
set(_s3_dir "${KYTHIRA_S3_SOURCE_DIR}/")

# Task 1, Requirement 2.2: every operation of the pinned model is
# implemented or listed in doc/unsupported.md.
add_test(NAME s3_model_coverage
    COMMAND "${Python3_EXECUTABLE}" "${_s3_dir}tools/check_coverage.py"
            "${_s3_dir}model/s3-2006-03-01.json"
            "${_s3_dir}implemented-operations.txt"
            "${_s3_dir}doc/unsupported.md")
add_test(NAME s3_model_coverage_checker
    COMMAND "${Python3_EXECUTABLE}" "${_s3_dir}tools/test_check_coverage.py")

# Task 1, Requirement 2.3: the checked-in operation table matches the model,
# so a model upgrade carries its regenerated header in the same change.
add_test(NAME s3_operations_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_s3_dir}tools/gen_operations.py"
            "${_s3_dir}model/s3-2006-03-01.json"
            "${_s3_dir}include/kythira/s3/model/operations.hpp" --check)

# Task 1: s3_gateway_node links and runs.
add_test(NAME s3_gateway_node_self_test COMMAND s3_gateway_node --self-test)

set_tests_properties(
    s3_model_coverage
    s3_model_coverage_checker
    s3_operations_up_to_date
    s3_gateway_node_self_test
    PROPERTIES LABELS "unit;s3;s3-module" TIMEOUT 60)

kythira_scale_test_timeouts()
