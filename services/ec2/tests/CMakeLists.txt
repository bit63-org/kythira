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

# Task 1: ec2_node links and runs.
add_test(NAME ec2_node_self_test COMMAND ec2_node --self-test)

set_tests_properties(
    ec2_model_coverage
    ec2_model_coverage_checker
    ec2_operations_up_to_date
    ec2_node_self_test
    PROPERTIES LABELS "unit;ec2;ec2-module" TIMEOUT 60)

kythira_scale_test_timeouts()
