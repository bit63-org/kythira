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

# Task 1: the checked-in wire evidence (tests/evidence/README.md) names only
# model operations, shows every scenario finishing, and matches the
# addressing and upload framing the README claims for each client.
add_test(NAME s3_wire_evidence
    COMMAND "${Python3_EXECUTABLE}" "${_s3_dir}tests/evidence/check_evidence.py"
            "${_s3_dir}model/s3-2006-03-01.json"
            "${_s3_dir}tests/evidence/data")

# Task 1: s3_gateway_node links and runs.
add_test(NAME s3_gateway_node_self_test COMMAND s3_gateway_node --self-test)

# Task 3: S3's route table over the core REST-XML router. Every request the
# recorded clients sent (tests/evidence/data/) must route to the operation
# the recording names. The Boost.Test lookup is tests/CMakeLists.txt's.
find_package(Boost REQUIRED COMPONENTS unit_test_framework)
add_executable(s3_routing_test s3_routing_test.cpp)
target_link_libraries(s3_routing_test PRIVATE kythira_s3 Boost::unit_test_framework)
if(TARGET boost_json)
    target_link_libraries(s3_routing_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_routing_test PRIVATE Boost::json)
endif()
target_compile_definitions(s3_routing_test PRIVATE
    KYTHIRA_S3_EVIDENCE_DIR_DEFAULT="${_s3_dir}tests/evidence/data")
add_test(NAME s3_routing_test COMMAND s3_routing_test)

# Task 4: the object index state machine (buckets, versioning, conditions
# in apply, copies, multipart uploads, listings, reference counts with
# grace) and its replica, snapshot and recount properties. It includes the
# persistent state machine contract (raft/types.hpp), hence the shared test
# PCH target like the other modules' state machine tests.
add_raft_completion_test(s3_index_state_machine_test s3_index_state_machine_test.cpp)
target_link_libraries(s3_index_state_machine_test PRIVATE kythira_s3)

# Task 5: the write and read path for object bytes (placement, chunking,
# write quorum, commit after durability, verified reads with repair), on
# in-memory copies and on real chunk stores.
find_package(Threads REQUIRED)
add_executable(s3_data_path_test s3_data_path_test.cpp)
target_link_libraries(s3_data_path_test PRIVATE
    kythira_s3 Boost::unit_test_framework Threads::Threads)
add_test(NAME s3_data_path_test COMMAND s3_data_path_test)

set_tests_properties(
    s3_model_coverage
    s3_model_coverage_checker
    s3_operations_up_to_date
    s3_wire_evidence
    s3_gateway_node_self_test
    s3_routing_test
    s3_index_state_machine_test
    s3_data_path_test
    PROPERTIES LABELS "unit;s3;s3-module" TIMEOUT 60)

kythira_scale_test_timeouts()
