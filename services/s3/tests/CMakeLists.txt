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

# Task 6, Requirement 5.1: the action table is what tools/gen_s3_actions.py
# makes of the pinned service reference, so an upgrade carries its
# regenerated header and its diff.
add_test(NAME s3_actions_up_to_date
    COMMAND "${Python3_EXECUTABLE}" "${_s3_dir}tools/gen_s3_actions.py"
            "${_s3_dir}tools/s3-service-reference.json"
            "${_s3_dir}include/kythira/s3/s3_actions.hpp" --check)

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

# Task 6: the actions, resources and condition keys each request asks the
# authorizer for, against the reference's operation table.
add_executable(s3_authz_test s3_authz_test.cpp)
target_link_libraries(s3_authz_test PRIVATE kythira_s3 Boost::unit_test_framework)
add_test(NAME s3_authz_test COMMAND s3_authz_test)

# Task 6: SigV4 in headers and query strings, every payload mode including
# signed and unsigned streaming bodies, refused SigV2 and SigV4a, anonymous
# requests.
add_executable(s3_auth_test s3_auth_test.cpp)
target_link_libraries(s3_auth_test PRIVATE kythira_s3 Boost::unit_test_framework)
add_test(NAME s3_auth_test COMMAND s3_auth_test)

# Task 6: Object Ownership, canned and header ACLs, ACL XML, Block Public
# Access, policy publicness, and the decision combining the authorizer,
# ACLs and anonymous access.
add_executable(s3_access_test s3_access_test.cpp)
target_link_libraries(s3_access_test PRIVATE kythira_s3 Boost::unit_test_framework)
if(TARGET boost_json)
    target_link_libraries(s3_access_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_access_test PRIVATE Boost::json)
endif()
add_test(NAME s3_access_test COMMAND s3_access_test)

# Task 6: browser POST uploads: the streaming multipart/form-data parser,
# the policy document and its conditions, the policy's SigV4 signature.
add_executable(s3_post_policy_test s3_post_policy_test.cpp)
target_link_libraries(s3_post_policy_test PRIVATE kythira_s3 Boost::unit_test_framework)
if(TARGET boost_json)
    target_link_libraries(s3_post_policy_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_post_policy_test PRIVATE Boost::json)
endif()
add_test(NAME s3_post_policy_test COMMAND s3_post_policy_test)

# Task 8: additional checksums: check values, streaming, CRC combination
# for multipart full-object checksums, composite checksums, and what a
# request's checksum headers ask for.
add_executable(s3_checksums_test s3_checksums_test.cpp)
target_link_libraries(s3_checksums_test PRIVATE kythira_s3 Boost::unit_test_framework)
if(TARGET boost_json)
    target_link_libraries(s3_checksums_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_checksums_test PRIVATE Boost::json)
endif()
add_test(NAME s3_checksums_test COMMAND s3_checksums_test)

# Task 11: server-side encryption: chunk sealing, the data path over sealed
# chunks, the local key provider, the SSE headers, bucket default
# encryption, and object keys for SSE-S3, SSE-KMS with bucket keys and
# SSE-C.
add_executable(s3_encryption_test s3_encryption_test.cpp)
target_link_libraries(s3_encryption_test PRIVATE
    kythira_s3 Boost::unit_test_framework Threads::Threads)
if(TARGET boost_json)
    target_link_libraries(s3_encryption_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_encryption_test PRIVATE Boost::json)
endif()
add_test(NAME s3_encryption_test COMMAND s3_encryption_test)

# Task 12: chunk collection with tombstones, the orphan sweep and placement
# repair, on real chunk stores and the in-process metadata layer. Like the
# service test it includes the persistent state machine contract, hence the
# shared test PCH target.
add_raft_completion_test(s3_sweeps_test s3_sweeps_test.cpp)
target_link_libraries(s3_sweeps_test PRIVATE kythira_s3)
if(TARGET boost_json)
    target_link_libraries(s3_sweeps_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_sweeps_test PRIVATE Boost::json)
endif()

# Task 13: lifecycle configurations (XML both ways, S3's checks, timing)
# and the lifecycle worker over the in-process metadata layer. It includes
# the persistent state machine contract, hence the shared test PCH target.
add_raft_completion_test(s3_lifecycle_test s3_lifecycle_test.cpp)
target_link_libraries(s3_lifecycle_test PRIVATE kythira_s3)
if(TARGET boost_json)
    target_link_libraries(s3_lifecycle_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_lifecycle_test PRIVATE Boost::json)
endif()

# Task 7: the request pipeline end to end (routing, SigV4, the access check,
# bucket, object and listing handlers) over the in-process metadata layer.
# It includes the persistent state machine contract, hence the shared test
# PCH target like the index state machine test.
add_raft_completion_test(s3_service_test s3_service_test.cpp)
target_link_libraries(s3_service_test PRIVATE kythira_s3)
if(TARGET boost_json)
    target_link_libraries(s3_service_test PRIVATE boost_json)
elseif(TARGET Boost::json)
    target_link_libraries(s3_service_test PRIVATE Boost::json)
endif()
target_compile_definitions(s3_service_test PRIVATE KYTHIRA_S3_DIR_DEFAULT="${_s3_dir}")

set_tests_properties(
    s3_model_coverage
    s3_model_coverage_checker
    s3_operations_up_to_date
    s3_wire_evidence
    s3_gateway_node_self_test
    s3_routing_test
    s3_index_state_machine_test
    s3_data_path_test
    s3_actions_up_to_date
    s3_authz_test
    s3_auth_test
    s3_access_test
    s3_post_policy_test
    s3_checksums_test
    s3_encryption_test
    s3_sweeps_test
    s3_lifecycle_test
    s3_service_test
    PROPERTIES LABELS "unit;s3;s3-module" TIMEOUT 60)

kythira_scale_test_timeouts()
