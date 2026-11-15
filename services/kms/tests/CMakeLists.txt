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

# Task 3, Requirement 5.2, 5.3 and 14.1: the ciphertext blob and its
# additional data, with AES-GCM over OpenSSL standing in for the HSM
# (tamper, wrong context, wrong key), and seeded mutations of real blobs
# through the decoder (the sanitizer legs run it too).
foreach(_kms_test IN ITEMS kms_ciphertext_test kms_ciphertext_fuzz_test)
    kythira_kms_test(${_kms_test} ${_kms_test}.cpp)
    set_tests_properties(${_kms_test} PROPERTIES
        LABELS "unit;kms;kms-module" TIMEOUT 120)
endforeach()

# Task 4, Requirements 3.3-3.5, 6.1, 6.2, 8.1, 9.4 and 13.4: the catalog
# state machine one command at a time, and random command streams on
# replicas and a checkpoint-restored replica, with no field that can carry
# key material.
foreach(_kms_test IN ITEMS kms_catalog_test kms_catalog_property_test)
    kythira_kms_test(${_kms_test} ${_kms_test}.cpp)
    set_tests_properties(${_kms_test} PROPERTIES
        LABELS "unit;kms;kms-module" TIMEOUT 120)
endforeach()

# Task 5, Requirements 3.4, 4.1, 4.4, 4.5 and 9.2-9.4: two-step key
# creation and the leader's jobs over an in-memory PKCS#11 backend, with
# the scan of the catalog's log, engine and checkpoint for generated
# material.
kythira_kms_test(kms_keys_test kms_keys_test.cpp)
set_tests_properties(kms_keys_test PROPERTIES LABELS "unit;kms;kms-module" TIMEOUT 120)

# Task 5, Requirements 2.1 and 4.1-4.5: the catalog on three in-process
# multi-raft members sharing one PKCS#11 token: creation through a
# follower, a dead leader's Creating keys settled by the next, a sealed
# HSM, and a member cut off from the leader.
kythira_kms_test(kms_host_test kms_host_test.cpp)
target_link_libraries(kms_host_test PRIVATE kythira_test_support)
set_tests_properties(kms_host_test PROPERTIES
    LABELS "integration;kms;kms-module" TIMEOUT 300)

# Task 5, Requirements 4.1-4.3: every key spec's backing key on a real
# module, SoftHSM2 standing in for an external one; registered when the
# build finds SoftHSM2 and softhsm2-util (kms-module.yml installs them;
# Debian and Ubuntu ship the library under lib/softhsm/).
find_library(KYTHIRA_KMS_SOFTHSM2_LIBRARY NAMES softhsm2 PATH_SUFFIXES softhsm)
find_program(KYTHIRA_KMS_SOFTHSM2_UTIL softhsm2-util)
if(KYTHIRA_KMS_SOFTHSM2_LIBRARY AND KYTHIRA_KMS_SOFTHSM2_UTIL)
    kythira_kms_test(kms_backing_softhsm_test kms_backing_softhsm_test.cpp)
    target_compile_definitions(kms_backing_softhsm_test PRIVATE
        KYTHIRA_SOFTHSM2_LIBRARY="${KYTHIRA_KMS_SOFTHSM2_LIBRARY}"
        KYTHIRA_SOFTHSM2_UTIL="${KYTHIRA_KMS_SOFTHSM2_UTIL}")
    set_tests_properties(kms_backing_softhsm_test PROPERTIES
        LABELS "unit;kms;kms-module" TIMEOUT 300)
else()
    message(STATUS "kms_backing_softhsm_test: no SoftHSM2, not registered")
endif()

# Task 1: kms_node links and checks its model.
add_test(NAME kms_node_self_test COMMAND kms_node --self-test)
set_tests_properties(kms_node_self_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

kythira_scale_test_timeouts()
