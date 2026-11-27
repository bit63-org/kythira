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

# Task 18: the differential tool's case list, normaliser and comparison,
# offline (no boto3, no network). kms_node_cluster_test replays the AWS
# recording against the cluster.
add_test(NAME kms_differential_tool
    COMMAND "${Python3_EXECUTABLE}" tests/differential/test_kms_differential.py
    WORKING_DIRECTORY "${KYTHIRA_KMS_SOURCE_DIR}")
set_tests_properties(kms_differential_tool PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

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

# kms-independent-layers task 1, Requirements 3.1-3.3: the catalog seam
# handlers and jobs are built over answers what the replica does, and a
# catalog that cannot answer is KMSInternalException, never NotFound.
kythira_kms_test(kms_catalog_access_test kms_catalog_access_test.cpp)
set_tests_properties(kms_catalog_access_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 120)

# kms-independent-layers task 2, Requirements 5.1-5.3: the job lease in
# the catalog (one holder, tokens, release) and fenced job commands,
# including a stalled holder's jobs refused after a takeover.
kythira_kms_test(kms_job_lease_test kms_job_lease_test.cpp)
set_tests_properties(kms_job_lease_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 120)

# kms-independent-layers task 3, Requirements 3.1, 3.3, 4.1-4.3 and 9.2:
# the data layer's catalog API and the remote catalog access (every query
# answered as the replica does, read-index points, failover, an
# unreachable data layer never answered as "not found"); and the API
# suites again in the split layout, their handlers on a front end that
# reaches the catalog only through that API: the same binaries, run again
# with KMS_API_FIXTURE_LAYOUT=split (kms_api_fixture.hpp). Each split run
# is registered after its suite's target (below), so it is added at the
# end of this file.
kythira_kms_test(kms_catalog_api_test kms_catalog_api_test.cpp)
set_tests_properties(kms_catalog_api_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 120)

# kms-independent-layers task 4, Requirements 6.1-6.3, 7 and 9: the
# authenticated call's wire (with seeded mutations through its decoders),
# the front-end API's answers, who may call which internal route, the
# gateway's handover and its not-executed rule, the live front ends and
# the quota share over them, and a gateway and front end end to end. The
# *_split runs below put a gateway in front of every API suite.
kythira_kms_test(kms_front_end_api_test kms_front_end_api_test.cpp)
set_tests_properties(kms_front_end_api_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 120)

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

# Task 6, Requirements 3.1-3.6, 6.1-6.3, 7.2 and 7.3: the front end's
# framing, SigV4 and authorization guard, and key management, aliases and
# tags through signed requests over a catalog replica and a fake HSM.
kythira_kms_test(kms_api_test kms_api_test.cpp)
set_tests_properties(kms_api_test PROPERTIES LABELS "unit;kms;kms-module" TIMEOUT 120)

# Task 7, Requirements 5.1-5.3 and 5.6: Encrypt, Decrypt, ReEncrypt, the
# data keys and GenerateRandom through signed requests over the fake
# token's AES-GCM: tampering, wrong keys and contexts, key states,
# rotation, the HSM away, DryRun, and the authorizer's condition keys.
kythira_kms_test(kms_crypto_test kms_crypto_test.cpp)
set_tests_properties(kms_crypto_test PROPERTIES LABELS "unit;kms;kms-module" TIMEOUT 120)

# Task 8, Requirements 3.2, 5.1, 5.4 and 5.5: RSA-OAEP, Sign and Verify for
# every RSA and ECC spec and algorithm (RAW and DIGEST), GetPublicKey, data
# key pairs and HMAC, each signature and key checked with OpenSSL.
kythira_kms_test(kms_asymmetric_test kms_asymmetric_test.cpp)
set_tests_properties(kms_asymmetric_test PROPERTIES LABELS "unit;kms;kms-module" TIMEOUT 300)

# Task 9, Requirements 7.1, 7.2, 7.5 and 7.7: the key policy operations,
# the lockout safety check and the static roles.
kythira_kms_test(kms_policy_test kms_policy_test.cpp)
set_tests_properties(kms_policy_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 10, Requirements 8.1-8.4: grants, their constraints, grants made
# under grants, grant tokens and retirement.
kythira_kms_test(kms_grants_test kms_grants_test.cpp)
set_tests_properties(kms_grants_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 11, Requirements 9.1-9.4: rotation (on demand and scheduled) and
# deletion at the end of the window.
kythira_kms_test(kms_rotation_test kms_rotation_test.cpp)
set_tests_properties(kms_rotation_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 12: the peer protocol members forward to the leader with: the
# reply's wire form, who is a member, and serve_peer's answers.
# Task 13, Requirements 10.1 and 10.2: AWS managed keys made on first use
# with AWS's managed key policy, no customer changes, yearly rotation, and
# creation idempotent across members and failed attempts.
kythira_kms_test(kms_managed_test kms_managed_test.cpp)
set_tests_properties(kms_managed_test PROPERTIES LABELS "unit;kms;kms-module")

kythira_kms_test(kms_peer_test kms_peer_test.cpp)
set_tests_properties(kms_peer_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 12, Requirements 2.3 and 2.4: kms.client in process and over HTTPS
# (signed and handed to the front end), the forwarded principal honoured
# only from a trusted service, kms:ViaService, the service operations only.
kythira_kms_test(kms_client_test kms_client_test.cpp)
target_link_libraries(kms_client_test PRIVATE OpenSSL::SSL)
set_tests_properties(kms_client_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 14: CloudTrail-shaped request records and request metrics.
kythira_kms_test(kms_audit_test kms_audit_test.cpp)
target_link_libraries(kms_audit_test PRIVATE OpenSSL::SSL)
set_tests_properties(kms_audit_test PROPERTIES LABELS "unit;kms;kms-module")

# Task 14: AWS's per-account request quotas and ThrottlingException.
kythira_kms_test(kms_quotas_test kms_quotas_test.cpp)
target_link_libraries(kms_quotas_test PRIVATE OpenSSL::SSL)
set_tests_properties(kms_quotas_test PROPERTIES LABELS "unit;kms;kms-module")

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

# kms-independent-layers task 3, Requirements 1.1, 2.1-2.4 and 4.2:
# KYTHIRA_KMS_ROLES and what follows from it (who is a catalog member, who
# holds the HSM PIN, the bounded-staleness switch).
if(TARGET kythira_kms_node_common)
    kythira_kms_test(kms_node_config_test kms_node_config_test.cpp)
    target_link_libraries(kms_node_config_test PRIVATE kythira_kms_node_common)
    set_tests_properties(kms_node_config_test PROPERTIES
        LABELS "unit;kms;kms-module" TIMEOUT 60)
endif()

# Task 1: kms_node links and checks its model.
add_test(NAME kms_node_self_test COMMAND kms_node --self-test)
set_tests_properties(kms_node_self_test PROPERTIES
    LABELS "unit;kms;kms-module" TIMEOUT 60)

# Task 12: kms_node is kythira_node with the KMS module (and the HSM and
# IAM modules where built). Three of them with mutual TLS, static
# authentication and SoftHSM2 as the shared HSM: keys made through any
# member are seen by all, ciphertexts cross members, only members reach
# the peer paths, and two members carry on without the third. Task 18 adds
# the AWS client suites against the same cluster.
if(KYTHIRA_KMS_NODE_DAEMON)
    add_test(NAME kms_node_help COMMAND kms_node --help)
    set_tests_properties(kms_node_help PROPERTIES
        PASS_REGULAR_EXPRESSION "KYTHIRA_SERVICES +kms, optionally with hsm and iam"
        LABELS "unit;kms;kms-module" TIMEOUT 30)
    add_test(NAME kms_node_refuses_other_services COMMAND kms_node)
    set_tests_properties(kms_node_refuses_other_services PROPERTIES
        ENVIRONMENT "KYTHIRA_SERVICES=kms,redis;KYTHIRA_NODE_ID=1;KYTHIRA_NODE_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/refuses;KYTHIRA_NODE_INSECURE_PLAINTEXT=1"
        PASS_REGULAR_EXPRESSION "kms_node runs kms, hsm and iam only"
        LABELS "unit;kms;kms-module" TIMEOUT 30)
    # kms-independent-layers Requirement 2.4: a role set the node cannot
    # serve stops it at start with the reason; a gateway alone (task 4)
    # needs the front ends it hands calls to.
    add_test(NAME kms_node_refuses_a_gateway_without_front_ends COMMAND kms_node)
    set_tests_properties(kms_node_refuses_a_gateway_without_front_ends PROPERTIES
        ENVIRONMENT "KYTHIRA_SERVICES=kms;KYTHIRA_KMS_ROLES=gateway;KYTHIRA_NODE_ID=1;KYTHIRA_NODE_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/lone-gateway;KYTHIRA_NODE_INSECURE_PLAINTEXT=1"
        PASS_REGULAR_EXPRESSION "gateway needs KYTHIRA_KMS_FRONT_END_URLS"
        LABELS "unit;kms;kms-module" TIMEOUT 30)
    add_test(NAME kms_node_needs_kms COMMAND kms_node)
    set_tests_properties(kms_node_needs_kms PROPERTIES
        ENVIRONMENT "KYTHIRA_SERVICES=hsm;KYTHIRA_NODE_ID=1;KYTHIRA_NODE_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/needs-kms;KYTHIRA_NODE_INSECURE_PLAINTEXT=1"
        PASS_REGULAR_EXPRESSION "KYTHIRA_SERVICES must name kms"
        LABELS "unit;kms;kms-module" TIMEOUT 30)

    if(KYTHIRA_KMS_SOFTHSM2_LIBRARY AND KYTHIRA_KMS_SOFTHSM2_UTIL AND TARGET httplib::httplib)
        kythira_kms_test(kms_node_cluster_test kms_node_cluster_test.cpp)
        target_link_libraries(kms_node_cluster_test PRIVATE
            httplib::httplib boost_json OpenSSL::SSL OpenSSL::Crypto kythira_test_support)
        target_compile_definitions(kms_node_cluster_test PRIVATE
            KMS_NODE_PATH="$<TARGET_FILE:kms_node>"
            # Task 18: the AWS client suites (clients/requirements.txt).
            KYTHIRA_PYTHON3="${Python3_EXECUTABLE}"
            KMS_CLIENTS_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/clients/kms_clients.py"
            KMS_DIFFERENTIAL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/differential"
            KYTHIRA_SOFTHSM2_LIBRARY="${KYTHIRA_KMS_SOFTHSM2_LIBRARY}"
            KYTHIRA_SOFTHSM2_UTIL="${KYTHIRA_KMS_SOFTHSM2_UTIL}")
        add_dependencies(kms_node_cluster_test kms_node)
        set_tests_properties(kms_node_cluster_test PROPERTIES
            LABELS "integration;kms;kms-module" TIMEOUT 600)
    else()
        message(STATUS "kms_node_cluster_test: needs SoftHSM2 and httplib, not registered")
    endif()
endif()

kythira_scale_test_timeouts()

# kms-independent-layers tasks 3 and 4: the API suites in the split layout
# (gateway, front end and data apart, Requirement 11.1).
foreach(_kms_suite IN ITEMS kms_api_test kms_crypto_test kms_asymmetric_test kms_grants_test
                            kms_policy_test kms_managed_test kms_rotation_test kms_quotas_test
                            kms_audit_test kms_client_test kms_job_lease_test)
    if(TARGET ${_kms_suite})
        string(REPLACE "_test" "_split_test" _kms_split "${_kms_suite}")
        add_test(NAME ${_kms_split} COMMAND ${_kms_suite})
        set_tests_properties(${_kms_split} PROPERTIES
            ENVIRONMENT "KMS_API_FIXTURE_LAYOUT=split"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
            LABELS "unit;kms;kms-module" TIMEOUT 300)
    endif()
endforeach()
