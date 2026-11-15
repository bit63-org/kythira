# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The HSM module's tests (.kiro/specs/virtual-hsm/).
#
# Every module test carries `hsm` and `hsm-module`; hsm-module.yml checks
# that no `hsm-module` test exists with the module off.

include(kythira_test_helpers)

# add_raft_completion_test plus the module's headers. Binaries and working
# directories go to build/tests/, which the coverage job collects test
# binaries from, as the other modules' do.
function(kythira_hsm_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_hsm)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endfunction()

# Task 1, Requirement 1.1-1.2: the vendored OASIS headers compile under the
# platform macros <kythira/hsm/pkcs11.hpp> sets, declare version 3.0 and
# carry the 3.0 interface the library will export.
kythira_hsm_test(hsm_pkcs11_headers_test hsm_pkcs11_headers_test.cpp)
set_tests_properties(hsm_pkcs11_headers_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

# Task 2, Requirements 4.1-4.2 and 13.1: GF(2^8) Shamir splitting of the master key, the
# share encoding (version, checksum, check value) and every refusal path.
kythira_hsm_test(hsm_shamir_test hsm_shamir_test.cpp)
set_tests_properties(hsm_shamir_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

# Task 3, Requirements 12.3-12.4: key memory is mlock'ed and MADV_DONTDUMP,
# wiped on release, a lock failure is an error unless allowed, and
# harden_process() turns off core dumps and ptrace attachment.
kythira_hsm_test(hsm_secure_arena_test hsm_secure_arena_test.cpp)
set_tests_properties(hsm_secure_arena_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

# Task 4, Requirements 6.1-6.2 and 6.5: every key type and mechanism on
# OpenSSL 3, checked against published vectors, and the exclusions.
kythira_hsm_test(hsm_mechanisms_test hsm_mechanisms_test.cpp)
set_tests_properties(hsm_mechanisms_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

# Task 4, Requirements 6.3-6.4 and 13.3: one test per attribute rule.
kythira_hsm_test(hsm_attribute_policy_test hsm_attribute_policy_test.cpp)
set_tests_properties(hsm_attribute_policy_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

# Task 5, Requirements 3.1-3.3, 4.5-4.6, 7.1-7.2, 7.4, 8.2 and 13.4: the
# catalog and token state machines, leader-side generation, sealing, PIN
# verifiers, and the no-plaintext scan of engine, log and checkpoints.
kythira_hsm_test(hsm_key_store_test hsm_key_store_test.cpp)
set_tests_properties(hsm_key_store_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

# Task 1: hsm_node links and runs (and, from task 3, can lock key memory).
kythira_hsm_test(hsm_session_layer_test hsm_session_layer_test.cpp)
set_tests_properties(hsm_session_layer_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

kythira_hsm_test(hsm_object_import_test hsm_object_import_test.cpp)
set_tests_properties(hsm_object_import_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

# Task 6c: the store on multi_raft, three members on the in-process fabric:
# token groups on every member, follower forwarding of proposals and
# read-index rounds, destroys seen everywhere, partitions answering
# CKR_DEVICE_ERROR.
kythira_hsm_test(hsm_host_test hsm_host_test.cpp)
target_link_libraries(hsm_host_test PRIVATE kythira_test_support)
set_tests_properties(hsm_host_test PROPERTIES
    LABELS "integration;hsm;hsm-module" TIMEOUT 300)

# Task 6d: forwarding between members over HTTPS with client certificates
# (wire format, membership, refusals before the host is asked) and the
# operator API.
kythira_hsm_test(hsm_peer_test hsm_peer_test.cpp)
set_tests_properties(hsm_peer_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)
kythira_hsm_test(hsm_admin_test hsm_admin_test.cpp)
set_tests_properties(hsm_admin_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)
# Task 7: operator unseal (shares checked on arrival, k needed, expiry) and
# the vault sealing itself after a seal or rekey.
kythira_hsm_test(hsm_unseal_test hsm_unseal_test.cpp)
set_tests_properties(hsm_unseal_test PROPERTIES
    LABELS "unit;hsm" TIMEOUT 60)
# Task 8a: node unseal (key-file sealer, share store, collection from
# peers, the share routes, init and rekey delivering shares).
kythira_hsm_test(hsm_node_unseal_test hsm_node_unseal_test.cpp)
set_tests_properties(hsm_node_unseal_test PROPERTIES
    LABELS "unit;hsm" TIMEOUT 60)

add_test(NAME hsm_node_self_test COMMAND hsm_node --self-test)
set_tests_properties(hsm_node_self_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

kythira_scale_test_timeouts()
