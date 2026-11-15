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

# Task 9: the client wire protocol (every call through the dispatcher,
# mechanism parameters field by field, malformed and forged requests
# refused) and its listeners: the Unix socket's uid allow list and mutual
# TLS identities.
kythira_hsm_test(hsm_wire_test hsm_wire_test.cpp)
set_tests_properties(hsm_wire_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

# Task 10, Requirement 5: libkythira_pkcs11.so, loaded with dlopen as a
# consumer loads it, against wire servers on Unix sockets: the 3.0
# interfaces, sessions and logins, signing through the length query,
# AES-GCM, attribute rules, find, wrap and unwrap, failover to a second
# server, many threads, and the configuration file.
kythira_hsm_test(hsm_pkcs11_library_test hsm_pkcs11_library_test.cpp)
target_include_directories(hsm_pkcs11_library_test PRIVATE "${KYTHIRA_HSM_SOURCE_DIR}/pkcs11")
target_compile_definitions(hsm_pkcs11_library_test PRIVATE
    KYTHIRA_PKCS11_LIBRARY="$<TARGET_FILE:kythira_pkcs11>")
target_link_libraries(hsm_pkcs11_library_test PRIVATE ${CMAKE_DL_LIBS})
add_dependencies(hsm_pkcs11_library_test kythira_pkcs11)
set_tests_properties(hsm_pkcs11_library_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 120)

# Task 12, Requirement 9: core's consumer wrapper (raft/pkcs11_module.hpp)
# on three backends: in process, the library dlopen'd, and SoftHSM2
# standing in for an external module; and hsm_ctl migrate's copy to
# SoftHSM2. SoftHSM2's cases are compiled in when its library and
# softhsm2-util are found
# (hsm-module.yml installs them; Debian and Ubuntu ship the library under
# lib/softhsm/).
kythira_hsm_test(hsm_pkcs11_module_test hsm_pkcs11_module_test.cpp)
target_compile_definitions(hsm_pkcs11_module_test PRIVATE
    KYTHIRA_PKCS11_LIBRARY="$<TARGET_FILE:kythira_pkcs11>")
find_library(KYTHIRA_SOFTHSM2_LIBRARY NAMES softhsm2 PATH_SUFFIXES softhsm)
find_program(KYTHIRA_SOFTHSM2_UTIL softhsm2-util)
if(KYTHIRA_SOFTHSM2_LIBRARY AND KYTHIRA_SOFTHSM2_UTIL)
    message(STATUS "hsm_pkcs11_module_test: SoftHSM2 at ${KYTHIRA_SOFTHSM2_LIBRARY}")
    target_compile_definitions(hsm_pkcs11_module_test PRIVATE
        KYTHIRA_SOFTHSM2_LIBRARY="${KYTHIRA_SOFTHSM2_LIBRARY}"
        KYTHIRA_SOFTHSM2_UTIL="${KYTHIRA_SOFTHSM2_UTIL}")
else()
    message(STATUS "hsm_pkcs11_module_test: no SoftHSM2; its external-module case is left out")
endif()
# hsm_ctl migrate (task 12b) run as an operator runs it, when built.
if(TARGET hsm_ctl)
    target_compile_definitions(hsm_pkcs11_module_test PRIVATE
        KYTHIRA_HSM_CTL="$<TARGET_FILE:hsm_ctl>")
    add_dependencies(hsm_pkcs11_module_test hsm_ctl)
endif()
# The cluster CA with its key on a token (task 13b).
target_link_libraries(hsm_pkcs11_module_test PRIVATE ${CMAKE_DL_LIBS} certificate_authority)
add_dependencies(hsm_pkcs11_module_test kythira_pkcs11)
set_tests_properties(hsm_pkcs11_module_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 300)

# Task 13b, Requirement 10.1: three ca_cluster_node processes signing with
# one root key on a SoftHSM2 token (--ca-key-uri), across a leader kill.
if(TARGET ca_cluster_node AND KYTHIRA_SOFTHSM2_LIBRARY AND KYTHIRA_SOFTHSM2_UTIL)
    kythira_hsm_test(hsm_ca_cluster_test hsm_ca_cluster_test.cpp)
    target_compile_definitions(hsm_ca_cluster_test PRIVATE
        CA_CLUSTER_NODE_PATH="$<TARGET_FILE:ca_cluster_node>"
        KYTHIRA_SOFTHSM2_LIBRARY="${KYTHIRA_SOFTHSM2_LIBRARY}"
        KYTHIRA_SOFTHSM2_UTIL="${KYTHIRA_SOFTHSM2_UTIL}")
    target_link_libraries(hsm_ca_cluster_test PRIVATE
        certificate_authority httplib::httplib boost_json kythira_test_support ${CMAKE_DL_LIBS})
    add_dependencies(hsm_ca_cluster_test ca_cluster_node)
    set_tests_properties(hsm_ca_cluster_test PROPERTIES
        LABELS "hsm;hsm-module;integration" TIMEOUT 600 PROCESSORS 3)
endif()

# Task 10b, Requirement 5.6: the library under real consumers, each run
# by services/hsm/pkcs11/tests/consumers.sh against a node this test
# serves. The tools are installed only by hsm-module.yml's consumers job,
# which turns this on; it is opt-in, as the container suites are.
option(KYTHIRA_HSM_CONSUMER_TESTS
       "Register hsm_pkcs11_consumers_test (needs pkcs11-tool, pkcs11-provider, p11-kit, GnuTLS, Go, Java and PKCS11TEST)"
       OFF)
if(KYTHIRA_HSM_CONSUMER_TESTS)
    kythira_hsm_test(hsm_pkcs11_consumers_test hsm_pkcs11_consumers_test.cpp)
    target_compile_definitions(hsm_pkcs11_consumers_test PRIVATE
        KYTHIRA_PKCS11_LIBRARY="$<TARGET_FILE:kythira_pkcs11>"
        KYTHIRA_HSM_CONSUMERS_SCRIPT="${KYTHIRA_HSM_SOURCE_DIR}/pkcs11/tests/consumers.sh")
    add_dependencies(hsm_pkcs11_consumers_test kythira_pkcs11)
    set_tests_properties(hsm_pkcs11_consumers_test PROPERTIES
        LABELS "hsm;hsm-module;hsm-consumers" TIMEOUT 900)
endif()

add_test(NAME hsm_node_self_test COMMAND hsm_node --self-test)
set_tests_properties(hsm_node_self_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

# Task 11, Requirements 2.1 and 13.5: hsm_node is kythira_node with only the
# HSM module. Three of them, with the token group's leader killed during
# key generation and the catalog's leader killed during rekeys: every
# replica agrees and every key still works afterwards.
if(KYTHIRA_HSM_NODE_DAEMON)
    add_test(NAME hsm_node_help COMMAND hsm_node --help)
    set_tests_properties(hsm_node_help PROPERTIES
        PASS_REGULAR_EXPRESSION "KYTHIRA_HSM_API_LISTEN"
        LABELS "unit;hsm;hsm-module" TIMEOUT 30)
    add_test(NAME hsm_node_refuses_other_services COMMAND hsm_node)
    set_tests_properties(hsm_node_refuses_other_services PROPERTIES
        ENVIRONMENT "KYTHIRA_SERVICES=hsm,iam;KYTHIRA_NODE_ID=1;KYTHIRA_NODE_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/refuses;KYTHIRA_NODE_INSECURE_PLAINTEXT=1"
        PASS_REGULAR_EXPRESSION "hsm_node runs only the HSM"
        LABELS "unit;hsm;hsm-module" TIMEOUT 30)

    kythira_hsm_test(hsm_node_cluster_test hsm_node_cluster_test.cpp)
    target_link_libraries(hsm_node_cluster_test PRIVATE boost_json kythira_test_support)
    target_compile_definitions(hsm_node_cluster_test PRIVATE
        HSM_NODE_PATH="$<TARGET_FILE:hsm_node>")
    add_dependencies(hsm_node_cluster_test hsm_node)
    set_tests_properties(hsm_node_cluster_test PROPERTIES
        LABELS "integration;hsm;hsm-module" TIMEOUT 600)
endif()

# Task 11b (Requirement 13.6): the container scenario, where the daemon is
# built (the image carries it and kythira_node).
if(KYTHIRA_HSM_NODE_DAEMON AND Boost_FOUND AND httplib_FOUND)
    add_subdirectory(docker)
endif()

kythira_scale_test_timeouts()
