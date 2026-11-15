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

# Task 1: hsm_node links and runs (and, from task 3, can lock key memory).
add_test(NAME hsm_node_self_test COMMAND hsm_node --self-test)
set_tests_properties(hsm_node_self_test PROPERTIES
    LABELS "unit;hsm;hsm-module" TIMEOUT 60)

kythira_scale_test_timeouts()
