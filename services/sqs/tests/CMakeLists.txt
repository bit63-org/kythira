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

# add_raft_completion_test plus the module's headers. Binaries and working
# directories go to build/tests/, which the coverage job collects test
# binaries from, as the other modules' do.
function(kythira_sqs_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE kythira_sqs)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "unit;sqs;sqs-module" TIMEOUT 120)
endfunction()

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

# Task 1: the checked-in wire evidence (evidence/README.md) is well formed,
# names only model operations and shows every scenario finishing.
add_test(NAME sqs_wire_evidence
    COMMAND "${Python3_EXECUTABLE}" "${_sqs_dir}tests/evidence/check_evidence.py"
            "${_sqs_dir}model/service-2.json"
            "${_sqs_dir}tests/evidence/data")

# Task 1: sqs_node links and runs.
add_test(NAME sqs_node_self_test COMMAND sqs_node --self-test)

set_tests_properties(
    sqs_model_coverage
    sqs_model_coverage_checker
    sqs_operations_up_to_date
    sqs_wire_evidence
    sqs_node_self_test
    PROPERTIES LABELS "unit;sqs;sqs-module" TIMEOUT 60)

# Task 2: the queue state machine (Requirements 4.2, 4.3, 5.2, 5.4-5.7) on
# memory_kv_engine, with a seeded model check that rebuilds replicas mid-run.
kythira_sqs_test(sqs_queue_state_machine_test sqs_queue_state_machine_test.cpp)

# Task 3: both protocols (the recorded client traffic replayed through the
# codec), errors in both, the action table, static roles and the
# compatibility profile (Requirements 2.2, 2.3, 3.1, 3.3).
kythira_sqs_test(sqs_codec_test sqs_codec_test.cpp)
target_compile_definitions(sqs_codec_test PRIVATE
    KYTHIRA_SQS_EVIDENCE_DIR="${_sqs_dir}tests/evidence/data")

# Task 3: the front end: SigV4 in both protocols' wording, unsupported
# operations, queue resolution, authorization of the primary action on the
# queue with its tags and policy (Requirements 3.1-3.3), and the queue-policy
# edits of AddPermission and RemovePermission.
kythira_sqs_test(sqs_front_end_test sqs_front_end_test.cpp)

# Task 4: message bodies and attributes (validation, MD5 digests SQS
# clients check, attribute selection), receipt handles and their key ring,
# and queue attributes against the compatibility profile (Requirements
# 4.1, 5.1, 5.3).
kythira_sqs_test(sqs_messages_test sqs_messages_test.cpp)

# Task 4: the queue catalog in the queue state machine's log: CreateQueue
# idempotence, fresh ids and the deletion cooldown, compare-and-set settings,
# tags, the purge cooldown, listing, restart and the split veto
# (Requirements 4.1, 4.2).
kythira_sqs_test(sqs_catalog_test sqs_catalog_test.cpp)

# Task 4: the queue and message handlers end to end through the front end
# with real SigV4 over a local cluster with a test clock: queue lifecycle,
# attributes, permissions, tags and purges; sends, receives, deletes and
# visibility with their receipt rules; batches; FIFO; the query protocol
# (Requirements 4.1, 4.2, 5.1-5.5).
kythira_sqs_test(sqs_service_test sqs_service_test.cpp)

# Task 4: node-to-node forwarding to a group's leader (wire, HMAC, replay
# window), stamping entries with the proposing node's clock, and
# raft_queue_cluster over a stand-in multi-raft host.
kythira_sqs_test(sqs_forward_test sqs_forward_test.cpp)

# Task 4: the API over core's Beast server with real sockets and SigV4 in
# both protocols, the forwarding endpoint and its refusals, and sqs_node's
# settings.
find_package(Threads REQUIRED)
kythira_sqs_test(sqs_listener_test sqs_listener_test.cpp)
target_link_libraries(sqs_listener_test PRIVATE OpenSSL::SSL Threads::Threads)

# Task 5: long polling. The availability hub, and receives parked on it
# over a local_queue_cluster whose state machine notifies the hub and whose
# tick worker ends delays and visibility timeouts. Timing checks on the
# real clock, with wide margins.
kythira_sqs_test(sqs_long_poll_test sqs_long_poll_test.cpp)
target_link_libraries(sqs_long_poll_test PRIVATE Threads::Threads)

# Task 4: the module on multi_raft, as whole in-process nodes over the Beast
# Raft transport (sqs_module.hpp on memory_kv_engine): a restart, three
# nodes forwarding to their leader, and the settings a durable node refuses.
# Built where the module is (KYTHIRA_SQS_MODULE_AVAILABLE, services/sqs/cmd);
# add_beast_test is tests/'s helper, defined before this directory.
if(KYTHIRA_SQS_MODULE_AVAILABLE)
    add_beast_test(sqs_module_test sqs_module_test.cpp)
    target_link_libraries(sqs_module_test PRIVATE
        kythira_sqs_node_common kythira_test_support Threads::Threads)
    set_target_properties(sqs_module_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(sqs_module_test PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        LABELS "integration;sqs;sqs-module" TIMEOUT 300)
endif()

# Task 3: the checked-in model, query-name and action headers are what their
# generators make of the pinned inputs, so an upgrade of any input carries
# its regenerated header and diff.
add_test(NAME sqs_model_header_fresh
    COMMAND "${Python3_EXECUTABLE}" "${KYTHIRA_AWS_JSON_SHAPES_GENERATOR}"
            model/service-2.json
            include/kythira/sqs/model/sqs_model.hpp
            --namespace kythira::sqs::sqs_model
            --label services/sqs/model/service-2.json
            --check
    WORKING_DIRECTORY "${KYTHIRA_SQS_SOURCE_DIR}")
add_test(NAME sqs_query_names_header_fresh
    COMMAND "${Python3_EXECUTABLE}" tools/gen_query_names.py
            model/service-2.json model/query/service-2.json
            include/kythira/sqs/model/sqs_query_names.hpp --check
    WORKING_DIRECTORY "${KYTHIRA_SQS_SOURCE_DIR}")
add_test(NAME sqs_actions_header_fresh
    COMMAND "${Python3_EXECUTABLE}" tools/gen_sqs_actions.py
            tools/sqs-service-reference.json
            include/kythira/sqs/sqs_actions.hpp --check
    WORKING_DIRECTORY "${KYTHIRA_SQS_SOURCE_DIR}")
set_tests_properties(
    sqs_model_header_fresh
    sqs_query_names_header_fresh
    sqs_actions_header_fresh
    PROPERTIES LABELS "unit;sqs;sqs-module" TIMEOUT 60)

kythira_scale_test_timeouts()
