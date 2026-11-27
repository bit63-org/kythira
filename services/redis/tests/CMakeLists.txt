# Copyright (c) 2026 Clark Rawlins
# SPDX-License-Identifier: Apache-2.0

# The Redis module's tests. Moved here from tests/CMakeLists.txt and
# tests/docker_chaos/CMakeLists.txt (.kiro/specs/redis-gateway-module/
# task 4) with their names, labels and timeouts unchanged.

include(kythira_test_helpers)

# add_raft_completion_test, plus the module's headers and the in-process test
# fabric (multi_raft_test_fabric.hpp and friends, by name). The binary and
# its working directory stay where they were before the move, build/tests/,
# which the coverage job collects test binaries from.
function(kythira_redis_test test_name source_file)
    add_raft_completion_test(${test_name} ${source_file})
    target_include_directories(${test_name} PRIVATE "${KYTHIRA_REDIS_INCLUDE_DIR}")
    # kythira_build_version: the gateway's default kythira_version.
    target_link_libraries(${test_name} PRIVATE kythira_test_support kythira_build_version)
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endfunction()

# redis-compatible-kv spec: the RESP gateway over multi_raft for sccache's
# redis backend. The two codecs and the state machine have no dependency the
# tree does not already require, but they are gated together with the gateway
# anyway so that CONFIG_REDIS_GATEWAY=n leaves no trace of the feature in the
# target list (Requirement 16.4). The ACL needs OpenSSL for PBKDF2; the gateway
# integration tests need the in-process fabric and Boost.Asio, on any future
# backend: they only call folly::Init under Folly's.
kythira_redis_test(resp_protocol_unit_test resp_protocol_unit_test.cpp)
kythira_redis_test(redis_kv_commands_unit_test redis_kv_commands_unit_test.cpp)
# redis-general-data-types task 1: seeded fuzzing of the format-0x03 records.
kythira_redis_test(redis_kv_v3_codec_fuzz_test redis_kv_v3_codec_fuzz_test.cpp)
set_tests_properties(redis_kv_v3_codec_fuzz_test PROPERTIES LABELS "unit;redis" TIMEOUT 300)
kythira_redis_test(redis_kv_state_machine_unit_test redis_kv_state_machine_unit_test.cpp)
# persistent-state-machine task 2: the same command set on a kv_engine,
# checked against redis_kv_state_machine as the oracle.
kythira_redis_test(persistent_kv_state_machine_test persistent_kv_state_machine_test.cpp)
target_link_libraries(persistent_kv_state_machine_test PRIVATE OpenSSL::Crypto)
# multi-raft-transactions task 11: the multi-version variant.
kythira_redis_test(redis_kv_mvcc_state_machine_test redis_kv_mvcc_state_machine_test.cpp)
# redis-general-data-types task 2: the format gate in every store.
kythira_redis_test(redis_format_gate_unit_test redis_format_gate_unit_test.cpp)
# redis-general-data-types task 3: the typed reply tree and its codec.
kythira_redis_test(redis_reply_test redis_reply_test.cpp)
kythira_redis_test(redis_float128_test redis_float128_test.cpp)
kythira_redis_test(redis_string_exec_unit_test redis_string_exec_unit_test.cpp)
target_link_libraries(redis_format_gate_unit_test PRIVATE OpenSSL::Crypto)
# Task 12: snapshot isolation over three hosts whose shards keep versions.
kythira_redis_test(multi_raft_txn_snapshot_test multi_raft_txn_snapshot_test.cpp)
# Task 14: the tier-2 bank workload (snapshot reads always sum to the total).
kythira_redis_test(multi_raft_txn_snapshot_bank_test
                   multi_raft_txn_snapshot_bank_test.cpp)
# Task 17: write skew breaks a two-account minimum balance under
# snapshot and never under serializable.
kythira_redis_test(multi_raft_txn_write_skew_test multi_raft_txn_write_skew_test.cpp)
kythira_redis_test(redis_acl_unit_test redis_acl_unit_test.cpp)
# redis-gateway-module task 1: the log-entry and snapshot bytes of every
# state machine the daemon can be built with, against golden/redis/.
# The RESP-reply goldens live in the integration and txn tests below.
set(KYTHIRA_REDIS_GOLDEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/golden/redis")
kythira_redis_test(redis_golden_bytes_test redis_golden_bytes_test.cpp)
target_link_libraries(redis_golden_bytes_test PRIVATE OpenSSL::Crypto)
target_compile_definitions(redis_golden_bytes_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
set_tests_properties(redis_golden_bytes_test PROPERTIES LABELS "unit;redis;cache" TIMEOUT 120)
# redis-migration-tooling task 1: the whole-file RDB codec. The golden test
# reads dump.rdb files written by Redis 7.2-8.4 and Valkey 7.2-9.0, with the
# servers' own DUMP listings (golden/rdb/generate_rdb_goldens.py); the fuzz
# test mutates them (the sanitizer legs run it too).
set(KYTHIRA_REDIS_RDB_GOLDEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/golden/rdb")
foreach(_rdb_test IN ITEMS redis_rdb_file_unit_test redis_rdb_golden_test redis_rdb_file_fuzz_test)
    kythira_redis_test(${_rdb_test} ${_rdb_test}.cpp)
    target_compile_definitions(${_rdb_test} PRIVATE
        KYTHIRA_REDIS_RDB_GOLDEN_DIR="${KYTHIRA_REDIS_RDB_GOLDEN_DIR}")
    set_tests_properties(${_rdb_test} PROPERTIES LABELS "unit;redis" TIMEOUT 300)
endforeach()
target_link_libraries(redis_acl_unit_test PRIVATE OpenSSL::Crypto)
# redis-general-data-types task 1: the generated command registry, its
# agreement with the commands the gateway accepts, and its append-only ids;
# and the header's freshness against tools/redis_commands.yaml.
kythira_redis_test(redis_command_registry_test redis_command_registry_test.cpp)
target_compile_definitions(redis_command_registry_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
set_tests_properties(redis_command_registry_test PROPERTIES LABELS "unit;redis" TIMEOUT 60)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME redis_command_ids_header_fresh
    COMMAND "${Python3_EXECUTABLE}" tools/gen_redis_commands.py
            tools/redis_commands.yaml
            include/kythira/redis/redis_command_ids.hpp --check
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/..")
set_tests_properties(redis_command_ids_header_fresh PROPERTIES LABELS "unit;redis" TIMEOUT 60)
kythira_redis_test(redis_auth_limiter_unit_test redis_auth_limiter_unit_test.cpp)
# redis-general-data-types task 16: the data-layer API's bytes and the
# remote data access, against scripted data nodes.
kythira_redis_test(redis_data_wire_unit_test redis_data_wire_unit_test.cpp)
# Task 17: the bytes of an authenticated call from a gateway to a front end.
kythira_redis_test(redis_call_wire_unit_test redis_call_wire_unit_test.cpp)
# Task 18: SCAN cursors, the member list on the wire, load, DNS discovery.
kythira_redis_test(redis_layer_membership_unit_test redis_layer_membership_unit_test.cpp)
# task 18: the capacity loop on the membership group's leader, against the
# scripted quorum manager.
kythira_redis_test(redis_layer_capacity_unit_test redis_layer_capacity_unit_test.cpp)
target_include_directories(redis_layer_capacity_unit_test PRIVATE
                           "${CMAKE_CURRENT_SOURCE_DIR}/../cmd/redis_gateway_node")
# redis_gateway_node's own environment parsing (the plaintext-Raft opt-in).
kythira_redis_test(redis_gateway_node_config_unit_test
                   redis_gateway_node_config_unit_test.cpp)
target_sources(redis_gateway_node_config_unit_test PRIVATE
               "${CMAKE_CURRENT_SOURCE_DIR}/../cmd/redis_gateway_node/config.cpp")
target_include_directories(redis_gateway_node_config_unit_test PRIVATE
                           "${CMAKE_CURRENT_SOURCE_DIR}/../cmd/redis_gateway_node")
# .kiro/specs/disk-backed-build-cache/ task 2: the per-node chunk store and
# its pack files. The crash and write-failure cases need libfiu's control
# API; without it they compile away and the rest still run.
kythira_redis_test(cache_chunk_store_unit_test cache_chunk_store_unit_test.cpp)
target_link_libraries(cache_chunk_store_unit_test PRIVATE OpenSSL::Crypto)
set_tests_properties(cache_chunk_store_unit_test PROPERTIES
    LABELS "unit;redis;cache" TIMEOUT 600)
if(FIU_FOUND)
    target_compile_definitions(cache_chunk_store_unit_test PRIVATE FIU_ENABLE)
    target_link_libraries(cache_chunk_store_unit_test PRIVATE ${FIU_LDFLAGS})
    target_include_directories(cache_chunk_store_unit_test PRIVATE ${FIU_INCLUDE_DIRS})
endif()
# Task 3: the disk-backed state machine over the chunk store, with the
# design's correctness properties 1-4 as randomized trials and the
# Requirement 2.2 index-memory bound.
kythira_redis_test(cache_kv_state_machine_unit_test cache_kv_state_machine_unit_test.cpp)
target_link_libraries(cache_kv_state_machine_unit_test PRIVATE OpenSSL::Crypto)
set_tests_properties(cache_kv_state_machine_unit_test PROPERTIES
    LABELS "unit;redis;cache" TIMEOUT 600)
# Task 5: the chunk fetcher, with in-process nodes whose stores the fetch
# callback reads directly.
kythira_redis_test(cache_chunk_fetcher_unit_test cache_chunk_fetcher_unit_test.cpp)
target_link_libraries(cache_chunk_fetcher_unit_test PRIVATE OpenSSL::Crypto)
set_tests_properties(cache_chunk_fetcher_unit_test PROPERTIES
    LABELS "unit;redis;cache" TIMEOUT 300)
# doc/TODO.md "Disk mode applies under the node mutex": three hosts at the
# production election timeouts keep their leader while every chunk-store
# fsync stalls for 800 ms. In-process fabric, no sockets.
kythira_redis_test(cache_fsync_stall_test cache_fsync_stall_test.cpp)
target_link_libraries(cache_fsync_stall_test PRIVATE OpenSSL::Crypto)
set_tests_properties(cache_fsync_stall_test PROPERTIES
    LABELS "multi-raft;redis;cache" TIMEOUT 300)
# Task 7: the disk budget and the voters' free-space floors.
kythira_redis_test(cache_disk_guard_unit_test cache_disk_guard_unit_test.cpp)
set_tests_properties(cache_disk_guard_unit_test PROPERTIES
    LABELS "unit;redis;cache" TIMEOUT 60)
kythira_redis_test(redis_gateway_integration_test redis_gateway_integration_test.cpp)
target_compile_definitions(redis_gateway_integration_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
target_link_libraries(redis_gateway_integration_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_gateway_integration_test PROPERTIES LABELS "multi-raft;redis" TIMEOUT 600)
# The same cases over the disk-backed cache_kv_state_machine
# (.kiro/specs/disk-backed-build-cache/ Requirement 2.7).
kythira_redis_test(redis_gateway_disk_store_integration_test
                   redis_gateway_disk_store_integration_test.cpp)
target_compile_definitions(redis_gateway_disk_store_integration_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
target_link_libraries(redis_gateway_disk_store_integration_test PRIVATE
                      OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_gateway_disk_store_integration_test PROPERTIES
    LABELS "multi-raft;redis;cache" TIMEOUT 600)
# The same cases over the persistent persistent_kv_state_machine, one
# memory_kv_engine per host (.kiro/specs/persistent-state-machine/ task 7).
kythira_redis_test(redis_gateway_engine_store_integration_test
                   redis_gateway_engine_store_integration_test.cpp)
target_compile_definitions(redis_gateway_engine_store_integration_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
target_link_libraries(redis_gateway_engine_store_integration_test PRIVATE
                      OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_gateway_engine_store_integration_test PROPERTIES
    LABELS "multi-raft;redis" TIMEOUT 600)
# Task 6: the cache's HTTP front end over three in-process hosts,
# including a 1 GiB PUT whose peak RSS must stay under 64 MiB.
kythira_redis_test(cache_http_front_end_test cache_http_front_end_test.cpp)
target_link_libraries(cache_http_front_end_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
# In the `heavy_tu` pool (top-level CMakeLists.txt): this TU measured
# 11.9 GiB of compiler RSS (g++-13, -O2 -g, Boost backend, on main and
# on PR #745 alike), most of a 16 GiB runner. It only shows when the
# compiler cache misses, as it does for any change to the chunk store
# headers. Unpooled, it compiled beside the pooled redis_gateway_node
# TUs, and the arm64 g++-13 Build & Test runner was shut down for
# running out of memory three times in a row on PR #745.
set_target_properties(cache_http_front_end_test PROPERTIES JOB_POOL_COMPILE heavy_tu)
set_tests_properties(cache_http_front_end_test PROPERTIES
    LABELS "multi-raft;redis;cache" TIMEOUT 900)
# .kiro/specs/multi-raft-transactions/ task 9: the gateway's
# transaction surface over a wrapped KV state machine.
kythira_redis_test(redis_gateway_txn_test redis_gateway_txn_test.cpp)
target_compile_definitions(redis_gateway_txn_test PRIVATE
    KYTHIRA_REDIS_GOLDEN_DIR="${KYTHIRA_REDIS_GOLDEN_DIR}")
target_link_libraries(redis_gateway_txn_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_gateway_txn_test PROPERTIES LABELS "multi-raft;redis;txn" TIMEOUT 600)
# Tier 2 (task 14): the gateway over a multi-versioned KV and an
# oracle group, as CONFIG_REDIS_GATEWAY_SNAPSHOT_ISOLATION builds it.
kythira_redis_test(redis_gateway_snapshot_test redis_gateway_snapshot_test.cpp)
target_link_libraries(redis_gateway_snapshot_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_gateway_snapshot_test PROPERTIES LABELS "multi-raft;redis;txn" TIMEOUT 600)
# The differential harness's recordings (redis-general-data-types
# task 14 scaffold) replayed against the same snapshot-isolation
# cluster, so a command change is checked against Redis 7.2 and
# Valkey 8 in plain CTest, with no containers.
kythira_redis_test(redis_differential_replay_test
                   differential/redis_differential_replay_test.cpp)
target_include_directories(redis_differential_replay_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/differential")
target_compile_definitions(redis_differential_replay_test PRIVATE
    KYTHIRA_REDIS_DIFF_RECS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/differential/recs")
target_link_libraries(redis_differential_replay_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_tests_properties(redis_differential_replay_test PROPERTIES
    LABELS "multi-raft;redis;txn" TIMEOUT 600)

# The gateway's in-process cluster tests compile in the `heavy_tu` pool
# (top-level CMakeLists.txt), as cache_http_front_end_test above does.
# Each instantiates the whole gateway stack (redis_gateway_impl.hpp over
# the multi_raft test fabric), and the stdexec leg's memory sampler
# measured redis_gateway_integration_test and its disk-store and
# engine-store twins at 10-12 GiB of compiler RSS apiece under g++-13
# (run 45764030791, 2026-11-26), beside the pooled redis_gateway_node
# TUs at up to 15 GiB. Unpooled, they compile at neighbouring Ninja
# steps and so overlap each other on a 16 GiB GitHub-hosted runner
# whenever the compiler cache misses, which any change to the gateway
# headers causes. On 2026-11-26 the gateway refactors (main's data
# access object, and PRs #885, #975 and #976 on top of it) did exactly
# that, and five hosted runners -- x64 g++-13 and g++-14 Build & Test,
# and the stdexec full suite -- were shut down ("the hosted runner lost
# communication with the server") 50-60 minutes into Build.
foreach(_redis_gateway_heavy_test IN ITEMS
        redis_gateway_integration_test
        redis_gateway_disk_store_integration_test
        redis_gateway_engine_store_integration_test
        redis_gateway_txn_test
        redis_gateway_snapshot_test
        redis_differential_replay_test)
    set_target_properties(${_redis_gateway_heavy_test} PROPERTIES
        JOB_POOL_COMPILE heavy_tu)
endforeach()

# The transaction rows of the multi-Raft bench (.kiro/specs/multi-raft-
# transactions/ Requirement 13.6), one translation unit per wrapper tier.
# They run over the Redis KV state machines, so they live here and join
# core's multi_raft_bench_rows library; the catalog drops them by name when
# the module is off.
target_sources(multi_raft_bench_rows PRIVATE
    bench_rows/txn_fabric.cpp
    bench_rows/txn_snapshot_fabric.cpp
    # The persistence rows (.kiro/specs/persistent-state-machine/
    # Requirements 4.4 and 9.4): the gateway's state machine in RAM and on
    # an engine, over the same file log. One arm per translation unit.
    bench_rows/persistence_memory.cpp
    bench_rows/persistence_engine_memory.cpp
)
# The RocksDB arm only where the opt-in engine was built (root
# CMakeLists.txt); the catalog drops its rows by name otherwise.
if(TARGET raft_rocksdb_engine)
    target_sources(multi_raft_bench_rows PRIVATE bench_rows/persistence_engine_rocksdb.cpp)
    target_link_libraries(multi_raft_bench_rows PUBLIC raft_rocksdb_engine)
    target_compile_definitions(multi_raft_bench_rows PUBLIC KYTHIRA_BENCH_HAS_ROCKSDB)
endif()
target_include_directories(multi_raft_bench_rows PRIVATE "${KYTHIRA_REDIS_INCLUDE_DIR}")
target_compile_definitions(multi_raft_bench_rows PUBLIC KYTHIRA_BENCH_HAS_TXN)

# The same rows at a fifth of their budget: a liveness check of 1PC, 2PC over
# two and four shards and snapshot reads, labelled like
# multi_raft_performance_report_smoke so it runs where the report runs and
# not on every CI leg.
add_test(NAME multi_raft_performance_report_transactions
    COMMAND multi_raft_performance_report --axis transactions --budget-scale 0.2
            --out-dir "${CMAKE_BINARY_DIR}/tests/report_transactions")
set_tests_properties(multi_raft_performance_report_transactions PROPERTIES
    LABELS "performance;benchmark;multi-raft;report;transactions"
    TIMEOUT 900
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

# The persistence rows at a tenth of their budget (a 25.6 MiB restart): a
# liveness check of every arm's write and restart path, labelled like the
# transaction entry above.
add_test(NAME multi_raft_performance_report_persistence
    COMMAND multi_raft_performance_report --axis persistence --budget-scale 0.1
            --out-dir "${CMAKE_BINARY_DIR}/tests/report_persistence")
set_tests_properties(multi_raft_performance_report_persistence PROPERTIES
    LABELS "performance;benchmark;multi-raft;report;persistence"
    TIMEOUT 900
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

# The differential harness (.kiro/specs/redis-general-data-types/ task 14's
# scaffold): its reply parser, seeded generator, comparison rules and the
# committed Redis 7.2 / Valkey 8 recordings, checked without containers. The
# container run against live servers is docker/'s
# docker-redis-differential-tests.
kythira_redis_test(redis_differential_unit_test differential/redis_differential_unit_test.cpp)
target_include_directories(redis_differential_unit_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/differential")
target_compile_definitions(redis_differential_unit_test PRIVATE
    KYTHIRA_REDIS_DIFF_RECS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/differential/recs")
set_tests_properties(redis_differential_unit_test PROPERTIES LABELS "unit;redis" TIMEOUT 120)

# redis-general-data-types task 25: the Lua script sandbox, and the golden
# that holds amd64 and arm64 to the same results (ci.yml runs both).
if(TARGET kythira_redis_lua)
    kythira_redis_test(lua_sandbox_unit_test lua_sandbox_unit_test.cpp)
    target_link_libraries(lua_sandbox_unit_test PRIVATE kythira_redis_lua)
    set_tests_properties(lua_sandbox_unit_test PROPERTIES LABELS "unit;redis" TIMEOUT 300)
    kythira_redis_test(lua_sandbox_determinism_test lua_sandbox_determinism_test.cpp)
    target_link_libraries(lua_sandbox_determinism_test PRIVATE kythira_redis_lua)
    target_compile_definitions(lua_sandbox_determinism_test PRIVATE
        KYTHIRA_LUA_GOLDEN_FILE="${CMAKE_CURRENT_SOURCE_DIR}/golden/lua/determinism.txt")
    set_tests_properties(lua_sandbox_determinism_test PROPERTIES LABELS "unit;redis" TIMEOUT 300)
endif()

# The container scenarios, under the guard tests/docker_chaos/ is entered with.
if(Boost_FOUND AND httplib_FOUND)
    add_subdirectory(docker)
endif()

# What tests/CMakeLists.txt does for its own directory at its end.
kythira_scale_test_timeouts()
kythira_attach_test_reports()
