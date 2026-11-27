// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_format_gate_unit_test.cpp
/// @brief The format gate in the stores (.kiro/specs/redis-general-data-types/
///        task 2, Requirement 14.3-14.5).
///
/// - a gate raises a memory-store group's level, one way, and survives a
///   snapshot and a split;
/// - a typed record before the gate changes nothing and says so;
/// - a record or gate above this binary's level, or a snapshot from a newer
///   level, throws `redis_format_too_new` (the Raft core then halts the
///   group's apply) instead of being skipped;
/// - the engine and multi-version stores, which read no format-0x03 record
///   yet, refuse every one rather than skipping it.

#define BOOST_TEST_MODULE redis_format_gate_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/persistent_kv_state_machine.hpp>
#include <kythira/redis/redis_format_level.hpp>
#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <raft/memory_kv_engine.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace kythira;
using mem_sm = redis_kv_state_machine<std::uint64_t>;

auto gate(std::uint16_t level, std::string key = "a") -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_format_gate_command{std::move(key), level});
}

auto exec_record() -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_exec_command{"k", 1, 1000, 0, {"k", "v"}, {}});
}

auto set_record(const std::string& key) -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_set_command{key, {std::byte{'v'}}, 0});
}

auto status_of(const std::vector<std::byte>& result) -> redis_v3_apply_status {
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    return static_cast<redis_v3_apply_status>(result[0]);
}

}  // namespace

BOOST_AUTO_TEST_CASE(record_levels_follow_the_version_byte) {
    BOOST_CHECK_EQUAL(redis_record_level({}), 0U);
    BOOST_CHECK_EQUAL(redis_record_level(set_record("k")), k_redis_base_format_level);
    BOOST_CHECK_EQUAL(redis_record_level(gate(3)), 3U);
    const std::vector<std::byte> future{std::byte{0x04}, std::byte{0x08}};
    BOOST_CHECK_EQUAL(redis_record_level(future), 4U);
    BOOST_CHECK_NO_THROW(require_redis_record_level(gate(3)));
    BOOST_CHECK_THROW(require_redis_record_level(future), redis_format_too_new);
    try {
        require_redis_record_level(future);
    } catch (const redis_format_too_new& e) {
        BOOST_CHECK_EQUAL(e.needed(), 4U);
        BOOST_CHECK(std::string(e.what()).find("needs Redis format level 4") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(a_gate_raises_the_level_one_way, *boost::unit_test::timeout(10)) {
    mem_sm sm;
    BOOST_CHECK_EQUAL(sm.format_level(), 0U);
    BOOST_CHECK(status_of(sm.apply(exec_record(), 1)) ==
                redis_v3_apply_status::refused_before_gate);
    // A gate below the first gated level asks for nothing.
    BOOST_CHECK(status_of(sm.apply(gate(2), 2)) == redis_v3_apply_status::unchanged);
    BOOST_CHECK_EQUAL(sm.format_level(), 0U);
    BOOST_CHECK(status_of(sm.apply(gate(3), 3)) == redis_v3_apply_status::changed);
    BOOST_CHECK_EQUAL(sm.format_level(), 3U);
    BOOST_CHECK(status_of(sm.apply(gate(3), 4)) == redis_v3_apply_status::unchanged);
    BOOST_CHECK_EQUAL(sm.last_applied_index(), 4U);
    // After the gate a typed record is the store's to apply (task 3 on).
    BOOST_CHECK(status_of(sm.apply(exec_record(), 5)) !=
                redis_v3_apply_status::refused_before_gate);
    // The old records still apply after it.
    (void)sm.apply(set_record("k"), 6);
    BOOST_CHECK(sm.lookup("k") != nullptr);
}

BOOST_AUTO_TEST_CASE(the_level_survives_a_snapshot_and_a_split, *boost::unit_test::timeout(10)) {
    mem_sm sm;
    (void)sm.apply(set_record("a"), 1);
    (void)sm.apply(set_record("q"), 2);
    (void)sm.apply(gate(3), 3);

    mem_sm restored;
    restored.restore_from_snapshot(sm.get_state(), 3);
    BOOST_CHECK_EQUAL(restored.format_level(), 3U);

    // The child a split makes inherits the gate.
    const auto parts = sm.split_state({"m"});
    BOOST_REQUIRE_EQUAL(parts.size(), 2U);
    for (const auto& part : parts) {
        mem_sm child;
        child.restore_from_snapshot(part, 3);
        BOOST_CHECK_EQUAL(child.format_level(), 3U);
        BOOST_CHECK(status_of(child.apply(exec_record(), 4)) !=
                    redis_v3_apply_status::refused_before_gate);
    }
}

BOOST_AUTO_TEST_CASE(newer_records_and_snapshots_stop_the_group, *boost::unit_test::timeout(10)) {
    mem_sm sm;
    // A gate naming a level this binary does not have.
    BOOST_CHECK_THROW((void)sm.apply(gate(k_redis_format_level + 1), 1), redis_format_too_new);
    BOOST_CHECK_EQUAL(sm.format_level(), 0U);
    // A record whose version byte is from a newer format.
    auto future = exec_record();
    future[0] = std::byte{k_redis_format_level + 1};
    BOOST_CHECK_THROW((void)sm.apply(future, 2), redis_format_too_new);
    // A snapshot written at a newer level.
    (void)sm.apply(gate(3), 3);
    auto blob = sm.get_state();
    // marker (4 bytes), then u16 BE level
    blob[4] = std::byte{0};
    blob[5] = std::byte{k_redis_format_level + 1};
    mem_sm other;
    BOOST_CHECK_THROW(other.restore_from_snapshot(blob, 3), redis_format_too_new);
}

BOOST_AUTO_TEST_CASE(stores_without_typed_values_refuse_every_v3_record,
                     *boost::unit_test::timeout(10)) {
    auto future = exec_record();
    future[0] = std::byte{k_redis_format_level + 1};

    redis_kv_mvcc_state_machine<std::uint64_t> mvcc;
    BOOST_CHECK_THROW((void)mvcc.apply(gate(3), 1), redis_kv_codec_error);
    BOOST_CHECK_THROW((void)mvcc.apply(exec_record(), 1), redis_kv_codec_error);
    BOOST_CHECK_THROW((void)mvcc.apply(future, 1), redis_format_too_new);

    memory_kv_engine engine;
    persistent_kv_state_machine<memory_kv_engine> engine_sm("ns/");
    engine_sm.open(engine, key_range{.start = "", .end = std::nullopt});
    BOOST_CHECK_THROW((void)engine_sm.apply(gate(3), 1), redis_kv_codec_error);
    BOOST_CHECK_THROW((void)engine_sm.apply(future, 1), redis_format_too_new);
}
