// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_admin_unit_test.cpp
/// @brief The admin tools' store side (.kiro/specs/redis-general-data-types/
///        task 13, Requirement 8): the range delete behind
///        `KYTHIRA.DELPREFIX`, `FLUSHDB` and `FLUSHALL` in each store, and the
///        transaction wrapper refusing one while a transaction holds a key
///        in its range.

#define BOOST_TEST_MODULE redis_admin_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <raft/txn_state_machine.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kythira;
using memory_sm = redis_kv_state_machine<std::uint64_t>;

auto gate() -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_format_gate_command{"", 3});
}
auto set(const std::string& key, std::uint64_t expire = 0) -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_set_command{key, {std::byte{'v'}}, expire});
}
auto range_delete(const std::string& lo, const std::string& hi, std::uint32_t max)
    -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_range_delete_command{lo, lo, hi, max});
}

/// The count and last key of a range delete's reply.
auto outcome(const std::vector<std::byte>& result) -> std::pair<std::int64_t, std::string> {
    const auto r = decode_redis_reply(result);
    BOOST_REQUIRE_EQUAL(r._elements.size(), 2u);
    return {r._elements[0]._integer,
            r._elements[1]._kind == redis_reply_kind::null ? "<nil>" : r._elements[1]._text};
}

const std::vector<std::string> k_keys{"a1", "a2", "a3", "a4", "a5", "a6",
                                      "a7", "a8", "a9", "b1", "c1"};

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_admin_tests)

BOOST_AUTO_TEST_CASE(a_range_delete_walks_its_range_in_bounded_entries) {
    memory_sm sm;
    std::uint64_t index = 0;
    (void)sm.apply(gate(), ++index);
    for (const auto& k : k_keys) {
        (void)sm.apply(set(k, k == "a3" ? 1 : 0), ++index);  // a3 expired long ago
    }
    using result = std::pair<std::int64_t, std::string>;
    BOOST_CHECK(outcome(sm.apply(range_delete("a", "b", 4), ++index)) == result(4, "a4"));
    BOOST_CHECK(outcome(sm.apply(range_delete(std::string("a4\0", 3), "b", 4), ++index)) ==
                result(4, "a8"));
    BOOST_CHECK(outcome(sm.apply(range_delete(std::string("a8\0", 3), "b", 4), ++index)) ==
                result(1, "a9"));
    BOOST_CHECK(outcome(sm.apply(range_delete(std::string("a9\0", 3), "b", 4), ++index)) ==
                result(0, "<nil>"));
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 2u);
    BOOST_CHECK(sm.lookup("b1") != nullptr);
    // An empty upper bound is the end of the keyspace; no keys, no entry.
    BOOST_CHECK(outcome(sm.apply(range_delete("", "", 100), ++index)) == result(2, "c1"));
    BOOST_CHECK(outcome(sm.apply(range_delete("", "", 0), ++index)) == result(0, "<nil>"));
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 0u);
}

BOOST_AUTO_TEST_CASE(a_range_delete_needs_the_gate) {
    memory_sm sm;
    (void)sm.apply(set("a1"), 1);
    const auto r = sm.apply(range_delete("a", "b", 10), 2);
    BOOST_REQUIRE_EQUAL(r.size(), 1u);
    BOOST_CHECK(r[0] == static_cast<std::byte>(redis_v3_apply_status::refused_before_gate));
    BOOST_CHECK(sm.lookup("a1") != nullptr);
}

BOOST_AUTO_TEST_CASE(mvcc_deletes_with_tombstones_at_the_entry_timestamp) {
    redis_kv_mvcc_state_machine<std::uint64_t> sm;
    (void)sm.apply_at(gate(), 1);
    for (std::uint64_t i = 0; i < k_keys.size(); ++i) {
        (void)sm.apply_at(set(k_keys[i]), 10 + i);
    }
    using result = std::pair<std::int64_t, std::string>;
    BOOST_CHECK(outcome(sm.apply_at(range_delete("a", "b", 100), 50)) == result(9, "a9"));
    BOOST_CHECK(sm.read_at("a5", 49) != nullptr);  // a snapshot below still reads it
    BOOST_CHECK(sm.read_at("a5", 50) == nullptr);
    BOOST_CHECK(sm.read_at("b1", 50) != nullptr);
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 2u);
    // Tombstoned keys are not walked again.
    BOOST_CHECK(outcome(sm.apply_at(range_delete("a", "b", 100), 51)) == result(0, "<nil>"));
}

BOOST_AUTO_TEST_CASE(a_held_key_in_the_range_refuses_the_range_delete) {
    using txn_sm = transactional_state_machine<memory_sm, std::string, redis_kv_partitioner>;
    txn_sm sm;
    std::uint64_t index = 0;
    const auto run = [&](const txn_envelope<std::string>& e) {
        return decode_txn_result<std::string>(
            sm.apply(encode_txn_envelope<std::string>(e), ++index));
    };
    BOOST_REQUIRE(run(txn_plain{gate()})._status == txn_result_status::ok);
    for (const auto& k : k_keys) {
        BOOST_REQUIRE(run(txn_plain{set(k)})._status == txn_result_status::ok);
    }
    const txn_id holder{0, 7};
    BOOST_REQUIRE(
        run(txn_prepare<std::string>{
                holder, "a6", {txn_write<std::string>{"a6", set("a6")}}, {}, 0, 1000, true})
            ._status == txn_result_status::ok);
    // The range holds a6: refused, naming it, and nothing is deleted.
    const auto refused = run(txn_plain{range_delete("a", "b", 100)});
    BOOST_CHECK(refused._status == txn_result_status::key_locked);
    BOOST_CHECK_EQUAL(refused._key, "a6");
    BOOST_REQUIRE(refused._holder.has_value());
    BOOST_CHECK(refused._holder->_txn == holder);
    // A range around it is not held.
    const auto other = run(txn_plain{range_delete("b", "", 100)});
    BOOST_REQUIRE(other._status == txn_result_status::ok);
    using result = std::pair<std::int64_t, std::string>;
    BOOST_CHECK(outcome(other._payload) == result(2, "c1"));
    BOOST_CHECK(outcome(run(txn_plain{range_delete("a", "a6", 100)})._payload) == result(5, "a5"));
}

BOOST_AUTO_TEST_CASE(the_partitioner_names_a_range_delete_s_range) {
    const redis_kv_partitioner p;
    const auto r = p.range_of(range_delete("a", "b", 1));
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r->first, "a");
    BOOST_CHECK(r->second == std::optional<std::string>("b"));
    BOOST_CHECK(!p.range_of(range_delete("a", "", 1))->second.has_value());
    BOOST_CHECK(!p.range_of(set("a")).has_value());
    BOOST_CHECK_EQUAL(p.key_of(range_delete("a", "b", 1)), "a");
}

BOOST_AUTO_TEST_SUITE_END()
