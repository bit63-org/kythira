// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_string_exec_unit_test.cpp
/// @brief The tier 1 string commands as the memory store applies and reads
///        them (.kiro/specs/redis-general-data-types/ task 3): replies come
///        from apply(), decided at the entry's command time, so replicas
///        agree; reads are a pure function of the entry and the clock.

#define BOOST_TEST_MODULE redis_string_exec_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_state_machine.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kythira;
using sm_type = redis_kv_state_machine<std::uint64_t>;

struct fixture {
    sm_type sm;
    std::uint64_t index = 0;

    fixture() {
        (void)sm.apply(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}), ++index);
    }

    auto exec(redis_command_id id, std::vector<std::string> args, std::uint64_t now = 1000,
              std::uint8_t policy = 0) -> redis_reply {
        redis_kv_exec_command c;
        c._key = args.empty() ? "" : args[0];
        c._command_id = static_cast<std::uint16_t>(id);
        c._now_ms = now;
        c._policy = policy;
        c._args = std::move(args);
        return decode_redis_reply(sm.apply(encode_redis_kv_command(c), ++index));
    }

    auto read(redis_command_id id, const std::string& key, std::vector<std::string> args = {},
              std::uint64_t now = 1000) -> redis_reply {
        return sm.evaluate_read(id, key, args, now);
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(command_time_decides_liveness, fixture) {
    BOOST_CHECK(exec(redis_command_id::set, {"k", "v", "PXAT", "5000"}) ==
                redis_reply::simple("OK"));
    // At t=4999 the key is live: NX fails. A later entry stamped earlier
    // still runs at the floor, so the key does not come back to life.
    BOOST_CHECK(exec(redis_command_id::set, {"k", "w", "NX"}, 4999) == redis_reply::null());
    BOOST_CHECK(exec(redis_command_id::set, {"k", "w", "NX"}, 5000) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(redis_command_id::getdel, {"k"}, 10) == redis_reply::bulk("w"));
    BOOST_CHECK_EQUAL(sm.applied_time_ms(), 5000U);
}

BOOST_FIXTURE_TEST_CASE(counters_and_appends, fixture) {
    BOOST_CHECK(exec(redis_command_id::incrby, {"n", "5"}) == redis_reply::integer(5));
    BOOST_CHECK(exec(redis_command_id::incrby, {"n", "-7"}) == redis_reply::integer(-2));
    BOOST_CHECK(exec(redis_command_id::incrbyfloat, {"n", "0.5"}) == redis_reply::bulk("-1.5"));
    BOOST_CHECK(exec(redis_command_id::incrby, {"n", "1"}) ==
                redis_reply::error("ERR value is not an integer or out of range"));
    BOOST_CHECK(exec(redis_command_id::append, {"s", "ab", "10"}) == redis_reply::integer(2));
    BOOST_CHECK(exec(redis_command_id::append, {"s", "123456789", "10"}) ==
                redis_reply::error("ERR string exceeds maximum allowed size (proto-max-bulk-len)"));
    BOOST_CHECK(exec(redis_command_id::setrange, {"s", "1", "Z", "10"}) == redis_reply::integer(2));
    BOOST_CHECK(read(redis_command_id::get, "s") == redis_reply::bulk("aZ"));
    BOOST_CHECK(exec(redis_command_id::setnx, {"s", "x"}) == redis_reply::integer(0));
}

BOOST_FIXTURE_TEST_CASE(the_immutable_rule_and_its_mutable_bit, fixture) {
    const auto rule = redis_kv_exec_policy::immutable_rule;
    BOOST_CHECK(exec(redis_command_id::incrby, {"n", "1"}, 1000, rule) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::incrby, {"n", "1"}, 1000, rule) ==
                redis_reply::error("ERR value conflict for an existing key"));
    // The same bytes again are not a change.
    BOOST_CHECK(exec(redis_command_id::set, {"n", "1", "GET"}, 1000, rule) ==
                redis_reply::bulk("1"));
    // A key in a mutable prefix (bit 0 of the bitmap) may change.
    redis_kv_exec_command c{"n",        static_cast<std::uint16_t>(redis_command_id::incrby),
                            1000,       rule,
                            {"n", "1"}, {std::byte{0x01}}};
    BOOST_CHECK(decode_redis_reply(sm.apply(encode_redis_kv_command(c), ++index)) ==
                redis_reply::integer(2));
}

BOOST_FIXTURE_TEST_CASE(reads_are_pure_functions_of_the_entry, fixture) {
    (void)exec(redis_command_id::set, {"k", "Hello", "PXAT", "10500"});
    BOOST_CHECK(read(redis_command_id::strlen, "k") == redis_reply::integer(5));
    BOOST_CHECK(read(redis_command_id::ttl, "k") == redis_reply::integer(10));
    BOOST_CHECK(read(redis_command_id::ttl, "k", {}, 10600) == redis_reply::integer(-2));
    BOOST_CHECK(read(redis_command_id::getrange, "k", {"0", "-100"}) == redis_reply::bulk("H"));
    BOOST_CHECK(read(redis_command_id::type, "nope") == redis_reply::simple("none"));
    (void)exec(redis_command_id::set, {"i", "12345"});
    BOOST_CHECK(read(redis_command_id::object, "i", {"ENCODING"}) == redis_reply::bulk("int"));
    BOOST_CHECK(read(redis_command_id::exists, "i") == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::set, "i").is_error());
}

BOOST_FIXTURE_TEST_CASE(an_unknown_command_id_halts, fixture) {
    redis_kv_exec_command c{"k", 65000, 1000, 0, {"k"}, {}};
    BOOST_CHECK_THROW((void)sm.apply(encode_redis_kv_command(c), ++index),
                      redis_unknown_command_id);
}

// Task 4: the expiry family. The front end normalises EXPIRE, PEXPIRE and
// EXPIREAT to PEXPIREAT with an absolute deadline; apply() decides.
BOOST_FIXTURE_TEST_CASE(pexpireat_conditions_follow_redis, fixture) {
    using id = redis_command_id;
    BOOST_CHECK(exec(id::pexpireat, {"missing", "9000"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::set, {"k", "v"}) == redis_reply::simple("OK"));
    // No deadline yet: XX and GT refuse, NX and LT pass.
    BOOST_CHECK(exec(id::pexpireat, {"k", "9000", "XX"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::pexpireat, {"k", "9000", "GT"}) == redis_reply::integer(0));
    BOOST_CHECK(read(id::pttl, "k") == redis_reply::integer(-1));
    BOOST_CHECK(exec(id::pexpireat, {"k", "9000", "LT"}) == redis_reply::integer(1));
    BOOST_CHECK(read(id::pexpiretime, "k") == redis_reply::integer(9000));
    BOOST_CHECK(exec(id::pexpireat, {"k", "8000", "NX"}) == redis_reply::integer(0));
    // GT and LT against the deadline 9000.
    BOOST_CHECK(exec(id::pexpireat, {"k", "9000", "GT"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::pexpireat, {"k", "9500", "GT", "XX"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(id::pexpireat, {"k", "9500", "LT"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::pexpireat, {"k", "8500", "LT"}) == redis_reply::integer(1));
    BOOST_CHECK(read(id::pttl, "k") == redis_reply::integer(7500));
    BOOST_CHECK(read(id::ttl, "k") == redis_reply::integer(8));
    BOOST_CHECK(read(id::expiretime, "k") == redis_reply::integer(9));
    BOOST_CHECK(read(id::pttl, "missing") == redis_reply::integer(-2));
    BOOST_CHECK(read(id::expiretime, "missing") == redis_reply::integer(-2));
    // PERSIST drops the deadline once.
    BOOST_CHECK(exec(id::persist, {"k"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(id::persist, {"k"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::persist, {"missing"}) == redis_reply::integer(0));
    BOOST_CHECK(read(id::pexpiretime, "k") == redis_reply::integer(-1));
    BOOST_CHECK(read(id::get, "k") == redis_reply::bulk("v"));
}

BOOST_FIXTURE_TEST_CASE(a_past_deadline_deletes_the_key, fixture) {
    using id = redis_command_id;
    BOOST_CHECK(exec(id::set, {"k", "v"}) == redis_reply::simple("OK"));
    // GT on a key without a deadline refuses even a past time: no delete.
    BOOST_CHECK(exec(id::pexpireat, {"k", "-5000", "GT"}) == redis_reply::integer(0));
    BOOST_CHECK(read(id::exists, "k") == redis_reply::integer(1));
    // A deadline at the command time is already past: the key goes, 1.
    BOOST_CHECK(exec(id::pexpireat, {"k", "1000"}) == redis_reply::integer(1));
    BOOST_CHECK(read(id::exists, "k") == redis_reply::integer(0));
    BOOST_CHECK(exec(id::set, {"n", "v"}) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(id::pexpireat, {"n", "-5000"}) == redis_reply::integer(1));
    BOOST_CHECK(read(id::exists, "n") == redis_reply::integer(0));
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 0U);
}

BOOST_FIXTURE_TEST_CASE(deadlines_change_under_the_immutable_rule, fixture) {
    using id = redis_command_id;
    const auto rule = redis_kv_exec_policy::immutable_rule;
    BOOST_CHECK(exec(id::set, {"k", "v"}, 1000, rule) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(id::pexpireat, {"k", "9000"}, 1000, rule) == redis_reply::integer(1));
    BOOST_CHECK(exec(id::persist, {"k"}, 1000, rule) == redis_reply::integer(1));
    BOOST_CHECK(exec(id::pexpireat, {"k", "0"}, 1000, rule) == redis_reply::integer(1));
    BOOST_CHECK(read(id::exists, "k") == redis_reply::integer(0));
}

BOOST_FIXTURE_TEST_CASE(replicas_agree_on_expiry_replies, fixture) {
    // A second replica applying the same log reaches the same replies and
    // state, whatever its own clock says: only the stamped times count.
    fixture other;
    using id = redis_command_id;
    const std::vector<std::pair<std::vector<std::string>, std::uint64_t>> log{
        {{"k", "v", "PXAT", "3000"}, 1000}, {{"k", "2500", "LT"}, 1200}, {{"k", "2000"}, 2600}};
    BOOST_CHECK(exec(id::set, log[0].first, log[0].second) ==
                other.exec(id::set, log[0].first, log[0].second));
    BOOST_CHECK(exec(id::pexpireat, log[1].first, log[1].second) == redis_reply::integer(1));
    BOOST_CHECK(other.exec(id::pexpireat, log[1].first, log[1].second) == redis_reply::integer(1));
    // At t=2600 the key's 2500 deadline has passed: it is gone, 0.
    BOOST_CHECK(exec(id::pexpireat, log[2].first, log[2].second) == redis_reply::integer(0));
    BOOST_CHECK(other.exec(id::pexpireat, log[2].first, log[2].second) == redis_reply::integer(0));
}

// The sweep names each key with the deadline the leader saw. An EXPIRE or
// PERSIST that lands in the log between the sweep being built and applied
// changes that deadline, so the sweep must leave the key alone; one that
// lands after the sweep finds the key gone.
BOOST_FIXTURE_TEST_CASE(sweep_racing_expire_and_persist, fixture) {
    using id = redis_command_id;
    BOOST_CHECK(exec(id::set, {"e", "v", "PXAT", "5000"}) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(id::set, {"p", "v", "PXAT", "5000"}) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(id::set, {"late", "v", "PXAT", "5000"}) == redis_reply::simple("OK"));
    const auto sweep = sm.collect_expired(5000, 16);
    BOOST_REQUIRE_EQUAL(sweep.size(), 3U);

    // Stamped before the deadline, applied before the sweep.
    BOOST_CHECK(exec(id::pexpireat, {"e", "9000"}, 4990) == redis_reply::integer(1));
    BOOST_CHECK(exec(id::persist, {"p"}, 4991) == redis_reply::integer(1));
    (void)sm.apply(encode_redis_kv_command(redis_kv_sweep_command{sweep}), ++index);

    BOOST_CHECK(read(id::pexpiretime, "e", {}, 5000) == redis_reply::integer(9000));
    BOOST_CHECK(read(id::pttl, "p", {}, 5000) == redis_reply::integer(-1));
    BOOST_CHECK(read(id::exists, "late", {}, 5000) == redis_reply::integer(0));
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 2U);
    // After the sweep, the deleted key cannot be revived by EXPIRE or PERSIST.
    BOOST_CHECK(exec(id::pexpireat, {"late", "9000"}, 4995) == redis_reply::integer(0));
    BOOST_CHECK(exec(id::persist, {"late"}, 4996) == redis_reply::integer(0));
}
