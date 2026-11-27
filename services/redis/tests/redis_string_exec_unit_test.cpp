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
