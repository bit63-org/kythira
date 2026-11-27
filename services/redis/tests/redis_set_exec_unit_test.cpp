// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_set_exec_unit_test.cpp
/// @brief Sets in the memory store (.kiro/specs/redis-general-data-types/
///        task 8, Requirements 9 and 11): every set write as apply() decides
///        it, `SPOP` removing only members still present, the store forms
///        and `SMOVE`, reads, snapshots, and two replicas agreeing on a
///        random stream.

#define BOOST_TEST_MODULE redis_set_exec_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_state_machine.hpp>

#include <cstdint>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kythira;
using sm_type = redis_kv_state_machine<std::uint64_t>;

const std::string k_max_bytes = "1000000";
const std::string k_max_count = "1000";

auto make_exec(redis_command_id id, std::vector<std::string> args, std::uint64_t now,
               std::uint8_t policy = 0, std::byte mutable_bits = std::byte{0})
    -> std::vector<std::byte> {
    redis_kv_exec_command c;
    c._key = args.empty() ? "" : args[0];
    c._command_id = static_cast<std::uint16_t>(id);
    c._now_ms = now;
    c._policy = policy;
    c._mutable_keys = {mutable_bits};
    c._args = std::move(args);
    return encode_redis_kv_command(c);
}

struct fixture {
    sm_type sm;
    std::uint64_t index = 0;

    fixture() {
        (void)sm.apply(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}), ++index);
    }

    auto exec(redis_command_id id, std::vector<std::string> args, std::uint64_t now = 1000,
              std::uint8_t policy = 0, std::byte mutable_bits = std::byte{0}) -> redis_reply {
        return decode_redis_reply(
            sm.apply(make_exec(id, std::move(args), now, policy, mutable_bits), ++index));
    }

    auto sadd(const std::string& key, std::vector<std::string> members) -> redis_reply {
        std::vector<std::string> args{key, k_max_bytes, k_max_count};
        args.insert(args.end(), members.begin(), members.end());
        return exec(redis_command_id::sadd, std::move(args));
    }

    auto read(redis_command_id id, const std::string& key, std::vector<std::string> args = {},
              std::uint64_t now = 1000) -> redis_reply {
        return sm.evaluate_read(id, key, args, now);
    }

    [[nodiscard]] auto recount() const -> std::size_t {
        sm_type copy;
        copy.restore_from_snapshot(sm.get_state(), 1);
        return copy.approximate_size_bytes();
    }
};

auto bulks(std::initializer_list<const char*> items) -> std::vector<redis_reply> {
    std::vector<redis_reply> out;
    for (const auto* i : items) {
        out.push_back(redis_reply::bulk(i));
    }
    return out;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(set_writes_and_reads, fixture) {
    BOOST_CHECK(sadd("s", {"b", "a", "b"}) == redis_reply::integer(2));
    BOOST_CHECK(sadd("s", {"a", "c"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::smembers, "s") == redis_reply::set(bulks({"a", "b", "c"})));
    BOOST_CHECK(read(redis_command_id::scard, "s") == redis_reply::integer(3));
    BOOST_CHECK(read(redis_command_id::sismember, "s", {"b"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::smismember, "s", {"a", "z"}) ==
                redis_reply::array({redis_reply::integer(1), redis_reply::integer(0)}));
    BOOST_CHECK(read(redis_command_id::type, "s") == redis_reply::simple("set"));
    BOOST_CHECK(read(redis_command_id::object, "s", {"ENCODING"}) == redis_reply::bulk("listpack"));
    BOOST_CHECK(sadd("long", {std::string(65, 'x')}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::object, "long", {"ENCODING"}) ==
                redis_reply::bulk("hashtable"));
    BOOST_CHECK(sadd("n", {"1", "-2", "30"}) == redis_reply::integer(3));
    BOOST_CHECK(read(redis_command_id::object, "n", {"ENCODING"}) == redis_reply::bulk("intset"));
    BOOST_CHECK(exec(redis_command_id::srem, {"s", "a", "z"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::srem, {"s", "b", "c"}) == redis_reply::integer(2));
    BOOST_CHECK(sm.lookup("s") == nullptr);
    BOOST_CHECK(read(redis_command_id::smembers, "s") == redis_reply::set({}));
    BOOST_CHECK(read(redis_command_id::srandmember, "s") == redis_reply::null());
    BOOST_CHECK(read(redis_command_id::srandmember, "n", {"10"}) ==
                redis_reply::array(bulks({"-2", "1", "30"})));
    BOOST_CHECK(read(redis_command_id::srandmember, "n", {"-4"})._elements.size() == 4);
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());
}

BOOST_FIXTURE_TEST_CASE(spop_removes_only_what_is_still_there, fixture) {
    BOOST_CHECK(sadd("s", {"a", "b", "c"}) == redis_reply::integer(3));
    BOOST_CHECK(exec(redis_command_id::spop, {"s", "0", "b"}) == redis_reply::bulk("b"));
    // Picked by a leader that saw an older set: "b" is gone already.
    BOOST_CHECK(exec(redis_command_id::spop, {"s", "0", "b"}) == redis_reply::null());
    BOOST_CHECK(exec(redis_command_id::spop, {"s", "1", "a", "b", "c"}) ==
                redis_reply::set(bulks({"a", "c"})));
    BOOST_CHECK(sm.lookup("s") == nullptr);
    BOOST_CHECK(exec(redis_command_id::spop, {"s", "1"}) == redis_reply::set({}));
}

BOOST_FIXTURE_TEST_CASE(smove_and_the_store_forms, fixture) {
    const redis_reply wrongtype = redis_reply::error(std::string(k_redis_wrongtype));
    BOOST_CHECK(sadd("x", {"a", "b", "c"}) == redis_reply::integer(3));
    BOOST_CHECK(sadd("y", {"b", "c", "d"}) == redis_reply::integer(3));
    BOOST_CHECK(exec(redis_command_id::set, {"str", "v"}) == redis_reply::simple("OK"));

    const auto store = [&](redis_command_id id, std::vector<std::string> srcs) {
        std::vector<std::string> args{"dst", k_max_bytes, k_max_count};
        args.insert(args.end(), srcs.begin(), srcs.end());
        return exec(id, std::move(args));
    };
    BOOST_CHECK(store(redis_command_id::sinterstore, {"x", "y"}) == redis_reply::integer(2));
    BOOST_CHECK(read(redis_command_id::smembers, "dst") == redis_reply::set(bulks({"b", "c"})));
    BOOST_CHECK(store(redis_command_id::sunionstore, {"x", "y", "none"}) ==
                redis_reply::integer(4));
    BOOST_CHECK(store(redis_command_id::sdiffstore, {"x", "y"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::smembers, "dst") == redis_reply::set(bulks({"a"})));
    BOOST_CHECK(store(redis_command_id::sinterstore, {"x", "str"}) == wrongtype);
    // An empty result deletes the destination, whatever it held.
    BOOST_CHECK(exec(redis_command_id::set, {"dst", "string"}) == redis_reply::simple("OK"));
    BOOST_CHECK(store(redis_command_id::sinterstore, {"x", "none"}) == redis_reply::integer(0));
    BOOST_CHECK(sm.lookup("dst") == nullptr);

    const auto smove = [&](const std::string& src, const std::string& dst, const std::string& m) {
        return exec(redis_command_id::smove, {src, dst, k_max_bytes, k_max_count, m});
    };
    BOOST_CHECK(smove("x", "y", "a") == redis_reply::integer(1));
    BOOST_CHECK(smove("x", "y", "a") == redis_reply::integer(0));
    BOOST_CHECK(smove("x", "y", "b") == redis_reply::integer(1));
    BOOST_CHECK(smove("x", "x", "c") == redis_reply::integer(1));
    BOOST_CHECK(smove("x", "str", "c") == wrongtype);
    // A missing source answers 0 before either type is checked (smoveCommand).
    BOOST_CHECK(smove("none", "str", "c") == redis_reply::integer(0));
    BOOST_CHECK(smove("x", "z", "c") == redis_reply::integer(1));
    BOOST_CHECK(sm.lookup("x") == nullptr);
    BOOST_CHECK(read(redis_command_id::smembers, "y") ==
                redis_reply::set(bulks({"a", "b", "c", "d"})));
    BOOST_CHECK(read(redis_command_id::smembers, "z") == redis_reply::set(bulks({"c"})));
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());
}

BOOST_FIXTURE_TEST_CASE(types_limits_and_the_immutable_rule, fixture) {
    const redis_reply wrongtype = redis_reply::error(std::string(k_redis_wrongtype));
    const redis_reply conflict = redis_reply::error("ERR value conflict for an existing key");
    BOOST_CHECK(exec(redis_command_id::set, {"str", "v"}) == redis_reply::simple("OK"));
    BOOST_CHECK(sadd("str", {"a"}) == wrongtype);
    BOOST_CHECK(read(redis_command_id::smembers, "str") == wrongtype);
    BOOST_CHECK(sadd("s", {"q"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::get, "s") == wrongtype);
    BOOST_CHECK(read(redis_command_id::hgetall, "s") == wrongtype);
    BOOST_CHECK(exec(redis_command_id::sadd, {"s", "1000", "1", "b"}) ==
                redis_reply::error("ERR collection exceeds the configured maximum of 1 elements"));

    const auto rule = redis_kv_exec_policy::immutable_rule;
    BOOST_CHECK(exec(redis_command_id::sadd, {"t", k_max_bytes, k_max_count, "a"}, 1000, rule) ==
                redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::sadd, {"t", k_max_bytes, k_max_count, "a"}, 1000, rule) ==
                redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::sadd, {"t", k_max_bytes, k_max_count, "b"}, 1000, rule) ==
                conflict);
    BOOST_CHECK(exec(redis_command_id::srem, {"t", "a"}, 1000, rule) == conflict);
    BOOST_CHECK(exec(redis_command_id::srem, {"t", "z"}, 1000, rule) == redis_reply::integer(0));
    // SMOVE needs the source's bit, and the destination's when it changes.
    BOOST_CHECK(exec(redis_command_id::smove, {"t", "s", k_max_bytes, k_max_count, "a"}, 1000, rule,
                     std::byte{0x01}) == conflict);
    BOOST_CHECK(exec(redis_command_id::smove, {"t", "s", k_max_bytes, k_max_count, "a"}, 1000, rule,
                     std::byte{0x03}) == redis_reply::integer(1));
}

BOOST_FIXTURE_TEST_CASE(sets_round_trip_through_snapshots_and_splits, fixture) {
    std::vector<std::string> members;
    for (int i = 0; i < 600; ++i) {
        members.push_back("m" + std::to_string((i * 7919) % 600));
    }
    BOOST_CHECK(sadd("big", members) == redis_reply::integer(600));
    BOOST_CHECK(sadd("z", {"x"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::pexpireat, {"z", "9000"}) == redis_reply::integer(1));
    const auto whole = sm.get_state();
    sm_type copy;
    copy.restore_from_snapshot(whole, 1);
    BOOST_CHECK(copy.get_state() == whole);
    BOOST_CHECK_EQUAL(copy.approximate_size_bytes(), sm.approximate_size_bytes());
    const auto parts = sm.split_state({"m"});
    sm_type left;
    left.restore_from_snapshot(parts[0], 1);
    left.absorb(parts[1], shard_range<std::string>{"m", std::nullopt});
    BOOST_CHECK(left.get_state() == whole);
    BOOST_CHECK(left.evaluate_read(redis_command_id::pexpiretime, "z", std::vector<std::string>{},
                                   1000) == redis_reply::integer(9000));
}

BOOST_AUTO_TEST_CASE(two_replicas_agree_on_a_random_stream, *boost::unit_test::timeout(60)) {
    std::mt19937_64 rng{20261119};
    sm_type one;
    sm_type two;
    std::uint64_t index = 0;
    const auto both = [&](const std::vector<std::byte>& entry) {
        ++index;
        BOOST_REQUIRE(one.apply(entry, index) == two.apply(entry, index));
    };
    both(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}));
    const auto pick = [&](std::size_t n) {
        return std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
    };
    const std::vector<std::string> keys{"s0", "s1", "s2", "h0"};
    const auto member = [&] { return "m" + std::to_string(pick(200)); };
    std::uint64_t now = 1000;
    for (int step = 0; step < 4000; ++step) {
        now += pick(5);
        const auto& key = keys[pick(keys.size())];
        const auto& other = keys[pick(keys.size())];
        switch (pick(7)) {
            case 0:
            case 1: {
                std::vector<std::string> args{key, "20000", "150"};
                for (std::size_t i = 0, n = 1 + pick(5); i < n; ++i) {
                    args.push_back(member());
                }
                both(make_exec(redis_command_id::sadd, args, now));
                break;
            }
            case 2:
                both(make_exec(redis_command_id::srem, {key, member(), member()}, now));
                break;
            case 3:
                both(make_exec(redis_command_id::spop, {key, "1", member(), member()}, now));
                break;
            case 4:
                both(make_exec(redis_command_id::smove, {key, other, "20000", "150", member()},
                               now));
                break;
            case 5:
                both(make_exec(redis_command_id::sunionstore,
                               {key, "20000", "150", other, keys[pick(keys.size())]}, now));
                break;
            default:
                both(make_exec(redis_command_id::hset, {key, "20000", "150", member(), "v"}, now));
                break;
        }
        if (step % 500 == 0) {
            BOOST_REQUIRE(one.get_state() == two.get_state());
            sm_type fresh;
            fresh.restore_from_snapshot(one.get_state(), index);
            BOOST_REQUIRE_EQUAL(fresh.approximate_size_bytes(), one.approximate_size_bytes());
        }
    }
    BOOST_CHECK(one.get_state() == two.get_state());
}
