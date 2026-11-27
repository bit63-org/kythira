// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_hash_exec_unit_test.cpp
/// @brief Typed values and hashes in the memory store
///        (.kiro/specs/redis-general-data-types/ task 7, Requirements 9 and
///        10): type errors, empty hashes deleting their key, collection
///        limits, incremental size accounting, snapshots and splits, and two
///        replicas agreeing on a random stream of writes.

#define BOOST_TEST_MODULE redis_hash_exec_unit_test
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
               std::uint8_t policy = 0, bool mutable_key = false) -> std::vector<std::byte> {
    redis_kv_exec_command c;
    c._key = args.empty() ? "" : args[0];
    c._command_id = static_cast<std::uint16_t>(id);
    c._now_ms = now;
    c._policy = policy;
    if (mutable_key) {
        c._mutable_keys = {std::byte{0x01}};
    }
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
              std::uint8_t policy = 0, bool mutable_key = false) -> redis_reply {
        return decode_redis_reply(
            sm.apply(make_exec(id, std::move(args), now, policy, mutable_key), ++index));
    }

    /// HSET key f v [f v ...] with the fixture's limits.
    auto hset(const std::string& key, std::vector<std::string> pairs,
              redis_command_id id = redis_command_id::hset) -> redis_reply {
        std::vector<std::string> args{key, k_max_bytes, k_max_count};
        args.insert(args.end(), pairs.begin(), pairs.end());
        return exec(id, std::move(args));
    }

    auto read(redis_command_id id, const std::string& key, std::vector<std::string> args = {},
              std::uint64_t now = 1000) -> redis_reply {
        return sm.evaluate_read(id, key, args, now);
    }

    /// The byte total recomputed from scratch, as the incremental counter
    /// must keep it.
    [[nodiscard]] auto recount() const -> std::size_t {
        sm_type copy;
        copy.restore_from_snapshot(sm.get_state(), 1);
        return copy.approximate_size_bytes();
    }
};

auto bulk_list(std::initializer_list<const char*> items) -> std::vector<redis_reply> {
    std::vector<redis_reply> out;
    for (const auto* i : items) {
        out.push_back(redis_reply::bulk(i));
    }
    return out;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(hash_writes_and_reads, fixture) {
    BOOST_CHECK(hset("h", {"b", "2", "a", "1"}) == redis_reply::integer(2));
    BOOST_CHECK(hset("h", {"a", "1", "c", "3"}) == redis_reply::integer(1));
    BOOST_CHECK(hset("h", {"a", "one"}, redis_command_id::hmset) == redis_reply::simple("OK"));
    BOOST_CHECK(exec(redis_command_id::hsetnx, {"h", k_max_bytes, k_max_count, "a", "x"}) ==
                redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::hsetnx, {"h", k_max_bytes, k_max_count, "d", "4"}) ==
                redis_reply::integer(1));

    BOOST_CHECK(read(redis_command_id::hget, "h", {"a"}) == redis_reply::bulk("one"));
    BOOST_CHECK(read(redis_command_id::hget, "h", {"z"}) == redis_reply::null());
    BOOST_CHECK(read(redis_command_id::hmget, "h", {"a", "z"}) ==
                redis_reply::array({redis_reply::bulk("one"), redis_reply::null()}));
    BOOST_CHECK(read(redis_command_id::hlen, "h") == redis_reply::integer(4));
    BOOST_CHECK(read(redis_command_id::hexists, "h", {"c"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hstrlen, "h", {"a"}) == redis_reply::integer(3));
    // Byte order of the field (Requirement 9.3).
    BOOST_CHECK(read(redis_command_id::hkeys, "h") ==
                redis_reply::array(bulk_list({"a", "b", "c", "d"})));
    BOOST_CHECK(read(redis_command_id::hvals, "h") ==
                redis_reply::array(bulk_list({"one", "2", "3", "4"})));
    BOOST_CHECK(read(redis_command_id::hgetall, "h") ==
                redis_reply::map(bulk_list({"a", "one", "b", "2", "c", "3", "d", "4"})));
    BOOST_CHECK(read(redis_command_id::type, "h") == redis_reply::simple("hash"));
    BOOST_CHECK(read(redis_command_id::object, "h", {"ENCODING"}) == redis_reply::bulk("listpack"));
    BOOST_CHECK(read(redis_command_id::exists, "h") == redis_reply::integer(1));

    // Absent keys read as empty hashes.
    BOOST_CHECK(read(redis_command_id::hlen, "none") == redis_reply::integer(0));
    BOOST_CHECK(read(redis_command_id::hgetall, "none") == redis_reply::map({}));
    BOOST_CHECK(read(redis_command_id::hrandfield, "none") == redis_reply::null());
    BOOST_CHECK(read(redis_command_id::hrandfield, "none", {"3"}) == redis_reply::array({}));
}

BOOST_FIXTURE_TEST_CASE(empty_hash_deletes_its_key, fixture) {
    BOOST_CHECK(hset("h", {"a", "1", "b", "2"}) == redis_reply::integer(2));
    BOOST_CHECK(exec(redis_command_id::hdel, {"h", "a", "z"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::hdel, {"h", "b"}) == redis_reply::integer(1));
    BOOST_CHECK(sm.lookup("h") == nullptr);
    BOOST_CHECK_EQUAL(sm.approximate_key_count(), 0U);
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), 0U);
    BOOST_CHECK(read(redis_command_id::type, "h") == redis_reply::simple("none"));
}

BOOST_FIXTURE_TEST_CASE(wrong_type_changes_nothing, fixture) {
    const redis_reply wrongtype = redis_reply::error(std::string(k_redis_wrongtype));
    BOOST_CHECK(exec(redis_command_id::set, {"s", "v"}) == redis_reply::simple("OK"));
    BOOST_CHECK(hset("h", {"f", "v"}) == redis_reply::integer(1));

    BOOST_CHECK(hset("s", {"f", "v"}) == wrongtype);
    BOOST_CHECK(exec(redis_command_id::hdel, {"s", "f"}) == wrongtype);
    BOOST_CHECK(read(redis_command_id::hget, "s", {"f"}) == wrongtype);
    BOOST_CHECK(read(redis_command_id::hgetall, "s") == wrongtype);

    BOOST_CHECK(read(redis_command_id::get, "h") == wrongtype);
    BOOST_CHECK(read(redis_command_id::strlen, "h") == wrongtype);
    BOOST_CHECK(read(redis_command_id::getrange, "h", {"0", "1"}) == wrongtype);
    for (const auto& [id, args] :
         std::vector<std::pair<redis_command_id, std::vector<std::string>>>{
             {redis_command_id::incrby, {"h", "1"}},
             {redis_command_id::incrbyfloat, {"h", "1"}},
             {redis_command_id::append, {"h", "x", "100"}},
             {redis_command_id::setrange, {"h", "0", "x", "100"}},
             {redis_command_id::getdel, {"h"}},
             {redis_command_id::getex, {"h"}},
             {redis_command_id::set, {"h", "v", "GET"}},
         }) {
        BOOST_CHECK(exec(id, args) == wrongtype);
    }
    BOOST_CHECK(read(redis_command_id::hget, "h", {"f"}) == redis_reply::bulk("v"));
    // SETNX sees a live key; plain SET replaces any type, as in Redis.
    BOOST_CHECK(exec(redis_command_id::setnx, {"h", "v"}) == redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::set, {"h", "GET"}) == redis_reply::simple("OK"));
    BOOST_CHECK(read(redis_command_id::get, "h") == redis_reply::bulk("GET"));
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());
}

BOOST_FIXTURE_TEST_CASE(collection_limits_refuse_in_apply, fixture) {
    BOOST_CHECK(exec(redis_command_id::hset, {"h", "1000", "2", "a", "1", "b", "2"}) ==
                redis_reply::integer(2));
    BOOST_CHECK(exec(redis_command_id::hset, {"h", "1000", "2", "c", "3"}) ==
                redis_reply::error("ERR collection exceeds the configured maximum of 2 elements"));
    // Overwriting within the limits still works.
    BOOST_CHECK(exec(redis_command_id::hset, {"h", "1000", "2", "a", "9"}) ==
                redis_reply::integer(0));
    // Each field counts its bytes plus the element overhead.
    const auto per = std::to_string(2 * (2 + k_redis_element_overhead));
    BOOST_CHECK(
        exec(redis_command_id::hset, {"h", per, "10", "a", "long value"}) ==
        redis_reply::error("ERR collection exceeds the configured maximum of " + per + " bytes"));
    BOOST_CHECK(read(redis_command_id::hgetall, "h") ==
                redis_reply::map(bulk_list({"a", "9", "b", "2"})));
}

BOOST_FIXTURE_TEST_CASE(increments, fixture) {
    const auto incr = [&](const std::string& f, const std::string& d) {
        return exec(redis_command_id::hincrby, {"h", k_max_bytes, k_max_count, f, d});
    };
    const auto fincr = [&](const std::string& f, const std::string& d) {
        return exec(redis_command_id::hincrbyfloat, {"h", k_max_bytes, k_max_count, f, d});
    };
    BOOST_CHECK(incr("n", "5") == redis_reply::integer(5));
    BOOST_CHECK(incr("n", "-7") == redis_reply::integer(-2));
    BOOST_CHECK(incr("n", "9223372036854775807") == redis_reply::integer(9223372036854775805));
    BOOST_CHECK(incr("n", "3") == redis_reply::error("ERR increment or decrement would overflow"));
    BOOST_CHECK(fincr("f", "10.5") == redis_reply::bulk("10.5"));
    BOOST_CHECK(fincr("f", "0.1") == redis_reply::bulk("10.6"));
    BOOST_CHECK(fincr("f", "5.0e3") == redis_reply::bulk("5010.6"));
    BOOST_CHECK(hset("h", {"s", "abc"}) == redis_reply::integer(1));
    BOOST_CHECK(incr("s", "1") == redis_reply::error("ERR hash value is not an integer"));
    BOOST_CHECK(fincr("s", "1") == redis_reply::error("ERR hash value is not a float"));
    BOOST_CHECK(fincr("f", "inf") ==
                redis_reply::error("ERR increment would produce NaN or Infinity"));
}

BOOST_FIXTURE_TEST_CASE(deadlines_survive_field_changes, fixture) {
    BOOST_CHECK(hset("h", {"a", "1"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::pexpireat, {"h", "9000"}) == redis_reply::integer(1));
    BOOST_CHECK(hset("h", {"b", "2"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::hdel, {"h", "a"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::pexpiretime, "h") == redis_reply::integer(9000));
    BOOST_CHECK(read(redis_command_id::type, "h") == redis_reply::simple("hash"));
    BOOST_CHECK_EQUAL(sm.expiring_key_count(), 1U);
    BOOST_CHECK(exec(redis_command_id::persist, {"h"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hgetall, "h") == redis_reply::map(bulk_list({"b", "2"})));
    // An expired hash reads as absent and a write starts a fresh one.
    BOOST_CHECK(exec(redis_command_id::pexpireat, {"h", "9000"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hlen, "h", {}, 9000) == redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::hset, {"h", k_max_bytes, k_max_count, "c", "3"}, 9001) ==
                redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hgetall, "h", {}, 9001) ==
                redis_reply::map(bulk_list({"c", "3"})));
    BOOST_CHECK(read(redis_command_id::pttl, "h", {}, 9001) == redis_reply::integer(-1));
}

BOOST_FIXTURE_TEST_CASE(rename_and_copy_keep_the_type, fixture) {
    BOOST_CHECK(hset("h", {"a", "1"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::pexpireat, {"h", "9000"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::copy, {"h", "c"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::rename, {"h", "r"}) == redis_reply::simple("OK"));
    for (const auto* key : {"c", "r"}) {
        BOOST_CHECK(read(redis_command_id::hgetall, key) ==
                    redis_reply::map(bulk_list({"a", "1"})));
        BOOST_CHECK(read(redis_command_id::pexpiretime, key) == redis_reply::integer(9000));
    }
    // The copy shares the hash, but a write to one leaves the other alone.
    BOOST_CHECK(hset("c", {"b", "2"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hlen, "r") == redis_reply::integer(1));
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());
}

BOOST_FIXTURE_TEST_CASE(the_immutable_rule_on_hashes, fixture) {
    const redis_reply conflict = redis_reply::error("ERR value conflict for an existing key");
    const auto rule = redis_kv_exec_policy::immutable_rule;
    const auto args = [](std::vector<std::string> pairs) {
        std::vector<std::string> out{"h", k_max_bytes, k_max_count};
        out.insert(out.end(), pairs.begin(), pairs.end());
        return out;
    };
    // Creating a hash is allowed; changing it is not, unless nothing changes.
    BOOST_CHECK(exec(redis_command_id::hset, args({"a", "1"}), 1000, rule) ==
                redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::hset, args({"a", "1"}), 1000, rule) ==
                redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::hset, args({"b", "2"}), 1000, rule) == conflict);
    BOOST_CHECK(exec(redis_command_id::hdel, {"h", "a"}, 1000, rule) == conflict);
    BOOST_CHECK(exec(redis_command_id::hdel, {"h", "z"}, 1000, rule) == redis_reply::integer(0));
    BOOST_CHECK(exec(redis_command_id::hincrby, args({"a", "0"}), 1000, rule) ==
                redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::set, {"h", "v"}, 1000, rule) == conflict);
    // The mutable bit lifts it.
    BOOST_CHECK(exec(redis_command_id::hset, args({"b", "2"}), 1000, rule, true) ==
                redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::hlen, "h") == redis_reply::integer(2));
}

BOOST_FIXTURE_TEST_CASE(large_hashes_chunk_and_split, fixture) {
    // Enough fields for several chunks; insert in a scrambled order.
    std::vector<std::string> fields;
    for (int i = 0; i < 1000; ++i) {
        fields.push_back("f" + std::to_string((i * 7919) % 1000));
    }
    for (const auto& f : fields) {
        BOOST_REQUIRE(hset("big", {f, "value-" + f}) == redis_reply::integer(1));
    }
    const auto entry = sm.lookup("big");
    BOOST_REQUIRE(entry && entry->_hash);
    BOOST_CHECK_EQUAL(entry->_hash->size(), 1000U);
    BOOST_CHECK_GT(entry->_hash->chunks().size(), 1U);
    for (const auto& c : entry->_hash->chunks()) {
        BOOST_CHECK_LE(c->size(), k_redis_chunk_entries);
    }
    BOOST_CHECK(read(redis_command_id::object, "big", {"ENCODING"}) ==
                redis_reply::bulk("hashtable"));
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());

    // A write to a large hash copies one chunk and shares the rest.
    BOOST_CHECK(hset("big", {"f500", "changed"}) == redis_reply::integer(0));
    const auto after = sm.lookup("big");
    std::size_t shared = 0;
    for (std::size_t i = 0; i < after->_hash->chunks().size(); ++i) {
        shared += after->_hash->chunks()[i] == entry->_hash->chunks()[i] ? 1 : 0;
    }
    BOOST_CHECK_EQUAL(shared, after->_hash->chunks().size() - 1);
    // The handle taken before the write still reads the old hash.
    BOOST_CHECK_EQUAL(*entry->_hash->find("f500"), "value-f500");

    // Strings and hashes on both sides of a cut; split and absorb restore it.
    BOOST_CHECK(exec(redis_command_id::set, {"a-string", "x"}) == redis_reply::simple("OK"));
    BOOST_CHECK(hset("z-hash", {"f", "v"}) == redis_reply::integer(1));
    const auto whole = sm.get_state();
    const auto parts = sm.split_state({"m"});
    BOOST_REQUIRE_EQUAL(parts.size(), 2U);
    sm_type left;
    left.restore_from_snapshot(parts[0], 1);
    BOOST_CHECK_EQUAL(left.approximate_key_count(), 2U);
    left.absorb(parts[1], shard_range<std::string>{"m", std::nullopt});
    BOOST_CHECK(left.get_state() == whole);
    BOOST_CHECK_EQUAL(left.approximate_size_bytes(), sm.approximate_size_bytes());
    BOOST_CHECK(left.evaluate_read(redis_command_id::hget, "big", std::vector<std::string>{"f500"},
                                   1000) == redis_reply::bulk("changed"));
}

BOOST_FIXTURE_TEST_CASE(snapshots_refuse_bad_typed_sections, fixture) {
    BOOST_CHECK(hset("h", {"a", "1", "b", "2"}) == redis_reply::integer(2));
    auto blob = sm.get_state();
    sm_type other;
    other.restore_from_snapshot(blob, 1);
    BOOST_CHECK(other.get_state() == blob);
    // Swap the two fields' names so they are out of order.
    auto bad = blob;
    const auto a_at = std::ranges::search(bad, std::vector<std::byte>{std::byte{'a'}}).begin();
    const auto b_at = std::ranges::search(bad, std::vector<std::byte>{std::byte{'b'}}).begin();
    BOOST_REQUIRE(a_at != bad.end() && b_at != bad.end());
    std::swap(*a_at, *b_at);
    BOOST_CHECK_THROW(other.restore_from_snapshot(bad, 2), redis_kv_codec_error);
    // A typed section needs format level 3.
    sm_type plain;
    BOOST_CHECK_THROW(
        plain.restore_from_snapshot(std::vector<std::byte>{blob.begin() + 14, blob.end()}, 1),
        std::exception);
}

BOOST_AUTO_TEST_CASE(two_replicas_agree_on_a_random_stream, *boost::unit_test::timeout(60)) {
    // Requirement 9.3: the same log gives the same replies and the same
    // state bytes on every replica, whatever the writes.
    std::mt19937_64 rng{20261118};
    sm_type one;
    sm_type two;
    std::uint64_t index = 0;
    const auto both = [&](const std::vector<std::byte>& entry) {
        ++index;
        const auto r1 = one.apply(entry, index);
        const auto r2 = two.apply(entry, index);
        BOOST_REQUIRE(r1 == r2);
    };
    both(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}));
    const auto pick = [&](std::size_t n) {
        return std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
    };
    const std::vector<std::string> keys{"h0", "h1", "h2", "s0"};
    std::uint64_t now = 1000;
    for (int step = 0; step < 4000; ++step) {
        now += pick(5);
        const auto& key = keys[pick(keys.size())];
        const auto field = "f" + std::to_string(pick(300));
        std::vector<std::string> limits{key, "40000", "250"};
        switch (pick(8)) {
            case 0:
            case 1: {
                auto args = limits;
                for (std::size_t i = 0, n = 1 + pick(4); i < n; ++i) {
                    args.push_back("f" + std::to_string(pick(300)));
                    args.push_back(std::string(pick(40), static_cast<char>('a' + pick(26))));
                }
                both(make_exec(redis_command_id::hset, args, now));
                break;
            }
            case 2:
                both(make_exec(redis_command_id::hdel,
                               {key, field, "f" + std::to_string(pick(300))}, now));
                break;
            case 3: {
                auto args = limits;
                args.push_back(field);
                args.push_back(std::to_string(static_cast<int>(pick(200)) - 100));
                both(make_exec(redis_command_id::hincrby, args, now));
                break;
            }
            case 4: {
                auto args = limits;
                args.push_back(field);
                args.push_back("0." + std::to_string(pick(1000)));
                both(make_exec(redis_command_id::hincrbyfloat, args, now));
                break;
            }
            case 5:
                both(make_exec(redis_command_id::set, {key, "plain"}, now));
                break;
            case 6:
                both(make_exec(redis_command_id::pexpireat, {key, std::to_string(now + pick(50))},
                               now));
                break;
            default:
                both(make_exec(redis_command_id::rename, {key, keys[pick(keys.size())]}, now));
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
    BOOST_CHECK_EQUAL(one.approximate_size_bytes(), two.approximate_size_bytes());
}
