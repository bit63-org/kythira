// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_txn_view_unit_test.cpp
/// @brief Typed values in transactions (.kiro/specs/redis-general-data-types/
///        task 11, Requirement 13.4): the transaction view the front end
///        evaluates commands against, the record the commit proposes for
///        each key it changed, and `KYTHIRA.INSTALL`, which applies that
///        record in every store exactly as the view evaluated it.

#define BOOST_TEST_MODULE redis_txn_view_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_txn_view.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kythira;
using sm_type = redis_kv_state_machine<std::uint64_t>;
using entry_handle = redis_txn_view::entry_handle;

constexpr std::uint64_t k_now = 1000;

auto exec_record(redis_command_id id, std::vector<std::string> args, std::uint64_t now = k_now)
    -> redis_kv_exec_command {
    // The key is copied first: argument evaluation order is unspecified.
    auto key = args.empty() ? std::string{} : args[0];
    return make_redis_exec_record(std::move(key), static_cast<std::uint16_t>(id), std::move(args),
                                  now, false, false);
}

/// A memory store past the gate, with commands applied in log order.
struct store {
    sm_type sm;
    std::uint64_t index = 0;
    store() { apply(encode_redis_kv_command(redis_kv_format_gate_command{"", 3})); }
    auto apply(const std::vector<std::byte>& record) -> std::vector<std::byte> {
        return sm.apply(record, ++index);
    }
    auto exec(redis_command_id id, std::vector<std::string> args) -> redis_reply {
        return decode_redis_reply(apply(encode_redis_kv_command(exec_record(id, std::move(args)))));
    }
    auto read(redis_command_id id, const std::string& key, std::vector<std::string> args = {})
        -> redis_reply {
        return sm.evaluate_read(id, key, args, k_now);
    }
    [[nodiscard]] auto entry(const std::string& key) const -> entry_handle {
        return sm.lookup(key);
    }
};

/// A view whose committed state is `committed`, counting reads.
struct view_over {
    std::map<std::string, entry_handle> committed;
    int reads = 0;
    redis_txn_view view{[this](const std::string& key) -> entry_handle {
        ++reads;
        auto it = committed.find(key);
        return it == committed.end() ? nullptr : it->second;
    }};
};

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_txn_view_tests)

BOOST_AUTO_TEST_CASE(the_view_reads_each_key_once_and_keeps_its_writes) {
    store s;
    BOOST_REQUIRE(!s.exec(redis_command_id::hset, {"h", "1000000", "100000", "f", "1"}).is_error());
    view_over v;
    v.committed["h"] = s.entry("h");

    auto reply = apply_redis_exec(
        v.view, exec_record(redis_command_id::hincrby, {"h", "1000000", "100000", "f", "5"}),
        k_now);
    BOOST_REQUIRE(reply);
    BOOST_CHECK_EQUAL(reply->_integer, 6);
    reply = apply_redis_exec(
        v.view, exec_record(redis_command_id::hincrby, {"h", "1000000", "100000", "f", "1"}),
        k_now);
    BOOST_CHECK_EQUAL(reply->_integer, 7);
    BOOST_CHECK_EQUAL(v.reads, 1);

    // The committed hash is untouched: the view wrote a new value.
    BOOST_CHECK_EQUAL(s.read(redis_command_id::hget, "h", {"f"})._text, "1");
    BOOST_REQUIRE_EQUAL(v.view.writes().size(), 1u);
    const auto& written = v.view.writes().at("h");
    BOOST_REQUIRE(written);
    BOOST_CHECK(written->_type == redis_value_type::hash);
}

BOOST_AUTO_TEST_CASE(erasing_what_is_not_there_writes_nothing) {
    view_over v;
    BOOST_CHECK(!v.view.erase("absent"));
    BOOST_CHECK(v.view.writes().empty());
    v.view.put("k", {std::byte{'v'}}, 0);
    BOOST_CHECK(v.view.erase("k"));
    BOOST_REQUIRE_EQUAL(v.view.writes().size(), 1u);
    BOOST_CHECK(v.view.writes().at("k") == nullptr);
    BOOST_CHECK(!v.view.find("k"));
}

BOOST_AUTO_TEST_CASE(a_read_that_throws_is_remembered) {
    redis_txn_view view(
        [](const std::string&) -> entry_handle { throw std::runtime_error("shard unreachable"); });
    BOOST_CHECK(!view.failure());
    BOOST_CHECK_THROW((void)view.find("k"), std::runtime_error);
    BOOST_CHECK(view.failure());
}

BOOST_AUTO_TEST_CASE(the_commit_record_matches_the_value) {
    view_over v;
    // A deletion, a string with its deadline, and each collection.
    v.view.put("s", {std::byte{'x'}}, 5000);
    BOOST_REQUIRE(apply_redis_exec(
        v.view, exec_record(redis_command_id::hset, {"h", "1000000", "100000", "b", "2", "a", "1"}),
        k_now));
    BOOST_REQUIRE(apply_redis_exec(
        v.view, exec_record(redis_command_id::sadd, {"t", "1000000", "100000", "m", "l"}), k_now));
    BOOST_REQUIRE(apply_redis_exec(
        v.view, exec_record(redis_command_id::rpush, {"l", "1000000", "100000", "x", "y", "x"}),
        k_now));
    store s;
    s.apply(redis_txn_write_record("gone", nullptr, k_now));
    for (const auto& [key, entry] : v.view.writes()) {
        const auto record = redis_txn_write_record(key, entry, k_now);
        if (key == "s") {
            BOOST_CHECK(
                std::holds_alternative<redis_kv_set_command>(decode_redis_kv_command(record)));
        } else {
            BOOST_CHECK_NO_THROW((void)decode_redis_kv_v3_command(record));
        }
        s.apply(record);
    }
    BOOST_CHECK_EQUAL(s.read(redis_command_id::get, "s")._text, "x");
    BOOST_CHECK_EQUAL(s.read(redis_command_id::pexpiretime, "s")._integer, 5000);
    const auto all = s.read(redis_command_id::hgetall, "h");
    BOOST_REQUIRE_EQUAL(all._elements.size(), 4u);
    BOOST_CHECK_EQUAL(all._elements[0]._text, "a");
    BOOST_CHECK_EQUAL(all._elements[3]._text, "2");
    BOOST_CHECK_EQUAL(s.read(redis_command_id::scard, "t")._integer, 2);
    const auto range = s.read(redis_command_id::lrange, "l", {"0", "-1"});
    BOOST_REQUIRE_EQUAL(range._elements.size(), 3u);
    BOOST_CHECK_EQUAL(range._elements[1]._text, "y");
}

BOOST_AUTO_TEST_CASE(install_replaces_the_value_and_honours_its_deadline) {
    store s;
    BOOST_REQUIRE(!s.exec(redis_command_id::rpush, {"k", "1000000", "100000", "old"}).is_error());
    auto install = [&](std::vector<std::string> args, std::uint64_t now = k_now) {
        return decode_redis_reply(s.apply(encode_redis_kv_command(
            exec_record(redis_command_id::kythira_install, std::move(args), now))));
    };
    // A set replaces the list outright, deadline included.
    BOOST_CHECK_EQUAL(install({"k", "set", "9000", "a", "b"})._text, "OK");
    BOOST_CHECK_EQUAL(s.read(redis_command_id::type, "k")._text, "set");
    BOOST_CHECK_EQUAL(s.read(redis_command_id::pexpiretime, "k")._integer, 9000);
    // A deadline already past deletes the key, as SET ... PXAT does.
    BOOST_CHECK_EQUAL(install({"k", "hash", "900", "f", "v"})._text, "OK");
    BOOST_CHECK_EQUAL(s.read(redis_command_id::exists, "k")._integer, 0);
    // Malformed records change nothing.
    BOOST_CHECK_EQUAL(install({"m", "string", "0", "v"})._text, "OK");
    for (const auto& bad : std::vector<std::vector<std::string>>{
             {"m", "hash", "0", "b", "1", "a", "2"},  // fields out of order
             {"m", "hash", "0", "f"},                 // a field without a value
             {"m", "set", "0", "b", "a"},             // members out of order
             {"m", "set", "0", "a", "a"},             // a duplicate member
             {"m", "string", "0", "a", "b"},          // two strings
             {"m", "zset", "0", "a"},                 // no such type
             {"m", "list", "01", "a"},                // not a canonical number
             {"m", "list", "0"}}) {                   // too short
        BOOST_CHECK(install(bad).is_error());
    }
    BOOST_CHECK_EQUAL(s.read(redis_command_id::get, "m")._text, "v");
}

BOOST_AUTO_TEST_CASE(install_round_trips_random_collections_in_every_store) {
    std::mt19937 rng(11);
    store memory;
    redis_kv_mvcc_state_machine<std::uint64_t> mvcc;
    (void)mvcc.apply_at(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}), 1);
    for (int round = 0; round < 50; ++round) {
        view_over v;
        const auto key = "k" + std::to_string(round % 7);
        const auto n = 1 + rng() % 40;
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto member = "m" + std::to_string(rng() % 60);
            switch (round % 3) {
                case 0:
                    (void)apply_redis_exec(
                        v.view,
                        exec_record(redis_command_id::hset,
                                    {key, "1000000", "100000", member, std::to_string(i)}),
                        k_now);
                    break;
                case 1:
                    (void)apply_redis_exec(
                        v.view,
                        exec_record(redis_command_id::sadd, {key, "1000000", "100000", member}),
                        k_now);
                    break;
                default:
                    (void)apply_redis_exec(
                        v.view,
                        exec_record(redis_command_id::lpush, {key, "1000000", "100000", member}),
                        k_now);
                    break;
            }
        }
        const auto& expected = v.view.writes().at(key);
        const auto record = redis_txn_write_record(key, expected, k_now);
        memory.apply(record);
        (void)mvcc.apply_at(record, 10 + round);
        for (const auto& got : {memory.entry(key), mvcc.read_at(key, 10 + round)}) {
            BOOST_REQUIRE(got);
            BOOST_CHECK(make_redis_install_args(key, *got) ==
                        make_redis_install_args(key, *expected));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
