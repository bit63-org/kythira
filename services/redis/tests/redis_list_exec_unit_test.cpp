// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_list_exec_unit_test.cpp
/// @brief Lists in the memory store (.kiro/specs/redis-general-data-types/
///        task 9, Requirement 12): every non-blocking list write as apply()
///        decides it, the reads, chunking that keeps end operations to one
///        chunk, snapshots, and two replicas agreeing on a random stream
///        checked against a plain `std::deque` model.

#define BOOST_TEST_MODULE redis_list_exec_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_state_machine.hpp>

#include <cstdint>
#include <deque>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kythira;
using sm_type = redis_kv_state_machine<std::uint64_t>;

const std::string k_max_bytes = "1000000";
const std::string k_max_count = "100000";

auto make_exec(redis_command_id id, std::vector<std::string> args, std::uint64_t now,
               std::uint8_t policy = 0) -> std::vector<std::byte> {
    redis_kv_exec_command c;
    c._key = args.empty() ? "" : args[0];
    c._command_id = static_cast<std::uint16_t>(id);
    c._now_ms = now;
    c._policy = policy;
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
              std::uint8_t policy = 0) -> redis_reply {
        return decode_redis_reply(sm.apply(make_exec(id, std::move(args), now, policy), ++index));
    }

    auto push(redis_command_id id, const std::string& key, std::vector<std::string> items)
        -> redis_reply {
        std::vector<std::string> args{key, k_max_bytes, k_max_count};
        args.insert(args.end(), items.begin(), items.end());
        return exec(id, std::move(args));
    }

    auto read(redis_command_id id, const std::string& key, std::vector<std::string> args = {})
        -> redis_reply {
        return sm.evaluate_read(id, key, args, 1000);
    }

    auto range(const std::string& key) -> redis_reply {
        return read(redis_command_id::lrange, key, {"0", "-1"});
    }

    [[nodiscard]] auto recount() const -> std::size_t {
        sm_type copy;
        copy.restore_from_snapshot(sm.get_state(), 1);
        return copy.approximate_size_bytes();
    }
};

auto bulks(std::initializer_list<const char*> items) -> redis_reply {
    std::vector<redis_reply> out;
    for (const auto* i : items) {
        out.push_back(redis_reply::bulk(i));
    }
    return redis_reply::array(std::move(out));
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(pushes_pops_and_reads, fixture) {
    BOOST_CHECK(push(redis_command_id::rpush, "l", {"b", "c"}) == redis_reply::integer(2));
    BOOST_CHECK(push(redis_command_id::lpush, "l", {"a", "z"}) == redis_reply::integer(4));
    BOOST_CHECK(range("l") == bulks({"z", "a", "b", "c"}));
    BOOST_CHECK(push(redis_command_id::rpushx, "none", {"x"}) == redis_reply::integer(0));
    BOOST_CHECK(sm.lookup("none") == nullptr);
    BOOST_CHECK(read(redis_command_id::llen, "l") == redis_reply::integer(4));
    BOOST_CHECK(read(redis_command_id::lindex, "l", {"-1"}) == redis_reply::bulk("c"));
    BOOST_CHECK(read(redis_command_id::lindex, "l", {"9"}) == redis_reply::null());
    BOOST_CHECK(read(redis_command_id::lrange, "l", {"1", "100"}) == bulks({"a", "b", "c"}));
    BOOST_CHECK(read(redis_command_id::lrange, "l", {"-2", "-3"}) == bulks({}));
    BOOST_CHECK(read(redis_command_id::type, "l") == redis_reply::simple("list"));
    BOOST_CHECK(read(redis_command_id::object, "l", {"ENCODING"}) ==
                redis_reply::bulk("quicklist"));

    BOOST_CHECK(exec(redis_command_id::lpop, {"l", "0", "1"}) == redis_reply::bulk("z"));
    BOOST_CHECK(exec(redis_command_id::rpop, {"l", "1", "2"}) == bulks({"c", "b"}));
    BOOST_CHECK(exec(redis_command_id::rpop, {"l", "1", "0"}) == redis_reply::array({}));
    BOOST_CHECK(exec(redis_command_id::rpop, {"l", "1", "9"}) == bulks({"a"}));
    BOOST_CHECK(sm.lookup("l") == nullptr);
    BOOST_CHECK(exec(redis_command_id::lpop, {"l", "0", "1"}) == redis_reply::null());
    BOOST_CHECK(exec(redis_command_id::lpop, {"l", "1", "2"}) == redis_reply::null_array());
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), 0U);
}

BOOST_FIXTURE_TEST_CASE(index_writes, fixture) {
    BOOST_CHECK(push(redis_command_id::rpush, "l", {"a", "b", "a", "c", "a"}) ==
                redis_reply::integer(5));
    BOOST_CHECK(exec(redis_command_id::lset, {"l", "-1", "A", k_max_bytes}) ==
                redis_reply::simple("OK"));
    BOOST_CHECK(exec(redis_command_id::lset, {"l", "5", "x", k_max_bytes}) ==
                redis_reply::error("ERR index out of range"));
    BOOST_CHECK(exec(redis_command_id::lset, {"none", "0", "x", k_max_bytes}) ==
                redis_reply::error("ERR no such key"));
    BOOST_CHECK(exec(redis_command_id::linsert, {"l", "BEFORE", "b", "x", k_max_bytes,
                                                 k_max_count}) == redis_reply::integer(6));
    BOOST_CHECK(exec(redis_command_id::linsert, {"l", "AFTER", "zz", "x", k_max_bytes,
                                                 k_max_count}) == redis_reply::integer(-1));
    BOOST_CHECK(exec(redis_command_id::linsert, {"none", "AFTER", "a", "x", k_max_bytes,
                                                 k_max_count}) == redis_reply::integer(0));
    BOOST_CHECK(range("l") == bulks({"a", "x", "b", "a", "c", "A"}));
    BOOST_CHECK(read(redis_command_id::lpos, "l", {"a", "1", "0", "0", "1"}) ==
                redis_reply::array({redis_reply::integer(0), redis_reply::integer(3)}));
    BOOST_CHECK(read(redis_command_id::lpos, "l", {"a", "-1", "1", "0", "0"}) ==
                redis_reply::integer(3));
    BOOST_CHECK(read(redis_command_id::lpos, "l", {"a", "2", "1", "0", "0"}) ==
                redis_reply::integer(3));
    BOOST_CHECK(read(redis_command_id::lpos, "l", {"a", "1", "1", "2", "0"}) ==
                redis_reply::integer(0));
    BOOST_CHECK(read(redis_command_id::lpos, "l", {"c", "1", "1", "2", "0"}) ==
                redis_reply::null());

    BOOST_CHECK(exec(redis_command_id::lrem, {"l", "-1", "a"}) == redis_reply::integer(1));
    BOOST_CHECK(range("l") == bulks({"a", "x", "b", "c", "A"}));
    BOOST_CHECK(exec(redis_command_id::lrem, {"l", "0", "x"}) == redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::ltrim, {"l", "1", "-2"}) == redis_reply::simple("OK"));
    BOOST_CHECK(range("l") == bulks({"b", "c"}));
    BOOST_CHECK(exec(redis_command_id::ltrim, {"l", "5", "10"}) == redis_reply::simple("OK"));
    BOOST_CHECK(sm.lookup("l") == nullptr);
}

BOOST_FIXTURE_TEST_CASE(moves_and_multi_pops, fixture) {
    BOOST_CHECK(push(redis_command_id::rpush, "a", {"1", "2", "3"}) == redis_reply::integer(3));
    BOOST_CHECK(exec(redis_command_id::lmove, {"a", "b", "RIGHT", "LEFT", k_max_bytes,
                                               k_max_count}) == redis_reply::bulk("3"));
    BOOST_CHECK(exec(redis_command_id::lmove, {"a", "a", "LEFT", "RIGHT", k_max_bytes,
                                               k_max_count}) == redis_reply::bulk("1"));
    BOOST_CHECK(range("a") == bulks({"2", "1"}));
    BOOST_CHECK(exec(redis_command_id::lmove, {"none", "a", "LEFT", "LEFT", k_max_bytes,
                                               k_max_count}) == redis_reply::null());
    BOOST_CHECK(exec(redis_command_id::set, {"s", "v"}) == redis_reply::simple("OK"));
    BOOST_CHECK(
        exec(redis_command_id::lmove, {"a", "s", "LEFT", "LEFT", k_max_bytes, k_max_count}) ==
        redis_reply::error(std::string(k_redis_wrongtype)));
    BOOST_CHECK(range("a") == bulks({"2", "1"}));

    BOOST_CHECK(exec(redis_command_id::lmpop, {"3", "none", "b", "a", "LEFT", "5"}) ==
                redis_reply::array({redis_reply::bulk("b"), bulks({"3"})}));
    BOOST_CHECK(exec(redis_command_id::lmpop, {"2", "b", "a", "RIGHT", "1"}) ==
                redis_reply::array({redis_reply::bulk("a"), bulks({"1"})}));
    BOOST_CHECK(exec(redis_command_id::lmpop, {"1", "none", "LEFT", "1"}) ==
                redis_reply::null_array());
    BOOST_CHECK(exec(redis_command_id::lmpop, {"2", "s", "a", "LEFT", "1"}) ==
                redis_reply::error(std::string(k_redis_wrongtype)));
    BOOST_CHECK_EQUAL(sm.approximate_size_bytes(), recount());
}

BOOST_FIXTURE_TEST_CASE(types_limits_and_the_immutable_rule, fixture) {
    const redis_reply wrongtype = redis_reply::error(std::string(k_redis_wrongtype));
    BOOST_CHECK(exec(redis_command_id::set, {"s", "v"}) == redis_reply::simple("OK"));
    BOOST_CHECK(push(redis_command_id::lpush, "s", {"x"}) == wrongtype);
    BOOST_CHECK(read(redis_command_id::lrange, "s", {"0", "-1"}) == wrongtype);
    BOOST_CHECK(push(redis_command_id::rpush, "l", {"x"}) == redis_reply::integer(1));
    BOOST_CHECK(read(redis_command_id::smembers, "l") == wrongtype);
    BOOST_CHECK(exec(redis_command_id::rpush, {"l", "1000", "1", "y"}) ==
                redis_reply::error("ERR collection exceeds the configured maximum of 1 elements"));
    const auto rule = redis_kv_exec_policy::immutable_rule;
    const redis_reply conflict = redis_reply::error("ERR value conflict for an existing key");
    BOOST_CHECK(exec(redis_command_id::rpush, {"new", k_max_bytes, k_max_count, "a"}, 1000, rule) ==
                redis_reply::integer(1));
    BOOST_CHECK(exec(redis_command_id::rpush, {"new", k_max_bytes, k_max_count, "b"}, 1000, rule) ==
                conflict);
    BOOST_CHECK(exec(redis_command_id::lpop, {"new", "0", "1"}, 1000, rule) == conflict);
    BOOST_CHECK(exec(redis_command_id::lset, {"new", "0", "a", k_max_bytes}, 1000, rule) ==
                redis_reply::simple("OK"));
    BOOST_CHECK(exec(redis_command_id::ltrim, {"new", "0", "-1"}, 1000, rule) ==
                redis_reply::simple("OK"));
}

BOOST_FIXTURE_TEST_CASE(end_operations_touch_one_chunk, fixture) {
    std::vector<std::string> items;
    for (int i = 0; i < 1000; ++i) {
        items.push_back(std::to_string(i));
    }
    BOOST_CHECK(push(redis_command_id::rpush, "l", items) == redis_reply::integer(1000));
    const auto before = sm.lookup("l");
    BOOST_REQUIRE(before && before->_list);
    BOOST_CHECK_GT(before->_list->chunks().size(), 5U);
    BOOST_CHECK(push(redis_command_id::rpush, "l", {"tail"}) == redis_reply::integer(1001));
    BOOST_CHECK(exec(redis_command_id::lpop, {"l", "0", "1"}) == redis_reply::bulk("0"));
    const auto after = sm.lookup("l");
    std::size_t shared = 0;
    for (const auto& c : after->_list->chunks()) {
        for (const auto& old : before->_list->chunks()) {
            shared += c == old ? 1 : 0;
        }
    }
    // Every chunk but the two ends is shared with the earlier list.
    BOOST_CHECK_GE(shared + 2, after->_list->chunks().size());
    BOOST_CHECK(read(redis_command_id::lindex, "l", {"499"}) == redis_reply::bulk("500"));
    BOOST_CHECK_EQUAL(before->_list->at(0), "0");

    const auto whole = sm.get_state();
    sm_type copy;
    copy.restore_from_snapshot(whole, 1);
    BOOST_CHECK(copy.get_state() == whole);
    BOOST_CHECK_EQUAL(copy.approximate_size_bytes(), sm.approximate_size_bytes());
}

BOOST_AUTO_TEST_CASE(two_replicas_agree_with_a_model, *boost::unit_test::timeout(60)) {
    std::mt19937_64 rng{20261120};
    sm_type one;
    sm_type two;
    std::deque<std::string> model;
    std::uint64_t index = 0;
    const auto both = [&](const std::vector<std::byte>& entry) {
        ++index;
        auto r1 = one.apply(entry, index);
        BOOST_REQUIRE(r1 == two.apply(entry, index));
        return decode_redis_reply(r1);
    };
    ++index;
    const auto gate = encode_redis_kv_command(redis_kv_format_gate_command{"", 3});
    (void)one.apply(gate, index);
    (void)two.apply(gate, index);
    const auto pick = [&](std::size_t n) {
        return std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
    };
    const auto value = [&] { return "v" + std::to_string(pick(20)); };
    for (int step = 0; step < 5000; ++step) {
        const auto len = static_cast<std::int64_t>(model.size());
        switch (pick(8)) {
            case 0: {
                auto v = value();
                both(make_exec(redis_command_id::rpush, {"l", k_max_bytes, k_max_count, v}, 1000));
                model.push_back(v);
                break;
            }
            case 1: {
                auto v = value();
                both(make_exec(redis_command_id::lpush, {"l", k_max_bytes, k_max_count, v}, 1000));
                model.push_front(v);
                break;
            }
            case 2:
                both(make_exec(redis_command_id::lpop, {"l", "1", "2"}, 1000));
                for (int i = 0; i < 2 && !model.empty(); ++i) {
                    model.pop_front();
                }
                break;
            case 3:
                both(make_exec(redis_command_id::rpop, {"l", "0", "1"}, 1000));
                if (!model.empty()) {
                    model.pop_back();
                }
                break;
            case 4: {
                if (model.empty()) {
                    break;
                }
                const auto i = pick(model.size());
                auto v = value();
                both(make_exec(redis_command_id::lset, {"l", std::to_string(i), v, k_max_bytes},
                               1000));
                model[i] = v;
                break;
            }
            case 5: {
                if (model.empty()) {
                    break;
                }
                const auto& pivot = model[pick(model.size())];
                const auto at = std::ranges::find(model, pivot) - model.begin();
                auto v = value();
                both(make_exec(redis_command_id::linsert,
                               {"l", "AFTER", pivot, v, k_max_bytes, k_max_count}, 1000));
                model.insert(model.begin() + at + 1, v);
                break;
            }
            case 6: {
                auto v = value();
                const auto r = both(make_exec(redis_command_id::lrem, {"l", "1", v}, 1000));
                if (auto it = std::ranges::find(model, v); it != model.end()) {
                    model.erase(it);
                    BOOST_REQUIRE(r == redis_reply::integer(1));
                }
                break;
            }
            default: {
                if (len < 300) {
                    break;
                }
                both(make_exec(redis_command_id::ltrim, {"l", "10", "-10"}, 1000));
                model.erase(model.end() - 9, model.end());
                model.erase(model.begin(), model.begin() + 10);
                break;
            }
        }
        if (step % 250 == 0) {
            const auto got = one.evaluate_read(redis_command_id::lrange, "l",
                                               std::vector<std::string>{"0", "-1"}, 1000);
            std::vector<redis_reply> want;
            for (const auto& v : model) {
                want.push_back(redis_reply::bulk(v));
            }
            BOOST_REQUIRE(got == redis_reply::array(want));
            BOOST_REQUIRE(one.get_state() == two.get_state());
        }
    }
}
