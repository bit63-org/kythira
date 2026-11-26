// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_call_wire_unit_test.cpp
/// @brief The bytes of an authenticated call from a gateway to a front end
///        (redis_call_wire.hpp, .kiro/specs/redis-general-data-types/
///        task 17): every field round-trips, and every malformed payload
///        is refused.

#define BOOST_TEST_MODULE redis_call_wire_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_call_wire.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace wire = kythira::redis_call_wire;

namespace {

auto full_state() -> wire::call_state {
    wire::call_state s;
    s.user = "farm";
    s.resp_version = 3;
    s.isolation = 3;
    s.in_multi = true;
    s.multi_failed = true;
    s.watch_ts = 1ULL << 40U;
    s.watched = {"a/w", std::string("bin\0ary", 7)};
    s.queued = {{"SET", "a/k", "v"}, {"GET", "a/k"}, {"MSET", "a", "", "b", "2"}};
    return s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_state_round_trips) {
    const auto s = full_state();
    BOOST_CHECK(wire::decode_state(wire::encode_state(s)) == s);
    // The defaults: RESP2, no isolation, nothing watched or queued.
    wire::call_state plain;
    plain.user = "reader";
    BOOST_CHECK(wire::decode_state(wire::encode_state(plain)) == plain);
    // Every isolation level.
    for (std::uint8_t level = 0; level <= 3; ++level) {
        plain.isolation = level;
        BOOST_CHECK(wire::decode_state(wire::encode_state(plain)) == plain);
    }
}

BOOST_AUTO_TEST_CASE(an_answer_round_trips_without_the_queue) {
    wire::call_answer a{full_state(), true, "+QUEUED\r\n"};
    auto back = wire::decode_answer(wire::encode_answer(a));
    BOOST_REQUIRE(back.has_value());
    // The queue stays with the gateway: an answer never carries it.
    BOOST_CHECK(back->state.queued.empty());
    a.state.queued.clear();
    BOOST_CHECK(*back == a);
    wire::call_answer empty{wire::call_state{.user = "u"}, false, ""};
    BOOST_CHECK(wire::decode_answer(wire::encode_answer(empty)) == empty);
}

BOOST_AUTO_TEST_CASE(every_truncation_and_trailing_byte_is_refused) {
    const auto state = wire::encode_state(full_state());
    for (std::size_t n = 0; n < state.size(); ++n) {
        BOOST_CHECK_MESSAGE(!wire::decode_state(state.substr(0, n)), "state cut at " << n);
    }
    BOOST_CHECK(!wire::decode_state(state + '\0'));
    auto plain = full_state();
    plain.queued.clear();
    const auto answer = wire::encode_answer(wire::call_answer{plain, false, "+OK\r\n"});
    for (std::size_t n = 0; n < answer.size(); ++n) {
        BOOST_CHECK_MESSAGE(!wire::decode_answer(answer.substr(0, n)), "answer cut at " << n);
    }
    BOOST_CHECK(!wire::decode_answer(answer + 'x'));
}

BOOST_AUTO_TEST_CASE(bad_fields_are_refused) {
    wire::call_state s;
    s.user = "u";
    const auto good = wire::encode_state(s);
    // Byte 0 is the format, then the user (one length byte, one letter),
    // then the protocol, the isolation and the flags.
    auto with = [&](std::size_t at, char c) {
        auto b = good;
        b[at] = c;
        return b;
    };
    BOOST_CHECK(!wire::decode_state(with(0, 2)));  // a newer format
    BOOST_CHECK(!wire::decode_state(with(3, 1)));  // RESP1
    BOOST_CHECK(!wire::decode_state(with(3, 4)));  // RESP4
    BOOST_CHECK(!wire::decode_state(with(4, 5)));  // isolation past serializable
    BOOST_CHECK(!wire::decode_state(with(5, 4)));  // an unknown flag
    BOOST_CHECK(wire::decode_state(with(5, 3)).has_value());
    // A queued command with no words.
    auto q = s;
    q.queued = {{"PING"}};
    auto bytes = wire::encode_state(q);
    BOOST_REQUIRE_EQUAL(bytes[bytes.size() - 7], '\1');  // the queue's count
    bytes[bytes.size() - 6] = '\0';                      // argc 0
    BOOST_CHECK(!wire::decode_state(bytes.substr(0, bytes.size() - 5)));
    // An answer whose state carries a queue, or a queued flag past 1.
    BOOST_CHECK(!wire::decode_answer(wire::encode_state(q) + '\0' + '\0'));
    auto answer = wire::encode_answer(wire::call_answer{s, false, ""});
    answer[answer.size() - 2] = '\2';
    BOOST_CHECK(!wire::decode_answer(answer));
    // A huge forged count is refused before anything is reserved.
    auto huge = good;
    huge[huge.size() - 2] = '\x7f';  // the watched count
    BOOST_CHECK(!wire::decode_state(huge));
}
