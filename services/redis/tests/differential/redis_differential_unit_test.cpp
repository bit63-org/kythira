// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#define BOOST_TEST_MODULE redis_differential_unit_test
#include <boost/test/unit_test.hpp>

#include "redis_differential.hpp"

#include <boost/json.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// The differential harness without containers: the reply parser, the
// generator's determinism, the comparison rules, the recording format, and
// the committed recordings in recs/ (redis_differential.hpp,
// redis_differential_test.cpp for the container run).

namespace diff = kythira::redis_diff;
namespace fs = std::filesystem;

namespace {

auto bulk(std::string s) -> diff::reply {
    return diff::reply{diff::reply_kind::bulk, std::move(s), 0, {}};
}
auto integer(std::int64_t v) -> diff::reply {
    return diff::reply{diff::reply_kind::integer, {}, v, {}};
}
auto cmd(std::vector<std::string> argv) -> diff::command {
    return diff::command{std::move(argv), "test"};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(parser)

BOOST_AUTO_TEST_CASE(parses_every_resp2_and_resp3_type) {
    using diff::reply_kind;
    BOOST_TEST((diff::parse_one("+OK\r\n").kind == reply_kind::simple));
    BOOST_TEST(diff::parse_one("-ERR x y\r\n").text == "ERR x y");
    BOOST_TEST(diff::parse_one(":-42\r\n").integer == -42);
    BOOST_TEST(diff::parse_one("$5\r\nhe\r\no\r\n").text == "he\r\no");
    BOOST_TEST((diff::parse_one("$-1\r\n").kind == reply_kind::null));
    BOOST_TEST((diff::parse_one("*-1\r\n").kind == reply_kind::null));
    BOOST_TEST((diff::parse_one("_\r\n").kind == reply_kind::null));
    BOOST_TEST(diff::parse_one(",3.5\r\n").text == "3.5");
    BOOST_TEST(diff::parse_one("#t\r\n").integer == 1);
    BOOST_TEST(diff::parse_one("(123456789012345678901234\r\n").text == "123456789012345678901234");
    BOOST_TEST(diff::parse_one("!7\r\nERR bad\r\n").text == "ERR bad");
    BOOST_TEST(diff::parse_one("=8\r\ntxt:abcd\r\n").text == "abcd");
    auto arr = diff::parse_one("*3\r\n:1\r\n$1\r\na\r\n*0\r\n");
    BOOST_TEST(arr.items.size() == 3U);
    BOOST_TEST((arr.items[2].kind == reply_kind::array));
    auto map = diff::parse_one("%1\r\n+k\r\n:2\r\n");
    BOOST_TEST(map.items.size() == 2U);
    BOOST_TEST((diff::parse_one("~2\r\n:1\r\n:2\r\n").kind == reply_kind::set));
    BOOST_TEST((diff::parse_one(">1\r\n+x\r\n").kind == reply_kind::push));
    // An attribute map is dropped and the reply it annotates is returned.
    BOOST_TEST(diff::parse_one("|1\r\n+ttl\r\n:3\r\n:7\r\n").integer == 7);
}

BOOST_AUTO_TEST_CASE(partial_input_asks_for_more_and_leaves_pos) {
    const std::string whole = "*2\r\n$3\r\nfoo\r\n:9\r\n+next\r\n";
    for (std::size_t cut = 0; cut < 17; ++cut) {
        std::size_t pos = 0;
        BOOST_TEST(!diff::parse_reply(std::string_view(whole).substr(0, cut), pos).has_value());
        BOOST_TEST(pos == 0U);
    }
    std::size_t pos = 0;
    auto r = diff::parse_reply(whole, pos);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(pos == 17U);
    BOOST_TEST(diff::parse_reply(whole, pos)->text == "next");
}

BOOST_AUTO_TEST_CASE(malformed_input_throws) {
    BOOST_CHECK_THROW(diff::parse_one("?x\r\n"), std::runtime_error);
    BOOST_CHECK_THROW(diff::parse_one(":12a\r\n"), std::runtime_error);
    BOOST_CHECK_THROW(diff::parse_one("$2\r\nabcd\r\n"), std::runtime_error);
    BOOST_CHECK_THROW(diff::parse_one("+OK\r\n+OK\r\n"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(display_is_one_line) {
    BOOST_TEST(diff::display(diff::parse_one("$3\r\na\"\n\r\n")) == R"("a\"\x0a")");
    BOOST_TEST(diff::display(diff::parse_one("%1\r\n+k\r\n:2\r\n")) == "{+k: (integer) 2}");
    BOOST_TEST(diff::display(diff::parse_one("*2\r\n$-1\r\n-ERR e\r\n")) ==
               "[(nil), (error) ERR e]");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(generator)

BOOST_AUTO_TEST_CASE(same_seed_same_stream_different_seed_different_stream) {
    diff::generator_options opt;
    BOOST_TEST((diff::generate(7, opt) == diff::generate(7, opt)));
    BOOST_TEST(diff::fingerprint(diff::generate(7, opt)) !=
               diff::fingerprint(diff::generate(8, opt)));
}

// The golden fingerprint: if this changes, a seed now produces a different
// stream, so recs/ no longer matches. Bump k_generator_version, regenerate
// recs/ (README.md) and update the value here in the same change.
BOOST_AUTO_TEST_CASE(seed_one_is_stable) {
    diff::generator_options opt;
    opt.tag = "s1";
    const auto stream = diff::generate(1, opt);
    BOOST_TEST(diff::k_generator_version == 1);
    BOOST_TEST(diff::fingerprint(stream) == 0x77c62aa7e4256344ULL,
               std::hex << diff::fingerprint(stream));
}

BOOST_AUTO_TEST_CASE(keys_stay_in_the_key_space_and_blocks_are_whole) {
    diff::generator_options opt;
    opt.length = 3000;
    opt.tag = "x";
    const auto stream = diff::generate(42, opt);
    BOOST_TEST(stream.size() >= opt.length);
    std::set<std::string> shapes;
    int depth = 0;
    for (const auto& c : stream) {
        shapes.insert(c.shape);
        const auto name = diff::detail::upper(c.argv.front());
        if (name == "MULTI" && c.shape == "multi_exec") {
            BOOST_TEST(depth == 0);
            depth = 1;
        } else if ((name == "EXEC" || name == "DISCARD") && c.shape == "multi_exec") {
            depth = 0;
        }
        for (std::size_t i = 1; i < c.argv.size(); ++i) {
            const auto& a = c.argv[i];
            if (a.size() == 3 && a[1] == ':' && a[2] == 'x') {
                BOOST_TEST((a[0] >= 'a' && a[0] < 'a' + 8));
            }
        }
    }
    BOOST_TEST(depth == 0);
    // Every shape turns up in a long stream.
    BOOST_TEST(shapes.size() == diff::shapes().size());
}

BOOST_AUTO_TEST_CASE(transactions_off_leaves_out_transaction_shapes) {
    diff::generator_options opt;
    opt.length = 2000;
    opt.transactions = false;
    for (const auto& c : diff::generate(3, opt)) {
        const auto name = diff::detail::upper(c.argv.front());
        BOOST_TEST(name != "MULTI");
        BOOST_TEST(name != "MSET");
        BOOST_TEST(name != "MGET");
        BOOST_TEST(name != "WATCH");
        BOOST_TEST((name != "DEL" || c.argv.size() <= 2));
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(comparison)

BOOST_AUTO_TEST_CASE(either_reference_is_a_match) {
    const auto c = cmd({"GET", "a:t"});
    BOOST_TEST((diff::classify(c, bulk("x"), bulk("y"), bulk("y")).result == diff::outcome::same));
    BOOST_TEST(
        (diff::classify(c, bulk("x"), std::nullopt, bulk("x")).result == diff::outcome::same));
    BOOST_TEST(
        (diff::classify(c, bulk("x"), bulk("y"), bulk("z")).result == diff::outcome::differs));
}

BOOST_AUTO_TEST_CASE(ttl_clock_tolerance) {
    const auto c = cmd({"TTL", "a:t"});
    auto v = diff::classify(c, integer(100), integer(100), integer(102));
    BOOST_TEST((v.result == diff::outcome::allowed));
    BOOST_TEST(v.rule == "clock");
    BOOST_TEST((diff::classify(c, integer(100), integer(100), integer(103)).result ==
                diff::outcome::differs));
    // -1 and -2 are exact answers, not clock readings.
    BOOST_TEST((diff::classify(c, integer(-2), integer(-2), integer(-1)).result ==
                diff::outcome::differs));
    BOOST_TEST((diff::classify(cmd({"STRLEN", "a:t"}), integer(1), integer(1), integer(2)).result ==
                diff::outcome::differs));
}

BOOST_AUTO_TEST_CASE(d2_unordered_collections) {
    const auto a = diff::parse_one("*2\r\n$1\r\nx\r\n$1\r\ny\r\n");
    const auto b = diff::parse_one("*2\r\n$1\r\ny\r\n$1\r\nx\r\n");
    auto v = diff::classify(cmd({"SMEMBERS", "s"}), a, a, b);
    BOOST_TEST(v.rule == "D2");
    BOOST_TEST((diff::classify(cmd({"MGET", "x", "y"}), a, a, b).result == diff::outcome::differs));
    const auto m1 = diff::parse_one("%2\r\n+f\r\n:1\r\n+g\r\n:2\r\n");
    const auto m2 = diff::parse_one("%2\r\n+g\r\n:2\r\n+f\r\n:1\r\n");
    const auto m3 = diff::parse_one("%2\r\n+g\r\n:1\r\n+f\r\n:2\r\n");
    BOOST_TEST(diff::classify(cmd({"HGETALL", "h"}), m1, m1, m2).rule == "D2");
    BOOST_TEST(
        (diff::classify(cmd({"HGETALL", "h"}), m1, m1, m3).result == diff::outcome::differs));
}

// Every gap names the task that closes it, and the list is explicit here so
// adding a gap is a visible decision in review, not a silent widening.
BOOST_AUTO_TEST_CASE(rules_are_named_and_gaps_name_their_task) {
    std::set<std::string> ids;
    for (const auto& r : diff::rules()) {
        BOOST_TEST(ids.insert(r.id).second, "duplicate rule " << r.id);
        BOOST_TEST(!r.description.empty());
        if (r.id.front() == 'G') {
            BOOST_TEST(r.reference.find("task") != std::string::npos, r.id);
        }
    }
    const std::set<std::string> expected{"clock", "D2", "G1", "G2"};
    BOOST_TEST((ids == expected));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recordings)

BOOST_AUTO_TEST_CASE(round_trip) {
    diff::recording r;
    r.server = "redis";
    r.version = "7.2.17";
    r.date = "2026-11-18";
    r.seed = 9;
    r.length = 1;
    r.entries.push_back({{"SET", "a:s9", "q\"\\"}, "set", "+OK\r\n", "+OK\r\n"});
    const auto text = diff::serialize(r);
    const auto back = diff::recording_from_json(boost::json::parse(text));
    BOOST_TEST(back.server == r.server);
    BOOST_TEST(back.seed == r.seed);
    BOOST_REQUIRE(back.entries.size() == 1U);
    BOOST_TEST((back.entries[0].argv == r.entries[0].argv));
    BOOST_TEST(back.entries[0].resp3 == "+OK\r\n");
}

// recs/ holds what Redis 7.2 and Valkey 8 answered to the default streams.
// Each must still be the stream its seed generates (else it is stale), and
// every reply must parse. Where the two references disagree is reported, so
// a regeneration that changes the set shows up in the log.
BOOST_AUTO_TEST_CASE(committed_recordings_match_the_generator) {
    const fs::path dir = KYTHIRA_REDIS_DIFF_RECS_DIR;
    std::size_t files = 0;
    std::map<std::uint64_t, std::map<std::string, diff::recording>> by_seed;
    for (const auto& f : fs::directory_iterator(dir)) {
        if (f.path().extension() != ".json") {
            continue;
        }
        ++files;
        std::ifstream in(f.path());
        std::stringstream text;
        text << in.rdbuf();
        auto rec = diff::recording_from_json(boost::json::parse(text.str()));
        BOOST_TEST(rec.generator_version == diff::k_generator_version, f.path());
        diff::generator_options opt;
        opt.length = rec.length;
        opt.tag = "s" + std::to_string(rec.seed);
        const auto stream = diff::generate(rec.seed, opt);
        BOOST_REQUIRE_EQUAL(stream.size(), rec.entries.size());
        for (std::size_t i = 0; i < stream.size(); ++i) {
            BOOST_TEST((stream[i].argv == rec.entries[i].argv), f.path() << " entry " << i);
            BOOST_CHECK_NO_THROW(diff::parse_one(rec.entries[i].resp2));
            BOOST_CHECK_NO_THROW(diff::parse_one(rec.entries[i].resp3));
        }
        by_seed[rec.seed][rec.server] = std::move(rec);
    }
    BOOST_TEST(files >= 2U);
    for (const auto& [seed, servers] : by_seed) {
        if (!servers.contains("redis") || !servers.contains("valkey")) {
            continue;
        }
        const auto& r = servers.at("redis");
        const auto& v = servers.at("valkey");
        std::size_t differ = 0;
        for (std::size_t i = 0; i < r.entries.size(); ++i) {
            differ += r.entries[i].resp2 != v.entries[i].resp2 ? 1 : 0;
            differ += r.entries[i].resp3 != v.entries[i].resp3 ? 1 : 0;
        }
        BOOST_TEST_MESSAGE("seed " << seed << ": Redis " << r.version << " and Valkey " << v.version
                                   << " disagree on " << differ << " replies");
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(difference_table_escapes_pipes) {
    diff::difference_row row{1,           3,           4,         {"ECHO", "a|b"},
                             bulk("a|b"), bulk("a|b"), bulk("c"), "DIFFERS"};
    const auto t = diff::render_difference_table({row});
    BOOST_TEST(t.find("`ECHO a\\|b`") != std::string::npos);
    BOOST_TEST(t.find("| DIFFERS |") != std::string::npos);
}
