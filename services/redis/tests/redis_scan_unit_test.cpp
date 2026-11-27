// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_scan_unit_test.cpp
/// @brief The SCAN family's pieces that need no cluster
///        (.kiro/specs/redis-general-data-types/ task 12, Requirement 7):
///        Redis's glob, the key range a pattern's literal prefix narrows a
///        walk to, the cursor layout, the page codec of the internal hop,
///        the filter, and each store's ordered key walk.

#define BOOST_TEST_MODULE redis_scan_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_exec_appliers.hpp>
#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_scan.hpp>

#include <chrono>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using namespace kythira;

struct walked {
    std::string _key;
    std::uint64_t _expire;
    redis_value_type _type;
    auto operator==(const walked&) const -> bool = default;
};

template<typename Store>
auto walk(const Store& s, std::string_view from, const std::optional<std::string>& to,
          std::size_t stop_after = 1000) -> std::vector<walked> {
    std::vector<walked> out;
    s.scan_keys(from, to, [&](const std::string& k, std::uint64_t e, redis_value_type t) {
        out.push_back({k, e, t});
        return out.size() < stop_after;
    });
    return out;
}

auto exec_record(redis_command_id id, std::vector<std::string> args) -> redis_kv_exec_command {
    auto key = args[0];
    return make_redis_exec_record(std::move(key), static_cast<std::uint16_t>(id), std::move(args),
                                  1000, false, false);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_scan_tests)

BOOST_AUTO_TEST_CASE(glob_matches_as_redis_does) {
    const std::vector<std::tuple<std::string, std::string, bool>> cases{
        {"*", "", true},
        {"*", "anything", true},
        {"", "", true},
        {"", "x", false},
        {"h?llo", "hello", true},
        {"h?llo", "hllo", false},
        {"h*llo", "hllo", true},
        {"h*llo", "heeeello", true},
        {"h*llo", "hello!", false},
        {"h[ae]llo", "hallo", true},
        {"h[ae]llo", "hillo", false},
        {"h[^e]llo", "hallo", true},
        {"h[^e]llo", "hello", false},
        {"h[a-b]llo", "hbllo", true},
        {"h[b-a]llo", "hallo", true},  // a reversed range still matches
        {"h[a-b]llo", "hcllo", false},
        {"h\\*llo", "h*llo", true},
        {"h\\*llo", "hello", false},
        {"[\\]]", "]", true},
        {"a[bc", "ab", true},  // an unterminated class runs to the end
        {"*a*b*c", "xxaxxbxxc", true},
        {"*a*b*c", "xxaxxcxxb", false},
        {"a/*", "a/k1", true},
        {"a/*", "b/k1", false},
        {"**", "", true},
        {"?", "", false},
    };
    for (const auto& [pattern, text, expected] : cases) {
        BOOST_CHECK_MESSAGE(redis_glob_match(pattern, text) == expected,
                            "'" << pattern << "' on '" << text << "'");
    }
    BOOST_CHECK(redis_glob_match("H[A-C]LLO", "hbllo", true));
    BOOST_CHECK(!redis_glob_match("H[A-C]LLO", "hbllo", false));
}

BOOST_AUTO_TEST_CASE(many_stars_stay_linear) {
    const std::string pattern = "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
    const std::string text(20000, 'a');
    const auto start = std::chrono::steady_clock::now();
    BOOST_CHECK(!redis_glob_match(pattern, text));
    BOOST_CHECK(redis_glob_match(pattern, text + "b"));
    BOOST_CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds{5});
}

BOOST_AUTO_TEST_CASE(a_literal_prefix_narrows_the_range) {
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("a/k1*"), "a/k1");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("a?b"), "a");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("a[bc]"), "a");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("foo\\*bar*"), "foo*bar");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("plain"), "plain");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("*"), "");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix("ab\\"), "ab");
    BOOST_CHECK_EQUAL(redis_glob_literal_prefix(""), "");

    BOOST_CHECK(redis_prefix_successor("ab") == std::optional<std::string>("ac"));
    BOOST_CHECK(redis_prefix_successor("a\xff") == std::optional<std::string>("b"));
    BOOST_CHECK(!redis_prefix_successor("\xff\xff"));
    BOOST_CHECK(!redis_prefix_successor(""));
    // Every key with the prefix sorts below the successor, and the
    // successor itself does not have the prefix.
    for (const std::string key : {"a/k1", "a/k1\xff\xff", "a/k19"}) {
        BOOST_CHECK(key < *redis_prefix_successor("a/k1"));
    }
    BOOST_CHECK(!redis_prefix_successor("a/k1")->starts_with("a/k1"));
}

BOOST_AUTO_TEST_CASE(the_cursor_keeps_its_issuer_and_id) {
    for (const std::uint16_t index :
         {std::uint16_t{1}, std::uint16_t{3}, k_redis_cursor_max_index}) {
        for (const std::uint64_t id :
             {std::uint64_t{1}, std::uint64_t{12345}, k_redis_cursor_id_mask}) {
            const auto c = redis_cursor_make(index, id);
            BOOST_CHECK_NE(c, 0u);
            BOOST_CHECK_EQUAL(redis_cursor_index(c), index);
            BOOST_CHECK_EQUAL(redis_cursor_id(c), id);
        }
    }
    // An id wider than 50 bits never spills into the index.
    BOOST_CHECK_EQUAL(redis_cursor_index(redis_cursor_make(2, ~std::uint64_t{0})), 2);
}

BOOST_AUTO_TEST_CASE(the_filter_compares_types_as_redis_7_2) {
    const redis_scan_filter any;
    BOOST_CHECK(any.keeps("k", redis_value_type::list));
    const redis_scan_filter hashes{"", "HaSh"};
    BOOST_CHECK(hashes.keeps("k", redis_value_type::hash));
    BOOST_CHECK(!hashes.keeps("k", redis_value_type::set));
    const redis_scan_filter unknown{"", "zset"};
    BOOST_CHECK(!unknown.keeps("k", redis_value_type::string));
    BOOST_CHECK(!unknown.keeps("k", redis_value_type::hash));
    const redis_scan_filter both{"a/*", "string"};
    BOOST_CHECK(both.keeps("a/1", redis_value_type::string));
    BOOST_CHECK(!both.keeps("b/1", redis_value_type::string));
    BOOST_CHECK(!both.keeps("a/1", redis_value_type::list));
}

BOOST_AUTO_TEST_CASE(the_page_codec_round_trips) {
    std::mt19937 rng(12);
    for (int round = 0; round < 200; ++round) {
        redis_scan_page p;
        p._exhausted = (rng() & 1U) != 0;
        p._approximate_keys = rng();
        p._examined = rng() % 1000;
        if ((rng() & 1U) != 0) {
            p._last = std::string(rng() % 20, static_cast<char>(rng()));
        }
        if ((rng() & 1U) != 0) {
            p._range_end = std::string(rng() % 20, static_cast<char>(rng()));
        }
        for (std::uint32_t i = rng() % 10; i > 0; --i) {
            p._keys.emplace_back(rng() % 30, static_cast<char>(rng()));
        }
        const auto bytes = encode_redis_scan_page(p);
        const auto back = decode_redis_scan_page(bytes);
        BOOST_CHECK_EQUAL(back._exhausted, p._exhausted);
        BOOST_CHECK_EQUAL(back._approximate_keys, p._approximate_keys);
        BOOST_CHECK_EQUAL(back._examined, p._examined);
        BOOST_CHECK(back._last == p._last);
        BOOST_CHECK(back._range_end == p._range_end);
        BOOST_CHECK(back._keys == p._keys);
        if (!bytes.empty()) {
            BOOST_CHECK_THROW((void)decode_redis_scan_page(bytes.substr(0, bytes.size() - 1)),
                              std::runtime_error);
        }
        BOOST_CHECK_THROW((void)decode_redis_scan_page(bytes + "x"), std::runtime_error);
    }
    BOOST_CHECK_THROW((void)decode_redis_scan_page(""), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(each_store_walks_its_keys_in_order) {
    redis_kv_state_machine<std::uint64_t> memory;
    redis_kv_mvcc_state_machine<std::uint64_t> mvcc;
    std::uint64_t index = 0;
    const auto both = [&](const std::vector<std::byte>& record) {
        ++index;
        (void)memory.apply(record, index);
        (void)mvcc.apply_at(record, index);
    };
    both(encode_redis_kv_command(redis_kv_format_gate_command{"", 3}));
    both(encode_redis_kv_command(redis_kv_set_command{"b", {std::byte{'1'}}, 0}));
    both(encode_redis_kv_command(redis_kv_set_command{"d", {std::byte{'2'}}, 7000}));
    both(encode_redis_kv_command(
        exec_record(redis_command_id::hset, {"c", "1000000", "100000", "f", "v"})));
    both(encode_redis_kv_command(
        exec_record(redis_command_id::rpush, {"a", "1000000", "100000", "x"})));
    both(encode_redis_kv_command(redis_kv_set_command{"e", {std::byte{'3'}}, 0}));
    both(encode_redis_kv_command(redis_kv_del_command{"e"}));

    const std::vector<walked> all{{"a", 0, redis_value_type::list},
                                  {"b", 0, redis_value_type::string},
                                  {"c", 0, redis_value_type::hash},
                                  {"d", 7000, redis_value_type::string}};
    BOOST_CHECK(walk(memory, "", std::nullopt) == all);
    BOOST_CHECK(walk(mvcc, "", std::nullopt) == all);
    // `[from, to)`, and a walk stops when told.
    const std::vector<walked> middle{all[1], all[2]};
    BOOST_CHECK(walk(memory, "b", std::string("d")) == middle);
    BOOST_CHECK(walk(mvcc, std::string("a\0", 2), std::string("d")) == middle);
    BOOST_CHECK_EQUAL(walk(memory, "", std::nullopt, 1).size(), 1u);
    BOOST_CHECK(walk(memory, "z", std::nullopt).empty());
}

BOOST_AUTO_TEST_SUITE_END()
