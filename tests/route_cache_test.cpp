// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The route cache a node without Raft membership routes by, and the data
// node's routes answer and stale-epoch check (include/raft/route_cache.hpp,
// .kiro/specs/kinesis-independent-layers/ task 5, Requirement 6): splits,
// merges, leader changes, replica moves, answers out of order, suspect
// addresses and refresh fallback.

#define BOOST_TEST_MODULE route_cache_test

#include <boost/test/unit_test.hpp>

#include <raft/route_cache.hpp>
#include <raft/shard_map.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace {

using group = std::uint64_t;
using node = std::uint64_t;
using key = std::string;
using descriptor = kythira::shard_descriptor<group, key, node>;
using cache = kythira::route_cache<group, key, node>;
using range = kythira::shard_range<key>;
using kythira::shard_epoch;

auto bound(const char* k) -> std::optional<key> {
    return k == nullptr ? std::nullopt : std::optional<key>(k);
}

auto row(group g, const char* start, const char* end, std::uint64_t version,
         std::vector<node> voters, std::optional<node> leader = std::nullopt,
         std::uint64_t conf = 0, std::vector<node> learners = {}) -> descriptor {
    return descriptor{._group_id = g,
                      ._range = range{._start = bound(start), ._end = bound(end)},
                      ._epoch = shard_epoch{._version = version, ._conf_version = conf},
                      ._voters = std::move(voters),
                      ._learners = std::move(learners),
                      ._leader_hint = leader};
}

auto reply(std::vector<descriptor> rows) -> cache::routes_reply {
    cache::routes_reply r;
    r.routes = std::move(rows);
    for (node n = 1; n <= 9; ++n) {
        r.addresses.emplace_back(n, "data-" + std::to_string(n) + ":7000");
    }
    return r;
}

/// A fake data layer: answers from a map per address, counts calls.
struct fake_layer {
    std::map<std::string, kythira::shard_map<group, key, node>> nodes;
    std::vector<std::string> asked;

    auto fetcher() -> cache::fetcher {
        return [this](const std::string& address,
                      const range& r) -> std::optional<cache::routes_reply> {
            asked.push_back(address);
            const auto it = nodes.find(address);
            if (it == nodes.end()) {
                return std::nullopt;
            }
            return reply(kythira::routes_answer(it->second, r));
        };
    }
};

auto everything() -> range {
    return kythira::unbounded_shard_range<key>();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(front_end_cache)

BOOST_AUTO_TEST_CASE(a_cold_cache_refreshes_from_a_seed_and_routes_writes_to_the_leader) {
    fake_layer layer;
    layer.nodes["seed-a:7000"].upsert(row(1, nullptr, nullptr, 0, {1, 2, 3}, 2));
    cache c({"seed-a:7000"}, layer.fetcher());
    BOOST_TEST(!c.lookup("k").has_value());
    const auto r = c.ensure("k");
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->_group_id == 1U);
    BOOST_TEST((c.write_targets("k") == std::vector<node>{2, 1, 3}));
    BOOST_TEST((c.address_of(2) == std::optional<std::string>("data-2:7000")));
    // A warm cache does not ask again.
    (void)c.ensure("k");
    BOOST_TEST(layer.asked.size() == 1U);
}

BOOST_AUTO_TEST_CASE(a_split_replaces_the_parent_with_its_children) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    // Split at "m": the derived child keeps group 1, the new one is group 2,
    // both at version 1 + 2.
    BOOST_TEST(c.learn(reply({row(1, nullptr, "m", 3, {1, 2, 3}, 1),
                              row(2, "m", nullptr, 3, {1, 2, 3}, 2)})) == 2U);
    BOOST_TEST(c.lookup("a")->_group_id == 1U);
    BOOST_TEST(c.lookup("z")->_group_id == 2U);
    BOOST_TEST(c.routes().size() == 2U);
}

BOOST_AUTO_TEST_CASE(a_split_learned_one_child_at_a_time_never_leaves_an_overlap) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    // Only the new right child is learned (a stale-epoch answer for a key
    // in it): the parent row overlapping it is evicted.
    c.on_stale_epoch(row(2, "m", nullptr, 3, {1, 2, 3}, 2));
    BOOST_TEST(c.lookup("z")->_group_id == 2U);
    BOOST_TEST(!c.lookup("a").has_value());
    BOOST_TEST(c.routes().size() == 1U);
}

BOOST_AUTO_TEST_CASE(a_merge_replaces_both_sources_with_the_survivor) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, "m", 3, {1, 2, 3}, 1), row(2, "m", nullptr, 3, {1, 2, 3}, 2)}));
    BOOST_TEST(c.learn(reply({row(1, nullptr, nullptr, 4, {1, 2, 3}, 1)})) == 1U);
    BOOST_TEST(c.lookup("z")->_group_id == 1U);
    BOOST_TEST(c.routes().size() == 1U);
}

BOOST_AUTO_TEST_CASE(answers_arriving_out_of_order_never_move_the_cache_backwards) {
    cache c({}, {});
    // After a merge, a late answer still naming the merged-away source.
    c.learn(reply({row(1, nullptr, nullptr, 4, {1, 2, 3}, 1)}));
    BOOST_TEST(c.learn(reply({row(2, "m", nullptr, 3, {1, 2, 3}, 2)})) == 0U);
    BOOST_TEST(c.lookup("z")->_group_id == 1U);
    // After a split, a late answer naming the parent.
    cache d({}, {});
    d.learn(reply({row(1, nullptr, "m", 3, {1, 2, 3}), row(2, "m", nullptr, 3, {1, 2, 3})}));
    BOOST_TEST(d.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3})})) == 0U);
    BOOST_TEST(d.lookup("z")->_group_id == 2U);
    BOOST_TEST(d.stats().rows_ignored_stale == 1U);
}

BOOST_AUTO_TEST_CASE(a_leader_change_is_followed_through_not_leader_hints) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    c.on_not_leader(1, 3);
    BOOST_TEST(c.write_targets("k").front() == 3U);
    // Leader unknown: voters in order.
    c.on_not_leader(1, std::nullopt);
    BOOST_TEST((c.write_targets("k") == std::vector<node>{1, 2, 3}));
    // A same-epoch answer refreshes the hint but not the row.
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 2)}));
    BOOST_TEST(c.write_targets("k").front() == 2U);
    BOOST_TEST(c.stats().not_leader == 2U);
}

BOOST_AUTO_TEST_CASE(a_replica_move_is_picked_up_from_the_newer_conf_version) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1, 0)}));
    // Node 3 replaced by node 4: conf_version + 1.
    c.on_stale_epoch(row(1, nullptr, nullptr, 1, {1, 2, 4}, 1, 1));
    BOOST_TEST(c.lookup("k")->_voters == (std::vector<node>{1, 2, 4}));
    // The older membership arriving late is ignored.
    BOOST_TEST(c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1, 0)})) == 0U);
    BOOST_TEST(c.lookup("k")->_voters == (std::vector<node>{1, 2, 4}));
}

BOOST_AUTO_TEST_CASE(an_unknown_group_drops_the_row_so_the_next_call_refreshes) {
    fake_layer layer;
    layer.nodes["seed:7000"].upsert(row(5, nullptr, nullptr, 9, {4, 5, 6}, 4));
    cache c({"seed:7000"}, layer.fetcher());
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    c.on_unknown_group(1);
    BOOST_TEST(!c.lookup("k").has_value());
    BOOST_TEST(c.ensure("k")->_group_id == 5U);
}

BOOST_AUTO_TEST_CASE(reads_prefer_self_then_the_placement_group_then_the_rest) {
    cache c({}, {});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1, 0, {4})}));
    BOOST_TEST((c.read_targets("k") == std::vector<node>{1, 2, 3, 4}));
    BOOST_TEST((c.read_targets("k", node{3}) == std::vector<node>{3, 1, 2, 4}));
    auto zone_b = [](const node& n) { return n == 4 || n == 2; };
    BOOST_TEST((c.read_targets("k", node{9}, zone_b) == std::vector<node>{2, 4, 1, 3}));
    BOOST_TEST(c.read_targets("k", node{9}, zone_b).front() == 2U);
}

BOOST_AUTO_TEST_CASE(a_failed_connection_moves_a_node_back_and_clears_its_leadership) {
    cache c({}, {}, kythira::route_cache_options{.suspect_for = std::chrono::hours(1)});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    c.on_connection_failure(1);
    BOOST_TEST(c.suspect(1));
    BOOST_TEST((c.write_targets("k") == std::vector<node>{2, 3, 1}));
    BOOST_TEST((c.read_targets("k", node{1}) == std::vector<node>{2, 3, 1}));
    BOOST_TEST(!c.lookup("k")->_leader_hint.has_value());
}

BOOST_AUTO_TEST_CASE(suspicion_expires) {
    cache c({}, {}, kythira::route_cache_options{.suspect_for = std::chrono::milliseconds(0)});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    c.on_connection_failure(2);
    BOOST_TEST(!c.suspect(2));
}

BOOST_AUTO_TEST_CASE(refresh_tries_known_nodes_then_seeds_then_suspects) {
    fake_layer layer;
    layer.nodes["data-3:7000"].upsert(row(1, nullptr, nullptr, 2, {1, 2, 3}, 3));
    cache c({"seed:7000"}, layer.fetcher(),
            kythira::route_cache_options{.suspect_for = std::chrono::hours(1)});
    c.learn(reply({row(1, nullptr, nullptr, 1, {1, 2, 3}, 1)}));
    // Learned addresses for nodes 1-9; only data-3 answers. Mark 3 suspect:
    // it is asked after every other known node and the seed.
    c.on_connection_failure(3);
    layer.asked.clear();
    BOOST_TEST(c.refresh(everything()));
    BOOST_REQUIRE(!layer.asked.empty());
    BOOST_TEST(layer.asked.back() == "data-3:7000");
    const auto seed_at = std::ranges::find(layer.asked, std::string("seed:7000"));
    BOOST_TEST((seed_at != layer.asked.end() && seed_at + 1 == layer.asked.end() - 1));
    BOOST_TEST(c.lookup("k")->_epoch._version == 2U);
}

BOOST_AUTO_TEST_CASE(refresh_reports_failure_when_nobody_answers) {
    fake_layer layer;
    cache c({"a:1", "b:2"}, layer.fetcher());
    BOOST_TEST(!c.refresh(everything()));
    BOOST_TEST(!c.ensure("k").has_value());
    BOOST_TEST(c.stats().refresh_failures == 2U);
}

BOOST_AUTO_TEST_CASE(names_resolve_at_use) {
    cache c({}, {});
    c.learn(cache::routes_reply{.routes = {row(1, nullptr, nullptr, 1, {1})},
                                .addresses = {{1, "127.0.0.1:7000"}, {2, "[::1]:7001"}}});
    const auto v4 = c.resolve(1);
    BOOST_REQUIRE(v4.has_value());
    BOOST_TEST(!v4->empty());
    BOOST_TEST(!c.resolve(7).has_value());
}

BOOST_AUTO_TEST_CASE(host_port_splitting) {
    using kythira::split_host_port;
    BOOST_TEST(split_host_port("data-1:7000")->first == "data-1");
    BOOST_TEST(split_host_port("data-1:7000")->second == "7000");
    BOOST_TEST(split_host_port("[::1]:80")->first == "::1");
    BOOST_TEST(!split_host_port("::1:80").has_value());
    BOOST_TEST(!split_host_port("data-1").has_value());
    BOOST_TEST(!split_host_port("data-1:").has_value());
    BOOST_TEST(!split_host_port("data-1:http").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(data_node_side)

BOOST_AUTO_TEST_CASE(routes_answer_returns_overlapping_rows_with_fresh_leaders) {
    kythira::shard_map<group, key, node> map;
    map.upsert(row(1, nullptr, "g", 3, {1, 2, 3}));
    map.upsert(row(2, "g", "p", 3, {1, 2, 3}));
    map.upsert(row(3, "p", nullptr, 3, {1, 2, 3}));
    const auto some = kythira::routes_answer(map, range{._start = bound("h"), ._end = bound("q")});
    BOOST_TEST(some.size() == 2U);
    BOOST_TEST(some[0]._group_id == 2U);
    auto leaders = [](const group& g) -> std::optional<node> {
        return g == 2 ? std::optional<node>(3) : std::nullopt;
    };
    const auto hinted = kythira::routes_answer(map, everything(), leaders);
    BOOST_TEST(hinted.size() == 3U);
    BOOST_TEST((hinted[1]._leader_hint == std::optional<node>(3)));
    BOOST_TEST(!hinted[0]._leader_hint.has_value());
}

BOOST_AUTO_TEST_CASE(a_call_routed_with_an_old_epoch_gets_the_current_route) {
    kythira::shard_map<group, key, node> map;
    map.upsert(row(1, nullptr, "m", 3, {1, 2, 3}, std::nullopt, 2));
    map.upsert(row(2, "m", nullptr, 3, {1, 2, 3}));
    using kythira::route_check_kind;

    auto ok = kythira::check_route(map, group{1}, shard_epoch{3, 2}, key{"a"});
    BOOST_TEST((ok.kind == route_check_kind::current));
    // A newer epoch than this node's row: served (this row lags).
    BOOST_TEST((kythira::check_route(map, group{1}, shard_epoch{4, 2}, key{"a"}).kind ==
                route_check_kind::current));

    auto old_range = kythira::check_route(map, group{1}, shard_epoch{1, 2}, key{"a"});
    BOOST_TEST((old_range.kind == route_check_kind::stale));
    BOOST_TEST(old_range.route->_epoch._version == 3U);
    auto old_members = kythira::check_route(map, group{1}, shard_epoch{3, 1}, key{"a"});
    BOOST_TEST((old_members.kind == route_check_kind::stale));

    // Key now in another group (the caller has the pre-split parent).
    auto moved = kythira::check_route(map, group{1}, shard_epoch{3, 2}, key{"z"});
    BOOST_TEST((moved.kind == route_check_kind::stale));
    BOOST_TEST(moved.route->_group_id == 2U);

    // Group merged away: the owner of the key is sent.
    auto gone = kythira::check_route(map, group{7}, shard_epoch{1, 0}, key{"z"});
    BOOST_TEST((gone.kind == route_check_kind::stale));
    BOOST_TEST(gone.route->_group_id == 2U);

    kythira::shard_map<group, key, node> empty;
    BOOST_TEST((kythira::check_route(empty, group{7}, shard_epoch{}, key{"z"}).kind ==
                route_check_kind::unknown_group));
}

BOOST_AUTO_TEST_CASE(a_front_end_converges_through_stale_answers_after_a_split) {
    // End to end: the front end routes with the pre-split row, the data
    // node answers stale with the current route, and the next attempt is
    // current.
    kythira::shard_map<group, key, node> data_node;
    data_node.upsert(row(1, nullptr, nullptr, 1, {1, 2, 3}, 1));
    cache c({}, {});
    c.learn(reply(kythira::routes_answer(data_node, everything())));

    data_node.apply_split(
        row(1, nullptr, nullptr, 1, {1, 2, 3}, 1),
        {row(1, nullptr, "m", 3, {1, 2, 3}, 1), row(2, "m", nullptr, 3, {1, 2, 3}, 1)});
    const auto mine = c.lookup("z");
    auto answer = kythira::check_route(data_node, mine->_group_id, mine->_epoch, key{"z"});
    BOOST_REQUIRE((answer.kind == kythira::route_check_kind::stale));
    c.on_stale_epoch(*answer.route);
    const auto now = c.lookup("z");
    BOOST_TEST(now->_group_id == 2U);
    BOOST_TEST((kythira::check_route(data_node, now->_group_id, now->_epoch, key{"z"}).kind ==
                kythira::route_check_kind::current));
}

BOOST_AUTO_TEST_SUITE_END()
