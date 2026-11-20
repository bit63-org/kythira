// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Where each data replica's segment volume goes
// (.kiro/specs/kinesis-independent-layers/ task 10, Requirements 9.4, 9.5
// and 9.8): replicas never share a segment node, placement groups are
// spread where the layer spans them, the node with the most room wins, and
// a replacement raises the epoch so the old writer is fenced.

#define BOOST_TEST_MODULE segment_volume_placement_test

#include <boost/test/unit_test.hpp>

#include <raft/segment_volume_placement.hpp>

#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using kythira::segment_node_info;
using kythira::volume_assignment;

auto node(std::string id, std::string group = {}, std::uint64_t available = 0)
    -> segment_node_info {
    return {._id = id,
            ._endpoint = "seg-" + id + ":8443",
            ._placement_group = std::move(group),
            ._capacity_bytes = available * 2,
            ._available_bytes = available};
}

auto nodes_of(const std::vector<volume_assignment>& as) -> std::set<std::string> {
    std::set<std::string> out;
    for (const auto& a : as) {
        out.insert(a._segment_node);
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(replicas_get_distinct_segment_nodes_at_epoch_one) {
    const auto as = kythira::initial_volume_assignments(
        "kinesis", {"1", "2", "3"}, {node("a"), node("b"), node("c"), node("d")});
    BOOST_REQUIRE_EQUAL(as.size(), 3U);
    BOOST_TEST(nodes_of(as).size() == 3U);
    for (const auto& a : as) {
        BOOST_TEST(a._epoch == 1U);
        BOOST_TEST(a._volume == "kinesis-" + a._replica);
    }
    // With nothing known about room, the lowest ids, in replica order.
    BOOST_TEST(as[0]._segment_node == "a");
    BOOST_TEST(as[1]._segment_node == "b");
    BOOST_TEST(as[2]._segment_node == "c");
}

BOOST_AUTO_TEST_CASE(placement_is_the_same_wherever_it_is_computed) {
    const std::vector<segment_node_info> one{node("c", "z1"), node("a", "z2"), node("b", "z1"),
                                             node("d", "z3")};
    const std::vector<segment_node_info> other{node("d", "z3"), node("b", "z1"), node("a", "z2"),
                                               node("c", "z1")};
    BOOST_TEST((kythira::initial_volume_assignments("kinesis", {"1", "2", "3"}, one) ==
                kythira::initial_volume_assignments("kinesis", {"1", "2", "3"}, other)));
}

BOOST_AUTO_TEST_CASE(placement_groups_are_spread_when_the_layer_spans_them) {
    // Lowest ids would put two replicas in z1; spreading takes z2 and z3.
    const auto as = kythira::initial_volume_assignments(
        "kinesis", {"1", "2", "3"},
        {node("a", "z1"), node("b", "z1"), node("c", "z2"), node("d", "z3")});
    std::set<std::string> groups;
    for (const auto& a : as) {
        groups.insert(a._segment_node == "a" || a._segment_node == "b" ? "z1"
                      : a._segment_node == "c"                         ? "z2"
                                                                       : "z3");
    }
    BOOST_TEST(groups.size() == 3U);
}

BOOST_AUTO_TEST_CASE(one_placement_group_still_serves) {
    const auto as = kythira::initial_volume_assignments(
        "kinesis", {"1", "2", "3"}, {node("a", "z1"), node("b", "z1"), node("c", "z1")});
    BOOST_TEST(nodes_of(as).size() == 3U);
}

BOOST_AUTO_TEST_CASE(the_node_with_the_most_room_wins_after_the_group_rule) {
    const std::vector<segment_node_info> ns{node("a", "z1", 10), node("b", "z2", 50),
                                            node("c", "z2", 90), node("d", "z1", 70)};
    // No peers: every group is free, so room decides.
    BOOST_TEST(kythira::choose_segment_node({}, ns)->_id == "c");
    // A peer on c (z2): z1 is preferred over the roomier b in z2.
    const std::vector<volume_assignment> peers{
        {._replica = "1", ._segment_node = "c", ._volume = "kinesis-1", ._epoch = 1}};
    BOOST_TEST(kythira::choose_segment_node(peers, ns)->_id == "d");
    // Excluding d leaves a in z1.
    BOOST_TEST(kythira::choose_segment_node(peers, ns, {"d"})->_id == "a");
}

BOOST_AUTO_TEST_CASE(too_few_segment_nodes_or_a_repeated_one_is_refused) {
    BOOST_CHECK_THROW((void)kythira::initial_volume_assignments("kinesis", {"1", "2", "3"},
                                                                {node("a"), node("b")}),
                      std::invalid_argument);
    BOOST_CHECK_THROW(
        (void)kythira::initial_volume_assignments("kinesis", {"1", "2"}, {node("a"), node("a")}),
        std::invalid_argument);
    BOOST_TEST(
        !kythira::choose_segment_node(
             {{._replica = "1", ._segment_node = "a", ._volume = "v", ._epoch = 1}}, {node("a")})
             .has_value());
}

BOOST_AUTO_TEST_CASE(a_replacement_moves_off_the_lost_node_and_its_peers_with_a_new_epoch) {
    const std::vector<segment_node_info> ns{node("a"), node("b"), node("c"), node("d")};
    const auto as = kythira::initial_volume_assignments("kinesis", {"1", "2", "3"}, ns);
    const std::vector<volume_assignment> peers{as[0], as[2]};
    const auto next = kythira::replace_volume(as[1], peers, ns);
    BOOST_REQUIRE(next.has_value());
    BOOST_TEST(next->_segment_node == "d");
    BOOST_TEST(next->_epoch == 2U);
    BOOST_TEST(next->_volume == as[1]._volume);
    BOOST_TEST(next->_replica == "2");
    // With no spare node there is nowhere to go.
    BOOST_TEST(!kythira::replace_volume(as[1], peers, {node("a"), node("b"), node("c")}));
}

BOOST_AUTO_TEST_CASE(volume_ids_are_checked) {
    BOOST_TEST(kythira::volume_id_for("kinesis", "12") == "kinesis-12");
    BOOST_TEST(kythira::volume_id_for("dynamodb", "node-a.1") == "dynamodb-node-a.1");
    BOOST_CHECK_THROW((void)kythira::volume_id_for("kinesis", ""), std::invalid_argument);
    BOOST_CHECK_THROW((void)kythira::volume_id_for("kinesis", "a/b"), std::invalid_argument);
    BOOST_CHECK_THROW((void)kythira::volume_id_for("", "1"), std::invalid_argument);
    BOOST_CHECK_THROW((void)kythira::volume_id_for("kinesis", std::string(130, 'x')),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(segment_node_lists_parse_and_bad_entries_are_named) {
    const auto ns = kythira::parse_segment_nodes("11=seg-a:8443@us-east-1a,12=seg-b:8443");
    BOOST_REQUIRE_EQUAL(ns.size(), 2U);
    BOOST_TEST(ns[0]._id == "11");
    BOOST_TEST(ns[0]._endpoint == "seg-a:8443");
    BOOST_TEST(ns[0]._placement_group == "us-east-1a");
    BOOST_TEST(ns[1]._placement_group.empty());
    BOOST_TEST(kythira::parse_segment_nodes("").empty());
    for (const auto* bad : {"11", "=seg:1", "11=", "11=seg", "11=seg:1@", "1=a:1,1=b:2"}) {
        BOOST_TEST_CONTEXT(bad) {
            BOOST_CHECK_THROW((void)kythira::parse_segment_nodes(bad), std::invalid_argument);
        }
    }
}

BOOST_AUTO_TEST_CASE(assignments_round_trip_as_json_and_junk_is_refused) {
    const volume_assignment a{
        ._replica = "2", ._segment_node = "d", ._volume = "kinesis-2", ._epoch = 7};
    const auto text = kythira::encode_volume_assignment(a);
    BOOST_TEST((kythira::decode_volume_assignment(text) == a));
    for (const auto* bad :
         {"", "[]", "{}", R"({"replica":"2","segment_node":"d","volume":"v","epoch":0})",
          R"({"replica":"","segment_node":"d","volume":"v","epoch":1})",
          R"({"replica":"2","segment_node":"d","volume":"v","epoch":-1})",
          R"({"replica":"2","segment_node":"d","volume":"v","epoch":1,"extra":1})",
          R"({"replica":2,"segment_node":"d","volume":"v","epoch":1})"}) {
        BOOST_TEST_CONTEXT(bad) {
            BOOST_TEST(!kythira::decode_volume_assignment(bad).has_value());
        }
    }
    BOOST_TEST(kythira::assignment_of({a}, "2").has_value());
    BOOST_TEST(!kythira::assignment_of({a}, "3").has_value());
    BOOST_TEST(kythira::segment_node_of({node("d")}, "d")->_endpoint == "seg-d:8443");
}
