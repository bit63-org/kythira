// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The catalog's segment volume assignments
// (.kiro/specs/kinesis-independent-layers/ task 10, Requirements 9.4, 9.5
// and 9.8): the catalog leader seeds each replica's record from the
// settings' placement, and moves the volumes of a segment node that stays
// silent to one that answers, at the next epoch, never onto a node another
// replica's volume uses. Every node reads its own record back.

#define BOOST_TEST_MODULE kinesis_volume_keeper_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_volume_keeper.hpp>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace k = kythira::kinesis;

/// The in-process cluster with a switch for whether this node leads.
struct switchable_cluster {
    k::local_stream_cluster _inner;
    bool _leader = true;

    auto propose(const std::string& key, std::vector<std::byte> command,
                 k::admission a = k::admission::none) -> std::optional<k::apply_result> {
        return _inner.propose(key, std::move(command), a);
    }
    auto read(const std::string& key, const k::stream_reader& f) -> bool {
        return _inner.read(key, f);
    }
    [[nodiscard]] auto now_ms() const -> std::int64_t { return _inner.now_ms(); }
    [[nodiscard]] auto leads(const std::string& /*key*/) const -> bool { return _leader; }
};

/// Segment nodes a..e, each up or down, with room set per node.
struct segment_layer {
    std::vector<kythira::segment_node_info> _nodes;
    std::set<std::string> _down;
    std::map<std::string, std::uint64_t> _available;

    segment_layer() {
        for (const auto* id : {"a", "b", "c", "d", "e"}) {
            _nodes.push_back({._id = id, ._endpoint = std::string("seg-") + id + ":8443"});
        }
    }

    auto probe() -> k::segment_probe {
        return [this](const kythira::segment_node_info& n)
                   -> std::optional<std::pair<std::uint64_t, std::uint64_t>> {
            if (_down.contains(n._id)) {
                return std::nullopt;
            }
            const auto it = _available.find(n._id);
            const std::uint64_t avail = it == _available.end() ? 100 : it->second;
            return std::pair<std::uint64_t, std::uint64_t>{1000, avail};
        };
    }
};

auto config(segment_layer& layer, std::string self = "1") -> k::volume_keeper_config {
    return {._service = "kinesis",
            ._self = std::move(self),
            ._replicas = {"1", "2", "3"},
            ._nodes = layer._nodes,
            ._replace_after_ms = 30'000,
            ._probe = layer.probe()};
}

auto node_of(const std::vector<kythira::volume_assignment>& as, const std::string& replica)
    -> std::string {
    return kythira::assignment_of(as, replica)->_segment_node;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_leader_seeds_the_placement_every_replica_opened) {
    segment_layer layer;
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer));
    const auto p = keeper.pass(0);
    BOOST_TEST(p._leader);
    BOOST_TEST(p._seeded == 3U);
    BOOST_REQUIRE(p._self.has_value());
    // Exactly what each data node computed from its settings at start.
    const auto expected =
        kythira::initial_volume_assignments("kinesis", {"1", "2", "3"}, layer._nodes);
    BOOST_TEST((keeper.assignments() == expected));
    BOOST_TEST((*p._self == expected[0]));
    // Nothing more to do on the next pass.
    const auto again = keeper.pass(1000);
    BOOST_TEST(again._seeded == 0U);
    BOOST_TEST(again._replaced == 0U);
    BOOST_TEST(again._failures == 0U);
}

BOOST_AUTO_TEST_CASE(a_follower_only_reads_its_own_record) {
    segment_layer layer;
    switchable_cluster cluster;
    cluster._leader = false;
    k::volume_keeper keeper(cluster, config(layer, "2"));
    const auto p = keeper.pass(0);
    BOOST_TEST(!p._leader);
    BOOST_TEST(p._seeded == 0U);
    BOOST_TEST(!p._self.has_value());
    cluster._leader = true;
    (void)keeper.pass(0);
    cluster._leader = false;
    BOOST_TEST(keeper.pass(0)._self->_replica == "2");
}

BOOST_AUTO_TEST_CASE(a_silent_segment_node_loses_its_volume_after_the_grace_period) {
    segment_layer layer;
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer, "2"));
    (void)keeper.pass(0);
    const auto before = keeper.assignments();
    const auto lost = node_of(before, "2");  // "b"
    layer._down.insert(lost);
    layer._available["e"] = 900;  // the roomiest free node

    // Not yet: a short silence is a blip, not a lost node.
    BOOST_TEST(keeper.pass(1'000)._replaced == 0U);
    BOOST_TEST(keeper.pass(30'000)._replaced == 0U);
    const auto p = keeper.pass(31'000);
    BOOST_TEST(p._replaced == 1U);
    BOOST_REQUIRE(p._self.has_value());
    BOOST_TEST(p._self->_segment_node == "e");
    BOOST_TEST(p._self->_epoch == 2U);
    BOOST_TEST(p._self->_volume == "kinesis-2");
    // The others stayed put; no two replicas share a segment node.
    const auto after = keeper.assignments();
    BOOST_TEST(node_of(after, "1") == node_of(before, "1"));
    BOOST_TEST(node_of(after, "3") == node_of(before, "3"));
    std::set<std::string> used;
    for (const auto& a : after) {
        used.insert(a._segment_node);
    }
    BOOST_TEST(used.size() == 3U);
    // It came back: nothing moves back, and nothing moves again.
    layer._down.clear();
    BOOST_TEST(keeper.pass(40'000)._replaced == 0U);
    BOOST_TEST(kythira::assignment_of(keeper.assignments(), "2")->_epoch == 2U);
}

BOOST_AUTO_TEST_CASE(a_node_that_answers_again_in_time_keeps_its_volumes) {
    segment_layer layer;
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer));
    (void)keeper.pass(0);
    layer._down.insert("a");
    (void)keeper.pass(10'000);
    layer._down.clear();
    (void)keeper.pass(20'000);
    layer._down.insert("a");
    // Silent again from 35s: the clock restarted when it answered.
    (void)keeper.pass(35'000);
    BOOST_TEST(keeper.pass(60'000)._replaced == 0U);
    BOOST_TEST(keeper.pass(65'000)._replaced == 1U);
}

BOOST_AUTO_TEST_CASE(volumes_leaving_together_land_on_different_nodes) {
    segment_layer layer;
    layer._nodes.resize(4);  // a..d
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer));
    (void)keeper.pass(0);
    // a and b (replicas 1 and 2) go; only d answers spare, c holds 3.
    layer._down = {"a", "b"};
    (void)keeper.pass(0);
    const auto p = keeper.pass(30'000);
    BOOST_TEST(p._replaced == 1U);
    BOOST_TEST(p._unplaceable == 1U);
    const auto after = keeper.assignments();
    std::set<std::string> used;
    for (const auto& a : after) {
        used.insert(a._segment_node);
    }
    BOOST_TEST(used.contains("d"));
    BOOST_TEST(used.contains("c"));
}

BOOST_AUTO_TEST_CASE(a_new_leader_starts_its_own_silence_clock) {
    segment_layer layer;
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer));
    (void)keeper.pass(0);
    layer._down.insert("a");
    (void)keeper.pass(0);
    cluster._leader = false;
    (void)keeper.pass(20'000);
    cluster._leader = true;
    BOOST_TEST(keeper.pass(40'000)._replaced == 0U);
    BOOST_TEST(keeper.pass(70'000)._replaced == 1U);
}

BOOST_AUTO_TEST_CASE(a_lost_leader_counts_failures_and_changes_nothing) {
    segment_layer layer;
    switchable_cluster cluster;
    k::volume_keeper keeper(cluster, config(layer));
    cluster._inner.set_unavailable(true);
    const auto p = keeper.pass(0);
    BOOST_TEST(p._seeded == 0U);
    BOOST_TEST(p._failures == 3U);
    BOOST_TEST(keeper.assignments().empty());
}
