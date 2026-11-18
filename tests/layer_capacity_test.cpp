// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// Scaling the stateless layers: the snapshot built from layer members, the
/// layer capacity policy, and the drain hooks that drain a member through
/// the membership group (kinesis-independent-layers task 12,
/// Requirements 10.4 and 10.5).

#define BOOST_TEST_MODULE layer_capacity_test
#include <boost/test/unit_test.hpp>

#include <raft/layer_capacity.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using kythira::capacity_reason;
using kythira::capacity_watermark;
using kythira::layers::drain_state;
using kythira::layers::layer_capacity_config;
using kythira::layers::layer_capacity_policy;
using kythira::layers::layer_capacity_snapshot;
using kythira::layers::layer_member;
using kythira::layers::role;
using kythira::layers::role_set;

namespace {

constexpr std::int64_t stale_ms = 30'000;

auto front_end(std::string id, double rps, std::string zone = "zone-a", double cpu = 0.2,
               std::int64_t reported_at = 0) -> layer_member {
    layer_member m;
    m.id = std::move(id);
    m.roles = role_set{role::front_end};
    m.address = m.id + ":7100";
    m.placement_group = std::move(zone);
    m.load.requests_per_second = rps;
    m.load.cpu = cpu;
    m.announced_at_ms = reported_at;
    m.reported_at_ms = reported_at;
    return m;
}

auto enabled_config() -> layer_capacity_config {
    layer_capacity_config c;
    c.enabled = true;
    c.requests_per_member = {._high = 1000.0, ._low = 300.0};
    c.sustained_for = 2min;
    c.sustained_for_scale_in = 10min;
    c.cooldown = 5min;
    return c;
}

/// Feeds the same members to the policy once a minute for `minutes`,
/// stamping each report with the evaluation time so none is stale. Returns
/// the last decision.
auto run(layer_capacity_policy<>& p, std::vector<layer_member> members, std::int64_t& now_ms,
         int minutes, const layer_capacity_config& cfg) {
    kythira::capacity_decision<std::string, std::string> last;
    for (int i = 0; i < minutes; ++i) {
        for (auto& m : members) {
            m.reported_at_ms = now_ms;
        }
        last = p.evaluate(
            layer_capacity_snapshot(members, role_set{role::front_end}, now_ms, stale_ms, cfg));
        if (!last.is_hold()) {
            return last;
        }
        now_ms += 60'000;
    }
    return last;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(snapshot)

BOOST_AUTO_TEST_CASE(members_become_node_views_of_the_requested_layer_only) {
    auto cfg = enabled_config();
    auto busy = front_end("fe-1", 900.0, "zone-a", 0.9, 10'000);
    busy.load.bytes_served_per_second = 4096;
    auto gw = front_end("gw-1", 50.0, "zone-a", 0.1, 10'000);
    gw.roles = role_set{role::gateway};
    auto draining = front_end("fe-2", 10.0, "zone-b", 0.1, 10'000);
    draining.drain = drain_state::draining;
    auto old = front_end("fe-3", 10.0, "zone-b", 0.1, 1'000);

    const auto s = layer_capacity_snapshot({busy, gw, draining, old}, role_set{role::front_end},
                                           40'000, stale_ms, cfg);
    BOOST_REQUIRE_EQUAL(s._nodes.size(), 3U);
    const auto& v = s._nodes[0];
    BOOST_TEST(v.node_id() == "fe-1");
    BOOST_TEST(v._report._read_qps == 900.0);
    BOOST_TEST(v._report._read_bytes_per_sec == 4096.0);
    BOOST_TEST(v._report._overloaded);  // cpu 0.9 >= 0.85
    BOOST_TEST(!v._stale);
    BOOST_TEST((v._placement_group == std::optional<std::string>{"zone-a"}));
    BOOST_TEST(s._nodes[1]._draining);
    BOOST_TEST(s._nodes[2]._stale);  // 39 s since its report, window 30 s
    // Draining members are not counted as part of the layer's size.
    BOOST_TEST(s.cluster_size() == 2U);
    BOOST_TEST(s.fresh_node_count() == 1U);
    const auto* zone_b = s.find_group("zone-b");
    BOOST_REQUIRE(zone_b != nullptr);
    BOOST_TEST(zone_b->_known == 2U);
    BOOST_TEST(zone_b->_live == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(policy)

BOOST_AUTO_TEST_CASE(a_disabled_policy_always_holds) {
    layer_capacity_config cfg;  // enabled = false
    layer_capacity_policy<> p(cfg);
    std::int64_t now = 0;
    const auto d = run(p, {front_end("fe-1", 1e6), front_end("fe-2", 1e6)}, now, 30, cfg);
    BOOST_TEST(d.is_hold());
}

BOOST_AUTO_TEST_CASE(validation_reports_every_error) {
    layer_capacity_config cfg = enabled_config();
    cfg.requests_per_member = {._high = 100.0, ._low = 200.0};  // inverted
    cfg.overloaded = {._high = 1.5, ._low = 0.0};               // not a fraction
    cfg.overload_cpu = 0.0;
    cfg.sustained_for = 0ms;
    cfg.sustained_for_scale_in = -1ms;
    cfg.scale_out_step = 0;
    cfg.min_members = 0;
    const layer_capacity_policy<> p(cfg);
    BOOST_TEST(!p.validate());
    BOOST_TEST(p.get_validation_errors().size() == 7U);

    layer_capacity_config tight = enabled_config();
    tight.requests_per_member = {._high = 1000.0, ._low = 900.0};  // gap too small
    BOOST_TEST(!layer_capacity_policy<>(tight).validate());

    BOOST_TEST(layer_capacity_policy<>(enabled_config()).validate());
    BOOST_TEST(layer_capacity_policy<>(layer_capacity_config{}).validate());
}

BOOST_AUTO_TEST_CASE(a_short_spike_adds_nobody_and_a_plateau_adds_one_member) {
    const auto cfg = enabled_config();
    layer_capacity_policy<> p(cfg);
    std::int64_t now = 0;
    const std::vector<layer_member> hot{front_end("fe-1", 1500.0), front_end("fe-2", 1500.0)};
    const std::vector<layer_member> calm{front_end("fe-1", 500.0), front_end("fe-2", 500.0)};

    // One minute hot, then calm: the crossing resets.
    BOOST_TEST(run(p, hot, now, 1, cfg).is_hold());
    BOOST_TEST(run(p, calm, now, 1, cfg).is_hold());
    BOOST_TEST(run(p, hot, now, 2, cfg).is_hold());

    // Hot for the full two minutes: one member more.
    const auto d = run(p, hot, now, 1, cfg);
    BOOST_REQUIRE(d.is_scale_out());
    BOOST_TEST(d.count() == 1U);
    BOOST_TEST((d.reason() == capacity_reason::load));
    BOOST_REQUIRE(!d.evidence()._signals.empty());
    BOOST_TEST(d.evidence()._signals.front()._name == "requests_per_member");
    BOOST_TEST(d.evidence()._signals.front()._value == 1500.0);

    // Inside the cooldown, and with the crossing consumed, nothing more.
    now += 60'000;
    BOOST_TEST(run(p, hot, now, 4, cfg).is_hold());
}

BOOST_AUTO_TEST_CASE(overloaded_members_add_capacity_even_at_modest_request_rates) {
    const auto cfg = enabled_config();
    layer_capacity_policy<> p(cfg);
    std::int64_t now = 0;
    const std::vector<layer_member> members{front_end("fe-1", 100.0, "zone-a", 0.95),
                                            front_end("fe-2", 100.0, "zone-a", 0.95),
                                            front_end("fe-3", 100.0, "zone-b", 0.10)};
    const auto d = run(p, members, now, 5, cfg);
    BOOST_REQUIRE(d.is_scale_out());
    BOOST_TEST((d.reason() == capacity_reason::overload));
}

BOOST_AUTO_TEST_CASE(no_scale_out_past_the_snapshot_ceiling) {
    const auto cfg = enabled_config();
    layer_capacity_policy<> p(cfg);
    std::vector<layer_member> members{front_end("fe-1", 5000.0), front_end("fe-2", 5000.0)};
    for (std::int64_t now = 0; now < 10 * 60'000; now += 60'000) {
        for (auto& m : members) {
            m.reported_at_ms = now;
        }
        auto s = layer_capacity_snapshot(members, role_set{role::front_end}, now, stale_ms, cfg);
        s._max_cluster_size = 2;
        BOOST_TEST(p.evaluate(s).is_hold());
    }
}

BOOST_AUTO_TEST_CASE(a_quiet_layer_sheds_its_least_loaded_member_from_its_largest_group) {
    const auto cfg = enabled_config();
    layer_capacity_policy<> p(cfg);
    std::int64_t now = 0;
    const std::vector<layer_member> members{
        front_end("fe-1", 100.0, "zone-a"), front_end("fe-2", 20.0, "zone-b"),
        front_end("fe-3", 80.0, "zone-a"), front_end("fe-4", 90.0, "zone-a")};
    // Not before ten quiet minutes.
    BOOST_TEST(run(p, members, now, 10, cfg).is_hold());
    const auto d = run(p, members, now, 1, cfg);
    BOOST_REQUIRE(d.is_scale_in());
    // fe-2 is the quietest, but zone-b has only one member: the layer stays
    // spread, so the quietest member of zone-a goes.
    BOOST_TEST((d.node() == std::optional<std::string>{"fe-3"}));
    BOOST_TEST((d.group() == std::optional<std::string>{"zone-a"}));
}

BOOST_AUTO_TEST_CASE(scale_in_stops_at_the_floor_and_while_a_member_drains) {
    const auto cfg = enabled_config();  // min_members = 2
    {
        layer_capacity_policy<> p(cfg);
        std::int64_t now = 0;
        BOOST_TEST(
            run(p, {front_end("fe-1", 1.0), front_end("fe-2", 1.0)}, now, 30, cfg).is_hold());
    }
    {
        layer_capacity_policy<> p(cfg);
        std::int64_t now = 0;
        auto draining = front_end("fe-3", 1.0);
        draining.drain = drain_state::draining;
        BOOST_TEST(
            run(p,
                {front_end("fe-1", 1.0), front_end("fe-2", 1.0), front_end("fe-4", 1.0), draining},
                now, 30, cfg)
                .is_hold());
    }
}

BOOST_AUTO_TEST_CASE(scale_in_never_pushes_the_rest_over_the_high_mark) {
    auto cfg = enabled_config();
    cfg.requests_per_member = {._high = 700.0, ._low = 420.0};
    {
        // Three members at 400: two would carry 600 each, under 700.
        layer_capacity_policy<> p(cfg);
        std::int64_t now = 0;
        BOOST_TEST(run(p, {front_end("a", 400.0), front_end("b", 400.0), front_end("c", 400.0)},
                       now, 12, cfg)
                       .is_scale_in());
    }
    {
        // Two fresh members at 400 and a third that stopped reporting. The
        // floor of two counts all three, but the load is carried by the two
        // that report, and one of them alone would carry 800.
        layer_capacity_policy<> p(cfg);
        std::vector<layer_member> members{front_end("a", 400.0), front_end("b", 400.0),
                                          front_end("c", 0.0)};
        for (std::int64_t now = 0; now < 20 * 60'000; now += 60'000) {
            members[0].reported_at_ms = now;
            members[1].reported_at_ms = now;
            BOOST_TEST(p.evaluate(layer_capacity_snapshot(members, role_set{role::front_end}, now,
                                                          stale_ms, cfg))
                           .is_hold());
        }
    }
}

BOOST_AUTO_TEST_CASE(stale_reports_are_not_a_reason_to_act) {
    const auto cfg = enabled_config();
    layer_capacity_policy<> p(cfg);
    // Every member last reported at 0; evaluated from minute 1 on, all stale.
    const std::vector<layer_member> members{front_end("fe-1", 9000.0), front_end("fe-2", 9000.0)};
    for (std::int64_t now = 60'000; now < 20 * 60'000; now += 60'000) {
        BOOST_TEST(p.evaluate(layer_capacity_snapshot(members, role_set{role::front_end}, now,
                                                      stale_ms, cfg))
                       .is_hold());
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(drain_hooks)

using membership_sm = kythira::layers::layer_membership_state_machine<std::uint64_t>;

BOOST_AUTO_TEST_CASE(a_member_is_drained_through_the_group_and_returned_on_cancel) {
    membership_sm sm;
    std::uint64_t index = 0;
    kythira::layers::replicated_layer_membership group(
        [&](std::vector<std::byte> b) -> std::optional<std::vector<std::byte>> {
            return sm.apply(b, ++index);
        },
        [&] { return sm.members(); });
    std::int64_t now = 10'000;
    BOOST_REQUIRE(group.announce(front_end("fe-1", 0.0, "zone-a", 0.1, now)));
    BOOST_REQUIRE(group.announce(front_end("fe-2", 0.0, "zone-a", 0.1, now)));

    auto hooks = kythira::layers::layer_drain_hooks(group, [&] { return now; }, stale_ms);
    BOOST_TEST(hooks.holds_work("fe-1"));  // serving

    hooks.begin("fe-1");
    BOOST_TEST((sm.members()[0].drain == drain_state::draining));
    BOOST_TEST(hooks.holds_work("fe-1"));  // still has streams open

    // The member closes its last stream and says so.
    BOOST_REQUIRE(group.set_drain("fe-1", drain_state::drained));
    BOOST_TEST(!hooks.holds_work("fe-1"));

    // A member that stops reporting holds nothing: it is gone or dead.
    now += stale_ms + 1;
    BOOST_TEST(!hooks.holds_work("fe-2"));
    // A member the group never heard of holds nothing.
    BOOST_TEST(!hooks.holds_work("fe-9"));

    hooks.cancel("fe-1");
    BOOST_TEST((sm.members()[0].drain == drain_state::serving));
    // Cancelling twice is harmless: a controller that took over may repeat it.
    hooks.cancel("fe-1");
    BOOST_TEST((sm.members()[0].drain == drain_state::serving));
}

BOOST_AUTO_TEST_SUITE_END()
