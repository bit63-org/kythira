// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// The Redis capacity loop over a stateless layer
/// (.kiro/specs/redis-general-data-types/ task 18, Requirement 20.3): only the
/// membership group's leader acts, a sustained load adds a member that is
/// admitted once it joins, and a quiet layer drains its least loaded member
/// through the group before the quorum manager decommissions it. A scripted
/// quorum manager, a manual clock and a manual executor make every step
/// deterministic.

#define BOOST_TEST_MODULE redis_layer_capacity_unit_test
#include <boost/test/unit_test.hpp>

#include "redis_layer_capacity_impl.hpp"

#include <mock_capacity_quorum_manager.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using kythira::layers::drain_state;
using kythira::layers::layer_member;
using kythira::layers::role;
using kythira::layers::role_set;
using kythira::testing::manual_clock;
using kythira::testing::manual_executor;

namespace {

using manager_type = kythira::testing::mock_capacity_quorum_manager<>;
using loop_type = kythira::redis_node::capacity_loop<manager_type>;

/// A replica of the group that answers at once, and leads when told to.
class fake_group final : public kythira::redis_node::membership_group {
public:
    void start() override {}
    void stop() override {}
    void tick() override {}
    auto propose(std::vector<std::byte> command) -> std::optional<std::vector<std::byte>> override {
        if (!lead) {
            return std::nullopt;
        }
        return _sm.apply(command, ++_index);
    }
    auto read() -> std::vector<layer_member> override { return _sm.members(); }
    auto leading() -> bool override { return lead; }
    auto term() -> std::uint64_t override { return 1; }

    /// What a member's own round would commit: its announcement and load.
    void report(const std::string& id, double rps, std::int64_t at_ms) {
        const bool was = lead;
        lead = true;
        kythira::layers::replicated_layer_membership m(
            [this](std::vector<std::byte> c) { return propose(std::move(c)); },
            [this] { return read(); });
        const auto members = read();
        const bool known =
            std::any_of(members.begin(), members.end(), [&](const auto& x) { return x.id == id; });
        if (!known) {
            layer_member self;
            self.id = id;
            self.roles = role_set{role::front_end};
            self.address = "fe-" + id + ":6379";
            self.announced_at_ms = at_ms;
            BOOST_REQUIRE(m.announce(self));
        }
        kythira::layers::layer_load load;
        load.requests_per_second = rps;
        load.cpu = 0.1;
        BOOST_REQUIRE(m.report_load(id, load, at_ms));
        lead = was;
    }
    void set_drain(const std::string& id, drain_state s) {
        const bool was = lead;
        lead = true;
        kythira::layers::replicated_layer_membership m(
            [this](std::vector<std::byte> c) { return propose(std::move(c)); },
            [this] { return read(); });
        BOOST_REQUIRE(m.set_drain(id, s));
        lead = was;
    }
    [[nodiscard]] auto drain_of(const std::string& id) -> drain_state {
        for (const auto& m : read()) {
            if (m.id == id) {
                return m.drain;
            }
        }
        return drain_state::drained;
    }

    bool lead = true;

private:
    kythira::layers::layer_membership_state_machine<std::uint64_t> _sm;
    std::uint64_t _index = 0;
};

auto settings() -> kythira::redis_node::capacity_options {
    kythira::redis_node::capacity_options c;
    c._layer = "front_end";
    c._dry_run = false;
    c._min_members = 2;
    c._max_members = 4;
    c._requests_high = 1000.0;
    c._requests_low = 300.0;
    c._overload_cpu = 0.0;  // requests alone drive these cases
    c._sustained = 2min;
    c._scale_in_sustained = 4min;
    c._cooldown = 1min;
    c._drain_deadline = 10min;
    c._interval = 10s;
    return c;
}

auto topology() -> kythira::desired_topology<std::string> {
    return {.groups = {{.group_id = "default", .target_count = 2}}};
}

constexpr auto k_stale = 10s;

struct harness {
    manual_clock clock;
    manual_executor executor;
    fake_group group;
    manager_type manager{clock, topology(), 1000};
    std::unique_ptr<loop_type> loop;

    harness() {
        // Real time, so the controller's own clock and the members' report
        // times agree.
        clock.advance(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()));
        manager.add_existing(1, "default");
        manager.add_existing(2, "default");
        loop = std::make_unique<loop_type>(manager, settings(), role_set{role::front_end}, k_stale,
                                           group, kythira::log_level::error, clock.fn(),
                                           executor.fn());
    }

    [[nodiscard]] auto now_ms() const -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch())
            .count();
    }

    /// `rounds` rounds 10 s apart, every member in `rps` reporting first.
    void run(const std::vector<std::pair<std::string, double>>& rps, int rounds) {
        for (int i = 0; i < rounds; ++i) {
            for (const auto& [id, r] : rps) {
                group.report(id, r, now_ms());
            }
            loop->round();
            executor.run_all();
            manager.settle();
            executor.run_all();
            clock.advance(10s);
        }
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_sustained_load_adds_one_member_admitted_once_it_joins) {
    harness h;
    h.run({{"1", 1500.0}, {"2", 1500.0}}, 6);  // one minute: not yet sustained
    BOOST_TEST(h.manager.call_count("provision") == 0U);
    h.run({{"1", 1500.0}, {"2", 1500.0}}, 12);
    BOOST_REQUIRE_EQUAL(h.manager.call_count("provision"), 1U);
    // The machine starts and its front end announces itself to the group.
    h.run({{"1", 900.0}, {"2", 900.0}, {"1000", 900.0}}, 3);
    BOOST_TEST(h.loop->controller().counter("admission{outcome=completed}") == 1U);
    BOOST_TEST(h.manager.call_count("provision") == 1U);
}

BOOST_AUTO_TEST_CASE(a_quiet_layer_drains_a_member_before_decommissioning_it) {
    harness h;
    h.manager.add_existing(3, "default");
    h.run({{"1", 100.0}, {"2", 120.0}, {"3", 150.0}}, 30);
    BOOST_TEST(h.manager.call_count("decommission") == 0U);
    // The least loaded member is draining, through the group.
    BOOST_REQUIRE((h.group.drain_of("1") == drain_state::draining));
    BOOST_TEST((h.group.drain_of("2") == drain_state::serving));
    // While it still serves clients, the machine stays.
    h.run({{"1", 10.0}, {"2", 120.0}, {"3", 150.0}}, 6);
    BOOST_TEST(h.manager.call_count("decommission") == 0U);
    // Its last client gone, it says so; then the machine goes.
    h.group.set_drain("1", drain_state::drained);
    h.run({{"1", 0.0}, {"2", 120.0}, {"3", 150.0}}, 6);
    BOOST_REQUIRE_EQUAL(h.manager.call_count("decommission"), 1U);
    BOOST_TEST(h.manager.machine(1)->_decommissioned);
    BOOST_TEST(!h.manager.machine(2)->_decommissioned);
}

BOOST_AUTO_TEST_CASE(only_the_leader_acts_and_an_operator_drain_is_not_counted) {
    harness h;
    h.group.lead = false;
    h.run({{"1", 1500.0}, {"2", 1500.0}}, 24);
    BOOST_TEST(h.manager.call_count("provision") == 0U);

    // Leading, with one member drained by an operator: the other's load is
    // the layer's, and one member carrying it is no reason to remove one.
    harness g;
    g.manager.add_existing(3, "default");
    g.group.report("3", 100.0, g.now_ms());
    g.group.set_drain("3", drain_state::drained);
    g.run({{"1", 100.0}, {"2", 100.0}}, 30);
    BOOST_TEST(g.manager.call_count("decommission") == 0U);
    BOOST_TEST((g.group.drain_of("1") == drain_state::serving));
    BOOST_TEST((g.group.drain_of("2") == drain_state::serving));
}
