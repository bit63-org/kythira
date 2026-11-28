// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Recovery mode (.kiro/specs/az-cold-start/ Requirement 7, task 12): entry
// on mass silence at start or BeginRecovery, the withheld actions, exit at
// 95 % reported, 30 minutes or EndRecovery, and the hand-off of the hosts
// still silent.

#define BOOST_TEST_MODULE recovery_mode_unit_test

#include <boost/test/unit_test.hpp>

#include <raft/recovery_mode.hpp>

#include <chrono>
#include <cstdint>
#include <set>
#include <vector>

using namespace std::chrono_literals;
using raft::recovery_entry;
using raft::recovery_exit;
using raft::recovery_withheld_action;

namespace {

using mode = raft::recovery_mode<std::uint64_t>;
using event = mode::event;

const auto t0 = std::chrono::steady_clock::time_point{} + 1h;

auto hosts(std::uint64_t first, std::uint64_t last) -> std::set<std::uint64_t> {
    std::set<std::uint64_t> s;
    for (auto h = first; h <= last; ++h) {
        s.insert(h);
    }
    return s;
}

constexpr recovery_withheld_action all_withheld[] = {
    recovery_withheld_action::declare_host_lost,
    recovery_withheld_action::replace_replica,
    recovery_withheld_action::mark_impaired_for_silence,
    recovery_withheld_action::stop_or_retire_instance,
    recovery_withheld_action::start_drain,
    recovery_withheld_action::open_enrollment_window,
    recovery_withheld_action::change_volume_layout,
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_cold_start_enters_and_withholds_every_silence_action) {
    std::vector<event> events;
    mode m{{}, [&events](const event& e) { events.push_back(e); }};
    m.start(t0, hosts(1, 100), {});  // every host silent
    BOOST_TEST(m.active());
    BOOST_REQUIRE(events.size() == 1U);
    BOOST_TEST((events[0].what == event::kind::entered));
    BOOST_TEST((events[0].entry == recovery_entry::mass_silence_at_start));
    for (const auto a : all_withheld) {
        BOOST_TEST(!m.allows(a), raft::to_string(a));
    }
    const auto s = m.status();
    BOOST_TEST(s.active);
    BOOST_TEST(s.in_service == 100U);
    BOOST_TEST(s.reported == 0U);
}

BOOST_AUTO_TEST_CASE(a_normal_restart_does_not_enter) {
    mode m;
    // 5 of 100 silent is at the threshold, not above it.
    m.start(t0, hosts(1, 100), hosts(1, 95));
    BOOST_TEST(!m.active());
    for (const auto a : all_withheld) {
        BOOST_TEST(m.allows(a));
    }
    mode m2;
    m2.start(t0, hosts(1, 100), hosts(1, 94));
    BOOST_TEST(m2.active());
    mode empty;
    empty.start(t0, {}, {});
    BOOST_TEST(!empty.active());
}

BOOST_AUTO_TEST_CASE(leaves_at_95_percent_reported_and_hands_off_the_rest) {
    std::vector<event> events;
    mode m{{}, [&events](const event& e) { events.push_back(e); }};
    m.start(t0, hosts(1, 100), {});
    for (std::uint64_t h = 1; h <= 94; ++h) {
        m.host_reported(t0 + 1min, h);
    }
    m.host_reported(t0 + 1min, 94);   // twice counts once
    m.host_reported(t0 + 1min, 500);  // not in service: ignored
    BOOST_TEST(m.active());
    m.host_reported(t0 + 2min, 95);
    BOOST_TEST(!m.active());
    BOOST_REQUIRE(events.size() == 2U);
    const auto& out = events[1];
    BOOST_TEST((out.what == event::kind::exited));
    BOOST_TEST((out.exit == recovery_exit::hosts_reported));
    BOOST_TEST((out.at == t0 + 2min));
    BOOST_TEST((out.still_silent == std::vector<std::uint64_t>{96, 97, 98, 99, 100}));
    BOOST_TEST((m.status().last_exit == recovery_exit::hosts_reported));
}

BOOST_AUTO_TEST_CASE(leaves_after_thirty_minutes_whatever_reported) {
    std::vector<event> events;
    mode m{{}, [&events](const event& e) { events.push_back(e); }};
    m.start(t0, hosts(1, 10), {});
    m.host_reported(t0 + 1min, 1);
    m.poll(t0 + 29min);
    BOOST_TEST(m.active());
    m.poll(t0 + 30min);
    BOOST_TEST(!m.active());
    BOOST_REQUIRE(events.size() == 2U);
    BOOST_TEST((events[1].exit == recovery_exit::timed_out));
    BOOST_TEST(events[1].still_silent.size() == 9U);
}

BOOST_AUTO_TEST_CASE(the_operator_starts_and_ends_a_drill) {
    std::vector<event> events;
    mode m{{.max_duration = 10min}, [&events](const event& e) { events.push_back(e); }};
    m.start(t0, hosts(1, 10), hosts(1, 10));
    for (std::uint64_t h = 1; h <= 10; ++h) {
        m.host_reported(t0, h);
    }
    BOOST_TEST(!m.active());
    // A drill forgets who reported and restarts the clock.
    m.begin(t0 + 1h);
    BOOST_TEST(m.active());
    BOOST_TEST((m.status().entry == recovery_entry::operator_drill));
    BOOST_TEST(m.silent_hosts().size() == 10U);
    m.begin(t0 + 1h + 1min);  // already active: no second event
    m.poll(t0 + 1h + 9min);
    BOOST_TEST(m.active());
    m.end(t0 + 1h + 9min);
    BOOST_TEST(!m.active());
    m.end(t0 + 1h + 9min);  // not active: nothing
    BOOST_REQUIRE(events.size() == 2U);
    BOOST_TEST((events[1].exit == recovery_exit::operator_ended));
}

BOOST_AUTO_TEST_CASE(a_shrinking_fleet_can_end_recovery) {
    mode m;
    m.start(t0, hosts(1, 20), {});
    for (std::uint64_t h = 1; h <= 18; ++h) {
        m.host_reported(t0, h);
    }
    BOOST_TEST(m.active());                     // 18 of 20 is 90 %
    m.set_in_service(t0 + 1min, hosts(1, 19));  // the operator retired host 20
    BOOST_TEST(m.active());                     // 18 of 19 is 94.7 %
    m.set_in_service(t0 + 2min, hosts(1, 18));  // and host 19
    BOOST_TEST(!m.active());
    BOOST_TEST((m.status().last_exit == recovery_exit::hosts_reported));
}

BOOST_AUTO_TEST_CASE(names) {
    BOOST_TEST(raft::to_string(recovery_entry::mass_silence_at_start) == "mass_silence_at_start");
    BOOST_TEST(raft::to_string(recovery_entry::operator_drill) == "operator_drill");
    BOOST_TEST(raft::to_string(recovery_exit::hosts_reported) == "hosts_reported");
    BOOST_TEST(raft::to_string(recovery_exit::timed_out) == "timed_out");
    BOOST_TEST(raft::to_string(recovery_exit::operator_ended) == "operator_ended");
    BOOST_TEST(raft::to_string(recovery_withheld_action::start_drain) == "start_drain");
}
