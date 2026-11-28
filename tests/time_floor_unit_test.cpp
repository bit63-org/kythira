// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The time floor and the issuing-clock checks (.kiro/specs/az-cold-start/
// Requirement 10, task 11): the floor only rises, a clock below it or more
// than five minutes ahead of its sources' median may not issue, and the
// floor is committed every ten minutes on the steady clock, only from a
// clock that may issue.

#define BOOST_TEST_MODULE time_floor_unit_test

#include <boost/test/unit_test.hpp>

#include <raft/time_floor.hpp>

#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using raft::check_issuing_clock;
using raft::clock_verdict;
using raft::time_source_sample;

namespace {

constexpr raft::unix_seconds floor_s = 1'795'000'000;

auto at(raft::unix_seconds s) -> std::chrono::system_clock::time_point {
    return std::chrono::system_clock::time_point{std::chrono::seconds{s}};
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_floor_only_rises) {
    raft::time_floor f;
    BOOST_TEST(f.value() == 0);
    BOOST_TEST(f.observe(floor_s));
    BOOST_TEST(!f.observe(floor_s - 600));
    BOOST_TEST(!f.observe(floor_s));
    BOOST_TEST(f.value() == floor_s);
    BOOST_TEST(f.observe(floor_s + 1));
    BOOST_TEST(f.value() == floor_s + 1);
}

BOOST_AUTO_TEST_CASE(concurrent_observers_keep_the_highest) {
    raft::time_floor f;
    {
        std::vector<std::jthread> threads;
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([&f, t] {
                for (raft::unix_seconds i = 0; i < 10'000; ++i) {
                    (void)f.observe((i * 4) + t);
                }
            });
        }
    }
    BOOST_TEST(f.value() == (9'999 * 4) + 3);
}

BOOST_AUTO_TEST_CASE(median_of_the_sources) {
    BOOST_TEST(!raft::median_offset({}).has_value());
    BOOST_TEST(raft::median_offset({{"a", 7ms}}).value() == 7ms);
    // Even count: the mean of the middle two.
    BOOST_TEST(raft::median_offset({{"a", 10ms}, {"b", 20ms}}).value() == 15ms);
    // One wrong source of three moves nothing.
    BOOST_TEST(raft::median_offset({{"gnss", 2ms}, {"ptp", -1ms}, {"bad", 86'400'000ms}}).value() ==
               2ms);
}

BOOST_AUTO_TEST_CASE(a_clock_below_the_floor_may_not_issue) {
    // A dead RTC battery: 1970.
    auto c = check_issuing_clock(at(0), floor_s, {});
    BOOST_TEST((c.verdict == clock_verdict::below_floor));
    BOOST_TEST(c.below_floor_by == std::chrono::seconds{floor_s});
    BOOST_TEST(!c.ok());
    // At the floor is fine: the floor is a time already passed.
    BOOST_TEST(check_issuing_clock(at(floor_s), floor_s, {}).ok());
    // Below the floor wins even when the sources agree with the clock.
    c = check_issuing_clock(at(floor_s - 1), floor_s, {{"gnss", 0ms}, {"ptp", 0ms}});
    BOOST_TEST((c.verdict == clock_verdict::below_floor));
    BOOST_TEST(c.below_floor_by == 1s);
    BOOST_TEST(c.sources == 2U);
}

BOOST_AUTO_TEST_CASE(a_clock_far_ahead_of_its_sources_may_not_issue) {
    // The sources read 6 minutes behind the local clock: it is ahead.
    auto c = check_issuing_clock(at(floor_s + 3600), floor_s, {{"gnss", -6min}, {"ptp", -6min}});
    BOOST_TEST((c.verdict == clock_verdict::ahead_of_sources));
    BOOST_TEST(c.source_offset.value() == -6min);
    // Up to five minutes ahead, or any amount behind (the floor guards that
    // side), still issues.
    BOOST_TEST(check_issuing_clock(at(floor_s + 3600), floor_s, {{"gnss", -5min}}).ok());
    BOOST_TEST(check_issuing_clock(at(floor_s + 3600), floor_s, {{"gnss", 2h}}).ok());
    // No sources: only the floor applies.
    BOOST_TEST(check_issuing_clock(at(floor_s + 86'400 * 365), floor_s, {}).ok());
}

BOOST_AUTO_TEST_CASE(verdicts_have_names) {
    BOOST_TEST(raft::to_string(clock_verdict::ok) == "ok");
    BOOST_TEST(raft::to_string(clock_verdict::below_floor) == "clock_below_time_floor");
    BOOST_TEST(raft::to_string(clock_verdict::ahead_of_sources) == "clock_ahead_of_time_sources");
}

BOOST_AUTO_TEST_CASE(the_floor_is_committed_every_interval_from_a_good_clock) {
    raft::time_floor_schedule schedule;
    const auto t0 = std::chrono::steady_clock::time_point{} + 1h;
    BOOST_TEST(schedule.due(t0));  // a new leader commits at once
    schedule.committed(t0);
    BOOST_TEST(!schedule.due(t0 + 9min));
    BOOST_TEST(schedule.due(t0 + 10min));
    schedule.reset();
    BOOST_TEST(schedule.due(t0 + 1s));

    const auto good = check_issuing_clock(at(floor_s + 600), floor_s, {});
    BOOST_TEST(raft::time_floor_schedule::next_floor(good, at(floor_s + 600), floor_s).value() ==
               floor_s + 600);
    // Never the same floor again, never a lower one.
    BOOST_TEST(!raft::time_floor_schedule::next_floor(good, at(floor_s), floor_s).has_value());
    // A clock that may not issue commits nothing, so a node with a clock in
    // the future can never drag the floor there.
    const auto ahead = check_issuing_clock(at(floor_s + 86'400), floor_s, {{"gnss", -1h}});
    BOOST_TEST(
        !raft::time_floor_schedule::next_floor(ahead, at(floor_s + 86'400), floor_s).has_value());
}
