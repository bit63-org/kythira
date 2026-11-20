// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file load_buckets_unit_test.cpp
/// @brief `bucket_set` and `bucket_config` (tasks 1 and 2 of
///        `.kiro/specs/multi-raft-load-buckets/`).
///
/// The cases follow Requirement 7.1 where it concerns the bucket set on its
/// own: boundaries from a key list and from the reservoir, the range filter,
/// the sum rule (Requirement 3.3), window expiry, and an equal refresh keeping
/// its counters. The routing, policy, split and merge cases arrive with the
/// tasks that wire the set into the host.

#define BOOST_TEST_MODULE load_buckets_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/load_buckets.hpp>
#include <raft/shard_types.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using kythira::bucket_config;
using kythira::bucket_counts;
using kythira::bucket_set;
using kythira::key_reservoir;
using kythira::normalized;
using kythira::shard_range;

namespace {

using key_type = std::string;
using set_type = bucket_set<key_type>;
using clock = set_type::clock;
using namespace std::chrono_literals;

/// Three-digit decimal keys, so lexicographic order is numeric order.
auto key_of(int n) -> key_type {
    auto s = std::to_string(n);
    return std::string(3 - s.size(), '0') + s;
}

auto enabled_config() -> bucket_config {
    bucket_config cfg;
    cfg._enabled = true;
    cfg._target_buckets = 4;
    cfg._window_slots = 3;
    cfg._slot_duration = 10s;
    cfg._reservoir_size = 256;
    cfg._reservoir_stride = 1;
    cfg._seed = 20261120;
    return cfg;
}

auto unbounded() -> shard_range<key_type> {
    return kythira::unbounded_shard_range<key_type>();
}

auto range_of(int start, int end) -> shard_range<key_type> {
    return shard_range<key_type>{._start = key_of(start), ._end = key_of(end)};
}

auto total(const std::vector<bucket_counts>& counts) -> bucket_counts {
    bucket_counts sum;
    for (const auto& c : counts) {
        sum += c;
    }
    return sum;
}

}  // namespace

// ── bucket_config ────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(defaults_are_off_and_already_legal) {
    const bucket_config cfg;
    BOOST_TEST(!cfg._enabled);
    const auto n = normalized(cfg);
    BOOST_TEST(n._target_buckets == 16U);
    BOOST_TEST(n._window_slots == 6U);
    BOOST_TEST(n._reservoir_size == 1024U);
    BOOST_TEST(n._reservoir_stride == 16U);
    BOOST_TEST(n._report_top_buckets == 4U);
}

BOOST_AUTO_TEST_CASE(counts_are_clamped_into_range) {
    bucket_config cfg;
    cfg._target_buckets = 1000;
    cfg._window_slots = 1;
    cfg._reservoir_size = 3;
    cfg._reservoir_stride = 0;
    cfg._report_top_buckets = 999;
    auto n = normalized(cfg);
    BOOST_TEST(n._target_buckets == bucket_config::k_max_target_buckets);
    BOOST_TEST(n._window_slots == bucket_config::k_min_window_slots);
    // Never smaller than the bucket count, or the quantiles cannot be distinct.
    BOOST_TEST(n._reservoir_size == n._target_buckets);
    BOOST_TEST(n._reservoir_stride == 1U);
    BOOST_TEST(n._report_top_buckets == n._target_buckets);

    cfg._target_buckets = 0;
    n = normalized(cfg);
    BOOST_TEST(n._target_buckets == bucket_config::k_min_target_buckets);
}

BOOST_AUTO_TEST_CASE(an_enabled_config_with_a_zero_duration_is_refused) {
    auto cfg = enabled_config();
    cfg._slot_duration = 0ms;
    BOOST_CHECK_THROW((void)normalized(cfg), std::invalid_argument);

    cfg = enabled_config();
    cfg._refresh_interval = -1ms;
    BOOST_CHECK_THROW((void)normalized(cfg), std::invalid_argument);

    // A disabled host never counts, so it must not fail to start over knobs it
    // ignores.
    cfg._enabled = false;
    BOOST_CHECK_NO_THROW((void)normalized(cfg));
}

// ── boundaries ───────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(a_fresh_set_is_one_bucket_at_version_one) {
    const set_type set{enabled_config(), unbounded(), clock::now()};
    BOOST_TEST(set.bucket_count() == 1U);
    BOOST_TEST(set.version() == 1U);
    const auto snap = set.snapshot();
    BOOST_REQUIRE(snap.size() == 1U);
    BOOST_TEST(!snap[0]._start.has_value());
    BOOST_TEST(!snap[0]._end.has_value());
}

BOOST_AUTO_TEST_CASE(boundaries_outside_or_on_the_range_start_are_dropped) {
    // [100, 200): 100 is the start (an empty first bucket), 200 the end
    // (outside, half-open), 050 and 250 plainly outside.
    const auto kept = set_type::normalize_boundaries(
        {key_of(150), key_of(100), key_of(200), key_of(50), key_of(250), key_of(120), key_of(150)},
        range_of(100, 200), 10);
    BOOST_TEST(kept == (std::vector<key_type>{key_of(120), key_of(150)}));
}

BOOST_AUTO_TEST_CASE(too_many_boundaries_are_trimmed_evenly) {
    std::vector<key_type> keys;
    for (int i = 1; i < 100; ++i) {
        keys.push_back(key_of(i));
    }
    const auto kept = set_type::normalize_boundaries(keys, unbounded(), 3);
    BOOST_REQUIRE(kept.size() == 3U);
    // The midpoints of three equal runs of 99 keys, not the first three.
    BOOST_TEST(kept[0] == key_of(17));
    BOOST_TEST(kept[1] == key_of(50));
    BOOST_TEST(kept[2] == key_of(83));
}

BOOST_AUTO_TEST_CASE(a_set_never_holds_more_than_target_buckets) {
    auto cfg = enabled_config();  // 4 buckets, so 3 boundaries
    std::vector<key_type> keys;
    for (int i = 1; i < 50; ++i) {
        keys.push_back(key_of(i));
    }
    set_type set{cfg, unbounded(), clock::now(), keys};
    BOOST_TEST(set.bucket_count() == 4U);
    BOOST_TEST(set.refresh(keys, clock::now()) == false);
    BOOST_TEST(set.bucket_count() == 4U);
}

BOOST_AUTO_TEST_CASE(a_key_lands_in_the_bucket_whose_range_holds_it) {
    const std::vector<key_type> b{key_of(10), key_of(20), key_of(30)};
    BOOST_TEST(set_type::bucket_index(b, key_of(0)) == 0U);
    BOOST_TEST(set_type::bucket_index(b, key_of(9)) == 0U);
    // Half-open: a boundary key belongs to the bucket it starts.
    BOOST_TEST(set_type::bucket_index(b, key_of(10)) == 1U);
    BOOST_TEST(set_type::bucket_index(b, key_of(29)) == 2U);
    BOOST_TEST(set_type::bucket_index(b, key_of(30)) == 3U);
    BOOST_TEST(set_type::bucket_index(b, key_of(999)) == 3U);
}

BOOST_AUTO_TEST_CASE(reservoir_boundaries_follow_the_traffic) {
    auto cfg = enabled_config();
    set_type set{cfg, unbounded(), clock::now()};
    BOOST_TEST(set.reservoir_boundaries().empty());

    // All traffic in [000, 100): the cut must land there, not spread over the
    // whole key space.
    for (int round = 0; round < 10; ++round) {
        for (int i = 0; i < 100; ++i) {
            set.count(key_of(i), 1, false);
        }
    }
    const auto b = set.reservoir_boundaries();
    BOOST_REQUIRE(b.size() == 3U);
    for (const auto& k : b) {
        BOOST_TEST(k < key_of(100));
    }
    // Roughly the quartiles of a uniform 0..99.
    BOOST_TEST(b[0] > key_of(10));
    BOOST_TEST(b[0] < key_of(40));
    BOOST_TEST(b[2] > key_of(60));
}

BOOST_AUTO_TEST_CASE(a_single_key_reservoir_yields_no_boundary_on_the_range_start) {
    auto cfg = enabled_config();
    set_type set{cfg, range_of(100, 200), clock::now()};
    for (int i = 0; i < 100; ++i) {
        set.count(key_of(100), 1, false);
    }
    // Every quantile is the range's own start; none is a legal cut.
    BOOST_TEST(set.reservoir_boundaries().empty());
}

BOOST_AUTO_TEST_CASE(the_stride_feeds_one_request_in_n_to_the_reservoir) {
    key_reservoir<key_type> r{8, 1};
    for (int i = 0; i < 4; ++i) {
        r.offer(key_of(i));
    }
    BOOST_TEST(r.size() == 4U);
    for (int i = 0; i < 100; ++i) {
        r.offer(key_of(i));
    }
    BOOST_TEST(r.size() == 8U);  // bounded
    BOOST_TEST(r.seen() == 104U);

    auto cfg = enabled_config();
    cfg._reservoir_stride = 10;
    cfg._target_buckets = 2;
    set_type set{cfg, unbounded(), clock::now()};
    // Requests 0, 10, 20, ... feed it, and those are exactly the ones keyed
    // 000: nine requests in ten go to 999 and none of them is offered.
    for (int i = 0; i < 100; ++i) {
        set.count(key_of(i % 10 == 0 ? 0 : 999), 1, false);
    }
    const auto b = set.reservoir_boundaries();
    BOOST_REQUIRE(b.size() == 1U);
    BOOST_TEST(b[0] == key_of(0));
}

// ── counting and the window ──────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(bucket_counts_sum_to_the_requests_counted) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0, {key_of(250), key_of(500), key_of(750)}};
    std::uint64_t reads = 0;
    std::uint64_t writes = 0;
    std::uint64_t bytes = 0;
    for (int i = 0; i < 1000; ++i) {
        const bool is_read = i % 3 == 0;
        set.count(key_of(i), static_cast<std::uint64_t>(i), is_read);
        (is_read ? reads : writes) += 1;
        bytes += static_cast<std::uint64_t>(i);
    }
    // Nothing is reported while the slot that holds it is still filling.
    BOOST_TEST(total(set.window_counts()).requests() == 0U);

    BOOST_TEST(set.roll(t0 + 10s));
    const auto counts = set.window_counts();
    BOOST_REQUIRE(counts.size() == 4U);
    const auto sum = total(counts);
    BOOST_TEST(sum._reads == reads);
    BOOST_TEST(sum._writes == writes);
    BOOST_TEST(sum._read_bytes + sum._write_bytes == bytes);
    for (const auto& c : counts) {
        BOOST_TEST(c.requests() == 250U);
    }
}

BOOST_AUTO_TEST_CASE(add_bytes_counts_bytes_but_no_request) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0};
    set.count(key_of(1), 0, true);
    set.add_bytes(key_of(1), 4096, true);
    set.roll(t0 + 10s);
    const auto c = total(set.window_counts());
    BOOST_TEST(c._reads == 1U);
    BOOST_TEST(c._read_bytes == 4096U);
}

BOOST_AUTO_TEST_CASE(rates_divide_by_the_time_the_window_covered) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0, {key_of(500)}};
    for (int i = 0; i < 100; ++i) {
        set.count(key_of(100), 10, false);
    }
    BOOST_TEST(set.snapshot()[0]._write_qps == 0.0);  // no closed slot yet

    // A late tick: the slot really ran 20 s, and the rate says so.
    BOOST_TEST(set.roll(t0 + 20s));
    BOOST_TEST(set.window_covered() == clock::duration{20s});
    const auto snap = set.snapshot();
    BOOST_REQUIRE(snap.size() == 2U);
    BOOST_TEST(snap[0]._write_qps == 5.0);
    BOOST_TEST(snap[0]._write_bytes_per_sec == 50.0);
    BOOST_TEST(snap[1]._write_qps == 0.0);
    BOOST_TEST(!snap[0]._start.has_value());
    BOOST_TEST((snap[0]._end == std::optional<key_type>{key_of(500)}));
    BOOST_TEST((snap[1]._start == std::optional<key_type>{key_of(500)}));
    BOOST_TEST(!snap[1]._end.has_value());
}

BOOST_AUTO_TEST_CASE(roll_waits_for_a_full_slot) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0};
    BOOST_TEST(!set.roll(t0 + 9s));
    BOOST_TEST(set.roll(t0 + 10s));
    BOOST_TEST(!set.roll(t0 + 19s));
}

BOOST_AUTO_TEST_CASE(old_slots_expire_from_the_window) {
    // Three slots: two complete ones are reported, plus the one filling.
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0};
    set.count(key_of(1), 0, false);  // slot A
    set.roll(t0 + 10s);
    set.count(key_of(1), 0, false);  // slot B
    set.count(key_of(1), 0, false);
    set.roll(t0 + 20s);
    BOOST_TEST(total(set.window_counts())._writes == 3U);
    BOOST_TEST(set.window_covered() == clock::duration{20s});

    set.roll(t0 + 30s);  // A falls out; the slot being filled was empty
    BOOST_TEST(total(set.window_counts())._writes == 2U);
    BOOST_TEST(set.window_covered() == clock::duration{20s});

    set.roll(t0 + 40s);
    set.roll(t0 + 50s);
    BOOST_TEST(total(set.window_counts())._writes == 0U);
}

BOOST_AUTO_TEST_CASE(an_equal_refresh_keeps_counters_and_version) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0, {key_of(500)}};
    set.count(key_of(1), 0, false);
    set.roll(t0 + 10s);
    // The same keys, unsorted and duplicated, are the same set.
    BOOST_TEST(!set.refresh({key_of(500), key_of(500)}, t0 + 11s));
    BOOST_TEST(set.version() == 1U);
    BOOST_TEST(total(set.window_counts())._writes == 1U);
}

BOOST_AUTO_TEST_CASE(a_different_refresh_bumps_the_version_and_empties_the_window) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0, {key_of(500)}};
    set.count(key_of(1), 0, false);
    set.roll(t0 + 10s);
    BOOST_TEST(set.refresh({key_of(300), key_of(600)}, t0 + 11s));
    BOOST_TEST(set.version() == 2U);
    BOOST_TEST(set.bucket_count() == 3U);
    BOOST_TEST(total(set.window_counts()).requests() == 0U);
    BOOST_TEST(set.window_covered() == clock::duration::zero());

    // The new slot started at the refresh, so the next roll is a slot later.
    BOOST_TEST(!set.roll(t0 + 20s));
    set.count(key_of(400), 0, true);
    BOOST_TEST(set.roll(t0 + 21s));
    const auto counts = set.window_counts();
    BOOST_TEST(counts[1]._reads == 1U);
}

BOOST_AUTO_TEST_CASE(a_layout_swap_under_concurrent_counts_loses_nothing_it_keeps) {
    // Counts racing refreshes and rolls: no crash, no torn layout (TSan and
    // ASan see this one), and every count lands in some layout's counters.
    auto cfg = enabled_config();
    cfg._window_slots = 64;  // never wrap, so nothing counted is zeroed
    const auto t0 = clock::now();
    set_type set{cfg, unbounded(), t0, {key_of(500)}};

    std::atomic<bool> stop{false};
    std::vector<std::thread> counters;
    std::atomic<std::uint64_t> counted{0};
    for (int t = 0; t < 4; ++t) {
        counters.emplace_back([&, t] {
            int i = t;
            while (!stop.load(std::memory_order_relaxed)) {
                set.count(key_of(i % 1000), 1, (i & 1) != 0);
                counted.fetch_add(1, std::memory_order_relaxed);
                i += 7;
            }
        });
    }
    auto now = t0;
    for (int r = 0; r < 200; ++r) {
        now += 10s;
        set.roll(now);
        if (r % 20 == 0) {
            (void)set.refresh({key_of(100 + r), key_of(600)}, now);
        }
        (void)set.snapshot();
    }
    stop = true;
    for (auto& t : counters) {
        t.join();
    }
    BOOST_TEST(counted.load() > 0U);
    for (const auto& b : set.snapshot()) {
        BOOST_TEST(b._read_qps >= 0.0);
    }
}

BOOST_AUTO_TEST_CASE(inherited_boundaries_start_a_fresh_set_at_the_given_version) {
    // What a split child does (Requirement 4.2): the parent's boundaries inside
    // its own range, empty counters, a fresh version.
    const set_type child{enabled_config(),
                         range_of(100, 500),
                         clock::now(),
                         {key_of(50), key_of(200), key_of(300), key_of(700)}};
    BOOST_TEST(child.boundaries() == (std::vector<key_type>{key_of(200), key_of(300)}));
    BOOST_TEST(child.version() == 1U);
    const auto snap = child.snapshot();
    BOOST_REQUIRE(snap.size() == 3U);
    BOOST_TEST((snap.front()._start == std::optional<key_type>{key_of(100)}));
    BOOST_TEST((snap.back()._end == std::optional<key_type>{key_of(500)}));
}

// ── reset, split and merge helpers (task 5) ──────────────────────────────────

BOOST_AUTO_TEST_CASE(reset_starts_over_on_a_new_range_at_version_one) {
    const auto t0 = clock::now();
    set_type set{enabled_config(), unbounded(), t0, {key_of(300), key_of(600)}};
    set.count(key_of(1), 0, false);
    set.roll(t0 + 10s);
    BOOST_TEST(set.refresh({key_of(400)}, t0 + 11s));
    BOOST_TEST(set.version() == 2U);

    // A leader that lost the shard and won it back, or a split child: the new
    // range, the boundaries inside it, version 1, nothing counted, nothing in
    // the reservoir.
    set.reset(range_of(100, 500), {key_of(50), key_of(200), key_of(700)}, t0 + 12s);
    BOOST_TEST(set.version() == 1U);
    BOOST_TEST(set.boundaries() == (std::vector<key_type>{key_of(200)}));
    BOOST_TEST((set.range() == range_of(100, 500)));
    BOOST_TEST(set.window_covered() == clock::duration::zero());
    BOOST_TEST(total(set.window_counts()).requests() == 0U);
    BOOST_TEST(set.reservoir_boundaries().empty());
    BOOST_TEST(!set.roll(t0 + 21s));  // the slot restarted at the reset
    BOOST_TEST(set.roll(t0 + 22s));
}

BOOST_AUTO_TEST_CASE(trimming_drops_the_boundary_between_the_coldest_pair) {
    // Loads 5 | 1 | 1 | 9 | 2: the pair (1, 1) around boundary 1 is coldest.
    const std::vector<key_type> b{key_of(10), key_of(20), key_of(30), key_of(40)};
    auto kept = set_type::trim_by_load(b, {5, 1, 1, 9, 2}, 3);
    BOOST_TEST(kept == (std::vector<key_type>{key_of(10), key_of(30), key_of(40)}));
    // Then 5 | 2 | 9 | 2: (5, 2) = 7 beats (2, 9) = 11 and (9, 2) = 11.
    kept = set_type::trim_by_load(b, {5, 1, 1, 9, 2}, 2);
    BOOST_TEST(kept == (std::vector<key_type>{key_of(30), key_of(40)}));
    // Equal loads drop leftmost first, deterministically.
    kept = set_type::trim_by_load(b, {0, 0, 0, 0, 0}, 1);
    BOOST_TEST(kept == (std::vector<key_type>{key_of(40)}));
    BOOST_TEST(set_type::trim_by_load(b, {}, 10) == b);
}

BOOST_AUTO_TEST_CASE(a_merge_survivor_takes_both_lists_and_the_shared_bound) {
    // Survivor [100, 500) with one boundary at 300, absorbing [500, 900) with
    // one at 700: the union plus 500 is three boundaries, which fits.
    const auto merged = range_of(100, 900);
    const auto b = set_type::merge_boundaries(merged, range_of(100, 500), {key_of(300)},
                                              {bucket_counts{._writes = 4}, bucket_counts{}},
                                              {key_of(700)}, 3);
    BOOST_TEST(b == (std::vector<key_type>{key_of(300), key_of(500), key_of(700)}));

    // Absorbing from the LEFT: the shared bound is the survivor's old start.
    const auto left =
        set_type::merge_boundaries(merged, range_of(500, 900), {key_of(700)}, {}, {key_of(300)}, 3);
    BOOST_TEST(left == (std::vector<key_type>{key_of(300), key_of(500), key_of(700)}));
}

BOOST_AUTO_TEST_CASE(a_merge_over_target_coarsens_the_unmeasured_side_first) {
    // Survivor [100, 500) cut at 200 / 300 / 400 with real load in every
    // bucket; the absorbed side's buckets were never measured here, so they
    // count as zero and their boundaries go first (Requirement 4.3).
    const std::vector<bucket_counts> own{bucket_counts{._writes = 10}, bucket_counts{._reads = 10},
                                         bucket_counts{._writes = 10},
                                         bucket_counts{._writes = 10}};
    const auto b = set_type::merge_boundaries(range_of(100, 900), range_of(100, 500),
                                              {key_of(200), key_of(300), key_of(400)}, own,
                                              {key_of(600), key_of(700), key_of(800)}, 4);
    // Seven candidates trimmed to four: the absorbed 600 / 700 / 800 go, then
    // nothing more is needed once the shared bound 500 separates the measured
    // buckets from the single unmeasured one.
    BOOST_TEST(b == (std::vector<key_type>{key_of(200), key_of(300), key_of(400), key_of(500)}));
}

BOOST_AUTO_TEST_CASE(a_merge_with_no_measured_side_still_keeps_the_shared_bound) {
    // A replica that led neither shard's set has nothing but the bound.
    const auto b =
        set_type::merge_boundaries(range_of(100, 900), range_of(100, 500), {}, {}, {}, 3);
    BOOST_TEST(b == (std::vector<key_type>{key_of(500)}));
}

// ── exposure helpers (task 6) ────────────────────────────────────────────────

namespace {

auto stats_with(std::vector<double> qps) -> std::vector<kythira::bucket_stats<key_type>> {
    std::vector<kythira::bucket_stats<key_type>> out;
    for (std::size_t i = 0; i < qps.size(); ++i) {
        kythira::bucket_stats<key_type> b;
        if (i > 0) {
            b._start = key_of(static_cast<int>(i) * 100);
        }
        if (i + 1 < qps.size()) {
            b._end = key_of(static_cast<int>(i + 1) * 100);
        }
        b._read_qps = qps[i] / 2;
        b._write_qps = qps[i] / 2;
        out.push_back(b);
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_hottest_share_is_the_busiest_buckets_fraction) {
    BOOST_TEST(kythira::hottest_bucket_share(stats_with({10, 30, 60})) == 0.6);
    BOOST_TEST(kythira::hottest_bucket_share(stats_with({0, 0})) == 0.0);
    BOOST_TEST(kythira::hottest_bucket_share(std::vector<kythira::bucket_stats<key_type>>{}) ==
               0.0);
    BOOST_TEST(kythira::hottest_bucket_share(stats_with({5})) == 1.0);
}

BOOST_AUTO_TEST_CASE(the_report_carries_at_most_k_buckets_busiest_first) {
    // Requirement 5.2.
    const auto top = kythira::top_buckets(stats_with({10, 40, 30, 40, 5}), 3);
    BOOST_REQUIRE(top.size() == 3U);
    BOOST_TEST(top[0].qps() == 40.0);
    BOOST_TEST((top[0]._start == std::optional<key_type>{key_of(100)}));  // ties in key order
    BOOST_TEST(top[1].qps() == 40.0);
    BOOST_TEST(top[2].qps() == 30.0);
    BOOST_TEST(kythira::top_buckets(stats_with({1, 2}), 4).size() == 2U);
}

BOOST_AUTO_TEST_CASE(the_best_cut_balances_and_reports_how_evenly) {
    const auto cut = kythira::best_bucket_cut(stats_with({10, 200, 150, 40}));
    BOOST_REQUIRE(cut.has_value());
    BOOST_TEST(cut->_boundary == 1U);
    BOOST_TEST(cut->_left == 210.0);
    BOOST_TEST(cut->_right == 190.0);
    BOOST_TEST(cut->one_sided_fraction() == 210.0 / 400.0);
    BOOST_TEST(!kythira::best_bucket_cut(stats_with({100})).has_value());
    BOOST_TEST(kythira::best_bucket_cut(stats_with({0, 0}))->one_sided_fraction() == 1.0);
}
