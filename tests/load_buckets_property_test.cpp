// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file load_buckets_property_test.cpp
/// @brief Requirement 7.2 of `.kiro/specs/multi-raft-load-buckets/`: over
///        random boundary sets and key streams, every key lands in exactly
///        one bucket, and that bucket's range contains it.
///
/// Integer keys over a small domain, so random keys hit boundaries, range
/// bounds and their neighbours often: those are where an off-by-one between
/// `upper_bound` and the half-open ranges `snapshot()` reports would show.

#define BOOST_TEST_MODULE load_buckets_property_test
#include <boost/test/unit_test.hpp>

#include <raft/load_buckets.hpp>
#include <raft/shard_types.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

using kythira::bucket_config;
using kythira::bucket_set;
using kythira::shard_range;

namespace {

using key_type = std::int64_t;
using set_type = bucket_set<key_type>;
using clock = set_type::clock;
using namespace std::chrono_literals;

constexpr int k_iterations = 500;
constexpr key_type k_domain = 200;

auto random_range(std::mt19937_64& rng) -> shard_range<key_type> {
    std::uniform_int_distribution<int> kind{0, 3};
    std::uniform_int_distribution<key_type> key{-k_domain, k_domain};
    shard_range<key_type> r;
    const auto k = kind(rng);
    if (k == 1 || k == 3) {
        r._start = key(rng);
    }
    if (k == 2 || k == 3) {
        r._end = key(rng);
        if (r._start.has_value() && !(*r._start < *r._end)) {
            r._end = *r._start + 1 + (key(rng) & 63);
        }
    }
    return r;
}

}  // namespace

BOOST_AUTO_TEST_CASE(every_key_lands_in_exactly_one_bucket_that_contains_it) {
    std::mt19937_64 rng{20261120};
    std::uniform_int_distribution<key_type> key{-k_domain - 10, k_domain + 80};
    std::uniform_int_distribution<std::size_t> target{2, 40};
    std::uniform_int_distribution<int> candidates{0, 80};

    for (int iter = 0; iter < k_iterations; ++iter) {
        const auto range = random_range(rng);
        bucket_config cfg;
        cfg._enabled = true;
        cfg._target_buckets = target(rng);
        cfg._window_slots = 2;
        cfg._reservoir_stride = 1;
        cfg._seed = static_cast<std::uint64_t>(iter) + 1;

        // Random candidates, including keys outside the range and repeats:
        // the set must normalise them, never trust them.
        std::vector<key_type> raw;
        const auto n = candidates(rng);
        for (int i = 0; i < n; ++i) {
            raw.push_back(key(rng));
        }
        const auto t0 = clock::now();
        set_type set{cfg, range, t0, raw};

        const auto boundaries = set.boundaries();
        BOOST_REQUIRE(boundaries.size() + 1 <= cfg._target_buckets);
        BOOST_REQUIRE(set.bucket_count() == boundaries.size() + 1);
        for (std::size_t i = 0; i < boundaries.size(); ++i) {
            BOOST_REQUIRE(range.is_interior(boundaries[i]));
            if (i > 0) {
                BOOST_REQUIRE(boundaries[i - 1] < boundaries[i]);
            }
        }

        // The buckets tile the range: first starts where it does, last ends
        // where it does, each starts where the previous ended.
        const auto snap = set.snapshot();
        BOOST_REQUIRE(snap.size() == set.bucket_count());
        BOOST_REQUIRE(snap.front()._start == range._start);
        BOOST_REQUIRE(snap.back()._end == range._end);
        for (std::size_t b = 1; b < snap.size(); ++b) {
            BOOST_REQUIRE(snap[b]._start == snap[b - 1]._end);
            BOOST_REQUIRE(!snap[b].range().is_empty());
        }

        // Every key the range holds is in exactly one bucket's range, and it
        // is the one `bucket_index` names — and counting it lands there.
        std::vector<std::uint64_t> expected(set.bucket_count(), 0);
        for (int i = 0; i < 300; ++i) {
            const auto k = key(rng);
            if (!range.contains(k)) {
                continue;
            }
            std::size_t holders = 0;
            std::size_t holder = 0;
            for (std::size_t b = 0; b < snap.size(); ++b) {
                if (snap[b].range().contains(k)) {
                    ++holders;
                    holder = b;
                }
            }
            BOOST_REQUIRE(holders == 1U);
            BOOST_REQUIRE(set_type::bucket_index(boundaries, k) == holder);
            set.count(k, 1, (i & 1) != 0);
            ++expected[holder];
        }
        BOOST_REQUIRE(set.roll(t0 + cfg._slot_duration));
        const auto counts = set.window_counts();
        for (std::size_t b = 0; b < counts.size(); ++b) {
            BOOST_REQUIRE(counts[b].requests() == expected[b]);
        }

        // Re-cutting from the reservoir keeps every property above.
        (void)set.refresh(set.reservoir_boundaries(), t0 + cfg._slot_duration);
        for (const auto& b : set.boundaries()) {
            BOOST_REQUIRE(range.is_interior(b));
        }
        BOOST_REQUIRE(set.bucket_count() <= cfg._target_buckets);
    }
}
