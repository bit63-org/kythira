// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file multi_raft_load_buckets_test.cpp
/// @brief Load buckets wired into the host (tasks 3-5 of
///        `.kiro/specs/multi-raft-load-buckets/`): counting at the routing
///        layer, boundaries on the policy phase, and what a split and a merge
///        hand down.
///
/// One single-voter host ticked by hand, with slots and policy ticks of a few
/// tens of milliseconds so a window fills inside a test.

#define BOOST_TEST_MODULE multi_raft_load_buckets_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <raft/split_merge_policy.hpp>
#include <raft/test_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <atomic>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("multi_raft_load_buckets_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using kythira::arbiter_gate;
using kythira::group_report;
using kythira::hibernation_mode;
using kythira::multi_raft;
using kythira::multi_raft_config;
using kythira::no_valid_split_key_exception;
using kythira::shard_busy_exception;
using kythira::shard_descriptor;
using kythira::shard_epoch;
using kythira::shard_operation_state;
using kythira::shard_range;
using kythira::signal_channel;
using kythira::split_options;
using kythira::threshold_split_merge_policy;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

struct host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type = fabric_client;
    using network_server_type = fabric_server;

    using persistence_engine_type =
        kythira::memory_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = kythira::test_key_value_state_machine<log_index_type>;

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

using host_type = multi_raft<host_types, key_type, group_id_type>;
using config_type = multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = shard_descriptor<group_id_type, key_type, node_id_t>;
using stats_type = kythira::shard_stats<group_id_type, key_type, node_id_t>;
using policy_type = threshold_split_merge_policy<group_id_type, key_type>;

constexpr group_id_type k_group = 1;

auto workload_keys() -> std::vector<key_type> {
    return {"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"};
}

/// One host, one single-voter shard, ticked by hand. Same harness as
/// multi_raft_arbiter_unit_test.
class bucket_host {
public:
    explicit bucket_host(std::function<void(config_type&)> tweak = {}) {
        config_type cfg{
            .node_id = 1,
            .network_client = fabric_client{_fabric, 1},
            .network_server = fabric_server{_fabric, 1},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{40};
        cfg.config._election_timeout_max = std::chrono::milliseconds{80};
        cfg.config._heartbeat_interval = std::chrono::milliseconds{10};
        cfg.hibernation = hibernation_mode::off;
        cfg.executor_stripes = 2;
        cfg.allocate_group_ids = [this](std::size_t n) {
            std::vector<group_id_type> out;
            for (std::size_t i = 0; i < n; ++i) {
                out.push_back(_next_id++);
            }
            return out;
        };
        // No cooldown by default: most cases here are about other gates, and a
        // one-hour interval would mask every one of them behind the first.
        cfg.split_merge_interval = std::chrono::milliseconds{0};
        if (tweak) {
            tweak(cfg);
        }
        _host = std::make_unique<host_type>(std::move(cfg));
        _host->create_group(descriptor_type{._group_id = k_group,
                                            ._range = kythira::unbounded_shard_range<key_type>(),
                                            ._epoch = shard_epoch{},
                                            ._voters = {1},
                                            ._learners = {},
                                            ._leader_hint = std::nullopt});
        _host->start();
    }

    ~bucket_host() { _host->stop(); }

    bucket_host(const bucket_host&) = delete;
    auto operator=(const bucket_host&) -> bucket_host& = delete;

    [[nodiscard]] auto host() -> host_type& { return *_host; }

    auto tick_until(const std::function<bool()>& predicate,
                    std::chrono::milliseconds budget = std::chrono::milliseconds{5000}) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            _host->tick();
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        return predicate();
    }

    auto await_leader() -> bool {
        return tick_until([&] { return _host->group_node(k_group)->is_leader(); });
    }

    auto put(const key_type& key, const std::string& value) -> bool {
        auto f =
            _host->submit_command(key, host_types::state_machine_type::make_put_command(key, value),
                                  std::chrono::milliseconds{2000});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (!f.wait(std::chrono::milliseconds{5}) &&
               std::chrono::steady_clock::now() < deadline) {
            _host->tick();
        }
        try {
            std::ignore = std::move(f).get();
            return true;
        } catch (...) {
            return false;
        }
    }

    /// @brief Resolve a future while keeping the host ticking underneath it.
    template<typename Future> auto settle(Future&& f) -> std::exception_ptr {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{6};
        while (!f.wait(std::chrono::milliseconds{5}) &&
               std::chrono::steady_clock::now() < deadline) {
            _host->tick();
        }
        if (!f.wait(std::chrono::milliseconds{100})) {
            return std::make_exception_ptr(std::runtime_error("never resolved"));
        }
        try {
            std::ignore = std::forward<Future>(f).get();
            return nullptr;
        } catch (...) {
            return std::current_exception();
        }
    }

    auto seed() -> void {
        for (const auto& k : workload_keys()) {
            BOOST_REQUIRE(put(k, "v-" + k));
        }
    }

private:
    message_fabric _fabric{2};
    std::unique_ptr<host_type> _host;
    group_id_type _next_id{100};
};

auto key_of(int n) -> key_type {
    auto s = std::to_string(n);
    return "k" + std::string(3 - s.size(), '0') + s;
}

auto enable_buckets(config_type& cfg) -> void {
    cfg.buckets._enabled = true;
    cfg.buckets._target_buckets = 4;
    cfg.buckets._window_slots = 3;
    cfg.buckets._slot_duration = std::chrono::milliseconds{30};
    // Long, so the only cuts are the first one and the ones a split or merge
    // hands down: the cases below assert on exact boundaries.
    cfg.buckets._refresh_interval = std::chrono::hours{1};
    cfg.buckets._reservoir_stride = 1;
    cfg.buckets._seed = 20261120;
    cfg.policy_interval = std::chrono::milliseconds{10};
}

auto boundaries_of(const stats_type& s) -> std::vector<key_type> {
    std::vector<key_type> out;
    for (std::size_t i = 1; i < s._buckets.size(); ++i) {
        out.push_back(*s._buckets[i]._start);
    }
    return out;
}

/// Seed 40 keys, then tick until the leader has cut its range into four
/// buckets at the state machine's suggested keys.
auto seed_and_cut(bucket_host& h) -> std::vector<key_type> {
    for (int i = 0; i < 40; ++i) {
        BOOST_REQUIRE(h.put(key_of(i), "v"));
    }
    BOOST_REQUIRE(h.tick_until([&] {
        auto s = h.host().stats_for(k_group);
        return s.has_value() && s->_buckets.size() == 4;
    }));
    return boundaries_of(*h.host().stats_for(k_group));
}

/// Keep `work` running and the host ticking until `predicate` holds.
auto drive_until(bucket_host& h, const std::function<void()>& work,
                 const std::function<bool()>& predicate,
                 std::chrono::milliseconds budget = std::chrono::milliseconds{8000}) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        work();
        h.host().tick();
        if (predicate()) {
            return true;
        }
    }
    return predicate();
}

/// The load-split gates of multi_raft_arbiter_unit_test, with buckets on or
/// off: thresholds low enough that in-process traffic is hot, size triggers
/// out of reach, and a sampling window longer than the bursts below.
auto load_split_config(bool buckets) -> std::function<void(config_type&)> {
    return [buckets](config_type& cfg) {
        cfg.load_split._enabled = true;
        cfg.load_split._qps_threshold = 1.0;
        cfg.load_split._bytes_threshold = 1e12;
        cfg.load_split._duration = std::chrono::milliseconds{100};
        cfg.load_split._one_sided_fraction = 0.99;
        cfg.load_split._seed = 20261120;

        kythira::threshold_split_merge_policy_config policy_cfg;
        policy_cfg._load_split_enabled = true;
        policy_cfg._load_split_qps_threshold = 1.0;
        policy_cfg._load_split_duration = std::chrono::milliseconds{100};
        policy_cfg._load_split_one_sided_fraction = 0.99;
        policy_cfg._shard_split_size_bytes = 1ULL << 40;
        policy_cfg._shard_max_size_bytes = 1ULL << 41;
        policy_cfg._shard_split_keys = 1'000'000'000;
        policy_cfg._shard_max_keys = 2'000'000'000;
        policy_cfg._shard_merge_max_size_bytes = 1;
        policy_cfg._shard_merge_max_keys = 1;
        auto policy = std::make_shared<policy_type>(policy_cfg);
        cfg.evaluate_split = [policy](const stats_type& s) { return policy->evaluate_split(s); };
        cfg.policy_interval = std::chrono::milliseconds{20};
        cfg.split_merge_interval = std::chrono::milliseconds{0};

        if (buckets) {
            cfg.buckets._enabled = true;
            cfg.buckets._target_buckets = 16;
            cfg.buckets._window_slots = 6;
            cfg.buckets._slot_duration = std::chrono::milliseconds{50};
            cfg.buckets._refresh_interval = std::chrono::hours{1};
            cfg.buckets._seed = 20261120;
        }
    };
}

/// Requirement 7.3's skew: a quarter of the key space ([k000, k025)) takes
/// 90% of the writes. Sustained in bursts: 60 ms of writes, then 60 ms with
/// none, round after round. The load never stops for long, but every idle
/// gap spans whole policy ticks with no writes, which is exactly a "spike
/// that ended" to the sampler, so its 100 ms window never completes. The
/// buckets' window spans the gaps, and is what this measures.
///
/// @return The first split's cut key, or nothing within `budget`.
auto run_bursty_skew(bucket_host& h, std::chrono::milliseconds budget) -> std::optional<key_type> {
    for (int i = 0; i < 100; ++i) {
        BOOST_REQUIRE(h.put(key_of(i), "v"));
    }
    std::mt19937 rng{20261120};
    std::uniform_int_distribution<int> pct{0, 99};
    std::uniform_int_distribution<int> hot{0, 24};
    std::uniform_int_distribution<int> cold{25, 99};
    const auto deadline = std::chrono::steady_clock::now() + budget;
    const auto burst = std::chrono::milliseconds{60};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto busy_until = std::chrono::steady_clock::now() + burst;
        while (std::chrono::steady_clock::now() < busy_until) {
            std::ignore = h.put(key_of(pct(rng) < 90 ? hot(rng) : cold(rng)), "w");
            h.host().tick();
            if (h.host().applied_split_count() > 0) {
                return h.host().stats_for(k_group)->descriptor()._range._end;
            }
        }
        const auto idle_until = std::chrono::steady_clock::now() + burst;
        while (std::chrono::steady_clock::now() < idle_until) {
            h.host().tick();
            if (h.host().applied_split_count() > 0) {
                return h.host().stats_for(k_group)->descriptor()._range._end;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
    }
    return std::nullopt;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(multi_raft_load_buckets)

BOOST_AUTO_TEST_CASE(a_host_with_buckets_off_reports_none, *boost::unit_test::timeout(120)) {
    // Requirement 1.3: off by default, and `_buckets` stays empty.
    bucket_host h{[](config_type& cfg) { cfg.policy_interval = std::chrono::milliseconds{10}; }};
    BOOST_REQUIRE(h.await_leader());
    for (int i = 0; i < 20; ++i) {
        BOOST_REQUIRE(h.put(key_of(i), "v"));
    }
    for (int i = 0; i < 10; ++i) {
        h.host().tick();
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    const auto s = h.host().stats_for(k_group);
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST(s->_buckets.empty());
    BOOST_TEST(s->_buckets_version == 0U);
}

BOOST_AUTO_TEST_CASE(the_leader_cuts_at_the_suggested_keys_and_counts_each_write_where_it_lands,
                     *boost::unit_test::timeout(120)) {
    bucket_host h{enable_buckets};
    BOOST_REQUIRE(h.await_leader());
    const auto cut = seed_and_cut(h);

    // Requirement 2.1: the test state machine suggests keys evenly spaced by
    // count, and every one it suggests is a key it holds.
    BOOST_REQUIRE(cut.size() == 3U);
    BOOST_TEST(cut[0] < cut[1]);
    BOOST_TEST(cut[1] < cut[2]);
    BOOST_TEST(h.host().stats_for(k_group)->_buckets_version >= 1U);

    // Requirement 3.1: writes to keys below the first boundary load only the
    // first bucket, once the window has rolled past the seeding traffic.
    int next = 0;
    const auto first_only = [&] {
        const auto s = h.host().stats_for(k_group);
        if (!s || s->_buckets.size() != 4 || s->_buckets[0]._write_qps <= 0.0) {
            return false;
        }
        for (std::size_t b = 1; b < 4; ++b) {
            if (s->_buckets[b].qps() != 0.0) {
                return false;
            }
        }
        return true;
    };
    BOOST_TEST(drive_until(h, [&] { std::ignore = h.put(key_of(next++ % 3), "w"); }, first_only));
    const auto s = h.host().stats_for(k_group);
    BOOST_TEST(s->_buckets[0]._write_bytes_per_sec > 0.0);
    // The cut stays put: equal refreshes keep the version (Requirement 2.3).
    BOOST_TEST(boundaries_of(*s) == cut);
}

BOOST_AUTO_TEST_CASE(a_keyless_request_is_counted_only_at_shard_level,
                     *boost::unit_test::timeout(120)) {
    // Requirement 3.4: `submit_command(group, ...)` has no key, so it loads
    // the shard and no bucket.
    bucket_host h{enable_buckets};
    BOOST_REQUIRE(h.await_leader());
    std::ignore = seed_and_cut(h);
    const auto epoch = h.host().stats_for(k_group)->epoch();
    const auto keyless = [&] {
        auto f = h.host().submit_command(
            k_group, epoch, host_types::state_machine_type::make_put_command("k001", "x"),
            std::chrono::milliseconds{2000});
        std::ignore = h.settle(std::move(f));
    };
    const auto shard_only = [&] {
        const auto s = h.host().stats_for(k_group);
        if (!s || s->_write_qps <= 0.0 || s->_buckets.size() != 4) {
            return false;
        }
        double sum = 0.0;
        for (const auto& b : s->_buckets) {
            sum += b.qps();
        }
        return sum == 0.0;
    };
    BOOST_TEST(drive_until(h, keyless, shard_only));
}

BOOST_AUTO_TEST_CASE(split_children_inherit_the_boundaries_inside_their_ranges,
                     *boost::unit_test::timeout(120)) {
    bucket_host h{enable_buckets};
    BOOST_REQUIRE(h.await_leader());
    const auto cut = seed_and_cut(h);
    BOOST_REQUIRE(cut.size() == 3U);

    // Split at the middle boundary: the left part keeps the parent's id and
    // inherits the first boundary, the right child the third (Requirement
    // 4.2), each at a fresh version 1.
    BOOST_REQUIRE(h.settle(h.host().split_shard(k_group, {cut[1]},
                                                std::chrono::milliseconds{5000})) == nullptr);
    BOOST_REQUIRE(h.tick_until([&] { return h.host().applied_split_count() > 0; }));
    const group_id_type right = 100;
    const auto inherited = [&](group_id_type g, const key_type& expected) {
        const auto s = h.host().stats_for(g);
        return s.has_value() && s->_buckets.size() == 2 && *s->_buckets[1]._start == expected;
    };
    BOOST_TEST(h.tick_until([&] { return inherited(k_group, cut[0]); }));
    BOOST_TEST(h.tick_until([&] { return inherited(right, cut[2]); }));
    const auto left = h.host().stats_for(k_group);
    BOOST_TEST(left->_buckets_version == 1U);
    BOOST_TEST(!left->_buckets.front()._start.has_value());
    BOOST_TEST((left->_buckets.back()._end == std::optional<key_type>{cut[1]}));
    const auto r = h.host().stats_for(right);
    BOOST_TEST(r->_buckets_version == 1U);
    BOOST_TEST((r->_buckets.front()._start == std::optional<key_type>{cut[1]}));
    BOOST_TEST(!r->_buckets.back()._end.has_value());

    // Merging them back: the survivor takes both lists plus the old shared
    // bound (Requirement 4.3). Three boundaries fit four buckets, so nothing
    // is trimmed and the original cut comes back.
    BOOST_REQUIRE(h.settle(h.host().merge_shards(right, k_group,
                                                 std::chrono::milliseconds{5000})) == nullptr);
    BOOST_REQUIRE(h.tick_until([&] { return h.host().applied_merge_count() > 0; }));
    BOOST_TEST(h.tick_until([&] {
        const auto s = h.host().stats_for(k_group);
        return s.has_value() && boundaries_of(*s) == cut;
    }));
    BOOST_TEST(h.host().stats_for(k_group)->_buckets_version == 1U);
}

BOOST_AUTO_TEST_CASE(the_report_carries_the_busiest_buckets_and_no_more,
                     *boost::unit_test::timeout(120)) {
    // Requirement 5.2: four buckets, two reported, busiest first.
    bucket_host h{[](config_type& cfg) {
        enable_buckets(cfg);
        cfg.buckets._report_top_buckets = 2;
    }};
    BOOST_REQUIRE(h.await_leader());
    const auto cut = seed_and_cut(h);
    int next = 0;
    const auto reported = [&] {
        const auto reports = h.host().build_shard_reports();
        return reports.size() == 1 && reports[0]._hot_buckets.size() == 2 &&
               reports[0]._hot_buckets[0].qps() > 0.0;
    };
    // All writes below the first boundary: that bucket leads the report.
    BOOST_REQUIRE(drive_until(h, [&] { std::ignore = h.put(key_of(next++ % 3), "w"); }, reported));
    const auto r = h.host().build_shard_reports().front();
    BOOST_TEST(!r._hot_buckets[0]._start.has_value());
    BOOST_TEST((r._hot_buckets[0]._end == std::optional<key_type>{cut[0]}));
    BOOST_TEST(r._hot_buckets[0].qps() >= r._hot_buckets[1].qps());
}

BOOST_AUTO_TEST_CASE(buckets_split_a_skewed_load_the_sampler_alone_keeps_abandoning,
                     *boost::unit_test::timeout(180)) {
    // Requirement 7.3, first half. The sampler alone: every burst gap reads
    // as a spike that ended, so its window restarts and no split comes.
    {
        bucket_host h{load_split_config(false)};
        BOOST_REQUIRE(h.await_leader());
        BOOST_TEST(!run_bursty_skew(h, std::chrono::milliseconds{3000}).has_value());
        const auto counters = h.host().load_sampler_counters(k_group).value();
        BOOST_TEST(counters[1] >= 1U);  // abandoned spikes: the reason, recorded
    }
    // With buckets, the window spans the gaps: a split comes inside the same
    // budget, and it cuts inside the hot quarter.
    bucket_host h{load_split_config(true)};
    BOOST_REQUIRE(h.await_leader());
    const auto at = run_bursty_skew(h, std::chrono::milliseconds{3000});
    BOOST_REQUIRE_MESSAGE(at.has_value(), "buckets should split the skewed load within budget");
    BOOST_TEST(*at > key_of(0));
    BOOST_TEST(*at < key_of(25));
    BOOST_TEST(!h.host().shard_map_snapshot().check_tiling().has_value());
}

BOOST_AUTO_TEST_CASE(a_single_hot_key_is_never_split_with_buckets_on,
                     *boost::unit_test::timeout(180)) {
    // Requirement 7.3, second half: every boundary is one-sided, so the policy
    // declines; the host narrows the sampler to the hot bucket, which finds
    // the one key and backs the shard off, and the back-off holds the bucket
    // branch too (Requirement 6.4).
    bucket_host h{load_split_config(true)};
    BOOST_REQUIRE(h.await_leader());
    for (int i = 0; i < 100; ++i) {
        BOOST_REQUIRE(h.put(key_of(i), "v"));
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline) {
        std::ignore = h.put(key_of(50), "w");
        h.host().tick();
    }
    BOOST_TEST(h.host().applied_split_count() == 0U);
    const auto counters = h.host().load_sampler_counters(k_group).value();
    BOOST_TEST(counters[2] >= 1U);  // single-hot-key verdicts
    BOOST_TEST(counters[3] == 0U);  // proposals
    BOOST_TEST(h.host().stats_for(k_group)->_load_split_backoff);
}

BOOST_AUTO_TEST_SUITE_END()
