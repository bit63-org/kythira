// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file replica_evacuation_test.cpp
/// @brief Evacuating a node's replicas over the placement operators
///        (include/raft/replica_evacuation.hpp,
///        .kiro/specs/kinesis-independent-layers/ task 13, Requirement 11.3).
///
/// The step function on its own: each step of the learner-first sequence,
/// resuming after a leader change, never removing the evacuee before the
/// group has its voters without it, spreading replacements by load. Then
/// the evacuator on real `multi_raft` hosts over the in-process fabric: a
/// co-located node's replicas move to a new node and back while writes
/// continue, no write is lost, and every group keeps three voters at the
/// end of each direction.

#define BOOST_TEST_MODULE replica_evacuation_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <raft/replica_evacuation.hpp>
#include <raft/test_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("replica_evacuation_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using namespace std::chrono_literals;
using kythira::evacuation_action;
using kythira::evacuation_view;
using kythira::next_evacuation_step;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;

auto step(const evacuation_view<node_id_t>& v, node_id_t evacuee, std::vector<node_id_t> targets,
          std::size_t replicas = 3, std::function<std::size_t(const node_id_t&)> load = {}) {
    return next_evacuation_step<node_id_t>(v, evacuee, targets, replicas, load);
}

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

using host_type = kythira::multi_raft<host_types, key_type, group_id_type>;
using config_type = kythira::multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = kythira::shard_descriptor<group_id_type, key_type, node_id_t>;
using evacuator_type = kythira::replica_evacuator<host_type>;

constexpr group_id_type k_groups = 3;

/// Four hosts; groups 1-3 on hosts 1-3, host 4 empty. Each host runs an
/// evacuator; a lookup for an unknown group asks every host for its live
/// descriptor, as a node would ask its peers.
class cluster {
public:
    cluster() {
        for (node_id_t id = 1; id <= 4; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
        }
        for (node_id_t id = 1; id <= 3; ++id) {
            for (group_id_type g = 1; g <= k_groups; ++g) {
                host(id).create_group(descriptor(g));
            }
        }
        for (auto& h : _hosts) {
            _evacuators.push_back(std::make_unique<evacuator_type>(*h));
            h->start();
        }
        _running = true;
        for (const auto& host : _hosts) {
            _drivers.emplace_back([this, h = host.get()] {
                while (_running.load()) {
                    h->tick();
                    std::this_thread::sleep_for(5ms);
                }
            });
        }
    }

    ~cluster() {
        _running = false;
        for (auto& t : _drivers) {
            t.join();
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;
    cluster(cluster&&) = delete;
    auto operator=(cluster&&) -> cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }
    [[nodiscard]] auto evacuator(node_id_t id) -> evacuator_type& {
        return *_evacuators.at(id - 1);
    }

    [[nodiscard]] auto leader_of(group_id_type g) -> host_type* {
        for (auto& h : _hosts) {
            auto* n = h->group_node(g);
            if (n != nullptr && n->is_leader()) {
                return h.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto membership(group_id_type g) -> std::optional<descriptor_type> {
        auto* l = leader_of(g);
        return l == nullptr ? std::nullopt : kythira::live_descriptor(*l, g);
    }

    /// Every host runs the job; passes until every group is done.
    auto evacuate(node_id_t evacuee, std::vector<node_id_t> targets,
                  std::chrono::milliseconds budget) -> bool {
        for (auto& e : _evacuators) {
            e->start({._evacuee = evacuee, ._targets = targets, ._replicas = 3});
        }
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            std::size_t led_done = 0;
            for (auto& e : _evacuators) {
                const auto p = e->pass();
                for (const auto& g : p._led) {
                    if (g._action == evacuation_action::stuck) {
                        BOOST_TEST_MESSAGE("group " << g._group << " stuck");
                    }
                    if (g._action == evacuation_action::done) {
                        ++led_done;
                    }
                }
            }
            note_voters();
            if (led_done == k_groups && all_moved(evacuee)) {
                for (auto& e : _evacuators) {
                    e->cancel();
                }
                return true;
            }
            std::this_thread::sleep_for(20ms);
        }
        return false;
    }

    [[nodiscard]] auto all_moved(node_id_t evacuee) -> bool {
        for (group_id_type g = 1; g <= k_groups; ++g) {
            const auto d = membership(g);
            if (!d || d->has_replica(evacuee) || d->_voters.size() != 3) {
                return false;
            }
        }
        return true;
    }

    auto put(const key_type& key, const std::string& value) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        const auto g = group_of(key);
        while (std::chrono::steady_clock::now() < deadline) {
            if (auto* l = leader_of(g)) {
                auto f = l->submit_command(
                    key, host_types::state_machine_type::make_put_command(key, value), 2s);
                if (f.wait(2s)) {
                    try {
                        static_cast<void>(std::move(f).get());
                        return true;
                    } catch (const std::exception&) {
                        // Not the leader any more, or lost: retry.
                    }
                }
            }
            std::this_thread::sleep_for(20ms);
        }
        return false;
    }

    /// The value as `id`'s replica has applied it.
    auto get(node_id_t id, const key_type& key) -> std::optional<std::string> {
        auto v = host(id).with_group_state_machine(
            group_of(key), [&](auto& sm, const auto&) { return sm.get_value(key); });
        return v ? *v : std::nullopt;
    }

    [[nodiscard]] static auto group_of(const key_type& key) -> group_id_type {
        return key < "h" ? 1 : key < "p" ? 2 : 3;
    }

    [[nodiscard]] auto fewest_voters() const -> std::size_t { return _fewest; }

private:
    static auto descriptor(group_id_type g) -> descriptor_type {
        // Three ranges: (-inf, "h"), ["h", "p"), ["p", +inf).
        std::optional<key_type> start;
        std::optional<key_type> end;
        if (g == 1) {
            end = "h";
        } else if (g == 2) {
            start = "h";
            end = "p";
        } else {
            start = "p";
        }
        return descriptor_type{
            ._group_id = g,
            ._range = kythira::shard_range<key_type>{._start = start, ._end = end},
            ._epoch = kythira::shard_epoch{},
            ._voters = {1, 2, 3},
            ._learners = {},
            ._leader_hint = std::nullopt};
    }

    void note_voters() {
        for (group_id_type g = 1; g <= k_groups; ++g) {
            if (auto d = membership(g)) {
                _fewest = std::min(_fewest, d->_voters.size());
            }
        }
    }

    auto make_config(node_id_t id) -> config_type {
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = 150ms;
        cfg.config._election_timeout_max = 300ms;
        cfg.config._heartbeat_interval = 25ms;
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.executor_stripes = 2;
        cfg.heartbeat_interval = 0ms;
        cfg.logger = kythira::console_logger{kythira::log_level::warning};
        cfg.logger_factory = [](const group_id_type&) {
            return kythira::console_logger{kythira::log_level::warning};
        };
        cfg.automatic_split_merge_enabled = false;
        cfg.unknown_group_lookup_interval = 50ms;
        cfg.lookup_descriptor = [this,
                                 id](const group_id_type& g) -> std::optional<descriptor_type> {
            for (node_id_t other = 1; other <= 4; ++other) {
                if (other == id) {
                    continue;
                }
                auto& h = host(other);
                auto* n = h.group_node(g);
                if (n != nullptr && n->is_leader()) {
                    return kythira::live_descriptor(h, g);
                }
            }
            return std::nullopt;
        };
        return cfg;
    }

    message_fabric _fabric{6};
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::unique_ptr<evacuator_type>> _evacuators;
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
    std::size_t _fewest{3};
};

}  // namespace

BOOST_AUTO_TEST_SUITE(evacuation_steps)

BOOST_AUTO_TEST_CASE(a_group_without_the_evacuee_is_done) {
    const auto s = step({._voters = {2, 3, 4}, ._leader = 2}, 1, {4});
    BOOST_TEST((s._action == evacuation_action::done));
}

BOOST_AUTO_TEST_CASE(a_replacement_is_added_before_anything_is_removed) {
    const auto s = step({._voters = {1, 2, 3}, ._leader = 2}, 1, {4});
    BOOST_TEST((s._action == evacuation_action::add_replica));
    BOOST_TEST((s._node == std::optional<node_id_t>{4}));
}

BOOST_AUTO_TEST_CASE(a_learner_target_is_resumed_not_doubled) {
    // A leader change after the learner was added: the new leader resumes
    // that learner instead of adding a second target.
    const auto s = step({._voters = {1, 2, 3}, ._learners = {5}, ._leader = 3}, 1, {4, 5});
    BOOST_TEST((s._action == evacuation_action::add_replica));
    BOOST_TEST((s._node == std::optional<node_id_t>{5}));
}

BOOST_AUTO_TEST_CASE(the_evacuee_goes_once_the_group_has_its_voters_without_it) {
    const auto s = step({._voters = {1, 2, 3, 4}, ._leader = 2}, 1, {4});
    BOOST_TEST((s._action == evacuation_action::remove_replica));
    BOOST_TEST((s._node == std::optional<node_id_t>{1}));
}

BOOST_AUTO_TEST_CASE(a_leading_evacuee_hands_leadership_to_its_replacement_first) {
    const auto s = step({._voters = {1, 2, 3, 4}, ._leader = 1}, 1, {4});
    BOOST_TEST((s._action == evacuation_action::transfer_leader));
    BOOST_TEST((s._node == std::optional<node_id_t>{4}));
}

BOOST_AUTO_TEST_CASE(nothing_starts_while_a_change_is_in_flight) {
    const auto s = step({._voters = {1, 2, 3}, ._changing = true, ._leader = 2}, 1, {4});
    BOOST_TEST((s._action == evacuation_action::wait));
}

BOOST_AUTO_TEST_CASE(an_evacuee_that_is_only_a_learner_is_removed_at_once) {
    const auto s = step({._voters = {2, 3, 4}, ._learners = {1}, ._leader = 2}, 1, {});
    BOOST_TEST((s._action == evacuation_action::remove_replica));
}

BOOST_AUTO_TEST_CASE(with_no_target_outside_the_group_the_move_is_stuck) {
    // Removing the evacuee now would drop the group to two voters.
    BOOST_TEST((step({._voters = {1, 2, 3}, ._leader = 2}, 1, {2, 3})._action ==
                evacuation_action::stuck));
    BOOST_TEST(
        (step({._voters = {1, 2, 3}, ._leader = 2}, 1, {})._action == evacuation_action::stuck));
}

BOOST_AUTO_TEST_CASE(replacements_go_to_the_least_loaded_target) {
    std::map<node_id_t, std::size_t> load{{4, 7}, {5, 2}, {6, 2}};
    const auto s = step({._voters = {1, 2, 3}, ._leader = 2}, 1, {4, 5, 6}, 3,
                        [&](const node_id_t& n) { return load[n]; });
    BOOST_TEST((s._node == std::optional<node_id_t>{5}));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(evacuation_on_hosts)

namespace {
/// Keys that fall in all three groups' ranges in turn.
auto key_of(int i) -> std::string {
    static constexpr std::array<const char*, 3> prefixes{"c", "k", "t"};
    return std::string(prefixes.at(static_cast<std::size_t>(i) % 3)) + std::to_string(i);
}
}  // namespace

BOOST_AUTO_TEST_CASE(a_node_is_evacuated_to_a_new_node_and_back_under_writes,
                     *boost::unit_test::timeout(180)) {
    cluster c;
    const auto leaders = [&] {
        for (group_id_type g = 1; g <= k_groups; ++g) {
            if (c.leader_of(g) == nullptr) {
                return false;
            }
        }
        return true;
    };
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (!leaders() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    BOOST_REQUIRE(leaders());

    // A writer for the whole test, over all three groups: every
    // acknowledged write must be on every voter at the end.
    std::atomic<bool> writing{true};
    std::atomic<int> acked{0};
    std::thread w([&] {
        for (int i = 0; writing.load(); ++i) {
            if (c.put(key_of(i), "v" + std::to_string(i))) {
                acked.store(i + 1);
            } else {
                break;
            }
        }
    });

    // Co-located (1, 2, 3) to a data-only node: 1's replicas move to 4.
    BOOST_REQUIRE(c.evacuate(1, {4}, 60s));
    for (group_id_type g = 1; g <= k_groups; ++g) {
        const auto d = c.membership(g);
        BOOST_REQUIRE(d.has_value());
        BOOST_TEST(d->has_voter(4));
        BOOST_TEST(!d->has_replica(1));
    }
    BOOST_TEST(c.host(4).lazily_created_replica_count() == k_groups);
    // The reverse: 4's replicas move back to 1.
    BOOST_REQUIRE(c.evacuate(4, {1}, 60s));
    for (group_id_type g = 1; g <= k_groups; ++g) {
        const auto d = c.membership(g);
        BOOST_REQUIRE(d.has_value());
        BOOST_TEST(d->has_voter(1));
        BOOST_TEST(!d->has_replica(4));
    }
    writing.store(false);
    w.join();
    BOOST_TEST_MESSAGE("acknowledged writes: " << acked.load());
    BOOST_REQUIRE(acked.load() > 0);
    BOOST_TEST(c.fewest_voters() >= 3U);

    // Every acknowledged write is on every voter, 1 included again.
    BOOST_REQUIRE(c.put("fence", "x"));
    BOOST_REQUIRE(c.put("apple", "x"));
    BOOST_REQUIRE(c.put("zebra", "x"));
    const auto applied = [&](node_id_t id) {
        for (int i = 0; i < acked.load(); ++i) {
            const auto k = key_of(i);
            if (c.get(id, k) != std::optional<std::string>{"v" + std::to_string(i)}) {
                BOOST_TEST_MESSAGE("host " << id << " lacks " << k << " in group "
                                           << cluster::group_of(k) << ": "
                                           << c.get(id, k).value_or("(none)"));
                return false;
            }
        }
        return true;
    };
    for (node_id_t id = 1; id <= 3; ++id) {
        const auto until = std::chrono::steady_clock::now() + 10s;
        while (!applied(id) && std::chrono::steady_clock::now() < until) {
            std::this_thread::sleep_for(50ms);
        }
        BOOST_TEST_INFO("host " << id);
        BOOST_TEST(applied(id));
    }
}

BOOST_AUTO_TEST_CASE(evacuating_to_two_targets_spreads_the_replicas,
                     *boost::unit_test::timeout(120)) {
    // Host 1 leaves; hosts 4 and one more already-full voter are named, but
    // only 4 is outside the groups, so every group goes to 4. A target
    // already in a group never takes a second replica.
    cluster c;
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (std::chrono::steady_clock::now() < deadline &&
           (c.leader_of(1) == nullptr || c.leader_of(2) == nullptr || c.leader_of(3) == nullptr)) {
        std::this_thread::sleep_for(20ms);
    }
    BOOST_REQUIRE(c.evacuate(1, {2, 4}, 60s));
    for (group_id_type g = 1; g <= k_groups; ++g) {
        const auto d = c.membership(g);
        BOOST_REQUIRE(d.has_value());
        BOOST_TEST(d->_voters.size() == 3U);
        BOOST_TEST(d->has_voter(2));
        BOOST_TEST(d->has_voter(4));
    }
}

BOOST_AUTO_TEST_SUITE_END()
