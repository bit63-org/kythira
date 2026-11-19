// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file multi_raft_group_quorum_loop_test.cpp
/// @brief A `multi_raft` group's own quorum loop never acts on a silent voter.
///
/// Every group's `node` runs the single-group quorum loop against
/// `no_op_quorum_manager`, with one unbounded placement target so that a
/// placement driver's learner → promote sequence passes the capacity check.
/// The design relies on that loop never acting: membership is the placement
/// driver's job and capacity is `elastic_capacity_controller`'s, once per host.
///
/// `no_op_quorum_manager` always reports `healthy`, but the leader's process
/// liveness rule (`quorum_peer_dead_after`, raft-consensus Req 13.7) demotes a
/// voter that has been silent for the window to unreachable on its own. Against
/// the unbounded target that turned a group `critical` 30 s after any voter
/// went quiet, and the loop then, on every assessment, in every group:
///
/// - promoted any learner it found in the group to voter, behind the
///   placement driver's back; and
/// - called `provision_node`, which `no_op_quorum_manager` always fails,
///   logging `provision_node failed` at error level each time.
///
/// The tests below use a short window and interval, so the bug shows in
/// well under a second.

#define BOOST_TEST_MODULE multi_raft_group_quorum_loop_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>
#include <raft/test_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("multi_raft_group_quorum_loop_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using kythira::hibernation_mode;
using kythira::multi_raft;
using kythira::multi_raft_config;
using kythira::shard_descriptor;
using kythira::shard_epoch;
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

constexpr std::size_t k_host_count = 4;
constexpr group_id_type k_group = 1;
constexpr node_id_t k_learner = 4;

/// One group: voters on hosts 1-3, a learner on host 4.
auto the_group() -> descriptor_type {
    return descriptor_type{._group_id = k_group,
                           ._range = kythira::unbounded_shard_range<key_type>(),
                           ._epoch = shard_epoch{},
                           ._voters = {1, 2, 3},
                           ._learners = {k_learner},
                           ._leader_hint = std::nullopt};
}

/// Four hosts, each ticked by its own thread as `chaos_node` drives a node.
class cluster {
public:
    explicit cluster(kythira::raft_configuration raft_cfg) : _raft_cfg(std::move(raft_cfg)) {
        for (node_id_t id = 1; id <= k_host_count; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id)));
            _hosts.back()->create_group(the_group());
        }
        for (auto& h : _hosts) {
            h->start();
        }
        _running = true;
        for (std::size_t i = 0; i < _hosts.size(); ++i) {
            _drivers.emplace_back([this, i] { drive(i); });
        }
    }

    ~cluster() {
        _running = false;
        for (auto& t : _drivers) {
            if (t.joinable()) {
                t.join();
            }
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }

    [[nodiscard]] auto leader() -> node_id_t {
        for (node_id_t id = 1; id <= k_host_count; ++id) {
            auto* n = host(id).group_node(k_group);
            if (n != nullptr && n->is_leader()) {
                return id;
            }
        }
        return 0;
    }

    auto await_leader(std::chrono::milliseconds budget) -> node_id_t {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            if (auto id = leader(); id != 0) {
                return id;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return 0;
    }

    /// @brief Whether `id` is still a learner in the configuration the group
    ///        runs under on host `on`.
    [[nodiscard]] auto is_learner(node_id_t id, node_id_t on) -> bool {
        auto* n = host(on).group_node(k_group);
        if (n == nullptr) {
            return false;
        }
        const auto m = n->current_membership();
        return std::ranges::find(m.learners, id) != m.learners.end() &&
               std::ranges::find(m.voters, id) == m.voters.end();
    }

    /// @brief The voter's process dies: its driver stops and the fabric drops
    ///        everything to and from it. Its host is left constructed, as a
    ///        VM a cloud manager would still list as running.
    auto kill(node_id_t id) -> void {
        _paused[id - 1] = true;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!_idle[id - 1].load() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        _fabric.kill(id);
    }

private:
    auto make_config(node_id_t id) -> config_type {
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory =
                [](const group_id_type&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config = _raft_cfg;
        cfg.hibernation = hibernation_mode::off;
        cfg.executor_stripes = 2;
        return cfg;
    }

    auto drive(std::size_t index) -> void {
        while (_running.load()) {
            if (_paused[index].load()) {
                _idle[index] = true;
            } else {
                _idle[index] = false;
                _hosts[index]->tick();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        _idle[index] = true;
    }

    kythira::raft_configuration _raft_cfg;
    message_fabric _fabric{8};
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
    std::array<std::atomic<bool>, k_host_count> _paused{};
    std::array<std::atomic<bool>, k_host_count> _idle{};
};

/// Fast protocol timings, and a liveness window and assessment interval short
/// enough that a group leader would act on a silent voter within ~0.3 s.
auto fast_config() -> kythira::raft_configuration {
    kythira::raft_configuration cfg;
    cfg._election_timeout_min = std::chrono::milliseconds{120};
    cfg._election_timeout_max = std::chrono::milliseconds{260};
    cfg._heartbeat_interval = std::chrono::milliseconds{25};
    cfg._quorum_check_interval = std::chrono::milliseconds{50};
    cfg._quorum_peer_dead_after = std::chrono::milliseconds{200};
    return cfg;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(multi_raft_group_quorum_loop)

// A silent voter must not get a group's learner promoted: only the placement
// driver changes a group's membership. The unfixed loop promoted host 4 about
// 0.25 s after host 3 went quiet; the check waits eight windows.
BOOST_AUTO_TEST_CASE(a_silent_voter_does_not_promote_the_groups_learner,
                     *boost::unit_test::timeout(120)) {
    cluster c{fast_config()};
    auto leader = c.await_leader(std::chrono::seconds{20});
    BOOST_REQUIRE(leader != 0);
    BOOST_REQUIRE(c.is_learner(k_learner, leader));

    // Kill a voter other than the leader, so the group keeps its leader (and
    // its quorum loop) throughout.
    const node_id_t victim = leader == 3 ? 2 : 3;
    c.kill(victim);

    std::this_thread::sleep_for(std::chrono::milliseconds{1600});
    BOOST_REQUIRE_EQUAL(c.leader(), leader);
    BOOST_CHECK_MESSAGE(c.is_learner(k_learner, leader),
                        "the group's quorum loop promoted the learner on host "
                            << k_learner << " after voter " << victim << " went silent");
}

BOOST_AUTO_TEST_SUITE_END()
