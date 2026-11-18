// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The stateless layers' member list (include/raft/layer_membership.hpp,
// .kiro/specs/kinesis-independent-layers/ task 11, Requirements 10.1-10.3):
// the state machine's commands and snapshots, the configuration directory,
// and the layer membership group running as one Raft group with three
// voters and a learner, which keeps the member list across a failover.

#define BOOST_TEST_MODULE layer_membership_test

#include <boost/test/unit_test.hpp>

#include "multi_raft_test_fabric.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/layer_membership.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>

#if __has_include(<folly/init/Init.h>)
#include <folly/init/Init.h>
#define KYTHIRA_LAYER_MEMBERSHIP_FOLLY 1
#endif

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

#ifdef KYTHIRA_LAYER_MEMBERSHIP_FOLLY
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        static char name[] = "layer_membership_test";
        char* argv_storage[] = {name, nullptr};
        char** argv = argv_storage;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace kythira::layers {
inline auto operator<<(std::ostream& os, drain_state s) -> std::ostream& {
    return os << to_string(s);
}
}  // namespace kythira::layers

namespace {

namespace layers = kythira::layers;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;
using layers::drain_state;
using layers::layer_member;
using layers::role;
using layers::role_set;

auto member(std::string id, role_set roles, std::int64_t at = 1000) -> layer_member {
    layer_member m;
    m.id = id;
    m.roles = roles;
    m.address = id + ":7100";
    m.placement_group = "zone-a";
    m.announced_at_ms = at;
    m.reported_at_ms = at;
    return m;
}

// ---------------------------------------------------------------------------
// The group as a Raft group on a multi-raft host, as the capacity ledger's
// coordination group is run.
// ---------------------------------------------------------------------------

using membership_sm = layers::layer_membership_state_machine<std::uint64_t>;

struct membership_types {
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
    using state_machine_type = membership_sm;

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

using host_type = kythira::multi_raft<membership_types, std::string, std::uint64_t>;
using config_type = kythira::multi_raft_config<membership_types, std::string, std::uint64_t>;
using descriptor_type = host_type::descriptor_type;

constexpr std::uint64_t k_membership_group = 1;

auto make_host(message_fabric& fabric, std::uint64_t id) -> std::unique_ptr<host_type> {
    config_type cfg{
        .node_id = id,
        .network_client = fabric_client{fabric, id},
        .network_server = fabric_server{fabric, id},
        .store_factory =
            [](const std::uint64_t&) { return membership_types::persistence_engine_type{}; },
    };
    cfg.config._election_timeout_min = std::chrono::milliseconds{60};
    cfg.config._election_timeout_max = std::chrono::milliseconds{120};
    cfg.config._heartbeat_interval = std::chrono::milliseconds{15};
    cfg.hibernation = kythira::hibernation_mode::off;
    cfg.executor_stripes = 2;
    cfg.heartbeat_interval = std::chrono::milliseconds{0};
    return std::make_unique<host_type>(std::move(cfg));
}

/// The membership as the member on `host` sees it.
auto membership_on(host_type& host) -> layers::replicated_layer_membership {
    return layers::replicated_layer_membership{
        [&host](std::vector<std::byte> bytes) -> std::optional<std::vector<std::byte>> {
            try {
                const auto epoch = host.local_descriptor(k_membership_group)->_epoch;
                return host
                    .submit_command(k_membership_group, epoch, bytes, std::chrono::seconds{2})
                    .get();
            } catch (const std::exception&) {
                return std::nullopt;
            }
        },
        [&host] {
            auto* n = host.group_node(k_membership_group);
            if (n == nullptr) {
                return std::vector<layer_member>{};
            }
            return n->with_state_machine([](membership_sm& sm) { return sm.members(); });
        }};
}

template<typename Pred>
auto tick_until(const std::vector<host_type*>& hosts, Pred pred,
                std::chrono::milliseconds budget = std::chrono::milliseconds{8000}) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        for (auto* h : hosts) {
            h->tick();
        }
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return pred();
}

auto leader_index(const std::vector<host_type*>& hosts) -> std::optional<std::size_t> {
    std::optional<std::size_t> found;
    for (std::size_t i = 0; i < hosts.size(); ++i) {
        auto* n = hosts[i]->group_node(k_membership_group);
        if (n != nullptr && n->is_leader()) {
            if (found) {
                return std::nullopt;
            }
            found = i;
        }
    }
    return found;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(state)

BOOST_AUTO_TEST_CASE(members_announce_report_drain_and_leave) {
    layers::layer_membership_core core;
    using core_t = layers::layer_membership_core;
    BOOST_TEST(core.apply_command(core_t::encode_announce(member("fe-1", {role::front_end}))));
    BOOST_TEST(core.apply_command(core_t::encode_announce(member("gw-1", {role::gateway}))));
    BOOST_TEST(core.members().size() == 2U);

    layers::layer_load load{.requests_per_second = 120.5,
                            .open_streams = 3,
                            .cpu = 0.4,
                            .bytes_served_per_second = 1 << 20};
    BOOST_TEST(core.apply_command(core_t::encode_load("fe-1", load, 2000)));
    BOOST_TEST((core.find("fe-1")->load == load));
    // An older report arriving late is refused.
    BOOST_TEST(!core.apply_command(core_t::encode_load("fe-1", {}, 1500)));
    BOOST_TEST(core.find("fe-1")->reported_at_ms == 2000);
    // Reports for strangers are refused.
    BOOST_TEST(!core.apply_command(core_t::encode_load("nobody", load, 3000)));

    BOOST_TEST(core.apply_command(core_t::encode_drain("fe-1", drain_state::draining)));
    // A restart re-announces; the operator's drain survives it.
    BOOST_TEST(
        core.apply_command(core_t::encode_announce(member("fe-1", {role::front_end}, 5000))));
    BOOST_TEST(core.find("fe-1")->drain == drain_state::draining);
    BOOST_TEST(core.find("fe-1")->announced_at_ms == 5000);

    BOOST_TEST(core.apply_command(core_t::encode_leave("gw-1")));
    BOOST_TEST(!core.apply_command(core_t::encode_leave("gw-1")));
    BOOST_TEST(core.members().size() == 1U);
}

BOOST_AUTO_TEST_CASE(the_settings_version_only_moves_forward) {
    layers::layer_membership_core core;
    using core_t = layers::layer_membership_core;
    BOOST_TEST(core.apply_command(core_t::encode_settings(3)));
    BOOST_TEST(!core.apply_command(core_t::encode_settings(3)));
    BOOST_TEST(!core.apply_command(core_t::encode_settings(2)));
    BOOST_TEST(core.settings_version() == 3U);
}

BOOST_AUTO_TEST_CASE(malformed_commands_change_nothing) {
    layers::layer_membership_core core;
    auto bytes = [](std::string_view s) {
        std::vector<std::byte> out;
        for (const char c : s) {
            out.push_back(static_cast<std::byte>(c));
        }
        return out;
    };
    for (const auto* bad :
         {"", "not json", "[]", R"({"op":"explode"})", R"({"op":"leave"})",
          R"({"op":"drain","id":"x","state":9})", R"({"op":"announce","member":{"id":"x"}})"}) {
        BOOST_TEST_INFO(bad);
        BOOST_TEST(!core.apply_command(bytes(bad)));
    }
    auto no_roles = member("x", {});
    BOOST_TEST(!core.apply_command(layers::layer_membership_core::encode_announce(no_roles)));
    BOOST_TEST(core.members().empty());
}

BOOST_AUTO_TEST_CASE(a_snapshot_restores_the_same_state) {
    membership_sm a;
    a.apply(layers::layer_membership_core::encode_announce(member("fe-1", {role::front_end})), 1);
    a.apply(layers::layer_membership_core::encode_announce(
                member("gw-1", role_set{role::gateway, role::front_end})),
            2);
    a.apply(layers::layer_membership_core::encode_drain("gw-1", drain_state::drained), 3);
    a.apply(layers::layer_membership_core::encode_settings(7), 4);
    membership_sm b;
    b.restore_from_snapshot(a.get_state(), 4);
    BOOST_TEST((b.members() == a.members()));
    BOOST_TEST(b.settings_version() == 7U);
    BOOST_TEST(b.last_applied() == 4U);
    b.restore_from_snapshot({}, 0);
    BOOST_TEST(b.members().empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(directories)

BOOST_AUTO_TEST_CASE(configuration_lists_parse_and_every_entry_is_live) {
    const auto fes = layers::static_member_directory::parse(
        "KINESIS_FRONT_ENDS", "fe-1=front-1:7100,front-2:7100", {role::front_end});
    BOOST_REQUIRE(fes.size() == 2U);
    BOOST_TEST(fes[0].id == "fe-1");
    BOOST_TEST(fes[0].address == "front-1:7100");
    BOOST_TEST(fes[1].id == "front-2:7100");
    layers::static_member_directory dir(fes);
    BOOST_TEST(dir.live_members({role::front_end}, 1'000'000, 1).size() == 2U);
    BOOST_TEST(dir.live_members({role::gateway}, 0, 1).empty());

    BOOST_CHECK_THROW((void)layers::static_member_directory::parse("X", "a,,b", {role::data}),
                      std::invalid_argument);
    BOOST_CHECK_THROW(
        (void)layers::static_member_directory::parse("X", "a=h:1,a=h:2", {role::data}),
        std::invalid_argument);
    BOOST_CHECK_THROW((void)layers::static_member_directory::parse("X", "=h:1", {role::data}),
                      std::invalid_argument);
    BOOST_TEST(layers::static_member_directory::parse("X", "", {role::data}).empty());
}

BOOST_AUTO_TEST_CASE(live_members_skip_drained_and_stale_members_of_the_group) {
    membership_sm sm;
    std::uint64_t index = 0;
    layers::replicated_layer_membership dir(
        [&](std::vector<std::byte> b) -> std::optional<std::vector<std::byte>> {
            return sm.apply(b, ++index);
        },
        [&] { return sm.members(); });
    BOOST_TEST(dir.announce(member("fe-1", {role::front_end}, 1000)));
    BOOST_TEST(dir.announce(member("fe-2", {role::front_end}, 1000)));
    BOOST_TEST(dir.announce(member("fe-3", {role::front_end}, 1000)));
    BOOST_TEST(dir.report_load("fe-1", {}, 9000));
    BOOST_TEST(dir.report_load("fe-2", {}, 9500));
    BOOST_TEST(dir.set_drain("fe-2", drain_state::draining));
    // fe-3 last reported at 1000: stale at 10000 with a 5 s window.
    const auto live = dir.live_members({role::front_end}, 10'000, 5'000);
    BOOST_REQUIRE(live.size() == 1U);
    BOOST_TEST(live[0].id == "fe-1");
    BOOST_TEST(!dir.publish_settings_version(0));
    BOOST_TEST(dir.publish_settings_version(1));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(raft_group)

BOOST_AUTO_TEST_CASE(three_voters_and_a_learner_keep_the_list_across_a_failover,
                     *boost::unit_test::timeout(180)) {
    message_fabric fabric{4};
    std::vector<std::unique_ptr<host_type>> hosts;
    // Voters 1-3; host 4 joins as a learner, as every stateless node beyond
    // the fixed voters does.
    const descriptor_type group{._group_id = k_membership_group,
                                ._range = kythira::unbounded_shard_range<std::string>(),
                                ._epoch = {},
                                ._voters = {1, 2, 3},
                                ._learners = {4},
                                ._leader_hint = std::nullopt};
    for (std::uint64_t id = 1; id <= 4; ++id) {
        hosts.push_back(make_host(fabric, id));
        hosts.back()->create_group(group);
        hosts.back()->start();
    }
    std::vector<host_type*> all;
    for (auto& h : hosts) {
        all.push_back(h.get());
    }
    const std::vector<host_type*> voters{all[0], all[1], all[2]};
    BOOST_REQUIRE(tick_until(all, [&] { return leader_index(voters).has_value(); }));
    BOOST_TEST(!all[3]->group_node(k_membership_group)->is_leader());

    // Members announce through any host (the learner forwards to the
    // leader like any other member).
    auto learner_view = membership_on(*all[3]);
    const auto first = *leader_index(voters);
    auto leader_view = membership_on(*voters[first]);
    bool announced = false;
    BOOST_REQUIRE(tick_until(all, [&] {
        announced = announced || leader_view.announce(member("fe-1", {role::front_end}));
        return announced;
    }));
    BOOST_REQUIRE(tick_until(
        all, [&] { return leader_view.announce(member("gw-1", role_set{role::gateway})); }));
    BOOST_REQUIRE(
        tick_until(all, [&] { return leader_view.set_drain("gw-1", drain_state::draining); }));

    // The learner's replica catches up.
    BOOST_REQUIRE(tick_until(all, [&] { return learner_view.members().size() == 2U; }));
    BOOST_TEST(learner_view.live_members({role::front_end}, 1000, 10'000).size() == 1U);

    // The leader dies; a new one is elected among the voters and the list
    // is intact. The learner never becomes leader.
    fabric.kill(voters[first]->node_id());
    std::vector<host_type*> survivors;
    for (std::size_t i = 0; i < voters.size(); ++i) {
        if (i != first) {
            survivors.push_back(voters[i]);
        }
    }
    std::vector<host_type*> alive = survivors;
    alive.push_back(all[3]);
    BOOST_REQUIRE(tick_until(alive, [&] { return leader_index(survivors).has_value(); }));
    BOOST_TEST(!all[3]->group_node(k_membership_group)->is_leader());
    auto next_view = membership_on(*survivors[*leader_index(survivors)]);
    BOOST_TEST(next_view.members().size() == 2U);
    BOOST_REQUIRE(
        tick_until(alive, [&] { return next_view.announce(member("fe-2", {role::front_end})); }));
    BOOST_REQUIRE(tick_until(alive, [&] { return learner_view.members().size() == 3U; }));

    for (auto& h : hosts) {
        h->stop();
    }
}

BOOST_AUTO_TEST_SUITE_END()
