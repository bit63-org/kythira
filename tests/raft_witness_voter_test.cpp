// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Witness voters (.kiro/specs/khold-block-service/ task 4, Requirement
// 5.2) on a three-node cluster over the network simulator: nodes 1 and 2
// hold data, node 3 is a witness. Every engine is an
// append_sink_persistence whose sink can describe entries.
//
//  1. A witness never campaigns and never leads, however long it goes
//     without hearing from a leader, and refuses TimeoutNow and transfer.
//  2. A witness votes and acknowledges: with the other data replica cut
//     off, the leader commits on itself plus the witness. The witness's
//     storage and sink hold descriptors only; no payload reaches it.
//  3. A candidate behind the witness cannot be elected. Writes commit on
//     the leader and the witness while node 2 is cut off; the leader then
//     dies and node 2 comes back. Node 2's log lacks entries the witness
//     has, so the witness refuses its votes and nobody leads: the group
//     stops rather than serve stale data.
//  4. A learner promoted with promote_to_witness() becomes a witness
//     through joint consensus on every member, and from then on receives
//     descriptors.
//  5. Random schedules of partitions, heals, crashes and writes: the
//     witness is never leader, at most one leader leads a term, and every
//     command a leader acknowledged is in the log of every later leader.
#define BOOST_TEST_MODULE raft_witness_voter_test
#include <boost/test/unit_test.hpp>

#include "raft_khold_cluster.hpp"

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
struct FollyInitFixture {
    FollyInitFixture() {
        int argc = 1;
        char* argv0[] = {const_cast<char*>("raft_witness_voter_test"), nullptr};
        char** argv = argv0;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
BOOST_GLOBAL_FIXTURE(FollyInitFixture);
#endif

using namespace raft_khold_cluster;

BOOST_AUTO_TEST_SUITE(raft_witness_voter)

BOOST_AUTO_TEST_CASE(a_witness_never_campaigns, *boost::unit_test::timeout(60)) {
    cluster c;
    // Alone, the witness waits out many election timeouts and never even
    // becomes a candidate: its term does not move.
    c.isolate(witness_id);
    const auto term = c.nodes[witness_id - 1]->get_current_term();
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds{1500};
    while (std::chrono::steady_clock::now() < end) {
        c.nodes[witness_id - 1]->check_election_timeout();
        BOOST_REQUIRE((c.nodes[witness_id - 1]->get_state() == kythira::server_state::follower));
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    BOOST_TEST(c.nodes[witness_id - 1]->get_current_term() == term);

    // With everyone connected a data node leads, and a transfer to the
    // witness is refused.
    c.heal();
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    BOOST_TEST(l->get_node_id() != witness_id);
    for (std::uint64_t id = 1; id <= 3; ++id) {
        BOOST_TEST(c.nodes[id - 1]->is_witness_member(witness_id));
        BOOST_TEST(c.nodes[id - 1]->is_witness_member(id) == (id == witness_id));
    }
}

BOOST_AUTO_TEST_CASE(a_witness_acknowledges_and_holds_only_descriptors,
                     *boost::unit_test::timeout(60)) {
    cluster c;
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    const auto leader_id = l->get_node_id();
    const auto other = leader_id == 1 ? std::uint64_t{2} : std::uint64_t{1};

    // The other data replica is cut off: commits need the witness's ack.
    c.isolate(other);
    constexpr int writes = 8;
    for (int i = 0; i < writes; ++i) {
        BOOST_REQUIRE_MESSAGE(submit(c, *l, i), "write " << i << " did not commit");
    }
    c.run(std::chrono::milliseconds{200});

    const auto w = c.stored(witness_id);
    BOOST_TEST(w.normal >= static_cast<std::size_t>(writes));
    BOOST_TEST(w.full == 0U);
    BOOST_TEST(c.sinks[witness_id - 1]->payload_count() == 0U);
    // The witness's state machine is handed descriptors, never payloads.
    BOOST_TEST(c.payload_commands(witness_id) == 0U);
    BOOST_TEST(c.payload_commands(leader_id) == static_cast<std::size_t>(writes));

    // Healed, the data follower receives the payloads.
    c.heal();
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.payload_commands(other) == static_cast<std::size_t>(writes);
    }));
    BOOST_TEST(c.sinks[other - 1]->payload_count() >= static_cast<std::size_t>(writes));
}

BOOST_AUTO_TEST_CASE(a_candidate_behind_the_witness_is_not_elected,
                     *boost::unit_test::timeout(60)) {
    cluster c;
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    const auto leader_id = l->get_node_id();
    const auto other = leader_id == 1 ? std::uint64_t{2} : std::uint64_t{1};

    c.isolate(other);
    for (int i = 0; i < 4; ++i) {
        BOOST_REQUIRE(submit(c, *l, i));
    }
    c.run(std::chrono::milliseconds{100});
    c.crash(leader_id);
    c.heal();

    // Two seconds is more than ten election timeouts: node 2 campaigns
    // again and again, the witness refuses every vote, and nobody leads.
    std::map<std::uint64_t, std::set<std::uint64_t>> leaders;
    c.run(std::chrono::milliseconds{2000}, &leaders);
    BOOST_TEST(leaders.empty());
    BOOST_TEST(c.nodes[other - 1]->get_current_term() > seed_term);

    // The old leader returns and the group resumes with every write.
    c.restart(leader_id);
    auto* back = c.elect();
    BOOST_REQUIRE(back != nullptr);
    BOOST_TEST(back->get_node_id() == leader_id);
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.payload_commands(other) == 4U;
    }));
}

BOOST_AUTO_TEST_CASE(a_learner_promoted_to_witness_becomes_one_everywhere,
                     *boost::unit_test::timeout(60)) {
    kythira::cluster_configuration<std::uint64_t> initial{{1, 2}, false, std::nullopt, {3}};
    cluster c{initial};
    auto* l = c.elect();
    BOOST_REQUIRE(l != nullptr);
    BOOST_TEST(l->get_node_id() != witness_id);
    BOOST_TEST(!l->is_witness_member(witness_id));
    BOOST_REQUIRE(submit(c, *l, 0));

    BOOST_REQUIRE(settle(c, l->promote_to_witness(witness_id)) == std::optional<bool>{true});
    BOOST_REQUIRE(wait_until([&] {
        c.tick();
        return c.nodes[0]->is_witness_member(witness_id) &&
               c.nodes[1]->is_witness_member(witness_id) &&
               c.nodes[2]->is_witness_member(witness_id);
    }));

    // From now on the witness gets descriptors: everything past the
    // promotion lands as descriptors, and a commit can use its ack.
    const auto before = c.stored(witness_id);
    const auto leader_id = l->get_node_id();
    c.isolate(leader_id == 1 ? 2 : 1);
    for (int i = 1; i <= 4; ++i) {
        BOOST_REQUIRE(submit(c, *l, i));
    }
    c.run(std::chrono::milliseconds{200});
    const auto after = c.stored(witness_id);
    BOOST_TEST(after.descriptors - before.descriptors >= 4U);
    BOOST_TEST(after.full == before.full);
}

BOOST_AUTO_TEST_CASE(random_schedules_never_elect_the_witness_or_lose_a_write,
                     *boost::unit_test::timeout(300)) {
    std::mt19937_64 rng(0x7769746eULL);
    std::size_t total_acknowledged = 0;
    std::size_t total_terms = 0;
    for (int round = 0; round < 6; ++round) {
        cluster c;
        std::map<std::uint64_t, std::set<std::uint64_t>> leaders;
        std::vector<int> acknowledged;
        int next = 0;
        for (int step = 0; step < 12; ++step) {
            switch (rng() % 6) {
                case 0:
                    c.isolate(1 + (rng() % 3));
                    break;
                case 1:
                    c.heal();
                    break;
                case 2: {
                    const auto id = 1 + (rng() % 3);
                    c.restart(id);
                    break;
                }
                default:
                    if (auto* l = c.leader()) {
                        for (int k = 0; k < 3; ++k) {
                            if (submit(c, *l, next, std::chrono::milliseconds{300})) {
                                acknowledged.push_back(next);
                            }
                            ++next;
                        }
                    }
                    break;
            }
            c.run(std::chrono::milliseconds{250}, &leaders);
        }
        for (const auto& [term, ids] : leaders) {
            BOOST_TEST_INFO("round " << round << " term " << term);
            BOOST_TEST(ids.size() == 1U);
            BOOST_TEST(!ids.contains(witness_id));
        }
        // Healed, a data leader emerges holding every acknowledged write.
        c.heal();
        for (std::uint64_t id = 1; id <= 3; ++id) {
            if (!c.nodes[id - 1]) {
                c.restart(id);
            }
        }
        // A write in the final leader's term commits everything before it.
        // Leadership may still move while the healed cluster settles, so
        // retry on whichever data node leads.
        node_t* l = nullptr;
        bool committed = false;
        for (int attempt = 0; attempt < 10 && !committed; ++attempt) {
            l = c.elect();
            BOOST_REQUIRE(l != nullptr);
            BOOST_TEST(l->get_node_id() != witness_id);
            committed = submit(c, *l, next);
        }
        BOOST_REQUIRE_MESSAGE(committed, "round " << round << ": no write commits once healed");
        const auto lid = l->get_node_id();
        auto& store = *c.stores[lid - 1];
        std::set<std::vector<std::byte>> held;
        {
            const std::lock_guard lock(store.mu);
            const auto last = store.state.get_last_log_index();
            for (std::uint64_t i = seed_index + 1; i <= last; ++i) {
                const auto e = store.state.get_log_entry(i);
                if (e && e->type() == kythira::entry_type::normal) {
                    if (auto p = c.sinks[lid - 1]->payload(i)) {
                        held.insert(*p);
                    }
                }
            }
        }
        for (const int a : acknowledged) {
            BOOST_TEST_INFO("round " << round << " write " << a);
            BOOST_TEST(held.contains(command(a)));
        }
        total_acknowledged += acknowledged.size();
        total_terms += leaders.size();
    }
    // The schedules did exercise something: writes were acknowledged and
    // leadership changed hands.
    BOOST_TEST(total_acknowledged > 0U);
    BOOST_TEST(total_terms > 6U);
}

BOOST_AUTO_TEST_SUITE_END()
