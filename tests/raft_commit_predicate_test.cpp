// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Commit predicates (.kiro/specs/khold-block-service/ task 5,
// Requirements 7.1-7.3, 7.5, 7.6) on khold's general group shape: nodes
// 1 and 2 hold data, node 3 is a witness, over the network simulator.
//
//  1. Under all_in_sync a write is acknowledged only once every data
//     replica holds it.
//  2. A data follower that stops acknowledging pauses writes for the
//     member deadline; the leader then records it lagging through a
//     configuration entry, which commits on the leader and the witness
//     and carries the paused write with it. Writes then go on without it.
//     Once it returns and catches up it is recorded in sync, and writes
//     need it again.
//     A write before the marker never commits until the marker does.
//  3. Losing the witness never pauses writes, and records nobody lagging.
//  4. The `majority` option commits on a majority (with at least one data
//     replica) without waiting for the other data replica.
//  5. Random schedules of partitions, crashes and writes: at the moment a
//     write is acknowledged, every data replica holds it unless the
//     acknowledging leader records that replica as lagging, and every
//     acknowledged write survives into the final leader.
#define BOOST_TEST_MODULE raft_commit_predicate_test
#include <boost/test/unit_test.hpp>

#include "raft_khold_cluster.hpp"

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
struct FollyInitFixture {
    FollyInitFixture() {
        int argc = 1;
        char* argv0[] = {const_cast<char*>("raft_commit_predicate_test"), nullptr};
        char** argv = argv0;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
BOOST_GLOBAL_FIXTURE(FollyInitFixture);
#endif

using namespace raft_khold_cluster;

namespace {

constexpr auto member_deadline = std::chrono::milliseconds{300};

auto with_rule(kythira::commit_rule rule, std::chrono::milliseconds deadline = member_deadline) {
    return [rule, deadline](kythira::raft_configuration& cfg) {
        cfg._commit_rule = rule;
        cfg._member_deadline = deadline;
    };
}

auto all_in_sync() {
    return with_rule(kythira::commit_rule::all_in_sync);
}

// The data node that is not `leader`.
auto other_data(const node_t& leader) -> std::uint64_t {
    return leader.get_node_id() == 1 ? 2 : 1;
}

auto is_lagging(const node_t& n, std::uint64_t id) -> bool {
    const auto lagging = n.lagging_members();
    return std::ranges::find(lagging, id) != lagging.end();
}

// Elects a data leader and commits one write in its term, so every member
// has caught up before the case starts.
auto settle(cluster& c, int& next) -> node_t* {
    for (int attempt = 0; attempt < 10; ++attempt) {
        auto* l = c.elect();
        BOOST_REQUIRE(l != nullptr);
        if (submit(c, *l, next++)) {
            return l;
        }
    }
    BOOST_FAIL("no write commits on a healthy cluster");
    return nullptr;
}

// Submits command `i` and returns how long it took to commit, or nothing.
auto timed_submit(cluster& c, node_t& leader, int i,
                  std::chrono::milliseconds timeout = std::chrono::milliseconds{3000})
    -> std::optional<std::chrono::milliseconds> {
    const auto start = std::chrono::steady_clock::now();
    if (!submit(c, leader, i, timeout)) {
        return std::nullopt;
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 start);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(raft_commit_predicate)

BOOST_AUTO_TEST_CASE(a_write_is_acknowledged_on_every_data_replica,
                     *boost::unit_test::timeout(60)) {
    cluster c{cluster::default_config(), all_in_sync()};
    int next = 0;
    auto* l = settle(c, next);
    const auto follower = other_data(*l);
    for (int k = 0; k < 10; ++k) {
        const int i = next++;
        BOOST_REQUIRE(submit(c, *l, i));
        // At the moment of acknowledgement, not eventually.
        BOOST_TEST(c.sinks[l->get_node_id() - 1]->holds(command(i)));
        BOOST_TEST(c.sinks[follower - 1]->holds(command(i)));
        // The witness acknowledges too, but never holds a payload.
        BOOST_TEST(!c.sinks[witness_id - 1]->holds(command(i)));
    }
    BOOST_TEST(l->lagging_members().empty());
}

BOOST_AUTO_TEST_CASE(a_stalled_data_replica_is_recorded_lagging_then_in_sync,
                     *boost::unit_test::timeout(120)) {
    cluster c{cluster::default_config(), all_in_sync()};
    int next = 0;
    auto* l = settle(c, next);
    const auto follower = other_data(*l);
    c.isolate(follower);

    // The first write waits out the member deadline, then commits together
    // with the lagging marker the leader appended after it.
    const int paused = next++;
    const auto pause = timed_submit(c, *l, paused);
    BOOST_REQUIRE(pause.has_value());
    BOOST_TEST(pause->count() >= member_deadline.count() - 20);
    BOOST_TEST(is_lagging(*l, follower));
    BOOST_TEST(!c.sinks[follower - 1]->holds(command(paused)));
    // Requirement 7.2: the marker committed before the write was
    // acknowledged without the follower, so the witness, the only other
    // member up, already holds it at the moment of acknowledgement.
    BOOST_TEST(
        (c.nodes[witness_id - 1]->lagging_members() == std::vector<std::uint64_t>{follower}));

    // From then on writes commit on the leader and the witness, promptly.
    for (int k = 0; k < 5; ++k) {
        const auto t = timed_submit(c, *l, next++);
        BOOST_REQUIRE(t.has_value());
        BOOST_TEST(t->count() < member_deadline.count());
    }

    // Back and caught up, the follower is recorded in sync. Its higher term
    // may unseat the leader on the way; whichever data node leads ends up
    // recording it in sync once it holds every committed write.
    c.heal();
    node_t* now_leading = nullptr;
    BOOST_REQUIRE(wait_until(
        [&] {
            c.tick();
            now_leading = c.leader();
            return now_leading != nullptr && !is_lagging(*now_leading, follower) &&
                   c.sinks[follower - 1]->holds(command(paused));
        },
        std::chrono::milliseconds{10000}));
    BOOST_TEST(now_leading->get_node_id() != witness_id);

    // And writes need it again: acknowledged only once both data replicas
    // hold them.
    l = settle(c, next);
    for (int k = 0; k < 5; ++k) {
        const int i = next++;
        BOOST_REQUIRE(submit(c, *l, i));
        BOOST_TEST(c.sinks[0]->holds(command(i)));
        BOOST_TEST(c.sinks[1]->holds(command(i)));
    }
    BOOST_TEST(l->lagging_members().empty());
}

BOOST_AUTO_TEST_CASE(a_write_waits_for_its_lagging_marker_to_commit,
                     *boost::unit_test::timeout(60)) {
    // The marker relaxes the rule only from its own index on. Here the
    // follower is cut off, the write reaches the witness, and then the
    // witness is cut off too before the deadline: the leader appends the
    // marker but nobody else can hold it, so the write, which a majority
    // holds, must still not commit. It commits once the marker can.
    cluster c{cluster::default_config(), all_in_sync()};
    int next = 0;
    auto* l = settle(c, next);
    const auto lid = l->get_node_id();
    c.isolate(other_data(*l));
    auto f = l->submit_command(command(next++), std::chrono::milliseconds{5000});
    c.run(member_deadline / 3);
    BOOST_REQUIRE(!f.isReady());
    c.link(lid, witness_id, false);
    c.run(member_deadline * 2);
    BOOST_TEST(is_lagging(*l, other_data(*l)));                      // appended...
    BOOST_TEST(c.nodes[witness_id - 1]->lagging_members().empty());  // ...not replicated
    BOOST_TEST(!f.isReady());
    c.link(lid, witness_id, true);
    BOOST_TEST(wait_until([&] {
        c.tick();
        return f.isReady();
    }));
}

BOOST_AUTO_TEST_CASE(losing_the_witness_never_pauses_writes, *boost::unit_test::timeout(60)) {
    cluster c{cluster::default_config(), all_in_sync()};
    int next = 0;
    auto* l = settle(c, next);
    c.isolate(witness_id);
    for (int k = 0; k < 10; ++k) {
        const auto t = timed_submit(c, *l, next++);
        BOOST_REQUIRE(t.has_value());
        BOOST_TEST(t->count() < member_deadline.count());
    }
    c.run(member_deadline * 2);
    BOOST_TEST(l->lagging_members().empty());
}

BOOST_AUTO_TEST_CASE(the_majority_option_does_not_wait_for_the_other_data_replica,
                     *boost::unit_test::timeout(60)) {
    cluster c{cluster::default_config(), with_rule(kythira::commit_rule::majority)};
    int next = 0;
    auto* l = settle(c, next);
    c.isolate(other_data(*l));
    for (int k = 0; k < 10; ++k) {
        const auto t = timed_submit(c, *l, next++);
        BOOST_REQUIRE(t.has_value());
        BOOST_TEST(t->count() < member_deadline.count());
    }
    c.run(member_deadline * 2);
    // Nothing to record: majority never needs the member.
    BOOST_TEST(l->lagging_members().empty());
}

BOOST_AUTO_TEST_CASE(random_schedules_acknowledge_only_on_every_in_sync_data_replica,
                     *boost::unit_test::timeout(300)) {
    std::mt19937_64 rng(0x6c616767ULL);
    std::size_t total_acknowledged = 0;
    std::size_t total_markers = 0;
    for (int round = 0; round < 6; ++round) {
        cluster c{cluster::default_config(),
                  with_rule(kythira::commit_rule::all_in_sync, std::chrono::milliseconds{150})};
        std::vector<int> acknowledged;
        int next = 0;
        for (int step = 0; step < 14; ++step) {
            switch (rng() % 6) {
                case 0:
                    c.isolate(1 + (rng() % 3));
                    break;
                case 1:
                    c.heal();
                    break;
                case 2:
                    c.restart(1 + (rng() % 3));
                    break;
                default:
                    if (auto* l = c.leader()) {
                        for (int k = 0; k < 3; ++k) {
                            const int i = next++;
                            if (!submit(c, *l, i, std::chrono::milliseconds{500})) {
                                continue;
                            }
                            acknowledged.push_back(i);
                            // Requirement 7.1 at the moment of
                            // acknowledgement: every data replica holds the
                            // write, or the leader has it recorded lagging.
                            for (const std::uint64_t d : {1U, 2U}) {
                                BOOST_TEST_INFO("round " << round << " write " << i
                                                         << " data replica " << d);
                                BOOST_TEST(
                                    (c.sinks[d - 1]->holds(command(i)) || is_lagging(*l, d)));
                            }
                            total_markers += l->lagging_members().size();
                        }
                    }
                    break;
            }
            c.run(std::chrono::milliseconds{250});
        }
        // Healed, a data leader emerges holding every acknowledged write.
        c.heal();
        for (std::uint64_t id = 1; id <= 3; ++id) {
            if (!c.nodes[id - 1]) {
                c.restart(id);
            }
        }
        node_t* l = nullptr;
        bool committed = false;
        for (int attempt = 0; attempt < 10 && !committed; ++attempt) {
            l = c.elect();
            BOOST_REQUIRE(l != nullptr);
            committed = submit(c, *l, next++);
        }
        BOOST_REQUIRE_MESSAGE(committed, "round " << round << ": no write commits once healed");
        for (const int a : acknowledged) {
            BOOST_TEST_INFO("round " << round << " write " << a);
            BOOST_TEST(c.sinks[l->get_node_id() - 1]->holds(command(a)));
        }
        total_acknowledged += acknowledged.size();
    }
    // The schedules exercised both paths: writes were acknowledged, and
    // some while a replica was recorded lagging.
    BOOST_TEST(total_acknowledged > 0U);
    BOOST_TEST(total_markers > 0U);
}

BOOST_AUTO_TEST_SUITE_END()
