// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The HSM's store over multi_raft (.kiro/specs/virtual-hsm/ task 6c):
// three members on the in-process message fabric, each with its own
// engine, vault and session layer. Every member votes in the catalog and
// in every token group. A PKCS#11 call may reach any member: one that
// does not lead the group forwards its proposals and read-index rounds to
// the leader, so a key generated through one follower signs on another,
// and a destroy on one member stops the key's use on every other. A
// member cut off from the leader answers CKR_DEVICE_ERROR, never a stale
// result.

#define BOOST_TEST_MODULE hsm_host_test
#include <boost/test/unit_test.hpp>

#include "hsm_raft_cluster.hpp"

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("hsm_host_test"), nullptr};
        char** argv = argv_data;
        init_ = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> init_;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

namespace hsm = kythira::hsm;
using hsm::raft_test::cluster;
using hsm::raft_test::group_sm;
using hsm::raft_test::k_members;
using hsm::raft_test::k_token;
using hsm::raft_test::rv;
using kythira::memory_kv_engine;

}  // namespace

BOOST_AUTO_TEST_CASE(ranges_name_the_catalog_and_each_token) {
    BOOST_TEST(group_sm::catalog_range().start == "c/");
    BOOST_TEST(group_sm::token_range(7).start == "t/7/");
    BOOST_TEST(hsm::token_id_of_range(group_sm::token_range(42)).value_or(0) == 42U);
    BOOST_TEST(!hsm::token_id_of_range(group_sm::catalog_range()).has_value());
    // Leading zeros, zero and junk are not token ranges.
    for (const auto* start : {"t/07/", "t/0/", "t/x/", "t//", "t/1"}) {
        BOOST_TEST(!hsm::token_id_of_range(kythira::key_range{start, std::nullopt}).has_value());
    }
    // Decimal namespaces are prefix-free, so neighbouring ranges are disjoint.
    const auto one = group_sm::token_range(1);
    const auto ten = group_sm::token_range(10);
    BOOST_TEST((ten.start >= *one.end || *ten.end <= one.start));
    group_sm sm;
    memory_kv_engine engine;
    BOOST_CHECK_THROW(sm.open(engine, kythira::key_range{"x/", std::string("x0")}),
                      std::invalid_argument);
    BOOST_TEST(!sm.can_split_at("t/1/a"));
    BOOST_TEST(sm.suggest_split_keys(4).empty());
}

BOOST_AUTO_TEST_CASE(catalog_and_token_groups_reach_every_member) {
    cluster c;
    c.initialize();
    // The initialize went through a follower, so it was forwarded.
    std::uint64_t forwarded = 0;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        forwarded += c.at(id).host->stats().proposals_forwarded;
        BOOST_TEST(c.at(id).host->hosts(k_token));
        BOOST_TEST(c.at(id).host->token(k_token).has_value());
        BOOST_TEST(c.at(id).host->may_open("app-a", k_token));
    }
    BOOST_TEST(forwarded > 0U);
    BOOST_TEST(c.at(1).host->stats().groups_created >= 1U);
}

BOOST_AUTO_TEST_CASE(a_key_generated_through_one_follower_signs_on_another) {
    cluster c;
    c.initialize();
    const auto a = c.follower_of(k_token);
    const auto b = c.follower_of(k_token, a);
    BOOST_REQUIRE(a != b);
    auto& ma = c.at(a);
    auto& mb = c.at(b);
    const auto sa = cluster::user_session(ma);
    const auto [pub, priv] = cluster::ec_pair(ma, sa);
    const auto sb = cluster::user_session(mb);
    // Member b may not have applied the key yet; its read barrier waits.
    const auto sig = cluster::sign(mb, sb, priv, "hello");
    BOOST_REQUIRE(sig.has_value());
    BOOST_TEST(cluster::verify(ma, sa, pub, "hello", *sig) == CKR_OK);
    BOOST_TEST(mb.host->stats().read_indexes_forwarded > 0U);
    const auto leader = c.leader_of(k_token);
    BOOST_REQUIRE(leader.has_value());
    BOOST_TEST(c.at(*leader).host->stats().read_indexes_served > 0U);
}

BOOST_AUTO_TEST_CASE(a_destroy_on_one_member_stops_use_on_every_other) {
    cluster c;
    c.initialize();
    const auto a = c.follower_of(k_token);
    // Logins are per application and token, so one session per member.
    std::vector<CK_SESSION_HANDLE> sessions;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        sessions.push_back(cluster::user_session(c.at(id)));
    }
    auto& ma = c.at(a);
    const auto sa = sessions.at(a - 1);
    const auto [pub, priv] = cluster::ec_pair(ma, sa);
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        BOOST_REQUIRE(cluster::sign(c.at(id), sessions.at(id - 1), priv, "before").has_value());
    }
    BOOST_REQUIRE(rv(ma.client->destroy_object(sa, priv)) == CKR_OK);
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        BOOST_TEST(rv(cluster::sign(c.at(id), sessions.at(id - 1), priv, "after")) ==
                   CKR_KEY_HANDLE_INVALID);
    }
}

BOOST_AUTO_TEST_CASE(a_member_cut_off_from_the_leader_answers_device_error) {
    cluster c;
    c.initialize();
    const auto f = c.follower_of(k_token);
    auto& m = c.at(f);
    const auto s = cluster::user_session(m);
    const auto [pub, priv] = cluster::ec_pair(m, s);
    BOOST_REQUIRE(cluster::sign(m, s, priv, "connected").has_value());
    c.isolate(f);
    BOOST_TEST(rv(cluster::sign(m, s, priv, "alone")) == CKR_DEVICE_ERROR);
    // The other two still have a quorum and keep serving.
    auto& other = c.at(f % k_members + 1);
    const auto so = cluster::user_session(other);
    BOOST_TEST(cluster::sign(other, so, priv, "quorum").has_value());
    c.heal();
    BOOST_TEST(cluster::await([&] { return cluster::sign(m, s, priv, "healed").has_value(); }));
}

BOOST_AUTO_TEST_CASE(a_new_leader_keeps_the_token_writable) {
    cluster c;
    c.initialize();
    std::optional<std::uint64_t> old;
    BOOST_REQUIRE(cluster::await([&] { return (old = c.leader_of(k_token)).has_value(); }));
    c.isolate(*old);
    std::optional<std::uint64_t> fresh;
    BOOST_REQUIRE(cluster::await([&] { return (fresh = c.leader_of(k_token, *old)).has_value(); }));
    std::uint64_t survivor = 0;
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        if (id != *old && id != *fresh) {
            survivor = id;
        }
    }
    auto& m = c.at(survivor);
    const auto s = cluster::user_session(m);
    const auto [pub, priv] = cluster::ec_pair(m, s);
    const auto sig = cluster::sign(m, s, priv, "after the election");
    BOOST_REQUIRE(sig.has_value());
    c.heal();
    auto& back = c.at(*old);
    const auto sb = cluster::user_session(back);
    BOOST_TEST(cluster::verify(back, sb, pub, "after the election", *sig) == CKR_OK);
}

BOOST_AUTO_TEST_CASE(deleted_tokens_lose_their_groups_and_ids_are_not_reused) {
    cluster c;
    c.initialize();
    auto& m = c.at(c.follower_of(0));
    constexpr std::uint64_t k_second = 2;
    c.add_token(m, k_second, "beta");
    BOOST_REQUIRE(cluster::propose_catalog(m, hsm::make_delete_token_command(k_second)) == CKR_OK);
    for (std::uint64_t id = 1; id <= k_members; ++id) {
        auto& each = c.at(id);
        BOOST_TEST(cluster::await([&] {
            return !each.host->hosts(k_second) &&
                   !each.raft->has_group(each.host->host_group(k_second));
        }));
        BOOST_TEST(each.host->hosts(k_token));
    }
    BOOST_TEST(m.host->stats().groups_destroyed >= 1U);
    hsm::secret_bytes mk(32);
    BOOST_REQUIRE(hsm::generate_random(mk.span()).has_value());
    // Any create with that id is refused, whatever its contents.
    const auto again = hsm::prepare_token(mk.view(), 1, k_second, "beta again");
    BOOST_TEST(cluster::propose_catalog(m, hsm::make_create_token_command(again.entry)) ==
               CKR_FUNCTION_REJECTED);
}
