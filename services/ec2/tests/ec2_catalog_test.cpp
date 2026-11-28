// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The EC2 catalog group (`.kiro/specs/ec2-compatible-api/` task 4,
// Requirements 4.1-4.3): the command codec, ID blocks, VNIs and MACs, the
// ClientToken index, and two property tests: IDs are never reused across
// leader changes (state rebuilt from a snapshot plus the log tail) and
// group splits, and a retried token returns the original result.

#define BOOST_TEST_MODULE ec2_catalog_test
#include <boost/test/unit_test.hpp>

#include <kythira/ec2/ec2_catalog.hpp>

#include <cstdint>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace ec2 = kythira::ec2;
namespace e = kythira::aws_ec2;

namespace {

/// A replicated log over catalog state machines: every command goes into
/// the log, and a "leader change" rebuilds the leader from the last
/// snapshot plus the log tail, as a new leader's state machine would be.
struct cluster {
    ec2::catalog_config config;
    std::vector<std::vector<std::byte>> log{};
    std::vector<std::byte> snapshot{};
    std::uint64_t snapshot_index = 0;
    ec2::catalog_state_machine leader{config};

    auto run(const ec2::catalog_command& c) -> ec2::catalog_result {
        log.push_back(ec2::encode_command(c));
        return ec2::decode_result(leader.apply(log.back(), log.size()));
    }

    void take_snapshot() {
        snapshot = leader.get_state();
        snapshot_index = log.size();
    }

    void change_leader() {
        ec2::catalog_state_machine fresh{config};
        if (!snapshot.empty()) {
            fresh.restore_from_snapshot(snapshot, snapshot_index);
        }
        for (auto i = snapshot_index; i < log.size(); ++i) {
            (void)fresh.apply(log[i], i + 1);
        }
        BOOST_REQUIRE(fresh.get_state() == leader.get_state());
        leader = std::move(fresh);
    }
};

auto token(std::string t, std::string fp, std::string result, std::int64_t now,
           std::int64_t retention = 86'400'000) -> ec2::record_token_command {
    return {"111122223333", "RunInstances", std::move(t), std::move(fp), std::move(result), now,
            retention};
}

}  // namespace

BOOST_AUTO_TEST_CASE(commands_round_trip_and_junk_is_invalid) {
    const std::vector<ec2::catalog_command> all = {
        ec2::allocate_ids_command{ec2::id_kind::subnet, 64},
        ec2::allocate_vni_command{},
        ec2::allocate_mac_command{},
        token("t", "fp", "<r/>", 5),
        ec2::expire_tokens_command{9},
    };
    for (const auto& c : all) {
        const auto bytes = ec2::encode_command(c);
        BOOST_TEST((ec2::encode_command(ec2::decode_command(bytes)) == bytes));
    }
    ec2::catalog_state_machine sm;
    const std::vector<std::byte> junk = {std::byte{9}, std::byte{0}};
    BOOST_TEST((ec2::decode_result(sm.apply(junk, 1))._status == ec2::catalog_status::invalid));
    auto bad_kind = ec2::encode_command(ec2::allocate_ids_command{ec2::id_kind::vpc, 1});
    bad_kind[2] = std::byte{200};
    BOOST_TEST((ec2::decode_result(sm.apply(bad_kind, 2))._status == ec2::catalog_status::invalid));
}

BOOST_AUTO_TEST_CASE(prefixes_are_ec2s) {
    BOOST_TEST(ec2::id_prefix(ec2::id_kind::instance) == "i-");
    BOOST_TEST(ec2::id_prefix(ec2::id_kind::network_interface) == "eni-");
    BOOST_TEST(ec2::id_prefix(ec2::id_kind::route_table_association) == "rtbassoc-");
    BOOST_TEST(ec2::id_prefix(ec2::id_kind::subnet_cidr_association) == "subnet-cidr-assoc-");
}

BOOST_AUTO_TEST_CASE(blocks_are_disjoint_per_kind) {
    cluster c;
    const auto a = c.run(ec2::allocate_ids_command{ec2::id_kind::instance, 10});
    const auto b = c.run(ec2::allocate_ids_command{ec2::id_kind::instance, 5});
    const auto v = c.run(ec2::allocate_ids_command{ec2::id_kind::volume, 3});
    BOOST_TEST(a._first == 1U);
    BOOST_TEST(a._end == 11U);
    BOOST_TEST(b._first == 11U);
    BOOST_TEST(v._first == 1U);  // kinds count separately: vol-…1 and i-…1 differ
    BOOST_TEST((c.run(ec2::allocate_ids_command{ec2::id_kind::instance, 0})._status ==
                ec2::catalog_status::invalid));
    BOOST_TEST((c.run(ec2::allocate_ids_command{ec2::id_kind::instance, 1U << 21U})._status ==
                ec2::catalog_status::invalid));
    ec2::id_block blk{a._first, a._end};
    std::set<std::uint64_t> seen;
    while (auto id = blk.take()) {
        seen.insert(*id);
    }
    BOOST_TEST(seen.size() == 10U);
    BOOST_TEST(!blk.take().has_value());
}

BOOST_AUTO_TEST_CASE(vnis_and_macs_never_wrap) {
    ec2::catalog_config cfg;
    cfg._first_vni = ec2::k_max_vni - 1;
    cfg._mac_counter_bits = 24;
    cluster c{cfg};
    c.leader = ec2::catalog_state_machine{cfg};
    BOOST_TEST(c.run(ec2::allocate_vni_command{})._first == ec2::k_max_vni - 1);
    BOOST_TEST(c.run(ec2::allocate_vni_command{})._first == ec2::k_max_vni);
    BOOST_TEST((c.run(ec2::allocate_vni_command{})._status == ec2::catalog_status::exhausted));
    const auto mac = c.run(ec2::allocate_mac_command{});
    BOOST_TEST(c.leader.mac_text(mac._first) == "02:4b:59:00:00:01");
    BOOST_TEST(c.run(ec2::allocate_mac_command{})._first == mac._first + 1);
}

BOOST_AUTO_TEST_CASE(ids_are_never_reused_across_leader_changes_and_splits) {
    // Property (Requirement 4.1): groups take blocks, split (the new side
    // takes its own block, the old side keeps what it had), the catalog's
    // leader changes and snapshots at random, and no ID is ever handed out
    // twice.
    std::mt19937_64 rng(0xEC2'4);
    for (int round = 0; round < 20; ++round) {
        cluster c;
        std::vector<ec2::id_block> groups(1);
        std::set<std::uint64_t> handed;
        for (int step = 0; step < 400; ++step) {
            switch (rng() % 8) {
                case 0:
                    c.change_leader();
                    break;
                case 1:
                    c.take_snapshot();
                    break;
                case 2: {
                    // Split: the new group starts with a fresh block.
                    const auto r =
                        c.run(ec2::allocate_ids_command{ec2::id_kind::volume, 1 + rng() % 16});
                    groups.push_back({r._first, r._end});
                    break;
                }
                default: {
                    auto& g = groups[rng() % groups.size()];
                    auto id = g.take();
                    if (!id) {
                        const auto r =
                            c.run(ec2::allocate_ids_command{ec2::id_kind::volume, 1 + rng() % 16});
                        BOOST_REQUIRE((r._status == ec2::catalog_status::ok));
                        g = {r._first, r._end};
                        id = g.take();
                    }
                    BOOST_REQUIRE(handed.insert(*id).second);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(a_retried_token_returns_the_original_result) {
    // Property (Requirement 4.3): whatever leader changes fall between the
    // first request and its retries, the same token and parameters get the
    // first result, other parameters get mismatch.
    std::mt19937_64 rng(0x7043'4);
    cluster c;
    std::map<std::string, std::pair<std::string, std::string>> first;  // token -> (fp, result)
    for (int step = 0; step < 600; ++step) {
        const auto t = "tok-" + std::to_string(rng() % 40);
        const auto fp = "fp-" + std::to_string(rng() % 3);
        const auto result = "<instancesSet>" + std::to_string(step) + "</instancesSet>";
        if (rng() % 10 == 0) {
            c.change_leader();
        }
        if (rng() % 15 == 0) {
            c.take_snapshot();
        }
        const auto r = c.run(token(t, fp, result, 1000 + step));
        const auto it = first.find(t);
        if (it == first.end()) {
            BOOST_TEST((r._status == ec2::catalog_status::ok));
            BOOST_TEST(r._result == result);
            first.emplace(t, std::pair{fp, result});
        } else if (it->second.first == fp) {
            BOOST_TEST((r._status == ec2::catalog_status::duplicate));
            BOOST_TEST(r._result == it->second.second);
        } else {
            BOOST_TEST((r._status == ec2::catalog_status::mismatch));
        }
    }
}

BOOST_AUTO_TEST_CASE(tokens_expire_and_are_scoped) {
    cluster c;
    BOOST_TEST((c.run(token("a", "fp", "r1", 0, 100))._status == ec2::catalog_status::ok));
    BOOST_TEST(c.leader.find_token("111122223333", "RunInstances", "a", 50) != nullptr);
    BOOST_TEST(c.leader.find_token("111122223333", "RunInstances", "a", 100) == nullptr);
    // Another account or operation is another token.
    auto other = token("a", "fp2", "r2", 10);
    other._account = "444455556666";
    BOOST_TEST((c.run(other)._status == ec2::catalog_status::ok));
    other._operation = "CreateVolume";
    BOOST_TEST((c.run(other)._status == ec2::catalog_status::ok));
    // Past its retention the token is new again, with any parameters.
    BOOST_TEST((c.run(token("a", "fp-new", "r3", 150))._status == ec2::catalog_status::ok));
    BOOST_TEST(c.run(ec2::expire_tokens_command{10'000'000'000})._expired == 3U);
    BOOST_TEST(c.leader.token_count() == 0U);
    BOOST_TEST((c.run(token("a", "fp", "r", 0, 0))._status == ec2::catalog_status::invalid));
}

BOOST_AUTO_TEST_CASE(fingerprints_ignore_order_token_and_dry_run) {
    const auto a = e::params::parse("ImageId=ami-1&MinCount=1&MaxCount=1&ClientToken=x").value();
    const auto b =
        e::params::parse("MaxCount=1&DryRun=false&ImageId=ami-1&MinCount=1&ClientToken=y").value();
    const auto c = e::params::parse("ImageId=ami-1&MinCount=1&MaxCount=2").value();
    BOOST_TEST(ec2::request_fingerprint("RunInstances", a) ==
               ec2::request_fingerprint("RunInstances", b));
    BOOST_TEST(ec2::request_fingerprint("RunInstances", a) !=
               ec2::request_fingerprint("RunInstances", c));
    BOOST_TEST(ec2::request_fingerprint("RunInstances", a) !=
               ec2::request_fingerprint("CreateVolume", a));
    BOOST_TEST(ec2::request_fingerprint("RunInstances", a).size() == 64U);
}

BOOST_AUTO_TEST_CASE(client_tokens_are_checked) {
    BOOST_TEST(!ec2::check_client_token("550e8400-e29b-41d4-a716-446655440000").has_value());
    BOOST_TEST(ec2::check_client_token("").has_value());
    BOOST_TEST(ec2::check_client_token(std::string(65, 'a')).has_value());
    BOOST_TEST(ec2::check_client_token("caf\xc3\xa9").has_value());
    BOOST_TEST(ec2::idempotent_parameter_mismatch().code == "IdempotentParameterMismatch");
}

BOOST_AUTO_TEST_CASE(a_snapshot_restores_everything) {
    cluster c;
    (void)c.run(ec2::allocate_ids_command{ec2::id_kind::image, 7});
    (void)c.run(ec2::allocate_vni_command{});
    (void)c.run(ec2::allocate_mac_command{});
    (void)c.run(token("t", "f", "r", 1));
    ec2::catalog_state_machine copy;
    copy.restore_from_snapshot(c.leader.get_state(), 4);
    BOOST_TEST(copy.next_id(ec2::id_kind::image) == 8U);
    BOOST_TEST(copy.next_vni() == c.leader.next_vni());
    BOOST_TEST(copy.token_count() == 1U);
    BOOST_TEST(copy.last_applied_index() == 4U);
    BOOST_TEST((copy.get_state() == c.leader.get_state()));
    auto broken = c.leader.get_state();
    broken.pop_back();
    BOOST_CHECK_THROW(copy.restore_from_snapshot(broken, 5), ec2::ec2_codec_error);
    BOOST_TEST(copy.token_count() == 1U);  // unchanged by the failed restore
}
