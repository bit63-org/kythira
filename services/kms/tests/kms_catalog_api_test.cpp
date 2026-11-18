// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/kms-independent-layers/ task 3 (Requirements 3.1, 3.3,
// 4.1-4.3 and 9.2): the data layer's catalog API and the remote catalog
// access a front end without a replica uses. Every query answers what the
// replica does; a query is answered only by a data node that has applied
// past the caller's last read-index point or write; data nodes fail over;
// an unreachable data layer is KMSInternalException and never an absent
// key; and only front ends and data nodes may call.
//
// The fixture runs in the split layout here, as the *_split runs of the
// API suites do.

#define BOOST_TEST_MODULE kms_catalog_api_test

#include "kms_api_fixture.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

const bool k_split = (split_layout() = true);

/// A mixed catalog: aliases, a grant, tags, rotation, a pending deletion,
/// account limits and the job lease.
auto populate(fixture& f) -> std::vector<std::string> {
    const auto a = f.create(R"({"Description":"a","Tags":[{"TagKey":"t","TagValue":"1"}]})");
    const auto b = f.create(R"({"Description":"b"})");
    const auto c = f.create(R"({"Description":"c"})");
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/a","TargetKeyId":")" + a + R"("})").status ==
        200U);
    BOOST_REQUIRE(f.call("EnableKeyRotation", kid(b)).status == 200U);
    BOOST_REQUIRE(f.call("RotateKeyOnDemand", kid(b)).status == 200U);
    BOOST_REQUIRE(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + c + R"(","PendingWindowInDays":7})")
            .status == 200U);
    kms::grant_record g;
    g.grant_id = "g1";
    g.key_id = a;
    g.grantee_principal = "arn:aws:iam::111122223333:role/r";
    g.issuing_account = std::string(k_account);
    g.operations = {"Decrypt", "Encrypt"};
    g.constraint = kms::grant_constraint::context_subset;
    g.constraint_context = {{"purpose", "test"}};
    g.created_ms = 7;
    BOOST_REQUIRE((f.propose(kms::make_create_grant_command(g)) == kms::catalog_status::ok));
    BOOST_REQUIRE((f.propose(kms::make_set_account_limits_command(
                       std::string(k_account), {9, 8})) == kms::catalog_status::ok));
    BOOST_REQUIRE((f.propose(kms::make_acquire_lease_command("fe-1", f.now, 30'000)) ==
                   kms::catalog_status::ok));
    return {a, b, c, "00000000-0000-4000-8000-000000000000"};
}

/// A transport over data nodes whose answers the test controls.
struct data_layer {
    std::map<std::string, std::optional<kms::catalog_server_deps>> nodes;  // nullopt: unreachable
    std::vector<std::string> asked;
    bool allowed = true;

    auto transport() -> kms::catalog_transport {
        return [this](std::string_view url, std::string_view target,
                      std::string body) -> std::optional<std::pair<unsigned, std::string>> {
            asked.emplace_back(url);
            const auto& n = nodes.at(std::string(url));
            if (!n) {
                return std::nullopt;
            }
            const auto a = kms::serve_catalog(*n, allowed, "POST", target, body);
            BOOST_REQUIRE(a.has_value());
            return std::make_pair(a->status, a->body);
        };
    }
};

}  // namespace

// Requirement 3.3: through the data layer, every query answers what the
// replica does.
BOOST_AUTO_TEST_CASE(every_query_answers_what_the_replica_does) {
    fixture f;
    const auto ids = populate(f);
    BOOST_REQUIRE(f.access.barrier());
    const auto r = f.access.reader();
    const auto& sm = f.sm;
    for (const auto now : {f.now, f.now + (400 * kms::k_ms_per_day)}) {
        for (const auto account : {k_account, k_other}) {
            BOOST_TEST((r->keys(account) == sm.keys(account)));
            BOOST_TEST((r->keys(account, ids[0], 1) == sm.keys(account, ids[0], 1)));
            BOOST_TEST((r->aliases(account) == sm.aliases(account)));
            BOOST_TEST((r->alias(account, "alias/a") == sm.alias(account, "alias/a")));
            BOOST_TEST((r->counts(account) == sm.counts(account)));
            BOOST_TEST((r->limits(account) == sm.limits(account)));
            for (const auto& id : ids) {
                BOOST_TEST((r->aliases(account, id) == sm.aliases(account, id)));
            }
        }
        for (const auto& id : ids) {
            BOOST_TEST_CONTEXT(id) {
                BOOST_TEST((r->key(id) == sm.key(id)));
                BOOST_TEST(r->tombstoned(id) == sm.tombstoned(id));
                BOOST_TEST((r->versions(id) == sm.versions(id)));
                BOOST_TEST((r->version(id, 1) == sm.version(id, 1)));
                BOOST_TEST((r->version(id, 2) == sm.version(id, 2)));
                BOOST_TEST((r->tags(id) == sm.tags(id)));
                BOOST_TEST((r->grants(id) == sm.grants(id)));
                BOOST_TEST((r->grant(id, "g1") == sm.grant(id, "g1")));
            }
        }
        BOOST_TEST((r->lease() == sm.lease()));
        BOOST_TEST((r->creating_keys() == sm.creating_keys()));
        BOOST_TEST((r->due_deletions(now) == sm.due_deletions(now)));
        BOOST_TEST((r->due_rotations(now) == sm.due_rotations(now)));
    }
    BOOST_TEST(r->grant(ids[0], "g1")->constraint_context.at("purpose") == "test");
}

// Requirement 4.1: queries are answered only at or past the caller's
// read-index point or last write, by any data node that has got there.
BOOST_AUTO_TEST_CASE(queries_wait_for_the_read_index_point_on_any_data_node) {
    fixture f;
    const auto id = f.create();
    std::uint64_t lagging_applied = 0;  // a follower behind the leader
    const auto node = [&](bool lagging) {
        auto d = f.data_node;
        if (lagging) {
            d.wait_applied = [&](std::uint64_t i) { return i <= lagging_applied; };
            d.applied_index = [&] { return lagging_applied; };
        }
        return d;
    };
    data_layer dl;
    dl.nodes = {{"https://lag", node(true)}, {"https://cur", node(false)}};
    kms::remote_catalog_access access({"https://lag", "https://cur"}, dl.transport());
    const auto r = access.reader();

    // Before any barrier, the lagging node may answer (index 0).
    BOOST_TEST(r->key(id).has_value() == f.sm.key(id).has_value());
    BOOST_TEST(dl.asked.back() == "https://lag");

    // After a barrier at the leader's index, the lagging node declines and
    // the current one answers; later queries start from it.
    BOOST_REQUIRE(access.barrier());
    BOOST_TEST(access.min_index() == f.index);
    dl.asked.clear();
    BOOST_TEST(r->key(id)->key_id == id);
    BOOST_TEST((dl.asked == std::vector<std::string>{"https://lag", "https://cur"}));

    // Once the follower catches up it may answer again.
    lagging_applied = f.index;
    dl.nodes["https://cur"] = std::nullopt;  // the current node goes away
    dl.asked.clear();
    BOOST_TEST(r->key(id)->key_id == id);
    BOOST_TEST((dl.asked == std::vector<std::string>{"https://cur", "https://lag"}));

    // A write raises the point to the index it applied at (read your
    // writes), so the follower, now one behind, no longer answers.
    dl.nodes["https://cur"] = node(false);
    dl.nodes["https://lag"] = std::nullopt;
    const auto before = access.min_index();
    BOOST_TEST((access.propose(kms::make_update_description_command(id, "new")) ==
                kms::catalog_status::ok));
    BOOST_TEST(access.min_index() == before + 1);
    dl.nodes["https://lag"] = node(true);
    dl.asked.clear();
    BOOST_TEST(r->key(id)->description == "new");
    BOOST_TEST((dl.asked == std::vector<std::string>{"https://cur"}));
}

// Requirement 4.3: with no data node able to answer, the barrier fails,
// queries throw kms_catalog_unreachable, and proposals throw; handlers
// answer KMSInternalException or DependencyTimeoutException, never
// NotFoundException.
BOOST_AUTO_TEST_CASE(an_unreachable_data_layer_fails_requests_and_is_never_not_found) {
    fixture f;
    const auto id = f.create();
    const auto enc = f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGVsbG8="})");
    BOOST_REQUIRE(enc.status == 200U);

    f.data_layer_down = true;
    BOOST_TEST(!f.access.barrier());
    BOOST_CHECK_THROW(std::ignore = f.access.reader()->key(id), kms::kms_catalog_unreachable);
    BOOST_CHECK_THROW(std::ignore = f.access.propose(kms::make_set_enabled_command(id, false)),
                      kms::kms_catalog_unreachable);
    for (const auto& [op, body] : std::vector<std::pair<std::string, std::string>>{
             {"DescribeKey", kid(id)},
             {"DescribeKey", kid("alias/none")},
             {"Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGVsbG8="})"},
             {"Decrypt", R"({"CiphertextBlob":")" + enc.str("CiphertextBlob") + R"("})"},
             {"DisableKey", kid(id)},
         }) {
        const auto r = f.call(op, body);
        BOOST_TEST(r.status >= 500U, op);
        BOOST_TEST((r.type() == "KMSInternalException" || r.type() == "DependencyTimeoutException"),
                   op << ": " << r.type());
    }

    // A leaderless catalog behind reachable data nodes: the same.
    f.data_layer_down = false;
    f.leaderless = true;
    BOOST_TEST(!f.access.barrier());
    BOOST_TEST(f.call("DescribeKey", kid(id)).status >= 500U);
    f.leaderless = false;
    BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
}

// Requirement 9.2 and the request's own faults.
BOOST_AUTO_TEST_CASE(only_front_ends_and_data_nodes_call_and_bad_requests_are_400) {
    fixture f;
    const auto& d = f.data_node;
    BOOST_TEST(!kms::serve_catalog(d, true, "POST", "/", "").has_value());
    BOOST_TEST(!kms::serve_catalog(d, true, "POST", "/v1/kms/peer/propose", "").has_value());
    BOOST_TEST(kms::serve_catalog(d, false, "POST", kms::catalog_read_index_path, "")->status ==
               403U);
    BOOST_TEST(kms::serve_catalog(d, true, "GET", kms::catalog_read_index_path, "")->status ==
               400U);
    BOOST_TEST(kms::serve_catalog(d, true, "POST", "/v1/kms/catalog/other", "")->status == 400U);
    BOOST_TEST(kms::serve_catalog(d, true, "POST", kms::catalog_query_path, "")->status == 400U);
    BOOST_TEST(kms::serve_catalog(d, true, "POST", kms::catalog_query_path,
                                  std::string("\x09\0\0\0\0\0\0\0\0\x01", 10))
                   ->status == 400U);  // unknown version
    BOOST_TEST(kms::serve_catalog(d, true, "POST", kms::catalog_query_path,
                                  std::string("\x01\0\0\0\0\0\0\0\0\x63", 10))
                   ->status == 400U);  // unknown query
    BOOST_TEST(kms::serve_catalog(d, true, "POST", kms::catalog_propose_path, "\x01")->status ==
               400U);

    // A refused caller fails over to no one; a 400 is not retried
    // elsewhere and surfaces as the caller's bug.
    data_layer dl;
    dl.nodes = {{"https://a", f.data_node}, {"https://b", f.data_node}};
    dl.allowed = false;
    kms::remote_catalog_access access({"https://a", "https://b"}, dl.transport());
    BOOST_TEST(!access.barrier());
    BOOST_TEST(dl.asked.size() == 2U);
    dl.allowed = true;
    dl.asked.clear();
    BOOST_CHECK_THROW(std::ignore = access.propose({std::byte{1}}), std::invalid_argument);
    BOOST_TEST(dl.asked.size() == 1U);

    BOOST_CHECK_THROW(kms::remote_catalog_access({}, dl.transport()), std::invalid_argument);
    BOOST_CHECK_THROW(kms::remote_catalog_access({"https://a"}, {}), std::invalid_argument);
}

// The jobs in the split layout (Requirement 5.1): a front end's lease
// holder reads due work and fences its steps through the data layer.
BOOST_AUTO_TEST_CASE(the_jobs_run_on_a_front_end_through_the_data_layer) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":7})")
            .status == 200U);
    BOOST_REQUIRE((f.access.propose(kms::make_acquire_lease_command("fe-1", f.now, 30'000)) ==
                   kms::catalog_status::ok));
    BOOST_REQUIRE(f.access.barrier());
    const auto token = f.access.reader()->lease().token;
    const auto reader = f.access.reader();
    kms::key_jobs<reader_t> jobs{*reader, *f.hsm,
                                 [&f, token](const std::vector<std::byte>& c) {
                                     return f.access.propose(kms::make_fenced_command(token, c));
                                 },
                                 [&f] { return f.now; }, std::chrono::minutes(5)};
    f.now += 8 * kms::k_ms_per_day;
    const auto r = jobs.run_once();
    BOOST_TEST(r.deleted == 1U);
    BOOST_TEST(r.failures == 0U);
    BOOST_TEST(f.sm.tombstoned(id));
}
