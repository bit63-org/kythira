// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Three kms_node processes (.kiro/specs/kms-compatible-api/ task 12):
// the daemon with mutual TLS between members, static authentication, and
// SoftHSM2 standing in for the HSM (one token directory, as members would
// share one HSM). AWS clients' signed JSON requests reach any member:
//
//   * a key created through any member is described by every member, so
//     a follower forwards the proposal to the catalog's leader and reads
//     behind a read barrier;
//   * a ciphertext made by one member decrypts on another;
//   * the peer paths answer only a verified certificate naming a member:
//     a client with no certificate, or with one the CA signed for someone
//     else, is refused with 403 before anything is proposed;
//   * a member the others cannot reach is not needed: with one member
//     stopped the other two still create keys, and the stopped member
//     catches up when it is back.
//   * boto3, the AWS CLI v2 and the AWS Encryption SDK work against the
//     cluster, their calls spread over its members (task 18,
//     clients/kms_clients.py).
//   * independent layers (.kiro/specs/kms-independent-layers/ task 3):
//     three data nodes and two front ends with gateways, where only the
//     front ends serve the API, hold the HSM PIN and run the jobs, and
//     only the data nodes serve the catalog.

#define BOOST_TEST_MODULE kms_node_cluster_test

#include "kms_process_cluster.hpp"

#include <chrono>
#include <cstdlib>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace kms_process_testing;  // NOLINT(google-build-using-namespace)

BOOST_FIXTURE_TEST_CASE(keys_made_through_any_member_are_seen_by_all, process_cluster) {
    for (std::size_t via = 0; via < 3; ++via) {
        const auto desc = "via member " + std::to_string(via + 1);
        const auto r = call(via, "CreateKey", R"({"Description":")" + desc + R"("})");
        BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
        const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
        for (std::size_t on = 0; on < 3; ++on) {
            const auto d = call(on, "DescribeKey", R"({"KeyId":")" + id + R"("})");
            BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
            BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() == desc);
        }
    }

    // A ciphertext made on one member decrypts on another.
    const auto k = call(1, "CreateKey", "{}");
    BOOST_REQUIRE(k.status == 200);
    const auto id = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto e = call(0, "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200, e.status << " " << e.str("__type"));
    const auto d = call(2, "Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.str("Plaintext") == "c2VjcmV0");

    // Task 14: the member that answered wrote the request's audit record
    // (on stderr by default), naming the key.
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    std::string record;
    while (record.empty() && std::chrono::steady_clock::now() < deadline) {
        const auto log = log_of(2);
        for (auto at = log.find(R"("eventName":"Decrypt")"); at != std::string::npos;
             at = log.find(R"("eventName":"Decrypt")", at + 1)) {
            const auto begin = log.rfind('\n', at);
            const auto end = log.find('\n', at);
            record = log.substr(begin == std::string::npos ? 0 : begin + 1,
                                end == std::string::npos ? std::string::npos : end - begin - 1);
        }
        if (record.empty()) {
            std::this_thread::sleep_for(50ms);
        }
    }
    BOOST_REQUIRE_MESSAGE(!record.empty(), "no Decrypt record in member 3's log");
    BOOST_TEST(record.find(R"("eventSource":"kms.amazonaws.com")") != std::string::npos);
    BOOST_TEST(record.find("key/" + id) != std::string::npos);
    BOOST_TEST(record.find("c2VjcmV0") == std::string::npos);
}

// Task 13: an AWS managed key made on first use through any member is one
// key, seen by all.
BOOST_FIXTURE_TEST_CASE(a_managed_key_is_made_once_through_any_member, process_cluster) {
    const auto first = call(1, "DescribeKey", R"({"KeyId":"alias/aws/kinesis"})");
    BOOST_REQUIRE_MESSAGE(first.status == 200, first.status << " " << first.str("__type"));
    const auto& md = first.body.at("KeyMetadata").as_object();
    BOOST_TEST(md.at("KeyManager").as_string() == "AWS");
    const auto id = std::string(md.at("KeyId").as_string());
    for (std::size_t on = 0; on < 3; ++on) {
        const auto d = call(on, "DescribeKey", R"({"KeyId":"alias/aws/kinesis"})");
        BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
        BOOST_TEST(d.body.at("KeyMetadata").as_object().at("KeyId").as_string() == id);
    }
    const auto keys = call(2, "ListKeys", "{}");
    BOOST_REQUIRE(keys.status == 200);
    BOOST_TEST(keys.body.at("Keys").as_array().size() == 1U);
}

// Task 18 (Requirement 14.2): boto3, the AWS CLI v2 and the AWS
// Encryption SDK against the cluster, spread over its members
// (clients/kms_clients.py). CI installs all three;
// KYTHIRA_KMS_CLIENTS_SKIP=cli (say) leaves one out on a machine without it.
BOOST_FIXTURE_TEST_CASE(aws_clients_work_against_the_cluster, process_cluster) {
    // Ready: the catalog has a leader that takes writes.
    BOOST_REQUIRE_EQUAL(call(0, "ListKeys", "{}").status, 200);
    std::string endpoints;
    for (std::size_t i = 0; i < 3; ++i) {
        endpoints += (i == 0 ? "" : ",") + api_url(i);
    }
    const char* skip = std::getenv("KYTHIRA_KMS_CLIENTS_SKIP");  // NOLINT(concurrency-mt-unsafe)
    const auto out = dir() / "clients.log";
    const auto command =
        std::string("AWS_ACCESS_KEY_ID=") + std::string(k_akid) +
        " AWS_SECRET_ACCESS_KEY=" + std::string(k_secret) +
        " AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null " + KYTHIRA_PYTHON3 +
        " " + KMS_CLIENTS_SCRIPT + " --endpoints " + endpoints + " --ca " + ca_path() +
        (skip != nullptr && *skip != '\0' ? " --skip " + std::string(skip) : std::string()) + " >" +
        out.string() + " 2>&1";
    const int rc = std::system(command.c_str());  // NOLINT(concurrency-mt-unsafe)
    BOOST_TEST_MESSAGE(slurp(out));
    BOOST_TEST(rc == 0, "the client suites failed:\n" << slurp(out));
}

// Task 18 (Requirement 14.3): the cases recorded against real AWS KMS
// (differential/recordings/) answer alike here: each error's type and
// status, each success's fields, apart from what allow.json lists. Needs
// boto3, as the client suites do.
BOOST_FIXTURE_TEST_CASE(differential_replay_matches_the_aws_recording, process_cluster) {
    BOOST_REQUIRE_EQUAL(call(0, "ListKeys", "{}").status, 200);
    const std::string dir_name = KMS_DIFFERENTIAL_DIR;
    const auto out = dir() / "differential.log";
    const auto command =
        std::string("AWS_ACCESS_KEY_ID=") + std::string(k_akid) +
        " AWS_SECRET_ACCESS_KEY=" + std::string(k_secret) +
        " AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null " + KYTHIRA_PYTHON3 +
        " " + dir_name + "/kms_differential.py compare --endpoint " + api_url(1) + " --ca " +
        ca_path() + " --recording " + dir_name + "/recordings/aws-us-east-1.json --allow " +
        dir_name + "/recordings/allow.json >" + out.string() + " 2>&1";
    const int rc = std::system(command.c_str());  // NOLINT(concurrency-mt-unsafe)
    BOOST_TEST_MESSAGE(slurp(out));
    BOOST_TEST(rc == 0, "the replay differs from AWS:\n" << slurp(out));
}

BOOST_FIXTURE_TEST_CASE(only_members_reach_the_peer_paths, process_cluster) {
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(peer(i, nullptr) == 403, "member " << i + 1 << ", no certificate");
        BOOST_TEST(peer(i, &stranger()) == 403, "member " << i + 1 << ", a stranger");
        BOOST_TEST(peer(i, &tls((i + 1) % 3)) == 200, "member " << i + 1 << ", a member");
    }
}

BOOST_FIXTURE_TEST_CASE(two_members_carry_on_without_the_third, process_cluster) {
    stop(2);
    const auto r = call(1, "CreateKey", R"({"Description":"while 3 was away"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
    const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    start(2);
    wait_serving(2);
    const auto d = call(2, "DescribeKey", R"({"KeyId":")" + id + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() ==
               "while 3 was away");
}

// kms-independent-layers task 2 (Requirements 5.1, 5.2 and 10.2): one
// member holds the job lease, whichever leads the catalog; a member that
// stops releases it and another takes it at its next pass, well before the
// lease would have expired.
BOOST_FIXTURE_TEST_CASE(one_member_runs_the_jobs_and_hands_them_over_on_stop, process_cluster) {
    const auto first = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(first.has_value(), "no single job lease holder");
    BOOST_TEST_MESSAGE("job lease holder: member " << *first + 1);
    stop(*first);
    const auto t0 = std::chrono::steady_clock::now();
    const auto second = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(second.has_value(), "the job lease was not taken over");
    BOOST_TEST(*second != *first);
    // Released, not expired: the default lease is 30 s.
    BOOST_TEST((std::chrono::steady_clock::now() - t0 < 20s));
    start(*first);
    wait_serving(*first);
    // The member that came back does not take the lease from the holder.
    std::this_thread::sleep_for(1s);
    const auto now = lease_holders();
    BOOST_TEST(now.size() == 1U);
    BOOST_TEST((now.size() == 1U && now[0] == *second));
}

// Task 14: the operator's key and alias limits reach every member's
// catalog, and AWS's quotas answer ThrottlingException.
BOOST_FIXTURE_TEST_CASE(account_limits_and_quotas_apply, process_cluster) {
    const auto k = call(0, "CreateKey", "{}");
    BOOST_REQUIRE_MESSAGE(k.status == 200, k.status << " " << k.str("__type"));
    const auto id = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto alias = [&](std::size_t on, int n) {
        return call(
            on, "CreateAlias",
            R"({"AliasName":"alias/a)" + std::to_string(n) + R"(","TargetKeyId":")" + id + R"("})");
    };
    // The leader writes the limit at a job pass (every 200 ms here).
    std::this_thread::sleep_for(3s);
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    int made = 0;
    std::string refused;
    while (refused.empty() && std::chrono::steady_clock::now() < deadline) {
        const auto r = alias(static_cast<std::size_t>(made) % 3, made);
        if (r.status == 200) {
            ++made;
        } else if (r.str("__type") == "ThrottlingException") {
            std::this_thread::sleep_for(1s);
        } else {
            refused = r.str("__type");
        }
    }
    BOOST_TEST(refused == "LimitExceededException");
    BOOST_TEST(made == 3);

    // DescribeKey's 2000 per second is far away; CreateKey's 5 is not.
    std::size_t throttled = 0;
    for (int i = 0; i < 20; ++i) {
        throttled += call(1, "CreateKey", "{}").str("__type") == "ThrottlingException" ? 1U : 0U;
    }
    BOOST_TEST(throttled > 0U);
    BOOST_TEST(call(1, "DescribeKey", R"({"KeyId":")" + id + R"("})").status == 200);
}

namespace {

/// kms-independent-layers task 3: three data nodes and two front ends
/// with gateways (members 4 and 5), none of them co-located.
struct split_cluster : process_cluster {
    split_cluster()
        : process_cluster({"data", "data", "data", "gateway,front_end", "gateway,front_end"}) {}
};

constexpr std::size_t k_front_end_a = 3;
constexpr std::size_t k_front_end_b = 4;

/// kms-independent-layers task 4: every layer apart. Three data nodes, two
/// front ends (members 4 and 5) and a gateway alone (member 6).
struct gateway_cluster : process_cluster {
    gateway_cluster()
        : process_cluster({"data", "data", "data", "front_end", "front_end", "gateway"}) {}
};

constexpr std::size_t k_gateway = 5;

/// Waits up to 15 s for member i's metric `name` to read `want`.
auto await_metric(const process_cluster& c, std::size_t i, std::string_view name, double want)
    -> bool {
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (c.metric(i, name) == want) {
            return true;
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

}  // namespace

// Requirements 2.1-2.3 and 3.3: front ends without a replica answer as
// co-located members do; only data nodes hold the catalog, and only front
// ends serve clients, hold the PIN and run the jobs.
BOOST_FIXTURE_TEST_CASE(front_ends_without_a_replica_serve_the_api, split_cluster) {
    const auto r = call(k_front_end_a, "CreateKey", R"({"Description":"split"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
    const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto d = call(k_front_end_b, "DescribeKey", R"({"KeyId":")" + id + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.body.at("KeyMetadata").as_object().at("Description").as_string() == "split");
    const auto e =
        call(k_front_end_a, "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200, e.status << " " << e.str("__type"));
    const auto p = call(k_front_end_b, "Decrypt",
                        R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(p.status == 200, p.status << " " << p.str("__type"));
    BOOST_TEST(p.str("Plaintext") == "c2VjcmV0");

    // Data nodes run no gateway; front ends hold no catalog.
    const std::string read_index(1, '\x01');  // catalog API version 1
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(call(i, "ListKeys", "{}").status == 404, "data node " << i + 1);
        BOOST_TEST(peer(i, &tls(k_front_end_a), "/v1/kms/catalog/read-index", read_index) == 200,
                   "data node " << i + 1 << ", a front end");
        BOOST_TEST(peer(i, &stranger(), "/v1/kms/catalog/read-index", read_index) == 403,
                   "data node " << i + 1 << ", a stranger");
    }
    for (const auto f : {k_front_end_a, k_front_end_b}) {
        BOOST_TEST(peer(f, &tls(0), "/v1/kms/catalog/read-index", read_index) == 404);
        BOOST_TEST(peer(f, &tls(0)) == 404);
        BOOST_TEST(log_of(f).find("roles=gateway,front_end data_nodes=3") != std::string::npos);
    }

    // The job lease goes to a front end; data nodes report no jobs, and
    // front ends no catalog leadership.
    const auto holder = await_one_lease_holder();
    BOOST_REQUIRE_MESSAGE(holder.has_value(), "no single job lease holder");
    BOOST_TEST(*holder >= k_front_end_a);
    for (std::size_t i = 0; i < 3; ++i) {
        BOOST_TEST(!metric(i, "job_lease_holder").has_value(), "data node " << i + 1);
        BOOST_TEST(metric(i, "leader").has_value(), "data node " << i + 1);
        BOOST_TEST(log_of(i).find("roles=data members=3") != std::string::npos);
        BOOST_TEST(log_of(i).find("pkcs11=") == std::string::npos);
    }
    BOOST_TEST(!metric(k_front_end_a, "leader").has_value());

    // A data node away: the front ends reach the other two.
    stop(0);
    const auto k = call(k_front_end_b, "CreateKey", R"({"Description":"while 1 was away"})");
    BOOST_REQUIRE_MESSAGE(k.status == 200, k.status << " " << k.str("__type"));
    const auto kid = std::string(k.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    BOOST_TEST(call(k_front_end_a, "DescribeKey", R"({"KeyId":")" + kid + R"("})").status == 200);
    start(0);
    wait_serving(0);
}

// Task 4, Requirements 6.1, 7 and 9: a gateway alone verifies signatures
// and hands each call to a front end on another node; only gateways may
// hand calls over; a front end away is skipped; the quotas are shared
// over the live front ends.
BOOST_FIXTURE_TEST_CASE(a_gateway_alone_hands_calls_to_front_ends, gateway_cluster) {
    const auto r = call(k_gateway, "CreateKey", R"({"Description":"through a gateway"})");
    BOOST_REQUIRE_MESSAGE(r.status == 200, r.status << " " << r.str("__type"));
    const auto id = std::string(r.body.at("KeyMetadata").as_object().at("KeyId").as_string());
    const auto e =
        call(k_gateway, "Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200, e.status << " " << e.str("__type"));
    // A front end without its own gateway serves no clients.
    BOOST_TEST(call(k_front_end_a, "ListKeys", "{}").status == 404);
    const auto d =
        call(k_gateway, "Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200, d.status << " " << d.str("__type"));
    BOOST_TEST(d.str("Plaintext") == "c2VjcmV0");

    // The gateway holds no PIN, no HSM client and no catalog.
    BOOST_TEST(log_of(k_gateway).find("roles=gateway data_nodes=3 front_ends=2") !=
               std::string::npos);
    BOOST_TEST(log_of(k_gateway).find("pkcs11=") == std::string::npos);
    BOOST_TEST(!metric(k_gateway, "job_lease_holder").has_value());
    BOOST_TEST(metric(k_gateway, "calls_handed_over").value_or(0) >= 3.0);

    // Only callers the front ends know may hand them calls; a node with no
    // front end says the call was not executed there.
    const std::string empty_call(1, '\x01');
    BOOST_TEST(peer(k_front_end_a, &stranger(), "/v1/kms/front-end/call", empty_call) == 403);
    BOOST_TEST(peer(k_front_end_a, nullptr, "/v1/kms/front-end/call", empty_call) == 403);
    BOOST_TEST(peer(0, &tls(k_gateway), "/v1/kms/front-end/call", empty_call) == 503);
    BOOST_TEST(peer(k_front_end_a, &tls(k_gateway), "/v1/kms/front-end/health") == 200);

    // Both front ends live: each holds half of the quotas.
    for (const auto f : {k_front_end_a, k_front_end_b}) {
        BOOST_TEST(await_metric(*this, f, "front_ends_live", 2.0), "front end " << f + 1);
        BOOST_TEST(await_metric(*this, f, "quota_share_members", 2.0), "front end " << f + 1);
    }

    // A front end away: the gateway hands calls to the other, which now
    // holds the whole quota.
    stop(k_front_end_a);
    for (int i = 0; i < 4; ++i) {
        const auto k = call(k_gateway, "DescribeKey", R"({"KeyId":")" + id + R"("})");
        BOOST_TEST(k.status == 200, i << ": " << k.status << " " << k.str("__type"));
    }
    BOOST_TEST(await_metric(*this, k_front_end_b, "front_ends_live", 1.0));
    BOOST_TEST(await_metric(*this, k_front_end_b, "quota_share_members", 1.0));
    start(k_front_end_a);
    wait_serving(k_front_end_a);
    BOOST_TEST(await_metric(*this, k_front_end_b, "front_ends_live", 2.0));
}
