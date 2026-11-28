// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Kinesis and DynamoDB on the KMS's layers (.kiro/specs/
// kms-independent-layers/ task 5, Requirements 8.1 and 8.2), as processes.
// The KMS's catalog runs on three kms_node data nodes; beside them:
//
//   * member 4, a kms_node gateway and front end: the "remote" front end;
//   * member 5, a kythira_node running Kinesis, DynamoDB and a KMS front
//     end of its own, whose catalog is the data nodes'. Kinesis seals
//     records and DynamoDB opens table keys through the front end's
//     in-process client (kms.client), never over the network;
//   * member 6, a kythira_node running Kinesis and DynamoDB with no KMS,
//     on a Raft peer set of its own as another cluster's node would be.
//     Both reach member 4 over HTTPS (KINESIS_KMS_ENDPOINT,
//     KYTHIRA_DYNAMODB_KMS_ENDPOINT), signing as a principal the KMS
//     trusts as a service (KYTHIRA_KMS_TRUSTED_SERVICES) and naming the
//     caller they serve.
//
// A customer managed key made through member 4 seals a Kinesis stream's
// records and a DynamoDB table's items on members 5 and 6 alike, and the
// KMS's audit record of each use says which service asked. A node whose
// co-located KMS runs no front end has no in-process client, so a
// consumer told to use it and given no endpoint refuses to start, naming
// KYTHIRA_KMS_ROLES (Requirement 8.1).
//
// A module test may include no other module, so the Kinesis and DynamoDB
// calls speak each wire directly. Every service authenticates with the
// same static keys file (Kinesis and the KMS share its format; DynamoDB
// takes the same keys inline).

#define BOOST_TEST_MODULE kythira_node_kms_consumers_test

#include "kms_process_cluster.hpp"

#ifndef KYTHIRA_NODE_PATH
#error "KYTHIRA_NODE_PATH must be defined"
#endif

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace kms_process_testing;  // NOLINT(google-build-using-namespace)

namespace {

constexpr std::size_t k_remote_front_end = 3;
constexpr std::size_t k_co_located = 4;
constexpr std::size_t k_elsewhere = 5;

/// The principal member 6's services sign their KMS calls as.
constexpr std::string_view k_consumer_akid = "AKIDKMSCONSUMER";
constexpr std::string_view k_consumer_secret = "kms-consumers-test-service-secret";

auto consumer_arn() -> std::string {
    return "arn:aws:iam::" + std::string(k_account) + ":user/consumer";
}

/// Kinesis and DynamoDB settings for a kythira_node member numbered `id`
/// (1-based) listening on `kinesis` and `dynamodb`, authenticating with
/// `keys_file` and the harness's admin key.
auto consumer_env(std::size_t id, std::uint16_t kinesis, std::uint16_t dynamodb,
                  const std::string& keys_file) -> std::vector<std::string> {
    const auto n = std::to_string(id);
    return {
        "KINESIS_LISTEN=127.0.0.1:" + std::to_string(kinesis),
        "KINESIS_AUTH=static",
        "KINESIS_STATIC_KEYS_FILE=" + keys_file,
        "KINESIS_REGION=us-east-1",
        "KINESIS_FORWARD_SECRET=kythira-node-kms-consumers-test-kinesis",
        "KINESIS_PEER_GATEWAYS=" + n + "=localhost:" + std::to_string(kinesis),
        "KINESIS_KMS=kythira",
        "KYTHIRA_DYNAMODB_BIND=127.0.0.1",
        "KYTHIRA_DYNAMODB_PORT=" + std::to_string(dynamodb),
        "KYTHIRA_DYNAMODB_AUTH=static",
        "KYTHIRA_DYNAMODB_STATIC_KEYS=" + std::string(k_akid) + ":" + std::string(k_secret) + ":" +
            std::string(k_account) + ":tester:admin",
        "KYTHIRA_DYNAMODB_ACCOUNT_ID=" + std::string(k_account),
        "KYTHIRA_DYNAMODB_FORWARD_SECRET=kythira-node-kms-consumers-test-dynamodb",
        "KYTHIRA_DYNAMODB_PEER_GATEWAYS=" + n + "=localhost:" + std::to_string(dynamodb),
        "KYTHIRA_DYNAMODB_DISK_FLOOR_BYTES=0",
        "KYTHIRA_DYNAMODB_COMPAT=throttling=off",
        "KYTHIRA_DYNAMODB_KMS=kythira",
    };
}

/// The KMS's members trust member 6's services to name their callers.
auto trusting() -> std::vector<std::string> {
    return {"KYTHIRA_KMS_TRUSTED_SERVICES=" + consumer_arn()};
}

/// Data nodes 1-3, member 4 (gateway and front end), member 5 (Kinesis,
/// DynamoDB and a KMS front end) and member 6 (Kinesis and DynamoDB, no
/// KMS). Ports are known only once the harness has them, so the consumer
/// settings are filled in before the members start.
struct consumers_cluster : process_cluster {
    consumers_cluster() : process_cluster(specs(), options_of()) {
        fill_consumer_env();
        for (std::size_t i = 0; i < size(); ++i) {
            start(i);
        }
        for (std::size_t i = 0; i < size(); ++i) {
            wait_serving(i);
        }
    }

    static auto specs() -> std::vector<member_spec> {
        std::vector<member_spec> out;
        for (int i = 0; i < 3; ++i) {
            member_spec data;
            data.roles = "data";
            data.env = trusting();
            out.push_back(std::move(data));
        }
        member_spec remote;
        remote.roles = "gateway,front_end";
        remote.env = trusting();
        out.push_back(std::move(remote));

        member_spec co_located;
        co_located.roles = "front_end";
        co_located.services = "kinesis,dynamodb,kms";
        co_located.binary = KYTHIRA_NODE_PATH;
        co_located.own_cluster = true;
        co_located.env = trusting();
        out.push_back(std::move(co_located));

        member_spec elsewhere;
        elsewhere.services = "kinesis,dynamodb";
        elsewhere.binary = KYTHIRA_NODE_PATH;
        elsewhere.own_cluster = true;
        out.push_back(std::move(elsewhere));
        return out;
    }

    static auto options_of() -> options {
        options o;
        o.key_lines.push_back(std::string(k_consumer_akid) + " " + std::string(k_consumer_secret) +
                              " " + std::string(k_account) + " consumer read-write");
        o.start = false;
        return o;
    }

    void fill_consumer_env() {
        const auto keys = (dir() / "keys").string();
        for (const auto i : {k_co_located, k_elsewhere}) {
            auto env = consumer_env(i + 1, at(i).aux_a, at(i).aux_b, keys);
            spec(i).env.insert(spec(i).env.end(), env.begin(), env.end());
        }
        const auto endpoint = "localhost:" + std::to_string(at(k_remote_front_end).api);
        for (auto e : std::vector<std::string>{
                 "KINESIS_KMS_ENDPOINT=" + endpoint,
                 "KINESIS_KMS_CA=" + ca_path(),
                 "KYTHIRA_DYNAMODB_KMS_ENDPOINT=" + endpoint,
                 "KYTHIRA_DYNAMODB_KMS_CA=" + ca_path(),
                 "AWS_ACCESS_KEY_ID=" + std::string(k_consumer_akid),
                 "AWS_SECRET_ACCESS_KEY=" + std::string(k_consumer_secret),
             }) {
            spec(k_elsewhere).env.push_back(std::move(e));
        }
    }

    /// A Kinesis call on member i's Kinesis listener, as the admin.
    auto kinesis(std::size_t i, std::string_view op, const std::string& body) -> answer {
        return aws_call(at(i).aux_a, "kinesis", "Kinesis_20131202." + std::string(op),
                        "application/x-amz-json-1.1", body,
                        credentials{std::string(k_akid), std::string(k_secret)});
    }

    /// A DynamoDB call on member i's DynamoDB listener, as the admin.
    auto dynamodb(std::size_t i, std::string_view op, const std::string& body) -> answer {
        return aws_call(at(i).aux_b, "dynamodb", "DynamoDB_20120810." + std::string(op),
                        "application/x-amz-json-1.0", body,
                        credentials{std::string(k_akid), std::string(k_secret)});
    }
};

/// Repeats `attempt` until `done` holds of its answer, or 60 s pass; the
/// last answer.
auto until(const std::function<answer()>& attempt, const std::function<bool(const answer&)>& done)
    -> answer {
    answer out;
    const auto deadline = std::chrono::steady_clock::now() + 60s;
    do {
        out = attempt();
        if (done(out)) {
            return out;
        }
        std::this_thread::sleep_for(250ms);
    } while (std::chrono::steady_clock::now() < deadline);
    return out;
}

auto ok(const answer& a) -> bool {
    return a.status == 200;
}

/// A Kinesis stream encrypted under `key_arn` on member i: one record
/// written and read back sealed.
void kinesis_round_trip(consumers_cluster& c, std::size_t i, const std::string& key_arn) {
    const auto stream = "orders-" + std::to_string(i + 1);
    const auto name = R"("StreamName":")" + stream + R"(")";
    const auto made =
        until([&] { return c.kinesis(i, "CreateStream", "{" + name + R"(,"ShardCount":1})"); },
              [](const answer& a) { return ok(a) || a.str("__type") == "ResourceInUseException"; });
    BOOST_REQUIRE_MESSAGE(
        made.status == 200 || made.str("__type") == "ResourceInUseException",
        "CreateStream on member " << i + 1 << ": " << made.status << " " << made.raw);
    const auto active =
        until([&] { return c.kinesis(i, "DescribeStreamSummary", "{" + name + "}"); },
              [](const answer& a) {
                  return ok(a) && a.raw.find(R"("StreamStatus":"ACTIVE")") != std::string::npos;
              });
    BOOST_REQUIRE_MESSAGE(ok(active), "stream not ACTIVE: " << active.raw);
    const auto sealed = until(
        [&] {
            return c.kinesis(
                i, "StartStreamEncryption",
                "{" + name + R"(,"EncryptionType":"KMS","KeyId":")" + key_arn + R"("})");
        },
        ok);
    BOOST_REQUIRE_MESSAGE(ok(sealed),
                          "StartStreamEncryption on member " << i + 1 << ": " << sealed.raw);
    const auto put = until(
        [&] {
            return c.kinesis(i, "PutRecord",
                             "{" + name + R"(,"PartitionKey":"pk","Data":"c2VjcmV0"})");
        },
        ok);
    BOOST_REQUIRE_MESSAGE(ok(put), "PutRecord on member " << i + 1 << ": " << put.raw);
    BOOST_TEST(put.str("EncryptionType") == "KMS");
    const auto it = c.kinesis(
        i, "GetShardIterator",
        "{" + name + R"(,"ShardId":"shardId-000000000000","ShardIteratorType":"TRIM_HORIZON"})");
    BOOST_REQUIRE_MESSAGE(ok(it), "GetShardIterator: " << it.raw);
    const auto read =
        c.kinesis(i, "GetRecords", R"({"ShardIterator":")" + it.str("ShardIterator") + R"("})");
    BOOST_REQUIRE_MESSAGE(ok(read), "GetRecords on member " << i + 1 << ": " << read.raw);
    const auto& records = read.body.at("Records").as_array();
    BOOST_REQUIRE_EQUAL(records.size(), 1U);
    BOOST_TEST(records.at(0).as_object().at("Data").as_string() == "c2VjcmV0");
}

/// A DynamoDB table encrypted under `key_arn` on member i: one item
/// written and read back.
void dynamodb_round_trip(consumers_cluster& c, std::size_t i, const std::string& key_arn) {
    const auto table = "sealed-" + std::to_string(i + 1);
    const auto made = until(
        [&] {
            return c.dynamodb(
                i, "CreateTable",
                R"({"TableName":")" + table +
                    R"(","BillingMode":"PAY_PER_REQUEST",)"
                    R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],)"
                    R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],)"
                    R"("SSESpecification":{"Enabled":true,"SSEType":"KMS","KMSMasterKeyId":")" +
                    key_arn + R"("}})");
        },
        [](const answer& a) {
            return ok(a) || a.str("__type").ends_with("ResourceInUseException");
        });
    BOOST_REQUIRE_MESSAGE(
        ok(made) || made.str("__type").ends_with("ResourceInUseException"),
        "CreateTable on member " << i + 1 << ": " << made.status << " " << made.raw);
    const auto active =
        until([&] { return c.dynamodb(i, "DescribeTable", R"({"TableName":")" + table + R"("})"); },
              [](const answer& a) {
                  return ok(a) && a.raw.find(R"("TableStatus":"ACTIVE")") != std::string::npos;
              });
    BOOST_REQUIRE_MESSAGE(ok(active), "table not ACTIVE: " << active.raw);
    BOOST_TEST(active.raw.find(R"("SSEType":"KMS")") != std::string::npos, active.raw);
    BOOST_TEST(active.raw.find(key_arn) != std::string::npos, active.raw);
    const auto put = until(
        [&] {
            return c.dynamodb(
                i, "PutItem",
                R"({"TableName":")" + table + R"(","Item":{"pk":{"S":"a"},"v":{"S":"hello"}}})");
        },
        ok);
    BOOST_REQUIRE_MESSAGE(ok(put), "PutItem on member " << i + 1 << ": " << put.raw);
    const auto got = until(
        [&] {
            return c.dynamodb(
                i, "GetItem",
                R"({"TableName":")" + table + R"(","Key":{"pk":{"S":"a"}},"ConsistentRead":true})");
        },
        [](const answer& a) { return ok(a) && a.raw.find("hello") != std::string::npos; });
    BOOST_REQUIRE_MESSAGE(ok(got), "GetItem on member " << i + 1 << ": " << got.raw);
    BOOST_TEST(got.raw.find("hello") != std::string::npos, got.raw);
}

/// Waits up to 10 s for member i's log to hold a KMS audit record of a
/// call `service` (kinesis or dynamodb) made for its caller.
auto await_audited(const process_cluster& c, std::size_t i, std::string_view service) -> bool {
    const auto by = R"("invokedBy":")" + std::string(service) + R"(.amazonaws.com")";
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (c.log_of(i).find(by) != std::string::npos) {
            return true;
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

}  // namespace

// Requirement 8.2: Kinesis seals records and DynamoDB opens table keys
// through a co-located front end (member 5, in-process) and a remote one
// (member 4, over HTTPS from member 6), under one customer managed key.
BOOST_FIXTURE_TEST_CASE(consumers_use_a_co_located_and_a_remote_front_end, consumers_cluster,
                        *boost::unit_test::timeout(600)) {
    const auto key = call(k_remote_front_end, "CreateKey", R"({"Description":"consumers"})");
    BOOST_REQUIRE_MESSAGE(key.status == 200, key.status << " " << key.raw);
    const std::string key_arn(key.body.at("KeyMetadata").as_object().at("Arn").as_string());

    for (const auto i : {k_co_located, k_elsewhere}) {
        BOOST_TEST_CONTEXT("member " << i + 1) {
            kinesis_round_trip(*this, i, key_arn);
            dynamodb_round_trip(*this, i, key_arn);
        }
    }

    // The co-located front end answered member 5's services itself, and
    // the remote one member 6's; each record names the asking service.
    BOOST_TEST(await_audited(*this, k_co_located, "kinesis"));
    BOOST_TEST(await_audited(*this, k_co_located, "dynamodb"));
    BOOST_TEST(await_audited(*this, k_remote_front_end, "kinesis"));
    BOOST_TEST(await_audited(*this, k_remote_front_end, "dynamodb"));
    // Member 6 runs no KMS: nothing it did was audited there.
    BOOST_TEST(log_of(k_elsewhere).find(R"("eventSource":"kms.amazonaws.com")") ==
               std::string::npos);
}

namespace {

/// The data nodes, member 4, and a kythira_node (member 5) whose
/// co-located KMS has the `roles` given (no front end), running Kinesis
/// or DynamoDB as `service` says with no KMS endpoint. Not started.
struct no_front_end_cluster : process_cluster {
    no_front_end_cluster(const std::string& roles, const std::string& service)
        : process_cluster(specs(roles, service), options_of()) {
        auto env = consumer_env(5, at(4).aux_a, at(4).aux_b, (dir() / "keys").string());
        spec(4).env.insert(spec(4).env.end(), env.begin(), env.end());
    }

    static auto specs(const std::string& roles, const std::string& service)
        -> std::vector<member_spec> {
        std::vector<member_spec> out(3);
        for (auto& d : out) {
            d.roles = "data";
        }
        member_spec fe;
        fe.roles = "gateway,front_end";
        out.push_back(std::move(fe));
        member_spec n;
        n.roles = roles;
        n.services = service + ",kms";
        n.binary = KYTHIRA_NODE_PATH;
        n.own_cluster = true;
        out.push_back(std::move(n));
        return out;
    }

    static auto options_of() -> options {
        options o;
        o.start = false;
        return o;
    }
};

}  // namespace

// Requirement 8.1: only a node with the KMS front end publishes kms.client;
// a consumer beside a KMS gateway alone, told to use Kythira's KMS with no
// endpoint, stops at start and says how to fix it.
BOOST_AUTO_TEST_CASE(a_consumer_beside_a_kms_without_a_front_end_refuses_to_start,
                     *boost::unit_test::timeout(300)) {
    const std::vector<std::pair<std::string, std::string>> cases{
        {"kinesis", "KINESIS_KMS=kythira: the co-located KMS module publishes no client"},
        {"dynamodb", "KYTHIRA_DYNAMODB_KMS=kythira: the co-located KMS module publishes no client"},
    };
    for (const auto& [service, message] : cases) {
        BOOST_TEST_CONTEXT(service) {
            no_front_end_cluster c("gateway", service);
            c.start(4);
            const auto status = c.await_exit(4, 60s);
            BOOST_REQUIRE_MESSAGE(status.has_value(), "the node kept running:\n" << c.log_of(4));
            BOOST_TEST((!WIFEXITED(*status) || WEXITSTATUS(*status) != 0));
            const auto log = c.log_of(4);
            BOOST_TEST(log.find(message) != std::string::npos, log);
            BOOST_TEST(log.find("KYTHIRA_KMS_ROLES") != std::string::npos);
        }
    }
}
