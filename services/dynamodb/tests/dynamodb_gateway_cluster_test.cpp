// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// dynamodb_gateway_node as a three-node cluster, in one process
// (`.kiro/specs/dynamodb-compatible-api/` task 7): each node is the
// daemon's own run_cluster() on the memory engine, with its Raft listener
// and gateway on free loopback ports, in plaintext. Requests go to every
// node over HTTP, signed as an SDK signs them, so a request that lands on a
// node that does not lead its group crosses the forward link to the one
// that does.

#define BOOST_TEST_MODULE dynamodb_gateway_cluster_test

#include <boost/test/unit_test.hpp>

#include "dynamodb_cluster_fixture.hpp"

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <variant>
#include <vector>

#include <unistd.h>

// The default (Folly) backend needs folly::Init before the first Raft
// timer asks for folly's Timekeeper singleton.
#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("dynamodb_gateway_cluster_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

using namespace dynamodb_cluster_test;

// Task 24: the ids a voter gives a split's children. Voters' ranges are
// disjoint, and a node that keeps its data never hands out an id twice,
// even when it is killed between reserving and using a block.
BOOST_AUTO_TEST_CASE(split_children_get_ids_from_the_voters_own_range) {
    using dynamodb_gateway::reserved_group_ids;
    reserved_group_ids a(0, std::nullopt);
    reserved_group_ids b(1, std::nullopt);
    BOOST_TEST(a.first() > 2U);  // above the bootstrap groups
    BOOST_TEST(a.last() == b.first());
    const auto from_a = a.allocate(3);
    const auto from_b = b.allocate(3);
    BOOST_TEST_REQUIRE(from_a.size() == 3U);
    BOOST_TEST_REQUIRE(from_b.size() == 3U);
    for (const auto id : from_a) {
        BOOST_TEST((id >= a.first() && id < a.last()));
    }
    for (const auto id : from_b) {
        BOOST_TEST((id >= b.first() && id < b.last()));
    }
    BOOST_CHECK_THROW(reserved_group_ids(255, std::nullopt), std::invalid_argument);

    const auto dir = std::filesystem::temp_directory_path() /
                     ("kythira-ddb-group-ids-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    std::vector<std::uint64_t> seen;
    {
        reserved_group_ids first_run(2, dir / "group-ids");
        for (const auto id : first_run.allocate(reserved_group_ids::k_block + 5)) {
            seen.push_back(id);
        }
    }
    // A restart (or a SIGKILL) resumes after the last reserved block.
    reserved_group_ids second_run(2, dir / "group-ids");
    const auto more = second_run.allocate(4);
    BOOST_TEST_REQUIRE(more.size() == 4U);
    for (const auto id : more) {
        BOOST_TEST(id > seen.back());
        BOOST_TEST((id >= second_run.first() && id < second_run.last()));
    }
    // Another voter's file is refused rather than trusted.
    BOOST_CHECK_THROW(reserved_group_ids(3, dir / "group-ids"), std::runtime_error);
    std::filesystem::remove_all(dir);
}

// Task 24: the layout a RocksDB node restarts with. Binary range bounds,
// open ends, epochs and members come back as saved; no file means none;
// a damaged file is refused rather than read as the bootstrap layout.
BOOST_AUTO_TEST_CASE(a_saved_group_layout_loads_back) {
    using descriptor = kythira::shard_descriptor<std::uint64_t, std::string, std::uint64_t>;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("kythira-ddb-layout-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const dynamodb_gateway::group_layout_file<descriptor, std::uint64_t> file(
        dir / "layout.json", [](const std::uint64_t& n) { return std::to_string(n); },
        [](const std::string& t) { return static_cast<std::uint64_t>(std::stoull(t)); });
    BOOST_TEST(!file.load().has_value());

    descriptor left;
    left._group_id = 2;
    left._range._start = std::string("t/", 2);
    left._range._end = std::string("t/\0\0\0\0\0\0\0\x05/\xff\x01", 13);
    left._epoch = {._version = 3, ._conf_version = 1};
    left._voters = {1, 2, 3};
    descriptor right = left;
    right._group_id = 281474976710656ULL;
    right._range._start = left._range._end;
    right._range._end.reset();
    right._learners = {4};
    BOOST_TEST_REQUIRE(file.save({left, right}));
    const auto loaded = file.load();
    BOOST_TEST_REQUIRE(loaded.has_value());
    BOOST_TEST_REQUIRE(loaded->size() == 2U);
    BOOST_TEST(((*loaded)[0] == left));
    BOOST_TEST(((*loaded)[1] == right));
    BOOST_TEST(((*loaded)[1]._learners == std::vector<std::uint64_t>{4}));

    {
        std::ofstream(dir / "layout.json") << "{\"groups\": [";
    }
    BOOST_CHECK_THROW((void)file.load(), std::runtime_error);
    std::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(requests_on_every_node_reach_one_table) {
    cluster c;
    // The first CreateTable may be retried across an election; a retry of
    // one that did commit meets the table.
    const auto created =
        c.call_until_served(0, "CreateTable",
                            R"({"TableName":"orders","BillingMode":"PAY_PER_REQUEST",)"
                            R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},)"
                            R"({"AttributeName":"sk","AttributeType":"N"}],)"
                            R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},)"
                            R"({"AttributeName":"sk","KeyType":"RANGE"}]})");
    BOOST_REQUIRE_MESSAGE(created.status == 200U || created.type() == "ResourceInUseException",
                          json::serialize(created.body));

    // Every node comes to see it ACTIVE.
    for (int i = 0; i < k_nodes; ++i) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::string status;
        while (status != "ACTIVE" && std::chrono::steady_clock::now() < deadline) {
            const auto d = c.call_until_served(i, "DescribeTable", R"({"TableName":"orders"})");
            if (d.status == 200U) {
                status = std::string(d.body.at("Table").at("TableStatus").as_string());
            }
            if (status != "ACTIVE") {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        BOOST_REQUIRE_MESSAGE(status == "ACTIVE", "node " << i + 1 << ": " << status);
    }

    // Writes through each node; a consistent read through every other node
    // sees each of them.
    for (int i = 0; i < k_nodes; ++i) {
        const auto put = c.call_until_served(
            i, "PutItem",
            R"({"TableName":"orders","Item":{"pk":{"S":"p"},"sk":{"N":")" + std::to_string(i) +
                R"("},"by":{"N":")" + std::to_string(i + 1) + R"("}}})");
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
        for (int j = 0; j < k_nodes; ++j) {
            const auto got = c.call_until_served(
                j, "GetItem",
                R"({"TableName":"orders","ConsistentRead":true,"Key":{"pk":{"S":"p"},)"
                R"("sk":{"N":")" +
                    std::to_string(i) + R"("}}})");
            BOOST_REQUIRE_MESSAGE(got.status == 200U, json::serialize(got.body));
            BOOST_TEST(got.body.at("Item").at("by").at("N").as_string() == std::to_string(i + 1),
                       "write via node " << i + 1 << ", read via node " << j + 1);
        }
    }

    // A failed condition crosses the link as the client's error.
    const auto cond =
        c.call_until_served(2, "PutItem",
                            R"({"TableName":"orders","Item":{"pk":{"S":"p"},"sk":{"N":"0"}},)"
                            R"x("ConditionExpression":"attribute_not_exists(pk)"})x");
    BOOST_TEST(cond.type() == "ConditionalCheckFailedException");

    // Query and Scan from each node see all three items, in order.
    for (int i = 0; i < k_nodes; ++i) {
        const auto q = c.call_until_served(
            i, "Query",
            R"({"TableName":"orders","ConsistentRead":true,"KeyConditionExpression":"pk = :p",)"
            R"("ExpressionAttributeValues":{":p":{"S":"p"}}})");
        BOOST_REQUIRE_MESSAGE(q.status == 200U, json::serialize(q.body));
        const auto& items = q.body.at("Items").as_array();
        BOOST_REQUIRE(items.size() == 3U);
        BOOST_TEST(items[2].at("sk").at("N").as_string() == "2");
        const auto s = c.call_until_served(
            i, "Scan", R"({"TableName":"orders","ConsistentRead":true,"Select":"COUNT"})");
        BOOST_TEST(s.body.at("Count").to_number<int>() == 3);
    }

    // DeleteTable through the last node frees the name everywhere.
    const auto del = c.call_until_served(2, "DeleteTable", R"({"TableName":"orders"})");
    BOOST_REQUIRE_MESSAGE(del.status == 200U, json::serialize(del.body));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    std::string type;
    while (type != "ResourceNotFoundException" && std::chrono::steady_clock::now() < deadline) {
        type = c.call_until_served(0, "DescribeTable", R"({"TableName":"orders"})").type();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    BOOST_TEST(type == "ResourceNotFoundException");

    for (int i = 0; i < k_nodes; ++i) {
        BOOST_TEST(!c.failures.at(i), "node " << i + 1 << " stopped early");
    }
}

namespace {

/// A raw request to `port`: the status, the role header and the body.
auto raw_request(std::uint16_t port, http::verb verb, const std::string& body)
    -> std::tuple<unsigned, std::string, std::string> {
    http::request<http::string_body> req{verb, "/", 11};
    req.set(http::field::host, "127.0.0.1:" + std::to_string(port));
    req.set(http::field::content_type, "application/x-amz-json-1.0");
    req.body() = body;
    req.prepare_payload();
    boost::asio::io_context ioc;
    boost::beast::tcp_stream s(ioc);
    s.expires_after(std::chrono::seconds(30));
    s.connect({boost::asio::ip::make_address("127.0.0.1"), port});
    http::write(s, req);
    boost::beast::flat_buffer buf;
    http::response<http::string_body> res;
    http::read(s, buf, res);
    return {static_cast<unsigned>(res.result_int()), std::string(res[ddb::k_roles_header]),
            res.body()};
}

}  // namespace

// .kiro/specs/dynamodb-independent-layers/ task 1: a voter started with
// KYTHIRA_DYNAMODB_ROLES=data,segments holds replicas, votes, and serves
// the ops the other voters' gateways forward to the groups it leads, but
// answers no client.
BOOST_AUTO_TEST_CASE(a_data_only_voter_holds_replicas_and_serves_no_client) {
    constexpr int k_data_only = 2;
    cluster c(false, {}, false, {{k_data_only, {{"KYTHIRA_DYNAMODB_ROLES", "data,segments"}}}});
    BOOST_REQUIRE(c.wait_for_log(k_data_only, "roles data,segments", std::chrono::seconds(60)));
    BOOST_REQUIRE(
        c.wait_for_log(0, "roles gateway,front_end,data,segments", std::chrono::seconds(60)));

    const auto created = c.call_until_served(
        0, "CreateTable",
        R"({"TableName":"orders","BillingMode":"PAY_PER_REQUEST",)"
        R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],)"
        R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]})");
    BOOST_REQUIRE_MESSAGE(created.status == 200U || created.type() == "ResourceInUseException",
                          json::serialize(created.body));
    const auto active = [&](int i) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        while (std::chrono::steady_clock::now() < deadline) {
            const auto d = c.call_until_served(i, "DescribeTable", R"({"TableName":"orders"})");
            if (d.status == 200U && d.body.at("Table").at("TableStatus").as_string() == "ACTIVE") {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    };
    BOOST_REQUIRE(active(0));
    BOOST_REQUIRE(active(1));

    // Writes and consistent reads through both client nodes, whichever
    // voter leads the item's group.
    for (int k = 0; k < 8; ++k) {
        const auto key = "k" + std::to_string(k);
        const auto put = c.call_until_served(
            k % 2, "PutItem", R"({"TableName":"orders","Item":{"pk":{"S":")" + key + R"("}}})");
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
        const auto got = c.call_until_served(
            1 - k % 2, "GetItem",
            R"({"TableName":"orders","ConsistentRead":true,"Key":{"pk":{"S":")" + key + R"("}}})");
        BOOST_REQUIRE_MESSAGE(got.status == 200U && got.body.contains("Item"),
                              json::serialize(got.body));
    }

    // The data node answers health with its roles, and clients with 404.
    const auto port = c.gateway_ports.at(k_data_only);
    const auto [health, health_roles, health_body] = raw_request(port, http::verb::get, "");
    BOOST_TEST(health == 200U);
    BOOST_TEST(health_roles == "data,segments");
    const auto [refused, refused_roles, refused_body] =
        raw_request(port, http::verb::post, R"({"TableName":"orders"})");
    BOOST_TEST(refused == 404U);
    BOOST_TEST(refused_roles == "data,segments");
    BOOST_TEST(refused_body.find("no DynamoDB gateway") != std::string::npos);
    const auto [full, full_roles, full_body] =
        raw_request(c.gateway_ports.at(0), http::verb::get, "");
    BOOST_TEST(full_roles == "gateway,front_end,data,segments");

    // It is a voter: with node 1 stopped, node 2 and the data node are the
    // quorum every write needs.
    c.stop(0);
    for (int k = 0; k < 8; ++k) {
        const auto key = "after-" + std::to_string(k);
        const auto put = c.call_until_served(
            1, "PutItem", R"({"TableName":"orders","Item":{"pk":{"S":")" + key + R"("}}})");
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
    }
    const auto scan = c.call_until_served(
        1, "Scan", R"({"TableName":"orders","ConsistentRead":true,"Select":"COUNT"})");
    BOOST_REQUIRE_MESSAGE(scan.status == 200U, json::serialize(scan.body));
    BOOST_TEST(scan.body.at("Count").to_number<int>() == 16);
    for (int i = 1; i < k_nodes; ++i) {
        BOOST_TEST(!c.failures.at(i), "node " << i + 1 << " stopped early");
    }
}

// Time to live on the cluster (task 13): the catalog leader's gateway sweeps,
// and its conditional deletes reach the item group's leader wherever it is.
BOOST_AUTO_TEST_CASE(expired_items_are_swept_on_the_cluster) {
    cluster c;
    const auto created = c.call_until_served(
        1, "CreateTable",
        R"({"TableName":"sessions","BillingMode":"PAY_PER_REQUEST",)"
        R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],)"
        R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],)"
        R"("Tags":[{"Key":"kythira:compat:ttl-delay","Value":"prompt"}]})");
    BOOST_REQUIRE_MESSAGE(created.status == 200U || created.type() == "ResourceInUseException",
                          json::serialize(created.body));
    // Every node comes to see it ACTIVE before writing through it: a node
    // whose catalog is behind answers ResourceNotFoundException.
    for (int i = 0; i < k_nodes; ++i) {
        const auto active_by = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::string status;
        while (status != "ACTIVE" && std::chrono::steady_clock::now() < active_by) {
            const auto d = c.call_until_served(i, "DescribeTable", R"({"TableName":"sessions"})");
            if (d.status == 200U) {
                status = std::string(d.body.at("Table").at("TableStatus").as_string());
            }
            if (status != "ACTIVE") {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        BOOST_REQUIRE_MESSAGE(status == "ACTIVE", "node " << i + 1 << ": " << status);
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    answer ttl;
    while (ttl.status != 200U && std::chrono::steady_clock::now() < deadline) {
        ttl = c.call_until_served(
            1, "UpdateTimeToLive",
            R"({"TableName":"sessions","TimeToLiveSpecification":{"Enabled":true,)"
            R"("AttributeName":"exp"}})");
        if (ttl.status != 200U) {
            // CREATING, or a retry of a change that did commit.
            if (ttl.message() == "TimeToLive is already enabled") {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    for (int i = 0; i < k_nodes; ++i) {
        const auto put = c.call_until_served(i, "PutItem",
                                             R"({"TableName":"sessions","Item":{"pk":{"S":"s)" +
                                                 std::to_string(i) + R"("},"exp":{"N":")" +
                                                 std::to_string(now_s - 60) + R"("}}})");
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
    }
    const auto keep =
        c.call_until_served(0, "PutItem",
                            R"({"TableName":"sessions","Item":{"pk":{"S":"keep"},"exp":{"N":")" +
                                std::to_string(now_s + 3600) + R"("}}})");
    BOOST_REQUIRE_MESSAGE(keep.status == 200U, json::serialize(keep.body));

    int count = -1;
    const auto swept = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (count != 1 && std::chrono::steady_clock::now() < swept) {
        const auto s = c.call_until_served(
            2, "Scan", R"({"TableName":"sessions","ConsistentRead":true,"Select":"COUNT"})");
        if (s.status == 200U) {
            count = s.body.at("Count").to_number<int>();
        }
        if (count != 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    BOOST_TEST(count == 1);
    const auto got = c.call_until_served(
        2, "GetItem",
        R"({"TableName":"sessions","ConsistentRead":true,"Key":{"pk":{"S":"keep"}}})");
    BOOST_TEST(got.body.contains("Item"));

    for (int i = 0; i < k_nodes; ++i) {
        BOOST_TEST(!c.failures.at(i), "node " << i + 1 << " stopped early");
    }
}
