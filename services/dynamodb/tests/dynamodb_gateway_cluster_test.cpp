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

// .kiro/specs/dynamodb-independent-layers/ task 4: a front end without the
// data role (KYTHIRA_DYNAMODB_ROLES=gateway,front_end) beside the three
// voters. It holds no replica and runs no Raft: it learns the routes from
// the data nodes it is given and sends each op to its group's leader over
// the forward channel. Clients reach every table through it, it answers
// DescribeEndpoints with its own endpoint, and it keeps serving when a data
// node it was given goes away.
BOOST_AUTO_TEST_CASE(a_front_end_without_the_data_role_serves_every_table) {
    cluster c;
    const auto port = kythira::testing::free_port();
    const std::map<std::string, std::string> vars{
        {"KYTHIRA_DYNAMODB_INSECURE_PLAINTEXT", "1"},
        {"KYTHIRA_DYNAMODB_BIND", "127.0.0.1"},
        {"KYTHIRA_DYNAMODB_PORT", std::to_string(port)},
        {"KYTHIRA_DYNAMODB_ADVERTISED_ENDPOINT", "front.example:" + std::to_string(port)},
        {"KYTHIRA_DYNAMODB_STATIC_KEYS",
         "AKIDADMIN:" + std::string(k_secret) + ":111122223333:admin:admin"},
        {"KYTHIRA_DYNAMODB_ROLES", "gateway,front_end"},
        {"KYTHIRA_DYNAMODB_DATA_NODES", "127.0.0.1:" + std::to_string(c.gateway_ports.at(0)) +
                                            ",127.0.0.1:" + std::to_string(c.gateway_ports.at(1))},
        {"KYTHIRA_DYNAMODB_FORWARD_SECRET", "0123456789abcdef-cluster-test"},
        {"KYTHIRA_DYNAMODB_FRONT_ENDS", "4"},
    };
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    std::vector<std::string> lines;
    std::exception_ptr failure;
    std::thread front([&] {
        try {
            dynamodb_gateway::run_front_end(
                cluster::parse(vars),
                [&](bool, std::string_view line) {
                    const std::lock_guard lock(mu);
                    lines.emplace_back(line);
                },
                [&] {
                    std::unique_lock lock(mu);
                    cv.wait(lock, [&] { return done; });
                });
        } catch (...) {
            failure = std::current_exception();
        }
    });
    struct stopper {
        std::mutex& mu;
        std::condition_variable& cv;
        bool& done;
        std::thread& t;
        ~stopper() {
            {
                const std::lock_guard lock(mu);
                done = true;
            }
            cv.notify_all();
            t.join();
        }
    } stop_front{mu, cv, done, front};

    const auto fe = [&](std::string_view op, const std::string& body) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        while (true) {
            std::optional<answer> a;
            try {
                a = cluster::call_at(port, "us-east-1", op, body);
            } catch (const std::exception&) {
                // The listener is not up yet.
            }
            if ((a && a->status < 500U) || std::chrono::steady_clock::now() > deadline) {
                return a.value_or(answer{});
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    };

    const auto created =
        fe("CreateTable", R"({"TableName":"orders","BillingMode":"PAY_PER_REQUEST",)"
                          R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},)"
                          R"({"AttributeName":"sk","AttributeType":"N"}],)"
                          R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},)"
                          R"({"AttributeName":"sk","KeyType":"RANGE"}]})");
    BOOST_REQUIRE_MESSAGE(created.status == 200U || created.type() == "ResourceInUseException",
                          json::serialize(created.body));
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::string status;
        while (status != "ACTIVE" && std::chrono::steady_clock::now() < deadline) {
            const auto d = fe("DescribeTable", R"({"TableName":"orders"})");
            if (d.status == 200U) {
                status = std::string(d.body.at("Table").at("TableStatus").as_string());
            }
            if (status != "ACTIVE") {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        BOOST_REQUIRE_MESSAGE(status == "ACTIVE", status);
    }
    const auto get_body = [](int sk) {
        return R"({"TableName":"orders","ConsistentRead":true,"Key":{"pk":{"S":"p"},"sk":{"N":")" +
               std::to_string(sk) + R"("}}})";
    };
    const auto put_body = [](int sk, int by) {
        return R"({"TableName":"orders","Item":{"pk":{"S":"p"},"sk":{"N":")" + std::to_string(sk) +
               R"("},"by":{"N":")" + std::to_string(by) + R"("}}})";
    };
    // What the front end writes the voters read, and the other way.
    BOOST_REQUIRE(fe("PutItem", put_body(1, 10)).status == 200U);
    for (int j = 0; j < k_nodes; ++j) {
        const auto got = c.call_until_served(j, "GetItem", get_body(1));
        BOOST_REQUIRE_MESSAGE(got.status == 200U, json::serialize(got.body));
        BOOST_TEST(got.body.at("Item").at("by").at("N").as_string() == "10");
    }
    BOOST_REQUIRE(c.call_until_served(2, "PutItem", put_body(2, 20)).status == 200U);
    const auto got = fe("GetItem", get_body(2));
    BOOST_REQUIRE_MESSAGE(got.status == 200U, json::serialize(got.body));
    BOOST_TEST(got.body.at("Item").at("by").at("N").as_string() == "20");

    // A failed condition and a transaction come back as the client's.
    const auto cond = fe("PutItem", R"({"TableName":"orders","Item":{"pk":{"S":"p"},)"
                                    R"("sk":{"N":"1"}},"ConditionExpression":)"
                                    R"x("attribute_not_exists(pk)"})x");
    BOOST_TEST(cond.status == 400U);
    BOOST_TEST(cond.type() == "ConditionalCheckFailedException");
    const auto txn = fe("TransactWriteItems",
                        R"({"TransactItems":[{"Put":{"TableName":"orders","Item":)"
                        R"({"pk":{"S":"q"},"sk":{"N":"1"}}}},{"Update":{"TableName":"orders",)"
                        R"("Key":{"pk":{"S":"p"},"sk":{"N":"1"}},"UpdateExpression":"SET #b = :b",)"
                        R"("ExpressionAttributeNames":{"#b":"by"},)"
                        R"("ExpressionAttributeValues":{":b":{"N":"11"}}}}]})");
    BOOST_REQUIRE_MESSAGE(txn.status == 200U, json::serialize(txn.body));
    BOOST_TEST(c.call_until_served(1, "GetItem", get_body(1))
                   .body.at("Item")
                   .at("by")
                   .at("N")
                   .as_string() == "11");
    const auto counted =
        fe("Scan", R"({"TableName":"orders","ConsistentRead":true,"Select":"COUNT"})");
    BOOST_REQUIRE(counted.status == 200U);
    BOOST_TEST(counted.body.at("Count").to_number<int>() == 3);

    // DescribeEndpoints names this gateway, never a data node.
    const auto endpoints = fe("DescribeEndpoints", "{}");
    BOOST_REQUIRE(endpoints.status == 200U);
    BOOST_TEST(endpoints.body.at("Endpoints").as_array()[0].at("Address").as_string() ==
               "front.example:" + std::to_string(port));
    const auto [health, roles, health_body] = raw_request(port, http::verb::get, "");
    BOOST_TEST(health == 200U);
    BOOST_TEST(roles == "gateway,front_end");
    {
        const std::lock_guard lock(mu);
        BOOST_TEST(std::any_of(lines.begin(), lines.end(), [](const std::string& l) {
            return l.find("no replica") != std::string::npos;
        }));
    }

    // The first data node it was given goes away: the routes it learned
    // name the others.
    c.stop(0);
    BOOST_REQUIRE(fe("PutItem", put_body(3, 30)).status == 200U);
    const auto after = fe("GetItem", get_body(3));
    BOOST_REQUIRE_MESSAGE(after.status == 200U, json::serialize(after.body));
    BOOST_TEST(after.body.at("Item").at("by").at("N").as_string() == "30");
    BOOST_TEST(c.call_until_served(2, "GetItem", get_body(3))
                   .body.at("Item")
                   .at("by")
                   .at("N")
                   .as_string() == "30");
    BOOST_TEST(!failure);
}

namespace {

/// A node run on its own thread by one of the daemon's `run_*` functions,
/// stopped (its `wait()` released) on destruction or by `stop()`.
class background_node {
public:
    using runner = std::function<void(const std::function<void(bool, std::string_view)>&,
                                      const std::function<void()>&)>;

    explicit background_node(runner run)
        : _thread([this, run = std::move(run)] {
              try {
                  run(
                      [this](bool, std::string_view line) {
                          const std::lock_guard lock(_mu);
                          _lines.emplace_back(line);
                      },
                      [this] {
                          std::unique_lock lock(_mu);
                          _cv.wait(lock, [this] { return _done; });
                      });
              } catch (...) {
                  _failure = std::current_exception();
              }
          }) {}

    background_node(const background_node&) = delete;
    auto operator=(const background_node&) -> background_node& = delete;
    background_node(background_node&&) = delete;
    auto operator=(background_node&&) -> background_node& = delete;
    ~background_node() { stop(); }

    void stop() {
        {
            const std::lock_guard lock(_mu);
            _done = true;
        }
        _cv.notify_all();
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    [[nodiscard]] auto logged(std::string_view part) -> bool {
        const std::lock_guard lock(_mu);
        return std::any_of(_lines.begin(), _lines.end(),
                           [&](const std::string& l) { return l.find(part) != std::string::npos; });
    }
    [[nodiscard]] auto failed() const -> bool { return static_cast<bool>(_failure); }

private:
    std::mutex _mu;
    std::condition_variable _cv;
    bool _done = false;
    std::vector<std::string> _lines;
    std::exception_ptr _failure;
    std::thread _thread;
};

/// A call to `port`, retried while the listener is not up or the answer is
/// a 5xx, for up to a minute.
auto call_until_answered(std::uint16_t port, std::string_view op, const std::string& body)
    -> answer {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (true) {
        std::optional<answer> a;
        try {
            a = cluster::call_at(port, "us-east-1", op, body);
        } catch (const std::exception&) {
            // The listener is not up yet.
        }
        if ((a && a->status < 500U) || std::chrono::steady_clock::now() > deadline) {
            return a.value_or(answer{});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

}  // namespace

// .kiro/specs/dynamodb-independent-layers/ task 5: gateways apart from
// their front ends. A gateway alone (KYTHIRA_DYNAMODB_ROLES=gateway) holds
// nothing: it verifies each request and hands it to a front end, here a
// front end alone (KYTHIRA_DYNAMODB_ROLES=front_end, which serves only
// gateways) and one of the voters, which keeps every role. A client moves
// from a voter's gateway onto the gateway alone and back, and no write it
// was told succeeded is lost on the way, in either direction (the gateway
// role's migration paths). When the front end alone goes away, the gateway
// hands its calls to the voter instead.
BOOST_AUTO_TEST_CASE(a_gateway_alone_serves_through_front_ends_and_clients_move_both_ways) {
    cluster c;
    const std::string secret = "0123456789abcdef-cluster-test";
    const auto keys = "AKIDADMIN:" + std::string(k_secret) + ":111122223333:admin:admin";
    const auto fe_port = kythira::testing::free_port();
    const auto gw_port = kythira::testing::free_port();
    auto front_node = std::make_unique<background_node>([&](const auto& log, const auto& wait) {
        dynamodb_gateway::run_front_end(
            cluster::parse({{"KYTHIRA_DYNAMODB_INSECURE_PLAINTEXT", "1"},
                            {"KYTHIRA_DYNAMODB_BIND", "127.0.0.1"},
                            {"KYTHIRA_DYNAMODB_PORT", std::to_string(fe_port)},
                            {"KYTHIRA_DYNAMODB_STATIC_KEYS", keys},
                            {"KYTHIRA_DYNAMODB_ROLES", "front_end"},
                            {"KYTHIRA_DYNAMODB_DATA_NODES",
                             "127.0.0.1:" + std::to_string(c.gateway_ports.at(1))},
                            {"KYTHIRA_DYNAMODB_FORWARD_SECRET", secret},
                            {"KYTHIRA_DYNAMODB_FRONT_ENDS", "4"}}),
            log, wait);
    });
    background_node gate([&](const auto& log, const auto& wait) {
        dynamodb_gateway::run_gateway_relay(
            cluster::parse({{"KYTHIRA_DYNAMODB_INSECURE_PLAINTEXT", "1"},
                            {"KYTHIRA_DYNAMODB_BIND", "127.0.0.1"},
                            {"KYTHIRA_DYNAMODB_PORT", std::to_string(gw_port)},
                            {"KYTHIRA_DYNAMODB_ADVERTISED_ENDPOINT",
                             "edge.example:" + std::to_string(gw_port)},
                            {"KYTHIRA_DYNAMODB_STATIC_KEYS", keys},
                            {"KYTHIRA_DYNAMODB_ROLES", "gateway"},
                            {"KYTHIRA_DYNAMODB_FRONT_END_NODES",
                             "127.0.0.1:" + std::to_string(fe_port) +
                                 ",127.0.0.1:" + std::to_string(c.gateway_ports.at(2))},
                            {"KYTHIRA_DYNAMODB_FORWARD_SECRET", secret}}),
            log, wait);
    });

    const auto put_body = [](int sk) {
        return R"({"TableName":"orders","Item":{"pk":{"S":"p"},"sk":{"N":")" + std::to_string(sk) +
               R"("}}})";
    };
    const auto get_body = [](int sk) {
        return R"({"TableName":"orders","ConsistentRead":true,"Key":{"pk":{"S":"p"},"sk":{"N":")" +
               std::to_string(sk) + R"("}}})";
    };
    const auto count_at = [&](std::uint16_t port) {
        const auto n = call_until_answered(
            port, "Scan", R"({"TableName":"orders","ConsistentRead":true,"Select":"COUNT"})");
        BOOST_REQUIRE_MESSAGE(n.status == 200U, json::serialize(n.body));
        return n.body.at("Count").to_number<int>();
    };

    // Co-located: the client starts on voter 0's gateway.
    const auto created =
        c.call_until_served(0, "CreateTable",
                            R"({"TableName":"orders","BillingMode":"PAY_PER_REQUEST",)"
                            R"("AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},)"
                            R"({"AttributeName":"sk","AttributeType":"N"}],)"
                            R"("KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},)"
                            R"({"AttributeName":"sk","KeyType":"RANGE"}]})");
    BOOST_REQUIRE_MESSAGE(created.status == 200U || created.type() == "ResourceInUseException",
                          json::serialize(created.body));
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        std::string status;
        while (status != "ACTIVE" && std::chrono::steady_clock::now() < deadline) {
            const auto d = c.call_until_served(0, "DescribeTable", R"({"TableName":"orders"})");
            if (d.status == 200U) {
                status = std::string(d.body.at("Table").at("TableStatus").as_string());
            }
            if (status != "ACTIVE") {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        BOOST_REQUIRE_MESSAGE(status == "ACTIVE", status);
    }
    int acknowledged = 0;
    for (int sk = 0; sk < 5; ++sk) {
        BOOST_REQUIRE(c.call_until_served(0, "PutItem", put_body(sk)).status == 200U);
        ++acknowledged;
    }

    // Onto the gateway alone: every earlier write is there, and its own
    // writes, conditions and transactions behave as on a voter.
    BOOST_TEST(count_at(gw_port) == acknowledged);
    for (int sk = 5; sk < 10; ++sk) {
        const auto put = call_until_answered(gw_port, "PutItem", put_body(sk));
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
        ++acknowledged;
    }
    const auto cond =
        call_until_answered(gw_port, "PutItem",
                            R"({"TableName":"orders","Item":{"pk":{"S":"p"},"sk":{"N":"1"}},)"
                            R"x("ConditionExpression":"attribute_not_exists(pk)"})x");
    BOOST_TEST(cond.status == 400U);
    BOOST_TEST(cond.type() == "ConditionalCheckFailedException");
    const auto txn = call_until_answered(
        gw_port, "TransactWriteItems",
        R"({"TransactItems":[{"Put":{"TableName":"orders","Item":)"
        R"x({"pk":{"S":"p"},"sk":{"N":"10"}},"ConditionExpression":"attribute_not_exists(pk)"}},)x"
        R"({"ConditionCheck":{"TableName":"orders","Key":{"pk":{"S":"p"},"sk":{"N":"0"}},)"
        R"x("ConditionExpression":"attribute_exists(pk)"}}]})x");
    BOOST_REQUIRE_MESSAGE(txn.status == 200U, json::serialize(txn.body));
    ++acknowledged;
    // DescribeEndpoints names the gateway, and health its roles.
    const auto endpoints = call_until_answered(gw_port, "DescribeEndpoints", "{}");
    BOOST_REQUIRE(endpoints.status == 200U);
    BOOST_TEST(endpoints.body.at("Endpoints").as_array()[0].at("Address").as_string() ==
               "edge.example:" + std::to_string(gw_port));
    const auto [health, roles, health_body] = raw_request(gw_port, http::verb::get, "");
    BOOST_TEST(health == 200U);
    BOOST_TEST(roles == "gateway");
    BOOST_TEST(gate.logged("gateway only"));
    // The front end alone serves gateways, not clients.
    const auto [direct, direct_roles, direct_body] =
        raw_request(fe_port, http::verb::post, R"({"TableName":"orders"})");
    BOOST_TEST(direct == 404U);
    BOOST_TEST(direct_roles == "front_end");

    // The front end alone goes away: the gateway hands its calls to the
    // voter's front end.
    front_node->stop();
    front_node.reset();
    for (int sk = 11; sk < 14; ++sk) {
        const auto put = call_until_answered(gw_port, "PutItem", put_body(sk));
        BOOST_REQUIRE_MESSAGE(put.status == 200U, json::serialize(put.body));
        ++acknowledged;
    }
    BOOST_TEST(count_at(gw_port) == acknowledged);

    // And back to a voter's gateway: nothing acknowledged on the way is
    // missing, and the gateway's writes read back there.
    BOOST_TEST(count_at(c.gateway_ports.at(1)) == acknowledged);
    const auto last = c.call_until_served(1, "GetItem", get_body(13));
    BOOST_REQUIRE_MESSAGE(last.status == 200U, json::serialize(last.body));
    BOOST_TEST(last.body.contains("Item"));
    BOOST_TEST(!gate.failed());
}
