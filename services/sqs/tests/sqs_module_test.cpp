// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SQS module on multi_raft (`.kiro/specs/sqs-compatible-queues/` task
// 4, Requirements 1.2 and 5.2): whole nodes, each a Beast Raft transport, a
// node host and the module, with real sockets and real SigV4. One node
// keeps what it acknowledged across a restart; in three nodes a follower
// forwards to the leader, so every node answers every request; and the
// settings a durable node refuses.
//
// The engine is `memory_kv_engine`, so a restart rebuilds the queues by
// replaying the Raft log; the RocksDB engine kythira_node uses is the
// persistent-state-machine spec's to test.

#define BOOST_TEST_MODULE sqs_module_test

#include <boost/test/unit_test.hpp>

#include "sqs_module_harness.hpp"

BOOST_AUTO_TEST_SUITE(sqs_module)

BOOST_AUTO_TEST_CASE(one_node_keeps_what_it_acknowledged_across_a_restart) {
    temp_dir dir;
    const auto raft_port = kythira::testing::free_port();
    auto env = base_env(dir, "1", raft_port, 0);
    {
        node n(env);
        BOOST_TEST(n.module().health().healthy);
        auto r = n.call_until_ok("CreateQueue", {{"QueueName", "orders"}});
        BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
        BOOST_TEST(body_of(r).at("QueueUrl").as_string() == k_queue_url);
        r = n.call_until_ok("SendMessage", {{"QueueUrl", k_queue_url}, {"MessageBody", "kept"}});
        BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
    }
    node again(env);
    const auto r = again.call_until_ok("GetQueueUrl", {{"QueueName", "orders"}});
    BOOST_TEST(r.result_int() == 200U, r.body());
    BOOST_TEST((receive_one(again) == std::optional<std::string>("kept")));
}

BOOST_AUTO_TEST_CASE(every_node_of_three_answers_and_followers_forward) {
    temp_dir dir;
    const auto raft = kythira::testing::free_port_block(3);
    const auto api = kythira::testing::free_port_block(3);
    // One host, so each node's SQS port differs and is named for the
    // forwards (the default assumes one port on every host).
    std::string peers;
    std::string endpoints;
    for (int i = 0; i < 3; ++i) {
        const auto sep = std::string(i == 0 ? "" : ",") + std::to_string(i + 1);
        peers += sep + "=127.0.0.1:" + std::to_string(raft + i);
        endpoints += sep + "=http://127.0.0.1:" + std::to_string(api + i);
    }
    std::vector<std::unique_ptr<node>> nodes;
    std::vector<std::thread> starting;
    nodes.resize(3);
    for (int i = 0; i < 3; ++i) {
        auto env = base_env(dir, std::to_string(i + 1), static_cast<std::uint16_t>(raft + i),
                            static_cast<std::uint16_t>(api + i));
        env["KYTHIRA_NODE_PEERS"] = peers;
        env["SQS_PEER_ENDPOINTS"] = endpoints;
        starting.emplace_back(
            [&nodes, i, env] { nodes[static_cast<std::size_t>(i)] = std::make_unique<node>(env); });
    }
    for (auto& t : starting) {
        t.join();
    }
    const auto created = nodes[0]->call_until_ok("CreateQueue", {{"QueueName", "orders"}});
    BOOST_TEST_REQUIRE(created.result_int() == 200U, created.body());
    for (int i = 0; i < 3; ++i) {
        const auto r = nodes[static_cast<std::size_t>(i)]->call_until_ok(
            "SendMessage",
            {{"QueueUrl", k_queue_url}, {"MessageBody", "from " + std::to_string(i)}});
        BOOST_TEST(r.result_int() == 200U, r.body());
    }
    std::uint64_t forwarded = 0;
    for (const auto& n : nodes) {
        for (const auto& m : n->module().metrics()) {
            // A follower sends its writes and reads to the leader's
            // internal endpoints, which count them.
            if (m.name == "peer_requests") {
                forwarded += static_cast<std::uint64_t>(m.value);
            }
        }
    }
    // Two of the three nodes follow, and each sent at least once.
    BOOST_TEST(forwarded >= 2U);
    std::vector<std::string> got;
    for (int i = 0; i < 3; ++i) {
        if (auto b = receive_one(*nodes[static_cast<std::size_t>(2 - i)])) {
            got.push_back(*b);
        }
    }
    std::sort(got.begin(), got.end());
    BOOST_TEST((got == std::vector<std::string>{"from 0", "from 1", "from 2"}));

    // A long poll parked on one node answers when a send commits through
    // another: its own replica applies the entry and wakes it.
    auto parked = std::async(std::launch::async, [&nodes] {
        return nodes[2]->call("ReceiveMessage",
                              {{"QueueUrl", k_queue_url}, {"WaitTimeSeconds", 15}});
    });
    const auto metric = [&nodes](const std::string& name) {
        for (const auto& m : nodes[2]->module().metrics()) {
            if (m.name == name) {
                return m.value;
            }
        }
        return 0.0;
    };
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (metric("long_polls_parked") < 1 && std::chrono::steady_clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    BOOST_TEST_REQUIRE(metric("long_polls_parked") >= 1);
    const auto start = std::chrono::steady_clock::now();
    BOOST_TEST_REQUIRE(nodes[0]
                           ->call_until_ok("SendMessage", {{"QueueUrl", k_queue_url},
                                                           {"MessageBody", "long polled"}})
                           .result_int() == 200U);
    const auto r = parked.get();
    BOOST_TEST_REQUIRE(r.result_int() == 200U, r.body());
    const auto o = body_of(r);
    BOOST_TEST_REQUIRE(o.contains("Messages"), r.body());
    BOOST_TEST(o.at("Messages").as_array().at(0).at("Body").as_string() == "long polled");
    BOOST_TEST((std::chrono::steady_clock::now() - start < std::chrono::seconds(10)));
}

BOOST_AUTO_TEST_CASE(a_durable_node_refuses_settings_that_would_break_handles) {
    temp_dir dir;
    module_type m(true);
    auto env = base_env(dir, "1", 7400, 0);
    env.erase("SQS_FORWARD_SECRET");
    const auto lookup = [&env](std::string_view name) -> std::optional<std::string> {
        const auto it = env.find(name);
        return it == env.end() ? std::nullopt : std::optional<std::string>(it->second);
    };
    auto e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_RECEIPT_KEYS_FILE or SQS_FORWARD_SECRET") != std::string::npos);

    std::ofstream(dir.path / "receipts") << "0 " << std::string(32, 'r') << "\n";
    env["SQS_RECEIPT_KEYS_FILE"] = (dir.path / "receipts").string();
    // SSE-SQS is on by default: messages must open after a restart.
    e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_SSE_KEY_FILE or SQS_FORWARD_SECRET") != std::string::npos);
    std::ofstream(dir.path / "sse") << std::string(32, 's') << "\n";
    env["SQS_SSE_KEY_FILE"] = (dir.path / "sse").string();
    env["SQS_KMS"] = "local";
    e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_KMS_PASSPHRASE_FILE") != std::string::npos);
    env.erase("SQS_KMS");
    env["KYTHIRA_NODE_PEERS"] = "1=127.0.0.1:7400,2=127.0.0.1:7401";
    env["SQS_LISTEN"] = "127.0.0.1:9324";
    e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_FORWARD_SECRET is required with more than one node") !=
               std::string::npos);

    env["SQS_FORWARD_SECRET"] = "forwarding-secret-0123456789";
    env["SQS_LISTEN"] = "127.0.0.1:0";
    e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_PEER_ENDPOINTS") != std::string::npos);

    env["SQS_PEER_ENDPOINTS"] = "1=http://127.0.0.1:9324,2=http://127.0.0.1:9325";
    BOOST_TEST(!m.configure(lookup).has_value());
}

// Task 10: over TLS a node that runs only some layers calls the others, and
// checks them (and shows them its layer identity) against the peer CA.
BOOST_AUTO_TEST_CASE(a_partial_node_over_tls_needs_the_peer_ca) {
    temp_dir dir;
    module_type m(true);
    auto env = base_env(dir, "1", 7410, 0);
    env["SQS_ALLOW_PLAINTEXT"] = "off";
    env["SQS_TLS_CERT"] = (dir.path / "node.crt").string();
    env["SQS_TLS_KEY"] = (dir.path / "node.key").string();
    env["KYTHIRA_SQS_ROLES"] = "front_end";
    env["SQS_DATA_ENDPOINTS"] = "https://127.0.0.1:9324";
    const auto lookup = [&env](std::string_view name) -> std::optional<std::string> {
        const auto it = env.find(name);
        return it == env.end() ? std::nullopt : std::optional<std::string>(it->second);
    };
    auto e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_PEER_CA") != std::string::npos);
    env["SQS_IDENTITY_CLUSTER"] = "a/b";
    env["SQS_PEER_CA"] = (dir.path / "ca.pem").string();
    e = m.configure(lookup);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->find("SQS_IDENTITY_CLUSTER") != std::string::npos);
    env["SQS_IDENTITY_CLUSTER"] = "prod-east";
    BOOST_TEST(!m.configure(lookup).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
