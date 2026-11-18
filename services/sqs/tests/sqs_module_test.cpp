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

#include "sqs_module.hpp"

#include <kythira/sqs/sqs_actions.hpp>

#include <raft/kythira_node_host.hpp>
#include <raft/memory_kv_engine.hpp>
#include <raft/node_core.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include "test_ports.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h>

namespace sn = kythira::service_node;
namespace sv4 = kythira::sigv4;
namespace http = boost::beast::http;
namespace json = boost::json;

namespace {

using host_type = sn::kythira_node_host;
using module_type = kythira::sqs_node::sqs_module<host_type, kythira::memory_kv_engine>;

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_queue_url = "http://localhost:9324/111122223333/orders";

struct temp_dir {
    std::filesystem::path path;
    temp_dir() {
        path = std::filesystem::temp_directory_path() /
               ("sqs_module_test_" + std::to_string(::getpid()) + "_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(path);
        std::ofstream(path / "keys") << "AKIDADMIN " << k_secret << " 111122223333 admin admin\n";
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

using env_map = std::map<std::string, std::string, std::less<>>;

/// One whole node: transport, host and the module, stand-alone (sqs_node's
/// shape).
class node {
public:
    explicit node(env_map env) : _env(std::move(env)) {
        const auto lookup = env_fn();
        auto parsed = sn::node_config_from_env(lookup);
        if (const auto* refused = std::get_if<std::string>(&parsed)) {
            BOOST_FAIL(*refused);
        }
        _config = std::get<sn::node_config>(parsed);
        _stack = std::make_unique<sn::kythira_node_stack>(_config);
        _host =
            std::make_unique<host_type>(_config, sn::kythira_node_stack::parse_id(_config.node_id),
                                        _stack->client(), _stack->server());
        sn::module_plan<host_type> plan;
        auto m = std::make_unique<module_type>(true);
        _module = m.get();
        plan.modules.push_back(std::move(m));
        plan.spaces.push_back(sn::group_space::standalone(sn::module_numbers::sqs));
        _runner = std::make_unique<sn::node_runner<host_type>>(std::move(plan), _config);
        _runner->start(*_host, lookup);
    }
    ~node() { stop(); }
    node(const node&) = delete;
    auto operator=(const node&) -> node& = delete;
    node(node&&) = delete;
    auto operator=(node&&) -> node& = delete;

    void stop() {
        if (_runner) {
            _runner->stop([this] { _stack->shutdown(); });
            _runner.reset();
        }
        _host.reset();
        _stack.reset();
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _module->api_port(); }
    [[nodiscard]] auto module() const -> module_type& { return *_module; }

    /// One signed AWS JSON call.
    auto call(std::string_view op, const json::object& in) -> http::response<http::string_body> {
        const auto body = json::serialize(in);
        const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
        const auto amz_date = sv4::detail::format_amz_date(now);
        const auto day = amz_date.substr(0, 8);
        std::vector<std::pair<std::string, std::string>> headers{
            {"Content-Type", "application/x-amz-json-1.0"},
            {"Host", "localhost:9324"},
            {"X-Amz-Date", amz_date},
            {"X-Amz-Target", "AmazonSQS." + std::string(op)}};
        sv4::service_rules rules;
        rules.service = "sqs";
        const sv4::credential_scope scope{day, "us-east-1", "sqs"};
        auto signing = headers;
        signing.emplace_back("Authorization",
                             "AWS4-HMAC-SHA256 Credential=AKIDADMIN/" + scope.text() +
                                 ", SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
                                 "Signature=" +
                                 std::string(64, '0'));
        const auto parsed = sv4::parse(sv4::request{"POST", "/", "", signing, body}, rules, now);
        BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
        auto auth = signing.back().second;
        auth.replace(auth.size() - 64, 64,
                     sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope)));

        boost::asio::io_context io;
        boost::beast::tcp_stream stream(io);
        stream.expires_after(std::chrono::seconds(20));
        stream.connect(
            boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port()));
        http::request<http::string_body> req{http::verb::post, "/", 11};
        for (const auto& [k, v] : headers) {
            req.set(k, v);
        }
        req.set(http::field::authorization, auth);
        req.body() = body;
        req.prepare_payload();
        http::write(stream, req);
        boost::beast::flat_buffer buf;
        http::response<http::string_body> res;
        http::read(stream, buf, res);
        boost::system::error_code ec;
        (void)stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        return res;
    }

    /// `call` until it answers 200 or `deadline` passes (an election, or a
    /// follower that has not heard of its leader yet, answers retryably).
    auto call_until_ok(std::string_view op, const json::object& in,
                       std::chrono::seconds deadline = std::chrono::seconds(20))
        -> http::response<http::string_body> {
        const auto end = std::chrono::steady_clock::now() + deadline;
        for (;;) {
            auto r = call(op, in);
            if (r.result_int() == 200U || std::chrono::steady_clock::now() > end) {
                return r;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

private:
    env_map _env;
    sn::node_config _config;
    std::unique_ptr<sn::kythira_node_stack> _stack;
    std::unique_ptr<host_type> _host;
    std::unique_ptr<sn::node_runner<host_type>> _runner;
    module_type* _module = nullptr;

    [[nodiscard]] auto env_fn() const -> sn::env_lookup {
        return [this](std::string_view name) -> std::optional<std::string> {
            const auto it = _env.find(name);
            return it == _env.end() ? std::nullopt : std::optional<std::string>(it->second);
        };
    }
};

auto base_env(const temp_dir& dir, const std::string& id, std::uint16_t raft_port,
              std::uint16_t api_port) -> env_map {
    std::filesystem::create_directories(dir.path / id);
    return {
        {"KYTHIRA_NODE_ID", id},
        {"KYTHIRA_NODE_DATA_DIR", (dir.path / id).string()},
        {"KYTHIRA_NODE_RAFT_BIND", "127.0.0.1"},
        {"KYTHIRA_NODE_RAFT_PORT", std::to_string(raft_port)},
        {"KYTHIRA_NODE_INSECURE_PLAINTEXT", "1"},
        {"SQS_LISTEN", "127.0.0.1:" + std::to_string(api_port)},
        {"SQS_ENDPOINT", "http://localhost:9324"},
        {"SQS_STATIC_KEYS_FILE", (dir.path / "keys").string()},
        {"SQS_FORWARD_SECRET", "forwarding-secret-0123456789"},
        {"KYTHIRA_ELECTION_TIMEOUT_MIN_MS", "150"},
        {"KYTHIRA_ELECTION_TIMEOUT_MAX_MS", "300"},
        {"KYTHIRA_HEARTBEAT_INTERVAL_MS", "40"},
        {"KYTHIRA_LOG_LEVEL", "warning"},
    };
}

auto body_of(const http::response<http::string_body>& r) -> json::object {
    return json::parse(r.body()).as_object();
}

auto receive_one(node& n) -> std::optional<std::string> {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < end) {
        const auto r = n.call("ReceiveMessage", {{"QueueUrl", k_queue_url}});
        if (r.result_int() == 200U) {
            const auto o = body_of(r);
            if (const auto* m = o.if_contains("Messages"); m != nullptr && !m->as_array().empty()) {
                return std::string(m->as_array().at(0).at("Body").as_string());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return std::nullopt;
}

}  // namespace

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
            if (m.name == "proposals_forwarded") {
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

BOOST_AUTO_TEST_SUITE_END()
