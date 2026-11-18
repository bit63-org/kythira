// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Whole in-process sqs_node nodes for the module and migration tests: a
// Beast Raft transport, a node host and the module (on memory_kv_engine),
// with real sockets and real SigV4. Include after Boost.Test.

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

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
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

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
// The Folly backend's futures time out through folly::Timekeeper, a
// singleton that aborts the process unless folly::Init ran first. The
// default build never defines KYTHIRA_FUTURE_BACKEND_FOLLY, so this guard
// names the other two backends instead.
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("sqs_module_harness"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

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

[[maybe_unused]] auto receive_one(node& n) -> std::optional<std::string> {
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
