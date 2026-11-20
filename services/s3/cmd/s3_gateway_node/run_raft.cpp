// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// s3_gateway_node as a Raft member (.kiro/specs/s3-compatible-storage/
// task 16a): its own Raft transport, Boost.Beast with the JSON wire over
// mutual TLS (the internal listener's certificate, key and CA), and the S3
// module (s3_module.hpp) as a one-module node, stand-alone, so its group
// ids and data directory are its own.

#include "run_raft.hpp"

#include "s3_module.hpp"

#include <raft/beast_http_transport_impl.hpp>
#include <raft/json_serializer.hpp>
#include <raft/module_registry.hpp>
#include <raft/node_core.hpp>
#include <raft/node_host.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kythira::s3_node {

namespace {

using serializer_type = kythira::json_rpc_serializer<std::vector<std::byte>>;

/// The Raft transport: one io_context, its threads, the Beast server and
/// client.
struct raft_stack {
    using bundle = kythira::host_transport_types<serializer_type>;
    using client_type = kythira::boost_beast_client<bundle, kythira::host_node_id>;
    using server_type = kythira::boost_beast_server<bundle, kythira::host_node_id>;

    static auto peers(const s3::node_config& cfg)
        -> std::unordered_map<kythira::host_node_id, std::string> {
        std::unordered_map<kythira::host_node_id, std::string> out;
        for (const auto& [id, addr] : cfg.raft_peers) {
            auto parsed = kythira::parse_host_peer_node_id(id);
            if (!parsed) {
                throw std::invalid_argument("KYTHIRA_S3_RAFT_PEERS: " + parsed.error());
            }
            out[std::move(parsed).value()] = "https://" + addr;
        }
        return out;
    }

    static auto server_config(const s3::node_config& cfg) -> kythira::boost_beast_server_config {
        kythira::boost_beast_server_config c;
        // An AppendEntries carries index entries (manifests, not bytes),
        // JSON encoded; snapshot chunks are smaller.
        c.max_request_body_size = std::size_t{64} << 20U;
        c.enable_ssl = true;
        c.ssl_cert_path = cfg.internal_tls.cert;
        c.ssl_key_path = cfg.internal_tls.key;
        c.ca_cert_path = cfg.internal_tls.ca;
        c.require_client_cert = true;
        return c;
    }

    static auto client_config(const s3::node_config& cfg) -> kythira::boost_beast_client_config {
        kythira::boost_beast_client_config c;
        c.request_timeout = std::chrono::milliseconds{5000};
        c.ca_cert_path = cfg.internal_tls.ca;
        c.client_cert_path = cfg.internal_tls.cert;
        c.client_key_path = cfg.internal_tls.key;
        return c;
    }

    explicit raft_stack(const s3::node_config& cfg)
        : work(boost::asio::make_work_guard(*ioc)),
          server(*ioc, cfg.raft_listen.bind, cfg.raft_listen.port, server_config(cfg),
                 kythira::noop_metrics{}),
          client(*ioc, peers(cfg), client_config(cfg), kythira::noop_metrics{}, ioc) {
        server.set_peer_seen_handler(client.peer_seen_handler());
        const auto n = std::max(2U, std::thread::hardware_concurrency() / 2);
        for (unsigned i = 0; i < n; ++i) {
            threads.emplace_back([this] { ioc->run(); });
        }
    }
    ~raft_stack() { shutdown(); }
    raft_stack(const raft_stack&) = delete;
    auto operator=(const raft_stack&) -> raft_stack& = delete;
    raft_stack(raft_stack&&) = delete;
    auto operator=(raft_stack&&) -> raft_stack& = delete;

    void shutdown() {
        if (stopped.exchange(true)) {
            return;
        }
        work.reset();
        ioc->stop();
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        threads.clear();
    }

    std::shared_ptr<boost::asio::io_context> ioc{std::make_shared<boost::asio::io_context>()};
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work;
    server_type server;
    client_type client;
    std::vector<std::thread> threads;
    std::atomic<bool> stopped{false};
};

using standalone_host = service_node::node_host<raft_stack::client_type, raft_stack::server_type,
                                                kythira::host_node_id>;

}  // namespace

auto run_raft(const s3::env_lookup& env, const s3::node_config& cfg,
              const std::function<void()>& wait) -> int {
    auto self = kythira::parse_host_peer_node_id(cfg.node_id);
    if (!self) {
        std::cerr << "s3_gateway_node: KYTHIRA_S3_NODE_ID: " << self.error() << "\n";
        return 2;
    }
    raft_stack stack(cfg);
    service_node::node_config node_cfg;
    node_cfg.node_id = cfg.node_id;
    node_cfg.data_dir = cfg.data_dir;
    node_cfg.raft_bind = cfg.raft_listen.bind;
    node_cfg.raft_port = cfg.raft_listen.port;
    standalone_host host(node_cfg, std::move(self).value(), stack.client, stack.server);

    service_node::module_plan<standalone_host> plan;
    plan.modules.push_back(std::make_unique<s3_module<standalone_host>>(true));
    plan.spaces.push_back(service_node::group_space::standalone(service_node::module_numbers::s3));
    service_node::node_runner<standalone_host> runner(
        std::move(plan), node_cfg,
        [](bool error, std::string_view line) { log_line(error, line); });

    int status = 0;
    try {
        runner.start(host, [&env](std::string_view name) { return env(name); });
        wait();
    } catch (const std::invalid_argument& e) {
        std::cerr << "s3_gateway_node: " << e.what() << "\n";
        status = 2;
    } catch (const std::exception& e) {
        std::cerr << "s3_gateway_node: " << e.what() << "\n";
        status = 1;
    }
    // The module drains its listeners, then stops its group, before the
    // transport goes.
    runner.stop([&stack] { stack.shutdown(); });
    return status;
}

}  // namespace kythira::s3_node
