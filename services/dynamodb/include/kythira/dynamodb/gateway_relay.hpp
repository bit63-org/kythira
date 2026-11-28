// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file gateway_relay.hpp
/// @brief A DynamoDB node with the gateway role alone
///        (`KYTHIRA_DYNAMODB_ROLES=gateway`,
///        `.kiro/specs/dynamodb-independent-layers/` task 5, Requirement 4).
///
/// It keeps nothing: no Raft, no replica, no handlers, nothing on disk. It
/// takes client connections and TLS, frames each request, holds it to the
/// request limits, verifies SigV4 (static keys or Kythira IAM, as any
/// gateway does), answers `DescribeEndpoints` with its own advertised
/// endpoint and `GET /` for health, and hands every other call to a front
/// end in `KYTHIRA_DYNAMODB_FRONT_END_NODES` (`front_end_handoff.hpp`).
/// The front end authorizes and runs it, so the gateway needs no table
/// tags or resource policies (Requirement 4.2).
///
/// The internal routes are not served here: the forward channel answers
/// 404 (no data role) and a handoff answers "not executed" (no front end),
/// so a gateway listed by mistake as a front end costs one retry, not a
/// failed call. Drain works as on every node (`front_end_handoff.hpp`).

#include <kythira/dynamodb/dynamodb_actions.hpp>
#include <kythira/dynamodb/front_end.hpp>
#include <kythira/dynamodb/front_end_handoff.hpp>
#include <kythira/dynamodb/gateway.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/static_or_iam_authorizer.hpp>

#include <boost/beast/http.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::dynamodb {

class gateway_relay {
public:
    using authorizer = aws_auth::static_or_iam_authorizer;

    gateway_relay(gateway_config config, std::function<void(bool, std::string_view)> log = {})
        : _config(std::move(config)),
          _auth(_config.keys, _config.front.partition),
          _log(std::move(log)) {
        _auth.register_service(dynamodb_static_roles());
        _auth.set_mode(_config.auth, _config.iam);
    }

    gateway_relay(const gateway_relay&) = delete;
    auto operator=(const gateway_relay&) -> gateway_relay& = delete;
    gateway_relay(gateway_relay&&) = delete;
    auto operator=(gateway_relay&&) -> gateway_relay& = delete;
    ~gateway_relay() { stop(); }

    /// How calls reach the front ends; unset, the forward channel's client.
    /// For tests. Set before `start`.
    void set_relay_transport(relay_transport transport) { _transport = std::move(transport); }

    /// Binds and starts serving. Throws when the listener or TLS setup
    /// fails, or the key table is bad.
    void start() {
        if (_config.cluster.front_end_nodes.empty()) {
            throw std::invalid_argument(
                "a gateway without its front end needs KYTHIRA_DYNAMODB_FRONT_END_NODES");
        }
        if (const auto both = _auth.conflicting_keys(); !both.empty()) {
            std::string ids;
            for (const auto& id : both) {
                ids += (ids.empty() ? "" : ", ") + id;
            }
            throw std::invalid_argument("KYTHIRA_DYNAMODB_AUTH=both: IAM also has the static key " +
                                        ids + "; remove it from one of them");
        }
        _relay = gateway_detail::make_front_end_relay(_config, std::move(_transport));
        _server = std::make_unique<https::server>(
            _config.http,
            [this](const https::request& req, const https::request_context& ctx) {
                return handle(req, ctx);
            },
            _log);
        _server->start();
        auto front = _config.front;
        if (front.advertised_endpoint.empty()) {
            front.advertised_endpoint = "localhost:" + std::to_string(_server->port());
        }
        _front = std::make_unique<front_end<authorizer>>(std::move(front), _auth);
        _ready.store(true, std::memory_order_release);
    }

    void begin_drain() {
        if (_draining.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        if (_log) {
            _log(false, "draining: no new connections, requests in flight get " +
                            std::to_string(_config.cluster.drain_timeout.count()) + " ms");
        }
        if (_server) {
            _server->stop_accepting();
        }
    }

    [[nodiscard]] auto draining() const noexcept -> bool {
        return _draining.load(std::memory_order_acquire);
    }

    [[nodiscard]] auto in_flight() const noexcept -> std::uint64_t {
        return _in_flight.load(std::memory_order_acquire);
    }

    auto drain() -> bool {
        begin_drain();
        return gateway_detail::await_in_flight(_in_flight, 0, _config.cluster.drain_timeout);
    }

    void stop() {
        if (_server) {
            _server->stop();
        }
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return _server ? _server->port() : 0; }
    [[nodiscard]] auto relay() const -> const front_end_relay* { return _relay.get(); }

    /// One request; public so tests can call it without a socket.
    auto handle(const https::request& req, const https::request_context& ctx) -> https::response {
        const gateway_detail::in_flight_count counted(_in_flight);
        auto res = answer(req, ctx);
        if (draining()) {
            res.keep_alive(false);
        }
        return res;
    }

private:
    auto answer(const https::request& req, const https::request_context& ctx) -> https::response {
        namespace http = boost::beast::http;
        const std::string_view target(req.target().data(), req.target().size());
        const auto roles = _config.roles.to_string();
        if (req.method() == http::verb::get && target == "/") {
            auto res = draining()
                           ? gateway_detail::text_reply(http::status::service_unavailable,
                                                        req.version(), "draining\n")
                           : gateway_detail::text_reply(
                                 http::status::ok, req.version(),
                                 "healthy: dynamodb." + _config.front.region + ".amazonaws.com ");
            res.set(k_roles_header, roles);
            return res;
        }
        if (target == handoff::k_drain_path) {
            if (req.method() != http::verb::post ||
                !handoff::signed_by_secret(req, handoff::k_drain_path,
                                           _config.cluster.forward_secret)) {
                return gateway_detail::text_reply(http::status::forbidden, req.version(),
                                                  "refused\n");
            }
            begin_drain();
            return gateway_detail::text_reply(http::status::accepted, req.version(), "draining\n");
        }
        if (target.starts_with(handoff::k_prefix)) {
            return gateway_detail::not_executed_reply(
                req.version(), "this node runs no DynamoDB front end (roles " + roles + ")");
        }
        if (target == k_forward_path || target == k_strong_forward_path) {
            auto res = gateway_detail::text_reply(
                http::status::not_found, req.version(),
                "this node holds no DynamoDB data (roles " + roles + ")\n");
            res.set(k_roles_header, roles);
            return res;
        }
        if (!_ready.load(std::memory_order_acquire)) {
            https::response res{http::status::service_unavailable, req.version()};
            res.prepare_payload();
            return res;
        }
        return gateway_detail::relay_call(*_front, *_relay, to_front_end_request(req, ctx),
                                          req.version(), _log);
    }

    gateway_config _config;
    authorizer _auth;
    std::function<void(bool, std::string_view)> _log;
    relay_transport _transport;
    std::unique_ptr<front_end_relay> _relay;
    std::unique_ptr<front_end<authorizer>> _front;
    std::atomic<bool> _ready{false};
    std::atomic<bool> _draining{false};
    std::atomic<std::uint64_t> _in_flight{0};
    std::unique_ptr<https::server> _server;
};

}  // namespace kythira::dynamodb
