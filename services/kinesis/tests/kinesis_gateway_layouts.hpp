// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The gateway apart from the front end, in process
// (`.kiro/specs/kinesis-independent-layers/` task 8):
//
// - `loopback_front_end` serves one front end's front-end API to gateways
//   on a loopback listener, as a node with the `front_end` role does.
// - `gateway_apart` is a gateway without a front end that hands every
//   call it is given to such front ends over the real internal transport.
//
// Kept out of kinesis_layouts.hpp, which every layout suite includes: the
// HTTPS listener and peer client these instantiate are what made that
// header expensive to compile. Only the gateway tests include this one.

#include "kinesis_layouts.hpp"

#include <kythira/kinesis/kinesis_authenticated_call.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_gateway.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/layer_identity.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kinesis::test {

/// A Kinesis request as the gateway's listener hands it over.
[[nodiscard]] inline auto to_https(const front_end_request& r) -> https::request {
    https::request req;
    req.method(boost::beast::http::string_to_verb(r._method));
    req.target(r._query.empty() ? r._path : r._path + "?" + r._query);
    req.version(11);
    for (const auto& [k, v] : r._headers) {
        req.set(k, v);
    }
    req.body() = r._body;
    req.prepare_payload();
    return req;
}

[[nodiscard]] inline auto from_https(const https::response& res) -> aws_json::http_response {
    aws_json::http_response out;
    out.status = res.result_int();
    for (const auto& f : res) {
        out.headers.emplace_back(std::string(f.name_string()), std::string(f.value()));
    }
    out.body = res.body();
    return out;
}

namespace layout_detail {

/// A gateway over `fe` with no Raft proposals of its own: the layouts here
/// hand every call to a front end, local or remote.
template<typename FrontEnd>
auto make_gateway(FrontEnd& fe, std::string secret) -> std::unique_ptr<gateway<FrontEnd>> {
    return std::make_unique<gateway<FrontEnd>>(
        fe,
        [](const std::string&, const std::vector<std::byte>&, admission) {
            return std::optional<apply_result>{};
        },
        nullptr, std::move(secret));
}

}  // namespace layout_detail

/// One front end serving gateways on a loopback listener: what a node with
/// the `front_end` role and no `gateway` role runs (task 8). `FrontEnd` is
/// the test's `front_end<Authorizer>`; `lease` executes Lease API calls.
template<typename FrontEnd> class loopback_front_end {
public:
    using lease_fn = std::function<aws_json::http_response(const authenticated_call&)>;

    loopback_front_end(FrontEnd& fe, lease_fn lease, std::function<std::string()> metrics = {},
                       std::string secret = std::string(layout_detail::k_secret),
                       layers::role_set roles = layers::role_set::parse("front_end"))
        : _fe(fe), _gateway(layout_detail::make_gateway(fe, std::move(secret))) {
        front_end_routes routes;
        routes._execute = [this](authenticated_call& c) {
            auto r = _fe.execute(c);
            return front_end_routes::execution{std::move(r._response), std::move(r._events)};
        };
        routes._lease = std::move(lease);
        routes._metrics = std::move(metrics);
        _routes = routes;
        _server_api = std::make_unique<front_end_server>(std::move(routes));
        _gateway->set_roles(roles);
        _gateway->set_front_end_server(_server_api.get());
        start();
    }

    loopback_front_end(const loopback_front_end&) = delete;
    auto operator=(const loopback_front_end&) -> loopback_front_end& = delete;
    loopback_front_end(loopback_front_end&&) = delete;
    auto operator=(loopback_front_end&&) -> loopback_front_end& = delete;
    ~loopback_front_end() { stop(); }

    /// Stops listening: gateways can no longer reach it (a crash).
    void stop() {
        if (_listener) {
            _listener->stop();
            _listener.reset();
        }
    }

    /// Stops and comes back on the same port as a new process would: its
    /// event-stream sessions are gone.
    void restart() {
        stop();
        _server_api = std::make_unique<front_end_server>(_routes);
        _gateway->set_front_end_server(_server_api.get());
        start();
    }

    /// Listens again on the same port, after `stop`.
    void start() {
        https::server_config sc;
        sc.bind_address = "127.0.0.1";
        sc.port = _port;
        sc.insecure_plaintext = true;
        sc.max_body_bytes = std::uint64_t{8} * 1024 * 1024;
        _listener = std::make_unique<https::server>(
            sc, [this](const https::request& req, const https::request_context& ctx) {
                return _gateway->handle(req, ctx);
            });
        _listener->start();
        _port = _listener->port();
    }

    [[nodiscard]] auto address() const -> std::string {
        return "127.0.0.1:" + std::to_string(_port);
    }

    [[nodiscard]] auto api() -> front_end_server& { return *_server_api; }
    [[nodiscard]] auto node() -> gateway<FrontEnd>& { return *_gateway; }

    /// Authenticated calls this front end executed.
    [[nodiscard]] auto executed() const -> std::uint64_t { return _server_api->stats()._calls; }

private:
    FrontEnd& _fe;
    front_end_routes _routes;
    std::unique_ptr<front_end_server> _server_api;
    std::unique_ptr<gateway<FrontEnd>> _gateway;
    std::unique_ptr<https::server> _listener;
    std::uint16_t _port = 0;
};

/// A gateway without a front end (KINESIS_ROLES=gateway, task 8): it
/// frames, decodes and verifies each request with `Authorizer` and hands
/// the call to one of `front_ends` by affinity over the real internal
/// transport. Requests are handed to it in-process (`handle`, `stream`), as
/// its listener would.
template<typename Authorizer> class gateway_apart {
public:
    using front_end_type = front_end<Authorizer>;

    gateway_apart(Authorizer& auth, std::vector<std::string> front_ends,
                  std::string secret = std::string(layout_detail::k_secret),
                  std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
        : _auth(auth),
          _peers(peer_client_config{._tls = false, ._ca_path = {}, ._timeout = timeout}),
          _fe(front_end_config{}, auth),
          _remote(std::make_shared<remote_front_ends>(
              std::move(front_ends), make_http_front_end_transport(_peers, secret))),
          _gateway(layout_detail::make_gateway(_fe, std::move(secret))) {
        _fe.set_operations_served_elsewhere(kinesis_service<data_access>::k_operations);
        _gateway->set_roles(layers::role_set::parse("gateway"));
        _gateway->set_remote_front_ends(_remote);
        _gateway->set_lease_authenticator([this](const front_end_request& r) {
            return authenticate_lease_request(_auth, front_end_config{}, r);
        });
    }

    [[nodiscard]] auto handle(const front_end_request& r, const https::request_context& ctx = {})
        -> aws_json::http_response {
        return from_https(_gateway->handle(to_https(r), ctx));
    }

    [[nodiscard]] auto node() -> gateway<front_end_type>& { return *_gateway; }
    [[nodiscard]] auto link() -> remote_front_ends& { return *_remote; }

private:
    Authorizer& _auth;
    peer_client _peers;
    front_end_type _fe;
    std::shared_ptr<remote_front_ends> _remote;
    std::unique_ptr<gateway<front_end_type>> _gateway;
};

}  // namespace kythira::kinesis::test
