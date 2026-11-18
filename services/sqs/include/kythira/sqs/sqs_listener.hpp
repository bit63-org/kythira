// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_listener.hpp
/// @brief The SQS API over core's Beast HTTPS server
///        (`.kiro/specs/sqs-compatible-queues/` task 4).
///
/// `sqs_http_handler` is the `https::handler` an SQS listener runs: it turns
/// a Beast request into the transport-free `sqs_request` the front end
/// takes (the target split into path and query, every header, the peer
/// address for `aws:SourceIp`, whether TLS carried it) and the front end's
/// answer back into a Beast response. Both protocols arrive on `/` (JSON
/// by `X-Amz-Target`, query by form or GET); a query request may also name
/// its queue by path, which the codec resolves.
///
/// The same listener serves node-to-node forwarding (`sqs_forward.hpp`) at
/// its own path, only when a forwarding secret is set: the HMAC is checked
/// before the body is read as an entry, and the entry is proposed locally,
/// never forwarded again. 503 means "not committed here", which the
/// forwarding node reports to its client as retryable. A data node also
/// answers front ends' named reads (`sqs_data_access.hpp`) at
/// `/_kythira/sqs/v1/query`, authenticated the same way; 503 there means
/// "no replica of that group here".

#include <kythira/sqs/sqs_availability.hpp>
#include <kythira/sqs/sqs_data_access.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_front_end.hpp>

#include <raft/beast_https_server.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

/// Answers a front end's named read from this node's replica, or nullopt.
using local_querier = std::function<std::optional<data_answer>(const data_query&)>;

/// Proposes a forwarded entry here; what `apply()` returned, or nullopt.
using local_proposer = std::function<std::optional<std::vector<std::byte>>(
    const std::string& key, std::vector<std::byte> entry)>;

namespace listener_detail {

[[nodiscard]] inline auto to_sqs_request(const https::request& req,
                                         const https::request_context& ctx) -> sqs_request {
    sqs_request out;
    out._method = std::string(req.method_string());
    const std::string_view target = req.target();
    const auto q = target.find('?');
    out._path = std::string(target.substr(0, q));
    if (q != std::string_view::npos) {
        out._query = std::string(target.substr(q + 1));
    }
    for (const auto& field : req) {
        out._headers.emplace_back(std::string(field.name_string()), std::string(field.value()));
    }
    out._body = req.body();
    out._source_ip = ctx.peer_address;
    out._secure = ctx.tls;
    return out;
}

[[nodiscard]] inline auto to_beast(const aws_json::http_response& r, unsigned version)
    -> https::response {
    https::response out{static_cast<boost::beast::http::status>(r.status), version};
    for (const auto& [k, v] : r.headers) {
        out.set(k, v);
    }
    out.body() = r.body;
    out.prepare_payload();
    return out;
}

[[nodiscard]] inline auto plain(unsigned status, std::string body, unsigned version)
    -> https::response {
    https::response out{static_cast<boost::beast::http::status>(status), version};
    out.set(boost::beast::http::field::content_type, "text/plain");
    out.body() = std::move(body);
    out.prepare_payload();
    return out;
}

}  // namespace listener_detail

/// The handler of an SQS listener. `FrontEnd` is `sqs_front_end<A>`.
template<typename FrontEnd> class sqs_http_handler {
public:
    using clock_fn = std::function<std::chrono::system_clock::time_point()>;
    /// The SNS bridge (`sqs_sns_bridge.hpp`): method, path, body to status
    /// and body.
    using bridge_fn = std::function<std::pair<unsigned, std::string>(
        std::string_view method, std::string_view path, std::string_view body)>;

    /// @param front_end Outlives the handler.
    /// @param forward_secret Empty: the forwarding path answers 404.
    sqs_http_handler(
        FrontEnd& front_end, std::string forward_secret, local_proposer propose,
        clock_fn clock = [] { return std::chrono::system_clock::now(); })
        : _front_end(front_end),
          _secret(std::move(forward_secret)),
          _propose(std::move(propose)),
          _clock(std::move(clock)) {}

    auto operator()(const https::request& req, const https::request_context& ctx)
        -> https::response {
        const std::string_view target = req.target();
        if (target == forward::k_path) {
            return forwarded(req);
        }
        if (target == data_wire::k_query_path) {
            return queried(req);
        }
        if (target == k_availability_path) {
            return availability(req);
        }
        if (!_client_api) {
            return listener_detail::plain(404, "this node serves no SQS API (data role only)\n",
                                          req.version());
        }
        if (_bridge && target.starts_with("/sns-bridge/")) {
            const auto method = req.method_string();
            const auto [status, body] = _bridge(std::string_view(method.data(), method.size()),
                                                target.substr(0, target.find('?')), req.body());
            return listener_detail::plain(status, body, req.version());
        }
        return listener_detail::to_beast(
            _front_end.handle(listener_detail::to_sqs_request(req, ctx)), req.version());
    }

    /// Serves front ends' named reads (`sqs_data_access.hpp`) at
    /// `/_kythira/sqs/v1/query` (set before serving; a data node only).
    void set_local_query(local_querier query) { _query = std::move(query); }

    /// Serves the long-poll wake-up stream (`sqs_availability.hpp`) from
    /// `feed`, holding each call up to `wait` (set before serving; a data
    /// node only). `feed` outlives the handler.
    void set_availability_feed(availability_feed* feed,
                               std::chrono::milliseconds wait = std::chrono::seconds{10}) {
        _feed = feed;
        _feed_wait = wait;
    }

    /// Serves `/sns-bridge/...` through `bridge` (set before serving).
    void set_sns_bridge(bridge_fn bridge) { _bridge = std::move(bridge); }

    /// false: only the internal endpoints answer, every other path 404 (a
    /// node without the front-end role; set before serving).
    void set_client_api(bool on) { _client_api = on; }

private:
    FrontEnd& _front_end;
    bridge_fn _bridge;
    std::string _secret;
    local_proposer _propose;
    local_querier _query;
    availability_feed* _feed = nullptr;
    std::chrono::milliseconds _feed_wait{10000};
    bool _client_api = true;
    clock_fn _clock;

    auto availability(const https::request& req) -> https::response {
        using listener_detail::plain;
        if (_secret.empty() || _feed == nullptr) {
            return plain(404, "not found\n", req.version());
        }
        if (req.method() != boost::beast::http::verb::post) {
            return plain(405, "POST only\n", req.version());
        }
        if (!signed_by_peer(req)) {
            return plain(403, "bad or stale forwarding signature\n", req.version());
        }
        boost::system::error_code ec;
        const auto v = boost::json::parse(req.body(), ec);
        if (ec || !v.is_object()) {
            return plain(400, "malformed availability request\n", req.version());
        }
        const auto batch = _feed->wait(data_wire::str(v.as_object(), "epoch"),
                                       data_wire::u64(v.as_object(), "since"), _feed_wait);
        https::response r{boost::beast::http::status::ok, req.version()};
        r.set(boost::beast::http::field::content_type, "application/json");
        r.body() = encode_availability(batch);
        r.prepare_payload();
        return r;
    }

    /// Whether `req` carries a valid forwarding signature over its body.
    [[nodiscard]] auto signed_by_peer(const https::request& req) const -> bool {
        const auto header = req[forward::k_header];
        return forward::verify(_secret, std::string_view(header.data(), header.size()), req.body(),
                               _clock());
    }

    auto queried(const https::request& req) -> https::response {
        using listener_detail::plain;
        if (_secret.empty() || !_query) {
            return plain(404, "not found\n", req.version());
        }
        if (req.method() != boost::beast::http::verb::post) {
            return plain(405, "POST only\n", req.version());
        }
        if (!signed_by_peer(req)) {
            return plain(403, "bad or stale forwarding signature\n", req.version());
        }
        const auto q = decode_query(req.body());
        if (!q) {
            return plain(400, "malformed query\n", req.version());
        }
        const auto a = _query(*q);
        if (!a) {
            return plain(503, "no replica here\n", req.version());
        }
        https::response r{boost::beast::http::status::ok, req.version()};
        r.set(boost::beast::http::field::content_type, "application/json");
        r.body() = encode_answer(*a);
        r.prepare_payload();
        return r;
    }

    auto forwarded(const https::request& req) -> https::response {
        using listener_detail::plain;
        if (_secret.empty() || !_propose) {
            return plain(404, "not found\n", req.version());
        }
        if (req.method() != boost::beast::http::verb::post) {
            return plain(405, "POST only\n", req.version());
        }
        if (!signed_by_peer(req)) {
            return plain(403, "bad or stale forwarding signature\n", req.version());
        }
        auto p = forward::decode_body(req.body());
        if (!p) {
            return plain(400, "malformed forwarded entry\n", req.version());
        }
        const auto out = _propose(p->_key, std::move(p->_entry));
        if (!out) {
            return plain(503, "not committed here\n", req.version());
        }
        https::response r{boost::beast::http::status::ok, req.version()};
        r.set(boost::beast::http::field::content_type, "application/octet-stream");
        r.body().assign(reinterpret_cast<const char*>(out->data()), out->size());  // NOLINT
        r.prepare_payload();
        return r;
    }
};

}  // namespace kythira::sqs
