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
/// forwarding node reports to its client as retryable.

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
        return listener_detail::to_beast(
            _front_end.handle(listener_detail::to_sqs_request(req, ctx)), req.version());
    }

private:
    FrontEnd& _front_end;
    std::string _secret;
    local_proposer _propose;
    clock_fn _clock;

    auto forwarded(const https::request& req) -> https::response {
        using listener_detail::plain;
        if (_secret.empty() || !_propose) {
            return plain(404, "not found\n", req.version());
        }
        if (req.method() != boost::beast::http::verb::post) {
            return plain(405, "POST only\n", req.version());
        }
        const auto header = req[forward::k_header];
        if (!forward::verify(_secret, std::string_view(header.data(), header.size()), req.body(),
                             _clock())) {
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
