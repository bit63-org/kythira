// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_gateway.hpp
/// @brief The gateway's HTTP surface over the shared Beast HTTPS server
///        (`.kiro/specs/kinesis-compatible-streams/` task 6, design "Front
///        end: Beast host, forwarding, replica reads").
///
/// One listener carries six things:
///
/// - `POST /` and everything else: the Kinesis API, handed to the front end
///   (`kinesis_front_end.hpp`) as a `front_end_request`.
/// - `POST /_kythira/kinesis/v1/propose`: a write another gateway forwards
///   to this node because it leads the key's group (`kinesis_forward.hpp`
///   has the wire). Proposed locally, never forwarded again.
/// - `GET /_kythira/kinesis/v1/segment?stream=&first=&length=`: the raw
///   bytes of a local segment, for a replica restoring a snapshot or
///   reading a segment it lacks (`record_segment_store::fetch_segment`
///   checks them against the descriptor's SHA-256, so the peer is not
///   trusted for content). Signed like a forwarded write, over the path and
///   query, so a segment cannot be read by anyone without the cluster
///   secret.
/// - `POST /_kythira/kinesis/v1/volume`: a volume API request from a data
///   node whose record segments live on this segment node (task 10 of
///   kinesis-independent-layers), signed like a forwarded write.
/// - `POST /_kythira/kinesis/v1/txn`: a resharding transaction op (task 11)
///   another gateway's coordinator sends to the leader of the keys' group,
///   submitted here with `submit_txn` when the composition root sets a
///   transaction handler. Signed like a forwarded write.
/// - `POST /_kythira/kinesis/v2/...`: the data-layer API
///   (`kinesis_data_api.hpp`, kinesis-independent-layers task 6) a front
///   end without a replica calls, when the composition root sets its deps.
///   Admitted when signed like a forwarded write over the path and body,
///   or when the caller presents a layer identity the root's guard allows.
/// - `GET /healthz`: 200 while the process serves.
/// - `GET /metrics`: this node's per-stream and per-shard metrics in the
///   Prometheus text format (`kinesis_metrics.hpp`), when the composition
///   root sets a metrics handler (`KINESIS_METRICS=true`); otherwise the
///   front end, which refuses it. Unauthenticated, like `/healthz`, for a
///   scraper: it names streams and accounts, so it is off by default.
/// - `/v1/leases/…`: the Lease API (`kinesis_lease_api.hpp`), when the
///   composition root sets a lease handler; otherwise the front end, which
///   refuses it.
///
/// The internal endpoints answer 404 when no forwarding secret is
/// configured: a single-node gateway has no peers to listen to.
///
/// A node without the `gateway` role (`KINESIS_ROLES=data,segments`,
/// kinesis-independent-layers task 4) keeps the internal endpoints,
/// `/healthz` and `/metrics`, and answers the Kinesis API, the Lease API
/// and `SubscribeToShard` with a 404 naming its roles. `/healthz` and that
/// refusal carry the roles in `x-kythira-roles`.
///
/// This file also holds the client halves: the forwarder
/// `raft_stream_cluster` calls on a follower, and the segment fetch
/// transport.

#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_forward.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_leases.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/layer_identity.hpp>
#include <raft/layer_roles.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/remote_segment_store.hpp>
#include <raft/segment_volume_service.hpp>

#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

inline constexpr std::string_view k_segment_path = "/_kythira/kinesis/v1/segment";
/// The volume API a data node without the `segments` role writes its
/// record segments through (kinesis-independent-layers task 10): `POST`,
/// the body one `segment_volume_service` request, signed with the
/// forwarding secret over `volume_signed_text`.
inline constexpr std::string_view k_volume_path = "/_kythira/kinesis/v1/volume";

/// What a volume call's signature covers: the path, then the body, so a
/// signed volume request cannot be replayed as a forwarded write or a
/// transaction op.
[[nodiscard]] inline auto volume_signed_text(std::string_view body) -> std::string {
    std::string out(k_volume_path);
    out.push_back('\n');
    out.append(body);
    return out;
}
inline constexpr std::string_view k_health_path = "/healthz";
inline constexpr std::string_view k_metrics_path = "/metrics";
/// The node's role set, on `/healthz` and on a refusal for want of one.
inline constexpr std::string_view k_roles_header = "x-kythira-roles";

/// Proposes a forwarded command on this node without forwarding it again
/// (`raft_stream_cluster::propose_local`).
using local_proposer = std::function<std::optional<apply_result>(
    const std::string& key, const std::vector<std::byte>& command, admission mode)>;

namespace gateway_detail {

[[nodiscard]] inline auto hex_value(char c) -> int {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/// RFC 3986 unreserved characters pass; every other byte is %XX.
[[nodiscard]] inline auto percent_encode(std::string_view s) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4U]);
            out.push_back(hex[c & 0xFU]);
        }
    }
    return out;
}

[[nodiscard]] inline auto percent_decode(std::string_view s) -> std::optional<std::string> {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '%') {
            out.push_back(s[i]);
            continue;
        }
        if (i + 2 >= s.size()) {
            return std::nullopt;
        }
        const auto hi = hex_value(s[i + 1]);
        const auto lo = hex_value(s[i + 2]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
    }
    return out;
}

/// The value of `name` in `query` (`a=1&b=2`), decoded; nullopt when absent
/// or malformed.
[[nodiscard]] inline auto query_param(std::string_view query, std::string_view name)
    -> std::optional<std::string> {
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto pair = query.substr(0, amp);
        const auto eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == name) {
            return percent_decode(pair.substr(eq + 1));
        }
        if (amp == std::string_view::npos) {
            break;
        }
        query.remove_prefix(amp + 1);
    }
    return std::nullopt;
}

[[nodiscard]] inline auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > 19) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return v;
}

/// The operations whose answers are event streams.
[[nodiscard]] inline auto is_streaming_target(std::string_view target) -> bool {
    return target == "Kinesis_20131202.SubscribeToShard";
}

[[nodiscard]] inline auto to_front_end_request(const https::request& req,
                                               const https::request_context& ctx)
    -> front_end_request {
    front_end_request r;
    r._method = std::string(req.method_string());
    const std::string_view target = req.target();
    const auto q = target.find('?');
    r._path = std::string(target.substr(0, q));
    r._query = q == std::string_view::npos ? std::string() : std::string(target.substr(q + 1));
    for (const auto& f : req) {
        r._headers.emplace_back(std::string(f.name_string()), std::string(f.value()));
    }
    r._body = req.body();
    r._source_ip = ctx.peer_address;
    r._secure = ctx.tls;
    return r;
}

[[nodiscard]] inline auto reply(const https::request& req, unsigned status, std::string body,
                                std::string_view content_type) -> https::response {
    https::response res{static_cast<boost::beast::http::status>(status), req.version()};
    res.set(boost::beast::http::field::content_type, content_type);
    res.keep_alive(req.keep_alive());
    res.body() = std::move(body);
    res.prepare_payload();
    return res;
}

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(s.size());
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

[[nodiscard]] inline auto to_string(std::span<const std::byte> b) -> std::string {
    std::string out;
    out.reserve(b.size());
    for (const auto c : b) {
        out.push_back(static_cast<char>(c));
    }
    return out;
}

}  // namespace gateway_detail

/// The query a segment fetch sends, and what its signature covers.
[[nodiscard]] inline auto segment_query(std::string_view stream, std::uint64_t first_seq,
                                        std::uint64_t length) -> std::string {
    return "stream=" + gateway_detail::percent_encode(stream) +
           "&first=" + std::to_string(first_seq) + "&length=" + std::to_string(length);
}

/// What a segment fetch's `x-kythira-forward` signs: path and query, so it
/// can never pass for a forwarded write's body (whose first four bytes are
/// a key length).
[[nodiscard]] inline auto segment_signed_text(std::string_view query) -> std::string {
    return std::string(k_segment_path) + "?" + std::string(query);
}

/// Answers a volume API request on the internal listener: a `POST` whose
/// body `secret` signs, handed to `volumes`. 404 without a secret (a
/// single node has no peers to serve); the service's own answer, with its
/// status inside, otherwise.
[[nodiscard]] inline auto serve_volume(const https::request& req, std::string_view secret,
                                       segment_volume_service& volumes,
                                       std::chrono::system_clock::time_point now)
    -> https::response {
    if (secret.empty()) {
        return gateway_detail::reply(req, 404, "not found\n", "text/plain");
    }
    if (req.method() != boost::beast::http::verb::post) {
        return gateway_detail::reply(req, 405, "method not allowed\n", "text/plain");
    }
    const auto it = req.find(forward::k_header);
    if (it == req.end() ||
        !forward::verify(secret, it->value(), volume_signed_text(req.body()), now)) {
        return gateway_detail::reply(req, 403, "bad or stale forwarding signature\n", "text/plain");
    }
    const auto request = gateway_detail::to_bytes(req.body());
    return gateway_detail::reply(req, 200, gateway_detail::to_string(volumes.handle(request)),
                                 "application/cbor");
}

struct gateway_stats {
    std::atomic<std::uint64_t> _forwarded_in{0};
    std::atomic<std::uint64_t> _forward_refused{0};
    std::atomic<std::uint64_t> _segments_served{0};
    std::atomic<std::uint64_t> _data_api_served{0};
};

template<typename FrontEnd> class gateway {
public:
    using clock_fn = std::function<std::chrono::system_clock::time_point()>;
    using lease_handler = std::function<aws_json::http_response(const front_end_request&)>;
    /// Submits a transaction op locally: the encoded `txn_result`, or
    /// nullopt when this node cannot (not the leader, timed out).
    using txn_handler = std::function<std::optional<std::vector<std::byte>>(
        const std::vector<std::string>& keys, const std::vector<std::byte>& envelope)>;

    gateway(
        FrontEnd& front_end, local_proposer propose, const segment_store* store,
        std::string forward_secret,
        clock_fn clock = [] { return std::chrono::system_clock::now(); })
        : _front_end(front_end),
          _propose(std::move(propose)),
          _store(store),
          _secret(std::move(forward_secret)),
          _clock(std::move(clock)) {}

    [[nodiscard]] auto handle(const https::request& req, const https::request_context& ctx)
        -> https::response {
        namespace http = boost::beast::http;
        if (auto internal = handle_internal_route(req, ctx)) {
            return std::move(*internal);
        }
        const std::string_view target = req.target();
        const auto path = target.substr(0, target.find('?'));
        if (_metrics && path == k_metrics_path && req.method() == http::verb::get) {
            return gateway_detail::reply(req, 200, _metrics(), "text/plain; version=0.0.4");
        }
        if (!_roles.has(layers::role::gateway)) {
            return not_a_gateway(req);
        }
        const auto r = _leases && path.starts_with(k_lease_path_prefix)
                           ? _leases(gateway_detail::to_front_end_request(req, ctx))
                           : _front_end.handle(gateway_detail::to_front_end_request(req, ctx));
        https::response res{static_cast<http::status>(r.status), req.version()};
        for (const auto& [k, v] : r.headers) {
            res.set(k, v);
        }
        res.keep_alive(req.keep_alive());
        res.body() = r.body;
        res.prepare_payload();
        return res;
    }

    /// The internal listener (`KINESIS_INTERNAL_LISTEN`): the internal
    /// routes and `/healthz`, and nothing else.
    [[nodiscard]] auto handle_internal(const https::request& req, const https::request_context& ctx)
        -> https::response {
        if (auto internal = handle_internal_route(req, ctx)) {
            return std::move(*internal);
        }
        return gateway_detail::reply(req, 404, "not found\n", "text/plain");
    }

    /// The streaming route (`https::server::set_stream_handler`): takes
    /// `SubscribeToShard` (task 13) and passes everything else on. Its
    /// events go out as the body, one event-stream message per pull; an
    /// answer without events (a refusal) goes out whole.
    [[nodiscard]] auto stream(const https::request& req, const https::request_context& ctx)
        -> std::optional<https::streaming_response> {
        namespace http = boost::beast::http;
        // Without the gateway role, handle() refuses it whole.
        if (req.method() != http::verb::post ||
            !gateway_detail::is_streaming_target(req["x-amz-target"]) ||
            !_roles.has(layers::role::gateway)) {
            return std::nullopt;
        }
        auto r = _front_end.handle_streaming(gateway_detail::to_front_end_request(req, ctx));
        https::streaming_response out;
        out.head = https::response{static_cast<http::status>(r._response.status), req.version()};
        for (const auto& [k, v] : r._response.headers) {
            out.head.set(k, v);
        }
        if (!r._events) {
            auto body = std::make_shared<std::string>(std::move(r._response.body));
            out.next = [body](std::string& chunk) {
                chunk = std::move(*body);
                return false;
            };
            return out;
        }
        // A last message can come with `_done`: send it, then end.
        out.next = [events = r._events, done = false](std::string& chunk) mutable {
            if (done) {
                chunk.clear();
                return false;
            }
            auto p = events->next(std::chrono::milliseconds(500));
            chunk = std::move(p._message);
            done = p._done;
            return !done || !chunk.empty();
        };
        out.cancel = [events = r._events] { events->cancel(); };
        return out;
    }

    [[nodiscard]] auto stats() const noexcept -> const gateway_stats& { return _stats; }

    /// Serve the Lease API under `k_lease_path_prefix`. Set before the
    /// listener starts.
    void set_lease_handler(lease_handler h) { _leases = std::move(h); }

    /// Serve transaction ops on `forward::k_txn_path`. Set before the
    /// listener starts.
    void set_txn_handler(txn_handler h) { _txn = std::move(h); }

    /// Serve `k_volume_path` from `volumes`: this node holds volumes for
    /// data nodes without the `segments` role. Set before the listener
    /// starts; it must outlive the gateway.
    void set_volume_service(segment_volume_service* volumes) { _volumes = volumes; }

    /// Serve `k_metrics_path` with what `h` renders. Set before the
    /// listener starts.
    void set_metrics_handler(std::function<std::string()> h) { _metrics = std::move(h); }

    /// Serve the data-layer API on `data_api::k_prefix` from `deps`. Set
    /// before the listener starts.
    void set_data_api(data_api_deps deps) { _data_api = std::move(deps); }

    /// Admit data-layer API callers presenting a layer identity this guard
    /// allows (its rules name the routes and roles), beside those signing
    /// with the forward secret. Set before the listener starts.
    void set_layer_guard(std::shared_ptr<const layers::route_guard> guard) {
        _guard = std::move(guard);
    }

    /// The layers this node runs (all four unless set). Set before the
    /// listener starts.
    void set_roles(layers::role_set roles) {
        _roles = roles;
        _roles_text = roles.to_string();
    }

    [[nodiscard]] auto roles() const noexcept -> layers::role_set { return _roles; }

private:
    FrontEnd& _front_end;
    layers::role_set _roles{layers::role_set::all()};
    std::string _roles_text{layers::role_set::all().to_string()};
    std::function<std::string()> _metrics;
    lease_handler _leases;
    txn_handler _txn;
    segment_volume_service* _volumes = nullptr;
    std::optional<data_api_deps> _data_api;
    std::shared_ptr<const layers::route_guard> _guard;
    local_proposer _propose;
    const segment_store* _store;
    std::string _secret;
    clock_fn _clock;
    gateway_stats _stats;

    /// A client call to a node that runs no gateway: 404, in the API's own
    /// error shape, naming the node's roles so an operator sees at once
    /// that the load balancer points at the wrong layer.
    [[nodiscard]] auto not_a_gateway(const https::request& req) const -> https::response {
        boost::json::object body;
        body["__type"] = "LayerNotServed";
        body["message"] = "This node runs " + _roles_text +
                          " and does not serve the Kinesis API. Send API calls to a gateway.";
        auto res = gateway_detail::reply(req, 404, boost::json::serialize(body),
                                         "application/x-amz-json-1.1");
        res.set(k_roles_header, _roles_text);
        return res;
    }

    /// `/healthz` and the routes between nodes, or nothing for anything
    /// else.
    auto handle_internal_route(const https::request& req, const https::request_context& ctx)
        -> std::optional<https::response> {
        namespace http = boost::beast::http;
        const std::string_view target = req.target();
        const auto q = target.find('?');
        const auto path = target.substr(0, q);
        const auto query = q == std::string_view::npos ? std::string_view() : target.substr(q + 1);
        if (path == k_health_path && req.method() == http::verb::get) {
            auto res = gateway_detail::reply(req, 200, "ok\n", "text/plain");
            res.set(k_roles_header, _roles_text);
            return res;
        }
        if (path == forward::k_path) {
            return propose(req);
        }
        if (path == k_segment_path) {
            return segment(req, query);
        }
        if (path == forward::k_txn_path) {
            return txn(req);
        }
        if (path == k_volume_path) {
            if (_volumes == nullptr) {
                return gateway_detail::reply(req, 404, "not found\n", "text/plain");
            }
            return serve_volume(req, _secret, *_volumes, _clock());
        }
        if (data_api::is_data_api_path(path)) {
            return data_api_route(req, ctx, path);
        }
        return std::nullopt;
    }

    auto data_api_route(const https::request& req, const https::request_context& ctx,
                        std::string_view path) -> https::response {
        if (!_data_api) {
            return gateway_detail::reply(req, 404, "not found\n", "text/plain");
        }
        const bool signed_ok =
            !_secret.empty() && signed_by_peer(req, data_api::signed_text(path, req.body()));
        const bool identity_ok =
            !signed_ok && _guard && _guard->check(req, ctx).kind == layers::verdict_kind::allowed;
        const auto a = serve_data_api(*_data_api, signed_ok || identity_ok,
                                      std::string_view(req.method_string()), path, req.body());
        if (!a) {
            return gateway_detail::reply(req, 404, "not found\n", "text/plain");
        }
        if (a->_status == data_api::k_refused) {
            ++_stats._forward_refused;
        } else {
            ++_stats._data_api_served;
        }
        return gateway_detail::reply(req, a->_status, a->_body, "application/octet-stream");
    }

    auto refuse(const https::request& req, unsigned status, std::string_view why)
        -> https::response {
        ++_stats._forward_refused;
        return gateway_detail::reply(req, status, std::string(why) + "\n", "text/plain");
    }

    [[nodiscard]] auto signed_by_peer(const https::request& req, std::string_view text) const
        -> bool {
        const auto it = req.find(forward::k_header);
        return it != req.end() && forward::verify(_secret, it->value(), text, _clock());
    }

    auto propose(const https::request& req) -> https::response {
        if (_secret.empty()) {
            return gateway_detail::reply(req, 404, "not found\n", "text/plain");
        }
        if (req.method() != boost::beast::http::verb::post) {
            return refuse(req, 405, "method not allowed");
        }
        if (!signed_by_peer(req, req.body())) {
            return refuse(req, 403, "bad or stale forwarding signature");
        }
        auto p = forward::decode_body(req.body());
        if (!p) {
            return refuse(req, 400, "malformed proposal");
        }
        ++_stats._forwarded_in;
        const auto r = _propose ? _propose(p->_key, p->_command, p->_admission) : std::nullopt;
        if (!r) {
            // Not the leader any more, or no commit in time: the first node
            // fails the write as unavailable and the client retries.
            return refuse(req, 503, "not committed here");
        }
        return gateway_detail::reply(req, 200, gateway_detail::to_string(encode_result(*r)),
                                     "application/octet-stream");
    }

    auto txn(const https::request& req) -> https::response {
        if (_secret.empty() || !_txn) {
            return gateway_detail::reply(req, 404, "not found\n", "text/plain");
        }
        if (req.method() != boost::beast::http::verb::post) {
            return refuse(req, 405, "method not allowed");
        }
        if (!signed_by_peer(req, req.body())) {
            return refuse(req, 403, "bad or stale forwarding signature");
        }
        auto op = forward::decode_txn_body(req.body());
        if (!op) {
            return refuse(req, 400, "malformed transaction op");
        }
        ++_stats._forwarded_in;
        const auto r = _txn(op->_keys, op->_envelope);
        if (!r) {
            return refuse(req, 503, "not submitted here");
        }
        return gateway_detail::reply(req, 200, gateway_detail::to_string(*r),
                                     "application/octet-stream");
    }

    auto segment(const https::request& req, std::string_view query) -> https::response {
        if (_secret.empty() || _store == nullptr) {
            return gateway_detail::reply(req, 404, "not found\n", "text/plain");
        }
        if (req.method() != boost::beast::http::verb::get) {
            return refuse(req, 405, "method not allowed");
        }
        if (!signed_by_peer(req, segment_signed_text(query))) {
            return refuse(req, 403, "bad or stale forwarding signature");
        }
        const auto stream = gateway_detail::query_param(query, "stream");
        const auto first = gateway_detail::query_param(query, "first");
        const auto length = gateway_detail::query_param(query, "length");
        const auto first_seq = first ? gateway_detail::parse_u64(*first) : std::nullopt;
        const auto bytes = length ? gateway_detail::parse_u64(*length) : std::nullopt;
        if (!stream || stream->empty() || !first_seq || !bytes) {
            return refuse(req, 400, "malformed segment request");
        }
        auto data = _store->read_segment_bytes(*stream, *first_seq, *bytes);
        if (!data) {
            return gateway_detail::reply(req, 404, "no such segment here\n", "text/plain");
        }
        ++_stats._segments_served;
        return gateway_detail::reply(req, 200, gateway_detail::to_string(*data),
                                     "application/octet-stream");
    }
};

/// The forwarder `raft_stream_cluster` takes: posts the command to the
/// leader's gateway, found by `address_of`.
template<typename NodeId>
[[nodiscard]] auto make_http_forwarder(
    const peer_client& client, std::string secret,
    std::function<std::optional<std::string>(const NodeId&)> address_of,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) {
    return [&client, secret = std::move(secret), address_of = std::move(address_of),
            clock = std::move(clock)](const NodeId& leader, const std::string& key,
                                      const std::vector<std::byte>& command,
                                      admission mode) -> std::optional<apply_result> {
        if (secret.empty()) {
            return std::nullopt;
        }
        const auto address = address_of(leader);
        if (!address) {
            return std::nullopt;
        }
        auto body = forward::encode_body({._key = key, ._command = command, ._admission = mode});
        const auto signature = forward::sign(secret, body, clock());
        const auto res = client.request(*address, boost::beast::http::verb::post, forward::k_path,
                                        {{std::string(forward::k_header), signature},
                                         {"Content-Type", "application/octet-stream"}},
                                        std::move(body));
        if (!res || res->_status != 200) {
            return std::nullopt;
        }
        try {
            return decode_result(gateway_detail::to_bytes(res->_body));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    };
}

/// The transaction-op forwarder the resharding coordinator uses on a node
/// that does not lead the keys' group: posts the op to the leader's
/// gateway, found by `address_of`; the encoded `txn_result`, or nullopt.
template<typename NodeId>
[[nodiscard]] auto make_http_txn_forwarder(
    const peer_client& client, std::string secret,
    std::function<std::optional<std::string>(const NodeId&)> address_of,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) {
    return [&client, secret = std::move(secret), address_of = std::move(address_of),
            clock = std::move(clock)](
               const NodeId& leader, const std::vector<std::string>& keys,
               const std::vector<std::byte>& envelope) -> std::optional<std::vector<std::byte>> {
        if (secret.empty()) {
            return std::nullopt;
        }
        const auto address = address_of(leader);
        if (!address) {
            return std::nullopt;
        }
        auto body = forward::encode_txn_body({._keys = keys, ._envelope = envelope});
        const auto signature = forward::sign(secret, body, clock());
        const auto res =
            client.request(*address, boost::beast::http::verb::post, forward::k_txn_path,
                           {{std::string(forward::k_header), signature},
                            {"Content-Type", "application/octet-stream"}},
                           std::move(body));
        if (!res || res->_status != 200) {
            return std::nullopt;
        }
        return gateway_detail::to_bytes(res->_body);
    };
}

/// The segment store's fetch transport: `peer` is the gateway's
/// `host:port`.
[[nodiscard]] inline auto make_segment_transport(
    const peer_client& client, std::string secret,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) -> segment_store::fetch_transport {
    return [&client, secret = std::move(secret), clock = std::move(clock)](
               const std::string& peer, const std::string& stream, std::uint64_t first_seq,
               std::uint64_t length) -> std::optional<std::vector<std::byte>> {
        if (secret.empty()) {
            return std::nullopt;
        }
        const auto query = segment_query(stream, first_seq, length);
        const auto signature = forward::sign(secret, segment_signed_text(query), clock());
        const auto res = client.request(peer, boost::beast::http::verb::get,
                                        std::string(k_segment_path) + "?" + query,
                                        {{std::string(forward::k_header), signature}});
        if (!res || res->_status != 200) {
            return std::nullopt;
        }
        return gateway_detail::to_bytes(res->_body);
    };
}

/// A data node's volume transport: posts each volume API request to the
/// segment node at `endpoint` (`host:port`), signed with `secret`;
/// `nullopt` when the node cannot be reached or refuses the call outright
/// (which `remote_segment_store` treats as an unreachable volume).
[[nodiscard]] inline auto make_volume_transport(
    const peer_client& client, std::string secret, std::string endpoint,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) -> segment_volume_transport {
    return [&client, secret = std::move(secret), endpoint = std::move(endpoint),
            clock = std::move(clock)](
               std::vector<std::byte> request) -> std::optional<std::vector<std::byte>> {
        if (secret.empty()) {
            return std::nullopt;
        }
        auto body = gateway_detail::to_string(request);
        const auto signature = forward::sign(secret, volume_signed_text(body), clock());
        const auto res = client.request(
            endpoint, boost::beast::http::verb::post, k_volume_path,
            {{std::string(forward::k_header), signature}, {"Content-Type", "application/cbor"}},
            std::move(body));
        if (!res || res->_status != 200) {
            return std::nullopt;
        }
        return gateway_detail::to_bytes(res->_body);
    };
}

}  // namespace kythira::kinesis
