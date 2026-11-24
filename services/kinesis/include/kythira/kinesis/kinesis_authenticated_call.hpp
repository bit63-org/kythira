// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_authenticated_call.hpp
/// @brief The call a gateway hands a front end on another node, and both
///        ends of it (`.kiro/specs/kinesis-independent-layers/` task 8,
///        design "Gateway hands over an authenticated call, not the signed
///        request" and "EFO across the gateway", Requirements 4.1-4.6).
///
/// A gateway frames, decodes and verifies a request (`front_end::
/// authenticate`), picks a front end by affinity (`kinesis_affinity.hpp`)
/// and sends it the `authenticated_call`: operation, decoded input, the
/// principal SigV4 proved, the encoding to answer in, and the request's
/// condition keys. The front end authorizes and executes it
/// (`front_end::execute`) and answers in the client's encoding; the
/// gateway passes the answer on unchanged. Five routes on any node with the
/// `front_end` role (its gateway listener, which is also its internal
/// listener when it runs no gateway):
///
///   POST /_kythira/kinesis/fe/v1/call       call -> answer
///   POST /_kythira/kinesis/fe/v1/subscribe  call -> answer, session
///   POST /_kythira/kinesis/fe/v1/pull       session, wait -> messages, done
///   POST /_kythira/kinesis/fe/v1/cancel     session
///   POST /_kythira/kinesis/fe/v1/metrics    -> the front end's /metrics
///
/// Bodies use the catalog codec (`kinesis_catalog.hpp`) the data-layer API
/// uses, behind a version byte; the API input travels as its JSON text,
/// which is how the codec already holds it whatever the client sent (CBOR
/// input is decoded at the gateway). The design names CBOR for the wire;
/// one binary codec for every internal route is the simpler choice and
/// carries the same thing.
///
/// ## Who may call
///
/// The front end takes the principal on trust, so only a gateway may hand
/// one over (Requirement 4.3): a caller presenting a layer identity with
/// the `gateway` role (`layers::route_guard`, rule `k_prefix` ->
/// `gateway`), or, on a cluster that runs without layer identities, one
/// that signs the path and body with the forward secret every node of the
/// cluster shares, as the data-layer API admits. Anything else is refused
/// with 403 before the body is read as a call.
///
/// ## Not executed
///
/// A gateway retries a call on the next front end only when it cannot have
/// run (Requirement 4.4): the connection failed before the request was
/// written, or the front end answered 503 with `x-kythira-not-executed`
/// (it is draining, or runs no front end). A call that was sent and got no
/// answer may have run, so the gateway answers it as InternalFailure, which
/// every Kinesis client retries, as a timeout on a co-located node is
/// answered today.
///
/// ## Event streams
///
/// `SubscribeToShard` holds the client's HTTP/2 stream on the gateway
/// (Requirement 4.5). `subscribe` executes the call on the shard's affinity
/// front end, which keeps the resulting `event_source` as a session and
/// answers its id; the gateway then pulls whole event-stream messages
/// (`pull`, waiting up to half a second for one) and relays them without
/// parsing. The internal stream is a sequence of long polls rather than one
/// chunked response because the internal client is one request, one
/// response, as every other internal route. If a pull fails, or the session
/// is gone (the front end restarted), the gateway ends the client's stream
/// with `InternalFailureException`, the event AWS sends for a retryable
/// failure; the client resubscribes from its continuation sequence number,
/// as it does today when a replica is removed. A session nobody pulls for
/// `_session_idle` is cancelled, so a gateway that died leaks nothing.

#include <kythira/kinesis/kinesis_affinity.hpp>
#include <kythira/kinesis/kinesis_catalog.hpp>
#include <kythira/kinesis/kinesis_errors.hpp>
#include <kythira/kinesis/kinesis_forward.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/model/kinesis_model.hpp>

#include <raft/aws_eventstream.hpp>
#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include <openssl/rand.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis {

namespace front_end_api {

inline constexpr std::string_view k_prefix = "/_kythira/kinesis/fe/v1/";
inline constexpr std::string_view k_call_path = "/_kythira/kinesis/fe/v1/call";
inline constexpr std::string_view k_subscribe_path = "/_kythira/kinesis/fe/v1/subscribe";
inline constexpr std::string_view k_pull_path = "/_kythira/kinesis/fe/v1/pull";
inline constexpr std::string_view k_cancel_path = "/_kythira/kinesis/fe/v1/cancel";
inline constexpr std::string_view k_metrics_path = "/_kythira/kinesis/fe/v1/metrics";
inline constexpr std::uint8_t k_version = 1;

/// On a 503: the call did not run here, so another front end may take it.
inline constexpr std::string_view k_not_executed_header = "x-kythira-not-executed";

inline constexpr unsigned k_ok = 200;
inline constexpr unsigned k_malformed = 400;
inline constexpr unsigned k_refused = 403;
/// No such session (expired, cancelled, or the front end restarted).
inline constexpr unsigned k_no_session = 404;
inline constexpr unsigned k_not_executed = 503;

/// The most messages one pull answers, and about the most bytes.
inline constexpr std::size_t k_max_pull_messages = 64;
inline constexpr std::size_t k_max_pull_bytes = std::size_t{8} * 1024 * 1024;

[[nodiscard]] inline auto is_front_end_api_path(std::string_view path) -> bool {
    return path.starts_with(k_prefix);
}

/// What a call's forward-secret signature covers: the path, then the body,
/// so a signed call cannot be replayed on another route.
[[nodiscard]] inline auto signed_text(std::string_view path, std::string_view body) -> std::string {
    std::string out(path);
    out.push_back('\n');
    out.append(body);
    return out;
}

namespace detail {

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    const auto* p = reinterpret_cast<const std::byte*>(s.data());
    return {p, p + s.size()};
}

[[nodiscard]] inline auto to_string(std::span<const std::byte> b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

inline void put_pairs(codec::writer& w, const std::vector<std::pair<std::string, std::string>>& v) {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& [k, x] : v) {
        w.str(k).str(x);
    }
}

[[nodiscard]] inline auto get_pairs(codec::reader& r)
    -> std::vector<std::pair<std::string, std::string>> {
    const auto n = r.u32();
    std::vector<std::pair<std::string, std::string>> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        auto k = r.str();
        auto v = r.str();
        out.emplace_back(std::move(k), std::move(v));
    }
    return out;
}

inline void put_strs(codec::writer& w, const std::vector<std::string>& v) {
    w.u32(static_cast<std::uint32_t>(v.size()));
    for (const auto& x : v) {
        w.str(x);
    }
}

[[nodiscard]] inline auto get_strs(codec::reader& r) -> std::vector<std::string> {
    const auto n = r.u32();
    std::vector<std::string> out;
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(r.str());
    }
    return out;
}

inline void put_time(codec::writer& w,
                     const std::optional<std::chrono::system_clock::time_point>& t) {
    w.u8(t ? 1 : 0);
    if (t) {
        w.i64(std::chrono::duration_cast<std::chrono::nanoseconds>(t->time_since_epoch()).count());
    }
}

[[nodiscard]] inline auto get_time(codec::reader& r)
    -> std::optional<std::chrono::system_clock::time_point> {
    if (!r.boolean()) {
        return std::nullopt;
    }
    return std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::nanoseconds(r.i64())));
}

inline void put_principal(codec::writer& w, const aws_auth::principal_context& p) {
    w.u8(static_cast<std::uint8_t>(p.type));
    w.str(p.account).str(p.arn).str(p.userid).str(p.username).str(p.access_key_id);
    w.str(p.role_arn).str(p.role_name).str(p.session_name).str(p.user_arn);
    put_pairs(w, p.tags);
    put_time(w, p.token_issue_time);
    put_time(w, p.expires);
    w.str(p.source_identity);
    put_strs(w, p.session_policies);
    put_strs(w, p.transitive_tag_keys);
    w.u8(p.session_token ? 1 : 0);
}

[[nodiscard]] inline auto get_principal(codec::reader& r) -> aws_auth::principal_context {
    aws_auth::principal_context p;
    p.type = r.enumeration<aws_auth::principal_type>(
        static_cast<std::uint8_t>(aws_auth::principal_type::federated_user));
    p.account = r.str();
    p.arn = r.str();
    p.userid = r.str();
    p.username = r.str();
    p.access_key_id = r.str();
    p.role_arn = r.str();
    p.role_name = r.str();
    p.session_name = r.str();
    p.user_arn = r.str();
    p.tags = get_pairs(r);
    p.token_issue_time = get_time(r);
    p.expires = get_time(r);
    p.source_identity = r.str();
    p.session_policies = get_strs(r);
    p.transitive_tag_keys = get_strs(r);
    p.session_token = r.boolean();
    return p;
}

}  // namespace detail

/// An authenticated call on the wire.
[[nodiscard]] inline auto encode_call(const authenticated_call& c) -> std::string {
    codec::writer w;
    w.u8(k_version).u8(static_cast<std::uint8_t>(c._kind));
    w.str(c._operation).str(boost::json::serialize(c._input));
    w.u8(static_cast<std::uint8_t>(c._encoding)).str(c._request_id);
    detail::put_principal(w, c._principal);
    w.str(c._source_ip).str(c._user_agent).u8(c._secure ? 1 : 0);
    w.str(c._method).str(c._path).str(c._query);
    detail::put_pairs(w, c._headers);
    w.str(c._body);
    return detail::to_string(w.take());
}

/// The call `body` holds; nullopt when it is not one this version reads.
[[nodiscard]] inline auto decode_call(std::string_view body) -> std::optional<authenticated_call> {
    try {
        const auto bytes = detail::to_bytes(body);
        codec::reader r(bytes);
        if (r.u8() != k_version) {
            return std::nullopt;
        }
        authenticated_call c;
        c._kind = r.enumeration<call_kind>(static_cast<std::uint8_t>(call_kind::lease));
        c._operation = r.str();
        const auto input_text = r.str();
        boost::system::error_code ec;
        auto input = boost::json::parse(input_text, ec);
        if (ec || !input.is_object()) {
            return std::nullopt;
        }
        c._input = std::move(input.as_object());
        c._encoding = r.enumeration<aws_json::body_encoding>(
            static_cast<std::uint8_t>(aws_json::body_encoding::cbor));
        c._request_id = r.str();
        c._principal = detail::get_principal(r);
        c._source_ip = r.str();
        c._user_agent = r.str();
        c._secure = r.boolean();
        c._method = r.str();
        c._path = r.str();
        c._query = r.str();
        c._headers = detail::get_pairs(r);
        c._body = r.str();
        r.expect_end("authenticated call");
        return c;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

/// A front end's answer to a call: the client's HTTP response, and for a
/// subscription the session the events are pulled from (empty without one).
struct call_answer {
    aws_json::http_response _response;
    std::string _session;
};

[[nodiscard]] inline auto encode_answer(const call_answer& a) -> std::string {
    codec::writer w;
    w.u8(k_version).u16(static_cast<std::uint16_t>(a._response.status));
    detail::put_pairs(w, a._response.headers);
    w.str(a._response.body).str(a._session);
    return detail::to_string(w.take());
}

[[nodiscard]] inline auto decode_answer(std::string_view body) -> std::optional<call_answer> {
    try {
        const auto bytes = detail::to_bytes(body);
        codec::reader r(bytes);
        if (r.u8() != k_version) {
            return std::nullopt;
        }
        call_answer a;
        a._response.status = r.u16();
        a._response.headers = detail::get_pairs(r);
        a._response.body = r.str();
        a._session = r.str();
        r.expect_end("call answer");
        return a;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

struct pull_request {
    std::string _session;
    std::uint32_t _wait_ms = 500;
};

struct pull_answer {
    std::vector<std::string> _messages;
    bool _done = false;
};

[[nodiscard]] inline auto encode_pull(const pull_request& p) -> std::string {
    codec::writer w;
    w.u8(k_version).str(p._session).u32(p._wait_ms);
    return detail::to_string(w.take());
}

[[nodiscard]] inline auto decode_pull(std::string_view body) -> std::optional<pull_request> {
    try {
        const auto bytes = detail::to_bytes(body);
        codec::reader r(bytes);
        if (r.u8() != k_version) {
            return std::nullopt;
        }
        pull_request p;
        p._session = r.str();
        p._wait_ms = r.u32();
        r.expect_end("pull");
        return p;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] inline auto encode_pull_answer(const pull_answer& a) -> std::string {
    codec::writer w;
    w.u8(k_version).u8(a._done ? 1 : 0);
    detail::put_strs(w, a._messages);
    return detail::to_string(w.take());
}

[[nodiscard]] inline auto decode_pull_answer(std::string_view body) -> std::optional<pull_answer> {
    try {
        const auto bytes = detail::to_bytes(body);
        codec::reader r(bytes);
        if (r.u8() != k_version) {
            return std::nullopt;
        }
        pull_answer a;
        a._done = r.boolean();
        a._messages = detail::get_strs(r);
        r.expect_end("pull answer");
        return a;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

/// The retryable end of an event stream: `InternalFailureException`, in the
/// call's encoding, as `kinesis_service`'s subscription words it.
[[nodiscard]] inline auto retryable_failure_event(aws_json::body_encoding encoding,
                                                  const std::string& message) -> std::string {
    const boost::json::object payload{{"message", message}};
    std::string body;
    std::string content_type;
    if (encoding == aws_json::body_encoding::cbor) {
        body = aws_json::json_to_cbor(kinesis_model::k_model, aws_json::no_shape,
                                      boost::json::value(payload),
                                      aws_json::cbor_timestamp_unit::milliseconds);
        content_type = "application/x-amz-cbor-1.1";
    } else {
        body = boost::json::serialize(payload);
        content_type = "application/json";
    }
    const auto bytes = aws_eventstream::encode(aws_eventstream::make_exception(
        "InternalFailureException", std::move(content_type), detail::to_bytes(body)));
    return detail::to_string(bytes);
}

}  // namespace front_end_api

// ---- the front end's side ------------------------------------------------

/// What a front end does with a call, set by the composition root.
struct front_end_routes {
    struct execution {
        aws_json::http_response _response;
        std::shared_ptr<event_source> _events;
    };
    /// An API call: `front_end::execute`.
    std::function<execution(authenticated_call&)> _execute;
    /// A Lease API call: `lease_api::execute`. Empty: refused.
    std::function<aws_json::http_response(const authenticated_call&)> _lease;
    /// The front end's `/metrics` text. Empty: 404.
    std::function<std::string()> _metrics;
};

struct front_end_server_options {
    /// A session nobody pulled for this long is cancelled.
    std::chrono::milliseconds _session_idle{30'000};
    /// The most sessions held; a subscribe past it is not executed.
    std::size_t _max_sessions = 10'000;
    /// The longest a pull may wait.
    std::chrono::milliseconds _max_wait{2'000};
    std::function<std::chrono::steady_clock::time_point()> _clock = [] {
        return std::chrono::steady_clock::now();
    };
};

struct front_end_server_stats {
    std::atomic<std::uint64_t> _calls{0};
    std::atomic<std::uint64_t> _refused{0};
    std::atomic<std::uint64_t> _not_executed{0};
    std::atomic<std::uint64_t> _sessions_opened{0};
    std::atomic<std::uint64_t> _sessions_expired{0};
};

/// The front-end API: serves the routes above for one front end.
/// Thread-safe; each session is pulled by one gateway at a time.
class front_end_server {
public:
    struct answer {
        unsigned _status = front_end_api::k_ok;
        std::string _body;
        /// Set with 503: the call did not run.
        bool _not_executed = false;
    };

    explicit front_end_server(front_end_routes routes, front_end_server_options options = {})
        : _routes(std::move(routes)), _options(std::move(options)) {}

    front_end_server(const front_end_server&) = delete;
    auto operator=(const front_end_server&) -> front_end_server& = delete;
    front_end_server(front_end_server&&) = delete;
    auto operator=(front_end_server&&) -> front_end_server& = delete;
    ~front_end_server() { cancel_all(); }

    /// One request on `path`, from a caller the listener admitted (or not:
    /// `admitted` false answers 403 and reads nothing). nullopt for a path
    /// that is not this API's.
    [[nodiscard]] auto serve(bool admitted, std::string_view method, std::string_view path,
                             std::string_view body) -> std::optional<answer> {
        using namespace front_end_api;
        if (!is_front_end_api_path(path)) {
            return std::nullopt;
        }
        if (!admitted) {
            ++_stats._refused;
            return answer{._status = k_refused, ._body = "refused\n"};
        }
        if (method != "POST") {
            return answer{._status = k_malformed, ._body = "method not allowed\n"};
        }
        reap();
        if (path == k_call_path || path == k_subscribe_path) {
            return call(body, path == k_subscribe_path);
        }
        if (path == k_pull_path) {
            return pull(body);
        }
        if (path == k_cancel_path) {
            const auto p = decode_pull(body);
            if (!p) {
                return answer{._status = k_malformed, ._body = "malformed cancel\n"};
            }
            cancel(p->_session);
            return answer{._status = k_ok, ._body = {}};
        }
        if (path == k_metrics_path) {
            if (!_routes._metrics) {
                return answer{._status = k_no_session, ._body = "no metrics here\n"};
            }
            return answer{._status = k_ok, ._body = _routes._metrics()};
        }
        return answer{._status = k_no_session, ._body = "not found\n"};
    }

    /// Takes no new call (each answers not executed, so the gateway tries
    /// another front end) and ends every session. For a front end that is
    /// about to stop.
    void drain() {
        _draining.store(true, std::memory_order_release);
        cancel_all();
    }

    [[nodiscard]] auto sessions() const -> std::size_t {
        const std::scoped_lock lock(_mu);
        return _sessions.size();
    }

    [[nodiscard]] auto stats() const noexcept -> const front_end_server_stats& { return _stats; }

private:
    struct session {
        std::shared_ptr<event_source> _events;
        std::mutex _pulling;
        std::chrono::steady_clock::time_point _touched;
    };

    front_end_routes _routes;
    front_end_server_options _options;
    front_end_server_stats _stats;
    std::atomic<bool> _draining{false};
    mutable std::mutex _mu;
    std::map<std::string, std::shared_ptr<session>, std::less<>> _sessions;

    [[nodiscard]] auto not_executed(std::string_view why) -> answer {
        ++_stats._not_executed;
        return answer{._status = front_end_api::k_not_executed,
                      ._body = std::string(why) + "\n",
                      ._not_executed = true};
    }

    [[nodiscard]] static auto new_session_id() -> std::string {
        std::array<unsigned char, 16> raw{};
        if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
            throw std::runtime_error("front end: no randomness for a session id");
        }
        static constexpr std::string_view hex = "0123456789abcdef";
        std::string out;
        for (const auto b : raw) {
            out.push_back(hex[b >> 4U]);
            out.push_back(hex[b & 0xFU]);
        }
        return out;
    }

    auto call(std::string_view body, bool subscribe) -> answer {
        using namespace front_end_api;
        if (_draining.load(std::memory_order_acquire)) {
            return not_executed("draining");
        }
        auto c = decode_call(body);
        if (!c) {
            return answer{._status = k_malformed, ._body = "malformed call\n"};
        }
        if (subscribe) {
            const std::scoped_lock lock(_mu);
            if (_sessions.size() >= _options._max_sessions) {
                return not_executed("too many sessions");
            }
        }
        ++_stats._calls;
        call_answer out;
        if (c->_kind == call_kind::lease) {
            if (!_routes._lease) {
                return not_executed("no lease api here");
            }
            out._response = _routes._lease(*c);
            return answer{._status = k_ok, ._body = encode_answer(out)};
        }
        auto e = _routes._execute(*c);
        out._response = std::move(e._response);
        if (e._events) {
            if (!subscribe) {
                // A transport that cannot stream: the events are dropped, as
                // `front_end::handle` drops them.
                e._events->cancel();
            } else {
                out._session = new_session_id();
                auto s = std::make_shared<session>();
                s->_events = std::move(e._events);
                s->_touched = _options._clock();
                const std::scoped_lock lock(_mu);
                _sessions.emplace(out._session, std::move(s));
                ++_stats._sessions_opened;
            }
        }
        return answer{._status = k_ok, ._body = encode_answer(out)};
    }

    auto pull(std::string_view body) -> answer {
        using namespace front_end_api;
        const auto p = decode_pull(body);
        if (!p) {
            return answer{._status = k_malformed, ._body = "malformed pull\n"};
        }
        std::shared_ptr<session> s;
        {
            const std::scoped_lock lock(_mu);
            const auto it = _sessions.find(p->_session);
            if (it == _sessions.end()) {
                return answer{._status = k_no_session, ._body = "no such session\n"};
            }
            s = it->second;
            s->_touched = _options._clock();
        }
        pull_answer out;
        {
            const std::scoped_lock pulling(s->_pulling);
            const auto wait = std::min(std::chrono::milliseconds(p->_wait_ms), _options._max_wait);
            auto first = s->_events->next(wait);
            std::size_t bytes = first._message.size();
            if (!first._message.empty()) {
                out._messages.push_back(std::move(first._message));
            }
            out._done = first._done;
            // Whatever else is ready, without waiting.
            while (!out._done && !out._messages.empty() &&
                   out._messages.size() < k_max_pull_messages && bytes < k_max_pull_bytes) {
                auto more = s->_events->next(std::chrono::milliseconds(0));
                out._done = more._done;
                if (more._message.empty()) {
                    break;
                }
                bytes += more._message.size();
                out._messages.push_back(std::move(more._message));
            }
        }
        {
            const std::scoped_lock lock(_mu);
            if (out._done) {
                _sessions.erase(p->_session);
            } else if (const auto it = _sessions.find(p->_session); it != _sessions.end()) {
                it->second->_touched = _options._clock();
            }
        }
        return answer{._status = k_ok, ._body = encode_pull_answer(out)};
    }

    void cancel(std::string_view id) {
        std::shared_ptr<session> s;
        {
            const std::scoped_lock lock(_mu);
            const auto it = _sessions.find(id);
            if (it == _sessions.end()) {
                return;
            }
            s = std::move(it->second);
            _sessions.erase(it);
        }
        s->_events->cancel();
    }

    void cancel_all() {
        std::map<std::string, std::shared_ptr<session>, std::less<>> gone;
        {
            const std::scoped_lock lock(_mu);
            gone.swap(_sessions);
        }
        for (const auto& [id, s] : gone) {
            s->_events->cancel();
        }
    }

    /// Cancels sessions nobody pulled for `_session_idle`.
    void reap() {
        std::vector<std::shared_ptr<session>> idle;
        const auto now = _options._clock();
        {
            const std::scoped_lock lock(_mu);
            for (auto it = _sessions.begin(); it != _sessions.end();) {
                if (now - it->second->_touched > _options._session_idle) {
                    idle.push_back(std::move(it->second));
                    it = _sessions.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& s : idle) {
            ++_stats._sessions_expired;
            s->_events->cancel();
        }
    }
};

// ---- the gateway's side --------------------------------------------------

/// Posts one front-end API request to the front end at `address`.
using front_end_transport = std::function<https_peer::peer_outcome(
    const std::string& address, std::string_view path, std::string body)>;

/// The transport over the internal HTTP(S) client: each request signed with
/// the forward secret over `signed_text`. A layer-identity cluster
/// authenticates the same requests by the client certificate instead.
[[nodiscard]] inline auto make_http_front_end_transport(
    const peer_client& client, std::string secret,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) -> front_end_transport {
    return [&client, secret = std::move(secret), clock = std::move(clock)](
               const std::string& address, std::string_view path,
               std::string body) -> https_peer::peer_outcome {
        peer_client::headers headers{{"Content-Type", "application/octet-stream"}};
        if (!secret.empty()) {
            headers.emplace_back(
                std::string(forward::k_header),
                forward::sign(secret, front_end_api::signed_text(path, body), clock()));
        }
        return client.exchange(address, boost::beast::http::verb::post, path, headers,
                               std::move(body));
    };
}

struct remote_front_end_stats {
    std::atomic<std::uint64_t> _calls{0};
    /// Calls handed to a second front end because the first could not take
    /// them.
    std::atomic<std::uint64_t> _failovers{0};
    /// Calls no front end took (InternalFailure to the client).
    std::atomic<std::uint64_t> _unplaced{0};
    /// Calls sent without an answer (InternalFailure: they may have run).
    std::atomic<std::uint64_t> _unanswered{0};
    std::atomic<std::uint64_t> _streams_relayed{0};
    std::atomic<std::uint64_t> _streams_broken{0};
};

/// A gateway's link to the front ends on other nodes: places each call by
/// affinity and fails over only when the call cannot have run.
class remote_front_ends {
public:
    /// How a call fared.
    enum class fate : std::uint8_t {
        /// A front end answered: pass `_answer` on.
        answered,
        /// No front end took it; it did not run anywhere.
        unplaced,
        /// Sent, and no answer: it may have run.
        unanswered
    };

    struct outcome {
        fate _fate = fate::unplaced;
        front_end_api::call_answer _answer;
        /// The front end that answered.
        std::string _address;
    };

    remote_front_ends(std::vector<std::string> addresses, front_end_transport transport,
                      front_end_set_options options = {})
        : _set(std::move(addresses), std::move(options)), _transport(std::move(transport)) {}

    /// `call` on its affinity front end, or the next in its order once
    /// when the first cannot take it. `subscribe` asks for an event-stream
    /// session.
    [[nodiscard]] auto call(const authenticated_call& c, bool subscribe = false) -> outcome {
        ++_stats._calls;
        const auto body = front_end_api::encode_call(c);
        const auto path = subscribe ? front_end_api::k_subscribe_path : front_end_api::k_call_path;
        const auto order = _set.order_for(affinity_of(c));
        outcome out;
        // The first choice and one more (Requirement 4.4, design "Error
        // handling").
        const std::size_t tries = std::min<std::size_t>(order.size(), 2);
        for (std::size_t i = 0; i < tries; ++i) {
            if (i > 0) {
                ++_stats._failovers;
            }
            const auto& address = order[i];
            auto r = _transport(address, path, body);
            if (!r._response) {
                if (r._sent) {
                    ++_stats._unanswered;
                    out._fate = fate::unanswered;
                    out._address = address;
                    return out;
                }
                _set.mark_unreachable(address);
                continue;
            }
            if (r._response->_status == front_end_api::k_not_executed) {
                // Draining, full or not a front end: it says it did not run.
                _set.mark_unreachable(address);
                continue;
            }
            if (r._response->_status != front_end_api::k_ok) {
                // Refused (a misconfigured secret or identity) or malformed:
                // it did not run, and another front end with the same
                // settings would refuse it too.
                _set.mark_unreachable(address);
                continue;
            }
            auto a = front_end_api::decode_answer(r._response->_body);
            if (!a) {
                ++_stats._unanswered;
                out._fate = fate::unanswered;
                out._address = address;
                return out;
            }
            _set.mark_reachable(address);
            out._fate = fate::answered;
            out._answer = std::move(*a);
            out._address = address;
            return out;
        }
        ++_stats._unplaced;
        return out;
    }

    /// The next messages of `session` on `address`; nullopt when the front
    /// end or the session is gone.
    [[nodiscard]] auto pull(const std::string& address, const std::string& session,
                            std::chrono::milliseconds wait)
        -> std::optional<front_end_api::pull_answer> {
        const auto r = _transport(
            address, front_end_api::k_pull_path,
            front_end_api::encode_pull(
                {._session = session, ._wait_ms = static_cast<std::uint32_t>(wait.count())}));
        if (!r._response || r._response->_status != front_end_api::k_ok) {
            if (!r._response) {
                _set.mark_unreachable(address);
            }
            return std::nullopt;
        }
        return front_end_api::decode_pull_answer(r._response->_body);
    }

    /// Ends `session` early; best effort.
    void cancel(const std::string& address, const std::string& session) {
        (void)_transport(address, front_end_api::k_cancel_path,
                         front_end_api::encode_pull({._session = session, ._wait_ms = 0}));
    }

    /// One front end's `/metrics` text: the first in the order of a fixed
    /// key, so a scraper sees the same front end while it is up.
    [[nodiscard]] auto metrics() -> std::optional<std::string> {
        const auto order = _set.order_for({affinity_kind::account, "metrics"});
        for (const auto& address : order) {
            const auto r = _transport(address, front_end_api::k_metrics_path, {});
            if (r._response && r._response->_status == front_end_api::k_ok) {
                return r._response->_body;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto front_ends() noexcept -> front_end_set& { return _set; }
    [[nodiscard]] auto stats() noexcept -> remote_front_end_stats& { return _stats; }

private:
    front_end_set _set;
    front_end_transport _transport;
    remote_front_end_stats _stats;
};

/// The events of a subscription executed on another node, relayed by the
/// gateway (Requirement 4.5). Each `next` pulls the session; when the pull
/// fails, the session is gone, or the gateway drains, the stream ends with
/// the retryable `InternalFailureException`.
class remote_event_source final : public event_source {
public:
    remote_event_source(remote_front_ends& link, std::string address, std::string session,
                        aws_json::body_encoding encoding, std::function<bool()> stopping)
        : _link(link),
          _address(std::move(address)),
          _session(std::move(session)),
          _encoding(encoding),
          _stopping(std::move(stopping)) {
        ++_link.stats()._streams_relayed;
    }

    remote_event_source(const remote_event_source&) = delete;
    remote_event_source(remote_event_source&&) = delete;
    auto operator=(const remote_event_source&) -> remote_event_source& = delete;
    auto operator=(remote_event_source&&) -> remote_event_source& = delete;
    ~remote_event_source() override { cancel(); }

    auto next(std::chrono::milliseconds wait) -> pull override {
        const std::scoped_lock lock(_mu);
        if (!_ready.empty()) {
            auto m = std::move(_ready.front());
            _ready.pop_front();
            return {._message = std::move(m), ._done = _ready.empty() && _ended};
        }
        if (_ended || _cancelled.load()) {
            return {._message = {}, ._done = true};
        }
        if (_stopping && _stopping()) {
            return fail("The gateway is draining; subscribe again.");
        }
        auto a = _link.pull(_address, _session, wait);
        if (!a) {
            ++_link.stats()._streams_broken;
            return fail("The front end serving this subscription went away; subscribe again.");
        }
        for (auto& m : a->_messages) {
            _ready.push_back(std::move(m));
        }
        _ended = a->_done;
        if (_ended) {
            _session_open = false;
        }
        if (_ready.empty()) {
            return {._message = {}, ._done = _ended};
        }
        auto m = std::move(_ready.front());
        _ready.pop_front();
        return {._message = std::move(m), ._done = _ready.empty() && _ended};
    }

    void cancel() override {
        if (_cancelled.exchange(true)) {
            return;
        }
        if (_session_open) {
            _session_open = false;
            _link.cancel(_address, _session);
        }
    }

private:
    remote_front_ends& _link;
    std::string _address;
    std::string _session;
    aws_json::body_encoding _encoding;
    std::function<bool()> _stopping;
    std::mutex _mu;
    std::deque<std::string> _ready;
    bool _ended = false;
    std::atomic<bool> _session_open{true};
    std::atomic<bool> _cancelled{false};

    auto fail(const std::string& message) -> pull {
        _ended = true;
        if (_session_open.exchange(false)) {
            _link.cancel(_address, _session);
        }
        return {._message = front_end_api::retryable_failure_event(_encoding, message),
                ._done = true};
    }
};

}  // namespace kythira::kinesis
