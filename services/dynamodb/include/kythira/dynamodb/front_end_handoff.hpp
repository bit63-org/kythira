// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file front_end_handoff.hpp
/// @brief The call a DynamoDB gateway hands a front end on another node,
///        both ends of it, and the role checks on DynamoDB's internal routes
///        (`.kiro/specs/dynamodb-independent-layers/` task 5, Requirements
///        4.1, 4.2, 4.4 and 8.1-8.3).
///
/// A gateway frames the request and verifies its SigV4 signature
/// (`front_end::authenticate`), then hands the `authenticated_call` (the
/// request as it arrived, the principal the signature proved and the
/// request id) to a front end, which authorizes and runs it
/// (`front_end::execute`) and answers with the client's HTTP response; the
/// gateway passes that on unchanged. Authorization stays in the front end,
/// which can read the tables' tags and resource policies (4.2). This is the
/// shape of Kinesis's handoff (`kinesis_authenticated_call.hpp`): the same
/// route layout, admission and "not executed" rule, so an operator reads
/// both services' internal routes one way. The wire differs: DynamoDB's
/// internal routes all speak the item codec's varint and byte strings
/// (`op_wire.hpp`), so the call does too, instead of Kinesis's catalog
/// codec. DynamoDB has no event streams, so there is one route:
///
///   POST /_kythira/dynamodb/fe/v1/call    call -> answer
///
/// on every node with the `front_end` role, co-located ones included, so
/// gateways can be put in front of a running cluster.
///
/// ## Who may call
///
/// The front end takes the principal on trust, so only a gateway may hand
/// one over. With a route guard (`layer_identity.hpp`), that is a caller
/// whose layer identity holds `gateway`; the forward secret, which the guard
/// treats as the `data` role, is refused there (8.2). Without one (a
/// cluster that runs without layer identities, which is every cluster
/// until the daemons load identities), a caller that signs the path and
/// body with `KYTHIRA_DYNAMODB_FORWARD_SECRET` (`path_signed_text`), as the
/// forward channel admits its callers. Anything else gets 403 before the
/// body is read as a call.
///
/// ## Not executed
///
/// A gateway tries the next front end only when the call cannot have run
/// (Kinesis Requirement 4.4): the connection failed before the request was
/// written, or the front end answered 503 with `x-kythira-not-executed`
/// (it is draining, or runs no front end). A call that was written and got
/// no answer may have run, so it is answered InternalServerError, which
/// every DynamoDB client retries, as a timeout on a co-located node is
/// answered today. A front end that failed goes to the back of the order
/// for `down_for`.
///
/// ## Internal routes and roles
///
/// `route_guard_options_for` names who may call each internal route when
/// layer identities are in use (8.1): the forward channel
/// (`k_forward_path`) takes data nodes and front ends (a front end without
/// the data role sends its ops there, task 4), the handoff takes gateways.
/// The strong host's forward path is not a rule: strong voters in other
/// regions keep the strong secret (8.3), as global-table replicators keep
/// SigV4.
///
/// ## Drain
///
/// `POST /_kythira/dynamodb/v1/drain`, signed with the forward secret over
/// the path (and an empty body), or SIGTERM, drains a node (4.4, Kinesis
/// Requirement 4.7): `GET /` answers 503 so load balancers stop sending,
/// the listener stops accepting, answers close their connections, a front
/// end answers new handoffs as not executed, and requests in flight get up
/// to the drain timeout to finish.

#include <kythira/dynamodb/forward_link.hpp>
#include <kythira/dynamodb/front_end.hpp>
#include <kythira/dynamodb/item_codec.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/layer_identity.hpp>
#include <raft/layer_roles.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

namespace handoff {

inline constexpr std::string_view k_prefix = "/_kythira/dynamodb/fe/v1/";
inline constexpr std::string_view k_call_path = "/_kythira/dynamodb/fe/v1/call";
/// Begins draining the node: `POST`, signed with the forward secret over
/// `path_signed_text(k_drain_path, "")`.
inline constexpr std::string_view k_drain_path = "/_kythira/dynamodb/v1/drain";
/// On a 503: the call did not run here, so another front end may take it.
inline constexpr std::string_view k_not_executed_header = "x-kythira-not-executed";
inline constexpr std::uint8_t k_version = 1;

namespace wire {

inline void put_strings(std::string& out, const std::vector<std::string>& v) {
    detail::put_varint(out, v.size());
    for (const auto& s : v) {
        detail::put_bytes(out, s);
    }
}

inline void put_pairs(std::string& out, const std::vector<std::pair<std::string, std::string>>& v) {
    detail::put_varint(out, v.size());
    for (const auto& [k, x] : v) {
        detail::put_bytes(out, k);
        detail::put_bytes(out, x);
    }
}

inline void put_time(std::string& out,
                     const std::optional<std::chrono::system_clock::time_point>& t) {
    if (!t) {
        out.push_back('\0');
        return;
    }
    out.push_back('\1');
    const auto ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t->time_since_epoch()).count();
    // Zig-zag, so a time before 1970 survives the varint.
    detail::put_varint(out, (static_cast<std::uint64_t>(ns) << 1U) ^
                                static_cast<std::uint64_t>(ns >> 63));  // NOLINT
}

/// Throws `std::runtime_error` on a short or malformed body.
class in {
public:
    explicit in(std::string_view bytes) : _r(bytes) {}

    auto byte() -> std::uint8_t { return need(_r.byte()); }
    auto varint() -> std::uint64_t { return need(_r.varint()); }
    auto bytes() -> std::string { return need(_r.bytes()); }
    auto count() -> std::size_t {
        const auto n = varint();
        // Every element takes at least a byte, so a count past what is left
        // is a lie; refusing it bounds the allocation.
        if (n > k_max_count) {
            throw std::runtime_error("handoff: count too large");
        }
        return static_cast<std::size_t>(n);
    }
    auto strings() -> std::vector<std::string> {
        std::vector<std::string> out(count());
        for (auto& s : out) {
            s = bytes();
        }
        return out;
    }
    auto pairs() -> std::vector<std::pair<std::string, std::string>> {
        const auto n = count();
        std::vector<std::pair<std::string, std::string>> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            auto k = bytes();
            auto v = bytes();
            out.emplace_back(std::move(k), std::move(v));
        }
        return out;
    }
    auto time() -> std::optional<std::chrono::system_clock::time_point> {
        const auto present = byte();
        if (present == 0) {
            return std::nullopt;
        }
        if (present != 1) {
            throw std::runtime_error("handoff: bad time marker");
        }
        const auto z = varint();
        const auto ns = static_cast<std::int64_t>((z >> 1U) ^ (~(z & 1U) + 1U));
        return std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::nanoseconds(ns)));
    }
    [[nodiscard]] auto done() const -> bool { return _r.done(); }

private:
    static constexpr std::uint64_t k_max_count = 4096;

    template<typename T> static auto need(std::optional<T> v) -> T {
        if (!v) {
            throw std::runtime_error("handoff: truncated");
        }
        return std::move(*v);
    }

    detail::reader _r;
};

inline void put_principal(std::string& out, const aws_auth::principal_context& p) {
    out.push_back(static_cast<char>(p.type));
    for (const auto* s : {&p.account, &p.arn, &p.userid, &p.username, &p.access_key_id, &p.role_arn,
                          &p.role_name, &p.session_name, &p.user_arn}) {
        detail::put_bytes(out, *s);
    }
    put_pairs(out, p.tags);
    put_time(out, p.token_issue_time);
    put_time(out, p.expires);
    detail::put_bytes(out, p.source_identity);
    put_strings(out, p.session_policies);
    put_strings(out, p.transitive_tag_keys);
    out.push_back(p.session_token ? '\1' : '\0');
}

inline auto get_principal(in& r) -> aws_auth::principal_context {
    aws_auth::principal_context p;
    const auto type = r.byte();
    if (type > static_cast<std::uint8_t>(aws_auth::principal_type::federated_user)) {
        throw std::runtime_error("handoff: unknown principal type");
    }
    p.type = static_cast<aws_auth::principal_type>(type);
    for (auto* s : {&p.account, &p.arn, &p.userid, &p.username, &p.access_key_id, &p.role_arn,
                    &p.role_name, &p.session_name, &p.user_arn}) {
        *s = r.bytes();
    }
    p.tags = r.pairs();
    p.token_issue_time = r.time();
    p.expires = r.time();
    p.source_identity = r.bytes();
    p.session_policies = r.strings();
    p.transitive_tag_keys = r.strings();
    const auto token = r.byte();
    if (token > 1) {
        throw std::runtime_error("handoff: bad flag");
    }
    p.session_token = token == 1;
    return p;
}

}  // namespace wire

/// An authenticated call on the wire.
[[nodiscard]] inline auto encode_call(const authenticated_call& c) -> std::string {
    std::string out;
    out.push_back(static_cast<char>(k_version));
    detail::put_bytes(out, c.request_id);
    wire::put_principal(out, c.principal);
    const auto& q = c.request;
    for (const auto* s : {&q.method, &q.path, &q.query}) {
        detail::put_bytes(out, *s);
    }
    wire::put_pairs(out, q.headers);
    detail::put_bytes(out, q.body);
    detail::put_bytes(out, q.source_ip);
    out.push_back(q.secure ? '\1' : '\0');
    return out;
}

/// The call `body` holds; nullopt when it is not one this version reads.
[[nodiscard]] inline auto decode_call(std::string_view body) -> std::optional<authenticated_call> {
    try {
        wire::in r(body);
        if (r.byte() != k_version) {
            return std::nullopt;
        }
        authenticated_call c;
        c.request_id = r.bytes();
        c.principal = wire::get_principal(r);
        auto& q = c.request;
        for (auto* s : {&q.method, &q.path, &q.query}) {
            *s = r.bytes();
        }
        q.headers = r.pairs();
        q.body = r.bytes();
        q.source_ip = r.bytes();
        const auto secure = r.byte();
        if (secure > 1 || !r.done()) {
            return std::nullopt;
        }
        q.secure = secure == 1;
        return c;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

/// A front end's answer: the client's HTTP response.
[[nodiscard]] inline auto encode_answer(const aws_json::http_response& a) -> std::string {
    std::string out;
    out.push_back(static_cast<char>(k_version));
    detail::put_varint(out, a.status);
    wire::put_pairs(out, a.headers);
    detail::put_bytes(out, a.body);
    return out;
}

[[nodiscard]] inline auto decode_answer(std::string_view body)
    -> std::optional<aws_json::http_response> {
    try {
        wire::in r(body);
        if (r.byte() != k_version) {
            return std::nullopt;
        }
        aws_json::http_response a;
        const auto status = r.varint();
        if (status < 100 || status > 599) {
            return std::nullopt;
        }
        a.status = static_cast<unsigned>(status);
        a.headers = r.pairs();
        a.body = r.bytes();
        if (!r.done()) {
            return std::nullopt;
        }
        return a;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

/// Whether a signed internal request (time and MAC headers over
/// `path_signed_text(path, body)`) is good now.
template<typename Request>
[[nodiscard]] auto signed_by_secret(const Request& req, std::string_view path,
                                    std::string_view secret) -> bool {
    if (secret.empty()) {
        return false;
    }
    const auto time = req.find(k_forward_time_header);
    const auto mac = req.find(k_forward_mac_header);
    if (time == req.end() || mac == req.end()) {
        return false;
    }
    const auto now =
        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count());
    return forward_authentic(secret, time->value(), mac->value(),
                             path_signed_text(path, req.body()), now);
}

}  // namespace handoff

/// Who may call DynamoDB's internal routes when the cluster runs with layer
/// identities (Requirement 8.1): the forward channel takes data nodes and
/// front ends, the handoff takes gateways. `forward_secret` checks a
/// plaintext caller's forward-channel MAC, which the guard counts as the
/// `data` role alone (8.2): so a forward-secret caller still reaches the
/// forward channel between co-located data nodes and never the handoff.
[[nodiscard]] inline auto route_guard_options_for(std::string cluster, std::string secret)
    -> layers::route_guard_options {
    using layers::role;
    using layers::role_set;
    layers::route_guard_options o;
    o.service = "dynamodb";
    o.cluster = std::move(cluster);
    o.rules = {
        layers::route_rule{std::string(k_forward_path), role_set{role::data, role::front_end}},
        layers::route_rule{std::string(handoff::k_prefix), role_set{role::gateway}},
    };
    if (!secret.empty()) {
        o.forward_secret = [secret = std::move(secret)](const https::request& req) {
            const auto time = req.find(k_forward_time_header);
            const auto mac = req.find(k_forward_mac_header);
            if (time == req.end() || mac == req.end()) {
                return false;
            }
            const auto now =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            // The forward channel signs its body alone; anything else a
            // forward-secret caller sends is path-bound.
            const std::string_view target(req.target().data(), req.target().size());
            const auto text = target == k_forward_path ? std::string(req.body())
                                                       : path_signed_text(target, req.body());
            return forward_authentic(secret, time->value(), mac->value(), text, now);
        };
    }
    return o;
}

struct front_end_relay_options {
    /// The front ends' handoff listeners (their gateway ports).
    std::vector<forward_peer> front_ends;
    /// How long a front end that failed sits at the back of the order.
    std::chrono::milliseconds down_for{2000};
    std::function<std::chrono::steady_clock::time_point()> clock = [] {
        return std::chrono::steady_clock::now();
    };
};

/// Sends a handoff and reports what came back (`forward_client::post`).
using relay_transport =
    std::function<forward_reply(const forward_peer&, std::string_view path, const std::string&)>;

struct front_end_relay_stats {
    std::atomic<std::uint64_t> calls{0};
    /// Calls tried on a second front end after the first could not run it.
    std::atomic<std::uint64_t> retried{0};
    /// Calls answered InternalServerError for want of an answer.
    std::atomic<std::uint64_t> failed{0};
};

/// The gateway's side: picks a front end for each call, in turn, and
/// fails over once when the first could not have run it. Thread-safe.
class front_end_relay {
public:
    front_end_relay(front_end_relay_options options, relay_transport transport)
        : _options(std::move(options)),
          _transport(std::move(transport)),
          _down(_options.front_ends.size()) {
        if (_options.front_ends.empty()) {
            throw std::invalid_argument("front_end_relay: no front ends");
        }
    }

    /// The front end's answer to `call`, or nullopt when none came: the
    /// caller answers InternalServerError (`front_end::internal_error`).
    [[nodiscard]] auto relay(const authenticated_call& call)
        -> std::optional<aws_json::http_response> {
        ++_stats.calls;
        const auto body = handoff::encode_call(call);
        const auto order = pick_order();
        for (std::size_t attempt = 0; attempt < std::min<std::size_t>(2, order.size()); ++attempt) {
            const auto i = order[attempt];
            if (attempt > 0) {
                ++_stats.retried;
            }
            const auto reply = _transport(_options.front_ends[i], handoff::k_call_path, body);
            if (!reply.written || not_executed(reply)) {
                mark_down(i);
                continue;
            }
            if (reply.answered && reply.status == 200) {
                if (auto answer = handoff::decode_answer(reply.body)) {
                    return answer;
                }
            }
            // Written and refused, malformed or unanswered: it may have run,
            // so it is not tried again.
            mark_down(i);
            break;
        }
        ++_stats.failed;
        return std::nullopt;
    }

    [[nodiscard]] auto stats() const -> const front_end_relay_stats& { return _stats; }
    [[nodiscard]] auto front_ends() const -> const std::vector<forward_peer>& {
        return _options.front_ends;
    }

private:
    [[nodiscard]] static auto not_executed(const forward_reply& r) -> bool {
        if (!r.answered || r.status != 503) {
            return false;
        }
        return std::ranges::any_of(r.headers, [](const auto& h) {
            return h.first.size() == handoff::k_not_executed_header.size() &&
                   std::equal(h.first.begin(), h.first.end(),
                              handoff::k_not_executed_header.begin(),
                              [](char a, char b) { return std::tolower(a) == std::tolower(b); });
        });
    }

    /// Every front end, starting at the next in turn, the ones marked down
    /// moved to the back.
    [[nodiscard]] auto pick_order() -> std::vector<std::size_t> {
        const auto n = _options.front_ends.size();
        const auto start = _next.fetch_add(1, std::memory_order_relaxed) % n;
        const auto now = _options.clock();
        std::vector<std::size_t> up;
        std::vector<std::size_t> down;
        const std::scoped_lock lock(_mu);
        for (std::size_t k = 0; k < n; ++k) {
            const auto i = (start + k) % n;
            (_down[i] > now ? down : up).push_back(i);
        }
        up.insert(up.end(), down.begin(), down.end());
        return up;
    }

    void mark_down(std::size_t i) {
        const std::scoped_lock lock(_mu);
        _down[i] = _options.clock() + _options.down_for;
    }

    front_end_relay_options _options;
    relay_transport _transport;
    std::mutex _mu;
    std::vector<std::chrono::steady_clock::time_point> _down;
    std::atomic<std::size_t> _next{0};
    front_end_relay_stats _stats;
};

}  // namespace kythira::dynamodb
