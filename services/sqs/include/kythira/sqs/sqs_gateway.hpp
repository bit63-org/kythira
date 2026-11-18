// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_gateway.hpp
/// @brief The gateway layer's hand-off to front ends
///        (`.kiro/specs/sqs-compatible-queues/` task 10, Requirement 11.3).
///
/// A node with the gateway role and without the front-end role checks a
/// client's SigV4 signature itself (`sqs_front_end::admit`) and hands the
/// request on as an *authenticated call*:
///
/// - `POST /_kythira/sqs/v1/call` on a front end, signed like every
///   internal call (`sqs_forward.hpp`), with body
///   `{"request": {...}, "principal": {...}}`: the client's request as it
///   arrived (method, path, query, headers, body in base64, source address,
///   whether it came over TLS) and who signed it.
/// - The front end runs everything after authentication on it
///   (`sqs_front_end::handle_as`) and answers
///   `{"status": N, "headers": [[k, v], ...], "body": "<base64>"}`: the
///   client's answer, which the gateway relays as it is.
///
/// The front end trusts the principal because the call is signed with the
/// cluster's secret: only a node holding it can name one. The client's own
/// signature is not checked again (a front end may not hold the keys), but
/// the source address and transport travel with the call, so
/// `aws:SourceIp` and `aws:SecureTransport` still see the client.
///
/// A call that fails in transit is not retried on another front end: the
/// request may have run, and the client's SDK retries a 5xx with the same
/// idempotency an SQS client already copes with (at-least-once delivery,
/// FIFO deduplication). The next request starts at the next front end.
/// A long poll holds its call open up to 20 seconds, so the transport's
/// timeout must exceed that.

#include <kythira/sqs/sqs_data_access.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_remote_cluster.hpp>

#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

inline constexpr std::string_view k_call_path = "/_kythira/sqs/v1/call";

/// One authenticated call: the client's request and who signed it.
struct authenticated_call {
    sqs_request _request;
    aws_auth::principal_context _principal;
};

namespace gateway_wire {

using data_wire::b64;
using data_wire::str;
using data_wire::unb64;

[[nodiscard]] inline auto pairs(const std::vector<std::pair<std::string, std::string>>& in)
    -> boost::json::array {
    boost::json::array out;
    for (const auto& [k, v] : in) {
        out.push_back(boost::json::array{boost::json::string(k), boost::json::string(v)});
    }
    return out;
}

[[nodiscard]] inline auto unpairs(const boost::json::object& o, std::string_view key)
    -> std::optional<std::vector<std::pair<std::string, std::string>>> {
    std::vector<std::pair<std::string, std::string>> out;
    const auto* v = o.if_contains(key);
    if (v == nullptr) {
        return out;
    }
    if (!v->is_array()) {
        return std::nullopt;
    }
    for (const auto& e : v->as_array()) {
        if (!e.is_array() || e.as_array().size() != 2 || !e.as_array()[0].is_string() ||
            !e.as_array()[1].is_string()) {
            return std::nullopt;
        }
        out.emplace_back(std::string(e.as_array()[0].as_string()),
                         std::string(e.as_array()[1].as_string()));
    }
    return out;
}

[[nodiscard]] inline auto strings(const std::vector<std::string>& in) -> boost::json::array {
    boost::json::array out;
    for (const auto& s : in) {
        out.emplace_back(s);
    }
    return out;
}

[[nodiscard]] inline auto unstrings(const boost::json::object& o, std::string_view key)
    -> std::optional<std::vector<std::string>> {
    std::vector<std::string> out;
    const auto* v = o.if_contains(key);
    if (v == nullptr) {
        return out;
    }
    if (!v->is_array()) {
        return std::nullopt;
    }
    for (const auto& e : v->as_array()) {
        if (!e.is_string()) {
            return std::nullopt;
        }
        out.emplace_back(e.as_string());
    }
    return out;
}

[[nodiscard]] inline auto millis(std::chrono::system_clock::time_point t) -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

[[nodiscard]] inline auto time_at(const boost::json::object& o, std::string_view key)
    -> std::optional<std::chrono::system_clock::time_point> {
    const auto* v = o.if_contains(key);
    if (v == nullptr || !v->is_int64()) {
        return std::nullopt;
    }
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(v->as_int64()));
}

[[nodiscard]] inline auto encode_principal(const aws_auth::principal_context& p)
    -> boost::json::object {
    boost::json::object o;
    o["type"] = static_cast<std::uint64_t>(p.type);
    o["account"] = p.account;
    o["arn"] = p.arn;
    o["userid"] = p.userid;
    o["username"] = p.username;
    o["access_key_id"] = p.access_key_id;
    o["role_arn"] = p.role_arn;
    o["role_name"] = p.role_name;
    o["session_name"] = p.session_name;
    o["user_arn"] = p.user_arn;
    o["tags"] = pairs(p.tags);
    if (p.token_issue_time) {
        o["token_issue_time"] = millis(*p.token_issue_time);
    }
    if (p.expires) {
        o["expires"] = millis(*p.expires);
    }
    o["source_identity"] = p.source_identity;
    o["session_policies"] = strings(p.session_policies);
    o["transitive_tag_keys"] = strings(p.transitive_tag_keys);
    o["session_token"] = p.session_token;
    return o;
}

[[nodiscard]] inline auto decode_principal(const boost::json::object& o)
    -> std::optional<aws_auth::principal_context> {
    aws_auth::principal_context p;
    const auto type = data_wire::u64(o, "type");
    if (type > static_cast<std::uint64_t>(aws_auth::principal_type::federated_user)) {
        return std::nullopt;
    }
    p.type = static_cast<aws_auth::principal_type>(type);
    p.account = str(o, "account");
    p.arn = str(o, "arn");
    p.userid = str(o, "userid");
    p.username = str(o, "username");
    p.access_key_id = str(o, "access_key_id");
    p.role_arn = str(o, "role_arn");
    p.role_name = str(o, "role_name");
    p.session_name = str(o, "session_name");
    p.user_arn = str(o, "user_arn");
    auto tags = unpairs(o, "tags");
    auto policies = unstrings(o, "session_policies");
    auto transitive = unstrings(o, "transitive_tag_keys");
    if (!tags || !policies || !transitive || p.account.empty()) {
        return std::nullopt;
    }
    p.tags = std::move(*tags);
    p.session_policies = std::move(*policies);
    p.transitive_tag_keys = std::move(*transitive);
    p.token_issue_time = time_at(o, "token_issue_time");
    p.expires = time_at(o, "expires");
    p.source_identity = str(o, "source_identity");
    const auto* st = o.if_contains("session_token");
    p.session_token = st != nullptr && st->is_bool() && st->as_bool();
    return p;
}

}  // namespace gateway_wire

[[nodiscard]] inline auto encode_call(const authenticated_call& c) -> std::string {
    using namespace gateway_wire;
    const auto& r = c._request;
    boost::json::object req;
    req["method"] = r._method;
    req["path"] = r._path;
    req["query"] = r._query;
    req["headers"] = pairs(r._headers);
    req["body"] = b64(r._body);
    req["source_ip"] = r._source_ip;
    req["secure"] = r._secure;
    boost::json::object o;
    o["request"] = std::move(req);
    o["principal"] = encode_principal(c._principal);
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_call(std::string_view in) -> std::optional<authenticated_call> {
    using namespace gateway_wire;
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto* req = v.as_object().if_contains("request");
    const auto* who = v.as_object().if_contains("principal");
    if (req == nullptr || !req->is_object() || who == nullptr || !who->is_object()) {
        return std::nullopt;
    }
    const auto& ro = req->as_object();
    authenticated_call c;
    c._request._method = str(ro, "method");
    c._request._path = str(ro, "path");
    c._request._query = str(ro, "query");
    auto headers = unpairs(ro, "headers");
    const auto* body = ro.if_contains("body");
    auto raw = body != nullptr ? unb64(*body) : std::nullopt;
    auto principal = decode_principal(who->as_object());
    if (!headers || !raw || !principal || c._request._method.empty() || c._request._path.empty()) {
        return std::nullopt;
    }
    c._request._headers = std::move(*headers);
    c._request._body = std::move(*raw);
    c._request._source_ip = str(ro, "source_ip");
    const auto* secure = ro.if_contains("secure");
    c._request._secure = secure != nullptr && secure->is_bool() && secure->as_bool();
    c._principal = std::move(*principal);
    return c;
}

[[nodiscard]] inline auto encode_call_answer(const aws_json::http_response& r) -> std::string {
    boost::json::object o;
    o["status"] = r.status;
    o["headers"] = gateway_wire::pairs(r.headers);
    o["body"] = data_wire::b64(r.body);
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_call_answer(std::string_view in)
    -> std::optional<aws_json::http_response> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    aws_json::http_response r;
    const auto status = data_wire::u64(o, "status");
    auto headers = gateway_wire::unpairs(o, "headers");
    const auto* body = o.if_contains("body");
    auto raw = body != nullptr ? data_wire::unb64(*body) : std::nullopt;
    if (status < 100 || status > 599 || !headers || !raw) {
        return std::nullopt;
    }
    r.status = static_cast<unsigned>(status);
    r.headers = std::move(*headers);
    r.body = std::move(*raw);
    return r;
}

/// The gateway's side: sends authenticated calls to the front ends in turn.
class gateway_forwarder {
public:
    using wall_clock_fn = std::function<std::chrono::system_clock::time_point()>;

    /// @param front_ends Base URLs of the front ends' SQS listeners.
    gateway_forwarder(
        std::vector<std::string> front_ends, std::string forward_secret, data_transport transport,
        wall_clock_fn wall = [] { return std::chrono::system_clock::now(); })
        : _endpoints(std::move(front_ends)),
          _secret(std::move(forward_secret)),
          _transport(std::move(transport)),
          _wall(std::move(wall)) {
        if (_endpoints.empty()) {
            throw std::invalid_argument("gateway_forwarder: no front ends");
        }
    }

    /// The front end's answer to `call`, or nullopt when the call failed in
    /// transit (the caller answers the client with a retryable error).
    auto forward(const authenticated_call& call) -> std::optional<aws_json::http_response> {
        const auto body = encode_call(call);
        std::vector<std::pair<std::string, std::string>> headers;
        if (!_secret.empty()) {
            headers.emplace_back(std::string(forward::k_header),
                                 forward::sign(_secret, body, _wall()));
        }
        const auto at = _next.fetch_add(1) % _endpoints.size();
        const auto r = _transport(_endpoints[at], std::string(k_call_path), headers, body);
        if (!r || r->first != 200) {
            ++_failures;
            return std::nullopt;
        }
        auto answer = decode_call_answer(r->second);
        if (!answer) {
            ++_failures;
        }
        return answer;
    }

    [[nodiscard]] auto failures() const -> std::uint64_t { return _failures.load(); }

private:
    std::vector<std::string> _endpoints;
    std::string _secret;
    data_transport _transport;
    wall_clock_fn _wall;
    std::atomic<std::size_t> _next{0};
    std::atomic<std::uint64_t> _failures{0};
};

}  // namespace kythira::sqs
