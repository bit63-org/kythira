// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The front-end API: how a gateway hands a front end on another node the
// call it authenticated (.kiro/specs/kms-independent-layers/ task 4,
// Requirements 6.1-6.3 and 7), and the gateway's side of it.
//
// A gateway frames the request and verifies its SigV4 signature
// (`front_end::authenticate`), then sends the `authenticated_call` (the
// operation, the request id, the principal SigV4 proved, and the client's
// request whole) to a front end, which authorizes and runs it
// (`front_end::execute`) and answers with the KMS response the gateway
// passes on unchanged. Two requests on any node's KMS listener:
//
//   POST /v1/kms/front-end/call     call -> the KMS response
//   POST /v1/kms/front-end/health   -> 200 while the node serves calls
//
// Authorization, key policies, grants, kms:ViaService and the quotas stay
// in the front end (Requirements 6.2 and 7.1). A trusted service's
// forwarding headers are part of the request the gateway sends and are
// judged by the front end against its KYTHIRA_KMS_TRUSTED_SERVICES, so a
// gateway passes envelopes through without knowing them (Requirement
// 6.3).
//
// Who may call is the listener's business (serve_front_end takes the
// verdict; kms_layer_auth.hpp decides it): the call route takes gateways
// only, since the front end takes the principal on trust, and the health
// route gateways and front ends.
//
// Not executed. A front end that is draining, or a node that runs no
// front end, answers 503: the call did not run there, and the gateway
// tries the next front end. A call that was sent and got no answer may
// have run (CreateKey twice makes two keys), so the gateway answers
// KMSInternalException, which AWS's SDKs retry, as a timeout on a
// co-located node is answered.
//
// Live front ends. A gateway knows the front ends from configuration
// (KYTHIRA_KMS_FRONT_END_URLS) and asks each one's health route every
// probe interval; one that answered within the staleness bound is live.
// Calls go to live front ends first, round robin, and one that fails a
// dial is not live until it answers a probe again. Front ends keep the
// same directory of each other, and the live count is how many share the
// quotas (Requirement 7.2: configuration, with liveness from the probes).
//
// Wire format: a version byte, then length-prefixed fields (big-endian
// u32 lengths). Request bodies and header values travel as raw bytes, not
// text: a client may send anything, and the front end, not the gateway,
// answers for a malformed body.

#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/kms_forwarding.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::kms {

namespace front_end_api {

inline constexpr std::string_view k_prefix = "/v1/kms/front-end/";
inline constexpr std::string_view k_call_path = "/v1/kms/front-end/call";
inline constexpr std::string_view k_health_path = "/v1/kms/front-end/health";
inline constexpr std::uint8_t k_version = 1;

inline constexpr unsigned k_ok = 200;
inline constexpr unsigned k_malformed = 400;
inline constexpr unsigned k_refused = 403;
inline constexpr unsigned k_not_found = 404;
/// The call did not run here: another front end may take it.
inline constexpr unsigned k_not_executed = 503;

/// The most headers one call carries (the listener's own limit is lower).
inline constexpr std::uint32_t k_max_headers = 256;

[[nodiscard]] inline auto is_front_end_path(std::string_view target) -> bool {
    return target.starts_with(k_prefix);
}

namespace detail {

class writer {
public:
    auto u8(std::uint8_t v) -> writer& {
        _out.push_back(static_cast<char>(v));
        return *this;
    }
    auto u32(std::uint32_t v) -> writer& {
        for (int shift = 24; shift >= 0; shift -= 8) {
            u8(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
        }
        return *this;
    }
    auto boolean(bool v) -> writer& { return u8(v ? 1 : 0); }
    auto bytes(std::string_view v) -> writer& {
        if (v.size() > UINT32_MAX) {
            throw std::length_error("kms front-end API: field too long");
        }
        u32(static_cast<std::uint32_t>(v.size()));
        _out.append(v);
        return *this;
    }
    [[nodiscard]] auto take() -> std::string { return std::move(_out); }

private:
    std::string _out;
};

/// Reads what writer wrote; nothing past the end (every read checks).
class reader {
public:
    explicit reader(std::string_view in) : _in(in) {}

    [[nodiscard]] auto u8() -> std::optional<std::uint8_t> {
        if (_in.empty()) {
            return std::nullopt;
        }
        const auto v = static_cast<std::uint8_t>(_in.front());
        _in.remove_prefix(1);
        return v;
    }
    [[nodiscard]] auto u32() -> std::optional<std::uint32_t> {
        if (_in.size() < 4) {
            return std::nullopt;
        }
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_in[static_cast<std::size_t>(i)]);
        }
        _in.remove_prefix(4);
        return v;
    }
    [[nodiscard]] auto boolean() -> std::optional<bool> {
        const auto v = u8();
        if (!v || *v > 1) {
            return std::nullopt;
        }
        return *v == 1;
    }
    [[nodiscard]] auto bytes() -> std::optional<std::string> {
        const auto n = u32();
        if (!n || _in.size() < *n) {
            return std::nullopt;
        }
        std::string out(_in.substr(0, *n));
        _in.remove_prefix(*n);
        return out;
    }
    [[nodiscard]] auto done() const -> bool { return _in.empty(); }

private:
    std::string_view _in;
};

inline void put_headers(writer& w, const std::vector<std::pair<std::string, std::string>>& h) {
    if (h.size() > k_max_headers) {
        throw std::length_error("kms front-end API: too many headers");
    }
    w.u32(static_cast<std::uint32_t>(h.size()));
    for (const auto& [name, value] : h) {
        w.bytes(name).bytes(value);
    }
}

[[nodiscard]] inline auto get_headers(reader& r)
    -> std::optional<std::vector<std::pair<std::string, std::string>>> {
    const auto n = r.u32();
    if (!n || *n > k_max_headers) {
        return std::nullopt;
    }
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(*n);
    for (std::uint32_t i = 0; i < *n; ++i) {
        auto name = r.bytes();
        auto value = r.bytes();
        if (!name || !value) {
            return std::nullopt;
        }
        out.emplace_back(std::move(*name), std::move(*value));
    }
    return out;
}

}  // namespace detail

/// `call` on the wire. Throws std::length_error for a call too large to
/// frame, which a listener's limits never let through.
[[nodiscard]] inline auto encode_call(const authenticated_call& call) -> std::string {
    detail::writer w;
    w.u8(k_version);
    w.bytes(call.operation).bytes(call.request_id);
    w.bytes(kms_forwarding::encode_principal(call.principal));
    const auto& r = call.request;
    w.bytes(r.method).bytes(r.path).bytes(r.query);
    detail::put_headers(w, r.headers);
    w.bytes(r.body).bytes(r.source_ip).boolean(r.secure);
    return w.take();
}

/// The call in `body`, or nothing when it is not one this version wrote.
[[nodiscard]] inline auto decode_call(std::string_view body) -> std::optional<authenticated_call> {
    detail::reader r(body);
    if (r.u8() != std::optional<std::uint8_t>(k_version)) {
        return std::nullopt;
    }
    auto operation = r.bytes();
    auto request_id = r.bytes();
    auto principal_text = r.bytes();
    auto method = r.bytes();
    auto path = r.bytes();
    auto query = r.bytes();
    auto headers = detail::get_headers(r);
    auto request_body = r.bytes();
    auto source_ip = r.bytes();
    const auto secure = r.boolean();
    if (!operation || !request_id || !principal_text || !method || !path || !query || !headers ||
        !request_body || !source_ip || !secure || !r.done() || operation->empty()) {
        return std::nullopt;
    }
    auto principal = kms_forwarding::decode_principal(*principal_text);
    if (!principal) {
        return std::nullopt;
    }
    authenticated_call call;
    call.operation = std::move(*operation);
    call.request_id = std::move(*request_id);
    call.principal = std::move(*principal);
    call.request.method = std::move(*method);
    call.request.path = std::move(*path);
    call.request.query = std::move(*query);
    call.request.headers = std::move(*headers);
    call.request.body = std::move(*request_body);
    call.request.source_ip = std::move(*source_ip);
    call.request.secure = *secure;
    return call;
}

/// A front end's KMS response on the wire.
[[nodiscard]] inline auto encode_answer(const aws_json::http_response& res) -> std::string {
    detail::writer w;
    w.u8(k_version).u32(res.status);
    detail::put_headers(w, res.headers);
    w.bytes(res.body);
    return w.take();
}

[[nodiscard]] inline auto decode_answer(std::string_view body)
    -> std::optional<aws_json::http_response> {
    detail::reader r(body);
    if (r.u8() != std::optional<std::uint8_t>(k_version)) {
        return std::nullopt;
    }
    const auto status = r.u32();
    auto headers = detail::get_headers(r);
    auto payload = r.bytes();
    if (!status || *status < 100 || *status > 599 || !headers || !payload || !r.done()) {
        return std::nullopt;
    }
    aws_json::http_response res;
    res.status = *status;
    res.headers = std::move(*headers);
    res.body = std::move(*payload);
    return res;
}

struct answer {
    unsigned status = k_ok;
    std::string body;
};

/// Runs a call this node's front end takes (front_end::execute).
using executor = std::function<aws_json::http_response(authenticated_call)>;

/// Serves one front-end API request. `admitted` is the listener's verdict
/// on the caller for this route (kms_layer_auth.hpp); `accepting` is false
/// while the node runs no front end or is draining, when every request
/// answers 503 so a gateway goes elsewhere.
[[nodiscard]] inline auto serve_front_end(bool admitted, bool accepting, std::string_view method,
                                          std::string_view target, std::string_view body,
                                          const executor& execute) -> answer {
    if (!is_front_end_path(target)) {
        return {k_not_found, "not a front-end API path"};
    }
    if (!admitted) {
        return {k_refused, "this caller may not use " + std::string(target)};
    }
    if (method != "POST" || (target != k_call_path && target != k_health_path)) {
        return {k_malformed, "malformed front-end API request"};
    }
    if (!accepting) {
        return {k_not_executed, "not executed: this node takes no KMS calls now"};
    }
    if (target == k_health_path) {
        return {k_ok, "serving"};
    }
    auto call = decode_call(body);
    if (!call) {
        return {k_malformed, "malformed authenticated call"};
    }
    return {k_ok, encode_answer(execute(std::move(*call)))};
}

}  // namespace front_end_api

/// One front end a gateway or front end knows from configuration.
struct front_end_endpoint {
    std::string id;
    std::string url;
};

/// The front ends of a KMS and which of them answer (see the file
/// comment). Thread-safe.
class front_end_directory {
public:
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    /// `others`: every front end but this node. `self_serves`: whether
    /// this node is a front end itself, which always counts as live.
    front_end_directory(
        std::vector<front_end_endpoint> others, bool self_serves,
        std::chrono::milliseconds stale_after,
        clock_fn now = [] { return std::chrono::steady_clock::now(); })
        : _self_serves(self_serves), _stale_after(stale_after), _now(std::move(now)) {
        for (auto& e : others) {
            _entries.push_back(entry{std::move(e), std::nullopt});
        }
    }

    /// Records a probe's or a call's outcome for `url`: answered (live
    /// from now) or failed (not live until it answers again).
    void mark(std::string_view url, bool answered) {
        const std::scoped_lock lock(_mu);
        for (auto& e : _entries) {
            if (e.endpoint.url == url) {
                if (answered) {
                    e.last_answer = _now();
                } else {
                    e.last_answer.reset();
                }
            }
        }
    }

    /// Asks every other front end's health route once (`answered` is the
    /// probe, which must not throw), outside the lock.
    void probe(const std::function<bool(std::string_view url)>& answered) {
        for (const auto& url : urls()) {
            mark(url, answered(url));
        }
    }

    /// How many front ends answer now, this one included when it serves:
    /// how many share the quotas. At least one when this node serves.
    [[nodiscard]] auto live_count() const -> std::size_t {
        const std::scoped_lock lock(_mu);
        std::size_t n = _self_serves ? 1 : 0;
        const auto now = _now();
        for (const auto& e : _entries) {
            n += live(e, now) ? 1 : 0;
        }
        return n;
    }

    /// The order a gateway tries front ends in for its next call: the live
    /// ones from a rotating start, then the rest (a front end may answer
    /// before its next probe says so).
    [[nodiscard]] auto order() -> std::vector<std::string> {
        const std::scoped_lock lock(_mu);
        std::vector<std::string> live_urls;
        std::vector<std::string> rest;
        const auto now = _now();
        const auto n = _entries.size();
        const auto start = n == 0 ? std::size_t{0} : _next++ % n;
        for (std::size_t i = 0; i < n; ++i) {
            const auto& e = _entries[(start + i) % n];
            (live(e, now) ? live_urls : rest).push_back(e.endpoint.url);
        }
        live_urls.insert(live_urls.end(), rest.begin(), rest.end());
        return live_urls;
    }

    [[nodiscard]] auto size() const -> std::size_t {
        const std::scoped_lock lock(_mu);
        return _entries.size();
    }

private:
    struct entry {
        front_end_endpoint endpoint;
        std::optional<std::chrono::steady_clock::time_point> last_answer;
    };

    [[nodiscard]] auto live(const entry& e, std::chrono::steady_clock::time_point now) const
        -> bool {
        return e.last_answer && now - *e.last_answer <= _stale_after;
    }

    [[nodiscard]] auto urls() const -> std::vector<std::string> {
        const std::scoped_lock lock(_mu);
        std::vector<std::string> out;
        out.reserve(_entries.size());
        for (const auto& e : _entries) {
            out.push_back(e.endpoint.url);
        }
        return out;
    }

    bool _self_serves;
    std::chrono::milliseconds _stale_after;
    clock_fn _now;
    mutable std::mutex _mu;
    std::vector<entry> _entries;
    std::size_t _next = 0;
};

/// One exchange with a front end: the status and body if an answer came,
/// and whether the request may have reached it (mtls::client::attempt).
struct front_end_attempt {
    std::optional<std::pair<unsigned, std::string>> answer;
    bool may_have_arrived = false;
};

/// Why a gateway could not answer a call with a front end's response.
enum class handoff_failure : std::uint8_t {
    /// No front end took it: none answered, or every one that did said it
    /// was not executed. Safe for the client to retry.
    no_front_end,
    /// A front end may have run it but no answer came.
    outcome_unknown,
};

/// The gateway's side: hands calls to the front ends in `directory`
/// through `send` (an HTTPS request to a front end's listener).
class front_end_link {
public:
    using send_fn = std::function<front_end_attempt(std::string_view base_url,
                                                    std::string_view target, std::string body)>;

    front_end_link(front_end_directory& directory, send_fn send)
        : _directory(directory), _send(std::move(send)) {}

    /// The front end's KMS response to `call`, or why there is none. Tries
    /// front ends in the directory's order until one runs the call, moving
    /// on only when the call cannot have run where it was sent.
    [[nodiscard]] auto hand_over(const authenticated_call& call)
        -> std::variant<aws_json::http_response, handoff_failure> {
        const auto body = front_end_api::encode_call(call);
        for (const auto& url : _directory.order()) {
            front_end_attempt a;
            try {
                a = _send(url, front_end_api::k_call_path, body);
            } catch (const std::exception&) {
                a = {};
            }
            if (!a.answer) {
                _directory.mark(url, false);
                if (a.may_have_arrived) {
                    ++_unknown;
                    return handoff_failure::outcome_unknown;
                }
                continue;
            }
            if (a.answer->first == front_end_api::k_ok) {
                if (auto res = front_end_api::decode_answer(a.answer->second)) {
                    _directory.mark(url, true);
                    ++_handed_over;
                    return std::move(*res);
                }
                // It ran, but the answer is unreadable: the outcome is
                // unknown to the client.
                ++_unknown;
                return handoff_failure::outcome_unknown;
            }
            // 503: not executed (draining, or no front end there). 403 or
            // 400: refused before it ran (a misconfigured identity or a
            // version skew), so the call is safe elsewhere too.
            _directory.mark(url, false);
            ++_not_executed;
        }
        ++_unplaced;
        return handoff_failure::no_front_end;
    }

    struct stats {
        std::uint64_t handed_over = 0;
        std::uint64_t not_executed = 0;
        std::uint64_t outcome_unknown = 0;
        std::uint64_t no_front_end = 0;
    };

    [[nodiscard]] auto counters() const -> stats {
        return {_handed_over.load(), _not_executed.load(), _unknown.load(), _unplaced.load()};
    }

    /// The KMS error a gateway answers for `f`.
    [[nodiscard]] static auto error_for(handoff_failure f) -> aws_json::error {
        return f == handoff_failure::no_front_end
                   ? internal_error("No KMS front end could take the request; retry it.")
                   : internal_error(
                         "The KMS front end did not answer; the request may have been carried "
                         "out.");
    }

private:
    front_end_directory& _directory;
    send_fn _send;
    std::atomic<std::uint64_t> _handed_over{0};
    std::atomic<std::uint64_t> _not_executed{0};
    std::atomic<std::uint64_t> _unknown{0};
    std::atomic<std::uint64_t> _unplaced{0};
};

}  // namespace kythira::kms
