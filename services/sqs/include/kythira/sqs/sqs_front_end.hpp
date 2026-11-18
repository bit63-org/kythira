// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_front_end.hpp
/// @brief The SQS front end: SigV4, queue resolution, authorization and
///        dispatch in both protocols (`.kiro/specs/sqs-compatible-queues/`
///        task 3, Requirements 3.1-3.3).
///
/// One request, in order:
///
///   1. Framing. A JSON request whose `X-Amz-Target` names no SQS
///      operation is answered with the codec's error before anything else.
///      A query request names its action in the signed body, so its
///      framing waits for step 2.
///   2. SigV4 through the authorizer (`aws_request_authorizer`: the IAM
///      authorizer, or `static_key_authorizer` without IAM), signing
///      service `sqs`, worded for the request's protocol. Nothing about the
///      API is answered to an unsigned caller beyond step 1.
///   3. A modeled operation with no handler answers UnknownOperationException
///      (JSON) or InvalidAction (query) before its input is validated: the
///      operations `doc/unsupported.md` lists. Then the codec parses and
///      validates the input.
///   4. The queue. `QueueUrl` (`<endpoint>/<account>/<name>`, any host, as
///      SQS accepts), `QueueName` (CreateQueue, GetQueueUrl, with
///      `QueueOwnerAWSAccountId` for another account's queue) or
///      `SourceArn` (the move-task operations). A URL or ARN that does not
///      name a queue answers QueueDoesNotExist, as SQS does.
///   5. Authorization: the operation's primary `sqs:` action
///      (`sqs_actions.hpp`; a batch authorizes as its single-entry action)
///      on the queue's ARN, or `*` for ListQueues, with the queue's tags and
///      policy from the resource lookup, so queue policies are evaluated
///      together with identity policies, cross-account included. Request
///      tags go in as `aws:RequestTag/*`, removed keys as `aws:TagKeys`.
///      CreateQueue with tags also needs `sqs:TagQueue` on the new queue.
///      CancelMessageMoveTask names its task by handle; its handler
///      authorizes through `sqs_call_context::authorize` once it has
///      looked the task up. A handler that answers without anything
///      authorized gets InternalFailure, never the data.
///   6. The handler. An exception becomes InternalFailure (500).
///
/// Every answer is in the request's protocol, with `x-amzn-query-error`
/// for a query-compatible JSON client (`sqs_errors.hpp`). The front end is
/// transport-free: the gateway adapts the Beast host's request into
/// `sqs_request` and the answer back.

#include <kythira/sqs/sqs_actions.hpp>
#include <kythira/sqs/sqs_codec.hpp>
#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_query_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

struct sqs_front_end_config {
    std::string _region = "us-east-1";
    std::string _partition = "aws";
    /// `scheme://host[:port]` queue URLs are minted on (`QueueUrl` answers)
    /// and query requests that name their queue by path resolve against.
    std::string _endpoint = "http://localhost:9324";
    aws_json::request_limits _limits{};
};

/// An HTTP request as the transport hands it over.
struct sqs_request {
    std::string _method;
    std::string _path;
    std::string _query;  ///< without '?'
    std::vector<std::pair<std::string, std::string>> _headers;
    std::string _body;
    std::string _source_ip;
    bool _secure = true;
};

/// What authorization needs to know about an existing queue: its tags
/// (`aws:ResourceTag/*`) and its `Policy` attribute, if it has one.
struct queue_facts {
    std::vector<std::pair<std::string, std::string>> _tags;
    std::optional<std::string> _policy;
};

/// Looks a queue up by ARN for authorization; nullopt when it does not
/// exist (the handler then answers QueueDoesNotExist).
using queue_lookup = std::function<std::optional<queue_facts>(std::string_view arn)>;

/// The queue a request acts on.
struct queue_ref {
    std::string _account;
    std::string _name;
    std::string _arn;
    std::string _url;
};

/// The parts of an SQS queue ARN (`arn:<partition>:sqs:<region>:<account>:
/// <name>`), or nullopt when `arn` is not one.
struct sqs_arn {
    std::string_view _partition;
    std::string_view _region;
    std::string_view _account;
    std::string_view _name;
};

[[nodiscard]] inline auto parse_sqs_arn(std::string_view arn) -> std::optional<sqs_arn> {
    std::array<std::string_view, 6> parts{};
    for (std::size_t i = 0; i < 5; ++i) {
        const auto colon = arn.find(':');
        if (colon == std::string_view::npos) {
            return std::nullopt;
        }
        parts.at(i) = arn.substr(0, colon);
        arn.remove_prefix(colon + 1);
    }
    parts[5] = arn;
    if (parts[0] != "arn" || parts[2] != "sqs" || parts[4].empty() || parts[5].empty() ||
        parts[5].find_first_of(":/") != std::string_view::npos) {
        return std::nullopt;
    }
    return sqs_arn{parts[1], parts[3], parts[4], parts[5]};
}

/// The account and name of a queue ARN as owned strings (the move worker's
/// `arn_fn`), or nullopt.
[[nodiscard]] inline auto sqs_arn_queue(const std::string& arn)
    -> std::optional<std::pair<std::string, std::string>> {
    const auto p = parse_sqs_arn(arn);
    if (!p) {
        return std::nullopt;
    }
    return std::pair{std::string(p->_account), std::string(p->_name)};
}

/// The account and queue name of a queue URL (`<scheme>://<host>/<account>/
/// <name>`), or nullopt. The host is not checked: SQS answers a URL on any
/// of its endpoint names, and a client behind a proxy may rewrite it.
[[nodiscard]] inline auto parse_queue_url(std::string_view url)
    -> std::optional<std::pair<std::string_view, std::string_view>> {
    const auto scheme = url.find("://");
    if (scheme == std::string_view::npos) {
        return std::nullopt;
    }
    auto rest = url.substr(scheme + 3);
    const auto slash = rest.find('/');
    if (slash == std::string_view::npos || slash == 0) {
        return std::nullopt;
    }
    rest.remove_prefix(slash + 1);
    const auto mid = rest.find('/');
    if (mid == std::string_view::npos) {
        return std::nullopt;
    }
    const auto account = rest.substr(0, mid);
    const auto name = rest.substr(mid + 1);
    if (account.empty() || name.empty() || name.find('/') != std::string_view::npos ||
        !std::all_of(account.begin(), account.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    return std::pair{account, name};
}

/// What a handler sees besides its input.
struct sqs_call_context {
    std::string_view _operation;
    std::string _request_id;
    aws_auth::principal_context _principal;
    std::string _region;
    std::string _partition;
    std::string _endpoint;
    sqs_protocol _protocol = sqs_protocol::json;
    /// The queue the request names, resolved (step 4).
    std::optional<queue_ref> _queue;
    /// The operation changes queue state, so it goes through the leader of
    /// the queue's group (ReceiveMessage included: it is a committed entry).
    bool _writes = true;
    /// Something authorized the request; when false at the end, the
    /// handler's answer is replaced with InternalFailure.
    bool _authorized = false;
    /// Authorizes one more action, or the request's own action on a
    /// resource only the handler could identify. On refusal, the
    /// AccessDenied error to return. An allowed call marks the request
    /// authorized.
    std::function<std::optional<aws_json::error>(aws_auth::authz_request)> _authorize;

    [[nodiscard]] auto queue_arn(std::string_view account, std::string_view name) const
        -> std::string {
        return "arn:" + _partition + ":sqs:" + _region + ":" + std::string(account) + ":" +
               std::string(name);
    }

    [[nodiscard]] auto queue_url(std::string_view account, std::string_view name) const
        -> std::string {
        return _endpoint + "/" + std::string(account) + "/" + std::string(name);
    }

    [[nodiscard]] auto make_queue_ref(std::string_view account, std::string_view name) const
        -> queue_ref {
        return queue_ref{std::string(account), std::string(name), queue_arn(account, name),
                         queue_url(account, name)};
    }

    [[nodiscard]] auto authorize(aws_auth::authz_request r) -> std::optional<aws_json::error> {
        return _authorize(std::move(r));
    }
};

using sqs_handler =
    std::function<aws_json::result<boost::json::object>(sqs_call_context&, boost::json::object&)>;

namespace front_end_detail {

[[nodiscard]] inline auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
               return std::tolower(x) == std::tolower(y);
           });
}

[[nodiscard]] inline auto header_value(const sqs_request& r, std::string_view name)
    -> std::string_view {
    for (const auto& [n, v] : r._headers) {
        if (iequals(n, name)) {
            return v;
        }
    }
    return {};
}

[[nodiscard]] inline auto string_member(const boost::json::object& o, std::string_view key)
    -> std::optional<std::string_view> {
    if (const auto* v = o.if_contains(key); v != nullptr && v->is_string()) {
        return std::string_view(v->get_string());
    }
    return std::nullopt;
}

/// The actions AWS defines with no resource (ListQueues): authorized on
/// `*`.
[[nodiscard]] inline auto resourceless_actions() -> const std::set<std::string, std::less<>>& {
    static const auto actions = [] {
        std::set<std::string, std::less<>> out;
        for (const auto& a : sqs_actions().actions) {
            if (a.resource_templates == std::vector<std::string>{"*"}) {
                out.emplace(a.name);
            }
        }
        return out;
    }();
    return actions;
}

[[nodiscard]] inline auto tags_of(const boost::json::object& in, std::string_view member)
    -> std::optional<std::vector<std::pair<std::string, std::string>>> {
    const auto* tags = in.if_contains(member);
    if (tags == nullptr || !tags->is_object()) {
        return std::nullopt;
    }
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& kv : tags->get_object()) {
        out.emplace_back(std::string(kv.key()),
                         kv.value().is_string() ? std::string(kv.value().get_string()) : "");
    }
    return out;
}

}  // namespace front_end_detail

template<aws_auth::aws_request_authorizer Authorizer> class sqs_front_end {
public:
    sqs_front_end(sqs_front_end_config config, Authorizer& authorizer)
        : _config(std::move(config)),
          _authorizer(authorizer),
          _codec(sqs_codec_options{.endpoint = _config._endpoint, .limits = _config._limits}) {}

    sqs_front_end(const sqs_front_end&) = delete;
    auto operator=(const sqs_front_end&) -> sqs_front_end& = delete;
    sqs_front_end(sqs_front_end&&) = delete;
    auto operator=(sqs_front_end&&) -> sqs_front_end& = delete;
    ~sqs_front_end() = default;

    /// Registers the handler for an SQS operation. Throws
    /// `std::invalid_argument` for an operation the model does not have or
    /// one already registered.
    void on(std::string_view operation, sqs_handler h) {
        if (sqs_codec::model().find_operation(operation) == nullptr) {
            throw std::invalid_argument("no such SQS operation: " + std::string(operation));
        }
        if (!_handlers.emplace(std::string(operation), std::move(h)).second) {
            throw std::invalid_argument("handler already registered: " + std::string(operation));
        }
    }

    [[nodiscard]] auto handles(std::string_view operation) const -> bool {
        return _handlers.contains(operation);
    }

    /// Supplies queue tags and policies to authorization. Without it,
    /// requests are authorized on identity policies alone.
    void set_queue_lookup(queue_lookup lookup) { _lookup = std::move(lookup); }

    [[nodiscard]] auto codec() const -> const sqs_codec& { return _codec; }
    [[nodiscard]] auto config() const -> const sqs_front_end_config& { return _config; }

    [[nodiscard]] auto handle(const sqs_request& req) -> aws_json::http_response {
        const auto content_type = front_end_detail::header_value(req, "content-type");
        const auto target = front_end_detail::header_value(req, "x-amz-target");
        const sqs_request_view view{
            .method = req._method,
            .path = req._path,
            .query_string = req._query,
            .content_type = content_type,
            .target = target,
            .query_mode = front_end_detail::iequals(
                front_end_detail::header_value(req, "x-amzn-query-mode"), "true"),
            .body = req._body,
        };
        const auto protocol = sqs_codec::protocol_of(view);
        auto id = _codec.new_request_id();

        // Step 1.
        if (protocol == sqs_protocol::json &&
            _codec.json_codec().resolve_target(aws_json::http_request_view{
                .method = req._method,
                .path = req._path,
                .content_type = content_type,
                .target = target,
                .body = req._body,
            }) == nullptr) {
            auto parsed = _codec.parse(view);
            return _codec.respond(view, parsed ? unknown_operation() : parsed.error(), id);
        }

        // Step 2.
        sigv4::service_rules rules;
        rules.service = "sqs";
        rules.protocol = protocol == sqs_protocol::json ? sigv4::error_protocol::json
                                                        : sigv4::error_protocol::query;
        if (!_config._region.empty()) {
            rules.regions = {_config._region};
        }
        const sigv4::request sreq{req._method, req._path, req._query, req._headers, req._body};
        const auto who = _authorizer.authenticate(sreq, rules);
        if (!who) {
            return _codec.respond(view, auth_error(who.error()), id);
        }

        // Step 3.
        if (const auto name = operation_name(view); name && !_handlers.contains(*name)) {
            return _codec.respond(view, unknown_operation(), id);
        }
        auto parsed = _codec.parse(view);
        if (!parsed) {
            return _codec.respond(view, parsed.error(), id);
        }
        const auto& op = *parsed->op;
        auto& input = parsed->input;
        const auto h = _handlers.find(op.name);
        if (h == _handlers.end()) {
            return _codec.respond(view, unknown_operation(), id);
        }

        sqs_call_context ctx;
        ctx._operation = op.name;
        ctx._request_id = id;
        ctx._principal = *who;
        ctx._region = _config._region;
        ctx._partition = _config._partition;
        ctx._endpoint = _config._endpoint;
        ctx._protocol = protocol;
        const auto* acts = find_operation_actions(op.name);
        ctx._writes = acts == nullptr || acts->writes;
        ctx._authorize = [this, &ctx, &req](aws_auth::authz_request r) {
            auto denied = check(ctx, req, std::move(r));
            if (!denied) {
                ctx._authorized = true;
            }
            return denied;
        };

        // Step 4.
        auto queue = resolve_queue(ctx, input);
        if (!queue) {
            return _codec.respond(view, queue.error(), id);
        }
        ctx._queue = std::move(*queue);

        // Step 5.
        if (auto denied = authorize_primary(ctx, input, acts)) {
            return _codec.respond(view, *denied, id);
        }

        // Step 6.
        try {
            auto out = h->second(ctx, input);
            if (!out) {
                return _codec.respond(view, out.error(), id);
            }
            if (!ctx._authorized) {
                // A handler bug, not a client fault: never let data out
                // unauthorized.
                return _codec.respond(view, internal_failure(), id);
            }
            return _codec.respond(view, op, *out, id);
        } catch (const std::exception&) {
            return _codec.respond(view, internal_failure(), id);
        }
    }

private:
    sqs_front_end_config _config;
    Authorizer& _authorizer;
    sqs_codec _codec;
    std::map<std::string, sqs_handler, std::less<>> _handlers;
    queue_lookup _lookup;

    [[nodiscard]] static auto unknown_operation() -> aws_json::error {
        return make_error(k_unknown_operation_error, "The action is not valid for this endpoint.");
    }

    [[nodiscard]] static auto auth_error(const sigv4::aws_error& e) -> aws_json::error {
        aws_json::error out;
        out.status = static_cast<unsigned>(e.http_status);
        out.type = e.code;
        out.message = e.message;
        return out;
    }

    /// The operation a request names, without validating its input: the
    /// target's suffix (JSON) or the form's Action (query). Nullopt when
    /// the request names none the codec could read; the codec's parse
    /// then words the fault.
    [[nodiscard]] static auto operation_name(const sqs_request_view& view)
        -> std::optional<std::string> {
        const aws_json::operation* op = nullptr;
        if (sqs_codec::protocol_of(view) == sqs_protocol::json) {
            const auto dot = view.target.rfind('.');
            op = dot == std::string_view::npos
                     ? nullptr
                     : sqs_codec::model().find_operation(view.target.substr(dot + 1));
        } else {
            const auto f =
                aws_query::form::parse(view.method == "GET" ? view.query_string : view.body);
            const auto action = f ? f->get("Action") : std::nullopt;
            op = action ? sqs_codec::model().find_operation(*action) : nullptr;
        }
        return op != nullptr ? std::optional<std::string>(op->name) : std::nullopt;
    }

    // Step 4: the one queue the request acts on.
    [[nodiscard]] static auto resolve_queue(const sqs_call_context& ctx,
                                            const boost::json::object& in)
        -> aws_json::result<std::optional<queue_ref>> {
        using front_end_detail::string_member;
        if (const auto url = string_member(in, "QueueUrl")) {
            const auto parts = parse_queue_url(*url);
            if (!parts) {
                return queue_does_not_exist();
            }
            auto ref = ctx.make_queue_ref(parts->first, parts->second);
            ref._url = std::string(*url);
            return std::optional<queue_ref>(std::move(ref));
        }
        if (const auto arn = string_member(in, "SourceArn")) {
            const auto parts = parse_sqs_arn(*arn);
            if (!parts) {
                return queue_does_not_exist();
            }
            auto ref = ctx.make_queue_ref(parts->_account, parts->_name);
            ref._arn = std::string(*arn);
            return std::optional<queue_ref>(std::move(ref));
        }
        if (const auto name = string_member(in, "QueueName")) {
            const auto owner = string_member(in, "QueueOwnerAWSAccountId");
            return std::optional<queue_ref>(ctx.make_queue_ref(
                owner ? *owner : std::string_view(ctx._principal.account), *name));
        }
        return std::optional<queue_ref>{};
    }

    // Step 5.
    [[nodiscard]] auto authorize_primary(sqs_call_context& ctx, const boost::json::object& in,
                                         const operation_actions* acts)
        -> std::optional<aws_json::error> {
        if (acts == nullptr) {
            return std::nullopt;
        }
        std::string resource;
        if (front_end_detail::resourceless_actions().contains(acts->primary_action)) {
            resource = "*";
        } else if (ctx._queue) {
            resource = ctx._queue->_arn;
        } else {
            // The input does not name the queue (CancelMessageMoveTask's
            // task handle): the handler authorizes.
            return std::nullopt;
        }
        aws_auth::authz_request r;
        r.action = "sqs:" + std::string(acts->primary_action);
        r.resource = resource;
        const auto request_tags =
            front_end_detail::tags_of(in, ctx._operation == "CreateQueue" ? "tags" : "Tags");
        r.request_tags = request_tags;
        if (const auto* keys = in.if_contains("TagKeys"); keys != nullptr && keys->is_array()) {
            std::vector<std::string> names;
            for (const auto& k : keys->get_array()) {
                if (k.is_string()) {
                    names.emplace_back(k.get_string());
                }
            }
            r.keys.emplace_back("aws:TagKeys", std::move(names));
        }
        if (auto denied = ctx.authorize(std::move(r))) {
            return denied;
        }
        if (ctx._operation == "CreateQueue" && request_tags && !request_tags->empty()) {
            aws_auth::authz_request tag;
            tag.action = "sqs:TagQueue";
            tag.resource = resource;
            tag.request_tags = request_tags;
            return ctx.authorize(std::move(tag));
        }
        return std::nullopt;
    }

    [[nodiscard]] auto check(const sqs_call_context& ctx, const sqs_request& req,
                             aws_auth::authz_request r) -> std::optional<aws_json::error> {
        r.source_ip = req._source_ip;
        r.user_agent = std::string(front_end_detail::header_value(req, "user-agent"));
        r.region = _config._region;
        r.secure_transport = req._secure;
        if (r.resource != "*") {
            if (r.resource_account.empty()) {
                if (const auto parts = parse_sqs_arn(r.resource);
                    parts && parts->_account != ctx._principal.account) {
                    r.resource_account = std::string(parts->_account);
                }
            }
            if (_lookup) {
                if (auto facts = _lookup(r.resource)) {
                    if (r.resource_tags.empty()) {
                        r.resource_tags = std::move(facts->_tags);
                    }
                    if (!r.resource_policy) {
                        r.resource_policy = std::move(facts->_policy);
                    }
                }
            }
        }
        const auto d = _authorizer.authorize(ctx._principal, r);
        if (d.allowed) {
            return std::nullopt;
        }
        return make_error(
            k_access_denied_error,
            "User: " + ctx._principal.arn + " is not authorized to perform: " + r.action +
                " on resource: " + r.resource +
                (d.explicit_deny
                     ? " with an explicit deny"
                     : " because no identity-based policy allows the " + r.action + " action"));
    }
};

}  // namespace kythira::sqs
