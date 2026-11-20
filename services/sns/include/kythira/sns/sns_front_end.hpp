// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_front_end.hpp
/// @brief The SNS front end: framing, SigV4, the query codec, authorization
///        and dispatch (`.kiro/specs/sns-compatible-notifications/` task 3,
///        Requirements 2.2, 3.1 and 3.2).
///
/// One request, in order:
///
///   1. Framing: a body no larger than the configured limit; `POST` with a
///      form-encoded body (the content type's charset is optional: the JS
///      and Go SDKs leave it off), or `GET` with the parameters in the
///      query string. Anything else is MalformedQueryString.
///   2. SigV4 through the authorizer (`aws_request_authorizer`: the IAM
///      authorizer, or `static_key_authorizer` without IAM), signing name
///      `sns`, errors in the query protocol's words. Authentication comes
///      before the parameters are read, so an unsigned caller learns
///      nothing about the API.
///   3. The form: a parameter named twice is MalformedQueryString, as on
///      AWS. `Action` missing is MissingAction; a `Version` other than
///      2010-03-31, an action the model lacks, or a modelled one with no
///      handler (the SMS and push operations `doc/unsupported.md` lists)
///      is InvalidAction.
///   4. Admission: the throttling hook, when the composition root sets one
///      (`sns_compat_profile` holds the rates), may refuse with Throttled.
///   5. The topic the request acts on: `TopicArn`, `ResourceArn` (the tag
///      operations), `TargetArn` (Publish), the topic inside
///      `SubscriptionArn`, or for
///      CreateTopic the ARN `Name` would have. A value that is not such an
///      ARN is InvalidParameter before anything is authorized.
///   6. Authorization: the operation's `sns:` action (`sns:Publish` for
///      PublishBatch) on that topic, or on `*` for the actions AWS defines
///      without a resource (ListTopics, ListSubscriptions). The topic's
///      policy and tags come from the resource lookup and are evaluated
///      with the caller's identity policies; a topic in another account is
///      named as the resource account. The request supplies
///      `aws:SourceOwner` (the caller's account, as SNS does for a direct
///      call, which is what the default topic policy keys on), Subscribe's
///      `sns:Protocol` and `sns:Endpoint`, and the request's tags as
///      `aws:RequestTag/*` and `aws:TagKeys`. CreateTopic with tags also
///      needs `sns:TagResource`, and with a `DataProtectionPolicy`
///      attribute `sns:PutDataProtectionPolicy`, as on AWS. A refusal is
///      AuthorizationError (403).
///   7. The handler, with the parameters as a `params` view. It returns
///      the XML inside `<{Action}Result>` (empty for an operation with no
///      result) or an `sns_error`. A handler that answers for an
///      unauthorized request gets InternalError instead; an exception is
///      InternalError too (500, Receiver), which clients retry.
///
/// The front end is transport-free: the gateway (the daemon's Beast host)
/// adapts its request into `front_end_request` and the response back.
/// Routing (a publish to the topic partition's leader, a read from any
/// replica) is the handlers' business, from `call_context::_read_only`.

#include <kythira/sns/sns_actions.hpp>
#include <kythira/sns/sns_errors.hpp>
#include <kythira/sns/sns_operations.hpp>
#include <kythira/sns/sns_query.hpp>
#include <kythira/sns/sns_topic_policy.hpp>

#include <raft/aws_query_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/sigv4_verifier.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
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

namespace kythira::sns {

struct front_end_config {
    std::string _region = "us-east-1";
    std::string _partition = "aws";
    /// The largest request body. A 1 MiB message form-encodes to at most
    /// three times its size, and a batch of ten carries at most 1 MiB in
    /// all, so 4 MiB admits every request SNS does.
    std::size_t _max_body = 4U * 1024U * 1024U;
};

/// An HTTP request as the transport hands it over.
struct front_end_request {
    std::string _method;
    std::string _path;
    std::string _query;  ///< without '?'
    std::vector<std::pair<std::string, std::string>> _headers;
    std::string _body;
    std::string _source_ip;
    bool _secure = true;
};

struct front_end_response {
    unsigned _status = 200;
    std::vector<std::pair<std::string, std::string>> _headers;
    std::string _body;
};

/// What authorization needs to know about a topic.
struct resource_facts {
    std::optional<std::string> _policy;
    tag_list _tags;
};

/// Looks a topic up by ARN; nullopt when it does not exist (the handler
/// then answers NotFound).
using resource_lookup = std::function<std::optional<resource_facts>(std::string_view topic_arn)>;

/// Admission control (throttling): nullopt admits the request.
using admission_check = std::function<std::optional<sns_error>(
    std::string_view operation, const aws_auth::principal_context& who)>;

/// What a handler sees besides its parameters.
struct call_context {
    std::string_view _operation;
    std::string _request_id;
    aws_auth::principal_context _principal;
    std::string _region;
    std::string _partition;
    /// The topic the request names (step 5), when it names one.
    std::optional<topic_arn_parts> _topic;
    std::string _topic_arn;
    /// The operation writes nothing, so any replica may answer it.
    bool _read_only = false;
    /// The front end authorized the request; when false, the handler must
    /// call `authorize` before it answers.
    bool _authorized = false;
    /// Authorizes one more action, or the request's own action on a
    /// resource only the handler could identify. On refusal, the
    /// AuthorizationError to return. An allowed call marks the request
    /// authorized.
    std::function<std::optional<sns_error>(aws_auth::authz_request)> _authorize;

    /// `arn:<partition>:sns:<region>:<account>:<name>`, in the caller's
    /// account.
    [[nodiscard]] auto topic_arn(std::string_view name) const -> std::string {
        return "arn:" + _partition + ":sns:" + _region + ":" + _principal.account + ":" +
               std::string(name);
    }

    [[nodiscard]] auto authorize(aws_auth::authz_request r) -> std::optional<sns_error> {
        return _authorize(std::move(r));
    }
};

/// A handler: the XML inside `<{Action}Result>`, or the error.
using front_end_handler = std::function<query_result<std::string>(call_context&, const params&)>;

namespace front_end_detail {

[[nodiscard]] inline auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
               return std::tolower(x) == std::tolower(y);
           });
}

[[nodiscard]] inline auto header_value(const front_end_request& r, std::string_view name)
    -> std::string_view {
    for (const auto& [n, v] : r._headers) {
        if (iequals(n, name)) {
            return v;
        }
    }
    return {};
}

[[nodiscard]] inline auto is_form(std::string_view content_type) -> bool {
    auto media = content_type.substr(0, content_type.find(';'));
    while (!media.empty() && media.back() == ' ') {
        media.remove_suffix(1);
    }
    return iequals(media, "application/x-www-form-urlencoded");
}

/// The actions AWS defines with no resource: authorized on `*`.
[[nodiscard]] inline auto resourceless_actions() -> const std::set<std::string, std::less<>>& {
    static const auto actions = [] {
        std::set<std::string, std::less<>> out;
        for (const auto& a : sns_actions().actions) {
            if (a.resource_templates == std::vector<std::string>{"*"}) {
                out.emplace(a.name);
            }
        }
        return out;
    }();
    return actions;
}

/// The `sns` action an operation is authorized as: its same-named action,
/// or for PublishBatch the one it maps to. nullopt when the reference has
/// none.
[[nodiscard]] inline auto primary_action(std::string_view operation)
    -> std::optional<std::string_view> {
    const auto* acts = find_operation_actions(operation);
    if (acts == nullptr) {
        return std::nullopt;
    }
    for (const auto a : acts->actions) {
        if (a == operation) {
            return a;
        }
    }
    if (!acts->actions[0].empty()) {
        return acts->actions[0];
    }
    return std::nullopt;
}

/// A random (version 4) UUID, the form of SNS's request ids.
[[nodiscard]] inline auto new_request_id() -> std::string {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("sns: RAND_bytes failed");
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0FU) | 0x40U);
    b[8] = static_cast<unsigned char>((b[8] & 0x3FU) | 0x80U);
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out.push_back('-');
        }
        out.push_back(hex[b.at(i) >> 4U]);
        out.push_back(hex[b.at(i) & 0x0FU]);
    }
    return out;
}

/// The SigV4 parameters of a presigned GET, which are not API parameters.
[[nodiscard]] inline auto is_signature_param(std::string_view name) -> bool {
    return name.starts_with("X-Amz-");
}

}  // namespace front_end_detail

template<aws_auth::aws_request_authorizer Authorizer> class front_end {
public:
    front_end(front_end_config config, Authorizer& authorizer)
        : _config(std::move(config)), _authorizer(authorizer) {}

    front_end(const front_end&) = delete;
    auto operator=(const front_end&) -> front_end& = delete;
    front_end(front_end&&) = delete;
    auto operator=(front_end&&) -> front_end& = delete;
    ~front_end() = default;

    /// Registers the handler for an SNS operation. Throws
    /// `std::invalid_argument` for an operation the model does not have or
    /// one already registered.
    void on(std::string_view operation, front_end_handler h) {
        if (find_operation(operation) == nullptr) {
            throw std::invalid_argument("no such SNS operation: " + std::string(operation));
        }
        if (!_handlers.emplace(std::string(operation), std::move(h)).second) {
            throw std::invalid_argument("handler already registered: " + std::string(operation));
        }
    }

    [[nodiscard]] auto handles(std::string_view operation) const -> bool {
        return _handlers.contains(operation);
    }

    /// Supplies topic policies and tags to authorization. Without it,
    /// requests are authorized on identity policies alone.
    void set_resource_lookup(resource_lookup lookup) { _lookup = std::move(lookup); }

    /// Sets the admission (throttling) check, run after authentication.
    void set_admission(admission_check check) { _admit = std::move(check); }

    [[nodiscard]] auto handle(const front_end_request& req) -> front_end_response {
        const auto id = front_end_detail::new_request_id();
        if (req._body.size() > _config._max_body) {
            return refuse(request_too_large(), id);
        }
        const auto content_type = front_end_detail::header_value(req, "content-type");
        const bool post = req._method == "POST" && front_end_detail::is_form(content_type);
        const bool get = req._method == "GET";
        if (!post && !get) {
            return refuse(malformed_query("Requests must be a form-encoded POST or a GET."), id);
        }

        sigv4::service_rules rules;
        rules.service = std::string(signing_name);
        rules.protocol = sigv4::error_protocol::query;
        if (!_config._region.empty()) {
            rules.regions = {_config._region};
        }
        const sigv4::request sreq{req._method, req._path, req._query, req._headers, req._body};
        const auto who = _authorizer.authenticate(sreq, rules);
        if (!who) {
            return refuse(from_sigv4(who.error()), id);
        }

        const auto form = aws_query::form::parse(post ? std::string_view(req._body)
                                                      : std::string_view(req._query));
        if (!form) {
            return refuse(malformed_query("The request parameters could not be read."), id);
        }
        param_map all;
        for (const auto& [k, v] : form->params()) {
            if (get && front_end_detail::is_signature_param(k)) {
                continue;
            }
            all.emplace(k, v);
        }
        const params in(all);
        const auto action = in.get("Action");
        if (!action || action->empty()) {
            return refuse(missing_action(), id);
        }
        if (const auto v = in.get("Version"); v && *v != api_version) {
            return refuse(invalid_action(*action), id);
        }
        const auto* op = find_operation(*action);
        const auto h = op == nullptr ? _handlers.end() : _handlers.find(op->_name);
        if (h == _handlers.end()) {
            return refuse(invalid_action(*action), id);
        }
        if (_admit) {
            if (auto refused = _admit(op->_name, *who)) {
                return refuse(*refused, id);
            }
        }

        call_context ctx;
        ctx._operation = op->_name;
        ctx._request_id = id;
        ctx._principal = *who;
        ctx._region = _config._region;
        ctx._partition = _config._partition;
        const auto* acts = find_operation_actions(op->_name);
        ctx._read_only = acts != nullptr && !acts->writes;
        ctx._authorize = [this, &ctx, &req](aws_auth::authz_request r) {
            auto denied = check(ctx, req, std::move(r));
            if (!denied) {
                ctx._authorized = true;
            }
            return denied;
        };

        if (auto bad = resolve_topic(ctx, in)) {
            return refuse(*bad, id);
        }
        if (auto denied = authorize_primary(ctx, in)) {
            return refuse(*denied, id);
        }

        try {
            auto out = h->second(ctx, in);
            if (!out) {
                return refuse(out.error(), id);
            }
            if (!ctx._authorized) {
                // A handler bug, not a client fault: never let data out
                // unauthorized.
                return refuse(internal_error(), id);
            }
            return answer(200, aws_query::response_xml(op->_name, xml_namespace, *out, id), id);
        } catch (const std::exception&) {
            return refuse(internal_error(), id);
        }
    }

private:
    front_end_config _config;
    Authorizer& _authorizer;
    std::map<std::string, front_end_handler, std::less<>> _handlers;
    resource_lookup _lookup;
    admission_check _admit;

    [[nodiscard]] static auto answer(unsigned status, std::string body, const std::string& id)
        -> front_end_response {
        front_end_response r;
        r._status = status;
        r._headers = {{"Content-Type", "text/xml"}, {"x-amzn-RequestId", id}};
        r._body = std::move(body);
        return r;
    }

    [[nodiscard]] static auto refuse(const sns_error& e, const std::string& id)
        -> front_end_response {
        return answer(e._status, error_document(e, id), id);
    }

    // Step 5: the one topic the request acts on.
    [[nodiscard]] static auto resolve_topic(call_context& ctx, const params& in)
        -> std::optional<sns_error> {
        const auto set = [&ctx](std::string arn) {
            ctx._topic = parse_topic_arn(arn);
            ctx._topic_arn = std::move(arn);
        };
        if (ctx._operation == "CreateTopic") {
            // The name is the handler's to validate (it depends on the
            // FifoTopic attribute); authorization needs only the ARN.
            if (const auto name = in.get("Name"); name && !name->empty()) {
                set(ctx.topic_arn(*name));
            }
            return std::nullopt;
        }
        // Publish may name its topic as TargetArn; a platform endpoint ARN
        // there (mobile push, out of scope) is not a topic ARN, so it is
        // InvalidParameter.
        for (const auto* key : {"TopicArn", "ResourceArn", "TargetArn"}) {
            if (const auto arn = in.get(key)) {
                if (!parse_topic_arn(*arn)) {
                    return invalid_parameter(key);
                }
                set(std::string(*arn));
                return std::nullopt;
            }
        }
        if (const auto arn = in.get("SubscriptionArn")) {
            auto topic = topic_of_subscription(*arn);
            if (!topic) {
                return invalid_parameter("SubscriptionArn");
            }
            set(std::move(*topic));
        }
        return std::nullopt;
    }

    // Step 6.
    [[nodiscard]] auto authorize_primary(call_context& ctx, const params& in)
        -> std::optional<sns_error> {
        const auto action = front_end_detail::primary_action(ctx._operation);
        if (!action) {
            // No action in the reference (none today): the handler
            // authorizes.
            return std::nullopt;
        }
        aws_auth::authz_request r;
        r.action = "sns:" + std::string(*action);
        if (front_end_detail::resourceless_actions().contains(*action)) {
            r.resource = "*";
        } else if (!ctx._topic_arn.empty()) {
            r.resource = ctx._topic_arn;
        } else {
            // The input names no topic (a required parameter missing): the
            // handler refuses, or authorizes once it knows the resource.
            return std::nullopt;
        }
        if (ctx._operation == "Subscribe") {
            r.keys.emplace_back("sns:Protocol", std::vector<std::string>{
                                                    std::string(in.get("Protocol").value_or(""))});
            r.keys.emplace_back("sns:Endpoint", std::vector<std::string>{
                                                    std::string(in.get("Endpoint").value_or(""))});
        }
        std::optional<tag_list> request_tags;
        if (ctx._operation == "CreateTopic" || ctx._operation == "TagResource") {
            auto tags = in.tags();
            if (!tags) {
                return tags.error();
            }
            if (!tags->empty() || ctx._operation == "TagResource") {
                request_tags = std::move(*tags);
            }
        }
        if (request_tags) {
            std::vector<std::string> keys;
            for (const auto& [k, _] : *request_tags) {
                keys.push_back(k);
            }
            r.keys.emplace_back("aws:TagKeys", std::move(keys));
            r.request_tags = request_tags;
        }
        if (ctx._operation == "UntagResource") {
            auto keys = in.list("TagKeys");
            if (!keys) {
                return keys.error();
            }
            r.keys.emplace_back("aws:TagKeys", std::move(*keys));
        }
        const auto resource = r.resource;
        if (auto denied = ctx.authorize(std::move(r))) {
            return denied;
        }
        if (ctx._operation == "CreateTopic") {
            if (request_tags) {
                aws_auth::authz_request tag;
                tag.action = "sns:TagResource";
                tag.resource = resource;
                tag.request_tags = request_tags;
                std::vector<std::string> keys;
                for (const auto& [k, _] : *request_tags) {
                    keys.push_back(k);
                }
                tag.keys.emplace_back("aws:TagKeys", std::move(keys));
                if (auto denied = ctx.authorize(std::move(tag))) {
                    return denied;
                }
            }
            auto attrs = in.string_map("Attributes");
            if (!attrs) {
                return attrs.error();
            }
            if (attrs->contains("DataProtectionPolicy")) {
                aws_auth::authz_request dpp;
                dpp.action = "sns:PutDataProtectionPolicy";
                dpp.resource = resource;
                return ctx.authorize(std::move(dpp));
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto check(const call_context& ctx, const front_end_request& req,
                             aws_auth::authz_request r) -> std::optional<sns_error> {
        r.source_ip = req._source_ip;
        r.user_agent = std::string(front_end_detail::header_value(req, "user-agent"));
        r.region = _config._region;
        r.secure_transport = req._secure;
        r.keys.emplace_back("aws:SourceOwner", std::vector<std::string>{ctx._principal.account});
        if (r.resource != "*") {
            const auto parts = parse_topic_arn(r.resource);
            if (r.resource_account.empty() && parts && parts->_account != ctx._principal.account) {
                r.resource_account = parts->_account;
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
        // SNS names its actions `SNS:Publish` in this message.
        const auto shown = "SNS:" + r.action.substr(r.action.find(':') + 1);
        return authorization_error(
            "User: " + ctx._principal.arn + " is not authorized to perform: " + shown +
            " on resource: " + r.resource +
            (d.explicit_deny
                 ? " with an explicit deny"
                 : " because no identity-based policy allows the " + shown + " action"));
    }
};

}  // namespace kythira::sns
