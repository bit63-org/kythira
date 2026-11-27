// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_front_end.hpp
/// @brief The EC2 front end: framing, SigV4, the EC2 query codec,
///        admission, authorization, `DryRun` and dispatch
///        (`.kiro/specs/ec2-compatible-api/` task 3, Requirements 3.2-3.5).
///
/// One request, in order:
///
///   1. Framing: a body no larger than the configured limit; `POST` with a
///      form-encoded body, or `GET` with the parameters in the query
///      string. Anything else is MalformedQueryString.
///   2. SigV4 through the authorizer (`aws_request_authorizer`: the IAM
///      authorizer, or `static_key_authorizer` without IAM), signing name
///      `ec2`. An unknown access key is EC2's AuthFailure (401, "AWS was
///      not able to validate the provided access credentials"); the other
///      SigV4 errors keep the query protocol's codes, which EC2 shares.
///      Authentication comes first, so an unsigned caller learns nothing
///      about the API.
///   3. The form, through `aws_ec2::params`: MalformedQueryString,
///      MissingAction, MissingParameter (no Version), NoSuchVersion. An
///      action the pinned model lacks is InvalidAction; a modelled one with
///      no handler is UnsupportedOperation (`doc/unsupported.md`).
///   4. Admission: the throttling hook (`ec2_throttle` when the account's
///      profile has throttling on) may refuse with RequestLimitExceeded.
///   5. `prepare`: the operation's validation, which reads the parameters,
///      refuses bad ones with EC2's error, changes nothing, and names every
///      resource EC2 authorizes the request on (`authz_plan`): for
///      RunInstances the instance, image, subnet, network interfaces,
///      volumes, key pair and security groups, with their condition keys.
///   6. Authorization: every check of the plan through the authorizer,
///      with `ec2:Region` and, per resource, its tags as
///      `aws:ResourceTag/*` and `ec2:ResourceTag/*`; request tags as
///      `aws:RequestTag/*` and `aws:TagKeys`; tagging on create as
///      `ec2:CreateTags` with `ec2:CreateAction`; an instance profile's
///      role as `iam:PassRole` with `iam:PassedToService`. An action the
///      operation checks that the plan does not name is checked on `*`
///      when the action has no resource types, and is otherwise a handler
///      bug (InternalError), as is a plan with no check at all, so no
///      operation is ever authorized on less than EC2 checks. A refusal is UnauthorizedOperation
///      (403) with the authorizer's encoded authorization message when it gives one, which
///      `sts:DecodeAuthorizationMessage` on Kythira's IAM module opens.
///   7. `DryRun=true` stops here with DryRunOperation (412): validation and
///      authorization passed and `execute` never runs, so nothing changes.
///   8. `execute`: the operation, returning the XML inside
///      `<{Action}Response>` after `requestId`, or EC2's error. An
///      exception is InternalError (500), which clients retry.
///
/// The front end is transport-free: the gateway adapts its HTTP request
/// into `front_end_request` and the response back.

#include <kythira/ec2/ec2_actions.hpp>
#include <kythira/ec2/model/operations.hpp>

#include <raft/aws_ec2_protocol.hpp>
#include <raft/aws_query_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/sigv4_verifier.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::ec2 {

struct front_end_config {
    std::string _region = "us-east-1";
    std::string _partition = "aws";
    /// The largest request body. RunInstances with 16 KB of user data and
    /// every list at its maximum stays well inside 1 MiB.
    std::size_t _max_body = 1024U * 1024U;
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

using tag_pairs = std::vector<std::pair<std::string, std::string>>;

/// One authorization check: an action on one resource.
struct authz_check {
    /// The `ec2` action without its prefix; empty means the operation's own
    /// (its same-named action).
    std::string _action;
    /// The resource type (`instance`) and its ID (`i-...`), or a full ARN
    /// in `_arn` for a resource of another service. Both empty: `*`.
    std::string _type;
    std::string _id;
    std::string _arn;
    /// The resource's owner when it is not the caller (a public image).
    std::string _account;
    /// Service condition keys (`ec2:InstanceType`, `ec2:Encrypted`).
    std::vector<std::pair<std::string, std::vector<std::string>>> _keys;
    /// The resource's own tags.
    tag_pairs _resource_tags;
    /// The tags the request puts on the resource, when it puts any.
    std::optional<tag_pairs> _request_tags;
};

/// Everything a request is authorized on (step 5).
struct authz_plan {
    std::vector<authz_check> _checks;
    /// Roles passed to EC2 (an instance profile's role), by ARN.
    std::vector<std::string> _pass_roles;

    /// The operation's own action on one resource.
    auto on(std::string type, std::string id) -> authz_check& {
        authz_check c;
        c._type = std::move(type);
        c._id = std::move(id);
        _checks.push_back(std::move(c));
        return _checks.back();
    }

    /// `ec2:CreateTags` on a resource the request creates and tags, as EC2
    /// checks for TagSpecifications: `ec2:CreateAction` names the
    /// operation.
    auto tag_on_create(std::string_view operation, std::string type, std::string id, tag_pairs tags)
        -> authz_check& {
        authz_check c;
        c._action = "CreateTags";
        c._type = std::move(type);
        c._id = std::move(id);
        c._keys.emplace_back("ec2:CreateAction", std::vector<std::string>{std::string(operation)});
        c._request_tags = std::move(tags);
        _checks.push_back(std::move(c));
        return _checks.back();
    }
};

/// What an operation sees besides its parameters.
struct call_context {
    std::string_view _operation;
    std::string _request_id;
    aws_auth::principal_context _principal;
    std::string _region;
    std::string _partition;
    bool _dry_run = false;
    /// The operation writes nothing, so any replica may answer it.
    bool _read_only = false;

    /// The ARN of `id` of type `type` in the caller's account (no account
    /// for images and snapshots, as on EC2).
    [[nodiscard]] auto arn(std::string_view type, std::string_view id) const -> std::string {
        return resource_arn(type, _partition, _region, _principal.account, id)
            .value_or(std::string());
    }
};

/// An operation: validation that names its resources, and the work.
struct operation_handler {
    std::function<aws_ec2::result<authz_plan>(call_context&, const aws_ec2::params&)> _prepare;
    std::function<aws_ec2::result<std::string>(call_context&, const aws_ec2::params&)> _execute;
};

/// Admission control (throttling): nullopt admits the request.
using admission_check = std::function<std::optional<aws_ec2::error>(
    std::string_view operation, const aws_auth::principal_context& who, const aws_ec2::params& p)>;

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

/// A random (version 4) UUID, the form of EC2's request ids.
[[nodiscard]] inline auto new_request_id() -> std::string {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("ec2: RAND_bytes failed");
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

[[nodiscard]] inline auto find_model_operation(std::string_view name)
    -> const model::operation_info* {
    const auto& ops = model::operations;
    const auto* it = std::lower_bound(
        ops.begin(), ops.end(), name,
        [](const model::operation_info& o, std::string_view n) { return o._name < n; });
    return it != ops.end() && it->_name == name ? &*it : nullptr;
}

/// The SigV4 parameters of a presigned GET, which are not API parameters.
[[nodiscard]] inline auto strip_signature_params(const aws_ec2::params& p) -> aws_ec2::params {
    aws_ec2::params::map_type out;
    for (const auto& [k, v] : p.all()) {
        if (!k.starts_with("X-Amz-")) {
            out.emplace(k, v);
        }
    }
    return aws_ec2::params(std::move(out));
}

[[nodiscard]] inline auto keys_of(const tag_pairs& tags) -> std::vector<std::string> {
    std::vector<std::string> out;
    out.reserve(tags.size());
    for (const auto& [k, _] : tags) {
        out.push_back(k);
    }
    return out;
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

    /// Registers an operation. Throws `std::invalid_argument` for one the
    /// model does not have, one already registered, or a handler missing
    /// either half.
    void on(std::string_view operation, operation_handler h) {
        if (front_end_detail::find_model_operation(operation) == nullptr) {
            throw std::invalid_argument("no such EC2 operation: " + std::string(operation));
        }
        if (!h._prepare || !h._execute) {
            throw std::invalid_argument("incomplete handler: " + std::string(operation));
        }
        if (!_handlers.emplace(std::string(operation), std::move(h)).second) {
            throw std::invalid_argument("handler already registered: " + std::string(operation));
        }
    }

    [[nodiscard]] auto handles(std::string_view operation) const -> bool {
        return _handlers.contains(operation);
    }

    /// Sets the admission (throttling) check, run after authentication.
    void set_admission(admission_check check) { _admit = std::move(check); }

    [[nodiscard]] auto handle(const front_end_request& req) -> front_end_response {
        const auto id = front_end_detail::new_request_id();
        if (req._body.size() > _config._max_body) {
            return refuse(aws_ec2::make_error(aws_ec2::codes::malformed_query,
                                              "The request body is larger than " +
                                                  std::to_string(_config._max_body) + " bytes."),
                          id);
        }
        const auto content_type = front_end_detail::header_value(req, "content-type");
        const bool post = req._method == "POST" && front_end_detail::is_form(content_type);
        const bool get = req._method == "GET";
        if (!post && !get) {
            return refuse(aws_ec2::make_error(aws_ec2::codes::malformed_query,
                                              "Requests must be a form-encoded POST or a GET."),
                          id);
        }

        sigv4::service_rules rules;
        rules.service = std::string(model::signing_name);
        rules.protocol = sigv4::error_protocol::query;
        if (!_config._region.empty()) {
            rules.regions = {_config._region};
        }
        const sigv4::request sreq{req._method, req._path, req._query, req._headers, req._body};
        const auto who = _authorizer.authenticate(sreq, rules);
        if (!who) {
            return refuse_sigv4(who.error(), id);
        }

        auto parsed = aws_ec2::params::parse(post ? std::string_view(req._body)
                                                  : std::string_view(req._query));
        if (!parsed) {
            return refuse(parsed.err(), id);
        }
        const auto in = get ? front_end_detail::strip_signature_params(*parsed) : *parsed;
        const auto request = aws_ec2::read_request(in);
        if (!request) {
            return refuse(request.err(), id);
        }
        const auto* op = front_end_detail::find_model_operation(request->action);
        if (op == nullptr) {
            return refuse(aws_ec2::make_error(aws_ec2::codes::invalid_action,
                                              "The action " + request->action +
                                                  " is not valid for this web service."),
                          id);
        }
        const auto h = _handlers.find(op->_name);
        if (h == _handlers.end()) {
            return refuse(aws_ec2::make_error(aws_ec2::codes::unsupported_operation,
                                              "The operation " + std::string(op->_name) +
                                                  " is not supported by this endpoint."),
                          id);
        }
        if (_admit) {
            if (auto refused = _admit(op->_name, *who, in)) {
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
        ctx._read_only = acts != nullptr && !acts->_writes;
        if (op->_dry_run) {
            const auto dry = in.boolean("DryRun");
            if (!dry) {
                return refuse(dry.err(), id);
            }
            ctx._dry_run = dry->value_or(false);
        }

        try {
            auto plan = h->second._prepare(ctx, in);
            if (!plan) {
                return refuse(plan.err(), id);
            }
            if (auto denied = authorize(ctx, req, *plan)) {
                return refuse(*denied, id);
            }
            if (ctx._dry_run) {
                return refuse(aws_ec2::dry_run_success(), id);
            }
            auto out = h->second._execute(ctx, in);
            if (!out) {
                return refuse(out.err(), id);
            }
            return answer(200, aws_ec2::response_xml(op->_name, id, *out), id);
        } catch (const std::exception&) {
            return refuse(internal_error(), id);
        }
    }

private:
    front_end_config _config;
    Authorizer& _authorizer;
    std::map<std::string, operation_handler, std::less<>> _handlers;
    admission_check _admit;

    [[nodiscard]] static auto internal_error() -> aws_ec2::error {
        return aws_ec2::make_error(aws_ec2::codes::internal_error,
                                   "An internal error has occurred");
    }

    [[nodiscard]] static auto answer(unsigned status, std::string body, const std::string& id)
        -> front_end_response {
        front_end_response r;
        r._status = status;
        r._headers = {{"Content-Type", "text/xml;charset=UTF-8"}, {"x-amzn-RequestId", id}};
        r._body = std::move(body);
        return r;
    }

    [[nodiscard]] static auto refuse(const aws_ec2::error& e, const std::string& id)
        -> front_end_response {
        return answer(aws_ec2::http_status(e.code), aws_ec2::error_xml(e, id), id);
    }

    [[nodiscard]] static auto refuse_sigv4(const sigv4::aws_error& e, const std::string& id)
        -> front_end_response {
        if (e.code == "InvalidClientTokenId") {
            return refuse(
                aws_ec2::make_error(aws_ec2::codes::auth_failure,
                                    "AWS was not able to validate the provided access credentials"),
                id);
        }
        return answer(static_cast<unsigned>(e.http_status),
                      aws_ec2::error_xml(e.code, e.message, id), id);
    }

    // Step 6. Completes the plan with every action the operation checks,
    // then runs each check.
    [[nodiscard]] auto authorize(const call_context& ctx, const front_end_request& req,
                                 authz_plan plan) -> std::optional<aws_ec2::error> {
        const auto* acts = find_operation_actions(ctx._operation);
        const std::string own(ctx._operation);
        for (auto& c : plan._checks) {
            if (c._action.empty()) {
                c._action = own;
            }
        }
        if (acts != nullptr) {
            for (const auto a : acts->_actions) {
                if (a.empty() || a == "CreateTags") {
                    // CreateTags is checked only when the request tags what
                    // it creates (plan.tag_on_create).
                    continue;
                }
                const bool named =
                    std::any_of(plan._checks.begin(), plan._checks.end(),
                                [&](const authz_check& c) { return c._action == a; });
                if (named) {
                    continue;
                }
                const auto* info = find_action(a);
                if (info == nullptr || info->_resources_n != 0) {
                    // A resource-level action the operation did not name a
                    // resource for: never authorize on less than EC2 does.
                    return internal_error();
                }
                authz_check c;
                c._action = std::string(a);
                plan._checks.push_back(std::move(c));
            }
        }
        if (plan._checks.empty()) {
            // An operation the reference gives no action and whose handler
            // named none: never answer without authorizing something.
            return internal_error();
        }
        for (const auto& c : plan._checks) {
            if (auto denied = check(ctx, req, c)) {
                return denied;
            }
        }
        for (const auto& role : plan._pass_roles) {
            aws_auth::authz_request r;
            r.action = "iam:PassRole";
            r.resource = role;
            r.keys.emplace_back("iam:PassedToService",
                                std::vector<std::string>{"ec2.amazonaws.com"});
            if (auto denied = decide(ctx, req, std::move(r))) {
                return denied;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto check(const call_context& ctx, const front_end_request& req,
                             const authz_check& c) -> std::optional<aws_ec2::error> {
        aws_auth::authz_request r;
        r.action = "ec2:" + c._action;
        if (!c._arn.empty()) {
            r.resource = c._arn;
        } else if (!c._type.empty()) {
            const auto account = c._account.empty() ? ctx._principal.account : c._account;
            auto arn = resource_arn(c._type, ctx._partition, ctx._region, account, c._id);
            if (!arn) {
                return internal_error();
            }
            r.resource = std::move(*arn);
        }
        if (!c._account.empty() && c._account != ctx._principal.account) {
            r.resource_account = c._account;
        }
        r.keys = c._keys;
        r.keys.emplace_back("ec2:Region", std::vector<std::string>{ctx._region});
        r.resource_tags = c._resource_tags;
        for (const auto& [k, v] : c._resource_tags) {
            r.keys.emplace_back("ec2:ResourceTag/" + k, std::vector<std::string>{v});
        }
        if (c._request_tags) {
            r.request_tags = c._request_tags;
            r.keys.emplace_back("aws:TagKeys", front_end_detail::keys_of(*c._request_tags));
        }
        return decide(ctx, req, std::move(r));
    }

    [[nodiscard]] auto decide(const call_context& ctx, const front_end_request& req,
                              aws_auth::authz_request r) -> std::optional<aws_ec2::error> {
        r.source_ip = req._source_ip;
        r.user_agent = std::string(front_end_detail::header_value(req, "user-agent"));
        r.region = _config._region;
        r.secure_transport = req._secure;
        r.want_encoded_message = true;
        const auto d = _authorizer.authorize(ctx._principal, r);
        if (d.allowed) {
            return std::nullopt;
        }
        std::string message =
            "You are not authorized to perform this operation. User: " + ctx._principal.arn +
            " is not authorized to perform: " + r.action + " on resource: " + r.resource +
            (d.explicit_deny
                 ? " with an explicit deny"
                 : " because no identity-based policy allows the " + r.action + " action");
        if (d.encoded_message) {
            message += ". Encoded authorization failure message: " + *d.encoded_message;
        }
        return aws_ec2::make_error(aws_ec2::codes::unauthorized_operation, std::move(message));
    }
};

}  // namespace kythira::ec2
