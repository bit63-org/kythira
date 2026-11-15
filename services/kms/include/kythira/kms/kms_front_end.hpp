// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS front end: framing, SigV4, dispatch and the authorization guard
// (.kiro/specs/kms-compatible-api/ task 6, Requirements 3.1 and 7.3).
//
// One request, in order:
//
//   1. Framing: `POST /`, the JSON 1.1 content type and an `X-Amz-Target`
//      of `TrentService.<Action>` naming a modeled operation; anything
//      else is the codec's error to word.
//   2. SigV4 through the authorizer (the IAM evaluator, or static keys
//      without IAM), signing service `kms`, before the body is read, so an
//      unsigned caller learns nothing about the API.
//   3. A modeled operation with no handler answers
//      UnsupportedOperationException (doc/unsupported.md lists them); then
//      the codec parses and validates the body against the pinned model.
//   4. The handler. Almost every KMS operation names its key by id, ARN
//      or alias, which only the catalog resolves, so the handler
//      authorizes through `call_context::authorize` once it knows the key
//      (with the key's policy as the resource policy). A handler that
//      answers without authorizing gets KMSInternalException, never the
//      data. An exception becomes KMSInternalException too.
//
// The front end is transport-free: the module adapts the HTTPS listener's
// request into `front_end_request` and the response back.

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/model/kms_model.hpp>

#include <raft/aws_json_protocol.hpp>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

struct front_end_config {
    std::string region = "us-east-1";
    std::string partition = "aws";
    aws_json::request_limits limits{.max_body_bytes = std::size_t{1} << 20U, .max_depth = 64};
};

/// An HTTP request as the transport hands it over.
struct front_end_request {
    std::string method;
    std::string path;
    std::string query;  ///< without '?'
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string source_ip;
    bool secure = true;
};

/// The parts of a KMS ARN (`arn:<partition>:kms:<region>:<account>:
/// <resource>`), or nullopt when `arn` is not one.
struct kms_arn {
    std::string_view partition;
    std::string_view region;
    std::string_view account;
    std::string_view resource;  ///< `key/<id>` or `alias/<name>`
};

[[nodiscard]] inline auto parse_kms_arn(std::string_view arn) -> std::optional<kms_arn> {
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
    if (parts[0] != "arn" || parts[2] != "kms" || parts[5].empty()) {
        return std::nullopt;
    }
    return kms_arn{parts[1], parts[3], parts[4], parts[5]};
}

/// What a handler sees besides its input.
struct call_context {
    std::string_view operation;
    std::string request_id;
    aws_auth::principal_context principal;
    std::string region;
    std::string partition;
    /// The operation writes nothing, so any replica may answer it.
    bool replica_read_ok = false;
    /// Set once an authorization succeeded; a handler that answers without
    /// it gets KMSInternalException.
    bool authorized = false;
    /// Authorizes one action. On refusal, the AccessDeniedException to
    /// return. An allowed call marks the request authorized.
    std::function<std::optional<aws_json::error>(aws_auth::authz_request)> authorize_fn;

    [[nodiscard]] auto authorize(aws_auth::authz_request r) -> std::optional<aws_json::error> {
        return authorize_fn(std::move(r));
    }

    /// `arn:<partition>:kms:<region>:<account>:key/<id>`.
    [[nodiscard]] auto key_arn(std::string_view account, std::string_view key_id) const
        -> std::string {
        return "arn:" + partition + ":kms:" + region + ":" + std::string(account) + ":key/" +
               std::string(key_id);
    }

    /// `arn:<partition>:kms:<region>:<account>:alias/<name>`, from
    /// `alias/<name>`.
    [[nodiscard]] auto alias_arn(std::string_view account, std::string_view alias_name) const
        -> std::string {
        return "arn:" + partition + ":kms:" + region + ":" + std::string(account) + ":" +
               std::string(alias_name);
    }
};

using front_end_handler =
    std::function<aws_json::result<boost::json::object>(call_context&, boost::json::object&)>;

namespace front_end_detail {

[[nodiscard]] inline auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
               return std::tolower(x) == std::tolower(y);
           });
}

[[nodiscard]] inline auto header_value(const front_end_request& r, std::string_view name)
    -> std::string_view {
    for (const auto& [n, v] : r.headers) {
        if (iequals(n, name)) {
            return v;
        }
    }
    return {};
}

}  // namespace front_end_detail

template<aws_auth::aws_request_authorizer Authorizer> class front_end {
public:
    front_end(front_end_config config, Authorizer& authorizer)
        : _config(std::move(config)),
          _authorizer(authorizer),
          _codec(kms_model::k_model, options(_config)) {}

    front_end(const front_end&) = delete;
    auto operator=(const front_end&) -> front_end& = delete;
    front_end(front_end&&) = delete;
    auto operator=(front_end&&) -> front_end& = delete;
    ~front_end() = default;

    /// Registers the handler for a KMS operation. Throws
    /// std::invalid_argument for an operation the model does not have or
    /// one already registered.
    void on(std::string_view operation, front_end_handler h) {
        if (kms_model::k_model.find_operation(operation) == nullptr) {
            throw std::invalid_argument("no such KMS operation: " + std::string(operation));
        }
        if (!_handlers.emplace(std::string(operation), std::move(h)).second) {
            throw std::invalid_argument("handler already registered: " + std::string(operation));
        }
    }

    [[nodiscard]] auto handles(std::string_view operation) const -> bool {
        return _handlers.contains(operation);
    }

    [[nodiscard]] auto config() const -> const front_end_config& { return _config; }

    [[nodiscard]] auto handle(const front_end_request& req) -> aws_json::http_response {
        const auto target = front_end_detail::header_value(req, "x-amz-target");
        const auto content_type = front_end_detail::header_value(req, "content-type");
        const aws_json::http_request_view view{req.method, req.path, content_type, target,
                                               req.body};
        constexpr auto json = aws_json::body_encoding::json;
        auto id = _codec.new_request_id();

        const auto* op = _codec.resolve_target(view);
        if (op == nullptr) {
            auto parsed = _codec.parse(view);
            return _codec.respond(parsed ? unknown_operation() : parsed.error(), id, json);
        }

        sigv4::service_rules rules;
        rules.service = "kms";
        rules.protocol = sigv4::error_protocol::json;
        if (!_config.region.empty()) {
            rules.regions = {_config.region};
        }
        const sigv4::request sreq{req.method, req.path, req.query, req.headers, req.body};
        const auto who = _authorizer.authenticate(sreq, rules);
        if (!who) {
            aws_json::error e;
            e.status = static_cast<unsigned>(who.error().http_status);
            e.type = who.error().code;
            e.message = who.error().message;
            return _codec.respond(e, id, json);
        }

        const auto h = _handlers.find(op->name);
        if (h == _handlers.end()) {
            return _codec.respond(
                unsupported("Kythira's KMS does not implement " + std::string(op->name) +
                            "; see services/kms/doc/unsupported.md"),
                id, json);
        }
        auto parsed = _codec.parse(view);
        if (!parsed) {
            return _codec.respond(parsed.error(), id, json);
        }

        call_context ctx;
        ctx.operation = op->name;
        ctx.request_id = id;
        ctx.principal = *who;
        ctx.region = _config.region;
        ctx.partition = _config.partition;
        const auto* acts = find_operation_actions(op->name);
        ctx.replica_read_ok = acts != nullptr && !acts->writes;
        ctx.authorize_fn = [this, &ctx, &req](aws_auth::authz_request r) {
            auto denied = check(ctx, req, std::move(r));
            if (!denied) {
                ctx.authorized = true;
            }
            return denied;
        };

        try {
            auto out = h->second(ctx, parsed->input);
            if (!out) {
                return _codec.respond(out.error(), id, json);
            }
            if (!ctx.authorized) {
                // A handler bug, not a client fault: never let data out
                // unauthorized.
                return _codec.respond(internal_error(), id, json);
            }
            return _codec.respond(*out, id, json, op);
        } catch (const std::exception&) {
            return _codec.respond(internal_error(), id, json);
        }
    }

private:
    [[nodiscard]] static auto options(const front_end_config& cfg) -> aws_json::codec_options {
        aws_json::codec_options o;
        o.style = kms_error_style();
        o.ids = aws_json::request_id_style::uuid;
        o.limits = cfg.limits;
        return o;
    }

    [[nodiscard]] static auto unknown_operation() -> aws_json::error {
        aws_json::error e;
        e.type = kms_error_style().unknown_operation_type;
        e.message = std::nullopt;
        return e;
    }

    [[nodiscard]] auto check(const call_context& ctx, const front_end_request& req,
                             aws_auth::authz_request r) -> std::optional<aws_json::error> {
        r.source_ip = req.source_ip;
        r.user_agent = std::string(front_end_detail::header_value(req, "user-agent"));
        r.region = _config.region;
        r.secure_transport = req.secure;
        if (r.resource != "*" && r.resource_account.empty()) {
            if (const auto parts = parse_kms_arn(r.resource);
                parts && parts->account != ctx.principal.account) {
                r.resource_account = std::string(parts->account);
            }
        }
        r.keys.emplace_back("kms:CallerAccount", std::vector<std::string>{ctx.principal.account});
        const auto d = _authorizer.authorize(ctx.principal, r);
        if (d.allowed) {
            return std::nullopt;
        }
        aws_json::error e;
        e.type = "AccessDeniedException";
        e.message = "User: " + ctx.principal.arn + " is not authorized to perform: " + r.action +
                    " on resource: " + r.resource +
                    (d.explicit_deny
                         ? " with an explicit deny"
                         : " because no resource-based policy allows the " + r.action + " action");
        return e;
    }

    front_end_config _config;
    Authorizer& _authorizer;
    aws_json::codec _codec;
    std::map<std::string, front_end_handler, std::less<>> _handlers;
};

}  // namespace kythira::kms
