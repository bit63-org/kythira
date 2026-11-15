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
#include <kythira/kms/kms_grants.hpp>
#include <kythira/kms/kms_quotas.hpp>
#include <kythira/kms/model/kms_model.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/kms_forwarding.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
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
    /// Whether grants allow requests (kms_grants.hpp). True with IAM; a
    /// deployment on static keys turns it off, because Requirement 7.7 has
    /// the static roles decide alone. Grants are still stored and listed.
    bool evaluate_grants = true;
    /// The principals (user or role ARNs) whose requests may carry the
    /// principal they serve (raft/kms_forwarding.hpp): consuming services
    /// on other clusters. Empty: no request may.
    std::set<std::string, std::less<>> trusted_services;
    /// On static keys (Requirement 7.7), whether a consumer's own call as
    /// an account's root is allowed on that account's keys: a call with no
    /// access key and kms:ViaService set, which only `kms.client` (or a
    /// trusted service's forwarding) makes, such as DynamoDB opening a
    /// table key on a replica or re-sealing after the request that chose
    /// the key has gone. No static key names the root, so the roles alone
    /// would refuse every such call, and an encrypted table could never be
    /// read off the node that created it. The request that chose the key
    /// was judged by the roles when it was made.
    bool admit_consumer_root = false;
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
    /// Whether the last refusal was an explicit deny, which a grant cannot
    /// override.
    bool last_denial_explicit = false;
    /// Whether grants may allow what the authorizer refused
    /// (front_end_config::evaluate_grants).
    bool grants_apply = true;
    /// The consuming service the call came through ("kinesis"), for
    /// kms:ViaService; empty for a caller's own request.
    std::string via_service;

    [[nodiscard]] auto authorize(aws_auth::authz_request r) -> std::optional<aws_json::error> {
        return authorize_fn(std::move(r));
    }

    /// The key the request acted on (its ARN), for the audit record: the
    /// last key-scoped authorization asked.
    std::string audited_key_arn;
    /// The grant that allowed the request, if one did.
    std::string audited_grant_id;

    /// Admits a shared cryptographic operation by its key's type
    /// (kms_quotas.hpp); unset when no quotas apply.
    std::function<bool(key_spec)> admit_key_fn;
    bool key_admitted = false;

    /// Counts the request against the quota of the first key it
    /// authorizes: ThrottlingException when that quota is spent.
    [[nodiscard]] auto admit_key(key_spec spec) -> std::optional<aws_json::error> {
        if (key_admitted || !admit_key_fn) {
            return std::nullopt;
        }
        key_admitted = true;
        if (admit_key_fn(spec)) {
            return std::nullopt;
        }
        return kms_error("ThrottlingException", "Rate exceeded");
    }

    /// A live grant allowed what IAM refused without an explicit deny
    /// (kms_grants.hpp): the request is authorized.
    auto allow_by_grant(std::string grant_id) -> void {
        authorized = true;
        audited_grant_id = std::move(grant_id);
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

/// The access key id an Authorization header claims, or nothing. Only
/// characters an access key id can hold are kept, so a forged header
/// cannot put arbitrary text in the audit trail.
[[nodiscard]] inline auto claimed_access_key(std::string_view authorization) -> std::string {
    constexpr std::string_view marker = "Credential=";
    const auto at = authorization.find(marker);
    if (at == std::string_view::npos) {
        return {};
    }
    auto rest = authorization.substr(at + marker.size());
    rest = rest.substr(0, std::min(rest.find('/'), std::size_t{128}));
    for (const char c : rest) {
        if (std::isalnum(static_cast<unsigned char>(c)) == 0) {
            return {};
        }
    }
    return std::string(rest);
}

}  // namespace front_end_detail

/// What the front end saw of one request, for the audit trail and the
/// metrics (Requirements 13.1 and 13.2). No key material and no
/// encryption context value: only the context's keys.
struct request_record {
    std::string operation;  ///< empty when the target named none
    std::string request_id;
    /// Who: the signer, or the caller a trusted service forwarded; empty
    /// when authentication failed.
    std::optional<aws_auth::principal_context> principal;
    std::string access_key_id;  ///< the signer's, when known
    std::string via_service;
    std::string source_ip;
    std::string user_agent;
    std::string key_arn;
    std::string grant_id;
    std::vector<std::string> context_keys;
    unsigned status = 0;
    std::string error_type;  ///< empty on success
    std::string error_message;
    bool read_only = false;
    std::chrono::system_clock::time_point time;
    std::chrono::microseconds duration{0};
};

using request_observer = std::function<void(const request_record&)>;

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

    /// Called once per request after its answer is made, on the
    /// request's thread. Set before serving.
    void set_observer(request_observer o) { _observer = std::move(o); }

    /// Applies AWS's request quotas (kms_quotas.hpp). Set before serving;
    /// none by default.
    void set_quotas(std::shared_ptr<request_quotas> q) { _quotas = std::move(q); }

    [[nodiscard]] auto handle(const front_end_request& req) -> aws_json::http_response {
        request_record rec;
        rec.time = std::chrono::system_clock::now();
        rec.source_ip = req.source_ip;
        rec.user_agent = std::string(front_end_detail::header_value(req, "user-agent"));
        const auto start = std::chrono::steady_clock::now();
        auto res = handle_impl(req, rec);
        observe(rec, res, start);
        return res;
    }

    /// A consuming service's call for its caller (`kms.client` in process,
    /// service-colocation Requirement 7.2): authorized as `principal`,
    /// with kms:ViaService set to `via_service`, exactly as the same call
    /// forwarded over HTTPS by a trusted service. No signature: the caller
    /// is a module of this process. Only the service operations are taken
    /// (kms_forwarding::service_operations).
    [[nodiscard]] auto handle_service_call(std::string_view operation, std::string body,
                                           aws_auth::principal_context principal,
                                           std::string via_service, std::string source_ip)
        -> aws_json::http_response {
        request_record rec;
        rec.time = std::chrono::system_clock::now();
        rec.operation = std::string(operation);
        rec.source_ip = source_ip;
        rec.via_service = via_service;
        rec.principal = principal;
        rec.access_key_id = principal.access_key_id;
        const auto start = std::chrono::steady_clock::now();
        auto res = service_call_impl(operation, std::move(body), std::move(principal),
                                     std::move(via_service), std::move(source_ip), rec);
        observe(rec, res, start);
        return res;
    }

private:
    [[nodiscard]] auto handle_impl(const front_end_request& req, request_record& rec)
        -> aws_json::http_response {
        const auto target = front_end_detail::header_value(req, "x-amz-target");
        const auto content_type = front_end_detail::header_value(req, "content-type");
        const aws_json::http_request_view view{req.method, req.path, content_type, target,
                                               req.body};
        constexpr auto json = aws_json::body_encoding::json;
        auto id = _codec.new_request_id();
        rec.request_id = id;

        const auto* op = _codec.resolve_target(view);
        if (op == nullptr) {
            auto parsed = _codec.parse(view);
            return _codec.respond(parsed ? unknown_operation() : parsed.error(), id, json);
        }
        rec.operation = std::string(op->name);

        sigv4::service_rules rules;
        rules.service = "kms";
        rules.protocol = sigv4::error_protocol::json;
        if (!_config.region.empty()) {
            rules.regions = {_config.region};
        }
        const sigv4::request sreq{req.method, req.path, req.query, req.headers, req.body};
        const auto who = _authorizer.authenticate(sreq, rules);
        if (!who) {
            // CloudTrail names the key a refused signature claimed.
            rec.access_key_id = front_end_detail::claimed_access_key(
                front_end_detail::header_value(req, "authorization"));
            aws_json::error e;
            e.status = static_cast<unsigned>(who.error().http_status);
            e.type = who.error().code;
            e.message = who.error().message;
            return _codec.respond(e, id, json);
        }
        auto principal = *who;
        rec.access_key_id = who->access_key_id;
        rec.principal = principal;
        std::string via;
        if (auto bad = forwarded(*who, req, principal, via)) {
            return _codec.respond(*bad, id, json);
        }
        rec.principal = principal;
        rec.via_service = via;
        return run(req, view, *op, std::move(principal), std::move(via), id, rec);
    }

    [[nodiscard]] auto service_call_impl(std::string_view operation, std::string body,
                                         aws_auth::principal_context principal,
                                         std::string via_service, std::string source_ip,
                                         request_record& rec) -> aws_json::http_response {
        constexpr auto json = aws_json::body_encoding::json;
        auto id = _codec.new_request_id();
        rec.request_id = id;
        if (!kms_forwarding::is_service_operation(operation)) {
            return _codec.respond(
                unsupported(std::string(operation) + " is not taken through a service"), id, json);
        }
        if (!kms_forwarding::valid_service_name(via_service) || principal.arn.empty() ||
            principal.account.empty()) {
            return _codec.respond(internal_error(), id, json);  // a consumer's bug
        }
        front_end_request req;
        req.method = "POST";
        req.path = "/";
        req.headers = {{"Content-Type", "application/x-amz-json-1.1"},
                       {"X-Amz-Target", "TrentService." + std::string(operation)}};
        req.body = std::move(body);
        req.source_ip = std::move(source_ip);
        req.secure = true;
        const aws_json::http_request_view view{req.method, req.path, req.headers[0].second,
                                               req.headers[1].second, req.body};
        const auto* op = _codec.resolve_target(view);
        if (op == nullptr) {
            return _codec.respond(unknown_operation(), id, json);
        }
        return run(req, view, *op, std::move(principal), std::move(via_service), id, rec);
    }

    /// Fills in the record from the answer and hands it to the observer.
    void observe(request_record& rec, const aws_json::http_response& res,
                 std::chrono::steady_clock::time_point start) const {
        if (!_observer) {
            return;
        }
        rec.status = res.status;
        rec.duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start);
        if (const auto* acts = find_operation_actions(rec.operation)) {
            rec.read_only = !acts->writes;
        }
        if (res.status != 200) {
            boost::system::error_code ec;
            const auto v = boost::json::parse(res.body, ec);
            if (!ec && v.is_object()) {
                if (const auto* t = v.as_object().if_contains("__type");
                    t != nullptr && t->is_string()) {
                    const std::string_view type(t->get_string());
                    rec.error_type = std::string(type.substr(type.find('#') + 1));
                }
                for (const char* k : {"message", "Message"}) {
                    if (const auto* m = v.as_object().if_contains(k);
                        m != nullptr && m->is_string()) {
                        rec.error_message = std::string(m->get_string());
                    }
                }
            }
        }
        try {
            _observer(rec);
        } catch (const std::exception&) {
            // An audit or metrics failure never changes the answer.
        }
    }

    /// The encryption context keys a request carries (never the values).
    static void collect_context_keys(const boost::json::object& in, request_record& rec) {
        for (const char* member :
             {"EncryptionContext", "SourceEncryptionContext", "DestinationEncryptionContext"}) {
            const auto* c = in.if_contains(member);
            if (c == nullptr || !c->is_object()) {
                continue;
            }
            for (const auto& kv : c->get_object()) {
                const std::string k(kv.key());
                if (std::find(rec.context_keys.begin(), rec.context_keys.end(), k) ==
                    rec.context_keys.end()) {
                    rec.context_keys.push_back(k);
                }
            }
        }
    }

    /// Dispatches an authenticated request to its handler as `principal`.
    template<typename Operation>
    [[nodiscard]] auto run(const front_end_request& req, const aws_json::http_request_view& view,
                           const Operation& op, aws_auth::principal_context principal,
                           std::string via, std::string& id, request_record& rec)
        -> aws_json::http_response {
        constexpr auto json = aws_json::body_encoding::json;
        const auto h = _handlers.find(op.name);
        if (h == _handlers.end()) {
            return _codec.respond(
                unsupported("Kythira's KMS does not implement " + std::string(op.name) +
                            "; see services/kms/doc/unsupported.md"),
                id, json);
        }
        if (!via.empty() && !kms_forwarding::is_service_operation(op.name)) {
            return _codec.respond(
                access_denied(std::string(op.name) + " is not taken through a service"), id, json);
        }
        auto parsed = _codec.parse(view);
        if (!parsed) {
            return _codec.respond(parsed.error(), id, json);
        }
        collect_context_keys(parsed->input, rec);
        if (auto bad = check_grant_tokens(parsed->input)) {
            return _codec.respond(*bad, id, json);
        }
        if (_quotas && !_quotas->admit_operation(principal.account, op.name, parsed->input)) {
            return _codec.respond(kms_error("ThrottlingException", "Rate exceeded"), id, json);
        }

        call_context ctx;
        ctx.operation = op.name;
        ctx.request_id = id;
        ctx.principal = std::move(principal);
        ctx.region = _config.region;
        ctx.partition = _config.partition;
        ctx.grants_apply = _config.evaluate_grants;
        ctx.via_service = std::move(via);
        const auto* acts = find_operation_actions(op.name);
        ctx.replica_read_ok = acts != nullptr && !acts->writes;
        if (_quotas) {
            ctx.admit_key_fn = [q = _quotas.get(), &ctx](key_spec spec) {
                return q->admit_key_use(ctx.principal.account, ctx.operation, spec);
            };
        }
        ctx.authorize_fn = [this, &ctx, &req](aws_auth::authz_request r) {
            auto denied = check(ctx, req, std::move(r));
            if (!denied) {
                ctx.authorized = true;
            }
            return denied;
        };

        // Whatever the handler answers, the record names the key and grant
        // it reached.
        struct record_keys {
            call_context& ctx;
            request_record& rec;
            record_keys(call_context& c, request_record& r) : ctx(c), rec(r) {}
            record_keys(const record_keys&) = delete;
            auto operator=(const record_keys&) -> record_keys& = delete;
            record_keys(record_keys&&) = delete;
            auto operator=(record_keys&&) -> record_keys& = delete;
            ~record_keys() {
                rec.key_arn = ctx.audited_key_arn;
                rec.grant_id = ctx.audited_grant_id;
            }
        } const keep(ctx, rec);
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
            return _codec.respond(*out, id, json, &op);
        } catch (const std::exception&) {
            return _codec.respond(internal_error(), id, json);
        }
    }

    /// A trusted service's forwarded principal (raft/kms_forwarding.hpp):
    /// on success `principal` and `via` are the end caller and the
    /// service. A request with neither header is the signer's own.
    [[nodiscard]] auto forwarded(const aws_auth::principal_context& signer,
                                 const front_end_request& req,
                                 aws_auth::principal_context& principal, std::string& via) const
        -> std::optional<aws_json::error> {
        const auto fwd = front_end_detail::header_value(req, kms_forwarding::principal_header);
        const auto service =
            front_end_detail::header_value(req, kms_forwarding::via_service_header);
        if (fwd.empty() && service.empty()) {
            return std::nullopt;
        }
        if (!kms_forwarding::header_is_signed(req.headers, kms_forwarding::principal_header) ||
            !kms_forwarding::header_is_signed(req.headers, kms_forwarding::via_service_header)) {
            return access_denied("A forwarded principal must be signed, with its service");
        }
        if (!_config.trusted_services.contains(signer.arn) &&
            (signer.role_arn.empty() || !_config.trusted_services.contains(signer.role_arn))) {
            return access_denied("User: " + signer.arn +
                                 " is not a service trusted to forward principals");
        }
        auto decoded = kms_forwarding::decode_principal(fwd);
        if (!decoded || !kms_forwarding::valid_service_name(service)) {
            return access_denied("The forwarded principal or service is malformed");
        }
        principal = std::move(*decoded);
        via = std::string(service);
        return std::nullopt;
    }

    [[nodiscard]] static auto access_denied(std::string message) -> aws_json::error {
        aws_json::error e;
        e.type = "AccessDeniedException";
        e.message = std::move(message);
        return e;
    }

    /// Grant tokens this KMS made; any other is InvalidGrantTokenException,
    /// as on AWS. A valid token adds no authority (kms_grants.hpp).
    [[nodiscard]] static auto check_grant_tokens(const boost::json::object& in)
        -> std::optional<aws_json::error> {
        const auto* t = in.if_contains("GrantTokens");
        if (t == nullptr || !t->is_array()) {
            return std::nullopt;
        }
        for (const auto& v : t->get_array()) {
            if (!v.is_string() || !parse_grant_token(v.get_string())) {
                return kms_error("InvalidGrantTokenException", "The grant token is not valid");
            }
        }
        return std::nullopt;
    }

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

    /// A consumer's own call as its account's root (front_end_config::
    /// admit_consumer_root).
    [[nodiscard]] auto consumer_root(const call_context& ctx) const -> bool {
        const auto& p = ctx.principal;
        return !ctx.via_service.empty() && p.access_key_id.empty() &&
               p.type == aws_auth::principal_type::root &&
               p.arn == "arn:" + _config.partition + ":iam::" + p.account + ":root";
    }

    [[nodiscard]] auto check(call_context& ctx, const front_end_request& req,
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
        if (r.resource.find(":key/") != std::string::npos) {
            ctx.audited_key_arn = r.resource;
            if (_config.admit_consumer_root &&
                (r.resource_account.empty() || r.resource_account == ctx.principal.account) &&
                consumer_root(ctx)) {
                ctx.last_denial_explicit = false;
                return std::nullopt;
            }
        }
        r.keys.emplace_back("kms:CallerAccount", std::vector<std::string>{ctx.principal.account});
        if (!ctx.via_service.empty()) {
            r.keys.emplace_back("kms:ViaService",
                                std::vector<std::string>{ctx.via_service + "." + _config.region +
                                                         ".amazonaws.com"});
        }
        const auto d = _authorizer.authorize(ctx.principal, r);
        ctx.last_denial_explicit = !d.allowed && d.explicit_deny;
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
    request_observer _observer;
    std::shared_ptr<request_quotas> _quotas;
};

}  // namespace kythira::kms
