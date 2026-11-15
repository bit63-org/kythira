// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM's operator API (.kiro/specs/virtual-hsm/ task 6d), JSON over the
// module's HTTPS listener, transport-free so the tests call it directly:
//
//   GET    /v1/status                          this node: initialized,
//                                              sealed, mode, k, n,
//                                              generation, token count,
//                                              whether it leads the catalog
//   GET    /v1/tokens                          every token: id, label,
//                                              generation, whether this
//                                              node hosts its group
//   POST   /v1/tokens       {"id":N,"label":L} create a token (unsealed
//                                              node: its key is sealed
//                                              under the master key)
//   DELETE /v1/tokens/N                        delete it; the id is never
//                                              reused
//   PUT    /v1/tokens/N/bindings/<identity>    let a client identity open it
//   DELETE /v1/tokens/N/bindings/<identity>    and no longer
//
// <identity> is percent-encoded (a SPIFFE URI has slashes). Only the
// operator identities in admin_policy may call any of it; the client
// certificate's URI or DNS SAN is the identity. Init, unseal, seal and
// rekey come with task 7 (hsm_ctl).
//
// Answers: 200/201 with JSON, 400 for a malformed request, 403 for a caller
// who is not an operator, 404 for an unknown route or token, 405 for a
// method a route does not take, 409 when the
// catalog refuses (not initialized, id taken or deleted), 503 while sealed
// or when the group could not commit (the change may still have taken
// effect; read the tokens before retrying).

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>

#include <boost/json.hpp>

#include <cctype>
#include <charconv>
#include <cstdint>
#include <exception>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kythira::hsm {

struct admin_policy {
    /// The operators' certificate identities.
    std::set<std::string> operators;
};

struct admin_request {
    std::string method;
    /// The path, without a query string.
    std::string path;
    std::string body;
    /// Every identity the caller's verified certificate carries (URI and
    /// DNS SANs); empty when it presented none.
    std::vector<std::string> identities;
};

struct admin_response {
    unsigned status = 200;
    std::string body;
};

/// `%XX` decoded; nothing when an escape is malformed.
[[nodiscard]] inline auto percent_decode(std::string_view in) -> std::optional<std::string> {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '%') {
            out.push_back(in[i]);
            continue;
        }
        if (i + 2 >= in.size() || std::isxdigit(static_cast<unsigned char>(in[i + 1])) == 0 ||
            std::isxdigit(static_cast<unsigned char>(in[i + 2])) == 0) {
            return std::nullopt;
        }
        unsigned v = 0;
        std::from_chars(in.data() + i + 1, in.data() + i + 3, v, 16);
        out.push_back(static_cast<char>(v));
        i += 2;
    }
    return out;
}

template<typename HsmHost> class admin_api {
public:
    admin_api(HsmHost& host, key_vault& vault, admin_policy policy)
        : _host(&host), _vault(&vault), _policy(std::move(policy)) {}

    [[nodiscard]] auto handle(const admin_request& req) -> admin_response {
        if (!is_operator(req)) {
            return error(403, "forbidden", "the caller is not an HSM operator");
        }
        try {
            return route(req);
        } catch (const std::exception& e) {
            return error(400, "bad_request", e.what());
        }
    }

private:
    [[nodiscard]] auto is_operator(const admin_request& req) const -> bool {
        for (const auto& id : req.identities) {
            if (_policy.operators.contains(id)) {
                return true;
            }
        }
        return false;
    }

    auto route(const admin_request& req) -> admin_response {
        constexpr std::string_view tokens = "/v1/tokens";
        if (req.path == "/v1/status") {
            return req.method == "GET" ? status() : not_allowed();
        }
        if (req.path == tokens) {
            if (req.method == "GET") {
                return list_tokens();
            }
            return req.method == "POST" ? create_token(req.body) : not_allowed();
        }
        if (!req.path.starts_with(std::string(tokens) + "/")) {
            return error(404, "not_found", "no such route");
        }
        // /v1/tokens/N[/bindings/<identity>]
        std::string_view rest = std::string_view(req.path).substr(tokens.size() + 1);
        const auto slash = rest.find('/');
        const auto id = parse_id(rest.substr(0, slash));
        if (!id) {
            return error(400, "bad_request", "a token id is a positive integer");
        }
        if (slash == std::string_view::npos) {
            return req.method == "DELETE" ? delete_token(*id) : not_allowed();
        }
        constexpr std::string_view bindings = "/bindings/";
        const auto tail = rest.substr(slash);
        if (!tail.starts_with(bindings) || tail.size() == bindings.size()) {
            return error(404, "not_found", "no such route");
        }
        const auto identity = percent_decode(tail.substr(bindings.size()));
        if (!identity || identity->empty()) {
            return error(400, "bad_request", "malformed identity");
        }
        if (req.method == "PUT") {
            return bind(*id, *identity, true);
        }
        return req.method == "DELETE" ? bind(*id, *identity, false) : not_allowed();
    }

    auto status() -> admin_response {
        boost::json::object o;
        const auto c = _host->catalog();
        o["initialized"] = c.has_value();
        o["sealed"] = _vault->sealed();
        if (c) {
            o["mode"] = c->mode == unseal_mode::operator_shares ? "operator" : "node";
            o["k"] = c->k;
            o["n"] = c->n;
            o["generation"] = c->generation;
        }
        o["tokens"] = _host->tokens().size();
        o["catalog_leader"] = _host->leads(0);
        return ok(200, o);
    }

    auto list_tokens() -> admin_response {
        boost::json::array out;
        for (const auto& t : _host->tokens()) {
            boost::json::object o;
            o["id"] = t.token_id;
            o["label"] = t.label;
            o["generation"] = t.generation;
            o["hosted"] = _host->hosts(t.token_id);
            out.push_back(std::move(o));
        }
        boost::json::object body;
        body["tokens"] = std::move(out);
        return ok(200, body);
    }

    auto create_token(const std::string& text) -> admin_response {
        const auto v = boost::json::parse(text);
        const auto& o = v.as_object();
        const auto* id_v = o.if_contains("id");
        const auto* label_v = o.if_contains("label");
        if (id_v == nullptr || !id_v->is_int64() || id_v->as_int64() <= 0 || label_v == nullptr ||
            !label_v->is_string()) {
            return error(400, "bad_request", R"(expected {"id": positive integer, "label": text})");
        }
        const auto id = static_cast<std::uint64_t>(id_v->as_int64());
        const std::string label(label_v->as_string());
        if (!_host->fits(id)) {
            return error(400, "bad_request", "the token id is outside the module's group space");
        }
        if (label.size() > 32) {
            return error(400, "bad_request", "a token label is at most 32 bytes");
        }
        const auto c = _host->catalog();
        if (!c) {
            return error(409, "not_initialized", "the HSM is not initialized");
        }
        auto entry = _vault->with_master_key([&](std::span<const std::uint8_t> mk) {
            return prepare_token(mk, c->generation, id, label).entry;
        });
        if (!entry) {
            return error(503, "sealed", "this node is sealed");
        }
        auto rv = propose(make_create_token_command(*entry));
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        boost::json::object body;
        body["id"] = id;
        body["label"] = label;
        return ok(201, body);
    }

    auto delete_token(std::uint64_t id) -> admin_response {
        const auto rv = propose(make_delete_token_command(id));
        if (rv == CKR_TOKEN_NOT_PRESENT) {
            return error(404, "not_found", "no such token");
        }
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        _vault->forget(id);
        return ok(200, boost::json::object{{"deleted", id}});
    }

    auto bind(std::uint64_t id, const std::string& identity, bool add) -> admin_response {
        const auto rv =
            propose(add ? make_bind_command(identity, id) : make_unbind_command(identity, id));
        if (rv == CKR_TOKEN_NOT_PRESENT) {
            return error(404, "not_found", "no such token");
        }
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        boost::json::object body;
        body["token"] = id;
        body["identity"] = identity;
        body["bound"] = add;
        return ok(200, body);
    }

    /// The catalog's answer to `cmd`, or CKR_DEVICE_ERROR when it did not
    /// commit.
    auto propose(std::vector<std::byte> cmd) -> CK_RV {
        auto r = _host->propose_catalog(std::move(cmd));
        return r ? catalog_reply_rv(*r) : r.error();
    }

    static auto refusal(CK_RV rv) -> admin_response {
        switch (rv) {
            case CKR_CRYPTOKI_NOT_INITIALIZED:
                return error(409, "not_initialized", "the HSM is not initialized");
            case CKR_FUNCTION_REJECTED:
                return error(409, "conflict",
                             "the catalog refused it (an id in use or deleted, or a stale "
                             "master key generation)");
            case CKR_DEVICE_ERROR:
                return error(503, "unavailable",
                             "the catalog could not commit; the change may still take effect");
            default:
                return error(409, "refused", "the catalog answered CK_RV " + std::to_string(rv));
        }
    }

    [[nodiscard]] static auto parse_id(std::string_view s) -> std::optional<std::uint64_t> {
        std::uint64_t v = 0;
        const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (s.empty() || ec != std::errc{} || end != s.data() + s.size() || v == 0) {
            return std::nullopt;
        }
        return v;
    }

    static auto ok(unsigned status, const boost::json::object& o) -> admin_response {
        return {status, boost::json::serialize(o)};
    }

    static auto error(unsigned status, std::string_view code, std::string_view message)
        -> admin_response {
        boost::json::object o;
        o["error"] = code;
        o["message"] = message;
        return {status, boost::json::serialize(o)};
    }

    static auto not_allowed() -> admin_response {
        return error(405, "method_not_allowed", "method not allowed on this route");
    }

    HsmHost* _host;
    key_vault* _vault;
    admin_policy _policy;
};

}  // namespace kythira::hsm
