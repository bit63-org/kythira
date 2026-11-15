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
// and, from task 7 (requirement 4):
//
//   POST   /v1/init    {"mode":"operator"|"node","k":K,"n":N}
//                      generate the master key, record its check value
//                      and hand out its n shares, once; no node is left
//                      unsealed, each is unsealed with k shares
//   POST   /v1/unseal  {"share":"khs1-..."}  one operator's share for this
//                      node; held in memory until k arrive or the timeout
//   DELETE /v1/unseal  discard the shares held on this node
//   POST   /v1/seal    every node discards its master key and token keys
//   POST   /v1/rekey   {"mode":M,"k":K,"n":N} (each optional) a new master
//                      key: every token key re-sealed in one entry, new
//                      shares handed out, the old ones stop working, and
//                      every other node is sealed until unsealed with them
//
// <identity> is percent-encoded (a SPIFFE URI has slashes). Only the
// operator identities in admin_policy may call any of it; the client
// certificate's URI or DNS SAN is the identity.
//
// Answers: 200/201 with JSON, 400 for a malformed request, 403 for a caller
// who is not an operator, 404 for an unknown route or token, 405 for a
// method a route does not take, 409 when the
// catalog refuses (not initialized, id taken or deleted), 503 while sealed
// or when the group could not commit (the change may still have taken
// effect; read the tokens before retrying).
//
// Init and rekey answer the shares even when the entry's commit is
// uncertain (503 with "shares"): if it did commit, those shares are the
// only way to the new master key, so dropping them would lose every key.
// The status's generation says which set is current.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/shamir.hpp>
#include <kythira/hsm/unseal.hpp>

#include <boost/json.hpp>

#include <cctype>
#include <charconv>
#include <chrono>
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
    /// Permit k = 1 at init and rekey (development only; requirement 4.1).
    bool allow_single_share = false;
    /// How long partial operator shares are held (requirement 4.3).
    std::chrono::seconds unseal_timeout{std::chrono::minutes{10}};
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
        : _host(&host),
          _vault(&vault),
          _policy(std::move(policy)),
          _unseal(vault, _policy.unseal_timeout) {}

    /// Run periodically: seals this node when the catalog was sealed or
    /// rekeyed since it unsealed, and drops expired partial shares. True
    /// when it sealed.
    auto maintain() -> bool {
        _unseal.expire();
        return _vault->enforce(_host->catalog());
    }

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
        if (req.path == "/v1/init") {
            return req.method == "POST" ? initialize(req.body) : not_allowed();
        }
        if (req.path == "/v1/unseal") {
            if (req.method == "DELETE") {
                _unseal.reset();
                return status();
            }
            return req.method == "POST" ? unseal(req.body) : not_allowed();
        }
        if (req.path == "/v1/seal") {
            return req.method == "POST" ? seal() : not_allowed();
        }
        if (req.path == "/v1/rekey") {
            return req.method == "POST" ? rekey(req.body) : not_allowed();
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
        const auto p = _unseal.progress(c);
        o["unseal_received"] = p.received;
        o["unseal_needed"] = p.needed;
        o["tokens"] = _host->tokens().size();
        o["catalog_leader"] = _host->leads(0);
        return ok(200, o);
    }

    /// The mode, k and n of an init or rekey body; absent fields take
    /// `fallback`'s. Nothing (with `why`) when a field is malformed.
    auto split_of(const boost::json::object& o, split_parameters fallback, std::string& why) const
        -> std::optional<split_parameters> {
        split_parameters out = fallback;
        if (const auto* m = o.if_contains("mode")) {
            if (m->is_string() && m->as_string() == "operator") {
                out.mode = unseal_mode::operator_shares;
            } else if (m->is_string() && m->as_string() == "node") {
                out.mode = unseal_mode::node_shares;
            } else {
                why = R"(mode is "operator" or "node")";
                return std::nullopt;
            }
        }
        for (const auto& [name, field] : {std::pair{"k", &out.k}, std::pair{"n", &out.n}}) {
            if (const auto* v = o.if_contains(name)) {
                if (!v->is_int64() || v->as_int64() < 1 || v->as_int64() > shamir_max_shares) {
                    why = std::string(name) + " is an integer from 1 to 16";
                    return std::nullopt;
                }
                *field = static_cast<std::uint8_t>(v->as_int64());
            }
        }
        if (out.k == 0 || out.n == 0 || out.k > out.n) {
            why = "k and n are required, with 1 <= k <= n <= 16";
            return std::nullopt;
        }
        if (out.k == 1 && !_policy.allow_single_share) {
            why = "k = 1 needs KYTHIRA_HSM_ALLOW_SINGLE_SHARE (development only)";
            return std::nullopt;
        }
        return out;
    }

    /// A fresh master key, its shares and its check value.
    struct fresh_key {
        secret_bytes mk;
        std::vector<std::string> shares;
        std::array<std::uint8_t, 8> check{};
    };

    [[nodiscard]] auto fresh(split_parameters split) const -> fresh_key {
        fresh_key out;
        out.mk = secret_bytes(sealing_key_size);
        if (!generate_random(out.mk.span())) {
            throw std::runtime_error("no randomness for the master key");
        }
        auto shares = shamir_split(out.mk.view(), split.k, split.n, _policy.allow_single_share);
        if (!shares) {
            throw std::runtime_error(std::string(shamir_error_message(shares.error())));
        }
        for (const auto& share : *shares) {
            out.shares.push_back(shamir_encode_text(share));
        }
        out.check = key_check_value(out.mk.view());
        return out;
    }

    /// The answer carrying new shares: `status` 200 when the entry
    /// committed, 503 when that is uncertain (see the header comment).
    static auto with_shares(unsigned status, const split_parameters& split,
                            std::uint32_t generation, const std::vector<std::string>& shares)
        -> admin_response {
        boost::json::object o;
        boost::json::array list;
        for (const auto& s : shares) {
            list.emplace_back(s);
        }
        o["shares"] = std::move(list);
        o["mode"] = split.mode == unseal_mode::operator_shares ? "operator" : "node";
        o["k"] = split.k;
        o["n"] = split.n;
        o["generation"] = generation;
        if (status != 200) {
            o["error"] = "unavailable";
            o["message"] =
                "the entry's commit is uncertain: keep these shares, and use them if the "
                "status shows generation " +
                std::to_string(generation);
        }
        return ok(status, o);
    }

    auto initialize(const std::string& text) -> admin_response {
        const auto v = boost::json::parse(text);
        if (!v.is_object()) {
            return error(400, "bad_request", R"(expected {"mode": M, "k": K, "n": N})");
        }
        std::string why;
        const auto split = split_of(v.as_object(), {}, why);
        if (!split) {
            return error(400, "bad_request", why);
        }
        if (_host->catalog()) {
            return error(409, "already_initialized", "the HSM is already initialized");
        }
        auto key = fresh(*split);
        const auto rv =
            propose(make_initialize_command(split->mode, split->k, split->n, key.check));
        if (rv == CKR_FUNCTION_REJECTED) {
            return error(409, "already_initialized", "the HSM is already initialized");
        }
        if (rv == CKR_DEVICE_ERROR) {
            return with_shares(503, *split, 1, key.shares);
        }
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        return with_shares(200, *split, 1, key.shares);
    }

    auto unseal(const std::string& text) -> admin_response {
        const auto v = boost::json::parse(text);
        const auto* share = v.is_object() ? v.as_object().if_contains("share") : nullptr;
        if (share == nullptr || !share->is_string()) {
            return error(400, "bad_request", R"(expected {"share": "khs1-..."})");
        }
        // The catalog this node checks shares against must be current: a
        // lagging replica would refuse new shares after a rekey, or accept
        // a seal it has not applied yet.
        if (!_host->catalog_barrier()) {
            return error(503, "unavailable", "the catalog group has no quorum");
        }
        const auto c = _host->catalog();
        const auto outcome = _unseal.submit(std::string_view(share->as_string()), c);
        switch (outcome) {
            case share_outcome::accepted:
            case share_outcome::unsealed:
            case share_outcome::already_unsealed:
                break;
            case share_outcome::not_initialized:
                return error(409, "not_initialized", share_outcome_message(outcome));
            case share_outcome::duplicate:
                return error(409, "duplicate", share_outcome_message(outcome));
            case share_outcome::malformed:
                return error(400, "malformed_share", share_outcome_message(outcome));
            case share_outcome::wrong_split:
                return error(400, "wrong_split", share_outcome_message(outcome));
            case share_outcome::wrong_key:
                return error(400, "wrong_key", share_outcome_message(outcome));
        }
        const auto p = _unseal.progress(c);
        boost::json::object o;
        o["outcome"] = share_outcome_message(outcome);
        o["sealed"] = p.sealed;
        o["unseal_received"] = p.received;
        o["unseal_needed"] = p.needed;
        return ok(200, o);
    }

    auto seal() -> admin_response {
        const auto rv = propose(make_seal_command());
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        // This node at once; the others when they apply the entry.
        _unseal.reset();
        _vault->seal();
        return ok(200, boost::json::object{{"sealed", true}});
    }

    auto rekey(const std::string& text) -> admin_response {
        const auto v = boost::json::parse(text.empty() ? std::string("{}") : text);
        if (!v.is_object()) {
            return error(400, "bad_request", R"(expected {"mode": M, "k": K, "n": N})");
        }
        const auto c = _host->catalog();
        if (!c) {
            return error(409, "not_initialized", "the HSM is not initialized");
        }
        std::string why;
        const auto split = split_of(v.as_object(), {c->mode, c->k, c->n}, why);
        if (!split) {
            return error(400, "bad_request", why);
        }
        auto key = fresh(*split);
        const auto tokens = _host->tokens();
        auto entry = _vault->with_master_key([&](std::span<const std::uint8_t> old_mk) {
            return prepare_rekey(old_mk, key.mk.view(), key.check, *split, *c, tokens);
        });
        if (!entry) {
            return error(503, "sealed", "this node is sealed");
        }
        if (!*entry) {
            // The vault's MK opens no token key: this replica lagged a rekey.
            return error(409, "conflict", "this node's master key is stale; retry");
        }
        const auto generation = c->generation + 1;
        const auto rv = propose(std::move(**entry));
        if (rv == CKR_DEVICE_ERROR) {
            return with_shares(503, *split, generation, key.shares);
        }
        if (rv != CKR_OK) {
            return refusal(rv);  // a token created meanwhile, or a concurrent rekey
        }
        // The entry has applied here, so the vault takes the new MK; every
        // other node seals itself when it applies the entry.
        (void)_vault->unseal(std::move(key.mk), _host->catalog());
        return with_shares(200, *split, generation, key.shares);
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
    operator_unseal _unseal;
};

}  // namespace kythira::hsm
