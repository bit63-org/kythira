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
//                                              node hosts its group and
//                                              whether it leads it
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
//                      and hand out its n shares, once: to the operator,
//                      or in node mode one to each member (n must be the
//                      member count; task 8); no node is left unsealed
//   POST   /v1/unseal  {"share":"khs1-..."}  one operator's share for this
//                      node; held in memory until k arrive or the timeout
//   DELETE /v1/unseal  discard the shares held on this node
//   POST   /v1/seal    every node discards its master key and token keys
//   POST   /v1/rekey   {"mode":M,"k":K,"n":N} (each optional) a new master
//                      key: every token key re-sealed in one entry, new
//                      shares handed out, the old ones stop working, and
//                      every other node is sealed until unsealed with them
//
// and, for independent layers (.kiro/specs/hsm-independent-layers/ task 2,
// Requirement 5):
//
//   GET    /v1/crypto-members                the crypto member list in
//                                            effect and whether it is
//                                            seeded (else the store
//                                            members are the crypto
//                                            members)
//   POST   /v1/crypto-members/seed           write the store members
//                                            (admin_policy::store_members)
//                                            in as the list, once, before
//                                            the first split
//   PUT    /v1/crypto-members/<identity>     admit one; in node mode it
//                                            gets a share only from the
//                                            next rekey (Requirement 5.5)
//   DELETE /v1/crypto-members/<identity>     remove one. The removed node
//                      [{"rekey":true,       keeps its old share, so the
//                        "k":K,"n":N}]       removal is complete only after
//                                            a rekey: without "rekey" the
//                                            answer is 202 with "complete":
//                                            false; with it, the rekey runs
//                                            in the same request and the
//                                            answer is the rekey's
//                                            (Requirement 5.4)
//
// With the list seeded, node-mode init and rekey hand share i to the i-th
// listed member through node_share_delivery::deliver_to, and n must be the
// list's size; store-only nodes get none and count toward neither k nor n
// (Requirement 5.3).
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

#include <kythira/hsm/audit.hpp>
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
#include <functional>
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
    /// The store members' identities, which the crypto member list is
    /// seeded from.
    std::vector<std::string> store_members;
};

/// How init and rekey hand node-mode shares to the members (task 8).
struct node_share_delivery {
    /// The members, in the order shares are handed out (share i + 1 to
    /// member i); n must equal this.
    std::size_t members = 0;
    /// Stores `share` on member `index` (this node included); false when
    /// it could not.
    std::function<bool(std::size_t index, const shamir_share& share)> deliver;
    /// Stores `share` on the crypto member `identity`, once the catalog's
    /// crypto member list is seeded; false when it could not.
    std::function<bool(const std::string& identity, const shamir_share& share)> deliver_to;
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

    /// Enables node mode at init and rekey: how share i reaches member i.
    void set_node_share_delivery(node_share_delivery delivery) { _delivery = std::move(delivery); }

    /// Run periodically: seals this node when the catalog was sealed or
    /// rekeyed since it unsealed, and drops expired partial shares. True
    /// when it sealed.
    auto maintain() -> bool {
        _unseal.expire();
        if (!_vault->enforce(_host->catalog())) {
            return false;
        }
        if (_on_seal) {
            _on_seal();  // the vault is sealed; drop what was opened with it
        }
        return true;
    }

    /// Called whenever this node seals (the seal route, or maintain()
    /// finding the catalog sealed or rekeyed), in place of sealing the
    /// vault alone: the module passes session_layer::seal, which also
    /// wipes the key cache and session objects (requirement 4.7).
    void set_seal_hook(std::function<void()> hook) { _on_seal = std::move(hook); }

    /// Receives an event for every request that changes something (init,
    /// unseal, seal, rekey, tokens and bindings) and every refused caller
    /// (task 14); never a share or a request body.
    void set_audit_hook(audit_hook hook) { _audit = std::move(hook); }

    [[nodiscard]] auto handle(const admin_request& req) -> admin_response {
        const auto started = std::chrono::steady_clock::now();
        auto res = handle_unaudited(req);
        if (_audit && (req.method != "GET" || res.status == 403)) {
            audit_event e;
            e.action = admin_action(req);
            e.identity = req.identities.empty() ? std::string() : req.identities.front();
            for (const auto& id : req.identities) {
                if (_policy.operators.contains(id)) {
                    e.identity = id;
                    break;
                }
            }
            e.token = token_of(req.path);
            e.rv = res.status >= 200 && res.status < 300 ? CKR_OK
                   : res.status == 403                   ? CKR_USER_NOT_LOGGED_IN
                                                         : CKR_FUNCTION_FAILED;
            e.http_status = res.status;
            e.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started);
            _audit(e);
        }
        return res;
    }

private:
    [[nodiscard]] auto handle_unaudited(const admin_request& req) -> admin_response {
        if (!is_operator(req)) {
            return error(403, "forbidden", "the caller is not an HSM operator");
        }
        try {
            // The seal state every route answers from is the catalog's as
            // this node has applied it: a seal or rekey it applied since the
            // last maintain() seals it now, so the status never reports a
            // vault unsealed under a master key the catalog has replaced.
            (void)maintain();
            return route(req);
        } catch (const std::exception& e) {
            return error(400, "bad_request", e.what());
        }
    }

    /// The audit action a request names.
    [[nodiscard]] static auto admin_action(const admin_request& req) -> std::string_view {
        const auto& p = req.path;
        const bool del = req.method == "DELETE";
        if (p == "/v1/init") {
            return "init";
        }
        if (p == "/v1/unseal") {
            return del ? "unseal_reset" : "unseal";
        }
        if (p == "/v1/seal") {
            return "seal";
        }
        if (p == "/v1/rekey") {
            return "rekey";
        }
        if (p.starts_with("/v1/crypto-members")) {
            if (req.method == "GET") {
                return "list_crypto_members";
            }
            if (p == "/v1/crypto-members/seed") {
                return "seed_crypto_members";
            }
            return del ? "remove_crypto_member" : "admit_crypto_member";
        }
        if (p == "/v1/tokens") {
            return req.method == "GET" ? "list_tokens" : "create_token";
        }
        if (p.find("/bindings/") != std::string::npos) {
            return del ? "unbind" : "bind";
        }
        if (p.starts_with("/v1/tokens/")) {
            return "delete_token";
        }
        return p == "/v1/status" ? "status" : "admin";
    }

    /// The token a /v1/tokens/N... path names.
    [[nodiscard]] static auto token_of(std::string_view path) -> std::optional<std::uint64_t> {
        constexpr std::string_view prefix = "/v1/tokens/";
        if (!path.starts_with(prefix)) {
            return std::nullopt;
        }
        path.remove_prefix(prefix.size());
        std::uint64_t id = 0;
        const auto [end, ec] = std::from_chars(path.data(), path.data() + path.size(), id);
        if (ec != std::errc{} || (end != path.data() + path.size() && *end != '/')) {
            return std::nullopt;
        }
        return id;
    }

public:
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
        if (req.path == "/v1/crypto-members" || req.path.starts_with("/v1/crypto-members/")) {
            return crypto_members_route(req);
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
        std::vector<shamir_share> raw;
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
        out.raw = std::move(*shares);
        out.check = key_check_value(out.mk.view());
        return out;
    }

    /// In node mode, share i to the i-th member, every one before the
    /// catalog entry is proposed (task 8): an error answer when that
    /// cannot be done, so nothing is committed. With the crypto member
    /// list seeded, the members are the listed crypto members.
    auto deliver(const fresh_key& key, const split_parameters& split)
        -> std::optional<admin_response> {
        if (split.mode != unseal_mode::node_shares) {
            return std::nullopt;
        }
        if (const auto crypto = _host->crypto_members(); !crypto.empty()) {
            if (!_delivery.deliver_to) {
                return error(400, "bad_request",
                             "node unseal to listed crypto members is not available on this node");
            }
            if (split.n != crypto.size()) {
                return error(400, "bad_request",
                             "node unseal gives each crypto member one share: n must be " +
                                 std::to_string(crypto.size()));
            }
            for (std::size_t i = 0; i < key.raw.size(); ++i) {
                if (!_delivery.deliver_to(crypto[i], key.raw[i])) {
                    return error(503, "unavailable",
                                 "crypto member " + crypto[i] +
                                     " could not take its share; nothing was committed");
                }
            }
            return std::nullopt;
        }
        if (!_delivery.deliver) {
            return error(400, "bad_request", "node unseal is not available on this node");
        }
        if (split.n != _delivery.members) {
            return error(400, "bad_request",
                         "node unseal gives each member one share: n must be " +
                             std::to_string(_delivery.members));
        }
        for (std::size_t i = 0; i < key.raw.size(); ++i) {
            if (!_delivery.deliver(i, key.raw[i])) {
                return error(503, "unavailable",
                             "member " + std::to_string(i + 1) +
                                 " could not take its share; nothing was committed");
            }
        }
        return std::nullopt;
    }

    /// The answer carrying new shares: `status` 200 when the entry
    /// committed, 503 when that is uncertain (see the header comment).
    static auto with_shares(unsigned status, const split_parameters& split,
                            std::uint32_t generation, const std::vector<std::string>& shares)
        -> admin_response {
        boost::json::object o;
        if (split.mode == unseal_mode::operator_shares) {
            boost::json::array list;
            for (const auto& s : shares) {
                list.emplace_back(s);
            }
            o["shares"] = std::move(list);
        } else {
            o["delivered"] = shares.size();  // one to each member, kept by none here
        }
        o["mode"] = split.mode == unseal_mode::operator_shares ? "operator" : "node";
        o["k"] = split.k;
        o["n"] = split.n;
        o["generation"] = generation;
        if (status != 200) {
            o["error"] = "unavailable";
            o["message"] =
                "the entry's commit is uncertain: the shares are current if the "
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
        if (auto refused = deliver(key, *split)) {
            return std::move(*refused);
        }
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
        if (_on_seal) {
            _on_seal();
        } else {
            _vault->seal();
        }
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
        if (_vault->sealed()) {
            return error(503, "sealed", "this node is sealed");
        }
        if (auto refused = deliver(key, *split)) {
            return std::move(*refused);
        }
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

    auto crypto_members_route(const admin_request& req) -> admin_response {
        constexpr std::string_view base = "/v1/crypto-members";
        if (req.path == base) {
            return req.method == "GET" ? list_crypto_members() : not_allowed();
        }
        const auto rest = std::string_view(req.path).substr(base.size() + 1);
        if (rest == "seed") {
            return req.method == "POST" ? seed_crypto_members() : not_allowed();
        }
        const auto identity = percent_decode(rest);
        if (!identity || identity->empty() || identity->find('\0') != std::string::npos) {
            return error(400, "bad_request", "malformed identity");
        }
        if (req.method == "PUT") {
            return admit_crypto_member(*identity);
        }
        return req.method == "DELETE" ? remove_crypto_member(*identity, req.body) : not_allowed();
    }

    auto list_crypto_members() -> admin_response {
        const auto listed = _host->crypto_members();
        boost::json::array members;
        for (const auto& id : effective_crypto_members(listed, _policy.store_members)) {
            members.emplace_back(id);
        }
        boost::json::object o;
        o["members"] = std::move(members);
        o["seeded"] = !listed.empty();
        return ok(200, o);
    }

    auto seed_crypto_members() -> admin_response {
        if (_policy.store_members.empty()) {
            return error(400, "bad_request", "this node does not know the store members");
        }
        const auto rv = propose(make_seed_crypto_members_command(_policy.store_members));
        if (rv == CKR_FUNCTION_REJECTED) {
            return error(409, "already_seeded", "the crypto member list is already seeded");
        }
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        return list_crypto_members();
    }

    auto admit_crypto_member(const std::string& identity) -> admin_response {
        if (_host->crypto_members().empty()) {
            // Admitting into an empty list would drop the store members
            // from it: seed first, so the list and the unsealed set agree
            // (Requirement 9.1).
            return error(409, "not_seeded",
                         "seed the crypto member list (POST /v1/crypto-members/seed) first");
        }
        const auto rv = propose(make_admit_crypto_member_command(identity));
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        const auto c = _host->catalog();
        boost::json::object o;
        o["admitted"] = identity;
        o["share"] = c && c->mode == unseal_mode::node_shares
                         ? "from the next rekey (POST /v1/rekey)"
                         : "unsealed by operators with their shares";
        return ok(200, o);
    }

    auto remove_crypto_member(const std::string& identity, const std::string& text)
        -> admin_response {
        const auto v = boost::json::parse(text.empty() ? std::string("{}") : text);
        if (!v.is_object()) {
            return error(400, "bad_request", R"(expected {"rekey": true, "k": K, "n": N})");
        }
        auto opts = v.as_object();
        const auto* rk = opts.if_contains("rekey");
        const bool with_rekey = rk != nullptr && rk->is_bool() && rk->as_bool();
        if (rk != nullptr && !rk->is_bool()) {
            return error(400, "bad_request", "rekey is true or false");
        }
        if (_host->crypto_members().empty()) {
            return error(409, "not_seeded", "the crypto member list is not seeded");
        }
        const auto rv = propose(make_remove_crypto_member_command(identity));
        if (rv == CKR_FUNCTION_REJECTED) {
            return error(409, "last_member", "the last crypto member cannot be removed");
        }
        if (rv != CKR_OK) {
            return refusal(rv);
        }
        if (!with_rekey) {
            boost::json::object o;
            o["removed"] = identity;
            o["complete"] = false;
            o["message"] =
                "the removed node still holds its share of the current master key; the "
                "removal is complete after a rekey (POST /v1/rekey)";
            return ok(202, o);
        }
        opts.erase("rekey");
        // In node mode every listed member gets one share, so n follows
        // the list unless the operator gave it; k stays the operator's.
        if (const auto c = _host->catalog();
            c && !opts.contains("n") &&
            (c->mode == unseal_mode::node_shares ||
             (opts.contains("mode") && opts.at("mode").is_string() &&
              opts.at("mode").as_string() == "node"))) {
            opts["n"] = _host->crypto_members().size();
        }
        auto res = rekey(boost::json::serialize(opts));
        if (res.status == 200 || res.status == 503) {
            auto body = boost::json::parse(res.body).as_object();
            body["removed"] = identity;
            body["complete"] = res.status == 200;
            res.body = boost::json::serialize(body);
            return res;
        }
        // The removal committed but the rekey did not run: say so, with
        // the rekey's reason.
        auto body = boost::json::parse(res.body).as_object();
        body["removed"] = identity;
        body["complete"] = false;
        res.body = boost::json::serialize(body);
        return res;
    }

    auto list_tokens() -> admin_response {
        boost::json::array out;
        for (const auto& t : _host->tokens()) {
            boost::json::object o;
            o["id"] = t.token_id;
            o["label"] = t.label;
            o["generation"] = t.generation;
            o["hosted"] = _host->hosts(t.token_id);
            o["leader"] = _host->leads(t.token_id);
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
    audit_hook _audit;
    std::function<void()> _on_seal;
    node_share_delivery _delivery;
};

}  // namespace kythira::hsm
