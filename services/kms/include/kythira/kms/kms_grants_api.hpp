// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The grant operations (.kiro/specs/kms-compatible-api/ task 10,
// Requirements 8.1-8.4): CreateGrant, ListGrants, ListRetirableGrants,
// RetireGrant and RevokeGrant. How a grant allows a request is in
// kms_grants.hpp; every key-authorized handler consults it through
// api_common::authorize_with_grants.
//
// Grants are catalog records, so a grant is in force for every request on
// any replica once it commits: reads pass a read barrier first. That is
// tighter than AWS's eventual consistency, and is why a grant token needs
// to carry nothing but the grant's name.

#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_grants.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// A fresh grant id: 64 hex digits, as AWS's are.
[[nodiscard]] inline auto random_grant_id() -> std::string {
    std::array<unsigned char, 32> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("kms: no randomness for a grant id");
    }
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (const auto c : b) {
        out.push_back(hex[c >> 4U]);
        out.push_back(hex[c & 0x0FU]);
    }
    return out;
}

template<typename Catalog> class grants_api : protected api_common {
public:
    using result = aws_json::result<boost::json::object>;

    explicit grants_api(api_deps<Catalog> deps) : _d(std::move(deps)) {}

    static constexpr std::array<std::string_view, 5> k_operations{
        "CreateGrant", "ListGrants", "ListRetirableGrants", "RetireGrant", "RevokeGrant"};

    template<typename FrontEnd> void register_on(FrontEnd& fe) {
        const auto bind = [this](auto method) {
            return [this, method](call_context& ctx, boost::json::object& in) -> result {
                return (this->*method)(ctx, in);
            };
        };
        fe.on("CreateGrant", bind(&grants_api::create_grant));
        fe.on("ListGrants", bind(&grants_api::list_grants));
        fe.on("ListRetirableGrants", bind(&grants_api::list_retirable_grants));
        fe.on("RetireGrant", bind(&grants_api::retire_grant));
        fe.on("RevokeGrant", bind(&grants_api::revoke_grant));
    }

    auto create_grant(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        auto g = read_grant(in, k->record);
        if (!g) {
            return g.error();
        }
        g->key_id = k->record.key_id;
        g->issuing_account = ctx.principal.account;
        g->for_aws_resource = k->record.manager == key_manager::aws;

        auto r = key_request(ctx, **c, *k, "CreateGrant");
        r.keys.emplace_back("kms:GrantOperations", g->operations);
        r.keys.emplace_back("kms:GranteePrincipal", std::vector<std::string>{g->grantee_principal});
        if (!g->retiring_principal.empty()) {
            r.keys.emplace_back("kms:RetiringPrincipal",
                                std::vector<std::string>{g->retiring_principal});
        }
        r.keys.emplace_back("kms:GrantIsForAWSResource",
                            std::vector<std::string>{g->for_aws_resource ? "true" : "false"});
        // A constraint's pairs are the encryption context condition keys,
        // as on AWS, so a policy can require grants to carry one.
        std::vector<std::string> context_keys;
        for (const auto& [ck, cv] : g->constraint_context) {
            r.keys.emplace_back("kms:EncryptionContext:" + ck, std::vector<std::string>{cv});
            context_keys.push_back(ck);
        }
        r.keys.emplace_back("kms:EncryptionContextKeys", std::move(context_keys));
        if (auto denied = ctx.authorize(std::move(r))) {
            // A grant that allows CreateGrant lets its grantee pass on no
            // more than it holds.
            if (ctx.last_denial_explicit || !ctx.grants_apply || !parent_grant(**c, ctx, *g)) {
                return *denied;
            }
            ctx.allow_by_grant();
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        // The same Name and parameters again is the same grant (AWS's
        // idempotency for retried calls).
        if (!g->name.empty()) {
            for (const auto& e : (*c)->grants(k->record.key_id)) {
                if (same_grant(e, *g)) {
                    return boost::json::object{
                        {"GrantId", e.grant_id},
                        {"GrantToken", make_grant_token(e.key_id, e.grant_id)}};
                }
            }
        }
        g->grant_id = _new_grant_id();
        g->created_ms = _d.clock_ms();
        auto out = write(make_create_grant_command(*g), key_label(ctx, k->record));
        if (!out) {
            return out;
        }
        return boost::json::object{{"GrantId", g->grant_id},
                                   {"GrantToken", make_grant_token(g->key_id, g->grant_id)}};
    }

    auto list_grants(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        auto r = key_request(ctx, **c, *k, "ListGrants");
        r.keys.emplace_back(
            "kms:GrantIsForAWSResource",
            std::vector<std::string>{k->record.manager == key_manager::aws ? "true" : "false"});
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        const auto limit = std::min<std::size_t>(limit_of(in, 50), 100);
        const auto marker = str(in, "Marker").value_or("");
        const auto only_id = str(in, "GrantId");
        const auto only_grantee = str(in, "GranteePrincipal");
        boost::json::array out;
        bool truncated = false;
        std::string last;
        for (const auto& g : (*c)->grants(k->record.key_id)) {
            if ((!marker.empty() && g.grant_id <= marker) || (only_id && g.grant_id != *only_id) ||
                (only_grantee && g.grantee_principal != *only_grantee)) {
                continue;
            }
            if (out.size() == limit) {
                truncated = true;
                break;
            }
            out.push_back(entry(ctx, k->record, g));
            last = g.grant_id;
        }
        boost::json::object res{{"Grants", std::move(out)}, {"Truncated", truncated}};
        if (truncated) {
            res["NextMarker"] = last;
        }
        return res;
    }

    auto list_retirable_grants(call_context& ctx, boost::json::object& in) -> result {
        const auto retiring = str(in, "RetiringPrincipal");
        if (!retiring || retiring->empty()) {
            return validation_error("RetiringPrincipal is required");
        }
        aws_auth::authz_request r;
        r.action = "kms:ListRetirableGrants";
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto limit = std::min<std::size_t>(limit_of(in, 50), 100);
        // The marker is "<key id>/<grant id>" of the last grant answered.
        const std::string marker(str(in, "Marker").value_or(""));
        boost::json::array out;
        bool truncated = false;
        std::string last;
        for (const auto& id : (*c)->keys(ctx.principal.account)) {
            const auto key = (*c)->key(id);
            if (!key) {
                continue;
            }
            for (const auto& g : (*c)->grants(id)) {
                const auto at = id + "/" + g.grant_id;
                if (g.retiring_principal != *retiring || (!marker.empty() && at <= marker)) {
                    continue;
                }
                if (out.size() == limit) {
                    truncated = true;
                    break;
                }
                out.push_back(entry(ctx, *key, g));
                last = at;
            }
            if (truncated) {
                break;
            }
        }
        boost::json::object res{{"Grants", std::move(out)}, {"Truncated", truncated}};
        if (truncated) {
            res["NextMarker"] = last;
        }
        return res;
    }

    auto retire_grant(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        std::string key_id;
        std::string grant_id;
        std::string account = ctx.principal.account;
        if (const auto token = str(in, "GrantToken")) {
            const auto parts = parse_grant_token(*token);
            if (!parts) {
                return kms_error("InvalidGrantTokenException", "The grant token is not valid");
            }
            key_id = parts->key_id;
            grant_id = parts->grant_id;
            const auto k = (*c)->key(key_id);
            if (k) {
                account = k->account;
            }
        } else {
            const auto gid = str(in, "GrantId");
            if (!gid || !in.contains("KeyId")) {
                return validation_error("Either GrantToken or both KeyId and GrantId are required");
            }
            auto k = resolve(ctx, **c, in, "KeyId", false);
            if (!k) {
                return k.error();
            }
            key_id = k->record.key_id;
            account = k->record.account;
            grant_id = std::string(*gid);
        }
        const auto k = (*c)->key(key_id);
        if (!k || k->account != account) {
            return not_found("Key '" + ctx.key_arn(account, key_id) + "' does not exist");
        }
        const auto g = (*c)->grant(key_id, grant_id);
        if (!g) {
            return not_found("Grant " + grant_id + " does not exist");
        }
        // The grant decides, not a policy (as on AWS): its retiring
        // principal, its grantee when it lists RetireGrant, or the root of
        // the account that issued it.
        const bool may = grantee_matches(ctx.principal, g->retiring_principal) ||
                         (grantee_matches(ctx.principal, g->grantee_principal) &&
                          std::find(g->operations.begin(), g->operations.end(), "RetireGrant") !=
                              g->operations.end()) ||
                         (ctx.principal.type == aws_auth::principal_type::root &&
                          ctx.principal.account == g->issuing_account);
        if (!may) {
            return kms_error("AccessDeniedException",
                             "User: " + ctx.principal.arn +
                                 " is not authorized to perform: kms:RetireGrant on resource: " +
                                 ctx.key_arn(k->account, k->key_id) +
                                 " because the grant does not name it",
                             400);
        }
        ctx.allow_by_grant();
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        return write(make_remove_grant_command(key_id, grant_id), "Grant " + grant_id);
    }

    auto revoke_grant(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        const auto gid = str(in, "GrantId");
        if (!gid || gid->empty()) {
            return validation_error("GrantId is required");
        }
        auto r = key_request(ctx, **c, *k, "RevokeGrant");
        r.keys.emplace_back(
            "kms:GrantIsForAWSResource",
            std::vector<std::string>{k->record.manager == key_manager::aws ? "true" : "false"});
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        if (!(*c)->grant(k->record.key_id, *gid)) {
            return not_found("Grant " + std::string(*gid) + " does not exist");
        }
        if (auto dry = dry_run(in)) {
            return *dry;
        }
        return write(make_remove_grant_command(k->record.key_id, *gid),
                     "Grant " + std::string(*gid));
    }

    /// Tests replace the id source to name grants predictably.
    void set_grant_id_source(std::function<std::string()> f) { _new_grant_id = std::move(f); }

private:
    /// A request's grant, checked against the key it is for.
    [[nodiscard]] static auto read_grant(const boost::json::object& in, const key_record& key)
        -> aws_json::result<grant_record> {
        grant_record g;
        const auto grantee = str(in, "GranteePrincipal");
        if (!grantee || grantee->empty()) {
            return validation_error("GranteePrincipal is required");
        }
        g.grantee_principal = std::string(*grantee);
        g.retiring_principal = std::string(str(in, "RetiringPrincipal").value_or(""));
        g.name = std::string(str(in, "Name").value_or(""));
        const auto* ops = in.if_contains("Operations");
        if (ops == nullptr || !ops->is_array() || ops->get_array().empty()) {
            return validation_error("Operations must list at least one operation");
        }
        std::set<std::string> seen;
        for (const auto& v : ops->get_array()) {
            if (!v.is_string()) {
                return validation_error("Operations must be strings");
            }
            const std::string op(v.get_string());
            if (std::find(k_grant_operations.begin(), k_grant_operations.end(), op) ==
                k_grant_operations.end()) {
                return validation_error("Operation " + op + " is not a grant operation");
            }
            if (!grant_operation_allowed(key.spec, key.usage, op)) {
                return validation_error("Operation " + op +
                                        " is not valid for this key's KeySpec and KeyUsage");
            }
            if (seen.insert(op).second) {
                g.operations.push_back(op);
            }
        }
        if (const auto* cons = in.if_contains("Constraints");
            cons != nullptr && cons->is_object()) {
            const auto& o = cons->get_object();
            const auto* subset = o.if_contains("EncryptionContextSubset");
            const auto* equals = o.if_contains("EncryptionContextEquals");
            if (subset != nullptr && equals != nullptr) {
                return validation_error(
                    "Constraints take EncryptionContextSubset or EncryptionContextEquals, not "
                    "both");
            }
            const auto* chosen = subset != nullptr ? subset : equals;
            if (chosen != nullptr) {
                if (key.spec != key_spec::symmetric_default) {
                    return validation_error(
                        "Encryption context constraints are only valid on symmetric encryption "
                        "keys");
                }
                g.constraint = subset != nullptr ? grant_constraint::context_subset
                                                 : grant_constraint::context_equals;
                if (chosen->is_object()) {
                    for (const auto& [ck, cv] : chosen->get_object()) {
                        if (cv.is_string()) {
                            g.constraint_context.emplace(std::string(ck),
                                                         std::string(cv.get_string()));
                        }
                    }
                }
            }
        }
        return g;
    }

    /// A live grant for the caller that lists CreateGrant and is at least
    /// as wide as `child`. CreateGrant takes no encryption context, so a
    /// constrained parent is judged by grant_within, which makes the child
    /// keep the constraint.
    [[nodiscard]] static auto parent_grant(const Catalog& c, const call_context& ctx,
                                           const grant_record& child) -> bool {
        const auto grants = c.grants(child.key_id);
        return std::any_of(grants.begin(), grants.end(), [&](const grant_record& g) {
            return grantee_matches(ctx.principal, g.grantee_principal) &&
                   std::find(g.operations.begin(), g.operations.end(), "CreateGrant") !=
                       g.operations.end() &&
                   grant_within(child, g);
        });
    }

    [[nodiscard]] static auto same_grant(const grant_record& a, const grant_record& b) -> bool {
        const std::set<std::string> ao(a.operations.begin(), a.operations.end());
        const std::set<std::string> bo(b.operations.begin(), b.operations.end());
        return a.name == b.name && a.grantee_principal == b.grantee_principal &&
               a.retiring_principal == b.retiring_principal && ao == bo &&
               a.constraint == b.constraint && a.constraint_context == b.constraint_context;
    }

    [[nodiscard]] static auto entry(const call_context& ctx, const key_record& key,
                                    const grant_record& g) -> boost::json::object {
        boost::json::array ops;
        for (const auto& op : g.operations) {
            ops.emplace_back(op);
        }
        boost::json::object e{
            {"KeyId", ctx.key_arn(key.account, key.key_id)},
            {"GrantId", g.grant_id},
            {"CreationDate", static_cast<double>(g.created_ms) / 1000.0},
            {"GranteePrincipal", g.grantee_principal},
            {"IssuingAccount", "arn:" + ctx.partition + ":iam::" + g.issuing_account + ":root"},
            {"Operations", std::move(ops)},
        };
        if (!g.name.empty()) {
            e["Name"] = g.name;
        }
        if (!g.retiring_principal.empty()) {
            e["RetiringPrincipal"] = g.retiring_principal;
        }
        if (g.constraint != grant_constraint::none) {
            boost::json::object pairs;
            for (const auto& [ck, cv] : g.constraint_context) {
                pairs[ck] = cv;
            }
            e["Constraints"] = boost::json::object{{g.constraint == grant_constraint::context_subset
                                                        ? "EncryptionContextSubset"
                                                        : "EncryptionContextEquals",
                                                    std::move(pairs)}};
        }
        return e;
    }

    [[nodiscard]] static auto dry_run(const boost::json::object& in)
        -> std::optional<aws_json::error> {
        if (const auto* d = in.if_contains("DryRun");
            d != nullptr && d->is_bool() && d->get_bool()) {
            return kms_error("DryRunOperationException",
                             "The request would have succeeded, but the DryRun option is set.",
                             412);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto catalog() const -> aws_json::result<std::shared_ptr<const Catalog>> {
        if (!_d.barrier()) {
            return dependency_timeout();
        }
        auto c = _d.catalog();
        if (!c) {
            return internal_error("The KMS catalog has not opened yet");
        }
        return c;
    }

    [[nodiscard]] auto write(const std::vector<std::byte>& cmd, const std::string& what) const
        -> result {
        catalog_status s{};
        try {
            s = _d.propose(cmd);
        } catch (const std::exception&) {
            return dependency_timeout();
        }
        if (s != catalog_status::ok) {
            return catalog_error(s, what);
        }
        return boost::json::object{};
    }

    api_deps<Catalog> _d;
    std::function<std::string()> _new_grant_id = random_grant_id;
};

}  // namespace kythira::kms
