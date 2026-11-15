// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS operations over the catalog and the HSM
// (.kiro/specs/kms-compatible-api/ task 6, Requirements 3.1-3.6, 6.1-6.3
// and 7.2): key management, aliases and tags. The cryptographic
// operations join in tasks 7 and 8, key policies and grants in 9 and 10.
//
// Every handler resolves the key the request names (key id, key ARN, and
// where AWS takes one an alias name or alias ARN), authorizes the
// operation's action on the key's ARN with the key's policy as a KMS key
// policy (so an identity policy alone suffices only when the key policy
// delegates to the account, Requirement 7.3), and only then reads or
// writes. A key in another account is reached only by ARN, as on AWS.
//
// Reads pass a read barrier first, so an answer is never older than the
// last write any member acknowledged. Writes are catalog proposals; every
// input is checked here first, because the catalog treats a structurally
// bad command as a bug.

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_errors.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
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

/// A fresh key id: a random (version 4) UUID.
[[nodiscard]] inline auto random_key_id() -> std::string {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) {
        throw std::runtime_error("kms: no randomness for a key id");
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0FU) | 0x40U);
    b[8] = static_cast<unsigned char>((b[8] & 0x3FU) | 0x80U);
    std::array<char, 37> out{};
    std::snprintf(out.data(), out.size(),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0],
                  b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                  b[14], b[15]);
    return out.data();
}

/// AWS's default key policy (Requirement 7.2): the account's root
/// principal may do everything, which delegates to the account's IAM
/// policies.
[[nodiscard]] inline auto default_key_policy(std::string_view partition, std::string_view account)
    -> std::string {
    return R"({"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User )"
           R"(Permissions","Effect":"Allow","Principal":{"AWS":"arn:)" +
           std::string(partition) + ":iam::" + std::string(account) +
           R"(:root"},"Action":"kms:*","Resource":"*"}]})";
}

[[nodiscard]] constexpr auto usage_name(key_usage u) -> std::string_view {
    switch (u) {
        case key_usage::encrypt_decrypt:
            return "ENCRYPT_DECRYPT";
        case key_usage::sign_verify:
            return "SIGN_VERIFY";
        case key_usage::generate_verify_mac:
            return "GENERATE_VERIFY_MAC";
    }
    return "";
}

[[nodiscard]] constexpr auto state_name(key_state s) -> std::string_view {
    switch (s) {
        case key_state::creating:
            return "Creating";
        case key_state::enabled:
            return "Enabled";
        case key_state::disabled:
            return "Disabled";
        case key_state::pending_deletion:
            return "PendingDeletion";
    }
    return "";
}

/// The algorithms AWS lists for a key: encryption, signing or MAC.
struct key_algorithms {
    std::vector<std::string_view> encryption;
    std::vector<std::string_view> signing;
    std::vector<std::string_view> mac;
};

[[nodiscard]] inline auto algorithms_of(key_spec spec, key_usage usage) -> key_algorithms {
    key_algorithms a;
    switch (spec) {
        case key_spec::symmetric_default:
            a.encryption = {"SYMMETRIC_DEFAULT"};
            break;
        case key_spec::rsa_2048:
        case key_spec::rsa_3072:
        case key_spec::rsa_4096:
            if (usage == key_usage::encrypt_decrypt) {
                a.encryption = {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"};
            } else {
                a.signing = {"RSASSA_PSS_SHA_256",        "RSASSA_PSS_SHA_384",
                             "RSASSA_PSS_SHA_512",        "RSASSA_PKCS1_V1_5_SHA_256",
                             "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PKCS1_V1_5_SHA_512"};
            }
            break;
        case key_spec::ecc_nist_p256:
        case key_spec::ecc_secg_p256k1:
            a.signing = {"ECDSA_SHA_256"};
            break;
        case key_spec::ecc_nist_p384:
            a.signing = {"ECDSA_SHA_384"};
            break;
        case key_spec::ecc_nist_p521:
            a.signing = {"ECDSA_SHA_512"};
            break;
        case key_spec::hmac_224:
            a.mac = {"HMAC_SHA_224"};
            break;
        case key_spec::hmac_256:
            a.mac = {"HMAC_SHA_256"};
            break;
        case key_spec::hmac_384:
            a.mac = {"HMAC_SHA_384"};
            break;
        case key_spec::hmac_512:
            a.mac = {"HMAC_SHA_512"};
            break;
    }
    return a;
}

/// What the operations need from the module: the catalog replica, a read
/// barrier, proposals, CreateKey's two steps, and a clock.
template<typename Catalog> struct api_deps {
    /// This replica of the catalog, or null before it opens.
    std::function<std::shared_ptr<const Catalog>()> catalog;
    /// Waits until the replica has applied what was committed; false when
    /// no leader answered in time.
    std::function<bool()> barrier;
    /// A catalog proposal's status. Throws when no leader answered or the
    /// outcome is unknown.
    std::function<catalog_status(const std::vector<std::byte>&)> propose;
    /// CreateKey's two steps (key_jobs::create_key).
    std::function<key_result(key_record, const tag_map&)> create_key;
    /// Milliseconds since the epoch.
    std::function<std::uint64_t()> clock_ms;
    std::function<std::string()> new_key_id = random_key_id;
};

/// What every KMS operation shares: reading the request, resolving the key
/// it names, and authorizing an action on that key with its key policy.
class api_common {
protected:
    /// A key the request named, and whether it named it by alias.
    struct resolved {
        key_record record;
        bool by_alias = false;
        std::string alias;  ///< the alias name, when named by alias
    };

    [[nodiscard]] static auto str(const boost::json::object& o, std::string_view key)
        -> std::optional<std::string_view> {
        if (const auto* v = o.if_contains(key); v != nullptr && v->is_string()) {
            return std::string_view(v->get_string());
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto seconds(std::uint64_t ms) -> double {
        return static_cast<double>(ms) / 1000.0;
    }

    [[nodiscard]] static auto limit_of(const boost::json::object& in, std::size_t def)
        -> std::size_t {
        if (const auto* l = in.if_contains("Limit"); l != nullptr && l->is_int64()) {
            return static_cast<std::size_t>(std::clamp<std::int64_t>(l->get_int64(), 1, 1000));
        }
        return def;
    }

    static auto add_request_tags(aws_auth::authz_request& r, const tag_map& tags) -> void {
        std::vector<std::pair<std::string, std::string>> pairs(tags.begin(), tags.end());
        std::vector<std::string> keys;
        for (const auto& [k, v] : tags) {
            keys.push_back(k);
        }
        r.request_tags = std::move(pairs);
        r.keys.emplace_back("aws:TagKeys", std::move(keys));
    }

    [[nodiscard]] static auto spec_keys(const key_record& k)
        -> std::vector<std::pair<std::string, std::vector<std::string>>> {
        const auto* info = find_key_spec(k.spec);
        return {{"kms:KeySpec", {std::string(info != nullptr ? info->name : "")}},
                {"kms:KeyUsage", {std::string(usage_name(k.usage))}},
                {"kms:KeyOrigin", {"AWS_KMS"}},
                {"kms:MultiRegion", {"false"}}};
    }

    /// The key `member` names: a key id or key ARN, and with `alias_ok`
    /// an alias name or alias ARN.
    template<typename Catalog>
    [[nodiscard]] static auto resolve(const call_context& ctx, const Catalog& c,
                                      const boost::json::object& in, std::string_view member,
                                      bool alias_ok) -> aws_json::result<resolved> {
        const auto text = str(in, member).value_or("");
        std::string account = ctx.principal.account;
        std::string key_id;
        bool by_alias = false;
        std::string_view name = text;
        if (text.starts_with("arn:")) {
            const auto parts = parse_kms_arn(text);
            if (!parts || parts->partition != ctx.partition || parts->region != ctx.region) {
                return not_found("Invalid arn " + std::string(text));
            }
            account = std::string(parts->account);
            name = parts->resource;
            if (name.starts_with("key/")) {
                key_id = std::string(name.substr(4));
            }
        } else if (!name.starts_with("alias/")) {
            key_id = std::string(name);
        }
        if (key_id.empty()) {
            if (!name.starts_with("alias/") || !alias_ok) {
                return not_found(std::string(member) + " " + std::string(text) +
                                 " is not a key id or key ARN");
            }
            const auto a = c.alias(account, name);
            if (!a) {
                return not_found("Alias " + ctx.alias_arn(account, name) + " is not found.");
            }
            key_id = a->key_id;
            by_alias = true;
        }
        const auto k = c.key(key_id);
        if (!k || k->account != account) {
            return not_found("Key '" + ctx.key_arn(account, key_id) + "' does not exist");
        }
        return resolved{*k, by_alias, by_alias ? std::string(name) : std::string()};
    }

    template<typename Catalog>
    [[nodiscard]] static auto key_request(const call_context& ctx, const Catalog& c,
                                          const resolved& k, std::string_view action)
        -> aws_auth::authz_request {
        aws_auth::authz_request r;
        r.action = "kms:" + std::string(action);
        r.resource = ctx.key_arn(k.record.account, k.record.key_id);
        r.resource_account = k.record.account;
        r.resource_policy = k.record.policy;
        r.resource_kind = aws_auth::resource_policy_kind::key;
        for (const auto& [tk, tv] : c.tags(k.record.key_id)) {
            r.resource_tags.emplace_back(tk, tv);
        }
        r.keys = spec_keys(k.record);
        std::vector<std::string> aliases;
        for (const auto& a : c.aliases(k.record.account, k.record.key_id)) {
            aliases.push_back(a.name);
        }
        r.keys.emplace_back("kms:ResourceAliases", std::move(aliases));
        if (k.by_alias) {
            r.keys.emplace_back("kms:RequestAlias", std::vector<std::string>{k.alias});
        }
        return r;
    }

    template<typename Catalog>
    [[nodiscard]] static auto authorize_key(call_context& ctx, const Catalog& c, const resolved& k,
                                            std::string_view action,
                                            const tag_map* request_tags = nullptr)
        -> std::optional<aws_json::error> {
        auto r = key_request(ctx, c, k, action);
        if (request_tags != nullptr) {
            add_request_tags(r, *request_tags);
        }
        return ctx.authorize(std::move(r));
    }

    /// An alias action on the alias's own ARN, decided by identity policies
    /// (an alias has no policy of its own).
    [[nodiscard]] static auto authorize_alias(call_context& ctx, std::string_view name,
                                              std::string_view action)
        -> std::optional<aws_json::error> {
        aws_auth::authz_request r;
        r.action = "kms:" + std::string(action);
        r.resource = ctx.alias_arn(ctx.principal.account, name);
        return ctx.authorize(std::move(r));
    }

    [[nodiscard]] static auto key_label(const call_context& ctx, const key_record& k)
        -> std::string {
        return "Key '" + ctx.key_arn(k.account, k.key_id) + "'";
    }
};

/// The key management operations.
template<typename Catalog> class key_management_api : protected api_common {
public:
    using result = aws_json::result<boost::json::object>;

    explicit key_management_api(api_deps<Catalog> deps) : _d(std::move(deps)) {}

    /// The operations this registers, for implemented-operations.txt.
    static constexpr std::array<std::string_view, 15> k_operations{
        "CreateKey",           "DescribeKey",       "ListKeys",
        "EnableKey",           "DisableKey",        "UpdateKeyDescription",
        "ScheduleKeyDeletion", "CancelKeyDeletion", "CreateAlias",
        "UpdateAlias",         "DeleteAlias",       "ListAliases",
        "TagResource",         "UntagResource",     "ListResourceTags"};

    template<typename FrontEnd> void register_on(FrontEnd& fe) {
        const auto bind = [this](auto method) {
            return [this, method](call_context& ctx, boost::json::object& in) -> result {
                return (this->*method)(ctx, in);
            };
        };
        fe.on("CreateKey", bind(&key_management_api::create_key));
        fe.on("DescribeKey", bind(&key_management_api::describe_key));
        fe.on("ListKeys", bind(&key_management_api::list_keys));
        fe.on("EnableKey", bind(&key_management_api::enable_key));
        fe.on("DisableKey", bind(&key_management_api::disable_key));
        fe.on("UpdateKeyDescription", bind(&key_management_api::update_description));
        fe.on("ScheduleKeyDeletion", bind(&key_management_api::schedule_deletion));
        fe.on("CancelKeyDeletion", bind(&key_management_api::cancel_deletion));
        fe.on("CreateAlias", bind(&key_management_api::create_alias));
        fe.on("UpdateAlias", bind(&key_management_api::update_alias));
        fe.on("DeleteAlias", bind(&key_management_api::delete_alias));
        fe.on("ListAliases", bind(&key_management_api::list_aliases));
        fe.on("TagResource", bind(&key_management_api::tag_resource));
        fe.on("UntagResource", bind(&key_management_api::untag_resource));
        fe.on("ListResourceTags", bind(&key_management_api::list_resource_tags));
    }

    // -- Keys ------------------------------------------------------------------

    auto create_key(call_context& ctx, boost::json::object& in) -> result {
        if (in.contains("CustomKeyStoreId") || in.contains("XksKeyId")) {
            return unsupported(
                "Custom key stores are not supported: the backing store is "
                "configured for the whole service");
        }
        if (const auto origin = str(in, "Origin"); origin && *origin != "AWS_KMS") {
            return unsupported("Origin " + std::string(*origin) + " is not supported");
        }
        if (const auto* mr = in.if_contains("MultiRegion");
            mr != nullptr && mr->is_bool() && mr->get_bool()) {
            return unsupported("Multi-Region keys are not supported");
        }
        const auto spec_name = str(in, "KeySpec");
        const auto cmk_name = str(in, "CustomerMasterKeySpec");
        if (spec_name && cmk_name && *spec_name != *cmk_name) {
            return validation_error("KeySpec and CustomerMasterKeySpec name different specs");
        }
        const auto* spec =
            find_spec_named(spec_name.value_or(cmk_name.value_or("SYMMETRIC_DEFAULT")));
        if (spec == nullptr) {
            return validation_error("KeySpec " +
                                    std::string(spec_name.value_or(cmk_name.value_or(""))) +
                                    " is not supported");
        }
        const auto usage = parse_usage(str(in, "KeyUsage").value_or("ENCRYPT_DECRYPT"));
        if (!usage || !usage_allowed(spec->spec, *usage)) {
            return validation_error("KeyUsage " +
                                    std::string(str(in, "KeyUsage").value_or("ENCRYPT_DECRYPT")) +
                                    " is not valid for KeySpec " + std::string(spec->name));
        }
        std::string policy;
        if (const auto p = str(in, "Policy")) {
            if (auto bad = check_policy(*p)) {
                return *bad;
            }
            policy = std::string(*p);
        } else {
            policy = default_key_policy(ctx.partition, ctx.principal.account);
        }
        auto tags = read_tags(in);
        if (!tags) {
            return tags.error();
        }

        key_record k;
        k.key_id = _d.new_key_id();
        k.account = ctx.principal.account;
        k.description = std::string(str(in, "Description").value_or(""));
        k.spec = spec->spec;
        k.usage = *usage;
        k.policy = std::move(policy);

        aws_auth::authz_request r;
        r.action = "kms:CreateKey";
        r.keys = spec_keys(k);
        if (const auto* b = in.if_contains("BypassPolicyLockoutSafetyCheck");
            b != nullptr && b->is_bool()) {
            r.keys.emplace_back("kms:BypassPolicyLockoutSafetyCheck",
                                std::vector<std::string>{b->get_bool() ? "true" : "false"});
        }
        add_request_tags(r, *tags);
        if (auto denied = ctx.authorize(r)) {
            return *denied;
        }
        if (!tags->empty()) {
            aws_auth::authz_request t;
            t.action = "kms:TagResource";
            add_request_tags(t, *tags);
            if (auto denied = ctx.authorize(std::move(t))) {
                return *denied;
            }
        }

        key_result created;
        try {
            created = _d.create_key(k, *tags);
        } catch (const std::exception&) {
            return dependency_timeout();
        }
        if (!created.ok()) {
            return outcome_error(created, "the key");
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto made = (*c)->key(k.key_id);
        if (!made) {
            return internal_error();
        }
        return boost::json::object{{"KeyMetadata", metadata(ctx, *made)}};
    }

    auto describe_key(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", true);
        if (!k) {
            return k.error();
        }
        if (auto denied = authorize_key(ctx, **c, *k, "DescribeKey")) {
            return *denied;
        }
        return boost::json::object{{"KeyMetadata", metadata(ctx, k->record)}};
    }

    auto list_keys(call_context& ctx, boost::json::object& in) -> result {
        aws_auth::authz_request r;
        r.action = "kms:ListKeys";
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto limit = limit_of(in, 100);
        const auto marker = str(in, "Marker").value_or("");
        auto ids = (*c)->keys(ctx.principal.account, marker, limit + 1);
        const bool truncated = ids.size() > limit;
        if (truncated) {
            ids.resize(limit);
        }
        boost::json::array keys;
        for (const auto& id : ids) {
            keys.push_back(boost::json::object{{"KeyId", id},
                                               {"KeyArn", ctx.key_arn(ctx.principal.account, id)}});
        }
        boost::json::object out{{"Keys", std::move(keys)}, {"Truncated", truncated}};
        if (truncated) {
            out["NextMarker"] = ids.back();
        }
        return out;
    }

    auto enable_key(call_context& ctx, boost::json::object& in) -> result {
        return simple_write(ctx, in, "EnableKey", [](const key_record& k) {
            return make_set_enabled_command(k.key_id, true);
        });
    }

    auto disable_key(call_context& ctx, boost::json::object& in) -> result {
        return simple_write(ctx, in, "DisableKey", [](const key_record& k) {
            return make_set_enabled_command(k.key_id, false);
        });
    }

    auto update_description(call_context& ctx, boost::json::object& in) -> result {
        const std::string description(str(in, "Description").value_or(""));
        if (description.size() > k_max_description_bytes) {
            return validation_error("Description is longer than 8192 bytes");
        }
        return simple_write(ctx, in, "UpdateKeyDescription", [&](const key_record& k) {
            return make_update_description_command(k.key_id, description);
        });
    }

    auto schedule_deletion(call_context& ctx, boost::json::object& in) -> result {
        std::uint32_t days = 30;
        if (const auto* d = in.if_contains("PendingWindowInDays"); d != nullptr && d->is_int64()) {
            const auto v = d->get_int64();
            if (v < 7 || v > 30) {
                return validation_error("PendingWindowInDays must be between 7 and 30");
            }
            days = static_cast<std::uint32_t>(v);
        }
        key_record acted;
        auto out = simple_write(
            ctx, in, "ScheduleKeyDeletion",
            [&](const key_record& k) {
                return make_schedule_deletion_command(k.key_id, days, _d.clock_ms());
            },
            &acted);
        if (!out) {
            return out;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto k = (*c)->key(acted.key_id);
        if (!k) {
            return internal_error();
        }
        return boost::json::object{{"KeyId", ctx.key_arn(k->account, k->key_id)},
                                   {"DeletionDate", seconds(k->deletion_ms)},
                                   {"KeyState", state_name(k->state)},
                                   {"PendingWindowInDays", k->pending_window_days}};
    }

    auto cancel_deletion(call_context& ctx, boost::json::object& in) -> result {
        key_record acted;
        auto out = simple_write(
            ctx, in, "CancelKeyDeletion",
            [](const key_record& k) { return make_cancel_deletion_command(k.key_id); }, &acted);
        if (!out) {
            return out;
        }
        return boost::json::object{{"KeyId", ctx.key_arn(acted.account, acted.key_id)}};
    }

    // -- Aliases -----------------------------------------------------------------

    auto create_alias(call_context& ctx, boost::json::object& in) -> result {
        const std::string name(str(in, "AliasName").value_or(""));
        if (auto bad = check_alias_name(name)) {
            return *bad;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "TargetKeyId", false);
        if (!k) {
            return k.error();
        }
        if (k->record.account != ctx.principal.account) {
            return not_found("Key '" + ctx.key_arn(k->record.account, k->record.key_id) +
                             "' is not in the caller's account");
        }
        if (auto denied = authorize_alias(ctx, name, "CreateAlias")) {
            return *denied;
        }
        if (auto denied = authorize_key(ctx, **c, *k, "CreateAlias")) {
            return *denied;
        }
        return write(make_create_alias_command(ctx.principal.account, name, k->record.key_id, false,
                                               _d.clock_ms()),
                     "Alias " + name);
    }

    auto update_alias(call_context& ctx, boost::json::object& in) -> result {
        const std::string name(str(in, "AliasName").value_or(""));
        if (auto bad = check_alias_name(name)) {
            return *bad;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto alias = (*c)->alias(ctx.principal.account, name);
        if (!alias) {
            return not_found("Alias " + ctx.alias_arn(ctx.principal.account, name) +
                             " is not found.");
        }
        auto target = resolve(ctx, **c, in, "TargetKeyId", false);
        if (!target) {
            return target.error();
        }
        if (target->record.account != ctx.principal.account) {
            return not_found("Key '" + ctx.key_arn(target->record.account, target->record.key_id) +
                             "' is not in the caller's account");
        }
        const auto old = (*c)->key(alias->key_id);
        if (old && (old->spec != target->record.spec || old->usage != target->record.usage)) {
            return validation_error(
                "An alias can move only to a key of the same key spec and usage");
        }
        if (auto denied = authorize_alias(ctx, name, "UpdateAlias")) {
            return *denied;
        }
        if (old) {
            if (auto denied = authorize_key(ctx, **c, resolved{*old, false, {}}, "UpdateAlias")) {
                return *denied;
            }
        }
        if (auto denied = authorize_key(ctx, **c, *target, "UpdateAlias")) {
            return *denied;
        }
        return write(make_update_alias_command(ctx.principal.account, name, target->record.key_id,
                                               _d.clock_ms()),
                     "Alias " + name);
    }

    auto delete_alias(call_context& ctx, boost::json::object& in) -> result {
        const std::string name(str(in, "AliasName").value_or(""));
        if (auto bad = check_alias_name(name)) {
            return *bad;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        const auto alias = (*c)->alias(ctx.principal.account, name);
        if (!alias) {
            return not_found("Alias " + ctx.alias_arn(ctx.principal.account, name) +
                             " is not found.");
        }
        if (auto denied = authorize_alias(ctx, name, "DeleteAlias")) {
            return *denied;
        }
        if (const auto k = (*c)->key(alias->key_id)) {
            if (auto denied = authorize_key(ctx, **c, resolved{*k, false, {}}, "DeleteAlias")) {
                return *denied;
            }
        }
        return write(make_delete_alias_command(ctx.principal.account, name), "Alias " + name);
    }

    auto list_aliases(call_context& ctx, boost::json::object& in) -> result {
        aws_auth::authz_request r;
        r.action = "kms:ListAliases";
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        std::string key_id;
        if (in.contains("KeyId")) {
            auto k = resolve(ctx, **c, in, "KeyId", false);
            if (!k) {
                return k.error();
            }
            if (k->record.account != ctx.principal.account) {
                return not_found("Key is not in the caller's account");
            }
            key_id = k->record.key_id;
        }
        const auto limit = limit_of(in, 50);
        const auto marker = str(in, "Marker").value_or("");
        boost::json::array out;
        bool truncated = false;
        std::string last;
        for (const auto& a : (*c)->aliases(ctx.principal.account, key_id)) {
            if (!marker.empty() && a.name <= marker) {
                continue;
            }
            if (out.size() == limit) {
                truncated = true;
                break;
            }
            out.push_back(boost::json::object{{"AliasName", a.name},
                                              {"AliasArn", ctx.alias_arn(a.account, a.name)},
                                              {"TargetKeyId", a.key_id},
                                              {"CreationDate", seconds(a.created_ms)},
                                              {"LastUpdatedDate", seconds(a.updated_ms)}});
            last = a.name;
        }
        boost::json::object res{{"Aliases", std::move(out)}, {"Truncated", truncated}};
        if (truncated) {
            res["NextMarker"] = last;
        }
        return res;
    }

    // -- Tags --------------------------------------------------------------------

    auto tag_resource(call_context& ctx, boost::json::object& in) -> result {
        auto tags = read_tags(in);
        if (!tags) {
            return tags.error();
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        if (auto denied = authorize_key(ctx, **c, *k, "TagResource", &*tags)) {
            return *denied;
        }
        return write(make_tag_key_command(k->record.key_id, *tags), key_label(ctx, k->record));
    }

    auto untag_resource(call_context& ctx, boost::json::object& in) -> result {
        std::vector<std::string> keys;
        if (const auto* a = in.if_contains("TagKeys"); a != nullptr && a->is_array()) {
            for (const auto& v : a->get_array()) {
                if (v.is_string()) {
                    keys.emplace_back(v.get_string());
                }
            }
        }
        for (const auto& key : keys) {
            if (key.empty() || key.size() > 128 || key.find('\0') != std::string::npos) {
                return kms_error("TagException", "Tag key '" + key + "' is not valid");
            }
        }
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        aws_auth::authz_request r = key_request(ctx, **c, *k, "UntagResource");
        r.keys.emplace_back("aws:TagKeys", keys);
        if (auto denied = ctx.authorize(std::move(r))) {
            return *denied;
        }
        return write(make_untag_key_command(k->record.key_id, keys), key_label(ctx, k->record));
    }

    auto list_resource_tags(call_context& ctx, boost::json::object& in) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        if (auto denied = authorize_key(ctx, **c, *k, "ListResourceTags")) {
            return *denied;
        }
        const auto limit = std::min<std::size_t>(limit_of(in, 50), 50);
        const auto marker = str(in, "Marker").value_or("");
        boost::json::array out;
        bool truncated = false;
        std::string last;
        for (const auto& [key, value] : (*c)->tags(k->record.key_id)) {
            if (!marker.empty() && key <= marker) {
                continue;
            }
            if (out.size() == limit) {
                truncated = true;
                break;
            }
            out.push_back(boost::json::object{{"TagKey", key}, {"TagValue", value}});
            last = key;
        }
        boost::json::object res{{"Tags", std::move(out)}, {"Truncated", truncated}};
        if (truncated) {
            res["NextMarker"] = last;
        }
        return res;
    }

private:
    [[nodiscard]] static auto find_spec_named(std::string_view name) -> const key_spec_info* {
        for (const auto& i : k_key_specs) {
            if (i.name == name) {
                return &i;
            }
        }
        return nullptr;
    }

    [[nodiscard]] static auto parse_usage(std::string_view name) -> std::optional<key_usage> {
        for (const auto u :
             {key_usage::encrypt_decrypt, key_usage::sign_verify, key_usage::generate_verify_mac}) {
            if (usage_name(u) == name) {
                return u;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto check_policy(std::string_view p) -> std::optional<aws_json::error> {
        if (p.size() > k_max_policy_bytes) {
            return kms_error("LimitExceededException", "The key policy is larger than 32 KB");
        }
        boost::system::error_code ec;
        const auto v = boost::json::parse(p, ec);
        if (ec || !v.is_object()) {
            return kms_error("MalformedPolicyDocumentException",
                             "The key policy is not a JSON policy document");
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto check_alias_name(std::string_view name)
        -> std::optional<aws_json::error> {
        if (!valid_alias_name(name)) {
            return kms_error("InvalidAliasNameException",
                             "Alias name " + std::string(name) +
                                 " must begin with alias/ and use only A-Z a-z 0-9 / _ -");
        }
        if (is_aws_alias(name)) {
            return kms_error("InvalidAliasNameException",
                             "Alias names beginning with alias/aws/ are reserved for AWS "
                             "managed keys");
        }
        return std::nullopt;
    }

    /// The Tags member, checked as AWS checks it (TagException).
    [[nodiscard]] static auto read_tags(const boost::json::object& in)
        -> aws_json::result<tag_map> {
        tag_map out;
        const auto* list = in.if_contains("Tags");
        if (list == nullptr || !list->is_array()) {
            return out;
        }
        for (const auto& t : list->get_array()) {
            if (!t.is_object()) {
                continue;
            }
            const auto key = str(t.get_object(), "TagKey").value_or("");
            const auto value = str(t.get_object(), "TagValue").value_or("");
            if (key.empty() || key.size() > 128 || value.size() > 256 ||
                key.find('\0') != std::string_view::npos) {
                return kms_error("TagException", "Tag key '" + std::string(key) + "' is not valid");
            }
            if (key.starts_with("aws:")) {
                return kms_error("TagException",
                                 "Tag keys beginning with aws: are reserved for AWS");
            }
            if (!out.emplace(std::string(key), std::string(value)).second) {
                return kms_error("TagException", "Tag key '" + std::string(key) + "' repeats");
            }
        }
        if (out.size() > k_max_tags_per_key) {
            return kms_error("LimitExceededException", "A key may have at most 50 tags");
        }
        return out;
    }

    /// The catalog after a read barrier.
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

    /// Proposes `cmd` and answers `{}` on success.
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

    /// Resolve the key (no alias), authorize `action`, propose make(key).
    /// The key acted on goes to `acted` when given, for the answers that
    /// name it.
    template<typename Make>
    auto simple_write(call_context& ctx, boost::json::object& in, std::string_view action,
                      Make make, key_record* acted = nullptr) -> result {
        auto c = catalog();
        if (!c) {
            return c.error();
        }
        auto k = resolve(ctx, **c, in, "KeyId", false);
        if (!k) {
            return k.error();
        }
        if (auto denied = authorize_key(ctx, **c, *k, action)) {
            return *denied;
        }
        if (k->record.state == key_state::creating) {
            return invalid_state(key_label(ctx, k->record) + " is still being created");
        }
        if (acted != nullptr) {
            *acted = k->record;
        }
        auto out = write(make(k->record), key_label(ctx, k->record));
        if (!out && out.error().type == "ValidationException" &&
            k->record.manager == key_manager::aws) {
            return unsupported("This operation is not allowed on an AWS managed key");
        }
        return out;
    }

    [[nodiscard]] auto metadata(const call_context& ctx, const key_record& k) const
        -> boost::json::object {
        const auto* info = find_key_spec(k.spec);
        const std::string spec(info != nullptr ? info->name : "");
        boost::json::object m{
            {"AWSAccountId", k.account},
            {"KeyId", k.key_id},
            {"Arn", ctx.key_arn(k.account, k.key_id)},
            {"CreationDate", seconds(k.creation_ms)},
            {"Enabled", k.state == key_state::enabled},
            {"Description", k.description},
            {"KeyUsage", usage_name(k.usage)},
            {"KeyState", state_name(k.state)},
            {"Origin", "AWS_KMS"},
            {"KeyManager", k.manager == key_manager::aws ? "AWS" : "CUSTOMER"},
            {"CustomerMasterKeySpec", spec},
            {"KeySpec", spec},
            {"MultiRegion", false},
        };
        if (k.state == key_state::pending_deletion) {
            m["DeletionDate"] = seconds(k.deletion_ms);
        }
        const auto algs = algorithms_of(k.spec, k.usage);
        const auto list = [](const std::vector<std::string_view>& v) {
            boost::json::array a;
            for (const auto s : v) {
                a.emplace_back(s);
            }
            return a;
        };
        if (!algs.encryption.empty()) {
            m["EncryptionAlgorithms"] = list(algs.encryption);
        }
        if (!algs.signing.empty()) {
            m["SigningAlgorithms"] = list(algs.signing);
        }
        if (!algs.mac.empty()) {
            m["MacAlgorithms"] = list(algs.mac);
        }
        return m;
    }

    api_deps<Catalog> _d;
};

}  // namespace kythira::kms
