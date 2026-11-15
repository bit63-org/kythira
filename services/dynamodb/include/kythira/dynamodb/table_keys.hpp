// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file table_keys.hpp
/// @brief Table keys (`.kiro/specs/kms-compatible-api/` task 16,
///        Requirements 12.1, 12.2, 12.5, 12.7, 12.11 and 12.12): the
///        256-bit key each encrypted table has, made by a key provider
///        (`raft/kms_key_provider.hpp`) under the table's KMS key and
///        stored only wrapped, in the table descriptor (`table_sse`).
///
/// `KYTHIRA_DYNAMODB_KMS` picks the provider, as `KINESIS_KMS` does for
/// Kinesis:
///
///   - `kythira`: Kythira's KMS, through `kms.client` in process or over
///     HTTPS as a trusted service, with `kms:ViaService` dynamodb. The
///     default where the KMS module runs in the same node.
///   - `aws`: real AWS KMS under the operator's credentials.
///   - `local`: a passphrase-sealed master key on the node; it takes only
///     the owned key.
///   - `off`: no table is encrypted.
///
/// A table that names no key (`SSESpecification` absent, or `Enabled`
/// false) is encrypted under the owned key, as AWS encrypts it under an
/// AWS owned key, when `KYTHIRA_DYNAMODB_ENCRYPT_AT_REST=owned` (the
/// default with a provider). The owned key is the KMS's owned key for
/// DynamoDB in the table's account (`alias/aws/dynamodb/owned`, kythira),
/// a key the operator names (aws: AWS owned keys are not usable outside
/// AWS), or the local master key. `Enabled` true without a key names the
/// AWS managed key `alias/aws/dynamodb`.
///
/// The table key is bound to the table by its encryption context,
/// `{"aws:dynamodb:tableName": <name>, "aws:dynamodb:subscriberId":
/// <account>}`, as AWS binds it. Each wrapped key records the provider
/// that wrapped it, so a table keeps opening after the cluster moves to
/// another provider (the old one kept as `KYTHIRA_DYNAMODB_KMS_PREVIOUS`),
/// and `UpdateTable` moving a table to another key re-wraps the same
/// table key under it, unwrapped with the old provider and wrapped with
/// the current one, so no stored data is rewritten.
///
/// The key a customer names is used for the request's caller (Kythira's
/// KMS evaluates the key policy, grants and identity policies for that
/// principal); the owned key for the table's account.

#include <kythira/dynamodb/catalog.hpp>
#include <kythira/dynamodb/errors.hpp>
#include <kythira/dynamodb/front_end.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/kms_key_provider.hpp>

#include <boost/json.hpp>

#include <openssl/crypto.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace kythira::dynamodb {

/// What `KYTHIRA_DYNAMODB_ENCRYPT_AT_REST` asks of a table that names no
/// key.
enum class at_rest_mode : std::uint8_t {
    off = 0,
    owned = 1,
};

/// The providers and how tables use them.
struct table_key_config {
    /// The provider's name (`kythira`, `aws` or `local`); empty: none.
    std::string provider_name;
    kms_provider::key_provider provider;
    /// Providers that wrapped older tables' keys, by name.
    std::map<std::string, kms_provider::key_provider, std::less<>> previous;
    at_rest_mode at_rest = at_rest_mode::owned;
    /// The provider's id for the owned key: `alias/aws/dynamodb/owned`
    /// (kythira), the operator's key (aws), or any label (local).
    std::string owned_key_id;
    /// What `Enabled` true without `KMSMasterKeyId` names.
    std::string managed_key_id = "alias/aws/dynamodb";
    /// Whether a table may name a key of its own (false for `local`).
    bool customer_keys = true;
};

/// `KYTHIRA_DYNAMODB_KMS` and its siblings as read from the environment;
/// the daemon makes the providers from them (`table_key_providers.hpp`).
struct encryption_settings {
    /// `kythira`, `aws`, `local` or `off`; empty: `kythira` where the KMS
    /// module runs in the same node, else `off`.
    std::string kms;
    /// The provider before this one, still opening older tables' keys.
    std::string kms_previous;
    /// `owned` or `off` (`KYTHIRA_DYNAMODB_ENCRYPT_AT_REST`); empty: owned.
    std::string at_rest;
    /// aws: the key that stands for the owned key.
    std::string owned_key;
    /// aws: the KMS's region (the gateway's when empty) and endpoint
    /// (`host:port`, AWS's when empty); kythira: the endpoint of a KMS on
    /// another cluster, reached over HTTPS as a trusted service.
    std::string region;
    std::string endpoint;
    /// The PEM bundle `endpoint` chains to (system roots when empty).
    std::string ca;
    /// local: the passphrase the master key is derived from.
    std::string passphrase;
};

/// Reads the settings; the error text on a bad one.
template<typename Env>
[[nodiscard]] auto encryption_settings_from_env(const Env& env)
    -> std::variant<encryption_settings, std::string> {
    encryption_settings s;
    s.kms = env("KYTHIRA_DYNAMODB_KMS").value_or("");
    s.kms_previous = env("KYTHIRA_DYNAMODB_KMS_PREVIOUS").value_or("");
    s.at_rest = env("KYTHIRA_DYNAMODB_ENCRYPT_AT_REST").value_or("");
    s.owned_key = env("KYTHIRA_DYNAMODB_KMS_OWNED_KEY").value_or("");
    s.region = env("KYTHIRA_DYNAMODB_KMS_REGION").value_or("");
    s.endpoint = env("KYTHIRA_DYNAMODB_KMS_ENDPOINT").value_or("");
    s.ca = env("KYTHIRA_DYNAMODB_KMS_CA").value_or("");
    s.passphrase = env("KYTHIRA_DYNAMODB_KMS_PASSPHRASE").value_or("");
    const auto known = [](std::string_view v) {
        return v == "kythira" || v == "aws" || v == "local";
    };
    if (!s.kms.empty() && s.kms != "off" && !known(s.kms)) {
        return "KYTHIRA_DYNAMODB_KMS: expected kythira, aws, local or off, got '" + s.kms + "'";
    }
    if (!s.kms_previous.empty() && !known(s.kms_previous)) {
        return "KYTHIRA_DYNAMODB_KMS_PREVIOUS: expected kythira, aws or local, got '" +
               s.kms_previous + "'";
    }
    if (!s.kms_previous.empty() && s.kms_previous == s.kms) {
        return std::string(
            "KYTHIRA_DYNAMODB_KMS_PREVIOUS names the current provider; it is the one before");
    }
    if (!s.at_rest.empty() && s.at_rest != "owned" && s.at_rest != "off") {
        return "KYTHIRA_DYNAMODB_ENCRYPT_AT_REST: expected owned or off, got '" + s.at_rest + "'";
    }
    const auto uses = [&](std::string_view p) { return s.kms == p || s.kms_previous == p; };
    if (uses("local") && s.passphrase.empty()) {
        return std::string("KYTHIRA_DYNAMODB_KMS=local needs KYTHIRA_DYNAMODB_KMS_PASSPHRASE");
    }
    if (s.kms == "aws" && s.at_rest != "off" && s.owned_key.empty()) {
        return std::string(
            "KYTHIRA_DYNAMODB_KMS=aws needs KYTHIRA_DYNAMODB_KMS_OWNED_KEY (AWS owned keys "
            "cannot be used outside AWS), or KYTHIRA_DYNAMODB_ENCRYPT_AT_REST=off");
    }
    if (uses("aws") && uses("kythira") && !s.endpoint.empty()) {
        return std::string(
            "KYTHIRA_DYNAMODB_KMS_ENDPOINT would serve both aws and kythira; use one of them");
    }
    return s;
}

/// The encryption context that binds a table key to its table.
[[nodiscard]] inline auto table_key_context(std::string_view table, std::string_view account)
    -> kms_provider::encryption_context {
    return {{"aws:dynamodb:tableName", std::string(table)},
            {"aws:dynamodb:subscriberId", std::string(account)}};
}

/// The name a client knows a table by: the catalog name without its
/// `<account>/` when tables are namespaced.
[[nodiscard]] inline auto client_table_name(std::string_view catalog_name) -> std::string_view {
    const auto slash = catalog_name.find('/');
    return slash == std::string_view::npos ? catalog_name : catalog_name.substr(slash + 1);
}

/// The account that owns the table with catalog name `catalog_name`: its
/// `<account>/` when tables are namespaced, else `fallback`.
[[nodiscard]] inline auto table_account(std::string_view catalog_name, std::string_view fallback)
    -> std::string {
    const auto slash = catalog_name.find('/');
    return std::string(slash == std::string_view::npos ? fallback : catalog_name.substr(0, slash));
}

/// A provider's failure as DynamoDB answers it.
[[nodiscard]] inline auto table_key_error(const kms_provider::kms_error& e, std::string_view key)
    -> aws_json::error {
    using kms_provider::kms_failure;
    switch (e.failure()) {
        case kms_failure::access_denied: {
            aws_json::error out;
            out.type = "com.amazon.coral.service#AccessDeniedException";
            out.message = "The KMS key " + std::string(key) + " cannot be used: " + e.what();
            return out;
        }
        case kms_failure::throttling: {
            aws_json::error out;
            out.type = dynamodb_error_style().service_prefix + "ThrottlingException";
            out.message = "KMS throttled the request: " + std::string(e.what());
            return out;
        }
        case kms_failure::unavailable: {
            aws_json::error out;
            out.type = dynamodb_error_style().service_prefix + "InternalServerError";
            out.message = "The table's key provider is unavailable: " + std::string(e.what());
            out.status = 500;
            return out;
        }
        case kms_failure::disabled:
            return validation_error("KMSMasterKeyId " + std::string(key) + " is disabled");
        case kms_failure::not_found:
            return validation_error("KMSMasterKeyId " + std::string(key) + " is not found");
        case kms_failure::invalid_state:
        case kms_failure::opt_in_required:
            break;
    }
    return validation_error("KMSMasterKeyId " + std::string(key) +
                            " cannot be used: " + std::string(e.what()));
}

/// Makes and re-wraps table keys. Thread-safe: the providers are.
class table_keys {
public:
    table_keys() = default;
    explicit table_keys(table_key_config config) : _config(std::move(config)) {}

    /// Whether tables may be encrypted at all.
    [[nodiscard]] auto configured() const -> bool {
        return !_config.provider_name.empty() && static_cast<bool>(_config.provider);
    }

    [[nodiscard]] auto config() const -> const table_key_config& { return _config; }

    /// What a table made by `CreateTable` (or a restore) with `spec`, its
    /// `SSESpecification` (null for none), stores: an owned or customer
    /// key's wrapped table key, or nothing (no provider, or `off` and no
    /// key asked for). `table` is the client's name, `account` the owner.
    [[nodiscard]] auto make(const call_context& ctx, std::string_view table,
                            std::string_view account, const boost::json::object* spec) const
        -> aws_json::result<table_sse> {
        auto want = requested(spec);
        if (!want) {
            return want.error();
        }
        if (!want->has_value() && (!configured() || _config.at_rest == at_rest_mode::off)) {
            return table_sse{};
        }
        if (!configured()) {
            return validation_error(
                "SSESpecification needs a key provider: set KYTHIRA_DYNAMODB_KMS");
        }
        const auto context = table_key_context(table, account);
        const std::string key = want->value_or(_config.owned_key_id);
        const auto principal = for_key(ctx, want->has_value(), account);
        try {
            auto made = _config.provider.generate_data_key(key, context, caller(ctx, principal));
            OPENSSL_cleanse(made._plaintext.data(), made._plaintext.size());
            return stored(want->has_value(), made, account);
        } catch (const kms_provider::kms_error& e) {
            return table_key_error(e, key);
        }
    }

    /// What `UpdateTable` with `spec` changes the table's `current` keys
    /// to: the same table key re-wrapped under the key `spec` names (a
    /// fresh one for a table that had none). Refused when the table is
    /// already under that key.
    [[nodiscard]] auto rewrap(const call_context& ctx, std::string_view table,
                              const table_sse& current, std::string_view account,
                              const boost::json::object& spec) const
        -> aws_json::result<table_sse> {
        auto want = requested(&spec);
        if (!want) {
            return want.error();
        }
        if (!configured()) {
            return validation_error(
                "SSESpecification needs a key provider: set KYTHIRA_DYNAMODB_KMS");
        }
        const bool customer = want->has_value();
        if (!customer && current.kind == sse_kind::owned) {
            return validation_error("Table is already encrypted by an AWS owned key");
        }
        if (current.kind == sse_kind::none) {
            return make(ctx, table, account, &spec);
        }
        const auto& subscriber = current.account.empty() ? std::string(account) : current.account;
        const auto context = table_key_context(table, subscriber);
        const std::string key = want->value_or(_config.owned_key_id);
        try {
            const auto* old = provider_named(current.provider);
            if (old == nullptr) {
                return validation_error("The table's key was wrapped by the " + current.provider +
                                        " key provider, which this node does not have; set "
                                        "KYTHIRA_DYNAMODB_KMS_PREVIOUS=" +
                                        current.provider);
            }
            const auto old_principal = for_key(ctx, current.kind == sse_kind::kms, subscriber);
            auto plain = old->decrypt_data_key(current.key_arn, current.wrapped, context,
                                               caller(ctx, old_principal));
            const auto principal = for_key(ctx, customer, subscriber);
            auto made = _config.provider.wrap_data_key(key, plain, context, caller(ctx, principal));
            OPENSSL_cleanse(plain.data(), plain.size());
            OPENSSL_cleanse(made._plaintext.data(), made._plaintext.size());
            if (customer && current.kind == sse_kind::kms && made._key_id == current.key_arn &&
                current.provider == _config.provider_name) {
                return validation_error("Table is already encrypted by given KMSMasterKeyId");
            }
            return stored(customer, made, subscriber);
        } catch (const kms_provider::kms_error& e) {
            return table_key_error(e, current.key_arn);
        }
    }

    /// The table key of `d`, unwrapped by the provider that wrapped it, for
    /// the replicas of its groups (KMS task 16). Asked as the table's
    /// account: no request is in hand, as when AWS's DynamoDB opens a
    /// table key under the grant it made at `CreateTable`. Throws
    /// `kms_error` when the provider refuses or cannot answer.
    [[nodiscard]] auto open(const table_descriptor& d, std::string_view partition = "aws") const
        -> kms_provider::data_key_bytes {
        const auto* p = provider_named(d.sse.provider);
        if (p == nullptr) {
            throw kms_provider::kms_error(kms_provider::kms_failure::unavailable,
                                          "the table's key was wrapped by the " + d.sse.provider +
                                              " key provider, which this node does not have (set "
                                              "KYTHIRA_DYNAMODB_KMS_PREVIOUS=" +
                                              d.sse.provider + ")");
        }
        const auto account = d.sse.account.empty() ? table_account(d.name, "") : d.sse.account;
        const auto who = root_of(account, partition);
        return p->decrypt_data_key(d.sse.key_arn, d.sse.wrapped,
                                   table_key_context(client_table_name(d.name), account),
                                   kms_provider::kms_caller{._principal = &who});
    }

    /// A fresh data key under `key_id` for one object of an export
    /// (`S3SseKmsKeyId`, `bucket_sse.hpp`), asked as `account`'s root: the
    /// export runs on the catalog leader after the request has gone.
    [[nodiscard]] auto generate_object_key(const std::string& key_id,
                                           const kms_provider::encryption_context& context,
                                           std::string_view account,
                                           std::string_view partition) const
        -> kms_provider::generated_data_key {
        const auto who = root_of(account, partition);
        return _config.provider.generate_data_key(key_id, context,
                                                  kms_provider::kms_caller{._principal = &who});
    }

    /// The data key `wrapped` holds, for an object sealed by
    /// `generate_object_key`: asked of this node's provider, then of each
    /// previous one (the object does not say which wrapped it). Throws
    /// the first provider's `kms_error` when none opens it.
    [[nodiscard]] auto decrypt_object_key(const std::string& key_id, const std::string& wrapped,
                                          const kms_provider::encryption_context& context,
                                          std::string_view account,
                                          std::string_view partition) const
        -> kms_provider::data_key_bytes {
        const auto who = root_of(account, partition);
        const kms_provider::kms_caller as{._principal = &who};
        try {
            return _config.provider.decrypt_data_key(key_id, wrapped, context, as);
        } catch (const kms_provider::kms_error&) {
            for (const auto& entry : _config.previous) {
                try {
                    return entry.second.decrypt_data_key(key_id, wrapped, context, as);
                } catch (const kms_provider::kms_error&) {
                    // the next one may have wrapped it
                }
            }
            throw;
        }
    }

    /// The root of `account`: who the provider is asked for when no
    /// request is in hand (a replica, an archive, a replica table made
    /// for a peer region).
    [[nodiscard]] static auto root_of(std::string_view account, std::string_view partition)
        -> aws_auth::principal_context {
        aws_auth::principal_context root;
        root.type = aws_auth::principal_type::root;
        root.account = std::string(account);
        root.arn = "arn:" + (partition.empty() ? std::string("aws") : std::string(partition)) +
                   ":iam::" + std::string(account) + ":root";
        root.userid = std::string(account);
        return root;
    }

    /// The `SSESpecification` a request names: the customer key it asks
    /// for, or nothing for the owned key. Checked as DynamoDB checks it.
    [[nodiscard]] auto requested(const boost::json::object* spec) const
        -> aws_json::result<std::optional<std::string>> {
        if (spec == nullptr) {
            return std::optional<std::string>();
        }
        bool enabled = false;
        if (const auto* e = spec->if_contains("Enabled"); e != nullptr && e->is_bool()) {
            enabled = e->as_bool();
        }
        const auto* type = spec->if_contains("SSEType");
        const auto* key = spec->if_contains("KMSMasterKeyId");
        if (!enabled) {
            if ((type != nullptr && !type->is_null()) || (key != nullptr && !key->is_null())) {
                return validation_error(std::string(k_invalid_parameters) +
                                        "SSEType or KMSMasterKeyId is given but SSE is not "
                                        "enabled");
            }
            return std::optional<std::string>();
        }
        if (type != nullptr && type->is_string() && type->as_string() != "KMS") {
            return validation_error(std::string(k_invalid_parameters) + "SSEType " +
                                    std::string(type->as_string()) +
                                    " is not supported; only KMS is");
        }
        if (!_config.customer_keys) {
            return validation_error(
                "This cluster's key provider (KYTHIRA_DYNAMODB_KMS=" + _config.provider_name +
                ") takes only the owned key: SSESpecification may not enable a KMS key");
        }
        if (key != nullptr && key->is_string() && !key->as_string().empty()) {
            return std::optional<std::string>(std::string(key->as_string()));
        }
        return std::optional<std::string>(_config.managed_key_id);
    }

private:
    [[nodiscard]] auto provider_named(std::string_view name) const
        -> const kms_provider::key_provider* {
        if (name == _config.provider_name) {
            return &_config.provider;
        }
        const auto it = _config.previous.find(name);
        return it == _config.previous.end() ? nullptr : &it->second;
    }

    /// Who the provider is asked for: the caller for a key the customer
    /// named, the table's account for the owned key, which lives there.
    [[nodiscard]] static auto for_key(const call_context& ctx, bool customer,
                                      std::string_view account) -> aws_auth::principal_context {
        if (customer) {
            return ctx.principal;
        }
        return root_of(account, ctx.partition);
    }

    [[nodiscard]] static auto caller(const call_context& /*ctx*/,
                                     const aws_auth::principal_context& who)
        -> kms_provider::kms_caller {
        return kms_provider::kms_caller{._principal = &who};
    }

    [[nodiscard]] auto stored(bool customer, const kms_provider::generated_data_key& made,
                              std::string_view account) const -> table_sse {
        table_sse s;
        s.kind = customer ? sse_kind::kms : sse_kind::owned;
        s.key_arn = made._key_id;
        s.wrapped = made._wrapped;
        s.provider = _config.provider_name;
        s.account = std::string(account);
        s.status = sse_status::enabled;
        return s;
    }

    table_key_config _config;
};

/// Gives a table about to be made (`CreateTable`, `ImportTable`, a
/// restore) its table key, as `spec` (the request's `SSESpecification` or
/// `SSESpecificationOverride`, or null) asks. `keys` null: no provider.
[[nodiscard]] inline auto encrypt_new_table(const table_keys* keys, const call_context& ctx,
                                            table_descriptor& d, const boost::json::value* spec)
    -> std::optional<aws_json::error> {
    static const table_keys none;
    const auto& k = keys != nullptr ? *keys : none;
    const auto* object = spec != nullptr && spec->is_object() ? &spec->get_object() : nullptr;
    auto sse = k.make(ctx, client_table_name(d.name), table_account(d.name, ctx.owner()), object);
    if (!sse) {
        return sse.error();
    }
    d.sse = std::move(*sse);
    return std::nullopt;
}

/// `SSEDescription` for `sse`, or nothing: a clear table, and one under
/// the owned key, have none, as on AWS.
[[nodiscard]] inline auto sse_description(const table_sse& sse)
    -> std::optional<boost::json::object> {
    if (sse.kind != sse_kind::kms) {
        return std::nullopt;
    }
    boost::json::object out{{"SSEType", "KMS"}, {"KMSMasterKeyArn", sse.key_arn}};
    switch (sse.status) {
        case sse_status::enabled:
            out["Status"] = "ENABLED";
            break;
        case sse_status::updating:
            out["Status"] = "UPDATING";
            break;
        case sse_status::inaccessible:
            out["Status"] = "ENABLED";
            out["InaccessibleEncryptionDateTime"] =
                static_cast<double>(sse.inaccessible_ms) / 1000.0;
            break;
    }
    return out;
}

}  // namespace kythira::dynamodb
