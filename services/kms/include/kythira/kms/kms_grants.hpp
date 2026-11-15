// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Grant evaluation (.kiro/specs/kms-compatible-api/ task 10, Requirements
// 8.1-8.4). A grant is not a policy: the KMS consults a key's grants only
// when IAM refused a request without an explicit deny, and allows it when a
// live grant names the caller as grantee, lists the operation, and its
// encryption context constraint holds. That is AWS's model, where a grant
// is an alternative to the key policy and an explicit Deny in any policy
// still wins.
//
// Matching the grantee is by exact ARN: the caller's own ARN, or for a role
// session the role's ARN (AWS lets a grant name a role and then serves its
// sessions). A grant to an account's root principal serves only that root
// principal here; AWS additionally lets the account delegate such a grant
// through IAM policies, which Kythira does not (doc/unsupported.md).

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_ciphertext.hpp>

#include <raft/aws_request_authorizer.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::kms {

/// Every operation a grant may list, as AWS names them.
inline constexpr std::array<std::string_view, 17> k_grant_operations{
    "CreateGrant",
    "Decrypt",
    "DeriveSharedSecret",
    "DescribeKey",
    "Encrypt",
    "GenerateDataKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
    "GenerateDataKeyWithoutPlaintext",
    "GenerateMac",
    "GetPublicKey",
    "ReEncryptFrom",
    "ReEncryptTo",
    "RetireGrant",
    "Sign",
    "Verify",
    "VerifyMac",
};

/// Whether a grant on a key of this spec and usage may list `op`, as AWS
/// allows per key type: symmetric encryption keys take the data key
/// operations, asymmetric encryption keys GetPublicKey but no data keys,
/// signing keys Sign, Verify and GetPublicKey, HMAC keys the MAC
/// operations. Every key takes CreateGrant, RetireGrant and DescribeKey.
/// DeriveSharedSecret needs key agreement keys, which Kythira does not
/// make, so no key takes it.
[[nodiscard]] inline auto grant_operation_allowed(key_spec spec, key_usage usage,
                                                  std::string_view op) -> bool {
    if (op == "CreateGrant" || op == "RetireGrant" || op == "DescribeKey") {
        return true;
    }
    switch (usage) {
        case key_usage::encrypt_decrypt:
            if (op == "Encrypt" || op == "Decrypt" || op == "ReEncryptFrom" ||
                op == "ReEncryptTo") {
                return true;
            }
            if (spec == key_spec::symmetric_default) {
                return op == "GenerateDataKey" || op == "GenerateDataKeyWithoutPlaintext" ||
                       op == "GenerateDataKeyPair" || op == "GenerateDataKeyPairWithoutPlaintext";
            }
            return op == "GetPublicKey";
        case key_usage::sign_verify:
            return op == "Sign" || op == "Verify" || op == "GetPublicKey";
        case key_usage::generate_verify_mac:
            return op == "GenerateMac" || op == "VerifyMac";
    }
    return false;
}

/// The operations that take an encryption context, and so can be served
/// by a grant with an encryption context constraint. AWS allows a
/// constrained grant to list others, but they are never allowed by it.
[[nodiscard]] constexpr auto takes_encryption_context(std::string_view op) -> bool {
    return op == "Encrypt" || op == "Decrypt" || op == "ReEncryptFrom" || op == "ReEncryptTo" ||
           op == "GenerateDataKey" || op == "GenerateDataKeyWithoutPlaintext" ||
           op == "GenerateDataKeyPair" || op == "GenerateDataKeyPairWithoutPlaintext";
}

/// Whether `who` is the principal `grantee` names.
[[nodiscard]] inline auto grantee_matches(const aws_auth::principal_context& who,
                                          std::string_view grantee) -> bool {
    return !grantee.empty() &&
           (who.arn == grantee || (!who.role_arn.empty() && who.role_arn == grantee));
}

/// Whether a constraint allows a request with `context`: Equals needs the
/// same pairs exactly, Subset needs the constraint's pairs among the
/// request's.
[[nodiscard]] inline auto constraint_holds(grant_constraint kind, const tag_map& constraint,
                                           const encryption_context& context) -> bool {
    switch (kind) {
        case grant_constraint::none:
            return true;
        case grant_constraint::context_equals:
            return constraint.size() == context.size() &&
                   std::equal(constraint.begin(), constraint.end(), context.begin());
        case grant_constraint::context_subset:
            return std::all_of(constraint.begin(), constraint.end(), [&](const auto& kv) {
                const auto it = context.find(kv.first);
                return it != context.end() && it->second == kv.second;
            });
    }
    return false;
}

/// Whether grant `g` allows `who` to perform `op`. `context` is the
/// request's encryption context, or null for an operation that takes none
/// (which a constrained grant never allows).
[[nodiscard]] inline auto grant_allows(const grant_record& g,
                                       const aws_auth::principal_context& who, std::string_view op,
                                       const encryption_context* context) -> bool {
    if (!grantee_matches(who, g.grantee_principal) ||
        std::find(g.operations.begin(), g.operations.end(), op) == g.operations.end()) {
        return false;
    }
    if (g.constraint == grant_constraint::none) {
        return true;
    }
    return context != nullptr && takes_encryption_context(op) &&
           constraint_holds(g.constraint, g.constraint_context, *context);
}

/// Whether a child grant is no wider than its parent, as AWS requires of a
/// grant made under another grant's CreateGrant: its operations are among
/// the parent's, and any constraint of the parent's is kept or narrowed.
[[nodiscard]] inline auto grant_within(const grant_record& child, const grant_record& parent)
    -> bool {
    const bool ops_ok =
        std::all_of(child.operations.begin(), child.operations.end(), [&](const std::string& op) {
            return std::find(parent.operations.begin(), parent.operations.end(), op) !=
                   parent.operations.end();
        });
    if (!ops_ok) {
        return false;
    }
    switch (parent.constraint) {
        case grant_constraint::none:
            return true;
        case grant_constraint::context_equals:
            return child.constraint == grant_constraint::context_equals &&
                   child.constraint_context == parent.constraint_context;
        case grant_constraint::context_subset:
            // Any context the child allows must hold the parent's pairs.
            return child.constraint != grant_constraint::none &&
                   constraint_holds(grant_constraint::context_subset, parent.constraint_context,
                                    encryption_context(child.constraint_context.begin(),
                                                       child.constraint_context.end()));
    }
    return false;
}

/// A grant token: opaque to callers, naming the grant it came from. A
/// request that presents one is served after the grant committed (every
/// read passes a read barrier), which is the "at once" Requirement 8.3
/// asks for; the token itself carries no authority.
[[nodiscard]] inline auto make_grant_token(std::string_view key_id, std::string_view grant_id)
    -> std::string {
    return "kgt1." + std::string(key_id) + "." + std::string(grant_id);
}

struct grant_token_parts {
    std::string key_id;
    std::string grant_id;
};

/// The key and grant a token names, or nullopt for one this KMS did not
/// make.
[[nodiscard]] inline auto parse_grant_token(std::string_view token)
    -> std::optional<grant_token_parts> {
    constexpr std::string_view prefix = "kgt1.";
    if (!token.starts_with(prefix)) {
        return std::nullopt;
    }
    token.remove_prefix(prefix.size());
    const auto dot = token.rfind('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 == token.size()) {
        return std::nullopt;
    }
    return grant_token_parts{std::string(token.substr(0, dot)), std::string(token.substr(dot + 1))};
}

}  // namespace kythira::kms
