// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_access.hpp
/// @brief S3's access model around the authorizer: Object Ownership, ACLs,
///        Block Public Access and anonymous access
///        (.kiro/specs/s3-compatible-storage/ task 6, Requirements 5.1-5.5).
///
/// **The decision.** Every check `s3_authz.hpp` produces goes to the
/// authorizer with the bucket policy as its resource policy and the bucket
/// owner as the resource account, so identity and bucket policies combine
/// as IAM combines them (5.1, 5.2). An explicit deny ends it. Otherwise an
/// ACL can still allow, as S3 evaluates ACLs beside policies, but only
/// when the bucket's Object Ownership enables ACLs (5.3): S3's default,
/// `BucketOwnerEnforced`, disables them. An ACL grant to the caller's
/// account (or to AuthenticatedUsers) is the resource side only; the
/// caller's own identity policies must still allow, which is asked of the
/// authorizer as a request in the caller's own account with no resource
/// policy. A grant to AllUsers allows an anonymous caller outright.
///
/// **Anonymous requests** (5.5) have no identity: the bucket policy, through
/// `aws_anonymous_authorizer`, or an AllUsers ACL grant must allow them. An
/// authorizer without that hook (static keys) allows them nothing by
/// policy.
///
/// **Block Public Access** (5.4) is the account's setting OR'd with the
/// bucket's, every flag on by default, as S3 sets new buckets since 2023:
///
/// - `BlockPublicAcls`: a write that sets a public ACL is refused.
/// - `IgnorePublicAcls`: public grants (AllUsers, AuthenticatedUsers) are
///   ignored when deciding.
/// - `BlockPublicPolicy`: a bucket policy that is public is refused.
/// - `RestrictPublicBuckets`: while the bucket's policy is public, only
///   principals in the bucket owner's account get anything from it.
///
/// A policy is public by S3's rule ("The meaning of public"): some Allow
/// statement grants a wildcard principal (`*`, `{"AWS": "*"}`, a principal
/// containing `*`, or any `NotPrincipal`) without a condition that fixes
/// one of the keys S3 accepts as restricting (`aws:SourceArn`,
/// `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceAccount`,
/// `aws:SourceOwner`, `aws:PrincipalArn`, `aws:PrincipalAccount`,
/// `aws:PrincipalOrgID`, `aws:userid`, `s3:DataAccessPointArn`,
/// `s3:DataAccessPointAccount`, or `aws:SourceIp` narrower than /8 for IPv4
/// and /32 for IPv6) to values without wildcards. An `...IfExists`
/// operator does not fix anything.
///
/// **Canonical ids.** S3 names an ACL grantee by a 64-hex canonical user
/// id. Kythira uses the account id as the canonical id, so an ACL names
/// accounts exactly as policies do; a grant by email address is refused
/// (`UnresolvableGrantByEmailAddress`), as S3 does in every region opened
/// since 2019.

#include <kythira/s3/s3_auth.hpp>
#include <kythira/s3/s3_authz.hpp>

#include <raft/aws_request_authorizer.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// Object Ownership
// ---------------------------------------------------------------------------

enum class object_ownership : std::uint8_t {
    bucket_owner_enforced,  ///< ACLs disabled (S3's default)
    bucket_owner_preferred,
    object_writer,
};

[[nodiscard]] inline auto to_string(object_ownership o) -> std::string_view {
    switch (o) {
        case object_ownership::bucket_owner_enforced:
            return "BucketOwnerEnforced";
        case object_ownership::bucket_owner_preferred:
            return "BucketOwnerPreferred";
        case object_ownership::object_writer:
            return "ObjectWriter";
    }
    return "BucketOwnerEnforced";
}

[[nodiscard]] inline auto parse_ownership(std::string_view s) -> std::optional<object_ownership> {
    for (auto o : {object_ownership::bucket_owner_enforced,
                   object_ownership::bucket_owner_preferred, object_ownership::object_writer}) {
        if (to_string(o) == s) {
            return o;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// ACLs
// ---------------------------------------------------------------------------

enum class acl_permission : std::uint8_t {
    read,
    write,
    read_acp,
    write_acp,
    full_control
};

[[nodiscard]] inline auto to_string(acl_permission p) -> std::string_view {
    switch (p) {
        case acl_permission::read:
            return "READ";
        case acl_permission::write:
            return "WRITE";
        case acl_permission::read_acp:
            return "READ_ACP";
        case acl_permission::write_acp:
            return "WRITE_ACP";
        case acl_permission::full_control:
            return "FULL_CONTROL";
    }
    return "READ";
}

[[nodiscard]] inline auto parse_permission(std::string_view s) -> std::optional<acl_permission> {
    for (auto p : {acl_permission::read, acl_permission::write, acl_permission::read_acp,
                   acl_permission::write_acp, acl_permission::full_control}) {
        if (to_string(p) == s) {
            return p;
        }
    }
    return std::nullopt;
}

inline constexpr std::string_view all_users_uri = "http://acs.amazonaws.com/groups/global/AllUsers";
inline constexpr std::string_view authenticated_users_uri =
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
inline constexpr std::string_view log_delivery_uri =
    "http://acs.amazonaws.com/groups/s3/LogDelivery";

struct acl_grant {
    bool group = false;  ///< `uri` grantee; else a canonical user (account)
    std::string grantee;
    acl_permission permission = acl_permission::read;

    friend auto operator==(const acl_grant&, const acl_grant&) -> bool = default;
};

struct access_control_list {
    std::string owner;  ///< canonical id = account
    std::vector<acl_grant> grants;

    friend auto operator==(const access_control_list&, const access_control_list&)
        -> bool = default;
};

[[nodiscard]] inline auto owner_only(std::string owner) -> access_control_list {
    access_control_list acl{owner, {}};
    acl.grants.push_back({false, std::move(owner), acl_permission::full_control});
    return acl;
}

/// Whether a grant reaches the public (AllUsers or AuthenticatedUsers, as
/// Block Public Access counts them).
[[nodiscard]] inline auto is_public(const acl_grant& g) -> bool {
    return g.group && (g.grantee == all_users_uri || g.grantee == authenticated_users_uri);
}
[[nodiscard]] inline auto is_public(const access_control_list& acl) -> bool {
    return std::ranges::any_of(acl.grants, [](const acl_grant& g) { return is_public(g); });
}

[[nodiscard]] inline auto access_denied() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(403, "AccessDenied", "Access Denied");
}
[[nodiscard]] inline auto acl_not_supported() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "AccessControlListNotSupported",
                                      "The bucket does not allow ACLs");
}
[[nodiscard]] inline auto invalid_argument(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
}

/// A canned ACL for a resource owned by `owner` in a bucket owned by
/// `bucket_owner`.
[[nodiscard]] inline auto canned_acl(std::string_view name, const std::string& owner,
                                     const std::string& bucket_owner)
    -> aws_rest_xml::result<access_control_list> {
    auto acl = owner_only(owner);
    const auto add = [&](bool group, std::string_view who, acl_permission p) {
        acl.grants.push_back({group, std::string(who), p});
    };
    if (name == "private") {
    } else if (name == "public-read") {
        add(true, all_users_uri, acl_permission::read);
    } else if (name == "public-read-write") {
        add(true, all_users_uri, acl_permission::read);
        add(true, all_users_uri, acl_permission::write);
    } else if (name == "authenticated-read") {
        add(true, authenticated_users_uri, acl_permission::read);
    } else if (name == "bucket-owner-read") {
        if (bucket_owner != owner) {
            add(false, bucket_owner, acl_permission::read);
        }
    } else if (name == "bucket-owner-full-control") {
        if (bucket_owner != owner) {
            add(false, bucket_owner, acl_permission::full_control);
        }
    } else if (name == "log-delivery-write") {
        add(true, log_delivery_uri, acl_permission::write);
        add(true, log_delivery_uri, acl_permission::read_acp);
    } else {
        // aws-exec-read names an EC2 principal Kythira does not have.
        return invalid_argument("Unsupported canned ACL: " + std::string(name));
    }
    return acl;
}

namespace access_detail {

[[nodiscard]] inline auto trim(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] inline auto header(const std::vector<std::pair<std::string, std::string>>& h,
                                 std::string_view name) -> std::optional<std::string> {
    for (const auto& [k, v] : h) {
        if (aws_rest_xml::detail::iequals(k, name)) {
            return v;
        }
    }
    return std::nullopt;
}

}  // namespace access_detail

/// The ACL a request's headers set (`x-amz-acl` or `x-amz-grant-*`), if
/// any. The grant headers list `id="..."`, `uri="..."` or
/// `emailAddress="..."` grantees, comma separated.
[[nodiscard]] inline auto acl_from_headers(
    const std::vector<std::pair<std::string, std::string>>& headers, const std::string& owner,
    const std::string& bucket_owner) -> std::optional<aws_rest_xml::result<access_control_list>> {
    using access_detail::header;
    static constexpr std::array<std::pair<std::string_view, acl_permission>, 5> grant_headers{{
        {"x-amz-grant-read", acl_permission::read},
        {"x-amz-grant-write", acl_permission::write},
        {"x-amz-grant-read-acp", acl_permission::read_acp},
        {"x-amz-grant-write-acp", acl_permission::write_acp},
        {"x-amz-grant-full-control", acl_permission::full_control},
    }};
    const auto canned = header(headers, "x-amz-acl");
    const bool any_grant = std::ranges::any_of(
        grant_headers, [&](const auto& g) { return header(headers, g.first).has_value(); });
    if (!canned && !any_grant) {
        return std::nullopt;
    }
    if (canned && any_grant) {
        return aws_rest_xml::result<access_control_list>(aws_rest_xml::errors::make(
            400, "InvalidRequest", "Specifying both Canned ACLs and Header Grants is not allowed"));
    }
    if (canned) {
        return canned_acl(*canned, owner, bucket_owner);
    }
    access_control_list acl{owner, {}};
    for (const auto& [name, perm] : grant_headers) {
        const auto value = header(headers, name);
        if (!value) {
            continue;
        }
        std::string_view rest = *value;
        while (!rest.empty()) {
            const auto comma = rest.find(',');
            const auto item = access_detail::trim(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            const auto eq = item.find('=');
            if (eq == std::string_view::npos) {
                return aws_rest_xml::result<access_control_list>(
                    invalid_argument("Invalid grant header value"));
            }
            const auto kind = access_detail::trim(item.substr(0, eq));
            auto v = access_detail::trim(item.substr(eq + 1));
            if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
                v = v.substr(1, v.size() - 2);
            }
            if (v.empty()) {
                return aws_rest_xml::result<access_control_list>(
                    invalid_argument("Invalid grant header value"));
            }
            if (aws_rest_xml::detail::iequals(kind, "id")) {
                acl.grants.push_back({false, std::string(v), perm});
            } else if (aws_rest_xml::detail::iequals(kind, "uri")) {
                if (v != all_users_uri && v != authenticated_users_uri && v != log_delivery_uri) {
                    return aws_rest_xml::result<access_control_list>(
                        invalid_argument("Invalid group uri"));
                }
                acl.grants.push_back({true, std::string(v), perm});
            } else if (aws_rest_xml::detail::iequals(kind, "emailAddress")) {
                return aws_rest_xml::result<access_control_list>(aws_rest_xml::errors::make(
                    400, "UnresolvableGrantByEmailAddress",
                    "The email address you provided does not match any account on record."));
            } else {
                return aws_rest_xml::result<access_control_list>(
                    invalid_argument("Invalid grant header value"));
            }
        }
    }
    return acl;
}

/// `<AccessControlPolicy>`, as GetObjectAcl and GetBucketAcl answer.
[[nodiscard]] inline auto acl_xml(const access_control_list& acl) -> std::string {
    auto w = aws_rest_xml::document("AccessControlPolicy");
    w.open("Owner").element("ID", acl.owner).element("DisplayName", acl.owner).close();
    w.open("AccessControlList");
    for (const auto& g : acl.grants) {
        w.open("Grant");
        w.raw(std::string(R"(<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" )") +
              (g.group ? R"(xsi:type="Group">)" : R"(xsi:type="CanonicalUser">)"));
        if (g.group) {
            w.element("URI", g.grantee);
        } else {
            w.element("ID", g.grantee).element("DisplayName", g.grantee);
        }
        w.raw("</Grantee>");
        w.element("Permission", to_string(g.permission));
        w.close();
    }
    w.close().close();
    return w.str();
}

/// A PutObjectAcl or PutBucketAcl body. The owner must be the resource's
/// (S3 refuses a change of owner).
[[nodiscard]] inline auto parse_acl_xml(std::string_view body, const std::string& owner)
    -> aws_rest_xml::result<access_control_list> {
    auto doc = aws_rest_xml::parse_xml(body);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "AccessControlPolicy") {
        return aws_rest_xml::errors::malformed_xml("root is not AccessControlPolicy");
    }
    access_control_list acl{owner, {}};
    if (const auto* o = doc->child("Owner")) {
        if (auto id = o->child_text("ID"); id && *id != owner) {
            return access_denied();
        }
    }
    const auto* list = doc->child("AccessControlList");
    if (list == nullptr) {
        return aws_rest_xml::errors::malformed_xml("no AccessControlList");
    }
    for (const auto* g : list->children_named("Grant")) {
        const auto* grantee = g->child("Grantee");
        const auto perm = parse_permission(g->child_text("Permission").value_or(""));
        if (grantee == nullptr || !perm) {
            return aws_rest_xml::errors::malformed_xml("a Grant needs a Grantee and a Permission");
        }
        std::string type;
        for (const auto& [k, v] : grantee->attributes) {
            if (k == "type" || k.ends_with(":type")) {
                type = v;
            }
        }
        if (type == "CanonicalUser") {
            auto id = grantee->child_text("ID");
            if (!id || id->empty()) {
                return aws_rest_xml::errors::malformed_xml("a CanonicalUser grantee needs an ID");
            }
            acl.grants.push_back({false, *id, *perm});
        } else if (type == "Group") {
            auto uri = grantee->child_text("URI").value_or("");
            if (uri != all_users_uri && uri != authenticated_users_uri && uri != log_delivery_uri) {
                return invalid_argument("Invalid group uri");
            }
            acl.grants.push_back({true, uri, *perm});
        } else if (type == "AmazonCustomerByEmail") {
            return aws_rest_xml::errors::make(
                400, "UnresolvableGrantByEmailAddress",
                "The email address you provided does not match any account on record.");
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown grantee type");
        }
    }
    return acl;
}

// ---------------------------------------------------------------------------
// Block Public Access
// ---------------------------------------------------------------------------

struct public_access_block {
    bool block_public_acls = true;
    bool ignore_public_acls = true;
    bool block_public_policy = true;
    bool restrict_public_buckets = true;

    friend auto operator==(const public_access_block&, const public_access_block&)
        -> bool = default;
};

/// What applies: the account's setting OR'd with the bucket's.
[[nodiscard]] inline auto effective(const public_access_block& account,
                                    const public_access_block& bucket) -> public_access_block {
    return {account.block_public_acls || bucket.block_public_acls,
            account.ignore_public_acls || bucket.ignore_public_acls,
            account.block_public_policy || bucket.block_public_policy,
            account.restrict_public_buckets || bucket.restrict_public_buckets};
}

[[nodiscard]] inline auto public_access_block_xml(const public_access_block& b) -> std::string {
    auto w = aws_rest_xml::document("PublicAccessBlockConfiguration");
    w.boolean("BlockPublicAcls", b.block_public_acls)
        .boolean("IgnorePublicAcls", b.ignore_public_acls)
        .boolean("BlockPublicPolicy", b.block_public_policy)
        .boolean("RestrictPublicBuckets", b.restrict_public_buckets);
    w.close();
    return w.str();
}

/// A PutPublicAccessBlock body; absent members are false, as in S3.
[[nodiscard]] inline auto parse_public_access_block(std::string_view body)
    -> aws_rest_xml::result<public_access_block> {
    auto doc = aws_rest_xml::parse_xml(body);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "PublicAccessBlockConfiguration") {
        return aws_rest_xml::errors::malformed_xml("root is not PublicAccessBlockConfiguration");
    }
    public_access_block b{false, false, false, false};
    const auto flag = [&](std::string_view name, bool& out) -> bool {
        auto v = doc->child_text(name);
        if (!v) {
            return true;
        }
        if (*v == "true" || *v == "TRUE" || *v == "True") {
            out = true;
            return true;
        }
        return *v == "false" || *v == "FALSE" || *v == "False";
    };
    if (!flag("BlockPublicAcls", b.block_public_acls) ||
        !flag("IgnorePublicAcls", b.ignore_public_acls) ||
        !flag("BlockPublicPolicy", b.block_public_policy) ||
        !flag("RestrictPublicBuckets", b.restrict_public_buckets)) {
        return aws_rest_xml::errors::malformed_xml("a flag is not true or false");
    }
    return b;
}

// ---------------------------------------------------------------------------
// Bucket policies: well-formedness and publicness
// ---------------------------------------------------------------------------

namespace access_detail {

[[nodiscard]] inline auto strings_of(const boost::json::value& v) -> std::vector<std::string> {
    std::vector<std::string> out;
    if (v.is_string()) {
        out.emplace_back(v.as_string());
    } else if (v.is_array()) {
        for (const auto& e : v.as_array()) {
            if (e.is_string()) {
                out.emplace_back(e.as_string());
            } else {
                out.emplace_back("*");  // not a string: assume the worst
            }
        }
    } else {
        out.emplace_back("*");
    }
    return out;
}

/// Whether a Principal element names anyone through a wildcard.
[[nodiscard]] inline auto wildcard_principal(const boost::json::value& p) -> bool {
    if (p.is_string()) {
        return p.as_string().find('*') != boost::json::string::npos;
    }
    if (!p.is_object()) {
        return true;
    }
    for (const auto& [type, values] : p.as_object()) {
        if (type != "AWS" && type != "CanonicalUser") {
            continue;  // Service and Federated principals are not public
        }
        for (const auto& v : strings_of(values)) {
            if (v.find('*') != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

/// Whether a CIDR is narrow enough to count as restricting.
[[nodiscard]] inline auto narrow_cidr(std::string_view cidr) -> bool {
    const auto slash = cidr.find('/');
    const bool v6 = cidr.find(':') != std::string_view::npos;
    if (slash == std::string_view::npos) {
        return true;  // one address
    }
    int bits = 0;
    const auto digits = cidr.substr(slash + 1);
    if (digits.empty() || digits.size() > 3) {
        return false;
    }
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return false;
        }
        bits = bits * 10 + (c - '0');
    }
    return v6 ? bits >= 32 : bits >= 8;
}

/// Whether a Condition element fixes a restricting key to values without
/// wildcards.
[[nodiscard]] inline auto restricting_condition(const boost::json::value& cond) -> bool {
    static constexpr std::array<std::string_view, 12> keys{
        "aws:sourcearn",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:sourceaccount",
        "aws:sourceowner",
        "aws:principalarn",
        "aws:principalaccount",
        "aws:principalorgid",
        "aws:userid",
        "s3:dataaccesspointarn",
        "s3:dataaccesspointaccount",
        "aws:principalorgpaths",
    };
    static constexpr std::array<std::string_view, 6> fixing_ops{
        "stringequals", "stringequalsignorecase", "arnequals", "stringlike", "arnlike", "ipaddress",
    };
    if (!cond.is_object()) {
        return false;
    }
    for (const auto& [op_raw, body] : cond.as_object()) {
        auto op = authz_detail::lower(std::string_view(op_raw.data(), op_raw.size()));
        for (std::string_view prefix : {"foranyvalue:", "forallvalues:"}) {
            if (op.starts_with(prefix)) {
                op.erase(0, prefix.size());
            }
        }
        if (std::ranges::find(fixing_ops, op) == fixing_ops.end() || !body.is_object()) {
            continue;  // includes every ...IfExists form
        }
        for (const auto& [key_raw, values] : body.as_object()) {
            const auto key = authz_detail::lower(std::string_view(key_raw.data(), key_raw.size()));
            const auto vals = strings_of(values);
            if (vals.empty()) {
                continue;
            }
            if (key == "aws:sourceip" && op == "ipaddress") {
                if (std::ranges::all_of(vals,
                                        [](const std::string& v) { return narrow_cidr(v); })) {
                    return true;
                }
                continue;
            }
            if (std::ranges::find(keys, key) == keys.end() || op == "ipaddress") {
                continue;
            }
            const bool fixed = std::ranges::none_of(vals, [](const std::string& v) {
                return v.find('*') != std::string::npos || v.find('?') != std::string::npos;
            });
            if (fixed) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace access_detail

/// Whether a (well-formed) bucket policy is public by S3's rule.
[[nodiscard]] inline auto policy_is_public(std::string_view json) -> bool {
    boost::system::error_code ec;
    const auto v = boost::json::parse(json, ec);
    if (ec || !v.is_object()) {
        return false;  // refused as malformed elsewhere; grants nothing
    }
    const auto* st = v.as_object().if_contains("Statement");
    if (st == nullptr) {
        return false;
    }
    std::vector<const boost::json::value*> statements;
    if (st->is_array()) {
        for (const auto& s : st->as_array()) {
            statements.push_back(&s);
        }
    } else {
        statements.push_back(st);
    }
    for (const auto* s : statements) {
        if (!s->is_object()) {
            continue;
        }
        const auto& o = s->as_object();
        const auto* effect = o.if_contains("Effect");
        if (effect == nullptr || !effect->is_string() || effect->as_string() != "Allow") {
            continue;
        }
        bool wildcard = o.contains("NotPrincipal");
        if (const auto* p = o.if_contains("Principal")) {
            wildcard = wildcard || access_detail::wildcard_principal(*p);
        }
        if (!wildcard) {
            continue;
        }
        const auto* cond = o.if_contains("Condition");
        if (cond == nullptr || !access_detail::restricting_condition(*cond)) {
            return true;
        }
    }
    return false;
}

/// A PutBucketPolicy body: JSON with a Statement, at most 20 KB, and every
/// statement naming a Principal (a bucket policy is a resource policy).
/// Deeper checks (actions, resources, condition operators) are the IAM
/// parser's when the policy is evaluated.
[[nodiscard]] inline auto check_bucket_policy(std::string_view json)
    -> std::optional<aws_rest_xml::error> {
    const auto malformed = [](std::string m) {
        return aws_rest_xml::errors::make(400, "MalformedPolicy", std::move(m));
    };
    if (json.size() > 20 * 1024) {
        return aws_rest_xml::errors::make(400, "PolicyTooLarge",
                                          "Policies must be less than 20 KB");
    }
    boost::system::error_code ec;
    const auto v = boost::json::parse(json, ec);
    if (ec || !v.is_object()) {
        return malformed("This policy contains invalid Json");
    }
    const auto* st = v.as_object().if_contains("Statement");
    if (st == nullptr || !(st->is_array() || st->is_object())) {
        return malformed("Missing required field Statement");
    }
    const auto check = [&](const boost::json::value& s) -> std::optional<aws_rest_xml::error> {
        if (!s.is_object()) {
            return malformed("Statement is not an object");
        }
        const auto& o = s.as_object();
        if (!o.contains("Principal") && !o.contains("NotPrincipal")) {
            return malformed("Missing required field Principal");
        }
        if (!o.contains("Effect")) {
            return malformed("Missing required field Effect");
        }
        if (!o.contains("Action") && !o.contains("NotAction")) {
            return malformed("Missing required field Action");
        }
        return std::nullopt;
    };
    if (st->is_array()) {
        if (st->as_array().empty()) {
            return malformed("Missing required field Statement");
        }
        for (const auto& s : st->as_array()) {
            if (auto e = check(s)) {
                return e;
            }
        }
        return std::nullopt;
    }
    return check(*st);
}

// ---------------------------------------------------------------------------
// Checks on writes that change access
// ---------------------------------------------------------------------------

/// An ACL set by PutObject, CreateBucket, PutObjectAcl or PutBucketAcl.
[[nodiscard]] inline auto check_acl_write(object_ownership ownership,
                                          const public_access_block& bpa,
                                          const access_control_list& acl,
                                          const std::string& bucket_owner)
    -> std::optional<aws_rest_xml::error> {
    if (ownership == object_ownership::bucket_owner_enforced) {
        // Only ACLs that grant nothing beyond the bucket owner are taken.
        const bool owner_only_acl = std::ranges::all_of(acl.grants, [&](const acl_grant& g) {
            return !g.group && g.grantee == bucket_owner &&
                   g.permission == acl_permission::full_control;
        });
        if (!owner_only_acl) {
            return acl_not_supported();
        }
    }
    if (bpa.block_public_acls && is_public(acl)) {
        return access_denied();
    }
    return std::nullopt;
}

/// A bucket policy about to be stored.
[[nodiscard]] inline auto check_policy_write(const public_access_block& bpa, std::string_view json)
    -> std::optional<aws_rest_xml::error> {
    if (auto e = check_bucket_policy(json)) {
        return e;
    }
    if (bpa.block_public_policy && policy_is_public(json)) {
        return access_denied();
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// The permission an ACL must grant for an action, and whether it is the
/// object's ACL (else the bucket's). Nothing for actions ACLs do not cover.
struct acl_need {
    acl_permission permission;
    bool on_object;
};

[[nodiscard]] inline auto acl_need_for(std::string_view action) -> std::optional<acl_need> {
    if (action.starts_with("s3:")) {
        action.remove_prefix(3);
    }
    if (action == "GetObject" || action == "GetObjectVersion" || action == "GetObjectTorrent" ||
        action == "GetObjectVersionTorrent") {
        return acl_need{acl_permission::read, true};
    }
    if (action == "GetObjectAcl" || action == "GetObjectVersionAcl") {
        return acl_need{acl_permission::read_acp, true};
    }
    if (action == "PutObjectAcl" || action == "PutObjectVersionAcl") {
        return acl_need{acl_permission::write_acp, true};
    }
    if (action == "ListBucket" || action == "ListBucketVersions" ||
        action == "ListBucketMultipartUploads") {
        return acl_need{acl_permission::read, false};
    }
    if (action == "PutObject" || action == "DeleteObject" || action == "DeleteObjectVersion") {
        return acl_need{acl_permission::write, false};
    }
    if (action == "GetBucketAcl") {
        return acl_need{acl_permission::read_acp, false};
    }
    if (action == "PutBucketAcl") {
        return acl_need{acl_permission::write_acp, false};
    }
    return std::nullopt;
}

/// What the decision needs to know about the bucket (and object) a check
/// names.
struct access_context {
    std::string bucket_owner;
    object_ownership ownership = object_ownership::bucket_owner_enforced;
    public_access_block bpa;  ///< effective (account OR bucket)
    std::optional<std::string> bucket_policy;
    const access_control_list* bucket_acl = nullptr;
    const access_control_list* object_acl = nullptr;
    // Request facts for the global condition keys.
    std::string source_ip;
    std::string user_agent;
    std::string region;
    bool secure_transport = true;
};

namespace access_detail {

[[nodiscard]] inline auto grants(const access_control_list& acl, acl_permission need,
                                 const std::string& account, bool authenticated, bool ignore_public)
    -> bool {
    return std::ranges::any_of(acl.grants, [&](const acl_grant& g) {
        if (g.permission != need && g.permission != acl_permission::full_control) {
            return false;
        }
        if (ignore_public && is_public(g)) {
            return false;
        }
        if (g.group) {
            return g.grantee == all_users_uri ||
                   (authenticated && g.grantee == authenticated_users_uri);
        }
        return authenticated && g.grantee == account;
    });
}

}  // namespace access_detail

/// Whether `auth` may make `check`, or the error to answer with.
template<aws_auth::aws_request_authorizer A>
[[nodiscard]] auto authorize_check(A& authorizer, const authenticated& auth,
                                   const authz_check& check, const access_context& ctx)
    -> std::optional<aws_rest_xml::error> {
    const bool anonymous = !auth.who.has_value();
    const std::string account = anonymous ? std::string{} : auth.who->account;
    const bool policy_public = ctx.bucket_policy && policy_is_public(*ctx.bucket_policy);
    const bool policy_usable = ctx.bucket_policy && !(ctx.bpa.restrict_public_buckets &&
                                                      policy_public && account != ctx.bucket_owner);

    aws_auth::authz_request req;
    req.action = check.action;
    req.resource = check.resource;
    req.resource_account = ctx.bucket_owner;
    req.keys = check.keys;
    if (policy_usable) {
        req.resource_policy = ctx.bucket_policy;
    }
    req.source_ip = ctx.source_ip;
    req.user_agent = ctx.user_agent;
    req.region = ctx.region;
    req.secure_transport = ctx.secure_transport;

    if (anonymous) {
        if constexpr (aws_auth::aws_anonymous_authorizer<A>) {
            if (policy_usable) {
                const auto d = authorizer.authorize_anonymous(req);
                if (d.explicit_deny) {
                    return access_denied();
                }
                if (d.allowed) {
                    return std::nullopt;
                }
            }
        }
    } else {
        const auto d = authorizer.authorize(*auth.who, req);
        if (d.explicit_deny) {
            return access_denied();
        }
        if (d.allowed) {
            return std::nullopt;
        }
    }

    // ACLs, where Object Ownership leaves them on.
    if (ctx.ownership == object_ownership::bucket_owner_enforced) {
        return access_denied();
    }
    const auto need = acl_need_for(check.action);
    if (!need) {
        return access_denied();
    }
    const auto* acl = need->on_object ? ctx.object_acl : ctx.bucket_acl;
    if (acl == nullptr || !access_detail::grants(*acl, need->permission, account, !anonymous,
                                                 ctx.bpa.ignore_public_acls)) {
        return access_denied();
    }
    if (anonymous) {
        return std::nullopt;
    }
    // The ACL is the resource side; the caller's own account must allow
    // the action too: its identity policies, as a request in its own
    // account with no resource policy.
    auto own = req;
    own.resource_account = account;
    own.resource_policy.reset();
    const auto d = authorizer.authorize(*auth.who, own);
    return d.allowed ? std::nullopt : std::optional<aws_rest_xml::error>(access_denied());
}

/// Every check, each against the context of the bucket it names (a copy's
/// source is another bucket's). `context_for` returns null for a bucket
/// that does not exist, which is refused as AccessDenied here; the handler
/// decides between that and NoSuchBucket before asking.
template<aws_auth::aws_request_authorizer A>
[[nodiscard]] auto authorize_all(
    A& authorizer, const authenticated& auth, const std::vector<authz_check>& checks,
    const std::function<const access_context*(const authz_check&)>& context_for)
    -> std::optional<aws_rest_xml::error> {
    if (checks.empty()) {
        return access_denied();
    }
    for (const auto& c : checks) {
        const auto* ctx = context_for(c);
        if (ctx == nullptr) {
            return access_denied();
        }
        if (auto e = authorize_check(authorizer, auth, c, *ctx)) {
            return e;
        }
    }
    return std::nullopt;
}

}  // namespace kythira::s3
