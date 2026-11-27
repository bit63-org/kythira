// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_authz.hpp
/// @brief What an S3 request asks the authorizer: the `s3` actions it
///        needs, the resources they act on and the condition keys it
///        supplies (.kiro/specs/s3-compatible-storage/ task 6, Requirement
///        5.1).
///
/// S3's operations and actions are not one to one, and which actions a
/// request needs depends on the request. AWS's service reference lists, per
/// operation, every action S3 may check (`k_operation_actions` in the
/// generated `s3_actions.hpp`); `checks_for` picks those this request needs,
/// following S3's documented behaviour:
///
/// - One primary action per operation: the same-named action where there is
///   one (`PutObject`), else the operation's only action
///   (`CompleteMultipartUpload` is `s3:PutObject`), else the documented one
///   (`HeadObject` and `GetObjectAttributes` are `s3:GetObject`,
///   `ListObjectsV2` is `s3:ListBucket`, `CopyObject` and `UploadPartCopy`
///   are `s3:PutObject` on the destination).
/// - With a `versionId`, the version action where S3 has one
///   (`s3:GetObjectVersion`, `s3:DeleteObjectVersion`,
///   `s3:PutObjectVersionTagging`, ...).
/// - Extra actions for what the request carries: an ACL header adds
///   `s3:PutObjectAcl` (or `s3:PutBucketAcl` on `CreateBucket`), a
///   `x-amz-tagging` header `s3:PutObjectTagging`, object lock headers
///   `s3:PutObjectRetention` and `s3:PutObjectLegalHold`,
///   `x-amz-bypass-governance-retention: true`
///   `s3:BypassGovernanceRetention`; `CreateBucket` with object lock adds
///   `s3:PutBucketObjectLockConfiguration` and `s3:PutBucketVersioning`, and
///   with `x-amz-object-ownership` `s3:PutBucketOwnershipControls`.
/// - A copy also needs `s3:GetObject` (or `s3:GetObjectVersion`) on the
///   source.
///
/// Every action chosen is one the reference lists for the operation, which
/// the tests check for every operation. `DeleteObjects` is checked per key:
/// the front end calls `checks_for` once for each object in the body, with
/// its version in `request_facts::version_id`.
///
/// Each check carries the condition keys its action declares and the
/// request supplies: `s3:x-amz-*` from the same-named header, `s3:prefix`,
/// `s3:delimiter` and `s3:max-keys` from the query (`s3:prefix` is empty
/// when absent, as S3 sets it), `s3:versionid`, `s3:if-match`,
/// `s3:if-none-match`, the object lock headers, request and existing object
/// tags, bucket tags, and the authentication facts (`s3:authType`,
/// `s3:signatureversion`, `s3:signatureAge`, `s3:TlsVersion`,
/// `s3:ResourceAccount`). Global keys (`aws:SourceIp`,
/// `aws:SecureTransport`, ...) are the authorizer's to add.

#include <kythira/s3/s3_actions.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// One action the request needs, on one resource, with its keys.
struct authz_check {
    std::string action;    ///< `s3:GetObject`
    std::string resource;  ///< an ARN, or `*`
    std::vector<std::pair<std::string, std::vector<std::string>>> keys;
};

/// What `checks_for` reads from a request. The front end fills it after
/// routing and authentication.
struct request_facts {
    std::string operation;  ///< the model operation, `PutObject`
    std::string bucket;
    std::string key;
    /// Names in any case, values as received.
    std::vector<std::pair<std::string, std::string>> headers;
    aws_rest_xml::query query;
    /// The version acted on: `DeleteObjects` sets each object's; else the
    /// query's `versionId` counts.
    std::optional<std::string> version_id;
    /// `x-amz-copy-source`, decoded (CopyObject, UploadPartCopy).
    std::string source_bucket;
    std::string source_key;
    std::optional<std::string> source_version_id;
    /// `REST-HEADER`, `REST-QUERY-STRING` or `POST`; empty when anonymous.
    std::string auth_type;
    std::optional<std::int64_t> signature_age_ms;
    std::string tls_version;       ///< `1.3`
    std::string resource_account;  ///< the bucket owner's account
    /// `PutObjectTagging`'s body; else parsed from `x-amz-tagging`.
    std::optional<std::vector<std::pair<std::string, std::string>>> request_tags;
    /// The object's tags, when the front end has read them.
    std::vector<std::pair<std::string, std::string>> existing_tags;
    std::vector<std::pair<std::string, std::string>> bucket_tags;
    std::optional<std::string> location_constraint;  ///< CreateBucket's body
    std::string partition = "aws";
};

namespace authz_detail {

[[nodiscard]] inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    for (auto& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] inline auto header(const request_facts& f, std::string_view name)
    -> std::optional<std::string> {
    for (const auto& [k, v] : f.headers) {
        if (aws_rest_xml::detail::iequals(k, name)) {
            return v;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto has_header(const request_facts& f, std::string_view name) -> bool {
    return header(f, name).has_value();
}

[[nodiscard]] inline auto lists(const operation_actions& op, std::string_view action) -> bool {
    return std::ranges::find(op.actions, action) != op.actions.end();
}

/// The resource kinds an action acts on, from its ARN formats.
struct action_info {
    bool object = false;  ///< `arn:...:s3:::bucket/key`
    bool bucket = false;  ///< `arn:...:s3:::bucket`
    std::vector<std::string> keys;
};

[[nodiscard]] inline auto action_infos() -> const std::map<std::string, action_info, std::less<>>& {
    static const auto table = [] {
        std::map<std::string, action_info, std::less<>> out;
        for (const auto& a : s3_actions().actions) {
            action_info info;
            for (const auto& t : a.resource_templates) {
                if (t == "arn:${Partition}:s3:::${BucketName}/${ObjectName}") {
                    info.object = true;
                } else if (t == "arn:${Partition}:s3:::${BucketName}") {
                    info.bucket = true;
                }
            }
            info.keys = a.condition_keys;
            out.emplace(a.name, std::move(info));
        }
        return out;
    }();
    return table;
}

/// `GetObjectAcl` -> `GetObjectVersionAcl`; empty when S3 has none.
[[nodiscard]] inline auto version_twin(std::string_view action) -> std::string {
    static constexpr std::string_view object = "Object";
    const auto at = action.find(object);
    if (at == std::string_view::npos) {
        return {};
    }
    std::string twin(action.substr(0, at + object.size()));
    twin += "Version";
    twin += action.substr(at + object.size());
    return action_infos().contains(twin) ? twin : std::string{};
}

/// The `x-amz-tagging` header's tags (a URL-encoded query string).
[[nodiscard]] inline auto header_tags(const request_facts& f)
    -> std::optional<std::vector<std::pair<std::string, std::string>>> {
    if (f.request_tags) {
        return f.request_tags;
    }
    const auto h = header(f, "x-amz-tagging");
    if (!h) {
        return std::nullopt;
    }
    auto q = aws_rest_xml::parse_query(*h);
    if (!q) {
        return std::vector<std::pair<std::string, std::string>>{};
    }
    return q->params();
}

}  // namespace authz_detail

/// The ARN of a bucket or object.
[[nodiscard]] inline auto bucket_arn(std::string_view partition, std::string_view bucket)
    -> std::string {
    return "arn:" + std::string(partition) + ":s3:::" + std::string(bucket);
}
[[nodiscard]] inline auto object_arn(std::string_view partition, std::string_view bucket,
                                     std::string_view key) -> std::string {
    return bucket_arn(partition, bucket) + "/" + std::string(key);
}

/// The condition keys `action` declares that the request supplies.
[[nodiscard]] inline auto condition_keys_for(std::string_view action, const request_facts& f)
    -> std::vector<std::pair<std::string, std::vector<std::string>>> {
    using authz_detail::header;
    std::vector<std::pair<std::string, std::vector<std::string>>> out;
    const auto& infos = authz_detail::action_infos();
    const auto it = infos.find(action);
    if (it == infos.end()) {
        return out;
    }
    const auto add = [&](std::string k, std::string v) {
        out.emplace_back(std::move(k), std::vector<std::string>{std::move(v)});
    };
    const auto add_tags = [&](std::string_view prefix,
                              const std::vector<std::pair<std::string, std::string>>& tags) {
        for (const auto& [k, v] : tags) {
            add(std::string(prefix) + k, v);
        }
    };
    for (const auto& key : it->second.keys) {
        if (key.starts_with("s3:x-amz-")) {
            if (auto v = header(f, key.substr(3))) {
                add(key, *v);
            }
        } else if (key == "s3:prefix") {
            add(key, f.query.get("prefix").value_or(""));
        } else if (key == "s3:delimiter" || key == "s3:max-keys") {
            if (auto v = f.query.get(key.substr(3))) {
                add(key, *v);
            }
        } else if (key == "s3:versionid") {
            if (auto v = f.version_id ? f.version_id : f.query.get("versionId")) {
                add(key, *v);
            }
        } else if (key == "s3:if-match" || key == "s3:if-none-match") {
            if (auto v = header(f, key.substr(3))) {
                add(key, *v);
            }
        } else if (key == "s3:object-lock-mode" || key == "s3:object-lock-retain-until-date" ||
                   key == "s3:object-lock-legal-hold") {
            if (auto v = header(f, "x-amz-" + key.substr(3))) {
                add(key, *v);
            }
        } else if (key == "s3:locationconstraint") {
            if (f.location_constraint) {
                add(key, *f.location_constraint);
            }
        } else if (key == "s3:RequestObjectTag/<key>") {
            if (auto tags = authz_detail::header_tags(f)) {
                add_tags("s3:RequestObjectTag/", *tags);
            }
        } else if (key == "s3:RequestObjectTagKeys") {
            if (auto tags = authz_detail::header_tags(f)) {
                std::vector<std::string> names;
                for (const auto& [k, v] : *tags) {
                    names.push_back(k);
                }
                out.emplace_back(key, std::move(names));
            }
        } else if (key == "s3:ExistingObjectTag/<key>") {
            add_tags("s3:ExistingObjectTag/", f.existing_tags);
        } else if (key == "s3:BucketTag/${TagKey}") {
            add_tags("s3:BucketTag/", f.bucket_tags);
        } else if (key == "s3:authType") {
            if (!f.auth_type.empty()) {
                add(key, f.auth_type);
            }
        } else if (key == "s3:signatureversion") {
            if (!f.auth_type.empty()) {
                add(key, "AWS4-HMAC-SHA256");
            }
        } else if (key == "s3:signatureAge") {
            if (f.signature_age_ms) {
                add(key, std::to_string(*f.signature_age_ms));
            }
        } else if (key == "s3:TlsVersion") {
            if (!f.tls_version.empty()) {
                add(key, f.tls_version);
            }
        } else if (key == "s3:ResourceAccount") {
            if (!f.resource_account.empty()) {
                add(key, f.resource_account);
            }
        }
    }
    return out;
}

/// Every check the request needs, primary action first. Empty for an
/// operation the reference does not authorize (refused upstream).
[[nodiscard]] inline auto checks_for(const request_facts& f) -> std::vector<authz_check> {
    using authz_detail::has_header;
    using authz_detail::lists;
    std::vector<authz_check> out;
    const auto* op = find_operation_actions(f.operation);
    if (op == nullptr || op->actions.front().empty()) {
        return out;
    }
    const auto& infos = authz_detail::action_infos();
    const auto resource_for = [&](std::string_view action, std::string_view bucket,
                                  std::string_view key) -> std::string {
        const auto it = infos.find(action);
        if (it == infos.end() || bucket.empty()) {
            return "*";
        }
        if (it->second.object && !key.empty()) {
            return object_arn(f.partition, bucket, key);
        }
        if (it->second.bucket) {
            return bucket_arn(f.partition, bucket);
        }
        return "*";
    };
    const auto add = [&](std::string_view action, std::string_view bucket, std::string_view key) {
        const std::string name(action);
        if (std::ranges::any_of(out,
                                [&](const authz_check& c) { return c.action == "s3:" + name; })) {
            return;
        }
        out.push_back({"s3:" + name, resource_for(name, bucket, key), condition_keys_for(name, f)});
    };

    // The primary action.
    static const std::map<std::string_view, std::string_view, std::less<>> documented{
        {"CopyObject", "PutObject"},          {"DeleteObjects", "DeleteObject"},
        {"GetObjectAttributes", "GetObject"}, {"HeadObject", "GetObject"},
        {"ListObjects", "ListBucket"},        {"ListObjectsV2", "ListBucket"},
        {"UploadPartCopy", "PutObject"},      {"CreateMultipartUpload", "PutObject"},
        {"GetObjectTorrent", "GetObject"},    {"SelectObjectContent", "GetObject"},
    };
    std::string primary;
    if (auto d = documented.find(f.operation); d != documented.end()) {
        primary = d->second;
    } else if (lists(*op, f.operation)) {
        primary = f.operation;
    } else {
        primary = op->actions.front();
    }
    const auto version = f.version_id ? f.version_id : f.query.get("versionId");
    if (version) {
        if (auto twin = authz_detail::version_twin(primary); !twin.empty() && lists(*op, twin)) {
            primary = twin;
        }
    }
    add(primary, f.bucket, f.key);

    // What the request carries.
    const bool acl = has_header(f, "x-amz-acl") || has_header(f, "x-amz-grant-read") ||
                     has_header(f, "x-amz-grant-write") || has_header(f, "x-amz-grant-read-acp") ||
                     has_header(f, "x-amz-grant-write-acp") ||
                     has_header(f, "x-amz-grant-full-control");
    const auto truthy = [&](std::string_view name) {
        auto v = authz_detail::header(f, name);
        return v && authz_detail::lower(*v) == "true";
    };
    if (f.operation == "CreateBucket") {
        if (acl && lists(*op, "PutBucketAcl")) {
            add("PutBucketAcl", f.bucket, {});
        }
        if (truthy("x-amz-bucket-object-lock-enabled")) {
            add("PutBucketObjectLockConfiguration", f.bucket, {});
            add("PutBucketVersioning", f.bucket, {});
        }
        if (has_header(f, "x-amz-object-ownership")) {
            add("PutBucketOwnershipControls", f.bucket, {});
        }
    } else {
        if (acl && lists(*op, "PutObjectAcl") && primary != "PutObjectAcl") {
            add("PutObjectAcl", f.bucket, f.key);
        }
        if (has_header(f, "x-amz-tagging") && lists(*op, "PutObjectTagging") &&
            primary != "PutObjectTagging") {
            add("PutObjectTagging", f.bucket, f.key);
        }
        if ((has_header(f, "x-amz-object-lock-mode") ||
             has_header(f, "x-amz-object-lock-retain-until-date")) &&
            lists(*op, "PutObjectRetention") && primary != "PutObjectRetention") {
            add("PutObjectRetention", f.bucket, f.key);
        }
        if (has_header(f, "x-amz-object-lock-legal-hold") && lists(*op, "PutObjectLegalHold")) {
            add("PutObjectLegalHold", f.bucket, f.key);
        }
        if (truthy("x-amz-bypass-governance-retention") &&
            lists(*op, "BypassGovernanceRetention")) {
            add("BypassGovernanceRetention", f.bucket, f.key);
        }
    }

    // A copy reads its source.
    if ((f.operation == "CopyObject" || f.operation == "UploadPartCopy") &&
        !f.source_bucket.empty()) {
        const std::string_view read = f.source_version_id && lists(*op, "GetObjectVersion")
                                          ? "GetObjectVersion"
                                          : "GetObject";
        out.push_back({"s3:" + std::string(read),
                       object_arn(f.partition, f.source_bucket, f.source_key),
                       condition_keys_for(read, f)});
    }
    return out;
}

}  // namespace kythira::s3
