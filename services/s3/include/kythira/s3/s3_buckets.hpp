// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_buckets.hpp
/// @brief Bucket operations (.kiro/specs/s3-compatible-storage/ task 7,
///        Requirements 6.1-6.3; the access sub-resources of task 6,
///        Requirements 5.2-5.4).
///
/// Create, delete, head, list (with prefix and continuation), location,
/// and the sub-resources this task owns: ACL, ownership controls, public
/// access block, policy and its status, tagging, logging (accepted and
/// stored; Kythira writes no access logs) and request payment (always
/// `BucketOwner`). Each handler runs after authentication and the access
/// check, and answers as S3 does, down to the error for a sub-resource
/// that was never set.

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_auth.hpp>
#include <kythira/s3/s3_compat.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_metadata.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

using handler_result = aws_rest_xml::result<s3_response>;

namespace bucket_detail {

[[nodiscard]] inline auto too_big() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "MaxMessageLengthExceeded", "Your request was too big.");
}

template<metadata_access M>
[[nodiscard]] auto document(const handler_context<M>& ctx, const s3_request& req)
    -> aws_rest_xml::result<std::string> {
    return read_all(req.body, ctx.options.max_document_bytes, too_big());
}

[[nodiscard]] inline auto no_content() -> s3_response {
    s3_response r;
    r.status = 204;
    return r;
}

[[nodiscard]] inline auto time_of(std::uint64_t ms) -> std::chrono::system_clock::time_point {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

/// Set or delete one sub-resource.
template<metadata_access M>
[[nodiscard]] auto store(handler_context<M>& ctx, const bucket_state& b, std::string name,
                         std::optional<std::string> doc) -> std::optional<aws_rest_xml::error> {
    index_command c;
    c.op = index_command::kind::put_bucket_config;
    c.now_ms = ctx.now_ms();
    c.bucket = b.desc.name;
    c.config_name = std::move(name);
    c.document = std::move(doc);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        return from_index(r);
    }
    return std::nullopt;
}

[[nodiscard]] inline auto invalid_tag(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidTag", std::move(message));
}

[[nodiscard]] inline auto b64(std::string_view s) -> std::string {
    return aws_json::base64_encode(std::as_bytes(std::span(s.data(), s.size())));
}

[[nodiscard]] inline auto unb64(std::string_view s) -> std::optional<std::string> {
    auto bytes = aws_json::base64_decode(s);
    if (!bytes) {
        return std::nullopt;
    }
    std::string out(bytes->size(), '\0');
    std::ranges::transform(*bytes, out.begin(), [](std::byte b) { return static_cast<char>(b); });
    return out;
}

}  // namespace bucket_detail

/// S3's tag rules: at most `max` tags, keys 1-128 and values 0-256
/// characters, no `aws:` keys, no key twice.
[[nodiscard]] inline auto check_tags(const std::vector<std::pair<std::string, std::string>>& tags,
                                     std::size_t max) -> std::optional<aws_rest_xml::error> {
    using bucket_detail::invalid_tag;
    if (tags.size() > max) {
        return aws_rest_xml::errors::make(
            400, max == 10 ? "BadRequest" : "InvalidTag",
            "Object tags cannot be greater than " + std::to_string(max));
    }
    std::set<std::string, std::less<>> seen;
    for (const auto& [k, v] : tags) {
        if (k.empty() || k.size() > 128) {
            return invalid_tag("The TagKey you have provided is invalid");
        }
        if (v.size() > 256) {
            return invalid_tag("The TagValue you have provided is invalid");
        }
        if (k.starts_with("aws:")) {
            return invalid_tag("Your TagKey cannot be prefixed with aws:");
        }
        if (!seen.insert(k).second) {
            return invalid_tag("Cannot provide multiple Tags with the same key");
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto tagging_xml(const std::vector<std::pair<std::string, std::string>>& tags)
    -> std::string {
    auto w = aws_rest_xml::document("Tagging");
    w.open("TagSet");
    for (const auto& [k, v] : tags) {
        w.open("Tag").element("Key", k).element("Value", v).close();
    }
    w.close().close();
    return w.str();
}

// ---------------------------------------------------------------------------
// Service-level operations
// ---------------------------------------------------------------------------

/// CreateBucket. The bucket starts with the cluster's default ownership
/// and Block Public Access, or the request's `x-amz-object-ownership`, and
/// the ACL its headers ask for (which ownership must allow).
template<metadata_access M>
[[nodiscard]] auto create_bucket(handler_context<M>& ctx, const s3_request& req,
                                 const authenticated& auth) -> handler_result {
    const auto& account = auth.who->account;
    const auto& opts = ctx.options;

    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    std::optional<std::string> constraint;
    if (!body->empty()) {
        auto doc = aws_rest_xml::parse_xml(*body);
        if (!doc) {
            return doc.error();
        }
        if (doc->name != "CreateBucketConfiguration") {
            return aws_rest_xml::errors::malformed_xml("root is not CreateBucketConfiguration");
        }
        constraint = doc->child_text("LocationConstraint");
    }
    const bool us_east_1 = opts.region == "us-east-1";
    if (constraint && !constraint->empty()) {
        if (us_east_1 && *constraint == "us-east-1") {
            return aws_rest_xml::errors::make(400, "InvalidLocationConstraint",
                                              "The specified location-constraint is not valid");
        }
        if (*constraint != opts.region) {
            return aws_rest_xml::errors::make(
                400, "IllegalLocationConstraintException",
                "The " + *constraint +
                    " location constraint is incompatible for the region specific endpoint this "
                    "request was sent to.");
        }
    } else if (!us_east_1) {
        return aws_rest_xml::errors::make(
            400, "IllegalLocationConstraintException",
            "The unspecified location constraint is incompatible for the region specific "
            "endpoint this request was sent to.");
    }

    auto ownership = opts.profile.default_ownership;
    if (auto h = req.header("x-amz-object-ownership")) {
        auto o = parse_ownership(*h);
        if (!o) {
            return invalid_argument("Invalid x-amz-object-ownership header: " + *h);
        }
        ownership = *o;
    }
    const auto bpa = opts.profile.default_public_access_block;
    auto acl = owner_only(account);
    if (auto a = acl_from_headers(req.headers, account, account)) {
        if (!*a) {
            return a->error();
        }
        acl = std::move(**a);
    }
    if (auto e = check_acl_write(ownership, bpa, acl, account)) {
        if (e->code == "AccessControlListNotSupported") {
            return aws_rest_xml::errors::make(
                400, "InvalidBucketAclWithObjectOwnership",
                "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting");
        }
        return *e;
    }
    bool lock = false;
    if (auto h = req.header("x-amz-bucket-object-lock-enabled")) {
        lock = authz_detail::lower(*h) == "true";
    }

    const auto name = ctx.catalog_name(req.resource.bucket, account);
    if (!ctx.meta.bucket(name)) {
        const auto owned = ctx.meta.list_buckets(account).size();
        if (owned >= opts.profile.max_buckets_per_account) {
            return aws_rest_xml::errors::make(
                400, "TooManyBuckets", "You have attempted to create more buckets than allowed");
        }
    }

    index_command c;
    c.op = index_command::kind::create_bucket;
    c.now_ms = ctx.now_ms();
    c.owner = account;
    c.bucket = name;
    c.region = opts.region;
    c.object_lock = lock;
    c.config["ownership-controls"] = ownership_controls_xml(ownership);
    c.config["public-access-block"] = public_access_block_xml(bpa);
    if (acl != owner_only(account)) {
        c.config["acl"] = acl_xml(acl);
    }
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        return from_index(r);
    }
    s3_response out;
    out.set("Location", "/" + req.resource.bucket);
    return out;
}

/// ListBuckets: the caller's buckets by name, `prefix`, `max-buckets`
/// (1-10,000) and an opaque `continuation-token`.
template<metadata_access M>
[[nodiscard]] auto list_buckets(handler_context<M>& ctx, const s3_request& req,
                                const authenticated& auth) -> handler_result {
    const auto& account = auth.who->account;
    const auto prefix = req.query.get("prefix").value_or("");
    const auto region_filter = req.query.get("bucket-region");
    std::size_t max = 10'000;
    bool paged = false;
    if (auto m = req.query.get("max-buckets")) {
        std::size_t n = 0;
        const bool digits = !m->empty() && m->size() <= 5 &&
                            std::ranges::all_of(*m, [](char ch) { return ch >= '0' && ch <= '9'; });
        if (digits) {
            n = std::stoul(*m);
        }
        if (!digits || n < 1 || n > 10'000) {
            return invalid_argument("max-buckets must be between 1 and 10000");
        }
        max = n;
        paged = true;
    }
    std::string after;
    if (auto t = req.query.get("continuation-token")) {
        auto decoded = bucket_detail::unb64(*t);
        if (!decoded) {
            return invalid_argument("The continuation token provided is incorrect");
        }
        after = *decoded;
        paged = true;
    }

    auto w = aws_rest_xml::document("ListAllMyBucketsResult");
    w.open("Buckets");
    std::string last;
    bool more = false;
    std::size_t n = 0;
    for (const auto& b : ctx.meta.list_buckets(account)) {
        const auto name = ctx.client_name(b.name);
        if (!name.starts_with(prefix) || (!after.empty() && name <= after) ||
            (region_filter && b.region != *region_filter)) {
            continue;
        }
        if (n == max) {
            more = true;
            break;
        }
        w.open("Bucket")
            .element("Name", name)
            .element("CreationDate",
                     aws_rest_xml::iso8601_ms(bucket_detail::time_of(b.created_ms)));
        if (paged || region_filter) {
            w.element("BucketRegion", b.region);
        }
        w.close();
        last = name;
        ++n;
    }
    w.close();
    w.open("Owner").element("ID", account).element("DisplayName", account).close();
    if (more) {
        w.element("ContinuationToken", bucket_detail::b64(last));
    }
    if (!prefix.empty()) {
        w.element("Prefix", prefix);
    }
    w.close();
    return xml_response(w.str());
}

// ---------------------------------------------------------------------------
// Bucket operations
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto delete_bucket(handler_context<M>& ctx, const s3_request& /*req*/,
                                 const authenticated& /*auth*/, bucket_state& b) -> handler_result {
    index_command c;
    c.op = index_command::kind::delete_bucket;
    c.now_ms = ctx.now_ms();
    c.bucket = b.desc.name;
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        auto e = from_index(r);
        if (e.code == "BucketNotEmpty") {
            e.extra.emplace_back("BucketName", b.client_name);
        }
        return e;
    }
    return bucket_detail::no_content();
}

template<metadata_access M>
[[nodiscard]] auto head_bucket(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                               const authenticated& /*auth*/, bucket_state& b) -> handler_result {
    s3_response r;
    r.set("x-amz-bucket-region", b.desc.region);
    r.set("x-amz-access-point-alias", "false");
    return r;
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_location(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                       const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    // us-east-1 is the empty constraint, as on S3.
    aws_query::xml_writer w;
    w.raw(aws_rest_xml::xml_declaration);
    w.open("LocationConstraint", aws_rest_xml::s3_namespace);
    w.raw(b.desc.region == "us-east-1" ? "" : b.desc.region);
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_request_payment(handler_context<M>& /*ctx*/,
                                              const s3_request& /*req*/,
                                              const authenticated& /*auth*/, bucket_state& /*b*/)
    -> handler_result {
    auto w = aws_rest_xml::document("RequestPaymentConfiguration");
    w.element("Payer", "BucketOwner");
    w.close();
    return xml_response(w.str());
}

// ---- logging ---------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_logging(handler_context<M>& ctx, const s3_request& req,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "BucketLoggingStatus") {
        return aws_rest_xml::errors::malformed_xml("root is not BucketLoggingStatus");
    }
    // An empty status turns logging off.
    const bool off = doc->child("LoggingEnabled") == nullptr;
    if (auto e = bucket_detail::store(ctx, b, "logging",
                                      off ? std::nullopt : std::optional<std::string>(*body))) {
        return *e;
    }
    return s3_response{};
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_logging(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto it = b.desc.config.find("logging"); it != b.desc.config.end()) {
        return xml_response(it->second);
    }
    auto w = aws_rest_xml::document("BucketLoggingStatus");
    w.close();
    return xml_response(w.str());
}

// ---- tagging -----------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_tagging(handler_context<M>& ctx, const s3_request& req,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto tags = parse_tagging(*body);
    if (!tags) {
        return tags.error();
    }
    if (auto e = check_tags(*tags, 50)) {
        return *e;
    }
    if (auto e = bucket_detail::store(ctx, b, "tagging", tagging_xml(*tags))) {
        return *e;
    }
    return bucket_detail::no_content();
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_tagging(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.config.contains("tagging")) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchTagSet", "The TagSet does not exist");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    return xml_response(tagging_xml(b.tags));
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_tagging(handler_context<M>& ctx, const s3_request& /*req*/,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "tagging", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

// ---- policy ------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_policy(handler_context<M>& ctx, const s3_request& req,
                                     const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    if (auto e = check_policy_write(b.access.bpa, *body)) {
        return *e;
    }
    if (auto e = bucket_detail::store(ctx, b, "policy", *body)) {
        return *e;
    }
    return bucket_detail::no_content();
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_policy(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                     const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.access.bucket_policy) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchBucketPolicy",
                                            "The bucket policy does not exist");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    s3_response r;
    r.body = *b.access.bucket_policy;
    r.set("Content-Type", "application/json");
    return r;
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_policy(handler_context<M>& ctx, const s3_request& /*req*/,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "policy", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_policy_status(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                            const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.access.bucket_policy) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchBucketPolicy",
                                            "The bucket policy does not exist");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    auto w = aws_rest_xml::document("PolicyStatus");
    w.boolean("IsPublic", policy_is_public(*b.access.bucket_policy));
    w.close();
    return xml_response(w.str());
}

// ---- ACL ---------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_bucket_acl(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                  const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    return xml_response(acl_xml(b.acl));
}

template<metadata_access M>
[[nodiscard]] auto put_bucket_acl(handler_context<M>& ctx, const s3_request& req,
                                  const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    const auto& owner = b.desc.owner;
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto from_headers = acl_from_headers(req.headers, owner, owner);
    if (from_headers && !body->empty()) {
        return aws_rest_xml::errors::make(400, "UnexpectedContent",
                                          "This request does not support content");
    }
    access_control_list acl;
    if (from_headers) {
        if (!*from_headers) {
            return from_headers->error();
        }
        acl = std::move(**from_headers);
    } else if (!body->empty()) {
        auto parsed = parse_acl_xml(*body, owner);
        if (!parsed) {
            return parsed.error();
        }
        acl = std::move(*parsed);
    } else {
        return aws_rest_xml::errors::make(400, "MissingSecurityHeader",
                                          "Your request was missing a required header");
    }
    if (auto e = check_acl_write(b.ownership, b.access.bpa, acl, owner)) {
        return *e;
    }
    if (auto e = bucket_detail::store(ctx, b, "acl", acl_xml(acl))) {
        return *e;
    }
    return s3_response{};
}

// ---- ownership controls ------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_ownership_controls(handler_context<M>& ctx, const s3_request& req,
                                                 const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto o = parse_ownership_controls(*body);
    if (!o) {
        return o.error();
    }
    // ACLs cannot be turned off while the bucket's ACL grants anyone
    // beyond its owner.
    if (*o == object_ownership::bucket_owner_enforced &&
        check_acl_write(*o, {false, false, false, false}, b.acl, b.desc.owner)) {
        return aws_rest_xml::errors::make(
            400, "InvalidBucketAclWithObjectOwnership",
            "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting");
    }
    if (auto e = bucket_detail::store(ctx, b, "ownership-controls", ownership_controls_xml(*o))) {
        return *e;
    }
    return s3_response{};
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_ownership_controls(handler_context<M>& /*ctx*/,
                                                 const s3_request& /*req*/,
                                                 const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.config.contains("ownership-controls")) {
        auto e = aws_rest_xml::errors::make(404, "OwnershipControlsNotFoundError",
                                            "The bucket ownership controls were not found");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    return xml_response(ownership_controls_xml(b.ownership));
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_ownership_controls(handler_context<M>& ctx,
                                                    const s3_request& /*req*/,
                                                    const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "ownership-controls", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

// ---- public access block -----------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_public_access_block(handler_context<M>& ctx, const s3_request& req,
                                           const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto bpa = parse_public_access_block(*body);
    if (!bpa) {
        return bpa.error();
    }
    if (auto e =
            bucket_detail::store(ctx, b, "public-access-block", public_access_block_xml(*bpa))) {
        return *e;
    }
    return s3_response{};
}

template<metadata_access M>
[[nodiscard]] auto get_public_access_block(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                           const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.config.contains("public-access-block")) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchPublicAccessBlockConfiguration",
                                            "The public access block configuration was not found");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    return xml_response(public_access_block_xml(b.bucket_public_access_block));
}

template<metadata_access M>
[[nodiscard]] auto delete_public_access_block(handler_context<M>& ctx, const s3_request& /*req*/,
                                              const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "public-access-block", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

}  // namespace kythira::s3
