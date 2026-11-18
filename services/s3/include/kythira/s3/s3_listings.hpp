// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_listings.hpp
/// @brief ListObjects (V1 and V2) and DeleteObjects
///        (.kiro/specs/s3-compatible-storage/ task 7, Requirement 7.1).
///
/// Listings are one range read of the index at the metadata layer's
/// current state, so a listing after an acknowledged write or delete
/// shows it (7.2). V1 pages by `marker`, V2 by an opaque continuation
/// token (the last key or common prefix returned, base64) or
/// `start-after`; both roll keys up at `delimiter` and take at most
/// `max-keys` (S3 caps it at 1,000) items, contents and common prefixes
/// together. `encoding-type=url` URL-encodes every key-like element.
///
/// DeleteObjects takes up to 1,000 keys. Each key is authorized and
/// deleted on its own, so one refused key is an `<Error>` beside the
/// others' `<Deleted>`, as on S3; `Quiet` leaves out the deletions.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_objects.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

namespace listing_detail {

struct list_params {
    std::string prefix;
    std::string delimiter;
    std::size_t max_keys = 1000;
    bool url = false;
};

[[nodiscard]] inline auto params(const s3_request& req) -> aws_rest_xml::result<list_params> {
    list_params p;
    p.prefix = req.query.get("prefix").value_or("");
    p.delimiter = req.query.get("delimiter").value_or("");
    if (auto m = req.query.get("max-keys")) {
        const auto n = compat_detail::to_u64(*m);
        if (!n) {
            auto e = invalid_argument("Provided max-keys not an integer or within integer range");
            e.extra.emplace_back("ArgumentName", "max-keys");
            e.extra.emplace_back("ArgumentValue", *m);
            return e;
        }
        p.max_keys = static_cast<std::size_t>(std::min<std::uint64_t>(*n, 1000));
    }
    if (auto e = req.query.get("encoding-type")) {
        if (*e != "url") {
            auto err = invalid_argument("Invalid Encoding Method specified in Request");
            err.extra.emplace_back("ArgumentName", "encoding-type");
            err.extra.emplace_back("ArgumentValue", *e);
            return err;
        }
        p.url = true;
    }
    return p;
}

[[nodiscard]] inline auto enc(const list_params& p, std::string_view s) -> std::string {
    return p.url ? aws_rest_xml::url_encode_key(s) : std::string(s);
}

inline void contents(aws_query::xml_writer& w, const list_params& p, const object_version& v,
                     bool owner) {
    w.open("Contents")
        .element("Key", enc(p, v.key))
        .element("LastModified",
                 aws_rest_xml::iso8601_ms(bucket_detail::time_of(v.last_modified_ms)))
        .element("ETag", object_detail::quote(v.content.etag))
        .element("Size", std::to_string(v.content.size()));
    if (owner) {
        w.open("Owner").element("ID", v.owner).element("DisplayName", v.owner).close();
    }
    w.element("StorageClass", v.content.storage_class);
    w.close();
}

}  // namespace listing_detail

template<metadata_access M>
[[nodiscard]] auto list_objects(handler_context<M>& ctx, const s3_request& req,
                                const authenticated& /*auth*/, bucket_state& b) -> handler_result {
    using namespace listing_detail;
    auto p = params(req);
    if (!p) {
        return p.error();
    }
    const auto marker = req.query.get("marker").value_or("");
    const auto l = ctx.meta.list_objects(b.desc.id, p->prefix, p->delimiter, marker, p->max_keys);
    auto w = aws_rest_xml::document("ListBucketResult");
    w.element("Name", b.client_name)
        .element("Prefix", enc(*p, p->prefix))
        .element("Marker", enc(*p, marker))
        .element("MaxKeys", std::to_string(p->max_keys));
    if (!p->delimiter.empty()) {
        w.element("Delimiter", enc(*p, p->delimiter));
    }
    w.boolean("IsTruncated", l.truncated);
    if (l.truncated && !p->delimiter.empty()) {
        w.element("NextMarker", enc(*p, l.next_marker));
    }
    if (p->url) {
        w.element("EncodingType", "url");
    }
    for (const auto& v : l.contents) {
        contents(w, *p, v, true);
    }
    for (const auto& cp : l.common_prefixes) {
        w.open("CommonPrefixes").element("Prefix", enc(*p, cp)).close();
    }
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto list_objects_v2(handler_context<M>& ctx, const s3_request& req,
                                   const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace listing_detail;
    auto p = params(req);
    if (!p) {
        return p.error();
    }
    const auto token = req.query.get("continuation-token");
    const auto start_after = req.query.get("start-after").value_or("");
    std::string after = start_after;
    if (token) {
        auto decoded = bucket_detail::unb64(*token);
        if (!decoded || token->empty()) {
            auto e = invalid_argument("The continuation token provided is incorrect");
            e.extra.emplace_back("ArgumentName", "continuation-token");
            return e;
        }
        after = *decoded;
    }
    const bool owner = req.query.get("fetch-owner").value_or("false") == "true";
    const auto l = ctx.meta.list_objects(b.desc.id, p->prefix, p->delimiter, after, p->max_keys);
    auto w = aws_rest_xml::document("ListBucketResult");
    w.element("Name", b.client_name).element("Prefix", enc(*p, p->prefix));
    if (!p->delimiter.empty()) {
        w.element("Delimiter", enc(*p, p->delimiter));
    }
    w.element("MaxKeys", std::to_string(p->max_keys))
        .element("KeyCount", std::to_string(l.contents.size() + l.common_prefixes.size()));
    w.boolean("IsTruncated", l.truncated);
    if (token) {
        w.element("ContinuationToken", *token);
    }
    if (l.truncated) {
        w.element("NextContinuationToken", bucket_detail::b64(l.next_marker));
    }
    if (req.query.has("start-after")) {
        w.element("StartAfter", enc(*p, start_after));
    }
    if (p->url) {
        w.element("EncodingType", "url");
    }
    for (const auto& v : l.contents) {
        contents(w, *p, v, owner);
    }
    for (const auto& cp : l.common_prefixes) {
        w.open("CommonPrefixes").element("Prefix", enc(*p, cp)).close();
    }
    w.close();
    return xml_response(w.str());
}

/// Authorizes deleting one key (and version) of a DeleteObjects request.
using delete_authorizer = std::function<std::optional<aws_rest_xml::error>(
    const std::string& key, const std::optional<std::string>& version)>;

template<metadata_access M>
[[nodiscard]] auto delete_objects(handler_context<M>& ctx, const s3_request& req,
                                  const authenticated& auth, bucket_state& b,
                                  const delete_authorizer& may_delete) -> handler_result {
    if (!req.header("Content-MD5") && !std::ranges::any_of(req.headers, [](const auto& h) {
            return authz_detail::lower(h.first).starts_with("x-amz-checksum-") ||
                   aws_rest_xml::detail::iequals(h.first, "x-amz-sdk-checksum-algorithm");
        })) {
        return aws_rest_xml::errors::make(400, "InvalidRequest",
                                          "Missing required header for this request: Content-MD5");
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    if (auto h = req.header("Content-MD5")) {
        if (bucket_detail::b64(object_detail::md5_raw(*body)) != *h) {
            return aws_rest_xml::errors::make(
                400, "BadDigest", "The Content-MD5 you specified did not match what we received.");
        }
    }
    auto want = requested(req.headers);
    if (!want) {
        return want.error();
    }
    if (auto e = verify(*want, checksum_of(want->algorithm, *body),
                        req.trailers ? req.trailers() : header_list{})) {
        return *e;
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "Delete") {
        return aws_rest_xml::errors::malformed_xml("root is not Delete");
    }
    const auto objects = doc->children_named("Object");
    if (objects.empty() || objects.size() > 1000) {
        return aws_rest_xml::errors::malformed_xml("between 1 and 1000 Object elements");
    }
    const bool quiet = authz_detail::lower(doc->child_text("Quiet").value_or("false")) == "true";

    auto w = aws_rest_xml::document("DeleteResult");
    for (const auto* o : objects) {
        const auto key = o->child_text("Key");
        if (!key || key->empty()) {
            return aws_rest_xml::errors::malformed_xml("an Object needs a Key");
        }
        const auto version = o->child_text("VersionId");
        const auto error = [&](const aws_rest_xml::error& e) {
            w.open("Error").element("Key", *key);
            if (version) {
                w.element("VersionId", *version);
            }
            w.element("Code", e.code).element("Message", e.message).close();
        };
        if (version && !object_detail::valid_version_id(*version)) {
            error(invalid_argument("Invalid version id specified"));
            continue;
        }
        if (auto e = may_delete(*key, version)) {
            error(*e);
            continue;
        }
        index_command c;
        c.op = index_command::kind::delete_object;
        c.now_ms = ctx.now_ms();
        c.owner = auth.who ? auth.who->account : b.desc.owner;
        c.target = ref_of(b.desc);
        c.key = *key;
        c.version_id = version;
        const auto r = ctx.meta.propose(c);
        if (!r.ok()) {
            error(from_index(r));
            continue;
        }
        if (quiet) {
            continue;
        }
        w.open("Deleted").element("Key", *key);
        if (version) {
            w.element("VersionId", *version);
        }
        if (r.delete_marker) {
            w.element("DeleteMarker", "true");
            if (!version) {
                w.element("DeleteMarkerVersionId", r.version_id);
            }
        }
        w.close();
    }
    w.close();
    return xml_response(w.str());
}

}  // namespace kythira::s3
