// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_versioning.hpp
/// @brief Versioning and object lock operations
///        (.kiro/specs/s3-compatible-storage/ task 10, Requirement 8).
///
/// | Operation | Request |
/// |---|---|
/// | GetBucketVersioning, PutBucketVersioning | `?versioning` |
/// | ListObjectVersions | `GET /b?versions` |
/// | GetObjectLockConfiguration, PutObjectLockConfiguration | `?object-lock` |
/// | GetObjectRetention, PutObjectRetention | `/b/k?retention` |
/// | GetObjectLegalHold, PutObjectLegalHold | `/b/k?legal-hold` |
///
/// Versioning states, `null` versions and delete markers are the index's
/// (task 4); these handlers are the wire. A bucket never versioned
/// answers an empty `<VersioningConfiguration/>`. MFA delete is not
/// supported: `MfaDelete` `Enabled` is refused with `NotImplemented`,
/// since no MFA device can be presented.
///
/// Object lock needs versioning `Enabled` (or the bucket created with
/// `x-amz-bucket-object-lock-enabled`) and cannot be turned off. The
/// index enforces retention and legal hold on every removal (see
/// `s3_object_lock.hpp`); PutObjectRetention can extend any retention
/// and can shorten or remove GOVERNANCE retention only with
/// `x-amz-bypass-governance-retention`, COMPLIANCE never.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_listings.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_object_lock.hpp>
#include <kythira/s3/s3_objects.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <optional>
#include <string>
#include <utility>

namespace kythira::s3 {

namespace versioning_detail {

[[nodiscard]] inline auto missing_lock() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest",
                                      "Bucket is missing Object Lock Configuration");
}

[[nodiscard]] inline auto no_object_lock_configuration() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(404, "NoSuchObjectLockConfiguration",
                                      "The specified object does not have a ObjectLock "
                                      "configuration");
}

[[nodiscard]] inline auto integrity_required() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        400, "InvalidRequest",
        "Missing required header for this request: Content-MD5 OR x-amz-checksum-*");
}

/// Propose one object lock change.
template<metadata_access M>
[[nodiscard]] auto set_lock(handler_context<M>& ctx, const s3_request& req, const bucket_state& b,
                            std::string name, std::optional<std::string> document)
    -> handler_result {
    const auto version_id = req.query.get("versionId");
    if (version_id && !object_detail::valid_version_id(*version_id)) {
        return invalid_argument("Invalid version id specified");
    }
    index_command c;
    c.op = index_command::kind::set_object_lock;
    c.now_ms = ctx.now_ms();
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.version_id = version_id;
    c.config_name = std::move(name);
    c.document = std::move(document);
    c.bypass_governance = bypass_governance(req.headers);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "NoSuchKey") {
            return object_detail::no_such_key(req.resource.key);
        }
        return from_index(r);
    }
    return s3_response{};
}

}  // namespace versioning_detail

// ---------------------------------------------------------------------------
// Bucket versioning
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_bucket_versioning(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto w = aws_rest_xml::document("VersioningConfiguration");
    if (b.desc.versioning == versioning_state::enabled) {
        w.element("Status", "Enabled");
    } else if (b.desc.versioning == versioning_state::suspended) {
        w.element("Status", "Suspended");
    }
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto put_bucket_versioning(handler_context<M>& ctx, const s3_request& req,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    if (!doc || doc->name != "VersioningConfiguration") {
        return lock_detail::malformed();
    }
    if (doc->child_text("MfaDelete").value_or("Disabled") == "Enabled") {
        return not_implemented();
    }
    const auto status = doc->child_text("Status");
    if (!status) {
        return s3_response{};  // S3 leaves the state as it is
    }
    if (*status != "Enabled" && b.replication) {
        // Replication needs every version kept (task 14).
        return aws_rest_xml::errors::make(
            409, "InvalidBucketState",
            "A replication configuration is present on this bucket, so you cannot change the "
            "versioning state. To change the versioning state, first delete the replication "
            "configuration.");
    }
    if (auto e = bucket_detail::store(ctx, b, "versioning", status)) {
        return *e;
    }
    return s3_response{};
}

// ---------------------------------------------------------------------------
// ListObjectVersions
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto list_object_versions(handler_context<M>& ctx, const s3_request& req,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace listing_detail;
    auto p = params(req);
    if (!p) {
        return p.error();
    }
    const auto key_marker = req.query.get("key-marker").value_or("");
    const auto version_marker = req.query.get("version-id-marker").value_or("");
    if (!version_marker.empty()) {
        if (key_marker.empty()) {
            return invalid_argument(
                "A version-id marker cannot be specified without a key "
                "marker.");
        }
        if (!object_detail::valid_version_id(version_marker)) {
            return invalid_argument("Invalid version id specified");
        }
    }
    const auto l = ctx.meta.list_versions(b.desc.id, p->prefix, p->delimiter, key_marker,
                                          version_marker, p->max_keys);
    auto w = aws_rest_xml::document("ListVersionsResult");
    w.element("Name", b.client_name)
        .element("Prefix", enc(*p, p->prefix))
        .element("KeyMarker", enc(*p, key_marker))
        .element("VersionIdMarker", version_marker);
    if (l.truncated) {
        w.element("NextKeyMarker", enc(*p, l.next_key_marker))
            .element("NextVersionIdMarker", l.next_version_id_marker);
    }
    w.element("MaxKeys", std::to_string(p->max_keys));
    if (!p->delimiter.empty()) {
        w.element("Delimiter", enc(*p, p->delimiter));
    }
    w.boolean("IsTruncated", l.truncated);
    if (p->url) {
        w.element("EncodingType", "url");
    }
    for (const auto& e : l.versions) {
        const auto& v = e.version;
        const auto modified = aws_rest_xml::iso8601_ms(bucket_detail::time_of(v.last_modified_ms));
        if (v.delete_marker) {
            w.open("DeleteMarker")
                .element("Key", enc(*p, v.key))
                .element("VersionId", v.version_id())
                .boolean("IsLatest", e.is_latest)
                .element("LastModified", modified);
            w.open("Owner").element("ID", v.owner).element("DisplayName", v.owner).close();
            w.close();
            continue;
        }
        w.open("Version")
            .element("Key", enc(*p, v.key))
            .element("VersionId", v.version_id())
            .boolean("IsLatest", e.is_latest)
            .element("LastModified", modified)
            .element("ETag", object_detail::quote(v.content.etag))
            .element("Size", std::to_string(v.content.size()));
        w.open("Owner").element("ID", v.owner).element("DisplayName", v.owner).close();
        w.element("StorageClass", v.content.storage_class);
        for (auto a : all_checksum_algorithms) {
            if (v.content.system_metadata.contains(checksum_header(a))) {
                w.element("ChecksumAlgorithm", to_string(a));
                if (auto t = v.content.system_metadata.find("x-amz-checksum-type");
                    t != v.content.system_metadata.end()) {
                    w.element("ChecksumType", t->second);
                }
                break;
            }
        }
        w.close();
    }
    for (const auto& cp : l.common_prefixes) {
        w.open("CommonPrefixes").element("Prefix", enc(*p, cp)).close();
    }
    w.close();
    return xml_response(w.str());
}

// ---------------------------------------------------------------------------
// Bucket object lock configuration
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_object_lock_configuration(handler_context<M>& /*ctx*/,
                                                 const s3_request& /*req*/,
                                                 const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.object_lock) {
        return aws_rest_xml::errors::make(404, "ObjectLockConfigurationNotFoundError",
                                          "Object Lock configuration does not exist for this "
                                          "bucket");
    }
    const auto def = lock_detail::bucket_lock(b);
    auto w = aws_rest_xml::document("ObjectLockConfiguration");
    w.element("ObjectLockEnabled", "Enabled");
    if (!def.mode.empty()) {
        w.open("Rule").open("DefaultRetention").element("Mode", def.mode);
        if (def.days != 0) {
            w.element("Days", std::to_string(def.days));
        } else {
            w.element("Years", std::to_string(def.years));
        }
        w.close().close();
    }
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto put_object_lock_configuration(handler_context<M>& ctx, const s3_request& req,
                                                 const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!lock_detail::has_integrity_header(req.headers)) {
        return versioning_detail::integrity_required();
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto config = lock_detail::parse_lock_configuration(*body);
    if (!config) {
        return config.error();
    }
    if (auto doc = aws_rest_xml::parse_xml(*body);
        !doc || doc->child_text("ObjectLockEnabled") != "Enabled") {
        return lock_detail::malformed();
    }
    if (auto e = bucket_detail::store(ctx, b, "object-lock", *body)) {
        return *e;
    }
    return s3_response{};
}

// ---------------------------------------------------------------------------
// Retention and legal hold
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_object_retention(handler_context<M>& ctx, const s3_request& req,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.object_lock) {
        return versioning_detail::missing_lock();
    }
    auto found = object_detail::find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    const auto lock = lock_state_of(found.version->content.system_metadata);
    if (lock.mode.empty()) {
        return versioning_detail::no_object_lock_configuration();
    }
    auto w = aws_rest_xml::document("Retention");
    w.element("Mode", lock.mode)
        .element("RetainUntilDate", lock_detail::render_date(lock.until_ms));
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto put_object_retention(handler_context<M>& ctx, const s3_request& req,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.object_lock) {
        return versioning_detail::missing_lock();
    }
    if (!lock_detail::has_integrity_header(req.headers)) {
        return versioning_detail::integrity_required();
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    if (!doc || doc->name != "Retention") {
        return lock_detail::malformed();
    }
    const auto mode = doc->child_text("Mode");
    const auto until = doc->child_text("RetainUntilDate");
    if (mode.has_value() != until.has_value()) {
        return lock_detail::malformed();
    }
    std::optional<std::string> document;
    if (mode) {
        if (*mode != "GOVERNANCE" && *mode != "COMPLIANCE") {
            return lock_detail::malformed();
        }
        const auto at = lock_detail::parse_date(*until);
        if (!at) {
            return lock_detail::malformed();
        }
        if (*at <= ctx.now_ms()) {
            return invalid_argument("The retain until date must be in the future!");
        }
        document = *mode + " " + std::to_string(*at);
    }
    return versioning_detail::set_lock(ctx, req, b, "retention", std::move(document));
}

template<metadata_access M>
[[nodiscard]] auto get_object_legal_hold(handler_context<M>& ctx, const s3_request& req,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.object_lock) {
        return versioning_detail::missing_lock();
    }
    auto found = object_detail::find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    const auto& m = found.version->content.system_metadata;
    const auto it = m.find(std::string(legal_hold_metadata));
    if (it == m.end()) {
        return versioning_detail::no_object_lock_configuration();
    }
    auto w = aws_rest_xml::document("LegalHold");
    w.element("Status", it->second);
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto put_object_legal_hold(handler_context<M>& ctx, const s3_request& req,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.desc.object_lock) {
        return versioning_detail::missing_lock();
    }
    if (!lock_detail::has_integrity_header(req.headers)) {
        return versioning_detail::integrity_required();
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    const auto status = doc && doc->name == "LegalHold" ? doc->child_text("Status") : std::nullopt;
    if (!status || (*status != "ON" && *status != "OFF")) {
        return lock_detail::malformed();
    }
    return versioning_detail::set_lock(ctx, req, b, "legal-hold", status);
}

}  // namespace kythira::s3
