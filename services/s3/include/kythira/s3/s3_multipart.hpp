// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_multipart.hpp
/// @brief Multipart upload (.kiro/specs/s3-compatible-storage/ task 9,
///        Requirement 9).
///
/// | Operation | Request |
/// |---|---|
/// | CreateMultipartUpload | `POST /b/k?uploads` |
/// | UploadPart | `PUT /b/k?partNumber=N&uploadId=U` |
/// | UploadPartCopy | the same, with `x-amz-copy-source` |
/// | ListParts | `GET /b/k?uploadId=U` |
/// | ListMultipartUploads | `GET /b?uploads` |
/// | CompleteMultipartUpload | `POST /b/k?uploadId=U` |
/// | AbortMultipartUpload | `DELETE /b/k?uploadId=U` |
///
/// **Bytes.** A part is stored as chunks as it arrives (9.2), exactly as a
/// PUT body is, and the index takes a reference on each. Complete commits
/// one manifest naming the chosen parts' chunks in order; no byte is read
/// or copied. A part written again replaces the old one, whose chunks lose
/// their reference. UploadPartCopy reads the source range and writes it as
/// a new part: chunks are content addressed, so a copy of whole aligned
/// chunks stores nothing new.
///
/// **Checksums.** The upload's algorithm and type come from
/// CreateMultipartUpload (`x-amz-checksum-algorithm`,
/// `x-amz-checksum-type`). With neither, S3's default since 2025:
/// CRC64NVME, full object. A named algorithm defaults to `COMPOSITE`,
/// except CRC64NVME, which has only `FULL_OBJECT`; the SHAs have only
/// `COMPOSITE`. Every part is hashed with the upload's algorithm (and also
/// with the part request's own, when a default upload's part names
/// another, to verify it). Complete derives the object's checksum from
/// the parts' stored values: the CRC combination for `FULL_OBJECT`, the
/// checksum of the parts' digests with `-N` for `COMPOSITE`. A checksum
/// named in the Complete request must equal it (`BadDigest`); a part's
/// checksum in the Complete body must equal the stored one (`InvalidPart`).
/// When the upload named its algorithm, every part in the body must carry
/// its checksum, as on S3.
///
/// While an upload is open its chosen algorithm and type are kept as
/// system metadata `x-amz-checksum-algorithm` and `x-amz-checksum-type`;
/// Complete replaces them with the object's `x-amz-checksum-<alg>` and
/// type.
///
/// **Limits** are the bucket's compatibility profile: `max_parts` part
/// numbers, `min_part_bytes` for every part but the last,
/// `max_put_bytes` per part, `max_object_bytes` for the whole.
///
/// **Stale uploads** (9.3). AbortMultipartUpload drops one;
/// `sweep_stale_uploads` aborts every upload older than an age, for the
/// gateway's periodic sweep. Lifecycle's `AbortIncompleteMultipartUpload`
/// rule (task 13) uses the same abort.

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_checksums.hpp>
#include <kythira/s3/s3_compat.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_objects.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

namespace multipart_detail {

inline constexpr std::string_view algorithm_key = "x-amz-checksum-algorithm";
inline constexpr std::string_view type_key = "x-amz-checksum-type";

/// The checksum an upload keeps for its parts and its object.
struct upload_checksum {
    checksum_algorithm algorithm = checksum_algorithm::crc64nvme;
    bool full_object = true;
    /// Named by CreateMultipartUpload (not S3's default).
    bool chosen = false;

    [[nodiscard]] auto type() const -> std::string_view {
        return full_object ? "FULL_OBJECT" : "COMPOSITE";
    }
};

[[nodiscard]] inline auto no_such_upload(std::string_view upload_id) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(
        404, "NoSuchUpload",
        "The specified upload does not exist. The upload ID may be invalid, or the upload may "
        "have been aborted or completed.");
    e.extra.emplace_back("UploadId", std::string(upload_id));
    return e;
}

[[nodiscard]] inline auto invalid_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

[[nodiscard]] inline auto invalid_part() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        400, "InvalidPart",
        "One or more of the specified parts could not be found.  The part may not have been "
        "uploaded, or the specified entity tag may not match the part's entity tag.");
}

[[nodiscard]] inline auto entity_too_large(std::uint64_t max) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(400, "EntityTooLarge",
                                        "Your proposed upload exceeds the maximum allowed size");
    e.extra.emplace_back("MaxSizeAllowed", std::to_string(max));
    return e;
}

/// What CreateMultipartUpload's headers ask for.
[[nodiscard]] inline auto checksum_from_headers(const header_list& headers)
    -> aws_rest_xml::result<upload_checksum> {
    upload_checksum out;
    const auto alg = find_header(headers, "x-amz-checksum-algorithm");
    const auto type = find_header(headers, "x-amz-checksum-type");
    if (alg) {
        auto a = parse_checksum_algorithm(*alg);
        if (!a) {
            return invalid_argument(
                "Checksum algorithm provided is unsupported. Please try again "
                "with any of the valid types: [CRC32, CRC32C, CRC64NVME, "
                "SHA1, SHA256]");
        }
        out.algorithm = *a;
        out.chosen = true;
        out.full_object = *a == checksum_algorithm::crc64nvme;
    }
    if (type) {
        if (*type != "COMPOSITE" && *type != "FULL_OBJECT") {
            return invalid_argument("Value for x-amz-checksum-type header is invalid.");
        }
        if (!alg) {
            return invalid_request(
                "The x-amz-checksum-type header can only be used with the "
                "x-amz-checksum-algorithm header.");
        }
        out.full_object = *type == "FULL_OBJECT";
    }
    if (out.full_object && !is_crc(out.algorithm)) {
        return invalid_request("The FULL_OBJECT checksum type cannot be used with the " +
                               std::string(to_string(out.algorithm)) + " checksum algorithm.");
    }
    if (!out.full_object && out.algorithm == checksum_algorithm::crc64nvme) {
        return invalid_request(
            "The COMPOSITE checksum type cannot be used with the CRC64NVME checksum algorithm.");
    }
    return out;
}

/// The checksum an open upload keeps (from its stored metadata).
[[nodiscard]] inline auto checksum_of_upload(const upload_record& u) -> upload_checksum {
    upload_checksum out;
    const auto& m = u.content.system_metadata;
    if (auto it = m.find(std::string(algorithm_key)); it != m.end()) {
        if (auto a = parse_checksum_algorithm(it->second)) {
            out.algorithm = *a;
            out.chosen = true;
        }
    }
    if (auto it = m.find(std::string(type_key)); it != m.end()) {
        out.full_object = it->second == "FULL_OBJECT";
    }
    return out;
}

[[nodiscard]] inline auto part_number(const s3_request& req)
    -> aws_rest_xml::result<std::uint32_t> {
    const auto n = compat_detail::to_u64(req.query.get("partNumber").value_or(""));
    if (!n || *n < 1 || *n > 10'000) {
        auto e = invalid_argument("Part number must be an integer between 1 and 10000, inclusive");
        e.extra.emplace_back("ArgumentName", "partNumber");
        e.extra.emplace_back("ArgumentValue", req.query.get("partNumber").value_or(""));
        return e;
    }
    return static_cast<std::uint32_t>(*n);
}

/// The open upload a request names, or `NoSuchUpload`.
template<metadata_access M>
[[nodiscard]] auto find_upload(const handler_context<M>& ctx, const bucket_state& b,
                               const s3_request& req) -> aws_rest_xml::result<upload_record> {
    const auto id = req.query.get("uploadId").value_or("");
    auto u = ctx.meta.upload(b.desc.id, req.resource.key, id);
    if (!u) {
        return no_such_upload(id);
    }
    return std::move(*u);
}

inline void party(aws_query::xml_writer& w, std::string_view tag, std::string_view account) {
    w.open(tag).element("ID", account).element("DisplayName", account).close();
}

/// A part's stored checksums as `<ChecksumX>` elements.
inline void part_checksums(aws_query::xml_writer& w, const part_record& p) {
    for (auto a : all_checksum_algorithms) {
        if (auto it = p.checksums.find(checksum_header(a)); it != p.checksums.end()) {
            w.element(checksum_element(a), it->second);
        }
    }
}

[[nodiscard]] inline auto hex_of(std::string_view raw) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (unsigned char ch : raw) {
        out.push_back(digits[ch >> 4U]);
        out.push_back(digits[ch & 0xFU]);
    }
    return out;
}

/// A part as stored: its record (number unset) and its checksum with the
/// upload's algorithm.
struct stored_part {
    part_record part;
    std::string checksum;
    /// Of the plaintext, for `Content-MD5`; the part's ETag unless the
    /// upload hides MD5s (SSE-KMS, SSE-C).
    std::string md5_hex;
};

/// Store the bytes `produce` hands over (it calls its argument once per
/// piece and returns an error or nothing), hashing them with the upload's
/// algorithm and verifying what the request names against `trailers`. An
/// encrypted upload's parts are sealed with `cipher`; `hide_md5` gives the
/// part a `sealed_etag` instead of the MD5 of its bytes.
template<typename Produce>
[[nodiscard]] auto store_part(data_path& data, Produce&& produce, std::uint64_t max_bytes,
                              const upload_checksum& kept, const requested_checksum& want,
                              const std::function<header_list()>& trailers,
                              const chunk_cipher* cipher = nullptr, bool hide_md5 = false)
    -> aws_rest_xml::result<stored_part> {
    checksummer sum(kept.algorithm);
    std::optional<checksummer> other;
    if (want.algorithm != kept.algorithm) {
        other.emplace(want.algorithm);
    }
    auto w = data.writer(cipher);
    std::uint64_t size = 0;
    std::optional<aws_rest_xml::error> failed;
    const auto consume = [&](std::string_view piece) {
        if (failed || piece.empty()) {
            return;
        }
        size += piece.size();
        if (size > max_bytes) {
            failed = entity_too_large(max_bytes);
            return;
        }
        sum.update(piece);
        if (other) {
            other->update(piece);
        }
        failed = w.append(std::as_bytes(std::span(piece.data(), piece.size())));
    };
    if (auto e = produce(consume)) {
        return *e;
    }
    if (failed) {
        return *failed;
    }
    const auto value = sum.value();
    const auto requested_value = other ? other->value() : value;
    if (auto e = verify(want, requested_value, trailers ? trailers() : header_list{})) {
        return *e;
    }
    auto written = w.finish();
    if (!written) {
        return written.error();
    }
    stored_part out;
    out.md5_hex = written->md5_hex;
    out.part.manifest = std::move(written->manifest);
    out.part.etag = hide_md5 ? sealed_etag(out.part.manifest) : written->md5_hex;
    out.part.checksums[checksum_header(kept.algorithm)] = value;
    out.checksum = value;
    return out;
}

template<metadata_access M>
[[nodiscard]] auto propose_part(handler_context<M>& ctx, const s3_request& req,
                                const bucket_state& b, part_record part, std::uint64_t started_ms)
    -> aws_rest_xml::result<index_result> {
    if (ctx.write_expired(started_ms)) {
        return slow_down();
    }
    index_command c;
    c.op = index_command::kind::upload_part;
    c.now_ms = ctx.now_ms();
    c.written_ms = started_ms;
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.upload_id = req.query.get("uploadId").value_or("");
    c.part = std::move(part);
    c.max_parts = static_cast<std::uint32_t>(std::min<std::uint64_t>(b.profile.max_parts, 10'000));
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "NoSuchUpload") {
            return no_such_upload(c.upload_id);
        }
        return from_index(r);
    }
    return r;
}

}  // namespace multipart_detail

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto create_multipart_upload(handler_context<M>& ctx, const s3_request& req,
                                           const authenticated& auth, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    using namespace multipart_detail;
    auto sse = parse_sse_request(req.headers, req.secure_transport);
    if (!sse) {
        return sse.error();
    }
    auto checksum = checksum_from_headers(req.headers);
    if (!checksum) {
        return checksum.error();
    }
    auto content = content_from_headers(req.headers);
    if (!content) {
        return content.error();
    }
    const std::string writer = auth.who ? auth.who->account : std::string{};
    const auto owner = new_owner(b, writer, req.headers);
    auto acl = requested_acl(b, owner, req.headers);
    if (!acl) {
        return acl.error();
    }
    if (*acl) {
        content->system_metadata[std::string(object_acl_metadata)] = **acl;
    }
    // An explicit lock is kept from now; the bucket's default retention
    // counts from the complete.
    if (auto e = apply_object_lock(b, req.headers, ctx.now_ms(), content->system_metadata, false)) {
        return *e;
    }
    if (checksum->chosen) {
        content->system_metadata[std::string(algorithm_key)] = to_string(checksum->algorithm);
        content->system_metadata[std::string(type_key)] = checksum->type();
    }
    // The upload's data key is made now and kept wrapped with the upload;
    // each part opens it again (SSE-C: checks the part's key against it).
    auto sealed = ctx.keys().seal(plan_for(std::move(*sse), b.encryption), b.client_name,
                                  req.resource.key, caller_of(auth.who, req));
    if (!sealed) {
        return sealed.error();
    }
    content->system_metadata.insert(sealed->metadata.begin(), sealed->metadata.end());
    // Replication is decided when the upload starts, from its tags and
    // encryption; the completed object takes the upload's metadata.
    mark_replication(b, req.resource.key, *content, false);
    index_command c;
    c.op = index_command::kind::create_upload;
    c.now_ms = ctx.now_ms();
    c.owner = owner;
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.content = std::move(*content);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        return from_index(r);
    }
    auto w = aws_rest_xml::document("InitiateMultipartUploadResult");
    w.element("Bucket", b.client_name)
        .element("Key", req.resource.key)
        .element("UploadId", r.upload_id);
    w.close();
    auto out = xml_response(w.str());
    out.set("x-amz-checksum-algorithm", std::string(to_string(checksum->algorithm)));
    out.set("x-amz-checksum-type", std::string(checksum->type()));
    for (auto& h : sealed->response) {
        out.headers.push_back(std::move(h));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Parts
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto upload_part(handler_context<M>& ctx, const s3_request& req,
                               const authenticated& auth, bucket_state& b) -> handler_result {
    using namespace multipart_detail;
    if (auto e = refuse_write_headers_on_read(req.headers)) {
        return *e;
    }
    auto customer = parse_customer_key(req.headers, customer_prefix, req.secure_transport);
    if (!customer) {
        return customer.error();
    }
    auto number = part_number(req);
    if (!number) {
        return number.error();
    }
    // Nothing is stored for an upload that is not there.
    auto u = find_upload(ctx, b, req);
    if (!u) {
        return u.error();
    }
    const auto& sse_meta = u->content.system_metadata;
    auto cipher = ctx.keys().open(sse_meta, *customer, caller_of(auth.who, req));
    if (!cipher) {
        return cipher.error();
    }
    const auto kept = checksum_of_upload(*u);
    auto want = requested(req.headers);
    if (!want) {
        return want.error();
    }
    if (want->defaulted) {
        want->algorithm = kept.algorithm;
    } else if (kept.chosen && want->algorithm != kept.algorithm) {
        return invalid_request(
            "Checksum Type mismatch occurred, expected checksum Type: " +
            authz_detail::lower(to_string(kept.algorithm)) +
            ", actual checksum Type: " + authz_detail::lower(to_string(want->algorithm)));
    }
    std::optional<std::string> want_md5;
    if (auto h = req.header("Content-MD5")) {
        auto raw = bucket_detail::unb64(*h);
        if (!raw || raw->size() != 16) {
            return aws_rest_xml::errors::make(400, "InvalidDigest",
                                              "The Content-MD5 you specified was invalid.");
        }
        want_md5 = hex_of(*raw);
    }
    const auto from_body = [&](const auto& consume) -> std::optional<aws_rest_xml::error> {
        std::string buf;
        for (bool more = static_cast<bool>(req.body); more;) {
            buf.clear();
            auto r = req.body(buf);
            if (!r) {
                return r.error();
            }
            more = *r;
            consume(buf);
        }
        return std::nullopt;
    };
    const auto started_ms = ctx.now_ms();
    auto stored =
        store_part(ctx.data, from_body, b.profile.max_put_bytes, kept, *want, req.trailers,
                   *cipher ? &**cipher : nullptr, hides_md5(stored_kind(sse_meta)));
    if (!stored) {
        return stored.error();
    }
    if (want_md5 && *want_md5 != stored->md5_hex) {
        return aws_rest_xml::errors::make(
            400, "BadDigest", "The Content-MD5 you specified did not match what we received.");
    }
    const auto declared = req.header("x-amz-decoded-content-length")
                              ? req.header("x-amz-decoded-content-length")
                              : req.header("Content-Length");
    if (declared) {
        if (const auto n = compat_detail::to_u64(*declared); n && *n != stored->part.size()) {
            return aws_rest_xml::errors::make(
                400, "IncompleteBody",
                "You did not provide the number of bytes specified by the Content-Length HTTP "
                "header");
        }
    }
    stored->part.number = *number;
    auto r = propose_part(ctx, req, b, stored->part, started_ms);
    if (!r) {
        return r.error();
    }
    s3_response out;
    out.set("ETag", object_detail::quote(r->etag));
    out.set(checksum_header(kept.algorithm), stored->checksum);
    for (auto& h : sse_response_headers(sse_meta)) {
        out.headers.push_back(std::move(h));
    }
    return out;
}

/// `x-amz-copy-source-range: bytes=first-last` against a source of `size`.
[[nodiscard]] inline auto parse_copy_range(std::optional<std::string> header, std::uint64_t size)
    -> aws_rest_xml::result<std::pair<std::uint64_t, std::uint64_t>> {
    if (!header) {
        return std::pair<std::uint64_t, std::uint64_t>{0, size};
    }
    const auto bad = [] {
        return invalid_argument(
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first "
            "and last are the zero-based offsets of the first and last bytes to copy");
    };
    std::string_view v = *header;
    if (!v.starts_with("bytes=")) {
        return bad();
    }
    v.remove_prefix(6);
    const auto dash = v.find('-');
    if (dash == std::string_view::npos) {
        return bad();
    }
    const auto first = compat_detail::to_u64(v.substr(0, dash));
    const auto last = compat_detail::to_u64(v.substr(dash + 1));
    if (!first || !last || *last < *first) {
        return bad();
    }
    if (*last >= size) {
        return aws_rest_xml::errors::make(
            400, "InvalidRange",
            "Range specified is not valid for source object of size: " + std::to_string(size));
    }
    return std::pair<std::uint64_t, std::uint64_t>{*first, *last - *first + 1};
}

template<metadata_access M>
[[nodiscard]] auto upload_part_copy(handler_context<M>& ctx, const s3_request& req,
                                    const authenticated& auth, bucket_state& b,
                                    const bucket_state& source, const copy_source& src)
    -> handler_result {
    using namespace multipart_detail;
    using object_detail::parse_http_date;
    if (auto e = refuse_write_headers_on_read(req.headers)) {
        return *e;
    }
    auto customer = parse_customer_key(req.headers, customer_prefix, req.secure_transport);
    if (!customer) {
        return customer.error();
    }
    auto source_customer =
        parse_customer_key(req.headers, copy_source_customer_prefix, req.secure_transport);
    if (!source_customer) {
        return source_customer.error();
    }
    auto number = part_number(req);
    if (!number) {
        return number.error();
    }
    auto u = find_upload(ctx, b, req);
    if (!u) {
        return u.error();
    }
    auto found = object_detail::find_object(ctx, source, src.key, src.version_id);
    if (found.error) {
        return *found.error;
    }
    const auto& v = *found.version;
    source_conditions cond;
    cond.if_match = req.header("x-amz-copy-source-if-match");
    cond.if_none_match = req.header("x-amz-copy-source-if-none-match");
    if (auto h = req.header("x-amz-copy-source-if-modified-since")) {
        if (auto t = parse_http_date(*h)) {
            cond.if_modified_since_ms = *t + 999;
        }
    }
    if (auto h = req.header("x-amz-copy-source-if-unmodified-since")) {
        if (auto t = parse_http_date(*h)) {
            cond.if_unmodified_since_ms = *t + 999;
        }
    }
    if (!s3_index_state_machine<>::source_conditions_hold(cond, v)) {
        return object_detail::precondition_failed("x-amz-copy-source-If");
    }
    const auto who = caller_of(auth.who, req);
    auto source_cipher = ctx.keys().open(v.content.system_metadata, *source_customer, who);
    if (!source_cipher) {
        return source_cipher.error();
    }
    const auto& sse_meta = u->content.system_metadata;
    auto cipher = ctx.keys().open(sse_meta, *customer, who);
    if (!cipher) {
        return cipher.error();
    }
    auto range = parse_copy_range(req.header("x-amz-copy-source-range"), v.content.size());
    if (!range) {
        return range.error();
    }
    if (range->second > b.profile.max_put_bytes) {
        return entity_too_large(b.profile.max_put_bytes);
    }
    const auto kept = checksum_of_upload(*u);
    requested_checksum want;
    want.algorithm = kept.algorithm;

    // The range streams from the source's chunks into the part writer.
    const auto from_source = [&](const auto& consume) -> std::optional<aws_rest_xml::error> {
        auto r = ctx.data.read_range(
            v.content, range->first, range->second,
            [&](std::span<const std::byte> bytes) {
                consume(std::string_view(reinterpret_cast<const char*>(bytes.data()),  // NOLINT
                                         bytes.size()));
            },
            *source_cipher ? &**source_cipher : nullptr);
        if (!r) {
            return r.error();
        }
        return std::nullopt;
    };
    const auto started_ms = ctx.now_ms();
    auto stored = store_part(ctx.data, from_source, b.profile.max_put_bytes, kept, want, {},
                             *cipher ? &**cipher : nullptr, hides_md5(stored_kind(sse_meta)));
    if (!stored) {
        return stored.error();
    }
    stored->part.number = *number;
    auto r = propose_part(ctx, req, b, stored->part, started_ms);
    if (!r) {
        return r.error();
    }
    auto w = aws_rest_xml::document("CopyPartResult");
    w.element("ETag", object_detail::quote(r->etag))
        .element("LastModified", aws_rest_xml::iso8601_ms(bucket_detail::time_of(ctx.now_ms())))
        .element(checksum_element(kept.algorithm), stored->checksum);
    w.close();
    auto out = xml_response(w.str());
    if (src.version_id) {
        out.set("x-amz-copy-source-version-id", *src.version_id);
    } else if (source.desc.versioning != versioning_state::unversioned) {
        out.set("x-amz-copy-source-version-id", v.version_id());
    }
    for (auto& h : sse_response_headers(sse_meta)) {
        out.headers.push_back(std::move(h));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto list_parts(handler_context<M>& ctx, const s3_request& req,
                              const authenticated& /*auth*/, bucket_state& b) -> handler_result {
    using namespace multipart_detail;
    auto u = find_upload(ctx, b, req);
    if (!u) {
        return u.error();
    }
    std::size_t max = 1000;
    if (auto m = req.query.get("max-parts")) {
        const auto n = compat_detail::to_u64(*m);
        if (!n) {
            auto e = invalid_argument("Provided max-parts not an integer or within integer range");
            e.extra.emplace_back("ArgumentName", "max-parts");
            e.extra.emplace_back("ArgumentValue", *m);
            return e;
        }
        max = static_cast<std::size_t>(std::min<std::uint64_t>(*n, 1000));
    }
    std::uint64_t marker = 0;
    if (auto m = req.query.get("part-number-marker")) {
        const auto n = compat_detail::to_u64(*m);
        if (!n) {
            auto e = invalid_argument(
                "Provided part-number-marker not an integer or within "
                "integer range");
            e.extra.emplace_back("ArgumentName", "part-number-marker");
            e.extra.emplace_back("ArgumentValue", *m);
            return e;
        }
        marker = *n;
    }
    const auto kept = checksum_of_upload(*u);
    auto w = aws_rest_xml::document("ListPartsResult");
    w.element("Bucket", b.client_name)
        .element("Key", req.resource.key)
        .element("UploadId", u->upload_id());
    party(w, "Initiator", u->owner);
    party(w, "Owner", u->owner);
    w.element("StorageClass", u->content.storage_class)
        .element("PartNumberMarker", std::to_string(marker));
    std::vector<const part_record*> page;
    bool truncated = false;
    for (auto it = u->parts.upper_bound(static_cast<std::uint32_t>(
             std::min<std::uint64_t>(marker, std::numeric_limits<std::uint32_t>::max())));
         it != u->parts.end(); ++it) {
        if (page.size() == max) {
            truncated = true;
            break;
        }
        page.push_back(&it->second);
    }
    w.element("NextPartNumberMarker",
              std::to_string(page.empty() ? marker : std::uint64_t{page.back()->number}))
        .element("MaxParts", std::to_string(max))
        .boolean("IsTruncated", truncated);
    for (const auto* p : page) {
        w.open("Part")
            .element("PartNumber", std::to_string(p->number))
            .element("LastModified",
                     aws_rest_xml::iso8601_ms(bucket_detail::time_of(p->last_modified_ms)))
            .element("ETag", object_detail::quote(p->etag))
            .element("Size", std::to_string(p->size()));
        part_checksums(w, *p);
        w.close();
    }
    w.element("ChecksumAlgorithm", to_string(kept.algorithm)).element("ChecksumType", kept.type());
    w.close();
    return xml_response(w.str());
}

template<metadata_access M>
[[nodiscard]] auto list_multipart_uploads(handler_context<M>& ctx, const s3_request& req,
                                          const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace multipart_detail;
    const auto prefix = req.query.get("prefix").value_or("");
    const auto delimiter = req.query.get("delimiter").value_or("");
    const auto key_marker = req.query.get("key-marker").value_or("");
    const auto upload_id_marker =
        key_marker.empty() ? std::string{} : req.query.get("upload-id-marker").value_or("");
    std::size_t max = 1000;
    if (auto m = req.query.get("max-uploads")) {
        const auto n = compat_detail::to_u64(*m);
        if (!n) {
            auto e = invalid_argument(
                "Provided max-uploads not an integer or within integer "
                "range");
            e.extra.emplace_back("ArgumentName", "max-uploads");
            e.extra.emplace_back("ArgumentValue", *m);
            return e;
        }
        max = static_cast<std::size_t>(std::min<std::uint64_t>(*n, 1000));
    }
    bool url = false;
    if (auto e = req.query.get("encoding-type")) {
        if (*e != "url") {
            auto err = invalid_argument("Invalid Encoding Method specified in Request");
            err.extra.emplace_back("ArgumentName", "encoding-type");
            err.extra.emplace_back("ArgumentValue", *e);
            return err;
        }
        url = true;
    }
    const auto enc = [&](std::string_view s) {
        return url ? aws_rest_xml::url_encode_key(s) : std::string(s);
    };

    // Uploads and common prefixes count together against `max`; a
    // prefix that a previous page ended on is not repeated.
    std::vector<upload_record> uploads;
    std::vector<std::string> prefixes;
    std::string km = key_marker;
    std::string um = upload_id_marker;
    std::string next_key;
    std::string next_upload;
    bool truncated = false;
    const bool resume_prefix =
        !delimiter.empty() && key_marker.ends_with(delimiter) && key_marker.starts_with(prefix);
    for (bool more = true, full = false; more && !full;) {
        auto [page, page_more] = ctx.meta.list_uploads(b.desc.id, prefix, km, um, max + 1);
        more = page_more;
        for (auto& u : page) {
            km = u.key;
            um = u.upload_id();
            if (resume_prefix && u.key.starts_with(key_marker)) {
                continue;
            }
            std::optional<std::string> rolled;
            if (!delimiter.empty()) {
                const auto at = u.key.find(delimiter, prefix.size());
                if (at != std::string::npos) {
                    rolled = u.key.substr(0, at + delimiter.size());
                }
            }
            if (rolled && !prefixes.empty() && prefixes.back() == *rolled) {
                continue;
            }
            if (uploads.size() + prefixes.size() == max) {
                truncated = true;
                full = true;
                break;
            }
            if (rolled) {
                prefixes.push_back(*rolled);
                next_key = *rolled;
                next_upload.clear();
            } else {
                next_key = u.key;
                next_upload = u.upload_id();
                uploads.push_back(std::move(u));
            }
        }
        if (page.empty()) {
            break;
        }
    }

    auto w = aws_rest_xml::document("ListMultipartUploadsResult");
    w.element("Bucket", b.client_name)
        .element("KeyMarker", enc(key_marker))
        .element("UploadIdMarker", upload_id_marker);
    if (truncated) {
        w.element("NextKeyMarker", enc(next_key)).element("NextUploadIdMarker", next_upload);
    }
    if (!delimiter.empty()) {
        w.element("Delimiter", enc(delimiter));
    }
    w.element("Prefix", enc(prefix))
        .element("MaxUploads", std::to_string(max))
        .boolean("IsTruncated", truncated);
    if (url) {
        w.element("EncodingType", "url");
    }
    for (const auto& u : uploads) {
        const auto kept = checksum_of_upload(u);
        w.open("Upload").element("Key", enc(u.key)).element("UploadId", u.upload_id());
        party(w, "Initiator", u.owner);
        party(w, "Owner", u.owner);
        w.element("StorageClass", u.content.storage_class)
            .element("Initiated", aws_rest_xml::iso8601_ms(bucket_detail::time_of(u.initiated_ms)))
            .element("ChecksumAlgorithm", to_string(kept.algorithm))
            .element("ChecksumType", kept.type());
        w.close();
    }
    for (const auto& p : prefixes) {
        w.open("CommonPrefixes").element("Prefix", enc(p)).close();
    }
    w.close();
    return xml_response(w.str());
}

// ---------------------------------------------------------------------------
// Complete and abort
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto complete_multipart_upload(handler_context<M>& ctx, const s3_request& req,
                                             const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace multipart_detail;
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto u = find_upload(ctx, b, req);
    if (!u) {
        return u.error();
    }
    auto doc = aws_rest_xml::parse_xml(*body);
    if (!doc || doc->name != "CompleteMultipartUpload") {
        return aws_rest_xml::errors::malformed_xml("expected CompleteMultipartUpload");
    }
    const auto kept = checksum_of_upload(*u);
    const auto element = checksum_element(kept.algorithm);
    std::vector<completed_part> parts;
    std::vector<std::pair<std::string, std::uint64_t>> sums;
    std::vector<std::string> values;
    std::uint64_t total = 0;
    for (const auto* p : doc->children_named("Part")) {
        const auto n = compat_detail::to_u64(p->child_text("PartNumber").value_or(""));
        const auto etag = p->child_text("ETag");
        if (!n || !etag || *n > std::numeric_limits<std::uint32_t>::max()) {
            return aws_rest_xml::errors::malformed_xml("a Part needs a PartNumber and an ETag");
        }
        parts.push_back({static_cast<std::uint32_t>(*n), *etag});
        // Checks the index makes again atomically (order, existence,
        // ETag) answer from the index; these need the part's stored
        // checksum and size.
        const auto it = u->parts.find(static_cast<std::uint32_t>(*n));
        if (it == u->parts.end()) {
            continue;
        }
        const auto stored = it->second.checksums.find(checksum_header(kept.algorithm));
        const auto given = p->child_text(element);
        for (auto a : all_checksum_algorithms) {
            if (a != kept.algorithm && p->child("Checksum" + std::string(to_string(a)))) {
                return invalid_part();
            }
        }
        if (given && (stored == it->second.checksums.end() || *given != stored->second)) {
            return invalid_part();
        }
        if (!given && kept.chosen) {
            return invalid_request("The upload was created using a " +
                                   authz_detail::lower(to_string(kept.algorithm)) +
                                   " checksum. The complete request must include the checksum "
                                   "for each part. It was missing for part " +
                                   std::to_string(*n) + " in the request.");
        }
        if (stored != it->second.checksums.end()) {
            sums.emplace_back(stored->second, it->second.size());
            values.push_back(stored->second);
        }
        total += it->second.size();
    }
    if (total > b.profile.max_object_bytes) {
        return entity_too_large(b.profile.max_object_bytes);
    }
    if (auto h = req.header("x-amz-mp-object-size")) {
        if (compat_detail::to_u64(*h) != total) {
            return invalid_request("The provided 'x-amz-mp-object-size' header value " + *h +
                                   " does not match what was computed: " + std::to_string(total));
        }
    }
    if (auto h = req.header("x-amz-checksum-type"); h && *h != kept.type()) {
        return invalid_request("The upload was created using the " + std::string(kept.type()) +
                               " checksum mode. The complete request must use the same "
                               "checksum mode.");
    }

    // The object's checksum, from the parts' values.
    std::optional<std::string> checksum;
    if (sums.size() == parts.size()) {
        checksum = kept.full_object ? combine_full_object(kept.algorithm, sums)
                                    : composite_checksum(kept.algorithm, values);
    }
    for (auto a : all_checksum_algorithms) {
        if (auto h = req.header(checksum_header(a))) {
            if (a != kept.algorithm || !checksum || *h != *checksum) {
                return bad_digest(a);
            }
        }
    }

    index_command c;
    c.op = index_command::kind::complete_upload;
    c.now_ms = ctx.now_ms();
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.upload_id = u->upload_id();
    c.parts = std::move(parts);
    c.min_part_bytes = b.profile.min_part_bytes;
    c.max_parts = static_cast<std::uint32_t>(std::min<std::uint64_t>(b.profile.max_parts, 10'000));
    // The upload's open-state keys give way to the object's checksum.
    c.content.system_metadata[std::string(algorithm_key)] = "";
    c.content.system_metadata[std::string(type_key)] = "";
    if (checksum) {
        c.content.system_metadata[checksum_header(kept.algorithm)] = *checksum;
        c.content.system_metadata[std::string(type_key)] = kept.type();
    }
    // The bucket's default retention, unless the upload named a lock.
    if (b.desc.object_lock && lock_state_of(u->content.system_metadata).mode.empty()) {
        if (auto e = apply_object_lock(b, {}, c.now_ms, c.content.system_metadata)) {
            return *e;
        }
    }
    if (auto h = req.header("If-None-Match")) {
        if (access_detail::trim(*h) != "*") {
            return not_implemented();
        }
        c.conditions.if_none_match_star = true;
    }
    if (auto h = req.header("If-Match")) {
        c.conditions.if_match = std::string(access_detail::trim(*h));
    }
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "NoSuchUpload") {
            return no_such_upload(c.upload_id);
        }
        if (r.error == "PreconditionFailed") {
            return object_detail::precondition_failed(c.conditions.if_match ? "If-Match"
                                                                            : "If-None-Match");
        }
        if (r.error == "NoSuchKey") {
            return object_detail::no_such_key(req.resource.key);
        }
        return from_index(r);
    }
    auto w = aws_rest_xml::document("CompleteMultipartUploadResult");
    w.element("Location", "/" + b.client_name + "/" + aws_rest_xml::url_encode_key(c.key))
        .element("Bucket", b.client_name)
        .element("Key", c.key)
        .element("ETag", object_detail::quote(r.etag));
    if (checksum) {
        w.element(element, *checksum).element("ChecksumType", kept.type());
    }
    w.close();
    auto out = xml_response(w.str());
    if (auto v = object_detail::version_header(b, r)) {
        out.set("x-amz-version-id", *v);
    }
    for (auto& h : sse_response_headers(u->content.system_metadata)) {
        if (!h.first.starts_with("x-amz-server-side-encryption-customer")) {
            out.headers.push_back(std::move(h));
        }
    }
    return out;
}

template<metadata_access M>
[[nodiscard]] auto abort_multipart_upload(handler_context<M>& ctx, const s3_request& req,
                                          const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    index_command c;
    c.op = index_command::kind::abort_upload;
    c.now_ms = ctx.now_ms();
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.upload_id = req.query.get("uploadId").value_or("");
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "NoSuchUpload") {
            return multipart_detail::no_such_upload(c.upload_id);
        }
        return from_index(r);
    }
    return bucket_detail::no_content();
}

// ---------------------------------------------------------------------------
// Stale-upload sweep
// ---------------------------------------------------------------------------

/// Abort every upload, in every bucket, initiated at least `max_age_ms`
/// before `now_ms`; at most `limit` per call. Returns how many it aborted.
/// The gateway runs it periodically (Requirement 9.3); an upload a client
/// completes meanwhile simply answers `NoSuchUpload` to the abort.
template<metadata_access M>
auto sweep_stale_uploads(M& meta, std::uint64_t now_ms, std::uint64_t max_age_ms,
                         std::size_t limit = 1000) -> std::size_t {
    std::size_t aborted = 0;
    const auto cutoff = now_ms > max_age_ms ? now_ms - max_age_ms : 0;
    for (const auto& b : meta.list_buckets("")) {
        std::string km;
        std::string um;
        for (bool more = true; more && aborted < limit;) {
            auto [page, page_more] = meta.list_uploads(b.id, "", km, um, 1000);
            more = page_more;
            for (const auto& u : page) {
                km = u.key;
                um = u.upload_id();
                if (u.initiated_ms > cutoff || aborted == limit) {
                    continue;
                }
                index_command c;
                c.op = index_command::kind::abort_upload;
                c.now_ms = now_ms;
                c.target = ref_of(b);
                c.key = u.key;
                c.upload_id = u.upload_id();
                if (meta.propose(c).ok()) {
                    ++aborted;
                }
            }
            if (page.empty()) {
                break;
            }
        }
    }
    return aborted;
}

}  // namespace kythira::s3
