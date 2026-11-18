// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_objects.hpp
/// @brief Object operations (.kiro/specs/s3-compatible-storage/ task 7,
///        Requirements 7.1-7.3 and 7.5): put, get and head (ranges,
///        `partNumber`, response header overrides, conditional reads),
///        delete, copy (metadata and tagging directives, conditional copy),
///        attributes, tagging and object ACLs.
///
/// **Bytes and metadata.** A PUT streams the body into the data path,
/// which writes each chunk to its write quorum; only then is the manifest
/// proposed, with the conditions (`If-None-Match: *`, `If-Match`) decided
/// in `apply()` (7.3). A read takes the version from the metadata layer
/// first and then the chunks, which are immutable, so it sees every write
/// acknowledged before it (7.2).
///
/// **Stored headers.** `Content-Type` (S3's `binary/octet-stream` when
/// absent), `x-amz-meta-*` (at most 2 KB, `MetadataTooLarge`), and
/// `Cache-Control`, `Content-Disposition`, `Content-Encoding` (without
/// `aws-chunked`), `Content-Language`, `Expires`,
/// `x-amz-website-redirect-location` and `x-amz-tagging` are kept and
/// returned. An object's ACL, when it is not just its owner's, is kept as
/// `x-kythira-acl`, which is never returned as a header.
///
/// **Checksums** (task 8). Every PUT stores one full-object checksum: the
/// algorithm the request names (a header value or an aws-chunked
/// trailer, verified, `BadDigest` on a mismatch) or CRC64NVME when it
/// names none, as S3 does since 2025. It is kept as system metadata
/// `x-amz-checksum-<alg>` with `x-amz-checksum-type`, returned on the
/// PUT, by GetObjectAttributes, and on a whole-object GET or HEAD with
/// `x-amz-checksum-mode: ENABLED` (never on a range). A copy keeps it.
///
/// **Object lock** (task 10, `s3_object_lock.hpp`). A PUT, copy or
/// multipart upload takes its lock from its headers or the bucket's
/// default retention; reads return the lock headers; a delete passes
/// `x-amz-bypass-governance-retention` to the index, which refuses to
/// remove a locked version.
///
/// **Not here yet.** SSE (11): a request that asks for SSE-KMS or SSE-C
/// is refused with `NotImplemented` rather than stored unencrypted.
/// Storage classes other than `STANDARD` are stored and returned; their
/// tiering is task 13.

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_auth.hpp>
#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_checksums.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_object_lock.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

inline constexpr std::string_view object_acl_metadata = "x-kythira-acl";
inline constexpr std::string_view tagging_metadata = "x-amz-tagging";

namespace object_detail {

/// Stored as sent and returned on GET and HEAD.
inline constexpr std::array<std::string_view, 7> stored_headers{
    "cache-control",    "content-disposition",
    "content-encoding", "content-language",
    "expires",          "x-amz-website-redirect-location",
    "x-amz-tagging",
};

inline constexpr std::array<std::string_view, 8> storage_classes{
    "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING",
    "GLACIER",  "DEEP_ARCHIVE",       "GLACIER_IR",
};

/// MD5 of `bytes`, as raw bytes (for `Content-MD5`).
[[nodiscard]] inline auto md5_raw(std::string_view bytes) -> std::string {
    detail::md5_stream md5;
    md5.update(std::as_bytes(std::span(bytes.data(), bytes.size())));
    const auto hex = md5.hex();
    std::string out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out.push_back(static_cast<char>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    }
    return out;
}

[[nodiscard]] inline auto quote(std::string_view etag) -> std::string {
    return "\"" + std::string(etag) + "\"";
}

/// Whether an `If-Match`/`If-None-Match` value names `etag`: `*`, or a
/// comma-separated list of (possibly weak, possibly unquoted) tags.
[[nodiscard]] inline auto etag_matches(std::string_view header, std::string_view etag) -> bool {
    while (!header.empty()) {
        const auto comma = header.find(',');
        auto item = access_detail::trim(header.substr(0, comma));
        header = comma == std::string_view::npos ? std::string_view{} : header.substr(comma + 1);
        if (item == "*") {
            return true;
        }
        if (item.starts_with("W/")) {
            item.remove_prefix(2);
        }
        if (item.size() >= 2 && item.front() == '"' && item.back() == '"') {
            item = item.substr(1, item.size() - 2);
        }
        if (item == etag) {
            return true;
        }
    }
    return false;
}

/// An HTTP date (RFC 7231's IMF-fixdate, `Sun, 06 Nov 1994 08:49:37
/// GMT`), in milliseconds since the epoch. S3 ignores a date it cannot
/// read, so this answers nothing for one.
[[nodiscard]] inline auto parse_http_date(std::string_view s) -> std::optional<std::uint64_t> {
    static constexpr std::array<std::string_view, 12> months{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (s.size() != 29 || s.substr(3, 2) != ", " || !s.ends_with(" GMT")) {
        return std::nullopt;
    }
    const auto num = [&](std::size_t at, std::size_t len) -> int {
        int v = 0;
        for (std::size_t i = at; i < at + len; ++i) {
            if (s[i] < '0' || s[i] > '9') {
                return -1;
            }
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    const int day = num(5, 2);
    const auto* const mon = std::ranges::find(months, s.substr(8, 3));
    const int year = num(12, 4);
    const int h = num(17, 2);
    const int mi = num(20, 2);
    const int sec = num(23, 2);
    if (mon == months.end() || day < 1 || year < 0 || h < 0 || h > 23 || mi < 0 || mi > 59 ||
        sec < 0 || sec > 60) {
        return std::nullopt;
    }
    const std::chrono::year_month_day ymd{
        std::chrono::year(year),
        std::chrono::month(static_cast<unsigned>(mon - months.begin() + 1)),
        std::chrono::day(static_cast<unsigned>(day))};
    if (!ymd.ok()) {
        return std::nullopt;
    }
    const auto t = std::chrono::sys_days(ymd) + std::chrono::hours(h) + std::chrono::minutes(mi) +
                   std::chrono::seconds(sec);
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
}

/// The seconds of a millisecond time, as HTTP dates compare.
[[nodiscard]] inline auto whole_seconds(std::uint64_t ms) -> std::uint64_t {
    return ms / 1000 * 1000;
}

struct byte_range {
    std::uint64_t first = 0;
    std::uint64_t last = 0;  ///< inclusive
};

/// `Range: bytes=a-b | a- | -n` against an object of `size` bytes:
/// nothing when absent or not one S3 honours (it then sends the whole
/// object), a range, or `InvalidRange`.
[[nodiscard]] inline auto parse_range(const std::optional<std::string>& header, std::uint64_t size)
    -> aws_rest_xml::result<std::optional<byte_range>> {
    using out_t = aws_rest_xml::result<std::optional<byte_range>>;
    if (!header) {
        return out_t(std::optional<byte_range>{});
    }
    std::string_view h = access_detail::trim(*header);
    if (!h.starts_with("bytes=") || h.find(',') != std::string_view::npos) {
        return out_t(std::optional<byte_range>{});
    }
    h.remove_prefix(6);
    const auto dash = h.find('-');
    if (dash == std::string_view::npos) {
        return out_t(std::optional<byte_range>{});
    }
    const auto num = [](std::string_view d) -> std::optional<std::uint64_t> {
        if (d.empty() || d.size() > 19) {
            return std::nullopt;
        }
        std::uint64_t n = 0;
        for (char c : d) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            n = n * 10 + static_cast<std::uint64_t>(c - '0');
        }
        return n;
    };
    const auto a = h.substr(0, dash);
    const auto b = h.substr(dash + 1);
    const auto unsatisfiable = [&] {
        auto e = invalid_range();
        e.extra.emplace_back("RangeRequested", *header);
        e.extra.emplace_back("ActualObjectSize", std::to_string(size));
        return out_t(e);
    };
    if (a.empty()) {
        const auto n = num(b);
        if (!n) {
            return out_t(std::optional<byte_range>{});
        }
        if (*n == 0 || size == 0) {
            return unsatisfiable();
        }
        return out_t(byte_range{size - std::min(*n, size), size - 1});
    }
    const auto first = num(a);
    const auto last = b.empty() ? std::optional<std::uint64_t>(UINT64_MAX) : num(b);
    if (!first || !last || *last < *first) {
        return out_t(std::optional<byte_range>{});
    }
    if (*first >= size) {
        return unsatisfiable();
    }
    return out_t(byte_range{*first, std::min(*last, size - 1)});
}

/// `x-amz-tagging` (and PutObjectTagging) as tags: a URL query string.
[[nodiscard]] inline auto parse_tag_header(std::string_view value)
    -> aws_rest_xml::result<std::vector<std::pair<std::string, std::string>>> {
    auto q = aws_rest_xml::parse_query(value);
    if (!q) {
        return bucket_detail::invalid_tag(
            "The header 'x-amz-tagging' shall be encoded as UTF-8 "
            "then URLEncoded URL query parameters without tag "
            "name duplicates.");
    }
    return q->params();
}

/// Tags as `x-amz-tagging` stores them.
[[nodiscard]] inline auto tag_header(const std::vector<std::pair<std::string, std::string>>& tags)
    -> std::string {
    std::string out;
    for (const auto& [k, v] : tags) {
        out += out.empty() ? "" : "&";
        out += aws_rest_xml::url_encode_key(k) + "=" + aws_rest_xml::url_encode_key(v);
    }
    return out;
}

[[nodiscard]] inline auto stored_tags(const object_version& v)
    -> std::vector<std::pair<std::string, std::string>> {
    const auto& m = v.content.system_metadata;
    if (auto it = m.find(std::string(tagging_metadata)); it != m.end()) {
        if (auto t = parse_tag_header(it->second)) {
            return *t;
        }
    }
    return {};
}

/// The metadata a PUT (or a REPLACE copy) asks to store.
[[nodiscard]] inline auto content_from_headers(const header_list& headers)
    -> aws_rest_xml::result<object_content> {
    object_content c;
    c.content_type = find_header(headers, "Content-Type").value_or("binary/octet-stream");
    std::size_t meta_bytes = 0;
    for (const auto& [k, v] : headers) {
        const auto name = authz_detail::lower(k);
        if (name.starts_with("x-amz-meta-")) {
            auto key = name.substr(11);
            meta_bytes += key.size() + v.size();
            c.user_metadata[std::move(key)] = v;
            continue;
        }
        if (std::ranges::find(stored_headers, name) == stored_headers.end()) {
            continue;
        }
        if (name == "content-encoding") {
            // aws-chunked is the transfer's, not the object's.
            std::string kept;
            for (auto part : aws_rest_xml::detail::split_list(v)) {
                part = access_detail::trim(part);
                if (!part.empty() && !aws_rest_xml::detail::iequals(part, "aws-chunked")) {
                    kept += kept.empty() ? "" : ",";
                    kept += part;
                }
            }
            if (!kept.empty()) {
                c.system_metadata[name] = kept;
            }
            continue;
        }
        c.system_metadata[name] = v;
    }
    if (meta_bytes > aws_rest_xml::limits::max_user_metadata_bytes) {
        return aws_rest_xml::errors::make(
            400, "MetadataTooLarge",
            "Your metadata headers exceed the maximum allowed metadata size");
    }
    if (auto sc = find_header(headers, "x-amz-storage-class")) {
        if (std::ranges::find(storage_classes, *sc) == storage_classes.end()) {
            return aws_rest_xml::errors::make(400, "InvalidStorageClass",
                                              "The storage class you specified is not valid");
        }
        c.storage_class = *sc;
    }
    if (auto it = c.system_metadata.find(std::string(tagging_metadata));
        it != c.system_metadata.end()) {
        auto tags = parse_tag_header(it->second);
        if (!tags) {
            return tags.error();
        }
        if (auto e = check_tags(*tags, 10)) {
            return *e;
        }
        if (tags->empty()) {
            c.system_metadata.erase(it);
        } else {
            it->second = tag_header(*tags);
        }
    }
    return c;
}

/// SSE asks this task cannot honour yet (task 11).
[[nodiscard]] inline auto refuse_encryption(const header_list& headers)
    -> std::optional<aws_rest_xml::error> {
    if (auto sse = find_header(headers, "x-amz-server-side-encryption"); sse && *sse != "AES256") {
        return not_implemented();
    }
    if (find_header(headers, "x-amz-server-side-encryption-customer-algorithm")) {
        return not_implemented();
    }
    return std::nullopt;
}

/// The owner of a new object: the bucket owner unless ACLs are on and the
/// writer keeps it (ObjectWriter, or BucketOwnerPreferred without
/// `bucket-owner-full-control`).
[[nodiscard]] inline auto new_owner(const bucket_state& b, const std::string& writer,
                                    const header_list& headers) -> std::string {
    switch (b.ownership) {
        case object_ownership::bucket_owner_enforced:
            return b.desc.owner;
        case object_ownership::bucket_owner_preferred:
            return find_header(headers, "x-amz-acl").value_or("") == "bucket-owner-full-control"
                       ? b.desc.owner
                       : writer;
        case object_ownership::object_writer:
            return writer;
    }
    return b.desc.owner;
}

/// The ACL a write asks for, checked against the bucket's settings, or
/// nothing for the owner alone.
[[nodiscard]] inline auto requested_acl(const bucket_state& b, const std::string& owner,
                                        const header_list& headers)
    -> aws_rest_xml::result<std::optional<std::string>> {
    using out_t = aws_rest_xml::result<std::optional<std::string>>;
    auto acl = acl_from_headers(headers, owner, b.desc.owner);
    if (!acl) {
        return out_t(std::optional<std::string>{});
    }
    if (!*acl) {
        return out_t(acl->error());
    }
    if (auto e = check_acl_write(b.ownership, b.access.bpa, **acl, b.desc.owner)) {
        return out_t(*e);
    }
    if (**acl == owner_only(owner)) {
        return out_t(std::optional<std::string>{});
    }
    return out_t(std::optional<std::string>(acl_xml(**acl)));
}

/// The object ACL a version carries.
[[nodiscard]] inline auto acl_of(const object_version& v) -> access_control_list {
    const auto& m = v.content.system_metadata;
    if (auto it = m.find(std::string(object_acl_metadata)); it != m.end()) {
        if (auto a = parse_acl_xml(it->second, v.owner)) {
            return std::move(*a);
        }
    }
    return owner_only(v.owner);
}

/// Headers every object response carries for `v`; the stored checksum
/// only when `checksums` (a whole-object read with
/// `x-amz-checksum-mode: ENABLED`).
inline void object_headers(s3_response& r, const object_version& v, const bucket_state& b,
                           bool checksums = false) {
    const auto& c = v.content;
    r.set("Last-Modified", aws_rest_xml::http_date(bucket_detail::time_of(v.last_modified_ms)));
    r.set("ETag", quote(c.etag));
    r.set("Accept-Ranges", "bytes");
    r.set("Content-Type", c.content_type);
    if (b.desc.versioning != versioning_state::unversioned || !v.null_version) {
        r.set("x-amz-version-id", v.version_id());
    }
    for (const auto& [k, val] : c.user_metadata) {
        r.set("x-amz-meta-" + k, val);
    }
    for (const auto& [k, val] : c.system_metadata) {
        if (k == tagging_metadata || k.starts_with("x-kythira-") || k == lock_mode_metadata ||
            k == legal_hold_metadata) {
            continue;
        }
        if (k.starts_with("x-amz-checksum-") && !checksums) {
            continue;
        }
        r.set(k, val);
    }
    object_lock_headers(r, c.system_metadata);
    if (const auto n = stored_tags(v).size(); n > 0) {
        r.set("x-amz-tagging-count", std::to_string(n));
    }
    if (c.storage_class != "STANDARD") {
        r.set("x-amz-storage-class", c.storage_class);
    }
    if (!c.part_sizes.empty()) {
        r.set("x-amz-mp-parts-count", std::to_string(c.part_sizes.size()));
    }
}

[[nodiscard]] inline auto no_such_key(std::string_view key) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(404, "NoSuchKey", "The specified key does not exist.");
    e.extra.emplace_back("Key", std::string(key));
    return e;
}

[[nodiscard]] inline auto no_such_version(std::string_view key, std::string_view version)
    -> aws_rest_xml::error {
    auto e =
        aws_rest_xml::errors::make(404, "NoSuchVersion", "The specified version does not exist.");
    e.extra.emplace_back("Key", std::string(key));
    e.extra.emplace_back("VersionId", std::string(version));
    return e;
}

[[nodiscard]] inline auto valid_version_id(std::string_view id) -> bool {
    return id == null_version_id || parse_stamp_id(id).has_value();
}

/// What a read of an object finds, or the response that says it is not
/// there (NoSuchKey/NoSuchVersion/MethodNotAllowed with the delete marker
/// headers S3 sends).
struct lookup {
    std::optional<object_version> version;
    std::optional<aws_rest_xml::error> error;
    header_list error_headers;
};

template<metadata_access M>
[[nodiscard]] auto find_object(const handler_context<M>& ctx, const bucket_state& b,
                               const std::string& key, const std::optional<std::string>& version_id)
    -> lookup {
    lookup out;
    if (version_id && !valid_version_id(*version_id)) {
        out.error = invalid_argument("Invalid version id specified");
        out.error->extra.emplace_back("ArgumentName", "versionId");
        out.error->extra.emplace_back("ArgumentValue", *version_id);
        return out;
    }
    auto v = ctx.meta.version(b.desc.id, key, version_id);
    if (!v) {
        out.error = version_id ? no_such_version(key, *version_id) : no_such_key(key);
        return out;
    }
    if (v->delete_marker) {
        out.error_headers.emplace_back("x-amz-delete-marker", "true");
        out.error_headers.emplace_back("x-amz-version-id", v->version_id());
        if (version_id) {
            out.error = aws_rest_xml::errors::make(
                405, "MethodNotAllowed",
                "The specified method is not allowed against this resource.");
            out.error_headers.emplace_back("Allow", "DELETE");
        } else {
            out.error = no_such_key(key);
        }
        return out;
    }
    out.version = std::move(v);
    return out;
}

[[nodiscard]] inline auto precondition_failed(std::string_view condition) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(412, "PreconditionFailed",
                                        "At least one of the pre-conditions you specified did not "
                                        "hold");
    e.extra.emplace_back("Condition", std::string(condition));
    return e;
}

/// RFC 7232's order, as S3 applies it to GET and HEAD: a 412, a 304, or
/// nothing.
[[nodiscard]] inline auto read_conditions(const s3_request& req, const object_version& v)
    -> std::optional<s3_response> {
    const auto& etag = v.content.etag;
    const auto modified = whole_seconds(v.last_modified_ms);
    const auto fail = [&](std::string_view which) {
        return error_response(precondition_failed(which), req.request_id, req.method == "HEAD");
    };
    const auto not_modified = [&] {
        s3_response r;
        r.status = 304;
        r.set("ETag", quote(etag));
        r.set("Last-Modified", aws_rest_xml::http_date(bucket_detail::time_of(v.last_modified_ms)));
        return r;
    };
    const auto if_match = req.header("If-Match");
    if (if_match) {
        if (!etag_matches(*if_match, etag)) {
            return fail("If-Match");
        }
    } else if (auto h = req.header("If-Unmodified-Since")) {
        if (auto t = parse_http_date(*h); t && modified > *t) {
            return fail("If-Unmodified-Since");
        }
    }
    const auto if_none_match = req.header("If-None-Match");
    if (if_none_match) {
        if (etag_matches(*if_none_match, etag)) {
            return not_modified();
        }
    } else if (auto h = req.header("If-Modified-Since")) {
        if (auto t = parse_http_date(*h); t && modified <= *t) {
            return not_modified();
        }
    }
    return std::nullopt;
}

inline constexpr std::array<std::pair<std::string_view, std::string_view>, 6> response_overrides{{
    {"response-content-type", "Content-Type"},
    {"response-content-language", "Content-Language"},
    {"response-expires", "Expires"},
    {"response-cache-control", "Cache-Control"},
    {"response-content-disposition", "Content-Disposition"},
    {"response-content-encoding", "Content-Encoding"},
}};

inline void replace_header(s3_response& r, std::string_view name, std::string value) {
    std::erase_if(r.headers,
                  [&](const auto& h) { return aws_rest_xml::detail::iequals(h.first, name); });
    r.set(std::string(name), std::move(value));
}

[[nodiscard]] inline auto version_header(const bucket_state& b, const index_result& r)
    -> std::optional<std::string> {
    if (b.desc.versioning == versioning_state::unversioned) {
        return std::nullopt;
    }
    return r.version_id;
}

}  // namespace object_detail

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_object(handler_context<M>& ctx, const s3_request& req,
                              const authenticated& auth, bucket_state& b) -> handler_result {
    using namespace object_detail;
    if (auto e = refuse_encryption(req.headers)) {
        return *e;
    }
    const auto& limits = b.profile;
    const auto declared = req.header("x-amz-decoded-content-length")
                              ? req.header("x-amz-decoded-content-length")
                              : req.header("Content-Length");
    const auto too_large = [&] {
        auto e = aws_rest_xml::errors::make(
            400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size");
        e.extra.emplace_back("MaxSizeAllowed", std::to_string(limits.max_put_bytes));
        return e;
    };
    if (declared) {
        const auto n = compat_detail::to_u64(*declared);
        if (n && *n > limits.max_put_bytes) {
            return too_large();
        }
    }
    std::optional<std::string> want_md5;
    if (auto h = req.header("Content-MD5")) {
        auto raw = bucket_detail::unb64(*h);
        if (!raw || raw->size() != 16) {
            return aws_rest_xml::errors::make(400, "InvalidDigest",
                                              "The Content-MD5 you specified was invalid.");
        }
        static constexpr std::string_view digits = "0123456789abcdef";
        std::string hex;
        for (unsigned char ch : *raw) {
            hex.push_back(digits[ch >> 4U]);
            hex.push_back(digits[ch & 0xFU]);
        }
        want_md5 = hex;
    }
    auto content = content_from_headers(req.headers);
    if (!content) {
        return content.error();
    }
    auto want = requested(req.headers);
    if (!want) {
        return want.error();
    }
    checksummer sum(want->algorithm);
    const std::string writer = auth.who ? auth.who->account : std::string{};
    const auto owner = new_owner(b, writer, req.headers);
    auto acl = requested_acl(b, owner, req.headers);
    if (!acl) {
        return acl.error();
    }
    if (*acl) {
        content->system_metadata[std::string(object_acl_metadata)] = **acl;
    }
    if (auto e = apply_object_lock(b, req.headers, ctx.now_ms(), content->system_metadata)) {
        return *e;
    }
    write_conditions conditions;
    if (auto h = req.header("If-None-Match")) {
        if (access_detail::trim(*h) != "*") {
            return not_implemented();
        }
        conditions.if_none_match_star = true;
    }
    if (auto h = req.header("If-Match")) {
        conditions.if_match = std::string(access_detail::trim(*h));
    }

    auto w = ctx.data.writer();
    std::string buf;
    std::uint64_t size = 0;
    for (bool more = true; more;) {
        buf.clear();
        auto r = req.body ? req.body(buf) : aws_rest_xml::result<bool>(false);
        if (!r) {
            return r.error();
        }
        more = *r;
        size += buf.size();
        if (size > limits.max_put_bytes) {
            return too_large();
        }
        if (!buf.empty()) {
            sum.update(buf);
            if (auto e = w.append(std::as_bytes(std::span(buf.data(), buf.size())))) {
                return *e;
            }
        }
    }
    const auto checksum = sum.value();
    if (auto e = verify(*want, checksum, req.trailers ? req.trailers() : header_list{})) {
        return *e;
    }
    auto written = w.finish();
    if (!written) {
        return written.error();
    }
    if (want_md5 && *want_md5 != written->md5_hex) {
        return aws_rest_xml::errors::make(
            400, "BadDigest", "The Content-MD5 you specified did not match what we received.");
    }
    if (declared) {
        if (const auto n = compat_detail::to_u64(*declared); n && *n != written->size) {
            return aws_rest_xml::errors::make(
                400, "IncompleteBody",
                "You did not provide the number of bytes specified by the Content-Length HTTP "
                "header");
        }
    }
    content->manifest = std::move(written->manifest);
    content->etag = written->md5_hex;
    content->system_metadata[checksum_header(want->algorithm)] = checksum;
    content->system_metadata["x-amz-checksum-type"] = "FULL_OBJECT";

    index_command c;
    c.op = index_command::kind::put_object;
    c.now_ms = ctx.now_ms();
    c.owner = owner;
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.content = std::move(*content);
    c.conditions = conditions;
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "PreconditionFailed") {
            return precondition_failed(conditions.if_match ? "If-Match" : "If-None-Match");
        }
        if (r.error == "NoSuchKey") {
            return no_such_key(req.resource.key);
        }
        return from_index(r);
    }
    s3_response out;
    out.set("ETag", quote(r.etag));
    out.set(checksum_header(want->algorithm), checksum);
    out.set("x-amz-checksum-type", "FULL_OBJECT");
    if (auto v = version_header(b, r)) {
        out.set("x-amz-version-id", *v);
    }
    return out;
}

// ---------------------------------------------------------------------------
// GET and HEAD
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_object(handler_context<M>& ctx, const s3_request& req,
                              const authenticated& auth, bucket_state& b) -> handler_result {
    using namespace object_detail;
    const bool head = req.method == "HEAD";
    const auto range_header = req.header("Range");
    const auto part = req.query.get("partNumber");
    if (part && range_header) {
        return aws_rest_xml::errors::make(
            400, "InvalidRequest",
            "Cannot specify both Range header and partNumber query parameter");
    }
    bool overrides = false;
    for (const auto& [q, h] : response_overrides) {
        overrides = overrides || req.query.has(q);
    }
    if (overrides && !auth.who) {
        return aws_rest_xml::errors::make(
            400, "InvalidRequest",
            "Request specific response headers cannot be used for anonymous GET requests.");
    }
    auto found = find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        auto r = error_response(*found.error, req.request_id, head);
        for (auto& h : found.error_headers) {
            r.headers.push_back(std::move(h));
        }
        return r;
    }
    const auto& v = *found.version;
    if (auto r = read_conditions(req, v)) {
        return std::move(*r);
    }
    const auto size = v.content.size();

    // Checksums cover the whole object, so a range read carries none.
    const bool checksum_mode =
        authz_detail::lower(req.header("x-amz-checksum-mode").value_or("")) == "enabled";
    const bool whole = !range_header && (!part || v.content.part_sizes.size() <= 1);
    s3_response out;
    object_headers(out, v, b, checksum_mode && whole);
    std::uint64_t first = 0;
    std::uint64_t length = size;
    if (part) {
        const auto n = compat_detail::to_u64(*part);
        const auto parts = v.content.part_sizes.empty()
                               ? std::uint64_t{1}
                               : static_cast<std::uint64_t>(v.content.part_sizes.size());
        if (!n || *n < 1 || *n > 10'000) {
            return invalid_argument(
                "Part number must be an integer between 1 and 10000, "
                "inclusive");
        }
        if (*n > parts) {
            return aws_rest_xml::errors::make(416, "InvalidPartNumber",
                                              "The requested partnumber is not satisfiable");
        }
        if (!v.content.part_sizes.empty()) {
            for (std::uint64_t i = 0; i + 1 < *n; ++i) {
                first += v.content.part_sizes[i];
            }
            length = v.content.part_sizes[*n - 1];
        }
        out.status = 206;
        if (length > 0) {
            out.set("Content-Range", "bytes " + std::to_string(first) + "-" +
                                         std::to_string(first + length - 1) + "/" +
                                         std::to_string(size));
        }
    } else {
        auto range = parse_range(range_header, size);
        if (!range) {
            return range.error();
        }
        if (*range) {
            first = (*range)->first;
            length = (*range)->last - first + 1;
            out.status = 206;
            out.set("Content-Range", "bytes " + std::to_string(first) + "-" +
                                         std::to_string((*range)->last) + "/" +
                                         std::to_string(size));
        }
    }
    for (const auto& [q, h] : response_overrides) {
        if (auto value = req.query.get(q)) {
            replace_header(out, h, *value);
        }
    }
    out.set("Content-Length", std::to_string(length));
    if (head || length == 0) {
        return out;
    }
    out.stream_length = length;
    out.stream = [&data = ctx.data, content = v.content, first,
                  length](const body_sink& sink) -> std::optional<aws_rest_xml::error> {
        bool open = true;
        auto r = data.read_range(content, first, length, [&](std::span<const std::byte> bytes) {
            open = open && sink(bytes);
        });
        if (!r) {
            return r.error();
        }
        return std::nullopt;
    };
    return out;
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto delete_object(handler_context<M>& ctx, const s3_request& req,
                                 const authenticated& auth, bucket_state& b) -> handler_result {
    using namespace object_detail;
    const auto version_id = req.query.get("versionId");
    if (version_id && !valid_version_id(*version_id)) {
        return invalid_argument("Invalid version id specified");
    }
    index_command c;
    c.op = index_command::kind::delete_object;
    c.now_ms = ctx.now_ms();
    c.owner = auth.who ? auth.who->account : b.desc.owner;
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.version_id = version_id;
    c.bypass_governance = bypass_governance(req.headers);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        return from_index(r);
    }
    s3_response out;
    out.status = 204;
    if (r.delete_marker) {
        out.set("x-amz-delete-marker", "true");
    }
    if (version_id || b.desc.versioning != versioning_state::unversioned) {
        out.set("x-amz-version-id", version_id ? *version_id : r.version_id);
    }
    return out;
}

// ---------------------------------------------------------------------------
// COPY
// ---------------------------------------------------------------------------

/// `x-amz-copy-source`: `[/]bucket/key[?versionId=id]`, URL-encoded.
struct copy_source {
    std::string bucket;
    std::string key;
    std::optional<std::string> version_id;
};

[[nodiscard]] inline auto parse_copy_source(std::string_view value)
    -> aws_rest_xml::result<copy_source> {
    const auto bad = [] {
        return aws_rest_xml::errors::make(400, "InvalidArgument",
                                          "Copy Source must mention the source bucket and key: "
                                          "sourcebucket/sourcekey");
    };
    copy_source out;
    const auto q = value.find('?');
    auto path = value.substr(0, q);
    if (q != std::string_view::npos) {
        auto query = aws_rest_xml::parse_query(value.substr(q + 1));
        if (!query) {
            return bad();
        }
        out.version_id = query->get("versionId");
        if (out.version_id && !object_detail::valid_version_id(*out.version_id)) {
            return invalid_argument("Invalid version id specified");
        }
    }
    auto decoded = aws_rest_xml::percent_decode(path, false);
    if (!decoded) {
        return bad();
    }
    std::string_view p = *decoded;
    if (p.starts_with('/')) {
        p.remove_prefix(1);
    }
    const auto slash = p.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 == p.size()) {
        return bad();
    }
    out.bucket = std::string(p.substr(0, slash));
    out.key = std::string(p.substr(slash + 1));
    return out;
}

template<metadata_access M>
[[nodiscard]] auto copy_object(handler_context<M>& ctx, const s3_request& req,
                               const authenticated& auth, bucket_state& b,
                               const bucket_state& source, const copy_source& src)
    -> handler_result {
    using namespace object_detail;
    if (auto e = refuse_encryption(req.headers)) {
        return *e;
    }
    const auto metadata_directive = req.header("x-amz-metadata-directive").value_or("COPY");
    const auto tagging_directive = req.header("x-amz-tagging-directive").value_or("COPY");
    for (const auto& d : {metadata_directive, tagging_directive}) {
        if (d != "COPY" && d != "REPLACE") {
            return invalid_argument("Unknown metadata directive.");
        }
    }
    const bool replace = metadata_directive == "REPLACE";

    // The source as of now, for the size limit; apply() checks it again.
    if (auto v = ctx.meta.version(source.desc.id, src.key, src.version_id);
        v && !v->delete_marker && v->content.size() > b.profile.max_put_bytes) {
        return aws_rest_xml::errors::make(
            400, "InvalidRequest",
            "The specified copy source is larger than the maximum allowable size for a copy "
            "source: " +
                std::to_string(b.profile.max_put_bytes));
    }

    index_command c;
    c.op = index_command::kind::copy_object;
    c.now_ms = ctx.now_ms();
    const std::string writer = auth.who ? auth.who->account : std::string{};
    c.owner = new_owner(b, writer, req.headers);
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.source = ref_of(source.desc);
    c.source_key = src.key;
    c.version_id = src.version_id;
    c.replace_metadata = replace;
    if (replace) {
        auto content = content_from_headers(req.headers);
        if (!content) {
            return content.error();
        }
        c.content = std::move(*content);
    } else if (auto sc = req.header("x-amz-storage-class")) {
        // A storage class change alone is a REPLACE of that one field,
        // which S3 also accepts as a copy onto itself; keep it simple and
        // refuse until tiering exists.
        if (*sc != "STANDARD") {
            return not_implemented();
        }
    }
    // The new object's ACL and lock are the request's, never the source's.
    c.override_metadata.emplace_back(object_acl_metadata);
    for (const auto name : {lock_mode_metadata, lock_until_metadata, legal_hold_metadata}) {
        c.override_metadata.emplace_back(name);
    }
    if (auto e = apply_object_lock(b, req.headers, c.now_ms, c.content.system_metadata)) {
        return *e;
    }
    auto acl = requested_acl(b, c.owner, req.headers);
    if (!acl) {
        return acl.error();
    }
    if (*acl) {
        c.content.system_metadata[std::string(object_acl_metadata)] = **acl;
    }
    if (tagging_directive == "REPLACE") {
        c.override_metadata.emplace_back(tagging_metadata);
        const auto h = req.header("x-amz-tagging").value_or("");
        auto tags = parse_tag_header(h);
        if (!tags) {
            return tags.error();
        }
        if (auto e = check_tags(*tags, 10)) {
            return *e;
        }
        if (!tags->empty()) {
            c.content.system_metadata[std::string(tagging_metadata)] = tag_header(*tags);
        } else {
            c.content.system_metadata.erase(std::string(tagging_metadata));
        }
    } else if (replace) {
        // REPLACE takes the request's metadata; tags still follow COPY.
        c.override_metadata.emplace_back(tagging_metadata);
        if (auto v = ctx.meta.version(source.desc.id, src.key, src.version_id)) {
            const auto& m = v->content.system_metadata;
            if (auto it = m.find(std::string(tagging_metadata)); it != m.end()) {
                c.content.system_metadata[std::string(tagging_metadata)] = it->second;
            } else {
                c.content.system_metadata.erase(std::string(tagging_metadata));
            }
        }
    }
    if (auto h = req.header("x-amz-copy-source-if-match")) {
        c.source_if.if_match = *h;
    }
    if (auto h = req.header("x-amz-copy-source-if-none-match")) {
        c.source_if.if_none_match = *h;
    }
    if (auto h = req.header("x-amz-copy-source-if-modified-since")) {
        if (auto t = parse_http_date(*h)) {
            c.source_if.if_modified_since_ms = *t + 999;
        }
    }
    if (auto h = req.header("x-amz-copy-source-if-unmodified-since")) {
        if (auto t = parse_http_date(*h)) {
            c.source_if.if_unmodified_since_ms = *t + 999;
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
        if (r.error == "NoSuchKey") {
            return no_such_key(src.key);
        }
        return from_index(r);
    }
    auto w = aws_rest_xml::document("CopyObjectResult");
    w.element("ETag", quote(r.etag))
        .element("LastModified",
                 aws_rest_xml::iso8601_ms(bucket_detail::time_of(r.last_modified_ms)));
    w.close();
    auto out = xml_response(w.str());
    if (auto v = version_header(b, r)) {
        out.set("x-amz-version-id", *v);
    }
    if (src.version_id) {
        out.set("x-amz-copy-source-version-id", *src.version_id);
    } else if (source.desc.versioning != versioning_state::unversioned) {
        if (auto v = ctx.meta.version(source.desc.id, src.key, std::nullopt)) {
            out.set("x-amz-copy-source-version-id", v->version_id());
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Attributes, tagging, ACL
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto get_object_attributes(handler_context<M>& ctx, const s3_request& req,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    const auto wanted = req.header("x-amz-object-attributes");
    if (!wanted || access_detail::trim(*wanted).empty()) {
        return invalid_argument("Invalid attribute name specified.");
    }
    std::vector<std::string> attrs;
    for (auto a : aws_rest_xml::detail::split_list(*wanted)) {
        a = access_detail::trim(a);
        static constexpr std::array<std::string_view, 5> known{"ETag", "Checksum", "ObjectParts",
                                                               "StorageClass", "ObjectSize"};
        if (std::ranges::find(known, a) == known.end()) {
            return invalid_argument("Invalid attribute name specified.");
        }
        attrs.emplace_back(a);
    }
    auto found = find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        auto r = error_response(*found.error, req.request_id);
        for (auto& h : found.error_headers) {
            r.headers.push_back(std::move(h));
        }
        return r;
    }
    const auto& v = *found.version;
    if (auto r = read_conditions(req, v)) {
        return std::move(*r);
    }
    const auto has = [&](std::string_view a) { return std::ranges::find(attrs, a) != attrs.end(); };
    auto w = aws_rest_xml::document("GetObjectAttributesResponse");
    if (has("ETag")) {
        w.element("ETag", v.content.etag);
    }
    if (has("Checksum")) {
        const auto& m = v.content.system_metadata;
        for (auto a : all_checksum_algorithms) {
            if (auto it = m.find(checksum_header(a)); it != m.end()) {
                w.open("Checksum").element(checksum_element(a), it->second);
                if (auto t = m.find("x-amz-checksum-type"); t != m.end()) {
                    w.element("ChecksumType", t->second);
                }
                w.close();
                break;
            }
        }
    }
    if (has("ObjectParts") && !v.content.part_sizes.empty()) {
        w.open("ObjectParts")
            .element("TotalPartsCount", std::to_string(v.content.part_sizes.size()))
            .close();
    }
    if (has("StorageClass")) {
        w.element("StorageClass", v.content.storage_class);
    }
    if (has("ObjectSize")) {
        w.element("ObjectSize", std::to_string(v.content.size()));
    }
    w.close();
    auto out = xml_response(w.str());
    out.set("Last-Modified", aws_rest_xml::http_date(bucket_detail::time_of(v.last_modified_ms)));
    if (b.desc.versioning != versioning_state::unversioned || !v.null_version) {
        out.set("x-amz-version-id", v.version_id());
    }
    return out;
}

namespace object_detail {

template<metadata_access M>
[[nodiscard]] auto set_metadata(handler_context<M>& ctx, const s3_request& req, bucket_state& b,
                                std::string_view name, std::optional<std::string> value)
    -> aws_rest_xml::result<index_result> {
    const auto version_id = req.query.get("versionId");
    if (version_id && !valid_version_id(*version_id)) {
        return invalid_argument("Invalid version id specified");
    }
    index_command c;
    c.op = index_command::kind::set_object_metadata;
    c.now_ms = ctx.now_ms();
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.version_id = version_id;
    c.config_name = std::string(name);
    c.document = std::move(value);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        if (r.error == "NoSuchKey") {
            return no_such_key(req.resource.key);
        }
        if (r.error == "NoSuchVersion") {
            return no_such_version(req.resource.key, version_id.value_or(""));
        }
        return from_index(r);
    }
    return r;
}

}  // namespace object_detail

template<metadata_access M>
[[nodiscard]] auto get_object_tagging(handler_context<M>& ctx, const s3_request& req,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    auto found = find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    auto out = xml_response(tagging_xml(stored_tags(*found.version)));
    if (b.desc.versioning != versioning_state::unversioned || !found.version->null_version) {
        out.set("x-amz-version-id", found.version->version_id());
    }
    return out;
}

template<metadata_access M>
[[nodiscard]] auto put_object_tagging(handler_context<M>& ctx, const s3_request& req,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto tags = parse_tagging(*body);
    if (!tags) {
        return tags.error();
    }
    if (auto e = check_tags(*tags, 10)) {
        return *e;
    }
    auto r =
        set_metadata(ctx, req, b, tagging_metadata,
                     tags->empty() ? std::nullopt : std::optional<std::string>(tag_header(*tags)));
    if (!r) {
        return r.error();
    }
    s3_response out;
    if (auto v = version_header(b, *r)) {
        out.set("x-amz-version-id", *v);
    }
    return out;
}

template<metadata_access M>
[[nodiscard]] auto delete_object_tagging(handler_context<M>& ctx, const s3_request& req,
                                         const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    auto r = set_metadata(ctx, req, b, tagging_metadata, std::nullopt);
    if (!r) {
        return r.error();
    }
    s3_response out;
    out.status = 204;
    if (auto v = version_header(b, *r)) {
        out.set("x-amz-version-id", *v);
    }
    return out;
}

template<metadata_access M>
[[nodiscard]] auto get_object_acl(handler_context<M>& ctx, const s3_request& req,
                                  const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    auto found = find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    return xml_response(acl_xml(acl_of(*found.version)));
}

template<metadata_access M>
[[nodiscard]] auto put_object_acl(handler_context<M>& ctx, const s3_request& req,
                                  const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using namespace object_detail;
    auto found = find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    const auto& owner = found.version->owner;
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto from_headers = acl_from_headers(req.headers, owner, b.desc.owner);
    access_control_list acl;
    if (from_headers) {
        if (!body->empty()) {
            return aws_rest_xml::errors::make(400, "UnexpectedContent",
                                              "This request does not support content");
        }
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
    if (auto e = check_acl_write(b.ownership, b.access.bpa, acl, b.desc.owner)) {
        return *e;
    }
    auto r = set_metadata(
        ctx, req, b, object_acl_metadata,
        acl == owner_only(owner) ? std::nullopt : std::optional<std::string>(acl_xml(acl)));
    if (!r) {
        return r.error();
    }
    s3_response out;
    if (auto v = version_header(b, *r)) {
        out.set("x-amz-version-id", *v);
    }
    return out;
}

}  // namespace kythira::s3
