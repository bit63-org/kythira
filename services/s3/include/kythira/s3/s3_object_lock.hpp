// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_object_lock.hpp
/// @brief Object lock on the write path (.kiro/specs/s3-compatible-storage/
///        task 10, Requirement 8.2): the lock a write asks for, the
///        bucket's default retention, and the headers a read returns.
///
/// The index enforces the lock (`lock_refuses`, `set_object_lock` in
/// `s3_index_state_machine.hpp`), so no path can remove a locked version.
/// This header decides what lock a new version starts with:
///
/// - `x-amz-object-lock-mode` with `x-amz-object-lock-retain-until-date`
///   (both or neither), and `x-amz-object-lock-legal-hold`, on PutObject,
///   CopyObject, CreateMultipartUpload and browser POST. Any of them on a
///   bucket without object lock is `InvalidRequest`, and S3 asks for
///   `Content-MD5` or a checksum header beside them.
/// - Otherwise the bucket's default retention (`<DefaultRetention>` with
///   `Days` or `Years` in its `ObjectLockConfiguration`), counted from
///   the version's creation: the PUT, the copy, or the multipart
///   complete.

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_post_policy.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace kythira::s3 {

namespace lock_detail {

inline constexpr std::uint64_t day_ms = std::uint64_t{86'400'000};

/// A bucket's `<ObjectLockConfiguration>`: its default retention, if any.
struct lock_configuration {
    std::string mode;  ///< empty: no default retention
    std::uint64_t days = 0;
    std::uint64_t years = 0;

    [[nodiscard]] auto period_ms() const -> std::uint64_t {
        // S3 counts a year as 365 days.
        return (days + years * 365) * day_ms;
    }
};

[[nodiscard]] inline auto malformed() -> aws_rest_xml::error {
    return aws_rest_xml::errors::malformed_xml(
        "The XML you provided was not well-formed or did not validate against our published "
        "schema");
}

[[nodiscard]] inline auto parse_lock_configuration(std::string_view xml)
    -> aws_rest_xml::result<lock_configuration> {
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc || doc->name != "ObjectLockConfiguration") {
        return malformed();
    }
    lock_configuration out;
    if (auto enabled = doc->child_text("ObjectLockEnabled"); enabled && *enabled != "Enabled") {
        return malformed();
    }
    const auto* rule = doc->child("Rule");
    if (rule == nullptr) {
        return out;
    }
    const auto* d = rule->child("DefaultRetention");
    if (d == nullptr) {
        return malformed();
    }
    out.mode = d->child_text("Mode").value_or("");
    if (out.mode != "GOVERNANCE" && out.mode != "COMPLIANCE") {
        return malformed();
    }
    const auto days = d->child_text("Days");
    const auto years = d->child_text("Years");
    if (days.has_value() == years.has_value()) {
        return malformed();
    }
    const auto n = compat_detail::to_u64(days ? *days : *years);
    if (!n || *n == 0) {
        return aws_rest_xml::errors::make(
            400, "InvalidArgument", "Default retention period must be a positive integer value");
    }
    (days ? out.days : out.years) = *n;
    if (out.period_ms() > 100 * 365 * day_ms) {
        return aws_rest_xml::errors::make(400, "InvalidArgument",
                                          "Default retention period is too large.");
    }
    return out;
}

/// The bucket's stored lock configuration (none for a bucket without
/// object lock or without a stored document).
[[nodiscard]] inline auto bucket_lock(const bucket_state& b) -> lock_configuration {
    if (!b.desc.object_lock) {
        return {};
    }
    const auto it = b.desc.config.find("object-lock");
    if (it == b.desc.config.end()) {
        return {};
    }
    auto c = parse_lock_configuration(it->second);
    return c ? *c : lock_configuration{};
}

[[nodiscard]] inline auto ms_of(std::chrono::system_clock::time_point t) -> std::uint64_t {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
}

/// `2026-12-01T00:00:00Z` (or with milliseconds) as ms since the epoch.
[[nodiscard]] inline auto parse_date(std::string_view s) -> std::optional<std::uint64_t> {
    auto t = post_detail::parse_iso8601(s);
    if (!t) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(t->time_since_epoch().count());
}

[[nodiscard]] inline auto render_date(std::uint64_t ms) -> std::string {
    return aws_rest_xml::iso8601_ms(
        std::chrono::system_clock::time_point(std::chrono::milliseconds(ms)));
}

[[nodiscard]] inline auto has_integrity_header(const header_list& headers) -> bool {
    for (const auto& [k, v] : headers) {
        const auto n = authz_detail::lower(k);
        if (n == "content-md5" || n.starts_with("x-amz-checksum-") ||
            n == "x-amz-sdk-checksum-algorithm" || n == "x-amz-trailer") {
            return true;
        }
    }
    return false;
}

}  // namespace lock_detail

/// Set the lock a new version starts with into `metadata`: the request's
/// lock headers, else the bucket's default retention. With
/// `with_default` false only the headers count (CreateMultipartUpload,
/// whose default applies at complete).
[[nodiscard]] inline auto apply_object_lock(const bucket_state& b, const header_list& headers,
                                            std::uint64_t now_ms,
                                            std::map<std::string, std::string>& metadata,
                                            bool with_default = true)
    -> std::optional<aws_rest_xml::error> {
    using namespace lock_detail;
    const auto mode = find_header(headers, "x-amz-object-lock-mode");
    const auto until = find_header(headers, "x-amz-object-lock-retain-until-date");
    const auto hold = find_header(headers, "x-amz-object-lock-legal-hold");
    if (mode || until || hold) {
        if (!b.desc.object_lock) {
            return aws_rest_xml::errors::make(400, "InvalidRequest",
                                              "Bucket is missing Object Lock Configuration");
        }
        if (!has_integrity_header(headers)) {
            return aws_rest_xml::errors::make(
                400, "InvalidRequest",
                "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests "
                "with Object Lock parameters");
        }
    }
    if (mode.has_value() != until.has_value()) {
        return invalid_argument(
            "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be "
            "supplied");
    }
    if (mode) {
        if (*mode != "GOVERNANCE" && *mode != "COMPLIANCE") {
            return invalid_argument("Unknown wormMode directive.");
        }
        const auto at = parse_date(*until);
        if (!at) {
            return invalid_argument("The retain until date must be provided in ISO 8601 format");
        }
        if (*at <= now_ms) {
            return invalid_argument("The retain until date must be in the future!");
        }
        metadata[std::string(lock_mode_metadata)] = *mode;
        metadata[std::string(lock_until_metadata)] = std::to_string(*at);
    } else if (with_default) {
        const auto def = bucket_lock(b);
        if (!def.mode.empty()) {
            metadata[std::string(lock_mode_metadata)] = def.mode;
            metadata[std::string(lock_until_metadata)] = std::to_string(now_ms + def.period_ms());
        }
    }
    if (hold) {
        if (*hold != "ON" && *hold != "OFF") {
            return invalid_argument("Legal Hold must be either of 'ON' or 'OFF'");
        }
        metadata[std::string(legal_hold_metadata)] = *hold;
    }
    return std::nullopt;
}

/// The lock headers a read of `metadata` returns.
inline void object_lock_headers(s3_response& r,
                                const std::map<std::string, std::string>& metadata) {
    const auto lock = lock_state_of(metadata);
    if (!lock.mode.empty()) {
        r.set(std::string(lock_mode_metadata), lock.mode);
        r.set("x-amz-object-lock-retain-until-date", lock_detail::render_date(lock.until_ms));
    }
    if (auto it = metadata.find(std::string(legal_hold_metadata)); it != metadata.end()) {
        r.set(std::string(legal_hold_metadata), it->second);
    }
}

/// `x-amz-bypass-governance-retention: true` (authorized as
/// `s3:BypassGovernanceRetention` before the handler runs).
[[nodiscard]] inline auto bypass_governance(const header_list& headers) -> bool {
    return authz_detail::lower(
               find_header(headers, "x-amz-bypass-governance-retention").value_or("")) == "true";
}

}  // namespace kythira::s3
