// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_context.hpp
/// @brief What every handler shares: the service's options, the metadata
///        layer, the data path, and a bucket's access state read from its
///        stored configuration (.kiro/specs/s3-compatible-storage/ task 7).
///
/// A bucket's access settings live in its catalog entry as sub-resources,
/// written whole by the operations that own them:
///
/// | Sub-resource | Holds | Absent means |
/// |---|---|---|
/// | `ownership-controls` | `<OwnershipControls>` | `ObjectWriter`, as an S3 bucket from before
/// 2023 | | `public-access-block` | `<PublicAccessBlockConfiguration>` | every flag off | | `acl` |
/// `<AccessControlPolicy>` | the owner alone, `FULL_CONTROL` | | `policy` | the policy JSON | no
/// policy | | `tagging` | `<Tagging>` | no tags |
///
/// CreateBucket stores the cluster's defaults for the first two (on a new
/// bucket, BucketOwnerEnforced and every Block Public Access flag on, as
/// S3 does since April 2023) in the same entry that creates the bucket.
///
/// **Bucket namespaces** (Requirement 6.2). Names are unique in the
/// cluster, S3's global namespace scaled to one cluster. With
/// `account_namespaces` each account has its own: the catalog name is
/// `<account>/<name>` (a `/` cannot occur in a bucket name), and an
/// anonymous request, which names no account, finds no bucket.

#include <kythira/s3/s3_access.hpp>
#include <kythira/s3/s3_compat.hpp>
#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_encryption.hpp>
#include <kythira/s3/s3_event_sinks.hpp>
#include <kythira/s3/s3_lifecycle_rules.hpp>
#include <kythira/s3/s3_rates.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_replication_rules.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::s3 {

struct service_options {
    compat_profile profile;
    /// The region this endpoint serves (bucket locations, SigV4 scopes).
    std::string region = "us-east-1";
    std::string partition = "aws";
    aws_rest_xml::addressing_config addressing;
    /// Per-account Block Public Access (PutPublicAccessBlock on the S3
    /// Control API); none means every flag off, as for an AWS account.
    std::function<public_access_block(std::string_view account)> account_public_access_block;
    bool account_namespaces = false;
    /// Largest XML or JSON request body (configurations, DeleteObjects).
    std::size_t max_document_bytes = std::size_t{2} * 1024 * 1024;
    /// The clock, for tests; the system clock when empty.
    std::function<std::chrono::system_clock::time_point()> clock;
    /// Server-side encryption's key providers and bucket-key cache
    /// (`s3_encryption.hpp`). None: SSE-S3 objects are stored unencrypted,
    /// SSE-KMS is refused, SSE-C works (it needs no provider).
    std::shared_ptr<sse_keys> encryption;
    /// Per-prefix request rates (`s3_rates.hpp`): when a prefix counts as
    /// hot, and who hears about it.
    prefix_rates::options rates;
    prefix_rates::hot_fn on_hot_prefix;
    /// Longest a write may take from its first chunk to its commit. A
    /// slower one is refused (503 SlowDown) rather than committed: chunks
    /// it found already stored may have been collected meanwhile, and the
    /// index catches that only while their tombstones last, so the
    /// collector's grace period must exceed this (`s3_sweeps.hpp`).
    std::uint64_t max_write_ms = std::uint64_t{15} * 60 * 1000;
    /// A lifecycle "day" (`s3_lifecycle_rules.hpp`): rule ages, restore
    /// periods and the `x-amz-expiration` dates count in these. Tests
    /// shorten it, as Requirement 12.1's faster test interval.
    std::uint64_t lifecycle_day_ms = standard_day_ms;
    /// Where `PutBucketNotificationConfiguration` sends its `s3:TestEvent`
    /// (`s3_event_sinks.hpp`); none skips the destination check.
    notification_sink notifications;
};

/// The handlers' shared state.
template<metadata_access M> struct handler_context {
    M& meta;
    data_path& data;
    const service_options& options;

    /// The encryption keys; an empty set when none are configured.
    [[nodiscard]] auto keys() const -> sse_keys& {
        static sse_keys none;
        return options.encryption ? *options.encryption : none;
    }

    [[nodiscard]] auto now() const -> std::chrono::system_clock::time_point {
        return options.clock ? options.clock() : std::chrono::system_clock::now();
    }
    [[nodiscard]] auto now_ms() const -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now().time_since_epoch())
                .count());
    }
    /// Whether a write that began storing chunks at `started_ms` has run
    /// past `max_write_ms` and must not commit.
    [[nodiscard]] auto write_expired(std::uint64_t started_ms) const -> bool {
        return now_ms() > started_ms + options.max_write_ms;
    }
    /// The catalog name of `bucket` for `account`.
    [[nodiscard]] auto catalog_name(std::string_view bucket, std::string_view account) const
        -> std::string {
        if (!options.account_namespaces) {
            return std::string(bucket);
        }
        return std::string(account) + "/" + std::string(bucket);
    }
    /// The name a client sees for a catalog entry.
    [[nodiscard]] auto client_name(std::string_view catalog) const -> std::string {
        if (!options.account_namespaces) {
            return std::string(catalog);
        }
        const auto slash = catalog.find('/');
        return std::string(slash == std::string_view::npos ? catalog : catalog.substr(slash + 1));
    }
};

// ---------------------------------------------------------------------------
// Errors handlers share
// ---------------------------------------------------------------------------

[[nodiscard]] inline auto no_such_bucket(std::string_view bucket) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(404, "NoSuchBucket", "The specified bucket does not exist");
    e.extra.emplace_back("BucketName", std::string(bucket));
    return e;
}

[[nodiscard]] inline auto not_implemented() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        501, "NotImplemented",
        "A header you provided implies functionality that is not implemented");
}

[[nodiscard]] inline auto from_index(const index_result& r) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(r.status, r.error, r.message);
}

/// A fresh request id: 16 upper-case hex digits, as S3's look.
[[nodiscard]] inline auto new_request_id() -> std::string {
    thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr std::string_view digits = "0123456789ABCDEF";
    auto n = rng();
    std::string out(16, '0');
    for (auto& c : out) {
        c = digits[n & 0xFU];
        n >>= 4U;
    }
    return out;
}

// ---------------------------------------------------------------------------
// A bucket's access state
// ---------------------------------------------------------------------------

[[nodiscard]] inline auto ownership_controls_xml(object_ownership o) -> std::string {
    auto w = aws_rest_xml::document("OwnershipControls");
    w.open("Rule").element("ObjectOwnership", to_string(o)).close();
    w.close();
    return w.str();
}

[[nodiscard]] inline auto parse_ownership_controls(std::string_view xml)
    -> aws_rest_xml::result<object_ownership> {
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    const auto* rule = doc->name == "OwnershipControls" ? doc->child("Rule") : nullptr;
    const auto value = rule != nullptr ? rule->child_text("ObjectOwnership") : std::nullopt;
    if (!value || doc->children_named("Rule").size() != 1) {
        return aws_rest_xml::errors::malformed_xml("expected one OwnershipControls Rule");
    }
    auto o = parse_ownership(*value);
    if (!o) {
        return aws_rest_xml::errors::malformed_xml("unknown ObjectOwnership " + *value);
    }
    return *o;
}

struct bucket_state {
    bucket_descriptor desc;
    std::string client_name;
    object_ownership ownership = object_ownership::object_writer;
    public_access_block bucket_public_access_block{false, false, false, false};
    access_control_list acl;
    std::vector<std::pair<std::string, std::string>> tags;
    /// Default encryption (`PutBucketEncryption`); SSE-S3 when none is set.
    bucket_encryption encryption;
    /// `PutBucketLifecycleConfiguration`; none when not set.
    std::optional<lifecycle_configuration> lifecycle;
    /// `PutBucketReplication`; none when not set.
    std::optional<replication_configuration> replication;
    compat_profile profile;
    access_context access;  ///< for `authorize_check`; its `bucket_acl` points at `acl`

    bucket_state() = default;
    bucket_state(const bucket_state&) = delete;
    auto operator=(const bucket_state&) -> bucket_state& = delete;
    bucket_state(bucket_state&&) = delete;
    auto operator=(bucket_state&&) -> bucket_state& = delete;
};

/// Read a bucket's settings from its catalog entry. Stored documents were
/// checked when written; one that no longer parses counts as absent.
template<metadata_access M>
void load_bucket_state(const handler_context<M>& ctx, bucket_descriptor desc, bucket_state& out,
                       const s3_request& req) {
    const auto& cfg = desc.config;
    out.client_name = ctx.client_name(desc.name);
    if (auto it = cfg.find("ownership-controls"); it != cfg.end()) {
        if (auto o = parse_ownership_controls(it->second)) {
            out.ownership = *o;
        }
    }
    if (auto it = cfg.find("public-access-block"); it != cfg.end()) {
        if (auto b = parse_public_access_block(it->second)) {
            out.bucket_public_access_block = *b;
        }
    }
    out.acl = owner_only(desc.owner);
    if (auto it = cfg.find("acl"); it != cfg.end()) {
        if (auto a = parse_acl_xml(it->second, desc.owner)) {
            out.acl = std::move(*a);
        }
    }
    if (auto it = cfg.find("tagging"); it != cfg.end()) {
        if (auto t = parse_tagging(it->second)) {
            out.tags = std::move(*t);
        }
    }
    if (auto it = cfg.find("encryption"); it != cfg.end()) {
        if (auto e = parse_bucket_encryption(it->second)) {
            out.encryption = *e;
        }
    }
    if (auto it = cfg.find("lifecycle"); it != cfg.end()) {
        out.lifecycle = load_lifecycle(it->second);
    }
    if (auto it = cfg.find("replication"); it != cfg.end()) {
        out.replication = load_replication(it->second);
    }
    out.profile = for_bucket(ctx.options.profile, out.tags);

    const auto account_bpa = ctx.options.account_public_access_block
                                 ? ctx.options.account_public_access_block(desc.owner)
                                 : public_access_block{false, false, false, false};
    out.access.bucket_owner = desc.owner;
    out.access.ownership = out.ownership;
    out.access.bpa = effective(account_bpa, out.bucket_public_access_block);
    if (auto it = cfg.find("policy"); it != cfg.end()) {
        out.access.bucket_policy = it->second;
    }
    out.access.bucket_acl = &out.acl;
    out.access.source_ip = req.source_ip;
    out.access.user_agent = req.header("User-Agent").value_or("");
    out.access.region = ctx.options.region;
    out.access.secure_transport = req.secure_transport;
    out.desc = std::move(desc);
}

/// What an object entry carries about its bucket. A bucket with event
/// notifications or replication has its writes logged (`s3_change_log.hpp`).
[[nodiscard]] inline auto ref_of(const bucket_descriptor& b) -> bucket_ref {
    return {b.id, b.versioning, b.object_lock,
            b.config.contains("notification") || b.config.contains("replication")};
}

}  // namespace kythira::s3
