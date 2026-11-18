// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_compat.hpp
/// @brief The compatibility profile (.kiro/specs/s3-compatible-storage/
///        task 7, Requirement 3).
///
/// The `aws` profile is the default and is S3: its limits, its defaults
/// for new buckets, its error shapes. An operator can relax the limits for
/// the cluster, and a bucket can override them with `kythira:compat:*`
/// tags, the bucket's value winning (3.2):
///
/// | Tag | Field | S3 |
/// |---|---|---|
/// | `kythira:compat:max-object-bytes` | `max_object_bytes` | 5 TiB |
/// | `kythira:compat:max-put-bytes` | `max_put_bytes` | 5 GiB |
/// | `kythira:compat:max-parts` | `max_parts` | 10,000 |
/// | `kythira:compat:min-part-bytes` | `min_part_bytes` | 5 MiB |
/// | `kythira:compat:put-rate` | `prefix_put_rate` | 3,500/s |
/// | `kythira:compat:get-rate` | `prefix_get_rate` | 5,500/s |
///
/// Bucket count per account and the defaults for new buckets (Object
/// Ownership `BucketOwnerEnforced`, Block Public Access on) are cluster
/// settings only: a bucket's tags cannot exist before the bucket.
/// Error codes, messages and statuses are never relaxed (3.3).

#include <kythira/s3/s3_access.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

struct compat_profile {
    std::uint64_t max_object_bytes = std::uint64_t{5} << 40U;
    std::uint64_t max_put_bytes = std::uint64_t{5} << 30U;
    std::uint64_t max_parts = 10'000;
    std::uint64_t min_part_bytes = std::uint64_t{5} << 20U;
    std::uint64_t prefix_put_rate = 3'500;
    std::uint64_t prefix_get_rate = 5'500;
    /// S3's default general purpose bucket quota per account.
    std::uint64_t max_buckets_per_account = 10'000;
    object_ownership default_ownership = object_ownership::bucket_owner_enforced;
    public_access_block default_public_access_block;

    friend auto operator==(const compat_profile&, const compat_profile&) -> bool = default;
};

inline constexpr std::string_view compat_tag_prefix = "kythira:compat:";

/// The tags a `<Tagging>` document sets, in order.
[[nodiscard]] inline auto parse_tagging(std::string_view xml)
    -> aws_rest_xml::result<std::vector<std::pair<std::string, std::string>>> {
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "Tagging") {
        return aws_rest_xml::errors::malformed_xml("root is not Tagging");
    }
    const auto* set = doc->child("TagSet");
    if (set == nullptr) {
        return aws_rest_xml::errors::malformed_xml("no TagSet");
    }
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto* t : set->children_named("Tag")) {
        auto k = t->child_text("Key");
        auto v = t->child_text("Value");
        if (!k || !v) {
            return aws_rest_xml::errors::malformed_xml("a Tag needs a Key and a Value");
        }
        out.emplace_back(std::move(*k), std::move(*v));
    }
    return out;
}

namespace compat_detail {

[[nodiscard]] inline auto to_u64(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > 19) {
        return std::nullopt;
    }
    std::uint64_t n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        n = n * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return n;
}

}  // namespace compat_detail

/// The cluster's profile with a bucket's `kythira:compat:*` tags applied.
/// A tag with an unknown name or a value that is not a number is ignored
/// (it is still an ordinary tag).
[[nodiscard]] inline auto for_bucket(compat_profile cluster,
                                     const std::vector<std::pair<std::string, std::string>>& tags)
    -> compat_profile {
    static const std::map<std::string, std::uint64_t compat_profile::*, std::less<>> fields{
        {"max-object-bytes", &compat_profile::max_object_bytes},
        {"max-put-bytes", &compat_profile::max_put_bytes},
        {"max-parts", &compat_profile::max_parts},
        {"min-part-bytes", &compat_profile::min_part_bytes},
        {"put-rate", &compat_profile::prefix_put_rate},
        {"get-rate", &compat_profile::prefix_get_rate},
    };
    for (const auto& [k, v] : tags) {
        if (!k.starts_with(compat_tag_prefix)) {
            continue;
        }
        const auto it = fields.find(std::string_view(k).substr(compat_tag_prefix.size()));
        const auto n = compat_detail::to_u64(v);
        if (it != fields.end() && n) {
            cluster.*(it->second) = *n;
        }
    }
    return cluster;
}

/// The profile for a bucket whose stored config is `config` (its
/// `tagging` document, if any).
[[nodiscard]] inline auto for_bucket(const compat_profile& cluster,
                                     const std::map<std::string, std::string>& config)
    -> compat_profile {
    const auto it = config.find("tagging");
    if (it == config.end()) {
        return cluster;
    }
    auto tags = parse_tagging(it->second);
    return tags ? for_bucket(cluster, *tags) : cluster;
}

}  // namespace kythira::s3
