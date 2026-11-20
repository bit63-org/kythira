// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_replication_rules.hpp
/// @brief A bucket's replication configuration: S3's XML both ways, S3's
///        checks on it, and which destinations a new version goes to
///        (.kiro/specs/s3-compatible-storage/ task 14, Requirement 12.3).
///
/// Both schema versions are read. The current one (rules with `Filter`)
/// takes `Priority`, `DeleteMarkerReplication` and filters by prefix and
/// tags; the original one (rules with a top-level `Prefix`) neither, and
/// its prefixes may not overlap. One configuration may not mix them.
///
/// A new version goes to every destination bucket whose rules match it:
/// per destination, the matching enabled rule with the highest priority
/// decides (the original schema has at most one per key). An object
/// encrypted with SSE-KMS goes only where the rule opts into
/// `SseKmsEncryptedObjects`; an SSE-C object goes nowhere, since the
/// replicator cannot read it (`doc/unsupported.md`).
///
/// What is stored and echoed but not acted on: `ReplicaModifications`,
/// `ReplicationTime` and `Metrics` (no replication metrics or time
/// control), and `AccessControlTranslation` (buckets default to
/// BucketOwnerEnforced, where ACLs do not move ownership).
/// `ExistingObjectReplication` would need batch replication and is refused.

#include <kythira/s3/s3_lifecycle_rules.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

struct replication_rule {
    std::string id;
    std::optional<std::uint32_t> priority;
    bool enabled = true;
    /// Prefix and tags only (no sizes); `legacy_prefix` marks the original
    /// schema.
    lifecycle_filter filter;
    /// `arn:aws:s3:::<bucket>`.
    std::string destination;
    std::string destination_account;
    std::string storage_class;
    bool owner_override = false;
    std::string replica_kms_key;
    bool delete_markers = false;
    bool sse_kms = false;
    bool replica_modifications = false;
    std::optional<std::uint32_t> replication_time_minutes;
    std::optional<std::uint32_t> metrics_minutes;
    bool metrics = false;

    /// The destination bucket's name.
    [[nodiscard]] auto destination_bucket() const -> std::string {
        const auto colons = destination.find(":::");
        return colons == std::string::npos ? destination : destination.substr(colons + 3);
    }

    friend auto operator==(const replication_rule&, const replication_rule&) -> bool = default;
};

struct replication_configuration {
    std::string role;
    std::vector<replication_rule> rules;

    friend auto operator==(const replication_configuration&, const replication_configuration&)
        -> bool = default;
};

namespace replication_detail {

[[nodiscard]] inline auto invalid_request(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

[[nodiscard]] inline auto bad_argument(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
}

/// `<X><Status>Enabled|Disabled</Status></X>`; none when absent.
[[nodiscard]] inline auto status_of(const aws_rest_xml::xml_element* e)
    -> aws_rest_xml::result<std::optional<bool>> {
    if (e == nullptr) {
        return std::optional<bool>{};
    }
    const auto s = e->child_text("Status");
    if (!s || (*s != "Enabled" && *s != "Disabled")) {
        return aws_rest_xml::errors::malformed_xml(e->name + " Status must be Enabled or Disabled");
    }
    return std::optional<bool>(*s == "Enabled");
}

[[nodiscard]] inline auto minutes_of(const aws_rest_xml::xml_element* e)
    -> std::optional<std::uint32_t> {
    if (e == nullptr) {
        return std::nullopt;
    }
    if (auto n = lifecycle_detail::number(e->child_text("Minutes").value_or(""), 100'000)) {
        return static_cast<std::uint32_t>(*n);
    }
    return std::nullopt;
}

[[nodiscard]] inline auto parse_rule(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<replication_rule> {
    replication_rule r;
    r.id = e.child_text("ID").value_or("");
    if (r.id.size() > 255) {
        return bad_argument("ID length should not exceed allowed limit of 255");
    }
    const auto status = e.child_text("Status");
    if (!status || (*status != "Enabled" && *status != "Disabled")) {
        return aws_rest_xml::errors::malformed_xml("a Rule Status must be Enabled or Disabled");
    }
    r.enabled = *status == "Enabled";
    if (auto p = e.child_text("Priority")) {
        const auto n = lifecycle_detail::number(*p, 0x7FFFFFFF);
        if (!n) {
            return bad_argument("Priority must be a non-negative integer");
        }
        r.priority = static_cast<std::uint32_t>(*n);
    }
    const auto* filter = e.child("Filter");
    const auto legacy = e.child_text("Prefix");
    if (filter != nullptr && legacy) {
        return aws_rest_xml::errors::malformed_xml("a Rule takes Filter or Prefix, not both");
    }
    if (filter != nullptr) {
        auto f = lifecycle_detail::parse_filter(*filter);
        if (!f) {
            return f.error();
        }
        if (f->size_greater || f->size_less) {
            return aws_rest_xml::errors::malformed_xml("a replication Filter takes no sizes");
        }
        r.filter = std::move(*f);
    } else {
        r.filter.prefix = legacy.value_or("");
        r.filter.legacy_prefix = true;
    }
    const auto* dest = e.child("Destination");
    if (dest == nullptr) {
        return aws_rest_xml::errors::malformed_xml("a Rule needs a Destination");
    }
    r.destination = dest->child_text("Bucket").value_or("");
    if (!r.destination.starts_with("arn:") || r.destination.find(":s3:::") == std::string::npos ||
        r.destination_bucket().empty()) {
        return bad_argument("Invalid bucket ARN.");
    }
    r.destination_account = dest->child_text("Account").value_or("");
    r.storage_class = dest->child_text("StorageClass").value_or("");
    if (const auto* act = dest->child("AccessControlTranslation")) {
        if (act->child_text("Owner").value_or("") != "Destination") {
            return aws_rest_xml::errors::malformed_xml(
                "AccessControlTranslation Owner must be "
                "Destination");
        }
        if (r.destination_account.empty()) {
            return invalid_request(
                "Account is required when AccessControlTranslation is specified.");
        }
        r.owner_override = true;
    }
    if (const auto* enc = dest->child("EncryptionConfiguration")) {
        r.replica_kms_key = enc->child_text("ReplicaKmsKeyID").value_or("");
    }
    auto rtc = status_of(dest->child("ReplicationTime"));
    if (!rtc) {
        return rtc.error();
    }
    if (rtc->value_or(false)) {
        r.replication_time_minutes =
            minutes_of(dest->child("ReplicationTime")->child("Time")).value_or(15);
    }
    auto metrics = status_of(dest->child("Metrics"));
    if (!metrics) {
        return metrics.error();
    }
    r.metrics = metrics->value_or(false);
    if (r.metrics) {
        r.metrics_minutes = minutes_of(dest->child("Metrics")->child("EventThreshold"));
    }
    if (const auto* ssc = e.child("SourceSelectionCriteria")) {
        auto kms = status_of(ssc->child("SseKmsEncryptedObjects"));
        if (!kms) {
            return kms.error();
        }
        r.sse_kms = kms->value_or(false);
        auto mods = status_of(ssc->child("ReplicaModifications"));
        if (!mods) {
            return mods.error();
        }
        r.replica_modifications = mods->value_or(false);
    }
    if (r.sse_kms != !r.replica_kms_key.empty()) {
        return invalid_request(
            r.sse_kms
                ? "ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present."
                : "SseKmsEncryptedObjects must be specified if EncryptionConfiguration is "
                  "present.");
    }
    auto markers = status_of(e.child("DeleteMarkerReplication"));
    if (!markers) {
        return markers.error();
    }
    if (filter != nullptr && !markers->has_value()) {
        return invalid_request(
            "DeleteMarkerReplication must be specified for this version of Cross Region "
            "Replication configuration schema.");
    }
    if (filter == nullptr && markers->has_value()) {
        return aws_rest_xml::errors::malformed_xml(
            "DeleteMarkerReplication needs the Filter form of a Rule");
    }
    r.delete_markers = markers->value_or(false);
    if (r.delete_markers && !r.filter.tags.empty()) {
        return invalid_request(
            "Delete marker replication is not supported if any Tag filter is "
            "specified.");
    }
    auto existing = status_of(e.child("ExistingObjectReplication"));
    if (!existing) {
        return existing.error();
    }
    if (existing->value_or(false)) {
        return aws_rest_xml::errors::make(
            501, "NotImplemented",
            "A header you provided implies functionality that is not implemented");
    }
    return r;
}

}  // namespace replication_detail

/// `<ReplicationConfiguration>` as PutBucketReplication sends it. The
/// caller checks what depends on buckets (versioning, the destination).
[[nodiscard]] inline auto parse_replication_configuration(std::string_view xml)
    -> aws_rest_xml::result<replication_configuration> {
    using namespace replication_detail;
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "ReplicationConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected ReplicationConfiguration");
    }
    replication_configuration out;
    out.role = doc->child_text("Role").value_or("");
    if (out.role.empty()) {
        return aws_rest_xml::errors::malformed_xml("a ReplicationConfiguration needs a Role");
    }
    const auto rules = doc->children_named("Rule");
    if (rules.empty()) {
        return aws_rest_xml::errors::malformed_xml("a ReplicationConfiguration needs a Rule");
    }
    if (rules.size() > 1000) {
        return invalid_request("The number of rules exceeds the limit of 1000.");
    }
    for (const auto& c : doc->children) {
        if (c.name != "Role" && c.name != "Rule") {
            return aws_rest_xml::errors::malformed_xml("unknown ReplicationConfiguration element " +
                                                       c.name);
        }
    }
    std::set<std::string> ids;
    std::set<std::uint32_t> priorities;
    for (std::size_t i = 0; i < rules.size(); ++i) {
        auto r = parse_rule(*rules[i]);
        if (!r) {
            return r.error();
        }
        if (r->id.empty()) {
            r->id = "rule-" + std::to_string(i + 1);
        }
        if (!ids.insert(r->id).second) {
            return bad_argument("Rule Id must be unique.");
        }
        out.rules.push_back(std::move(*r));
    }
    const bool legacy = out.rules.front().filter.legacy_prefix;
    for (const auto& r : out.rules) {
        if (r.filter.legacy_prefix != legacy) {
            return aws_rest_xml::errors::malformed_xml(
                "the Filter and Prefix forms of a Rule cannot be mixed");
        }
    }
    if (legacy) {
        for (std::size_t i = 0; i < out.rules.size(); ++i) {
            for (std::size_t j = i + 1; j < out.rules.size(); ++j) {
                const auto& a = out.rules[i].filter.prefix.value_or("");
                const auto& b = out.rules[j].filter.prefix.value_or("");
                if (a.starts_with(b) || b.starts_with(a)) {
                    return invalid_request("Found overlapping prefixes '" + a + "' and '" + b +
                                           "' for same destination bucket.");
                }
            }
        }
    } else {
        for (auto& r : out.rules) {
            if (!r.priority) {
                if (out.rules.size() > 1) {
                    return invalid_request(
                        "Priority must be specified for this version of Cross Region "
                        "Replication configuration schema.");
                }
                r.priority = 0;
            }
            if (!priorities.insert(*r.priority).second) {
                return invalid_request("Found duplicate priority " + std::to_string(*r.priority) +
                                       " when multiple rules apply to the same object.");
            }
        }
    }
    return out;
}

[[nodiscard]] inline auto replication_xml(const replication_configuration& c) -> std::string {
    auto w = aws_rest_xml::document("ReplicationConfiguration");
    w.element("Role", c.role);
    const auto status = [&](std::string_view element, bool on) {
        w.open(element).element("Status", on ? "Enabled" : "Disabled").close();
    };
    for (const auto& r : c.rules) {
        w.open("Rule");
        w.element("ID", r.id);
        if (r.priority && !r.filter.legacy_prefix) {
            w.element("Priority", std::to_string(*r.priority));
        }
        w.element("Status", r.enabled ? "Enabled" : "Disabled");
        if (r.filter.legacy_prefix) {
            w.element("Prefix", r.filter.prefix.value_or(""));
        } else {
            w.open("Filter");
            const auto n = (r.filter.prefix ? 1U : 0U) + r.filter.tags.size();
            if (n > 1) {
                w.open("And");
            }
            if (r.filter.prefix) {
                w.element("Prefix", *r.filter.prefix);
            }
            for (const auto& [k, v] : r.filter.tags) {
                w.open("Tag").element("Key", k).element("Value", v).close();
            }
            if (n > 1) {
                w.close();
            }
            w.close();
        }
        if (r.sse_kms || r.replica_modifications) {
            w.open("SourceSelectionCriteria");
            if (r.sse_kms) {
                status("SseKmsEncryptedObjects", true);
            }
            if (r.replica_modifications) {
                status("ReplicaModifications", true);
            }
            w.close();
        }
        w.open("Destination");
        w.element("Bucket", r.destination);
        if (!r.destination_account.empty()) {
            w.element("Account", r.destination_account);
        }
        if (!r.storage_class.empty()) {
            w.element("StorageClass", r.storage_class);
        }
        if (r.owner_override) {
            w.open("AccessControlTranslation").element("Owner", "Destination").close();
        }
        if (!r.replica_kms_key.empty()) {
            w.open("EncryptionConfiguration").element("ReplicaKmsKeyID", r.replica_kms_key).close();
        }
        if (r.replication_time_minutes) {
            w.open("ReplicationTime").element("Status", "Enabled");
            w.open("Time").element("Minutes", std::to_string(*r.replication_time_minutes)).close();
            w.close();
        }
        if (r.metrics) {
            w.open("Metrics").element("Status", "Enabled");
            if (r.metrics_minutes) {
                w.open("EventThreshold")
                    .element("Minutes", std::to_string(*r.metrics_minutes))
                    .close();
            }
            w.close();
        }
        w.close();
        if (!r.filter.legacy_prefix) {
            status("DeleteMarkerReplication", r.delete_markers);
        }
        w.close();
    }
    w.close();
    return w.str();
}

/// A bucket's stored configuration; none when absent or unreadable.
[[nodiscard]] inline auto load_replication(std::string_view stored)
    -> std::optional<replication_configuration> {
    auto c = parse_replication_configuration(stored);
    if (!c) {
        return std::nullopt;
    }
    return std::move(*c);
}

/// The rule that decides for each destination a version goes to.
/// `kms`: the version is encrypted with SSE-KMS.
[[nodiscard]] inline auto replication_rules_for(
    const replication_configuration& c, std::string_view key,
    const std::vector<std::pair<std::string, std::string>>& tags, bool kms)
    -> std::vector<const replication_rule*> {
    std::map<std::string, const replication_rule*> best;
    for (const auto& r : c.rules) {
        if (!r.enabled || !matches(r.filter, key, 0, tags) || (kms && !r.sse_kms)) {
            continue;
        }
        auto& slot = best[r.destination];
        if (slot == nullptr || r.priority.value_or(0) > slot->priority.value_or(0)) {
            slot = &r;
        }
    }
    std::vector<const replication_rule*> out;
    out.reserve(best.size());
    for (const auto& [dest, r] : best) {
        out.push_back(r);
    }
    return out;
}

/// The rules that replicate a delete marker on `key` (by prefix: tag
/// filters cannot replicate markers).
[[nodiscard]] inline auto delete_marker_rules_for(const replication_configuration& c,
                                                  std::string_view key)
    -> std::vector<const replication_rule*> {
    std::vector<const replication_rule*> out;
    for (const auto* r : replication_rules_for(c, key, {}, false)) {
        if (r->delete_markers) {
            out.push_back(r);
        }
    }
    return out;
}

}  // namespace kythira::s3
