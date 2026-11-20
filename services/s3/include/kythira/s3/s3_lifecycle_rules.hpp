// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_lifecycle_rules.hpp
/// @brief Lifecycle configurations and storage classes
///        (.kiro/specs/s3-compatible-storage/ task 13, Requirements 7.5,
///        12.1): the rule model, its XML both ways with S3's checks, and
///        when each rule's actions fall due.
///
/// **Days.** S3 counts a rule's days from the object's creation (for
/// noncurrent actions, from when it became noncurrent: its successor's
/// creation) and rounds the result up to the next midnight UTC, so an
/// object created 15 January at 10:30 under a three-day rule expires at
/// midnight starting 19 January. `due_after` does that with a day length
/// that tests shorten (`lifecycle_day_ms`). A `Date` action applies to
/// every matching object from that midnight on.
///
/// **Which action wins.** Expiration over transition, and among due
/// transitions the coldest class, in S3's order STANDARD,
/// INTELLIGENT_TIERING, STANDARD_IA, ONEZONE_IA, GLACIER_IR, GLACIER,
/// DEEP_ARCHIVE. An object never moves to a warmer class.
///
/// **Small objects.** Since September 2024 S3 transitions nothing under
/// 128 KiB unless a rule's size filter says otherwise
/// (`x-amz-transition-default-minimum-object-size: all_storage_classes_128K`);
/// `varies_by_storage_class` keeps that minimum only for the IA classes and
/// INTELLIGENT_TIERING. The choice is stored with the configuration.

#include <kythira/s3/s3_index_records.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

inline constexpr std::uint64_t standard_day_ms = std::uint64_t{24} * 60 * 60 * 1000;
/// The smallest object S3 transitions by default.
inline constexpr std::uint64_t transition_minimum_bytes = std::uint64_t{128} * 1024;

/// Storage classes a lifecycle rule may transition to.
inline constexpr std::array<std::string_view, 6> transition_classes{
    "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE",
};

/// How cold a class is; higher is colder (and cheaper to keep).
[[nodiscard]] inline auto coldness(std::string_view storage_class) noexcept -> int {
    if (storage_class == "INTELLIGENT_TIERING") {
        return 1;
    }
    if (storage_class == "STANDARD_IA") {
        return 2;
    }
    if (storage_class == "ONEZONE_IA") {
        return 3;
    }
    if (storage_class == "GLACIER_IR") {
        return 4;
    }
    if (storage_class == "GLACIER") {
        return 5;
    }
    if (storage_class == "DEEP_ARCHIVE") {
        return 6;
    }
    return 0;  // STANDARD, REDUCED_REDUNDANCY
}

/// Classes whose objects need `RestoreObject` before a read.
[[nodiscard]] inline auto is_archive_class(std::string_view storage_class) noexcept -> bool {
    return storage_class == "GLACIER" || storage_class == "DEEP_ARCHIVE";
}

enum class transition_minimum : std::uint8_t {
    all_storage_classes_128k,
    varies_by_storage_class,
};

[[nodiscard]] inline auto to_string(transition_minimum m) -> std::string_view {
    return m == transition_minimum::varies_by_storage_class ? "varies_by_storage_class"
                                                            : "all_storage_classes_128K";
}

struct lifecycle_filter {
    std::optional<std::string> prefix;
    std::vector<std::pair<std::string, std::string>> tags;
    std::optional<std::uint64_t> size_greater;
    std::optional<std::uint64_t> size_less;
    /// The rule used the old top-level `<Prefix>` instead of `<Filter>`.
    bool legacy_prefix = false;

    friend auto operator==(const lifecycle_filter&, const lifecycle_filter&) -> bool = default;
};

struct lifecycle_transition {
    std::optional<std::uint32_t> days;
    std::optional<std::uint64_t> date_ms;
    std::string storage_class;

    friend auto operator==(const lifecycle_transition&, const lifecycle_transition&)
        -> bool = default;
};

struct noncurrent_transition {
    std::uint32_t days = 0;
    std::optional<std::uint32_t> newer_versions;
    std::string storage_class;

    friend auto operator==(const noncurrent_transition&, const noncurrent_transition&)
        -> bool = default;
};

struct lifecycle_rule {
    std::string id;
    bool enabled = true;
    lifecycle_filter filter;
    std::optional<std::uint32_t> expiration_days;
    std::optional<std::uint64_t> expiration_date_ms;
    bool expired_object_delete_marker = false;
    std::optional<std::uint32_t> noncurrent_days;
    std::optional<std::uint32_t> newer_noncurrent_versions;
    std::optional<std::uint32_t> abort_days;
    std::vector<lifecycle_transition> transitions;
    std::vector<noncurrent_transition> noncurrent_transitions;

    friend auto operator==(const lifecycle_rule&, const lifecycle_rule&) -> bool = default;
};

struct lifecycle_configuration {
    std::vector<lifecycle_rule> rules;
    transition_minimum minimum = transition_minimum::all_storage_classes_128k;

    friend auto operator==(const lifecycle_configuration&, const lifecycle_configuration&)
        -> bool = default;
};

namespace lifecycle_detail {

[[nodiscard]] inline auto argument_error(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
}
[[nodiscard]] inline auto request_error(std::string message) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidRequest", std::move(message));
}

/// A non-negative decimal integer that fits `max`.
[[nodiscard]] inline auto number(std::string_view s, std::uint64_t max)
    -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > 20) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (max - d) / 10) {
            return std::nullopt;
        }
        v = v * 10 + d;
    }
    return v;
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
[[nodiscard]] constexpr auto days_from_civil(int y, unsigned m, unsigned d) noexcept
    -> std::int64_t {
    y -= m <= 2 ? 1 : 0;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

/// A lifecycle `Date`: ISO 8601, which S3 requires to be midnight UTC
/// (`2027-01-01T00:00:00Z`, with optional milliseconds or `+00:00`).
/// nullopt when it does not parse; `midnight` says whether it was one.
struct parsed_date {
    std::uint64_t ms = 0;
    bool midnight = false;
};

[[nodiscard]] inline auto parse_date(std::string_view s) -> std::optional<parsed_date> {
    const auto digits = [&](std::size_t at, std::size_t n) -> std::optional<unsigned> {
        if (at + n > s.size()) {
            return std::nullopt;
        }
        unsigned v = 0;
        for (std::size_t i = at; i < at + n; ++i) {
            if (s[i] < '0' || s[i] > '9') {
                return std::nullopt;
            }
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
        }
        return v;
    };
    if (s.size() < 10 || s[4] != '-' || s[7] != '-') {
        return std::nullopt;
    }
    const auto y = digits(0, 4);
    const auto mo = digits(5, 2);
    const auto d = digits(8, 2);
    if (!y || !mo || !d || *mo < 1 || *mo > 12 || *d < 1 || *d > 31) {
        return std::nullopt;
    }
    unsigned h = 0;
    unsigned mi = 0;
    unsigned sec = 0;
    bool fraction_zero = true;
    auto rest = s.substr(10);
    if (!rest.empty()) {
        if (rest.size() < 9 || rest[0] != 'T' || rest[3] != ':' || rest[6] != ':') {
            return std::nullopt;
        }
        const auto hh = digits(11, 2);
        const auto mm = digits(14, 2);
        const auto ss = digits(17, 2);
        if (!hh || !mm || !ss || *hh > 23 || *mm > 59 || *ss > 60) {
            return std::nullopt;
        }
        h = *hh;
        mi = *mm;
        sec = *ss;
        rest = rest.substr(9);
        if (!rest.empty() && rest[0] == '.') {
            std::size_t i = 1;
            while (i < rest.size() && rest[i] >= '0' && rest[i] <= '9') {
                fraction_zero = fraction_zero && rest[i] == '0';
                ++i;
            }
            if (i == 1) {
                return std::nullopt;
            }
            rest = rest.substr(i);
        }
        if (rest != "Z" && rest != "+00:00" && rest != "-00:00") {
            return std::nullopt;
        }
    }
    const auto days = days_from_civil(static_cast<int>(*y), *mo, *d);
    if (days < 0) {
        return std::nullopt;
    }
    parsed_date out;
    out.ms = static_cast<std::uint64_t>(days) * standard_day_ms +
             (std::uint64_t{h} * 3600 + std::uint64_t{mi} * 60 + sec) * 1000;
    out.midnight = h == 0 && mi == 0 && sec == 0 && fraction_zero;
    return out;
}

[[nodiscard]] inline auto render_date(std::uint64_t ms) -> std::string {
    return aws_rest_xml::iso8601_ms(
        std::chrono::system_clock::time_point(std::chrono::milliseconds(ms)));
}

[[nodiscard]] inline auto parse_tag(const aws_rest_xml::xml_element& t)
    -> aws_rest_xml::result<std::pair<std::string, std::string>> {
    auto k = t.child_text("Key");
    auto v = t.child_text("Value");
    if (!k || !v) {
        return aws_rest_xml::errors::malformed_xml("a Tag needs a Key and a Value");
    }
    if (k->empty() || k->size() > 128 || v->size() > 256) {
        return aws_rest_xml::errors::make(400, "InvalidTag",
                                          "The TagKey or TagValue you have provided is invalid");
    }
    return std::pair{std::move(*k), std::move(*v)};
}

[[nodiscard]] inline auto days_of(const aws_rest_xml::xml_element& e, std::string_view name,
                                  std::string_view action, bool zero_ok = false)
    -> aws_rest_xml::result<std::optional<std::uint32_t>> {
    auto text = e.child_text(name);
    if (!text) {
        return std::optional<std::uint32_t>{};
    }
    const auto n = number(*text, 0x7FFF'FFFF);
    if (!n || (*n == 0 && !zero_ok)) {
        return lifecycle_detail::argument_error("'" + std::string(name) + "' for " +
                                                std::string(action) +
                                                " action must be a positive integer");
    }
    return std::optional<std::uint32_t>(static_cast<std::uint32_t>(*n));
}

[[nodiscard]] inline auto date_of(const aws_rest_xml::xml_element& e)
    -> aws_rest_xml::result<std::optional<std::uint64_t>> {
    auto text = e.child_text("Date");
    if (!text) {
        return std::optional<std::uint64_t>{};
    }
    const auto d = parse_date(*text);
    if (!d) {
        return lifecycle_detail::argument_error("Invalid date");
    }
    if (!d->midnight) {
        return lifecycle_detail::argument_error("'Date' must be at midnight GMT");
    }
    return std::optional<std::uint64_t>(d->ms);
}

[[nodiscard]] inline auto parse_filter(const aws_rest_xml::xml_element& f)
    -> aws_rest_xml::result<lifecycle_filter> {
    lifecycle_filter out;
    std::size_t predicates = 0;
    const auto size =
        [](const aws_rest_xml::xml_element& e,
           std::string_view name) -> aws_rest_xml::result<std::optional<std::uint64_t>> {
        auto text = e.child_text(name);
        if (!text) {
            return std::optional<std::uint64_t>{};
        }
        const auto n = number(*text, std::uint64_t{1} << 62U);
        if (!n) {
            return lifecycle_detail::argument_error("Invalid " + std::string(name));
        }
        return n;
    };
    const auto read_sizes =
        [&](const aws_rest_xml::xml_element& e) -> std::optional<aws_rest_xml::error> {
        auto gt = size(e, "ObjectSizeGreaterThan");
        if (!gt) {
            return gt.error();
        }
        auto lt = size(e, "ObjectSizeLessThan");
        if (!lt) {
            return lt.error();
        }
        out.size_greater = *gt;
        out.size_less = *lt;
        if (out.size_less && *out.size_less == 0) {
            return lifecycle_detail::argument_error("ObjectSizeLessThan must be greater than 0");
        }
        if (out.size_greater && out.size_less && *out.size_greater >= *out.size_less) {
            return lifecycle_detail::argument_error(
                "ObjectSizeGreaterThan must be less than ObjectSizeLessThan in an And");
        }
        return std::nullopt;
    };
    for (const auto& c : f.children) {
        if (c.name == "Prefix" || c.name == "Tag" || c.name == "And" ||
            c.name == "ObjectSizeGreaterThan" || c.name == "ObjectSizeLessThan") {
            ++predicates;
        } else {
            return aws_rest_xml::errors::malformed_xml("unknown Filter element " + c.name);
        }
    }
    if (predicates > 1) {
        return aws_rest_xml::errors::malformed_xml(
            "a Filter takes one of Prefix, Tag, ObjectSizeGreaterThan, ObjectSizeLessThan or And");
    }
    if (auto p = f.child_text("Prefix")) {
        out.prefix = std::move(*p);
    }
    if (const auto* t = f.child("Tag")) {
        auto tag = parse_tag(*t);
        if (!tag) {
            return tag.error();
        }
        out.tags.push_back(std::move(*tag));
    }
    if (auto e = read_sizes(f)) {
        return *e;
    }
    if (const auto* a = f.child("And")) {
        for (const auto& c : a->children) {
            if (c.name != "Prefix" && c.name != "Tag" && c.name != "ObjectSizeGreaterThan" &&
                c.name != "ObjectSizeLessThan") {
                return aws_rest_xml::errors::malformed_xml("unknown And element " + c.name);
            }
        }
        if (auto p = a->child_text("Prefix")) {
            out.prefix = std::move(*p);
        }
        std::set<std::string> seen;
        for (const auto* t : a->children_named("Tag")) {
            auto tag = parse_tag(*t);
            if (!tag) {
                return tag.error();
            }
            if (!seen.insert(tag->first).second) {
                return lifecycle_detail::argument_error("Duplicate Tag Keys are not allowed.");
            }
            out.tags.push_back(std::move(*tag));
        }
        if (auto e = read_sizes(*a)) {
            return *e;
        }
    }
    return out;
}

}  // namespace lifecycle_detail

/// A lifecycle configuration from `PutBucketLifecycleConfiguration` (or the
/// older `PutBucketLifecycle`), checked as S3 checks it.
[[nodiscard]] inline auto parse_lifecycle(std::string_view xml, transition_minimum minimum = {})
    -> aws_rest_xml::result<lifecycle_configuration> {
    using namespace lifecycle_detail;
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "LifecycleConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected LifecycleConfiguration");
    }
    const auto rules = doc->children_named("Rule");
    if (rules.empty() || rules.size() > 1000) {
        return aws_rest_xml::errors::malformed_xml("a LifecycleConfiguration has 1 to 1000 Rules");
    }
    lifecycle_configuration out;
    out.minimum = minimum;
    std::set<std::string> ids;
    std::size_t n = 0;
    for (const auto* r : rules) {
        ++n;
        lifecycle_rule rule;
        rule.id = r->child_text("ID").value_or("");
        if (rule.id.empty()) {
            rule.id = "rule-" + std::to_string(n);
        }
        if (rule.id.size() > 255) {
            return lifecycle_detail::argument_error(
                "ID length should not exceed allowed limit of 255");
        }
        if (!ids.insert(rule.id).second) {
            return lifecycle_detail::argument_error(
                "Rule ID must be unique. Found same ID for more than one rule");
        }
        const auto status = r->child_text("Status");
        if (!status || (*status != "Enabled" && *status != "Disabled")) {
            return aws_rest_xml::errors::malformed_xml("Status must be Enabled or Disabled");
        }
        rule.enabled = *status == "Enabled";
        const auto* filter = r->child("Filter");
        const auto legacy = r->child_text("Prefix");
        if ((filter != nullptr) == legacy.has_value()) {
            return aws_rest_xml::errors::malformed_xml("a Rule takes either Filter or Prefix");
        }
        if (filter != nullptr) {
            auto f = parse_filter(*filter);
            if (!f) {
                return f.error();
            }
            rule.filter = std::move(*f);
        } else {
            rule.filter.prefix = *legacy;
            rule.filter.legacy_prefix = true;
        }
        if (rule.filter.prefix && rule.filter.prefix->size() > 1024) {
            return lifecycle_detail::argument_error("The maximum size of a prefix is 1024.");
        }
        const bool tagged = !rule.filter.tags.empty();

        if (const auto* e = r->child("Expiration")) {
            auto days = days_of(*e, "Days", "Expiration");
            if (!days) {
                return days.error();
            }
            auto date = date_of(*e);
            if (!date) {
                return date.error();
            }
            const auto marker = e->child_text("ExpiredObjectDeleteMarker");
            if (marker && *marker != "true" && *marker != "false") {
                return aws_rest_xml::errors::malformed_xml(
                    "ExpiredObjectDeleteMarker must be true or false");
            }
            const int set = (*days ? 1 : 0) + (*date ? 1 : 0) + (marker ? 1 : 0);
            if (set != 1) {
                return lifecycle_detail::argument_error(
                    "ExpiredObjectDeleteMarker cannot be specified with Days or Date in a "
                    "Lifecycle Expiration Policy");
            }
            if (marker && tagged) {
                return lifecycle_detail::argument_error(
                    "ExpiredObjectDeleteMarker cannot be specified with object tags");
            }
            rule.expiration_days = *days;
            rule.expiration_date_ms = *date;
            rule.expired_object_delete_marker = marker && *marker == "true";
        }
        if (const auto* e = r->child("NoncurrentVersionExpiration")) {
            auto days = days_of(*e, "NoncurrentDays", "NoncurrentVersionExpiration");
            if (!days) {
                return days.error();
            }
            if (!*days) {
                return aws_rest_xml::errors::malformed_xml(
                    "NoncurrentVersionExpiration needs NoncurrentDays");
            }
            rule.noncurrent_days = *days;
            if (auto newer = e->child_text("NewerNoncurrentVersions")) {
                const auto v = number(*newer, 100);
                if (!v || *v == 0) {
                    return lifecycle_detail::argument_error(
                        "NewerNoncurrentVersions must be an integer between 1 and 100");
                }
                rule.newer_noncurrent_versions = static_cast<std::uint32_t>(*v);
            }
        }
        if (const auto* e = r->child("AbortIncompleteMultipartUpload")) {
            if (tagged) {
                return lifecycle_detail::argument_error(
                    "AbortIncompleteMultipartUpload cannot be specified with Tags.");
            }
            auto days = days_of(*e, "DaysAfterInitiation", "AbortIncompleteMultipartUpload");
            if (!days) {
                return days.error();
            }
            if (!*days) {
                return aws_rest_xml::errors::malformed_xml(
                    "AbortIncompleteMultipartUpload needs DaysAfterInitiation");
            }
            rule.abort_days = *days;
        }
        std::set<std::string> classes;
        for (const auto* t : r->children_named("Transition")) {
            lifecycle_transition tr;
            auto days = days_of(*t, "Days", "Transition", true);
            if (!days) {
                return days.error();
            }
            auto date = date_of(*t);
            if (!date) {
                return date.error();
            }
            if (days->has_value() == date->has_value()) {
                return aws_rest_xml::errors::malformed_xml("a Transition takes Days or Date");
            }
            tr.days = *days;
            tr.date_ms = *date;
            tr.storage_class = t->child_text("StorageClass").value_or("");
            if (std::ranges::find(transition_classes, tr.storage_class) ==
                transition_classes.end()) {
                return aws_rest_xml::errors::malformed_xml("invalid Transition StorageClass");
            }
            if ((tr.storage_class == "STANDARD_IA" || tr.storage_class == "ONEZONE_IA") &&
                tr.days && *tr.days < 30) {
                return lifecycle_detail::argument_error(
                    "'Days' in Transition action must be greater than or "
                    "equal to 30 for storageClass '" +
                    tr.storage_class + "'");
            }
            if (!classes.insert(tr.storage_class).second) {
                return lifecycle_detail::request_error(
                    "'StorageClass' must be different for 'Transition' "
                    "actions in same 'Rule'");
            }
            if (rule.expiration_days && tr.days && *tr.days >= *rule.expiration_days) {
                return lifecycle_detail::argument_error(
                    "'Days' in the Expiration action for filter must be "
                    "greater than 'Days' in the Transition action");
            }
            rule.transitions.push_back(std::move(tr));
        }
        classes.clear();
        for (const auto* t : r->children_named("NoncurrentVersionTransition")) {
            noncurrent_transition tr;
            auto days = days_of(*t, "NoncurrentDays", "NoncurrentVersionTransition", true);
            if (!days) {
                return days.error();
            }
            if (!*days) {
                return aws_rest_xml::errors::malformed_xml(
                    "NoncurrentVersionTransition needs NoncurrentDays");
            }
            tr.days = **days;
            tr.storage_class = t->child_text("StorageClass").value_or("");
            if (std::ranges::find(transition_classes, tr.storage_class) ==
                transition_classes.end()) {
                return aws_rest_xml::errors::malformed_xml(
                    "invalid NoncurrentVersionTransition StorageClass");
            }
            if ((tr.storage_class == "STANDARD_IA" || tr.storage_class == "ONEZONE_IA") &&
                tr.days < 30) {
                return lifecycle_detail::argument_error(
                    "'NoncurrentDays' in NoncurrentVersionTransition action "
                    "must be greater than or equal to 30 for storageClass '" +
                    tr.storage_class + "'");
            }
            if (auto newer = t->child_text("NewerNoncurrentVersions")) {
                const auto v = number(*newer, 100);
                if (!v || *v == 0) {
                    return lifecycle_detail::argument_error(
                        "NewerNoncurrentVersions must be an integer between 1 and 100");
                }
                tr.newer_versions = static_cast<std::uint32_t>(*v);
            }
            if (!classes.insert(tr.storage_class).second) {
                return lifecycle_detail::request_error(
                    "'StorageClass' must be different for "
                    "'NoncurrentVersionTransition' actions in same 'Rule'");
            }
            rule.noncurrent_transitions.push_back(std::move(tr));
        }
        if (!rule.expiration_days && !rule.expiration_date_ms &&
            !rule.expired_object_delete_marker && r->child("Expiration") == nullptr &&
            !rule.noncurrent_days && !rule.abort_days && rule.transitions.empty() &&
            rule.noncurrent_transitions.empty()) {
            return lifecycle_detail::request_error(
                "At least one action needs to be specified in a rule");
        }
        out.rules.push_back(std::move(rule));
    }
    return out;
}

/// The configuration as `GetBucketLifecycleConfiguration` returns it.
[[nodiscard]] inline auto lifecycle_xml(const lifecycle_configuration& c) -> std::string {
    using lifecycle_detail::render_date;
    auto w = aws_rest_xml::document("LifecycleConfiguration");
    for (const auto& r : c.rules) {
        w.open("Rule");
        w.element("ID", r.id);
        const auto& f = r.filter;
        if (f.legacy_prefix) {
            w.element("Prefix", f.prefix.value_or(""));
        } else {
            w.open("Filter");
            const int n = (f.prefix ? 1 : 0) + static_cast<int>(f.tags.size()) +
                          (f.size_greater ? 1 : 0) + (f.size_less ? 1 : 0);
            if (n > 1) {
                w.open("And");
            }
            if (f.prefix) {
                w.element("Prefix", *f.prefix);
            }
            for (const auto& [k, v] : f.tags) {
                w.open("Tag").element("Key", k).element("Value", v).close();
            }
            if (f.size_greater) {
                w.element("ObjectSizeGreaterThan", std::to_string(*f.size_greater));
            }
            if (f.size_less) {
                w.element("ObjectSizeLessThan", std::to_string(*f.size_less));
            }
            if (n > 1) {
                w.close();
            }
            w.close();
        }
        w.element("Status", r.enabled ? "Enabled" : "Disabled");
        for (const auto& t : r.transitions) {
            w.open("Transition");
            if (t.days) {
                w.element("Days", std::to_string(*t.days));
            } else if (t.date_ms) {
                w.element("Date", render_date(*t.date_ms));
            }
            w.element("StorageClass", t.storage_class).close();
        }
        if (r.expiration_days || r.expiration_date_ms || r.expired_object_delete_marker) {
            w.open("Expiration");
            if (r.expiration_days) {
                w.element("Days", std::to_string(*r.expiration_days));
            } else if (r.expiration_date_ms) {
                w.element("Date", render_date(*r.expiration_date_ms));
            } else {
                w.element("ExpiredObjectDeleteMarker", "true");
            }
            w.close();
        }
        for (const auto& t : r.noncurrent_transitions) {
            w.open("NoncurrentVersionTransition");
            w.element("NoncurrentDays", std::to_string(t.days));
            w.element("StorageClass", t.storage_class);
            if (t.newer_versions) {
                w.element("NewerNoncurrentVersions", std::to_string(*t.newer_versions));
            }
            w.close();
        }
        if (r.noncurrent_days) {
            w.open("NoncurrentVersionExpiration");
            w.element("NoncurrentDays", std::to_string(*r.noncurrent_days));
            if (r.newer_noncurrent_versions) {
                w.element("NewerNoncurrentVersions", std::to_string(*r.newer_noncurrent_versions));
            }
            w.close();
        }
        if (r.abort_days) {
            w.open("AbortIncompleteMultipartUpload")
                .element("DaysAfterInitiation", std::to_string(*r.abort_days))
                .close();
        }
        w.close();
    }
    w.close();
    return w.str();
}

/// How the configuration is kept in the bucket's catalog entry: the
/// returned document, after a line naming the transition minimum.
[[nodiscard]] inline auto stored_lifecycle(const lifecycle_configuration& c) -> std::string {
    return std::string(to_string(c.minimum)) + "\n" + lifecycle_xml(c);
}

[[nodiscard]] inline auto load_lifecycle(std::string_view stored)
    -> std::optional<lifecycle_configuration> {
    const auto nl = stored.find('\n');
    if (nl == std::string_view::npos) {
        return std::nullopt;
    }
    const auto head = stored.substr(0, nl);
    const auto minimum = head == "varies_by_storage_class"
                             ? transition_minimum::varies_by_storage_class
                             : transition_minimum::all_storage_classes_128k;
    auto c = parse_lifecycle(stored.substr(nl + 1), minimum);
    if (!c) {
        return std::nullopt;
    }
    return std::move(*c);
}

/// Stored headers of a restore: S3's own, and when it ends.
inline constexpr std::string_view restore_metadata = "x-amz-restore";
inline constexpr std::string_view restore_until_metadata = "x-kythira-restore-until";

/// When `v`'s restored copy stops being readable; 0 when it has none.
[[nodiscard]] inline auto restore_until(const object_version& v) -> std::uint64_t {
    const auto& m = v.content.system_metadata;
    if (auto it = m.find(std::string(restore_until_metadata)); it != m.end()) {
        return lifecycle_detail::number(it->second, ~std::uint64_t{0}).value_or(0);
    }
    return 0;
}

/// `403 InvalidObjectState` for an archived version that is not restored
/// at `now_ms`: what GET and a copy from it answer.
[[nodiscard]] inline auto refuse_archived(const object_version& v, std::uint64_t now_ms)
    -> std::optional<aws_rest_xml::error> {
    if (!is_archive_class(v.content.storage_class) || restore_until(v) > now_ms) {
        return std::nullopt;
    }
    auto e = aws_rest_xml::errors::make(403, "InvalidObjectState",
                                        "The operation is not valid for the object's storage "
                                        "class");
    e.extra.emplace_back("StorageClass", v.content.storage_class);
    return e;
}

// ---- evaluation ---------------------------------------------------------------

/// `days` after `from_ms`, rounded up to the next midnight (of `day_ms`
/// days).
[[nodiscard]] inline auto due_after(std::uint64_t from_ms, std::uint32_t days, std::uint64_t day_ms)
    -> std::uint64_t {
    const auto t = from_ms + std::uint64_t{days} * day_ms;
    return (t / day_ms + 1) * day_ms;
}

/// Whether `rule`'s filter takes an object of `key`, `size` and `tags`.
[[nodiscard]] inline auto matches(const lifecycle_filter& f, std::string_view key,
                                  std::uint64_t size,
                                  const std::vector<std::pair<std::string, std::string>>& tags)
    -> bool {
    if (f.prefix && !key.starts_with(*f.prefix)) {
        return false;
    }
    for (const auto& want : f.tags) {
        if (std::ranges::find(tags, want) == tags.end()) {
            return false;
        }
    }
    if (f.size_greater && size <= *f.size_greater) {
        return false;
    }
    if (f.size_less && size >= *f.size_less) {
        return false;
    }
    return true;
}

/// Whether an object of `size` may move to `storage_class` under `rule`.
[[nodiscard]] inline auto transition_size_ok(const lifecycle_configuration& c,
                                             const lifecycle_rule& rule,
                                             std::string_view storage_class, std::uint64_t size)
    -> bool {
    if (rule.filter.size_greater || rule.filter.size_less) {
        return true;  // the rule says which sizes it means
    }
    const bool minimum_applies = c.minimum == transition_minimum::all_storage_classes_128k ||
                                 storage_class == "STANDARD_IA" || storage_class == "ONEZONE_IA" ||
                                 storage_class == "INTELLIGENT_TIERING";
    return !minimum_applies || size >= transition_minimum_bytes;
}

/// The earliest expiration of the current version `v` under the enabled
/// rules, with the rule's id: the `x-amz-expiration` header.
[[nodiscard]] inline auto expiration_of(
    const lifecycle_configuration& c, const object_version& v,
    const std::vector<std::pair<std::string, std::string>>& tags, std::uint64_t day_ms)
    -> std::optional<std::pair<std::uint64_t, std::string>> {
    std::optional<std::pair<std::uint64_t, std::string>> best;
    for (const auto& r : c.rules) {
        if (!r.enabled || !matches(r.filter, v.key, v.content.size(), tags)) {
            continue;
        }
        std::optional<std::uint64_t> due;
        if (r.expiration_days) {
            due = due_after(v.last_modified_ms, *r.expiration_days, day_ms);
        } else if (r.expiration_date_ms) {
            due = std::max(*r.expiration_date_ms, v.last_modified_ms);
        }
        if (due && (!best || *due < best->first)) {
            best = std::pair{*due, r.id};
        }
    }
    return best;
}

/// `expiry-date="Fri, 23 Dec 2012 00:00:00 GMT", rule-id="..."`.
[[nodiscard]] inline auto expiration_header(const std::pair<std::uint64_t, std::string>& e)
    -> std::string {
    return "expiry-date=\"" +
           aws_rest_xml::http_date(
               std::chrono::system_clock::time_point(std::chrono::milliseconds(e.first))) +
           "\", rule-id=\"" + e.second + "\"";
}

}  // namespace kythira::s3
