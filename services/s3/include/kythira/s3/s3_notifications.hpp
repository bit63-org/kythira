// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_notifications.hpp
/// @brief Event notifications: the bucket configuration, S3's event JSON,
///        the API operations and the worker that delivers them
///        (.kiro/specs/s3-compatible-storage/ task 14, Requirement 12.2).
///
/// **Configuration.** `PutBucketNotificationConfiguration` stores the
/// bucket's `<NotificationConfiguration>` (sub-resource `notification`),
/// checked as S3 checks it: known event types, at most one prefix and one
/// suffix rule per filter, well-formed destination ARNs, unique ids (made
/// up when absent), and no two configurations whose event types, prefixes
/// and suffixes overlap ("Configuration is ambiguously defined"). An empty
/// configuration removes it. Destinations are SQS queues
/// (`QueueConfiguration`), SNS topics (`TopicConfiguration`), and,
/// as a Kythira extension that real S3 does not accept, Kinesis streams
/// (`KinesisStreamConfiguration` with a `Stream` ARN). Lambda functions
/// and EventBridge have nothing to deliver to in Kythira and are refused
/// (`doc/unsupported.md`). Before storing, a `s3:TestEvent` goes to each
/// destination, as on S3, unless `x-amz-skip-destination-validation` is
/// set or no sink is configured; a destination that refuses it fails the
/// request ("Unable to validate the following destination
/// configurations"). The deprecated `GetBucketNotification` and
/// `PutBucketNotification` read and write the same configuration in the
/// old one-per-kind form.
///
/// **Delivery** (`notification_worker`, one per index group, on the
/// metadata leader, task 16). It reads the group's change log after its
/// cursor (`s3_change_log.hpp`), and for every record whose bucket's
/// configuration matches (event type, then key prefix and suffix) builds
/// S3's event JSON and hands it to the sink, in log order. When a
/// destination fails it stops there, so one key's events never overtake
/// each other, and retries on the next run; a destination that fails
/// permanently, or `max_attempts` runs in a row, is skipped for that
/// record and counted as dropped (S3 drops events for a destination that
/// stays unavailable). The cursor advances through the log after each run,
/// so a new leader resumes there: delivery is at least once.
///
/// **Event JSON** follows S3's documented structure (event version 2.1;
/// 2.3 for lifecycle, tagging, ACL and restore-deletion events), with the
/// key form-encoded as S3 does and the change log sequence as the
/// `sequencer`. `userIdentity` is the account the write was made for, not
/// the IAM principal, and `sourceIPAddress` is empty: the index does not
/// record either.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_change_log.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_event_sinks.hpp>
#include <kythira/s3/s3_metadata.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <openssl/sha.h>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// One destination and what it hears about.
struct notification_target {
    std::string id;
    destination_kind kind = destination_kind::queue;
    std::string arn;
    /// As configured (`s3:ObjectCreated:*`).
    std::vector<std::string> events;
    std::string prefix;
    std::string suffix;

    friend auto operator==(const notification_target&, const notification_target&)
        -> bool = default;
};

struct notification_configuration {
    std::vector<notification_target> targets;

    [[nodiscard]] auto empty() const -> bool { return targets.empty(); }

    friend auto operator==(const notification_configuration&, const notification_configuration&)
        -> bool = default;
};

namespace notification_detail {

/// Every event type the model names. Some never fire in Kythira (lost
/// reduced-redundancy objects, replication metrics, Intelligent-Tiering
/// archives) but are accepted, as S3 accepts them on any bucket.
inline constexpr std::array<std::string_view, 30> known_events{
    "s3:ReducedRedundancyLostObject",
    "s3:ObjectCreated:*",
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Post",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectRemoved:*",
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
    "s3:ObjectRestore:*",
    "s3:ObjectRestore:Post",
    "s3:ObjectRestore:Completed",
    "s3:Replication:*",
    "s3:Replication:OperationFailedReplication",
    "s3:Replication:OperationNotTracked",
    "s3:Replication:OperationMissedThreshold",
    "s3:Replication:OperationReplicatedAfterThreshold",
    "s3:ObjectRestore:Delete",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:ObjectAcl:Put",
    "s3:LifecycleExpiration:*",
    "s3:LifecycleExpiration:Delete",
    "s3:LifecycleExpiration:DeleteMarkerCreated",
    "s3:ObjectTagging:*",
    "s3:ObjectTagging:Put",
    "s3:ObjectTagging:Delete",
    "s3:TestEvent",
    "s3:ObjectAcl:*",
    "s3:LifecycleTransition:*",
};

[[nodiscard]] inline auto known_event(std::string_view e) -> bool {
    // TestEvent and the last two are not configurable.
    for (std::size_t i = 0; i < known_events.size() - 3; ++i) {
        if (known_events[i] == e) {
            return true;
        }
    }
    return false;
}

/// Whether the configured pattern (`s3:ObjectCreated:*`) covers the
/// event name (`ObjectCreated:Put`, as change records name it).
[[nodiscard]] inline auto covers(std::string_view pattern, std::string_view name) -> bool {
    if (!pattern.starts_with("s3:")) {
        return false;
    }
    pattern.remove_prefix(3);
    if (pattern.ends_with(":*")) {
        pattern.remove_suffix(1);  // keep the colon
        return name.starts_with(pattern);
    }
    return pattern == name;
}

/// Whether two configured patterns can both match one event.
[[nodiscard]] inline auto events_overlap(std::string_view a, std::string_view b) -> bool {
    const auto family = [](std::string_view p) {
        p.remove_prefix(std::min<std::size_t>(3, p.size()));
        const auto colon = p.find(':');
        return p.substr(0, colon);
    };
    if (a == b) {
        return true;
    }
    if (family(a) != family(b)) {
        return false;
    }
    return a.ends_with(":*") || b.ends_with(":*");
}

[[nodiscard]] inline auto argument_error(std::string message, std::string name = {},
                                         std::string value = {}) -> aws_rest_xml::error {
    auto e = aws_rest_xml::errors::make(400, "InvalidArgument", std::move(message));
    if (!name.empty()) {
        e.extra.emplace_back("ArgumentName", std::move(name));
        e.extra.emplace_back("ArgumentValue", std::move(value));
    }
    return e;
}

[[nodiscard]] inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    for (auto& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

/// An id for a configuration that has none: stable for the same
/// configuration, as base64 of a digest of what it says.
[[nodiscard]] inline auto made_up_id(const notification_target& t, std::size_t n) -> std::string {
    std::string what = std::to_string(n) + "\n" + t.arn + "\n" + t.prefix + "\n" + t.suffix;
    for (const auto& e : t.events) {
        what += "\n" + e;
    }
    std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
    SHA256(reinterpret_cast<const unsigned char*>(what.data()), what.size(),  // NOLINT
           md.data());
    return aws_json::base64_encode(std::as_bytes(std::span<const unsigned char>(md.data(), 18)));
}

struct kind_names {
    destination_kind kind;
    std::string_view element;  ///< `QueueConfiguration`
    std::string_view arn;      ///< `Queue`
};

inline constexpr std::array<kind_names, 3> kinds{{
    {destination_kind::topic, "TopicConfiguration", "Topic"},
    {destination_kind::queue, "QueueConfiguration", "Queue"},
    {destination_kind::stream, "KinesisStreamConfiguration", "Stream"},
}};

[[nodiscard]] inline auto names_of(destination_kind k) -> const kind_names& {
    for (const auto& n : kinds) {
        if (n.kind == k) {
            return n;
        }
    }
    return kinds[0];
}

/// One `<...Configuration>` element; `legacy` reads the deprecated form,
/// whose events may be one `Event` or several.
[[nodiscard]] inline auto parse_target(const aws_rest_xml::xml_element& e, const kind_names& k)
    -> aws_rest_xml::result<notification_target> {
    notification_target t;
    t.kind = k.kind;
    t.id = e.child_text("Id").value_or("");
    auto arn = e.child_text(k.arn);
    if (!arn || arn->empty()) {
        return aws_rest_xml::errors::malformed_xml(std::string(k.element) + " needs a " +
                                                   std::string(k.arn));
    }
    if (!destination_arn_ok(k.kind, *arn)) {
        return argument_error("The ARN is not well formed", std::string(k.arn), *arn);
    }
    t.arn = std::move(*arn);
    for (const auto* ev : e.children_named("Event")) {
        if (!known_event(ev->text)) {
            return argument_error("The event is not supported for notifications", "Event",
                                  ev->text);
        }
        if (std::ranges::find(t.events, ev->text) == t.events.end()) {
            t.events.push_back(ev->text);
        }
    }
    if (t.events.empty()) {
        return aws_rest_xml::errors::malformed_xml(std::string(k.element) +
                                                   " needs at least one Event");
    }
    if (const auto* f = e.child("Filter")) {
        const auto* key = f->child("S3Key");
        if (key == nullptr || f->children.size() != 1) {
            return aws_rest_xml::errors::malformed_xml("a Filter holds one S3Key");
        }
        bool prefix = false;
        bool suffix = false;
        for (const auto& rule : key->children) {
            if (rule.name != "FilterRule") {
                return aws_rest_xml::errors::malformed_xml("unknown S3Key element " + rule.name);
            }
            const auto name = lower(rule.child_text("Name").value_or(""));
            auto value = rule.child_text("Value").value_or("");
            if (value.size() > 1024) {
                return argument_error("FilterRule value is too long", "FilterRule", value);
            }
            if (name == "prefix") {
                if (prefix) {
                    return argument_error("Cannot specify more than one prefix rule in a filter.",
                                          "FilterRule", "prefix");
                }
                prefix = true;
                t.prefix = std::move(value);
            } else if (name == "suffix") {
                if (suffix) {
                    return argument_error("Cannot specify more than one suffix rule in a filter.",
                                          "FilterRule", "suffix");
                }
                suffix = true;
                t.suffix = std::move(value);
            } else {
                return argument_error("filter rule name must be either prefix or suffix",
                                      "FilterRule", name);
            }
        }
    }
    return t;
}

/// S3's checks across configurations: unique ids (made up when absent)
/// and no overlap.
[[nodiscard]] inline auto check_targets(notification_configuration& c)
    -> std::optional<aws_rest_xml::error> {
    std::set<std::string> ids;
    for (std::size_t i = 0; i < c.targets.size(); ++i) {
        auto& t = c.targets[i];
        if (t.id.empty()) {
            t.id = made_up_id(t, i);
        }
        if (t.id.size() > 1024) {
            return argument_error("The notification id is too long", "Id", t.id);
        }
        if (!ids.insert(t.id).second) {
            return argument_error("Configurations must have unique ids", "Id", t.id);
        }
    }
    for (std::size_t i = 0; i < c.targets.size(); ++i) {
        for (std::size_t j = i + 1; j < c.targets.size(); ++j) {
            const auto& a = c.targets[i];
            const auto& b = c.targets[j];
            bool events = false;
            for (const auto& x : a.events) {
                for (const auto& y : b.events) {
                    events = events || events_overlap(x, y);
                }
            }
            const bool prefixes = a.prefix.starts_with(b.prefix) || b.prefix.starts_with(a.prefix);
            const bool suffixes = a.suffix.ends_with(b.suffix) || b.suffix.ends_with(a.suffix);
            if (events && prefixes && suffixes) {
                return argument_error(
                    "Configuration is ambiguously defined. Cannot have overlapping suffixes in two "
                    "rules if the prefixes are overlapping for the same event type.",
                    "Event", a.events.front());
            }
        }
    }
    return std::nullopt;
}

}  // namespace notification_detail

/// `<NotificationConfiguration>` as PutBucketNotificationConfiguration
/// sends it.
[[nodiscard]] inline auto parse_notification_configuration(std::string_view xml)
    -> aws_rest_xml::result<notification_configuration> {
    using namespace notification_detail;
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "NotificationConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected NotificationConfiguration");
    }
    notification_configuration out;
    for (const auto& child : doc->children) {
        if (child.name == "CloudFunctionConfiguration") {
            return argument_error("Unable to validate the following destination configurations",
                                  child.child_text("CloudFunction").value_or(""),
                                  "Kythira has no Lambda functions to invoke");
        }
        if (child.name == "EventBridgeConfiguration") {
            return not_implemented();
        }
        const auto* k = std::ranges::find_if(
            kinds, [&](const kind_names& n) { return n.element == child.name; });
        if (k == kinds.end()) {
            return aws_rest_xml::errors::malformed_xml(
                "unknown NotificationConfiguration element " + child.name);
        }
        auto t = parse_target(child, *k);
        if (!t) {
            return t.error();
        }
        out.targets.push_back(std::move(*t));
    }
    if (auto e = check_targets(out)) {
        return *e;
    }
    return out;
}

/// The deprecated form (PutBucketNotification): at most one configuration
/// per kind, with `Event` or `Events`.
[[nodiscard]] inline auto parse_legacy_notification(std::string_view xml)
    -> aws_rest_xml::result<notification_configuration> {
    using namespace notification_detail;
    auto doc = aws_rest_xml::parse_xml(xml);
    if (!doc) {
        return doc.error();
    }
    if (doc->name != "NotificationConfiguration") {
        return aws_rest_xml::errors::malformed_xml("expected NotificationConfiguration");
    }
    notification_configuration out;
    for (const auto& child : doc->children) {
        if (child.name == "CloudFunctionConfiguration") {
            return argument_error("Unable to validate the following destination configurations",
                                  child.child_text("CloudFunction").value_or(""),
                                  "Kythira has no Lambda functions to invoke");
        }
        if (child.name != "TopicConfiguration" && child.name != "QueueConfiguration") {
            return aws_rest_xml::errors::malformed_xml(
                "unknown NotificationConfiguration element " + child.name);
        }
        if (doc->children_named(child.name).size() > 1) {
            return aws_rest_xml::errors::malformed_xml("the deprecated form takes one " +
                                                       child.name);
        }
        if (child.child("Filter") != nullptr) {
            return aws_rest_xml::errors::malformed_xml("the deprecated form takes no Filter");
        }
        aws_rest_xml::xml_element flat = child;
        if (const auto* events = child.child("Events")) {
            // Some clients wrap the list; the model flattens it.
            std::erase_if(flat.children,
                          [](const aws_rest_xml::xml_element& c) { return c.name == "Events"; });
            for (const auto& ev : events->children) {
                flat.children.push_back(ev);
            }
        }
        const auto& k = names_of(child.name == "TopicConfiguration" ? destination_kind::topic
                                                                    : destination_kind::queue);
        auto t = parse_target(flat, k);
        if (!t) {
            return t.error();
        }
        out.targets.push_back(std::move(*t));
    }
    if (auto e = check_targets(out)) {
        return *e;
    }
    return out;
}

[[nodiscard]] inline auto notification_xml(const notification_configuration& c) -> std::string {
    using namespace notification_detail;
    auto w = aws_rest_xml::document("NotificationConfiguration");
    for (const auto& k : kinds) {
        for (const auto& t : c.targets) {
            if (t.kind != k.kind) {
                continue;
            }
            w.open(k.element);
            w.element("Id", t.id);
            w.element(k.arn, t.arn);
            for (const auto& e : t.events) {
                w.element("Event", e);
            }
            if (!t.prefix.empty() || !t.suffix.empty()) {
                w.open("Filter").open("S3Key");
                if (!t.prefix.empty()) {
                    w.open("FilterRule").element("Name", "Prefix").element("Value", t.prefix);
                    w.close();
                }
                if (!t.suffix.empty()) {
                    w.open("FilterRule").element("Name", "Suffix").element("Value", t.suffix);
                    w.close();
                }
                w.close().close();
            }
            w.close();
        }
    }
    w.close();
    return w.str();
}

/// The deprecated form: the first topic and queue configurations.
[[nodiscard]] inline auto legacy_notification_xml(const notification_configuration& c)
    -> std::string {
    auto w = aws_rest_xml::document("NotificationConfiguration");
    for (const auto& [kind, element, arn] :
         {std::tuple{destination_kind::topic, "TopicConfiguration", "Topic"},
          std::tuple{destination_kind::queue, "QueueConfiguration", "Queue"}}) {
        for (const auto& t : c.targets) {
            if (t.kind != kind) {
                continue;
            }
            w.open(element).element("Id", t.id);
            for (const auto& e : t.events) {
                w.element("Event", e);
            }
            w.element(arn, t.arn).close();
            break;
        }
    }
    w.close();
    return w.str();
}

/// A bucket's stored configuration; none when absent or unreadable.
[[nodiscard]] inline auto stored_notifications(const bucket_descriptor& d)
    -> std::optional<notification_configuration> {
    const auto it = d.config.find("notification");
    if (it == d.config.end()) {
        return std::nullopt;
    }
    auto c = parse_notification_configuration(it->second);
    if (!c) {
        return std::nullopt;
    }
    return std::move(*c);
}

/// Whether `t` hears about `event` on `key`.
[[nodiscard]] inline auto matches(const notification_target& t, change_event event,
                                  std::string_view key) -> bool {
    const auto name = event_name(event);
    if (!std::ranges::any_of(
            t.events, [&](const std::string& p) { return notification_detail::covers(p, name); })) {
        return false;
    }
    return key.starts_with(t.prefix) && key.ends_with(t.suffix);
}

// ---------------------------------------------------------------------------
// Event JSON
// ---------------------------------------------------------------------------

/// A key as S3's events carry it: form-encoded, `/` kept.
[[nodiscard]] inline auto event_key(std::string_view key) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out;
    for (const char ch : key) {
        const auto b = static_cast<unsigned char>(ch);
        if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
            b == '-' || b == '_' || b == '.' || b == '~' || b == '/' || b == '*') {
            out.push_back(ch);
        } else if (b == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(hex[b >> 4U]);
            out.push_back(hex[b & 0xFU]);
        }
    }
    return out;
}

/// S3's `sequencer`: hex, compared after padding; one key's events carry
/// increasing ones.
[[nodiscard]] inline auto sequencer(std::uint64_t seq) -> std::string {
    static constexpr std::string_view hex = "0123456789ABCDEF";
    std::string out(16, '0');
    for (auto i = out.size(); i-- > 0; seq >>= 4U) {
        out[i] = hex[seq & 0xFU];
    }
    return out;
}

/// What an event names besides the record.
struct event_context {
    std::string region = "us-east-1";
    std::string partition = "aws";
    std::string bucket;  ///< as clients see it
    std::string bucket_owner;
    std::string configuration_id;
};

[[nodiscard]] inline auto event_version(change_event e) -> std::string_view {
    switch (e) {
        case change_event::lifecycle_expiration_delete:
        case change_event::lifecycle_expiration_delete_marker_created:
        case change_event::lifecycle_transition:
        case change_event::object_restore_delete:
        case change_event::object_tagging_put:
        case change_event::object_tagging_delete:
        case change_event::object_acl_put:
            return "2.3";
        default:
            return "2.1";
    }
}

/// One record's event message (`{"Records":[...]}`).
[[nodiscard]] inline auto event_json(const sequenced_change& c, const event_context& ctx)
    -> std::string {
    const auto& r = c.record;
    const auto when =
        std::chrono::system_clock::time_point(std::chrono::milliseconds(r.written_ms));
    const auto request_id = sequencer(c.seq);
    boost::json::object object{{"key", event_key(r.key)}};
    const bool removal = r.event == change_event::object_removed_delete ||
                         r.event == change_event::object_removed_delete_marker_created ||
                         r.event == change_event::lifecycle_expiration_delete ||
                         r.event == change_event::lifecycle_expiration_delete_marker_created;
    if (!removal) {
        object["size"] = r.size;
        object["eTag"] = r.etag;
    }
    if (!r.version_id.empty() && r.version_id != null_version_id) {
        object["versionId"] = r.version_id;
    }
    object["sequencer"] = sequencer(c.seq);
    boost::json::object s3{{"s3SchemaVersion", "1.0"},
                           {"configurationId", ctx.configuration_id},
                           {"bucket",
                            {{"name", ctx.bucket},
                             {"ownerIdentity", {{"principalId", ctx.bucket_owner}}},
                             {"arn", "arn:" + ctx.partition + ":s3:::" + ctx.bucket}}},
                           {"object", std::move(object)}};
    boost::json::object rec{
        {"eventVersion", event_version(r.event)},
        {"eventSource", "aws:s3"},
        {"awsRegion", ctx.region},
        {"eventTime", aws_rest_xml::iso8601_ms(when)},
        {"eventName", event_name(r.event)},
        {"userIdentity",
         {{"principalId", r.requester.empty() ? std::string("AmazonS3") : "AWS:" + r.requester}}},
        {"requestParameters", {{"sourceIPAddress", ""}}},
        {"responseElements", {{"x-amz-request-id", request_id}, {"x-amz-id-2", request_id}}},
        {"s3", std::move(s3)}};
    if (r.event == change_event::lifecycle_transition) {
        rec["lifecycleEventData"] = {
            {"transitionEventData", {{"destinationStorageClass", r.storage_class}}}};
    }
    boost::json::array records;
    records.emplace_back(std::move(rec));
    return boost::json::serialize(boost::json::object{{"Records", std::move(records)}});
}

/// The message S3 sends when a configuration is stored.
[[nodiscard]] inline auto test_event_json(std::string_view bucket, std::uint64_t now_ms,
                                          std::string_view request_id) -> std::string {
    const auto when = std::chrono::system_clock::time_point(std::chrono::milliseconds(now_ms));
    return boost::json::serialize(boost::json::object{{"Service", "Amazon S3"},
                                                      {"Event", "s3:TestEvent"},
                                                      {"Time", aws_rest_xml::iso8601_ms(when)},
                                                      {"Bucket", bucket},
                                                      {"RequestId", request_id},
                                                      {"HostId", request_id}});
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

namespace notification_detail {

/// Sends the test event to each destination; the first that refuses it
/// fails the request.
template<metadata_access M>
[[nodiscard]] auto validate_destinations(const handler_context<M>& ctx, const s3_request& req,
                                         const bucket_state& b, const notification_configuration& c)
    -> std::optional<aws_rest_xml::error> {
    const auto skip = lower(req.header("x-amz-skip-destination-validation").value_or("")) == "true";
    if (skip || !ctx.options.notifications) {
        return std::nullopt;
    }
    const auto body = test_event_json(b.client_name, ctx.now_ms(), req.request_id);
    std::set<std::string> seen;
    for (const auto& t : c.targets) {
        if (!seen.insert(t.arn).second) {
            continue;
        }
        const auto out = ctx.options.notifications({t.kind, t.arn, body, b.client_name});
        if (!out.ok) {
            return argument_error("Unable to validate the following destination configurations",
                                  t.arn, out.error);
        }
    }
    return std::nullopt;
}

template<metadata_access M>
[[nodiscard]] auto store_notifications(handler_context<M>& ctx, const s3_request& req,
                                       const bucket_state& b,
                                       aws_rest_xml::result<notification_configuration> c)
    -> handler_result {
    if (!c) {
        return c.error();
    }
    if (auto e = validate_destinations(ctx, req, b, *c)) {
        return *e;
    }
    std::optional<std::string> doc;
    if (!c->empty()) {
        doc = notification_xml(*c);
    }
    if (auto e = bucket_detail::store(ctx, b, "notification", std::move(doc))) {
        return *e;
    }
    return s3_response{};
}

}  // namespace notification_detail

template<metadata_access M>
[[nodiscard]] auto put_bucket_notification_configuration(handler_context<M>& ctx,
                                                         const s3_request& req,
                                                         const authenticated& /*auth*/,
                                                         bucket_state& b) -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    return notification_detail::store_notifications(ctx, req, b,
                                                    parse_notification_configuration(*body));
}

template<metadata_access M>
[[nodiscard]] auto put_bucket_notification(handler_context<M>& ctx, const s3_request& req,
                                           const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    return notification_detail::store_notifications(ctx, req, b, parse_legacy_notification(*body));
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_notification_configuration(handler_context<M>& /*ctx*/,
                                                         const s3_request& /*req*/,
                                                         const authenticated& /*auth*/,
                                                         bucket_state& b) -> handler_result {
    return xml_response(
        notification_xml(stored_notifications(b.desc).value_or(notification_configuration{})));
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_notification(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                           const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    return xml_response(legacy_notification_xml(
        stored_notifications(b.desc).value_or(notification_configuration{})));
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

struct notification_options {
    std::string region = "us-east-1";
    std::string partition = "aws";
    /// Catalog names are `<account>/<name>` (`service_options`).
    bool account_namespaces = false;
    /// Records read per run.
    std::size_t page = 1000;
    /// Runs a failing destination is retried for one record before it is
    /// skipped for that record.
    std::uint32_t max_attempts = 10;
};

struct notification_report {
    std::uint64_t records = 0;    ///< read and finished with
    std::uint64_t delivered = 0;  ///< messages a destination accepted
    std::uint64_t dropped = 0;    ///< messages given up on
    std::uint64_t failures = 0;   ///< failed attempts, retried or not
    /// Stopped at a record whose destination is still being retried.
    bool blocked = false;
};

template<change_log_access M> class notification_worker {
public:
    notification_worker(M& meta, notification_sink sink, notification_options options = {})
        : _meta(meta), _sink(std::move(sink)), _options(std::move(options)) {
        if (!_sink) {
            throw std::invalid_argument("s3 notification worker: needs a sink");
        }
        if (_options.page == 0 || _options.max_attempts == 0) {
            throw std::invalid_argument("s3 notification worker: needs a page and attempts");
        }
    }

    auto run() -> notification_report {
        notification_report r;
        const auto cursor = _meta.change_cursor(notifications_consumer);
        const auto changes = _meta.read_changes(cursor, _options.page);
        if (changes.empty()) {
            return r;
        }
        std::map<std::uint64_t, bucket_descriptor> buckets;
        for (auto& d : _meta.list_buckets("")) {
            buckets.emplace(d.id, std::move(d));
        }
        std::uint64_t finished = cursor;
        for (const auto& c : changes) {
            if (!deliver(c, buckets, r)) {
                r.blocked = true;
                break;
            }
            finished = c.seq;
            ++r.records;
        }
        if (finished > cursor) {
            index_command a;
            a.op = index_command::kind::advance_change_log;
            a.config_name = std::string(notifications_consumer);
            a.change_seq = finished;
            (void)_meta.propose(a);  // lost with leadership: the next leader redelivers
        }
        return r;
    }

private:
    /// Every matching destination of one record; false when one is still
    /// being retried.
    auto deliver(const sequenced_change& c,
                 const std::map<std::uint64_t, bucket_descriptor>& buckets, notification_report& r)
        -> bool {
        const auto b = buckets.find(c.record.bucket_id);
        if (b == buckets.end()) {
            return true;  // the bucket is gone, and its configuration with it
        }
        const auto cfg = stored_notifications(b->second);
        if (!cfg) {
            return true;
        }
        if (_head != c.seq) {
            _head = c.seq;
            _done.clear();
            _attempts = 0;
        }
        bool all = true;
        event_context ctx{
            _options.region, _options.partition, client_name(b->second.name), b->second.owner, {}};
        for (const auto& t : cfg->targets) {
            if (!matches(t, c.record.event, c.record.key) || _done.contains(t.id)) {
                continue;
            }
            ctx.configuration_id = t.id;
            const auto out =
                _sink({t.kind, t.arn, event_json(c, ctx), ctx.bucket + "/" + c.record.key});
            if (out.ok) {
                ++r.delivered;
                _done.insert(t.id);
                continue;
            }
            ++r.failures;
            if (out.permanent || _attempts + 1 >= _options.max_attempts) {
                ++r.dropped;
                _done.insert(t.id);
                continue;
            }
            all = false;
        }
        if (!all) {
            ++_attempts;
        }
        return all;
    }

    [[nodiscard]] auto client_name(std::string_view catalog) const -> std::string {
        if (!_options.account_namespaces) {
            return std::string(catalog);
        }
        const auto slash = catalog.find('/');
        return std::string(slash == std::string_view::npos ? catalog : catalog.substr(slash + 1));
    }

    M& _meta;
    notification_sink _sink;
    notification_options _options;
    /// The record being retried, the destinations it has reached, and how
    /// many runs it has failed.
    std::uint64_t _head = 0;
    std::set<std::string> _done;
    std::uint32_t _attempts = 0;
};

}  // namespace kythira::s3
