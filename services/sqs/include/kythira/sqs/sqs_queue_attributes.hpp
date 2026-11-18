// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_queue_attributes.hpp
/// @brief Queue attributes as CreateQueue, SetQueueAttributes and
///        GetQueueAttributes see them (`.kiro/specs/sqs-compatible-queues/`
///        Requirement 4.1, 2.3).
///
/// `queue_settings` holds every attribute a client may set, at SQS's
/// defaults. `apply_attributes` checks a request's `Attributes` map and
/// applies it: an attribute SQS does not know, or one that does not fit the
/// queue (a FIFO attribute on a standard queue, `FifoQueue` outside
/// CreateQueue, a read-only attribute), is `InvalidAttributeName`; a value
/// out of range or malformed is `InvalidAttributeValue`. Ranges are SQS's,
/// narrowed or widened by the queue's compatibility profile where the
/// profile has a switch (message size, retention, long-poll maximum).
///
/// CreateQueue is idempotent on identical attributes: the handler applies
/// the request to fresh defaults and compares the result with the stored
/// settings (`operator==`), answering `QueueNameExists` when they differ.
///
/// `attribute_values` renders GetQueueAttributes: the asked-for names
/// (`All` for every one), each as SQS spells its value. Attributes that
/// are unset (no policy, no redrive policy, no KMS key) are left out, as
/// SQS leaves them out.
///
/// The `RedrivePolicy` target's existence and type are the handler's to
/// check (it needs the catalog); here the policy's shape is checked.

#include <kythira/sqs/sqs_compat_profile.hpp>
#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

struct queue_settings {
    std::uint32_t _delay_s = 0;
    std::uint32_t _max_message_bytes = 1048576;
    std::uint32_t _retention_s = 345600;
    std::uint32_t _wait_s = 0;
    std::uint32_t _visibility_s = 30;
    std::string _policy;
    std::string _redrive_policy;
    std::string _redrive_allow_policy;
    std::string _kms_key_id;
    std::uint32_t _kms_reuse_s = 300;
    bool _sqs_managed_sse = true;
    bool _fifo = false;
    bool _content_dedup = false;
    std::string _dedup_scope = "queue";
    std::string _throughput_limit = "perQueue";

    friend auto operator==(const queue_settings&, const queue_settings&) -> bool = default;
};

/// What GetQueueAttributes reports besides the settings.
struct queue_facts_view {
    std::string _arn;
    std::int64_t _created_s = 0;
    std::int64_t _modified_s = 0;
    std::uint64_t _visible = 0;
    std::uint64_t _not_visible = 0;
    std::uint64_t _delayed = 0;
};

namespace attribute_detail {

[[nodiscard]] inline auto unknown(std::string_view name) -> aws_json::error {
    return modeled_error("InvalidAttributeName", "Unknown Attribute " + std::string(name) + ".");
}

[[nodiscard]] inline auto bad_value(std::string_view name) -> aws_json::error {
    return modeled_error("InvalidAttributeValue",
                         "Invalid value for the parameter " + std::string(name) + ".");
}

[[nodiscard]] inline auto parse_u32(std::string_view s) -> std::optional<std::uint32_t> {
    std::uint32_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (s.empty() || ec != std::errc{} || p != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

[[nodiscard]] inline auto parse_bool(std::string_view s) -> std::optional<bool> {
    std::string l(s);
    std::transform(l.begin(), l.end(), l.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (l == "true") {
        return true;
    }
    if (l == "false") {
        return false;
    }
    return std::nullopt;
}

[[nodiscard]] inline auto parse_object(std::string_view s) -> std::optional<boost::json::object> {
    boost::system::error_code ec;
    auto v = boost::json::parse(s, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    return std::move(v.as_object());
}

/// `{"deadLetterTargetArn": "<arn>", "maxReceiveCount": 1..1000}`; the
/// count may be a number or a numeric string, as SDK examples write both.
[[nodiscard]] inline auto valid_redrive_policy(std::string_view s) -> bool {
    const auto o = parse_object(s);
    if (!o) {
        return false;
    }
    const auto* arn = o->if_contains("deadLetterTargetArn");
    const auto* count = o->if_contains("maxReceiveCount");
    if (arn == nullptr || !arn->is_string() || !arn->get_string().starts_with("arn:") ||
        count == nullptr) {
        return false;
    }
    std::int64_t n = 0;
    if (count->is_int64()) {
        n = count->get_int64();
    } else if (count->is_string()) {
        const auto v = parse_u32(count->get_string());
        if (!v) {
            return false;
        }
        n = *v;
    } else {
        return false;
    }
    return n >= 1 && n <= 1000 && o->size() == 2;
}

/// `{"redrivePermission": "allowAll"|"denyAll"|"byQueue",
///   "sourceQueueArns": [...]}`, the ARNs only (and 1 to 10 of them) with
/// byQueue.
[[nodiscard]] inline auto valid_redrive_allow_policy(std::string_view s) -> bool {
    const auto o = parse_object(s);
    if (!o) {
        return false;
    }
    const auto* perm = o->if_contains("redrivePermission");
    if (perm == nullptr || !perm->is_string()) {
        return false;
    }
    const std::string_view p = perm->get_string();
    const auto* arns = o->if_contains("sourceQueueArns");
    if (p == "byQueue") {
        return arns != nullptr && arns->is_array() && !arns->get_array().empty() &&
               arns->get_array().size() <= 10 &&
               std::all_of(arns->get_array().begin(), arns->get_array().end(),
                           [](const boost::json::value& a) { return a.is_string(); });
    }
    return (p == "allowAll" || p == "denyAll") && arns == nullptr;
}

/// Names GetQueueAttributes reports that no request may set.
inline constexpr std::array<std::string_view, 7> k_read_only{
    "All",
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesDelayed",
    "ApproximateNumberOfMessagesNotVisible",
    "CreatedTimestamp",
    "LastModifiedTimestamp",
    "QueueArn",
};

[[nodiscard]] inline auto is_read_only(std::string_view name) -> bool {
    return std::find(k_read_only.begin(), k_read_only.end(), name) != k_read_only.end();
}

[[nodiscard]] inline auto is_fifo_only(std::string_view name) -> bool {
    return name == "ContentBasedDeduplication" || name == "DeduplicationScope" ||
           name == "FifoThroughputLimit";
}

}  // namespace attribute_detail

/// Applies a request's `Attributes` to `s`. `create` is true for
/// CreateQueue (which alone may carry `FifoQueue`; `s._fifo` is then
/// already decided from it by `fifo_requested`). On an error `s` may be
/// partly changed; callers apply to a copy.
[[nodiscard]] inline auto apply_attributes(queue_settings& s, const boost::json::object& attrs,
                                           bool create, const sqs_compat_profile& profile)
    -> std::optional<aws_json::error> {
    using namespace attribute_detail;
    for (const auto& kv : attrs) {
        const std::string_view name = kv.key();
        if (!kv.value().is_string()) {
            return bad_value(name);
        }
        const std::string_view v = kv.value().get_string();
        const auto number = [&](std::uint32_t lo, std::uint32_t hi,
                                std::uint32_t& out) -> std::optional<aws_json::error> {
            const auto n = parse_u32(v);
            if (!n || *n < lo || *n > hi) {
                return bad_value(name);
            }
            out = *n;
            return std::nullopt;
        };
        std::optional<aws_json::error> e;
        if (is_read_only(name) || (is_fifo_only(name) && !s._fifo)) {
            return unknown(name);
        }
        if (name == "DelaySeconds") {
            e = number(0, 900, s._delay_s);
        } else if (name == "MaximumMessageSize") {
            e = number(1024, profile._max_message_bytes, s._max_message_bytes);
        } else if (name == "MessageRetentionPeriod") {
            e = number(profile._min_retention_s, profile._max_retention_s, s._retention_s);
        } else if (name == "ReceiveMessageWaitTimeSeconds") {
            e = number(0, profile._max_wait_s, s._wait_s);
        } else if (name == "VisibilityTimeout") {
            e = number(0, 43200, s._visibility_s);
        } else if (name == "KmsDataKeyReusePeriodSeconds") {
            e = number(60, 86400, s._kms_reuse_s);
        } else if (name == "Policy") {
            if (!v.empty() && !parse_object(v)) {
                return bad_value(name);
            }
            s._policy = std::string(v);
        } else if (name == "RedrivePolicy") {
            if (!v.empty() && !valid_redrive_policy(v)) {
                return bad_value(name);
            }
            s._redrive_policy = std::string(v);
        } else if (name == "RedriveAllowPolicy") {
            if (!v.empty() && !valid_redrive_allow_policy(v)) {
                return bad_value(name);
            }
            s._redrive_allow_policy = std::string(v);
        } else if (name == "KmsMasterKeyId") {
            s._kms_key_id = std::string(v);
            if (!v.empty()) {
                s._sqs_managed_sse = false;
            }
        } else if (name == "SqsManagedSseEnabled") {
            const auto b = parse_bool(v);
            if (!b) {
                return bad_value(name);
            }
            s._sqs_managed_sse = *b;
        } else if (name == "FifoQueue") {
            const auto b = parse_bool(v);
            if (!create) {
                return unknown(name);
            }
            if (!b || *b != s._fifo) {
                return bad_value(name);
            }
        } else if (name == "ContentBasedDeduplication") {
            const auto b = parse_bool(v);
            if (!b) {
                return bad_value(name);
            }
            s._content_dedup = *b;
        } else if (name == "DeduplicationScope") {
            if (v != "queue" && v != "messageGroup") {
                return bad_value(name);
            }
            s._dedup_scope = std::string(v);
        } else if (name == "FifoThroughputLimit") {
            if (v != "perQueue" && v != "perMessageGroupId") {
                return bad_value(name);
            }
            s._throughput_limit = std::string(v);
        } else {
            return unknown(name);
        }
        if (e) {
            return e;
        }
    }
    if (s._sqs_managed_sse && !s._kms_key_id.empty()) {
        // Only one server-side encryption option per queue.
        return bad_value("SqsManagedSseEnabled");
    }
    if (s._throughput_limit == "perMessageGroupId" && s._dedup_scope != "messageGroup") {
        // High-throughput FIFO needs per-group deduplication.
        return bad_value("FifoThroughputLimit");
    }
    return std::nullopt;
}

/// Whether CreateQueue's attributes ask for a FIFO queue (`FifoQueue` set
/// to true), or nullopt with the error for a value that is not a boolean.
[[nodiscard]] inline auto fifo_requested(const boost::json::object& attrs)
    -> aws_json::result<bool> {
    const auto* v = attrs.if_contains("FifoQueue");
    if (v == nullptr) {
        return false;
    }
    const auto b = v->is_string() ? attribute_detail::parse_bool(v->get_string()) : std::nullopt;
    if (!b) {
        return attribute_detail::bad_value("FifoQueue");
    }
    return *b;
}

/// Whether `name` is a queue name SQS takes for a queue of that kind: 1 to
/// 80 characters of `[A-Za-z0-9_-]`, with `.fifo` at the end (counted in
/// the 80) exactly when the queue is FIFO.
[[nodiscard]] inline auto valid_queue_name(std::string_view name, bool fifo) -> bool {
    if (name.empty() || name.size() > 80) {
        return false;
    }
    const bool has_suffix = name.ends_with(".fifo");
    if (has_suffix != fifo) {
        return false;
    }
    const auto stem = fifo ? name.substr(0, name.size() - 5) : name;
    return !stem.empty() && std::all_of(stem.begin(), stem.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_';
    });
}

/// GetQueueAttributes' `Attributes` for the names asked for. An unknown
/// name, or a FIFO attribute on a standard queue, is InvalidAttributeName.
[[nodiscard]] inline auto attribute_values(const queue_settings& s, const queue_facts_view& f,
                                           const std::vector<std::string>& wanted)
    -> aws_json::result<boost::json::object> {
    using namespace attribute_detail;
    std::vector<std::pair<std::string_view, std::string>> all{
        {"QueueArn", f._arn},
        {"ApproximateNumberOfMessages", std::to_string(f._visible)},
        {"ApproximateNumberOfMessagesNotVisible", std::to_string(f._not_visible)},
        {"ApproximateNumberOfMessagesDelayed", std::to_string(f._delayed)},
        {"CreatedTimestamp", std::to_string(f._created_s)},
        {"LastModifiedTimestamp", std::to_string(f._modified_s)},
        {"VisibilityTimeout", std::to_string(s._visibility_s)},
        {"MaximumMessageSize", std::to_string(s._max_message_bytes)},
        {"MessageRetentionPeriod", std::to_string(s._retention_s)},
        {"DelaySeconds", std::to_string(s._delay_s)},
        {"ReceiveMessageWaitTimeSeconds", std::to_string(s._wait_s)},
        {"SqsManagedSseEnabled", s._sqs_managed_sse ? "true" : "false"},
    };
    if (!s._policy.empty()) {
        all.emplace_back("Policy", s._policy);
    }
    if (!s._redrive_policy.empty()) {
        all.emplace_back("RedrivePolicy", s._redrive_policy);
    }
    if (!s._redrive_allow_policy.empty()) {
        all.emplace_back("RedriveAllowPolicy", s._redrive_allow_policy);
    }
    if (!s._kms_key_id.empty()) {
        all.emplace_back("KmsMasterKeyId", s._kms_key_id);
        all.emplace_back("KmsDataKeyReusePeriodSeconds", std::to_string(s._kms_reuse_s));
    }
    if (s._fifo) {
        all.emplace_back("FifoQueue", "true");
        all.emplace_back("ContentBasedDeduplication", s._content_dedup ? "true" : "false");
        all.emplace_back("DeduplicationScope", s._dedup_scope);
        all.emplace_back("FifoThroughputLimit", s._throughput_limit);
    }
    static constexpr std::array<std::string_view, 22> k_known{
        "All",
        "ApproximateNumberOfMessages",
        "ApproximateNumberOfMessagesDelayed",
        "ApproximateNumberOfMessagesNotVisible",
        "ContentBasedDeduplication",
        "CreatedTimestamp",
        "DeduplicationScope",
        "DelaySeconds",
        "FifoQueue",
        "FifoThroughputLimit",
        "KmsDataKeyReusePeriodSeconds",
        "KmsMasterKeyId",
        "LastModifiedTimestamp",
        "MaximumMessageSize",
        "MessageRetentionPeriod",
        "Policy",
        "QueueArn",
        "ReceiveMessageWaitTimeSeconds",
        "RedriveAllowPolicy",
        "RedrivePolicy",
        "SqsManagedSseEnabled",
        "VisibilityTimeout",
    };
    boost::json::object out;
    for (const auto& w : wanted) {
        if (std::find(k_known.begin(), k_known.end(), w) == k_known.end() ||
            ((is_fifo_only(w) || w == "FifoQueue") && !s._fifo)) {
            return unknown(w);
        }
    }
    const bool every = std::find(wanted.begin(), wanted.end(), "All") != wanted.end();
    for (const auto& [name, value] : all) {
        if (every || std::find(wanted.begin(), wanted.end(), name) != wanted.end()) {
            out[name] = value;
        }
    }
    return out;
}

}  // namespace kythira::sqs
