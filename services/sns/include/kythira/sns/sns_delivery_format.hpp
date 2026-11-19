// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_delivery_format.hpp
/// @brief What a delivery looks like on the wire
///        (`.kiro/specs/sns-compatible-notifications/` task 6, Requirements
///        6.3 and 6.4).
///
/// SNS sends the same JSON document to every protocol that is not raw: a
/// `Notification`, or a `SubscriptionConfirmation` when a subscription
/// waits for its token. Validators check signatures over these fields, and
/// some clients compare bodies, so the layout here is SNS's byte for byte,
/// as recorded from real SNS in `tests/evidence/deliveries/deliveries.json`:
///
/// - one member per line, `  "Name" : value`, in SNS's order;
/// - strings escaped as SNS's JSON writer does (quote, backslash and
///   control characters only; `/` and non-ASCII text are left alone);
/// - `MessageAttributes` last, one compact `{"Type":...,"Value":...}` per
///   attribute in name order, Binary values in base64;
/// - optional members (`Subject`, `SequenceNumber`, the signature trio,
///   `MessageAttributes`) left out when they have no value.
///
/// The signature itself is task 7's: callers pass the version, signature
/// and certificate URL in. The HTTP headers SNS adds, the body each protocol
/// gets from a `MessageStructure=json` message, and the confirmation and
/// unsubscribe links are here too.

#include <kythira/sns/sns_message.hpp>
#include <kythira/sns/sns_query.hpp>

#include <boost/json.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sns {

/// The `User-Agent` SNS sends with every HTTP delivery.
inline constexpr std::string_view k_delivery_user_agent =
    "Amazon Simple Notification Service Agent";
inline constexpr std::string_view k_delivery_content_type = "text/plain; charset=UTF-8";

/// A string as SNS's JSON writer quotes it.
[[nodiscard]] inline auto sns_json_string(std::string_view s) -> std::string {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            default:
                if (u < 0x20) {
                    std::array<char, 7> buf{};
                    std::snprintf(buf.data(), buf.size(), "\\u%04x", u);
                    out += buf.data();
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
    return out;
}

/// `2026-11-18T17:52:56.583Z`: UTC, always three digits of milliseconds.
[[nodiscard]] inline auto sns_timestamp(std::int64_t ms) -> std::string {
    auto secs = static_cast<std::time_t>(ms / 1000);
    auto millis = ms % 1000;
    if (millis < 0) {
        millis += 1000;
        --secs;
    }
    std::tm tm{};
    gmtime_r(&secs, &tm);
    std::array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(millis));
    return buf.data();
}

/// The signature members of a signed document (task 7 computes them).
struct envelope_signature {
    std::string _version{};
    std::string _signature{};
    std::string _signing_cert_url{};
};

/// The members of a `Notification`.
struct notification_fields {
    std::string _message_id{};
    /// FIFO topics only.
    std::optional<std::string> _sequence_number{};
    std::string _topic_arn{};
    std::optional<std::string> _subject{};
    std::string _message{};
    std::int64_t _timestamp_ms = 0;
    std::optional<envelope_signature> _signature{};
    std::string _unsubscribe_url{};
    message_attributes _attributes{};
};

/// The members of a `SubscriptionConfirmation` (or, by `_type`, an
/// `UnsubscribeConfirmation`, which real SNS was not seen to send; see
/// tasks.md task 1).
struct confirmation_fields {
    std::string _type = "SubscriptionConfirmation";
    std::string _message_id{};
    std::string _token{};
    std::string _topic_arn{};
    std::string _message{};
    std::string _subscribe_url{};
    std::int64_t _timestamp_ms = 0;
    std::optional<envelope_signature> _signature{};
};

namespace delivery_detail {

class document {
public:
    void member(std::string_view name, std::string_view raw_value) {
        _out += _first ? "{\n  " : ",\n  ";
        _first = false;
        _out += sns_json_string(name);
        _out += " : ";
        _out += raw_value;
    }
    void string(std::string_view name, std::string_view value) {
        member(name, sns_json_string(value));
    }
    void signature(const std::optional<envelope_signature>& s) {
        if (s) {
            string("SignatureVersion", s->_version);
            string("Signature", s->_signature);
            string("SigningCertURL", s->_signing_cert_url);
        }
    }
    [[nodiscard]] auto take() -> std::string {
        _out += _first ? "{\n}" : "\n}";
        return std::move(_out);
    }

private:
    std::string _out{};
    bool _first = true;
};

[[nodiscard]] inline auto attribute_value(const message_attribute& a) -> std::string {
    if (a._binary_value) {
        return base64_encode(*a._binary_value);
    }
    return a._string_value.value_or("");
}

}  // namespace delivery_detail

/// The JSON body SNS sends for a message that is not delivered raw.
[[nodiscard]] inline auto notification_body(const notification_fields& f) -> std::string {
    delivery_detail::document d;
    d.string("Type", "Notification");
    d.string("MessageId", f._message_id);
    if (f._sequence_number) {
        d.string("SequenceNumber", *f._sequence_number);
    }
    d.string("TopicArn", f._topic_arn);
    if (f._subject) {
        d.string("Subject", *f._subject);
    }
    d.string("Message", f._message);
    d.string("Timestamp", sns_timestamp(f._timestamp_ms));
    d.signature(f._signature);
    d.string("UnsubscribeURL", f._unsubscribe_url);
    if (!f._attributes.empty()) {
        std::string attrs = "{";
        bool first = true;
        for (const auto& [name, a] : f._attributes) {
            attrs += first ? "\n    " : ",\n    ";
            first = false;
            attrs += sns_json_string(name);
            attrs += " : {\"Type\":";
            attrs += sns_json_string(a._data_type);
            attrs += ",\"Value\":";
            attrs += sns_json_string(delivery_detail::attribute_value(a));
            attrs += "}";
        }
        attrs += "\n  }";
        d.member("MessageAttributes", attrs);
    }
    return d.take();
}

[[nodiscard]] inline auto confirmation_body(const confirmation_fields& f) -> std::string {
    delivery_detail::document d;
    d.string("Type", f._type);
    d.string("MessageId", f._message_id);
    d.string("Token", f._token);
    d.string("TopicArn", f._topic_arn);
    d.string("Message", f._message);
    d.string("SubscribeURL", f._subscribe_url);
    d.string("Timestamp", sns_timestamp(f._timestamp_ms));
    d.signature(f._signature);
    return d.take();
}

/// The text of a `SubscriptionConfirmation`'s `Message`.
[[nodiscard]] inline auto subscription_confirmation_message(std::string_view topic_arn)
    -> std::string {
    return "You have chosen to subscribe to the topic " + std::string(topic_arn) +
           ".\nTo confirm the subscription, visit the SubscribeURL included in this message.";
}

/// `<endpoint>?Action=ConfirmSubscription&TopicArn=<arn>&Token=<token>`,
/// with the ARN and token unescaped, as SNS writes it. `endpoint` is the
/// service's public URL with its trailing `/`.
[[nodiscard]] inline auto subscribe_url(std::string_view endpoint, std::string_view topic_arn,
                                        std::string_view token) -> std::string {
    return std::string(endpoint) +
           "?Action=ConfirmSubscription&TopicArn=" + std::string(topic_arn) +
           "&Token=" + std::string(token);
}

[[nodiscard]] inline auto unsubscribe_url(std::string_view endpoint,
                                          std::string_view subscription_arn) -> std::string {
    return std::string(endpoint) +
           "?Action=Unsubscribe&SubscriptionArn=" + std::string(subscription_arn);
}

/// SNS's public endpoint for a region, as the links in its documents
/// name it.
[[nodiscard]] inline auto sns_endpoint(std::string_view region) -> std::string {
    return "https://sns." + std::string(region) + ".amazonaws.com/";
}

/// The `Message` a protocol gets. With `MessageStructure=json` it is the
/// protocol's own member if it has one, else `default`; the front end
/// checked at publish that `default` is there.
[[nodiscard]] inline auto message_for_protocol(const published_message& m,
                                               std::string_view protocol) -> std::string {
    if (!m._json_structure) {
        return m._message;
    }
    boost::system::error_code ec;
    const auto v = boost::json::parse(m._message, ec);
    const auto* o = ec ? nullptr : v.if_object();
    if (o == nullptr) {
        return m._message;
    }
    for (const auto key : {protocol, std::string_view("default")}) {
        if (const auto* member = o->if_contains(key); member != nullptr && member->is_string()) {
            return std::string(member->get_string());
        }
    }
    return m._message;
}

using header_list = std::vector<std::pair<std::string, std::string>>;

/// The headers SNS sends with an HTTP or HTTPS delivery, lower-case, in
/// name order, without `Host`, `Content-Length` and `Accept-Encoding`,
/// which belong to the HTTP client. `subscription_arn` is set for a
/// `Notification` and empty for a confirmation.
[[nodiscard]] inline auto delivery_headers(std::string_view message_type,
                                           std::string_view message_id, std::string_view topic_arn,
                                           std::string_view subscription_arn, bool raw)
    -> header_list {
    header_list h;
    h.emplace_back("content-type", k_delivery_content_type);
    h.emplace_back("user-agent", k_delivery_user_agent);
    h.emplace_back("x-amz-sns-message-id", message_id);
    h.emplace_back("x-amz-sns-message-type", message_type);
    if (raw) {
        h.emplace_back("x-amz-sns-rawdelivery", "true");
    }
    if (!subscription_arn.empty()) {
        h.emplace_back("x-amz-sns-subscription-arn", subscription_arn);
    }
    h.emplace_back("x-amz-sns-topic-arn", topic_arn);
    return h;
}

}  // namespace kythira::sns
