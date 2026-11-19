// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_event_sinks.hpp
/// @brief Where event notifications go: Kythira's or Amazon's SQS queues,
///        SNS topics and Kinesis streams (.kiro/specs/s3-compatible-storage/
///        task 14, Requirement 12.2).
///
/// The notification worker and `PutBucketNotificationConfiguration`'s
/// destination check hand each message to a `notification_sink`. The
/// daemon (task 16) chooses one per deployment: the co-located SQS, SNS
/// or Kinesis module in process, or their APIs. `notification_api_sink`
/// is the API form: it builds each service's own request (SQS
/// `SendMessage` in the JSON protocol, SNS `Publish` in the query
/// protocol, Kinesis `PutRecord` in JSON 1.1) and sends it through an
/// `event_api_call`, which addresses, signs and sends it: core's
/// in-process client for a co-located module, or a SigV4 HTTPS client for
/// another cluster or AWS. Keeping the transport a function keeps this
/// header free of the module interfaces, as `kms_api_provider` does.
///
/// A delivery fails *permanently* when the destination says it does not
/// exist or refuses S3 (a 4xx answer other than throttling); the worker
/// then stops retrying it. Anything else (a 5xx, throttling, a transport
/// failure) is retried.

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// The kinds of destination a notification configuration names.
enum class destination_kind : std::uint8_t {
    queue = 1,   ///< SQS (`QueueConfiguration`)
    topic = 2,   ///< SNS (`TopicConfiguration`)
    stream = 3,  ///< Kinesis (Kythira's `KinesisStreamConfiguration`)
};

/// One message for one destination.
struct notification_delivery {
    destination_kind kind = destination_kind::queue;
    std::string arn;
    /// The event JSON (or the `s3:TestEvent`).
    std::string body;
    /// Kinesis: the record's partition key (bucket and key), so one key's
    /// events stay on one shard and in order.
    std::string partition_key;
};

struct delivery_outcome {
    bool ok = false;
    /// The destination is missing or refuses S3: retrying will not help.
    bool permanent = false;
    std::string error;
};

using notification_sink = std::function<delivery_outcome(const notification_delivery&)>;

/// The parts of an AWS ARN.
struct parsed_arn {
    std::string partition;
    std::string service;
    std::string region;
    std::string account;
    std::string resource;
};

[[nodiscard]] inline auto parse_arn(std::string_view arn) -> std::optional<parsed_arn> {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (int i = 0; i < 5; ++i) {
        const auto colon = arn.find(':', start);
        if (colon == std::string_view::npos) {
            return std::nullopt;
        }
        parts.emplace_back(arn.substr(start, colon - start));
        start = colon + 1;
    }
    if (parts[0] != "arn" || parts[1].empty() || parts[2].empty() || start >= arn.size()) {
        return std::nullopt;
    }
    return parsed_arn{parts[1], parts[2], parts[3], parts[4], std::string(arn.substr(start))};
}

/// Whether `arn` names a destination of `kind`: a queue or topic in a
/// region and account, or a Kinesis `stream/<name>`.
[[nodiscard]] inline auto destination_arn_ok(destination_kind kind, std::string_view arn) -> bool {
    const auto a = parse_arn(arn);
    if (!a || a->region.empty() || a->account.empty() || a->resource.empty()) {
        return false;
    }
    switch (kind) {
        case destination_kind::queue:
            return a->service == "sqs" && a->resource.find_first_of(":/") == std::string::npos;
        case destination_kind::topic:
            return a->service == "sns" && a->resource.find_first_of(":/") == std::string::npos;
        case destination_kind::stream:
            return a->service == "kinesis" && a->resource.starts_with("stream/") &&
                   a->resource.size() > 7;
    }
    return false;
}

/// One API request to SQS, SNS or Kinesis, before addressing and signing.
struct event_api_request {
    std::string service;  ///< `sqs`, `sns`, `kinesis` (the SigV4 service)
    std::string region;   ///< from the destination's ARN
    std::string account;  ///< likewise
    std::string target;   ///< `X-Amz-Target`; empty for SNS's query protocol
    std::string content_type;
    std::string body;
};

struct event_api_answer {
    int status = 0;
    std::string body;
};

/// Addresses, signs and sends one request; throws when it cannot.
using event_api_call = std::function<event_api_answer(const event_api_request&)>;

struct notification_api_options {
    /// A queue's URL from its ARN; empty: AWS's
    /// `https://sqs.<region>.amazonaws.com/<account>/<name>`, which
    /// Kythira's SQS accepts too.
    std::function<std::string(const parsed_arn&)> queue_url;
};

/// Sends deliveries through each service's own API.
class notification_api_sink {
public:
    explicit notification_api_sink(event_api_call call, notification_api_options options = {})
        : _call(std::move(call)), _options(std::move(options)) {
        if (!_call) {
            throw std::invalid_argument("s3 notification sink: needs a transport");
        }
    }

    [[nodiscard]] auto operator()(const notification_delivery& d) const -> delivery_outcome {
        const auto arn = parse_arn(d.arn);
        if (!arn || !destination_arn_ok(d.kind, d.arn)) {
            return {false, true, "not a destination ARN: " + d.arn};
        }
        event_api_request req;
        req.region = arn->region;
        req.account = arn->account;
        switch (d.kind) {
            case destination_kind::queue: {
                req.service = "sqs";
                req.target = "AmazonSQS.SendMessage";
                req.content_type = "application/x-amz-json-1.0";
                boost::json::object o{{"QueueUrl", queue_url(*arn)}, {"MessageBody", d.body}};
                req.body = boost::json::serialize(o);
                break;
            }
            case destination_kind::topic:
                req.service = "sns";
                req.content_type = "application/x-www-form-urlencoded; charset=utf-8";
                req.body = "Action=Publish&Version=2010-03-31&TopicArn=" + form(d.arn) +
                           "&Subject=" + form("Amazon S3 Notification") +
                           "&Message=" + form(d.body);
                break;
            case destination_kind::stream: {
                req.service = "kinesis";
                req.target = "Kinesis_20131202.PutRecord";
                req.content_type = "application/x-amz-json-1.1";
                boost::json::object o{
                    {"StreamARN", d.arn},
                    {"PartitionKey", partition_key(d.partition_key)},
                    {"Data", aws_json::base64_encode(std::as_bytes(
                                 std::span<const char>(d.body.data(), d.body.size())))}};
                req.body = boost::json::serialize(o);
                break;
            }
        }
        event_api_answer a;
        try {
            a = _call(req);
        } catch (const std::exception& e) {
            return {false, false, std::string("unreachable: ") + e.what()};
        }
        if (a.status >= 200 && a.status < 300) {
            return {true, false, {}};
        }
        const bool throttled = a.status == 429 || a.body.find("Throttl") != std::string::npos ||
                               a.body.find("RequestLimitExceeded") != std::string::npos ||
                               a.body.find("ProvisionedThroughputExceeded") != std::string::npos;
        return {false, a.status >= 400 && a.status < 500 && !throttled,
                req.service + " answered " + std::to_string(a.status) + ": " + a.body};
    }

    /// A Kinesis partition key is 1-256 characters; a longer one is cut
    /// (keys sharing their first 256 characters share a shard).
    [[nodiscard]] static auto partition_key(std::string_view key) -> std::string {
        if (key.empty()) {
            return "-";
        }
        std::size_t n = 0;
        std::size_t chars = 0;
        while (n < key.size() && chars < 256) {
            const auto b = static_cast<unsigned char>(key[n]);
            n += b < 0x80 ? 1 : b < 0xE0 ? 2 : b < 0xF0 ? 3 : 4;
            ++chars;
        }
        return std::string(key.substr(0, std::min(n, key.size())));
    }

    /// `application/x-www-form-urlencoded`, as SNS's query protocol reads.
    [[nodiscard]] static auto form(std::string_view in) -> std::string {
        static constexpr std::string_view hex = "0123456789ABCDEF";
        std::string out;
        for (const char ch : in) {
            const auto b = static_cast<unsigned char>(ch);
            if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
                b == '-' || b == '_' || b == '.' || b == '~') {
                out.push_back(ch);
            } else {
                out.push_back('%');
                out.push_back(hex[b >> 4U]);
                out.push_back(hex[b & 0xFU]);
            }
        }
        return out;
    }

private:
    [[nodiscard]] auto queue_url(const parsed_arn& a) const -> std::string {
        if (_options.queue_url) {
            return _options.queue_url(a);
        }
        return "https://sqs." + a.region + ".amazonaws.com/" + a.account + "/" + a.resource;
    }

    event_api_call _call;
    notification_api_options _options;
};

}  // namespace kythira::s3
