// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Delivery documents and retry policies
// (`.kiro/specs/sns-compatible-notifications/` task 6, Requirements 6.3 and
// 6.4). The documents are checked byte for byte against what real SNS sent
// (`evidence/deliveries/deliveries.json`, task 1): every wrapped
// Notification and SubscriptionConfirmation is rebuilt from its own fields
// and must come out identical, each recorded header set must be what
// delivery_headers gives, and raw deliveries must carry exactly the
// message. Then the body each protocol takes from a MessageStructure=json
// message, the escaping and timestamp rules on their own, and SNS's retry
// phases and the DeliveryPolicy grammar.

#define BOOST_TEST_MODULE sns_delivery_format_test
#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_delivery_format.hpp>
#include <kythira/sns/sns_delivery_policy.hpp>

#include <boost/json.hpp>

#include <ctime>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#ifndef SNS_DELIVERIES_JSON
#error "SNS_DELIVERIES_JSON must name evidence/deliveries/deliveries.json"
#endif

using namespace kythira::sns;

namespace {

auto recording() -> const boost::json::object& {
    static const boost::json::value v = [] {
        std::ifstream in(SNS_DELIVERIES_JSON);
        BOOST_REQUIRE_MESSAGE(in, "cannot open " SNS_DELIVERIES_JSON);
        std::stringstream ss;
        ss << in.rdbuf();
        return boost::json::parse(ss.str());
    }();
    return v.as_object();
}

auto str(const boost::json::object& o, std::string_view key) -> std::string {
    const auto* v = o.if_contains(key);
    return v != nullptr && v->is_string() ? std::string(v->get_string()) : std::string{};
}

/// `2026-11-18T17:52:56.583Z` back to milliseconds.
auto parse_timestamp(std::string_view s) -> std::int64_t {
    std::tm tm{};
    int millis = 0;
    BOOST_REQUIRE(std::sscanf(std::string(s).c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ", &tm.tm_year,
                              &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
                              &millis) == 7);
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return static_cast<std::int64_t>(timegm(&tm)) * 1000 + millis;
}

auto signature_of(const boost::json::object& doc) -> std::optional<envelope_signature> {
    if (!doc.contains("Signature")) {
        return std::nullopt;
    }
    return envelope_signature{str(doc, "SignatureVersion"), str(doc, "Signature"),
                              str(doc, "SigningCertURL")};
}

auto region() -> std::string {
    return str(recording(), "region");
}

auto headers_of(const boost::json::object& d) -> header_list {
    header_list h;
    for (const auto& [k, v] : d.at("headers").as_object()) {
        if (k != "host" && k != "content-length" && k != "accept-encoding") {
            h.emplace_back(std::string(k), std::string(v.as_string()));
        }
    }
    std::sort(h.begin(), h.end());
    return h;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(recorded_deliveries)

BOOST_AUTO_TEST_CASE(wrapped_notifications_rebuild_byte_for_byte) {
    int seen = 0;
    for (const auto& dv : recording().at("deliveries").as_array()) {
        const auto& d = dv.as_object();
        const auto body = str(d, "body");
        const auto& h = d.at("headers").as_object();
        if (str(h, "x-amz-sns-message-type") != "Notification" ||
            h.contains("x-amz-sns-rawdelivery")) {
            continue;
        }
        const auto doc = boost::json::parse(body).as_object();
        notification_fields f;
        f._message_id = str(doc, "MessageId");
        f._topic_arn = str(doc, "TopicArn");
        if (doc.contains("Subject")) {
            f._subject = str(doc, "Subject");
        }
        f._message = str(doc, "Message");
        f._timestamp_ms = parse_timestamp(str(doc, "Timestamp"));
        f._signature = signature_of(doc);
        const auto sub_arn = str(h, "x-amz-sns-subscription-arn");
        f._unsubscribe_url = unsubscribe_url(sns_endpoint(region()), sub_arn);
        if (const auto* attrs = doc.if_contains("MessageAttributes")) {
            for (const auto& [name, a] : attrs->as_object()) {
                message_attribute m;
                m._data_type = str(a.as_object(), "Type");
                const auto value = str(a.as_object(), "Value");
                if (m._data_type == "Binary") {
                    m._binary_value = base64_decode(value);
                } else {
                    m._string_value = value;
                }
                f._attributes.emplace(std::string(name), std::move(m));
            }
        }
        BOOST_TEST(notification_body(f) == body, "rebuilt " << str(d, "label"));
        BOOST_TEST(str(doc, "UnsubscribeURL") == f._unsubscribe_url);
        auto want = delivery_headers("Notification", f._message_id, f._topic_arn, sub_arn, false);
        BOOST_CHECK_MESSAGE(headers_of(d) == want, str(d, "label"));
        ++seen;
    }
    BOOST_TEST(seen == 6);
}

BOOST_AUTO_TEST_CASE(confirmations_rebuild_byte_for_byte) {
    int seen = 0;
    for (const auto& dv : recording().at("deliveries").as_array()) {
        const auto& d = dv.as_object();
        const auto& h = d.at("headers").as_object();
        if (str(h, "x-amz-sns-message-type") != "SubscriptionConfirmation") {
            continue;
        }
        const auto body = str(d, "body");
        const auto doc = boost::json::parse(body).as_object();
        confirmation_fields f;
        f._message_id = str(doc, "MessageId");
        f._token = str(doc, "Token");
        f._topic_arn = str(doc, "TopicArn");
        f._message = subscription_confirmation_message(f._topic_arn);
        f._subscribe_url = subscribe_url(sns_endpoint(region()), f._topic_arn, f._token);
        f._timestamp_ms = parse_timestamp(str(doc, "Timestamp"));
        f._signature = signature_of(doc);
        BOOST_TEST(confirmation_body(f) == body, str(d, "path"));
        BOOST_CHECK(headers_of(d) == delivery_headers("SubscriptionConfirmation", f._message_id,
                                                      f._topic_arn, "", false));
        ++seen;
    }
    BOOST_TEST(seen == 3);
}

BOOST_AUTO_TEST_CASE(raw_deliveries_carry_the_message_alone) {
    std::map<std::string, std::string, std::less<>> wrapped;  // message id -> Message
    for (const auto& dv : recording().at("deliveries").as_array()) {
        const auto& d = dv.as_object();
        if (str(d, "path") == "/a/wrapped" && str(d, "label") != "SubscriptionConfirmation") {
            const auto doc = boost::json::parse(str(d, "body")).as_object();
            wrapped.emplace(str(doc, "MessageId"), str(doc, "Message"));
        }
    }
    int seen = 0;
    for (const auto& dv : recording().at("deliveries").as_array()) {
        const auto& d = dv.as_object();
        const auto& h = d.at("headers").as_object();
        if (!h.contains("x-amz-sns-rawdelivery")) {
            continue;
        }
        const auto id = str(h, "x-amz-sns-message-id");
        BOOST_REQUIRE(wrapped.contains(id));
        BOOST_TEST(str(d, "body") == wrapped.at(id));
        BOOST_CHECK(headers_of(d) == delivery_headers("Notification", id,
                                                      str(h, "x-amz-sns-topic-arn"),
                                                      str(h, "x-amz-sns-subscription-arn"), true));
        ++seen;
    }
    BOOST_TEST(seen == 5);
}

BOOST_AUTO_TEST_CASE(a_json_structure_gives_each_protocol_its_member) {
    // What the recorder published; SNS delivered "https body" to HTTPS.
    published_message m;
    m._json_structure = true;
    m._message = R"({"default": "default body", "https": "https body", "sqs": "sqs body"})";
    BOOST_TEST(message_for_protocol(m, "https") == "https body");
    BOOST_TEST(message_for_protocol(m, "sqs") == "sqs body");
    BOOST_TEST(message_for_protocol(m, "email") == "default body");
    m._json_structure = false;
    BOOST_TEST(message_for_protocol(m, "https") == m._message);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(format)

BOOST_AUTO_TEST_CASE(escaping_leaves_slashes_and_unicode_alone) {
    BOOST_TEST(sns_json_string("a/b é \"q\" \\ \n\t\r") == R"("a/b é \"q\" \\ \n\t\r")");
    BOOST_TEST(sns_json_string(std::string("\x01\x1f", 2)) == R"("\u0001\u001f")");
}

BOOST_AUTO_TEST_CASE(timestamps_keep_three_digits) {
    BOOST_TEST(sns_timestamp(0) == "1970-01-01T00:00:00.000Z");
    BOOST_TEST(sns_timestamp(1'795'030'376'005) == "2026-11-18T19:32:56.005Z");
}

BOOST_AUTO_TEST_CASE(fifo_and_unsigned_notifications) {
    notification_fields f;
    f._message_id = "m";
    f._sequence_number = "10000000000000000001";
    f._topic_arn = "arn:aws:sns:us-east-1:111122223333:t.fifo";
    f._message = "hi";
    f._unsubscribe_url = "u";
    BOOST_TEST(notification_body(f) ==
               "{\n"
               "  \"Type\" : \"Notification\",\n"
               "  \"MessageId\" : \"m\",\n"
               "  \"SequenceNumber\" : \"10000000000000000001\",\n"
               "  \"TopicArn\" : \"arn:aws:sns:us-east-1:111122223333:t.fifo\",\n"
               "  \"Message\" : \"hi\",\n"
               "  \"Timestamp\" : \"1970-01-01T00:00:00.000Z\",\n"
               "  \"UnsubscribeURL\" : \"u\"\n"
               "}");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(retry_policies)

BOOST_AUTO_TEST_CASE(http_default_is_three_retries_twenty_seconds_apart) {
    const auto p = default_http_retry_policy();
    BOOST_TEST(*p.delay_before_retry(1) == 20'000);
    BOOST_TEST(*p.delay_before_retry(3) == 20'000);
    BOOST_TEST(!p.delay_before_retry(4).has_value());
    BOOST_TEST(!p.delay_before_retry(0).has_value());
}

BOOST_AUTO_TEST_CASE(phases_run_in_order) {
    retry_policy p{2, 10, 10, 2, 2, 2, backoff_function::linear};
    BOOST_TEST(*p.delay_before_retry(1) == 0);
    BOOST_TEST(*p.delay_before_retry(2) == 0);
    BOOST_TEST(*p.delay_before_retry(3) == 2'000);
    BOOST_TEST(*p.delay_before_retry(4) == 2'000);
    BOOST_TEST(p.backoff_retries() == 4U);
    BOOST_TEST(*p.delay_before_retry(5) == 2'000);   // backoff starts at min
    BOOST_TEST(*p.delay_before_retry(6) == 4'667);   // linear steps
    BOOST_TEST(*p.delay_before_retry(8) == 10'000);  // and ends at max
    BOOST_TEST(*p.delay_before_retry(9) == 10'000);  // post-backoff
    BOOST_TEST(*p.delay_before_retry(10) == 10'000);
    BOOST_TEST(!p.delay_before_retry(11).has_value());
}

BOOST_AUTO_TEST_CASE(every_backoff_curve_climbs_from_min_to_max) {
    for (const auto f : {backoff_function::linear, backoff_function::arithmetic,
                         backoff_function::geometric, backoff_function::exponential}) {
        retry_policy p{1, 60, 8, 0, 0, 0, f};
        std::int64_t last = 0;
        for (std::uint32_t n = 1; n <= 8; ++n) {
            const auto d = *p.delay_before_retry(n);
            BOOST_TEST(d >= last);
            last = d;
        }
        BOOST_TEST(*p.delay_before_retry(1) == 1'000);
        BOOST_TEST(*p.delay_before_retry(8) == 60'000);
    }
}

BOOST_AUTO_TEST_CASE(managed_endpoints_retry_for_about_23_days) {
    const auto p = managed_endpoint_retry_policy();
    BOOST_TEST(p._num_retries == 100'015U);
    std::int64_t total = 0;
    for (std::uint32_t n = 1; n <= p._num_retries; ++n) {
        total += *p.delay_before_retry(n);
    }
    const auto days = static_cast<double>(total) / 86'400'000.0;
    BOOST_TEST(days > 23.0);
    BOOST_TEST(days < 23.2);
    BOOST_TEST(smtp_retry_policy()._num_retries == 50U);
}

BOOST_AUTO_TEST_CASE(delivery_policies_layer_and_validate) {
    const auto* topic =
        R"({"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":5,"maxDelayTarget":30,)"
        R"("numRetries":6,"backoffFunction":"exponential"},)"
        R"("defaultThrottlePolicy":{"maxReceivesPerSecond":10}}})";
    const auto* sub = R"({"throttlePolicy":{"maxReceivesPerSecond":2}})";
    const auto p = effective_delivery_policy("https", topic, sub);
    BOOST_TEST(p._retry._num_retries == 6U);
    BOOST_TEST(p._retry._min_delay_s == 5);
    BOOST_TEST(p._max_receives_per_second == 2U);
    BOOST_CHECK(p._retry._backoff == backoff_function::exponential);

    const auto* locked = R"({"http":{"disableSubscriptionOverrides":true,)"
                         R"("defaultThrottlePolicy":{"maxReceivesPerSecond":10}}})";
    BOOST_TEST(effective_delivery_policy("http", locked, sub)._max_receives_per_second == 10U);
    BOOST_CHECK(effective_delivery_policy("sqs", topic, sub)._retry ==
                managed_endpoint_retry_policy());
    BOOST_CHECK(effective_delivery_policy("email", "", "")._retry == smtp_retry_policy());
    BOOST_CHECK(effective_delivery_policy("https", "", "")._retry == default_http_retry_policy());

    BOOST_TEST(!parse_subscription_delivery_policy("[]").has_value());
    BOOST_TEST(!parse_subscription_delivery_policy(
                    R"({"healthyRetryPolicy":{"minDelayTarget":30,"maxDelayTarget":20}})")
                    .has_value());
    BOOST_TEST(!parse_subscription_delivery_policy(
                    R"({"healthyRetryPolicy":{"numRetries":2,"numNoDelayRetries":3}})")
                    .has_value());
    BOOST_TEST(
        !parse_subscription_delivery_policy(R"({"healthyRetryPolicy":{"backoffFunction":"cubic"}})")
             .has_value());
    BOOST_TEST(!parse_subscription_delivery_policy(R"({"healthyRetryPolicy":{"numRetries":101}})")
                    .has_value());
    BOOST_TEST(parse_subscription_delivery_policy(
                   R"({"requestPolicy":{"headerContentType":"application/json"}})")
                   ->_content_type == "application/json");
    BOOST_TEST(
        !parse_topic_delivery_policy(R"({"http":{"disableSubscriptionOverrides":1}})").has_value());
}

BOOST_AUTO_TEST_SUITE_END()
