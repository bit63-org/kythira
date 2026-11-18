// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Message and queue details the API handlers build on
// (`.kiro/specs/sqs-compatible-queues/` task 4; Requirements 4.1, 5.1,
// 5.3): MD5 digests of bodies and attributes (expected values computed
// independently with moto's implementation, which the Java SDK accepted
// during the task 1 recordings), attribute checks, storage and selection;
// receipt handles; queue attributes, names and GetQueueAttributes.

#define BOOST_TEST_MODULE sqs_messages_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_messages.hpp>
#include <kythira/sqs/sqs_queue_attributes.hpp>
#include <kythira/sqs/sqs_receipts.hpp>

#include <boost/json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace sqs = kythira::sqs;
namespace json = boost::json;

namespace {

auto attrs(std::string_view text) -> json::object {
    return json::parse(text).as_object();
}

auto failure_code(const std::optional<kythira::aws_json::error>& e) -> std::string {
    BOOST_TEST_REQUIRE(e.has_value());
    return sqs::to_query(*e).code;
}

}  // namespace

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(body_digest_is_md5_of_utf8) {
    BOOST_TEST(sqs::md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e");
    BOOST_TEST(sqs::md5_hex("h\xc3\xa9llo w\xc3\xb6rld") == "ed0c22cc110ede12327851863c078138");
}

BOOST_AUTO_TEST_CASE(attribute_digest_matches_sqs) {
    BOOST_TEST(sqs::md5_of_attributes(
                   attrs(R"({"color": {"DataType": "String", "StringValue": "blue"}})")) ==
               "da1b33cc3cbfe8b1630921e78e6b9880");
    // Sorted by name, binary values decoded, custom type suffixes kept.
    BOOST_TEST(sqs::md5_of_attributes(attrs(R"({
        "raw": {"DataType": "Binary", "BinaryValue": "AAEC"},
        "n": {"DataType": "Number.int", "StringValue": "42"},
        "color": {"DataType": "String", "StringValue": "blue"}})")) ==
               "96969c9f35035d420263799c2b688729");
    BOOST_TEST(sqs::md5_of_attributes(attrs(R"({"AWSTraceHeader": {"DataType": "String",
        "StringValue": "Root=1-5759e988-bd862e3fe1be46a994272793"}})")) ==
               "62a56dd927315f2b2e12832b84617ea5");
    BOOST_TEST(sqs::md5_of_attributes({}).empty());
}

// ---------------------------------------------------------------------------
// Attribute checks
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(good_attributes_pass) {
    BOOST_TEST(!sqs::check_attributes(attrs(R"({
        "a.b-c_D9": {"DataType": "String", "StringValue": "x"},
        "n": {"DataType": "Number", "StringValue": "-1.5e10"},
        "b": {"DataType": "Binary.png", "BinaryValue": "AAEC"}})"),
                                      false)
                    .has_value());
    BOOST_TEST(
        !sqs::check_attributes(
             attrs(R"({"AWSTraceHeader": {"DataType": "String", "StringValue": "Root=1"}})"), true)
             .has_value());
}

BOOST_AUTO_TEST_CASE(bad_attributes_fail_with_invalid_parameter_value) {
    const auto bad = [](std::string_view text, bool system = false) {
        return failure_code(sqs::check_attributes(attrs(text), system));
    };
    for (const auto* name : {"AWS.x", "amazon.y", ".lead", "trail.", "two..dots", "sp ace", ""}) {
        json::object o;
        o[name] = json::object{{"DataType", "String"}, {"StringValue", "v"}};
        BOOST_TEST(failure_code(sqs::check_attributes(o, false)) == "InvalidParameterValue", name);
    }
    BOOST_TEST(bad(R"({"a": {"DataType": "Text", "StringValue": "v"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "String.", "StringValue": "v"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"StringValue": "v"}})") == "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "String", "StringValue": ""}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "String", "BinaryValue": "AAEC"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "Binary", "StringValue": "x"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "String", "StringListValues": ["x"]}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "Number", "StringValue": "1x"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"a": {"DataType": "String", "StringValue": "\u0001"}})") ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"Other": {"DataType": "String", "StringValue": "x"}})", true) ==
               "InvalidParameterValue");
    BOOST_TEST(bad(R"({"AWSTraceHeader": {"DataType": "Number", "StringValue": "1"}})", true) ==
               "InvalidParameterValue");
    json::object eleven;
    for (int i = 0; i < 11; ++i) {
        eleven["a" + std::to_string(i)] =
            json::object{{"DataType", "String"}, {"StringValue", "v"}};
    }
    BOOST_TEST(failure_code(sqs::check_attributes(eleven, false)) == "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(number_attributes_follow_sqs_bounds) {
    const auto ok = [](std::string_view n) {
        json::object o;
        o["n"] = json::object{{"DataType", "Number"}, {"StringValue", n}};
        return !sqs::check_attributes(o, false).has_value();
    };
    BOOST_TEST(ok("0"));
    BOOST_TEST(ok("-0.000"));
    BOOST_TEST(ok("12345678901234567890123456789012345678"));       // 38 digits
    BOOST_TEST(!ok("123456789012345678901234567890123456789"));     // 39
    BOOST_TEST(ok("1230000000000000000000000000000000000000000"));  // trailing zeros scale
    BOOST_TEST(ok("1e126"));
    BOOST_TEST(!ok("1.1e126"));
    BOOST_TEST(ok("-1e128"));
    BOOST_TEST(!ok("-2e128"));
    BOOST_TEST(ok("1e-130"));
    BOOST_TEST(ok("+7"));
    BOOST_TEST(!ok("."));
    BOOST_TEST(!ok("1e"));
    BOOST_TEST(!ok("--1"));
}

BOOST_AUTO_TEST_CASE(bodies_take_xml_characters_only) {
    BOOST_TEST(sqs::valid_body("plain\ttext\r\n"));
    BOOST_TEST(sqs::valid_body("\xf0\x9f\x98\x80"));  // U+1F600
    BOOST_TEST(!sqs::valid_body(std::string_view("a\0b", 3)));
    BOOST_TEST(!sqs::valid_body("\x01"));
    BOOST_TEST(!sqs::valid_body("\xef\xbf\xbe"));  // U+FFFE
    BOOST_TEST(!sqs::valid_body("\xed\xa0\x80"));  // a surrogate
    BOOST_TEST(!sqs::valid_body("\xc0\xaf"));      // overlong
    BOOST_TEST(!sqs::valid_body("\xe2\x82"));      // cut
}

BOOST_AUTO_TEST_CASE(attributes_round_trip_and_select) {
    const auto a = attrs(R"({"color": {"DataType": "String", "StringValue": "blue"},
                             "x.one": {"DataType": "String", "StringValue": "1"},
                             "x.two": {"DataType": "Binary", "BinaryValue": "AAEC"}})");
    BOOST_TEST(sqs::encode_attributes({}).empty());
    BOOST_TEST(sqs::decode_attributes(sqs::encode_attributes(a)) == a);
    BOOST_TEST(sqs::decode_attributes("").empty());
    BOOST_TEST(sqs::decode_attributes("not json").empty());
    BOOST_TEST(sqs::attributes_size(a) == 5U + 6U + 4U + 5U + 6U + 1U + 5U + 6U + 3U);

    BOOST_TEST(sqs::select_attributes(a, {"All"}).size() == 3U);
    BOOST_TEST(sqs::select_attributes(a, {".*"}).size() == 3U);
    BOOST_TEST(sqs::select_attributes(a, {"x.*"}).size() == 2U);
    BOOST_TEST(sqs::select_attributes(a, {"color", "nope"}).size() == 1U);
    BOOST_TEST(sqs::select_attributes(a, {}).empty());
}

// ---------------------------------------------------------------------------
// Receipt handles
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(receipts_round_trip_and_refuse_forgeries) {
    const auto ring = sqs::parse_receipt_keys(
        "# rotation\n2 new-secret-0123456789\n1 "
        "old-secret-0123456789\n");
    const sqs::receipt_handle h{7, 3, 42, 5, 1794787200000};
    const auto token = sqs::encode_receipt(h, ring);
    BOOST_TEST(token.size() == 96U);
    BOOST_TEST((sqs::decode_receipt(token, 7, ring) == std::optional<sqs::receipt_handle>(h)));
    // Another queue's handle (a recreated queue has a new id).
    BOOST_TEST(!sqs::decode_receipt(token, 8, ring).has_value());
    // A flipped byte anywhere.
    for (std::size_t i = 0; i < token.size(); i += 7) {
        auto t = token;
        t[i] = t[i] == 'A' ? 'B' : 'A';
        BOOST_TEST(!sqs::decode_receipt(t, 7, ring).has_value(), i);
    }
    BOOST_TEST(!sqs::decode_receipt("", 7, ring).has_value());
    BOOST_TEST(!sqs::decode_receipt("not base64!", 7, ring).has_value());
    // The old key still verifies after a rotation; a ring without it does not.
    const auto old_ring = sqs::parse_receipt_keys("1 old-secret-0123456789\n");
    const auto old_token = sqs::encode_receipt(h, old_ring);
    BOOST_TEST(sqs::decode_receipt(old_token, 7, ring).has_value());
    BOOST_TEST(!sqs::decode_receipt(token, 7, old_ring).has_value());
    // The derived ring is stable per secret.
    const auto d1 = sqs::derived_receipt_key("cluster-secret");
    const auto d2 = sqs::derived_receipt_key("cluster-secret");
    BOOST_TEST(sqs::decode_receipt(sqs::encode_receipt(h, d1), 7, d2).has_value());
    BOOST_TEST(!sqs::decode_receipt(sqs::encode_receipt(h, d1), 7,
                                    sqs::derived_receipt_key("other-secret"))
                    .has_value());
}

BOOST_AUTO_TEST_CASE(receipt_key_files_are_checked) {
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys(""), std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys("x secret-0123456789ab"),
                      std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys("1 short"), std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys("1 a b"), std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys("4294967296 secret-0123456789ab"),
                      std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::parse_receipt_keys("1 secret-0123456789ab\n1 secret-0123456789cd"),
                      std::invalid_argument);
    BOOST_CHECK_THROW((void)sqs::encode_receipt({}, sqs::receipt_key_ring{}),
                      std::invalid_argument);
    try {
        (void)sqs::parse_receipt_keys("1 short-but-secret");
    } catch (const std::invalid_argument& e) {
        BOOST_TEST(std::string(e.what()).find("short-but-secret") == std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// Queue attributes
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(queue_attributes_apply_within_sqs_ranges) {
    const sqs::sqs_compat_profile aws;
    sqs::queue_settings s;
    BOOST_TEST(!sqs::apply_attributes(s, attrs(R"({"DelaySeconds": "900",
        "MaximumMessageSize": "1024", "MessageRetentionPeriod": "60",
        "ReceiveMessageWaitTimeSeconds": "20", "VisibilityTimeout": "43200",
        "Policy": "{\"Version\":\"2012-10-17\"}",
        "RedrivePolicy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:1:d\",\"maxReceiveCount\":\"5\"}",
        "RedriveAllowPolicy": "{\"redrivePermission\":\"byQueue\",\"sourceQueueArns\":[\"arn:x\"]}",
        "SqsManagedSseEnabled": "false", "KmsMasterKeyId": "alias/aws/sqs",
        "KmsDataKeyReusePeriodSeconds": "60"})"),
                                      false, aws)
                    .has_value());
    BOOST_TEST(s._delay_s == 900U);
    BOOST_TEST(s._max_message_bytes == 1024U);
    BOOST_TEST(s._visibility_s == 43200U);
    BOOST_TEST(!s._sqs_managed_sse);
    BOOST_TEST(s._kms_key_id == "alias/aws/sqs");

    const auto code = [&aws](std::string_view text, bool fifo = false, bool create = false) {
        sqs::queue_settings q;
        q._fifo = fifo;
        return failure_code(sqs::apply_attributes(q, attrs(text), create, aws));
    };
    BOOST_TEST(code(R"({"DelaySeconds": "901"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"MaximumMessageSize": "1048577"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"MessageRetentionPeriod": "59"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"ReceiveMessageWaitTimeSeconds": "21"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"VisibilityTimeout": "-1"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"VisibilityTimeout": "ten"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"Policy": "nope"})") == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"RedrivePolicy": "{\"maxReceiveCount\":5}"})") == "InvalidAttributeValue");
    BOOST_TEST(
        code(
            R"({"RedrivePolicy": "{\"deadLetterTargetArn\":\"arn:x\",\"maxReceiveCount\":1001}"})") ==
        "InvalidAttributeValue");
    BOOST_TEST(
        code(
            R"({"RedriveAllowPolicy": "{\"redrivePermission\":\"allowAll\",\"sourceQueueArns\":[]}"})") ==
        "InvalidAttributeValue");
    BOOST_TEST(code(R"({"KmsMasterKeyId": "k", "SqsManagedSseEnabled": "true"})") ==
               "InvalidAttributeValue");
    BOOST_TEST(code(R"({"Colour": "blue"})") == "InvalidAttributeName");
    BOOST_TEST(code(R"({"QueueArn": "x"})") == "InvalidAttributeName");
    BOOST_TEST(code(R"({"ContentBasedDeduplication": "true"})") == "InvalidAttributeName");
    BOOST_TEST(code(R"({"FifoQueue": "true"})") == "InvalidAttributeName");  // not on create
    BOOST_TEST(code(R"({"FifoQueue": "true"})", false, true) == "InvalidAttributeValue");
    BOOST_TEST(code(R"({"FifoThroughputLimit": "perMessageGroupId"})", true) ==
               "InvalidAttributeValue");  // needs DeduplicationScope=messageGroup

    sqs::queue_settings f;
    f._fifo = true;
    BOOST_TEST(!sqs::apply_attributes(f, attrs(R"({"FifoQueue": "true",
        "ContentBasedDeduplication": "true", "DeduplicationScope": "messageGroup",
        "FifoThroughputLimit": "perMessageGroupId"})"),
                                      true, aws)
                    .has_value());
    BOOST_TEST(f._content_dedup);
}

BOOST_AUTO_TEST_CASE(the_compat_profile_moves_attribute_ranges) {
    sqs::sqs_compat_profile p;
    BOOST_TEST(p.set("message-size", "4194304"));
    BOOST_TEST(p.set("long-poll-max", "60"));
    sqs::queue_settings s;
    BOOST_TEST(!sqs::apply_attributes(s, attrs(R"({"MaximumMessageSize": "4194304",
        "ReceiveMessageWaitTimeSeconds": "60"})"),
                                      false, p)
                    .has_value());
    BOOST_TEST(s._max_message_bytes == 4194304U);
}

BOOST_AUTO_TEST_CASE(fifo_requests_and_queue_names) {
    BOOST_TEST(*sqs::fifo_requested(attrs(R"({"FifoQueue": "TRUE"})")));
    BOOST_TEST(!*sqs::fifo_requested(attrs(R"({})")));
    BOOST_TEST(!sqs::fifo_requested(attrs(R"({"FifoQueue": "yes"})")).has_value());

    BOOST_TEST(sqs::valid_queue_name("orders", false));
    BOOST_TEST(sqs::valid_queue_name("A-b_9", false));
    BOOST_TEST(sqs::valid_queue_name(std::string(80, 'q'), false));
    BOOST_TEST(!sqs::valid_queue_name(std::string(81, 'q'), false));
    BOOST_TEST(!sqs::valid_queue_name("", false));
    BOOST_TEST(!sqs::valid_queue_name("dots.here", false));
    BOOST_TEST(!sqs::valid_queue_name("orders.fifo", false));
    BOOST_TEST(sqs::valid_queue_name("orders.fifo", true));
    BOOST_TEST(!sqs::valid_queue_name("orders", true));
    BOOST_TEST(!sqs::valid_queue_name(".fifo", true));
    BOOST_TEST(sqs::valid_queue_name(std::string(75, 'q') + ".fifo", true));
    BOOST_TEST(!sqs::valid_queue_name(std::string(76, 'q') + ".fifo", true));
}

BOOST_AUTO_TEST_CASE(get_queue_attributes_renders_what_was_asked) {
    sqs::queue_settings s;
    const sqs::queue_facts_view f{"arn:aws:sqs:us-east-1:111122223333:orders", 100, 200, 3, 2, 1};
    auto all = sqs::attribute_values(s, f, {"All"});
    BOOST_TEST_REQUIRE(all.has_value());
    BOOST_TEST(all->at("QueueArn").as_string() == f._arn);
    BOOST_TEST(all->at("ApproximateNumberOfMessages").as_string() == "3");
    BOOST_TEST(all->at("ApproximateNumberOfMessagesNotVisible").as_string() == "2");
    BOOST_TEST(all->at("ApproximateNumberOfMessagesDelayed").as_string() == "1");
    BOOST_TEST(all->at("VisibilityTimeout").as_string() == "30");
    BOOST_TEST(all->at("MaximumMessageSize").as_string() == "1048576");
    BOOST_TEST(all->at("MessageRetentionPeriod").as_string() == "345600");
    BOOST_TEST(all->at("SqsManagedSseEnabled").as_string() == "true");
    BOOST_TEST(!all->contains("Policy"));
    BOOST_TEST(!all->contains("FifoQueue"));

    auto some = sqs::attribute_values(s, f, {"VisibilityTimeout", "Policy"});
    BOOST_TEST_REQUIRE(some.has_value());
    BOOST_TEST(some->size() == 1U);  // no policy set
    BOOST_TEST(!sqs::attribute_values(s, f, {"Colour"}).has_value());
    BOOST_TEST(!sqs::attribute_values(s, f, {"FifoQueue"}).has_value());

    s._fifo = true;
    s._policy = R"({"Version":"2012-10-17"})";
    all = sqs::attribute_values(s, f, {"All"});
    BOOST_TEST_REQUIRE(all.has_value());
    BOOST_TEST(all->at("FifoQueue").as_string() == "true");
    BOOST_TEST(all->at("DeduplicationScope").as_string() == "queue");
    BOOST_TEST(all->at("Policy").as_string() == s._policy);
}
