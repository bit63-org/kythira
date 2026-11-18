// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// What the SNS front end is built from (`.kiro/specs/sns-compatible-
// notifications/` task 3, Requirements 2.2, 2.3, 3.1, 3.2): the query
// inputs as the recorded clients send them (maps, message attributes,
// batches, in any parameter order), base64, the errors' codes and
// statuses, topic and subscription ARNs, the default topic policy and
// AddPermission/RemovePermission, the compatibility switches and the
// limits each profile means, and the generated `sns` action table.

#define BOOST_TEST_MODULE sns_gateway_inputs_test
#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_actions.hpp>
#include <kythira/sns/sns_compat_profile.hpp>
#include <kythira/sns/sns_errors.hpp>
#include <kythira/sns/sns_query.hpp>
#include <kythira/sns/sns_topic_policy.hpp>

#include <raft/aws_query_protocol.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sns = kythira::sns;

namespace {

auto parse(std::string_view body) -> sns::param_map {
    const auto f = kythira::aws_query::form::parse(body);
    BOOST_REQUIRE(f.has_value());
    sns::param_map out;
    for (const auto& [k, v] : f->params()) {
        out.emplace(k, v);
    }
    return out;
}

constexpr std::string_view k_arn = "arn:aws:sns:us-east-1:111122223333:orders";

}  // namespace

BOOST_AUTO_TEST_SUITE(query_inputs)

BOOST_AUTO_TEST_CASE(attribute_maps_decode_by_name_in_any_order) {
    // The Go SDK sorts parameters (tests/evidence/data/go-sdk-v2.json), so
    // values may come before keys and entries out of order.
    const auto m = parse(
        "Attributes.entry.2.value=Orders&Attributes.entry.1.value=true"
        "&Attributes.entry.2.key=DisplayName&Attributes.entry.1.key=FifoTopic");
    const sns::params in(m);
    const auto attrs = in.string_map("Attributes");
    BOOST_REQUIRE(attrs.has_value());
    BOOST_TEST(attrs->size() == 2U);
    BOOST_TEST(attrs->at("FifoTopic") == "true");
    BOOST_TEST(attrs->at("DisplayName") == "Orders");
    BOOST_TEST(in.string_map("Absent")->empty());
}

BOOST_AUTO_TEST_CASE(bad_maps_are_invalid_parameters) {
    for (const auto* body : {"Attributes.entry.0.key=a&Attributes.entry.0.value=b",
                             "Attributes.entry.x.key=a", "Attributes.entry.1.colour=a",
                             "Attributes.member.1.key=a", "Attributes.entry.1.value=only-a-value",
                             "Attributes.entry.1.key=a&Attributes.entry.2.key=a"}) {
        const auto m = parse(body);
        const auto r = sns::params(m).string_map("Attributes");
        BOOST_TEST_INFO(body);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST(r.error()._code == "InvalidParameter");
        BOOST_TEST(r.error()._message.starts_with("Invalid parameter: Attributes"));
    }
}

BOOST_AUTO_TEST_CASE(message_attributes_of_each_type) {
    const auto m = parse(
        "MessageAttributes.entry.1.Name=color&MessageAttributes.entry.1.Value.DataType=String"
        "&MessageAttributes.entry.1.Value.StringValue=red"
        "&MessageAttributes.entry.2.Name=size&MessageAttributes.entry.2.Value.DataType=Number"
        "&MessageAttributes.entry.2.Value.StringValue=4"
        "&MessageAttributes.entry.3.Name=blob&MessageAttributes.entry.3.Value.DataType=Binary.png"
        "&MessageAttributes.entry.3.Value.BinaryValue=AAEC%2F%2Fs%3D");
    const auto a = sns::params(m).message_attrs();
    BOOST_REQUIRE(a.has_value());
    BOOST_TEST(a->size() == 3U);
    BOOST_TEST(*a->at("color")._string_value == "red");
    BOOST_TEST(a->at("size")._data_type == "Number");
    BOOST_TEST(a->at("blob")._data_type == "Binary.png");
    BOOST_TEST(*a->at("blob")._binary_value == std::string("\x00\x01\x02\xff\xfb", 5));
    BOOST_TEST(!a->at("blob")._string_value.has_value());
}

BOOST_AUTO_TEST_CASE(message_attribute_faults) {
    const auto code_of = [](std::string_view body) {
        const auto m = parse(body);
        const auto r = sns::params(m).message_attrs();
        return r.has_value() ? std::string("ok") : r.error()._code;
    };
    BOOST_TEST(code_of("MessageAttributes.entry.1.Value.DataType=String"
                       "&MessageAttributes.entry.1.Value.StringValue=x") == "InvalidParameter");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a"
                       "&MessageAttributes.entry.1.Value.StringValue=x") ==
               "ParameterValueInvalid");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a&MessageAttributes.entry.1.Value.DataType="
                       "Binary&MessageAttributes.entry.1.Value.StringValue=x") ==
               "ParameterValueInvalid");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a&MessageAttributes.entry.1.Value.DataType="
                       "Binary&MessageAttributes.entry.1.Value.BinaryValue=%21%21%21%21") ==
               "ParameterValueInvalid");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a&MessageAttributes.entry.1.Value.DataType="
                       "Date&MessageAttributes.entry.1.Value.StringValue=x") ==
               "ParameterValueInvalid");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a&MessageAttributes.entry.1.Value.DataType="
                       "String&MessageAttributes.entry.1.Value.StringValue=x"
                       "&MessageAttributes.entry.2.Name=a&MessageAttributes.entry.2.Value.DataType="
                       "String&MessageAttributes.entry.2.Value.StringValue=y") ==
               "InvalidParameter");
    BOOST_TEST(code_of("MessageAttributes.entry.1.Name=a&MessageAttributes.entry.1.Value.DataType="
                       "String.price&MessageAttributes.entry.1.Value.StringValue=x") == "ok");
}

BOOST_AUTO_TEST_CASE(tags_and_lists_keep_position_order) {
    const auto m = parse(
        "Tags.member.2.Key=b&Tags.member.2.Value=2&Tags.member.1.Key=a&Tags.member.1.Value=1"
        "&Tags.member.7.Key=c&TagKeys.member.10=z&TagKeys.member.2=y");
    const sns::params in(m);
    const auto tags = in.tags();
    BOOST_REQUIRE(tags.has_value());
    BOOST_TEST(tags->size() == 3U);
    BOOST_TEST(tags->at(0).first == "a");
    BOOST_TEST(tags->at(1).second == "2");
    BOOST_TEST(tags->at(2).first == "c");
    BOOST_TEST(tags->at(2).second.empty());
    const auto keys = in.list("TagKeys");
    BOOST_REQUIRE(keys.has_value());
    BOOST_TEST(*keys == (std::vector<std::string>{"y", "z"}));
    const auto bad = parse("TagKeys.member.-1=z");
    BOOST_TEST(!sns::params(bad).list("TagKeys").has_value());
}

BOOST_AUTO_TEST_CASE(required_parameters) {
    const auto m = parse("TopicArn=&Message=x");
    const sns::params in(m);
    BOOST_TEST(*in.required("Message") == "x");
    BOOST_TEST(in.required("TopicArn").error()._message == "Invalid parameter: TopicArn");
    BOOST_TEST(in.required("Subject").error()._code == "InvalidParameter");
}

BOOST_AUTO_TEST_CASE(batch_entries_are_parameter_sets_of_their_own) {
    const auto m = parse(
        "TopicArn=t&PublishBatchRequestEntries.member.2.Id=two"
        "&PublishBatchRequestEntries.member.2.Message=second"
        "&PublishBatchRequestEntries.member.1.Id=one"
        "&PublishBatchRequestEntries.member.1.Message=first"
        "&PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Name=k"
        "&PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Value.DataType=String"
        "&PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Value.StringValue=v");
    const auto entries = sns::params(m).batch("PublishBatchRequestEntries", 10);
    BOOST_REQUIRE(entries.has_value());
    BOOST_REQUIRE_EQUAL(entries->size(), 2U);
    BOOST_TEST(*entries->at(0).get("Id") == "one");
    BOOST_TEST(*entries->at(1).get("Message") == "second");
    BOOST_TEST(!entries->at(0).contains("TopicArn"));
    const auto attrs = entries->at(0).message_attrs();
    BOOST_REQUIRE(attrs.has_value());
    BOOST_TEST(*attrs->at("k")._string_value == "v");
    BOOST_TEST(entries->at(1).message_attrs()->empty());
}

BOOST_AUTO_TEST_CASE(batch_rules_in_sns_order) {
    const auto code_of = [](const std::string& body) {
        const auto m = parse(body);
        const auto r = sns::params(m).batch("E", 10);
        return r.has_value() ? std::string("ok") : r.error()._code;
    };
    BOOST_TEST(code_of("TopicArn=t") == "EmptyBatchRequest");
    std::string eleven;
    for (int i = 1; i <= 11; ++i) {
        eleven += "&E.member." + std::to_string(i) + ".Id=e" + std::to_string(i);
    }
    BOOST_TEST(code_of(eleven.substr(1)) == "TooManyEntriesInBatchRequest");
    BOOST_TEST(code_of("E.member.1.Message=m") == "InvalidBatchEntryId");
    BOOST_TEST(code_of("E.member.1.Id=has%20space") == "InvalidBatchEntryId");
    BOOST_TEST(code_of("E.member.1.Id=" + std::string(81, 'a')) == "InvalidBatchEntryId");
    BOOST_TEST(code_of("E.member.1.Id=" + std::string(80, 'a')) == "ok");
    BOOST_TEST(code_of("E.member.1.Id=x&E.member.2.Id=x") == "BatchEntryIdsNotDistinct");
    BOOST_TEST(code_of("E.member.0.Id=x") == "InvalidParameter");
    BOOST_TEST(code_of("E.entry.1.Id=x") == "InvalidParameter");
}

BOOST_AUTO_TEST_CASE(base64_round_trips_and_refuses_junk) {
    std::mt19937 rng(7);
    for (int n = 0; n < 200; ++n) {
        std::string s(static_cast<std::size_t>(n % 37), '\0');
        for (auto& c : s) {
            c = static_cast<char>(rng() & 0xFFU);
        }
        const auto e = sns::base64_encode(s);
        BOOST_TEST(e.size() % 4 == 0U);
        BOOST_TEST(*sns::base64_decode(e) == s);
    }
    BOOST_TEST(sns::base64_encode("foob") == "Zm9vYg==");
    for (const auto* bad : {"Zm9", "Zm9v=Yg=", "Z===", "Zm9vYg=a", "Zm9v Yg==", "Zm-_"}) {
        BOOST_TEST_INFO(bad);
        BOOST_TEST(!sns::base64_decode(bad).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(errors)

BOOST_AUTO_TEST_CASE(modelled_errors_take_the_models_code_and_status) {
    BOOST_TEST(sns::not_found("x")._code == "NotFound");
    BOOST_TEST(sns::not_found("x")._status == 404U);
    BOOST_TEST(sns::authorization_error("x")._status == 403U);
    BOOST_TEST(sns::invalid_parameter_value("x")._code == "ParameterValueInvalid");
    BOOST_TEST(sns::throttled()._status == 429U);
    const auto ie = sns::internal_error();
    BOOST_TEST(ie._code == "InternalError");
    BOOST_TEST(ie._status == 500U);
    BOOST_TEST(!ie._sender_fault);
    BOOST_TEST(sns::invalid_parameter("Name", "must be short")._message ==
               "Invalid parameter: Name Reason: must be short");
    BOOST_CHECK_THROW((void)sns::model_error("NoSuchException", "x"), std::invalid_argument);
    static_assert(sns::error_index("NotFoundException") < sns::error_shapes.size());
    BOOST_REQUIRE(sns::find_operation("PublishBatch") != nullptr);
    BOOST_TEST(sns::find_operation("PublishBatch")->_batch);
    BOOST_TEST(sns::find_operation("SendMessage") == nullptr);
    for (const auto& op : sns::operations) {
        BOOST_TEST(sns::find_operation(op._name) == &op);
    }
}

BOOST_AUTO_TEST_CASE(sigv4_errors_pass_through) {
    const auto e = sns::from_sigv4({"SignatureDoesNotMatch", "no", 403});
    BOOST_TEST(e._code == "SignatureDoesNotMatch");
    BOOST_TEST(e._status == 403U);
    BOOST_TEST(e._sender_fault);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(arns_and_policies)

BOOST_AUTO_TEST_CASE(topic_names_and_arns) {
    BOOST_TEST(sns::valid_topic_name("orders", false));
    BOOST_TEST(sns::valid_topic_name("Orders_2-x", false));
    BOOST_TEST(!sns::valid_topic_name("orders.fifo", false));
    BOOST_TEST(sns::valid_topic_name("orders.fifo", true));
    BOOST_TEST(!sns::valid_topic_name("orders", true));
    BOOST_TEST(!sns::valid_topic_name(".fifo", true));
    BOOST_TEST(!sns::valid_topic_name("", false));
    BOOST_TEST(!sns::valid_topic_name("a b", false));
    BOOST_TEST(sns::valid_topic_name(std::string(256, 'a'), false));
    BOOST_TEST(!sns::valid_topic_name(std::string(257, 'a'), false));

    const auto p = sns::parse_topic_arn(k_arn);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->_partition == "aws");
    BOOST_TEST(p->_region == "us-east-1");
    BOOST_TEST(p->_account == "111122223333");
    BOOST_TEST(p->_name == "orders");
    BOOST_TEST(sns::parse_topic_arn("arn:aws-cn:sns:cn-north-1:111122223333:o.fifo").has_value());
    for (const auto* bad :
         {"arn:aws:sns:us-east-1:111122223333", "arn:aws:sqs:us-east-1:111122223333:q",
          "arn:aws:sns:us-east-1:11112222333x:o", "arn:aws:sns::111122223333:o",
          "arn:aws:sns:us-east-1:111122223333:o:extra"}) {
        BOOST_TEST_INFO(bad);
        BOOST_TEST(!sns::parse_topic_arn(bad).has_value());
    }
}

BOOST_AUTO_TEST_CASE(subscription_arns_name_their_topic) {
    const std::string sub = std::string(k_arn) + ":0e9b2b1c-4f1a-4c0e-9a77-8d8f3b0d6c11";
    BOOST_TEST(*sns::topic_of_subscription(sub) == k_arn);
    BOOST_TEST(!sns::topic_of_subscription("pending confirmation").has_value());
    BOOST_TEST(!sns::topic_of_subscription(k_arn).has_value());
    BOOST_TEST(!sns::topic_of_subscription(std::string(k_arn) + ":").has_value());
}

BOOST_AUTO_TEST_CASE(the_default_policy_is_snss) {
    BOOST_TEST(sns::default_topic_policy(k_arn, "111122223333") ==
               R"({"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":)"
               R"("__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":)"
               R"(["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission",)"
               R"("SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe",)"
               R"("SNS:ListSubscriptionsByTopic","SNS:Publish"],"Resource":)"
               R"("arn:aws:sns:us-east-1:111122223333:orders","Condition":{"StringEquals":)"
               R"({"AWS:SourceOwner":"111122223333"}}}]})");
}

BOOST_AUTO_TEST_CASE(add_and_remove_permission) {
    const auto base = sns::default_topic_policy(k_arn, "111122223333");
    const auto one = sns::add_permission(base, k_arn, "aws", "pub", {"444455556666"}, {"Publish"});
    BOOST_REQUIRE(one.has_value());
    const auto doc = boost::json::parse(*one).as_object();
    const auto& st = doc.at("Statement").as_array();
    BOOST_REQUIRE_EQUAL(st.size(), 2U);
    BOOST_TEST(boost::json::serialize(st[1]) ==
               R"({"Sid":"pub","Effect":"Allow","Principal":{"AWS":)"
               R"("arn:aws:iam::444455556666:root"},"Action":"SNS:Publish","Resource":)"
               R"("arn:aws:sns:us-east-1:111122223333:orders"})");

    const auto two = sns::add_permission(
        *one, k_arn, "aws", "many", {"444455556666", "777788889999"}, {"Publish", "Subscribe"});
    BOOST_REQUIRE(two.has_value());
    const auto st2 = boost::json::parse(*two).as_object().at("Statement").as_array();
    BOOST_TEST(st2[2].as_object().at("Action").is_array());
    BOOST_TEST(st2[2].as_object().at("Principal").as_object().at("AWS").as_array().size() == 2U);

    const auto again =
        sns::add_permission(*one, k_arn, "aws", "pub", {"444455556666"}, {"Publish"});
    BOOST_TEST(again.error()._code == "InvalidParameter");
    const auto scope = sns::add_permission(base, k_arn, "aws", "x", {"444455556666"},
                                           {"CreatePlatformApplication"});
    BOOST_TEST(scope.error()._message ==
               "Invalid parameter: Policy statement action out of service scope!");
    BOOST_TEST(!sns::add_permission(base, k_arn, "aws", "x", {"4444"}, {"Publish"}).has_value());
    BOOST_TEST(!sns::add_permission(base, k_arn, "aws", "bad label", {"444455556666"}, {"Publish"})
                    .has_value());
    BOOST_TEST(!sns::add_permission(base, k_arn, "aws", "x", {}, {"Publish"}).has_value());
    BOOST_TEST(!sns::add_permission(base, k_arn, "aws", "x", {"444455556666"}, {}).has_value());

    const auto removed = sns::remove_permission(*two, "pub");
    BOOST_REQUIRE(removed.has_value());
    const auto st3 = boost::json::parse(*removed).as_object().at("Statement").as_array();
    BOOST_TEST(st3.size() == 2U);
    BOOST_TEST(st3[1].as_object().at("Sid").as_string() == "many");
    BOOST_TEST(sns::remove_permission(*removed, "pub").error()._code == "InvalidParameter");
}

BOOST_AUTO_TEST_CASE(topic_policies_are_checked_before_they_are_stored) {
    BOOST_TEST(sns::check_topic_policy(R"({"Statement":{"Effect":"Allow"}})").has_value());
    BOOST_TEST(sns::check_topic_policy(R"({"Statement":[]})").has_value());
    for (const auto* bad : {"", "[]", "{", R"({"Version":"2012-10-17"})", R"({"Statement":[1]})"}) {
        BOOST_TEST_INFO(bad);
        const auto r = sns::check_topic_policy(bad);
        BOOST_REQUIRE(!r.has_value());
        BOOST_TEST(
            r.error()._message.starts_with("Invalid parameter: Policy Reason: Policy Error:"));
    }
    const std::string big =
        R"({"Statement":[],"Pad":")" + std::string(sns::k_max_topic_policy_bytes, 'x') + "\"}";
    BOOST_TEST(!sns::check_topic_policy(big).has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(compatibility)

BOOST_AUTO_TEST_CASE(aws_is_the_default_and_tags_override_the_cluster) {
    const sns::sns_compat_profile aws;
    BOOST_TEST(aws.relaxed().empty());
    const auto cluster = sns::cluster_profile({{"Throttling", "OFF"}, {"count-limits", "relaxed"}});
    BOOST_REQUIRE(cluster.has_value());
    BOOST_TEST(cluster->relaxed() == (std::vector<std::string_view>{"throttling", "count-limits"}));
    const auto topic = sns::resolve_profile(
        *cluster, {{"kythira:compat:throttling", "on"},
                   {"kythira:compat:message-size", "4194304"},
                   {"kythira:compat:signing-cert-host", "SNS.Kythira.Test:8443"},
                   {"kythira:compat:nonsense", "x"},
                   {"team", "red"}});
    BOOST_TEST(topic._throttling);
    BOOST_TEST(!topic._aws_count_limits);
    BOOST_TEST(*topic._message_bytes == 4'194'304U);
    BOOST_TEST(topic._signing_cert_host == "sns.kythira.test:8443");
    std::string bad;
    BOOST_TEST(!sns::cluster_profile({{"message-size", "huge"}}, &bad).has_value());
    BOOST_TEST(bad == "message-size=huge");
}

BOOST_AUTO_TEST_CASE(bad_compat_tags_are_refused) {
    BOOST_TEST(!sns::check_compat_tags({{"kythira:compat:throttling", "on"}, {"x", "y"}}));
    for (const auto& bad :
         {std::pair<std::string, std::string>{"kythira:compat:throttling", "maybe"},
          {"kythira:compat:message-size", "1023"},
          {"kythira:compat:message-size", "16777217"},
          {"kythira:compat:message-size", "-5"},
          {"kythira:compat:signing-cert-host", "bad host"},
          {"kythira:compat:signing-cert-host", "-x.test"},
          {"kythira:compat:signing-cert-host", "x.test:0"},
          {"kythira:compat:signing-cert-host", "x..test"},
          {"kythira:compat:unknown", "aws"}}) {
        BOOST_TEST_INFO(bad.first + "=" + bad.second);
        const auto e = sns::check_compat_tags({bad});
        BOOST_REQUIRE(e.has_value());
        BOOST_TEST(e->_code == "InvalidParameter");
        BOOST_TEST(e->_message.starts_with("Invalid parameter: Tags Reason: Unknown Kythira"));
    }
}

BOOST_AUTO_TEST_CASE(limits_follow_the_profile_and_region) {
    const sns::sns_limits virginia({}, "us-east-1");
    BOOST_TEST(virginia.max_message_bytes(std::nullopt) == 262'144U);
    BOOST_TEST(virginia.max_message_bytes(1'048'576U) == 1'048'576U);
    BOOST_TEST(virginia.max_message_bytes(2'000'000U) == 1'048'576U);
    BOOST_TEST(virginia.publish_per_second(false) == 30'000U);
    BOOST_TEST(virginia.api_per_second("CreateTopic") == 3'000U);
    BOOST_TEST(virginia.api_per_second("Subscribe") == 100U);
    BOOST_TEST(virginia.api_per_second("ListTopics") == 30U);
    BOOST_TEST(virginia.api_per_second("PutDataProtectionPolicy") == 1U);
    BOOST_TEST(virginia.api_per_second("Publish") == 0U);
    BOOST_TEST(virginia.topics_per_account(true) == 1'000U);
    BOOST_TEST(virginia.subscriptions_per_topic(false) == 12'500'000U);
    BOOST_TEST(virginia.subscriptions_per_topic(true) == 100U);
    BOOST_TEST(virginia.pending_subscriptions_per_account() == 5'000U);
    BOOST_TEST(virginia.fifo_topic_messages_per_second() == 3'000U);
    BOOST_TEST(virginia.fifo_group_messages_per_second() == 300U);
    BOOST_TEST(virginia.signing_cert_host() == "sns.us-east-1.amazonaws.com");

    BOOST_TEST(sns::sns_limits({}, "eu-west-1").publish_per_second(false) == 9'000U);
    BOOST_TEST(sns::sns_limits({}, "ap-northeast-1").publish_per_second(false) == 1'500U);
    BOOST_TEST(sns::sns_limits({}, "ap-northeast-1").publish_per_second(true) == 3'000U);
    BOOST_TEST(sns::sns_limits({}, "eu-west-2").publish_per_second(false) == 300U);
    BOOST_TEST(sns::sns_limits({}, "eu-west-2").api_per_second("DeleteTopic") == 30U);
    BOOST_TEST(sns::sns_limits({}, "us-west-2").api_per_second("SetTopicAttributes") == 900U);
    BOOST_TEST(sns::sns_limits({}, "eu-central-1").api_per_second("GetTopicAttributes") == 150U);

    sns::sns_compat_profile relaxed;
    BOOST_TEST(relaxed.set("throttling", "off"));
    BOOST_TEST(relaxed.set("count-limits", "relaxed"));
    BOOST_TEST(relaxed.set("fifo-throughput", "relaxed"));
    BOOST_TEST(relaxed.set("message-size", "8388608"));
    BOOST_TEST(relaxed.set("signing-cert-host", "sns.kythira.test"));
    const sns::sns_limits open(relaxed, "us-east-1");
    BOOST_TEST(open.publish_per_second(false) == 0U);
    BOOST_TEST(open.api_per_second("Subscribe") == 0U);
    BOOST_TEST(open.topics_per_account(false) == 0U);
    BOOST_TEST(open.fifo_topic_bytes_per_second() == 0U);
    BOOST_TEST(open.max_message_bytes(std::nullopt) == 8'388'608U);
    BOOST_TEST(open.signing_cert_host() == "sns.kythira.test");
    BOOST_TEST(relaxed.set("message-size", "aws"));
    BOOST_TEST(!relaxed._message_bytes.has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(action_table)

BOOST_AUTO_TEST_CASE(every_modelled_operation_has_an_action) {
    for (const auto& op : sns::operations) {
        BOOST_TEST_INFO(op._name);
        BOOST_TEST(sns::find_operation_actions(op._name) != nullptr);
    }
    const auto* batch = sns::find_operation_actions("PublishBatch");
    BOOST_REQUIRE(batch != nullptr);
    BOOST_TEST(batch->actions[0] == "Publish");
    BOOST_TEST(batch->writes);
    BOOST_TEST(!sns::find_operation_actions("ListTopics")->writes);
    BOOST_TEST(sns::find_operation_actions("SendMessage") == nullptr);
}

BOOST_AUTO_TEST_CASE(subscribe_carries_its_condition_keys) {
    const auto table = sns::sns_actions();
    BOOST_TEST(table.service_prefix == "sns");
    const auto it = std::find_if(table.actions.begin(), table.actions.end(),
                                 [](const auto& a) { return a.name == "Subscribe"; });
    BOOST_REQUIRE(it != table.actions.end());
    BOOST_TEST(std::count(it->condition_keys.begin(), it->condition_keys.end(), "sns:Protocol") ==
               1);
    BOOST_TEST(std::count(it->condition_keys.begin(), it->condition_keys.end(), "sns:Endpoint") ==
               1);
    BOOST_TEST(it->resource_templates ==
               std::vector<std::string>{"arn:${Partition}:sns:${Region}:${Account}:${TopicName}"});
}

BOOST_AUTO_TEST_CASE(static_roles_split_reads_data_and_management) {
    const auto roles = sns::sns_static_roles();
    const auto has = [](const std::vector<std::string>& v, std::string_view a) {
        return std::find(v.begin(), v.end(), a) != v.end();
    };
    BOOST_TEST(has(roles.read_only, "ListTopics"));
    BOOST_TEST(has(roles.read_only, "GetTopicAttributes"));
    BOOST_TEST(!has(roles.read_only, "Publish"));
    BOOST_TEST(has(roles.read_write, "Publish"));
    BOOST_TEST(has(roles.read_write, "Subscribe"));
    BOOST_TEST(!has(roles.read_write, "DeleteTopic"));
    BOOST_TEST(!has(roles.read_write, "AddPermission"));
}

BOOST_AUTO_TEST_SUITE_END()
