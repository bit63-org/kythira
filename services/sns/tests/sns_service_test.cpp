// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SNS topic operations (`.kiro/specs/sns-compatible-notifications/`
// task 4, Requirement 4.1), end to end through the front end and a local
// topic store: CreateTopic's idempotency and validation, FIFO naming and
// FIFO-only attributes, the attributes GetTopicAttributes derives, the
// default and edited topic policy (AddPermission, RemovePermission, and
// what authorization sees), ListTopics pages and tokens, tags and their
// limits, data protection policies, deletion and ids that are never
// reused, and a cross-account caller acting on the owner's topic.

#define BOOST_TEST_MODULE sns_service_test
#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_service.hpp>

#include <boost/json.hpp>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sns = kythira::sns;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace q = kythira::aws_query;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_other = "444455556666";

auto topic(std::string_view name, std::string_view account = k_account) -> std::string {
    return "arn:aws:sns:us-east-1:" + std::string(account) + ":" + std::string(name);
}

/// Authenticates every request as a user of `account` and allows it: the
/// authorization rules are the front end's tests' subject, not these.
struct allow_all {
    az::principal_context who;
    explicit allow_all(std::string_view account = k_account) { as(account); }
    void as(std::string_view account) {
        who.account = std::string(account);
        who.arn = "arn:aws:iam::" + std::string(account) + ":user/alice";
        who.access_key_id = "AKIDALICE";
    }
    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        return who;
    }
    auto authorize(const az::principal_context&, const az::authz_request&) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = true;
        return d;
    }
};

static_assert(az::aws_request_authorizer<allow_all>);

auto element(const std::string& xml, std::string_view tag, std::size_t from = 0) -> std::string {
    const auto open = "<" + std::string(tag) + ">";
    const auto close = "</" + std::string(tag) + ">";
    const auto a = xml.find(open, from);
    const auto b = xml.find(close, a);
    if (a == std::string::npos || b == std::string::npos) {
        return {};
    }
    return xml.substr(a + open.size(), b - a - open.size());
}

auto count(const std::string& xml, std::string_view needle) -> std::size_t {
    std::size_t n = 0;
    for (auto at = xml.find(needle); at != std::string::npos; at = xml.find(needle, at + 1)) {
        ++n;
    }
    return n;
}

/// The value of `key` in an `<entry><key/><value/></entry>` map.
/// `<absent>` when there is none.
auto entry(const std::string& xml, std::string_view key) -> std::string {
    const auto k = "<key>" + std::string(key) + "</key><value>";
    const auto a = xml.find(k);
    if (a == std::string::npos) {
        return "<absent>";
    }
    const auto b = xml.find("</value>", a);
    return xml.substr(a + k.size(), b - a - k.size());
}

auto unescape(std::string s) -> std::string {
    for (const auto& [from, to] : std::vector<std::pair<std::string, std::string>>{
             {"&quot;", "\""}, {"&lt;", "<"}, {"&gt;", ">"}, {"&apos;", "'"}, {"&amp;", "&"}}) {
        for (auto at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size())) {
            s.replace(at, from.size(), to);
        }
    }
    return s;
}

struct fixture {
    allow_all auth;
    sns::front_end<allow_all> fe{sns::front_end_config{}, auth};
    sns::local_topic_store<> store;
    std::int64_t now = 1'763'467'200'000;
    sns::sns_service service{store, [this] {
                                 sns::service_config c;
                                 c._now_ms = [this] { return now; };
                                 return c;
                             }()};

    fixture() { service.attach(fe); }

    /// Calls `action` with `params` (name, value pairs, encoded here).
    auto call(std::string_view action,
              const std::vector<std::pair<std::string, std::string>>& params = {})
        -> sns::front_end_response {
        std::string body = "Action=" + std::string(action) + "&Version=2010-03-31";
        for (const auto& [k, v] : params) {
            body += "&" + q::url_encode(k) + "=" + q::url_encode(v);
        }
        sns::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = std::move(body);
        r._headers = {{"Host", "sns.us-east-1.amazonaws.com"},
                      {"Content-Type", "application/x-www-form-urlencoded"}};
        return fe.handle(r);
    }

    auto create(std::string_view name, std::vector<std::pair<std::string, std::string>> extra = {})
        -> std::string {
        extra.insert(extra.begin(), {"Name", std::string(name)});
        const auto r = call("CreateTopic", extra);
        BOOST_REQUIRE_MESSAGE(r._status == 200U, r._body);
        return element(r._body, "TopicArn");
    }

    auto attributes(std::string_view arn) -> std::string {
        const auto r = call("GetTopicAttributes", {{"TopicArn", std::string(arn)}});
        BOOST_REQUIRE_MESSAGE(r._status == 200U, r._body);
        return r._body;
    }
};

auto code(const sns::front_end_response& r) -> std::string {
    return element(r._body, "Code");
}
auto message(const sns::front_end_response& r) -> std::string {
    return element(r._body, "Message");
}

}  // namespace

BOOST_AUTO_TEST_SUITE(create_topic)

BOOST_FIXTURE_TEST_CASE(answers_the_arn_and_is_idempotent, fixture) {
    const auto arn = create("orders", {{"Attributes.entry.1.key", "DisplayName"},
                                       {"Attributes.entry.1.value", "Orders"}});
    BOOST_TEST(arn == topic("orders"));
    BOOST_TEST(create("orders", {{"Attributes.entry.1.key", "DisplayName"},
                                 {"Attributes.entry.1.value", "Orders"}}) == arn);
    BOOST_TEST(store.machine().topic_count() == 1U);

    const auto different = call("CreateTopic", {{"Name", "orders"},
                                                {"Attributes.entry.1.key", "DisplayName"},
                                                {"Attributes.entry.1.value", "Other"}});
    BOOST_TEST(different._status == 400U);
    BOOST_TEST(code(different) == "InvalidParameter");
    BOOST_TEST(message(different) ==
               "Invalid parameter: Attributes Reason: Topic already exists with different "
               "attributes");
}

BOOST_FIXTURE_TEST_CASE(different_tags_are_refused, fixture) {
    create("tagged", {{"Tags.member.1.Key", "team"}, {"Tags.member.1.Value", "a"}});
    const auto r =
        call("CreateTopic",
             {{"Name", "tagged"}, {"Tags.member.1.Key", "team"}, {"Tags.member.1.Value", "b"}});
    BOOST_TEST(code(r) == "InvalidParameter");
    BOOST_TEST(message(r) ==
               "Invalid parameter: Tags Reason: Topic already exists with different tags");
}

BOOST_FIXTURE_TEST_CASE(names_and_attributes_are_checked, fixture) {
    for (const auto* bad : {"", "has space", "x.fifo"}) {
        const auto r = call("CreateTopic", {{"Name", bad}});
        BOOST_TEST(code(r) == "InvalidParameter", bad);
    }
    const auto missing = call("CreateTopic");
    BOOST_TEST(code(missing) == "InvalidParameter");

    const auto unknown = call(
        "CreateTopic",
        {{"Name", "t"}, {"Attributes.entry.1.key", "Colour"}, {"Attributes.entry.1.value", "red"}});
    BOOST_TEST(code(unknown) == "InvalidParameter");

    const auto version = call("CreateTopic", {{"Name", "t"},
                                              {"Attributes.entry.1.key", "SignatureVersion"},
                                              {"Attributes.entry.1.value", "3"}});
    BOOST_TEST(code(version) == "InvalidParameter");

    const auto policy = call("CreateTopic", {{"Name", "t"},
                                             {"Attributes.entry.1.key", "Policy"},
                                             {"Attributes.entry.1.value", "not json"}});
    BOOST_TEST(code(policy) == "InvalidParameter");

    const auto dedup = call("CreateTopic", {{"Name", "t"},
                                            {"Attributes.entry.1.key", "ContentBasedDeduplication"},
                                            {"Attributes.entry.1.value", "true"}});
    BOOST_TEST(code(dedup) == "InvalidParameter");
    BOOST_TEST(store.machine().topic_count() == 0U);
}

BOOST_FIXTURE_TEST_CASE(a_fifo_topic_needs_the_suffix_and_the_attribute, fixture) {
    const auto no_suffix = call("CreateTopic", {{"Name", "jobs"},
                                                {"Attributes.entry.1.key", "FifoTopic"},
                                                {"Attributes.entry.1.value", "true"}});
    BOOST_TEST(code(no_suffix) == "InvalidParameter");

    const auto arn = create("jobs.fifo", {{"Attributes.entry.1.key", "FifoTopic"},
                                          {"Attributes.entry.1.value", "true"},
                                          {"Attributes.entry.2.key", "ContentBasedDeduplication"},
                                          {"Attributes.entry.2.value", "true"}});
    BOOST_TEST(arn == topic("jobs.fifo"));
    const auto attrs = attributes(arn);
    BOOST_TEST(entry(attrs, "FifoTopic") == "true");
    BOOST_TEST(entry(attrs, "ContentBasedDeduplication") == "true");
    // FifoTopic is the record's flag, not a stored attribute, so the same
    // request again is idempotent.
    const auto again = call("CreateTopic", {{"Name", "jobs.fifo"},
                                            {"Attributes.entry.1.key", "FifoTopic"},
                                            {"Attributes.entry.1.value", "true"},
                                            {"Attributes.entry.2.key", "ContentBasedDeduplication"},
                                            {"Attributes.entry.2.value", "true"}});
    BOOST_TEST(element(again._body, "TopicArn") == arn);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(attributes)

BOOST_FIXTURE_TEST_CASE(get_reports_what_sns_derives, fixture) {
    const auto arn = create("orders");
    const auto attrs = attributes(arn);
    BOOST_TEST(entry(attrs, "TopicArn") == arn);
    BOOST_TEST(entry(attrs, "Owner") == std::string(k_account));
    BOOST_TEST(entry(attrs, "DisplayName") == "");
    BOOST_TEST(entry(attrs, "SubscriptionsConfirmed") == "0");
    BOOST_TEST(entry(attrs, "SubscriptionsPending") == "0");
    BOOST_TEST(entry(attrs, "SubscriptionsDeleted") == "0");
    BOOST_TEST(entry(attrs, "FifoTopic") == "<absent>");
    const auto policy = unescape(entry(attrs, "Policy"));
    BOOST_TEST(policy == sns::default_topic_policy(arn, k_account));
    const auto delivery = unescape(entry(attrs, "EffectiveDeliveryPolicy"));
    BOOST_TEST(delivery == sns::k_default_effective_delivery_policy);
}

BOOST_FIXTURE_TEST_CASE(set_changes_one_attribute, fixture) {
    const auto arn = create("orders");
    const auto r = call(
        "SetTopicAttributes",
        {{"TopicArn", arn}, {"AttributeName", "DisplayName"}, {"AttributeValue", "Orders & Co"}});
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(unescape(entry(attributes(arn), "DisplayName")) == "Orders & Co");

    const std::string delivery = R"({"http":{"defaultHealthyRetryPolicy":{"numRetries":5}}})";
    BOOST_TEST(
        call("SetTopicAttributes",
             {{"TopicArn", arn}, {"AttributeName", "DeliveryPolicy"}, {"AttributeValue", delivery}})
            ._status == 200U);
    BOOST_TEST(unescape(entry(attributes(arn), "EffectiveDeliveryPolicy")) == delivery);
}

BOOST_FIXTURE_TEST_CASE(set_refuses_what_sns_refuses, fixture) {
    const auto arn = create("orders");
    const auto set = [&](std::string name, std::string value) {
        return call("SetTopicAttributes",
                    {{"TopicArn", arn}, {"AttributeName", name}, {"AttributeValue", value}});
    };
    BOOST_TEST(code(set("Colour", "red")) == "InvalidParameter");
    BOOST_TEST(message(set("Colour", "red")) == "Invalid parameter: AttributeName");
    BOOST_TEST(code(set("FifoTopic", "true")) == "InvalidParameter");
    BOOST_TEST(code(set("DataProtectionPolicy", "{}")) == "InvalidParameter");
    BOOST_TEST(code(set("ContentBasedDeduplication", "true")) == "InvalidParameter");
    BOOST_TEST(code(set("TracingConfig", "Sometimes")) == "InvalidParameter");
    BOOST_TEST(code(set("HTTPSuccessFeedbackSampleRate", "101")) == "InvalidParameter");
    BOOST_TEST(set("HTTPSuccessFeedbackSampleRate", "100")._status == 200U);
    BOOST_TEST(set("TracingConfig", "Active")._status == 200U);
    BOOST_TEST(set("SignatureVersion", "2")._status == 200U);
    BOOST_TEST(entry(attributes(arn), "SignatureVersion") == "2");

    const auto gone = call(
        "SetTopicAttributes",
        {{"TopicArn", topic("nope")}, {"AttributeName", "DisplayName"}, {"AttributeValue", "x"}});
    BOOST_TEST(gone._status == 404U);
    BOOST_TEST(code(gone) == "NotFound");
    BOOST_TEST(message(gone) == "Topic does not exist");
}

BOOST_FIXTURE_TEST_CASE(another_region_names_no_topic_here, fixture) {
    create("orders");
    const auto r =
        call("GetTopicAttributes", {{"TopicArn", "arn:aws:sns:eu-west-1:111122223333:orders"}});
    BOOST_TEST(code(r) == "NotFound");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(listing)

BOOST_FIXTURE_TEST_CASE(list_topics_pages_by_100, fixture) {
    for (int i = 0; i < 150; ++i) {
        const auto n = std::to_string(i);
        create("t" + std::string(3 - n.size(), '0') + n);
    }
    auth.as(k_other);
    create("theirs");
    auth.as(k_account);

    const auto first = call("ListTopics");
    BOOST_TEST(count(first._body, "<TopicArn>") == 100U);
    BOOST_TEST(element(first._body, "TopicArn") == topic("t000"));
    const auto token = element(first._body, "NextToken");
    BOOST_TEST(!token.empty());

    const auto second = call("ListTopics", {{"NextToken", token}});
    BOOST_TEST(count(second._body, "<TopicArn>") == 50U);
    BOOST_TEST(element(second._body, "TopicArn") == topic("t100"));
    BOOST_TEST(element(second._body, "NextToken").empty());
    BOOST_TEST(second._body.find("theirs") == std::string::npos);

    const auto forged = call("ListTopics", {{"NextToken", "dDA0OQ"}});
    BOOST_TEST(code(forged) == "InvalidParameter");

    // Another account's token does not open for this one.
    auth.as(k_other);
    BOOST_TEST(code(call("ListTopics", {{"NextToken", token}})) == "InvalidParameter");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(tags)

BOOST_FIXTURE_TEST_CASE(tag_list_and_untag, fixture) {
    const auto arn =
        create("orders", {{"Tags.member.1.Key", "team"}, {"Tags.member.1.Value", "a"}});
    BOOST_TEST(call("TagResource", {{"ResourceArn", arn},
                                    {"Tags.member.1.Key", "env"},
                                    {"Tags.member.1.Value", "prod"},
                                    {"Tags.member.2.Key", "team"},
                                    {"Tags.member.2.Value", "b"}})
                   ._status == 200U);
    auto listed = call("ListTagsForResource", {{"ResourceArn", arn}});
    BOOST_TEST(listed._status == 200U);
    BOOST_TEST(count(listed._body, "<member>") == 2U);
    BOOST_TEST(listed._body.find("<Key>team</Key><Value>b</Value>") != std::string::npos);

    BOOST_TEST(
        call("UntagResource", {{"ResourceArn", arn}, {"TagKeys.member.1", "team"}})._status ==
        200U);
    listed = call("ListTagsForResource", {{"ResourceArn", arn}});
    BOOST_TEST(count(listed._body, "<member>") == 1U);
    BOOST_TEST(listed._body.find("<Key>env</Key><Value>prod</Value>") != std::string::npos);

    // What authorization sees.
    const auto facts = service.lookup(arn);
    BOOST_REQUIRE(facts.has_value());
    BOOST_TEST(facts->_tags.size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(tag_limits_and_missing_resources, fixture) {
    const auto arn = create("orders");
    std::vector<std::pair<std::string, std::string>> many{{"ResourceArn", arn}};
    for (int i = 1; i <= 51; ++i) {
        many.emplace_back("Tags.member." + std::to_string(i) + ".Key", "k" + std::to_string(i));
        many.emplace_back("Tags.member." + std::to_string(i) + ".Value", "v");
    }
    BOOST_TEST(code(call("TagResource", many)) == "TagLimitExceeded");

    const auto reserved = call(
        "TagResource",
        {{"ResourceArn", arn}, {"Tags.member.1.Key", "aws:owner"}, {"Tags.member.1.Value", "x"}});
    BOOST_TEST(code(reserved) == "InvalidParameter");

    const auto compat = call("TagResource", {{"ResourceArn", arn},
                                             {"Tags.member.1.Key", "kythira:compat:throttling"},
                                             {"Tags.member.1.Value", "sometimes"}});
    BOOST_TEST(code(compat) == "InvalidParameter");

    const auto missing = call("ListTagsForResource", {{"ResourceArn", topic("nope")}});
    BOOST_TEST(missing._status == 404U);
    BOOST_TEST(code(missing) == "ResourceNotFound");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(permissions)

BOOST_FIXTURE_TEST_CASE(add_and_remove_permission_edit_the_policy, fixture) {
    const auto arn = create("orders");
    const auto r = call("AddPermission", {{"TopicArn", arn},
                                          {"Label", "let-them-publish"},
                                          {"AWSAccountId.member.1", std::string(k_other)},
                                          {"ActionName.member.1", "Publish"}});
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);

    const auto facts = service.lookup(arn);
    BOOST_REQUIRE(facts.has_value() && facts->_policy.has_value());
    const auto doc = boost::json::parse(*facts->_policy).as_object();
    const auto& statements = doc.at("Statement").as_array();
    BOOST_TEST(statements.size() == 2U);
    const auto& added = statements.at(1).as_object();
    BOOST_TEST(added.at("Sid").as_string() == "let-them-publish");
    BOOST_TEST(added.at("Action").as_string() == "SNS:Publish");
    BOOST_TEST(added.at("Principal").as_object().at("AWS").as_string() ==
               "arn:aws:iam::444455556666:root");

    const auto twice = call("AddPermission", {{"TopicArn", arn},
                                              {"Label", "let-them-publish"},
                                              {"AWSAccountId.member.1", std::string(k_other)},
                                              {"ActionName.member.1", "Publish"}});
    BOOST_TEST(code(twice) == "InvalidParameter");

    BOOST_TEST(
        call("RemovePermission", {{"TopicArn", arn}, {"Label", "let-them-publish"}})._status ==
        200U);
    BOOST_TEST(boost::json::parse(*service.lookup(arn)->_policy)
                   .as_object()
                   .at("Statement")
                   .as_array()
                   .size() == 1U);
    const auto unknown = call("RemovePermission", {{"TopicArn", arn}, {"Label", "nope"}});
    BOOST_TEST(code(unknown) == "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(a_cross_account_caller_acts_on_the_owners_topic, fixture) {
    const auto arn = create("orders");
    auth.as(k_other);
    const auto r = call("SetTopicAttributes", {{"TopicArn", arn},
                                               {"AttributeName", "DisplayName"},
                                               {"AttributeValue", "set by a partner"}});
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(entry(attributes(arn), "Owner") == std::string(k_account));
    BOOST_TEST(!store.find_topic(k_other, "orders").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(data_protection)

BOOST_FIXTURE_TEST_CASE(put_and_get, fixture) {
    const auto arn = create("orders");
    auto r = call("GetDataProtectionPolicy", {{"ResourceArn", arn}});
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(element(r._body, "DataProtectionPolicy").empty());

    const std::string doc = R"({"Name":"p","Version":"2021-06-01","Statement":[]})";
    BOOST_TEST(
        call("PutDataProtectionPolicy", {{"ResourceArn", arn}, {"DataProtectionPolicy", doc}})
            ._status == 200U);
    r = call("GetDataProtectionPolicy", {{"ResourceArn", arn}});
    BOOST_TEST(unescape(element(r._body, "DataProtectionPolicy")) == doc);
    // Not one of GetTopicAttributes' attributes.
    BOOST_TEST(entry(attributes(arn), "DataProtectionPolicy") == "<absent>");

    BOOST_TEST(code(call("PutDataProtectionPolicy",
                         {{"ResourceArn", arn}, {"DataProtectionPolicy", "[]"}})) ==
               "InvalidParameter");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(deletion)

BOOST_FIXTURE_TEST_CASE(delete_then_recreate_takes_a_new_id, fixture) {
    const auto arn = create("orders");
    const auto first = store.find_topic(k_account, "orders")->_id;
    BOOST_TEST(call("DeleteTopic", {{"TopicArn", arn}})._status == 200U);
    BOOST_TEST(code(call("GetTopicAttributes", {{"TopicArn", arn}})) == "NotFound");
    // Deleting it again succeeds, as on SNS.
    BOOST_TEST(call("DeleteTopic", {{"TopicArn", arn}})._status == 200U);
    create("orders");
    BOOST_TEST(store.find_topic(k_account, "orders")->_id > first);
}

BOOST_AUTO_TEST_SUITE_END()
