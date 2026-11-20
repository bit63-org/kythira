// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SNS topic operations (`.kiro/specs/sns-compatible-notifications/`
// task 4, Requirement 4.1), end to end through the front end and a local
// topic store: CreateTopic's idempotency and validation, FIFO naming and
// FIFO-only attributes, the attributes GetTopicAttributes derives, the
// default and edited topic policy (AddPermission, RemovePermission, and
// what authorization sees), ListTopics pages and tokens, tags and their
// limits, data protection policies, deletion and ids that are never
// reused, and a cross-account caller acting on the owner's topic. Then the
// subscription operations (Requirement 4.2): which protocols wait for a
// confirmation token, tokens that work once and expire, endpoints checked
// against their protocol and FIFO topics, subscription attributes, ARNs
// that name their own topic, and both list operations' pages. Then
// publishing (Requirements 5.1 to 5.4): message, subject, structure and
// attribute checks, sizes, FIFO groups and deduplication (explicit and
// content-based, five minutes), PublishBatch's per-entry results and
// request rules, and the published message's encoding.

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

// ---- subscriptions (Requirements 4.1 and 4.2) ------------------------------

namespace {

constexpr std::string_view k_queue = "arn:aws:sqs:us-east-1:111122223333:orders-queue";

struct subscription_fixture : fixture {
    std::string arn = create("orders");

    auto subscribe(std::string protocol, std::string endpoint,
                   std::vector<std::pair<std::string, std::string>> extra = {})
        -> sns::front_end_response {
        extra.insert(extra.begin(), {{"TopicArn", arn},
                                     {"Protocol", std::move(protocol)},
                                     {"Endpoint", std::move(endpoint)}});
        return call("Subscribe", extra);
    }

    /// The pending token of the topic's only (or last) subscription.
    auto token() -> std::string {
        const auto subs = store.subscriptions_of(store.find_topic(k_account, "orders")->_id);
        BOOST_REQUIRE(!subs.empty());
        return subs.back()._token;
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(subscriptions)

BOOST_FIXTURE_TEST_CASE(an_sqs_queue_in_the_same_account_needs_no_confirmation,
                        subscription_fixture) {
    const auto r = subscribe("sqs", std::string(k_queue));
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);
    const auto sub = element(r._body, "SubscriptionArn");
    BOOST_TEST(sub.starts_with(arn + ":"));
    BOOST_TEST(sub.size() == arn.size() + 37U);

    const auto attrs = call("GetSubscriptionAttributes", {{"SubscriptionArn", sub}});
    BOOST_TEST_REQUIRE(attrs._status == 200U, attrs._body);
    BOOST_TEST(entry(attrs._body, "SubscriptionArn") == sub);
    BOOST_TEST(entry(attrs._body, "TopicArn") == arn);
    BOOST_TEST(entry(attrs._body, "Protocol") == "sqs");
    BOOST_TEST(entry(attrs._body, "Endpoint") == k_queue);
    BOOST_TEST(entry(attrs._body, "Owner") == k_account);
    BOOST_TEST(entry(attrs._body, "PendingConfirmation") == "false");
    BOOST_TEST(entry(attrs._body, "RawMessageDelivery") == "false");
    BOOST_TEST(entry(attrs._body, "EffectiveDeliveryPolicy") == "<absent>");
    BOOST_TEST(entry(attributes(arn), "SubscriptionsConfirmed") == "1");

    // The same endpoint again is the same subscription.
    BOOST_TEST(element(subscribe("sqs", std::string(k_queue))._body, "SubscriptionArn") == sub);
    const auto different = subscribe(
        "sqs", std::string(k_queue),
        {{"Attributes.entry.1.key", "RawMessageDelivery"}, {"Attributes.entry.1.value", "true"}});
    BOOST_TEST(code(different) == "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(http_waits_for_its_token, subscription_fixture) {
    const auto r = subscribe("https", "https://example.com/hook");
    BOOST_TEST(element(r._body, "SubscriptionArn") == "pending confirmation");
    BOOST_TEST(entry(attributes(arn), "SubscriptionsPending") == "1");
    const auto t = token();
    BOOST_TEST(t.size() == 256U);

    auto listed = call("ListSubscriptionsByTopic", {{"TopicArn", arn}});
    BOOST_TEST(element(listed._body, "SubscriptionArn") == "PendingConfirmation");

    BOOST_TEST(code(call("ConfirmSubscription", {{"TopicArn", arn}, {"Token", "nope"}})) ==
               "InvalidParameter");
    const auto confirmed = call("ConfirmSubscription", {{"TopicArn", arn}, {"Token", t}});
    BOOST_TEST_REQUIRE(confirmed._status == 200U, confirmed._body);
    const auto sub = element(confirmed._body, "SubscriptionArn");
    BOOST_TEST(sub.starts_with(arn + ":"));
    listed = call("ListSubscriptionsByTopic", {{"TopicArn", arn}});
    BOOST_TEST(element(listed._body, "SubscriptionArn") == sub);
    const auto attrs = call("GetSubscriptionAttributes", {{"SubscriptionArn", sub}});
    BOOST_TEST(entry(attrs._body, "PendingConfirmation") == "false");
    BOOST_TEST(entry(attrs._body, "ConfirmationWasAuthenticated") == "true");
    BOOST_TEST(unescape(entry(attrs._body, "EffectiveDeliveryPolicy")) ==
               sns::k_default_effective_delivery_policy);
    // A token works once.
    BOOST_TEST(code(call("ConfirmSubscription", {{"TopicArn", arn}, {"Token", t}})) ==
               "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(a_token_expires_after_three_days, subscription_fixture) {
    subscribe("email", "ops@example.com");
    const auto t = token();
    now += sns::k_confirmation_window_ms;
    BOOST_TEST(code(call("ConfirmSubscription", {{"TopicArn", arn}, {"Token", t}})) ==
               "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(return_subscription_arn_and_cross_account_queues, subscription_fixture) {
    const auto r = subscribe("sqs", "arn:aws:sqs:us-east-1:444455556666:theirs",
                             {{"ReturnSubscriptionArn", "true"}});
    const auto sub = element(r._body, "SubscriptionArn");
    BOOST_TEST(sub.starts_with(arn + ":"));
    const auto attrs = call("GetSubscriptionAttributes", {{"SubscriptionArn", sub}});
    BOOST_TEST(entry(attrs._body, "PendingConfirmation") == "true");
}

BOOST_FIXTURE_TEST_CASE(endpoints_must_match_their_protocol, subscription_fixture) {
    BOOST_TEST(code(subscribe("http", "https://example.com/")) == "InvalidParameter");
    BOOST_TEST(code(subscribe("https", "ftp://example.com/")) == "InvalidParameter");
    BOOST_TEST(code(subscribe("email", "nobody")) == "InvalidParameter");
    BOOST_TEST(code(subscribe("sqs", "my-queue")) == "InvalidParameter");
    BOOST_TEST(code(subscribe("sms", "+15555550100")) == "InvalidParameter");
    BOOST_TEST(code(subscribe("firehose", "arn:aws:firehose:us-east-1:111122223333:stream/s")) ==
               "InvalidParameter");
    BOOST_TEST(code(subscribe("email", "ops@example.com",
                              {{"Attributes.entry.1.key", "RawMessageDelivery"},
                               {"Attributes.entry.1.value", "true"}})) == "InvalidParameter");
    BOOST_TEST(code(subscribe("sqs", std::string(k_queue),
                              {{"Attributes.entry.1.key", "RedrivePolicy"},
                               {"Attributes.entry.1.value", "{}"}})) == "InvalidParameter");
    BOOST_TEST(store.machine().subscription_count() == 0U);
}

BOOST_FIXTURE_TEST_CASE(a_fifo_topic_takes_only_fifo_queues, fixture) {
    const auto fifo = create("jobs.fifo", {{"Attributes.entry.1.key", "FifoTopic"},
                                           {"Attributes.entry.1.value", "true"}});
    const auto sub = [&](std::string protocol, std::string endpoint) {
        return call("Subscribe",
                    {{"TopicArn", fifo}, {"Protocol", protocol}, {"Endpoint", endpoint}});
    };
    BOOST_TEST(message(sub("https", "https://example.com/")) ==
               "Invalid parameter: Invalid protocol type: https");
    BOOST_TEST(message(sub("sqs", std::string(k_queue))) ==
               "Invalid parameter: Endpoint Reason: Please use FIFO SQS queue");
    BOOST_TEST(sub("sqs", std::string(k_queue) + ".fifo")._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(set_attributes_and_unsubscribe, subscription_fixture) {
    const auto sub = element(subscribe("sqs", std::string(k_queue))._body, "SubscriptionArn");
    BOOST_TEST(call("SetSubscriptionAttributes", {{"SubscriptionArn", sub},
                                                  {"AttributeName", "RawMessageDelivery"},
                                                  {"AttributeValue", "true"}})
                   ._status == 200U);
    const std::string policy = R"({"store":["example_corp"]})";
    BOOST_TEST(call("SetSubscriptionAttributes", {{"SubscriptionArn", sub},
                                                  {"AttributeName", "FilterPolicy"},
                                                  {"AttributeValue", policy}})
                   ._status == 200U);
    const auto attrs = call("GetSubscriptionAttributes", {{"SubscriptionArn", sub}});
    BOOST_TEST(entry(attrs._body, "RawMessageDelivery") == "true");
    BOOST_TEST(unescape(entry(attrs._body, "FilterPolicy")) == policy);
    BOOST_TEST(code(call("SetSubscriptionAttributes", {{"SubscriptionArn", sub},
                                                       {"AttributeName", "Colour"},
                                                       {"AttributeValue", "red"}})) ==
               "InvalidParameter");

    BOOST_TEST(call("Unsubscribe", {{"SubscriptionArn", sub}})._status == 200U);
    const auto gone = call("GetSubscriptionAttributes", {{"SubscriptionArn", sub}});
    BOOST_TEST(gone._status == 404U);
    BOOST_TEST(message(gone) == "Subscription does not exist");
    BOOST_TEST(code(call("Unsubscribe", {{"SubscriptionArn", sub}})) == "NotFound");
    BOOST_TEST(code(call("Unsubscribe", {{"SubscriptionArn", arn + ":not-a-uuid"}})) ==
               "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(filter_policies_are_checked_in_their_scope, subscription_fixture) {
    const auto nested = std::string(R"({"order":{"status":["shipped"]}})");
    // Nested keys need payload scope, on Subscribe and on a later change.
    BOOST_TEST(message(subscribe("sqs", std::string(k_queue),
                                 {{"Attributes.entry.1.key", "FilterPolicy"},
                                  {"Attributes.entry.1.value", nested}})) ==
               "Invalid parameter: Filter policy scope MessageAttributes does not support "
               "nested filter policy");
    const auto r = subscribe("sqs", std::string(k_queue),
                             {{"Attributes.entry.1.key", "FilterPolicy"},
                              {"Attributes.entry.1.value", nested},
                              {"Attributes.entry.2.key", "FilterPolicyScope"},
                              {"Attributes.entry.2.value", "MessageBody"}});
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);
    const auto sub = element(r._body, "SubscriptionArn");
    const auto set = [&](std::string name, std::string value) {
        return call("SetSubscriptionAttributes", {{"SubscriptionArn", sub},
                                                  {"AttributeName", std::move(name)},
                                                  {"AttributeValue", std::move(value)}});
    };
    BOOST_TEST(code(set("FilterPolicyScope", "MessageAttributes")) == "InvalidParameter");
    BOOST_TEST(unescape(message(set("FilterPolicy", R"({"a":[{"numeric":["<","x"]}]})"))) ==
               "Invalid parameter: FilterPolicy: Value of < must be numeric");
    BOOST_TEST(message(set("FilterPolicy", "[1]")) ==
               "Invalid parameter: FilterPolicy: Filter policy must be a JSON object");
    // Removing the policy frees the scope to change.
    BOOST_TEST(set("FilterPolicy", "")._status == 200U);
    BOOST_TEST(set("FilterPolicyScope", "MessageAttributes")._status == 200U);
    BOOST_TEST(set("FilterPolicy", R"({"store":[{"prefix":"ex"}]})")._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(a_topic_holds_at_most_200_filter_policies, subscription_fixture) {
    const std::vector<std::pair<std::string, std::string>> filtered = {
        {"Attributes.entry.1.key", "FilterPolicy"}, {"Attributes.entry.1.value", R"({"a":["b"]})"}};
    for (std::size_t i = 0; i < sns::k_max_filter_policies_per_topic; ++i) {
        BOOST_TEST_REQUIRE(
            subscribe("sqs", std::string(k_queue) + std::to_string(i), filtered)._status == 200U);
    }
    const auto over = subscribe("sqs", std::string(k_queue) + "-over", filtered);
    BOOST_TEST(code(over) == "FilterPolicyLimitExceeded");
    BOOST_TEST(over._status == 403U);
    // Without a policy the subscription is fine, and changing one that
    // already has a policy does not count it twice.
    BOOST_TEST(subscribe("sqs", std::string(k_queue) + "-plain")._status == 200U);
    const auto first =
        element(call("ListSubscriptionsByTopic", {{"TopicArn", arn}})._body, "SubscriptionArn");
    BOOST_TEST(call("SetSubscriptionAttributes", {{"SubscriptionArn", first},
                                                  {"AttributeName", "FilterPolicy"},
                                                  {"AttributeValue", R"({"a":["c"]})"}})
                   ._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(a_subscription_arn_names_its_own_topic, subscription_fixture) {
    const auto sub = element(subscribe("sqs", std::string(k_queue))._body, "SubscriptionArn");
    const auto other = create("other");
    const auto moved = other + sub.substr(arn.size());
    BOOST_TEST(code(call("GetSubscriptionAttributes", {{"SubscriptionArn", moved}})) == "NotFound");
}

BOOST_FIXTURE_TEST_CASE(list_subscriptions_pages_the_callers_own, subscription_fixture) {
    for (int i = 0; i < 120; ++i) {
        subscribe("sqs", std::string(k_queue) + std::to_string(i));
    }
    auth.as(k_other);
    call("Subscribe", {{"TopicArn", arn},
                       {"Protocol", "sqs"},
                       {"Endpoint", "arn:aws:sqs:us-east-1:444455556666:theirs"}});
    auth.as(k_account);

    const auto first = call("ListSubscriptions");
    BOOST_TEST(count(first._body, "<member>") == 100U);
    const auto token = element(first._body, "NextToken");
    BOOST_TEST(!token.empty());
    const auto second = call("ListSubscriptions", {{"NextToken", token}});
    BOOST_TEST(count(second._body, "<member>") == 20U);
    BOOST_TEST(element(second._body, "NextToken").empty());
    BOOST_TEST(second._body.find("theirs") == std::string::npos);

    // By topic shows everyone's.
    const auto by_topic = call("ListSubscriptionsByTopic", {{"TopicArn", arn}});
    const auto rest =
        call("ListSubscriptionsByTopic",
             {{"TopicArn", arn}, {"NextToken", element(by_topic._body, "NextToken")}});
    BOOST_TEST(count(rest._body, "<member>") == 21U);
    BOOST_TEST(code(call("ListSubscriptionsByTopic", {{"TopicArn", arn}, {"NextToken", token}})) ==
               "InvalidParameter");

    // Deleting the topic drops its subscriptions.
    call("DeleteTopic", {{"TopicArn", arn}});
    BOOST_TEST(count(call("ListSubscriptions")._body, "<member>") == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- publishing (Requirements 5.1 to 5.4) ----------------------------------

namespace {

struct publish_fixture : fixture {
    std::string arn = create("orders");
    std::string fifo = create("jobs.fifo", {{"Attributes.entry.1.key", "FifoTopic"},
                                            {"Attributes.entry.1.value", "true"}});

    auto publish(std::string topic_arn, std::vector<std::pair<std::string, std::string>> extra)
        -> sns::front_end_response {
        extra.insert(extra.begin(), {"TopicArn", std::move(topic_arn)});
        return call("Publish", extra);
    }

    auto last_seq(std::string_view name, std::uint32_t partition = 0) -> std::uint64_t {
        const auto id = store.find_topic(k_account, name)->_id;
        return store.machine().partition(id, partition)->_last_seq;
    }
};

auto is_uuid(const std::string& s) -> bool {
    return s.size() == 36U && s[8] == '-' && s[13] == '-' && s[14] == '4' && s[18] == '-' &&
           s[23] == '-';
}

}  // namespace

BOOST_AUTO_TEST_SUITE(publishing)

BOOST_FIXTURE_TEST_CASE(publish_commits_and_answers_a_message_id, publish_fixture) {
    const auto r = publish(arn, {{"Message", "hello"}, {"Subject", "greeting"}});
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);
    BOOST_TEST(is_uuid(element(r._body, "MessageId")));
    BOOST_TEST(element(r._body, "SequenceNumber").empty());
    BOOST_TEST(last_seq("orders") == 1U);

    // TargetArn names a topic too.
    BOOST_TEST(call("Publish", {{"TargetArn", arn}, {"Message", "again"}})._status == 200U);
    BOOST_TEST(last_seq("orders") == 2U);

    BOOST_TEST(code(publish(topic("nope"), {{"Message", "x"}})) == "NotFound");
    const auto none = call("Publish", {{"Message", "x"}});
    BOOST_TEST(message(none) ==
               "Invalid parameter: TopicArn or TargetArn Reason: no value for required parameter");
    BOOST_TEST(code(call("Publish", {{"PhoneNumber", "+15555550100"}, {"Message", "x"}})) ==
               "InvalidParameter");
}

BOOST_FIXTURE_TEST_CASE(messages_are_checked_as_sns_checks_them, publish_fixture) {
    BOOST_TEST(message(publish(arn, {{"Message", ""}})) == "Invalid parameter: Empty message");
    BOOST_TEST(code(publish(arn, {{"Message", "x"}, {"Subject", std::string(101, 's')}})) ==
               "InvalidParameter");
    BOOST_TEST(code(publish(arn, {{"Message", "x"}, {"Subject", "two\nlines"}})) ==
               "InvalidParameter");
    BOOST_TEST(
        message(publish(arn, {{"Message", R"({"sqs":"q"})"}, {"MessageStructure", "json"}})) ==
        "Invalid parameter: Message Structure - No default entry in JSON message body");
    BOOST_TEST(message(publish(arn, {{"Message", "not json"}, {"MessageStructure", "json"}})) ==
               "Invalid parameter: Message Structure - JSON message body failed to parse");
    BOOST_TEST(
        publish(arn, {{"Message", R"({"default":"d","sqs":"q"})"}, {"MessageStructure", "json"}})
            ._status == 200U);
    BOOST_TEST(message(publish(arn, {{"Message", std::string(262'145, 'm')}})) ==
               "Invalid parameter: Message too long");
    BOOST_TEST(publish(arn, {{"Message", std::string(262'144, 'm')}})._status == 200U);
    BOOST_TEST(message(publish(arn, {{"Message", "x"}, {"MessageDeduplicationId", "d"}})) ==
               "Invalid parameter: MessageDeduplicationId Reason: The request includes "
               "MessageDeduplicationId parameter that is not valid for this topic type");
    BOOST_TEST(last_seq("orders") == 2U);
}

BOOST_FIXTURE_TEST_CASE(message_attributes_are_checked, publish_fixture) {
    const auto attr = [&](std::string name, std::string type, std::string field,
                          std::string value) {
        return publish(arn, {{"Message", "x"},
                             {"MessageAttributes.entry.1.Name", name},
                             {"MessageAttributes.entry.1.Value.DataType", type},
                             {"MessageAttributes.entry.1.Value." + field, value}});
    };
    BOOST_TEST(attr("price", "Number", "StringValue", "-1.5e3")._status == 200U);
    BOOST_TEST(attr("blob", "Binary", "BinaryValue", "AAEC")._status == 200U);
    BOOST_TEST(attr("store", "String.custom", "StringValue", "a")._status == 200U);
    BOOST_TEST(code(attr("price", "Number", "StringValue", "1.2.3")) == "ParameterValueInvalid");
    BOOST_TEST(code(attr("AWS.trace", "String", "StringValue", "x")) == "ParameterValueInvalid");
    BOOST_TEST(code(attr("a..b", "String", "StringValue", "x")) == "ParameterValueInvalid");
    BOOST_TEST(code(attr("empty", "String", "StringValue", "")) == "ParameterValueInvalid");
}

BOOST_FIXTURE_TEST_CASE(a_published_message_round_trips, publish_fixture) {
    sns::published_message m;
    m._message = R"({"default":"d"})";
    m._json_structure = true;
    m._subject = "s";
    m._timestamp_ms = now;
    m._publisher = std::string(k_account);
    m._attributes.emplace("price", sns::message_attribute{"Number", "1", std::nullopt});
    m._attributes.emplace("blob",
                          sns::message_attribute{"Binary", std::nullopt, std::string("\0\1", 2)});
    BOOST_TEST((sns::decode_published_message(sns::encode_published_message(m)) == m));
    auto bytes = sns::encode_published_message(m);
    bytes.pop_back();
    BOOST_CHECK_THROW(static_cast<void>(sns::decode_published_message(bytes)),
                      sns::sns_codec_error);
}

BOOST_FIXTURE_TEST_CASE(fifo_needs_a_group_and_a_dedup_id, publish_fixture) {
    BOOST_TEST(message(publish(fifo, {{"Message", "x"}})) ==
               "Invalid parameter: The MessageGroupId parameter is required for FIFO topics");
    BOOST_TEST(message(publish(fifo, {{"Message", "x"}, {"MessageGroupId", "g"}})) ==
               "Invalid parameter: The topic should either have ContentBasedDeduplication "
               "enabled or MessageDeduplicationId provided explicitly");

    const auto first = publish(
        fifo, {{"Message", "x"}, {"MessageGroupId", "g"}, {"MessageDeduplicationId", "d1"}});
    BOOST_TEST_REQUIRE(first._status == 200U, first._body);
    BOOST_TEST(element(first._body, "SequenceNumber") == "00000000000000000001");

    // The same dedup id within five minutes is the same message.
    now += sns::k_dedup_window_ms - 1;
    const auto again = publish(
        fifo,
        {{"Message", "different body"}, {"MessageGroupId", "g"}, {"MessageDeduplicationId", "d1"}});
    BOOST_TEST(element(again._body, "MessageId") == element(first._body, "MessageId"));
    BOOST_TEST(element(again._body, "SequenceNumber") == "00000000000000000001");
    BOOST_TEST(last_seq("jobs.fifo") == 1U);

    now += 1;
    const auto later = publish(
        fifo, {{"Message", "x"}, {"MessageGroupId", "g"}, {"MessageDeduplicationId", "d1"}});
    BOOST_TEST(element(later._body, "MessageId") != element(first._body, "MessageId"));
    BOOST_TEST(element(later._body, "SequenceNumber") == "00000000000000000002");
}

BOOST_FIXTURE_TEST_CASE(content_based_deduplication_hashes_the_body, publish_fixture) {
    BOOST_TEST(call("SetTopicAttributes", {{"TopicArn", fifo},
                                           {"AttributeName", "ContentBasedDeduplication"},
                                           {"AttributeValue", "true"}})
                   ._status == 200U);
    const auto a = publish(fifo, {{"Message", "same"}, {"MessageGroupId", "g1"}});
    const auto b = publish(fifo, {{"Message", "same"}, {"MessageGroupId", "g2"}});
    const auto c = publish(fifo, {{"Message", "other"}, {"MessageGroupId", "g1"}});
    BOOST_TEST(element(a._body, "MessageId") == element(b._body, "MessageId"));
    BOOST_TEST(element(a._body, "MessageId") != element(c._body, "MessageId"));
    BOOST_TEST(sns::service_detail::sha256_hex("abc") ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

BOOST_FIXTURE_TEST_CASE(publish_batch_reports_each_entry, publish_fixture) {
    const auto r = call("PublishBatch", {{"TopicArn", arn},
                                         {"PublishBatchRequestEntries.member.1.Id", "a"},
                                         {"PublishBatchRequestEntries.member.1.Message", "one"},
                                         {"PublishBatchRequestEntries.member.2.Id", "b"},
                                         {"PublishBatchRequestEntries.member.2.Message", ""},
                                         {"PublishBatchRequestEntries.member.3.Id", "c"},
                                         {"PublishBatchRequestEntries.member.3.Message", "three"},
                                         {"PublishBatchRequestEntries.member.3.Subject", "s"}});
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);
    const auto ok = element(r._body, "Successful");
    const auto failed = element(r._body, "Failed");
    BOOST_TEST(count(ok, "<member>") == 2U);
    BOOST_TEST(element(ok, "Id") == "a");
    BOOST_TEST(is_uuid(element(ok, "MessageId")));
    BOOST_TEST(count(failed, "<member>") == 1U);
    BOOST_TEST(element(failed, "Id") == "b");
    BOOST_TEST(element(failed, "Code") == "InvalidParameter");
    BOOST_TEST(element(failed, "Message") == "Invalid parameter: Empty message");
    BOOST_TEST(element(failed, "SenderFault") == "true");
    BOOST_TEST(last_seq("orders") == 2U);
}

BOOST_FIXTURE_TEST_CASE(publish_batch_request_rules, publish_fixture) {
    std::vector<std::pair<std::string, std::string>> eleven{{"TopicArn", arn}};
    for (int i = 1; i <= 11; ++i) {
        const auto p = "PublishBatchRequestEntries.member." + std::to_string(i) + ".";
        eleven.emplace_back(p + "Id", "e" + std::to_string(i));
        eleven.emplace_back(p + "Message", "m");
    }
    BOOST_TEST(code(call("PublishBatch", eleven)) == "TooManyEntriesInBatchRequest");
    BOOST_TEST(code(call("PublishBatch", {{"TopicArn", arn},
                                          {"PublishBatchRequestEntries.member.1.Id", "a"},
                                          {"PublishBatchRequestEntries.member.1.Message", "m"},
                                          {"PublishBatchRequestEntries.member.2.Id", "a"},
                                          {"PublishBatchRequestEntries.member.2.Message", "m"}})) ==
               "BatchEntryIdsNotDistinct");
    BOOST_TEST(code(call("PublishBatch", {{"TopicArn", arn}})) == "EmptyBatchRequest");
    const auto big = std::string(200'000, 'm');
    BOOST_TEST(code(call("PublishBatch", {{"TopicArn", arn},
                                          {"PublishBatchRequestEntries.member.1.Id", "a"},
                                          {"PublishBatchRequestEntries.member.1.Message", big},
                                          {"PublishBatchRequestEntries.member.2.Id", "b"},
                                          {"PublishBatchRequestEntries.member.2.Message", big}})) ==
               "BatchRequestTooLong");
    BOOST_TEST(last_seq("orders") == 0U);
}

BOOST_FIXTURE_TEST_CASE(a_fifo_batch_answers_sequence_numbers, publish_fixture) {
    const auto r =
        call("PublishBatch", {{"TopicArn", fifo},
                              {"PublishBatchRequestEntries.member.1.Id", "a"},
                              {"PublishBatchRequestEntries.member.1.Message", "one"},
                              {"PublishBatchRequestEntries.member.1.MessageGroupId", "g"},
                              {"PublishBatchRequestEntries.member.1.MessageDeduplicationId", "1"},
                              {"PublishBatchRequestEntries.member.2.Id", "b"},
                              {"PublishBatchRequestEntries.member.2.Message", "two"},
                              {"PublishBatchRequestEntries.member.2.MessageGroupId", "g"},
                              {"PublishBatchRequestEntries.member.2.MessageDeduplicationId", "2"}});
    BOOST_TEST_REQUIRE(r._status == 200U, r._body);
    BOOST_TEST(count(r._body, "<SequenceNumber>") == 2U);
    BOOST_TEST(r._body.find("<SequenceNumber>00000000000000000002</SequenceNumber>") !=
               std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
