// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SNS front end (`.kiro/specs/sns-compatible-notifications/` task 3,
// Requirements 3.1 and 3.2): real SigV4 through the static-key authorizer
// (POST forms as every client sends them, and GET), the query protocol's
// framing errors, unsupported operations, the topic each request is
// authorized on, the condition keys and extra actions AWS checks, the
// topic policy handed to the authorizer, cross-account resources, the
// handler safety net, and the static-key roles.

#define BOOST_TEST_MODULE sns_front_end_test
#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_front_end.hpp>

#include <raft/static_key_authorizer.hpp>

#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sns = kythira::sns;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_other = "444455556666";
constexpr std::string_view k_form = "application/x-www-form-urlencoded; charset=utf-8";
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

auto topic(std::string_view name, std::string_view account = k_account) -> std::string {
    return "arn:aws:sns:us-east-1:" + std::string(account) + ":" + std::string(name);
}

auto post(std::string body, std::string_view content_type = k_form) -> sns::front_end_request {
    sns::front_end_request r;
    r._method = "POST";
    r._path = "/";
    r._body = std::move(body);
    r._source_ip = "192.0.2.10";
    r._headers = {{"Host", "sns.us-east-1.amazonaws.com"},
                  {"Content-Type", std::string(content_type)},
                  {"X-Amz-Date", "20261118T120000Z"}};
    return r;
}

// Signs `r` as `akid` (header form), as an SDK does.
auto sign(sns::front_end_request r, std::string_view akid) -> sns::front_end_request {
    sv4::service_rules rules;
    rules.service = "sns";
    rules.protocol = sv4::error_protocol::query;
    const sv4::credential_scope scope{"20261118", "us-east-1", "sns"};
    const bool has_type = !sns::front_end_detail::header_value(r, "Content-Type").empty();
    r._headers.emplace_back(
        "Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(akid) + "/" + scope.text() +
                             ", SignedHeaders=" + (has_type ? "content-type;" : "") +
                             "host;x-amz-date, Signature=" + std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r._method, r._path, r._query, r._headers, r._body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r._headers.back().second.replace(r._headers.back().second.size() - 64, 64, sig);
    return r;
}

auto element(const std::string& xml, std::string_view tag) -> std::string {
    const auto open = "<" + std::string(tag) + ">";
    const auto close = "</" + std::string(tag) + ">";
    const auto a = xml.find(open);
    const auto b = xml.find(close, a);
    if (a == std::string::npos || b == std::string::npos) {
        return {};
    }
    return xml.substr(a + open.size(), b - a - open.size());
}

auto code_of(const sns::front_end_response& r) -> std::string {
    return element(r._body, "Code");
}

auto echo(sns::call_context& ctx, const sns::params& in) -> sns::query_result<std::string> {
    kythira::aws_query::xml_writer w;
    w.element("Who", ctx._principal.arn);
    w.element("Topic", ctx._topic_arn);
    w.element("Message", in.get("Message").value_or(""));
    w.boolean("ReadOnly", ctx._read_only);
    return w.str();
}

struct static_fixture {
    az::static_key_authorizer auth{{{"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                     "admin", az::static_role::admin},
                                    {"AKIDWRITER", std::string(k_secret), std::string(k_account),
                                     "writer", az::static_role::read_write},
                                    {"AKIDREADER", std::string(k_secret), std::string(k_account),
                                     "reader", az::static_role::read_only}},
                                   "aws",
                                   [] { return k_now; }};
    sns::front_end<az::static_key_authorizer> fe{sns::front_end_config{}, auth};

    static_fixture() {
        auth.register_service(sns::sns_static_roles());
        for (const auto* op : {"Publish", "PublishBatch", "CreateTopic", "ListTopics",
                               "GetTopicAttributes", "Subscribe", "DeleteTopic"}) {
            fe.on(op, echo);
        }
    }
};

/// Authenticates everyone as one principal and records each authorization
/// request; `deny` names actions to refuse.
struct recording_authorizer {
    az::principal_context who;
    std::vector<az::authz_request> seen;
    std::vector<std::string> deny;
    bool explicit_deny = false;

    recording_authorizer() {
        who.account = std::string(k_account);
        who.arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
        who.access_key_id = "AKIDALICE";
    }

    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        return who;
    }

    auto authorize(const az::principal_context&, const az::authz_request& r) -> az::authz_decision {
        seen.push_back(r);
        az::authz_decision d;
        d.allowed = std::find(deny.begin(), deny.end(), r.action) == deny.end();
        d.explicit_deny = !d.allowed && explicit_deny;
        return d;
    }
};

static_assert(az::aws_request_authorizer<recording_authorizer>);

struct recording_fixture {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe{sns::front_end_config{}, auth};
    std::map<std::string, sns::resource_facts> topics;

    recording_fixture() {
        for (const auto* op :
             {"Publish", "PublishBatch", "CreateTopic", "ListTopics", "Subscribe", "Unsubscribe",
              "TagResource", "UntagResource", "GetSubscriptionAttributes", "ConfirmSubscription"}) {
            fe.on(op, echo);
        }
        fe.set_resource_lookup([this](std::string_view arn) -> std::optional<sns::resource_facts> {
            const auto it = topics.find(std::string(arn));
            if (it == topics.end()) {
                return std::nullopt;
            }
            return it->second;
        });
    }

    auto call(std::string body) -> sns::front_end_response {
        return fe.handle(post(std::move(body)));
    }

    [[nodiscard]] auto key(const az::authz_request& r, std::string_view name) const
        -> std::vector<std::string> {
        for (const auto& [k, v] : r.keys) {
            if (k == name) {
                return v;
            }
        }
        return {"<absent>"};
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(sigv4_and_framing)

BOOST_FIXTURE_TEST_CASE(a_signed_publish_reaches_its_handler, static_fixture) {
    const auto arn = topic("orders");
    const auto r =
        fe.handle(sign(post("Action=Publish&Version=2010-03-31&TopicArn=" +
                            kythira::aws_query::url_encode(arn) + "&Message=hello+world"),
                       "AKIDWRITER"));
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(r._body.starts_with(
        "<PublishResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><PublishResult>"));
    BOOST_TEST(element(r._body, "Who") == "arn:aws:iam::111122223333:user/writer");
    BOOST_TEST(element(r._body, "Topic") == arn);
    BOOST_TEST(element(r._body, "Message") == "hello world");
    BOOST_TEST(element(r._body, "ReadOnly") == "false");
    const auto id = element(r._body, "RequestId");
    BOOST_TEST(id.size() == 36U);
    BOOST_TEST(id[14] == '4');
    sns::front_end_request headers;
    headers._headers = r._headers;
    BOOST_TEST(sns::front_end_detail::header_value(headers, "x-amzn-RequestId") == id);
    BOOST_TEST(sns::front_end_detail::header_value(headers, "content-type") == "text/xml");
}

BOOST_FIXTURE_TEST_CASE(the_charset_is_optional, static_fixture) {
    // The JS and Go SDKs send the bare media type (tests/evidence).
    const auto r = fe.handle(
        sign(post("Action=ListTopics&Version=2010-03-31", "application/x-www-form-urlencoded"),
             "AKIDREADER"));
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(element(r._body, "ReadOnly") == "true");
}

BOOST_FIXTURE_TEST_CASE(a_get_carries_its_parameters_in_the_query, static_fixture) {
    auto req = post("");
    req._method = "GET";
    req._query = "Action=ListTopics&Version=2010-03-31";
    req._headers.erase(req._headers.begin() + 1);  // no Content-Type
    const auto r = fe.handle(sign(std::move(req), "AKIDREADER"));
    BOOST_TEST(r._status == 200U, r._body);
}

BOOST_FIXTURE_TEST_CASE(sigv4_refusals_are_in_query_words, static_fixture) {
    auto unsigned_req = fe.handle(post("Action=ListTopics&Version=2010-03-31"));
    BOOST_TEST(unsigned_req._status != 200U);
    BOOST_TEST(element(unsigned_req._body, "Type") == "Sender");

    auto tampered = sign(post("Action=ListTopics&Version=2010-03-31"), "AKIDREADER");
    tampered._body += "&NextToken=x";
    const auto r = fe.handle(tampered);
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(code_of(r) == "SignatureDoesNotMatch");

    const auto unknown = fe.handle(sign(post("Action=ListTopics"), "AKIDNOBODY"));
    BOOST_TEST(code_of(unknown) == "InvalidClientTokenId");
}

BOOST_FIXTURE_TEST_CASE(framing_faults, static_fixture) {
    const auto json = fe.handle(sign(post("{}", "application/json"), "AKIDADMIN"));
    BOOST_TEST(json._status == 400U);
    BOOST_TEST(code_of(json) == "MalformedQueryString");

    const auto twice = fe.handle(sign(post("Action=ListTopics&Action=ListTopics"), "AKIDADMIN"));
    BOOST_TEST(code_of(twice) == "MalformedQueryString");

    const auto none = fe.handle(sign(post("Version=2010-03-31"), "AKIDADMIN"));
    BOOST_TEST(none._status == 400U);
    BOOST_TEST(code_of(none) == "MissingAction");

    const auto version = fe.handle(sign(post("Action=ListTopics&Version=2012-11-05"), "AKIDADMIN"));
    BOOST_TEST(code_of(version) == "InvalidAction");

    const auto bogus = fe.handle(sign(post("Action=SendMessage&Version=2010-03-31"), "AKIDADMIN"));
    BOOST_TEST(bogus._status == 400U);
    BOOST_TEST(code_of(bogus) == "InvalidAction");
    BOOST_TEST(element(bogus._body, "Message") ==
               "Could not find operation SendMessage for version 2010-03-31");
}

BOOST_FIXTURE_TEST_CASE(unsupported_operations_are_invalid_actions, static_fixture) {
    // Modelled, but out of scope (doc/unsupported.md): no handler.
    const auto r =
        fe.handle(sign(post("Action=CreatePlatformApplication&Version=2010-03-31"), "AKIDADMIN"));
    BOOST_TEST(r._status == 400U);
    BOOST_TEST(code_of(r) == "InvalidAction");
}

BOOST_AUTO_TEST_CASE(an_oversized_body_is_refused_before_anything_else) {
    recording_authorizer auth;
    sns::front_end_config cfg;
    cfg._max_body = 64;
    sns::front_end<recording_authorizer> fe(cfg, auth);
    fe.on("Publish", echo);
    const auto r = fe.handle(post("Action=Publish&Message=" + std::string(100, 'x')));
    BOOST_TEST(r._status == 413U);
    BOOST_TEST(code_of(r) == "RequestEntityTooLarge");
}

BOOST_AUTO_TEST_CASE(handlers_register_once_and_only_for_modelled_operations) {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe(sns::front_end_config{}, auth);
    fe.on("Publish", echo);
    BOOST_TEST(fe.handles("Publish"));
    BOOST_TEST(!fe.handles("Subscribe"));
    BOOST_CHECK_THROW(fe.on("Publish", echo), std::invalid_argument);
    BOOST_CHECK_THROW(fe.on("SendMessage", echo), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(static_key_roles)

BOOST_FIXTURE_TEST_CASE(roles_decide_by_action, static_fixture) {
    const auto body = [](std::string_view action) {
        return "Action=" + std::string(action) +
               "&Version=2010-03-31&TopicArn=" + kythira::aws_query::url_encode(topic("orders")) +
               "&Message=m";
    };
    // read-only reads, and nothing else.
    BOOST_TEST(fe.handle(sign(post(body("GetTopicAttributes")), "AKIDREADER"))._status == 200U);
    const auto ro = fe.handle(sign(post(body("Publish")), "AKIDREADER"));
    BOOST_TEST(ro._status == 403U);
    BOOST_TEST(code_of(ro) == "AuthorizationError");
    BOOST_TEST(element(ro._body, "Message") ==
               "User: arn:aws:iam::111122223333:user/reader is not authorized to perform: "
               "SNS:Publish on resource: " +
                   topic("orders") +
                   " because no identity-based policy allows the SNS:Publish "
                   "action");
    // read-write publishes and subscribes, but does not manage topics.
    BOOST_TEST(fe.handle(sign(post(body("Publish")), "AKIDWRITER"))._status == 200U);
    BOOST_TEST(fe.handle(sign(post(body("Subscribe")), "AKIDWRITER"))._status == 200U);
    BOOST_TEST(code_of(fe.handle(sign(post(body("DeleteTopic")), "AKIDWRITER"))) ==
               "AuthorizationError");
    BOOST_TEST(fe.handle(sign(post(body("DeleteTopic")), "AKIDADMIN"))._status == 200U);
    // PublishBatch is sns:Publish.
    BOOST_TEST(fe.handle(sign(post(body("PublishBatch")), "AKIDWRITER"))._status == 200U);
    BOOST_TEST(code_of(fe.handle(sign(post(body("PublishBatch")), "AKIDREADER"))) ==
               "AuthorizationError");
}

BOOST_FIXTURE_TEST_CASE(static_keys_have_no_cross_account_access, static_fixture) {
    const auto r = fe.handle(sign(
        post("Action=Publish&TopicArn=" + kythira::aws_query::url_encode(topic("orders", k_other)) +
             "&Message=m"),
        "AKIDADMIN"));
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(code_of(r) == "AuthorizationError");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(authorization)

BOOST_FIXTURE_TEST_CASE(publish_is_authorized_on_its_topic_with_the_topic_policy,
                        recording_fixture) {
    const auto arn = topic("orders");
    topics[arn] = {sns::default_topic_policy(arn, k_account), {{"team", "red"}}};
    const auto r =
        call("Action=Publish&TopicArn=" + kythira::aws_query::url_encode(arn) + "&Message=m");
    BOOST_TEST(r._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    const auto& q = auth.seen[0];
    BOOST_TEST(q.action == "sns:Publish");
    BOOST_TEST(q.resource == arn);
    BOOST_TEST(q.resource_account.empty());
    BOOST_REQUIRE(q.resource_policy.has_value());
    BOOST_TEST(*q.resource_policy == sns::default_topic_policy(arn, k_account));
    BOOST_TEST(q.resource_tags.size() == 1U);
    BOOST_TEST(key(q, "aws:SourceOwner") == std::vector<std::string>{std::string(k_account)});
    BOOST_TEST(q.source_ip == "192.0.2.10");
    BOOST_TEST(q.region == "us-east-1");
}

BOOST_FIXTURE_TEST_CASE(another_accounts_topic_names_its_account, recording_fixture) {
    const auto arn = topic("shared", k_other);
    BOOST_TEST(
        call("Action=PublishBatch&TopicArn=" + kythira::aws_query::url_encode(arn))._status ==
        200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    BOOST_TEST(auth.seen[0].action == "sns:Publish");
    BOOST_TEST(auth.seen[0].resource_account == k_other);
    // The caller's account is the source owner, so the other account's
    // default policy does not let it in.
    BOOST_TEST(key(auth.seen[0], "aws:SourceOwner") ==
               std::vector<std::string>{std::string(k_account)});
}

BOOST_FIXTURE_TEST_CASE(resourceless_actions_are_on_star, recording_fixture) {
    BOOST_TEST(call("Action=ListTopics")._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    BOOST_TEST(auth.seen[0].action == "sns:ListTopics");
    BOOST_TEST(auth.seen[0].resource == "*");
}

BOOST_FIXTURE_TEST_CASE(subscribe_supplies_protocol_and_endpoint, recording_fixture) {
    const auto arn = topic("orders");
    BOOST_TEST(call("Action=Subscribe&TopicArn=" + kythira::aws_query::url_encode(arn) +
                    "&Protocol=https&Endpoint=https%3A%2F%2Fexample.com%2Fhook")
                   ._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    BOOST_TEST(key(auth.seen[0], "sns:Protocol") == std::vector<std::string>{"https"});
    BOOST_TEST(key(auth.seen[0], "sns:Endpoint") ==
               std::vector<std::string>{"https://example.com/hook"});
}

BOOST_FIXTURE_TEST_CASE(subscription_operations_are_authorized_on_the_topic, recording_fixture) {
    const auto arn = topic("orders");
    const auto sub = arn + ":0e9b2b1c-4f1a-4c0e-9a77-8d8f3b0d6c11";
    BOOST_TEST(
        call("Action=Unsubscribe&SubscriptionArn=" + kythira::aws_query::url_encode(sub))._status ==
        200U);
    BOOST_TEST(call("Action=GetSubscriptionAttributes&SubscriptionArn=" +
                    kythira::aws_query::url_encode(sub))
                   ._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 2U);
    BOOST_TEST(auth.seen[0].action == "sns:Unsubscribe");
    BOOST_TEST(auth.seen[0].resource == arn);
    BOOST_TEST(auth.seen[1].action == "sns:GetSubscriptionAttributes");

    const auto pending = call("Action=Unsubscribe&SubscriptionArn=pending+confirmation");
    BOOST_TEST(pending._status == 400U);
    BOOST_TEST(code_of(pending) == "InvalidParameter");
    BOOST_TEST(element(pending._body, "Message") == "Invalid parameter: SubscriptionArn");
    BOOST_TEST(auth.seen.size() == 2U);
}

BOOST_FIXTURE_TEST_CASE(a_malformed_topic_arn_is_refused_before_authorization, recording_fixture) {
    for (const auto* bad :
         {"orders", "arn:aws:sqs:us-east-1:111122223333:orders",
          "arn:aws:sns:us-east-1:1111:orders", "arn:aws:sns:us-east-1:111122223333:bad%20name"}) {
        const auto r = call("Action=Publish&Message=m&TopicArn=" + std::string(bad));
        BOOST_TEST(r._status == 400U);
        BOOST_TEST(element(r._body, "Message") == "Invalid parameter: TopicArn");
    }
    BOOST_TEST(auth.seen.empty());
}

BOOST_FIXTURE_TEST_CASE(create_topic_checks_tagging_and_data_protection, recording_fixture) {
    const auto r = call(
        "Action=CreateTopic&Name=orders&Tags.member.1.Key=team&Tags.member.1.Value=red"
        "&Attributes.entry.1.key=DataProtectionPolicy&Attributes.entry.1.value=%7B%7D");
    BOOST_TEST(r._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 3U);
    BOOST_TEST(auth.seen[0].action == "sns:CreateTopic");
    BOOST_TEST(auth.seen[0].resource == topic("orders"));
    BOOST_REQUIRE(auth.seen[0].request_tags.has_value());
    BOOST_TEST(auth.seen[0].request_tags->at(0).first == "team");
    BOOST_TEST(key(auth.seen[0], "aws:TagKeys") == std::vector<std::string>{"team"});
    BOOST_TEST(auth.seen[1].action == "sns:TagResource");
    BOOST_TEST(auth.seen[2].action == "sns:PutDataProtectionPolicy");

    auth.seen.clear();
    BOOST_TEST(call("Action=CreateTopic&Name=plain")._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 1U);
    BOOST_TEST(!auth.seen[0].request_tags.has_value());

    auth.seen.clear();
    auth.deny = {"sns:TagResource"};
    const auto denied =
        call("Action=CreateTopic&Name=orders&Tags.member.1.Key=team&Tags.member.1.Value=red");
    BOOST_TEST(denied._status == 403U);
    BOOST_TEST(element(denied._body, "Message").find("SNS:TagResource") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(tag_operations_supply_tag_keys, recording_fixture) {
    const auto arn = kythira::aws_query::url_encode(topic("orders"));
    BOOST_TEST(call("Action=TagResource&ResourceArn=" + arn +
                    "&Tags.member.1.Key=a&Tags.member.1.Value=1&Tags.member.2.Key=b"
                    "&Tags.member.2.Value=2")
                   ._status == 200U);
    BOOST_TEST(
        call("Action=UntagResource&ResourceArn=" + arn + "&TagKeys.member.2=b&TagKeys.member.1=a")
            ._status == 200U);
    BOOST_REQUIRE_EQUAL(auth.seen.size(), 2U);
    BOOST_TEST(key(auth.seen[0], "aws:TagKeys") == (std::vector<std::string>{"a", "b"}));
    BOOST_TEST(key(auth.seen[1], "aws:TagKeys") == (std::vector<std::string>{"a", "b"}));
    BOOST_TEST(auth.seen[1].resource == topic("orders"));
}

BOOST_FIXTURE_TEST_CASE(an_explicit_deny_is_worded_as_one, recording_fixture) {
    auth.deny = {"sns:Publish"};
    auth.explicit_deny = true;
    const auto r = call("Action=Publish&Message=m&TopicArn=" +
                        kythira::aws_query::url_encode(topic("orders")));
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(element(r._body, "Message").ends_with(" with an explicit deny"));
}

BOOST_AUTO_TEST_CASE(a_handler_must_not_answer_unauthorized) {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe(sns::front_end_config{}, auth);
    // Publish without a TopicArn: the front end cannot authorize, so the
    // handler must; this one forgets.
    fe.on("Publish", echo);
    const auto r = fe.handle(post("Action=Publish&Message=m"));
    BOOST_TEST(r._status == 500U);
    BOOST_TEST(code_of(r) == "InternalError");
    BOOST_TEST(element(r._body, "Type") == "Receiver");
}

BOOST_AUTO_TEST_CASE(handler_errors_and_exceptions) {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe(sns::front_end_config{}, auth);
    fe.on("Publish", [](sns::call_context&, const sns::params&) -> sns::query_result<std::string> {
        return sns::not_found("Topic does not exist");
    });
    fe.on("ListTopics",
          [](sns::call_context&, const sns::params&) -> sns::query_result<std::string> {
              throw std::runtime_error("no quorum");
          });
    const auto nf = fe.handle(
        post("Action=Publish&Message=m&TopicArn=" + kythira::aws_query::url_encode(topic("gone"))));
    BOOST_TEST(nf._status == 404U);
    BOOST_TEST(nf._body ==
               "<ErrorResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><Error><Type>"
               "Sender</Type><Code>NotFound</Code><Message>Topic does not exist</Message></Error>"
               "<RequestId>" +
                   element(nf._body, "RequestId") + "</RequestId></ErrorResponse>");
    const auto boom = fe.handle(post("Action=ListTopics"));
    BOOST_TEST(boom._status == 500U);
    BOOST_TEST(code_of(boom) == "InternalError");
}

BOOST_AUTO_TEST_CASE(admission_runs_after_authentication) {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe(sns::front_end_config{}, auth);
    fe.on("ListTopics", echo);
    std::vector<std::string> asked;
    fe.set_admission([&asked](std::string_view op,
                              const az::principal_context& who) -> std::optional<sns::sns_error> {
        asked.push_back(std::string(op) + "/" + who.account);
        return sns::throttled();
    });
    const auto r = fe.handle(post("Action=ListTopics"));
    BOOST_TEST(r._status == 429U);
    BOOST_TEST(code_of(r) == "Throttled");
    BOOST_TEST(asked == std::vector<std::string>{"ListTopics/111122223333"});
    BOOST_TEST(auth.seen.empty());
}

BOOST_AUTO_TEST_CASE(handlers_can_authorize_further) {
    recording_authorizer auth;
    sns::front_end<recording_authorizer> fe(sns::front_end_config{}, auth);
    fe.on("ConfirmSubscription",
          [](sns::call_context& ctx, const sns::params&) -> sns::query_result<std::string> {
              az::authz_request r;
              r.action = "sns:Subscribe";
              r.resource = ctx._topic_arn;
              if (auto denied = ctx.authorize(std::move(r))) {
                  return *denied;
              }
              return std::string("<SubscriptionArn>x</SubscriptionArn>");
          });
    auth.deny = {"sns:Subscribe"};
    const auto r = fe.handle(post("Action=ConfirmSubscription&Token=t&TopicArn=" +
                                  kythira::aws_query::url_encode(topic("orders"))));
    BOOST_TEST(r._status == 403U);
    BOOST_TEST(auth.seen.size() == 2U);
}

BOOST_AUTO_TEST_SUITE_END()
