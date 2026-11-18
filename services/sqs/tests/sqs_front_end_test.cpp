// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The front end (`.kiro/specs/sqs-compatible-queues/` task 3,
// Requirements 3.1-3.3): SigV4 in both protocols' wording, unsupported
// operations, queue resolution from QueueUrl, QueueName and SourceArn,
// authorization of the primary action on the queue with its tags and
// policy, CreateQueue's extra TagQueue check, handler-driven authorization
// and its safety net, and the queue-policy edits AddPermission and
// RemovePermission make. Real SigV4 through the static-key authorizer,
// plus a recording authorizer for the resource and key checks.

#define BOOST_TEST_MODULE sqs_front_end_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_queue_policy.hpp>

#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sqs = kythira::sqs;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_other = "444455556666";
constexpr std::string_view k_url = "http://localhost:9324/111122223333/orders";
constexpr std::string_view k_arn = "arn:aws:sqs:us-east-1:111122223333:orders";
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

auto json_request(std::string_view op, std::string body) -> sqs::sqs_request {
    sqs::sqs_request r;
    r._method = "POST";
    r._path = "/";
    r._body = std::move(body);
    r._source_ip = "192.0.2.10";
    r._headers = {{"Host", "localhost:9324"},
                  {"Content-Type", "application/x-amz-json-1.0"},
                  {"X-Amz-Date", "20261118T120000Z"},
                  {"X-Amz-Target", "AmazonSQS." + std::string(op)},
                  {"x-amzn-query-mode", "true"}};
    return r;
}

auto query_request(std::string body, std::string path = "/") -> sqs::sqs_request {
    sqs::sqs_request r;
    r._method = "POST";
    r._path = std::move(path);
    r._body = std::move(body);
    r._headers = {{"Host", "localhost:9324"},
                  {"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
                  {"X-Amz-Date", "20261118T120000Z"}};
    return r;
}

// Signs `r` as `akid` (header form) for `service`, as an SDK does.
auto sign(sqs::sqs_request r, std::string_view akid, std::string_view service = "sqs")
    -> sqs::sqs_request {
    sv4::service_rules rules;
    rules.service = std::string(service);
    const sv4::credential_scope scope{"20261118", "us-east-1", std::string(service)};
    const bool json = !sqs::front_end_detail::header_value(r, "X-Amz-Target").empty();
    r._headers.emplace_back("Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(akid) +
                                                 "/" + scope.text() +
                                                 ", SignedHeaders=content-type;host;x-amz-date" +
                                                 (json ? ";x-amz-target;x-amzn-query-mode" : "") +
                                                 ", Signature=" + std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r._method, r._path, r._query, r._headers, r._body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r._headers.back().second.replace(r._headers.back().second.size() - 64, 64, sig);
    return r;
}

auto body_of(const aj::http_response& r) -> json::object {
    return json::parse(r.body).as_object();
}

auto type_of(const aj::http_response& r) -> std::string {
    return std::string(body_of(r).at("__type").as_string());
}

auto query_code_of(const aj::http_response& r) -> std::string {
    const auto open = r.body.find("<Code>");
    const auto close = r.body.find("</Code>");
    BOOST_REQUIRE_MESSAGE(open != std::string::npos && close != std::string::npos, r.body);
    return r.body.substr(open + 6, close - open - 6);
}

auto echo(sqs::sqs_call_context& ctx, json::object&) -> aj::result<json::object> {
    json::object out;
    if (ctx._operation == "GetQueueUrl" && ctx._queue) {
        out["QueueUrl"] = ctx._queue->_url;
    }
    return out;
}

struct static_fixture {
    az::static_key_authorizer auth{std::vector<az::static_key>{
                                       {"AKIDREAD", std::string(k_secret), std::string(k_account),
                                        "reader", az::static_role::read_only},
                                       {"AKIDWRITE", std::string(k_secret), std::string(k_account),
                                        "writer", az::static_role::read_write},
                                       {"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                        "admin", az::static_role::admin},
                                   },
                                   "aws",
                                   [] { return std::chrono::system_clock::time_point(k_now); }};
    std::unique_ptr<sqs::sqs_front_end<az::static_key_authorizer>> fe;

    static_fixture() {
        auth.register_service(sqs::sqs_static_roles());
        fe = std::make_unique<sqs::sqs_front_end<az::static_key_authorizer>>(
            sqs::sqs_front_end_config{}, auth);
        for (const auto* op : {"GetQueueUrl", "SendMessage", "SendMessageBatch", "ReceiveMessage",
                               "CreateQueue", "ListQueues"}) {
            fe->on(op, echo);
        }
    }
};

// Authenticates everyone as one IAM user and records what it is asked.
struct recording_authorizer {
    std::vector<az::authz_request> asked;
    std::set<std::string> deny;

    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        az::principal_context p;
        p.account = std::string(k_account);
        p.arn = "arn:aws:iam::111122223333:user/alice";
        p.access_key_id = "AKIDALICE";
        return p;
    }
    auto authorize(const az::principal_context&, const az::authz_request& r) -> az::authz_decision {
        asked.push_back(r);
        az::authz_decision d;
        d.allowed = !deny.contains(r.action);
        return d;
    }
};
static_assert(az::aws_request_authorizer<recording_authorizer>);

struct recording_fixture {
    recording_authorizer auth;
    sqs::sqs_front_end<recording_authorizer> fe{sqs::sqs_front_end_config{}, auth};

    recording_fixture() {
        for (const auto* op : {"SendMessage", "SendMessageBatch", "CreateQueue", "TagQueue",
                               "UntagQueue", "ListQueues", "GetQueueUrl", "StartMessageMoveTask",
                               "PurgeQueue", "ReceiveMessage"}) {
            fe.on(op, echo);
        }
    }

    auto send(std::string_view op, std::string body) -> aj::http_response {
        return fe.handle(json_request(op, std::move(body)));
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Authentication, framing and roles
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_signed_read_reaches_its_handler_in_both_protocols) {
    static_fixture f;
    auto r =
        f.fe->handle(sign(json_request("GetQueueUrl", R"({"QueueName":"orders"})"), "AKIDREAD"));
    BOOST_TEST_REQUIRE(r.status == 200U, r.body);
    BOOST_TEST(body_of(r).at("QueueUrl").as_string() == k_url);

    r = f.fe->handle(sign(query_request("Action=GetQueueUrl&QueueName=orders"), "AKIDREAD"));
    BOOST_TEST_REQUIRE(r.status == 200U, r.body);
    BOOST_TEST(r.body.find("<GetQueueUrlResult><QueueUrl>" + std::string(k_url) +
                           "</QueueUrl></GetQueueUrlResult>") != std::string::npos,
               r.body);
}

BOOST_AUTO_TEST_CASE(unsigned_and_badly_signed_requests_are_refused_in_their_protocol) {
    static_fixture f;
    // Unsigned, with a body that would not even parse: the caller learns
    // only that it must sign.
    auto r = f.fe->handle(json_request("SendMessage", "{not json"));
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(type_of(r) == "IncompleteSignatureException");
    BOOST_TEST(*r.header("x-amzn-query-error") == "IncompleteSignature;Sender");

    r = f.fe->handle(query_request("Action=SendMessage"));
    BOOST_TEST(query_code_of(r) == "IncompleteSignature");
    BOOST_TEST(r.body.find("<Type>Sender</Type>") != std::string::npos);

    // Signed for another service.
    r = f.fe->handle(sign(json_request("ListQueues", "{}"), "AKIDREAD", "kinesis"));
    BOOST_TEST(r.status >= 400U);
    // An unknown key.
    r = f.fe->handle(sign(json_request("ListQueues", "{}"), "AKIDNOBODY"));
    BOOST_TEST(type_of(r) == "UnrecognizedClientException");
    BOOST_TEST(*r.header("x-amzn-query-error") == "InvalidClientTokenId;Sender");
    r = f.fe->handle(sign(query_request("Action=ListQueues"), "AKIDNOBODY"));
    BOOST_TEST(query_code_of(r) == "InvalidClientTokenId");
}

BOOST_AUTO_TEST_CASE(unknown_and_unimplemented_operations) {
    static_fixture f;
    // An unknown target is refused before authentication.
    auto r = f.fe->handle(json_request("Frobnicate", "{}"));
    BOOST_TEST(type_of(r) == "com.amazon.coral.service#UnknownOperationException");
    BOOST_TEST(*r.header("x-amzn-query-error") == "InvalidAction;Sender");
    // A modeled operation without a handler, whatever its input.
    r = f.fe->handle(sign(json_request("PurgeQueue", R"({"QueueUrl": 7})"), "AKIDADMIN"));
    BOOST_TEST(type_of(r) == "com.amazon.coral.service#UnknownOperationException");
    r = f.fe->handle(sign(query_request("Action=PurgeQueue"), "AKIDADMIN"));
    BOOST_TEST(query_code_of(r) == "InvalidAction");
    r = f.fe->handle(sign(query_request("Action=Frobnicate"), "AKIDADMIN"));
    BOOST_TEST(query_code_of(r) == "InvalidAction");
    r = f.fe->handle(sign(query_request("Version=2012-11-05"), "AKIDADMIN"));
    BOOST_TEST(query_code_of(r) == "MissingAction");
}

BOOST_AUTO_TEST_CASE(static_roles_gate_message_and_admin_actions) {
    static_fixture f;
    const std::string send = R"({"QueueUrl":")" + std::string(k_url) + R"(","MessageBody":"hi"})";
    auto r = f.fe->handle(sign(json_request("SendMessage", send), "AKIDREAD"));
    BOOST_TEST(r.status == 403U);
    BOOST_TEST(type_of(r) == "com.amazon.coral.service#AccessDeniedException");
    BOOST_TEST(*r.header("x-amzn-query-error") == "AccessDenied;Sender");
    BOOST_TEST(body_of(r).at("message").as_string().find("sqs:SendMessage") != std::string::npos);

    BOOST_TEST(f.fe->handle(sign(json_request("SendMessage", send), "AKIDWRITE")).status == 200U);
    // A batch authorizes as its single-entry action.
    const std::string batch =
        R"({"QueueUrl":")" + std::string(k_url) + R"(","Entries":[{"Id":"a","MessageBody":"x"}]})";
    BOOST_TEST(f.fe->handle(sign(json_request("SendMessageBatch", batch), "AKIDWRITE")).status ==
               200U);
    // Receiving consumes: not for a read-only key.
    const std::string recv = R"({"QueueUrl":")" + std::string(k_url) + R"("})";
    BOOST_TEST(f.fe->handle(sign(json_request("ReceiveMessage", recv), "AKIDREAD")).status == 403U);
    BOOST_TEST(f.fe->handle(sign(json_request("ReceiveMessage", recv), "AKIDWRITE")).status ==
               200U);
    // CreateQueue is administration.
    const auto create = sign(query_request("Action=CreateQueue&QueueName=new"), "AKIDWRITE");
    r = f.fe->handle(create);
    BOOST_TEST(r.status == 403U);
    BOOST_TEST(query_code_of(r) == "AccessDenied");
    BOOST_TEST(
        f.fe->handle(sign(query_request("Action=CreateQueue&QueueName=new"), "AKIDADMIN")).status ==
        200U);
    BOOST_TEST(f.fe->handle(sign(json_request("ListQueues", "{}"), "AKIDREAD")).status == 200U);
}

// ---------------------------------------------------------------------------
// Queues and authorization requests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_queue_comes_from_its_url_name_or_arn) {
    recording_fixture f;
    const std::string send = R"({"QueueUrl":")" + std::string(k_url) + R"(","MessageBody":"hi"})";
    BOOST_TEST(f.send("SendMessage", send).status == 200U);
    BOOST_TEST_REQUIRE(f.auth.asked.size() == 1U);
    BOOST_TEST(f.auth.asked[0].action == "sqs:SendMessage");
    BOOST_TEST(f.auth.asked[0].resource == k_arn);
    BOOST_TEST(f.auth.asked[0].resource_account.empty());
    BOOST_TEST(f.auth.asked[0].source_ip == "192.0.2.10");

    f.auth.asked.clear();
    BOOST_TEST(f.send("GetQueueUrl", R"({"QueueName":"orders","QueueOwnerAWSAccountId":")" +
                                         std::string(k_other) + R"("})")
                   .status == 200U);
    BOOST_TEST(f.auth.asked.at(0).action == "sqs:GetQueueUrl");
    BOOST_TEST(f.auth.asked.at(0).resource == "arn:aws:sqs:us-east-1:444455556666:orders");
    BOOST_TEST(f.auth.asked.at(0).resource_account == k_other);

    f.auth.asked.clear();
    BOOST_TEST(f.send("StartMessageMoveTask",
                      R"({"SourceArn":"arn:aws:sqs:us-east-1:111122223333:orders-dlq"})")
                   .status == 200U);
    BOOST_TEST(f.auth.asked.at(0).resource == "arn:aws:sqs:us-east-1:111122223333:orders-dlq");

    f.auth.asked.clear();
    BOOST_TEST(f.send("ListQueues", "{}").status == 200U);
    BOOST_TEST(f.auth.asked.at(0).action == "sqs:ListQueues");
    BOOST_TEST(f.auth.asked.at(0).resource == "*");

    // A query request may name its queue by path.
    f.auth.asked.clear();
    BOOST_TEST(f.fe.handle(query_request("Action=PurgeQueue", "/111122223333/orders")).status ==
               200U);
    BOOST_TEST(f.auth.asked.at(0).resource == k_arn);
}

BOOST_AUTO_TEST_CASE(a_url_or_arn_that_names_no_queue_is_queue_does_not_exist) {
    recording_fixture f;
    for (const auto* url : {"orders", "http://h/", "http://h/orders", "http://h/acct/orders",
                            "http://h/111122223333/a/b"}) {
        const auto r = f.send("SendMessage",
                              R"({"QueueUrl":")" + std::string(url) + R"(","MessageBody":"x"})");
        BOOST_TEST(type_of(r) == "com.amazonaws.sqs#QueueDoesNotExist", url);
        BOOST_TEST(*r.header("x-amzn-query-error") ==
                   "AWS.SimpleQueueService.NonExistentQueue;Sender");
    }
    const auto r = f.send("StartMessageMoveTask", R"({"SourceArn":"arn:aws:sns:us-east-1:1:t"})");
    BOOST_TEST(type_of(r) == "com.amazonaws.sqs#QueueDoesNotExist");
    BOOST_TEST(f.auth.asked.empty());
}

BOOST_AUTO_TEST_CASE(queue_tags_and_policy_reach_the_authorizer) {
    recording_fixture f;
    const std::string policy = R"({"Version":"2012-10-17","Statement":[]})";
    f.fe.set_queue_lookup([&policy](std::string_view arn) -> std::optional<sqs::queue_facts> {
        if (arn != k_arn) {
            return std::nullopt;
        }
        return sqs::queue_facts{{{"team", "k"}}, policy};
    });
    const std::string send = R"({"QueueUrl":")" + std::string(k_url) + R"(","MessageBody":"hi"})";
    BOOST_TEST(f.send("SendMessage", send).status == 200U);
    const auto& r = f.auth.asked.at(0);
    BOOST_TEST(r.resource_policy.value_or("") == policy);
    BOOST_TEST_REQUIRE(r.resource_tags.size() == 1U);
    BOOST_TEST(r.resource_tags[0].first == "team");
}

BOOST_AUTO_TEST_CASE(cross_account_queues_carry_their_account) {
    recording_fixture f;
    f.auth.deny.insert("sqs:SendMessage");
    const auto r = f.send("SendMessage", R"({"QueueUrl":"http://h/444455556666/shared",)"
                                         R"("MessageBody":"hi"})");
    BOOST_TEST(r.status == 403U);
    BOOST_TEST(f.auth.asked.at(0).resource == "arn:aws:sqs:us-east-1:444455556666:shared");
    BOOST_TEST(f.auth.asked.at(0).resource_account == k_other);
}

BOOST_AUTO_TEST_CASE(tagging_requests_carry_their_tags) {
    recording_fixture f;
    BOOST_TEST(f.send("CreateQueue", R"({"QueueName":"new","tags":{"team":"k"}})").status == 200U);
    BOOST_TEST_REQUIRE(f.auth.asked.size() == 2U);
    BOOST_TEST(f.auth.asked[0].action == "sqs:CreateQueue");
    BOOST_TEST(f.auth.asked[1].action == "sqs:TagQueue");
    BOOST_TEST(f.auth.asked[1].resource == "arn:aws:sqs:us-east-1:111122223333:new");
    BOOST_TEST_REQUIRE(f.auth.asked[1].request_tags.has_value());
    BOOST_TEST(f.auth.asked[1].request_tags->at(0).second == "k");

    // Without tags, no TagQueue check.
    f.auth.asked.clear();
    BOOST_TEST(f.send("CreateQueue", R"({"QueueName":"plain"})").status == 200U);
    BOOST_TEST(f.auth.asked.size() == 1U);

    // Denied tagging fails the create.
    f.auth.asked.clear();
    f.auth.deny.insert("sqs:TagQueue");
    BOOST_TEST(f.send("CreateQueue", R"({"QueueName":"new","tags":{"team":"k"}})").status == 403U);

    f.auth.asked.clear();
    f.auth.deny.clear();
    const std::string url = std::string(k_url);
    BOOST_TEST(f.send("TagQueue", R"({"QueueUrl":")" + url + R"(","Tags":{"a":"1"}})").status ==
               200U);
    BOOST_TEST(f.auth.asked.at(0).request_tags->at(0).first == "a");
    f.auth.asked.clear();
    BOOST_TEST(
        f.send("UntagQueue", R"({"QueueUrl":")" + url + R"(","TagKeys":["a","b"]})").status ==
        200U);
    const auto& keys = f.auth.asked.at(0).keys;
    BOOST_TEST_REQUIRE(keys.size() == 1U);
    BOOST_TEST(keys[0].first == "aws:TagKeys");
    BOOST_TEST((keys[0].second == std::vector<std::string>{"a", "b"}));
}

BOOST_AUTO_TEST_CASE(handlers_must_authorize_what_the_front_end_cannot) {
    recording_fixture f;
    f.fe.on("CancelMessageMoveTask", [](sqs::sqs_call_context&, json::object&) {
        return aj::result<json::object>(json::object{});
    });
    // The task handle names no queue: nothing authorized, so the answer is
    // withheld.
    auto r = f.send("CancelMessageMoveTask", R"({"TaskHandle":"t"})");
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(type_of(r) == "com.amazon.coral.service#InternalFailure");
    BOOST_TEST(*r.header("x-amzn-query-error") == "InternalFailure;Receiver");

    recording_fixture g;
    g.fe.on("CancelMessageMoveTask", [](sqs::sqs_call_context& ctx, json::object&) {
        az::authz_request a;
        a.action = "sqs:CancelMessageMoveTask";
        a.resource = ctx.queue_arn(ctx._principal.account, "orders-dlq");
        if (auto denied = ctx.authorize(std::move(a))) {
            return aj::result<json::object>(*denied);
        }
        return aj::result<json::object>(json::object{});
    });
    BOOST_TEST(g.send("CancelMessageMoveTask", R"({"TaskHandle":"t"})").status == 200U);
    BOOST_TEST(g.auth.asked.at(0).resource == "arn:aws:sqs:us-east-1:111122223333:orders-dlq");
}

BOOST_AUTO_TEST_CASE(a_throwing_handler_is_an_internal_failure) {
    recording_fixture f;
    f.fe.on("DeleteQueue", [](sqs::sqs_call_context&, json::object&) -> aj::result<json::object> {
        throw std::runtime_error("boom");
    });
    const auto r = f.fe.handle(query_request("Action=DeleteQueue&QueueUrl=" + std::string(k_url)));
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(query_code_of(r) == "InternalFailure");
    BOOST_TEST(r.body.find("<Type>Receiver</Type>") != std::string::npos);
    BOOST_TEST(r.body.find("boom") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(writes_are_flagged_for_the_leader) {
    recording_fixture f;
    std::optional<bool> seen;
    f.fe.on("GetQueueAttributes", [&seen](sqs::sqs_call_context& ctx, json::object&) {
        seen = ctx._writes;
        return aj::result<json::object>(json::object{});
    });
    BOOST_TEST(
        f.send("GetQueueAttributes", R"({"QueueUrl":")" + std::string(k_url) + R"("})").status ==
        200U);
    BOOST_TEST((seen == std::optional<bool>(false)));
    BOOST_CHECK_THROW(f.fe.on("Frobnicate", echo), std::invalid_argument);
    BOOST_CHECK_THROW(f.fe.on("SendMessage", echo), std::invalid_argument);
    BOOST_TEST(f.fe.handles("SendMessage"));
    BOOST_TEST(!f.fe.handles("AddPermission"));
}

// ---------------------------------------------------------------------------
// Queue policies
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(add_permission_writes_sqs_statements) {
    auto p =
        sqs::add_permission("", k_arn, "aws", "share", {std::string(k_other)}, {"SendMessage"});
    BOOST_TEST_REQUIRE(p.has_value());
    const auto doc = json::parse(*p).as_object();
    BOOST_TEST(doc.at("Version").as_string() == "2012-10-17");
    BOOST_TEST(doc.at("Id").as_string() == std::string(k_arn) + "/SQSDefaultPolicy");
    const auto& st = doc.at("Statement").as_array().at(0).as_object();
    BOOST_TEST(st.at("Sid").as_string() == "share");
    BOOST_TEST(st.at("Effect").as_string() == "Allow");
    BOOST_TEST(st.at("Principal").at("AWS").as_string() == "arn:aws:iam::444455556666:root");
    BOOST_TEST(st.at("Action").as_string() == "SQS:SendMessage");
    BOOST_TEST(st.at("Resource").as_string() == k_arn);

    // A second label adds a statement; lists stay lists.
    p = sqs::add_permission(*p, k_arn, "aws", "two", {std::string(k_other), "777788889999"},
                            {"ReceiveMessage", "DeleteMessage"});
    BOOST_TEST_REQUIRE(p.has_value());
    const auto doc2 = json::parse(*p).as_object();
    const auto& st2 = doc2.at("Statement").as_array().at(1).as_object();
    BOOST_TEST(st2.at("Principal").at("AWS").as_array().size() == 2U);
    BOOST_TEST(st2.at("Action").as_array().size() == 2U);
}

BOOST_AUTO_TEST_CASE(add_permission_refuses_what_sqs_refuses) {
    const auto code = [](const aj::result<std::string>& r) {
        BOOST_TEST_REQUIRE(!r.has_value());
        return sqs::to_query(r.error()).code;
    };
    const std::vector<std::string> acct{std::string(k_other)};
    BOOST_TEST(code(sqs::add_permission("", k_arn, "aws", "bad label", acct, {"SendMessage"})) ==
               "InvalidParameterValue");
    BOOST_TEST(code(sqs::add_permission("", k_arn, "aws", "l", {"123"}, {"SendMessage"})) ==
               "InvalidParameterValue");
    BOOST_TEST(code(sqs::add_permission("", k_arn, "aws", "l", acct, {"CreateQueue"})) ==
               "InvalidParameterValue");
    BOOST_TEST(code(sqs::add_permission("", k_arn, "aws", "l", acct, {})) == "MissingParameter");
    BOOST_TEST(code(sqs::add_permission("", k_arn, "aws", "l", {}, {"*"})) == "MissingParameter");
    BOOST_TEST(code(sqs::add_permission("not json", k_arn, "aws", "l", acct, {"*"})) ==
               "InvalidParameterValue");
    const auto once = sqs::add_permission("", k_arn, "aws", "l", acct, {"*"});
    BOOST_TEST_REQUIRE(once.has_value());
    BOOST_TEST(code(sqs::add_permission(*once, k_arn, "aws", "l", acct, {"*"})) ==
               "InvalidParameterValue");
    std::string full;
    for (std::size_t i = 0; i < sqs::k_max_policy_statements; ++i) {
        auto next = sqs::add_permission(full, k_arn, "aws", "l" + std::to_string(i), acct, {"*"});
        BOOST_TEST_REQUIRE(next.has_value());
        full = *next;
    }
    BOOST_TEST(code(sqs::add_permission(full, k_arn, "aws", "over", acct, {"*"})) == "OverLimit");
}

BOOST_AUTO_TEST_CASE(remove_permission_drops_one_label) {
    const std::vector<std::string> acct{std::string(k_other)};
    auto p = sqs::add_permission("", k_arn, "aws", "a", acct, {"SendMessage"});
    p = sqs::add_permission(*p, k_arn, "aws", "b", acct, {"ReceiveMessage"});
    BOOST_TEST_REQUIRE(p.has_value());
    auto removed = sqs::remove_permission(*p, k_arn, "a");
    BOOST_TEST_REQUIRE(removed.has_value());
    const auto doc = json::parse(*removed).as_object();
    BOOST_TEST(doc.at("Statement").as_array().size() == 1U);
    BOOST_TEST(doc.at("Statement").as_array().at(0).at("Sid").as_string() == "b");
    // The last label leaves no policy.
    removed = sqs::remove_permission(*removed, k_arn, "b");
    BOOST_TEST_REQUIRE(removed.has_value());
    BOOST_TEST(removed->empty());
    // An unknown label, or no policy at all.
    BOOST_TEST(!sqs::remove_permission(*p, k_arn, "zzz").has_value());
    BOOST_TEST(!sqs::remove_permission("", k_arn, "a").has_value());
    // A policy written with a single statement object is read too.
    const std::string single =
        R"({"Version":"2012-10-17","Statement":{"Sid":"x","Effect":"Allow","Action":"*"}})";
    removed = sqs::remove_permission(single, k_arn, "x");
    BOOST_TEST_REQUIRE(removed.has_value());
    BOOST_TEST(removed->empty());
}
