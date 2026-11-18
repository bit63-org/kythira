// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// SQS's two protocols, its errors, action table and compatibility profile
// (`.kiro/specs/sqs-compatible-queues/` task 3; Requirements 2.2, 2.3,
// 3.1, 3.3).
//
// The recorded client traffic (tests/evidence/data/) is replayed through
// the codec: every JSON request must parse and validate, and every query
// request must decode to exactly the JSON body botocore built it from, so
// the query names, flattening and scalar conversion are checked against
// what a real client sends. The answers are checked against AWS's
// documented XML shapes.

#define BOOST_TEST_MODULE sqs_codec_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/model/sqs_query_names.hpp>
#include <kythira/sqs/sqs_actions.hpp>
#include <kythira/sqs/sqs_codec.hpp>
#include <kythira/sqs/sqs_compat_profile.hpp>
#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_query_protocol.hpp>

#include <boost/json.hpp>

#include <cstddef>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef KYTHIRA_SQS_EVIDENCE_DIR
#error "KYTHIRA_SQS_EVIDENCE_DIR must name tests/evidence/data"
#endif

namespace sqs = kythira::sqs;
namespace aj = kythira::aws_json;
namespace aq = kythira::aws_query;

namespace {

auto load_evidence(std::string_view file) -> boost::json::object {
    std::ifstream in(std::string(KYTHIRA_SQS_EVIDENCE_DIR) + "/" + std::string(file));
    BOOST_TEST_REQUIRE(in.good(), "cannot open evidence file " << file);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return boost::json::parse(text).as_object();
}

auto header(const boost::json::object& request, std::string_view name) -> std::string {
    for (const auto& h : request.at("headers").as_array()) {
        const auto& pair = h.as_array();
        if (pair.at(0).as_string() == name) {
            return std::string(pair.at(1).as_string());
        }
    }
    return {};
}

auto make_codec() -> sqs::sqs_codec {
    return sqs::sqs_codec(sqs::sqs_codec_options{.endpoint = "http://localhost:9324"});
}

auto json_request(std::string_view op, const std::string& body) -> sqs::sqs_request_view {
    static thread_local std::string target;
    target = "AmazonSQS." + std::string(op);
    return sqs::sqs_request_view{
        .method = "POST",
        .path = "/",
        .content_type = "application/x-amz-json-1.0",
        .target = target,
        .query_mode = true,
        .body = body,
    };
}

auto form_request(const std::string& body, std::string_view path = "/") -> sqs::sqs_request_view {
    return sqs::sqs_request_view{
        .method = "POST",
        .path = path,
        .content_type = "application/x-www-form-urlencoded; charset=utf-8",
        .body = body,
    };
}

auto parse_form(const std::string& body, std::string_view path = "/")
    -> aj::result<sqs::sqs_parsed_request> {
    return make_codec().parse(form_request(body, path));
}

auto query_code(const aj::http_response& r) -> std::string {
    const auto open = r.body.find("<Code>");
    const auto close = r.body.find("</Code>");
    if (open == std::string::npos || close == std::string::npos) {
        return {};
    }
    return r.body.substr(open + 6, close - open - 6);
}

}  // namespace

// ---------------------------------------------------------------------------
// Recorded traffic
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(recorded_query_forms_decode_to_their_json_bodies) {
    const auto codec = make_codec();
    const auto evidence = load_evidence("boto3-query.json");
    std::size_t checked = 0;
    for (const auto& r : evidence.at("requests").as_array()) {
        const auto& request = r.as_object();
        std::string body;
        for (const auto& kv : request.at("form").as_array()) {
            const auto& pair = kv.as_array();
            if (!body.empty()) {
                body += '&';
            }
            body += aq::url_encode(pair.at(0).as_string());
            body += '=';
            body += aq::url_encode(pair.at(1).as_string());
        }
        const auto op = std::string(request.at("operation").as_string());
        const auto parsed = codec.parse(form_request(body));
        BOOST_TEST_REQUIRE(parsed.has_value(),
                           op << ": " << (parsed.has_value() ? "" : parsed.error().type) << " "
                              << (parsed.has_value() ? "" : parsed.error().message.value_or("")));
        BOOST_TEST(parsed->op->name == op);
        const boost::json::value got(parsed->input);
        const auto& want = request.at("body");
        BOOST_TEST(got == want, op << ": got " << boost::json::serialize(got) << " want "
                                   << boost::json::serialize(want));
        ++checked;
    }
    BOOST_TEST(checked == 24U);
}

BOOST_AUTO_TEST_CASE(recorded_json_requests_parse_and_validate) {
    const auto codec = make_codec();
    std::size_t checked = 0;
    for (const auto* file :
         {"boto3.json", "awscli-v2.json", "java-sdk-v2.json", "jms.json", "kombu.json"}) {
        const auto evidence = load_evidence(file);
        for (const auto& r : evidence.at("requests").as_array()) {
            const auto& request = r.as_object();
            const auto body = boost::json::serialize(request.at("body"));
            const auto target = header(request, "X-Amz-Target");
            const sqs::sqs_request_view view{
                .method = "POST",
                .path = "/",
                .content_type = "application/x-amz-json-1.0",
                .target = target,
                .query_mode = header(request, "x-amzn-query-mode") == "true",
                .body = body,
            };
            BOOST_TEST((sqs::sqs_codec::protocol_of(view) == sqs::sqs_protocol::json));
            BOOST_TEST(view.query_mode, file << ": every JSON client sends x-amzn-query-mode");
            const auto parsed = codec.parse(view);
            BOOST_TEST_REQUIRE(
                parsed.has_value(),
                file << " " << target << ": " << (parsed.has_value() ? "" : parsed.error().type)
                     << " " << (parsed.has_value() ? "" : parsed.error().message.value_or("")));
            BOOST_TEST(parsed->op->name == std::string_view(request.at("operation").as_string()));
            ++checked;
        }
    }
    BOOST_TEST(checked == 72U);
}

// ---------------------------------------------------------------------------
// Query requests
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(query_send_message_attributes_and_system_attributes) {
    const auto parsed = parse_form(
        "Action=SendMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2Fh%2F1%2Fq"
        "&MessageBody=hi&DelaySeconds=5"
        "&MessageAttribute.1.Name=color&MessageAttribute.1.Value.DataType=String"
        "&MessageAttribute.1.Value.StringValue=blue"
        "&MessageAttribute.2.Name=raw&MessageAttribute.2.Value.DataType=Binary"
        "&MessageAttribute.2.Value.BinaryValue=AAEC"
        "&MessageSystemAttribute.1.Name=AWSTraceHeader"
        "&MessageSystemAttribute.1.Value.DataType=String"
        "&MessageSystemAttribute.1.Value.StringValue=Root%3D1-abc");
    BOOST_TEST_REQUIRE(parsed.has_value());
    const auto want = boost::json::parse(R"({
        "QueueUrl": "http://h/1/q", "MessageBody": "hi", "DelaySeconds": 5,
        "MessageAttributes": {
            "color": {"DataType": "String", "StringValue": "blue"},
            "raw": {"DataType": "Binary", "BinaryValue": "AAEC"}},
        "MessageSystemAttributes": {
            "AWSTraceHeader": {"DataType": "String", "StringValue": "Root=1-abc"}}})");
    BOOST_TEST(boost::json::value(parsed->input) == want, boost::json::serialize(parsed->input));
}

BOOST_AUTO_TEST_CASE(query_lists_come_back_in_index_order) {
    const auto parsed = parse_form(
        "Action=ReceiveMessage&QueueUrl=http%3A%2F%2Fh%2F1%2Fq&MaxNumberOfMessages=10"
        "&AttributeName.10=SentTimestamp&AttributeName.2=All&MessageAttributeName.1=color");
    BOOST_TEST_REQUIRE(parsed.has_value());
    const auto want = boost::json::parse(R"({
        "QueueUrl": "http://h/1/q", "MaxNumberOfMessages": 10,
        "AttributeNames": ["All", "SentTimestamp"], "MessageAttributeNames": ["color"]})");
    BOOST_TEST(boost::json::value(parsed->input) == want, boost::json::serialize(parsed->input));
}

BOOST_AUTO_TEST_CASE(query_get_reads_the_query_string) {
    const auto codec = make_codec();
    const sqs::sqs_request_view view{
        .method = "GET",
        .path = "/123456789012/orders",
        .query_string = "Action=GetQueueAttributes&AttributeName.1=All",
    };
    BOOST_TEST((sqs::sqs_codec::protocol_of(view) == sqs::sqs_protocol::query));
    const auto parsed = codec.parse(view);
    BOOST_TEST_REQUIRE(parsed.has_value());
    BOOST_TEST(parsed->input.at("QueueUrl").as_string() ==
               "http://localhost:9324/123456789012/orders");
    BOOST_TEST(parsed->input.at("AttributeNames").as_array().size() == 1U);
}

BOOST_AUTO_TEST_CASE(query_queue_url_from_the_path_only_when_absent) {
    auto parsed = parse_form("Action=PurgeQueue", "/123456789012/orders");
    BOOST_TEST_REQUIRE(parsed.has_value());
    BOOST_TEST(parsed->input.at("QueueUrl").as_string() ==
               "http://localhost:9324/123456789012/orders");
    parsed =
        parse_form("Action=PurgeQueue&QueueUrl=http%3A%2F%2Fother%2F1%2Fq", "/123456789012/orders");
    BOOST_TEST_REQUIRE(parsed.has_value());
    BOOST_TEST(parsed->input.at("QueueUrl").as_string() == "http://other/1/q");
    // ListQueues has no QueueUrl member: the path is not one.
    parsed = parse_form("Action=ListQueues", "/123456789012/orders");
    BOOST_TEST_REQUIRE(parsed.has_value());
    BOOST_TEST(!parsed->input.contains("QueueUrl"));
}

BOOST_AUTO_TEST_CASE(query_failures_use_query_codes) {
    const auto codec = make_codec();
    const auto code_of = [&codec](const std::string& body) {
        const auto view = form_request(body);
        const auto parsed = codec.parse(view);
        BOOST_TEST_REQUIRE(!parsed.has_value(), body);
        const auto r = codec.respond(view, parsed.error(), "rid");
        BOOST_TEST(r.status == 400U);
        BOOST_TEST(*r.header("Content-Type") == "text/xml");
        return query_code(r);
    };
    BOOST_TEST(code_of("Version=2012-11-05") == "MissingAction");
    BOOST_TEST(code_of("Action=Explode") == "InvalidAction");
    BOOST_TEST(code_of("Action=ListQueues&MaxResults=ten") == "InvalidParameterValue");
    BOOST_TEST(code_of("Action=ListQueues&MaxResults=99999999999") == "InvalidParameterValue");
    BOOST_TEST(code_of("Action=GetQueueUrl") == "InvalidParameterValue");  // missing QueueName
    BOOST_TEST(code_of("Action=GetQueueAttributes&QueueUrl=u&AttributeName.0=All") ==
               "InvalidParameterValue");
    BOOST_TEST(code_of("Action=TagQueue&QueueUrl=u&Tag.1.Value=v") == "MissingParameter");
    BOOST_TEST(code_of("Action=ListQueues&Action=ListQueues") == "MalformedQueryString");
    BOOST_TEST(code_of("Action=ListQueues&QueueNamePrefix=%zz") == "MalformedQueryString");
}

BOOST_AUTO_TEST_CASE(unknown_parameters_and_members_are_ignored) {
    auto parsed = parse_form("Action=ListQueues&FutureParameter=1");
    BOOST_TEST(parsed.has_value());
    const auto codec = make_codec();
    const std::string body = R"({"QueueNamePrefix": "a", "FutureMember": {"x": 1}})";
    const auto json = codec.parse(json_request("ListQueues", body));
    BOOST_TEST_REQUIRE(json.has_value());
    BOOST_TEST(json->input.at("QueueNamePrefix").as_string() == "a");
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(receive_message_answers_in_aws_xml) {
    const auto codec = make_codec();
    const auto* op = sqs::sqs_codec::model().find_operation("ReceiveMessage");
    BOOST_TEST_REQUIRE(op != nullptr);
    const auto output = boost::json::parse(R"({"Messages": [{
        "MessageId": "m-1", "ReceiptHandle": "rh", "MD5OfBody": "d41d",
        "Body": "a<b", "Attributes": {"SenderId": "AID", "ApproximateReceiveCount": "1"},
        "MD5OfMessageAttributes": "e5f6",
        "MessageAttributes": {"color": {"StringValue": "blue", "DataType": "String"},
                              "tags": {"StringListValues": ["x", "y"], "DataType": "String"}}
    }]})")
                            .as_object();
    const auto r = codec.respond(form_request("Action=ReceiveMessage"), *op, output, "rid-1");
    BOOST_TEST(r.status == 200U);
    BOOST_TEST(*r.header("Content-Type") == "text/xml");
    BOOST_TEST(*r.header("x-amzn-RequestId") == "rid-1");
    const std::string want =
        R"(<ReceiveMessageResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">)"
        "<ReceiveMessageResult><Message>"
        "<MessageId>m-1</MessageId><ReceiptHandle>rh</ReceiptHandle><MD5OfBody>d41d</MD5OfBody>"
        "<Body>a&lt;b</Body>"
        "<Attribute><Name>SenderId</Name><Value>AID</Value></Attribute>"
        "<Attribute><Name>ApproximateReceiveCount</Name><Value>1</Value></Attribute>"
        "<MD5OfMessageAttributes>e5f6</MD5OfMessageAttributes>"
        "<MessageAttribute><Name>color</Name><Value><StringValue>blue</StringValue>"
        "<DataType>String</DataType></Value></MessageAttribute>"
        "<MessageAttribute><Name>tags</Name><Value><StringListValue>x</StringListValue>"
        "<StringListValue>y</StringListValue><DataType>String</DataType></Value>"
        "</MessageAttribute>"
        "</Message></ReceiveMessageResult>"
        "<ResponseMetadata><RequestId>rid-1</RequestId></ResponseMetadata>"
        "</ReceiveMessageResponse>";
    BOOST_TEST(r.body == want);
}

BOOST_AUTO_TEST_CASE(list_and_batch_answers_flatten_their_lists) {
    const auto codec = make_codec();
    const auto* list = sqs::sqs_codec::model().find_operation("ListQueues");
    auto output = boost::json::parse(R"({"QueueUrls": ["u1", "u2"], "NextToken": "t"})");
    BOOST_TEST(codec.json_to_xml(list->output, output.as_object()) ==
               "<QueueUrl>u1</QueueUrl><QueueUrl>u2</QueueUrl><NextToken>t</NextToken>");

    const auto* batch = sqs::sqs_codec::model().find_operation("SendMessageBatch");
    output = boost::json::parse(R"({
        "Successful": [{"Id": "a", "MessageId": "m", "MD5OfMessageBody": "x"}],
        "Failed": [{"Id": "b", "SenderFault": true, "Code": "InvalidParameterValue",
                    "Message": "no"}]})");
    BOOST_TEST(codec.json_to_xml(batch->output, output.as_object()) ==
               "<SendMessageBatchResultEntry><Id>a</Id><MessageId>m</MessageId>"
               "<MD5OfMessageBody>x</MD5OfMessageBody></SendMessageBatchResultEntry>"
               "<BatchResultErrorEntry><Id>b</Id><SenderFault>true</SenderFault>"
               "<Code>InvalidParameterValue</Code><Message>no</Message></BatchResultErrorEntry>");

    const auto* attrs = sqs::sqs_codec::model().find_operation("GetQueueAttributes");
    output = boost::json::parse(R"({"Attributes": {"DelaySeconds": "0"}})");
    BOOST_TEST(codec.json_to_xml(attrs->output, output.as_object()) ==
               "<Attribute><Name>DelaySeconds</Name><Value>0</Value></Attribute>");

    const auto* tags = sqs::sqs_codec::model().find_operation("ListQueueTags");
    output = boost::json::parse(R"({"Tags": {"team": "k"}})");
    BOOST_TEST(codec.json_to_xml(tags->output, output.as_object()) ==
               "<Tag><Key>team</Key><Value>k</Value></Tag>");
}

// botocore finds the answer by its <{Action}Result> wrapper, so an empty
// receive must still carry the element or the client raises KeyError.
BOOST_AUTO_TEST_CASE(empty_output_still_carries_the_result_element) {
    const auto codec = make_codec();
    const auto* op = sqs::sqs_codec::model().find_operation("ReceiveMessage");
    BOOST_TEST_REQUIRE(op != nullptr);
    const auto r = codec.respond(form_request("Action=ReceiveMessage"), *op, {}, "rid");
    BOOST_TEST(r.body ==
               R"(<ReceiveMessageResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">)"
               "<ReceiveMessageResult></ReceiveMessageResult>"
               "<ResponseMetadata><RequestId>rid</RequestId></ResponseMetadata>"
               "</ReceiveMessageResponse>");
}

BOOST_AUTO_TEST_CASE(operations_without_output_answer_with_metadata_only) {
    const auto codec = make_codec();
    const auto* op = sqs::sqs_codec::model().find_operation("DeleteMessage");
    const auto r = codec.respond(form_request("Action=DeleteMessage"), *op, {}, "rid");
    BOOST_TEST(r.body ==
               R"(<DeleteMessageResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">)"
               "<ResponseMetadata><RequestId>rid</RequestId></ResponseMetadata>"
               "</DeleteMessageResponse>");
    const auto j = codec.respond(json_request("DeleteMessage", "{}"), *op, {}, "rid");
    BOOST_TEST(j.body == "{}");
    BOOST_TEST(*j.header("Content-Type") == "application/x-amz-json-1.0");
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(modeled_errors_in_both_protocols) {
    const auto codec = make_codec();
    const auto e = sqs::queue_does_not_exist();
    BOOST_TEST(e.type == "com.amazonaws.sqs#QueueDoesNotExist");

    auto view = json_request("GetQueueUrl", "{}");
    auto r = codec.respond(view, e, "rid");
    BOOST_TEST(r.status == 400U);
    const auto body = boost::json::parse(r.body).as_object();
    BOOST_TEST(body.at("__type").as_string() == "com.amazonaws.sqs#QueueDoesNotExist");
    BOOST_TEST(body.at("message").as_string() == "The specified queue does not exist.");
    BOOST_TEST(*r.header("x-amzn-query-error") == "AWS.SimpleQueueService.NonExistentQueue;Sender");

    view.query_mode = false;
    r = codec.respond(view, e, "rid");
    BOOST_TEST(!r.header("x-amzn-query-error").has_value());

    r = codec.respond(form_request("Action=GetQueueUrl"), e, "rid-2");
    BOOST_TEST(r.body ==
               R"(<ErrorResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">)"
               "<Error><Type>Sender</Type><Code>AWS.SimpleQueueService.NonExistentQueue</Code>"
               "<Message>The specified queue does not exist.</Message></Error>"
               "<RequestId>rid-2</RequestId></ErrorResponse>");
}

BOOST_AUTO_TEST_CASE(query_statuses_come_from_the_query_model) {
    BOOST_TEST(sqs::modeled_error("OverLimit", "x").status == 403U);
    BOOST_TEST(sqs::modeled_error("PurgeQueueInProgress", "x").status == 403U);
    BOOST_TEST(sqs::modeled_error("QueueNameExists", "x").status == 400U);
    BOOST_TEST(sqs::to_query(sqs::modeled_error("QueueNameExists", "x")).code ==
               "QueueAlreadyExists");
    BOOST_TEST(sqs::to_query(sqs::modeled_error("ReceiptHandleIsInvalid", "x")).code ==
               "ReceiptHandleIsInvalid");
    BOOST_CHECK_THROW((void)sqs::modeled_error("NoSuchShape", "x"), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(protocol_and_foreign_errors_map_to_query_codes) {
    const auto internal = sqs::internal_failure();
    const auto q = sqs::to_query(internal);
    BOOST_TEST(q.code == "InternalFailure");
    BOOST_TEST(!q.sender);
    aj::error auth;
    auth.status = 403;
    auth.type = "com.amazon.coral.service#InvalidClientTokenId";
    BOOST_TEST(sqs::to_query(auth).code == "InvalidClientTokenId");
    BOOST_TEST(sqs::to_query(auth).sender);

    const auto codec = make_codec();
    const auto bad = codec.parse(json_request("ListQueues", "{not json"));
    BOOST_TEST_REQUIRE(!bad.has_value());
    const auto r = codec.respond(json_request("ListQueues", ""), bad.error(), "rid");
    BOOST_TEST(*r.header("x-amzn-query-error") == "MalformedQueryString;Sender");
}

BOOST_AUTO_TEST_CASE(every_exception_shape_has_a_query_error) {
    const auto& m = sqs::sqs_codec::model();
    std::size_t exceptions = 0;
    for (const auto& s : m.shapes) {
        if (s.is(aj::shape_flag_exception)) {
            ++exceptions;
            BOOST_TEST(sqs::sqs_query::find_error(s.name) != nullptr, s.name);
        }
    }
    BOOST_TEST(exceptions == sqs::sqs_query::k_errors.size());
}

BOOST_AUTO_TEST_CASE(every_structure_member_has_query_names) {
    const auto& m = sqs::sqs_codec::model();
    for (const auto& s : m.shapes) {
        if (s.kind != aj::shape_kind::structure || s.is(aj::shape_flag_exception)) {
            continue;
        }
        for (const auto& member : m.members_of(s)) {
            BOOST_TEST(sqs::sqs_query::find_member(s.name, member.name) != nullptr,
                       s.name << "." << member.name);
        }
    }
}

// ---------------------------------------------------------------------------
// Actions and static roles
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(every_operation_has_an_authorizing_action) {
    const auto table = sqs::sqs_actions();
    std::set<std::string> actions;
    for (const auto& a : table.actions) {
        actions.insert(a.name);
    }
    for (const auto& op : sqs::sqs_codec::model().operations) {
        const auto* entry = sqs::find_operation_actions(op.name);
        BOOST_TEST_REQUIRE(entry != nullptr, op.name);
        BOOST_TEST(actions.contains(std::string(entry->primary_action)), op.name);
    }
    BOOST_TEST(sqs::find_operation_actions("SendMessageBatch")->primary_action == "SendMessage");
    BOOST_TEST(sqs::find_operation_actions("ReceiveMessage")->writes);
    BOOST_TEST(!sqs::find_operation_actions("GetQueueUrl")->writes);
    BOOST_TEST(sqs::find_operation_actions("Explode") == nullptr);
}

BOOST_AUTO_TEST_CASE(static_roles_split_metadata_reads_from_message_actions) {
    const auto roles = sqs::sqs_static_roles();
    const std::set<std::string> ro(roles.read_only.begin(), roles.read_only.end());
    const std::set<std::string> rw(roles.read_write.begin(), roles.read_write.end());
    BOOST_TEST(ro.contains("GetQueueAttributes"));
    BOOST_TEST(!ro.contains("ReceiveMessage"));
    BOOST_TEST(!ro.contains("SetQueueAttributes"));
    BOOST_TEST(rw == (std::set<std::string>{"ChangeMessageVisibility", "DeleteMessage",
                                            "ReceiveMessage", "SendMessage"}));
}

// ---------------------------------------------------------------------------
// Compatibility profile
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(compat_profile_defaults_are_sqs) {
    const sqs::sqs_compat_profile p;
    BOOST_TEST(p._max_message_bytes == 1048576U);
    BOOST_TEST(p._max_batch_entries == 10U);
    BOOST_TEST(p._max_wait_s == 20U);
    BOOST_TEST(p._max_inflight_fifo == 120000U);
    BOOST_TEST(p.relaxed().empty());
}

BOOST_AUTO_TEST_CASE(compat_profile_switches) {
    sqs::sqs_compat_profile p;
    BOOST_TEST(p.set("Message-Size", "4194304"));
    BOOST_TEST(p._max_message_bytes == 4194304U);
    BOOST_TEST(p.set("long-poll-max", "60"));
    BOOST_TEST(p.set("fifo-throughput", "OFF"));
    BOOST_TEST(!p._fifo_throughput_limits);
    BOOST_TEST((p.relaxed() ==
                std::vector<std::string_view>{"message-size", "fifo-throughput", "long-poll-max"}));
    BOOST_TEST(p.set("message-size", "aws"));
    BOOST_TEST(p._max_message_bytes == 1048576U);

    const auto before = p;
    BOOST_TEST(!p.set("message-size", "100"));  // below range
    BOOST_TEST(!p.set("batch-size", "101"));    // above range
    BOOST_TEST(!p.set("batch-size", "ten"));
    BOOST_TEST(!p.set("batch-size", ""));
    BOOST_TEST(!p.set("fifo-throughput", "aws"));    // on/off only
    BOOST_TEST(!p.set("retention-min", "1209601"));  // above the range
    BOOST_TEST(!p.set("no-such-switch", "1"));
    BOOST_TEST(p.set("retention-max", "120"));
    BOOST_TEST(!p.set("retention-min", "121"));  // would pass retention-max
    BOOST_TEST(p.set("retention-min", "120"));
    BOOST_TEST((p != before));
}

BOOST_AUTO_TEST_CASE(compat_profile_cluster_and_queue_tags) {
    const auto cluster = sqs::cluster_profile({{"long-poll-max", "30"}});
    BOOST_TEST_REQUIRE(cluster.has_value());
    BOOST_TEST(cluster->_max_wait_s == 30U);
    BOOST_TEST(!sqs::cluster_profile({{"long-poll-max", "301"}}).has_value());

    const std::vector<std::pair<std::string, std::string>> tags{
        {"team", "k"}, {"kythira:compat:batch-size", "25"}};
    BOOST_TEST(!sqs::check_compat_tags(*cluster, tags).has_value());
    const auto q = sqs::resolve_profile(*cluster, tags);
    BOOST_TEST(q._max_batch_entries == 25U);
    BOOST_TEST(q._max_wait_s == 30U);

    const auto bad = sqs::check_compat_tags(*cluster, {{"kythira:compat:batch-size", "x"}});
    BOOST_TEST_REQUIRE(bad.has_value());
    BOOST_TEST(sqs::to_query(*bad).code == "InvalidParameterValue");
    // A bad tag already on a queue is skipped.
    const auto skipped = sqs::resolve_profile(*cluster, {{"kythira:compat:batch-size", "x"}});
    BOOST_TEST((skipped == *cluster));
}
