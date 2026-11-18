// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The queue and message handlers (`.kiro/specs/sqs-compatible-queues/`
// task 4, Requirements 4.1, 4.2, 5.1-5.5), end to end through the front end
// with real SigV4 over a local_queue_cluster whose clock the test turns:
// queue lifecycle (idempotent create, QueueNameExists, the deletion
// cooldown, fresh ids), listing, attributes and counts, permissions, tags
// and purges; sends, receives, deletes and visibility changes with their
// receipt-handle rules; batches with per-entry results; FIFO groups,
// deduplication and sequence numbers; and the query protocol's answers.

#define BOOST_TEST_MODULE sqs_service_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_messages.hpp>
#include <kythira/sqs/sqs_service.hpp>

#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <set>
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
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

auto sign(sqs::sqs_request r, std::string_view akid) -> sqs::sqs_request {
    sv4::service_rules rules;
    rules.service = "sqs";
    const sv4::credential_scope scope{"20261118", "us-east-1", "sqs"};
    const bool is_json = !sqs::front_end_detail::header_value(r, "X-Amz-Target").empty();
    r._headers.emplace_back("Authorization", "AWS4-HMAC-SHA256 Credential=" + std::string(akid) +
                                                 "/" + scope.text() +
                                                 ", SignedHeaders=content-type;host;x-amz-date" +
                                                 (is_json ? ";x-amz-target" : "") +
                                                 ", Signature=" + std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r._method, r._path, r._query, r._headers, r._body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r._headers.back().second.replace(r._headers.back().second.size() - 64, 64, sig);
    return r;
}

struct reply {
    unsigned status = 0;
    json::object body;

    [[nodiscard]] auto type() const -> std::string {
        const auto* t = body.if_contains("__type");
        return t != nullptr ? std::string(t->as_string()) : std::string();
    }
    [[nodiscard]] auto str(std::string_view k) const -> std::string {
        return std::string(body.at(k).as_string());
    }
};

struct fixture {
    std::uint64_t now = 1'800'000'000'000;
    sqs::local_queue_cluster cluster{[this] { return now; }};
    az::static_key_authorizer auth{std::vector<az::static_key>{
                                       {"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                        "admin", az::static_role::admin},
                                   },
                                   "aws",
                                   [] { return std::chrono::system_clock::time_point(k_now); }};
    std::unique_ptr<sqs::sqs_front_end<az::static_key_authorizer>> fe;
    std::unique_ptr<sqs::sqs_service<sqs::local_queue_cluster>> service;

    fixture() {
        auth.register_service(sqs::sqs_static_roles());
        fe = std::make_unique<sqs::sqs_front_end<az::static_key_authorizer>>(
            sqs::sqs_front_end_config{}, auth);
        sqs::sqs_service_config cfg;
        cfg._receipt_keys = sqs::derived_receipt_key("forwarding-secret");
        service = std::make_unique<sqs::sqs_service<sqs::local_queue_cluster>>(cluster, cfg);
        service->register_with(*fe);
    }

    auto call(std::string_view op, const json::object& in) -> reply {
        sqs::sqs_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(in);
        r._source_ip = "192.0.2.10";
        r._headers = {{"Host", "localhost:9324"},
                      {"Content-Type", "application/x-amz-json-1.0"},
                      {"X-Amz-Date", "20261118T120000Z"},
                      {"X-Amz-Target", "AmazonSQS." + std::string(op)}};
        const auto out = fe->handle(sign(std::move(r), "AKIDADMIN"));
        reply rep;
        rep.status = static_cast<unsigned>(out.status);
        rep.body = out.body.empty() ? json::object{} : json::parse(out.body).as_object();
        return rep;
    }

    auto query(std::string form) -> aj::http_response {
        sqs::sqs_request r;
        r._method = "POST";
        r._path = "/";
        r._body = std::move(form);
        r._headers = {{"Host", "localhost:9324"},
                      {"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
                      {"X-Amz-Date", "20261118T120000Z"}};
        return fe->handle(sign(std::move(r), "AKIDADMIN"));
    }

    auto create(const std::string& name, json::object attrs = {}) -> std::string {
        json::object in{{"QueueName", name}};
        if (!attrs.empty()) {
            in["Attributes"] = std::move(attrs);
        }
        const auto r = call("CreateQueue", in);
        BOOST_REQUIRE_MESSAGE(r.status == 200, json::serialize(r.body));
        return r.str("QueueUrl");
    }

    auto send(const std::string& url, const std::string& body, json::object extra = {}) -> reply {
        extra["QueueUrl"] = url;
        extra["MessageBody"] = body;
        return call("SendMessage", extra);
    }

    auto receive(const std::string& url, int max = 10, json::object extra = {}) -> json::array {
        extra["QueueUrl"] = url;
        extra["MaxNumberOfMessages"] = max;
        const auto r = call("ReceiveMessage", extra);
        BOOST_REQUIRE_MESSAGE(r.status == 200, json::serialize(r.body));
        const auto* m = r.body.if_contains("Messages");
        return m != nullptr ? m->as_array() : json::array{};
    }

    auto attributes(const std::string& url) -> json::object {
        const auto r =
            call("GetQueueAttributes", {{"QueueUrl", url}, {"AttributeNames", json::array{"All"}}});
        BOOST_REQUIRE_MESSAGE(r.status == 200, json::serialize(r.body));
        return r.body.at("Attributes").as_object();
    }
};

auto field(const json::value& m, std::string_view k) -> std::string {
    return std::string(m.as_object().at(k).as_string());
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(queues_are_created_found_listed_and_deleted, fixture) {
    const auto url = create("orders");
    BOOST_TEST(url == "http://localhost:9324/111122223333/orders");
    // Identical attributes: the same URL; others: QueueNameExists.
    BOOST_TEST(create("orders") == url);
    auto clash = call("CreateQueue",
                      {{"QueueName", "orders"}, {"Attributes", {{"VisibilityTimeout", "60"}}}});
    BOOST_TEST(clash.status == 400U);
    BOOST_TEST(clash.type() == "com.amazonaws.sqs#QueueNameExists");

    BOOST_TEST(call("GetQueueUrl", {{"QueueName", "orders"}}).str("QueueUrl") == url);
    BOOST_TEST(call("GetQueueUrl", {{"QueueName", "nope"}}).type() ==
               "com.amazonaws.sqs#QueueDoesNotExist");

    create("orders-2");
    create("billing");
    const auto all = call("ListQueues", {});
    BOOST_TEST(all.body.at("QueueUrls").as_array().size() == 3U);
    BOOST_TEST(!all.body.contains("NextToken"));
    const auto page = call("ListQueues", {{"QueueNamePrefix", "orders"}, {"MaxResults", 1}});
    BOOST_TEST(page.body.at("QueueUrls").as_array().size() == 1U);
    const auto next = call(
        "ListQueues",
        {{"QueueNamePrefix", "orders"}, {"MaxResults", 1}, {"NextToken", page.str("NextToken")}});
    BOOST_TEST(next.body.at("QueueUrls").as_array().at(0).as_string() ==
               "http://localhost:9324/111122223333/orders-2");
    BOOST_TEST(!next.body.contains("NextToken"));
    BOOST_TEST(call("ListQueues", {{"MaxResults", 0}}).type() ==
               "com.amazon.coral.validate#ValidationException");

    // A deleted queue's name waits out the cooldown, then comes back empty
    // under a new id: an old receipt handle no longer opens.
    BOOST_TEST(send(url, "old").status == 200U);
    const auto old = receive(url);
    BOOST_REQUIRE(old.size() == 1U);
    BOOST_TEST(call("DeleteQueue", {{"QueueUrl", url}}).status == 200U);
    BOOST_TEST(call("DeleteQueue", {{"QueueUrl", url}}).type() ==
               "com.amazonaws.sqs#QueueDoesNotExist");
    BOOST_TEST(call("CreateQueue", {{"QueueName", "orders"}}).type() ==
               "com.amazonaws.sqs#QueueDeletedRecently");
    now += 60'000;
    BOOST_TEST(create("orders") == url);
    BOOST_TEST(receive(url).empty());
    BOOST_TEST(call("DeleteMessage",
                    {{"QueueUrl", url}, {"ReceiptHandle", field(old.at(0), "ReceiptHandle")}})
                   .type() == "com.amazonaws.sqs#ReceiptHandleIsInvalid");
}

BOOST_FIXTURE_TEST_CASE(create_checks_names_and_attributes, fixture) {
    BOOST_TEST(call("CreateQueue", {{"QueueName", "bad name"}}).type() ==
               "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(
        call("CreateQueue", {{"QueueName", "plain"}, {"Attributes", {{"FifoQueue", "true"}}}})
            .type() == "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(call("CreateQueue", {{"QueueName", "orders"},
                                    {"Attributes", {{"ContentBasedDeduplication", "true"}}}})
                   .type() == "com.amazonaws.sqs#InvalidAttributeName");
    BOOST_TEST(
        call("CreateQueue", {{"QueueName", "orders"}, {"Attributes", {{"DelaySeconds", "901"}}}})
            .type() == "com.amazonaws.sqs#InvalidAttributeValue");
    // A redrive target must exist and be of the same kind.
    const auto policy = std::string(R"({"deadLetterTargetArn":"arn:aws:sqs:us-east-1:)") +
                        std::string(k_account) + R"(:dlq","maxReceiveCount":"3"})";
    BOOST_TEST(
        call("CreateQueue", {{"QueueName", "orders"}, {"Attributes", {{"RedrivePolicy", policy}}}})
            .type() == "com.amazon.coral.validate#ValidationException");
    create("dlq");
    create("orders", {{"RedrivePolicy", policy}});
    BOOST_TEST(
        call("CreateQueue", {{"QueueName", "orders.fifo"},
                             {"Attributes", {{"FifoQueue", "true"}, {"RedrivePolicy", policy}}}})
            .type() == "com.amazon.coral.validate#ValidationException");
}

BOOST_FIXTURE_TEST_CASE(attributes_counts_permissions_tags_and_purge, fixture) {
    const auto url = create("orders", {{"VisibilityTimeout", "45"}});
    send(url, "a");
    send(url, "b");
    send(url, "c", {{"DelaySeconds", 30}});
    BOOST_REQUIRE(receive(url, 1).size() == 1U);
    auto a = attributes(url);
    BOOST_TEST(a.at("VisibilityTimeout").as_string() == "45");
    BOOST_TEST(a.at("ApproximateNumberOfMessages").as_string() == "1");
    BOOST_TEST(a.at("ApproximateNumberOfMessagesNotVisible").as_string() == "1");
    BOOST_TEST(a.at("ApproximateNumberOfMessagesDelayed").as_string() == "1");
    BOOST_TEST(a.at("QueueArn").as_string() == "arn:aws:sqs:us-east-1:111122223333:orders");
    BOOST_TEST(a.at("CreatedTimestamp").as_string() == "1800000000");

    now += 5'000;
    BOOST_TEST(
        call("SetQueueAttributes", {{"QueueUrl", url}, {"Attributes", {{"DelaySeconds", "5"}}}})
            .status == 200U);
    a = attributes(url);
    BOOST_TEST(a.at("DelaySeconds").as_string() == "5");
    BOOST_TEST(a.at("LastModifiedTimestamp").as_string() == "1800000005");
    BOOST_TEST(call("SetQueueAttributes",
                    {{"QueueUrl", url}, {"Attributes", {{"ApproximateNumberOfMessages", "5"}}}})
                   .type() == "com.amazonaws.sqs#InvalidAttributeName");

    BOOST_TEST(call("AddPermission", {{"QueueUrl", url},
                                      {"Label", "share"},
                                      {"AWSAccountIds", json::array{"444455556666"}},
                                      {"Actions", json::array{"SendMessage"}}})
                   .status == 200U);
    a = attributes(url);
    BOOST_TEST(a.at("Policy").as_string().find("\"Sid\":\"share\"") != std::string::npos);
    BOOST_TEST(call("AddPermission", {{"QueueUrl", url},
                                      {"Label", "share"},
                                      {"AWSAccountIds", json::array{"444455556666"}},
                                      {"Actions", json::array{"SendMessage"}}})
                   .type() == "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(call("RemovePermission", {{"QueueUrl", url}, {"Label", "share"}}).status == 200U);
    BOOST_TEST(!attributes(url).contains("Policy"));

    BOOST_TEST(
        call("TagQueue", {{"QueueUrl", url}, {"Tags", {{"team", "a"}, {"env", "prod"}}}}).status ==
        200U);
    BOOST_TEST(call("UntagQueue", {{"QueueUrl", url}, {"TagKeys", json::array{"env"}}}).status ==
               200U);
    const auto tags = call("ListQueueTags", {{"QueueUrl", url}});
    BOOST_TEST(json::serialize(tags.body.at("Tags")) == R"({"team":"a"})");

    BOOST_TEST(call("PurgeQueue", {{"QueueUrl", url}}).status == 200U);
    BOOST_TEST(call("PurgeQueue", {{"QueueUrl", url}}).type() ==
               "com.amazonaws.sqs#PurgeQueueInProgress");
    a = attributes(url);
    BOOST_TEST(a.at("ApproximateNumberOfMessages").as_string() == "0");
    BOOST_TEST(a.at("ApproximateNumberOfMessagesNotVisible").as_string() == "0");
    BOOST_TEST(a.at("ApproximateNumberOfMessagesDelayed").as_string() == "0");
    now += 60'000;
    BOOST_TEST(call("PurgeQueue", {{"QueueUrl", url}}).status == 200U);
}

BOOST_FIXTURE_TEST_CASE(messages_are_sent_received_and_deleted, fixture) {
    const auto url = create("orders");
    const json::object attrs{{"color", {{"DataType", "String"}, {"StringValue", "blue"}}}};
    const auto sent = send(url, "hello", {{"MessageAttributes", attrs}});
    BOOST_TEST(sent.status == 200U);
    BOOST_TEST(sent.str("MD5OfMessageBody") == sqs::md5_hex("hello"));
    BOOST_TEST(sent.str("MD5OfMessageAttributes") == "da1b33cc3cbfe8b1630921e78e6b9880");
    BOOST_TEST(sent.str("MessageId").size() == 36U);
    BOOST_TEST(!sent.body.contains("SequenceNumber"));

    const auto got = receive(url, 10,
                             {{"MessageAttributeNames", json::array{"All"}},
                              {"MessageSystemAttributeNames", json::array{"All"}}});
    BOOST_REQUIRE(got.size() == 1U);
    const auto& m = got.at(0).as_object();
    BOOST_TEST(field(m, "MessageId") == sent.str("MessageId"));
    BOOST_TEST(field(m, "Body") == "hello");
    BOOST_TEST(field(m, "MD5OfBody") == sqs::md5_hex("hello"));
    BOOST_TEST(field(m, "MD5OfMessageAttributes") == "da1b33cc3cbfe8b1630921e78e6b9880");
    BOOST_TEST(field(m, "ReceiptHandle").size() == 96U);
    const auto& sys = m.at("Attributes").as_object();
    BOOST_TEST(sys.at("ApproximateReceiveCount").as_string() == "1");
    BOOST_TEST(sys.at("SentTimestamp").as_string() == std::to_string(now));
    BOOST_TEST(!sys.at("SenderId").as_string().empty());

    // In flight: nothing more to receive. The delete takes, a second one
    // with the same handle is accepted and does nothing.
    BOOST_TEST(receive(url).empty());
    const auto handle = field(m, "ReceiptHandle");
    BOOST_TEST(call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", handle}}).status ==
               200U);
    BOOST_TEST(call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", handle}}).status ==
               200U);
    BOOST_TEST(call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", "garbage"}}).type() ==
               "com.amazonaws.sqs#ReceiptHandleIsInvalid");
    now += 31'000;
    BOOST_TEST(receive(url).empty());

    // Errors of a send.
    BOOST_TEST(call("SendMessage", {{"QueueUrl", url}, {"MessageBody", ""}}).type() ==
               "com.amazonaws.sqs#MissingParameter");
    BOOST_TEST(send(url, std::string("bad\x01", 4)).type() ==
               "com.amazonaws.sqs#InvalidMessageContents");
    BOOST_TEST(send(url, "x", {{"DelaySeconds", 901}}).type() ==
               "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(send(url, "x", {{"MessageDeduplicationId", "d"}}).type() ==
               "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(send(url, std::string(1048577, 'x')).type() ==
               "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(call("SendMessage",
                    {{"QueueUrl", "http://localhost:9324/111122223333/nope"}, {"MessageBody", "x"}})
                   .type() == "com.amazonaws.sqs#QueueDoesNotExist");
}

BOOST_FIXTURE_TEST_CASE(a_handle_is_good_only_for_its_receive, fixture) {
    const auto url = create("orders", {{"VisibilityTimeout", "10"}});
    send(url, "m");
    const auto first = receive(url);
    BOOST_REQUIRE(first.size() == 1U);
    now += 10'000;  // the timeout ends: the message comes back
    const auto second =
        receive(url, 10, {{"AttributeNames", json::array{"ApproximateReceiveCount"}}});
    BOOST_REQUIRE(second.size() == 1U);
    BOOST_TEST(second.at(0)
                   .as_object()
                   .at("Attributes")
                   .as_object()
                   .at("ApproximateReceiveCount")
                   .as_string() == "2");

    // The first handle's delete is accepted and ignored; its visibility
    // change is refused.
    const auto old = field(first.at(0), "ReceiptHandle");
    BOOST_TEST(call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", old}}).status == 200U);
    BOOST_TEST(call("ChangeMessageVisibility",
                    {{"QueueUrl", url}, {"ReceiptHandle", old}, {"VisibilityTimeout", 0}})
                   .type() == "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(attributes(url).at("ApproximateNumberOfMessagesNotVisible").as_string() == "1");

    // The current handle can make it visible at once.
    const auto cur = field(second.at(0), "ReceiptHandle");
    BOOST_TEST(call("ChangeMessageVisibility",
                    {{"QueueUrl", url}, {"ReceiptHandle", cur}, {"VisibilityTimeout", 0}})
                   .status == 200U);
    BOOST_TEST(call("ChangeMessageVisibility",
                    {{"QueueUrl", url}, {"ReceiptHandle", cur}, {"VisibilityTimeout", 43201}})
                   .type() == "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(call("ChangeMessageVisibility",
                    {{"QueueUrl", url}, {"ReceiptHandle", cur}, {"VisibilityTimeout", 30}})
                   .type() == "com.amazonaws.sqs#MessageNotInflight");
    BOOST_TEST(receive(url).size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(delays_hold_messages_back, fixture) {
    const auto url = create("orders", {{"DelaySeconds", "20"}});
    send(url, "queue-delay");
    send(url, "own-delay", {{"DelaySeconds", 0}});
    auto got = receive(url);
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got.at(0), "Body") == "own-delay");
    now += 20'000;
    got = receive(url);
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got.at(0), "Body") == "queue-delay");
}

BOOST_FIXTURE_TEST_CASE(batches_answer_per_entry, fixture) {
    const auto url = create("orders");
    const auto r = call("SendMessageBatch",
                        {{"QueueUrl", url},
                         {"Entries", json::array{{{"Id", "a"}, {"MessageBody", "one"}},
                                                 {{"Id", "b"}, {"MessageBody", ""}},
                                                 {{"Id", "c"}, {"MessageBody", "three"}}}}});
    BOOST_REQUIRE(r.status == 200U);
    BOOST_TEST(r.body.at("Successful").as_array().size() == 2U);
    const auto& failed = r.body.at("Failed").as_array();
    BOOST_REQUIRE(failed.size() == 1U);
    BOOST_TEST(field(failed.at(0), "Id") == "b");
    BOOST_TEST(field(failed.at(0), "Code") == "MissingParameter");
    BOOST_TEST(failed.at(0).as_object().at("SenderFault").as_bool());

    const auto got = receive(url);
    BOOST_REQUIRE(got.size() == 2U);
    json::array entries;
    entries.push_back({{"Id", "x"}, {"ReceiptHandle", field(got.at(0), "ReceiptHandle")}});
    entries.push_back({{"Id", "y"}, {"ReceiptHandle", "garbage"}});
    entries.push_back({{"Id", "z"}, {"ReceiptHandle", field(got.at(1), "ReceiptHandle")}});
    const auto d = call("DeleteMessageBatch", {{"QueueUrl", url}, {"Entries", entries}});
    BOOST_TEST(d.body.at("Successful").as_array().size() == 2U);
    BOOST_TEST(field(d.body.at("Failed").as_array().at(0), "Code") == "ReceiptHandleIsInvalid");
    BOOST_TEST(attributes(url).at("ApproximateNumberOfMessagesNotVisible").as_string() == "0");

    // Request-level errors.
    BOOST_TEST(call("DeleteMessageBatch", {{"QueueUrl", url}, {"Entries", json::array{}}}).type() ==
               "com.amazonaws.sqs#EmptyBatchRequest");
    json::array many;
    for (int i = 0; i < 11; ++i) {
        many.push_back({{"Id", "e" + std::to_string(i)}, {"MessageBody", "x"}});
    }
    BOOST_TEST(call("SendMessageBatch", {{"QueueUrl", url}, {"Entries", many}}).type() ==
               "com.amazonaws.sqs#TooManyEntriesInBatchRequest");
    BOOST_TEST(
        call("SendMessageBatch", {{"QueueUrl", url},
                                  {"Entries", json::array{{{"Id", "a"}, {"MessageBody", "1"}},
                                                          {{"Id", "a"}, {"MessageBody", "2"}}}}})
            .type() == "com.amazonaws.sqs#BatchEntryIdsNotDistinct");
    BOOST_TEST(
        call("SendMessageBatch",
             {{"QueueUrl", url}, {"Entries", json::array{{{"Id", "a b"}, {"MessageBody", "1"}}}}})
            .type() == "com.amazonaws.sqs#InvalidBatchEntryId");
    json::array big;
    for (int i = 0; i < 3; ++i) {
        big.push_back(
            {{"Id", "e" + std::to_string(i)}, {"MessageBody", std::string(400'000, 'x')}});
    }
    BOOST_TEST(call("SendMessageBatch", {{"QueueUrl", url}, {"Entries", big}}).type() ==
               "com.amazonaws.sqs#BatchRequestTooLong");

    // Visibility batch.
    send(url, "v");
    const auto v = receive(url);
    BOOST_REQUIRE(v.size() == 1U);
    const auto cv =
        call("ChangeMessageVisibilityBatch",
             {{"QueueUrl", url},
              {"Entries", json::array{{{"Id", "k"},
                                       {"ReceiptHandle", field(v.at(0), "ReceiptHandle")},
                                       {"VisibilityTimeout", 0}}}}});
    BOOST_TEST(cv.body.at("Successful").as_array().size() == 1U);
    BOOST_TEST(receive(url).size() == 1U);
}

BOOST_FIXTURE_TEST_CASE(fifo_queues_keep_group_order_and_deduplicate, fixture) {
    const auto url = create("orders.fifo", {{"FifoQueue", "true"}});
    BOOST_TEST(send(url, "x").type() == "com.amazonaws.sqs#MissingParameter");
    BOOST_TEST(send(url, "x", {{"MessageGroupId", "g"}}).type() ==
               "com.amazon.coral.validate#ValidationException");
    BOOST_TEST(send(url, "x", {{"MessageGroupId", "g"}, {"DelaySeconds", 1}}).type() ==
               "com.amazon.coral.validate#ValidationException");

    const auto a = send(url, "a1", {{"MessageGroupId", "a"}, {"MessageDeduplicationId", "1"}});
    const auto dup = send(url, "a1", {{"MessageGroupId", "a"}, {"MessageDeduplicationId", "1"}});
    BOOST_TEST(dup.str("MessageId") == a.str("MessageId"));
    BOOST_TEST(dup.str("SequenceNumber") == a.str("SequenceNumber"));
    BOOST_TEST(a.str("SequenceNumber").size() == 20U);
    const auto a2 = send(url, "a2", {{"MessageGroupId", "a"}, {"MessageDeduplicationId", "2"}});
    BOOST_TEST(a2.str("SequenceNumber") > a.str("SequenceNumber"));
    send(url, "b1", {{"MessageGroupId", "b"}, {"MessageDeduplicationId", "3"}});

    // A receive takes a group's visible messages in order; a group whose
    // first message is in flight hands out nothing more until it is gone.
    auto got = receive(url, 1, {{"AttributeNames", json::array{"All"}}});
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got.at(0), "Body") == "a1");
    const auto& sys = got.at(0).as_object().at("Attributes").as_object();
    BOOST_TEST(sys.at("MessageGroupId").as_string() == "a");
    BOOST_TEST(sys.at("MessageDeduplicationId").as_string() == "1");
    BOOST_TEST(sys.at("SequenceNumber").as_string() == a.str("SequenceNumber"));
    const auto a1_handle = field(got.at(0), "ReceiptHandle");
    got = receive(url, 1);
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got.at(0), "Body") == "b1");
    BOOST_TEST(receive(url).empty());
    call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", a1_handle}});
    got = receive(url);
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got.at(0), "Body") == "a2");

    // Content-based deduplication hashes the body.
    const auto cb =
        create("cb.fifo", {{"FifoQueue", "true"}, {"ContentBasedDeduplication", "true"}});
    const auto c1 = send(cb, "same", {{"MessageGroupId", "g"}});
    const auto c2 = send(cb, "same", {{"MessageGroupId", "g"}});
    BOOST_TEST(c1.str("MessageId") == c2.str("MessageId"));
    now += 5 * 60'000;  // the window ends
    BOOST_TEST(send(cb, "same", {{"MessageGroupId", "g"}}).str("MessageId") != c1.str("MessageId"));
}

BOOST_FIXTURE_TEST_CASE(standard_queues_spread_over_partitions, fixture) {
    const auto url = create("orders");
    for (int i = 0; i < 12; ++i) {
        BOOST_REQUIRE(send(url, "m" + std::to_string(i)).status == 200U);
    }
    std::set<std::string> seen;
    for (int round = 0; round < 3; ++round) {
        for (const auto& m : receive(url)) {
            seen.insert(field(m, "Body"));
        }
    }
    BOOST_TEST(seen.size() == 12U);
    const auto q = service->find(k_account, "orders");
    BOOST_REQUIRE(q.has_value());
    BOOST_TEST(q->_partitions == 4U);
}

BOOST_FIXTURE_TEST_CASE(the_query_protocol_gets_xml_answers, fixture) {
    create("orders");
    const auto sent = query(
        "Action=SendMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2Flocalhost%3A9324%2F"
        "111122223333%2Forders&MessageBody=hi");
    BOOST_TEST(sent.status == 200U);
    BOOST_TEST(sent.body.find("<MD5OfMessageBody>" + sqs::md5_hex("hi") + "</MD5OfMessageBody>") !=
               std::string::npos);
    const auto got = query(
        "Action=ReceiveMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2Flocalhost%3A9324%2F"
        "111122223333%2Forders");
    BOOST_TEST(got.body.find("<Body>hi</Body>") != std::string::npos);
    const auto missing = query("Action=GetQueueUrl&Version=2012-11-05&QueueName=nope");
    BOOST_TEST(missing.status == 400U);
    BOOST_TEST(missing.body.find("<Code>AWS.SimpleQueueService.NonExistentQueue</Code>") !=
               std::string::npos);
}
