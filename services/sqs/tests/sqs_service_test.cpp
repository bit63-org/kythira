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
#include <kythira/sqs/sqs_sns_bridge.hpp>
#include <kythira/sqs/sqs_sse.hpp>
#include <kythira/sqs/sqs_workers.hpp>

#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <span>
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

/// SSE-KMS for tests: wraps like a real provider, but key ids under
/// `alias/denied` are refused as a key policy would.
struct test_kms {
    sqs::wrapping_provider wrap{sqs::derived_key("test-kms", "master")};
    auto generate_data_key(const std::string& id, const sqs::encryption_context& c)
        -> sqs::generated_data_key {
        refuse(id);
        auto k = wrap.generate_data_key(id, c);
        k._key_id = "arn:aws:kms:us-east-1:111122223333:key/" + id.substr(id.rfind('/') + 1);
        return k;
    }
    auto decrypt_data_key(const std::string& id, const std::string& w,
                          const sqs::encryption_context& c) -> sqs::data_key_bytes {
        refuse(id);
        return wrap.decrypt_data_key(id, w, c);
    }
    static void refuse(const std::string& id) {
        if (id.starts_with("alias/denied")) {
            throw sqs::kms_error(sqs::kms_failure::access_denied, "denied by key policy");
        }
    }
};

struct fixture {
    std::uint64_t now = 1'800'000'000'000;
    std::shared_ptr<sqs::sse_keys> sse = std::make_shared<sqs::sse_keys>(
        sqs::key_provider(sqs::wrapping_provider(sqs::derived_key("cluster", "sse"))),
        sqs::key_provider(test_kms{}));
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
        cfg._sse = sse;
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

    // The first handle's delete and visibility change are accepted and
    // ignored, as SQS accepts them (task 13's recordings).
    const auto old = field(first.at(0), "ReceiptHandle");
    BOOST_TEST(call("DeleteMessage", {{"QueueUrl", url}, {"ReceiptHandle", old}}).status == 200U);
    BOOST_TEST(call("ChangeMessageVisibility",
                    {{"QueueUrl", url}, {"ReceiptHandle", old}, {"VisibilityTimeout", 0}})
                   .status == 200U);
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

// -- task 6: dead-letter queues ---------------------------------------------------

namespace {

auto redrive_to(std::string_view dlq, int count) -> std::string {
    return std::string(R"({"deadLetterTargetArn":"arn:aws:sqs:us-east-1:)") +
           std::string(k_account) + ":" + std::string(dlq) + R"(","maxReceiveCount":)" +
           std::to_string(count) + "}";
}

auto arn_of(std::string_view name) -> std::string {
    return "arn:aws:sqs:us-east-1:" + std::string(k_account) + ":" + std::string(name);
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(a_message_received_too_often_moves_to_its_dead_letter_queue, fixture) {
    const auto dlq = create("orders-dlq");
    const auto url = create("orders", {{"RedrivePolicy", redrive_to("orders-dlq", 2)}});
    const auto sent = send(url, "poison");
    BOOST_TEST_REQUIRE(sent.status == 200U);
    const auto id = sent.str("MessageId");
    // Received twice (maxReceiveCount), each time left to time out.
    for (int i = 0; i < 2; ++i) {
        const auto got = receive(url, 10, {{"VisibilityTimeout", 1}});
        BOOST_TEST_REQUIRE(got.size() == 1U);
        BOOST_TEST(field(got[0], "MessageId") == id);
        now += 1500;
    }
    // The third receive moves it instead of delivering it: in one queue only.
    BOOST_TEST(receive(url).empty());
    BOOST_TEST(attributes(url).at("ApproximateNumberOfMessages").as_string() == "0");
    BOOST_TEST(attributes(url).at("ApproximateNumberOfMessagesNotVisible").as_string() == "0");
    const auto moved = receive(dlq, 10, {{"MessageSystemAttributeNames", json::array{"All"}}});
    BOOST_TEST_REQUIRE(moved.size() == 1U);
    BOOST_TEST(field(moved[0], "MessageId") == id);
    BOOST_TEST(field(moved[0], "Body") == "poison");
    const auto& attrs = moved[0].at("Attributes").as_object();
    BOOST_TEST(attrs.at("DeadLetterQueueSourceArn").as_string() == arn_of("orders"));
    BOOST_TEST(attrs.at("ApproximateReceiveCount").as_string() == "1");
}

BOOST_FIXTURE_TEST_CASE(a_fifo_group_keeps_its_order_into_its_dead_letter_queue, fixture) {
    const auto dlq = create("jobs-dlq.fifo", {{"FifoQueue", "true"}});
    const auto url = create("jobs.fifo", {{"FifoQueue", "true"},
                                          {"ContentBasedDeduplication", "true"},
                                          {"RedrivePolicy", redrive_to("jobs-dlq.fifo", 1)}});
    for (const auto* b : {"first", "second"}) {
        BOOST_TEST_REQUIRE(send(url, b, {{"MessageGroupId", "g"}}).status == 200U);
    }
    // Both delivered once, then left to time out.
    BOOST_TEST_REQUIRE(receive(url, 10, {{"VisibilityTimeout", 1}}).size() == 2U);
    now += 1500;
    BOOST_TEST(receive(url).empty());
    const auto moved = receive(dlq, 10, {{"MessageSystemAttributeNames", json::array{"All"}}});
    BOOST_TEST_REQUIRE(moved.size() == 2U);
    BOOST_TEST(field(moved[0], "Body") == "first");
    BOOST_TEST(field(moved[1], "Body") == "second");
    BOOST_TEST(moved[0].at("Attributes").at("MessageGroupId").as_string() == "g");
}

BOOST_FIXTURE_TEST_CASE(redrive_allow_policies_are_enforced, fixture) {
    create("closed", {{"RedriveAllowPolicy", R"({"redrivePermission":"denyAll"})"}});
    create("picky",
           {{"RedriveAllowPolicy", R"({"redrivePermission":"byQueue","sourceQueueArns":[")" +
                                       arn_of("chosen") + R"("]})"}});
    BOOST_TEST(call("CreateQueue", {{"QueueName", "a"},
                                    {"Attributes", {{"RedrivePolicy", redrive_to("closed", 3)}}}})
                   .status == 400U);
    BOOST_TEST(call("CreateQueue", {{"QueueName", "other"},
                                    {"Attributes", {{"RedrivePolicy", redrive_to("picky", 3)}}}})
                   .status == 400U);
    create("chosen", {{"RedrivePolicy", redrive_to("picky", 3)}});
    const auto plain = create("plain");
    const auto r =
        call("SetQueueAttributes",
             {{"QueueUrl", plain}, {"Attributes", {{"RedrivePolicy", redrive_to("closed", 3)}}}});
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.type() == "com.amazon.coral.validate#ValidationException");
}

BOOST_FIXTURE_TEST_CASE(dead_letter_source_queues_are_listed_and_paged, fixture) {
    const auto dlq = create("dlq");
    create("unrelated");
    for (const auto* n : {"c-src", "a-src", "b-src"}) {
        create(n, {{"RedrivePolicy", redrive_to("dlq", 5)}});
    }
    auto r = call("ListDeadLetterSourceQueues", {{"QueueUrl", dlq}});
    BOOST_TEST_REQUIRE(r.status == 200U);
    const auto& all = r.body.at("queueUrls").as_array();
    BOOST_TEST_REQUIRE(all.size() == 3U);
    BOOST_TEST(all[0].as_string() == "http://localhost:9324/111122223333/a-src");
    BOOST_TEST(all[2].as_string() == "http://localhost:9324/111122223333/c-src");
    BOOST_TEST(!r.body.contains("NextToken"));
    r = call("ListDeadLetterSourceQueues", {{"QueueUrl", dlq}, {"MaxResults", 2}});
    BOOST_TEST_REQUIRE(r.body.at("queueUrls").as_array().size() == 2U);
    const auto token = r.str("NextToken");
    r = call("ListDeadLetterSourceQueues",
             {{"QueueUrl", dlq}, {"MaxResults", 2}, {"NextToken", token}});
    BOOST_TEST_REQUIRE(r.body.at("queueUrls").as_array().size() == 1U);
    BOOST_TEST(r.body.at("queueUrls").as_array()[0].as_string() ==
               "http://localhost:9324/111122223333/c-src");
    BOOST_TEST(!r.body.contains("NextToken"));
    // A queue nothing redrives to: an empty list, still present.
    r = call("ListDeadLetterSourceQueues",
             {{"QueueUrl", "http://localhost:9324/111122223333/unrelated"}});
    BOOST_TEST(r.body.at("queueUrls").as_array().empty());
}

// -- task 6: message move tasks ---------------------------------------------------

namespace {

struct mover : fixture {
    sqs::move_worker<sqs::local_queue_cluster> worker{
        cluster, [](const std::string&) { return true; }, sqs::sqs_arn_queue};

    /// Sends `body` to `url` and lets one receive (maxReceiveCount 1) and
    /// the next move it to the dead-letter queue.
    void dead_letter(const std::string& url, const std::string& body) {
        BOOST_TEST_REQUIRE(send(url, body).status == 200U);
        BOOST_TEST_REQUIRE(receive(url, 10, {{"VisibilityTimeout", 1}}).size() == 1U);
        now += 1500;
        BOOST_TEST_REQUIRE(receive(url).empty());
    }

    auto tasks(const std::string& source, int max = 10) -> json::array {
        const auto r =
            call("ListMessageMoveTasks", {{"SourceArn", arn_of(source)}, {"MaxResults", max}});
        BOOST_REQUIRE_MESSAGE(r.status == 200, json::serialize(r.body));
        return r.body.at("Results").as_array();
    }

    auto bodies(const std::string& url) -> std::vector<std::string> {
        std::vector<std::string> out;
        for (const auto& m : receive(url)) {
            out.push_back(field(m, "Body"));
        }
        std::sort(out.begin(), out.end());
        return out;
    }
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(a_move_task_redrives_each_message_to_its_source, mover) {
    const auto dlq = create("dlq");
    const auto a = create("a", {{"RedrivePolicy", redrive_to("dlq", 1)}});
    const auto b = create("b", {{"RedrivePolicy", redrive_to("dlq", 1)}});
    dead_letter(a, "for-a");
    dead_letter(b, "for-b");
    BOOST_TEST(attributes(dlq).at("ApproximateNumberOfMessages").as_string() == "2");

    // Only a dead-letter queue is a source; destinations must exist.
    auto r = call("StartMessageMoveTask", {{"SourceArn", arn_of("a")}});
    BOOST_TEST(r.status == 400U);
    r = call("StartMessageMoveTask", {{"SourceArn", arn_of("nope")}});
    BOOST_TEST(r.type() == "com.amazonaws.sqs#ResourceNotFoundException");
    r = call("StartMessageMoveTask",
             {{"SourceArn", arn_of("dlq")}, {"DestinationArn", arn_of("nope")}});
    BOOST_TEST(r.type() == "com.amazonaws.sqs#ResourceNotFoundException");
    r = call("StartMessageMoveTask",
             {{"SourceArn", arn_of("dlq")}, {"MaxNumberOfMessagesPerSecond", 501}});
    BOOST_TEST(r.status == 400U);

    r = call("StartMessageMoveTask", {{"SourceArn", arn_of("dlq")}});
    BOOST_TEST_REQUIRE(r.status == 200U);
    BOOST_TEST(!r.str("TaskHandle").empty());
    // One active task per source.
    r = call("StartMessageMoveTask", {{"SourceArn", arn_of("dlq")}});
    BOOST_TEST(r.type() == "com.amazonaws.sqs#UnsupportedOperation");
    auto listed = tasks("dlq");
    BOOST_TEST_REQUIRE(listed.size() == 1U);
    BOOST_TEST(listed[0].at("Status").as_string() == "RUNNING");
    BOOST_TEST(listed[0].as_object().contains("TaskHandle"));
    BOOST_TEST(listed[0].at("ApproximateNumberOfMessagesToMove").as_int64() == 2);

    BOOST_TEST(!worker.run_once());
    BOOST_TEST(worker.moved() == 2U);
    BOOST_TEST(attributes(dlq).at("ApproximateNumberOfMessages").as_string() == "0");
    BOOST_TEST(bodies(a) == std::vector<std::string>{"for-a"});
    BOOST_TEST(bodies(b) == std::vector<std::string>{"for-b"});
    listed = tasks("dlq");
    BOOST_TEST_REQUIRE(listed.size() == 1U);
    BOOST_TEST(listed[0].at("Status").as_string() == "COMPLETED");
    BOOST_TEST(!listed[0].as_object().contains("TaskHandle"));
    BOOST_TEST(listed[0].at("ApproximateNumberOfMessagesMoved").as_int64() == 2);
    BOOST_TEST(listed[0].at("SourceArn").as_string() == arn_of("dlq"));
    // A new task may start once the last ended; the newest lists first.
    now += 10;
    BOOST_TEST(call("StartMessageMoveTask", {{"SourceArn", arn_of("dlq")}}).status == 200U);
    BOOST_TEST(tasks("dlq", 1).size() == 1U);
    BOOST_TEST(tasks("dlq").size() == 2U);
    BOOST_TEST(tasks("dlq")[0].at("Status").as_string() == "RUNNING");
}

BOOST_FIXTURE_TEST_CASE(a_move_task_keeps_its_rate_and_can_be_cancelled, mover) {
    const auto dlq = create("dlq");
    const auto src = create("src", {{"RedrivePolicy", redrive_to("dlq", 1)}});
    const auto dest = create("elsewhere");
    for (const auto* body : {"one", "two", "three"}) {
        dead_letter(src, body);
    }
    const auto r = call("StartMessageMoveTask", {{"SourceArn", arn_of("dlq")},
                                                 {"DestinationArn", arn_of("elsewhere")},
                                                 {"MaxNumberOfMessagesPerSecond", 1}});
    BOOST_TEST_REQUIRE(r.status == 200U);
    const auto handle = r.str("TaskHandle");
    // One message a second.
    BOOST_TEST(worker.run_once());
    BOOST_TEST(worker.moved() == 1U);
    BOOST_TEST(worker.run_once());
    BOOST_TEST(worker.moved() == 1U);
    now += 1000;
    BOOST_TEST(worker.run_once());
    BOOST_TEST(worker.moved() == 2U);
    const auto listed = tasks("dlq");
    BOOST_TEST(listed[0].at("DestinationArn").as_string() == arn_of("elsewhere"));
    BOOST_TEST(listed[0].at("MaxNumberOfMessagesPerSecond").as_int64() == 1);

    const auto c = call("CancelMessageMoveTask", {{"TaskHandle", handle}});
    BOOST_TEST_REQUIRE(c.status == 200U);
    BOOST_TEST(c.body.at("ApproximateNumberOfMessagesMoved").as_int64() == 2);
    // Cancelling, then cancelled by the worker; the last message stays.
    BOOST_TEST(tasks("dlq")[0].at("Status").as_string() == "CANCELLING");
    BOOST_TEST(!worker.run_once());
    BOOST_TEST(tasks("dlq")[0].at("Status").as_string() == "CANCELLED");
    BOOST_TEST(attributes(dlq).at("ApproximateNumberOfMessages").as_string() == "1");
    BOOST_TEST(bodies(dest).size() == 2U);
    // A task that is not running, or a handle that names none, is not found.
    BOOST_TEST(call("CancelMessageMoveTask", {{"TaskHandle", handle}}).type() ==
               "com.amazonaws.sqs#ResourceNotFoundException");
    BOOST_TEST(call("CancelMessageMoveTask", {{"TaskHandle", "bm90LWEtaGFuZGxl"}}).type() ==
               "com.amazonaws.sqs#ResourceNotFoundException");
}

BOOST_FIXTURE_TEST_CASE(a_move_task_fails_when_its_destination_is_gone, mover) {
    create("dlq");
    const auto src = create("src", {{"RedrivePolicy", redrive_to("dlq", 1)}});
    const auto dest = create("gone");
    dead_letter(src, "stuck");
    BOOST_TEST_REQUIRE(call("StartMessageMoveTask",
                            {{"SourceArn", arn_of("dlq")}, {"DestinationArn", arn_of("gone")}})
                           .status == 200U);
    BOOST_TEST_REQUIRE(call("DeleteQueue", {{"QueueUrl", dest}}).status == 200U);
    BOOST_TEST(!worker.run_once());
    const auto listed = tasks("dlq");
    BOOST_TEST(listed[0].at("Status").as_string() == "FAILED");
    BOOST_TEST(!listed[0].at("FailureReason").as_string().empty());
}

// -- task 7: encryption -----------------------------------------------------------

namespace {

/// The stored bodies of a queue's visible messages, as the replica holds them.
auto stored_bodies(fixture& f, const std::string& name) -> std::vector<std::string> {
    const auto q = f.service->find(k_account, name);
    BOOST_REQUIRE(q.has_value());
    std::vector<std::string> out;
    for (std::uint16_t p = 0; p < q->_partitions; ++p) {
        const auto t = q->target(p);
        (void)f.cluster.read(sqs::queue_keys::partition_prefix(t),
                             [&](const sqs::local_queue_cluster::state_machine_type& sm) {
                                 for (const auto& [seq, m] : sm.visible_messages(t, 100)) {
                                     out.push_back(m.body + m.attributes);
                                 }
                             });
    }
    return out;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(new_queues_hold_only_ciphertext, fixture) {
    const auto url = create("secret");
    BOOST_TEST(attributes(url).at("SqsManagedSseEnabled").as_string() == "true");
    const json::object attrs{{"colour", {{"DataType", "String"}, {"StringValue", "plum-red"}}}};
    const auto sent = send(url, "attack at dawn", {{"MessageAttributes", attrs}});
    BOOST_TEST_REQUIRE(sent.status == 200U);
    const auto stored = stored_bodies(*this, "secret");
    BOOST_TEST_REQUIRE(stored.size() == 1U);
    BOOST_TEST(sqs::is_sealed(stored[0]));
    BOOST_TEST(stored[0].find("attack at dawn") == std::string::npos);
    BOOST_TEST(stored[0].find("plum-red") == std::string::npos);
    // The client sees plaintext and digests over it.
    const auto got = receive(url, 10, {{"MessageAttributeNames", json::array{"All"}}});
    BOOST_TEST_REQUIRE(got.size() == 1U);
    BOOST_TEST(field(got[0], "Body") == "attack at dawn");
    BOOST_TEST(field(got[0], "MD5OfBody") == sent.str("MD5OfMessageBody"));
    BOOST_TEST(field(got[0], "MD5OfMessageAttributes") == sent.str("MD5OfMessageAttributes"));
    BOOST_TEST(got[0].at("MessageAttributes").at("colour").at("StringValue").as_string() ==
               "plum-red");
}

BOOST_FIXTURE_TEST_CASE(sse_can_be_off_and_changes_keep_messages_readable, fixture) {
    const auto url = create("plain", {{"SqsManagedSseEnabled", "false"}});
    BOOST_TEST_REQUIRE(send(url, "in the clear").status == 200U);
    BOOST_TEST(stored_bodies(*this, "plain") == std::vector<std::string>{"in the clear"});
    // Turned on, then to SSE-KMS: every message still opens.
    BOOST_TEST_REQUIRE(call("SetQueueAttributes",
                            {{"QueueUrl", url}, {"Attributes", {{"SqsManagedSseEnabled", "true"}}}})
                           .status == 200U);
    BOOST_TEST_REQUIRE(send(url, "managed").status == 200U);
    BOOST_TEST_REQUIRE(call("SetQueueAttributes",
                            {{"QueueUrl", url}, {"Attributes", {{"KmsMasterKeyId", "alias/app"}}}})
                           .status == 200U);
    BOOST_TEST_REQUIRE(send(url, "kms").status == 200U);
    std::vector<std::string> bodies;
    for (const auto& m : receive(url)) {
        bodies.push_back(field(m, "Body"));
    }
    std::sort(bodies.begin(), bodies.end());
    BOOST_TEST((bodies == std::vector<std::string>{"in the clear", "kms", "managed"}));
}

BOOST_FIXTURE_TEST_CASE(data_keys_are_reused_for_the_reuse_period, fixture) {
    const auto url =
        create("busy", {{"KmsMasterKeyId", "alias/app"}, {"KmsDataKeyReusePeriodSeconds", "60"}});
    const auto before = sse->provider_calls();
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST_REQUIRE(send(url, "m" + std::to_string(i)).status == 200U);
    }
    BOOST_TEST(receive(url).size() == 5U);
    // One data key generated; opening needed no provider call.
    BOOST_TEST(sse->provider_calls() - before == 1U);
    now += 61'000;
    BOOST_TEST_REQUIRE(send(url, "later").status == 200U);
    BOOST_TEST(sse->provider_calls() - before == 2U);
}

BOOST_FIXTURE_TEST_CASE(kms_refusals_are_answered_as_sqs_kms_errors, fixture) {
    const auto url = create("locked", {{"KmsMasterKeyId", "alias/denied"}});
    const auto r = send(url, "nope");
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.type() == "com.amazonaws.sqs#KmsAccessDenied");
    const auto q = query("Action=SendMessage&QueueUrl=" + url + "&MessageBody=nope");
    // The query-era model predates the Kms* errors, so the query code is
    // the shape's name (task 13's recorded responses pin it).
    BOOST_TEST(q.body.find("<Code>KmsAccessDenied</Code>") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(sealed_messages_open_after_a_dead_letter_move, fixture) {
    const auto dlq = create("vault-dlq", {{"KmsMasterKeyId", "alias/other"}});
    const auto url = create("vault", {{"RedrivePolicy", redrive_to("vault-dlq", 1)}});
    BOOST_TEST_REQUIRE(send(url, "kept secret").status == 200U);
    BOOST_TEST_REQUIRE(receive(url, 10, {{"VisibilityTimeout", 1}}).size() == 1U);
    now += 1500;
    BOOST_TEST_REQUIRE(receive(url).empty());
    BOOST_TEST(sqs::is_sealed(stored_bodies(*this, "vault-dlq").at(0)));
    const auto moved = receive(dlq);
    BOOST_TEST_REQUIRE(moved.size() == 1U);
    BOOST_TEST(field(moved[0], "Body") == "kept secret");
}

// -- task 8: partitioning and throughput ------------------------------------------

BOOST_FIXTURE_TEST_CASE(fifo_queues_keep_sqs_request_rates, fixture) {
    const auto url =
        create("rated.fifo", {{"FifoQueue", "true"}, {"ContentBasedDeduplication", "true"}});
    int accepted = 0;
    int throttled = 0;
    for (int i = 0; i < 310; ++i) {
        const auto r = send(url, "m" + std::to_string(i), {{"MessageGroupId", "g"}});
        if (r.status == 200U) {
            ++accepted;
        } else {
            BOOST_TEST(r.type() == "com.amazonaws.sqs#RequestThrottled");
            ++throttled;
        }
    }
    BOOST_TEST(accepted == 300);
    BOOST_TEST(throttled == 10);
    // Receives have their own budget; the send budget refills with time.
    BOOST_TEST(call("ReceiveMessage", {{"QueueUrl", url}}).status == 200U);
    now += 100;
    BOOST_TEST(send(url, "later", {{"MessageGroupId", "g"}}).status == 200U);
    // A standard queue, and a FIFO queue with the limits switched off, are
    // not throttled.
    const auto plain = create("unrated");
    const auto relaxed =
        create("relaxed.fifo", {{"FifoQueue", "true"}, {"ContentBasedDeduplication", "true"}});
    BOOST_TEST_REQUIRE(call("TagQueue", {{"QueueUrl", relaxed},
                                         {"Tags", {{"kythira:compat:fifo-throughput", "off"}}}})
                           .status == 200U);
    for (int i = 0; i < 310; ++i) {
        BOOST_TEST_REQUIRE(send(plain, "m").status == 200U);
        BOOST_TEST_REQUIRE(
            send(relaxed, "m" + std::to_string(i), {{"MessageGroupId", "g"}}).status == 200U);
    }
}

BOOST_FIXTURE_TEST_CASE(in_flight_limits_answer_as_sqs_does, fixture) {
    const auto url = create("busy");
    const auto fifo =
        create("busy.fifo", {{"FifoQueue", "true"}, {"ContentBasedDeduplication", "true"}});
    for (const auto& u : {url, fifo}) {
        BOOST_TEST_REQUIRE(call("TagQueue", {{"QueueUrl", u},
                                             {"Tags",
                                              {{"kythira:compat:inflight-standard", "2"},
                                               {"kythira:compat:inflight-fifo", "2"}}}})
                               .status == 200U);
        for (int i = 0; i < 4; ++i) {
            BOOST_TEST_REQUIRE(
                send(u, "m" + std::to_string(i), {{"MessageGroupId", "g" + std::to_string(i)}})
                    .status == 200U);
        }
        BOOST_TEST_REQUIRE(receive(u, 2).size() == 2U);
    }
    const auto r = call("ReceiveMessage", {{"QueueUrl", url}});
    BOOST_TEST(r.status == 403U);  // the model's status for OverLimit
    BOOST_TEST(r.type() == "com.amazonaws.sqs#OverLimit");
    // FIFO: no error, no messages.
    BOOST_TEST(receive(fifo).empty());
}

BOOST_FIXTURE_TEST_CASE(high_throughput_fifo_spans_partitions, fixture) {
    const auto ht = create("ht.fifo", {{"FifoQueue", "true"},
                                       {"ContentBasedDeduplication", "true"},
                                       {"DeduplicationScope", "messageGroup"},
                                       {"FifoThroughputLimit", "perMessageGroupId"}});
    BOOST_TEST(service->find(k_account, "ht.fifo")->_partitions == 16U);
    // SQS refuses perMessageGroupId without per-group deduplication.
    BOOST_TEST(call("CreateQueue",
                    {{"QueueName", "half.fifo"},
                     {"Attributes",
                      {{"FifoQueue", "true"}, {"FifoThroughputLimit", "perMessageGroupId"}}}})
                   .status == 400U);
    // Each group keeps its order across the partitions.
    for (int i = 0; i < 3; ++i) {
        for (const auto* g : {"a", "b", "c", "d"}) {
            BOOST_TEST_REQUIRE(
                send(ht, std::string(g) + std::to_string(i), {{"MessageGroupId", g}}).status ==
                200U);
        }
    }
    std::map<std::string, std::vector<std::string>> by_group;
    for (int round = 0; round < 12; ++round) {
        const auto got = receive(ht, 10, {{"VisibilityTimeout", 0}});
        for (const auto& m : got) {
            by_group[field(m, "Body").substr(0, 1)].push_back(field(m, "Body"));
            BOOST_TEST_REQUIRE(call("DeleteMessage", {{"QueueUrl", ht},
                                                      {"ReceiptHandle", field(m, "ReceiptHandle")}})
                                   .status == 200U);
        }
    }
    BOOST_TEST(by_group.size() == 4U);
    for (const auto& [g, bodies] : by_group) {
        BOOST_TEST((bodies == std::vector<std::string>{g + "0", g + "1", g + "2"}));
    }
    // Queue-wide deduplication cannot span its partitions, even with the
    // throughput limit back to perQueue (which SQS would allow).
    const auto r = call(
        "SetQueueAttributes",
        {{"QueueUrl", ht},
         {"Attributes", {{"DeduplicationScope", "queue"}, {"FifoThroughputLimit", "perQueue"}}}});
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.str("message").find("high throughput") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(standard_queues_grow_with_their_send_rate, fixture) {
    const auto url = create("growing");
    const auto fifo =
        create("fixed.fifo", {{"FifoQueue", "true"}, {"ContentBasedDeduplication", "true"}});
    sqs::grow_worker<sqs::local_queue_cluster> grower(
        cluster, [](const std::string&) { return true; }, {std::chrono::milliseconds(1000), 5.0});
    BOOST_TEST(grower.run_once() == 0U);  // the first sample
    for (int i = 0; i < 30; ++i) {
        BOOST_TEST_REQUIRE(send(url, "m" + std::to_string(i)).status == 200U);
        BOOST_TEST_REQUIRE(send(fifo, "m" + std::to_string(i), {{"MessageGroupId", "g"}}).status ==
                           200U);
    }
    now += 1000;
    // 30 sends in a second over 4 partitions is 7.5 a partition: grow.
    BOOST_TEST(grower.run_once() == 1U);
    BOOST_TEST(service->find(k_account, "growing")->_partitions == 8U);
    BOOST_TEST(service->find(k_account, "fixed.fifo")->_partitions == 1U);
    // The old messages are still received, and new sends reach the new
    // partitions.
    for (int i = 0; i < 16; ++i) {
        BOOST_TEST_REQUIRE(send(url, "n" + std::to_string(i)).status == 200U);
    }
    std::size_t total = 0;
    for (int i = 0; i < 10; ++i) {
        total += receive(url).size();
    }
    BOOST_TEST(total == 46U);
    // A quiet second does not grow it again.
    now += 1000;
    BOOST_TEST(grower.run_once() == 0U);
    now += 1000;
    BOOST_TEST(grower.run_once() == 0U);
}

// -- task 9: SNS HTTPS bridge -----------------------------------------------------

namespace {

/// A signing key and its self-signed certificate, as SNS's.
struct sns_signer {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    std::string pem;

    sns_signer() {
        X509* x = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x), 3600);
        X509_set_pubkey(x, key);
        X509_NAME* n = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(
            n, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("sns.amazonaws.com"),  // NOLINT
            -1, -1, 0);
        X509_set_issuer_name(x, n);
        X509_sign(x, key, EVP_sha256());
        BIO* b = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(b, x);
        char* data = nullptr;
        const auto len = BIO_get_mem_data(b, &data);
        pem.assign(data, static_cast<std::size_t>(len));
        BIO_free(b);
        X509_free(x);
    }
    sns_signer(const sns_signer&) = delete;
    auto operator=(const sns_signer&) -> sns_signer& = delete;
    sns_signer(sns_signer&&) = delete;
    auto operator=(sns_signer&&) -> sns_signer& = delete;
    ~sns_signer() { EVP_PKEY_free(key); }

    /// Signs `m` in place with SignatureVersion `version`.
    void sign(json::object& m, const std::string& version = "2") const {
        m["SignatureVersion"] = version;
        m["SigningCertURL"] = std::string(k_cert_url);
        const auto text = sqs::sns_detail::string_to_sign(m).value();
        EVP_MD_CTX* c = EVP_MD_CTX_new();
        std::size_t len = 0;
        EVP_DigestSignInit(c, nullptr, version == "1" ? EVP_sha1() : EVP_sha256(), nullptr, key);
        EVP_DigestSignUpdate(c, text.data(), text.size());
        EVP_DigestSignFinal(c, nullptr, &len);
        std::vector<unsigned char> sig(len);
        EVP_DigestSignFinal(c, sig.data(), &len);
        EVP_MD_CTX_free(c);
        m["Signature"] = aj::base64_encode(std::as_bytes(std::span(sig.data(), len)));
    }

    static constexpr std::string_view k_cert_url =
        "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem";
};

constexpr std::string_view k_topic = "arn:aws:sns:us-east-1:111122223333:orders";

struct bridged : fixture {
    sns_signer signer;
    std::vector<std::string> fetched;
    sqs::sns_bridge<sqs::sqs_service<sqs::local_queue_cluster>> bridge{
        *service, sqs::sns_bridge_config{
                      "us-east-1",
                      "aws",
                      "http://localhost:9324",
                      {},
                      [this](const std::string& url) -> std::optional<std::string> {
                          fetched.push_back(url);
                          if (url == sns_signer::k_cert_url) {
                              return signer.pem;
                          }
                          if (url.find("Action=ConfirmSubscription") != std::string::npos) {
                              return std::string("<ok/>");
                          }
                          return std::nullopt;
                      }}};

    static auto notification(const std::string& message) -> json::object {
        return {{"Type", "Notification"},
                {"MessageId", "5f1e0e2a-0000-4000-8000-000000000001"},
                {"TopicArn", std::string(k_topic)},
                {"Subject", "hello"},
                {"Message", message},
                {"Timestamp", "2026-11-18T12:00:00.000Z"},
                {"UnsubscribeURL", "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe"}};
    }

    auto post(const std::string& queue, const json::object& m) -> sqs::sns_bridge_response {
        return bridge.handle("POST", "/sns-bridge/" + std::string(k_account) + "/" + queue,
                             json::serialize(m));
    }

    auto take(const std::string& queue, const json::array& names) -> std::string {
        const auto url = "http://localhost:9324/" + std::string(k_account) + "/" + queue;
        const auto got =
            call("ReceiveMessage", {{"QueueUrl", url},
                                    {"MessageAttributeNames", names},
                                    {"MessageSystemAttributeNames", json::array{"All"}}});
        BOOST_REQUIRE_MESSAGE(got.status == 200U && got.body.contains("Messages"),
                              json::serialize(got.body));
        last = got.body.at("Messages").as_array().at(0).as_object();
        return std::string(last.at("Body").as_string());
    }

    json::object last;
};

}  // namespace

BOOST_FIXTURE_TEST_CASE(the_bridge_confirms_subscriptions_from_allowed_topics, bridged) {
    create("inbox");
    json::object c{{"Type", "SubscriptionConfirmation"},
                   {"MessageId", "m-1"},
                   {"Token", "tok"},
                   {"TopicArn", std::string(k_topic)},
                   {"Message", "You have chosen to subscribe"},
                   {"SubscribeURL",
                    "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=tok"},
                   {"Timestamp", "2026-11-18T12:00:00.000Z"}};
    signer.sign(c);
    // Not until the queue says it takes the topic.
    BOOST_TEST(post("inbox", c)._status == 403U);
    BOOST_TEST(post("nowhere", c)._status == 404U);
    BOOST_TEST_REQUIRE(
        call("TagQueue", {{"QueueUrl", "http://localhost:9324/111122223333/inbox"},
                          {"Tags", {{"kythira:sns-bridge-topics", std::string(k_topic)}}}})
            .status == 200U);
    const auto r = post("inbox", c);
    BOOST_TEST(r._status == 200U);
    BOOST_TEST((fetched.back() == std::string(c.at("SubscribeURL").as_string())));
    // A subscribe URL elsewhere is never fetched.
    auto evil = c;
    evil["SubscribeURL"] = "https://attacker.example/?Action=ConfirmSubscription";
    signer.sign(evil);
    const auto before = fetched.size();
    BOOST_TEST(post("inbox", evil)._status == 403U);
    BOOST_TEST(fetched.size() == before);
    BOOST_TEST(bridge.handle("GET", "/sns-bridge/111122223333/inbox", "")._status == 405U);
}

BOOST_FIXTURE_TEST_CASE(the_bridge_enqueues_the_envelope_or_the_raw_message, bridged) {
    for (const auto* q : {"wrapped", "raw"}) {
        create(q);
        json::object tags{{"kythira:sns-bridge-topics", "*"}};
        if (std::string_view(q) == "raw") {
            tags["kythira:sns-bridge-raw"] = "true";
        }
        BOOST_TEST_REQUIRE(
            call("TagQueue", {{"QueueUrl", "http://localhost:9324/111122223333/" + std::string(q)},
                              {"Tags", tags}})
                .status == 200U);
    }
    auto m = notification("order 42 shipped");
    m["MessageAttributes"] = {{"kind", {{"Type", "String"}, {"Value", "shipment"}}}};
    signer.sign(m);
    BOOST_TEST_REQUIRE(post("wrapped", m)._status == 200U);
    const auto envelope = json::parse(take("wrapped", json::array{"All"})).as_object();
    BOOST_TEST(envelope.at("Message").as_string() == "order 42 shipped");
    BOOST_TEST(envelope.at("TopicArn").as_string() == k_topic);
    BOOST_TEST(envelope.at("Type").as_string() == "Notification");
    BOOST_TEST(envelope.at("MessageAttributes").at("kind").at("Value").as_string() == "shipment");
    BOOST_TEST(last.at("Attributes").at("SenderId").as_string() == "sns.amazonaws.com");

    BOOST_TEST_REQUIRE(post("raw", m)._status == 200U);
    BOOST_TEST(take("raw", json::array{"All"}) == "order 42 shipped");
    BOOST_TEST(last.at("MessageAttributes").at("kind").at("StringValue").as_string() == "shipment");
    BOOST_TEST(bridge.delivered() == 2U);
    // SignatureVersion 1 (SHA1withRSA) still verifies.
    auto v1 = notification("by sha1");
    signer.sign(v1, "1");
    BOOST_TEST(post("raw", v1)._status == 200U);
}

BOOST_FIXTURE_TEST_CASE(the_bridge_refuses_what_sns_did_not_sign, bridged) {
    create("strict", {{"SqsManagedSseEnabled", "false"}});
    BOOST_TEST_REQUIRE(call("TagQueue", {{"QueueUrl", "http://localhost:9324/111122223333/strict"},
                                         {"Tags", {{"kythira:sns-bridge-topics", "*"}}}})
                           .status == 200U);
    auto m = notification("genuine");
    signer.sign(m);
    auto forged = m;
    forged["Message"] = "forged";
    BOOST_TEST(post("strict", forged)._status == 403U);
    // A certificate from another host is never fetched.
    auto elsewhere = m;
    elsewhere["SigningCertURL"] = "https://attacker.example/cert.pem";
    const auto before = fetched.size();
    BOOST_TEST(post("strict", elsewhere)._status == 403U);
    BOOST_TEST(fetched.size() == before);
    auto unsigned_ = notification("no signature");
    BOOST_TEST(post("strict", unsigned_)._status == 403U);
    // `*` is the queue's own account's topics only.
    auto other = notification("from afar");
    other["TopicArn"] = "arn:aws:sns:us-east-1:999999999999:theirs";
    signer.sign(other);
    BOOST_TEST(post("strict", other)._status == 403U);
    BOOST_TEST(post("strict", m)._status == 200U);
    BOOST_TEST(bridge.delivered() == 1U);
    // FIFO queues: SNS sends HTTPS only from standard topics.
    create("strict.fifo", {{"FifoQueue", "true"}});
    BOOST_TEST_REQUIRE(
        call("TagQueue", {{"QueueUrl", "http://localhost:9324/111122223333/strict.fifo"},
                          {"Tags", {{"kythira:sns-bridge-topics", "*"}}}})
            .status == 200U);
    BOOST_TEST(post("strict.fifo", m)._status == 400U);
}
