// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_notifications_test.cpp
/// @brief Event notifications (`s3_notifications.hpp`, `s3_event_sinks.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 14, Requirement 12.2).
///
/// The configuration's XML both ways and S3's checks on it (events,
/// filters, ARNs, ids, overlaps, the deprecated form); matching; S3's
/// event JSON; the SQS, SNS and Kinesis requests the API sink builds; and
/// the worker over the in-process index with a real segment store: log
/// order, retries that hold back later records, permanent failures and
/// the attempt limit, and a second worker (a new leader) resuming at the
/// cursor.

#define BOOST_TEST_MODULE s3_notifications_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_notifications.hpp>

#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using namespace kythira::s3;
namespace aws_rest_xml = kythira::aws_rest_xml;

constexpr std::string_view k_queue = "arn:aws:sqs:us-east-1:111122223333:events";
constexpr std::string_view k_topic = "arn:aws:sns:us-east-1:111122223333:alerts";
constexpr std::string_view k_stream = "arn:aws:kinesis:us-east-1:111122223333:stream/changes";

auto config(const std::string& body) -> std::string {
    return R"(<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">)" + body +
           "</NotificationConfiguration>";
}

auto queue(std::string_view id, std::string_view events, std::string_view filter = {},
           std::string_view arn = k_queue) -> std::string {
    std::string out = "<QueueConfiguration>";
    if (!id.empty()) {
        out += "<Id>" + std::string(id) + "</Id>";
    }
    out += "<Queue>" + std::string(arn) + "</Queue>" + std::string(events);
    if (!filter.empty()) {
        out += "<Filter><S3Key>" + std::string(filter) + "</S3Key></Filter>";
    }
    return out + "</QueueConfiguration>";
}

auto rule(std::string_view name, std::string_view value) -> std::string {
    return "<FilterRule><Name>" + std::string(name) + "</Name><Value>" + std::string(value) +
           "</Value></FilterRule>";
}

auto code_of(const aws_rest_xml::result<notification_configuration>& r) -> std::string {
    return r ? std::string{} : r.error().code;
}

auto message_of(const aws_rest_xml::result<notification_configuration>& r) -> std::string {
    return r ? std::string{} : r.error().message;
}

struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> n{0};
        path = fs::temp_directory_path() /
               ("s3_notify_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

/// A recording sink that fails the destinations it is told to.
struct recorder {
    std::vector<notification_delivery> sent;
    std::set<std::string> failing;
    bool permanent = false;

    auto sink() -> notification_sink {
        return [this](const notification_delivery& d) -> delivery_outcome {
            if (failing.contains(d.arn)) {
                return {false, permanent, "down"};
            }
            sent.push_back(d);
            return {true, false, {}};
        };
    }
};

/// One bucket in the in-process index with a change log on disk.
struct logged_bucket {
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store;
    std::unique_ptr<local_metadata> meta;
    std::uint64_t now = 1'700'000'000'000;

    explicit logged_bucket(const std::string& notification) {
        store = std::make_unique<kythira::record_segment_store>(
            kythira::record_segment_store_options{._data_dir = dir.path});
        meta = std::make_unique<local_metadata>(index_options{}, store.get());
        index_command c;
        c.op = index_command::kind::create_bucket;
        c.now_ms = now;
        c.bucket = "photos";
        c.owner = "111122223333";
        c.region = "us-east-1";
        BOOST_REQUIRE(meta->propose(c).ok());
        index_command n;
        n.op = index_command::kind::put_bucket_config;
        n.now_ms = now;
        n.bucket = "photos";
        n.config_name = "notification";
        auto parsed = parse_notification_configuration(notification);
        BOOST_REQUIRE_MESSAGE(parsed.has_value(), message_of(parsed));
        n.document = notification_xml(*parsed);
        BOOST_REQUIRE(meta->propose(n).ok());
    }

    auto put(const std::string& key, std::uint64_t size = 10) -> index_result {
        index_command c;
        c.op = index_command::kind::put_object;
        c.now_ms = ++now;
        c.owner = "111122223333";
        c.target = ref_of(meta->bucket("photos").value());
        c.key = key;
        c.content.manifest.push_back({kythira::sha256_of(std::as_bytes(std::span(key))), size});
        c.content.etag = "etag-" + key;
        auto r = meta->propose(c);
        BOOST_REQUIRE(r.ok());
        return r;
    }

    void del(const std::string& key) {
        index_command c;
        c.op = index_command::kind::delete_object;
        c.now_ms = ++now;
        c.target = ref_of(meta->bucket("photos").value());
        c.key = key;
        BOOST_REQUIRE(meta->propose(c).ok());
    }
};

auto parse_json(const std::string& s) -> boost::json::object {
    return boost::json::parse(s).as_object();
}

auto first_record(const std::string& s) -> boost::json::object {
    return parse_json(s).at("Records").as_array().at(0).as_object();
}

}  // namespace

// ---- configuration ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(configurations_round_trip_with_every_destination_kind) {
    const auto xml =
        config("<TopicConfiguration><Id>t</Id><Topic>" + std::string(k_topic) +
               "</Topic><Event>s3:ObjectRemoved:*</Event></TopicConfiguration>" +
               queue("q", "<Event>s3:ObjectCreated:Put</Event><Event>s3:ObjectCreated:Post</Event>",
                     rule("prefix", "img/") + rule("Suffix", ".jpg")) +
               "<KinesisStreamConfiguration><Id>k</Id><Stream>" + std::string(k_stream) +
               "</Stream><Event>s3:LifecycleTransition</Event></KinesisStreamConfiguration>");
    auto c = parse_notification_configuration(xml);
    BOOST_TEST_REQUIRE(c.has_value(), message_of(c));
    BOOST_TEST_REQUIRE(c->targets.size() == 3U);
    BOOST_TEST((c->targets[1].kind == destination_kind::queue));
    BOOST_TEST(c->targets[1].prefix == "img/");
    BOOST_TEST(c->targets[1].suffix == ".jpg");
    BOOST_TEST(c->targets[1].events.size() == 2U);
    BOOST_TEST((c->targets[2].kind == destination_kind::stream));

    const auto rendered = notification_xml(*c);
    BOOST_TEST(rendered.find("<Name>Prefix</Name><Value>img/</Value>") != std::string::npos);
    auto again = parse_notification_configuration(rendered);
    BOOST_TEST_REQUIRE(again.has_value());
    BOOST_TEST((*again == *c));

    // An empty configuration is valid: it removes the bucket's.
    BOOST_TEST(parse_notification_configuration(config("")).value().empty());
}

BOOST_AUTO_TEST_CASE(ids_are_made_up_when_absent_and_must_be_unique) {
    auto c =
        parse_notification_configuration(config(queue("", "<Event>s3:ObjectCreated:*</Event>") +
                                                queue("", "<Event>s3:ObjectRemoved:*</Event>")));
    BOOST_TEST_REQUIRE(c.has_value(), message_of(c));
    BOOST_TEST(!c->targets[0].id.empty());
    BOOST_TEST(c->targets[0].id != c->targets[1].id);
    // The same configuration gets the same ids.
    auto same =
        parse_notification_configuration(config(queue("", "<Event>s3:ObjectCreated:*</Event>") +
                                                queue("", "<Event>s3:ObjectRemoved:*</Event>")));
    BOOST_TEST(same->targets[0].id == c->targets[0].id);

    BOOST_TEST(code_of(parse_notification_configuration(
                   config(queue("x", "<Event>s3:ObjectCreated:*</Event>") +
                          queue("x", "<Event>s3:ObjectRemoved:*</Event>")))) == "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(s3_refuses_what_it_cannot_deliver_or_could_deliver_twice) {
    const auto refused = [](const std::string& body) {
        return code_of(parse_notification_configuration(config(body)));
    };
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectMoved:*</Event>")) == "InvalidArgument");
    BOOST_TEST(refused(queue("a", "")) == "MalformedXML");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>", {},
                             "arn:aws:sns:us-east-1:111122223333:t")) == "InvalidArgument");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>", {}, "not-an-arn")) ==
               "InvalidArgument");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>",
                             rule("prefix", "a") + rule("prefix", "b"))) == "InvalidArgument");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>", rule("middle", "a"))) ==
               "InvalidArgument");
    BOOST_TEST(refused("<CloudFunctionConfiguration><CloudFunction>arn:aws:lambda:us-east-1:1:"
                       "function:f</CloudFunction><Event>s3:ObjectCreated:*</Event>"
                       "</CloudFunctionConfiguration>") == "InvalidArgument");
    BOOST_TEST(refused("<EventBridgeConfiguration/>") == "NotImplemented");
    BOOST_TEST(refused("<Bogus/>") == "MalformedXML");

    // Overlap: same event family, prefixes and suffixes both overlapping.
    const auto ambiguous = config(
        queue("a", "<Event>s3:ObjectCreated:*</Event>", rule("prefix", "img/")) +
        queue("b", "<Event>s3:ObjectCreated:Put</Event>", rule("prefix", "img/cats/"), k_queue));
    BOOST_TEST(message_of(parse_notification_configuration(ambiguous)).find("ambiguously") !=
               std::string::npos);
    // Disjoint prefixes, disjoint suffixes, or different events are fine.
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>", rule("prefix", "img/")) +
                       queue("b", "<Event>s3:ObjectCreated:*</Event>", rule("prefix", "doc/"))) ==
               "");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>", rule("suffix", ".jpg")) +
                       queue("b", "<Event>s3:ObjectCreated:*</Event>", rule("suffix", ".png"))) ==
               "");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:Put</Event>") +
                       queue("b", "<Event>s3:ObjectCreated:Copy</Event>")) == "");
    BOOST_TEST(refused(queue("a", "<Event>s3:ObjectCreated:*</Event>") +
                       queue("b", "<Event>s3:ObjectRemoved:*</Event>")) == "");
}

BOOST_AUTO_TEST_CASE(the_deprecated_form_reads_and_writes_one_configuration_per_kind) {
    auto c = parse_legacy_notification(
        config("<QueueConfiguration><Id>q</Id><Event>s3:ObjectCreated:*</Event><Queue>" +
               std::string(k_queue) +
               "</Queue></QueueConfiguration><TopicConfiguration><Id>t</Id><Events><Event>s3:"
               "ObjectRemoved:Delete</Event></Events><Topic>" +
               std::string(k_topic) + "</Topic></TopicConfiguration>"));
    BOOST_TEST_REQUIRE(c.has_value(), message_of(c));
    BOOST_TEST(c->targets.size() == 2U);
    const auto xml = legacy_notification_xml(*c);
    BOOST_TEST(xml.find("<TopicConfiguration><Id>t</Id><Event>s3:ObjectRemoved:Delete</Event>"
                        "<Topic>") != std::string::npos);
    BOOST_TEST(code_of(parse_legacy_notification(
                   config(queue("a", "<Event>s3:ObjectCreated:*</Event>") +
                          queue("b", "<Event>s3:ObjectRemoved:*</Event>")))) == "MalformedXML");
}

BOOST_AUTO_TEST_CASE(targets_match_by_event_then_prefix_and_suffix) {
    notification_target t;
    t.events = {"s3:ObjectCreated:*", "s3:ObjectRemoved:DeleteMarkerCreated"};
    t.prefix = "img/";
    t.suffix = ".jpg";
    BOOST_TEST(matches(t, change_event::object_created_put, "img/a.jpg"));
    BOOST_TEST(matches(t, change_event::object_created_complete_multipart_upload, "img/b.jpg"));
    BOOST_TEST(matches(t, change_event::object_removed_delete_marker_created, "img/c.jpg"));
    BOOST_TEST(!matches(t, change_event::object_removed_delete, "img/c.jpg"));
    BOOST_TEST(!matches(t, change_event::object_created_put, "doc/a.jpg"));
    BOOST_TEST(!matches(t, change_event::object_created_put, "img/a.png"));
    t.events = {"s3:LifecycleTransition"};
    BOOST_TEST(matches(t, change_event::lifecycle_transition, "img/x.jpg"));
    BOOST_TEST(!matches(t, change_event::lifecycle_expiration_delete, "img/x.jpg"));
}

// ---- event JSON --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(events_carry_s3s_documented_fields) {
    sequenced_change c{42,
                       {change_event::object_created_put, 7, "img/my cat+1.jpg", "AAAA0001", 1024,
                        "abc", "111122223333", "", 1'700'000'000'123}};
    const auto rec =
        first_record(event_json(c, {"eu-west-1", "aws", "photos", "111122223333", "cfg-1"}));
    BOOST_TEST(rec.at("eventVersion").as_string() == "2.1");
    BOOST_TEST(rec.at("eventSource").as_string() == "aws:s3");
    BOOST_TEST(rec.at("awsRegion").as_string() == "eu-west-1");
    BOOST_TEST(rec.at("eventTime").as_string() == "2023-11-14T22:13:20.123Z");
    BOOST_TEST(rec.at("eventName").as_string() == "ObjectCreated:Put");
    BOOST_TEST(rec.at("userIdentity").at("principalId").as_string() == "AWS:111122223333");
    const auto& s3 = rec.at("s3").as_object();
    BOOST_TEST(s3.at("s3SchemaVersion").as_string() == "1.0");
    BOOST_TEST(s3.at("configurationId").as_string() == "cfg-1");
    BOOST_TEST(s3.at("bucket").at("name").as_string() == "photos");
    BOOST_TEST(s3.at("bucket").at("arn").as_string() == "arn:aws:s3:::photos");
    const auto& obj = s3.at("object").as_object();
    BOOST_TEST(obj.at("key").as_string() == "img/my+cat%2B1.jpg");
    BOOST_TEST(obj.at("size").as_int64() == 1024);
    BOOST_TEST(obj.at("eTag").as_string() == "abc");
    BOOST_TEST(obj.at("versionId").as_string() == "AAAA0001");
    BOOST_TEST(obj.at("sequencer").as_string() == "000000000000002A");

    // A delete has no size or ETag; an unversioned write no version id.
    c.record.event = change_event::object_removed_delete;
    c.record.version_id = "null";
    const auto del = first_record(event_json(c, {}));
    BOOST_TEST(!del.at("s3").at("object").as_object().contains("size"));
    BOOST_TEST(!del.at("s3").at("object").as_object().contains("versionId"));

    // Lifecycle events are version 2.3 and say where a transition went.
    c.record.event = change_event::lifecycle_transition;
    c.record.storage_class = "GLACIER";
    c.record.requester.clear();
    const auto lc = first_record(event_json(c, {}));
    BOOST_TEST(lc.at("eventVersion").as_string() == "2.3");
    BOOST_TEST(lc.at("userIdentity").at("principalId").as_string() == "AmazonS3");
    BOOST_TEST(lc.at("lifecycleEventData")
                   .at("transitionEventData")
                   .at("destinationStorageClass")
                   .as_string() == "GLACIER");

    const auto test = parse_json(test_event_json("photos", 0, "REQ"));
    BOOST_TEST(test.at("Event").as_string() == "s3:TestEvent");
    BOOST_TEST(test.at("Bucket").as_string() == "photos");
    BOOST_TEST(test.at("Time").as_string() == "1970-01-01T00:00:00.000Z");
}

// ---- API sink ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_api_sink_speaks_each_services_protocol) {
    std::vector<event_api_request> calls;
    event_api_answer answer{200, "{}"};
    notification_api_sink sink([&](const event_api_request& r) {
        calls.push_back(r);
        return answer;
    });

    BOOST_TEST(sink({destination_kind::queue, std::string(k_queue), "{\"a\":1}", "p/k"}).ok);
    BOOST_TEST(calls.back().service == "sqs");
    BOOST_TEST(calls.back().region == "us-east-1");
    BOOST_TEST(calls.back().target == "AmazonSQS.SendMessage");
    const auto sqs = parse_json(calls.back().body);
    BOOST_TEST(sqs.at("QueueUrl").as_string() ==
               "https://sqs.us-east-1.amazonaws.com/111122223333/events");
    BOOST_TEST(sqs.at("MessageBody").as_string() == "{\"a\":1}");

    BOOST_TEST(sink({destination_kind::topic, std::string(k_topic), "{\"a\": 1}", "p/k"}).ok);
    BOOST_TEST(calls.back().service == "sns");
    BOOST_TEST(calls.back().target.empty());
    BOOST_TEST(calls.back().body ==
               "Action=Publish&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%"
               "3A111122223333%3Aalerts&Subject=Amazon%20S3%20Notification&Message=%7B%22a%22%"
               "3A%201%7D");

    BOOST_TEST(sink({destination_kind::stream, std::string(k_stream), "hi", "photos/k"}).ok);
    BOOST_TEST(calls.back().service == "kinesis");
    BOOST_TEST(calls.back().target == "Kinesis_20131202.PutRecord");
    const auto kin = parse_json(calls.back().body);
    BOOST_TEST(kin.at("StreamARN").as_string() == k_stream);
    BOOST_TEST(kin.at("PartitionKey").as_string() == "photos/k");
    BOOST_TEST(kin.at("Data").as_string() == "aGk=");
    BOOST_TEST(notification_api_sink::partition_key(std::string(300, 'x')).size() == 256U);

    // Missing destinations fail for good; throttling and 5xx are retried.
    answer = {400, R"({"__type":"AWS.SimpleQueueService.NonExistentQueue"})"};
    auto out = sink({destination_kind::queue, std::string(k_queue), "x", "k"});
    BOOST_TEST(!out.ok);
    BOOST_TEST(out.permanent);
    answer = {400, R"({"__type":"ThrottlingException"})"};
    BOOST_TEST(!sink({destination_kind::queue, std::string(k_queue), "x", "k"}).permanent);
    answer = {503, ""};
    BOOST_TEST(!sink({destination_kind::queue, std::string(k_queue), "x", "k"}).permanent);
    notification_api_sink broken(
        [](const event_api_request&) -> event_api_answer { throw std::runtime_error("no route"); });
    out = broken({destination_kind::queue, std::string(k_queue), "x", "k"});
    BOOST_TEST(!out.ok);
    BOOST_TEST(!out.permanent);
    BOOST_TEST(broken({destination_kind::queue, "arn:aws:sqs:::x", "x", "k"}).permanent);
}

// ---- the worker ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_worker_delivers_matching_events_in_log_order_and_advances) {
    logged_bucket b(
        config(queue("created", "<Event>s3:ObjectCreated:*</Event>", rule("prefix", "img/")) +
               "<TopicConfiguration><Id>removed</Id><Topic>" + std::string(k_topic) +
               "</Topic><Event>s3:ObjectRemoved:*</Event></TopicConfiguration>"));
    const auto v = b.put("img/a.jpg", 5);
    b.put("doc/b.txt");  // matches nothing
    b.del("img/a.jpg");
    b.put("img/c.jpg");

    recorder rec;
    notification_worker w(*b.meta, rec.sink(), {.region = "us-east-1"});
    const auto r = w.run();
    BOOST_TEST(r.records == 4U);
    BOOST_TEST(r.delivered == 3U);
    BOOST_TEST(!r.blocked);
    BOOST_TEST_REQUIRE(rec.sent.size() == 3U);
    BOOST_TEST(rec.sent[0].arn == k_queue);
    BOOST_TEST(rec.sent[1].arn == k_topic);
    BOOST_TEST((rec.sent[1].kind == destination_kind::topic));
    BOOST_TEST(rec.sent[2].arn == k_queue);
    const auto first = first_record(rec.sent[0].body);
    BOOST_TEST(first.at("s3").at("configurationId").as_string() == "created");
    BOOST_TEST(first.at("s3").at("object").at("key").as_string() == "img/a.jpg");
    BOOST_TEST(first.at("s3").at("object").at("size").as_int64() == 5);
    BOOST_TEST(first.at("s3").at("bucket").at("name").as_string() == "photos");
    BOOST_TEST(first_record(rec.sent[1].body).at("eventName").as_string() ==
               "ObjectRemoved:Delete");
    BOOST_TEST(rec.sent[0].partition_key == "photos/img/a.jpg");
    (void)v;

    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 4U);
    BOOST_TEST(w.run().records == 0U);  // nothing new
    BOOST_TEST(rec.sent.size() == 3U);
}

BOOST_AUTO_TEST_CASE(a_failing_destination_holds_back_later_records_until_it_recovers) {
    logged_bucket b(config(queue("q", "<Event>s3:ObjectCreated:*</Event>", rule("prefix", "a/")) +
                           "<TopicConfiguration><Id>t</Id><Topic>" + std::string(k_topic) +
                           "</Topic><Event>s3:ObjectCreated:*</Event><Filter><S3Key>" +
                           rule("prefix", "b/") + "</S3Key></Filter></TopicConfiguration>"));
    b.put("a/1");
    b.put("b/2");
    b.put("a/3");
    recorder rec;
    rec.failing.insert(std::string(k_topic));
    notification_worker w(*b.meta, rec.sink());
    auto r = w.run();
    BOOST_TEST(r.blocked);
    BOOST_TEST(r.records == 1U);
    BOOST_TEST(r.failures == 1U);
    BOOST_TEST(rec.sent.size() == 1U);  // a/3 waits behind b/2
    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 1U);

    rec.failing.clear();
    r = w.run();
    BOOST_TEST(!r.blocked);
    BOOST_TEST(r.records == 2U);
    BOOST_TEST_REQUIRE(rec.sent.size() == 3U);
    BOOST_TEST(rec.sent[1].arn == k_topic);
    BOOST_TEST(first_record(rec.sent[2].body).at("s3").at("object").at("key").as_string() == "a/3");
    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 3U);
}

BOOST_AUTO_TEST_CASE(permanent_failures_and_the_attempt_limit_drop_a_delivery) {
    logged_bucket b(config(queue("q", "<Event>s3:ObjectCreated:*</Event>")));
    b.put("k1");
    recorder rec;
    rec.failing.insert(std::string(k_queue));
    rec.permanent = true;
    notification_worker w(*b.meta, rec.sink());
    auto r = w.run();
    BOOST_TEST(r.dropped == 1U);
    BOOST_TEST(r.records == 1U);
    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 1U);

    b.put("k2");
    rec.permanent = false;
    notification_worker limited(*b.meta, rec.sink(), {.max_attempts = 3});
    BOOST_TEST(limited.run().blocked);
    BOOST_TEST(limited.run().blocked);
    r = limited.run();
    BOOST_TEST(!r.blocked);
    BOOST_TEST(r.dropped == 1U);
    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 2U);
}

BOOST_AUTO_TEST_CASE(a_new_leader_resumes_at_the_cursor) {
    logged_bucket b(config(queue("q", "<Event>s3:ObjectCreated:*</Event>")));
    for (int i = 0; i < 5; ++i) {
        b.put("k" + std::to_string(i));
    }
    recorder rec;
    notification_worker first(*b.meta, rec.sink(), {.page = 3});
    BOOST_TEST(first.run().records == 3U);
    BOOST_TEST(b.meta->change_cursor(notifications_consumer) == 3U);
    notification_worker second(*b.meta, rec.sink(), {.page = 3});
    BOOST_TEST(second.run().records == 2U);
    BOOST_TEST_REQUIRE(rec.sent.size() == 5U);
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(first_record(rec.sent[static_cast<std::size_t>(i)].body)
                       .at("s3")
                       .at("object")
                       .at("key")
                       .as_string() == "k" + std::to_string(i));
    }
}

BOOST_AUTO_TEST_CASE(a_bucket_without_a_configuration_logs_nothing) {
    temp_dir dir;
    kythira::record_segment_store store({._data_dir = dir.path});
    local_metadata meta(index_options{}, &store);
    index_command c;
    c.op = index_command::kind::create_bucket;
    c.bucket = "quiet";
    c.owner = "1";
    BOOST_REQUIRE(meta.propose(c).ok());
    const auto d = meta.bucket("quiet").value();
    BOOST_TEST(!ref_of(d).log_changes);
    index_command p;
    p.op = index_command::kind::put_object;
    p.target = ref_of(d);
    p.key = "k";
    BOOST_REQUIRE(meta.propose(p).ok());
    BOOST_TEST(meta.read_changes(0, 10).empty());
    BOOST_TEST(store.streams().empty());
}
