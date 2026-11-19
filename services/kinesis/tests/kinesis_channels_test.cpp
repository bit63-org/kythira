// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Channels (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement
// 18.1) through the front end over the in-process cluster: CreateChannel,
// DescribeChannel, ListChannels, UpdateChannel and DeleteChannel with the
// model's shapes and the rules its documentation states (one destination,
// on-demand sources only, record formats by destination, no deleting a
// stream that feeds a channel), tags on channel ARNs, and the catalog
// record's codec and snapshot round trip.

#define BOOST_TEST_MODULE kinesis_channels_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_service.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <boost/json.hpp>

#include <string>
#include <string_view>

namespace kin = kythira::kinesis;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_role = "arn:aws:iam::111122223333:role/channel-delivery";

struct allow_all {
    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        az::principal_context p;
        p.account = std::string(k_account);
        p.arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
        return p;
    }
    auto authorize(const az::principal_context&, const az::authz_request&) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = true;
        return d;
    }
};

struct fixture {
    std::int64_t clock = 1'762'776'000'000;
    kin::local_stream_cluster cluster{nullptr, [this] { return clock; }};
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<kin::local_stream_cluster> service{cluster, no_rates()};

    fixture() { service.register_with(fe); }

    static auto no_rates() -> kin::kinesis_service_config {
        kin::kinesis_service_config cfg;
        cfg._control_plane._rates.clear();
        return cfg;
    }

    auto call(std::string_view op, const json::value& body) -> aj::http_response {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
        return fe.handle(r);
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto error_type(std::string_view op, const json::value& body) -> std::string {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status != 200U, std::string(op) + " unexpectedly succeeded");
        return std::string(json::parse(r.body).as_object().at("__type").as_string());
    }

    auto on_demand(std::string_view name) -> void {
        (void)ok("CreateStream",
                 {{"StreamName", name}, {"StreamModeDetails", {{"StreamMode", "ON_DEMAND"}}}});
    }
    auto provisioned(std::string_view name) -> void {
        (void)ok("CreateStream", {{"StreamName", name}, {"ShardCount", 1}});
    }
};

auto stream_arn(std::string_view name) -> std::string {
    return "arn:aws:kinesis:us-east-1:" + std::string(k_account) + ":stream/" + std::string(name);
}

auto s3_destination() -> json::object {
    return {{"StorageConfiguration",
             {{"BucketARN", "arn:aws:s3:::delivered"},
              {"ExpectedBucketOwner", k_account},
              {"CompressionType", "GZIP"}}},
            {"DeadLetterQueueS3Configuration",
             {{"BucketARN", "arn:aws:s3:::dead-letters"}, {"ExpectedBucketOwner", k_account}}}};
}

auto tables_destination() -> json::object {
    return {
        {"DeadLetterQueueS3Configuration",
         {{"BucketARN", "arn:aws:s3:::dead-letters"}, {"ExpectedBucketOwner", k_account}}},
        {"S3TablesConfigurationList",
         json::array{{{"TableBucketARN", "arn:aws:s3tables:us-east-1:111122223333:bucket/tables"},
                      {"Namespace", "events"},
                      {"TableName", "clicks"},
                      {"CompressionType", "ZSTD"}}}}};
}

auto source(std::string_view stream, std::string_view format = "JSON") -> json::object {
    return {{"StreamARN", stream_arn(stream)},
            {"RecordConfiguration", {{"RecordFormatType", format}}}};
}

auto create_body(std::string_view name, json::array sources) -> json::object {
    return {{"ChannelName", name},
            {"ServiceExecutionRoleARN", k_role},
            {"StreamConfigurationList", std::move(sources)},
            {"S3DestinationConfiguration", s3_destination()}};
}

auto str(const json::value& v) -> std::string {
    return std::string(v.as_string());
}

}  // namespace

BOOST_AUTO_TEST_SUITE(kinesis_channels)

BOOST_AUTO_TEST_CASE(create_describe_and_list) {
    fixture f;
    f.on_demand("orders");
    auto body = create_body("to-s3", {source("orders")});
    body["Tags"] = {{"team", "data"}};
    const auto created = f.ok("CreateChannel", body).at("ChannelDescription").as_object();
    BOOST_TEST(str(created.at("ChannelName")) == "to-s3");
    BOOST_TEST(str(created.at("ChannelStatus")) == "ACTIVE");
    const auto arn = str(created.at("ChannelARN"));
    const auto id = str(created.at("ChannelId"));
    BOOST_TEST(arn == "arn:aws:kinesis:us-east-1:111122223333:channel/" + id);
    BOOST_TEST(str(created.at("ServiceExecutionRoleARN")) == k_role);
    BOOST_TEST(created.at("ChannelCreationTimestamp").as_double() == 1'762'776'000.0);
    const auto& dest = created.at("S3DestinationConfiguration").as_object();
    BOOST_TEST(dest.at("DataFreshnessInSeconds").as_int64() == 300);  // the default
    BOOST_TEST(str(dest.at("StorageConfiguration").at("CompressionType")) == "GZIP");
    BOOST_TEST(str(dest.at("DeadLetterQueueS3Configuration").at("BucketARN")) ==
               "arn:aws:s3:::dead-letters");
    BOOST_TEST(!created.contains("S3TablesDestinationConfiguration"));
    BOOST_TEST(created.at("LoggingConfiguration").at("CloudWatchLogs").at("Enabled").as_bool() ==
               false);
    const auto& streams = created.at("StreamConfigurationList").as_array();
    BOOST_REQUIRE(streams.size() == 1U);
    BOOST_TEST(str(streams[0].at("StreamARN")) == stream_arn("orders"));
    BOOST_TEST(str(streams[0].at("RecordConfiguration").at("RecordFormatType")) == "JSON");

    const auto described =
        f.ok("DescribeChannel", {{"ChannelARN", arn}}).at("ChannelDescription").as_object();
    BOOST_TEST(json::serialize(described) == json::serialize(created));

    const auto listed = f.ok("ListChannels", json::object{});
    const auto& summaries = listed.at("ChannelSummaries").as_array();
    BOOST_REQUIRE(summaries.size() == 1U);
    BOOST_TEST(str(summaries[0].at("ChannelARN")) == arn);
    BOOST_TEST(str(summaries[0].at("ChannelDestinationType")) == "S3");
    BOOST_TEST(str(summaries[0].at("Streams").at(0).at("StreamARN")) == stream_arn("orders"));
    BOOST_TEST(!listed.contains("NextToken"));

    const auto summary = f.ok("DescribeStreamSummary", {{"StreamName", "orders"}});
    BOOST_TEST(summary.at("StreamDescriptionSummary").at("ChannelCount").as_int64() == 1);

    const auto tags = f.ok("ListTagsForResource", {{"ResourceARN", arn}});
    BOOST_TEST(json::serialize(tags.at("Tags")) == R"([{"Key":"team","Value":"data"}])");
}

// The model's S3DestinationDescription requires DataFreshnessInSeconds and
// DeadLetterQueueS3Configuration (the differential tool's model check found
// the second missing). A channel created without a dead-letter configuration
// describes the one delivery uses: the destination bucket under errors/.
BOOST_AUTO_TEST_CASE(an_s3_channel_describes_its_default_dead_letter_location) {
    fixture f;
    f.on_demand("orders");
    auto body = create_body("to-s3", {source("orders")});
    body["S3DestinationConfiguration"].as_object().erase("DeadLetterQueueS3Configuration");
    const auto created = f.ok("CreateChannel", body).at("ChannelDescription").as_object();
    const auto& dest = created.at("S3DestinationConfiguration").as_object();
    BOOST_TEST(dest.at("DataFreshnessInSeconds").as_int64() == 300);
    const auto& dlq = dest.at("DeadLetterQueueS3Configuration").as_object();
    BOOST_TEST(str(dlq.at("BucketARN")) == "arn:aws:s3:::delivered");
    BOOST_TEST(str(dlq.at("ExpectedBucketOwner")) == std::string(k_account));
    BOOST_TEST(str(dlq.at("ErrorOutputPrefix")) == "errors/");
    const auto described = f.ok("DescribeChannel", {{"ChannelARN", created.at("ChannelARN")}})
                               .at("ChannelDescription")
                               .as_object();
    BOOST_TEST(json::serialize(described) == json::serialize(created));
}

BOOST_AUTO_TEST_CASE(s3_tables_destination) {
    fixture f;
    f.on_demand("clicks");
    auto rc = source("clicks", "GSR_JSON");
    rc["RecordConfiguration"].as_object()["GSRSchemaARN"] =
        "arn:aws:glue:us-east-1:111122223333:schema/registry/clicks";
    json::object body{{"ChannelName", "to-tables"},
                      {"ServiceExecutionRoleARN", k_role},
                      {"StreamConfigurationList", json::array{rc}},
                      {"S3TablesDestinationConfiguration", tables_destination()}};
    const auto d = f.ok("CreateChannel", body).at("ChannelDescription").as_object();
    BOOST_TEST(d.contains("S3TablesDestinationConfiguration"));
    BOOST_TEST(!d.contains("S3DestinationConfiguration"));
    const auto listed = f.ok("ListChannels", json::object{});
    BOOST_TEST(str(listed.at("ChannelSummaries").at(0).at("ChannelDestinationType")) ==
               "S3_TABLES");
}

BOOST_AUTO_TEST_CASE(create_refusals) {
    fixture f;
    f.on_demand("orders");
    f.provisioned("legacy");

    auto both = create_body("c", {source("orders")});
    both["S3TablesDestinationConfiguration"] = tables_destination();
    BOOST_TEST(f.error_type("CreateChannel", both) == "InvalidArgumentException");

    auto none = create_body("c", {source("orders")});
    none.erase("S3DestinationConfiguration");
    BOOST_TEST(f.error_type("CreateChannel", none) == "InvalidArgumentException");

    BOOST_TEST(f.error_type("CreateChannel", create_body("c", {source("legacy")})) ==
               "InvalidArgumentException");
    BOOST_TEST(f.error_type("CreateChannel", create_body("c", {source("missing")})) ==
               "ResourceNotFoundException");
    BOOST_TEST(
        f.error_type("CreateChannel", create_body("c", {source("orders"), source("orders")})) ==
        "InvalidArgumentException");
    BOOST_TEST(f.error_type("CreateChannel", create_body("c", {source("orders", "GSR_JSON")})) ==
               "InvalidArgumentException");

    json::object other{{"StreamARN", "arn:aws:kinesis:us-east-1:444455556666:stream/orders"},
                       {"RecordConfiguration", {{"RecordFormatType", "JSON"}}}};
    BOOST_TEST(f.error_type("CreateChannel", create_body("c", {other})) ==
               "InvalidArgumentException");

    // S3 Tables: STRING is S3-only, and a Glue schema is required.
    json::object tables{{"ChannelName", "t"},
                        {"ServiceExecutionRoleARN", k_role},
                        {"StreamConfigurationList", json::array{source("orders")}},
                        {"S3TablesDestinationConfiguration", tables_destination()}};
    BOOST_TEST(f.error_type("CreateChannel", tables) == "InvalidArgumentException");
    tables["StreamConfigurationList"] = json::array{source("orders", "STRING")};
    BOOST_TEST(f.error_type("CreateChannel", tables) == "InvalidArgumentException");

    auto two_tables = tables_destination();
    two_tables["S3TablesConfigurationList"].as_array().push_back(
        two_tables["S3TablesConfigurationList"].as_array()[0]);
    auto with_schema = source("orders");
    with_schema["RecordConfiguration"].as_object()["GSRSchemaARN"] =
        "arn:aws:glue:us-east-1:111122223333:schema/registry/orders";
    BOOST_TEST(f.error_type("CreateChannel", {{"ChannelName", "t"},
                                              {"ServiceExecutionRoleARN", k_role},
                                              {"StreamConfigurationList", json::array{with_schema}},
                                              {"S3TablesDestinationConfiguration", two_tables}}) ==
               "InvalidArgumentException");

    auto managed = create_body("c", {source("orders")});
    managed["EncryptionConfiguration"] = {{"EncryptionType", "KMS"},
                                          {"KeyId", "alias/aws/kinesis"}};
    BOOST_TEST(f.error_type("CreateChannel", managed) == "InvalidArgumentException");

    (void)f.ok("CreateChannel", create_body("c", {source("orders")}));
    BOOST_TEST(f.error_type("CreateChannel", create_body("c", {source("orders")})) ==
               "ResourceInUseException");
}

BOOST_AUTO_TEST_CASE(update_channel) {
    fixture f;
    f.on_demand("orders");
    const auto arn = str(f.ok("CreateChannel", create_body("c", {source("orders")}))
                             .at("ChannelDescription")
                             .at("ChannelARN"));
    const auto updated =
        f.ok("UpdateChannel",
             {{"ChannelARN", arn},
              {"S3DestinationConfiguration", {{"DataFreshnessInSeconds", 600}}},
              {"LoggingConfiguration",
               {{"CloudWatchLogs", {{"Enabled", true}, {"LogGroupName", "channels"}}}}}})
            .at("ChannelDescription")
            .as_object();
    BOOST_TEST(updated.at("S3DestinationConfiguration").at("DataFreshnessInSeconds").as_int64() ==
               600);
    // The rest of the destination is unchanged.
    BOOST_TEST(
        str(updated.at("S3DestinationConfiguration").at("StorageConfiguration").at("BucketARN")) ==
        "arn:aws:s3:::delivered");
    BOOST_TEST(updated.at("LoggingConfiguration").at("CloudWatchLogs").at("Enabled").as_bool());
    const auto described =
        f.ok("DescribeChannel", {{"ChannelARN", arn}}).at("ChannelDescription").as_object();
    BOOST_TEST(json::serialize(described) == json::serialize(updated));

    BOOST_TEST(f.error_type("UpdateChannel", {{"ChannelARN", arn},
                                              {"S3TablesDestinationConfiguration",
                                               {{"DataFreshnessInSeconds", 60}}}}) ==
               "InvalidArgumentException");
    BOOST_TEST(f.error_type("UpdateChannel", {{"ChannelARN", arn}}) == "InvalidArgumentException");
    // The model's documented range is 300 to 900 seconds.
    for (const int bad : {299, 901}) {
        BOOST_TEST(f.error_type("UpdateChannel", {{"ChannelARN", arn},
                                                  {"S3DestinationConfiguration",
                                                   {{"DataFreshnessInSeconds", bad}}}}) ==
                   "InvalidArgumentException");
    }
}

BOOST_AUTO_TEST_CASE(delete_channel_and_its_stream) {
    fixture f;
    f.on_demand("orders");
    const auto arn = str(f.ok("CreateChannel", create_body("c", {source("orders")}))
                             .at("ChannelDescription")
                             .at("ChannelARN"));
    // AWS: no deleting a stream while it has channels.
    BOOST_TEST(f.error_type("DeleteStream", {{"StreamName", "orders"}}) ==
               "ResourceInUseException");
    (void)f.ok("DeleteChannel", {{"ChannelARN", arn}});
    BOOST_TEST(f.error_type("DescribeChannel", {{"ChannelARN", arn}}) ==
               "ResourceNotFoundException");
    BOOST_TEST(f.error_type("DeleteChannel", {{"ChannelARN", arn}}) == "ResourceNotFoundException");
    BOOST_TEST(f.ok("ListChannels", json::object{}).at("ChannelSummaries").as_array().empty());
    (void)f.ok("DeleteStream", {{"StreamName", "orders"}});

    // A channel created again under the name has another id, and the old
    // ARN does not reach it.
    f.on_demand("orders");
    const auto again = str(f.ok("CreateChannel", create_body("c", {source("orders")}))
                               .at("ChannelDescription")
                               .at("ChannelARN"));
    BOOST_TEST(again != arn);
    BOOST_TEST(f.error_type("DescribeChannel", {{"ChannelARN", arn}}) ==
               "ResourceNotFoundException");
}

BOOST_AUTO_TEST_CASE(list_pages_and_filters) {
    fixture f;
    f.on_demand("a");
    f.on_demand("b");
    (void)f.ok("CreateChannel", create_body("one", {source("a")}));
    (void)f.ok("CreateChannel", create_body("two", {source("b")}));
    (void)f.ok("CreateChannel", create_body("three", {source("a"), source("b")}));

    std::vector<std::string> names;
    json::object req{{"MaxResults", 1}};
    for (int i = 0; i < 10; ++i) {
        const auto page = f.ok("ListChannels", req);
        for (const auto& c : page.at("ChannelSummaries").as_array()) {
            names.push_back(str(c.at("ChannelName")));
        }
        if (!page.contains("NextToken")) {
            break;
        }
        req = {{"MaxResults", 1}, {"NextToken", page.at("NextToken")}};
    }
    BOOST_TEST((names == std::vector<std::string>{"one", "three", "two"}));

    const auto from_a =
        f.ok("ListChannels", {{"StreamFilter", json::array{{{"StreamARN", stream_arn("a")}}}}});
    std::vector<std::string> a_names;
    for (const auto& c : from_a.at("ChannelSummaries").as_array()) {
        a_names.push_back(str(c.at("ChannelName")));
    }
    BOOST_TEST((a_names == std::vector<std::string>{"one", "three"}));

    BOOST_TEST(f.error_type("ListChannels", {{"NextToken", "not-a-token"}}) ==
               "ExpiredNextTokenException");
}

BOOST_AUTO_TEST_CASE(tags_on_channel_arns) {
    fixture f;
    f.on_demand("orders");
    const auto arn = str(f.ok("CreateChannel", create_body("c", {source("orders")}))
                             .at("ChannelDescription")
                             .at("ChannelARN"));
    (void)f.ok("TagResource", {{"ResourceARN", arn}, {"Tags", {{"a", "1"}, {"b", "2"}}}});
    (void)f.ok("UntagResource", {{"ResourceARN", arn}, {"TagKeys", json::array{"a"}}});
    const auto tags = f.ok("ListTagsForResource", {{"ResourceARN", arn}});
    BOOST_TEST(json::serialize(tags.at("Tags")) == R"([{"Key":"b","Value":"2"}])");
}

BOOST_AUTO_TEST_CASE(record_codec_and_snapshot) {
    kin::channel_record c;
    c._id = 42;
    c._account = std::string(k_account);
    c._name = "to-s3";
    c._status = kin::channel_status::active;
    c._created_ms = 7;
    c._role_arn = std::string(k_role);
    c._destination = kin::channel_destination::s3_tables;
    c._streams.push_back({._stream = "orders",
                          ._stream_id = 3,
                          ._stream_created_ms = 5,
                          ._record_config = R"({"RecordFormatType":"JSON"})"});
    c._destination_config = R"({"DataFreshnessInSeconds":60})";
    c._logging_config = R"({"CloudWatchLogs":{"Enabled":false}})";
    c._tags = {{"k", "v"}};
    BOOST_TEST((kin::decode_channel_record(kin::encode_channel_record(c)) == c));

    BOOST_TEST(kin::channel_id_text(42) == "00000000-0000-4000-8000-00000000002a");
    BOOST_TEST(
        (kin::parse_channel_id(kin::channel_id_text(42)) == std::optional<std::uint64_t>{42}));
    BOOST_TEST(!kin::parse_channel_id("not-an-id"));

    // A command carrying it round-trips, and a machine with a channel
    // restores from its own snapshot unchanged.
    const kin::stream_command cmd = kin::channel_command{
        ._account = c._account, ._name = c._name, ._op = kin::channel_op::create, ._record = c};
    const auto back = kin::decode_command(kin::encode_command(cmd));
    BOOST_TEST((std::get<kin::channel_command>(back)._record == c));

    kin::stream_state_machine<> sm;
    std::uint64_t index = 0;
    const auto apply = [&](const kin::stream_command& x) {
        return kin::decode_result(sm.apply(kin::encode_command(x), ++index));
    };
    BOOST_TEST((apply(kin::create_stream_command{._account = c._account,
                                                 ._name = "orders",
                                                 ._shard_count = 1,
                                                 ._mode = kin::stream_mode::on_demand,
                                                 ._retention_hours = 24})
                    ._status == kin::apply_status::ok));
    const auto* stream = sm.find_stream(c._account, "orders");
    BOOST_REQUIRE(stream != nullptr);
    BOOST_TEST((apply(kin::set_stream_status_command{c._account, "orders", stream->_id,
                                                     kin::stream_status::active})
                    ._status == kin::apply_status::ok));
    auto create = std::get<kin::channel_command>(cmd);
    create._record._streams[0]._stream_id = stream->_id;
    const auto r = apply(create);
    BOOST_TEST((r._status == kin::apply_status::ok));
    BOOST_TEST((apply(create)._status == kin::apply_status::already_exists));
    BOOST_REQUIRE(sm.find_channel(c._account, c._name) != nullptr);
    BOOST_TEST(sm.find_channel(c._account, c._name)->_id == r._id);

    kin::stream_state_machine<> copy;
    copy.restore_from_snapshot(sm.get_state(), index);
    BOOST_TEST((copy.entries() == sm.entries()));

    // Another id is not this channel.
    BOOST_TEST((apply(kin::channel_command{._account = c._account,
                                           ._name = c._name,
                                           ._op = kin::channel_op::remove,
                                           ._id = r._id + 1})
                    ._status == kin::apply_status::not_found));
    BOOST_TEST((apply(kin::channel_command{._account = c._account,
                                           ._name = c._name,
                                           ._op = kin::channel_op::remove,
                                           ._id = r._id})
                    ._status == kin::apply_status::ok));
    BOOST_TEST(sm.find_channel(c._account, c._name) == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
