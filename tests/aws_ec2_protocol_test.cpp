// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The EC2 query protocol codec (`.kiro/specs/ec2-compatible-api/` task 2,
// Requirement 3.1): `Name.N` flattening at every depth, Action and Version,
// filters, tags and tag specifications, MaxResults and NextToken, the
// answer and error documents and their HTTP statuses. The requests here are
// copied from the recorded clients (services/ec2/tests/evidence/data/);
// the module's ec2_protocol_evidence_test decodes every recording.

#define BOOST_TEST_MODULE aws_ec2_protocol_test

#include <boost/test/unit_test.hpp>

#include <raft/aws_ec2_protocol.hpp>

#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace e = kythira::aws_ec2;
namespace q = kythira::aws_query;

namespace {

auto parse(std::string_view body) -> e::params {
    auto p = e::params::parse(body);
    BOOST_REQUIRE(p.has_value());
    return std::move(p).value();
}

// RunInstances as boto3 1.43.126 sent it (data/boto3.json, request 9).
constexpr std::string_view run_instances =
    "Action=RunInstances&Version=2016-11-15&ClientToken=evidence-run-1"
    "&ImageId=ami-0000000000000a001&InstanceType=t3.micro&MinCount=1&MaxCount=2"
    "&SubnetId=subnet-00000000000000003&UserData=IyEvYmluL3NoCmVjaG8gaGVsbG8K"
    "&BlockDeviceMapping.1.DeviceName=%2Fdev%2Fxvda&BlockDeviceMapping.1.Ebs.VolumeSize=8"
    "&BlockDeviceMapping.1.Ebs.VolumeType=gp3&BlockDeviceMapping.1.Ebs.DeleteOnTermination=true"
    "&BlockDeviceMapping.2.DeviceName=%2Fdev%2Fsdb&BlockDeviceMapping.2.VirtualName=ephemeral0"
    "&TagSpecification.1.ResourceType=instance&TagSpecification.1.Tag.1.Key=Name"
    "&TagSpecification.1.Tag.1.Value=evidence&TagSpecification.2.ResourceType=volume"
    "&TagSpecification.2.Tag.1.Key=Name&TagSpecification.2.Tag.1.Value=evidence-root";

}  // namespace

BOOST_AUTO_TEST_SUITE(requests)

BOOST_AUTO_TEST_CASE(reads_action_and_version) {
    auto r = e::read_request(parse(run_instances));
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->action == "RunInstances");
    BOOST_TEST(r->version == "2016-11-15");
    BOOST_TEST(*r->args.get("ImageId") == "ami-0000000000000a001");
    BOOST_TEST(*r->args.get("BlockDeviceMapping.1.DeviceName") == "/dev/xvda");
}

BOOST_AUTO_TEST_CASE(refuses_a_missing_action_or_version) {
    BOOST_TEST(e::read_request(parse("Version=2016-11-15")).err().code == "MissingAction");
    BOOST_TEST(e::read_request(parse("Action=&Version=2016-11-15")).err().code == "MissingAction");
    BOOST_TEST(e::read_request(parse("Action=DescribeRegions")).err().code == "MissingParameter");
    const auto old = e::read_request(parse("Action=DescribeRegions&Version=2014-10-01"));
    BOOST_TEST(old.err().code == "NoSuchVersion");
    BOOST_TEST(old.err().message.find("2014-10-01") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(refuses_a_malformed_body) {
    BOOST_TEST(e::params::parse("A=%zz").err().code == "MalformedQueryString");
    BOOST_TEST(e::params::parse("InstanceId.1=a&InstanceId.1=b").err().code ==
               "MalformedQueryString");
    BOOST_TEST(e::params::parse("").has_value());
}

BOOST_AUTO_TEST_CASE(parameter_order_does_not_matter) {
    // The Go SDK sorts parameters by name, so Version comes late
    // (data/go-sdk-v2.json).
    const auto go = parse(
        "Action=CreateTags&ResourceId.1=i-00000000000000007&ResourceId.2=vol-00000000000000004"
        "&Tag.1.Key=stage&Tag.1.Value=evidence&Tag.2.Key=flag&Version=2016-11-15");
    const auto cli = parse(
        "Action=CreateTags&Version=2016-11-15&ResourceId.1=i-00000000000000007"
        "&ResourceId.2=vol-00000000000000004&Tag.1.Key=stage&Tag.1.Value=evidence&Tag.2.Key=flag");
    BOOST_TEST((go == cli));
}

BOOST_AUTO_TEST_CASE(encode_round_trips) {
    const auto p = parse(run_instances);
    const auto again = e::params::parse(p.encode());
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST((*again == p));
    BOOST_TEST(p.encode().find("%2Fdev%2Fxvda") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(flattening)

BOOST_AUTO_TEST_CASE(lists_come_back_in_index_order) {
    const auto p = parse("InstanceId.2=b&InstanceId.1=a&InstanceId.10=c&Other=x");
    const auto ids = p.list("InstanceId");
    BOOST_REQUIRE(ids.has_value());
    BOOST_TEST((*ids == std::vector<std::string>{"a", "b", "c"}));
    BOOST_TEST(p.list("Missing")->empty());
    BOOST_TEST(p.has("InstanceId"));
    BOOST_TEST(!p.has("Instance"));
}

BOOST_AUTO_TEST_CASE(a_bad_index_is_refused) {
    for (const auto* body : {"InstanceId.0=a", "InstanceId.01=a", "InstanceId.x=a",
                             "InstanceId.1.Foo=a", "InstanceId=a&InstanceId.1=b", "InstanceId.-1=a",
                             "InstanceId.99999999999999999999999=a"}) {
        BOOST_TEST_CONTEXT(body) {
            const auto r = parse(body).list("InstanceId");
            BOOST_REQUIRE(!r.has_value());
            BOOST_TEST(r.err().code == "InvalidParameterValue");
        }
    }
}

BOOST_AUTO_TEST_CASE(structures_nest) {
    const auto p = parse(run_instances);
    const auto bdm = p.structs("BlockDeviceMapping");
    BOOST_REQUIRE(bdm.has_value());
    BOOST_REQUIRE(bdm->size() == 2);
    const auto& root = (*bdm)[0];
    BOOST_TEST(*root.get("DeviceName") == "/dev/xvda");
    const auto ebs = root.sub("Ebs");
    BOOST_TEST(*ebs.get("VolumeSize") == "8");
    BOOST_TEST(*ebs.boolean("DeleteOnTermination").value() == true);
    BOOST_TEST(*ebs.integer("VolumeSize", 1, 16384).value() == 8);
    BOOST_TEST(*(*bdm)[1].get("VirtualName") == "ephemeral0");
    BOOST_TEST(!(*bdm)[1].has("Ebs"));
}

BOOST_AUTO_TEST_CASE(a_structure_list_needs_fields) {
    BOOST_TEST(parse("BlockDeviceMapping.1=x").structs("BlockDeviceMapping").err().code ==
               "InvalidParameterValue");
    BOOST_TEST(parse("BlockDeviceMapping.1.=x").structs("BlockDeviceMapping").err().code ==
               "InvalidParameterValue");
    BOOST_TEST(
        parse("BlockDeviceMapping.z.DeviceName=x").structs("BlockDeviceMapping").err().code ==
        "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(booleans_and_integers) {
    const auto p = parse("DryRun=true&Force=false&Bad=yes&Size=16&Big=99999&Neg=-1&Empty=");
    BOOST_TEST(*p.boolean("DryRun").value() == true);
    BOOST_TEST(*p.boolean("Force").value() == false);
    BOOST_TEST(!p.boolean("Missing").value().has_value());
    BOOST_TEST(p.boolean("Bad").err().code == "InvalidParameterValue");
    BOOST_TEST(*p.integer("Size", 1, 16384).value() == 16);
    BOOST_TEST(p.integer("Big", 1, 16384).err().code == "InvalidParameterValue");
    BOOST_TEST(p.integer("Neg", 0, 10).err().code == "InvalidParameterValue");
    BOOST_TEST(p.integer("Empty", 0, 10).err().code == "InvalidParameterValue");
    BOOST_TEST(*p.integer("Neg", -5, 10).value() == -1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(common_inputs)

BOOST_AUTO_TEST_CASE(filters_with_values) {
    // DescribeInstances as every client sent it (request 11).
    const auto p = parse(
        "Action=DescribeInstances&Version=2016-11-15&InstanceId.1=i-00000000000000007"
        "&InstanceId.2=i-00000000000000008&Filter.1.Name=instance-state-name"
        "&Filter.1.Value.1=pending&Filter.1.Value.2=running&Filter.2.Name=tag%3AName"
        "&Filter.2.Value.1=evidence");
    const auto f = e::filters(p);
    BOOST_REQUIRE(f.has_value());
    BOOST_REQUIRE(f->size() == 2);
    BOOST_TEST(((*f)[0] == e::filter{"instance-state-name", {"pending", "running"}}));
    BOOST_TEST(((*f)[1] == e::filter{"tag:Name", {"evidence"}}));
}

BOOST_AUTO_TEST_CASE(a_filter_needs_a_name_and_known_fields) {
    BOOST_TEST(e::filters(parse("Filter.1.Value.1=x")).err().code == "InvalidParameterValue");
    BOOST_TEST(e::filters(parse("Filter.1.Name=a&Filter.1.Values.1=x")).err().code ==
               "InvalidParameterValue");
    BOOST_TEST(e::filters(parse("Filter.1.Name=a&Filter.1.Value=x")).err().code ==
               "InvalidParameterValue");
    // No values: kept, and matches nothing (the front end's rule).
    const auto empty = e::filters(parse("Filter.1.Name=a"));
    BOOST_REQUIRE(empty.has_value());
    BOOST_TEST((*empty)[0].values.empty());
}

BOOST_AUTO_TEST_CASE(tags_with_and_without_values) {
    const auto t =
        e::tags(parse("Tag.1.Key=stage&Tag.1.Value=evidence&Tag.2.Key=flag"
                      "&Tag.3.Key=empty&Tag.3.Value="));
    BOOST_REQUIRE(t.has_value());
    BOOST_REQUIRE(t->size() == 3);
    BOOST_TEST(((*t)[0] == e::tag{"stage", "evidence"}));
    BOOST_TEST(!(*t)[1].value.has_value());
    BOOST_TEST(((*t)[2] == e::tag{"empty", ""}));
    BOOST_TEST(e::tags(parse("Tag.1.Value=v")).err().code == "InvalidParameterValue");
    BOOST_TEST(e::tags(parse("Tag.1.Key=k&Tag.1.Colour=v")).err().code == "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(tag_specifications_per_resource_type) {
    const auto s = e::tag_specifications(parse(run_instances));
    BOOST_REQUIRE(s.has_value());
    BOOST_REQUIRE(s->size() == 2);
    BOOST_TEST((*s)[0].resource_type == "instance");
    BOOST_TEST(((*s)[0].tags == std::vector<e::tag>{{"Name", "evidence"}}));
    BOOST_TEST((*s)[1].resource_type == "volume");
    BOOST_TEST(e::tag_specifications(parse("TagSpecification.1.Tag.1.Key=k")).err().code ==
               "InvalidParameterValue");
    BOOST_TEST(e::tag_specifications(parse("TagSpecification.1.ResourceType=vpc"
                                           "&TagSpecification.2.ResourceType=vpc"))
                   .err()
                   .code == "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(max_results_and_next_token) {
    const std::array<unsigned char, 32> key{1, 2, 3};
    const q::marker_sealer sealer(key);
    const auto token = sealer.seal("DescribeVolumes/123456789012", "vol-00000000000000004");
    const auto p = parse("MaxResults=5&NextToken=" + q::url_encode(token));
    BOOST_TEST(*e::max_results(p, 5, 500).value() == 5);
    BOOST_TEST(e::max_results(p, 6, 500).err().code == "InvalidParameterValue");
    BOOST_TEST(!e::max_results(parse(""), 5, 500).value().has_value());
    const auto last = e::open_next_token(p, sealer, "DescribeVolumes/123456789012");
    BOOST_REQUIRE(last.has_value());
    BOOST_TEST(**last == "vol-00000000000000004");
    // Another list's token, or another account's, does not open.
    BOOST_TEST(e::open_next_token(p, sealer, "DescribeVolumes/210987654321").err().code ==
               "InvalidPaginationToken");
    BOOST_TEST(e::open_next_token(parse("NextToken=evidence-page-2"), sealer, "x").err().code ==
               "InvalidPaginationToken");
    BOOST_TEST(!e::open_next_token(parse(""), sealer, "x").value().has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(answers)

BOOST_AUTO_TEST_CASE(response_document) {
    q::xml_writer w;
    w.open("vpc").element("vpcId", "vpc-00000000000000001").element("state", "available");
    e::tag_set(w, std::vector<std::pair<std::string, std::string>>{{"Name", "a<b"}});
    w.close();
    const auto xml = e::response_xml("CreateVpc", "req-1", w.str());
    BOOST_TEST(xml ==
               "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<CreateVpcResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"
               "<requestId>req-1</requestId><vpc><vpcId>vpc-00000000000000001</vpcId>"
               "<state>available</state><tagSet><item><key>Name</key><value>a&lt;b</value>"
               "</item></tagSet></vpc></CreateVpcResponse>");
    BOOST_TEST(e::response_xml("DeleteVpc", "r", e::return_true).find("<return>true</return>") !=
               std::string::npos);
}

BOOST_AUTO_TEST_CASE(empty_lists_are_written) {
    q::xml_writer w;
    e::item_list(w, "instancesSet", std::vector<int>{}, [](q::xml_writer&, int) {});
    BOOST_TEST(w.str() == "<instancesSet></instancesSet>");
    q::xml_writer w2;
    e::item_list(w2, "set", std::vector<int>{1, 2},
                 [](q::xml_writer& x, int n) { x.element("n", std::to_string(n)); });
    BOOST_TEST(w2.str() == "<set><item><n>1</n></item><item><n>2</n></item></set>");
}

BOOST_AUTO_TEST_CASE(error_document_and_status) {
    BOOST_TEST(e::error_xml("UnsupportedOperation", "No <security> groups.", "req-2") ==
               "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<Response><Errors><Error><Code>UnsupportedOperation</Code>"
               "<Message>No &lt;security&gt; groups.</Message></Error></Errors>"
               "<RequestID>req-2</RequestID></Response>");
    BOOST_TEST(e::http_status("UnsupportedOperation") == 400U);
    BOOST_TEST(e::http_status("DryRunOperation") == 412U);
    BOOST_TEST(e::http_status("UnauthorizedOperation") == 403U);
    BOOST_TEST(e::http_status("AuthFailure") == 401U);
    BOOST_TEST(e::http_status("RequestLimitExceeded") == 503U);
    BOOST_TEST(e::http_status("InsufficientInstanceCapacity") == 500U);
    BOOST_TEST(e::retryable("InternalError"));
    BOOST_TEST(!e::retryable("IdempotentParameterMismatch"));
    BOOST_TEST(e::dry_run_success().code == "DryRunOperation");
    static_assert(e::http_status("Unavailable") == 503U);
}

BOOST_AUTO_TEST_CASE(timestamps) {
    using namespace std::chrono;
    const sys_days day = year{2026} / November / 27;
    BOOST_TEST(e::timestamp(day + hours{1} + minutes{2} + seconds{3} + milliseconds{45}) ==
               "2026-11-27T01:02:03.045Z");
    BOOST_TEST(e::timestamp(system_clock::time_point(day)) == "2026-11-27T00:00:00.000Z");
}

BOOST_AUTO_TEST_SUITE_END()
