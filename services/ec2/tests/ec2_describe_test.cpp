// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// What every EC2 describe shares (`.kiro/specs/ec2-compatible-api/` task 4,
// Requirements 2.4, 4.4 and 4.5): tag rules and CreateTags/DeleteTags
// semantics, TagSpecifications on create, the filter engine with EC2's
// wildcards and tag filters, sealed paging, and the region, zone and
// instance-type describes through the front end.

#define BOOST_TEST_MODULE ec2_describe_test
#include <boost/test/unit_test.hpp>

#include <kythira/ec2/ec2_filters.hpp>
#include <kythira/ec2/ec2_region.hpp>
#include <kythira/ec2/ec2_tags.hpp>

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ec2 = kythira::ec2;
namespace e = kythira::aws_ec2;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;

namespace {

auto parse(std::string_view body) -> e::params {
    return e::params::parse(body).value();
}

auto tag(std::string k, std::optional<std::string> v = std::nullopt) -> e::tag {
    return {std::move(k), std::move(v)};
}

auto sealer() -> std::shared_ptr<const kythira::aws_query::marker_sealer> {
    static const std::array<unsigned char, 32> key{1, 2, 3};
    return std::make_shared<const kythira::aws_query::marker_sealer>(key);
}

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

struct allow_all {
    az::principal_context who;
    allow_all() {
        who.account = "111122223333";
        who.arn = "arn:aws:iam::111122223333:user/alice";
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

struct service_fixture {
    allow_all auth;
    ec2::front_end<allow_all> fe{ec2::front_end_config{}, auth};
    ec2::region_service svc;

    explicit service_fixture(
        ec2::instance_type_catalog types = ec2::instance_type_catalog::defaults())
        : svc(ec2::region_config{"us-east-1",
                                 "ec2.us-east-1.amazonaws.com",
                                 {{"us-east-1a", "use1-az1"}, {"us-east-1b", "use1-az2"}}},
              std::move(types), sealer()) {
        svc.register_with(fe);
    }

    auto call(std::string body) -> ec2::front_end_response {
        ec2::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = std::move(body) + "&Version=2016-11-15";
        r._headers = {{"Content-Type", "application/x-www-form-urlencoded"}};
        return fe.handle(r);
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(tags)

BOOST_AUTO_TEST_CASE(limits_are_ec2s) {
    BOOST_TEST(!ec2::check_tag(tag(std::string(127, 'k'), std::string(255, 'v'))).has_value());
    BOOST_TEST(ec2::check_tag(tag(std::string(128, 'k'))).has_value());
    BOOST_TEST(ec2::check_tag(tag("k", std::string(256, 'v'))).has_value());
    // Characters, not bytes: 127 two-byte letters fit.
    std::string accented;
    for (int i = 0; i < 127; ++i) {
        accented += "\xc3\xa9";
    }
    BOOST_TEST(!ec2::check_tag(tag(accented)).has_value());
    BOOST_TEST(ec2::check_tag(tag("aws:cloudformation:stack-name")).has_value());
    BOOST_TEST(ec2::check_tag(tag("AWS:x")).has_value());
    BOOST_TEST(!ec2::check_tag(tag("awsome")).has_value());
    BOOST_TEST(ec2::check_tag(tag(""))->code == "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(create_tags_adds_replaces_and_counts_after_the_change) {
    ec2::tag_map m;
    BOOST_TEST(!ec2::create_tags(m, {tag("Name", "web"), tag("flag")}).has_value());
    BOOST_TEST(m.at("Name") == "web");
    BOOST_TEST(m.at("flag").empty());
    for (int i = 0; i < 48; ++i) {
        m.emplace("k" + std::to_string(i), "v");
    }
    BOOST_TEST(m.size() == 50U);
    BOOST_TEST(!ec2::create_tags(m, {tag("Name", "api")}).has_value());  // a replace fits
    BOOST_TEST(m.at("Name") == "api");
    const auto full = ec2::create_tags(m, {tag("one-more", "x")});
    BOOST_REQUIRE(full.has_value());
    BOOST_TEST(full->code == "TagLimitExceeded");
    BOOST_TEST(!m.contains("one-more"));
    BOOST_TEST(ec2::create_tags(m, {tag("ok", "1"), tag("aws:no", "2")}).has_value());
    BOOST_TEST(!m.contains("ok"));  // nothing applied
}

BOOST_AUTO_TEST_CASE(delete_tags_matches_values_when_given) {
    ec2::tag_map m{{"a", "1"}, {"b", "2"}, {"c", ""}, {"aws:keep", "x"}};
    BOOST_TEST(!ec2::delete_tags(m, {tag("a", "other")}).has_value());
    BOOST_TEST(m.contains("a"));
    BOOST_TEST(!ec2::delete_tags(m, {tag("a", "1"), tag("b"), tag("missing")}).has_value());
    BOOST_TEST(!m.contains("a"));
    BOOST_TEST(!m.contains("b"));
    BOOST_TEST(!ec2::delete_tags(m, {tag("c", "x")}).has_value());
    BOOST_TEST(m.contains("c"));  // the empty value matches only the empty value
    BOOST_TEST(!ec2::delete_tags(m, {tag("c", "")}).has_value());
    BOOST_TEST(!m.contains("c"));
    BOOST_TEST(ec2::delete_tags(m, {tag("aws:keep")}).has_value());
    m.emplace("d", "4");
    BOOST_TEST(!ec2::delete_tags(m, {}).has_value());  // no Tag.N: all but reserved
    BOOST_TEST((m == ec2::tag_map{{"aws:keep", "x"}}));
}

BOOST_AUTO_TEST_CASE(tag_specifications_name_only_what_the_create_makes) {
    const auto p = parse(
        "TagSpecification.1.ResourceType=instance&TagSpecification.1.Tag.1.Key=Name"
        "&TagSpecification.1.Tag.1.Value=web&TagSpecification.2.ResourceType=volume"
        "&TagSpecification.2.Tag.1.Key=stage");
    const auto ok = ec2::tags_on_create(p, {"instance", "volume", "network-interface"});
    BOOST_REQUIRE(ok.has_value());
    BOOST_TEST(ok->at("instance").at("Name") == "web");
    BOOST_TEST(ok->at("volume").at("stage").empty());
    const auto bad = ec2::tags_on_create(p, {"volume"});
    BOOST_REQUIRE(!bad.has_value());
    BOOST_TEST(bad.err().message ==
               "'instance' is not a valid taggable resource type for this operation.");
    const auto reserved = ec2::tags_on_create(parse("TagSpecification.1.ResourceType=volume"
                                                    "&TagSpecification.1.Tag.1.Key=aws%3Ax"),
                                              {"volume"});
    BOOST_TEST(!reserved.has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(filters)

BOOST_AUTO_TEST_CASE(wildcards_are_ec2s) {
    BOOST_TEST(ec2::wildcard_match("web-*", "web-01"));
    BOOST_TEST(ec2::wildcard_match("*", ""));
    BOOST_TEST(ec2::wildcard_match("w?b", "web"));
    BOOST_TEST(!ec2::wildcard_match("w?b", "wb"));
    BOOST_TEST(ec2::wildcard_match("*-0?", "api-07"));
    BOOST_TEST(ec2::wildcard_match("a*b*c", "aXbYbZc"));
    BOOST_TEST(!ec2::wildcard_match("a*b*c", "aXbYbZ"));
    BOOST_TEST(ec2::wildcard_match("literal\\*", "literal*"));
    BOOST_TEST(!ec2::wildcard_match("literal\\*", "literalX"));
    BOOST_TEST(ec2::wildcard_match("q\\?", "q?"));
    BOOST_TEST(!ec2::wildcard_match("Web", "web"));  // case-sensitive
}

BOOST_AUTO_TEST_CASE(filters_or_values_and_and_names) {
    const ec2::filter_names names{"instance-state-name", "instance-type", "tag:", "tag-key",
                                  "tag-value"};
    const ec2::tag_map tags{{"Name", "web-01"}, {"team", "core"}};
    const ec2::field_lookup fields = [](std::string_view n) -> std::vector<std::string> {
        if (n == "instance-state-name") {
            return {"running"};
        }
        return {"k1.small"};
    };
    const auto match = [&](std::string_view body) {
        const auto fs = ec2::filter_set::read(parse(body), names);
        BOOST_REQUIRE(fs.has_value());
        return fs->matches(fields, tags);
    };
    BOOST_TEST(match(""));
    BOOST_TEST(
        match("Filter.1.Name=instance-state-name&Filter.1.Value.1=pending"
              "&Filter.1.Value.2=running"));
    BOOST_TEST(!match("Filter.1.Name=instance-state-name&Filter.1.Value.1=stopped"));
    BOOST_TEST(
        !match("Filter.1.Name=instance-state-name&Filter.1.Value.1=running"
               "&Filter.2.Name=instance-type&Filter.2.Value.1=k1.large"));
    BOOST_TEST(match("Filter.1.Name=tag%3AName&Filter.1.Value.1=web-*"));
    BOOST_TEST(!match("Filter.1.Name=tag%3Amissing&Filter.1.Value.1=*"));
    BOOST_TEST(match("Filter.1.Name=tag-key&Filter.1.Value.1=team"));
    BOOST_TEST(match("Filter.1.Name=tag-value&Filter.1.Value.1=co*"));
    BOOST_TEST(!match("Filter.1.Name=instance-state-name"));  // no values: nothing
    const auto bad =
        ec2::filter_set::read(parse("Filter.1.Name=owner-id&Filter.1.Value.1=x"), names);
    BOOST_REQUIRE(!bad.has_value());
    BOOST_TEST(bad.err().code == "InvalidParameterValue");
    BOOST_TEST(bad.err().message == "The filter 'owner-id' is invalid");
    BOOST_TEST(!ec2::filter_set::read(parse("Filter.1.Name=tag%3A&Filter.1.Value.1=x"), names)
                    .has_value());
}

BOOST_AUTO_TEST_CASE(pages_are_sealed_and_resume_after_their_key) {
    const auto s = sealer();
    std::vector<std::pair<std::string, int>> items;
    for (int i = 0; i < 12; ++i) {
        items.emplace_back("vol-" + std::to_string(100 + i), i);
    }
    const auto ctx = ec2::page_context("DescribeVolumes", "111122223333");
    auto req = ec2::read_page(parse("MaxResults=5"), *s, ctx, 5, 1000);
    BOOST_REQUIRE(req.has_value());
    std::vector<int> all;
    std::optional<std::string> token;
    int pages = 0;
    do {
        auto body = std::string("MaxResults=5");
        if (token) {
            body += "&NextToken=" + kythira::aws_query::url_encode(*token);
        }
        const auto r = ec2::read_page(parse(body), *s, ctx, 5, 1000);
        BOOST_REQUIRE(r.has_value());
        const auto pg = ec2::paginate(items, *r, *s, ctx);
        all.insert(all.end(), pg._items.begin(), pg._items.end());
        token = pg._next_token;
        ++pages;
    } while (token);
    BOOST_TEST(pages == 3);
    BOOST_TEST(all.size() == 12U);
    BOOST_TEST(std::is_sorted(all.begin(), all.end()));
    // Another describe's or account's token is refused.
    const auto first = ec2::paginate(items, *req, *s, ctx)._next_token.value();
    const auto enc = kythira::aws_query::url_encode(first);
    const auto other =
        ec2::read_page(parse("NextToken=" + enc), *s,
                       ec2::page_context("DescribeVolumes", "444455556666"), 5, 1000);
    BOOST_REQUIRE(!other.has_value());
    BOOST_TEST(other.err().code == "InvalidPaginationToken");
    BOOST_TEST(!ec2::read_page(parse("MaxResults=4"), *s, ctx, 5, 1000).has_value());
    BOOST_TEST(ec2::next_token_xml(std::nullopt).empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(region_describes)

BOOST_FIXTURE_TEST_CASE(describe_regions_names_this_region, service_fixture) {
    const auto r = call("Action=DescribeRegions");
    BOOST_TEST(r._status == 200U);
    BOOST_TEST(element(r._body, "regionName") == "us-east-1");
    BOOST_TEST(element(r._body, "regionEndpoint") == "ec2.us-east-1.amazonaws.com");
    BOOST_TEST(element(r._body, "optInStatus") == "opt-in-not-required");
    BOOST_TEST(call("Action=DescribeRegions&RegionName.1=us-east-1")._status == 200U);
    BOOST_TEST(element(call("Action=DescribeRegions&RegionName.1=eu-west-1")._body, "Code") ==
               "InvalidParameterValue");
    const auto none =
        call("Action=DescribeRegions&Filter.1.Name=region-name&Filter.1.Value.1=eu-*");
    BOOST_TEST(count(none._body, "<item>") == 0U);
    BOOST_TEST(none._body.find("<regionInfo></regionInfo>") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(describe_zones_lists_and_filters, service_fixture) {
    const auto all = call("Action=DescribeAvailabilityZones");
    BOOST_TEST(all._status == 200U);
    BOOST_TEST(count(all._body, "<zoneName>") == 2U);
    BOOST_TEST(element(all._body, "zoneState") == "available");
    BOOST_TEST(element(all._body, "zoneId") == "use1-az1");
    const auto one = call("Action=DescribeAvailabilityZones&ZoneName.1=us-east-1b");
    BOOST_TEST(count(one._body, "<zoneName>") == 1U);
    BOOST_TEST(element(one._body, "zoneName") == "us-east-1b");
    const auto by_id = call("Action=DescribeAvailabilityZones&ZoneId.1=use1-az1");
    BOOST_TEST(element(by_id._body, "zoneName") == "us-east-1a");
    const auto filtered =
        call("Action=DescribeAvailabilityZones&Filter.1.Name=zone-name&Filter.1.Value.1=*b");
    BOOST_TEST(count(filtered._body, "<zoneName>") == 1U);
    const auto bad = call("Action=DescribeAvailabilityZones&ZoneName.1=us-east-1z");
    BOOST_TEST(element(bad._body, "Code") == "InvalidParameterValue");
    BOOST_TEST(element(bad._body, "Message") == "Invalid availability zone: [us-east-1z]");
}

BOOST_FIXTURE_TEST_CASE(describe_instance_types_serves_the_catalog, service_fixture) {
    const auto all = call("Action=DescribeInstanceTypes");
    BOOST_TEST(all._status == 200U);
    BOOST_TEST(count(all._body, "<instanceType>") == 6U);
    const auto one = call("Action=DescribeInstanceTypes&InstanceType.1=k1.medium");
    BOOST_TEST(element(one._body, "instanceType") == "k1.medium");
    BOOST_TEST(element(one._body, "defaultVCpus") == "2");
    BOOST_TEST(element(one._body, "sizeInMiB") == "4096");
    BOOST_TEST(element(one._body, "supportedArchitectures") == "<item>x86_64</item>");
    const auto missing = call("Action=DescribeInstanceTypes&InstanceType.1=t3.micro");
    BOOST_TEST(element(missing._body, "Code") == "InvalidInstanceType");
    BOOST_TEST(element(missing._body, "Message") ==
               "The following supplied instance types do not exist: [t3.micro]");
    const auto big = call(
        "Action=DescribeInstanceTypes&Filter.1.Name=vcpu-info.default-vcpus"
        "&Filter.1.Value.1=8&Filter.1.Value.2=16");
    BOOST_TEST(count(big._body, "<instanceType>") == 2U);
    // Paging: five, then the sixth with no further token.
    const auto p1 = call("Action=DescribeInstanceTypes&MaxResults=5");
    BOOST_TEST(count(p1._body, "<instanceType>") == 5U);
    const auto token = element(p1._body, "nextToken");
    BOOST_REQUIRE(!token.empty());
    const auto p2 = call("Action=DescribeInstanceTypes&MaxResults=5&NextToken=" +
                         kythira::aws_query::url_encode(token));
    BOOST_TEST(count(p2._body, "<instanceType>") == 1U);
    BOOST_TEST(element(p2._body, "nextToken").empty());
    BOOST_TEST(element(call("Action=DescribeInstanceTypes&MaxResults=101")._body, "Code") ==
               "InvalidParameterValue");
}

BOOST_AUTO_TEST_CASE(aliases_describe_as_themselves) {
    std::string error;
    const auto cat = ec2::instance_type_catalog::parse(
        "# Kythira types\n"
        "type k1.small cores=1 memory=2\n"
        "type g1.large cores=8 memory=64 arch=arm64 devices=gpu:1,nvme:2\n"
        "alias t3.micro k1.small\n",
        &error);
    BOOST_REQUIRE_MESSAGE(cat.has_value(), error);
    const auto t = cat->find("t3.micro");
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(t->_name == "t3.micro");
    BOOST_TEST(t->_cores == 1U);
    const auto g = cat->find("g1.large");
    BOOST_TEST(g->_arch == "arm64");
    BOOST_TEST((g->_devices == std::vector<ec2::device_count>{{"gpu", 1}, {"nvme", 2}}));
    BOOST_TEST(cat->all().size() == 3U);

    service_fixture f(*cat);
    const auto r = f.call("Action=DescribeInstanceTypes&InstanceType.1=t3.micro");
    BOOST_TEST(element(r._body, "instanceType") == "t3.micro");
}

BOOST_AUTO_TEST_CASE(bad_catalogs_say_which_line) {
    std::string error;
    BOOST_TEST(!ec2::instance_type_catalog::parse("type a cores=1\n", &error).has_value());
    BOOST_TEST(error == "line 1: type a needs cores and memory");
    BOOST_TEST(!ec2::instance_type_catalog::parse("type a cores=1 memory=1\nalias b c\n", &error)
                    .has_value());
    BOOST_TEST(error == "line 2: alias b names unknown type c");
    BOOST_TEST(!ec2::instance_type_catalog::parse("type a cores=0 memory=1", &error).has_value());
    BOOST_TEST(!ec2::instance_type_catalog::parse("flavor a", &error).has_value());
    BOOST_TEST(!ec2::instance_type_catalog::parse("type a cores=1 memory=1 arch=mips", &error)
                    .has_value());
    BOOST_TEST(!ec2::instance_type_catalog::parse("", &error).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
