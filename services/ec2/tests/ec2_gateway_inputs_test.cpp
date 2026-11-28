// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// What the EC2 front end is configured with (`.kiro/specs/ec2-compatible-api/`
// task 3, Requirements 2.2, 2.3 and 3.3): the `ec2` action table generated
// from AWS's Service Authorization Reference, the operation-to-action map
// against the pinned model, resource ARNs, the static-key roles, EC2's
// throttling buckets, and the `aws` profile with its cluster and account
// switches.

#define BOOST_TEST_MODULE ec2_gateway_inputs_test
#include <boost/test/unit_test.hpp>

#include <kythira/ec2/ec2_actions.hpp>
#include <kythira/ec2/ec2_profile.hpp>
#include <kythira/ec2/ec2_throttle.hpp>
#include <kythira/ec2/model/operations.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace ec2 = kythira::ec2;
namespace e = kythira::aws_ec2;
using namespace std::chrono_literals;

BOOST_TEST_DONT_PRINT_LOG_VALUE(kythira::ec2::bucket_rate)
BOOST_TEST_DONT_PRINT_LOG_VALUE(kythira::ec2::ec2_profile)

namespace {

auto entry(std::string_view action) -> const kythira::aws_auth::action_entry& {
    static const auto table = ec2::ec2_actions();
    const auto it = std::find_if(table.actions.begin(), table.actions.end(),
                                 [&](const auto& a) { return a.name == action; });
    BOOST_REQUIRE(it != table.actions.end());
    return *it;
}

auto has(const std::vector<std::string>& v, std::string_view s) -> bool {
    return std::find(v.begin(), v.end(), s) != v.end();
}

auto parse(std::string_view body) -> e::params {
    return e::params::parse(body).value();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(action_table)

BOOST_AUTO_TEST_CASE(tables_are_sorted_for_lookup) {
    BOOST_TEST(std::ranges::is_sorted(ec2::k_actions, {}, &ec2::action_info::_name));
    BOOST_TEST(std::ranges::is_sorted(ec2::k_resource_types, {}, &ec2::resource_type::_name));
    BOOST_TEST(std::ranges::is_sorted(ec2::k_condition_keys));
    BOOST_TEST(
        std::ranges::is_sorted(ec2::k_operation_actions, {}, &ec2::operation_actions::_operation));
    for (const auto& a : ec2::k_actions) {
        BOOST_TEST(a._resources_at + a._resources_n <= ec2::k_action_resources.size());
        BOOST_TEST(a._keys_at + a._keys_n <= ec2::k_action_keys.size());
    }
}

BOOST_AUTO_TEST_CASE(run_instances_names_every_resource_ec2_authorizes) {
    // Requirement 3.3: the instance, image, subnet, network interfaces,
    // volumes and key pair, and the security groups.
    const auto* run = ec2::find_action("RunInstances");
    BOOST_REQUIRE(run != nullptr);
    for (const auto* type : {"instance", "image", "subnet", "network-interface", "volume",
                             "key-pair", "security-group"}) {
        BOOST_TEST(ec2::acts_on(*run, type), type);
    }
    BOOST_TEST(run->_write);
    for (const auto* key : {"ec2:InstanceType", "aws:RequestTag/${TagKey}", "aws:TagKeys",
                            "ec2:ResourceTag/${TagKey}", "ec2:Region", "ec2:InstanceProfile"}) {
        BOOST_TEST(ec2::has_condition_key(*run, key), key);
    }
    const auto& e = entry("RunInstances");
    BOOST_TEST(has(e.resource_templates,
                   "arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}"));
    BOOST_TEST(has(e.condition_keys, "ec2:InstanceType"));
}

BOOST_AUTO_TEST_CASE(volume_actions_carry_their_keys) {
    const auto* create = ec2::find_action("CreateVolume");
    BOOST_REQUIRE(create != nullptr);
    BOOST_TEST(ec2::has_condition_key(*create, "ec2:Encrypted"));
    BOOST_TEST(ec2::has_condition_key(*create, "ec2:VolumeType"));
    BOOST_TEST(ec2::acts_on(*create, "volume"));
}

BOOST_AUTO_TEST_CASE(describes_have_no_resource_types) {
    const auto* d = ec2::find_action("DescribeInstances");
    BOOST_REQUIRE(d != nullptr);
    BOOST_TEST(d->_resources_n == 0U);
    BOOST_TEST(!d->_write);
    BOOST_TEST(entry("DescribeInstances").resource_templates == std::vector<std::string>{"*"});
}

BOOST_AUTO_TEST_CASE(every_model_operation_has_its_actions) {
    for (const auto& op : ec2::model::operations) {
        BOOST_TEST_CONTEXT(op._name) {
            const auto* acts = ec2::find_operation_actions(op._name);
            BOOST_REQUIRE(acts != nullptr);
            // The reference names no action for one Capacity Manager read,
            // out of scope (doc/unsupported.md); every other operation has
            // at least one.
            BOOST_TEST(acts->_actions[0].empty() ==
                       (op._name == "GetCapacityManagerSupportabilityScores"));
            for (const auto a : acts->_actions) {
                BOOST_TEST((a.empty() || ec2::find_action(a) != nullptr));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(run_instances_checks_tags_and_pass_role) {
    const auto* run = ec2::find_operation_actions("RunInstances");
    BOOST_REQUIRE(run != nullptr);
    BOOST_TEST(run->_pass_role);
    BOOST_TEST(run->_writes);
    BOOST_TEST(std::ranges::count(run->_actions, "CreateTags") == 1);
    BOOST_TEST(std::ranges::count(run->_actions, "RunInstances") == 1);
    BOOST_TEST(!ec2::find_operation_actions("DescribeInstances")->_writes);
    BOOST_TEST(!ec2::find_operation_actions("CreateVolume")->_pass_role);
    BOOST_TEST(ec2::find_operation_actions("AssociateIamInstanceProfile")->_pass_role);
}

BOOST_AUTO_TEST_CASE(resource_arns_follow_the_reference) {
    BOOST_TEST(*ec2::resource_arn("instance", "aws", "us-east-1", "111122223333", "i-1") ==
               "arn:aws:ec2:us-east-1:111122223333:instance/i-1");
    BOOST_TEST(*ec2::resource_arn("snapshot", "aws", "us-east-1", "111122223333", "snap-1") ==
               "arn:aws:ec2:us-east-1::snapshot/snap-1");
    BOOST_TEST(*ec2::resource_arn("key-pair", "aws-cn", "cn-north-1", "1", "deploy") ==
               "arn:aws-cn:ec2:cn-north-1:1:key-pair/deploy");
    BOOST_TEST(!ec2::resource_arn("spaceship", "aws", "us-east-1", "1", "x").has_value());
}

BOOST_AUTO_TEST_CASE(static_roles_split_reads_runs_and_admin) {
    const auto roles = ec2::ec2_static_roles();
    BOOST_TEST(roles.service_prefix == "ec2");
    BOOST_TEST(has(roles.read_only, "DescribeInstances"));
    BOOST_TEST(has(roles.read_only, "DescribeVolumes"));
    BOOST_TEST(!has(roles.read_only, "RunInstances"));
    BOOST_TEST(has(roles.read_write, "RunInstances"));
    BOOST_TEST(has(roles.read_write, "AttachVolume"));
    BOOST_TEST(!has(roles.read_write, "CreateVpc"));
    BOOST_TEST(!has(roles.read_write, "CreateKeyPair"));
    for (const auto& a : roles.read_only) {
        const auto* info = ec2::find_action(a);
        BOOST_REQUIRE(info != nullptr);
        BOOST_TEST(!info->_write);
        BOOST_TEST(!info->_permissions);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(throttling)

BOOST_AUTO_TEST_CASE(requests_meet_ec2s_buckets) {
    const auto none = parse("");
    BOOST_TEST(ec2::request_bucket_for("RunInstances", none)._rate == (ec2::bucket_rate{5, 2}));
    BOOST_TEST(ec2::request_bucket_for("CreateTags", none)._rate == (ec2::bucket_rate{100, 10}));
    BOOST_TEST(ec2::request_bucket_for("CreateKeyPair", none)._key == "resource-intensive");
    BOOST_TEST(ec2::request_bucket_for("CreateVpc", none)._key == "mutating");
    BOOST_TEST(ec2::request_bucket_for("DescribeRegions", none)._key == "non-mutating");
    BOOST_TEST(ec2::request_bucket_for("DescribeSnapshots", none)._key ==
               "unfiltered-non-mutating");
    BOOST_TEST(ec2::request_bucket_for("DescribeSnapshots", parse("MaxResults=5"))._key ==
               "non-mutating");
    BOOST_TEST(ec2::request_bucket_for("DescribeInstances", parse("InstanceId.1=i-1"))._rate ==
               (ec2::bucket_rate{500, 500}));
    BOOST_TEST(
        ec2::request_bucket_for("DescribeInstances", parse("InstanceId.1=i-1&InstanceId.2=i-2"))
            ._rate == (ec2::bucket_rate{250, 250}));
    BOOST_TEST(
        ec2::request_bucket_for("DescribeInstances", parse("Filter.1.Name=a&Filter.1.Value.1=b"))
            ._rate == (ec2::bucket_rate{100, 100}));
    BOOST_TEST(ec2::request_bucket_for("DescribeInstances", none)._key ==
               "unfiltered-non-mutating");
    BOOST_TEST(ec2::request_bucket_for("DescribeVolumes", parse("VolumeId.1=vol-1"))._rate ==
               (ec2::bucket_rate{100, 100}));
}

BOOST_AUTO_TEST_CASE(buckets_refill_continuously) {
    auto now = std::chrono::steady_clock::time_point{} + 1h;
    ec2::ec2_throttle t([&] { return now; });
    const auto p = parse("MaxCount=1");
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(!t.admit("111122223333", "RunInstances", p).has_value());
    }
    const auto refused = t.admit("111122223333", "RunInstances", p);
    BOOST_REQUIRE(refused.has_value());
    BOOST_TEST(refused->code == "RequestLimitExceeded");
    BOOST_TEST(e::http_status(refused->code) == 503U);
    // Another account has its own buckets.
    BOOST_TEST(!t.admit("444455556666", "RunInstances", p).has_value());
    // Two calls a second come back.
    now += 500ms;
    BOOST_TEST(!t.admit("111122223333", "RunInstances", p).has_value());
    BOOST_TEST(t.admit("111122223333", "RunInstances", p).has_value());
}

BOOST_AUTO_TEST_CASE(resource_buckets_meter_instances) {
    auto now = std::chrono::steady_clock::time_point{} + 1h;
    ec2::ec2_throttle t([&] { return now; });
    // 1000 instances, refilling at 2 a second; the request bucket (5, 2/s)
    // is refilled between calls so only the resource bucket binds.
    BOOST_TEST(!t.admit("1", "RunInstances", parse("MinCount=1&MaxCount=600")).has_value());
    now += 3s;
    BOOST_TEST(t.admit("1", "RunInstances", parse("MinCount=1&MaxCount=600")).has_value());
    // A refusal charged nothing: 406 instances are there (400 + 3 s * 2).
    BOOST_TEST(!t.admit("1", "RunInstances", parse("MinCount=1&MaxCount=406")).has_value());
    BOOST_TEST(ec2::resource_tokens("StopInstances", parse("InstanceId.1=a&InstanceId.2=b")) == 2U);
    BOOST_TEST(ec2::resource_tokens("DescribeInstances", parse("")) == 0U);
}

BOOST_AUTO_TEST_CASE(idle_buckets_are_dropped) {
    auto now = std::chrono::steady_clock::time_point{} + 1h;
    ec2::ec2_throttle t([&] { return now; });
    BOOST_TEST(!t.admit("1", "CreateVpc", parse("")).has_value());
    BOOST_TEST(!t.admit("2", "RunInstances", parse("MaxCount=1")).has_value());
    BOOST_TEST(t.buckets() == 3U);
    now += 11min;
    BOOST_TEST(!t.admit("3", "CreateVpc", parse("")).has_value());
    BOOST_TEST(t.buckets() == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(profile)

BOOST_AUTO_TEST_CASE(the_aws_profile_is_ec2s) {
    const ec2::ec2_profile p;
    BOOST_TEST(p._throttling);
    BOOST_TEST(!p._instance_quota.has_value());
    BOOST_TEST(p._vcpu_quota == 5U);
    BOOST_TEST(!p._volume_quota.has_value());
    BOOST_TEST(p._volume_capacity_gib == 51200U);
    BOOST_TEST(p._snapshot_quota == 100000U);
    BOOST_TEST(p._terminated_retention == 1h);
    BOOST_TEST(p._client_token_retention == 24h);
    BOOST_TEST(p.relaxed().empty());
}

BOOST_AUTO_TEST_CASE(switches_set_and_restore) {
    ec2::ec2_profile p;
    BOOST_TEST(p.set("Throttling", "OFF"));
    BOOST_TEST(p.set("vcpu-quota", "256"));
    BOOST_TEST(p.set("instance-quota", "64"));
    BOOST_TEST(p.set("terminated-retention", "60"));
    BOOST_TEST(!p._throttling);
    BOOST_TEST(p._vcpu_quota == 256U);
    BOOST_TEST(*p._instance_quota == 64U);
    BOOST_TEST(p._terminated_retention == 60s);
    BOOST_TEST(
        (p.relaxed() == std::vector<std::string_view>{"throttling", "instance-quota", "vcpu-quota",
                                                      "terminated-retention"}));
    BOOST_TEST(p.set("vcpu-quota", "aws"));
    BOOST_TEST(p.set("instance-quota", "AWS"));
    BOOST_TEST(p._vcpu_quota == 5U);
    BOOST_TEST(!p._instance_quota.has_value());
}

BOOST_AUTO_TEST_CASE(bad_switches_change_nothing) {
    ec2::ec2_profile p;
    BOOST_TEST(!p.set("throttling", "maybe"));
    BOOST_TEST(!p.set("vcpu-quota", "-1"));
    BOOST_TEST(!p.set("vcpu-quota", "12x"));
    BOOST_TEST(!p.set("vcpu-quota", "99999999999"));
    BOOST_TEST(!p.set("warp-drive", "on"));
    BOOST_TEST(p == ec2::ec2_profile{});
}

BOOST_AUTO_TEST_CASE(accounts_override_the_cluster) {
    ec2::ec2_profiles ps;
    BOOST_TEST(ps.apply("# cluster"));
    BOOST_TEST(ps.apply(""));
    BOOST_TEST(ps.apply("vcpu-quota = 1024"));
    BOOST_TEST(ps.apply("account.111122223333.throttling = off"));
    BOOST_TEST(!ps.apply("account.1111.throttling = off"));
    BOOST_TEST(!ps.apply("account.111122223333.warp = on"));
    BOOST_TEST(!ps.apply("vcpu-quota"));
    const auto& a = ps.for_account("111122223333");
    BOOST_TEST(!a._throttling);
    BOOST_TEST(a._vcpu_quota == 1024U);
    const auto& b = ps.for_account("444455556666");
    BOOST_TEST(b._throttling);
    BOOST_TEST(b._vcpu_quota == 1024U);
    BOOST_TEST(&b == &ps.cluster());
}

BOOST_AUTO_TEST_SUITE_END()
