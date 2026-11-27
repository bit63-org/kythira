// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 2 (Requirement 3.1): every request the recorded clients sent
// (tests/evidence/data/*.json) through the core EC2 query codec. Each body,
// rebuilt from the recorded pairs in the order the client sent them,
// parses; Action and Version read back; every list, structure, filter, tag
// and tag specification in it decodes; and request by request every client
// decodes to the same parameters, whatever order it sent them in, except
// for the ClientToken a client made up itself.

#define BOOST_TEST_MODULE ec2_protocol_evidence_test

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include <raft/aws_ec2_protocol.hpp>

#include <kythira/ec2/model/operations.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace e = kythira::aws_ec2;
namespace json = boost::json;

namespace {

struct recording {
    std::string file;
    std::vector<std::string> operations;
    std::vector<std::string> bodies;
};

auto load(const std::filesystem::path& path) -> recording {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    const auto doc = json::parse(ss.str()).as_object();
    recording r{path.filename().string(), {}, {}};
    for (const auto& req : doc.at("requests").as_array()) {
        const auto& o = req.as_object();
        r.operations.emplace_back(o.at("operation").as_string());
        std::string body;
        for (const auto& pair : o.at("form").as_array()) {
            const auto& kv = pair.as_array();
            if (!body.empty()) {
                body += '&';
            }
            body += kythira::aws_query::url_encode(std::string(kv.at(0).as_string()));
            body += '=';
            body += kythira::aws_query::url_encode(std::string(kv.at(1).as_string()));
        }
        r.bodies.push_back(std::move(body));
    }
    return r;
}

auto recordings() -> std::vector<recording> {
    std::vector<recording> out;
    for (const auto& entry : std::filesystem::directory_iterator(KYTHIRA_EC2_EVIDENCE_DIR)) {
        if (entry.path().extension() == ".json") {
            out.push_back(load(entry.path()));
        }
    }
    std::ranges::sort(out, {}, &recording::file);
    return out;
}

auto known_operation(const std::string& name) -> bool {
    const auto& ops = kythira::ec2::model::operations;
    return std::ranges::any_of(ops, [&](const auto& op) { return op._name == name; });
}

// The list and structure parameters the scenario uses, by name. VpcId and
// VolumeId are lists in the describes (VpcId.1) and plain values elsewhere
// (CreateSubnet's VpcId), so a list is read only where no plain value is.
constexpr const char* value_lists[] = {"InstanceId", "ResourceId", "RegionName", "VpcId",
                                       "VolumeId"};
constexpr const char* struct_lists[] = {"BlockDeviceMapping", "Filter", "Tag", "TagSpecification"};

}  // namespace

BOOST_AUTO_TEST_CASE(every_client_is_recorded) {
    const auto all = recordings();
    BOOST_REQUIRE_EQUAL(all.size(), 5U);
    for (const auto& r : all) {
        BOOST_TEST_CONTEXT(r.file) {
            BOOST_TEST(r.bodies.size() == 25U);
        }
    }
}

BOOST_AUTO_TEST_CASE(every_request_decodes) {
    for (const auto& r : recordings()) {
        for (std::size_t i = 0; i < r.bodies.size(); ++i) {
            BOOST_TEST_CONTEXT(r.file << " request " << i << " (" << r.operations[i] << ")") {
                auto p = e::params::parse(r.bodies[i]);
                BOOST_REQUIRE(p.has_value());
                const auto req = e::read_request(*p);
                BOOST_REQUIRE(req.has_value());
                BOOST_TEST(req->action == r.operations[i]);
                BOOST_TEST(known_operation(req->action));
                for (const auto* name : value_lists) {
                    if (!p->contains(name)) {
                        BOOST_TEST(p->list(name).has_value(), name);
                    }
                }
                for (const auto* name : struct_lists) {
                    BOOST_TEST(p->structs(name).has_value(), name);
                }
                BOOST_TEST(e::filters(*p).has_value());
                BOOST_TEST(e::tags(*p).has_value());
                BOOST_TEST(e::tag_specifications(*p).has_value());
                BOOST_TEST(p->boolean("DryRun").has_value());
                BOOST_TEST(e::max_results(*p, 5, 1000).has_value());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(every_client_decodes_to_the_same_requests) {
    const auto all = recordings();
    BOOST_REQUIRE(!all.empty());
    const auto& ref = all.front();
    for (const auto& r : all) {
        BOOST_REQUIRE_EQUAL(r.bodies.size(), ref.bodies.size());
        for (std::size_t i = 0; i < r.bodies.size(); ++i) {
            BOOST_TEST_CONTEXT(r.file << " request " << i << " against " << ref.file) {
                auto a = e::params::parse(ref.bodies[i])->all();
                auto b = e::params::parse(r.bodies[i])->all();
                // A ClientToken the client generated (recorded as <uuid>)
                // stands for a different random value in each client.
                BOOST_TEST((a == b));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(the_scenario_reads_as_written) {
    // Spot checks that the decoded values are the scenario's, from the
    // first recording (README.md "The scenario").
    const auto r = recordings().front();
    const auto run = e::params::parse(r.bodies[9]).value();
    const auto bdm = run.structs("BlockDeviceMapping").value();
    BOOST_REQUIRE_EQUAL(bdm.size(), 2U);
    BOOST_TEST(*bdm[0].get("DeviceName") == "/dev/xvda");
    BOOST_TEST(*bdm[0].sub("Ebs").integer("VolumeSize", 1, 16384).value() == 8);
    BOOST_TEST(*bdm[0].sub("Ebs").boolean("DeleteOnTermination").value() == true);
    BOOST_TEST(*bdm[1].get("VirtualName") == "ephemeral0");
    const auto specs = e::tag_specifications(run).value();
    BOOST_REQUIRE_EQUAL(specs.size(), 2U);
    BOOST_TEST(specs[0].resource_type == "instance");
    BOOST_TEST(specs[1].resource_type == "volume");
    BOOST_TEST(*run.integer("MaxCount", 1, 1000).value() == 2);

    const auto dry = e::params::parse(r.bodies[10]).value();
    BOOST_TEST(*dry.boolean("DryRun").value() == true);
    BOOST_TEST(*dry.get("ClientToken") == "<uuid>");

    const auto describe = e::params::parse(r.bodies[11]).value();
    const auto f = e::filters(describe).value();
    BOOST_REQUIRE_EQUAL(f.size(), 1U);
    BOOST_TEST(f[0].name == "instance-state-name");
    BOOST_TEST((f[0].values == std::vector<std::string>{"pending", "running"}));
    BOOST_TEST(describe.list("InstanceId")->size() == 2U);

    const auto tags = e::tags(e::params::parse(r.bodies[12]).value()).value();
    BOOST_REQUIRE_EQUAL(tags.size(), 2U);
    BOOST_TEST(!tags[1].value.has_value());

    const auto page2 = e::params::parse(r.bodies[8]).value();
    BOOST_TEST(*page2.get("NextToken") == "evidence-page-2");
    BOOST_TEST(*e::max_results(page2, 5, 1000).value() == 5);
}
