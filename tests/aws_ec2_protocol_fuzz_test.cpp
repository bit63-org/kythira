// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The EC2 query codec's fuzz target (`.kiro/specs/ec2-compatible-api/`
// task 2): seeded mutations of recorded request bodies through every
// decoder. Each input decodes or is refused with an error code, never a
// throw or an out-of-bounds read (the sanitizer legs run this test); a body
// that parses encodes back to the same parameters; and every list a decoder
// returns accounts for exactly the wire names under its prefix.
// KYTHIRA_EC2_FUZZ_ITERATIONS overrides the count.

#define BOOST_TEST_MODULE aws_ec2_protocol_fuzz_test

#include <boost/test/unit_test.hpp>

#include <raft/aws_ec2_protocol.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <string_view>

namespace e = kythira::aws_ec2;

namespace {

auto iterations() -> int {
    if (const char* v = std::getenv("KYTHIRA_EC2_FUZZ_ITERATIONS")) {
        return std::atoi(v);
    }
    return 50000;
}

// Request bodies the recorded clients sent (services/ec2/tests/evidence/).
constexpr std::array<std::string_view, 5> seeds = {
    "Action=RunInstances&Version=2016-11-15&ClientToken=evidence-run-1"
    "&ImageId=ami-0000000000000a001&InstanceType=t3.micro&MinCount=1&MaxCount=2"
    "&BlockDeviceMapping.1.DeviceName=%2Fdev%2Fxvda&BlockDeviceMapping.1.Ebs.VolumeSize=8"
    "&BlockDeviceMapping.1.Ebs.DeleteOnTermination=true&BlockDeviceMapping.2.VirtualName=ephemeral0"
    "&TagSpecification.1.ResourceType=instance&TagSpecification.1.Tag.1.Key=Name"
    "&TagSpecification.1.Tag.1.Value=evidence",
    "Action=DescribeInstances&Version=2016-11-15&InstanceId.1=i-00000000000000007"
    "&InstanceId.2=i-00000000000000008&Filter.1.Name=instance-state-name"
    "&Filter.1.Value.1=pending&Filter.1.Value.2=running",
    "Action=CreateTags&ResourceId.1=i-00000000000000007&ResourceId.2=vol-00000000000000004"
    "&Tag.1.Key=stage&Tag.1.Value=evidence&Tag.2.Key=flag&Version=2016-11-15",
    "Action=DescribeVolumes&Version=2016-11-15&Filter.1.Name=availability-zone"
    "&Filter.1.Value.1=us-east-1a&MaxResults=5&NextToken=evidence-page-2",
    "Action=CreateVolume&Version=2016-11-15&AvailabilityZone=us-east-1a&Size=8"
    "&VolumeType=gp3&Encrypted=true&DryRun=true",
};

// Characters that matter to the codec, so mutations reach its branches. A
// literal with its length, since it holds a NUL.
constexpr char alphabet_chars[] = "&=.%+0123456789AZaz-_ \x00\xff";  // NOLINT
constexpr std::string_view alphabet(alphabet_chars, sizeof alphabet_chars - 1);

auto mutate(std::string in, std::mt19937_64& rng) -> std::string {
    auto pick = [&](std::size_t n) {
        return n == 0 ? std::size_t{0} : std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
    };
    auto ch = [&] {
        return pick(2) == 0 ? alphabet[pick(alphabet.size())] : static_cast<char>(rng());
    };
    const auto rounds = 1 + pick(4);
    for (std::size_t r = 0; r < rounds; ++r) {
        switch (pick(5)) {
            case 0:
                if (!in.empty()) {
                    in[pick(in.size())] = ch();
                }
                break;
            case 1:
                in.insert(in.begin() + static_cast<std::ptrdiff_t>(pick(in.size() + 1)), ch());
                break;
            case 2:
                if (!in.empty()) {
                    in.erase(pick(in.size()), 1 + pick(8));
                }
                break;
            case 3:
                in.resize(pick(in.size() + 1));
                break;
            default: {
                // Splice a piece of another seed in: recombines list prefixes.
                const auto other = seeds[pick(seeds.size())];
                const auto from = pick(other.size());
                in.insert(pick(in.size() + 1), other.substr(from, pick(40)));
            }
        }
    }
    return in;
}

// Every name under `prefix.` that `count` decoded entries account for.
auto names_under(const e::params& p, std::string_view prefix) -> std::size_t {
    return p.sub(prefix).size();
}

// Returns whether the body parsed, so the test can check the mutations
// still reach the decoders behind the parser.
auto exercise(std::string_view body) -> bool {
    const auto p = e::params::parse(body);
    if (!p) {
        BOOST_REQUIRE(p.err().code == "MalformedQueryString");
        return false;
    }
    // Encoding round-trips.
    const auto again = e::params::parse(p->encode());
    BOOST_REQUIRE(again.has_value());
    BOOST_REQUIRE(*again == *p);

    const auto r = e::read_request(*p);
    if (!r) {
        const auto& c = r.err().code;
        BOOST_REQUIRE(c == "MissingAction" || c == "MissingParameter" || c == "NoSuchVersion");
    }
    for (const auto* name : {"InstanceId", "ResourceId", "Filter", "Tag"}) {
        const auto l = p->list(name);
        if (l) {
            BOOST_REQUIRE(l->size() == names_under(*p, name));
        } else {
            BOOST_REQUIRE(l.err().code == "InvalidParameterValue");
        }
    }
    const auto s = p->structs("BlockDeviceMapping");
    if (s) {
        std::size_t fields = 0;
        for (const auto& entry : *s) {
            BOOST_REQUIRE(!entry.empty());
            fields += entry.size();
            (void)entry.sub("Ebs").integer("VolumeSize", 1, 16384);
            (void)entry.sub("Ebs").boolean("DeleteOnTermination");
        }
        BOOST_REQUIRE(fields == names_under(*p, "BlockDeviceMapping"));
    }
    if (const auto f = e::filters(*p)) {
        for (const auto& one : *f) {
            BOOST_REQUIRE(!one.name.empty());
        }
    } else {
        BOOST_REQUIRE(f.err().code == "InvalidParameterValue");
    }
    if (const auto t = e::tags(*p)) {
        BOOST_REQUIRE(t->size() <= names_under(*p, "Tag"));
    }
    if (const auto ts = e::tag_specifications(*p); !ts) {
        BOOST_REQUIRE(ts.err().code == "InvalidParameterValue");
    }
    (void)e::max_results(*p, 5, 1000);
    (void)p->boolean("DryRun");
    (void)p->boolean("Encrypted");
    (void)p->integer("Size", 1, 16384);
    return true;
}

}  // namespace

BOOST_AUTO_TEST_CASE(seeds_decode_cleanly) {
    for (const auto seed : seeds) {
        const auto p = e::params::parse(seed);
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST(e::read_request(*p).has_value());
        BOOST_TEST(e::filters(*p).has_value());
        BOOST_TEST(e::tags(*p).has_value());
        BOOST_TEST(e::tag_specifications(*p).has_value());
        exercise(seed);
    }
}

BOOST_AUTO_TEST_CASE(mutated_bodies_decode_or_are_refused) {
    std::mt19937_64 rng(0xEC2);
    const int n = iterations();
    int parsed = 0;
    for (int i = 0; i < n; ++i) {
        parsed +=
            exercise(mutate(std::string(seeds[static_cast<std::size_t>(i) % seeds.size()]), rng))
                ? 1
                : 0;
    }
    // Most mutations must get past the form parser, or the decoders behind
    // it are not being fuzzed at all.
    BOOST_TEST_MESSAGE(parsed << " of " << n << " mutated bodies parsed");
    BOOST_TEST(parsed * 4 >= n);
}
