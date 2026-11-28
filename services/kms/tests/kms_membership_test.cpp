// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The data role's membership calls (.kiro/specs/kms-independent-layers/
// task 6, kms_membership.hpp): the evacuate and status bodies both ways,
// refusals of malformed ones (with seeded mutations that must never
// throw), the routes' answers and who may call them, and the replica
// marker a release leaves.

#define BOOST_TEST_MODULE kms_membership_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_membership.hpp>

#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace ms = kythira::kms::membership;
namespace fs = std::filesystem;

namespace {

auto id(std::uint64_t n) -> kythira::host_node_id {
    return kythira::host_node_id_from_number(n);
}

}  // namespace

BOOST_AUTO_TEST_CASE(an_evacuation_round_trips) {
    const ms::evacuation_request r{
        .node = id(1), .targets = {id(4), id(5)}, .replicas = 3, .fan_out = false};
    const auto back = ms::parse_evacuation(ms::to_json(r));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == r));

    // Numbers for ids, defaults, and a repeated target kept once.
    const auto d = ms::parse_evacuation(R"({"node":2,"targets":[4,"4",5]})");
    BOOST_REQUIRE(d.has_value());
    BOOST_TEST(d->replicas == 3U);
    BOOST_TEST(d->fan_out);
    BOOST_TEST(d->targets.size() == 2U);
}

BOOST_AUTO_TEST_CASE(malformed_evacuations_are_refused) {
    const std::vector<std::pair<std::string, std::string>> cases{
        {"[]", "not a JSON object"},
        {"{", "not a JSON object"},
        {R"({"targets":["4"]})", "\"node\" is required"},
        {R"({"node":"1"})", "\"targets\""},
        {R"({"node":"1","targets":[]})", "\"targets\""},
        {R"({"node":"1","targets":["1"]})", "its own target"},
        {R"({"node":-1,"targets":["2"]})", "node id"},
        {R"({"node":"1","targets":["2"],"replicas":0})", "\"replicas\""},
        {R"({"node":"1","targets":["2"],"replicas":16})", "\"replicas\""},
        {R"({"node":"1","targets":["2"],"replicas":"3"})", "\"replicas\""},
        {R"({"node":"1","targets":["2"],"fan_out":1})", "\"fan_out\""},
    };
    for (const auto& [body, why] : cases) {
        const auto r = ms::parse_evacuation(body);
        BOOST_TEST(!r.has_value(), body);
        if (!r) {
            BOOST_TEST(r.error().find(why) != std::string::npos, body << ": " << r.error());
        }
    }
    std::string many = R"({"node":"1","targets":[)";
    for (int i = 2; i < 2 + static_cast<int>(ms::k_max_targets) + 1; ++i) {
        many += (i == 2 ? "\"" : ",\"") + std::to_string(i) + "\"";
    }
    many += "]}";
    BOOST_TEST(!ms::parse_evacuation(many).has_value());
    BOOST_TEST(!ms::parse_evacuation(std::string(ms::k_max_body + 1, ' ')).has_value());
}

BOOST_AUTO_TEST_CASE(mutated_bodies_never_throw) {
    const ms::status st{.self = id(2),
                        .voters = {id(1), id(2), id(3)},
                        .learners = {id(4)},
                        .leader = true,
                        .job = ms::evacuation_request{.node = id(1), .targets = {id(4)}},
                        .action = "add_replica",
                        .error = "",
                        .done = false};
    const std::vector<std::string> seeds{
        ms::to_json(ms::evacuation_request{.node = id(1), .targets = {id(4), id(5)}}),
        ms::to_json(st)};
    std::mt19937 rng(20261128);
    for (const auto& seed : seeds) {
        for (int i = 0; i < 2000; ++i) {
            auto b = seed;
            const auto edits = 1 + rng() % 4;
            for (unsigned e = 0; e < edits; ++e) {
                const auto at = rng() % b.size();
                switch (rng() % 3) {
                    case 0:
                        b[at] = static_cast<char>(rng() % 256);
                        break;
                    case 1:
                        b.erase(at, 1 + rng() % 3);
                        break;
                    default:
                        b.insert(at, 1, "{}[]\",:0a-"[rng() % 11]);
                        break;
                }
                if (b.empty()) {
                    b = "{";
                }
            }
            BOOST_CHECK_NO_THROW((void)ms::parse_evacuation(b));
            BOOST_CHECK_NO_THROW((void)ms::parse_status(b));
        }
    }
}

BOOST_AUTO_TEST_CASE(a_status_round_trips) {
    const ms::status st{.self = id(2),
                        .voters = {id(1), id(2), id(3)},
                        .learners = {id(4)},
                        .leader = true,
                        .job =
                            ms::evacuation_request{
                                .node = id(1), .targets = {id(4)}, .replicas = 3, .fan_out = false},
                        .action = "add_replica",
                        .error = "busy",
                        .done = false};
    const auto back = ms::parse_status(ms::to_json(st));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->self == st.self));
    BOOST_TEST((back->voters == st.voters));
    BOOST_TEST((back->learners == st.learners));
    BOOST_TEST(back->leader);
    BOOST_TEST(!back->done);
    BOOST_TEST(back->action == "add_replica");
    BOOST_TEST(back->error == "busy");
    BOOST_REQUIRE(back->job.has_value());
    BOOST_TEST((*back->job == *st.job));
}

BOOST_AUTO_TEST_CASE(the_routes_answer_data_nodes_only) {
    int evacuations = 0;
    bool spread = false;
    ms::handlers h;
    h.evacuate = [&](const ms::evacuation_request& r) {
        ++evacuations;
        return ms::answer{200, ms::to_json(r)};
    };
    h.status = [] { return ms::answer{200, "{\"status\":1}"}; };
    h.cancel = [&](bool fan_out) {
        spread = fan_out;
        return ms::answer{200, "{}"};
    };
    h.release = [] { return ms::answer{200, R"({"released":true})"}; };

    const auto* const body = R"({"node":"1","targets":["4"]})";
    BOOST_TEST(ms::serve(h, false, "POST", ms::k_evacuate_path, body).status == 403U);
    BOOST_TEST(evacuations == 0);
    BOOST_TEST(ms::serve(h, true, "POST", ms::k_evacuate_path, body).status == 200U);
    BOOST_TEST(evacuations == 1);
    BOOST_TEST(ms::serve(h, true, "POST", ms::k_evacuate_path, "{}").status == 400U);
    BOOST_TEST(ms::serve(h, true, "GET", ms::k_evacuate_path, "").body == "{\"status\":1}");
    BOOST_TEST(ms::serve(h, true, "PUT", ms::k_evacuate_path, body).status == 405U);
    BOOST_TEST(ms::serve(h, true, "POST", ms::k_cancel_path, "").status == 200U);
    BOOST_TEST(spread);
    BOOST_TEST(
        ms::serve(h, true, "POST", std::string(ms::k_cancel_path) + "?fan_out=false", "").status ==
        200U);
    BOOST_TEST(!spread);
    BOOST_TEST(ms::serve(h, true, "POST", ms::k_release_path, "").status == 200U);
    BOOST_TEST(ms::serve(h, true, "POST", "/v1/kms/membership/other", "").status == 404U);

    BOOST_TEST(ms::is_membership_path("/v1/kms/membership/evacuate?x=1"));
    BOOST_TEST(!ms::is_membership_path("/v1/kms/catalog/query"));
    // Data nodes only, as layer identities see it.
    BOOST_TEST(ms::membership_route_roles.has(kythira::layers::role::data));
    BOOST_TEST(!ms::membership_route_roles.has(kythira::layers::role::front_end));
    BOOST_TEST(!ms::membership_route_roles.has(kythira::layers::role::gateway));
}

BOOST_AUTO_TEST_CASE(a_released_replica_is_discarded_and_the_node_stays_left) {
    std::random_device rd;
    const auto dir = fs::temp_directory_path() / ("kythira-kms-membership-" + std::to_string(rd()));
    fs::create_directories(dir / "raft" / "1");
    fs::create_directories(dir / "engine");
    std::ofstream(dir / "raft" / "1" / "log") << "x";
    BOOST_TEST(ms::holds_replica(dir));
    BOOST_TEST(!ms::read_marker(dir).has_value());

    ms::write_marker(dir, ms::k_marker_released);
    BOOST_TEST((ms::read_marker(dir) == std::string(ms::k_marker_released)));
    ms::discard_replica(dir);
    BOOST_TEST(!ms::holds_replica(dir));
    // The marker stays, now saying the node has left: it only ever rejoins.
    BOOST_TEST((ms::read_marker(dir) == std::string(ms::k_marker_left)));
    std::error_code ec;
    fs::remove_all(dir, ec);
}
