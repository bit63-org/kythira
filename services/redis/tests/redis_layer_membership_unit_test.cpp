// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_layer_membership_unit_test.cpp
/// @brief The gateway-free pieces of Redis layer membership
///        (redis_layer_membership.hpp, .kiro/specs/redis-general-data-types/
///        task 18): SCAN cursors that name their front end, the member list
///        on the internal link, the load a node reports, and DNS discovery.

#define BOOST_TEST_MODULE redis_layer_membership_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_layer_membership.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace rm = kythira::redis_membership;
namespace layers = kythira::layers;

namespace {

auto member(std::string id, layers::role_set roles, std::uint32_t index = 0)
    -> layers::layer_member {
    layers::layer_member m;
    m.id = id;
    m.roles = roles;
    m.address = id + ":6379";
    m.placement_group = "zone-a";
    m.index = index;
    m.drain = layers::drain_state::draining;
    m.load.requests_per_second = 12.5;
    m.load.open_streams = 7;
    m.load.cpu = 0.25;
    m.announced_at_ms = 1000;
    m.reported_at_ms = 2000;
    return m;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_cursor_names_its_front_end_and_its_id) {
    const auto c = rm::pack_cursor(5, 42);
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(*c == ((std::uint64_t{5} << 50U) | 42U));
    const auto parts = rm::unpack_cursor(*c);
    BOOST_REQUIRE(parts.has_value());
    BOOST_TEST(parts->front_end_index == 5U);
    BOOST_TEST(parts->id == 42U);
    // The largest of each.
    const auto top = rm::pack_cursor(rm::k_max_front_end_index, rm::k_max_cursor_id);
    BOOST_REQUIRE(top.has_value());
    BOOST_TEST(*top == ~std::uint64_t{0});
    BOOST_TEST(rm::unpack_cursor(*top)->front_end_index == rm::k_max_front_end_index);
    // What does not fit is refused, and 0 is "start" and "done".
    BOOST_TEST(!rm::pack_cursor(0, 1).has_value());
    BOOST_TEST(!rm::pack_cursor(rm::k_max_front_end_index + 1, 1).has_value());
    BOOST_TEST(!rm::pack_cursor(1, 0).has_value());
    BOOST_TEST(!rm::pack_cursor(1, rm::k_max_cursor_id + 1).has_value());
    BOOST_TEST(!rm::unpack_cursor(0).has_value());
    BOOST_TEST(!rm::unpack_cursor(42).has_value());                       // no issuer
    BOOST_TEST(!rm::unpack_cursor(std::uint64_t{3} << 50U).has_value());  // no id
}

BOOST_AUTO_TEST_CASE(a_numeric_node_id_is_the_default_front_end_index) {
    BOOST_TEST(rm::default_front_end_index("7") == 7U);
    BOOST_TEST(rm::default_front_end_index("16383") == 16383U);
    BOOST_TEST(rm::default_front_end_index("16384") == 0U);
    BOOST_TEST(rm::default_front_end_index("0") == 0U);
    BOOST_TEST(rm::default_front_end_index("node-7") == 0U);
    BOOST_TEST(rm::default_front_end_index("") == 0U);
    BOOST_TEST(rm::default_front_end_index("123456") == 0U);
}

BOOST_AUTO_TEST_CASE(a_cursor_finds_the_address_of_its_issuer) {
    const std::vector<layers::layer_member> members{
        member("gw", layers::role_set{layers::role::gateway}, 3),
        member("fe-3", layers::role_set{layers::role::front_end}, 3),
        member("fe-4", layers::role_set{layers::role::front_end}, 4)};
    BOOST_TEST(rm::front_end_address(members, 3).value() == "fe-3:6379");
    BOOST_TEST(rm::front_end_address(members, 4).value() == "fe-4:6379");
    BOOST_TEST(!rm::front_end_address(members, 5).has_value());
    BOOST_TEST(!rm::front_end_address(members, 0).has_value());
}

BOOST_AUTO_TEST_CASE(the_member_list_round_trips_on_the_internal_link) {
    const std::vector<layers::layer_member> members{
        member("fe-1", layers::role_set{layers::role::front_end}, 9),
        member("gw-1", layers::role_set{layers::role::gateway, layers::role::front_end})};
    const auto decoded = rm::decode_members(rm::encode_members(members));
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST((*decoded == members));
    BOOST_TEST(rm::decode_members("[]").value().empty());
    // Damage is never an empty layer.
    BOOST_TEST(!rm::decode_members("").has_value());
    BOOST_TEST(!rm::decode_members("{}").has_value());
    BOOST_TEST(!rm::decode_members(R"([{"id":"x"}])").has_value());
}

BOOST_AUTO_TEST_CASE(a_member_written_before_the_index_existed_still_parses) {
    auto json = layers::layer_membership_core::member_to_json(
        member("fe-1", layers::role_set{layers::role::front_end}, 9));
    json.erase("index");
    const auto m = layers::layer_membership_core::member_from_json(json);
    BOOST_TEST(m.index == 0U);
    BOOST_TEST(m.id == "fe-1");
}

BOOST_AUTO_TEST_CASE(load_is_measured_between_samples) {
    rm::load_meter meter;
    const auto t0 = std::chrono::steady_clock::time_point{} + std::chrono::seconds{100};
    auto first =
        meter.sample({.connections = 4, .commands = 1000, .bytes_out = 0, .cpu_seconds = 10.0}, t0);
    // The first sample has nothing to compare with.
    BOOST_TEST(first.open_streams == 4U);
    BOOST_TEST(first.requests_per_second == 0.0);
    const auto second =
        meter.sample({.connections = 6, .commands = 3000, .bytes_out = 4000, .cpu_seconds = 10.0},
                     t0 + std::chrono::seconds{2});
    BOOST_TEST(second.open_streams == 6U);
    BOOST_TEST(second.requests_per_second == 1000.0);
    BOOST_TEST(second.bytes_served_per_second == 2000U);
    BOOST_TEST(second.cpu == 0.0);
    // A counter that went backwards (a restart) reads as no load, not as a
    // huge one.
    const auto third = meter.sample(
        {.connections = 1, .commands = 10, .bytes_out = 0, .cpu_seconds = std::nullopt},
        t0 + std::chrono::seconds{3});
    BOOST_TEST(third.requests_per_second == 0.0);
    BOOST_TEST(third.cpu == 0.0);
}

BOOST_AUTO_TEST_CASE(this_process_cpu_time_is_readable_on_linux) {
#if defined(__linux__)
    const auto cpu = rm::process_cpu_seconds();
    BOOST_REQUIRE(cpu.has_value());
    BOOST_TEST(*cpu >= 0.0);
#endif
}

BOOST_AUTO_TEST_CASE(dns_discovery_resolves_every_address) {
    BOOST_TEST(!rm::split_host_port("noport").has_value());
    BOOST_TEST(!rm::split_host_port(":1").has_value());
    BOOST_TEST(rm::split_host_port("[::1]:6379")->first == "::1");
    BOOST_TEST(rm::split_host_port("fe.example:6379")->second == "6379");

    const auto local = rm::resolve_all("127.0.0.1:6379");
    BOOST_REQUIRE(local.size() == 1U);
    BOOST_TEST(local.front() == "127.0.0.1:6379");
    const auto v6 = rm::resolve_all("[::1]:7");
    if (!v6.empty()) {  // no IPv6 on some runners
        BOOST_TEST(v6.front() == "[::1]:7");
    }
    BOOST_TEST(rm::resolve_all("no-port").empty());
    BOOST_TEST(rm::resolve_all("name.invalid:1").empty());

    const auto found = rm::discovered_front_ends({"10.0.0.1:6379", "10.0.0.2:6379"});
    BOOST_REQUIRE(found.size() == 2U);
    BOOST_TEST(found[0].id == "10.0.0.1:6379");
    BOOST_TEST(found[0].address == "10.0.0.1:6379");
    BOOST_TEST(found[1].roles.to_string() == "front_end");
}
