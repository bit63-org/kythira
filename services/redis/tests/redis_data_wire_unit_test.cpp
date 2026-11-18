// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_data_wire_unit_test.cpp
/// @brief The Redis data-layer API's bytes (redis_data_wire.hpp) and the
///        remote data access that speaks it (redis_remote_data_access.hpp),
///        against scripted data nodes (.kiro/specs/redis-general-data-types/
///        task 16).

#define BOOST_TEST_MODULE redis_data_wire_unit_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_data_wire.hpp>
#include <kythira/redis/redis_remote_data_access.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace kythira;
namespace wire = kythira::redis_data_wire;

namespace {

using group_t = std::uint64_t;
using node_t = std::uint64_t;
using descriptor = shard_descriptor<group_t, std::string, node_t>;
using routes_t = wire::routes_payload<group_t, node_t>;
using remote_t = redis_remote_data_access<group_t, node_t>;
using not_leader_ex = shard_not_leader_exception<group_t, node_t>;

auto routes_decode(std::string_view b) {
    return wire::decode_routes<group_t, node_t>(b);
}
auto propose_decode(std::string_view b) {
    return wire::decode_propose<group_t, node_t>(b);
}

auto row(group_t g, std::optional<std::string> start, std::optional<std::string> end,
         std::uint64_t version, std::vector<node_t> voters,
         std::optional<node_t> hint = std::nullopt) -> descriptor {
    descriptor d;
    d._group_id = g;
    d._range = shard_range<std::string>{._start = std::move(start), ._end = std::move(end)};
    d._epoch = shard_epoch{._version = version, ._conf_version = 1};
    d._voters = std::move(voters);
    d._leader_hint = hint;
    return d;
}

auto bulk(const std::string& body) -> std::string {
    return "$" + std::to_string(body.size()) + "\r\n" + body + "\r\n";
}

auto bytes_of(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto text_of(const std::vector<std::byte>& b) -> std::string {
    std::string out;
    for (auto c : b) {
        out.push_back(static_cast<char>(c));
    }
    return out;
}

/// Data nodes scripted per address: each sees the argv and answers.
struct fake_nodes {
    using handler = std::function<std::optional<std::string>(const std::vector<std::string>&)>;
    std::map<std::string, handler> nodes;
    std::vector<std::string> calls;  ///< "address SUBCOMMAND" per call

    auto call() -> remote_t::call_fn {
        return [this](const std::string& address, const std::vector<std::string>& argv) {
            calls.push_back(address + " " + argv.at(1));
            auto it = nodes.find(address);
            if (it == nodes.end()) {
                return std::optional<std::string>{};
            }
            return it->second(argv);
        };
    }
};

/// One group over every key, voters 1-3 at n1..n3, leader `leader`.
auto one_group(std::optional<node_t> leader, std::uint64_t version = 1) -> routes_t {
    routes_t r;
    r.routes.push_back(row(7, std::nullopt, std::nullopt, version, {1, 2, 3}, leader));
    r.addresses = {{1, "n1:1"}, {2, "n2:1"}, {3, "n3:1"}};
    return r;
}

auto fast() -> remote_t::options {
    remote_t::options o;
    o.timeout = std::chrono::milliseconds{300};
    o.retry_pause = std::chrono::milliseconds{1};
    return o;
}

}  // namespace

// ── the bytes ──────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(range_round_trips_bounded_and_unbounded, *boost::unit_test::timeout(10)) {
    for (const auto& r :
         {shard_range<std::string>{}, shard_range<std::string>{._start = "a", ._end = std::nullopt},
          shard_range<std::string>{._start = std::nullopt, ._end = "m"},
          shard_range<std::string>{._start = std::string("\0a", 2), ._end = "z"}}) {
        auto back = wire::decode_range(wire::encode_range(r));
        BOOST_REQUIRE(back.has_value());
        BOOST_CHECK(back->_start == r._start);
        BOOST_CHECK(back->_end == r._end);
    }
    BOOST_CHECK(!wire::decode_range("").has_value());
    BOOST_CHECK(!wire::decode_range(wire::encode_range({}) + "x").has_value());
}

BOOST_AUTO_TEST_CASE(routes_round_trip_with_addresses, *boost::unit_test::timeout(10)) {
    routes_t r;
    r.routes.push_back(row(1, std::nullopt, "m", 3, {1, 2, 3}, 2));
    r.routes.push_back(row(2, "m", std::nullopt, 9, {2, 3}));
    r.routes.back()._learners = {4};
    r.addresses = {{1, "redis-data-0:6380"}, {4, "[::1]:6380"}};
    const auto text = wire::encode_routes(r);
    auto back = wire::decode_routes<group_t, node_t>(text);
    BOOST_REQUIRE(back.has_value());
    BOOST_REQUIRE_EQUAL(back->routes.size(), 2u);
    BOOST_CHECK(back->routes[0] == r.routes[0]);
    BOOST_CHECK(back->routes[1] == r.routes[1]);
    BOOST_CHECK(back->addresses == r.addresses);
    // Truncated or trailing bytes are refused, never half-read.
    for (std::size_t n = 0; n < text.size(); ++n) {
        BOOST_CHECK_MESSAGE(!routes_decode(text.substr(0, n)).has_value(), "prefix " << n);
    }
    BOOST_CHECK(!routes_decode(text + '\0').has_value());
}

BOOST_AUTO_TEST_CASE(every_propose_answer_round_trips, *boost::unit_test::timeout(10)) {
    using wire::propose_status;
    auto ok =
        wire::decode_propose<group_t, node_t>(wire::encode_propose_ok(std::string("r\0s", 3)));
    BOOST_REQUIRE(ok.has_value());
    BOOST_CHECK(ok->status == propose_status::ok);
    BOOST_CHECK_EQUAL(ok->payload, std::string("r\0s", 3));

    auto nl = wire::decode_propose<group_t, node_t>(
        wire::encode_propose_not_leader(std::optional<node_t>{3}));
    BOOST_REQUIRE(nl.has_value());
    BOOST_CHECK(nl->status == propose_status::not_leader);
    BOOST_CHECK(nl->leader == std::optional<node_t>{3});
    auto none = wire::decode_propose<group_t, node_t>(
        wire::encode_propose_not_leader(std::optional<node_t>{}));
    BOOST_REQUIRE(none.has_value());
    BOOST_CHECK(!none->leader.has_value());

    auto stale = wire::decode_propose<group_t, node_t>(wire::encode_propose_stale(one_group(2, 4)));
    BOOST_REQUIRE(stale.has_value());
    BOOST_CHECK(stale->status == propose_status::stale_route);
    BOOST_REQUIRE_EQUAL(stale->routes.routes.size(), 1u);
    BOOST_CHECK_EQUAL(stale->routes.routes[0]._epoch._version, 4u);

    const txn_id holder{._hi = 11, ._lo = 12};
    auto locked =
        wire::decode_propose<group_t, node_t>(wire::encode_propose_locked("k", holder, "p"));
    BOOST_REQUIRE(locked.has_value());
    BOOST_CHECK(locked->status == propose_status::key_locked);
    BOOST_CHECK_EQUAL(locked->locked_key, "k");
    BOOST_CHECK(locked->holder == holder);
    BOOST_CHECK_EQUAL(locked->primary, "p");

    for (auto s :
         {propose_status::unknown_group, propose_status::unrouted, propose_status::timeout}) {
        auto d = wire::decode_propose<group_t, node_t>(wire::encode_propose_status(s));
        BOOST_REQUIRE(d.has_value());
        BOOST_CHECK(d->status == s);
    }
    auto failed = wire::decode_propose<group_t, node_t>(
        wire::encode_propose_status(propose_status::failed, "boom"));
    BOOST_REQUIRE(failed.has_value());
    BOOST_CHECK_EQUAL(failed->payload, "boom");

    BOOST_CHECK(!propose_decode("").has_value());
    BOOST_CHECK(!propose_decode(std::string(1, '\x08')).has_value());
    BOOST_CHECK(!propose_decode(std::string(1, '\x01')).has_value());
}

BOOST_AUTO_TEST_CASE(peer_answers_parse, *boost::unit_test::timeout(10)) {
    auto b = parse_redis_peer_answer(bulk(std::string("a\r\nb", 4)));
    BOOST_CHECK(b._kind == redis_peer_answer::kind::bulk);
    BOOST_CHECK_EQUAL(b._text, std::string("a\r\nb", 4));
    auto e = parse_redis_peer_answer("-NOPERM no\r\n");
    BOOST_CHECK(e._kind == redis_peer_answer::kind::error);
    BOOST_CHECK_EQUAL(e._text, "NOPERM no");
    BOOST_CHECK(parse_redis_peer_answer("+OK\r\n")._kind == redis_peer_answer::kind::other);
    BOOST_CHECK(parse_redis_peer_answer("$5\r\nab\r\n")._kind == redis_peer_answer::kind::other);
    BOOST_CHECK(parse_redis_peer_answer("")._kind == redis_peer_answer::kind::other);
}

// ── the remote data access ─────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(routes_come_from_a_seed_and_writes_go_to_the_leader_hint,
                     *boost::unit_test::timeout(10)) {
    fake_nodes f;
    f.nodes["seed:1"] = [](const std::vector<std::string>& argv) -> std::optional<std::string> {
        BOOST_CHECK_EQUAL(argv.at(1), "ROUTES");
        BOOST_CHECK(wire::decode_range(argv.at(2)).has_value());
        return bulk(wire::encode_routes(one_group(2)));
    };
    f.nodes["n2:1"] = [](const std::vector<std::string>& argv) -> std::optional<std::string> {
        BOOST_CHECK_EQUAL(argv.at(1), "PROPOSE");
        BOOST_CHECK_EQUAL(argv.at(2), "7");
        BOOST_CHECK_EQUAL(argv.at(3), "1");
        BOOST_CHECK_EQUAL(argv.at(4), "1");
        return bulk(wire::encode_propose_ok("applied:" + argv.at(5)));
    };
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK(remote.group_of("k") == std::optional<group_t>{7});
    BOOST_CHECK(remote.leader_of("k") == std::optional<node_t>{2});
    BOOST_CHECK_EQUAL(text_of(remote.propose("k", bytes_of("e"), std::chrono::seconds{1})),
                      "applied:e");
    BOOST_CHECK((f.calls == std::vector<std::string>{"seed:1 ROUTES", "n2:1 PROPOSE"}));
}

BOOST_AUTO_TEST_CASE(not_leader_moves_to_the_named_leader, *boost::unit_test::timeout(10)) {
    fake_nodes f;
    f.nodes["seed:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_routes(one_group(1)));
    };
    f.nodes["n1:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_propose_not_leader(std::optional<node_t>{3}));
    };
    f.nodes["n3:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_propose_ok("ok"));
    };
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK_EQUAL(text_of(remote.propose("k", bytes_of("e"), std::chrono::seconds{1})), "ok");
    BOOST_CHECK(
        (f.calls == std::vector<std::string>{"seed:1 ROUTES", "n1:1 PROPOSE", "n3:1 PROPOSE"}));
    BOOST_CHECK(remote.leader_of("k") == std::optional<node_t>{3});
    BOOST_CHECK_EQUAL(remote.cache().stats().not_leader, 1u);
}

BOOST_AUTO_TEST_CASE(unreachable_and_foreign_nodes_are_skipped, *boost::unit_test::timeout(10)) {
    // n1 (the hint) does not answer, n2 is an old build that refuses the
    // command: both are passed over for n3, never retried in the same round.
    fake_nodes f;
    f.nodes["seed:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_routes(one_group(1)));
    };
    f.nodes["n2:1"] = [](const auto&) -> std::optional<std::string> {
        return std::string("-ERR unknown command 'KYTHIRA.DATA'\r\n");
    };
    f.nodes["n3:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_propose_ok("ok"));
    };
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK_EQUAL(text_of(remote.propose("k", bytes_of("e"), std::chrono::seconds{1})), "ok");
    BOOST_CHECK_EQUAL(remote.cache().stats().connection_failures, 2u);
    BOOST_CHECK(remote.cache().suspect(1));
    // The next write starts at a node that is not suspect.
    BOOST_CHECK(remote.leader_of("k") == std::optional<node_t>{3});
}

BOOST_AUTO_TEST_CASE(a_stale_route_is_replaced_by_the_one_the_refusal_carries,
                     *boost::unit_test::timeout(10)) {
    // The cache holds one group over every key at version 1; the data node
    // has split it: "k" now lives in group 8 at version 2, led by n3.
    routes_t split;
    split.routes.push_back(row(7, std::nullopt, "h", 2, {1, 2, 3}, 1));
    split.routes.push_back(row(8, "h", std::nullopt, 2, {1, 2, 3}, 3));
    split.addresses = {{1, "n1:1"}, {2, "n2:1"}, {3, "n3:1"}};
    fake_nodes f;
    f.nodes["seed:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_routes(one_group(1)));
    };
    f.nodes["n1:1"] = [&](const std::vector<std::string>& argv) -> std::optional<std::string> {
        BOOST_CHECK_EQUAL(argv.at(2), "7");
        return bulk(wire::encode_propose_stale(split));
    };
    f.nodes["n3:1"] = [](const std::vector<std::string>& argv) -> std::optional<std::string> {
        BOOST_CHECK_EQUAL(argv.at(2), "8");
        BOOST_CHECK_EQUAL(argv.at(3), "2");
        return bulk(wire::encode_propose_ok("ok"));
    };
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK_EQUAL(text_of(remote.propose("k", bytes_of("e"), std::chrono::seconds{1})), "ok");
    BOOST_CHECK(remote.group_of("k") == std::optional<group_t>{8});
    BOOST_CHECK(remote.group_of("a") == std::optional<group_t>{7});
}

BOOST_AUTO_TEST_CASE(an_unknown_group_refreshes_the_route, *boost::unit_test::timeout(10)) {
    int fetches = 0;
    fake_nodes f;
    f.nodes["seed:1"] = [&](const auto&) -> std::optional<std::string> {
        ++fetches;
        if (fetches == 1) {
            return bulk(wire::encode_routes(one_group(1)));
        }
        routes_t merged;
        merged.routes.push_back(row(9, std::nullopt, std::nullopt, 3, {2}, 2));
        merged.addresses = {{2, "n2:1"}};
        return bulk(wire::encode_routes(merged));
    };
    f.nodes["n1:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_propose_status(wire::propose_status::unknown_group));
    };
    f.nodes["n2:1"] = [](const std::vector<std::string>& argv) -> std::optional<std::string> {
        if (argv.at(2) != "9") {
            return bulk(wire::encode_propose_status(wire::propose_status::unknown_group));
        }
        return bulk(wire::encode_propose_ok("ok"));
    };
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK_EQUAL(text_of(remote.propose("k", bytes_of("e"), std::chrono::seconds{1})), "ok");
    BOOST_CHECK_GE(fetches, 2);
    BOOST_CHECK(remote.group_of("k") == std::optional<group_t>{9});
}

BOOST_AUTO_TEST_CASE(refusals_the_caller_handles_raise_the_hosts_exceptions,
                     *boost::unit_test::timeout(10)) {
    std::string answer;
    fake_nodes f;
    f.nodes["seed:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_routes(one_group(1)));
    };
    f.nodes["n1:1"] = [&](const auto&) -> std::optional<std::string> { return bulk(answer); };
    remote_t remote({"seed:1"}, f.call(), fast());
    const auto entry = bytes_of("e");
    const auto t = std::chrono::seconds{1};

    answer = wire::encode_propose_locked("k", txn_id{._hi = 1, ._lo = 2}, "p");
    try {
        (void)remote.propose("k", entry, t);
        BOOST_FAIL("expected key_locked_exception");
    } catch (const key_locked_exception<std::string>& e) {
        BOOST_CHECK_EQUAL(e.key(), "k");
        BOOST_CHECK_EQUAL(e.primary(), "p");
        BOOST_CHECK((e.holder() == txn_id{._hi = 1, ._lo = 2}));
    }
    answer = wire::encode_propose_status(wire::propose_status::unrouted);
    BOOST_CHECK_THROW((void)remote.propose("k", entry, t), unrouted_key_exception<std::string>);
    answer = wire::encode_propose_status(wire::propose_status::timeout);
    BOOST_CHECK_THROW((void)remote.propose("k", entry, t), std::runtime_error);
    answer = wire::encode_propose_status(wire::propose_status::failed, "disk full");
    try {
        (void)remote.propose("k", entry, t);
        BOOST_FAIL("expected runtime_error");
    } catch (const std::runtime_error& e) {
        BOOST_CHECK(std::string(e.what()).find("disk full") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(no_answer_in_time_is_not_leader, *boost::unit_test::timeout(10)) {
    fake_nodes f;  // no node answers at all
    remote_t remote({"seed:1"}, f.call(), fast());
    BOOST_CHECK(!remote.route("k").has_value());
    BOOST_CHECK_THROW((void)remote.propose("k", bytes_of("e"), std::chrono::seconds{1}),
                      not_leader_ex);

    // Routes but every voter refuses with no hint: also not leader, at the
    // caller's own (shorter) timeout.
    fake_nodes g;
    g.nodes["seed:1"] = [](const auto&) -> std::optional<std::string> {
        return bulk(wire::encode_routes(one_group(std::nullopt)));
    };
    for (const auto* a : {"n1:1", "n2:1", "n3:1"}) {
        g.nodes[a] = [](const auto&) -> std::optional<std::string> {
            return bulk(wire::encode_propose_not_leader(std::optional<node_t>{}));
        };
    }
    remote_t busy({"seed:1"}, g.call(), fast());
    const auto start = std::chrono::steady_clock::now();
    BOOST_CHECK_THROW((void)busy.propose("k", bytes_of("e"), std::chrono::milliseconds{50}),
                      not_leader_ex);
    BOOST_CHECK_LT(std::chrono::steady_clock::now() - start, std::chrono::milliseconds{250});
}
