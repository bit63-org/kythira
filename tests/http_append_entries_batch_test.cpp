// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file http_append_entries_batch_test.cpp
/// @brief Batched AppendEntries over the HTTP transports
///        (`.kiro/specs/multi-raft-message-batching/` task 7, Requirement 5.2
///        and 5.4).
///
/// Two halves. The first talks to one cpp-httplib server directly and pins
/// the wire contract: a batch's members come back in order, an unregistered
/// handler is "not implemented", a server without the route (an older build)
/// is "not implemented" too, and a batch over the member limit is "too
/// large". The second stands three `multi_raft` hosts up over real sockets,
/// on cpp-httplib and on Beast and Proxygen when the build has them, with
/// batching on, and checks that writes commit while AppendEntries travel in
/// batches.

#define BOOST_TEST_MODULE http_append_entries_batch_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_transport_harness.hpp"
#include "test_ports.hpp"
#include "test_timeout_scale.hpp"

#include <raft/exceptions.hpp>
#include <raft/http_transport.hpp>
#include <raft/http_transport_impl.hpp>
#include <raft/json_serializer.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <httplib.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("http_append_entries_batch_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using namespace std::chrono_literals;

using serializer_type = kythira::json_rpc_serializer<std::vector<std::byte>>;
using bundle = kythira::host_transport_types<serializer_type>;
using client_type = kythira::cpp_httplib_client<bundle>;
using server_type = kythira::cpp_httplib_server<bundle>;
using ae_request = kythira::append_entries_request<>;
using ae_response = kythira::append_entries_response<>;
using batch_request = kythira::append_entries_batch_request<ae_request>;
using batch_response = kythira::append_entries_batch_response<ae_response>;

static_assert(kythira::network_client_with_append_entries_batch<client_type>);
static_assert(kythira::network_server_with_append_entries_batch<server_type>);

auto append_for(std::uint64_t group, std::uint64_t term) -> ae_request {
    return ae_request{._term = term,
                      ._leader_id = 1,
                      ._prev_log_index = 0,
                      ._prev_log_term = 0,
                      ._entries = {},
                      ._leader_commit = 0,
                      ._group_id = group};
}

auto batch_of(std::size_t n) -> batch_request {
    batch_request batch;
    for (std::size_t i = 0; i < n; ++i) {
        batch._members.push_back(append_for(10 + i, 3 + i));
    }
    return batch;
}

auto url_for(std::uint16_t port) -> std::string {
    return "http://127.0.0.1:" + std::to_string(port);
}

template<typename Exception, typename Future> auto fails_with(Future f) -> bool {
    try {
        std::move(f).get();
    } catch (const Exception&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

/// One server on a kernel-chosen port, and a client that knows it as node 2.
struct one_server {
    explicit one_server(kythira::cpp_httplib_server_config cfg = {})
        : server("127.0.0.1", 0, cfg, kythira::noop_metrics{}) {}

    auto start() -> void {
        server.start();
        client = std::make_unique<client_type>(
            std::unordered_map<std::uint64_t, std::string>{{2, url_for(server.bound_port())}},
            kythira::cpp_httplib_client_config{}, kythira::noop_metrics{});
    }

    ~one_server() {
        client.reset();
        server.stop();
    }

    server_type server;
    std::unique_ptr<client_type> client;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(cpp_httplib_wire)

BOOST_AUTO_TEST_CASE(members_come_back_in_order, *boost::unit_test::timeout(60)) {
    one_server s;
    s.server.register_append_entries_batch_handler([](const batch_request& batch) {
        batch_response out;
        for (const auto& m : batch.members()) {
            if (m.group_id() == 11) {
                out._members.emplace_back(kythira::batch_member_error{
                    ._kind = kythira::batch_member_error::kind_type::handler_failed,
                    ._message = "nope"});
                continue;
            }
            out._members.emplace_back(ae_response{._term = m.term(),
                                                  ._success = true,
                                                  ._conflict_index = std::nullopt,
                                                  ._conflict_term = std::nullopt,
                                                  ._group_id = m.group_id()});
        }
        return out;
    });
    s.start();
    const auto out = s.client->send_append_entries_batch(2, batch_of(3), 5000ms).get();
    BOOST_REQUIRE_EQUAL(out._members.size(), 3U);
    BOOST_TEST(std::get<0>(out._members[0]).group_id() == 10U);
    BOOST_TEST(std::get<0>(out._members[0]).term() == 3U);
    BOOST_TEST(std::get<1>(out._members[1]).message() == "nope");
    BOOST_TEST(std::get<0>(out._members[2]).group_id() == 12U);
}

// Requirement 4.1's trigger, from a peer that has the route but no handler.
BOOST_AUTO_TEST_CASE(an_unregistered_handler_is_not_implemented, *boost::unit_test::timeout(60)) {
    one_server s;
    s.start();
    BOOST_TEST(fails_with<kythira::rpc_not_implemented_exception>(
        s.client->send_append_entries_batch(2, batch_of(1), 5000ms)));
}

// An older build has no route at all and answers 404.
BOOST_AUTO_TEST_CASE(a_server_without_the_route_is_not_implemented,
                     *boost::unit_test::timeout(60)) {
    httplib::Server old;
    const int port = old.bind_to_any_port("127.0.0.1");
    BOOST_REQUIRE_GT(port, 0);
    std::thread t([&] { old.listen_after_bind(); });
    old.wait_until_ready();
    {
        client_type client(
            std::unordered_map<std::uint64_t, std::string>{
                {2, url_for(static_cast<std::uint16_t>(port))}},
            kythira::cpp_httplib_client_config{}, kythira::noop_metrics{});
        BOOST_TEST(fails_with<kythira::rpc_not_implemented_exception>(
            client.send_append_entries_batch(2, batch_of(2), 5000ms)));
    }
    old.stop();
    t.join();
}

// Requirement 5.4: over the member limit is "too large", not "not implemented".
BOOST_AUTO_TEST_CASE(too_many_members_is_too_large, *boost::unit_test::timeout(60)) {
    kythira::cpp_httplib_server_config cfg;
    cfg.max_append_entries_batch_members = 2;
    one_server s(cfg);
    bool called = false;
    s.server.register_append_entries_batch_handler([&](const batch_request&) {
        called = true;
        return batch_response{};
    });
    s.start();
    BOOST_TEST(fails_with<kythira::rpc_payload_too_large_exception>(
        s.client->send_append_entries_batch(2, batch_of(3), 5000ms)));
    BOOST_TEST(!called);
    // At the limit is fine.
    BOOST_TEST(fails_with<kythira::rpc_payload_too_large_exception>(
                   s.client->send_append_entries_batch(2, batch_of(2), 5000ms)) == false);
}

// And over the body limit is "too large" too.
BOOST_AUTO_TEST_CASE(an_oversized_body_is_too_large, *boost::unit_test::timeout(60)) {
    kythira::cpp_httplib_server_config cfg;
    cfg.max_request_body_size = 512;
    one_server s(cfg);
    s.server.register_append_entries_batch_handler(
        [](const batch_request&) { return batch_response{}; });
    s.start();
    BOOST_TEST(fails_with<kythira::rpc_payload_too_large_exception>(
        s.client->send_append_entries_batch(2, batch_of(20), 5000ms)));
}

BOOST_AUTO_TEST_SUITE_END()

// ── three hosts with batching on ────────────────────────────────────────────

namespace {

auto batching_options() -> kythira::testing::kv_cluster_options {
    kythira::testing::kv_cluster_options options;
    options._nodes = 3;
    options._groups = 8;
    options._key_count = 1000;
    options._election_timeout_min = 300ms;
    options._election_timeout_max = 600ms;
    options._heartbeat_interval = 50ms;
    options._batching._enabled = true;
    return options;
}

template<typename Transport> auto writes_commit_in_batches() -> void {
    kythira::testing::kv_cluster<Transport> cluster(batching_options());
    BOOST_REQUIRE_MESSAGE(cluster.await_all_leaders(kythira::testing::scaled_deadline(20000)),
                          "no leaders over " << Transport::name());
    BOOST_REQUIRE(cluster.host(0).batching_active());

    const auto before = cluster.rpc_counts();
    kythira::testing::operation_tally tally;
    std::size_t committed = 0;
    for (std::uint64_t i = 0; i < 200; ++i) {
        const auto key = kythira::testing::kv_key(i * 5);
        if (cluster.run_command(key, kythira::testing::kv_put(key, "v"), 5000ms, tally)) {
            ++committed;
        }
    }
    const auto window = cluster.rpc_counts() - before;
    BOOST_TEST_MESSAGE(Transport::name()
                       << ": " << committed << " writes, " << window._append_entries
                       << " AppendEntries in " << window._append_entries_batches << " batches");
    BOOST_CHECK_GE(committed, 190U);
    BOOST_CHECK_GT(window._append_entries_batches, 0U);
    BOOST_CHECK_GT(window._batched_members, window._append_entries_batches);
    BOOST_CHECK_LT(window.wire_rpcs(), window.total_rpcs());
    std::uint64_t fallbacks = 0;
    for (std::size_t h = 0; h < cluster.host_count(); ++h) {
        fallbacks += cluster.host(h).batcher()->fallbacks();
    }
    BOOST_CHECK_EQUAL(fallbacks, 0U);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(multi_raft_over_http)

BOOST_AUTO_TEST_CASE(cpp_httplib_writes_commit_in_batches, *boost::unit_test::timeout(180)) {
    writes_commit_in_batches<kythira::testing::cpp_httplib_transport<serializer_type>>();
}

#if defined(KYTHIRA_BENCH_HAS_BEAST)
BOOST_AUTO_TEST_CASE(beast_writes_commit_in_batches, *boost::unit_test::timeout(180)) {
    writes_commit_in_batches<kythira::testing::beast_http_transport<serializer_type>>();
}
#endif

#if defined(KYTHIRA_BENCH_HAS_PROXYGEN)
BOOST_AUTO_TEST_CASE(proxygen_writes_commit_in_batches, *boost::unit_test::timeout(180)) {
    writes_commit_in_batches<kythira::testing::proxygen_http_transport<serializer_type>>();
}
#endif

BOOST_AUTO_TEST_SUITE_END()
