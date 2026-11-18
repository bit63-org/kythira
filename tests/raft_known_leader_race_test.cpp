// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// `node::_known_leader`, written by an AppendEntries handler and read by the
// reconnect thread, must be guarded by a lock both of them take.
//
// A restarting node (one with persisted state) starts `run_reconnect()` on a
// thread of its own. That thread waits on `_reconnect_cv` under
// `_reconnect_cv_mutex` alone, and its wait predicate reads `_known_leader`.
// `handle_append_entries` sets `_known_leader` on another thread. It used to
// write it under `_mutex` only, which the reconnect thread never takes, so
// the predicate could read a torn `std::optional` (found by ThreadSanitizer
// on the RocksDB node suite, November 9, 2026). The write is now also made
// under `_reconnect_cv_mutex`.
//
// The race does not change a result a test can see, so this file is a
// ThreadSanitizer regression check: the CI `tsan` job runs it, and a write
// that drops `_reconnect_cv_mutex` is reported there as a data race between
// `handle_append_entries` and `run_reconnect`. Each case starts a restarting
// follower, lets its reconnect thread evaluate the predicate, and delivers a
// heartbeat from a thread of its own, the way a concurrent RPC server would.
// The simulator transport cannot do that (it serves one RPC at a time), so the
// node's handler is registered on a capturing server and called directly.
#define BOOST_TEST_MODULE raft_known_leader_race_test
#include <boost/test/unit_test.hpp>
#include <raft/future_default.hpp>

#include <raft/persistence.hpp>
#include <raft/raft.hpp>
#include <raft/test_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>

#endif
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
struct FollyInitFixture {
    FollyInitFixture() {
        int argc = 1;
        char* argv0[] = {const_cast<char*>("raft_known_leader_race_test"), nullptr};
        char** argv = argv0;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
BOOST_GLOBAL_FIXTURE(FollyInitFixture);
#endif

namespace {

using memory_engine_t =
    kythira::memory_persistence_engine<std::uint64_t, std::uint64_t, std::uint64_t>;
using snapshot_t = memory_engine_t::snapshot_t;
using sm_t = kythira::test_key_value_state_machine<std::uint64_t>;
using ae_request_t = kythira::append_entries_request<>;
using ae_response_t = kythira::append_entries_response<>;

constexpr std::uint64_t k_snapshot_index = 10;
constexpr std::uint64_t k_seed_term = 1;
constexpr std::uint64_t k_leader = 1;
constexpr int k_rounds = 20;

/// The AppendEntries handler `node` registers, kept for the test to call on a
/// thread of its own.
struct registered_handlers {
    std::function<ae_response_t(const ae_request_t&)> append_entries;
};

class capturing_server {
public:
    explicit capturing_server(std::shared_ptr<registered_handlers> h) : _h(std::move(h)) {}

    template<typename F> auto register_request_vote_handler(F) -> void {}
    template<typename F> auto register_install_snapshot_handler(F) -> void {}
    auto register_append_entries_handler(std::function<ae_response_t(const ae_request_t&)> f)
        -> void {
        _h->append_entries = std::move(f);
    }
    auto start() -> void { _running = true; }
    auto stop() -> void { _running = false; }
    [[nodiscard]] auto is_running() const -> bool { return _running; }

private:
    std::shared_ptr<registered_handlers> _h;
    bool _running{false};
};

/// A client that reaches nobody. The node under test is a follower whose
/// election timeout outlasts every case, so it has nothing to send.
class unreachable_client {
public:
    template<typename Request>
    auto send_request_vote(std::uint64_t, const Request&, std::chrono::milliseconds)
        -> kythira::future_default<kythira::request_vote_response<>> {
        return fail<kythira::request_vote_response<>>();
    }
    template<typename Request>
    auto send_append_entries(std::uint64_t, const Request&, std::chrono::milliseconds)
        -> kythira::future_default<ae_response_t> {
        return fail<ae_response_t>();
    }
    template<typename Request>
    auto send_install_snapshot(std::uint64_t, const Request&, std::chrono::milliseconds)
        -> kythira::future_default<kythira::install_snapshot_response<>> {
        return fail<kythira::install_snapshot_response<>>();
    }

private:
    template<typename T> static auto fail() -> kythira::future_default<T> {
        kythira::promise_default<T> promise;
        auto future = promise.getFuture();
        promise.setException(
            std::make_exception_ptr(std::runtime_error("unreachable_client: no peers")));
        return future;
    }
};

template<typename NodeId, typename Address> class empty_peer_discovery {
public:
    using node_id_type = NodeId;
    using address_type = Address;
    auto register_node(NodeId, Address) -> kythira::future_default<void> {
        return kythira::future_factory_default::makeFuture();
    }
    [[nodiscard]] auto find_peers(std::chrono::milliseconds) const
        -> kythira::future_default<std::vector<kythira::peer_info<NodeId, Address>>> {
        return kythira::future_factory_default::makeFuture(
            std::vector<kythira::peer_info<NodeId, Address>>{});
    }
};

struct test_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type = unreachable_client;
    using network_server_type = capturing_server;

    using persistence_engine_type = memory_engine_t;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = sm_t;
    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type>;
    using append_entries_request_type = ae_request_t;
    using append_entries_response_type = ae_response_t;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type>;
    using install_snapshot_response_type = kythira::install_snapshot_response<term_id_type>;

    using address_type = std::string;
    using peer_discovery_type = empty_peer_discovery<node_id_type, address_type>;
    using cluster_join_request_type = kythira::cluster_join_request<node_id_type, address_type>;
    using cluster_join_response_type = kythira::cluster_join_response<node_id_type, address_type>;
};

using node_t = kythira::node<test_types>;

/// Node 3 of {1, 2, 3}, restarting at term 1 from a snapshot through 10, so
/// `start()` launches the reconnect thread rather than bootstrapping.
auto restarting_follower(const std::shared_ptr<registered_handlers>& handlers)
    -> std::unique_ptr<node_t> {
    memory_engine_t engine;
    engine.save_current_term(k_seed_term);
    sm_t sm;
    engine.save_snapshot(snapshot_t{
        ._last_included_index = k_snapshot_index,
        ._last_included_term = k_seed_term,
        ._configuration =
            kythira::cluster_configuration<std::uint64_t>{{1, 2, 3}, false, std::nullopt},
        ._state_machine_state = sm.get_state()});

    kythira::raft_configuration cfg;
    cfg._election_timeout_min = std::chrono::milliseconds{60000};
    cfg._election_timeout_max = std::chrono::milliseconds{70000};
    cfg._heartbeat_interval = std::chrono::milliseconds{50};
    cfg._rpc_timeout = std::chrono::milliseconds{200};
    return std::make_unique<node_t>(kythira::node_config<test_types>{
        .node_id = 3,
        .network_client = unreachable_client{},
        .network_server = capturing_server{handlers},
        .persistence = std::move(engine),
        .logger = kythira::console_logger{kythira::log_level::warning},
        .metrics = test_types::metrics_type{},
        .membership = test_types::membership_manager_type{},
        .config = cfg,
        .self_address = "3",
        .peer_discovery = empty_peer_discovery<std::uint64_t, std::string>{}});
}

auto heartbeat(std::uint64_t term) -> ae_request_t {
    return ae_request_t{._term = term,
                        ._leader_id = k_leader,
                        ._prev_log_index = k_snapshot_index,
                        ._prev_log_term = k_seed_term,
                        ._entries = {},
                        ._leader_commit = k_snapshot_index};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(raft_known_leader_race)

// The reconnect thread reads `_known_leader` in its wait predicate while a
// heartbeat, handled on another thread, sets it. Under ThreadSanitizer the
// two must be ordered by a lock; everywhere, the node must learn its leader
// and `stop()` must join the reconnect thread.
BOOST_AUTO_TEST_CASE(a_heartbeat_sets_the_leader_the_reconnect_thread_waits_for,
                     *boost::unit_test::timeout(120)) {
    for (int round = 0; round < k_rounds; ++round) {
        BOOST_TEST_CONTEXT("round " << round) {
            auto handlers = std::make_shared<registered_handlers>();
            auto node = restarting_follower(handlers);
            node->start();
            BOOST_REQUIRE(handlers->append_entries);
            BOOST_TEST(!node->known_leader().has_value());

            // Let the reconnect thread reach its first predicate check on
            // most rounds; the rest race the handler for it, which is fine
            // either way: TSan orders by locks, not by wall-clock time.
            if (round % 2 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }

            std::optional<ae_response_t> response;
            std::thread server_thread(
                [&] { response = handlers->append_entries(heartbeat(k_seed_term + 1)); });
            server_thread.join();

            BOOST_REQUIRE(response.has_value());
            BOOST_TEST(response->success());
            const auto leader = node->known_leader();
            BOOST_REQUIRE(leader.has_value());
            BOOST_TEST(*leader == k_leader);
            node->stop();
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
