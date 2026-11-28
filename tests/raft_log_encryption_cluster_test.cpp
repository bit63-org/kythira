// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file raft_log_encryption_cluster_test.cpp
/// @brief A three-node cluster whose nodes seal their Raft logs in
///        different modes (`.kiro/specs/raft-log-encryption/` task 3,
///        requirements 4.4-4.6).
///
/// Three in-process hosts over one message fabric, each keeping one group's
/// Raft log on disk in `binary_file_persistence_engine` with its own options:
///
/// 1. node 1 plaintext, nodes 2 and 3 sealed;
/// 2. restarted with node 3 in `decrypt_only` (the step on the way off),
///    then two leader changes in which a new leader must send a lagging
///    follower entries read back from its own log;
/// 3. node 3's log rewritten in the clear offline and the node restarted
///    with no key ring at all, while node 1 turns sealing on.
///
/// After each phase every node holds every write, and a byte scan of each
/// node's files shows exactly the values its modes allowed in the clear:
/// sealing never changes what goes over the wire, so nodes in any mix of
/// modes replicate with each other and through any leader.

#define BOOST_TEST_MODULE raft_log_encryption_cluster_test
#include <boost/test/unit_test.hpp>

#include "multi_raft_kv_workload.hpp"
#include "multi_raft_test_fabric.hpp"

#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/raft_log_encryption.hpp>
#include <raft/test_state_machine.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("raft_log_encryption_cluster_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

namespace fs = std::filesystem;

using kythira::hibernation_mode;
using kythira::log_encryption_mode;
using kythira::multi_raft;
using kythira::multi_raft_config;
using kythira::shard_descriptor;
using kythira::shard_epoch;
using kythira::shard_range;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::kv_partitioner;
using kythira::testing::message_fabric;

using key_type = std::string;
using group_id_type = std::uint64_t;
using node_id_t = std::uint64_t;
using kv_sm = kythira::test_key_value_state_machine<std::uint64_t>;
using engine_type =
    kythira::binary_file_persistence_engine<std::uint64_t, std::uint64_t, std::uint64_t>;

struct host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = std::uint64_t;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type = fabric_client;
    using network_server_type = fabric_server;

    using persistence_engine_type = engine_type;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = kv_sm;

    using configuration_type = kythira::raft_configuration;

    using log_entry_type = kythira::log_entry<term_id_type, log_index_type>;
    using cluster_configuration_type = kythira::cluster_configuration<node_id_type>;
    using snapshot_type = kythira::snapshot<node_id_type, term_id_type, log_index_type>;

    using request_vote_request_type =
        kythira::request_vote_request<node_id_type, term_id_type, log_index_type, group_id_type>;
    using request_vote_response_type = kythira::request_vote_response<term_id_type, group_id_type>;
    using append_entries_request_type =
        kythira::append_entries_request<node_id_type, term_id_type, log_index_type, log_entry_type,
                                        group_id_type>;
    using append_entries_response_type =
        kythira::append_entries_response<term_id_type, log_index_type, group_id_type>;
    using install_snapshot_request_type =
        kythira::install_snapshot_request<node_id_type, term_id_type, log_index_type,
                                          group_id_type>;
    using install_snapshot_response_type =
        kythira::install_snapshot_response<term_id_type, group_id_type>;
};

using host_type = multi_raft<host_types, key_type, group_id_type>;
using config_type = multi_raft_config<host_types, key_type, group_id_type>;
using descriptor_type = shard_descriptor<group_id_type, key_type, std::uint64_t>;

constexpr group_id_type k_group = 1;
constexpr node_id_t k_node_count = 3;
constexpr auto k_timeout = std::chrono::milliseconds{2000};
constexpr auto k_election_timeout_max = std::chrono::milliseconds{260};

/// A directory removed when the test ends.
class temp_dir {
public:
    temp_dir() {
        static std::atomic<int> counter{0};
        _path = fs::temp_directory_path() / ("kythira-rle-cluster-" + std::to_string(::getpid()) +
                                             "-" + std::to_string(counter.fetch_add(1)));
        fs::create_directories(_path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    [[nodiscard]] auto path() const -> const fs::path& { return _path; }

private:
    fs::path _path;
};

[[nodiscard]] auto node_dir(const fs::path& root, node_id_t id) -> fs::path {
    return root / ("node-" + std::to_string(id));
}

[[nodiscard]] auto group_dir(const fs::path& root, node_id_t id) -> fs::path {
    return node_dir(root, id) / ("group-" + std::to_string(k_group));
}

/// How one node keeps its log in a phase.
enum class mode {
    plaintext,
    sealed,
    decrypt_only
};

/// The node's engine options for `m`: a key ring in its data directory
/// (opened, or reloaded, from `raft-log-keys` there) unless plaintext.
[[nodiscard]] auto options_for(const fs::path& root, node_id_t id, mode m)
    -> kythira::binary_file_persistence_options {
    kythira::binary_file_persistence_options o;
    if (m == mode::plaintext) {
        return o;
    }
    kythira::raft_log_data_key_bytes wrapping{};
    wrapping.fill(static_cast<unsigned char>(0x40 + id));
    fs::create_directories(node_dir(root, id));
    o._key_ring = kythira::raft_log_key_file_ring::open(
        node_dir(root, id) / "raft-log-keys", kythira::raft_log_fixed_key_source(wrapping));
    o._encryption =
        m == mode::sealed ? log_encryption_mode::seal : log_encryption_mode::decrypt_only;
    return o;
}

/// Three hosts over one fabric, each driven by its own thread, each with
/// its own engine options; a second `cluster` over the same directory is
/// the first one restarted.
class cluster {
public:
    cluster(const fs::path& dir, const std::array<mode, k_node_count>& modes) {
        const std::vector<node_id_t> voters{1, 2, 3};
        for (node_id_t id = 1; id <= k_node_count; ++id) {
            _hosts.push_back(std::make_unique<host_type>(make_config(id, dir, modes.at(id - 1))));
            if (!_hosts.back()->has_group(k_group)) {
                _hosts.back()->create_group(descriptor_type{
                    ._group_id = k_group,
                    ._range = shard_range<key_type>{._start = std::nullopt, ._end = std::nullopt},
                    ._epoch = shard_epoch{},
                    ._voters = voters});
            }
        }
        for (auto& h : _hosts) {
            h->start();
        }
        _running = true;
        for (auto& h : _hosts) {
            _drivers.emplace_back([this, host = h.get()] {
                while (_running.load()) {
                    host->tick();
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            });
        }
    }

    ~cluster() {
        _running = false;
        for (auto& t : _drivers) {
            t.join();
        }
        for (auto& h : _hosts) {
            h->stop();
        }
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;

    [[nodiscard]] auto host(node_id_t id) -> host_type& { return *_hosts.at(id - 1); }

    /// The host whose replica leads, among those not in `skip`.
    [[nodiscard]] auto await_leader(const std::vector<node_id_t>& skip = {})
        -> std::optional<node_id_t> {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        while (std::chrono::steady_clock::now() < deadline) {
            for (node_id_t id = 1; id <= k_node_count; ++id) {
                if (std::find(skip.begin(), skip.end(), id) != skip.end()) {
                    continue;
                }
                auto* n = host(id).group_node(k_group);
                if (n != nullptr && n->is_leader()) {
                    return id;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return std::nullopt;
    }

    /// Write `key` = `value` through whichever host leads among those not
    /// in `skip`, retrying through elections. Returns the host that took it.
    auto put(const std::string& key, const std::string& value,
             const std::vector<node_id_t>& skip = {}) -> node_id_t {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        std::string last;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto leader = await_leader(skip);
            if (!leader) {
                break;
            }
            try {
                std::ignore =
                    host(*leader)
                        .submit_command(key, kv_sm::make_put_command(key, value), k_timeout)
                        .get();
                return *leader;
            } catch (const std::exception& e) {
                last = e.what();
                std::this_thread::sleep_for(std::chrono::milliseconds{20});
            }
        }
        throw std::runtime_error("no leader took " + key + ": " + last);
    }

    /// The value host `id`'s replica has applied for `key`.
    [[nodiscard]] auto value_at(node_id_t id, const std::string& key)
        -> std::optional<std::string> {
        auto* n = host(id).group_node(k_group);
        if (n == nullptr) {
            return std::nullopt;
        }
        std::optional<std::string> out;
        n->with_state_machine([&](kv_sm& sm) { out = sm.get_value(key); });
        return out;
    }

    /// Wait until every host has applied every write in `expected`.
    [[nodiscard]] auto converged(const std::map<std::string, std::string>& expected) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        while (std::chrono::steady_clock::now() < deadline) {
            bool all = true;
            for (node_id_t id = 1; id <= k_node_count && all; ++id) {
                for (const auto& [k, v] : expected) {
                    if (value_at(id, k) != v) {
                        all = false;
                        break;
                    }
                }
            }
            if (all) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return false;
    }

    /// Cut `id` off from every other host, both ways.
    auto isolate(node_id_t id) -> void {
        for (node_id_t other = 1; other <= k_node_count; ++other) {
            if (other != id) {
                _fabric.partition(id, other);
                _fabric.partition(other, id);
            }
        }
    }

    /// Restore the links between `a` and `b`, both ways.
    auto heal_link(node_id_t a, node_id_t b) -> void {
        _fabric.heal(a, b);
        _fabric.heal(b, a);
    }

    auto heal() -> void { _fabric.heal_all(); }

private:
    auto make_config(node_id_t id, const fs::path& dir, mode m) -> config_type {
        const auto gdir = group_dir(dir, id);
        config_type cfg{
            .node_id = id,
            .network_client = fabric_client{_fabric, id},
            .network_server = fabric_server{_fabric, id},
            .store_factory = [gdir, options = options_for(dir, id, m)](
                                 const group_id_type&) { return engine_type{gdir, options}; },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{120};
        cfg.config._election_timeout_max = k_election_timeout_max;
        cfg.config._heartbeat_interval = std::chrono::milliseconds{25};
        cfg.hibernation = hibernation_mode::off;
        cfg.automatic_split_merge_enabled = false;
        cfg.executor_stripes = 2;
        cfg.partitioner = kythira::make_partitioner<key_type>(kv_partitioner{});
        cfg.logger = kythira::console_logger{kythira::log_level::warning};
        cfg.logger_factory = [](const group_id_type&) {
            return kythira::console_logger{kythira::log_level::warning};
        };
        return cfg;
    }

    message_fabric _fabric{8};
    std::vector<std::unique_ptr<host_type>> _hosts;
    std::vector<std::thread> _drivers;
    std::atomic<bool> _running{false};
};

/// A value easy to find in a byte scan; never a substring of another.
[[nodiscard]] auto marker(int phase, int i) -> std::string {
    return "SECRET-P" + std::to_string(phase) + "-" + std::to_string(1000 + i) + "-MARKER";
}

/// Every file under `dir`, concatenated.
[[nodiscard]] auto all_bytes(const fs::path& dir) -> std::string {
    std::string out;
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        if (!e.is_regular_file()) {
            continue;
        }
        std::ifstream in(e.path(), std::ios::binary);
        out.append(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    return out;
}

/// How many of phase `phase`'s `count` markers appear in `bytes`.
[[nodiscard]] auto markers_found(const std::string& bytes, int phase, int count) -> int {
    int found = 0;
    for (int i = 0; i < count; ++i) {
        if (bytes.find(marker(phase, i)) != std::string::npos) {
            ++found;
        }
    }
    return found;
}

[[nodiscard]] auto sealed_records(const fs::path& root, node_id_t id,
                                  const kythira::binary_file_persistence_options& o)
    -> std::size_t {
    const engine_type engine{group_dir(root, id), o};
    return engine.sealed_record_count();
}

constexpr int k_writes = 15;

}  // namespace

BOOST_AUTO_TEST_SUITE(raft_log_encryption_cluster)

// Requirements 4.4-4.6: plaintext, sealed and decrypt-only nodes replicate
// through leader changes, each node's files hold exactly what its mode let
// it write in the clear, and nodes move between modes with a restart (and,
// off, a rewrite) while the cluster keeps every write.
BOOST_AUTO_TEST_CASE(mixed_modes_replicate_through_leader_changes,
                     *boost::unit_test::timeout(300)) {
    temp_dir dir;
    std::map<std::string, std::string> expected;
    const auto put = [&](cluster& c, int phase, int i, const std::vector<node_id_t>& skip = {}) {
        const auto key = "k-" + std::to_string(phase) + "-" + std::to_string(i);
        expected[key] = marker(phase, i);
        return c.put(key, marker(phase, i), skip);
    };

    // Phase 1: node 1 plaintext, nodes 2 and 3 sealed.
    {
        cluster c(dir.path(), {mode::plaintext, mode::sealed, mode::sealed});
        for (int i = 0; i < k_writes; ++i) {
            put(c, 1, i);
        }
        BOOST_REQUIRE(c.converged(expected));
    }
    BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 1)), 1, k_writes) == k_writes);
    BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 2)), 1, k_writes) == 0);
    BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 3)), 1, k_writes) == 0);

    // Phase 2: node 3 on its way off (decrypt_only), through two leader
    // changes. Each round lags one follower behind a write, then cuts the
    // leader off: the new leader (the follower that kept up) must send the
    // lagging one entries read back from its own log, sealed or not.
    {
        cluster c(dir.path(), {mode::plaintext, mode::sealed, mode::decrypt_only});
        BOOST_REQUIRE(c.converged(expected));  // node 3 reads its sealed records
        int i = 0;
        std::vector<node_id_t> leaders;
        for (int round = 0; round < 2; ++round) {
            c.heal();
            const auto leader = c.await_leader();
            BOOST_REQUIRE(leader.has_value());
            const node_id_t lagging = *leader % k_node_count + 1;
            c.isolate(lagging);
            node_id_t writer = 0;
            for (int n = 0; n < 5; ++n) {
                writer = put(c, 2, i++, {lagging});
            }
            leaders.push_back(writer);
            // Cut the writer off before the lagging node hears from anyone,
            // then join the lagging node to the one that kept up, which
            // alone has every committed entry and so wins.
            c.isolate(writer);
            const node_id_t other = 6 - writer - lagging;
            c.heal_link(lagging, other);
            const auto next = put(c, 2, i++, {writer});
            BOOST_TEST(next == other);
            for (int n = 0; n < 2; ++n) {
                put(c, 2, i++, {writer});
            }
        }
        c.heal();
        BOOST_TEST_MESSAGE("phase 2 leaders: " << leaders.at(0) << ", " << leaders.at(1));
        BOOST_REQUIRE(c.converged(expected));
        BOOST_REQUIRE(i == 2 * 8);
    }
    constexpr int k_phase2 = 16;
    {
        const auto n1 = all_bytes(node_dir(dir.path(), 1));
        const auto n2 = all_bytes(node_dir(dir.path(), 2));
        const auto n3 = all_bytes(node_dir(dir.path(), 3));
        BOOST_TEST(markers_found(n1, 2, k_phase2) == k_phase2);
        BOOST_TEST(markers_found(n2, 1, k_writes) == 0);
        BOOST_TEST(markers_found(n2, 2, k_phase2) == 0);
        // decrypt_only writes in the clear and leaves what it sealed sealed.
        BOOST_TEST(markers_found(n3, 1, k_writes) == 0);
        BOOST_TEST(markers_found(n3, 2, k_phase2) == k_phase2);
    }

    // Offline, node 3 rewrites its log in the clear and drops its key ring.
    {
        const auto o = options_for(dir.path(), 3, mode::decrypt_only);
        BOOST_TEST(sealed_records(dir.path(), 3, o) > 0U);
        {
            engine_type engine{group_dir(dir.path(), 3), o};
            engine.rewrite_records();
            BOOST_TEST(engine.sealed_record_count() == 0U);
            BOOST_TEST(!engine.lowest_live_generation().has_value());
        }
        BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 3)), 1, k_writes) == k_writes);
        fs::remove(node_dir(dir.path(), 3) / "raft-log-keys");
    }

    // Phase 3: node 3 with no key ring at all; node 1 turns sealing on.
    {
        cluster c(dir.path(), {mode::sealed, mode::sealed, mode::plaintext});
        BOOST_REQUIRE(c.converged(expected));
        for (int i = 0; i < k_writes; ++i) {
            put(c, 3, i);
        }
        const auto leader = c.await_leader();
        BOOST_REQUIRE(leader.has_value());
        c.isolate(*leader);
        put(c, 3, k_writes, {*leader});
        c.heal();
        BOOST_REQUIRE(c.converged(expected));
    }
    constexpr int k_phase3 = k_writes + 1;
    const auto n1 = all_bytes(node_dir(dir.path(), 1));
    BOOST_TEST(markers_found(n1, 1, k_writes) == k_writes);  // old records stay plaintext
    BOOST_TEST(markers_found(n1, 3, k_phase3) == 0);         // new ones are sealed
    BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 2)), 3, k_phase3) == 0);
    BOOST_TEST(markers_found(all_bytes(node_dir(dir.path(), 3)), 3, k_phase3) == k_phase3);
    // Phase 3's writes, plus whatever no-op entries its elections added.
    BOOST_TEST(sealed_records(dir.path(), 1, options_for(dir.path(), 1, mode::sealed)) >=
               static_cast<std::size_t>(k_phase3));
}

BOOST_AUTO_TEST_SUITE_END()
