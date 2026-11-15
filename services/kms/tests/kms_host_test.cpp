// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The KMS catalog over multi_raft (.kiro/specs/kms-compatible-api/ task 5,
// Requirements 2.1 and 4.1-4.5): three members on the in-process message
// fabric, each with its own engine, sharing one PKCS#11 token as members
// of a real deployment share the HSM. A request may reach any member: a
// follower forwards its proposals and read barriers to the leader. Key
// creation through a follower leaves an Enabled key on every replica; a
// Creating key a dead leader left is settled by the next leader's jobs; a
// sealed HSM fails CreateKey and leaves no key; a member cut off from the
// leader fails rather than answer from a stale replica.

#define BOOST_TEST_MODULE kms_host_test
#include <boost/test/unit_test.hpp>

#include "kms_fake_pkcs11.hpp"
#include "multi_raft_test_fabric.hpp"

#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_group_state_machine.hpp>
#include <kythira/kms/kms_host.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/memory_kv_engine.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("kms_host_test"), nullptr};
        char** argv = argv_data;
        init_ = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> init_;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;
using kms::catalog_status;
using kms::key_state;
using kythira::memory_kv_engine;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using group_sm = kms::kms_group_state_machine<memory_kv_engine>;

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

    using persistence_engine_type =
        kythira::memory_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = group_sm;

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

using raft_host = kythira::multi_raft<host_types, std::string, std::uint64_t>;
using raft_config = kythira::multi_raft_config<host_types, std::string, std::uint64_t>;
using kms_host = kms::basic_kms_host<raft_host, memory_kv_engine>;
using catalog_type = kms_host::catalog_type;
using jobs_type = kms::key_jobs<catalog_type>;

constexpr std::uint64_t k_members = 3;
constexpr std::uint64_t k_group = 7;  // not 0, as in a composite node
constexpr std::string_view k_account = "111122223333";
constexpr std::uint64_t k_minute = 60000;

auto key_id(int n) -> std::string {
    std::array<char, 37> buf{};
    std::snprintf(buf.data(), buf.size(), "%08x-2222-4000-8000-000000000000", n);
    return buf.data();
}

auto record(const std::string& id) -> kms::key_record {
    kms::key_record k;
    k.key_id = id;
    k.account = std::string(k_account);
    k.spec = kms::key_spec::symmetric_default;
    k.usage = kms::key_usage::encrypt_decrypt;
    k.policy = "{}";
    return k;
}

/// One member: its raft host and KMS host.
struct member {
    std::uint64_t id = 0;
    std::shared_ptr<group_sm::context> ctx;
    std::unique_ptr<raft_host> raft;
    std::unique_ptr<kms_host> host;
};

class cluster {
public:
    /// One token every member reaches, as members share the HSM.
    std::shared_ptr<kt::fake_backend> hsm_backend = std::make_shared<kt::fake_backend>();
    kms::backing_store hsm{hsm_backend, 1, "1234"};
    std::atomic<std::uint64_t> now{10 * k_minute};

    cluster() {
        std::vector<std::uint64_t> ids;
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            ids.push_back(id);
        }
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            auto m = std::make_unique<member>();
            m->id = id;
            m->ctx = kms_host::make_context();
            m->raft = std::make_unique<raft_host>(make_config(id, m->ctx));
            kms_host::options opts;
            opts.members = ids;
            opts.group = k_group;
            opts.propose_timeout = std::chrono::milliseconds{3000};
            opts.forward.propose = [this, id](const std::uint64_t& to,
                                              const std::vector<std::byte>& cmd) {
                reach(id, to);
                return at(to).host->serve_propose(cmd);
            };
            opts.forward.read_index = [this, id](const std::uint64_t& to) {
                reach(id, to);
                return at(to).host->serve_read_index();
            };
            m->host = std::make_unique<kms_host>(*m->raft, m->ctx, opts);
            members_.push_back(std::move(m));
        }
        for (auto& m : members_) {
            m->host->bootstrap();
            m->raft->start();
        }
        running_ = true;
        for (auto& m : members_) {
            drivers_.emplace_back([this, raft = m->raft.get()] {
                while (running_.load()) {
                    raft->tick();
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            });
        }
    }

    ~cluster() {
        running_ = false;
        for (auto& t : drivers_) {
            t.join();
        }
        for (auto& m : members_) {
            m->raft->stop();
        }
        fabric_.shutdown();
    }

    cluster(const cluster&) = delete;
    auto operator=(const cluster&) -> cluster& = delete;
    cluster(cluster&&) = delete;
    auto operator=(cluster&&) -> cluster& = delete;

    [[nodiscard]] auto at(std::uint64_t id) -> member& { return *members_.at(id - 1); }

    /// Key jobs on member `m`, over its replica and its host.
    auto jobs(member& m) -> jobs_type {
        auto c = m.host->catalog();
        BOOST_REQUIRE(c != nullptr);
        return jobs_type(
            *c, hsm, [&m](const std::vector<std::byte>& cmd) { return m.host->propose(cmd); },
            [this] { return now.load(); }, std::chrono::minutes(5));
    }

    auto isolate(std::uint64_t id) -> void {
        const std::lock_guard lock(cut_mutex_);
        for (std::uint64_t other = 1; other <= k_members; ++other) {
            if (other != id) {
                fabric_.partition(id, other);
                fabric_.partition(other, id);
                cut_.insert({id, other});
                cut_.insert({other, id});
            }
        }
    }

    auto heal() -> void {
        const std::lock_guard lock(cut_mutex_);
        fabric_.heal_all();
        cut_.clear();
    }

    static auto await(const std::function<bool()>& predicate,
                      std::chrono::milliseconds budget = std::chrono::seconds{15}) -> bool {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        return predicate();
    }

    [[nodiscard]] auto leader(std::uint64_t except = 0) -> std::uint64_t {
        std::uint64_t found = 0;
        BOOST_REQUIRE(await([&] {
            for (auto& m : members_) {
                if (m->id != except && m->host->leads()) {
                    found = m->id;
                    return true;
                }
            }
            return false;
        }));
        return found;
    }

    [[nodiscard]] auto follower() -> std::uint64_t {
        const auto l = leader();
        return l == 1 ? 2 : 1;
    }

    /// Whether every member's replica has key `id` in `state`.
    auto everywhere(const std::string& id, key_state state) -> bool {
        return await([&] {
            for (auto& m : members_) {
                const auto c = m->host->catalog();
                const auto k = c ? c->key(id) : std::nullopt;
                if (!k || k->state != state) {
                    return false;
                }
            }
            return true;
        });
    }

    /// Whether no member's replica has key `id`.
    auto nowhere(const std::string& id) -> bool {
        return await([&] {
            for (auto& m : members_) {
                const auto c = m->host->catalog();
                if (c && c->key(id)) {
                    return false;
                }
            }
            return true;
        });
    }

private:
    auto reach(std::uint64_t from, std::uint64_t to) -> void {
        const std::lock_guard lock(cut_mutex_);
        if (cut_.contains({from, to})) {
            throw std::runtime_error("partitioned");
        }
    }

    auto make_config(std::uint64_t id, std::shared_ptr<group_sm::context> ctx) -> raft_config {
        raft_config cfg{
            .node_id = id,
            .network_client = fabric_client{fabric_, id},
            .network_server = fabric_server{fabric_, id},
            .store_factory =
                [](const std::uint64_t&) { return host_types::persistence_engine_type{}; },
        };
        cfg.config._election_timeout_min = std::chrono::milliseconds{120};
        cfg.config._election_timeout_max = std::chrono::milliseconds{260};
        cfg.config._heartbeat_interval = std::chrono::milliseconds{25};
        cfg.config._snapshot_disk_margin_bytes = 0;
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.logger = kythira::console_logger(kythira::log_level::error);
        cfg.logger_factory = [](const std::uint64_t&) {
            return kythira::console_logger(kythira::log_level::error);
        };
        cfg.state_engine = std::make_shared<memory_kv_engine>();
        cfg.state_machine_factory = [ctx](const std::uint64_t&) { return group_sm(ctx); };
        cfg.automatic_split_merge_enabled = false;
        cfg.executor_stripes = 2;
        return cfg;
    }

    message_fabric fabric_;
    std::vector<std::unique_ptr<member>> members_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> drivers_;
    std::mutex cut_mutex_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> cut_;
};

}  // namespace

BOOST_AUTO_TEST_CASE(the_catalog_range_is_the_only_one_and_never_splits) {
    BOOST_TEST(group_sm::catalog_range().start == std::string(kms::catalog_namespace));
    group_sm sm;
    memory_kv_engine engine;
    BOOST_CHECK_THROW(sm.open(engine, kythira::key_range{"x/", std::string("x0")}),
                      std::invalid_argument);
    BOOST_CHECK_THROW((void)sm.apply({}, 1), std::logic_error);  // before open
    sm.open(engine, group_sm::catalog_range());
    BOOST_TEST(sm.shared_context()->catalog() != nullptr);
    BOOST_TEST(!sm.can_split_at("kms/k"));
    BOOST_TEST(sm.suggest_split_keys(4).empty());
    BOOST_CHECK_THROW((void)sm.split_at({"kms/k"}), std::logic_error);
    BOOST_CHECK_THROW(sm.adopt(group_sm::catalog_range()), std::logic_error);
    BOOST_TEST(sm.shared_context()->vetoes.load() == 3U);
    sm.drop();
    BOOST_TEST(sm.shared_context()->catalog() == nullptr);
}

BOOST_AUTO_TEST_CASE(create_key_through_a_follower_enables_the_key_everywhere) {
    cluster c;
    auto& f = c.at(c.follower());
    auto jobs = c.jobs(f);
    const auto id = key_id(1);
    const auto r = jobs.create_key(record(id), {{"team", "a"}});
    BOOST_TEST(r.ok());
    // Read your writes on the follower that took the request.
    const auto k = f.host->catalog()->key(id);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST((k->state == key_state::enabled));
    BOOST_TEST(c.everywhere(id, key_state::enabled));
    const auto v = f.host->catalog()->version(id, 1);
    BOOST_REQUIRE(v.has_value());
    BOOST_TEST((c.hsm.find(id, 1) == std::optional<std::uint64_t>(v->hsm_object)));
    BOOST_TEST(f.host->stats().proposals_forwarded >= 2U);
    BOOST_TEST(c.at(c.leader()).host->stats().proposals_served >= 2U);
    // A reused id is the catalog's answer, not an error of the host.
    BOOST_TEST((f.host->propose(kms::make_create_key_command(record(id), {})) ==
                catalog_status::rejected));
    // A barrier through the follower passes.
    BOOST_TEST(f.host->barrier());
}

BOOST_AUTO_TEST_CASE(the_next_leader_settles_what_a_dead_leader_left_creating) {
    cluster c;
    const auto first = c.leader();
    auto& l = c.at(first);
    // The dead leader's first step for two keys; the HSM step happened for
    // only one of them.
    const auto made = key_id(2);
    const auto lost = key_id(3);
    for (const auto& id : {made, lost}) {
        auto k = record(id);
        k.creation_ms = c.now.load();
        BOOST_REQUIRE((l.host->propose(kms::make_create_key_command(k, {})) == catalog_status::ok));
    }
    const auto handle =
        c.hsm.generate(made, 1, kms::key_spec::symmetric_default, kms::key_usage::encrypt_decrypt);
    BOOST_REQUIRE(c.everywhere(made, key_state::creating));
    BOOST_REQUIRE(c.everywhere(lost, key_state::creating));

    c.isolate(first);
    auto& next = c.at(c.leader(first));
    BOOST_REQUIRE(next.host->barrier());
    auto jobs = c.jobs(next);
    // Within the grace period a Creating key is left alone: its CreateKey
    // may still be running.
    const auto early = jobs.run_once();
    BOOST_TEST(early.completed == 0U);
    BOOST_TEST(early.abandoned == 0U);
    c.now += 6 * k_minute;
    const auto r = jobs.run_once();
    BOOST_TEST(r.completed == 1U);
    BOOST_TEST(r.abandoned == 1U);
    BOOST_TEST(r.failures == 0U);
    const auto v = next.host->catalog()->version(made, 1);
    BOOST_REQUIRE(v.has_value());
    BOOST_TEST(v->hsm_object == handle);
    c.heal();
    BOOST_TEST(c.everywhere(made, key_state::enabled));
    BOOST_TEST(c.nowhere(lost));
}

BOOST_AUTO_TEST_CASE(a_sealed_hsm_fails_create_key_and_leaves_no_key) {
    cluster c;
    auto& f = c.at(c.follower());
    auto jobs = c.jobs(f);
    c.hsm_backend->sealed = true;
    const auto id = key_id(4);
    const auto r = jobs.create_key(record(id), {});
    BOOST_TEST((r.outcome == kms::key_outcome::unavailable));
    BOOST_TEST(c.nowhere(id));
    BOOST_TEST(c.hsm_backend->objects().empty());
    // Unsealed again, the same request succeeds.
    c.hsm_backend->sealed = false;
    BOOST_TEST(jobs.create_key(record(key_id(5)), {}).ok());
}

BOOST_AUTO_TEST_CASE(a_member_cut_off_from_the_leader_fails_rather_than_guess) {
    cluster c;
    const auto f = c.follower();
    auto& m = c.at(f);
    BOOST_REQUIRE((m.host->propose(kms::make_create_key_command(record(key_id(6)), {})) ==
                   catalog_status::ok));
    c.isolate(f);
    BOOST_CHECK_THROW((void)m.host->propose(kms::make_create_key_command(record(key_id(7)), {})),
                      kms::kms_unavailable);
    BOOST_TEST(!m.host->barrier());
    // The jobs count the failure and touch nothing.
    auto jobs = c.jobs(m);
    c.now += 6 * k_minute;
    const auto r = jobs.run_once();
    BOOST_TEST(r.abandoned == 0U);
    BOOST_TEST(r.failures >= 1U);
    c.heal();
    BOOST_TEST(c.await([&] { return m.host->barrier(); }));
}
