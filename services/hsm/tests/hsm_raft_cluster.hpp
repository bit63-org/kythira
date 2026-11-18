// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A three-member HSM store on multi_raft and the in-process message
// fabric, each member with its own engine, vault, session layer and
// client (.kiro/specs/virtual-hsm/ task 6c). hsm_host_test drives it as a
// co-located cluster; hsm_remote_store_test adds crypto-only nodes that
// reach it through the store API
// (.kiro/specs/hsm-independent-layers/ task 3).
//
// The including test must set up folly (or another future backend) the
// way hsm_host_test does.

#include "multi_raft_test_fabric.hpp"

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_group_state_machine.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/native_client.hpp>
#include <kythira/hsm/session_layer.hpp>
#include <kythira/hsm/shamir.hpp>

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/memory_kv_engine.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/persistence.hpp>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::hsm::raft_test {

namespace hsm = kythira::hsm;

using kythira::memory_kv_engine;
using kythira::testing::fabric_client;
using kythira::testing::fabric_server;
using kythira::testing::message_fabric;

using group_sm = hsm::hsm_group_state_machine<memory_kv_engine>;

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
using hsm_host = hsm::basic_hsm_host<raft_host, memory_kv_engine>;

inline constexpr std::uint64_t k_members = 3;
inline constexpr std::uint64_t k_token = 1;
inline const std::string k_so_pin = "so-secret";
inline const std::string k_user_pin = "user-1234";
inline const hsm::bytes k_p256 = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
inline const CK_MECHANISM k_ec_gen{CKM_EC_KEY_PAIR_GEN, nullptr, 0};
inline const CK_MECHANISM k_ecdsa{CKM_ECDSA_SHA256, nullptr, 0};

auto rv(const auto& result) -> CK_RV {
    return result ? CKR_OK : result.error();
}

inline auto data(std::string_view s) -> std::vector<std::uint8_t> {
    return {s.begin(), s.end()};
}

inline auto session_options() -> hsm::session_options {
    hsm::session_options o;
    o.pin_log2_n = 10;  // fast tests
    o.max_login_failures = 3;
    return o;
}

/// One member: its raft host, HSM store, vault, session layer and client.
struct member {
    std::uint64_t id = 0;
    std::shared_ptr<group_sm::context> ctx;
    std::unique_ptr<raft_host> raft;
    std::unique_ptr<hsm_host> host;
    hsm::key_vault vault;
    std::unique_ptr<hsm::session_layer> layer;
    std::unique_ptr<hsm::native_client> client;
};

class cluster {
public:
    cluster() {
        std::vector<std::uint64_t> ids;
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            ids.push_back(id);
        }
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            auto m = std::make_unique<member>();
            m->id = id;
            m->ctx = hsm_host::make_context();
            m->raft = std::make_unique<raft_host>(make_config(id, m->ctx));
            hsm_host::options opts;
            opts.members = ids;
            opts.propose_timeout = std::chrono::milliseconds{3000};
            opts.maintenance_interval = std::chrono::milliseconds{50};
            opts.forward.propose = [this, id](const std::uint64_t& to, std::uint64_t g,
                                              const std::vector<std::byte>& cmd) {
                reach(id, to);
                return at(to).host->serve_propose(g, cmd);
            };
            opts.forward.read_index = [this, id](const std::uint64_t& to, std::uint64_t g) {
                reach(id, to);
                return at(to).host->serve_read_index(g);
            };
            m->host = std::make_unique<hsm_host>(*m->raft, m->ctx, opts);
            m->layer = std::make_unique<hsm::session_layer>(*m->host, m->vault, session_options());
            m->client = std::make_unique<hsm::native_client>(*m->layer, "app-a");
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
        for (auto& m : members_) {
            m->host->start();
        }
    }

    ~cluster() {
        for (auto& m : members_) {
            m->client.reset();
            m->host->stop();
        }
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

    /// The master key every member was unsealed with.
    [[nodiscard]] auto master_key() const -> const hsm::secret_bytes& { return mk_; }

    /// Cut `id` off from every other member, both ways, forwarding too.
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

    /// The member leading local group `local`, other than `except`.
    [[nodiscard]] auto leader_of(std::uint64_t local, std::uint64_t except = 0)
        -> std::optional<std::uint64_t> {
        for (auto& m : members_) {
            if (m->id != except && m->host->leads(local)) {
                return m->id;
            }
        }
        return std::nullopt;
    }

    /// A member that does not lead local group `local`, other than `except`.
    [[nodiscard]] auto follower_of(std::uint64_t local, std::uint64_t except = 0) -> std::uint64_t {
        std::optional<std::uint64_t> leader;
        BOOST_REQUIRE(await([&] { return (leader = leader_of(local)).has_value(); }));
        for (std::uint64_t id = 1; id <= k_members; ++id) {
            if (id != *leader && id != except) {
                return id;
            }
        }
        BOOST_FAIL("no follower");
        return 0;
    }

    /// Initialize the catalog through a follower, create and bind
    /// `k_token`, unseal every member and set the token's PINs.
    auto initialize() -> void {
        BOOST_REQUIRE(hsm::generate_random(mk_.span()).has_value());
        auto& f = at(follower_of(0));
        BOOST_REQUIRE(propose_catalog(f, hsm::make_initialize_command(
                                             hsm::unseal_mode::operator_shares, 2, 3,
                                             hsm::key_check_value(mk_.view()))) == CKR_OK);
        for (auto& m : members_) {
            BOOST_REQUIRE(await([&] { return m->host->catalog().has_value(); }));
            BOOST_REQUIRE(m->vault.unseal(mk_.clone(), m->host->catalog()) ==
                          hsm::unseal_result::unsealed);
        }
        add_token(f, k_token, "alpha");
        auto& c = *f.client;
        BOOST_REQUIRE(rv(c.init_token(k_token, k_so_pin, "alpha")) == CKR_OK);
        auto s = c.open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        BOOST_REQUIRE(s.has_value());
        BOOST_REQUIRE(rv(c.login(*s, CKU_SO, k_so_pin)) == CKR_OK);
        BOOST_REQUIRE(rv(c.init_pin(*s, k_user_pin)) == CKR_OK);
        BOOST_REQUIRE(rv(c.close_session(*s)) == CKR_OK);
    }

    auto add_token(member& m, std::uint64_t id, const std::string& label) -> void {
        auto t = hsm::prepare_token(mk_.view(), 1, id, label);
        BOOST_REQUIRE(propose_catalog(m, hsm::make_create_token_command(t.entry)) == CKR_OK);
        BOOST_REQUIRE(propose_catalog(m, hsm::make_bind_command("app-a", id)) == CKR_OK);
        for (auto& each : members_) {
            BOOST_REQUIRE(await([&] { return each->host->hosts(id); }));
        }
    }

    static auto propose_catalog(member& m, std::vector<std::byte> cmd) -> CK_RV {
        auto r = m.host->propose_catalog(std::move(cmd));
        BOOST_REQUIRE(r.has_value());
        return hsm::catalog_reply_rv(*r);
    }

    /// A read-write session on member `m`, logged in as the token's user.
    /// A login takes a read-index round, which answers CKR_DEVICE_ERROR
    /// while the member has not yet heard a leader of the current term
    /// (just after an election, or a healed former leader), so it is
    /// retried until one answers.
    static auto user_session(member& m) -> CK_SESSION_HANDLE {
        CK_SESSION_HANDLE out = 0;
        BOOST_REQUIRE(await([&] {
            auto s = m.client->open_session(k_token, CKF_SERIAL_SESSION | CKF_RW_SESSION);
            if (!s.has_value()) {
                return false;
            }
            const auto r = rv(m.client->login(*s, CKU_USER, k_user_pin));
            if (r == CKR_OK) {
                out = *s;
                return true;
            }
            BOOST_REQUIRE(r == CKR_DEVICE_ERROR);
            (void)m.client->close_session(*s);
            return false;
        }));
        return out;
    }

    static auto ec_pair(member& m, CK_SESSION_HANDLE s)
        -> std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> {
        hsm::attribute_map pub;
        pub.set_bool(CKA_TOKEN, true);
        pub.set_bytes(CKA_EC_PARAMS, k_p256);
        pub.set_bool(CKA_VERIFY, true);
        hsm::attribute_map priv;
        priv.set_bool(CKA_TOKEN, true);
        priv.set_bool(CKA_SIGN, true);
        auto pair = m.client->generate_key_pair(s, k_ec_gen, pub, priv);
        BOOST_REQUIRE(pair.has_value());
        return *pair;
    }

    static auto sign(member& m, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key, std::string_view msg)
        -> hsm::ck_result<hsm::bytes> {
        if (auto r = m.client->sign_init(s, k_ecdsa, key); !r) {
            return hsm::unexpected(r.error());
        }
        return m.client->sign(s, data(msg));
    }

    static auto verify(member& m, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key, std::string_view msg,
                       const hsm::bytes& sig) -> CK_RV {
        if (auto r = m.client->verify_init(s, k_ecdsa, key); !r) {
            return r.error();
        }
        return rv(m.client->verify(s, data(msg), sig));
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
    hsm::secret_bytes mk_{32};
    std::mutex cut_mutex_;
    std::set<std::pair<std::uint64_t, std::uint64_t>> cut_;
};

}  // namespace kythira::hsm::raft_test
