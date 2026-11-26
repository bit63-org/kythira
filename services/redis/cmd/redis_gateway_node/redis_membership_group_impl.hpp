// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_membership_group_impl.hpp
/// @brief `make_membership_group`'s definition, included only by the
///        membership_group_*.cpp files that instantiate it.

#include "redis_membership_group.hpp"

#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/json_serializer.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/persistence.hpp>

#include <algorithm>
#include <exception>
#include <string>
#include <utility>

namespace kythira::redis_node {

namespace membership_detail {

template<typename Host> struct types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = kythira::host_node_id;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    using serializer_type = kythira::json_rpc_serializer<serialized_data_type>;

    using network_client_type =
        kythira::transport_client_handle<typename Host::client_type, node_id_type>;
    using network_server_type = typename Host::view_type;

    using persistence_engine_type =
        kythira::memory_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = layers::layer_membership_state_machine<std::uint64_t>;

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

template<typename Host> class group final : public membership_group {
public:
    using types_type = types<Host>;
    using host_type = kythira::multi_raft<types_type, std::string, std::uint64_t>;
    using config_type = kythira::multi_raft_config<types_type, std::string, std::uint64_t>;
    using descriptor_type = typename host_type::descriptor_type;
    using state_machine_type = typename types_type::state_machine_type;

    group(const node_options& opt, Host& node, std::uint64_t id, typename Host::view_type view)
        : _id(id),
          _timeout(std::max(opt._rpc_timeout * 2, std::chrono::milliseconds{1000})),
          _logger{opt._log_level} {
        config_type cfg{
            .node_id = opt._node_id,
            .network_client = typename types_type::network_client_type{node.client()},
            .network_server = std::move(view),
            .store_factory =
                [](const std::uint64_t&) { return typename types_type::persistence_engine_type{}; },
        };
        cfg.logger = kythira::console_logger{opt._log_level};
        cfg.logger_factory = [level = opt._log_level](const std::uint64_t&) {
            return kythira::console_logger{level};
        };
        cfg.config._election_timeout_min = opt._election_timeout_min;
        cfg.config._election_timeout_max = opt._election_timeout_max;
        cfg.config._heartbeat_interval = opt._heartbeat_interval;
        cfg.config._rpc_timeout = opt._rpc_timeout;
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.executor_stripes = 1;
        // A group of its own with no keys: the split and merge policy has
        // nothing to do here.
        cfg.policy_interval = std::chrono::hours{24};
        _host = std::make_unique<host_type>(std::move(cfg));
        _host->create_group(descriptor_type{._group_id = id,
                                            ._range = kythira::unbounded_shard_range<std::string>(),
                                            ._epoch = kythira::shard_epoch{},
                                            ._voters = opt._membership_voters});
    }

    ~group() override { group::stop(); }
    group(const group&) = delete;
    auto operator=(const group&) -> group& = delete;
    group(group&&) = delete;
    auto operator=(group&&) -> group& = delete;

    void start() override {
        if (!_started) {
            _host->start();
            _started = true;
        }
    }
    void stop() override {
        if (_started) {
            _host->stop();
            _started = false;
        }
    }
    void tick() override {
        if (_started) {
            (void)_host->tick();
        }
    }

    auto propose(std::vector<std::byte> command) -> std::optional<std::vector<std::byte>> override {
        try {
            auto* node = _host->group_node(_id);
            if (node == nullptr || !node->is_leader()) {
                return std::nullopt;  // the caller asks the next voter
            }
            const auto epoch = _host->local_descriptor(_id)->_epoch;
            return _host->submit_command(_id, epoch, command, _timeout).get();
        } catch (const std::exception& e) {
            _logger.log(kythira::log_level::debug, "redis membership group: proposal failed",
                        {{"error", e.what()}});
            return std::nullopt;
        }
    }

    [[nodiscard]] auto read() -> std::vector<layers::layer_member> override {
        auto* node = _host->group_node(_id);
        if (node == nullptr) {
            return {};
        }
        return node->with_state_machine([](state_machine_type& sm) { return sm.members(); });
    }

private:
    std::uint64_t _id;
    std::chrono::milliseconds _timeout;
    kythira::console_logger _logger;
    std::unique_ptr<host_type> _host;
    bool _started = false;
};

}  // namespace membership_detail

template<typename Host>
auto make_membership_group(const node_options& opt, Host& node, std::uint64_t group,
                           typename Host::view_type view) -> std::unique_ptr<membership_group> {
    return std::make_unique<membership_detail::group<Host>>(opt, node, group, std::move(view));
}

}  // namespace kythira::redis_node
