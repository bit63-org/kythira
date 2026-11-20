// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// S3 as a service module on a node's Raft host
// (.kiro/specs/s3-compatible-storage/ task 16a;
// .kiro/specs/service-colocation/): a metadata node whose index group runs
// on Raft with the other metadata nodes. s3_gateway_node runs it alone on
// its own Raft listener when KYTHIRA_S3_RAFT_PEERS is set (run_raft.cpp),
// and kythira_node runs it beside the other modules on the node's shared
// listener, in S3's group space (s3_module_registrar.cpp).
//
// `Host` is a service_node::node_host: the module's multi_raft host takes
// the node's client and `server_for(space)`.
//
// Data directory (KYTHIRA_S3_DATA_DIR stand-alone, the node's s3/ in
// kythira_node):
//   index/                  the RocksDB database: the index group's state
//   raft/<group>/           the group's Raft log
//   snapshots/              checkpoints and incoming snapshot transfers
//   changes/                the change log's segments
//   blobs/                  the chunk store

#include "s3_node.hpp"

#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_node_config.hpp>
#include <kythira/s3/s3_raft_metadata.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/console_logger.hpp>
#include <raft/future_default.hpp>
#include <raft/host_node_id.hpp>
#include <raft/json_serializer.hpp>
#include <raft/metrics.hpp>
#include <raft/multi_raft_impl.hpp>
#include <raft/multi_raft_transport_handles.hpp>
#include <raft/node_core.hpp>
#include <raft/rocksdb_kv_engine.hpp>
#include <raft/service_module.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::s3_node {

using engine_type = kythira::rocksdb_kv_engine;
using index_sm = s3::s3_index_state_machine<engine_type>;

/// S3's multi_raft types on a node whose transport is `Host`'s.
template<typename Host> struct module_host_types {
    using future_type = kythira::future_default<std::vector<std::byte>>;
    using promise_type = kythira::promise_default<std::vector<std::byte>>;
    using try_type = kythira::try_default<std::vector<std::byte>>;

    using node_id_type = kythira::host_node_id;
    using term_id_type = std::uint64_t;
    using log_index_type = std::uint64_t;
    using group_id_type = std::uint64_t;

    using serialized_data_type = std::vector<std::byte>;
    /// Not used by the host: the wire is the node's transport's.
    using serializer_type = kythira::json_rpc_serializer<std::vector<std::byte>>;

    using network_client_type =
        kythira::transport_client_handle<typename Host::client_type, node_id_type>;
    using network_server_type = typename Host::view_type;

    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id_type, term_id_type, log_index_type>;
    using logger_type = kythira::console_logger;
    using metrics_type = kythira::noop_metrics;
    using membership_manager_type = kythira::default_membership_manager<node_id_type>;
    using state_machine_type = index_sm;

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

/// In kythira_node, the node's settings for what S3's own variables leave
/// unset: its id, data directory (s3/), peers (the index group's members,
/// on the node's one Raft listener) and TLS material.
inline auto composite_env(s3::env_lookup env) -> s3::env_lookup {
    return [env = std::move(env)](std::string_view name) -> std::optional<std::string> {
        if (name == "KYTHIRA_S3_DATA_DIR") {
            auto dir = env("KYTHIRA_NODE_DATA_DIR");
            if (!dir) {
                return std::nullopt;
            }
            return (std::filesystem::path(*dir) / "s3").string();
        }
        if (auto v = env(name); v && !v->empty()) {
            return v;
        }
        if (name == "KYTHIRA_S3_NODE_ID") {
            return env("KYTHIRA_NODE_ID");
        }
        if (name == "KYTHIRA_S3_RAFT_PEERS") {
            if (auto peers = env("KYTHIRA_NODE_PEERS")) {
                return peers;
            }
            // A single node: itself, on the node's listener.
            const auto id = env("KYTHIRA_NODE_ID");
            if (!id) {
                return std::nullopt;
            }
            return *id + "=127.0.0.1:" + env("KYTHIRA_NODE_RAFT_PORT").value_or("7400");
        }
        if (name == "KYTHIRA_S3_INTERNAL_TLS_CERT") {
            return env("KYTHIRA_NODE_TLS_CERT");
        }
        if (name == "KYTHIRA_S3_INTERNAL_TLS_KEY") {
            return env("KYTHIRA_NODE_TLS_KEY");
        }
        if (name == "KYTHIRA_S3_INTERNAL_TLS_CA") {
            return env("KYTHIRA_NODE_TLS_CA");
        }
        return std::nullopt;
    };
}

template<typename Host> class s3_module final : public service_node::service_module<Host> {
public:
    using types = module_host_types<Host>;
    using raft_host = kythira::multi_raft<types, std::string, std::uint64_t>;
    using raft_config = kythira::multi_raft_config<types, std::string, std::uint64_t>;
    using metadata = s3::raft_metadata<raft_host>;

    /// @param standalone s3_gateway_node's module: S3's variables only and
    ///        the data directory itself. Otherwise kythira_node's: the
    ///        node's settings fill in what KYTHIRA_S3_* leaves unset.
    explicit s3_module(bool standalone) : _standalone(standalone) {}

    s3_module(const s3_module&) = delete;
    auto operator=(const s3_module&) -> s3_module& = delete;
    s3_module(s3_module&&) = delete;
    auto operator=(s3_module&&) -> s3_module& = delete;
    ~s3_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "s3"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return service_node::module_numbers::s3;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override { return "KYTHIRA_S3_"; }
    [[nodiscard]] auto data_subdir() const -> std::string override {
        return _standalone ? std::string() : std::string("s3");
    }

    [[nodiscard]] auto configure(const service_node::env_lookup& env)
        -> std::optional<std::string> override {
        auto parsed = s3::node_config_from_env(_standalone ? env : composite_env(env));
        if (auto* e = std::get_if<std::string>(&parsed)) {
            return *e;
        }
        _cfg = std::get<s3::node_config>(std::move(parsed));
        if (!_cfg.raft()) {
            return std::string(
                "the S3 module runs the index group on Raft: it needs the "
                "metadata role and KYTHIRA_S3_RAFT_PEERS");
        }
        try {
            _self = parse_id("KYTHIRA_S3_NODE_ID", _cfg.node_id);
            for (const auto& [id, addr] : _cfg.raft_peers) {
                _members.push_back(parse_id("KYTHIRA_S3_RAFT_PEERS", id));
            }
            for (const auto& [id, url] : _cfg.metadata_endpoints) {
                _member_urls[parse_id("KYTHIRA_S3_METADATA_ENDPOINTS", id)] = url;
            }
        } catch (const std::invalid_argument& e) {
            return std::string(e.what());
        }
        return std::nullopt;
    }

    void register_groups(Host& host, const service_node::group_space& space) override {
        for (const auto* sub : {"index", "raft", "snapshots", "changes"}) {
            std::filesystem::create_directories(_cfg.data_dir / sub);
        }
        _changes = std::make_unique<kythira::record_segment_store>(
            kythira::record_segment_store_options{._data_dir = _cfg.data_dir / "changes"});
        auto client = std::make_shared<kythira::mtls::client>(internal_client_config(_cfg));
        auto urls = _member_urls;
        auto forward = s3::make_group_forwarder<kythira::host_node_id>(
            [client, urls](
                const kythira::host_node_id& to, const std::string& target,
                const std::string& body) -> std::optional<std::pair<unsigned, std::string>> {
                const auto it = urls.find(to);
                if (it == urls.end()) {
                    return std::nullopt;
                }
                return client->request("POST", it->second, target, body, "application/octet-stream",
                                       "kythira-s3");
            },
            [](std::string_view text) -> std::optional<kythira::host_node_id> {
                auto id = kythira::parse_host_peer_node_id(text);
                return id ? std::optional<kythira::host_node_id>(std::move(id).value())
                          : std::nullopt;
            });
        _raft = std::make_unique<raft_host>(make_raft_config(host, space, forward));
        typename metadata::options o;
        o.members = _members;
        o.group = space.first() + 1;
        o.forward = std::move(forward);
        o.change_log = _changes.get();
        _meta = std::make_unique<metadata>(*_raft, std::move(o));
        _meta->bootstrap();
        _group_server = std::make_shared<s3::group_server<raft_host>>(
            *_meta, [](const kythira::host_node_id& id) { return kythira::host_node_id_text(id); });
    }

    void start(service_node::module_registry& /*registry*/) override {
        _raft->start();
        _driving = true;
        _driver = std::thread([this] {
            while (_driving.load(std::memory_order_acquire)) {
                try {
                    (void)_raft->tick();
                } catch (const std::exception& e) {
                    log_line(true, std::string("raft tick failed: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        });
        _node = std::make_unique<node>(_cfg);
        auto groups = _group_server;
        _node->start_with(
            *_meta, [meta = _meta.get()] { return meta->leads(); },
            [groups](std::string_view method, std::string_view target, std::string_view body) {
                return groups->handle(method, target, body);
            });
        _started = true;
    }

    /// No new request reaches the group once it is being torn down.
    void drain() override {
        if (_node) {
            _node->stop();
        }
    }

    void stop() override {
        drain();
        _driving.store(false, std::memory_order_release);
        if (_driver.joinable()) {
            _driver.join();
        }
        if (_raft) {
            _raft->stop();
        }
        _node.reset();
        _group_server.reset();
        _meta.reset();
        _raft.reset();
        _started = false;
    }

    [[nodiscard]] auto health() const -> service_node::module_health override {
        if (!_started) {
            return {false, "not started"};
        }
        if (!_meta->leader()) {
            return {false, "the index group has no leader this node knows of"};
        }
        return {true, {}};
    }

    [[nodiscard]] auto metrics() const -> std::vector<service_node::module_metric> override {
        if (!_meta) {
            return {};
        }
        const auto s = _meta->stats();
        return {{"index_leader", _meta->leads() ? 1.0 : 0.0, {}},
                {"proposals_forwarded", double(s.proposals_forwarded), {}},
                {"proposals_served", double(s.proposals_served), {}},
                {"metadata_unavailable", double(s.unavailable), {}},
                {"raft_term_sum", service_node::raft_term_sum(*_raft), {}}};
    }

private:
    static auto parse_id(std::string_view setting, const std::string& text)
        -> kythira::host_node_id {
        auto id = kythira::parse_host_peer_node_id(text);
        if (!id) {
            throw std::invalid_argument(std::string(setting) + ": " + id.error());
        }
        return std::move(id).value();
    }

    auto make_raft_config(Host& host, const service_node::group_space& space,
                          const s3::group_forwarder<kythira::host_node_id>& forward)
        -> raft_config {
        const auto raft_dir = _cfg.data_dir / "raft";
        raft_config cfg{
            .node_id = host.node_id(),
            .network_client = typename types::network_client_type{host.client()},
            .network_server = host.server_for(space),
            .store_factory =
                [raft_dir](const std::uint64_t& group) {
                    return
                        typename types::persistence_engine_type{raft_dir / std::to_string(group)};
                },
        };
        cfg.state_engine = std::make_shared<engine_type>(_cfg.data_dir / "index");
        cfg.state_machine_factory =
            [changes = _changes.get(),
             fetch = s3::make_change_log_fetcher<kythira::host_node_id>(
                 _changes.get(), _members, _self, forward)](const std::uint64_t&) {
                return metadata::template make_state_machine<engine_type>(s3::index_options{},
                                                                          changes, fetch);
            };
        cfg.automatic_split_merge_enabled = false;  // one group until task 18
        cfg.hibernation = kythira::hibernation_mode::off;
        cfg.logger = kythira::console_logger{kythira::log_level::warning};
        cfg.logger_factory = [](const std::uint64_t&) {
            return kythira::console_logger{kythira::log_level::warning};
        };
        cfg.config._snapshot_staging_directory = _cfg.data_dir / "snapshots";
        return cfg;
    }

    bool _standalone;
    s3::node_config _cfg;
    kythira::host_node_id _self{};
    std::vector<kythira::host_node_id> _members;
    std::map<kythira::host_node_id, std::string> _member_urls;
    std::unique_ptr<kythira::record_segment_store> _changes;
    std::unique_ptr<raft_host> _raft;
    std::unique_ptr<metadata> _meta;
    std::shared_ptr<s3::group_server<raft_host>> _group_server;
    std::unique_ptr<node> _node;
    std::atomic<bool> _driving{false};
    std::thread _driver;
    std::atomic<bool> _started{false};
};

}  // namespace kythira::s3_node
