// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// DynamoDB as a service module (.kiro/specs/service-colocation/ task 6):
// what dynamodb_gateway_node's main() did after reading its settings,
// behind service_module<Host>, so that dynamodb_gateway_node (one module,
// its own JSON Beast transport, ids and data directory exactly as before)
// and kythira_node (beside other modules, on the node's shared listener, in
// DynamoDB's group space) run the same code.
//
// Without peers the module is one node with no Raft (local_backend on the
// memory engine), as the daemon always was. With them it is a cluster_node
// (run_cluster.hpp): the cluster's host on the node's transport, its
// bootstrap groups and each voter's split range placed in the module's
// space, and the strong host (task 27) on its own listener.
//
// Kinesis streaming destinations (Requirement 7.4) publish through a
// co-located Kinesis module's `kinesis.put_records` when there is one and
// KYTHIRA_DYNAMODB_KINESIS_ENDPOINT is unset. The calls are signed with the
// same credentials as over the network, so Kinesis authorizes them as it
// would a network call. Otherwise they go to the configured endpoint, as
// before.
//
// Data directory (KYTHIRA_DYNAMODB_DATA_DIR stand-alone, the node's data
// directory's dynamodb/ in kythira_node), on the RocksDB engine:
//   engine/, raft/<group>/   the cluster host's database and Raft logs
//   strong/                  the same for the strong host

#include "backup_s3.hpp"
#include "composite_env.hpp"
#include "run_cluster.hpp"
#ifdef KYTHIRA_DYNAMODB_GATEWAY_IAM
#include "iam_auth.hpp"
#endif

#include <kythira/dynamodb/backend.hpp>
#include <kythira/dynamodb/dynamodb_actions.hpp>
#include <kythira/dynamodb/gateway.hpp>
#include <kythira/dynamodb/kinesis_destination.hpp>
#include <kythira/dynamodb/table_key_providers.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/module_interfaces.hpp>
#include <raft/module_registry.hpp>
#include <raft/service_module.hpp>
#if defined(KYTHIRA_DYNAMODB_ROCKSDB)
#include <raft/rocksdb_kv_engine.hpp>
#endif

#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace dynamodb_gateway {

#if defined(KYTHIRA_DYNAMODB_ROCKSDB)
/// One RocksDB database per host, the Raft logs beside it.
struct rocksdb_storage {
    using engine_type = kythira::rocksdb_kv_engine;
    using persistence_engine_type =
        kythira::binary_file_persistence_engine<node_id, std::uint64_t, std::uint64_t>;
    static constexpr std::string_view k_name = "rocksdb";
};
#endif

/// What the module runs: a cluster node or the one node with no Raft.
class serving {
public:
    serving() = default;
    serving(const serving&) = delete;
    auto operator=(const serving&) -> serving& = delete;
    serving(serving&&) = delete;
    auto operator=(serving&&) -> serving& = delete;
    virtual ~serving() = default;

    /// `iam`, when set, replaces the configured IAM hooks (a co-located
    /// IAM module's evaluator).
    virtual void start(ddb::kinesis_sink kinesis, std::optional<ddb::iam_hooks> iam) = 0;
    virtual void drain() = 0;
    virtual void stop() = 0;
    [[nodiscard]] virtual auto port() const -> std::uint16_t = 0;
    /// `service_node::raft_term_sum` over the groups held here; 0 with
    /// no Raft (local mode).
    [[nodiscard]] virtual auto raft_term_sum() const -> double { return 0.0; }
};

template<typename Storage, typename Host> class cluster_serving final : public serving {
public:
    template<typename... Args>
    explicit cluster_serving(Args&&... args) : _node(std::forward<Args>(args)...) {}
    void start(ddb::kinesis_sink kinesis, std::optional<ddb::iam_hooks> iam) override {
        _node.start(std::move(kinesis), std::move(iam));
    }
    void drain() override { _node.drain(); }
    void stop() override { _node.stop(); }
    [[nodiscard]] auto port() const -> std::uint16_t override { return _node.port(); }
    [[nodiscard]] auto raft_term_sum() const -> double override { return _node.raft_term_sum(); }

private:
    cluster_node<Storage, Host> _node;
};

/// One node, no Raft: local_backend on the memory engine, nothing kept
/// across a restart.
class local_serving final : public serving {
public:
    local_serving(ddb::gateway_config cfg, std::function<void(bool, std::string_view)> log)
        : _cfg(std::move(cfg)), _log(std::move(log)) {
        _change_log = open_change_log(_cfg, _scratch);
        _backend = std::make_unique<ddb::local_backend<>>(
            _engine, ddb::local_backend<>::system_clock_ms(), _change_log.get());
        // One node on the memory engine keeps backups in memory too, unless
        // told where else (backup.hpp), and its export and import buckets
        // (export_import.hpp).
        if (!_cfg.backups && _cfg.backup_dir.empty()) {
            _cfg.backups = std::make_shared<ddb::memory_backup_store>();
        }
        if (!_cfg.buckets && _cfg.bucket_dir.empty() && _cfg.backup_dir.empty()) {
            _cfg.buckets = _buckets.resolver();
        }
    }
    ~local_serving() override { stop(); }
    local_serving(const local_serving&) = delete;
    auto operator=(const local_serving&) -> local_serving& = delete;
    local_serving(local_serving&&) = delete;
    auto operator=(local_serving&&) -> local_serving& = delete;

    void start(ddb::kinesis_sink kinesis, std::optional<ddb::iam_hooks> iam) override {
        if (kinesis.configured()) {
            _cfg.kinesis = std::move(kinesis);
        }
        if (iam) {
            _cfg.iam = std::move(iam);
        }
        _backend->set_sealer(ddb::item_sealer(_cfg.key_ring));
        _gateway = std::make_unique<ddb::gateway<ddb::local_backend<>>>(_cfg, *_backend, _log);
        _gateway->start();
        _log(false, "serving " + std::string(_cfg.http.insecure_plaintext ? "http" : "https") +
                        " on " + _cfg.http.bind_address + ":" + std::to_string(_gateway->port()) +
                        ", engine " + _cfg.engine + " (nothing is kept across a restart)");
    }
    void drain() override {
        if (_gateway) {
            _gateway->stop();
        }
    }
    void stop() override { drain(); }
    [[nodiscard]] auto port() const -> std::uint16_t override {
        return _gateway ? _gateway->port() : 0;
    }

private:
    ddb::gateway_config _cfg;
    std::function<void(bool, std::string_view)> _log;
    kythira::memory_kv_engine _engine;
    std::optional<scratch_dir> _scratch;
    std::unique_ptr<kythira::record_segment_store> _change_log;
    std::unique_ptr<ddb::local_backend<>> _backend;
    ddb::memory_buckets _buckets;
    std::unique_ptr<ddb::gateway<ddb::local_backend<>>> _gateway;
};

/// Kinesis streaming destinations through a co-located Kinesis module: the
/// HTTP sink's signed calls, handed to `kinesis.put_records` instead of a
/// socket. The credentials are the network path's (AWS_ACCESS_KEY_ID,
/// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
[[nodiscard]] inline auto in_process_kinesis_sink(
    std::shared_ptr<kythira::service_node::aws_json_endpoint> kinesis) -> ddb::kinesis_sink {
    const auto env = [](const char* name) -> std::string {
        const char* v = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read at start
        return v == nullptr ? std::string{} : std::string(v);
    };
    ddb::kinesis_http_sink_config cfg;
    cfg.credentials =
        [creds = ddb::kinesis_credentials{env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"),
                                          env("AWS_SESSION_TOKEN")}] { return creds; };
    return ddb::kinesis_http_sink(
               std::move(cfg),
               [kinesis = std::move(kinesis)](
                   const std::string& /*host_port*/,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   const std::string& body) -> std::optional<ddb::kinesis_http_answer> {
                   const auto r = kinesis->call(kythira::service_node::caller{.module = "dynamodb"},
                                                {.headers = headers, .body = body});
                   return ddb::kinesis_http_answer{r.status, r.body};
               })
        .as_sink();
}

template<typename Host>
class dynamodb_module final : public kythira::service_node::service_module<Host> {
public:
    /// @param standalone dynamodb_gateway_node's module: its own variables
    ///        for the node-wide settings and the data directory as given.
    ///        Otherwise kythira_node's: the node's settings fill in what the
    ///        KYTHIRA_DYNAMODB_* variables leave unset (composite_env), and
    ///        the data directory is the node's dynamodb/.
    explicit dynamodb_module(bool standalone) : _standalone(standalone) {}

    dynamodb_module(const dynamodb_module&) = delete;
    auto operator=(const dynamodb_module&) -> dynamodb_module& = delete;
    dynamodb_module(dynamodb_module&&) = delete;
    auto operator=(dynamodb_module&&) -> dynamodb_module& = delete;
    ~dynamodb_module() override { stop(); }

    [[nodiscard]] auto name() const -> std::string_view override { return "dynamodb"; }
    [[nodiscard]] auto number() const -> std::uint8_t override {
        return kythira::service_node::module_numbers::dynamodb;
    }
    [[nodiscard]] auto env_prefix() const -> std::string_view override {
        return "KYTHIRA_DYNAMODB_";
    }
    [[nodiscard]] auto data_subdir() const -> std::string override {
        return _standalone ? std::string() : std::string("dynamodb");
    }
    /// A co-located Kinesis publishes `kinesis.put_records` for the
    /// streaming destinations, without one they use the network; a
    /// co-located IAM's evaluator answers before this module serves.
    [[nodiscard]] auto starts_after() const -> std::vector<std::string> override {
        return {"iam", "kinesis", "kms"};
    }

    /// The settings, the S3 stores and IAM's replica: everything that can
    /// be wrong, before a port is bound.
    [[nodiscard]] auto configure(const kythira::service_node::env_lookup& env)
        -> std::optional<std::string> override {
        auto parsed = ddb::gateway_config_from_env(_standalone ? env : composite_env(env));
        if (auto* e = std::get_if<std::string>(&parsed)) {
            return *e;
        }
        _cfg = std::get<ddb::gateway_config>(std::move(parsed));
        if (auto e = configure_table_keys(env)) {
            return e;
        }
        try {
            if (!_cfg.backups) {
                _cfg.backups = make_s3_backup_store(_cfg);
            }
            if (!_cfg.buckets && _cfg.bucket_dir.empty() && !_cfg.backup_s3_bucket.empty()) {
                _cfg.buckets = make_s3_bucket_resolver(_cfg);
            }
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        // IAM (task 28): the co-located IAM module's evaluator when
        // kythira_node runs one, taken at start; otherwise the embedded
        // replica, which outlives the gateway that uses it.
        _iam_in_process = !_standalone && _cfg.auth != ddb::auth_mode::static_keys &&
                          kythira::service_node::co_located(env, "iam");
        if (_cfg.auth != ddb::auth_mode::static_keys && !_iam_in_process) {
#ifdef KYTHIRA_DYNAMODB_GATEWAY_IAM
            try {
                _iam = start_iam_auth_from_env();
                _cfg.iam = _iam->hooks();
            } catch (const std::exception& e) {
                return std::string(e.what());
            }
#else
            return std::string(
                "KYTHIRA_DYNAMODB_AUTH=iam or both needs a build with "
                "CONFIG_DYNAMODB_GATEWAY_IAM");
#endif
        }
#if !defined(KYTHIRA_DYNAMODB_ROCKSDB)
        if (_cfg.engine == "rocksdb") {
            return std::string(
                "KYTHIRA_DYNAMODB_ENGINE=rocksdb: this build has no RocksDB "
                "(CONFIG_ENGINE_ROCKSDB)");
        }
#endif
        return std::nullopt;
    }

    void register_groups(Host& host, const kythira::service_node::group_space& space) override {
        const auto log = [](bool warning, std::string_view m) {
            std::cerr << (warning ? "[warn] " : "[info] ") << "dynamodb_gateway_node: " << m
                      << "\n";
        };
        if (!_cfg.cluster.enabled()) {
            _serving = std::make_unique<local_serving>(_cfg, log);
            return;
        }
        if (_cfg.engine == "memory") {
            using storage = memory_storage;
            _serving = std::make_unique<cluster_serving<storage, Host>>(
                _cfg, log, host, space,
                host_storage<storage>{std::make_shared<storage::engine_type>(), [](std::uint64_t) {
                                          return storage::persistence_engine_type{};
                                      }});
            return;
        }
#if defined(KYTHIRA_DYNAMODB_ROCKSDB)
        // Layout: engine/ (the database) and raft/<group> (the Raft logs);
        // the strong host's (task 27) the same under strong/.
        const std::filesystem::path dir(_cfg.data_dir);
        const auto storage_in = [](const std::filesystem::path& d) {
            std::filesystem::create_directories(d / "engine");
            std::filesystem::create_directories(d / "raft");
            return host_storage<rocksdb_storage>{
                std::make_shared<kythira::rocksdb_kv_engine>(d / "engine"),
                [d](std::uint64_t group) {
                    return rocksdb_storage::persistence_engine_type{d / "raft" /
                                                                    std::to_string(group)};
                }};
        };
        std::optional<host_storage<rocksdb_storage>> strong;
        if (_cfg.strong.enabled()) {
            strong = storage_in(dir / "strong");
        }
        _serving = std::make_unique<cluster_serving<rocksdb_storage, Host>>(
            _cfg, log, host, space, storage_in(dir), std::move(strong));
#endif
    }

    void start(kythira::service_node::module_registry& registry) override {
        if (_kms_in_process) {
            // The KMS starts first (starts_after) and publishes its client;
            // the providers read the slot from the first table on.
            *_kms_slot = registry.lookup<kythira::service_node::kms_endpoint>(
                std::string(kythira::service_node::interface_names::kms_client));
            if (!*_kms_slot) {
                throw std::invalid_argument(
                    "KYTHIRA_DYNAMODB_KMS=kythira: the KMS module publishes no client");
            }
        }
        ddb::kinesis_sink kinesis;
        const auto co_located = registry.lookup<kythira::service_node::aws_json_endpoint>(
            kythira::service_node::interface_names::kinesis_put_records);
        // NOLINTNEXTLINE(concurrency-mt-unsafe): read at start
        const char* endpoint = std::getenv("KYTHIRA_DYNAMODB_KINESIS_ENDPOINT");
        if (co_located && !_cfg.kinesis.configured() &&
            (endpoint == nullptr || *endpoint == '\0')) {
            kinesis = in_process_kinesis_sink(co_located);
            std::cerr << "[info] dynamodb_gateway_node: Kinesis streaming destinations publish "
                         "to the co-located Kinesis module\n";
        }
        std::optional<ddb::iam_hooks> iam;
        if (_iam_in_process) {
            auto evaluator = registry.lookup<kythira::service_node::iam_evaluator>(
                kythira::service_node::interface_names::iam_evaluator);
            if (!evaluator) {
                throw std::invalid_argument(
                    "KYTHIRA_DYNAMODB_AUTH=iam or both: the IAM module publishes no evaluator");
            }
            evaluator->add_actions(ddb::dynamodb_actions());
            iam = evaluator->hooks();
            _iam_evaluator = std::move(evaluator);
        }
        _serving->start(std::move(kinesis), std::move(iam));
        _started = true;
    }

    void drain() override {
        if (_serving) {
            _serving->drain();
        }
    }

    void stop() override {
        if (_serving) {
            _serving->stop();
            _serving.reset();
        }
        _started = false;
    }

    [[nodiscard]] auto health() const -> kythira::service_node::module_health override {
        if (!_started) {
            return {false, "not started", _cfg.roles.to_string()};
        }
        return {true, {}, _cfg.roles.to_string()};
    }

    [[nodiscard]] auto metrics() const
        -> std::vector<kythira::service_node::module_metric> override {
        if (!_serving) {
            return {};
        }
        std::vector<kythira::service_node::module_metric> out{
            {"raft_term_sum", _serving->raft_term_sum(), {}}};
        // kythira_dynamodb_role{role="..."}: 1 for each layer this node
        // runs, 0 for the others, so a query finds every node of a layer.
        for (const auto r : kythira::layers::every_role) {
            out.push_back({"role",
                           _cfg.roles.has(r) ? 1.0 : 0.0,
                           {{"role", std::string(kythira::layers::role_name(r))}}});
        }
        return out;
    }

    /// The API's port once started (tests pass port 0).
    [[nodiscard]] auto api_port() const -> std::uint16_t { return _serving ? _serving->port() : 0; }

private:
    bool _standalone;
    ddb::gateway_config _cfg;
    /// KYTHIRA_DYNAMODB_AUTH=iam|both in kythira_node beside the IAM module.
    bool _iam_in_process{false};
    std::shared_ptr<kythira::service_node::iam_evaluator> _iam_evaluator;
    /// The co-located KMS's client (KMS task 16), filled at start.
    ddb::kms_endpoint_slot _kms_slot =
        std::make_shared<std::shared_ptr<kythira::service_node::kms_endpoint>>();
    bool _kms_in_process{false};

    /// The table keys' provider (KMS task 16): `KYTHIRA_DYNAMODB_KMS`, or
    /// kythira where the KMS module runs in this node, else none.
    auto configure_table_keys(const kythira::service_node::env_lookup& env)
        -> std::optional<std::string> {
        const auto& s = _cfg.kms;
        const bool kms_here = !_standalone && kythira::service_node::co_located(env, "kms");
        const std::string provider = !s.kms.empty() ? s.kms : (kms_here ? "kythira" : "off");
        const bool uses_kythira = provider == "kythira" || s.kms_previous == "kythira";
        if (uses_kythira && s.endpoint.empty() && !kms_here) {
            return std::string(
                "KYTHIRA_DYNAMODB_KMS=kythira needs the KMS module in this kythira_node or "
                "KYTHIRA_DYNAMODB_KMS_ENDPOINT");
        }
        _kms_in_process = uses_kythira && s.endpoint.empty();
        // Every node holds the keys its replicas seal with, even with no
        // provider: a table sealed before the provider was turned off then
        // reports its key as unavailable rather than reading as corrupt.
        _cfg.key_ring = std::make_shared<ddb::table_key_ring>();
        try {
            _cfg.encryption = ddb::make_table_key_config(s, provider, _cfg.front.region, _kms_slot);
        } catch (const std::exception& e) {
            return std::string(e.what());
        }
        if (provider != "off") {
            std::cerr << "[info] dynamodb_gateway_node: tables are encrypted with the " << provider
                      << " key provider ("
                      << (_cfg.encryption.at_rest == ddb::at_rest_mode::owned
                              ? "owned key by default"
                              : "only when a table asks")
                      << ")\n";
        }
        return std::nullopt;
    }
#ifdef KYTHIRA_DYNAMODB_GATEWAY_IAM
    std::unique_ptr<iam_auth> _iam;
#endif
    std::unique_ptr<serving> _serving;
    std::atomic<bool> _started{false};
};

}  // namespace dynamodb_gateway
