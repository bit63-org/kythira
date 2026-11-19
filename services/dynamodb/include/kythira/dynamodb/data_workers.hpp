// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

// DynamoDB's leader-side workers, as the data role runs them
// (.kiro/specs/dynamodb-independent-layers/ task 2, Requirement 6).
//
// One thread makes a pass of each worker a second, on the node that leads
// the catalog when the backend has one: the TTL sweeper (`ttl.hpp`),
// backups and restores (`backup.hpp`), the point-in-time archiver
// (`pitr.hpp`), exports and imports (`export_import.hpp`), bulk puts
// (`bulk_put.hpp`), the vector index worker (`vector_search.hpp`), the
// strong-table worker (`strong_tables.hpp`, task 27), the global-table
// replicator (`global_tables.hpp`), the table key check (KMS task 16) and
// the Kinesis destination publisher (`kinesis_destination.hpp`). A long backup or export delays the
// others until it ends.
//
// They lived in `gateway<Backend>`; they are here so that only a node with
// the data role runs them (Requirement 6.1, 6.4): the gateway builds this
// only when its role set has `data`. The other leader-side tasks, the GSI
// propagator and the catalog jobs, were always the backend's own
// (`raft_backend.hpp`) and so were already on data nodes. What the workers
// do is unchanged (Requirement 6.2), and so are their object-store,
// Kinesis and peer-region credentials, which are therefore needed only on
// data nodes (Requirement 6.3).

#include <kythira/dynamodb/backend.hpp>
#include <kythira/dynamodb/backup.hpp>
#include <kythira/dynamodb/bulk_put.hpp>
#include <kythira/dynamodb/compat_profile.hpp>
#include <kythira/dynamodb/export_import.hpp>
#include <kythira/dynamodb/global_tables.hpp>
#include <kythira/dynamodb/kinesis_destination.hpp>
#include <kythira/dynamodb/pitr.hpp>
#include <kythira/dynamodb/strong_tables.hpp>
#include <kythira/dynamodb/ttl.hpp>
#include <kythira/dynamodb/vector_search.hpp>

#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::dynamodb {

/// What the workers need from the node's configuration.
template<typename Backend> struct data_worker_settings {
    dynamo_compat_profile compat{};
    std::string region;
    /// Where backups, archives and job records live; none refuses them.
    std::shared_ptr<backup_store> store;
    bucket_resolver buckets;
    /// The Kinesis destinations' sink.
    kinesis_sink kinesis{};
    /// Global tables' peer regions.
    peer_set* peers = nullptr;
    /// The vector graphs this node builds; the vector API's registry when
    /// the node also serves the front end.
    vector_registry<Backend>* vectors = nullptr;
    /// The strong host's voters in this node's region (task 27); empty
    /// with no strong host.
    std::vector<std::string> strong_region_voters;
    /// Keys that seal encrypted tables' backups and archives (KMS task
    /// 17); unset seals nothing.
    archive_key_source archive_keys;
    /// Keys for exports with S3SseKmsKeyId (Requirement 12.9).
    typename export_import_worker<Backend>::object_key_source object_keys;
    /// The catalog leader's table key check (KMS task 16), run each pass
    /// before the publisher; unset with no key provider.
    std::function<void()> table_keys;
    /// Whether table names are settled (`gateway<Backend>`), which the
    /// strong-table worker waits for; unset is always.
    std::function<bool()> names_settled;
};

template<dynamo_backend Backend> class data_workers {
public:
    data_workers(Backend& backend, data_worker_settings<Backend> settings,
                 std::function<void(bool, std::string_view)> log = {})
        : _backend(backend),
          _settings(std::move(settings)),
          _log(std::move(log)),
          _own_vectors(_settings.vectors == nullptr
                           ? std::make_unique<vector_registry<Backend>>(backend)
                           : nullptr),
          _sweeper(backend),
          _publisher(backend, {}),
          _backup_worker(backend, nullptr),
          _pitr_worker(backend, nullptr),
          _job_worker(backend, nullptr, nullptr),
          _bulk_worker(backend, nullptr, nullptr),
          _vector_worker(backend,
                         _settings.vectors != nullptr ? _settings.vectors : _own_vectors.get()),
          _replicator(backend, nullptr) {
        _sweeper.set_compat_profile(_settings.compat);
        _backup_worker.set_store(_settings.store);
        _pitr_worker.set_store(_settings.store);
        _job_worker.set_store(_settings.store);
        _job_worker.set_buckets(_settings.buckets);
        _bulk_worker.set_store(_settings.store);
        _bulk_worker.set_buckets(_settings.buckets);
        if (_settings.archive_keys) {
            _backup_worker.set_archive_keys(_settings.archive_keys);
            _pitr_worker.set_archive_keys(_settings.archive_keys);
            _job_worker.set_archive_keys(_settings.archive_keys);
        }
        if (_settings.object_keys) {
            _job_worker.set_object_keys(_settings.object_keys);
        }
        _publisher.set_sink(_settings.kinesis);
        _publisher.set_region(_settings.region);
        _replicator.set_peers(_settings.peers);
        _replicator.set_log([this](std::string_view line) { warn(line); });
        if constexpr (k_routes_strong) {
            if (_backend.has_strong()) {
                _strong_tables = std::make_unique<strong_table_worker<Backend>>(_backend);
                _strong_tables->set_region(_settings.region);
                _strong_tables->set_region_voters(_settings.strong_region_voters);
                _strong_tables->set_log([this](std::string_view line) { warn(line); });
            }
        }
    }

    data_workers(const data_workers&) = delete;
    auto operator=(const data_workers&) -> data_workers& = delete;
    data_workers(data_workers&&) = delete;
    auto operator=(data_workers&&) -> data_workers& = delete;
    ~data_workers() { stop(); }

    void start() {
        {
            const std::lock_guard lock(_mu);
            if (_thread.joinable()) {
                return;
            }
            _stopping = false;
        }
        _thread = std::thread([this] { loop(); });
    }

    void stop() {
        {
            const std::lock_guard lock(_mu);
            _stopping = true;
        }
        _cv.notify_all();
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /// Hints from this node's front end that a job is waiting; without them
    /// the next pass still finds it.
    void backup_created() { _backup_worker.poke(); }
    void pitr_changed() { _pitr_worker.poke(); }
    void job_started() { _job_worker.poke(); }
    void bulk_started() { _bulk_worker.poke(); }

    /// One pass of every worker, as the thread makes each second; public
    /// for tests. Does nothing on a node that does not lead the catalog.
    void pass() {
        try {
            bool here = true;
            if constexpr (requires(Backend& b) {
                              { b.leads_catalog() } -> std::same_as<bool>;
                          }) {
                here = _backend.leads_catalog();
            }
            if (!here) {
                return;
            }
            step("ttl sweeper", [this] { (void)_sweeper.pass(); });
            // An unfinished backup or restore is taken up again on the
            // next pass, here or on a new leader.
            step("backups", [this] { (void)_backup_worker.pass(); });
            // The archive resumes from the stored cursors; a restore is
            // loaded again from the start.
            step("point-in-time recovery", [this] { (void)_pitr_worker.pass(); });
            // An unfinished export or import runs again from the start on
            // the next pass, here or on a new leader.
            step("exports and imports", [this] { (void)_job_worker.pass(); });
            // A bulk put resumes at its first input object not done, here
            // or on a new leader.
            step("bulk operations", [this] { (void)_bulk_worker.pass(); });
            // A new vector index turns ACTIVE once this node has built its
            // graphs; others build theirs on demand.
            step("vector indexes", [this] { (void)_vector_worker.pass(); });
            // Only once the names are settled: before, this region and the
            // strong catalog may name a table differently, and the worker
            // would adopt it again.
            if constexpr (k_routes_strong) {
                if (_strong_tables && (!_settings.names_settled || _settings.names_settled())) {
                    // Replicas adopted, statuses copied, old key spaces
                    // salvaged (task 27).
                    step("strong tables", [this] { (void)_strong_tables->pass(); });
                }
            }
            // Each replica resumes from its stored cursors, here or on a
            // new leader.
            step("global tables", [this] { (void)_replicator.pass(); });
            // Sealed tables' keys checked, clear tables that gained a key
            // re-sealed (KMS task 16).
            if (_settings.table_keys) {
                step("table keys", [this] { _settings.table_keys(); });
            }
            // Unpublished records stay in the change log; the next pass
            // resumes from the stored cursors.
            (void)_publisher.pass();
        } catch (const std::exception& e) {
            warn(std::string("kinesis destinations: ") + e.what());
        }
    }

    [[nodiscard]] auto running() const -> bool { return _thread.joinable(); }

private:
    /// A backend with a strong host (`routed_backend`, task 27).
    static constexpr bool k_routes_strong = requires(Backend& b) {
        { b.has_strong() } -> std::same_as<bool>;
    };

    void warn(std::string_view line) const {
        if (_log) {
            _log(true, line);
        }
    }

    /// Runs one worker's pass; a lost leader or a timeout is logged and
    /// the next pass starts over.
    template<typename F> void step(std::string_view name, F&& f) {
        try {
            std::forward<F>(f)();
        } catch (const std::exception& e) {
            warn(std::string(name) + ": " + e.what());
        }
    }

    void loop() {
        std::unique_lock lock(_mu);
        while (!_stopping) {
            lock.unlock();
            pass();
            lock.lock();
            _cv.wait_for(lock, std::chrono::seconds{1}, [this] { return _stopping; });
        }
    }

    Backend& _backend;
    data_worker_settings<Backend> _settings;
    std::function<void(bool, std::string_view)> _log;
    /// The graphs the vector worker builds when no front end shares its
    /// registry with this node.
    std::unique_ptr<vector_registry<Backend>> _own_vectors;
    ttl_sweeper<Backend> _sweeper;
    kinesis_publisher<Backend> _publisher;
    backup_worker<Backend> _backup_worker;
    pitr_worker<Backend> _pitr_worker;
    export_import_worker<Backend> _job_worker;
    bulk_put_worker<Backend> _bulk_worker;
    vector_index_worker<Backend> _vector_worker;
    global_table_replicator<Backend> _replicator;
    std::unique_ptr<strong_table_worker<Backend>> _strong_tables;
    std::mutex _mu;
    std::condition_variable _cv;
    bool _stopping = false;
    std::thread _thread;
};

}  // namespace kythira::dynamodb
