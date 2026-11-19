// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_metadata.hpp
/// @brief How the front end reaches the metadata layer
///        (.kiro/specs/s3-compatible-storage/ task 7; design "Strong
///        consistency from the metadata layer").
///
/// `metadata_access` is what the handlers need: propose an index entry
/// and get what applying it produced, and the reads, each answering at or
/// after every write the caller has seen acknowledged (Requirement 7.2).
/// The handlers are templates over it, so the deployments of task 16
/// (local, remote, hybrid, through the multi-Raft host) plug in without
/// touching them.
///
/// `local_metadata` is the in-process form: one state machine over a
/// memory engine, entries applied in order under a mutex with the log
/// index counted here. It is what a single node without Raft amounts to,
/// and what the handler tests run against.

#include <kythira/s3/s3_index_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

template<typename M>
concept metadata_access =
    requires(M& m, const M& cm, const index_command& c, std::string_view s, std::uint64_t id,
             const std::optional<std::string>& vid, std::size_t n) {
        { m.propose(c) } -> std::same_as<index_result>;
        { cm.bucket(s) } -> std::same_as<std::optional<bucket_descriptor>>;
        { cm.list_buckets(s) } -> std::same_as<std::vector<bucket_descriptor>>;
        { cm.version(id, s, vid) } -> std::same_as<std::optional<object_version>>;
        { cm.list_objects(id, s, s, s, n) } -> std::same_as<object_listing>;
        { cm.list_versions(id, s, s, s, s, n) } -> std::same_as<version_listing>;
        { cm.upload(id, s, s) } -> std::same_as<std::optional<upload_record>>;
        {
            cm.list_uploads(id, s, s, s, n)
        } -> std::same_as<std::pair<std::vector<upload_record>, bool>>;
    };

/// One state machine in process, entries applied in order.
class local_metadata {
public:
    explicit local_metadata(index_options options = {}) : _sm(options) {
        _sm.open(_engine, key_range{"", std::nullopt});
    }

    auto propose(const index_command& c) -> index_result {
        const std::scoped_lock lock(_mutex);
        return codec::decode_result(_sm.apply(codec::encode(c), ++_index));
    }

    [[nodiscard]] auto bucket(std::string_view name) const -> std::optional<bucket_descriptor> {
        const std::scoped_lock lock(_mutex);
        return _sm.bucket(name);
    }
    [[nodiscard]] auto list_buckets(std::string_view owner) const
        -> std::vector<bucket_descriptor> {
        const std::scoped_lock lock(_mutex);
        return _sm.list_buckets(owner);
    }
    [[nodiscard]] auto version(std::uint64_t bucket_id, std::string_view key,
                               const std::optional<std::string>& version_id) const
        -> std::optional<object_version> {
        const std::scoped_lock lock(_mutex);
        return _sm.version(bucket_id, key, version_id);
    }
    [[nodiscard]] auto list_objects(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view delimiter, std::string_view marker,
                                    std::size_t max_keys) const -> object_listing {
        const std::scoped_lock lock(_mutex);
        return _sm.list_objects(bucket_id, prefix, delimiter, marker, max_keys);
    }
    [[nodiscard]] auto list_versions(std::uint64_t bucket_id, std::string_view prefix,
                                     std::string_view delimiter, std::string_view key_marker,
                                     std::string_view version_id_marker, std::size_t max_keys) const
        -> version_listing {
        const std::scoped_lock lock(_mutex);
        return _sm.list_versions(bucket_id, prefix, delimiter, key_marker, version_id_marker,
                                 max_keys);
    }
    [[nodiscard]] auto upload(std::uint64_t bucket_id, std::string_view key,
                              std::string_view upload_id) const -> std::optional<upload_record> {
        const std::scoped_lock lock(_mutex);
        return _sm.upload(bucket_id, key, upload_id);
    }
    [[nodiscard]] auto list_uploads(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view key_marker, std::string_view upload_id_marker,
                                    std::size_t max) const
        -> std::pair<std::vector<upload_record>, bool> {
        const std::scoped_lock lock(_mutex);
        return _sm.list_uploads(bucket_id, prefix, key_marker, upload_id_marker, max);
    }

    [[nodiscard]] auto refcount(const chunk_sha& sha) const -> std::optional<refcount_record> {
        const std::scoped_lock lock(_mutex);
        return _sm.refcount(sha);
    }
    [[nodiscard]] auto pending_deletions(std::size_t max) const -> std::vector<chunk_sha> {
        const std::scoped_lock lock(_mutex);
        return _sm.pending_deletions(max);
    }

    [[nodiscard]] auto pending_restores(std::size_t max) const -> std::vector<pending_restore> {
        const std::scoped_lock lock(_mutex);
        return _sm.pending_restores(max);
    }
    [[nodiscard]] auto tier_garbage_list(std::size_t max) const -> std::vector<tier_garbage_entry> {
        const std::scoped_lock lock(_mutex);
        return _sm.tier_garbage_list(max);
    }

    /// The state machine, for tests that look underneath.
    [[nodiscard]] auto state_machine() const -> const s3_index_state_machine<>& { return _sm; }

private:
    mutable std::mutex _mutex;
    memory_kv_engine _engine;
    s3_index_state_machine<> _sm;
    std::uint64_t _index = 0;
};

static_assert(metadata_access<local_metadata>);

}  // namespace kythira::s3
