// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_index_state_machine.hpp
/// @brief The object index: S3's metadata as a persistent Raft state
///        machine (.kiro/specs/s3-compatible-storage/ task 4; Requirements
///        6.3, 7.2, 7.3, 8.1, 10.2 and 10.3).
///
/// Object bytes never go through Raft: the front end writes an object's
/// chunks to their placement first and proposes only a manifest of their
/// hashes (design "Object bytes never go through Raft"). This state machine
/// keeps what the proposals say, in the node's `kv_engine` under the
/// group's key range (`s3_index_records.hpp` has the layout):
///
/// - **Buckets.** Create (ids from a counter, never reused, Requirement
///   6.3), delete (empty only), versioning state, object lock, and every
///   other bucket sub-resource stored as sent.
/// - **Versions.** A write adds a version; what happens to the others
///   follows the bucket's versioning state exactly as on S3 (Requirement
///   8.1): unversioned and suspended buckets replace the `null` version,
///   enabled buckets keep every version; deletes add delete markers or
///   remove one version. A key's versions sort newest first.
/// - **Uploads.** Create, upload part (a part number written again
///   replaces the old part), complete (part order, ETags and the minimum
///   part size checked; the multipart ETag computed) and abort.
/// - **Conditions in apply** (Requirement 7.3). `If-None-Match: *` and
///   `If-Match` on PUT, complete and copy, and the copy-source conditions,
///   are evaluated against the committed state when the entry applies, so
///   two racing conditional writes cannot both succeed.
/// - **Reference counts with a grace period** (Requirement 10.3). Every
///   manifest that names a chunk (an object version or an uploaded part)
///   counts once per occurrence. A count that reaches zero records when;
///   `collect_chunks` hands back only chunks that have been unreferenced
///   for longer than the grace period, which must exceed the longest
///   in-flight write, so a PUT racing a delete of the same bytes keeps
///   them.
///
/// Entries carry everything they need: the proposer's clock (`now_ms`), and
/// for object writes the bucket's id, versioning state and object lock
/// flag, read by the front end from the catalog. So applying needs no
/// catalog lookup and replicas cannot disagree about a setting they read at
/// different times (DynamoDB's item state machine does the same with key
/// schemas). Version and upload ids come from the entry's log index, raised
/// past the key's newest stamp, so they are deterministic and keep a key's
/// versions ordered even after its range moves between groups.
///
/// One state machine type serves the catalog group and object groups. An
/// entry that would write outside the group's range fails with
/// `InternalError` and changes nothing. Until placement spreads the key
/// spaces over groups (task 18), the deployment keeps the catalog, objects,
/// uploads and reference counts in one group; `delete_bucket` checks
/// emptiness only in its own range.
///
/// A failed condition or a missing bucket is a normal result: the entry
/// still advances the applied index and changes nothing else.

#include <kythira/s3/s3_index_records.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// Commands and results
// ---------------------------------------------------------------------------

/// `If-Match` and `If-None-Match: *` on a write (PUT, complete, copy).
struct write_conditions {
    /// The current version's ETag must be this (`*` for "any").
    std::optional<std::string> if_match;
    /// No current version may exist.
    bool if_none_match_star = false;

    friend auto operator==(const write_conditions&, const write_conditions&) -> bool = default;
};

/// `x-amz-copy-source-if-*`.
struct source_conditions {
    std::optional<std::string> if_match;
    std::optional<std::string> if_none_match;
    std::optional<std::uint64_t> if_modified_since_ms;
    std::optional<std::uint64_t> if_unmodified_since_ms;

    friend auto operator==(const source_conditions&, const source_conditions&) -> bool = default;
};

/// What an object write needs to know about its bucket, read by the front
/// end from the catalog.
struct bucket_ref {
    std::uint64_t id = 0;
    versioning_state versioning = versioning_state::unversioned;
    bool object_lock = false;

    friend auto operator==(const bucket_ref&, const bucket_ref&) -> bool = default;
};

/// A part named in CompleteMultipartUpload.
struct completed_part {
    std::uint32_t number = 0;
    std::string etag;

    friend auto operator==(const completed_part&, const completed_part&) -> bool = default;
};

/// One Raft entry for the index. Fields not used by `kind` stay default.
struct index_command {
    enum class kind : std::uint8_t {
        create_bucket = 1,
        delete_bucket = 2,
        /// Set (`document`) or delete (no `document`) one bucket
        /// sub-resource. `versioning` takes `Enabled` or `Suspended`;
        /// `object-lock` turns object lock on for a versioned bucket.
        put_bucket_config = 3,
        put_object = 4,
        /// Without `version_id`: by the bucket's versioning state. With
        /// one: removes exactly that version or delete marker.
        delete_object = 5,
        /// From `source_*` in this group: reuses the source's manifest.
        copy_object = 6,
        create_upload = 7,
        upload_part = 8,
        complete_upload = 9,
        abort_upload = 10,
        /// Hand back and forget up to `max` chunks unreferenced for at
        /// least `grace_ms`.
        collect_chunks = 11,
        /// Set (`document`) or erase (no `document`) one stored header,
        /// `config_name`, of the version `version_id` names (the current
        /// one without it): object tagging and object ACLs. A delete
        /// marker has none (`405 MethodNotAllowed`), and nothing else about
        /// the version changes.
        set_object_metadata = 12,
    };

    kind op = kind::put_object;
    std::uint64_t now_ms = 0;
    /// The requester's account: a new bucket's or version's owner.
    std::string owner;
    std::string bucket;  ///< name (catalog commands)
    bucket_ref target;   ///< object commands
    std::string key;
    std::string region;        ///< create_bucket
    bool object_lock = false;  ///< create_bucket
    /// create_bucket: sub-resources the bucket starts with (its ACL,
    /// ownership controls, public access block), so a new bucket is never
    /// seen without them.
    std::map<std::string, std::string> config;
    std::string config_name;  ///< put_bucket_config
    std::optional<std::string> document;
    std::optional<std::string> version_id;  ///< delete_object, copy source
    object_content content;                 ///< put, copy (replacement metadata), create_upload
    write_conditions conditions;
    bucket_ref source;  ///< copy_object
    std::string source_key;
    source_conditions source_if;
    bool replace_metadata = false;  ///< copy_object: COPY or REPLACE
    /// copy_object: stored headers taken from `content.system_metadata`
    /// whatever `replace_metadata` says (erased when absent there): the
    /// new object's ACL, which is never copied, and its tags under
    /// `x-amz-tagging-directive: REPLACE`.
    std::vector<std::string> override_metadata;
    std::string upload_id;
    part_record part;                   ///< upload_part
    std::vector<completed_part> parts;  ///< complete_upload
    std::uint64_t grace_ms = 0;         ///< collect_chunks
    std::uint32_t max = 0;              ///< collect_chunks

    friend auto operator==(const index_command&, const index_command&) -> bool = default;
};

/// What applying an entry produced.
struct index_result {
    /// Empty on success; else S3's error code and HTTP status.
    std::string error;
    std::string message;
    unsigned status = 200;
    std::string version_id;
    bool delete_marker = false;
    std::string etag;
    std::string upload_id;
    std::uint64_t bucket_id = 0;
    std::uint64_t last_modified_ms = 0;
    /// collect_chunks: the chunks to delete from the blob stores.
    std::vector<chunk_sha> collected;

    [[nodiscard]] auto ok() const noexcept -> bool { return error.empty(); }

    friend auto operator==(const index_result&, const index_result&) -> bool = default;
};

namespace codec {

inline constexpr std::uint8_t command_format = 1;
inline constexpr std::uint8_t result_format = 1;

inline void write_bucket_ref(detail::writer& w, const bucket_ref& b) {
    w.u64(b.id).u8(static_cast<std::uint8_t>(b.versioning)).boolean(b.object_lock);
}

[[nodiscard]] inline auto read_bucket_ref(detail::reader& r) -> bucket_ref {
    bucket_ref b;
    b.id = r.u64();
    const auto v = r.u8();
    if (v > 2) {
        throw index_format_error("s3 index: bad versioning state");
    }
    b.versioning = static_cast<versioning_state>(v);
    b.object_lock = r.boolean();
    return b;
}

inline void write_opt_u64(detail::writer& w, const std::optional<std::uint64_t>& v) {
    w.boolean(v.has_value());
    if (v) {
        w.u64(*v);
    }
}

[[nodiscard]] inline auto read_opt_u64(detail::reader& r) -> std::optional<std::uint64_t> {
    if (r.boolean()) {
        return r.u64();
    }
    return std::nullopt;
}

[[nodiscard]] inline auto encode(const index_command& c) -> std::vector<std::byte> {
    detail::writer w;
    w.u8(command_format).u8(static_cast<std::uint8_t>(c.op)).u64(c.now_ms).str(c.owner);
    w.str(c.bucket);
    write_bucket_ref(w, c.target);
    w.str(c.key).str(c.region).boolean(c.object_lock).str(c.config_name).opt_str(c.document);
    w.opt_str(c.version_id);
    write_content(w, c.content);
    w.opt_str(c.conditions.if_match).boolean(c.conditions.if_none_match_star);
    write_bucket_ref(w, c.source);
    w.str(c.source_key).opt_str(c.source_if.if_match).opt_str(c.source_if.if_none_match);
    write_opt_u64(w, c.source_if.if_modified_since_ms);
    write_opt_u64(w, c.source_if.if_unmodified_since_ms);
    w.boolean(c.replace_metadata).str(c.upload_id);
    w.u32(c.part.number).str(c.part.etag).u64(c.part.last_modified_ms);
    write_manifest(w, c.part.manifest);
    w.map(c.part.checksums);
    w.u32(static_cast<std::uint32_t>(c.parts.size()));
    for (const auto& p : c.parts) {
        w.u32(p.number).str(p.etag);
    }
    w.u64(c.grace_ms).u32(c.max);
    w.map(c.config);
    w.u32(static_cast<std::uint32_t>(c.override_metadata.size()));
    for (const auto& name : c.override_metadata) {
        w.str(name);
    }
    const auto s = w.take();
    std::vector<std::byte> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

[[nodiscard]] inline auto decode_command(const std::vector<std::byte>& bytes) -> index_command {
    const std::string_view in(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    detail::reader r(in);
    r.expect_format(command_format, "command");
    index_command c;
    const auto op = r.u8();
    if (op < 1 || op > 12) {
        throw index_format_error("s3 index: unknown command");
    }
    c.op = static_cast<index_command::kind>(op);
    c.now_ms = r.u64();
    c.owner = r.str();
    c.bucket = r.str();
    c.target = read_bucket_ref(r);
    c.key = r.str();
    c.region = r.str();
    c.object_lock = r.boolean();
    c.config_name = r.str();
    c.document = r.opt_str();
    c.version_id = r.opt_str();
    c.content = read_content(r);
    c.conditions.if_match = r.opt_str();
    c.conditions.if_none_match_star = r.boolean();
    c.source = read_bucket_ref(r);
    c.source_key = r.str();
    c.source_if.if_match = r.opt_str();
    c.source_if.if_none_match = r.opt_str();
    c.source_if.if_modified_since_ms = read_opt_u64(r);
    c.source_if.if_unmodified_since_ms = read_opt_u64(r);
    c.replace_metadata = r.boolean();
    c.upload_id = r.str();
    c.part.number = r.u32();
    c.part.etag = r.str();
    c.part.last_modified_ms = r.u64();
    c.part.manifest = read_manifest(r);
    c.part.checksums = r.map();
    c.parts.resize(r.u32());
    for (auto& p : c.parts) {
        p.number = r.u32();
        p.etag = r.str();
    }
    c.grace_ms = r.u64();
    c.max = r.u32();
    c.config = r.map();
    c.override_metadata.resize(r.u32());
    for (auto& name : c.override_metadata) {
        name = r.str();
    }
    r.done("command");
    return c;
}

[[nodiscard]] inline auto encode(const index_result& x) -> std::vector<std::byte> {
    detail::writer w;
    w.u8(result_format).str(x.error).str(x.message).u32(x.status).str(x.version_id);
    w.boolean(x.delete_marker).str(x.etag).str(x.upload_id).u64(x.bucket_id);
    w.u64(x.last_modified_ms).u32(static_cast<std::uint32_t>(x.collected.size()));
    for (const auto& s : x.collected) {
        w.sha(s);
    }
    const auto s = w.take();
    std::vector<std::byte> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

[[nodiscard]] inline auto decode_result(const std::vector<std::byte>& bytes) -> index_result {
    const std::string_view in(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    detail::reader r(in);
    r.expect_format(result_format, "result");
    index_result x;
    x.error = r.str();
    x.message = r.str();
    x.status = r.u32();
    x.version_id = r.str();
    x.delete_marker = r.boolean();
    x.etag = r.str();
    x.upload_id = r.str();
    x.bucket_id = r.u64();
    x.last_modified_ms = r.u64();
    x.collected.resize(r.u32());
    for (auto& s : x.collected) {
        s = r.sha();
    }
    r.done("result");
    return x;
}

}  // namespace codec

// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

struct object_listing {
    std::vector<object_version> contents;
    std::vector<std::string> common_prefixes;
    bool truncated = false;
    /// The last key or common prefix returned: V1's NextMarker, and what
    /// V2 seals into its continuation token.
    std::string next_marker;
};

struct version_listing {
    struct entry {
        object_version version;
        bool is_latest = false;
    };
    std::vector<entry> versions;
    std::vector<std::string> common_prefixes;
    bool truncated = false;
    std::string next_key_marker;
    std::string next_version_id_marker;
};

struct index_options {
    /// The smallest part but the last that CompleteMultipartUpload accepts
    /// (S3: 5 MiB).
    std::uint64_t min_part_bytes = std::uint64_t{5} * 1024 * 1024;
    std::uint32_t max_parts = 10'000;
};

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

template<typename Engine = memory_kv_engine, typename LogIndex = std::uint64_t>
requires kv_engine<Engine>
class s3_index_state_machine {
public:
    using engine_type = Engine;

    explicit s3_index_state_machine(index_options options = {}) : _options(options) {}

    // ---- persistent_state_machine ----------------------------------------

    auto open(engine_type& engine, const key_range& range) -> void {
        _engine = &engine;
        _range = range;
        _ring.clear();
        _applied = 0;
        if (const auto v = _engine->get(column_family::meta, meta_key())) {
            _applied = static_cast<LogIndex>(std::stoull(*v));
        }
        _durable_floor = _applied;
    }

    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        if (index <= _applied) {
            return {};
        }
        const auto cmd = codec::decode_command(command);
        txn t(*this);
        index_result result;
        try {
            result = dispatch(t, cmd, static_cast<std::uint64_t>(index));
        } catch (const out_of_range&) {
            t = txn(*this);  // nothing of a refused entry is written
            result =
                fail(500, "InternalError", "The entry names a key outside this group's range.");
        }
        if (!result.ok()) {
            t = txn(*this);  // a failed entry changes nothing but the applied index
        }
        t.batch.put(column_family::meta, meta_key(), std::to_string(index));
        const auto seq = engine().write(t.batch);
        _applied = index;
        _ring.emplace_back(index, seq);
        trim_ring();
        return codec::encode(result);
    }

    [[nodiscard]] auto applied_index() const -> LogIndex { return _applied; }

    [[nodiscard]] auto durable_applied_index() const -> LogIndex {
        const auto durable_seq = engine().durable_sequence();
        LogIndex best = _durable_floor;
        for (const auto& [index, seq] : _ring) {
            if (seq > durable_seq) {
                break;
            }
            best = index;
        }
        return best;
    }

    auto checkpoint(const std::filesystem::path& dir) -> snapshot_manifest {
        return engine().checkpoint(_range, dir);
    }

    auto ingest(const std::filesystem::path& dir, const snapshot_manifest& manifest, LogIndex index)
        -> void {
        engine().ingest(_range, dir, manifest);
        _applied = index;
        _durable_floor = index;
        _ring.clear();
    }

    auto drop() -> void { engine().drop(_range); }

    [[nodiscard]] auto range() const -> const key_range& { return _range; }

    // ---- reads (local, at this replica's applied index) -------------------

    [[nodiscard]] auto bucket(std::string_view name) const -> std::optional<bucket_descriptor> {
        if (auto v = engine().get(column_family::data, keys::bucket(name))) {
            return codec::decode_bucket(*v);
        }
        return std::nullopt;
    }

    /// Every bucket, or the ones `owner` owns, by name.
    [[nodiscard]] auto list_buckets(std::string_view owner = {}) const
        -> std::vector<bucket_descriptor> {
        std::vector<bucket_descriptor> out;
        const std::string start(keys::bucket_prefix);
        engine().scan(column_family::data, key_range{start, keys::prefix_end(start)},
                      scan_direction::forward, [&](std::string_view, std::string_view v) {
                          auto b = codec::decode_bucket(v);
                          if (owner.empty() || b.owner == owner) {
                              out.push_back(std::move(b));
                          }
                          return true;
                      });
        return out;
    }

    /// The newest version of `key` (possibly a delete marker), or the one
    /// `version_id` names. Nothing for a malformed or unknown id.
    [[nodiscard]] auto version(std::uint64_t bucket_id, std::string_view key,
                               const std::optional<std::string>& version_id = std::nullopt) const
        -> std::optional<object_version> {
        return find_version(nullptr, bucket_id, key, version_id);
    }

    /// Current objects (newest version not a delete marker) under `prefix`,
    /// after `marker`, rolled up at `delimiter`, at most `max_keys` items
    /// (contents plus common prefixes), as S3 lists them.
    [[nodiscard]] auto list_objects(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view delimiter, std::string_view marker,
                                    std::size_t max_keys) const -> object_listing {
        object_listing out;
        const auto space = keys::bucket_space(keys::object_space, bucket_id);
        const auto end = keys::prefix_end(space + std::string(prefix));
        std::string cursor = space + std::string(prefix);
        if (!marker.empty()) {
            cursor = std::max(cursor, space + std::string(marker) + '\x01');
        }
        std::size_t items = 0;
        while (true) {
            auto next = first_in(cursor, end);
            if (!next) {
                break;
            }
            const auto split = keys::split(next->first, space.size());
            if (auto cp = common_prefix(split.key, prefix, delimiter)) {
                cursor = keys::prefix_end(space + *cp).value_or(std::string{});
                if (*cp <= marker) {
                    if (cursor.empty()) {
                        break;
                    }
                    continue;
                }
                if (items == max_keys) {
                    out.truncated = true;
                    break;
                }
                ++items;
                out.next_marker = *cp;
                out.common_prefixes.push_back(std::move(*cp));
                if (cursor.empty()) {
                    break;
                }
                continue;
            }
            cursor = space + split.key + '\x01';
            auto v = codec::decode_version(next->second);
            if (v.delete_marker) {
                continue;
            }
            if (items == max_keys) {
                out.truncated = true;
                break;
            }
            ++items;
            out.next_marker = v.key;
            out.contents.push_back(std::move(v));
        }
        return out;
    }

    /// Every version and delete marker under `prefix`, keys ascending and
    /// each key's versions newest first, after (`key_marker`,
    /// `version_id_marker`), as ListObjectVersions returns them.
    [[nodiscard]] auto list_versions(std::uint64_t bucket_id, std::string_view prefix,
                                     std::string_view delimiter, std::string_view key_marker,
                                     std::string_view version_id_marker, std::size_t max_keys) const
        -> version_listing {
        version_listing out;
        const auto space = keys::bucket_space(keys::object_space, bucket_id);
        const auto end = keys::prefix_end(space + std::string(prefix));
        std::string cursor = space + std::string(prefix);
        if (!key_marker.empty()) {
            std::optional<std::string> after;
            if (!version_id_marker.empty()) {
                if (auto v = version(bucket_id, key_marker, std::string(version_id_marker))) {
                    after =
                        keys::versioned(keys::object_space, bucket_id, key_marker, v->stamp) + '\0';
                }
            }
            cursor = std::max(cursor, after.value_or(space + std::string(key_marker) + '\x01'));
        }
        std::size_t items = 0;
        std::string latest_key;
        bool have_latest_key = false;
        while (true) {
            auto next = first_in(cursor, end);
            if (!next) {
                break;
            }
            const auto split = keys::split(next->first, space.size());
            if (auto cp = common_prefix(split.key, prefix, delimiter)) {
                cursor = keys::prefix_end(space + *cp).value_or(std::string{});
                if (*cp <= key_marker) {
                    if (cursor.empty()) {
                        break;
                    }
                    continue;
                }
                if (items == max_keys) {
                    out.truncated = true;
                    break;
                }
                ++items;
                out.next_key_marker = *cp;
                out.next_version_id_marker.clear();
                out.common_prefixes.push_back(std::move(*cp));
                if (cursor.empty()) {
                    break;
                }
                continue;
            }
            cursor = next->first + '\0';
            if (items == max_keys) {
                out.truncated = true;
                break;
            }
            auto v = codec::decode_version(next->second);
            bool latest = false;
            if (!have_latest_key || latest_key != v.key) {
                // The first version seen of a key is its latest unless the
                // listing resumed inside the key.
                const auto newest = first_in(
                    keys::key_prefix(keys::object_space, bucket_id, v.key),
                    keys::prefix_end(keys::key_prefix(keys::object_space, bucket_id, v.key)));
                latest = newest && newest->first == next->first;
                latest_key = v.key;
                have_latest_key = true;
            }
            ++items;
            out.next_key_marker = v.key;
            out.next_version_id_marker = v.version_id();
            out.versions.push_back({std::move(v), latest});
        }
        return out;
    }

    [[nodiscard]] auto upload(std::uint64_t bucket_id, std::string_view key,
                              std::string_view upload_id) const -> std::optional<upload_record> {
        const auto stamp = parse_stamp_id(upload_id);
        if (!stamp) {
            return std::nullopt;
        }
        if (auto v = engine().get(column_family::data,
                                  keys::versioned(keys::upload_space, bucket_id, key, *stamp))) {
            return codec::decode_upload(*v);
        }
        return std::nullopt;
    }

    /// Uploads in progress under `prefix`, by key then newest first, after
    /// (`key_marker`, `upload_id_marker`), at most `max`.
    [[nodiscard]] auto list_uploads(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view key_marker, std::string_view upload_id_marker,
                                    std::size_t max) const
        -> std::pair<std::vector<upload_record>, bool> {
        std::vector<upload_record> out;
        const auto space = keys::bucket_space(keys::upload_space, bucket_id);
        std::string cursor = space + std::string(prefix);
        if (!key_marker.empty()) {
            std::string after = space + std::string(key_marker) + '\x01';
            if (const auto s = parse_stamp_id(upload_id_marker)) {
                after = keys::versioned(keys::upload_space, bucket_id, key_marker, *s) + '\0';
            }
            cursor = std::max(cursor, after);
        }
        bool truncated = false;
        engine().scan(column_family::data,
                      key_range{cursor, keys::prefix_end(space + std::string(prefix))},
                      scan_direction::forward, [&](std::string_view, std::string_view v) {
                          if (out.size() == max) {
                              truncated = true;
                              return false;
                          }
                          out.push_back(codec::decode_upload(v));
                          return true;
                      });
        return {std::move(out), truncated};
    }

    [[nodiscard]] auto refcount(const chunk_sha& sha) const -> std::optional<refcount_record> {
        if (auto v = engine().get(column_family::data, keys::refcount(sha))) {
            return codec::decode_refcount(*v);
        }
        return std::nullopt;
    }

    /// Every reference count, for audits and the property tests.
    [[nodiscard]] auto all_refcounts() const -> std::map<chunk_sha, refcount_record> {
        std::map<chunk_sha, refcount_record> out;
        const std::string start(keys::refcount_space);
        engine().scan(column_family::data, key_range{start, keys::prefix_end(start)},
                      scan_direction::forward, [&](std::string_view k, std::string_view v) {
                          chunk_sha sha{};
                          std::memcpy(sha.data(), k.data() + start.size(), sha.size());
                          out.emplace(sha, codec::decode_refcount(v));
                          return true;
                      });
        return out;
    }

    /// Every key and value of the group's range, for replica comparisons.
    [[nodiscard]] auto dump() const -> std::map<std::string, std::string> {
        std::map<std::string, std::string> out;
        engine().scan(column_family::data, _range, scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          out.emplace(std::string(k), std::string(v));
                          return true;
                      });
        return out;
    }

private:
    struct out_of_range {};

    /// One entry's writes: a batch plus an overlay, so the entry reads its
    /// own writes (a manifest naming one chunk twice counts it twice).
    struct txn {
        explicit txn(s3_index_state_machine& sm) : self(&sm) {}

        [[nodiscard]] auto get(const std::string& key) const -> std::optional<std::string> {
            if (auto it = overlay.find(key); it != overlay.end()) {
                return it->second;
            }
            return self->engine().get(column_family::data, key);
        }
        void put(const std::string& key, std::string value) {
            self->check_range(key);
            overlay[key] = value;
            batch.put(column_family::data, key, std::move(value));
        }
        void erase(const std::string& key) {
            self->check_range(key);
            overlay[key] = std::nullopt;
            batch.erase(column_family::data, key);
        }

        s3_index_state_machine* self;
        write_batch batch;
        std::map<std::string, std::optional<std::string>> overlay;
    };

    [[nodiscard]] static auto fail(unsigned status, std::string code, std::string message)
        -> index_result {
        index_result r;
        r.status = status;
        r.error = std::move(code);
        r.message = std::move(message);
        return r;
    }
    [[nodiscard]] static auto no_such_bucket() -> index_result {
        return fail(404, "NoSuchBucket", "The specified bucket does not exist");
    }
    [[nodiscard]] static auto no_such_key() -> index_result {
        return fail(404, "NoSuchKey", "The specified key does not exist.");
    }
    [[nodiscard]] static auto no_such_upload() -> index_result {
        return fail(404, "NoSuchUpload",
                    "The specified upload does not exist. The upload ID may be invalid, or the "
                    "upload may have been aborted or completed.");
    }
    [[nodiscard]] static auto precondition_failed() -> index_result {
        return fail(412, "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold");
    }

    void check_range(const std::string& key) const {
        if (!_range.contains(key)) {
            throw out_of_range{};
        }
    }

    auto dispatch(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        using k = index_command::kind;
        switch (c.op) {
            case k::create_bucket:
                return create_bucket(t, c);
            case k::delete_bucket:
                return delete_bucket(t, c);
            case k::put_bucket_config:
                return put_bucket_config(t, c);
            case k::put_object:
                return put_object(t, c, index);
            case k::delete_object:
                return delete_object(t, c, index);
            case k::copy_object:
                return copy_object(t, c, index);
            case k::create_upload:
                return create_upload(t, c, index);
            case k::upload_part:
                return upload_part(t, c);
            case k::complete_upload:
                return complete_upload(t, c, index);
            case k::abort_upload:
                return abort_upload(t, c);
            case k::collect_chunks:
                return collect_chunks(t, c);
            case k::set_object_metadata:
                return set_object_metadata(t, c);
        }
        return fail(400, "InvalidRequest", "Unknown index command");
    }

    // ---- buckets ------------------------------------------------------------

    auto create_bucket(txn& t, const index_command& c) -> index_result {
        const auto key = keys::bucket(c.bucket);
        if (auto existing = t.get(key)) {
            const auto b = codec::decode_bucket(*existing);
            if (b.owner != c.owner) {
                return fail(409, "BucketAlreadyExists",
                            "The requested bucket name is not available. The bucket namespace is "
                            "shared by all users of the system. Please select a different name "
                            "and try again.");
            }
            // us-east-1 answers a repeated create by the owner with success,
            // which rclone relies on (it creates before every command).
            if (b.region == "us-east-1" && c.region == "us-east-1") {
                index_result r;
                r.bucket_id = b.id;
                return r;
            }
            return fail(409, "BucketAlreadyOwnedByYou",
                        "Your previous request to create the named bucket succeeded and you "
                        "already own it.");
        }
        const std::string counter(keys::next_bucket_id);
        std::uint64_t id = 1;
        if (auto v = t.get(counter)) {
            detail::reader r(*v);
            id = r.u64();
        }
        t.put(counter, detail::writer{}.u64(id + 1).take());
        bucket_descriptor b;
        b.name = c.bucket;
        b.id = id;
        b.owner = c.owner;
        b.region = c.region;
        b.created_ms = c.now_ms;
        b.object_lock = c.object_lock;
        b.config = c.config;
        // A bucket created with object lock is versioned from the start.
        b.versioning = c.object_lock ? versioning_state::enabled : versioning_state::unversioned;
        t.put(key, codec::encode(b));
        index_result r;
        r.bucket_id = id;
        return r;
    }

    auto delete_bucket(txn& t, const index_command& c) -> index_result {
        const auto key = keys::bucket(c.bucket);
        auto existing = t.get(key);
        if (!existing) {
            return no_such_bucket();
        }
        const auto b = codec::decode_bucket(*existing);
        for (const auto space : {keys::object_space, keys::upload_space}) {
            const auto prefix = keys::bucket_space(space, b.id);
            if (first_in(prefix, keys::prefix_end(prefix))) {
                return fail(409, "BucketNotEmpty", "The bucket you tried to delete is not empty");
            }
        }
        t.erase(key);
        index_result r;
        r.bucket_id = b.id;
        return r;
    }

    auto put_bucket_config(txn& t, const index_command& c) -> index_result {
        const auto key = keys::bucket(c.bucket);
        auto existing = t.get(key);
        if (!existing) {
            return no_such_bucket();
        }
        auto b = codec::decode_bucket(*existing);
        if (c.config_name == "versioning") {
            if (!c.document || (*c.document != "Enabled" && *c.document != "Suspended")) {
                return fail(400, "IllegalVersioningConfigurationException",
                            "The Versioning element must be specified");
            }
            if (*c.document == "Suspended" && b.object_lock) {
                return fail(409, "InvalidBucketState",
                            "An Object Lock configuration is present on this bucket, so the "
                            "versioning state cannot be changed.");
            }
            b.versioning =
                *c.document == "Enabled" ? versioning_state::enabled : versioning_state::suspended;
        } else if (c.config_name == "object-lock") {
            if (b.versioning != versioning_state::enabled) {
                return fail(409, "InvalidBucketState",
                            "Versioning must be 'Enabled' on the bucket to apply a Object Lock "
                            "configuration");
            }
            b.object_lock = true;
            if (c.document) {
                b.config[c.config_name] = *c.document;
            }
        } else if (c.document) {
            b.config[c.config_name] = *c.document;
        } else {
            b.config.erase(c.config_name);
        }
        t.put(key, codec::encode(b));
        index_result r;
        r.bucket_id = b.id;
        return r;
    }

    // ---- versions -----------------------------------------------------------

    /// The key's versions, newest first, read through the entry's overlay
    /// for any version this entry already wrote. Bounded by the key's
    /// version count.
    [[nodiscard]] auto versions_of(const txn* t, std::uint64_t bucket_id,
                                   std::string_view key) const -> std::vector<object_version> {
        std::vector<object_version> out;
        const auto prefix = keys::key_prefix(keys::object_space, bucket_id, key);
        engine().scan(column_family::data, key_range{prefix, keys::prefix_end(prefix)},
                      scan_direction::forward, [&](std::string_view k, std::string_view v) {
                          if (t != nullptr) {
                              if (auto it = t->overlay.find(std::string(k));
                                  it != t->overlay.end()) {
                                  if (it->second) {
                                      out.push_back(codec::decode_version(*it->second));
                                  }
                                  return true;
                              }
                          }
                          out.push_back(codec::decode_version(v));
                          return true;
                      });
        if (t != nullptr) {
            for (const auto& [k, v] : t->overlay) {
                if (v && k.starts_with(prefix) &&
                    !engine().get(column_family::data, k).has_value()) {
                    out.push_back(codec::decode_version(*v));
                }
            }
            std::sort(out.begin(), out.end(),
                      [](const auto& a, const auto& b) { return a.stamp > b.stamp; });
        }
        return out;
    }

    [[nodiscard]] auto find_version(const txn* t, std::uint64_t bucket_id, std::string_view key,
                                    const std::optional<std::string>& version_id) const
        -> std::optional<object_version> {
        if (!version_id) {
            auto all = versions_of(t, bucket_id, key);
            if (all.empty()) {
                return std::nullopt;
            }
            return std::move(all.front());
        }
        if (*version_id == null_version_id) {
            for (auto& v : versions_of(t, bucket_id, key)) {
                if (v.null_version) {
                    return std::move(v);
                }
            }
            return std::nullopt;
        }
        const auto stamp = parse_stamp_id(*version_id);
        if (!stamp) {
            return std::nullopt;
        }
        const auto k = keys::versioned(keys::object_space, bucket_id, key, *stamp);
        const auto v = t != nullptr ? t->get(k) : engine().get(column_family::data, k);
        if (!v) {
            return std::nullopt;
        }
        auto ver = codec::decode_version(*v);
        if (ver.null_version) {
            return std::nullopt;  // reachable only as "null"
        }
        return ver;
    }

    /// The next stamp for a version or upload of `key`: the entry's index,
    /// raised past the key's newest stamp in `space`.
    [[nodiscard]] auto next_stamp(const txn& t, std::string_view space, std::uint64_t bucket_id,
                                  std::string_view key, std::uint64_t index) const
        -> std::uint64_t {
        std::uint64_t stamp = index;
        const auto prefix = keys::key_prefix(space, bucket_id, key);
        const auto stamp_of = [](std::string_view k) {
            return ~detail::get_be64(k.substr(k.size() - 8));
        };
        if (auto newest = first_in(prefix, keys::prefix_end(prefix))) {
            stamp = std::max(stamp, stamp_of(newest->first) + 1);
        }
        for (const auto& [k, v] : t.overlay) {
            if (v && k.starts_with(prefix)) {
                stamp = std::max(stamp, stamp_of(k) + 1);
            }
        }
        return stamp;
    }

    void ref(txn& t, const std::vector<chunk_ref>& manifest, bool add, std::uint64_t now_ms) {
        for (const auto& c : manifest) {
            const auto key = keys::refcount(c.sha);
            refcount_record rec;
            const auto existing = t.get(key);
            if (existing) {
                rec = codec::decode_refcount(*existing);
            }
            if (add) {
                if (existing && rec.count == 0) {
                    t.erase(keys::zero(rec.zero_since_ms, c.sha));
                }
                ++rec.count;
                rec.zero_since_ms = 0;
            } else {
                if (!existing || rec.count == 0) {
                    throw std::logic_error("s3 index: reference count below zero for " +
                                           to_hex(c.sha));
                }
                if (--rec.count == 0) {
                    rec.zero_since_ms = now_ms;
                    t.put(keys::zero(now_ms, c.sha), {});
                }
            }
            t.put(key, codec::encode(rec));
        }
    }

    void remove_version(txn& t, std::uint64_t bucket_id, const object_version& v,
                        std::uint64_t now_ms) {
        t.erase(keys::versioned(keys::object_space, bucket_id, v.key, v.stamp));
        ref(t, v.content.manifest, false, now_ms);
    }

    /// `If-Match` / `If-None-Match: *` against the key's current version.
    [[nodiscard]] auto check_write(const txn& t, std::uint64_t bucket_id, std::string_view key,
                                   const write_conditions& w) const -> std::optional<index_result> {
        if (!w.if_match && !w.if_none_match_star) {
            return std::nullopt;
        }
        auto current = find_version(&t, bucket_id, key, std::nullopt);
        const bool exists = current && !current->delete_marker;
        if (w.if_none_match_star && exists) {
            return precondition_failed();
        }
        if (w.if_match) {
            if (!exists) {
                return no_such_key();
            }
            if (*w.if_match != "*" && unquote(*w.if_match) != current->content.etag) {
                return precondition_failed();
            }
        }
        return std::nullopt;
    }

    /// Store a new version of `key` per the bucket's versioning state.
    auto write_version(txn& t, const bucket_ref& b, const std::string& key, object_version v,
                       std::uint64_t index, std::uint64_t now_ms) -> index_result {
        if (key.find('\0') != std::string::npos) {
            return fail(400, "InvalidArgument", "Object keys may not contain NUL");
        }
        v.key = key;
        v.stamp = next_stamp(t, keys::object_space, b.id, key, index);
        v.null_version = b.versioning != versioning_state::enabled;
        if (v.null_version) {
            if (auto old = find_version(&t, b.id, key, std::string(null_version_id))) {
                remove_version(t, b.id, *old, now_ms);
            }
        }
        ref(t, v.content.manifest, true, now_ms);
        t.put(keys::versioned(keys::object_space, b.id, key, v.stamp), codec::encode(v));
        index_result r;
        r.bucket_id = b.id;
        r.version_id = v.version_id();
        r.delete_marker = v.delete_marker;
        r.etag = v.content.etag;
        r.last_modified_ms = v.last_modified_ms;
        return r;
    }

    auto put_object(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        if (auto failed = check_write(t, c.target.id, c.key, c.conditions)) {
            return *failed;
        }
        object_version v;
        v.last_modified_ms = c.now_ms;
        v.owner = c.owner;
        v.content = c.content;
        return write_version(t, c.target, c.key, std::move(v), index, c.now_ms);
    }

    auto set_object_metadata(txn& t, const index_command& c) -> index_result {
        const auto& b = c.target;
        if (c.version_id && *c.version_id != null_version_id && !parse_stamp_id(*c.version_id)) {
            return fail(400, "InvalidArgument", "Invalid version id specified");
        }
        auto v = find_version(&t, b.id, c.key, c.version_id);
        if (!v) {
            return c.version_id
                       ? fail(404, "NoSuchVersion", "The specified version does not exist.")
                       : no_such_key();
        }
        if (v->delete_marker) {
            return fail(405, "MethodNotAllowed",
                        "The specified method is not allowed against this resource.");
        }
        if (c.document) {
            v->content.system_metadata[c.config_name] = *c.document;
        } else {
            v->content.system_metadata.erase(c.config_name);
        }
        t.put(keys::versioned(keys::object_space, b.id, c.key, v->stamp), codec::encode(*v));
        index_result r;
        r.bucket_id = b.id;
        r.version_id = v->version_id();
        r.etag = v->content.etag;
        r.last_modified_ms = v->last_modified_ms;
        return r;
    }

    auto delete_object(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        const auto& b = c.target;
        if (c.version_id) {
            if (*c.version_id != null_version_id && !parse_stamp_id(*c.version_id)) {
                return fail(400, "InvalidArgument", "Invalid version id specified");
            }
            index_result r;
            r.bucket_id = b.id;
            r.version_id = *c.version_id;
            if (auto v = find_version(&t, b.id, c.key, c.version_id)) {
                r.delete_marker = v->delete_marker;
                remove_version(t, b.id, *v, c.now_ms);
            }
            return r;
        }
        if (b.versioning == versioning_state::unversioned) {
            if (auto v = find_version(&t, b.id, c.key, std::string(null_version_id))) {
                remove_version(t, b.id, *v, c.now_ms);
            }
            index_result r;
            r.bucket_id = b.id;
            return r;
        }
        object_version marker;
        marker.delete_marker = true;
        marker.last_modified_ms = c.now_ms;
        marker.owner = c.owner;
        return write_version(t, b, c.key, std::move(marker), index, c.now_ms);
    }

    auto copy_object(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        const auto source_key = keys::key_prefix(keys::object_space, c.source.id, c.source_key);
        check_range(source_key);
        auto src = find_version(&t, c.source.id, c.source_key, c.version_id);
        if (!src) {
            if (c.version_id && *c.version_id != null_version_id &&
                !parse_stamp_id(*c.version_id)) {
                return fail(400, "InvalidArgument", "Invalid version id specified");
            }
            return no_such_key();
        }
        if (src->delete_marker) {
            return c.version_id ? fail(400, "InvalidRequest",
                                       "The source of a copy request may not specifically refer "
                                       "to a delete marker by version id.")
                                : no_such_key();
        }
        if (!source_conditions_hold(c.source_if, *src)) {
            return precondition_failed();
        }
        if (c.source.id == c.target.id && c.source_key == c.key && !c.replace_metadata &&
            !c.version_id) {
            return fail(400, "InvalidRequest",
                        "This copy request is illegal because it is trying to copy an object to "
                        "itself without changing the object's metadata, storage class, website "
                        "redirect location or encryption attributes.");
        }
        if (auto failed = check_write(t, c.target.id, c.key, c.conditions)) {
            return *failed;
        }
        object_version v;
        v.last_modified_ms = c.now_ms;
        v.owner = c.owner;
        v.content = src->content;
        if (c.replace_metadata) {
            v.content.content_type = c.content.content_type;
            v.content.user_metadata = c.content.user_metadata;
            v.content.system_metadata = c.content.system_metadata;
            v.content.storage_class = c.content.storage_class;
        }
        for (const auto& name : c.override_metadata) {
            if (auto it = c.content.system_metadata.find(name);
                it != c.content.system_metadata.end()) {
                v.content.system_metadata[name] = it->second;
            } else {
                v.content.system_metadata.erase(name);
            }
        }
        if (!c.content.etag.empty()) {
            v.content.etag = c.content.etag;
        }
        return write_version(t, c.target, c.key, std::move(v), index, c.now_ms);
    }

    /// S3's copy-source rules, including its two documented pairings:
    /// if-match true with if-unmodified-since false copies, and
    /// if-none-match false with if-modified-since true fails.
    [[nodiscard]] static auto source_conditions_hold(const source_conditions& s,
                                                     const object_version& v) -> bool {
        const auto& etag = v.content.etag;
        if (s.if_match) {
            if (*s.if_match != "*" && unquote(*s.if_match) != etag) {
                return false;
            }
        } else if (s.if_unmodified_since_ms && v.last_modified_ms > *s.if_unmodified_since_ms) {
            return false;
        }
        if (s.if_none_match) {
            if (*s.if_none_match == "*" || unquote(*s.if_none_match) == etag) {
                return false;
            }
        } else if (s.if_modified_since_ms && v.last_modified_ms <= *s.if_modified_since_ms) {
            return false;
        }
        return true;
    }

    // ---- uploads ------------------------------------------------------------

    auto create_upload(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        if (c.key.find('\0') != std::string::npos) {
            return fail(400, "InvalidArgument", "Object keys may not contain NUL");
        }
        upload_record u;
        u.key = c.key;
        u.stamp = next_stamp(t, keys::upload_space, c.target.id, c.key, index);
        u.initiated_ms = c.now_ms;
        u.owner = c.owner;
        u.content = c.content;
        u.content.manifest.clear();
        t.put(keys::versioned(keys::upload_space, c.target.id, c.key, u.stamp), codec::encode(u));
        index_result r;
        r.bucket_id = c.target.id;
        r.upload_id = u.upload_id();
        return r;
    }

    [[nodiscard]] auto load_upload(const txn& t, const index_command& c) const
        -> std::optional<std::pair<std::string, upload_record>> {
        const auto stamp = parse_stamp_id(c.upload_id);
        if (!stamp) {
            return std::nullopt;
        }
        auto key = keys::versioned(keys::upload_space, c.target.id, c.key, *stamp);
        auto v = t.get(key);
        if (!v) {
            return std::nullopt;
        }
        return std::pair{std::move(key), codec::decode_upload(*v)};
    }

    auto upload_part(txn& t, const index_command& c) -> index_result {
        if (c.part.number < 1 || c.part.number > _options.max_parts) {
            return fail(400, "InvalidArgument",
                        "Part number must be an integer between 1 and 10000, inclusive");
        }
        auto loaded = load_upload(t, c);
        if (!loaded) {
            return no_such_upload();
        }
        auto& [key, u] = *loaded;
        if (auto old = u.parts.find(c.part.number); old != u.parts.end()) {
            ref(t, old->second.manifest, false, c.now_ms);
        }
        part_record p = c.part;
        p.last_modified_ms = c.now_ms;
        ref(t, p.manifest, true, c.now_ms);
        u.parts[p.number] = p;
        t.put(key, codec::encode(u));
        index_result r;
        r.bucket_id = c.target.id;
        r.etag = p.etag;
        return r;
    }

    auto complete_upload(txn& t, const index_command& c, std::uint64_t index) -> index_result {
        auto loaded = load_upload(t, c);
        if (!loaded) {
            return no_such_upload();
        }
        auto& [upload_key, u] = *loaded;
        if (c.parts.empty()) {
            return fail(400, "MalformedXML",
                        "The XML you provided was not well-formed or did not validate against our "
                        "published schema");
        }
        for (std::size_t i = 1; i < c.parts.size(); ++i) {
            if (c.parts[i].number <= c.parts[i - 1].number) {
                return fail(400, "InvalidPartOrder",
                            "The list of parts was not in ascending order. Parts must be ordered "
                            "by part number.");
            }
        }
        std::vector<const part_record*> chosen;
        for (const auto& want : c.parts) {
            auto it = u.parts.find(want.number);
            if (it == u.parts.end() || unquote(want.etag) != it->second.etag) {
                return fail(400, "InvalidPart",
                            "One or more of the specified parts could not be found. The part may "
                            "not have been uploaded, or the specified entity tag may not match the "
                            "part's entity tag.");
            }
            chosen.push_back(&it->second);
        }
        for (std::size_t i = 0; i + 1 < chosen.size(); ++i) {
            if (chosen[i]->size() < _options.min_part_bytes) {
                return fail(
                    400, "EntityTooSmall",
                    "Your proposed upload is smaller than the minimum allowed object size.");
            }
        }
        if (auto failed = check_write(t, c.target.id, c.key, c.conditions)) {
            return *failed;
        }
        object_version v;
        v.last_modified_ms = c.now_ms;
        v.owner = u.owner;
        v.content = u.content;
        std::vector<std::string> part_etags;
        for (const auto* p : chosen) {
            v.content.manifest.insert(v.content.manifest.end(), p->manifest.begin(),
                                      p->manifest.end());
            v.content.part_sizes.push_back(p->size());
            part_etags.push_back(p->etag);
        }
        v.content.etag = multipart_etag(part_etags);
        // Every part gives up its references and the new version takes
        // the chosen parts' chunks: the net effect moves the chosen parts'
        // references to the object and drops the parts left out.
        for (const auto& [n, p] : u.parts) {
            ref(t, p.manifest, false, c.now_ms);
        }
        t.erase(upload_key);
        return write_version(t, c.target, c.key, std::move(v), index, c.now_ms);
    }

    auto abort_upload(txn& t, const index_command& c) -> index_result {
        auto loaded = load_upload(t, c);
        if (!loaded) {
            return no_such_upload();
        }
        auto& [key, u] = *loaded;
        for (const auto& [n, p] : u.parts) {
            ref(t, p.manifest, false, c.now_ms);
        }
        t.erase(key);
        index_result r;
        r.bucket_id = c.target.id;
        return r;
    }

    /// S3's multipart ETag: the MD5 of the parts' binary MD5s, then `-N`.
    /// A part ETag that is not 32 hex digits (an SSE-C part, say) is hashed
    /// as its text.
    [[nodiscard]] static auto multipart_etag(const std::vector<std::string>& part_etags)
        -> std::string {
        std::string concat;
        for (const auto& e : part_etags) {
            const bool hex = e.size() == 32 && std::all_of(e.begin(), e.end(), [](char ch) {
                                 return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                                        (ch >= 'A' && ch <= 'F');
                             });
            if (!hex) {
                concat += e;
                continue;
            }
            for (std::size_t i = 0; i < 32; i += 2) {
                const auto nib = [](char ch) {
                    return ch <= '9' ? ch - '0' : (ch | 0x20) - 'a' + 10;
                };
                concat.push_back(static_cast<char>((nib(e[i]) << 4) | nib(e[i + 1])));
            }
        }
        std::array<unsigned char, 16> md{};
        unsigned int len = 0;
        if (::EVP_Digest(concat.data(), concat.size(), md.data(), &len, ::EVP_md5(), nullptr) !=
            1) {
            throw std::runtime_error("s3 index: EVP_Digest(md5) failed");
        }
        static constexpr std::string_view hex_digits = "0123456789abcdef";
        std::string out;
        for (const auto b : md) {
            out.push_back(hex_digits[b >> 4U]);
            out.push_back(hex_digits[b & 0xFU]);
        }
        return out + "-" + std::to_string(part_etags.size());
    }

    // ---- reference counts ---------------------------------------------------

    auto collect_chunks(txn& t, const index_command& c) -> index_result {
        index_result r;
        const std::string start(keys::zero_space);
        std::vector<std::pair<std::string, chunk_sha>> due;
        engine().scan(column_family::data, key_range{start, keys::prefix_end(start)},
                      scan_direction::forward, [&](std::string_view k, std::string_view) {
                          if (due.size() >= c.max) {
                              return false;
                          }
                          const auto since = detail::get_be64(k.substr(start.size()));
                          if (since + c.grace_ms > c.now_ms) {
                              return false;  // oldest first: nothing later is due
                          }
                          chunk_sha sha{};
                          std::memcpy(sha.data(), k.data() + start.size() + 8, sha.size());
                          due.emplace_back(std::string(k), sha);
                          return true;
                      });
        for (const auto& [zkey, sha] : due) {
            t.erase(zkey);
            t.erase(keys::refcount(sha));
            r.collected.push_back(sha);
        }
        return r;
    }

    // ---- helpers ------------------------------------------------------------

    [[nodiscard]] static auto unquote(std::string_view etag) -> std::string {
        if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') {
            etag = etag.substr(1, etag.size() - 2);
        }
        return std::string(etag);
    }

    /// The common prefix `key` rolls up into, if `delimiter` occurs after
    /// `prefix`.
    [[nodiscard]] static auto common_prefix(std::string_view key, std::string_view prefix,
                                            std::string_view delimiter)
        -> std::optional<std::string> {
        if (delimiter.empty() || !key.starts_with(prefix)) {
            return std::nullopt;
        }
        const auto pos = key.find(delimiter, prefix.size());
        if (pos == std::string_view::npos) {
            return std::nullopt;
        }
        return std::string(key.substr(0, pos + delimiter.size()));
    }

    [[nodiscard]] auto first_in(const std::string& start,
                                const std::optional<std::string>& end) const
        -> std::optional<std::pair<std::string, std::string>> {
        std::optional<std::pair<std::string, std::string>> out;
        engine().scan(column_family::data, key_range{start, end}, scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          out.emplace(std::string(k), std::string(v));
                          return false;
                      });
        return out;
    }

    [[nodiscard]] auto meta_key() const -> std::string { return "s3-applied/" + _range.start; }

    [[nodiscard]] auto engine() const -> engine_type& {
        if (_engine == nullptr) {
            throw std::logic_error("s3_index_state_machine: not open");
        }
        return *_engine;
    }

    auto trim_ring() -> void {
        const auto durable_seq = engine().durable_sequence();
        while (_ring.size() > 1 && _ring[1].second <= durable_seq) {
            _durable_floor = _ring.front().first;
            _ring.pop_front();
        }
    }

    index_options _options;
    engine_type* _engine = nullptr;
    key_range _range;
    LogIndex _applied{};
    LogIndex _durable_floor{};
    std::deque<std::pair<LogIndex, engine_sequence>> _ring;
};

static_assert(persistent_state_machine<s3_index_state_machine<>, std::uint64_t>);

}  // namespace kythira::s3
