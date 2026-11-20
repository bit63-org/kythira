// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_tiers.hpp
/// @brief Archive storage classes in a cloud object store
///        (.kiro/specs/s3-compatible-storage/ task 13, Requirement 7.5).
///
/// A deployment may map the archive classes (GLACIER, DEEP_ARCHIVE) to a
/// `cloud_tier`: a bucket and prefix on any store core's
/// `key_object_store` reaches (S3, Azure Blob, GCS, OCI, OSS). The other
/// classes stay on the blob stores, since they must be readable without a
/// restore. `tier_worker::run` does the tier's work:
///
/// 1. **Archive.** A version in a mapped class whose bytes are still on the
///    blob stores has its chunks copied to the tier, as stored (sealed when
///    encrypted), under `<prefix><bucket id>/<stamp>/<sha>`. Then
///    `set_object_state` marks it tiered (`x-kythira-tier`), and the index
///    drops its references on the blob stores, so the sweeper collects
///    chunks nothing else shares after the grace period. A version with a
///    restore asked or running is left for later.
/// 2. **Restore.** For each restore the index lists (`s3/r/`), the chunks
///    come back from the tier, verified against their hashes, and are
///    written to the blob stores at their write quorum; then the version
///    is marked restored (`x-kythira-restored`, which takes references on
///    the blob stores again, through the same `written_ms` check as any
///    write) with the requested expiry. When the restore ends, the
///    lifecycle worker clears it and the references go.
/// 3. **Garbage.** Removing a tiered version leaves an `s3/g/` entry naming
///    its cloud keys; they are deleted and the entry dropped.
///
/// Cloud keys are per version, so archived bytes are not deduplicated
/// across objects: nothing in the tier is shared, and a version's copies
/// can go the moment it does, with no reference counts or grace period in
/// the tier. A copy that a crash left behind before its commit is written
/// again by the next run (the keys are the same); one left by a version
/// removed in between stays until a tier listing sweep, which is not
/// built.
///
/// One worker runs per index (on the metadata leader, task 16).

#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_lifecycle_rules.hpp>
#include <kythira/s3/s3_metadata.hpp>

#include <raft/chunk_store.hpp>
#include <raft/key_object_store.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// One cloud bucket and prefix holding archived chunks. Does not own the
/// store.
class cloud_tier {
public:
    template<key_object_store S>
    cloud_tier(std::string name, const S& store, std::string bucket, std::string prefix = {})
        : _name(std::move(name)),
          _put([&store, b = bucket](const std::string& key, std::string_view bytes) {
              (void)store.put_object(b, key, bytes);
          }),
          _get([&store, b = bucket](const std::string& key) -> std::optional<std::string> {
              auto r = store.get_object(b, key);
              if (!r) {
                  return std::nullopt;
              }
              return std::move(r->body);
          }),
          _remove([&store, b = std::move(bucket)](const std::string& key) {
              store.delete_object(b, key);
          }),
          _prefix(std::move(prefix)) {
        if (_name.empty()) {
            throw std::invalid_argument("s3 cloud tier: needs a name");
        }
    }

    [[nodiscard]] auto name() const noexcept -> const std::string& { return _name; }

    /// The cloud key of one chunk of a version.
    [[nodiscard]] auto key_of(std::uint64_t bucket_id, std::uint64_t stamp,
                              const chunk_sha& sha) const -> std::string {
        return _prefix + std::to_string(bucket_id) + "/" + stamp_id(stamp) + "/" + to_hex(sha);
    }

    void put(std::uint64_t bucket_id, std::uint64_t stamp, const chunk_sha& sha,
             std::span<const std::byte> bytes) const {
        _put(key_of(bucket_id, stamp, sha),
             std::string_view(reinterpret_cast<const char*>(bytes.data()),  // NOLINT
                              bytes.size()));
    }

    /// The chunk's bytes, or nullopt when absent or not what its hash says.
    [[nodiscard]] auto get(std::uint64_t bucket_id, std::uint64_t stamp, const chunk_sha& sha) const
        -> std::optional<std::vector<std::byte>> {
        auto got = _get(key_of(bucket_id, stamp, sha));
        if (!got) {
            return std::nullopt;
        }
        std::vector<std::byte> out(got->size());
        std::memcpy(out.data(), got->data(), got->size());
        if (sha256_of(out) != sha) {
            return std::nullopt;
        }
        return out;
    }

    void remove(std::uint64_t bucket_id, std::uint64_t stamp, const chunk_sha& sha) const {
        _remove(key_of(bucket_id, stamp, sha));
    }

private:
    std::string _name;
    std::function<void(const std::string&, std::string_view)> _put;
    std::function<std::optional<std::string>(const std::string&)> _get;
    std::function<void(const std::string&)> _remove;
    std::string _prefix;
};

/// What the tier worker needs from the metadata layer.
template<typename M>
concept tier_metadata_access = metadata_access<M> && requires(const M& cm, std::size_t n) {
    { cm.pending_restores(n) } -> std::same_as<std::vector<pending_restore>>;
    { cm.tier_garbage_list(n) } -> std::same_as<std::vector<tier_garbage_entry>>;
};

struct tier_options {
    /// Storage class to tier name; only the archive classes may be mapped.
    std::map<std::string, std::string> class_tiers;
    /// A lifecycle day, for restore expiries.
    std::uint64_t day_ms = standard_day_ms;
    /// Versions, restores and garbage entries read per page.
    std::size_t page = 1000;
    /// The clock, for tests; the system clock when empty.
    std::function<std::uint64_t()> clock;
};

struct tier_report {
    std::uint64_t archived = 0;
    std::uint64_t chunks_uploaded = 0;
    std::uint64_t restored = 0;
    std::uint64_t chunks_restored = 0;
    std::uint64_t garbage_versions = 0;
    std::uint64_t chunks_deleted = 0;
    /// Work that failed (a chunk unreadable, a store error, a lost race)
    /// and is retried by a later run.
    std::uint64_t failures = 0;
};

template<tier_metadata_access M> class tier_worker {
public:
    tier_worker(M& meta, data_path& data, std::vector<const cloud_tier*> tiers,
                tier_options options = {})
        : _meta(meta), _data(data), _options(std::move(options)) {
        for (const auto* t : tiers) {
            if (t == nullptr || !_tiers.emplace(t->name(), t).second) {
                throw std::invalid_argument("s3 tier worker: tiers need distinct names");
            }
        }
        for (const auto& [cls, tier] : _options.class_tiers) {
            if (!is_archive_class(cls)) {
                throw std::invalid_argument(
                    "s3 tier worker: only GLACIER and DEEP_ARCHIVE may "
                    "live in a cloud tier, not " +
                    cls);
            }
            if (!_tiers.contains(tier)) {
                throw std::invalid_argument("s3 tier worker: no tier named " + tier);
            }
        }
        if (_options.day_ms == 0 || _options.page == 0) {
            throw std::invalid_argument("s3 tier worker: needs a day length and a page size");
        }
    }

    auto run() -> tier_report {
        tier_report r;
        restore(r);
        collect_garbage(r);
        if (!_options.class_tiers.empty()) {
            for (const auto& b : _meta.list_buckets("")) {
                archive_bucket(b, r);
            }
        }
        return r;
    }

private:
    [[nodiscard]] auto now_ms() const -> std::uint64_t {
        if (_options.clock) {
            return _options.clock();
        }
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

    void archive_bucket(const bucket_descriptor& desc, tier_report& r) {
        std::string km;
        std::string vm;
        for (bool more = true; more;) {
            auto page = _meta.list_versions(desc.id, "", "", km, vm, _options.page);
            more = page.truncated;
            km = page.next_key_marker;
            vm = page.next_version_id_marker;
            for (const auto& e : page.versions) {
                archive(desc, e.version, r);
            }
            if (page.versions.empty()) {
                break;
            }
        }
    }

    void archive(const bucket_descriptor& desc, const object_version& v, tier_report& r) {
        if (v.delete_marker) {
            return;
        }
        const auto& m = v.content.system_metadata;
        const auto mapped = _options.class_tiers.find(v.content.storage_class);
        if (mapped == _options.class_tiers.end() || m.contains(std::string(tier_metadata)) ||
            m.contains(std::string(restore_pending_metadata)) || restore_until(v) > now_ms()) {
            return;
        }
        const auto& tier = *_tiers.at(mapped->second);
        std::uint64_t uploaded = 0;
        try {
            for (const auto& c : v.content.manifest) {
                auto bytes = _data.read_chunk(c);
                if (!bytes) {
                    ++r.failures;
                    return;
                }
                tier.put(desc.id, v.stamp, c.sha, *bytes);
                ++uploaded;
            }
        } catch (const std::exception&) {
            ++r.failures;
            return;
        }
        index_command c;
        c.op = index_command::kind::set_object_state;
        c.now_ms = now_ms();
        c.target = ref_of(desc);
        c.key = v.key;
        c.version_id = v.version_id();
        c.expect_stamp = v.stamp;
        c.override_metadata = {std::string(tier_metadata)};
        c.content.system_metadata[std::string(tier_metadata)] = tier.name();
        if (const auto res = _meta.propose(c); !res.ok()) {
            ++r.failures;
            if (res.error == "PreconditionFailed" || res.error == "NoSuchVersion") {
                // Gone or replaced meanwhile: nothing will name these copies.
                remove_copies(tier, desc.id, v.stamp, v.content.manifest, r);
            }
            return;
        }
        ++r.archived;
        r.chunks_uploaded += uploaded;
    }

    void restore(tier_report& r) {
        for (const auto& p : _meta.pending_restores(_options.page)) {
            const auto desc = find_bucket(p.bucket_id);
            if (!desc) {
                continue;
            }
            const auto v = version_of(*desc, p.key, p.stamp);
            if (!v) {
                continue;
            }
            const auto& m = v->content.system_metadata;
            const auto tier_name = m.find(std::string(tier_metadata));
            if (tier_name == m.end() || !_tiers.contains(tier_name->second)) {
                ++r.failures;
                continue;
            }
            const auto& tier = *_tiers.at(tier_name->second);
            const auto written_ms = now_ms();
            std::uint64_t chunks = 0;
            bool ok = true;
            try {
                for (const auto& c : v->content.manifest) {
                    auto bytes = tier.get(desc->id, v->stamp, c.sha);
                    if (!bytes) {
                        ok = false;
                        break;
                    }
                    auto w = _data.write_chunk(*bytes);
                    if (!w || w->sha != c.sha) {
                        ok = false;
                        break;
                    }
                    ++chunks;
                }
            } catch (const std::exception&) {
                ok = false;
            }
            if (!ok) {
                ++r.failures;
                continue;
            }
            const auto now = now_ms();
            const auto until = due_after(now, std::max<std::uint32_t>(p.days, 1), _options.day_ms);
            index_command c;
            c.op = index_command::kind::set_object_state;
            c.now_ms = now;
            c.written_ms = written_ms;
            c.target = ref_of(*desc);
            c.key = v->key;
            c.version_id = v->version_id();
            c.expect_stamp = v->stamp;
            c.override_metadata = {std::string(restored_metadata), std::string(restore_metadata),
                                   std::string(restore_until_metadata),
                                   std::string(restore_pending_metadata)};
            auto& sm = c.content.system_metadata;
            sm[std::string(restored_metadata)] = "1";
            sm[std::string(restore_metadata)] =
                "ongoing-request=\"false\", expiry-date=\"" +
                aws_rest_xml::http_date(
                    std::chrono::system_clock::time_point(std::chrono::milliseconds(until))) +
                "\"";
            sm[std::string(restore_until_metadata)] = std::to_string(until);
            if (_meta.propose(c).ok()) {
                ++r.restored;
                r.chunks_restored += chunks;
            } else {
                ++r.failures;  // e.g. SlowDown while a chunk was being collected: next run
            }
        }
    }

    void collect_garbage(tier_report& r) {
        const auto garbage = _meta.tier_garbage_list(_options.page);
        std::vector<std::string> done;
        for (const auto& g : garbage) {
            const auto it = _tiers.find(g.tier);
            if (it == _tiers.end()) {
                ++r.failures;
                continue;
            }
            std::vector<chunk_ref> refs;
            for (const auto& sha : g.chunks) {
                refs.push_back({sha, 0});
            }
            if (remove_copies(*it->second, g.bucket_id, g.stamp, refs, r)) {
                ++r.garbage_versions;
                done.push_back(g.index_key);
            }
        }
        if (!done.empty()) {
            index_command c;
            c.op = index_command::kind::drop_tier_garbage;
            c.now_ms = now_ms();
            c.garbage_keys = std::move(done);
            (void)_meta.propose(c);
        }
    }

    auto remove_copies(const cloud_tier& tier, std::uint64_t bucket_id, std::uint64_t stamp,
                       const std::vector<chunk_ref>& manifest, tier_report& r) -> bool {
        try {
            for (const auto& c : manifest) {
                tier.remove(bucket_id, stamp, c.sha);
                ++r.chunks_deleted;
            }
        } catch (const std::exception&) {
            ++r.failures;
            return false;
        }
        return true;
    }

    [[nodiscard]] auto find_bucket(std::uint64_t id) const -> std::optional<bucket_descriptor> {
        for (auto& b : _meta.list_buckets("")) {
            if (b.id == id) {
                return b;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto version_of(const bucket_descriptor& b, const std::string& key,
                                  std::uint64_t stamp) const -> std::optional<object_version> {
        auto v = _meta.version(b.id, key, stamp_id(stamp));
        if (!v) {
            // An unversioned bucket's version is `null`.
            v = _meta.version(b.id, key, std::string(null_version_id));
            if (v && v->stamp != stamp) {
                v.reset();
            }
        }
        return v;
    }

    M& _meta;
    data_path& _data;
    std::map<std::string, const cloud_tier*> _tiers;
    tier_options _options;
};

}  // namespace kythira::s3
