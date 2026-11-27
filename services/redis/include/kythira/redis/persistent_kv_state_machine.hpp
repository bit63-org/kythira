// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file persistent_kv_state_machine.hpp
/// @brief The Redis gateway's command set on a `kv_engine`
///        (.kiro/specs/persistent-state-machine/ task 2, Requirements 2.1-2.4
///        and 9.1; typed values from .kiro/specs/redis-general-data-types/
///        task 10, Requirement 13.2).
///
/// `redis_kv_state_machine` keeps a shard in a `std::map` and moves it as one
/// buffer on every snapshot, restart and split. This class applies the same
/// commands (`redis_kv_commands.hpp`) to a range of the node's engine instead,
/// with the same results, so the gateway can run on either one.
///
/// Layout, for a host namespace `ns` and a shard range `[start, end)`:
///
/// - `data` column family, a string: `ns + K` → `u64 BE expire_at_ms` then
///   the value.
/// - `data` column family, a collection (hash, set or list; after the
///   group's format gate, redis-general-data-types Component 6): a header
///   row `ns + K + "\x00\x00"` → `u64 expire_at_ms, u8 type, u64 count,
///   u64 bytes, u64 head`, then one row per element:
///   - hash: `ns + K + "\x00\x01" + field` → the value;
///   - set: `ns + K + "\x00\x01" + member` → empty;
///   - list: `ns + K + "\x00\x02" + u64 BE seq` → the element, with seqs
///     `head .. head + count - 1` in list order. A new list starts at
///     2^63, so pushing at either end has room for 2^63 elements.
///
///   An element write rewrites only that element's row and the header
///   (Requirement 13.2), and a key's rows sort together between the key
///   and the next user key, so the engine's range operations (checkpoint,
///   ingest, drop, split, merge) carry a collection whole.
/// - `meta` column family: one record at `ns + start`, the first key of the
///   group's own range, holding the applied index, the counters
///   (`approximate_size_bytes`, key count, expiring count) and, once the
///   group has passed a format gate, its format level and applied command
///   time.
///
/// **Key escaping.** For the composite keys above to be unambiguous, `K` is
/// the user key with every `0x00` byte written as `0x00 0xFF` once the group
/// has passed its format gate. Then `0x00` followed by anything but `0xFF`
/// ends the key, and the escaping keeps byte order, so a key's rows still
/// sort before the next user key's. Before the gate `K` is the raw key, as
/// it always was, so a binary that predates typed values reads the same
/// rows; the gate rewrites the group's few keys that contain `0x00` into the
/// escaped form in its own batch. A shard bound has to mean the same engine
/// key either way, so this store never splits at a key containing `0x00`
/// (`can_split_at`), and a group whose bounds contain one (from a split made
/// by an older build) refuses the gate: its typed commands keep answering
/// the format-gate error until it is merged away.
///
/// Keeping the meta record inside the group's range (in its own column
/// family, so it never collides with data) means the engine's range
/// operations treat it as part of the group: a checkpoint carries the
/// leader's applied index and counters, an ingest replaces them, a drop
/// removes them, and no other group's range can contain them, since ranges
/// on one engine are disjoint. A split writes a record at each child's start;
/// a merge erases the source's record in the batch that widens the target.
/// The design sketched `<ns>/group/<id>/applied_index` instead, which needs a
/// group id this concept's `open(engine, range)` does not carry and would sit
/// inside whichever group's range happens to cover that string.
///
/// A meta record with a format level is 48 bytes instead of 32. A build
/// without typed values refuses one ("meta record has the wrong size") and
/// stops, which is the loud failure Requirement 14.4 asks for: such a build
/// cannot read the escaped keys or the collection rows behind it.
///
/// Every `apply` writes its effects and the new meta record in one batch
/// (Requirement 2.1) without syncing (2.4): the Raft log is durable, so a
/// batch lost in a power cut is replayed, and `durable_applied_index()` maps
/// the engine's durable sequence back to the highest applied index it covers
/// so the node never compacts past it (Requirement 3.1).
///
/// `apply` stays a pure function of the log, as in the in-memory machine:
/// expiry is a deadline stamped by the leader and removed by a `sweep` entry,
/// never by `apply` reading a clock. Format-0x03 `exec` records run through
/// the same appliers as the in-memory machine (`redis_*_exec.hpp`), on an
/// adaptor that decodes each key it touches and writes back only what
/// changed.
///
/// The decoded collections the appliers last wrote are kept in a bounded
/// cache, so a run of writes to one large collection decodes it once rather
/// than on every command. Like every other member it is only touched under
/// the node's lock (`raft::node::with_state_machine` and apply), which
/// serialises reads against writes.

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>
#include <kythira/redis/redis_format_level.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_exec_appliers.hpp>
#include <kythira/redis/redis_typed_read.hpp>
#include <kythira/redis/redis_value.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira {

namespace persistent_kv_detail {

inline auto put_u64(std::string& out, std::uint64_t v) -> void {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((v >> shift) & 0xFFU));
    }
}

inline auto get_u64(std::string_view in, std::size_t at) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v = (v << 8U) | static_cast<unsigned char>(in[at + i]);
    }
    return v;
}

/// The smallest string greater than every string starting with `prefix`, or
/// nullopt when there is none (empty, or all 0xFF bytes).
inline auto prefix_successor(std::string prefix) -> std::optional<std::string> {
    while (!prefix.empty()) {
        auto& last = prefix.back();
        if (static_cast<unsigned char>(last) != 0xFFU) {
            last = static_cast<char>(static_cast<unsigned char>(last) + 1U);
            return prefix;
        }
        prefix.pop_back();
    }
    return std::nullopt;
}

/// A stored data value: the deadline, then the bytes.
inline auto encode_value(std::uint64_t expire_at_ms, const std::vector<std::byte>& value)
    -> std::string {
    std::string out;
    out.reserve(8 + value.size());
    put_u64(out, expire_at_ms);
    out.append(reinterpret_cast<const char*>(value.data()), value.size());
    return out;
}

inline auto value_expiry(std::string_view stored) -> std::uint64_t {
    if (stored.size() < 8) {
        throw persistent_storage_error("persistent_kv_state_machine: truncated value record");
    }
    return get_u64(stored, 0);
}

inline auto value_size(std::string_view stored) -> std::size_t {
    return stored.size() - 8;
}

inline auto decode_value(std::string_view stored) -> std::shared_ptr<const redis_kv_value_entry> {
    auto entry = std::make_shared<redis_kv_value_entry>();
    entry->_expire_at_ms = value_expiry(stored);
    const auto body = stored.substr(8);
    entry->_value.resize(body.size());
    std::memcpy(entry->_value.data(), body.data(), body.size());
    return entry;
}

// ---- typed-value rows (redis-general-data-types task 10) -------------------

/// The suffixes after an escaped key: its header row, its hash or set
/// element rows, its list element rows. The end of the element rows is
/// `"\x00\x03"`.
inline constexpr std::string_view k_header_suffix{"\x00\x00", 2};
inline constexpr std::string_view k_member_suffix{"\x00\x01", 2};
inline constexpr std::string_view k_list_suffix{"\x00\x02", 2};
inline constexpr std::string_view k_elements_end{"\x00\x03", 2};

/// The seq of a new list's first element: the middle of the u64 range, so
/// either end can grow.
inline constexpr std::uint64_t k_list_origin = std::uint64_t{1} << 63U;

/// `key` with each `0x00` written as `0x00 0xFF`: order-preserving, and no
/// escaped key contains `0x00` followed by anything else.
inline auto escape_key(std::string_view key) -> std::string {
    std::string out;
    out.reserve(key.size());
    for (const char c : key) {
        out.push_back(c);
        if (c == '\0') {
            out.push_back('\xFF');
        }
    }
    return out;
}

[[nodiscard]] inline auto has_nul(std::string_view s) noexcept -> bool {
    return s.find('\0') != std::string_view::npos;
}

enum class row_kind : std::uint8_t {
    string,
    header,
    element
};

struct parsed_row {
    row_kind kind = row_kind::string;
    /// The user key, unescaped.
    std::string key;
};

/// What a data row is, from its key without the namespace. `escaped` is
/// whether the group has passed its gate; before it every row is a string.
inline auto parse_row(std::string_view row, bool escaped) -> parsed_row {
    if (!escaped) {
        return {row_kind::string, std::string(row)};
    }
    parsed_row out;
    out.key.reserve(row.size());
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] != '\0') {
            out.key.push_back(row[i]);
            continue;
        }
        if (i + 1 >= row.size()) {
            throw persistent_storage_error("persistent_kv_state_machine: malformed row key");
        }
        const auto next = static_cast<unsigned char>(row[i + 1]);
        if (next == 0xFFU) {
            out.key.push_back('\0');
            ++i;
            continue;
        }
        out.kind = next == 0 ? row_kind::header : row_kind::element;
        return out;
    }
    return out;
}

/// A collection's header row.
struct collection_header {
    std::uint64_t expire_at_ms = 0;
    redis_value_type type = redis_value_type::hash;
    std::uint64_t count = 0;
    std::uint64_t bytes = 0;
    /// A list's first seq; 0 for a hash or set.
    std::uint64_t head = 0;

    static constexpr std::size_t k_encoded_size = 33;

    [[nodiscard]] auto encode() const -> std::string {
        std::string out;
        out.reserve(k_encoded_size);
        put_u64(out, expire_at_ms);
        out.push_back(static_cast<char>(type));
        put_u64(out, count);
        put_u64(out, bytes);
        put_u64(out, head);
        return out;
    }

    [[nodiscard]] static auto decode(std::string_view in) -> collection_header {
        if (in.size() != k_encoded_size) {
            throw persistent_storage_error(
                "persistent_kv_state_machine: collection header has the wrong size");
        }
        const auto type = static_cast<std::uint8_t>(in[8]);
        if (type < static_cast<std::uint8_t>(redis_value_type::hash) ||
            type > static_cast<std::uint8_t>(redis_value_type::list)) {
            throw persistent_storage_error(
                "persistent_kv_state_machine: collection header names an unknown type " +
                std::to_string(type));
        }
        return {get_u64(in, 0), static_cast<redis_value_type>(type), get_u64(in, 9),
                get_u64(in, 17), get_u64(in, 25)};
    }
};

inline auto list_seq(std::uint64_t seq) -> std::string {
    std::string out;
    out.reserve(8);
    put_u64(out, seq);
    return out;
}

/// Builds one collection from its header and element rows, in row order.
class collection_builder {
public:
    explicit collection_builder(collection_header h) : _h(h) {}

    /// `suffix` is the element row's key after the escaped key.
    auto add(std::string_view suffix, std::string_view value) -> void {
        if (suffix.size() < 2) {
            throw persistent_storage_error("persistent_kv_state_machine: malformed element row");
        }
        const auto tail = suffix.substr(2);
        switch (_h.type) {
            case redis_value_type::hash:
                _pairs.emplace_back(std::string(tail), std::string(value));
                break;
            case redis_value_type::set:
                _members.emplace_back(tail);
                break;
            case redis_value_type::list:
                _members.emplace_back(value);
                break;
            case redis_value_type::string:
                break;
        }
    }

    [[nodiscard]] auto finish() -> std::shared_ptr<const redis_kv_value_entry> {
        auto e = std::make_shared<redis_kv_value_entry>();
        e->_expire_at_ms = _h.expire_at_ms;
        e->_type = _h.type;
        std::size_t n = 0;
        switch (_h.type) {
            case redis_value_type::hash:
                n = _pairs.size();
                e->_hash = std::make_shared<redis_hash>(redis_hash::from_sorted(std::move(_pairs)));
                break;
            case redis_value_type::set:
                n = _members.size();
                e->_set = std::make_shared<redis_set>(redis_set::from_sorted(std::move(_members)));
                break;
            case redis_value_type::list:
                n = _members.size();
                e->_list =
                    std::make_shared<redis_list>(redis_list::from_elements(std::move(_members)));
                break;
            case redis_value_type::string:
                break;
        }
        if (n != _h.count || n == 0) {
            throw persistent_storage_error(
                "persistent_kv_state_machine: a collection's rows do not match its header");
        }
        return e;
    }

    [[nodiscard]] auto header() const noexcept -> const collection_header& { return _h; }

private:
    collection_header _h;
    std::vector<std::pair<std::string, std::string>> _pairs;
    std::vector<std::string> _members;
};

/// The per-group meta record.
struct meta_record {
    std::uint64_t applied = 0;
    std::uint64_t keys = 0;
    std::uint64_t bytes = 0;
    std::uint64_t expiring = 0;
    /// The format level the group has passed a gate for; 0 before any.
    std::uint64_t level = 0;
    /// The largest command time a format-0x03 entry has applied at.
    std::uint64_t applied_time = 0;

    static constexpr std::size_t k_encoded_size = 32;
    static constexpr std::size_t k_encoded_size_v3 = 48;

    /// 32 bytes, as every earlier build wrote it, until the group passes a
    /// gate; then 48.
    [[nodiscard]] auto encode() const -> std::string {
        std::string out;
        out.reserve(level > 0 ? k_encoded_size_v3 : k_encoded_size);
        put_u64(out, applied);
        put_u64(out, keys);
        put_u64(out, bytes);
        put_u64(out, expiring);
        if (level > 0) {
            put_u64(out, level);
            put_u64(out, applied_time);
        }
        return out;
    }

    [[nodiscard]] static auto decode(std::string_view in) -> meta_record {
        if (in.size() != k_encoded_size && in.size() != k_encoded_size_v3) {
            throw persistent_storage_error(
                "persistent_kv_state_machine: meta record has the wrong size");
        }
        meta_record m{get_u64(in, 0), get_u64(in, 8), get_u64(in, 16), get_u64(in, 24)};
        if (in.size() == k_encoded_size_v3) {
            m.level = get_u64(in, 32);
            m.applied_time = get_u64(in, 40);
            if (m.level > k_redis_format_level) {
                throw redis_format_too_new(static_cast<std::uint16_t>(m.level));
            }
        }
        return m;
    }
};

}  // namespace persistent_kv_detail

template<typename Engine = memory_kv_engine, typename LogIndex = std::uint64_t>
requires log_index<LogIndex>
class persistent_kv_state_machine {
public:
    using engine_type = Engine;
    using key_type = std::string;
    using entry_handle = std::shared_ptr<const redis_kv_value_entry>;

    /// The decoded collections kept between commands, in `redis_entry_bytes`.
    static constexpr std::size_t k_cache_bytes = std::size_t{64} << 20U;

    /// `ns` prefixes every engine key, keeping two hosts in one process apart
    /// (design "One engine per node, groups as key ranges").
    explicit persistent_kv_state_machine(std::string ns = {}) : _ns(std::move(ns)) {}

    // ---- persistent_state_machine -----------------------------------------

    /// Attaches to `range` of `engine` (in shard-key space) and reads its meta
    /// record back. Nothing else is read (Requirement 4.1). What was recovered
    /// is durable, so the durable applied index starts there.
    auto open(engine_type& engine, const key_range& range) -> void {
        _engine = &engine;
        _range = range;
        _seqs.clear();
        discard_staged();
        clear_cache();
        const auto stored = engine.get(column_family::meta, meta_key());
        _meta = stored.has_value() ? persistent_kv_detail::meta_record::decode(*stored)
                                   : persistent_kv_detail::meta_record{};
        _durable_floor = static_cast<LogIndex>(_meta.applied);
    }

    /// Applies one committed entry and records `index` in the same batch
    /// (Requirement 2.1). An index at or below `applied_index()` is a replay
    /// of something the engine already holds and changes nothing (2.3). The
    /// reply is the in-memory machine's: one byte, 1 if the entry changed
    /// anything, or for a format-0x03 record its status or encoded reply.
    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        require_open();
        if (static_cast<std::uint64_t>(index) <= _meta.applied) {
            return {std::byte{0}};
        }
        write_batch batch;
        try {
            auto reply = stage(command, batch);
            commit_staged(batch, index);
            return reply;
        } catch (...) {
            discard_staged();
            throw;
        }
    }

    // ---- persistent_staged_state_machine ----------------------------------

    /// Adds `command`'s effects to `batch` (Requirement 8.1). Later `stage`
    /// calls of the same entry read what this one wrote, and the counters
    /// carry over until `commit_staged`.
    auto stage(const std::vector<std::byte>& command, write_batch& batch)
        -> std::vector<std::byte> {
        require_open();
        if (!_staged.has_value()) {
            _overlay.clear();
            _staged = _meta;
        }
        // A record from a newer format halts the group rather than being
        // skipped (redis-general-data-types Requirement 14.4).
        require_redis_record_level(command);
        _batch = &batch;
        try {
            std::vector<std::byte> reply;
            if (is_redis_kv_v3_record(command)) {
                reply = stage_v3(decode_redis_kv_v3_command(command));
            } else {
                auto decoded = decode_redis_kv_command(command);
                const bool changed = std::visit([&](auto& c) { return apply_one(c); }, decoded);
                reply = {changed ? std::byte{1} : std::byte{0}};
            }
            _batch = nullptr;
            return reply;
        } catch (...) {
            _batch = nullptr;
            throw;
        }
    }

    /// Writes `batch` with `index` as the applied index and the staged
    /// counters, in one write.
    auto commit_staged(write_batch& batch, LogIndex index) -> void {
        require_open();
        auto next = _staged.value_or(_meta);
        _staged.reset();
        next.applied = static_cast<std::uint64_t>(index);
        batch.put(column_family::meta, meta_key(), next.encode());
        commit(batch, next);
        for (auto& [key, l] : _overlay) {
            remember(key, std::move(l));
        }
        _overlay.clear();
    }

    auto discard_staged() -> void {
        _staged.reset();
        _overlay.clear();
    }

    [[nodiscard]] auto key_prefix() const noexcept -> const std::string& { return _ns; }

    [[nodiscard]] auto applied_index() const -> LogIndex {
        return static_cast<LogIndex>(_meta.applied);
    }

    /// The highest applied index whose batch the engine has made durable.
    [[nodiscard]] auto durable_applied_index() const -> LogIndex {
        if (_engine == nullptr) {
            return _durable_floor;
        }
        const auto durable = _engine->durable_sequence();
        while (!_seqs.empty() && _seqs.front().second <= durable) {
            _durable_floor = _seqs.front().first;
            _seqs.pop_front();
        }
        return _durable_floor;
    }

    /// Makes every batch applied so far durable. The node calls it before
    /// compacting when the durable index lags by more than
    /// `raft_configuration::_persistent_sync_lag_entries`; without it an
    /// engine that syncs only when asked (RocksDB) never advances the
    /// durable index, and the group's log is never compacted.
    auto sync_durable() -> void {
        require_open();
        if (!_seqs.empty()) {
            _engine->sync(_seqs.back().second);
        }
    }

    /// A checkpoint of the whole range at `applied_index()`, meta record
    /// included, for a follower (file-install-snapshot).
    auto checkpoint(const std::filesystem::path& dir) -> snapshot_manifest {
        require_open();
        return _engine->checkpoint(engine_range(), dir);
    }

    /// Replaces the range with a leader's checkpoint taken at `index`. The
    /// checkpoint brought the leader's meta record, format level included;
    /// the applied index is set to `index` in a second batch, and a crash
    /// between the two leaves the leader's own applied index, which is the
    /// checkpoint's point too.
    auto ingest(const std::filesystem::path& dir, const snapshot_manifest& manifest, LogIndex index)
        -> void {
        require_open();
        clear_cache();
        _engine->ingest(engine_range(), dir, manifest);
        const auto stored = _engine->get(column_family::meta, meta_key());
        auto next = stored.has_value() ? persistent_kv_detail::meta_record::decode(*stored)
                                       : persistent_kv_detail::meta_record{};
        next.applied = static_cast<std::uint64_t>(index);
        write_batch batch;
        batch.put(column_family::meta, meta_key(), next.encode());
        commit(batch, next);
    }

    /// Deletes every key of the range, meta record included.
    auto drop() -> void {
        require_open();
        clear_cache();
        _engine->drop(engine_range());
        _meta = {};
        _seqs.clear();
        _durable_floor = LogIndex{};
    }

    // ---- persistent_splittable_state_machine -------------------------------

    /// Narrows this range to the part below the first cut and returns the
    /// child ranges in key order. One batch writes a meta record at each
    /// child's start, carrying this group's applied index, format level and
    /// command time (a child's applied index starts at the split entry's, as
    /// a derived child's does today) and the counters of its part. No data
    /// key moves: a cut is a user key, and all of a key's rows sort between
    /// it and the next user key. The counters are recounted by a scan of
    /// each part. A cut containing `0x00` is dropped (`can_split_at`).
    auto split_at(const std::vector<std::string>& keys) -> std::vector<key_range> {
        require_open();
        std::vector<std::string> cuts = keys;
        std::ranges::sort(cuts);
        cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
        std::erase_if(cuts, [&](const std::string& k) {
            return !_range.contains(k) || persistent_kv_detail::has_nul(k);
        });
        if (cuts.empty() || cuts.front() == _range.start) {
            if (!cuts.empty()) {
                throw std::invalid_argument(
                    "persistent_kv_state_machine: split at the range start");
            }
            return {};
        }

        std::vector<key_range> children;
        for (std::size_t i = 0; i < cuts.size(); ++i) {
            children.push_back(key_range{cuts[i], i + 1 < cuts.size()
                                                      ? std::optional<std::string>(cuts[i + 1])
                                                      : _range.end});
        }
        write_batch batch;
        for (const auto& child : children) {
            auto m = count(child, escaped());
            carry_header(m, _meta);
            batch.put(column_family::meta, _ns + child.start, m.encode());
        }
        _range.end = cuts.front();
        auto next = count(_range, escaped());
        carry_header(next, _meta);
        batch.put(column_family::meta, meta_key(), next.encode());
        commit(batch, next);
        clear_cache();
        return children;
    }

    /// Widens this range over the adjacent `range`, above or below it,
    /// already in the same engine. The source's meta record is folded into
    /// this one in one batch; no data key moves. Adopting from below moves
    /// this group's record to the new start, which is the source's key, so
    /// the source's record is overwritten rather than erased. Adopting a
    /// range already covered is a no-op (design "Split and merge",
    /// idempotence).
    ///
    /// The merged group takes the higher format level and command time. When
    /// only one side had passed its gate, the same batch escapes the other
    /// side's keys that contain `0x00`. That needs bounds without `0x00`,
    /// which every split since this build guarantees; an older split's bound
    /// is refused with `persistent_storage_error`.
    auto adopt(const key_range& range) -> void {
        require_open();
        if (_range.contains(range)) {
            return;
        }
        const bool above = _range.end.has_value() && range.start == *_range.end;
        const bool below = range.end.has_value() && *range.end == _range.start;
        if (!above && !below) {
            throw std::invalid_argument(
                "persistent_kv_state_machine: adopt of a range that is not adjacent");
        }
        const auto source_key = _ns + range.start;
        const auto stored = _engine->get(column_family::meta, source_key);
        const auto source = stored.has_value() ? persistent_kv_detail::meta_record::decode(*stored)
                                               : persistent_kv_detail::meta_record{};
        auto next = _meta;
        next.keys += source.keys;
        next.bytes += source.bytes;
        next.expiring += source.expiring;
        next.level = std::max(_meta.level, source.level);
        next.applied_time = std::max(_meta.applied_time, source.applied_time);
        write_batch batch;
        const bool mine_gated = _meta.level >= k_redis_typed_values_level;
        const bool source_gated = source.level >= k_redis_typed_values_level;
        if (mine_gated != source_gated) {
            const auto merged_end = above ? range.end : _range.end;
            const auto merged_start = above ? _range.start : range.start;
            if (persistent_kv_detail::has_nul(merged_start) ||
                (merged_end && persistent_kv_detail::has_nul(*merged_end)) ||
                persistent_kv_detail::has_nul(range.start) ||
                (range.end && persistent_kv_detail::has_nul(*range.end))) {
                throw persistent_storage_error(
                    "persistent_kv_state_machine: cannot merge a typed group with an untyped one "
                    "across a shard bound containing a NUL byte");
            }
            std::map<std::string, entry_handle, std::less<>> moving;
            for (auto& [key, stored] : raw_nul_keys(mine_gated ? range : _range)) {
                moving.emplace(key, persistent_kv_detail::decode_value(stored));
            }
            write_escaped(moving, batch);
        }
        if (above) {
            batch.erase(column_family::meta, source_key);
            _range.end = range.end;
        } else {
            batch.erase(column_family::meta, meta_key());
            _range.start = range.start;
        }
        batch.put(column_family::meta, meta_key(), next.encode());
        commit(batch, next);
        clear_cache();
    }

    // ---- splittable_state_machine's size hints -----------------------------

    [[nodiscard]] auto approximate_size_bytes() const noexcept -> std::size_t {
        return static_cast<std::size_t>(_meta.bytes);
    }
    [[nodiscard]] auto approximate_key_count() const noexcept -> std::size_t {
        return static_cast<std::size_t>(_meta.keys);
    }
    [[nodiscard]] auto expiring_key_count() const noexcept -> std::size_t {
        return static_cast<std::size_t>(_meta.expiring);
    }

    /// The in-memory machine's choice: evenly spaced by key count, never the
    /// first key. Keys containing `0x00` are passed over (`can_split_at`).
    [[nodiscard]] auto suggest_split_keys(std::size_t max) const -> std::vector<key_type> {
        std::vector<key_type> out;
        const auto n = approximate_key_count();
        if (max == 0 || n < 2) {
            return out;
        }
        const std::size_t wanted = std::min(max, n - 1);
        const std::size_t stride = n / (wanted + 1);
        if (stride == 0) {
            return out;
        }
        std::size_t index = 0;
        for_each_user_row([&](const persistent_kv_detail::parsed_row& row, std::string_view) {
            ++index;
            if (out.size() < wanted && index % stride == 0 && index < n &&
                !persistent_kv_detail::has_nul(row.key)) {
                out.push_back(row.key);
            }
            return out.size() < wanted;
        });
        return out;
    }

    /// A shard bound must name the same engine key before and after the
    /// format gate, so never one containing `0x00` (see the file comment).
    [[nodiscard]] auto can_split_at(const key_type& key) const -> bool {
        return !persistent_kv_detail::has_nul(key);
    }

    // ---- command time and format level (redis-general-data-types) ---------

    /// The format level the group has passed a gate for; 0 before any. Inside
    /// a staged entry, the level that entry has reached.
    [[nodiscard]] auto format_level() const noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>(_staged ? _staged->level : _meta.level);
    }

    /// Raises the group's format level (one way). Called by
    /// `apply_redis_v3_common` for a gate inside `stage`, which has already
    /// checked the bounds: the same batch escapes the keys that contain
    /// `0x00`.
    auto enable_format(std::uint16_t level) -> void {
        if (!_staged || _batch == nullptr) {
            throw std::logic_error("persistent_kv_state_machine: enable_format outside stage");
        }
        if (level <= _staged->level) {
            return;
        }
        const bool was_escaped = _staged->level >= k_redis_typed_values_level;
        if (!was_escaped && level >= k_redis_typed_values_level) {
            // The final value of each key with a NUL byte: the engine's raw
            // row, unless this entry already wrote the key (the overlay).
            std::map<std::string, entry_handle, std::less<>> moving;
            for (auto& [key, stored] : raw_nul_keys(_range)) {
                moving.emplace(key, persistent_kv_detail::decode_value(stored));
            }
            for (const auto& [key, l] : _overlay) {
                if (persistent_kv_detail::has_nul(key)) {
                    moving[key] = l.entry;
                }
            }
            write_escaped(moving, *_batch);
            for (auto& [key, entry] : moving) {
                _overlay[key] = loaded{std::move(entry), 0};
            }
        }
        _staged->level = level;
    }

    /// The command time a format-0x03 entry stamped `entry_now_ms` runs at,
    /// as in the in-memory machine (Requirement 2.2-2.3).
    auto advance_command_time(std::uint64_t entry_now_ms) -> std::uint64_t {
        auto& m = _staged ? *_staged : _meta;
        m.applied_time = std::max(m.applied_time, entry_now_ms);
        return m.applied_time;
    }

    [[nodiscard]] auto applied_time_ms() const noexcept -> std::uint64_t {
        return _meta.applied_time;
    }

    // ---- read path (the in-memory machine's API) ---------------------------

    /// A handle to a value, read from the engine; null if absent. Like the
    /// in-memory machine it ignores the deadline.
    [[nodiscard]] auto lookup(std::string_view key) const -> entry_handle {
        require_open();
        return load_committed(std::string(key)).entry;
    }

    /// The reply to a read of `key` at the serving node's time `now_ms`, as
    /// the in-memory machine's `evaluate_read`.
    [[nodiscard]] auto evaluate_read(redis_command_id id, const key_type& key,
                                     std::span<const std::string> args, std::uint64_t now_ms) const
        -> redis_reply {
        const auto entry = lookup(key);
        if (auto reply = evaluate_redis_read(entry.get(), id, args, now_ms)) {
            return *reply;
        }
        return redis_reply::error("ERR command id " + std::to_string(static_cast<int>(id)) +
                                  " is not a read of this store");
    }

    /// Keys whose deadline is non-zero and at or before `now_ms`, in key
    /// order, at most `max`.
    [[nodiscard]] auto collect_expired(std::uint64_t now_ms, std::size_t max) const
        -> std::vector<redis_kv_sweep_entry> {
        std::vector<redis_kv_sweep_entry> out;
        if (max == 0) {
            return out;
        }
        for_each_user_row(
            [&](const persistent_kv_detail::parsed_row& row, std::string_view stored) {
                const auto expire = row_expiry(row, stored);
                if (expire != 0 && expire <= now_ms) {
                    out.push_back({row.key, expire});
                }
                return out.size() < max;
            });
        return out;
    }

    /// Every key in order with its entry. A collection is built from its
    /// rows in the same scan, since they follow its header.
    template<typename F> auto for_each_key(F&& f) const -> void {
        require_open();
        const bool esc = _meta.level >= k_redis_typed_values_level;
        std::optional<std::pair<std::string, persistent_kv_detail::collection_builder>> building;
        std::size_t open_key_end = 0;
        std::string open_row;
        const auto flush = [&] {
            if (building) {
                const auto entry = building->second.finish();
                f(building->first, *entry);
                building.reset();
            }
        };
        _engine->scan(
            column_family::data, engine_range(), scan_direction::forward,
            [&](std::string_view engine_key, std::string_view stored) {
                const auto row_key = engine_key.substr(_ns.size());
                // An element row of the collection being built:
                // its escaped key, then 0x00 0x01 or 0x00 0x02.
                if (building && row_key.size() >= open_key_end + 2 &&
                    row_key.substr(0, open_key_end) == open_row && row_key[open_key_end] == '\0' &&
                    (row_key[open_key_end + 1] == '\x01' || row_key[open_key_end + 1] == '\x02')) {
                    building->second.add(row_key.substr(open_key_end), stored);
                    return true;
                }
                flush();
                auto row = persistent_kv_detail::parse_row(row_key, esc);
                if (row.kind == persistent_kv_detail::row_kind::string) {
                    const auto entry = persistent_kv_detail::decode_value(stored);
                    f(row.key, *entry);
                } else if (row.kind == persistent_kv_detail::row_kind::header) {
                    open_key_end = row_key.size() - 2;
                    open_row = std::string(row_key.substr(0, open_key_end));
                    building.emplace(std::move(row.key),
                                     persistent_kv_detail::collection_builder(
                                         persistent_kv_detail::collection_header::decode(stored)));
                }
                return true;
            });
        flush();
    }

    [[nodiscard]] auto range() const noexcept -> const key_range& { return _range; }

private:
    /// A decoded key and, for a list, its first seq.
    struct loaded {
        entry_handle entry;
        std::uint64_t head = 0;
    };

    // ---- format-0x03 records ----------------------------------------------

    auto stage_v3(const redis_kv_v3_command& record) -> std::vector<std::byte> {
        if (const auto* gate = std::get_if<redis_kv_format_gate_command>(&record)) {
            // A bound with a NUL byte would name a different engine key once
            // escaped, so such a group stays at its level (file comment).
            if (gate->_level <= k_redis_format_level &&
                gate->_level >= k_redis_typed_values_level &&
                format_level() < k_redis_typed_values_level && bounds_have_nul()) {
                return redis_v3_apply_result(redis_v3_apply_status::unchanged);
            }
        }
        if (auto status = apply_redis_v3_common(*this, record)) {
            return redis_v3_apply_result(*status);
        }
        if (const auto* exec = std::get_if<redis_kv_exec_command>(&record)) {
            return apply_exec(*exec);
        }
        // range_delete and remove_members are not proposed yet (tasks 13
        // and 8 use exec records); they change nothing, as in memory.
        return redis_v3_apply_result(redis_v3_apply_status::unchanged);
    }

    auto apply_exec(const redis_kv_exec_command& c) -> std::vector<std::byte> {
        const auto t = advance_command_time(c._now_ms);
        struct store_ops {
            persistent_kv_state_machine& _sm;
            [[nodiscard]] auto find(const key_type& key) const -> entry_handle {
                return _sm.load(key).entry;
            }
            auto put(const key_type& key, std::vector<std::byte> value, std::uint64_t expire_at_ms)
                -> void {
                auto entry = std::make_shared<redis_kv_value_entry>();
                entry->_value = std::move(value);
                entry->_expire_at_ms = expire_at_ms;
                _sm.store(key, std::move(entry));
            }
            auto put_entry(const key_type& key, entry_handle entry) -> void {
                _sm.store(key, std::move(entry));
            }
            auto erase(const key_type& key) -> bool { return _sm.erase(key); }
        } ops{*this};
        auto reply = apply_redis_exec(ops, c, t);
        if (!reply) {
            throw redis_unknown_command_id(c._command_id);
        }
        return encode_redis_reply(*reply);
    }

    // ---- format-0x01/0x02 records ------------------------------------------

    auto apply_one(redis_kv_set_command& c) -> bool {
        auto entry = std::make_shared<redis_kv_value_entry>();
        entry->_value = std::move(c._value);
        entry->_expire_at_ms = c._expire_at_ms;
        store(c._key, std::move(entry));
        return true;
    }

    auto apply_one(const redis_kv_del_command& c) -> bool { return erase(c._key); }

    /// Deletes each key only if its stored deadline still equals the one the
    /// sweep was built from, as the in-memory machine does.
    auto apply_one(const redis_kv_sweep_command& c) -> bool {
        bool changed = false;
        for (const auto& e : c._entries) {
            if (e._expire_at_ms == 0) {
                continue;
            }
            const auto current = load(e._key).entry;
            if (current && current->_expire_at_ms == e._expire_at_ms) {
                changed = erase(e._key) || changed;
            }
        }
        return changed;
    }

    /// The disk-backed store's records; no-ops here as in the in-memory
    /// machine.
    auto apply_one(const redis_kv_put_chunk_command&) -> bool { return false; }
    auto apply_one(const redis_kv_commit_command&) -> bool { return false; }
    auto apply_one(const redis_kv_touch_command&) -> bool { return false; }

    auto apply_one(const redis_kv_evict_command& c) -> bool {
        bool changed = false;
        for (const auto& k : c._keys) {
            changed = erase(k) || changed;
        }
        return changed;
    }

    // ---- user-level reads and writes ---------------------------------------

    /// Whether the staged (inside `stage`) or committed level escapes keys.
    [[nodiscard]] auto escaped() const noexcept -> bool {
        return format_level() >= k_redis_typed_values_level;
    }

    [[nodiscard]] auto row_key(const std::string& key, bool esc) const -> std::string {
        return _ns + (esc ? persistent_kv_detail::escape_key(key) : key);
    }

    /// `key` as this entry has left it so far. A batch is applied only at
    /// commit, so later commands of the same entry (a sweep or evict naming
    /// one key twice, an `LMOVE` from a list to itself) must see earlier
    /// ones' effects.
    auto load(const std::string& key) -> loaded {
        if (const auto it = _overlay.find(key); it != _overlay.end()) {
            return it->second;
        }
        return load_engine(key, escaped());
    }

    /// `key` as committed: the cache, else the engine.
    [[nodiscard]] auto load_committed(const std::string& key) const -> loaded {
        return load_engine(key, _meta.level >= k_redis_typed_values_level);
    }

    [[nodiscard]] auto load_engine(const std::string& key, bool esc) const -> loaded {
        if (const auto it = _cache.find(key); it != _cache.end()) {
            return it->second;
        }
        const auto rk = row_key(key, esc);
        if (auto stored = _engine->get(column_family::data, rk)) {
            return {persistent_kv_detail::decode_value(*stored), 0};
        }
        if (!esc) {
            return {};
        }
        const auto header_row = rk + std::string(persistent_kv_detail::k_header_suffix);
        const auto stored = _engine->get(column_family::data, header_row);
        if (!stored) {
            return {};
        }
        persistent_kv_detail::collection_builder builder(
            persistent_kv_detail::collection_header::decode(*stored));
        _engine->scan(column_family::data,
                      key_range{rk + std::string(persistent_kv_detail::k_member_suffix),
                                rk + std::string(persistent_kv_detail::k_elements_end)},
                      scan_direction::forward, [&](std::string_view k, std::string_view v) {
                          builder.add(k.substr(rk.size()), v);
                          return true;
                      });
        const auto head = builder.header().head;
        return {builder.finish(), head};
    }

    /// Replaces `key`'s value with `next`, writing only the rows that
    /// differ, and updates the counters.
    auto store(const std::string& key, entry_handle next) -> void {
        auto& m = *_staged;
        const auto old = load(key);
        if (old.entry) {
            uncount(key, *old.entry, m);
        }
        const auto next_type = redis_entry_type(*next);
        if (next_type != redis_value_type::string && collection_size(*next) == 0) {
            // An applier never leaves an empty collection; store nothing.
            if (old.entry) {
                erase_rows(key, old);
            }
            _overlay[key] = loaded{};
            return;
        }
        if (next_type != redis_value_type::string && !escaped()) {
            // apply_redis_v3_common refuses typed records before the gate.
            throw std::logic_error("persistent_kv_state_machine: a collection before the gate");
        }
        m.keys += 1;
        m.bytes += key.size() + redis_entry_bytes(*next);
        m.expiring += next->_expire_at_ms != 0 ? 1 : 0;
        const auto rk = row_key(key, escaped());
        const auto old_type = old.entry ? redis_entry_type(*old.entry) : next_type;
        if (old.entry && old_type != next_type) {
            erase_rows(key, old);
        }
        const loaded base = old.entry && old_type == next_type ? old : loaded{};
        std::uint64_t head = 0;
        switch (next_type) {
            case redis_value_type::string:
                _batch->put(column_family::data, rk,
                            persistent_kv_detail::encode_value(next->_expire_at_ms, next->_value));
                break;
            case redis_value_type::hash:
                write_hash(rk, base.entry ? base.entry->_hash.get() : nullptr, *next->_hash);
                break;
            case redis_value_type::set:
                write_set(rk, base.entry ? base.entry->_set.get() : nullptr, *next->_set);
                break;
            case redis_value_type::list:
                head = write_list(rk, base.entry ? base.entry->_list.get() : nullptr, base.head,
                                  *next->_list);
                break;
        }
        if (next_type != redis_value_type::string) {
            persistent_kv_detail::collection_header h{next->_expire_at_ms, next_type,
                                                      collection_size(*next),
                                                      redis_entry_bytes(*next), head};
            _batch->put(column_family::data,
                        rk + std::string(persistent_kv_detail::k_header_suffix), h.encode());
        }
        _overlay[key] = loaded{std::move(next), head};
    }

    auto erase(const std::string& key) -> bool {
        const auto old = load(key);
        if (!old.entry) {
            return false;
        }
        uncount(key, *old.entry, *_staged);
        erase_rows(key, old);
        _overlay[key] = loaded{};
        return true;
    }

    auto erase_rows(const std::string& key, const loaded& old) -> void {
        const auto rk = row_key(key, escaped());
        if (redis_entry_type(*old.entry) == redis_value_type::string) {
            _batch->erase(column_family::data, rk);
            return;
        }
        _batch->erase(column_family::data, rk + std::string(persistent_kv_detail::k_header_suffix));
        _batch->erase_range(column_family::data,
                            key_range{rk + std::string(persistent_kv_detail::k_member_suffix),
                                      rk + std::string(persistent_kv_detail::k_elements_end)});
    }

    static auto uncount(const std::string& key, const redis_kv_value_entry& e,
                        persistent_kv_detail::meta_record& m) -> void {
        m.keys -= 1;
        m.bytes -= key.size() + redis_entry_bytes(e);
        m.expiring -= e._expire_at_ms != 0 ? 1 : 0;
    }

    [[nodiscard]] static auto collection_size(const redis_kv_value_entry& e) -> std::uint64_t {
        switch (redis_entry_type(e)) {
            case redis_value_type::hash:
                return e._hash ? e._hash->size() : 0;
            case redis_value_type::set:
                return e._set ? e._set->size() : 0;
            case redis_value_type::list:
                return e._list ? e._list->size() : 0;
            case redis_value_type::string:
                break;
        }
        return 0;
    }

    /// Merges two sorted element sequences, calling `put(e)` for each new or
    /// changed element of `next` and `erase(key)` for each key only in
    /// `old`.
    template<typename Entry, typename Put, typename Erase>
    static auto diff_sorted(const std::vector<const Entry*>& old,
                            const std::vector<const Entry*>& next, Put&& put, Erase&& erase)
        -> void {
        using traits = redis_value_detail::element_traits<Entry>;
        std::size_t i = 0;
        std::size_t j = 0;
        while (i < old.size() || j < next.size()) {
            if (j == next.size() ||
                (i < old.size() && traits::key(*old[i]) < traits::key(*next[j]))) {
                erase(traits::key(*old[i]));
                ++i;
            } else if (i == old.size() || traits::key(*next[j]) < traits::key(*old[i])) {
                put(*next[j]);
                ++j;
            } else {
                if (!(*old[i] == *next[j])) {
                    put(*next[j]);
                }
                ++i;
                ++j;
            }
        }
    }

    template<typename Collection>
    [[nodiscard]] static auto entries_of(const Collection* c)
        -> std::vector<const typename Collection::entry*> {
        std::vector<const typename Collection::entry*> out;
        if (c != nullptr) {
            out.reserve(c->size());
            c->for_each_entry([&](const typename Collection::entry& e) { out.push_back(&e); });
        }
        return out;
    }

    auto write_hash(const std::string& rk, const redis_hash* old, const redis_hash& next) -> void {
        if (old == &next) {
            return;
        }
        const auto prefix = rk + std::string(persistent_kv_detail::k_member_suffix);
        diff_sorted<redis_hash::entry>(
            entries_of(old), entries_of(&next),
            [&](const redis_hash::entry& e) {
                _batch->put(column_family::data, prefix + e.first, e.second);
            },
            [&](std::string_view field) {
                _batch->erase(column_family::data, prefix + std::string(field));
            });
    }

    auto write_set(const std::string& rk, const redis_set* old, const redis_set& next) -> void {
        if (old == &next) {
            return;
        }
        const auto prefix = rk + std::string(persistent_kv_detail::k_member_suffix);
        diff_sorted<redis_set::entry>(
            entries_of(old), entries_of(&next),
            [&](const std::string& member) {
                _batch->put(column_family::data, prefix + member, std::string{});
            },
            [&](std::string_view member) {
                _batch->erase(column_family::data, prefix + std::string(member));
            });
    }

    /// Writes `next` over `old` (whose first seq is `old_head`) and returns
    /// `next`'s first seq. The new seqs are anchored either at the old head
    /// or at the old tail, whichever rewrites fewer rows: a push or pop at
    /// either end, an `LSET` or an `LTRIM` writes O(1) rows, and an insert
    /// or removal in the middle shifts the shorter side.
    auto write_list(const std::string& rk, const redis_list* old, std::uint64_t old_head,
                    const redis_list& next) -> std::uint64_t {
        if (old == &next) {
            return old_head;
        }
        std::vector<const std::string*> before;
        std::vector<const std::string*> after;
        if (old != nullptr) {
            before.reserve(old->size());
            old->visit(0, old->size() - 1, [&](std::size_t, const std::string& v) {
                before.push_back(&v);
                return true;
            });
        }
        after.reserve(next.size());
        next.visit(0, next.size() - 1, [&](std::size_t, const std::string& v) {
            after.push_back(&v);
            return true;
        });
        const auto n0 = before.size();
        const auto n1 = after.size();
        // Rows to write when element i of `after` lands on the seq where
        // element i + shift of `before` was.
        const auto writes = [&](std::ptrdiff_t shift) {
            std::size_t w = 0;
            for (std::size_t i = 0; i < n1; ++i) {
                const auto at = static_cast<std::ptrdiff_t>(i) + shift;
                if (at < 0 || at >= static_cast<std::ptrdiff_t>(n0) ||
                    *before[static_cast<std::size_t>(at)] != *after[i]) {
                    ++w;
                }
            }
            return w;
        };
        std::uint64_t head = persistent_kv_detail::k_list_origin;
        std::ptrdiff_t shift = 0;
        if (old != nullptr) {
            // Anchored at the head: shift 0. At the tail: the last elements
            // line up.
            const auto tail_shift =
                static_cast<std::ptrdiff_t>(n0) - static_cast<std::ptrdiff_t>(n1);
            shift = writes(tail_shift) < writes(0) ? tail_shift : 0;
            head = old_head + static_cast<std::uint64_t>(shift);
        }
        const auto prefix = rk + std::string(persistent_kv_detail::k_list_suffix);
        for (std::size_t i = 0; i < n1; ++i) {
            const auto at = static_cast<std::ptrdiff_t>(i) + shift;
            if (old == nullptr || at < 0 || at >= static_cast<std::ptrdiff_t>(n0) ||
                *before[static_cast<std::size_t>(at)] != *after[i]) {
                _batch->put(column_family::data, prefix + persistent_kv_detail::list_seq(head + i),
                            *after[i]);
            }
        }
        if (old != nullptr) {
            // Old seqs outside [head, head + n1).
            const auto old_end = old_head + n0;
            const auto new_end = head + n1;
            if (old_head < head) {
                _batch->erase_range(
                    column_family::data,
                    key_range{prefix + persistent_kv_detail::list_seq(old_head),
                              prefix + persistent_kv_detail::list_seq(std::min(head, old_end))});
            }
            if (old_end > new_end) {
                _batch->erase_range(
                    column_family::data,
                    key_range{prefix + persistent_kv_detail::list_seq(std::max(new_end, old_head)),
                              prefix + persistent_kv_detail::list_seq(old_end)});
            }
        }
        return head;
    }

    /// The raw (unescaped) rows of `range` whose key contains `0x00`, with
    /// the namespace stripped. Only strings exist before the gate.
    [[nodiscard]] auto raw_nul_keys(const key_range& range) const
        -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> found;
        _engine->scan(column_family::data, to_engine(range), scan_direction::forward,
                      [&](std::string_view key, std::string_view stored) {
                          const auto user = key.substr(_ns.size());
                          if (persistent_kv_detail::has_nul(user)) {
                              found.emplace_back(std::string(user), std::string(stored));
                          }
                          return true;
                      });
        return found;
    }

    /// Moves each key of `moving` from its raw row to its escaped one, with
    /// its value (a null entry: the key is gone). Every erase goes before any
    /// put, since one key's escaped form can be another key's raw form
    /// (`"a\0"` escapes to the raw `"a\0\xFF"`), and that other key, having
    /// a NUL byte too, is in `moving` as well.
    auto write_escaped(const std::map<std::string, entry_handle, std::less<>>& moving,
                       write_batch& batch) const -> void {
        for (const auto& [key, entry] : moving) {
            batch.erase(column_family::data, _ns + key);
        }
        for (const auto& [key, entry] : moving) {
            if (entry) {
                batch.put(column_family::data, _ns + persistent_kv_detail::escape_key(key),
                          persistent_kv_detail::encode_value(entry->_expire_at_ms, entry->_value));
            }
        }
    }

    [[nodiscard]] auto bounds_have_nul() const -> bool {
        return persistent_kv_detail::has_nul(_range.start) ||
               (_range.end && persistent_kv_detail::has_nul(*_range.end));
    }

    // ---- the decoded-collection cache --------------------------------------

    auto remember(const std::string& key, loaded l) -> void {
        if (const auto it = _cache.find(key); it != _cache.end()) {
            _cache_bytes -= redis_entry_bytes(*it->second.entry);
            _cache.erase(it);
        }
        if (!l.entry || redis_entry_type(*l.entry) == redis_value_type::string) {
            return;
        }
        const auto size = redis_entry_bytes(*l.entry);
        if (size > k_cache_bytes) {
            return;
        }
        if (_cache_bytes + size > k_cache_bytes) {
            clear_cache();
        }
        _cache_bytes += size;
        _cache.emplace(key, std::move(l));
    }

    auto clear_cache() -> void {
        _cache.clear();
        _cache_bytes = 0;
    }

    // ---- scans ---------------------------------------------------------------

    /// The deadline of a string or header row.
    [[nodiscard]] static auto row_expiry(const persistent_kv_detail::parsed_row& row,
                                         std::string_view stored) -> std::uint64_t {
        return row.kind == persistent_kv_detail::row_kind::string
                   ? persistent_kv_detail::value_expiry(stored)
                   : persistent_kv_detail::collection_header::decode(stored).expire_at_ms;
    }

    /// The bytes a string or header row's key counts for.
    [[nodiscard]] static auto row_bytes(const persistent_kv_detail::parsed_row& row,
                                        std::string_view stored) -> std::uint64_t {
        return row.key.size() +
               (row.kind == persistent_kv_detail::row_kind::string
                    ? persistent_kv_detail::value_size(stored)
                    : persistent_kv_detail::collection_header::decode(stored).bytes);
    }

    /// Visits one row per user key (its string or header row) of `range`, in
    /// key order, skipping element rows.
    template<typename F>
    auto for_each_user_row(const key_range& range, bool esc, F&& f) const -> void {
        _engine->scan(column_family::data, to_engine(range), scan_direction::forward,
                      [&](std::string_view key, std::string_view stored) {
                          const auto row =
                              persistent_kv_detail::parse_row(key.substr(_ns.size()), esc);
                          if (row.kind == persistent_kv_detail::row_kind::element) {
                              return true;
                          }
                          return f(row, stored);
                      });
    }

    template<typename F> auto for_each_user_row(F&& f) const -> void {
        require_open();
        for_each_user_row(_range, _meta.level >= k_redis_typed_values_level, std::forward<F>(f));
    }

    auto commit(const write_batch& batch, const persistent_kv_detail::meta_record& next) -> void {
        const auto seq = _engine->write(batch);
        _meta = next;
        _seqs.emplace_back(static_cast<LogIndex>(next.applied), seq);
    }

    /// The applied index, level and command time a split child carries.
    static auto carry_header(persistent_kv_detail::meta_record& m,
                             const persistent_kv_detail::meta_record& from) -> void {
        m.applied = from.applied;
        m.level = from.level;
        m.applied_time = from.applied_time;
    }

    /// Counts the keys, bytes and deadlines of a shard-key range.
    [[nodiscard]] auto count(const key_range& range, bool esc) const
        -> persistent_kv_detail::meta_record {
        persistent_kv_detail::meta_record m;
        for_each_user_row(
            range, esc, [&](const persistent_kv_detail::parsed_row& row, std::string_view stored) {
                m.keys += 1;
                m.bytes += row_bytes(row, stored);
                m.expiring += row_expiry(row, stored) != 0 ? 1 : 0;
                return true;
            });
        return m;
    }

    [[nodiscard]] auto to_engine(const key_range& range) const -> key_range {
        return key_range{_ns + range.start, range.end.has_value()
                                                ? std::optional<std::string>(_ns + *range.end)
                                                : persistent_kv_detail::prefix_successor(_ns)};
    }

    [[nodiscard]] auto engine_range() const -> key_range { return to_engine(_range); }
    [[nodiscard]] auto meta_key() const -> std::string { return _ns + _range.start; }

    auto require_open() const -> void {
        if (_engine == nullptr) {
            throw std::logic_error("persistent_kv_state_machine: used before open()");
        }
    }

    std::string _ns;
    engine_type* _engine = nullptr;
    key_range _range;
    persistent_kv_detail::meta_record _meta;
    mutable LogIndex _durable_floor{};
    /// (applied index, engine sequence) of each batch not yet known durable.
    mutable std::deque<std::pair<LogIndex, engine_sequence>> _seqs;
    /// Keys this entry has already written (a null entry = erased), so later
    /// commands of the same entry read them; cleared at commit.
    std::map<std::string, loaded, std::less<>> _overlay;
    /// The counters, level and command time as the entry being staged has
    /// left them; empty between entries.
    std::optional<persistent_kv_detail::meta_record> _staged;
    /// The batch `stage` is filling, for `enable_format`; null outside it.
    write_batch* _batch = nullptr;
    /// Committed collections, decoded (see the file comment).
    std::map<std::string, loaded, std::less<>> _cache;
    std::size_t _cache_bytes = 0;
};

}  // namespace kythira
