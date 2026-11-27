// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_kv_mvcc_state_machine.hpp
/// @brief The multi-version Redis KV of `.kiro/specs/multi-raft-transactions/`
///        tier 2 (task 11, Requirement 8.1).
///
/// `redis_kv_state_machine` keeps one value per key. This variant keeps every
/// version a snapshot read might still need: per key, a list of
/// `(commit_ts, value)` sorted newest first, where a deletion is a tombstone
/// version. A read at timestamp `ts` takes the newest version at or below
/// `ts`. The commands are the same `redis_kv_command`s, so the gateway
/// proposes exactly what it proposes today; what changes is that each one is
/// applied at a commit timestamp.
///
/// The rules `redis_kv_state_machine` follows hold here too: `apply` and
/// `apply_at` are pure functions of their arguments, and values are shared,
/// never copied out under the node's lock.
///
/// **Timestamps.** Under `mvcc::on` (task 12) the transactional wrapper calls
/// `apply_at` with the commit timestamp the oracle gave the writing
/// transaction; a plain write is a one-phase transaction with its own.
/// `apply` without a timestamp is kept for the `state_machine` concept and
/// for an unwrapped host: it applies at the newest timestamp this shard has
/// applied, so its write is ordered after everything already applied and
/// replaces a version written at that same timestamp.
///
/// **Expiry.** A sweep deletes a key by writing a tombstone at the sweep's
/// commit timestamp, if the key's newest version still carries the deadline
/// the sweep was built from. A snapshot older than the sweep still sees the
/// value: expiry is a write like any other.
///
/// **Garbage.** `collect_garbage(sp)` keeps, per key, every version above
/// `sp` and the newest one at or below it, so any read at or above `sp`
/// is unchanged. A key whose only remaining version is a tombstone at or
/// below `sp` is dropped altogether, since every such read finds nothing
/// either way. Reads below the safe point are refused before they get here
/// (`snapshot_too_old`, task 13).
///
/// **Typed values** (.kiro/specs/redis-general-data-types/ task 11,
/// Requirement 13.5). After the group's format gate, format-0x03 `exec`
/// records apply here as in `redis_kv_state_machine`, through the same
/// appliers, each at its commit timestamp: a write reads the newest version
/// at or below it and writes a new version there. A collection's new value
/// is built from the old one's chunks (redis_value.hpp), so one element
/// write adds one chunk and the chunk vector, not a copy of the collection;
/// the versions share every chunk the write did not touch. `collect_garbage`
/// drops versions, and a chunk is freed with the last version that holds
/// it. Snapshots of a gated group start with `KMV3`, its level and its
/// applied command time, and carry collections as their own version kind.

#include <raft/multi_version_state_machine.hpp>
#include <kythira/redis/redis_format_level.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_exec_appliers.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_typed_read.hpp>
#include <raft/shard_types.hpp>
#include <raft/splittable_state_machine.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira {

template<typename LogIndex = std::uint64_t>
requires log_index<LogIndex>
class redis_kv_mvcc_state_machine {
public:
    using key_type = std::string;
    using entry_handle = std::shared_ptr<const redis_kv_value_entry>;

    /// One version. A null `_entry` is a deletion.
    struct version {
        std::uint64_t _commit_ts{0};
        entry_handle _entry;
    };
    /// Newest first.
    using version_list = std::vector<version>;
    using store_type = std::map<key_type, version_list, std::less<>>;

    redis_kv_mvcc_state_machine() = default;

    // ---- kythira::state_machine -------------------------------------------

    /// Apply at the newest timestamp this shard has applied (see the file
    /// comment). One status byte, as `redis_kv_state_machine` returns.
    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        _last_applied_index = index;
        return apply_at(command, _max_commit_ts);
    }

    /// The whole store: `u64 BE` newest commit timestamp, `u32 BE` key
    /// count, then per key in key order `u32 BE keylen, key, u32 BE version
    /// count`, and per version, newest first, `u64 BE commit_ts, u8 kind`
    /// (0 = deletion, 1 = value) and for a value `u64 BE expire_at_ms,
    /// u32 BE len, value`. Every `split_state` blob has this format too.
    ///
    /// Once the group has passed a format gate the blob starts with `KMV3`,
    /// `u16 BE` level and `u64 BE` applied command time, and a collection is
    /// version kind 2: `u64 BE expire_at_ms, u8 type`, then its body
    /// (`redis_kv_detail::put_collection_body`). A blob without the marker
    /// is the earlier format, byte for byte.
    [[nodiscard]] auto get_state() const -> std::vector<std::byte> {
        return serialize_store(_store.begin(), _store.end(), _store.size(), _max_commit_ts,
                               header());
    }

    auto restore_from_snapshot(const std::vector<std::byte>& snapshot_data, LogIndex index)
        -> void {
        store_type incoming;
        std::uint64_t max_ts = 0;
        const auto head = deserialize_store(snapshot_data, incoming, max_ts);
        _store = std::move(incoming);
        _max_commit_ts = max_ts;
        _format_level = head._format_level;
        _applied_time_ms = head._applied_time_ms;
        recount();
        _last_applied_index = index;
    }

    [[nodiscard]] auto last_applied_index() const noexcept -> LogIndex {
        return _last_applied_index;
    }

    // ---- kythira::multi_version_state_machine ------------------------------

    /// Apply `command` as committed at `commit_ts`. Returns `{1}` when it
    /// changed what some read would see, `{0}` otherwise.
    auto apply_at(const std::vector<std::byte>& command, std::uint64_t commit_ts)
        -> std::vector<std::byte> {
        // A record from a newer format halts the group rather than being
        // skipped (redis-general-data-types Requirement 14.4).
        require_redis_record_level(command);
        if (is_redis_kv_v3_record(command)) {
            auto reply = apply_v3(decode_redis_kv_v3_command(command), commit_ts);
            _max_commit_ts = std::max(_max_commit_ts, commit_ts);
            return reply;
        }
        auto decoded = decode_redis_kv_command(command);
        const bool changed =
            std::visit([this, commit_ts](auto& c) { return apply_one(c, commit_ts); }, decoded);
        _max_commit_ts = std::max(_max_commit_ts, commit_ts);
        return {changed ? std::byte{1} : std::byte{0}};
    }

    /// `apply_at` that also records the log index, for a wrapper that
    /// applies through it.
    auto apply_at(const std::vector<std::byte>& command, std::uint64_t commit_ts, LogIndex index)
        -> std::vector<std::byte> {
        _last_applied_index = index;
        return apply_at(command, commit_ts);
    }

    /// The value the newest version at or below `ts` holds; null if that
    /// version is a deletion or there is none.
    [[nodiscard]] auto read_at(std::string_view key, std::uint64_t ts) const -> entry_handle {
        auto it = _store.find(key);
        if (it == _store.end()) {
            return nullptr;
        }
        for (const auto& v : it->second) {
            if (v._commit_ts <= ts) {
                return v._entry;
            }
        }
        return nullptr;
    }

    /// The newest version's timestamp, deletions included.
    [[nodiscard]] auto latest_commit_ts(std::string_view key) const
        -> std::optional<std::uint64_t> {
        auto it = _store.find(key);
        if (it == _store.end() || it->second.empty()) {
            return std::nullopt;
        }
        return it->second.front()._commit_ts;
    }

    /// Drop the versions no read at or above `safe_point` can see. Returns
    /// how many versions went.
    auto collect_garbage(std::uint64_t safe_point) -> std::size_t {
        std::size_t dropped = 0;
        for (auto it = _store.begin(); it != _store.end();) {
            auto& versions = it->second;
            // The first version at or below the safe point is kept; every
            // one after it (older) goes.
            auto keep = std::find_if(versions.begin(), versions.end(), [safe_point](const auto& v) {
                return v._commit_ts <= safe_point;
            });
            if (keep != versions.end()) {
                for (auto old = std::next(keep); old != versions.end(); ++old) {
                    uncount(it->first, *old);
                    ++dropped;
                }
                versions.erase(std::next(keep), versions.end());
                if (keep == versions.begin() && !keep->_entry) {
                    // Only a deletion at or below the safe point is left.
                    uncount(it->first, *keep);
                    ++dropped;
                    versions.erase(keep);
                }
            }
            if (versions.empty()) {
                it = _store.erase(it);
            } else {
                ++it;
            }
        }
        return dropped;
    }

    /// The newest commit timestamp applied, by any command.
    [[nodiscard]] auto max_commit_ts() const noexcept -> std::uint64_t { return _max_commit_ts; }

    /// Versions held, deletions included.
    [[nodiscard]] auto version_count() const noexcept -> std::size_t { return _versions; }

    /// Every version of `key`, newest first, for tests and diagnostics.
    [[nodiscard]] auto versions_of(std::string_view key) const -> version_list {
        auto it = _store.find(key);
        return it == _store.end() ? version_list{} : it->second;
    }

    // ---- kythira::splittable_state_machine ---------------------------------

    /// Keys plus every version's value: what the shard holds, old versions
    /// included, since that is what a split would move.
    [[nodiscard]] auto approximate_size_bytes() const noexcept -> std::size_t { return _bytes; }
    /// Keys whose newest version is a value.
    [[nodiscard]] auto approximate_key_count() const noexcept -> std::size_t { return _live; }
    /// Live keys whose newest value carries a deadline.
    [[nodiscard]] auto expiring_key_count() const noexcept -> std::size_t { return _expiring; }

    /// Evenly spaced by key count, never the first key, as
    /// `redis_kv_state_machine` does.
    [[nodiscard]] auto suggest_split_keys(std::size_t max) -> std::vector<key_type> {
        std::vector<key_type> out;
        if (max == 0 || _store.size() < 2) {
            return out;
        }
        const std::size_t wanted = std::min(max, _store.size() - 1);
        const std::size_t stride = _store.size() / (wanted + 1);
        if (stride == 0) {
            return out;
        }
        std::size_t index = 0;
        std::size_t taken = 0;
        for (const auto& [key, versions] : _store) {
            ++index;
            if (taken < wanted && index % stride == 0 && index < _store.size()) {
                out.push_back(key);
                ++taken;
            }
        }
        return out;
    }

    /// Always true: a key's versions travel with it, so no cut separates
    /// anything that belongs together.
    [[nodiscard]] auto can_split_at([[maybe_unused]] const key_type& key) const -> bool {
        return true;
    }

    /// `keys.size() + 1` blobs in key order, each in `get_state()`'s format
    /// and each carrying this shard's newest commit timestamp.
    [[nodiscard]] auto split_state(const std::vector<key_type>& keys)
        -> std::vector<std::vector<std::byte>> {
        std::vector<key_type> cuts = keys;
        std::sort(cuts.begin(), cuts.end());
        cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());

        std::vector<std::vector<std::byte>> out;
        out.reserve(cuts.size() + 1);
        auto it = _store.begin();
        for (const auto& cut : cuts) {
            auto begin = it;
            std::size_t n = 0;
            while (it != _store.end() && it->first < cut) {
                ++it;
                ++n;
            }
            out.push_back(serialize_store(begin, it, n, _max_commit_ts, header()));
        }
        const auto n = static_cast<std::size_t>(std::distance(it, _store.end()));
        out.push_back(serialize_store(it, _store.end(), n, _max_commit_ts, header()));
        return out;
    }

    /// Take on a sibling's state. Incoming keys win on a collision, which
    /// cannot happen between siblings of one split. The newest commit
    /// timestamp is the larger of the two.
    auto absorb(const std::vector<std::byte>& other_state,
                [[maybe_unused]] const shard_range<key_type>& range) -> void {
        store_type incoming;
        std::uint64_t max_ts = 0;
        const auto head = deserialize_store(other_state, incoming, max_ts);
        for (auto& [key, versions] : incoming) {
            _store[key] = std::move(versions);
        }
        _max_commit_ts = std::max(_max_commit_ts, max_ts);
        enable_format(head._format_level);
        advance_command_time(head._applied_time_ms);
        recount();
    }

    // ---- read path, as redis_kv_state_machine's ------------------------------

    /// The newest value; null if the key is absent or deleted.
    [[nodiscard]] auto lookup(std::string_view key) const -> entry_handle {
        auto it = _store.find(key);
        return it == _store.end() || it->second.empty() ? nullptr : it->second.front()._entry;
    }

    /// Live keys whose newest value's deadline is non-zero and `<= now_ms`,
    /// at most `max`. The leader builds a sweep from it.
    [[nodiscard]] auto collect_expired(std::uint64_t now_ms, std::size_t max) const
        -> std::vector<redis_kv_sweep_entry> {
        std::vector<redis_kv_sweep_entry> out;
        for (const auto& [key, versions] : _store) {
            if (out.size() >= max) {
                break;
            }
            const auto& e = versions.front()._entry;
            if (e && e->_expire_at_ms != 0 && e->_expire_at_ms <= now_ms) {
                out.push_back({key, e->_expire_at_ms});
            }
        }
        return out;
    }

    /// Every live key in order, with its newest value.
    template<typename F> auto for_each_key(F&& f) const -> void {
        for (const auto& [key, versions] : _store) {
            if (const auto& e = versions.front()._entry) {
                f(key, *e);
            }
        }
    }

    /// The reply to a read of `key`'s newest value at the serving node's
    /// time `now_ms`, as `redis_kv_state_machine::evaluate_read`.
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

    // ---- command time and format level (redis-general-data-types) ---------

    /// As in `redis_kv_state_machine`: `max(entry_now_ms, applied time)`,
    /// which becomes the new applied time (Requirement 2.2-2.3).
    auto advance_command_time(std::uint64_t entry_now_ms) noexcept -> std::uint64_t {
        _applied_time_ms = std::max(_applied_time_ms, entry_now_ms);
        return _applied_time_ms;
    }

    [[nodiscard]] auto applied_time_ms() const noexcept -> std::uint64_t {
        return _applied_time_ms;
    }

    /// The format level the group has passed a gate for; 0 before any.
    [[nodiscard]] auto format_level() const noexcept -> std::uint16_t { return _format_level; }

    /// Raises the group's level (one way), for `apply_redis_v3_common`.
    auto enable_format(std::uint16_t level) noexcept -> void {
        _format_level = std::max(_format_level, level);
    }

    // ---- codec, public so tests can check the split/absorb law -------------

    /// The level and command time a gated blob starts with.
    struct state_header {
        std::uint16_t _format_level = 0;
        std::uint64_t _applied_time_ms = 0;
    };

    template<typename It>
    [[nodiscard]] static auto serialize_store(It begin, It end, std::size_t count,
                                              std::uint64_t max_ts, state_header head = {})
        -> std::vector<std::byte> {
        std::vector<std::byte> out;
        if (head._format_level > 0) {
            redis_kv_detail::put_bytes(out, k_state_marker);
            redis_kv_detail::put_u16(out, head._format_level);
            redis_kv_detail::put_u64(out, head._applied_time_ms);
        }
        redis_kv_detail::put_u64(out, max_ts);
        redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(count));
        for (auto it = begin; it != end; ++it) {
            const auto& [key, versions] = *it;
            redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(key.size()));
            redis_kv_detail::put_string(out, key);
            redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(versions.size()));
            for (const auto& v : versions) {
                redis_kv_detail::put_u64(out, v._commit_ts);
                if (!v._entry) {
                    out.push_back(std::byte{0});
                } else if (redis_entry_type(*v._entry) == redis_value_type::string) {
                    out.push_back(std::byte{1});
                    redis_kv_detail::put_u64(out, v._entry->_expire_at_ms);
                    redis_kv_detail::put_u32(out,
                                             static_cast<std::uint32_t>(v._entry->_value.size()));
                    redis_kv_detail::put_bytes(out, v._entry->_value);
                } else {
                    if (head._format_level < k_redis_typed_values_level) {
                        throw redis_kv_codec_error(
                            "a typed value in a state blob without a format level");
                    }
                    out.push_back(std::byte{2});
                    redis_kv_detail::put_u64(out, v._entry->_expire_at_ms);
                    out.push_back(static_cast<std::byte>(v._entry->_type));
                    redis_kv_detail::put_collection_body(out, *v._entry);
                }
            }
        }
        return out;
    }

    /// Reads both formats. An earlier blob starts with its `u64 BE` newest
    /// commit timestamp; `KMV3` read as one is above 5.4e18, which no
    /// oracle timestamp reaches, so the marker cannot be mistaken for one.
    static auto deserialize_store(const std::vector<std::byte>& blob, store_type& into,
                                  std::uint64_t& max_ts) -> state_header {
        redis_kv_detail::reader in(blob);
        state_header head;
        if (blob.size() >= k_state_marker.size() &&
            std::equal(k_state_marker.begin(), k_state_marker.end(), blob.begin())) {
            (void)in.bytes(k_state_marker.size());
            head._format_level = in.u16();
            head._applied_time_ms = in.u64();
            if (head._format_level == 0) {
                throw redis_kv_codec_error("redis kv mvcc state marker with format level 0");
            }
            if (head._format_level > k_redis_format_level) {
                throw redis_format_too_new(head._format_level);
            }
        }
        max_ts = in.u64();
        auto count = in.u32();
        for (std::uint32_t i = 0; i < count; ++i) {
            auto key = in.string(in.u32());
            const auto n = in.u32();
            version_list versions;
            versions.reserve(std::min<std::size_t>(n, in.remaining() / 9));
            for (std::uint32_t j = 0; j < n; ++j) {
                version v;
                v._commit_ts = in.u64();
                const auto kind = in.u8();
                if (kind > 2 || (kind == 2 && head._format_level < k_redis_typed_values_level)) {
                    throw redis_kv_codec_error("unknown version kind in redis kv mvcc state");
                }
                if (kind == 1) {
                    auto entry = std::make_shared<redis_kv_value_entry>();
                    entry->_expire_at_ms = in.u64();
                    auto bytes = in.bytes(in.u32());
                    entry->_value.assign(bytes.begin(), bytes.end());
                    v._entry = std::move(entry);
                } else if (kind == 2) {
                    auto entry = std::make_shared<redis_kv_value_entry>();
                    entry->_expire_at_ms = in.u64();
                    redis_kv_detail::read_collection_body(in, in.u8(), *entry);
                    v._entry = std::move(entry);
                }
                if (!versions.empty() && versions.back()._commit_ts <= v._commit_ts) {
                    throw redis_kv_codec_error("redis kv mvcc versions out of order");
                }
                versions.push_back(std::move(v));
            }
            if (!versions.empty()) {
                into[std::move(key)] = std::move(versions);
            }
        }
        if (in.remaining() != 0) {
            throw redis_kv_codec_error("trailing bytes after redis kv mvcc state blob");
        }
        return head;
    }

private:
    static constexpr std::array<std::byte, 4> k_state_marker{std::byte{'K'}, std::byte{'M'},
                                                             std::byte{'V'}, std::byte{'3'}};

    [[nodiscard]] auto header() const noexcept -> state_header {
        return {_format_level, _applied_time_ms};
    }

    /// A format-0x03 record at `ts`: the gate and the refusal before it are
    /// shared with every store; an `exec` runs the appliers.
    auto apply_v3(const redis_kv_v3_command& record, std::uint64_t ts) -> std::vector<std::byte> {
        if (auto status = apply_redis_v3_common(*this, record)) {
            return redis_v3_apply_result(*status);
        }
        if (const auto* exec = std::get_if<redis_kv_exec_command>(&record)) {
            return apply_exec(*exec, ts);
        }
        return redis_v3_apply_result(redis_v3_apply_status::unchanged);
    }

    /// An `exec` record committed at `ts`: each key reads its version at or
    /// below `ts` (its own earlier writes in this record included, since they
    /// are versions at `ts`) and writes a version at `ts`.
    auto apply_exec(const redis_kv_exec_command& c, std::uint64_t ts) -> std::vector<std::byte> {
        const auto t = advance_command_time(c._now_ms);
        struct store_ops {
            redis_kv_mvcc_state_machine& _sm;
            std::uint64_t _ts;
            [[nodiscard]] auto find(const key_type& key) const -> entry_handle {
                return _sm.read_at(key, _ts);
            }
            auto put(const key_type& key, std::vector<std::byte> value, std::uint64_t expire_at_ms)
                -> void {
                auto entry = std::make_shared<redis_kv_value_entry>();
                entry->_value = std::move(value);
                entry->_expire_at_ms = expire_at_ms;
                _sm.put_version(key, _ts, std::move(entry));
            }
            auto put_entry(const key_type& key, entry_handle entry) -> void {
                _sm.put_version(key, _ts, std::move(entry));
            }
            auto erase(const key_type& key) -> bool { return _sm.delete_at(key, _ts); }
        } ops{*this, ts};
        auto reply = apply_redis_exec(ops, c, t);
        if (!reply) {
            throw redis_unknown_command_id(c._command_id);
        }
        return encode_redis_reply(*reply);
    }

    auto apply_one(redis_kv_set_command& c, std::uint64_t ts) -> bool {
        auto entry = std::make_shared<redis_kv_value_entry>();
        entry->_value = std::move(c._value);
        entry->_expire_at_ms = c._expire_at_ms;
        put_version(c._key, ts, std::move(entry));
        return true;
    }

    auto apply_one(const redis_kv_del_command& c, std::uint64_t ts) -> bool {
        return delete_at(c._key, ts);
    }

    /// Delete each key whose newest value still carries the sweep's
    /// deadline: a SET between the sweep's proposal and its apply replaced
    /// the deadline and survives.
    auto apply_one(const redis_kv_sweep_command& c, std::uint64_t ts) -> bool {
        bool changed = false;
        for (const auto& e : c._entries) {
            const auto current = lookup(e._key);
            if (current && e._expire_at_ms != 0 && current->_expire_at_ms == e._expire_at_ms) {
                changed = delete_at(e._key, ts) || changed;
            }
        }
        return changed;
    }

    auto apply_one(const redis_kv_evict_command& c, std::uint64_t ts) -> bool {
        bool changed = false;
        for (const auto& k : c._keys) {
            changed = delete_at(k, ts) || changed;
        }
        return changed;
    }

    /// The disk-backed store's records: no-ops, as in
    /// `redis_kv_state_machine`.
    auto apply_one(const redis_kv_put_chunk_command&, std::uint64_t) -> bool { return false; }
    auto apply_one(const redis_kv_commit_command&, std::uint64_t) -> bool { return false; }
    auto apply_one(const redis_kv_touch_command&, std::uint64_t) -> bool { return false; }

    /// A tombstone at `ts`, if the key is live there.
    auto delete_at(const key_type& key, std::uint64_t ts) -> bool {
        if (!read_at(key, ts)) {
            return false;
        }
        put_version(key, ts, nullptr);
        return true;
    }

    /// Insert a version in timestamp order, replacing one at the same
    /// timestamp.
    auto put_version(const key_type& key, std::uint64_t ts, entry_handle entry) -> void {
        auto& versions = _store[key];
        const bool was_live = !versions.empty() && versions.front()._entry;
        const bool was_expiring = was_live && versions.front()._entry->_expire_at_ms != 0;

        auto pos = std::find_if(versions.begin(), versions.end(),
                                [ts](const auto& v) { return v._commit_ts <= ts; });
        if (pos != versions.end() && pos->_commit_ts == ts) {
            uncount(key, *pos);
            pos->_entry = std::move(entry);
            count(key, *pos);
        } else {
            pos = versions.insert(pos, version{._commit_ts = ts, ._entry = std::move(entry)});
            count(key, *pos);
        }

        const bool is_live = versions.front()._entry != nullptr;
        const bool is_expiring = is_live && versions.front()._entry->_expire_at_ms != 0;
        _live = _live - (was_live ? 1 : 0) + (is_live ? 1 : 0);
        _expiring = _expiring - (was_expiring ? 1 : 0) + (is_expiring ? 1 : 0);
    }

    /// A version counts its key and its value's bytes. Versions that share
    /// a collection's chunks each count the whole collection: the size is
    /// what a split would move, and a split writes every version out.
    auto count(const key_type& key, const version& v) -> void {
        _bytes += key.size() + (v._entry ? redis_entry_bytes(*v._entry) : 0);
        ++_versions;
    }

    auto uncount(const key_type& key, const version& v) -> void {
        _bytes -= key.size() + (v._entry ? redis_entry_bytes(*v._entry) : 0);
        --_versions;
    }

    /// Rebuild every counter from the store, after a restore or an absorb.
    auto recount() -> void {
        _bytes = 0;
        _versions = 0;
        _live = 0;
        _expiring = 0;
        for (const auto& [key, versions] : _store) {
            for (const auto& v : versions) {
                count(key, v);
            }
            if (!versions.empty() && versions.front()._entry) {
                ++_live;
                _expiring += versions.front()._entry->_expire_at_ms != 0 ? 1 : 0;
            }
        }
    }

    // `collect_garbage` drops a key's newest version only when it is a
    // deletion, so it never changes `_live` or `_expiring`.
    store_type _store;
    std::uint64_t _max_commit_ts{0};
    std::size_t _bytes{0};
    std::size_t _versions{0};
    std::size_t _live{0};
    std::size_t _expiring{0};
    std::uint16_t _format_level{0};
    std::uint64_t _applied_time_ms{0};
    LogIndex _last_applied_index{};
};

static_assert(state_machine<redis_kv_mvcc_state_machine<std::uint64_t>, std::uint64_t>,
              "redis_kv_mvcc_state_machine must satisfy the state_machine concept");
static_assert(splittable_state_machine<redis_kv_mvcc_state_machine<std::uint64_t>, std::string>,
              "redis_kv_mvcc_state_machine must satisfy the splittable_state_machine concept");
static_assert(multi_version_state_machine<redis_kv_mvcc_state_machine<std::uint64_t>, std::string>,
              "redis_kv_mvcc_state_machine must satisfy the multi_version_state_machine concept");

}  // namespace kythira
