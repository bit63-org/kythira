// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_kv_state_machine.hpp
/// @brief The replicated data behind the Redis-compatible gateway
///        (.kiro/specs/redis-compatible-kv/ design Component 3).
///
/// One instance per shard. It satisfies both `kythira::state_machine` and
/// `kythira::splittable_state_machine<_, std::string>` so that `multi_raft`
/// can split and merge shards without knowing what a Redis value is.
///
/// Two rules shape everything here:
///
///  1. `apply()` is a pure function of the log. It never reads a clock, the
///     environment or a random source, because the same entry is applied on
///     every replica and any of those would let two replicas diverge. Expiry
///     is therefore an absolute `expire_at_ms` stamped by the leader before
///     the entry was proposed, and expired keys are removed by a `sweep`
///     entry the leader proposes, never by `apply` noticing a deadline.
///
///  2. Values are shared, never copied out under the node's lock. `lookup()`
///     returns a `shared_ptr<const value_entry>` so the gateway can take the
///     handle inside `node::with_state_machine` (which runs under the node
///     mutex) and write the bytes to the socket after the lock is released.
///     An 8 MiB compiler artefact copied under that mutex would stall every
///     AppendEntries for the shard.

#include <kythira/redis/redis_expiry_exec.hpp>
#include <kythira/redis/redis_format_level.hpp>
#include <kythira/redis/redis_hash_exec.hpp>
#include <kythira/redis/redis_exec_appliers.hpp>
#include <kythira/redis/redis_list_exec.hpp>
#include <kythira/redis/redis_set_exec.hpp>
#include <kythira/redis/redis_typed_read.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_multi_key_exec.hpp>
#include <kythira/redis/redis_string_exec.hpp>
#include <kythira/redis/redis_string_read.hpp>
#include <kythira/redis/redis_value.hpp>
#include <raft/shard_types.hpp>
#include <raft/splittable_state_machine.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira {

/// A stored value plus its deadline. Immutable once published: a SET that
/// replaces a key installs a fresh entry rather than mutating this one, so a
/// reader still holding the old handle keeps reading consistent bytes.
struct redis_kv_value_entry {
    /// A string's bytes; empty for a collection.
    std::vector<std::byte> _value;
    /// ms since the Unix epoch; 0 = never expires.
    std::uint64_t _expire_at_ms = 0;
    /// What the key holds (redis-general-data-types task 7). The in-memory
    /// and engine stores hold collections (the engine store decodes them
    /// from its rows, task 10); the multi-version store's entries are
    /// strings until task 11.
    redis_value_type _type = redis_value_type::string;
    /// The hash when `_type` is `hash`: shared, so a reader encodes it after
    /// the node lock is released (redis_value.hpp).
    std::shared_ptr<const redis_hash> _hash;
    /// The set when `_type` is `set` (task 8).
    std::shared_ptr<const redis_set> _set;
    /// The list when `_type` is `list` (task 9).
    std::shared_ptr<const redis_list> _list;
};

/// The bytes an entry counts for size accounting (key excluded).
[[nodiscard]] inline auto redis_entry_bytes(const redis_kv_value_entry& e) noexcept -> std::size_t {
    switch (e._type) {
        case redis_value_type::hash:
            return e._hash ? e._hash->bytes() : 0;
        case redis_value_type::set:
            return e._set ? e._set->bytes() : 0;
        case redis_value_type::list:
            return e._list ? e._list->bytes() : 0;
        default:
            return e._value.size();
    }
}

namespace redis_kv_detail {

/// A collection's body, as snapshots and transactional reads carry it:
/// `u32 BE n`, then each element as `u32 BE len, bytes` in the collection's
/// order (a hash's field, then its value). The type byte is the caller's.
inline auto put_collection_body(std::vector<std::byte>& out, const redis_kv_value_entry& e)
    -> void {
    const auto put_text = [&](const std::string& text) {
        put_u32(out, static_cast<std::uint32_t>(text.size()));
        put_string(out, text);
    };
    switch (e._type) {
        case redis_value_type::hash:
            put_u32(out, static_cast<std::uint32_t>(e._hash->size()));
            e._hash->for_each([&](const std::string& f, const std::string& v) {
                put_text(f);
                put_text(v);
            });
            break;
        case redis_value_type::set:
            put_u32(out, static_cast<std::uint32_t>(e._set->size()));
            e._set->for_each([&](const std::string& m) { put_text(m); });
            break;
        case redis_value_type::list:
            put_u32(out, static_cast<std::uint32_t>(e._list->size()));
            e._list->visit(0, e._list->size() - 1, [&](std::size_t, const std::string& v) {
                put_text(v);
                return true;
            });
            break;
        default:
            throw redis_kv_codec_error("a value type this build cannot store");
    }
}

/// Reads a body `put_collection_body` wrote for a collection of type `tag`
/// into `e`. Refuses an empty collection, and hash fields or set members out
/// of order (which also refuses duplicates).
inline auto read_collection_body(reader& in, std::uint8_t tag, redis_kv_value_entry& e) -> void {
    switch (static_cast<redis_value_type>(tag)) {
        case redis_value_type::hash: {
            const auto n = in.u32();
            std::vector<redis_hash::entry> fields;
            fields.reserve(std::min<std::size_t>(n, in.remaining() / 8));
            for (std::uint32_t j = 0; j < n; ++j) {
                auto f = in.string(in.u32());
                auto v = in.string(in.u32());
                if (!fields.empty() && fields.back().first >= f) {
                    throw redis_kv_codec_error("hash fields out of order in a state blob");
                }
                fields.emplace_back(std::move(f), std::move(v));
            }
            if (fields.empty()) {
                throw redis_kv_codec_error("an empty hash in a state blob");
            }
            e._type = redis_value_type::hash;
            e._hash =
                std::make_shared<const redis_hash>(redis_hash::from_sorted(std::move(fields)));
            return;
        }
        case redis_value_type::set: {
            const auto n = in.u32();
            std::vector<std::string> members;
            members.reserve(std::min<std::size_t>(n, in.remaining() / 4));
            for (std::uint32_t j = 0; j < n; ++j) {
                auto m = in.string(in.u32());
                if (!members.empty() && members.back() >= m) {
                    throw redis_kv_codec_error("set members out of order in a state blob");
                }
                members.push_back(std::move(m));
            }
            if (members.empty()) {
                throw redis_kv_codec_error("an empty set in a state blob");
            }
            e._type = redis_value_type::set;
            e._set = std::make_shared<const redis_set>(redis_set::from_sorted(std::move(members)));
            return;
        }
        case redis_value_type::list: {
            const auto n = in.u32();
            std::vector<std::string> elements;
            elements.reserve(std::min<std::size_t>(n, in.remaining() / 4));
            for (std::uint32_t j = 0; j < n; ++j) {
                elements.push_back(in.string(in.u32()));
            }
            if (elements.empty()) {
                throw redis_kv_codec_error("an empty list in a state blob");
            }
            e._type = redis_value_type::list;
            e._list =
                std::make_shared<const redis_list>(redis_list::from_elements(std::move(elements)));
            return;
        }
        default:
            throw redis_kv_codec_error("unknown value type " + std::to_string(tag) +
                                       " in a state blob");
    }
}

}  // namespace redis_kv_detail

template<typename LogIndex = std::uint64_t>
requires log_index<LogIndex>
class redis_kv_state_machine {
public:
    using key_type = std::string;
    using entry_handle = std::shared_ptr<const redis_kv_value_entry>;

    redis_kv_state_machine() = default;

    // ---- kythira::state_machine -------------------------------------------

    /// Apply one committed entry. The reply bytes are unused by the gateway
    /// (it answers from its own knowledge of what it proposed) but the
    /// concept requires them; a single status byte is returned so a caller
    /// through `node::read_state`-style paths can tell a no-op from a change.
    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        _last_applied_index = index;
        require_redis_record_level(command);
        if (is_redis_kv_v3_record(command)) {
            const auto record = decode_redis_kv_v3_command(command);
            if (auto status = apply_redis_v3_common(*this, record)) {
                return redis_v3_apply_result(*status);
            }
            if (const auto* exec = std::get_if<redis_kv_exec_command>(&record)) {
                return apply_exec(*exec);
            }
            // range_delete and remove_members: tasks 6 and 8.
            return redis_v3_apply_result(redis_v3_apply_status::unchanged);
        }
        auto decoded = decode_redis_kv_command(command);
        bool changed = std::visit([this](auto& c) { return apply_one(c); }, decoded);
        return {changed ? std::byte{1} : std::byte{0}};
    }

    /// Serialize the whole store in key order: for each key `u32 BE keylen,
    /// key, u64 BE expire_at_ms, u32 BE value len, value`, preceded by a
    /// `u32 BE` entry count. This is also the format of every blob
    /// `split_state` produces, so the split/absorb law holds by construction.
    ///
    /// Once the group has passed a format gate (`format_level() > 0`,
    /// redis-general-data-types Requirement 14.2-14.3), the blob starts with
    /// the marker `KRV3`, then `u16 BE` format level and `u64 BE` applied
    /// command time, then the store as above. Before the gate the bytes are
    /// exactly the earlier format, so a group that never enables the new
    /// commands writes the snapshots it always did.
    [[nodiscard]] auto get_state() const -> std::vector<std::byte> {
        return serialize_store(_store.begin(), _store.end(), _store.size(), header());
    }

    auto restore_from_snapshot(const std::vector<std::byte>& snapshot_data, LogIndex index)
        -> void {
        store_type incoming;
        std::size_t bytes = 0;
        const auto head = deserialize_store(snapshot_data, incoming, bytes);
        _format_level = head._format_level;
        _applied_time_ms = head._applied_time_ms;
        _store = std::move(incoming);
        _bytes = bytes;
        _expiring = 0;
        for (const auto& [key, entry] : _store) {
            _expiring += entry->_expire_at_ms != 0 ? 1 : 0;
        }
        _last_applied_index = index;
    }

    /// The reply to a read of `key` at the serving node's time `now_ms`
    /// (redis_string_read.hpp), for the data layer's `read_op`; call it
    /// under the group's lock. `args` are the arguments after the key.
    [[nodiscard]] auto evaluate_read(redis_command_id id, const key_type& key,
                                     std::span<const std::string> args, std::uint64_t now_ms) const
        -> redis_reply {
        auto it = _store.find(key);
        const redis_kv_value_entry* entry = it == _store.end() ? nullptr : it->second.get();
        if (auto reply = evaluate_redis_read(entry, id, args, now_ms)) {
            return *reply;
        }
        return redis_reply::error("ERR command id " + std::to_string(static_cast<int>(id)) +
                                  " is not a read of this store");
    }

    [[nodiscard]] auto last_applied_index() const noexcept -> LogIndex {
        return _last_applied_index;
    }

    // ---- command time and format level (redis-general-data-types) ---------

    /// The command time a format-0x03 entry stamped `entry_now_ms` runs at:
    /// `max(entry_now_ms, applied time)`, which also becomes the new applied
    /// time (Requirement 2.2-2.3). The floor keeps time from running
    /// backwards when leadership moves to a node whose clock is behind, so
    /// two entries in log order never see expiry in the opposite order.
    /// Called only from `apply()`; reads no clock.
    auto advance_command_time(std::uint64_t entry_now_ms) noexcept -> std::uint64_t {
        _applied_time_ms = std::max(_applied_time_ms, entry_now_ms);
        return _applied_time_ms;
    }

    /// The largest command time this group has applied; 0 before any
    /// format-0x03 entry. In snapshots and `split_state` output once the
    /// group has passed the format gate.
    [[nodiscard]] auto applied_time_ms() const noexcept -> std::uint64_t {
        return _applied_time_ms;
    }

    /// The format level the group has passed a gate for; 0 is the earlier
    /// formats only. One-way (Requirement 14.5).
    [[nodiscard]] auto format_level() const noexcept -> std::uint16_t { return _format_level; }

    /// Raise the format level, as an applied `format_gate` entry does. A
    /// lower level than the current one changes nothing.
    auto enable_format(std::uint16_t level) noexcept -> void {
        _format_level = std::max(_format_level, level);
    }

    // ---- kythira::splittable_state_machine ---------------------------------

    /// Keys plus values, maintained incrementally so the policy tick that
    /// polls it does not walk the map.
    [[nodiscard]] auto approximate_size_bytes() const noexcept -> std::size_t { return _bytes; }
    [[nodiscard]] auto approximate_key_count() const noexcept -> std::size_t {
        return _store.size();
    }
    /// Keys carrying a deadline, swept or not; INFO's `expires=`.
    [[nodiscard]] auto expiring_key_count() const noexcept -> std::size_t { return _expiring; }

    /// Evenly spaced by key count, never the first key (an empty left child
    /// is a legal shard and a useless one). sccache keys are content hashes,
    /// so count and bytes are close enough that a size-weighted walk would
    /// buy nothing.
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
        for (const auto& [key, entry] : _store) {
            ++index;
            if (taken < wanted && index % stride == 0 && index < _store.size()) {
                out.push_back(key);
                ++taken;
            }
        }
        return out;
    }

    /// Always true. Redis keys are independent of one another: there is no
    /// row/index relationship, no multi-key command in the closure, and no
    /// per-range metadata, so there is never a key between which and its
    /// neighbour a cut would be wrong. The concept requires the veto to exist
    /// because other state machines need it; this one has nothing to protect.
    [[nodiscard]] auto can_split_at([[maybe_unused]] const key_type& key) const -> bool {
        return true;
    }

    /// Cut the store at `keys`, returning `keys.size() + 1` blobs in key
    /// order, each in `get_state()`'s format. Cuts are sorted and deduplicated
    /// first so a caller's ordering mistake cannot yield overlapping children.
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
            out.push_back(serialize_store(begin, it, n, header()));
        }
        std::size_t n = 0;
        for (auto tail = it; tail != _store.end(); ++tail) {
            ++n;
        }
        out.push_back(serialize_store(it, _store.end(), n, header()));
        return out;
    }

    /// Take on a sibling's state. `range` is unused: there is no range-scoped
    /// structure to update. Incoming entries win on a key collision, which
    /// cannot happen between siblings of one split and is the documented
    /// behaviour if it ever does. The merged group keeps the larger applied
    /// command time and the higher format level, so neither time nor the
    /// gate runs backwards across a merge.
    auto absorb(const std::vector<std::byte>& other_state,
                [[maybe_unused]] const shard_range<key_type>& range) -> void {
        store_type incoming;
        std::size_t bytes = 0;
        const auto head = deserialize_store(other_state, incoming, bytes);
        enable_format(head._format_level);
        advance_command_time(head._applied_time_ms);
        for (auto& [key, entry] : incoming) {
            insert_or_replace(key, std::move(entry));
        }
    }

    // ---- read path ---------------------------------------------------------

    /// O(1)-ish handle to a value; null if absent. Does NOT consult the
    /// deadline: the gateway compares `_expire_at_ms` to its own clock, which
    /// keeps this method and everything else here clock-free.
    [[nodiscard]] auto lookup(std::string_view key) const -> entry_handle {
        auto it = _store.find(key);
        return it == _store.end() ? nullptr : it->second;
    }

    /// Keys whose deadline is non-zero and `<= now_ms`, oldest deadline first,
    /// at most `max`. The leader calls this on its policy tick to build a
    /// `sweep` proposal; replicas never call it.
    [[nodiscard]] auto collect_expired(std::uint64_t now_ms, std::size_t max) const
        -> std::vector<redis_kv_sweep_entry> {
        std::vector<redis_kv_sweep_entry> out;
        for (const auto& [key, entry] : _store) {
            if (out.size() >= max) {
                break;
            }
            if (entry->_expire_at_ms != 0 && entry->_expire_at_ms <= now_ms) {
                out.push_back({key, entry->_expire_at_ms});
            }
        }
        return out;
    }

    /// Every key in order; for INFO/DBSIZE-style diagnostics and the leader's
    /// eviction bookkeeping when it has to seed an advisory LRU.
    template<typename F> auto for_each_key(F&& f) const -> void {
        for (const auto& [key, entry] : _store) {
            f(key, *entry);
        }
    }

    /// Keys in `[from, to)` (`to` empty: no bound) in key order, for the
    /// SCAN family (task 12): `f(key, expire_at_ms, type)` returns whether
    /// to go on. Expired keys are visited too; the caller skips them.
    template<typename F>
    auto scan_keys(std::string_view from, const std::optional<std::string>& to, F&& f) const
        -> void {
        for (auto it = _store.lower_bound(from); it != _store.end(); ++it) {
            if (to && it->first >= *to) {
                return;
            }
            if (!f(it->first, it->second->_expire_at_ms, redis_entry_type(*it->second))) {
                return;
            }
        }
    }

    // ---- codec, public so tests can check the split/absorb law -------------

    using store_type = std::map<key_type, entry_handle, std::less<>>;

    /// The `KRV3` snapshot marker (Requirement 14.2).
    /// Opens the collections section of a state blob (task 7).
    static constexpr std::array<std::byte, 4> k_typed_marker{std::byte{'K'}, std::byte{'R'},
                                                             std::byte{'V'}, std::byte{'T'}};
    static constexpr std::array<std::byte, 4> k_state_marker{std::byte{'K'}, std::byte{'R'},
                                                             std::byte{'V'}, std::byte{'3'}};

    /// What precedes the store in a post-gate blob. A level of 0 means no
    /// header at all: the earlier format.
    struct state_header {
        std::uint16_t _format_level = 0;
        std::uint64_t _applied_time_ms = 0;
    };

    template<typename It>
    [[nodiscard]] static auto serialize_store(It begin, It end, std::size_t count,
                                              state_header head = {}) -> std::vector<std::byte> {
        std::vector<std::byte> out;
        if (head._format_level > 0) {
            redis_kv_detail::put_bytes(out, k_state_marker);
            redis_kv_detail::put_u16(out, head._format_level);
            redis_kv_detail::put_u64(out, head._applied_time_ms);
        }
        // Strings first, in the earlier layout; collections after them in a
        // section of their own, so a blob without one reads as before.
        std::size_t typed = 0;
        for (auto it = begin; it != end; ++it) {
            typed += it->second->_type != redis_value_type::string ? 1 : 0;
        }
        if (typed != 0 && head._format_level == 0) {
            throw redis_kv_codec_error("a typed value in a state blob without a format level");
        }
        redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(count - typed));
        for (auto it = begin; it != end; ++it) {
            const auto& [key, entry] = *it;
            if (entry->_type != redis_value_type::string) {
                continue;
            }
            redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(key.size()));
            redis_kv_detail::put_string(out, key);
            redis_kv_detail::put_u64(out, entry->_expire_at_ms);
            redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(entry->_value.size()));
            redis_kv_detail::put_bytes(out, entry->_value);
        }
        if (typed == 0) {
            return out;
        }
        redis_kv_detail::put_bytes(out, k_typed_marker);
        redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(typed));
        for (auto it = begin; it != end; ++it) {
            const auto& [key, entry] = *it;
            if (entry->_type == redis_value_type::string) {
                continue;
            }
            redis_kv_detail::put_u32(out, static_cast<std::uint32_t>(key.size()));
            redis_kv_detail::put_string(out, key);
            redis_kv_detail::put_u64(out, entry->_expire_at_ms);
            out.push_back(static_cast<std::byte>(entry->_type));
            redis_kv_detail::put_collection_body(out, *entry);
        }
        return out;
    }

    /// Reads both formats. An earlier-format blob starts with its `u32 BE`
    /// entry count; `KRV3` read as a count is 1,263,687,219 entries, which
    /// would need a blob of over 20 GB, so the marker cannot be mistaken for
    /// one in a blob that fits the shard limit.
    static auto deserialize_store(const std::vector<std::byte>& blob, store_type& into,
                                  std::size_t& bytes) -> state_header {
        redis_kv_detail::reader in(blob);
        state_header head;
        if (blob.size() >= k_state_marker.size() &&
            std::equal(k_state_marker.begin(), k_state_marker.end(), blob.begin())) {
            (void)in.bytes(k_state_marker.size());
            head._format_level = in.u16();
            head._applied_time_ms = in.u64();
            if (head._format_level == 0) {
                throw redis_kv_codec_error("redis kv state marker with format level 0");
            }
            if (head._format_level > k_redis_format_level) {
                throw redis_format_too_new(head._format_level);
            }
        }
        auto count = in.u32();
        for (std::uint32_t i = 0; i < count; ++i) {
            auto key = in.string(in.u32());
            auto entry = std::make_shared<redis_kv_value_entry>();
            entry->_expire_at_ms = in.u64();
            auto v = in.bytes(in.u32());
            entry->_value.assign(v.begin(), v.end());
            bytes += key.size() + entry->_value.size();
            into[std::move(key)] = std::move(entry);
        }
        if (in.remaining() >= k_typed_marker.size()) {
            const auto marker = in.bytes(k_typed_marker.size());
            if (!std::equal(marker.begin(), marker.end(), k_typed_marker.begin()) ||
                head._format_level < k_redis_typed_values_level) {
                throw redis_kv_codec_error("trailing bytes after redis kv state blob");
            }
            const auto typed = in.u32();
            for (std::uint32_t i = 0; i < typed; ++i) {
                auto key = in.string(in.u32());
                auto entry = std::make_shared<redis_kv_value_entry>();
                entry->_expire_at_ms = in.u64();
                redis_kv_detail::read_collection_body(in, in.u8(), *entry);
                if (into.contains(key)) {
                    throw redis_kv_codec_error("a key twice in a state blob");
                }
                bytes += key.size() + redis_entry_bytes(*entry);
                into[std::move(key)] = std::move(entry);
            }
        }
        if (in.remaining() != 0) {
            throw redis_kv_codec_error("trailing bytes after redis kv state blob");
        }
        return head;
    }

private:
    auto apply_one(redis_kv_set_command& c) -> bool {
        auto entry = std::make_shared<redis_kv_value_entry>();
        entry->_value = std::move(c._value);
        entry->_expire_at_ms = c._expire_at_ms;
        insert_or_replace(c._key, std::move(entry));
        return true;
    }

    auto apply_one(const redis_kv_del_command& c) -> bool { return erase(c._key); }

    /// Delete each named key only if its stored deadline still equals the
    /// one the sweep was built from: a SET that landed between the sweep's
    /// proposal and its apply replaced the deadline and must survive.
    auto apply_one(const redis_kv_sweep_command& c) -> bool {
        bool changed = false;
        for (const auto& e : c._entries) {
            auto it = _store.find(e._key);
            if (it != _store.end() && it->second->_expire_at_ms == e._expire_at_ms &&
                e._expire_at_ms != 0) {
                forget(it);
                _store.erase(it);
                changed = true;
            }
        }
        return changed;
    }

    /// The disk-backed store's records (`cache_kv_state_machine`). The
    /// in-memory gateway never proposes them, so they are no-ops here: a
    /// pure function of the entry, as every apply must be, rather than an
    /// exception that would stop the replica.
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

    /// An `exec` record at its command time; the reply, encoded, is the
    /// apply result the front end renders (design Component 2).
    auto apply_exec(const redis_kv_exec_command& c) -> std::vector<std::byte> {
        const auto t = advance_command_time(c._now_ms);
        struct store_ops {
            redis_kv_state_machine& _sm;
            [[nodiscard]] auto find(const key_type& key) const -> entry_handle {
                auto it = _sm._store.find(key);
                return it == _sm._store.end() ? nullptr : it->second;
            }
            auto put(const key_type& key, std::vector<std::byte> value, std::uint64_t expire_at_ms)
                -> void {
                auto entry = std::make_shared<redis_kv_value_entry>();
                entry->_value = std::move(value);
                entry->_expire_at_ms = expire_at_ms;
                _sm.insert_or_replace(key, std::move(entry));
            }
            auto put_entry(const key_type& key, entry_handle entry) -> void {
                _sm.insert_or_replace(key, std::move(entry));
            }
            auto erase(const key_type& key) -> bool { return _sm.erase(key); }
        } ops{*this};
        auto reply = apply_redis_exec(ops, c, t);
        if (!reply) {
            throw redis_unknown_command_id(c._command_id);
        }
        return encode_redis_reply(*reply);
    }

    auto insert_or_replace(const key_type& key, entry_handle entry) -> void {
        auto [it, inserted] = _store.try_emplace(key, nullptr);
        if (!inserted) {
            forget(it);
        }
        _bytes += key.size() + redis_entry_bytes(*entry);
        _expiring += entry->_expire_at_ms != 0 ? 1 : 0;
        it->second = std::move(entry);
    }

    /// Undo an entry's contribution to the incremental counters.
    auto forget(store_type::const_iterator it) -> void {
        _bytes -= it->first.size() + redis_entry_bytes(*it->second);
        _expiring -= it->second->_expire_at_ms != 0 ? 1 : 0;
    }

    auto erase(const key_type& key) -> bool {
        auto it = _store.find(key);
        if (it == _store.end()) {
            return false;
        }
        forget(it);
        _store.erase(it);
        return true;
    }

    [[nodiscard]] auto header() const noexcept -> state_header {
        return {_format_level, _applied_time_ms};
    }

    store_type _store;
    std::size_t _bytes = 0;
    std::size_t _expiring = 0;
    LogIndex _last_applied_index{};
    std::uint16_t _format_level = 0;
    std::uint64_t _applied_time_ms = 0;
};

static_assert(state_machine<redis_kv_state_machine<std::uint64_t>, std::uint64_t>,
              "redis_kv_state_machine must satisfy the state_machine concept");
static_assert(splittable_state_machine<redis_kv_state_machine<std::uint64_t>, std::string>,
              "redis_kv_state_machine must satisfy the splittable_state_machine concept");

}  // namespace kythira
