// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_value.hpp
/// The typed value model (.kiro/specs/redis-general-data-types/ task 7,
/// design Component 3, Requirement 9).
///
/// A stored value is a string or a collection. Collections are **chunked**:
/// a vector of `shared_ptr<const chunk>`, each chunk a byte-ordered run of
/// at most `k_redis_chunk_entries` entries. A writer copies only the chunks
/// it touches and shares the rest, so
///
/// - a reader takes a `shared_ptr` to the collection under the node lock and
///   encodes after releasing it (`HGETALL` never copies a large hash under
///   the lock, Requirement 10.2);
/// - a write to a large collection costs one chunk, not the collection;
/// - iteration is deterministic: byte order of the field (Requirement 9.3).
///
/// Every collection keeps its element count and its byte total (each
/// element's bytes plus `k_redis_element_overhead`), so the state machine's
/// size accounting stays incremental (Requirement 9.6).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

/// What a key holds (Requirement 9.1). The values are the snapshot tags.
enum class redis_value_type : std::uint8_t {
    string = 0,
    hash = 1,
    set = 2,
    list = 3,
};

[[nodiscard]] inline auto redis_value_type_name(redis_value_type t) -> std::string_view {
    switch (t) {
        case redis_value_type::string:
            return "string";
        case redis_value_type::hash:
            return "hash";
        case redis_value_type::set:
            return "set";
        case redis_value_type::list:
            return "list";
    }
    return "none";
}

/// Installs under `key` a copy of `e` with deadline `expire_at_ms`, sharing
/// its collection: the deadline and rename paths keep a value's type. A
/// store without whole-entry puts holds only strings.
template<typename Store, typename Entry>
auto redis_store_put_copy(Store& store, const std::string& key, const Entry& e,
                          std::uint64_t expire_at_ms) -> void {
    if constexpr (requires { store.put_entry(key, std::make_shared<Entry>(e)); }) {
        auto out = std::make_shared<Entry>(e);
        out->_expire_at_ms = expire_at_ms;
        store.put_entry(key, std::move(out));
    } else {
        store.put(key, e._value, expire_at_ms);
    }
}

/// Most entries in one chunk.
inline constexpr std::size_t k_redis_chunk_entries = 128;
/// Bytes counted per element on top of its own, for size accounting.
inline constexpr std::size_t k_redis_element_overhead = 16;

inline constexpr std::string_view k_redis_wrongtype =
    "WRONGTYPE Operation against a key holding the wrong kind of value";

/// What `e` holds. Entries without a `_type` (every store but the in-memory
/// one, until task 10) hold strings.
template<typename Entry>
[[nodiscard]] auto redis_entry_type(const Entry& e) noexcept -> redis_value_type {
    if constexpr (requires { e._type; }) {
        return e._type;
    } else {
        return redis_value_type::string;
    }
}

/// A hash: field → value, chunked, in byte order of the field. Immutable
/// once published; the mutators return a new hash sharing untouched chunks.
class redis_hash {
public:
    using entry = std::pair<std::string, std::string>;
    using chunk = std::vector<entry>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _count; }
    [[nodiscard]] auto bytes() const noexcept -> std::size_t { return _bytes; }
    [[nodiscard]] auto empty() const noexcept -> bool { return _count == 0; }
    [[nodiscard]] auto chunks() const noexcept -> const std::vector<std::shared_ptr<const chunk>>& {
        return _chunks;
    }

    /// The value of `field`, or nullptr.
    [[nodiscard]] auto find(std::string_view field) const -> const std::string* {
        const auto c = chunk_for(field);
        if (c >= _chunks.size()) {
            return nullptr;
        }
        const auto& ch = *_chunks[c];
        const auto it = std::ranges::lower_bound(ch, field, {}, &entry::first);
        return it != ch.end() && it->first == field ? &it->second : nullptr;
    }

    /// Calls `f(field, value)` for every entry in byte order of the field.
    template<typename F> auto for_each(F&& f) const -> void {
        for (const auto& c : _chunks) {
            for (const auto& [field, value] : *c) {
                f(field, value);
            }
        }
    }

    /// This hash with `field` set to `value`; `added` says whether the field
    /// is new.
    [[nodiscard]] auto with(std::string field, std::string value, bool& added) const -> redis_hash {
        redis_hash out = *this;
        // Every published chunk is non-empty, so `chunk_for` can read its
        // first field; an empty hash starts its first chunk here.
        const auto c = out._chunks.empty() ? 0 : out.chunk_for(field);
        if (out._chunks.empty()) {
            out._chunks.push_back(std::make_shared<const chunk>());
        }
        auto ch = std::make_shared<chunk>(*out._chunks[c]);
        auto it = std::ranges::lower_bound(*ch, field, {}, &entry::first);
        if (it != ch->end() && it->first == field) {
            added = false;
            out._bytes -= it->second.size();
            out._bytes += value.size();
            it->second = std::move(value);
        } else {
            added = true;
            ++out._count;
            out._bytes += field.size() + value.size() + k_redis_element_overhead;
            ch->insert(it, entry{std::move(field), std::move(value)});
        }
        out.replace_chunk(c, std::move(ch));
        return out;
    }

    /// This hash without `field`; `removed` says whether it was there.
    [[nodiscard]] auto without(std::string_view field, bool& removed) const -> redis_hash {
        removed = false;
        const auto c = chunk_for(field);
        if (c >= _chunks.size()) {
            return *this;
        }
        const auto& old = *_chunks[c];
        const auto pos = std::ranges::lower_bound(old, field, {}, &entry::first);
        if (pos == old.end() || pos->first != field) {
            return *this;
        }
        removed = true;
        redis_hash out = *this;
        auto ch = std::make_shared<chunk>(old);
        auto it = ch->begin() + (pos - old.begin());
        --out._count;
        out._bytes -= it->first.size() + it->second.size() + k_redis_element_overhead;
        ch->erase(it);
        out.replace_chunk(c, std::move(ch));
        return out;
    }

    /// Builds a hash from entries in strictly increasing field order (a
    /// snapshot's), chunk by chunk.
    [[nodiscard]] static auto from_sorted(std::vector<entry> entries) -> redis_hash {
        redis_hash out;
        for (std::size_t i = 0; i < entries.size(); i += k_redis_chunk_entries) {
            const auto end = std::min(entries.size(), i + k_redis_chunk_entries);
            auto ch = std::make_shared<chunk>();
            for (std::size_t j = i; j < end; ++j) {
                out._bytes +=
                    entries[j].first.size() + entries[j].second.size() + k_redis_element_overhead;
                ch->push_back(std::move(entries[j]));
            }
            out._count += ch->size();
            out._chunks.push_back(std::move(ch));
        }
        return out;
    }

private:
    /// The chunk that holds or would hold `field`: the last whose first
    /// field is at or below it (the first chunk for anything below all).
    [[nodiscard]] auto chunk_for(std::string_view field) const -> std::size_t {
        if (_chunks.empty()) {
            return 0;
        }
        const auto it =
            std::ranges::upper_bound(_chunks, field, {}, [](const std::shared_ptr<const chunk>& c) {
                return std::string_view(c->front().first);
            });
        return it == _chunks.begin() ? 0 : static_cast<std::size_t>(it - _chunks.begin()) - 1;
    }

    /// Installs `ch` at `c`, splitting it in two when it outgrew a chunk and
    /// dropping it when it emptied.
    auto replace_chunk(std::size_t c, std::shared_ptr<chunk> ch) -> void {
        if (ch->empty()) {
            _chunks.erase(_chunks.begin() + static_cast<std::ptrdiff_t>(c));
            return;
        }
        if (ch->size() > k_redis_chunk_entries) {
            const auto half = static_cast<std::ptrdiff_t>(ch->size() / 2);
            auto upper = std::make_shared<chunk>(std::make_move_iterator(ch->begin() + half),
                                                 std::make_move_iterator(ch->end()));
            ch->erase(ch->begin() + half, ch->end());
            _chunks[c] = std::move(ch);
            _chunks.insert(_chunks.begin() + static_cast<std::ptrdiff_t>(c) + 1, std::move(upper));
            return;
        }
        _chunks[c] = std::move(ch);
    }

    std::vector<std::shared_ptr<const chunk>> _chunks;
    std::size_t _count = 0;
    std::size_t _bytes = 0;
};

}  // namespace kythira
