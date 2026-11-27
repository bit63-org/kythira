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

namespace redis_value_detail {

/// How a collection reads its element type: the sort key and the bytes it
/// counts.
template<typename Entry> struct element_traits;

template<> struct element_traits<std::pair<std::string, std::string>> {
    [[nodiscard]] static auto key(const std::pair<std::string, std::string>& e) noexcept
        -> std::string_view {
        return e.first;
    }
    [[nodiscard]] static auto bytes(const std::pair<std::string, std::string>& e) noexcept
        -> std::size_t {
        return e.first.size() + e.second.size();
    }
};

template<> struct element_traits<std::string> {
    [[nodiscard]] static auto key(const std::string& e) noexcept -> std::string_view { return e; }
    [[nodiscard]] static auto bytes(const std::string& e) noexcept -> std::size_t {
        return e.size();
    }
};

}  // namespace redis_value_detail

/// Elements in byte order of their key, chunked: the shared core of hashes
/// and sets. Immutable once published; the mutators return a new
/// collection sharing untouched chunks.
template<typename Entry> class redis_sorted_chunks {
public:
    using entry = Entry;
    using chunk = std::vector<entry>;
    using traits = redis_value_detail::element_traits<Entry>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _count; }
    [[nodiscard]] auto bytes() const noexcept -> std::size_t { return _bytes; }
    [[nodiscard]] auto empty() const noexcept -> bool { return _count == 0; }
    [[nodiscard]] auto chunks() const noexcept -> const std::vector<std::shared_ptr<const chunk>>& {
        return _chunks;
    }

    /// The element whose key is `key`, or nullptr.
    [[nodiscard]] auto find_entry(std::string_view key) const -> const entry* {
        const auto c = chunk_for(key);
        if (c >= _chunks.size()) {
            return nullptr;
        }
        const auto& ch = *_chunks[c];
        const auto it = std::ranges::lower_bound(ch, key, {}, &traits::key);
        return it != ch.end() && traits::key(*it) == key ? &*it : nullptr;
    }

    /// The `n`th element in order (`n < size()`).
    [[nodiscard]] auto at(std::size_t n) const -> const entry& {
        for (const auto& c : _chunks) {
            if (n < c->size()) {
                return (*c)[n];
            }
            n -= c->size();
        }
        return _chunks.back()->back();
    }

    /// Calls `f(element)` for each element whose key is above `after` (every
    /// element when `after` is empty and `from_start`), in order, while it
    /// returns true; for HSCAN and SSCAN pages (task 12). Starts at the
    /// chunk that would hold `after`, so a page costs a chunk, not the
    /// elements before it.
    template<typename F>
    auto visit_after(std::string_view after, bool from_start, F&& f) const -> void {
        for (auto c = from_start ? 0 : chunk_for(after); c < _chunks.size(); ++c) {
            const auto& ch = *_chunks[c];
            auto it =
                from_start ? ch.begin() : std::ranges::upper_bound(ch, after, {}, &traits::key);
            for (; it != ch.end(); ++it) {
                if (!f(*it)) {
                    return;
                }
            }
        }
    }

    /// Calls `f(element)` for every element in order.
    template<typename F> auto for_each_entry(F&& f) const -> void {
        for (const auto& c : _chunks) {
            for (const auto& e : *c) {
                f(e);
            }
        }
    }

protected:
    /// Inserts `e`, or replaces the element with its key; `added` says which.
    auto put(entry e, bool& added) -> void {
        // Every published chunk is non-empty, so `chunk_for` can read its
        // first key; an empty collection starts its first chunk here.
        const auto c = _chunks.empty() ? 0 : chunk_for(traits::key(e));
        if (_chunks.empty()) {
            _chunks.push_back(std::make_shared<const chunk>());
        }
        auto ch = std::make_shared<chunk>(*_chunks[c]);
        auto it = std::ranges::lower_bound(*ch, traits::key(e), {}, &traits::key);
        if (it != ch->end() && traits::key(*it) == traits::key(e)) {
            added = false;
            _bytes -= traits::bytes(*it);
            _bytes += traits::bytes(e);
            *it = std::move(e);
        } else {
            added = true;
            ++_count;
            _bytes += traits::bytes(e) + k_redis_element_overhead;
            ch->insert(it, std::move(e));
        }
        replace_chunk(c, std::move(ch));
    }

    /// Removes the element with `key`; `removed` says whether it was there.
    auto remove(std::string_view key, bool& removed) -> void {
        removed = false;
        const auto c = chunk_for(key);
        if (c >= _chunks.size()) {
            return;
        }
        const auto& old = *_chunks[c];
        const auto pos = std::ranges::lower_bound(old, key, {}, &traits::key);
        if (pos == old.end() || traits::key(*pos) != key) {
            return;
        }
        removed = true;
        auto ch = std::make_shared<chunk>(old);
        auto it = ch->begin() + (pos - old.begin());
        --_count;
        _bytes -= traits::bytes(*it) + k_redis_element_overhead;
        ch->erase(it);
        replace_chunk(c, std::move(ch));
    }

    /// Fills an empty collection from elements in strictly increasing key
    /// order (a snapshot's), chunk by chunk.
    auto fill_sorted(std::vector<entry> entries) -> void {
        for (std::size_t i = 0; i < entries.size(); i += k_redis_chunk_entries) {
            const auto end = std::min(entries.size(), i + k_redis_chunk_entries);
            auto ch = std::make_shared<chunk>();
            for (std::size_t j = i; j < end; ++j) {
                _bytes += traits::bytes(entries[j]) + k_redis_element_overhead;
                ch->push_back(std::move(entries[j]));
            }
            _count += ch->size();
            _chunks.push_back(std::move(ch));
        }
    }

private:
    /// The chunk that holds or would hold `key`: the last whose first key is
    /// at or below it (the first chunk for anything below all).
    [[nodiscard]] auto chunk_for(std::string_view key) const -> std::size_t {
        if (_chunks.empty()) {
            return 0;
        }
        const auto it = std::ranges::upper_bound(
            _chunks, key, {},
            [](const std::shared_ptr<const chunk>& c) { return traits::key(c->front()); });
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

/// A hash: field → value, in byte order of the field.
class redis_hash : public redis_sorted_chunks<std::pair<std::string, std::string>> {
public:
    /// The value of `field`, or nullptr.
    [[nodiscard]] auto find(std::string_view field) const -> const std::string* {
        const auto* e = find_entry(field);
        return e != nullptr ? &e->second : nullptr;
    }

    /// Calls `f(field, value)` for every entry in byte order of the field.
    template<typename F> auto for_each(F&& f) const -> void {
        for_each_entry([&](const entry& e) { f(e.first, e.second); });
    }

    /// This hash with `field` set to `value`; `added` says whether the field
    /// is new.
    [[nodiscard]] auto with(std::string field, std::string value, bool& added) const -> redis_hash {
        redis_hash out = *this;
        out.put(entry{std::move(field), std::move(value)}, added);
        return out;
    }

    /// This hash without `field`; `removed` says whether it was there.
    [[nodiscard]] auto without(std::string_view field, bool& removed) const -> redis_hash {
        redis_hash out = *this;
        out.remove(field, removed);
        return removed ? out : *this;
    }

    /// Builds a hash from entries in strictly increasing field order.
    [[nodiscard]] static auto from_sorted(std::vector<entry> entries) -> redis_hash {
        redis_hash out;
        out.fill_sorted(std::move(entries));
        return out;
    }
};

/// A set of members, in byte order (Requirement 9.3).
class redis_set : public redis_sorted_chunks<std::string> {
public:
    [[nodiscard]] auto contains(std::string_view member) const -> bool {
        return find_entry(member) != nullptr;
    }

    /// Calls `f(member)` for every member in byte order.
    template<typename F> auto for_each(F&& f) const -> void { for_each_entry(f); }

    /// This set with `member`; `added` says whether it is new.
    [[nodiscard]] auto with(std::string member, bool& added) const -> redis_set {
        if (contains(member)) {
            added = false;
            return *this;
        }
        redis_set out = *this;
        out.put(std::move(member), added);
        return out;
    }

    /// This set without `member`; `removed` says whether it was there.
    [[nodiscard]] auto without(std::string_view member, bool& removed) const -> redis_set {
        redis_set out = *this;
        out.remove(member, removed);
        return removed ? out : *this;
    }

    /// Builds a set from members in strictly increasing order.
    [[nodiscard]] static auto from_sorted(std::vector<std::string> members) -> redis_set {
        redis_set out;
        out.fill_sorted(std::move(members));
        return out;
    }
};

/// A list, in list order, chunked: a vector of shared chunks of at most
/// `k_redis_chunk_entries` elements. The mutators change this list in
/// place, copying only the chunks they touch, so a caller copies the list
/// (sharing every chunk) and mutates the copy: a published list never
/// changes. Pushing or popping at an end copies one chunk and the chunk
/// vector (Requirement 12.2: bounded by the chunking, not the list).
class redis_list {
public:
    using chunk = std::vector<std::string>;

    [[nodiscard]] auto size() const noexcept -> std::size_t { return _count; }
    [[nodiscard]] auto bytes() const noexcept -> std::size_t { return _bytes; }
    [[nodiscard]] auto empty() const noexcept -> bool { return _count == 0; }
    [[nodiscard]] auto chunks() const noexcept -> const std::vector<std::shared_ptr<const chunk>>& {
        return _chunks;
    }

    /// The element at `i` (`i < size()`).
    [[nodiscard]] auto at(std::size_t i) const -> const std::string& {
        const auto [c, off] = locate(i);
        return (*_chunks[c])[off];
    }

    /// Calls `f(index, element)` for elements `first..last` inclusive, in
    /// order, while `f` returns true.
    template<typename F> auto visit(std::size_t first, std::size_t last, F&& f) const -> void {
        if (first > last || first >= _count) {
            return;
        }
        auto [c, off] = locate(first);
        for (std::size_t i = first; i <= last && i < _count; ++i) {
            if (!f(i, (*_chunks[c])[off])) {
                return;
            }
            if (++off == _chunks[c]->size()) {
                ++c;
                off = 0;
            }
        }
    }

    /// Calls `f(index, element)` from the last element back to the first,
    /// while `f` returns true.
    template<typename F> auto visit_backwards(F&& f) const -> void {
        std::size_t i = _count;
        for (auto c = _chunks.size(); c-- > 0;) {
            for (auto off = _chunks[c]->size(); off-- > 0;) {
                if (!f(--i, (*_chunks[c])[off])) {
                    return;
                }
            }
        }
    }

    auto push_back(std::string v) -> void {
        account_add(v);
        if (_chunks.empty() || _chunks.back()->size() >= k_redis_chunk_entries) {
            _chunks.push_back(std::make_shared<const chunk>(chunk{std::move(v)}));
            return;
        }
        auto ch = std::make_shared<chunk>(*_chunks.back());
        ch->push_back(std::move(v));
        _chunks.back() = std::move(ch);
    }

    auto push_front(std::string v) -> void {
        account_add(v);
        if (_chunks.empty() || _chunks.front()->size() >= k_redis_chunk_entries) {
            _chunks.insert(_chunks.begin(), std::make_shared<const chunk>(chunk{std::move(v)}));
            return;
        }
        auto ch = std::make_shared<chunk>();
        ch->reserve(_chunks.front()->size() + 1);
        ch->push_back(std::move(v));
        ch->insert(ch->end(), _chunks.front()->begin(), _chunks.front()->end());
        _chunks.front() = std::move(ch);
    }

    /// Removes and returns the first element (`!empty()`).
    auto pop_front() -> std::string {
        auto ch = std::make_shared<chunk>(*_chunks.front());
        auto v = std::move(ch->front());
        ch->erase(ch->begin());
        account_remove(v);
        if (ch->empty()) {
            _chunks.erase(_chunks.begin());
        } else {
            _chunks.front() = std::move(ch);
        }
        return v;
    }

    /// Removes and returns the last element (`!empty()`).
    auto pop_back() -> std::string {
        auto ch = std::make_shared<chunk>(*_chunks.back());
        auto v = std::move(ch->back());
        ch->pop_back();
        account_remove(v);
        if (ch->empty()) {
            _chunks.pop_back();
        } else {
            _chunks.back() = std::move(ch);
        }
        return v;
    }

    /// Replaces the element at `i` (`i < size()`).
    auto set(std::size_t i, std::string v) -> void {
        const auto [c, off] = locate(i);
        auto ch = std::make_shared<chunk>(*_chunks[c]);
        _bytes -= (*ch)[off].size();
        _bytes += v.size();
        (*ch)[off] = std::move(v);
        _chunks[c] = std::move(ch);
    }

    /// Inserts `v` so that it lands at index `i` (`i <= size()`).
    auto insert(std::size_t i, std::string v) -> void {
        if (i == _count) {
            push_back(std::move(v));
            return;
        }
        const auto [c, off] = locate(i);
        account_add(v);
        auto ch = std::make_shared<chunk>(*_chunks[c]);
        ch->insert(ch->begin() + static_cast<std::ptrdiff_t>(off), std::move(v));
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

    /// Keeps only elements whose index `keep(i, element)` accepts, copying
    /// only the chunks that lose an element. Returns how many were removed.
    template<typename Keep> auto retain(Keep&& keep) -> std::size_t {
        std::vector<std::shared_ptr<const chunk>> next;
        next.reserve(_chunks.size());
        std::size_t i = 0;
        std::size_t removed = 0;
        for (const auto& c : _chunks) {
            std::shared_ptr<chunk> copy;
            for (std::size_t off = 0; off < c->size(); ++off, ++i) {
                const bool kept = keep(i, (*c)[off]);
                if (!kept && !copy) {
                    copy = std::make_shared<chunk>(c->begin(),
                                                   c->begin() + static_cast<std::ptrdiff_t>(off));
                }
                if (!kept) {
                    ++removed;
                    account_remove((*c)[off]);
                } else if (copy) {
                    copy->push_back((*c)[off]);
                }
            }
            if (!copy) {
                next.push_back(c);
            } else if (!copy->empty()) {
                next.push_back(std::move(copy));
            }
        }
        _chunks = std::move(next);
        return removed;
    }

    /// Builds a list from elements in order (a snapshot's).
    [[nodiscard]] static auto from_elements(std::vector<std::string> elements) -> redis_list {
        redis_list out;
        for (auto& e : elements) {
            out.push_back(std::move(e));
        }
        return out;
    }

private:
    [[nodiscard]] auto locate(std::size_t i) const -> std::pair<std::size_t, std::size_t> {
        // Walk from the nearer end.
        if (i < _count / 2) {
            for (std::size_t c = 0; c < _chunks.size(); ++c) {
                if (i < _chunks[c]->size()) {
                    return {c, i};
                }
                i -= _chunks[c]->size();
            }
        } else {
            std::size_t from_end = _count - i;
            for (auto c = _chunks.size(); c-- > 0;) {
                if (from_end <= _chunks[c]->size()) {
                    return {c, _chunks[c]->size() - from_end};
                }
                from_end -= _chunks[c]->size();
            }
        }
        return {_chunks.size() - 1, _chunks.back()->size() - 1};
    }

    auto account_add(const std::string& v) noexcept -> void {
        ++_count;
        _bytes += v.size() + k_redis_element_overhead;
    }
    auto account_remove(const std::string& v) noexcept -> void {
        --_count;
        _bytes -= v.size() + k_redis_element_overhead;
    }

    std::vector<std::shared_ptr<const chunk>> _chunks;
    std::size_t _count = 0;
    std::size_t _bytes = 0;
};

}  // namespace kythira
