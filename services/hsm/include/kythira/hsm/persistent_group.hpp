// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The engine plumbing the HSM's two state machines share: a group owns every
// key under its namespace `ns` in one kv_engine, keeps its applied index in
// the meta column family at `ns`, writes each entry and its index in one
// batch, tracks which applied index is durable, and moves as a checkpoint
// (persistent_state_machine.hpp, Requirement 2-4 of that spec). HSM groups
// never split: one group per token and one catalog, each small.

#include <raft/persistent_state_machine.hpp>

#include <cstdint>
#include <deque>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace kythira::hsm {

template<kythira::kv_engine Engine, typename LogIndex = std::uint64_t> class persistent_group {
public:
    using engine_type = Engine;

    explicit persistent_group(std::string ns) : _ns(std::move(ns)) {
        if (_ns.empty()) {
            throw std::invalid_argument("hsm group: empty namespace");
        }
    }

    auto open(engine_type& engine, const kythira::key_range& range) -> void {
        _engine = &engine;
        _range = range;
        _ring.clear();
        _applied = 0;
        if (const auto v = _engine->get(kythira::column_family::meta, _ns)) {
            _applied = static_cast<LogIndex>(std::stoull(*v));
        }
        _durable_floor = _applied;
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

    auto sync_durable() -> void { engine().sync(engine().latest_sequence()); }

    auto checkpoint(const std::filesystem::path& dir) -> kythira::snapshot_manifest {
        return engine().checkpoint(engine_range(), dir);
    }

    auto ingest(const std::filesystem::path& dir, const kythira::snapshot_manifest& manifest,
                LogIndex index) -> void {
        engine().ingest(engine_range(), dir, manifest);
        _applied = index;
        _durable_floor = index;
        _ring.clear();
    }

    auto drop() -> void { engine().drop(engine_range()); }

    [[nodiscard]] auto range() const -> const kythira::key_range& { return _range; }
    [[nodiscard]] auto key_prefix() const -> const std::string& { return _ns; }

    /// Every engine key of this group: `[ns, successor(ns))`.
    [[nodiscard]] auto engine_range() const -> kythira::key_range {
        return kythira::key_range{_ns, prefix_end(_ns)};
    }

    /// The smallest key above every key that starts with `prefix`.
    [[nodiscard]] static auto prefix_end(std::string prefix) -> std::optional<std::string> {
        while (!prefix.empty() && static_cast<unsigned char>(prefix.back()) == 0xFF) {
            prefix.pop_back();
        }
        if (prefix.empty()) {
            return std::nullopt;
        }
        prefix.back() = static_cast<char>(static_cast<unsigned char>(prefix.back()) + 1);
        return prefix;
    }

protected:
    /// True when `index` was already applied (a replay after restart).
    [[nodiscard]] auto already_applied(LogIndex index) const -> bool { return index <= _applied; }

    /// Writes `batch` with `index` as the applied index, in one write.
    auto commit(kythira::write_batch& batch, LogIndex index) -> void {
        batch.put(kythira::column_family::meta, _ns, std::to_string(index));
        const auto seq = engine().write(batch);
        _applied = index;
        _ring.emplace_back(index, seq);
        const auto durable_seq = engine().durable_sequence();
        while (_ring.size() > 1 && _ring[1].second <= durable_seq) {
            _durable_floor = _ring.front().first;
            _ring.pop_front();
        }
    }

    [[nodiscard]] auto engine() const -> engine_type& {
        if (_engine == nullptr) {
            throw std::logic_error("hsm group: not opened");
        }
        return *_engine;
    }

    [[nodiscard]] auto get(const std::string& suffix) const -> std::optional<std::string> {
        return engine().get(kythira::column_family::data, _ns + suffix);
    }

    [[nodiscard]] auto key(const std::string& suffix) const -> std::string { return _ns + suffix; }

    /// Visits every data key starting with `ns + prefix`, passing the part
    /// after `ns`.
    template<typename F> auto scan_prefix(const std::string& prefix, F&& f) const -> void {
        const std::string full = _ns + prefix;
        engine().scan(
            kythira::column_family::data, kythira::key_range{full, prefix_end(full)},
            kythira::scan_direction::forward,
            [&](std::string_view k, std::string_view v) { return f(k.substr(_ns.size()), v); });
    }

private:
    std::string _ns;
    engine_type* _engine{nullptr};
    kythira::key_range _range{};
    LogIndex _applied{0};
    LogIndex _durable_floor{0};
    std::deque<std::pair<LogIndex, kythira::engine_sequence>> _ring;
};

/// `v` as 8 big-endian bytes, so engine keys sort by number.
[[nodiscard]] inline auto be64_key(std::uint64_t v) -> std::string {
    std::string out(8, '\0');
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = static_cast<char>(v & 0xFFU);
        v >>= 8U;
    }
    return out;
}

[[nodiscard]] inline auto from_be64_key(std::string_view k) -> std::uint64_t {
    std::uint64_t v = 0;
    for (char c : k.substr(0, 8)) {
        v = (v << 8U) | static_cast<unsigned char>(c);
    }
    return v;
}

}  // namespace kythira::hsm
