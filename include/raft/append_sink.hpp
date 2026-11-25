// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file append_sink.hpp
/// @brief The append sink: a state machine takes an entry's payload at
///        append time, and the log stores only a descriptor of it.
///
/// See `.kiro/specs/khold-block-service/` task 3 and design "Core changes"
/// (Requirement 7.4). khold writes block payloads once, to its block store,
/// while the Raft log carries only the entry descriptor (LBA range, CRCs).
/// Writing every block into the log and again into the store would double
/// the write cost of the hottest path and keep the payload on disk twice.
///
/// **The hook is a persistence-engine adaptor, not a change to `node`.**
/// `append_sink_persistence<Engine, Sink>` is itself a `persistence_engine`:
///
///   - on append it hands each `normal` entry to the sink, which takes the
///     payload and returns the entry to store (its descriptor), and appends
///     that to the wrapped engine;
///   - on read it asks the sink to put the payload back (`rehydrate`), so the
///     node, its in-memory log, replication and the state machine's `apply`
///     see exactly the entries they would without a sink, including after a
///     restart that reloads the log from storage;
///   - on truncation and compaction it tells the sink which payloads are
///     gone.
///
/// A node built without the adaptor runs exactly the code it ran before,
/// so no existing state machine changes. A node whose state machine wants
/// payloads at append time wraps its engine in the adaptor. Entries of any
/// other type (configuration, no-op, split and merge records) bypass the
/// sink: the node reads them back from storage itself and must find them
/// intact.
///
/// **One durable point covers both stores.** An append is durable only when
/// its payload and its descriptor both are, and a payload is always durable
/// no later than its descriptor:
///
///   - over an engine whose appends are durable when they return (no
///     barrier extension, or `durability_class::synchronous`), the adaptor
///     calls `sink.sync()` after the sink takes the payload and before the
///     descriptor is appended;
///   - over a barriered engine, `barrier_through` calls `sink.sync()` first
///     and then the engine's barrier, so a group commit stays one sink sync
///     plus one log barrier however many entries it covers;
///   - over a batched engine, `commit_batch` does the same.
///
/// A crash can therefore leave a descriptor on disk whose payload never
/// reached it, but only for an entry no barrier covered, which the node
/// never acknowledged. Construction finds the lowest such entry and
/// truncates the log from there (`recover`), so a restarted node never
/// reads a descriptor without its payload.

#include <raft/exceptions.hpp>
#include <raft/group_storage.hpp>
#include <raft/persistence.hpp>
#include <raft/types.hpp>

#include <concepts>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace kythira {

/// @brief What a state machine provides to take payloads at append time.
///
/// Every call is made with the persistence engine's caller holding whatever
/// lock the node holds around persistence, in log order.
///
/// - `on_append(entry)`: take `entry`'s payload and return the entry to store
///   in the log in its place, with the same term, index and type. The
///   payload need not be durable when it returns; `sync()` makes it so. An
///   entry that is already a descriptor (one a witness receives) is returned
///   as it is.
/// - `has_payload(stored)`: whether the payload of a stored entry is on the
///   sink's durable media. Used only by recovery.
/// - `rehydrate(stored)`: the full entry for a stored one, or `nullopt` when
///   the payload is gone.
/// - `sync()`: make every payload taken so far durable.
/// - `on_truncate(index)`: forget the payloads of entries at `index` and
///   above (a leader overwrote them, or a snapshot replaced the log).
/// - `release_before(index)`: the log no longer holds entries below `index`;
///   their payloads may go once the state machine no longer needs them.
template<typename S, typename LogEntry, typename LogIndex>
concept append_sink = requires(S& sink, const LogEntry& entry, LogIndex index) {
    { sink.on_append(entry) } -> std::same_as<LogEntry>;
    { sink.has_payload(entry) } -> std::same_as<bool>;
    { sink.rehydrate(entry) } -> std::same_as<std::optional<LogEntry>>;
    { sink.sync() } -> std::same_as<void>;
    { sink.on_truncate(index) } -> std::same_as<void>;
    { sink.release_before(index) } -> std::same_as<void>;
};

/// @brief A `persistence_engine` that routes `normal` entries' payloads to an
///        append sink and stores their descriptors in `Engine`.
///
/// The sink is shared (`std::shared_ptr`) because a node takes its engine by
/// value while the state machine that owns the payloads lives beside it.
/// The optional extensions (barrier, bulk append, hard state, batching) are
/// forwarded exactly when `Engine` has them, as `group_scoped_persistence`
/// does, so wrapping an engine never silently drops its barrier.
///
/// @tparam Engine Must satisfy `persistence_engine`.
/// @tparam Sink   Must satisfy `append_sink` for `Engine`'s entries.
template<typename Engine, typename Sink> class append_sink_persistence {
public:
    using engine_type = Engine;
    using sink_type = Sink;
    using log_entry_t = typename Engine::log_entry_t;
    using snapshot_t = typename Engine::snapshot_t;
    using log_index_t = decltype(std::declval<const log_entry_t&>().index());

    static_assert(append_sink<Sink, log_entry_t, log_index_t>,
                  "Sink must satisfy kythira::append_sink for this engine's log entries");

    /// @brief Wrap @p engine, then recover: truncate the log from the lowest
    ///        entry whose descriptor survived a crash without its payload.
    append_sink_persistence(Engine engine, std::shared_ptr<Sink> sink)
        : _engine(std::move(engine)), _sink(std::move(sink)) {
        if (!_sink) {
            throw std::invalid_argument("append_sink_persistence: null sink");
        }
        _recovered_from = recover();
    }

    [[nodiscard]] auto engine() -> Engine& { return _engine; }
    [[nodiscard]] auto engine() const -> const Engine& { return _engine; }
    [[nodiscard]] auto sink() const -> const std::shared_ptr<Sink>& { return _sink; }

    /// @brief The index recovery truncated the log from, or `nullopt` when
    ///        every stored entry had its payload.
    [[nodiscard]] auto recovered_from() const -> std::optional<log_index_t> {
        return _recovered_from;
    }

    // ── persistence_engine ───────────────────────────────────────────────────

    template<typename TermId> auto save_current_term(TermId term) -> void {
        _engine.save_current_term(term);
    }
    auto load_current_term() { return _engine.load_current_term(); }

    template<typename NodeId> auto save_voted_for(NodeId node) -> void {
        _engine.save_voted_for(std::move(node));
    }
    auto load_voted_for() { return _engine.load_voted_for(); }

    auto append_log_entry(const log_entry_t& entry) -> void {
        if (!takes_payload(entry)) {
            _engine.append_log_entry(entry);
            return;
        }
        auto stored = take(entry);
        guarded(entry.index(), [&] {
            if (appends_are_durable()) {
                _sink->sync();
            }
            _engine.append_log_entry(stored);
        });
    }

    template<typename LogIndex> auto get_log_entry(LogIndex index) -> std::optional<log_entry_t> {
        auto stored = _engine.get_log_entry(index);
        if (!stored) {
            return stored;
        }
        return full(std::move(*stored));
    }

    template<typename LogIndex>
    auto get_log_entries(LogIndex start, LogIndex end) -> std::vector<log_entry_t> {
        auto entries = _engine.get_log_entries(start, end);
        for (auto& e : entries) {
            e = full(std::move(e));
        }
        return entries;
    }

    auto get_last_log_index() { return _engine.get_last_log_index(); }

    /// Payloads first: a crash between the two leaves descriptors at and
    /// above @p index without payloads, which recovery truncates anyway.
    template<typename LogIndex> auto truncate_log(LogIndex index) -> void {
        _sink->on_truncate(static_cast<log_index_t>(index));
        _engine.truncate_log(index);
    }

    auto save_snapshot(const snapshot_t& snap) -> void { _engine.save_snapshot(snap); }
    auto load_snapshot() { return _engine.load_snapshot(); }

    /// Descriptors first: a payload outliving its descriptor is harmless, a
    /// descriptor outliving its payload is what recovery has to repair.
    template<typename LogIndex> auto delete_log_entries_before(LogIndex index) -> void {
        _engine.delete_log_entries_before(index);
        _sink->release_before(static_cast<log_index_t>(index));
    }

    // ── bulk_append / hard_state, conditionally ──────────────────────────────

    /// One sink sync for the run (when appends must be durable on return),
    /// then one bulk append of the descriptors. If either throws, the
    /// payloads taken for the run are forgotten, so the sink and the engine
    /// agree that none of the run was stored, as the bulk contract requires.
    auto append_log_entries(std::span<const log_entry_t> entries) -> void
    requires bulk_append_persistence_engine<Engine>
    {
        if (entries.empty()) {
            _engine.append_log_entries(entries);
            return;
        }
        std::vector<log_entry_t> stored;
        stored.reserve(entries.size());
        bool took = false;
        guarded(entries.front().index(), [&] {
            for (const auto& e : entries) {
                if (takes_payload(e)) {
                    stored.push_back(_sink->on_append(e));
                    took = true;
                } else {
                    stored.push_back(e);
                }
            }
            if (took && appends_are_durable()) {
                _sink->sync();
            }
            _engine.append_log_entries(std::span<const log_entry_t>(stored));
        });
    }

    template<typename TermId, typename NodeId>
    auto save_hard_state(TermId term, std::optional<NodeId> vote) -> void
    requires hard_state_persistence_engine<Engine>
    {
        _engine.save_hard_state(term, std::move(vote));
    }

    // ── barriered_persistence_engine, conditionally ──────────────────────────

    auto append_log_entry_sequenced(const log_entry_t& entry) -> write_sequence
    requires barriered_persistence_engine<Engine>
    {
        if (!takes_payload(entry)) {
            return _engine.append_log_entry_sequenced(entry);
        }
        auto stored = take(entry);
        write_sequence seq{};
        guarded(entry.index(), [&] {
            if (appends_are_durable()) {
                _sink->sync();
            }
            seq = _engine.append_log_entry_sequenced(stored);
        });
        return seq;
    }

    /// The sink's sync first, so every payload is durable no later than the
    /// descriptors the barrier covers.
    auto barrier_through(write_sequence seq) -> void
    requires barriered_persistence_engine<Engine>
    {
        _sink->sync();
        _engine.barrier_through(seq);
    }

    [[nodiscard]] auto durable_through() const -> write_sequence
    requires barriered_persistence_engine<Engine>
    {
        return _engine.durable_through();
    }

    [[nodiscard]] auto durability() const -> durability_class
    requires barriered_persistence_engine<Engine>
    {
        return _engine.durability();
    }

    // ── batched_persistence_engine, conditionally ────────────────────────────

    auto begin_batch() -> void
    requires batched_persistence_engine<Engine>
    {
        _engine.begin_batch();
    }
    auto commit_batch() -> void
    requires batched_persistence_engine<Engine>
    {
        _sink->sync();
        _engine.commit_batch();
    }
    auto abort_batch() -> void
    requires batched_persistence_engine<Engine>
    {
        _engine.abort_batch();
    }

private:
    [[nodiscard]] static auto takes_payload(const log_entry_t& entry) -> bool {
        return entry.type() == entry_type::normal;
    }

    /// Whether the wrapped engine's appends are durable when they return,
    /// so the payload must be synced before the descriptor is appended
    /// rather than at a barrier.
    [[nodiscard]] auto appends_are_durable() const -> bool {
        if constexpr (barriered_persistence_engine<Engine>) {
            return _engine.durability() == durability_class::synchronous;
        } else {
            return true;
        }
    }

    auto take(const log_entry_t& entry) -> log_entry_t {
        auto stored = _sink->on_append(entry);
        if (stored.index() != entry.index() || stored.term() != entry.term() ||
            stored.type() != entry.type()) {
            _sink->on_truncate(entry.index());
            throw std::logic_error(
                "append sink returned an entry with a different term, index or type");
        }
        return stored;
    }

    /// Runs @p f; if it throws, forgets the payloads taken from @p first on,
    /// so the sink never holds a payload for an entry the engine refused.
    template<typename F> auto guarded(log_index_t first, F&& f) -> void {
        try {
            std::forward<F>(f)();
        } catch (...) {
            _sink->on_truncate(first);
            throw;
        }
    }

    auto full(log_entry_t stored) -> log_entry_t {
        if (!takes_payload(stored)) {
            return stored;
        }
        auto e = _sink->rehydrate(stored);
        if (!e) {
            // Recovery removed every descriptor whose payload a crash lost,
            // so this is a sink that dropped a payload the log still holds.
            throw persistence_exception("append sink lost the payload of a stored log entry");
        }
        return std::move(*e);
    }

    /// Walks the stored log down from its last entry to the first one the
    /// engine still holds, finds the lowest `normal` entry whose payload is
    /// not on the sink's media, and truncates the log from there.
    ///
    /// Why from the lowest and not just the tail: payloads above the last
    /// barrier may reach the media in any order, so a present payload can
    /// sit above a missing one. Everything from the lowest missing payload up
    /// was never covered by a barrier (a barrier syncs every payload taken
    /// before it), so the node never acknowledged any of it and dropping it
    /// all is safe. The walk costs one `has_payload` per stored entry, once,
    /// at start-up; compaction keeps the log short.
    auto recover() -> std::optional<log_index_t> {
        const auto last = static_cast<log_index_t>(_engine.get_last_log_index());
        std::optional<log_index_t> lowest_missing;
        for (auto i = last; i > 0; --i) {
            auto stored = _engine.get_log_entry(i);
            if (!stored) {
                break;
            }
            if (takes_payload(*stored) && !_sink->has_payload(*stored)) {
                lowest_missing = i;
            }
        }
        if (lowest_missing) {
            _sink->on_truncate(*lowest_missing);
            _engine.truncate_log(*lowest_missing);
        }
        return lowest_missing;
    }

    Engine _engine;
    std::shared_ptr<Sink> _sink;
    std::optional<log_index_t> _recovered_from;
};

}  // namespace kythira
