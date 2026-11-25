// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file segment_store_move.hpp
/// @brief The in-place store move: a replica's record segments go from its
///        local directory to a segment node's volume, or back, without
///        replacing the replica
///        (.kiro/specs/kinesis-independent-layers/ task 13, design
///        "Migration", Requirement 11.5).
///
/// A state machine holds a `movable_segment_store` where it held its store.
/// Every call is forwarded to the store underneath under a shared lock, so
/// nothing changes while no move runs. `move_to()` then moves the bytes in
/// three steps:
///
/// 1. **Copy outside the fence.** Sealed segments are installed whole (the
///    store checks each against the descriptor's SHA-256), and each active
///    segment's prefix as far as it is written. Writes go on meanwhile.
///    Rounds repeat until what is left (the tail written since the last
///    round) is at most `_max_fence_bytes`. A store that keeps outrunning
///    the copy is refused after `_max_rounds`: nothing has switched and the
///    old store keeps serving.
/// 2. **Fence.** The exclusive lock stops every store call, which is how a
///    replica's apply loop pauses: an entry's appends and its barrier are
///    store calls, so none is in flight. The bound is checked again under
///    the lock; above it, the lock is released and another round runs. The
///    tail is copied by appending the missing records to the target's
///    active segment (the same appends produce the same bytes), sealing
///    where the source sealed, and falling back to a whole-segment install
///    where the result does not match. The target is made durable and must
///    then describe every segment exactly as the source does, or the move
///    is refused and the old store kept.
/// 3. **Switch.** The target becomes the store, `on_switch` runs (the
///    Kinesis node writes its new volume assignment through Raft there),
///    and the fence lifts. The pause, the time the lock was held, is in the
///    report.
///
/// The old store is handed back; the caller decides whether to drop its
/// copy. A target that already holds an older copy (a move back to a
/// directory that was moved away from) is reconciled, not refilled: only
/// what differs is copied, and what the source no longer has is removed.

#include <raft/segment_store.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

struct segment_store_move_options {
    /// Copy rounds outside the fence before the move is refused.
    std::size_t _max_rounds = 8;
    /// The most bytes the fence may copy. The fence starts only when the
    /// tail left after a round is at most this.
    std::uint64_t _max_fence_bytes = std::uint64_t{4} * 1024 * 1024;
    /// The most bytes one call to the target may carry. A segment larger
    /// than this is copied by appending its records in batches of at most
    /// this size (sealing where the source sealed) instead of one install,
    /// so a target behind a request size limit (a volume on a segment
    /// node, whose gateway caps request bodies) still takes it.
    std::uint64_t _max_call_bytes = std::uint64_t{4} * 1024 * 1024;
};

/// What a move did, and the pause it cost.
struct segment_store_move_report {
    /// Copy rounds outside the fence, the fence's own pass not counted.
    std::size_t _rounds = 0;
    /// Times the fence was taken and released again because the tail had
    /// grown past the bound.
    std::size_t _fence_retries = 0;
    std::uint64_t _streams = 0;
    /// Sealed segments installed whole outside the fence.
    std::uint64_t _sealed_segments = 0;
    std::uint64_t _sealed_bytes = 0;
    /// Active segment prefixes installed outside the fence, in bytes.
    std::uint64_t _prefix_bytes = 0;
    /// What the fence copied: records appended, and bytes moved by appends
    /// and by any whole-segment installs it fell back to.
    std::uint64_t _fence_records = 0;
    std::uint64_t _fence_bytes = 0;
    /// Segments the fence installed whole because appending did not
    /// reproduce the source's bytes.
    std::uint64_t _fence_installs = 0;
    /// How long store calls were held: the replica's apply pause.
    std::chrono::microseconds _pause{0};
};

/// The move did not happen and the old store still serves: another move is
/// running, the tail never came under the bound, or the target did not end
/// up identical.
class segment_store_move_refused : public record_segment_error {
public:
    using record_segment_error::record_segment_error;
};

namespace detail::store_move {

/// Bytes `to` lacks of `from`'s segments: for a segment `to` holds as a
/// shorter copy, the difference; for one it lacks, all of it.
[[nodiscard]] inline auto remaining_bytes(const segment_store& from, const segment_store& to)
    -> std::uint64_t {
    std::uint64_t left = 0;
    for (const auto& stream : from.streams()) {
        std::map<std::uint64_t, record_segment_descriptor> have;
        for (auto& d : to.local_segments(stream)) {
            have.emplace(d._first_seq, std::move(d));
        }
        for (const auto& d : from.local_segments(stream)) {
            const auto it = have.find(d._first_seq);
            if (it == have.end()) {
                left += d._bytes;
            } else if (!(it->second == d)) {
                left += d._bytes > it->second._bytes ? d._bytes - it->second._bytes : d._bytes;
            }
        }
    }
    return left;
}

/// Installs `d` whole from `from`; false when the source changed under the
/// read (a truncation, a roll) so the bytes no longer match.
inline auto install_whole(const segment_store& from, segment_store& to,
                          const record_segment_descriptor& d) -> bool {
    auto bytes = from.read_segment_bytes(d._stream, d._first_seq, d._bytes);
    if (!bytes || bytes->size() != d._bytes) {
        return false;
    }
    try {
        (void)to.install_segment(d, *bytes);
    } catch (const std::invalid_argument&) {
        return false;
    }
    return true;
}

/// Appends `from`'s records of segment `d` above `after` to `to`'s active
/// segment, then seals if `d` is sealed. Returns the records appended, or
/// nullopt when `to` rolled somewhere `from` did not (the caller installs
/// instead).
inline auto append_tail(const segment_store& from, segment_store& to,
                        const record_segment_descriptor& d, std::optional<std::uint64_t> after,
                        std::uint64_t& bytes, std::uint64_t max_call_bytes)
    -> std::optional<std::uint64_t> {
    std::uint64_t appended = 0;
    std::uint64_t next = after ? *after + 1 : d._first_seq;
    // One read is one append: its records stay under the call bound. A
    // record larger than the bound still goes alone (the read returns at
    // least one).
    const segment_read_limits limits{._max_records = 10'000, ._max_bytes = max_call_bytes};
    while (next <= d._last_seq) {
        auto r = from.read_segment(d._stream, d._first_seq, next, limits);
        if (!r || r->_records.empty()) {
            break;
        }
        std::vector<segment_record_view> views;
        views.reserve(r->_records.size());
        for (const auto& rec : r->_records) {
            if (rec._seq > d._last_seq) {
                break;
            }
            views.push_back({rec._seq, rec._timestamp_ms, rec._data});
            bytes += rec._data.size();
        }
        if (views.empty()) {
            break;
        }
        const auto res = to.append(d._stream, views);
        appended += views.size();
        if (!res._sealed.empty()) {
            // The target rolled on its own: its options differ from the
            // source's, so its files would not match. Not a tail copy.
            return std::nullopt;
        }
        next = r->_next_seq;
    }
    if (d._sealed) {
        (void)to.seal(d._stream);
    }
    return appended;
}

}  // namespace detail::store_move

/// A `segment_store` whose store underneath can be swapped for another
/// holding the same segments. See the file comment.
class movable_segment_store final : public segment_store {
public:
    explicit movable_segment_store(std::unique_ptr<segment_store> inner)
        : _inner(std::move(inner)) {
        if (!_inner) {
            throw std::invalid_argument("movable_segment_store: no store");
        }
    }

    movable_segment_store(const movable_segment_store&) = delete;
    auto operator=(const movable_segment_store&) -> movable_segment_store& = delete;
    movable_segment_store(movable_segment_store&&) = delete;
    auto operator=(movable_segment_store&&) -> movable_segment_store& = delete;
    ~movable_segment_store() override = default;

    /// Whether a move is running.
    [[nodiscard]] auto moving() const -> bool { return _moving.load(std::memory_order_acquire); }

    /// Runs `f` on the store underneath, as one more store call.
    template<typename F> auto with_inner(F&& f) const {
        const std::shared_lock lock(_mu);
        return std::forward<F>(f)(*_inner);
    }

    /// Moves every segment to `target` and makes it the store; returns
    /// what it did and the old store. Throws `segment_store_move_refused`,
    /// with the old store still in place, when it cannot. `on_switch` runs
    /// under the fence, after the target matches and before the switch; a
    /// throw from it refuses the move.
    auto move_to(std::unique_ptr<segment_store> target, const segment_store_move_options& options,
                 const std::function<void(segment_store& from, segment_store& to)>& on_switch = {})
        -> std::pair<segment_store_move_report, std::unique_ptr<segment_store>> {
        namespace m = detail::store_move;
        if (!target) {
            throw std::invalid_argument("movable_segment_store: no target store");
        }
        if (_moving.exchange(true, std::memory_order_acq_rel)) {
            throw segment_store_move_refused("segment store move: another move is running");
        }
        struct clear_on_exit {
            std::atomic<bool>& flag;
            explicit clear_on_exit(std::atomic<bool>& f) : flag(f) {}
            clear_on_exit(const clear_on_exit&) = delete;
            auto operator=(const clear_on_exit&) -> clear_on_exit& = delete;
            clear_on_exit(clear_on_exit&&) = delete;
            auto operator=(clear_on_exit&&) -> clear_on_exit& = delete;
            ~clear_on_exit() { flag.store(false, std::memory_order_release); }
        } clear{_moving};

        segment_store_move_report report;
        // The store underneath changes only under the exclusive lock, which
        // only this function takes, and `_moving` keeps a second one out: a
        // plain read of `_inner` is safe here.
        segment_store& from = *_inner;
        for (;;) {
            if (report._rounds >= options._max_rounds) {
                throw segment_store_move_refused("segment store move: the tail was still " +
                                                 std::to_string(m::remaining_bytes(from, *target)) +
                                                 " bytes after " + std::to_string(report._rounds) +
                                                 " rounds, above the fence bound of " +
                                                 std::to_string(options._max_fence_bytes));
            }
            copy_round(from, *target, options, report);
            ++report._rounds;
            if (m::remaining_bytes(from, *target) > options._max_fence_bytes) {
                continue;
            }
            const std::unique_lock lock(_mu);
            const auto fenced_at = std::chrono::steady_clock::now();
            if (m::remaining_bytes(from, *target) > options._max_fence_bytes) {
                // Writes outran the last round between its end and the
                // fence: let them go on and copy again.
                ++report._fence_retries;
                report._pause += pause_since(fenced_at);
                continue;
            }
            try {
                fenced_round(from, *target, options, report);
                target->barrier();
                verify_identical(from, *target);
                if (on_switch) {
                    on_switch(from, *target);
                }
            } catch (const segment_store_move_refused&) {
                report._pause += pause_since(fenced_at);
                throw;
            } catch (const std::exception& e) {
                report._pause += pause_since(fenced_at);
                throw segment_store_move_refused(std::string("segment store move: ") + e.what());
            }
            std::swap(_inner, target);
            report._pause += pause_since(fenced_at);
            return {report, std::move(target)};
        }
    }

    // ---- segment_store, forwarded ------------------------------------------

    [[nodiscard]] auto max_record_bytes() const noexcept -> std::uint32_t override {
        const std::shared_lock lock(_mu);
        return _inner->max_record_bytes();
    }

    auto append(const std::string& stream, std::span<const segment_record_view> records)
        -> record_segment_append_result override {
        const std::shared_lock lock(_mu);
        return _inner->append(stream, records);
    }

    using segment_store::append;

    void barrier() override {
        const std::shared_lock lock(_mu);
        _inner->barrier();
    }

    auto seal(const std::string& stream) -> std::optional<record_segment_descriptor> override {
        const std::shared_lock lock(_mu);
        return _inner->seal(stream);
    }

    void truncate_after(const std::string& stream, std::optional<std::uint64_t> seq) override {
        const std::shared_lock lock(_mu);
        _inner->truncate_after(stream, seq);
    }

    auto trim_before(const std::string& stream, std::uint64_t seq)
        -> std::vector<std::uint64_t> override {
        const std::shared_lock lock(_mu);
        return _inner->trim_before(stream, seq);
    }

    auto remove_segment(const std::string& stream, std::uint64_t first_seq) -> bool override {
        const std::shared_lock lock(_mu);
        return _inner->remove_segment(stream, first_seq);
    }

    void drop_stream(const std::string& stream) override {
        const std::shared_lock lock(_mu);
        _inner->drop_stream(stream);
    }

    auto install_segment(const record_segment_descriptor& d, std::span<const std::byte> bytes)
        -> bool override {
        const std::shared_lock lock(_mu);
        return _inner->install_segment(d, bytes);
    }

    auto fetch_segment(const record_segment_descriptor& d, std::span<const std::string> peers,
                       const fetch_transport& transport) -> bool override {
        const std::shared_lock lock(_mu);
        return _inner->fetch_segment(d, peers, transport);
    }

    [[nodiscard]] auto read_segment_bytes(const std::string& stream, std::uint64_t first_seq,
                                          std::uint64_t length) const
        -> std::optional<std::vector<std::byte>> override {
        const std::shared_lock lock(_mu);
        return _inner->read_segment_bytes(stream, first_seq, length);
    }

    [[nodiscard]] auto read_segment(const std::string& stream, std::uint64_t first_seq,
                                    std::uint64_t from_seq, const segment_read_limits& limits) const
        -> std::optional<segment_read_result> override {
        const std::shared_lock lock(_mu);
        return _inner->read_segment(stream, first_seq, from_seq, limits);
    }

    using segment_store::read_segment;

    [[nodiscard]] auto read(const std::string& stream, std::uint64_t from_seq,
                            const segment_read_limits& limits) const
        -> segment_read_result override {
        const std::shared_lock lock(_mu);
        return _inner->read(stream, from_seq, limits);
    }

    using segment_store::read;

    [[nodiscard]] auto describe(const std::string& stream, std::uint64_t first_seq) const
        -> std::optional<record_segment_descriptor> override {
        const std::shared_lock lock(_mu);
        return _inner->describe(stream, first_seq);
    }

    [[nodiscard]] auto local_segments(const std::string& stream) const
        -> std::vector<record_segment_descriptor> override {
        const std::shared_lock lock(_mu);
        return _inner->local_segments(stream);
    }

    [[nodiscard]] auto has_segment(const record_segment_descriptor& d) const -> bool override {
        const std::shared_lock lock(_mu);
        return _inner->has_segment(d);
    }

    [[nodiscard]] auto last_seq(const std::string& stream) const
        -> std::optional<std::uint64_t> override {
        const std::shared_lock lock(_mu);
        return _inner->last_seq(stream);
    }

    [[nodiscard]] auto streams() const -> std::vector<std::string> override {
        const std::shared_lock lock(_mu);
        return _inner->streams();
    }

    [[nodiscard]] auto stats() const -> record_segment_store_stats override {
        const std::shared_lock lock(_mu);
        return _inner->stats();
    }

private:
    [[nodiscard]] static auto pause_since(std::chrono::steady_clock::time_point t)
        -> std::chrono::microseconds {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t);
    }

    /// One pass outside the fence: whole sealed segments and active
    /// prefixes, and removal of what the source no longer holds. A segment
    /// that changes under its read is left for the next round.
    static void copy_round(const segment_store& from, segment_store& to,
                           const segment_store_move_options& options,
                           segment_store_move_report& report) {
        namespace m = detail::store_move;
        const auto streams = from.streams();
        report._streams = streams.size();
        for (const auto& stream : streams) {
            std::map<std::uint64_t, record_segment_descriptor> have;
            for (auto& d : to.local_segments(stream)) {
                have.emplace(d._first_seq, std::move(d));
            }
            const auto src = from.local_segments(stream);
            std::set<std::uint64_t> wanted;
            for (const auto& d : src) {
                wanted.insert(d._first_seq);
            }
            // Stale copies first, so an active segment installed below is
            // the stream's last in the target as the store requires.
            for (const auto& [first, d] : have) {
                if (!wanted.contains(first)) {
                    drop_copy(to, d);
                }
            }
            for (const auto& d : src) {
                const auto it = have.find(d._first_seq);
                if (it != have.end() && it->second == d) {
                    continue;
                }
                if (d._bytes > options._max_call_bytes) {
                    // Too large for one call: append it in batches, onto
                    // the target's shorter active copy or as its new last
                    // segment. A segment that cannot be appended here
                    // waits for a later round (or the fence).
                    std::optional<std::uint64_t> after;
                    if (!appendable(to, stream, d, it == have.end() ? nullptr : &it->second,
                                    after)) {
                        continue;
                    }
                    std::uint64_t bytes = 0;
                    const auto appended =
                        m::append_tail(from, to, d, after, bytes, options._max_call_bytes);
                    if (!appended) {
                        // The target rolled where the source did not: undo
                        // the partial copy so the fence installs it.
                        drop_copy(to, d);
                        continue;
                    }
                    if (d._sealed) {
                        ++report._sealed_segments;
                        report._sealed_bytes += bytes;
                    } else {
                        report._prefix_bytes += bytes;
                    }
                    continue;
                }
                if (!m::install_whole(from, to, d)) {
                    continue;
                }
                if (d._sealed) {
                    ++report._sealed_segments;
                    report._sealed_bytes += d._bytes;
                } else {
                    report._prefix_bytes += d._bytes;
                }
            }
        }
        drop_streams_missing_from(from, to);
    }

    /// The pass under the fence: nothing writes, so every descriptor read
    /// here is final. Tails are appended; anything else is installed.
    static void fenced_round(const segment_store& from, segment_store& to,
                             const segment_store_move_options& options,
                             segment_store_move_report& report) {
        namespace m = detail::store_move;
        for (const auto& stream : from.streams()) {
            std::map<std::uint64_t, record_segment_descriptor> have;
            for (auto& d : to.local_segments(stream)) {
                have.emplace(d._first_seq, std::move(d));
            }
            const auto src = from.local_segments(stream);
            std::set<std::uint64_t> wanted;
            for (const auto& d : src) {
                wanted.insert(d._first_seq);
            }
            for (const auto& [first, d] : have) {
                if (!wanted.contains(first)) {
                    drop_copy(to, d);
                }
            }
            for (const auto& d : src) {
                const auto it = have.find(d._first_seq);
                if (it != have.end() && it->second == d) {
                    continue;
                }
                // A shorter active copy, or none at all past a sealed (or no)
                // segment: append what is missing.
                std::optional<std::uint64_t> after;
                if (appendable(to, stream, d, it == have.end() ? nullptr : &it->second, after)) {
                    std::uint64_t bytes = 0;
                    const auto appended =
                        m::append_tail(from, to, d, after, bytes, options._max_call_bytes);
                    if (appended && to.describe(stream, d._first_seq) == d) {
                        report._fence_records += *appended;
                        report._fence_bytes += bytes;
                        continue;
                    }
                }
                if (!m::install_whole(from, to, d)) {
                    throw segment_store_move_refused("segment store move: segment " + stream + "@" +
                                                     std::to_string(d._first_seq) +
                                                     " did not install under the fence");
                }
                ++report._fence_installs;
                report._fence_bytes += d._bytes;
            }
        }
        drop_streams_missing_from(from, to);
    }

    /// Whether `d` can be copied by appending: `to` holds a shorter active
    /// copy of it (`after` is then that copy's last record, if any), or
    /// none and `d` would be its last segment after sealed ones.
    static auto appendable(const segment_store& to, const std::string& stream,
                           const record_segment_descriptor& d,
                           const record_segment_descriptor* have,
                           std::optional<std::uint64_t>& after) -> bool {
        after.reset();
        if (have != nullptr) {
            if (have->_sealed || have->_last_seq > d._last_seq || have->_bytes > d._bytes) {
                return false;
            }
            if (have->_records > 0) {
                after = have->_last_seq;
            }
            return true;
        }
        return is_last_after_sealed(to, stream, d);
    }

    /// Whether `d` would be `to`'s last segment of `stream`, after only
    /// sealed ones: the only place an append can start a segment.
    static auto is_last_after_sealed(const segment_store& to, const std::string& stream,
                                     const record_segment_descriptor& d) -> bool {
        const auto segs = to.local_segments(stream);
        return std::all_of(segs.begin(), segs.end(),
                           [&](const auto& s) { return s._sealed && s._last_seq < d._first_seq; });
    }

    /// Removes a copy the source no longer has: a sealed segment directly,
    /// an active one by truncating its records away.
    static void drop_copy(segment_store& to, const record_segment_descriptor& d) {
        if (d._sealed) {
            (void)to.remove_segment(d._stream, d._first_seq);
            return;
        }
        to.truncate_after(d._stream, d._first_seq > 0
                                         ? std::optional<std::uint64_t>{d._first_seq - 1}
                                         : std::nullopt);
    }

    static void drop_streams_missing_from(const segment_store& from, segment_store& to) {
        const auto keep = from.streams();
        const std::set<std::string> wanted(keep.begin(), keep.end());
        for (const auto& s : to.streams()) {
            if (!wanted.contains(s)) {
                to.drop_stream(s);
            }
        }
    }

    /// The target holds exactly what the source does, digests included.
    static void verify_identical(const segment_store& from, const segment_store& to) {
        auto a = from.streams();
        auto b = to.streams();
        std::sort(a.begin(), a.end());
        std::sort(b.begin(), b.end());
        if (a != b) {
            throw segment_store_move_refused(
                "segment store move: the target's streams differ from the source's");
        }
        for (const auto& s : a) {
            if (from.local_segments(s) != to.local_segments(s)) {
                throw segment_store_move_refused("segment store move: stream " + s +
                                                 " differs in the target after the fence");
            }
        }
    }

    mutable std::shared_mutex _mu;
    std::unique_ptr<segment_store> _inner;
    std::atomic<bool> _moving{false};
};

}  // namespace kythira
