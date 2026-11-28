// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The time floor and the issuing-clock checks (.kiro/specs/az-cold-start/
// Requirement 10, task 11).
//
// After a whole-AZ power loss a node can come back with its clock in 1970
// (a dead RTC battery) or in the future (a bad RTC), and the internet may
// not be reachable to correct it. Raft does not care: its timers are
// monotonic (Requirement 10.5). Certificates do. Two defences:
//
//   - The time floor: the newest time the bootstrap tier is known to have
//     passed. The bootstrap tier commits its clock as the floor every ten
//     minutes (Requirement 10.2), so after an outage of any length the
//     floor is at most ten minutes behind the time power was lost. A clock
//     below the floor is certainly wrong.
//   - The time sources: at least two local sources in different power
//     domains (`time_sources` in config/cold_start_graph.yaml,
//     Requirement 10.1). A clock more than five minutes ahead of their
//     median is wrong the other way (Requirement 10.4).
//
// A node that issues certificates or signs standing records checks its
// clock with check_issuing_clock() before every issuance and refuses while
// the verdict is not `ok` (Requirement 10.3). It commits a new floor only
// from a clock that passes the same check, so a node with a wrong clock
// can never drag the floor into the future.
//
// Everything here is plain logic over values the caller supplies (the
// floor from its replicated state, the samples from its sources, "now" from
// its clock), so it is shared by the CA, the metal data layer and anything
// else that issues, and tested without clocks.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace raft {

/// Unix seconds; the floor's unit on the wire and in every record.
using unix_seconds = std::int64_t;

/// How often the bootstrap tier commits the floor (Requirement 10.2).
inline constexpr std::chrono::minutes time_floor_commit_interval{10};

/// How far ahead of its time sources' median a clock may be and still
/// issue (Requirement 10.4).
inline constexpr std::chrono::minutes max_clock_ahead_of_sources{5};

[[nodiscard]] inline auto to_unix_seconds(std::chrono::system_clock::time_point t) noexcept
    -> unix_seconds {
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

/// The newest floor a node knows. It only rises: an older floor is still
/// a true lower bound, so observing one changes nothing. value() and
/// observe() are safe from any thread.
class time_floor {
public:
    time_floor() = default;
    explicit time_floor(unix_seconds initial) noexcept : _floor{initial} {}

    /// True if `floor` raised it.
    auto observe(unix_seconds floor) noexcept -> bool {
        auto current = _floor.load(std::memory_order_acquire);
        while (floor > current) {
            if (_floor.compare_exchange_weak(current, floor, std::memory_order_acq_rel)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto value() const noexcept -> unix_seconds {
        return _floor.load(std::memory_order_acquire);
    }

private:
    std::atomic<unix_seconds> _floor{0};
};

/// One reading of a time source: how far the source's clock was from the
/// local clock when it was read (positive: the source is ahead).
struct time_source_sample {
    std::string source;  ///< its name in the cold-start graph's time_sources
    std::chrono::milliseconds offset{0};
};

/// The median of the samples' offsets (the mean of the middle two for an
/// even count), or nothing without samples. A median rather than a mean,
/// so that with three or more sources one wrong source cannot move it far.
[[nodiscard]] inline auto median_offset(std::vector<time_source_sample> samples)
    -> std::optional<std::chrono::milliseconds> {
    if (samples.empty()) {
        return std::nullopt;
    }
    std::ranges::sort(samples, {}, &time_source_sample::offset);
    const auto n = samples.size();
    if (n % 2 == 1) {
        return samples[n / 2].offset;
    }
    return (samples[(n / 2) - 1].offset + samples[n / 2].offset) / 2;
}

enum class clock_verdict : std::uint8_t {
    ok,
    below_floor,       ///< Requirement 10.3: older than a time already passed
    ahead_of_sources,  ///< Requirement 10.4: more than 5 minutes ahead
};

[[nodiscard]] constexpr auto to_string(clock_verdict v) noexcept -> std::string_view {
    switch (v) {
        case clock_verdict::ok:
            return "ok";
        case clock_verdict::below_floor:
            return "clock_below_time_floor";
        case clock_verdict::ahead_of_sources:
            return "clock_ahead_of_time_sources";
    }
    return "unknown";
}

/// What a node reports about its clock (Requirement 10.3, "and SHALL
/// report the skew"), exported as metrics by the caller.
struct clock_check {
    clock_verdict verdict{clock_verdict::ok};
    /// How far the clock is below the floor; zero when it is not.
    std::chrono::seconds below_floor_by{0};
    /// The time sources' median offset from the local clock (positive: the
    /// clock is behind them), or nothing when no source answered.
    std::optional<std::chrono::milliseconds> source_offset;
    /// How many sources answered.
    std::size_t sources{0};

    [[nodiscard]] auto ok() const noexcept -> bool { return verdict == clock_verdict::ok; }
};

/// Checks a clock reading `now` against the floor and the time sources.
/// With no samples only the floor applies: Requirement 10.1 asks for two
/// local sources, but a node whose sources are all down must still be able
/// to tell a clock in 1970, and refusing every issuance until a source
/// answers would make the sources a cold-start dependency of the CA.
[[nodiscard]] inline auto check_issuing_clock(
    std::chrono::system_clock::time_point now, unix_seconds floor,
    const std::vector<time_source_sample>& samples,
    std::chrono::milliseconds max_ahead = max_clock_ahead_of_sources) -> clock_check {
    clock_check c;
    const auto now_s = to_unix_seconds(now);
    c.sources = samples.size();
    c.source_offset = median_offset(samples);
    if (now_s < floor) {
        c.verdict = clock_verdict::below_floor;
        c.below_floor_by = std::chrono::seconds{floor - now_s};
        return c;
    }
    // The clock is ahead of the sources when their offset is negative.
    if (c.source_offset && -*c.source_offset > max_ahead) {
        c.verdict = clock_verdict::ahead_of_sources;
    }
    return c;
}

/// When the bootstrap tier's leader commits the next floor. The schedule
/// runs on the steady clock, so a wall-clock step during recovery never
/// changes it (Requirement 10.5).
class time_floor_schedule {
public:
    explicit time_floor_schedule(
        std::chrono::steady_clock::duration interval = time_floor_commit_interval) noexcept
        : _interval{interval} {}

    /// Whether a commit is due at `steady_now`: immediately after reset()
    /// (a new leader), then once per interval after each success.
    [[nodiscard]] auto due(std::chrono::steady_clock::time_point steady_now) const noexcept
        -> bool {
        return !_last || steady_now - *_last >= _interval;
    }

    /// The floor to commit when due: the clock reading, but only from a
    /// clock that passed check_issuing_clock(), and never below the floor
    /// already committed. Nothing when there is nothing to commit.
    [[nodiscard]] static auto next_floor(const clock_check& check,
                                         std::chrono::system_clock::time_point now,
                                         unix_seconds committed) noexcept
        -> std::optional<unix_seconds> {
        if (!check.ok()) {
            return std::nullopt;
        }
        const auto now_s = to_unix_seconds(now);
        if (now_s <= committed) {
            return std::nullopt;
        }
        return now_s;
    }

    auto committed(std::chrono::steady_clock::time_point steady_now) noexcept -> void {
        _last = steady_now;
    }
    /// A new leader commits at once: the old leader may have been silent
    /// for most of an interval before it lost the lease.
    auto reset() noexcept -> void { _last.reset(); }

private:
    std::chrono::steady_clock::duration _interval;
    std::optional<std::chrono::steady_clock::time_point> _last;
};

}  // namespace raft
