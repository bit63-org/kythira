// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Recovery mode (.kiro/specs/az-cold-start/ Requirement 7, task 12).
//
// A controller that has just started after a whole-AZ power loss sees
// every host silent. Silence normally means a host died, and the actions
// that follow (declare it lost, replace its replicas, retire its
// instances) are right for one dead host and disastrous for a fleet that is
// still booting. Recovery mode is the mass-silence suspension of
// `.kiro/specs/ec2-controller-scale/` Requirement 8 entered at start-up:
// while it holds, the controller withholds every silence-driven action
// (Requirement 7.2) and keeps doing everything that helps hosts come back
// (7.3).
//
// It is entered when the controller starts with more than the mass-silence
// threshold (5 %) of in-service hosts unlinked, or when the operator starts
// a drill (BeginRecovery). It ends (7.4) when 95 % of in-service hosts have
// reported an inventory, when 30 minutes have passed since the controller
// started, or when the operator calls EndRecovery, whichever comes first.
// Hosts still silent then go to the ordinary rate-limited silence rules,
// never all at once: exit hands the caller the list.
//
// The EC2 controller, khold's controller library and the metal registry
// each hold one recovery_mode and ask allows() before every action in
// recovery_withheld_action. Events and status (7.5) are for the caller to
// record and export; this class only decides. Time is the steady clock, so
// a wall-clock step during recovery changes nothing.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace raft {

/// Actions recovery mode withholds (Requirement 7.2).
enum class recovery_withheld_action : std::uint8_t {
    declare_host_lost,  ///< or failed
    replace_replica,
    mark_impaired_for_silence,  ///< a status check `impaired` because of silence
    stop_or_retire_instance,
    start_drain,
    open_enrollment_window,  ///< automatically; the operator still may
    change_volume_layout,    ///< except restoring a standing attachment
};

[[nodiscard]] constexpr auto to_string(recovery_withheld_action a) noexcept -> std::string_view {
    switch (a) {
        case recovery_withheld_action::declare_host_lost:
            return "declare_host_lost";
        case recovery_withheld_action::replace_replica:
            return "replace_replica";
        case recovery_withheld_action::mark_impaired_for_silence:
            return "mark_impaired_for_silence";
        case recovery_withheld_action::stop_or_retire_instance:
            return "stop_or_retire_instance";
        case recovery_withheld_action::start_drain:
            return "start_drain";
        case recovery_withheld_action::open_enrollment_window:
            return "open_enrollment_window";
        case recovery_withheld_action::change_volume_layout:
            return "change_volume_layout";
    }
    return "unknown";
}

enum class recovery_entry : std::uint8_t {
    mass_silence_at_start,  ///< Requirement 7.1, first case
    operator_drill,         ///< BeginRecovery
};

enum class recovery_exit : std::uint8_t {
    hosts_reported,  ///< at least exit_reported_fraction reported
    timed_out,       ///< max_duration since the controller started
    operator_ended,  ///< EndRecovery
};

[[nodiscard]] constexpr auto to_string(recovery_entry e) noexcept -> std::string_view {
    return e == recovery_entry::mass_silence_at_start ? "mass_silence_at_start" : "operator_drill";
}

[[nodiscard]] constexpr auto to_string(recovery_exit e) noexcept -> std::string_view {
    switch (e) {
        case recovery_exit::hosts_reported:
            return "hosts_reported";
        case recovery_exit::timed_out:
            return "timed_out";
        case recovery_exit::operator_ended:
            return "operator_ended";
    }
    return "unknown";
}

struct recovery_config {
    /// Enter at start when more than this fraction of in-service hosts has
    /// no link (ec2-controller-scale Requirement 8's mass-silence threshold).
    double mass_silence_fraction{0.05};
    /// Leave once at least this fraction has reported an inventory.
    double exit_reported_fraction{0.95};
    /// Leave this long after the controller started, whatever reported.
    std::chrono::steady_clock::duration max_duration{std::chrono::minutes{30}};
};

template<typename HostId> struct recovery_event {
    enum class kind : std::uint8_t {
        entered,
        exited
    } what{kind::entered};
    std::chrono::steady_clock::time_point at{};
    std::optional<recovery_entry> entry;  ///< set for `entered`
    std::optional<recovery_exit> exit;    ///< set for `exited`
    /// For `exited`: the in-service hosts that never reported, which the
    /// caller hands to the rate-limited silence rules.
    std::vector<HostId> still_silent;
};

/// For metrics (Requirement 7.5).
struct recovery_status {
    bool active{false};
    std::size_t in_service{0};
    std::size_t reported{0};
    std::optional<recovery_entry> entry;
    std::optional<recovery_exit> last_exit;
};

/// One controller's recovery mode. Not thread-safe: the controller calls
/// it from its own loop (or under its own lock).
template<typename HostId> class recovery_mode {
public:
    using event = recovery_event<HostId>;
    using event_sink = std::function<void(const event&)>;

    explicit recovery_mode(recovery_config config = {}, event_sink on_event = {})
        : _config{config}, _on_event{std::move(on_event)} {}

    /// At controller start: the in-service hosts and those with a link.
    /// Enters recovery mode if too many are silent. Call once.
    auto start(std::chrono::steady_clock::time_point now, std::set<HostId> in_service,
               const std::set<HostId>& linked) -> void {
        _started_at = now;
        _in_service = std::move(in_service);
        _reported.clear();
        std::size_t silent = 0;
        for (const auto& h : _in_service) {
            if (!linked.contains(h)) {
                ++silent;
            }
        }
        if (!_in_service.empty() &&
            static_cast<double>(silent) >
                _config.mass_silence_fraction * static_cast<double>(_in_service.size())) {
            enter(now, recovery_entry::mass_silence_at_start);
        }
    }

    /// BeginRecovery: a drill. Restarts the clock and forgets who reported,
    /// so the drill measures a full recovery. Nothing if already active.
    auto begin(std::chrono::steady_clock::time_point now) -> void {
        if (_active) {
            return;
        }
        _started_at = now;
        _reported.clear();
        enter(now, recovery_entry::operator_drill);
    }

    /// EndRecovery.
    auto end(std::chrono::steady_clock::time_point now) -> void {
        if (_active) {
            leave(now, recovery_exit::operator_ended);
        }
    }

    /// A host reported an inventory (Requirement 7.3: reports are always
    /// accepted). May end recovery mode.
    auto host_reported(std::chrono::steady_clock::time_point now, const HostId& host) -> void {
        if (_in_service.contains(host)) {
            _reported.insert(host);
        }
        check_exit(now);
    }

    /// The in-service set changed (a host enrolled or was retired by the
    /// operator). May end recovery mode.
    auto set_in_service(std::chrono::steady_clock::time_point now, std::set<HostId> in_service)
        -> void {
        _in_service = std::move(in_service);
        std::erase_if(_reported, [this](const HostId& h) { return !_in_service.contains(h); });
        check_exit(now);
    }

    /// Call periodically: ends recovery mode once max_duration has passed.
    auto poll(std::chrono::steady_clock::time_point now) -> void { check_exit(now); }

    [[nodiscard]] auto active() const noexcept -> bool { return _active; }

    /// Whether `action` may run now (Requirement 7.2). Everything not in
    /// recovery_withheld_action is always allowed.
    [[nodiscard]] auto allows(recovery_withheld_action /*action*/) const noexcept -> bool {
        return !_active;
    }

    [[nodiscard]] auto status() const -> recovery_status {
        return {.active = _active,
                .in_service = _in_service.size(),
                .reported = _reported.size(),
                .entry = _active ? _entry : std::nullopt,
                .last_exit = _last_exit};
    }

    /// In-service hosts that have not reported since recovery started.
    [[nodiscard]] auto silent_hosts() const -> std::vector<HostId> {
        std::vector<HostId> out;
        for (const auto& h : _in_service) {
            if (!_reported.contains(h)) {
                out.push_back(h);
            }
        }
        return out;
    }

private:
    auto enter(std::chrono::steady_clock::time_point now, recovery_entry why) -> void {
        _active = true;
        _entry = why;
        if (_on_event) {
            _on_event({.what = event::kind::entered,
                       .at = now,
                       .entry = why,
                       .exit = std::nullopt,
                       .still_silent = {}});
        }
        check_exit(now);  // an empty fleet, say, needs no recovery
    }

    auto leave(std::chrono::steady_clock::time_point now, recovery_exit why) -> void {
        _active = false;
        _last_exit = why;
        if (_on_event) {
            _on_event({.what = event::kind::exited,
                       .at = now,
                       .entry = std::nullopt,
                       .exit = why,
                       .still_silent = silent_hosts()});
        }
    }

    auto check_exit(std::chrono::steady_clock::time_point now) -> void {
        if (!_active) {
            return;
        }
        if (static_cast<double>(_reported.size()) >=
            _config.exit_reported_fraction * static_cast<double>(_in_service.size())) {
            leave(now, recovery_exit::hosts_reported);
        } else if (now - _started_at >= _config.max_duration) {
            leave(now, recovery_exit::timed_out);
        }
    }

    recovery_config _config;
    event_sink _on_event;
    std::chrono::steady_clock::time_point _started_at{};
    std::set<HostId> _in_service;
    std::set<HostId> _reported;
    bool _active{false};
    std::optional<recovery_entry> _entry;
    std::optional<recovery_exit> _last_exit;
};

}  // namespace raft
