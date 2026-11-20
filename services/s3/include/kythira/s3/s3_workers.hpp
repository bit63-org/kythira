// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_workers.hpp
/// @brief Running the leader-side workers on metadata nodes only
///        (.kiro/specs/s3-compatible-storage/ task 16; Requirement 14.6).
///
/// The lifecycle worker, the tier worker, the notification and replication
/// workers and the chunk sweeper each do one bounded pass when called
/// (`run()` or `sweep()`). `worker_runner` calls them on a schedule, on one
/// thread, under two gates:
///
///  - **Role.** A node without the metadata role runs none: front ends,
///    gateways and blob nodes are stateless or hold bytes only, and would
///    otherwise act on an index they do not own. The runner of such a node
///    is constructed (so the daemon wires it the same way everywhere) but
///    never starts a thread.
///  - **Leadership.** Each pass first asks `is_leader`. A metadata node that
///    does not lead its group skips the pass: two leaders' workers acting on
///    one index would deliver notifications twice and race their entries.
///    The workers keep their progress in the index (cursors, stamps,
///    collection states), so a new leader resumes where the old one
///    stopped.
///
/// A pass that throws (a metadata or blob node unreachable, a destination
/// down) is counted, logged, and tried again at the job's next time; one
/// job's failure never stops another.

#include <kythira/s3/s3_roles.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// One periodic worker pass.
struct worker_job {
    std::string name;
    std::chrono::milliseconds every{std::chrono::seconds(60)};
    /// One pass; returns a one-line summary for the log (empty: nothing
    /// worth logging).
    std::function<std::string()> run;
};

/// What one job has done.
struct worker_job_stats {
    std::uint64_t runs = 0;
    std::uint64_t failures = 0;
    /// Passes skipped because this node did not lead its group.
    std::uint64_t skipped_not_leader = 0;
    std::string last_error;
};

class worker_runner {
public:
    using clock = std::chrono::steady_clock;
    /// (is_warning, line)
    using log_fn = std::function<void(bool, std::string_view)>;

    /// `is_leader` empty means this node always leads (a single metadata
    /// node with its group in process).
    worker_runner(role_set roles, std::function<bool()> is_leader, std::vector<worker_job> jobs,
                  log_fn log = {})
        : _enabled(roles.has(role::data)),
          _is_leader(std::move(is_leader)),
          _jobs(std::move(jobs)),
          _log(std::move(log)),
          _stats(_jobs.size()),
          _due(_jobs.size(), clock::time_point::min()) {
        for (const auto& j : _jobs) {
            if (j.name.empty() || !j.run || j.every <= std::chrono::milliseconds::zero()) {
                throw std::invalid_argument(
                    "s3 worker runner: a job needs a name, a pass and "
                    "a positive interval");
            }
        }
    }

    worker_runner(const worker_runner&) = delete;
    auto operator=(const worker_runner&) -> worker_runner& = delete;
    worker_runner(worker_runner&&) = delete;
    auto operator=(worker_runner&&) -> worker_runner& = delete;
    ~worker_runner() { stop(); }

    /// Whether this node runs workers at all (it has the metadata role).
    [[nodiscard]] auto enabled() const noexcept -> bool { return _enabled; }

    /// Runs every job that is due at `now`, if this node may. Returns how
    /// many passes ran. The thread calls this; tests call it directly.
    auto tick(clock::time_point now) -> std::size_t {
        if (!_enabled) {
            return 0;
        }
        std::size_t ran = 0;
        for (std::size_t i = 0; i < _jobs.size(); ++i) {
            if (now < _due[i]) {
                continue;
            }
            _due[i] = now + _jobs[i].every;
            auto& st = stats_at(i);
            if (_is_leader && !_is_leader()) {
                const std::lock_guard lock(_stats_mu);
                ++st.skipped_not_leader;
                continue;
            }
            try {
                auto line = _jobs[i].run();
                {
                    const std::lock_guard lock(_stats_mu);
                    ++st.runs;
                }
                if (!line.empty()) {
                    log(false, _jobs[i].name + ": " + line);
                }
            } catch (const std::exception& e) {
                {
                    const std::lock_guard lock(_stats_mu);
                    ++st.runs;
                    ++st.failures;
                    st.last_error = e.what();
                }
                log(true, _jobs[i].name + " failed: " + e.what());
            }
            ++ran;
        }
        return ran;
    }

    /// Starts the thread (a no-op without the metadata role or jobs).
    void start() {
        if (!_enabled || _jobs.empty() || _thread.joinable()) {
            return;
        }
        _stopping = false;
        _thread = std::thread([this] { loop(); });
    }

    /// Stops the thread after its current pass.
    void stop() {
        {
            const std::lock_guard lock(_wake_mu);
            _stopping = true;
        }
        _wake.notify_all();
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    [[nodiscard]] auto running() const noexcept -> bool { return _thread.joinable(); }

    /// A copy of one job's counters, by name; zeros for an unknown name.
    [[nodiscard]] auto stats(std::string_view name) const -> worker_job_stats {
        const std::lock_guard lock(_stats_mu);
        for (std::size_t i = 0; i < _jobs.size(); ++i) {
            if (_jobs[i].name == name) {
                return _stats[i];
            }
        }
        return {};
    }

private:
    auto stats_at(std::size_t i) -> worker_job_stats& { return _stats[i]; }

    void log(bool warning, const std::string& line) const {
        if (_log) {
            _log(warning, line);
        }
    }

    void loop() {
        const auto shortest =
            std::ranges::min_element(_jobs, {}, [](const auto& j) { return j.every; })->every;
        const auto nap = std::min<std::chrono::milliseconds>(shortest, std::chrono::seconds(1));
        std::unique_lock lock(_wake_mu);
        while (!_stopping) {
            lock.unlock();
            tick(clock::now());
            lock.lock();
            _wake.wait_for(lock, nap, [this] { return _stopping; });
        }
    }

    bool _enabled;
    std::function<bool()> _is_leader;
    std::vector<worker_job> _jobs;
    log_fn _log;
    mutable std::mutex _stats_mu;
    std::vector<worker_job_stats> _stats;
    std::vector<clock::time_point> _due;
    std::mutex _wake_mu;
    std::condition_variable _wake;
    bool _stopping = false;
    std::thread _thread;
};

}  // namespace kythira::s3
