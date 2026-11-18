// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_workers.hpp
/// @brief The leader's deadline ticks (`.kiro/specs/sqs-compatible-queues/`
///        task 5, Requirement 6.2; design "Long polling without polling").
///
/// A delayed message becoming visible, or an in-flight one whose
/// visibility timeout ran out, changes nothing until an entry runs the
/// partition's housekeeping. `tick_worker` makes that moment a committed
/// fact: on the node that leads a partition's group it proposes a `tick`
/// when the partition's earliest deadline (`next_deadline`) has passed.
/// Every replica applies the tick, finds the messages visible and tells its
/// long polls (`sqs_long_poll.hpp`).
///
/// The worker sleeps until the earliest deadline it saw, and the state
/// machines' listener wakes it on every commit, since an entry can add an
/// earlier deadline (a delayed send, a shorter visibility change). It also
/// wakes every `idle` at most, which catches a leadership change, so the
/// walk of the catalog it does then runs at most once per `idle` on an idle
/// cluster. Passes are at least `min_gap` apart so a deadline housekeeping
/// cannot clear yet cannot spin the worker.

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::sqs {

template<queue_cluster Cluster> class tick_worker {
public:
    using state_machine_type = typename Cluster::state_machine_type;
    /// Whether this node leads the group owning a key.
    using leads_fn = std::function<bool(const std::string& key)>;

    struct options {
        std::chrono::milliseconds _idle{1000};
        std::chrono::milliseconds _min_gap{20};
    };

    tick_worker(Cluster& cluster, leads_fn leads, options o = {})
        : _cluster(cluster), _leads(std::move(leads)), _opt(o) {}
    tick_worker(const tick_worker&) = delete;
    auto operator=(const tick_worker&) -> tick_worker& = delete;
    tick_worker(tick_worker&&) = delete;
    auto operator=(tick_worker&&) -> tick_worker& = delete;
    ~tick_worker() { stop(); }

    /// One walk: proposes a tick for every partition this node leads whose
    /// earliest deadline has passed, and returns the earliest deadline
    /// still ahead (Unix ms), if any.
    auto run_once() -> std::optional<std::uint64_t> {
        std::vector<queue_target> targets;
        (void)_cluster.read(catalog_keys::prefix(), [&](const state_machine_type& sm) {
            sm.for_each_queue([&](const queue_record& q) {
                for (std::uint16_t p = 0; p < std::max<std::uint16_t>(q._partitions, 1); ++p) {
                    targets.push_back(q.target(p));
                }
                return true;
            });
        });
        std::optional<std::uint64_t> next;
        for (const auto& t : targets) {
            const auto key = queue_keys::partition_prefix(t);
            if (!_leads(key)) {
                continue;
            }
            std::optional<std::uint64_t> due;
            (void)_cluster.read(key,
                                [&](const state_machine_type& sm) { due = sm.next_deadline(t); });
            if (!due) {
                continue;
            }
            const auto now = _cluster.now_ms();
            if (*due > now) {
                next = next ? std::min(*next, *due) : *due;
                continue;
            }
            queue_command c;
            c.op = queue_command::kind::tick;
            c.target = t;
            c.now_ms = now;
            if (_cluster.propose(key, record_detail::to_bytes(encode_queue_command(c)))) {
                ++_ticks;
            }
            // What is due next is read on the next pass, after the tick.
            next = now;
        }
        return next;
    }

    void start() {
        _running = true;
        _thread = std::thread([this] { loop(); });
    }

    void stop() {
        {
            const std::scoped_lock lock(_mutex);
            _running = false;
        }
        _cv.notify_all();
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /// Something committed: look again (the state machines' listener).
    void wake() {
        {
            const std::scoped_lock lock(_mutex);
            _woken = true;
        }
        _cv.notify_all();
    }

    [[nodiscard]] auto ticks() const -> std::uint64_t { return _ticks; }

private:
    Cluster& _cluster;
    leads_fn _leads;
    options _opt;
    std::thread _thread;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _running = false;
    bool _woken = false;
    std::atomic<std::uint64_t> _ticks{0};

    void loop() {
        for (;;) {
            std::optional<std::uint64_t> next;
            try {
                next = run_once();
            } catch (const std::exception&) {
                next.reset();  // a replica not ready yet; try again after idle
            }
            std::unique_lock lock(_mutex);
            if (!_running) {
                return;
            }
            _cv.wait_for(lock, _opt._min_gap, [this] { return !_running; });
            auto wait = _opt._idle;
            if (next) {
                const auto now = _cluster.now_ms();
                const auto ahead = *next > now ? std::chrono::milliseconds(*next - now)
                                               : std::chrono::milliseconds(0);
                wait = std::min(wait, ahead);
            }
            _cv.wait_for(lock, wait, [this] { return !_running || _woken; });
            _woken = false;
            if (!_running) {
                return;
            }
        }
    }
};

}  // namespace kythira::sqs
