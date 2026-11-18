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
///
/// `move_worker` runs the message move tasks (task 6, Requirement 7.3) on
/// the node that leads the catalog entry of each task's source queue. Each
/// pass takes up to the task's rate worth of visible messages from the
/// source's partitions, proposes one `move` command per partition (each
/// message leaves the source and enters its destination in the same
/// entry), and records the progress with a catalog `move_update`. A task
/// ends when the source has no visible message left, when a destination
/// is gone (failed), or after a cancel (cancelled). The rate is a token
/// bucket kept by the worker: a new leader starts it again, which can only
/// make a pass smaller.
///
/// `grow_worker` grows standard queues (task 8, Requirement 9.1; design
/// "Partitions"): on the node leading a queue's catalog entry it samples
/// the queue's send count (the partitions' sequence counters) every
/// `interval`, and when the rate per partition passes
/// `per_partition_rate` it proposes a catalog `grow` doubling the count,
/// up to `k_max_partitions`. New sends spread over every partition and
/// receives rotate over all of them; nothing moves. A new leader starts
/// sampling again, so growth waits one interval after a leader change.

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
#include <map>
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

template<queue_cluster Cluster> class move_worker {
public:
    using state_machine_type = typename Cluster::state_machine_type;
    using leads_fn = std::function<bool(const std::string& key)>;
    /// The parts of a queue ARN: account and name, or nullopt.
    using arn_fn =
        std::function<std::optional<std::pair<std::string, std::string>>(const std::string& arn)>;

    struct options {
        std::chrono::milliseconds _idle{1000};
        /// Between passes while a task runs.
        std::chrono::milliseconds _busy{50};
        /// Messages per second when the task gives no rate.
        std::uint32_t _default_rate = 500;
        /// Moves in one proposed command.
        std::size_t _batch = 32;
    };

    move_worker(Cluster& cluster, leads_fn leads, arn_fn parse_arn, options o = {})
        : _cluster(cluster), _leads(std::move(leads)), _parse_arn(std::move(parse_arn)), _opt(o) {}
    move_worker(const move_worker&) = delete;
    auto operator=(const move_worker&) -> move_worker& = delete;
    move_worker(move_worker&&) = delete;
    auto operator=(move_worker&&) -> move_worker& = delete;
    ~move_worker() { stop(); }

    /// One pass over the active tasks this node leads. Returns whether any
    /// is still active.
    auto run_once() -> bool {
        std::vector<move_task> tasks;
        (void)_cluster.read(catalog_keys::moves_prefix(),
                            [&](const state_machine_type& sm) { tasks = sm.active_move_tasks(); });
        bool active = false;
        std::map<std::string, std::uint64_t> seen;
        for (auto& t : tasks) {
            const auto key = catalog_keys::queue(t._account, t._name);
            if (!_leads(key)) {
                continue;
            }
            const auto id = catalog_keys::move(t._account, t._name, t._started_ms);
            seen.emplace(id, 0);
            if (step(t, id)) {
                active = true;
            }
        }
        // Buckets of tasks that ended or moved away.
        std::erase_if(_buckets, [&](const auto& kv) { return !seen.contains(kv.first); });
        return active;
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

    /// Something committed (a task may have started): look again.
    void wake() {
        {
            const std::scoped_lock lock(_mutex);
            _woken = true;
        }
        _cv.notify_all();
    }

    [[nodiscard]] auto moved() const -> std::uint64_t { return _moved; }

private:
    struct bucket {
        std::uint64_t _last_ms = 0;
        double _credit = 0;
    };

    Cluster& _cluster;
    leads_fn _leads;
    arn_fn _parse_arn;
    options _opt;
    std::map<std::string, bucket> _buckets;
    std::thread _thread;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _running = false;
    bool _woken = false;
    std::atomic<std::uint64_t> _moved{0};

    [[nodiscard]] auto find(const std::string& account, const std::string& name)
        -> std::optional<queue_record> {
        std::optional<queue_record> out;
        (void)_cluster.read(catalog_keys::queue(account, name), [&](const state_machine_type& sm) {
            out = sm.find_queue(account, name);
        });
        return out;
    }

    auto update(const move_task& t, std::uint64_t moved, move_task::state s, std::string failure)
        -> void {
        catalog_command c;
        c._op = catalog_command::kind::move_update;
        c._account = t._account;
        c._name = t._name;
        c._now_ms = _cluster.now_ms();
        c._move._started_ms = t._started_ms;
        c._move._moved = moved;
        c._move._status = s;
        c._move._failure = std::move(failure);
        (void)_cluster.propose(catalog_keys::queue(c._account, c._name),
                               record_detail::to_bytes(encode_catalog_command(c)));
    }

    /// Advances one task; returns whether it is still running.
    auto step(const move_task& t, const std::string& id) -> bool {
        if (t._status == move_task::state::cancelling) {
            update(t, 0, move_task::state::cancelled, {});
            return false;
        }
        const auto source = find(t._account, t._name);
        if (!source) {
            update(t, 0, move_task::state::failed, "Source queue does not exist.");
            return false;
        }
        const auto now = _cluster.now_ms();
        const double rate = t._rate != 0 ? t._rate : _opt._default_rate;
        auto& b = _buckets[id];
        if (b._last_ms == 0) {
            b._credit = std::min(rate, static_cast<double>(_opt._batch));
        } else if (now > b._last_ms) {
            b._credit =
                std::min(rate, b._credit + rate * static_cast<double>(now - b._last_ms) / 1000.0);
        }
        b._last_ms = now;
        auto allowance = static_cast<std::size_t>(b._credit);

        std::map<std::string, std::optional<queue_record>> dests;
        std::uint64_t moved = 0;
        std::uint64_t left = 0;
        for (std::uint16_t p = 0; p < std::max<std::uint16_t>(source->_partitions, 1); ++p) {
            const auto src = source->target(p);
            const auto key = queue_keys::partition_prefix(src);
            std::vector<std::pair<std::uint64_t, stored_message>> msgs;
            (void)_cluster.read(key, [&](const state_machine_type& sm) {
                msgs = sm.visible_messages(src, std::min(allowance, _opt._batch));
                left += sm.counts(src).visible;
            });
            if (msgs.empty()) {
                continue;
            }
            queue_command c;
            c.op = queue_command::kind::move;
            c.target = src;
            c.now_ms = now;
            for (const auto& [seq, m] : msgs) {
                const auto& arn =
                    t._destination_arn.empty() ? m.dead_letter_source : t._destination_arn;
                auto it = dests.find(arn);
                if (it == dests.end()) {
                    const auto parts = arn.empty() ? std::nullopt : _parse_arn(arn);
                    it =
                        dests.emplace(arn, parts ? find(parts->first, parts->second) : std::nullopt)
                            .first;
                }
                if (!it->second) {
                    if (moved > 0 || !c.moves.empty()) {
                        break;  // record what moved first; fail on the next pass
                    }
                    update(t, 0, move_task::state::failed,
                           arn.empty() ? "Message has no source queue to move back to."
                                       : "Destination queue " + arn + " does not exist.");
                    return false;
                }
                c.moves.push_back(move_entry{seq, it->second->target(0), it->second->_partitions});
            }
            if (c.moves.empty()) {
                continue;
            }
            const auto out =
                _cluster.propose(key, record_detail::to_bytes(encode_queue_command(c)));
            const auto r = out ? decode_queue_result(record_detail::to_string(*out)) : std::nullopt;
            if (!r) {
                continue;
            }
            for (const auto& e : r->entries) {
                if (e.outcome == entry_result::status::ok) {
                    ++moved;
                }
            }
            allowance -= std::min(allowance, c.moves.size());
        }
        b._credit -= std::min(b._credit, static_cast<double>(moved));
        _moved += moved;
        const bool done = left <= moved;
        if (moved > 0 || done) {
            update(t, moved, done ? move_task::state::completed : move_task::state::running, {});
        }
        return !done;
    }

    void loop() {
        for (;;) {
            bool active = false;
            try {
                active = run_once();
            } catch (const std::exception&) {
                active = false;  // a replica not ready yet; try again after idle
            }
            std::unique_lock lock(_mutex);
            if (!_running) {
                return;
            }
            _cv.wait_for(lock, active ? _opt._busy : _opt._idle,
                         [this] { return !_running || _woken; });
            _woken = false;
            if (!_running) {
                return;
            }
        }
    }
};

template<queue_cluster Cluster> class grow_worker {
public:
    using state_machine_type = typename Cluster::state_machine_type;
    using leads_fn = std::function<bool(const std::string& key)>;

    struct options {
        std::chrono::milliseconds _interval{10'000};
        /// Sends a second one partition takes before the queue grows.
        double _per_partition_rate = 500.0;
    };

    grow_worker(Cluster& cluster, leads_fn leads, options o = {})
        : _cluster(cluster), _leads(std::move(leads)), _opt(o) {}
    grow_worker(const grow_worker&) = delete;
    auto operator=(const grow_worker&) -> grow_worker& = delete;
    grow_worker(grow_worker&&) = delete;
    auto operator=(grow_worker&&) -> grow_worker& = delete;
    ~grow_worker() { stop(); }

    /// One sample of every standard queue this node leads; proposes the
    /// growths due. Returns how many it proposed.
    auto run_once() -> std::size_t {
        std::vector<queue_record> queues;
        (void)_cluster.read(catalog_keys::prefix(), [&](const state_machine_type& sm) {
            sm.for_each_queue([&](const queue_record& q) {
                if (!q._settings._fifo) {
                    queues.push_back(q);
                }
                return true;
            });
        });
        const auto now = _cluster.now_ms();
        std::size_t grown = 0;
        std::map<std::uint64_t, sample> next;
        for (const auto& q : queues) {
            if (!_leads(catalog_keys::queue(q._account, q._name))) {
                continue;
            }
            std::uint64_t sent = 0;
            const auto n = std::max<std::uint16_t>(q._partitions, 1);
            for (std::uint16_t p = 0; p < n; ++p) {
                const auto t = q.target(p);
                (void)_cluster.read(queue_keys::partition_prefix(t),
                                    [&](const state_machine_type& sm) {
                                        sent += sm.counters(t).next_sequence - 1;
                                    });
            }
            next[q._id] = sample{sent, now};
            const auto it = _samples.find(q._id);
            if (it == _samples.end() || now <= it->second._ms || n >= k_max_partitions) {
                continue;
            }
            const auto rate = static_cast<double>(sent - std::min(sent, it->second._sent)) *
                              1000.0 / static_cast<double>(now - it->second._ms);
            if (rate <= _opt._per_partition_rate * n) {
                continue;
            }
            catalog_command c;
            c._op = catalog_command::kind::grow;
            c._account = q._account;
            c._name = q._name;
            c._now_ms = now;
            c._partitions = static_cast<std::uint16_t>(std::min<int>(n * 2, k_max_partitions));
            if (_cluster.propose(catalog_keys::queue(q._account, q._name),
                                 record_detail::to_bytes(encode_catalog_command(c)))) {
                ++grown;
                ++_grown;
            }
        }
        _samples = std::move(next);
        return grown;
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

    [[nodiscard]] auto grown() const -> std::uint64_t { return _grown; }

private:
    struct sample {
        std::uint64_t _sent = 0;
        std::uint64_t _ms = 0;
    };

    Cluster& _cluster;
    leads_fn _leads;
    options _opt;
    std::map<std::uint64_t, sample> _samples;
    std::thread _thread;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _running = false;
    std::atomic<std::uint64_t> _grown{0};

    void loop() {
        for (;;) {
            try {
                (void)run_once();
            } catch (const std::exception&) {
                _samples.clear();  // a replica not ready yet; sample again
            }
            std::unique_lock lock(_mutex);
            if (_cv.wait_for(lock, _opt._interval, [this] { return !_running; })) {
                return;
            }
        }
    }
};

}  // namespace kythira::sqs
