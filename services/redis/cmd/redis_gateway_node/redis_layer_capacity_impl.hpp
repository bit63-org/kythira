// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_layer_capacity_impl.hpp
/// @brief The capacity loop's template, included by layer_capacity_docker.cpp
///        and by its unit test (which drives it with a scripted quorum
///        manager, a manual clock and a manual executor).

#include "redis_layer_capacity.hpp"

#include <raft/capacity_lease.hpp>
#include <raft/capacity_ledger.hpp>
#include <raft/console_logger.hpp>
#include <raft/elastic_capacity_controller.hpp>
#include <raft/layer_capacity.hpp>
#include <raft/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::redis_node {

namespace capacity_detail {

/// The shared policy's knobs from the node's settings.
inline auto policy_config(const capacity_options& c) -> layers::layer_capacity_config {
    layers::layer_capacity_config p;
    p.enabled = true;
    p.requests_per_member = {
        ._high = c._requests_high, ._low = c._requests_low, ._enabled = c._requests_high > 0.0};
    p.connections_per_member = {._high = c._connections_high,
                                ._low = c._connections_low,
                                ._enabled = c._connections_high > 0.0};
    if (c._overload_cpu > 0.0) {
        p.overload_cpu = c._overload_cpu;
    } else {
        p.overloaded._enabled = false;
    }
    p.sustained_for = c._sustained;
    p.sustained_for_scale_in = c._scale_in_sustained;
    p.cooldown = c._cooldown;
    p.min_members = c._min_members;
    return p;
}

/// The controller's settings: one machine at a time, admitted on join (a
/// stateless member never holds a replica), the drain bounded by the
/// node's own deadline.
inline auto controller_config(const capacity_options& c, std::chrono::milliseconds stale_after)
    -> elastic_capacity_config {
    elastic_capacity_config e;
    e.enabled = true;
    e.dry_run = c._dry_run;
    e.scale_in_enabled = c._scale_in;
    e.admit_on_join = true;
    e.min_cluster_size = c._min_members;
    e.max_cluster_size = c._max_members;
    e.evaluation_interval = c._interval;
    e.node_report_staleness = stale_after;
    e.min_provider_call_interval = std::min(c._cooldown, e.min_provider_call_interval);
    e.drain_deadline = c._drain_deadline;
    e.assess_interval = std::max(c._interval * 6, std::chrono::milliseconds{30000});
    return e;
}

/// One thread that runs the controller's provider work in order.
class work_queue {
public:
    work_queue() : _thread([this] { run(); }) {}
    ~work_queue() {
        {
            std::lock_guard lock(_m);
            _stop = true;
        }
        _cv.notify_all();
        _thread.join();
    }
    work_queue(const work_queue&) = delete;
    auto operator=(const work_queue&) -> work_queue& = delete;
    work_queue(work_queue&&) = delete;
    auto operator=(work_queue&&) -> work_queue& = delete;

    auto fn() -> std::function<void(std::function<void()>)> {
        return [this](std::function<void()> w) {
            {
                std::lock_guard lock(_m);
                _q.push_back(std::move(w));
            }
            _cv.notify_one();
        };
    }

private:
    void run() {
        for (;;) {
            std::function<void()> w;
            {
                std::unique_lock lock(_m);
                _cv.wait(lock, [this] { return _stop || !_q.empty(); });
                if (_stop && _q.empty()) {
                    return;
                }
                w = std::move(_q.front());
                _q.pop_front();
            }
            try {
                w();
            } catch (...) {  // NOLINT(bugprone-empty-catch): the controller
                // records a failed provider call through its own future; a
                // throw here is a call that never started, retried next step.
            }
        }
    }

    std::mutex _m;
    std::condition_variable _cv;
    std::deque<std::function<void()>> _q;
    bool _stop{false};
    std::thread _thread;
};

}  // namespace capacity_detail

/// @brief The loop over one quorum manager.
template<typename QuorumMgr> class capacity_loop final : public layer_capacity_loop {
public:
    using node_id_type = typename QuorumMgr::node_id_type;
    using policy_type = layers::layer_capacity_policy<std::uint64_t, std::string, node_id_type>;
    using ledger_type = memory_capacity_ledger<node_id_type, std::string>;
    using controller_type =
        elastic_capacity_controller<QuorumMgr, policy_type, ledger_type, raft_leadership_lease,
                                    std::uint64_t, std::string, noop_metrics, console_logger>;
    using clock_fn = std::function<std::chrono::system_clock::time_point()>;
    using executor_fn = std::function<void(std::function<void()>)>;

    /// @param layer       The roles whose members it scales.
    /// @param stale_after How long a member may go without reporting before
    ///                    its numbers stop counting (the gateways' own mark).
    /// @param executor    Runs provider calls; empty runs them on a thread of
    ///                    the loop's own.
    capacity_loop(QuorumMgr manager, const capacity_options& opt, layers::role_set layer,
                  std::chrono::milliseconds stale_after, membership_group& group, log_level level,
                  clock_fn clock = {}, executor_fn executor = {})
        : _opt(opt),
          _layer(layer),
          _stale_after(stale_after),
          _group(group),
          _clock(clock ? std::move(clock) : [] { return std::chrono::system_clock::now(); }),
          _work(executor ? nullptr : std::make_unique<capacity_detail::work_queue>()),
          _membership([&group](std::vector<std::byte> c) { return group.propose(std::move(c)); },
                      [&group] { return group.read(); }),
          _controller(std::move(manager), policy_type{capacity_detail::policy_config(opt)}, _ledger,
                      raft_leadership_lease{[&group] { return group.leading(); },
                                            [&group] { return group.term(); }},
                      capacity_detail::controller_config(opt, stale_after),
                      executor ? std::move(executor) : _work->fn(), _clock, noop_metrics{},
                      console_logger{level}) {
        _controller.set_drain_hooks(layers::layer_drain_hooks<node_id_type>(
            _membership, [this] { return now_ms(); }, _stale_after.count()));
    }

    ~capacity_loop() override { stop(); }
    capacity_loop(const capacity_loop&) = delete;
    auto operator=(const capacity_loop&) -> capacity_loop& = delete;
    capacity_loop(capacity_loop&&) = delete;
    auto operator=(capacity_loop&&) -> capacity_loop& = delete;

    void start() override {
        std::lock_guard lock(_m);
        if (_thread.joinable()) {
            return;
        }
        _stopping = false;
        _thread = std::thread([this] {
            std::unique_lock lock(_m);
            while (!_stopping) {
                lock.unlock();
                try {
                    round();
                } catch (...) {  // NOLINT(bugprone-empty-catch): the next
                    // round reads the group again; a throw here is a group
                    // that could not answer this one.
                }
                lock.lock();
                _cv.wait_for(lock, _opt._interval, [this] { return _stopping; });
            }
        });
    }

    void stop() override {
        {
            std::lock_guard lock(_m);
            _stopping = true;
        }
        _cv.notify_all();
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /// One round: on the group's leader, a report per fresh member of the
    /// layer, then a step. Public for the unit test.
    void round() {
        if (!_group.leading()) {
            return;  // the lease would refuse too; this skips reading
        }
        const auto members = _group.read();
        const auto now = now_ms();
        std::set<node_id_type> ours;
        for (const auto& v : _controller.snapshot()._nodes) {
            if (v._draining) {
                ours.insert(v._report._node_id);
            }
        }
        const auto cfg = policy_settings();
        for (const auto& m : members) {
            if (!m.roles.intersects(_layer) || now - m.reported_at_ms > _stale_after.count()) {
                // A member that stopped reporting ages out of the
                // controller's view on its own, as a stale machine.
                continue;
            }
            auto report = layers::layer_node_report<node_id_type>(m, cfg);
            if (!report) {
                continue;
            }
            // One an operator drained (KYTHIRA.LAYERS DRAIN) is out of
            // service and not the controller's to count; one the controller
            // drains it keeps watching until it is gone.
            if (m.drain != layers::drain_state::serving && !ours.contains(report->_node_id)) {
                continue;
            }
            _controller.observe_node(*report);
        }
        static_cast<void>(_controller.step());
    }

    [[nodiscard]] auto controller() -> controller_type& { return _controller; }

private:
    [[nodiscard]] auto now_ms() const -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(_clock().time_since_epoch())
            .count();
    }
    [[nodiscard]] auto policy_settings() const -> layers::layer_capacity_config {
        return capacity_detail::policy_config(_opt);
    }

    capacity_options _opt;
    layers::role_set _layer;
    std::chrono::milliseconds _stale_after;
    membership_group& _group;
    clock_fn _clock;
    std::unique_ptr<capacity_detail::work_queue> _work;
    layers::replicated_layer_membership _membership;
    ledger_type _ledger;
    controller_type _controller;

    std::mutex _m;
    std::condition_variable _cv;
    bool _stopping{false};
    std::thread _thread;
};

}  // namespace kythira::redis_node
