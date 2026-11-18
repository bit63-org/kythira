// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_long_poll.hpp
/// @brief Where long polls park (`.kiro/specs/sqs-compatible-queues/` task 5,
///        Requirements 6.1 and 6.2).
///
/// A receive that finds nothing and may wait subscribes to every partition
/// of its queue (Requirement 6.3) and parks on the subscription. The
/// replica's state machine reports each partition that has visible
/// messages after an entry commits (`set_availability_listener`): a send,
/// a visibility change, or a leader `tick` that ended a delay or a
/// visibility timeout. The hub wakes the subscriptions on that partition
/// and the receive tries again. Nothing polls the data layer; a parked
/// request costs one condition-variable wait.
///
/// Co-located, the listener calls `notify` in-process. Across layers
/// (task 12) the same notifications arrive on a stream from the data
/// nodes.
///
/// `close()` is the drain (Requirement 12.1): every parked request wakes
/// as closed and is answered with what it has, which for a long poll is an
/// empty answer that SQS clients treat as normal. Subscriptions taken after
/// it are closed from the start.

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace kythira::sqs {

class availability_hub {
    struct waiter {
        bool _ready = false;
        bool _closed = false;
        std::condition_variable _cv;
    };

public:
    /// How a wait ended.
    enum class wake : std::uint8_t {
        ready,      // a subscribed partition has visible messages
        timed_out,  // the deadline passed first
        closed,     // the hub is draining
    };

    /// One parked request's interest in a set of partitions; unsubscribes
    /// when destroyed.
    class subscription {
    public:
        subscription(const subscription&) = delete;
        auto operator=(const subscription&) -> subscription& = delete;
        subscription(subscription&& o) noexcept
            : _hub(std::exchange(o._hub, nullptr)),
              _keys(std::move(o._keys)),
              _w(std::move(o._w)) {}
        auto operator=(subscription&&) -> subscription& = delete;
        ~subscription() {
            if (_hub != nullptr) {
                _hub->unsubscribe(_keys, _w);
            }
        }

        /// Parks until a notification on one of the partitions since the
        /// subscription was taken (or since the last wake), the deadline,
        /// or the drain. A notification that arrived before the call is
        /// not lost.
        auto wait_until(std::chrono::steady_clock::time_point deadline) -> wake {
            std::unique_lock lock(_hub->_mutex);
            const bool woke =
                _w->_cv.wait_until(lock, deadline, [this] { return _w->_ready || _w->_closed; });
            if (_w->_closed) {
                return wake::closed;
            }
            if (!woke) {
                return wake::timed_out;
            }
            _w->_ready = false;
            return wake::ready;
        }

    private:
        friend class availability_hub;
        subscription(availability_hub* hub, std::vector<std::string> keys,
                     std::shared_ptr<waiter> w)
            : _hub(hub), _keys(std::move(keys)), _w(std::move(w)) {}

        availability_hub* _hub;
        std::vector<std::string> _keys;
        std::shared_ptr<waiter> _w;
    };

    availability_hub() = default;
    availability_hub(const availability_hub&) = delete;
    auto operator=(const availability_hub&) -> availability_hub& = delete;
    availability_hub(availability_hub&&) = delete;
    auto operator=(availability_hub&&) -> availability_hub& = delete;
    ~availability_hub() = default;

    /// Subscribes to `keys` (partition prefixes, `queue_keys::partition_prefix`).
    /// The hub must outlive the subscription.
    [[nodiscard]] auto subscribe(std::vector<std::string> keys) -> subscription {
        auto w = std::make_shared<waiter>();
        const std::scoped_lock lock(_mutex);
        w->_closed = _closed;
        for (const auto& k : keys) {
            _waiters[k].insert(w);
        }
        ++_parked;
        return subscription(this, std::move(keys), std::move(w));
    }

    /// Partition `key` has visible messages: wakes its subscriptions.
    auto notify(const std::string& key) -> void {
        const std::scoped_lock lock(_mutex);
        const auto it = _waiters.find(key);
        if (it == _waiters.end()) {
            return;
        }
        for (const auto& w : it->second) {
            w->_ready = true;
            w->_cv.notify_one();
        }
        ++_notified;
    }

    /// Wakes every subscription as closed, now and from now on.
    auto close() -> void {
        const std::scoped_lock lock(_mutex);
        _closed = true;
        for (auto& [key, set] : _waiters) {
            for (const auto& w : set) {
                w->_closed = true;
                w->_cv.notify_one();
            }
        }
    }

    /// Accepts subscriptions again (a module restarted in-process).
    auto reopen() -> void {
        const std::scoped_lock lock(_mutex);
        _closed = false;
    }

    /// Requests parked now.
    [[nodiscard]] auto parked() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        return _parked;
    }

    /// Notifications that found a parked request.
    [[nodiscard]] auto notified() const -> std::uint64_t {
        const std::scoped_lock lock(_mutex);
        return _notified;
    }

private:
    mutable std::mutex _mutex;
    std::map<std::string, std::set<std::shared_ptr<waiter>>, std::less<>> _waiters;
    bool _closed = false;
    std::size_t _parked = 0;
    std::uint64_t _notified = 0;

    auto unsubscribe(const std::vector<std::string>& keys, const std::shared_ptr<waiter>& w)
        -> void {
        const std::scoped_lock lock(_mutex);
        for (const auto& k : keys) {
            const auto it = _waiters.find(k);
            if (it == _waiters.end()) {
                continue;
            }
            it->second.erase(w);
            if (it->second.empty()) {
                _waiters.erase(it);
            }
        }
        --_parked;
    }
};

}  // namespace kythira::sqs
