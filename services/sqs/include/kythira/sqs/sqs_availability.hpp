// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_availability.hpp
/// @brief Long-poll wake-ups across layers (`.kiro/specs/sqs-compatible-queues/`
///        task 10, Requirement 11.4).
///
/// Co-located, a replica's state machine tells the node's
/// `availability_hub` in-process when a partition gains visible messages.
/// A front end without the data role parks its long polls on its own hub,
/// fed by a stream from the data nodes:
///
/// - `availability_feed` (data node): every partition the replica reports
///   goes into a numbered window of recent notifications.
/// - The data node serves `POST /_kythira/sqs/v1/availability` with body
///   `{"epoch": E, "since": N}`: it answers as soon as there are
///   notifications after `N` (or at the end of its wait, with none), as
///   `{"epoch": E', "next": M, "reset": bool, "keys": [...]}`. `reset` means
///   the caller cannot be told exactly what it missed: its `N` fell out of
///   the window, or `E` is not this feed's epoch (the data node restarted,
///   or the caller is new).
/// - `availability_follower` (front end): one thread per data node, each
///   asking again as soon as it has an answer, so the calls form a stream.
///   Keys wake the hub's subscriptions on those partitions; a reset, or a
///   call that fails, wakes every parked request, which then receives once
///   and parks again. A spurious wake costs one receive entry; a missed
///   one would cost a long poll its messages until its wait ended.
///
/// Every replica applies every entry of its group, so any one data node's
/// feed is complete for the groups it holds. Following every data node
/// survives any one of them stopping, at the price of duplicate wake-ups.
///
/// Authenticated like the other internal calls (`sqs_forward.hpp`).

#include <kythira/sqs/sqs_long_poll.hpp>
#include <kythira/sqs/sqs_remote_cluster.hpp>

#include <boost/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira::sqs {

inline constexpr std::string_view k_availability_path = "/_kythira/sqs/v1/availability";

/// What one availability call answers.
struct availability_batch {
    std::string _epoch;
    std::uint64_t _next = 0;
    bool _reset = false;
    std::vector<std::string> _keys;
};

[[nodiscard]] inline auto encode_availability_request(std::string_view epoch, std::uint64_t since)
    -> std::string {
    boost::json::object o;
    o["epoch"] = epoch;
    o["since"] = since;
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto encode_availability(const availability_batch& b) -> std::string {
    boost::json::object o;
    o["epoch"] = b._epoch;
    o["next"] = b._next;
    o["reset"] = b._reset;
    boost::json::array keys;
    for (const auto& k : b._keys) {
        keys.emplace_back(data_wire::b64(k));
    }
    o["keys"] = std::move(keys);
    return boost::json::serialize(o);
}

[[nodiscard]] inline auto decode_availability(std::string_view in)
    -> std::optional<availability_batch> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(in, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    const auto& o = v.as_object();
    availability_batch b;
    b._epoch = data_wire::str(o, "epoch");
    b._next = data_wire::u64(o, "next");
    const auto* reset = o.if_contains("reset");
    b._reset = reset != nullptr && reset->is_bool() && reset->as_bool();
    if (const auto* keys = o.if_contains("keys"); keys != nullptr && keys->is_array()) {
        for (const auto& k : keys->as_array()) {
            auto raw = data_wire::unb64(k);
            if (!raw) {
                return std::nullopt;
            }
            b._keys.push_back(std::move(*raw));
        }
    }
    return b;
}

/// The data node's window of recent notifications.
class availability_feed {
public:
    explicit availability_feed(std::size_t window = 4096) : _window(window), _epoch(new_epoch()) {}

    /// Partition `key` gained visible messages.
    auto publish(const std::string& key) -> void {
        {
            const std::scoped_lock lock(_mutex);
            _events.emplace_back(++_seq, key);
            while (_events.size() > _window) {
                _events.pop_front();
            }
        }
        _cv.notify_all();
    }

    /// What happened after `since`, waiting up to `wait` for something to.
    [[nodiscard]] auto wait(std::string_view epoch, std::uint64_t since,
                            std::chrono::milliseconds wait) -> availability_batch {
        std::unique_lock lock(_mutex);
        availability_batch b;
        b._epoch = _epoch;
        if (epoch != _epoch || since > _seq) {
            b._reset = true;
            b._next = _seq;
            return b;
        }
        _cv.wait_for(lock, wait, [&] { return _seq > since || _closed; });
        b._next = _seq;
        if (!_events.empty() && _events.front().first > since + 1) {
            b._reset = true;
            return b;
        }
        std::set<std::string> seen;
        for (const auto& [seq, key] : _events) {
            if (seq > since && seen.insert(key).second) {
                b._keys.push_back(key);
            }
        }
        return b;
    }

    /// Ends every wait now (the node is stopping).
    auto close() -> void {
        {
            const std::scoped_lock lock(_mutex);
            _closed = true;
        }
        _cv.notify_all();
    }

    [[nodiscard]] auto epoch() const -> const std::string& { return _epoch; }

private:
    std::size_t _window;
    std::string _epoch;
    std::mutex _mutex;
    std::condition_variable _cv;
    std::deque<std::pair<std::uint64_t, std::string>> _events;
    std::uint64_t _seq = 0;
    bool _closed = false;

    [[nodiscard]] static auto new_epoch() -> std::string {
        std::random_device rd;
        return std::to_string(rd()) + "-" + std::to_string(rd());
    }
};

/// The front end's side: follows each data node's feed into `hub`.
class availability_follower {
public:
    using wall_clock_fn = std::function<std::chrono::system_clock::time_point()>;

    /// @param retry How long to wait after a failed call before the next.
    availability_follower(
        availability_hub& hub, std::vector<std::string> data_endpoints, std::string forward_secret,
        data_transport transport, std::chrono::milliseconds retry = std::chrono::milliseconds{500},
        wall_clock_fn wall = [] { return std::chrono::system_clock::now(); })
        : _hub(hub),
          _endpoints(std::move(data_endpoints)),
          _secret(std::move(forward_secret)),
          _transport(std::move(transport)),
          _retry(retry),
          _wall(std::move(wall)) {}

    ~availability_follower() { stop(); }
    availability_follower(const availability_follower&) = delete;
    auto operator=(const availability_follower&) -> availability_follower& = delete;
    availability_follower(availability_follower&&) = delete;
    auto operator=(availability_follower&&) -> availability_follower& = delete;

    auto start() -> void {
        for (const auto& e : _endpoints) {
            _threads.emplace_back([this, e] { follow(e); });
        }
    }

    /// Stops asking; an outstanding call ends with the data node's wait.
    auto stop() -> void {
        {
            const std::scoped_lock lock(_mutex);
            _stopping = true;
        }
        _cv.notify_all();
        for (auto& t : _threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        _threads.clear();
    }

    /// Answers taken from the data nodes (for tests and metrics).
    [[nodiscard]] auto batches() const -> std::uint64_t { return _batches.load(); }

private:
    availability_hub& _hub;
    std::vector<std::string> _endpoints;
    std::string _secret;
    data_transport _transport;
    std::chrono::milliseconds _retry;
    wall_clock_fn _wall;
    std::vector<std::thread> _threads;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _stopping = false;
    std::atomic<std::uint64_t> _batches{0};

    [[nodiscard]] auto stopping() -> bool {
        const std::scoped_lock lock(_mutex);
        return _stopping;
    }

    auto follow(const std::string& endpoint) -> void {
        std::string epoch;
        std::uint64_t since = 0;
        while (!stopping()) {
            const auto body = encode_availability_request(epoch, since);
            std::vector<std::pair<std::string, std::string>> headers;
            if (!_secret.empty()) {
                headers.emplace_back(std::string(forward::k_header),
                                     forward::sign(_secret, body, _wall()));
            }
            const auto r = _transport(endpoint, std::string(k_availability_path), headers, body);
            auto b = r && r->first == 200 ? decode_availability(r->second) : std::nullopt;
            if (!b) {
                // Whatever happened meanwhile is unknown: wake everyone,
                // start over with this node, and do not spin on a dead one.
                _hub.notify_all();
                epoch.clear();
                std::unique_lock lock(_mutex);
                _cv.wait_for(lock, _retry, [&] { return _stopping; });
                continue;
            }
            ++_batches;
            if (b->_reset) {
                _hub.notify_all();
            } else {
                for (const auto& k : b->_keys) {
                    _hub.notify(k);
                }
            }
            epoch = std::move(b->_epoch);
            since = b->_next;
        }
    }
};

}  // namespace kythira::sqs
