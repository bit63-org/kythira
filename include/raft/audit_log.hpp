// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file audit_log.hpp
/// @brief A bounded audit queue drained by one writer thread, shared by
///        IAM's authorizer and the virtual HSM (`.kiro/specs/virtual-hsm/`
///        task 14).
///
/// A caller posts a line and never waits for the sink: lines that do not
/// fit are counted, and the writer reports the count as one
/// {"audit":"dropped","lines":N} line once room returns. The writer hands
/// the sink everything queued since its last pass, line by line or, for a
/// sink that sends batches (a ledger), all at once.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kythira {

class audit_log {
public:
    using sink = std::function<void(std::string_view line)>;
    using batch_sink = std::function<void(std::span<const std::string> lines)>;

    /// One line at a time.
    explicit audit_log(sink out, std::size_t capacity = 8192)
        : audit_log(batch_sink([out = std::move(out)](std::span<const std::string> lines) {
                        for (const auto& line : lines) {
                            out(line);
                        }
                    }),
                    capacity) {}

    /// Everything queued since the last pass at once.
    audit_log(batch_sink out, std::size_t capacity)
        : _out(std::move(out)), _capacity(capacity), _writer([this] { run(); }) {}

    audit_log(const audit_log&) = delete;
    auto operator=(const audit_log&) -> audit_log& = delete;
    audit_log(audit_log&&) = delete;
    auto operator=(audit_log&&) -> audit_log& = delete;

    ~audit_log() {
        {
            const std::lock_guard lock(_mu);
            _stopping = true;
        }
        _cv.notify_one();
        _writer.join();
    }

    /// Queues a line, or counts it as dropped when the queue is full.
    void post(std::string line) {
        {
            const std::lock_guard lock(_mu);
            if (_queue.size() >= _capacity) {
                _dropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            _queue.push_back(std::move(line));
        }
        _cv.notify_one();
    }

    /// Lines dropped because the queue was full.
    [[nodiscard]] auto dropped() const noexcept -> std::uint64_t {
        return _dropped.load(std::memory_order_relaxed);
    }

    /// Blocks until every queued line has reached the sink (tests, shutdown).
    void flush() {
        std::unique_lock lock(_mu);
        _idle_cv.wait(lock, [&] { return _queue.empty() && !_writing; });
    }

private:
    void run() {
        std::uint64_t reported = 0;
        std::unique_lock lock(_mu);
        for (;;) {
            _cv.wait(lock, [&] { return _stopping || !_queue.empty(); });
            if (_queue.empty() && _stopping) {
                return;
            }
            std::vector<std::string> batch(std::make_move_iterator(_queue.begin()),
                                           std::make_move_iterator(_queue.end()));
            _queue.clear();
            _writing = true;
            lock.unlock();
            if (const auto d = dropped(); d != reported) {
                batch.push_back(R"({"audit":"dropped","lines":)" + std::to_string(d - reported) +
                                "}");
                reported = d;
            }
            _out(batch);
            lock.lock();
            _writing = false;
            _idle_cv.notify_all();
        }
    }

    batch_sink _out;
    std::size_t _capacity;
    std::mutex _mu;
    std::condition_variable _cv;
    std::condition_variable _idle_cv;
    std::deque<std::string> _queue;
    bool _stopping = false;
    bool _writing = false;
    std::atomic<std::uint64_t> _dropped{0};
    std::thread _writer;  // last: starts once the rest is built
};

}  // namespace kythira
