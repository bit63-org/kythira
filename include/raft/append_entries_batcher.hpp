// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file append_entries_batcher.hpp
/// @brief Coalesces many groups' AppendEntries for one destination into one
///        request (`.kiro/specs/multi-raft-message-batching/`).
///
/// ```
/// group A ─┐ group_scoped_client::send_append_entries(target, req)
/// group B ─┼──▶ append_entries_batcher ── per-destination queue ──▶ flush
/// group C ─┘        │ (marked / oversized)                          │
///                   ▼                                               ▼
///    shared client::send_append_entries   shared client::send_append_entries_batch
/// ```
///
/// `node<Types>` still calls `send_append_entries` and still gets back a
/// future of one response. It cannot tell whether its message travelled
/// alone (Requirement 1.3).
///
/// ### When a queue is flushed
///
/// - At the end of the host's send phase, by `flush_all()` (Requirement 3.1).
/// - By the batcher's own timer, at most `_max_delay` after a message was
///   queued, for sends made outside the send phase (Requirement 3.2). The
///   timer thread sleeps while every queue is empty, so an idle host pays
///   nothing for it.
/// - Inline, as soon as a queue holds `_max_messages` members or
///   `_max_bytes` of estimated payload (Requirement 3.3).
///
/// A member larger than `_max_bytes` on its own, and every member for a
/// destination currently marked as not batching, skips the queue and goes
/// through the shared client's ordinary `send_append_entries` (Requirement
/// 3.4, 4.1).
///
/// ### Ordering
///
/// A flush swaps a destination's whole queue out under that destination's
/// lock, and the batch is handed to the shared client while a second,
/// per-destination send lock is held. So batches to one destination are
/// *issued* in the order their members were queued, and a group's later
/// message can only travel in a later batch (Requirement 2.4). Two batches
/// may still complete out of order on the wire, exactly as two lone
/// AppendEntries from one group already can; Raft's `prev_log_index` check
/// makes either order safe.

#include <raft/exceptions.hpp>
#include <raft/executor_default.hpp>
#include <raft/future_default.hpp>
#include <raft/network.hpp>
#include <raft/synchronized.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace kythira {

/// @brief How a multi-Raft host batches AppendEntries (Requirement 1.4).
///
/// Off by default, and off means the host never builds a batcher: every
/// message takes exactly today's path, even on a batching transport.
struct batching_config {
    bool _enabled{false};
    /// Flush a destination once it holds this many members.
    std::size_t _max_messages{256};
    /// Flush a destination once its members' estimated size reaches this;
    /// a member this big on its own is sent alone.
    std::size_t _max_bytes{std::size_t{1} << 20U};
    /// Longest a message sent outside the send phase waits in a queue.
    std::chrono::microseconds _max_delay{500};
    /// How long a destination that answered "not implemented" is sent to
    /// message by message before batching is tried again.
    std::chrono::milliseconds _probe_interval{std::chrono::minutes{5}};
};

/// @brief The promise that fulfils a given future type, or `void` when the
///        batcher does not know how to make one.
///
/// The batcher hands each member a future before the batch is sent, so it
/// must make that future itself, and it must be the very type the shared
/// client's `send_append_entries` returns: `group_scoped_client` returns one
/// or the other from the same function. The project's default backend is the
/// one every batching transport returns (the HTTP clients build their own
/// futures the same way), so that is the one mapping provided. A client
/// returning anything else simply does not batch.
/// Upper bounds of a batcher's members-per-batch histogram buckets; one more
/// bucket counts everything above the last bound.
inline constexpr std::array<std::size_t, 9> batch_histogram_bounds{1,  2,  4,   8,  16,
                                                                   32, 64, 128, 256};

template<typename Future> struct batch_promise_for {
    using type = void;
};
template<typename T> struct batch_promise_for<future_default<T>> {
    using type = promise_default<T>;
};

/// @brief The future type a client's `send_append_entries` returns.
template<typename Client, typename Messages>
using append_entries_future_t =
    std::remove_cvref_t<decltype(std::declval<Client&>().send_append_entries(
        std::declval<typename Messages::node_id_type>(),
        std::declval<const typename Messages::append_entries_request_type&>(),
        std::chrono::milliseconds{}))>;

/// @brief A shared client the batcher can sit in front of: it speaks the
///        batch RPC, and the batcher can make the futures it returns.
template<typename Client, typename Messages>
concept append_entries_batching_client =
    network_client_with_append_entries_batch<Client, typename Messages::node_id_type> &&
    !std::is_void_v<typename batch_promise_for<append_entries_future_t<Client, Messages>>::type>;

/// @brief Per-destination AppendEntries queues over one shared client.
///
/// Not copyable or movable: completions capture `this`. The host owns one,
/// beside the shared client, for its lifetime, and `stop()` waits out every
/// batch still in flight before the client can go away.
///
/// @tparam Client   The host's shared client; must satisfy
///                  `append_entries_batching_client`.
/// @tparam Messages The RPC message bundle; see `group_rpc_messages`.
template<typename Client, typename Messages> class append_entries_batcher {
public:
    using node_id_type = typename Messages::node_id_type;
    using request_type = typename Messages::append_entries_request_type;
    using response_type = typename Messages::append_entries_response_type;
    using batch_request_type = append_entries_batch_request<request_type>;
    using batch_response_type = append_entries_batch_response<response_type>;
    using future_type = append_entries_future_t<Client, Messages>;
    using promise_type = typename batch_promise_for<future_type>::type;
    using clock = std::chrono::steady_clock;

    /// Upper bounds of the members-per-batch histogram's buckets; the last
    /// bucket counts everything above the last bound.
    static constexpr auto k_histogram_bounds = batch_histogram_bounds;

    append_entries_batcher(Client& inner, batching_config cfg) : _inner(&inner), _cfg(cfg) {
        _cfg._max_messages = std::max<std::size_t>(_cfg._max_messages, 1);
    }

    append_entries_batcher(const append_entries_batcher&) = delete;
    auto operator=(const append_entries_batcher&) -> append_entries_batcher& = delete;
    append_entries_batcher(append_entries_batcher&&) = delete;
    auto operator=(append_entries_batcher&&) -> append_entries_batcher& = delete;

    ~append_entries_batcher() { stop(); }

    [[nodiscard]] auto config() const -> const batching_config& { return _cfg; }

    /// @brief Where the batcher reports a destination it stops batching to
    ///        (Requirement 4.1: once per marking, at info level).
    auto set_info_logger(std::function<void(const std::string&)> log) -> void {
        _info = std::move(log);
    }

    /// @brief Start the off-tick flush timer (and, on the boost future
    ///        backend, the member completion pool). Idempotent.
    auto start() -> void {
        std::lock_guard lock(_timer_mutex);
#if defined(KYTHIRA_FUTURE_BACKEND_BOOST)
        if (!_completion_pool) {
            _completion_pool = std::make_unique<executor_default>(completion_threads());
            _completion_executor.store(_completion_pool.get(), std::memory_order_release);
        }
#endif
        if (_timer.joinable()) {
            return;
        }
        _stopping = false;
        _timer = std::thread([this] { run_timer(); });
    }

    /// @brief Send everything still queued, stop the timer, and wait for
    ///        every batch in flight to complete. Idempotent.
    auto stop() -> void {
        // A host over a client that cannot batch still names this type (its
        // `unique_ptr` member does, and that instantiates this destructor)
        // but never builds one. Nothing below may be instantiated for such a
        // client: it would name the batch RPC the client does not have.
        if constexpr (append_entries_batching_client<Client, Messages>) {
            {
                std::lock_guard lock(_timer_mutex);
                _stopping = true;
            }
            _timer_cv.notify_all();
            if (_timer.joinable()) {
                _timer.join();
            }
            flush_all();
            std::unique_lock lock(_flight_mutex);
            _flight_cv.wait(lock, [&] { return _in_flight == 0; });
        }
    }

    // ── sending ──────────────────────────────────────────────────────────────

    /// @brief Queue one group-stamped AppendEntries for `target`.
    ///
    /// The returned future completes with this member's own response, or with
    /// the exception it would have seen sent alone (Requirement 2.1).
    auto send(const node_id_type& target, const request_type& req,
              std::chrono::milliseconds timeout) -> future_type {
        const auto bytes = estimate_bytes(req);
        if (bytes > _cfg._max_bytes) {
            _oversized.fetch_add(1, std::memory_order_relaxed);
            return _inner->send_append_entries(target, req, timeout);
        }

        auto& dest = destination_for(target);
        auto promise = std::make_shared<promise_type>();
        auto future = member_future(*promise);
        std::vector<pending> overflow;
        std::vector<pending> full;
        bool wake_timer = false;
        // Completion is attached only once every batcher lock is released:
        // see `launch`.
        std::vector<launch> launches;
        {
            std::unique_lock lock(dest._mutex);
            if (clock::now() < dest._not_batching_until) {
                lock.unlock();
                return _inner->send_append_entries(target, req, timeout);
            }
            // A member that would push the queue past the byte cap closes
            // the current batch first, so no batch exceeds `_max_bytes`.
            if (!dest._queue.empty() && dest._bytes + bytes > _cfg._max_bytes) {
                overflow = take(dest);
            }
            if (dest._queue.empty()) {
                dest._first_enqueued = clock::now();
                wake_timer = true;
            }
            dest._queue.push_back(pending{req, timeout, std::move(promise), bytes});
            dest._bytes += bytes;
            _queued.fetch_add(1, std::memory_order_relaxed);
            if (dest._queue.size() >= _cfg._max_messages || dest._bytes >= _cfg._max_bytes) {
                full = take(dest);
                wake_timer = false;
            }
            // The send lock is taken before the queue lock is released, so a
            // batch taken here is issued before any batch taken after it.
            if (!overflow.empty() || !full.empty()) {
                std::unique_lock send_lock(dest._send_mutex);
                lock.unlock();
                if (!overflow.empty()) {
                    launches.push_back(issue(target, std::move(overflow)));
                }
                if (!full.empty()) {
                    launches.push_back(issue(target, std::move(full)));
                }
            }
        }
        run(launches);
        if (wake_timer) {
            std::lock_guard timer_lock(_timer_mutex);
            _timer_cv.notify_one();
        }
        return future;
    }

    /// @brief Send every queued member now (Requirement 3.1).
    auto flush_all() -> void {
        flush_if([](const destination&) { return true; });
    }

    /// @brief Send every destination whose oldest member will have waited
    ///        `_max_delay` by `deadline` (Requirement 3.2).
    auto flush_due(clock::time_point deadline) -> void {
        flush_if([this, deadline](const destination& d) {
            return d._first_enqueued + _cfg._max_delay <= deadline;
        });
    }

    // ── observability (Requirement 6) ────────────────────────────────────────

    [[nodiscard]] auto batches_sent() const -> std::uint64_t {
        return _batches.load(std::memory_order_relaxed);
    }
    [[nodiscard]] auto members_sent() const -> std::uint64_t {
        return _members.load(std::memory_order_relaxed);
    }
    /// Batches whose members were resent one by one: "not implemented" and
    /// "too large" refusals.
    [[nodiscard]] auto fallbacks() const -> std::uint64_t {
        return _fallbacks.load(std::memory_order_relaxed);
    }
    /// Members sent alone because they exceeded `_max_bytes` by themselves.
    [[nodiscard]] auto oversized_sent() const -> std::uint64_t {
        return _oversized.load(std::memory_order_relaxed);
    }
    /// Members waiting in a queue right now.
    [[nodiscard]] auto queued() const -> std::uint64_t {
        return _queued.load(std::memory_order_relaxed);
    }
    [[nodiscard]] auto members_per_batch_histogram() const
        -> std::array<std::uint64_t, k_histogram_bounds.size() + 1> {
        std::array<std::uint64_t, k_histogram_bounds.size() + 1> out{};
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = _histogram[i].load(std::memory_order_relaxed);
        }
        return out;
    }
    /// Destinations currently sent to message by message.
    [[nodiscard]] auto marked_destinations() const -> std::size_t {
        const auto now = clock::now();
        std::size_t count = 0;
        for (auto* d : destinations()) {
            std::lock_guard lock(d->_mutex);
            if (now < d->_not_batching_until) {
                ++count;
            }
        }
        return count;
    }

private:
    struct pending {
        request_type _req;
        std::chrono::milliseconds _timeout;
        std::shared_ptr<promise_type> _done;
        std::size_t _bytes;
    };

    struct destination {
        explicit destination(node_id_type id) : _id(std::move(id)) {}
        node_id_type _id;
        std::mutex _mutex;
        /// Held from taking a batch until it has been handed to the client.
        std::mutex _send_mutex;
        std::vector<pending> _queue;
        std::size_t _bytes{0};
        clock::time_point _first_enqueued{};
        clock::time_point _not_batching_until{};
    };

    /// What one in-flight batch needs at completion: the members' requests
    /// (for a fallback resend and the unknown-group answer) and promises.
    struct in_flight_batch {
        node_id_type _target;
        batch_request_type _request;
        std::vector<std::chrono::milliseconds> _timeouts;
        std::vector<std::shared_ptr<promise_type>> _done;
    };

    /// A size estimate, not an encoding: the batcher sits above the
    /// serializer. The fixed costs are a generous bound on a member's
    /// envelope, so the estimate errs towards smaller batches.
    [[nodiscard]] static auto estimate_bytes(const request_type& req) -> std::size_t {
        std::size_t bytes = 64;
        for (const auto& e : req.entries()) {
            bytes += 32;
            if constexpr (requires { e.command().size(); }) {
                bytes += e.command().size();
            }
        }
        return bytes;
    }

    auto destination_for(const node_id_type& target) -> destination& {
        {
            auto locked = _dests.rlock();
            if (auto it = locked->find(target); it != locked->end()) {
                return *it->second;
            }
        }
        auto locked = _dests.wlock();
        auto [it, inserted] = locked->try_emplace(target, nullptr);
        if (inserted) {
            it->second = std::make_unique<destination>(target);
        }
        return *it->second;
    }

    /// Destinations are never erased, so a raw pointer outlives the lock.
    [[nodiscard]] auto destinations() const -> std::vector<destination*> {
        std::vector<destination*> out;
        auto locked = _dests.rlock();
        out.reserve(locked->size());
        for (const auto& [id, d] : *locked) {
            out.push_back(d.get());
        }
        return out;
    }

    /// Swap a destination's queue out. Caller holds `dest._mutex`.
    auto take(destination& dest) -> std::vector<pending> {
        std::vector<pending> out;
        out.swap(dest._queue);
        dest._bytes = 0;
        _queued.fetch_sub(out.size(), std::memory_order_relaxed);
        return out;
    }

    template<typename Pred> auto flush_if(Pred pred) -> void {
        for (auto* d : destinations()) {
            std::unique_lock lock(d->_mutex);
            if (d->_queue.empty() || !pred(*d)) {
                continue;
            }
            auto batch = take(*d);
            launch next;
            {
                std::unique_lock send_lock(d->_send_mutex);
                lock.unlock();
                next = issue(d->_id, std::move(batch));
            }
            if (next) {
                next();
            }
        }
    }

    /// What is left of issuing a batch once the client has it: attaching
    /// the completion. The caller runs it after releasing every batcher
    /// lock, never under `_send_mutex`. A client may return a future that
    /// is already complete (a refused or failed send, an in-process
    /// fabric), and on the Folly backend a continuation attached to such a
    /// future runs at once, on this thread. Completion fulfils member
    /// promises, whose own continuations (the group's response handling)
    /// may then send the next AppendEntries to the same destination. Under
    /// `_send_mutex` that send blocked on the lock its own thread held:
    /// the split suite's batching run hung for 15 minutes in most CI runs.
    using launch = std::function<void()>;

    static auto run(std::vector<launch>& launches) -> void {
        for (auto& l : launches) {
            if (l) {
                l();
            }
        }
    }

    /// Hand one batch to the shared client. A batch of one is still sent as
    /// a batch: it is what probes a destination after `_probe_interval`, and
    /// it keeps the receive side on one code path.
    ///
    /// Called with `_send_mutex` held, so batches reach the client in the
    /// order they were taken; returns the completion for the caller to
    /// attach once that lock is released.
    [[nodiscard]] auto issue(const node_id_type& target, std::vector<pending> members) -> launch {
        // The host calls `flush_all()` behind a run-time check, so this is
        // instantiated for a client that cannot batch as well; such a host
        // never builds a batcher, and nothing can have been queued.
        if constexpr (append_entries_batching_client<Client, Messages>) {
            return issue_batch(target, std::move(members));
        } else {
            return {};
        }
    }

    [[nodiscard]] auto issue_batch(const node_id_type& target, std::vector<pending> members)
        -> launch {
        auto batch = std::make_shared<in_flight_batch>();
        batch->_target = target;
        batch->_request._members.reserve(members.size());
        batch->_timeouts.reserve(members.size());
        batch->_done.reserve(members.size());
        auto timeout = members.front()._timeout;
        for (auto& m : members) {
            // Requirement 2.5: the batch waits no longer than its most
            // impatient member would have alone.
            timeout = std::min(timeout, m._timeout);
            batch->_request._members.push_back(std::move(m._req));
            batch->_timeouts.push_back(m._timeout);
            batch->_done.push_back(std::move(m._done));
        }

        _batches.fetch_add(1, std::memory_order_relaxed);
        _members.fetch_add(members.size(), std::memory_order_relaxed);
        _histogram[bucket_of(members.size())].fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard lock(_flight_mutex);
            ++_in_flight;
        }
        try {
            auto sent = _inner->send_append_entries_batch(target, batch->_request, timeout);
            auto held = std::make_shared<decltype(sent)>(std::move(sent));
            return [this, batch, held] {
                std::move(*held)
                    .thenTry([this, batch](auto&& result) {
                        complete(*batch, std::forward<decltype(result)>(result));
                        finish_flight();
                    })
                    .detach();
            };
        } catch (...) {
            return [this, batch, error = std::current_exception()] {
                fail_all(*batch, error);
                finish_flight();
            };
        }
    }

    template<typename Try> auto complete(in_flight_batch& batch, Try&& result) -> void {
        if (result.hasException()) {
            const std::exception_ptr error = result.exception();
            try {
                std::rethrow_exception(error);
            } catch (const rpc_not_implemented_exception&) {
                // An older peer (Requirement 4.1): every member again, alone,
                // and no batches to it until the probe interval has passed.
                mark_not_batching(batch._target);
                resend_alone(batch);
            } catch (const rpc_payload_too_large_exception&) {
                // Too big for this peer's limits (Requirement 5.4): only this
                // batch goes alone. The peer does take batches.
                resend_alone(batch);
            } catch (...) {
                // Requirement 2.2: the whole batch failed, so every member did.
                fail_all(batch, error);
            }
            return;
        }

        auto& response = result.value();
        if (response._members.size() != batch._done.size()) {
            fail_all(batch, std::make_exception_ptr(network_exception(
                                "append_entries_batch: peer answered " +
                                std::to_string(response._members.size()) + " members for " +
                                std::to_string(batch._done.size()))));
            return;
        }
        for (std::size_t i = 0; i < batch._done.size(); ++i) {
            auto& slot = response._members[i];
            auto& done = *batch._done[i];
            if (auto* ok = std::get_if<0>(&slot)) {
                done.setValue(std::move(*ok));
                continue;
            }
            const auto& err = std::get<1>(slot);
            if (err.kind() == batch_member_error::kind_type::unknown_group) {
                // Requirement 2.3: exactly what the receiver's demultiplexer
                // answers a lone message for a group it does not hold.
                const auto& req = batch._request._members[i];
                done.setValue(response_type{._term = req.term(),
                                            ._success = false,
                                            ._conflict_index = std::nullopt,
                                            ._conflict_term = std::nullopt,
                                            ._group_id = req.group_id()});
            } else {
                done.setException(std::make_exception_ptr(network_exception(
                    "append_entries_batch: member failed at peer: " + err.message())));
            }
        }
    }

    auto resend_alone(in_flight_batch& batch) -> void {
        _fallbacks.fetch_add(1, std::memory_order_relaxed);
        for (std::size_t i = 0; i < batch._done.size(); ++i) {
            auto done = batch._done[i];
            try {
                _inner
                    ->send_append_entries(batch._target, batch._request._members[i],
                                          batch._timeouts[i])
                    .thenTry([done](auto&& r) {
                        if (r.hasException()) {
                            done->setException(r.exception());
                        } else {
                            done->setValue(std::move(r.value()));
                        }
                    })
                    .detach();
            } catch (...) {
                done->setException(std::current_exception());
            }
        }
    }

    static auto fail_all(in_flight_batch& batch, const std::exception_ptr& error) -> void {
        for (auto& done : batch._done) {
            done->setException(error);
        }
    }

    auto mark_not_batching(const node_id_type& target) -> void {
        auto& dest = destination_for(target);
        bool newly = false;
        {
            std::lock_guard lock(dest._mutex);
            const auto now = clock::now();
            newly = !(now < dest._not_batching_until);
            dest._not_batching_until = now + _cfg._probe_interval;
        }
        if (newly && _info) {
            _info(
                "append_entries_batch: peer does not take batched AppendEntries; sending to it "
                "message by message until the next probe");
        }
    }

    /// @brief The future a member's caller gets back.
    ///
    /// On the boost future backend a continuation attached to a plain
    /// promise's future runs on a freshly created OS thread, and
    /// `pthread_create` serialises on a glibc lock. Lone AppendEntries do
    /// not pay this: the Beast client `.via()`s each response future onto
    /// its stream's strand. A batch response fulfils every member's
    /// promise at once, so completing a 1000-member batch meant 1000
    /// thread creations back to back. On a 48-thread host at 1000 groups
    /// every asio I/O thread sat in `pthread_create`, heartbeats and votes
    /// timed out and the cluster crawled; moving completion to one
    /// dedicated thread made it worse (thread creation could no longer
    /// keep up at all). Running member continuations on a small pool
    /// removes the thread creation instead. A batcher that was never
    /// started (unit tests drive it by hand) hands back the plain future.
    /// The Folly and stdexec backends do not start a thread per
    /// continuation, so their futures are left as they are.
    auto member_future(promise_type& promise) -> future_type {
        auto future = promise.getFuture();
#if defined(KYTHIRA_FUTURE_BACKEND_BOOST)
        if (auto* pool = _completion_executor.load(std::memory_order_acquire)) {
            return std::move(future).via(pool->handle());
        }
#endif
        return future;
    }

    static auto completion_threads() -> std::size_t {
        return std::clamp<std::size_t>(std::thread::hardware_concurrency() / 8, 2, 8);
    }

    auto finish_flight() -> void {
        std::lock_guard lock(_flight_mutex);
        if (--_in_flight == 0) {
            _flight_cv.notify_all();
        }
    }

    [[nodiscard]] static auto bucket_of(std::size_t members) -> std::size_t {
        for (std::size_t i = 0; i < k_histogram_bounds.size(); ++i) {
            if (members <= k_histogram_bounds[i]) {
                return i;
            }
        }
        return k_histogram_bounds.size();
    }

    auto run_timer() -> void {
        std::unique_lock lock(_timer_mutex);
        while (!_stopping) {
            if (_queued.load(std::memory_order_relaxed) == 0) {
                _timer_cv.wait(
                    lock, [&] { return _stopping || _queued.load(std::memory_order_relaxed) > 0; });
                continue;
            }
            _timer_cv.wait_for(lock, _cfg._max_delay, [&] { return _stopping; });
            if (_stopping) {
                break;
            }
            lock.unlock();
            // Anything that would otherwise wait past its bound before the
            // next wake goes now, so no member waits longer than `_max_delay`.
            flush_due(clock::now() + _cfg._max_delay);
            lock.lock();
        }
    }

    Client* _inner;
    batching_config _cfg;
    std::function<void(const std::string&)> _info;
    synchronized<std::unordered_map<node_id_type, std::unique_ptr<destination>>> _dests;

    std::atomic<std::uint64_t> _queued{0};
    std::atomic<std::uint64_t> _batches{0};
    std::atomic<std::uint64_t> _members{0};
    std::atomic<std::uint64_t> _fallbacks{0};
    std::atomic<std::uint64_t> _oversized{0};
    std::array<std::atomic<std::uint64_t>, k_histogram_bounds.size() + 1> _histogram{};

    std::mutex _timer_mutex;
    std::condition_variable _timer_cv;
    bool _stopping{false};
    std::thread _timer;

    // Boost backend only: where member futures' continuations run (see
    // member_future()). Created by start() and kept until destruction, so
    // a continuation chained after stop() still has somewhere to run.
    std::unique_ptr<executor_default> _completion_pool;
    std::atomic<executor_default*> _completion_executor{nullptr};

    std::mutex _flight_mutex;
    std::condition_variable _flight_cv;
    std::size_t _in_flight{0};
};

/// @brief Publishes a batcher's counters to a metrics sink
///        (.kiro/specs/multi-raft-message-batching/ Requirement 6.2).
///
/// Holds what it last published, so each `publish` emits only the change:
/// a sink that sums counts sees the batcher's totals, however the batches
/// were flushed (tick, timer or full queue) between two calls. The metrics
/// concept has no histogram primitive, so members per batch goes out as one
/// count per bucket with a `max_members` dimension naming the bucket's upper
/// bound ("more" for the overflow bucket). Buckets do not overlap, unlike a
/// Prometheus `le`, so a sink sums them. Marked destinations is a gauge,
/// emitted only when it moves; a call with no change emits nothing.
///
/// Not thread-safe: one caller (the host's `tick()`) publishes, holding
/// whatever lock guards the sink.
class batching_metrics_emitter {
public:
    static constexpr const char* k_batches = "kythira.multiraft.batching.batches";
    static constexpr const char* k_fallbacks = "kythira.multiraft.batching.fallbacks";
    static constexpr const char* k_members_per_batch =
        "kythira.multiraft.batching.members_per_batch";
    static constexpr const char* k_marked_destinations =
        "kythira.multiraft.batching.marked_destinations";

    template<typename Batcher, typename Metrics>
    auto publish(const Batcher& batcher, Metrics& metrics) -> void {
        const auto histogram = batcher.members_per_batch_histogram();
        static_assert(std::tuple_size_v<decltype(histogram)> ==
                      std::tuple_size_v<decltype(_histogram)>);
        count(metrics, k_batches, batcher.batches_sent(), _batches);
        count(metrics, k_fallbacks, batcher.fallbacks(), _fallbacks);
        for (std::size_t i = 0; i < histogram.size(); ++i) {
            if (histogram[i] > _histogram[i]) {
                metrics.set_metric_name(k_members_per_batch);
                metrics.add_dimension("max_members", i < k_bounds.size()
                                                         ? std::to_string(k_bounds[i])
                                                         : std::string{"more"});
                metrics.add_count(static_cast<std::int64_t>(histogram[i] - _histogram[i]));
                metrics.emit();
            }
            _histogram[i] = histogram[i];
        }
        const auto marked = batcher.marked_destinations();
        if (marked != _marked) {
            metrics.set_metric_name(k_marked_destinations);
            metrics.add_value(static_cast<double>(marked));
            metrics.emit();
            _marked = marked;
        }
    }

private:
    static constexpr auto k_bounds = batch_histogram_bounds;

    template<typename Metrics>
    static auto count(Metrics& metrics, const char* name, std::uint64_t now, std::uint64_t& was)
        -> void {
        if (now > was) {
            metrics.set_metric_name(name);
            metrics.add_count(static_cast<std::int64_t>(now - was));
            metrics.emit();
        }
        was = now;
    }

    std::uint64_t _batches{0};
    std::uint64_t _fallbacks{0};
    std::size_t _marked{0};
    std::array<std::uint64_t, k_bounds.size() + 1> _histogram{};
};

}  // namespace kythira
