// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file remote_segment_store.hpp
/// @brief A `segment_store` whose segments live in a volume on a segment
///        node (.kiro/specs/kinesis-independent-layers/ task 9, design
///        "Segment store as a layer", Requirements 9.1-9.3 and 9.6).
///
/// A data replica that does not keep its record bytes on its own disk holds
/// one of these instead of a `record_segment_store`. Every call becomes one
/// request to the segment node's `segment_volume_service`
/// (`segment_volume_service.hpp`), carrying the replica's volume id and
/// writer epoch; the state machine cannot tell the difference.
///
/// - **Appends** write through the segment node's page cache and return the
///   segments that rolled, as a local append does. They are not durable
///   until a barrier, and need no fsync of their own, so an append costs one
///   round trip and no disk wait.
/// - **Barriers** coalesce: concurrent `apply()` callers share one barrier
///   request covering every append that returned before it was sent, as
///   concurrent local barriers share one round of fsyncs. The segment node
///   runs its volume's barrier and answers. The added latency per
///   acknowledged write is one data-to-segment round trip.
/// - **Fencing**: a write refused for its epoch throws
///   `segment_volume_fenced`, and an unreachable volume throws
///   `record_segment_error`. A state machine treats both like a failed disk:
///   it stops applying (a skipped append would diverge) and the replica is
///   replaced (Requirement 9.6).
/// - `install_segment` refusals come back as `std::invalid_argument`, as the
///   local store throws them.
///
/// Appends are one request each rather than streamed ahead of their roll
/// results: `append` must return the segments that sealed, and predicting
/// rolls here would mean re-implementing the segment file format on the
/// client. The measurement row (task 15) states the per-append cost.

#include <raft/segment_store.hpp>
#include <raft/segment_volume_service.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

/// Sends one volume API request to the segment node and returns its
/// response; `nullopt` when the node cannot be reached.
using segment_volume_transport =
    std::function<std::optional<std::vector<std::byte>>(std::vector<std::byte> request)>;

class remote_segment_store final : public segment_store {
public:
    using segment_store::append;
    using segment_store::read;
    using segment_store::read_segment;

    /// Opens `volume` as the writer at `epoch`. Throws
    /// `record_segment_error` when the segment node cannot be reached or
    /// has no such volume.
    remote_segment_store(segment_volume_transport transport, std::string volume,
                         std::uint64_t epoch)
        : _transport(std::move(transport)), _volume(std::move(volume)), _epoch(epoch) {
        if (!_transport) {
            throw std::invalid_argument("remote_segment_store: no transport");
        }
        auto r = call(volume_wire::op::max_record_bytes, [](volume_wire::writer&) {}, 0);
        _max_record_bytes = static_cast<std::uint32_t>(r.uint());
    }

    remote_segment_store(const remote_segment_store&) = delete;
    auto operator=(const remote_segment_store&) -> remote_segment_store& = delete;
    remote_segment_store(remote_segment_store&&) = delete;
    auto operator=(remote_segment_store&&) -> remote_segment_store& = delete;
    ~remote_segment_store() override = default;

    [[nodiscard]] auto volume() const noexcept -> const std::string& { return _volume; }
    [[nodiscard]] auto epoch() const noexcept -> std::uint64_t { return _epoch; }
    /// Barrier requests sent, against `barrier()` calls: the coalescing.
    [[nodiscard]] auto barrier_requests() const -> std::uint64_t {
        const std::lock_guard lock(_barrier_mu);
        return _barrier_requests;
    }

    [[nodiscard]] auto max_record_bytes() const noexcept -> std::uint32_t override {
        return _max_record_bytes;
    }

    // ---- writes ---------------------------------------------------------

    auto append(const std::string& stream, std::span<const segment_record_view> records)
        -> record_segment_append_result override {
        auto r = call(
            volume_wire::op::append,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.array(records.size());
                for (const auto& rec : records) {
                    w.array(3);
                    w.uint(rec._seq);
                    w.uint(static_cast<std::uint64_t>(rec._timestamp_ms));
                    w.bytes(rec._data);
                }
            },
            2);
        record_segment_append_result out;
        out._sealed.resize(r.array());
        for (auto& d : out._sealed) {
            d = r.descriptor();
        }
        {
            const std::lock_guard lock(_barrier_mu);
            ++_appended;
        }
        return out;
    }

    void barrier() override {
        std::unique_lock lock(_barrier_mu);
        const auto target = _appended;
        while (_durable < target) {
            if (_barrier_in_flight) {
                _barrier_cv.wait(lock);
                continue;
            }
            _barrier_in_flight = true;
            const auto covers = _appended;
            lock.unlock();
            try {
                (void)call(volume_wire::op::barrier, [](volume_wire::writer&) {}, 0);
            } catch (...) {
                lock.lock();
                _barrier_in_flight = false;
                _barrier_cv.notify_all();
                throw;
            }
            lock.lock();
            _barrier_in_flight = false;
            _durable = std::max(_durable, covers);
            ++_barrier_requests;
            _barrier_cv.notify_all();
        }
    }

    auto seal(const std::string& stream) -> std::optional<record_segment_descriptor> override {
        auto r = call(volume_wire::op::seal, [&](volume_wire::writer& w) { w.text(stream); }, 1);
        if (r.null()) {
            return std::nullopt;
        }
        return r.descriptor();
    }

    void truncate_after(const std::string& stream, std::optional<std::uint64_t> seq) override {
        (void)call(
            volume_wire::op::truncate_after,
            [&](volume_wire::writer& w) {
                w.text(stream);
                seq ? w.uint(*seq) : w.null();
            },
            2);
    }

    auto trim_before(const std::string& stream, std::uint64_t seq)
        -> std::vector<std::uint64_t> override {
        auto r = call(
            volume_wire::op::trim_before,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(seq);
            },
            2);
        std::vector<std::uint64_t> out(r.array());
        for (auto& s : out) {
            s = r.uint();
        }
        return out;
    }

    auto remove_segment(const std::string& stream, std::uint64_t first_seq) -> bool override {
        auto r = call(
            volume_wire::op::remove_segment,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(first_seq);
            },
            2);
        return r.boolean();
    }

    void drop_stream(const std::string& stream) override {
        (void)call(
            volume_wire::op::drop_stream, [&](volume_wire::writer& w) { w.text(stream); }, 1);
    }

    auto install_segment(const record_segment_descriptor& d, std::span<const std::byte> bytes)
        -> bool override {
        auto r = call(
            volume_wire::op::install_segment,
            [&](volume_wire::writer& w) {
                w.descriptor(d);
                w.bytes(bytes);
            },
            2);
        return r.boolean();
    }

    /// Fetches `d` from the first peer whose bytes match it, through this
    /// data node, and installs it in the volume.
    auto fetch_segment(const record_segment_descriptor& d, std::span<const std::string> peers,
                       const fetch_transport& transport) -> bool override {
        if (has_segment(d)) {
            return true;
        }
        for (const auto& peer : peers) {
            auto bytes = transport(peer, d._stream, d._first_seq, d._bytes);
            if (!bytes || bytes->size() != d._bytes || segment_sha256_of(*bytes) != d._sha256) {
                ++_fetch_misses;
                continue;
            }
            try {
                (void)install_segment(d, *bytes);
                return true;
            } catch (const std::invalid_argument&) {
                ++_fetch_misses;
            }
        }
        return false;
    }

    // ---- reads ----------------------------------------------------------

    [[nodiscard]] auto read_segment_bytes(const std::string& stream, std::uint64_t first_seq,
                                          std::uint64_t length) const
        -> std::optional<std::vector<std::byte>> override {
        auto r = call(
            volume_wire::op::read_segment_bytes,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(first_seq);
                w.uint(length);
            },
            3);
        if (r.null()) {
            return std::nullopt;
        }
        return r.bytes();
    }

    [[nodiscard]] auto read_segment(const std::string& stream, std::uint64_t first_seq,
                                    std::uint64_t from_seq, const segment_read_limits& limits) const
        -> std::optional<segment_read_result> override {
        auto r = call(
            volume_wire::op::read_segment,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(first_seq);
                w.uint(from_seq);
                w.uint(limits._max_records);
                w.uint(limits._max_bytes);
            },
            5);
        if (r.null()) {
            return std::nullopt;
        }
        return volume_wire::read_read_result(r.wire());
    }

    [[nodiscard]] auto read(const std::string& stream, std::uint64_t from_seq,
                            const segment_read_limits& limits) const
        -> segment_read_result override {
        auto r = call(
            volume_wire::op::read,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(from_seq);
                w.uint(limits._max_records);
                w.uint(limits._max_bytes);
            },
            4);
        return volume_wire::read_read_result(r.wire());
    }

    [[nodiscard]] auto describe(const std::string& stream, std::uint64_t first_seq) const
        -> std::optional<record_segment_descriptor> override {
        auto r = call(
            volume_wire::op::describe,
            [&](volume_wire::writer& w) {
                w.text(stream);
                w.uint(first_seq);
            },
            2);
        if (r.null()) {
            return std::nullopt;
        }
        return r.descriptor();
    }

    [[nodiscard]] auto local_segments(const std::string& stream) const
        -> std::vector<record_segment_descriptor> override {
        auto r = call(
            volume_wire::op::local_segments, [&](volume_wire::writer& w) { w.text(stream); }, 1);
        std::vector<record_segment_descriptor> out(r.array());
        for (auto& d : out) {
            d = r.descriptor();
        }
        return out;
    }

    [[nodiscard]] auto has_segment(const record_segment_descriptor& d) const -> bool override {
        auto r =
            call(volume_wire::op::has_segment, [&](volume_wire::writer& w) { w.descriptor(d); }, 1);
        return r.boolean();
    }

    [[nodiscard]] auto last_seq(const std::string& stream) const
        -> std::optional<std::uint64_t> override {
        auto r =
            call(volume_wire::op::last_seq, [&](volume_wire::writer& w) { w.text(stream); }, 1);
        if (r.null()) {
            return std::nullopt;
        }
        return r.uint();
    }

    [[nodiscard]] auto streams() const -> std::vector<std::string> override {
        auto r = call(volume_wire::op::streams, [](volume_wire::writer&) {}, 0);
        std::vector<std::string> out(r.array());
        for (auto& s : out) {
            s = r.text();
        }
        return out;
    }

    /// The volume's stats, with this client's fetch misses added.
    [[nodiscard]] auto stats() const -> record_segment_store_stats override {
        auto r = call(volume_wire::op::stats, [](volume_wire::writer&) {}, 0);
        auto s = volume_wire::read_stats(r.wire());
        s._fetch_misses += _fetch_misses;
        return s;
    }

private:
    /// A response reader that keeps its bytes alive.
    class response {
    public:
        explicit response(std::vector<std::byte> bytes)
            : _bytes(std::move(bytes)), _reader(_bytes) {}
        response(const response&) = delete;
        auto operator=(const response&) -> response& = delete;
        response(response&&) = delete;
        auto operator=(response&&) -> response& = delete;
        ~response() = default;

        [[nodiscard]] auto reader() -> volume_wire::reader& { return _reader; }

    private:
        std::vector<std::byte> _bytes;
        volume_wire::reader _reader;
    };

    /// The results of one successful call, read in order.
    class results {
    public:
        explicit results(std::vector<std::byte> bytes)
            : _response(std::make_unique<response>(std::move(bytes))) {}

        [[nodiscard]] auto uint() -> std::uint64_t { return wire().uint(); }
        [[nodiscard]] auto bytes() -> std::vector<std::byte> { return wire().bytes(); }
        [[nodiscard]] auto text() -> std::string { return wire().text(); }
        [[nodiscard]] auto array() -> std::size_t { return wire().array(); }
        [[nodiscard]] auto boolean() -> bool { return wire().boolean(); }
        [[nodiscard]] auto null() -> bool { return wire().null(); }
        [[nodiscard]] auto descriptor() -> record_segment_descriptor { return wire().descriptor(); }
        [[nodiscard]] auto wire() -> volume_wire::reader& { return _response->reader(); }

    private:
        std::unique_ptr<response> _response;
    };

    /// Sends `[op, volume, epoch, args...]` (`args` writes `arg_count`
    /// items) and returns the results after an `ok` status.
    template<typename Args>
    [[nodiscard]] auto call(volume_wire::op o, Args&& args, std::size_t arg_count) const
        -> results {
        volume_wire::writer w;
        w.array(3 + arg_count);
        w.uint(static_cast<std::uint64_t>(o));
        w.text(_volume);
        w.uint(_epoch);
        std::forward<Args>(args)(w);
        auto reply = _transport(w.take());
        if (!reply) {
            throw record_segment_error("remote_segment_store: volume " + _volume +
                                       " is unreachable");
        }
        results res(std::move(*reply));
        std::uint64_t status = 0;
        std::size_t n = 0;
        try {
            n = res.array();
            status = n == 0 ? static_cast<std::uint64_t>(volume_wire::status::failed) : res.uint();
        } catch (const std::invalid_argument& e) {
            throw record_segment_error(std::string("remote_segment_store: bad response: ") +
                                       e.what());
        }
        if (status == static_cast<std::uint64_t>(volume_wire::status::ok)) {
            return res;
        }
        std::string message = "(no message)";
        if (n >= 2) {
            try {
                message = res.text();
            } catch (const std::invalid_argument&) {
            }
        }
        message = "remote_segment_store: volume " + _volume + ": " + message;
        switch (static_cast<volume_wire::status>(status)) {
            case volume_wire::status::stale_epoch:
                throw segment_volume_fenced(message);
            case volume_wire::status::invalid_argument:
                throw std::invalid_argument(message);
            default:
                throw record_segment_error(message);
        }
    }

    segment_volume_transport _transport;
    std::string _volume;
    std::uint64_t _epoch;
    std::uint32_t _max_record_bytes = 0;

    mutable std::mutex _barrier_mu;
    std::condition_variable _barrier_cv;
    std::uint64_t _appended = 0;
    std::uint64_t _durable = 0;
    bool _barrier_in_flight = false;
    std::uint64_t _barrier_requests = 0;
    std::atomic<std::uint64_t> _fetch_misses{0};
};

}  // namespace kythira
