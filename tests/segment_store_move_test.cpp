// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The in-place store move (include/raft/segment_store_move.hpp,
// .kiro/specs/kinesis-independent-layers/ task 13, Requirement 11.5): a
// replica's segments go from a local directory to a segment node's volume
// and back while a writer keeps appending, the tail is copied behind a
// bounded fence by appending (not by recopying the segment), the pause is
// measured, and every way the move can fail leaves the old store serving.

#define BOOST_TEST_MODULE segment_store_move_test

#include <boost/test/unit_test.hpp>

#include "record_segment_store_conformance.hpp"

#include <raft/record_segment_store.hpp>
#include <raft/remote_segment_store.hpp>
#include <raft/segment_store_move.hpp>
#include <raft/segment_volume_service.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using kythira::segment_conformance::scratch_dir;

auto payload(std::uint64_t seq) -> std::vector<std::byte> {
    std::vector<std::byte> out(64 + (seq * 37) % 300);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>((seq * 31 + i) & 0xFFU);
    }
    return out;
}

auto small_segments(const fs::path& dir = {}) -> kythira::record_segment_store_options {
    kythira::record_segment_store_options o;
    o._data_dir = dir;
    o._max_segment_bytes = 4096;
    o._index_interval_bytes = 256;
    return o;
}

auto local_store(const fs::path& dir) -> std::unique_ptr<kythira::record_segment_store> {
    fs::create_directories(dir);
    return std::make_unique<kythira::record_segment_store>(small_segments(dir));
}

void put(kythira::segment_store& s, const std::string& stream, std::uint64_t seq) {
    const auto p = payload(seq);
    (void)s.append(stream, kythira::segment_record_view{
                               seq, 1'700'000'000'000 + static_cast<std::int64_t>(seq), p});
}

/// Appends `n` records to each of two streams, sealing one stream midway
/// and trimming the other, so there are sealed, active and trimmed
/// segments to move.
auto fill(kythira::segment_store& s, std::uint64_t n) -> void {
    for (std::uint64_t seq = 1; seq <= n; ++seq) {
        put(s, "shard-a", seq);
        if (seq % 2 == 0) {
            put(s, "shard-b", seq);
        }
    }
    (void)s.seal("shard-b");
    (void)s.trim_before("shard-a", n / 4);
    s.barrier();
}

auto read_all(const kythira::segment_store& s, const std::string& stream)
    -> std::vector<kythira::segment_record> {
    std::vector<kythira::segment_record> out;
    std::uint64_t next = 0;
    for (;;) {
        auto r = s.read(stream, next, {._max_records = 50, ._max_bytes = 8192});
        if (r._records.empty()) {
            return out;
        }
        out.insert(out.end(), r._records.begin(), r._records.end());
        next = r._next_seq;
    }
}

/// Every file under `root/streams`, by relative path, with its bytes.
auto files_under(const fs::path& root) -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    if (!fs::exists(root / "streams")) {
        return out;
    }
    for (const auto& e : fs::recursive_directory_iterator(root / "streams")) {
        if (e.is_regular_file()) {
            std::ifstream in(e.path(), std::ios::binary);
            out[fs::relative(e.path(), root).string()] =
                std::string(std::istreambuf_iterator<char>(in), {});
        }
    }
    return out;
}

/// A segment node in-process.
struct segment_node {
    std::unique_ptr<kythira::segment_volume_service> service;

    explicit segment_node(const fs::path& dir)
        : service(std::make_unique<kythira::segment_volume_service>(
              kythira::segment_volume_service_options{.data_dir = dir,
                                                      .store = small_segments()})) {}

    auto open(const std::string& volume, std::uint64_t epoch)
        -> std::unique_ptr<kythira::remote_segment_store> {
        service->assign(volume, epoch);
        return std::make_unique<kythira::remote_segment_store>(
            [this](std::vector<std::byte> req) -> std::optional<std::vector<std::byte>> {
                return service->handle(req);
            },
            volume, epoch);
    }
};

/// Forwards to a store and lets a test act inside chosen calls.
class hooked_store final : public kythira::segment_store {
public:
    explicit hooked_store(std::unique_ptr<kythira::segment_store> inner)
        : _inner(std::move(inner)) {}

    /// Runs once, after the first read of an active segment's bytes.
    mutable std::function<void()> after_active_read;
    /// Throws from installs of active segments while set.
    std::atomic<bool> refuse_active_installs{false};

    [[nodiscard]] auto max_record_bytes() const noexcept -> std::uint32_t override {
        return _inner->max_record_bytes();
    }
    auto append(const std::string& s, std::span<const kythira::segment_record_view> r)
        -> kythira::record_segment_append_result override {
        return _inner->append(s, r);
    }
    using kythira::segment_store::append;
    void barrier() override { _inner->barrier(); }
    auto seal(const std::string& s) -> std::optional<kythira::record_segment_descriptor> override {
        return _inner->seal(s);
    }
    void truncate_after(const std::string& s, std::optional<std::uint64_t> q) override {
        _inner->truncate_after(s, q);
    }
    auto trim_before(const std::string& s, std::uint64_t q) -> std::vector<std::uint64_t> override {
        return _inner->trim_before(s, q);
    }
    auto remove_segment(const std::string& s, std::uint64_t f) -> bool override {
        return _inner->remove_segment(s, f);
    }
    void drop_stream(const std::string& s) override { _inner->drop_stream(s); }
    auto install_segment(const kythira::record_segment_descriptor& d, std::span<const std::byte> b)
        -> bool override {
        if (!d._sealed && refuse_active_installs.load()) {
            throw std::invalid_argument("test: active installs refused");
        }
        return _inner->install_segment(d, b);
    }
    auto fetch_segment(const kythira::record_segment_descriptor& d, std::span<const std::string> p,
                       const fetch_transport& t) -> bool override {
        return _inner->fetch_segment(d, p, t);
    }
    [[nodiscard]] auto read_segment_bytes(const std::string& s, std::uint64_t f,
                                          std::uint64_t n) const
        -> std::optional<std::vector<std::byte>> override {
        auto out = _inner->read_segment_bytes(s, f, n);
        const auto d = _inner->describe(s, f);
        if (d && !d->_sealed) {
            std::function<void()> hook;
            {
                const std::scoped_lock lock(_hook_mu);
                hook = std::exchange(after_active_read, {});
            }
            if (hook) {
                hook();
            }
        }
        return out;
    }
    [[nodiscard]] auto read_segment(const std::string& s, std::uint64_t f, std::uint64_t from,
                                    const kythira::segment_read_limits& l) const
        -> std::optional<kythira::segment_read_result> override {
        return _inner->read_segment(s, f, from, l);
    }
    using kythira::segment_store::read_segment;
    [[nodiscard]] auto read(const std::string& s, std::uint64_t from,
                            const kythira::segment_read_limits& l) const
        -> kythira::segment_read_result override {
        return _inner->read(s, from, l);
    }
    using kythira::segment_store::read;
    [[nodiscard]] auto describe(const std::string& s, std::uint64_t f) const
        -> std::optional<kythira::record_segment_descriptor> override {
        return _inner->describe(s, f);
    }
    [[nodiscard]] auto local_segments(const std::string& s) const
        -> std::vector<kythira::record_segment_descriptor> override {
        return _inner->local_segments(s);
    }
    [[nodiscard]] auto has_segment(const kythira::record_segment_descriptor& d) const
        -> bool override {
        return _inner->has_segment(d);
    }
    [[nodiscard]] auto last_seq(const std::string& s) const
        -> std::optional<std::uint64_t> override {
        return _inner->last_seq(s);
    }
    [[nodiscard]] auto streams() const -> std::vector<std::string> override {
        return _inner->streams();
    }
    [[nodiscard]] auto stats() const -> kythira::record_segment_store_stats override {
        return _inner->stats();
    }

    [[nodiscard]] auto inner() -> kythira::segment_store& { return *_inner; }

private:
    std::unique_ptr<kythira::segment_store> _inner;
    mutable std::mutex _hook_mu;
};

/// A writer appending to `shard-a` through the movable store until told to
/// stop, the way a replica's apply loop does: append then barrier.
class writer {
public:
    writer(kythira::segment_store& s, std::uint64_t first) : _next(first) {
        _thread = std::thread([this, &s] {
            while (!_stop.load()) {
                put(s, "shard-a", _next);
                s.barrier();
                _written.store(_next);
                ++_next;
                std::this_thread::sleep_for(200us);
            }
        });
    }
    writer(const writer&) = delete;
    auto operator=(const writer&) -> writer& = delete;
    writer(writer&&) = delete;
    auto operator=(writer&&) -> writer& = delete;
    ~writer() { stop(); }

    void stop() {
        _stop.store(true);
        if (_thread.joinable()) {
            _thread.join();
        }
    }
    [[nodiscard]] auto written() const -> std::uint64_t { return _written.load(); }

private:
    std::uint64_t _next;
    std::atomic<std::uint64_t> _written{0};
    std::atomic<bool> _stop{false};
    std::thread _thread;
};

/// shard-a holds every sequence from its first kept one to `last`, in
/// order, with the payload written for each.
void check_contiguous(const kythira::segment_store& s, std::uint64_t last) {
    const auto all = read_all(s, "shard-a");
    BOOST_REQUIRE(!all.empty());
    BOOST_TEST(all.back()._seq == last);
    for (std::size_t i = 0; i < all.size(); ++i) {
        BOOST_TEST_INFO(all[i]._seq);
        BOOST_TEST((all[i]._data == payload(all[i]._seq)));
        if (i > 0) {
            BOOST_TEST(all[i]._seq == all[i - 1]._seq + 1);
        }
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(store_move)

BOOST_AUTO_TEST_CASE(a_local_store_moves_to_a_volume_under_writes_and_back) {
    scratch_dir d;
    segment_node node(d.sub("segment-node"));
    kythira::movable_segment_store store(local_store(d.sub("local")));
    fill(store, 300);
    const auto shard_b = read_all(store, "shard-b");

    kythira::segment_store_move_report there;
    {
        writer w(store, 301);
        std::this_thread::sleep_for(20ms);
        auto [report, old] = store.move_to(node.open("replica-1", 1), {});
        there = report;
        std::this_thread::sleep_for(20ms);
        w.stop();
        // The writer kept going across the switch, into the volume.
        BOOST_TEST(w.written() > 301U);
        check_contiguous(store, w.written());
        // The old local copy stopped at the switch and is behind.
        BOOST_TEST(old->last_seq("shard-a").value() < w.written());
    }
    BOOST_TEST(there._rounds >= 1U);
    BOOST_TEST(there._sealed_segments > 0U);
    BOOST_TEST(there._streams == 2U);
    BOOST_TEST(there._fence_bytes <= kythira::segment_store_move_options{}._max_fence_bytes);
    BOOST_TEST_MESSAGE("local -> volume: rounds=" << there._rounds
                                                  << " sealed=" << there._sealed_segments
                                                  << " fence_records=" << there._fence_records
                                                  << " fence_bytes=" << there._fence_bytes
                                                  << " pause_us=" << there._pause.count());
    BOOST_TEST(read_all(store, "shard-b") == shard_b);

    // And back into the directory it left: an older copy is reconciled.
    const auto at_volume = store.with_inner([](auto& s) { return s.last_seq("shard-a"); });
    {
        writer w(store, *at_volume + 1);
        std::this_thread::sleep_for(20ms);
        auto [report, old] = store.move_to(local_store(d.sub("local")), {});
        BOOST_TEST_MESSAGE("volume -> local: rounds=" << report._rounds
                                                      << " fence_records=" << report._fence_records
                                                      << " pause_us=" << report._pause.count());
        std::this_thread::sleep_for(20ms);
        w.stop();
        check_contiguous(store, w.written());
        // The volume's copy is what the caller drops.
        for (const auto& s : old->streams()) {
            old->drop_stream(s);
        }
        BOOST_TEST(old->streams().empty());
    }
    BOOST_TEST(read_all(store, "shard-b") == shard_b);
}

BOOST_AUTO_TEST_CASE(the_moved_files_are_byte_identical_to_the_source) {
    scratch_dir d;
    segment_node node(d.sub("segment-node"));
    kythira::movable_segment_store store(local_store(d.sub("local")));
    fill(store, 400);
    const auto before = files_under(d.sub("local"));
    BOOST_TEST(before.size() > 3U);

    auto [report, old] = store.move_to(node.open("replica-1", 4), {});
    // Nothing wrote, so one round copied everything and the fence nothing.
    BOOST_TEST(report._rounds == 1U);
    BOOST_TEST(report._fence_bytes == 0U);
    BOOST_TEST(report._fence_installs == 0U);
    const auto after = files_under(node.service->volume_dir("replica-1"));
    BOOST_TEST(after.size() == before.size());
    for (const auto& [path, bytes] : before) {
        BOOST_TEST_INFO(path);
        BOOST_REQUIRE(after.contains(path));
        BOOST_TEST((after.at(path) == bytes));
    }
}

BOOST_AUTO_TEST_CASE(segments_larger_than_one_call_are_appended_in_batches) {
    // A segment node's gateway caps request bodies: a volume whose
    // transport drops any request over 1.5 KiB never takes a 4 KiB segment
    // whole. Segments over `_max_call_bytes` go as batched appends (and a
    // seal where the source sealed), and the files still match byte for
    // byte, on the way there and back.
    scratch_dir d;
    segment_node node(d.sub("segment-node"));
    node.service->assign("replica-1", 2);
    std::size_t refused_calls = 0;
    auto capped = std::make_unique<kythira::remote_segment_store>(
        [&](std::vector<std::byte> req) -> std::optional<std::vector<std::byte>> {
            if (req.size() > 1536) {
                ++refused_calls;
                return std::nullopt;
            }
            return node.service->handle(req);
        },
        "replica-1", 2);
    kythira::movable_segment_store store(local_store(d.sub("local")));
    fill(store, 400);
    const auto before = files_under(d.sub("local"));
    const auto shard_a = read_all(store, "shard-a");

    kythira::segment_store_move_options options;
    options._max_call_bytes = 1024;
    auto [report, old] = store.move_to(std::move(capped), options);
    BOOST_TEST(refused_calls == 0U);
    BOOST_TEST(report._sealed_segments > 0U);
    const auto after = files_under(node.service->volume_dir("replica-1"));
    BOOST_TEST(after.size() == before.size());
    for (const auto& [path, bytes] : before) {
        BOOST_TEST_INFO(path);
        BOOST_REQUIRE(after.contains(path));
        BOOST_TEST((after.at(path) == bytes));
    }
    BOOST_TEST(read_all(store, "shard-a") == shard_a);

    // And back to a fresh local directory, the same way.
    auto [back, volume] = store.move_to(local_store(d.sub("local-again")), options);
    BOOST_TEST(files_under(d.sub("local-again")) == before);
    BOOST_TEST(read_all(store, "shard-a") == shard_a);
}

BOOST_AUTO_TEST_CASE(the_tail_written_after_the_copy_is_appended_under_the_fence) {
    // Deterministic: the first read of an active segment's bytes (the
    // prefix copy) is followed by more writes, so the fence finds a short
    // copy and must append the tail, across a roll into a new segment,
    // rather than recopy the segment.
    scratch_dir d;
    auto src = std::make_unique<hooked_store>(local_store(d.sub("local")));
    auto* hooks = src.get();
    kythira::movable_segment_store store(std::move(src));
    fill(store, 100);
    hooks->after_active_read = [hooks] {
        for (std::uint64_t seq = 101; seq <= 140; ++seq) {
            put(hooks->inner(), "shard-a", seq);
        }
        hooks->inner().barrier();
    };

    auto [report, old] = store.move_to(local_store(d.sub("moved")), {});
    BOOST_TEST(report._fence_records >= 40U);
    BOOST_TEST(report._fence_installs == 0U);
    BOOST_TEST(report._fence_bytes > 0U);
    BOOST_TEST(report._fence_bytes < 40U * 400U);
    check_contiguous(store, 140);
    // The appended copy is the same as the source, file for file.
    const auto a = files_under(d.sub("local"));
    const auto b = files_under(d.sub("moved"));
    BOOST_TEST(a.size() == b.size());
    for (const auto& [path, bytes] : a) {
        BOOST_TEST_INFO(path);
        BOOST_REQUIRE(b.contains(path));
        BOOST_TEST((b.at(path) == bytes));
    }
}

BOOST_AUTO_TEST_CASE(a_tail_that_never_comes_under_the_bound_is_refused) {
    scratch_dir d;
    kythira::movable_segment_store store(local_store(d.sub("local")));
    fill(store, 200);
    auto target = std::make_unique<hooked_store>(local_store(d.sub("moved")));
    target->refuse_active_installs = true;

    BOOST_CHECK_THROW(
        (void)store.move_to(std::move(target), {._max_rounds = 3, ._max_fence_bytes = 16}),
        kythira::segment_store_move_refused);
    // Not switched: writes and reads still go to the local store.
    put(store, "shard-a", 201);
    store.barrier();
    check_contiguous(store, 201);
    BOOST_TEST(!store.moving());
    BOOST_TEST(store.with_inner([](auto& s) { return s.last_seq("shard-a"); }).value() == 201U);
}

BOOST_AUTO_TEST_CASE(a_failure_at_the_switch_keeps_the_old_store) {
    scratch_dir d;
    kythira::movable_segment_store store(local_store(d.sub("local")));
    fill(store, 120);
    BOOST_CHECK_THROW(
        (void)store.move_to(
            local_store(d.sub("moved")), {},
            [](auto&, auto&) { throw std::runtime_error("the assignment did not commit"); }),
        kythira::segment_store_move_refused);
    put(store, "shard-a", 121);
    check_contiguous(store, 121);

    // A move that does commit runs on_switch once, with both stores.
    int calls = 0;
    auto [report, old] =
        store.move_to(local_store(d.sub("moved")), {},
                      [&](kythira::segment_store& from, kythira::segment_store& to) {
                          ++calls;
                          BOOST_TEST(from.last_seq("shard-a") == to.last_seq("shard-a"));
                      });
    BOOST_TEST(calls == 1);
    BOOST_TEST(report._pause.count() >= 0);
    check_contiguous(store, 121);
}

BOOST_AUTO_TEST_CASE(stale_segments_in_the_target_are_removed) {
    // A target left with segments the source has since trimmed, a stream
    // the source has since dropped, and an active segment past the
    // source's end ends up holding exactly the source's segments.
    scratch_dir d;
    kythira::movable_segment_store store(local_store(d.sub("local")));
    auto target = local_store(d.sub("moved"));
    fill(*target, 300);
    put(*target, "gone", 1);
    target->barrier();
    fill(store, 200);
    (void)store.trim_before("shard-a", 120);

    auto [report, old] = store.move_to(std::move(target), {});
    BOOST_TEST(store.streams() == old->streams());
    for (const auto& s : old->streams()) {
        BOOST_TEST(store.local_segments(s) == old->local_segments(s));
    }
    check_contiguous(store, 200);
}

BOOST_AUTO_TEST_CASE(a_second_move_while_one_runs_is_refused) {
    scratch_dir d;
    auto src = std::make_unique<hooked_store>(local_store(d.sub("local")));
    auto* hooks = src.get();
    kythira::movable_segment_store store(std::move(src));
    fill(store, 100);
    bool refused = false;
    hooks->after_active_read = [&] {
        try {
            (void)store.move_to(local_store(d.sub("other")), {});
        } catch (const kythira::segment_store_move_refused&) {
            refused = true;
        }
    };
    auto [report, old] = store.move_to(local_store(d.sub("moved")), {});
    BOOST_TEST(refused);
    check_contiguous(store, 100);
}

BOOST_AUTO_TEST_SUITE_END()
