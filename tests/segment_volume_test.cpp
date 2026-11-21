// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// A segment node's volumes and the remote segment store a data replica
// writes through (include/raft/segment_volume_service.hpp,
// include/raft/remote_segment_store.hpp,
// .kiro/specs/kinesis-independent-layers/ task 9, Requirements 9.1-9.3, 9.6
// and 9.7): byte-identical files against a local store fed the same
// operations, writer fencing by epoch, restart and torn-tail truncation,
// truncate_after and drop_stream remotely, barrier coalescing, peer fetch,
// and a service that never throws on a bad request.

#define BOOST_TEST_MODULE segment_volume_test

#include <boost/test/unit_test.hpp>

#include "record_segment_store_conformance.hpp"

#include <raft/record_segment_store.hpp>
#include <raft/remote_segment_store.hpp>
#include <raft/segment_volume_service.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
using kythira::segment_conformance::scratch_dir;

auto payload(std::uint64_t seq) -> std::vector<std::byte> {
    std::vector<std::byte> out(64 + (seq * 37) % 300);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>((seq * 31 + i) & 0xFFU);
    }
    return out;
}

auto small_segments() -> kythira::record_segment_store_options {
    kythira::record_segment_store_options o;
    o._max_segment_bytes = 4096;
    o._index_interval_bytes = 256;
    return o;
}

/// A segment node in-process: the service and a transport to it that a
/// test can cut.
struct segment_node {
    fs::path dir;
    std::unique_ptr<kythira::segment_volume_service> service;
    std::shared_ptr<std::atomic<bool>> reachable = std::make_shared<std::atomic<bool>>(true);

    explicit segment_node(fs::path d) : dir(std::move(d)) { start(); }

    void start() {
        service = std::make_unique<kythira::segment_volume_service>(
            kythira::segment_volume_service_options{.data_dir = dir, .store = small_segments()});
    }
    void restart() {
        service.reset();
        start();
    }

    auto transport() -> kythira::segment_volume_transport {
        return [this, up = reachable](
                   std::vector<std::byte> req) -> std::optional<std::vector<std::byte>> {
            if (!up->load()) {
                return std::nullopt;
            }
            return service->handle(req);
        };
    }

    auto open(const std::string& volume, std::uint64_t epoch)
        -> std::unique_ptr<kythira::remote_segment_store> {
        return std::make_unique<kythira::remote_segment_store>(transport(), volume, epoch);
    }
};

/// Every file under `root/streams`, by relative path, with its bytes.
auto files_under(const fs::path& root) -> std::map<std::string, std::string> {
    std::map<std::string, std::string> out;
    for (const auto& e : fs::recursive_directory_iterator(root / "streams")) {
        if (e.is_regular_file()) {
            std::ifstream in(e.path(), std::ios::binary);
            out[fs::relative(e.path(), root).string()] =
                std::string(std::istreambuf_iterator<char>(in), {});
        }
    }
    return out;
}

/// The same operations against any store: appends that roll, a seal, a
/// trim, a truncation and a dropped stream.
void drive(kythira::segment_store& s) {
    for (std::uint64_t seq = 1; seq <= 120; ++seq) {
        const auto p = payload(seq);
        (void)s.append("shard-a", kythira::segment_record_view{
                                      seq, 1'700'000'000'000 + static_cast<std::int64_t>(seq), p});
        if (seq % 3 == 0) {
            const auto q = payload(seq + 1000);
            (void)s.append("shard-b",
                           kythira::segment_record_view{
                               seq, 1'700'000'000'000 + static_cast<std::int64_t>(seq), q});
        }
        if (seq % 25 == 0) {
            s.barrier();
        }
    }
    (void)s.seal("shard-b");
    (void)s.trim_before("shard-a", 40);
    s.truncate_after("shard-a", 110);
    const auto p = payload(999);
    (void)s.append("doomed", kythira::segment_record_view{1, 0, p});
    s.drop_stream("doomed");
    s.barrier();
}

auto read_all(const kythira::segment_store& s, const std::string& stream)
    -> std::vector<kythira::segment_record> {
    std::vector<kythira::segment_record> out;
    std::uint64_t next = 0;
    for (;;) {
        auto r = s.read(stream, next, {._max_records = 17, ._max_bytes = 4096});
        if (r._records.empty()) {
            return out;
        }
        out.insert(out.end(), r._records.begin(), r._records.end());
        next = r._next_seq;
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(remote_store)

BOOST_AUTO_TEST_CASE(a_volume_holds_byte_identical_files_to_a_local_store) {
    scratch_dir d;
    auto local_opts = small_segments();
    local_opts._data_dir = d.path() / "local";
    kythira::record_segment_store local(local_opts);
    segment_node node(d.path() / "segment-node");
    node.service->assign("replica-1", 1);
    auto remote = node.open("replica-1", 1);

    drive(local);
    drive(*remote);

    const auto mine = files_under(local_opts._data_dir);
    const auto theirs = files_under(node.service->volume_dir("replica-1"));
    BOOST_TEST(mine.size() > 3U);  // rolled, so several files
    BOOST_TEST(mine.size() == theirs.size());
    for (const auto& [path, bytes] : mine) {
        BOOST_TEST_INFO(path);
        BOOST_REQUIRE(theirs.contains(path));
        BOOST_TEST((theirs.at(path) == bytes));
    }
    // And the interface answers the same.
    BOOST_TEST(read_all(local, "shard-a") == read_all(*remote, "shard-a"));
    BOOST_TEST(local.local_segments("shard-b") == remote->local_segments("shard-b"));
    BOOST_TEST(local.streams() == remote->streams());
    BOOST_TEST(local.last_seq("shard-a") == remote->last_seq("shard-a"));
    BOOST_TEST(!remote->last_seq("doomed").has_value());
    BOOST_TEST(remote->max_record_bytes() == local.max_record_bytes());
}

BOOST_AUTO_TEST_CASE(reads_of_one_segment_and_its_bytes_match_the_local_store) {
    scratch_dir d;
    auto local_opts = small_segments();
    local_opts._data_dir = d.path() / "local";
    kythira::record_segment_store local(local_opts);
    segment_node node(d.path() / "seg");
    node.service->assign("v", 3);
    auto remote = node.open("v", 3);
    drive(local);
    drive(*remote);
    for (const auto& seg : local.local_segments("shard-a")) {
        BOOST_TEST((remote->describe("shard-a", seg._first_seq) ==
                    local.describe("shard-a", seg._first_seq)));
        BOOST_TEST(remote->has_segment(seg));
        BOOST_TEST((remote->read_segment_bytes("shard-a", seg._first_seq, seg._bytes) ==
                    local.read_segment_bytes("shard-a", seg._first_seq, seg._bytes)));
        const auto a = local.read_segment("shard-a", seg._first_seq, seg._first_seq);
        const auto b = remote->read_segment("shard-a", seg._first_seq, seg._first_seq);
        BOOST_REQUIRE(a.has_value());
        BOOST_REQUIRE(b.has_value());
        BOOST_TEST(a->_records == b->_records);
        BOOST_TEST(a->_next_seq == b->_next_seq);
        BOOST_TEST(a->_segment_exhausted == b->_segment_exhausted);
    }
    BOOST_TEST(!remote->read_segment("shard-a", 999'999, 0).has_value());
    BOOST_TEST(!remote->describe("shard-a", 999'999).has_value());
    BOOST_TEST(remote->stats()._streams == local.stats()._streams);
}

BOOST_AUTO_TEST_CASE(a_replaced_writer_is_fenced_but_may_still_read) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    auto old_writer = node.open("v", 1);
    const auto p = payload(1);
    (void)old_writer->append("s", kythira::segment_record_view{1, 0, p});
    old_writer->barrier();

    // The replica is replaced: the assignment moves to epoch 2.
    node.service->assign("v", 2);
    BOOST_CHECK_THROW((void)old_writer->append("s", kythira::segment_record_view{2, 0, p}),
                      kythira::segment_volume_fenced);
    BOOST_CHECK_THROW(old_writer->truncate_after("s", std::nullopt),
                      kythira::segment_volume_fenced);
    BOOST_CHECK_THROW(old_writer->drop_stream("s"), kythira::segment_volume_fenced);
    BOOST_TEST(old_writer->last_seq("s") == std::optional<std::uint64_t>(1));

    auto new_writer = node.open("v", 2);
    (void)new_writer->append("s", kythira::segment_record_view{2, 0, p});
    new_writer->barrier();
    BOOST_TEST(new_writer->last_seq("s") == std::optional<std::uint64_t>(2));

    // A fenced writer's barrier must fail too: it may not acknowledge.
    auto fenced = std::make_unique<kythira::remote_segment_store>(node.transport(), "v", 1);
    BOOST_CHECK_THROW((void)fenced->append("s", kythira::segment_record_view{3, 0, p}),
                      kythira::segment_volume_fenced);
    BOOST_CHECK_THROW(node.service->assign("v", 1), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(a_barrier_after_fencing_fails) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    auto w = node.open("v", 1);
    const auto p = payload(1);
    (void)w->append("s", kythira::segment_record_view{1, 0, p});
    node.service->assign("v", 2);
    BOOST_CHECK_THROW(w->barrier(), kythira::segment_volume_fenced);
}

BOOST_AUTO_TEST_CASE(a_volume_survives_a_segment_node_restart_with_its_epoch) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 7);
    {
        auto w = node.open("v", 7);
        for (std::uint64_t seq = 1; seq <= 40; ++seq) {
            const auto p = payload(seq);
            (void)w->append("s", kythira::segment_record_view{seq, 0, p});
        }
        w->barrier();
    }
    node.restart();
    const auto vols = node.service->volumes();
    BOOST_REQUIRE(vols.size() == 1U);
    BOOST_TEST(vols[0].first == "v");
    BOOST_TEST(vols[0].second == 7U);
    auto w = node.open("v", 7);
    BOOST_TEST(read_all(*w, "s").size() == 40U);
}

BOOST_AUTO_TEST_CASE(a_torn_tail_is_truncated_when_the_segment_node_restarts) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    {
        auto w = node.open("v", 1);
        for (std::uint64_t seq = 1; seq <= 5; ++seq) {
            const auto p = payload(seq);
            (void)w->append("s", kythira::segment_record_view{seq, 0, p});
        }
        w->barrier();
    }
    node.service.reset();
    // A crash mid-append: half a record after the barriered ones.
    fs::path open_file;
    for (const auto& e : fs::recursive_directory_iterator(d.path() / "volumes" / "v" / "streams")) {
        if (e.path().extension() == ".open") {
            open_file = e.path();
        }
    }
    BOOST_REQUIRE(!open_file.empty());
    {
        std::ofstream out(open_file, std::ios::binary | std::ios::app);
        out << std::string("\x00\x00\x01\x00garbage", 11);
    }
    node.start();
    auto w = node.open("v", 1);
    BOOST_TEST(read_all(*w, "s").size() == 5U);
    BOOST_TEST(w->stats()._torn_tails_truncated == 1U);
    // Appends continue where the barrier left off.
    const auto p = payload(6);
    (void)w->append("s", kythira::segment_record_view{6, 0, p});
    w->barrier();
    BOOST_TEST(w->last_seq("s") == std::optional<std::uint64_t>(6));
}

BOOST_AUTO_TEST_CASE(truncate_after_and_drop_stream_work_remotely) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    auto w = node.open("v", 1);
    for (std::uint64_t seq = 1; seq <= 60; ++seq) {
        const auto p = payload(seq);
        (void)w->append("s", kythira::segment_record_view{seq, 0, p});
    }
    w->truncate_after("s", 33);
    BOOST_TEST(w->last_seq("s") == std::optional<std::uint64_t>(33));
    BOOST_TEST(read_all(*w, "s").back()._seq == 33U);
    w->truncate_after("s", std::nullopt);
    BOOST_TEST(!w->last_seq("s").has_value());
    const auto p = payload(1);
    (void)w->append("t", kythira::segment_record_view{1, 0, p});
    w->drop_stream("t");
    BOOST_TEST(w->streams().empty());
}

BOOST_AUTO_TEST_CASE(concurrent_barriers_share_requests) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    auto w = node.open("v", 1);
    constexpr int threads = 8;
    constexpr int rounds = 50;
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&, t] {
            const auto stream = "s" + std::to_string(t);
            for (std::uint64_t seq = 1; seq <= rounds; ++seq) {
                const auto p = payload(seq);
                (void)w->append(stream, kythira::segment_record_view{seq, 0, p});
                w->barrier();
            }
        });
    }
    for (auto& t : pool) {
        t.join();
    }
    BOOST_TEST(w->barrier_requests() <= static_cast<std::uint64_t>(threads * rounds));
    BOOST_TEST(w->barrier_requests() >= 1U);
    for (int t = 0; t < threads; ++t) {
        BOOST_TEST(w->last_seq("s" + std::to_string(t)) == std::optional<std::uint64_t>(rounds));
    }
    // A barrier with nothing new to cover sends nothing.
    const auto before = w->barrier_requests();
    w->barrier();
    BOOST_TEST(w->barrier_requests() == before);
}

BOOST_AUTO_TEST_CASE(an_unreachable_volume_throws_like_a_failed_disk) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 1);
    auto w = node.open("v", 1);
    const auto p = payload(1);
    (void)w->append("s", kythira::segment_record_view{1, 0, p});
    node.reachable->store(false);
    BOOST_CHECK_THROW(w->barrier(), kythira::record_segment_error);
    BOOST_CHECK_THROW((void)w->append("s", kythira::segment_record_view{2, 0, p}),
                      kythira::record_segment_error);
    node.reachable->store(true);
    BOOST_CHECK_NO_THROW(w->barrier());
    BOOST_CHECK_THROW((void)node.open("missing", 1), kythira::record_segment_error);
}

// Task 10 (Requirement 10.6): the segment node's storage, for the data
// node's capacity probe and disk guard. Not fenced: any epoch may ask.
BOOST_AUTO_TEST_CASE(the_segment_node_reports_its_space_to_any_writer) {
    scratch_dir d;
    segment_node node(d.path());
    node.service->assign("v", 2);
    auto w = node.open("v", 2);
    const auto [capacity, available] = w->space();
    const auto fs_space = fs::space(d.path());
    BOOST_TEST(capacity == static_cast<std::uint64_t>(fs_space.capacity));
    BOOST_TEST(available > 0U);
    BOOST_TEST(available <= capacity);
    node.service->assign("v", 3);
    BOOST_CHECK_NO_THROW((void)w->space());
    node.reachable->store(false);
    BOOST_CHECK_THROW((void)w->space(), kythira::record_segment_error);
}

// Task 10: a writer moved to a segment node that never heard of its
// volume assigns it there at the catalog's epoch, then opens it. A newer
// epoch fences the old writer; an older one is refused.
BOOST_AUTO_TEST_CASE(a_writer_assigns_its_volume_at_the_catalog_epoch) {
    scratch_dir d;
    segment_node node(d.path());
    BOOST_CHECK_THROW((void)node.open("moved", 2), kythira::record_segment_error);
    kythira::remote_segment_store::assign(node.transport(), "moved", 2);
    auto w = node.open("moved", 2);
    const auto p = payload(1);
    (void)w->append("s", kythira::segment_record_view{1, 0, p});
    w->barrier();
    // Again at the same epoch: nothing changes, the files stay.
    kythira::remote_segment_store::assign(node.transport(), "moved", 2);
    BOOST_TEST(w->last_seq("s") == std::optional<std::uint64_t>(1));
    BOOST_CHECK_THROW(kythira::remote_segment_store::assign(node.transport(), "moved", 1),
                      std::invalid_argument);
    BOOST_CHECK_THROW(kythira::remote_segment_store::assign(node.transport(), "moved", 0),
                      std::invalid_argument);
    kythira::remote_segment_store::assign(node.transport(), "moved", 3);
    BOOST_CHECK_THROW((void)w->append("s", kythira::segment_record_view{2, 0, p}),
                      kythira::segment_volume_fenced);
    BOOST_CHECK_THROW(kythira::remote_segment_store::assign(node.transport(), "a/b", 1),
                      std::invalid_argument);
    node.reachable->store(false);
    BOOST_CHECK_THROW(kythira::remote_segment_store::assign(node.transport(), "moved", 4),
                      kythira::record_segment_error);
}

// Task 10: placement probes a segment node's room without a volume.
BOOST_AUTO_TEST_CASE(a_probe_reads_space_without_a_volume) {
    scratch_dir d;
    segment_node node(d.path());
    const auto space = kythira::remote_segment_store::probe_space(node.transport());
    BOOST_REQUIRE(space.has_value());
    BOOST_TEST(space->second <= space->first);
    node.reachable->store(false);
    BOOST_TEST(!kythira::remote_segment_store::probe_space(node.transport()).has_value());
}

BOOST_AUTO_TEST_CASE(a_segment_is_fetched_from_a_peer_into_the_volume) {
    scratch_dir d;
    auto peer_opts = small_segments();
    peer_opts._data_dir = d.path() / "peer";
    kythira::record_segment_store peer(peer_opts);
    for (std::uint64_t seq = 1; seq <= 80; ++seq) {
        const auto p = payload(seq);
        (void)peer.append("s", kythira::segment_record_view{seq, 0, p});
    }
    const auto sealed = peer.local_segments("s").front();
    BOOST_REQUIRE(sealed._sealed);

    segment_node node(d.path() / "seg");
    node.service->assign("v", 1);
    auto w = node.open("v", 1);
    const std::vector<std::string> peers = {"liar", "peer"};
    auto transport = [&](const std::string& who, const std::string& stream, std::uint64_t first,
                         std::uint64_t length) -> std::optional<std::vector<std::byte>> {
        if (who == "liar") {
            return std::vector<std::byte>(length, std::byte{0});
        }
        return peer.read_segment_bytes(stream, first, length);
    };
    BOOST_TEST(w->fetch_segment(sealed, peers, transport));
    BOOST_TEST(w->has_segment(sealed));
    BOOST_TEST(w->stats()._fetch_misses == 1U);
    // Bytes that do not match the descriptor are refused as the local store
    // refuses them.
    auto wrong = sealed;
    wrong._first_seq += 1000;
    const auto bytes = peer.read_segment_bytes("s", sealed._first_seq, sealed._bytes);
    BOOST_CHECK_THROW((void)w->install_segment(wrong, *bytes), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(service)

BOOST_AUTO_TEST_CASE(bad_requests_get_a_status_never_an_exception) {
    scratch_dir d;
    kythira::segment_volume_service svc({.data_dir = d.path(), .store = small_segments()});
    svc.assign("v", 1);
    auto status_of = [&](const std::vector<std::byte>& req) {
        const auto resp = svc.handle(req);
        kythira::volume_wire::reader r(resp);
        (void)r.array();
        return static_cast<kythira::volume_wire::status>(r.uint());
    };
    using kythira::volume_wire::status;
    BOOST_TEST((status_of({}) == status::invalid_argument));
    BOOST_TEST((status_of({std::byte{0xFF}, std::byte{0x00}}) == status::invalid_argument));
    kythira::volume_wire::writer w;
    w.array(3);
    w.uint(200);  // no such op
    w.text("v");
    w.uint(1);
    BOOST_TEST((status_of(w.take()) == status::invalid_argument));
    kythira::volume_wire::writer u;
    u.array(3);
    u.uint(static_cast<std::uint64_t>(kythira::volume_wire::op::streams));
    u.text("nope");
    u.uint(1);
    BOOST_TEST((status_of(u.take()) == status::unknown_volume));
    // An array claiming more elements than bytes left.
    kythira::volume_wire::writer big;
    big.array(1'000'000);
    BOOST_TEST((status_of(big.take()) == status::invalid_argument));
    // Trailing bytes after a complete request.
    kythira::volume_wire::writer t;
    t.array(3);
    t.uint(static_cast<std::uint64_t>(kythira::volume_wire::op::streams));
    t.text("v");
    t.uint(1);
    auto trailing = t.take();
    trailing.push_back(std::byte{0});
    BOOST_TEST((status_of(trailing) == status::invalid_argument));
}

BOOST_AUTO_TEST_CASE(volume_ids_are_checked_and_volumes_can_be_dropped) {
    scratch_dir d;
    kythira::segment_volume_service svc({.data_dir = d.path(), .store = small_segments()});
    BOOST_CHECK_THROW(svc.assign("../escape", 1), std::invalid_argument);
    BOOST_CHECK_THROW(svc.assign(".hidden", 1), std::invalid_argument);
    BOOST_CHECK_THROW(svc.assign("", 1), std::invalid_argument);
    svc.assign("a", 1);
    svc.assign("b", 4);
    svc.assign("b", 5);
    BOOST_TEST(svc.volumes().size() == 2U);
    svc.drop("a");
    BOOST_TEST(svc.volumes().size() == 1U);
    BOOST_TEST(!fs::exists(d.path() / "volumes" / "a"));
}

BOOST_AUTO_TEST_CASE(the_wire_codec_round_trips_every_length_encoding) {
    kythira::volume_wire::writer w;
    const std::vector<std::uint64_t> values = {
        0, 23, 24, 255, 256, 65535, 65536, 0xFFFFFFFFULL, 0x100000000ULL, ~0ULL};
    w.array(values.size());
    for (const auto v : values) {
        w.uint(v);
    }
    w.text("héllo");
    w.boolean(true);
    w.null();
    const auto bytes = w.take();
    kythira::volume_wire::reader r(bytes);
    BOOST_TEST(r.array() == values.size());
    for (const auto v : values) {
        BOOST_TEST(r.uint() == v);
    }
    BOOST_TEST(r.text() == "héllo");
    BOOST_TEST(r.boolean());
    BOOST_TEST(r.null());
    BOOST_TEST(r.at_end());
}

BOOST_AUTO_TEST_SUITE_END()
