// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file raft_log_encryption_unit_test.cpp
/// @brief Raft log records and snapshots sealed at rest
///        (.kiro/specs/raft-log-encryption/ tasks 1-3).
///
/// The key ring and per-log cipher on their own first, then
/// `binary_file_persistence_engine` with a key ring: no command bytes in any
/// file, every bound field tampered, the torn-tail rule still cutting sealed
/// records, migration from plaintext to sealed and back, rotation and
/// pruning, and `rewrite_records()` interrupted at each step.

#define BOOST_TEST_MODULE raft_log_encryption_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/binary_file_persistence.hpp>
#include <raft/crc32.hpp>
#include <raft/raft_log_encryption.hpp>

#ifdef FIU_ENABLE
#include <fiu-control.h>
#include <fiu.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;
using engine_t = kythira::binary_file_persistence_engine<>;
using log_entry_t = kythira::log_entry<>;
using snapshot_t = kythira::snapshot<>;
using kythira::log_encryption_mode;
using kythira::persistence_exception;
using kythira::raft_log_key_file_ring;

#ifdef FIU_ENABLE
namespace {
struct fiu_init_fixture {
    fiu_init_fixture() { ::fiu_init(0); }
};
}  // namespace
BOOST_GLOBAL_FIXTURE(fiu_init_fixture);
#endif

namespace {

struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> counter{0};
        path = fs::temp_directory_path() / ("kythira_rle_" + std::to_string(::getpid()) + "_" +
                                            std::to_string(counter.fetch_add(1)));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

auto wrapping_key(unsigned char fill = 0x42) -> kythira::raft_log_data_key_bytes {
    kythira::raft_log_data_key_bytes k{};
    k.fill(fill);
    return k;
}

/// A key source that counts its provider calls.
struct counting_source {
    std::shared_ptr<int> generated = std::make_shared<int>(0);
    std::shared_ptr<int> unwrapped = std::make_shared<int>(0);
    [[nodiscard]] auto source(unsigned char fill = 0x42) const -> kythira::raft_log_key_source {
        auto inner = kythira::raft_log_fixed_key_source(wrapping_key(fill), "test-key");
        kythira::raft_log_key_source s;
        s._generate = [inner, g = generated]() {
            ++*g;
            return inner._generate();
        };
        s._unwrap = [inner, u = unwrapped](const std::string& id, const std::string& w) {
            ++*u;
            return inner._unwrap(id, w);
        };
        return s;
    }
};

auto open_ring(const fs::path& file, unsigned char fill = 0x42)
    -> std::shared_ptr<raft_log_key_file_ring> {
    return raft_log_key_file_ring::open(file,
                                        kythira::raft_log_fixed_key_source(wrapping_key(fill)));
}

auto sealed_options(std::shared_ptr<kythira::log_key_ring> ring,
                    log_encryption_mode mode = log_encryption_mode::seal,
                    std::size_t segment_max = std::size_t{64} * 1024 * 1024)
    -> kythira::binary_file_persistence_options {
    kythira::binary_file_persistence_options o;
    o._key_ring = std::move(ring);
    o._encryption = mode;
    o._segment_max_bytes = segment_max;
    return o;
}

/// A command whose bytes are easy to search for.
auto marker_command(std::uint64_t i) -> std::vector<std::byte> {
    const std::string text = "SECRET-VALUE-" + std::to_string(i) + "-PLAINTEXT-MARKER";
    std::vector<std::byte> out(text.size());
    std::transform(text.begin(), text.end(), out.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return out;
}

auto make_entry(std::uint64_t term, std::uint64_t index, std::vector<std::byte> cmd)
    -> log_entry_t {
    log_entry_t e;
    e._term = term;
    e._index = index;
    e._command = std::move(cmd);
    return e;
}

auto read_file(const fs::path& p) -> std::string {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

/// Files under `dir` holding `needle`.
auto files_holding(const fs::path& dir, const std::string& needle) -> std::vector<fs::path> {
    std::vector<fs::path> out;
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        if (e.is_regular_file() && read_file(e.path()).find(needle) != std::string::npos) {
            out.push_back(e.path());
        }
    }
    return out;
}

auto segments_in(const fs::path& dir) -> std::vector<fs::path> {
    std::vector<fs::path> out;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().filename().string().starts_with("log.")) {
            out.push_back(e.path());
        }
    }
    std::sort(out.begin(), out.end(), [](const fs::path& a, const fs::path& b) {
        return std::stoull(a.extension().string().substr(1)) <
               std::stoull(b.extension().string().substr(1));
    });
    return out;
}

/// Change byte `at` of the first record in `seg` and write a CRC that
/// matches, so only authentication can notice.
void tamper_first_record(const fs::path& seg, std::size_t at, std::byte mask = std::byte{0x01}) {
    auto bytes = read_file(seg);
    std::vector<std::byte> buf(bytes.size());
    std::transform(bytes.begin(), bytes.end(), buf.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    const auto len = (static_cast<std::uint32_t>(buf[17]) << 24U) |
                     (static_cast<std::uint32_t>(buf[18]) << 16U) |
                     (static_cast<std::uint32_t>(buf[19]) << 8U) |
                     static_cast<std::uint32_t>(buf[20]);
    const std::size_t body = 21 + len;
    buf[at] ^= mask;
    const auto crc = kythira::crc32(std::span<const std::byte>(buf.data(), body));
    buf[body] = static_cast<std::byte>(crc >> 24U);
    buf[body + 1] = static_cast<std::byte>(crc >> 16U);
    buf[body + 2] = static_cast<std::byte>(crc >> 8U);
    buf[body + 3] = static_cast<std::byte>(crc);
    std::ofstream out(seg, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
}

auto make_snapshot(std::uint64_t index, std::uint64_t term, const std::string& state)
    -> snapshot_t {
    snapshot_t s{};
    s._last_included_index = index;
    s._last_included_term = term;
    s._configuration._nodes = {1, 2, 3};
    s._state_machine_state.resize(state.size());
    std::transform(state.begin(), state.end(), s._state_machine_state.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return s;
}

}  // namespace

// ── Key ring ─────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(key_ring_starts_with_one_generation_and_reloads,
                     *boost::unit_test::timeout(10)) {
    temp_dir d;
    const counting_source counts;
    {
        auto ring = raft_log_key_file_ring::open(d.path / "raft-log-keys", counts.source());
        BOOST_TEST(ring->newest_generation() == 1U);
        BOOST_TEST(*counts.generated == 1);
        BOOST_TEST(ring->key_id(1).value() == "test-key");
    }
    // One unwrap per generation per start, not one per log.
    auto ring = raft_log_key_file_ring::open(d.path / "raft-log-keys", counts.source());
    BOOST_TEST(*counts.generated == 1);
    BOOST_TEST(*counts.unwrapped == 1);
    std::array<std::byte, kythira::log_id_bytes> a{};
    std::array<std::byte, kythira::log_id_bytes> b{};
    b[0] = std::byte{1};
    for (int i = 0; i < 10; ++i) {
        (void)ring->cipher_for(i % 2 == 0 ? a : b);
    }
    BOOST_TEST(*counts.unwrapped == 1);

    // The data key itself never reaches the file.
    const auto file = read_file(d.path / "raft-log-keys");
    const auto key = ring->data_key(1).value();
    BOOST_TEST(file.find(std::string(reinterpret_cast<const char*>(key._bytes.data()),
                                     key._bytes.size())) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(key_ring_refuses_a_provider_that_cannot_unwrap,
                     *boost::unit_test::timeout(10)) {
    temp_dir d;
    (void)open_ring(d.path / "raft-log-keys", 0x42);
    try {
        (void)open_ring(d.path / "raft-log-keys", 0x43);
        BOOST_FAIL("a ring opened under the wrong wrapping key");
    } catch (const persistence_exception& e) {
        const std::string what = e.what();
        BOOST_TEST(what.find("generation 1") != std::string::npos);
        BOOST_TEST(what.find("fixed") != std::string::npos);
    }
    // A damaged file is refused, not treated as empty.
    {
        std::fstream f(d.path / "raft-log-keys", std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(14);
        f.put('\x55');
    }
    BOOST_CHECK_THROW((void)open_ring(d.path / "raft-log-keys"), persistence_exception);
}

BOOST_AUTO_TEST_CASE(key_ring_rotates_and_prunes, *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    BOOST_TEST(ring->rotate() == 2U);
    BOOST_TEST(ring->rotate() == 3U);
    ring->prune(2);
    BOOST_TEST((ring->generations() == std::vector<std::uint32_t>{2, 3}));
    // The newest generation always stays.
    ring->prune(99);
    BOOST_TEST((ring->generations() == std::vector<std::uint32_t>{3}));
    auto again = open_ring(d.path / "keys");
    BOOST_TEST((again->generations() == std::vector<std::uint32_t>{3}));
}

BOOST_AUTO_TEST_CASE(cipher_binds_log_generation_and_additional_data,
                     *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    ring->rotate();
    std::array<std::byte, kythira::log_id_bytes> id_a{};
    std::array<std::byte, kythira::log_id_bytes> id_b{};
    id_b[15] = std::byte{9};
    auto a = ring->cipher_for(id_a);
    auto b = ring->cipher_for(id_b);
    const auto aad = marker_command(1);
    const auto pt = marker_command(2);
    const auto sealed = a->seal(2, aad, pt);
    BOOST_TEST(sealed.size() == pt.size() + kythira::sealed_overhead_bytes);
    BOOST_CHECK(a->open(2, aad, sealed) == pt);
    // Same plaintext twice: different nonces.
    BOOST_CHECK(a->seal(2, aad, pt) != sealed);
    BOOST_CHECK_THROW((void)b->open(2, aad, sealed), persistence_exception);
    BOOST_CHECK_THROW((void)a->open(1, aad, sealed), persistence_exception);
    auto other_aad = aad;
    other_aad[0] ^= std::byte{1};
    BOOST_CHECK_THROW((void)a->open(2, other_aad, sealed), persistence_exception);
    for (std::size_t i = 0; i < sealed.size(); i += 7) {
        auto bad = sealed;
        bad[i] ^= std::byte{0x80};
        BOOST_CHECK_THROW((void)a->open(2, aad, bad), persistence_exception);
    }
    BOOST_CHECK_THROW((void)a->open(7, aad, sealed), persistence_exception);
    // An empty payload seals and opens too.
    const auto empty = a->seal(2, aad, {});
    BOOST_TEST(a->open(2, aad, empty).empty());
}

// ── Sealed engine ────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(sealed_engine_round_trips_and_leaves_no_plaintext,
                     *boost::unit_test::timeout(30)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    const auto log = d.path / "raft" / "1";
    {
        engine_t eng(log, sealed_options(ring, log_encryption_mode::seal, 512));
        for (std::uint64_t i = 1; i <= 40; ++i) {
            eng.append_log_entry(make_entry(1 + (i / 10), i, marker_command(i)));
        }
        eng.save_snapshot(make_snapshot(5, 1, "SNAPSHOT-STATE-PLAINTEXT-MARKER"));
        eng.save_current_term(4);
        BOOST_TEST(eng.sealed_record_count() == 40U);
        BOOST_TEST(eng.segment_count() > 1U);
        BOOST_TEST(eng.lowest_live_generation().value() == 1U);
    }
    BOOST_TEST(files_holding(d.path, "PLAINTEXT-MARKER").empty());
    BOOST_TEST(files_holding(d.path, "SECRET-VALUE").empty());

    engine_t eng(log, sealed_options(ring, log_encryption_mode::seal, 512));
    BOOST_TEST(eng.get_last_log_index() == 40U);
    BOOST_TEST(eng.load_current_term() == 4U);
    for (std::uint64_t i = 1; i <= 40; ++i) {
        const auto e = eng.get_log_entry(i);
        BOOST_REQUIRE(e.has_value());
        BOOST_CHECK(e->command() == marker_command(i));
        BOOST_TEST(e->term() == 1 + (i / 10));
    }
    const auto snap = eng.load_snapshot();
    BOOST_REQUIRE(snap.has_value());
    BOOST_TEST(snap->last_included_index() == 5U);
    BOOST_CHECK(snap->state_machine_state() ==
                make_snapshot(5, 1, "SNAPSHOT-STATE-PLAINTEXT-MARKER").state_machine_state());
    BOOST_TEST((snap->configuration().nodes() == std::vector<std::uint64_t>{1, 2, 3}));

    // Range reads, truncation and prefix deletion work on sealed records.
    BOOST_TEST(eng.get_log_entries(10, 19).size() == 10U);
    eng.truncate_log(31);
    eng.append_log_entry(make_entry(9, 31, marker_command(1031)));
    eng.delete_log_entries_before(20);
    BOOST_CHECK(eng.get_log_entry(31)->command() == marker_command(1031));
    BOOST_TEST(!eng.get_log_entry(19).has_value());
}

BOOST_AUTO_TEST_CASE(sealed_record_with_good_crc_but_bad_tag_is_fatal,
                     *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    const auto log = d.path / "log";
    {
        engine_t eng(log, sealed_options(ring));
        eng.append_log_entry(make_entry(1, 1, marker_command(1)));
        eng.append_log_entry(make_entry(1, 2, marker_command(2)));
    }
    const auto seg = segments_in(log).front();
    const auto pristine = read_file(seg);
    auto restore = [&] {
        std::ofstream out(seg, std::ios::binary | std::ios::trunc);
        out << pristine;
    };
    // The ciphertext, the generation, the index and the term are each bound;
    // the CRC is fixed up each time, so only the tag can notice. The load
    // reads headers only, so the failure shows on the read of the record.
    for (const std::size_t at : {std::size_t{40}, std::size_t{22}, std::size_t{7}}) {
        tamper_first_record(seg, at);
        try {
            engine_t eng(log, sealed_options(ring));
            (void)eng.get_log_entry(1);
            BOOST_FAIL("a tampered record at byte " << at << " opened");
        } catch (const persistence_exception& e) {
            BOOST_TEST_MESSAGE(e.what());
        }
        restore();
    }
    // The term (byte 15) moved: authentication fails, it is not a torn tail.
    tamper_first_record(seg, 15);
    {
        engine_t eng(log, sealed_options(ring));
        BOOST_CHECK_THROW((void)eng.get_log_entry(1), persistence_exception);
        BOOST_TEST(eng.get_last_log_index() == 2U);
    }
    restore();
    engine_t eng(log, sealed_options(ring));
    BOOST_CHECK(eng.get_log_entry(1)->command() == marker_command(1));
}

BOOST_AUTO_TEST_CASE(a_sealed_log_copied_elsewhere_does_not_open, *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    {
        engine_t a(d.path / "a", sealed_options(ring));
        engine_t b(d.path / "b", sealed_options(ring));
        a.append_log_entry(make_entry(1, 1, marker_command(1)));
        b.append_log_entry(make_entry(1, 1, marker_command(2)));
    }
    // Group a's segment dropped into group b's directory.
    fs::copy_file(segments_in(d.path / "a").front(), segments_in(d.path / "b").front(),
                  fs::copy_options::overwrite_existing);
    engine_t b(d.path / "b", sealed_options(ring));
    BOOST_CHECK_THROW((void)b.get_log_entry(1), persistence_exception);

    // A whole directory on a node with another key ring.
    auto other = open_ring(d.path / "other-keys", 0x77);
    engine_t a(d.path / "a", sealed_options(other));
    BOOST_CHECK_THROW((void)a.get_log_entry(1), persistence_exception);
}

BOOST_AUTO_TEST_CASE(torn_sealed_tail_is_cut_without_a_key_check, *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    const auto log = d.path / "log";
    {
        engine_t eng(log, sealed_options(ring));
        for (std::uint64_t i = 1; i <= 3; ++i) {
            eng.append_log_entry(make_entry(1, i, marker_command(i)));
        }
    }
    const auto seg = segments_in(log).back();
    fs::resize_file(seg, fs::file_size(seg) - 5);
    {
        engine_t eng(log, sealed_options(ring));
        BOOST_TEST(eng.get_last_log_index() == 2U);
        eng.append_log_entry(make_entry(1, 3, marker_command(33)));
    }
    engine_t eng(log, sealed_options(ring));
    BOOST_CHECK(eng.get_log_entry(3)->command() == marker_command(33));
}

BOOST_AUTO_TEST_CASE(an_engine_without_a_key_ring_refuses_sealed_records,
                     *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    {
        engine_t eng(d.path / "log", sealed_options(ring));
        eng.append_log_entry(make_entry(1, 1, marker_command(1)));
    }
    try {
        engine_t eng(d.path / "log");
        BOOST_FAIL("a sealed log loaded without a key ring");
    } catch (const persistence_exception& e) {
        BOOST_TEST(std::string(e.what()).find("no key ring") != std::string::npos);
    }
    // A sealed snapshot alone is refused too.
    {
        engine_t eng(d.path / "snap", sealed_options(ring));
        eng.save_snapshot(make_snapshot(3, 1, "state"));
    }
    BOOST_CHECK_THROW(engine_t(d.path / "snap"), persistence_exception);
}

// ── Migration (requirement 4) ────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(plaintext_to_sealed_and_back, *boost::unit_test::timeout(30)) {
    temp_dir d;
    const auto log = d.path / "log";
    // A log written before encryption existed, with a version 1 snapshot.
    {
        engine_t eng(log);
        for (std::uint64_t i = 1; i <= 10; ++i) {
            eng.append_log_entry(make_entry(1, i, marker_command(i)));
        }
        eng.save_snapshot(make_snapshot(2, 1, "SNAPSHOT-PLAINTEXT-MARKER"));
    }
    BOOST_TEST(!files_holding(log, "SECRET-VALUE-3-").empty());

    auto ring = open_ring(d.path / "keys");
    {
        // Turn sealing on: old records still read, new ones are sealed.
        engine_t eng(log, sealed_options(ring));
        BOOST_TEST(eng.sealed_record_count() == 0U);
        for (std::uint64_t i = 11; i <= 15; ++i) {
            eng.append_log_entry(make_entry(2, i, marker_command(i)));
        }
        BOOST_TEST(eng.sealed_record_count() == 5U);
        BOOST_CHECK(eng.get_log_entry(3)->command() == marker_command(3));
        BOOST_TEST(files_holding(log, "SECRET-VALUE-12-").empty());
        BOOST_TEST(!files_holding(log, "SECRET-VALUE-3-").empty());
        // The rewrite seals the rest and the snapshot.
        eng.rewrite_records();
        BOOST_TEST(eng.sealed_record_count() == 15U);
    }
    BOOST_TEST(files_holding(log, "PLAINTEXT-MARKER").empty());
    BOOST_TEST(!fs::exists(log / "rewrite"));
    {
        engine_t eng(log, sealed_options(ring));
        for (std::uint64_t i = 1; i <= 15; ++i) {
            BOOST_CHECK(eng.get_log_entry(i)->command() == marker_command(i));
        }
        BOOST_TEST(eng.load_snapshot()->last_included_index() == 2U);
    }

    // Turn it off: decrypt_only reads sealed records, writes plaintext, and
    // its rewrite leaves nothing a plain engine cannot read.
    {
        engine_t eng(log, sealed_options(ring, log_encryption_mode::decrypt_only));
        eng.append_log_entry(make_entry(3, 16, marker_command(16)));
        BOOST_TEST(eng.sealed_record_count() == 15U);
        eng.rewrite_records();
        BOOST_TEST(eng.sealed_record_count() == 0U);
        BOOST_TEST(!eng.lowest_live_generation().has_value());
    }
    engine_t plain(log);
    BOOST_TEST(plain.get_last_log_index() == 16U);
    for (std::uint64_t i = 1; i <= 16; ++i) {
        BOOST_CHECK(plain.get_log_entry(i)->command() == marker_command(i));
    }
    BOOST_TEST(plain.load_snapshot()->last_included_index() == 2U);
}

BOOST_AUTO_TEST_CASE(rotation_then_rewrite_then_prune, *boost::unit_test::timeout(30)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    const auto log = d.path / "log";
    engine_t eng(log, sealed_options(ring, log_encryption_mode::seal, 300));
    for (std::uint64_t i = 1; i <= 6; ++i) {
        eng.append_log_entry(make_entry(1, i, marker_command(i)));
    }
    BOOST_TEST(ring->rotate() == 2U);
    for (std::uint64_t i = 7; i <= 12; ++i) {
        eng.append_log_entry(make_entry(1, i, marker_command(i)));
    }
    BOOST_TEST(eng.lowest_live_generation().value() == 1U);
    eng.save_snapshot(make_snapshot(4, 1, "state"));
    eng.rewrite_records();
    BOOST_TEST(eng.lowest_live_generation().value() == 2U);
    ring->prune(*eng.lowest_live_generation());
    BOOST_TEST((ring->generations() == std::vector<std::uint32_t>{2}));
    for (std::uint64_t i = 1; i <= 12; ++i) {
        BOOST_CHECK(eng.get_log_entry(i)->command() == marker_command(i));
    }
    // A fresh process: the pruned ring still opens everything.
    auto reopened = open_ring(d.path / "keys");
    engine_t again(log, sealed_options(reopened, log_encryption_mode::seal, 300));
    for (std::uint64_t i = 1; i <= 12; ++i) {
        BOOST_CHECK(again.get_log_entry(i)->command() == marker_command(i));
    }
    BOOST_TEST(again.load_snapshot().has_value());
}

BOOST_AUTO_TEST_CASE(pruning_a_live_generation_is_caught_on_read, *boost::unit_test::timeout(10)) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    {
        engine_t eng(d.path / "log", sealed_options(ring));
        eng.append_log_entry(make_entry(1, 1, marker_command(1)));
    }
    ring->rotate();
    ring->prune(2);  // wrong: generation 1 is still live
    auto reopened = open_ring(d.path / "keys");
    engine_t eng(d.path / "log", sealed_options(reopened));
    try {
        (void)eng.get_log_entry(1);
        BOOST_FAIL("a record sealed under a pruned generation opened");
    } catch (const persistence_exception& e) {
        BOOST_TEST(std::string(e.what()).find("generation 1") != std::string::npos);
    }
}

#ifdef FIU_ENABLE
namespace {

/// Interrupt a sealing rewrite at `point`, then check that a fresh engine
/// loads the whole log, sealed or not, with no stray segments or marker.
void interrupted_rewrite(const char* point, bool expect_sealed) {
    temp_dir d;
    auto ring = open_ring(d.path / "keys");
    const auto log = d.path / "log";
    {
        kythira::binary_file_persistence_options plain;
        plain._segment_max_bytes = 300;
        engine_t eng(log, plain);
        for (std::uint64_t i = 1; i <= 12; ++i) {
            eng.append_log_entry(make_entry(1, i, marker_command(i)));
        }
    }
    {
        engine_t eng(log, sealed_options(ring, log_encryption_mode::seal, 300));
        ::fiu_enable(point, 1, nullptr, FIU_ONETIME);
        BOOST_CHECK_THROW(eng.rewrite_records(), persistence_exception);
        ::fiu_disable(point);
    }
    engine_t eng(log, sealed_options(ring, log_encryption_mode::seal, 300));
    BOOST_TEST(!fs::exists(log / "rewrite"), point);
    BOOST_TEST(eng.get_last_log_index() == 12U, point);
    for (std::uint64_t i = 1; i <= 12; ++i) {
        BOOST_CHECK(eng.get_log_entry(i)->command() == marker_command(i));
    }
    BOOST_TEST(eng.sealed_record_count() == (expect_sealed ? 12U : 0U), point);
    BOOST_TEST(files_holding(log, "SECRET-VALUE").empty() == expect_sealed, point);
    // Appends continue after whichever run survived.
    eng.append_log_entry(make_entry(2, 13, marker_command(13)));
    engine_t again(log, sealed_options(ring, log_encryption_mode::seal, 300));
    BOOST_CHECK(again.get_log_entry(13)->command() == marker_command(13));
}

}  // namespace

BOOST_AUTO_TEST_CASE(rewrite_interrupted_after_the_pending_marker, *boost::unit_test::timeout(30)) {
    interrupted_rewrite("raft/binary_persistence/rewrite_after_pending", false);
}

BOOST_AUTO_TEST_CASE(rewrite_interrupted_while_copying, *boost::unit_test::timeout(30)) {
    interrupted_rewrite("raft/binary_persistence/rewrite_mid_copy", false);
}

BOOST_AUTO_TEST_CASE(rewrite_interrupted_after_the_committed_marker,
                     *boost::unit_test::timeout(30)) {
    interrupted_rewrite("raft/binary_persistence/rewrite_after_commit", true);
}
#endif
