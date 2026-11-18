// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_data_path_test.cpp
/// @brief S3's write and read path for object bytes (`s3_data_path.hpp`,
///        `s3_placement.hpp`; .kiro/specs/s3-compatible-storage/ task 5,
///        Requirements 7.1, 10.1, 10.2, 10.5 and 15.1).
///
/// Placement under both rules; chunking and the MD5 ETag; the write quorum
/// with nodes down or refusing; that the manifest is committed only once its
/// chunks are durable on a quorum; ranged reads; and repair of missing and
/// corrupt copies, on in-memory copies and on real chunk stores.

#define BOOST_TEST_MODULE s3_data_path_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_placement.hpp>

#include <raft/chunk_service.hpp>
#include <raft/chunk_store.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using kythira::chunk_read_result;
using kythira::chunk_read_status;
using kythira::chunk_sha;
using kythira::chunk_write_result;
using kythira::sha256_of;
using kythira::s3::blob_node;
using kythira::s3::chunk_copy;
using kythira::s3::chunk_event;
using kythira::s3::chunk_placement;
using kythira::s3::data_path;
using kythira::s3::data_path_options;
using kythira::s3::object_content;
using kythira::s3::placement_map;
using kythira::s3::placement_rule;

auto make_bytes(std::size_t n, std::uint32_t seed) -> std::vector<std::byte> {
    std::mt19937 rng(seed);
    std::vector<std::byte> out(n);
    for (auto& b : out) {
        b = static_cast<std::byte>(rng() & 0xFFU);
    }
    return out;
}

auto chunk_of(std::uint32_t seed) -> chunk_sha {
    return sha256_of(make_bytes(16, seed));
}

auto md5_hex(std::span<const std::byte> b) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int len = 0;
    BOOST_REQUIRE(::EVP_Digest(b.data(), b.size(), md.data(), &len, ::EVP_md5(), nullptr) == 1);
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        static constexpr std::string_view d = "0123456789abcdef";
        out.push_back(d[md.at(i) >> 4U]);
        out.push_back(d[md.at(i) & 0xFU]);
    }
    return out;
}

/// An in-memory copy that can be down, refuse, lose or damage chunks.
struct fake_copy {
    enum class mode : std::uint8_t {
        ok,
        down,
        refuse
    };
    mutable std::mutex mu;
    mode m = mode::ok;
    std::map<chunk_sha, std::vector<std::byte>> chunks;
    std::set<chunk_sha> damaged;
    std::size_t writes = 0;
    std::size_t reads = 0;

    auto write(const chunk_sha& sha, std::span<const std::byte> bytes) -> chunk_write_result {
        const std::lock_guard lock(mu);
        ++writes;
        if (m == mode::down) {
            return chunk_write_result::unavailable;
        }
        if (m == mode::refuse || sha256_of(bytes) != sha) {
            return chunk_write_result::refused;
        }
        const bool fresh =
            chunks.emplace(sha, std::vector<std::byte>(bytes.begin(), bytes.end())).second;
        return fresh ? chunk_write_result::created : chunk_write_result::present;
    }
    auto read(const chunk_sha& sha) -> chunk_read_result {
        const std::lock_guard lock(mu);
        ++reads;
        if (m == mode::down) {
            return {chunk_read_status::unavailable, {}};
        }
        auto it = chunks.find(sha);
        if (it == chunks.end()) {
            return {chunk_read_status::missing, {}};
        }
        if (damaged.erase(sha) != 0) {
            // As local_chunk_access does: the bad copy is dropped.
            chunks.erase(it);
            return {chunk_read_status::corrupt, {}};
        }
        return {chunk_read_status::found, it->second};
    }
    [[nodiscard]] auto holds(const chunk_sha& sha) const -> bool {
        const std::lock_guard lock(mu);
        return chunks.contains(sha);
    }
};

/// Three in-memory nodes, co-located placement over all of them.
struct cluster {
    std::array<fake_copy, 3> nodes;
    std::vector<chunk_copy> copies;
    std::vector<std::string> replicas{"n0", "n1", "n2"};
    std::vector<chunk_event> events;

    cluster() {
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            copies.emplace_back("n" + std::to_string(i), nodes.at(i));
        }
    }

    auto path(data_path_options o = {}) -> data_path {
        return data_path(
            [this](const chunk_sha& sha) { return place(placement_map{}, sha, replicas); },
            kythira::s3::resolver_for(copies), o,
            [this](const chunk_event& e) { events.push_back(e); });
    }

    [[nodiscard]] auto durable_copies(const chunk_sha& sha) const -> std::size_t {
        return static_cast<std::size_t>(
            std::ranges::count_if(nodes, [&](const fake_copy& n) { return n.holds(sha); }));
    }
};

auto small_chunks() -> data_path_options {
    data_path_options o;
    o.chunk_bytes = 1000;
    return o;
}

auto rendezvous_map(std::size_t n, std::size_t groups) -> placement_map {
    placement_map m;
    m.rule = placement_rule::rendezvous;
    m.epoch = 7;
    for (std::size_t i = 0; i < n; ++i) {
        m.nodes.push_back({"b" + std::to_string(i), "g" + std::to_string(i % groups), 1});
    }
    return m;
}

auto group_of(const placement_map& m, const std::string& id) -> std::string {
    for (const auto& n : m.nodes) {
        if (n.id == id) {
            return n.group;
        }
    }
    return {};
}

}  // namespace

// ---- placement ------------------------------------------------------------

BOOST_AUTO_TEST_CASE(co_located_copies_are_the_owning_replicas_with_a_majority_quorum) {
    const placement_map m;  // co-located by default
    const auto sha = chunk_of(1);
    for (std::size_t n = 1; n <= 5; ++n) {
        std::vector<std::string> replicas;
        for (std::size_t i = 0; i < n; ++i) {
            replicas.push_back("r" + std::to_string(i));
        }
        const auto p = place(m, sha, replicas);
        BOOST_TEST(p.nodes == replicas);
        BOOST_TEST(p.write_quorum == n / 2 + 1);
    }
    BOOST_CHECK_THROW((void)place(m, sha, {}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(rendezvous_is_deterministic_and_spreads_across_groups) {
    const auto m = rendezvous_map(9, 3);
    for (std::uint32_t s = 0; s < 200; ++s) {
        const auto sha = chunk_of(s);
        const auto p = place(m, sha, {});
        BOOST_TEST(p.nodes.size() == 3U);
        BOOST_TEST(p.write_quorum == 2U);
        BOOST_TEST((p.nodes == place(m, sha, {}).nodes));
        std::set<std::string> groups;
        for (const auto& id : p.nodes) {
            groups.insert(group_of(m, id));
        }
        BOOST_TEST(groups.size() == 3U);
    }
    // Fewer groups than copies: one group gives two.
    const auto two = rendezvous_map(6, 2);
    const auto p = place(two, chunk_of(3), {});
    BOOST_TEST(p.nodes.size() == 3U);
    BOOST_TEST(std::set<std::string>(p.nodes.begin(), p.nodes.end()).size() == 3U);
}

BOOST_AUTO_TEST_CASE(rendezvous_follows_weights_and_moves_little_when_a_node_joins) {
    auto m = rendezvous_map(4, 4);
    m.copies = 1;
    m.write_quorum = 1;
    m.nodes[0].weight = 3;
    std::map<std::string, std::size_t> first;
    constexpr std::uint32_t chunks = 6000;
    std::vector<std::string> before;
    for (std::uint32_t s = 0; s < chunks; ++s) {
        before.push_back(place(m, chunk_of(s), {}).nodes.at(0));
        ++first[before.back()];
    }
    // Weight 3 of a total 6: about half the first choices.
    BOOST_TEST(first["b0"] > chunks * 4 / 10);
    BOOST_TEST(first["b0"] < chunks * 6 / 10);
    for (const auto* id : {"b1", "b2", "b3"}) {
        BOOST_TEST(first[id] > chunks / 10);
        BOOST_TEST(first[id] < chunks * 23 / 100);
    }
    // A fifth node of weight 1 (of 7) takes about a seventh, and only
    // chunks that move to it move at all.
    m.nodes.push_back({"b4", "g4", 1});
    std::size_t moved = 0;
    for (std::uint32_t s = 0; s < chunks; ++s) {
        const auto now = place(m, chunk_of(s), {}).nodes.at(0);
        if (now != before[s]) {
            ++moved;
            BOOST_TEST(now == "b4");
        }
    }
    BOOST_TEST(moved > chunks / 10);
    BOOST_TEST(moved < chunks / 5);
}

BOOST_AUTO_TEST_CASE(a_bad_rendezvous_map_is_refused) {
    auto m = rendezvous_map(3, 3);
    BOOST_CHECK_NO_THROW(kythira::s3::validate(m));
    m.write_quorum = 4;
    BOOST_CHECK_THROW(kythira::s3::validate(m), std::invalid_argument);
    m = rendezvous_map(2, 2);
    BOOST_CHECK_THROW(kythira::s3::validate(m), std::invalid_argument);
    m = rendezvous_map(3, 3);
    m.nodes[1].id = m.nodes[0].id;
    BOOST_CHECK_THROW(kythira::s3::validate(m), std::invalid_argument);
    m = rendezvous_map(3, 3);
    m.nodes[2].weight = 0;
    BOOST_CHECK_THROW((void)place(m, chunk_of(1), {}), std::invalid_argument);
}

// ---- writes ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_body_is_cut_into_chunks_with_its_md5) {
    cluster c;
    auto path = c.path(small_chunks());
    for (const std::size_t size : {0UL, 1UL, 999UL, 1000UL, 1001UL, 3500UL}) {
        const auto body = make_bytes(size, static_cast<std::uint32_t>(size));
        auto w = path.write_body(body);
        BOOST_TEST_REQUIRE(w.has_value());
        BOOST_TEST(w->size == size);
        BOOST_TEST(w->md5_hex == md5_hex(body));
        BOOST_TEST(w->manifest.size() == (size + 999) / 1000);
        std::size_t pos = 0;
        for (const auto& ref : w->manifest) {
            BOOST_TEST(ref.size == std::min<std::size_t>(1000, size - pos));
            BOOST_TEST((ref.sha == sha256_of(std::span(body).subspan(pos, ref.size))));
            BOOST_TEST(c.durable_copies(ref.sha) == 3U);
            pos += ref.size;
        }
    }
    // MD5 of nothing, S3's ETag of an empty object.
    BOOST_TEST(path.write_body({})->md5_hex == "d41d8cd98f00b204e9800998ecf8427e");
}

BOOST_AUTO_TEST_CASE(a_streamed_body_gives_the_same_manifest_in_any_pieces) {
    cluster c;
    auto path = c.path(small_chunks());
    const auto body = make_bytes(7777, 9);
    const auto whole = path.write_body(body);
    BOOST_TEST_REQUIRE(whole.has_value());
    std::mt19937 rng(4);
    for (int round = 0; round < 20; ++round) {
        auto w = path.writer();
        std::size_t pos = 0;
        while (pos < body.size()) {
            const auto n = std::min<std::size_t>(rng() % 2600, body.size() - pos);
            BOOST_TEST(!w.append(std::span(body).subspan(pos, n)).has_value());
            pos += n;
        }
        auto streamed = w.finish();
        BOOST_TEST_REQUIRE(streamed.has_value());
        BOOST_TEST((streamed->manifest == whole->manifest));
        BOOST_TEST(streamed->md5_hex == whole->md5_hex);
    }
}

BOOST_AUTO_TEST_CASE(one_node_down_still_makes_the_quorum) {
    for (const bool parallel : {true, false}) {
        cluster c;
        c.nodes[1].m = fake_copy::mode::down;
        auto o = small_chunks();
        o.parallel_writes = parallel;
        auto path = c.path(o);
        auto w = path.write_body(make_bytes(2500, 1));
        BOOST_TEST_REQUIRE(w.has_value());
        for (const auto& ref : w->manifest) {
            BOOST_TEST(c.durable_copies(ref.sha) == 2U);
        }
        BOOST_TEST(path.stats().chunks_written == 3U);
        BOOST_TEST(path.stats().copies_written == 6U);
    }
}

BOOST_AUTO_TEST_CASE(two_nodes_down_is_slow_down_and_nothing_is_committed) {
    cluster c;
    c.nodes[0].m = fake_copy::mode::down;
    c.nodes[2].m = fake_copy::mode::down;
    auto path = c.path(small_chunks());
    bool committed = false;
    auto r = path.put_object(object_content{}, make_bytes(2500, 2), [&](const object_content&) {
        committed = true;
        return 0;
    });
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().status == 503U);
    BOOST_TEST(r.error().code == "SlowDown");
    BOOST_TEST(!committed);
    // The first chunk failed, so the body was abandoned there.
    BOOST_TEST(c.nodes[1].writes == 1U);
    BOOST_TEST(path.stats().quorum_failures == 1U);
}

BOOST_AUTO_TEST_CASE(a_refused_chunk_is_an_internal_error_not_a_retry) {
    cluster c;
    c.nodes[2].m = fake_copy::mode::refuse;
    auto path = c.path(small_chunks());
    auto r = path.write_body(make_bytes(10, 3));
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().status == 500U);
    BOOST_TEST(r.error().code == "InternalError");
}

BOOST_AUTO_TEST_CASE(the_manifest_is_committed_only_after_its_chunks_are_durable) {
    cluster c;
    c.nodes[2].m = fake_copy::mode::down;
    auto path = c.path(small_chunks());
    object_content content;
    content.content_type = "text/plain";
    const auto body = make_bytes(4321, 5);
    auto r = path.put_object(content, body, [&](const object_content& committed) {
        // At commit time every chunk named is on a quorum.
        for (const auto& ref : committed.manifest) {
            BOOST_TEST(c.durable_copies(ref.sha) >= 2U);
        }
        BOOST_TEST(committed.content_type == "text/plain");
        BOOST_TEST(committed.etag == md5_hex(body));
        BOOST_TEST(committed.size() == body.size());
        return std::string("v1");
    });
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(*r == "v1");
}

// ---- reads ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(ranged_reads_return_exactly_the_bytes_asked_for) {
    cluster c;
    auto path = c.path(small_chunks());
    const auto body = make_bytes(5432, 6);
    object_content content;
    content.manifest = path.write_body(body)->manifest;
    std::mt19937 rng(8);
    for (int i = 0; i < 300; ++i) {
        const std::uint64_t off = rng() % (body.size() + 1);
        const std::uint64_t len = rng() % (body.size() - off + 1);
        std::vector<std::byte> got;
        auto n = path.read_range(content, off, len, [&](std::span<const std::byte> s) {
            got.insert(got.end(), s.begin(), s.end());
        });
        BOOST_TEST_REQUIRE(n.has_value());
        BOOST_TEST(*n == len);
        BOOST_TEST(
            (got == std::vector<std::byte>(body.begin() + static_cast<std::ptrdiff_t>(off),
                                           body.begin() + static_cast<std::ptrdiff_t>(off + len))));
    }
    // Only the chunks a range overlaps are read.
    const auto before = path.stats().chunks_read;
    (void)path.read_range(content, 1500, 1000, [](std::span<const std::byte>) {});
    BOOST_TEST(path.stats().chunks_read - before == 2U);
    // Past the end.
    auto bad = path.read_range(content, 5000, 433, [](std::span<const std::byte>) {});
    BOOST_TEST_REQUIRE(!bad.has_value());
    BOOST_TEST(bad.error().status == 416U);
}

BOOST_AUTO_TEST_CASE(missing_and_corrupt_copies_are_repaired_and_reported) {
    cluster c;
    auto path = c.path(small_chunks());
    const auto body = make_bytes(800, 7);
    const auto ref = path.write_body(body)->manifest.at(0);
    c.nodes[0].damaged.insert(ref.sha);  // corrupt on the first node read
    c.nodes[1].chunks.erase(ref.sha);    // lost on the second
    auto got = path.read_chunk(ref);
    BOOST_TEST_REQUIRE(got.has_value());
    BOOST_TEST((*got == body));
    BOOST_TEST_REQUIRE(c.events.size() == 2U);
    BOOST_TEST(c.events[0].node == "n0");
    BOOST_TEST((c.events[0].found == chunk_read_status::corrupt));
    BOOST_TEST(c.events[0].repaired);
    BOOST_TEST(c.events[1].node == "n1");
    BOOST_TEST((c.events[1].found == chunk_read_status::missing));
    BOOST_TEST(c.events[1].repaired);
    BOOST_TEST(c.durable_copies(ref.sha) == 3U);
    BOOST_TEST(path.stats().repairs == 2U);
    BOOST_TEST(path.stats().bad_copies == 2U);
    // Now the first copy answers.
    c.events.clear();
    BOOST_TEST((*path.read_chunk(ref) == body));
    BOOST_TEST(c.events.empty());
}

BOOST_AUTO_TEST_CASE(a_node_that_does_not_answer_is_skipped_not_repaired) {
    cluster c;
    auto path = c.path(small_chunks());
    const auto body = make_bytes(500, 8);
    const auto ref = path.write_body(body)->manifest.at(0);
    c.nodes[0].m = fake_copy::mode::down;
    BOOST_TEST((*path.read_chunk(ref) == body));
    BOOST_TEST(c.events.empty());
    BOOST_TEST(c.nodes[0].writes == 1U);  // the original write only
}

BOOST_AUTO_TEST_CASE(no_good_copy_is_an_internal_error_and_serves_nothing) {
    cluster c;
    auto path = c.path(small_chunks());
    const auto body = make_bytes(2500, 9);
    object_content content;
    content.manifest = path.write_body(body)->manifest;
    const auto& lost = content.manifest.at(1);
    c.nodes[0].damaged.insert(lost.sha);
    c.nodes[1].chunks.erase(lost.sha);
    c.nodes[2].m = fake_copy::mode::down;
    std::uint64_t seen = 0;
    auto r = path.read_range(content, 0, body.size(),
                             [&](std::span<const std::byte> s) { seen += s.size(); });
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().status == 500U);
    BOOST_TEST(r.error().code == "InternalError");
    BOOST_TEST(seen == 1000U);  // the first chunk only, never a bad one
    BOOST_TEST_REQUIRE(c.events.size() == 2U);
    BOOST_TEST(!c.events[0].repaired);
    BOOST_TEST(!c.events[1].repaired);
    BOOST_TEST(path.stats().unreadable_chunks == 1U);
}

// ---- real stores ----------------------------------------------------------

namespace {

struct temp_dir {
    fs::path path;
    temp_dir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("s3_data_path_test_" + std::to_string(rd()));
        fs::create_directories(path);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(a_corrupt_file_in_a_real_store_is_repaired_on_read) {
    temp_dir dir;
    std::vector<std::unique_ptr<kythira::chunk_store>> stores;
    std::vector<std::unique_ptr<kythira::local_chunk_access>> locals;
    std::vector<chunk_copy> copies;
    std::vector<std::string> replicas;
    for (int i = 0; i < 3; ++i) {
        kythira::chunk_store_options o;
        o._data_dir = dir.path / std::to_string(i);
        stores.push_back(std::make_unique<kythira::chunk_store>(o));
        locals.push_back(std::make_unique<kythira::local_chunk_access>(*stores.back()));
        replicas.push_back("n" + std::to_string(i));
        copies.emplace_back(replicas.back(), *locals.back());
    }
    std::vector<chunk_event> events;
    data_path_options opts;
    opts.chunk_bytes = 128 * 1024;  // above the pack threshold: loose files
    data_path path([&](const chunk_sha& sha) { return place(placement_map{}, sha, replicas); },
                   kythira::s3::resolver_for(copies), opts,
                   [&](const chunk_event& e) { events.push_back(e); });
    const auto body = make_bytes(300 * 1024, 10);
    object_content content;
    content.manifest = path.write_body(body)->manifest;
    BOOST_TEST_REQUIRE(content.manifest.size() == 3U);
    const auto sha = content.manifest.at(0).sha;
    for (const auto& s : stores) {
        BOOST_TEST(s->verify(sha));
    }
    {
        std::fstream f(stores[0]->loose_path(sha), std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(100);
        f.put('\x55');
    }
    BOOST_TEST(!stores[0]->verify(sha));
    std::vector<std::byte> got;
    auto n = path.read_range(content, 0, body.size(), [&](std::span<const std::byte> s) {
        got.insert(got.end(), s.begin(), s.end());
    });
    BOOST_TEST_REQUIRE(n.has_value());
    BOOST_TEST((got == body));
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST(events[0].repaired);
    BOOST_TEST(stores[0]->verify(sha));
}
