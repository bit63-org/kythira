// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_sweeps_test.cpp
/// @brief Chunk collection, the orphan sweep and placement repair
///        (`s3_sweeps.hpp`; .kiro/specs/s3-compatible-storage/ task 12,
///        Requirements 10.3, 10.4 and 10.6).
///
/// On three real chunk stores and the in-process metadata layer: collected
/// chunks leave every store and keep a tombstone; uncommitted chunks go
/// after two sweeps a grace period apart and committed ones never do; a
/// node that is down holds a delete back until it answers; a store that
/// lost everything is refilled from the others.

#define BOOST_TEST_MODULE s3_sweeps_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_sweeps.hpp>

#include <raft/chunk_service.hpp>
#include <raft/chunk_store.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

namespace fs = std::filesystem;
using kythira::chunk_listing;
using kythira::chunk_read_result;
using kythira::chunk_read_status;
using kythira::chunk_remove_result;
using kythira::chunk_sha;
using kythira::chunk_write_result;
using namespace kythira::s3;

auto make_bytes(std::size_t n, std::uint32_t seed) -> std::vector<std::byte> {
    std::mt19937 rng(seed);
    std::vector<std::byte> out(n);
    for (auto& b : out) {
        b = static_cast<std::byte>(rng() & 0xFFU);
    }
    return out;
}

struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> n{0};
        path = fs::temp_directory_path() /
               ("s3_sweeps_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
};

/// A real store behind an access that can be switched off.
struct switchable {
    kythira::local_chunk_access* local = nullptr;
    bool down = false;

    auto write(const chunk_sha& sha, std::span<const std::byte> b) -> chunk_write_result {
        return down ? chunk_write_result::unavailable : local->write(sha, b);
    }
    auto read(const chunk_sha& sha) -> chunk_read_result {
        return down ? chunk_read_result{chunk_read_status::unavailable, {}} : local->read(sha);
    }
    auto list(const std::optional<chunk_sha>& after, std::size_t n)
        -> std::optional<chunk_listing> {
        return down ? std::nullopt : local->list(after, n);
    }
    auto remove(const chunk_sha& sha) -> chunk_remove_result {
        return down ? chunk_remove_result::unavailable : local->remove(sha);
    }
};

/// Three nodes, co-located placement over all of them, one bucket.
struct cluster {
    temp_dir dir;
    std::vector<std::unique_ptr<kythira::chunk_store>> stores;
    std::vector<std::unique_ptr<kythira::local_chunk_access>> locals;
    std::vector<std::unique_ptr<switchable>> nodes;
    std::vector<chunk_copy> copies;
    std::vector<std::unique_ptr<chunk_inventory>> inventories;
    std::vector<std::string> names{"n0", "n1", "n2"};
    local_metadata meta;
    std::unique_ptr<data_path> path;
    std::uint64_t now = 10'000'000;
    std::uint64_t bucket_id = 0;

    cluster() {
        for (std::size_t i = 0; i < names.size(); ++i) {
            open_store(i);
            nodes.push_back(std::make_unique<switchable>(switchable{locals[i].get()}));
            copies.emplace_back(names[i], *nodes[i]);
            inventories.push_back(std::make_unique<chunk_inventory>(names[i], *nodes[i]));
        }
        data_path_options o;
        o.chunk_bytes = 64 * 1024;
        o.parallel_writes = false;
        path = std::make_unique<data_path>(
            [this](const chunk_sha& sha) { return place(placement_map{}, sha, names); },
            resolver_for(copies), o);
        index_command c;
        c.op = index_command::kind::create_bucket;
        c.now_ms = ++now;
        c.bucket = "b";
        c.owner = "acct";
        c.region = "us-east-1";
        BOOST_REQUIRE(meta.propose(c).ok());
        bucket_id = meta.bucket("b")->id;
    }

    void open_store(std::size_t i) {
        kythira::chunk_store_options o;
        o._data_dir = dir.path / (names[i] + "-" + std::to_string(stores.size()));
        auto store = std::make_unique<kythira::chunk_store>(o);
        auto local = std::make_unique<kythira::local_chunk_access>(*store);
        if (i < stores.size()) {
            stores[i] = std::move(store);
            locals[i] = std::move(local);
            nodes[i]->local = locals[i].get();
        } else {
            stores.push_back(std::move(store));
            locals.push_back(std::move(local));
        }
    }

    auto sweeper(sweep_options o = {}) -> chunk_sweeper<local_metadata> {
        o.grace_ms = o.grace_ms != 0 ? o.grace_ms : 60 * 60 * 1000;
        o.clock = [this] { return now; };
        return chunk_sweeper<local_metadata>(
            meta,
            [this] {
                std::vector<const chunk_inventory*> out;
                for (const auto& i : inventories) {
                    out.push_back(i.get());
                }
                return out;
            },
            [this](const chunk_sha& sha) { return place(placement_map{}, sha, names); }, o);
    }

    /// Store a body and commit it under `key`; its manifest.
    auto put(const std::string& key, std::uint32_t seed, std::size_t bytes = 150 * 1024)
        -> std::vector<chunk_ref> {
        const auto body = make_bytes(bytes, seed);
        auto w = path->write_body(body);
        BOOST_REQUIRE(w.has_value());
        index_command c;
        c.op = index_command::kind::put_object;
        c.now_ms = ++now;
        c.written_ms = now;
        c.target = {bucket_id, versioning_state::unversioned, false};
        c.key = key;
        c.owner = "acct";
        c.content.manifest = w->manifest;
        c.content.etag = w->md5_hex;
        BOOST_REQUIRE(meta.propose(c).ok());
        return w->manifest;
    }

    void del(const std::string& key) {
        index_command c;
        c.op = index_command::kind::delete_object;
        c.now_ms = ++now;
        c.target = {bucket_id, versioning_state::unversioned, false};
        c.key = key;
        BOOST_REQUIRE(meta.propose(c).ok());
    }

    [[nodiscard]] auto held_by(const chunk_sha& sha) const -> std::size_t {
        std::size_t n = 0;
        for (const auto& s : stores) {
            n += s->verify(sha) ? 1 : 0;
        }
        return n;
    }
};

constexpr std::uint64_t hour = 60 * 60 * 1000;

}  // namespace

BOOST_AUTO_TEST_CASE(collected_chunks_leave_every_store_and_keep_a_tombstone) {
    cluster c;
    const auto gone = c.put("gone", 1);
    const auto kept = c.put("kept", 2);
    c.del("gone");
    auto s = c.sweeper();

    c.now += hour - 10;  // inside the grace period
    auto r = s.sweep();
    BOOST_TEST(r.collected == 0U);
    BOOST_TEST(r.orphans_seen == 0U);
    BOOST_TEST(c.held_by(gone[0].sha) == 3U);

    c.now += 20;
    r = s.sweep();
    BOOST_TEST(r.collected == gone.size());
    BOOST_TEST(r.deleted == gone.size());
    BOOST_TEST(r.copies_removed == 3 * gone.size());
    BOOST_TEST(r.deletes_pending == 0U);
    for (const auto& ref : gone) {
        BOOST_TEST(c.held_by(ref.sha) == 0U);
        const auto rec = c.meta.refcount(ref.sha);
        BOOST_REQUIRE(rec.has_value());
        BOOST_TEST((rec->state == chunk_state::deleted));
        BOOST_TEST(rec->deleted_ms == c.now);
    }
    for (const auto& ref : kept) {
        BOOST_TEST(c.held_by(ref.sha) == 3U);
    }
    BOOST_TEST(c.meta.pending_deletions(10).empty());

    // A grace period later the tombstones go too.
    c.now += hour;
    s.sweep();
    BOOST_TEST(!c.meta.refcount(gone[0].sha).has_value());
    BOOST_TEST(c.meta.refcount(kept[0].sha).has_value());
}

BOOST_AUTO_TEST_CASE(uncommitted_chunks_go_after_two_sweeps_a_grace_period_apart) {
    cluster c;
    const auto kept = c.put("kept", 1);
    const auto orphan = c.path->write_body(make_bytes(100 * 1024, 7))->manifest;
    BOOST_REQUIRE(orphan.size() == 2U);
    auto s = c.sweeper();

    auto r = s.sweep();
    BOOST_TEST(r.orphans_seen == orphan.size());
    BOOST_TEST(r.orphans_claimed == 0U);
    BOOST_TEST(r.chunks_listed == 3 * (kept.size() + orphan.size()));
    BOOST_TEST(s.candidates() == orphan.size());

    c.now += hour - 1;
    r = s.sweep();
    BOOST_TEST(r.orphans_claimed == 0U);
    BOOST_TEST(c.held_by(orphan[0].sha) == 3U);

    c.now += 1;
    r = s.sweep();
    BOOST_TEST(r.orphans_claimed == orphan.size());
    BOOST_TEST(r.deleted == orphan.size());
    BOOST_TEST(s.candidates() == 0U);
    for (const auto& ref : orphan) {
        BOOST_TEST(c.held_by(ref.sha) == 0U);
    }
    for (const auto& ref : kept) {
        BOOST_TEST(c.held_by(ref.sha) == 3U);
    }
}

BOOST_AUTO_TEST_CASE(a_candidate_that_commits_is_not_claimed) {
    cluster c;
    const auto body = make_bytes(50 * 1024, 3);
    const auto w = c.path->write_body(body);
    auto s = c.sweeper();
    BOOST_TEST(s.sweep().orphans_seen == 1U);

    // The write commits after all (inside its max write time).
    index_command put;
    put.op = index_command::kind::put_object;
    put.now_ms = ++c.now;
    put.written_ms = c.now - 1;
    put.target = {c.bucket_id, versioning_state::unversioned, false};
    put.key = "late";
    put.owner = "acct";
    put.content.manifest = w->manifest;
    BOOST_REQUIRE(c.meta.propose(put).ok());

    c.now += 2 * hour;
    const auto r = s.sweep();
    BOOST_TEST(r.orphans_seen == 0U);
    BOOST_TEST(r.orphans_claimed == 0U);
    BOOST_TEST(c.held_by(w->manifest[0].sha) == 3U);
}

BOOST_AUTO_TEST_CASE(a_node_that_is_down_holds_a_delete_back_until_it_answers) {
    cluster c;
    const auto gone = c.put("gone", 4, 10 * 1024);
    c.del("gone");
    auto s = c.sweeper();
    c.nodes[1]->down = true;
    c.now += 2 * hour;
    auto r = s.sweep();
    BOOST_TEST(r.collected == 1U);
    BOOST_TEST(r.deleted == 0U);
    BOOST_TEST(r.deletes_pending == 1U);
    BOOST_TEST(r.unreachable_nodes == 1U);
    BOOST_TEST((c.meta.refcount(gone[0].sha)->state == chunk_state::collecting));
    BOOST_TEST(c.held_by(gone[0].sha) == 1U);  // the node that was down

    // Meanwhile a PUT of the same bytes is refused, so nothing commits a
    // reference to bytes on their way out.
    index_command put;
    put.op = index_command::kind::put_object;
    put.now_ms = ++c.now;
    put.written_ms = c.now;
    put.target = {c.bucket_id, versioning_state::unversioned, false};
    put.key = "again";
    put.owner = "acct";
    put.content.manifest = gone;
    BOOST_TEST(c.meta.propose(put).error == "SlowDown");

    c.nodes[1]->down = false;
    r = s.sweep();
    BOOST_TEST(r.deleted == 1U);
    BOOST_TEST(c.held_by(gone[0].sha) == 0U);
    BOOST_TEST((c.meta.refcount(gone[0].sha)->state == chunk_state::deleted));

    // Once the deletion is past the clock allowance, the bytes can be
    // written and referenced again.
    c.now += chunk_clock_skew_ms;
    const auto again = c.put("again", 4, 10 * 1024);
    BOOST_TEST((again[0].sha == gone[0].sha));
    BOOST_TEST(c.held_by(gone[0].sha) == 3U);
    BOOST_TEST((c.meta.refcount(gone[0].sha)->state == chunk_state::live));
}

BOOST_AUTO_TEST_CASE(a_store_that_lost_everything_is_refilled_from_the_others) {
    cluster c;
    const auto a = c.put("a", 5);
    const auto b = c.put("b", 6);
    c.open_store(2);  // an empty disk in place of n2's
    BOOST_TEST(c.held_by(a[0].sha) == 2U);
    auto s = c.sweeper();
    const auto r = s.sweep();
    BOOST_TEST(r.repaired == a.size() + b.size());
    BOOST_TEST(r.repair_failures == 0U);
    for (const auto& ref : a) {
        BOOST_TEST(c.held_by(ref.sha) == 3U);
    }
    for (const auto& ref : b) {
        BOOST_TEST(c.held_by(ref.sha) == 3U);
    }
    BOOST_TEST(s.sweep().repaired == 0U);
}

BOOST_AUTO_TEST_CASE(a_node_that_does_not_list_is_neither_repaired_nor_counted) {
    cluster c;
    const auto a = c.put("a", 8);
    c.open_store(2);
    c.nodes[2]->down = true;
    auto s = c.sweeper();
    const auto r = s.sweep();
    BOOST_TEST(r.unreachable_nodes == 1U);
    BOOST_TEST(r.repaired == 0U);
    BOOST_TEST(r.repair_failures == 0U);
    BOOST_TEST(c.held_by(a[0].sha) == 2U);
}

BOOST_AUTO_TEST_CASE(listings_page_across_nodes_in_hash_order) {
    cluster c;
    std::vector<chunk_ref> all;
    for (std::uint32_t i = 0; i < 7; ++i) {
        const auto m = c.put("k" + std::to_string(i), 100 + i, 10 * 1024);
        all.insert(all.end(), m.begin(), m.end());
    }
    c.open_store(1);
    sweep_options o;
    o.batch = 2;  // several pages a node
    auto s = c.sweeper(o);
    const auto r = s.sweep();
    BOOST_TEST(r.chunks_listed == 2 * all.size());
    BOOST_TEST(r.repaired == all.size());
    BOOST_TEST(r.orphans_seen == 0U);
}

BOOST_AUTO_TEST_CASE(the_grace_period_must_outlast_the_longest_write) {
    local_metadata meta;
    sweep_options o;
    o.grace_ms = 60'000;
    o.max_write_ms = 60'000;
    const auto nodes = [] { return std::vector<const chunk_inventory*>{}; };
    const auto placement = [](const chunk_sha&) { return chunk_placement{}; };
    BOOST_CHECK_THROW(chunk_sweeper<local_metadata>(meta, nodes, placement, o),
                      std::invalid_argument);
    o.grace_ms = 60'000 + chunk_clock_skew_ms + 1;
    BOOST_CHECK_NO_THROW(chunk_sweeper<local_metadata>(meta, nodes, placement, o));
}
