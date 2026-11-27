// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file redis_kv_mvcc_state_machine_test.cpp
/// @brief The multi-version Redis KV (task 11 of
///        `.kiro/specs/multi-raft-transactions/`, Requirements 8.1 and 8.6).
///
/// Version reads, versioned deletes and expiry, garbage collection keeping
/// the newest version at or below the safe point, the snapshot round trip,
/// and the split/absorb law. The randomized cases check every read against a
/// plain model: a list of `(ts, key, value-or-deletion)` writes.

#define BOOST_TEST_MODULE redis_kv_mvcc_state_machine_test
#include <boost/test/unit_test.hpp>

#include <kythira/redis/redis_kv_mvcc_state_machine.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

using namespace kythira;

BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<std::uint64_t>)

namespace {

using sm_type = redis_kv_mvcc_state_machine<std::uint64_t>;

auto bytes_of(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<std::byte>(s[i]);
    }
    return out;
}

auto set_cmd(const std::string& k, const std::string& v, std::uint64_t exp = 0) {
    return encode_redis_kv_command(redis_kv_set_command{k, bytes_of(v), exp});
}

auto del_cmd(const std::string& k) {
    return encode_redis_kv_command(redis_kv_del_command{k});
}

auto text(const sm_type::entry_handle& h) -> std::string {
    if (!h) {
        return "<none>";
    }
    return std::string(reinterpret_cast<const char*>(h->_value.data()),
                       h->_value.size());  // NOLINT
}

auto at(const sm_type& sm, const std::string& k, std::uint64_t ts) -> std::string {
    return text(sm.read_at(k, ts));
}

/// The model: every write, in apply order.
struct model_write {
    std::uint64_t _ts;
    std::string _key;
    std::optional<std::string> _value;
};

auto model_read(const std::vector<model_write>& writes, const std::string& key, std::uint64_t ts)
    -> std::string {
    std::optional<std::uint64_t> best_ts;
    std::string out = "<none>";
    for (const auto& w : writes) {
        if (w._key != key || w._ts > ts) {
            continue;
        }
        if (!best_ts || w._ts >= *best_ts) {
            best_ts = w._ts;
            out = w._value.value_or("<none>");
        }
    }
    return out;
}

/// Random writes at increasing timestamps over a small key space, applied to
/// `sm` and recorded in the model. A delete of an absent key is not
/// recorded, since it writes no version.
auto random_history(sm_type& sm, std::mt19937& rng, int n) -> std::vector<model_write> {
    std::vector<model_write> writes;
    std::uniform_int_distribution<int> key(0, 7);
    std::uniform_int_distribution<int> op(0, 3);
    std::uniform_int_distribution<int> step(1, 3);
    std::uint64_t ts = 10;
    for (int i = 0; i < n; ++i) {
        ts += static_cast<std::uint64_t>(step(rng));
        const auto k = "k" + std::to_string(key(rng));
        if (op(rng) == 0) {
            if (sm.lookup(k)) {
                writes.push_back({ts, k, std::nullopt});
            }
            sm.apply_at(del_cmd(k), ts);
        } else {
            const auto v = "v" + std::to_string(i);
            writes.push_back({ts, k, v});
            sm.apply_at(set_cmd(k, v), ts);
        }
    }
    return writes;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_kv_mvcc)

BOOST_AUTO_TEST_CASE(reads_see_the_newest_version_at_or_below_their_timestamp,
                     *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "one"), 10);
    sm.apply_at(set_cmd("a", "two"), 20);
    sm.apply_at(del_cmd("a"), 30);
    sm.apply_at(set_cmd("a", "four"), 40);

    BOOST_TEST(at(sm, "a", 9) == "<none>");
    BOOST_TEST(at(sm, "a", 10) == "one");
    BOOST_TEST(at(sm, "a", 19) == "one");
    BOOST_TEST(at(sm, "a", 20) == "two");
    BOOST_TEST(at(sm, "a", 30) == "<none>");
    BOOST_TEST(at(sm, "a", 39) == "<none>");
    BOOST_TEST(at(sm, "a", 1000) == "four");
    BOOST_TEST(text(sm.lookup("a")) == "four");
    BOOST_TEST(sm.latest_commit_ts("a") == std::optional<std::uint64_t>(40));
    BOOST_TEST(!sm.latest_commit_ts("b").has_value());
    BOOST_TEST(sm.version_count() == 4U);
    BOOST_TEST(sm.max_commit_ts() == 40U);
}

BOOST_AUTO_TEST_CASE(a_deletion_is_a_version, *boost::unit_test::timeout(10)) {
    sm_type sm;
    // Deleting an absent key writes nothing and changes nothing.
    BOOST_TEST((sm.apply_at(del_cmd("a"), 5) == std::vector<std::byte>{std::byte{0}}));
    BOOST_TEST(!sm.latest_commit_ts("a").has_value());

    sm.apply_at(set_cmd("a", "x"), 10);
    BOOST_TEST((sm.apply_at(del_cmd("a"), 20) == std::vector<std::byte>{std::byte{1}}));
    BOOST_TEST(sm.latest_commit_ts("a") == std::optional<std::uint64_t>(20));
    BOOST_TEST(!sm.lookup("a"));
    BOOST_TEST(sm.approximate_key_count() == 0U);
    // The old value is still there for a snapshot below the deletion.
    BOOST_TEST(at(sm, "a", 15) == "x");
}

BOOST_AUTO_TEST_CASE(a_write_at_an_existing_timestamp_replaces_it, *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "x"), 10);
    sm.apply_at(set_cmd("a", "y"), 10);
    BOOST_TEST(sm.version_count() == 1U);
    BOOST_TEST(at(sm, "a", 10) == "y");
    BOOST_TEST(sm.approximate_size_bytes() == 2U);  // "a" + "y"
}

BOOST_AUTO_TEST_CASE(versions_out_of_order_are_placed_by_timestamp,
                     *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "late"), 30);
    sm.apply_at(set_cmd("a", "early"), 10);
    BOOST_TEST(at(sm, "a", 20) == "early");
    BOOST_TEST(at(sm, "a", 30) == "late");
    BOOST_TEST(sm.latest_commit_ts("a") == std::optional<std::uint64_t>(30));
    BOOST_TEST(sm.max_commit_ts() == 30U);
}

// `apply` without a timestamp lands at the newest one applied.
BOOST_AUTO_TEST_CASE(plain_apply_lands_at_the_newest_timestamp, *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply(set_cmd("a", "zero"), 1);
    BOOST_TEST(sm.latest_commit_ts("a") == std::optional<std::uint64_t>(0));
    sm.apply_at(set_cmd("b", "x"), 50, 2);
    BOOST_TEST(sm.last_applied_index() == 2U);
    sm.apply(set_cmd("a", "fifty"), 3);
    BOOST_TEST(sm.last_applied_index() == 3U);
    BOOST_TEST(sm.latest_commit_ts("a") == std::optional<std::uint64_t>(50));
    BOOST_TEST(at(sm, "a", 49) == "zero");
    BOOST_TEST(at(sm, "a", 50) == "fifty");
}

// Expiry is a versioned deletion at the sweep's timestamp.
BOOST_AUTO_TEST_CASE(a_sweep_deletes_at_its_timestamp_if_the_deadline_matches,
                     *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "x", 1000), 10);
    sm.apply_at(set_cmd("b", "y", 2000), 10);
    BOOST_TEST(sm.expiring_key_count() == 2U);
    const auto expired = sm.collect_expired(1500, 10);
    BOOST_REQUIRE(expired.size() == 1U);
    BOOST_TEST(expired[0]._key == "a");

    // "b" was rewritten with a new deadline after the sweep was built.
    sm.apply_at(set_cmd("b", "y2", 9000), 15);
    sm.apply_at(
        encode_redis_kv_command(redis_kv_sweep_command{{{"a", 1000}, {"b", 2000}, {"missing", 5}}}),
        20);
    BOOST_TEST(at(sm, "a", 20) == "<none>");
    BOOST_TEST(at(sm, "a", 19) == "x");
    BOOST_TEST(at(sm, "b", 20) == "y2");
    BOOST_TEST(sm.expiring_key_count() == 1U);
}

BOOST_AUTO_TEST_CASE(evict_writes_deletions, *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "x"), 10);
    sm.apply_at(set_cmd("b", "y"), 10);
    sm.apply_at(encode_redis_kv_command(redis_kv_evict_command{{"a", "zz"}}), 20);
    BOOST_TEST(!sm.lookup("a"));
    BOOST_TEST(text(sm.lookup("b")) == "y");
    BOOST_TEST(at(sm, "a", 10) == "x");
}

// Requirement 8.6: the newest version at or below the safe point is kept.
BOOST_AUTO_TEST_CASE(garbage_collection_keeps_the_newest_at_or_below_the_safe_point,
                     *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "one"), 10);
    sm.apply_at(set_cmd("a", "two"), 20);
    sm.apply_at(set_cmd("a", "three"), 30);
    sm.apply_at(set_cmd("gone", "x"), 10);
    sm.apply_at(del_cmd("gone"), 20);
    sm.apply_at(set_cmd("back", "x"), 10);
    sm.apply_at(del_cmd("back"), 20);
    sm.apply_at(set_cmd("back", "y"), 30);

    const auto dropped = sm.collect_garbage(25);
    // a: "one" goes. gone: "x" and its deletion go. back: "x" goes; the
    // deletion at 20 stays, since "y" is newer than the safe point.
    BOOST_TEST(dropped == 4U);
    BOOST_TEST(sm.versions_of("a").size() == 2U);
    BOOST_TEST(at(sm, "a", 25) == "two");
    BOOST_TEST(at(sm, "a", 30) == "three");
    BOOST_TEST(sm.versions_of("gone").empty());
    BOOST_TEST(!sm.latest_commit_ts("gone").has_value());
    BOOST_TEST(sm.versions_of("back").size() == 2U);
    BOOST_TEST(at(sm, "back", 25) == "<none>");
    BOOST_TEST(at(sm, "back", 30) == "y");

    // Idempotent, and the counters match a rebuilt copy.
    BOOST_TEST(sm.collect_garbage(25) == 0U);
    sm_type copy;
    copy.restore_from_snapshot(sm.get_state(), 0);
    BOOST_TEST(copy.approximate_size_bytes() == sm.approximate_size_bytes());
    BOOST_TEST(copy.version_count() == sm.version_count());
    BOOST_TEST(copy.approximate_key_count() == sm.approximate_key_count());
}

// Every read against the model, before and after garbage collection.
BOOST_AUTO_TEST_CASE(reads_match_the_model_and_gc_keeps_reads_above_the_safe_point,
                     *boost::unit_test::timeout(30)) {
    for (unsigned seed = 1; seed <= 25; ++seed) {
        std::mt19937 rng(seed);
        sm_type sm;
        const auto writes = random_history(sm, rng, 200);
        const auto max_ts = writes.empty() ? 0 : writes.back()._ts + 5;
        for (std::uint64_t ts = 0; ts <= max_ts; ++ts) {
            for (int k = 0; k < 8; ++k) {
                const auto key = "k" + std::to_string(k);
                BOOST_TEST_CONTEXT("seed " << seed << " key " << key << " ts " << ts) {
                    BOOST_TEST(at(sm, key, ts) == model_read(writes, key, ts));
                }
            }
        }

        const std::uint64_t safe_point = max_ts / 2;
        const auto before = sm.version_count();
        const auto dropped = sm.collect_garbage(safe_point);
        BOOST_TEST(sm.version_count() == before - dropped);
        for (std::uint64_t ts = safe_point; ts <= max_ts; ++ts) {
            for (int k = 0; k < 8; ++k) {
                const auto key = "k" + std::to_string(k);
                BOOST_TEST_CONTEXT("after gc, seed " << seed << " key " << key << " ts " << ts) {
                    BOOST_TEST(at(sm, key, ts) == model_read(writes, key, ts));
                }
            }
        }
        // At most one version per key at or below the safe point survives.
        for (int k = 0; k < 8; ++k) {
            std::size_t old = 0;
            for (const auto& v : sm.versions_of("k" + std::to_string(k))) {
                old += v._commit_ts <= safe_point ? 1 : 0;
            }
            BOOST_TEST(old <= 1U);
        }
    }
}

BOOST_AUTO_TEST_CASE(snapshot_round_trip_keeps_every_version, *boost::unit_test::timeout(10)) {
    std::mt19937 rng(7);
    sm_type sm;
    (void)random_history(sm, rng, 100);
    sm.apply_at(set_cmd("exp", "x", 12345), sm.max_commit_ts() + 1);

    sm_type copy;
    copy.restore_from_snapshot(sm.get_state(), 99);
    BOOST_TEST(copy.get_state() == sm.get_state());
    BOOST_TEST(copy.last_applied_index() == 99U);
    BOOST_TEST(copy.max_commit_ts() == sm.max_commit_ts());
    BOOST_TEST(copy.approximate_size_bytes() == sm.approximate_size_bytes());
    BOOST_TEST(copy.approximate_key_count() == sm.approximate_key_count());
    BOOST_TEST(copy.expiring_key_count() == sm.expiring_key_count());
    BOOST_TEST(copy.version_count() == sm.version_count());
    BOOST_TEST(copy.lookup("exp")->_expire_at_ms == 12345U);
}

// The split/absorb law: absorbing every child of a split rebuilds the
// parent exactly, versions and newest timestamp included.
BOOST_AUTO_TEST_CASE(split_then_absorb_is_the_identity, *boost::unit_test::timeout(30)) {
    for (unsigned seed = 1; seed <= 20; ++seed) {
        std::mt19937 rng(seed);
        sm_type sm;
        (void)random_history(sm, rng, 120);
        std::vector<std::string> cuts{"k2", "k5"};
        if (seed % 2 == 0) {
            cuts = {"k6", "k1", "k6"};  // unsorted with a duplicate
        }
        const auto children = sm.split_state(cuts);
        BOOST_REQUIRE(children.size() == 3U);

        sm_type rebuilt;
        rebuilt.restore_from_snapshot(children.front(), 0);
        for (std::size_t i = 1; i < children.size(); ++i) {
            rebuilt.absorb(children[i], shard_range<std::string>{});
        }
        BOOST_TEST_CONTEXT("seed " << seed) {
            BOOST_TEST(rebuilt.get_state() == sm.get_state());
            BOOST_TEST(rebuilt.version_count() == sm.version_count());
            BOOST_TEST(rebuilt.approximate_size_bytes() == sm.approximate_size_bytes());
            BOOST_TEST(rebuilt.approximate_key_count() == sm.approximate_key_count());
        }

        // Each child holds only its own range's keys, with every version.
        sm_type left;
        left.restore_from_snapshot(children.front(), 0);
        left.for_each_key([&](const std::string& key, const redis_kv_value_entry&) {
            BOOST_TEST(key < (seed % 2 == 0 ? std::string{"k1"} : std::string{"k2"}));
        });
        BOOST_TEST(left.max_commit_ts() == sm.max_commit_ts());
    }
}

BOOST_AUTO_TEST_CASE(suggest_split_keys_never_returns_the_first_key,
                     *boost::unit_test::timeout(10)) {
    sm_type sm;
    for (int i = 0; i < 10; ++i) {
        sm.apply_at(set_cmd("key" + std::to_string(i), "v"), 10 + static_cast<std::uint64_t>(i));
    }
    const auto keys = sm.suggest_split_keys(3);
    BOOST_TEST(!keys.empty());
    for (const auto& k : keys) {
        BOOST_TEST(k != "key0");
    }
    BOOST_TEST(sm.can_split_at("anything"));
}

BOOST_AUTO_TEST_CASE(rejects_corrupt_snapshots, *boost::unit_test::timeout(10)) {
    sm_type sm;
    sm.apply_at(set_cmd("a", "x"), 10);
    sm.apply_at(set_cmd("a", "y"), 20);
    auto blob = sm.get_state();

    sm_type other;
    auto truncated = blob;
    truncated.pop_back();
    BOOST_CHECK_THROW(other.restore_from_snapshot(truncated, 0), redis_kv_codec_error);
    auto trailing = blob;
    trailing.push_back(std::byte{0});
    BOOST_CHECK_THROW(other.restore_from_snapshot(trailing, 0), redis_kv_codec_error);

    // Versions must be strictly newest first. Swap the two timestamps: the
    // first version's is at byte 8 + 4 + 4 + 1 + 4, the second follows its
    // 9-byte header and 8 + 4 + 1 bytes of value.
    auto bad = blob;
    const std::size_t first = 8 + 4 + 4 + 1 + 4;
    const std::size_t second = first + 8 + 1 + 8 + 4 + 1;
    for (std::size_t i = 0; i < 8; ++i) {
        std::swap(bad[first + i], bad[second + i]);
    }
    BOOST_CHECK_THROW(other.restore_from_snapshot(bad, 0), redis_kv_codec_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- typed values (redis-general-data-types task 11) -----------------------

namespace {

using mem_type = redis_kv_state_machine<std::uint64_t>;

const std::string k_max_bytes = "1000000";
const std::string k_max_count = "100000";

auto gate_cmd() -> std::vector<std::byte> {
    return encode_redis_kv_command(redis_kv_format_gate_command{"", 3});
}

auto exec_cmd(redis_command_id id, std::vector<std::string> args, std::uint64_t now = 1000)
    -> std::vector<std::byte> {
    redis_kv_exec_command c;
    c._key = args.empty() ? "" : args[0];
    c._command_id = static_cast<std::uint16_t>(id);
    c._now_ms = now;
    c._args = std::move(args);
    return encode_redis_kv_command(c);
}

/// A value's type, deadline and elements.
auto describe(const sm_type::entry_handle& h) -> std::string {
    if (!h) {
        return "<none>";
    }
    std::string out = std::string(redis_value_type_name(redis_entry_type(*h))) + "@" +
                      std::to_string(h->_expire_at_ms) + ":";
    switch (redis_entry_type(*h)) {
        case redis_value_type::string:
            out += text(h);
            break;
        case redis_value_type::hash:
            h->_hash->for_each(
                [&](const std::string& f, const std::string& v) { out += f + "=" + v + ","; });
            break;
        case redis_value_type::set:
            h->_set->for_each([&](const std::string& m) { out += m + ","; });
            break;
        case redis_value_type::list:
            h->_list->visit(0, h->_list->size() - 1, [&](std::size_t, const std::string& v) {
                out += v + ",";
                return true;
            });
            break;
    }
    return out;
}

auto random_typed(std::mt19937_64& rng, std::uint64_t now) -> std::vector<std::byte> {
    const std::vector<std::string> keys{"a", "b", "c", "d"};
    auto pick = [&] { return keys[rng() % keys.size()]; };
    auto item = [&] { return std::string(1, static_cast<char>('a' + rng() % 8)); };
    switch (rng() % 12) {
        case 0:
            return exec_cmd(redis_command_id::set, {pick(), item()}, now);
        case 1:
        case 2: {
            const auto k = pick();
            const auto f = item();
            return exec_cmd(redis_command_id::hset, {k, k_max_bytes, k_max_count, f, item()}, now);
        }
        case 3: {
            const auto k = pick();
            return exec_cmd(redis_command_id::hdel, {k, item()}, now);
        }
        case 4: {
            const auto k = pick();
            return exec_cmd(redis_command_id::sadd, {k, k_max_bytes, k_max_count, item()}, now);
        }
        case 5: {
            const auto k = pick();
            return exec_cmd(redis_command_id::srem, {k, item()}, now);
        }
        case 6: {
            const auto k = pick();
            return exec_cmd(redis_command_id::rpush, {k, k_max_bytes, k_max_count, item()}, now);
        }
        case 7: {
            const auto k = pick();
            return exec_cmd(redis_command_id::lpop, {k, "0", "1"}, now);
        }
        case 8: {
            const auto src = pick();
            const auto dst = pick();
            return exec_cmd(redis_command_id::rename, {src, dst}, now);
        }
        case 9: {
            const auto k = pick();
            return exec_cmd(redis_command_id::pexpireat, {k, std::to_string(now + rng() % 20)},
                            now);
        }
        case 10: {
            const auto k = pick();
            const auto dst = pick();
            return exec_cmd(redis_command_id::smove, {k, dst, k_max_bytes, k_max_count, item()},
                            now);
        }
        default:
            return del_cmd(pick());
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(redis_kv_mvcc_typed)

// The newest versions follow the single-version store exactly, and every
// older version stays readable at its own timestamp.
BOOST_AUTO_TEST_CASE(typed_writes_match_the_single_version_store_at_every_timestamp,
                     *boost::unit_test::timeout(60)) {
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        std::mt19937_64 rng(seed);
        sm_type sm;
        mem_type mem;
        (void)sm.apply_at(gate_cmd(), 1, 1);
        (void)mem.apply(gate_cmd(), 1);
        std::map<std::uint64_t, std::map<std::string, std::string>> seen;  // ts -> key -> value
        std::uint64_t now = 1000;
        for (std::uint64_t i = 2; i < 300; ++i) {
            now += rng() % 3;
            const auto cmd = random_typed(rng, now);
            const std::uint64_t ts = i * 10;
            BOOST_REQUIRE_MESSAGE(sm.apply_at(cmd, ts, i) == mem.apply(cmd, i),
                                  "reply differs at seed " << seed << " step " << i);
            for (const auto* k : {"a", "b", "c", "d"}) {
                seen[ts][k] = describe(mem.lookup(k));
                BOOST_REQUIRE_EQUAL(describe(sm.lookup(k)), seen[ts][k]);
            }
            BOOST_REQUIRE_EQUAL(sm.approximate_key_count(), mem.approximate_key_count());
            BOOST_REQUIRE_EQUAL(sm.expiring_key_count(), mem.expiring_key_count());
        }
        for (const auto& [ts, keys] : seen) {
            for (const auto& [k, v] : keys) {
                BOOST_REQUIRE_EQUAL(describe(sm.read_at(k, ts)), v);
            }
        }
        BOOST_REQUIRE_EQUAL(sm.applied_time_ms(), mem.applied_time_ms());

        // A snapshot and a split keep every version, the level and the time.
        sm_type restored;
        restored.restore_from_snapshot(sm.get_state(), 300);
        BOOST_REQUIRE(restored.get_state() == sm.get_state());
        BOOST_REQUIRE_EQUAL(restored.format_level(), 3U);
        const auto parts = sm.split_state({"c"});
        sm_type lower;
        lower.restore_from_snapshot(parts[0], 300);
        lower.absorb(parts[1], shard_range<std::string>{});
        BOOST_REQUIRE(lower.get_state() == sm.get_state());
        for (const auto& [ts, keys] : seen) {
            for (const auto& [k, v] : keys) {
                BOOST_REQUIRE_EQUAL(describe(restored.read_at(k, ts)), v);
            }
        }
    }
}

// One element write makes a version that shares every untouched chunk with
// the one before it; garbage collection frees the chunks only the dropped
// version held (Requirement 13.5).
BOOST_AUTO_TEST_CASE(versions_share_chunks_and_gc_frees_the_unshared_ones,
                     *boost::unit_test::timeout(30)) {
    sm_type sm;
    (void)sm.apply_at(gate_cmd(), 1, 1);
    std::vector<std::string> args{"h", k_max_bytes, k_max_count};
    for (int i = 0; i < 1000; ++i) {
        char field[8];
        std::snprintf(field, sizeof field, "f%04d", i);
        args.emplace_back(field);
        args.emplace_back("v");
    }
    (void)sm.apply_at(exec_cmd(redis_command_id::hset, args), 10, 2);
    (void)sm.apply_at(
        exec_cmd(redis_command_id::hset, {"h", k_max_bytes, k_max_count, "f0500", "w"}), 20, 3);
    std::weak_ptr<const redis_hash::chunk> replaced;
    std::weak_ptr<const redis_hash::chunk> kept;
    {
        // A copy of the version list holds references; it goes out of scope
        // before the collection.
        const auto versions = sm.versions_of("h");
        BOOST_REQUIRE_EQUAL(versions.size(), 2U);
        const auto& newer = versions[0]._entry->_hash->chunks();
        const auto& older = versions[1]._entry->_hash->chunks();
        BOOST_REQUIRE_EQUAL(newer.size(), older.size());
        std::size_t shared = 0;
        for (std::size_t i = 0; i < newer.size(); ++i) {
            if (newer[i] == older[i]) {
                ++shared;
            } else {
                replaced = older[i];
            }
        }
        BOOST_TEST(shared == newer.size() - 1);
        kept = newer.front();
    }
    BOOST_TEST(*sm.read_at("h", 15)->_hash->find("f0500") == "v");
    BOOST_TEST(*sm.read_at("h", 25)->_hash->find("f0500") == "w");
    BOOST_REQUIRE(!replaced.expired());
    BOOST_TEST(sm.collect_garbage(20) == 1U);
    BOOST_TEST(replaced.expired());  // only the old version held it
    BOOST_TEST(!kept.expired());
    BOOST_TEST(sm.version_count() == 1U);
}

BOOST_AUTO_TEST_CASE(a_typed_blob_needs_its_marker, *boost::unit_test::timeout(10)) {
    sm_type sm;
    (void)sm.apply_at(set_cmd("s", "v"), 5, 1);
    const auto before_gate = sm.get_state();
    (void)sm.apply_at(gate_cmd(), 6, 2);
    (void)sm.apply_at(exec_cmd(redis_command_id::sadd, {"t", k_max_bytes, k_max_count, "m"}), 7, 3);
    const auto blob = sm.get_state();
    BOOST_TEST(std::string(reinterpret_cast<const char*>(blob.data()), 4) == "KMV3");
    // Before any gate the blob is the earlier format, byte for byte.
    sm_type plain;
    (void)plain.apply_at(set_cmd("s", "v"), 5, 1);
    BOOST_TEST((plain.get_state() == before_gate));
    // A newer level halts the restore.
    auto newer = blob;
    newer[4] = std::byte{0};
    newer[5] = std::byte{k_redis_format_level + 1};
    sm_type other;
    BOOST_CHECK_THROW(other.restore_from_snapshot(newer, 3), redis_format_too_new);
}

BOOST_AUTO_TEST_SUITE_END()
