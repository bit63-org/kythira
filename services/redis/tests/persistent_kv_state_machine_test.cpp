// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// persistent-state-machine task 2: the Redis command set on a kv_engine,
// checked against the in-memory redis_kv_state_machine as the oracle, plus
// atomic apply, replay, crash recovery, checkpoints, split and merge.

#include <raft/memory_kv_engine.hpp>
#include <kythira/redis/persistent_kv_state_machine.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>

#define BOOST_TEST_MODULE persistent_kv_state_machine_test
#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <random>
#include <string>
#include <vector>

using kythira::column_family;
using kythira::key_range;
using kythira::memory_kv_engine;
using kythira::persistent_kv_state_machine;
using kythira::redis_kv_command;
using kythira::redis_kv_state_machine;

namespace {

using psm = persistent_kv_state_machine<memory_kv_engine>;
using oracle = redis_kv_state_machine<std::uint64_t>;

static_assert(kythira::persistent_state_machine<psm>);
static_assert(kythira::persistent_splittable_state_machine<psm>);
static_assert(kythira::storage_kind_of<psm> == kythira::state_machine_storage::persistent);
static_assert(!kythira::state_machine<psm, std::uint64_t>);
static_assert(kythira::persistent_staged_state_machine<psm>);

class temp_dir {
public:
    temp_dir() {
        auto tmpl = (std::filesystem::temp_directory_path() / "kythira-pkv-XXXXXX").string();
        if (::mkdtemp(tmpl.data()) == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        _path = tmpl;
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return _path; }

private:
    std::filesystem::path _path;
};

auto bytes(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    std::memcpy(out.data(), s.data(), s.size());
    return out;
}

auto set(const std::string& k, const std::string& v, std::uint64_t expire = 0)
    -> std::vector<std::byte> {
    return kythira::encode_redis_kv_command(
        kythira::redis_kv_set_command{._key = k, ._value = bytes(v), ._expire_at_ms = expire});
}

auto del(const std::string& k) -> std::vector<std::byte> {
    return kythira::encode_redis_kv_command(kythira::redis_kv_del_command{._key = k});
}

const key_range k_everything{.start = "", .end = std::nullopt};

/// Every observable of the persistent machine equals the oracle's over the
/// key universe `keys`.
auto check_same(const psm& p, const oracle& o, const std::vector<std::string>& keys,
                std::uint64_t now_ms) -> void {
    for (const auto& k : keys) {
        const auto a = p.lookup(k);
        const auto b = o.lookup(k);
        BOOST_REQUIRE_MESSAGE((a == nullptr) == (b == nullptr), "presence of " << k);
        if (a != nullptr) {
            BOOST_REQUIRE_MESSAGE(a->_value == b->_value, "value of " << k);
            BOOST_REQUIRE_EQUAL(a->_expire_at_ms, b->_expire_at_ms);
        }
    }
    BOOST_REQUIRE_EQUAL(p.approximate_key_count(), o.approximate_key_count());
    BOOST_REQUIRE_EQUAL(p.approximate_size_bytes(), o.approximate_size_bytes());
    BOOST_REQUIRE_EQUAL(p.expiring_key_count(), o.expiring_key_count());
    const auto pe = p.collect_expired(now_ms, 1000);
    const auto oe = o.collect_expired(now_ms, 1000);
    BOOST_REQUIRE_EQUAL(pe.size(), oe.size());
    for (std::size_t i = 0; i < pe.size(); ++i) {
        BOOST_REQUIRE_EQUAL(pe[i]._key, oe[i]._key);
        BOOST_REQUIRE_EQUAL(pe[i]._expire_at_ms, oe[i]._expire_at_ms);
    }
    BOOST_REQUIRE_EQUAL(p.suggest_split_keys(3).size(),
                        const_cast<oracle&>(o).suggest_split_keys(3).size());
}

/// A random command over a small key universe, so sets, deletes, sweeps
/// and evictions keep hitting the same keys.
auto random_command(std::mt19937_64& rng, const std::vector<std::string>& keys, const oracle& o)
    -> std::vector<std::byte> {
    auto pick = [&] { return keys[rng() % keys.size()]; };
    switch (rng() % 8) {
        case 0:
        case 1:
        case 2: {
            const auto expire = (rng() % 3 == 0) ? 1000 + rng() % 100 : 0;
            return set(pick(), std::string(rng() % 40, static_cast<char>('a' + rng() % 26)),
                       expire);
        }
        case 3:
            return del(pick());
        case 4: {
            // A sweep built from the oracle's view, plus a stale entry.
            auto entries = o.collect_expired(1050, 3);
            entries.push_back({pick(), 1000 + rng() % 100});
            entries.push_back(entries.front());  // a key named twice
            return kythira::encode_redis_kv_command(
                kythira::redis_kv_sweep_command{._entries = entries});
        }
        case 5: {
            const auto k = pick();
            return kythira::encode_redis_kv_command(
                kythira::redis_kv_evict_command{._keys = {k, pick(), k}});
        }
        case 6:
            return kythira::encode_redis_kv_command(
                kythira::redis_kv_touch_command{._keys = {pick()}});
        default:
            return kythira::encode_redis_kv_command(kythira::redis_kv_put_chunk_command{
                ._key = pick(), ._sha = {}, ._bytes = bytes("chunk")});
    }
}

auto key_universe() -> std::vector<std::string> {
    std::vector<std::string> keys;
    for (char c = 'a'; c <= 'p'; ++c) {
        keys.emplace_back(std::string("key-") + c);
    }
    keys.emplace_back("");  // the empty key is a legal Redis key
    return keys;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(oracle_equivalence)

BOOST_AUTO_TEST_CASE(random_workloads_match_the_in_memory_machine) {
    const auto keys = key_universe();
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
        std::mt19937_64 rng(seed);
        memory_kv_engine engine;
        psm p("ns/");
        p.open(engine, k_everything);
        oracle o;
        for (std::uint64_t index = 1; index <= 150; ++index) {
            const auto cmd = random_command(rng, keys, o);
            const auto rp = p.apply(cmd, index);
            const auto ro = o.apply(cmd, index);
            BOOST_REQUIRE_MESSAGE(rp == ro, "reply differs at seed " << seed << " index " << index);
            BOOST_REQUIRE_EQUAL(p.applied_index(), index);
        }
        check_same(p, o, keys, 1050);

        // A restart reads back exactly the same machine.
        psm reopened("ns/");
        reopened.open(engine, k_everything);
        BOOST_REQUIRE_EQUAL(reopened.applied_index(), 150U);
        check_same(reopened, o, keys, 1050);
    }
}

BOOST_AUTO_TEST_CASE(for_each_key_visits_keys_in_order_without_the_namespace) {
    memory_kv_engine engine;
    psm p("tenant/");
    p.open(engine, k_everything);
    p.apply(set("b", "2"), 1);
    p.apply(set("a", "1", 99), 2);
    std::vector<std::string> seen;
    p.for_each_key([&](const std::string& k, const kythira::redis_kv_value_entry& e) {
        seen.push_back(
            k + "=" + std::string(reinterpret_cast<const char*>(e._value.data()), e._value.size()));
    });
    BOOST_TEST((seen == std::vector<std::string>{"a=1", "b=2"}));
    BOOST_TEST(engine.get(column_family::data, "tenant/a").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(atomic_apply_and_replay)

BOOST_AUTO_TEST_CASE(replay_at_or_below_applied_index_changes_nothing) {
    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    p.apply(set("k", "v1"), 1);
    p.apply(set("k", "v2"), 2);
    const auto seq = engine.latest_sequence();
    // A replay of entry 1 must not put v1 back.
    BOOST_TEST((p.apply(set("k", "v1"), 1) == std::vector<std::byte>{std::byte{0}}));
    BOOST_TEST((p.apply(del("k"), 2) == std::vector<std::byte>{std::byte{0}}));
    BOOST_TEST(engine.latest_sequence() == seq);
    BOOST_TEST((p.lookup("k")->_value == bytes("v2")));
    BOOST_TEST(p.applied_index() == 2U);
}

BOOST_AUTO_TEST_CASE(each_apply_is_one_batch_with_the_applied_index) {
    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    const auto before = engine.latest_sequence();
    p.apply(kythira::encode_redis_kv_command(kythira::redis_kv_evict_command{._keys = {"x", "y"}}),
            1);
    p.apply(set("x", "1"), 2);
    BOOST_TEST(engine.latest_sequence() == before + 2);
    // A no-op entry still records its index.
    psm reopened;
    reopened.open(engine, k_everything);
    BOOST_TEST(reopened.applied_index() == 2U);
}

// Requirement 8.1: a transactional wrapper stages several commands of one
// entry into one batch. Later commands see earlier ones, the counters carry
// across them, and the engine sees one write.
BOOST_AUTO_TEST_CASE(staged_commands_share_one_batch_and_see_each_other) {
    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    p.apply(set("a", "old"), 1);
    const auto before = engine.latest_sequence();

    kythira::write_batch batch;
    BOOST_TEST((p.stage(set("b", "1"), batch) == std::vector<std::byte>{std::byte{1}}));
    BOOST_TEST((p.stage(del("a"), batch) == std::vector<std::byte>{std::byte{1}}));
    // "a" is already deleted in this entry, so a second delete changes
    // nothing.
    BOOST_TEST((p.stage(del("a"), batch) == std::vector<std::byte>{std::byte{0}}));
    BOOST_TEST(engine.latest_sequence() == before);
    p.commit_staged(batch, 2);

    BOOST_TEST(engine.latest_sequence() == before + 1);
    BOOST_TEST(p.applied_index() == 2U);
    BOOST_TEST(p.approximate_key_count() == 1U);
    BOOST_TEST(!p.lookup("a"));
    psm reopened;
    reopened.open(engine, k_everything);
    BOOST_TEST(reopened.approximate_key_count() == 1U);
    BOOST_TEST(reopened.applied_index() == 2U);
}

BOOST_AUTO_TEST_CASE(discarded_stages_leave_nothing) {
    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    p.apply(set("a", "1"), 1);
    kythira::write_batch batch;
    std::ignore = p.stage(del("a"), batch);
    p.discard_staged();
    // A fresh entry reads the engine again, not the discarded delete.
    BOOST_TEST((p.apply(del("a"), 2) == std::vector<std::byte>{std::byte{1}}));
    BOOST_TEST(p.approximate_key_count() == 0U);
}

BOOST_AUTO_TEST_CASE(crash_loses_only_undurable_batches_and_replay_restores_them) {
    const auto keys = key_universe();
    std::mt19937_64 rng(7);
    std::vector<std::vector<std::byte>> log;
    oracle o;
    for (std::uint64_t i = 1; i <= 60; ++i) {
        log.push_back(random_command(rng, keys, o));
        o.apply(log.back(), i);
    }

    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    for (std::uint64_t i = 1; i <= 20; ++i) {
        p.apply(log[i - 1], i);
    }
    BOOST_TEST(p.durable_applied_index() == 20U);

    engine.hold_durability();
    for (std::uint64_t i = 21; i <= 45; ++i) {
        p.apply(log[i - 1], i);
    }
    BOOST_TEST(p.applied_index() == 45U);
    BOOST_TEST(p.durable_applied_index() == 20U);  // log compaction must stop here

    // Make part of the held writes durable: entries up to 30.
    p.apply(log[45], 46);
    engine.sync(engine.durable_sequence() + 10);
    BOOST_TEST(p.durable_applied_index() == 30U);

    engine.simulate_crash();
    psm recovered;
    recovered.open(engine, k_everything);
    BOOST_TEST(recovered.applied_index() == 30U);
    BOOST_TEST(recovered.durable_applied_index() == 30U);

    // The node replays from applied_index() + 1, and from further back too:
    // the overlap is harmless.
    for (std::uint64_t i = 25; i <= 60; ++i) {
        recovered.apply(log[i - 1], i);
    }
    check_same(recovered, o, keys, 1050);
}

// The node asks for this before compacting when the durable index lags
// (raft_configuration::_persistent_sync_lag_entries). Without it, on an
// engine that syncs only when asked (RocksDB), the durable index never
// moved and a gateway on engine storage never compacted its log: the
// engine chaos scenario's bulk load found it.
BOOST_AUTO_TEST_CASE(sync_durable_makes_every_applied_batch_durable) {
    memory_kv_engine engine;
    psm p;
    p.open(engine, k_everything);
    p.sync_durable();  // nothing applied yet: a no-op
    engine.hold_durability();
    for (std::uint64_t i = 1; i <= 12; ++i) {
        p.apply(set("k" + std::to_string(i), "v"), i);
    }
    BOOST_TEST(p.durable_applied_index() == 0U);
    p.sync_durable();
    BOOST_TEST(p.durable_applied_index() == 12U);

    engine.simulate_crash();
    psm recovered;
    recovered.open(engine, k_everything);
    BOOST_TEST(recovered.applied_index() == 12U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ranges_and_movement)

BOOST_AUTO_TEST_CASE(checkpoint_and_ingest_move_a_group_between_engines) {
    temp_dir tmp;
    const key_range shard{.start = "g", .end = std::string("p")};
    memory_kv_engine leader_engine;
    psm leader("ns/");
    leader.open(leader_engine, shard);
    oracle o;
    std::uint64_t index = 0;
    for (const auto* k : {"g", "h1", "h2", "m", "o"}) {
        ++index;
        leader.apply(set(k, std::string(k) + "-value", index % 2 == 0 ? 1001 : 0), index);
        o.apply(set(k, std::string(k) + "-value", index % 2 == 0 ? 1001 : 0), index);
    }
    ++index;
    leader.apply(del("h2"), index);
    o.apply(del("h2"), index);

    const auto manifest = leader.checkpoint(tmp.path() / "cp");

    // The follower's engine already holds another group below the shard and
    // stale keys of its own inside it.
    memory_kv_engine follower_engine;
    psm neighbour("ns/");
    neighbour.open(follower_engine, key_range{.start = "a", .end = std::string("g")});
    neighbour.apply(set("b", "neighbour"), 1);
    psm follower("ns/");
    follower.open(follower_engine, shard);
    follower.apply(set("n-stale", "x"), 1);

    follower.ingest(tmp.path() / "cp", manifest, index);
    BOOST_TEST(follower.applied_index() == index);
    check_same(follower, o, {"g", "h1", "h2", "m", "o", "n-stale"}, 1050);
    BOOST_TEST(follower.lookup("n-stale") == nullptr);
    BOOST_TEST((neighbour.lookup("b")->_value == bytes("neighbour")));

    psm reopened("ns/");
    reopened.open(follower_engine, shard);
    BOOST_TEST(reopened.applied_index() == index);
    BOOST_TEST(reopened.approximate_key_count() == o.approximate_key_count());
}

BOOST_AUTO_TEST_CASE(split_moves_no_keys_and_adopt_undoes_it) {
    memory_kv_engine engine;
    psm parent("ns/");
    parent.open(engine, k_everything);
    oracle o;
    const std::vector<std::string> keys{"a", "c", "e", "g", "i", "k"};
    std::uint64_t index = 0;
    for (const auto& k : keys) {
        ++index;
        parent.apply(set(k, k + k, k == "e" ? 77 : 0), index);
        o.apply(set(k, k + k, k == "e" ? 77 : 0), index);
    }
    const auto writes_before = engine.latest_sequence();

    const auto children = parent.split_at({"g", "d"});
    BOOST_REQUIRE_EQUAL(children.size(), 2U);
    BOOST_TEST(children[0].start == "d");
    BOOST_TEST((children[0].end == std::optional<std::string>("g")));
    BOOST_TEST(children[1].start == "g");
    BOOST_TEST(!children[1].end.has_value());
    BOOST_TEST(engine.latest_sequence() == writes_before + 1);  // one batch
    BOOST_TEST(parent.approximate_key_count() == 2U);           // a, c

    psm middle("ns/");
    middle.open(engine, children[0]);
    psm upper("ns/");
    upper.open(engine, children[1]);
    BOOST_TEST(middle.applied_index() == index);
    BOOST_TEST(upper.applied_index() == index);
    BOOST_TEST(middle.approximate_key_count() == 1U);  // e
    BOOST_TEST(middle.expiring_key_count() == 1U);
    BOOST_TEST(upper.approximate_key_count() == 3U);  // g, i, k
    BOOST_TEST(parent.approximate_size_bytes() + middle.approximate_size_bytes() +
                   upper.approximate_size_bytes() ==
               o.approximate_size_bytes());
    BOOST_TEST(parent.lookup("a") != nullptr);
    BOOST_TEST(upper.lookup("k") != nullptr);

    // Merge back: middle adopts upper, then parent adopts middle.
    middle.adopt(children[1]);
    middle.adopt(children[1]);  // idempotent
    BOOST_TEST(!engine.get(column_family::meta, "ns/g").has_value());
    parent.adopt(middle.range());
    BOOST_TEST(!engine.get(column_family::meta, "ns/d").has_value());
    BOOST_TEST(!parent.range().end.has_value());
    BOOST_TEST(parent.approximate_key_count() == o.approximate_key_count());
    BOOST_TEST(parent.approximate_size_bytes() == o.approximate_size_bytes());
    BOOST_TEST(parent.expiring_key_count() == o.expiring_key_count());

    // A range that is not adjacent on either side is refused.
    psm lone("other/");
    lone.open(engine, key_range{.start = "a", .end = std::string("b")});
    BOOST_CHECK_THROW(lone.adopt(key_range{.start = "c", .end = std::string("d")}),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(adopt_from_below_moves_the_meta_record_to_the_new_start) {
    memory_kv_engine engine;
    psm parent("ns/");
    parent.open(engine, k_everything);
    parent.apply(set("a", "aa"), 1);
    parent.apply(set("m", "mm"), 2);
    parent.apply(set("x", "xx"), 3);
    const auto children = parent.split_at({"k"});
    BOOST_REQUIRE_EQUAL(children.size(), 1U);

    // The upper child absorbs the parent's range below it, as a merge whose
    // target is the right-hand group does.
    psm upper("ns/");
    upper.open(engine, children[0]);
    upper.apply(set("y", "yy"), 4);
    upper.adopt(parent.range());
    upper.adopt(parent.range());  // idempotent
    BOOST_TEST(upper.range().start == "");
    BOOST_TEST(!upper.range().end.has_value());
    BOOST_TEST(!engine.get(column_family::meta, "ns/k").has_value());
    BOOST_TEST(upper.approximate_key_count() == 4U);
    BOOST_TEST(upper.lookup("a") != nullptr);

    // The record now lives at the new start and carries the target's index.
    psm reopened("ns/");
    reopened.open(engine, upper.range());
    BOOST_TEST(reopened.applied_index() == 4U);
    BOOST_TEST(reopened.approximate_key_count() == 4U);
}

BOOST_AUTO_TEST_CASE(namespaces_keep_hosts_apart_and_drop_is_scoped) {
    memory_kv_engine engine;
    psm one("host-1/");
    psm two("host-2/");
    one.open(engine, k_everything);
    two.open(engine, k_everything);
    one.apply(set("k", "one"), 1);
    two.apply(set("k", "two"), 1);
    two.apply(set("only-two", "x"), 2);
    BOOST_TEST((one.lookup("k")->_value == bytes("one")));
    BOOST_TEST(one.lookup("only-two") == nullptr);
    BOOST_TEST(one.approximate_key_count() == 1U);

    one.drop();
    BOOST_TEST(one.lookup("k") == nullptr);
    BOOST_TEST(one.applied_index() == 0U);
    BOOST_TEST((two.lookup("k")->_value == bytes("two")));
    psm reopened("host-2/");
    reopened.open(engine, k_everything);
    BOOST_TEST(reopened.applied_index() == 2U);
}

BOOST_AUTO_TEST_CASE(use_before_open_is_refused) {
    psm p;
    BOOST_CHECK_THROW(p.apply(set("k", "v"), 1), std::logic_error);
    BOOST_CHECK_THROW((void)p.lookup("k"), std::logic_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ---- typed values (redis-general-data-types task 10) -----------------------

namespace {

using kythira::redis_command_id;

const std::string k_max_bytes = "1000000";
const std::string k_max_count = "100000";

auto gate() -> std::vector<std::byte> {
    return kythira::encode_redis_kv_command(kythira::redis_kv_format_gate_command{"", 3});
}

auto exec(redis_command_id id, std::vector<std::string> args, std::uint64_t now = 1000)
    -> std::vector<std::byte> {
    kythira::redis_kv_exec_command c;
    c._key = args.empty() ? "" : args[0];
    c._command_id = static_cast<std::uint16_t>(id);
    c._now_ms = now;
    c._args = std::move(args);
    return kythira::encode_redis_kv_command(c);
}

/// A value's type, deadline and elements, in a form two stores can compare.
auto describe(const kythira::redis_kv_value_entry& e) -> std::string {
    std::string out = std::string(kythira::redis_value_type_name(kythira::redis_entry_type(e))) +
                      "@" + std::to_string(e._expire_at_ms) + ":";
    switch (kythira::redis_entry_type(e)) {
        case kythira::redis_value_type::string:
            out.append(reinterpret_cast<const char*>(e._value.data()), e._value.size());
            break;
        case kythira::redis_value_type::hash:
            e._hash->for_each(
                [&](const std::string& f, const std::string& v) { out += f + "=" + v + ","; });
            out += "#" + std::to_string(e._hash->bytes());
            break;
        case kythira::redis_value_type::set:
            e._set->for_each([&](const std::string& m) { out += m + ","; });
            out += "#" + std::to_string(e._set->bytes());
            break;
        case kythira::redis_value_type::list:
            e._list->visit(0, e._list->size() - 1, [&](std::size_t, const std::string& v) {
                out += v + ",";
                return true;
            });
            out += "#" + std::to_string(e._list->bytes());
            break;
    }
    return out;
}

auto listing(const psm& p) -> std::vector<std::string> {
    std::vector<std::string> out;
    p.for_each_key([&](const std::string& k, const kythira::redis_kv_value_entry& e) {
        out.push_back(k + "->" + describe(e));
    });
    return out;
}

auto listing(const oracle& o) -> std::vector<std::string> {
    std::vector<std::string> out;
    o.for_each_key([&](const std::string& k, const kythira::redis_kv_value_entry& e) {
        out.push_back(k + "->" + describe(e));
    });
    return out;
}

auto check_same_typed(const psm& p, const oracle& o, const std::vector<std::string>& keys,
                      std::uint64_t now_ms) -> void {
    for (const auto& k : keys) {
        const auto a = p.lookup(k);
        const auto b = o.lookup(k);
        BOOST_REQUIRE_MESSAGE((a == nullptr) == (b == nullptr), "presence of "
                                                                    << k << ": " << (a != nullptr)
                                                                    << " vs " << (b != nullptr));
        if (a != nullptr) {
            BOOST_REQUIRE_EQUAL(describe(*a), describe(*b));
        }
    }
    BOOST_REQUIRE(listing(p) == listing(o));
    BOOST_REQUIRE_EQUAL(p.approximate_key_count(), o.approximate_key_count());
    BOOST_REQUIRE_EQUAL(p.approximate_size_bytes(), o.approximate_size_bytes());
    BOOST_REQUIRE_EQUAL(p.expiring_key_count(), o.expiring_key_count());
    BOOST_REQUIRE_EQUAL(p.format_level(), o.format_level());
    BOOST_REQUIRE_EQUAL(p.applied_time_ms(), o.applied_time_ms());
    const auto pe = p.collect_expired(now_ms, 1000);
    const auto oe = o.collect_expired(now_ms, 1000);
    BOOST_REQUIRE_EQUAL(pe.size(), oe.size());
    for (std::size_t i = 0; i < pe.size(); ++i) {
        BOOST_REQUIRE_EQUAL(pe[i]._key, oe[i]._key);
        BOOST_REQUIRE_EQUAL(pe[i]._expire_at_ms, oe[i]._expire_at_ms);
    }
}

/// Keys with NUL bytes next to their prefixes, so escaping is exercised
/// between neighbours.
auto typed_universe() -> std::vector<std::string> {
    return {
        "",  "a", std::string("a\0", 2), std::string("a\0b", 3), std::string("a\0\xFF", 3), "ab",
        "b", "c"};
}

/// A random typed or string write, in the front end's normal forms.
auto random_typed_command(std::mt19937_64& rng, const std::vector<std::string>& keys,
                          const oracle& o, std::uint64_t now) -> std::vector<std::byte> {
    auto pick = [&] { return keys[rng() % keys.size()]; };
    auto item = [&] { return std::string(1, static_cast<char>('a' + rng() % 12)); };
    auto items = [&](std::vector<std::string> args) {
        const auto n = 1 + rng() % 4;
        for (std::size_t i = 0; i < n; ++i) {
            args.push_back(item());
        }
        return args;
    };
    const auto side = [&] { return rng() % 2 == 0 ? std::string("LEFT") : std::string("RIGHT"); };
    switch (rng() % 24) {
        case 0:
            return exec(redis_command_id::set, {pick(), item() + item()}, now);
        case 1:
        case 2: {
            std::vector<std::string> args{pick(), k_max_bytes, k_max_count};
            const auto n = 1 + rng() % 3;
            for (std::size_t i = 0; i < n; ++i) {
                args.push_back(item());
                args.push_back(item() + item());
            }
            return exec(redis_command_id::hset, std::move(args), now);
        }
        case 3:
            return exec(redis_command_id::hdel, items({pick()}), now);
        case 4:
            return exec(redis_command_id::hincrby, {pick(), k_max_bytes, k_max_count, "n", "3"},
                        now);
        case 5:
        case 6:
            return exec(redis_command_id::sadd, items({pick(), k_max_bytes, k_max_count}), now);
        case 7:
            return exec(redis_command_id::srem, items({pick()}), now);
        case 8:
            return exec(redis_command_id::spop, items({pick(), "1"}), now);
        case 9: {
            const auto src = pick();
            const auto dst = pick();
            return exec(redis_command_id::smove, {src, dst, k_max_bytes, k_max_count, item()}, now);
        }
        case 10: {
            const auto dst = pick();
            const auto a = pick();
            const auto b = pick();
            return exec(redis_command_id::sunionstore, {dst, k_max_bytes, k_max_count, a, b}, now);
        }
        case 11:
            return exec(redis_command_id::lpush, items({pick(), k_max_bytes, k_max_count}), now);
        case 12:
            return exec(redis_command_id::rpush, items({pick(), k_max_bytes, k_max_count}), now);
        case 13:
            return exec(rng() % 2 == 0 ? redis_command_id::lpop : redis_command_id::rpop,
                        {pick(), "1", std::to_string(1 + rng() % 3)}, now);
        case 14: {
            const auto k = pick();
            return exec(redis_command_id::lset,
                        {k, std::to_string(static_cast<int>(rng() % 7) - 3), item(), k_max_bytes},
                        now);
        }
        case 15: {
            const auto k = pick();
            const auto where = rng() % 2 == 0 ? std::string("BEFORE") : std::string("AFTER");
            const auto pivot = item();
            return exec(redis_command_id::linsert,
                        {k, where, pivot, item(), k_max_bytes, k_max_count}, now);
        }
        case 16: {
            const auto k = pick();
            return exec(redis_command_id::lrem,
                        {k, std::to_string(static_cast<int>(rng() % 5) - 2), item()}, now);
        }
        case 17: {
            const auto k = pick();
            const auto start = std::to_string(rng() % 3);
            return exec(redis_command_id::ltrim,
                        {k, start, std::to_string(static_cast<int>(rng() % 8) - 2)}, now);
        }
        case 18: {
            const auto src = pick();
            const auto dst = pick();
            const auto from = side();
            const auto to = side();
            return exec(redis_command_id::lmove, {src, dst, from, to, k_max_bytes, k_max_count},
                        now);
        }
        case 19: {
            const auto k = pick();
            return exec(redis_command_id::pexpireat, {k, std::to_string(now + 5 + rng() % 40)},
                        now);
        }
        case 20:
            return exec(redis_command_id::persist, {pick()}, now);
        case 21: {
            const auto src = pick();
            const auto dst = pick();
            return rng() % 2 == 0 ? exec(redis_command_id::rename, {src, dst}, now)
                                  : exec(redis_command_id::copy, {src, dst, "REPLACE"}, now);
        }
        case 22:
            return del(pick());
        default: {
            auto entries = o.collect_expired(now, 3);
            if (entries.empty()) {
                return exec(redis_command_id::del, {pick(), pick()}, now);
            }
            return kythira::encode_redis_kv_command(
                kythira::redis_kv_sweep_command{._entries = entries});
        }
    }
}

}  // namespace

BOOST_AUTO_TEST_SUITE(typed_values)

BOOST_AUTO_TEST_CASE(typed_workloads_match_the_in_memory_machine) {
    const auto keys = typed_universe();
    for (std::uint64_t seed = 1; seed <= 25; ++seed) {
        std::mt19937_64 rng(seed);
        memory_kv_engine engine;
        auto p = std::make_unique<psm>("ns/");
        p->open(engine, k_everything);
        oracle o;
        std::uint64_t index = 0;
        // A few strings before the gate, NUL keys among them, so the gate
        // has keys to escape.
        for (const auto& k : keys) {
            if (rng() % 2 == 0) {
                ++index;
                BOOST_REQUIRE(p->apply(set(k, "v" + k), index) == o.apply(set(k, "v" + k), index));
            }
        }
        ++index;
        BOOST_REQUIRE(p->apply(gate(), index) == o.apply(gate(), index));
        check_same_typed(*p, o, keys, 0);
        std::uint64_t now = 1000;
        for (int step = 0; step < 400; ++step) {
            now += rng() % 4;
            const auto cmd = random_typed_command(rng, keys, o, now);
            ++index;
            const auto rp = p->apply(cmd, index);
            const auto ro = o.apply(cmd, index);
            BOOST_REQUIRE_MESSAGE(rp == ro, "reply differs at seed " << seed << " step " << step);
            if (step % 40 == 39) {
                check_same_typed(*p, o, keys, now);
                // A restart decodes every collection from its rows again.
                p = std::make_unique<psm>("ns/");
                p->open(engine, k_everything);
                check_same_typed(*p, o, keys, now);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(an_element_write_rewrites_one_row_and_the_header) {
    memory_kv_engine engine;
    psm p("ns/");
    p.open(engine, k_everything);
    std::uint64_t index = 0;
    p.apply(gate(), ++index);
    std::vector<std::string> fields{"h", k_max_bytes, k_max_count};
    std::vector<std::string> members{"s", k_max_bytes, k_max_count};
    std::vector<std::string> elements{"l", k_max_bytes, k_max_count};
    for (int i = 0; i < 500; ++i) {
        fields.push_back("f" + std::to_string(i));
        fields.push_back("v");
        members.push_back("m" + std::to_string(i));
        elements.push_back("e" + std::to_string(i));
    }
    p.apply(exec(redis_command_id::hset, fields), ++index);
    p.apply(exec(redis_command_id::sadd, members), ++index);
    p.apply(exec(redis_command_id::rpush, elements), ++index);

    const auto ops_of = [&](std::vector<std::byte> cmd) {
        kythira::write_batch batch;
        (void)p.stage(cmd, batch);
        p.commit_staged(batch, ++index);
        return batch.operations().size() - 1;  // less the meta record
    };
    BOOST_TEST(ops_of(exec(redis_command_id::hset, {"h", k_max_bytes, k_max_count, "f7", "w"})) ==
               2U);
    BOOST_TEST(ops_of(exec(redis_command_id::hdel, {"h", "f9"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::sadd, {"s", k_max_bytes, k_max_count, "new"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::lpush, {"l", k_max_bytes, k_max_count, "x"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::rpush, {"l", k_max_bytes, k_max_count, "y"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::lpop, {"l", "0", "1"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::rpop, {"l", "0", "1"})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::lset, {"l", "250", "z", k_max_bytes})) == 2U);
    BOOST_TEST(ops_of(exec(redis_command_id::pexpireat, {"l", "999999"})) == 1U);

    // And every one of those reads back.
    psm reopened("ns/");
    reopened.open(engine, k_everything);
    const auto l = reopened.lookup("l");
    BOOST_REQUIRE(l != nullptr);
    BOOST_TEST(l->_list->size() == 500U);
    BOOST_TEST(l->_list->at(0) == "e0");
    BOOST_TEST(l->_list->at(250) == "z");
    BOOST_TEST(l->_expire_at_ms == 999999U);
    BOOST_TEST(*reopened.lookup("h")->_hash->find("f7") == "w");
    BOOST_TEST(reopened.lookup("h")->_hash->find("f9") == nullptr);
    BOOST_TEST(reopened.lookup("s")->_set->contains("new"));
}

BOOST_AUTO_TEST_CASE(the_gate_escapes_nul_keys_and_a_newer_reader_is_needed_after_it) {
    memory_kv_engine engine;
    psm p("ns/");
    p.open(engine, k_everything);
    const std::string nul_key("a\0b", 3);
    p.apply(set(nul_key, "x"), 1);
    p.apply(set("c", "y"), 2);
    BOOST_TEST(engine.get(column_family::data, "ns/" + nul_key).has_value());
    const auto meta_before = engine.get(column_family::meta, "ns/");
    BOOST_REQUIRE(meta_before.has_value());
    BOOST_TEST(meta_before->size() == 32U);  // as every earlier build wrote it

    p.apply(gate(), 3);
    BOOST_TEST(p.format_level() == 3U);
    BOOST_TEST(!engine.get(column_family::data, "ns/" + nul_key).has_value());
    BOOST_TEST(engine
                   .get(column_family::data, "ns/" + std::string("a\0\xFF"
                                                                 "b",
                                                                 4))
                   .has_value());
    BOOST_TEST((p.lookup(nul_key)->_value == bytes("x")));
    BOOST_TEST(engine.get(column_family::meta, "ns/")->size() == 48U);

    // A hash at "a" sorts its rows between "a" and the escaped "a\0b".
    p.apply(exec(redis_command_id::hset, {"a", k_max_bytes, k_max_count, "f", "v"}), 4);
    BOOST_TEST((p.lookup(nul_key)->_value == bytes("x")));
    BOOST_TEST((p.lookup("a")->_type == kythira::redis_value_type::hash));
    std::vector<std::string> keys;
    p.for_each_key(
        [&](const std::string& k, const kythira::redis_kv_value_entry&) { keys.push_back(k); });
    BOOST_TEST((keys == std::vector<std::string>{"a", nul_key, "c"}));

    // A restart keeps the level.
    psm reopened("ns/");
    reopened.open(engine, k_everything);
    BOOST_TEST(reopened.format_level() == 3U);
    BOOST_TEST(reopened.lookup("a")->_hash->size() == 1U);

    // A record of a newer format halts rather than being skipped.
    auto newer = gate();
    newer[0] = std::byte{0x09};
    BOOST_CHECK_THROW(reopened.apply(newer, 5), kythira::redis_format_too_new);
    BOOST_TEST(reopened.applied_index() == 4U);
}

BOOST_AUTO_TEST_CASE(a_typed_record_before_the_gate_is_refused) {
    memory_kv_engine engine;
    psm p("ns/");
    p.open(engine, k_everything);
    const auto reply =
        p.apply(exec(redis_command_id::sadd, {"s", k_max_bytes, k_max_count, "m"}), 1);
    BOOST_TEST(reply.size() == 1U);
    BOOST_TEST(static_cast<int>(reply[0]) ==
               static_cast<int>(kythira::redis_v3_apply_status::refused_before_gate));
    BOOST_TEST(p.lookup("s") == nullptr);
    BOOST_TEST(p.applied_index() == 1U);
}

BOOST_AUTO_TEST_CASE(nul_bounds_refuse_the_gate_and_splits_never_make_one) {
    memory_kv_engine engine;
    psm p("ns/");
    p.open(engine, key_range{.start = std::string("k\0", 2), .end = std::nullopt});
    p.apply(gate(), 1);
    BOOST_TEST(p.format_level() == 0U);  // refused: the bound has a NUL byte

    psm q("ns2/");
    q.open(engine, k_everything);
    q.apply(set("a", "1"), 1);
    q.apply(set(std::string("b\0", 2), "2"), 2);
    q.apply(set("c", "3"), 3);
    BOOST_TEST(!q.can_split_at(std::string("b\0", 2)));
    BOOST_TEST(q.can_split_at("b"));
    for (const auto& k : q.suggest_split_keys(5)) {
        BOOST_TEST(k.find('\0') == std::string::npos);
    }
    const auto children = q.split_at({std::string("b\0", 2), "c"});
    BOOST_REQUIRE_EQUAL(children.size(), 1U);
    BOOST_TEST(children[0].start == "c");
}

BOOST_AUTO_TEST_CASE(split_checkpoint_and_merge_carry_collections_whole) {
    memory_kv_engine engine;
    psm parent("ns/");
    parent.open(engine, k_everything);
    oracle o;
    std::uint64_t index = 0;
    const auto both = [&](const std::vector<std::byte>& cmd) {
        ++index;
        BOOST_REQUIRE(parent.apply(cmd, index) == o.apply(cmd, index));
    };
    both(gate());
    both(exec(redis_command_id::hset, {"b", k_max_bytes, k_max_count, "f", "1", "g", "2"}));
    both(exec(redis_command_id::rpush, {"m", k_max_bytes, k_max_count, "x", "y", "z"}));
    both(exec(redis_command_id::sadd, {"s", k_max_bytes, k_max_count, "p", "q"}));
    both(exec(redis_command_id::pexpireat, {"s", "50000"}));
    both(set("z", "zz"));

    const auto children = parent.split_at({"m"});
    BOOST_REQUIRE_EQUAL(children.size(), 1U);
    psm upper("ns/");
    upper.open(engine, children[0]);
    BOOST_TEST(upper.format_level() == 3U);
    BOOST_TEST(upper.applied_time_ms() == parent.applied_time_ms());
    BOOST_TEST(parent.approximate_key_count() == 1U);  // b
    BOOST_TEST(upper.approximate_key_count() == 3U);   // m, s, z
    BOOST_TEST(upper.expiring_key_count() == 1U);
    BOOST_TEST(parent.approximate_size_bytes() + upper.approximate_size_bytes() ==
               o.approximate_size_bytes());
    BOOST_TEST(upper.lookup("m")->_list->size() == 3U);

    // The upper half moves to another engine whole.
    temp_dir dir;
    const auto manifest = upper.checkpoint(dir.path() / "cp");
    memory_kv_engine other;
    psm moved("ns/");
    moved.open(other, children[0]);
    moved.ingest(dir.path() / "cp", manifest, index);
    BOOST_TEST(moved.format_level() == 3U);
    BOOST_TEST(describe(*moved.lookup("m")) == describe(*o.lookup("m")));
    BOOST_TEST(describe(*moved.lookup("s")) == describe(*o.lookup("s")));
    BOOST_TEST(moved.approximate_size_bytes() == upper.approximate_size_bytes());

    // Merging back restores the whole machine.
    parent.adopt(children[0]);
    check_same_typed(parent, o, typed_universe(), 60000);
    for (const auto& k : {"b", "m", "s", "z"}) {
        BOOST_TEST(describe(*parent.lookup(k)) == describe(*o.lookup(k)));
    }
}

BOOST_AUTO_TEST_CASE(merging_an_untyped_group_into_a_typed_one_escapes_its_keys) {
    memory_kv_engine engine;
    psm parent("ns/");
    parent.open(engine, k_everything);
    const std::string nul_key("q\0", 2);
    parent.apply(set("a", "1"), 1);
    parent.apply(set(nul_key, "2"), 2);
    const auto children = parent.split_at({"m"});
    BOOST_REQUIRE_EQUAL(children.size(), 1U);
    // Only the lower half passes its gate.
    parent.apply(gate(), 3);
    parent.apply(exec(redis_command_id::sadd, {"b", k_max_bytes, k_max_count, "x"}), 4);
    BOOST_TEST(parent.format_level() == 3U);

    parent.adopt(children[0]);
    BOOST_TEST(parent.format_level() == 3U);
    BOOST_TEST((parent.lookup(nul_key)->_value == bytes("2")));
    BOOST_TEST(parent.approximate_key_count() == 3U);
    psm reopened("ns/");
    reopened.open(engine, k_everything);
    BOOST_TEST((reopened.lookup(nul_key)->_value == bytes("2")));
    BOOST_TEST(reopened.lookup("b")->_set->contains("x"));
}

BOOST_AUTO_TEST_SUITE_END()
