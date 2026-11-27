// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file append_sink_unit_test.cpp
/// @brief `append_sink_persistence` (.kiro/specs/khold-block-service/ task 3,
///        Requirement 7.4): the log stores descriptors, the sink holds the
///        payloads, reads give the full entries back, one durable point covers
///        both, and recovery drops descriptors a crash left without payloads.
///
/// The sink here models a block store with a page cache: `on_append` puts the
/// payload in a volatile map, `sync()` moves everything to a durable map, and
/// `crash()` throws the volatile map away. The wrapped engine records every
/// call into the same journal as the sink, so the ordering claims (payload
/// synced before the descriptor is durable) are checked on the sequence of
/// calls, which is the only place they are observable.

#define BOOST_TEST_MODULE append_sink_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/append_sink.hpp>
#include <raft/persistence.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using entry_t = kythira::log_entry<std::uint64_t, std::uint64_t>;
using mem_engine = kythira::memory_persistence_engine<>;
using kythira::durability_class;
using kythira::entry_type;
using kythira::write_sequence;

constexpr std::byte descriptor_tag{0xDE};

auto payload(std::uint64_t index, std::size_t size) -> std::vector<std::byte> {
    std::vector<std::byte> p(size);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = std::byte{static_cast<std::uint8_t>((index * 31U) + i)};
    }
    return p;
}

auto entry(std::uint64_t index, std::uint64_t term = 1, std::size_t size = 64,
           entry_type type = entry_type::normal) -> entry_t {
    return {._term = term, ._index = index, ._command = payload(index, size), ._type = type};
}

// The descriptor this sink stores: a tag and the payload's size. A real
// sink (khold) stores the LBA range and CRCs.
auto is_descriptor(const entry_t& e) -> bool {
    return e.command().size() == 2 && e.command()[0] == descriptor_tag;
}

struct journal {
    std::vector<std::string> _calls;
    auto add(std::string c) -> void { _calls.push_back(std::move(c)); }
    [[nodiscard]] auto count(const std::string& c) const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count(_calls, c));
    }
    // Position of the last occurrence, or npos.
    [[nodiscard]] auto last(const std::string& c) const -> std::size_t {
        for (std::size_t i = _calls.size(); i > 0; --i) {
            if (_calls[i - 1] == c) {
                return i - 1;
            }
        }
        return std::string::npos;
    }
};

class test_sink {
public:
    explicit test_sink(std::shared_ptr<journal> j) : _journal(std::move(j)) {}

    auto on_append(const entry_t& e) -> entry_t {
        _journal->add("sink.append");
        if (is_descriptor(e)) {
            return e;
        }
        _volatile[e.index()] = e.command();
        entry_t d = e;
        d._command = {descriptor_tag, std::byte{static_cast<std::uint8_t>(e.command().size())}};
        return d;
    }
    auto has_payload(const entry_t& e) -> bool { return _durable.contains(e.index()); }
    auto rehydrate(const entry_t& e) -> std::optional<entry_t> {
        if (!is_descriptor(e)) {
            return e;
        }
        const auto* p = find(e.index());
        if (p == nullptr) {
            return std::nullopt;
        }
        entry_t full = e;
        full._command = *p;
        return full;
    }
    auto sync() -> void {
        _journal->add("sink.sync");
        for (auto& [i, p] : _volatile) {
            _durable[i] = std::move(p);
        }
        _volatile.clear();
    }
    auto on_truncate(std::uint64_t from) -> void {
        _journal->add("sink.truncate");
        _volatile.erase(_volatile.lower_bound(from), _volatile.end());
        _durable.erase(_durable.lower_bound(from), _durable.end());
    }
    auto release_before(std::uint64_t before) -> void {
        _journal->add("sink.release");
        _durable.erase(_durable.begin(), _durable.lower_bound(before));
    }

    // Loses every payload not yet synced, as a power cut would.
    auto crash() -> void { _volatile.clear(); }
    // Makes one volatile payload durable without a sync, as an out-of-order
    // page-cache writeback would.
    auto writeback(std::uint64_t index) -> void {
        if (auto it = _volatile.find(index); it != _volatile.end()) {
            _durable[index] = it->second;
            _volatile.erase(it);
        }
    }
    [[nodiscard]] auto payloads() const -> std::size_t {
        return _volatile.size() + _durable.size();
    }

private:
    [[nodiscard]] auto find(std::uint64_t i) const -> const std::vector<std::byte>* {
        if (auto it = _durable.find(i); it != _durable.end()) {
            return &it->second;
        }
        if (auto it = _volatile.find(i); it != _volatile.end()) {
            return &it->second;
        }
        return nullptr;
    }

    std::shared_ptr<journal> _journal;
    std::map<std::uint64_t, std::vector<std::byte>> _volatile;
    std::map<std::uint64_t, std::vector<std::byte>> _durable;
};

// A memory engine shared between "restarts", journaling the calls that
// matter for ordering. Barriered (answering `durability`) and bulk, like
// the memory engine it wraps.
class recording_engine {
public:
    using log_entry_t = mem_engine::log_entry_t;
    using snapshot_t = mem_engine::snapshot_t;

    recording_engine(std::shared_ptr<mem_engine> e, std::shared_ptr<journal> j,
                     durability_class d = durability_class::barrier)
        : _e(std::move(e)), _journal(std::move(j)), _durability(d) {}

    auto save_current_term(std::uint64_t t) -> void { _e->save_current_term(t); }
    auto load_current_term() -> std::uint64_t { return _e->load_current_term(); }
    auto save_voted_for(std::uint64_t n) -> void { _e->save_voted_for(n); }
    auto load_voted_for() -> std::optional<std::uint64_t> { return _e->load_voted_for(); }
    auto append_log_entry(const log_entry_t& e) -> void {
        check_fail();
        _journal->add("engine.append");
        _e->append_log_entry(e);
    }
    auto append_log_entries(std::span<const log_entry_t> es) -> void {
        check_fail();
        _journal->add("engine.bulk");
        _e->append_log_entries(es);
    }
    auto append_log_entry_sequenced(const log_entry_t& e) -> write_sequence {
        check_fail();
        _journal->add("engine.append");
        return _e->append_log_entry_sequenced(e);
    }
    auto barrier_through(write_sequence s) -> void {
        _journal->add("engine.barrier");
        _e->barrier_through(s);
    }
    [[nodiscard]] auto durable_through() const -> write_sequence { return _e->durable_through(); }
    [[nodiscard]] auto durability() const -> durability_class { return _durability; }
    auto get_log_entry(std::uint64_t i) -> std::optional<log_entry_t> {
        return _e->get_log_entry(i);
    }
    auto get_log_entries(std::uint64_t a, std::uint64_t b) -> std::vector<log_entry_t> {
        return _e->get_log_entries(a, b);
    }
    auto get_last_log_index() -> std::uint64_t { return _e->get_last_log_index(); }
    auto truncate_log(std::uint64_t i) -> void { _e->truncate_log(i); }
    auto save_snapshot(const snapshot_t& s) -> void { _e->save_snapshot(s); }
    auto load_snapshot() -> std::optional<snapshot_t> { return _e->load_snapshot(); }
    auto delete_log_entries_before(std::uint64_t i) -> void { _e->delete_log_entries_before(i); }

    bool _fail_next{false};

private:
    auto check_fail() -> void {
        if (_fail_next) {
            _fail_next = false;
            throw std::runtime_error("injected append failure");
        }
    }
    std::shared_ptr<mem_engine> _e;
    std::shared_ptr<journal> _journal;
    durability_class _durability;
};

// An engine with only the base concept: appends are durable on return.
class plain_engine {
public:
    using log_entry_t = mem_engine::log_entry_t;
    using snapshot_t = mem_engine::snapshot_t;
    explicit plain_engine(std::shared_ptr<journal> j) : _journal(std::move(j)) {}
    auto save_current_term(std::uint64_t t) -> void { _e.save_current_term(t); }
    auto load_current_term() -> std::uint64_t { return _e.load_current_term(); }
    auto save_voted_for(std::uint64_t n) -> void { _e.save_voted_for(n); }
    auto load_voted_for() -> std::optional<std::uint64_t> { return _e.load_voted_for(); }
    auto append_log_entry(const log_entry_t& e) -> void {
        _journal->add("engine.append");
        _e.append_log_entry(e);
    }
    auto get_log_entry(std::uint64_t i) -> std::optional<log_entry_t> {
        return _e.get_log_entry(i);
    }
    auto get_log_entries(std::uint64_t a, std::uint64_t b) -> std::vector<log_entry_t> {
        return _e.get_log_entries(a, b);
    }
    auto get_last_log_index() -> std::uint64_t { return _e.get_last_log_index(); }
    auto truncate_log(std::uint64_t i) -> void { _e.truncate_log(i); }
    auto save_snapshot(const snapshot_t& s) -> void { _e.save_snapshot(s); }
    auto load_snapshot() -> std::optional<snapshot_t> { return _e.load_snapshot(); }
    auto delete_log_entries_before(std::uint64_t i) -> void { _e.delete_log_entries_before(i); }

private:
    mem_engine _e;
    std::shared_ptr<journal> _journal;
};

using sinking = kythira::append_sink_persistence<recording_engine, test_sink>;
using plain_sinking = kythira::append_sink_persistence<plain_engine, test_sink>;

struct fixture {
    std::shared_ptr<journal> j = std::make_shared<journal>();
    std::shared_ptr<mem_engine> store = std::make_shared<mem_engine>();
    std::shared_ptr<test_sink> sink = std::make_shared<test_sink>(j);

    auto make(durability_class d = durability_class::barrier) -> sinking {
        return sinking{recording_engine{store, j, d}, sink};
    }
};

}  // namespace

// The adaptor is a persistence engine, and has each extension exactly when
// the wrapped engine does.
static_assert(kythira::persistence_engine<sinking, std::uint64_t, std::uint64_t, std::uint64_t,
                                          entry_t, mem_engine::snapshot_t>);
static_assert(kythira::barriered_persistence_engine<sinking>);
static_assert(kythira::bulk_append_persistence_engine<sinking>);
static_assert(kythira::persistence_engine<plain_sinking, std::uint64_t, std::uint64_t,
                                          std::uint64_t, entry_t, mem_engine::snapshot_t>);
static_assert(!kythira::barriered_persistence_engine<plain_sinking>);
static_assert(!kythira::bulk_append_persistence_engine<plain_sinking>);
static_assert(!kythira::hard_state_persistence_engine<plain_sinking>);
static_assert(kythira::hard_state_persistence_engine<
              kythira::append_sink_persistence<mem_engine, test_sink>>);
static_assert(kythira::append_sink<test_sink, entry_t, std::uint64_t>);

BOOST_AUTO_TEST_SUITE(append_sink)

BOOST_FIXTURE_TEST_CASE(the_log_stores_descriptors_and_reads_give_full_entries, fixture) {
    auto p = make();
    for (std::uint64_t i = 1; i <= 5; ++i) {
        p.append_log_entry(entry(i, 1, 100 + i));
    }
    for (std::uint64_t i = 1; i <= 5; ++i) {
        const auto stored = store->get_log_entry(i);
        BOOST_REQUIRE(stored.has_value());
        BOOST_TEST(is_descriptor(*stored));
        BOOST_TEST(stored->term() == 1U);
        const auto read = p.get_log_entry(i);
        BOOST_REQUIRE(read.has_value());
        BOOST_TEST((read->command() == payload(i, 100 + i)));
    }
    const auto run = p.get_log_entries(2, 4);
    BOOST_REQUIRE(run.size() == 3U);
    for (const auto& e : run) {
        BOOST_TEST((e.command() == payload(e.index(), 100 + e.index())));
    }
    BOOST_TEST(p.get_last_log_index() == 5U);
    BOOST_TEST(!p.get_log_entry(6).has_value());
}

BOOST_FIXTURE_TEST_CASE(entries_other_than_normal_bypass_the_sink, fixture) {
    auto p = make();
    for (auto type : {entry_type::configuration, entry_type::no_op, entry_type::split,
                      entry_type::merge_commit}) {
        const auto i = p.get_last_log_index() + 1;
        p.append_log_entry(entry(i, 1, 40, type));
        const auto stored = store->get_log_entry(i);
        BOOST_REQUIRE(stored.has_value());
        BOOST_TEST((stored->command() == payload(i, 40)));
        BOOST_TEST((stored->type() == type));
    }
    BOOST_TEST(j->count("sink.append") == 0U);
    BOOST_TEST(sink->payloads() == 0U);
}

BOOST_FIXTURE_TEST_CASE(a_barrier_syncs_the_sink_before_the_log, fixture) {
    auto p = make(durability_class::barrier);
    write_sequence seq{};
    for (std::uint64_t i = 1; i <= 8; ++i) {
        seq = p.append_log_entry_sequenced(entry(i));
    }
    // A group commit: no sync per append, one sync then one barrier.
    BOOST_TEST(j->count("sink.sync") == 0U);
    p.barrier_through(seq);
    BOOST_TEST(j->count("sink.sync") == 1U);
    BOOST_TEST(j->last("sink.sync") < j->last("engine.barrier"));
    BOOST_TEST((p.durability() == durability_class::barrier));
}

BOOST_FIXTURE_TEST_CASE(a_synchronous_engine_gets_the_payload_synced_before_each_append, fixture) {
    auto p = make(durability_class::synchronous);
    (void)p.append_log_entry_sequenced(entry(1));
    p.append_log_entry(entry(2));
    BOOST_TEST(j->count("sink.sync") == 2U);
    // Every descriptor append follows a sync of the payload it describes.
    for (std::size_t i = 0; i < j->_calls.size(); ++i) {
        if (j->_calls[i] == "engine.append") {
            BOOST_REQUIRE(i > 0);
            BOOST_TEST(j->_calls[i - 1] == "sink.sync");
        }
    }
}

BOOST_FIXTURE_TEST_CASE(an_engine_without_a_barrier_syncs_before_each_append, fixture) {
    plain_sinking p{plain_engine{j}, sink};
    p.append_log_entry(entry(1));
    p.append_log_entry(entry(2, 1, 10, entry_type::no_op));
    BOOST_TEST(j->count("sink.sync") == 1U);
    BOOST_TEST(j->last("sink.sync") < j->last("engine.append"));
    BOOST_TEST((p.get_log_entry(1)->command() == payload(1, 64)));
}

BOOST_FIXTURE_TEST_CASE(a_bulk_run_takes_one_sync_when_appends_are_durable, fixture) {
    auto p = make(durability_class::synchronous);
    std::vector<entry_t> run;
    for (std::uint64_t i = 1; i <= 6; ++i) {
        run.push_back(entry(i, 2, 30, i == 3 ? entry_type::no_op : entry_type::normal));
    }
    p.append_log_entries(run);
    BOOST_TEST(j->count("sink.append") == 5U);
    BOOST_TEST(j->count("sink.sync") == 1U);
    BOOST_TEST(j->last("sink.sync") < j->last("engine.bulk"));
    BOOST_TEST((store->get_log_entry(3)->command() == payload(3, 30)));
    BOOST_TEST(is_descriptor(*store->get_log_entry(4)));
    for (const auto& e : p.get_log_entries(1, 6)) {
        BOOST_TEST((e.command() == payload(e.index(), 30)));
    }
}

BOOST_FIXTURE_TEST_CASE(a_refused_append_leaves_no_payload_behind, fixture) {
    sinking p{recording_engine{store, j}, sink};
    p.append_log_entry(entry(1));
    p.engine()._fail_next = true;
    BOOST_CHECK_THROW(p.append_log_entry(entry(2)), std::runtime_error);
    BOOST_TEST(sink->payloads() == 1U);

    p.engine()._fail_next = true;
    std::vector<entry_t> run{entry(2), entry(3)};
    BOOST_CHECK_THROW(p.append_log_entries(run), std::runtime_error);
    BOOST_TEST(sink->payloads() == 1U);
    BOOST_TEST(p.get_last_log_index() == 1U);
}

BOOST_FIXTURE_TEST_CASE(truncation_and_compaction_reach_the_sink, fixture) {
    auto p = make();
    for (std::uint64_t i = 1; i <= 10; ++i) {
        p.append_log_entry(entry(i));
    }
    p.truncate_log(7);
    BOOST_TEST(p.get_last_log_index() == 6U);
    BOOST_TEST(sink->payloads() == 6U);
    // A new leader's entries at the overwritten indices carry new payloads.
    p.append_log_entry(entry(7, 2, 9));
    BOOST_TEST((p.get_log_entry(7)->command() == payload(7, 9)));
    p.barrier_through(p.durable_through());
    p.delete_log_entries_before(4);
    BOOST_TEST(j->count("sink.release") == 1U);
    BOOST_TEST(sink->payloads() == 4U);
    BOOST_TEST((p.get_log_entry(5)->command() == payload(5, 64)));
}

BOOST_FIXTURE_TEST_CASE(recovery_drops_descriptors_whose_payload_a_crash_lost, fixture) {
    {
        auto p = make();
        write_sequence seq{};
        for (std::uint64_t i = 1; i <= 4; ++i) {
            seq = p.append_log_entry_sequenced(entry(i));
        }
        p.barrier_through(seq);  // 1-4 acknowledged
        for (std::uint64_t i = 5; i <= 9; ++i) {
            (void)p.append_log_entry_sequenced(entry(i));
        }
        BOOST_TEST(!p.recovered_from().has_value());
    }
    // Before the power cut, writeback reached 5 and 8 but not 6, 7 or 9:
    // a present payload above a missing one.
    sink->writeback(5);
    sink->writeback(8);
    sink->crash();

    auto restarted = make();
    BOOST_REQUIRE(restarted.recovered_from().has_value());
    BOOST_TEST(*restarted.recovered_from() == 6U);
    BOOST_TEST(restarted.get_last_log_index() == 5U);
    for (std::uint64_t i = 1; i <= 5; ++i) {
        BOOST_TEST((restarted.get_log_entry(i)->command() == payload(i, 64)));
    }
    // Every acknowledged entry survived.
    BOOST_TEST(sink->payloads() == 5U);
}

BOOST_FIXTURE_TEST_CASE(a_lost_payload_under_a_held_descriptor_is_reported, fixture) {
    auto p = make();
    p.append_log_entry(entry(1));
    p.barrier_through(p.durable_through());
    sink->release_before(2);  // a sink that drops what the log still holds
    BOOST_CHECK_THROW((void)p.get_log_entry(1), kythira::persistence_exception);
}

BOOST_FIXTURE_TEST_CASE(a_sink_that_changes_an_entrys_identity_is_refused, fixture) {
    class renumbering_sink : public test_sink {
    public:
        using test_sink::test_sink;
        auto on_append(const entry_t& e) -> entry_t {
            auto d = test_sink::on_append(e);
            d._index += 1;
            return d;
        }
    };
    kythira::append_sink_persistence<recording_engine, renumbering_sink> p{
        recording_engine{store, j}, std::make_shared<renumbering_sink>(j)};
    BOOST_CHECK_THROW(p.append_log_entry(entry(1)), std::logic_error);
    BOOST_TEST(p.get_last_log_index() == 0U);
    BOOST_CHECK_THROW((sinking{recording_engine{store, j}, nullptr}), std::invalid_argument);
}

// Random appends, truncations, barriers and crashes against a model: after
// every crash and restart, the log is exactly the acknowledged prefix plus
// whatever unacknowledged suffix kept all its payloads, and every entry
// reads back with its own payload.
BOOST_AUTO_TEST_CASE(random_crash_schedules_keep_every_acknowledged_entry) {
    std::mt19937_64 rng(0x6b686f6c64ULL);
    for (int round = 0; round < 200; ++round) {
        fixture f;
        std::uint64_t acknowledged = 0;
        std::uint64_t term = 1;
        std::map<std::uint64_t, std::size_t> sizes;  // index -> payload size
        auto p = std::make_unique<sinking>(f.make());
        for (int step = 0; step < 60; ++step) {
            const auto r = rng() % 10;
            const auto last = p->get_last_log_index();
            if (r < 6) {
                const auto size = static_cast<std::size_t>(1 + (rng() % 200));
                (void)p->append_log_entry_sequenced(entry(last + 1, term, size));
                sizes[last + 1] = size;
            } else if (r < 7 && last > acknowledged) {
                // A new leader overwrites unacknowledged entries only.
                const auto from = acknowledged + 1 + (rng() % (last - acknowledged));
                p->truncate_log(from);
                sizes.erase(sizes.lower_bound(from), sizes.end());
                ++term;
            } else if (r < 9) {
                p->barrier_through(p->durable_through());
                acknowledged = p->get_last_log_index();
            } else {
                for (std::uint64_t i = acknowledged + 1; i <= last; ++i) {
                    if (rng() % 2 == 0) {
                        f.sink->writeback(i);
                    }
                }
                f.sink->crash();
                p.reset();
                p = std::make_unique<sinking>(f.make());
                const auto now = p->get_last_log_index();
                BOOST_REQUIRE(now >= acknowledged);
                sizes.erase(sizes.upper_bound(now), sizes.end());
                for (std::uint64_t i = 1; i <= now; ++i) {
                    BOOST_TEST(f.sink->has_payload(*f.store->get_log_entry(i)));
                }
            }
            for (const auto& [i, size] : sizes) {
                const auto e = p->get_log_entry(i);
                BOOST_REQUIRE(e.has_value());
                BOOST_REQUIRE((e->command() == payload(i, size)));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
