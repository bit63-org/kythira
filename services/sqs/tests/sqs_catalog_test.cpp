// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The queue catalog (`.kiro/specs/sqs-compatible-queues/` task 4,
// Requirements 4.1, 4.2): record and entry encodings; CreateQueue's
// idempotence on identical settings and refusal on others; fresh ids for a
// recreated queue and the deletion cooldown; compare-and-set settings
// changes; the tag cap; the purge cooldown; listing by prefix and token;
// catalog and partition entries in one log, surviving a restart; and the
// split veto keeping the catalog in one group. Runs on memory_kv_engine.

#define BOOST_TEST_MODULE sqs_catalog_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sqs = kythira::sqs;
using kythira::key_range;
using kythira::memory_kv_engine;

namespace {

using queue_sm = sqs::sqs_queue_state_machine<>;
using kind = sqs::catalog_command::kind;
using status = sqs::catalog_result::status;

const key_range k_all{"", std::nullopt};

auto bytes(const std::string& s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto text(const std::vector<std::byte>& b) -> std::string {
    std::string out;
    for (const auto c : b) {
        out.push_back(static_cast<char>(c));
    }
    return out;
}

struct replica {
    std::unique_ptr<memory_kv_engine> engine = std::make_unique<memory_kv_engine>();
    queue_sm sm;
    std::uint64_t index = 0;

    replica() { sm.open(*engine, k_all); }

    auto run(const sqs::catalog_command& c) -> sqs::catalog_result {
        auto r = sqs::decode_catalog_result(
            text(sm.apply(bytes(sqs::encode_catalog_command(c)), ++index)));
        BOOST_REQUIRE(r.has_value());
        return *r;
    }
};

auto command(kind op, const std::string& name, std::uint64_t now = 1'000) -> sqs::catalog_command {
    sqs::catalog_command c;
    c._op = op;
    c._account = "123456789012";
    c._name = name;
    c._now_ms = now;
    c._partitions = 4;
    return c;
}

auto create(const std::string& name, std::uint64_t now = 1'000) -> sqs::catalog_command {
    auto c = command(kind::create, name, now);
    c._cooldown_ms = 60'000;
    return c;
}

}  // namespace

BOOST_AUTO_TEST_CASE(records_and_entries_round_trip) {
    sqs::queue_record q;
    q._id = 7;
    q._account = "123456789012";
    q._name = "orders.fifo";
    q._settings._fifo = true;
    q._settings._policy = R"({"Statement":[]})";
    q._tags = {{"team", "a"}, {"env", "prod"}};
    q._created_ms = 5;
    q._modified_ms = 6;
    q._version = 3;
    q._partitions = 16;
    q._last_purge_ms = 9;
    BOOST_TEST((sqs::decode_queue_record(sqs::encode_queue_record(q)) == std::optional(q)));

    auto c = create("orders");
    c._tags = {{"k", "v"}};
    c._tag_keys = {"x", "y"};
    c._expected_version = 4;
    BOOST_TEST((sqs::decode_catalog_command(sqs::encode_catalog_command(c)) == std::optional(c)));
    BOOST_TEST(sqs::is_catalog_entry(sqs::encode_catalog_command(c)));
    BOOST_TEST(!sqs::is_catalog_entry(sqs::encode_queue_command(sqs::queue_command{})));

    sqs::catalog_result r{status::name_exists, q, {}};
    BOOST_TEST((sqs::decode_catalog_result(sqs::encode_catalog_result(r)) == std::optional(r)));

    // Move tasks travel in commands, results and their own records.
    sqs::move_task m;
    m._account = "1";
    m._name = "dlq";
    m._started_ms = 99;
    m._status = sqs::move_task::state::cancelling;
    m._source_arn = "arn:aws:sqs:us-east-1:1:dlq";
    m._destination_arn = "arn:aws:sqs:us-east-1:1:src";
    m._rate = 50;
    m._moved = 7;
    m._to_move = 9;
    m._failure = "gone";
    BOOST_TEST((sqs::decode_move_task(sqs::encode_move_task(m)) == std::optional(m)));
    auto mc = c;
    mc._op = sqs::catalog_command::kind::move_update;
    mc._move = m;
    BOOST_TEST((sqs::decode_catalog_command(sqs::encode_catalog_command(mc)) == std::optional(mc)));
    sqs::catalog_result mr{status::move_in_progress, std::nullopt, m};
    BOOST_TEST((sqs::decode_catalog_result(sqs::encode_catalog_result(mr)) == std::optional(mr)));

    // Truncations and trailing bytes never decode.
    const auto e = sqs::encode_catalog_command(c);
    for (std::size_t n = 0; n < e.size(); ++n) {
        BOOST_TEST(!sqs::decode_catalog_command(e.substr(0, n)).has_value());
    }
    BOOST_TEST(!sqs::decode_catalog_command(e + "x").has_value());
    BOOST_TEST(!sqs::decode_queue_record(sqs::encode_queue_record(q) + "x").has_value());
}

BOOST_AUTO_TEST_CASE(initial_partitions_follow_the_queue_type) {
    sqs::queue_settings s;
    BOOST_TEST(sqs::initial_partitions(s) == 4U);
    s._fifo = true;
    BOOST_TEST(sqs::initial_partitions(s) == 1U);
    s._throughput_limit = "perMessageGroupId";
    BOOST_TEST(sqs::initial_partitions(s) == 16U);
}

BOOST_AUTO_TEST_CASE(create_is_idempotent_on_identical_settings) {
    replica r;
    const auto a = r.run(create("orders"));
    BOOST_TEST((a._outcome == status::ok));
    BOOST_REQUIRE(a._record.has_value());
    BOOST_TEST(a._record->_id == 1U);
    BOOST_TEST(a._record->_version == 1U);
    BOOST_TEST(a._record->_partitions == 4U);
    BOOST_TEST(a._record->_created_ms == 1'000U);

    // Same settings: the stored record, unchanged, whatever the time.
    const auto b = r.run(create("orders", 2'000));
    BOOST_TEST((b._outcome == status::exists));
    BOOST_TEST((b._record == a._record));

    // Other settings: refused.
    auto other = create("orders", 3'000);
    other._settings._visibility_s = 60;
    BOOST_TEST((r.run(other)._outcome == status::name_exists));

    // Names are per account, and each queue gets the next id.
    auto elsewhere = create("orders");
    elsewhere._account = "210987654321";
    BOOST_TEST(r.run(elsewhere)._record->_id == 2U);
    BOOST_TEST(r.run(create("billing"))._record->_id == 3U);
}

BOOST_AUTO_TEST_CASE(a_recreated_queue_waits_for_the_cooldown_and_gets_a_new_id) {
    replica r;
    const auto first = r.run(create("orders"))._record->_id;
    const auto gone = r.run(command(kind::delete_, "orders", 10'000));
    BOOST_TEST((gone._outcome == status::ok));
    BOOST_TEST(gone._record->_id == first);
    BOOST_TEST(!r.sm.find_queue("123456789012", "orders").has_value());
    BOOST_TEST(
        (r.run(command(kind::delete_, "orders", 10'001))._outcome == status::does_not_exist));

    BOOST_TEST((r.run(create("orders", 69'999))._outcome == status::deleted_recently));
    const auto again = r.run(create("orders", 70'000));
    BOOST_TEST((again._outcome == status::ok));
    BOOST_TEST(again._record->_id != first);

    // The marker is gone with the new queue: deleting and recreating after
    // another cooldown works the same way.
    r.run(command(kind::delete_, "orders", 80'000));
    BOOST_TEST((r.run(create("orders", 100'000))._outcome == status::deleted_recently));
    BOOST_TEST((r.run(create("orders", 140'000))._outcome == status::ok));
}

BOOST_AUTO_TEST_CASE(settings_change_by_compare_and_set) {
    replica r;
    const auto q = *r.run(create("orders"))._record;

    auto set = command(kind::set_settings, "orders", 5'000);
    set._settings = q._settings;
    set._settings._visibility_s = 90;
    set._expected_version = q._version;
    const auto a = r.run(set);
    BOOST_TEST((a._outcome == status::ok));
    BOOST_TEST(a._record->_settings._visibility_s == 90U);
    BOOST_TEST(a._record->_version == 2U);
    BOOST_TEST(a._record->_modified_ms == 5'000U);

    // A second writer that read version 1 is refused and shown the record.
    auto stale = set;
    stale._settings._delay_s = 5;
    const auto b = r.run(stale);
    BOOST_TEST((b._outcome == status::conflict));
    BOOST_TEST(b._record->_settings._delay_s == 0U);
    BOOST_TEST(b._record->_settings._visibility_s == 90U);

    // FIFO-ness is fixed at creation; an unchanged write keeps the
    // modification time but still advances the version.
    auto same = command(kind::set_settings, "orders", 9'000);
    same._settings = a._record->_settings;
    same._settings._fifo = true;
    same._expected_version = 2;
    const auto c = r.run(same);
    BOOST_TEST((c._outcome == status::ok));
    BOOST_TEST(!c._record->_settings._fifo);
    BOOST_TEST(c._record->_modified_ms == 5'000U);
    BOOST_TEST(c._record->_version == 3U);

    BOOST_TEST((r.run(command(kind::set_settings, "missing"))._outcome == status::does_not_exist));
}

BOOST_AUTO_TEST_CASE(tags_are_merged_removed_and_capped) {
    replica r;
    auto c = create("orders");
    c._tags = {{"team", "a"}};
    r.run(c);

    auto tag = command(kind::tag, "orders");
    tag._tags = {{"team", "b"}, {"env", "prod"}};
    const auto a = r.run(tag);
    BOOST_TEST((a._outcome == status::ok));
    BOOST_TEST(a._record->_tags.size() == 2U);
    BOOST_TEST(a._record->_tags.at("team") == "b");
    BOOST_TEST(a._record->_modified_ms == 1'000U);

    auto untag = command(kind::untag, "orders");
    untag._tag_keys = {"team", "absent"};
    BOOST_TEST(r.run(untag)._record->_tags.size() == 1U);

    auto many = command(kind::tag, "orders");
    for (int i = 0; i < 50; ++i) {
        many._tags["k" + std::to_string(i)] = "v";
    }
    BOOST_TEST((r.run(many)._outcome == status::too_many_tags));
    BOOST_TEST(r.sm.find_queue("123456789012", "orders")->_tags.size() == 1U);

    auto big = create("big");
    big._tags = many._tags;
    big._tags["one-more"] = "v";
    BOOST_TEST((r.run(big)._outcome == status::too_many_tags));
    BOOST_TEST(!r.sm.find_queue("123456789012", "big").has_value());
}

BOOST_AUTO_TEST_CASE(purges_are_spaced_by_the_cooldown) {
    replica r;
    r.run(create("orders"));
    auto purge = command(kind::purge, "orders", 10'000);
    purge._cooldown_ms = 60'000;
    const auto a = r.run(purge);
    BOOST_TEST((a._outcome == status::ok));
    BOOST_TEST(a._record->_last_purge_ms == 10'000U);

    purge._now_ms = 69'999;
    BOOST_TEST((r.run(purge)._outcome == status::purge_in_progress));
    purge._now_ms = 70'000;
    BOOST_TEST((r.run(purge)._outcome == status::ok));
}

BOOST_AUTO_TEST_CASE(queues_list_by_prefix_and_token) {
    replica r;
    for (const auto* n : {"alpha", "beta", "beta-2", "beta-3", "gamma"}) {
        r.run(create(n));
    }
    auto other = create("beta-other");
    other._account = "210987654321";
    r.run(other);

    const auto names = [](const std::vector<sqs::queue_record>& qs) {
        std::vector<std::string> out;
        for (const auto& q : qs) {
            out.push_back(q._name);
        }
        return out;
    };
    BOOST_TEST(names(r.sm.list_queues("123456789012", "", "", 1000)) ==
                   (std::vector<std::string>{"alpha", "beta", "beta-2", "beta-3", "gamma"}),
               boost::test_tools::per_element());
    BOOST_TEST(names(r.sm.list_queues("123456789012", "beta", "", 2)) ==
                   (std::vector<std::string>{"beta", "beta-2"}),
               boost::test_tools::per_element());
    BOOST_TEST(names(r.sm.list_queues("123456789012", "beta", "beta-2", 2)) ==
                   (std::vector<std::string>{"beta-3"}),
               boost::test_tools::per_element());
    BOOST_TEST(r.sm.list_queues("999999999999", "", "", 10).empty());
}

BOOST_AUTO_TEST_CASE(malformed_entries_change_nothing) {
    replica r;
    auto bad = create("orders");
    bad._account = "a/b";
    BOOST_TEST((r.run(bad)._outcome == status::malformed));
    bad = create("");
    BOOST_TEST((r.run(bad)._outcome == status::malformed));

    // A group that does not hold the catalog refuses catalog entries.
    memory_kv_engine engine;
    queue_sm sm;
    sm.open(engine, key_range{"q/", std::nullopt});
    const auto out = sqs::decode_catalog_result(
        text(sm.apply(bytes(sqs::encode_catalog_command(create("orders"))), 1)));
    BOOST_REQUIRE(out.has_value());
    BOOST_TEST((out->_outcome == status::malformed));

    // A corrupt catalog entry (right format byte, bad body) is malformed.
    const auto junk = sqs::decode_catalog_result(text(sm.apply(bytes(std::string(1, '\x40')), 2)));
    BOOST_REQUIRE(junk.has_value());
    BOOST_TEST((junk->_outcome == status::malformed));
}

BOOST_AUTO_TEST_CASE(catalog_and_partitions_share_a_log_and_survive_restart) {
    replica r;
    const auto q = *r.run(create("orders"))._record;

    sqs::queue_command send;
    send.op = sqs::queue_command::kind::send;
    send.target = q.target(2);
    send.now_ms = 2'000;
    sqs::send_entry e;
    e.message_id = "m1";
    e.body = "hello";
    send.sends.push_back(e);
    const auto res = sqs::decode_queue_result(
        text(r.sm.apply(bytes(sqs::encode_queue_command(send)), ++r.index)));
    BOOST_REQUIRE(res.has_value());
    BOOST_TEST(res->entries.size() == 1U);
    BOOST_TEST(r.sm.counts(q.target(2)).visible == 1U);

    // Reopen on the same engine: the record, the id counter and the
    // partition are all still there, and replayed entries are skipped.
    queue_sm again;
    again.open(*r.engine, k_all);
    BOOST_TEST(again.applied_index() == r.index);
    BOOST_TEST((again.find_queue("123456789012", "orders") == std::optional(q)));
    BOOST_TEST(again.counts(q.target(2)).visible == 1U);
    BOOST_TEST(again.apply(bytes(sqs::encode_catalog_command(create("next"))), r.index).empty());
    const auto next = sqs::decode_catalog_result(
        text(again.apply(bytes(sqs::encode_catalog_command(create("next"))), r.index + 1)));
    BOOST_TEST(next->_record->_id == q._id + 1);
}

BOOST_AUTO_TEST_CASE(the_catalog_is_never_split) {
    replica r;
    r.run(create("orders"));
    BOOST_TEST(!queue_sm::can_split_at(sqs::catalog_keys::next_id()));
    BOOST_TEST(!queue_sm::can_split_at(sqs::catalog_keys::queue("123456789012", "orders")));
    const bool catalog_first = sqs::catalog_keys::queue("123456789012", "orders")
                                   .compare(sqs::queue_keys::partition_prefix(0, 0)) < 0;
    BOOST_TEST(catalog_first);
    BOOST_CHECK_THROW((void)r.sm.split_at({sqs::catalog_keys::queue("123456789012", "orders")}),
                      std::invalid_argument);
    // The size policy never proposes a cut inside the catalog.
    for (const auto& k : r.sm.suggest_split_keys(8)) {
        BOOST_TEST(queue_sm::can_split_at(k));
    }
}
