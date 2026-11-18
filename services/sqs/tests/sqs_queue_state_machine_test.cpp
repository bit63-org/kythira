// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The queue state machine (`.kiro/specs/sqs-compatible-queues/` task 2):
// commands and their encodings; sends, receives as committed entries,
// receipts valid only for their receive, visibility changes, delays and
// retention from leader-stamped times; FIFO order, group blocking and
// deduplication; purge and drop; replay, restart, checkpoints and splits;
// and a seeded model check in which replicas are rebuilt mid-run (a
// restart, or a new leader installed from a snapshot) and must keep
// answering exactly as the reference model does. Runs on memory_kv_engine.

#define BOOST_TEST_MODULE sqs_queue_state_machine_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_queue_commands.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace sqs = kythira::sqs;
using kythira::column_family;
using kythira::key_range;
using kythira::memory_kv_engine;

namespace {

using queue_sm = sqs::sqs_queue_state_machine<>;
using kind = sqs::queue_command::kind;
using status = sqs::entry_result::status;

const key_range k_all{"", std::nullopt};

auto standard(std::uint64_t id = 1, std::uint16_t partition = 0) -> sqs::queue_target {
    return sqs::queue_target{id, partition, false, 345'600};
}

auto fifo(std::uint64_t id = 2) -> sqs::queue_target {
    return sqs::queue_target{id, 0, true, 345'600};
}

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

auto message(const std::string& body, const std::string& group = {}, const std::string& dedup = {},
             std::uint32_t delay_s = 0) -> sqs::send_entry {
    sqs::send_entry e;
    e.message_id = "id-" + body;
    e.body = body;
    e.md5_of_body = "md5-" + body;
    e.group_id = group;
    e.dedup_key = dedup;
    e.dedup_id = dedup;
    e.delay_s = delay_s;
    return e;
}

/// One replica: an engine and the state machine open on all of it.
struct replica {
    std::unique_ptr<memory_kv_engine> engine = std::make_unique<memory_kv_engine>();
    queue_sm sm;
    std::uint64_t index = 0;

    replica() { sm.open(*engine, k_all); }

    auto apply(const sqs::queue_command& c) -> sqs::queue_result {
        const auto out = sm.apply(bytes(sqs::encode_queue_command(c)), ++index);
        auto r = sqs::decode_queue_result(text(out));
        BOOST_REQUIRE(r.has_value());
        return *r;
    }

    auto send(const sqs::queue_target& t, std::uint64_t now, std::vector<sqs::send_entry> s)
        -> sqs::queue_result {
        sqs::queue_command c;
        c.op = kind::send;
        c.target = t;
        c.now_ms = now;
        c.sends = std::move(s);
        return apply(c);
    }

    auto receive(const sqs::queue_target& t, std::uint64_t now, std::uint32_t max,
                 std::uint32_t timeout_s = 30) -> std::vector<sqs::received_message> {
        sqs::queue_command c;
        c.op = kind::receive;
        c.target = t;
        c.now_ms = now;
        c.max_messages = max;
        c.visibility_timeout_s = timeout_s;
        return apply(c).messages;
    }

    auto receipts(kind op, const sqs::queue_target& t, std::uint64_t now,
                  std::vector<sqs::receipt_ref> r) -> std::vector<sqs::entry_result> {
        sqs::queue_command c;
        c.op = op;
        c.target = t;
        c.now_ms = now;
        c.receipts = std::move(r);
        return apply(c).entries;
    }

    auto simple(kind op, const sqs::queue_target& t, std::uint64_t now) -> sqs::queue_result {
        sqs::queue_command c;
        c.op = op;
        c.target = t;
        c.now_ms = now;
        return apply(c);
    }

    /// Every data key and value, for comparing replicas.
    [[nodiscard]] auto dump() const -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> out;
        engine->scan(column_family::data, k_all, kythira::scan_direction::forward,
                     [&](std::string_view k, std::string_view v) {
                         out.emplace_back(k, v);
                         return true;
                     });
        return out;
    }
};

auto ref(const sqs::received_message& m, std::uint32_t timeout_s = 0) -> sqs::receipt_ref {
    return sqs::receipt_ref{{}, m.sequence, m.receive_sequence, timeout_s};
}

auto bodies(const std::vector<sqs::received_message>& ms) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& m : ms) {
        out.push_back(m.body);
    }
    return out;
}

constexpr std::uint64_t k_t0 = 1'794'787'200'000;  // 2026-11-18T00:00:00Z

}  // namespace

BOOST_AUTO_TEST_SUITE(sqs_queue_state_machine_suite)

BOOST_AUTO_TEST_CASE(concepts_hold) {
    static_assert(kythira::persistent_state_machine<queue_sm>);
    static_assert(kythira::persistent_splittable_state_machine<queue_sm>);
    static_assert(kythira::persistent_staged_state_machine<queue_sm>);
    BOOST_TEST(true);
}

BOOST_AUTO_TEST_CASE(commands_and_results_round_trip) {
    sqs::queue_command c;
    c.op = kind::send;
    c.target = fifo(9);
    c.now_ms = k_t0;
    c.sends = {message("a", "g", "d", 3), message(std::string("\0\xff", 2))};
    c.receipts = {sqs::receipt_ref{"e", 4, 5, 6}};
    c.redrive = sqs::redrive_target{3, fifo(10), 2, "arn:aws:sqs:us-east-1:1:src"};
    const auto enc = sqs::encode_queue_command(c);
    BOOST_TEST((sqs::decode_queue_command(enc) == c));
    // Every truncation, and trailing garbage, is refused without throwing.
    for (std::size_t n = 0; n < enc.size(); ++n) {
        BOOST_TEST(!sqs::decode_queue_command(enc.substr(0, n)).has_value());
    }
    BOOST_TEST(!sqs::decode_queue_command(enc + "x").has_value());

    sqs::queue_result r;
    r.entries = {sqs::entry_result{"e", status::duplicate, "m", 7}};
    r.messages.push_back(sqs::received_message{1, 2, 3, "m", "b", "a", "s", "5", "6", "7", "g", "d",
                                               8, 9, 10, "arn:aws:sqs:us-east-1:1:src"});
    const auto renc = sqs::encode_queue_result(r);
    BOOST_TEST((sqs::decode_queue_result(renc) == r));
    for (std::size_t n = 0; n < renc.size(); ++n) {
        BOOST_TEST(!sqs::decode_queue_result(renc.substr(0, n)).has_value());
    }
}

BOOST_AUTO_TEST_CASE(a_malformed_entry_changes_only_the_applied_index) {
    replica r;
    const auto out = r.sm.apply(bytes("not a command"), 1);
    const auto res = sqs::decode_queue_result(text(out));
    BOOST_REQUIRE(res.has_value());
    BOOST_TEST((res->outcome == sqs::queue_result::status::malformed));
    BOOST_TEST(r.sm.applied_index() == 1U);
    BOOST_TEST(r.dump().empty());
}

BOOST_AUTO_TEST_CASE(standard_send_receive_delete) {
    replica r;
    const auto t = standard();
    const auto sent = r.send(t, k_t0, {message("one"), message("two"), message("three")});
    BOOST_REQUIRE_EQUAL(sent.entries.size(), 3U);
    BOOST_TEST(sent.entries[0].sequence == 1U);
    BOOST_TEST(sent.entries[2].message_id == "id-three");
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{3, 0, 0}));

    auto got = r.receive(t, k_t0 + 1, 2, 30);
    BOOST_TEST((bodies(got) == std::vector<std::string>{"one", "two"}));
    BOOST_TEST(got[0].receive_count == 1U);
    BOOST_TEST(got[0].visible_at_ms == k_t0 + 1 + 30'000);
    BOOST_TEST(got[0].first_receive_ms == k_t0 + 1);
    BOOST_TEST(got[0].receive_sequence != got[1].receive_sequence);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 2, 0}));

    // In-flight messages are not handed out again.
    auto more = r.receive(t, k_t0 + 2, 10);
    BOOST_TEST((bodies(more) == std::vector<std::string>{"three"}));
    BOOST_TEST(r.receive(t, k_t0 + 3, 10).empty());

    const auto del = r.receipts(kind::delete_, t, k_t0 + 4, {ref(got[0]), ref(got[1])});
    BOOST_TEST((del[0].outcome == status::ok));
    BOOST_TEST(del[0].message_id == "id-one");
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{0, 1, 0}));
    BOOST_TEST(!r.sm.message(t, got[0].sequence).has_value());
}

BOOST_AUTO_TEST_CASE(a_receipt_is_valid_only_for_its_receive) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("m")});
    const auto first = r.receive(t, k_t0, 1, 10);
    // The timeout ends; the message is received again.
    const auto second = r.receive(t, k_t0 + 10'000, 1, 10);
    BOOST_REQUIRE_EQUAL(second.size(), 1U);
    BOOST_TEST(second[0].receive_count == 2U);
    BOOST_TEST(second[0].first_receive_ms == k_t0);
    // The first handle no longer deletes or changes it; both are accepted,
    // as SQS accepts them.
    BOOST_TEST(
        (r.receipts(kind::delete_, t, k_t0 + 10'001, {ref(first[0])})[0].outcome == status::stale));
    BOOST_TEST(
        (r.receipts(kind::change_visibility, t, k_t0 + 10'001, {ref(first[0], 0)})[0].outcome ==
         status::stale));
    BOOST_TEST(
        (r.sm.message(t, first[0].sequence)->status == sqs::stored_message::state::in_flight));
    BOOST_TEST(r.sm.message(t, first[0].sequence).has_value());
    // The latest one does.
    BOOST_TEST(
        (r.receipts(kind::delete_, t, k_t0 + 10'002, {ref(second[0])})[0].outcome == status::ok));
    // A delete of a deleted message is accepted and does nothing.
    BOOST_TEST((r.receipts(kind::delete_, t, k_t0 + 10'003, {ref(second[0])})[0].outcome ==
                status::stale));
}

BOOST_AUTO_TEST_CASE(an_expired_receipt_of_a_message_not_received_again_still_deletes) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("m")});
    const auto got = r.receive(t, k_t0, 1, 1);
    // Visible again, but nobody received it since: the handle is the latest.
    r.simple(kind::tick, t, k_t0 + 5'000);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 0, 0}));
    BOOST_TEST(
        (r.receipts(kind::delete_, t, k_t0 + 5'001, {ref(got[0])})[0].outcome == status::ok));
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{0, 0, 0}));
}

BOOST_AUTO_TEST_CASE(visibility_changes) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("a"), message("b")});
    const auto got = r.receive(t, k_t0, 2, 30);
    // Extend one, release the other.
    const auto out =
        r.receipts(kind::change_visibility, t, k_t0 + 1, {ref(got[0], 120), ref(got[1], 0)});
    BOOST_TEST((out[0].outcome == status::ok));
    BOOST_TEST((out[1].outcome == status::ok));
    BOOST_TEST(r.sm.message(t, got[0].sequence)->at_ms == k_t0 + 1 + 120'000);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 1, 0}));
    // The released one is visible at once; the extended one after 120 s,
    // not after its original 30 s.
    BOOST_TEST((bodies(r.receive(t, k_t0 + 2, 10, 3600)) == std::vector<std::string>{"b"}));
    BOOST_TEST(r.receive(t, k_t0 + 60'000, 10).empty());
    BOOST_TEST((bodies(r.receive(t, k_t0 + 121'001, 10)) == std::vector<std::string>{"a"}));
}

BOOST_AUTO_TEST_CASE(visibility_change_errors) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("a")});
    auto got = r.receive(t, k_t0, 1, 30);
    // Past 12 hours from the receive.
    BOOST_TEST(
        (r.receipts(kind::change_visibility, t, k_t0 + 1000, {ref(got[0], 43'200)})[0].outcome ==
         status::timeout_too_long));
    BOOST_TEST((r.receipts(kind::change_visibility, t, k_t0, {ref(got[0], 43'200)})[0].outcome ==
                status::ok));
    // Released, then changed again with the same (still latest) handle.
    r.receipts(kind::change_visibility, t, k_t0 + 1, {ref(got[0], 0)});
    BOOST_TEST((r.receipts(kind::change_visibility, t, k_t0 + 2, {ref(got[0], 10)})[0].outcome ==
                status::not_inflight));
    // A handle naming no message.
    BOOST_TEST(
        (r.receipts(kind::change_visibility, t, k_t0 + 3, {sqs::receipt_ref{"x", 99, 1, 10}})[0]
             .outcome == status::invalid_receipt));
}

BOOST_AUTO_TEST_CASE(delays_end_at_leader_stamped_times) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("late", {}, {}, 5), message("now")});
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 0, 1}));
    BOOST_TEST(r.sm.next_deadline(t).has_value());
    BOOST_TEST((bodies(r.receive(t, k_t0 + 4'999, 10)) == std::vector<std::string>{"now"}));
    // The tick at the deadline makes it visible: a committed fact.
    r.simple(kind::tick, t, k_t0 + 5'000);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 1, 0}));
    BOOST_TEST((bodies(r.receive(t, k_t0 + 5'001, 10)) == std::vector<std::string>{"late"}));
}

BOOST_AUTO_TEST_CASE(retention_deletes_every_message_past_it) {
    replica r;
    auto t = standard();
    t.retention_s = 60;
    r.send(t, k_t0, {message("old"), message("held")});
    r.receive(t, k_t0, 1, 3600);  // "old" is in flight
    r.send(t, k_t0 + 30'000, {message("young")});
    r.simple(kind::tick, t, k_t0 + 60'000);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 0, 0}));
    BOOST_TEST((bodies(r.receive(t, k_t0 + 60'001, 10)) == std::vector<std::string>{"young"}));
}

BOOST_AUTO_TEST_CASE(fifo_order_and_group_blocking) {
    replica r;
    const auto t = fifo();
    r.send(t, k_t0,
           {message("a1", "A", "a1"), message("b1", "B", "b1"), message("a2", "A", "a2"),
            message("a3", "A", "a3"), message("b2", "B", "b2")});
    // A group's messages come together and in order, oldest group first.
    auto got = r.receive(t, k_t0 + 1, 2);
    BOOST_TEST((bodies(got) == std::vector<std::string>{"a1", "a2"}));
    // Group A is blocked while a1 is in flight; B is served.
    auto next = r.receive(t, k_t0 + 2, 10);
    BOOST_TEST((bodies(next) == std::vector<std::string>{"b1", "b2"}));
    BOOST_TEST(r.receive(t, k_t0 + 3, 10).empty());
    // Deleting a1 leaves a2 in flight at the head: still blocked.
    r.receipts(kind::delete_, t, k_t0 + 4, {ref(got[0])});
    BOOST_TEST(r.receive(t, k_t0 + 5, 10).empty());
    // Deleting a2 frees the group: a3 comes next.
    r.receipts(kind::delete_, t, k_t0 + 6, {ref(got[1])});
    BOOST_TEST((bodies(r.receive(t, k_t0 + 7, 10)) == std::vector<std::string>{"a3"}));
}

BOOST_AUTO_TEST_CASE(fifo_group_resumes_after_its_head_times_out) {
    replica r;
    const auto t = fifo();
    r.send(t, k_t0, {message("a1", "A", "1"), message("a2", "A", "2")});
    auto got = r.receive(t, k_t0, 1, 10);
    BOOST_TEST((bodies(got) == std::vector<std::string>{"a1"}));
    BOOST_TEST(r.receive(t, k_t0 + 9'999, 10).empty());
    // The head's timeout ends: the group is served from the head again.
    auto again = r.receive(t, k_t0 + 10'000, 10);
    BOOST_TEST((bodies(again) == std::vector<std::string>{"a1", "a2"}));
    BOOST_TEST(again[0].receive_count == 2U);
}

BOOST_AUTO_TEST_CASE(fifo_deduplication_window) {
    replica r;
    const auto t = fifo();
    const auto first = r.send(t, k_t0, {message("x", "G", "dedup-1")});
    auto dup = message("x-again", "G", "dedup-1");
    dup.message_id = "other-id";
    const auto second = r.send(t, k_t0 + 299'999, {dup});
    BOOST_TEST((second.entries[0].outcome == status::duplicate));
    BOOST_TEST(second.entries[0].message_id == "id-x");
    BOOST_TEST(second.entries[0].sequence == first.entries[0].sequence);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 0, 0}));
    // After five minutes the key is new again.
    const auto third = r.send(t, k_t0 + 300'000, {dup});
    BOOST_TEST((third.entries[0].outcome == status::ok));
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{2, 0, 0}));
    // The expired record was cleaned and replaced, never left behind.
    r.simple(kind::tick, t, k_t0 + 600'001);
    for (const auto& [k, v] : r.dump()) {
        BOOST_TEST(k.find("/d/") == std::string::npos);
        BOOST_TEST(k.find("/e/") == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(purge_keeps_sequences_and_drop_removes_everything) {
    replica r;
    const auto t = standard();
    r.send(t, k_t0, {message("a"), message("b")});
    r.receive(t, k_t0, 1);
    r.simple(kind::purge, t, k_t0 + 1);
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{0, 0, 0}));
    BOOST_TEST(r.receive(t, k_t0 + 2, 10).empty());
    const auto after = r.send(t, k_t0 + 3, {message("c")});
    BOOST_TEST(after.entries[0].sequence == 3U);

    const auto other = standard(5);
    r.send(other, k_t0, {message("keep")});
    r.simple(kind::drop, t, k_t0 + 4);
    for (const auto& [k, v] : r.dump()) {
        BOOST_TEST(!k.starts_with(sqs::queue_keys::partition_prefix(t)));
    }
    BOOST_TEST((r.sm.counts(other) == sqs::partition_counts{1, 0, 0}));
}

BOOST_AUTO_TEST_CASE(a_recreated_queue_sees_no_old_message) {
    replica r;
    r.send(standard(1), k_t0, {message("old")});
    // The catalog gives the recreated queue a new id (Requirement 4.2).
    BOOST_TEST(r.receive(standard(2), k_t0 + 1, 10).empty());
}

BOOST_AUTO_TEST_CASE(partitions_are_independent) {
    replica r;
    r.send(standard(1, 0), k_t0, {message("p0")});
    r.send(standard(1, 1), k_t0, {message("p1")});
    BOOST_TEST((bodies(r.receive(standard(1, 1), k_t0, 10)) == std::vector<std::string>{"p1"}));
    BOOST_TEST((r.sm.counts(standard(1, 0)) == sqs::partition_counts{1, 0, 0}));
    BOOST_TEST(r.send(standard(1, 1), k_t0, {message("again")}).entries[0].sequence == 2U);
}

BOOST_AUTO_TEST_CASE(replay_and_restart) {
    replica r;
    const auto t = standard();
    const auto entry = bytes(sqs::encode_queue_command([&] {
        sqs::queue_command c;
        c.op = kind::send;
        c.target = t;
        c.now_ms = k_t0;
        c.sends = {message("once")};
        return c;
    }()));
    r.sm.apply(entry, 1);
    // A replayed index is a no-op.
    BOOST_TEST(r.sm.apply(entry, 1).empty());
    BOOST_TEST((r.sm.counts(t) == sqs::partition_counts{1, 0, 0}));
    // Reopened on the same engine, it resumes at its applied index.
    queue_sm again;
    again.open(*r.engine, k_all);
    BOOST_TEST(again.applied_index() == 1U);
    BOOST_TEST((again.counts(t) == sqs::partition_counts{1, 0, 0}));
    BOOST_TEST(again.apply(entry, 1).empty());
}

BOOST_AUTO_TEST_CASE(checkpoint_and_ingest) {
    replica a;
    const auto t = fifo();
    a.send(t, k_t0, {message("1", "G", "1"), message("2", "G", "2")});
    a.receive(t, k_t0, 1);
    const auto dir = std::filesystem::temp_directory_path() / "sqs_queue_sm_checkpoint";
    std::filesystem::remove_all(dir);
    const auto manifest = a.sm.checkpoint(dir);
    replica b;
    b.sm.ingest(dir, manifest, a.index);
    b.index = a.index;
    BOOST_TEST((b.dump() == a.dump()));
    BOOST_TEST(b.sm.applied_index() == a.sm.applied_index());
    // Both go on identically.
    BOOST_TEST((a.receive(t, k_t0 + 40'000, 10) == b.receive(t, k_t0 + 40'000, 10)));
    BOOST_TEST((b.dump() == a.dump()));
    std::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(splits_only_at_partition_boundaries) {
    replica r;
    r.send(standard(1), k_t0, {message("a")});
    r.send(standard(3), k_t0, {message("b")});
    const auto cut = sqs::queue_keys::partition_prefix(3, 0);
    BOOST_CHECK_THROW(r.sm.split_at({cut + "m/"}), std::invalid_argument);
    const auto children = r.sm.split_at({cut});
    BOOST_REQUIRE_EQUAL(children.size(), 1U);
    BOOST_TEST(children[0].start == cut);
    BOOST_TEST((r.sm.range().end == std::optional<std::string>(cut)));
    // The child opens where the parent was and owns queue 3.
    queue_sm child;
    child.open(*r.engine, children[0]);
    BOOST_TEST(child.applied_index() == r.sm.applied_index());
    BOOST_TEST((child.counts(standard(3)) == sqs::partition_counts{1, 0, 0}));
    // The parent refuses commands for queue 3 now.
    sqs::queue_command c;
    c.op = kind::receive;
    c.target = standard(3);
    c.now_ms = k_t0;
    const auto out =
        sqs::decode_queue_result(text(r.sm.apply(bytes(sqs::encode_queue_command(c)), ++r.index)));
    BOOST_TEST((out->outcome == sqs::queue_result::status::malformed));
    // Merged back.
    r.sm.adopt(children[0]);
    BOOST_TEST(!r.sm.range().end.has_value());
    BOOST_TEST((bodies(r.receive(standard(3), k_t0, 10)) == std::vector<std::string>{"b"}));
    BOOST_TEST(r.sm.suggest_split_keys(1).size() <= 1U);
}

// ---------------------------------------------------------------------------
// Model check
// ---------------------------------------------------------------------------

namespace {

/// The reference: the semantics of Requirements 5.4-5.7 written as plainly
/// as possible, with no indexes.
struct model {
    struct msg {
        std::uint64_t seq;
        std::string body;
        std::string group;
        enum {
            visible,
            delayed,
            in_flight
        } st;
        std::uint64_t at;
        std::uint64_t expire;
        std::uint64_t receive_seq = 0;
        std::uint32_t count = 0;
        std::uint64_t last_receive = 0;
    };
    struct dedup {
        std::uint64_t expire;
        std::uint64_t seq;
    };
    bool is_fifo;
    std::uint32_t retention_s;
    std::map<std::uint64_t, msg> msgs;
    std::map<std::string, dedup> dedups;
    std::uint64_t next_seq = 1;
    std::uint64_t next_receive = 1;

    [[nodiscard]] auto head(const std::string& g) const -> std::optional<std::uint64_t> {
        for (const auto& [s, m] : msgs) {
            if (m.group == g) {
                return s;
            }
        }
        return std::nullopt;
    }

    void housekeeping(std::uint64_t now) {
        for (auto& [s, m] : msgs) {
            if (m.st != msg::visible && m.at <= now) {
                m.st = msg::visible;
            }
        }
        std::erase_if(msgs, [&](const auto& kv) { return kv.second.expire <= now; });
        std::erase_if(dedups, [&](const auto& kv) { return kv.second.expire <= now; });
    }

    auto send(std::uint64_t now, const sqs::send_entry& e) -> std::pair<status, std::uint64_t> {
        housekeeping(now);
        if (is_fifo) {
            if (const auto it = dedups.find(e.dedup_key);
                it != dedups.end() && it->second.expire > now) {
                return {status::duplicate, it->second.seq};
            }
        }
        const auto seq = next_seq++;
        msg m{seq, e.body, e.group_id, msg::visible, 0, now + std::uint64_t{retention_s} * 1000};
        if (e.delay_s > 0) {
            m.st = msg::delayed;
            m.at = now + std::uint64_t{e.delay_s} * 1000;
        }
        msgs.emplace(seq, m);
        if (is_fifo) {
            dedups[e.dedup_key] = dedup{now + 300'000, seq};
        }
        return {status::ok, seq};
    }

    auto receive(std::uint64_t now, std::uint32_t want, std::uint32_t timeout_s)
        -> std::vector<std::uint64_t> {
        housekeeping(now);
        std::vector<std::uint64_t> out;
        auto take = [&](msg& m) {
            m.st = msg::in_flight;
            m.at = now + std::uint64_t{timeout_s} * 1000;
            m.receive_seq = next_receive++;
            m.count += 1;
            m.last_receive = now;
            out.push_back(m.seq);
        };
        if (!is_fifo) {
            for (auto& [s, m] : msgs) {
                if (out.size() == want) {
                    break;
                }
                if (m.st == msg::visible) {
                    take(m);
                }
            }
            return out;
        }
        // Groups whose head is visible, by head sequence.
        std::vector<std::pair<std::uint64_t, std::string>> groups;
        std::set<std::string> seen;
        for (const auto& [s, m] : msgs) {
            if (seen.insert(m.group).second && m.st == msg::visible) {
                groups.emplace_back(s, m.group);
            }
        }
        for (const auto& [h, g] : groups) {
            for (auto& [s, m] : msgs) {
                if (out.size() == want) {
                    return out;
                }
                if (m.group != g) {
                    continue;
                }
                if (m.st != msg::visible) {
                    break;
                }
                take(m);
            }
        }
        return out;
    }

    auto remove(std::uint64_t now, std::uint64_t seq, std::uint64_t rseq) -> status {
        housekeeping(now);
        const auto it = msgs.find(seq);
        if (it == msgs.end() || it->second.receive_seq != rseq || rseq == 0) {
            return status::stale;
        }
        msgs.erase(it);
        return status::ok;
    }

    auto change(std::uint64_t now, std::uint64_t seq, std::uint64_t rseq, std::uint32_t timeout_s)
        -> status {
        housekeeping(now);
        const auto it = msgs.find(seq);
        if (it == msgs.end() || rseq == 0) {
            return status::invalid_receipt;
        }
        if (it->second.receive_seq != rseq) {
            return status::stale;
        }
        auto& m = it->second;
        if (m.st != msg::in_flight) {
            return status::not_inflight;
        }
        const auto deadline = now + std::uint64_t{timeout_s} * 1000;
        if (deadline > m.last_receive + 12ULL * 3600 * 1000) {
            return status::timeout_too_long;
        }
        if (timeout_s == 0) {
            m.st = msg::visible;
            m.at = 0;
        } else {
            m.at = deadline;
        }
        return status::ok;
    }

    [[nodiscard]] auto counts() const -> sqs::partition_counts {
        sqs::partition_counts c;
        for (const auto& [s, m] : msgs) {
            (m.st == msg::visible ? c.visible : m.st == msg::delayed ? c.delayed : c.not_visible)++;
        }
        return c;
    }
};

void run_model_check(bool is_fifo, unsigned seed) {
    std::mt19937_64 rng(seed);
    const auto t = is_fifo ? fifo(7) : standard(7);
    const auto t_other = standard(8);
    model ref_model{is_fifo, 600, {}, {}};
    auto target = t;
    target.retention_s = 600;
    replica a;
    std::unique_ptr<replica> b = std::make_unique<replica>();
    std::uint64_t now = k_t0;
    // Receipts the test holds: (sequence, receive sequence), some stale.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> held;
    const auto dir =
        std::filesystem::temp_directory_path() / ("sqs_queue_sm_model_" + std::to_string(seed));
    auto pick = [&](std::uint64_t n) {
        return std::uniform_int_distribution<std::uint64_t>(0, n - 1)(rng);
    };
    const std::vector<std::string> groups{"g0", "g1", "g2"};

    for (int step = 0; step < 1500; ++step) {
        now += pick(4) == 0 ? pick(40'000) : pick(500);
        sqs::queue_command c;
        c.target = target;
        c.now_ms = now;
        const auto op = pick(10);
        if (op < 4) {
            c.op = kind::send;
            const auto n = 1 + pick(3);
            for (std::uint64_t i = 0; i < n; ++i) {
                auto e =
                    message("m" + std::to_string(step) + "-" + std::to_string(i),
                            is_fifo ? groups[pick(groups.size())] : std::string{},
                            is_fifo ? "d" + std::to_string(pick(40)) : std::string{},
                            is_fifo || pick(4) != 0 ? 0 : static_cast<std::uint32_t>(pick(20)));
                e.entry_id = std::to_string(i);
                c.sends.push_back(e);
            }
        } else if (op < 7) {
            c.op = kind::receive;
            c.max_messages = static_cast<std::uint32_t>(1 + pick(10));
            c.visibility_timeout_s = static_cast<std::uint32_t>(pick(60));
        } else if (op < 9 && !held.empty()) {
            c.op = op == 7 ? kind::delete_ : kind::change_visibility;
            const auto n = 1 + pick(std::min<std::uint64_t>(3, held.size()));
            for (std::uint64_t i = 0; i < n; ++i) {
                const auto& [s, rs] = held[pick(held.size())];
                c.receipts.push_back(
                    sqs::receipt_ref{std::to_string(i), s, rs,
                                     static_cast<std::uint32_t>(pick(4) == 0 ? 50'000 : pick(90))});
            }
        } else {
            c.op = kind::tick;
        }

        // The model's answer.
        std::vector<std::pair<status, std::uint64_t>> want_entries;
        std::vector<std::uint64_t> want_received;
        switch (c.op) {
            case kind::send:
                for (const auto& e : c.sends) {
                    want_entries.push_back(ref_model.send(now, e));
                }
                break;
            case kind::receive:
                want_received = ref_model.receive(now, c.max_messages, c.visibility_timeout_s);
                break;
            case kind::delete_:
                for (const auto& r : c.receipts) {
                    want_entries.emplace_back(ref_model.remove(now, r.sequence, r.receive_sequence),
                                              r.sequence);
                }
                break;
            case kind::change_visibility:
                for (const auto& r : c.receipts) {
                    want_entries.emplace_back(ref_model.change(now, r.sequence, r.receive_sequence,
                                                               r.visibility_timeout_s),
                                              r.sequence);
                }
                break;
            default:
                ref_model.housekeeping(now);
                break;
        }

        // Both replicas apply the entry and must agree byte for byte.
        const auto ra = a.apply(c);
        const auto rb = b->apply(c);
        BOOST_REQUIRE_MESSAGE(ra == rb, "replicas diverged at step " << step);
        BOOST_REQUIRE_EQUAL(ra.entries.size(), want_entries.size());
        for (std::size_t i = 0; i < want_entries.size(); ++i) {
            BOOST_REQUIRE_MESSAGE(ra.entries[i].outcome == want_entries[i].first,
                                  "step " << step << " entry " << i);
            BOOST_REQUIRE_EQUAL(ra.entries[i].sequence, want_entries[i].second);
        }
        std::vector<std::uint64_t> got;
        for (const auto& m : ra.messages) {
            got.push_back(m.sequence);
            held.emplace_back(m.sequence, m.receive_sequence);
        }
        BOOST_REQUIRE_MESSAGE(got == want_received, "receive differs at step " << step);
        BOOST_REQUIRE_MESSAGE(a.sm.counts(target) == ref_model.counts(),
                              "counts differ at step " << step);
        if (held.size() > 64) {
            held.erase(held.begin(), held.begin() + 32);
        }

        // Another queue on the same group is never touched.
        if (step == 0) {
            a.send(t_other, now, {message("bystander")});
            b->send(t_other, now, {message("bystander")});
        }

        // Now and then replica b is rebuilt: restarted on its engine, or
        // replaced by a new member installed from a's snapshot (what a new
        // leader or a lagging follower goes through).
        if (step % 97 == 96) {
            auto fresh = std::make_unique<replica>();
            if (pick(2) == 0) {
                fresh->engine = std::move(b->engine);
                fresh->sm.open(*fresh->engine, k_all);
                fresh->index = b->index;
            } else {
                std::filesystem::remove_all(dir);
                const auto m = a.sm.checkpoint(dir);
                fresh->sm.ingest(dir, m, a.index);
                fresh->index = a.index;
            }
            b = std::move(fresh);
            BOOST_REQUIRE_MESSAGE(b->dump() == a.dump(), "rebuilt replica differs at " << step);
        }
    }
    BOOST_TEST((a.sm.counts(t_other) == sqs::partition_counts{1, 0, 0}));
    std::filesystem::remove_all(dir);
}

}  // namespace

BOOST_AUTO_TEST_CASE(model_check_standard) {
    for (unsigned seed : {1U, 2U, 3U}) {
        run_model_check(false, seed);
    }
}

BOOST_AUTO_TEST_CASE(model_check_fifo) {
    for (unsigned seed : {11U, 12U, 13U}) {
        run_model_check(true, seed);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// -- task 8: fair queues ------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_noisy_group_does_not_starve_a_quiet_one) {
    replica r;
    const auto t = standard();
    for (int i = 0; i < 40; ++i) {
        (void)r.send(t, 1000, {message("noisy-" + std::to_string(i), "noisy")});
    }
    (void)r.send(t, 1000, {message("quiet-0", "quiet")});
    const auto got = r.receive(t, 2000, 10);
    BOOST_TEST_REQUIRE(got.size() == 10U);
    std::size_t quiet = 0;
    for (const auto& m : got) {
        quiet += m.body.starts_with("quiet") ? 1 : 0;
    }
    BOOST_TEST(quiet == 1U);
    // Within a group, oldest first.
    BOOST_TEST((got.front().body == "noisy-0" || got.front().body == "quiet-0"));
}

BOOST_AUTO_TEST_CASE(the_turn_goes_on_across_receives_when_groups_outnumber_places) {
    replica r;
    const auto t = standard();
    std::vector<std::string> groups;
    for (char g = 'a'; g <= 'l'; ++g) {
        groups.emplace_back(1, g);
        for (int i = 0; i < 3; ++i) {
            (void)r.send(t, 1000, {message(std::string(1, g) + std::to_string(i), groups.back())});
        }
    }
    std::set<std::string> first;
    for (const auto& m : r.receive(t, 2000, 10)) {
        first.insert(m.group_id);
    }
    BOOST_TEST(first.size() == 10U);
    std::set<std::string> second;
    for (const auto& m : r.receive(t, 2000, 10)) {
        second.insert(m.group_id);
    }
    // The two groups the first receive did not reach come first now.
    for (const auto& g : groups) {
        if (!first.contains(g)) {
            BOOST_TEST(second.contains(g));
        }
    }
}

BOOST_AUTO_TEST_CASE(ungrouped_standard_messages_stay_oldest_first) {
    replica r;
    const auto t = standard();
    for (int i = 0; i < 5; ++i) {
        (void)r.send(t, 1000, {message("m" + std::to_string(i))});
    }
    const auto got = r.receive(t, 2000, 3);
    BOOST_TEST_REQUIRE(got.size() == 3U);
    BOOST_TEST(got[0].body == "m0");
    BOOST_TEST(got[2].body == "m2");
}
