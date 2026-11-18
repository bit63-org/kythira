// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 2: the topic state machine (.kiro/specs/sns-compatible-notifications/
// Requirements 4.3, 5.1 and 5.3): topics and subscriptions, publishing into
// the record segment store, FIFO deduplication, delivery leases with
// fencing, cursors and retry state. Property tests drive random command
// sequences through independent replicas, and through a replica restored
// from a snapshot taken midway that must fetch the active segment it lacks,
// and require byte-identical state and logs.

#define BOOST_TEST_MODULE sns_topic_state_machine_test

#include <boost/test/unit_test.hpp>

#include <kythira/sns/sns_topic_state_machine.hpp>

#include <raft/record_segment_store.hpp>
#include <raft/types.hpp>

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace s = kythira::sns;

using sm_type = s::topic_state_machine<std::uint64_t>;
static_assert(kythira::state_machine<sm_type, std::uint64_t>);

BOOST_TEST_DONT_PRINT_LOG_VALUE(s::apply_status)
BOOST_TEST_DONT_PRINT_LOG_VALUE(s::publish_status)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::vector<std::byte>)

namespace {

const std::string account = "123456789012";

/// A scratch directory removed at scope exit.
struct temp_dir {
    std::filesystem::path _path;
    temp_dir() {
        static int counter = 0;
        _path = std::filesystem::temp_directory_path() /
                ("sns_sm_test." + std::to_string(::getpid()) + "." + std::to_string(++counter));
        std::filesystem::remove_all(_path);
        std::filesystem::create_directories(_path);
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

/// Small segments, so the property tests roll and seal plenty of them.
auto small_segments(const std::filesystem::path& dir) -> kythira::record_segment_store_options {
    kythira::record_segment_store_options o;
    o._data_dir = dir;
    o._max_segment_bytes = 2048;
    o._barriers_enabled = false;
    return o;
}

/// A store and a state machine on it, as one replica.
struct replica {
    temp_dir _dir;
    std::unique_ptr<kythira::record_segment_store> _store;
    std::unique_ptr<sm_type> _sm;
    std::uint64_t _index = 0;

    explicit replica(s::segment_fetcher fetch = {})
        : _store(std::make_unique<kythira::record_segment_store>(small_segments(_dir._path))),
          _sm(std::make_unique<sm_type>(_store.get(), std::move(fetch))) {}

    auto run(const s::topic_command& c) -> s::apply_result {
        return s::decode_result(_sm->apply(s::encode_command(c), ++_index));
    }
};

auto bytes_of(std::string_view text) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

auto create(std::string name, bool fifo = false, std::uint32_t partitions = 1,
            std::uint32_t buckets = 1) -> s::create_topic_command {
    s::create_topic_command c;
    c._account = account;
    c._name = std::move(name);
    c._fifo = fifo;
    c._partitions = partitions;
    c._delivery_buckets = buckets;
    if (fifo) {
        c._attributes["FifoTopic"] = "true";
    }
    c._now_ms = 1000;
    return c;
}

auto publish_one(std::string topic, std::string message_id, std::int64_t now_ms,
                 std::string group = {}, std::string dedup = {}, std::uint32_t partition = 0)
    -> s::publish_command {
    s::publish_command c;
    c._account = account;
    c._name = std::move(topic);
    c._now_ms = now_ms;
    c._entries.push_back({._partition = partition,
                          ._message_id = message_id,
                          ._group_id = std::move(group),
                          ._dedup_id = std::move(dedup),
                          ._payload = bytes_of("body of " + message_id)});
    return c;
}

auto subscribe(std::string topic, std::string protocol, std::string endpoint, bool confirm = false,
               std::string token = {}) -> s::subscribe_command {
    s::subscribe_command c;
    c._account = account;
    c._name = std::move(topic);
    c._protocol = std::move(protocol);
    c._endpoint = std::move(endpoint);
    c._owner = account;
    c._needs_confirmation = confirm;
    c._token = std::move(token);
    c._now_ms = 2000;
    return c;
}

/// Every record of a log partition, read back from a replica's store.
auto log_of(const replica& r, std::uint64_t topic, std::uint32_t partition)
    -> std::vector<kythira::segment_record> {
    return r._store->read(s::publish_log_stream(topic, partition), 1)._records;
}

}  // namespace

// ---- codec -----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(every_command_round_trips) {
    s::commit_delivery_command commit;
    commit._partition = {._topic_id = 7, ._partition = 2, ._bucket = 1};
    commit._owner = "worker-a";
    commit._token = 99;
    commit._cursors = {{._subscription_id = 3, ._seq = 10}};
    commit._retries = {{._subscription_id = 3, ._seq = 11, ._attempt = 2, ._next_ms = 5000}};
    commit._cleared = {{._subscription_id = 3, ._seq = 9}};
    s::tag_topic_command tag;
    tag._account = account;
    tag._name = "t";
    tag._set = {{"a", "1"}, {"b", "2"}};
    tag._remove = {"c"};
    const std::vector<s::topic_command> all = {
        create("t", true, 4, 2),
        s::delete_topic_command{._account = account, ._name = "t"},
        s::set_topic_attribute_command{
            ._account = account, ._name = "t", ._key = "k", ._value = "v"},
        tag,
        subscribe("t", "http", "http://x/", true, "tok"),
        s::confirm_subscription_command{._account = account, ._name = "t", ._token = "tok"},
        s::unsubscribe_command{._subscription_id = 5},
        s::set_subscription_attribute_command{._subscription_id = 5, ._key = "k", ._value = "v"},
        publish_one("t", "m1", 3000, "g", "d", 1),
        s::acquire_lease_command{
            ._partition = {7, 1, 0}, ._owner = "w", ._now_ms = 1, ._duration_ms = 2},
        s::renew_lease_command{
            ._partition = {7, 1, 0}, ._owner = "w", ._token = 3, ._now_ms = 4, ._duration_ms = 5},
        s::release_lease_command{._partition = {7, 1, 0}, ._owner = "w", ._token = 3},
        commit,
    };
    BOOST_TEST(all.size() == std::variant_size_v<s::topic_command>);
    for (const auto& c : all) {
        const auto bytes = s::encode_command(c);
        const auto back = s::decode_command(bytes);
        BOOST_TEST(back.index() == c.index());
        BOOST_TEST(s::encode_command(back) == bytes);
        // Every proper prefix is refused, never misread.
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            BOOST_CHECK_THROW((void)s::decode_command(std::span(bytes.data(), n)),
                              s::sns_codec_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(results_and_stored_messages_round_trip) {
    s::apply_result a{
        ._status = s::apply_status::lease_held, ._id = 4, ._existing = true, ._detail = "worker-b"};
    a._entries.push_back(
        {._status = s::publish_status::duplicate, ._partition = 3, ._seq = 8, ._message_id = "m"});
    BOOST_TEST((s::decode_result(s::encode_result(a)) == a));

    const auto payload = bytes_of("payload");
    const auto m = s::decode_stored_message(s::encode_stored_message("id", "g", "d", payload));
    BOOST_TEST(m._message_id == "id");
    BOOST_TEST(m._group_id == "g");
    BOOST_TEST(m._dedup_id == "d");
    BOOST_TEST(m._payload == payload);
}

BOOST_AUTO_TEST_CASE(garbage_commands_answer_invalid) {
    sm_type sm;
    std::mt19937_64 rng(7);
    for (int i = 0; i < 2000; ++i) {
        std::vector<std::byte> junk(rng() % 64);
        for (auto& b : junk) {
            b = static_cast<std::byte>(rng());
        }
        if (!junk.empty()) {
            junk[0] = std::byte{s::k_command_version};
        }
        // Junk either fails to decode (answered `invalid`) or decodes to some
        // command that is refused or applied; it never throws out of apply().
        BOOST_CHECK_NO_THROW(
            (void)s::decode_result(sm.apply(junk, static_cast<std::uint64_t>(i + 1))));
    }
    BOOST_TEST(sm.last_applied_index() == 2000U);
}

// ---- topics ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(create_topic_is_idempotent_and_ids_are_never_reused) {
    replica r;
    const auto first = r.run(create("orders"));
    BOOST_TEST(first._status == s::apply_status::ok);
    BOOST_TEST(first._id == 1U);
    BOOST_TEST(!first._existing);

    const auto again = r.run(create("orders"));
    BOOST_TEST(again._status == s::apply_status::ok);
    BOOST_TEST(again._id == 1U);
    BOOST_TEST(again._existing);

    auto different = create("orders");
    different._attributes["DisplayName"] = "Orders";
    BOOST_TEST(r.run(different)._status == s::apply_status::topic_exists_with_different_attributes);
    auto tagged = create("orders");
    tagged._tags["team"] = "x";
    BOOST_TEST(r.run(tagged)._status == s::apply_status::topic_exists_with_different_tags);

    BOOST_TEST(r.run(publish_one("orders", "m1", 2000))._status == s::apply_status::ok);
    BOOST_TEST(log_of(r, 1, 0).size() == 1U);

    // Deleting drops the topic and its log; recreating gets a new id.
    BOOST_TEST(r.run(s::delete_topic_command{._account = account, ._name = "orders"})._id == 1U);
    BOOST_TEST(r._sm->find_topic(account, "orders") == nullptr);
    BOOST_TEST(log_of(r, 1, 0).empty());
    BOOST_TEST(r.run(s::delete_topic_command{._account = account, ._name = "orders"})._status ==
               s::apply_status::ok);
    const auto recreated = r.run(create("orders"));
    BOOST_TEST(recreated._id == 2U);
    BOOST_TEST(r._sm->partition(1, 0) == nullptr);
    BOOST_TEST(r._sm->partition(2, 0)->_last_seq == 0U);

    BOOST_TEST(r.run(create("bad", false, 0))._status == s::apply_status::invalid_parameter);
}

BOOST_AUTO_TEST_CASE(topic_attributes_tags_and_listing) {
    replica r;
    r.run(create("b"));
    r.run(create("a"));
    auto other = create("c");
    other._account = "999999999999";
    r.run(other);
    const auto listed = r._sm->list_topics(account);
    BOOST_TEST_REQUIRE(listed.size() == 2U);
    BOOST_TEST(listed[0]->_name == "a");
    BOOST_TEST(listed[1]->_name == "b");
    BOOST_TEST(r._sm->list_topics(account, "a").size() == 1U);
    BOOST_TEST(r._sm->list_topics(account, {}, 1).size() == 1U);

    BOOST_TEST(r.run(s::set_topic_attribute_command{
                         ._account = account, ._name = "a", ._key = "DisplayName", ._value = "A"})
                   ._status == s::apply_status::ok);
    BOOST_TEST(r._sm->find_topic(account, "a")->_attributes.at("DisplayName") == "A");
    BOOST_TEST(r.run(s::set_topic_attribute_command{._account = account, ._name = "zz"})._status ==
               s::apply_status::topic_not_found);

    s::tag_topic_command tag{
        ._account = account, ._name = "a", ._set = {{"env", "test"}, {"x", "1"}}};
    r.run(tag);
    r.run(s::tag_topic_command{._account = account, ._name = "a", ._remove = {"x"}});
    BOOST_TEST((r._sm->find_topic(account, "a")->_tags == s::string_map{{"env", "test"}}));
}

// ---- subscriptions ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(subscriptions_confirm_and_unsubscribe) {
    replica r;
    r.run(create("t"));
    const auto queue = r.run(subscribe("t", "sqs", "arn:aws:sqs:us-east-1:1:q"));
    BOOST_TEST(queue._status == s::apply_status::ok);
    BOOST_TEST(r._sm->find_subscription(queue._id)->_confirmed);

    const auto http = r.run(subscribe("t", "http", "http://h/", true, "tok-1"));
    BOOST_TEST(!r._sm->find_subscription(http._id)->_confirmed);
    // Subscribing again resends: same id, the new token replaces the old.
    const auto again = r.run(subscribe("t", "http", "http://h/", true, "tok-2"));
    BOOST_TEST(again._id == http._id);
    BOOST_TEST(again._existing);
    auto other_attrs = subscribe("t", "http", "http://h/", true, "tok-3");
    other_attrs._attributes["RawMessageDelivery"] = "true";
    BOOST_TEST(r.run(other_attrs)._status ==
               s::apply_status::subscription_exists_with_different_attributes);

    s::confirm_subscription_command confirm{
        ._account = account, ._name = "t", ._token = "tok-1", ._now_ms = 3000};
    BOOST_TEST(r.run(confirm)._status == s::apply_status::invalid_token);
    confirm._token = "tok-2";
    confirm._now_ms = 2000 + s::k_confirmation_window_ms;
    BOOST_TEST(r.run(confirm)._status == s::apply_status::invalid_token);  // expired
    confirm._now_ms = 3000;
    const auto confirmed = r.run(confirm);
    BOOST_TEST(confirmed._status == s::apply_status::ok);
    BOOST_TEST(confirmed._id == http._id);
    BOOST_TEST(r._sm->find_subscription(http._id)->_confirmed);
    BOOST_TEST(r.run(confirm)._status == s::apply_status::invalid_token);  // used

    BOOST_TEST(r._sm->subscriptions_of(1).size() == 2U);
    BOOST_TEST(
        r.run(s::set_subscription_attribute_command{
                  ._subscription_id = queue._id, ._key = "RawMessageDelivery", ._value = "true"})
            ._status == s::apply_status::ok);
    BOOST_TEST(r._sm->find_subscription(queue._id)->_attributes.at("RawMessageDelivery") == "true");

    BOOST_TEST(r.run(s::unsubscribe_command{._subscription_id = queue._id})._status ==
               s::apply_status::ok);
    BOOST_TEST(r._sm->find_subscription(queue._id) == nullptr);
    BOOST_TEST(r.run(s::unsubscribe_command{._subscription_id = queue._id})._status ==
               s::apply_status::subscription_not_found);
    BOOST_TEST(r.run(subscribe("missing", "sqs", "q"))._status == s::apply_status::topic_not_found);
}

// ---- publishing ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(publish_appends_to_the_partition_log) {
    replica r;
    r.run(create("t", false, 2));
    const auto a = r.run(publish_one("t", "m1", 5000, {}, {}, 0));
    BOOST_TEST_REQUIRE(a._entries.size() == 1U);
    BOOST_TEST(a._entries[0]._status == s::publish_status::ok);
    BOOST_TEST(a._entries[0]._seq == 1U);

    // A batch across partitions; the clock going back is clamped.
    s::publish_command batch = publish_one("t", "m2", 4000, {}, {}, 1);
    batch._entries.push_back({._partition = 0, ._message_id = "m3", ._payload = bytes_of("x")});
    batch._entries.push_back({._partition = 5, ._message_id = "m4"});
    const auto b = r.run(batch);
    BOOST_TEST_REQUIRE(b._entries.size() == 3U);
    BOOST_TEST(b._entries[0]._seq == 1U);
    BOOST_TEST(b._entries[1]._seq == 2U);
    BOOST_TEST(b._entries[2]._status == s::publish_status::invalid_parameter);

    const auto log0 = log_of(r, 1, 0);
    BOOST_TEST_REQUIRE(log0.size() == 2U);
    BOOST_TEST(log0[1]._timestamp_ms == 5000);
    const auto m3 = s::decode_stored_message(log0[1]._data);
    BOOST_TEST(m3._message_id == "m3");
    BOOST_TEST(m3._payload == bytes_of("x"));
    BOOST_TEST(r._sm->partition(1, 0)->_last_seq == 2U);
    BOOST_TEST(r._sm->partition(1, 1)->_last_seq == 1U);

    BOOST_TEST(r.run(publish_one("missing", "m", 1))._status == s::apply_status::topic_not_found);
    s::publish_command too_many = publish_one("t", "m", 1);
    too_many._entries.resize(s::k_max_publish_entries + 1, too_many._entries[0]);
    BOOST_TEST(r.run(too_many)._status == s::apply_status::invalid_parameter);
}

BOOST_AUTO_TEST_CASE(fifo_deduplicates_within_five_minutes) {
    replica r;
    r.run(create("t.fifo", true, 2));
    const auto first = r.run(publish_one("t.fifo", "m1", 10'000, "g1", "d1", 1));
    BOOST_TEST(first._entries[0]._status == s::publish_status::ok);

    // A retry with a new message id: the original answers, nothing appended.
    auto retry =
        publish_one("t.fifo", "m1-retry", 10'000 + s::k_dedup_window_ms - 1, "g1", "d1", 0);
    const auto dup = r.run(retry);
    BOOST_TEST(dup._entries[0]._status == s::publish_status::duplicate);
    BOOST_TEST(dup._entries[0]._message_id == "m1");
    BOOST_TEST(dup._entries[0]._partition == 1U);
    BOOST_TEST(dup._entries[0]._seq == 1U);
    BOOST_TEST(log_of(r, 1, 0).empty());
    BOOST_TEST(log_of(r, 1, 1).size() == 1U);

    // Within one batch, the second use of a dedup id is a duplicate too.
    s::publish_command batch = publish_one("t.fifo", "m2", 20'000, "g2", "d2", 0);
    batch._entries.push_back(
        {._partition = 0, ._message_id = "m3", ._group_id = "g2", ._dedup_id = "d2"});
    batch._entries.push_back({._partition = 0, ._message_id = "m4", ._dedup_id = "d4"});
    const auto b = r.run(batch);
    BOOST_TEST(b._entries[0]._status == s::publish_status::ok);
    BOOST_TEST(b._entries[1]._status == s::publish_status::duplicate);
    BOOST_TEST(b._entries[1]._message_id == "m2");
    BOOST_TEST(b._entries[2]._status == s::publish_status::invalid_parameter);  // no group

    // Once the window has passed, the same dedup id is a new message.
    retry._now_ms = 10'000 + s::k_dedup_window_ms;
    const auto later = r.run(retry);
    BOOST_TEST(later._entries[0]._status == s::publish_status::ok);
    BOOST_TEST(later._entries[0]._seq == 2U);
    const auto stored = s::decode_stored_message(log_of(r, 1, 0).back()._data);
    BOOST_TEST(stored._group_id == "g1");
    BOOST_TEST(stored._dedup_id == "d1");
}

BOOST_AUTO_TEST_CASE(dedup_survives_a_snapshot_restore) {
    replica a;
    a.run(create("t.fifo", true));
    a.run(publish_one("t.fifo", "m1", 10'000, "g", "d"));
    const auto snap = a._sm->get_state();

    // A new leader restored from the snapshot still sees the dedup record.
    replica b;
    b._sm =
        std::make_unique<sm_type>(b._store.get(), [&](const kythira::record_segment_descriptor& d) {
            const std::vector<std::string> peers{"a"};
            BOOST_TEST_REQUIRE(b._store->fetch_segment(
                d, peers,
                [&](const std::string&, const std::string& stream, std::uint64_t first,
                    std::uint64_t length) {
                    return a._store->read_segment_bytes(stream, first, length);
                }));
        });
    b._sm->restore_from_snapshot(snap, 2);
    b._index = 2;
    const auto dup = b.run(publish_one("t.fifo", "m1-again", 11'000, "g", "d"));
    BOOST_TEST(dup._entries[0]._status == s::publish_status::duplicate);
    BOOST_TEST(dup._entries[0]._message_id == "m1");
    BOOST_TEST(log_of(b, 1, 0).size() == 1U);
}

// ---- leases, cursors and retries -------------------------------------------

BOOST_AUTO_TEST_CASE(leases_fence_a_stalled_worker) {
    replica r;
    r.run(create("t", false, 1, 2));
    const auto sub = r.run(subscribe("t", "sqs", "q"))._id;  // id 1: bucket 1
    r.run(publish_one("t", "m1", 1000));
    r.run(publish_one("t", "m2", 1000));
    const s::delivery_partition dp{._topic_id = 1, ._partition = 0, ._bucket = 1};
    BOOST_TEST(r._sm->subscriptions_in(dp).size() == 1U);

    const auto a = r.run(s::acquire_lease_command{
        ._partition = dp, ._owner = "a", ._now_ms = 1000, ._duration_ms = 500});
    BOOST_TEST(a._status == s::apply_status::ok);
    const auto held = r.run(s::acquire_lease_command{
        ._partition = dp, ._owner = "b", ._now_ms = 1499, ._duration_ms = 500});
    BOOST_TEST(held._status == s::apply_status::lease_held);
    BOOST_TEST(held._detail == "a");

    s::commit_delivery_command commit{._partition = dp, ._owner = "a", ._token = a._id};
    commit._cursors = {{._subscription_id = sub, ._seq = 1}};
    BOOST_TEST(r.run(commit)._status == s::apply_status::ok);
    BOOST_TEST(r._sm->cursor(sub, 0) == 1U);

    // a stalls past its lease; b takes over with a new token.
    const auto b = r.run(s::acquire_lease_command{
        ._partition = dp, ._owner = "b", ._now_ms = 1500, ._duration_ms = 500});
    BOOST_TEST(b._status == s::apply_status::ok);
    BOOST_TEST(b._id > a._id);
    commit._cursors = {{._subscription_id = sub, ._seq = 2}};
    BOOST_TEST(r.run(commit)._status == s::apply_status::lease_lost);
    BOOST_TEST(r._sm->cursor(sub, 0) == 1U);
    BOOST_TEST(r.run(s::renew_lease_command{._partition = dp,
                                            ._owner = "a",
                                            ._token = a._id,
                                            ._now_ms = 1600,
                                            ._duration_ms = 500})
                   ._status == s::apply_status::lease_lost);

    // b renews, re-acquires under its own name (same token) and commits.
    BOOST_TEST(r.run(s::renew_lease_command{._partition = dp,
                                            ._owner = "b",
                                            ._token = b._id,
                                            ._now_ms = 1600,
                                            ._duration_ms = 500})
                   ._status == s::apply_status::ok);
    const auto b_again = r.run(s::acquire_lease_command{
        ._partition = dp, ._owner = "b", ._now_ms = 1700, ._duration_ms = 500});
    BOOST_TEST(b_again._id == b._id);
    BOOST_TEST(b_again._existing);
    commit._owner = "b";
    commit._token = b._id;
    BOOST_TEST(r.run(commit)._status == s::apply_status::ok);
    BOOST_TEST(r._sm->cursor(sub, 0) == 2U);

    // Cursors never move back.
    commit._cursors = {{._subscription_id = sub, ._seq = 1}};
    BOOST_TEST(r.run(commit)._status == s::apply_status::ok);
    BOOST_TEST(r._sm->cursor(sub, 0) == 2U);

    BOOST_TEST(
        r.run(s::release_lease_command{._partition = dp, ._owner = "b", ._token = b._id})._status ==
        s::apply_status::ok);
    BOOST_TEST(r._sm->lease(dp) == nullptr);
    BOOST_TEST(r.run(commit)._status == s::apply_status::lease_lost);

    BOOST_TEST(r.run(s::acquire_lease_command{
                         ._partition = {1, 0, 2}, ._owner = "a", ._now_ms = 1, ._duration_ms = 1})
                   ._status == s::apply_status::topic_not_found);
}

BOOST_AUTO_TEST_CASE(commits_are_all_or_nothing) {
    replica r;
    r.run(create("t", false, 1, 2));
    const auto odd = r.run(subscribe("t", "sqs", "q1"))._id;   // bucket 1
    const auto even = r.run(subscribe("t", "sqs", "q2"))._id;  // bucket 0
    r.run(publish_one("t", "m1", 1000));
    r.run(publish_one("t", "m2", 1000));
    const s::delivery_partition dp{._topic_id = 1, ._partition = 0, ._bucket = 1};
    const auto token =
        r.run(s::acquire_lease_command{
                  ._partition = dp, ._owner = "w", ._now_ms = 0, ._duration_ms = 100})
            ._id;

    s::commit_delivery_command commit{._partition = dp, ._owner = "w", ._token = token};
    commit._cursors = {{._subscription_id = odd, ._seq = 1}};
    commit._retries = {{._subscription_id = odd, ._seq = 2, ._attempt = 1, ._next_ms = 900}};
    BOOST_TEST(r.run(commit)._status == s::apply_status::ok);
    BOOST_TEST(r._sm->retries_of(odd, 0).size() == 1U);
    BOOST_TEST(r._sm->retries_of(odd, 0)[0].second._next_ms == 900);

    // A subscription of another bucket, or a sequence never appended,
    // refuses the whole commit.
    s::commit_delivery_command bad = commit;
    bad._cursors = {{._subscription_id = odd, ._seq = 2}, {._subscription_id = even, ._seq = 2}};
    BOOST_TEST(r.run(bad)._status == s::apply_status::invalid_parameter);
    bad._cursors = {{._subscription_id = odd, ._seq = 3}};
    BOOST_TEST(r.run(bad)._status == s::apply_status::invalid_parameter);
    BOOST_TEST(r._sm->cursor(odd, 0) == 1U);

    s::commit_delivery_command done{._partition = dp, ._owner = "w", ._token = token};
    done._cursors = {{._subscription_id = odd, ._seq = 2}};
    done._cleared = {{._subscription_id = odd, ._seq = 2}};
    BOOST_TEST(r.run(done)._status == s::apply_status::ok);
    BOOST_TEST(r._sm->retries_of(odd, 0).empty());

    // Unsubscribing drops what is left.
    r.run(commit);
    r.run(s::unsubscribe_command{._subscription_id = odd});
    BOOST_TEST(r._sm->cursor(odd, 0) == 0U);
    BOOST_TEST(r._sm->retries_of(odd, 0).empty());
}

// ---- properties -------------------------------------------------------------------

namespace {

/// A random but valid-looking command mix over a few topics, subscriptions
/// and workers, with a clock that mostly moves forward.
class command_generator {
public:
    explicit command_generator(std::uint64_t seed) : _rng(seed) {}

    auto next() -> s::topic_command {
        _now += static_cast<std::int64_t>(pick(30'000));
        const std::string& topic = topics[pick(topics.size())];
        const bool fifo = topic.ends_with(".fifo");
        switch (pick(14)) {
            case 0:
                return create(topic, fifo, 3, 2);
            case 1:
                if (pick(8) == 0) {
                    return s::delete_topic_command{._account = account, ._name = topic};
                }
                [[fallthrough]];
            case 2:
            case 3:
            case 4:
            case 5: {
                s::publish_command c;
                c._account = account;
                c._name = topic;
                c._now_ms = _now - static_cast<std::int64_t>(pick(2000));  // skew
                const auto n = 1 + pick(4);
                for (std::size_t i = 0; i < n; ++i) {
                    const auto group = "g" + std::to_string(pick(5));
                    c._entries.push_back(
                        {._partition = static_cast<std::uint32_t>(pick(3)),
                         ._message_id = "m" + std::to_string(++_messages),
                         ._group_id = fifo ? group : "",
                         ._dedup_id = fifo ? "d" + std::to_string(pick(40)) : "",
                         ._payload = std::vector<std::byte>(pick(300), std::byte{0x5A})});
                }
                return c;
            }
            case 6:
                return subscribe(topic, "sqs", "q" + std::to_string(pick(4)));
            case 7: {
                auto c = subscribe(topic, "http", "http://h" + std::to_string(pick(3)), true,
                                   "tok" + std::to_string(pick(3)));
                c._now_ms = _now;
                return c;
            }
            case 8:
                return s::confirm_subscription_command{._account = account,
                                                       ._name = topic,
                                                       ._token = "tok" + std::to_string(pick(3)),
                                                       ._now_ms = _now};
            case 9:
                return s::unsubscribe_command{._subscription_id = 1 + pick(12)};
            case 10:
                return s::acquire_lease_command{._partition = partition(),
                                                ._owner = worker(),
                                                ._now_ms = _now,
                                                ._duration_ms = 40'000};
            case 11:
                return s::renew_lease_command{._partition = partition(),
                                              ._owner = worker(),
                                              ._token = 1 + pick(20),
                                              ._now_ms = _now,
                                              ._duration_ms = 40'000};
            case 12: {
                s::commit_delivery_command c{
                    ._partition = partition(), ._owner = worker(), ._token = 1 + pick(20)};
                if (!_granted.empty() && pick(4) != 0) {
                    // Mostly a lease some worker was granted, which may since
                    // have been taken over: current or stale.
                    const auto& g = _granted[pick(_granted.size())];
                    c._partition = g._partition;
                    c._owner = g._owner;
                    c._token = g._token;
                }
                const auto sub = 1 + pick(12);
                const auto seq = 1 + pick(8);
                c._cursors.push_back({._subscription_id = sub, ._seq = seq});
                c._retries.push_back({._subscription_id = sub,
                                      ._seq = seq + 1,
                                      ._attempt = static_cast<std::uint32_t>(pick(5)),
                                      ._next_ms = _now + 1000});
                return c;
            }
            default:
                return s::set_topic_attribute_command{._account = account,
                                                      ._name = topic,
                                                      ._key = "DisplayName",
                                                      ._value = std::to_string(pick(3))};
        }
    }

    /// Feed back a grant, so later commits can use it.
    auto observe(const s::topic_command& c, const s::apply_result& r) -> void {
        if (const auto* a = std::get_if<s::acquire_lease_command>(&c);
            a != nullptr && r._status == s::apply_status::ok) {
            _granted.push_back({._partition = a->_partition, ._owner = a->_owner, ._token = r._id});
        }
    }

private:
    struct grant {
        s::delivery_partition _partition{};
        std::string _owner{};
        std::uint64_t _token = 0;
    };
    static inline const std::vector<std::string> topics = {"a", "b", "c.fifo"};
    auto pick(std::size_t n) -> std::size_t { return static_cast<std::size_t>(_rng() % n); }
    auto partition() -> s::delivery_partition {
        return {._topic_id = 1 + pick(5),
                ._partition = static_cast<std::uint32_t>(pick(3)),
                ._bucket = static_cast<std::uint32_t>(pick(2))};
    }
    auto worker() -> std::string { return "w" + std::to_string(pick(3)); }

    std::mt19937_64 _rng;
    std::int64_t _now = 1'000'000;
    std::uint64_t _messages = 0;
    std::vector<grant> _granted;
};

/// Every log partition of every live topic reads back the same on both.
auto same_logs(const replica& x, const replica& y) -> bool {
    for (const auto* t : x._sm->list_topics(account)) {
        for (std::uint32_t p = 0; p < t->_partitions; ++p) {
            const auto a = log_of(x, t->_id, p);
            if (a != log_of(y, t->_id, p)) {
                return false;
            }
            const auto* ps = x._sm->partition(t->_id, p);
            if (ps == nullptr || (a.empty() ? 0 : a.back()._seq) != ps->_last_seq ||
                (!a.empty() && a.size() != ps->_last_seq)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

BOOST_AUTO_TEST_CASE(replicas_agree_byte_for_byte) {
    // What the random mix reached, so a generator that drifts into refusing
    // everything cannot pass by agreeing on nothing.
    std::size_t appended = 0;
    std::size_t duplicates = 0;
    std::size_t sealed = 0;
    std::size_t commits = 0;
    std::size_t fenced = 0;
    for (std::uint64_t seed = 1; seed <= 12; ++seed) {
        BOOST_TEST_CONTEXT("seed " << seed) {
            replica x;
            replica y;
            command_generator gen(seed);
            for (int i = 0; i < 400; ++i) {
                const auto cmd = gen.next();
                const auto bytes = s::encode_command(cmd);
                const auto rx = x._sm->apply(bytes, ++x._index);
                const auto ry = y._sm->apply(bytes, ++y._index);
                BOOST_TEST_REQUIRE(rx == ry);
                const auto r = s::decode_result(rx);
                gen.observe(cmd, r);
                for (const auto& e : r._entries) {
                    appended += e._status == s::publish_status::ok ? 1 : 0;
                    duplicates += e._status == s::publish_status::duplicate ? 1 : 0;
                }
                if (std::holds_alternative<s::commit_delivery_command>(cmd)) {
                    commits += r._status == s::apply_status::ok ? 1 : 0;
                    fenced += r._status == s::apply_status::lease_lost ? 1 : 0;
                }
            }
            BOOST_TEST(x._sm->get_state() == y._sm->get_state());
            BOOST_TEST(same_logs(x, y));
            for (const auto* t : x._sm->list_topics(account)) {
                for (std::uint32_t p = 0; p < t->_partitions; ++p) {
                    sealed += x._sm->partition(t->_id, p)->_sealed.size();
                }
            }
        }
    }
    BOOST_TEST_MESSAGE("appended " << appended << ", duplicates " << duplicates << ", sealed "
                                   << sealed << ", commits " << commits << ", fenced " << fenced);
    BOOST_TEST(appended > 500U);
    BOOST_TEST(duplicates > 10U);
    BOOST_TEST(sealed > 10U);
    BOOST_TEST(commits > 0U);
    BOOST_TEST(fenced > 10U);
}

BOOST_AUTO_TEST_CASE(a_replica_restored_midway_catches_up_exactly) {
    for (std::uint64_t seed = 101; seed <= 110; ++seed) {
        BOOST_TEST_CONTEXT("seed " << seed) {
            replica x;
            command_generator gen(seed);
            std::vector<std::vector<std::byte>> log;
            const std::size_t cut = 100 + (seed * 37) % 300;
            for (std::size_t i = 0; i < cut; ++i) {
                const auto cmd = gen.next();
                log.push_back(s::encode_command(cmd));
                gen.observe(cmd, s::decode_result(x._sm->apply(log.back(), ++x._index)));
            }
            const auto snap = x._sm->get_state();

            // A fresh node restores the snapshot, fetching the active
            // segments it lacks from x, then replays the rest of the log.
            replica y;
            std::size_t fetched = 0;
            y._sm = std::make_unique<sm_type>(
                y._store.get(), [&](const kythira::record_segment_descriptor& d) {
                    const std::vector<std::string> peers{"x"};
                    ++fetched;
                    if (!y._store->fetch_segment(d, peers,
                                                 [&](const std::string&, const std::string& stream,
                                                     std::uint64_t first, std::uint64_t length) {
                                                     return x._store->read_segment_bytes(
                                                         stream, first, length);
                                                 })) {
                        throw kythira::record_segment_error("fetch failed");
                    }
                });
            y._sm->restore_from_snapshot(snap, cut);
            y._index = cut;
            BOOST_TEST(y._sm->get_state() == snap);

            // Sealed segments are fetched lazily on read; copy them now so
            // the logs can be compared whole.
            for (const auto* t : x._sm->list_topics(account)) {
                for (std::uint32_t p = 0; p < t->_partitions; ++p) {
                    for (const auto& d : x._sm->partition(t->_id, p)->_sealed) {
                        const std::vector<std::string> peers{"x"};
                        BOOST_TEST_REQUIRE(y._store->fetch_segment(
                            d, peers,
                            [&](const std::string&, const std::string& stream, std::uint64_t first,
                                std::uint64_t length) {
                                return x._store->read_segment_bytes(stream, first, length);
                            }));
                    }
                }
            }
            for (std::size_t i = cut; i < 500; ++i) {
                const auto cmd = gen.next();
                const auto bytes = s::encode_command(cmd);
                const auto rx = x._sm->apply(bytes, ++x._index);
                const auto ry = y._sm->apply(bytes, ++y._index);
                BOOST_TEST_REQUIRE(rx == ry);
                gen.observe(cmd, s::decode_result(rx));
            }
            BOOST_TEST(x._sm->get_state() == y._sm->get_state());
            BOOST_TEST(same_logs(x, y));
            BOOST_TEST_MESSAGE("seed " << seed << ": fetched " << fetched << " active segments");
        }
    }
}

BOOST_AUTO_TEST_CASE(a_restore_truncates_a_tail_past_the_snapshot) {
    replica x;
    x.run(create("t"));
    x.run(publish_one("t", "m1", 1000));
    const auto snap = x._sm->get_state();
    x.run(publish_one("t", "m2", 1000));
    x.run(publish_one("t", "m3", 1000));
    BOOST_TEST(log_of(x, 1, 0).size() == 3U);

    // The node crashed after writing m2 and m3 but its last snapshot covers
    // only m1: restoring drops the tail, and the log replays it.
    x._sm->restore_from_snapshot(snap, 2);
    x._index = 2;
    BOOST_TEST(log_of(x, 1, 0).size() == 1U);
    const auto again = x.run(publish_one("t", "m2", 1000));
    BOOST_TEST(again._entries[0]._seq == 2U);
    BOOST_TEST(log_of(x, 1, 0).size() == 2U);
}

BOOST_AUTO_TEST_CASE(a_snapshot_naming_a_missing_segment_needs_a_fetcher) {
    replica x;
    x.run(create("t"));
    x.run(publish_one("t", "m1", 1000));
    const auto snap = x._sm->get_state();
    replica y;
    BOOST_CHECK_THROW(y._sm->restore_from_snapshot(snap, 2), kythira::record_segment_error);
    // A store-less instance restores the same snapshot without fetching.
    sm_type bare;
    bare.restore_from_snapshot(snap, 2);
    BOOST_TEST(bare.find_topic(account, "t")->_id == 1U);
    BOOST_CHECK_THROW(bare.restore_from_snapshot({std::byte{9}}, 3), s::sns_codec_error);
}
