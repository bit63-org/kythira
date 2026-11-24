// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file append_entries_batcher_unit_test.cpp
/// @brief `append_entries_batcher` over a fake shared client, and the batch
///        handler `multi_group_network_server` installs
///        (`.kiro/specs/multi-raft-message-batching/` task 2 and 4,
///        Requirement 7.2).
///
/// The fake client records every lone send and every batch and hands their
/// promises to the test, so each case decides exactly how the peer answers:
/// per member, for the whole batch, with "not implemented", or "too large".
/// Nothing here touches a socket or a timer the test does not control,
/// except the one case that is about the batcher's own timer.

#define BOOST_TEST_MODULE append_entries_batcher_unit_test
#include <boost/test/unit_test.hpp>

#include <raft/append_entries_batcher.hpp>
#include <raft/exceptions.hpp>
#include <raft/future_default.hpp>
#include <raft/group_transport.hpp>
#include <raft/metrics.hpp>
#include <raft/network.hpp>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
#include <folly/init/Init.h>
#endif

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if !defined(KYTHIRA_FUTURE_BACKEND_STDEXEC) && !defined(KYTHIRA_FUTURE_BACKEND_BOOST)
namespace {
struct folly_init_fixture {
    folly_init_fixture() {
        int argc = 1;
        char* argv_data[] = {const_cast<char*>("append_entries_batcher_unit_test"), nullptr};
        char** argv = argv_data;
        _init = std::make_unique<folly::Init>(&argc, &argv);
    }
    std::unique_ptr<folly::Init> _init;
};
}  // namespace
BOOST_GLOBAL_FIXTURE(folly_init_fixture);
#endif

namespace {

using namespace std::chrono_literals;

using messages = kythira::group_rpc_messages<>;
using ae_request = messages::append_entries_request_type;
using ae_response = messages::append_entries_response_type;
using rv_request = messages::request_vote_request_type;
using rv_response = messages::request_vote_response_type;
using is_request = messages::install_snapshot_request_type;
using is_response = messages::install_snapshot_response_type;
using batch_request = kythira::append_entries_batch_request<ae_request>;
using batch_response = kythira::append_entries_batch_response<ae_response>;
using kythira::batch_member_error;
using kythira::batching_config;

template<typename T> using promise_ptr = std::shared_ptr<kythira::promise_default<T>>;

/// A shared client whose peers answer only when the test says so.
class fake_client {
public:
    struct batch_call {
        std::uint64_t _target;
        batch_request _request;
        std::chrono::milliseconds _timeout;
        promise_ptr<batch_response> _done;
    };
    struct lone_call {
        std::uint64_t _target;
        ae_request _request;
        std::chrono::milliseconds _timeout;
        promise_ptr<ae_response> _done;
    };

    auto send_append_entries(std::uint64_t target, const ae_request& req,
                             std::chrono::milliseconds timeout)
        -> kythira::future_default<ae_response> {
        auto p = std::make_shared<kythira::promise_default<ae_response>>();
        auto f = p->getFuture();
        std::function<void(lone_call&)> answer;
        lone_call call{target, req, timeout, p};
        {
            std::lock_guard lock(_mutex);
            _lones.push_back(call);
            answer = _answer_lone;
        }
        if (answer) {
            answer(call);
        }
        return f;
    }

    auto send_append_entries_batch(std::uint64_t target, const batch_request& req,
                                   std::chrono::milliseconds timeout)
        -> kythira::future_default<batch_response> {
        auto p = std::make_shared<kythira::promise_default<batch_response>>();
        auto f = p->getFuture();
        std::function<void(batch_call&)> answer;
        batch_call call{target, req, timeout, p};
        {
            std::lock_guard lock(_mutex);
            _batches.push_back(call);
            answer = _answer_batch;
        }
        if (answer) {
            answer(call);
        }
        return f;
    }

    // Unused by the batcher; present so `group_scoped_client` over this is a
    // `network_client` for the static checks below.
    auto send_request_vote(std::uint64_t, const rv_request&, std::chrono::milliseconds)
        -> kythira::future_default<rv_response> {
        return kythira::future_factory_default::makeExceptionalFuture<rv_response>(
            std::make_exception_ptr(std::logic_error("unused")));
    }
    auto send_install_snapshot(std::uint64_t, const is_request&, std::chrono::milliseconds)
        -> kythira::future_default<is_response> {
        return kythira::future_factory_default::makeExceptionalFuture<is_response>(
            std::make_exception_ptr(std::logic_error("unused")));
    }

    auto answer_batches_with(std::function<void(batch_call&)> f) -> void {
        std::lock_guard lock(_mutex);
        _answer_batch = std::move(f);
    }
    auto answer_lones_with(std::function<void(lone_call&)> f) -> void {
        std::lock_guard lock(_mutex);
        _answer_lone = std::move(f);
    }

    [[nodiscard]] auto batches() -> std::vector<batch_call> {
        std::lock_guard lock(_mutex);
        return _batches;
    }
    [[nodiscard]] auto lones() -> std::vector<lone_call> {
        std::lock_guard lock(_mutex);
        return _lones;
    }

private:
    std::mutex _mutex;
    std::vector<batch_call> _batches;
    std::vector<lone_call> _lones;
    std::function<void(batch_call&)> _answer_batch;
    std::function<void(lone_call&)> _answer_lone;
};

/// The same client without the batch RPC.
class lone_only_client {
public:
    auto send_append_entries(std::uint64_t, const ae_request&, std::chrono::milliseconds)
        -> kythira::future_default<ae_response> {
        return kythira::future_factory_default::makeExceptionalFuture<ae_response>(
            std::make_exception_ptr(std::logic_error("unused")));
    }
    auto send_request_vote(std::uint64_t, const rv_request&, std::chrono::milliseconds)
        -> kythira::future_default<rv_response> {
        return kythira::future_factory_default::makeExceptionalFuture<rv_response>(
            std::make_exception_ptr(std::logic_error("unused")));
    }
    auto send_install_snapshot(std::uint64_t, const is_request&, std::chrono::milliseconds)
        -> kythira::future_default<is_response> {
        return kythira::future_factory_default::makeExceptionalFuture<is_response>(
            std::make_exception_ptr(std::logic_error("unused")));
    }
};

using batcher_type = kythira::append_entries_batcher<fake_client, messages>;

// Requirement 1.1 / 1.2: batching is detected, never assumed.
static_assert(kythira::network_client_with_append_entries_batch<fake_client>);
static_assert(kythira::append_entries_batching_client<fake_client, messages>);
static_assert(!kythira::network_client_with_append_entries_batch<lone_only_client>);
static_assert(!kythira::append_entries_batching_client<lone_only_client, messages>);
static_assert(kythira::network_client<kythira::group_scoped_client<fake_client>>);
static_assert(kythira::network_client<kythira::group_scoped_client<lone_only_client>>);

auto append_for(std::uint64_t group, std::uint64_t term, std::size_t entry_bytes = 0)
    -> ae_request {
    ae_request req{._term = term,
                   ._leader_id = 1,
                   ._prev_log_index = 0,
                   ._prev_log_term = 0,
                   ._entries = {},
                   ._leader_commit = 0,
                   ._group_id = group};
    if (entry_bytes > 0) {
        req._entries.push_back(
            {._term = term, ._index = 1, ._command = std::vector<std::byte>(entry_bytes)});
    }
    return req;
}

auto ok_for(const ae_request& req) -> ae_response {
    return ae_response{._term = req.term(),
                       ._success = true,
                       ._conflict_index = std::nullopt,
                       ._conflict_term = std::nullopt,
                       ._group_id = req.group_id()};
}

/// A peer that answers every member with success at the member's own term.
auto answer_all_ok(fake_client::batch_call& call) -> void {
    batch_response out;
    for (const auto& m : call._request._members) {
        out._members.emplace_back(ok_for(m));
    }
    call._done->setValue(std::move(out));
}

auto answer_lone_ok(fake_client::lone_call& call) -> void {
    call._done->setValue(ok_for(call._request));
}

auto config(std::size_t max_messages = 256, std::size_t max_bytes = std::size_t{1} << 20U)
    -> batching_config {
    return batching_config{._enabled = true,
                           ._max_messages = max_messages,
                           ._max_bytes = max_bytes,
                           ._max_delay = std::chrono::microseconds{500},
                           ._probe_interval = std::chrono::milliseconds{50}};
}

template<typename Pred> auto eventually(Pred pred, std::chrono::milliseconds limit = 2s) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

template<typename Exception, typename Future> auto fails_with(Future f) -> bool {
    try {
        std::move(f).get();
    } catch (const Exception&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(append_entries_batcher_suite)

// Requirement 2.1 and 3.1: one batch per destination, each member's future
// completes with its own response.
BOOST_AUTO_TEST_CASE(each_member_gets_its_own_response) {
    fake_client client;
    batcher_type batcher(client, config());

    auto a = batcher.send(2, append_for(10, 3), 100ms);
    auto b = batcher.send(2, append_for(11, 4), 100ms);
    auto c = batcher.send(3, append_for(12, 5), 100ms);
    BOOST_TEST(client.batches().empty());
    BOOST_TEST(batcher.queued() == 3U);

    batcher.flush_all();
    auto batches = client.batches();
    BOOST_REQUIRE_EQUAL(batches.size(), 2U);
    for (auto& call : batches) {
        answer_all_ok(call);
    }

    const auto ra = std::move(a).get();
    const auto rb = std::move(b).get();
    const auto rc = std::move(c).get();
    BOOST_TEST(ra.group_id() == 10U);
    BOOST_TEST(ra.term() == 3U);
    BOOST_TEST(rb.group_id() == 11U);
    BOOST_TEST(rb.term() == 4U);
    BOOST_TEST(rc.group_id() == 12U);
    BOOST_TEST(batcher.batches_sent() == 2U);
    BOOST_TEST(batcher.members_sent() == 3U);
    BOOST_TEST(batcher.queued() == 0U);
    BOOST_TEST(client.lones().empty());
}

// Requirement 2.2: a whole-batch failure fails every member with it.
BOOST_AUTO_TEST_CASE(a_failed_batch_fails_every_member) {
    fake_client client;
    batcher_type batcher(client, config());
    auto a = batcher.send(2, append_for(10, 1), 100ms);
    auto b = batcher.send(2, append_for(11, 1), 100ms);
    batcher.flush_all();
    auto batches = client.batches();
    BOOST_REQUIRE_EQUAL(batches.size(), 1U);
    batches[0]._done->setException(
        std::make_exception_ptr(kythira::network_exception("connection refused")));
    BOOST_TEST(fails_with<kythira::network_exception>(std::move(a)));
    BOOST_TEST(fails_with<kythira::network_exception>(std::move(b)));
    BOOST_TEST(client.lones().empty());
    BOOST_TEST(batcher.marked_destinations() == 0U);
}

// Requirement 2.3: an unknown group gets the lone-message refusal, and its
// neighbours are untouched; a member whose handler failed fails alone.
BOOST_AUTO_TEST_CASE(member_errors_stay_with_their_member) {
    fake_client client;
    batcher_type batcher(client, config());
    auto known = batcher.send(2, append_for(10, 7), 100ms);
    auto unknown = batcher.send(2, append_for(99, 8), 100ms);
    auto broken = batcher.send(2, append_for(11, 9), 100ms);
    batcher.flush_all();
    auto batches = client.batches();
    BOOST_REQUIRE_EQUAL(batches.size(), 1U);
    batch_response out;
    out._members.emplace_back(ok_for(batches[0]._request._members[0]));
    out._members.emplace_back(
        batch_member_error{._kind = batch_member_error::kind_type::unknown_group});
    out._members.emplace_back(batch_member_error{
        ._kind = batch_member_error::kind_type::handler_failed, ._message = "boom"});
    batches[0]._done->setValue(std::move(out));

    BOOST_TEST(std::move(known).get().success());
    const auto refused = std::move(unknown).get();
    BOOST_TEST(!refused.success());
    BOOST_TEST(refused.term() == 8U);
    BOOST_TEST(refused.group_id() == 99U);
    BOOST_TEST(!refused.conflict_index().has_value());
    BOOST_TEST(fails_with<kythira::network_exception>(std::move(broken)));
}

// A peer that answers the wrong number of members has broken the protocol;
// nothing it said can be matched to a member.
BOOST_AUTO_TEST_CASE(a_short_answer_fails_every_member) {
    fake_client client;
    batcher_type batcher(client, config());
    auto a = batcher.send(2, append_for(10, 1), 100ms);
    auto b = batcher.send(2, append_for(11, 1), 100ms);
    batcher.flush_all();
    auto batches = client.batches();
    batch_response out;
    out._members.emplace_back(ok_for(batches[0]._request._members[0]));
    batches[0]._done->setValue(std::move(out));
    BOOST_TEST(fails_with<kythira::network_exception>(std::move(a)));
    BOOST_TEST(fails_with<kythira::network_exception>(std::move(b)));
}

// Requirement 2.4: a group's messages leave in the order they were sent,
// within a batch and across batches.
BOOST_AUTO_TEST_CASE(a_groups_messages_keep_their_order) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config());
    auto first = batcher.send(2, append_for(10, 1), 100ms);
    auto other = batcher.send(2, append_for(11, 1), 100ms);
    auto second = batcher.send(2, append_for(10, 2), 100ms);
    batcher.flush_all();
    auto third = batcher.send(2, append_for(10, 3), 100ms);
    batcher.flush_all();

    auto batches = client.batches();
    BOOST_REQUIRE_EQUAL(batches.size(), 2U);
    const auto& m = batches[0]._request._members;
    BOOST_REQUIRE_EQUAL(m.size(), 3U);
    BOOST_TEST(m[0].group_id() == 10U);
    BOOST_TEST(m[0].term() == 1U);
    BOOST_TEST(m[1].group_id() == 11U);
    BOOST_TEST(m[2].group_id() == 10U);
    BOOST_TEST(m[2].term() == 2U);
    BOOST_REQUIRE_EQUAL(batches[1]._request._members.size(), 1U);
    BOOST_TEST(batches[1]._request._members[0].term() == 3U);
    BOOST_TEST(std::move(first).get().term() == 1U);
    BOOST_TEST(std::move(other).get().group_id() == 11U);
    BOOST_TEST(std::move(second).get().term() == 2U);
    BOOST_TEST(std::move(third).get().term() == 3U);
}

// Requirement 2.5: the batch waits no longer than its shortest member.
BOOST_AUTO_TEST_CASE(the_batch_timeout_is_the_shortest_members) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config());
    auto a = batcher.send(2, append_for(10, 1), 300ms);
    auto b = batcher.send(2, append_for(11, 1), 40ms);
    auto c = batcher.send(2, append_for(12, 1), 900ms);
    batcher.flush_all();
    auto batches = client.batches();
    BOOST_REQUIRE_EQUAL(batches.size(), 1U);
    BOOST_TEST(batches[0]._timeout.count() == 40);
    std::move(a).get();
    std::move(b).get();
    std::move(c).get();
}

// Requirement 3.3: a full queue leaves at once, by count or by bytes.
BOOST_AUTO_TEST_CASE(a_full_queue_is_flushed_without_waiting) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    {
        batcher_type batcher(client, config(3));
        auto a = batcher.send(2, append_for(10, 1), 100ms);
        auto b = batcher.send(2, append_for(11, 1), 100ms);
        BOOST_TEST(client.batches().empty());
        auto c = batcher.send(2, append_for(12, 1), 100ms);
        BOOST_REQUIRE_EQUAL(client.batches().size(), 1U);
        BOOST_TEST(client.batches()[0]._request._members.size() == 3U);
        std::move(a).get();
        std::move(b).get();
        std::move(c).get();
    }
    fake_client by_bytes;
    by_bytes.answer_batches_with(answer_all_ok);
    {
        // Each member is estimated at well over 1000 bytes, so the second
        // closes the first's batch and the third fills its own.
        batcher_type batcher(by_bytes, config(256, 2500));
        auto a = batcher.send(2, append_for(10, 1, 1000), 100ms);
        BOOST_TEST(by_bytes.batches().empty());
        auto b = batcher.send(2, append_for(11, 1, 1000), 100ms);
        auto c = batcher.send(2, append_for(12, 1, 1000), 100ms);
        auto batches = by_bytes.batches();
        BOOST_REQUIRE_EQUAL(batches.size(), 1U);
        BOOST_TEST(batches[0]._request._members.size() == 2U);
        batcher.flush_all();
        BOOST_REQUIRE_EQUAL(by_bytes.batches().size(), 2U);
        std::move(a).get();
        std::move(b).get();
        std::move(c).get();
    }
}

// A member's continuation that sends again must not find the batcher's
// locks held. The client here answers inside the call, so the batch future
// is already complete when the batcher attaches its completion; on the
// Folly backend that completion, and the member continuation below, run on
// the sending thread at once. The continuation's two sends fill a batch to
// the same destination, which takes that destination's send lock: before
// the fix the batcher still held it, and this deadlocked. Backends that
// run continuations elsewhere pass either way.
BOOST_AUTO_TEST_CASE(a_completion_may_send_to_the_same_destination) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config(2));

    std::promise<std::size_t> finished;
    auto done = finished.get_future();
    std::thread scenario([&] {
        try {
            std::vector<kythira::future_default<ae_response>> again;
            std::mutex again_mutex;
            auto a = batcher.send(2, append_for(10, 1), 100ms);
            auto chained = std::move(a).thenValue([&](ae_response) {
                auto c = batcher.send(2, append_for(12, 1), 100ms);
                auto d = batcher.send(2, append_for(13, 1), 100ms);
                std::lock_guard lock(again_mutex);
                again.push_back(std::move(c));
                again.push_back(std::move(d));
            });
            auto b = batcher.send(2, append_for(11, 1), 100ms);  // fills the first batch
            std::move(chained).get();
            std::move(b).get();
            std::vector<kythira::future_default<ae_response>> sent;
            {
                std::lock_guard lock(again_mutex);
                sent = std::move(again);
            }
            for (auto& f : sent) {
                std::move(f).get();
            }
            finished.set_value(client.batches().size());
        } catch (...) {
            finished.set_exception(std::current_exception());
        }
    });
    if (done.wait_for(10s) != std::future_status::ready) {
        // A deadlocked thread cannot be joined; report and leave at once.
        std::fprintf(stderr, "a_completion_may_send_to_the_same_destination: deadlocked\n");
        std::_Exit(1);
    }
    scenario.join();
    BOOST_TEST(done.get() == 2U);
}

// Requirement 3.4: a member too big for any batch goes alone.
BOOST_AUTO_TEST_CASE(an_oversized_member_is_sent_alone) {
    fake_client client;
    client.answer_lones_with(answer_lone_ok);
    batcher_type batcher(client, config(256, 1000));
    auto big = batcher.send(2, append_for(10, 1, 5000), 100ms);
    BOOST_TEST(std::move(big).get().success());
    BOOST_TEST(client.lones().size() == 1U);
    BOOST_TEST(client.batches().empty());
    BOOST_TEST(batcher.oversized_sent() == 1U);
    BOOST_TEST(batcher.queued() == 0U);
}

// Requirement 3.2: a message sent outside the send phase is not stranded;
// the batcher's timer sends it on its own.
BOOST_AUTO_TEST_CASE(the_timer_flushes_off_tick_sends) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config());
    batcher.start();
    const auto t0 = std::chrono::steady_clock::now();
    auto a = batcher.send(2, append_for(10, 1), 100ms);
    BOOST_TEST(std::move(a).get().success());
    // `_max_delay` is 500 us; a generous ceiling keeps a loaded CI box quiet
    // while still failing if the timer never fired.
    BOOST_TEST((std::chrono::steady_clock::now() - t0 < 1s));
    BOOST_TEST(client.batches().size() == 1U);

    // And it goes back to sleep: a later message is sent the same way.
    std::this_thread::sleep_for(5ms);
    auto b = batcher.send(3, append_for(11, 1), 100ms);
    BOOST_TEST(std::move(b).get().success());
    BOOST_TEST(client.batches().size() == 2U);
    batcher.stop();
}

// `stop()` sends whatever is still queued rather than stranding it.
BOOST_AUTO_TEST_CASE(stop_sends_what_is_queued) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config());
    auto a = batcher.send(2, append_for(10, 1), 100ms);
    batcher.stop();
    BOOST_TEST(client.batches().size() == 1U);
    BOOST_TEST(std::move(a).get().success());
}

// Requirement 4.1 / 4.2: an older peer gets every member again, alone; the
// destination is skipped until the probe interval passes, then probed.
BOOST_AUTO_TEST_CASE(an_older_peer_is_sent_to_alone_until_the_probe) {
    fake_client client;
    client.answer_lones_with(answer_lone_ok);
    client.answer_batches_with([](fake_client::batch_call& call) {
        call._done->setException(std::make_exception_ptr(
            kythira::rpc_not_implemented_exception("append_entries_batch", call._target)));
    });
    batcher_type batcher(client, config());
    std::vector<std::string> logged;
    batcher.set_info_logger([&](const std::string& m) { logged.push_back(m); });

    auto a = batcher.send(2, append_for(10, 1), 100ms);
    auto b = batcher.send(2, append_for(11, 1), 100ms);
    batcher.flush_all();
    BOOST_TEST(std::move(a).get().group_id() == 10U);
    BOOST_TEST(std::move(b).get().group_id() == 11U);
    auto lones = client.lones();
    BOOST_REQUIRE_EQUAL(lones.size(), 2U);
    BOOST_TEST(lones[0]._request.group_id() == 10U);
    BOOST_TEST(lones[1]._request.group_id() == 11U);
    BOOST_TEST(batcher.fallbacks() == 1U);
    BOOST_TEST(batcher.marked_destinations() == 1U);
    BOOST_TEST(logged.size() == 1U);

    // While marked: straight through, no queue, no flush needed.
    auto c = batcher.send(2, append_for(12, 1), 100ms);
    BOOST_TEST(std::move(c).get().group_id() == 12U);
    BOOST_TEST(client.lones().size() == 3U);
    BOOST_TEST(client.batches().size() == 1U);

    // Other destinations still batch.
    client.answer_batches_with(answer_all_ok);
    auto d = batcher.send(3, append_for(13, 1), 100ms);
    batcher.flush_all();
    BOOST_TEST(std::move(d).get().success());
    BOOST_TEST(client.batches().size() == 2U);

    // After the probe interval the upgraded peer is batched to again.
    std::this_thread::sleep_for(80ms);
    BOOST_TEST(batcher.marked_destinations() == 0U);
    auto e = batcher.send(2, append_for(14, 1), 100ms);
    batcher.flush_all();
    BOOST_TEST(std::move(e).get().success());
    BOOST_TEST(client.batches().size() == 3U);
    BOOST_TEST(client.lones().size() == 3U);
}

// Requirement 5.4: "too large" resends that batch alone, without marking.
BOOST_AUTO_TEST_CASE(a_too_large_batch_is_resent_alone_without_marking) {
    fake_client client;
    client.answer_lones_with(answer_lone_ok);
    client.answer_batches_with([](fake_client::batch_call& call) {
        call._done->setException(std::make_exception_ptr(
            kythira::rpc_payload_too_large_exception("413 Payload Too Large")));
    });
    batcher_type batcher(client, config());
    auto a = batcher.send(2, append_for(10, 1), 100ms);
    auto b = batcher.send(2, append_for(11, 1), 100ms);
    batcher.flush_all();
    BOOST_TEST(std::move(a).get().success());
    BOOST_TEST(std::move(b).get().success());
    BOOST_TEST(client.lones().size() == 2U);
    BOOST_TEST(batcher.fallbacks() == 1U);
    BOOST_TEST(batcher.marked_destinations() == 0U);

    // The next message is queued for a batch again.
    auto c = batcher.send(2, append_for(12, 1), 100ms);
    BOOST_TEST(client.lones().size() == 2U);
    batcher.flush_all();
    BOOST_TEST(client.batches().size() == 2U);
    BOOST_TEST(std::move(c).get().success());
}

// A host over a client without the batch RPC still names the batcher type
// in its `unique_ptr` member, which instantiates the destructor. That must
// compile, and an unbuilt batcher must cost nothing.
BOOST_AUTO_TEST_CASE(a_non_batching_client_can_still_name_the_batcher) {
    std::unique_ptr<kythira::append_entries_batcher<lone_only_client, messages>> none;
    BOOST_TEST(none == nullptr);
    lone_only_client client;
    {
        kythira::append_entries_batcher<lone_only_client, messages> unused(client, config());
        BOOST_TEST(unused.batches_sent() == 0U);
    }
}

BOOST_AUTO_TEST_CASE(the_histogram_counts_members_per_batch) {
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    batcher_type batcher(client, config());
    std::vector<kythira::future_default<ae_response>> futures;
    futures.push_back(batcher.send(2, append_for(10, 1), 100ms));
    batcher.flush_all();
    for (std::uint64_t g = 0; g < 5; ++g) {
        futures.push_back(batcher.send(2, append_for(20 + g, 1), 100ms));
    }
    batcher.flush_all();
    for (auto& f : futures) {
        std::move(f).get();
    }
    const auto h = batcher.members_per_batch_histogram();
    BOOST_TEST(h[0] == 1U);  // a batch of 1
    BOOST_TEST(h[3] == 1U);  // a batch of 5: in (4, 8]
}

/// A metrics sink that keeps each emission's name, dimensions and amount.
class counting_metrics {
public:
    struct emission {
        std::string _name;
        std::map<std::string, std::string> _dims;
        std::int64_t _count{0};
        double _value{0};
    };

    auto set_metric_name(std::string_view name) -> void { _pending._name = name; }
    auto add_dimension(std::string_view k, std::string_view v) -> void {
        _pending._dims.emplace(std::string(k), std::string(v));
    }
    auto add_one() -> void { ++_pending._count; }
    auto add_count(std::int64_t n) -> void { _pending._count += n; }
    auto add_duration(std::chrono::nanoseconds) -> void {}
    auto add_value(double v) -> void { _pending._value = v; }
    auto emit() -> void {
        _emitted.push_back(std::move(_pending));
        _pending = {};
    }

    [[nodiscard]] auto emitted() const -> const std::vector<emission>& { return _emitted; }
    auto clear() -> void { _emitted.clear(); }
    [[nodiscard]] auto total(std::string_view name) const -> std::int64_t {
        std::int64_t sum = 0;
        for (const auto& e : _emitted) {
            if (e._name == name) {
                sum += e._count;
            }
        }
        return sum;
    }

private:
    emission _pending;
    std::vector<emission> _emitted;
};
static_assert(kythira::metrics<counting_metrics>);

// Requirement 6.2: batches, fallbacks, members per batch and marked
// destinations reach the host's metrics, each as the change since the last
// publish.
BOOST_AUTO_TEST_CASE(metrics_publish_the_change_since_last_time) {
    using emitter = kythira::batching_metrics_emitter;
    fake_client client;
    client.answer_batches_with(answer_all_ok);
    client.answer_lones_with(answer_lone_ok);
    batcher_type batcher(client, config());
    emitter publisher;
    counting_metrics sink;

    // Nothing sent: nothing emitted.
    publisher.publish(batcher, sink);
    BOOST_TEST(sink.emitted().empty());

    std::vector<kythira::future_default<ae_response>> futures;
    futures.push_back(batcher.send(2, append_for(10, 1), 100ms));
    batcher.flush_all();
    for (std::uint64_t g = 0; g < 5; ++g) {
        futures.push_back(batcher.send(2, append_for(20 + g, 1), 100ms));
    }
    batcher.flush_all();
    for (auto& f : futures) {
        std::move(f).get();
    }
    futures.clear();

    publisher.publish(batcher, sink);
    BOOST_TEST(sink.total(emitter::k_batches) == 2);
    BOOST_TEST(sink.total(emitter::k_fallbacks) == 0);
    std::map<std::string, std::int64_t> buckets;
    for (const auto& e : sink.emitted()) {
        if (e._name == emitter::k_members_per_batch) {
            buckets[e._dims.at("max_members")] += e._count;
        }
    }
    BOOST_TEST(buckets.size() == 2U);
    BOOST_TEST(buckets["1"] == 1);
    BOOST_TEST(buckets["8"] == 1);

    // Unchanged since: a second publish emits nothing.
    sink.clear();
    publisher.publish(batcher, sink);
    BOOST_TEST(sink.emitted().empty());

    // An older peer: one fallback, one marked destination, and the gauge
    // goes back to zero once the probe interval passes.
    client.answer_batches_with([](fake_client::batch_call& call) {
        call._done->setException(std::make_exception_ptr(
            kythira::rpc_not_implemented_exception("append_entries_batch", call._target)));
    });
    futures.push_back(batcher.send(3, append_for(30, 1), 100ms));
    batcher.flush_all();
    std::move(futures.back()).get();
    publisher.publish(batcher, sink);
    BOOST_TEST(sink.total(emitter::k_batches) == 1);
    BOOST_TEST(sink.total(emitter::k_fallbacks) == 1);
    const auto gauge = [&] {
        std::optional<double> last;
        for (const auto& e : sink.emitted()) {
            if (e._name == emitter::k_marked_destinations) {
                last = e._value;
            }
        }
        return last;
    };
    BOOST_TEST((gauge() == std::optional<double>{1.0}));

    sink.clear();
    std::this_thread::sleep_for(80ms);
    publisher.publish(batcher, sink);
    BOOST_TEST((gauge() == std::optional<double>{0.0}));
}

BOOST_AUTO_TEST_SUITE_END()

// ── the receiving side: multi_group_network_server's batch handler ───────────

namespace {

/// A server with an AppendEntries and a batch slot, fed by the test.
class batch_server {
public:
    auto register_request_vote_handler(std::function<rv_response(const rv_request&)> h) -> void {
        _rv = std::move(h);
    }
    auto register_append_entries_handler(std::function<ae_response(const ae_request&)> h) -> void {
        _ae = std::move(h);
    }
    auto register_install_snapshot_handler(std::function<is_response(const is_request&)> h)
        -> void {
        _is = std::move(h);
    }
    auto register_append_entries_batch_handler(
        std::function<batch_response(const batch_request&)> h) -> void {
        _batch = std::move(h);
    }
    auto start() -> void { _running = true; }
    auto stop() -> void { _running = false; }
    [[nodiscard]] auto is_running() const -> bool { return _running; }

    [[nodiscard]] auto deliver(const ae_request& r) const -> ae_response { return _ae(r); }
    [[nodiscard]] auto deliver(const batch_request& r) const -> batch_response { return _batch(r); }

private:
    std::function<rv_response(const rv_request&)> _rv;
    std::function<ae_response(const ae_request&)> _ae;
    std::function<is_response(const is_request&)> _is;
    std::function<batch_response(const batch_request&)> _batch;
    bool _running{false};
};

static_assert(kythira::network_server<batch_server>);
static_assert(kythira::network_server_with_append_entries_batch<batch_server>);

using batch_demux = kythira::multi_group_network_server<batch_server, std::uint64_t, messages>;

}  // namespace

BOOST_AUTO_TEST_SUITE(batch_dispatch_suite)

// Requirement 2.3, 2.4, 2.6: each member through the group lookup, in order;
// an unknown group's member gets exactly the lone-message refusal; a throwing
// handler fails only its own member.
BOOST_AUTO_TEST_CASE(members_are_dispatched_by_group_in_order) {
    batch_demux demux{batch_server{}};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> seen;  // (group, term)
    std::vector<std::uint64_t> observed;
    demux.set_message_observer([&](const std::uint64_t& g) { observed.push_back(g); });
    for (std::uint64_t g : {1U, 2U, 3U}) {
        kythira::group_rpc_handlers<messages> h;
        h._group = g;
        h._append_entries = [&seen, g](const ae_request& r) {
            if (g == 3) {
                throw std::runtime_error("handler exploded");
            }
            seen.emplace_back(r.group_id(), r.term());
            return ok_for(r);
        };
        demux.register_group(g, h);
    }
    demux.start();

    batch_request batch;
    batch._members = {append_for(1, 5), append_for(2, 6), append_for(1, 7), append_for(42, 8),
                      append_for(3, 9)};
    const auto out = demux.inner().deliver(batch);
    BOOST_REQUIRE_EQUAL(out._members.size(), 5U);

    BOOST_TEST(std::get<0>(out._members[0]).term() == 5U);
    BOOST_TEST(std::get<0>(out._members[1]).group_id() == 2U);
    BOOST_TEST(std::get<0>(out._members[2]).term() == 7U);

    // Unknown group: the very response a lone message gets.
    const auto lone = demux.inner().deliver(append_for(42, 8));
    const auto& member = std::get<0>(out._members[3]);
    BOOST_TEST(member.success() == lone.success());
    BOOST_TEST(member.term() == lone.term());
    BOOST_TEST(member.group_id() == 42U);
    BOOST_TEST(!member.success());

    const auto& err = std::get<1>(out._members[4]);
    BOOST_TEST((err.kind() == batch_member_error::kind_type::handler_failed));
    BOOST_TEST(err.message() == "handler exploded");

    // Order within group 1 is the batch's order.
    BOOST_REQUIRE_EQUAL(seen.size(), 3U);
    BOOST_TEST(seen[0].second == 5U);
    BOOST_TEST(seen[1].first == 2U);
    BOOST_TEST(seen[2].second == 7U);

    // Every member counts as a wake signal for its group, as a lone message does.
    BOOST_REQUIRE_GE(observed.size(), 5U);
    BOOST_TEST(observed[0] == 1U);
    BOOST_TEST(observed[3] == 42U);
    BOOST_TEST(observed[4] == 3U);
}

BOOST_AUTO_TEST_SUITE_END()
