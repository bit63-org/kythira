// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Long polling (`.kiro/specs/sqs-compatible-queues/` task 5, Requirements
// 6.1-6.3 and 12.1): the availability hub on its own; then receives through
// the front end over a local_queue_cluster whose state machine notifies the
// hub and whose tick worker turns passed deadlines into committed ticks. A
// parked receive answers as soon as a send commits, when a delay or a
// visibility timeout ends, empty when its wait ends, and empty at once
// when the hub drains. The cluster runs on the real clock, so the timing
// checks leave wide margins.

#define BOOST_TEST_MODULE sqs_long_poll_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_long_poll.hpp>
#include <kythira/sqs/sqs_service.hpp>
#include <kythira/sqs/sqs_workers.hpp>

#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace sqs = kythira::sqs;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

auto sign(sqs::sqs_request r) -> sqs::sqs_request {
    sv4::service_rules rules;
    rules.service = "sqs";
    const sv4::credential_scope scope{"20261118", "us-east-1", "sqs"};
    r._headers.emplace_back("Authorization",
                            "AWS4-HMAC-SHA256 Credential=AKIDADMIN/" + scope.text() +
                                ", SignedHeaders=content-type;host;x-amz-date;x-amz-target"
                                ", Signature=" +
                                std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r._method, r._path, r._query, r._headers, r._body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r._headers.back().second.replace(r._headers.back().second.size() - 64, 64, sig);
    return r;
}

using service_t = sqs::sqs_service<sqs::local_queue_cluster>;
using worker_t = sqs::tick_worker<sqs::local_queue_cluster>;

struct fixture {
    sqs::availability_hub hub;
    sqs::local_queue_cluster cluster;
    worker_t worker{cluster, [](const std::string&) { return true; },
                    worker_t::options{._idle = 5000ms, ._min_gap = 5ms}};
    az::static_key_authorizer auth{
        std::vector<az::static_key>{
            {"AKIDADMIN", std::string(k_secret), "111122223333", "admin", az::static_role::admin}},
        "aws", [] { return std::chrono::system_clock::time_point(k_now); }};
    std::unique_ptr<sqs::sqs_front_end<az::static_key_authorizer>> fe;
    std::unique_ptr<service_t> service;
    std::string url;

    fixture() {
        auth.register_service(sqs::sqs_static_roles());
        fe = std::make_unique<sqs::sqs_front_end<az::static_key_authorizer>>(
            sqs::sqs_front_end_config{}, auth);
        sqs::sqs_service_config cfg;
        cfg._receipt_keys = sqs::derived_receipt_key("forwarding-secret");
        cfg._waits = &hub;
        service = std::make_unique<service_t>(cluster, cfg);
        service->register_with(*fe);
        cluster.set_availability_listener([this](const sqs::queue_target& t, bool visible) {
            if (visible) {
                hub.notify(sqs::queue_keys::partition_prefix(t));
            }
            worker.wake();
        });
        worker.start();
        url = std::string(call("CreateQueue", {{"QueueName", "jobs"}}).at("QueueUrl").as_string());
    }
    ~fixture() {
        worker.stop();
        cluster.set_availability_listener({});
    }
    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;
    fixture(fixture&&) = delete;
    auto operator=(fixture&&) -> fixture& = delete;

    auto call(std::string_view op, const json::object& in) -> json::object {
        sqs::sqs_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(in);
        r._source_ip = "192.0.2.10";
        r._headers = {{"Host", "localhost:9324"},
                      {"Content-Type", "application/x-amz-json-1.0"},
                      {"X-Amz-Date", "20261118T120000Z"},
                      {"X-Amz-Target", "AmazonSQS." + std::string(op)}};
        const auto out = fe->handle(sign(std::move(r)));
        BOOST_TEST_REQUIRE(out.status == 200U, out.body);
        return out.body.empty() ? json::object{} : json::parse(out.body).as_object();
    }

    /// A receive on another thread, with how long it took.
    struct timed {
        json::object body;
        std::chrono::milliseconds took{};
    };
    auto receive_async(json::object in) -> std::future<timed> {
        in["QueueUrl"] = url;
        return std::async(std::launch::async, [this, in] {
            const auto start = std::chrono::steady_clock::now();
            auto body = call("ReceiveMessage", in);
            return timed{std::move(body), std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::steady_clock::now() - start)};
        });
    }

    /// Waits until a receive has parked on the hub.
    void until_parked() {
        const auto end = std::chrono::steady_clock::now() + 5s;
        while (hub.parked() == 0 && std::chrono::steady_clock::now() < end) {
            std::this_thread::sleep_for(5ms);
        }
        BOOST_TEST_REQUIRE(hub.parked() > 0U);
    }

    static auto bodies(const json::object& o) -> std::vector<std::string> {
        std::vector<std::string> out;
        if (const auto* m = o.if_contains("Messages"); m != nullptr) {
            for (const auto& v : m->as_array()) {
                out.emplace_back(v.at("Body").as_string());
            }
        }
        return out;
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(hub)

BOOST_AUTO_TEST_CASE(a_notification_before_the_wait_is_not_lost) {
    sqs::availability_hub h;
    auto sub = h.subscribe({"a", "b"});
    BOOST_TEST(h.parked() == 1U);
    h.notify("c");
    h.notify("b");
    BOOST_TEST((sub.wait_until(std::chrono::steady_clock::now() + 1s) ==
                sqs::availability_hub::wake::ready));
    BOOST_TEST((sub.wait_until(std::chrono::steady_clock::now() + 20ms) ==
                sqs::availability_hub::wake::timed_out));
}

BOOST_AUTO_TEST_CASE(close_wakes_parked_and_later_subscriptions) {
    sqs::availability_hub h;
    auto sub = h.subscribe({"a"});
    auto waiting = std::async(
        std::launch::async, [&] { return sub.wait_until(std::chrono::steady_clock::now() + 10s); });
    std::this_thread::sleep_for(20ms);
    h.close();
    BOOST_TEST((waiting.get() == sqs::availability_hub::wake::closed));
    auto late = h.subscribe({"a"});
    BOOST_TEST((late.wait_until(std::chrono::steady_clock::now() + 10s) ==
                sqs::availability_hub::wake::closed));
    h.reopen();
    auto again = h.subscribe({"a"});
    BOOST_TEST((again.wait_until(std::chrono::steady_clock::now() + 10ms) ==
                sqs::availability_hub::wake::timed_out));
}

BOOST_AUTO_TEST_CASE(a_subscription_unsubscribes_when_destroyed) {
    sqs::availability_hub h;
    {
        auto sub = h.subscribe({"a"});
        BOOST_TEST(h.parked() == 1U);
    }
    BOOST_TEST(h.parked() == 0U);
    h.notify("a");
    BOOST_TEST(h.notified() == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(long_poll)

BOOST_FIXTURE_TEST_CASE(a_parked_receive_answers_when_a_send_commits, fixture) {
    auto r = receive_async({{"WaitTimeSeconds", 10}});
    until_parked();
    call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "wake up"}});
    const auto got = r.get();
    BOOST_TEST((bodies(got.body) == std::vector<std::string>{"wake up"}));
    BOOST_TEST(got.took.count() < 5000);
    BOOST_TEST(hub.parked() == 0U);
}

BOOST_FIXTURE_TEST_CASE(an_empty_wait_answers_empty_when_it_ends, fixture) {
    auto r = receive_async({{"WaitTimeSeconds", 1}});
    const auto got = r.get();
    BOOST_TEST(bodies(got.body).empty());
    BOOST_TEST(got.took.count() >= 900);
    BOOST_TEST(got.took.count() < 5000);
}

BOOST_FIXTURE_TEST_CASE(the_queue_wait_applies_without_wait_time_seconds, fixture) {
    call("SetQueueAttributes",
         {{"QueueUrl", url}, {"Attributes", {{"ReceiveMessageWaitTimeSeconds", "1"}}}});
    auto r = receive_async({});
    const auto parked_got = r.get();
    BOOST_TEST(parked_got.took.count() >= 900);
    // WaitTimeSeconds=0 overrides the queue's wait: a short poll.
    auto s = receive_async({{"WaitTimeSeconds", 0}});
    BOOST_TEST(s.get().took.count() < 900);
}

BOOST_FIXTURE_TEST_CASE(a_delay_ending_wakes_a_parked_receive, fixture) {
    auto r = receive_async({{"WaitTimeSeconds", 10}});
    until_parked();
    call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "later"}, {"DelaySeconds", 1}});
    const auto got = r.get();
    BOOST_TEST((bodies(got.body) == std::vector<std::string>{"later"}));
    BOOST_TEST(got.took.count() >= 900);
    BOOST_TEST(got.took.count() < 5000);
    BOOST_TEST(worker.ticks() >= 1U);
}

BOOST_FIXTURE_TEST_CASE(a_visibility_timeout_ending_wakes_a_parked_receive, fixture) {
    call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "retry me"}});
    const auto first = call("ReceiveMessage", {{"QueueUrl", url}, {"VisibilityTimeout", 1}});
    BOOST_TEST_REQUIRE(bodies(first).size() == 1U);
    auto r = receive_async({{"WaitTimeSeconds", 10}});
    const auto got = r.get();
    BOOST_TEST((bodies(got.body) == std::vector<std::string>{"retry me"}));
    BOOST_TEST(got.took.count() < 5000);
}

BOOST_FIXTURE_TEST_CASE(a_drain_answers_parked_receives_empty_at_once, fixture) {
    auto r = receive_async({{"WaitTimeSeconds", 20}});
    until_parked();
    hub.close();
    const auto got = r.get();
    BOOST_TEST(bodies(got.body).empty());
    BOOST_TEST(got.took.count() < 5000);
}

BOOST_FIXTURE_TEST_CASE(a_long_poll_sees_every_partition_of_a_standard_queue, fixture) {
    // Four partitions; sends rotate, so the second and third land on
    // partitions other than the first.
    auto r = receive_async({{"WaitTimeSeconds", 10}, {"MaxNumberOfMessages", 10}});
    until_parked();
    call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "one"}});
    auto got = r.get();
    std::vector<std::string> seen = bodies(got.body);
    for (int i = 0; i < 3 && seen.size() < 3; ++i) {
        if (i == 0) {
            call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "two"}});
            call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "three"}});
        }
        auto more = receive_async({{"WaitTimeSeconds", 5}, {"MaxNumberOfMessages", 10}}).get();
        for (auto& b : bodies(more.body)) {
            seen.push_back(std::move(b));
        }
    }
    std::sort(seen.begin(), seen.end());
    BOOST_TEST((seen == std::vector<std::string>{"one", "three", "two"}));
}

BOOST_AUTO_TEST_SUITE_END()
