// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Independent layers (`.kiro/specs/sqs-compatible-queues/` task 10): the
// front end's named reads, a front end without the data role running the
// whole API over a data node's internal endpoints with real sockets, the
// remote cluster finding the leader among data nodes, and the hybrid
// cluster choosing per call.

#define BOOST_TEST_MODULE sqs_layers_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_availability.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_data_access.hpp>
#include <kythira/sqs/sqs_evacuate.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_gateway.hpp>
#include <kythira/sqs/sqs_layers.hpp>
#include <kythira/sqs/sqs_listener.hpp>
#include <kythira/sqs/sqs_remote_cluster.hpp>
#include <kythira/sqs/sqs_service.hpp>

#include <raft/beast_https_server.hpp>
#if KYTHIRA_SQS_TEST_IDENTITIES
#include <raft/certificate_authority.hpp>
#include <raft/certificate_provider.hpp>
#include <raft/layer_identity.hpp>
#endif
#include <raft/mtls_https_client.hpp>
#include <raft/static_key_authorizer.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <filesystem>
#include <map>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace sqs = kythira::sqs;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace http = boost::beast::http;
namespace json = boost::json;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_forward_secret = "forwarding-secret-0123456789";
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

using front_end_t = sqs::sqs_front_end<az::static_key_authorizer>;

auto authorization(const std::string& method, const std::string& path,
                   std::vector<std::pair<std::string, std::string>> headers,
                   const std::string& body) -> std::string {
    sv4::service_rules rules;
    rules.service = "sqs";
    const sv4::credential_scope scope{"20261118", "us-east-1", "sqs"};
    std::string signed_names;
    for (const auto& [k, v] : headers) {
        std::string lower;
        for (const char c : k) {
            lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        signed_names += (signed_names.empty() ? "" : ";") + lower;
    }
    headers.emplace_back("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDADMIN/" + scope.text() +
                                              ", SignedHeaders=" + signed_names +
                                              ", Signature=" + std::string(64, '0'));
    const auto parsed = sv4::parse(sv4::request{method, path, "", headers, body}, rules, k_now);
    BOOST_REQUIRE(parsed.has_value());
    auto value = headers.back().second;
    value.replace(value.size() - 64, 64,
                  sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope)));
    return value;
}

auto make_auth() -> std::unique_ptr<az::static_key_authorizer> {
    auto auth = std::make_unique<az::static_key_authorizer>(
        std::vector<az::static_key>{
            {"AKIDADMIN", std::string(k_secret), "111122223333", "admin", az::static_role::admin}},
        "aws", [] { return std::chrono::system_clock::time_point(k_now); });
    auth->register_service(sqs::sqs_static_roles());
    return auth;
}

auto start_server(kythira::https::handler h) -> std::unique_ptr<kythira::https::server> {
    kythira::https::server_config hc;
    hc.bind_address = "127.0.0.1";
    hc.port = 0;
    hc.insecure_plaintext = true;
    auto s = std::make_unique<kythira::https::server>(hc, std::move(h));
    s->start();
    return s;
}

/// The internal calls over plain HTTP, as a front end makes them.
auto plain_transport() -> sqs::data_transport {
    kythira::mtls::client_config cc;
    cc.plaintext = true;
    cc.client_certificate = false;
    auto client = std::make_shared<kythira::mtls::client>(cc);
    return [client](const std::string& base, const std::string& path,
                    const std::vector<std::pair<std::string, std::string>>& headers,
                    std::string body) {
        return client->request("POST", base, path, std::move(body), "application/octet-stream",
                               "sqs-layers-test", headers);
    };
}

/// A data node: the queues and the internal endpoints, no client API use.
struct data_node {
    sqs::local_queue_cluster cluster;
    sqs::availability_feed feed;
    std::unique_ptr<az::static_key_authorizer> auth = make_auth();
    std::unique_ptr<front_end_t> fe;
    std::unique_ptr<sqs::sqs_http_handler<front_end_t>> handler;
    std::unique_ptr<kythira::https::server> server;

    data_node() {
        fe = std::make_unique<front_end_t>(sqs::sqs_front_end_config{}, *auth);
        handler = std::make_unique<sqs::sqs_http_handler<front_end_t>>(
            *fe, std::string(k_forward_secret),
            [this](const std::string& key, std::vector<std::byte> entry) {
                return cluster.propose(key, std::move(entry));
            });
        handler->set_local_query([this](const sqs::data_query& q) { return cluster.query(q); });
        handler->set_availability_feed(&feed, std::chrono::seconds{1});
        cluster.set_availability_listener([this](const sqs::queue_target& t, bool visible) {
            if (visible) {
                feed.publish(sqs::queue_keys::partition_prefix(t));
            }
        });
        server = start_server(
            [this](const kythira::https::request& r, const kythira::https::request_context& c) {
                return (*handler)(r, c);
            });
    }
    ~data_node() {
        cluster.set_availability_listener({});
        feed.close();
        server->stop();
    }
    data_node(const data_node&) = delete;
    auto operator=(const data_node&) -> data_node& = delete;
    data_node(data_node&&) = delete;
    auto operator=(data_node&&) -> data_node& = delete;

    [[nodiscard]] auto url() const -> std::string {
        return "http://127.0.0.1:" + std::to_string(server->port());
    }
};

/// One signed SQS JSON call to the listener on `port`; its body, after
/// checking the status is `want`.
auto api_call(std::uint16_t port, std::string_view op, const json::object& in, unsigned want = 200,
              bool good_signature = true) -> json::object {
    const auto body = json::serialize(in);
    std::vector<std::pair<std::string, std::string>> headers{
        {"Content-Type", "application/x-amz-json-1.0"},
        {"Host", "localhost:9324"},
        {"X-Amz-Date", "20261118T120000Z"},
        {"X-Amz-Target", "AmazonSQS." + std::string(op)}};
    auto all = headers;
    auto auth = authorization("POST", "/", headers, body);
    if (!good_signature) {
        auth.back() = auth.back() == '0' ? '1' : '0';
    }
    all.emplace_back("Authorization", auth);
    boost::asio::io_context io;
    boost::beast::tcp_stream stream(io);
    stream.connect(
        boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    http::request<http::string_body> req{http::verb::post, "/", 11};
    for (const auto& [k, v] : all) {
        req.set(k, v);
    }
    req.body() = body;
    req.prepare_payload();
    http::write(stream, req);
    boost::beast::flat_buffer buf;
    http::response<http::string_body> res;
    http::read(stream, buf, res);
    BOOST_TEST_INFO(op << " -> " << res.body());
    BOOST_TEST(res.result_int() == want);
    boost::system::error_code ec;
    auto v = json::parse(res.body(), ec);
    return !ec && v.is_object() ? v.as_object() : json::object{};
}

/// A front end without the data role over `remote`.
struct front_end_node {
    std::unique_ptr<az::static_key_authorizer> auth = make_auth();
    std::unique_ptr<front_end_t> fe;
    std::unique_ptr<sqs::sqs_service<sqs::remote_queue_cluster>> service;
    std::unique_ptr<sqs::sqs_http_handler<front_end_t>> handler;
    std::unique_ptr<kythira::https::server> server;

    /// @param behind_gateway Serve gateways' authenticated calls instead
    ///        of the client API.
    explicit front_end_node(sqs::remote_queue_cluster& remote,
                            sqs::availability_hub* waits = nullptr, bool behind_gateway = false) {
        fe = std::make_unique<front_end_t>(sqs::sqs_front_end_config{}, *auth);
        sqs::sqs_service_config sc;
        sc._receipt_keys = sqs::derived_receipt_key(k_forward_secret);
        sc._waits = waits;
        service = std::make_unique<sqs::sqs_service<sqs::remote_queue_cluster>>(remote, sc);
        service->register_with(*fe);
        handler = std::make_unique<sqs::sqs_http_handler<front_end_t>>(
            *fe, behind_gateway ? std::string(k_forward_secret) : std::string(), nullptr);
        if (behind_gateway) {
            handler->set_serve_calls(true);
            handler->set_client_api(false);
        }
        server = start_server(
            [this](const kythira::https::request& r, const kythira::https::request_context& c) {
                return (*handler)(r, c);
            });
    }
    ~front_end_node() { server->stop(); }
    front_end_node(const front_end_node&) = delete;
    auto operator=(const front_end_node&) -> front_end_node& = delete;
    front_end_node(front_end_node&&) = delete;
    auto operator=(front_end_node&&) -> front_end_node& = delete;

    auto call(std::string_view op, const json::object& in) -> json::object {
        return api_call(server->port(), op, in);
    }
};

/// A gateway without the front-end role: SigV4 here, the rest on a front end.
struct gateway_node {
    std::unique_ptr<az::static_key_authorizer> auth = make_auth();
    std::unique_ptr<front_end_t> fe;
    std::unique_ptr<sqs::gateway_forwarder> forwarder;
    std::unique_ptr<sqs::sqs_http_handler<front_end_t>> handler;
    std::unique_ptr<kythira::https::server> server;

    explicit gateway_node(std::vector<std::string> front_ends) {
        fe = std::make_unique<front_end_t>(sqs::sqs_front_end_config{}, *auth);
        forwarder = std::make_unique<sqs::gateway_forwarder>(
            std::move(front_ends), std::string(k_forward_secret), plain_transport());
        handler = std::make_unique<sqs::sqs_http_handler<front_end_t>>(*fe, "", nullptr);
        handler->set_gateway(forwarder.get());
        server = start_server(
            [this](const kythira::https::request& r, const kythira::https::request_context& c) {
                return (*handler)(r, c);
            });
    }
    ~gateway_node() { server->stop(); }
    gateway_node(const gateway_node&) = delete;
    auto operator=(const gateway_node&) -> gateway_node& = delete;
    gateway_node(gateway_node&&) = delete;
    auto operator=(gateway_node&&) -> gateway_node& = delete;

    auto call(std::string_view op, const json::object& in, unsigned want = 200,
              bool good_signature = true) -> json::object {
        return api_call(server->port(), op, in, want, good_signature);
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(named_reads)

BOOST_AUTO_TEST_CASE(queries_and_answers_survive_the_wire) {
    for (const auto& q : {sqs::data_query::find("111122223333", "orders"),
                          sqs::data_query::list("111122223333", "or", "a", 1001),
                          sqs::data_query::moves("111122223333", "dlq"),
                          sqs::data_query::counts_of(sqs::queue_target{
                              .queue_id = 42, .partition = 3, .fifo = true, .retention_s = 60})}) {
        const auto back = sqs::decode_query(sqs::encode_query(q));
        BOOST_TEST_REQUIRE(back.has_value());
        BOOST_TEST((*back == q));
    }
    BOOST_TEST(!sqs::decode_query("{\"kind\":9}").has_value());
    BOOST_TEST(!sqs::decode_query("not json").has_value());

    sqs::data_answer a;
    a._counts = {.visible = 4, .not_visible = 2, .delayed = 1};
    a._deadline = 1234;
    const auto back = sqs::decode_answer(sqs::encode_answer(a));
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((back->_counts == a._counts));
    BOOST_TEST((back->_deadline == std::optional<std::uint64_t>(1234)));
    BOOST_TEST(!back->_queue.has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(split)

// The whole message path from a front end that holds no replica.
BOOST_AUTO_TEST_CASE(a_front_end_without_data_serves_the_api) {
    data_node data;
    sqs::remote_queue_cluster remote({data.url()}, std::string(k_forward_secret),
                                     plain_transport());
    front_end_node front(remote);

    const auto url = front.call("CreateQueue", {{"QueueName", "orders"}}).at("QueueUrl");
    BOOST_TEST(
        data.cluster.query(sqs::data_query::find("111122223333", "orders"))->_queue.has_value());
    front.call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "hello"}});
    const auto attrs = front.call(
        "GetQueueAttributes",
        {{"QueueUrl", url}, {"AttributeNames", json::array{"ApproximateNumberOfMessages"}}});
    BOOST_TEST(attrs.at("Attributes").at("ApproximateNumberOfMessages").as_string() == "1");
    const auto got = front.call("ReceiveMessage", {{"QueueUrl", url}, {"WaitTimeSeconds", 0}});
    const auto& msgs = got.at("Messages").as_array();
    BOOST_TEST_REQUIRE(msgs.size() == 1U);
    BOOST_TEST(msgs[0].at("Body").as_string() == "hello");
    front.call("DeleteMessage",
               {{"QueueUrl", url}, {"ReceiptHandle", msgs[0].at("ReceiptHandle")}});
    const auto listed = front.call("ListQueues", {});
    BOOST_TEST(listed.at("QueueUrls").as_array().size() == 1U);
    front.call("DeleteQueue", {{"QueueUrl", url}});
    BOOST_TEST(
        !data.cluster.query(sqs::data_query::find("111122223333", "orders"))->_queue.has_value());
}

// A long poll parked on a front end without the data role wakes when a
// send commits on the data node, well before its wait ends.
BOOST_AUTO_TEST_CASE(a_long_poll_on_a_front_end_wakes_on_a_send) {
    data_node data;
    sqs::remote_queue_cluster remote({data.url()}, std::string(k_forward_secret),
                                     plain_transport());
    sqs::availability_hub hub;
    front_end_node front(remote, &hub);
    sqs::availability_follower follower(hub, {data.url()}, std::string(k_forward_secret),
                                        plain_transport(), std::chrono::milliseconds{50});
    follower.start();

    const auto url = front.call("CreateQueue", {{"QueueName", "jobs"}}).at("QueueUrl");
    // Let the follower's first call (a reset, being new) come back.
    for (int i = 0; i < 100 && follower.batches() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    BOOST_TEST_REQUIRE(follower.batches() > 0U);

    const auto start = std::chrono::steady_clock::now();
    std::thread sender([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{300});
        front.call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "late"}});
    });
    const auto got = front.call("ReceiveMessage", {{"QueueUrl", url}, {"WaitTimeSeconds", 10}});
    const auto took = std::chrono::steady_clock::now() - start;
    sender.join();
    const auto* msgs = got.if_contains("Messages");
    BOOST_TEST_REQUIRE(msgs != nullptr);
    BOOST_TEST_REQUIRE(msgs->as_array().size() == 1U);
    BOOST_TEST(msgs->as_array()[0].at("Body").as_string() == "late");
    BOOST_TEST((took < std::chrono::seconds{5}));
    follower.stop();
}

BOOST_AUTO_TEST_CASE(unsigned_internal_calls_are_refused) {
    data_node data;
    sqs::remote_queue_cluster wrong({data.url()}, "another-secret-0123456789", plain_transport());
    BOOST_TEST(!wrong.query(sqs::data_query::find("111122223333", "orders")).has_value());
    BOOST_TEST(!wrong.propose("k", {std::byte{1}}).has_value());
}

// A node without the front-end role answers only its internal endpoints.
BOOST_AUTO_TEST_CASE(a_data_only_node_serves_no_client_api) {
    data_node data;
    data.handler->set_client_api(false);
    const auto r =
        plain_transport()(data.url(), "/", {{"X-Amz-Target", "AmazonSQS.ListQueues"}}, "{}");
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->first == 404U);
    sqs::remote_queue_cluster remote({data.url()}, std::string(k_forward_secret),
                                     plain_transport());
    BOOST_TEST(remote.query(sqs::data_query::find("111122223333", "orders")).has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(routing)

// Data nodes that answer 503 (not the leader, no replica) are passed over,
// and the one that accepted is tried first next time.
BOOST_AUTO_TEST_CASE(the_remote_cluster_finds_and_remembers_the_leader) {
    std::vector<std::string> asked;
    auto transport =
        [&](const std::string& base, const std::string& path,
            const std::vector<std::pair<std::string, std::string>>& headers,
            const std::string& body) -> std::optional<std::pair<unsigned, std::string>> {
        asked.push_back(base);
        BOOST_TEST(headers.size() == 1U);
        BOOST_TEST(sqs::forward::verify(k_forward_secret, headers[0].second, body,
                                        std::chrono::system_clock::now()));
        if (base == "http://down") {
            return std::nullopt;
        }
        if (base != "http://leader") {
            return std::pair<unsigned, std::string>{503, "not committed here\n"};
        }
        if (path == sqs::forward::k_path) {
            return std::pair<unsigned, std::string>{200, "ok"};
        }
        return std::pair<unsigned, std::string>{200, sqs::encode_answer({})};
    };
    sqs::remote_queue_cluster remote({"http://follower", "http://down", "http://leader"},
                                     std::string(k_forward_secret), transport);
    BOOST_TEST(remote.propose("k", {std::byte{1}}).has_value());
    BOOST_TEST(asked ==
               (std::vector<std::string>{"http://follower", "http://down", "http://leader"}));
    asked.clear();
    BOOST_TEST(remote.propose("k", {std::byte{1}}).has_value());
    BOOST_TEST(asked == std::vector<std::string>{"http://leader"});
    BOOST_TEST(remote.query(sqs::data_query::find("111122223333", "q")).has_value());
    BOOST_TEST(!remote.read("k", [](const auto&) {}));
}

BOOST_AUTO_TEST_CASE(a_refusal_other_than_503_is_final) {
    int calls = 0;
    sqs::remote_queue_cluster remote(
        {"http://a", "http://b"}, std::string(k_forward_secret),
        [&](const std::string&, const std::string&,
            const std::vector<std::pair<std::string, std::string>>&,
            const std::string&) -> std::optional<std::pair<unsigned, std::string>> {
            ++calls;
            return std::pair<unsigned, std::string>{403, "no\n"};
        });
    BOOST_TEST(!remote.propose("k", {std::byte{1}}).has_value());
    BOOST_TEST(calls == 1);
}

BOOST_AUTO_TEST_CASE(the_hybrid_cluster_runs_held_keys_here) {
    sqs::local_queue_cluster local;
    int remote_calls = 0;
    sqs::remote_queue_cluster remote(
        {"http://data"}, std::string(k_forward_secret),
        [&](const std::string&, const std::string&,
            const std::vector<std::pair<std::string, std::string>>&,
            const std::string&) -> std::optional<std::pair<unsigned, std::string>> {
            ++remote_calls;
            return std::pair<unsigned, std::string>{200, sqs::encode_answer({})};
        });
    const auto held = sqs::catalog_keys::queues_prefix("111122223333");
    sqs::hybrid_queue_cluster<sqs::local_queue_cluster> hybrid(
        &local, &remote, [&](const std::string& key) { return key.starts_with(held); });
    static_assert(sqs::queue_cluster<decltype(hybrid)>);
    static_assert(sqs::queue_cluster<sqs::remote_queue_cluster>);

    BOOST_TEST(hybrid.query(sqs::data_query::find("111122223333", "q")).has_value());
    BOOST_TEST(remote_calls == 0);
    BOOST_TEST(hybrid.query(sqs::data_query::find("444455556666", "q")).has_value());
    BOOST_TEST(remote_calls == 1);

    // Without a remote side every call is local (a co-located node).
    sqs::hybrid_queue_cluster<sqs::local_queue_cluster> colocated(
        &local, nullptr, [](const std::string&) { return false; });
    BOOST_TEST(colocated.query(sqs::data_query::find("444455556666", "q")).has_value());
    BOOST_TEST(remote_calls == 1);
    // Without a local side every call is remote (a front end only).
    sqs::hybrid_queue_cluster<sqs::local_queue_cluster> front(
        nullptr, &remote, [](const std::string&) { return true; });
    BOOST_TEST(front.query(sqs::data_query::find("111122223333", "q")).has_value());
    BOOST_TEST(remote_calls == 2);
    BOOST_CHECK_THROW((sqs::hybrid_queue_cluster<sqs::local_queue_cluster>(
                          nullptr, nullptr, [](const std::string&) { return true; })),
                      std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(availability)

BOOST_AUTO_TEST_CASE(the_feed_answers_what_came_after_since) {
    sqs::availability_feed feed(4);
    const auto first = feed.wait("", 0, std::chrono::milliseconds{0});
    BOOST_TEST(first._reset);  // a new caller cannot know what it missed
    BOOST_TEST(first._next == 0U);
    feed.publish("a");
    feed.publish("b");
    feed.publish("a");
    const auto b = feed.wait(first._epoch, first._next, std::chrono::milliseconds{0});
    BOOST_TEST(!b._reset);
    BOOST_TEST(b._next == 3U);
    BOOST_TEST((b._keys == std::vector<std::string>{"a", "b"}));
    // Nothing new: the wait ends empty.
    const auto none = feed.wait(b._epoch, b._next, std::chrono::milliseconds{10});
    BOOST_TEST(!none._reset);
    BOOST_TEST(none._keys.empty());
}

BOOST_AUTO_TEST_CASE(a_caller_left_behind_the_window_is_reset) {
    sqs::availability_feed feed(2);
    const auto e = feed.epoch();
    for (int i = 0; i < 5; ++i) {
        feed.publish("k" + std::to_string(i));
    }
    BOOST_TEST(feed.wait(e, 1, std::chrono::milliseconds{0})._reset);
    BOOST_TEST(!feed.wait(e, 3, std::chrono::milliseconds{0})._reset);
    BOOST_TEST(feed.wait("another-epoch", 3, std::chrono::milliseconds{0})._reset);
    BOOST_TEST(feed.wait(e, 9, std::chrono::milliseconds{0})._reset);
}

BOOST_AUTO_TEST_CASE(a_wait_wakes_on_publish_and_on_close) {
    sqs::availability_feed feed;
    const auto e = feed.epoch();
    std::thread t([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        feed.publish("x");
    });
    const auto start = std::chrono::steady_clock::now();
    const auto b = feed.wait(e, 0, std::chrono::seconds{10});
    t.join();
    BOOST_TEST((b._keys == std::vector<std::string>{"x"}));
    BOOST_TEST((std::chrono::steady_clock::now() - start < std::chrono::seconds{5}));
    feed.close();
    BOOST_TEST(feed.wait(e, 1, std::chrono::seconds{10})._keys.empty());
}

BOOST_AUTO_TEST_CASE(batches_survive_the_wire) {
    sqs::availability_batch b{"e1", 7, false, {std::string("p\0q", 3), "r"}};
    const auto d = sqs::decode_availability(sqs::encode_availability(b));
    BOOST_TEST_REQUIRE(d.has_value());
    BOOST_TEST(d->_epoch == "e1");
    BOOST_TEST(d->_next == 7U);
    BOOST_TEST(!d->_reset);
    BOOST_TEST((d->_keys == b._keys));
    BOOST_TEST(!sqs::decode_availability("{\"keys\": [1]}").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(gateway)

BOOST_AUTO_TEST_CASE(calls_survive_the_wire) {
    sqs::authenticated_call c;
    c._request = {"POST",
                  "/",
                  "a=b",
                  {{"X-Amz-Target", "AmazonSQS.ListQueues"}},
                  std::string("{\"x\":\"\0\"}", 9),
                  "10.0.0.7",
                  false};
    c._principal.type = kythira::aws_auth::principal_type::assumed_role;
    c._principal.account = "111122223333";
    c._principal.arn = "arn:aws:sts::111122223333:assumed-role/r/s";
    c._principal.tags = {{"team", "q"}};
    c._principal.expires = std::chrono::system_clock::time_point(std::chrono::milliseconds(1234));
    c._principal.session_policies = {"{}"};
    const auto d = sqs::decode_call(sqs::encode_call(c));
    BOOST_TEST_REQUIRE(d.has_value());
    BOOST_TEST(d->_request._body == c._request._body);
    BOOST_TEST(d->_request._query == "a=b");
    BOOST_TEST(d->_request._source_ip == "10.0.0.7");
    BOOST_TEST(!d->_request._secure);
    BOOST_TEST((d->_request._headers == c._request._headers));
    BOOST_TEST((d->_principal.type == c._principal.type));
    BOOST_TEST(d->_principal.arn == c._principal.arn);
    BOOST_TEST((d->_principal.tags == c._principal.tags));
    BOOST_TEST((d->_principal.expires == c._principal.expires));
    BOOST_TEST(!d->_principal.token_issue_time.has_value());
    BOOST_TEST(!sqs::decode_call("{\"request\": {}}").has_value());

    kythira::aws_json::http_response r;
    r.status = 400;
    r.headers = {{"x-amzn-query-error", "Q;Sender"}};
    r.body = "{}";
    const auto a = sqs::decode_call_answer(sqs::encode_call_answer(r));
    BOOST_TEST_REQUIRE(a.has_value());
    BOOST_TEST(a->status == 400U);
    BOOST_TEST((a->headers == r.headers));
    BOOST_TEST(!sqs::decode_call_answer("{\"status\": 42, \"body\": \"\"}").has_value());
}

// Three layers on three nodes: a gateway, a front end behind it, a data node.
BOOST_AUTO_TEST_CASE(a_gateway_hands_calls_to_a_front_end) {
    data_node data;
    sqs::remote_queue_cluster remote({data.url()}, std::string(k_forward_secret),
                                     plain_transport());
    front_end_node front(remote, nullptr, true);
    gateway_node gw({"http://127.0.0.1:" + std::to_string(front.server->port())});

    const auto url = gw.call("CreateQueue", {{"QueueName", "via"}}).at("QueueUrl");
    gw.call("SendMessage", {{"QueueUrl", url}, {"MessageBody", "hop"}});
    const auto got = gw.call("ReceiveMessage", {{"QueueUrl", url}});
    BOOST_TEST_REQUIRE(got.at("Messages").as_array().size() == 1U);
    BOOST_TEST(got.at("Messages").as_array()[0].at("Body").as_string() == "hop");
    // A modeled error comes back as the front end worded it.
    const auto missing = gw.call("GetQueueUrl", {{"QueueName", "nope"}}, 400);
    BOOST_TEST(missing.at("__type").as_string() == "com.amazonaws.sqs#QueueDoesNotExist");
    // A bad signature stops at the gateway.
    BOOST_TEST(gw.call("ListQueues", {}, 400, false).at("__type").as_string() ==
               "InvalidSignatureException");
    // The front end serves no client API of its own.
    api_call(front.server->port(), "ListQueues", {}, 404);
    BOOST_TEST(gw.forwarder->failures() == 0U);
}

BOOST_AUTO_TEST_CASE(an_unreachable_front_end_is_a_retryable_error) {
    gateway_node gw({"http://127.0.0.1:1"});
    const auto r = gw.call("ListQueues", {}, 503);
    BOOST_TEST(r.at("__type").as_string() ==
               "com.amazon.coral.availability#ServiceUnavailableException");
    BOOST_TEST(gw.forwarder->failures() == 1U);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

/// A group's membership, changed by the steps as a leader would.
struct fake_group {
    int self = 1;
    bool leading = true;
    bool joint = false;
    std::vector<int> voters{1, 2, 3};
    std::vector<int> learners;
    std::uint64_t last = 100;
    std::map<int, std::uint64_t> match;
    std::vector<std::string> calls;

    auto ops() -> sqs::membership_ops<int> {
        sqs::membership_ops<int> o;
        o.is_leader = [this] { return leading; };
        o.self = [this] { return self; };
        o.changing = [this] { return joint; };
        o.members = [this] { return std::pair{voters, learners}; };
        o.match_index = [this](int n) -> std::optional<std::uint64_t> {
            const auto it = match.find(n);
            return it == match.end() ? std::nullopt : std::optional(it->second);
        };
        o.last_index = [this] { return last; };
        o.add_learner = [this](int n) {
            learners.push_back(n);
            calls.push_back("learner " + std::to_string(n));
        };
        o.promote = [this](int n) {
            std::erase(learners, n);
            voters.push_back(n);
            calls.push_back("promote " + std::to_string(n));
        };
        o.remove_voter = [this](int n) {
            std::erase(voters, n);
            calls.push_back("remove " + std::to_string(n));
        };
        o.remove_learner = [this](int n) {
            std::erase(learners, n);
            calls.push_back("remove learner " + std::to_string(n));
        };
        o.transfer_to = [this](int n) {
            leading = false;
            calls.push_back("transfer " + std::to_string(n));
        };
        return o;
    }

    auto step(int from, int to) -> sqs::step_result {
        return sqs::evacuate_step<int>(ops(), from, to, 8,
                                       [](int n) { return "node " + std::to_string(n); });
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(evacuate)

using sqs::step_kind;

BOOST_AUTO_TEST_CASE(a_follower_moves_by_learner_promote_remove) {
    fake_group g;
    BOOST_TEST((g.step(2, 4)._kind == step_kind::progressed));
    // Not caught up: wait, however often asked.
    BOOST_TEST((g.step(2, 4)._kind == step_kind::waiting));
    g.match[4] = 50;
    BOOST_TEST((g.step(2, 4)._kind == step_kind::waiting));
    g.match[4] = 95;  // within the lag of 8
    BOOST_TEST((g.step(2, 4)._kind == step_kind::progressed));
    g.joint = true;
    BOOST_TEST((g.step(2, 4)._kind == step_kind::waiting));
    g.joint = false;
    BOOST_TEST((g.step(2, 4)._kind == step_kind::progressed));
    BOOST_TEST((g.step(2, 4)._kind == step_kind::done));
    BOOST_TEST((g.calls == std::vector<std::string>{"learner 4", "promote 4", "remove 2"}));
    BOOST_TEST((g.voters == std::vector<int>{1, 3, 4}));
}

BOOST_AUTO_TEST_CASE(a_leader_hands_over_before_it_is_removed) {
    fake_group g;
    g.match[4] = 100;
    BOOST_TEST((g.step(1, 4)._kind == step_kind::progressed));
    BOOST_TEST((g.step(1, 4)._kind == step_kind::progressed));
    const auto handed = g.step(1, 4);
    BOOST_TEST((handed._kind == step_kind::progressed));
    BOOST_TEST(handed._what.find("leadership") != std::string::npos);
    // Node 1 no longer leads: the rest happens on the new leader.
    BOOST_TEST((g.step(1, 4)._kind == step_kind::not_leader));
    g.self = 4;
    g.leading = true;
    BOOST_TEST((g.step(1, 4)._kind == step_kind::progressed));
    BOOST_TEST((g.step(1, 4)._kind == step_kind::done));
    BOOST_TEST(
        (g.calls == std::vector<std::string>{"learner 4", "promote 4", "transfer 4", "remove 1"}));
}

BOOST_AUTO_TEST_CASE(a_move_reverses_from_any_point) {
    // Stopped with 4 a learner: reversing removes it.
    fake_group g;
    g.learners = {4};
    BOOST_TEST((g.step(4, 2)._kind == step_kind::progressed));
    BOOST_TEST((g.step(4, 2)._kind == step_kind::done));
    BOOST_TEST(g.learners.empty());
    // Stopped with both voting: reversing removes the newcomer.
    fake_group h;
    h.voters = {1, 2, 3, 4};
    BOOST_TEST((h.step(4, 2)._kind == step_kind::progressed));
    BOOST_TEST((h.voters == std::vector<int>{1, 2, 3}));
    BOOST_TEST((h.step(4, 2)._kind == step_kind::done));
}

BOOST_AUTO_TEST_CASE(impossible_moves_are_refused) {
    fake_group g;
    BOOST_TEST((g.step(2, 2)._kind == step_kind::refused));
    BOOST_TEST((g.step(7, 8)._kind == step_kind::refused));
    g.leading = false;
    BOOST_TEST((g.step(2, 4)._kind == step_kind::not_leader));
    BOOST_TEST(g.calls.empty());
}

BOOST_AUTO_TEST_CASE(admin_calls_survive_the_wire) {
    const auto e = sqs::decode_evacuate(sqs::encode_evacuate({"1", "4"}));
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->_from == "1");
    BOOST_TEST(e->_to == "4");
    BOOST_TEST(!sqs::decode_evacuate("{\"from\": \"1\"}").has_value());
    const auto p = sqs::decode_peer(sqs::encode_peer({"4", "https://d4:17500", "https://d4:9324"}));
    BOOST_TEST_REQUIRE(p.has_value());
    BOOST_TEST(p->_raft_url == "https://d4:17500");
    BOOST_TEST(!sqs::decode_peer("{\"id\": \"4\", \"raft\": \"d4\", \"sqs\": \"x\"}").has_value());
    const auto s = sqs::decode_step(sqs::encode_step({step_kind::waiting, "catching up"}));
    BOOST_TEST_REQUIRE(s.has_value());
    BOOST_TEST((s->_kind == step_kind::waiting));
    BOOST_TEST(!sqs::decode_step("{\"result\": \"maybe\"}").has_value());
}

BOOST_AUTO_TEST_SUITE_END()

#if KYTHIRA_SQS_TEST_IDENTITIES

namespace {

namespace layers = kythira::layers;

/// A CA, and certificates with layer identities written to files.
struct identity_ca {
    raft::testing::certificate_authority ca;
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() /
        ("sqs-layers-" + std::to_string(::getpid()) + "-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    identity_ca() {
        std::filesystem::create_directories(dir);
        write("ca.pem", ca.root_certificate_pem());
    }
    ~identity_ca() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    identity_ca(const identity_ca&) = delete;
    auto operator=(const identity_ca&) -> identity_ca& = delete;
    identity_ca(identity_ca&&) = delete;
    auto operator=(identity_ca&&) -> identity_ca& = delete;

    void write(const std::string& name, const std::string& pem) const {
        std::ofstream(dir / name) << pem;
    }
    [[nodiscard]] auto path(const std::string& name) const -> std::string {
        return (dir / name).string();
    }

    /// Writes `<name>.crt` and `<name>.key` naming `roles` in `cluster`
    /// (no identity at all with an empty role set).
    void issue(const std::string& name, layers::role_set roles, const std::string& cluster = "c1") {
        raft::testing::leaf_certificate_options leaf;
        leaf.subject.common_name = name;
        auto csr = raft::testing::generate_key_and_csr(leaf);
        raft::testing::csr_signing_options o;
        o.dns_names = {"localhost"};
        o.ip_addresses = {"127.0.0.1"};
        o.client_auth = true;
        if (!roles.empty()) {
            layers::add_layer_identity(
                o, layers::identity{
                       .service = "sqs", .cluster = cluster, .node_id = name, .roles = roles});
        }
        const auto pem = ca.sign_csr(csr.csr_pem, o);
        write(name + ".crt", pem.chain_pem);
        write(name + ".key", csr.private_key_pem);
    }
};

/// A front end and data node over TLS whose internal routes check
/// identities of cluster c1.
struct tls_node {
    std::unique_ptr<az::static_key_authorizer> auth = make_auth();
    std::unique_ptr<front_end_t> fe;
    std::unique_ptr<sqs::sqs_http_handler<front_end_t>> handler;
    std::unique_ptr<kythira::https::server> server;

    explicit tls_node(const identity_ca& ca) {
        fe = std::make_unique<front_end_t>(sqs::sqs_front_end_config{}, *auth);
        handler = std::make_unique<sqs::sqs_http_handler<front_end_t>>(
            *fe, std::string(k_forward_secret), [](const std::string&, std::vector<std::byte>) {
                return std::optional<std::vector<std::byte>>{};
            });
        handler->set_local_query(
            [](const sqs::data_query&) { return std::optional<sqs::data_answer>{}; });
        handler->set_serve_calls(true);
        handler->set_peer_check(sqs::identity_peer_check(
            sqs::internal_route_guard("c1", std::string(k_forward_secret))));
        kythira::https::server_config hc;
        hc.bind_address = "127.0.0.1";
        hc.port = 0;
        hc.tls_cert_path = ca.path("server.crt");
        hc.tls_key_path = ca.path("server.key");
        hc.client_ca_path = ca.path("ca.pem");
        server = std::make_unique<kythira::https::server>(
            hc, [this](const kythira::https::request& r, const kythira::https::request_context& c) {
                return (*handler)(r, c);
            });
        server->start();
    }
    ~tls_node() { server->stop(); }
    tls_node(const tls_node&) = delete;
    auto operator=(const tls_node&) -> tls_node& = delete;
    tls_node(tls_node&&) = delete;
    auto operator=(tls_node&&) -> tls_node& = delete;

    /// POSTs `body` to `path` presenting certificate `who` (none when
    /// empty), signed with the forwarding secret when `sign`; the status
    /// and body.
    [[nodiscard]] auto post(const identity_ca& ca, const std::string& who, const std::string& path,
                            const std::string& body, bool sign = false) const
        -> std::pair<unsigned, std::string> {
        kythira::mtls::client_config cc;
        cc.ca_path = ca.path("ca.pem");
        cc.client_certificate = !who.empty();
        if (!who.empty()) {
            cc.cert_path = ca.path(who + ".crt");
            cc.key_path = ca.path(who + ".key");
        }
        const kythira::mtls::client client(cc);
        std::vector<std::pair<std::string, std::string>> headers;
        if (sign) {
            headers.emplace_back(
                std::string(sqs::forward::k_header),
                sqs::forward::sign(k_forward_secret, body, std::chrono::system_clock::now()));
        }
        const auto r = client.request("POST", "https://127.0.0.1:" + std::to_string(server->port()),
                                      path, body, "application/json", "sqs-layers-test", headers);
        BOOST_TEST_REQUIRE(r.has_value());
        return {r->first, r->second};
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(identities)

// Requirement 11.4: over TLS each layer reaches only its own routes.
BOOST_AUTO_TEST_CASE(each_layer_reaches_only_its_routes) {
    using layers::role;
    identity_ca ca;
    ca.issue("server", {role::front_end, role::data});
    ca.issue("fe", {role::front_end});
    ca.issue("gw", {role::gateway});
    ca.issue("data", {role::data});
    ca.issue("stranger", {role::front_end}, "c2");
    ca.issue("plain", {});
    tls_node node(ca);
    const std::string query(sqs::data_wire::k_query_path);
    const std::string call(sqs::k_call_path);
    const std::string avail(sqs::k_availability_path);

    // Past the check, a malformed body is a 400.
    BOOST_TEST(node.post(ca, "fe", query, "{}").first == 400U);
    BOOST_TEST(node.post(ca, "data", query, "{}").first == 400U);
    BOOST_TEST(node.post(ca, "gw", call, "{}").first == 400U);

    // A front end's certificate cannot name a principal; a gateway's
    // cannot read queues.
    const auto fe_call = node.post(ca, "fe", call, "{}");
    BOOST_TEST(fe_call.first == 403U);
    BOOST_TEST(fe_call.second.find("may not call") != std::string::npos);
    BOOST_TEST(node.post(ca, "gw", query, "{}").first == 403U);
    BOOST_TEST(node.post(ca, "gw", std::string(sqs::forward::k_path), "{}").first == 403U);
    // Another cluster's identity is none at all.
    BOOST_TEST(node.post(ca, "stranger", query, "{}").first == 403U);

    // Without an identity, the forwarding secret holds data alone.
    BOOST_TEST(node.post(ca, "plain", query, "{}").first == 403U);
    BOOST_TEST(node.post(ca, "plain", query, "{}", true).first == 400U);
    BOOST_TEST(node.post(ca, "", query, "{}", true).first == 400U);
    const auto secret_call = node.post(ca, "", call, "{}", true);
    BOOST_TEST(secret_call.first == 403U);
    BOOST_TEST(secret_call.second.find("forward secret may not call") != std::string::npos);
    BOOST_TEST(node.post(ca, "", query, "{}").first == 403U);
    // No feed here: the route is not served, whoever asks.
    BOOST_TEST(node.post(ca, "fe", avail, "{}").first == 404U);
}

BOOST_AUTO_TEST_CASE(the_route_table_covers_every_internal_path) {
    const auto guard = sqs::internal_route_guard("c1", "");
    using layers::role;
    for (const auto path :
         {sqs::forward::k_path, sqs::data_wire::k_query_path, sqs::k_availability_path}) {
        const auto* r = guard.rule_for(path);
        BOOST_TEST_REQUIRE(r != nullptr);
        BOOST_TEST((r->allowed == layers::role_set{role::front_end, role::data}));
    }
    const auto* c = guard.rule_for(sqs::k_call_path);
    BOOST_TEST_REQUIRE(c != nullptr);
    BOOST_TEST((c->allowed == layers::role_set{role::gateway}));
    const auto* a = guard.rule_for(sqs::k_admin_evacuate_path);
    BOOST_TEST_REQUIRE(a != nullptr);
    BOOST_TEST((a->allowed == layers::role_set{role::data}));
    BOOST_TEST(guard.rule_for("/") == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // KYTHIRA_SQS_TEST_IDENTITIES
