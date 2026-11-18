// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The SQS listener (`.kiro/specs/sqs-compatible-queues/` task 4): the API
// over core's Beast server, with real sockets and real SigV4, in both
// protocols; the node-to-node forwarding endpoint and its refusals; and
// sqs_node's settings from the environment.

#define BOOST_TEST_MODULE sqs_listener_test

#include <boost/test/unit_test.hpp>

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_cluster.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_front_end.hpp>
#include <kythira/sqs/sqs_listener.hpp>
#include <kythira/sqs/sqs_node_options.hpp>
#include <kythira/sqs/sqs_service.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/static_key_authorizer.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
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

/// SigV4 header form over `headers` as they will be sent.
auto authorization(const std::string& method, const std::string& path, const std::string& query,
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
    const auto parsed = sv4::parse(sv4::request{method, path, query, headers, body}, rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    auto value = headers.back().second;
    value.replace(value.size() - 64, 64,
                  sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope)));
    return value;
}

struct fixture {
    sqs::local_queue_cluster cluster;
    az::static_key_authorizer auth{
        std::vector<az::static_key>{
            {"AKIDADMIN", std::string(k_secret), "111122223333", "admin", az::static_role::admin}},
        "aws", [] { return std::chrono::system_clock::time_point(k_now); }};
    std::unique_ptr<front_end_t> fe;
    std::unique_ptr<sqs::sqs_service<sqs::local_queue_cluster>> service;
    std::unique_ptr<sqs::sqs_http_handler<front_end_t>> handler;
    std::unique_ptr<kythira::https::server> server;

    explicit fixture(std::string forward_secret = std::string(k_forward_secret)) {
        auth.register_service(sqs::sqs_static_roles());
        fe = std::make_unique<front_end_t>(sqs::sqs_front_end_config{}, auth);
        sqs::sqs_service_config sc;
        sc._receipt_keys = sqs::derived_receipt_key(k_forward_secret);
        service = std::make_unique<sqs::sqs_service<sqs::local_queue_cluster>>(cluster, sc);
        service->register_with(*fe);
        handler = std::make_unique<sqs::sqs_http_handler<front_end_t>>(
            *fe, std::move(forward_secret),
            [this](const std::string& key, std::vector<std::byte> entry) {
                return cluster.propose(key, std::move(entry));
            });
        kythira::https::server_config hc;
        hc.bind_address = "127.0.0.1";
        hc.port = 0;
        hc.insecure_plaintext = true;
        server = std::make_unique<kythira::https::server>(
            hc, [this](const kythira::https::request& r, const kythira::https::request_context& c) {
                return (*handler)(r, c);
            });
        server->start();
    }

    ~fixture() { server->stop(); }
    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;
    fixture(fixture&&) = delete;
    auto operator=(fixture&&) -> fixture& = delete;

    auto send(http::verb verb, const std::string& target,
              const std::vector<std::pair<std::string, std::string>>& headers,
              const std::string& body) -> http::response<http::string_body> {
        boost::asio::io_context io;
        boost::beast::tcp_stream stream(io);
        stream.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"),
                                                      server->port()));
        http::request<http::string_body> req{verb, target, 11};
        for (const auto& [k, v] : headers) {
            req.set(k, v);
        }
        req.body() = body;
        req.prepare_payload();
        http::write(stream, req);
        boost::beast::flat_buffer buf;
        http::response<http::string_body> res;
        http::read(stream, buf, res);
        boost::system::error_code ec;
        (void)stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        return res;
    }

    auto json_call(std::string_view op, const json::object& in)
        -> http::response<http::string_body> {
        const auto body = json::serialize(in);
        std::vector<std::pair<std::string, std::string>> headers{
            {"Content-Type", "application/x-amz-json-1.0"},
            {"Host", "localhost:9324"},
            {"X-Amz-Date", "20261118T120000Z"},
            {"X-Amz-Target", "AmazonSQS." + std::string(op)}};
        auto all = headers;
        all.emplace_back("Authorization", authorization("POST", "/", "", headers, body));
        return send(http::verb::post, "/", all, body);
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(listener)

BOOST_FIXTURE_TEST_CASE(the_json_protocol_round_trips_over_a_socket, fixture) {
    auto r = json_call("CreateQueue", {{"QueueName", "orders"}});
    BOOST_TEST(r.result_int() == 200U);
    BOOST_TEST(json::parse(r.body()).at("QueueUrl").as_string() ==
               "http://localhost:9324/111122223333/orders");
    r = json_call("SendMessage", {{"QueueUrl", "http://localhost:9324/111122223333/orders"},
                                  {"MessageBody", "hello"}});
    BOOST_TEST(r.result_int() == 200U);
    BOOST_TEST(r[http::field::content_type] == "application/x-amz-json-1.0");
    BOOST_TEST(!r["x-amzn-RequestId"].empty());
    r = json_call("ReceiveMessage", {{"QueueUrl", "http://localhost:9324/111122223333/orders"}});
    BOOST_TEST(json::parse(r.body()).at("Messages").as_array().at(0).at("Body").as_string() ==
               "hello");
    r = json_call("GetQueueUrl", {{"QueueName", "nope"}});
    BOOST_TEST(r.result_int() == 400U);
}

BOOST_FIXTURE_TEST_CASE(a_query_request_names_its_queue_by_path, fixture) {
    BOOST_REQUIRE(json_call("CreateQueue", {{"QueueName", "orders"}}).result_int() == 200U);
    const std::string body = "Action=SendMessage&Version=2012-11-05&MessageBody=hi";
    const std::vector<std::pair<std::string, std::string>> headers{
        {"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"},
        {"Host", "localhost:9324"},
        {"X-Amz-Date", "20261118T120000Z"}};
    auto all = headers;
    all.emplace_back("Authorization",
                     authorization("POST", "/111122223333/orders", "", headers, body));
    const auto r = send(http::verb::post, "/111122223333/orders", all, body);
    BOOST_TEST(r.result_int() == 200U);
    BOOST_TEST(r.body().find("<SendMessageResponse") != std::string::npos);
    BOOST_TEST(r[http::field::content_type].starts_with("text/xml"));
}

BOOST_FIXTURE_TEST_CASE(unsigned_requests_are_refused, fixture) {
    const auto r = send(
        http::verb::post, "/",
        {{"Content-Type", "application/x-amz-json-1.0"}, {"X-Amz-Target", "AmazonSQS.ListQueues"}},
        "{}");
    BOOST_TEST(r.result_int() >= 400U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(forwarding)

namespace {

auto create_entry(const std::string& name) -> std::vector<std::byte> {
    sqs::catalog_command c;
    c._op = sqs::catalog_command::kind::create;
    c._account = "111122223333";
    c._name = name;
    c._partitions = 4;
    const auto s = sqs::encode_catalog_command(c);
    std::vector<std::byte> out;
    for (const char ch : s) {
        out.push_back(static_cast<std::byte>(ch));
    }
    return out;
}

}  // namespace

BOOST_FIXTURE_TEST_CASE(a_signed_entry_is_proposed_here, fixture) {
    const auto body =
        sqs::forward::encode_body({._key = sqs::catalog_keys::queue("111122223333", "orders"),
                                   ._entry = create_entry("orders")});
    const auto sig = sqs::forward::sign(k_forward_secret, body, std::chrono::system_clock::now());
    const auto r = send(http::verb::post, std::string(sqs::forward::k_path),
                        {{std::string(sqs::forward::k_header), sig}}, body);
    BOOST_TEST(r.result_int() == 200U);
    const auto out = sqs::decode_catalog_result(r.body());
    BOOST_TEST_REQUIRE(out.has_value());
    BOOST_TEST((out->_outcome == sqs::catalog_result::status::ok));
    BOOST_TEST(service->find("111122223333", "orders").has_value());

    // Tampered, stale, malformed, or the wrong method: refused.
    BOOST_TEST(send(http::verb::post, std::string(sqs::forward::k_path),
                    {{std::string(sqs::forward::k_header), sig}}, body + "x")
                   .result_int() == 403U);
    const auto old = sqs::forward::sign(k_forward_secret, body,
                                        std::chrono::system_clock::now() - std::chrono::minutes{5});
    BOOST_TEST(send(http::verb::post, std::string(sqs::forward::k_path),
                    {{std::string(sqs::forward::k_header), old}}, body)
                   .result_int() == 403U);
    const std::string junk("\0\0\0\1k", 5);
    BOOST_TEST(
        send(http::verb::post, std::string(sqs::forward::k_path),
             {{std::string(sqs::forward::k_header),
               sqs::forward::sign(k_forward_secret, junk, std::chrono::system_clock::now())}},
             junk)
            .result_int() == 400U);
    BOOST_TEST(send(http::verb::get, std::string(sqs::forward::k_path), {}, "").result_int() ==
               405U);
}

BOOST_AUTO_TEST_CASE(without_a_secret_the_path_does_not_exist) {
    fixture f("");
    const auto body = sqs::forward::encode_body({._key = "k", ._entry = create_entry("orders")});
    const auto r = f.send(http::verb::post, std::string(sqs::forward::k_path),
                          {{std::string(sqs::forward::k_header),
                            sqs::forward::sign("", body, std::chrono::system_clock::now())}},
                          body);
    BOOST_TEST(r.result_int() == 404U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(options)

namespace {

auto env_of(std::map<std::string, std::string> vars) -> sqs::sqs_env {
    return [vars = std::move(vars)](std::string_view name) -> std::optional<std::string> {
        const auto it = vars.find(std::string(name));
        return it == vars.end() ? std::nullopt : std::optional<std::string>(it->second);
    };
}

auto refusal(std::map<std::string, std::string> vars) -> std::string {
    const auto r = sqs::sqs_node_options_from_env(env_of(std::move(vars)));
    const auto* s = std::get_if<std::string>(&r);
    return s != nullptr ? *s : std::string();
}

}  // namespace

BOOST_AUTO_TEST_CASE(defaults_and_settings) {
    auto r = sqs::sqs_node_options_from_env(
        env_of({{"SQS_STATIC_KEYS_FILE", "/k"}, {"SQS_ALLOW_PLAINTEXT", "on"}}));
    auto* o = std::get_if<sqs::sqs_node_options>(&r);
    BOOST_TEST_REQUIRE(o != nullptr);
    BOOST_TEST(o->_listen_host == "0.0.0.0");
    BOOST_TEST(o->_listen_port == 9324U);
    BOOST_TEST(o->_region == "us-east-1");

    r = sqs::sqs_node_options_from_env(
        env_of({{"SQS_STATIC_KEYS_FILE", "/k"},
                {"SQS_TLS_CERT", "/c"},
                {"SQS_TLS_KEY", "/p"},
                {"SQS_LISTEN", "[::1]:0"},
                {"SQS_ENDPOINT", "https://sqs.example"},
                {"SQS_COMPAT", "max-message-bytes=aws,purge-cooldown=0"},
                {"SQS_MAX_BODY_BYTES", "2048"}}));
    o = std::get_if<sqs::sqs_node_options>(&r);
    BOOST_TEST_REQUIRE(o != nullptr);
    BOOST_TEST(o->_listen_host == "::1");
    BOOST_TEST(o->_listen_port == 0U);
    BOOST_TEST(o->_endpoint == "https://sqs.example");
    BOOST_TEST(o->_compat.size() == 2U);
    BOOST_TEST(o->_compat[1].first == "purge-cooldown");
    BOOST_TEST(o->_max_body_bytes == 2048U);
}

BOOST_AUTO_TEST_CASE(refusals_name_the_variable) {
    BOOST_TEST(refusal({{"SQS_ALLOW_PLAINTEXT", "on"}}).find("SQS_STATIC_KEYS_FILE") !=
               std::string::npos);
    BOOST_TEST(refusal({{"SQS_STATIC_KEYS_FILE", "/k"}}).find("SQS_TLS_CERT") != std::string::npos);
    const std::map<std::string, std::string> base{{"SQS_STATIC_KEYS_FILE", "/k"},
                                                  {"SQS_ALLOW_PLAINTEXT", "on"}};
    const auto with = [&](const std::string& k, const std::string& v) {
        auto m = base;
        m[k] = v;
        return refusal(m);
    };
    BOOST_TEST(with("SQS_LISTEN", "9324").find("SQS_LISTEN") != std::string::npos);
    BOOST_TEST(with("SQS_LISTEN", "h:70000").find("SQS_LISTEN") != std::string::npos);
    BOOST_TEST(with("SQS_ALLOW_PLAINTEXT", "maybe").find("SQS_ALLOW_PLAINTEXT") !=
               std::string::npos);
    BOOST_TEST(with("SQS_ENDPOINT", "localhost").find("SQS_ENDPOINT") != std::string::npos);
    BOOST_TEST(with("SQS_ENDPOINT", "http://h/").find("SQS_ENDPOINT") != std::string::npos);
    BOOST_TEST(with("SQS_FORWARD_SECRET", "short").find("SQS_FORWARD_SECRET") != std::string::npos);
    BOOST_TEST(with("SQS_COMPAT", "novalue").find("SQS_COMPAT") != std::string::npos);
    BOOST_TEST(with("SQS_MAX_BODY_BYTES", "12").find("SQS_MAX_BODY_BYTES") != std::string::npos);
    BOOST_TEST(with("SQS_REGION", "").find("SQS_REGION") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(roles_and_data_endpoints) {
    using kythira::layers::role;
    const std::map<std::string, std::string> base{{"SQS_STATIC_KEYS_FILE", "/k"},
                                                  {"SQS_ALLOW_PLAINTEXT", "on"}};
    const auto parse = [&](std::map<std::string, std::string> extra) {
        auto m = base;
        m.merge(extra);
        return sqs::sqs_node_options_from_env(env_of(m));
    };
    // Every layer by default.
    auto r = parse({});
    auto* o = std::get_if<sqs::sqs_node_options>(&r);
    BOOST_TEST_REQUIRE(o != nullptr);
    BOOST_TEST((o->has(role::gateway) && o->has(role::front_end) && o->has(role::data)));
    BOOST_TEST(o->_data_endpoints.empty());

    // A front end without the data role names the data nodes and signs.
    r = parse({{"KYTHIRA_SQS_ROLES", "gateway,front_end"},
               {"SQS_DATA_ENDPOINTS", "http://d1:9324,https://d2:9324"},
               {"SQS_FORWARD_SECRET", "forwarding-secret-0123456789"}});
    o = std::get_if<sqs::sqs_node_options>(&r);
    BOOST_TEST_REQUIRE(o != nullptr);
    BOOST_TEST(!o->has(role::data));
    BOOST_TEST(
        (o->_data_endpoints == std::vector<std::string>{"http://d1:9324", "https://d2:9324"}));

    // A data node alone needs nothing more.
    r = parse({{"KYTHIRA_SQS_ROLES", "data"}});
    BOOST_TEST(std::holds_alternative<sqs::sqs_node_options>(r));

    const auto refused = [&](std::map<std::string, std::string> extra) {
        const auto x = parse(std::move(extra));
        const auto* s = std::get_if<std::string>(&x);
        return s != nullptr ? *s : std::string();
    };
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", "cache"}}).find("KYTHIRA_SQS_ROLES") !=
               std::string::npos);
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", "segments"}}).find("not an SQS layer") !=
               std::string::npos);
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", ""}}).find("at least one") != std::string::npos);
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", "front_end,data"}}).find("together") !=
               std::string::npos);
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", "gateway,front_end"},
                        {"SQS_FORWARD_SECRET", "forwarding-secret-0123456789"}})
                   .find("SQS_DATA_ENDPOINTS") != std::string::npos);
    BOOST_TEST(refused({{"KYTHIRA_SQS_ROLES", "gateway,front_end"},
                        {"SQS_DATA_ENDPOINTS", "http://d1:9324"}})
                   .find("SQS_FORWARD_SECRET") != std::string::npos);
    BOOST_TEST(refused({{"SQS_DATA_ENDPOINTS", "d1:9324"}}).find("SQS_DATA_ENDPOINTS") !=
               std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
