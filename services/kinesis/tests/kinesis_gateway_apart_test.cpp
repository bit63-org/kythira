// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The gateway apart from the front end (`.kiro/specs/kinesis-independent-
// layers/` task 8, Requirements 4.1-4.7 and 8.2-8.5): the authenticated
// call and its wire, affinity by shard and account, failover only for calls
// that cannot have run, the front end's trust in gateways alone, the Lease
// API, /metrics and SubscribeToShard relayed through the gateway, and
// draining.
//
// Front ends are separate objects over one in-process cluster, each serving
// the front-end API on a loopback listener (kinesis_layouts.hpp); the
// gateway reaches them over the real internal transport.

#define BOOST_TEST_MODULE kinesis_gateway_apart_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_affinity.hpp>
#include <kythira/kinesis/kinesis_authenticated_call.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_gateway.hpp>
#include <kythira/kinesis/kinesis_iterators.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include "kinesis_gateway_layouts.hpp"

#include <raft/aws_eventstream.hpp>
#include <raft/beast_https_server.hpp>
#include <raft/layer_identity.hpp>
#include <raft/record_segment_store.hpp>

#include <test_ports.hpp>

#include <boost/asio.hpp>
#include <boost/json.hpp>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kin = kythira::kinesis;
namespace kt = kythira::kinesis::test;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace es = kythira::aws_eventstream;
namespace https = kythira::https;
namespace layers = kythira::layers;
namespace json = boost::json;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_other_account = "444455556666";

struct temp_dir {
    std::filesystem::path _path;
    temp_dir() {
        static int counter = 0;
        _path = std::filesystem::temp_directory_path() /
                ("kinesis_gateway_apart_test." + std::to_string(::getpid()) + "." +
                 std::to_string(++counter));
        std::filesystem::remove_all(_path);
        std::filesystem::create_directories(_path);
    }
    ~temp_dir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
};

/// Signs everyone in as alice of `k_account`, or of the account an
/// `x-test-account` header names; refuses a request carrying
/// `x-test-unsigned`; allows every action except on `forbidden` streams.
struct test_auth {
    std::atomic<int> authentications{0};

    auto authenticate(const sv4::request& r, const sv4::service_rules&) -> az::authn_result {
        ++authentications;
        az::principal_context p;
        p.account = std::string(k_account);
        for (const auto& [k, v] : r.headers) {
            if (kin::detail::iequals(k, "x-test-unsigned")) {
                return sv4::aws_error{.code = "MissingAuthenticationTokenException",
                                      .message = "Missing Authentication Token",
                                      .http_status = 403};
            }
            if (kin::detail::iequals(k, "x-test-account")) {
                p.account = v;
            }
        }
        p.arn = "arn:aws:iam::" + p.account + ":user/alice";
        p.tags = {{"team", "streams"}};
        return p;
    }
    auto authorize(const az::principal_context&, const az::authz_request& r) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = r.resource.find("stream/forbidden") == std::string::npos;
        return d;
    }
};

auto service_config() -> kin::kinesis_service_config {
    kin::kinesis_service_config c;
    c._iterator_keys._keys.push_back({._id = 3, ._secret = "the cluster's iterator key, shared"});
    c._throughput._read_calls_per_s = 1e9;
    c._throughput._iterator_calls_per_s = 1e9;
    c._throughput._read_bytes_per_s = 1e12;
    c._control_plane._rates.clear();
    c._subscription_heartbeat = std::chrono::milliseconds(200);
    c._subscription_poll = std::chrono::milliseconds(10);
    c._subscription_recheck = std::chrono::milliseconds(50);
    return c;
}

/// The data layer: one in-process cluster.
struct data_layer {
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store =
        std::make_unique<kythira::record_segment_store>(kythira::record_segment_store_options{
            ._data_dir = dir._path, ._barriers_enabled = false});
    kin::local_stream_cluster cluster{store.get()};
};

/// One front end of the cluster serving gateways: its own service and
/// Lease API over the shared cluster, on a loopback listener.
struct front_end_node {
    test_auth auth;
    kin::front_end<test_auth> fe{kin::front_end_config{}, auth};
    kin::local_data_access<kin::local_stream_cluster> access;
    kin::kinesis_service<kin::data_access> service;
    kin::lease_api<kin::data_access, test_auth> leases;
    kt::loopback_front_end<kin::front_end<test_auth>> served;

    explicit front_end_node(data_layer& d,
                            std::string secret = std::string(kt::layout_detail::k_secret))
        : access(d.cluster),
          service(access, service_config()),
          leases(access, auth, kin::front_end_config{}),
          served(
              fe, [this](const kin::authenticated_call& c) { return leases.execute(c); },
              [this] { return service.metrics_text() + "# front end\n"; }, std::move(secret)) {
        service.register_with(fe);
        fe.set_resource_lookup(
            [this](std::string_view arn) { return service.resource_facts_of(arn); });
    }
};

auto request(std::string_view op, const json::value& body,
             std::vector<std::pair<std::string, std::string>> extra = {})
    -> kin::front_end_request {
    kin::front_end_request r;
    r._method = "POST";
    r._path = "/";
    r._body = json::serialize(body);
    r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                  {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
    for (auto& h : extra) {
        r._headers.push_back(std::move(h));
    }
    return r;
}

auto type_of(const aj::http_response& r) -> std::string {
    const auto o = json::parse(r.body).as_object();
    return o.contains("__type") ? std::string(o.at("__type").as_string()) : std::string();
}

/// A gateway in front of `front_ends`, with helpers for the calls tests
/// make.
struct gateway_node {
    test_auth auth;
    kt::gateway_apart<test_auth> gw;

    explicit gateway_node(std::vector<std::string> front_ends,
                          std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
        : gw(auth, std::move(front_ends), std::string(kt::layout_detail::k_secret), timeout) {}

    auto call(std::string_view op, const json::value& body,
              std::vector<std::pair<std::string, std::string>> extra = {}) -> aj::http_response {
        return gw.handle(request(op, body, std::move(extra)));
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto iterator(std::string_view stream, std::string_view shard) -> std::string {
        return std::string(
            ok("GetShardIterator",
               {{"StreamName", stream}, {"ShardId", shard}, {"ShardIteratorType", "TRIM_HORIZON"}})
                .at("ShardIterator")
                .as_string());
    }
};

auto shard_id(int i) -> std::string {
    return kin::shard_id_of(static_cast<std::uint32_t>(i));
}

auto a_call(std::string op, json::object input, std::string account = std::string(k_account))
    -> kin::authenticated_call {
    kin::authenticated_call c;
    c._operation = std::move(op);
    c._input = std::move(input);
    c._principal.account = std::move(account);
    return c;
}

}  // namespace

// ---- affinity --------------------------------------------------------------

// Requirement 8.3: a shard's reads, iterator calls and subscriptions share a
// key; control-plane calls are keyed by account; writes go anywhere.
BOOST_AUTO_TEST_CASE(calls_are_keyed_by_shard_account_or_nothing) {
    const auto shard3 = kin::affinity_of(
        a_call("GetShardIterator", {{"StreamName", "orders"}, {"ShardId", shard_id(3)}}));
    BOOST_TEST((shard3._kind == kin::affinity_kind::shard));
    // The same shard by ARN, by consumer and by iterator.
    BOOST_TEST((kin::affinity_of(
                    a_call("GetShardIterator",
                           {{"StreamARN", "arn:aws:kinesis:us-east-1:111122223333:stream/orders"},
                            {"ShardId", "shardId-000000000003"}})) == shard3));
    BOOST_TEST((kin::affinity_of(a_call(
                    "SubscribeToShard",
                    {{"ConsumerARN",
                      "arn:aws:kinesis:us-east-1:111122223333:stream/orders/consumer/c:1700000000"},
                     {"ShardId", shard_id(3)}})) == shard3));
    kin::iterator_key_ring ring;
    ring._keys.push_back({._id = 1, ._secret = "k"});
    const auto token = kin::encode_iterator(
        {._account = std::string(k_account), ._stream = "orders", ._stream_id = 9, ._ordinal = 3},
        ring);
    BOOST_TEST((kin::affinity_of(a_call("GetRecords", {{"ShardIterator", token}})) == shard3));
    // A forged token routes like a real one: the gateway does not check it.
    kin::iterator_key_ring other;
    other._keys.push_back({._id = 7, ._secret = "not the cluster's"});
    const auto forged = kin::encode_iterator(
        {._account = std::string(k_account), ._stream = "orders", ._stream_id = 9, ._ordinal = 3},
        other);
    BOOST_TEST((kin::affinity_of(a_call("GetRecords", {{"ShardIterator", forged}})) == shard3));
    BOOST_TEST(!kin::decode_iterator(forged, ring).has_value());
    // Another shard, another stream, another account: other keys.
    BOOST_TEST(!(kin::affinity_of(a_call("GetShardIterator",
                                         {{"StreamName", "orders"}, {"ShardId", shard_id(4)}})) ==
                 shard3));
    BOOST_TEST(!(kin::affinity_of(a_call("GetShardIterator",
                                         {{"StreamName", "orders"}, {"ShardId", shard_id(3)}},
                                         std::string(k_other_account))) == shard3));
    // A malformed iterator goes anywhere and fails there.
    BOOST_TEST((kin::affinity_of(a_call("GetRecords", {{"ShardIterator", "AAAA"}}))._kind ==
                kin::affinity_kind::any));

    // The control plane by account.
    const auto acct = kin::affinity_of(a_call("CreateStream", {{"StreamName", "orders"}}));
    BOOST_TEST((acct._kind == kin::affinity_kind::account));
    BOOST_TEST((kin::affinity_of(a_call("ListStreams", {})) == acct));
    BOOST_TEST((kin::affinity_of(a_call("DescribeStreamSummary", {{"StreamName", "x"}})) == acct));
    // Writes and leases anywhere.
    BOOST_TEST((kin::affinity_of(a_call("PutRecords", {{"StreamName", "orders"}}))._kind ==
                kin::affinity_kind::any));
    auto lease = a_call("", {});
    lease._kind = kin::call_kind::lease;
    BOOST_TEST((kin::affinity_of(lease)._kind == kin::affinity_kind::any));
}

// Requirement 8.4: when a front end leaves, only its own keys move.
BOOST_AUTO_TEST_CASE(rendezvous_moves_only_a_departing_front_ends_keys) {
    const std::vector<std::string> four{"fe-a:1", "fe-b:1", "fe-c:1", "fe-d:1"};
    const std::vector<std::string> three{"fe-a:1", "fe-b:1", "fe-d:1"};
    std::map<std::string, int> share;
    int moved = 0;
    for (int i = 0; i < 2000; ++i) {
        const auto key = "shard\n" + std::to_string(i);
        const auto before = four[kin::rendezvous_order(key, four).front()];
        const auto after = three[kin::rendezvous_order(key, three).front()];
        ++share[before];
        if (before != "fe-c:1") {
            BOOST_TEST(after == before, key);
        } else {
            ++moved;
        }
    }
    // Every front end owns a fair share (a quarter, give or take).
    for (const auto& [fe, n] : share) {
        BOOST_TEST((n > 350 && n < 650), fe << " owns " << n);
    }
    BOOST_TEST(moved == share["fe-c:1"]);
    // The order does not depend on how the list was written.
    const std::vector<std::string> shuffled{"fe-d:1", "fe-b:1", "fe-a:1", "fe-c:1"};
    kin::front_end_set a(four);
    kin::front_end_set b(shuffled);
    const kin::affinity_key k{kin::affinity_kind::shard, "shard\n42"};
    BOOST_TEST(a.order_for(k) == b.order_for(k));
}

BOOST_AUTO_TEST_CASE(a_front_end_that_failed_goes_to_the_back_for_a_while) {
    auto now = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    kin::front_end_set set(
        {"fe-a:1", "fe-b:1", "fe-c:1"},
        {._suspect_for = std::chrono::milliseconds(500), ._clock = [&] { return now; }});
    const kin::affinity_key k{kin::affinity_kind::account, "account\n1"};
    const auto order = set.order_for(k);
    set.mark_unreachable(order.front());
    const auto shunned = set.order_for(k);
    BOOST_TEST(shunned.back() == order.front());
    BOOST_TEST(shunned.front() == order[1]);
    BOOST_TEST(set.suspects() == 1U);
    now += std::chrono::milliseconds(600);
    BOOST_TEST(set.order_for(k) == order);
    set.mark_unreachable(order.front());
    set.mark_reachable(order.front());
    BOOST_TEST(set.order_for(k) == order);
    // `any` takes turns over every front end.
    std::set<std::string> firsts;
    for (int i = 0; i < 3; ++i) {
        firsts.insert(set.order_for({}).front());
    }
    BOOST_TEST(firsts.size() == 3U);
}

// ---- the wire --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(an_authenticated_call_crosses_the_wire_whole) {
    kin::authenticated_call c;
    c._kind = kin::call_kind::api;
    c._operation = "PutRecord";
    c._input = {{"StreamName", "orders"}, {"Data", "YQ=="}, {"Nested", {{"n", 1.5}, {"b", true}}}};
    c._encoding = aj::body_encoding::cbor;
    c._request_id = "req-1";
    c._principal.type = az::principal_type::assumed_role;
    c._principal.account = std::string(k_account);
    c._principal.arn = "arn:aws:sts::111122223333:assumed-role/r/s";
    c._principal.userid = "AROAEXAMPLE:s";
    c._principal.role_arn = "arn:aws:iam::111122223333:role/r";
    c._principal.session_name = "s";
    c._principal.tags = {{"team", "streams"}, {"env", "prod"}};
    c._principal.token_issue_time =
        std::chrono::system_clock::time_point(std::chrono::milliseconds(1'762'776'000'123));
    c._principal.source_identity = "alice";
    c._principal.session_policies = {R"({"Version":"2012-10-17"})"};
    c._principal.transitive_tag_keys = {"team"};
    c._principal.session_token = true;
    c._source_ip = "203.0.113.9";
    c._user_agent = "aws-sdk-java/2";
    c._secure = false;
    const auto back = kin::front_end_api::decode_call(kin::front_end_api::encode_call(c));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->_operation == c._operation);
    BOOST_TEST(back->_input == c._input);
    BOOST_TEST((back->_encoding == aj::body_encoding::cbor));
    BOOST_TEST(back->_request_id == "req-1");
    BOOST_TEST((back->_principal.type == az::principal_type::assumed_role));
    BOOST_TEST(back->_principal.arn == c._principal.arn);
    BOOST_TEST(back->_principal.tags == c._principal.tags);
    BOOST_TEST((back->_principal.token_issue_time == c._principal.token_issue_time));
    BOOST_TEST(!back->_principal.expires.has_value());
    BOOST_TEST(back->_principal.session_policies == c._principal.session_policies);
    BOOST_TEST(back->_principal.transitive_tag_keys == c._principal.transitive_tag_keys);
    BOOST_TEST(back->_principal.session_token);
    BOOST_TEST(back->_source_ip == "203.0.113.9");
    BOOST_TEST(back->_user_agent == "aws-sdk-java/2");
    BOOST_TEST(!back->_secure);

    // A lease call carries its REST request without the signature.
    kin::authenticated_call l;
    l._kind = kin::call_kind::lease;
    l._method = "PUT";
    l._path = "/v1/leases/app/k";
    l._query = "a=1";
    l._headers = {{"if-none-match", "*"}};
    l._body = R"({"leaseOwner":"w"})";
    const auto lb = kin::front_end_api::decode_call(kin::front_end_api::encode_call(l));
    BOOST_REQUIRE(lb.has_value());
    BOOST_TEST((lb->_kind == kin::call_kind::lease));
    BOOST_TEST(lb->_headers == l._headers);
    BOOST_TEST(lb->_body == l._body);

    // Truncated, padded or of another version: not a call.
    auto bytes = kin::front_end_api::encode_call(c);
    BOOST_TEST(!kin::front_end_api::decode_call(bytes.substr(0, bytes.size() - 1)).has_value());
    BOOST_TEST(!kin::front_end_api::decode_call(bytes + "x").has_value());
    bytes[0] = 2;
    BOOST_TEST(!kin::front_end_api::decode_call(bytes).has_value());
    BOOST_TEST(!kin::front_end_api::decode_call("").has_value());

    const kin::front_end_api::call_answer a{{.status = 400, .headers = {{"x", "y"}}, .body = "b"},
                                            "session"};
    const auto ab = kin::front_end_api::decode_answer(kin::front_end_api::encode_answer(a));
    BOOST_REQUIRE(ab.has_value());
    BOOST_TEST(ab->_response.status == 400U);
    BOOST_TEST(ab->_session == "session");
    const auto pb = kin::front_end_api::decode_pull_answer(
        kin::front_end_api::encode_pull_answer({{"m1", "m2"}, true}));
    BOOST_REQUIRE(pb.has_value());
    BOOST_TEST(pb->_messages.size() == 2U);
    BOOST_TEST(pb->_done);
}

// ---- through the gateway ---------------------------------------------------

// Requirements 4.1, 4.2 and 8.5: the gateway frames, decodes and verifies,
// and answers STS and every framing or signature fault itself; the front
// end authorizes and executes.
BOOST_AUTO_TEST_CASE(the_gateway_verifies_and_the_front_end_executes) {
    data_layer d;
    front_end_node fe(d);
    gateway_node g({fe.served.address()});

    g.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 2}});
    const auto put =
        g.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "a"}, {"Data", "YQ=="}});
    const auto shard = std::string(put.at("ShardId").as_string());
    const auto got = g.ok("GetRecords", {{"ShardIterator", g.iterator("orders", shard)}});
    BOOST_TEST(got.at("Records").as_array().size() == 1U);
    BOOST_TEST(fe.served.executed() == 4U);
    // SigV4 ran on the gateway only: the front end trusted the principal.
    BOOST_TEST(g.auth.authentications.load() == 4);
    BOOST_TEST(fe.auth.authentications.load() == 0);

    // Authorization is the front end's: it refuses a forbidden stream.
    const auto denied = g.call("CreateStream", {{"StreamName", "forbidden"}, {"ShardCount", 1}});
    BOOST_TEST(denied.status == 400U);
    BOOST_TEST(type_of(denied) == "AccessDeniedException");
    BOOST_TEST(fe.served.executed() == 5U);

    // The gateway answers these without reaching a front end.
    const auto unsigned_call = g.call("ListStreams", json::object{}, {{"x-test-unsigned", "1"}});
    BOOST_TEST(unsigned_call.status == 403U);
    BOOST_TEST(type_of(unsigned_call) == "MissingAuthenticationTokenException");
    const auto bad_input = g.call("CreateStream", {{"StreamName", 7}});
    BOOST_TEST(bad_input.status == 400U);
    BOOST_TEST(type_of(bad_input) != "AccessDeniedException");
    const auto unknown = g.call("NoSuchOperation", json::object{});
    BOOST_TEST(type_of(unknown) == "UnknownOperationException");
    kin::front_end_request sts;
    sts._method = "POST";
    sts._path = "/";
    sts._body = "Action=GetCallerIdentity&Version=2011-06-15";
    sts._headers = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const auto who = g.gw.handle(sts);
    BOOST_TEST(who.status == 200U);
    BOOST_TEST(who.body.find("<Account>111122223333</Account>") != std::string::npos);
    BOOST_TEST(fe.served.executed() == 5U);

    // The answer comes back in the client's encoding (CBOR here) with the
    // gateway's request id.
    auto cbor = request("ListStreams", json::object{});
    cbor._headers[0].second = "application/x-amz-cbor-1.1";
    cbor._body = aj::json_to_cbor(kin::kinesis_model::k_model,
                                  kin::kinesis_model::k_model.find_shape("ListStreamsInput"),
                                  json::object{}, aj::cbor_timestamp_unit::milliseconds);
    const auto listed = g.gw.handle(cbor);
    BOOST_TEST(listed.status == 200U);
    bool cbor_type = false;
    for (const auto& [k, v] : listed.headers) {
        cbor_type = cbor_type || (k == "Content-Type" && v == "application/x-amz-cbor-1.1");
    }
    BOOST_TEST(cbor_type);
}

// Requirement 4.6: the Lease API, authenticated at the gateway and executed
// on the front end, with its conditions intact.
BOOST_AUTO_TEST_CASE(the_lease_api_goes_through_the_gateway) {
    data_layer d;
    front_end_node fe(d);
    gateway_node g({fe.served.address()});
    const auto lease = [&](std::string method, std::string body,
                           std::vector<std::pair<std::string, std::string>> headers) {
        kin::front_end_request r;
        r._method = std::move(method);
        r._path = "/v1/leases/app/shard-1";
        r._body = std::move(body);
        r._headers = std::move(headers);
        return g.gw.handle(r);
    };
    BOOST_TEST(lease("PUT", R"({"leaseOwner":"w1"})", {{"If-None-Match", "*"}}).status == 200U);
    BOOST_TEST(lease("PUT", R"({"leaseOwner":"w2"})", {{"If-None-Match", "*"}}).status == 412U);
    const auto got = lease("GET", "", {});
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(got.body.find("\"w1\"") != std::string::npos);
    BOOST_TEST(lease("PATCH", R"({"leaseOwner":"w3"})", {{"If-Match", "\"999999\""}}).status ==
               412U);
    BOOST_TEST(fe.served.executed() == 4U);
    // An unsigned lease request stops at the gateway.
    const auto refused = lease("GET", "", {{"x-test-unsigned", "1"}});
    BOOST_TEST(refused.status == 403U);
    BOOST_TEST(fe.served.executed() == 4U);
}

// Requirement 8.3: every gateway sends a shard's reads to one front end, and
// spreads shards and accounts over all of them.
BOOST_AUTO_TEST_CASE(each_shard_and_account_has_one_front_end) {
    data_layer d;
    front_end_node a(d);
    front_end_node b(d);
    front_end_node c(d);
    const std::vector<std::string> all{a.served.address(), b.served.address(), c.served.address()};
    gateway_node g1(all);
    gateway_node g2({all[2], all[0], all[1]});  // listed in another order
    g1.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 8}});

    const std::vector<front_end_node*> fes{&a, &b, &c};
    const auto counts = [&] {
        std::vector<std::uint64_t> out;
        for (auto* f : fes) {
            out.push_back(f->served.executed());
        }
        return out;
    };
    const auto who_ran = [&](const std::vector<std::uint64_t>& before) {
        const auto after = counts();
        int ran = -1;
        for (std::size_t i = 0; i < after.size(); ++i) {
            if (after[i] != before[i]) {
                BOOST_TEST(ran == -1, "two front ends ran one call");
                ran = static_cast<int>(i);
            }
        }
        return ran;
    };
    std::set<int> owners;
    for (int s = 0; s < 8; ++s) {
        auto before = counts();
        const auto it = g1.iterator("orders", shard_id(s));
        const auto owner = who_ran(before);
        before = counts();
        (void)g2.ok("GetRecords", {{"ShardIterator", it}});
        BOOST_TEST(who_ran(before) == owner, "GetRecords of shard " << s);
        before = counts();
        (void)g2.iterator("orders", shard_id(s));
        BOOST_TEST(who_ran(before) == owner, "GetShardIterator of shard " << s << " on g2");
        owners.insert(owner);
    }
    BOOST_TEST(owners.size() >= 2U);
    // One account's control plane on one front end, from either gateway.
    auto before = counts();
    (void)g1.ok("ListStreams", json::object{});
    const auto acct = who_ran(before);
    before = counts();
    (void)g2.ok("DescribeStreamSummary", {{"StreamName", "orders"}});
    BOOST_TEST(who_ran(before) == acct);
}

// Requirement 4.4: a front end that cannot be reached, or says it did not
// run a call, is skipped; one that took a call and did not answer is not
// retried, since the call may have run.
BOOST_AUTO_TEST_CASE(a_call_moves_on_only_when_it_cannot_have_run) {
    data_layer d;
    front_end_node a(d);
    front_end_node b(d);
    gateway_node g({a.served.address(), b.served.address()});
    g.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});

    // A crashed front end: every call lands on the other.
    a.served.stop();
    for (int i = 0; i < 6; ++i) {
        g.ok("PutRecord",
             {{"StreamName", "orders"}, {"PartitionKey", std::to_string(i)}, {"Data", "YQ=="}});
    }
    BOOST_TEST(g.gw.link().stats()._failovers.load() > 0U);
    BOOST_TEST(g.gw.link().front_ends().suspects() == 1U);
    a.served.start();

    // A draining front end says it did not run the call.
    b.served.api().drain();
    const auto before = a.served.executed();
    for (int i = 0; i < 4; ++i) {
        g.ok("ListShards", {{"StreamName", "orders"}});
    }
    BOOST_TEST(a.served.executed() == before + 4U);
    BOOST_TEST(b.served.api().stats()._not_executed.load() > 0U);

    // Neither: InternalFailure, which every client retries.
    a.served.stop();
    const auto none = g.call("ListShards", {{"StreamName", "orders"}});
    BOOST_TEST(none.status == 500U);
    BOOST_TEST(type_of(none) == "InternalFailure");
    BOOST_TEST(g.gw.link().stats()._unplaced.load() > 0U);
}

BOOST_AUTO_TEST_CASE(a_call_that_may_have_run_is_not_sent_again) {
    data_layer d;
    front_end_node b(d);
    // A front end that takes the connection and the request, then hangs.
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::acceptor acceptor(ioc, {boost::asio::ip::make_address("127.0.0.1"), 0});
    std::atomic<bool> stop{false};
    std::thread hang([&] {
        boost::system::error_code ec;
        while (!stop.load()) {
            boost::asio::ip::tcp::socket s(ioc);
            (void)acceptor.accept(s, ec);
            if (ec) {
                return;
            }
            std::array<char, 4096> buf{};
            (void)s.read_some(boost::asio::buffer(buf), ec);
            while (!stop.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        }
    });
    const auto hanging = "127.0.0.1:" + std::to_string(acceptor.local_endpoint().port());
    gateway_node g({hanging, b.served.address()}, std::chrono::milliseconds(400));
    // An account whose control-plane calls go to the hanging one first.
    std::string account;
    for (int i = 0; i < 64 && account.empty(); ++i) {
        const auto acct = std::to_string(100000000000LL + i);
        const auto order =
            g.gw.link().front_ends().order_for(kin::affinity_of(a_call("ListStreams", {}, acct)));
        if (order.front() == hanging) {
            account = acct;
        }
    }
    BOOST_REQUIRE(!account.empty());
    const auto before = b.served.executed();
    const auto r = g.call("ListStreams", json::object{}, {{"x-test-account", account}});
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(type_of(r) == "InternalFailure");
    BOOST_TEST(b.served.executed() == before, "the call was not sent to a second front end");
    BOOST_TEST(g.gw.link().stats()._unanswered.load() == 1U);
    stop = true;
    boost::system::error_code ec;
    (void)acceptor.close(ec);
    hang.join();
}

// Requirement 4.3: only a gateway may hand a front end a principal.
BOOST_AUTO_TEST_CASE(a_front_end_trusts_only_gateways) {
    data_layer d;
    front_end_node fe(d);
    auto c = a_call("ListStreams", {});
    c._request_id = "r";
    const auto body = kin::front_end_api::encode_call(c);
    const kin::peer_client peers(kin::peer_client_config{._tls = false, ._ca_path = {}});
    const auto post = [&](std::vector<std::pair<std::string, std::string>> headers) {
        return peers.request(fe.served.address(), boost::beast::http::verb::post,
                             kin::front_end_api::k_call_path, headers, body);
    };
    // Unsigned, and signed with another cluster's secret: refused.
    BOOST_TEST(post({})->_status == 403U);
    const auto wrong =
        kin::forward::sign("another-cluster-secret-0123456789",
                           kin::front_end_api::signed_text(kin::front_end_api::k_call_path, body),
                           std::chrono::system_clock::now());
    BOOST_TEST(post({{std::string(kin::forward::k_header), wrong}})->_status == 403U);
    // A signature over another route does not carry over.
    const auto other_route =
        kin::forward::sign(std::string(kt::layout_detail::k_secret),
                           kin::front_end_api::signed_text(kin::front_end_api::k_pull_path, body),
                           std::chrono::system_clock::now());
    BOOST_TEST(post({{std::string(kin::forward::k_header), other_route}})->_status == 403U);
    BOOST_TEST(fe.served.executed() == 0U);
    BOOST_TEST(fe.served.api().stats()._refused.load() == 3U);
    // The cluster's secret over this route: executed.
    const auto good =
        kin::forward::sign(std::string(kt::layout_detail::k_secret),
                           kin::front_end_api::signed_text(kin::front_end_api::k_call_path, body),
                           std::chrono::system_clock::now());
    BOOST_TEST(post({{std::string(kin::forward::k_header), good}})->_status == 200U);
    BOOST_TEST(fe.served.executed() == 1U);

    // With layer identities: the gateway role is admitted, any other refused.
    layers::route_guard_options go;
    go.service = "kinesis";
    go.cluster = "test";
    go.rules = {{std::string(kin::front_end_api::k_prefix), layers::role_set::parse("gateway")}};
    fe.served.node().set_layer_guard(std::make_shared<layers::route_guard>(go));
    const auto with_identity = [&](std::string roles) {
        https::request req;
        req.method(boost::beast::http::verb::post);
        req.target(std::string(kin::front_end_api::k_call_path));
        req.body() = body;
        req.prepare_payload();
        https::request_context ctx;
        ctx.tls = true;
        ctx.client_verified = true;
        ctx.client_uri_sans = {"kythira://kinesis/test/7?roles=" + roles};
        return fe.served.node().handle(req, ctx).result_int();
    };
    BOOST_TEST(with_identity("gateway") == 200U);
    BOOST_TEST(with_identity("front_end,data") == 403U);
    BOOST_TEST(fe.served.executed() == 2U);

    // A node without the front_end role takes no call: not executed, so the
    // gateway moves on.
    test_auth auth;
    kin::front_end<test_auth> bare{kin::front_end_config{}, auth};
    kt::loopback_front_end<kin::front_end<test_auth>> data_only(
        bare, {}, {}, std::string(kt::layout_detail::k_secret),
        layers::role_set::parse("data,segments"));
    const auto r = peers.request(data_only.address(), boost::beast::http::verb::post,
                                 kin::front_end_api::k_call_path,
                                 {{std::string(kin::forward::k_header), good}}, body);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST(r->_status == kin::front_end_api::k_not_executed);
}

namespace {

struct pulled {
    std::string _message_type;
    std::string _type;
};

auto parse(const std::string& bytes) -> pulled {
    const auto m = es::decode({reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()});
    pulled p;
    p._message_type = std::string(m.string_header(":message-type").value_or(""));
    p._type = std::string(
        m.string_header(p._message_type == "exception" ? ":exception-type" : ":event-type")
            .value_or(""));
    return p;
}

/// The next message of a relayed stream within `limit`; nullopt at its end.
auto next_message(https::streaming_response& s, bool& open,
                  std::chrono::milliseconds limit = std::chrono::milliseconds(5000))
    -> std::optional<pulled> {
    const auto until = std::chrono::steady_clock::now() + limit;
    while (open && std::chrono::steady_clock::now() < until) {
        std::string chunk;
        open = s.next(chunk);
        if (!chunk.empty()) {
            return parse(chunk);
        }
    }
    return std::nullopt;
}

auto subscribe_request(const std::string& consumer) -> https::request {
    return kt::to_https(
        request("SubscribeToShard", {{"ConsumerARN", consumer},
                                     {"ShardId", shard_id(0)},
                                     {"StartingPosition", {{"Type", "TRIM_HORIZON"}}}}));
}

auto register_consumer(gateway_node& g) -> std::string {
    const auto arn = std::string(g.ok("DescribeStreamSummary", {{"StreamName", "orders"}})
                                     .at("StreamDescriptionSummary")
                                     .at("StreamARN")
                                     .as_string());
    return std::string(g.ok("RegisterStreamConsumer", {{"StreamARN", arn}, {"ConsumerName", "c"}})
                           .at("Consumer")
                           .at("ConsumerARN")
                           .as_string());
}

}  // namespace

// Requirement 4.5: the gateway holds the client's stream and relays the
// front end's events; when the front end goes away it ends the stream with
// the retryable InternalFailureException.
BOOST_AUTO_TEST_CASE(subscribe_to_shard_is_relayed_and_ends_retryably) {
    data_layer d;
    front_end_node fe(d);
    gateway_node g({fe.served.address()});
    g.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});
    const auto consumer = register_consumer(g);
    g.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "a"}, {"Data", "YQ=="}});

    auto s = g.gw.node().stream(subscribe_request(consumer), {});
    BOOST_REQUIRE(s.has_value());
    BOOST_TEST(s->head.result_int() == 200U);
    bool open = true;
    const auto first = next_message(*s, open);
    BOOST_REQUIRE(first.has_value());
    BOOST_TEST(first->_type == "initial-response");
    const auto event = next_message(*s, open);
    BOOST_REQUIRE(event.has_value());
    BOOST_TEST(event->_type == "SubscribeToShardEvent");
    BOOST_TEST(fe.served.api().sessions() == 1U);

    // The front end restarts: its sessions are gone, the gateway ends the
    // stream with the retryable error, and the client subscribes again.
    fe.served.restart();
    std::optional<pulled> last;
    while (auto m = next_message(*s, open)) {
        last = m;
    }
    BOOST_REQUIRE(last.has_value());
    BOOST_TEST(last->_message_type == "exception");
    BOOST_TEST(last->_type == "InternalFailureException");
    BOOST_TEST(!open);
    BOOST_TEST(g.gw.link().stats()._streams_broken.load() == 1U);

    auto again = g.gw.node().stream(subscribe_request(consumer), {});
    BOOST_REQUIRE(again.has_value());
    bool open2 = true;
    BOOST_TEST(next_message(*again, open2)->_type == "initial-response");
    // A client that goes away ends the session on the front end.
    again->cancel();
    BOOST_TEST(fe.served.api().sessions() <= 1U);

    // A refusal comes back whole: an unknown shard.
    auto refused = g.gw.node().stream(
        kt::to_https(request("SubscribeToShard", {{"ConsumerARN", consumer},
                                                  {"ShardId", shard_id(42)},
                                                  {"StartingPosition", {{"Type", "LATEST"}}}})),
        {});
    BOOST_REQUIRE(refused.has_value());
    BOOST_TEST(refused->head.result_int() == 400U);
}

// Requirement 4.7: a draining gateway reports unhealthy, stops its
// listener accepting, closes connections after each answer and ends its
// event streams with the retryable error.
BOOST_AUTO_TEST_CASE(a_draining_gateway_ends_streams_retryably) {
    data_layer d;
    front_end_node fe(d);
    gateway_node g({fe.served.address()});
    g.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});
    const auto consumer = register_consumer(g);
    int hooked = 0;
    g.gw.node().set_drain_hook([&] { ++hooked; });

    auto s = g.gw.node().stream(subscribe_request(consumer), {});
    BOOST_REQUIRE(s.has_value());
    bool open = true;
    BOOST_TEST(next_message(*s, open)->_type == "initial-response");

    https::request health;
    health.method(boost::beast::http::verb::get);
    health.target("/healthz");
    BOOST_TEST(g.gw.node().handle(health, {}).result_int() == 200U);

    // The drain route needs the cluster's signature.
    https::request drain;
    drain.method(boost::beast::http::verb::post);
    drain.target(std::string(kin::k_drain_path));
    BOOST_TEST(g.gw.node().handle(drain, {}).result_int() == 403U);
    drain.set(kin::forward::k_header,
              kin::forward::sign(std::string(kt::layout_detail::k_secret), kin::k_drain_path,
                                 std::chrono::system_clock::now()));
    BOOST_TEST(g.gw.node().handle(drain, {}).result_int() == 202U);
    BOOST_TEST(g.gw.node().draining());
    BOOST_TEST(hooked == 1);
    g.gw.node().begin_drain();
    BOOST_TEST(hooked == 1);

    BOOST_TEST(g.gw.node().handle(health, {}).result_int() == 503U);
    std::optional<pulled> last;
    while (auto m = next_message(*s, open)) {
        last = m;
    }
    BOOST_REQUIRE(last.has_value());
    BOOST_TEST(last->_type == "InternalFailureException");
    // Calls in flight finish; later answers close their connections.
    auto req = kt::to_https(request("ListStreams", json::object{}));
    req.keep_alive(true);
    const auto res = g.gw.node().handle(req, {});
    BOOST_TEST(res.result_int() == 200U);
    BOOST_TEST(!res.keep_alive());
    BOOST_TEST(g.gw.node().await_idle(std::chrono::milliseconds(100)));
    BOOST_TEST(g.gw.node().in_flight() == 0U);
}

// A listener that stops accepting keeps serving the connections it has.
BOOST_AUTO_TEST_CASE(a_listener_stops_accepting_and_keeps_its_connections) {
    https::server_config sc;
    sc.bind_address = "127.0.0.1";
    sc.insecure_plaintext = true;
    https::server server(sc, [](const https::request& req, const https::request_context&) {
        https::response res{boost::beast::http::status::ok, req.version()};
        res.keep_alive(req.keep_alive());
        res.body() = "ok";
        res.prepare_payload();
        return res;
    });
    server.start();
    namespace http = boost::beast::http;
    boost::asio::io_context ioc;
    boost::beast::tcp_stream open(ioc);
    open.connect({boost::asio::ip::make_address("127.0.0.1"), server.port()});
    const auto ask = [](boost::beast::tcp_stream& s) {
        http::request<http::string_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, "x");
        req.keep_alive(true);
        http::write(s, req);
        boost::beast::flat_buffer buf;
        http::response<http::string_body> res;
        http::read(s, buf, res);
        return res.body();
    };
    BOOST_TEST(ask(open) == "ok");
    server.stop_accepting();
    server.stop_accepting();
    BOOST_TEST(ask(open) == "ok");
    boost::beast::tcp_stream fresh(ioc);
    boost::system::error_code ec;
    (void)fresh.socket().connect({boost::asio::ip::make_address("127.0.0.1"), server.port()}, ec);
    BOOST_TEST(ec.failed(), "a new connection was accepted");
    server.stop();
}

// Requirement 4.6: /metrics through a gateway is a front end's, executed
// there.
BOOST_AUTO_TEST_CASE(metrics_come_from_a_front_end) {
    data_layer d;
    front_end_node fe(d);
    gateway_node g({fe.served.address()});
    g.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});
    const auto text = g.gw.link().metrics();
    BOOST_REQUIRE(text.has_value());
    BOOST_TEST(text->find("# front end") != std::string::npos);
    fe.served.stop();
    BOOST_TEST(!g.gw.link().metrics().has_value());
}
