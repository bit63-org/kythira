// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The gateway's HTTP surface (`.kiro/specs/kinesis-compatible-streams/`
// task 6) on a real listener: the Kinesis API through the front end, the
// internal propose and segment endpoints with their signatures, health,
// and the peer client over plain HTTP and verified TLS.

#define BOOST_TEST_MODULE kinesis_gateway_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_gateway.hpp>
#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_peer_client.hpp>
#include <kythira/kinesis/kinesis_service.hpp>
#include <kythira/kinesis/kinesis_static_keys.hpp>

#include <raft/beast_https_server.hpp>
#include <raft/certificate_authority.hpp>
#include <raft/private_file.hpp>
#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace https = kythira::https;
namespace json = boost::json;
namespace http = boost::beast::http;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_secret = "cluster-secret";

struct allow_all {
    auto authenticate(const sv4::request&, const sv4::service_rules&) -> az::authn_result {
        az::principal_context p;
        p.account = std::string(k_account);
        p.arn = "arn:aws:iam::" + std::string(k_account) + ":user/alice";
        return p;
    }
    auto authorize(const az::principal_context&, const az::authz_request&) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = true;
        return d;
    }
};

struct temp_dir {
    std::filesystem::path _path;
    temp_dir() {
        std::random_device rd;
        _path = std::filesystem::temp_directory_path() /
                ("kinesis-gateway-test-" + std::to_string(rd()) + std::to_string(rd()));
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

struct pki {
    temp_dir _dir;
    std::string _ca;
    std::string _cert;
    std::string _key;
    std::string _other_ca;

    pki() {
        raft::testing::certificate_authority ca;
        raft::testing::certificate_authority other;
        auto write = [this](const std::string& name, const std::string& pem) {
            const auto p = (_dir._path / name).string();
            raft::write_private_file(p, pem);
            return p;
        };
        _ca = write("ca.pem", ca.root_certificate_pem());
        _other_ca = write("other.pem", other.root_certificate_pem());
        raft::testing::leaf_certificate_options leaf;
        leaf.subject.common_name = "localhost";
        leaf.dns_names = {"localhost"};
        leaf.ip_addresses = {"127.0.0.1"};
        auto issued = ca.issue(leaf);
        _cert = write("server.pem", issued.chain_pem);
        _key = write("server.key", issued.private_key_pem);
    }
};

using front_end_type = kin::front_end<allow_all>;
using gateway_type = kin::gateway<front_end_type>;

/// One gateway over the in-process cluster with a segment store, on a
/// listener of its own (port 0: the kernel picks).
struct node {
    temp_dir _dir;
    std::unique_ptr<kythira::record_segment_store> _store;
    std::unique_ptr<kin::local_stream_cluster> _cluster;
    allow_all _auth;
    front_end_type _fe{kin::front_end_config{}, _auth};
    std::unique_ptr<kin::kinesis_service<kin::local_stream_cluster>> _service;
    std::unique_ptr<gateway_type> _gateway;
    std::unique_ptr<https::server> _server;

    explicit node(std::string secret = std::string(k_secret), const pki* tls = nullptr) {
        kythira::record_segment_store_options o;
        o._data_dir = _dir._path;
        _store = std::make_unique<kythira::record_segment_store>(o);
        _cluster = std::make_unique<kin::local_stream_cluster>(_store.get());
        _service = std::make_unique<kin::kinesis_service<kin::local_stream_cluster>>(*_cluster);
        _service->register_with(_fe);
        _gateway = std::make_unique<gateway_type>(
            _fe,
            [this](const std::string& key, const std::vector<std::byte>& cmd, kin::admission mode) {
                return _cluster->propose(key, cmd, mode);
            },
            _store.get(), std::move(secret));
        https::server_config sc;
        sc.bind_address = "127.0.0.1";
        if (tls != nullptr) {
            sc.tls_cert_path = tls->_cert;
            sc.tls_key_path = tls->_key;
        } else {
            sc.insecure_plaintext = true;
        }
        _server = std::make_unique<https::server>(
            sc, [this](const https::request& req, const https::request_context& ctx) {
                return _gateway->handle(req, ctx);
            });
        _server->start();
    }

    [[nodiscard]] auto address() const -> std::string {
        return "127.0.0.1:" + std::to_string(_server->port());
    }
};

auto plain_client() -> kin::peer_client {
    return kin::peer_client(kin::peer_client_config{._tls = false, ._ca_path = {}});
}

auto call(const kin::peer_client& c, const node& n, std::string_view op, const json::value& body)
    -> kin::peer_response {
    const auto r = c.request(n.address(), http::verb::post, "/",
                             {{"Content-Type", "application/x-amz-json-1.1"},
                              {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}},
                             json::serialize(body));
    BOOST_REQUIRE(r.has_value());
    return *r;
}

auto create(const std::string& name) -> std::vector<std::byte> {
    return kin::encode_command(kin::create_stream_command{
        ._account = std::string(k_account), ._name = name, ._shard_count = 1, ._created_ms = 1});
}

}  // namespace

BOOST_AUTO_TEST_CASE(health_and_the_kinesis_api_are_served) {
    node n;
    const auto c = plain_client();
    const auto h = c.request(n.address(), http::verb::get, kin::k_health_path, {});
    BOOST_TEST_REQUIRE(h.has_value());
    BOOST_TEST(h->_status == 200U);

    BOOST_TEST(call(c, n, "CreateStream", {{"StreamName", "orders"}, {"ShardCount", 2}})._status ==
               200U);
    const auto put = call(c, n, "PutRecord",
                          {{"StreamName", "orders"}, {"PartitionKey", "k"}, {"Data", "aGk="}});
    BOOST_TEST_REQUIRE(put._status == 200U);
    BOOST_TEST(json::parse(put._body).as_object().contains("SequenceNumber"));
    // AWS's errors pass through with their status.
    const auto missing = call(c, n, "DescribeStreamSummary", {{"StreamName", "nope"}});
    BOOST_TEST(missing._status == 400U);
    BOOST_TEST(missing._body.find("ResourceNotFoundException") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(a_signed_forwarded_write_commits_and_answers_its_result) {
    node n;
    const auto c = plain_client();
    const std::string address = n.address();
    auto forward = kin::make_http_forwarder<std::string>(
        c, std::string(k_secret),
        [&address](const std::string&) { return std::optional<std::string>(address); });
    const auto r = forward("leader", "k", create("s"), kin::admission::none);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->_status == kin::apply_status::ok));
    BOOST_TEST(n._gateway->stats()._forwarded_in == 1U);
    // Applied exactly once: the second create is a conflict, answered too.
    const auto again = forward("leader", "k", create("s"), kin::admission::none);
    BOOST_TEST_REQUIRE(again.has_value());
    BOOST_TEST((again->_status == kin::apply_status::already_exists));

    // A wrong secret, a stale clock, or an unknown leader reach nothing.
    auto wrong = kin::make_http_forwarder<std::string>(
        c, "other", [&address](const std::string&) { return std::optional<std::string>(address); });
    BOOST_TEST(!wrong("leader", "k", create("t"), kin::admission::none).has_value());
    auto stale = kin::make_http_forwarder<std::string>(
        c, std::string(k_secret),
        [&address](const std::string&) { return std::optional<std::string>(address); },
        [] { return std::chrono::system_clock::now() - std::chrono::minutes{5}; });
    BOOST_TEST(!stale("leader", "k", create("t"), kin::admission::none).has_value());
    auto nowhere = kin::make_http_forwarder<std::string>(
        c, std::string(k_secret),
        [](const std::string&) -> std::optional<std::string> { return std::nullopt; });
    BOOST_TEST(!nowhere("leader", "k", create("t"), kin::admission::none).has_value());
    BOOST_TEST(n._gateway->stats()._forward_refused == 2U);

    // Nothing proposed by the refused ones.
    bool absent = false;
    BOOST_TEST(n._cluster->read(
        "k", [&absent](const auto& sm) { absent = sm.find_stream(k_account, "t") == nullptr; }));
    BOOST_TEST(absent);
}

BOOST_AUTO_TEST_CASE(a_node_without_the_gateway_role_serves_only_its_peers) {
    // kinesis-independent-layers task 4: KINESIS_ROLES=data,segments is a
    // voter that holds replicas. It keeps the internal endpoints, health
    // and metrics, and turns clients away naming its roles.
    node n;
    n._gateway->set_roles(kythira::layers::role_set::parse("data,segments"));
    const auto c = plain_client();

    const auto h = c.request(n.address(), http::verb::get, kin::k_health_path, {});
    BOOST_TEST_REQUIRE(h.has_value());
    BOOST_TEST(h->_status == 200U);

    const auto api = call(c, n, "ListStreams", json::object{});
    BOOST_TEST(api._status == 404U);
    BOOST_TEST(api._body.find("LayerNotServed") != std::string::npos);
    BOOST_TEST(api._body.find("data,segments") != std::string::npos);
    // The Lease API is a client surface too.
    const auto lease =
        c.request(n.address(), http::verb::get, std::string(kin::k_lease_path_prefix) + "x", {});
    BOOST_TEST_REQUIRE(lease.has_value());
    BOOST_TEST(lease->_status == 404U);

    // A peer's signed write still commits here.
    const std::string address = n.address();
    auto forward = kin::make_http_forwarder<std::string>(
        c, std::string(k_secret),
        [&address](const std::string&) { return std::optional<std::string>(address); });
    const auto r = forward("leader", "k", create("s"), kin::admission::none);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->_status == kin::apply_status::ok));
}

BOOST_AUTO_TEST_CASE(a_front_end_reaches_the_data_layer_api_over_the_listener) {
    // kinesis-independent-layers task 6: a data node (here without the
    // gateway role) serves the v2 routes to a front end that signs with the
    // forward secret; an unsigned or wrongly signed call is refused.
    node n;
    n._gateway->set_roles(kythira::layers::role_set::parse("data,segments"));
    kin::local_data_access<kin::local_stream_cluster> local(*n._cluster);
    kin::data_api_deps deps;
    deps._local = &local;
    deps._propose_here = [&n](const std::string& key, const std::vector<std::byte>& command,
                              kin::admission mode) {
        kin::data_node_proposal p;
        p._result = n._cluster->propose(key, command, mode);
        p._kind = p._result ? kin::data_node_proposal::kind::committed
                            : kin::data_node_proposal::kind::failed;
        return p;
    };
    deps._check = [](const std::string&, const std::optional<kin::route_ref>&) {
        return kin::route_verdict{};
    };
    const std::string address = n.address();
    deps._routes = [address](const kythira::shard_range<std::string>&) {
        kin::data_route_cache::routes_reply reply;
        kin::data_route r;
        r._group_id = 1;
        r._voters = {"self"};
        r._leader_hint = "self";
        reply.routes.push_back(r);
        reply.addresses.emplace_back("self", address);
        return reply;
    };
    n._gateway->set_data_api(std::move(deps));

    const auto c = plain_client();
    kin::remote_data_access remote({address},
                                   kin::make_http_data_transport(c, std::string(k_secret)));
    const kin::stream_command cmd = kin::create_stream_command{
        ._account = std::string(k_account), ._name = "s", ._shard_count = 1, ._created_ms = 1};
    const auto r =
        remote.propose(kin::command_key(cmd), kin::encode_command(cmd), kin::admission::none);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->_status == kin::apply_status::ok));
    const auto found = remote.find_stream(k_account, "s");
    BOOST_TEST_REQUIRE(found.has_value());
    BOOST_TEST_REQUIRE(found->has_value());
    BOOST_TEST((*found)->_name == "s");
    BOOST_TEST(n._gateway->stats()._data_api_served.load() >= 2U);

    // Unsigned, or signed with another secret: 403, and the remote access
    // reports the group unreachable rather than an empty answer.
    const auto bare = c.request(address, http::verb::post, kin::data_api::k_routes_path, {},
                                std::string("\x01\x00\x00", 3));
    BOOST_TEST_REQUIRE(bare.has_value());
    BOOST_TEST(bare->_status == 403U);
    kin::remote_data_access stranger({address},
                                     kin::make_http_data_transport(c, std::string(32, 'x')));
    BOOST_TEST(!stranger.find_stream(k_account, "s").has_value());
}

BOOST_AUTO_TEST_CASE(health_and_the_refusal_carry_the_roles_header) {
    node n;
    const https::request_context ctx{};
    https::request health{http::verb::get, kin::k_health_path, 11};
    const auto h = n._gateway->handle(health, ctx);
    BOOST_TEST(h[kin::k_roles_header] == "gateway,front_end,data,segments");

    n._gateway->set_roles(kythira::layers::role_set::parse("data,segments"));
    BOOST_TEST(n._gateway->handle(health, ctx)[kin::k_roles_header] == "data,segments");
    https::request api{http::verb::post, "/", 11};
    api.set("X-Amz-Target", "Kinesis_20131202.ListStreams");
    api.body() = "{}";
    api.prepare_payload();
    const auto refused = n._gateway->handle(api, ctx);
    BOOST_TEST(refused.result_int() == 404U);
    BOOST_TEST(refused[kin::k_roles_header] == "data,segments");
    // SubscribeToShard's streaming route steps aside, so handle() refuses it.
    https::request sub{http::verb::post, "/", 11};
    sub.set("X-Amz-Target", "Kinesis_20131202.SubscribeToShard");
    BOOST_TEST(!n._gateway->stream(sub, ctx).has_value());
}

BOOST_AUTO_TEST_CASE(an_unavailable_leader_answers_503_and_the_forwarder_gives_up) {
    node n;
    n._cluster->set_unavailable(true);
    const auto c = plain_client();
    const std::string address = n.address();
    auto forward = kin::make_http_forwarder<std::string>(
        c, std::string(k_secret),
        [&address](const std::string&) { return std::optional<std::string>(address); });
    BOOST_TEST(!forward("leader", "k", create("s"), kin::admission::none).has_value());

    // Raw: the status is 503.
    auto body = kin::forward::encode_body({._key = "k", ._command = create("s")});
    const auto sig = kin::forward::sign(k_secret, body, std::chrono::system_clock::now());
    const auto r = c.request(address, http::verb::post, kin::forward::k_path,
                             {{std::string(kin::forward::k_header), sig}}, body);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->_status == 503U);
}

BOOST_AUTO_TEST_CASE(a_malformed_or_unsigned_internal_request_is_refused) {
    node n;
    const auto c = plain_client();
    const auto a = n.address();
    const auto unsigned_post =
        c.request(a, http::verb::post, kin::forward::k_path, {}, std::string("\0\0\0\0", 4));
    BOOST_TEST_REQUIRE(unsigned_post.has_value());
    BOOST_TEST(unsigned_post->_status == 403U);

    // Key length 9, only 5 bytes behind it.
    const std::string junk("\0\0\0\x09short", 9);
    const auto sig = kin::forward::sign(k_secret, junk, std::chrono::system_clock::now());
    const auto bad =
        c.request(a, http::verb::post, kin::forward::k_path, {{"x-kythira-forward", sig}}, junk);
    BOOST_TEST_REQUIRE(bad.has_value());
    BOOST_TEST(bad->_status == 400U);

    const auto get = c.request(a, http::verb::get, kin::forward::k_path, {});
    BOOST_TEST_REQUIRE(get.has_value());
    BOOST_TEST(get->_status == 405U);

    // A segment request signed as a forwarded write is refused: the
    // signature covers the path.
    const auto query = kin::segment_query("x", 1, 10);
    const auto wrong_domain = kin::forward::sign(k_secret, query, std::chrono::system_clock::now());
    const auto seg = c.request(a, http::verb::get, std::string(kin::k_segment_path) + "?" + query,
                               {{"x-kythira-forward", wrong_domain}});
    BOOST_TEST_REQUIRE(seg.has_value());
    BOOST_TEST(seg->_status == 403U);
}

BOOST_AUTO_TEST_CASE(without_a_secret_the_internal_endpoints_do_not_exist) {
    node n{""};
    const auto c = plain_client();
    const auto r = c.request(n.address(), http::verb::post, kin::forward::k_path, {}, "x");
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->_status == 404U);
    const auto s =
        c.request(n.address(), http::verb::get,
                  std::string(kin::k_segment_path) + "?" + kin::segment_query("x", 1, 1), {});
    BOOST_TEST_REQUIRE(s.has_value());
    BOOST_TEST(s->_status == 404U);
}

// kinesis-independent-layers task 10: a data node without `segments`
// writes its record segments through the volume API of the node holding
// its volume. Signed with the forwarding secret, and only where a volume
// service is set.
BOOST_AUTO_TEST_CASE(a_data_node_writes_its_segments_through_the_volume_api) {
    node n;
    temp_dir vd;
    kythira::segment_volume_service volumes(
        kythira::segment_volume_service_options{.data_dir = vd._path, .store = {}});
    volumes.assign("kinesis-2", 1);
    n._gateway->set_volume_service(&volumes);
    const auto c = plain_client();

    kythira::remote_segment_store store(
        kin::make_volume_transport(c, std::string(k_secret), n.address()), "kinesis-2", 1);
    const std::vector<std::byte> data(100, std::byte{7});
    (void)store.append("shard-1", kythira::segment_record_view{1, 1000, data});
    store.barrier();
    const auto r = store.read("shard-1", 0);
    BOOST_REQUIRE_EQUAL(r._records.size(), 1U);
    BOOST_TEST((r._records.front()._data == data));
    BOOST_TEST(store.space().second > 0U);
    // The bytes are in the volume's own directory on the segment node.
    BOOST_TEST(std::filesystem::exists(volumes.volume_dir("kinesis-2") / "streams"));

    // Unsigned, signed over the bare body, or the wrong secret: 403.
    const std::string body("\x83\x0f\x69kinesis-2\x01", 13);
    const auto unsigned_post =
        c.request(n.address(), http::verb::post, kin::k_volume_path, {}, body);
    BOOST_TEST_REQUIRE(unsigned_post.has_value());
    BOOST_TEST(unsigned_post->_status == 403U);
    const auto bare = kin::forward::sign(k_secret, body, std::chrono::system_clock::now());
    const auto replayed = c.request(n.address(), http::verb::post, kin::k_volume_path,
                                    {{std::string(kin::forward::k_header), bare}}, body);
    BOOST_TEST_REQUIRE(replayed.has_value());
    BOOST_TEST(replayed->_status == 403U);
    BOOST_CHECK_THROW(
        (void)std::make_unique<kythira::remote_segment_store>(
            kin::make_volume_transport(c, "another secret of 16+", n.address()), "kinesis-2", 1),
        kythira::record_segment_error);

    // A node holding no volumes does not serve the path.
    node other;
    const auto absent = c.request(other.address(), http::verb::post, kin::k_volume_path, {}, body);
    BOOST_TEST_REQUIRE(absent.has_value());
    BOOST_TEST(absent->_status == 404U);
}

BOOST_AUTO_TEST_CASE(a_peer_fetches_a_segment_and_the_store_verifies_it) {
    node source;
    const auto c = plain_client();
    BOOST_TEST(call(c, source, "CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}})._status ==
               200U);
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(call(c, source, "PutRecord",
                        {{"StreamName", "s"}, {"PartitionKey", "k"}, {"Data", "aGVsbG8="}})
                       ._status == 200U);
    }
    const auto streams = source._store->streams();
    BOOST_TEST_REQUIRE(streams.size() == 1U);
    const auto& key = streams.front();
    const auto local = source._store->local_segments(key);
    BOOST_TEST_REQUIRE(!local.empty());
    auto d = source._store->describe(key, local.front()._first_seq);
    BOOST_TEST_REQUIRE(d.has_value());

    temp_dir dest_dir;
    kythira::record_segment_store_options o;
    o._data_dir = dest_dir._path;
    kythira::record_segment_store dest(o);
    const auto transport = kin::make_segment_transport(c, std::string(k_secret));
    const std::vector<std::string> peers{"127.0.0.1:1", source.address()};
    BOOST_TEST(dest.fetch_segment(*d, peers, transport));
    BOOST_TEST(dest.has_segment(*d));
    BOOST_TEST(source._gateway->stats()._segments_served == 1U);
    const auto back = dest.read(key, 1);
    BOOST_TEST(back._records.size() == 5U);

    // A peer without the segment, or with another secret, yields nothing.
    BOOST_TEST(!transport(source.address(), "k/none", 1, 10).has_value());
    const auto wrong = kin::make_segment_transport(c, "other");
    BOOST_TEST(!wrong(source.address(), key, d->_first_seq, d->_bytes).has_value());
}

BOOST_AUTO_TEST_CASE(the_peer_client_verifies_the_peers_certificate) {
    const pki p;
    node n{std::string(k_secret), &p};
    const auto port = std::to_string(n._server->port());
    const kin::peer_client good(kin::peer_client_config{._tls = true, ._ca_path = p._ca});
    for (const auto* host : {"localhost:", "127.0.0.1:"}) {
        const auto r = good.request(host + port, http::verb::get, kin::k_health_path, {});
        BOOST_TEST_REQUIRE(r.has_value());
        BOOST_TEST(r->_status == 200U);
    }
    // Another CA, or a name the certificate lacks, fails the handshake.
    const kin::peer_client stranger(kin::peer_client_config{._tls = true, ._ca_path = p._other_ca});
    BOOST_TEST(!stranger.request("localhost:" + port, http::verb::get, kin::k_health_path, {})
                    .has_value());
    BOOST_TEST(
        !good.request("127.0.0.2:" + port, http::verb::get, kin::k_health_path, {}).has_value());
    // Plain HTTP to a TLS listener gets no answer it can parse.
    BOOST_TEST(!plain_client()
                    .request("127.0.0.1:" + port, http::verb::get, kin::k_health_path, {})
                    .has_value());
}

BOOST_AUTO_TEST_CASE(host_and_port_are_split_strictly) {
    BOOST_TEST((kin::split_host_port("a:1") == std::pair<std::string, std::string>{"a", "1"}));
    BOOST_TEST(
        (kin::split_host_port("[::1]:443") == std::pair<std::string, std::string>{"::1", "443"}));
    for (const auto* bad : {"", "a", ":1", "a:", "a:0", "a:65536", "a:1x", "::1:2", "[::1]443",
                            "[::1]:", "a:123456"}) {
        BOOST_TEST(!kin::split_host_port(bad).has_value(), bad);
    }
}

BOOST_AUTO_TEST_CASE(query_parameters_are_decoded) {
    namespace gd = kin::gateway_detail;
    const auto q = kin::segment_query(std::string("k/1\0x y", 7), 5, 9);
    BOOST_TEST(q == "stream=k%2F1%00x%20y&first=5&length=9");
    BOOST_TEST((gd::query_param(q, "stream") == std::string("k/1\0x y", 7)));
    BOOST_TEST((gd::query_param(q, "first") == std::string("5")));
    BOOST_TEST(!gd::query_param(q, "missing").has_value());
    BOOST_TEST(!gd::query_param("stream=%G1", "stream").has_value());
    BOOST_TEST(!gd::query_param("stream=%1", "stream").has_value());
    BOOST_TEST(!gd::parse_u64("").has_value());
    BOOST_TEST(!gd::parse_u64("12a").has_value());
    BOOST_TEST(!gd::parse_u64("12345678901234567890").has_value());
}

BOOST_AUTO_TEST_CASE(the_static_key_file_parses_and_refuses_without_echoing_secrets) {
    const auto keys = kin::parse_static_keys(
        "# id secret account name role\n"
        "\n"
        "AKIA1 s1 111122223333 ci read-write\r\n"
        "  AKIA2\ts2   444455556666 ops admin  \n"
        "AKIA3 s3 111122223333 viewer read-only");
    BOOST_TEST_REQUIRE(keys.size() == 3U);
    BOOST_TEST(keys[0].access_key_id == "AKIA1");
    BOOST_TEST(keys[0].secret == "s1");
    BOOST_TEST((keys[0].role == az::static_role::read_write));
    BOOST_TEST(keys[1].account == "444455556666");
    BOOST_TEST((keys[1].role == az::static_role::admin));
    BOOST_TEST((keys[2].role == az::static_role::read_only));

    const auto refused = [](std::string_view text) -> std::string {
        try {
            (void)kin::parse_static_keys(text);
        } catch (const std::invalid_argument& e) {
            return e.what();
        }
        return {};
    };
    const auto too_few = refused("AKIA1 topsecret 111122223333 ci");
    BOOST_TEST(too_few.find("line 1") != std::string::npos);
    BOOST_TEST(too_few.find("topsecret") == std::string::npos);
    BOOST_TEST(refused("# c\nAKIA1 s 12345 ci admin").find("line 2: account") != std::string::npos);
    BOOST_TEST(refused("AKIA1 s 111122223333 ci root").find("role") != std::string::npos);
    BOOST_TEST(refused("# only comments\n\n").find("no keys") != std::string::npos);
}
