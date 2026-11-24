// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// A front end without the data role (`.kiro/specs/kinesis-independent-
// layers/` task 7, Requirements 2.3, 3.4, 11.7 and 15.1): the front-end role
// split off a co-located node and folded back, in both directions and
// stopping half way, with one client's iterators, writes and leases carried
// across every move; the mixed layout's per-call choice of local or remote;
// and a front end whose data nodes are all gone failing retryably.
//
// The gateway apart from the front end (task 8, Requirements 4.1-4.6 and
// 15.7): the same client moved onto gateways that hand its calls to a
// co-located node's front end, to a front end without data, and to a mixed
// one, and back off them again, in both directions.
//
// Each front end is a separate service object over the real internal
// transport (kinesis_layouts.hpp), all over one data layer, as a cluster
// migrating between layouts runs them side by side; each gateway reaches
// its front end over the real internal transport too.

#define BOOST_TEST_MODULE kinesis_layouts_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include "kinesis_gateway_layouts.hpp"

#include <raft/record_segment_store.hpp>

#include <test_ports.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kin = kythira::kinesis;
namespace kt = kythira::kinesis::test;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

constexpr std::string_view k_account = "111122223333";

struct temp_dir {
    std::filesystem::path _path;
    temp_dir() {
        static int counter = 0;
        _path = std::filesystem::temp_directory_path() /
                ("kinesis_layouts_test." + std::to_string(::getpid()) + "." +
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

// Small segments, so the records roll several and reads cross them.
auto make_store(const temp_dir& dir) -> std::unique_ptr<kythira::record_segment_store> {
    return std::make_unique<kythira::record_segment_store>(kythira::record_segment_store_options{
        ._data_dir = dir._path,
        ._max_segment_bytes = 400,
        ._max_segment_age_ms = 0,
        ._max_record_bytes = 4096,
        ._index_interval_bytes = 64,
        ._barriers_enabled = false,
    });
}

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

/// What every front end of one cluster shares: the iterator key (derived
/// from the forward secret on real nodes) and the limits.
auto service_config() -> kin::kinesis_service_config {
    kin::kinesis_service_config c;
    c._iterator_keys._keys.push_back({._id = 3, ._secret = "the cluster's iterator key, shared"});
    c._throughput._read_calls_per_s = 1e9;
    c._throughput._iterator_calls_per_s = 1e9;
    c._throughput._read_bytes_per_s = 1e12;
    c._control_plane._rates.clear();
    return c;
}

/// The data layer every front end reaches: one cluster with a store.
struct data_layer {
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store = make_store(dir);
    std::int64_t clock = 1'762'776'000'000;
    kin::local_stream_cluster cluster{store.get(), [this] { return clock; }};
};

/// Where a client sends its calls: a front end's own listener, or a
/// gateway in front of one.
struct endpoint {
    endpoint() = default;
    endpoint(const endpoint&) = delete;
    auto operator=(const endpoint&) -> endpoint& = delete;
    endpoint(endpoint&&) = delete;
    auto operator=(endpoint&&) -> endpoint& = delete;
    virtual ~endpoint() = default;

    virtual auto handle(const kin::front_end_request& r) -> aj::http_response = 0;
    virtual auto lease_handle(const kin::front_end_request& r) -> aj::http_response = 0;
    [[nodiscard]] virtual auto name() const -> std::string = 0;

    auto call(std::string_view op, const json::value& body) -> aj::http_response {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
        return handle(r);
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, name() + " " + std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto lease(std::string method, std::string path, std::string body = {},
               std::vector<std::pair<std::string, std::string>> headers = {}) -> aj::http_response {
        kin::front_end_request r;
        r._method = std::move(method);
        r._path = std::move(path);
        r._body = std::move(body);
        r._headers = std::move(headers);
        return lease_handle(r);
    }
};

/// One front end in `kind`'s layout: its own service, Lease API and front
/// end over the shared data layer.
struct front_end_node final : endpoint {
    kt::layered_access layer;
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<kin::data_access> service;
    kin::lease_api<kin::data_access, allow_all> leases;

    front_end_node(data_layer& d, kt::layout_kind kind)
        : layer(d.cluster, kind),
          service(layer.get(), service_config()),
          leases(layer.get(), auth, kin::front_end_config{}) {
        service.register_with(fe);
    }

    auto handle(const kin::front_end_request& r) -> aj::http_response override {
        return fe.handle(r);
    }
    auto lease_handle(const kin::front_end_request& r) -> aj::http_response override {
        return leases.handle(r);
    }
    [[nodiscard]] auto name() const -> std::string override {
        return std::string(kt::layout_name(layer.kind()));
    }
};

/// A gateway without a front end in front of `target`'s front end, which
/// serves it over the front-end API as a node with the `front_end` role
/// does (task 8).
struct gateway_node final : endpoint {
    front_end_node& target;
    kt::loopback_front_end<kin::front_end<allow_all>> served;
    allow_all auth;
    kt::gateway_apart<allow_all> gateway;

    explicit gateway_node(front_end_node& f)
        : target(f),
          served(f.fe, [&f](const kin::authenticated_call& c) { return f.leases.execute(c); }),
          gateway(auth, {served.address()}) {}

    auto handle(const kin::front_end_request& r) -> aj::http_response override {
        return gateway.handle(r);
    }
    auto lease_handle(const kin::front_end_request& r) -> aj::http_response override {
        return gateway.handle(r);
    }
    [[nodiscard]] auto name() const -> std::string override {
        return "gateway -> " + target.name();
    }
};

auto str(const json::value& v) -> std::string {
    return std::string(v.as_string());
}

/// A client of one stream: what it has written (acknowledged sequence
/// numbers per shard) and where each shard's reader stands. It keeps its
/// iterators across a move to another front end, as a KCL worker behind a
/// load balancer does.
struct client {
    std::map<std::string, std::vector<std::string>> written;
    std::map<std::string, std::vector<std::string>> read;
    std::map<std::string, std::string> iterators;
    int next = 0;

    void write(endpoint& f, int records) {
        json::array recs;
        for (int i = 0; i < records; ++i) {
            const auto n = next++;
            recs.push_back({{"PartitionKey", "pk-" + std::to_string(n)},
                            {"Data", "cmVjb3JkLQ=="}});  // "record-"
        }
        const auto put = f.ok("PutRecords", {{"StreamName", "orders"}, {"Records", recs}});
        BOOST_TEST(put.at("FailedRecordCount").as_int64() == 0);
        for (const auto& r : put.at("Records").as_array()) {
            written[str(r.at("ShardId"))].push_back(str(r.at("SequenceNumber")));
        }
    }

    /// Reads every shard on `f` until it has caught up, from where the
    /// last front end left off (or the trim horizon the first time).
    void catch_up(endpoint& f) {
        for (const auto& shard : shard_ids(f)) {
            auto it = iterators.find(shard);
            if (it == iterators.end()) {
                it = iterators
                         .emplace(shard, str(f.ok("GetShardIterator",
                                                  {{"StreamName", "orders"},
                                                   {"ShardId", shard},
                                                   {"ShardIteratorType", "TRIM_HORIZON"}})
                                                 .at("ShardIterator")))
                         .first;
            }
            for (int page = 0; page < 50; ++page) {
                const auto r = f.ok("GetRecords", {{"ShardIterator", it->second}, {"Limit", 3}});
                for (const auto& rec : r.at("Records").as_array()) {
                    read[shard].push_back(str(rec.at("SequenceNumber")));
                }
                it->second = str(r.at("NextShardIterator"));
                if (r.at("Records").as_array().empty()) {
                    break;
                }
            }
        }
    }

    static auto shard_ids(endpoint& f) -> std::vector<std::string> {
        std::vector<std::string> out;
        const auto listed = f.ok("ListShards", {{"StreamName", "orders"}});
        for (const auto& s : listed.at("Shards").as_array()) {
            out.push_back(str(s.at("ShardId")));
        }
        return out;
    }

    /// Every acknowledged record read exactly once, in each shard's order.
    void check() const {
        BOOST_TEST(read.size() == written.size());
        for (const auto& [shard, sequences] : written) {
            const auto it = read.find(shard);
            BOOST_REQUIRE_MESSAGE(it != read.end(), "nothing read from " + shard);
            BOOST_TEST(it->second == sequences, shard << " read back as written");
        }
    }
};

const std::vector<std::pair<std::string, std::string>> k_create{{"if-none-match", "*"}};

auto lease_owner(endpoint& f, const std::string& path) -> std::string {
    const auto r = f.lease("GET", path);
    BOOST_REQUIRE_MESSAGE(r.status == 200U, path + ": " + r.body);
    return std::string(
        json::parse(r.body).as_object().at("lease").as_object().at("leaseOwner").as_string());
}

/// One stop of a move: a front end's layout, reached directly or through a
/// gateway apart from it.
struct stop {
    kt::layout_kind _kind;
    bool _via_gateway = false;
};

/// One client moved through `stops`, writing, reading and taking a lease at
/// each: every record it was acknowledged is read once and in order, every
/// lease taken at one stop holds at the next, and a lease cannot be taken
/// twice from two front ends.
void move_through(const std::vector<stop>& stops) {
    data_layer d;
    std::vector<std::unique_ptr<front_end_node>> nodes;
    std::vector<std::unique_ptr<gateway_node>> gateways;
    std::vector<endpoint*> endpoints;
    for (const auto& s : stops) {
        nodes.push_back(std::make_unique<front_end_node>(d, s._kind));
        if (s._via_gateway) {
            gateways.push_back(std::make_unique<gateway_node>(*nodes.back()));
            endpoints.push_back(gateways.back().get());
        } else {
            endpoints.push_back(nodes.back().get());
        }
    }
    endpoints.front()->ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 3}});

    client c;
    for (std::size_t i = 0; i < endpoints.size(); ++i) {
        auto& f = *endpoints[i];
        BOOST_TEST_CONTEXT("stop " << i << " (" << f.name() << ")") {
            c.catch_up(f);  // with the previous stop's iterators
            c.write(f, 12);
            c.catch_up(f);
            const auto lease = "/v1/leases/app/shard-" + std::to_string(i);
            BOOST_TEST(
                f.lease("PUT", lease, R"({"leaseOwner":"w)" + std::to_string(i) + R"("})", k_create)
                    .status == 200U);
            // Every earlier stop's leases hold here, and none can be taken
            // again from this front end.
            for (std::size_t j = 0; j <= i; ++j) {
                const auto path = "/v1/leases/app/shard-" + std::to_string(j);
                BOOST_TEST(lease_owner(f, path) == "w" + std::to_string(j));
                BOOST_TEST(f.lease("PUT", path, R"({"leaseOwner":"thief"})", k_create).status ==
                           412U);
            }
        }
    }
    c.check();
    // Every front end, whatever its layout, now answers the same.
    for (auto* n : endpoints) {
        client fresh;
        fresh.written = c.written;
        fresh.catch_up(*n);
        fresh.check();
        BOOST_TEST(n->ok("DescribeStreamSummary", {{"StreamName", "orders"}})
                       .at("StreamDescriptionSummary")
                       .at("OpenShardCount")
                       .as_int64() == 3);
    }
    // A gateway's calls ran on its front end, never on its own.
    for (const auto& g : gateways) {
        BOOST_TEST(g->served.executed() > 0U, g->name());
    }
}

void move_through(const std::vector<kt::layout_kind>& kinds) {
    std::vector<stop> stops;
    for (const auto k : kinds) {
        stops.push_back({k, false});
    }
    move_through(stops);
}

}  // namespace

using kt::layout_kind;

// Splitting the front-end role off: clients move from a co-located node to
// a front end without data, and back again (Requirement 15.7, the front-end
// role both ways).
BOOST_AUTO_TEST_CASE(the_front_end_role_splits_off_and_folds_back) {
    move_through({layout_kind::co_located, layout_kind::front_end_apart, layout_kind::co_located});
}

BOOST_AUTO_TEST_CASE(the_front_end_role_folds_in_and_splits_off_again) {
    move_through(
        {layout_kind::front_end_apart, layout_kind::co_located, layout_kind::front_end_apart});
}

// Stopping half way: a mixed cluster (a front end on a data node that holds
// only some groups) is a layout of its own, entered and left from either
// side.
BOOST_AUTO_TEST_CASE(a_move_stops_at_a_mixed_layout_and_reverses) {
    move_through({layout_kind::co_located, layout_kind::mixed, layout_kind::front_end_apart,
                  layout_kind::mixed, layout_kind::co_located});
}

// Splitting the gateway role off (task 8, Requirement 15.7, the gateway
// role both ways): gateways are started in front of a co-located node's
// front end and the client moves onto them, then onto a gateway whose
// front end holds no data, and back off both.
BOOST_AUTO_TEST_CASE(the_gateway_role_splits_off_and_folds_back) {
    move_through({{layout_kind::co_located, false},
                  {layout_kind::co_located, true},
                  {layout_kind::front_end_apart, true},
                  {layout_kind::co_located, true},
                  {layout_kind::co_located, false}});
}

BOOST_AUTO_TEST_CASE(the_gateway_role_folds_in_and_splits_off_again) {
    move_through({{layout_kind::front_end_apart, true},
                  {layout_kind::front_end_apart, false},
                  {layout_kind::co_located, false},
                  {layout_kind::mixed, true},
                  {layout_kind::front_end_apart, true}});
}

// Requirement 3.2: the mixed front end answers what its replica holds
// locally and sends the rest to the data node, per call.
BOOST_AUTO_TEST_CASE(the_mixed_front_end_picks_local_or_remote_per_call) {
    data_layer d;
    front_end_node f(d, layout_kind::mixed);
    f.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 2}});

    // The catalog group is held here: describing and listing cross no wire.
    const auto before = f.layer.remote_calls();
    f.ok("DescribeStreamSummary", {{"StreamName", "orders"}});
    f.ok("ListStreams", json::object{});
    BOOST_TEST(f.layer.remote_calls() == before);

    // The stream's shards are on the data node.
    f.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "a"}, {"Data", "YQ=="}});
    BOOST_TEST(f.layer.remote_calls() > before);

    // Co-located crosses no wire at all.
    front_end_node co(d, layout_kind::co_located);
    co.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "b"}, {"Data", "Yg=="}});
    BOOST_TEST(co.layer.remote_calls() == 0U);
}

// A front end whose data nodes all stopped answers every call as a
// retryable server error, never as a missing stream or an empty list.
BOOST_AUTO_TEST_CASE(a_front_end_without_a_data_node_fails_retryably) {
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    // Nothing listens on a free port.
    const auto remote =
        kt::remote_access_to("127.0.0.1:" + std::to_string(kythira::testing::free_port()));
    kin::kinesis_service<kin::data_access> service(*remote._access, service_config());
    service.register_with(fe);
    const auto call = [&](std::string_view op, const json::value& body) {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
        return fe.handle(r);
    };
    for (const auto& [op, body] : std::vector<std::pair<std::string, json::value>>{
             {"ListStreams", json::object{}},
             {"DescribeStreamSummary", {{"StreamName", "orders"}}},
             {"CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}}},
             {"PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "a"}, {"Data", "YQ=="}}},
         }) {
        const auto r = call(op, body);
        BOOST_TEST(r.status >= 500U, op << " answered " << r.status << ": " << r.body);
        BOOST_TEST(r.body.find("ResourceNotFoundException") == std::string::npos, op);
    }
    BOOST_TEST(remote._unreachable() > 0U);
}
