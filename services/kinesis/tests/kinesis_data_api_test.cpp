// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The data-layer API (`.kiro/specs/kinesis-independent-layers/` task 6,
// Requirements 3.2, 5.1-5.6): a front-end-only node (the service and the
// Lease API over `remote_data_access`) serves streams, records, leases and
// resharding through data nodes in two layouts, one data node holding
// every group and three each holding one, the second with a stale leader
// hint, a replica-less voter and an epoch bump. Then the wire's edges:
// refusals, malformed bodies, records as stored (sealed stays sealed),
// read caps, writes that may have committed never retried, a dead node
// skipped, and the hybrid access answering locally what it holds.

#define BOOST_TEST_MODULE kinesis_data_api_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_data_api.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_lease_api.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kin = kythira::kinesis;
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
                ("kinesis_data_api_test." + std::to_string(::getpid()) + "." +
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

auto range(std::optional<std::string> start, std::optional<std::string> end)
    -> kythira::shard_range<std::string> {
    return {._start = std::move(start), ._end = std::move(end)};
}

class layout;

/// One data node: its own state machine and segment store, serving only
/// the groups the layout gives it. `owned` is what the composition root's
/// `raft_stream_cluster` would be: reads and proposals for other groups
/// find no replica, and transactions go to each write's owner, as the
/// tier-1 coordinator sends them to each group's leader.
class data_node {
public:
    data_node(std::string name, layout& l, const std::int64_t& clock);

    /// The `stream_cluster` the node's `local_data_access` is over.
    class owned {
    public:
        explicit owned(data_node& n) : _n(n) {}
        auto propose(const std::string& key, std::vector<std::byte> command,
                     kin::admission mode = kin::admission::none)
            -> std::optional<kin::apply_result>;
        auto read(const std::string& key, const kin::stream_reader& f) -> bool;
        [[nodiscard]] auto now_ms() const -> std::int64_t { return _n._cluster.now_ms(); }
        auto transact(std::vector<kin::txn_write> writes) -> kin::transact_outcome;

    private:
        data_node& _n;
    };

    [[nodiscard]] auto holds(const std::string& key) const -> bool;
    auto serve(std::string_view target, std::string_view body) -> kin::data_api_answer;

    std::string _name;
    layout& _layout;
    temp_dir _dir;
    std::unique_ptr<kythira::record_segment_store> _store;
    kin::local_stream_cluster _cluster;
    owned _owned{*this};
    kin::local_data_access<owned> _local{_owned};
    kin::data_api_deps _deps;
    std::atomic<bool> _down{false};
    std::atomic<std::uint64_t> _served{0};
    std::atomic<std::uint64_t> _proposals_here{0};
};

/// Groups, who holds them, and the routes a data node answers.
class layout {
public:
    struct group {
        kin::data_route _route;
        /// The node that really holds and leads it.
        std::string _owner;
    };

    explicit layout(std::int64_t& clock) : _clock(clock) {}

    auto add_node(const std::string& name) -> data_node& {
        auto n = std::make_unique<data_node>(name, *this, _clock);
        auto& ref = *n;
        _nodes.emplace(name, std::move(n));
        return ref;
    }

    void add_group(std::uint64_t id, kythira::shard_range<std::string> r, std::string owner,
                   std::vector<std::string> voters, std::optional<std::string> leader_hint) {
        group g;
        g._route._group_id = id;
        g._route._range = std::move(r);
        g._route._epoch = {._version = 1, ._conf_version = 1};
        g._route._voters = std::move(voters);
        g._route._leader_hint = std::move(leader_hint);
        g._owner = std::move(owner);
        const std::scoped_lock lock(_mutex);
        _groups.push_back(std::move(g));
    }

    /// A range change: the group's epoch moves on (as a split would) and
    /// its leader hint becomes right.
    void bump(std::uint64_t id) {
        const std::scoped_lock lock(_mutex);
        for (auto& g : _groups) {
            if (g._route._group_id == id) {
                ++g._route._epoch._version;
                g._route._leader_hint = g._owner;
            }
        }
    }

    [[nodiscard]] auto group_of(const std::string& key) const -> std::optional<group> {
        const std::scoped_lock lock(_mutex);
        for (const auto& g : _groups) {
            if (g._route._range.contains(key)) {
                return g;
            }
        }
        return std::nullopt;
    }

    /// Every route, whatever the range asked: a cache takes what it is
    /// given.
    [[nodiscard]] auto routes(const kythira::shard_range<std::string>& /*r*/) const
        -> kin::data_route_cache::routes_reply {
        kin::data_route_cache::routes_reply reply;
        const std::scoped_lock lock(_mutex);
        for (const auto& g : _groups) {
            reply.routes.push_back(g._route);
        }
        for (const auto& [name, node] : _nodes) {
            reply.addresses.emplace_back(name, name + ":4567");
        }
        return reply;
    }

    auto node(const std::string& name) -> data_node& { return *_nodes.at(name); }

    /// The in-process transport: "name:port" reaches that node's API.
    auto transport() -> kin::data_transport {
        return [this](const std::string& address, std::string_view target,
                      std::string body) -> std::optional<std::pair<unsigned, std::string>> {
            const auto name = address.substr(0, address.find(':'));
            const auto it = _nodes.find(name);
            if (it == _nodes.end() || it->second->_down) {
                return std::nullopt;
            }
            const auto a = it->second->serve(target, body);
            return std::pair{a._status, a._body};
        };
    }

    std::vector<std::string> seeds() const {
        std::vector<std::string> out;
        for (const auto& [name, node] : _nodes) {
            out.push_back(name + ":4567");
        }
        return out;
    }

private:
    std::int64_t& _clock;
    mutable std::mutex _mutex;
    std::vector<group> _groups;
    std::map<std::string, std::unique_ptr<data_node>> _nodes;
};

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

data_node::data_node(std::string name, layout& l, const std::int64_t& clock)
    : _name(std::move(name)),
      _layout(l),
      _store(make_store(_dir)),
      _cluster(_store.get(), [&clock] { return clock; }) {
    _deps._local = &_local;
    _deps._propose_here = [this](const std::string& key, const std::vector<std::byte>& command,
                                 kin::admission mode) {
        kin::data_node_proposal p;
        const auto g = _layout.group_of(key);
        if (!g) {
            p._kind = kin::data_node_proposal::kind::no_replica;
            return p;
        }
        if (g->_owner != _name) {
            // A voter that does not lead: names the leader, proposes nothing.
            p._kind = kin::data_node_proposal::kind::not_leader;
            p._leader = g->_owner;
            return p;
        }
        ++_proposals_here;
        p._result = _cluster.propose(key, command, mode);
        p._kind = p._result ? kin::data_node_proposal::kind::committed
                            : kin::data_node_proposal::kind::failed;
        return p;
    };
    _deps._check = [this](const std::string& key, const std::optional<kin::route_ref>& ref) {
        kin::route_verdict v;
        const auto g = _layout.group_of(key);
        if (!g) {
            v._kind = kythira::route_check_kind::unknown_group;
            return v;
        }
        if (ref && (ref->_group != g->_route._group_id ||
                    ref->_epoch._version < g->_route._epoch._version)) {
            v._kind = kythira::route_check_kind::stale;
            v._route = g->_route;
        }
        return v;
    };
    _deps._routes = [this](const kythira::shard_range<std::string>& r) {
        return _layout.routes(r);
    };
}

auto data_node::holds(const std::string& key) const -> bool {
    const auto g = _layout.group_of(key);
    return g && g->_owner == _name;
}

auto data_node::serve(std::string_view target, std::string_view body) -> kin::data_api_answer {
    ++_served;
    auto a = kin::serve_data_api(_deps, true, "POST", target, body);
    BOOST_REQUIRE(a.has_value());
    return std::move(*a);
}

auto data_node::owned::propose(const std::string& key, std::vector<std::byte> command,
                               kin::admission mode) -> std::optional<kin::apply_result> {
    if (!_n.holds(key)) {
        return std::nullopt;
    }
    return _n._cluster.propose(key, std::move(command), mode);
}

auto data_node::owned::read(const std::string& key, const kin::stream_reader& f) -> bool {
    return _n.holds(key) && _n._cluster.read(key, f);
}

auto data_node::owned::transact(std::vector<kin::txn_write> writes) -> kin::transact_outcome {
    // Each write applies at its owner (the test's stand-in for the tier-1
    // coordinator's prepare/commit at each group's leader).
    for (auto& w : writes) {
        const auto g = _n._layout.group_of(w._key);
        if (!g) {
            return kin::transact_outcome::aborted;
        }
        (void)_n._layout.node(g->_owner)._cluster.transact({std::move(w)});
    }
    return kin::transact_outcome::committed;
}

static_assert(kin::stream_cluster<data_node::owned>);
static_assert(kin::transacts<data_node::owned>);

auto service_config(kin::key_provider kms = {}) -> kin::kinesis_service_config {
    kin::kinesis_service_config c;
    c._throughput._read_calls_per_s = 1e9;
    c._throughput._iterator_calls_per_s = 1e9;
    c._throughput._read_bytes_per_s = 1e12;
    c._control_plane._rates.clear();
    c._iterator_keys._keys.push_back({._id = 0, ._secret = std::string(32, 'k')});
    c._kms = std::move(kms);
    return c;
}

/// A front end with no replica: the service and the Lease API over the
/// remote access.
struct front_end_only {
    kin::remote_data_access data;
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<kin::remote_data_access> service;
    kin::lease_api<kin::remote_data_access, allow_all> leases;

    explicit front_end_only(layout& l, kin::key_provider kms = {})
        : data(l.seeds(), l.transport()),
          service(data, service_config(std::move(kms))),
          leases(data, auth, kin::front_end_config{}) {
        service.register_with(fe);
    }

    auto call(std::string_view op, const json::value& body) -> aj::http_response {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
        return fe.handle(r);
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto lease(std::string method, std::string path, std::string body = {},
               std::vector<std::pair<std::string, std::string>> headers = {}) -> aj::http_response {
        kin::front_end_request r;
        r._method = std::move(method);
        r._path = std::move(path);
        r._body = std::move(body);
        r._headers = std::move(headers);
        return leases.handle(r);
    }
};

auto str(const json::value& v) -> std::string {
    return std::string(v.as_string());
}

/// The same workload whatever the layout: create, write every shard, read
/// every shard back in order, list, describe, leases with conditions, a
/// split, and writes and reads after it.
void run_workload(front_end_only& f) {
    f.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 4}});
    f.ok("CreateStream", {{"StreamName", "audit"}, {"ShardCount", 1}});
    const auto listed = f.ok("ListStreams", json::object{});
    BOOST_TEST(listed.at("StreamNames").as_array().size() == 2U);
    BOOST_TEST(str(f.ok("DescribeStreamSummary", {{"StreamName", "orders"}})
                       .at("StreamDescriptionSummary")
                       .at("StreamStatus")) == "ACTIVE");

    std::map<std::string, std::vector<std::string>> sent;  // shard -> data
    for (int i = 0; i < 40; ++i) {
        json::array recs;
        for (int j = 0; j < 5; ++j) {
            recs.push_back({{"PartitionKey", "pk" + std::to_string((i * 5) + j)},
                            {"Data", "cmVjb3Jk"}});  // "record"
        }
        const auto put = f.ok("PutRecords", {{"StreamName", "orders"}, {"Records", recs}});
        BOOST_TEST(put.at("FailedRecordCount").as_int64() == 0);
        for (const auto& r : put.at("Records").as_array()) {
            sent[str(r.at("ShardId"))].push_back(str(r.at("SequenceNumber")));
        }
    }
    BOOST_TEST(sent.size() == 4U);

    for (const auto& [shard, sequences] : sent) {
        auto it = str(f.ok("GetShardIterator", {{"StreamName", "orders"},
                                                {"ShardId", shard},
                                                {"ShardIteratorType", "TRIM_HORIZON"}})
                          .at("ShardIterator"));
        std::vector<std::string> got;
        for (int page = 0; page < 20 && got.size() < sequences.size(); ++page) {
            const auto r = f.ok("GetRecords", {{"ShardIterator", it}, {"Limit", 7}});
            for (const auto& rec : r.at("Records").as_array()) {
                BOOST_TEST(str(rec.at("Data")) == "cmVjb3Jk");
                got.push_back(str(rec.at("SequenceNumber")));
            }
            it = str(r.at("NextShardIterator"));
        }
        BOOST_TEST(got == sequences);
    }

    // LATEST reads only what comes after it.
    auto latest = str(f.ok("GetShardIterator", {{"StreamName", "audit"},
                                                {"ShardId", "shardId-000000000000"},
                                                {"ShardIteratorType", "LATEST"}})
                          .at("ShardIterator"));
    f.ok("PutRecord", {{"StreamName", "audit"}, {"PartitionKey", "a"}, {"Data", "YWZ0ZXI="}});
    BOOST_TEST(f.ok("GetRecords", {{"ShardIterator", latest}}).at("Records").as_array().size() ==
               1U);

    // Leases: every read and write is a proposal through the data layer.
    const std::vector<std::pair<std::string, std::string>> none{{"if-none-match", "*"}};
    const auto created = f.lease("PUT", "/v1/leases/app-1/shard-0", R"({"leaseOwner":"w1"})", none);
    BOOST_TEST(created.status == 200U);
    BOOST_TEST(f.lease("PUT", "/v1/leases/app-1/shard-0", R"({"leaseOwner":"w2"})", none).status ==
               412U);
    const auto got = f.lease("GET", "/v1/leases/app-1/shard-0");
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(got.body.find("w1") != std::string::npos);
    BOOST_TEST(f.lease("GET", "/v1/leases/app-1").body.find("shard-0") != std::string::npos);

    // A split: a transaction a data node coordinates.
    f.ok("SplitShard", {{"StreamName", "orders"},
                        {"ShardToSplit", "shardId-000000000000"},
                        {"NewStartingHashKey", "42535295865117307932921825928971026432"}});
    const auto shards = f.ok("ListShards", {{"StreamName", "orders"}}).at("Shards").as_array();
    BOOST_TEST(shards.size() == 6U);
    const auto after = f.ok(
        "PutRecords",
        {{"StreamName", "orders"},
         {"Records",
          {{{"PartitionKey", "x"}, {"Data", "eA=="}}, {{"PartitionKey", "y"}, {"Data", "eQ=="}}}}});
    BOOST_TEST(after.at("FailedRecordCount").as_int64() == 0);
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_front_end_over_one_data_node_holding_every_group) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d1"}, "d1");

    front_end_only f(l);
    run_workload(f);
    BOOST_TEST(d1._proposals_here.load() > 0U);
    BOOST_TEST(f.data.stats()._unreachable == 0U);
}

BOOST_AUTO_TEST_CASE(a_front_end_over_three_data_nodes_one_group_each) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    auto& d2 = l.add_node("d2");
    auto& d3 = l.add_node("d3");
    // The catalog; stream 1's first two shards; everything after. Group 2's
    // route first names d3, a voter that does not lead and holds nothing
    // yet: writes must follow its not-leader hint, reads skip it.
    const auto cut = kin::routing_key(1, 2);
    l.add_group(1, range(std::nullopt, std::string("k/")), "d1", {"d1"}, "d1");
    l.add_group(2, range(std::string("k/"), cut), "d2", {"d3", "d2"}, "d3");
    l.add_group(3, range(cut, std::nullopt), "d3", {"d3"}, "d3");

    front_end_only f(l);
    run_workload(f);

    // Every node served its own groups.
    BOOST_TEST(d1._proposals_here.load() > 0U);
    BOOST_TEST(d2._proposals_here.load() > 0U);
    BOOST_TEST(d3._proposals_here.load() > 0U);
    const auto s = f.data.stats();
    BOOST_TEST(s._not_leader >= 1U);
    BOOST_TEST(s._unreachable == 0U);
    // The records live where their groups are.
    BOOST_TEST(d2._cluster.read(kin::routing_key(1, 1), [](const auto& sm) {
        BOOST_TEST(sm.find_shard(kin::routing_key(1, 1)) != nullptr);
    }));
    d3._cluster.read(kin::routing_key(1, 1), [](const auto& sm) {
        BOOST_TEST(sm.find_shard(kin::routing_key(1, 1)) == nullptr);
    });

    // A range change moves group 3's epoch: the cached route is stale, the
    // node answers with the current one, and the call still succeeds.
    l.bump(3);
    f.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "pk3"}, {"Data", "eg=="}});
    const auto rec = f.ok("DescribeStream", {{"StreamName", "orders"}});
    BOOST_TEST(rec.contains("StreamDescription"));
    BOOST_TEST(f.data.stats()._stale_route >= 1U);

    // The catalog's node goes away: calls fail retryably, then recover.
    d1._down = true;
    BOOST_TEST(f.call("DescribeStreamSummary", {{"StreamName", "orders"}}).status == 500U);
    d1._down = false;
    f.ok("DescribeStreamSummary", {{"StreamName", "orders"}});
}

BOOST_AUTO_TEST_CASE(records_cross_the_wire_as_stored) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d1"}, "d1");
    front_end_only f(l, kin::key_provider(kin::local_kms_provider("correct horse battery")));

    f.ok("CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
    f.ok("StartStreamEncryption",
         {{"StreamName", "s"}, {"EncryptionType", "KMS"}, {"KeyId", "alias/aws/kinesis"}});
    f.ok("PutRecord", {{"StreamName", "s"}, {"PartitionKey", "pk"}, {"Data", "c2VjcmV0"}});

    // What the data node hands out is the sealed record.
    const auto rec = **f.data.find_stream(k_account, "s");
    const auto raw = f.data.read_records(kin::routing_key(rec._id, 0), 0, 0,
                                         {._max_records = 10, ._max_bytes = 1 << 20});
    BOOST_REQUIRE(raw.has_value());
    BOOST_REQUIRE(raw->_read._records.size() == 1U);
    BOOST_TEST(kin::is_sealed_record(raw->_read._records.front()._data));
    // The front end opens it.
    const auto it = str(f.ok("GetShardIterator", {{"StreamName", "s"},
                                                  {"ShardId", "shardId-000000000000"},
                                                  {"ShardIteratorType", "TRIM_HORIZON"}})
                            .at("ShardIterator"));
    const auto got = f.ok("GetRecords", {{"ShardIterator", it}}).at("Records").as_array();
    BOOST_REQUIRE(got.size() == 1U);
    BOOST_TEST(str(got.front().at("Data")) == "c2VjcmV0");
    BOOST_TEST(str(got.front().at("EncryptionType")) == "KMS");

    // A shard's state crosses whole.
    const auto st = f.data.shard(kin::routing_key(rec._id, 0));
    BOOST_REQUIRE(st.has_value());
    BOOST_REQUIRE(st->has_value());
    BOOST_TEST((*st)->_last_counter == 1U);
    std::optional<kin::shard_state> local;
    d1._cluster.read(kin::routing_key(rec._id, 0),
                     [&](const auto& sm) { local = *sm.find_shard(kin::routing_key(rec._id, 0)); });
    BOOST_TEST((**st == *local));
}

BOOST_AUTO_TEST_CASE(the_wire_refuses_what_it_should) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d1"}, "d1");

    // Not an API path: not ours. A refused caller: 403. Wrong method: 400.
    BOOST_TEST(!kin::serve_data_api(d1._deps, true, "POST", "/", "").has_value());
    BOOST_TEST(
        kin::serve_data_api(d1._deps, false, "POST", kin::data_api::k_catalog_path, "")->_status ==
        403U);
    BOOST_TEST(
        kin::serve_data_api(d1._deps, true, "GET", kin::data_api::k_catalog_path, "")->_status ==
        400U);
    // Malformed bodies: empty, wrong version, truncated, trailing bytes,
    // unknown query, unknown route.
    for (const std::string& body : {std::string(), std::string("\x07", 1),
                                    std::string("\x01\x00", 2), std::string("\x01\x00\x09", 3)}) {
        BOOST_TEST(kin::serve_data_api(d1._deps, true, "POST", kin::data_api::k_catalog_path, body)
                       ->_status == 400U);
    }
    BOOST_TEST(kin::serve_data_api(d1._deps, true, "POST", "/_kythira/kinesis/v2/nope",
                                   std::string("\x01", 1))
                   ->_status == 400U);
    // A routes body with trailing bytes.
    BOOST_TEST(kin::serve_data_api(d1._deps, true, "POST", kin::data_api::k_routes_path,
                                   std::string("\x01\x00\x00\x00", 4))
                   ->_status == 400U);
    // A read asking for more than any GetRecords may is capped.
    front_end_only f(l);
    f.ok("CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
    for (int i = 0; i < 3; ++i) {
        f.ok("PutRecord", {{"StreamName", "s"}, {"PartitionKey", "pk"}, {"Data", "eA=="}});
    }
    const auto rec = **f.data.find_stream(k_account, "s");
    const auto all = f.data.read_records(kin::routing_key(rec._id, 0), 0, 0,
                                         {._max_records = SIZE_MAX, ._max_bytes = UINT64_MAX});
    BOOST_REQUIRE(all.has_value());
    BOOST_TEST(all->_read._records.size() == 3U);
}

BOOST_AUTO_TEST_CASE(a_write_that_may_have_committed_is_not_retried) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d1"}, "d1");
    front_end_only f(l);
    f.ok("CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
    const auto rec = **f.data.find_stream(k_account, "s");

    // The leader answers "not committed here" (a timeout): the remote access
    // reports it once and proposes nothing more, and tells the operator
    // which node said what.
    int calls = 0;
    std::vector<std::string> failures;
    kin::remote_data_options opts;
    opts._on_failure = [&](std::string_view line) { failures.emplace_back(line); };
    kin::remote_data_access flaky(
        {"d1:4567"},
        [&](const std::string& address, std::string_view target,
            std::string body) -> std::optional<std::pair<unsigned, std::string>> {
            if (target == kin::data_api::k_propose_path) {
                ++calls;
                return std::pair{503U, std::string("not committed here")};
            }
            return l.transport()(address, target, std::move(body));
        },
        opts);
    const kin::stream_command c = kin::shard_tip_command{kin::routing_key(rec._id, 0)};
    BOOST_TEST(!flaky.propose(kin::command_key(c), kin::encode_command(c), kin::admission::none));
    BOOST_TEST(calls == 1);
    BOOST_REQUIRE(failures.size() == 1U);
    BOOST_TEST(failures[0].find("may have committed") != std::string::npos, failures[0]);
    BOOST_TEST(failures[0].find("d1@") != std::string::npos, failures[0]);
    BOOST_TEST(failures[0].find("503 not committed here") != std::string::npos, failures[0]);
}

BOOST_AUTO_TEST_CASE(a_call_no_replica_answers_says_what_each_target_said) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d1"}, "d1");
    front_end_only f(l);
    f.ok("CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
    const auto rec = **f.data.find_stream(k_account, "s");

    // The only replica answers "no replica" to every read: the call gives
    // up after its rounds, and the line names the node and its answer.
    std::vector<std::string> failures;
    kin::remote_data_options opts;
    opts._on_failure = [&](std::string_view line) { failures.emplace_back(line); };
    kin::remote_data_access lost(
        {"d1:4567"},
        [&](const std::string& address, std::string_view target,
            std::string body) -> std::optional<std::pair<unsigned, std::string>> {
            if (target == kin::data_api::k_shard_path) {
                return std::pair{404U, std::string("no such group here")};
            }
            return l.transport()(address, target, std::move(body));
        },
        opts);
    BOOST_TEST(!lost.shard(kin::routing_key(rec._id, 0)).has_value());
    BOOST_REQUIRE(failures.size() == 1U);
    BOOST_TEST(failures[0].find("found no replica") != std::string::npos, failures[0]);
    BOOST_TEST(failures[0].find(": 404 no such group here") != std::string::npos, failures[0]);
}

BOOST_AUTO_TEST_CASE(a_dead_replica_is_skipped_for_reads) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    auto& d2 = l.add_node("d2");
    // d2 is listed first but is down; d1 serves.
    l.add_group(1, range(std::nullopt, std::nullopt), "d1", {"d2", "d1"}, "d1");
    front_end_only f(l);
    f.ok("CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
    d2._down = true;
    f.ok("DescribeStreamSummary", {{"StreamName", "s"}});
    BOOST_TEST(f.data.routes().stats().connection_failures >= 1U);
    BOOST_TEST(d1._served.load() > 0U);
}

BOOST_AUTO_TEST_CASE(the_hybrid_answers_locally_what_it_holds) {
    std::int64_t clock = 1'762'776'000'000;
    layout l(clock);
    auto& d1 = l.add_node("d1");
    auto& d2 = l.add_node("d2");
    const auto cut = std::string("k/");
    l.add_group(1, range(std::nullopt, cut), "d1", {"d1"}, "d1");
    l.add_group(2, range(cut, std::nullopt), "d2", {"d2"}, "d2");

    // A front end on d1: the catalog is local, the shards are on d2.
    kin::remote_data_access remote(l.seeds(), l.transport());
    kin::hybrid_data_access<data_node::owned> hybrid(d1._local, remote);
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<kin::hybrid_data_access<data_node::owned>> service(hybrid,
                                                                            service_config());
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
    BOOST_TEST(call("CreateStream", {{"StreamName", "s"}, {"ShardCount", 2}}).status == 200U);
    BOOST_TEST(
        call("PutRecord", {{"StreamName", "s"}, {"PartitionKey", "a"}, {"Data", "eA=="}}).status ==
        200U);
    const auto before = d1._served.load();
    BOOST_TEST(call("DescribeStreamSummary", {{"StreamName", "s"}}).status == 200U);
    // The catalog read never left d1's process.
    BOOST_TEST(d1._served.load() == before);
    // The shards' writes went to d2 over the API.
    BOOST_TEST(d2._proposals_here.load() > 0U);
    BOOST_TEST(d2._served.load() > 0U);
}
