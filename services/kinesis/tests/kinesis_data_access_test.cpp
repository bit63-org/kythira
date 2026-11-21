// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The named data-layer queries (`.kiro/specs/kinesis-independent-layers/`
// task 2, Requirements 1.2, 3.1, 3.3): `local_data_access` answers each
// query from the owning group's replica as a copy, a group with no replica
// here is `unreachable` (and the handlers fail the call as retryable,
// never as a missing stream), records come back as stored, and the
// service runs the same over a `data_access` it is handed as over a
// cluster it wraps itself.

#define BOOST_TEST_MODULE kinesis_data_access_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_data_access.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
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
                ("kinesis_data_access_test." + std::to_string(::getpid()) + "." +
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

/// A `local_stream_cluster` whose replica can go away: while `_blind`, every
/// read answers "no local replica", as a node outside a group does.
class blindable_cluster {
public:
    explicit blindable_cluster(kin::local_stream_cluster& inner) : _inner(inner) {}

    auto propose(const std::string& key, std::vector<std::byte> command,
                 kin::admission mode = kin::admission::none) -> std::optional<kin::apply_result> {
        return _inner.propose(key, std::move(command), mode);
    }
    auto read(const std::string& key, const kin::stream_reader& f) -> bool {
        return !_blind.load() && _inner.read(key, f);
    }
    [[nodiscard]] auto now_ms() const -> std::int64_t { return _inner.now_ms(); }

    std::atomic<bool> _blind{false};

private:
    kin::local_stream_cluster& _inner;
};

static_assert(kin::stream_cluster<blindable_cluster>);
static_assert(kin::data_layer<blindable_cluster>);
static_assert(kin::data_layer<kin::local_data_access<kin::local_stream_cluster>>);

auto service_config() -> kin::kinesis_service_config {
    kin::kinesis_service_config c;
    c._throughput._read_calls_per_s = 1e9;
    c._throughput._iterator_calls_per_s = 1e9;
    c._throughput._read_bytes_per_s = 1e12;
    c._control_plane._rates.clear();
    return c;
}

/// The service over `Layer`, through the front end.
template<typename Layer> struct api {
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    kin::kinesis_service<Layer> service;

    explicit api(Layer& layer) : service(layer, service_config()) { service.register_with(fe); }

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

    auto error_type(std::string_view op, const json::value& body) -> std::string {
        const auto r = call(op, body);
        BOOST_REQUIRE_MESSAGE(r.status != 200U, std::string(op) + " unexpectedly succeeded");
        return std::string(json::parse(r.body).as_object().at("__type").as_string());
    }
};

struct fixture {
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store = make_store(dir);
    std::int64_t clock = 1'762'776'000'000;
    kin::local_stream_cluster cluster{store.get(), [this] { return clock; }};
    blindable_cluster blindable{cluster};
    kin::local_data_access<blindable_cluster> data{blindable};
    api<blindable_cluster> a{blindable};
};

auto str(const json::value& v) -> std::string {
    return std::string(v.as_string());
}

auto bytes_of(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(catalog_queries_answer_copies_of_the_replica) {
    fixture f;
    for (const auto* name : {"alpha", "bravo", "charlie"}) {
        f.a.ok("CreateStream", {{"StreamName", name}, {"ShardCount", 2}});
    }

    const auto found = f.data.find_stream(k_account, "bravo");
    BOOST_REQUIRE(found.has_value());
    BOOST_REQUIRE(found->has_value());
    BOOST_TEST((*found)->_name == "bravo");
    BOOST_TEST((*found)->_shards.size() == 2U);
    BOOST_TEST(((*found)->_status == kin::stream_status::active));

    const auto missing = f.data.find_stream(k_account, "delta");
    BOOST_REQUIRE(missing.has_value());
    BOOST_TEST(!missing->has_value());

    // Name order, after a name, up to a limit; 0 is no limit.
    const auto all = f.data.list_streams(k_account, {}, 0);
    BOOST_REQUIRE(all.has_value());
    BOOST_REQUIRE(all->size() == 3U);
    BOOST_TEST(all->front()._name == "alpha");
    const auto page = f.data.list_streams(k_account, "alpha", 1);
    BOOST_REQUIRE(page.has_value());
    BOOST_REQUIRE(page->size() == 1U);
    BOOST_TEST(page->front()._name == "bravo");
    BOOST_TEST(f.data.list_streams("444455556666", {}, 0)->empty());

    // Every stream, or those of some statuses.
    BOOST_TEST(f.data.streams({})->size() == 3U);
    BOOST_TEST(f.data.streams({kin::stream_status::active})->size() == 3U);
    BOOST_TEST(f.data.streams({kin::stream_status::creating})->empty());

    BOOST_TEST(!f.data.find_channel(k_account, "nope")->has_value());
    BOOST_TEST(!f.data.find_channel_by_id(k_account, 7)->has_value());
    BOOST_TEST(f.data.list_channels(k_account, {}, 0)->empty());

    // A copy: a later change does not reach an answer already given.
    f.a.ok("AddTagsToStream", {{"StreamName", "bravo"}, {"Tags", {{"team", "red"}}}});
    BOOST_TEST((*found)->_tags.empty());
    BOOST_TEST((*f.data.find_stream(k_account, "bravo"))->_tags.size() == 1U);
}

BOOST_AUTO_TEST_CASE(records_come_back_as_stored) {
    fixture f;
    f.a.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});
    for (int i = 0; i < 12; ++i) {
        f.clock += 10;
        f.a.ok("PutRecord", {{"StreamName", "orders"},
                             {"PartitionKey", "pk" + std::to_string(i)},
                             {"Data", "aGVsbG8="}});  // "hello"
    }
    const auto rec = **f.data.find_stream(k_account, "orders");
    const auto key = kin::routing_key(rec._id, 0);

    const auto shard = f.data.shard(key);
    BOOST_REQUIRE(shard.has_value());
    BOOST_REQUIRE(shard->has_value());
    BOOST_TEST((*shard)->_last_counter == 12U);
    // The 400-byte segments roll: the read crosses sealed segments.
    BOOST_TEST(!(*shard)->_sealed.empty());

    const kythira::segment_read_limits all{._max_records = 100, ._max_bytes = 1 << 20};
    const auto got = f.data.read_records(key, 0, 0, all);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST(got->_found);
    BOOST_TEST(!got->_read._missing);
    BOOST_TEST(got->_read._caught_up);
    BOOST_REQUIRE(got->_read._records.size() == 12U);
    BOOST_TEST(got->_read._next_counter == 13U);
    BOOST_TEST(got->_last_arrival_ms == f.clock);
    for (std::size_t i = 0; i < 12; ++i) {
        const auto& r = got->_read._records[i];
        BOOST_TEST(r._seq == i + 1);
        BOOST_TEST(
            (r._data == kin::encode_stored_record("pk" + std::to_string(i), bytes_of("hello"))));
    }

    // Limits and a minimum timestamp, as GetRecords applies them.
    const auto two = f.data.read_records(key, 5, 0, {._max_records = 2, ._max_bytes = 1 << 20});
    BOOST_REQUIRE(two->_read._records.size() == 2U);
    BOOST_TEST(two->_read._records.front()._seq == 5U);
    BOOST_TEST(two->_read._next_counter == 7U);
    BOOST_TEST(!two->_read._caught_up);
    const auto late = f.data.read_records(key, 0, f.clock - 15, all);
    BOOST_REQUIRE(late->_read._records.size() == 2U);
    BOOST_TEST(late->_read._records.front()._seq == 11U);

    // Opening a raw read gives what read_shard gives.
    const auto opened = kin::open_shard_read(got->_read);
    BOOST_REQUIRE(opened._records.size() == 12U);
    BOOST_TEST(opened._records.front()._record._partition_key == "pk0");
    BOOST_TEST(opened._records.front()._arrival_ms == got->_read._records.front()._timestamp_ms);

    // A shard the replica does not have: found false, not unreachable.
    const auto absent = f.data.read_records(kin::routing_key(rec._id, 9), 0, 0, all);
    BOOST_REQUIRE(absent.has_value());
    BOOST_TEST(!absent->_found);
    BOOST_REQUIRE(f.data.shard(kin::routing_key(rec._id, 9)).has_value());
    BOOST_TEST(!f.data.shard(kin::routing_key(rec._id, 9))->has_value());
    BOOST_TEST(f.data.local_bytes(key) > 0U);
}

BOOST_AUTO_TEST_CASE(no_replica_is_unreachable_and_fails_retryably) {
    fixture f;
    f.a.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 1}});
    f.a.ok("PutRecord", {{"StreamName", "orders"}, {"PartitionKey", "a"}, {"Data", "aGk="}});
    const auto it = str(f.a.ok("GetShardIterator", {{"StreamName", "orders"},
                                                    {"ShardId", "shardId-000000000000"},
                                                    {"ShardIteratorType", "TRIM_HORIZON"}})
                            .at("ShardIterator"));

    f.blindable._blind = true;
    BOOST_TEST((f.data.find_stream(k_account, "orders").error() == kin::data_error::unreachable));
    BOOST_TEST(!f.data.list_streams(k_account, {}, 0).has_value());
    BOOST_TEST(!f.data.streams({}).has_value());
    BOOST_TEST(!f.data.find_channel(k_account, "c").has_value());
    BOOST_TEST(!f.data.list_channels(k_account, {}, 0).has_value());
    BOOST_TEST(!f.data.shard(kin::routing_key(1, 0)).has_value());
    BOOST_TEST(!f.data.read_records(kin::routing_key(1, 0), 0, 0, {}).has_value());
    BOOST_TEST(f.data.local_bytes(kin::routing_key(1, 0)) == 0U);

    // Retryable to every client, never "no such stream".
    BOOST_TEST(f.a.error_type("DescribeStreamSummary", {{"StreamName", "orders"}}) ==
               "InternalFailure");
    BOOST_TEST(f.a.error_type("ListStreams", json::object{}) == "InternalFailure");
    BOOST_TEST(f.a.error_type("GetRecords", {{"ShardIterator", it}}) == "InternalFailure");

    f.blindable._blind = false;
    const auto got = f.a.ok("GetRecords", {{"ShardIterator", it}});
    BOOST_TEST(got.at("Records").as_array().size() == 1U);
}

BOOST_AUTO_TEST_CASE(the_service_runs_over_a_data_access_it_is_handed) {
    temp_dir dir;
    auto store = make_store(dir);
    std::int64_t clock = 1'762'776'000'000;
    kin::local_stream_cluster cluster{store.get(), [&clock] { return clock; }};
    kin::local_data_access<kin::local_stream_cluster> data{cluster};
    api<kin::local_data_access<kin::local_stream_cluster>> a{data};

    a.ok("CreateStream", {{"StreamName", "orders"}, {"ShardCount", 4}});
    const auto put = a.ok("PutRecords", {{"StreamName", "orders"},
                                         {"Records",
                                          {{{"PartitionKey", "a"}, {"Data", "aGk="}},
                                           {{"PartitionKey", "b"}, {"Data", "aGk="}},
                                           {{"PartitionKey", "c"}, {"Data", "aGk="}}}}});
    BOOST_TEST(put.at("FailedRecordCount").as_int64() == 0);
    // One group: the three appends shared one entry (group commit through
    // `group_of`), after the create's catalog entries and four opens.
    const auto before = cluster.proposals();
    a.ok(
        "PutRecords",
        {{"StreamName", "orders"},
         {"Records",
          {{{"PartitionKey", "d"}, {"Data", "aGk="}}, {{"PartitionKey", "e"}, {"Data", "aGk="}}}}});
    BOOST_TEST(cluster.proposals() == before + 1);

    // Resharding is offered: local_stream_cluster commits transactions.
    BOOST_TEST(data.can_transact());
    a.ok("SplitShard", {{"StreamName", "orders"},
                        {"ShardToSplit", "shardId-000000000000"},
                        {"NewStartingHashKey", "42535295865117307932921825928971026432"}});
    const auto shards = a.ok("ListShards", {{"StreamName", "orders"}});
    BOOST_TEST(shards.at("Shards").as_array().size() == 6U);
}
