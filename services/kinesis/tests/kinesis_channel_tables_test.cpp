// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Channel delivery to S3 Tables (`.kiro/specs/kinesis-compatible-streams/`
// task 19, Requirement 18.3) over the in-process cluster, an in-memory
// object store and a fake Iceberg REST catalog that enforces the commit
// requirements as a real one does: rows land in Parquet data files per
// partition, a manifest and a manifest list carrying the parent's
// manifests, one snapshot per batch; records that do not fit the schema go
// to the dead-letter location; a commit that loses to another writer is
// rebuilt on the new parent; a commit whose answer was lost is not made
// twice; a table a channel cannot write fails the channel with the reason;
// a missing table leaves it ACTIVE and retrying.
//
// With KINESIS_TABLES_TEST_EXPORT set to a directory, the first case writes
// the bucket and the table metadata there, so pyiceberg can read the table
// back (services/kinesis/tests/iceberg/read_exported_table.py): an
// independent reader of the manifests and the Parquet data files.

#define BOOST_TEST_MODULE kinesis_channel_tables_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_avro.hpp>
#include <kythira/kinesis/kinesis_channel_delivery.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_iceberg.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include "parquet_test_reader.hpp"

#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace avro = kythira::kinesis::avro;
namespace json = boost::json;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_role = "arn:aws:iam::111122223333:role/channel-delivery";
constexpr std::string_view k_table_bucket = "arn:aws:s3tables:us-east-1:111122223333:bucket/tables";

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
        static int counter = 0;
        _path = std::filesystem::temp_directory_path() /
                ("kinesis_channel_tables_test." + std::to_string(::getpid()) + "." +
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

/// The events table: a required id, a timestamptz partitioned by hour, a
/// string partitioned by identity, an optional nested struct and a list.
auto events_metadata(const json::array& extra_fields = {}) -> json::object {
    json::array fields{
        json::object{{"id", 1}, {"name", "id"}, {"required", true}, {"type", "long"}},
        json::object{
            {"id", 2}, {"name", "event_time"}, {"required", true}, {"type", "timestamptz"}},
        json::object{{"id", 3}, {"name", "kind"}, {"required", false}, {"type", "string"}},
        json::object{
            {"id", 4},
            {"name", "detail"},
            {"required", false},
            {"type", json::object{{"type", "struct"},
                                  {"fields", json::array{json::object{{"id", 6},
                                                                      {"name", "score"},
                                                                      {"required", false},
                                                                      {"type", "double"}}}}}}},
        json::object{{"id", 5},
                     {"name", "tags"},
                     {"required", false},
                     {"type", json::object{{"type", "list"},
                                           {"element-id", 7},
                                           {"element", "string"},
                                           {"element-required", true}}}},
    };
    for (const auto& f : extra_fields) {
        fields.push_back(f);
    }
    return json::object{
        {"format-version", 2},
        {"table-uuid", "9c12d441-03fe-4693-9a96-a0705ddf69c1"},
        {"location", "s3://warehouse-bucket/events/clicks"},
        {"last-sequence-number", 0},
        {"last-updated-ms", 1'762'776'000'000},
        {"last-column-id", 7},
        {"current-schema-id", 0},
        {"schemas",
         json::array{json::object{{"type", "struct"}, {"schema-id", 0}, {"fields", fields}}}},
        {"default-spec-id", 0},
        {"partition-specs",
         json::array{json::object{{"spec-id", 0},
                                  {"fields", json::array{json::object{{"name", "event_time_hour"},
                                                                      {"transform", "hour"},
                                                                      {"source-id", 2},
                                                                      {"field-id", 1000}},
                                                         json::object{{"name", "kind"},
                                                                      {"transform", "identity"},
                                                                      {"source-id", 3},
                                                                      {"field-id", 1001}}}}}}},
        {"last-partition-id", 1001},
        {"default-sort-order-id", 0},
        {"sort-orders", json::array{json::object{{"order-id", 0}, {"fields", json::array{}}}}},
        {"properties", json::object{}},
        {"current-snapshot-id", -1},
        {"refs", json::object{}},
        {"snapshots", json::array{}},
        {"snapshot-log", json::array{}},
        {"metadata-log", json::array{}},
    };
}

/// A REST catalog holding one table, enforcing `assert-table-uuid` and
/// `assert-ref-snapshot-id` and applying `add-snapshot` / `set-snapshot-ref`.
struct fake_catalog {
    json::object _metadata = events_metadata();
    bool _exists = true;
    int _commits = 0;
    /// Runs before a commit is judged: another writer can commit here.
    std::function<void()> _before_commit;
    /// Apply the commit but answer 500, as if the answer was lost.
    bool _lose_answer = false;

    [[nodiscard]] auto load() const -> std::optional<kin::peer_response> {
        if (!_exists) {
            return kin::peer_response{
                ._status = 404,
                ._body =
                    R"({"error":{"message":"Table does not exist: events.clicks","type":"NoSuchTableException","code":404}})"};
        }
        return kin::peer_response{
            ._status = 200,
            ._body = json::serialize(json::object{
                {"metadata-location", "s3://warehouse-bucket/events/clicks/metadata/v.json"},
                {"metadata", _metadata}})};
    }

    auto apply(const json::object& req) -> std::optional<std::string> {
        auto main = [&]() -> json::value {
            const auto* r = _metadata.at("refs").as_object().if_contains("main");
            return r != nullptr ? r->as_object().at("snapshot-id") : json::value(nullptr);
        };
        for (const auto& r : req.at("requirements").as_array()) {
            const auto& o = r.as_object();
            if (o.at("type") == "assert-table-uuid" && o.at("uuid") != _metadata.at("table-uuid")) {
                return "uuid";
            }
            if (o.at("type") == "assert-ref-snapshot-id" && o.at("snapshot-id") != main()) {
                return "main has moved";
            }
        }
        for (const auto& u : req.at("updates").as_array()) {
            const auto& o = u.as_object();
            if (o.at("action") == "add-snapshot") {
                const auto& snap = o.at("snapshot").as_object();
                const auto seq = snap.at("sequence-number").as_int64();
                BOOST_REQUIRE(seq == _metadata.at("last-sequence-number").as_int64() + 1);
                _metadata["last-sequence-number"] = seq;
                _metadata["snapshots"].as_array().push_back(snap);
            } else if (o.at("action") == "set-snapshot-ref") {
                _metadata["refs"].as_object()["main"] =
                    json::object{{"snapshot-id", o.at("snapshot-id")}, {"type", "branch"}};
                _metadata["current-snapshot-id"] = o.at("snapshot-id");
            }
        }
        ++_commits;
        return std::nullopt;
    }

    auto commit(const std::string& body) -> std::optional<kin::peer_response> {
        if (_before_commit) {
            auto f = std::move(_before_commit);
            _before_commit = {};
            f();
        }
        const auto req = json::parse(body).as_object();
        BOOST_TEST(req.at("identifier").at("name") == "clicks");
        if (const auto conflict = apply(req)) {
            return kin::peer_response{._status = 409,
                                      ._body = R"({"error":{"message":"Requirement failed: )" +
                                               *conflict +
                                               R"(","type":"CommitFailedException","code":409}})"};
        }
        if (_lose_answer) {
            _lose_answer = false;
            return kin::peer_response{._status = 503, ._body = "gateway timeout"};
        }
        return load();
    }
};

using service_t = kin::kinesis_service<kin::local_stream_cluster>;
using delivery_t = kin::channel_delivery<kin::local_stream_cluster, service_t>;
using bucket = std::map<std::string, std::string>;

struct fixture {
    std::int64_t clock = 1'762'776'000'000;  // 2025-11-10T12:00:00Z
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store =
        std::make_unique<kythira::record_segment_store>(kythira::record_segment_store_options{
            ._data_dir = dir._path,
            ._max_segment_bytes = 4096,
            ._max_segment_age_ms = 0,
            ._max_record_bytes = 4096,
            ._index_interval_bytes = 64,
            ._barriers_enabled = false,
        });
    kin::local_stream_cluster cluster{store.get(), [this] { return clock; }};
    allow_all auth;
    kin::front_end<allow_all> fe{kin::front_end_config{}, auth};
    service_t service{cluster, no_rates()};
    std::map<std::string, bucket> buckets;
    fake_catalog catalog;
    std::vector<std::string> catalog_arns;
    delivery_t delivery{cluster, service, delivery_config()};
    std::string arn;

    fixture() { service.register_with(fe); }

    static auto no_rates() -> kin::kinesis_service_config {
        kin::kinesis_service_config cfg;
        cfg._control_plane._rates.clear();
        return cfg;
    }

    auto delivery_config() -> kin::channel_delivery_config {
        kin::channel_delivery_config cfg;
        cfg._destination = [this](
                               const std::string& name,
                               const kin::channel_access&) -> std::optional<kin::channel_bucket> {
            kin::channel_bucket t;
            t._put = [this, name](const std::string& k, std::string_view b,
                                  const kin::channel_put_options&) {
                buckets[name][k] = std::string(b);
            };
            t._get = [this, name](const std::string& k) -> std::optional<std::string> {
                const auto& b = buckets[name];
                const auto it = b.find(k);
                if (it == b.end()) {
                    return std::nullopt;
                }
                return it->second;
            };
            return t;
        };
        cfg._tables = [this](const std::string& table_bucket,
                             const kin::channel_access& a) -> std::optional<kin::iceberg_catalog> {
            catalog_arns.push_back(table_bucket);
            BOOST_TEST(a._role_arn == k_role);
            kin::iceberg_catalog c;
            c._load = [this](const std::string& ns, const std::string& table) {
                BOOST_TEST(ns == "events");
                BOOST_TEST(table == "clicks");
                return catalog.load();
            };
            c._commit = [this](const std::string&, const std::string&, std::string body) {
                return catalog.commit(body);
            };
            return c;
        };
        return cfg;
    }

    auto ok(std::string_view op, const json::value& body) -> json::object {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)}};
        const auto res = fe.handle(r);
        BOOST_REQUIRE_MESSAGE(res.status == 200U, std::string(op) + ": " + res.body);
        return json::parse(res.body).as_object();
    }

    auto put(std::string_view data) -> void {
        (void)ok("PutRecord", {{"StreamName", "clicks"},
                               {"PartitionKey", "k"},
                               {"Data", kin::channel_detail::base64(data)}});
    }

    auto channel(std::string_view compression = "SNAPPY", json::object table_extra = {}) -> void {
        (void)ok("CreateStream",
                 {{"StreamName", "clicks"}, {"StreamModeDetails", {{"StreamMode", "ON_DEMAND"}}}});
        json::object table{{"TableBucketARN", k_table_bucket},
                           {"Namespace", "events"},
                           {"TableName", "clicks"},
                           {"CompressionType", compression}};
        for (const auto& [k, v] : table_extra) {
            table[k] = v;
        }
        const auto created =
            ok("CreateChannel",
               {{"ChannelName", "to-tables"},
                {"ServiceExecutionRoleARN", k_role},
                {"StreamConfigurationList",
                 json::array{{{"StreamARN", "arn:aws:kinesis:us-east-1:" + std::string(k_account) +
                                                ":stream/clicks"},
                              {"RecordConfiguration",
                               {{"RecordFormatType", "GSR_JSON"},
                                {"GSRSchemaARN",
                                 "arn:aws:glue:us-east-1:111122223333:schema/registry/clicks"}}}}}},
                {"S3TablesDestinationConfiguration",
                 {{"DeadLetterQueueS3Configuration",
                   {{"BucketARN", "arn:aws:s3:::dead-letters"},
                    {"ExpectedBucketOwner", k_account},
                    {"ErrorOutputPrefix", "bad/"}}},
                  {"S3TablesConfigurationList", json::array{table}}}}});
        arn =
            std::string(created.at("ChannelDescription").as_object().at("ChannelARN").as_string());
        clock += 1000;
    }

    auto status() -> std::pair<std::string, std::string> {
        const auto d =
            ok("DescribeChannel", {{"ChannelARN", arn}}).at("ChannelDescription").as_object();
        const auto* reason = d.if_contains("ChannelStatusReason");
        return {std::string(d.at("ChannelStatus").as_string()),
                reason != nullptr && reason->is_string() ? std::string(reason->as_string())
                                                         : std::string()};
    }

    auto table() -> kin::iceberg::table_metadata {
        return kin::iceberg::parse_metadata(catalog._metadata);
    }

    /// The object at an s3:// URI.
    auto object(std::string_view uri) -> std::string {
        const auto where = kin::iceberg::split_s3_uri(uri);
        BOOST_REQUIRE(where);
        const auto& b = buckets[where->first];
        const auto it = b.find(where->second);
        BOOST_REQUIRE_MESSAGE(it != b.end(), "no object " + std::string(uri));
        return it->second;
    }

    /// The main snapshot's manifest list entries.
    auto manifest_list() -> std::vector<json::value> {
        const auto t = table();
        BOOST_REQUIRE(t._main_snapshot);
        const auto* snap = t.snapshot(*t._main_snapshot);
        BOOST_REQUIRE(snap != nullptr);
        return avro::read_file(object(snap->at("manifest-list").as_string()))._records;
    }

    /// Every row of every data file the main snapshot's manifests list:
    /// id, event_time, kind, detail.score and tags, read back from Parquet.
    auto rows() -> std::vector<json::object> {
        std::vector<json::object> out;
        for (const auto& m : manifest_list()) {
            const auto manifest = avro::read_file(object(m.at("manifest_path").as_string()));
            for (const auto& e : manifest._records) {
                const auto& df = e.at("data_file").as_object();
                const parquet_test::file data(object(df.at("file_path").as_string()));
                BOOST_TEST(data.rows() == df.at("record_count").as_int64());
                BOOST_TEST(data.key_value("iceberg.schema").has_value());
                const auto ids = data.column("id");
                const auto times = data.column("event_time");
                const auto kinds = data.column("kind");
                const auto scores = data.column("detail.score");
                const auto tags = data.read_leaf("tags.list.element");
                // tags optional, list repeated, element required.
                BOOST_TEST(tags._max_def == 2);
                BOOST_TEST(tags._max_rep == 1);
                std::vector<json::value> tag_rows;
                std::size_t v = 0;
                for (std::size_t i = 0; i < tags._defs.size(); ++i) {
                    const auto d = tags._defs[i];
                    if (tags._reps[i] == 0) {
                        tag_rows.emplace_back(d == 0 ? json::value(nullptr)
                                                     : json::value(json::array{}));
                    }
                    if (static_cast<int>(d) == tags._max_def) {
                        tag_rows.back().as_array().push_back(tags._values[v++]);
                    }
                }
                BOOST_REQUIRE(static_cast<std::int64_t>(ids.size()) == data.rows());
                BOOST_REQUIRE(tag_rows.size() == ids.size());
                for (std::size_t i = 0; i < ids.size(); ++i) {
                    out.push_back(json::object{{"id", ids[i]},
                                               {"event_time", times[i]},
                                               {"kind", kinds[i]},
                                               {"score", scores[i]},
                                               {"tags", tag_rows[i]}});
                }
            }
        }
        return out;
    }

    auto export_to(const std::filesystem::path& to) -> void {
        for (const auto& [b, objects] : buckets) {
            for (const auto& [k, v] : objects) {
                const auto p = to / b / k;
                std::filesystem::create_directories(p.parent_path());
                std::ofstream(p, std::ios::binary) << v;
            }
        }
        std::ofstream(to / "table.metadata.json") << json::serialize(catalog._metadata);
    }
};

auto ids(const std::vector<json::object>& rows) -> std::multiset<std::int64_t> {
    std::multiset<std::int64_t> out;
    for (const auto& r : rows) {
        out.insert(r.at("id").as_int64());
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(kinesis_channel_tables)

BOOST_AUTO_TEST_CASE(appends_rows_as_one_snapshot_per_batch) {
    fixture f;
    f.channel();
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z","kind":"view","tags":["a","b"]})");
    f.put(
        R"({"id":2,"event_time":"2025-11-10T12:30:00+00:00","kind":"click","detail":{"score":0.5}})");
    f.put(R"({"id":3,"event_time":1762779600000,"kind":"view","extra":"ignored"})");
    f.put(R"({"id":"four","event_time":"2025-11-10T12:00:00Z"})");  // wrong type
    f.put(R"({"event_time":"2025-11-10T12:00:00Z"})");              // required id missing
    f.put("not json");

    // Not yet DataFreshnessInSeconds old: nothing.
    auto stats = f.delivery.run_once();
    BOOST_TEST(f.catalog._commits == 0);

    f.clock += 300'000;
    stats = f.delivery.run_once();
    BOOST_TEST_MESSAGE(stats._last_failure);
    BOOST_TEST(stats._failures == 0U);
    BOOST_TEST(stats._records == 3U);
    BOOST_TEST(stats._dead_letters == 3U);
    BOOST_TEST(stats._checkpoints == 1U);
    BOOST_TEST(f.catalog._commits == 1);
    BOOST_TEST(f.catalog_arns.front() == k_table_bucket);
    BOOST_TEST(f.status().first == "ACTIVE");

    // One snapshot, its summary naming the batch.
    const auto t = f.table();
    BOOST_TEST(t._last_sequence_number == 1);
    BOOST_REQUIRE(t._snapshots.size() == 1U);
    const auto& snap = t._snapshots[0].as_object();
    const auto& summary = snap.at("summary").as_object();
    BOOST_TEST(summary.at("operation") == "append");
    BOOST_TEST(summary.at("added-records") == "3");
    BOOST_TEST(summary.at("added-data-files") == "3");  // (12h, view) (12h, click) (13h, view)
    BOOST_TEST(summary.at("total-records") == "3");
    BOOST_TEST(summary.at("kythira.channel-batch").as_string().starts_with("00000000-"));
    BOOST_TEST(!snap.contains("parent-snapshot-id"));
    BOOST_TEST(snap.at("manifest-list")
                   .as_string()
                   .starts_with("s3://warehouse-bucket/events/clicks/metadata/snap-"));

    // The manifest list holds the one new manifest, at sequence 1.
    const auto list = f.manifest_list();
    BOOST_REQUIRE(list.size() == 1U);
    BOOST_TEST(list[0].at("sequence_number").as_int64() == 1);
    BOOST_TEST(list[0].at("added_files_count").as_int64() == 3);
    BOOST_TEST(list[0].at("added_rows_count").as_int64() == 3);
    const auto& hour = list[0].at("partitions").as_array()[0].as_object();
    BOOST_TEST(!hour.at("contains_null").as_bool());
    // hour(2025-11-10T12:00Z) = 489660, little-endian int.
    BOOST_TEST(hour.at("lower_bound").as_string() == std::string("\xBC\x78\x07\x00", 4));
    BOOST_TEST(hour.at("upper_bound").as_string() == std::string("\xBD\x78\x07\x00", 4));

    // Entries ADDED by the snapshot, inheriting its sequence number, in
    // hour/kind partition directories.
    const auto manifest = avro::read_file(f.object(list[0].at("manifest_path").as_string()));
    BOOST_TEST(manifest._metadata.at("format-version") == "2");
    BOOST_TEST(manifest._metadata.at("partition-spec-id") == "0");
    BOOST_REQUIRE(manifest._records.size() == 3U);
    std::set<std::string> paths;
    for (const auto& e : manifest._records) {
        BOOST_TEST(e.at("status").as_int64() == 1);
        BOOST_TEST(e.at("snapshot_id") == snap.at("snapshot-id"));
        BOOST_TEST(e.at("sequence_number").is_null());
        const auto& df = e.at("data_file").as_object();
        BOOST_TEST(df.at("file_format") == "PARQUET");
        paths.insert(std::string(df.at("file_path").as_string()));
    }
    BOOST_TEST(paths.begin()->starts_with(
        "s3://warehouse-bucket/events/clicks/data/event_time_hour=489660/kind=click/"));

    // The rows, converted: microseconds for timestamps, nested and list
    // columns kept, unknown fields dropped.
    const auto rows = f.rows();
    BOOST_TEST(ids(rows) == (std::multiset<std::int64_t>{1, 2, 3}));
    for (const auto& r : rows) {
        if (r.at("id").as_int64() == 1) {
            BOOST_TEST(r.at("event_time").as_int64() == 1'762'776'001'000'000);
            BOOST_TEST(json::serialize(r.at("tags")) == R"(["a","b"])");
            BOOST_TEST(r.at("score").is_null());
        }
        if (r.at("id").as_int64() == 2) {
            BOOST_TEST(r.at("score").as_double() == 0.5);
            BOOST_TEST(r.at("tags").is_null());
        }
        if (r.at("id").as_int64() == 3) {
            BOOST_TEST(r.at("event_time").as_int64() == 1'762'779'600'000'000);
            BOOST_TEST(r.at("kind") == "view");
        }
    }

    // The three that did not fit, with why.
    const auto& dead = f.buckets.at("dead-letters");
    BOOST_REQUIRE(dead.size() == 1U);
    BOOST_TEST(dead.begin()->first.starts_with("bad/to-tables-shardId-"));
    const auto& lines = dead.begin()->second;
    BOOST_TEST(lines.find("SchemaMismatch") != std::string::npos);
    BOOST_TEST(lines.find("Required column 'id' is missing.") != std::string::npos);
    BOOST_TEST(lines.find("InvalidJson") != std::string::npos);

    if (const char* to = std::getenv("KINESIS_TABLES_TEST_EXPORT")) {
        f.export_to(to);
    }

    // A second batch is a second snapshot on top of the first, its list
    // carrying both manifests (the new one first).
    f.put(R"({"id":4,"event_time":"2025-11-10T12:10:00Z","kind":"view"})");
    f.clock += 300'000;
    stats = f.delivery.run_once();
    BOOST_TEST(stats._records == 1U);
    BOOST_TEST(f.catalog._commits == 2);
    const auto t2 = f.table();
    BOOST_TEST(t2._last_sequence_number == 2);
    BOOST_TEST(t2._snapshots[1].at("parent-snapshot-id") == snap.at("snapshot-id"));
    BOOST_TEST(t2._snapshots[1].at("summary").at("total-records") == "4");
    const auto list2 = f.manifest_list();
    BOOST_REQUIRE(list2.size() == 2U);
    BOOST_TEST(list2[0].at("sequence_number").as_int64() == 2);
    BOOST_TEST(list2[1].at("manifest_path") == list[0].at("manifest_path"));
    BOOST_TEST(ids(f.rows()) == (std::multiset<std::int64_t>{1, 2, 3, 4}));

    if (const char* to = std::getenv("KINESIS_TABLES_TEST_EXPORT")) {
        f.export_to(std::filesystem::path(to) / "second");
    }
}

BOOST_AUTO_TEST_CASE(a_commit_that_loses_is_rebuilt_on_the_new_parent) {
    fixture f;
    f.channel("ZSTD");
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z","kind":"view"})");
    f.clock += 300'000;
    // Another writer appends an empty snapshot first.
    f.catalog._before_commit = [&f] {
        const auto list = kin::iceberg::write_manifest_list(
            json::object{
                {"manifest_path", "s3://warehouse-bucket/events/clicks/metadata/other.avro"},
                {"manifest_length", 10},
                {"partition_spec_id", 0},
                {"content", 0},
                {"sequence_number", 1},
                {"min_sequence_number", 1},
                {"added_snapshot_id", 77},
                {"added_files_count", 0},
                {"existing_files_count", 0},
                {"deleted_files_count", 0},
                {"added_rows_count", 0},
                {"existing_rows_count", 0},
                {"deleted_rows_count", 0},
                {"partitions", nullptr},
                {"key_metadata", nullptr}},
            {}, 77, std::nullopt, 1, "other");
        f.buckets["warehouse-bucket"]["events/clicks/metadata/snap-77.avro"] = list;
        (void)f.catalog.apply(json::object{
            {"requirements", json::array{}},
            {"updates",
             json::array{
                 json::object{{"action", "add-snapshot"},
                              {"snapshot",
                               json::object{{"snapshot-id", 77},
                                            {"sequence-number", 1},
                                            {"timestamp-ms", 1'762'776'000'000},
                                            {"manifest-list",
                                             "s3://warehouse-bucket/events/clicks/"
                                             "metadata/snap-77.avro"},
                                            {"summary", json::object{{"operation", "append"}}}}}},
                 json::object{{"action", "set-snapshot-ref"},
                              {"ref-name", "main"},
                              {"type", "branch"},
                              {"snapshot-id", 77}}}}});
    };
    const auto stats = f.delivery.run_once();
    BOOST_TEST_MESSAGE(stats._last_failure);
    BOOST_TEST(stats._failures == 0U);
    BOOST_TEST(stats._checkpoints == 1U);
    const auto t = f.table();
    BOOST_REQUIRE(t._snapshots.size() == 2U);
    BOOST_TEST(t._snapshots[1].at("parent-snapshot-id").as_int64() == 77);
    BOOST_TEST(t._snapshots[1].at("sequence-number").as_int64() == 2);
    // The other writer's manifest is still listed, after ours.
    const auto list = f.manifest_list();
    BOOST_REQUIRE(list.size() == 2U);
    BOOST_TEST(list[1].at("added_snapshot_id").as_int64() == 77);
    BOOST_TEST(list[0].at("sequence_number").as_int64() == 2);
}

BOOST_AUTO_TEST_CASE(a_commit_whose_answer_was_lost_is_not_made_twice) {
    fixture f;
    f.channel("NONE");
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    f.catalog._lose_answer = true;
    const auto stats = f.delivery.run_once();
    BOOST_TEST(stats._failures == 0U);
    BOOST_TEST(stats._checkpoints == 1U);
    BOOST_TEST(f.catalog._commits == 1);
    BOOST_TEST(f.table()._snapshots.size() == 1U);
    BOOST_TEST(ids(f.rows()) == (std::multiset<std::int64_t>{1}));
}

BOOST_AUTO_TEST_CASE(a_batch_already_in_the_table_only_moves_the_checkpoint) {
    fixture f;
    f.channel();
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    (void)f.delivery.run_once();
    BOOST_TEST(f.catalog._commits == 1);

    // As if the checkpoint move had been lost after the commit: put every
    // checkpoint of the channel back to the start.
    std::vector<std::pair<std::string, std::uint64_t>> checkpoints;
    std::uint64_t channel_id = 0;
    (void)f.cluster.read(kin::next_id_key(), [&](const auto& sm) {
        const auto* rec = sm.find_channel(std::string(k_account), "to-tables");
        BOOST_REQUIRE(rec != nullptr);
        channel_id = rec->_id;
        const auto* s = sm.find_stream(std::string(k_account), "clicks");
        BOOST_REQUIRE(s != nullptr);
        for (const auto& shard : s->_shards) {
            const auto key = kin::routing_key(s->_id, shard._ordinal);
            checkpoints.emplace_back(key,
                                     sm.channel_checkpoint(std::string(k_account), rec->_id, key));
        }
    });
    for (const auto& [key, at] : checkpoints) {
        if (at == 0) {
            continue;
        }
        const kin::stream_command back =
            kin::channel_checkpoint_command{._account = std::string(k_account),
                                            ._channel = "to-tables",
                                            ._channel_id = channel_id,
                                            ._shard = key,
                                            ._expected = at,
                                            ._next = 0};
        const auto r = f.cluster.propose(kin::command_key(back), kin::encode_command(back),
                                         kin::admission::none);
        BOOST_REQUIRE(r.has_value());
        BOOST_REQUIRE((r->_status == kin::apply_status::ok));
    }

    // The same batch again: found in the table's history, not committed a
    // second time, and the checkpoint moves past it.
    f.clock += 300'000;
    const auto stats = f.delivery.run_once();
    BOOST_TEST(stats._checkpoints == 1U);
    BOOST_TEST(f.catalog._commits == 1);
    BOOST_TEST(f.table()._snapshots.size() == 1U);
    BOOST_TEST(ids(f.rows()) == (std::multiset<std::int64_t>{1}));
}

BOOST_AUTO_TEST_CASE(a_table_a_channel_cannot_write_fails_the_channel) {
    fixture f;
    f.catalog._metadata = events_metadata(json::array{
        json::object{{"id", 8}, {"name", "price"}, {"required", false}, {"type", "decimal(9,2)"}}});
    f.channel();
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    const auto stats = f.delivery.run_once();
    BOOST_TEST(stats._failed_channels == 1U);
    const auto [status, reason] = f.status();
    BOOST_TEST(status == "FAILED");
    BOOST_TEST(reason.find("Column 'price'") != std::string::npos);
    BOOST_TEST(f.catalog._commits == 0);
}

BOOST_AUTO_TEST_CASE(a_time_hour_spec_the_table_lacks_fails_the_channel) {
    fixture f;
    f.channel("SNAPPY",
              json::object{{"PartitionSpec",
                            {{"PartitionFields", json::array{{{"Transform", "TIME_HOUR"},
                                                              {"SourceName", "other_time"}}}}}}});
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    (void)f.delivery.run_once();
    const auto [status, reason] = f.status();
    BOOST_TEST(status == "FAILED");
    BOOST_TEST(reason.find("hour(other_time)") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(a_missing_table_is_retried) {
    fixture f;
    f.catalog._exists = false;
    f.channel();
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    auto stats = f.delivery.run_once();
    BOOST_TEST(stats._failures == 1U);
    BOOST_TEST(stats._checkpoints == 0U);
    BOOST_TEST(stats._last_failure.find("NoSuchTableException") != std::string::npos);
    BOOST_TEST(f.status().first == "ACTIVE");

    // Once the table exists the same records are delivered.
    f.catalog._exists = true;
    stats = f.delivery.run_once();
    BOOST_TEST(stats._records == 1U);
    BOOST_TEST(ids(f.rows()) == (std::multiset<std::int64_t>{1}));
}

BOOST_AUTO_TEST_CASE(a_node_without_a_catalog_leaves_tables_channels_alone) {
    fixture f;
    f.channel();
    f.put(R"({"id":1,"event_time":"2025-11-10T12:00:01Z"})");
    f.clock += 300'000;
    auto cfg = f.delivery_config();
    cfg._tables = {};
    delivery_t no_catalog{f.cluster, f.service, cfg};
    const auto stats = no_catalog.run_once();
    BOOST_TEST(stats._failures == 0U);
    BOOST_TEST(stats._checkpoints == 0U);
    BOOST_TEST(f.catalog._commits == 0);
}

BOOST_AUTO_TEST_SUITE_END()
