// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The format pieces behind channel delivery to S3 Tables (`.kiro/specs/
// kinesis-compatible-streams/` task 19): Snappy against a block libsnappy
// wrote, Avro container files through every codec and the schema forms
// manifests use, Parquet files read back, Iceberg's metadata, JSON-to-row
// conversion, partition transforms against the specification's own
// examples, manifest list normalization, and the REST catalog client's
// prefix discovery, paths, SigV4 and bearer token.

#define BOOST_TEST_MODULE kinesis_iceberg_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_avro.hpp>
#include <kythira/kinesis/kinesis_iceberg.hpp>
#include <kythira/kinesis/kinesis_iceberg_rest.hpp>
#include <kythira/kinesis/kinesis_parquet.hpp>
#include <kythira/kinesis/kinesis_snappy.hpp>

#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include "parquet_test_reader.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace ice = kythira::kinesis::iceberg;
namespace avro = kythira::kinesis::avro;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

auto unhex(std::string_view h) -> std::string {
    std::string out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<char>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

auto column_json(const parquet_test::file& f, std::string_view path) -> std::string {
    const auto values = f.column(path);
    return json::serialize(json::array(values.begin(), values.end()));
}

auto schema_of(std::string_view fields) -> json::object {
    return json::parse(R"({"type":"struct","schema-id":0,"fields":)" + std::string(fields) + "}")
        .as_object();
}

auto metadata(const json::object& schema, const json::array& spec_fields) -> json::object {
    return json::object{
        {"format-version", 2},
        {"table-uuid", "uuid-1"},
        {"location", "s3://b/t/"},
        {"last-sequence-number", 5},
        {"current-schema-id", 0},
        {"schemas", json::array{schema}},
        {"default-spec-id", 0},
        {"partition-specs", json::array{json::object{{"spec-id", 0}, {"fields", spec_fields}}}},
        {"current-snapshot-id", 9},
        {"snapshots",
         json::array{json::object{
             {"snapshot-id", 9}, {"summary", json::object{{"operation", "append"}, {"k", "v"}}}}}}};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(kinesis_iceberg)

BOOST_AUTO_TEST_CASE(snappy_round_trips_and_reads_libsnappy) {
    // libsnappy's compression of "Kinesis channel records " x 20 + 0..255.
    const auto lib = unhex(
        "e0055c4b696e65736973206368616e6e656c207265636f72647320fe1800fe1800fe1800fe1800fe1800fe18"
        "00fe18001118f0ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232"
        "425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"
        "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7"
        "d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9"
        "aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d"
        "6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    std::string plain;
    for (int i = 0; i < 20; ++i) {
        plain += "Kinesis channel records ";
    }
    for (int i = 0; i < 256; ++i) {
        plain.push_back(static_cast<char>(i));
    }
    const auto decoded = kin::snappy::decompress(lib);
    BOOST_REQUIRE(decoded);
    BOOST_TEST(*decoded == plain);

    for (const auto& in : {std::string(), std::string("a"), plain, std::string(200000, 'x')}) {
        const auto c = kin::snappy::compress(in);
        BOOST_TEST((kin::snappy::decompress(c) == std::optional<std::string>(in)));
    }
    BOOST_TEST(kin::snappy::compress(std::string(200000, 'x')).size() < 20000U);
    BOOST_TEST(!kin::snappy::decompress("\x05\x08zz"));  // literal runs past the end
}

BOOST_AUTO_TEST_CASE(avro_files_round_trip_through_every_codec) {
    const auto schema = json::parse(R"({"type":"record","name":"r","fields":[
        {"name":"id","type":"long","field-id":1},
        {"name":"s","type":["null","string"],"default":null},
        {"name":"d","type":"double"},
        {"name":"b","type":"boolean"},
        {"name":"f","type":{"type":"fixed","name":"f4","size":4}},
        {"name":"arr","type":{"type":"array","items":"int","element-id":9}},
        {"name":"m","type":{"type":"map","values":"long"}},
        {"name":"e","type":{"type":"enum","name":"E","symbols":["A","B"]}},
        {"name":"ts","type":{"type":"long","logicalType":"timestamp-micros"}},
        {"name":"again","type":["null","f4"]}]})");
    for (const auto* codec : {"null", "deflate", "snappy", "zstandard"}) {
        if (!avro::has_codec(codec)) {
            continue;
        }
        avro::file_writer w(schema, codec, {{"k", "v"}}, "seed");
        for (std::int64_t i = 0; i < 500; ++i) {
            w.append(
                json::object{{"id", i * 1'000'003 - 5},
                             {"s", i % 3 == 0 ? json::value(nullptr) : json::value("hello")},
                             {"d", static_cast<double>(i) / 2},
                             {"b", i % 2 == 0},
                             {"f", "abcd"},
                             {"arr", json::array{1, 2, i}},
                             {"m", json::object{{"x", i}}},
                             {"e", i % 2 == 0 ? "A" : "B"},
                             {"ts", 1'700'000'000'000'000 + i},
                             {"again", i % 2 == 0 ? json::value(nullptr) : json::value("wxyz")}});
        }
        const auto bytes = w.finish();
        const auto f = avro::read_file(bytes);
        BOOST_TEST(f._metadata.at("k") == "v");
        BOOST_TEST(f._metadata.at("avro.codec") == codec);
        BOOST_REQUIRE(f._records.size() == 500U);
        const auto& last = f._records.back().as_object();
        BOOST_TEST(last.at("id").as_int64() == 499 * 1'000'003 - 5);
        BOOST_TEST(last.at("s") == "hello");
        BOOST_TEST(last.at("again") == "wxyz");
        BOOST_TEST(json::serialize(last.at("arr")) == "[1,2,499]");
        BOOST_TEST(last.at("e") == "B");
        BOOST_TEST(f._records.front().at("s").is_null());

        // The same records and seed: the same bytes.
        avro::file_writer again(schema, codec, {{"k", "v"}}, "seed");
        for (const auto& r : f._records) {
            again.append(r);
        }
        BOOST_TEST(again.finish() == bytes);
    }

    BOOST_CHECK_THROW((void)avro::encode(schema, json::object{{"id", "not a long"}}),
                      avro::avro_error);
    BOOST_CHECK_THROW((void)avro::read_file("Obj\x02"), avro::avro_error);
    BOOST_CHECK_THROW((void)avro::file_writer(schema, "lzma", {}, ""), avro::avro_error);
}

BOOST_AUTO_TEST_CASE(parquet_files_read_back) {
    const auto schema = schema_of(R"([
        {"id":1,"name":"id","required":true,"type":"long"},
        {"id":2,"name":"name","required":false,"type":"string"},
        {"id":3,"name":"ok","required":false,"type":"boolean"},
        {"id":4,"name":"day","required":false,"type":"date"},
        {"id":5,"name":"s","required":false,"type":{"type":"struct","fields":[
            {"id":7,"name":"x","required":false,"type":"double"}]}},
        {"id":6,"name":"l","required":false,"type":{"type":"list","element-id":8,
            "element":"int","element-required":false}}])");
    std::vector<json::object> rows;
    for (const auto* r :
         {R"({"id":1,"name":"a","ok":true,"day":"2025-01-02","s":{"x":1.5},"l":[1,null,3]})",
          R"({"id":2,"l":[]})", R"({"id":3,"ok":false,"s":{}})"}) {
        rows.push_back(ice::to_row(schema, json::parse(r)));
    }
    for (const auto* codec : {"UNCOMPRESSED", "SNAPPY", "ZSTD"}) {
        if (!kin::parquet::has_codec(codec)) {
            continue;
        }
        const parquet_test::file f(kin::parquet::write_file(schema, rows, codec, {{"a", "b"}}));
        BOOST_TEST(f.rows() == 3);
        BOOST_TEST((f.key_value("a") == std::optional<std::string>("b")));
        BOOST_TEST(column_json(f, "id") == "[1,2,3]");
        BOOST_TEST(column_json(f, "name") == R"(["a",null,null])");
        BOOST_TEST(column_json(f, "ok") == "[true,null,false]");
        BOOST_TEST(column_json(f, "day") == "[20090,null,null]");
        BOOST_TEST(column_json(f, "s.x") == "[1.5E0,null,null]");
        const auto l = f.read_leaf("l.list.element");
        BOOST_TEST(l._max_def == 3);
        BOOST_TEST(l._max_rep == 1);
        // Row 1: three elements (one null); row 2: empty; row 3: null list.
        BOOST_TEST(l._reps == (std::vector<std::uint32_t>{0, 1, 1, 0, 0}));
        BOOST_TEST(l._defs == (std::vector<std::uint32_t>{3, 2, 3, 1, 0}));
        BOOST_TEST(json::serialize(json::array(l._values.begin(), l._values.end())) == "[1,3]");
    }
    // A required column with no value is refused.
    BOOST_CHECK_THROW((void)kin::parquet::write_file(schema, {json::object{}}, "UNCOMPRESSED"),
                      kin::parquet::parquet_error);
}

BOOST_AUTO_TEST_CASE(metadata_is_read) {
    const auto schema = schema_of(R"([{"id":1,"name":"id","required":true,"type":"long"}])");
    auto m = metadata(schema, json::array{});
    auto t = ice::parse_metadata(m);
    BOOST_TEST(t._location == "s3://b/t");
    BOOST_TEST(t._last_sequence_number == 5);
    BOOST_TEST((t._main_snapshot == std::optional<std::int64_t>(9)));
    BOOST_TEST(t.snapshot(9) != nullptr);
    BOOST_TEST(t.snapshot_with("k", "v") != nullptr);
    BOOST_TEST(t.snapshot_with("k", "w") == nullptr);

    // refs.main wins over current-snapshot-id; -1 is no snapshot.
    m["refs"] = json::object{{"main", json::object{{"snapshot-id", 9}, {"type", "branch"}}}};
    m["current-snapshot-id"] = -1;
    BOOST_TEST((ice::parse_metadata(m)._main_snapshot == std::optional<std::int64_t>(9)));
    m.erase("refs");
    BOOST_TEST(!ice::parse_metadata(m)._main_snapshot);

    m["format-version"] = 1;
    BOOST_CHECK_THROW((void)ice::parse_metadata(m), ice::table_error);

    BOOST_TEST((ice::split_s3_uri("s3://bucket/a/b") ==
                std::optional<std::pair<std::string, std::string>>({"bucket", "a/b"})));
    BOOST_TEST((ice::split_s3_uri("s3a://bucket") ==
                (std::optional<std::pair<std::string, std::string>>({"bucket", ""}))));
    BOOST_TEST(!ice::split_s3_uri("gs://bucket/a"));
}

BOOST_AUTO_TEST_CASE(records_become_rows) {
    const auto schema = schema_of(R"([
        {"id":1,"name":"i","required":false,"type":"int"},
        {"id":2,"name":"ts","required":false,"type":"timestamp"},
        {"id":3,"name":"tz","required":false,"type":"timestamptz"},
        {"id":4,"name":"t","required":false,"type":"time"},
        {"id":5,"name":"b","required":false,"type":"binary"},
        {"id":6,"name":"u","required":false,"type":"uuid"},
        {"id":7,"name":"9 lives","required":false,"type":"string"}])");
    const auto row = ice::to_row(schema, json::parse(R"({
        "i": 7, "ts": "2025-11-10 12:00:00.25", "tz": "2025-11-10T14:00:00+02:00",
        "t": "00:00:01.000001", "b": "AAEC", "u": "9c12d441-03fe-4693-9a96-a0705ddf69c1",
        "9 lives": "cat"})"));
    BOOST_TEST(row.at("i").as_int64() == 7);
    BOOST_TEST(row.at("ts").as_int64() == 1'762'776'000'250'000);
    BOOST_TEST(row.at("tz").as_int64() == 1'762'776'000'000'000);
    BOOST_TEST(row.at("t").as_int64() == 1'000'001);
    BOOST_TEST(row.at("b").as_string() == std::string_view("\0\1\2", 3));
    BOOST_TEST(row.at("u").as_string().size() == 16U);
    // Names that are not Avro names are escaped as Iceberg's writer does.
    BOOST_TEST(ice::avro_name("9 lives") == "_9_x20lives");
    BOOST_TEST(row.at("_9_x20lives") == "cat");
    BOOST_TEST(ice::to_row(schema, json::parse(R"({"tz": 1762776000000})")).at("tz").as_int64() ==
               1'762'776'000'000'000);

    auto refused = [&](std::string_view record) {
        try {
            (void)ice::to_row(schema, json::parse(record));
        } catch (const ice::record_error& e) {
            BOOST_TEST_MESSAGE(e.what());
            return true;
        }
        return false;
    };
    BOOST_TEST(refused(R"({"i": 4294967296})"));
    BOOST_TEST(refused(R"({"ts": "2025-11-10T12:00:00Z"})"));  // timestamp without zone
    BOOST_TEST(refused(R"({"tz": "yesterday"})"));
    BOOST_TEST(refused(R"({"t": "25:00"})"));
    BOOST_TEST(refused(R"({"b": "not*base64"})"));
    BOOST_TEST(refused(R"({"u": "9c12d441"})"));
    BOOST_TEST(refused(R"([1,2])"));

    // Columns a channel cannot write are refused for the table, naming them.
    try {
        ice::check_columns(
            schema_of(R"J([{"id":1,"name":"price","required":false,"type":"decimal(9,2)"}])J"));
        BOOST_FAIL("decimal should be refused");
    } catch (const ice::table_error& e) {
        BOOST_TEST(std::string(e.what()).find("'price'") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(transforms_match_the_specification) {
    // The Iceberg specification's hash examples (Appendix B).
    BOOST_TEST(ice::detail::murmur3_32(ice::detail::le64(34)) == 2017239379);
    BOOST_TEST(ice::detail::murmur3_32("iceberg") == 1210000089);
    BOOST_TEST(ice::detail::murmur3_32(ice::detail::le64(17486)) == -653330422);  // 2017-11-16

    const auto schema = schema_of(R"([
        {"id":1,"name":"id","required":false,"type":"long"},
        {"id":2,"name":"ts","required":false,"type":"timestamptz"},
        {"id":3,"name":"d","required":false,"type":"date"},
        {"id":4,"name":"s","required":false,"type":"string"}])");
    const auto spec = json::array{
        json::object{
            {"name", "b"}, {"transform", "bucket[16]"}, {"source-id", 1}, {"field-id", 1000}},
        json::object{{"name", "h"}, {"transform", "hour"}, {"source-id", 2}, {"field-id", 1001}},
        json::object{{"name", "y"}, {"transform", "year"}, {"source-id", 3}, {"field-id", 1002}},
        json::object{{"name", "m"}, {"transform", "month"}, {"source-id", 2}, {"field-id", 1003}},
        json::object{{"name", "dd"}, {"transform", "day"}, {"source-id", 2}, {"field-id", 1004}},
        json::object{
            {"name", "t"}, {"transform", "truncate[3]"}, {"source-id", 4}, {"field-id", 1005}},
        json::object{
            {"name", "ti"}, {"transform", "truncate[10]"}, {"source-id", 1}, {"field-id", 1006}},
        json::object{{"name", "v"}, {"transform", "void"}, {"source-id", 1}, {"field-id", 1007}}};
    const auto t = ice::parse_metadata(metadata(schema, spec));
    const auto bound = ice::bind_spec(t);
    BOOST_REQUIRE(bound.size() == 8U);
    BOOST_TEST(bound[4]._result_type == "date");
    const auto row = ice::to_row(
        schema,
        json::parse(R"({"id":-34,"ts":"1969-12-31T23:30:00Z","d":"2017-11-16","s":"ičeberg"})"));
    std::vector<json::value> v;
    for (const auto& f : bound) {
        v.push_back(ice::partition_value(f, row));
    }
    const auto expected_bucket = (ice::detail::murmur3_32(ice::detail::le64(-34)) & INT32_MAX) % 16;
    BOOST_TEST(v[0].as_int64() == expected_bucket);
    BOOST_TEST(v[1].as_int64() == -1);  // the hour before the epoch
    BOOST_TEST(v[2].as_int64() == 47);  // 2017 - 1970
    BOOST_TEST(v[3].as_int64() == -1);  // December 1969
    BOOST_TEST(v[4].as_int64() == -1);
    BOOST_TEST(v[5] == "iče");  // code points, not bytes
    BOOST_TEST(v[6].as_int64() == -40);
    BOOST_TEST(v[7].is_null());
    BOOST_TEST(ice::partition_path({bound[5]}, json::array{v[5]}) == "t=i%C4%8De/");

    // Transforms a channel cannot apply fail the table.
    auto bad = metadata(
        schema, json::array{json::object{
                    {"name", "x"}, {"transform", "hour"}, {"source-id", 3}, {"field-id", 1000}}});
    BOOST_CHECK_THROW((void)ice::bind_spec(ice::parse_metadata(bad)), ice::table_error);
    bad = metadata(
        schema, json::array{json::object{
                    {"name", "x"}, {"transform", "zorder"}, {"source-id", 1}, {"field-id", 1000}}});
    BOOST_CHECK_THROW((void)ice::bind_spec(ice::parse_metadata(bad)), ice::table_error);
}

BOOST_AUTO_TEST_CASE(parent_manifest_lists_are_normalized) {
    // v1 names, as some writers still use for the counts.
    const json::object v1{{"manifest_path", "s3://b/m.avro"}, {"manifest_length", 10},
                          {"partition_spec_id", 0},           {"sequence_number", 3},
                          {"min_sequence_number", 2},         {"added_snapshot_id", 4},
                          {"added_data_files_count", 1},      {"existing_data_files_count", 2},
                          {"deleted_data_files_count", 0},    {"added_rows_count", 5},
                          {"existing_rows_count", 6},         {"deleted_rows_count", 0}};
    const auto n = ice::normalize_list_entry(v1).as_object();
    BOOST_TEST(n.at("added_files_count").as_int64() == 1);
    BOOST_TEST(n.at("existing_files_count").as_int64() == 2);
    BOOST_TEST(n.at("content").as_int64() == 0);
    BOOST_TEST(n.at("partitions").is_null());
    // It encodes under the v2 schema.
    BOOST_TEST(!avro::encode(ice::manifest_list_schema(), n).empty());

    auto missing = v1;
    missing.erase("sequence_number");
    BOOST_CHECK_THROW((void)ice::normalize_list_entry(missing), ice::table_error);
}

BOOST_AUTO_TEST_CASE(commit_requests_require_the_parent) {
    const auto schema = schema_of(R"([{"id":1,"name":"id","required":true,"type":"long"}])");
    const auto t = ice::parse_metadata(metadata(schema, json::array{}));
    const auto req = ice::commit_request(t, "events", "clicks",
                                         json::object{{"snapshot-id", 10}, {"sequence-number", 6}});
    BOOST_TEST(json::serialize(req.at("identifier")) ==
               R"({"namespace":["events"],"name":"clicks"})");
    const auto& reqs = req.at("requirements").as_array();
    BOOST_TEST(reqs[0].at("type") == "assert-table-uuid");
    BOOST_TEST(reqs[1].at("type") == "assert-ref-snapshot-id");
    BOOST_TEST(reqs[1].at("snapshot-id").as_int64() == 9);
    const auto& ups = req.at("updates").as_array();
    BOOST_TEST(ups[0].at("action") == "add-snapshot");
    BOOST_TEST(ups[1].at("action") == "set-snapshot-ref");
    BOOST_TEST(ups[1].at("snapshot-id").as_int64() == 10);
}

BOOST_AUTO_TEST_CASE(rest_client_against_s3_tables) {
    const std::string arn = "arn:aws:s3tables:us-east-1:111122223333:bucket/tables";
    std::vector<kin::aws_request> seen;
    kin::iceberg_rest_client client(
        kin::iceberg_rest_config{
            ._uri = "https://s3tables.us-east-1.amazonaws.com/iceberg",
            ._warehouse = arn,
            ._sigv4 = true,
            ._region = "us-east-1",
            ._signing_name = "s3tables",
            ._credentials =
                [] {
                    return kin::sigv4_credentials{._access_key_id = "AKID",
                                                  ._secret_access_key = "secret",
                                                  ._session_token = "tok",
                                                  ._expires_ms = 0};
                },
            ._token = {},
            ._clock = [] { return std::chrono::sys_seconds{std::chrono::seconds{1'795'089'600}}; }},
        [&](const kin::aws_endpoint& e,
            const kin::aws_request& r) -> std::optional<kin::peer_response> {
            BOOST_TEST(e._host == "s3tables.us-east-1.amazonaws.com");
            seen.push_back(r);
            if (r._path == "/iceberg/v1/config") {
                // S3 Tables names the ARN itself as the prefix.
                return kin::peer_response{
                    ._status = 200,
                    ._body = R"({"defaults":{},"overrides":{"prefix":")" + arn + R"("}})"};
            }
            return kin::peer_response{._status = 200, ._body = "{}"};
        });
    BOOST_REQUIRE(client.load_table("events", "clicks"));
    BOOST_REQUIRE(client.commit("events", "clicks", "{}"));
    BOOST_REQUIRE(seen.size() == 3U);  // the prefix is asked once
    BOOST_TEST(seen[0]._query ==
               "warehouse=arn%3Aaws%3As3tables%3Aus-east-1%3A111122223333%3Abucket%2Ftables");
    const std::string table_path =
        "/iceberg/v1/arn%3Aaws%3As3tables%3Aus-east-1%3A111122223333%3Abucket%2Ftables/namespaces/"
        "events/tables/clicks";
    BOOST_TEST(seen[1]._path == table_path);
    BOOST_TEST((seen[1]._method == boost::beast::http::verb::get));
    BOOST_TEST(seen[2]._path == table_path);
    BOOST_TEST((seen[2]._method == boost::beast::http::verb::post));

    // Every call verifies as SigV4 for s3tables.
    for (const auto& r : seen) {
        sv4::request req;
        const auto method = std::string(boost::beast::http::to_string(r._method));
        req.method = method;
        req.raw_path = r._path;
        req.raw_query = r._query;
        req.headers = r._headers;
        req.body = r._body;
        sv4::service_rules rules;
        rules.service = "s3tables";
        const auto c =
            sv4::parse(req, rules, std::chrono::sys_seconds{std::chrono::seconds{1'795'089'600}});
        BOOST_REQUIRE_MESSAGE(c.has_value(), c.error().message);
        BOOST_TEST(c->scope.service == "s3tables");
        BOOST_TEST(sv4::verify(*c, sv4::derive_signing_key("secret", c->scope)));
    }
}

BOOST_AUTO_TEST_CASE(rest_client_against_a_local_catalog) {
    std::vector<kin::aws_request> seen;
    bool config_answers = false;
    kin::iceberg_rest_client client(
        kin::iceberg_rest_config{._uri = "http://iceberg-rest:8181",
                                 ._warehouse = {},
                                 ._sigv4 = false,
                                 ._region = {},
                                 ._signing_name = "s3tables",
                                 ._credentials = {},
                                 ._token = "t0ken",
                                 ._clock = {}},
        [&](const kin::aws_endpoint&,
            const kin::aws_request& r) -> std::optional<kin::peer_response> {
            seen.push_back(r);
            if (r._path == "/v1/config") {
                if (!config_answers) {
                    return std::nullopt;
                }
                return kin::peer_response{._status = 200,
                                          ._body = R"({"defaults":{},"overrides":{}})"};
            }
            return kin::peer_response{
                ._status = 404,
                ._body =
                    R"({"error":{"message":"Table does not exist: ns.t","type":"NoSuchTableException","code":404}})"};
        });
    // No config answer: no call, and asked again next time.
    BOOST_TEST(!client.load_table("ns", "t"));
    config_answers = true;
    const auto r = client.load_table("ns", "t");
    BOOST_REQUIRE(r);
    BOOST_TEST(r->_status == 404U);
    BOOST_TEST(kin::iceberg_error_message(*r) ==
               "NoSuchTableException: Table does not exist: ns.t");
    BOOST_TEST(seen.back()._path == "/v1/namespaces/ns/tables/t");
    bool bearer = false;
    for (const auto& [k, v] : seen.back()._headers) {
        bearer = bearer || (k == "Authorization" && v == "Bearer t0ken");
    }
    BOOST_TEST(bearer);
    BOOST_TEST(kin::iceberg_error_message(kin::peer_response{
                   ._status = 502, ._body = "bad gateway"}) == "HTTP 502 bad gateway");
}

BOOST_AUTO_TEST_SUITE_END()
