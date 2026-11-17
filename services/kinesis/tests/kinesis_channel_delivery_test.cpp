// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Channel delivery to general purpose S3 (`.kiro/specs/kinesis-compatible-
// streams/` task 19, Requirement 18.2-18.3) over the in-process cluster and
// an in-memory object store: a batch is written once its oldest record is
// DataFreshnessInSeconds old and never again, records from before the
// channel are not delivered, the record formats and GZIP, JSON that does
// not parse goes to the dead-letter location, a reshard's parent is
// delivered before its children, a compression this build cannot write
// fails the channel, and deleting a channel drops its checkpoints.

#define BOOST_TEST_MODULE kinesis_channel_delivery_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_channel_delivery.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_hash.hpp>
#include <kythira/kinesis/kinesis_service.hpp>
#include <kythira/kinesis/kinesis_stream_state_machine.hpp>

#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <unistd.h>

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
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
constexpr std::string_view k_role = "arn:aws:iam::111122223333:role/channel-delivery";

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
                ("kinesis_channel_delivery_test." + std::to_string(::getpid()) + "." +
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

using service_t = kin::kinesis_service<kin::local_stream_cluster>;
using delivery_t = kin::channel_delivery<kin::local_stream_cluster, service_t>;
using bucket = std::map<std::string, std::string>;

struct fixture {
    // 2025-11-10T12:00:00Z.
    std::int64_t clock = 1'762'776'000'000;
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
    delivery_t delivery{cluster, service, delivery_config()};

    fixture() { service.register_with(fe); }

    static auto no_rates() -> kin::kinesis_service_config {
        kin::kinesis_service_config cfg;
        cfg._control_plane._rates.clear();
        return cfg;
    }

    auto delivery_config() -> kin::channel_delivery_config {
        kin::channel_delivery_config cfg;
        cfg._destination = [this](const std::string& name) -> std::optional<kin::tier_store> {
            kin::tier_store t;
            t._put = [this, name](const std::string& k, std::string_view b) {
                buckets[name][k] = std::string(b);
            };
            return t;
        };
        return cfg;
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

    auto on_demand(std::string_view name) -> void {
        (void)ok("CreateStream",
                 {{"StreamName", name}, {"StreamModeDetails", {{"StreamMode", "ON_DEMAND"}}}});
    }

    /// Puts `data` (raw bytes) under `key`; returns its shard id.
    auto put(std::string_view stream, std::string_view data, std::string_view key = "k")
        -> std::string {
        const auto r = ok("PutRecord", {{"StreamName", stream},
                                        {"PartitionKey", key},
                                        {"Data", kin::channel_detail::base64(data)}});
        return std::string(r.at("ShardId").as_string());
    }

    auto put_hashed(std::string_view stream, std::string_view data, const std::string& hash)
        -> std::string {
        const auto r = ok("PutRecord", {{"StreamName", stream},
                                        {"PartitionKey", "k"},
                                        {"ExplicitHashKey", hash},
                                        {"Data", kin::channel_detail::base64(data)}});
        return std::string(r.at("ShardId").as_string());
    }

    auto channel(std::string_view name, std::string_view stream, std::string_view format,
                 std::string_view compression, json::object extra_storage = {},
                 std::optional<json::object> dlq = std::nullopt) -> void {
        json::object storage{{"BucketARN", "arn:aws:s3:::delivered"},
                             {"ExpectedBucketOwner", k_account},
                             {"CompressionType", compression}};
        for (const auto& [k, v] : extra_storage) {
            storage[k] = v;
        }
        json::object dest{{"StorageConfiguration", storage}};
        if (dlq) {
            dest["DeadLetterQueueS3Configuration"] = *dlq;
        }
        const auto created =
            ok("CreateChannel",
               {{"ChannelName", name},
                {"ServiceExecutionRoleARN", k_role},
                {"StreamConfigurationList",
                 json::array{{{"StreamARN", stream_arn(stream)},
                              {"RecordConfiguration", {{"RecordFormatType", format}}}}}},
                {"S3DestinationConfiguration", dest}});
        arns[std::string(name)] =
            std::string(created.at("ChannelDescription").as_object().at("ChannelARN").as_string());
    }

    std::map<std::string, std::string> arns;

    auto status(std::string_view channel) -> std::string {
        const auto d = ok("DescribeChannel", {{"ChannelARN", arns.at(std::string(channel))}});
        return std::string(d.at("ChannelDescription").as_object().at("ChannelStatus").as_string());
    }

    auto advance_s(std::int64_t s) -> void { clock += s * 1000; }

    static auto stream_arn(std::string_view name) -> std::string {
        return "arn:aws:kinesis:us-east-1:" + std::string(k_account) + ":stream/" +
               std::string(name);
    }
};

auto lines(std::string_view body) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at < body.size()) {
        const auto nl = body.find('\n', at);
        out.emplace_back(body.substr(at, nl - at));
        at = nl == std::string_view::npos ? body.size() : nl + 1;
    }
    return out;
}

/// Every line of every object in `b`, in key order.
auto all_lines(const bucket& b) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& [k, v] : b) {
        for (auto& l : lines(v)) {
            out.push_back(std::move(l));
        }
    }
    return out;
}

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
auto gunzip(std::string_view in) -> std::string {
    z_stream z{};
    BOOST_REQUIRE(inflateInit2(&z, 15 + 16) == Z_OK);
    std::string out(in.size() * 20 + 64, '\0');
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT
    z.avail_in = static_cast<uInt>(in.size());
    z.next_out = reinterpret_cast<Bytef*>(out.data());
    z.avail_out = static_cast<uInt>(out.size());
    const auto rc = inflate(&z, Z_FINISH);
    const auto n = z.total_out;
    inflateEnd(&z);
    BOOST_REQUIRE(rc == Z_STREAM_END);
    out.resize(n);
    return out;
}
#endif

}  // namespace

BOOST_AUTO_TEST_SUITE(kinesis_channel_delivery)

BOOST_AUTO_TEST_CASE(template_and_helpers) {
    namespace cd = kin::channel_detail;
    BOOST_TEST(cd::bucket_of("arn:aws:s3:::delivered") == "delivered");
    BOOST_TEST(cd::base64("") == "");
    BOOST_TEST(cd::base64("f") == "Zg==");
    BOOST_TEST(cd::base64("fo") == "Zm8=");
    BOOST_TEST(cd::base64("foo") == "Zm9v");
    BOOST_TEST(cd::base64("foobar") == "Zm9vYmFy");
    // 2025-11-10T12:34:56Z.
    const std::int64_t at = 1'762'778'096'000;
    BOOST_TEST(cd::expand_template(cd::k_default_key_template, at, "c", "s", "shardId-1") ==
               "s/2025/11/10/12/");
    BOOST_TEST(cd::expand_template("x/!{kinesis:channel-name}/!{kinesis:shard-id}/"
                                   "!{timestamp:yyyy-MM-dd'T'HH:mm}/!{other}",
                                   at, "c", "s",
                                   "shardId-1") == "x/c/shardId-1/2025-11-10'T'12:34/!{other}");
    BOOST_TEST(cd::expand_template("open!{", at, "c", "s", "x") == "open!{");
    BOOST_TEST(cd::can_compress("NONE"));
    BOOST_TEST(!cd::can_compress("LZ4"));
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    BOOST_TEST(cd::can_compress("ZSTD"));
#else
    BOOST_TEST(!cd::can_compress("ZSTD"));
#endif
    BOOST_TEST(cd::extension_of("GZIP") == ".gz");
    BOOST_TEST(cd::extension_of("NONE") == "");
}

BOOST_AUTO_TEST_CASE(delivers_once_fresh_and_never_again) {
    fixture f;
    f.on_demand("s");
    (void)f.put("s", "before the channel");
    f.advance_s(1);
    f.channel("c", "s", "STRING", "NONE");
    f.advance_s(1);
    (void)f.put("s", "one");
    (void)f.put("s", "two");

    // Not yet DataFreshnessInSeconds (300) old.
    auto stats = f.delivery.run_once();
    BOOST_TEST(stats._objects == 0U);
    BOOST_TEST(f.buckets.empty());

    f.advance_s(300);
    stats = f.delivery.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(stats._records == 2U);
    BOOST_TEST(stats._checkpoints == 1U);
    BOOST_TEST(stats._failures == 0U);
    BOOST_REQUIRE(f.buckets.count("delivered") == 1U);
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 1U);
    const auto& [key, body] = *b.begin();
    // The default template, then channel, shard and the sequence range.
    BOOST_TEST(key.starts_with("s/2025/11/10/12/c-shardId-"));
    BOOST_TEST(body == "one\ntwo\n");

    // Nothing new: nothing written.
    f.advance_s(600);
    stats = f.delivery.run_once();
    BOOST_TEST(stats._objects == 0U);
    BOOST_TEST(b.size() == 1U);

    // A later record is its own object, from the checkpoint on.
    (void)f.put("s", "three");
    f.advance_s(300);
    stats = f.delivery.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(all_lines(b) == (std::vector<std::string>{"one", "two", "three"}));
}

BOOST_AUTO_TEST_CASE(size_limit_writes_before_freshness) {
    fixture f;
    f.on_demand("s");
    kin::channel_delivery_config cfg = f.delivery_config();
    cfg._max_object_bytes = 8;
    delivery_t small{f.cluster, f.service, cfg};
    f.channel("c", "s", "STRING", "NONE");
    f.advance_s(1);
    (void)f.put("s", "aaaa");
    (void)f.put("s", "bbbb");
    (void)f.put("s", "cccc");
    // A batch that reaches the limit (two 5-byte lines) is written at once.
    auto stats = small.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(stats._records == 2U);
    // The rest is under the limit and waits for freshness.
    stats = small.run_once();
    BOOST_TEST(stats._objects == 0U);
    f.advance_s(300);
    stats = small.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(all_lines(f.buckets.at("delivered")).size() == 3U);
}

BOOST_AUTO_TEST_CASE(byte_array_is_base64_and_key_template_applies) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "BYTE_ARRAY", "NONE",
              {{"OutputKeyTemplate", "raw/!{kinesis:channel-name}/!{timestamp:yyyy}/"}});
    f.advance_s(1);
    (void)f.put("s", std::string("\x00\x01\xff", 3));
    f.advance_s(300);
    (void)f.delivery.run_once();
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 1U);
    BOOST_TEST(b.begin()->first.starts_with("raw/c/2025/c-shardId-"));
    BOOST_TEST(b.begin()->second == "AAH/\n");
}

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
BOOST_AUTO_TEST_CASE(gzip_objects) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "GZIP");
    f.advance_s(1);
    (void)f.put("s", "zipped");
    f.advance_s(300);
    (void)f.delivery.run_once();
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 1U);
    BOOST_TEST(b.begin()->first.ends_with(".gz"));
    BOOST_TEST(gunzip(b.begin()->second) == "zipped\n");
}
#endif

#ifdef KYTHIRA_KINESIS_HAS_ZSTD
BOOST_AUTO_TEST_CASE(zstd_objects) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "ZSTD");
    f.advance_s(1);
    (void)f.put("s", "squeezed");
    f.advance_s(300);
    (void)f.delivery.run_once();
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 1U);
    BOOST_TEST(b.begin()->first.ends_with(".zst"));
    const auto& z = b.begin()->second;
    const auto n = ZSTD_getFrameContentSize(z.data(), z.size());
    BOOST_REQUIRE(n == 9U);
    std::string out(n, '\0');
    BOOST_TEST(ZSTD_decompress(out.data(), out.size(), z.data(), z.size()) == 9U);
    BOOST_TEST(out == "squeezed\n");
}
#endif

BOOST_AUTO_TEST_CASE(invalid_json_goes_to_the_dead_letter_location) {
    fixture f;
    f.on_demand("s");
    f.on_demand("t");
    f.channel("c", "s", "JSON", "NONE");
    f.channel("d", "t", "JSON", "NONE", {},
              json::object{{"BucketARN", "arn:aws:s3:::dead"},
                           {"ExpectedBucketOwner", k_account},
                           {"ErrorOutputPrefix", "bad/"}});
    f.advance_s(1);
    (void)f.put("s", R"({"ok":1})");
    (void)f.put("s", "{not json");
    (void)f.put("t", "nope");
    f.advance_s(300);
    const auto stats = f.delivery.run_once();
    BOOST_TEST(stats._records == 1U);
    BOOST_TEST(stats._dead_letters == 2U);

    // Without a dead-letter configuration: the destination under errors/.
    const auto& b = f.buckets.at("delivered");
    std::vector<std::string> good;
    std::vector<std::string> errors;
    for (const auto& [k, v] : b) {
        for (auto& l : lines(v)) {
            (k.starts_with("errors/") ? errors : good).push_back(std::move(l));
        }
    }
    BOOST_TEST(good == (std::vector<std::string>{R"({"ok":1})"}));
    BOOST_REQUIRE(errors.size() == 1U);
    const auto e = json::parse(errors[0]).as_object();
    BOOST_TEST(e.at("errorCode").as_string() == "InvalidJson");
    BOOST_TEST(e.at("rawData").as_string() == kin::channel_detail::base64("{not json"));
    BOOST_TEST(e.at("partitionKey").as_string() == "k");

    // With one: its bucket and prefix, and nothing good to write.
    BOOST_REQUIRE(f.buckets.count("dead") == 1U);
    const auto& dead = f.buckets.at("dead");
    BOOST_REQUIRE(dead.size() == 1U);
    BOOST_TEST(dead.begin()->first.starts_with("bad/d-shardId-"));
    BOOST_TEST(dead.begin()->first.ends_with(".json"));
    for (const auto& [k, v] : b) {
        BOOST_TEST(!k.starts_with("t/"));
    }
}

BOOST_AUTO_TEST_CASE(parent_before_children_across_a_split) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "NONE");
    f.advance_s(1);
    const std::string low = "1000";
    const auto parent = f.put_hashed("s", "p1", low);
    // Split the shard holding `low` (through provisioned mode, where the
    // resharding calls are allowed).
    (void)f.ok("UpdateStreamMode", {{"StreamARN", fixture::stream_arn("s")},
                                    {"StreamModeDetails", {{"StreamMode", "PROVISIONED"}}}});
    const auto desc = f.ok("DescribeStream", {{"StreamName", "s"}});
    std::string split_at;
    for (const auto& sh : desc.at("StreamDescription").as_object().at("Shards").as_array()) {
        const auto& o = sh.as_object();
        if (o.at("ShardId").as_string() == parent) {
            const auto& r = o.at("HashKeyRange").as_object();
            const auto start = kin::parse_hash_key(r.at("StartingHashKey").as_string());
            const auto end = kin::parse_hash_key(r.at("EndingHashKey").as_string());
            BOOST_REQUIRE(start && end);
            split_at = kin::to_decimal(*start + (*end - *start) / 2);
        }
    }
    BOOST_REQUIRE(!split_at.empty());
    (void)f.ok("SplitShard",
               {{"StreamName", "s"}, {"ShardToSplit", parent}, {"NewStartingHashKey", split_at}});
    const auto child = f.put_hashed("s", "c1", low);
    BOOST_REQUIRE(child != parent);

    // The closed parent is written at once (read to its end), and the child
    // only once the parent's checkpoint passed its end, both in one pass
    // here since the child is fresh enough after the advance.
    f.advance_s(300);
    const auto stats = f.delivery.run_once();
    BOOST_TEST(stats._failures == 0U);
    BOOST_TEST(stats._objects == 2U);
    const auto& b = f.buckets.at("delivered");
    std::string parent_body;
    std::string child_body;
    for (const auto& [k, v] : b) {
        if (k.find("c-" + parent + "-") != std::string::npos) {
            parent_body = v;
        } else if (k.find("c-" + child + "-") != std::string::npos) {
            child_body = v;
        }
    }
    BOOST_TEST(parent_body == "p1\n");
    BOOST_TEST(child_body == "c1\n");
}

BOOST_AUTO_TEST_CASE(child_waits_for_its_parent) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "NONE");
    f.advance_s(1);
    const std::string low = "1000";
    const auto parent = f.put_hashed("s", "p1", low);
    (void)f.ok("UpdateStreamMode", {{"StreamARN", fixture::stream_arn("s")},
                                    {"StreamModeDetails", {{"StreamMode", "PROVISIONED"}}}});
    const auto desc = f.ok("DescribeStream", {{"StreamName", "s"}});
    std::string split_at;
    for (const auto& sh : desc.at("StreamDescription").as_object().at("Shards").as_array()) {
        const auto& o = sh.as_object();
        if (o.at("ShardId").as_string() == parent) {
            const auto& r = o.at("HashKeyRange").as_object();
            const auto start = kin::parse_hash_key(r.at("StartingHashKey").as_string());
            const auto end = kin::parse_hash_key(r.at("EndingHashKey").as_string());
            split_at = kin::to_decimal(*start + (*end - *start) / 2);
        }
    }
    (void)f.ok("SplitShard",
               {{"StreamName", "s"}, {"ShardToSplit", parent}, {"NewStartingHashKey", split_at}});
    (void)f.put_hashed("s", "c1", low);

    // The parent cannot be delivered: the destination is unreachable.
    kin::channel_delivery_config cfg;
    cfg._destination = [](const std::string&) -> std::optional<kin::tier_store> {
        return std::nullopt;
    };
    delivery_t blocked{f.cluster, f.service, cfg};
    f.advance_s(300);
    const auto stats = blocked.run_once();
    BOOST_TEST(stats._objects == 0U);
    BOOST_TEST(stats._checkpoints == 0U);
    // The parent failed; the child was not tried.
    BOOST_TEST(stats._failures == 1U);
}

BOOST_AUTO_TEST_CASE(unsupported_compression_fails_the_channel) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "ZSTD");
    BOOST_TEST(f.status("c") == "ACTIVE");
    // As a node built without libzstd sees it.
    auto cfg = f.delivery_config();
    cfg._can_compress = [](std::string_view c) { return c == "NONE"; };
    delivery_t without{f.cluster, f.service, cfg};
    const auto stats = without.run_once();
    BOOST_TEST(stats._failed_channels == 1U);
    BOOST_TEST(f.status("c") == "FAILED");
    const auto d = f.ok("DescribeChannel", {{"ChannelARN", f.arns.at("c")}});
    BOOST_TEST(
        std::string(d.at("ChannelDescription").as_object().at("ChannelStatusReason").as_string())
            .find("ZSTD") != std::string::npos);
    // A FAILED channel is not delivered again.
    BOOST_TEST(without.run_once()._failed_channels == 0U);
    BOOST_TEST(f.buckets.empty());
}

BOOST_AUTO_TEST_CASE(checkpoints_are_compare_and_set_and_dropped_with_the_channel) {
    fixture f;
    f.on_demand("s");
    f.channel("c", "s", "STRING", "NONE");
    f.advance_s(1);
    const auto shard = f.put("s", "one");
    f.advance_s(300);
    BOOST_TEST(f.delivery.run_once()._checkpoints == 1U);

    std::optional<kin::channel_record> rec;
    (void)f.cluster.read(kin::next_id_key(), [&](const auto& sm) {
        if (const auto* c = sm.find_channel(std::string(k_account), "c")) {
            rec = *c;
        }
    });
    BOOST_REQUIRE(rec.has_value());
    const auto stream_id = rec->_streams.at(0)._stream_id;
    const auto ordinal = kin::parse_shard_id(shard);
    BOOST_REQUIRE(ordinal.has_value());
    const auto key = kin::routing_key(stream_id, *ordinal);
    auto at = [&] {
        std::uint64_t v = 0;
        (void)f.cluster.read(kin::next_id_key(), [&](const auto& sm) {
            v = sm.channel_checkpoint(std::string(k_account), rec->_id, key);
        });
        return v;
    };
    const auto first = at();
    BOOST_TEST(first > 0U);

    // A move from a stale position is refused.
    const kin::stream_command stale =
        kin::channel_checkpoint_command{._account = std::string(k_account),
                                        ._channel = "c",
                                        ._channel_id = rec->_id,
                                        ._shard = key,
                                        ._expected = 0,
                                        ._next = first + 10};
    const auto r = f.cluster.propose(kin::command_key(stale), kin::encode_command(stale),
                                     kin::admission::none);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((r->_status != kin::apply_status::ok));
    BOOST_TEST(at() == first);

    (void)f.ok("DeleteChannel", {{"ChannelARN", f.arns.at("c")}});
    BOOST_TEST(at() == 0U);
}

BOOST_AUTO_TEST_SUITE_END()
