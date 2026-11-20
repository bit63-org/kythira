// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 19, Requirement 18.4: a channel's EncryptionConfiguration. Delivered
// objects are sealed under a data key from the node's key provider (local,
// AWS KMS and Kythira's KMS, each through the same delivery worker), asked
// for as the channel's execution role, or written plaintext with SSE-KMS
// asked of S3; S3 Tables channels always ask for SSE-KMS.

#define BOOST_TEST_MODULE kinesis_channel_encryption_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_channel_delivery.hpp>
#include <kythira/kinesis/kinesis_channels.hpp>
#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_kms_aws.hpp>
#include <kythira/kinesis/kinesis_kms_kythira.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include <raft/module_interfaces.hpp>
#include <raft/record_segment_store.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <unistd.h>

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
#include <zlib.h>
#endif

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sn = kythira::service_node;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;
namespace cd = kin::channel_detail;

namespace {

constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_role = "arn:aws:iam::111122223333:role/channel-delivery";
constexpr std::string_view k_key = "alias/channel-key";
const std::string k_key_arn = "arn:aws:kms:us-east-1:111122223333:key/k1";
/// The session the channel's KMS calls are made as: a fixture's first
/// channel takes id 2 from the counter its stream took 1 from.
const std::string k_session_arn =
    "arn:aws:sts::111122223333:assumed-role/channel-delivery/kinesis-channel-2";

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
                ("kinesis_channel_encryption_test." + std::to_string(::getpid()) + "." +
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
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

/// One KMS behind both fake transports: data keys "wrapped" as a JSON blob
/// that names the key and context, so Decrypt checks both; every call
/// recorded with the principal it was made for.
struct fake_kms_core {
    struct seen {
        std::string op;
        std::string principal;
        std::string via;
    };
    std::mutex mu;
    std::vector<seen> calls;
    /// Principals refused (AccessDeniedException).
    std::set<std::string> denied;

    auto count(std::string_view op) -> std::size_t {
        const std::scoped_lock lock(mu);
        std::size_t n = 0;
        for (const auto& c : calls) {
            n += c.op == op ? 1U : 0U;
        }
        return n;
    }

    /// The HTTP status and JSON answer to `op` with request `body`.
    auto answer(const std::string& op, const std::string& body, const std::string& principal,
                const std::string& via) -> std::pair<int, std::string> {
        const std::scoped_lock lock(mu);
        calls.push_back({op, principal, via});
        if (denied.contains(principal)) {
            return {400, R"({"__type":"AccessDeniedException","message":"not allowed"})"};
        }
        const auto in = json::parse(body).as_object();
        const auto key = std::string(in.at("KeyId").as_string());
        if (key != k_key_arn && key != k_key) {
            return {400, R"({"__type":"NotFoundException","message":"no such key"})"};
        }
        const auto context = in.contains("EncryptionContext")
                                 ? json::serialize(in.at("EncryptionContext"))
                                 : std::string("{}");
        if (op == "GenerateDataKey") {
            std::array<unsigned char, 32> k{};
            BOOST_REQUIRE(RAND_bytes(k.data(), static_cast<int>(k.size())) == 1);
            const std::string plain(reinterpret_cast<const char*>(k.data()), k.size());
            const auto blob = json::serialize(
                json::object{{"k", k_key_arn}, {"c", context}, {"p", cd::base64(plain)}});
            return {200, json::serialize(json::object{{"KeyId", k_key_arn},
                                                      {"Plaintext", cd::base64(plain)},
                                                      {"CiphertextBlob", cd::base64(blob)}})};
        }
        if (op == "Decrypt") {
            const auto blob = cd::unbase64(in.at("CiphertextBlob").as_string()).value();
            const auto b = json::parse(blob).as_object();
            if (b.at("c").as_string() != context) {
                return {400, R"({"__type":"InvalidCiphertextException","message":"context"})"};
            }
            return {200,
                    json::serialize(json::object{{"KeyId", b.at("k")}, {"Plaintext", b.at("p")}})};
        }
        return {400, R"({"__type":"UnsupportedOperationException"})"};
    }
};

/// The fake as Kythira's KMS module's client (`KINESIS_KMS=kythira`).
class fake_kms_endpoint final : public sn::kms_endpoint {
public:
    explicit fake_kms_endpoint(std::shared_ptr<fake_kms_core> core) : _core(std::move(core)) {}
    auto call(const sn::caller& /*who*/, const sn::kms_request& r)
        -> sn::aws_json_response override {
        const auto [status, body] =
            _core->answer(r.operation, r.body, r.principal.arn, r.via_service);
        return {status, body};
    }

private:
    std::shared_ptr<fake_kms_core> _core;
};

/// The provider a test runs with, and the KMS behind it (none for local).
struct provider_case {
    std::string _name;
    kin::key_provider _kms;
    std::shared_ptr<fake_kms_core> _core;
};

auto local_case() -> provider_case {
    return {"local", kin::key_provider(kin::local_kms_provider("channel-test-passphrase")), {}};
}

auto aws_case() -> provider_case {
    auto core = std::make_shared<fake_kms_core>();
    kin::aws_kms_config cfg;
    cfg._region = "us-east-1";
    cfg._credentials = [] { return kin::aws_kms_credentials{"AKIDEXAMPLE", "secret", ""}; };
    kin::aws_kms_provider p(cfg,
                            [core](const std::string&, const kin::peer_client::headers& headers,
                                   std::string body) -> std::optional<kin::peer_response> {
                                std::string target;
                                for (const auto& [k, v] : headers) {
                                    if (k == "x-amz-target") {
                                        target = v;
                                    }
                                }
                                const auto op = target.substr(target.find('.') + 1);
                                // The gateway's own credentials: AWS KMS sees no end caller.
                                const auto [status, out] = core->answer(op, body, "gateway", "");
                                return kin::peer_response{._status = static_cast<unsigned>(status),
                                                          ._body = out};
                            });
    return {"aws", kin::key_provider(std::move(p)), core};
}

auto kythira_case() -> provider_case {
    auto core = std::make_shared<fake_kms_core>();
    auto endpoint = std::make_shared<fake_kms_endpoint>(core);
    return {"kythira",
            kin::key_provider(kin::kythira_kms_provider(
                [endpoint]() -> std::shared_ptr<sn::kms_endpoint> { return endpoint; })),
            core};
}

using service_t = kin::kinesis_service<kin::local_stream_cluster>;
using delivery_t = kin::channel_delivery<kin::local_stream_cluster, service_t>;

struct written {
    std::string _body;
    kin::channel_put_options _options;
};
using bucket = std::map<std::string, written>;

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
    std::map<std::string, std::string> arns;

    fixture() { service.register_with(fe); }

    static auto no_rates() -> kin::kinesis_service_config {
        kin::kinesis_service_config cfg;
        cfg._control_plane._rates.clear();
        return cfg;
    }

    auto config(kin::key_provider kms,
                kin::channel_encryption mode = kin::channel_encryption::envelope)
        -> kin::channel_delivery_config {
        kin::channel_delivery_config cfg;
        cfg._destination = [this](
                               const std::string& name,
                               const kin::channel_access&) -> std::optional<kin::channel_bucket> {
            kin::channel_bucket t;
            t._put = [this, name](const std::string& k, std::string_view b,
                                  const kin::channel_put_options& o) {
                buckets[name][k] = written{._body = std::string(b), ._options = o};
            };
            return t;
        };
        cfg._encryption = mode;
        cfg._kms = std::move(kms);
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

    auto put(std::string_view stream, std::string_view data) -> void {
        (void)ok("PutRecord",
                 {{"StreamName", stream}, {"PartitionKey", "k"}, {"Data", cd::base64(data)}});
    }

    /// An S3 channel on `stream`, encrypted under `key` unless it is empty.
    auto channel(std::string_view name, std::string_view stream, std::string_view format,
                 std::string_view compression, std::string_view key) -> void {
        json::object in{
            {"ChannelName", name},
            {"ServiceExecutionRoleARN", k_role},
            {"StreamConfigurationList",
             json::array{{{"StreamARN", "arn:aws:kinesis:us-east-1:" + std::string(k_account) +
                                            ":stream/" + std::string(stream)},
                          {"RecordConfiguration", {{"RecordFormatType", format}}}}}},
            {"S3DestinationConfiguration",
             {{"StorageConfiguration",
               {{"BucketARN", "arn:aws:s3:::delivered"},
                {"ExpectedBucketOwner", k_account},
                {"CompressionType", compression}}}}}};
        if (!key.empty()) {
            in["EncryptionConfiguration"] = {{"EncryptionType", "KMS"}, {"KeyId", key}};
        }
        const auto created = ok("CreateChannel", in);
        arns[std::string(name)] =
            std::string(created.at("ChannelDescription").as_object().at("ChannelARN").as_string());
    }

    auto describe(std::string_view channel) -> json::object {
        return ok("DescribeChannel", {{"ChannelARN", arns.at(std::string(channel))}})
            .at("ChannelDescription")
            .as_object();
    }

    auto advance_s(std::int64_t s) -> void { clock += s * 1000; }
};

/// The objects of `b` whose key contains `part`.
auto objects_with(const bucket& b, std::string_view part) -> std::vector<const written*> {
    std::vector<const written*> out;
    for (const auto& [k, w] : b) {
        if (k.find(part) != std::string::npos) {
            out.push_back(&w);
        }
    }
    return out;
}

/// The channel role's session, as the KMS sees it.
auto channel_caller(const az::principal_context& p) -> kin::kms_caller {
    return kin::kms_caller{._principal = &p};
}

auto channel_session() -> az::principal_context {
    kin::channel_record c;
    c._id = 2;
    c._account = std::string(k_account);
    c._role_arn = std::string(k_role);
    return cd::channel_principal(c);
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

BOOST_AUTO_TEST_SUITE(kinesis_channel_encryption)

BOOST_AUTO_TEST_CASE(base64_round_trips) {
    for (const std::string_view s : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        BOOST_TEST(cd::unbase64(cd::base64(s)).value_or("<none>") == s);
    }
    std::string all;
    for (int i = 0; i < 256; ++i) {
        all.push_back(static_cast<char>(i));
    }
    BOOST_TEST(cd::unbase64(cd::base64(all)).value_or("") == all);
    BOOST_TEST(!cd::unbase64("Zm9").has_value());
    BOOST_TEST(!cd::unbase64("Zm=v").has_value());
    BOOST_TEST(!cd::unbase64("Zm9v!A==").has_value());
}

BOOST_AUTO_TEST_CASE(the_key_comes_from_the_encryption_configuration) {
    kin::channel_record c;
    BOOST_TEST(!cd::channel_key_id(c).has_value());
    c._encryption_config = R"({"EncryptionType":"KMS","KeyId":"alias/k"})";
    BOOST_TEST(cd::channel_key_id(c).value_or("") == "alias/k");
    c._encryption_config = R"({"EncryptionType":"NONE","KeyId":"alias/k"})";
    BOOST_TEST(!cd::channel_key_id(c).has_value());
    c._id = 0x2a;
    const auto ctx = cd::object_context(c);
    BOOST_TEST(ctx.at("aws:x-amz-cek-alg") == "AES/GCM/NoPadding");
    BOOST_TEST(ctx.at("kinesis:channel-id") == kin::channel_id_text(0x2a));
}

// The S3 Encryption Client's v2 layout, and what does not open.
BOOST_AUTO_TEST_CASE(sealed_objects_open_only_whole_and_under_their_context) {
    const auto p = local_case();
    kin::channel_record c;
    c._id = 7;
    const auto context = cd::object_context(c);
    const auto key = p._kms.generate_data_key("alias/k", context);
    const auto sealed = cd::seal_object(key, context, "one\ntwo\n");
    BOOST_TEST(sealed._body.size() == 8U + 16U);
    BOOST_TEST(sealed._body.find("one") == std::string::npos);
    const auto& m = sealed._metadata;
    BOOST_TEST(m.at("x-amz-cek-alg") == "AES/GCM/NoPadding");
    BOOST_TEST(m.at("x-amz-wrap-alg") == "kms+context");
    BOOST_TEST(m.at("x-amz-tag-len") == "128");
    BOOST_TEST(m.at("x-amz-unencrypted-content-length") == "8");
    BOOST_TEST(cd::unbase64(m.at("x-amz-iv")).value().size() == 12U);
    BOOST_TEST(cd::unbase64(m.at("x-amz-key-v2")).value() == key._wrapped);
    BOOST_TEST(m.at("kythira-kms-key-id") == "alias/k");
    BOOST_TEST(
        json::parse(m.at("x-amz-matdesc")).as_object().at("kinesis:channel-id").as_string() ==
        kin::channel_id_text(7));

    BOOST_TEST(cd::open_object(p._kms, m, sealed._body) == "one\ntwo\n");

    // S3 hands metadata back with its names in any case.
    std::map<std::string, std::string> upper;
    for (const auto& [k, v] : m) {
        std::string u(k);
        for (auto& ch : u) {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }
        upper[u] = v;
    }
    BOOST_TEST(cd::open_object(p._kms, upper, sealed._body) == "one\ntwo\n");

    auto flipped = sealed._body;
    flipped[0] = static_cast<char>(flipped[0] ^ 1);
    BOOST_CHECK_THROW((void)cd::open_object(p._kms, m, flipped), kin::record_open_error);

    // Another channel's context: the data key does not unwrap.
    auto moved = m;
    moved["x-amz-matdesc"] =
        R"({"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kinesis:channel-id":"other"})";
    BOOST_CHECK_THROW((void)cd::open_object(p._kms, moved, sealed._body), kin::kms_error);

    auto missing = m;
    missing.erase("x-amz-iv");
    BOOST_CHECK_THROW((void)cd::open_object(p._kms, missing, sealed._body), kin::record_open_error);

    // A second seal under the same key takes a fresh nonce.
    const auto again = cd::seal_object(key, context, "one\ntwo\n");
    BOOST_TEST(again._metadata.at("x-amz-iv") != m.at("x-amz-iv"));
    BOOST_TEST(again._body != sealed._body);
}

// The same delivery through each provider: objects and dead letters are
// sealed, nothing in them is plaintext, they open through the provider, and
// a per-caller KMS is asked as the channel's execution role through Kinesis.
BOOST_AUTO_TEST_CASE(every_provider_seals_objects_and_dead_letters) {
    for (const auto& p : {local_case(), aws_case(), kythira_case()}) {
        BOOST_TEST_CONTEXT("provider " << p._name) {
            fixture f;
            delivery_t delivery{f.cluster, f.service, f.config(p._kms)};
            f.on_demand("s");
            f.channel("c", "s", "JSON", "NONE", k_key);
            f.advance_s(1);
            f.put("s", R"({"n":1})");
            f.put("s", "not json");
            f.put("s", R"({"n":2})");
            f.advance_s(300);
            const auto stats = delivery.run_once();
            BOOST_TEST(stats._failures == 0U, stats._last_failure);
            BOOST_TEST(stats._objects == 1U);
            BOOST_TEST(stats._dead_letters == 1U);
            BOOST_TEST(stats._checkpoints == 1U);

            const auto& b = f.buckets.at("delivered");
            const auto session = channel_session();
            const auto objects = objects_with(b, "/c-shardId-");
            BOOST_REQUIRE(objects.size() == 2U);  // the records and errors/
            for (const auto* w : objects) {
                BOOST_TEST(w->_body.find("\"n\"") == std::string::npos);
                BOOST_TEST(w->_body.find("not json") == std::string::npos);
                BOOST_TEST(!w->_options._sse_kms_key_id.has_value());
                BOOST_TEST(w->_options._metadata.at("x-amz-wrap-alg") == "kms+context");
            }
            const auto records = objects_with(b, "s/2025/");
            BOOST_REQUIRE(records.size() == 1U);
            BOOST_TEST(cd::open_object(p._kms, records[0]->_options._metadata, records[0]->_body,
                                       channel_caller(session)) == "{\"n\":1}\n{\"n\":2}\n");
            const auto dead = objects_with(b, "errors/");
            BOOST_REQUIRE(dead.size() == 1U);
            const auto line = cd::open_object(p._kms, dead[0]->_options._metadata, dead[0]->_body,
                                              channel_caller(session));
            BOOST_TEST(json::parse(line).as_object().at("rawData").as_string() ==
                       cd::base64("not json"));

            if (p._core) {
                // One data key for both objects of the batch.
                BOOST_TEST(p._core->count("GenerateDataKey") == 1U);
            }
            if (p._name == "kythira") {
                const std::scoped_lock lock(p._core->mu);
                const auto& first = p._core->calls.front();
                BOOST_TEST(first.op == "GenerateDataKey");
                BOOST_TEST(first.principal == k_session_arn);
                BOOST_TEST(first.via == "kinesis");
            }
        }
    }
}

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
// Compression first, then encryption: the sealed bytes are the gzip file.
BOOST_AUTO_TEST_CASE(compressed_objects_are_sealed_after_compression) {
    const auto p = local_case();
    fixture f;
    delivery_t delivery{f.cluster, f.service, f.config(p._kms)};
    f.on_demand("s");
    f.channel("c", "s", "STRING", "GZIP", k_key);
    f.advance_s(1);
    f.put("s", "alpha");
    f.put("s", "beta");
    f.advance_s(300);
    BOOST_TEST(delivery.run_once()._objects == 1U);
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 1U);
    BOOST_TEST(b.begin()->first.ends_with(".gz"));
    const auto& w = b.begin()->second;
    const auto opened = cd::open_object(p._kms, w._options._metadata, w._body);
    BOOST_TEST(gunzip(opened) == "alpha\nbeta\n");
}
#endif

// A data key seals the channel's objects for the reuse window, then the
// provider is asked for another; 0 asks for one per object.
BOOST_AUTO_TEST_CASE(data_keys_are_reused_for_the_window) {
    auto p = aws_case();
    fixture f;
    delivery_t delivery{f.cluster, f.service, f.config(p._kms)};
    f.on_demand("s");
    f.channel("c", "s", "STRING", "NONE", k_key);
    std::set<std::string> wrapped;
    const auto deliver = [&](std::string_view data) {
        f.advance_s(1);
        f.put("s", data);
        f.advance_s(100);
        (void)delivery.run_once();
        f.advance_s(200);
        BOOST_TEST(delivery.run_once()._objects == 1U);
    };
    deliver("one");
    BOOST_TEST(p._core->count("GenerateDataKey") == 1U);
    // 301 s later the key is past its five minutes.
    deliver("two");
    BOOST_TEST(p._core->count("GenerateDataKey") == 2U);
    for (const auto& [k, w] : f.buckets.at("delivered")) {
        wrapped.insert(w._options._metadata.at("x-amz-key-v2"));
    }
    BOOST_TEST(wrapped.size() == 2U);

    // Inside the window: one key for several objects.
    auto q = aws_case();
    fixture g;
    auto cfg = g.config(q._kms);
    cfg._max_object_bytes = 4;
    delivery_t quick{g.cluster, g.service, cfg};
    g.on_demand("s");
    g.channel("c", "s", "STRING", "NONE", k_key);
    g.advance_s(1);
    g.put("s", "aaaa");
    BOOST_TEST(quick.run_once()._objects == 1U);
    g.advance_s(10);
    g.put("s", "bbbb");
    BOOST_TEST(quick.run_once()._objects == 1U);
    BOOST_TEST(q._core->count("GenerateDataKey") == 1U);

    auto r = aws_case();
    fixture h;
    auto per_object = h.config(r._kms);
    per_object._max_object_bytes = 4;
    per_object._data_key_reuse_ms = 0;
    delivery_t fresh{h.cluster, h.service, per_object};
    h.on_demand("s");
    h.channel("c", "s", "STRING", "NONE", k_key);
    h.advance_s(1);
    h.put("s", "aaaa");
    BOOST_TEST(fresh.run_once()._objects == 1U);
    h.put("s", "bbbb");
    BOOST_TEST(fresh.run_once()._objects == 1U);
    BOOST_TEST(r._core->count("GenerateDataKey") == 2U);
}

// A refused data key holds the batch back, with the KMS's reason; once the
// role may use the key the same records are delivered.
BOOST_AUTO_TEST_CASE(a_refused_key_holds_delivery_until_it_is_allowed) {
    auto p = kythira_case();
    p._core->denied.insert(k_session_arn);
    fixture f;
    delivery_t delivery{f.cluster, f.service, f.config(p._kms)};
    f.on_demand("s");
    f.channel("c", "s", "STRING", "NONE", k_key);
    f.advance_s(1);
    f.put("s", "held");
    f.advance_s(300);
    auto stats = delivery.run_once();
    BOOST_TEST(stats._objects == 0U);
    BOOST_TEST(stats._checkpoints == 0U);
    BOOST_TEST(stats._failures == 1U);
    BOOST_TEST(stats._last_failure.find("alias/channel-key") != std::string::npos,
               stats._last_failure);
    BOOST_TEST(f.buckets.empty());
    BOOST_TEST(std::string(f.describe("c").at("ChannelStatus").as_string()) == "ACTIVE");

    p._core->denied.clear();
    stats = delivery.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(stats._checkpoints == 1U);
    const auto& w = f.buckets.at("delivered").begin()->second;
    const auto session = channel_session();
    BOOST_TEST(cd::open_object(p._kms, w._options._metadata, w._body, channel_caller(session)) ==
               "held\n");
}

// Envelope encryption with no provider never writes plaintext: the channel
// is set to FAILED, saying what is missing.
BOOST_AUTO_TEST_CASE(no_provider_fails_an_encrypted_channel) {
    fixture f;
    delivery_t delivery{f.cluster, f.service, f.config({})};
    f.on_demand("s");
    f.channel("plain", "s", "STRING", "NONE", "");
    f.channel("c", "s", "STRING", "NONE", k_key);
    f.advance_s(1);
    f.put("s", "secret");
    f.advance_s(300);
    const auto stats = delivery.run_once();
    BOOST_TEST(stats._failed_channels == 1U);
    BOOST_TEST(stats._objects == 1U);  // the unencrypted channel's
    const auto d = f.describe("c");
    BOOST_TEST(std::string(d.at("ChannelStatus").as_string()) == "FAILED");
    BOOST_TEST(objects_with(f.buckets.at("delivered"), "/c-shardId-").empty());
    const auto plain = objects_with(f.buckets.at("delivered"), "/plain-shardId-");
    BOOST_REQUIRE(plain.size() == 1U);
    BOOST_TEST(plain[0]->_body == "secret\n");
    BOOST_TEST(plain[0]->_options._metadata.empty());
    BOOST_TEST(!plain[0]->_options._sse_kms_key_id.has_value());
}

// KINESIS_CHANNEL_ENCRYPTION=sse-kms: plaintext to the store with SSE-KMS
// asked under the channel's key, dead letters too; no provider needed.
BOOST_AUTO_TEST_CASE(sse_kms_asks_the_store_to_encrypt) {
    fixture f;
    delivery_t delivery{f.cluster, f.service, f.config({}, kin::channel_encryption::sse_kms)};
    f.on_demand("s");
    f.channel("c", "s", "JSON", "NONE", k_key);
    f.advance_s(1);
    f.put("s", R"({"n":1})");
    f.put("s", "bad");
    f.advance_s(300);
    const auto stats = delivery.run_once();
    BOOST_TEST(stats._objects == 1U);
    BOOST_TEST(stats._dead_letters == 1U);
    const auto& b = f.buckets.at("delivered");
    BOOST_REQUIRE(b.size() == 2U);
    for (const auto& [k, w] : b) {
        BOOST_TEST(w._options._sse_kms_key_id.value_or("") == k_key, k);
        BOOST_TEST(w._options._metadata.empty());
    }
    BOOST_TEST(objects_with(b, "s/2025/")[0]->_body == "{\"n\":1}\n");
}

BOOST_AUTO_TEST_SUITE_END()
