// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// `KINESIS_KMS=kythira` (`.kiro/specs/kms-compatible-api/` task 15,
// Requirements 11.1, 11.4, 11.6 and 11.8), against a fake `kms.client`
// that keeps per-principal permissions: every KMS call carries the Kinesis
// request's own caller and kms:ViaService kinesis; producers need only
// GenerateDataKey and consumers only Decrypt; a key another caller
// unwrapped proves nothing about the next one; an answer stands for the
// caller TTL, so a disabled key stops writes and reads within it; and a
// gateway that holds no data key adds one generation, not one per write.
//
// The KMS itself, with IAM and key policies, is exercised end to end in
// the node tests; this one has no KMS headers (module boundaries).

#define BOOST_TEST_MODULE kinesis_kms_kythira_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_cluster.hpp>
#include <kythira/kinesis/kinesis_front_end.hpp>
#include <kythira/kinesis/kinesis_kms.hpp>
#include <kythira/kinesis/kinesis_kms_kythira.hpp>
#include <kythira/kinesis/kinesis_service.hpp>

#include <raft/module_interfaces.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <openssl/rand.h>

#include <unistd.h>

#include <array>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace aj = kythira::aws_json;
namespace az = kythira::aws_auth;
namespace sn = kythira::service_node;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

constexpr std::string_view k_account = "111122223333";
const std::string k_key_arn = "arn:aws:kms:us-east-1:111122223333:key/k1";

auto arn_of(std::string_view user) -> std::string {
    return "arn:aws:iam::" + std::string(k_account) + ":user/" + std::string(user);
}

/// A KMS with one key (`alias/s` names it) and per-principal permissions.
class fake_kms final : public sn::kms_endpoint {
public:
    struct seen {
        std::string op;
        std::string principal;
        std::string via;
    };

    std::mutex mu;
    std::map<std::string, std::set<std::string>> allowed;  // principal ARN -> operations
    bool enabled = true;
    std::vector<seen> calls;

    void allow(std::string_view user, std::set<std::string> ops) { allowed[arn_of(user)] = ops; }

    [[nodiscard]] auto count(std::string_view op) -> std::size_t {
        const std::scoped_lock lock(mu);
        std::size_t n = 0;
        for (const auto& c : calls) {
            n += c.op == op ? 1U : 0U;
        }
        return n;
    }

    auto call(const sn::caller& /*who*/, const sn::kms_request& r)
        -> sn::aws_json_response override {
        const std::scoped_lock lock(mu);
        calls.push_back({r.operation, r.principal.arn, r.via_service});
        const auto in = json::parse(r.body).as_object();
        const auto key = std::string(in.at("KeyId").as_string());
        if (key != k_key_arn && key != "alias/s") {
            return refuse(400, "NotFoundException", "no such key");
        }
        const auto it = allowed.find(r.principal.arn);
        if (it == allowed.end() || !it->second.contains(r.operation)) {
            return refuse(400, "AccessDeniedException", r.principal.arn + " may not");
        }
        if (!enabled) {
            return refuse(400, "DisabledException", "disabled");
        }
        const auto context = in.contains("EncryptionContext")
                                 ? json::serialize(in.at("EncryptionContext"))
                                 : std::string("{}");
        if (r.operation == "GenerateDataKey") {
            std::array<unsigned char, 32> k{};
            BOOST_REQUIRE(RAND_bytes(k.data(), static_cast<int>(k.size())) == 1);
            const std::string plain(reinterpret_cast<const char*>(k.data()), k.size());
            const auto blob =
                json::serialize(json::object{{"k", k_key_arn},
                                             {"c", context},
                                             {"p", kin::kms_aws_detail::base64_encode(plain)}});
            return {200, json::serialize(json::object{
                             {"KeyId", k_key_arn},
                             {"Plaintext", kin::kms_aws_detail::base64_encode(plain)},
                             {"CiphertextBlob", kin::kms_aws_detail::base64_encode(blob)}})};
        }
        if (r.operation == "Decrypt") {
            const auto blob =
                kin::kms_aws_detail::base64_decode(in.at("CiphertextBlob").as_string()).value();
            const auto b = json::parse(blob).as_object();
            if (b.at("c").as_string() != context) {
                return refuse(400, "InvalidCiphertextException", "wrong context");
            }
            return {200,
                    json::serialize(json::object{{"KeyId", b.at("k")}, {"Plaintext", b.at("p")}})};
        }
        return refuse(400, "UnsupportedOperationException", r.operation);
    }

private:
    static auto refuse(int status, std::string_view type, std::string_view message)
        -> sn::aws_json_response {
        return {status, json::serialize(json::object{{"__type", type}, {"message", message}})};
    }
};

/// The caller is the user an `X-Test-User` header names (alice without).
struct by_header {
    auto authenticate(const sv4::request& req, const sv4::service_rules&) -> az::authn_result {
        std::string user = "alice";
        for (const auto& [k, v] : req.headers) {
            if (k == "X-Test-User") {
                user = v;
            }
        }
        az::principal_context p;
        p.type = az::principal_type::user;
        p.account = std::string(k_account);
        p.arn = arn_of(user);
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
                ("kinesis_kms_kythira_test." + std::to_string(::getpid()) + "." +
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

struct gateway {
    by_header auth;
    kin::front_end<by_header> fe{kin::front_end_config{}, auth};
    std::unique_ptr<kin::kinesis_service<kin::local_stream_cluster>> service;
    std::int64_t& _mono;

    gateway(kin::local_stream_cluster& cluster, const std::shared_ptr<fake_kms>& kms,
            std::int64_t& mono)
        : _mono(mono) {
        kin::kinesis_service_config c;
        c._iterator_keys._keys.push_back({._id = 0, ._secret = std::string(32, 'k')});
        c._kms = kin::key_provider(kin::kythira_kms_provider([kms] { return kms; }));
        c._monotonic = [&mono] { return mono; };
        c._kms_caller_ttl = std::chrono::milliseconds(60'000);
        service = std::make_unique<kin::kinesis_service<kin::local_stream_cluster>>(cluster, c);
        service->register_with(fe);
    }

    auto call(std::string_view user, std::string_view op, const json::value& body)
        -> aj::http_response {
        kin::front_end_request r;
        r._method = "POST";
        r._path = "/";
        r._body = json::serialize(body);
        r._headers = {{"Content-Type", "application/x-amz-json-1.1"},
                      {"X-Amz-Target", "Kinesis_20131202." + std::string(op)},
                      {"X-Test-User", std::string(user)}};
        return fe.handle(r);
    }

    auto ok(std::string_view user, std::string_view op, const json::value& body) -> json::object {
        const auto r = call(user, op, body);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, std::string(op) + ": " + r.body);
        return json::parse(r.body).as_object();
    }

    auto put(std::string_view user, std::string_view data) -> aj::http_response {
        return call(user, "PutRecord",
                    {{"StreamName", "s"},
                     {"PartitionKey", "pk"},
                     {"Data", kin::kms_aws_detail::base64_encode(data)}});
    }

    /// GetRecords from the start of the only shard, as `user`.
    auto get(std::string_view user) -> aj::http_response {
        _mono += 500;  // past the shard's five reads a second
        const auto it = ok(user, "GetShardIterator",
                           {{"StreamName", "s"},
                            {"ShardId", "shardId-000000000000"},
                            {"ShardIteratorType", "TRIM_HORIZON"}});
        return call(user, "GetRecords", {{"ShardIterator", it.at("ShardIterator")}});
    }
};

auto type_of(const aj::http_response& r) -> std::string {
    const auto v = json::parse(r.body);
    const auto* t = v.as_object().if_contains("__type");
    return t != nullptr ? std::string(t->as_string()) : std::string();
}

auto records_in(const aj::http_response& r) -> std::size_t {
    return json::parse(r.body).as_object().at("Records").as_array().size();
}

struct fixture {
    temp_dir dir;
    std::unique_ptr<kythira::record_segment_store> store =
        std::make_unique<kythira::record_segment_store>(kythira::record_segment_store_options{
            ._data_dir = dir._path, ._barriers_enabled = false});
    std::int64_t now = 1'000'000;
    std::int64_t mono = 5'000'000;
    kin::local_stream_cluster cluster{store.get(), [this] { return now; }};
    std::shared_ptr<fake_kms> kms = std::make_shared<fake_kms>();
    gateway gw{cluster, kms, mono};

    fixture() {
        kms->allow("admin", {"GenerateDataKey", "Decrypt"});
        kms->allow("producer", {"GenerateDataKey"});
        kms->allow("consumer", {"Decrypt"});
        (void)gw.ok("admin", "CreateStream", {{"StreamName", "s"}, {"ShardCount", 1}});
        (void)gw.ok("admin", "StartStreamEncryption",
                    {{"StreamName", "s"}, {"EncryptionType", "KMS"}, {"KeyId", "alias/s"}});
    }

    auto generations() -> std::size_t {
        std::size_t n = 0;
        (void)cluster.read("", [&](const auto& sm) {
            if (const auto* s = sm.find_stream(k_account, "s")) {
                n = s->_data_keys.size();
            }
        });
        return n;
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(the_provider_authorizes_each_caller) {
    BOOST_TEST(kin::key_provider(kin::kythira_kms_provider({})).per_caller());
    BOOST_TEST(!kin::key_provider(kin::local_kms_provider("correct horse battery")).per_caller());

    const kin::kythira_kms_provider none([] { return std::shared_ptr<sn::kms_endpoint>(); });
    az::principal_context p;
    p.arn = arn_of("admin");
    try {
        (void)none.generate_data_key("alias/s", {}, kin::kms_caller{._principal = &p});
        BOOST_ERROR("no KMS, yet a key");
    } catch (const kin::kms_error& e) {
        BOOST_TEST((e.failure() == kin::kms_failure::unavailable));
    }
    auto kms = std::make_shared<fake_kms>();
    const kin::kythira_kms_provider real([kms] { return kms; });
    try {
        (void)real.generate_data_key("alias/s", {}, {});
        BOOST_ERROR("no caller, yet a key");
    } catch (const kin::kms_error& e) {
        BOOST_TEST((e.failure() == kin::kms_failure::access_denied));
    }
    BOOST_TEST(kms->calls.empty());
    try {
        (void)real.generate_data_key("alias/nope", {}, kin::kms_caller{._principal = &p});
    } catch (const kin::kms_error& e) {
        BOOST_TEST((e.failure() == kin::kms_failure::not_found));
    }
}

BOOST_AUTO_TEST_CASE(stream_key_and_start_encryption_are_the_callers) {
    fixture f;
    // The admin's own GenerateDataKey made the stream's data key, through
    // Kinesis, and the stream keeps the ARN the KMS answered.
    BOOST_REQUIRE(!f.kms->calls.empty());
    BOOST_TEST(f.kms->calls.front().principal == arn_of("admin"));
    BOOST_TEST(f.kms->calls.front().via == "kinesis");
    const auto summary = f.gw.ok("admin", "DescribeStreamSummary", {{"StreamName", "s"}})
                             .at("StreamDescriptionSummary")
                             .as_object();
    BOOST_TEST(summary.at("KeyId").as_string() == "alias/s");

    // A caller the KMS refuses cannot start encryption.
    (void)f.gw.ok("admin", "CreateStream", {{"StreamName", "t"}, {"ShardCount", 1}});
    const auto r =
        f.gw.call("consumer", "StartStreamEncryption",
                  {{"StreamName", "t"}, {"EncryptionType", "KMS"}, {"KeyId", "alias/s"}});
    BOOST_TEST(type_of(r) == "KMSAccessDeniedException");
}

BOOST_AUTO_TEST_CASE(producers_need_generate_data_key_and_consumers_decrypt) {
    fixture f;
    BOOST_TEST(f.gw.put("producer", "one").status == 200U);
    BOOST_TEST(type_of(f.gw.put("consumer", "two")) == "KMSAccessDeniedException");
    BOOST_TEST(type_of(f.gw.put("stranger", "three")) == "KMSAccessDeniedException");

    // The data key is unwrapped on this gateway already (the admin made
    // it), yet each reader is asked about.
    const auto read = f.gw.get("consumer");
    BOOST_REQUIRE_MESSAGE(read.status == 200U, read.body);
    BOOST_TEST(records_in(read) == 1U);
    BOOST_TEST(type_of(f.gw.get("producer")) == "KMSAccessDeniedException");
    BOOST_TEST(type_of(f.gw.get("stranger")) == "KMSAccessDeniedException");
    for (const auto& c : f.kms->calls) {
        BOOST_TEST(c.via == "kinesis");
    }
}

BOOST_AUTO_TEST_CASE(an_answer_stands_for_the_ttl_and_a_disabled_key_stops_within_it) {
    fixture f;
    BOOST_TEST(f.gw.put("producer", "one").status == 200U);
    BOOST_TEST(f.gw.get("consumer").status == 200U);
    const auto gdk = f.kms->count("GenerateDataKey");
    const auto dec = f.kms->count("Decrypt");
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(f.gw.put("producer", "more").status == 200U);
        BOOST_TEST(f.gw.get("consumer").status == 200U);
    }
    BOOST_TEST(f.kms->count("GenerateDataKey") == gdk);
    BOOST_TEST(f.kms->count("Decrypt") == dec);

    f.kms->enabled = false;
    // Within the bound, the answers stand...
    BOOST_TEST(f.gw.put("producer", "still").status == 200U);
    // ...and once it passes, the KMS is asked again.
    f.mono += 60'001;
    BOOST_TEST(type_of(f.gw.put("producer", "after")) == "KMSDisabledException");
    BOOST_TEST(type_of(f.gw.get("consumer")) == "KMSDisabledException");
    f.kms->enabled = true;
    BOOST_TEST(f.gw.put("producer", "enabled again").status == 200U);
    const auto all = f.gw.get("consumer");
    BOOST_REQUIRE(all.status == 200U);
    BOOST_TEST(records_in(all) == 8U);
    // Writes after a fresh answer reuse the data key this gateway holds.
    BOOST_TEST(f.generations() == 1U);
}

BOOST_AUTO_TEST_CASE(a_gateway_without_the_key_adds_one_generation) {
    fixture f;
    // A second gateway (another node, or this one restarted) holds no data
    // key, and the producer may not Decrypt: its own GenerateDataKey
    // becomes another generation, once.
    gateway other(f.cluster, f.kms, f.mono);
    for (int i = 0; i < 4; ++i) {
        const auto r = other.put("producer", "from the other gateway");
        BOOST_TEST(r.status == 200U, r.body);
    }
    BOOST_TEST(f.generations() == 2U);
    f.mono += 60'001;
    BOOST_TEST(other.put("producer", "after the ttl").status == 200U);
    BOOST_TEST(f.generations() == 2U);
    // Both generations read back on the first gateway.
    BOOST_TEST(f.gw.put("producer", "from the first").status == 200U);
    const auto all = f.gw.get("consumer");
    BOOST_REQUIRE(all.status == 200U);
    BOOST_TEST(records_in(all) == 6U);

    // Stopping encryption beats a producer's late generation.
    (void)f.gw.ok("admin", "StopStreamEncryption",
                  {{"StreamName", "s"}, {"EncryptionType", "KMS"}, {"KeyId", "alias/s"}});
    gateway third(f.cluster, f.kms, f.mono);
    BOOST_TEST(third.put("producer", "plain now").status == 200U);
    BOOST_TEST(f.generations() == 2U);
}
