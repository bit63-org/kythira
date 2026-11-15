// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 6 (Requirements 3.1-3.6, 6.1-6.3, 7.2 and 7.3): the front end's
// framing, SigV4 and authorization guard, and the key management
// operations (keys, aliases, tags) over a catalog replica and a fake HSM,
// through signed JSON 1.1 requests as an SDK sends them.

#define BOOST_TEST_MODULE kms_api_test

#include <boost/test/unit_test.hpp>

#include "kms_fake_pkcs11.hpp"

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/kms_api.hpp>
#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_front_end.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/sigv4_verifier.hpp>
#include <raft/static_key_authorizer.hpp>

#include <boost/json.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace kms = kythira::kms;
namespace kt = kythira::kms::test;
namespace az = kythira::aws_auth;
namespace sv4 = kythira::sigv4;
namespace json = boost::json;

namespace {

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_account = "111122223333";
constexpr std::string_view k_other = "444455556666";
const auto k_now = sv4::detail::parse_amz_date("20261115T120000Z").value();

using catalog_t = kms::kms_catalog_state_machine<>;

/// Static keys for authentication; authorization through a hook the test
/// can replace, recording every request it is asked.
struct test_authorizer {
    az::static_key_authorizer keys{{
                                       {"AKIDADMIN", std::string(k_secret), std::string(k_account),
                                        "admin", az::static_role::admin},
                                       {"AKIDREAD", std::string(k_secret), std::string(k_account),
                                        "reader", az::static_role::read_only},
                                       {"AKIDOTHER", std::string(k_secret), std::string(k_other),
                                        "stranger", az::static_role::admin},
                                   },
                                   "aws",
                                   [] { return k_now; }};
    std::vector<az::authz_request> asked;
    std::function<az::authz_decision(const az::principal_context&, const az::authz_request&)>
        decide;

    test_authorizer() { keys.register_service(kms::kms_static_roles()); }

    auto authenticate(const sv4::request& req, const sv4::service_rules& rules)
        -> az::authn_result {
        return keys.authenticate(req, rules);
    }
    auto authorize(const az::principal_context& who, const az::authz_request& r)
        -> az::authz_decision {
        asked.push_back(r);
        return decide ? decide(who, r) : keys.authorize(who, r);
    }
};

static_assert(az::aws_request_authorizer<test_authorizer>);

auto request(std::string_view op, const std::string& body) -> kms::front_end_request {
    kms::front_end_request r;
    r.method = "POST";
    r.path = "/";
    r.body = body;
    r.source_ip = "192.0.2.10";
    r.headers = {{"Host", "kms.us-east-1.amazonaws.com"},
                 {"Content-Type", "application/x-amz-json-1.1"},
                 {"X-Amz-Date", "20261115T120000Z"},
                 {"X-Amz-Target", "TrentService." + std::string(op)}};
    return r;
}

auto sign(kms::front_end_request r, std::string_view akid) -> kms::front_end_request {
    sv4::service_rules rules;
    rules.service = "kms";
    rules.protocol = sv4::error_protocol::json;
    const sv4::credential_scope scope{"20261115", "us-east-1", "kms"};
    r.headers.emplace_back("Authorization",
                           "AWS4-HMAC-SHA256 Credential=" + std::string(akid) + "/" + scope.text() +
                               ", SignedHeaders=content-type;host;x-amz-date;x-amz-target"
                               ", Signature=" +
                               std::string(64, '0'));
    const auto parsed =
        sv4::parse(sv4::request{r.method, r.path, r.query, r.headers, r.body}, rules, k_now);
    BOOST_REQUIRE(parsed.has_value());
    const auto sig = sv4::compute_signature(*parsed, sv4::derive_signing_key(k_secret, scope));
    r.headers.back().second.replace(r.headers.back().second.size() - 64, 64, sig);
    return r;
}

struct reply {
    unsigned status = 0;
    json::object body;

    [[nodiscard]] auto type() const -> std::string {
        const auto* t = body.if_contains("__type");
        if (t == nullptr) {
            return {};
        }
        const std::string full(t->as_string());
        return full.substr(full.find('#') + 1);
    }
    [[nodiscard]] auto message() const -> std::string {
        for (const char* k : {"message", "Message"}) {
            if (const auto* m = body.if_contains(k)) {
                return std::string(m->as_string());
            }
        }
        return {};
    }
    [[nodiscard]] auto str(std::string_view a, std::string_view b = {}) const -> std::string {
        const auto& v = b.empty() ? body.at(a) : body.at(a).as_object().at(b);
        return std::string(v.as_string());
    }
};

struct fixture {
    kythira::memory_kv_engine engine;
    catalog_t sm{"kms/"};
    std::shared_ptr<kt::fake_backend> hsm_backend = std::make_shared<kt::fake_backend>();
    kms::backing_store hsm{hsm_backend, 1, "1234"};
    std::uint64_t index = 0;
    std::uint64_t now = 1'790'000'000'000;
    bool leaderless = false;
    int next_id = 0;
    kms::key_jobs<catalog_t> jobs{sm, hsm,
                                  [this](const std::vector<std::byte>& c) { return propose(c); },
                                  [this] { return now; }, std::chrono::minutes(5)};
    test_authorizer auth;
    kms::front_end<test_authorizer> fe{kms::front_end_config{}, auth};
    kms::key_management_api<catalog_t> api{kms::api_deps<catalog_t>{
        .catalog =
            [this] { return std::shared_ptr<const catalog_t>(&sm, [](const catalog_t*) {}); },
        .barrier = [this] { return !leaderless; },
        .propose = [this](const std::vector<std::byte>& c) { return propose(c); },
        .create_key = [this](kms::key_record k,
                             const kms::tag_map& t) { return jobs.create_key(std::move(k), t); },
        .clock_ms = [this] { return now; },
        .new_key_id =
            [this] {
                char buf[37];
                std::snprintf(buf, sizeof buf, "%08x-2222-4000-8000-000000000000", ++next_id);
                return std::string(buf);
            },
    }};

    fixture() {
        sm.open(engine, sm.engine_range());
        api.register_on(fe);
    }

    auto propose(const std::vector<std::byte>& c) -> kms::catalog_status {
        if (leaderless) {
            throw std::runtime_error("no leader");
        }
        return kms::catalog_reply_status(sm.apply(c, ++index));
    }

    auto call(std::string_view op, const std::string& body, std::string_view akid = "AKIDADMIN")
        -> reply {
        return answer(fe.handle(sign(request(op, body), akid)));
    }

    static auto answer(const kythira::aws_json::http_response& res) -> reply {
        reply r;
        r.status = res.status;
        if (!res.body.empty()) {
            r.body = json::parse(res.body).as_object();
        }
        return r;
    }

    /// CreateKey with `body`; the new key's id.
    auto create(const std::string& body = "{}", std::string_view akid = "AKIDADMIN")
        -> std::string {
        const auto r = call("CreateKey", body, akid);
        BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
        return r.str("KeyMetadata", "KeyId");
    }

    [[nodiscard]] static auto arn(std::string_view id, std::string_view account = k_account)
        -> std::string {
        return "arn:aws:kms:us-east-1:" + std::string(account) + ":key/" + std::string(id);
    }
};

auto kid(std::string_view id) -> std::string {
    return R"({"KeyId":")" + std::string(id) + R"("})";
}

}  // namespace

// -- Front end -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(an_unsigned_call_learns_only_that_it_must_sign) {
    fixture f;
    const auto r = fixture::answer(f.fe.handle(request("CreateKey", "{not json")));
    BOOST_TEST(r.status == 400U);
    BOOST_TEST(r.type() == "IncompleteSignatureException", r.type());
    BOOST_TEST(f.auth.asked.empty());
    BOOST_TEST(f.sm.keys(k_account).empty());

    // A bad signature too, and for the wrong service.
    auto forged = sign(request("ListKeys", "{}"), "AKIDADMIN");
    forged.body = R"({"Limit":1})";
    BOOST_TEST(fixture::answer(f.fe.handle(forged)).type() == "InvalidSignatureException");
}

BOOST_AUTO_TEST_CASE(framing_errors_and_unimplemented_operations) {
    fixture f;
    // Not a KMS operation.
    BOOST_TEST(f.call("CreateStream", "{}").type() == "UnknownOperationException");
    // Modeled, not implemented: named as unsupported, after the signature.
    const auto enc = f.call("Encrypt", R"({"KeyId":"x","Plaintext":"AA=="})");
    BOOST_TEST(enc.status == 400U);
    BOOST_TEST(enc.type() == "UnsupportedOperationException");
    BOOST_TEST(enc.message().find("unsupported.md") != std::string::npos, enc.message());
    // A body the model rejects.
    BOOST_TEST(f.call("DescribeKey", R"({"KeyId":7})").type() == "SerializationException");
    BOOST_TEST(f.call("DescribeKey", "[").status == 400U);
    // Every implemented operation is registered.
    for (const auto op : kms::key_management_api<catalog_t>::k_operations) {
        BOOST_TEST(f.fe.handles(op), op);
    }
}

BOOST_AUTO_TEST_CASE(a_handler_that_never_authorizes_cannot_answer) {
    fixture f;
    f.fe.on("GenerateRandom", [](kms::call_context&, json::object&) {
        return kythira::aws_json::result<json::object>(json::object{{"Plaintext", "c2VjcmV0"}});
    });
    const auto r = f.call("GenerateRandom", R"({"NumberOfBytes":8})");
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(r.type() == "KMSInternalException");
    BOOST_TEST(!r.body.contains("Plaintext"));
}

BOOST_AUTO_TEST_CASE(a_throwing_handler_answers_internal_error) {
    fixture f;
    f.fe.on("GenerateRandom",
            [](kms::call_context&, json::object&) -> kythira::aws_json::result<json::object> {
                throw std::runtime_error("boom");
            });
    const auto r = f.call("GenerateRandom", R"({"NumberOfBytes":8})");
    BOOST_TEST(r.status == 500U);
    BOOST_TEST(r.type() == "KMSInternalException");
    BOOST_TEST(r.message().find("boom") == std::string::npos);
    BOOST_CHECK_THROW(f.fe.on("NoSuchOperation", {}), std::invalid_argument);
    BOOST_CHECK_THROW(f.fe.on("CreateKey", {}), std::invalid_argument);
}

// -- Keys --------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(create_describe_and_list_keys) {
    fixture f;
    const auto r = f.call("CreateKey", R"({"Description":"orders","Tags":[{"TagKey":"team",)"
                                       R"("TagValue":"core"}]})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto& m = r.body.at("KeyMetadata").as_object();
    const std::string id(m.at("KeyId").as_string());
    BOOST_TEST(m.at("Arn").as_string() == fixture::arn(id));
    BOOST_TEST(m.at("AWSAccountId").as_string() == k_account);
    BOOST_TEST(m.at("KeyState").as_string() == "Enabled");
    BOOST_TEST(m.at("Enabled").as_bool());
    BOOST_TEST(m.at("KeySpec").as_string() == "SYMMETRIC_DEFAULT");
    BOOST_TEST(m.at("KeyUsage").as_string() == "ENCRYPT_DECRYPT");
    BOOST_TEST(m.at("KeyManager").as_string() == "CUSTOMER");
    BOOST_TEST(m.at("Origin").as_string() == "AWS_KMS");
    BOOST_TEST(m.at("Description").as_string() == "orders");
    BOOST_TEST(m.at("CreationDate").to_number<double>() == 1'790'000'000.0);
    BOOST_TEST(m.at("EncryptionAlgorithms").as_array().size() == 1U);
    BOOST_TEST(f.hsm_backend->objects().size() == 1U);
    // The default key policy delegates to the account (Requirement 7.2).
    const auto k = f.sm.key(id);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST(k->policy.find("arn:aws:iam::111122223333:root") != std::string::npos);
    BOOST_TEST(f.sm.tags(id).at("team") == "core");

    // CreateKey and TagResource were both authorized, with the tags.
    BOOST_REQUIRE(f.auth.asked.size() == 2U);
    BOOST_TEST(f.auth.asked[0].action == "kms:CreateKey");
    BOOST_TEST(f.auth.asked[1].action == "kms:TagResource");
    BOOST_TEST(f.auth.asked[1].request_tags.has_value());

    // DescribeKey by id, ARN, alias name and alias ARN.
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/orders","TargetKeyId":")" + id + R"("})")
            .status == 200U);
    for (const auto& name : {id, fixture::arn(id), std::string("alias/orders"),
                             std::string("arn:aws:kms:us-east-1:111122223333:alias/orders")}) {
        const auto d = f.call("DescribeKey", kid(name));
        BOOST_TEST(d.status == 200U, name);
        BOOST_TEST(d.str("KeyMetadata", "KeyId") == id, name);
    }
    BOOST_TEST(f.call("DescribeKey", kid("alias/none")).type() == "NotFoundException");
    BOOST_TEST(f.call("DescribeKey", kid("00000000-0000-4000-8000-000000000000")).type() ==
               "NotFoundException");
    BOOST_TEST(f.call("DescribeKey", kid("arn:aws:kms:eu-west-1:111122223333:key/" + id)).type() ==
               "NotFoundException");

    // ListKeys pages with Marker.
    f.create();
    f.create();
    const auto p1 = f.call("ListKeys", R"({"Limit":2})");
    BOOST_TEST(p1.body.at("Keys").as_array().size() == 2U);
    BOOST_TEST(p1.body.at("Truncated").as_bool());
    const auto p2 = f.call("ListKeys", R"({"Limit":2,"Marker":")" + p1.str("NextMarker") + R"("})");
    BOOST_TEST(p2.body.at("Keys").as_array().size() == 1U);
    BOOST_TEST(!p2.body.at("Truncated").as_bool());
    BOOST_TEST(p2.body.at("Keys").as_array()[0].as_object().at("KeyArn").as_string().starts_with(
        "arn:aws:kms:us-east-1:111122223333:key/"));
    // Another account sees none of them.
    BOOST_TEST(f.call("ListKeys", "{}", "AKIDOTHER").body.at("Keys").as_array().empty());
}

BOOST_AUTO_TEST_CASE(create_key_checks_its_input_before_proposing) {
    fixture f;
    const auto rsa = f.call("CreateKey", R"({"KeySpec":"RSA_2048","KeyUsage":"SIGN_VERIFY"})");
    BOOST_REQUIRE(rsa.status == 200U);
    BOOST_TEST(rsa.body.at("KeyMetadata").as_object().at("SigningAlgorithms").as_array().size() ==
               6U);
    const auto hmac =
        f.call("CreateKey", R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})");
    BOOST_REQUIRE(hmac.status == 200U);
    BOOST_TEST(hmac.body.at("KeyMetadata").as_object().at("MacAlgorithms").as_array()[0] ==
               "HMAC_SHA_256");

    const auto before = f.sm.keys(k_account).size();
    BOOST_TEST(f.call("CreateKey", R"({"KeySpec":"HMAC_256"})").type() == "ValidationException");
    BOOST_TEST(
        f.call("CreateKey", R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"ENCRYPT_DECRYPT"})").type() ==
        "ValidationException");
    BOOST_TEST(f.call("CreateKey", R"({"KeySpec":"RSA_2048","CustomerMasterKeySpec":"RSA_4096"})")
                   .type() == "ValidationException");
    BOOST_TEST(f.call("CreateKey", R"({"Origin":"EXTERNAL"})").type() ==
               "UnsupportedOperationException");
    BOOST_TEST(f.call("CreateKey", R"({"MultiRegion":true})").type() ==
               "UnsupportedOperationException");
    BOOST_TEST(f.call("CreateKey", R"({"CustomKeyStoreId":"cks-1234567890abcdef0"})").type() ==
               "UnsupportedOperationException");
    BOOST_TEST(f.call("CreateKey", R"({"Policy":"not a policy"})").type() ==
               "MalformedPolicyDocumentException");
    const std::string big = R"({"Version":"2012-10-17","Id":")" + std::string(32768, 'x') + R"("})";
    json::object in{{"Policy", big}};
    BOOST_TEST(f.call("CreateKey", json::serialize(in)).type() == "LimitExceededException");
    BOOST_TEST(f.call("CreateKey", R"({"Tags":[{"TagKey":"aws:x","TagValue":"v"}]})").type() ==
               "TagException");
    BOOST_TEST(f.call("CreateKey", R"({"Tags":[{"TagKey":"a","TagValue":"1"},)"
                                   R"({"TagKey":"a","TagValue":"2"}]})")
                   .type() == "TagException");
    json::array many;
    for (int i = 0; i < 51; ++i) {
        many.push_back(json::object{{"TagKey", "k" + std::to_string(i)}, {"TagValue", "v"}});
    }
    BOOST_TEST(f.call("CreateKey", json::serialize(json::object{{"Tags", many}})).type() ==
               "LimitExceededException");
    BOOST_TEST(f.sm.keys(k_account).size() == before);

    // A given policy is stored as given.
    const std::string policy =
        R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":)"
        R"({"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}]})";
    const auto id = f.create(json::serialize(json::object{{"Policy", policy}}));
    BOOST_TEST(f.sm.key(id)->policy == policy);
}

BOOST_AUTO_TEST_CASE(a_sealed_hsm_or_no_leader_answers_retryable_errors) {
    fixture f;
    const auto id = f.create();
    f.hsm_backend->sealed = true;
    const auto sealed = f.call("CreateKey", "{}");
    BOOST_TEST(sealed.status == 500U);
    BOOST_TEST(sealed.type() == "KMSInternalException");
    // Management needs no HSM.
    BOOST_TEST(f.call("DisableKey", kid(id)).status == 200U);
    f.hsm_backend->sealed = false;

    f.leaderless = true;
    const auto read = f.call("DescribeKey", kid(id));
    BOOST_TEST(read.status == 503U);
    BOOST_TEST(read.type() == "DependencyTimeoutException");
    BOOST_TEST(f.call("CreateKey", "{}").type() == "DependencyTimeoutException");
}

BOOST_AUTO_TEST_CASE(enable_disable_describe_and_schedule_deletion) {
    fixture f;
    const auto id = f.create();
    BOOST_TEST(f.call("DisableKey", kid(id)).status == 200U);
    BOOST_TEST(f.call("DescribeKey", kid(id)).str("KeyMetadata", "KeyState") == "Disabled");
    BOOST_TEST(f.call("EnableKey", kid(fixture::arn(id))).status == 200U);
    BOOST_TEST(f.call("DescribeKey", kid(id)).str("KeyMetadata", "KeyState") == "Enabled");
    // EnableKey and friends take no alias, as on AWS.
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/a","TargetKeyId":")" + id + R"("})").status ==
        200U);
    BOOST_TEST(f.call("DisableKey", kid("alias/a")).type() == "NotFoundException");

    BOOST_TEST(
        f.call("UpdateKeyDescription", R"({"KeyId":")" + id + R"(","Description":"new"})").status ==
        200U);
    BOOST_TEST(f.sm.key(id)->description == "new");

    BOOST_TEST(f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":6})")
                   .type() == "ValidationException");
    BOOST_TEST(
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":31})")
            .type() == "ValidationException");
    const auto s =
        f.call("ScheduleKeyDeletion", R"({"KeyId":")" + id + R"(","PendingWindowInDays":7})");
    BOOST_REQUIRE_MESSAGE(s.status == 200U, s.type() + ": " + s.message());
    BOOST_TEST(s.str("KeyId") == fixture::arn(id));
    BOOST_TEST(s.str("KeyState") == "PendingDeletion");
    BOOST_TEST(s.body.at("PendingWindowInDays").to_number<int>() == 7);
    BOOST_TEST(s.body.at("DeletionDate").to_number<double>() ==
               (1'790'000'000'000.0 + 7 * 86'400'000.0) / 1000.0);
    BOOST_TEST(
        f.call("DescribeKey", kid(id)).body.at("KeyMetadata").as_object().contains("DeletionDate"));
    // A key pending deletion cannot be enabled.
    BOOST_TEST(f.call("EnableKey", kid(id)).type() == "KMSInvalidStateException");

    const auto c = f.call("CancelKeyDeletion", kid(id));
    BOOST_REQUIRE(c.status == 200U);
    BOOST_TEST(c.str("KeyId") == fixture::arn(id));
    // A key whose deletion is cancelled is Disabled.
    BOOST_TEST(f.call("DescribeKey", kid(id)).str("KeyMetadata", "KeyState") == "Disabled");
    BOOST_TEST(f.call("CancelKeyDeletion", kid(id)).type() == "KMSInvalidStateException");
}

// -- Aliases -----------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(aliases_are_created_moved_listed_and_deleted) {
    fixture f;
    const auto a = f.create();
    const auto b = f.create();
    const auto rsa = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"SIGN_VERIFY"})");
    const auto alias = [](std::string_view name, std::string_view target) {
        return R"({"AliasName":")" + std::string(name) + R"(","TargetKeyId":")" +
               std::string(target) + R"("})";
    };
    BOOST_TEST(f.call("CreateAlias", alias("alias/app", a)).status == 200U);
    BOOST_TEST(f.call("CreateAlias", alias("alias/app", b)).type() == "AlreadyExistsException");
    BOOST_TEST(f.call("CreateAlias", alias("app", a)).type() == "InvalidAliasNameException");
    BOOST_TEST(f.call("CreateAlias", alias("alias/aws/s3", a)).type() ==
               "InvalidAliasNameException");
    BOOST_TEST(f.call("CreateAlias", alias("alias/x", "alias/app")).type() == "NotFoundException");
    // Another account's key, even by ARN, takes no alias of ours.
    const auto theirs = f.create("{}", "AKIDOTHER");
    BOOST_TEST(f.call("CreateAlias", alias("alias/x", fixture::arn(theirs, k_other))).type() ==
               "NotFoundException");

    BOOST_TEST(f.call("UpdateAlias", alias("alias/app", b)).status == 200U);
    BOOST_TEST(f.sm.alias(k_account, "alias/app")->key_id == b);
    BOOST_TEST(f.call("UpdateAlias", alias("alias/app", rsa)).type() == "ValidationException");
    BOOST_TEST(f.call("UpdateAlias", alias("alias/none", a)).type() == "NotFoundException");

    BOOST_TEST(f.call("CreateAlias", alias("alias/other", a)).status == 200U);
    const auto all = f.call("ListAliases", "{}");
    BOOST_TEST(all.body.at("Aliases").as_array().size() == 2U);
    const auto of_a = f.call("ListAliases", kid(a));
    BOOST_REQUIRE(of_a.body.at("Aliases").as_array().size() == 1U);
    const auto& entry = of_a.body.at("Aliases").as_array()[0].as_object();
    BOOST_TEST(entry.at("AliasName").as_string() == "alias/other");
    BOOST_TEST(entry.at("AliasArn").as_string() ==
               "arn:aws:kms:us-east-1:111122223333:alias/other");
    BOOST_TEST(entry.at("TargetKeyId").as_string() == a);
    const auto page = f.call("ListAliases", R"({"Limit":1})");
    BOOST_TEST(page.body.at("Truncated").as_bool());
    const auto rest =
        f.call("ListAliases", R"({"Limit":1,"Marker":")" + page.str("NextMarker") + R"("})");
    BOOST_TEST(rest.body.at("Aliases").as_array().size() == 1U);
    BOOST_TEST(!rest.body.at("Truncated").as_bool());

    BOOST_TEST(f.call("DeleteAlias", R"({"AliasName":"alias/app"})").status == 200U);
    BOOST_TEST(f.call("DeleteAlias", R"({"AliasName":"alias/app"})").type() == "NotFoundException");
    BOOST_TEST(!f.sm.alias(k_account, "alias/app").has_value());
}

// -- Tags --------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(tags_are_added_listed_and_removed) {
    fixture f;
    const auto id = f.create();
    BOOST_TEST(f.call("TagResource", R"({"KeyId":")" + id +
                                         R"(","Tags":[{"TagKey":"b","TagValue":"2"},)"
                                         R"({"TagKey":"a","TagValue":"1"}]})")
                   .status == 200U);
    const auto l = f.call("ListResourceTags", kid(id));
    BOOST_REQUIRE(l.body.at("Tags").as_array().size() == 2U);
    BOOST_TEST(l.body.at("Tags").as_array()[0].as_object().at("TagKey").as_string() == "a");
    const auto page = f.call("ListResourceTags", R"({"KeyId":")" + id + R"(","Limit":1})");
    BOOST_TEST(page.body.at("Truncated").as_bool());
    BOOST_TEST(page.str("NextMarker") == "a");

    BOOST_TEST(f.call("UntagResource", R"({"KeyId":")" + id + R"(","TagKeys":["a"]})").status ==
               200U);
    BOOST_TEST(f.sm.tags(id).size() == 1U);
    BOOST_TEST(f.call("TagResource",
                      R"({"KeyId":")" + id + R"(","Tags":[{"TagKey":"aws:x","TagValue":"v"}]})")
                   .type() == "TagException");
    // UntagResource names its keys to the authorizer as aws:TagKeys.
    BOOST_TEST(f.call("UntagResource", R"({"KeyId":")" + id + R"(","TagKeys":["b"]})").status ==
               200U);
    bool named = false;
    for (const auto& [k, v] : f.auth.asked.back().keys) {
        named = named || (k == "aws:TagKeys" && v == std::vector<std::string>{"b"});
    }
    BOOST_TEST(named);
}

// -- Authorization -----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(each_key_operation_is_authorized_with_the_key_policy) {
    fixture f;
    const auto id = f.create();
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/k","TargetKeyId":")" + id + R"("})").status ==
        200U);
    f.auth.asked.clear();
    BOOST_REQUIRE(f.call("DescribeKey", kid("alias/k")).status == 200U);
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    const auto& r = f.auth.asked[0];
    BOOST_TEST(r.action == "kms:DescribeKey");
    BOOST_TEST(r.resource == fixture::arn(id));
    BOOST_TEST((r.resource_kind == az::resource_policy_kind::key));
    BOOST_TEST(r.resource_policy.value_or("") == f.sm.key(id)->policy);
    BOOST_TEST(r.source_ip == "192.0.2.10");
    BOOST_TEST(r.region == "us-east-1");
    const auto has = [&](std::string_view key, std::string_view value) {
        for (const auto& [k, v] : r.keys) {
            if (k == key && std::find(v.begin(), v.end(), value) != v.end()) {
                return true;
            }
        }
        return false;
    };
    BOOST_TEST(has("kms:KeySpec", "SYMMETRIC_DEFAULT"));
    BOOST_TEST(has("kms:KeyUsage", "ENCRYPT_DECRYPT"));
    BOOST_TEST(has("kms:ResourceAliases", "alias/k"));
    BOOST_TEST(has("kms:CallerAccount", k_account));

    // The read-only key describes but does not disable.
    BOOST_TEST(f.call("DescribeKey", kid(id), "AKIDREAD").status == 200U);
    const auto denied = f.call("DisableKey", kid(id), "AKIDREAD");
    BOOST_TEST(denied.status == 400U);
    BOOST_TEST(denied.type() == "AccessDeniedException");
    BOOST_TEST(denied.message().find("kms:DisableKey") != std::string::npos, denied.message());
    BOOST_TEST(f.call("DescribeKey", kid(id)).str("KeyMetadata", "KeyState") == "Enabled");

    // An explicit deny is worded as one, and nothing is written.
    f.auth.decide = [](const az::principal_context&, const az::authz_request& q) {
        az::authz_decision d;
        d.allowed = q.action != "kms:ScheduleKeyDeletion";
        d.explicit_deny = !d.allowed;
        return d;
    };
    const auto deny = f.call("ScheduleKeyDeletion", kid(id));
    BOOST_TEST(deny.type() == "AccessDeniedException");
    BOOST_TEST(deny.message().find("explicit deny") != std::string::npos, deny.message());
    BOOST_TEST((f.sm.key(id)->state == kms::key_state::enabled));
}

BOOST_AUTO_TEST_CASE(another_accounts_key_is_reached_only_by_arn) {
    fixture f;
    const auto id = f.create();
    // By bare id, the stranger's own account is searched.
    BOOST_TEST(f.call("DescribeKey", kid(id), "AKIDOTHER").type() == "NotFoundException");
    f.auth.asked.clear();
    // By ARN, the key's account is the resource account. Static keys never
    // reach across accounts...
    const auto d = f.call("DescribeKey", kid(fixture::arn(id)), "AKIDOTHER");
    BOOST_TEST(d.type() == "AccessDeniedException", d.type());
    BOOST_REQUIRE(f.auth.asked.size() == 1U);
    BOOST_TEST(f.auth.asked[0].resource_account == k_account);
    // ...while an authorizer whose key policy grants the stranger does.
    f.auth.decide = [](const az::principal_context&, const az::authz_request&) {
        return az::authz_decision{.allowed = true};
    };
    BOOST_TEST(
        f.call("DescribeKey", kid(fixture::arn(id)), "AKIDOTHER").str("KeyMetadata", "KeyId") ==
        id);
    // A forged ARN naming the key under the stranger's account finds none.
    BOOST_TEST(f.call("DescribeKey", kid(fixture::arn(id, k_other)), "AKIDOTHER").type() ==
               "NotFoundException");
}
