// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 13 (Requirements 10.1 and 10.2): AWS managed keys. alias/aws/kinesis
// and alias/aws/dynamodb are made in an account the first time a request
// names them, with AWS's managed key policy and KeyManager AWS; no
// customer change is allowed; they rotate every year; and making one is
// idempotent, survives a failed attempt, and finishes a key another member
// made but did not alias.

#define BOOST_TEST_MODULE kms_managed_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_managed.hpp>

#include <cstdint>
#include <string>
#include <string_view>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

constexpr std::uint64_t k_day_ms = 86'400'000;

auto managed_id(std::string_view service, unsigned attempt = 0) -> std::string {
    return kms::managed_key_id(k_account, service, attempt);
}

auto describe(fixture& f, std::string_view key) -> reply {
    return f.call("DescribeKey", kid(key));
}

}  // namespace

BOOST_AUTO_TEST_CASE(first_use_makes_the_managed_key) {
    fixture f;
    const auto keys_before = f.call("ListKeys", "{}").body.at("Keys").as_array().size();
    auto r = describe(f, "alias/aws/kinesis");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto& md = r.body.at("KeyMetadata").as_object();
    BOOST_TEST(md.at("KeyManager").as_string() == "AWS");
    BOOST_TEST(md.at("KeyId").as_string() == managed_id("kinesis"));
    BOOST_TEST(md.at("KeyState").as_string() == "Enabled");
    BOOST_TEST(md.at("Description").as_string() ==
               "Default key that protects my Kinesis data when no other key is defined");

    // The same key every time, by alias, alias ARN, id or key ARN.
    for (const auto& name :
         {std::string("alias/aws/kinesis"),
          "arn:aws:kms:us-east-1:" + std::string(k_account) + ":alias/aws/kinesis",
          managed_id("kinesis"), fixture::arn(managed_id("kinesis"))}) {
        const auto again = describe(f, name);
        BOOST_REQUIRE_MESSAGE(again.status == 200U, name + ": " + again.message());
        BOOST_TEST(again.str("KeyMetadata", "KeyId") == managed_id("kinesis"));
    }
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().size() == keys_before + 1);

    // AWS's managed key policy: use only through the service, by the
    // account; the account may read metadata.
    const auto p = f.call("GetKeyPolicy",
                          R"({"KeyId":")" + managed_id("kinesis") + R"(","PolicyName":"default"})");
    BOOST_REQUIRE(p.status == 200U);
    const auto policy = p.str("Policy");
    BOOST_TEST(policy.find(R"("kms:ViaService":"kinesis.us-east-1.amazonaws.com")") !=
               std::string::npos);
    BOOST_TEST(policy.find(R"("kms:CallerAccount":"111122223333")") != std::string::npos);
    BOOST_TEST(policy.find(R"("AWS":"arn:aws:iam::111122223333:root")") != std::string::npos);
    BOOST_TEST(policy.find("kms:CreateGrant") == std::string::npos);  // DynamoDB's has it
    BOOST_TEST((boost::json::parse(policy).is_object()));
}

BOOST_AUTO_TEST_CASE(any_key_operation_naming_the_alias_makes_it) {
    fixture f;
    const auto e = f.call("Encrypt", R"({"KeyId":"alias/aws/dynamodb","Plaintext":"aGk="})");
    BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
    BOOST_TEST(e.str("KeyId") == fixture::arn(managed_id("dynamodb")));
    const auto d = f.call("Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})");
    BOOST_TEST(d.status == 200U);
    const auto p = f.call(
        "GetKeyPolicy", R"({"KeyId":")" + managed_id("dynamodb") + R"(","PolicyName":"default"})");
    BOOST_TEST(p.str("Policy").find("kms:CreateGrant") != std::string::npos);

    const auto g =
        f.call("GenerateDataKey", R"({"KeyId":"alias/aws/kinesis","KeySpec":"AES_256"})");
    BOOST_TEST(g.status == 200U, g.type());
    BOOST_TEST(f.sm.key(managed_id("kinesis")).has_value());
}

BOOST_AUTO_TEST_CASE(only_known_services_and_the_callers_account) {
    fixture f;
    BOOST_TEST(describe(f, "alias/aws/s3").type() == "NotFoundException");
    BOOST_TEST(describe(f, "alias/aws/").type() == "NotFoundException");
    BOOST_TEST(describe(f, "arn:aws:kms:us-east-1:" + std::string(k_other) + ":alias/aws/kinesis")
                   .type() == "NotFoundException");
    BOOST_TEST(!f.sm.key(kms::managed_key_id(k_other, "kinesis", 0)).has_value());
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().empty());
    // Customers may not make alias/aws/ names themselves.
    const auto id = f.create();
    BOOST_TEST(
        f.call("CreateAlias", R"({"AliasName":"alias/aws/kinesis","TargetKeyId":")" + id + R"("})")
            .status != 200U);
}

BOOST_AUTO_TEST_CASE(customers_cannot_change_a_managed_key) {
    fixture f;
    BOOST_REQUIRE(describe(f, "alias/aws/kinesis").status == 200U);
    const auto id = managed_id("kinesis");
    const auto key = kid(id);
    for (const auto& [op, body] : std::initializer_list<std::pair<const char*, std::string>>{
             {"DisableKey", key},
             {"ScheduleKeyDeletion", key},
             {"EnableKeyRotation", key},
             {"DisableKeyRotation", key},
             {"RotateKeyOnDemand", key},
             {"UpdateKeyDescription", R"({"KeyId":")" + id + R"(","Description":"mine"})"},
             {"PutKeyPolicy", R"({"KeyId":")" + id + R"(","PolicyName":"default","Policy":"{}"})"},
             {"TagResource", R"({"KeyId":")" + id + R"(","Tags":[{"TagKey":"a","TagValue":"b"}]})"},
             {"DeleteAlias", R"({"AliasName":"alias/aws/kinesis"})"},
         }) {
        const auto r = f.call(op, body);
        BOOST_TEST(r.status != 200U, op << " was allowed");
    }
    BOOST_TEST(describe(f, id).str("KeyMetadata", "KeyState") == "Enabled");
    BOOST_TEST(f.sm.alias(std::string(k_account), "alias/aws/kinesis").has_value());
}

BOOST_AUTO_TEST_CASE(managed_keys_rotate_every_year) {
    fixture f;
    BOOST_REQUIRE(describe(f, "alias/aws/kinesis").status == 200U);
    const auto id = managed_id("kinesis");
    const auto made = f.now;
    auto k = f.sm.key(id);
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST(k->rotation_enabled);
    BOOST_TEST(k->rotation_period_days == 365U);
    BOOST_TEST(k->next_rotation_ms == made + 365 * k_day_ms);
    const auto st = f.call("GetKeyRotationStatus", kid(id));
    BOOST_TEST(st.status == 200U, st.type());
    BOOST_TEST(st.body.at("KeyRotationEnabled").as_bool());

    f.now = made + 364 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().rotated == 0U);
    f.now = made + 365 * k_day_ms;
    BOOST_TEST(f.jobs.run_once().rotated == 1U);
    BOOST_TEST(f.sm.key(id)->current_version == 2U);
}

BOOST_AUTO_TEST_CASE(a_failed_attempt_moves_to_the_next_id) {
    fixture f;
    f.hsm_backend->sealed = true;
    BOOST_TEST(describe(f, "alias/aws/kinesis").status != 200U);
    BOOST_TEST(f.sm.tombstoned(managed_id("kinesis", 0)));
    BOOST_TEST(!f.sm.alias(std::string(k_account), "alias/aws/kinesis").has_value());
    f.hsm_backend->sealed = false;
    const auto r = describe(f, "alias/aws/kinesis");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("KeyMetadata", "KeyId") == managed_id("kinesis", 1));
}

BOOST_AUTO_TEST_CASE(a_key_another_member_made_is_aliased_not_doubled) {
    fixture f;
    // Another member's first use made the key and stopped before the
    // alias: this one finds the derived id and only adds the alias.
    kms::key_record k;
    k.key_id = managed_id("kinesis");
    k.account = std::string(k_account);
    k.manager = kms::key_manager::aws;
    k.policy = kms::managed_key_policy("aws", "us-east-1", k_account, kms::k_managed_services[1]);
    BOOST_REQUIRE(f.jobs.create_key(k, {}).ok());
    const auto r = describe(f, "alias/aws/kinesis");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("KeyMetadata", "KeyId") == managed_id("kinesis"));
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().size() == 1U);

    // And ensuring again is a no-op.
    BOOST_TEST(f.ensure(k_account, kms::k_managed_services[1]).ok());
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().size() == 1U);
}

BOOST_AUTO_TEST_CASE(derived_ids_are_stable_and_distinct) {
    BOOST_TEST(managed_id("kinesis") == managed_id("kinesis"));
    BOOST_TEST(managed_id("kinesis") != managed_id("dynamodb"));
    BOOST_TEST(managed_id("kinesis", 0) != managed_id("kinesis", 1));
    BOOST_TEST(kms::managed_key_id(k_other, "kinesis", 0) != managed_id("kinesis"));
    const auto id = managed_id("kinesis");
    BOOST_TEST(id.size() == 36U);
    BOOST_TEST(id[14] == '8');  // UUID version 8
}
