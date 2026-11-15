// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 13 (Requirements 10.1 and 10.2): AWS managed keys. alias/aws/kinesis
// and alias/aws/dynamodb are made in an account the first time a request
// names them, with AWS's managed key policy and KeyManager AWS; no
// customer change is allowed; they rotate every year; and making one is
// idempotent, survives a failed attempt, and finishes a key another member
// made but did not alias.
//
// Requirement 10.3: owned keys. A consuming service's
// alias/aws/<service>/owned is made on first use in the caller's account,
// answers only that service, and is listed and visible nowhere else.

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

/// The account's root, as a consuming service forwards its caller.
auto account_root(std::string_view account) -> kythira::aws_auth::principal_context {
    kythira::aws_auth::principal_context p;
    p.type = kythira::aws_auth::principal_type::root;
    p.account = std::string(account);
    p.arn = "arn:aws:iam::" + std::string(account) + ":root";
    p.userid = std::string(account);
    return p;
}

/// `op` through `service` for `account`'s root, as kms.client calls.
auto via(fixture& f, std::string_view service, std::string_view op, const std::string& body,
         std::string_view account = k_account) -> reply {
    return fixture::answer(
        f.fe.handle_service_call(op, body, account_root(account), std::string(service), "::1"));
}

auto owned_id(std::string_view service, std::string_view account = k_account) -> std::string {
    return kms::owned_key_id(account, service, 0);
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

BOOST_AUTO_TEST_CASE(a_service_owned_key_is_made_on_first_use) {
    fixture f;
    const auto name = kms::owned_key_name("dynamodb");
    BOOST_TEST(name == "alias/aws/dynamodb/owned");
    const auto e =
        via(f, "dynamodb", "GenerateDataKey", R"({"KeyId":")" + name + R"(","KeySpec":"AES_256"})");
    BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
    BOOST_TEST(e.str("KeyId") == fixture::arn(owned_id("dynamodb")));
    const auto k = f.sm.key(owned_id("dynamodb"));
    BOOST_REQUIRE(k.has_value());
    BOOST_TEST((k->manager == kms::key_manager::owned));
    BOOST_TEST(k->rotation_enabled);

    // The same key again, by name or id, and it opens what it made.
    const auto again =
        via(f, "dynamodb", "Encrypt", R"({"KeyId":")" + name + R"(","Plaintext":"aGk="})");
    BOOST_REQUIRE_MESSAGE(again.status == 200U, again.type());
    BOOST_TEST(again.str("KeyId") == fixture::arn(owned_id("dynamodb")));
    const auto d = via(f, "dynamodb", "Decrypt",
                       R"({"CiphertextBlob":")" + again.str("CiphertextBlob") + R"("})");
    BOOST_REQUIRE_MESSAGE(d.status == 200U, d.type());
    BOOST_TEST(d.str("Plaintext") == "aGk=");
    const auto md = via(f, "dynamodb", "DescribeKey", kid(owned_id("dynamodb")));
    BOOST_REQUIRE(md.status == 200U);
    BOOST_TEST(md.str("KeyMetadata", "KeyManager") == "AWS");

    // Each account has its own.
    const auto other =
        via(f, "dynamodb", "Encrypt", R"({"KeyId":")" + name + R"(","Plaintext":"aGk="})", k_other);
    BOOST_REQUIRE_MESSAGE(other.status == 200U, other.type());
    BOOST_TEST(other.str("KeyId").find(owned_id("dynamodb", k_other)) != std::string::npos);
    BOOST_TEST(owned_id("dynamodb") != owned_id("dynamodb", k_other));
    BOOST_TEST(owned_id("dynamodb") != managed_id("dynamodb"));
}

BOOST_AUTO_TEST_CASE(an_owned_key_answers_only_its_own_service) {
    fixture f;
    const auto name = kms::owned_key_name("dynamodb");
    const auto e =
        via(f, "dynamodb", "Encrypt", R"({"KeyId":")" + name + R"(","Plaintext":"aGk="})");
    BOOST_REQUIRE(e.status == 200U);
    const auto blob = R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})";
    const auto id = owned_id("dynamodb");

    // Another service: no such key, by name, id or ciphertext.
    BOOST_TEST(
        via(f, "kinesis", "Encrypt", R"({"KeyId":")" + name + R"(","Plaintext":"aGk="})").type() ==
        "NotFoundException");
    BOOST_TEST(via(f, "kinesis", "DescribeKey", kid(id)).type() == "NotFoundException");
    BOOST_TEST(via(f, "kinesis", "Decrypt", blob).status != 200U);
    // Kinesis naming it does not make Kinesis's own owned key either.
    BOOST_TEST(!f.sm.key(owned_id("kinesis")).has_value());

    // The account itself, directly: not listed, not visible, not usable,
    // and no change to it is allowed.
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().empty());
    BOOST_TEST(describe(f, id).type() == "NotFoundException");
    BOOST_TEST(describe(f, name).type() == "NotFoundException");
    BOOST_TEST(f.call("Decrypt", blob).status != 200U);
    for (const auto& [op, body] : std::initializer_list<std::pair<const char*, std::string>>{
             {"DisableKey", kid(id)},
             {"ScheduleKeyDeletion", kid(id)},
             {"DisableKeyRotation", kid(id)},
             {"GetKeyPolicy", R"({"KeyId":")" + id + R"(","PolicyName":"default"})"},
             {"CreateAlias", R"({"AliasName":"alias/mine","TargetKeyId":")" + id + R"("})"},
             {"CreateGrant", R"({"KeyId":")" + id +
                                 R"(","GranteePrincipal":"arn:aws:iam::111122223333:root",)"
                                 R"("Operations":["Decrypt"]})"},
         }) {
        const auto r = f.call(op, body);
        BOOST_TEST(r.status != 200U, op << " was allowed");
    }
    // The catalog refuses the changes too, whoever asks.
    BOOST_TEST((kms::service_managed(kms::key_manager::owned)));
    BOOST_TEST(via(f, "dynamodb", "Decrypt", blob).status == 200U);
}

BOOST_AUTO_TEST_CASE(owned_names_of_unknown_services_are_not_found) {
    fixture f;
    BOOST_TEST(!kms::owned_service_of("alias/aws/s3/owned").has_value());
    BOOST_TEST(!kms::owned_service_of("alias/aws//owned").has_value());
    BOOST_TEST(!kms::owned_service_of("alias/aws/dynamodb").has_value());
    BOOST_TEST(kms::owned_service_of("alias/aws/kinesis/owned")->name == "kinesis");
    BOOST_TEST(
        via(f, "s3", "Encrypt", R"({"KeyId":"alias/aws/s3/owned","Plaintext":"aGk="})").type() ==
        "NotFoundException");
}
