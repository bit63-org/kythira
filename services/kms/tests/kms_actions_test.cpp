// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 2 (Requirement 7.4, 7.7): the generated `kms` action table and
// operation map, held to the pinned model, to the condition keys the spec
// names and to what the static-key authorizer allows.

#define BOOST_TEST_MODULE kms_actions_test

#include <boost/test/unit_test.hpp>

#include <kythira/kms/kms_actions.hpp>
#include <kythira/kms/model/kms_model.hpp>

#include <raft/static_key_authorizer.hpp>

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace kms = kythira::kms;
namespace az = kythira::aws_auth;

namespace {

auto find_action(std::string_view name) -> const az::action_entry* {
    static const auto table = kms::kms_actions();
    for (const auto& a : table.actions) {
        if (a.name == name) {
            return &a;
        }
    }
    return nullptr;
}

constexpr std::string_view key_arn = "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}";
constexpr std::string_view alias_arn = "arn:${Partition}:kms:${Region}:${Account}:alias/${Alias}";

}  // namespace

BOOST_AUTO_TEST_CASE(every_model_operation_has_its_actions) {
    // The front end authorizes an operation as the actions the map lists,
    // so a model operation without an entry would go unauthorized.
    for (const auto& op : kms::kms_model::k_operations) {
        BOOST_TEST_INFO(op.name);
        const auto* entry = kms::find_operation_actions(op.name);
        BOOST_REQUIRE(entry != nullptr);
        BOOST_TEST(!entry->actions[0].empty());
        for (const auto& a : entry->actions) {
            if (!a.empty()) {
                BOOST_TEST_INFO(a);
                BOOST_TEST(find_action(a) != nullptr);
            }
        }
    }
    BOOST_TEST(kms::find_operation_actions("PutRecord") == nullptr);
    const auto& re = kms::find_operation_actions("ReEncrypt")->actions;
    BOOST_TEST((std::find(re.begin(), re.end(), "ReEncryptFrom") != re.end()));
    BOOST_TEST((std::find(re.begin(), re.end(), "ReEncryptTo") != re.end()));
}

BOOST_AUTO_TEST_CASE(actions_act_on_keys_and_aliases) {
    BOOST_TEST(kms::kms_actions().service_prefix == "kms");
    BOOST_TEST((find_action("Encrypt")->resource_templates ==
                std::vector<std::string>{std::string(key_arn)}));
    BOOST_TEST((find_action("CreateAlias")->resource_templates ==
                std::vector<std::string>{std::string(alias_arn), std::string(key_arn)}));
    for (const auto* any : {"CreateKey", "ListKeys", "ListAliases", "GenerateRandom"}) {
        BOOST_TEST_INFO(any);
        BOOST_TEST((find_action(any)->resource_templates == std::vector<std::string>{"*"}));
    }
    BOOST_TEST(!kms::find_operation_actions("DescribeKey")->writes);
    BOOST_TEST(!kms::find_operation_actions("ListAliases")->writes);
    BOOST_TEST(kms::find_operation_actions("Encrypt")->writes);
    BOOST_TEST(kms::find_operation_actions("ScheduleKeyDeletion")->writes);
}

BOOST_AUTO_TEST_CASE(the_specs_condition_keys_are_registered) {
    std::set<std::string> keys;
    for (const auto& a : kms::kms_actions().actions) {
        keys.insert(a.condition_keys.begin(), a.condition_keys.end());
    }
    for (const auto* k : {"kms:CallerAccount",
                          "kms:EncryptionContext:${EncryptionContextKey}",
                          "kms:EncryptionContextKeys",
                          "kms:EncryptionAlgorithm",
                          "kms:SigningAlgorithm",
                          "kms:MacAlgorithm",
                          "kms:GrantOperations",
                          "kms:GrantIsForAWSResource",
                          "kms:GranteePrincipal",
                          "kms:RetiringPrincipal",
                          "kms:KeySpec",
                          "kms:KeyUsage",
                          "kms:KeyOrigin",
                          "kms:ViaService",
                          "kms:RequestAlias",
                          "kms:ResourceAliases",
                          "kms:DataKeyPairSpec",
                          "kms:MessageType",
                          "kms:BypassPolicyLockoutSafetyCheck",
                          "kms:ScheduleKeyDeletionPendingWindowInDays"}) {
        BOOST_TEST(keys.contains(k), k);
    }
    // The key's own keys apply to every action on a key.
    const auto& sign = find_action("Sign")->condition_keys;
    for (const auto* k : {"kms:KeySpec", "kms:KeyUsage", "kms:SigningAlgorithm", "kms:ViaService",
                          "aws:ResourceTag/${TagKey}"}) {
        BOOST_TEST((std::find(sign.begin(), sign.end(), k) != sign.end()), k);
    }
}

BOOST_AUTO_TEST_CASE(static_roles_split_describe_crypto_and_admin) {
    const auto now = std::chrono::system_clock::now();
    az::static_key_authorizer auth{
        std::vector<az::static_key>{
            {"AKIDR", "s", "111122223333", "r", az::static_role::read_only},
            {"AKIDW", "s", "111122223333", "w", az::static_role::read_write},
            {"AKIDA", "s", "111122223333", "a", az::static_role::admin},
        },
        "aws", [now] { return now; }};
    auth.register_service(kms::kms_static_roles());

    const auto principal = [](std::string_view name) {
        az::principal_context p;
        p.account = "111122223333";
        p.arn = "arn:aws:iam::111122223333:user/" + std::string(name);
        p.username = std::string(name);
        p.access_key_id = name == "r" ? "AKIDR" : name == "w" ? "AKIDW" : "AKIDA";
        return p;
    };
    const auto allowed = [&](std::string_view who, std::string_view action) {
        az::authz_request r;
        r.action = "kms:" + std::string(action);
        r.resource = "arn:aws:kms:us-east-1:111122223333:key/k1";
        return auth.authorize(principal(who), r).allowed;
    };

    for (const auto* read : {"DescribeKey", "ListKeys", "ListAliases", "GetKeyPolicy",
                             "GetPublicKey", "GetKeyRotationStatus", "ListResourceTags"}) {
        BOOST_TEST_INFO(read);
        BOOST_TEST(allowed("r", read));
        BOOST_TEST(allowed("w", read));
    }
    for (const auto* crypto : {"Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo",
                               "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
                               "GenerateRandom", "Sign", "Verify", "GenerateMac", "VerifyMac"}) {
        BOOST_TEST_INFO(crypto);
        BOOST_TEST(!allowed("r", crypto));
        BOOST_TEST(allowed("w", crypto));
    }
    for (const auto* admin :
         {"CreateKey", "ScheduleKeyDeletion", "DisableKey", "PutKeyPolicy", "CreateGrant",
          "RevokeGrant", "CreateAlias", "TagResource", "EnableKeyRotation"}) {
        BOOST_TEST_INFO(admin);
        BOOST_TEST(!allowed("w", admin));
        BOOST_TEST(allowed("a", admin));
    }
}
