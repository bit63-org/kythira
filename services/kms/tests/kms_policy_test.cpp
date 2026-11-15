// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 9 (Requirements 7.1, 7.2, 7.5 and 7.7): GetKeyPolicy, PutKeyPolicy
// and ListKeyPolicies through signed requests, the default key policy,
// AWS's lockout safety check on PutKeyPolicy and CreateKey, and the static
// roles when IAM is off. Policy evaluation itself is IAM's and is pinned by
// the corpus (services/iam/tests/corpus/evaluate/kms_key_policies.json);
// here a small stand-in evaluator reads the policy the request carries.

#define BOOST_TEST_MODULE kms_policy_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <algorithm>
#include <string>
#include <string_view>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

auto asked_has(const az::authz_request& r, std::string_view key, std::string_view value) -> bool {
    return std::any_of(r.keys.begin(), r.keys.end(), [&](const auto& kv) {
        return kv.first == key &&
               std::find(kv.second.begin(), kv.second.end(), value) != kv.second.end();
    });
}

/// A policy that lets `principal` do `action` on the key.
auto policy_for(std::string_view principal, std::string_view action) -> std::string {
    return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":")" +
           std::string(principal) + R"("},"Action":")" + std::string(action) +
           R"(","Resource":"*"}]})";
}

/// A stand-in for IAM's evaluator: PutKeyPolicy is allowed only when the
/// key policy the request carries names it (or kms:*); everything else is
/// allowed.
auto policy_reader(const az::principal_context&, const az::authz_request& r) -> az::authz_decision {
    az::authz_decision d;
    const auto policy = r.resource_policy.value_or("");
    d.allowed = r.action != "kms:PutKeyPolicy" ||
                policy.find("\"kms:PutKeyPolicy\"") != std::string::npos ||
                policy.find("\"kms:*\"") != std::string::npos;
    return d;
}

auto put_body(std::string_view id, const std::string& policy, std::string_view extra = {})
    -> std::string {
    json::object o{{"KeyId", id}, {"Policy", policy}};
    auto s = json::serialize(o);
    if (!extra.empty()) {
        s.insert(s.size() - 1, "," + std::string(extra));
    }
    return s;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_new_key_gets_the_default_policy) {
    fixture f;
    const auto id = f.create();
    const auto r = f.call("GetKeyPolicy", kid(id));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(r.str("PolicyName") == "default");
    BOOST_TEST(r.str("Policy") == kms::default_key_policy("aws", k_account));
    // The default delegates to the account: its root may do everything.
    const auto doc = json::parse(r.str("Policy")).as_object();
    const auto& st = doc.at("Statement").as_array().at(0).as_object();
    BOOST_TEST(st.at("Principal").as_object().at("AWS").as_string() ==
               "arn:aws:iam::" + std::string(k_account) + ":root");
    BOOST_TEST(st.at("Action").as_string() == "kms:*");

    // The request IAM sees: GetKeyPolicy on the key's ARN with its policy.
    BOOST_TEST(f.auth.asked.back().action == "kms:GetKeyPolicy");
    BOOST_TEST(f.auth.asked.back().resource == fixture::arn(id));
    BOOST_TEST(f.auth.asked.back().resource_policy.value_or("") == r.str("Policy"));
    BOOST_TEST((f.auth.asked.back().resource_kind == az::resource_policy_kind::key));

    // An explicit PolicyName must be "default"; KeyId takes no alias.
    BOOST_TEST(
        f.call("GetKeyPolicy", R"({"KeyId":")" + id + R"(","PolicyName":"default"})").status ==
        200U);
    BOOST_TEST(f.call("GetKeyPolicy", R"({"KeyId":")" + id + R"(","PolicyName":"other"})").type() ==
               "NotFoundException");
    BOOST_REQUIRE(
        f.call("CreateAlias", R"({"AliasName":"alias/p","TargetKeyId":")" + id + R"("})").status ==
        200U);
    BOOST_TEST(f.call("GetKeyPolicy", kid("alias/p")).type() == "NotFoundException");
    BOOST_TEST(f.call("GetKeyPolicy", kid(fixture::arn(id))).status == 200U);
}

BOOST_AUTO_TEST_CASE(list_key_policies_names_only_default) {
    fixture f;
    const auto id = f.create();
    const auto r = f.call("ListKeyPolicies", kid(id));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto& names = r.body.at("PolicyNames").as_array();
    BOOST_REQUIRE(names.size() == 1U);
    BOOST_TEST(names[0].as_string() == "default");
    BOOST_TEST(r.body.at("Truncated").as_bool() == false);
    BOOST_TEST(f.auth.asked.back().action == "kms:ListKeyPolicies");
    // A marker past the one policy ends the list.
    const auto past = f.call("ListKeyPolicies", R"({"KeyId":")" + id + R"(","Marker":"default"})");
    BOOST_TEST(past.body.at("PolicyNames").as_array().empty());
    BOOST_TEST(f.call("ListKeyPolicies", kid("1234abcd-0000-4000-8000-000000000000")).type() ==
               "NotFoundException");
}

BOOST_AUTO_TEST_CASE(put_key_policy_replaces_the_policy) {
    fixture f;
    const auto id = f.create();
    const auto old_policy = f.sm.key(id)->policy;
    const auto mine = policy_for("arn:aws:iam::111122223333:role/admin", "kms:*");
    const auto r = f.call("PutKeyPolicy", put_body(id, mine));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(f.sm.key(id)->policy == mine);
    BOOST_TEST(f.call("GetKeyPolicy", kid(id)).str("Policy") == mine);

    // Authorized against the policy in force, then checked for lockout
    // against the new one.
    BOOST_REQUIRE(f.auth.asked.size() >= 3U);
    const auto& first = f.auth.asked[f.auth.asked.size() - 3];
    const auto& lockout = f.auth.asked[f.auth.asked.size() - 2];
    BOOST_TEST(first.action == "kms:PutKeyPolicy");
    BOOST_TEST(first.resource_policy.value_or("") == old_policy);
    BOOST_TEST(lockout.action == "kms:PutKeyPolicy");
    BOOST_TEST(lockout.resource_policy.value_or("") == mine);

    // Refusals change nothing.
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, "not json")).type() ==
               "MalformedPolicyDocumentException");
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, "[1,2]")).type() ==
               "MalformedPolicyDocumentException");
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, "{\"x\":\"" + std::string(33000, 'a') + "\"}"))
                   .type() == "LimitExceededException");
    BOOST_TEST(f.call("PutKeyPolicy", kid(id)).type() == "ValidationException");
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, mine, R"("PolicyName":"other")")).type() ==
               "NotFoundException");
    BOOST_TEST(f.sm.key(id)->policy == mine);

    // A key pending deletion may still have its policy changed, so that it
    // can be recovered.
    BOOST_REQUIRE(f.call("ScheduleKeyDeletion", kid(id)).status == 200U);
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, old_policy)).status == 200U);
    BOOST_TEST(f.sm.key(id)->policy == old_policy);

    // The HSM is never needed.
    f.hsm_bound = false;
    BOOST_TEST(f.call("GetKeyPolicy", kid(id)).status == 200U);
}

BOOST_AUTO_TEST_CASE(put_key_policy_refuses_a_policy_that_locks_the_caller_out) {
    fixture f;
    const auto id = f.create();
    f.auth.decide = policy_reader;
    const auto before = f.sm.key(id)->policy;

    // Only Decrypt for the caller: they could never change it again.
    const auto locking = policy_for("arn:aws:iam::111122223333:role/admin", "kms:Decrypt");
    const auto r = f.call("PutKeyPolicy", put_body(id, locking));
    BOOST_TEST(r.type() == "MalformedPolicyDocumentException");
    BOOST_TEST(r.message().find("will not allow you to update the key policy") != std::string::npos,
               r.message());
    BOOST_TEST(f.sm.key(id)->policy == before);

    // Bypassing the check is the caller's own choice, visible to policies.
    const auto bypass =
        f.call("PutKeyPolicy", put_body(id, locking, R"("BypassPolicyLockoutSafetyCheck":true)"));
    BOOST_REQUIRE_MESSAGE(bypass.status == 200U, bypass.type() + ": " + bypass.message());
    BOOST_TEST(asked_has(f.auth.asked.back(), "kms:BypassPolicyLockoutSafetyCheck", "true"));
    BOOST_TEST(f.sm.key(id)->policy == locking);

    // And now, as AWS warns, the policy cannot be changed back.
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, before)).type() == "AccessDeniedException");
    BOOST_TEST(f.sm.key(id)->policy == locking);

    // An explicit false is the same as no bypass.
    const auto id2 = f.create();
    BOOST_TEST(
        f.call("PutKeyPolicy", put_body(id2, locking, R"("BypassPolicyLockoutSafetyCheck":false)"))
            .type() == "MalformedPolicyDocumentException");
    BOOST_TEST(std::any_of(f.auth.asked.begin(), f.auth.asked.end(), [](const auto& q) {
        return asked_has(q, "kms:BypassPolicyLockoutSafetyCheck", "false");
    }));
}

BOOST_AUTO_TEST_CASE(create_key_applies_the_lockout_check_to_a_given_policy) {
    fixture f;
    f.auth.decide = policy_reader;
    const auto locking = policy_for("arn:aws:iam::111122223333:role/admin", "kms:Encrypt");

    json::object body{{"Policy", locking}};
    const auto r = f.call("CreateKey", json::serialize(body));
    BOOST_TEST(r.type() == "MalformedPolicyDocumentException");
    // The lockout request names the key it would create, with the policy.
    const auto q = f.auth.asked.back();
    BOOST_TEST(f.call("ListKeys", "{}").body.at("Keys").as_array().empty());
    BOOST_TEST(q.action == "kms:PutKeyPolicy");
    BOOST_TEST(q.resource.find(":key/") != std::string::npos);
    BOOST_TEST(q.resource_policy.value_or("") == locking);
    BOOST_TEST((q.resource_kind == az::resource_policy_kind::key));

    body["BypassPolicyLockoutSafetyCheck"] = true;
    const auto id = f.create(json::serialize(body));
    BOOST_TEST(f.sm.key(id)->policy == locking);

    // The default policy is never checked: it delegates to the account.
    f.auth.asked.clear();
    const auto id2 = f.create();
    BOOST_TEST(std::none_of(f.auth.asked.begin(), f.auth.asked.end(),
                            [](const auto& a) { return a.action == "kms:PutKeyPolicy"; }));
    BOOST_TEST(f.sm.key(id2)->policy == kms::default_key_policy("aws", k_account));

    // A policy that allows the caller to change it passes.
    const auto ok = policy_for("arn:aws:iam::111122223333:role/admin", "kms:*");
    json::object fine{{"Policy", ok}};
    BOOST_TEST(f.sm.key(f.create(json::serialize(fine)))->policy == ok);
}

BOOST_AUTO_TEST_CASE(static_roles_decide_with_iam_off) {
    // The fixture's default authorizer is the static one, which ignores key
    // policies: read-only may read the policy, only admin may change it.
    fixture f;
    const auto id = f.create();
    BOOST_TEST(f.call("GetKeyPolicy", kid(id), "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("ListKeyPolicies", kid(id), "AKIDREAD").status == 200U);
    const auto mine = policy_for("arn:aws:iam::111122223333:role/admin", "kms:*");
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, mine), "AKIDREAD").type() ==
               "AccessDeniedException");
    BOOST_TEST(f.sm.key(id)->policy == kms::default_key_policy("aws", k_account));

    // A policy that denies everyone is ignored by the static roles, so the
    // admin can still use and change the key; the lockout check, which asks
    // the same authorizer, passes for the admin.
    const std::string deny_all =
        R"({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*",)"
        R"("Action":"kms:*","Resource":"*"}]})";
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, deny_all)).status == 200U);
    BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
    BOOST_TEST(f.call("PutKeyPolicy", put_body(id, mine)).status == 200U);

    // Another account's admin is refused across accounts.
    BOOST_TEST(f.call("GetKeyPolicy", kid(fixture::arn(id)), "AKIDOTHER").type() ==
               "AccessDeniedException");
}
