// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 10 (Requirements 8.1-8.4): CreateGrant, ListGrants,
// ListRetirableGrants, RetireGrant and RevokeGrant through signed requests,
// and grants allowing what the policy refuses: the operations a grant
// lists, encryption context constraints, an explicit deny still winning,
// grants made under a grant, grant tokens, retirement rules and the
// operations AWS allows for each key type.

#define BOOST_TEST_MODULE kms_grants_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_grants.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)

namespace {

const std::string k_reader = "arn:aws:iam::111122223333:user/reader";
const std::string k_admin = "arn:aws:iam::111122223333:user/admin";

auto asked_has(const az::authz_request& r, std::string_view key, std::string_view value) -> bool {
    return std::any_of(r.keys.begin(), r.keys.end(), [&](const auto& kv) {
        return kv.first == key &&
               std::find(kv.second.begin(), kv.second.end(), value) != kv.second.end();
    });
}

/// CreateGrant's body: `extra` is more members, already JSON.
auto grant_body(std::string_view id, std::string_view grantee, std::string_view ops,
                std::string_view extra = {}) -> std::string {
    return R"({"KeyId":")" + std::string(id) + R"(","GranteePrincipal":")" + std::string(grantee) +
           R"(","Operations":)" + std::string(ops) +
           (extra.empty() ? "" : "," + std::string(extra)) + "}";
}

auto encrypt_body(std::string_view id, std::string_view context = "{}", std::string_view extra = {})
    -> std::string {
    return R"({"KeyId":")" + std::string(id) + R"(","Plaintext":"c2VjcmV0","EncryptionContext":)" +
           std::string(context) + (extra.empty() ? "" : "," + std::string(extra)) + "}";
}

/// A grant made by the admin; its id.
auto make_grant(fixture& f, std::string_view id, std::string_view grantee, std::string_view ops,
                std::string_view extra = {}) -> std::string {
    const auto r = f.call("CreateGrant", grant_body(id, grantee, ops, extra));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    return r.str("GrantId");
}

}  // namespace

BOOST_AUTO_TEST_CASE(create_grant_answers_an_id_and_token_and_list_grants_shows_it) {
    fixture f;
    const auto id = f.create();
    const auto r = f.call("CreateGrant",
                          grant_body(id, k_reader, R"(["Encrypt","Decrypt","Encrypt"])",
                                     R"("Name":"app","RetiringPrincipal":")" + k_admin + R"(")"));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    const auto gid = r.str("GrantId");
    BOOST_TEST(gid.size() == 64U);
    BOOST_TEST(gid.find_first_not_of("0123456789abcdef") == std::string::npos);
    const auto token = kms::parse_grant_token(r.str("GrantToken"));
    BOOST_REQUIRE(token.has_value());
    BOOST_TEST(token->key_id == id);
    BOOST_TEST(token->grant_id == gid);

    // The request IAM saw carries the grant's facts.
    const auto& q = f.auth.asked.back();
    BOOST_TEST(q.action == "kms:CreateGrant");
    BOOST_TEST(asked_has(q, "kms:GrantOperations", "Encrypt"));
    BOOST_TEST(asked_has(q, "kms:GrantOperations", "Decrypt"));
    BOOST_TEST(asked_has(q, "kms:GranteePrincipal", k_reader));
    BOOST_TEST(asked_has(q, "kms:RetiringPrincipal", k_admin));
    BOOST_TEST(asked_has(q, "kms:GrantIsForAWSResource", "false"));

    const auto l = f.call("ListGrants", kid(id));
    BOOST_REQUIRE_MESSAGE(l.status == 200U, l.type() + ": " + l.message());
    const auto& grants = l.body.at("Grants").as_array();
    BOOST_REQUIRE(grants.size() == 1U);
    const auto& g = grants[0].as_object();
    BOOST_TEST(g.at("GrantId").as_string() == gid);
    BOOST_TEST(g.at("KeyId").as_string() == fixture::arn(id));
    BOOST_TEST(g.at("Name").as_string() == "app");
    BOOST_TEST(g.at("GranteePrincipal").as_string() == k_reader);
    BOOST_TEST(g.at("RetiringPrincipal").as_string() == k_admin);
    BOOST_TEST(g.at("IssuingAccount").as_string() == "arn:aws:iam::111122223333:root");
    BOOST_TEST(g.at("Operations").as_array().size() == 2U);  // duplicates collapse
    BOOST_TEST(g.at("CreationDate").as_double() == static_cast<double>(f.now) / 1000.0);
    BOOST_TEST(!g.contains("Constraints"));
    BOOST_TEST(l.body.at("Truncated").as_bool() == false);
}

BOOST_AUTO_TEST_CASE(list_grants_filters_and_pages) {
    fixture f;
    const auto id = f.create();
    std::vector<std::string> ids;
    for (int i = 0; i < 3; ++i) {
        ids.push_back(make_grant(f, id, i == 0 ? k_admin : k_reader, R"(["Encrypt"])"));
    }
    std::sort(ids.begin(), ids.end());
    const auto page1 = f.call("ListGrants", R"({"KeyId":")" + id + R"(","Limit":2})");
    BOOST_TEST(page1.body.at("Grants").as_array().size() == 2U);
    BOOST_TEST(page1.body.at("Truncated").as_bool());
    const auto next = page1.str("NextMarker");
    const auto page2 =
        f.call("ListGrants", R"({"KeyId":")" + id + R"(","Limit":2,"Marker":")" + next + R"("})");
    BOOST_TEST(page2.body.at("Grants").as_array().size() == 1U);
    BOOST_TEST(page2.body.at("Truncated").as_bool() == false);
    BOOST_TEST(page2.body.at("Grants").as_array()[0].as_object().at("GrantId").as_string() ==
               ids[2]);

    const auto one =
        f.call("ListGrants", R"({"KeyId":")" + id + R"(","GrantId":")" + ids[1] + R"("})");
    BOOST_TEST(one.body.at("Grants").as_array().size() == 1U);
    const auto readers = f.call(
        "ListGrants", R"({"KeyId":")" + id + R"(","GranteePrincipal":")" + k_reader + R"("})");
    BOOST_TEST(readers.body.at("Grants").as_array().size() == 2U);
    // Listing is read-only, so the read-only key may.
    BOOST_TEST(f.call("ListGrants", kid(id), "AKIDREAD").status == 200U);
}

BOOST_AUTO_TEST_CASE(a_grant_allows_what_the_policy_refuses) {
    fixture f;
    const auto id = f.create();
    // The read-only role may not encrypt...
    BOOST_TEST(f.call("Encrypt", encrypt_body(id), "AKIDREAD").type() == "AccessDeniedException");
    const auto gid = make_grant(f, id, k_reader, R"(["Encrypt","Decrypt"])");
    // ...until a grant names it.
    const auto e = f.call("Encrypt", encrypt_body(id), "AKIDREAD");
    BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
    const auto d =
        f.call("Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})", "AKIDREAD");
    BOOST_TEST(d.status == 200U);
    // Only the operations it lists.
    BOOST_TEST(
        f.call("GenerateDataKey", R"({"KeyId":")" + id + R"(","KeySpec":"AES_256"})", "AKIDREAD")
            .type() == "AccessDeniedException");
    BOOST_TEST(f.call("DisableKey", kid(id), "AKIDREAD").type() == "AccessDeniedException");
    // Only for its key.
    const auto other = f.create();
    BOOST_TEST(f.call("Encrypt", encrypt_body(other), "AKIDREAD").type() ==
               "AccessDeniedException");

    // An explicit deny in a policy beats a grant.
    f.auth.decide = [](const az::principal_context&, const az::authz_request& q) {
        az::authz_decision dd;
        dd.allowed = false;
        dd.explicit_deny = q.action == "kms:Encrypt";
        return dd;
    };
    BOOST_TEST(f.call("Encrypt", encrypt_body(id), "AKIDREAD").type() == "AccessDeniedException");
    BOOST_TEST(
        f.call("Decrypt", R"({"CiphertextBlob":")" + e.str("CiphertextBlob") + R"("})", "AKIDREAD")
            .status == 200U);
    f.auth.decide = nullptr;

    // Revoked, it allows nothing.
    const auto rv =
        f.call("RevokeGrant", R"({"KeyId":")" + id + R"(","GrantId":")" + gid + R"("})");
    BOOST_REQUIRE_MESSAGE(rv.status == 200U, rv.type() + ": " + rv.message());
    BOOST_TEST(f.call("Encrypt", encrypt_body(id), "AKIDREAD").type() == "AccessDeniedException");
    BOOST_TEST(
        f.call("RevokeGrant", R"({"KeyId":")" + id + R"(","GrantId":")" + gid + R"("})").type() ==
        "NotFoundException");
    // Revoking is a policy decision: the read-only role may not.
    const auto g2 = make_grant(f, id, k_reader, R"(["Encrypt"])");
    BOOST_TEST(
        f.call("RevokeGrant", R"({"KeyId":")" + id + R"(","GrantId":")" + g2 + R"("})", "AKIDREAD")
            .type() == "AccessDeniedException");
}

BOOST_AUTO_TEST_CASE(signing_mac_and_describe_grants) {
    fixture f;
    const auto sig = f.create(R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"})");
    const auto mac = f.create(R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})");
    const std::string sign =
        R"({"KeyId":")" + sig + R"(","Message":"bWVzc2FnZQ==","SigningAlgorithm":"ECDSA_SHA_256"})";
    const std::string gen =
        R"({"KeyId":")" + mac + R"(","Message":"bWVzc2FnZQ==","MacAlgorithm":"HMAC_SHA_256"})";
    BOOST_TEST(f.call("Sign", sign, "AKIDREAD").type() == "AccessDeniedException");
    BOOST_TEST(f.call("GenerateMac", gen, "AKIDREAD").type() == "AccessDeniedException");
    make_grant(f, sig, k_reader, R"(["Sign"])");
    make_grant(f, mac, k_reader, R"(["GenerateMac"])");
    BOOST_TEST(f.call("Sign", sign, "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("GenerateMac", gen, "AKIDREAD").status == 200U);

    // DescribeKey by grant, for a principal no static role knows.
    f.auth.decide = [](const az::principal_context&, const az::authz_request&) {
        return az::authz_decision{};
    };
    BOOST_TEST(f.call("DescribeKey", kid(sig), "AKIDREAD").type() == "AccessDeniedException");
    f.auth.decide = nullptr;
    make_grant(f, sig, k_reader, R"(["DescribeKey"])");
    f.auth.decide = [](const az::principal_context&, const az::authz_request&) {
        return az::authz_decision{};
    };
    BOOST_TEST(f.call("DescribeKey", kid(sig), "AKIDREAD").status == 200U);
}

BOOST_AUTO_TEST_CASE(encryption_context_constraints) {
    fixture f;
    const auto id = f.create();
    make_grant(f, id, k_reader, R"(["Encrypt","DescribeKey"])",
               R"("Constraints":{"EncryptionContextSubset":{"dept":"a"}})");
    BOOST_TEST(f.call("Encrypt", encrypt_body(id, R"({"dept":"a","x":"1"})"), "AKIDREAD").status ==
               200U);
    BOOST_TEST(f.call("Encrypt", encrypt_body(id, R"({"dept":"a"})"), "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("Encrypt", encrypt_body(id, R"({"dept":"b"})"), "AKIDREAD").type() ==
               "AccessDeniedException");
    BOOST_TEST(f.call("Encrypt", encrypt_body(id), "AKIDREAD").type() == "AccessDeniedException");
    // A constrained grant never allows an operation without a context.
    f.auth.decide = [](const az::principal_context&, const az::authz_request&) {
        return az::authz_decision{};
    };
    BOOST_TEST(f.call("DescribeKey", kid(id), "AKIDREAD").type() == "AccessDeniedException");
    f.auth.decide = nullptr;

    const auto id2 = f.create();
    make_grant(f, id2, k_reader, R"(["Encrypt"])",
               R"("Constraints":{"EncryptionContextEquals":{"dept":"a"}})");
    BOOST_TEST(f.call("Encrypt", encrypt_body(id2, R"({"dept":"a"})"), "AKIDREAD").status == 200U);
    BOOST_TEST(f.call("Encrypt", encrypt_body(id2, R"({"dept":"a","x":"1"})"), "AKIDREAD").type() ==
               "AccessDeniedException");

    // ListGrants shows the constraint; IAM saw its pairs as condition keys.
    const auto l = f.call("ListGrants", kid(id2));
    const auto& g = l.body.at("Grants").as_array()[0].as_object();
    BOOST_TEST(g.at("Constraints")
                   .as_object()
                   .at("EncryptionContextEquals")
                   .as_object()
                   .at("dept")
                   .as_string() == "a");

    // Both kinds at once, or a constraint on a key without a context, are
    // refused.
    BOOST_TEST(
        f.call("CreateGrant", grant_body(id, k_reader, R"(["Encrypt"])",
                                         R"("Constraints":{"EncryptionContextSubset":{"a":"1"},)"
                                         R"("EncryptionContextEquals":{"a":"1"}})"))
            .type() == "ValidationException");
    const auto rsa = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    BOOST_TEST(f.call("CreateGrant", grant_body(rsa, k_reader, R"(["Encrypt"])",
                                                R"("Constraints":{"EncryptionContextSubset":)"
                                                R"({"a":"1"}})"))
                   .type() == "ValidationException");
}

BOOST_AUTO_TEST_CASE(grant_operations_must_fit_the_key) {
    fixture f;
    const auto sym = f.create();
    const auto rsa = f.create(R"({"KeySpec":"RSA_2048","KeyUsage":"ENCRYPT_DECRYPT"})");
    const auto sig = f.create(R"({"KeySpec":"ECC_NIST_P256","KeyUsage":"SIGN_VERIFY"})");
    const auto mac = f.create(R"({"KeySpec":"HMAC_256","KeyUsage":"GENERATE_VERIFY_MAC"})");
    const auto refused = [&](std::string_view key, std::string_view ops) {
        return f.call("CreateGrant", grant_body(key, k_reader, ops)).type() ==
               "ValidationException";
    };
    BOOST_TEST(refused(sym, R"(["Sign"])"));
    BOOST_TEST(refused(sym, R"(["GetPublicKey"])"));
    BOOST_TEST(refused(sym, R"(["EnableKey"])"));
    BOOST_TEST(refused(sym, R"([])"));
    BOOST_TEST(refused(sym, R"(["DeriveSharedSecret"])"));
    BOOST_TEST(refused(rsa, R"(["GenerateDataKey"])"));
    BOOST_TEST(refused(sig, R"(["Encrypt"])"));
    BOOST_TEST(refused(mac, R"(["Sign"])"));
    BOOST_TEST(!refused(rsa, R"(["Encrypt","Decrypt","GetPublicKey","DescribeKey"])"));
    BOOST_TEST(!refused(sig, R"(["Sign","Verify","GetPublicKey","CreateGrant","RetireGrant"])"));
    BOOST_TEST(!refused(mac, R"(["GenerateMac","VerifyMac"])"));
    BOOST_TEST(!refused(sym, R"(["GenerateDataKeyPair","ReEncryptFrom","ReEncryptTo"])"));
    BOOST_TEST(
        f.call("CreateGrant", R"({"KeyId":")" + sym + R"(","Operations":["Encrypt"]})").type() ==
        "ValidationException");

    const auto before = f.sm.grants(sym).size();
    // Not on a key pending deletion; DryRun stops before writing.
    BOOST_TEST(
        f.call("CreateGrant", grant_body(sym, k_reader, R"(["Encrypt"])", R"("DryRun":true)"))
            .type() == "DryRunOperationException");
    BOOST_TEST(f.sm.grants(sym).size() == before);
    BOOST_REQUIRE(f.call("ScheduleKeyDeletion", kid(sym)).status == 200U);
    BOOST_TEST(f.call("CreateGrant", grant_body(sym, k_reader, R"(["Encrypt"])")).type() ==
               "KMSInvalidStateException");
}

BOOST_AUTO_TEST_CASE(the_same_name_and_parameters_are_the_same_grant) {
    fixture f;
    const auto id = f.create();
    const auto a = make_grant(f, id, k_reader, R"(["Encrypt"])", R"("Name":"retry")");
    BOOST_TEST(make_grant(f, id, k_reader, R"(["Encrypt"])", R"("Name":"retry")") == a);
    BOOST_TEST(make_grant(f, id, k_reader, R"(["Decrypt"])", R"("Name":"retry")") != a);
    // Without a name every call is a new grant.
    BOOST_TEST(make_grant(f, id, k_reader, R"(["Encrypt"])") !=
               make_grant(f, id, k_reader, R"(["Encrypt"])"));
    BOOST_TEST(f.sm.grants(id).size() == 4U);
}

BOOST_AUTO_TEST_CASE(a_grant_with_create_grant_passes_on_no_more_than_it_holds) {
    fixture f;
    const auto id = f.create();
    make_grant(f, id, k_reader, R"(["Encrypt","CreateGrant"])");
    BOOST_TEST(
        f.call("CreateGrant", grant_body(id, k_admin, R"(["Encrypt"])"), "AKIDREAD").status ==
        200U);
    BOOST_TEST(
        f.call("CreateGrant", grant_body(id, k_admin, R"(["Decrypt"])"), "AKIDREAD").type() ==
        "AccessDeniedException");

    // A constrained parent's children keep its constraint.
    const auto id2 = f.create();
    make_grant(f, id2, k_reader, R"(["Encrypt","CreateGrant"])",
               R"("Constraints":{"EncryptionContextSubset":{"dept":"a"}})");
    BOOST_TEST(
        f.call("CreateGrant", grant_body(id2, k_admin, R"(["Encrypt"])"), "AKIDREAD").type() ==
        "AccessDeniedException");
    BOOST_TEST(f.call("CreateGrant",
                      grant_body(id2, k_admin, R"(["Encrypt"])",
                                 R"("Constraints":{"EncryptionContextSubset":)"
                                 R"({"dept":"a","team":"x"}})"),
                      "AKIDREAD")
                   .status == 200U);
    BOOST_TEST(f.call("CreateGrant",
                      grant_body(id2, k_admin, R"(["Encrypt"])",
                                 R"("Constraints":{"EncryptionContextEquals":{"dept":"b"}})"),
                      "AKIDREAD")
                   .type() == "AccessDeniedException");
}

BOOST_AUTO_TEST_CASE(retire_grant_follows_the_grant) {
    fixture f;
    const auto id = f.create();
    // The retiring principal may retire, by token.
    const auto r = f.call(
        "CreateGrant",
        grant_body(id, k_admin, R"(["Encrypt"])", R"("RetiringPrincipal":")" + k_reader + R"(")"));
    const auto token = r.str("GrantToken");
    const auto rt = f.call("RetireGrant", R"({"GrantToken":")" + token + R"("})", "AKIDREAD");
    BOOST_REQUIRE_MESSAGE(rt.status == 200U, rt.type() + ": " + rt.message());
    BOOST_TEST(f.sm.grants(id).empty());
    BOOST_TEST(f.call("RetireGrant", R"({"GrantToken":")" + token + R"("})", "AKIDREAD").type() ==
               "NotFoundException");

    // The grantee only when the grant lists RetireGrant.
    const auto g1 = make_grant(f, id, k_reader, R"(["Encrypt"])");
    const auto by_id = R"({"KeyId":")" + fixture::arn(id) + R"(","GrantId":")" + g1 + R"("})";
    BOOST_TEST(f.call("RetireGrant", by_id, "AKIDREAD").type() == "AccessDeniedException");
    const auto g2 = make_grant(f, id, k_reader, R"(["Encrypt","RetireGrant"])");
    BOOST_TEST(
        f.call("RetireGrant", R"({"KeyId":")" + id + R"(","GrantId":")" + g2 + R"("})", "AKIDREAD")
            .status == 200U);
    // Another account's admin, named nowhere, may not.
    BOOST_TEST(f.call("RetireGrant", by_id, "AKIDOTHER").type() == "AccessDeniedException");
    BOOST_TEST(f.sm.grant(id, g1).has_value());

    BOOST_TEST(f.call("RetireGrant", R"({"GrantToken":"not-a-token"})").type() ==
               "InvalidGrantTokenException");
    BOOST_TEST(f.call("RetireGrant", R"({"GrantId":"abc"})").type() == "ValidationException");
}

BOOST_AUTO_TEST_CASE(grant_tokens_are_checked_and_carry_no_authority) {
    fixture f;
    const auto id = f.create();
    const auto other = f.create();
    const auto r = f.call("CreateGrant", grant_body(id, k_reader, R"(["Encrypt"])"));
    const auto token = r.str("GrantToken");
    const auto with = std::string(R"("GrantTokens":[")") + token + R"("])";
    BOOST_TEST(f.call("Encrypt", encrypt_body(id, "{}", with), "AKIDREAD").status == 200U);
    // A valid token for one key does not open another.
    BOOST_TEST(f.call("Encrypt", encrypt_body(other, "{}", with), "AKIDREAD").type() ==
               "AccessDeniedException");
    BOOST_TEST(f.call("Encrypt", encrypt_body(id, "{}", R"("GrantTokens":["forged"])"), "AKIDREAD")
                   .type() == "InvalidGrantTokenException");
}

BOOST_AUTO_TEST_CASE(list_retirable_grants_spans_the_accounts_keys) {
    fixture f;
    const auto a = f.create();
    const auto b = f.create();
    const auto retiring = R"("RetiringPrincipal":")" + k_reader + R"(")";
    make_grant(f, a, k_admin, R"(["Encrypt"])", retiring);
    make_grant(f, b, k_admin, R"(["Encrypt"])", retiring);
    make_grant(f, b, k_admin, R"(["Encrypt"])", retiring);
    make_grant(f, b, k_admin, R"(["Encrypt"])");  // not retirable by the reader
    const auto all =
        f.call("ListRetirableGrants", R"({"RetiringPrincipal":")" + k_reader + R"("})");
    BOOST_REQUIRE_MESSAGE(all.status == 200U, all.type() + ": " + all.message());
    BOOST_TEST(all.body.at("Grants").as_array().size() == 3U);
    BOOST_TEST(f.auth.asked.back().action == "kms:ListRetirableGrants");
    BOOST_TEST(f.auth.asked.back().resource == "*");

    const auto p1 =
        f.call("ListRetirableGrants", R"({"RetiringPrincipal":")" + k_reader + R"(","Limit":2})");
    BOOST_TEST(p1.body.at("Grants").as_array().size() == 2U);
    BOOST_REQUIRE(p1.body.at("Truncated").as_bool());
    const auto p2 = f.call("ListRetirableGrants", R"({"RetiringPrincipal":")" + k_reader +
                                                      R"(","Limit":2,"Marker":")" +
                                                      p1.str("NextMarker") + R"("})");
    BOOST_TEST(p2.body.at("Grants").as_array().size() == 1U);
    BOOST_TEST(f.call("ListRetirableGrants", "{}").type() == "ValidationException");
}

BOOST_AUTO_TEST_CASE(static_key_deployments_store_grants_but_do_not_evaluate_them) {
    // Requirement 7.7: with IAM off the static roles decide alone.
    fixture f;
    kms::front_end_config cfg;
    cfg.evaluate_grants = false;
    kms::front_end<test_authorizer> fe{cfg, f.auth};
    f.api.register_on(fe);
    f.grants.register_on(fe);
    f.crypto.register_on(fe);
    const auto call = [&](std::string_view op, const std::string& body, std::string_view akid) {
        return fixture::answer(fe.handle(sign(request(op, body), akid)));
    };
    const auto id = f.create();
    const auto made =
        call("CreateGrant", grant_body(id, k_reader, R"(["Encrypt","CreateGrant"])"), "AKIDADMIN");
    BOOST_REQUIRE_MESSAGE(made.status == 200U, made.type() + ": " + made.message());
    BOOST_TEST(call("ListGrants", kid(id), "AKIDREAD").body.at("Grants").as_array().size() == 1U);
    BOOST_TEST(call("Encrypt", encrypt_body(id), "AKIDREAD").type() == "AccessDeniedException");
    BOOST_TEST(call("CreateGrant", grant_body(id, k_admin, R"(["Encrypt"])"), "AKIDREAD").type() ==
               "AccessDeniedException");
    // The same grant through the IAM-mode front end allows it.
    BOOST_TEST(f.call("Encrypt", encrypt_body(id), "AKIDREAD").status == 200U);
}
