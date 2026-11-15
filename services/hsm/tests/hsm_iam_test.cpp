// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 14b (Requirement 8.4): which identities are IAM principals, the
// `hsm` action table, the request IAM is asked, and the decision cache.

#define BOOST_TEST_MODULE hsm_iam_test

#include <boost/test/unit_test.hpp>

#include <kythira/hsm/hsm_iam.hpp>

#include <chrono>
#include <set>
#include <string>
#include <vector>

namespace hsm = kythira::hsm;
namespace aws_auth = kythira::aws_auth;

BOOST_AUTO_TEST_CASE(user_and_role_arns_are_principals_and_nothing_else) {
    const auto user = hsm::iam_principal("arn:aws:iam::123456789012:user/ops/alice");
    BOOST_REQUIRE(user.has_value());
    BOOST_TEST((user->type == aws_auth::principal_type::user));
    BOOST_TEST(user->account == "123456789012");
    BOOST_TEST(user->arn == "arn:aws:iam::123456789012:user/ops/alice");
    BOOST_TEST(user->username == "alice");

    const auto role = hsm::iam_principal("arn:aws-cn:iam::123456789012:role/signer");
    BOOST_REQUIRE(role.has_value());
    BOOST_TEST((role->type == aws_auth::principal_type::assumed_role));
    BOOST_TEST(role->role_arn == "arn:aws-cn:iam::123456789012:role/signer");
    BOOST_TEST(role->role_name == "signer");
    BOOST_TEST(role->arn == "arn:aws-cn:sts::123456789012:assumed-role/signer/hsm");

    for (const auto* other :
         {"spiffe://apps/ca", "app-a", "arn:aws:iam::123456789012:root",
          "arn:aws:iam::123456789012:group/admins", "arn:aws:iam:us-east-1:123456789012:user/a",
          "arn:aws:iam::12345:user/a", "arn:aws:iam::12345678901x:user/a",
          "arn:aws:sts::123456789012:assumed-role/r/s", "arn:aws:iam::123456789012:user/",
          "arn::iam::123456789012:user/a", "arn:aws:iam::123456789012"}) {
        BOOST_TEST(!hsm::iam_principal(other).has_value(), other);
    }
}

BOOST_AUTO_TEST_CASE(every_action_acts_on_a_token) {
    const auto t = hsm::hsm_actions();
    BOOST_TEST(t.service_prefix == "hsm");
    std::set<std::string> names;
    for (const auto& a : t.actions) {
        names.insert(a.name);
        BOOST_REQUIRE(a.resource_templates.size() == 1U);
        BOOST_TEST(a.resource_templates[0] ==
                   "arn:${Partition}:hsm:${Region}:${Account}:token/${TokenId}");
    }
    for (const auto* n : {"OpenToken", "Sign", "Verify", "Encrypt", "Decrypt", "GenerateKey",
                          "DestroyObject", "WrapKey", "UnwrapKey", "DeriveKey"}) {
        BOOST_TEST(names.contains(n), n);
    }
}

BOOST_AUTO_TEST_CASE(iam_is_asked_about_the_tokens_arn_and_answers_are_kept) {
    std::vector<aws_auth::authz_request> asked;
    std::vector<std::string> who;
    bool allow = true;
    auto now = std::chrono::steady_clock::time_point{};
    hsm::iam_token_config cfg;
    cfg.partition = "aws";
    cfg.region = "eu-west-1";
    cfg.cache_ttl = std::chrono::seconds{10};
    hsm::iam_token_authorizer authz(
        cfg,
        [&](const aws_auth::principal_context& p, const aws_auth::authz_request& r) {
            asked.push_back(r);
            who.push_back(p.arn);
            aws_auth::authz_decision d;
            d.allowed = allow;
            return d;
        },
        [&] { return now; });

    const std::string arn = "arn:aws:iam::123456789012:role/signer";
    BOOST_TEST(!authz("spiffe://apps/ca", 7, "hsm:Sign").has_value());
    BOOST_TEST(asked.empty());

    BOOST_TEST((authz(arn, 7, "hsm:Sign") == std::optional<bool>(true)));
    BOOST_REQUIRE(asked.size() == 1U);
    BOOST_TEST(asked[0].action == "hsm:Sign");
    BOOST_TEST(asked[0].resource == "arn:aws:hsm:eu-west-1:123456789012:token/7");
    BOOST_TEST(asked[0].region == "eu-west-1");
    BOOST_TEST(who[0] == "arn:aws:sts::123456789012:assumed-role/signer/hsm");

    // Kept for the TTL: a revoked grant takes effect when it lapses.
    allow = false;
    BOOST_TEST((authz(arn, 7, "hsm:Sign") == std::optional<bool>(true)));
    BOOST_TEST(asked.size() == 1U);
    BOOST_TEST((authz(arn, 7, "hsm:Verify") == std::optional<bool>(false)));  // another action
    BOOST_TEST((authz(arn, 8, "hsm:Sign") == std::optional<bool>(false)));    // another token
    BOOST_TEST(asked.size() == 3U);
    now += std::chrono::seconds{11};
    BOOST_TEST((authz(arn, 7, "hsm:Sign") == std::optional<bool>(false)));
    BOOST_TEST(asked.size() == 4U);
}

BOOST_AUTO_TEST_CASE(a_full_cache_starts_over) {
    int calls = 0;
    hsm::iam_token_config cfg;
    cfg.max_cached = 2;
    hsm::iam_token_authorizer authz(cfg, [&](const auto&, const auto&) {
        ++calls;
        aws_auth::authz_decision d;
        d.allowed = true;
        return d;
    });
    const std::string arn = "arn:aws:iam::123456789012:user/a";
    for (std::uint64_t t = 1; t <= 3; ++t) {
        BOOST_TEST((authz(arn, t, "hsm:OpenToken") == std::optional<bool>(true)));
    }
    BOOST_TEST(calls == 3);
    BOOST_TEST((authz(arn, 3, "hsm:OpenToken") == std::optional<bool>(true)));  // kept
    BOOST_TEST(calls == 3);
    BOOST_TEST((authz(arn, 1, "hsm:OpenToken") == std::optional<bool>(true)));  // dropped
    BOOST_TEST(calls == 4);
}
