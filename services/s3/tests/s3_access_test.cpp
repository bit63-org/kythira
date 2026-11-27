// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_access_test.cpp
/// @brief S3's access model (`s3_access.hpp`; .kiro/specs/s3-compatible-storage/
///        task 6, Requirements 5.1-5.5): Object Ownership, canned and header
///        ACLs, ACL XML, Block Public Access, policy publicness, and the
///        decision that combines the authorizer, ACLs and anonymous access.

#define BOOST_TEST_MODULE s3_access_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_access.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace s3 = kythira::s3;
namespace sv4 = kythira::sigv4;
namespace az = kythira::aws_auth;

using headers_t = std::vector<std::pair<std::string, std::string>>;

constexpr std::string_view k_owner = "111122223333";
constexpr std::string_view k_other = "444455556666";

/// An authorizer whose answers the test scripts, recording what it was asked.
struct scripted {
    std::function<az::authz_decision(const az::principal_context*, const az::authz_request&)>
        answer;
    std::vector<az::authz_request> asked;

    auto authenticate(const sv4::request& /*r*/, const sv4::service_rules& /*rules*/)
        -> az::authn_result {
        return az::authn_result(sv4::signature_mismatch(sv4::error_protocol::s3));
    }
    auto authorize(const az::principal_context& w, const az::authz_request& r)
        -> az::authz_decision {
        asked.push_back(r);
        return answer(&w, r);
    }
};
static_assert(az::aws_request_authorizer<scripted>);
static_assert(!az::aws_anonymous_authorizer<scripted>);

struct scripted_anonymous : scripted {
    auto authorize_anonymous(const az::authz_request& r) -> az::authz_decision {
        asked.push_back(r);
        return answer(nullptr, r);
    }
};
static_assert(az::aws_anonymous_authorizer<scripted_anonymous>);

auto allow() -> az::authz_decision {
    az::authz_decision d;
    d.allowed = true;
    return d;
}
auto deny() -> az::authz_decision {
    az::authz_decision d;
    d.explicit_deny = true;
    return d;
}
auto nothing() -> az::authz_decision {
    return {};
}

auto caller(std::string_view account) -> s3::authenticated {
    s3::authenticated a;
    a.kind = s3::auth_kind::header;
    az::principal_context who;
    who.account = std::string(account);
    who.arn = "arn:aws:iam::" + std::string(account) + ":user/u";
    a.who = who;
    return a;
}

auto get_object() -> s3::authz_check {
    return {"s3:GetObject", s3::object_arn("aws", "bk1", "k"), {}};
}

const std::string k_public_policy =
    R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",)"
    R"("Action":"s3:GetObject","Resource":"arn:aws:s3:::bk1/*"}]})";

auto code_of(const std::optional<kythira::aws_rest_xml::error>& e) -> std::string {
    return e ? e->code : std::string{};
}

}  // namespace

BOOST_AUTO_TEST_CASE(ownership_and_permissions_round_trip) {
    for (auto o :
         {s3::object_ownership::bucket_owner_enforced, s3::object_ownership::bucket_owner_preferred,
          s3::object_ownership::object_writer}) {
        BOOST_TEST((s3::parse_ownership(s3::to_string(o)) == o));
    }
    BOOST_TEST(!s3::parse_ownership("Owner").has_value());
    BOOST_TEST((s3::parse_permission("WRITE_ACP") == s3::acl_permission::write_acp));
    BOOST_TEST(!s3::parse_permission("write").has_value());
}

BOOST_AUTO_TEST_CASE(canned_acls) {
    const std::string owner(k_owner);
    const std::string other(k_other);
    auto priv = s3::canned_acl("private", owner, owner);
    BOOST_TEST_REQUIRE(priv.has_value());
    BOOST_TEST((*priv == s3::owner_only(owner)));
    BOOST_TEST(!s3::is_public(*priv));

    auto pr = s3::canned_acl("public-read", owner, owner);
    BOOST_TEST_REQUIRE(pr.has_value());
    BOOST_TEST(s3::is_public(*pr));
    BOOST_TEST(pr->grants.size() == 2U);

    auto ar = s3::canned_acl("authenticated-read", owner, owner);
    BOOST_TEST_REQUIRE(ar.has_value());
    BOOST_TEST(s3::is_public(*ar));  // Block Public Access counts it

    auto bofc = s3::canned_acl("bucket-owner-full-control", other, owner);
    BOOST_TEST_REQUIRE(bofc.has_value());
    BOOST_TEST(bofc->grants.size() == 2U);
    BOOST_TEST(bofc->grants[1].grantee == owner);
    auto same = s3::canned_acl("bucket-owner-full-control", owner, owner);
    BOOST_TEST_REQUIRE(same.has_value());
    BOOST_TEST(same->grants.size() == 1U);

    auto bad = s3::canned_acl("aws-exec-read", owner, owner);
    BOOST_TEST(!bad.has_value());
    BOOST_TEST((bad ? "" : bad.error().code) == "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(acls_from_headers) {
    const std::string owner(k_owner);
    BOOST_TEST(!s3::acl_from_headers({{"Content-Type", "x"}}, owner, owner).has_value());

    auto canned = s3::acl_from_headers({{"X-Amz-Acl", "public-read"}}, owner, owner);
    BOOST_TEST_REQUIRE(canned.has_value());
    BOOST_TEST_REQUIRE(canned->has_value());
    BOOST_TEST(s3::is_public(**canned));

    auto both = s3::acl_from_headers({{"x-amz-acl", "private"}, {"x-amz-grant-read", "id=1"}},
                                     owner, owner);
    BOOST_TEST_REQUIRE(both.has_value());
    BOOST_TEST((*both ? "" : both->error().code) == "InvalidRequest");

    auto grants = s3::acl_from_headers(
        {{"x-amz-grant-read",
          R"(id="444455556666", uri="http://acs.amazonaws.com/groups/global/AllUsers")"},
         {"x-amz-grant-full-control", "id=111122223333"}},
        owner, owner);
    BOOST_TEST_REQUIRE(grants.has_value());
    BOOST_TEST_REQUIRE(grants->has_value());
    const auto& acl = **grants;
    BOOST_TEST(acl.grants.size() == 3U);
    BOOST_TEST(acl.grants[0].grantee == std::string(k_other));
    BOOST_TEST(!acl.grants[0].group);
    BOOST_TEST(acl.grants[1].group);
    BOOST_TEST((acl.grants[2].permission == s3::acl_permission::full_control));

    auto email =
        s3::acl_from_headers({{"x-amz-grant-read", R"(emailAddress="a@b.c")"}}, owner, owner);
    BOOST_TEST_REQUIRE(email.has_value());
    BOOST_TEST((*email ? "" : email->error().code) == "UnresolvableGrantByEmailAddress");

    auto bad_uri =
        s3::acl_from_headers({{"x-amz-grant-read", R"(uri="http://example.com/g")"}}, owner, owner);
    BOOST_TEST_REQUIRE(bad_uri.has_value());
    BOOST_TEST((*bad_uri ? "" : bad_uri->error().code) == "InvalidArgument");

    auto no_eq = s3::acl_from_headers({{"x-amz-grant-read", "444455556666"}}, owner, owner);
    BOOST_TEST_REQUIRE(no_eq.has_value());
    BOOST_TEST(!no_eq->has_value());
}

BOOST_AUTO_TEST_CASE(acl_xml_round_trips) {
    const std::string owner(k_owner);
    auto acl = s3::owner_only(owner);
    acl.grants.push_back({true, std::string(s3::all_users_uri), s3::acl_permission::read});
    acl.grants.push_back({false, std::string(k_other), s3::acl_permission::write_acp});
    const auto xml = s3::acl_xml(acl);
    BOOST_TEST(xml.find(R"(xsi:type="Group")") != std::string::npos);
    BOOST_TEST(xml.find("<Permission>WRITE_ACP</Permission>") != std::string::npos);
    auto back = s3::parse_acl_xml(xml, owner);
    BOOST_TEST_REQUIRE(back.has_value(), (back ? "" : back.error().message));
    BOOST_TEST((*back == acl));

    // Another owner is refused; a bare list without an Owner is taken.
    auto other = s3::parse_acl_xml(xml, std::string(k_other));
    BOOST_TEST((other ? "" : other.error().code) == "AccessDenied");
    const std::string bare =
        R"(<AccessControlPolicy><AccessControlList><Grant>)"
        R"(<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">)"
        R"(<ID>111122223333</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>)"
        R"(</AccessControlList></AccessControlPolicy>)";
    auto b = s3::parse_acl_xml(bare, owner);
    BOOST_TEST_REQUIRE(b.has_value());
    BOOST_TEST((*b == s3::owner_only(owner)));

    const std::string email =
        R"(<AccessControlPolicy><AccessControlList><Grant>)"
        R"(<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" )"
        R"(xsi:type="AmazonCustomerByEmail"><EmailAddress>a@b.c</EmailAddress></Grantee>)"
        R"(<Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>)";
    auto e = s3::parse_acl_xml(email, owner);
    BOOST_TEST((e ? "" : e.error().code) == "UnresolvableGrantByEmailAddress");
    auto wrong_root = s3::parse_acl_xml("<Acl/>", owner);
    BOOST_TEST((wrong_root ? "" : wrong_root.error().code) == "MalformedXML");
}

BOOST_AUTO_TEST_CASE(block_public_access_settings) {
    const s3::public_access_block def;
    BOOST_TEST(def.block_public_acls);
    BOOST_TEST(def.restrict_public_buckets);
    const s3::public_access_block off{false, false, false, false};
    s3::public_access_block some = off;
    some.ignore_public_acls = true;
    const auto eff = s3::effective(off, some);
    BOOST_TEST(eff.ignore_public_acls);
    BOOST_TEST(!eff.block_public_acls);

    auto back = s3::parse_public_access_block(s3::public_access_block_xml(some));
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((*back == some));
    auto partial = s3::parse_public_access_block(
        "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy>"
        "</PublicAccessBlockConfiguration>");
    BOOST_TEST_REQUIRE(partial.has_value());
    BOOST_TEST(partial->block_public_policy);
    BOOST_TEST(!partial->block_public_acls);  // absent is false
    auto junk = s3::parse_public_access_block(
        "<PublicAccessBlockConfiguration><BlockPublicAcls>yes</BlockPublicAcls>"
        "</PublicAccessBlockConfiguration>");
    BOOST_TEST((junk ? "" : junk.error().code) == "MalformedXML");
}

BOOST_AUTO_TEST_CASE(policy_publicness) {
    const auto stmt = [](std::string body) {
        return R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",)"
               R"("Resource":"arn:aws:s3:::bk1/*",)" +
               body + "}]}";
    };
    BOOST_TEST(s3::policy_is_public(k_public_policy));
    BOOST_TEST(s3::policy_is_public(stmt(R"("Principal":{"AWS":"*"})")));
    BOOST_TEST(s3::policy_is_public(stmt(R"("Principal":{"AWS":["arn:aws:iam::*:root"]})")));
    BOOST_TEST(s3::policy_is_public(stmt(R"("NotPrincipal":{"AWS":"arn:aws:iam::1:root"})")));
    BOOST_TEST(
        !s3::policy_is_public(stmt(R"("Principal":{"AWS":"arn:aws:iam::444455556666:root"})")));
    BOOST_TEST(
        !s3::policy_is_public(stmt(R"("Principal":{"Service":"logging.s3.amazonaws.com"})")));
    // Restricting conditions.
    BOOST_TEST(!s3::policy_is_public(stmt(
        R"("Principal":"*","Condition":{"StringEquals":{"aws:SourceAccount":"444455556666"}})")));
    BOOST_TEST(!s3::policy_is_public(
        stmt(R"("Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/16"}})")));
    BOOST_TEST(s3::policy_is_public(
        stmt(R"("Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/1"}})")));
    BOOST_TEST(s3::policy_is_public(stmt(
        R"("Principal":"*","Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/x"}})")));
    BOOST_TEST(s3::policy_is_public(stmt(
        R"("Principal":"*","Condition":{"StringEqualsIfExists":{"aws:SourceAccount":"444455556666"}})")));
    BOOST_TEST(s3::policy_is_public(
        stmt(R"("Principal":"*","Condition":{"StringEquals":{"s3:prefix":"home/"}})")));
    // A Deny with a wildcard principal is not public.
    BOOST_TEST(!s3::policy_is_public(
        R"({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}})"));
    BOOST_TEST(!s3::policy_is_public("not json"));
}

BOOST_AUTO_TEST_CASE(policy_and_acl_writes) {
    BOOST_TEST(code_of(s3::check_bucket_policy("{")) == "MalformedPolicy");
    BOOST_TEST(code_of(s3::check_bucket_policy(R"({"Statement":[]})")) == "MalformedPolicy");
    BOOST_TEST(code_of(s3::check_bucket_policy(
                   R"({"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}})")) ==
               "MalformedPolicy");
    BOOST_TEST(code_of(s3::check_bucket_policy(std::string(21 * 1024, ' '))) == "PolicyTooLarge");
    BOOST_TEST(!s3::check_bucket_policy(k_public_policy).has_value());

    s3::public_access_block bpa;
    BOOST_TEST(code_of(s3::check_policy_write(bpa, k_public_policy)) == "AccessDenied");
    bpa.block_public_policy = false;
    BOOST_TEST(!s3::check_policy_write(bpa, k_public_policy).has_value());

    const std::string owner(k_owner);
    auto pr = s3::canned_acl("public-read", owner, owner).value();
    using s3::object_ownership;
    BOOST_TEST(code_of(s3::check_acl_write(object_ownership::bucket_owner_enforced, {}, pr,
                                           owner)) == "AccessControlListNotSupported");
    BOOST_TEST(!s3::check_acl_write(object_ownership::bucket_owner_enforced, {},
                                    s3::owner_only(owner), owner)
                    .has_value());
    BOOST_TEST(code_of(s3::check_acl_write(object_ownership::object_writer, {}, pr, owner)) ==
               "AccessDenied");
    BOOST_TEST(!s3::check_acl_write(object_ownership::object_writer, {false, false, false, false},
                                    pr, owner)
                    .has_value());
}

BOOST_AUTO_TEST_CASE(acl_needs) {
    BOOST_TEST((s3::acl_need_for("s3:GetObject")->permission == s3::acl_permission::read));
    BOOST_TEST(s3::acl_need_for("s3:GetObject")->on_object);
    BOOST_TEST(!s3::acl_need_for("s3:PutObject")->on_object);
    BOOST_TEST(!s3::acl_need_for("s3:PutBucketPolicy").has_value());
}

BOOST_AUTO_TEST_CASE(policies_decide_first) {
    scripted a;
    a.answer = [](const az::principal_context*, const az::authz_request&) { return allow(); };
    s3::access_context ctx;
    ctx.bucket_owner = std::string(k_owner);
    ctx.bucket_policy = R"({"Statement":[]})";
    ctx.source_ip = "10.0.0.1";
    BOOST_TEST(!s3::authorize_check(a, caller(k_other), get_object(), ctx).has_value());
    BOOST_TEST_REQUIRE(a.asked.size() == 1U);
    BOOST_TEST(a.asked[0].resource_account == std::string(k_owner));
    BOOST_TEST(a.asked[0].resource_policy.has_value());
    BOOST_TEST(a.asked[0].source_ip == "10.0.0.1");

    a.answer = [](const az::principal_context*, const az::authz_request&) { return deny(); };
    BOOST_TEST(code_of(s3::authorize_check(a, caller(k_other), get_object(), ctx)) ==
               "AccessDenied");
}

BOOST_AUTO_TEST_CASE(acls_only_when_ownership_allows) {
    scripted a;
    // Cross-account: no policy allows; the caller's own account allows.
    a.answer = [](const az::principal_context* w, const az::authz_request& r) {
        return r.resource_account == w->account && !r.resource_policy ? allow() : nothing();
    };
    const std::string owner(k_owner);
    auto obj_acl = s3::owner_only(owner);
    obj_acl.grants.push_back({false, std::string(k_other), s3::acl_permission::read});
    s3::access_context ctx;
    ctx.bucket_owner = owner;
    ctx.object_acl = &obj_acl;

    // BucketOwnerEnforced: the grant counts for nothing.
    BOOST_TEST(code_of(s3::authorize_check(a, caller(k_other), get_object(), ctx)) ==
               "AccessDenied");
    ctx.ownership = s3::object_ownership::bucket_owner_preferred;
    a.asked.clear();
    BOOST_TEST(!s3::authorize_check(a, caller(k_other), get_object(), ctx).has_value());
    BOOST_TEST_REQUIRE(a.asked.size() == 2U);
    BOOST_TEST(a.asked[1].resource_account == std::string(k_other));
    BOOST_TEST(!a.asked[1].resource_policy.has_value());

    // The caller's own identity policies must allow too.
    a.answer = [](const az::principal_context*, const az::authz_request&) { return nothing(); };
    BOOST_TEST(code_of(s3::authorize_check(a, caller(k_other), get_object(), ctx)) ==
               "AccessDenied");
    // An explicit deny is not overridden by an ACL.
    a.answer = [](const az::principal_context*, const az::authz_request&) { return deny(); };
    BOOST_TEST(code_of(s3::authorize_check(a, caller(k_other), get_object(), ctx)) ==
               "AccessDenied");
    // Write ACP is not READ.
    a.answer = [](const az::principal_context* w, const az::authz_request& r) {
        return r.resource_account == w->account ? allow() : nothing();
    };
    BOOST_TEST(code_of(s3::authorize_check(
                   a, caller(k_other), {"s3:PutObjectAcl", s3::object_arn("aws", "bk1", "k"), {}},
                   ctx)) == "AccessDenied");
}

BOOST_AUTO_TEST_CASE(anonymous_requests) {
    const std::string owner(k_owner);
    s3::authenticated anon;
    s3::access_context ctx;
    ctx.bucket_owner = owner;
    s3::public_access_block off{false, false, false, false};

    // Static keys: no policy route, and no ACL either under the default.
    scripted plain;
    plain.answer = [](const az::principal_context*, const az::authz_request&) { return allow(); };
    ctx.bucket_policy = k_public_policy;
    ctx.bpa = off;
    BOOST_TEST(code_of(s3::authorize_check(plain, anon, get_object(), ctx)) == "AccessDenied");
    BOOST_TEST(plain.asked.empty());

    // Through the bucket policy.
    scripted_anonymous a;
    a.answer = [](const az::principal_context* w, const az::authz_request& r) {
        return w == nullptr && r.resource_policy ? allow() : nothing();
    };
    BOOST_TEST(!s3::authorize_check(a, anon, get_object(), ctx).has_value());
    // RestrictPublicBuckets keeps a public policy from anyone outside the
    // owner's account, the anonymous caller included.
    ctx.bpa.restrict_public_buckets = true;
    BOOST_TEST(code_of(s3::authorize_check(a, anon, get_object(), ctx)) == "AccessDenied");
    scripted b;
    b.answer = [](const az::principal_context*, const az::authz_request& r) {
        return r.resource_policy ? allow() : nothing();
    };
    BOOST_TEST(code_of(s3::authorize_check(b, caller(k_other), get_object(), ctx)) ==
               "AccessDenied");
    BOOST_TEST(!s3::authorize_check(b, caller(k_owner), get_object(), ctx).has_value());

    // Through an AllUsers ACL grant, unless IgnorePublicAcls.
    ctx.bucket_policy.reset();
    ctx.bpa = off;
    ctx.ownership = s3::object_ownership::object_writer;
    auto acl = s3::canned_acl("public-read", owner, owner).value();
    ctx.object_acl = &acl;
    BOOST_TEST(!s3::authorize_check(a, anon, get_object(), ctx).has_value());
    ctx.bpa.ignore_public_acls = true;
    BOOST_TEST(code_of(s3::authorize_check(a, anon, get_object(), ctx)) == "AccessDenied");

    // AuthenticatedUsers does not reach an anonymous caller.
    ctx.bpa = off;
    auto auth_read = s3::canned_acl("authenticated-read", owner, owner).value();
    ctx.object_acl = &auth_read;
    BOOST_TEST(code_of(s3::authorize_check(a, anon, get_object(), ctx)) == "AccessDenied");
}

BOOST_AUTO_TEST_CASE(every_check_against_its_bucket) {
    scripted a;
    a.answer = [](const az::principal_context*, const az::authz_request& r) {
        return r.resource.find("src") != std::string::npos ? nothing() : allow();
    };
    s3::access_context ctx;
    ctx.bucket_owner = std::string(k_owner);
    const std::vector<s3::authz_check> checks{
        {"s3:PutObject", s3::object_arn("aws", "dst", "k"), {}},
        {"s3:GetObject", s3::object_arn("aws", "src", "k"), {}},
    };
    const auto any = [&](const s3::authz_check&) { return &ctx; };
    BOOST_TEST(code_of(s3::authorize_all(a, caller(k_owner), checks, any)) == "AccessDenied");
    a.answer = [](const az::principal_context*, const az::authz_request&) { return allow(); };
    BOOST_TEST(!s3::authorize_all(a, caller(k_owner), checks, any).has_value());
    const auto missing = [&](const s3::authz_check& c) -> const s3::access_context* {
        return c.resource.find("src") != std::string::npos ? nullptr : &ctx;
    };
    BOOST_TEST(code_of(s3::authorize_all(a, caller(k_owner), checks, missing)) == "AccessDenied");
    BOOST_TEST(code_of(s3::authorize_all(a, caller(k_owner), {}, any)) == "AccessDenied");
}
