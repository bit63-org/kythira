// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_authz_test.cpp
/// @brief The `s3` action table and what each request asks the authorizer
///        (`s3_actions.hpp`, `s3_authz.hpp`; .kiro/specs/s3-compatible-storage/
///        task 6, Requirements 5.1 and 5.6).

#define BOOST_TEST_MODULE s3_authz_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/model/operations.hpp>
#include <kythira/s3/s3_actions.hpp>
#include <kythira/s3/s3_authz.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace {

namespace s3 = kythira::s3;
namespace rx = kythira::aws_rest_xml;

auto facts(std::string op, std::string bucket = "bk1", std::string key = "") -> s3::request_facts {
    s3::request_facts f;
    f.operation = std::move(op);
    f.bucket = std::move(bucket);
    f.key = std::move(key);
    return f;
}

auto actions(const std::vector<s3::authz_check>& checks) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& c : checks) {
        out.push_back(c.action);
    }
    return out;
}

auto key_of(const s3::authz_check& c, std::string_view k) -> std::vector<std::string> {
    for (const auto& [name, values] : c.keys) {
        if (name == k) {
            return values;
        }
    }
    return {"<absent>"};
}

/// Every header and parameter that adds an action.
auto everything(std::string op) -> s3::request_facts {
    auto f = facts(std::move(op), "bk1", "dir/k");
    f.headers = {{"x-amz-acl", "private"},
                 {"x-amz-tagging", "a=1"},
                 {"x-amz-object-lock-mode", "GOVERNANCE"},
                 {"x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"},
                 {"x-amz-object-lock-legal-hold", "ON"},
                 {"x-amz-bypass-governance-retention", "true"},
                 {"x-amz-bucket-object-lock-enabled", "true"},
                 {"x-amz-object-ownership", "BucketOwnerEnforced"}};
    f.query = rx::query({{"versionId", "v1"}});
    f.source_bucket = "src";
    f.source_key = "s";
    f.source_version_id = "sv";
    return f;
}

}  // namespace

BOOST_AUTO_TEST_CASE(the_table_covers_every_model_operation) {
    for (const auto& op : s3::model::operations) {
        BOOST_TEST(s3::find_operation_actions(op._name) != nullptr, op._name);
    }
    const auto table = s3::s3_actions();
    BOOST_TEST(table.service_prefix == "s3");
    BOOST_TEST(table.actions.size() > 150U);
}

BOOST_AUTO_TEST_CASE(every_action_chosen_is_one_the_reference_lists) {
    for (const auto& op : s3::model::operations) {
        const auto* listed = s3::find_operation_actions(op._name);
        BOOST_TEST_REQUIRE(listed != nullptr);
        for (const auto& f :
             {facts(std::string(op._name), "bk1", "k"), everything(std::string(op._name))}) {
            const auto checks = s3::checks_for(f);
            BOOST_TEST(checks.empty() == listed->actions.front().empty(), op._name);
            for (const auto& c : checks) {
                BOOST_TEST_REQUIRE(c.action.starts_with("s3:"));
                const auto name = c.action.substr(3);
                BOOST_TEST(std::ranges::find(listed->actions, name) != listed->actions.end(),
                           op._name << " chose " << name);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(reads_and_their_version_twins) {
    auto f = facts("GetObject", "bk1", "a/b.txt");
    auto c = s3::checks_for(f);
    BOOST_TEST_REQUIRE(c.size() == 1U);
    BOOST_TEST(c[0].action == "s3:GetObject");
    BOOST_TEST(c[0].resource == "arn:aws:s3:::bk1/a/b.txt");
    f.query = rx::query({{"versionId", "v9"}});
    c = s3::checks_for(f);
    BOOST_TEST(c.at(0).action == "s3:GetObjectVersion");
    BOOST_TEST(key_of(c[0], "s3:versionid") == std::vector<std::string>{"v9"});
    BOOST_TEST(actions(s3::checks_for(facts("HeadObject", "bk1", "k"))) ==
               std::vector<std::string>{"s3:GetObject"});
    BOOST_TEST(actions(s3::checks_for(facts("GetObjectAttributes", "bk1", "k"))) ==
               std::vector<std::string>{"s3:GetObject"});
    auto tag = facts("PutObjectTagging", "bk1", "k");
    tag.query = rx::query({{"tagging", ""}, {"versionId", "v"}});
    BOOST_TEST(actions(s3::checks_for(tag)) ==
               std::vector<std::string>{"s3:PutObjectVersionTagging"});
}

BOOST_AUTO_TEST_CASE(bucket_and_service_operations) {
    auto list = facts("ListObjectsV2");
    auto c = s3::checks_for(list);
    BOOST_TEST_REQUIRE(c.size() == 1U);
    BOOST_TEST(c[0].action == "s3:ListBucket");
    BOOST_TEST(c[0].resource == "arn:aws:s3:::bk1");
    // s3:prefix is empty when the request has none.
    BOOST_TEST(key_of(c[0], "s3:prefix") == std::vector<std::string>{""});
    BOOST_TEST(key_of(c[0], "s3:delimiter") == std::vector<std::string>{"<absent>"});
    list.query = rx::query({{"list-type", "2"}, {"prefix", "home/"}, {"delimiter", "/"}});
    c = s3::checks_for(list);
    BOOST_TEST(key_of(c[0], "s3:prefix") == std::vector<std::string>{"home/"});
    BOOST_TEST(key_of(c[0], "s3:delimiter") == std::vector<std::string>{"/"});

    c = s3::checks_for(facts("ListBuckets", ""));
    BOOST_TEST_REQUIRE(c.size() == 1U);
    BOOST_TEST(c[0].action == "s3:ListAllMyBuckets");
    BOOST_TEST(c[0].resource == "*");
    BOOST_TEST(actions(s3::checks_for(facts("HeadBucket"))) ==
               std::vector<std::string>{"s3:ListBucket"});
    BOOST_TEST(actions(s3::checks_for(facts("GetBucketCors"))) ==
               std::vector<std::string>{"s3:GetBucketCORS"});
    // Deleting a sub-resource is the put action, as S3 documents.
    BOOST_TEST(actions(s3::checks_for(facts("DeleteBucketCors"))) ==
               std::vector<std::string>{"s3:PutBucketCORS"});
    BOOST_TEST(actions(s3::checks_for(facts("ListObjectVersions"))) ==
               std::vector<std::string>{"s3:ListBucketVersions"});
}

BOOST_AUTO_TEST_CASE(writes_add_actions_for_what_they_carry) {
    auto put = facts("PutObject", "bk1", "k");
    BOOST_TEST(actions(s3::checks_for(put)) == std::vector<std::string>{"s3:PutObject"});
    put.headers = {{"X-Amz-Acl", "public-read"},
                   {"x-amz-tagging", "team=a&env=prod"},
                   {"x-amz-server-side-encryption", "AES256"}};
    const auto c = s3::checks_for(put);
    BOOST_TEST(actions(c) == (std::vector<std::string>{"s3:PutObject", "s3:PutObjectAcl",
                                                       "s3:PutObjectTagging"}));
    BOOST_TEST(key_of(c[0], "s3:x-amz-acl") == std::vector<std::string>{"public-read"});
    BOOST_TEST(key_of(c[0], "s3:x-amz-server-side-encryption") ==
               std::vector<std::string>{"AES256"});
    BOOST_TEST(key_of(c[0], "s3:RequestObjectTag/team") == std::vector<std::string>{"a"});
    BOOST_TEST(key_of(c[0], "s3:RequestObjectTagKeys") ==
               (std::vector<std::string>{"team", "env"}));

    auto del = facts("DeleteObject", "bk1", "k");
    del.query = rx::query({{"versionId", "v"}});
    del.headers = {{"x-amz-bypass-governance-retention", "TRUE"}};
    BOOST_TEST(
        actions(s3::checks_for(del)) ==
        (std::vector<std::string>{"s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"}));

    // DeleteObjects is checked per key, with each object's version.
    auto multi = facts("DeleteObjects", "bk1", "k2");
    multi.version_id = "v2";
    const auto m = s3::checks_for(multi);
    BOOST_TEST(actions(m) == std::vector<std::string>{"s3:DeleteObjectVersion"});
    BOOST_TEST(m[0].resource == "arn:aws:s3:::bk1/k2");

    auto bucket = facts("CreateBucket");
    bucket.headers = {{"x-amz-acl", "private"},
                      {"x-amz-bucket-object-lock-enabled", "true"},
                      {"x-amz-object-ownership", "BucketOwnerPreferred"}};
    BOOST_TEST(actions(s3::checks_for(bucket)) ==
               (std::vector<std::string>{
                   "s3:CreateBucket", "s3:PutBucketAcl", "s3:PutBucketObjectLockConfiguration",
                   "s3:PutBucketVersioning", "s3:PutBucketOwnershipControls"}));
    BOOST_TEST(actions(s3::checks_for(facts("CompleteMultipartUpload", "bk1", "k"))) ==
               std::vector<std::string>{"s3:PutObject"});
}

BOOST_AUTO_TEST_CASE(a_copy_reads_its_source) {
    auto copy = facts("CopyObject", "dst", "d");
    copy.source_bucket = "src";
    copy.source_key = "path/s";
    auto c = s3::checks_for(copy);
    BOOST_TEST_REQUIRE(c.size() == 2U);
    BOOST_TEST(c[0].action == "s3:PutObject");
    BOOST_TEST(c[0].resource == "arn:aws:s3:::dst/d");
    BOOST_TEST(c[1].action == "s3:GetObject");
    BOOST_TEST(c[1].resource == "arn:aws:s3:::src/path/s");
    copy.operation = "UploadPartCopy";
    copy.source_version_id = "v";
    c = s3::checks_for(copy);
    BOOST_TEST(actions(c) == (std::vector<std::string>{"s3:PutObject", "s3:GetObjectVersion"}));
}

BOOST_AUTO_TEST_CASE(authentication_facts_become_keys) {
    auto f = facts("GetObject", "bk1", "k");
    f.auth_type = "REST-QUERY-STRING";
    f.signature_age_ms = 1234;
    f.tls_version = "1.3";
    f.resource_account = "111122223333";
    f.existing_tags = {{"class", "secret"}};
    const auto c = s3::checks_for(f).at(0);
    BOOST_TEST(key_of(c, "s3:authType") == std::vector<std::string>{"REST-QUERY-STRING"});
    BOOST_TEST(key_of(c, "s3:signatureversion") == std::vector<std::string>{"AWS4-HMAC-SHA256"});
    BOOST_TEST(key_of(c, "s3:signatureAge") == std::vector<std::string>{"1234"});
    BOOST_TEST(key_of(c, "s3:TlsVersion") == std::vector<std::string>{"1.3"});
    BOOST_TEST(key_of(c, "s3:ResourceAccount") == std::vector<std::string>{"111122223333"});
    BOOST_TEST(key_of(c, "s3:ExistingObjectTag/class") == std::vector<std::string>{"secret"});
    // An anonymous request has no signature keys.
    const auto anon = s3::checks_for(facts("GetObject", "bk1", "k")).at(0);
    BOOST_TEST(key_of(anon, "s3:authType") == std::vector<std::string>{"<absent>"});
}

BOOST_AUTO_TEST_CASE(static_roles_split_reads_from_data_writes) {
    const auto roles = s3::s3_static_roles();
    const auto has = [](const auto& list, std::string_view a) {
        return std::ranges::find(list, a) != list.end();
    };
    BOOST_TEST(roles.service_prefix == "s3");
    BOOST_TEST(has(roles.read_only, "GetObject"));
    BOOST_TEST(has(roles.read_only, "ListBucket"));
    BOOST_TEST(has(roles.read_only, "ListAllMyBuckets"));
    BOOST_TEST(!has(roles.read_only, "PutObject"));
    BOOST_TEST(has(roles.read_write, "PutObject"));
    BOOST_TEST(has(roles.read_write, "DeleteObject"));
    BOOST_TEST(!has(roles.read_write, "PutBucketPolicy"));
    BOOST_TEST(!has(roles.read_write, "CreateBucket"));
}
