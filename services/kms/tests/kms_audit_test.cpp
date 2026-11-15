// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 14 (Requirements 13.1 and 13.2): every request becomes one
// CloudTrail-shaped record naming the caller, the operation, the key and
// the outcome; a grant that allowed it is named; a call a service made
// for its caller names the service; encryption context values and key
// material never appear; and the requests are counted by operation,
// outcome and account.

#define BOOST_TEST_MODULE kms_audit_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_audit.hpp>
#include <kythira/kms/kms_in_process.hpp>

#include <boost/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)
namespace sn = kythira::service_node;

namespace {

const std::string k_reader = "arn:aws:iam::111122223333:user/reader";

/// Every record the front end hands its observer.
struct records {
    std::vector<kms::request_record> all;

    explicit records(fixture& f) {
        f.fe.set_observer([this](const kms::request_record& r) { all.push_back(r); });
    }

    [[nodiscard]] auto last() const -> json::object {
        BOOST_REQUIRE(!all.empty());
        return json::parse(kms::cloudtrail_line(all.back(), "us-east-1")).as_object();
    }
};

auto str(const json::object& o, std::string_view k) -> std::string {
    const auto* v = o.if_contains(k);
    return v != nullptr && v->is_string() ? std::string(v->as_string()) : std::string();
}

auto metric(const std::vector<sn::module_metric>& ms, std::string_view name,
            const std::vector<std::pair<std::string, std::string>>& labels) -> double {
    for (const auto& m : ms) {
        if (m.name == name && m.labels == labels) {
            return m.value;
        }
    }
    return -1;
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_request_is_one_cloudtrail_record) {
    fixture f;
    const auto id = f.create();
    records rec(f);
    const auto r = f.call("Encrypt", R"({"KeyId":")" + id +
                                         R"(","Plaintext":"c2VjcmV0",)"
                                         R"("EncryptionContext":{"tenant":"hush-hush-value"}})");
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_REQUIRE(rec.all.size() == 1U);
    const auto line = kms::cloudtrail_line(rec.all.back(), "us-east-1");
    const auto ev = json::parse(line).as_object();
    BOOST_TEST(str(ev, "eventSource") == "kms.amazonaws.com");
    BOOST_TEST(str(ev, "eventName") == "Encrypt");
    BOOST_TEST(str(ev, "awsRegion") == "us-east-1");
    BOOST_TEST(str(ev, "eventType") == "AwsApiCall");
    BOOST_TEST(str(ev, "recipientAccountId") == std::string(k_account));
    BOOST_TEST(!str(ev, "requestID").empty());
    BOOST_TEST(str(ev, "eventID").size() == 36U);
    BOOST_TEST(!ev.contains("errorCode"));
    BOOST_TEST(ev.at("readOnly").as_bool() == false);
    const auto& who = ev.at("userIdentity").as_object();
    BOOST_TEST(str(who, "accountId") == std::string(k_account));
    BOOST_TEST(str(who, "accessKeyId") == "AKIDADMIN");
    const auto& params = ev.at("requestParameters").as_object();
    BOOST_TEST(str(params, "keyId") == fixture::arn(id));
    BOOST_REQUIRE(params.contains("encryptionContextKeys"));
    BOOST_TEST(params.at("encryptionContextKeys").as_array().at(0).as_string() == "tenant");
    BOOST_TEST(str(ev.at("resources").as_array().at(0).as_object(), "ARN") == fixture::arn(id));
    // Context values and data never reach the line.
    BOOST_TEST(line.find("hush-hush-value") == std::string::npos);
    BOOST_TEST(line.find("c2VjcmV0") == std::string::npos);
    BOOST_TEST(line.find(r.str("CiphertextBlob")) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(refusals_are_recorded_with_their_error) {
    fixture f;
    const auto id = f.create();
    records rec(f);
    BOOST_TEST(f.call("DisableKey", kid(id), "AKIDREAD").type() == "AccessDeniedException");
    auto ev = rec.last();
    BOOST_TEST(str(ev, "eventName") == "DisableKey");
    BOOST_TEST(str(ev, "errorCode") == "AccessDeniedException");
    BOOST_TEST(!str(ev, "errorMessage").empty());

    // A bad signature: the record has no principal, only the key id.
    auto bad = sign(request("DescribeKey", kid(id)), "AKIDADMIN");
    bad.body += " ";
    (void)f.fe.handle(bad);
    ev = rec.last();
    BOOST_TEST(!str(ev, "errorCode").empty());
    BOOST_TEST(str(ev.at("userIdentity").as_object(), "accessKeyId") == "AKIDADMIN");
    BOOST_TEST(!ev.at("userIdentity").as_object().contains("arn"));

    // A read is marked read-only.
    BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
    BOOST_TEST(rec.last().at("readOnly").as_bool() == true);
}

BOOST_AUTO_TEST_CASE(a_grant_that_allowed_the_request_is_named) {
    fixture f;
    const auto id = f.create();
    const auto g = f.call("CreateGrant", R"({"KeyId":")" + id + R"(","GranteePrincipal":")" +
                                             k_reader + R"(","Operations":["Encrypt"]})");
    BOOST_REQUIRE_MESSAGE(g.status == 200U, g.type() + ": " + g.message());
    records rec(f);
    const auto e =
        f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})", "AKIDREAD");
    BOOST_REQUIRE_MESSAGE(e.status == 200U, e.type() + ": " + e.message());
    const auto ev = rec.last();
    BOOST_REQUIRE(ev.contains("additionalEventData"));
    BOOST_TEST(str(ev.at("additionalEventData").as_object(), "grantId") == g.str("GrantId"));
    // The admin's own call names no grant.
    BOOST_TEST(f.call("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"c2VjcmV0"})").status ==
               200U);
    BOOST_TEST(!rec.last().contains("additionalEventData"));
}

BOOST_AUTO_TEST_CASE(a_call_through_a_service_names_the_service) {
    fixture f;
    const auto id = f.create();
    records rec(f);
    // The admin user is no static key's principal here: allow it.
    f.auth.decide = [](const az::principal_context&, const az::authz_request&) {
        az::authz_decision d;
        d.allowed = true;
        return d;
    };
    kms::in_process_client client(f.fe);
    sn::caller who;
    who.module = "kinesis";
    az::principal_context p;
    p.type = az::principal_type::user;
    p.account = std::string(k_account);
    p.arn = "arn:aws:iam::111122223333:user/admin";
    p.userid = "AIDAADMIN";
    const auto res = client.call(who, sn::kms_request{.operation = "DescribeKey",
                                                      .body = kid(id),
                                                      .principal = p,
                                                      .via_service = "kinesis",
                                                      .source_ip = "198.51.100.7"});
    BOOST_REQUIRE_MESSAGE(res.status == 200, res.body);
    const auto ev = rec.last();
    BOOST_TEST(str(ev, "sourceIPAddress") == "kinesis.amazonaws.com");
    BOOST_TEST(str(ev, "userAgent") == "kinesis.amazonaws.com");
    const auto& u = ev.at("userIdentity").as_object();
    BOOST_TEST(str(u, "invokedBy") == "kinesis.amazonaws.com");
    BOOST_TEST(str(u, "arn") == p.arn);
    client.close();
}

BOOST_AUTO_TEST_CASE(requests_are_counted_by_operation_outcome_and_account) {
    fixture f;
    const auto id = f.create();
    const auto path = std::filesystem::temp_directory_path() /
                      ("kms_audit_test_" + std::to_string(::getpid()) + ".log");
    std::filesystem::remove(path);
    {
        kms::request_audit audit("file:" + path.string(), "us-east-1");
        f.fe.set_observer([&](const kms::request_record& r) { audit.record(r); });
        BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
        BOOST_TEST(f.call("DescribeKey", kid(id)).status == 200U);
        BOOST_TEST(f.call("DisableKey", kid(id), "AKIDREAD").status != 200U);
        audit.flush();
        const auto ms = audit.metrics();
        const std::string acct(k_account);
        BOOST_TEST(metric(ms, "api_requests",
                          {{"operation", "DescribeKey"}, {"outcome", "ok"}, {"account", acct}}) ==
                   2.0);
        BOOST_TEST(metric(ms, "api_requests",
                          {{"operation", "DisableKey"},
                           {"outcome", "AccessDeniedException"},
                           {"account", acct}}) == 1.0);
        BOOST_TEST(metric(ms, "api_latency_seconds_count", {{"operation", "DescribeKey"}}) == 2.0);
        BOOST_TEST(metric(ms, "audit_dropped", {}) == 0.0);
        f.fe.set_observer({});
    }
    std::ifstream in(path);
    std::vector<std::string> lines;
    for (std::string l; std::getline(in, l);) {
        lines.push_back(l);
    }
    BOOST_REQUIRE(lines.size() == 3U);
    BOOST_TEST(str(json::parse(lines[2]).as_object(), "eventName") == "DisableKey");
    std::filesystem::remove(path);

    BOOST_CHECK_THROW(kms::request_audit("syslog", "us-east-1"), std::invalid_argument);
    BOOST_CHECK_THROW(kms::request_audit("file:/nonexistent-dir/x.log", "us-east-1"),
                      std::runtime_error);
    kms::request_audit off("off", "us-east-1");
    BOOST_TEST(off.dropped() == 0U);
}
