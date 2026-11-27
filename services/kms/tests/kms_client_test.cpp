// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Task 12 (Requirements 2.3 and 2.4): the KMS as a consuming service
// reaches it. In process (`kms.client`) and over HTTPS from another
// cluster (`kms_https_endpoint`, here signed and handed to the front end
// without a network), the call is authorized as the service's caller with
// kms:ViaService set to the service; a forwarded principal is honoured
// only when signed by a trusted service; and only the service operations
// are taken.

#define BOOST_TEST_MODULE kms_client_test

#include <boost/test/unit_test.hpp>

#include "kms_api_fixture.hpp"

#include <kythira/kms/kms_in_process.hpp>

#include <raft/kms_forwarding.hpp>
#include <raft/kms_https_client.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace kms_api_fixture;  // NOLINT(google-build-using-namespace)
namespace sn = kythira::service_node;
namespace fwd = kythira::kms_forwarding;

namespace {

constexpr std::string_view k_via = "kinesis.us-east-1.amazonaws.com";

/// The end caller a service serves: a role session with tags, a session
/// policy and an expiry, so every field crosses.
auto end_caller() -> az::principal_context {
    az::principal_context p;
    p.type = az::principal_type::assumed_role;
    p.account = std::string(k_account);
    p.arn = "arn:aws:sts::111122223333:assumed-role/producer/s1";
    p.userid = "AROAEXAMPLE:s1";
    p.role_arn = "arn:aws:iam::111122223333:role/producer";
    p.role_name = "producer";
    p.session_name = "s1";
    p.tags = {{"team", "ingest"}, {"env", "prod é"}};
    p.session_policies = {R"({"Version":"2012-10-17","Statement":[]})"};
    p.transitive_tag_keys = {"team"};
    p.token_issue_time = std::chrono::system_clock::time_point(std::chrono::seconds(1'790'000'000));
    p.expires = std::chrono::system_clock::time_point(std::chrono::seconds(1'790'003'600));
    p.source_identity = "alice";
    return p;
}

/// Allows everything, recording who asked and the ViaService value.
struct recorder {
    std::vector<std::string> who;
    std::vector<std::optional<std::string>> via;

    void install(fixture& f) {
        f.auth.decide = [this](const az::principal_context& p, const az::authz_request& r) {
            who.push_back(p.arn);
            std::optional<std::string> v;
            for (const auto& [k, vals] : r.keys) {
                if (k == "kms:ViaService" && !vals.empty()) {
                    v = vals.front();
                }
            }
            via.push_back(v);
            az::authz_decision d;
            d.allowed = true;
            return d;
        };
    }
};

auto kinesis_caller() -> sn::caller {
    sn::caller c;
    c.module = "kinesis";
    return c;
}

auto service_request(std::string op, std::string body) -> sn::kms_request {
    return sn::kms_request{.operation = std::move(op),
                           .body = std::move(body),
                           .principal = end_caller(),
                           .via_service = "kinesis",
                           .source_ip = "198.51.100.7"};
}

/// A kms_https_endpoint signing as `akid`.
auto endpoint(std::string_view akid) -> sn::kms_https_endpoint {
    sn::kms_https_config c;
    c.endpoint = "https://kms.us-east-1.amazonaws.com:443";
    c.access_key_id = std::string(akid);
    c.secret_access_key = std::string(k_secret);
    return sn::kms_https_endpoint(c);
}

/// What the HTTPS endpoint would send, as the listener hands it over.
auto as_received(const sn::kms_signed_request& s) -> kms::front_end_request {
    kms::front_end_request r;
    r.method = "POST";
    r.path = "/";
    r.headers = s.headers;
    r.body = s.body;
    r.source_ip = "203.0.113.9";
    return r;
}

}  // namespace

BOOST_AUTO_TEST_CASE(principals_cross_intact) {
    const auto p = end_caller();
    const auto back = fwd::decode_principal(fwd::encode_principal(p));
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(back->arn == p.arn);
    BOOST_TEST(static_cast<int>(back->type) == static_cast<int>(p.type));
    BOOST_TEST(back->role_arn == p.role_arn);
    BOOST_TEST(back->session_name == "s1");
    BOOST_TEST(back->source_identity == "alice");
    BOOST_TEST((back->tags == p.tags));
    BOOST_TEST(back->session_policies == p.session_policies);
    BOOST_TEST(back->transitive_tag_keys == p.transitive_tag_keys);
    BOOST_TEST((back->expires == p.expires));
    BOOST_TEST((back->token_issue_time == p.token_issue_time));
    for (const std::string bad : {"", "!!!!", "e30=" /* {} */, "bnVsbA==" /* null */}) {
        BOOST_TEST(!fwd::decode_principal(bad).has_value(), bad);
    }
}

BOOST_AUTO_TEST_CASE(in_process_calls_are_the_callers_through_the_service) {
    fixture f;
    const auto id = f.create();
    recorder rec;
    rec.install(f);
    kms::in_process_client client(f.fe);
    const auto who = kinesis_caller();

    auto res = client.call(
        who,
        service_request("GenerateDataKey", R"({"KeyId":")" + id + R"(","KeySpec":"AES_256"})"));
    BOOST_REQUIRE_MESSAGE(res.status == 200, res.body);
    BOOST_REQUIRE(!rec.who.empty());
    BOOST_TEST(rec.who.back() == end_caller().arn);
    BOOST_TEST(rec.via.back().value_or("") == k_via);
    const auto blob = json::parse(res.body).as_object().at("CiphertextBlob").as_string();

    res = client.call(
        who, service_request("Decrypt", R"({"CiphertextBlob":")" + std::string(blob) + R"("})"));
    BOOST_TEST(res.status == 200, res.body);
    BOOST_TEST(rec.via.back().value_or("") == k_via);

    // Administration is not taken through a service, whatever the caller
    // could do on the listener.
    for (const char* op : {"CreateKey", "ScheduleKeyDeletion", "PutKeyPolicy", "CreateGrant"}) {
        res = client.call(who, service_request(op, kid(id)));
        BOOST_TEST(res.status == 400, op);
        BOOST_TEST(res.body.find("UnsupportedOperationException") != std::string::npos, op);
    }
    // A consumer that forgets who it serves gets an error, not the
    // module's own authority.
    auto anonymous = service_request("DescribeKey", kid(id));
    anonymous.principal = {};
    BOOST_TEST(client.call(who, anonymous).status == 500);

    client.close();
    BOOST_TEST(client.call(who, service_request("DescribeKey", kid(id))).status == 503);
}

BOOST_AUTO_TEST_CASE(a_trusted_service_forwards_its_caller_over_https) {
    fixture f;
    const auto id = f.create();
    recorder rec;
    rec.install(f);
    const auto svc = endpoint("AKIDSVC");
    const auto signed_req =
        svc.sign(service_request("Encrypt", R"({"KeyId":")" + id + R"(","Plaintext":"aGk="})"),
                 k_now, "kms.us-east-1.amazonaws.com");
    BOOST_TEST(fwd::header_is_signed(signed_req.headers, fwd::principal_header));
    BOOST_TEST(fwd::header_is_signed(signed_req.headers, fwd::via_service_header));
    const auto r = fixture::answer(f.handle(as_received(signed_req)));
    BOOST_REQUIRE_MESSAGE(r.status == 200U, r.type() + ": " + r.message());
    BOOST_TEST(rec.who.back() == end_caller().arn);
    BOOST_TEST(rec.via.back().value_or("") == k_via);
    BOOST_TEST(f.auth.asked.back().source_ip == "203.0.113.9");

    // Administration is refused even from a trusted service.
    const auto admin = fixture::answer(f.handle(as_received(
        svc.sign(service_request("DisableKey", kid(id)), k_now, "kms.us-east-1.amazonaws.com"))));
    BOOST_TEST(admin.type() == "AccessDeniedException");
}

BOOST_AUTO_TEST_CASE(only_trusted_signers_may_forward) {
    fixture f;
    const auto id = f.create();
    recorder rec;
    rec.install(f);

    // A principal not among the trusted services.
    const auto stranger =
        endpoint("AKIDREAD")
            .sign(service_request("DescribeKey", kid(id)), k_now, "kms.us-east-1.amazonaws.com");
    auto r = fixture::answer(f.handle(as_received(stranger)));
    BOOST_TEST(r.type() == "AccessDeniedException");
    BOOST_TEST(r.message().find("not a service trusted") != std::string::npos, r.message());
    BOOST_TEST(rec.who.empty());

    // A trusted signer, but the principal header added after signing.
    auto unsigned_hdr = sign(request("DescribeKey", kid(id)), "AKIDSVC");
    unsigned_hdr.headers.emplace_back("X-Kythira-Principal", fwd::encode_principal(end_caller()));
    unsigned_hdr.headers.emplace_back("X-Kythira-Via-Service", "kinesis");
    r = fixture::answer(f.handle(unsigned_hdr));
    BOOST_TEST(r.type() == "AccessDeniedException");
    BOOST_TEST(r.message().find("must be signed") != std::string::npos, r.message());

    // The trusted service on its own behalf: its own principal, no
    // ViaService.
    r = f.call("DescribeKey", kid(id), "AKIDSVC");
    BOOST_TEST(r.status == 200U);
    BOOST_TEST(rec.who.back() == k_service_arn);
    BOOST_TEST(!rec.via.back().has_value());
}

BOOST_AUTO_TEST_CASE(the_https_endpoint_refuses_administration_before_dialling) {
    auto svc = endpoint("AKIDSVC");
    const auto res = svc.call(kinesis_caller(), service_request("CreateKey", "{}"));
    BOOST_TEST(res.status == 400);
    BOOST_TEST(res.body.find("UnsupportedOperationException") != std::string::npos);
}
