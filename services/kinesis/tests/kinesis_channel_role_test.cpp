// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Assuming a channel's service execution role (`.kiro/specs/kinesis-
// compatible-streams/` task 19): requests signed here verify with the
// server-side SigV4 checks, STS `AssumeRole` is asked as the query protocol
// spells it and its answer and refusals are read, and the credential cache
// reuses a set until it nears expiry, remembers a refusal for a while, and
// keeps using unexpired credentials while STS refuses a refresh.

#define BOOST_TEST_MODULE kinesis_channel_role_test

#include <boost/test/unit_test.hpp>

#include <kythira/kinesis/kinesis_aws_call.hpp>
#include <kythira/kinesis/kinesis_channel_role.hpp>

#include <raft/sigv4_verifier.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kin = kythira::kinesis;
namespace sv4 = kythira::sigv4;

namespace {

constexpr std::string_view k_role = "arn:aws:iam::111122223333:role/channel-delivery";

// 2026-11-19T12:00:00Z.
const std::chrono::sys_seconds k_now{std::chrono::seconds{1'795'089'600}};

auto node_creds() -> kin::sigv4_credentials {
    return kin::sigv4_credentials{._access_key_id = "AKIDNODE",
                                  ._secret_access_key = "node-secret",
                                  ._session_token = {},
                                  ._expires_ms = 0};
}

/// Verifies `req` as a server would, with `secret`.
auto verifies(const kin::aws_request& req, std::string_view service, std::string_view secret,
              bool s3 = false) -> bool {
    sv4::request r;
    const auto method = std::string(boost::beast::http::to_string(req._method));
    r.method = method;
    r.raw_path = req._path;
    r.raw_query = req._query;
    r.headers = req._headers;
    r.body = req._body;
    sv4::service_rules rules;
    rules.service = std::string(service);
    rules.s3_path_rules = s3;
    rules.protocol = s3 ? sv4::error_protocol::s3 : sv4::error_protocol::query;
    const auto c = sv4::parse(r, rules, k_now);
    BOOST_TEST_MESSAGE("parse: " << c.error().code << " " << c.error().message);
    if (!c) {
        return false;
    }
    return sv4::verify(*c, sv4::derive_signing_key(secret, c->scope));
}

auto header(const kin::aws_request& req, std::string_view name) -> std::string {
    for (const auto& [k, v] : req._headers) {
        if (sv4::detail::lower(k) == name) {
            return v;
        }
    }
    return {};
}

constexpr std::string_view k_answer =
    R"(<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROA:kythira-channel-1</AssumedRoleId>
      <Arn>arn:aws:sts::111122223333:assumed-role/channel-delivery/kythira-channel-1</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIATEMP</AccessKeyId>
      <SecretAccessKey>temp-secret</SecretAccessKey>
      <SessionToken>token&amp;more</SessionToken>
      <Expiration>2026-11-19T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>)";

constexpr std::string_view k_denied =
    R"(<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code>
  <Message>User: arn:aws:iam::111122223333:user/node is not authorized to perform: sts:AssumeRole</Message></Error>
</ErrorResponse>)";

}  // namespace

BOOST_AUTO_TEST_SUITE(kinesis_channel_role)

BOOST_AUTO_TEST_CASE(endpoints) {
    auto e = kin::parse_aws_endpoint("https://sts.us-east-1.amazonaws.com");
    BOOST_REQUIRE(e);
    BOOST_TEST(e->_tls);
    BOOST_TEST(e->_host_port == "sts.us-east-1.amazonaws.com:443");
    BOOST_TEST(e->_host == "sts.us-east-1.amazonaws.com");
    BOOST_TEST(e->_base_path.empty());

    e = kin::parse_aws_endpoint("http://iceberg-rest:8181/catalog/");
    BOOST_REQUIRE(e);
    BOOST_TEST(!e->_tls);
    BOOST_TEST(e->_host_port == "iceberg-rest:8181");
    BOOST_TEST(e->_host == "iceberg-rest:8181");
    BOOST_TEST(e->_base_path == "/catalog");

    e = kin::parse_aws_endpoint("https://s3tables.eu-west-1.amazonaws.com:443/iceberg");
    BOOST_REQUIRE(e);
    BOOST_TEST(e->_host == "s3tables.eu-west-1.amazonaws.com");
    BOOST_TEST(e->_base_path == "/iceberg");

    BOOST_TEST(!kin::parse_aws_endpoint("ftp://x"));
    BOOST_TEST(!kin::parse_aws_endpoint("https://"));
    BOOST_TEST(!kin::parse_aws_endpoint("https://host:99999"));
}

BOOST_AUTO_TEST_CASE(signed_requests_verify_server_side) {
    const auto e = *kin::parse_aws_endpoint("https://s3tables.us-east-1.amazonaws.com/iceberg");
    kin::aws_request req;
    req._method = boost::beast::http::verb::post;
    // An encoded ARN in the path, as the Iceberg REST prefix is sent.
    req._path =
        "/iceberg/v1/arn%3Aaws%3As3tables%3Aus-east-1%3A111122223333%3Abucket%2Fb/"
        "namespaces/ns/tables/t";
    req._query = "warehouse=a%20b&x=1";
    req._headers.emplace_back("Content-Type", "application/json");
    req._body = R"({"requirements":[],"updates":[]})";
    auto creds = node_creds();
    creds._session_token = "session";
    kin::sign_aws_request(req, e, creds, "us-east-1", "s3tables", k_now);
    BOOST_TEST(header(req, "x-amz-security-token") == "session");
    BOOST_TEST(header(req, "host") == "s3tables.us-east-1.amazonaws.com");
    BOOST_TEST(verifies(req, "s3tables", "node-secret"));
    BOOST_TEST(!verifies(req, "s3tables", "wrong-secret"));

    // A body changed after signing no longer verifies.
    req._body += " ";
    BOOST_TEST(!verifies(req, "s3tables", "node-secret"));
}

BOOST_AUTO_TEST_CASE(assume_role_asks_and_reads_the_answer) {
    std::vector<kin::aws_request> seen;
    kin::sts_client sts(kin::sts_config{._region = "us-east-1",
                                        ._endpoint = {},
                                        ._credentials = node_creds,
                                        ._clock = [] { return k_now; },
                                        ._duration_seconds = 3600},
                        [&](const kin::aws_endpoint& e, const kin::aws_request& r) {
                            BOOST_TEST(e._host_port == "sts.us-east-1.amazonaws.com:443");
                            seen.push_back(r);
                            return std::optional<kin::peer_response>(
                                kin::peer_response{._status = 200, ._body = std::string(k_answer)});
                        });
    const auto creds =
        sts.assume_role(k_role, kin::channel_role_session("00000000-0000-4000-8000-00000000002a"));
    BOOST_TEST(creds._access_key_id == "ASIATEMP");
    BOOST_TEST(creds._secret_access_key == "temp-secret");
    BOOST_TEST(creds._session_token == "token&more");
    BOOST_TEST(creds._expires_ms == std::int64_t{1'795'093'200'000});

    BOOST_REQUIRE(seen.size() == 1U);
    const auto& r = seen.front();
    BOOST_TEST(r._path == "/");
    BOOST_TEST(r._body ==
               "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A111122223333%"
               "3Arole%2Fchannel-delivery&RoleSessionName=kythira-channel-00000000-0000-4000-"
               "8000-00000000002a&DurationSeconds=3600");
    BOOST_TEST(verifies(r, "sts", "node-secret"));
}

BOOST_AUTO_TEST_CASE(assume_role_refusals) {
    unsigned status = 403;
    std::string body(k_denied);
    bool answer = true;
    kin::sts_client sts(kin::sts_config{._region = "eu-west-1",
                                        ._endpoint = "http://iam:8443",
                                        ._credentials = node_creds,
                                        ._clock = [] { return k_now; },
                                        ._duration_seconds = 900},
                        [&](const kin::aws_endpoint& e,
                            const kin::aws_request&) -> std::optional<kin::peer_response> {
                            BOOST_TEST(!e._tls);
                            BOOST_TEST(e._host_port == "iam:8443");
                            if (!answer) {
                                return std::nullopt;
                            }
                            return kin::peer_response{._status = status, ._body = body};
                        });
    auto code_of = [&] {
        try {
            (void)sts.assume_role(k_role, "s");
        } catch (const kin::channel_role_error& e) {
            BOOST_TEST_MESSAGE(e.what());
            BOOST_TEST(std::string(e.what()).find(k_role) != std::string::npos);
            return e.code();
        }
        return std::string("none");
    };
    BOOST_TEST(code_of() == "AccessDenied");
    answer = false;
    BOOST_TEST(code_of() == "ServiceUnavailable");
    answer = true;
    status = 200;
    body = "<AssumeRoleResponse></AssumeRoleResponse>";
    BOOST_TEST(code_of() == "InvalidResponse");
    status = 500;
    body = "nonsense";
    BOOST_TEST(code_of() == "HTTP500");

    kin::sts_client keyless(kin::sts_config{._region = "eu-west-1",
                                            ._endpoint = {},
                                            ._credentials = {},
                                            ._clock = {},
                                            ._duration_seconds = 3600},
                            [](const kin::aws_endpoint&, const kin::aws_request&) {
                                return std::optional<kin::peer_response>{};
                            });
    try {
        (void)keyless.assume_role(k_role, "s");
        BOOST_FAIL("no credentials should refuse");
    } catch (const kin::channel_role_error& e) {
        BOOST_TEST(e.code() == "MissingAuthenticationToken");
    }
}

BOOST_AUTO_TEST_CASE(credentials_are_cached_and_refreshed) {
    std::int64_t now = 1'000'000;
    int calls = 0;
    bool refuse = false;
    kin::channel_role_credentials cache(
        [&](std::string_view role, std::string_view session) {
            ++calls;
            if (refuse) {
                throw kin::channel_role_error("AccessDenied", "refused");
            }
            return kin::sigv4_credentials{
                ._access_key_id =
                    std::string(role) + "/" + std::string(session) + "/" + std::to_string(calls),
                ._secret_access_key = "s",
                ._session_token = "t",
                ._expires_ms = now + 3'600'000};
        },
        kin::channel_role_cache_config{._refresh_before_ms = 300'000,
                                       ._retry_after_ms = 30'000,
                                       ._now_ms = [&] { return now; }});

    const auto a = cache.get("role-a", "s1");
    BOOST_TEST(a._access_key_id == "role-a/s1/1");
    // The same set until five minutes before it expires.
    now += 3'000'000;
    BOOST_TEST(cache.get("role-a", "s1")._access_key_id == "role-a/s1/1");
    BOOST_TEST(calls == 1);
    // Another role, or session, is its own set.
    BOOST_TEST(cache.get("role-b", "s1")._access_key_id == "role-b/s1/2");
    BOOST_TEST(cache.get("role-a", "s2")._access_key_id == "role-a/s2/3");

    // Inside the refresh window: asked again.
    now += 400'000;
    BOOST_TEST(cache.get("role-a", "s1")._access_key_id == "role-a/s1/4");

    // STS refuses a refresh while the old set still works: the old set.
    refuse = true;
    now += 3'400'000;
    BOOST_TEST(cache.get("role-a", "s1")._access_key_id == "role-a/s1/4");
    BOOST_TEST(calls == 5);
    // Within the retry window STS is not asked again.
    BOOST_TEST(cache.get("role-a", "s1")._access_key_id == "role-a/s1/4");
    BOOST_TEST(calls == 5);

    // Once the set has expired, the refusal is the answer, remembered for
    // the retry window.
    now += 300'000;
    BOOST_CHECK_THROW((void)cache.get("role-a", "s1"), kin::channel_role_error);
    BOOST_TEST(calls == 6);
    BOOST_CHECK_THROW((void)cache.get("role-a", "s1"), kin::channel_role_error);
    BOOST_TEST(calls == 6);
    now += 30'000;
    refuse = false;
    BOOST_TEST(cache.get("role-a", "s1")._access_key_id == "role-a/s1/7");
    BOOST_TEST(cache.calls() == 7U);
}

BOOST_AUTO_TEST_CASE(iso8601) {
    BOOST_TEST(kin::parse_iso8601_ms("1970-01-01T00:00:00Z").value() == 0);
    BOOST_TEST(kin::parse_iso8601_ms("2026-11-19T13:00:00.123Z").value() ==
               std::int64_t{1'795'093'200'000});
    BOOST_TEST(!kin::parse_iso8601_ms("2026-02-30T00:00:00Z"));
    BOOST_TEST(!kin::parse_iso8601_ms("yesterday"));
}

BOOST_AUTO_TEST_SUITE_END()
