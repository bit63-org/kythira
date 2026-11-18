// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_auth_test.cpp
/// @brief S3 request authentication and body checks (`s3_auth.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 6, Requirement 4.2):
///        header and presigned SigV4, every payload mode, signed and
///        unsigned streaming bodies, refused SigV2 and SigV4a, anonymous
///        requests, and an authorizer that cannot resolve keys.

#define BOOST_TEST_MODULE s3_auth_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_auth.hpp>

#include <raft/static_key_authorizer.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace {

namespace s3 = kythira::s3;
namespace sv4 = kythira::sigv4;
namespace az = kythira::aws_auth;

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_date = "20261118T120000Z";
const auto k_now = sv4::detail::parse_amz_date(k_date).value();
const sv4::credential_scope k_scope{"20261118", "us-east-1", "s3"};

auto authorizer() -> std::unique_ptr<az::static_key_authorizer> {
    auto a = std::make_unique<az::static_key_authorizer>(
        std::vector<az::static_key>{{"AKIDS3", std::string(k_secret), "111122223333", "writer",
                                     az::static_role::read_write}},
        "aws", [] { return std::chrono::system_clock::time_point(k_now); });
    return a;
}

/// An authorizer that can only authenticate, as before key resolution.
struct authenticate_only {
    az::static_key_authorizer* inner;
    auto authenticate(const sv4::request& r, const sv4::service_rules& rules) -> az::authn_result {
        return inner->authenticate(r, rules);
    }
    auto authorize(const az::principal_context& w, const az::authz_request& r)
        -> az::authz_decision {
        return inner->authorize(w, r);
    }
};
static_assert(az::aws_request_authorizer<authenticate_only>);
static_assert(!az::aws_claim_resolver<authenticate_only>);

struct http {
    std::string method = "GET";
    std::string path = "/bk1/key";
    std::string query;
    std::vector<std::pair<std::string, std::string>> headers;

    [[nodiscard]] auto view() const -> sv4::request {
        return {method, path, query, headers, std::nullopt};
    }
};

const auto rules = s3::s3_rules();

auto hex_key() -> sv4::signing_key {
    return sv4::derive_signing_key(k_secret, k_scope);
}

/// Sign a header-signed request whose x-amz-content-sha256 is `payload`.
auto header_signed(http r, std::string payload, std::string_view secret = k_secret) -> http {
    r.headers.emplace_back("Host", "s3.kythira.test");
    r.headers.emplace_back("X-Amz-Date", std::string(k_date));
    r.headers.emplace_back("x-amz-content-sha256", std::move(payload));
    std::string signed_names;
    std::vector<std::string> names;
    for (const auto& [k, v] : r.headers) {
        names.push_back(sv4::detail::lower(k));
    }
    std::ranges::sort(names);
    for (const auto& n : names) {
        signed_names += (signed_names.empty() ? "" : ";") + n;
    }
    const auto auth = [&](std::string_view sig) {
        return "AWS4-HMAC-SHA256 Credential=AKIDS3/" + k_scope.text() +
               ", SignedHeaders=" + signed_names + ", Signature=" + std::string(sig);
    };
    r.headers.emplace_back("Authorization", auth(std::string(64, '0')));
    const auto parsed = sv4::parse(r.view(), rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    r.headers.back().second =
        auth(sv4::compute_signature(*parsed, sv4::derive_signing_key(secret, k_scope)));
    return r;
}

auto presigned(http r) -> http {
    r.headers = {{"Host", "s3.kythira.test"}};
    const auto q = [&](std::string_view sig) {
        return "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDS3%2F20261118%2Fus-east-1%"
               "2Fs3%"
               "2Faws4_request&X-Amz-Date=" +
               std::string(k_date) +
               "&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" + std::string(sig);
    };
    r.query = q(std::string(64, '0'));
    const auto parsed = sv4::parse(r.view(), rules, k_now);
    BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
    r.query = q(sv4::compute_signature(*parsed, hex_key()));
    return r;
}

/// The aws-chunked signed body for `chunks`, seeded by the request's
/// signature.
auto signed_chunks(const sv4::claim& c, const std::vector<std::string>& chunks) -> std::string {
    std::string prev = c.signature;
    std::string out;
    const auto key = hex_key();
    auto add = [&](std::string_view data) {
        const auto sts = "AWS4-HMAC-SHA256-PAYLOAD\n" + std::string(k_date) + "\n" +
                         k_scope.text() + "\n" + prev + "\n" + std::string(sv4::k_empty_sha256) +
                         "\n" + sv4::detail::sha256_hex(data);
        prev = sv4::detail::to_hex(sv4::detail::hmac_sha256(key, sts));
        char size[32];
        std::snprintf(size, sizeof size, "%zx", data.size());
        out += std::string(size) + ";chunk-signature=" + prev + "\r\n" + std::string(data) + "\r\n";
    };
    for (const auto& ch : chunks) {
        add(ch);
    }
    add("");
    return out;
}

/// Feed `body` in pieces of `step` and finish.
auto read_body(s3::payload_reader& r, std::string_view body, std::size_t step = 7)
    -> std::pair<std::string, std::optional<kythira::aws_rest_xml::error>> {
    std::string out;
    for (std::size_t i = 0; i < body.size(); i += step) {
        if (auto e = r.feed(body.substr(i, step), out)) {
            return {out, e};
        }
    }
    return {out, r.finish()};
}

}  // namespace

BOOST_AUTO_TEST_CASE(a_header_signature_authenticates_and_checks_the_body_hash) {
    auto a = authorizer();
    const std::string body = "hello, s3";
    http put;
    put.method = "PUT";
    const auto req = header_signed(put, sv4::detail::sha256_hex(body));
    auto auth = s3::authenticate(*a, req.view(), rules, k_now);
    BOOST_TEST_REQUIRE(auth.has_value(), (auth ? "" : auth.error().code));
    BOOST_TEST((auth->kind == s3::auth_kind::header));
    BOOST_TEST(auth->who->username == "writer");
    BOOST_TEST(auth->auth_type() == "REST-HEADER");
    BOOST_TEST(*auth->signature_age_ms == 0);
    BOOST_TEST(!auth->key.has_value());  // only kept for signed streaming
    {
        s3::payload_reader r(*auth, req.view());
        auto [out, err] = read_body(r, body);
        BOOST_TEST(!err.has_value());
        BOOST_TEST(out == body);
    }
    {
        s3::payload_reader r(*auth, req.view());
        auto [out, err] = read_body(r, "hello, s4");
        BOOST_TEST_REQUIRE(err.has_value());
        BOOST_TEST(err->code == "XAmzContentSHA256Mismatch");
        BOOST_TEST(err->status == 400U);
    }
}

BOOST_AUTO_TEST_CASE(wrong_secrets_and_unknown_keys_are_s3_errors) {
    auto a = authorizer();
    const auto bad = header_signed(http{}, std::string(sv4::k_empty_sha256), "not-the-secret");
    auto r = s3::authenticate(*a, bad.view(), rules, k_now);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().code == "SignatureDoesNotMatch");
    BOOST_TEST(r.error().status == 403U);

    auto unknown = header_signed(http{}, std::string(sv4::k_empty_sha256));
    auto& h = unknown.headers.back().second;
    h.replace(h.find("AKIDS3"), 6, "AKIDXX");
    r = s3::authenticate(*a, unknown.view(), rules, k_now);
    BOOST_TEST(r.error().code == "InvalidAccessKeyId");

    // Too far from the server's clock.
    const auto late = header_signed(http{}, std::string(sv4::k_empty_sha256));
    r = s3::authenticate(*a, late.view(), rules, k_now + std::chrono::hours(1));
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().code == "RequestTimeTooSkewed");
}

BOOST_AUTO_TEST_CASE(presigned_urls_and_unsigned_payloads) {
    auto a = authorizer();
    const auto req = presigned(http{});
    auto auth = s3::authenticate(*a, req.view(), rules, k_now + std::chrono::minutes(30));
    BOOST_TEST_REQUIRE(auth.has_value(), (auth ? "" : auth.error().message));
    BOOST_TEST((auth->kind == s3::auth_kind::presigned));
    BOOST_TEST(auth->auth_type() == "REST-QUERY-STRING");
    BOOST_TEST(*auth->signature_age_ms == 30 * 60 * 1000);
    BOOST_TEST((auth->payload() == sv4::payload_mode::unsigned_payload));
    // Past X-Amz-Expires.
    auto expired = s3::authenticate(*a, req.view(), rules, k_now + std::chrono::hours(2));
    BOOST_TEST_REQUIRE(!expired.has_value());
    BOOST_TEST(expired.error().code == "AccessDenied");

    http put;
    put.method = "PUT";
    const auto unsigned_put = header_signed(put, "UNSIGNED-PAYLOAD");
    auth = s3::authenticate(*a, unsigned_put.view(), rules, k_now);
    BOOST_TEST_REQUIRE(auth.has_value());
    s3::payload_reader r(*auth, unsigned_put.view());
    auto [out, err] = read_body(r, "anything at all");
    BOOST_TEST(!err.has_value());
    BOOST_TEST(out == "anything at all");
}

BOOST_AUTO_TEST_CASE(a_signed_streaming_body_is_verified_chunk_by_chunk) {
    auto a = authorizer();
    http put;
    put.method = "PUT";
    const std::vector<std::string> chunks{std::string(9000, 'a'), std::string(9000, 'b'), "tail"};
    put.headers = {{"Content-Encoding", "aws-chunked"},
                   {"x-amz-decoded-content-length", std::to_string(18004)}};
    const auto req = header_signed(put, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
    auto auth = s3::authenticate(*a, req.view(), rules, k_now);
    BOOST_TEST_REQUIRE(auth.has_value(), (auth ? "" : auth.error().message));
    BOOST_TEST(auth->key.has_value());
    const auto body = signed_chunks(*auth->claim, chunks);
    {
        s3::payload_reader r(*auth, req.view());
        auto [out, err] = read_body(r, body, 1000);
        BOOST_TEST(!err.has_value(), (err ? err->message : ""));
        BOOST_TEST(out == chunks[0] + chunks[1] + chunks[2]);
    }
    {
        // A flipped byte in the second chunk: it is never released.
        auto bad = body;
        bad[bad.find('b') + 10] = 'c';
        s3::payload_reader r(*auth, req.view());
        auto [out, err] = read_body(r, bad, 1000);
        BOOST_TEST_REQUIRE(err.has_value());
        BOOST_TEST(err->code == "SignatureDoesNotMatch");
        BOOST_TEST(out.find('c') == std::string::npos);
    }

    // Without key resolution, signed streaming cannot be checked.
    authenticate_only plain{a.get()};
    auto refused = s3::authenticate(plain, req.view(), rules, k_now);
    BOOST_TEST_REQUIRE(!refused.has_value());
    BOOST_TEST(refused.error().status == 501U);
    // Everything else still works.
    const auto get = header_signed(http{}, std::string(sv4::k_empty_sha256));
    auto ok = s3::authenticate(plain, get.view(), rules, k_now);
    BOOST_TEST_REQUIRE(ok.has_value());
    BOOST_TEST(ok->who->username == "writer");
}

BOOST_AUTO_TEST_CASE(an_unsigned_streaming_body_hands_over_its_trailer) {
    auto a = authorizer();
    http put;
    put.method = "PUT";
    put.headers = {{"Content-Encoding", "aws-chunked"},
                   {"x-amz-decoded-content-length", "11"},
                   {"x-amz-trailer", "x-amz-checksum-crc32"}};
    const auto req = header_signed(put, "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
    auto auth = s3::authenticate(*a, req.view(), rules, k_now);
    BOOST_TEST_REQUIRE(auth.has_value(), (auth ? "" : auth.error().message));
    const std::string body = "b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";
    s3::payload_reader r(*auth, req.view());
    auto [out, err] = read_body(r, body, 3);
    BOOST_TEST(!err.has_value(), (err ? err->message : ""));
    BOOST_TEST(out == "hello world");
    const auto t = r.trailers();
    BOOST_TEST_REQUIRE(t.size() == 1U);
    BOOST_TEST(t[0].first == "x-amz-checksum-crc32");
    BOOST_TEST(t[0].second == "DUoRhQ==");
    // Truncated: the end never came.
    s3::payload_reader cut(*auth, req.view());
    auto [o2, e2] = read_body(cut, std::string_view(body).substr(0, 20), 3);
    BOOST_TEST(e2.has_value());
}

BOOST_AUTO_TEST_CASE(sigv2_and_sigv4a_are_refused_as_s3_does) {
    auto a = authorizer();
    http v2;
    v2.headers = {{"Authorization", "AWS AKIDS3:frJIUN8DYpKDtOLCwo//yllqDzg="}};
    auto r = s3::authenticate(*a, v2.view(), rules, k_now);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST(r.error().code == "InvalidRequest");
    BOOST_TEST(r.error().status == 400U);

    http v2q;
    v2q.query = "AWSAccessKeyId=AKIDS3&Expires=1700000000&Signature=abc%3D";
    BOOST_TEST(s3::authenticate(*a, v2q.view(), rules, k_now).error().code == "InvalidRequest");

    http v4a;
    v4a.headers = {{"Authorization",
                    "AWS4-ECDSA-P256-SHA256 Credential=AKIDS3/20261118/s3/"
                    "aws4_request, SignedHeaders=host, Signature=3045"}};
    BOOST_TEST(s3::authenticate(*a, v4a.view(), rules, k_now).error().code == "InvalidRequest");
    http v4aq;
    v4aq.query = "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256&X-Amz-Credential=x";
    BOOST_TEST(s3::authenticate(*a, v4aq.view(), rules, k_now).error().code == "InvalidRequest");
}

BOOST_AUTO_TEST_CASE(a_request_without_a_signature_is_anonymous) {
    auto a = authorizer();
    http anon;
    anon.headers = {{"Host", "bk1.s3.kythira.test"}};
    auto r = s3::authenticate(*a, anon.view(), rules, k_now);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->kind == s3::auth_kind::anonymous));
    BOOST_TEST(!r->who.has_value());
    BOOST_TEST(r->auth_type().empty());
    s3::payload_reader body(*r, anon.view());
    auto [out, err] = read_body(body, "public bytes");
    BOOST_TEST(!err.has_value());
    BOOST_TEST(out == "public bytes");
}
