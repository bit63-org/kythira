// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_post_policy_test.cpp
/// @brief Browser POST uploads (`s3_post_policy.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 6, Requirement 4.3): the
///        streaming multipart/form-data parser, the policy document and its
///        conditions, and the policy's SigV4 signature.

#define BOOST_TEST_MODULE s3_post_policy_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_post_policy.hpp>

#include <raft/static_key_authorizer.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace s3 = kythira::s3;
namespace sv4 = kythira::sigv4;
namespace az = kythira::aws_auth;

using fields_t = std::vector<std::pair<std::string, std::string>>;

constexpr std::string_view k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr std::string_view k_boundary = "----kythiraFormBoundary7MA4YWxkTrZu0gW";
const auto k_now = sv4::detail::parse_amz_date("20261118T120000Z").value();

auto authorizer() -> std::unique_ptr<az::static_key_authorizer> {
    return std::make_unique<az::static_key_authorizer>(
        std::vector<az::static_key>{{"AKIDS3", std::string(k_secret), "111122223333", "writer",
                                     az::static_role::read_write}},
        "aws", [] { return std::chrono::system_clock::time_point(k_now); });
}

auto body(const fields_t& before, std::string_view file, const fields_t& after = {},
          std::string_view filename = "photo.jpg") -> std::string {
    std::string b;
    const auto part = [&](const std::string& name, const std::string& value) {
        b += "--" + std::string(k_boundary) + "\r\n";
        b += R"(Content-Disposition: form-data; name=")" + name + "\"\r\n\r\n";
        b += value + "\r\n";
    };
    for (const auto& [k, v] : before) {
        part(k, v);
    }
    b += "--" + std::string(k_boundary) + "\r\n";
    b += R"(Content-Disposition: form-data; name="file"; filename=")" + std::string(filename) +
         "\"\r\n";
    b += "Content-Type: image/jpeg\r\n\r\n";
    b += std::string(file) + "\r\n";
    for (const auto& [k, v] : after) {
        part(k, v);
    }
    b += "--" + std::string(k_boundary) + "--\r\n";
    return b;
}

struct parsed {
    s3::form_reader::status st;
    s3::post_form form;
    std::string file;
    std::string code;
};

/// Parse `b` fed `step` bytes at a time.
auto parse(const std::string& b, std::size_t step, s3::form_limits lim = {}) -> parsed {
    s3::form_reader r(k_boundary, lim);
    std::string file;
    for (std::size_t i = 0; i < b.size(); i += step) {
        r.feed(std::string_view(b).substr(i, step), file);
    }
    const auto st = r.finish();
    return {st, r.form(), file, st == s3::form_reader::status::failed ? r.error().code : ""};
}

auto b64(std::string_view s) -> std::string {
    return kythira::aws_json::base64_encode(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()),  // NOLINT
                                   s.size()));
}

const std::string k_policy_json =
    R"({"expiration":"2026-11-18T13:00:00.000Z","conditions":[)"
    R"({"bucket":"bk1"},["starts-with","$key","user/"],{"acl":"private"},)"
    R"(["starts-with","$Content-Type","image/"],["content-length-range",1,1048576],)"
    R"({"x-amz-algorithm":"AWS4-HMAC-SHA256"},)"
    R"({"x-amz-credential":"AKIDS3/20261118/us-east-1/s3/aws4_request"},)"
    R"({"x-amz-date":"20261118T120000Z"}]})";

/// A signed form for `policy_json`.
auto signed_fields(const std::string& policy_json, std::string_view secret = k_secret) -> fields_t {
    const auto policy = b64(policy_json);
    const auto key = sv4::derive_signing_key(secret, {"20261118", "us-east-1", "s3"});
    const auto sig = sv4::detail::to_hex(sv4::detail::hmac_sha256(key, policy));
    return {{"key", "user/${filename}"},
            {"acl", "private"},
            {"Content-Type", "image/jpeg"},
            {"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
            {"X-Amz-Credential", "AKIDS3/20261118/us-east-1/s3/aws4_request"},
            {"X-Amz-Date", "20261118T120000Z"},
            {"Policy", policy},
            {"X-Amz-Signature", sig}};
}

auto form_of(const fields_t& f) -> s3::post_form {
    s3::post_form form;
    form.fields = f;
    form.filename = "photo.jpg";
    return form;
}

const auto rules = s3::s3_rules();
const std::chrono::system_clock::time_point now_tp(k_now);

template<class R> auto code(const R& r) -> std::string {
    return r ? std::string{} : r.error().code;
}

}  // namespace

BOOST_AUTO_TEST_CASE(boundary_from_content_type) {
    BOOST_TEST(s3::form_boundary("multipart/form-data; boundary=abc").value_or("") == "abc");
    BOOST_TEST(
        s3::form_boundary(R"(Multipart/Form-Data; charset=utf-8; boundary="a b")").value_or("") ==
        "a b");
    BOOST_TEST(!s3::form_boundary("application/x-www-form-urlencoded").has_value());
    BOOST_TEST(!s3::form_boundary("multipart/form-data").has_value());
}

BOOST_AUTO_TEST_CASE(form_parses_at_every_split) {
    const std::string file(3000, 'x');
    const auto b = body({{"key", "a/${filename}"}, {"acl", "private"}}, file + "\r\n--almost",
                        {{"after", "ignored"}});
    for (std::size_t step : {std::size_t{1}, std::size_t{7}, std::size_t{64}, b.size()}) {
        const auto p = parse(b, step);
        BOOST_TEST_REQUIRE((p.st == s3::form_reader::status::done),
                           "step " << step << " " << p.code);
        BOOST_TEST(p.file == file + "\r\n--almost");
        BOOST_TEST(p.form.fields.size() == 2U);
        BOOST_TEST(p.form.get("ACL").value_or("") == "private");
        BOOST_TEST(!p.form.get("after").has_value());
        BOOST_TEST(p.form.filename == "photo.jpg");
        BOOST_TEST(p.form.file_content_type == "image/jpeg");
        BOOST_TEST(p.form.object_key().value_or("") == "a/photo.jpg");
    }
}

BOOST_AUTO_TEST_CASE(fields_are_known_before_the_file_is_stored) {
    const auto b = body({{"key", "k"}}, std::string(10000, 'y'));
    s3::form_reader r(k_boundary);
    std::string file;
    const auto cut = b.find("yyyy") + 100;
    BOOST_TEST((r.feed(std::string_view(b).substr(0, cut), file) == s3::form_reader::status::file));
    BOOST_TEST(r.fields_complete());
    BOOST_TEST(r.form().get("key").value_or("") == "k");
    BOOST_TEST(file.size() < 100U);  // held back until no boundary can hide in it
    r.feed(std::string_view(b).substr(cut), file);
    BOOST_TEST((r.finish() == s3::form_reader::status::done));
    BOOST_TEST(r.file_bytes() == 10000U);
}

BOOST_AUTO_TEST_CASE(malformed_forms) {
    // No file part.
    std::string no_file = "--" + std::string(k_boundary) +
                          "\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--" +
                          std::string(k_boundary) + "--\r\n";
    BOOST_TEST(parse(no_file, 5).code == "InvalidArgument");
    // Truncated.
    const auto b = body({{"key", "k"}}, "data");
    BOOST_TEST(parse(b.substr(0, b.size() - 10), 9).code == "MalformedPOSTRequest");
    // A part without Content-Disposition.
    std::string bad = "--" + std::string(k_boundary) + "\r\nX: y\r\n\r\nv\r\n--" +
                      std::string(k_boundary) + "--\r\n";
    BOOST_TEST(parse(bad, 3).code == "MalformedPOSTRequest");
    // Fields over the limit.
    s3::form_limits lim;
    lim.max_field_bytes = 100;
    BOOST_TEST(parse(body({{"key", std::string(200, 'k')}}, "d"), 11, lim).code ==
               "MaxPostPreDataLengthExceeded");
}

BOOST_AUTO_TEST_CASE(policy_documents) {
    auto p = s3::parse_post_policy(k_policy_json);
    BOOST_TEST_REQUIRE(p.has_value(), code(p));
    BOOST_TEST(p->conditions.size() == 8U);
    BOOST_TEST(p->conditions[0].field == "bucket");
    BOOST_TEST(p->conditions[3].field == "content-type");
    BOOST_TEST((p->conditions[4].op == s3::post_condition::kind::content_length_range));
    BOOST_TEST(p->conditions[4].max == 1048576U);
    BOOST_TEST(s3::parse_post_policy(R"({"expiration":"2026-11-18T13:00:00Z","conditions":[]})")
                   .has_value());

    for (const char* bad : {
             "nope",
             R"({"conditions":[]})",
             R"({"expiration":"tomorrow","conditions":[]})",
             R"({"expiration":"2026-02-30T00:00:00Z","conditions":[]})",
             R"({"expiration":"2026-11-18T13:00:00Z"})",
             R"({"expiration":"2026-11-18T13:00:00Z","conditions":[["in","$key","a"]]})",
             R"({"expiration":"2026-11-18T13:00:00Z","conditions":[["eq","key","a"]]})",
             R"({"expiration":"2026-11-18T13:00:00Z","conditions":[["content-length-range",9,1]]})",
             R"({"expiration":"2026-11-18T13:00:00Z","conditions":[{"a":"b","c":"d"}]})",
         }) {
        BOOST_TEST(code(s3::parse_post_policy(bad)) == "InvalidPolicyDocument", bad);
    }
}

BOOST_AUTO_TEST_CASE(policy_conditions) {
    const auto p = s3::parse_post_policy(k_policy_json).value();
    auto form = form_of(signed_fields(k_policy_json));
    BOOST_TEST(!s3::check_post_policy(p, form, "bk1", now_tp).has_value());

    auto e = s3::check_post_policy(p, form, "bk2", now_tp);
    BOOST_TEST_REQUIRE(e.has_value());
    BOOST_TEST(e->code == "AccessDenied");
    BOOST_TEST(e->message.find("Policy Condition failed") != std::string::npos);

    BOOST_TEST(s3::check_post_policy(p, form, "bk1", now_tp + std::chrono::hours(2))
                   ->message.find("Policy expired") != std::string::npos);

    auto other_key = form;
    other_key.fields[0].second = "admin/x";
    BOOST_TEST(s3::check_post_policy(p, other_key, "bk1", now_tp).has_value());

    // Every comma-separated content type must match.
    auto types = form;
    types.fields[2].second = "image/png, text/html";
    BOOST_TEST(s3::check_post_policy(p, types, "bk1", now_tp).has_value());

    // A field no condition names.
    auto extra = form;
    extra.fields.emplace_back("x-amz-meta-owner", "me");
    extra.fields.emplace_back("x-ignore-this", "fine");
    auto ex = s3::check_post_policy(p, extra, "bk1", now_tp);
    BOOST_TEST_REQUIRE(ex.has_value());
    BOOST_TEST(ex->message.find("Extra input fields: x-amz-meta-owner") != std::string::npos);

    BOOST_TEST(!s3::check_post_length(p, 10).has_value());
    BOOST_TEST(s3::check_post_length(p, 0)->code == "EntityTooSmall");
    BOOST_TEST(s3::check_post_length(p, 2U << 20U)->code == "EntityTooLarge");
}

BOOST_AUTO_TEST_CASE(signed_forms_authenticate) {
    auto a = authorizer();
    auto r = s3::authenticate_post(*a, form_of(signed_fields(k_policy_json)), "bk1", rules, now_tp);
    BOOST_TEST_REQUIRE(r.has_value(), code(r));
    BOOST_TEST((r->auth.kind == s3::auth_kind::post));
    BOOST_TEST(r->auth.auth_type() == "POST");
    BOOST_TEST_REQUIRE(r->auth.who.has_value());
    BOOST_TEST(r->auth.who->account == "111122223333");
    BOOST_TEST(r->key == "user/photo.jpg");
    BOOST_TEST(r->policy.has_value());

    // The wrong secret.
    auto wrong = s3::authenticate_post(*a, form_of(signed_fields(k_policy_json, "other-secret")),
                                       "bk1", rules, now_tp);
    BOOST_TEST(code(wrong) == "SignatureDoesNotMatch");

    // A policy changed after signing.
    auto tampered = signed_fields(k_policy_json);
    tampered[6].second = b64(R"({"expiration":"2030-01-01T00:00:00Z","conditions":[]})");
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(tampered), "bk1", rules, now_tp)) ==
               "SignatureDoesNotMatch");

    // An unknown key.
    auto unknown = signed_fields(k_policy_json);
    unknown[4].second = "AKIDNOPE/20261118/us-east-1/s3/aws4_request";
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(unknown), "bk1", rules, now_tp)) ==
               "InvalidAccessKeyId");

    // A valid signature does not excuse the policy.
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(signed_fields(k_policy_json)), "bk2", rules,
                                          now_tp)) == "AccessDenied");
}

BOOST_AUTO_TEST_CASE(incomplete_and_refused_forms) {
    auto a = authorizer();
    const auto without = [](fields_t f, std::string_view name) {
        std::erase_if(f, [&](const auto& kv) {
            return kythira::aws_rest_xml::detail::iequals(kv.first, name);
        });
        return f;
    };
    const auto full = signed_fields(k_policy_json);
    for (std::string_view f : {"key", "Policy", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Algorithm",
                               "X-Amz-Signature"}) {
        BOOST_TEST(code(s3::authenticate_post(*a, form_of(without(full, f)), "bk1", rules,
                                              now_tp)) == "InvalidArgument",
                   f);
    }
    auto bad_cred = full;
    bad_cred[4].second = "AKIDS3/20261118/us-east-1/sqs/aws4_request";
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(bad_cred), "bk1", rules, now_tp)) ==
               "InvalidArgument");
    auto bad_date = full;
    bad_date[5].second = "20261119T120000Z";
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(bad_date), "bk1", rules, now_tp)) ==
               "InvalidArgument");
    auto bad_b64 = full;
    bad_b64[6].second = "not base64!";
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(bad_b64), "bk1", rules, now_tp)) ==
               "InvalidPolicyDocument");
    auto ecdsa = full;
    ecdsa[3].second = "AWS4-ECDSA-P256-SHA256";
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(ecdsa), "bk1", rules, now_tp)) ==
               "InvalidRequest");

    // SigV2 forms.
    const fields_t v2{
        {"key", "k"}, {"AWSAccessKeyId", "AKIDS3"}, {"policy", "e30="}, {"signature", "abc="}};
    BOOST_TEST(code(s3::authenticate_post(*a, form_of(v2), "bk1", rules, now_tp)) ==
               "InvalidRequest");

    // No policy and no signature: anonymous.
    auto anon = s3::authenticate_post(*a, form_of({{"key", "k"}}), "bk1", rules, now_tp);
    BOOST_TEST_REQUIRE(anon.has_value());
    BOOST_TEST((anon->auth.kind == s3::auth_kind::anonymous));
    BOOST_TEST(!anon->policy.has_value());
}
