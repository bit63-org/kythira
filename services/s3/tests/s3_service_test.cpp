// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_service_test.cpp
/// @brief The S3 request pipeline end to end (`s3_service.hpp`;
///        .kiro/specs/s3-compatible-storage/ tasks 6 and 7): SigV4-signed
///        requests through routing, authentication, the access check and
///        the bucket, object and listing handlers, against an in-process
///        metadata layer and three in-memory blob copies.

#define BOOST_TEST_MODULE s3_service_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_service.hpp>
#include <kythira/s3/s3_tiers.hpp>

#include <raft/key_object_store.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/static_key_authorizer.hpp>

#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

/// A key-sealing secret built at run time: test material, not a credential.
auto test_secret(int n) -> std::string {
    std::string out = "t";
    for (int i = 0; i < 16; ++i) {
        out.push_back(static_cast<char>('a' + ((n * 7 + i * 3) % 26)));
    }
    return out;
}

namespace s3 = kythira::s3;
namespace sv4 = kythira::sigv4;
namespace az = kythira::aws_auth;
using kythira::chunk_read_result;
using kythira::chunk_read_status;
using kythira::chunk_sha;
using kythira::chunk_write_result;

constexpr std::string_view k_owner = "111122223333";
constexpr std::string_view k_other = "444455556666";
constexpr std::string_view k_date = "20261118T120000Z";
const auto k_now = sv4::detail::parse_amz_date(k_date).value();
const sv4::credential_scope k_scope{"20261118", "us-east-1", "s3"};
constexpr std::string_view k_host = "s3.kythira.test";

const std::map<std::string, std::string, std::less<>> k_secrets{
    {"AKIDOWNER", "owner-secret"}, {"AKIDREADER", "reader-secret"}, {"AKIDOTHER", "other-secret"}};

/// One in-memory blob copy.
struct memory_copy {
    std::mutex mu;
    std::map<chunk_sha, std::vector<std::byte>> chunks;

    auto write(const chunk_sha& sha, std::span<const std::byte> bytes) -> chunk_write_result {
        const std::lock_guard lock(mu);
        return chunks.emplace(sha, std::vector<std::byte>(bytes.begin(), bytes.end())).second
                   ? chunk_write_result::created
                   : chunk_write_result::present;
    }
    auto read(const chunk_sha& sha) -> chunk_read_result {
        const std::lock_guard lock(mu);
        auto it = chunks.find(sha);
        if (it == chunks.end()) {
            return {chunk_read_status::missing, {}};
        }
        return {chunk_read_status::found, it->second};
    }
};

/// The static keys, plus anonymous access by the bucket policy alone, as
/// IAM would decide it for a policy that grants `*`.
struct authorizer {
    az::static_key_authorizer keys;

    authorizer()
        : keys(
              {{"AKIDOWNER", "owner-secret", std::string(k_owner), "owner", az::static_role::admin},
               {"AKIDREADER", "reader-secret", std::string(k_owner), "reader",
                az::static_role::read_only},
               {"AKIDOTHER", "other-secret", std::string(k_other), "other",
                az::static_role::admin}},
              "aws", [] { return std::chrono::system_clock::time_point(k_now); }) {
        keys.register_service(s3::s3_static_roles());
    }
    auto authenticate(const sv4::request& r, const sv4::service_rules& rules) -> az::authn_result {
        return keys.authenticate(r, rules);
    }
    auto resolve(const sv4::claim& c, sv4::error_protocol p) -> az::resolve_result {
        return keys.resolve(c, p);
    }
    auto authorize(const az::principal_context& w, const az::authz_request& r)
        -> az::authz_decision {
        return keys.authorize(w, r);
    }
    auto authorize_anonymous(const az::authz_request& r) -> az::authz_decision {
        az::authz_decision d;
        d.allowed = r.resource_policy && s3::policy_is_public(*r.resource_policy) &&
                    r.resource_policy->find(r.action) != std::string::npos;
        return d;
    }
};
static_assert(az::aws_claim_resolver<authorizer>);
static_assert(az::aws_anonymous_authorizer<authorizer>);

struct reply {
    unsigned status = 0;
    s3::header_list headers;
    std::string body;

    [[nodiscard]] auto header(std::string_view n) const -> std::string {
        return s3::find_header(headers, n).value_or("");
    }
    [[nodiscard]] auto code() const -> std::string {
        const auto a = body.find("<Code>");
        const auto b = body.find("</Code>");
        return a == std::string::npos ? std::string{} : body.substr(a + 6, b - a - 6);
    }
};

struct fixture {
    std::array<memory_copy, 3> nodes;
    std::vector<s3::chunk_copy> copies;
    std::vector<std::string> replicas{"n0", "n1", "n2"};
    /// Where the index keeps change records (task 14); none in most tests.
    kythira::segment_store* changes = nullptr;
    s3::local_metadata meta;
    std::unique_ptr<s3::data_path> data;
    authorizer auth;
    std::unique_ptr<s3::s3_service<s3::local_metadata, authorizer>> svc;

    explicit fixture(s3::service_options o = {}, kythira::segment_store* change_log = nullptr)
        : changes(change_log), meta(s3::index_options{}, change_log) {
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            copies.emplace_back("n" + std::to_string(i), nodes.at(i));
        }
        s3::data_path_options dp;
        dp.chunk_bytes = 64;  // many chunks per object
        dp.parallel_writes = false;
        data = std::make_unique<s3::data_path>(
            [this](const chunk_sha& sha) { return s3::place(s3::placement_map{}, sha, replicas); },
            s3::resolver_for(copies), dp);
        o.addressing.domains = {std::string(k_host)};
        if (!o.clock) {
            o.clock = [] { return std::chrono::system_clock::time_point(k_now); };
        }
        svc = std::make_unique<s3::s3_service<s3::local_metadata, authorizer>>(meta, *data, auth,
                                                                               std::move(o));
    }

    /// A request signed by `key` (empty: anonymous).
    auto send(std::string method, std::string target, s3::header_list headers = {},
              std::string body = {}, std::string_view key = "AKIDOWNER",
              std::optional<std::string> sent_body = std::nullopt) -> reply {
        headers.emplace_back("Host", std::string(k_host));
        if (!key.empty()) {
            headers.emplace_back("X-Amz-Date", std::string(k_date));
            if (!s3::find_header(headers, "x-amz-content-sha256")) {
                headers.emplace_back("x-amz-content-sha256", sv4::detail::sha256_hex(body));
            }
            std::vector<std::string> names;
            for (const auto& [k, v] : headers) {
                names.push_back(sv4::detail::lower(k));
            }
            std::ranges::sort(names);
            std::string signed_names;
            for (const auto& n : names) {
                signed_names += (signed_names.empty() ? "" : ";") + n;
            }
            const auto authz = [&](std::string_view sig) {
                return "AWS4-HMAC-SHA256 Credential=" + std::string(key) + "/" + k_scope.text() +
                       ", SignedHeaders=" + signed_names + ", Signature=" + std::string(sig);
            };
            headers.emplace_back("Authorization", authz(std::string(64, '0')));
            const auto q = target.find('?');
            const sv4::request view{method, std::string_view(target).substr(0, q),
                                    q == std::string::npos ? std::string_view{}
                                                           : std::string_view(target).substr(q + 1),
                                    headers, std::nullopt};
            const auto parsed = sv4::parse(view, s3::s3_rules(), k_now);
            BOOST_REQUIRE_MESSAGE(parsed.has_value(), parsed.error().message);
            headers.back().second = authz(sv4::compute_signature(
                *parsed, sv4::derive_signing_key(k_secrets.find(key)->second, k_scope)));
        }
        return raw(std::move(method), std::move(target), std::move(headers),
                   sent_body ? std::move(*sent_body) : std::move(body));
    }

    auto raw(std::string method, std::string target, s3::header_list headers, std::string body)
        -> reply {
        s3::http_request in;
        in.method = std::move(method);
        in.host = std::string(k_host);
        in.target = std::move(target);
        in.headers = std::move(headers);
        in.body = s3::memory_body(std::move(body));
        in.source_ip = "10.0.0.1";
        auto r = svc->serve(std::move(in));
        reply out{r.status, r.headers, r.body};
        if (r.stream) {
            BOOST_TEST(!r.stream([&](std::span<const std::byte> b) {
                             out.body.append(reinterpret_cast<const char*>(b.data()),  // NOLINT
                                             b.size());
                             return true;
                         }).has_value());
            BOOST_TEST(out.body.size() == r.stream_length);
        }
        return out;
    }

    auto make_bucket(const std::string& name, std::string_view key = "AKIDOWNER") -> reply {
        return send("PUT", "/" + name, {}, {}, key);
    }
};

auto md5_b64(std::string_view s) -> std::string {
    return s3::bucket_detail::b64(s3::object_detail::md5_raw(s));
}

auto md5_hex(std::string_view s) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const unsigned char c : s3::object_detail::md5_raw(s)) {
        out.push_back(digits[c >> 4U]);
        out.push_back(digits[c & 0xFU]);
    }
    return out;
}

auto contains(const std::string& s, std::string_view part) -> bool {
    return s.find(part) != std::string::npos;
}

const std::string k_public_read_policy =
    R"({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",)"
    R"("Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]})";

}  // namespace

BOOST_AUTO_TEST_CASE(buckets_are_created_listed_and_deleted) {
    fixture f;
    BOOST_TEST(f.make_bucket("alpha").status == 200U);
    BOOST_TEST(f.make_bucket("alpha").status == 200U);  // us-east-1 repeats succeed
    const auto taken = f.make_bucket("alpha", "AKIDOTHER");
    BOOST_TEST(taken.status == 409U);
    BOOST_TEST(taken.code() == "BucketAlreadyExists");
    BOOST_TEST(f.make_bucket("beta").status == 200U);
    BOOST_TEST(f.make_bucket("Bad_Name").code() == "InvalidBucketName");

    auto head = f.send("HEAD", "/alpha");
    BOOST_TEST(head.status == 200U);
    BOOST_TEST(head.header("x-amz-bucket-region") == "us-east-1");
    BOOST_TEST(!head.header("x-amz-request-id").empty());

    const auto all = f.send("GET", "/");
    BOOST_TEST(all.status == 200U);
    BOOST_TEST(contains(all.body, "<Name>alpha</Name>"));
    BOOST_TEST(contains(all.body, "<Name>beta</Name>"));
    BOOST_TEST(!contains(f.send("GET", "/", {}, {}, "AKIDOTHER").body, "<Name>alpha</Name>"));

    const auto page = f.send("GET", "/?max-buckets=1");
    BOOST_TEST(contains(page.body, "<Name>alpha</Name>"));
    BOOST_TEST(!contains(page.body, "<Name>beta</Name>"));
    const auto a = page.body.find("<ContinuationToken>") + 19;
    const auto token = page.body.substr(a, page.body.find('<', a) - a);
    const auto next =
        f.send("GET", "/?continuation-token=" + kythira::aws_rest_xml::url_encode_key(token));
    BOOST_TEST(contains(next.body, "<Name>beta</Name>"));
    BOOST_TEST(!contains(next.body, "<Name>alpha</Name>"));

    const auto loc = f.send("GET", "/alpha?location");
    BOOST_TEST(contains(loc.body,
                        "<LocationConstraint "
                        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"));
    BOOST_TEST(
        f.send("PUT", "/gamma", {},
               "<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint>"
               "</CreateBucketConfiguration>")
            .code() == "IllegalLocationConstraintException");

    BOOST_TEST(f.send("PUT", "/alpha/k", {}, "x").status == 200U);
    const auto busy = f.send("DELETE", "/alpha");
    BOOST_TEST(busy.status == 409U);
    BOOST_TEST(busy.code() == "BucketNotEmpty");
    BOOST_TEST(f.send("DELETE", "/alpha/k").status == 204U);
    BOOST_TEST(f.send("DELETE", "/alpha").status == 204U);
    BOOST_TEST(f.send("HEAD", "/alpha").status == 404U);
    BOOST_TEST(f.send("GET", "/alpha/k").code() == "NoSuchBucket");
    // A recreated bucket sees nothing of the old one.
    BOOST_TEST(f.make_bucket("alpha").status == 200U);
    BOOST_TEST(f.send("GET", "/alpha/k").code() == "NoSuchKey");
}

BOOST_AUTO_TEST_CASE(new_buckets_disable_acls_and_block_public_access) {
    fixture f;
    f.make_bucket("pub");
    const auto own = f.send("GET", "/pub?ownershipControls");
    BOOST_TEST(contains(own.body, "<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>"));
    const auto pab = f.send("GET", "/pub?publicAccessBlock");
    BOOST_TEST(contains(pab.body, "<BlockPublicPolicy>true</BlockPublicPolicy>"));
    BOOST_TEST(f.send("PUT", "/pub?acl", {{"x-amz-acl", "public-read"}}).code() ==
               "AccessControlListNotSupported");
    BOOST_TEST(f.send("PUT", "/pub/k", {{"x-amz-acl", "public-read"}}, "x").code() ==
               "AccessControlListNotSupported");
    BOOST_TEST(f.send("PUT", "/pub?policy", {}, k_public_read_policy).code() == "AccessDenied");
    BOOST_TEST(f.send("GET", "/pub?policy").code() == "NoSuchBucketPolicy");

    BOOST_TEST(f.send("DELETE", "/pub?publicAccessBlock").status == 204U);
    BOOST_TEST(f.send("GET", "/pub?publicAccessBlock").code() ==
               "NoSuchPublicAccessBlockConfiguration");
    BOOST_TEST(f.send("PUT", "/pub?policy", {}, k_public_read_policy).status == 204U);
    BOOST_TEST(f.send("GET", "/pub?policy").body == k_public_read_policy);
    BOOST_TEST(contains(f.send("GET", "/pub?policyStatus").body, "<IsPublic>true</IsPublic>"));
    BOOST_TEST(f.send("PUT", "/pub?policy", {}, "{nope").code() == "MalformedPolicy");

    // Anonymous reads follow the public policy.
    BOOST_TEST(f.send("PUT", "/pub/hello.txt", {}, "hi").status == 200U);
    const auto anon = f.send("GET", "/pub/hello.txt", {}, {}, "");
    BOOST_TEST(anon.status == 200U);
    BOOST_TEST(anon.body == "hi");
    BOOST_TEST(f.send("PUT", "/pub/x", {}, "no", "").code() == "AccessDenied");
    BOOST_TEST(f.send("GET", "/", {}, {}, "").code() == "AccessDenied");
    // RestrictPublicBuckets takes it away again.
    BOOST_TEST(f.send("PUT", "/pub?publicAccessBlock", {},
                      "<PublicAccessBlockConfiguration><RestrictPublicBuckets>true"
                      "</RestrictPublicBuckets></PublicAccessBlockConfiguration>")
                   .status == 200U);
    BOOST_TEST(f.send("GET", "/pub/hello.txt", {}, {}, "").code() == "AccessDenied");

    // Turning ACLs on lets an ACL grant read to everyone.
    BOOST_TEST(f.send("DELETE", "/pub?publicAccessBlock").status == 204U);
    BOOST_TEST(f.send("DELETE", "/pub?policy").status == 204U);
    BOOST_TEST(f.send("PUT", "/pub?ownershipControls", {},
                      "<OwnershipControls><Rule><ObjectOwnership>ObjectWriter</ObjectOwnership>"
                      "</Rule></OwnershipControls>")
                   .status == 200U);
    BOOST_TEST(f.send("PUT", "/pub/open", {{"x-amz-acl", "public-read"}}, "o").status == 200U);
    BOOST_TEST(f.send("GET", "/pub/open", {}, {}, "").body == "o");
    BOOST_TEST(f.send("GET", "/pub/hello.txt", {}, {}, "").code() == "AccessDenied");
    BOOST_TEST(contains(f.send("GET", "/pub/open?acl").body, "AllUsers"));
    // ACLs cannot be turned off while the bucket ACL grants others.
    BOOST_TEST(f.send("PUT", "/pub?acl", {{"x-amz-acl", "public-read"}}).status == 200U);
    BOOST_TEST(f.send("PUT", "/pub?ownershipControls", {},
                      "<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced"
                      "</ObjectOwnership></Rule></OwnershipControls>")
                   .code() == "InvalidBucketAclWithObjectOwnership");
}

BOOST_AUTO_TEST_CASE(objects_are_written_and_read_back) {
    fixture f;
    f.make_bucket("bkt");
    std::string big;
    for (int i = 0; i < 1000; ++i) {
        big += std::to_string(i) + ",";
    }
    const auto put = f.send("PUT", "/bkt/dir/big.csv",
                            {{"Content-Type", "text/csv"},
                             {"x-amz-meta-Color", "blue"},
                             {"Cache-Control", "no-cache"},
                             {"Content-MD5", md5_b64(big)},
                             {"x-amz-tagging", "team=core&tier=1"}},
                            big);
    BOOST_TEST_REQUIRE(put.status == 200U, put.body);
    const auto etag = put.header("ETag");
    BOOST_TEST(etag.size() == 34U);
    BOOST_TEST(put.header("x-amz-version-id").empty());  // unversioned

    const auto get = f.send("GET", "/bkt/dir/big.csv");
    BOOST_TEST(get.status == 200U);
    BOOST_TEST(get.body == big);
    BOOST_TEST(get.header("ETag") == etag);
    BOOST_TEST(get.header("Content-Type") == "text/csv");
    BOOST_TEST(get.header("x-amz-meta-color") == "blue");
    BOOST_TEST(get.header("cache-control") == "no-cache");
    BOOST_TEST(get.header("x-amz-tagging-count") == "2");
    BOOST_TEST(get.header("Content-Length") == std::to_string(big.size()));
    BOOST_TEST(!get.header("Last-Modified").empty());

    const auto head = f.send("HEAD", "/bkt/dir/big.csv");
    BOOST_TEST(head.status == 200U);
    BOOST_TEST(head.body.empty());
    BOOST_TEST(head.header("Content-Length") == std::to_string(big.size()));

    const auto r1 = f.send("GET", "/bkt/dir/big.csv", {{"Range", "bytes=2-9"}});
    BOOST_TEST(r1.status == 206U);
    BOOST_TEST(r1.body == big.substr(2, 8));
    BOOST_TEST(r1.header("Content-Range") == "bytes 2-9/" + std::to_string(big.size()));
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv", {{"Range", "bytes=-4"}}).body ==
               big.substr(big.size() - 4));
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv", {{"Range", "bytes=100-"}}).body ==
               big.substr(100));
    const auto past = f.send("GET", "/bkt/dir/big.csv", {{"Range", "bytes=99999-"}});
    BOOST_TEST(past.status == 416U);
    BOOST_TEST(past.code() == "InvalidRange");

    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv", {{"If-None-Match", etag}}).status == 304U);
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv", {{"If-Match", "\"nope\""}}).status == 412U);
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv", {{"If-Match", etag}}).status == 200U);
    BOOST_TEST(
        f.send("GET", "/bkt/dir/big.csv", {{"If-Modified-Since", "Thu, 19 Nov 2026 00:00:00 GMT"}})
            .status == 304U);
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv",
                      {{"If-Unmodified-Since", "Tue, 17 Nov 2026 00:00:00 GMT"}})
                   .status == 412U);
    const auto over = f.send("GET", "/bkt/dir/big.csv?response-content-type=application/x-test");
    BOOST_TEST(over.header("Content-Type") == "application/x-test");

    BOOST_TEST(f.send("PUT", "/bkt/bad", {{"Content-MD5", md5_b64("other")}}, "data").code() ==
               "BadDigest");
    BOOST_TEST(f.send("PUT", "/bkt/bad", {{"Content-MD5", "zz"}}, "data").code() ==
               "InvalidDigest");
    BOOST_TEST(f.send("GET", "/bkt/bad").code() == "NoSuchKey");
    BOOST_TEST(f.send("PUT", "/bkt/dir/big.csv", {{"If-None-Match", "*"}}, "x").status == 412U);
    BOOST_TEST(f.send("PUT", "/bkt/new", {{"If-Match", "\"x\""}}, "x").code() == "NoSuchKey");
    // No KMS provider on this endpoint.
    BOOST_TEST(f.send("PUT", "/bkt/e", {{"x-amz-server-side-encryption", "aws:kms"}}, "x").code() ==
               "KMS.NotFoundException");
    BOOST_TEST(
        f.send("PUT", "/bkt/e", {{"x-amz-server-side-encryption", "aws:kms:dsse"}}, "x").status ==
        501U);
    const auto empty = f.send("PUT", "/bkt/empty", {}, "");
    BOOST_TEST(empty.header("ETag") == "\"d41d8cd98f00b204e9800998ecf8427e\"");
    BOOST_TEST(f.send("GET", "/bkt/empty").body.empty());

    const auto attrs = f.send("GET", "/bkt/dir/big.csv?attributes",
                              {{"x-amz-object-attributes", "ETag,ObjectSize,StorageClass"}});
    BOOST_TEST(attrs.status == 200U);
    BOOST_TEST(contains(attrs.body, "<ObjectSize>" + std::to_string(big.size()) + "</ObjectSize>"));
    BOOST_TEST(contains(attrs.body, "<StorageClass>STANDARD</StorageClass>"));

    BOOST_TEST(f.send("DELETE", "/bkt/dir/big.csv").status == 204U);
    BOOST_TEST(f.send("GET", "/bkt/dir/big.csv").code() == "NoSuchKey");
    BOOST_TEST(f.send("HEAD", "/bkt/dir/big.csv").status == 404U);
    BOOST_TEST(f.send("DELETE", "/bkt/dir/big.csv").status == 204U);  // as on S3
}

BOOST_AUTO_TEST_CASE(object_tags_are_set_read_and_removed) {
    fixture f;
    f.make_bucket("bkt");
    f.send("PUT", "/bkt/k", {}, "v");
    BOOST_TEST(contains(f.send("GET", "/bkt/k?tagging").body, "<TagSet></TagSet>"));
    BOOST_TEST(f.send("PUT", "/bkt/k?tagging", {},
                      "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>")
                   .status == 200U);
    BOOST_TEST(contains(f.send("GET", "/bkt/k?tagging").body, "<Key>a</Key><Value>1</Value>"));
    BOOST_TEST(f.send("HEAD", "/bkt/k").header("x-amz-tagging-count") == "1");
    BOOST_TEST(f.send("PUT", "/bkt/k?tagging", {},
                      "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>a</Key>"
                      "<Value>2</Value></Tag></TagSet></Tagging>")
                   .code() == "InvalidTag");
    BOOST_TEST(f.send("DELETE", "/bkt/k?tagging").status == 204U);
    BOOST_TEST(f.send("HEAD", "/bkt/k").header("x-amz-tagging-count").empty());
    BOOST_TEST(f.send("GET", "/bkt/missing?tagging").code() == "NoSuchKey");

    BOOST_TEST(f.send("GET", "/bkt?tagging").code() == "NoSuchTagSet");
    BOOST_TEST(f.send("PUT", "/bkt?tagging", {},
                      "<Tagging><TagSet><Tag><Key>kythira:compat:max-put-bytes</Key><Value>3"
                      "</Value></Tag></TagSet></Tagging>")
                   .status == 204U);
    // The bucket's compatibility tag lowers its single-PUT limit.
    const auto big = f.send("PUT", "/bkt/big", {}, "four");
    BOOST_TEST(big.code() == "EntityTooLarge");
    BOOST_TEST(f.send("PUT", "/bkt/ok", {}, "abc").status == 200U);
}

BOOST_AUTO_TEST_CASE(listings_page_and_roll_up_prefixes) {
    fixture f;
    f.make_bucket("bkt");
    // Paths are percent-encoded with %20 for a space ('+' is a '+').
    for (const auto* k : {"a/1", "a/2", "b/1", "c", "d%20e%2Bf"}) {
        BOOST_TEST_REQUIRE(f.send("PUT", std::string("/bkt/") + k, {}, "x").status == 200U);
    }
    const auto v1 = f.send("GET", "/bkt?delimiter=/");
    BOOST_TEST(v1.status == 200U);
    BOOST_TEST(contains(v1.body, "<CommonPrefixes><Prefix>a/</Prefix></CommonPrefixes>"));
    BOOST_TEST(contains(v1.body, "<Key>c</Key>"));
    BOOST_TEST(!contains(v1.body, "<Key>a/1</Key>"));
    BOOST_TEST(contains(v1.body, "<IsTruncated>false</IsTruncated>"));

    const auto page = f.send("GET", "/bkt?list-type=2&max-keys=2");
    BOOST_TEST(contains(page.body, "<KeyCount>2</KeyCount>"));
    BOOST_TEST(contains(page.body, "<IsTruncated>true</IsTruncated>"));
    BOOST_TEST(!contains(page.body, "<Owner>"));
    const auto a = page.body.find("<NextContinuationToken>") + 23;
    const auto token = page.body.substr(a, page.body.find('<', a) - a);
    const auto rest = f.send("GET", "/bkt?list-type=2&fetch-owner=true&continuation-token=" +
                                        kythira::aws_rest_xml::url_encode_key(token));
    BOOST_TEST(contains(rest.body, "<Key>b/1</Key>"));
    BOOST_TEST(!contains(rest.body, "<Key>a/2</Key>"));
    BOOST_TEST(contains(rest.body, "<Owner><ID>111122223333</ID>"));

    const auto after = f.send("GET", "/bkt?list-type=2&start-after=c&encoding-type=url");
    BOOST_TEST(contains(after.body, "<Key>d+e%2Bf</Key>"));
    BOOST_TEST(contains(after.body, "<KeyCount>1</KeyCount>"));
    BOOST_TEST(f.send("GET", "/bkt?list-type=2&continuation-token=%25%25").code() ==
               "InvalidArgument");
    BOOST_TEST(f.send("GET", "/bkt?max-keys=lots").code() == "InvalidArgument");
    BOOST_TEST(f.send("GET", "/bkt?encoding-type=base64").code() == "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(delete_objects_reports_each_key) {
    fixture f;
    f.make_bucket("bkt");
    f.send("PUT", "/bkt/one", {}, "1");
    f.send("PUT", "/bkt/two", {}, "2");
    const std::string body =
        "<Delete><Object><Key>one</Key></Object><Object><Key>two</Key></Object>"
        "<Object><Key>three</Key><VersionId>bogus</VersionId></Object></Delete>";
    BOOST_TEST(f.send("POST", "/bkt?delete", {}, body).code() == "InvalidRequest");  // no MD5
    const auto r = f.send("POST", "/bkt?delete", {{"Content-MD5", md5_b64(body)}}, body);
    BOOST_TEST_REQUIRE(r.status == 200U, r.body);
    BOOST_TEST(contains(r.body, "<Deleted><Key>one</Key></Deleted>"));
    BOOST_TEST(contains(r.body, "<Deleted><Key>two</Key></Deleted>"));
    BOOST_TEST(contains(r.body,
                        "<Error><Key>three</Key><VersionId>bogus</VersionId>"
                        "<Code>InvalidArgument</Code>"));
    BOOST_TEST(f.send("GET", "/bkt/one").code() == "NoSuchKey");

    // A reader may not delete: every key is refused on its own.
    f.send("PUT", "/bkt/kept", {}, "k");
    const std::string quiet =
        "<Delete><Quiet>true</Quiet><Object><Key>kept</Key></Object></Delete>";
    const auto refused =
        f.send("POST", "/bkt?delete", {{"Content-MD5", md5_b64(quiet)}}, quiet, "AKIDREADER");
    BOOST_TEST(refused.status == 200U);
    BOOST_TEST(contains(refused.body, "<Code>AccessDenied</Code>"));
    BOOST_TEST(f.send("GET", "/bkt/kept").body == "k");
    const auto ok = f.send("POST", "/bkt?delete", {{"Content-MD5", md5_b64(quiet)}}, quiet);
    BOOST_TEST(!contains(ok.body, "<Deleted>"));
    BOOST_TEST(f.send("GET", "/bkt/kept").code() == "NoSuchKey");
}

BOOST_AUTO_TEST_CASE(copies_follow_their_directives_and_conditions) {
    fixture f;
    f.make_bucket("bkt");
    f.make_bucket("cbk");
    const auto src =
        f.send("PUT", "/bkt/src",
               {{"Content-Type", "text/plain"}, {"x-amz-meta-a", "1"}, {"x-amz-tagging", "t=1"}},
               "source bytes");
    const auto etag = src.header("ETag");

    const auto copy = f.send("PUT", "/cbk/dst", {{"x-amz-copy-source", "/bkt/src"}});
    BOOST_TEST_REQUIRE(copy.status == 200U, copy.body);
    BOOST_TEST(contains(copy.body, "<ETag>" + kythira::aws_query::xml_escape(etag) + "</ETag>"));
    auto got = f.send("GET", "/cbk/dst");
    BOOST_TEST(got.body == "source bytes");
    BOOST_TEST(got.header("x-amz-meta-a") == "1");
    BOOST_TEST(got.header("x-amz-tagging-count") == "1");

    f.send("PUT", "/cbk/dst2",
           {{"x-amz-copy-source", "bkt/src"},
            {"x-amz-metadata-directive", "REPLACE"},
            {"x-amz-tagging-directive", "REPLACE"},
            {"x-amz-tagging", "u=2&v=3"},
            {"Content-Type", "application/json"},
            {"x-amz-meta-b", "2"}});
    got = f.send("GET", "/cbk/dst2");
    BOOST_TEST(got.header("x-amz-meta-a").empty());
    BOOST_TEST(got.header("x-amz-meta-b") == "2");
    BOOST_TEST(got.header("Content-Type") == "application/json");
    BOOST_TEST(got.header("x-amz-tagging-count") == "2");

    BOOST_TEST(
        f.send("PUT", "/cbk/dst3",
               {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-copy-source-if-match", "\"other\""}})
            .status == 412U);
    BOOST_TEST(
        f.send("PUT", "/cbk/dst3",
               {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-copy-source-if-none-match", etag}})
            .status == 412U);
    BOOST_TEST(f.send("PUT", "/bkt/src", {{"x-amz-copy-source", "/bkt/src"}}).code() ==
               "InvalidRequest");
    BOOST_TEST(f.send("PUT", "/bkt/src",
                      {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-metadata-directive", "REPLACE"}})
                   .status == 200U);
    BOOST_TEST(f.send("PUT", "/cbk/x", {{"x-amz-copy-source", "/bkt/nope"}}).code() == "NoSuchKey");
    BOOST_TEST(f.send("PUT", "/cbk/x", {{"x-amz-copy-source", "/nobucket/k"}}).code() ==
               "NoSuchBucket");
    BOOST_TEST(f.send("PUT", "/cbk/x", {{"x-amz-copy-source", "nokey"}}).code() ==
               "InvalidArgument");
    // Another account cannot read the source.
    f.make_bucket("theirs", "AKIDOTHER");
    BOOST_TEST(
        f.send("PUT", "/theirs/x", {{"x-amz-copy-source", "/bkt/src"}}, {}, "AKIDOTHER").code() ==
        "AccessDenied");
}

BOOST_AUTO_TEST_CASE(checksums_are_verified_stored_and_returned) {
    using s3::checksum_algorithm;
    fixture f;
    f.make_bucket("bkt");
    const std::string body = "checksummed body, long enough for several chunks of 64 bytes";

    // No checksum asked for: CRC64NVME, returned on the PUT.
    const auto plain = f.send("PUT", "/bkt/plain", {}, body);
    BOOST_TEST_REQUIRE(plain.status == 200U, plain.body);
    const auto crc64 = s3::checksum_of(checksum_algorithm::crc64nvme, body);
    BOOST_TEST(plain.header("x-amz-checksum-crc64nvme") == crc64);
    BOOST_TEST(plain.header("x-amz-checksum-type") == "FULL_OBJECT");

    // Returned on a read only with checksum mode, and never on a range.
    BOOST_TEST(f.send("GET", "/bkt/plain").header("x-amz-checksum-crc64nvme").empty());
    const s3::header_list mode{{"x-amz-checksum-mode", "ENABLED"}};
    BOOST_TEST(f.send("GET", "/bkt/plain", mode).header("x-amz-checksum-crc64nvme") == crc64);
    BOOST_TEST(f.send("HEAD", "/bkt/plain", mode).header("x-amz-checksum-crc64nvme") == crc64);
    auto ranged = mode;
    ranged.emplace_back("Range", "bytes=0-3");
    BOOST_TEST(f.send("GET", "/bkt/plain", ranged).header("x-amz-checksum-crc64nvme").empty());

    // A header value is checked; a wrong one stores nothing.
    const auto sha = s3::checksum_of(checksum_algorithm::sha256, body);
    const auto put = f.send("PUT", "/bkt/sha", {{"x-amz-checksum-sha256", sha}}, body);
    BOOST_TEST_REQUIRE(put.status == 200U, put.body);
    BOOST_TEST(put.header("x-amz-checksum-sha256") == sha);
    const auto wrong = s3::checksum_of(checksum_algorithm::sha256, "other");
    BOOST_TEST(f.send("PUT", "/bkt/bad", {{"x-amz-checksum-sha256", wrong}}, body).code() ==
               "BadDigest");
    BOOST_TEST(f.send("GET", "/bkt/bad").code() == "NoSuchKey");
    BOOST_TEST(f.send("PUT", "/bkt/bad", {{"x-amz-checksum-crc32", "nope"}}, body).code() ==
               "InvalidRequest");

    const auto attrs =
        f.send("GET", "/bkt/sha?attributes", {{"x-amz-object-attributes", "Checksum"}});
    BOOST_TEST_REQUIRE(attrs.status == 200U, attrs.body);
    BOOST_TEST(contains(attrs.body, "<Checksum><ChecksumSHA256>" + sha +
                                        "</ChecksumSHA256>"
                                        "<ChecksumType>FULL_OBJECT</ChecksumType></Checksum>"));

    // A copy keeps the source's checksum.
    f.send("PUT", "/bkt/copy", {{"x-amz-copy-source", "/bkt/sha"}});
    BOOST_TEST(f.send("HEAD", "/bkt/copy", mode).header("x-amz-checksum-sha256") == sha);

    // An aws-chunked body with the checksum in its trailer.
    const auto chunked = [&](std::string_view trailer_value) {
        std::ostringstream wire;
        wire << std::hex << body.size() << "\r\n"
             << body << "\r\n0\r\n"
             << "x-amz-checksum-crc32:" << trailer_value << "\r\n\r\n";
        return f.send("PUT", "/bkt/trailer",
                      {{"x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
                       {"Content-Encoding", "aws-chunked"},
                       {"x-amz-decoded-content-length", std::to_string(body.size())},
                       {"x-amz-trailer", "x-amz-checksum-crc32"},
                       {"x-amz-sdk-checksum-algorithm", "CRC32"}},
                      wire.str());
    };
    const auto crc32 = s3::checksum_of(checksum_algorithm::crc32, body);
    const auto trailed = chunked(crc32);
    BOOST_TEST_REQUIRE(trailed.status == 200U, trailed.body);
    BOOST_TEST(trailed.header("x-amz-checksum-crc32") == crc32);
    BOOST_TEST(f.send("GET", "/bkt/trailer").body == body);
    BOOST_TEST(chunked(s3::checksum_of(checksum_algorithm::crc32, "x")).code() == "BadDigest");

    // DeleteObjects accepts a checksum header in place of Content-MD5.
    const std::string del = "<Delete><Object><Key>plain</Key></Object></Delete>";
    const auto d =
        f.send("POST", "/bkt?delete",
               {{"x-amz-checksum-crc32c", s3::checksum_of(checksum_algorithm::crc32c, del)}}, del);
    BOOST_TEST_REQUIRE(d.status == 200U, d.body);
    BOOST_TEST(contains(d.body, "<Deleted><Key>plain</Key></Deleted>"));
    BOOST_TEST(f.send("POST", "/bkt?delete",
                      {{"x-amz-checksum-crc32c", s3::checksum_of(checksum_algorithm::crc32c, "x")}},
                      del)
                   .code() == "BadDigest");
}

namespace {

/// The text of the first `<tag>` in `xml`.
auto element(const std::string& xml, const std::string& tag) -> std::string {
    const auto a = xml.find("<" + tag + ">");
    if (a == std::string::npos) {
        return {};
    }
    const auto from = a + tag.size() + 2;
    return xml.substr(from, xml.find("</" + tag + ">", from) - from);
}

auto count_of(const std::string& s, std::string_view part) -> std::size_t {
    std::size_t n = 0;
    for (auto at = s.find(part); at != std::string::npos; at = s.find(part, at + 1)) {
        ++n;
    }
    return n;
}

auto random_bytes(std::size_t n, unsigned seed) -> std::string {
    std::string out(n, '\0');
    std::uint32_t x = seed * 2654435761U + 1;
    for (auto& c : out) {
        x = x * 1664525U + 1013904223U;
        c = static_cast<char>(x >> 24U);
    }
    return out;
}

}  // namespace

BOOST_AUTO_TEST_CASE(multipart_uploads_complete_list_and_abort) {
    using s3::checksum_algorithm;
    fixture f;
    f.make_bucket("bkt");
    // Small parts for the test: the bucket's profile tag lowers the minimum.
    const std::string tagging =
        "<Tagging><TagSet><Tag><Key>kythira:compat:min-part-bytes</Key><Value>100</Value></Tag>"
        "</TagSet></Tagging>";
    BOOST_TEST_REQUIRE(
        f.send("PUT", "/bkt?tagging", {{"Content-MD5", md5_b64(tagging)}}, tagging).status == 204U);

    const auto create = f.send("POST", "/bkt/big.bin?uploads",
                               {{"Content-Type", "application/x-thing"}, {"x-amz-meta-k", "v"}});
    BOOST_TEST_REQUIRE(create.status == 200U, create.body);
    BOOST_TEST(create.header("x-amz-checksum-algorithm") == "CRC64NVME");
    BOOST_TEST(create.header("x-amz-checksum-type") == "FULL_OBJECT");
    const auto id = element(create.body, "UploadId");
    BOOST_TEST_REQUIRE(!id.empty());
    const auto at = [&](int n) {
        return "/bkt/big.bin?partNumber=" + std::to_string(n) + "&uploadId=" + id;
    };

    const auto p1 = random_bytes(300, 1);
    const auto p2 = random_bytes(250, 2);
    const auto p3 = random_bytes(40, 3);
    const auto put1 = f.send("PUT", at(1), {}, p1);
    BOOST_TEST_REQUIRE(put1.status == 200U, put1.body);
    BOOST_TEST(put1.header("x-amz-checksum-crc64nvme") ==
               s3::checksum_of(checksum_algorithm::crc64nvme, p1));
    // A part written again replaces the old one.
    f.send("PUT", at(2), {}, "replaced");
    const auto put2 = f.send("PUT", at(2), {}, p2);
    // A part may name its own algorithm on a default upload; it is checked.
    const auto put3 =
        f.send("PUT", at(3),
               {{"x-amz-checksum-crc32", s3::checksum_of(checksum_algorithm::crc32, p3)}}, p3);
    BOOST_TEST_REQUIRE(put3.status == 200U, put3.body);
    BOOST_TEST(f.send("PUT", at(4),
                      {{"x-amz-checksum-crc32", s3::checksum_of(checksum_algorithm::crc32, "x")}},
                      p3)
                   .code() == "BadDigest");
    BOOST_TEST(f.send("PUT", "/bkt/big.bin?partNumber=0&uploadId=" + id, {}, "x").code() ==
               "InvalidArgument");
    BOOST_TEST(
        f.send("PUT", "/bkt/big.bin?partNumber=1&uploadId=00000000000000ff", {}, "x").code() ==
        "NoSuchUpload");

    // ListParts pages by part number.
    const auto parts = f.send("GET", "/bkt/big.bin?uploadId=" + id + "&max-parts=2");
    BOOST_TEST_REQUIRE(parts.status == 200U, parts.body);
    BOOST_TEST(count_of(parts.body, "<Part>") == 2U);
    BOOST_TEST(element(parts.body, "IsTruncated") == "true");
    BOOST_TEST(element(parts.body, "NextPartNumberMarker") == "2");
    BOOST_TEST(contains(parts.body, "<Size>250</Size>"));
    const auto rest = f.send("GET", "/bkt/big.bin?uploadId=" + id + "&part-number-marker=2");
    BOOST_TEST(count_of(rest.body, "<Part>") == 1U);
    BOOST_TEST(element(rest.body, "PartNumber") == "3");

    // ListMultipartUploads, with a second upload rolled into a prefix.
    f.send("POST", "/bkt/dir/a?uploads");
    f.send("POST", "/bkt/dir/b?uploads");
    const auto ups = f.send("GET", "/bkt?uploads&delimiter=/");
    BOOST_TEST_REQUIRE(ups.status == 200U, ups.body);
    BOOST_TEST(count_of(ups.body, "<Upload>") == 1U);
    BOOST_TEST(contains(ups.body, "<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>"));
    const auto page = f.send("GET", "/bkt?uploads&max-uploads=1&prefix=dir/");
    BOOST_TEST(element(page.body, "IsTruncated") == "true");
    BOOST_TEST(element(page.body, "NextKeyMarker") == "dir/a");
    const auto page2 = f.send("GET", "/bkt?uploads&prefix=dir/&key-marker=dir/a&upload-id-marker=" +
                                         element(page.body, "NextUploadIdMarker"));
    BOOST_TEST(element(page2.body, "Key") == "dir/b");

    const auto complete_body = [&](bool with_checksums, bool order_ok = true) {
        const std::vector<std::pair<int, reply>> chosen{{1, put1}, {2, put2}, {3, put3}};
        std::string xml = "<CompleteMultipartUpload>";
        for (std::size_t i = 0; i < chosen.size(); ++i) {
            const auto& [n, r] = chosen[order_ok ? i : chosen.size() - 1 - i];
            xml += "<Part><PartNumber>" + std::to_string(n) + "</PartNumber><ETag>" +
                   r.header("ETag") + "</ETag>";
            if (with_checksums) {
                xml += "<ChecksumCRC64NVME>" + r.header("x-amz-checksum-crc64nvme") +
                       "</ChecksumCRC64NVME>";
            }
            xml += "</Part>";
        }
        return xml + "</CompleteMultipartUpload>";
    };
    BOOST_TEST(
        f.send("POST", "/bkt/big.bin?uploadId=" + id, {}, complete_body(false, false)).code() ==
        "InvalidPartOrder");
    const auto whole = p1 + p2 + p3;
    const auto full = s3::checksum_of(checksum_algorithm::crc64nvme, whole);
    BOOST_TEST(f.send("POST", "/bkt/big.bin?uploadId=" + id,
                      {{"x-amz-checksum-crc64nvme",
                        s3::checksum_of(checksum_algorithm::crc64nvme, "nope")}},
                      complete_body(true))
                   .code() == "BadDigest");
    const auto done = f.send("POST", "/bkt/big.bin?uploadId=" + id,
                             {{"x-amz-checksum-crc64nvme", full},
                              {"x-amz-mp-object-size", std::to_string(whole.size())}},
                             complete_body(true));
    BOOST_TEST_REQUIRE(done.status == 200U, done.body);
    BOOST_TEST(element(done.body, "ChecksumCRC64NVME") == full);
    BOOST_TEST(element(done.body, "ETag").ends_with("-3&quot;"));

    // The object reads back whole, by part, with its checksum.
    const s3::header_list mode{{"x-amz-checksum-mode", "ENABLED"}};
    const auto got = f.send("GET", "/bkt/big.bin", mode);
    BOOST_TEST(got.body == whole);
    BOOST_TEST(got.header("Content-Type") == "application/x-thing");
    BOOST_TEST(got.header("x-amz-meta-k") == "v");
    BOOST_TEST(got.header("x-amz-checksum-crc64nvme") == full);
    BOOST_TEST(got.header("x-amz-checksum-type") == "FULL_OBJECT");
    BOOST_TEST(got.header("x-amz-checksum-algorithm").empty());
    BOOST_TEST(f.send("GET", "/bkt/big.bin?partNumber=2").body == p2);
    BOOST_TEST(f.send("POST", "/bkt/big.bin?uploadId=" + id, {}, complete_body(true)).code() ==
               "NoSuchUpload");

    // Abort drops an upload; aborting again finds nothing.
    const auto other = element(f.send("POST", "/bkt/dir/a?uploads").body, "UploadId");
    BOOST_TEST(f.send("DELETE", "/bkt/dir/a?uploadId=" + other).status == 204U);
    BOOST_TEST(f.send("DELETE", "/bkt/dir/a?uploadId=" + other).code() == "NoSuchUpload");
}

BOOST_AUTO_TEST_CASE(multipart_composite_checksums_part_copies_and_limits) {
    using s3::checksum_algorithm;
    fixture f;
    f.make_bucket("bkt");
    const auto src = random_bytes(6 * 1024 * 1024, 9);  // above S3's 5 MiB minimum
    f.send("PUT", "/bkt/src", {}, src);

    const auto create =
        f.send("POST", "/bkt/dst?uploads", {{"x-amz-checksum-algorithm", "SHA256"}});
    BOOST_TEST_REQUIRE(create.status == 200U, create.body);
    BOOST_TEST(create.header("x-amz-checksum-type") == "COMPOSITE");
    const auto id = element(create.body, "UploadId");
    const auto at = [&](int n) {
        return "/bkt/dst?partNumber=" + std::to_string(n) + "&uploadId=" + id;
    };
    // A part naming another algorithm than the upload's is refused.
    BOOST_TEST(f.send("PUT", at(1),
                      {{"x-amz-checksum-crc32", s3::checksum_of(checksum_algorithm::crc32, "x")}},
                      "x")
                   .code() == "InvalidRequest");

    // Part 1 copies the whole source, part 2 a range of it.
    const auto c1 = f.send("PUT", at(1), {{"x-amz-copy-source", "/bkt/src"}});
    BOOST_TEST_REQUIRE(c1.status == 200U, c1.body);
    const auto sha1 = s3::checksum_of(checksum_algorithm::sha256, src);
    BOOST_TEST(element(c1.body, "ChecksumSHA256") == sha1);
    BOOST_TEST(element(c1.body, "ETag") ==
               "&quot;" + s3::multipart_detail::hex_of(s3::object_detail::md5_raw(src)) + "&quot;");
    const auto c2 =
        f.send("PUT", at(2),
               {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-copy-source-range", "bytes=10-109"}});
    BOOST_TEST_REQUIRE(c2.status == 200U, c2.body);
    const auto sha2 = s3::checksum_of(checksum_algorithm::sha256, src.substr(10, 100));
    BOOST_TEST(element(c2.body, "ChecksumSHA256") == sha2);
    BOOST_TEST(
        f.send("PUT", at(3),
               {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-copy-source-range", "bytes=0-99999999"}})
            .code() == "InvalidRange");
    BOOST_TEST(f.send("PUT", at(3),
                      {{"x-amz-copy-source", "/bkt/src"}, {"x-amz-copy-source-if-match", "\"no\""}})
                   .code() == "PreconditionFailed");

    const auto xml = [&](bool with_checksums) {
        std::string out = "<CompleteMultipartUpload>";
        int n = 1;
        for (const auto* r : {&c1, &c2}) {
            out += "<Part><PartNumber>" + std::to_string(n++) + "</PartNumber><ETag>" +
                   element(r->body, "ETag") + "</ETag>";
            if (with_checksums) {
                out +=
                    "<ChecksumSHA256>" + element(r->body, "ChecksumSHA256") + "</ChecksumSHA256>";
            }
            out += "</Part>";
        }
        return out + "</CompleteMultipartUpload>";
    };
    // A chosen algorithm needs every part's checksum in the request.
    BOOST_TEST(f.send("POST", "/bkt/dst?uploadId=" + id, {}, xml(false)).code() ==
               "InvalidRequest");
    const auto done = f.send("POST", "/bkt/dst?uploadId=" + id, {}, xml(true));
    BOOST_TEST_REQUIRE(done.status == 200U, done.body);
    const auto composite = s3::composite_checksum(checksum_algorithm::sha256, {sha1, sha2});
    BOOST_TEST_REQUIRE(composite.has_value());
    BOOST_TEST(composite->ends_with("-2"));
    BOOST_TEST(element(done.body, "ChecksumSHA256") == *composite);
    BOOST_TEST(element(done.body, "ChecksumType") == "COMPOSITE");
    BOOST_TEST(f.send("GET", "/bkt/dst").body == src + src.substr(10, 100));

    // The default 5 MiB minimum applies to every part but the last.
    const auto small = element(f.send("POST", "/bkt/small?uploads").body, "UploadId");
    const auto s1 = f.send("PUT", "/bkt/small?partNumber=1&uploadId=" + small, {}, "tiny");
    const auto s2 = f.send("PUT", "/bkt/small?partNumber=2&uploadId=" + small, {}, "end");
    const auto small_xml = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
                           s1.header("ETag") +
                           "</ETag></Part><Part><PartNumber>2</PartNumber><ETag>" +
                           s2.header("ETag") + "</ETag></Part></CompleteMultipartUpload>";
    BOOST_TEST(f.send("POST", "/bkt/small?uploadId=" + small, {}, small_xml).code() ==
               "EntityTooSmall");
    BOOST_TEST(
        f.send("POST", "/bkt/x?uploads",
               {{"x-amz-checksum-algorithm", "SHA1"}, {"x-amz-checksum-type", "FULL_OBJECT"}})
            .code() == "InvalidRequest");

    // The sweep aborts uploads older than its age, and only those.
    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::time_point(k_now).time_since_epoch())
            .count());
    BOOST_TEST(s3::sweep_stale_uploads(f.meta, now_ms + 1000, 5000) == 0U);
    BOOST_TEST(s3::sweep_stale_uploads(f.meta, now_ms + 1000, 500) == 1U);
    BOOST_TEST(f.send("POST", "/bkt/small?uploadId=" + small, {}, small_xml).code() ==
               "NoSuchUpload");
}

BOOST_AUTO_TEST_CASE(access_follows_keys_roles_and_accounts) {
    fixture f;
    f.make_bucket("bkt");
    f.send("PUT", "/bkt/k", {}, "v");
    BOOST_TEST(f.send("GET", "/bkt/k", {}, {}, "AKIDREADER").body == "v");
    BOOST_TEST(f.send("PUT", "/bkt/k", {}, "w", "AKIDREADER").code() == "AccessDenied");
    BOOST_TEST(f.send("GET", "/bkt/k", {}, {}, "AKIDOTHER").code() == "AccessDenied");
    BOOST_TEST(f.send("GET", "/bkt/k", {}, {}, "").code() == "AccessDenied");
    BOOST_TEST(f.send("PUT", "/xyz", {}, {}, "AKIDREADER").code() == "AccessDenied");
    // A missing bucket is NoSuchBucket even to a stranger.
    BOOST_TEST(f.send("GET", "/nothing/k", {}, {}, "AKIDOTHER").code() == "NoSuchBucket");
}

BOOST_AUTO_TEST_CASE(authentication_failures_and_unbuilt_operations) {
    fixture f;
    f.make_bucket("bkt");
    auto good = f.send("GET", "/bkt/k");
    BOOST_TEST(good.code() == "NoSuchKey");
    // A wrong signature.
    s3::header_list h{{"Host", std::string(k_host)},
                      {"X-Amz-Date", std::string(k_date)},
                      {"x-amz-content-sha256", std::string(sv4::k_empty_sha256)},
                      {"Authorization", "AWS4-HMAC-SHA256 Credential=AKIDOWNER/" + k_scope.text() +
                                            ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
                                            "Signature=" +
                                            std::string(64, 'a')}};
    BOOST_TEST(f.raw("GET", "/bkt/k", h, {}).code() == "SignatureDoesNotMatch");
    BOOST_TEST(f.raw("GET", "/bkt/k",
                     {{"Host", std::string(k_host)}, {"Authorization", "AWS AKID:sig"}}, {})
                   .code() == "InvalidRequest");
    // A body that does not match its signed hash stores nothing.
    const auto tampered = f.send("PUT", "/bkt/k", {}, "abc", "AKIDOWNER", "abd");
    BOOST_TEST(tampered.code() == "XAmzContentSHA256Mismatch");
    BOOST_TEST(f.send("GET", "/bkt/k").code() == "NoSuchKey");
    const auto r = f.send("GET", "/bkt?cors");
    BOOST_TEST(r.status == 501U);
    BOOST_TEST(r.code() == "NotImplemented");
    BOOST_TEST(f.send("GET", "/bkt?website").status == 501U);
}

BOOST_AUTO_TEST_CASE(versioned_buckets_answer_with_version_ids_and_delete_markers) {
    fixture f;
    f.make_bucket("vbk");
    BOOST_TEST(f.send("GET", "/vbk?versioning").body.find("<Status>") == std::string::npos);
    const std::string enable =
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    BOOST_TEST_REQUIRE(f.send("PUT", "/vbk?versioning", {}, enable).status == 200U);
    BOOST_TEST(contains(f.send("GET", "/vbk?versioning").body, "<Status>Enabled</Status>"));
    BOOST_TEST(f.send("PUT", "/vbk?versioning", {},
                      "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled"
                      "</MfaDelete></VersioningConfiguration>")
                   .code() == "NotImplemented");

    const auto first = f.send("PUT", "/vbk/k", {}, "one");
    const auto second = f.send("PUT", "/vbk/k", {}, "two");
    const auto v1 = first.header("x-amz-version-id");
    BOOST_TEST(!v1.empty());
    BOOST_TEST(v1 != second.header("x-amz-version-id"));
    BOOST_TEST(f.send("GET", "/vbk/k?versionId=" + v1).body == "one");
    BOOST_TEST(f.send("GET", "/vbk/k").body == "two");

    const auto del = f.send("DELETE", "/vbk/k");
    BOOST_TEST(del.header("x-amz-delete-marker") == "true");
    const auto marker = del.header("x-amz-version-id");
    const auto gone = f.send("GET", "/vbk/k");
    BOOST_TEST(gone.code() == "NoSuchKey");
    BOOST_TEST(gone.header("x-amz-delete-marker") == "true");
    const auto at_marker = f.send("GET", "/vbk/k?versionId=" + marker);
    BOOST_TEST(at_marker.status == 405U);
    BOOST_TEST(at_marker.header("Allow") == "DELETE");
    BOOST_TEST(f.send("GET", "/vbk/k?versionId=bad").code() == "InvalidArgument");
    BOOST_TEST(f.send("GET", "/vbk/k?versionId=0000000000000001").code() == "NoSuchVersion");

    // ListObjectVersions: newest first per key, markers interleaved.
    f.send("PUT", "/vbk/other", {}, "x");
    const auto all = f.send("GET", "/vbk?versions");
    BOOST_TEST_REQUIRE(all.status == 200U, all.body);
    BOOST_TEST(count_of(all.body, "<Version>") == 3U);
    BOOST_TEST(count_of(all.body, "<DeleteMarker>") == 1U);
    BOOST_TEST(all.body.find("<DeleteMarker><Key>k</Key><VersionId>" + marker +
                             "</VersionId><IsLatest>true</IsLatest>") < all.body.find(v1));
    const auto page = f.send("GET", "/vbk?versions&max-keys=2");
    BOOST_TEST(element(page.body, "IsTruncated") == "true");
    const auto next =
        f.send("GET", "/vbk?versions&key-marker=" + element(page.body, "NextKeyMarker") +
                          "&version-id-marker=" + element(page.body, "NextVersionIdMarker"));
    BOOST_TEST(count_of(page.body, "<Version>") + count_of(page.body, "<DeleteMarker>") +
                   count_of(next.body, "<Version>") + count_of(next.body, "<DeleteMarker>") ==
               4U);
    BOOST_TEST(f.send("GET", "/vbk?versions&version-id-marker=" + v1).code() == "InvalidArgument");

    // Removing the marker brings the object back.
    BOOST_TEST(f.send("DELETE", "/vbk/k?versionId=" + marker).status == 204U);
    BOOST_TEST(f.send("GET", "/vbk/k").body == "two");

    // Suspended: new writes replace the null version.
    BOOST_TEST(f.send("PUT", "/vbk?versioning", {},
                      "<VersioningConfiguration><Status>Suspended</Status>"
                      "</VersioningConfiguration>")
                   .status == 200U);
    BOOST_TEST(f.send("PUT", "/vbk/k", {}, "three").header("x-amz-version-id") == "null");
    BOOST_TEST(f.send("PUT", "/vbk/k", {}, "four").header("x-amz-version-id") == "null");
    BOOST_TEST(f.send("GET", "/vbk/k?versionId=null").body == "four");
    BOOST_TEST(f.send("GET", "/vbk/k?versionId=" + v1).body == "one");
}

BOOST_AUTO_TEST_CASE(object_lock_protects_versions) {
    fixture f;
    // A bucket created with object lock is versioned from the start.
    BOOST_TEST_REQUIRE(
        f.send("PUT", "/lck", {{"x-amz-bucket-object-lock-enabled", "true"}}).status == 200U);
    BOOST_TEST(contains(f.send("GET", "/lck?versioning").body, "<Status>Enabled</Status>"));
    BOOST_TEST(f.send("PUT", "/lck?versioning", {},
                      "<VersioningConfiguration><Status>Suspended</Status>"
                      "</VersioningConfiguration>")
                   .code() == "InvalidBucketState");
    f.make_bucket("open");
    BOOST_TEST(f.send("GET", "/open?object-lock").code() == "ObjectLockConfigurationNotFoundError");

    const std::string until = "2026-12-01T00:00:00Z";
    const auto md5 = [](const std::string& body) {
        return s3::header_list{{"Content-MD5", md5_b64(body)}};
    };
    // Explicit retention on the PUT, which needs an integrity header.
    s3::header_list lock{{"x-amz-object-lock-mode", "GOVERNANCE"},
                         {"x-amz-object-lock-retain-until-date", until}};
    BOOST_TEST(f.send("PUT", "/lck/g", lock, "gov").code() == "InvalidRequest");
    lock.emplace_back("Content-MD5", md5_b64("gov"));
    const auto gov = f.send("PUT", "/lck/g", lock, "gov");
    BOOST_TEST_REQUIRE(gov.status == 200U, gov.body);
    const auto gv = gov.header("x-amz-version-id");
    const auto head = f.send("HEAD", "/lck/g");
    BOOST_TEST(head.header("x-amz-object-lock-mode") == "GOVERNANCE");
    BOOST_TEST(head.header("x-amz-object-lock-retain-until-date") == "2026-12-01T00:00:00.000Z");
    BOOST_TEST(head.header("x-kythira-object-lock-until-ms").empty());
    BOOST_TEST(f.send("PUT", "/open/x", lock, "gov").code() == "InvalidRequest");
    BOOST_TEST(f.send("PUT", "/lck/past",
                      {{"x-amz-object-lock-mode", "GOVERNANCE"},
                       {"x-amz-object-lock-retain-until-date", "2026-01-01T00:00:00Z"},
                       {"Content-MD5", md5_b64("p")}},
                      "p")
                   .code() == "InvalidArgument");

    // GOVERNANCE: a version delete needs the bypass; a plain delete only
    // adds a marker.
    BOOST_TEST(f.send("DELETE", "/lck/g?versionId=" + gv).code() == "AccessDenied");
    BOOST_TEST(f.send("DELETE", "/lck/g").header("x-amz-delete-marker") == "true");
    BOOST_TEST(f.send("GET", "/lck/g?versionId=" + gv).body == "gov");
    const auto ret = f.send("GET", "/lck/g?retention&versionId=" + gv);
    BOOST_TEST(contains(ret.body, "<Mode>GOVERNANCE</Mode>"));
    // Shortening needs the bypass; extending does not.
    const auto retention = [](const std::string& mode, const std::string& date) {
        return "<Retention><Mode>" + mode + "</Mode><RetainUntilDate>" + date +
               "</RetainUntilDate></Retention>";
    };
    const auto shorter = retention("GOVERNANCE", "2026-11-20T00:00:00Z");
    BOOST_TEST(f.send("PUT", "/lck/g?retention&versionId=" + gv, md5(shorter), shorter).code() ==
               "AccessDenied");
    auto bypass = md5(shorter);
    bypass.emplace_back("x-amz-bypass-governance-retention", "true");
    BOOST_TEST(f.send("PUT", "/lck/g?retention&versionId=" + gv, bypass, shorter).status == 200U);
    auto del_bypass = s3::header_list{{"x-amz-bypass-governance-retention", "true"}};
    BOOST_TEST(f.send("DELETE", "/lck/g?versionId=" + gv, del_bypass).status == 204U);
    BOOST_TEST(f.send("GET", "/lck/g?versionId=" + gv).code() == "NoSuchVersion");

    // COMPLIANCE: nothing removes it or shortens it, bypass or not.
    const auto comp = f.send("PUT", "/lck/c",
                             {{"x-amz-object-lock-mode", "COMPLIANCE"},
                              {"x-amz-object-lock-retain-until-date", until},
                              {"Content-MD5", md5_b64("cmp")}},
                             "cmp");
    const auto cv = comp.header("x-amz-version-id");
    BOOST_TEST(f.send("DELETE", "/lck/c?versionId=" + cv, del_bypass).code() == "AccessDenied");
    const auto weaker = retention("GOVERNANCE", "2027-01-01T00:00:00Z");
    auto weaker_bypass = md5(weaker);
    weaker_bypass.emplace_back("x-amz-bypass-governance-retention", "true");
    BOOST_TEST(f.send("PUT", "/lck/c?retention", weaker_bypass, weaker).code() == "AccessDenied");
    const auto longer = retention("COMPLIANCE", "2027-01-01T00:00:00Z");
    BOOST_TEST(f.send("PUT", "/lck/c?retention", md5(longer), longer).status == 200U);
    const std::string del_body =
        "<Delete><Object><Key>c</Key><VersionId>" + cv + "</VersionId></Object></Delete>";
    const auto multi = f.send("POST", "/lck?delete", md5(del_body), del_body);
    BOOST_TEST(contains(multi.body, "<Code>AccessDenied</Code>"));

    // Legal hold blocks deletion until it is released.
    const auto plain = f.send("PUT", "/lck/h", {}, "held");
    const auto hv = plain.header("x-amz-version-id");
    BOOST_TEST(f.send("GET", "/lck/h?legal-hold").code() == "NoSuchObjectLockConfiguration");
    const std::string on = "<LegalHold><Status>ON</Status></LegalHold>";
    BOOST_TEST(f.send("PUT", "/lck/h?legal-hold", {}, on).code() == "InvalidRequest");
    BOOST_TEST(f.send("PUT", "/lck/h?legal-hold", md5(on), on).status == 200U);
    BOOST_TEST(contains(f.send("GET", "/lck/h?legal-hold").body, "<Status>ON</Status>"));
    BOOST_TEST(f.send("DELETE", "/lck/h?versionId=" + hv, del_bypass).code() == "AccessDenied");
    const std::string off = "<LegalHold><Status>OFF</Status></LegalHold>";
    BOOST_TEST(f.send("PUT", "/lck/h?legal-hold", md5(off), off).status == 200U);
    BOOST_TEST(f.send("DELETE", "/lck/h?versionId=" + hv).status == 204U);

    // Default retention applies to writes that name none, copies included,
    // and a copy never inherits its source's lock.
    const std::string config =
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule>"
        "<DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule>"
        "</ObjectLockConfiguration>";
    BOOST_TEST(f.send("PUT", "/lck?object-lock", {}, config).code() == "InvalidRequest");
    BOOST_TEST(f.send("PUT", "/lck?object-lock", md5(config), config).status == 200U);
    BOOST_TEST(contains(f.send("GET", "/lck?object-lock").body, "<Days>1</Days>"));
    const auto d = f.send("HEAD", "/lck/" + std::string("c"));
    BOOST_TEST(d.header("x-amz-object-lock-mode") == "COMPLIANCE");
    f.send("PUT", "/lck/d", {}, "default");
    BOOST_TEST(f.send("HEAD", "/lck/d").header("x-amz-object-lock-retain-until-date") ==
               "2026-11-19T12:00:00.000Z");
    f.send("PUT", "/lck/copy", {{"x-amz-copy-source", "/lck/c"}});
    BOOST_TEST(f.send("HEAD", "/lck/copy").header("x-amz-object-lock-mode") == "GOVERNANCE");

    // A bucket gains object lock once versioning is enabled.
    BOOST_TEST(f.send("PUT", "/open?object-lock", md5(config), config).code() ==
               "InvalidBucketState");
    const std::string enable =
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    f.send("PUT", "/open?versioning", {}, enable);
    BOOST_TEST(f.send("PUT", "/open?object-lock", md5(config), config).status == 200U);
    BOOST_TEST(contains(f.send("GET", "/open?object-lock").body,
                        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"));
}

BOOST_AUTO_TEST_CASE(browser_post_uploads) {
    fixture f;
    f.make_bucket("bkt");
    const std::string boundary = "XyZboundary";
    const auto policy_json =
        std::string(R"({"expiration":"2026-11-18T13:00:00Z","conditions":[)") +
        R"({"bucket":"bkt"},["starts-with","$key","up/"],)" + R"(["content-length-range",1,100],)" +
        R"({"success_action_status":"201"},)" + R"({"x-amz-algorithm":"AWS4-HMAC-SHA256"},)" +
        R"({"x-amz-credential":"AKIDOWNER/20261118/us-east-1/s3/aws4_request"},)" +
        R"({"x-amz-date":"20261118T120000Z"}]})";
    const auto policy = s3::bucket_detail::b64(policy_json);
    const auto sig = sv4::detail::to_hex(
        sv4::detail::hmac_sha256(sv4::derive_signing_key("owner-secret", k_scope), policy));
    const auto form = [&](const std::vector<std::pair<std::string, std::string>>& fields,
                          const std::string& file) {
        std::string b;
        for (const auto& [k, v] : fields) {
            b += "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + k +
                 "\"\r\n\r\n" + v + "\r\n";
        }
        b += "--" + boundary +
             "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
             "Content-Type: text/plain\r\n\r\n" +
             file + "\r\n--" + boundary + "--\r\n";
        return b;
    };
    const std::vector<std::pair<std::string, std::string>> fields{
        {"key", "up/${filename}"},
        {"success_action_status", "201"},
        {"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
        {"X-Amz-Credential", "AKIDOWNER/20261118/us-east-1/s3/aws4_request"},
        {"X-Amz-Date", "20261118T120000Z"},
        {"Policy", policy},
        {"X-Amz-Signature", sig}};
    const s3::header_list type{{"Content-Type", "multipart/form-data; boundary=" + boundary}};
    const auto r = f.raw("POST", "/bkt", type, form(fields, "posted!"));
    BOOST_TEST_REQUIRE(r.status == 201U, r.body);
    BOOST_TEST(contains(r.body, "<Key>up/a.txt</Key>"));
    const auto got = f.send("GET", "/bkt/up/a.txt");
    BOOST_TEST(got.body == "posted!");
    BOOST_TEST(got.header("Content-Type") == "text/plain");

    // Too long for the policy: refused and not kept.
    const auto big = f.raw("POST", "/bkt", type, form(fields, std::string(200, 'x')));
    BOOST_TEST(big.code() == "EntityTooLarge");
    // A tampered policy.
    auto bad = fields;
    bad[5].second =
        s3::bucket_detail::b64(R"({"expiration":"2030-01-01T00:00:00Z","conditions":[]})");
    BOOST_TEST(f.raw("POST", "/bkt", type, form(bad, "x")).code() == "SignatureDoesNotMatch");
    // Anonymous, to a private bucket.
    BOOST_TEST(f.raw("POST", "/bkt", type, form({{"key", "anon"}}, "x")).code() == "AccessDenied");
}

BOOST_AUTO_TEST_CASE(per_account_namespaces_let_names_repeat) {
    s3::service_options o;
    o.account_namespaces = true;
    fixture f(o);
    BOOST_TEST(f.make_bucket("same").status == 200U);
    BOOST_TEST(f.make_bucket("same", "AKIDOTHER").status == 200U);
    f.send("PUT", "/same/k", {}, "mine");
    f.send("PUT", "/same/k", {}, "theirs", "AKIDOTHER");
    BOOST_TEST(f.send("GET", "/same/k").body == "mine");
    BOOST_TEST(f.send("GET", "/same/k", {}, {}, "AKIDOTHER").body == "theirs");
    BOOST_TEST(contains(f.send("GET", "/").body, "<Name>same</Name>"));
    BOOST_TEST(f.send("GET", "/same/k", {}, {}, "").code() == "NoSuchBucket");
}

BOOST_AUTO_TEST_CASE(the_served_operations_are_the_ones_the_coverage_list_names) {
    std::ifstream in(std::string(KYTHIRA_S3_DIR_DEFAULT) + "implemented-operations.txt");
    BOOST_TEST_REQUIRE(in.good());
    std::set<std::string, std::less<>> listed;
    for (std::string line; std::getline(in, line);) {
        if (!line.empty() && line.front() != '#') {
            listed.insert(line);
        }
    }
    BOOST_TEST((listed == s3::implemented_operations()));
}

namespace {

/// A KMS for the encryption tests: wraps like the local provider, records
/// who asked, and refuses `reader` everything, as a key policy that names
/// only the owner would.
struct fake_kms {
    s3::local_key_provider inner{test_secret(5), test_secret(6)};
    std::shared_ptr<std::vector<std::string>> calls = std::make_shared<std::vector<std::string>>();

    void check(const s3::kms_caller& who, const std::string& op) const {
        calls->push_back(op + " " + (who.principal ? who.principal->arn : std::string("anon")));
        if (who.principal && who.principal->arn.ends_with("/reader")) {
            throw s3::kms_error(s3::kms_failure::access_denied,
                                "reader is not authorized to perform kms:" + op);
        }
    }
    [[nodiscard]] auto generate_data_key(const std::string& id, const s3::encryption_context& c,
                                         const s3::kms_caller& who) const
        -> s3::generated_data_key {
        check(who, "GenerateDataKey");
        if (id == "alias/disabled") {
            throw s3::kms_error(s3::kms_failure::disabled, "key is disabled");
        }
        auto k = inner.generate_data_key(id, c, who);
        k.key_id = id.starts_with("arn:") ? id : "arn:aws:kms:us-east-1:111122223333:key/" + id;
        return k;
    }
    [[nodiscard]] auto decrypt_data_key(const std::string& id, const std::string& wrapped,
                                        const s3::encryption_context& c,
                                        const s3::kms_caller& who) const -> std::string {
        check(who, "Decrypt");
        // Wrapped under the id the caller gave at generation.
        const auto slash = id.rfind('/');
        const auto bare = id.starts_with("arn:aws:kms:") ? id.substr(slash + 1) : id;
        for (const auto& candidate : {id, bare, std::string("alias/aws/s3")}) {
            try {
                return inner.decrypt_data_key(candidate, wrapped, c, who);
            } catch (const s3::kms_error&) {
            }
        }
        throw s3::kms_error(s3::kms_failure::invalid_ciphertext, "does not unwrap");
    }
};

struct sse_fixture {
    std::shared_ptr<s3::sse_keys> keys = std::make_shared<s3::sse_keys>();
    fake_kms kms;
    std::unique_ptr<fixture> f;

    sse_fixture() {
        keys->s3_managed = s3::key_provider(s3::local_key_provider(test_secret(7)));
        keys->kms = s3::key_provider(kms);
        s3::service_options o;
        o.encryption = keys;
        f = std::make_unique<fixture>(o);
        f->make_bucket("enc");
    }

    /// Whether any blob copy holds `text` in the clear.
    [[nodiscard]] auto stored_in_clear(std::string_view text) -> bool {
        for (auto& n : f->nodes) {
            const std::lock_guard lock(n.mu);
            for (const auto& [sha, bytes] : n.chunks) {
                const std::string_view s(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                if (s.find(text) != std::string_view::npos) {
                    return true;
                }
            }
        }
        return false;
    }
    [[nodiscard]] auto chunk_count() -> std::size_t {
        const std::lock_guard lock(f->nodes[0].mu);
        return f->nodes[0].chunks.size();
    }
};

auto customer_headers(const std::string& key,
                      std::string_view prefix = "x-amz-server-side-encryption-customer-")
    -> s3::header_list {
    const std::string p(prefix);
    return {{p + "algorithm", "AES256"},
            {p + "key", s3::bucket_detail::b64(key)},
            {p + "key-MD5", md5_b64(key)}};
}

}  // namespace

BOOST_AUTO_TEST_CASE(sse_s3_is_the_default_and_blob_stores_hold_ciphertext) {
    sse_fixture t;
    auto& f = *t.f;
    const std::string body = "plaintext marker " + std::string(150, 'p') + " end";
    const auto put = f.send("PUT", "/enc/a", {}, body);
    BOOST_TEST_REQUIRE(put.status == 200U, put.body);
    BOOST_TEST(put.header("x-amz-server-side-encryption") == "AES256");
    // SSE-S3 keeps the MD5 ETag S3 gives it.
    BOOST_TEST(put.header("ETag") == "\"" + md5_hex(body) + "\"");
    BOOST_TEST(!t.stored_in_clear("plaintext marker"));
    BOOST_TEST(!t.stored_in_clear(std::string(40, 'p')));

    const auto got = f.send("GET", "/enc/a");
    BOOST_TEST(got.body == body);
    BOOST_TEST(got.header("x-amz-server-side-encryption") == "AES256");
    BOOST_TEST(got.header("x-kythira-sse-wrapped").empty());
    BOOST_TEST(f.send("GET", "/enc/a", {{"Range", "bytes=60-139"}}).body == body.substr(60, 80));
    BOOST_TEST(f.send("HEAD", "/enc/a").header("Content-Length") == std::to_string(body.size()));
    // The reader needs no KMS permission for SSE-S3.
    BOOST_TEST(f.send("GET", "/enc/a", {}, {}, "AKIDREADER").body == body);

    // Same bytes under another object's key are other chunks.
    const auto before = t.chunk_count();
    f.send("PUT", "/enc/b", {}, body);
    BOOST_TEST(t.chunk_count() == 2 * before);
    // A copy between SSE-S3 objects shares the chunks.
    BOOST_TEST(f.send("PUT", "/enc/c", {{"x-amz-copy-source", "/enc/a"}}).status == 200U);
    BOOST_TEST(t.chunk_count() == 2 * before);
    BOOST_TEST(f.send("GET", "/enc/c").body == body);

    // Read-only headers on a GET, and bad write headers.
    BOOST_TEST(f.send("GET", "/enc/a", {{"x-amz-server-side-encryption", "AES256"}}).code() ==
               "InvalidArgument");
    BOOST_TEST(f.send("PUT", "/enc/x",
                      {{"x-amz-server-side-encryption", "AES256"},
                       {"x-amz-server-side-encryption-aws-kms-key-id", "k"}},
                      "x")
                   .code() == "InvalidArgument");
    BOOST_TEST(f.send("PUT", "/enc/x", {{"x-amz-server-side-encryption", "DES"}}, "x").code() ==
               "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(sse_kms_asks_the_kms_as_the_caller) {
    sse_fixture t;
    auto& f = *t.f;
    const std::string body = "kms secret " + std::string(100, 'k');
    const std::string context = s3::bucket_detail::b64(R"({"project":"x"})");
    const auto put = f.send("PUT", "/enc/k",
                            {{"x-amz-server-side-encryption", "aws:kms"},
                             {"x-amz-server-side-encryption-aws-kms-key-id", "key-1"},
                             {"x-amz-server-side-encryption-context", context}},
                            body);
    BOOST_TEST_REQUIRE(put.status == 200U, put.body);
    BOOST_TEST(put.header("x-amz-server-side-encryption") == "aws:kms");
    BOOST_TEST(put.header("x-amz-server-side-encryption-aws-kms-key-id") ==
               "arn:aws:kms:us-east-1:111122223333:key/key-1");
    const auto ctx_json =
        s3::bucket_detail::unb64(put.header("x-amz-server-side-encryption-context"));
    BOOST_TEST_REQUIRE(ctx_json.has_value());
    BOOST_TEST(contains(*ctx_json, R"("aws:s3:arn":"arn:aws:s3:::enc/k")"));
    BOOST_TEST(contains(*ctx_json, R"("project":"x")"));
    // No MD5 of the data in the ETag.
    BOOST_TEST(put.header("ETag") != "\"" + md5_hex(body) + "\"");
    BOOST_TEST(!t.stored_in_clear("kms secret"));

    const auto got = f.send("GET", "/enc/k");
    BOOST_TEST(got.body == body);
    BOOST_TEST(got.header("x-amz-server-side-encryption-aws-kms-key-id") ==
               "arn:aws:kms:us-east-1:111122223333:key/key-1");
    BOOST_TEST(t.kms.calls->back() == "Decrypt arn:aws:iam::111122223333:user/owner");
    // S3 lets the reader read; the KMS does not.
    BOOST_TEST(f.send("GET", "/enc/k", {}, {}, "AKIDREADER").code() == "AccessDenied");
    BOOST_TEST(f.send("PUT", "/enc/d",
                      {{"x-amz-server-side-encryption", "aws:kms"},
                       {"x-amz-server-side-encryption-aws-kms-key-id", "alias/disabled"}},
                      "x")
                   .code() == "KMS.DisabledException");
    BOOST_TEST(f.send("PUT", "/enc/d",
                      {{"x-amz-server-side-encryption", "aws:kms"},
                       {"x-amz-server-side-encryption-context", "not json"}},
                      "x")
                   .code() == "InvalidArgument");

    // A copy onto itself that asks for SSE-S3 re-encrypts it.
    const auto back =
        f.send("PUT", "/enc/k",
               {{"x-amz-copy-source", "/enc/k"}, {"x-amz-server-side-encryption", "AES256"}});
    BOOST_TEST_REQUIRE(back.status == 200U, back.body);
    BOOST_TEST(back.header("x-amz-server-side-encryption") == "AES256");
    BOOST_TEST(f.send("GET", "/enc/k", {}, {}, "AKIDREADER").body == body);
}

BOOST_AUTO_TEST_CASE(bucket_default_encryption_and_bucket_keys) {
    sse_fixture t;
    auto& f = *t.f;
    const auto initial = f.send("GET", "/enc?encryption");
    BOOST_TEST_REQUIRE(initial.status == 200U, initial.body);
    BOOST_TEST(element(initial.body, "SSEAlgorithm") == "AES256");
    BOOST_TEST(element(initial.body, "BucketKeyEnabled") == "false");

    const std::string cfg =
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>"
        "<SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>bucket-key</KMSMasterKeyID>"
        "</ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule>"
        "</ServerSideEncryptionConfiguration>";
    BOOST_TEST_REQUIRE(
        f.send("PUT", "/enc?encryption", {{"Content-MD5", md5_b64(cfg)}}, cfg).status == 200U);
    const auto now = f.send("GET", "/enc?encryption");
    BOOST_TEST(element(now.body, "KMSMasterKeyID") == "bucket-key");
    BOOST_TEST(element(now.body, "BucketKeyEnabled") == "true");

    // Three objects, one KMS call: the bucket key covers them.
    const auto before = t.keys->stats().kms_generate;
    for (const auto* k : {"one", "two", "three"}) {
        const auto put = f.send("PUT", std::string("/enc/") + k, {}, std::string("body of ") + k);
        BOOST_TEST_REQUIRE(put.status == 200U, put.body);
        BOOST_TEST(put.header("x-amz-server-side-encryption") == "aws:kms");
        BOOST_TEST(put.header("x-amz-server-side-encryption-bucket-key-enabled") == "true");
    }
    BOOST_TEST(t.keys->stats().kms_generate == before + 1);
    for (const auto* k : {"one", "two", "three"}) {
        BOOST_TEST(f.send("GET", std::string("/enc/") + k).body == std::string("body of ") + k);
    }
    // A request may still turn the bucket key off for its object.
    const auto own = f.send("PUT", "/enc/own",
                            {{"x-amz-server-side-encryption", "aws:kms"},
                             {"x-amz-server-side-encryption-bucket-key-enabled", "false"}},
                            "own");
    BOOST_TEST(own.header("x-amz-server-side-encryption-bucket-key-enabled").empty());
    BOOST_TEST(t.keys->stats().kms_generate == before + 2);

    const std::string bad =
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>"
        "<SSEAlgorithm>AES256</SSEAlgorithm><KMSMasterKeyID>k</KMSMasterKeyID>"
        "</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    BOOST_TEST(f.send("PUT", "/enc?encryption", {{"Content-MD5", md5_b64(bad)}}, bad).code() ==
               "InvalidArgument");
    BOOST_TEST(f.send("DELETE", "/enc?encryption").status == 204U);
    BOOST_TEST(element(f.send("GET", "/enc?encryption").body, "SSEAlgorithm") == "AES256");
    BOOST_TEST(f.send("PUT", "/enc/after", {}, "x").header("x-amz-server-side-encryption") ==
               "AES256");
}

BOOST_AUTO_TEST_CASE(sse_c_keys_are_checked_and_never_stored) {
    sse_fixture t;
    auto& f = *t.f;
    const std::string key(32, 'K');
    const std::string other(32, 'O');
    const std::string body = "customer secret " + std::string(90, 'c');
    const auto put = f.send("PUT", "/enc/c", customer_headers(key), body);
    BOOST_TEST_REQUIRE(put.status == 200U, put.body);
    BOOST_TEST(put.header("x-amz-server-side-encryption-customer-algorithm") == "AES256");
    BOOST_TEST(put.header("x-amz-server-side-encryption-customer-key-MD5") == md5_b64(key));
    BOOST_TEST(put.header("x-amz-server-side-encryption").empty());
    BOOST_TEST(!t.stored_in_clear("customer secret"));
    // The key is nowhere in the stored metadata.
    const auto v = f.meta.version(f.meta.bucket("enc")->id, "c", std::nullopt);
    BOOST_TEST_REQUIRE(v.has_value());
    for (const auto& [k, val] : v->content.system_metadata) {
        BOOST_TEST(!contains(val, s3::bucket_detail::b64(key)), k);
        BOOST_TEST(!contains(val, key), k);
    }

    BOOST_TEST(f.send("GET", "/enc/c").code() == "InvalidRequest");
    BOOST_TEST(f.send("HEAD", "/enc/c").status == 400U);
    BOOST_TEST(f.send("GET", "/enc/c", customer_headers(other)).status == 403U);
    const auto got = f.send("GET", "/enc/c", customer_headers(key));
    BOOST_TEST(got.body == body);
    BOOST_TEST(got.header("x-amz-server-side-encryption-customer-key-md5") == md5_b64(key));
    // SSE-C headers on an object that has none.
    f.send("PUT", "/enc/plain", {}, "plain");
    BOOST_TEST(f.send("GET", "/enc/plain", customer_headers(key)).code() == "InvalidRequest");

    // Malformed keys.
    auto wrong_md5 = customer_headers(key);
    wrong_md5[2].second = md5_b64(other);
    BOOST_TEST(f.send("PUT", "/enc/x", wrong_md5, "x").code() == "InvalidArgument");
    auto short_key = customer_headers(std::string(16, 'k'));
    BOOST_TEST(f.send("PUT", "/enc/x", short_key, "x").code() == "InvalidArgument");
    auto both = customer_headers(key);
    both.emplace_back("x-amz-server-side-encryption", "AES256");
    BOOST_TEST(f.send("PUT", "/enc/x", both, "x").code() == "InvalidArgument");

    // A copy opens the source with the copy-source key and seals the
    // target under the bucket default.
    auto copy = customer_headers(key, "x-amz-copy-source-server-side-encryption-customer-");
    copy.emplace_back("x-amz-copy-source", "/enc/c");
    const auto copied = f.send("PUT", "/enc/c2", copy);
    BOOST_TEST_REQUIRE(copied.status == 200U, copied.body);
    BOOST_TEST(copied.header("x-amz-server-side-encryption") == "AES256");
    BOOST_TEST(f.send("GET", "/enc/c2").body == body);
    BOOST_TEST(f.send("PUT", "/enc/c3", {{"x-amz-copy-source", "/enc/c"}}).code() ==
               "InvalidRequest");
}

BOOST_AUTO_TEST_CASE(encrypted_multipart_uploads) {
    sse_fixture t;
    auto& f = *t.f;
    const std::string tagging =
        "<Tagging><TagSet><Tag><Key>kythira:compat:min-part-bytes</Key><Value>100</Value></Tag>"
        "</TagSet></Tagging>";
    BOOST_TEST_REQUIRE(
        f.send("PUT", "/enc?tagging", {{"Content-MD5", md5_b64(tagging)}}, tagging).status == 204U);
    const std::string key(32, 'M');
    const auto create = f.send("POST", "/enc/mp?uploads", customer_headers(key));
    BOOST_TEST_REQUIRE(create.status == 200U, create.body);
    BOOST_TEST(create.header("x-amz-server-side-encryption-customer-algorithm") == "AES256");
    const auto id = element(create.body, "UploadId");
    const auto at = [&](int n) {
        return "/enc/mp?partNumber=" + std::to_string(n) + "&uploadId=" + id;
    };
    const auto p1 = random_bytes(200, 7);
    const auto p2 = random_bytes(90, 8);
    BOOST_TEST(f.send("PUT", at(1), {}, p1).code() == "InvalidRequest");
    BOOST_TEST(f.send("PUT", at(1), customer_headers(std::string(32, 'X')), p1).status == 403U);
    auto md5 = customer_headers(key);
    md5.emplace_back("Content-MD5", md5_b64(p1));
    const auto put1 = f.send("PUT", at(1), md5, p1);
    BOOST_TEST_REQUIRE(put1.status == 200U, put1.body);
    BOOST_TEST(put1.header("x-amz-server-side-encryption-customer-key-MD5") == md5_b64(key));
    BOOST_TEST(put1.header("ETag") != "\"" + md5_hex(p1) + "\"");

    // Part 2 copies from an SSE-KMS object.
    BOOST_TEST_REQUIRE(
        f.send("PUT", "/enc/src", {{"x-amz-server-side-encryption", "aws:kms"}}, p2).status ==
        200U);
    auto part_copy = customer_headers(key);
    part_copy.emplace_back("x-amz-copy-source", "/enc/src");
    const auto put2 = f.send("PUT", at(2), part_copy);
    BOOST_TEST_REQUIRE(put2.status == 200U, put2.body);
    const std::string done =
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + put1.header("ETag") +
        "</ETag></Part><Part><PartNumber>2</PartNumber>"
        "<ETag>" +
        element(put2.body, "ETag") + "</ETag></Part></CompleteMultipartUpload>";
    const auto complete = f.send("POST", "/enc/mp?uploadId=" + id, {}, done);
    BOOST_TEST_REQUIRE(complete.status == 200U, complete.body);
    BOOST_TEST(!t.stored_in_clear(p1.substr(0, 40)));
    BOOST_TEST(f.send("GET", "/enc/mp").code() == "InvalidRequest");
    BOOST_TEST(f.send("GET", "/enc/mp", customer_headers(key)).body == p1 + p2);
    auto ranged = customer_headers(key);
    ranged.emplace_back("Range", "bytes=150-249");
    BOOST_TEST(f.send("GET", "/enc/mp", ranged).body == (p1 + p2).substr(150, 100));
}

// ---- task 12: request rates and slow writes ----------------------------------

BOOST_AUTO_TEST_CASE(a_prefix_over_its_rate_gets_slow_down) {
    std::vector<std::pair<std::string, std::string>> hot;
    s3::service_options o;
    o.rates.hot_refusals = 1;
    o.on_hot_prefix = [&](const std::string& b, const std::string& p) { hot.emplace_back(b, p); };
    fixture f(std::move(o));
    f.make_bucket("bkt");
    BOOST_TEST(f.send("PUT", "/bkt?tagging", {},
                      "<Tagging><TagSet><Tag><Key>kythira:compat:put-rate</Key><Value>2</Value>"
                      "</Tag><Tag><Key>kythira:compat:get-rate</Key><Value>3</Value></Tag>"
                      "</TagSet></Tagging>")
                   .status == 204U);
    // The clock stands still, so each prefix has its one second of burst.
    BOOST_TEST(f.send("PUT", "/bkt/a/1", {}, "x").status == 200U);
    BOOST_TEST(f.send("PUT", "/bkt/a/2", {}, "x").status == 200U);
    const auto refused = f.send("PUT", "/bkt/a/3", {}, "x");
    BOOST_TEST(refused.status == 503U);
    BOOST_TEST(refused.code() == "SlowDown");
    // Deletes are writes; another prefix has its own bucket; reads have
    // theirs.
    BOOST_TEST(f.send("DELETE", "/bkt/a/1").code() == "SlowDown");
    BOOST_TEST(f.send("PUT", "/bkt/b/1", {}, "x").status == 200U);
    BOOST_TEST(f.send("GET", "/bkt/a/2").status == 200U);
    BOOST_TEST(f.send("HEAD", "/bkt/a/2").status == 200U);
    // A listing counts against its prefix up to the last '/'.
    BOOST_TEST(f.send("GET", "/bkt?prefix=a/x").status == 200U);
    BOOST_TEST(f.send("GET", "/bkt?prefix=a/").code() == "SlowDown");
    BOOST_TEST(f.send("GET", "/bkt?prefix=b/").status == 200U);

    BOOST_TEST(f.svc->rates().refused() == 3U);
    // More than one refusal in the window: reported once.
    BOOST_REQUIRE(hot.size() == 1U);
    BOOST_TEST(hot[0].second == "a/");
    BOOST_TEST(f.svc->rates().hot_reports() == 1U);
}

BOOST_AUTO_TEST_CASE(a_rate_of_zero_turns_the_limit_off) {
    fixture f;
    f.make_bucket("bkt");
    BOOST_TEST(f.send("PUT", "/bkt?tagging", {},
                      "<Tagging><TagSet><Tag><Key>kythira:compat:put-rate</Key><Value>0</Value>"
                      "</Tag></TagSet></Tagging>")
                   .status == 204U);
    for (int i = 0; i < 20; ++i) {
        BOOST_TEST(f.send("PUT", "/bkt/k", {}, "x").status == 200U);
    }
    // Only the tagging request itself, at the default rate, was counted.
    BOOST_TEST(f.svc->rates().tracked() == 1U);
}

BOOST_AUTO_TEST_CASE(a_write_slower_than_the_limit_is_not_committed) {
    s3::service_options o;
    o.max_write_ms = 0;  // any time at all between first chunk and commit
    auto ticks = std::make_shared<std::int64_t>(0);
    o.clock = [ticks] {
        return std::chrono::system_clock::time_point(k_now) + std::chrono::milliseconds((*ticks)++);
    };
    fixture f(std::move(o));
    f.make_bucket("bkt");
    const auto r = f.send("PUT", "/bkt/k", {}, "some bytes");
    BOOST_TEST(r.status == 503U);
    BOOST_TEST(r.code() == "SlowDown");
    BOOST_TEST(f.send("HEAD", "/bkt/k").status == 404U);
}

BOOST_AUTO_TEST_CASE(prefix_buckets_refill_with_time_and_idle_ones_are_dropped) {
    BOOST_TEST(s3::rate_prefix("a/b/c.txt") == "a/b/");
    BOOST_TEST(s3::rate_prefix("c.txt").empty());
    BOOST_TEST(s3::rate_prefix("dir/") == "dir/");

    s3::prefix_rates::options o;
    o.max_tracked = 2;
    s3::prefix_rates rates(o);
    // 10 a second: a burst of 10, then one every 100 ms.
    for (int i = 0; i < 10; ++i) {
        BOOST_TEST(rates.admit("b", "p/", true, 10, 1'000));
    }
    BOOST_TEST(!rates.admit("b", "p/", true, 10, 1'000));
    BOOST_TEST(!rates.admit("b", "p/", true, 10, 1'099));
    BOOST_TEST(rates.admit("b", "p/", true, 10, 1'100));
    // Reads and writes, and buckets, are counted apart.
    BOOST_TEST(rates.admit("b", "p/", false, 10, 1'100));
    BOOST_TEST(rates.tracked() == 2U);
    // A third bucket drops the ones idle for a second.
    BOOST_TEST(rates.admit("c", "p/", true, 10, 2'200));
    BOOST_TEST(rates.tracked() == 1U);
    BOOST_TEST(rates.refused() == 2U);
}

// ---- task 13: lifecycle, storage classes, restores ---------------------------

namespace {

auto lifecycle_doc(const std::string& rules) -> std::string {
    return "<LifecycleConfiguration>" + rules + "</LifecycleConfiguration>";
}

auto md5_b64(const std::string& body) -> std::string {
    return s3::sse_detail::b64(s3::sse_detail::md5_raw(body));
}

}  // namespace

BOOST_AUTO_TEST_CASE(lifecycle_configurations_are_set_read_and_removed) {
    fixture f;
    f.make_bucket("bkt");
    BOOST_TEST(f.send("GET", "/bkt?lifecycle").code() == "NoSuchLifecycleConfiguration");
    const auto doc = lifecycle_doc(
        "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>"
        "<Expiration><Days>3</Days></Expiration></Rule>");
    BOOST_TEST(f.send("PUT", "/bkt?lifecycle", {}, doc).code() == "InvalidRequest");
    const auto put = f.send("PUT", "/bkt?lifecycle", {{"Content-MD5", md5_b64(doc)}}, doc);
    BOOST_TEST(put.status == 200U);
    BOOST_TEST(put.header("x-amz-transition-default-minimum-object-size") ==
               "all_storage_classes_128K");
    const auto got = f.send("GET", "/bkt?lifecycle");
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(contains(got.body, "<ID>logs</ID>"));
    BOOST_TEST(contains(got.body, "<Days>3</Days>"));

    // Objects under the rule say when they expire.
    const auto written = f.send("PUT", "/bkt/logs/a", {}, "x");
    const auto expected =
        "expiry-date=\"" +
        kythira::aws_rest_xml::http_date(
            std::chrono::system_clock::time_point(std::chrono::milliseconds(s3::due_after(
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::time_point(k_now).time_since_epoch())
                        .count()),
                3, s3::standard_day_ms)))) +
        "\", rule-id=\"logs\"";
    BOOST_TEST(written.header("x-amz-expiration") == expected);
    BOOST_TEST(f.send("HEAD", "/bkt/logs/a").header("x-amz-expiration") == expected);
    BOOST_TEST(f.send("PUT", "/bkt/other", {}, "x").header("x-amz-expiration").empty());

    const auto bad = lifecycle_doc("<Rule><Filter/><Status>Enabled</Status></Rule>");
    BOOST_TEST(f.send("PUT", "/bkt?lifecycle", {{"Content-MD5", md5_b64(bad)}}, bad).code() ==
               "InvalidRequest");
    BOOST_TEST(f.send("DELETE", "/bkt?lifecycle").status == 204U);
    BOOST_TEST(f.send("GET", "/bkt?lifecycle").code() == "NoSuchLifecycleConfiguration");
}

BOOST_AUTO_TEST_CASE(archived_objects_need_a_restore_before_a_read) {
    fixture f;
    f.make_bucket("bkt");
    BOOST_TEST(f.send("PUT", "/bkt/cold", {{"x-amz-storage-class", "GLACIER"}}, "frozen").status ==
               200U);
    BOOST_TEST(f.send("PUT", "/bkt/warm", {}, "warm").status == 200U);
    const auto head = f.send("HEAD", "/bkt/cold");
    BOOST_TEST(head.status == 200U);
    BOOST_TEST(head.header("x-amz-storage-class") == "GLACIER");
    BOOST_TEST(f.send("GET", "/bkt/cold").code() == "InvalidObjectState");
    BOOST_TEST(f.send("PUT", "/bkt/copy", {{"x-amz-copy-source", "/bkt/cold"}}).code() ==
               "InvalidObjectState");

    const std::string req =
        "<RestoreRequest><Days>2</Days><GlacierJobParameters><Tier>Standard"
        "</Tier></GlacierJobParameters></RestoreRequest>";
    BOOST_TEST(f.send("POST", "/bkt/warm?restore", {}, req).code() == "InvalidObjectState");
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, "<RestoreRequest/>").code() ==
               "InvalidArgument");
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, req).status == 202U);
    BOOST_TEST(contains(f.send("HEAD", "/bkt/cold").header("x-amz-restore"),
                        "ongoing-request=\"false\", expiry-date="));
    const auto read = f.send("GET", "/bkt/cold");
    BOOST_TEST(read.status == 200U);
    BOOST_TEST(read.body == "frozen");
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, req).status == 200U);  // extends it
    BOOST_TEST(f.send("PUT", "/bkt/copy", {{"x-amz-copy-source", "/bkt/cold"}}).status == 200U);
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {},
                      "<RestoreRequest><Type>SELECT</Type></RestoreRequest>")
                   .status == 501U);
}

namespace {

/// A cloud store in memory, for the archive tier.
struct memory_cloud {
    mutable std::mutex mu;
    mutable std::map<std::string, std::string> objects;
    mutable bool failing = false;

    auto put_object(const std::string& bucket, const std::string& key, std::string_view bytes) const
        -> kythira::put_result {
        const std::lock_guard lock(mu);
        if (failing) {
            throw std::runtime_error("cloud down");
        }
        objects[bucket + "/" + key] = std::string(bytes);
        return {};
    }
    auto get_object(const std::string& bucket, const std::string& key) const
        -> std::optional<kythira::get_result> {
        const std::lock_guard lock(mu);
        if (failing) {
            throw std::runtime_error("cloud down");
        }
        auto it = objects.find(bucket + "/" + key);
        if (it == objects.end()) {
            return std::nullopt;
        }
        return kythira::get_result{it->second, {}};
    }
    void delete_object(const std::string& bucket, const std::string& key) const {
        const std::lock_guard lock(mu);
        if (failing) {
            throw std::runtime_error("cloud down");
        }
        objects.erase(bucket + "/" + key);
    }
    auto list_keys(const std::string& bucket, const std::string& prefix) const
        -> std::vector<std::string> {
        const std::lock_guard lock(mu);
        std::vector<std::string> out;
        for (const auto& [k, v] : objects) {
            if (k.starts_with(bucket + "/" + prefix)) {
                out.push_back(k.substr(bucket.size() + 1));
            }
        }
        return out;
    }
    [[nodiscard]] auto provider_name() const -> std::string_view { return "memory"; }
};
static_assert(kythira::key_object_store<memory_cloud>);

auto k_now_ms() -> std::uint64_t {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(k_now.time_since_epoch()).count());
}

struct tiered : fixture {
    memory_cloud cloud;
    s3::cloud_tier tier{"cold", cloud, "archive", "kythira/"};
    s3::tier_worker<s3::local_metadata> worker;

    static auto options() -> s3::tier_options {
        s3::tier_options o;
        o.class_tiers = {{"GLACIER", "cold"}, {"DEEP_ARCHIVE", "cold"}};
        o.clock = [] { return k_now_ms(); };
        return o;
    }
    tiered() : worker(meta, *data, {&tier}, options()) {}

    /// Forget every local copy, as the sweeper would once nothing refers
    /// to the chunks.
    void wipe_local() {
        for (auto& n : nodes) {
            const std::lock_guard lock(n.mu);
            n.chunks.clear();
        }
    }
    [[nodiscard]] auto local_chunks() const -> std::size_t {
        std::size_t n = 0;
        for (const auto& c : nodes) {
            n += c.chunks.size();
        }
        return n;
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(archived_bytes_move_to_the_cloud_tier_and_come_back_on_restore) {
    tiered f;
    f.make_bucket("bkt");
    std::string varied(200, 'z');  // four chunks of 64
    for (std::size_t i = 0; i < varied.size(); ++i) {
        varied[i] = static_cast<char>('a' + (i / 64));
    }
    BOOST_TEST(f.send("PUT", "/bkt/cold", {{"x-amz-storage-class", "GLACIER"}}, varied).status ==
               200U);
    BOOST_TEST(f.send("PUT", "/bkt/warm", {}, "warm").status == 200U);

    auto r = f.worker.run();
    BOOST_TEST(r.archived == 1U);
    BOOST_TEST(r.chunks_uploaded == 4U);
    BOOST_TEST(r.failures == 0U);
    BOOST_TEST(f.cloud.objects.size() == 4U);
    for (const auto& [k, v] : f.cloud.objects) {
        BOOST_TEST(k.starts_with("archive/kythira/"));
    }
    BOOST_TEST(f.worker.run().archived == 0U);  // done once

    // The sweeper may now take the local copies.
    f.wipe_local();
    BOOST_TEST(f.send("PUT", "/bkt/warm", {}, "warm").status == 200U);  // keep warm readable
    const auto head = f.send("HEAD", "/bkt/cold");
    BOOST_TEST(head.header("x-amz-storage-class") == "GLACIER");
    BOOST_TEST(head.header("x-amz-restore").empty());
    BOOST_TEST(f.send("GET", "/bkt/cold").code() == "InvalidObjectState");
    // A copy cannot read the bytes either, even to a warm class.
    BOOST_TEST(f.send("PUT", "/bkt/copy",
                      {{"x-amz-copy-source", "/bkt/cold"}, {"x-amz-storage-class", "STANDARD"}})
                   .code() == "InvalidObjectState");

    const std::string req = "<RestoreRequest><Days>3</Days></RestoreRequest>";
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, req).status == 202U);
    BOOST_TEST(f.send("HEAD", "/bkt/cold").header("x-amz-restore") == "ongoing-request=\"true\"");
    BOOST_TEST(f.send("GET", "/bkt/cold").code() == "InvalidObjectState");
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, req).code() == "RestoreAlreadyInProgress");

    // A failing cloud leaves the restore pending for the next run.
    f.cloud.failing = true;
    r = f.worker.run();
    BOOST_TEST(r.restored == 0U);
    BOOST_TEST(r.failures >= 1U);
    f.cloud.failing = false;

    r = f.worker.run();
    BOOST_TEST(r.restored == 1U);
    BOOST_TEST(r.chunks_restored == 4U);
    BOOST_TEST(f.local_chunks() >= 4U);
    BOOST_TEST(contains(f.send("HEAD", "/bkt/cold").header("x-amz-restore"),
                        "ongoing-request=\"false\", expiry-date="));
    const auto read = f.send("GET", "/bkt/cold");
    BOOST_TEST(read.status == 200U);
    BOOST_TEST(read.body == varied);
    BOOST_TEST(f.send("POST", "/bkt/cold?restore", {}, req).status == 200U);  // extends it
    BOOST_TEST(f.worker.run().archived == 0U);  // not archived again while restored

    // A copy of the restored object is an ordinary STANDARD object.
    BOOST_TEST(f.send("PUT", "/bkt/copy", {{"x-amz-copy-source", "/bkt/cold"}}).status == 200U);
    const auto copy = f.send("HEAD", "/bkt/copy");
    BOOST_TEST(copy.header("x-amz-storage-class").empty());
    BOOST_TEST(copy.header("x-amz-restore").empty());
    BOOST_TEST(f.send("GET", "/bkt/copy").body == varied);

    // Removing the version deletes its cloud copies.
    BOOST_TEST(f.send("DELETE", "/bkt/cold").status == 204U);
    r = f.worker.run();
    BOOST_TEST(r.garbage_versions == 1U);
    BOOST_TEST(r.chunks_deleted == 4U);
    BOOST_TEST(f.cloud.objects.empty());
    BOOST_TEST(f.worker.run().garbage_versions == 0U);
}

BOOST_AUTO_TEST_CASE(a_failed_or_stale_archive_leaves_the_version_local) {
    tiered f;
    f.make_bucket("bkt");
    BOOST_TEST(f.send("PUT", "/bkt/k", {{"x-amz-storage-class", "DEEP_ARCHIVE"}}, "deep").status ==
               200U);
    f.cloud.failing = true;
    auto r = f.worker.run();
    BOOST_TEST(r.archived == 0U);
    BOOST_TEST(r.failures == 1U);
    f.cloud.failing = false;
    // Still local: a restore completes at once, without the worker.
    BOOST_TEST(
        f.send("POST", "/bkt/k?restore", {}, "<RestoreRequest><Days>1</Days></RestoreRequest>")
            .status == 202U);
    BOOST_TEST(f.send("GET", "/bkt/k").body == "deep");
    BOOST_TEST(f.worker.run().archived == 0U);  // not while restored

    // Tiering configured for a warm class is refused.
    BOOST_CHECK_THROW(
        (s3::tier_worker<s3::local_metadata>(f.meta, *f.data, {&f.tier},
                                             [] {
                                                 s3::tier_options o;
                                                 o.class_tiers = {{"STANDARD_IA", "cold"}};
                                                 return o;
                                             }())),
        std::invalid_argument);
    BOOST_CHECK_THROW(
        (s3::tier_worker<s3::local_metadata>(f.meta, *f.data, {&f.tier},
                                             [] {
                                                 s3::tier_options o;
                                                 o.class_tiers = {{"GLACIER", "nowhere"}};
                                                 return o;
                                             }())),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(a_copy_can_change_only_the_storage_class) {
    fixture f;
    f.make_bucket("bkt");
    BOOST_TEST(f.send("PUT", "/bkt/k", {{"x-amz-meta-a", "1"}}, "body").status == 200U);
    const auto moved = f.send(
        "PUT", "/bkt/k", {{"x-amz-copy-source", "/bkt/k"}, {"x-amz-storage-class", "STANDARD_IA"}});
    BOOST_TEST(moved.status == 200U, moved.body);
    const auto head = f.send("HEAD", "/bkt/k");
    BOOST_TEST(head.header("x-amz-storage-class") == "STANDARD_IA");
    BOOST_TEST(head.header("x-amz-meta-a") == "1");
    BOOST_TEST(
        f.send("PUT", "/bkt/k", {{"x-amz-copy-source", "/bkt/k"}, {"x-amz-storage-class", "COLD"}})
            .code() == "InvalidStorageClass");
}

// ---- task 14: event notifications ---------------------------------------------

namespace {

auto notification_doc(const std::string& arn) -> std::string {
    return R"(<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">)"
           "<QueueConfiguration><Id>new-photos</Id><Queue>" +
           arn +
           "</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name>"
           "<Value>img/</Value></FilterRule></S3Key></Filter></QueueConfiguration>"
           "</NotificationConfiguration>";
}

const std::string k_queue_arn = "arn:aws:sqs:us-east-1:111122223333:photo-events";

}  // namespace

BOOST_AUTO_TEST_CASE(notification_configurations_are_checked_against_their_destinations) {
    std::vector<s3::notification_delivery> sent;
    bool refuse = false;
    s3::service_options o;
    o.notifications = [&](const s3::notification_delivery& d) -> s3::delivery_outcome {
        sent.push_back(d);
        if (refuse) {
            return {false, true, "AccessDenied"};
        }
        return {true, false, {}};
    };
    fixture f(std::move(o));
    BOOST_REQUIRE(f.make_bucket("bkt").status == 200U);
    auto got = f.send("GET", "/bkt?notification");
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(contains(got.body, "<NotificationConfiguration"));
    BOOST_TEST(!contains(got.body, "QueueConfiguration"));

    BOOST_TEST(f.send("PUT", "/bkt?notification", {}, notification_doc(k_queue_arn)).status ==
               200U);
    BOOST_TEST_REQUIRE(sent.size() == 1U);  // the test event
    BOOST_TEST(sent[0].arn == k_queue_arn);
    BOOST_TEST(contains(sent[0].body, "\"Event\":\"s3:TestEvent\""));
    BOOST_TEST(contains(sent[0].body, "\"Bucket\":\"bkt\""));
    got = f.send("GET", "/bkt?notification");
    BOOST_TEST(contains(got.body, "<Id>new-photos</Id>"));
    BOOST_TEST(contains(got.body, "<Name>Prefix</Name><Value>img/</Value>"));
    BOOST_TEST(f.meta.bucket("bkt")->config.contains("notification"));

    // Writes to the bucket are now logged for the worker.
    BOOST_TEST(f.send("PUT", "/bkt/img/a.jpg", {}, "abc").status == 200U);
    BOOST_TEST(f.meta.state_machine().change_log().value().last_seq == 1U);

    // A destination that refuses the test event fails the request.
    refuse = true;
    const auto other = notification_doc("arn:aws:sqs:us-east-1:111122223333:other");
    auto bad = f.send("PUT", "/bkt?notification", {}, other);
    BOOST_TEST(bad.status == 400U);
    BOOST_TEST(bad.code() == "InvalidArgument");
    BOOST_TEST(contains(bad.body, "Unable to validate the following destination configurations"));
    BOOST_TEST(contains(f.send("GET", "/bkt?notification").body, "photo-events"));
    // Unless the caller skips the check.
    BOOST_TEST(
        f.send("PUT", "/bkt?notification", {{"x-amz-skip-destination-validation", "true"}}, other)
            .status == 200U);
    BOOST_TEST(contains(f.send("GET", "/bkt?notification").body, ":other<"));

    // An empty configuration removes it, and writes stop being logged.
    BOOST_TEST(f.send("PUT", "/bkt?notification", {},
                      "<NotificationConfiguration "
                      "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>")
                   .status == 200U);
    BOOST_TEST(!f.meta.bucket("bkt")->config.contains("notification"));
    BOOST_TEST(f.send("PUT", "/bkt/img/b.jpg", {}, "abc").status == 200U);
    BOOST_TEST(f.meta.state_machine().change_log().value().last_seq == 1U);

    // Only the bucket owner (or a policy grant) may change it.
    BOOST_TEST(
        f.send("PUT", "/bkt?notification", {}, notification_doc(k_queue_arn), "AKIDOTHER").status ==
        403U);
    BOOST_TEST(f.send("PUT", "/bkt?notification", {}, "<Nope/>").code() == "MalformedXML");
}

// ---- task 14: replication -----------------------------------------------------

namespace {

auto replication_doc(const std::string& rules) -> std::string {
    return R"(<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">)"
           "<Role>arn:aws:iam::111122223333:role/replicator</Role>" +
           rules + "</ReplicationConfiguration>";
}

auto replication_rule(const std::string& id, const std::string& prefix, const std::string& dest,
                      int priority = 1, bool markers = true) -> std::string {
    return "<Rule><ID>" + id + "</ID><Priority>" + std::to_string(priority) +
           "</Priority><Status>Enabled</Status><Filter><Prefix>" + prefix +
           "</Prefix></Filter><Destination><Bucket>arn:aws:s3:::" + dest +
           "</Bucket></Destination><DeleteMarkerReplication><Status>" +
           (markers ? "Enabled" : "Disabled") + "</Status></DeleteMarkerReplication></Rule>";
}

/// `doc` as PutBucketReplication sends it (it needs Content-MD5).
auto put_replication(fixture& f, const std::string& bucket, const std::string& doc,
                     std::string_view key = "AKIDOWNER") -> reply {
    return f.send("PUT", "/" + bucket + "?replication", {{"Content-MD5", md5_b64(doc)}}, doc, key);
}

const std::string k_versioning_on =
    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";

struct scratch_dir {
    std::filesystem::path path;
    scratch_dir() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("s3_service_repl_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~scratch_dir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    scratch_dir(const scratch_dir&) = delete;
    auto operator=(const scratch_dir&) -> scratch_dir& = delete;
    scratch_dir(scratch_dir&&) = delete;
    auto operator=(scratch_dir&&) -> scratch_dir& = delete;
};

/// A source cluster with a change log, and a destination cluster the
/// replicator reaches through the S3 API, signed as the owner.
struct replication_pair {
    scratch_dir dir;
    std::unique_ptr<kythira::record_segment_store> store;
    std::unique_ptr<fixture> source;
    fixture dest;
    std::vector<s3::replication_request> sent;
    /// When set, answers instead of the destination.
    std::optional<s3::replication_answer> canned;

    replication_pair() {
        store = std::make_unique<kythira::record_segment_store>(
            kythira::record_segment_store_options{._data_dir = dir.path});
        source = std::make_unique<fixture>(s3::service_options{}, store.get());
        BOOST_REQUIRE(source->make_bucket("src").status == 200U);
        BOOST_REQUIRE(source->send("PUT", "/src?versioning", {}, k_versioning_on).status == 200U);
        BOOST_REQUIRE(dest.make_bucket("dst").status == 200U);
        BOOST_REQUIRE(dest.send("PUT", "/dst?versioning", {}, k_versioning_on).status == 200U);
    }

    auto call() -> s3::replication_call {
        return [this](s3::replication_request& q) -> s3::replication_answer {
            std::string body;
            if (q.body) {
                for (bool more = true; more;) {
                    auto r = q.body(body);
                    BOOST_REQUIRE(r.has_value());
                    more = *r;
                }
            }
            auto copy = q;
            copy.body = {};
            sent.push_back(copy);
            if (canned) {
                return *canned;
            }
            s3::header_list headers;
            for (const auto& [k, v] : q.headers) {
                if (k != "Content-Length") {
                    headers.emplace_back(k, v);
                }
            }
            auto r = dest.send(q.method, "/" + q.bucket + "/" + q.key, headers, body);
            return {static_cast<int>(r.status), r.body};
        };
    }

    auto worker(s3::replication_options o = {}) {
        return s3::replication_worker<s3::local_metadata>(source->meta, *source->data, nullptr,
                                                          call(), std::move(o));
    }
};

}  // namespace

BOOST_AUTO_TEST_CASE(replication_configurations_follow_s3s_rules) {
    fixture f;
    BOOST_REQUIRE(f.make_bucket("src").status == 200U);
    BOOST_REQUIRE(f.make_bucket("plain").status == 200U);
    BOOST_TEST(f.send("GET", "/src?replication").code() == "ReplicationConfigurationNotFoundError");
    const auto doc = replication_doc(replication_rule("r1", "docs/", "elsewhere"));
    // The source must keep versions.
    BOOST_TEST(put_replication(f, "src", doc).code() == "InvalidRequest");
    BOOST_REQUIRE(f.send("PUT", "/src?versioning", {}, k_versioning_on).status == 200U);
    BOOST_TEST(f.send("PUT", "/src?replication", {}, doc).code() == "InvalidRequest");  // no MD5
    BOOST_TEST(
        put_replication(f, "src", replication_doc(replication_rule("r", "", "src"))).code() ==
        "InvalidRequest");
    // A destination here must keep versions too.
    BOOST_TEST(
        put_replication(f, "src", replication_doc(replication_rule("r", "", "plain"))).code() ==
        "InvalidRequest");
    BOOST_TEST(put_replication(f, "src", doc).status == 200U);
    const auto got = f.send("GET", "/src?replication");
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(contains(got.body, "<Role>arn:aws:iam::111122223333:role/replicator</Role>"));
    BOOST_TEST(contains(got.body, "<Bucket>arn:aws:s3:::elsewhere</Bucket>"));
    BOOST_TEST(contains(got.body, "<DeleteMarkerReplication><Status>Enabled</Status>"));

    // Versioning stays on while replication is configured.
    BOOST_TEST(f.send("PUT", "/src?versioning", {},
                      "<VersioningConfiguration><Status>Suspended</Status>"
                      "</VersioningConfiguration>")
                   .code() == "InvalidBucketState");
    BOOST_TEST(f.send("DELETE", "/src?replication").status == 204U);
    BOOST_TEST(f.send("GET", "/src?replication").code() == "ReplicationConfigurationNotFoundError");
    BOOST_TEST(put_replication(f, "src", doc, "AKIDOTHER").status == 403U);
}

BOOST_AUTO_TEST_CASE(replication_rules_parse_both_schemas_and_refuse_bad_ones) {
    const auto parsed = [](const std::string& rules) {
        return s3::parse_replication_configuration(replication_doc(rules));
    };
    const auto code = [&](const std::string& rules) {
        auto c = parsed(rules);
        return c ? std::string{} : c.error().code;
    };
    auto v2 = parsed(
        "<Rule><ID>tagged</ID><Priority>2</Priority><Status>Enabled</Status><Filter><And>"
        "<Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>"
        "<SourceSelectionCriteria><SseKmsEncryptedObjects><Status>Enabled</Status>"
        "</SseKmsEncryptedObjects></SourceSelectionCriteria><Destination><Bucket>arn:aws:s3:::d"
        "</Bucket><StorageClass>STANDARD_IA</StorageClass><EncryptionConfiguration>"
        "<ReplicaKmsKeyID>arn:aws:kms:us-east-1:1:key/k</ReplicaKmsKeyID>"
        "</EncryptionConfiguration></Destination><DeleteMarkerReplication><Status>Disabled"
        "</Status></DeleteMarkerReplication></Rule>" +
        replication_rule("plain", "a/", "d", 1));
    BOOST_TEST_REQUIRE(v2.has_value());
    BOOST_TEST(v2->rules.size() == 2U);
    BOOST_TEST(v2->rules[0].sse_kms);
    BOOST_TEST(v2->rules[0].storage_class == "STANDARD_IA");
    auto again = s3::parse_replication_configuration(s3::replication_xml(*v2));
    BOOST_TEST_REQUIRE(again.has_value());
    BOOST_TEST((*again == *v2));
    // The higher priority decides for a destination; KMS objects only go
    // where the rule allows.
    const std::vector<std::pair<std::string, std::string>> tags{{"k", "v"}};
    auto rules = s3::replication_rules_for(*v2, "a/x", tags, false);
    BOOST_TEST_REQUIRE(rules.size() == 1U);
    BOOST_TEST(rules[0]->id == "tagged");
    rules = s3::replication_rules_for(*v2, "a/x", {}, false);
    BOOST_TEST_REQUIRE(rules.size() == 1U);
    BOOST_TEST(rules[0]->id == "plain");
    BOOST_TEST(s3::replication_rules_for(*v2, "a/x", {}, true).empty());
    BOOST_TEST(s3::replication_rules_for(*v2, "b/x", tags, false).empty());

    auto v1 = parsed(
        "<Rule><ID>old</ID><Status>Enabled</Status><Prefix>logs/</Prefix>"
        "<Destination><Bucket>arn:aws:s3:::d</Bucket></Destination></Rule>");
    BOOST_TEST_REQUIRE(v1.has_value());
    BOOST_TEST(v1->rules[0].filter.legacy_prefix);
    BOOST_TEST(contains(s3::replication_xml(*v1), "<Prefix>logs/</Prefix>"));

    BOOST_TEST(code("") == "MalformedXML");
    BOOST_TEST(code(replication_rule("a", "x/", "d", 1) + replication_rule("a", "y/", "d", 2)) ==
               "InvalidArgument");  // duplicate id
    BOOST_TEST(code(replication_rule("a", "x/", "d", 1) + replication_rule("b", "y/", "d", 1)) ==
               "InvalidRequest");  // duplicate priority
    BOOST_TEST(code("<Rule><ID>a</ID><Priority>1</Priority><Status>Enabled</Status><Filter/>"
                    "<Destination><Bucket>arn:aws:s3:::d</Bucket></Destination></Rule>") ==
               "InvalidRequest");  // the Filter form needs DeleteMarkerReplication
    BOOST_TEST(code("<Rule><ID>a</ID><Status>Enabled</Status><Prefix>x</Prefix><Destination>"
                    "<Bucket>arn:aws:s3:::d</Bucket></Destination></Rule><Rule><ID>b</ID>"
                    "<Status>Enabled</Status><Prefix>xy</Prefix><Destination><Bucket>"
                    "arn:aws:s3:::d</Bucket></Destination></Rule>") ==
               "InvalidRequest");  // overlapping prefixes
    BOOST_TEST(code("<Rule><ID>a</ID><Status>Enabled</Status><Prefix>x</Prefix><Destination>"
                    "<Bucket>bucket-d</Bucket></Destination></Rule>") == "InvalidArgument");
    BOOST_TEST(code("<Rule><ID>a</ID><Priority>1</Priority><Status>Enabled</Status><Filter/>"
                    "<ExistingObjectReplication><Status>Enabled</Status>"
                    "</ExistingObjectReplication><Destination><Bucket>arn:aws:s3:::d</Bucket>"
                    "</Destination><DeleteMarkerReplication><Status>Disabled</Status>"
                    "</DeleteMarkerReplication></Rule>") == "NotImplemented");
}

BOOST_AUTO_TEST_CASE(new_versions_replicate_to_another_kythira_cluster_in_order) {
    replication_pair p;
    auto& src = *p.source;
    BOOST_REQUIRE(
        put_replication(src, "src", replication_doc(replication_rule("docs", "docs/", "dst")))
            .status == 200U);
    const std::string body = "replicate me " + std::string(200, 'r');
    BOOST_REQUIRE(src.send("PUT", "/src/docs/a.txt",
                           {{"Content-Type", "text/plain"},
                            {"x-amz-meta-color", "blue"},
                            {"x-amz-tagging", "team=core"},
                            {"Cache-Control", "max-age=60"}},
                           body)
                      .status == 200U);
    BOOST_TEST(src.send("HEAD", "/src/docs/a.txt").header("x-amz-replication-status") == "PENDING");
    BOOST_REQUIRE(src.send("PUT", "/src/other/b.txt", {}, "stays").status == 200U);
    BOOST_TEST(src.send("HEAD", "/src/other/b.txt").header("x-amz-replication-status").empty());
    BOOST_REQUIRE(src.send("PUT", "/src/docs/a.txt", {}, "second version").status == 200U);

    auto w = p.worker();
    auto r = w.run();
    BOOST_TEST(r.replicated == 2U);
    BOOST_TEST(r.records == 3U);
    BOOST_TEST(!r.blocked);
    BOOST_TEST_REQUIRE(p.sent.size() == 2U);  // the two docs/ versions, in order
    BOOST_TEST(p.sent[0].length == body.size());

    // The destination holds both versions, the newest current, as replicas.
    auto got = p.dest.send("GET", "/dst/docs/a.txt");
    BOOST_TEST(got.status == 200U);
    BOOST_TEST(got.body == "second version");
    BOOST_TEST(got.header("x-amz-replication-status") == "REPLICA");
    auto versions = p.dest.send("GET", "/dst?versions");
    BOOST_TEST(contains(versions.body, "<IsLatest>false</IsLatest>"));
    auto first =
        p.dest.send("GET", "/dst/docs/a.txt?versionId=" +
                               versions.body.substr(versions.body.rfind("<VersionId>") + 11,
                                                    versions.body.rfind("</VersionId>") -
                                                        versions.body.rfind("<VersionId>") - 11));
    BOOST_TEST(first.body == body);
    BOOST_TEST(first.header("Content-Type") == "text/plain");
    BOOST_TEST(first.header("x-amz-meta-color") == "blue");
    BOOST_TEST(first.header("Cache-Control") == "max-age=60");
    BOOST_TEST(first.header("x-amz-tagging-count") == "1");
    BOOST_TEST(p.dest.send("GET", "/dst/other/b.txt").status == 404U);

    // The source says so.
    BOOST_TEST(src.send("HEAD", "/src/docs/a.txt").header("x-amz-replication-status") ==
               "COMPLETED");

    // A client's delete marker follows; a replica is never replicated on.
    BOOST_REQUIRE(src.send("DELETE", "/src/docs/a.txt").status == 204U);
    r = w.run();
    BOOST_TEST(r.delete_markers == 1U);
    BOOST_TEST(p.dest.send("GET", "/dst/docs/a.txt").status == 404U);
    BOOST_TEST(p.sent.back().method == "DELETE");
    BOOST_TEST(w.run().records == 0U);
}

BOOST_AUTO_TEST_CASE(only_principals_allowed_to_replicate_may_write_replicas) {
    fixture f;
    BOOST_REQUIRE(f.make_bucket("dst").status == 200U);
    BOOST_TEST(f.send("PUT", "/dst/k", {{"x-amz-replication-status", "REPLICA"}}, "x", "AKIDREADER")
                   .status == 403U);
    BOOST_TEST(f.send("PUT", "/dst/k", {{"x-amz-replication-status", "REPLICA"}}, "x").status ==
               200U);
    BOOST_TEST(f.send("HEAD", "/dst/k").header("x-amz-replication-status") == "REPLICA");
    // Without the header, no status.
    BOOST_TEST(f.send("PUT", "/dst/j", {}, "x").status == 200U);
    BOOST_TEST(f.send("HEAD", "/dst/j").header("x-amz-replication-status").empty());
}

BOOST_AUTO_TEST_CASE(a_destination_that_is_down_holds_back_replication_until_it_answers) {
    replication_pair p;
    auto& src = *p.source;
    BOOST_REQUIRE(
        put_replication(src, "src", replication_doc(replication_rule("all", "", "dst"))).status ==
        200U);
    BOOST_REQUIRE(src.send("PUT", "/src/k1", {}, "one").status == 200U);
    BOOST_REQUIRE(src.send("PUT", "/src/k2", {}, "two").status == 200U);
    p.canned = s3::replication_answer{503, "<Error><Code>SlowDown</Code></Error>"};
    auto w = p.worker({.max_attempts = 3});
    auto r = w.run();
    BOOST_TEST(r.blocked);
    BOOST_TEST(r.records == 0U);
    BOOST_TEST(p.sent.size() == 1U);  // k2 waits behind k1
    BOOST_TEST(src.send("HEAD", "/src/k1").header("x-amz-replication-status") == "PENDING");

    p.canned.reset();
    r = w.run();
    BOOST_TEST(!r.blocked);
    BOOST_TEST(r.replicated == 2U);
    BOOST_TEST(p.dest.send("GET", "/dst/k1").body == "one");
    BOOST_TEST(p.dest.send("GET", "/dst/k2").body == "two");

    // A refusal fails the version for good; so does running out of attempts.
    BOOST_REQUIRE(src.send("PUT", "/src/k3", {}, "three").status == 200U);
    p.canned = s3::replication_answer{403, "<Error><Code>AccessDenied</Code></Error>"};
    r = w.run();
    BOOST_TEST(r.failed == 1U);
    BOOST_TEST(src.send("HEAD", "/src/k3").header("x-amz-replication-status") == "FAILED");
    BOOST_REQUIRE(src.send("PUT", "/src/k4", {}, "four").status == 200U);
    p.canned = s3::replication_answer{500, "<Error><Code>InternalError</Code></Error>"};
    BOOST_TEST(w.run().blocked);
    BOOST_TEST(w.run().blocked);
    r = w.run();
    BOOST_TEST(r.failed == 1U);
    BOOST_TEST(src.send("HEAD", "/src/k4").header("x-amz-replication-status") == "FAILED");
    BOOST_TEST(src.meta.change_cursor(s3::replication_consumer) ==
               src.meta.state_machine().change_log()->last_seq);
}

BOOST_AUTO_TEST_CASE(copies_uploads_and_customer_keys_get_their_own_replication_status) {
    replication_pair p;
    auto& src = *p.source;
    BOOST_REQUIRE(
        put_replication(src, "src", replication_doc(replication_rule("docs", "docs/", "dst")))
            .status == 200U);
    BOOST_REQUIRE(src.send("PUT", "/src/other/a", {}, "bytes").status == 200U);
    // A copy into the replicated prefix replicates; one out of it does not
    // inherit the source's status.
    BOOST_REQUIRE(
        src.send("PUT", "/src/docs/copied", {{"x-amz-copy-source", "/src/other/a"}}).status ==
        200U);
    BOOST_TEST(src.send("HEAD", "/src/docs/copied").header("x-amz-replication-status") ==
               "PENDING");
    BOOST_REQUIRE(
        src.send("PUT", "/src/other/back", {{"x-amz-copy-source", "/src/docs/copied"}}).status ==
        200U);
    BOOST_TEST(src.send("HEAD", "/src/other/back").header("x-amz-replication-status").empty());

    // A multipart upload is decided when it starts.
    const auto created = src.send("POST", "/src/docs/mp?uploads");
    BOOST_REQUIRE(created.status == 200U);
    const auto a = created.body.find("<UploadId>") + 10;
    const auto upload_id = created.body.substr(a, created.body.find("</UploadId>") - a);
    const auto part = src.send("PUT", "/src/docs/mp?partNumber=1&uploadId=" + upload_id, {}, "p");
    BOOST_REQUIRE(part.status == 200U);
    const auto done_doc = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
                          part.header("ETag") + "</ETag></Part></CompleteMultipartUpload>";
    BOOST_REQUIRE(src.send("POST", "/src/docs/mp?uploadId=" + upload_id, {}, done_doc).status ==
                  200U);
    BOOST_TEST(src.send("HEAD", "/src/docs/mp").header("x-amz-replication-status") == "PENDING");

    // The replicator cannot read an object only its writer has the key to.
    const std::string key(32, 'K');
    BOOST_REQUIRE(src.send("PUT", "/src/docs/secret", customer_headers(key), "s").status == 200U);
    BOOST_TEST(src.send("HEAD", "/src/docs/secret", customer_headers(key))
                   .header("x-amz-replication-status")
                   .empty());

    auto w = p.worker();
    const auto r = w.run();
    BOOST_TEST(r.replicated == 2U);
    BOOST_TEST(p.dest.send("GET", "/dst/docs/copied").body == "bytes");
    BOOST_TEST(p.dest.send("GET", "/dst/docs/mp").body == "p");
    BOOST_TEST(p.dest.send("GET", "/dst/docs/secret").status == 404U);
}
