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

#include <raft/static_key_authorizer.hpp>

#include <array>
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

namespace {

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
    s3::local_metadata meta;
    std::unique_ptr<s3::data_path> data;
    authorizer auth;
    std::unique_ptr<s3::s3_service<s3::local_metadata, authorizer>> svc;

    explicit fixture(s3::service_options o = {}) {
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
        o.clock = [] { return std::chrono::system_clock::time_point(k_now); };
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
    BOOST_TEST(f.send("PUT", "/bkt/e", {{"x-amz-server-side-encryption", "aws:kms"}}, "x").status ==
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
    const auto r = f.send("GET", "/bkt?versioning");
    BOOST_TEST(r.status == 501U);
    BOOST_TEST(r.code() == "NotImplemented");
    BOOST_TEST(f.send("GET", "/bkt/k?legal-hold").status == 501U);
}

BOOST_AUTO_TEST_CASE(versioned_buckets_answer_with_version_ids_and_delete_markers) {
    fixture f;
    f.make_bucket("vbk");
    // PutBucketVersioning is task 10; set the state underneath.
    s3::index_command c;
    c.op = s3::index_command::kind::put_bucket_config;
    c.bucket = "vbk";
    c.config_name = "versioning";
    c.document = "Enabled";
    BOOST_TEST_REQUIRE(f.meta.propose(c).ok());

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
    // Removing the marker brings the object back.
    BOOST_TEST(f.send("DELETE", "/vbk/k?versionId=" + marker).status == 204U);
    BOOST_TEST(f.send("GET", "/vbk/k").body == "two");
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
