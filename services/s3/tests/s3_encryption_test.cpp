// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_encryption_test.cpp
/// @brief Server-side encryption's parts (.kiro/specs/s3-compatible-storage/
///        task 11): chunk sealing, the data path over sealed chunks, the
///        local key provider, the request headers, bucket default
///        encryption, and object keys (SSE-S3, SSE-KMS with bucket keys,
///        SSE-C). `s3_service_test` covers them end to end.

#define BOOST_TEST_MODULE s3_encryption_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_chunk_cipher.hpp>
#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_encryption.hpp>
#include <kythira/s3/s3_kms_provider.hpp>
#include <kythira/s3/s3_placement.hpp>

#include <raft/chunk_store.hpp>

#include <chrono>
#include <cstddef>
#include <map>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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
using kythira::chunk_read_result;
using kythira::chunk_read_status;
using kythira::chunk_sha;
using kythira::chunk_write_result;

auto bytes_of(std::string_view s) -> std::vector<std::byte> {
    const auto b = std::as_bytes(std::span(s.data(), s.size()));
    return {b.begin(), b.end()};
}

auto text_of(std::span<const std::byte> b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

const std::string k_key(32, 'k');

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

s3::kms_caller const k_owner{[] {
                                 kythira::aws_auth::principal_context p;
                                 p.arn = "arn:aws:iam::111122223333:user/owner";
                                 p.account = "111122223333";
                                 return p;
                             }(),
                             "198.51.100.1", "req"};

}  // namespace

BOOST_AUTO_TEST_CASE(chunks_seal_deterministically_and_open_only_under_their_key) {
    const s3::chunk_cipher c(k_key);
    const auto plain = bytes_of("some chunk of an object");
    const auto sealed = c.seal(plain);
    BOOST_TEST(sealed.size() == plain.size() + s3::chunk_cipher::overhead);
    BOOST_TEST(text_of(sealed).find("chunk") == std::string::npos);
    // The same plaintext under the same key is the same chunk.
    BOOST_TEST((c.seal(plain) == sealed));
    BOOST_TEST((c.seal(bytes_of("some chunk of an objecT")) != sealed));
    const auto opened = c.open(sealed);
    BOOST_TEST_REQUIRE(opened.has_value());
    BOOST_TEST((*opened == plain));

    const s3::chunk_cipher other(std::string(32, 'o'));
    BOOST_TEST((other.seal(plain) != sealed));
    BOOST_TEST(!other.open(sealed).has_value());
    auto tampered = sealed;
    tampered[20] ^= std::byte{1};
    BOOST_TEST(!c.open(tampered).has_value());
    BOOST_TEST(!c.open(std::span(sealed).first(sealed.size() - 1)).has_value());
    BOOST_TEST(!c.open(std::span(sealed).first(10)).has_value());

    const auto empty = c.seal({});
    BOOST_TEST(empty.size() == s3::chunk_cipher::overhead);
    BOOST_TEST(c.open(empty).value().empty());
    BOOST_CHECK_THROW(s3::chunk_cipher(std::string(16, 'x')), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(the_data_path_stores_only_sealed_chunks) {
    memory_copy store;
    std::vector<s3::chunk_copy> copies;
    copies.emplace_back("n0", store);
    s3::data_path_options o;
    o.chunk_bytes = 100;
    o.parallel_writes = false;
    std::vector<std::string> nodes{"n0"};
    s3::data_path data([&](const chunk_sha& sha) { return s3::place({}, sha, nodes); },
                       s3::resolver_for(copies), o);
    const s3::chunk_cipher c(k_key);
    std::string body;
    for (int i = 0; i < 30; ++i) {
        body += "line " + std::to_string(i) + " of the secret body\n";
    }
    auto w = data.writer(&c);
    BOOST_TEST_REQUIRE(!w.append(std::as_bytes(std::span(body.data(), body.size()))).has_value());
    auto written = w.finish();
    BOOST_TEST_REQUIRE(written.has_value());
    // Plaintext sizes in the manifest; sealed chunks no larger than a chunk.
    s3::object_content content;
    content.manifest = written->manifest;
    BOOST_TEST(content.size() == body.size());
    BOOST_TEST(written->manifest.front().size == 100 - s3::chunk_cipher::overhead);
    for (const auto& [sha, bytes] : store.chunks) {
        BOOST_TEST(bytes.size() <= 100U);
        BOOST_TEST(text_of(bytes).find("secret") == std::string::npos);
    }

    std::string back;
    const auto sink = [&](std::span<const std::byte> b) { back += text_of(b); };
    BOOST_TEST_REQUIRE(data.read_range(content, 0, body.size(), sink, &c).has_value());
    BOOST_TEST(back == body);
    back.clear();
    BOOST_TEST_REQUIRE(data.read_range(content, 150, 300, sink, &c).has_value());
    BOOST_TEST(back == body.substr(150, 300));

    // Never served under another key, or as if it were plaintext.
    const s3::chunk_cipher wrong(std::string(32, 'w'));
    auto bad = data.read_range(content, 0, 10, sink, &wrong);
    BOOST_TEST_REQUIRE(!bad.has_value());
    BOOST_TEST(bad.error().status == 500U);
    BOOST_TEST(!data.read_range(content, 0, 10, sink).has_value());
}

BOOST_AUTO_TEST_CASE(the_local_provider_binds_key_ids_and_contexts) {
    const s3::local_key_provider p(test_secret(1));
    const s3::encryption_context ctx{{"aws:s3:arn", "arn:aws:s3:::b/k"}};
    const auto k = p.generate_data_key("kythira/s3", ctx, k_owner);
    BOOST_TEST(k.plaintext.size() == 32U);
    BOOST_TEST(k.key_id == "kythira/s3");
    BOOST_TEST(p.decrypt_data_key("kythira/s3", k.wrapped, ctx, k_owner) == k.plaintext);
    // Another node with the same passphrase reads it.
    const s3::local_key_provider peer(test_secret(1));
    BOOST_TEST(peer.decrypt_data_key("kythira/s3", k.wrapped, ctx, k_owner) == k.plaintext);

    const auto refused = [&](const s3::local_key_provider& q, const std::string& id,
                             const s3::encryption_context& c) {
        try {
            (void)q.decrypt_data_key(id, k.wrapped, c, k_owner);
        } catch (const s3::kms_error& e) {
            return e.failure() == s3::kms_failure::invalid_ciphertext;
        }
        return false;
    };
    BOOST_TEST(refused(p, "other", ctx));
    BOOST_TEST(refused(p, "kythira/s3", {{"aws:s3:arn", "arn:aws:s3:::b/other"}}));
    BOOST_TEST(refused(s3::local_key_provider(test_secret(2)), "kythira/s3", ctx));
    BOOST_CHECK_THROW(s3::local_key_provider(""), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(customer_keys_are_checked_as_s3_checks_them) {
    const auto b64 = [](std::string_view s) { return s3::sse_detail::b64(s); };
    const auto md5 = [&](std::string_view s) { return b64(s3::sse_detail::md5_raw(s)); };
    const std::string p(s3::customer_prefix);
    const auto parse = [&](s3::header_list h, bool secure = true) {
        return s3::parse_customer_key(h, s3::customer_prefix, secure);
    };
    BOOST_TEST(!parse({}).value().has_value());
    const s3::header_list good{
        {p + "algorithm", "AES256"}, {p + "key", b64(k_key)}, {p + "key-MD5", md5(k_key)}};
    const auto ok = parse(good);
    BOOST_TEST_REQUIRE(ok.has_value());
    BOOST_TEST((*ok)->key == k_key);
    BOOST_TEST(parse(good, false).error().code == "InvalidRequest");
    BOOST_TEST(
        parse({{p + "algorithm", "AES128"}, {p + "key", b64(k_key)}, {p + "key-MD5", md5(k_key)}})
            .error()
            .code == "InvalidEncryptionAlgorithmError");
    BOOST_TEST(parse({{p + "algorithm", "AES256"}, {p + "key-MD5", md5(k_key)}}).error().code ==
               "InvalidArgument");
    BOOST_TEST(
        parse(
            {{p + "algorithm", "AES256"}, {p + "key", b64("short")}, {p + "key-MD5", md5("short")}})
            .error()
            .code == "InvalidArgument");
    BOOST_TEST(
        parse({{p + "algorithm", "AES256"}, {p + "key", b64(k_key)}, {p + "key-MD5", md5("x")}})
            .error()
            .code == "InvalidArgument");
    BOOST_TEST(parse({{p + "key", b64(k_key)}}).error().code == "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(write_headers_and_bucket_defaults_make_a_plan) {
    const auto parse = [](s3::header_list h) { return s3::parse_sse_request(h, true); };
    BOOST_TEST((parse({}).value().kind == s3::sse_kind::none));
    BOOST_TEST(
        (parse({{"x-amz-server-side-encryption", "AES256"}}).value().kind == s3::sse_kind::s3));
    const auto kms =
        parse({{"x-amz-server-side-encryption", "aws:kms"},
               {"x-amz-server-side-encryption-aws-kms-key-id", "k1"},
               {"x-amz-server-side-encryption-bucket-key-enabled", "TRUE"},
               {"x-amz-server-side-encryption-context", s3::sse_detail::b64(R"({"a":"b"})")}});
    BOOST_TEST_REQUIRE(kms.has_value());
    BOOST_TEST(kms->kms_key_id == "k1");
    BOOST_TEST(kms->bucket_key.value());
    BOOST_TEST(kms->context.at("a") == "b");
    BOOST_TEST(
        parse({{"x-amz-server-side-encryption", "aws:kms"},
               {"x-amz-server-side-encryption-context", s3::sse_detail::b64(R"({"aws:x":"b"})")}})
            .error()
            .code == "InvalidArgument");
    BOOST_TEST(parse({{"x-amz-server-side-encryption", "aws:kms"},
                      {"x-amz-server-side-encryption-context", s3::sse_detail::b64(R"({"a":1})")}})
                   .error()
                   .code == "InvalidArgument");
    BOOST_TEST(parse({{"x-amz-server-side-encryption", "aws:kms:dsse"}}).error().status == 501U);
    BOOST_TEST(parse({{"x-amz-server-side-encryption-aws-kms-key-id", "k"}}).error().code ==
               "InvalidArgument");

    // Bucket defaults.
    const auto xml = s3::bucket_encryption_xml({s3::sse_kind::kms, "bk", true});
    const auto back = s3::parse_bucket_encryption(xml);
    BOOST_TEST_REQUIRE(back.has_value());
    BOOST_TEST((back->algorithm == s3::sse_kind::kms));
    BOOST_TEST(back->kms_key_id == "bk");
    BOOST_TEST(back->bucket_key);
    BOOST_TEST(!s3::parse_bucket_encryption("<ServerSideEncryptionConfiguration/>").has_value());

    // The request wins; an AES256 request ignores the bucket's KMS key.
    const s3::bucket_encryption bucket{s3::sse_kind::kms, "bk", true};
    auto plan = s3::plan_for(parse({}).value(), bucket);
    BOOST_TEST((plan.kind == s3::sse_kind::kms));
    BOOST_TEST(plan.kms_key_id == "bk");
    BOOST_TEST(plan.bucket_key);
    plan = s3::plan_for(parse({{"x-amz-server-side-encryption", "AES256"}}).value(), bucket);
    BOOST_TEST((plan.kind == s3::sse_kind::s3));
    plan = s3::plan_for(parse({{"x-amz-server-side-encryption", "aws:kms"}}).value(),
                        s3::bucket_encryption{});
    BOOST_TEST(plan.kms_key_id == "alias/aws/s3");
    BOOST_TEST(!plan.bucket_key);
}

BOOST_AUTO_TEST_CASE(object_keys_for_each_kind) {
    s3::sse_keys none;
    // No S3-managed provider: SSE-S3 objects are stored as they are.
    auto plain = none.seal(s3::sse_plan{}, "b", "k", k_owner);
    BOOST_TEST_REQUIRE(plain.has_value());
    BOOST_TEST(!plain->cipher.has_value());
    BOOST_TEST(plain->metadata.empty());
    s3::sse_plan kms_plan;
    kms_plan.kind = s3::sse_kind::kms;
    kms_plan.kms_key_id = "k";
    BOOST_TEST(none.seal(kms_plan, "b", "k", k_owner).error().code == "KMS.NotFoundException");

    s3::sse_keys keys;
    keys.s3_managed = s3::key_provider(s3::local_key_provider(test_secret(3)));
    keys.kms = s3::key_provider(s3::local_key_provider(test_secret(4)));
    auto now = std::chrono::steady_clock::time_point{};
    keys.clock = [&] { return now; };
    const auto round_trip = [&](const s3::sse_plan& plan,
                                const std::optional<s3::customer_key>& c = std::nullopt) {
        auto sealed = keys.seal(plan, "b", "k", k_owner);
        BOOST_TEST_REQUIRE(sealed.has_value());
        BOOST_TEST_REQUIRE(sealed->cipher.has_value());
        const auto data = bytes_of("object bytes");
        auto opened = keys.open(sealed->metadata, c, k_owner);
        BOOST_TEST_REQUIRE(opened.has_value());
        BOOST_TEST_REQUIRE(opened->has_value());
        BOOST_TEST(((*opened)->open(sealed->cipher->seal(data)).value() == data));
        return sealed->metadata;
    };
    const auto s3_meta = round_trip(s3::sse_plan{});
    BOOST_TEST(s3_meta.at("x-amz-server-side-encryption") == "AES256");
    BOOST_TEST((s3::stored_kind(s3_meta) == s3::sse_kind::s3));

    const auto kms_meta = round_trip(kms_plan);
    BOOST_TEST(kms_meta.at("x-amz-server-side-encryption-aws-kms-key-id") == "k");
    // SSE-KMS needs a signed caller, writing or reading.
    BOOST_TEST(keys.seal(kms_plan, "b", "k", s3::kms_caller{}).error().code == "InvalidArgument");
    BOOST_TEST(keys.open(kms_meta, std::nullopt, s3::kms_caller{}).error().code ==
               "InvalidArgument");

    // Bucket keys: one KMS call per lifetime.
    kms_plan.bucket_key = true;
    const auto before = keys.stats().kms_generate;
    const auto bk1 = round_trip(kms_plan);
    const auto bk2 = round_trip(kms_plan);
    BOOST_TEST(keys.stats().kms_generate == before + 1);
    BOOST_TEST(bk1.at("x-kythira-sse-bucket-key") == bk2.at("x-kythira-sse-bucket-key"));
    BOOST_TEST(bk1.at("x-kythira-sse-wrapped") != bk2.at("x-kythira-sse-wrapped"));
    now += keys.bucket_key_lifetime;
    const auto bk3 = round_trip(kms_plan);
    BOOST_TEST(keys.stats().kms_generate == before + 2);
    BOOST_TEST(bk3.at("x-kythira-sse-bucket-key") != bk1.at("x-kythira-sse-bucket-key"));

    // SSE-C: the key opens, nothing else does, and it is not stored.
    s3::sse_plan c_plan;
    c_plan.kind = s3::sse_kind::customer;
    c_plan.customer = s3::customer_key{k_key, "md5"};
    const auto c_meta = round_trip(c_plan, c_plan.customer);
    for (const auto& [k, v] : c_meta) {
        BOOST_TEST(v.find(k_key) == std::string::npos, k);
        BOOST_TEST(v.find(s3::sse_detail::b64(k_key)) == std::string::npos, k);
    }
    BOOST_TEST(keys.open(c_meta, std::nullopt, k_owner).error().code == "InvalidRequest");
    BOOST_TEST(
        keys.open(c_meta, s3::customer_key{std::string(32, 'x'), "m"}, k_owner).error().status ==
        403U);
    BOOST_TEST(keys.open(s3_meta, c_plan.customer, k_owner).error().code == "InvalidRequest");
    // An object stored before encryption opens without a cipher.
    BOOST_TEST(!keys.open({}, std::nullopt, k_owner).value().has_value());
}

BOOST_AUTO_TEST_CASE(kms_failures_map_to_s3_errors) {
    using f = s3::kms_failure;
    BOOST_TEST(s3::from_kms(s3::kms_error(f::not_found, "x")).code == "KMS.NotFoundException");
    BOOST_TEST(s3::from_kms(s3::kms_error(f::disabled, "x")).code == "KMS.DisabledException");
    BOOST_TEST(s3::from_kms(s3::kms_error(f::invalid_state, "x")).code ==
               "KMS.KMSInvalidStateException");
    BOOST_TEST(s3::from_kms(s3::kms_error(f::access_denied, "x")).status == 403U);
    BOOST_TEST(s3::from_kms(s3::kms_error(f::unavailable, "x")).status == 503U);
}

BOOST_AUTO_TEST_CASE(the_kms_api_provider_speaks_the_kms_json_protocol) {
    std::vector<std::pair<std::string, std::string>> sent;
    const std::string key(32, 'd');
    s3::kms_answer next;
    s3::kms_api_provider p(
        [&](const std::string& op, const std::string& body, const s3::kms_caller& who) {
            BOOST_TEST(who.principal->arn == k_owner.principal->arn);
            sent.emplace_back(op, body);
            return next;
        });
    next = {200, R"({"KeyId":"arn:aws:kms:us-east-1:111122223333:key/k1","Plaintext":")" +
                     s3::sse_detail::b64(key) + R"(","CiphertextBlob":")" +
                     s3::sse_detail::b64("wrapped") + R"("})"};
    const s3::encryption_context ctx{{"aws:s3:arn", "arn:aws:s3:::b/k"}};
    const auto k = p.generate_data_key("alias/aws/s3", ctx, k_owner);
    BOOST_TEST(k.plaintext == key);
    BOOST_TEST(k.wrapped == "wrapped");
    BOOST_TEST(k.key_id == "arn:aws:kms:us-east-1:111122223333:key/k1");
    BOOST_TEST(sent.back().first == "GenerateDataKey");
    BOOST_TEST(sent.back().second == R"({"KeyId":"alias/aws/s3","KeySpec":"AES_256",)"
                                     R"("EncryptionContext":{"aws:s3:arn":"arn:aws:s3:::b/k"}})");

    next = {200, R"({"Plaintext":")" + s3::sse_detail::b64(key) + R"("})"};
    BOOST_TEST(p.decrypt_data_key(k.key_id, k.wrapped, ctx, k_owner) == key);
    BOOST_TEST(sent.back().first == "Decrypt");
    BOOST_TEST(sent.back().second.find(s3::sse_detail::b64("wrapped")) != std::string::npos);

    const auto failure = [&](s3::kms_answer a) {
        next = std::move(a);
        try {
            (void)p.generate_data_key("k", ctx, k_owner);
        } catch (const s3::kms_error& e) {
            return e.failure();
        }
        BOOST_FAIL("no error");
        return s3::kms_failure::unavailable;
    };
    BOOST_TEST((failure({400, R"({"__type":"NotFoundException","message":"no key"})"}) ==
                s3::kms_failure::not_found));
    BOOST_TEST((failure({400, R"({"__type":"com.amazonaws.kms#DisabledException"})"}) ==
                s3::kms_failure::disabled));
    BOOST_TEST((failure({400, R"({"__type":"AccessDeniedException"})"}) ==
                s3::kms_failure::access_denied));
    BOOST_TEST((failure({500, "oops"}) == s3::kms_failure::unavailable));
    BOOST_TEST((failure({200, R"({"Plaintext":"c2hvcnQ="})"}) == s3::kms_failure::unavailable));
}
