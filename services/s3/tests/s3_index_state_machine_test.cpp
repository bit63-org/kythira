// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_index_state_machine_test.cpp
/// @brief The object index (`s3_index_state_machine.hpp`;
///        .kiro/specs/s3-compatible-storage/ task 4, Requirements 6.3, 7.2,
///        7.3, 8.1, 10.2 and 10.3): buckets, the three versioning states,
///        conditions in apply, copies, multipart uploads, listings and
///        reference counts with their grace period; then randomized runs
///        that check replicas agree, a snapshot restores to the same state,
///        and every reference count equals a recount of the manifests.

#define BOOST_TEST_MODULE s3_index_state_machine_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_index_state_machine.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using namespace kythira::s3;
using kythira::chunk_sha;
using kythira::key_range;
using kythira::memory_kv_engine;
using kind = index_command::kind;

using index_sm = s3_index_state_machine<>;

const key_range everything{"", std::nullopt};

auto sha_of(int n) -> chunk_sha {
    const std::string s = "chunk-" + std::to_string(n);
    return kythira::sha256_of(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size()));
}

auto content_of(std::vector<int> chunks, std::string etag = "e") -> object_content {
    object_content c;
    for (const int n : chunks) {
        c.manifest.push_back({sha_of(n), 100});
    }
    c.etag = std::move(etag);
    c.content_type = "text/plain";
    return c;
}

/// One replica: an engine and the state machine over all of it.
struct replica {
    memory_kv_engine engine;
    index_sm sm;
    std::uint64_t index = 0;
    std::uint64_t now = 1'000'000;

    explicit replica(index_options o = {.min_part_bytes = 0, .max_parts = 10'000}) : sm(o) {
        sm.open(engine, everything);
    }

    auto apply(index_command c) -> index_result {
        c.now_ms = c.now_ms != 0 ? c.now_ms : ++now;
        return codec::decode_result(sm.apply(codec::encode(c), ++index));
    }

    auto create(const std::string& name, const std::string& owner = "acct",
                const std::string& region = "us-west-2", bool lock = false) -> index_result {
        index_command c;
        c.op = kind::create_bucket;
        c.bucket = name;
        c.owner = owner;
        c.region = region;
        c.object_lock = lock;
        return apply(c);
    }

    auto ref(const std::string& name) -> bucket_ref {
        const auto b = sm.bucket(name).value();
        return {b.id, b.versioning, b.object_lock};
    }

    auto config(const std::string& name, const std::string& what, std::optional<std::string> doc)
        -> index_result {
        index_command c;
        c.op = kind::put_bucket_config;
        c.bucket = name;
        c.config_name = what;
        c.document = std::move(doc);
        return apply(c);
    }

    auto put(const std::string& bucket, const std::string& key, object_content content,
             write_conditions w = {}) -> index_result {
        index_command c;
        c.op = kind::put_object;
        c.target = ref(bucket);
        c.key = key;
        c.owner = "acct";
        c.content = std::move(content);
        c.conditions = std::move(w);
        return apply(c);
    }

    auto del(const std::string& bucket, const std::string& key,
             std::optional<std::string> version = std::nullopt) -> index_result {
        index_command c;
        c.op = kind::delete_object;
        c.target = ref(bucket);
        c.key = key;
        c.version_id = std::move(version);
        return apply(c);
    }

    [[nodiscard]] auto count(int chunk) const -> std::uint64_t {
        const auto r = sm.refcount(sha_of(chunk));
        return r ? r->count : 0;
    }
};

struct temp_dir {
    fs::path path;
    temp_dir() {
        static std::atomic<int> n{0};
        path = fs::temp_directory_path() /
               ("s3_index_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    auto operator=(const temp_dir&) -> temp_dir& = delete;
    temp_dir(temp_dir&&) = delete;
    auto operator=(temp_dir&&) -> temp_dir& = delete;
};

}  // namespace

// ---- records and commands ---------------------------------------------------

BOOST_AUTO_TEST_CASE(records_and_commands_round_trip) {
    bucket_descriptor b{"photos", 7,
                        "acct",   "eu-west-1",
                        42,       versioning_state::suspended,
                        true,     {{"policy", "{}"}, {"cors", "<CORSConfiguration/>"}}};
    BOOST_TEST((codec::decode_bucket(codec::encode(b)) == b));

    object_version v;
    v.key = "a/b";
    v.stamp = 99;
    v.last_modified_ms = 5;
    v.owner = "acct";
    v.content = content_of({1, 2, 1}, "abc");
    v.content.user_metadata = {{"color", "blue"}};
    v.content.system_metadata = {{"x-amz-checksum-crc32", "AAAAAA=="}};
    v.content.part_sizes = {100, 200};
    BOOST_TEST((codec::decode_version(codec::encode(v)) == v));

    upload_record u;
    u.key = "k";
    u.stamp = 3;
    u.content = content_of({});
    u.parts[2] = part_record{2, "p2", 9, content_of({4}).manifest, {{"crc32", "x"}}};
    BOOST_TEST((codec::decode_upload(codec::encode(u)) == u));

    index_command c;
    c.op = kind::complete_upload;
    c.now_ms = 1;
    c.target = {3, versioning_state::enabled, false};
    c.key = "k";
    c.upload_id = stamp_id(3);
    c.parts = {{1, "a"}, {2, "b"}};
    c.conditions.if_match = "\"e\"";
    c.source_if.if_modified_since_ms = 77;
    c.document = "doc";
    BOOST_TEST((codec::decode_command(codec::encode(c)) == c));

    index_result r;
    r.error = "NoSuchKey";
    r.status = 404;
    r.collected = {sha_of(1), sha_of(2)};
    BOOST_TEST((codec::decode_result(codec::encode(r)) == r));

    auto bytes = codec::encode(v);
    bytes.pop_back();
    BOOST_CHECK_THROW(codec::decode_version(bytes), index_format_error);
    BOOST_CHECK_THROW(codec::decode_version("\x09"), index_format_error);
    BOOST_TEST(stamp_id(0xabcdef) == "0000000000abcdef");
    BOOST_TEST(*parse_stamp_id("0000000000abcdef") == 0xabcdefU);
    BOOST_TEST(!parse_stamp_id("null").has_value());
    BOOST_TEST(!parse_stamp_id("0000000000ABCDEF").has_value());
}

// ---- buckets ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bucket_ids_are_never_reused_and_names_are_unique) {
    replica r;
    BOOST_TEST(r.create("photos").bucket_id == 1U);
    BOOST_TEST(r.create("photos").error == "BucketAlreadyOwnedByYou");
    BOOST_TEST(r.create("photos", "other").error == "BucketAlreadyExists");
    BOOST_TEST(r.create("photos", "other").status == 409U);
    BOOST_TEST(r.create("logs", "other").bucket_id == 2U);

    index_command del;
    del.op = kind::delete_bucket;
    del.bucket = "photos";
    BOOST_TEST(r.apply(del).ok());
    BOOST_TEST(r.apply(del).error == "NoSuchBucket");
    // A recreated bucket gets a new id, so it sees none of the old objects.
    BOOST_TEST(r.create("photos").bucket_id == 3U);

    BOOST_TEST(r.sm.list_buckets().size() == 2U);
    BOOST_TEST(r.sm.list_buckets("other").size() == 1U);
    BOOST_TEST(r.sm.list_buckets("other").at(0).name == "logs");
}

BOOST_AUTO_TEST_CASE(us_east_1_answers_a_repeated_create_by_the_owner_with_success) {
    replica r;
    const auto first = r.create("rc", "acct", "us-east-1");
    const auto again = r.create("rc", "acct", "us-east-1");
    BOOST_TEST(again.ok());
    BOOST_TEST(again.bucket_id == first.bucket_id);
    BOOST_TEST(r.create("rc", "someone", "us-east-1").error == "BucketAlreadyExists");
}

BOOST_AUTO_TEST_CASE(only_empty_buckets_are_deleted) {
    replica r;
    r.create("b1");
    r.put("b1", "k", content_of({1}));
    index_command del;
    del.op = kind::delete_bucket;
    del.bucket = "b1";
    BOOST_TEST(r.apply(del).error == "BucketNotEmpty");
    r.del("b1", "k");
    // An upload in progress keeps the bucket too.
    index_command up;
    up.op = kind::create_upload;
    up.target = r.ref("b1");
    up.key = "big";
    const auto id = r.apply(up).upload_id;
    BOOST_TEST(r.apply(del).error == "BucketNotEmpty");
    index_command abort;
    abort.op = kind::abort_upload;
    abort.target = r.ref("b1");
    abort.key = "big";
    abort.upload_id = id;
    BOOST_TEST(r.apply(abort).ok());
    BOOST_TEST(r.apply(del).ok());
}

BOOST_AUTO_TEST_CASE(bucket_configuration_versioning_and_object_lock) {
    replica r;
    r.create("b1");
    BOOST_TEST(r.config("b1", "versioning", "Sometimes").error ==
               "IllegalVersioningConfigurationException");
    BOOST_TEST(r.config("b1", "object-lock", "<ObjectLockConfiguration/>").error ==
               "InvalidBucketState");
    BOOST_TEST(r.config("b1", "versioning", "Enabled").ok());
    BOOST_TEST((r.sm.bucket("b1")->versioning == versioning_state::enabled));
    BOOST_TEST(r.config("b1", "versioning", "Suspended").ok());
    BOOST_TEST((r.sm.bucket("b1")->versioning == versioning_state::suspended));
    BOOST_TEST(r.config("b1", "cors", "<CORSConfiguration/>").ok());
    BOOST_TEST(r.sm.bucket("b1")->config.at("cors") == "<CORSConfiguration/>");
    BOOST_TEST(r.config("b1", "cors", std::nullopt).ok());
    BOOST_TEST(!r.sm.bucket("b1")->config.contains("cors"));
    BOOST_TEST(r.config("nope", "cors", "x").error == "NoSuchBucket");

    r.create("locked", "acct", "us-west-2", true);
    const auto locked = r.sm.bucket("locked").value();
    BOOST_TEST(locked.object_lock);
    BOOST_TEST((locked.versioning == versioning_state::enabled));
    BOOST_TEST(r.config("locked", "versioning", "Suspended").error == "InvalidBucketState");
}

// ---- versions ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(an_unversioned_bucket_keeps_one_null_version) {
    replica r;
    r.create("b1");
    const auto first = r.put("b1", "k", content_of({1, 2}, "e1"));
    BOOST_TEST(first.version_id == "null");
    BOOST_TEST(r.count(1) == 1U);
    r.put("b1", "k", content_of({2, 3}, "e2"));
    BOOST_TEST(r.count(1) == 0U);  // the old version is gone
    BOOST_TEST(r.count(2) == 1U);
    BOOST_TEST(r.count(3) == 1U);
    BOOST_TEST(r.sm.version(r.ref("b1").id, "k")->content.etag == "e2");
    BOOST_TEST(r.sm.list_versions(r.ref("b1").id, "", "", "", "", 100).versions.size() == 1U);

    const auto d = r.del("b1", "k");
    BOOST_TEST(d.ok());
    BOOST_TEST(!d.delete_marker);
    BOOST_TEST(!r.sm.version(r.ref("b1").id, "k").has_value());
    BOOST_TEST(r.count(2) == 0U);
    // Deleting what is not there succeeds, as on S3.
    BOOST_TEST(r.del("b1", "k").ok());
}

BOOST_AUTO_TEST_CASE(an_enabled_bucket_keeps_every_version_and_writes_delete_markers) {
    replica r;
    r.create("b1");
    r.config("b1", "versioning", "Enabled");
    const auto id = r.ref("b1").id;
    const auto v1 = r.put("b1", "k", content_of({1}, "e1"));
    const auto v2 = r.put("b1", "k", content_of({2}, "e2"));
    BOOST_TEST(v1.version_id != "null");
    BOOST_TEST(v1.version_id != v2.version_id);
    BOOST_TEST(r.count(1) == 1U);  // still referenced by v1
    BOOST_TEST(r.sm.version(id, "k")->content.etag == "e2");
    BOOST_TEST(r.sm.version(id, "k", v1.version_id)->content.etag == "e1");

    const auto marker = r.del("b1", "k");
    BOOST_TEST(marker.delete_marker);
    BOOST_TEST(marker.version_id != "null");
    BOOST_TEST(r.sm.version(id, "k")->delete_marker);
    BOOST_TEST(r.sm.list_objects(id, "", "", "", 100).contents.empty());

    const auto listing = r.sm.list_versions(id, "", "", "", "", 100);
    BOOST_REQUIRE(listing.versions.size() == 3U);
    BOOST_TEST(listing.versions[0].version.delete_marker);
    BOOST_TEST(listing.versions[0].is_latest);
    BOOST_TEST(listing.versions[1].version.version_id() == v2.version_id);
    BOOST_TEST(!listing.versions[1].is_latest);
    BOOST_TEST(listing.versions[2].version.version_id() == v1.version_id);

    // Removing the delete marker by id brings the object back.
    const auto undo = r.del("b1", "k", marker.version_id);
    BOOST_TEST(undo.delete_marker);
    BOOST_TEST(r.sm.version(id, "k")->content.etag == "e2");
    // Removing a version by id releases its chunks.
    r.del("b1", "k", v1.version_id);
    BOOST_TEST(r.count(1) == 0U);
    BOOST_TEST(r.del("b1", "k", "not-a-version").error == "InvalidArgument");
    BOOST_TEST(r.del("b1", "k", "00000000000000ff").ok());  // unknown: still 204
}

BOOST_AUTO_TEST_CASE(a_suspended_bucket_replaces_only_the_null_version) {
    replica r;
    r.create("b1");
    r.put("b1", "k", content_of({1}, "null-before"));  // the null version
    r.config("b1", "versioning", "Enabled");
    const auto v = r.put("b1", "k", content_of({2}, "versioned"));
    r.config("b1", "versioning", "Suspended");
    const auto s = r.put("b1", "k", content_of({3}, "null-after"));
    BOOST_TEST(s.version_id == "null");
    const auto id = r.ref("b1").id;
    BOOST_TEST(r.count(1) == 0U);  // the first null version was replaced
    BOOST_TEST(r.count(2) == 1U);
    BOOST_TEST(r.sm.version(id, "k", v.version_id)->content.etag == "versioned");
    BOOST_TEST(r.sm.version(id, "k", std::string("null"))->content.etag == "null-after");

    // A delete writes a null delete marker in place of the null version.
    const auto d = r.del("b1", "k");
    BOOST_TEST(d.delete_marker);
    BOOST_TEST(d.version_id == "null");
    BOOST_TEST(r.count(3) == 0U);
    const auto listing = r.sm.list_versions(id, "", "", "", "", 100);
    BOOST_REQUIRE(listing.versions.size() == 2U);
    BOOST_TEST(listing.versions[0].version.delete_marker);
    BOOST_TEST(listing.versions[0].version.null_version);
    BOOST_TEST(listing.versions[1].version.version_id() == v.version_id);
}

// ---- conditions in apply ----------------------------------------------------

BOOST_AUTO_TEST_CASE(conditional_writes_are_decided_when_the_entry_applies) {
    replica r;
    r.create("b1");
    r.config("b1", "versioning", "Enabled");
    write_conditions create_only;
    create_only.if_none_match_star = true;
    BOOST_TEST(r.put("b1", "k", content_of({1}, "e1"), create_only).ok());
    // The second of two racing create-only writes loses, and writes nothing.
    const auto lost = r.put("b1", "k", content_of({2}, "e2"), create_only);
    BOOST_TEST(lost.error == "PreconditionFailed");
    BOOST_TEST(lost.status == 412U);
    BOOST_TEST(r.count(2) == 0U);

    write_conditions match;
    match.if_match = "\"e1\"";
    BOOST_TEST(r.put("b1", "k", content_of({3}, "e3"), match).ok());
    BOOST_TEST(r.put("b1", "k", content_of({4}, "e4"), match).error == "PreconditionFailed");
    match.if_match = "*";
    BOOST_TEST(r.put("b1", "k", content_of({4}, "e4"), match).ok());
    BOOST_TEST(r.put("b1", "missing", content_of({4}), match).error == "NoSuchKey");

    // A delete marker does not count as an object.
    r.del("b1", "k");
    BOOST_TEST(r.put("b1", "k", content_of({5}, "e5"), create_only).ok());
}

// ---- copies -----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_copy_reuses_the_manifest_and_checks_source_conditions) {
    replica r;
    r.create("b1");
    auto src = content_of({1, 2}, "srcetag");
    src.user_metadata = {{"a", "1"}};
    r.put("b1", "src", src);
    const auto modified = r.now;

    const auto when = [](std::optional<std::string> m, std::optional<std::string> nm,
                         std::optional<std::uint64_t> since, std::optional<std::uint64_t> until) {
        return source_conditions{std::move(m), std::move(nm), since, until};
    };
    auto copy = [&](source_conditions sc, bool replace = false,
                    std::string dest = "dst") -> index_result {
        index_command c;
        c.op = kind::copy_object;
        c.target = r.ref("b1");
        c.source = r.ref("b1");
        c.key = std::move(dest);
        c.source_key = "src";
        c.source_if = std::move(sc);
        c.replace_metadata = replace;
        c.content.user_metadata = {{"b", "2"}};
        c.content.content_type = "image/png";
        return r.apply(c);
    };

    BOOST_TEST(copy({}).ok());
    BOOST_TEST(r.count(1) == 2U);  // two manifests name it, one stored copy
    const auto id = r.ref("b1").id;
    BOOST_TEST(r.sm.version(id, "dst")->content.user_metadata.at("a") == "1");
    BOOST_TEST(r.sm.version(id, "dst")->content.etag == "srcetag");

    BOOST_TEST(copy({}, true).ok());
    BOOST_TEST(r.sm.version(id, "dst")->content.user_metadata.count("a") == 0U);
    BOOST_TEST(r.sm.version(id, "dst")->content.content_type == "image/png");

    BOOST_TEST(copy(when("\"other\"", {}, {}, {})).error == "PreconditionFailed");
    BOOST_TEST(copy(when({}, "srcetag", {}, {})).error == "PreconditionFailed");
    BOOST_TEST(copy(when({}, {}, modified, {})).error == "PreconditionFailed");
    BOOST_TEST(copy(when({}, {}, {}, modified - 1)).error == "PreconditionFailed");
    // S3's pairings: a true if-match overrides a false if-unmodified-since.
    BOOST_TEST(copy(when("srcetag", {}, {}, modified - 1)).ok());
    // A false if-none-match fails even with a true if-modified-since.
    BOOST_TEST(copy(when({}, "srcetag", modified - 1, {})).error == "PreconditionFailed");

    BOOST_TEST(copy({}, false, "src").error == "InvalidRequest");  // onto itself, unchanged
    BOOST_TEST(copy({}, true, "src").ok());

    index_command missing;
    missing.op = kind::copy_object;
    missing.target = r.ref("b1");
    missing.source = r.ref("b1");
    missing.key = "x";
    missing.source_key = "nope";
    BOOST_TEST(r.apply(missing).error == "NoSuchKey");
}

BOOST_AUTO_TEST_CASE(a_copy_of_a_delete_marker_version_is_refused) {
    replica r;
    r.create("b1");
    r.config("b1", "versioning", "Enabled");
    r.put("b1", "src", content_of({1}));
    const auto marker = r.del("b1", "src");
    index_command c;
    c.op = kind::copy_object;
    c.target = r.ref("b1");
    c.source = r.ref("b1");
    c.key = "dst";
    c.source_key = "src";
    BOOST_TEST(r.apply(c).error == "NoSuchKey");
    c.version_id = marker.version_id;
    BOOST_TEST(r.apply(c).error == "InvalidRequest");
}

// ---- multipart uploads ------------------------------------------------------

BOOST_AUTO_TEST_CASE(multipart_upload_complete_and_abort) {
    replica r(index_options{.min_part_bytes = 150, .max_parts = 10'000});
    r.create("b1");
    const auto b = r.ref("b1");
    index_command create;
    create.op = kind::create_upload;
    create.target = b;
    create.key = "big";
    create.owner = "acct";
    create.content = content_of({});
    create.content.user_metadata = {{"m", "v"}};
    const auto upload_id = r.apply(create).upload_id;
    BOOST_TEST(upload_id.size() == 16U);

    auto part = [&](std::uint32_t n, std::vector<int> chunks, std::string etag) {
        index_command c;
        c.op = kind::upload_part;
        c.target = b;
        c.key = "big";
        c.upload_id = upload_id;
        c.part.number = n;
        c.part.etag = std::move(etag);
        c.part.manifest = content_of(std::move(chunks)).manifest;
        return r.apply(c);
    };
    const std::string md5a = "0123456789abcdef0123456789abcdef";
    const std::string md5b = "fedcba9876543210fedcba9876543210";
    BOOST_TEST(part(1, {1, 2}, "old").ok());
    BOOST_TEST(part(1, {3, 4}, md5a).ok());  // replaces part 1
    BOOST_TEST(r.count(1) == 0U);
    BOOST_TEST(part(2, {5}, md5b).ok());
    BOOST_TEST(part(3, {6}, "unused").ok());
    BOOST_TEST(part(0, {6}, "x").error == "InvalidArgument");
    BOOST_TEST(r.count(6) == 1U);

    auto complete = [&](std::vector<completed_part> parts) {
        index_command c;
        c.op = kind::complete_upload;
        c.target = b;
        c.key = "big";
        c.upload_id = upload_id;
        c.parts = std::move(parts);
        return r.apply(c);
    };
    BOOST_TEST(complete({}).error == "MalformedXML");
    BOOST_TEST(complete({{2, md5b}, {1, md5a}}).error == "InvalidPartOrder");
    BOOST_TEST(complete({{1, md5a}, {2, "wrong"}}).error == "InvalidPart");
    BOOST_TEST(complete({{1, md5a}, {4, "x"}}).error == "InvalidPart");
    // Part 2 (100 bytes) is under the minimum and not last.
    BOOST_TEST(complete({{2, md5b}, {3, "unused"}}).error == "EntityTooSmall");
    BOOST_TEST(r.sm.upload(b.id, "big", upload_id).has_value());

    const auto done = complete({{1, "\"" + md5a + "\""}, {2, md5b}});
    BOOST_REQUIRE(done.ok());
    BOOST_TEST(done.etag.ends_with("-2"));
    BOOST_TEST(done.etag.size() == 34U);
    const auto v = r.sm.version(b.id, "big").value();
    BOOST_TEST(v.content.manifest.size() == 3U);
    BOOST_TEST(v.content.size() == 300U);
    BOOST_TEST((v.content.part_sizes == std::vector<std::uint64_t>{200, 100}));
    BOOST_TEST(v.content.user_metadata.at("m") == "v");
    BOOST_TEST(r.count(3) == 1U);
    BOOST_TEST(r.count(5) == 1U);
    BOOST_TEST(r.count(6) == 0U);  // the part left out
    BOOST_TEST(!r.sm.upload(b.id, "big", upload_id).has_value());
    BOOST_TEST(complete({{1, md5a}}).error == "NoSuchUpload");

    // Abort releases every part.
    const auto second = r.apply(create).upload_id;
    BOOST_TEST(second != upload_id);
    index_command p;
    p.op = kind::upload_part;
    p.target = b;
    p.key = "big";
    p.upload_id = second;
    p.part.number = 1;
    p.part.etag = "x";
    p.part.manifest = content_of({7}).manifest;
    r.apply(p);
    BOOST_TEST(r.count(7) == 1U);
    BOOST_TEST(r.sm.list_uploads(b.id, "", "", "", 10).first.size() == 1U);
    index_command abort;
    abort.op = kind::abort_upload;
    abort.target = b;
    abort.key = "big";
    abort.upload_id = second;
    BOOST_TEST(r.apply(abort).ok());
    BOOST_TEST(r.count(7) == 0U);
    BOOST_TEST(r.apply(abort).error == "NoSuchUpload");
}

BOOST_AUTO_TEST_CASE(the_multipart_etag_is_s3s) {
    // Two parts with known MD5s; S3's ETag is MD5(md5a || md5b) + "-2".
    replica r;
    r.create("b1");
    const auto b = r.ref("b1");
    index_command create;
    create.op = kind::create_upload;
    create.target = b;
    create.key = "k";
    const auto id = r.apply(create).upload_id;
    // MD5("a") and MD5("b").
    const std::string a = "0cc175b9c0f1b6a831c399e269772661";
    const std::string bb = "92eb5ffee6ae2fec3ad71c777531578f";
    for (std::uint32_t n : {1U, 2U}) {
        index_command p;
        p.op = kind::upload_part;
        p.target = b;
        p.key = "k";
        p.upload_id = id;
        p.part.number = n;
        p.part.etag = n == 1 ? a : bb;
        r.apply(p);
    }
    index_command c;
    c.op = kind::complete_upload;
    c.target = b;
    c.key = "k";
    c.upload_id = id;
    c.parts = {{1, a}, {2, bb}};
    // md5(bytes.fromhex(a) + bytes.fromhex(bb)).hexdigest() + "-2"
    BOOST_TEST(r.apply(c).etag == "96e024ba2074fe77e8e965ba43a704be-2");
}

// ---- listings ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(listings_roll_up_prefixes_skip_delete_markers_and_paginate) {
    replica r;
    r.create("b1");
    r.config("b1", "versioning", "Enabled");
    for (const auto* k : {"a.txt", "dir/1", "dir/2", "dir/sub/3", "e.txt", "f/x", "g.txt"}) {
        r.put("b1", k, content_of({1}));
    }
    r.del("b1", "e.txt");  // a delete marker hides it
    const auto id = r.ref("b1").id;

    auto all = r.sm.list_objects(id, "", "", "", 1000);
    std::vector<std::string> keys;
    for (const auto& v : all.contents) {
        keys.push_back(v.key);
    }
    BOOST_TEST(
        (keys == std::vector<std::string>{"a.txt", "dir/1", "dir/2", "dir/sub/3", "f/x", "g.txt"}));
    BOOST_TEST(!all.truncated);

    auto rolled = r.sm.list_objects(id, "", "/", "", 1000);
    BOOST_TEST((rolled.common_prefixes == std::vector<std::string>{"dir/", "f/"}));
    BOOST_TEST(rolled.contents.size() == 2U);  // a.txt, g.txt

    auto in_dir = r.sm.list_objects(id, "dir/", "/", "", 1000);
    BOOST_TEST((in_dir.common_prefixes == std::vector<std::string>{"dir/sub/"}));
    BOOST_TEST(in_dir.contents.size() == 2U);

    // Pages of two items, prefixes counting as items, resuming at the marker.
    std::vector<std::string> seen;
    std::string marker;
    int pages = 0;
    while (true) {
        auto page = r.sm.list_objects(id, "", "/", marker, 2);
        ++pages;
        for (const auto& v : page.contents) {
            seen.push_back(v.key);
        }
        for (const auto& p : page.common_prefixes) {
            seen.push_back(p);
        }
        if (!page.truncated) {
            break;
        }
        marker = page.next_marker;
    }
    std::sort(seen.begin(), seen.end());
    BOOST_TEST((seen == std::vector<std::string>{"a.txt", "dir/", "f/", "g.txt"}));
    BOOST_TEST(pages == 2);

    // A marker inside a common prefix does not return that prefix again.
    auto after = r.sm.list_objects(id, "", "/", "dir/1", 1000);
    BOOST_TEST((after.common_prefixes == std::vector<std::string>{"f/"}));

    // Version listing pages through versions of one key.
    r.put("b1", "a.txt", content_of({2}));
    r.put("b1", "a.txt", content_of({3}));
    auto v1 = r.sm.list_versions(id, "a.txt", "", "", "", 2);
    BOOST_TEST(v1.truncated);
    BOOST_TEST(v1.versions.size() == 2U);
    BOOST_TEST(v1.versions[0].is_latest);
    auto v2 = r.sm.list_versions(id, "a.txt", "", v1.next_key_marker, v1.next_version_id_marker, 2);
    BOOST_TEST(!v2.truncated);
    BOOST_REQUIRE(v2.versions.size() == 1U);
    BOOST_TEST(!v2.versions[0].is_latest);
}

// ---- reference counts -------------------------------------------------------

BOOST_AUTO_TEST_CASE(unreferenced_chunks_are_collected_only_after_the_grace_period) {
    replica r;
    r.create("b1");
    r.put("b1", "k", content_of({1, 2}));
    r.del("b1", "k");
    const auto zeroed_at = r.now;
    BOOST_TEST(r.count(1) == 0U);

    index_command gc;
    gc.op = kind::collect_chunks;
    gc.grace_ms = 60'000;
    gc.max = 100;
    gc.now_ms = zeroed_at + 59'999;
    BOOST_TEST(r.apply(gc).collected.empty());

    // A PUT of the same bytes inside the grace period keeps chunk 2.
    r.now = zeroed_at + 10;
    r.put("b1", "k2", content_of({2}));
    gc.now_ms = zeroed_at + 60'000;
    const auto collected = r.apply(gc).collected;
    BOOST_REQUIRE(collected.size() == 1U);
    BOOST_TEST((collected[0] == sha_of(1)));
    BOOST_TEST(!r.sm.refcount(sha_of(1)).has_value());
    BOOST_TEST(r.count(2) == 1U);
    BOOST_TEST(r.apply(gc).collected.empty());

    // `max` bounds one entry's work.
    for (int i = 10; i < 15; ++i) {
        r.put("b1", "t" + std::to_string(i), content_of({i}));
        r.del("b1", "t" + std::to_string(i));
    }
    gc.now_ms = r.now + 60'000;
    gc.max = 3;
    BOOST_TEST(r.apply(gc).collected.size() == 3U);
    BOOST_TEST(r.apply(gc).collected.size() == 2U);
}

BOOST_AUTO_TEST_CASE(a_manifest_naming_a_chunk_twice_counts_it_twice) {
    replica r;
    r.create("b1");
    r.put("b1", "k", content_of({1, 1, 1}));
    BOOST_TEST(r.count(1) == 3U);
    r.del("b1", "k");
    BOOST_TEST(r.count(1) == 0U);
}

// ---- entries ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(failed_entries_change_nothing_but_the_applied_index) {
    replica r;
    r.create("b1");
    const auto before = r.sm.dump();
    write_conditions w;
    w.if_match = "nope";
    BOOST_TEST(!r.put("b1", "k", content_of({1}), w).ok());
    BOOST_TEST((r.sm.dump() == before));
    BOOST_TEST(r.sm.applied_index() == r.index);

    // A replayed entry is ignored.
    index_command c;
    c.op = kind::create_bucket;
    c.bucket = "b2";
    c.owner = "acct";
    BOOST_TEST(r.sm.apply(codec::encode(c), r.index).empty());
    BOOST_TEST(!r.sm.bucket("b2").has_value());
}

BOOST_AUTO_TEST_CASE(an_entry_writing_outside_the_group_is_refused_whole) {
    memory_kv_engine engine;
    index_sm sm;
    // A group holding only the catalog.
    sm.open(engine, key_range{std::string(keys::catalog_prefix),
                              keys::prefix_end(std::string(keys::catalog_prefix))});
    index_command create;
    create.op = kind::create_bucket;
    create.bucket = "b1";
    create.owner = "acct";
    BOOST_TEST(codec::decode_result(sm.apply(codec::encode(create), 1)).ok());
    index_command put;
    put.op = kind::put_object;
    put.target = {1, versioning_state::unversioned, false};
    put.key = "k";
    put.content = content_of({1});
    const auto r = codec::decode_result(sm.apply(codec::encode(put), 2));
    BOOST_TEST(r.error == "InternalError");
    BOOST_TEST(sm.applied_index() == 2U);
    BOOST_TEST(sm.dump().size() == 2U);  // the bucket and the id counter
}

BOOST_AUTO_TEST_CASE(state_survives_reopening_the_engine) {
    replica r;
    r.create("b1");
    r.put("b1", "k", content_of({1}));
    index_sm reopened;
    reopened.open(r.engine, everything);
    BOOST_TEST(reopened.applied_index() == r.index);
    BOOST_TEST(reopened.version(r.ref("b1").id, "k").has_value());
}

// ---- properties -------------------------------------------------------------

namespace {

/// Proposes random commands the way a front end would: reading bucket
/// settings from the catalog, picking versions and uploads that exist.
class workload {
public:
    explicit workload(std::uint32_t seed) : _rng(seed) {}

    auto next(const index_sm& sm, std::uint64_t now) -> index_command {
        index_command c;
        c.now_ms = now;
        c.owner = "acct";
        const auto buckets = sm.list_buckets();
        if (buckets.empty() || pick(20) == 0) {
            c.op = kind::create_bucket;
            c.bucket = "bucket-" + std::to_string(pick(3));
            c.region = "us-west-2";
            return c;
        }
        const auto& b = buckets[pick(buckets.size())];
        c.bucket = b.name;
        c.target = {b.id, b.versioning, b.object_lock};
        c.key = "key-" + std::to_string(pick(4));
        switch (pick(12)) {
            case 0:
                c.op = kind::put_bucket_config;
                c.config_name = "versioning";
                c.document = pick(2) == 0 ? "Enabled" : "Suspended";
                return c;
            case 1:
            case 2:
            case 3:
                c.op = kind::put_object;
                c.content = random_content();
                if (pick(5) == 0) {
                    c.conditions.if_none_match_star = true;
                }
                return c;
            case 4:
            case 5: {
                c.op = kind::delete_object;
                const auto versions = sm.list_versions(b.id, c.key, "", "", "", 100).versions;
                if (!versions.empty() && pick(2) == 0) {
                    c.version_id = versions[pick(versions.size())].version.version_id();
                }
                return c;
            }
            case 6:
                c.op = kind::copy_object;
                c.source = c.target;
                c.source_key = "key-" + std::to_string(pick(4));
                c.replace_metadata = pick(2) == 0;
                return c;
            case 7:
                c.op = kind::create_upload;
                return c;
            case 8:
            case 9: {
                const auto uploads = sm.list_uploads(b.id, "", "", "", 100).first;
                if (uploads.empty()) {
                    c.op = kind::create_upload;
                    return c;
                }
                const auto& u = uploads[pick(uploads.size())];
                c.key = u.key;
                c.upload_id = u.upload_id();
                if (pick(3) != 0) {
                    c.op = kind::upload_part;
                    c.part.number = 1 + static_cast<std::uint32_t>(pick(3));
                    c.part.etag = "p" + std::to_string(pick(1000));
                    c.part.manifest = random_content().manifest;
                } else if (pick(2) == 0) {
                    c.op = kind::complete_upload;
                    for (const auto& [n, p] : u.parts) {
                        if (pick(3) != 0) {
                            c.parts.push_back({n, p.etag});
                        }
                    }
                } else {
                    c.op = kind::abort_upload;
                }
                return c;
            }
            case 10:
                c.op = kind::delete_bucket;
                return c;
            default:
                c.op = kind::collect_chunks;
                c.grace_ms = 5;
                c.max = 4;
                return c;
        }
    }

private:
    auto pick(std::size_t n) -> std::size_t {
        return std::uniform_int_distribution<std::size_t>(0, n - 1)(_rng);
    }
    auto random_content() -> object_content {
        std::vector<int> chunks;
        const auto n = pick(4);
        for (std::size_t i = 0; i < n; ++i) {
            chunks.push_back(static_cast<int>(pick(8)));
        }
        return content_of(chunks, "e" + std::to_string(pick(1000)));
    }

    std::mt19937 _rng;
};

/// Every chunk's count, recounted from the versions and parts that name it.
auto recount(const index_sm& sm) -> std::map<chunk_sha, std::uint64_t> {
    std::map<chunk_sha, std::uint64_t> out;
    for (const auto& b : sm.list_buckets()) {
        for (const auto& e : sm.list_versions(b.id, "", "", "", "", 100'000).versions) {
            for (const auto& c : e.version.content.manifest) {
                ++out[c.sha];
            }
        }
        for (const auto& u : sm.list_uploads(b.id, "", "", "", 100'000).first) {
            for (const auto& [n, p] : u.parts) {
                for (const auto& c : p.manifest) {
                    ++out[c.sha];
                }
            }
        }
    }
    return out;
}

void check_refcounts(const index_sm& sm) {
    const auto expected = recount(sm);
    const auto stored = sm.all_refcounts();
    for (const auto& [sha, n] : expected) {
        auto it = stored.find(sha);
        BOOST_TEST_REQUIRE((it != stored.end()));
        BOOST_TEST(it->second.count == n);
    }
    const auto dump = sm.dump();
    for (const auto& [sha, rec] : stored) {
        if (rec.count == 0) {
            BOOST_TEST(!expected.contains(sha));
            // An unreferenced chunk is in the zero index, at its time.
            BOOST_TEST(dump.contains(keys::zero(rec.zero_since_ms, sha)));
        }
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(replicas_agree_and_reference_counts_match_the_manifests) {
    std::map<kind, int> succeeded;
    for (std::uint32_t seed = 1; seed <= 20; ++seed) {
        BOOST_TEST_CONTEXT("seed " << seed) {
            replica a;
            replica b;
            workload w(seed);
            for (int i = 0; i < 300; ++i) {
                auto cmd = w.next(a.sm, a.now + 1);
                const auto ra = a.apply(cmd);
                const auto rb = b.apply(cmd);
                BOOST_TEST_REQUIRE((ra == rb));
                if (ra.ok()) {
                    ++succeeded[cmd.op];
                }
            }
            BOOST_TEST((a.sm.dump() == b.sm.dump()));
            check_refcounts(a.sm);
        }
    }
    // The workload reaches every kind of entry, so the agreement above
    // covers them all.
    for (int k = 1; k <= 11; ++k) {
        BOOST_TEST(succeeded[static_cast<kind>(k)] > 0, "kind " << k);
    }
    BOOST_TEST_MESSAGE("successful entries by kind: put " << succeeded[kind::put_object]
                                                          << ", complete "
                                                          << succeeded[kind::complete_upload]);
}

BOOST_AUTO_TEST_CASE(a_snapshot_restores_the_same_state_and_continues_the_same_way) {
    for (std::uint32_t seed = 100; seed < 110; ++seed) {
        BOOST_TEST_CONTEXT("seed " << seed) {
            replica leader;
            workload w(seed);
            std::vector<index_command> log;
            for (int i = 0; i < 150; ++i) {
                log.push_back(w.next(leader.sm, leader.now + 1));
                leader.apply(log.back());
            }
            temp_dir dir;
            const auto manifest = leader.sm.checkpoint(dir.path / "cp");
            replica follower;
            follower.sm.ingest(dir.path / "cp", manifest, leader.index);
            follower.index = leader.index;
            follower.now = leader.now;
            BOOST_TEST((follower.sm.dump() == leader.sm.dump()));
            BOOST_TEST(follower.sm.applied_index() == leader.index);
            for (int i = 0; i < 150; ++i) {
                auto cmd = w.next(leader.sm, leader.now + 1);
                BOOST_TEST_REQUIRE((leader.apply(cmd) == follower.apply(cmd)));
            }
            BOOST_TEST((follower.sm.dump() == leader.sm.dump()));
            check_refcounts(follower.sm);
        }
    }
}
