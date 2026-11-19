// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

/// @file s3_lifecycle_test.cpp
/// @brief Lifecycle rules and the lifecycle worker (`s3_lifecycle_rules.hpp`,
///        `s3_lifecycle.hpp`; .kiro/specs/s3-compatible-storage/ task 13,
///        Requirements 7.5 and 12.1).
///
/// The configuration's XML both ways and S3's checks on it; when actions
/// fall due (rounded to midnight); and the worker over the in-process
/// metadata layer with a one-second lifecycle day: expiration of current
/// and noncurrent versions, delete markers, transitions and their size
/// minimum, aborted uploads, object lock, races and ended restores.

#define BOOST_TEST_MODULE s3_lifecycle_test
#include <boost/test/unit_test.hpp>

#include <kythira/s3/s3_lifecycle.hpp>
#include <kythira/s3/s3_lifecycle_rules.hpp>
#include <kythira/s3/s3_metadata.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace kythira::s3;
using kythira::chunk_sha;
namespace aws_rest_xml = kythira::aws_rest_xml;

constexpr std::uint64_t day = 1000;

auto config(std::string rules) -> std::string {
    return "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" + rules +
           "</LifecycleConfiguration>";
}

auto code_of(const aws_rest_xml::result<lifecycle_configuration>& r) -> std::string {
    return r ? std::string{} : r.error().code;
}

/// One bucket in the in-process index, written to directly.
struct bucket {
    local_metadata meta;
    std::uint64_t now = 100 * day;
    std::uint64_t id = 0;

    explicit bucket(versioning_state v = versioning_state::unversioned, bool lock = false) {
        index_command c;
        c.op = index_command::kind::create_bucket;
        c.now_ms = now;
        c.bucket = "b";
        c.owner = "acct";
        c.region = "us-east-1";
        c.object_lock = lock;
        BOOST_REQUIRE(meta.propose(c).ok());
        if (v != versioning_state::unversioned && !lock) {
            index_command e;
            e.op = index_command::kind::put_bucket_config;
            e.now_ms = now;
            e.bucket = "b";
            e.config_name = "versioning";
            e.document = v == versioning_state::enabled ? "Enabled" : "Suspended";
            BOOST_REQUIRE(meta.propose(e).ok());
        }
        id = meta.bucket("b")->id;
    }

    [[nodiscard]] auto ref() const -> bucket_ref {
        const auto d = meta.bucket("b").value();
        return {d.id, d.versioning, d.object_lock};
    }

    void rules(const std::string& xml,
               transition_minimum m = transition_minimum::all_storage_classes_128k) {
        auto c = parse_lifecycle(config(xml), m);
        BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error().message));
        index_command e;
        e.op = index_command::kind::put_bucket_config;
        e.now_ms = now;
        e.bucket = "b";
        e.config_name = "lifecycle";
        e.document = stored_lifecycle(*c);
        BOOST_REQUIRE(meta.propose(e).ok());
    }

    auto put(const std::string& key, std::uint64_t size = 10, std::string tags = {},
             std::map<std::string, std::string> extra = {}) -> index_result {
        index_command c;
        c.op = index_command::kind::put_object;
        c.now_ms = now;
        c.target = ref();
        c.key = key;
        c.owner = "acct";
        chunk_sha sha{};
        sha[0] = static_cast<std::byte>(key.size());
        sha[1] = static_cast<std::byte>(size & 0xFFU);
        sha[2] = static_cast<std::byte>((size >> 8U) & 0xFFU);
        c.content.manifest = {{sha, size}};
        c.content.etag = "e";
        if (!tags.empty()) {
            c.content.system_metadata["x-amz-tagging"] = std::move(tags);
        }
        for (auto& [k, v] : extra) {
            c.content.system_metadata[k] = v;
        }
        auto r = meta.propose(c);
        BOOST_REQUIRE(r.ok());
        return r;
    }

    void del(const std::string& key) {
        index_command c;
        c.op = index_command::kind::delete_object;
        c.now_ms = now;
        c.target = ref();
        c.key = key;
        BOOST_REQUIRE(meta.propose(c).ok());
    }

    auto run() -> lifecycle_report {
        lifecycle_options o;
        o.day_ms = day;
        o.clock = [this] { return now; };
        return lifecycle_worker<local_metadata>(meta, o).run();
    }

    [[nodiscard]] auto current(const std::string& key) const -> std::optional<object_version> {
        return meta.version(id, key, std::nullopt);
    }
    [[nodiscard]] auto versions(const std::string& key) const -> std::size_t {
        return meta.list_versions(id, key, "", "", "", 1000).versions.size();
    }
};

}  // namespace

// ---- the configuration ------------------------------------------------------------

BOOST_AUTO_TEST_CASE(every_filter_form_and_action_round_trips) {
    const auto xml = config(
        "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>"
        "<Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition>"
        "<Transition><Days>90</Days><StorageClass>GLACIER</StorageClass></Transition>"
        "<Expiration><Days>365</Days></Expiration></Rule>"
        "<Rule><ID>tagged</ID><Filter><And><Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value>"
        "</Tag><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan><ObjectSizeLessThan>1000"
        "</ObjectSizeLessThan></And></Filter><Status>Disabled</Status>"
        "<Expiration><Date>2027-01-01T00:00:00.000Z</Date></Expiration></Rule>"
        "<Rule><ID>versions</ID><Filter/><Status>Enabled</Status>"
        "<NoncurrentVersionTransition><NoncurrentDays>10</NoncurrentDays><StorageClass>GLACIER_IR"
        "</StorageClass><NewerNoncurrentVersions>2</NewerNoncurrentVersions>"
        "</NoncurrentVersionTransition>"
        "<NoncurrentVersionExpiration><NoncurrentDays>40</NoncurrentDays>"
        "<NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration>"
        "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>"
        "<AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation>"
        "</AbortIncompleteMultipartUpload></Rule>"
        "<Rule><Prefix>old/</Prefix><Status>Enabled</Status><Expiration><Days>1</Days>"
        "</Expiration></Rule>");
    auto c = parse_lifecycle(xml);
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error().message));
    BOOST_REQUIRE(c->rules.size() == 4U);
    BOOST_TEST(c->rules[0].transitions.size() == 2U);
    BOOST_TEST(*c->rules[0].expiration_days == 365U);
    BOOST_TEST(!c->rules[1].enabled);
    BOOST_TEST(c->rules[1].filter.tags.size() == 1U);
    BOOST_TEST(*c->rules[1].filter.size_greater == 100U);
    BOOST_TEST(*c->rules[1].expiration_date_ms == 1'798'761'600'000ULL);
    BOOST_TEST(c->rules[2].expired_object_delete_marker);
    BOOST_TEST(*c->rules[2].newer_noncurrent_versions == 3U);
    BOOST_TEST(*c->rules[2].abort_days == 7U);
    BOOST_TEST(c->rules[3].id == "rule-4");  // S3 names a rule without an ID
    BOOST_TEST(c->rules[3].filter.legacy_prefix);

    auto again = parse_lifecycle(lifecycle_xml(*c));
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST((*again == *c));
    auto stored = load_lifecycle(stored_lifecycle(*c));
    BOOST_REQUIRE(stored.has_value());
    BOOST_TEST((*stored == *c));
}

BOOST_AUTO_TEST_CASE(configurations_s3_refuses_are_refused) {
    const std::string ok_action = "<Expiration><Days>1</Days></Expiration>";
    const auto rule = [&](const std::string& inner) {
        return config("<Rule>" + inner + "</Rule>");
    };
    BOOST_TEST(code_of(parse_lifecycle(config(""))) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle("<Other/>")) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(rule("<Filter/>" + ok_action))) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(rule("<Filter/><Prefix/><Status>Enabled</Status>" +
                                            ok_action))) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(rule("<Status>Enabled</Status>" + ok_action))) ==
               "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(
                   config("<Rule><ID>x</ID><Filter/><Status>Enabled</Status>" + ok_action +
                          "</Rule><Rule><ID>x</ID><Filter/><Status>Enabled</Status>" + ok_action +
                          "</Rule>"))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(rule("<ID>" + std::string(256, 'i') +
                                            "</ID><Filter/><Status>Enabled</Status>" +
                                            ok_action))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(rule("<Filter/><Status>Enabled</Status>"))) ==
               "InvalidRequest");
    BOOST_TEST(code_of(parse_lifecycle(rule(
                   "<Filter/><Status>Enabled</Status><Expiration><Days>0</Days></Expiration>"))) ==
               "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter/><Status>Enabled</Status><Expiration><Date>2027-01-01T10:00:00Z"
                        "</Date></Expiration>"))) == "InvalidArgument");
    BOOST_TEST(
        code_of(parse_lifecycle(rule("<Filter/><Status>Enabled</Status><Expiration><Days>3</Days>"
                                     "<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>"
                                     "</Expiration>"))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled"
                        "</Status><Expiration><ExpiredObjectDeleteMarker>true"
                        "</ExpiredObjectDeleteMarker></Expiration>"))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled"
                        "</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>1"
                        "</DaysAfterInitiation></AbortIncompleteMultipartUpload>"))) ==
               "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(rule(
                   "<Filter/><Status>Enabled</Status><Transition><Days>10</Days>"
                   "<StorageClass>STANDARD_IA</StorageClass></Transition>"))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter/><Status>Enabled</Status><Expiration><Days>30</Days></Expiration>"
                        "<Transition><Days>30</Days><StorageClass>GLACIER</StorageClass>"
                        "</Transition>"))) == "InvalidArgument");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter/><Status>Enabled</Status><Transition><Days>1</Days>"
                        "<StorageClass>STANDARD</StorageClass></Transition>"))) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter><Prefix>a</Prefix><Tag><Key>k</Key><Value>v</Value></Tag>"
                        "</Filter><Status>Enabled</Status>" +
                        ok_action))) == "MalformedXML");
    BOOST_TEST(code_of(parse_lifecycle(
                   rule("<Filter><And><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan>"
                        "<ObjectSizeLessThan>5</ObjectSizeLessThan></And></Filter><Status>Enabled"
                        "</Status>" +
                        ok_action))) == "InvalidArgument");
}

BOOST_AUTO_TEST_CASE(actions_fall_due_at_the_next_midnight) {
    // Created 2014-01-15 10:30 UTC, three days: midnight starting the 19th.
    const std::uint64_t created = 1'389'781'800'000ULL;
    BOOST_TEST(due_after(created, 3, standard_day_ms) == 1'390'089'600'000ULL);
    BOOST_TEST(due_after(0, 0, standard_day_ms) == standard_day_ms);

    auto c = parse_lifecycle(
        config("<Rule><ID>long</ID><Filter/><Status>Enabled</Status><Expiration><Days>10</Days>"
               "</Expiration></Rule><Rule><ID>short</ID><Filter><Prefix>a</Prefix></Filter><Status>"
               "Enabled</Status><Expiration><Days>2</Days></Expiration></Rule>"));
    BOOST_REQUIRE(c.has_value());
    object_version v;
    v.key = "ab";
    v.last_modified_ms = created;
    const auto e = expiration_of(*c, v, {}, standard_day_ms);
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST(e->second == "short");
    BOOST_TEST(expiration_header(*e) ==
               "expiry-date=\"Sat, 18 Jan 2014 00:00:00 GMT\", rule-id=\"short\"");
    v.key = "b";
    BOOST_TEST(expiration_of(*c, v, {}, standard_day_ms)->second == "long");
}

// ---- the worker ----------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(current_versions_expire_by_prefix_tag_and_size) {
    bucket b;
    b.rules(
        "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>"
        "<Expiration><Days>2</Days></Expiration></Rule>"
        "<Rule><ID>tmp</ID><Filter><And><Tag><Key>tmp</Key><Value>yes</Value></Tag>"
        "<ObjectSizeLessThan>100</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>"
        "<Expiration><Days>1</Days></Expiration></Rule>"
        "<Rule><ID>off</ID><Filter/><Status>Disabled</Status>"
        "<Expiration><Days>1</Days></Expiration></Rule>");
    b.put("logs/1");
    b.put("keep");
    b.put("t-small", 10, "tmp=yes");
    b.put("t-big", 500, "tmp=yes");
    b.put("t-other", 10, "tmp=no");

    b.now += 2 * day;  // created at 100, one day due at 102
    auto r = b.run();
    BOOST_TEST(r.expired == 1U);
    BOOST_TEST(!b.current("t-small").has_value());
    BOOST_TEST(b.current("logs/1").has_value());
    b.now += day;  // two days due at 103
    r = b.run();
    BOOST_TEST(r.expired == 1U);
    BOOST_TEST(!b.current("logs/1").has_value());
    for (const auto* k : {"keep", "t-big", "t-other"}) {
        BOOST_TEST(b.current(k).has_value());
    }
}

BOOST_AUTO_TEST_CASE(versioned_buckets_get_markers_lose_old_versions_and_lone_markers) {
    bucket b(versioning_state::enabled);
    b.rules(
        "<Rule><ID>all</ID><Filter/><Status>Enabled</Status>"
        "<Expiration><Days>5</Days></Expiration>"
        "<NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays>"
        "<NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration>"
        "</Rule>");
    b.put("k");  // v1 at 100
    b.now += day;
    b.put("k");  // v2 at 101: v1 noncurrent since 101
    b.now += day;
    b.put("k");  // v3 at 102: v2 noncurrent since 102
    BOOST_TEST(b.versions("k") == 3U);

    // v1, noncurrent since 101, is due at 104; v2 (since 102) is not, and
    // is the one newer noncurrent version the rule keeps anyway.
    b.now = 104 * day;
    auto r = b.run();
    BOOST_TEST(r.noncurrent_expired == 1U);
    BOOST_TEST(b.versions("k") == 2U);

    b.now = 108 * day;  // v3 (created 102) expires at 108: a marker on top
    r = b.run();
    BOOST_TEST(r.expired == 1U);
    BOOST_TEST(b.current("k")->delete_marker);
    BOOST_TEST(b.versions("k") == 3U);

    // A marker over nothing goes; then the key is gone entirely.
    bucket m(versioning_state::enabled);
    m.rules(
        "<Rule><ID>markers</ID><Filter/><Status>Enabled</Status>"
        "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>"
        "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>"
        "</NoncurrentVersionExpiration></Rule>");
    m.put("x");
    m.del("x");
    m.now += 3 * day;
    r = m.run();
    BOOST_TEST(r.noncurrent_expired == 1U);  // the version under the marker
    BOOST_TEST(r.delete_markers_removed == 0U);
    r = m.run();  // now the marker stands alone
    BOOST_TEST(r.delete_markers_removed == 1U);
    BOOST_TEST(m.versions("x") == 0U);
}

BOOST_AUTO_TEST_CASE(transitions_take_the_coldest_due_class_and_respect_the_minimum) {
    bucket b;
    b.rules(
        "<Rule><ID>t</ID><Filter/><Status>Enabled</Status>"
        "<Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition>"
        "<Transition><Days>60</Days><StorageClass>GLACIER</StorageClass></Transition>"
        "</Rule>");
    b.put("big", 200 * 1024);
    b.put("small", 1024);
    b.now += 31 * day;
    auto r = b.run();
    BOOST_TEST(r.transitioned == 1U);
    BOOST_TEST(b.current("big")->content.storage_class == "STANDARD_IA");
    BOOST_TEST(b.current("small")->content.storage_class == "STANDARD");  // under 128 KiB
    b.now += 60 * day;
    r = b.run();
    BOOST_TEST(b.current("big")->content.storage_class == "GLACIER");
    BOOST_TEST(b.run().transitioned == 0U);  // nothing colder is due

    // varies_by_storage_class: small objects may go to the Glacier classes.
    bucket v;
    v.rules(
        "<Rule><ID>t</ID><Filter/><Status>Enabled</Status>"
        "<Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition>"
        "<Transition><Days>40</Days><StorageClass>GLACIER_IR</StorageClass></Transition>"
        "</Rule>",
        transition_minimum::varies_by_storage_class);
    v.put("small", 1024);
    v.now += 35 * day;
    BOOST_TEST(v.run().transitioned == 0U);
    v.now += 10 * day;
    BOOST_TEST(v.run().transitioned == 1U);
    BOOST_TEST(v.current("small")->content.storage_class == "GLACIER_IR");

    // An object never moves to a warmer class.
    bucket w;
    w.rules(
        "<Rule><ID>t</ID><Filter/><Status>Enabled</Status>"
        "<Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition>"
        "</Rule>");
    index_command c;
    w.put("cold", 200 * 1024);
    c.op = index_command::kind::set_object_state;
    c.now_ms = w.now;
    c.target = w.ref();
    c.key = "cold";
    c.new_storage_class = "DEEP_ARCHIVE";
    BOOST_REQUIRE(w.meta.propose(c).ok());
    w.now += 31 * day;
    BOOST_TEST(w.run().transitioned == 0U);
    BOOST_TEST(w.current("cold")->content.storage_class == "DEEP_ARCHIVE");
}

BOOST_AUTO_TEST_CASE(noncurrent_versions_transition_and_expiration_beats_transition) {
    bucket b(versioning_state::enabled);
    b.rules(
        "<Rule><ID>nc</ID><Filter/><Status>Enabled</Status>"
        "<NoncurrentVersionTransition><NoncurrentDays>1</NoncurrentDays>"
        "<StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition></Rule>"
        "<Rule><ID>exp</ID><Filter><Prefix>gone</Prefix></Filter><Status>Enabled</Status>"
        "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>"
        "</NoncurrentVersionExpiration></Rule>");
    b.put("k", 200 * 1024);
    b.put("gone", 200 * 1024);
    b.now += day;
    b.put("k", 200 * 1024);
    b.put("gone", 200 * 1024);
    b.now += 2 * day;
    const auto r = b.run();
    BOOST_TEST(r.transitioned == 1U);
    BOOST_TEST(r.noncurrent_expired == 1U);
    const auto listing = b.meta.list_versions(b.id, "k", "", "", "", 10).versions;
    BOOST_REQUIRE(listing.size() == 2U);
    BOOST_TEST(listing[0].version.content.storage_class == "STANDARD");
    BOOST_TEST(listing[1].version.content.storage_class == "GLACIER");
    BOOST_TEST(b.versions("gone") == 1U);
}

BOOST_AUTO_TEST_CASE(incomplete_uploads_are_aborted_after_their_days) {
    bucket b;
    b.rules(
        "<Rule><ID>mpu</ID><Filter><Prefix>up/</Prefix></Filter><Status>Enabled</Status>"
        "<AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation>"
        "</AbortIncompleteMultipartUpload></Rule>");
    for (const auto* k : {"up/a", "other"}) {
        index_command c;
        c.op = index_command::kind::create_upload;
        c.now_ms = b.now;
        c.target = b.ref();
        c.key = k;
        c.owner = "acct";
        BOOST_REQUIRE(b.meta.propose(c).ok());
    }
    b.now += day;
    BOOST_TEST(b.run().uploads_aborted == 0U);
    b.now += 2 * day;
    BOOST_TEST(b.run().uploads_aborted == 1U);
    BOOST_TEST(b.meta.list_uploads(b.id, "", "", "", 10).first.size() == 1U);
}

BOOST_AUTO_TEST_CASE(locked_versions_are_skipped) {
    bucket b(versioning_state::enabled, true);
    b.rules(
        "<Rule><ID>nc</ID><Filter/><Status>Enabled</Status>"
        "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>"
        "</NoncurrentVersionExpiration></Rule>");
    b.put("k", 10, {},
          {{std::string(lock_mode_metadata), "COMPLIANCE"},
           {std::string(lock_until_metadata), std::to_string(b.now + 1000 * day)}});
    b.now += day;
    b.put("k");
    b.now += 3 * day;
    const auto r = b.run();
    BOOST_TEST(r.noncurrent_expired == 0U);
    BOOST_TEST(r.locked == 1U);
    BOOST_TEST(b.versions("k") == 2U);
}

BOOST_AUTO_TEST_CASE(a_version_that_changed_meanwhile_is_left_alone) {
    bucket b;
    const auto first = b.put("k");
    const auto stamp = b.current("k")->stamp;
    b.now += day;
    b.put("k");  // replaces the null version with a new stamp
    index_command c;
    c.op = index_command::kind::delete_object;
    c.now_ms = b.now;
    c.target = b.ref();
    c.key = "k";
    c.version_id = "null";
    c.expect_stamp = stamp;
    BOOST_TEST(b.meta.propose(c).error == "PreconditionFailed");
    c.version_id.reset();
    BOOST_TEST(b.meta.propose(c).error == "PreconditionFailed");
    c.op = index_command::kind::set_object_state;
    c.new_storage_class = "GLACIER";
    BOOST_TEST(b.meta.propose(c).error == "PreconditionFailed");
    BOOST_TEST(b.current("k").has_value());
    BOOST_TEST(b.current("k")->content.storage_class == "STANDARD");
    (void)first;
}

BOOST_AUTO_TEST_CASE(restored_copies_end_at_their_expiry) {
    bucket b;
    b.put("k", 10, {},
          {{std::string(restore_metadata), "ongoing-request=\"false\""},
           {std::string(restore_until_metadata), std::to_string(b.now + 2 * day)}});
    b.now += day;
    BOOST_TEST(b.run().restores_ended == 0U);
    b.now += day;
    BOOST_TEST(b.run().restores_ended == 1U);
    const auto v = b.current("k");
    BOOST_TEST(!v->content.system_metadata.contains(std::string(restore_metadata)));
    BOOST_TEST(restore_until(*v) == 0U);
}
