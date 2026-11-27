// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_lifecycle.hpp
/// @brief Lifecycle operations, restores and the lifecycle worker
///        (.kiro/specs/s3-compatible-storage/ task 13, Requirements 7.5,
///        12.1).
///
/// | Operation | Request |
/// |---|---|
/// | PutBucketLifecycleConfiguration (and the older PutBucketLifecycle) | `PUT /b?lifecycle` |
/// | GetBucketLifecycleConfiguration (and GetBucketLifecycle) | `GET /b?lifecycle` |
/// | DeleteBucketLifecycle | `DELETE /b?lifecycle` |
/// | RestoreObject | `POST /b/k?restore` |
///
/// The rules, their checks and their timing are `s3_lifecycle_rules.hpp`.
///
/// **Archive classes.** An object in GLACIER or DEEP_ARCHIVE answers a
/// GET (and a copy from it) with `403 InvalidObjectState` until
/// `RestoreObject` makes a temporary copy readable for the requested
/// days; HEAD shows the restore as `x-amz-restore`. An archived object
/// whose bytes are still on the blob stores (its class maps to no cloud
/// tier, or the tier worker has not moved it yet) is restored at once
/// (`ongoing-request="false"`). One held in a cloud tier answers 202 with
/// `ongoing-request="true"` and is listed for the tier worker
/// (`s3_tiers.hpp`), which brings the bytes back; a repeat meanwhile is
/// `409 RestoreAlreadyInProgress`. A repeat while restored answers 200 and
/// moves the expiry, as S3 does.
///
/// **The worker.** `lifecycle_worker::run` applies every enabled rule of
/// every bucket once, which is S3's daily evaluation; the daemon runs it
/// on the metadata leader each lifecycle day (task 16), and tests run it
/// with a short day. It walks each bucket's versions in key order, newest
/// first, so it knows each version's successor (when it became
/// noncurrent) and how many newer noncurrent versions a key has:
///
/// - a current version past an `Expiration` is deleted (a delete marker
///   in a versioned bucket, as S3 does);
/// - otherwise it moves to the coldest due `Transition` class;
/// - a noncurrent version past `NoncurrentVersionExpiration`, beyond the
///   newest `NewerNoncurrentVersions`, is removed for good (object lock
///   refuses that where it applies, and the version is skipped);
/// - otherwise it takes the coldest due `NoncurrentVersionTransition`;
/// - a delete marker left with no versions behind it is removed under
///   `ExpiredObjectDeleteMarker`, or an `Expiration` in days;
/// - uploads past `AbortIncompleteMultipartUpload` are aborted;
/// - restored copies past their expiry stop being readable.
///
/// Every change names the version stamp it judged (`expect_stamp`), so a
/// write that lands meanwhile is never expired or moved in its place.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_lifecycle_rules.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_object_lock.hpp>
#include <kythira/s3/s3_objects.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::s3 {

namespace lifecycle_detail {

[[nodiscard]] inline auto minimum_header(const s3_request& req)
    -> aws_rest_xml::result<transition_minimum> {
    const auto h = req.header("x-amz-transition-default-minimum-object-size");
    if (!h || *h == "all_storage_classes_128K") {
        return transition_minimum::all_storage_classes_128k;
    }
    if (*h == "varies_by_storage_class") {
        return transition_minimum::varies_by_storage_class;
    }
    return lifecycle_detail::argument_error("Invalid x-amz-transition-default-minimum-object-size");
}

}  // namespace lifecycle_detail

// ---- configuration --------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_lifecycle(handler_context<M>& ctx, const s3_request& req,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!lock_detail::has_integrity_header(req.headers)) {
        return lifecycle_detail::request_error(
            "Missing required header for this request: Content-MD5");
    }
    auto minimum = lifecycle_detail::minimum_header(req);
    if (!minimum) {
        return minimum.error();
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto c = parse_lifecycle(*body, *minimum);
    if (!c) {
        return c.error();
    }
    if (auto e = bucket_detail::store(ctx, b, "lifecycle", stored_lifecycle(*c))) {
        return *e;
    }
    s3_response r;
    r.set("x-amz-transition-default-minimum-object-size", std::string(to_string(c->minimum)));
    return r;
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_lifecycle(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                        const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.lifecycle) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchLifecycleConfiguration",
                                            "The lifecycle configuration does not exist");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    auto r = xml_response(lifecycle_xml(*b.lifecycle));
    r.set("x-amz-transition-default-minimum-object-size",
          std::string(to_string(b.lifecycle->minimum)));
    return r;
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_lifecycle(handler_context<M>& ctx, const s3_request& /*req*/,
                                           const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "lifecycle", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

// ---- restore ----------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto restore_object(handler_context<M>& ctx, const s3_request& req,
                                  const authenticated& auth, bucket_state& b) -> handler_result {
    using lifecycle_detail::argument_error;
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    std::optional<std::uint32_t> days;
    if (!body->empty()) {
        auto doc = aws_rest_xml::parse_xml(*body);
        if (!doc) {
            return doc.error();
        }
        if (doc->name != "RestoreRequest") {
            return aws_rest_xml::errors::malformed_xml("expected RestoreRequest");
        }
        if (doc->child("Type") != nullptr || doc->child("SelectParameters") != nullptr ||
            doc->child("OutputLocation") != nullptr) {
            return not_implemented();
        }
        auto d = lifecycle_detail::days_of(*doc, "Days", "RestoreRequest");
        if (!d) {
            return d.error();
        }
        days = *d;
        const auto* job = doc->child("GlacierJobParameters");
        const auto tier = job != nullptr ? job->child_text("Tier") : doc->child_text("Tier");
        if (tier && *tier != "Standard" && *tier != "Bulk" && *tier != "Expedited") {
            return aws_rest_xml::errors::malformed_xml("Tier must be Standard, Bulk or Expedited");
        }
    }
    auto found = object_detail::find_object(ctx, b, req.resource.key, req.query.get("versionId"));
    if (found.error) {
        return *found.error;
    }
    const auto& v = *found.version;
    if (!is_archive_class(v.content.storage_class)) {
        auto e = aws_rest_xml::errors::make(
            403, "InvalidObjectState",
            "Restore is not allowed for the object's current storage class");
        e.extra.emplace_back("StorageClass", v.content.storage_class);
        return e;
    }
    if (!days) {
        return lifecycle_detail::argument_error(
            "Days is required for a restore of an archived object");
    }
    const auto now = ctx.now_ms();
    const bool restored = restore_until(v) > now;
    const auto until = due_after(now, *days, ctx.options.lifecycle_day_ms);
    const auto& meta = v.content.system_metadata;
    if (meta.contains(std::string(restore_pending_metadata))) {
        return aws_rest_xml::errors::make(409, "RestoreAlreadyInProgress",
                                          "Object restore is already in progress");
    }
    if (meta.contains(std::string(tier_metadata)) && !restored) {
        // The bytes are in a cloud tier: the tier worker brings them back
        // and then makes the copy readable (`s3_tiers.hpp`).
        index_command c;
        c.op = index_command::kind::set_object_state;
        c.event = change_event::object_restore_post;
        c.now_ms = now;
        c.owner = auth.who ? auth.who->account : std::string{};
        c.target = ref_of(b.desc);
        c.key = req.resource.key;
        c.version_id = v.version_id();
        c.expect_stamp = v.stamp;
        c.override_metadata = {std::string(restore_metadata),
                               std::string(restore_pending_metadata)};
        c.content.system_metadata[std::string(restore_metadata)] = "ongoing-request=\"true\"";
        c.content.system_metadata[std::string(restore_pending_metadata)] = std::to_string(*days);
        auto r = ctx.meta.propose(c);
        if (!r.ok()) {
            return from_index(r);
        }
        s3_response out;
        out.status = 202;
        return out;
    }

    // The bytes are already here: the restore starts and completes in one
    // entry, which records both events.
    index_command c;
    c.op = index_command::kind::set_object_state;
    c.event = change_event::object_restore_completed;
    c.now_ms = now;
    c.owner = auth.who ? auth.who->account : std::string{};
    c.target = ref_of(b.desc);
    c.key = req.resource.key;
    c.version_id = v.version_id();
    c.expect_stamp = v.stamp;
    c.override_metadata = {std::string(restore_metadata), std::string(restore_until_metadata)};
    c.content.system_metadata[std::string(restore_metadata)] =
        "ongoing-request=\"false\", expiry-date=\"" +
        aws_rest_xml::http_date(bucket_detail::time_of(until)) + "\"";
    c.content.system_metadata[std::string(restore_until_metadata)] = std::to_string(until);
    auto r = ctx.meta.propose(c);
    if (!r.ok()) {
        return from_index(r);
    }
    s3_response out;
    out.status = restored ? 200 : 202;
    return out;
}

// ---- the worker ---------------------------------------------------------------------

struct lifecycle_options {
    /// A lifecycle day; shorter in tests.
    std::uint64_t day_ms = standard_day_ms;
    /// Versions and uploads read per listing page.
    std::size_t page = 1000;
    /// The clock, for tests; the system clock when empty.
    std::function<std::uint64_t()> clock;
};

/// What one run did.
struct lifecycle_report {
    std::uint64_t buckets = 0;
    std::uint64_t versions_seen = 0;
    std::uint64_t expired = 0;
    std::uint64_t noncurrent_expired = 0;
    std::uint64_t delete_markers_removed = 0;
    std::uint64_t transitioned = 0;
    std::uint64_t uploads_aborted = 0;
    std::uint64_t restores_ended = 0;
    /// Removals object lock refused, and changes that lost a race.
    std::uint64_t locked = 0;
    std::uint64_t raced = 0;
};

template<metadata_access M> class lifecycle_worker {
public:
    explicit lifecycle_worker(M& meta, lifecycle_options options = {})
        : _meta(meta), _options(std::move(options)) {
        if (_options.day_ms == 0 || _options.page == 0) {
            throw std::invalid_argument("s3 lifecycle: needs a day length and a page size");
        }
    }

    /// One evaluation of every bucket.
    auto run() -> lifecycle_report {
        lifecycle_report r;
        const auto now = now_ms();
        for (const auto& b : _meta.list_buckets("")) {
            run_bucket(b, now, r);
        }
        return r;
    }

    [[nodiscard]] auto options() const noexcept -> const lifecycle_options& { return _options; }

private:
    using tag_list = std::vector<std::pair<std::string, std::string>>;

    [[nodiscard]] auto now_ms() const -> std::uint64_t {
        if (_options.clock) {
            return _options.clock();
        }
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

    /// Where the walk is within one key's versions.
    struct key_walk {
        std::string key;
        std::optional<std::uint64_t> successor_ms;
        std::uint32_t noncurrent_rank = 0;
        /// A latest delete marker, judged once we know whether versions
        /// follow it.
        std::optional<object_version> lone_marker;
    };

    void run_bucket(const bucket_descriptor& desc, std::uint64_t now, lifecycle_report& r) {
        ++r.buckets;
        std::optional<lifecycle_configuration> cfg;
        if (auto it = desc.config.find("lifecycle"); it != desc.config.end()) {
            cfg = load_lifecycle(it->second);
        }
        const auto ref = ref_of(desc);
        key_walk walk;
        std::string km;
        std::string vm;
        for (bool more = true; more;) {
            auto page = _meta.list_versions(desc.id, "", "", km, vm, _options.page);
            more = page.truncated;
            km = page.next_key_marker;
            vm = page.next_version_id_marker;
            for (const auto& e : page.versions) {
                ++r.versions_seen;
                if (e.version.key != walk.key) {
                    finish_key(walk, cfg, ref, now, r);
                    walk = key_walk{e.version.key, std::nullopt, 0, std::nullopt};
                } else {
                    walk.lone_marker.reset();  // versions follow it
                }
                judge(e.version, e.is_latest, walk, cfg, ref, now, r);
                walk.successor_ms = e.version.last_modified_ms;
            }
            if (page.versions.empty()) {
                break;
            }
        }
        finish_key(walk, cfg, ref, now, r);
        if (cfg) {
            abort_uploads(desc, *cfg, now, r);
        }
    }

    void judge(const object_version& v, bool latest, key_walk& walk,
               const std::optional<lifecycle_configuration>& cfg, const bucket_ref& ref,
               std::uint64_t now, lifecycle_report& r) {
        if (v.delete_marker) {
            if (latest) {
                walk.lone_marker = v;
            } else if (cfg && walk.successor_ms) {
                // A noncurrent marker goes with the noncurrent versions.
                for (const auto& rule : cfg->rules) {
                    if (rule.enabled && rule.noncurrent_days && rule.filter.tags.empty() &&
                        matches_prefix(rule.filter, v.key) &&
                        due_after(*walk.successor_ms, *rule.noncurrent_days, _options.day_ms) <=
                            now) {
                        remove_version(ref, v, now, r, r.noncurrent_expired);
                        break;
                    }
                }
            }
            return;
        }
        const auto restored_until = restore_until(v);
        if (restored_until != 0 && restored_until <= now) {
            end_restore(ref, v, now, r);
        }
        if (!cfg) {
            return;
        }
        const auto tags = object_detail::stored_tags(v);
        const auto size = v.content.size();
        if (latest) {
            judge_current(*cfg, v, tags, size, ref, now, r);
        } else if (walk.successor_ms) {
            judge_noncurrent(*cfg, v, tags, size, *walk.successor_ms, walk.noncurrent_rank, ref,
                             now, r);
            ++walk.noncurrent_rank;
        }
    }

    void judge_current(const lifecycle_configuration& cfg, const object_version& v,
                       const tag_list& tags, std::uint64_t size, const bucket_ref& ref,
                       std::uint64_t now, lifecycle_report& r) {
        std::optional<std::string> colder;
        for (const auto& rule : cfg.rules) {
            if (!rule.enabled || !matches(rule.filter, v.key, size, tags)) {
                continue;
            }
            if ((rule.expiration_days &&
                 due_after(v.last_modified_ms, *rule.expiration_days, _options.day_ms) <= now) ||
                (rule.expiration_date_ms && *rule.expiration_date_ms <= now)) {
                index_command c = command(index_command::kind::delete_object, ref, v, now);
                c.version_id.reset();  // by the bucket's versioning: a marker when versioned
                count(_meta.propose(c), r, r.expired);
                return;
            }
            for (const auto& t : rule.transitions) {
                const bool due =
                    (t.days && due_after(v.last_modified_ms, *t.days, _options.day_ms) <= now) ||
                    (t.date_ms && *t.date_ms <= now);
                if (due && coldness(t.storage_class) > coldness(v.content.storage_class) &&
                    (!colder || coldness(t.storage_class) > coldness(*colder)) &&
                    transition_size_ok(cfg, rule, t.storage_class, size)) {
                    colder = t.storage_class;
                }
            }
        }
        if (colder) {
            transition(ref, v, *colder, now, r);
        }
    }

    void judge_noncurrent(const lifecycle_configuration& cfg, const object_version& v,
                          const tag_list& tags, std::uint64_t size, std::uint64_t since_ms,
                          std::uint32_t rank, const bucket_ref& ref, std::uint64_t now,
                          lifecycle_report& r) {
        std::optional<std::string> colder;
        for (const auto& rule : cfg.rules) {
            if (!rule.enabled || !matches(rule.filter, v.key, size, tags)) {
                continue;
            }
            if (rule.noncurrent_days &&
                due_after(since_ms, *rule.noncurrent_days, _options.day_ms) <= now &&
                rank >= rule.newer_noncurrent_versions.value_or(0)) {
                remove_version(ref, v, now, r, r.noncurrent_expired);
                return;
            }
            for (const auto& t : rule.noncurrent_transitions) {
                if (due_after(since_ms, t.days, _options.day_ms) <= now &&
                    rank >= t.newer_versions.value_or(0) &&
                    coldness(t.storage_class) > coldness(v.content.storage_class) &&
                    (!colder || coldness(t.storage_class) > coldness(*colder)) &&
                    transition_size_ok(cfg, rule, t.storage_class, size)) {
                    colder = t.storage_class;
                }
            }
        }
        if (colder) {
            transition(ref, v, *colder, now, r);
        }
    }

    /// A latest delete marker with nothing behind it.
    void finish_key(key_walk& walk, const std::optional<lifecycle_configuration>& cfg,
                    const bucket_ref& ref, std::uint64_t now, lifecycle_report& r) {
        if (!walk.lone_marker || !cfg) {
            return;
        }
        const auto& m = *walk.lone_marker;
        for (const auto& rule : cfg->rules) {
            if (rule.enabled && rule.filter.tags.empty() && matches_prefix(rule.filter, m.key) &&
                (rule.expired_object_delete_marker || rule.expiration_days)) {
                remove_version(ref, m, now, r, r.delete_markers_removed);
                return;
            }
        }
    }

    void abort_uploads(const bucket_descriptor& desc, const lifecycle_configuration& cfg,
                       std::uint64_t now, lifecycle_report& r) {
        const bool any = std::ranges::any_of(
            cfg.rules, [](const lifecycle_rule& x) { return x.enabled && x.abort_days; });
        if (!any) {
            return;
        }
        std::string km;
        std::string um;
        for (bool more = true; more;) {
            auto [page, page_more] = _meta.list_uploads(desc.id, "", km, um, _options.page);
            more = page_more;
            for (const auto& u : page) {
                km = u.key;
                um = u.upload_id();
                for (const auto& rule : cfg.rules) {
                    if (rule.enabled && rule.abort_days && matches_prefix(rule.filter, u.key) &&
                        due_after(u.initiated_ms, *rule.abort_days, _options.day_ms) <= now) {
                        index_command c;
                        c.op = index_command::kind::abort_upload;
                        c.now_ms = now;
                        c.target = ref_of(desc);
                        c.key = u.key;
                        c.upload_id = u.upload_id();
                        count(_meta.propose(c), r, r.uploads_aborted);
                        break;
                    }
                }
            }
            if (page.empty()) {
                break;
            }
        }
    }

    [[nodiscard]] static auto matches_prefix(const lifecycle_filter& f, std::string_view key)
        -> bool {
        return !f.prefix || key.starts_with(*f.prefix);
    }

    [[nodiscard]] static auto command(index_command::kind op, const bucket_ref& ref,
                                      const object_version& v, std::uint64_t now) -> index_command {
        index_command c;
        c.op = op;
        if (op == index_command::kind::delete_object) {
            c.event = change_event::lifecycle_expiration_delete;
        }
        c.now_ms = now;
        c.target = ref;
        c.key = v.key;
        c.version_id = v.version_id();
        c.expect_stamp = v.stamp;
        return c;
    }

    void remove_version(const bucket_ref& ref, const object_version& v, std::uint64_t now,
                        lifecycle_report& r, std::uint64_t& counter) {
        count(_meta.propose(command(index_command::kind::delete_object, ref, v, now)), r, counter);
    }

    void transition(const bucket_ref& ref, const object_version& v, const std::string& to,
                    std::uint64_t now, lifecycle_report& r) {
        auto c = command(index_command::kind::set_object_state, ref, v, now);
        c.event = change_event::lifecycle_transition;
        c.new_storage_class = to;
        count(_meta.propose(c), r, r.transitioned);
    }

    void end_restore(const bucket_ref& ref, const object_version& v, std::uint64_t now,
                     lifecycle_report& r) {
        auto c = command(index_command::kind::set_object_state, ref, v, now);
        c.event = change_event::object_restore_delete;
        // A tiered version also gives back its chunks on the blob stores.
        c.override_metadata = {std::string(restore_metadata), std::string(restore_until_metadata),
                               std::string(restored_metadata)};
        count(_meta.propose(c), r, r.restores_ended);
    }

    static void count(const index_result& res, lifecycle_report& r, std::uint64_t& counter) {
        if (res.ok()) {
            ++counter;
        } else if (res.error == "PreconditionFailed") {
            ++r.raced;
        } else if (res.error == "AccessDenied") {
            ++r.locked;
        }
    }

    M& _meta;
    lifecycle_options _options;
};

}  // namespace kythira::s3
