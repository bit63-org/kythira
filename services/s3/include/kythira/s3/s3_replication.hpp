// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_replication.hpp
/// @brief Bucket replication: the API operations and the worker that copies
///        new versions to their destinations (.kiro/specs/s3-compatible-storage/
///        task 14, Requirement 12.3).
///
/// **Operations.** `PutBucketReplication` stores the bucket's
/// configuration (sub-resource `replication`, `s3_replication_rules.hpp`)
/// once S3's checks pass: versioning enabled on the source, a destination
/// that is not the source, and, when the destination bucket is in this
/// cluster, versioning enabled there too. While a configuration is present
/// versioning cannot be suspended (`s3_versioning.hpp`).
///
/// **Status.** The front end decides when it writes a version whether it
/// replicates (by the rules, its tags and its encryption) and stores
/// `x-amz-replication-status: PENDING` with it, so a HEAD right after the
/// PUT says so, as on S3. A copy decides afresh; it never inherits the
/// status.
///
/// **The worker** (`replication_worker`, one per index group, on the
/// metadata leader, task 16) tails the group's change log after its cursor
/// (`s3_change_log.hpp`). For each new version still `PENDING` it reads the
/// bytes from the blob stores (opening SSE-S3 and SSE-KMS objects with the
/// service's keys) and PUTs them to each destination with the version's
/// content type, user metadata, stored headers, tags and object lock, and
/// `x-amz-replication-status: REPLICA`; then it sets the source's status
/// to `COMPLETED`, or `FAILED` when a destination refuses for good or
/// `max_attempts` runs in a row. A delete marker a client made goes, as a
/// DELETE, to the destinations whose rules enable delete marker
/// replication; version deletes and lifecycle's markers never do, as on
/// S3. Records are taken strictly in log order, and a destination that is
/// down holds back the rest until it answers, so one key's versions arrive
/// in the order they were written. The cursor advances through the log
/// after each run: a new leader resumes there, so a copy may be sent twice
/// (at least once).
///
/// **Destinations** are reached through a `replication_call`, which sends
/// one S3 request to the bucket a rule names: the daemon binds it to the
/// co-located S3 service in process (same-cluster replication), to another
/// Kythira cluster's endpoint, or to Amazon S3, signing with the
/// configured credentials (the rule's role is recorded, not assumed). A
/// Kythira destination authorizes the marked write as
/// `s3:ReplicateObject` (`s3:ReplicateDelete` for markers) and stores the
/// copy as `REPLICA`, which it never replicates on; Amazon S3 ignores the
/// header and stores a plain object. Destination version ids are the
/// destination's own: S3 keeps the source's, which only its internal
/// replication path can do.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_change_log.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_data_path.hpp>
#include <kythira/s3/s3_encryption.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_object_lock.hpp>
#include <kythira/s3/s3_objects.hpp>
#include <kythira/s3/s3_replication_rules.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

template<metadata_access M>
[[nodiscard]] auto put_bucket_replication(handler_context<M>& ctx, const s3_request& req,
                                          const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    using replication_detail::invalid_request;
    if (!lock_detail::has_integrity_header(req.headers)) {
        return invalid_request("Missing required header for this request: Content-MD5");
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto c = parse_replication_configuration(*body);
    if (!c) {
        return c.error();
    }
    if (b.desc.versioning != versioning_state::enabled) {
        return invalid_request(
            "Versioning must be 'Enabled' on the bucket to apply a replication configuration");
    }
    for (const auto& r : c->rules) {
        const auto dest = r.destination_bucket();
        if (dest == b.client_name) {
            return invalid_request("Destination bucket cannot be the same as the source bucket.");
        }
        const auto account = r.destination_account.empty() ? b.desc.owner : r.destination_account;
        if (auto d = ctx.meta.bucket(ctx.catalog_name(dest, account));
            d && d->versioning != versioning_state::enabled) {
            return invalid_request("Destination bucket must have versioning enabled.");
        }
    }
    if (auto e = bucket_detail::store(ctx, b, "replication", replication_xml(*c))) {
        return *e;
    }
    return s3_response{};
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_replication(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                          const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.replication) {
        auto e = aws_rest_xml::errors::make(404, "ReplicationConfigurationNotFoundError",
                                            "The replication configuration was not found");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    return xml_response(replication_xml(*b.replication));
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_replication(handler_context<M>& ctx, const s3_request& /*req*/,
                                             const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "replication", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

// ---------------------------------------------------------------------------
// Destinations
// ---------------------------------------------------------------------------

/// One S3 request to a destination bucket, before addressing and signing.
struct replication_request {
    std::string method;       ///< `PUT` or `DELETE`
    std::string destination;  ///< the rule's bucket ARN
    std::string account;      ///< the rule's `Account`, if any
    std::string bucket;
    std::string key;
    header_list headers;
    /// PUT: the object's bytes, `length` of them.
    std::uint64_t length = 0;
    body_source body;
};

struct replication_answer {
    int status = 0;
    std::string body;
};

/// Addresses, signs and sends one request; throws when it cannot.
using replication_call = std::function<replication_answer(replication_request&)>;

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

struct replication_options {
    /// Catalog names are `<account>/<name>` (`service_options`).
    bool account_namespaces = false;
    /// Records read per run.
    std::size_t page = 1000;
    /// Runs a destination is retried for one version before the version
    /// is marked `FAILED`.
    std::uint32_t max_attempts = 10;
    /// The clock, for tests; the system clock when empty.
    std::function<std::uint64_t()> clock;
};

struct replication_report {
    std::uint64_t records = 0;         ///< read and finished with
    std::uint64_t replicated = 0;      ///< versions marked COMPLETED
    std::uint64_t failed = 0;          ///< versions marked FAILED
    std::uint64_t delete_markers = 0;  ///< markers sent
    std::uint64_t failures = 0;        ///< failed requests, retried or not
    bool blocked = false;
};

template<change_log_access M> class replication_worker {
public:
    /// `keys`: the service's encryption keys, to read SSE-S3 and SSE-KMS
    /// objects; none reads only unencrypted ones.
    replication_worker(M& meta, data_path& data, std::shared_ptr<sse_keys> keys,
                       replication_call call, replication_options options = {})
        : _meta(meta),
          _data(data),
          _keys(keys ? std::move(keys) : std::make_shared<sse_keys>()),
          _call(std::move(call)),
          _options(std::move(options)) {
        if (!_call) {
            throw std::invalid_argument("s3 replication worker: needs a transport");
        }
        if (_options.page == 0 || _options.max_attempts == 0) {
            throw std::invalid_argument("s3 replication worker: needs a page and attempts");
        }
    }

    auto run() -> replication_report {
        replication_report r;
        const auto cursor = _meta.change_cursor(replication_consumer);
        const auto changes = _meta.read_changes(cursor, _options.page);
        if (changes.empty()) {
            return r;
        }
        std::map<std::uint64_t, bucket_descriptor> buckets;
        for (auto& d : _meta.list_buckets("")) {
            buckets.emplace(d.id, std::move(d));
        }
        std::uint64_t finished = cursor;
        for (const auto& c : changes) {
            if (!handle(c, buckets, r)) {
                r.blocked = true;
                break;
            }
            finished = c.seq;
            ++r.records;
        }
        if (finished > cursor) {
            index_command a;
            a.op = index_command::kind::advance_change_log;
            a.config_name = std::string(replication_consumer);
            a.change_seq = finished;
            (void)_meta.propose(a);
        }
        return r;
    }

private:
    enum class sent : std::uint8_t {
        ok,
        retry,
        failed
    };

    [[nodiscard]] auto now_ms() const -> std::uint64_t {
        if (_options.clock) {
            return _options.clock();
        }
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

    [[nodiscard]] auto client_name(std::string_view catalog) const -> std::string {
        if (!_options.account_namespaces) {
            return std::string(catalog);
        }
        const auto slash = catalog.find('/');
        return std::string(slash == std::string_view::npos ? catalog : catalog.substr(slash + 1));
    }

    /// One record; false when a destination is still being retried.
    auto handle(const sequenced_change& c,
                const std::map<std::uint64_t, bucket_descriptor>& buckets, replication_report& r)
        -> bool {
        const auto& rec = c.record;
        if (rec.replica) {
            return true;
        }
        const auto b = buckets.find(rec.bucket_id);
        if (b == buckets.end()) {
            return true;
        }
        if (_head != c.seq) {
            _head = c.seq;
            _done.clear();
            _gave_up = false;
            _attempts = 0;
        }
        switch (rec.event) {
            case change_event::object_created_put:
            case change_event::object_created_post:
            case change_event::object_created_copy:
            case change_event::object_created_complete_multipart_upload:
                return replicate_version(b->second, rec, r);
            case change_event::object_removed_delete_marker_created:
                return replicate_marker(b->second, rec, r);
            default:
                return true;
        }
    }

    auto replicate_version(const bucket_descriptor& desc, const change_record& rec,
                           replication_report& r) -> bool {
        const auto v = _meta.version(desc.id, rec.key, rec.version_id);
        if (!v || v->delete_marker) {
            return true;  // removed since: nothing to send
        }
        const auto& meta = v->content.system_metadata;
        const auto status = meta.find(std::string(replication_status_metadata));
        if (status == meta.end() || status->second != "PENDING") {
            return true;
        }
        const auto cfg = desc.config.contains("replication")
                             ? load_replication(desc.config.at("replication"))
                             : std::nullopt;
        const auto kind = stored_kind(meta);
        std::vector<const replication_rule*> rules;
        if (cfg) {
            rules = replication_rules_for(*cfg, v->key, object_detail::stored_tags(*v),
                                          kind == sse_kind::kms);
        }
        bool all = true;
        for (const auto* rule : rules) {
            if (_done.contains(rule->destination)) {
                continue;
            }
            switch (send_version(desc, *v, *rule, r)) {
                case sent::ok:
                    _done.insert(rule->destination);
                    break;
                case sent::failed:
                    _done.insert(rule->destination);
                    _gave_up = true;
                    break;
                case sent::retry:
                    all = false;
                    break;
            }
        }
        if (!all) {
            ++_attempts;
            return false;
        }
        // No rule left (the configuration changed): the version will not
        // be replicated, which S3 reports as a failure.
        const bool ok = !rules.empty() && !_gave_up;
        set_status(desc, *v, ok ? "COMPLETED" : "FAILED");
        ++(ok ? r.replicated : r.failed);
        return true;
    }

    auto replicate_marker(const bucket_descriptor& desc, const change_record& rec,
                          replication_report& r) -> bool {
        const auto it = desc.config.find("replication");
        const auto cfg = it != desc.config.end() ? load_replication(it->second) : std::nullopt;
        if (!cfg) {
            return true;
        }
        bool all = true;
        for (const auto* rule : delete_marker_rules_for(*cfg, rec.key)) {
            if (_done.contains(rule->destination)) {
                continue;
            }
            replication_request q;
            q.method = "DELETE";
            q.destination = rule->destination;
            q.account = rule->destination_account;
            q.bucket = rule->destination_bucket();
            q.key = rec.key;
            q.headers = {{"x-amz-replication-status", "REPLICA"}};
            switch (outcome(q, r)) {
                case sent::ok:
                    ++r.delete_markers;
                    _done.insert(rule->destination);
                    break;
                case sent::failed:
                    _done.insert(rule->destination);
                    break;
                case sent::retry:
                    all = false;
                    break;
            }
        }
        if (!all) {
            ++_attempts;
        }
        return all;
    }

    /// The PUT of one version to one destination.
    auto send_version(const bucket_descriptor& desc, const object_version& v,
                      const replication_rule& rule, replication_report& r) -> sent {
        const auto& c = v.content;
        const auto& meta = c.system_metadata;
        auto cipher = _keys->open(meta, std::nullopt, kms_caller{});
        if (!cipher) {
            ++r.failures;
            return give_up_or_retry(false);
        }
        replication_request q;
        q.method = "PUT";
        q.destination = rule.destination;
        q.account = rule.destination_account;
        q.bucket = rule.destination_bucket();
        q.key = v.key;
        q.length = c.size();
        auto& h = q.headers;
        h.emplace_back("Content-Type", c.content_type);
        h.emplace_back("Content-Length", std::to_string(q.length));
        for (const auto& [k, val] : c.user_metadata) {
            h.emplace_back("x-amz-meta-" + k, val);
        }
        for (const auto name : object_detail::stored_headers) {
            if (auto it = meta.find(std::string(name)); it != meta.end()) {
                h.emplace_back(std::string(name), it->second);
            }
        }
        const auto lock = lock_state_of(meta);
        if (!lock.mode.empty()) {
            h.emplace_back("x-amz-object-lock-mode", lock.mode);
            h.emplace_back("x-amz-object-lock-retain-until-date",
                           aws_rest_xml::iso8601_ms(bucket_detail::time_of(lock.until_ms)));
        }
        if (lock.legal_hold) {
            h.emplace_back("x-amz-object-lock-legal-hold", "ON");
        }
        const auto storage = !rule.storage_class.empty() ? rule.storage_class : c.storage_class;
        if (storage != "STANDARD") {
            h.emplace_back("x-amz-storage-class", storage);
        }
        if (!rule.replica_kms_key.empty() && stored_kind(meta) == sse_kind::kms) {
            h.emplace_back("x-amz-server-side-encryption", "aws:kms");
            h.emplace_back("x-amz-server-side-encryption-aws-kms-key-id", rule.replica_kms_key);
        }
        h.emplace_back("x-amz-replication-status", "REPLICA");
        (void)desc;

        // The body, one chunk at a time from the blob stores.
        struct reader_state {
            std::size_t next = 0;
            std::uint64_t offset = 0;
        };
        auto state = std::make_shared<reader_state>();
        auto keep = std::make_shared<std::optional<chunk_cipher>>(std::move(*cipher));
        const chunk_cipher* open = *keep ? &**keep : nullptr;
        q.body = [this, state, keep, open, &c](std::string& out) -> aws_rest_xml::result<bool> {
            if (state->next >= c.manifest.size()) {
                return false;
            }
            const auto size = c.manifest[state->next].size;
            auto read = _data.read_range(
                c, state->offset, size,
                [&](std::span<const std::byte> bytes) {
                    out.append(reinterpret_cast<const char*>(bytes.data()),  // NOLINT
                               bytes.size());
                },
                open);
            if (!read) {
                return read.error();
            }
            state->offset += size;
            ++state->next;
            return state->next < c.manifest.size();
        };
        return outcome(q, r);
    }

    auto outcome(replication_request& q, replication_report& r) -> sent {
        replication_answer a;
        try {
            a = _call(q);
        } catch (const std::exception&) {
            ++r.failures;
            return give_up_or_retry(false);
        }
        if (a.status >= 200 && a.status < 300) {
            return sent::ok;
        }
        ++r.failures;
        const bool throttled = a.status == 429 || a.status == 503 ||
                               a.body.find("<Code>SlowDown</Code>") != std::string::npos;
        return give_up_or_retry(a.status >= 400 && a.status < 500 && !throttled);
    }

    [[nodiscard]] auto give_up_or_retry(bool permanent) const -> sent {
        return permanent || _attempts + 1 >= _options.max_attempts ? sent::failed : sent::retry;
    }

    void set_status(const bucket_descriptor& desc, const object_version& v, std::string status) {
        index_command c;
        c.op = index_command::kind::set_object_state;
        c.now_ms = now_ms();
        c.target = ref_of(desc);
        c.key = v.key;
        c.version_id = v.version_id();
        c.expect_stamp = v.stamp;
        c.override_metadata = {std::string(replication_status_metadata)};
        c.content.system_metadata[std::string(replication_status_metadata)] = std::move(status);
        (void)_meta.propose(c);  // a version replaced meanwhile keeps its own status
    }

    M& _meta;
    data_path& _data;
    std::shared_ptr<sse_keys> _keys;
    replication_call _call;
    replication_options _options;
    /// The record being retried: destinations done, whether one was given
    /// up on, and how many runs it has failed.
    std::uint64_t _head = 0;
    std::set<std::string> _done;
    bool _gave_up = false;
    std::uint32_t _attempts = 0;
};

}  // namespace kythira::s3
