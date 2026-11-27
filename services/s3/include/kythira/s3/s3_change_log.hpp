// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_change_log.hpp
/// @brief The change log of an object index group: what it records, and
///        the state the group keeps about it (.kiro/specs/s3-compatible-storage/
///        task 14, Requirements 12.2 and 12.3; design "Notifications and
///        replication from a change log").
///
/// Every committed write to an object of a bucket that has event
/// notifications or replication configured (`bucket_ref::log_changes`)
/// appends one *change record* in the same apply: a new version (PUT,
/// POST, copy, completed upload), a delete or delete marker, a tagging or
/// ACL change, a lifecycle transition, expiration or restore. Buckets with
/// neither pay nothing: no record and no fsync.
///
/// The records go to the node's `segment_store` (core's record segment
/// store, which Kinesis shards and DynamoDB's change log use too), outside
/// the snapshot, one store stream per group: `s3/<hex of the group's range
/// start>/<epoch>`. The epoch is 0 until placement splits and merges
/// groups (task 18) and grows along every lineage then, as DynamoDB's
/// does, so a stream key is never reused.
///
/// The group keeps a `change_log_state` in its meta column family beside
/// the applied index, so it moves with snapshots: the stream, its sealed
/// segments, the last sequence written, and one *cursor* per consumer
/// (`notifications`, `replication`): the last sequence that consumer has
/// finished with. Consumers advance their cursors through the log
/// (`index_command::kind::advance_change_log`), so a new leader resumes
/// exactly where the old one stopped, and sealed segments every consumer
/// has passed are trimmed. Delivery is therefore at least once: a
/// consumer that delivered a record and lost leadership before its
/// cursor committed delivers it again.
///
/// Record timestamps come from the entry (the proposer's clock), clamped
/// never to go back, so every replica appends the same bytes and the
/// store rolls segments at the same records.

#include <kythira/s3/s3_index_records.hpp>

#include <raft/record_segment_store.hpp>
#include <raft/segment_store.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::s3 {

/// S3's event types, as change records carry them. The numbers are the
/// wire form: never reuse one.
enum class change_event : std::uint8_t {
    none = 0,
    object_created_put = 1,
    object_created_post = 2,
    object_created_copy = 3,
    object_created_complete_multipart_upload = 4,
    object_removed_delete = 5,
    object_removed_delete_marker_created = 6,
    lifecycle_expiration_delete = 7,
    lifecycle_expiration_delete_marker_created = 8,
    lifecycle_transition = 9,
    object_restore_post = 10,
    object_restore_completed = 11,
    object_restore_delete = 12,
    object_tagging_put = 13,
    object_tagging_delete = 14,
    object_acl_put = 15,
};

inline constexpr std::uint8_t k_last_change_event = 15;

/// The event's name in S3's event JSON (`eventName`), without `s3:`.
[[nodiscard]] constexpr auto event_name(change_event e) -> std::string_view {
    switch (e) {
        case change_event::none:
            return "";
        case change_event::object_created_put:
            return "ObjectCreated:Put";
        case change_event::object_created_post:
            return "ObjectCreated:Post";
        case change_event::object_created_copy:
            return "ObjectCreated:Copy";
        case change_event::object_created_complete_multipart_upload:
            return "ObjectCreated:CompleteMultipartUpload";
        case change_event::object_removed_delete:
            return "ObjectRemoved:Delete";
        case change_event::object_removed_delete_marker_created:
            return "ObjectRemoved:DeleteMarkerCreated";
        case change_event::lifecycle_expiration_delete:
            return "LifecycleExpiration:Delete";
        case change_event::lifecycle_expiration_delete_marker_created:
            return "LifecycleExpiration:DeleteMarkerCreated";
        case change_event::lifecycle_transition:
            return "LifecycleTransition";
        case change_event::object_restore_post:
            return "ObjectRestore:Post";
        case change_event::object_restore_completed:
            return "ObjectRestore:Completed";
        case change_event::object_restore_delete:
            return "ObjectRestore:Delete";
        case change_event::object_tagging_put:
            return "ObjectTagging:Put";
        case change_event::object_tagging_delete:
            return "ObjectTagging:Delete";
        case change_event::object_acl_put:
            return "ObjectAcl:Put";
    }
    return "";
}

/// One change to one object.
struct change_record {
    change_event event = change_event::none;
    std::uint64_t bucket_id = 0;
    std::string key;
    /// The version written or removed (or the delete marker written);
    /// empty for a delete in an unversioned bucket, which S3's event
    /// leaves without one.
    std::string version_id;
    std::uint64_t size = 0;
    std::string etag;
    /// The account the entry was made for (empty for the service's own
    /// workers: lifecycle, tiering).
    std::string requester;
    /// A lifecycle transition's new class.
    std::string storage_class;
    /// When the write was made (ms since the epoch), the store's timestamp.
    std::uint64_t written_ms = 0;
    /// A replicator wrote it (`x-amz-replication-status: REPLICA`): it is
    /// never replicated on, so two buckets replicating to each other do
    /// not loop.
    bool replica = false;

    friend auto operator==(const change_record&, const change_record&) -> bool = default;
};

/// A record with its place in the group's log; the sequence is also S3's
/// `sequencer` for the event.
struct sequenced_change {
    std::uint64_t seq = 0;
    change_record record;

    friend auto operator==(const sequenced_change&, const sequenced_change&) -> bool = default;
};

/// The consumers that keep a cursor. A sealed segment is trimmed once
/// every one of them has passed it.
inline constexpr std::string_view notifications_consumer = "notifications";
inline constexpr std::string_view replication_consumer = "replication";
inline constexpr std::array<std::string_view, 2> change_log_consumers{notifications_consumer,
                                                                      replication_consumer};

[[nodiscard]] inline auto is_change_log_consumer(std::string_view name) -> bool {
    for (const auto c : change_log_consumers) {
        if (c == name) {
            return true;
        }
    }
    return false;
}

/// What a group records about its change log.
struct change_log_state {
    std::uint64_t epoch = 0;
    std::string stream;
    /// The first sequence still kept, and the last written (0: none yet).
    std::uint64_t first_seq = 1;
    std::uint64_t last_seq = 0;
    /// The latest record timestamp, so timestamps never go back.
    std::uint64_t last_ms = 0;
    /// Sealed segments, oldest first.
    std::vector<record_segment_descriptor> sealed;
    /// Per consumer, the last sequence it has finished with.
    std::map<std::string, std::uint64_t> cursors;

    /// The lowest cursor of every consumer: records at or below it are
    /// done with.
    [[nodiscard]] auto consumed() const -> std::uint64_t {
        std::uint64_t low = last_seq;
        for (const auto c : change_log_consumers) {
            const auto it = cursors.find(std::string(c));
            low = std::min(low, it == cursors.end() ? std::uint64_t{0} : it->second);
        }
        return low;
    }

    friend auto operator==(const change_log_state&, const change_log_state&) -> bool = default;
};

/// The store stream of a group's change log in `epoch`.
[[nodiscard]] inline auto change_stream_key(std::string_view range_start, std::uint64_t epoch)
    -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out = "s3/";
    for (const char ch : range_start) {
        const auto b = static_cast<unsigned char>(ch);
        out.push_back(digits[b >> 4U]);
        out.push_back(digits[b & 0xFU]);
    }
    out += "/" + std::to_string(epoch);
    return out;
}

/// The meta key of a group's change log state.
[[nodiscard]] inline auto change_log_state_key(std::string_view range_start) -> std::string {
    return "s3-changes/" + std::string(range_start);
}

namespace codec {

inline constexpr std::uint8_t change_record_format = 1;
inline constexpr std::uint8_t change_log_state_format = 1;

[[nodiscard]] inline auto encode_change(const change_record& r) -> std::string {
    detail::writer w;
    w.u8(change_record_format).u8(static_cast<std::uint8_t>(r.event)).u64(r.bucket_id);
    w.str(r.key).str(r.version_id).u64(r.size).str(r.etag).str(r.requester);
    w.str(r.storage_class).u64(r.written_ms).boolean(r.replica);
    return w.take();
}

[[nodiscard]] inline auto decode_change(std::string_view in) -> change_record {
    detail::reader r(in);
    r.expect_format(change_record_format, "change record");
    change_record out;
    const auto e = r.u8();
    if (e == 0 || e > k_last_change_event) {
        throw index_format_error("s3 index: unknown change event");
    }
    out.event = static_cast<change_event>(e);
    out.bucket_id = r.u64();
    out.key = r.str();
    out.version_id = r.str();
    out.size = r.u64();
    out.etag = r.str();
    out.requester = r.str();
    out.storage_class = r.str();
    out.written_ms = r.u64();
    out.replica = r.boolean();
    r.done("change record");
    return out;
}

[[nodiscard]] inline auto encode_change_log_state(const change_log_state& s) -> std::string {
    detail::writer w;
    w.u8(change_log_state_format).u64(s.epoch).str(s.stream).u64(s.first_seq).u64(s.last_seq);
    w.u64(s.last_ms).u32(static_cast<std::uint32_t>(s.sealed.size()));
    for (const auto& d : s.sealed) {
        const auto bytes = encode_segment_descriptor(d);
        w.str(std::string_view(reinterpret_cast<const char*>(bytes.data()),  // NOLINT
                               bytes.size()));
    }
    w.u32(static_cast<std::uint32_t>(s.cursors.size()));
    for (const auto& [name, seq] : s.cursors) {
        w.str(name).u64(seq);
    }
    return w.take();
}

[[nodiscard]] inline auto decode_change_log_state(std::string_view in) -> change_log_state {
    detail::reader r(in);
    r.expect_format(change_log_state_format, "change log state");
    change_log_state s;
    s.epoch = r.u64();
    s.stream = r.str();
    s.first_seq = r.u64();
    s.last_seq = r.u64();
    s.last_ms = r.u64();
    const auto sealed = r.u32();
    for (std::uint32_t i = 0; i < sealed; ++i) {
        const auto raw = r.str();
        std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(raw.data()),  // NOLINT
                                         raw.size());
        auto d = decode_segment_descriptor(bytes);
        if (!d || !bytes.empty()) {
            throw index_format_error("s3 index: corrupt change log segment");
        }
        s.sealed.push_back(std::move(*d));
    }
    const auto cursors = r.u32();
    for (std::uint32_t i = 0; i < cursors; ++i) {
        auto name = r.str();
        s.cursors[std::move(name)] = r.u64();
    }
    r.done("change log state");
    return s;
}

}  // namespace codec

}  // namespace kythira::s3
