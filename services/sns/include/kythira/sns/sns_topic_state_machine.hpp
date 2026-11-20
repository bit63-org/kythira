// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file sns_topic_state_machine.hpp
/// @brief The replicated state behind SNS topics
///        (.kiro/specs/sns-compatible-notifications/ task 2, design "Publish
///        commits to a log; delivery reads it", "Delivery partitions and
///        leases" and "FIFO"; Requirements 4.3, 5.1 and 5.3).
///
/// One instance per multi_raft group. It satisfies `kythira::state_machine`
/// and holds:
///
/// - **topics**, by id, with an (account, name) index. Ids come from a
///   counter that only grows, so a deleted topic's id is never reused
///   (Requirement 4.3), and every cursor, lease and log stream named by an
///   old id stays dead;
/// - **subscriptions**, by (topic, id), with an id index;
/// - **log partitions**: each topic's publish log is cut into partitions,
///   each one stream of the core `record_segment_store` keyed
///   `t/<topic id>/<partition>`, with a per-partition sequence counter as the
///   store's sequence;
/// - **FIFO deduplication records**, per topic, for five minutes of leader
///   time;
/// - **delivery leases**: a delivery partition is (topic, log partition,
///   subscription bucket), owned by one worker under a lease that carries a
///   fencing token;
/// - **cursors** (a subscription's last delivered sequence in a log
///   partition) and **retry state** (a message waiting for its next attempt
///   to one subscription), both committed only under the current token.
///
/// ### Publishing
///
/// A publish is one command carrying up to ten entries (Requirement 5.1).
/// `apply()` checks each, appends the accepted ones to their partitions'
/// streams and calls the store's barrier before it returns, so a message id
/// the front end hands back is on disk on every replica that acknowledged
/// the entry. The state machine never looks inside a message's payload: the
/// front end encodes the subject, attributes and body (sealed with the
/// topic's data key when SSE is on, Requirement 9.1), and only the message
/// id, the group id and the dedup id are stored beside it, because delivery
/// orders by group and dedup is decided here.
///
/// The front end chooses each entry's partition (a hash of the group id on a
/// FIFO topic), the message id and the dedup id (explicit, or the SHA-256 of
/// the body for content-based deduplication), and stamps the leader's clock
/// into the command. `apply()` reads no clock, so every replica decides the
/// same way.
///
/// ### FIFO deduplication
///
/// A FIFO entry whose dedup id was accepted on the same topic less than five
/// minutes earlier (by the stamped clock) is a duplicate: it appends nothing
/// and answers the original message id and sequence, as SNS does. The
/// records are part of the state and its snapshots, so a retry after a
/// leader change, or on a replica restored from a snapshot, is still caught
/// (Requirement 5.3).
///
/// ### Leases and fencing
///
/// A worker acquires a delivery partition's lease with its owner name and a
/// duration. The grant carries a token from a counter that only grows. A
/// worker renews with its token, and commits cursors and retry state with it
/// (`commit_delivery`); a commit, renewal or release whose token is not the
/// current one is refused with `lease_lost`. Another worker can take the
/// lease only after it expires (by the stamped clock), and taking it changes
/// the token, so a worker that stalled past its lease cannot commit after
/// the new owner has started: it stops at its next commit (design "Error
/// handling"). Expiry is not checked on commit; the token is the fence.
///
/// ### Snapshots
///
/// The snapshot carries no message bytes: per partition the counter, the
/// last timestamp, the sealed segment descriptors, and (taken from the store
/// when the snapshot is serialized) the active segment's descriptor with its
/// digest so far. A replica restoring the snapshot truncates any local tail
/// past the snapshot's counters and fetches an active segment it lacks
/// through the `segment_fetcher` hook, as the Kinesis stream state machine
/// does. A store-less instance (tests of the topic logic) keeps the counters
/// but writes nothing.

#include <kythira/sns/sns_codec.hpp>
#include <raft/record_segment_store.hpp>
#include <raft/types.hpp>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::sns {

/// The FIFO deduplication window (Requirement 5.3).
inline constexpr std::int64_t k_dedup_window_ms = std::int64_t{5} * 60 * 1000;
/// How long a confirmation token is valid, as on SNS.
inline constexpr std::int64_t k_confirmation_window_ms = std::int64_t{3} * 24 * 60 * 60 * 1000;
/// The most entries one publish command carries (`PublishBatch`).
inline constexpr std::size_t k_max_publish_entries = 10;
/// The most log partitions and delivery buckets a topic may have.
inline constexpr std::uint32_t k_max_partitions = 1024;
inline constexpr std::uint32_t k_max_delivery_buckets = 1024;

/// The record store stream that holds one log partition of a topic.
[[nodiscard]] inline auto publish_log_stream(std::uint64_t topic_id, std::uint32_t partition)
    -> std::string {
    return "t/" + std::to_string(topic_id) + "/" + std::to_string(partition);
}

// ---- state ----------------------------------------------------------------

using string_map = std::map<std::string, std::string, std::less<>>;

struct topic_record {
    std::uint64_t _id = 0;
    std::string _account{};
    std::string _name{};
    bool _fifo = false;
    /// Log partitions, fixed at creation.
    std::uint32_t _partitions = 1;
    /// Subscription buckets per log partition; a delivery partition is one
    /// (log partition, bucket). Fixed at creation.
    std::uint32_t _delivery_buckets = 1;
    std::int64_t _created_ms = 0;
    /// Every attribute as the API set it, `FifoTopic` included. The state
    /// machine interprets none of them; the front end validates names and
    /// values (task 4).
    string_map _attributes{};
    string_map _tags{};

    friend auto operator==(const topic_record&, const topic_record&) -> bool = default;
};

struct subscription_record {
    std::uint64_t _id = 0;
    std::uint64_t _topic_id = 0;
    std::string _protocol{};
    std::string _endpoint{};
    /// The account that subscribed.
    std::string _owner{};
    string_map _attributes{};
    bool _confirmed = false;
    /// While pending: the token `ConfirmSubscription` must present, and
    /// when it stops being accepted.
    std::string _token{};
    std::int64_t _token_expires_ms = 0;
    std::int64_t _created_ms = 0;

    friend auto operator==(const subscription_record&, const subscription_record&)
        -> bool = default;
};

struct partition_state {
    /// The last sequence appended; 0 before the first message.
    std::uint64_t _last_seq = 0;
    /// The last stamped timestamp; appends never go back in time.
    std::int64_t _last_timestamp_ms = 0;
    /// Segments the store sealed by rolling, oldest first.
    std::vector<record_segment_descriptor> _sealed{};

    friend auto operator==(const partition_state&, const partition_state&) -> bool = default;
};

struct dedup_record {
    std::string _message_id{};
    std::uint32_t _partition = 0;
    std::uint64_t _seq = 0;
    std::int64_t _expires_ms = 0;

    friend auto operator==(const dedup_record&, const dedup_record&) -> bool = default;
};

/// One delivery partition: a log partition and a subscription bucket.
struct delivery_partition {
    std::uint64_t _topic_id = 0;
    std::uint32_t _partition = 0;
    std::uint32_t _bucket = 0;

    friend auto operator<=>(const delivery_partition&, const delivery_partition&) = default;
};

struct lease_record {
    std::string _owner{};
    std::uint64_t _token = 0;
    std::int64_t _expires_ms = 0;

    friend auto operator==(const lease_record&, const lease_record&) -> bool = default;
};

struct retry_record {
    /// Attempts made so far.
    std::uint32_t _attempt = 0;
    /// The stamped time of the next attempt.
    std::int64_t _next_ms = 0;

    friend auto operator==(const retry_record&, const retry_record&) -> bool = default;
};

/// (subscription, log partition).
using cursor_key = std::pair<std::uint64_t, std::uint32_t>;
/// (subscription, log partition, sequence).
using retry_key = std::tuple<std::uint64_t, std::uint32_t, std::uint64_t>;

// ---- stored messages ------------------------------------------------------

/// What one record of a publish log holds. `_payload` is the front end's
/// encoding of the message (and its ciphertext under SSE); the rest is what
/// delivery and deduplication need without opening it.
struct stored_message {
    std::string _message_id{};
    std::string _group_id{};
    std::string _dedup_id{};
    std::vector<std::byte> _payload{};

    friend auto operator==(const stored_message&, const stored_message&) -> bool = default;
};

inline constexpr std::uint8_t k_stored_message_version = 1;

[[nodiscard]] inline auto encode_stored_message(std::string_view message_id,
                                                std::string_view group_id,
                                                std::string_view dedup_id,
                                                std::span<const std::byte> payload)
    -> std::vector<std::byte> {
    codec::writer w;
    w.u8(k_stored_message_version).str(message_id).str(group_id).str(dedup_id).bytes(payload);
    return w.take();
}

[[nodiscard]] inline auto decode_stored_message(std::span<const std::byte> bytes)
    -> stored_message {
    codec::reader r(bytes);
    if (r.u8() != k_stored_message_version) {
        throw sns_codec_error("sns codec: unknown stored message version");
    }
    stored_message m;
    m._message_id = r.str();
    m._group_id = r.str();
    m._dedup_id = r.str();
    m._payload = r.bytes();
    r.expect_end("stored message");
    return m;
}

// ---- commands -------------------------------------------------------------

/// `CreateTopic`. Idempotent: the same name with the same attributes and
/// tags answers the existing topic's id (Requirement 4.1); different
/// attributes or tags are refused, as on SNS.
struct create_topic_command {
    std::string _account{};
    std::string _name{};
    bool _fifo = false;
    std::uint32_t _partitions = 1;
    std::uint32_t _delivery_buckets = 1;
    string_map _attributes{};
    string_map _tags{};
    std::int64_t _now_ms = 0;
};

/// `DeleteTopic`. Removes the topic, its subscriptions, partitions, dedup
/// records, leases, cursors and retry state, and drops its log streams.
/// Deleting a topic that does not exist succeeds, as on SNS.
struct delete_topic_command {
    std::string _account{};
    std::string _name{};
};

/// `SetTopicAttributes`, one attribute.
struct set_topic_attribute_command {
    std::string _account{};
    std::string _name{};
    std::string _key{};
    std::string _value{};
};

/// `TagResource` and `UntagResource`: set `_set`, then remove `_remove`.
struct tag_topic_command {
    std::string _account{};
    std::string _name{};
    string_map _set{};
    std::vector<std::string> _remove{};
};

/// `Subscribe`. The same protocol and endpoint on a topic answers the
/// existing subscription when the attributes match (a pending one takes the
/// new token, as SNS sends a new confirmation), and is refused otherwise.
struct subscribe_command {
    std::string _account{};
    std::string _name{};
    std::string _protocol{};
    std::string _endpoint{};
    std::string _owner{};
    string_map _attributes{};
    /// Whether the subscription must be confirmed first (HTTP/HTTPS and
    /// email; not SQS in the same account, Requirement 4.2). The front end
    /// decides; the token is the leader's random choice.
    bool _needs_confirmation = false;
    std::string _token{};
    std::int64_t _now_ms = 0;
};

/// `ConfirmSubscription`: the pending subscription of the topic whose token
/// this is, while the token is valid.
struct confirm_subscription_command {
    std::string _account{};
    std::string _name{};
    std::string _token{};
    std::int64_t _now_ms = 0;
};

/// `Unsubscribe`. Also drops the subscription's cursors and retry state.
struct unsubscribe_command {
    std::uint64_t _subscription_id = 0;
};

/// `SetSubscriptionAttributes`, one attribute.
struct set_subscription_attribute_command {
    std::uint64_t _subscription_id = 0;
    std::string _key{};
    std::string _value{};
};

struct publish_entry {
    std::uint32_t _partition = 0;
    std::string _message_id{};
    /// Required on a FIFO topic.
    std::string _group_id{};
    /// Required on a FIFO topic (explicit, or the body's SHA-256 under
    /// content-based deduplication); ignored on a standard topic.
    std::string _dedup_id{};
    std::vector<std::byte> _payload{};
};

/// `Publish` (one entry) and `PublishBatch` (up to ten).
struct publish_command {
    std::string _account{};
    std::string _name{};
    std::vector<publish_entry> _entries{};
    std::int64_t _now_ms = 0;
};

struct acquire_lease_command {
    delivery_partition _partition{};
    std::string _owner{};
    std::int64_t _now_ms = 0;
    std::int64_t _duration_ms = 0;
};

struct renew_lease_command {
    delivery_partition _partition{};
    std::string _owner{};
    std::uint64_t _token = 0;
    std::int64_t _now_ms = 0;
    std::int64_t _duration_ms = 0;
};

struct release_lease_command {
    delivery_partition _partition{};
    std::string _owner{};
    std::uint64_t _token = 0;
};

struct cursor_update {
    std::uint64_t _subscription_id = 0;
    std::uint64_t _seq = 0;
};

struct retry_update {
    std::uint64_t _subscription_id = 0;
    std::uint64_t _seq = 0;
    std::uint32_t _attempt = 0;
    std::int64_t _next_ms = 0;
};

struct retry_clear {
    std::uint64_t _subscription_id = 0;
    std::uint64_t _seq = 0;
};

/// A delivery worker's progress on one delivery partition, all or nothing:
/// cursors (which never move back), retry state to keep and retry state to
/// drop. Refused unless `_token` is the partition's current lease token.
/// Every subscription named must belong to the partition's topic and
/// bucket, and every sequence must have been appended.
struct commit_delivery_command {
    delivery_partition _partition{};
    std::string _owner{};
    std::uint64_t _token = 0;
    std::vector<cursor_update> _cursors{};
    std::vector<retry_update> _retries{};
    std::vector<retry_clear> _cleared{};
};

using topic_command =
    std::variant<create_topic_command, delete_topic_command, set_topic_attribute_command,
                 tag_topic_command, subscribe_command, confirm_subscription_command,
                 unsubscribe_command, set_subscription_attribute_command, publish_command,
                 acquire_lease_command, renew_lease_command, release_lease_command,
                 commit_delivery_command>;

namespace detail {

inline auto put(codec::writer& w, const delivery_partition& p) -> void {
    w.u64(p._topic_id).u32(p._partition).u32(p._bucket);
}

inline auto get_partition(codec::reader& r) -> delivery_partition {
    delivery_partition p;
    p._topic_id = r.u64();
    p._partition = r.u32();
    p._bucket = r.u32();
    return p;
}

inline auto put(codec::writer& w, const create_topic_command& c) -> void {
    w.str(c._account).str(c._name).boolean(c._fifo).u32(c._partitions).u32(c._delivery_buckets);
    w.strings(c._attributes).strings(c._tags).i64(c._now_ms);
}
inline auto put(codec::writer& w, const delete_topic_command& c) -> void {
    w.str(c._account).str(c._name);
}
inline auto put(codec::writer& w, const set_topic_attribute_command& c) -> void {
    w.str(c._account).str(c._name).str(c._key).str(c._value);
}
inline auto put(codec::writer& w, const tag_topic_command& c) -> void {
    w.str(c._account)
        .str(c._name)
        .strings(c._set)
        .u32(static_cast<std::uint32_t>(c._remove.size()));
    for (const auto& k : c._remove) {
        w.str(k);
    }
}
inline auto put(codec::writer& w, const subscribe_command& c) -> void {
    w.str(c._account).str(c._name).str(c._protocol).str(c._endpoint).str(c._owner);
    w.strings(c._attributes).boolean(c._needs_confirmation).str(c._token).i64(c._now_ms);
}
inline auto put(codec::writer& w, const confirm_subscription_command& c) -> void {
    w.str(c._account).str(c._name).str(c._token).i64(c._now_ms);
}
inline auto put(codec::writer& w, const unsubscribe_command& c) -> void {
    w.u64(c._subscription_id);
}
inline auto put(codec::writer& w, const set_subscription_attribute_command& c) -> void {
    w.u64(c._subscription_id).str(c._key).str(c._value);
}
inline auto put(codec::writer& w, const publish_command& c) -> void {
    w.str(c._account)
        .str(c._name)
        .i64(c._now_ms)
        .u32(static_cast<std::uint32_t>(c._entries.size()));
    for (const auto& e : c._entries) {
        w.u32(e._partition).str(e._message_id).str(e._group_id).str(e._dedup_id).bytes(e._payload);
    }
}
inline auto put(codec::writer& w, const acquire_lease_command& c) -> void {
    put(w, c._partition);
    w.str(c._owner).i64(c._now_ms).i64(c._duration_ms);
}
inline auto put(codec::writer& w, const renew_lease_command& c) -> void {
    put(w, c._partition);
    w.str(c._owner).u64(c._token).i64(c._now_ms).i64(c._duration_ms);
}
inline auto put(codec::writer& w, const release_lease_command& c) -> void {
    put(w, c._partition);
    w.str(c._owner).u64(c._token);
}
inline auto put(codec::writer& w, const commit_delivery_command& c) -> void {
    put(w, c._partition);
    w.str(c._owner).u64(c._token);
    w.u32(static_cast<std::uint32_t>(c._cursors.size()));
    for (const auto& u : c._cursors) {
        w.u64(u._subscription_id).u64(u._seq);
    }
    w.u32(static_cast<std::uint32_t>(c._retries.size()));
    for (const auto& u : c._retries) {
        w.u64(u._subscription_id).u64(u._seq).u32(u._attempt).i64(u._next_ms);
    }
    w.u32(static_cast<std::uint32_t>(c._cleared.size()));
    for (const auto& u : c._cleared) {
        w.u64(u._subscription_id).u64(u._seq);
    }
}

}  // namespace detail

inline constexpr std::uint8_t k_command_version = 1;

/// A command as it goes into the Raft log: a version byte, the variant's
/// index, then its fields.
[[nodiscard]] inline auto encode_command(const topic_command& c) -> std::vector<std::byte> {
    codec::writer w;
    w.u8(k_command_version).u8(static_cast<std::uint8_t>(c.index()));
    std::visit([&w](const auto& v) { detail::put(w, v); }, c);
    return w.take();
}

[[nodiscard]] inline auto decode_command(std::span<const std::byte> bytes) -> topic_command {
    codec::reader r(bytes);
    if (r.u8() != k_command_version) {
        throw sns_codec_error("sns codec: unknown command version");
    }
    const auto kind = r.u8();
    topic_command out;
    switch (kind) {
        case 0: {
            create_topic_command c;
            c._account = r.str();
            c._name = r.str();
            c._fifo = r.boolean();
            c._partitions = r.u32();
            c._delivery_buckets = r.u32();
            c._attributes = r.strings();
            c._tags = r.strings();
            c._now_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 1: {
            delete_topic_command c;
            c._account = r.str();
            c._name = r.str();
            out = std::move(c);
            break;
        }
        case 2: {
            set_topic_attribute_command c;
            c._account = r.str();
            c._name = r.str();
            c._key = r.str();
            c._value = r.str();
            out = std::move(c);
            break;
        }
        case 3: {
            tag_topic_command c;
            c._account = r.str();
            c._name = r.str();
            c._set = r.strings();
            const auto n = r.count(4);
            for (std::uint32_t i = 0; i < n; ++i) {
                c._remove.push_back(r.str());
            }
            out = std::move(c);
            break;
        }
        case 4: {
            subscribe_command c;
            c._account = r.str();
            c._name = r.str();
            c._protocol = r.str();
            c._endpoint = r.str();
            c._owner = r.str();
            c._attributes = r.strings();
            c._needs_confirmation = r.boolean();
            c._token = r.str();
            c._now_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 5: {
            confirm_subscription_command c;
            c._account = r.str();
            c._name = r.str();
            c._token = r.str();
            c._now_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 6: {
            unsubscribe_command c;
            c._subscription_id = r.u64();
            out = c;
            break;
        }
        case 7: {
            set_subscription_attribute_command c;
            c._subscription_id = r.u64();
            c._key = r.str();
            c._value = r.str();
            out = std::move(c);
            break;
        }
        case 8: {
            publish_command c;
            c._account = r.str();
            c._name = r.str();
            c._now_ms = r.i64();
            const auto n = r.count(20);
            for (std::uint32_t i = 0; i < n; ++i) {
                publish_entry e;
                e._partition = r.u32();
                e._message_id = r.str();
                e._group_id = r.str();
                e._dedup_id = r.str();
                e._payload = r.bytes();
                c._entries.push_back(std::move(e));
            }
            out = std::move(c);
            break;
        }
        case 9: {
            acquire_lease_command c;
            c._partition = detail::get_partition(r);
            c._owner = r.str();
            c._now_ms = r.i64();
            c._duration_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 10: {
            renew_lease_command c;
            c._partition = detail::get_partition(r);
            c._owner = r.str();
            c._token = r.u64();
            c._now_ms = r.i64();
            c._duration_ms = r.i64();
            out = std::move(c);
            break;
        }
        case 11: {
            release_lease_command c;
            c._partition = detail::get_partition(r);
            c._owner = r.str();
            c._token = r.u64();
            out = std::move(c);
            break;
        }
        case 12: {
            commit_delivery_command c;
            c._partition = detail::get_partition(r);
            c._owner = r.str();
            c._token = r.u64();
            auto n = r.count(16);
            for (std::uint32_t i = 0; i < n; ++i) {
                cursor_update u;
                u._subscription_id = r.u64();
                u._seq = r.u64();
                c._cursors.push_back(u);
            }
            n = r.count(28);
            for (std::uint32_t i = 0; i < n; ++i) {
                retry_update u;
                u._subscription_id = r.u64();
                u._seq = r.u64();
                u._attempt = r.u32();
                u._next_ms = r.i64();
                c._retries.push_back(u);
            }
            n = r.count(16);
            for (std::uint32_t i = 0; i < n; ++i) {
                retry_clear u;
                u._subscription_id = r.u64();
                u._seq = r.u64();
                c._cleared.push_back(u);
            }
            out = std::move(c);
            break;
        }
        default:
            throw sns_codec_error("sns codec: unknown command kind");
    }
    r.expect_end("command");
    return out;
}

// ---- results --------------------------------------------------------------

enum class apply_status : std::uint8_t {
    ok = 0,
    /// The command did not decode.
    invalid,
    topic_not_found,
    topic_exists_with_different_attributes,
    topic_exists_with_different_tags,
    subscription_not_found,
    subscription_exists_with_different_attributes,
    /// No pending subscription of the topic has this token, or it expired.
    invalid_token,
    /// A field the front end should have refused; `_detail` says which.
    invalid_parameter,
    /// Another owner holds the lease and it has not expired.
    lease_held,
    /// The token is not the partition's current lease token.
    lease_lost,
};
inline constexpr std::uint8_t k_max_apply_status =
    static_cast<std::uint8_t>(apply_status::lease_lost);

enum class publish_status : std::uint8_t {
    ok = 0,
    /// A FIFO entry whose dedup id was accepted within the window: nothing
    /// appended, the original message id and sequence answered.
    duplicate,
    invalid_parameter,
};

struct publish_entry_result {
    publish_status _status = publish_status::ok;
    std::uint32_t _partition = 0;
    std::uint64_t _seq = 0;
    std::string _message_id{};

    friend auto operator==(const publish_entry_result&, const publish_entry_result&)
        -> bool = default;
};

struct apply_result {
    apply_status _status = apply_status::ok;
    /// The topic id (topic commands), subscription id (subscription
    /// commands) or lease token (lease commands).
    std::uint64_t _id = 0;
    /// `CreateTopic` and `Subscribe`: the topic or subscription existed.
    bool _existing = false;
    /// For `invalid_parameter` and `lease_held`: what was wrong, or who
    /// holds the lease.
    std::string _detail{};
    /// `Publish`: one result per entry, in order.
    std::vector<publish_entry_result> _entries{};

    friend auto operator==(const apply_result&, const apply_result&) -> bool = default;
};

[[nodiscard]] inline auto encode_result(const apply_result& a) -> std::vector<std::byte> {
    codec::writer w;
    w.u8(static_cast<std::uint8_t>(a._status)).u64(a._id).boolean(a._existing).str(a._detail);
    w.u32(static_cast<std::uint32_t>(a._entries.size()));
    for (const auto& e : a._entries) {
        w.u8(static_cast<std::uint8_t>(e._status)).u32(e._partition).u64(e._seq).str(e._message_id);
    }
    return w.take();
}

[[nodiscard]] inline auto decode_result(std::span<const std::byte> bytes) -> apply_result {
    codec::reader r(bytes);
    apply_result a;
    a._status = r.enumeration<apply_status>(k_max_apply_status);
    a._id = r.u64();
    a._existing = r.boolean();
    a._detail = r.str();
    const auto n = r.count(17);
    for (std::uint32_t i = 0; i < n; ++i) {
        publish_entry_result e;
        e._status = r.enumeration<publish_status>(2);
        e._partition = r.u32();
        e._seq = r.u64();
        e._message_id = r.str();
        a._entries.push_back(std::move(e));
    }
    r.expect_end("apply result");
    return a;
}

// ---- the state machine ----------------------------------------------------

/// Called during `restore_from_snapshot` for an active segment the local
/// store lacks: fetch and install it (`record_segment_store::fetch_segment`
/// from the group's peers), or throw. Restore cannot finish without it.
using segment_fetcher = std::function<void(const record_segment_descriptor&)>;

template<typename LogIndex = std::uint64_t>
requires log_index<LogIndex>
class topic_state_machine {
public:
    topic_state_machine() = default;
    explicit topic_state_machine(record_segment_store* store, segment_fetcher fetch = {})
        : _store(store), _fetch(std::move(fetch)) {}

    // ---- kythira::state_machine -------------------------------------------

    auto apply(const std::vector<std::byte>& command, LogIndex index) -> std::vector<std::byte> {
        _last_applied_index = index;
        topic_command c;
        try {
            c = decode_command(command);
        } catch (const sns_codec_error&) {
            return encode_result({._status = apply_status::invalid});
        }
        return encode_result(std::visit([this](auto& v) { return this->apply_one(v); }, c));
    }

    [[nodiscard]] auto get_state() const -> std::vector<std::byte> { return serialize(); }

    auto restore_from_snapshot(const std::vector<std::byte>& snapshot_data, LogIndex index)
        -> void {
        topic_state_machine incoming;
        std::vector<record_segment_descriptor> active;
        incoming.deserialize(snapshot_data, active);
        if (_store != nullptr) {
            for (const auto& [key, p] : incoming._partitions) {
                // A tail past the snapshot (written before a crash, its
                // entries not yet re-applied) goes; the log replays it.
                _store->truncate_after(
                    publish_log_stream(key.first, key.second),
                    p._last_seq == 0 ? std::nullopt : std::optional{p._last_seq});
            }
            for (const auto& d : active) {
                if (!_store->has_segment(d)) {
                    if (!_fetch) {
                        throw record_segment_error("sns: snapshot names an active segment of " +
                                                   d._stream +
                                                   " this node lacks, and no fetcher is set");
                    }
                    _fetch(d);
                }
            }
        }
        _next_topic_id = incoming._next_topic_id;
        _next_subscription_id = incoming._next_subscription_id;
        _next_lease_token = incoming._next_lease_token;
        _topics = std::move(incoming._topics);
        _topic_index = std::move(incoming._topic_index);
        _subscriptions = std::move(incoming._subscriptions);
        _subscription_index = std::move(incoming._subscription_index);
        _partitions = std::move(incoming._partitions);
        _dedup = std::move(incoming._dedup);
        _leases = std::move(incoming._leases);
        _cursors = std::move(incoming._cursors);
        _retries = std::move(incoming._retries);
        _last_applied_index = index;
    }

    [[nodiscard]] auto last_applied_index() const noexcept -> LogIndex {
        return _last_applied_index;
    }

    // ---- queries (the front end and delivery workers, task 4 and 6) -------

    [[nodiscard]] auto find_topic(std::string_view account, std::string_view name) const
        -> const topic_record* {
        const auto it = _topic_index.find(std::pair{std::string(account), std::string(name)});
        return it == _topic_index.end() ? nullptr : topic_by_id(it->second);
    }

    [[nodiscard]] auto topic_by_id(std::uint64_t id) const -> const topic_record* {
        const auto it = _topics.find(id);
        return it == _topics.end() ? nullptr : &it->second;
    }

    /// An account's topics by name, after `start_after`, at most `limit`.
    [[nodiscard]] auto list_topics(std::string_view account, std::string_view start_after = {},
                                   std::size_t limit = SIZE_MAX) const
        -> std::vector<const topic_record*> {
        std::vector<const topic_record*> out;
        for (auto it = _topic_index.upper_bound(
                 std::pair{std::string(account), std::string(start_after)});
             it != _topic_index.end() && it->first.first == account && out.size() < limit; ++it) {
            out.push_back(topic_by_id(it->second));
        }
        return out;
    }

    [[nodiscard]] auto find_subscription(std::uint64_t id) const -> const subscription_record* {
        const auto t = _subscription_index.find(id);
        if (t == _subscription_index.end()) {
            return nullptr;
        }
        const auto it = _subscriptions.find(std::pair{t->second, id});
        return it == _subscriptions.end() ? nullptr : &it->second;
    }

    /// A topic's subscriptions by id.
    [[nodiscard]] auto subscriptions_of(std::uint64_t topic_id) const
        -> std::vector<const subscription_record*> {
        std::vector<const subscription_record*> out;
        for (auto it = _subscriptions.lower_bound(std::pair{topic_id, std::uint64_t{0}});
             it != _subscriptions.end() && it->first.first == topic_id; ++it) {
            out.push_back(&it->second);
        }
        return out;
    }

    /// Every subscription by id, after `after_id`, at most `limit`
    /// (ListSubscriptions pages through them).
    [[nodiscard]] auto subscriptions_after(std::uint64_t after_id, std::size_t limit) const
        -> std::vector<const subscription_record*> {
        std::vector<const subscription_record*> out;
        for (auto it = _subscription_index.upper_bound(after_id);
             it != _subscription_index.end() && out.size() < limit; ++it) {
            out.push_back(&_subscriptions.at(std::pair{it->second, it->first}));
        }
        return out;
    }

    /// The subscriptions one delivery partition serves.
    [[nodiscard]] auto subscriptions_in(const delivery_partition& p) const
        -> std::vector<const subscription_record*> {
        std::vector<const subscription_record*> out;
        const auto* t = topic_by_id(p._topic_id);
        if (t == nullptr) {
            return out;
        }
        for (const auto* s : subscriptions_of(p._topic_id)) {
            if (bucket_of(*t, s->_id) == p._bucket) {
                out.push_back(s);
            }
        }
        return out;
    }

    /// The bucket a subscription falls in.
    [[nodiscard]] static auto bucket_of(const topic_record& t, std::uint64_t subscription_id)
        -> std::uint32_t {
        return static_cast<std::uint32_t>(subscription_id % t._delivery_buckets);
    }

    [[nodiscard]] auto partition(std::uint64_t topic_id, std::uint32_t partition) const
        -> const partition_state* {
        const auto it = _partitions.find(std::pair{topic_id, partition});
        return it == _partitions.end() ? nullptr : &it->second;
    }

    [[nodiscard]] auto lease(const delivery_partition& p) const -> const lease_record* {
        const auto it = _leases.find(p);
        return it == _leases.end() ? nullptr : &it->second;
    }

    /// A subscription's last delivered sequence in a log partition; 0 when
    /// nothing has been delivered.
    [[nodiscard]] auto cursor(std::uint64_t subscription_id, std::uint32_t partition) const
        -> std::uint64_t {
        const auto it = _cursors.find(cursor_key{subscription_id, partition});
        return it == _cursors.end() ? 0 : it->second;
    }

    /// A subscription's pending retries in a log partition, by sequence.
    [[nodiscard]] auto retries_of(std::uint64_t subscription_id, std::uint32_t partition) const
        -> std::vector<std::pair<std::uint64_t, retry_record>> {
        std::vector<std::pair<std::uint64_t, retry_record>> out;
        for (auto it = _retries.lower_bound(retry_key{subscription_id, partition, 0});
             it != _retries.end() && std::get<0>(it->first) == subscription_id &&
             std::get<1>(it->first) == partition;
             ++it) {
            out.emplace_back(std::get<2>(it->first), it->second);
        }
        return out;
    }

    [[nodiscard]] auto find_dedup(std::uint64_t topic_id, std::string_view dedup_id) const
        -> const dedup_record* {
        const auto it = _dedup.find(std::pair{topic_id, std::string(dedup_id)});
        return it == _dedup.end() ? nullptr : &it->second;
    }

    [[nodiscard]] auto topic_count() const noexcept -> std::size_t { return _topics.size(); }
    [[nodiscard]] auto subscription_count() const noexcept -> std::size_t {
        return _subscriptions.size();
    }
    [[nodiscard]] auto next_topic_id() const noexcept -> std::uint64_t { return _next_topic_id; }
    [[nodiscard]] auto store() const noexcept -> record_segment_store* { return _store; }

    // ---- snapshot codec ---------------------------------------------------

    static constexpr std::uint8_t snapshot_version = 1;

    [[nodiscard]] auto serialize() const -> std::vector<std::byte> {
        codec::writer w;
        w.u8(snapshot_version)
            .u64(_next_topic_id)
            .u64(_next_subscription_id)
            .u64(_next_lease_token);
        w.u32(static_cast<std::uint32_t>(_topics.size()));
        for (const auto& [id, t] : _topics) {
            w.u64(t._id).str(t._account).str(t._name).boolean(t._fifo).u32(t._partitions);
            w.u32(t._delivery_buckets).i64(t._created_ms).strings(t._attributes).strings(t._tags);
        }
        w.u32(static_cast<std::uint32_t>(_subscriptions.size()));
        for (const auto& [key, s] : _subscriptions) {
            w.u64(s._id).u64(s._topic_id).str(s._protocol).str(s._endpoint).str(s._owner);
            w.strings(s._attributes).boolean(s._confirmed).str(s._token).i64(s._token_expires_ms);
            w.i64(s._created_ms);
        }
        w.u32(static_cast<std::uint32_t>(_partitions.size()));
        for (const auto& [key, p] : _partitions) {
            w.u64(key.first).u32(key.second).u64(p._last_seq).i64(p._last_timestamp_ms);
            w.u32(static_cast<std::uint32_t>(p._sealed.size()));
            for (const auto& d : p._sealed) {
                w.raw(encode_segment_descriptor(d));
            }
            const auto act = active_descriptor(publish_log_stream(key.first, key.second));
            w.boolean(act.has_value());
            if (act) {
                w.raw(encode_segment_descriptor(*act));
            }
        }
        w.u32(static_cast<std::uint32_t>(_dedup.size()));
        for (const auto& [key, d] : _dedup) {
            w.u64(key.first).str(key.second).str(d._message_id).u32(d._partition).u64(d._seq);
            w.i64(d._expires_ms);
        }
        w.u32(static_cast<std::uint32_t>(_leases.size()));
        for (const auto& [key, l] : _leases) {
            detail::put(w, key);
            w.str(l._owner).u64(l._token).i64(l._expires_ms);
        }
        w.u32(static_cast<std::uint32_t>(_cursors.size()));
        for (const auto& [key, seq] : _cursors) {
            w.u64(key.first).u32(key.second).u64(seq);
        }
        w.u32(static_cast<std::uint32_t>(_retries.size()));
        for (const auto& [key, r] : _retries) {
            w.u64(std::get<0>(key)).u32(std::get<1>(key)).u64(std::get<2>(key));
            w.u32(r._attempt).i64(r._next_ms);
        }
        return w.take();
    }

private:
    auto deserialize(std::span<const std::byte> blob,
                     std::vector<record_segment_descriptor>& active) -> void {
        codec::reader r(blob);
        if (r.u8() != snapshot_version) {
            throw sns_codec_error("sns codec: unknown snapshot version");
        }
        _next_topic_id = r.u64();
        _next_subscription_id = r.u64();
        _next_lease_token = r.u64();
        auto n = r.count(8);
        for (std::uint32_t i = 0; i < n; ++i) {
            topic_record t;
            t._id = r.u64();
            t._account = r.str();
            t._name = r.str();
            t._fifo = r.boolean();
            t._partitions = r.u32();
            t._delivery_buckets = r.u32();
            t._created_ms = r.i64();
            t._attributes = r.strings();
            t._tags = r.strings();
            if (t._partitions == 0 || t._delivery_buckets == 0) {
                throw sns_codec_error("sns codec: topic without partitions or buckets");
            }
            _topic_index[std::pair{t._account, t._name}] = t._id;
            _topics.insert_or_assign(t._id, std::move(t));
        }
        n = r.count(16);
        for (std::uint32_t i = 0; i < n; ++i) {
            subscription_record s;
            s._id = r.u64();
            s._topic_id = r.u64();
            s._protocol = r.str();
            s._endpoint = r.str();
            s._owner = r.str();
            s._attributes = r.strings();
            s._confirmed = r.boolean();
            s._token = r.str();
            s._token_expires_ms = r.i64();
            s._created_ms = r.i64();
            _subscription_index[s._id] = s._topic_id;
            _subscriptions.insert_or_assign(std::pair{s._topic_id, s._id}, std::move(s));
        }
        n = r.count(12);
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto topic = r.u64();
            const auto part = r.u32();
            partition_state p;
            p._last_seq = r.u64();
            p._last_timestamp_ms = r.i64();
            const auto segs = r.count(1);
            for (std::uint32_t j = 0; j < segs; ++j) {
                p._sealed.push_back(descriptor(r));
            }
            if (r.boolean()) {
                active.push_back(descriptor(r));
            }
            _partitions.insert_or_assign(std::pair{topic, part}, std::move(p));
        }
        n = r.count(8);
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto topic = r.u64();
            auto id = r.str();
            dedup_record d;
            d._message_id = r.str();
            d._partition = r.u32();
            d._seq = r.u64();
            d._expires_ms = r.i64();
            _dedup.insert_or_assign(std::pair{topic, std::move(id)}, std::move(d));
        }
        n = r.count(16);
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto key = detail::get_partition(r);
            lease_record l;
            l._owner = r.str();
            l._token = r.u64();
            l._expires_ms = r.i64();
            _leases.insert_or_assign(key, std::move(l));
        }
        n = r.count(20);
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto sub = r.u64();
            const auto part = r.u32();
            _cursors.insert_or_assign(cursor_key{sub, part}, r.u64());
        }
        n = r.count(32);
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto sub = r.u64();
            const auto part = r.u32();
            const auto seq = r.u64();
            retry_record rr;
            rr._attempt = r.u32();
            rr._next_ms = r.i64();
            _retries.insert_or_assign(retry_key{sub, part, seq}, rr);
        }
        r.expect_end("snapshot");
    }

    static auto descriptor(codec::reader& r) -> record_segment_descriptor {
        auto d = decode_segment_descriptor(r.rest());
        if (!d) {
            throw sns_codec_error("sns codec: bad segment descriptor");
        }
        return std::move(*d);
    }

    [[nodiscard]] auto active_descriptor(const std::string& stream) const
        -> std::optional<record_segment_descriptor> {
        if (_store == nullptr) {
            return std::nullopt;
        }
        auto local = _store->local_segments(stream);
        if (local.empty() || local.back()._sealed) {
            return std::nullopt;
        }
        return std::move(local.back());
    }

    static auto refuse(apply_status s, std::string detail = {}) -> apply_result {
        return {._status = s, ._detail = std::move(detail)};
    }

    auto topic_at(std::string_view account, std::string_view name) -> topic_record* {
        return const_cast<topic_record*>(std::as_const(*this).find_topic(account, name));
    }

    auto subscription_at(std::uint64_t id) -> subscription_record* {
        return const_cast<subscription_record*>(std::as_const(*this).find_subscription(id));
    }

    // ---- topics -------------------------------------------------------------

    auto apply_one(const create_topic_command& c) -> apply_result {
        if (const auto* t = find_topic(c._account, c._name)) {
            if (t->_attributes != c._attributes || t->_fifo != c._fifo) {
                return refuse(apply_status::topic_exists_with_different_attributes);
            }
            if (t->_tags != c._tags) {
                return refuse(apply_status::topic_exists_with_different_tags);
            }
            return {._id = t->_id, ._existing = true};
        }
        if (c._partitions == 0 || c._partitions > k_max_partitions || c._delivery_buckets == 0 ||
            c._delivery_buckets > k_max_delivery_buckets) {
            return refuse(apply_status::invalid_parameter, "partitions or delivery buckets");
        }
        topic_record t;
        t._id = ++_next_topic_id;
        t._account = c._account;
        t._name = c._name;
        t._fifo = c._fifo;
        t._partitions = c._partitions;
        t._delivery_buckets = c._delivery_buckets;
        t._created_ms = c._now_ms;
        t._attributes = c._attributes;
        t._tags = c._tags;
        for (std::uint32_t p = 0; p < t._partitions; ++p) {
            _partitions.emplace(std::pair{t._id, p}, partition_state{});
        }
        const auto id = t._id;
        _topic_index[std::pair{t._account, t._name}] = id;
        _topics.emplace(id, std::move(t));
        return {._id = id};
    }

    auto apply_one(const delete_topic_command& c) -> apply_result {
        const auto* t = find_topic(c._account, c._name);
        if (t == nullptr) {
            return {};
        }
        const auto id = t->_id;
        const auto partitions = t->_partitions;
        for (auto it = _subscriptions.lower_bound(std::pair{id, std::uint64_t{0}});
             it != _subscriptions.end() && it->first.first == id;) {
            drop_delivery_state(it->first.second);
            _subscription_index.erase(it->first.second);
            it = _subscriptions.erase(it);
        }
        for (std::uint32_t p = 0; p < partitions; ++p) {
            _partitions.erase(std::pair{id, p});
            if (_store != nullptr) {
                _store->drop_stream(publish_log_stream(id, p));
            }
        }
        std::erase_if(_dedup, [id](const auto& e) { return e.first.first == id; });
        std::erase_if(_leases, [id](const auto& e) { return e.first._topic_id == id; });
        _topic_index.erase(std::pair{c._account, c._name});
        _topics.erase(id);
        return {._id = id};
    }

    auto apply_one(const set_topic_attribute_command& c) -> apply_result {
        auto* t = topic_at(c._account, c._name);
        if (t == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        t->_attributes.insert_or_assign(c._key, c._value);
        return {._id = t->_id};
    }

    auto apply_one(const tag_topic_command& c) -> apply_result {
        auto* t = topic_at(c._account, c._name);
        if (t == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        for (const auto& [k, v] : c._set) {
            t->_tags.insert_or_assign(k, v);
        }
        for (const auto& k : c._remove) {
            t->_tags.erase(k);
        }
        return {._id = t->_id};
    }

    // ---- subscriptions ------------------------------------------------------

    auto apply_one(const subscribe_command& c) -> apply_result {
        const auto* t = find_topic(c._account, c._name);
        if (t == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        for (auto it = _subscriptions.lower_bound(std::pair{t->_id, std::uint64_t{0}});
             it != _subscriptions.end() && it->first.first == t->_id; ++it) {
            auto& s = it->second;
            if (s._protocol != c._protocol || s._endpoint != c._endpoint) {
                continue;
            }
            if (s._attributes != c._attributes) {
                return refuse(apply_status::subscription_exists_with_different_attributes);
            }
            if (!s._confirmed && c._needs_confirmation) {
                s._token = c._token;
                s._token_expires_ms = c._now_ms + k_confirmation_window_ms;
            }
            return {._id = s._id, ._existing = true};
        }
        subscription_record s;
        s._id = ++_next_subscription_id;
        s._topic_id = t->_id;
        s._protocol = c._protocol;
        s._endpoint = c._endpoint;
        s._owner = c._owner;
        s._attributes = c._attributes;
        s._confirmed = !c._needs_confirmation;
        if (c._needs_confirmation) {
            s._token = c._token;
            s._token_expires_ms = c._now_ms + k_confirmation_window_ms;
        }
        s._created_ms = c._now_ms;
        const auto id = s._id;
        _subscription_index[id] = t->_id;
        _subscriptions.emplace(std::pair{t->_id, id}, std::move(s));
        return {._id = id};
    }

    auto apply_one(const confirm_subscription_command& c) -> apply_result {
        const auto* t = find_topic(c._account, c._name);
        if (t == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        if (c._token.empty()) {
            return refuse(apply_status::invalid_token);
        }
        for (auto it = _subscriptions.lower_bound(std::pair{t->_id, std::uint64_t{0}});
             it != _subscriptions.end() && it->first.first == t->_id; ++it) {
            auto& s = it->second;
            if (!s._confirmed && s._token == c._token && c._now_ms < s._token_expires_ms) {
                s._confirmed = true;
                s._token.clear();
                s._token_expires_ms = 0;
                return {._id = s._id};
            }
        }
        return refuse(apply_status::invalid_token);
    }

    auto apply_one(const unsubscribe_command& c) -> apply_result {
        const auto t = _subscription_index.find(c._subscription_id);
        if (t == _subscription_index.end()) {
            return refuse(apply_status::subscription_not_found);
        }
        drop_delivery_state(c._subscription_id);
        _subscriptions.erase(std::pair{t->second, c._subscription_id});
        _subscription_index.erase(t);
        return {._id = c._subscription_id};
    }

    auto apply_one(const set_subscription_attribute_command& c) -> apply_result {
        auto* s = subscription_at(c._subscription_id);
        if (s == nullptr) {
            return refuse(apply_status::subscription_not_found);
        }
        s->_attributes.insert_or_assign(c._key, c._value);
        return {._id = s->_id};
    }

    /// A subscription's cursors and retry state, in every partition.
    auto drop_delivery_state(std::uint64_t subscription_id) -> void {
        std::erase_if(_cursors, [subscription_id](const auto& e) {
            return e.first.first == subscription_id;
        });
        _retries.erase(_retries.lower_bound(retry_key{subscription_id, 0, 0}),
                       _retries.lower_bound(retry_key{subscription_id + 1, 0, 0}));
    }

    // ---- publishing ---------------------------------------------------------

    auto apply_one(const publish_command& c) -> apply_result {
        const auto* t = find_topic(c._account, c._name);
        if (t == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        if (c._entries.empty() || c._entries.size() > k_max_publish_entries) {
            return refuse(apply_status::invalid_parameter, "entries");
        }
        const auto topic_id = t->_id;
        std::erase_if(_dedup, [&](const auto& e) {
            return e.first.first == topic_id && e.second._expires_ms <= c._now_ms;
        });

        apply_result out{._id = topic_id};
        // Accepted entries per partition, appended together in entry order.
        std::map<std::uint32_t, std::vector<std::pair<std::uint64_t, std::vector<std::byte>>>>
            appends;
        std::map<std::uint32_t, std::int64_t> stamps;
        for (const auto& e : c._entries) {
            publish_entry_result r{._partition = e._partition, ._message_id = e._message_id};
            if (e._partition >= t->_partitions || e._message_id.empty() ||
                (t->_fifo && (e._group_id.empty() || e._dedup_id.empty()))) {
                r._status = publish_status::invalid_parameter;
                out._entries.push_back(std::move(r));
                continue;
            }
            if (t->_fifo) {
                if (const auto* d = find_dedup(topic_id, e._dedup_id)) {
                    r._status = publish_status::duplicate;
                    r._partition = d->_partition;
                    r._seq = d->_seq;
                    r._message_id = d->_message_id;
                    out._entries.push_back(std::move(r));
                    continue;
                }
            }
            auto& p = _partitions[std::pair{topic_id, e._partition}];
            r._seq = ++p._last_seq;
            p._last_timestamp_ms = std::max(p._last_timestamp_ms, c._now_ms);
            stamps[e._partition] = p._last_timestamp_ms;
            if (t->_fifo) {
                _dedup.insert_or_assign(std::pair{topic_id, e._dedup_id},
                                        dedup_record{._message_id = e._message_id,
                                                     ._partition = e._partition,
                                                     ._seq = r._seq,
                                                     ._expires_ms = c._now_ms + k_dedup_window_ms});
            }
            appends[e._partition].emplace_back(
                r._seq, encode_stored_message(e._message_id, t->_fifo ? e._group_id : "",
                                              t->_fifo ? e._dedup_id : "", e._payload));
            out._entries.push_back(std::move(r));
        }
        if (_store != nullptr && !appends.empty()) {
            for (const auto& [part, records] : appends) {
                std::vector<segment_record_view> views;
                views.reserve(records.size());
                for (const auto& [seq, bytes] : records) {
                    views.push_back({._seq = seq, ._timestamp_ms = stamps[part], ._data = bytes});
                }
                auto res = _store->append(publish_log_stream(topic_id, part), views);
                auto& sealed = _partitions[std::pair{topic_id, part}]._sealed;
                sealed.insert(sealed.end(), std::make_move_iterator(res._sealed.begin()),
                              std::make_move_iterator(res._sealed.end()));
            }
            _store->barrier();
        }
        return out;
    }

    // ---- delivery leases, cursors and retries -------------------------------

    [[nodiscard]] auto valid_partition(const delivery_partition& p) const -> bool {
        const auto* t = topic_by_id(p._topic_id);
        return t != nullptr && p._partition < t->_partitions && p._bucket < t->_delivery_buckets;
    }

    auto apply_one(const acquire_lease_command& c) -> apply_result {
        if (!valid_partition(c._partition)) {
            return refuse(apply_status::topic_not_found);
        }
        if (c._owner.empty() || c._duration_ms <= 0) {
            return refuse(apply_status::invalid_parameter, "owner or duration");
        }
        auto it = _leases.find(c._partition);
        if (it != _leases.end() && it->second._owner != c._owner &&
            it->second._expires_ms > c._now_ms) {
            return refuse(apply_status::lease_held, it->second._owner);
        }
        if (it != _leases.end() && it->second._owner == c._owner &&
            it->second._expires_ms > c._now_ms) {
            // The holder asking again (a restart under the same name) keeps
            // its token, so nothing it committed is fenced off.
            it->second._expires_ms = c._now_ms + c._duration_ms;
            return {._id = it->second._token, ._existing = true};
        }
        lease_record l{._owner = c._owner,
                       ._token = ++_next_lease_token,
                       ._expires_ms = c._now_ms + c._duration_ms};
        const auto token = l._token;
        _leases.insert_or_assign(c._partition, std::move(l));
        return {._id = token};
    }

    [[nodiscard]] auto holds(const delivery_partition& p, std::string_view owner,
                             std::uint64_t token) const -> bool {
        const auto it = _leases.find(p);
        return it != _leases.end() && it->second._token == token && it->second._owner == owner;
    }

    auto apply_one(const renew_lease_command& c) -> apply_result {
        if (!holds(c._partition, c._owner, c._token)) {
            return refuse(apply_status::lease_lost);
        }
        if (c._duration_ms <= 0) {
            return refuse(apply_status::invalid_parameter, "duration");
        }
        _leases[c._partition]._expires_ms = c._now_ms + c._duration_ms;
        return {._id = c._token};
    }

    auto apply_one(const release_lease_command& c) -> apply_result {
        if (!holds(c._partition, c._owner, c._token)) {
            return refuse(apply_status::lease_lost);
        }
        _leases.erase(c._partition);
        return {._id = c._token};
    }

    auto apply_one(const commit_delivery_command& c) -> apply_result {
        if (!holds(c._partition, c._owner, c._token)) {
            return refuse(apply_status::lease_lost);
        }
        const auto* t = topic_by_id(c._partition._topic_id);
        const auto* p = partition(c._partition._topic_id, c._partition._partition);
        if (t == nullptr || p == nullptr) {
            return refuse(apply_status::topic_not_found);
        }
        // Validate everything first: the commit is all or nothing.
        const auto served = [&](std::uint64_t sub, std::uint64_t seq) {
            const auto* s = find_subscription(sub);
            return s != nullptr && s->_topic_id == t->_id &&
                   bucket_of(*t, sub) == c._partition._bucket && seq >= 1 && seq <= p->_last_seq;
        };
        for (const auto& u : c._cursors) {
            if (!served(u._subscription_id, u._seq)) {
                return refuse(apply_status::invalid_parameter, "cursor");
            }
        }
        for (const auto& u : c._retries) {
            if (!served(u._subscription_id, u._seq)) {
                return refuse(apply_status::invalid_parameter, "retry");
            }
        }
        for (const auto& u : c._cleared) {
            if (!served(u._subscription_id, u._seq)) {
                return refuse(apply_status::invalid_parameter, "cleared retry");
            }
        }
        const auto part = c._partition._partition;
        for (const auto& u : c._cursors) {
            auto& cur = _cursors[cursor_key{u._subscription_id, part}];
            cur = std::max(cur, u._seq);
        }
        for (const auto& u : c._cleared) {
            _retries.erase(retry_key{u._subscription_id, part, u._seq});
        }
        for (const auto& u : c._retries) {
            _retries.insert_or_assign(retry_key{u._subscription_id, part, u._seq},
                                      retry_record{._attempt = u._attempt, ._next_ms = u._next_ms});
        }
        return {._id = c._token};
    }

    record_segment_store* _store = nullptr;
    segment_fetcher _fetch;
    LogIndex _last_applied_index{};

    std::uint64_t _next_topic_id = 0;
    std::uint64_t _next_subscription_id = 0;
    std::uint64_t _next_lease_token = 0;
    std::map<std::uint64_t, topic_record> _topics;
    /// (account, name) -> topic id. Rebuilt from `_topics` on restore.
    std::map<std::pair<std::string, std::string>, std::uint64_t> _topic_index;
    /// (topic id, subscription id) -> subscription.
    std::map<std::pair<std::uint64_t, std::uint64_t>, subscription_record> _subscriptions;
    /// subscription id -> topic id. Rebuilt on restore.
    std::map<std::uint64_t, std::uint64_t> _subscription_index;
    std::map<std::pair<std::uint64_t, std::uint32_t>, partition_state> _partitions;
    /// (topic id, dedup id) -> the accepted message.
    std::map<std::pair<std::uint64_t, std::string>, dedup_record> _dedup;
    std::map<delivery_partition, lease_record> _leases;
    std::map<cursor_key, std::uint64_t> _cursors;
    std::map<retry_key, retry_record> _retries;
};

}  // namespace kythira::sns
