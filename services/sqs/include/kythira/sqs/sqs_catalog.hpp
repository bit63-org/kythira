// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_catalog.hpp
/// @brief The SQS queue catalog: its keys, records and Raft entries
///        (`.kiro/specs/sqs-compatible-queues/` Requirements 4.1, 4.2).
///
/// The catalog names every queue: per account and name, a `queue_record`
/// with the queue's id, settings, tags and partition count. It lives in the
/// same multi_raft key space as the queue partitions and is applied by the
/// same `sqs_queue_state_machine`, which tells a catalog entry from a
/// partition entry by its format byte.
///
/// | Key | Holds |
/// |---|---|
/// | `\0meta/sqs/next-id` | the next queue id (never decremented) |
/// | `\0meta/sqs/queues/<account>/<name>` | a `queue_record` |
/// | `\0meta/sqs/deleted/<account>/<name>` | when a queue of that name was deleted |
///
/// Every catalog key sorts before every partition key (`\0` < `q`) and the
/// state machine splits only at partition routing keys, so the catalog is
/// one contiguous range in one group: the group holding `next-id` holds
/// every record and allocates ids without a cross-group transaction. Ids
/// come from the counter, so a queue created again after deletion gets a
/// new id, new routing keys and a new receipt-handle scope, and never sees
/// an old message (Requirement 4.2).
///
/// What `apply()` decides is what races: whether a name is taken, whether
/// it was deleted too recently (`QueueDeletedRecently`), whether a purge is
/// still cooling down (`PurgeQueueInProgress`), the tag cap. What needs the
/// compatibility profile or another queue (attribute ranges, a redrive
/// target) the front end checks before proposing, and settings changes are
/// compare-and-set on the record's `_version`, so a SetQueueAttributes and
/// an AddPermission that read the same record cannot overwrite each other:
/// the second is answered `conflict` and the front end re-reads and
/// retries. Cooldowns are carried in the command, as the leader's front
/// end read them from its profile, and judged against the command's
/// `_now_ms`, never a replica's clock.

#include <kythira/sqs/sqs_queue_attributes.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs {

// ---- keys -----------------------------------------------------------------

namespace catalog_keys {

/// `\0meta/sqs/`, with its leading NUL.
[[nodiscard]] inline auto prefix() -> const std::string& {
    static const std::string p("\0meta/sqs/", 10);
    return p;
}

[[nodiscard]] inline auto next_id() -> std::string {
    return prefix() + "next-id";
}

[[nodiscard]] inline auto queues_prefix(std::string_view account) -> std::string {
    return prefix() + "queues/" + std::string(account) + "/";
}

[[nodiscard]] inline auto queue(std::string_view account, std::string_view name) -> std::string {
    return queues_prefix(account) + std::string(name);
}

[[nodiscard]] inline auto deleted(std::string_view account, std::string_view name) -> std::string {
    return prefix() + "deleted/" + std::string(account) + "/" + std::string(name);
}

/// Every message move task (Requirement 7.3).
[[nodiscard]] inline auto moves_prefix() -> std::string {
    return prefix() + "moves/";
}

/// The move tasks of one source queue, oldest first.
[[nodiscard]] inline auto moves_of(std::string_view account, std::string_view name) -> std::string {
    return moves_prefix() + std::string(account) + "/" + std::string(name) + "/";
}

/// One move task, by when it started (16 hex digits, so key order is
/// start order).
[[nodiscard]] inline auto move(std::string_view account, std::string_view name,
                               std::uint64_t started_ms) -> std::string {
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string h(16, '0');
    for (int i = 15; i >= 0; --i) {
        h[static_cast<std::size_t>(i)] = hex[started_ms & 0xFU];
        started_ms >>= 4U;
    }
    return moves_of(account, name) + h;
}

/// An account the catalog can key on: non-empty, at most 64 bytes, no '/'
/// or NUL (12 digits from IAM or a static key in practice).
[[nodiscard]] inline auto valid_account(std::string_view account) -> bool {
    return !account.empty() && account.size() <= 64 &&
           account.find('/') == std::string_view::npos &&
           account.find('\0') == std::string_view::npos;
}

}  // namespace catalog_keys

/// SQS's cap on the tags of one queue.
inline constexpr std::size_t k_max_queue_tags = 50;

/// Partitions a new queue starts with (design "Partitions", open question
/// 1): a standard queue four (it grows with its send rate, up to
/// `k_max_partitions`), a FIFO queue one, a high-throughput FIFO queue
/// sixteen. High throughput is SQS's: `FifoThroughputLimit` of
/// `perMessageGroupId` with `DeduplicationScope` of `messageGroup`. Only
/// then may a FIFO queue span partitions, because its deduplication
/// records are per partition and a group always maps to one. A FIFO
/// queue's count is fixed at creation: changing it would move groups
/// between partitions and break their order.
[[nodiscard]] inline auto high_throughput_fifo(const queue_settings& s) -> bool {
    return s._fifo && s._throughput_limit == "perMessageGroupId" &&
           s._dedup_scope == "messageGroup";
}

inline constexpr std::uint16_t k_max_partitions = 64;

[[nodiscard]] inline auto initial_partitions(const queue_settings& s) -> std::uint16_t {
    if (!s._fifo) {
        return 4;
    }
    return high_throughput_fifo(s) ? 16 : 1;
}

// ---- records --------------------------------------------------------------

struct queue_record {
    std::uint64_t _id = 0;
    std::string _account;
    std::string _name;
    queue_settings _settings;
    std::map<std::string, std::string> _tags;
    std::uint64_t _created_ms = 0;
    /// When an attribute last changed (SQS's `LastModifiedTimestamp`;
    /// tags do not count, as on SQS).
    std::uint64_t _modified_ms = 0;
    /// Bumped by every change, tags included; settings changes compare it.
    std::uint64_t _version = 0;
    std::uint16_t _partitions = 1;
    /// When the last PurgeQueue was accepted, 0 for never.
    std::uint64_t _last_purge_ms = 0;

    friend auto operator==(const queue_record&, const queue_record&) -> bool = default;

    /// What a partition command needs from this record.
    [[nodiscard]] auto target(std::uint16_t partition) const -> queue_target {
        return queue_target{_id, partition, _settings._fifo, _settings._retention_s};
    }
};

namespace catalog_detail {

using command_detail::put_le;
using command_detail::put_str;
using command_detail::put_u8;
using command_detail::reader;

inline constexpr std::uint8_t k_record_format = 1;
/// Catalog entries share the state machine's log with partition entries
/// (format 1), so they take a format byte of their own.
inline constexpr std::uint8_t k_command_format = 0x40;
inline constexpr std::uint8_t k_result_format = 0x40;

inline void put_settings(std::string& out, const queue_settings& s) {
    put_le(out, s._delay_s);
    put_le(out, s._max_message_bytes);
    put_le(out, s._retention_s);
    put_le(out, s._wait_s);
    put_le(out, s._visibility_s);
    put_str(out, s._policy);
    put_str(out, s._redrive_policy);
    put_str(out, s._redrive_allow_policy);
    put_str(out, s._kms_key_id);
    put_le(out, s._kms_reuse_s);
    put_u8(out, s._sqs_managed_sse ? 1 : 0);
    put_u8(out, s._fifo ? 1 : 0);
    put_u8(out, s._content_dedup ? 1 : 0);
    put_str(out, s._dedup_scope);
    put_str(out, s._throughput_limit);
}

inline auto get_settings(reader& r, queue_settings& s) -> bool {
    return r.le(s._delay_s) && r.le(s._max_message_bytes) && r.le(s._retention_s) &&
           r.le(s._wait_s) && r.le(s._visibility_s) && r.str(s._policy) &&
           r.str(s._redrive_policy) && r.str(s._redrive_allow_policy) && r.str(s._kms_key_id) &&
           r.le(s._kms_reuse_s) && r.boolean(s._sqs_managed_sse) && r.boolean(s._fifo) &&
           r.boolean(s._content_dedup) && r.str(s._dedup_scope) && r.str(s._throughput_limit);
}

inline void put_tags(std::string& out, const std::map<std::string, std::string>& tags) {
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(tags.size()));
    for (const auto& [k, v] : tags) {
        put_str(out, k);
        put_str(out, v);
    }
}

inline auto get_tags(reader& r, std::map<std::string, std::string>& tags) -> bool {
    std::size_t n = 0;
    if (!r.count(n)) {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i) {
        std::string k;
        std::string v;
        if (!r.str(k) || !r.str(v)) {
            return false;
        }
        tags[std::move(k)] = std::move(v);
    }
    return true;
}

inline void put_strings(std::string& out, const std::vector<std::string>& v) {
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) {
        put_str(out, s);
    }
}

inline auto get_strings(reader& r, std::vector<std::string>& v) -> bool {
    std::size_t n = 0;
    if (!r.count(n)) {
        return false;
    }
    v.resize(n);
    for (auto& s : v) {
        if (!r.str(s)) {
            return false;
        }
    }
    return true;
}

inline void put_record(std::string& out, const queue_record& q) {
    put_le(out, q._id);
    put_str(out, q._account);
    put_str(out, q._name);
    put_settings(out, q._settings);
    put_tags(out, q._tags);
    put_le(out, q._created_ms);
    put_le(out, q._modified_ms);
    put_le(out, q._version);
    put_le(out, q._partitions);
    put_le(out, q._last_purge_ms);
}

inline auto get_record(reader& r, queue_record& q) -> bool {
    return r.le(q._id) && r.str(q._account) && r.str(q._name) && get_settings(r, q._settings) &&
           get_tags(r, q._tags) && r.le(q._created_ms) && r.le(q._modified_ms) &&
           r.le(q._version) && r.le(q._partitions) && r.le(q._last_purge_ms);
}

}  // namespace catalog_detail

[[nodiscard]] inline auto encode_queue_record(const queue_record& q) -> std::string {
    std::string out;
    catalog_detail::put_u8(out, catalog_detail::k_record_format);
    catalog_detail::put_record(out, q);
    return out;
}

[[nodiscard]] inline auto decode_queue_record(std::string_view in) -> std::optional<queue_record> {
    catalog_detail::reader r(in);
    std::uint8_t format = 0;
    queue_record q;
    if (!r.u8(format) || format != catalog_detail::k_record_format ||
        !catalog_detail::get_record(r, q) || !r.done()) {
        return std::nullopt;
    }
    return q;
}

// ---- entries --------------------------------------------------------------

/// One change to the catalog.
/// A message move task (StartMessageMoveTask): messages go from a
/// dead-letter queue back to their sources or to one destination, at a
/// rate, moved by the catalog leader's worker (`sqs_workers.hpp`), which a
/// new leader resumes because the task lives here.
struct move_task {
    enum class state : std::uint8_t {
        running = 0,
        completed = 1,
        cancelling = 2,
        cancelled = 3,
        failed = 4,
    };

    std::string _account;
    /// The source (dead-letter) queue's name.
    std::string _name;
    std::uint64_t _started_ms = 0;
    state _status = state::running;
    std::string _source_arn;
    /// Empty: each message goes back to the queue it was moved from.
    std::string _destination_arn;
    /// Messages per second; 0 when not given (the system's rate).
    std::uint32_t _rate = 0;
    std::uint64_t _moved = 0;
    std::uint64_t _to_move = 0;
    std::string _failure;

    [[nodiscard]] auto active() const -> bool {
        return _status == state::running || _status == state::cancelling;
    }

    friend auto operator==(const move_task&, const move_task&) -> bool = default;
};

/// The most recent tasks a source queue keeps (ListMessageMoveTasks shows
/// up to 10).
inline constexpr std::size_t k_max_move_tasks = 10;

[[nodiscard]] inline auto move_state_name(move_task::state s) -> std::string_view {
    switch (s) {
        case move_task::state::running:
            return "RUNNING";
        case move_task::state::completed:
            return "COMPLETED";
        case move_task::state::cancelling:
            return "CANCELLING";
        case move_task::state::cancelled:
            return "CANCELLED";
        case move_task::state::failed:
            return "FAILED";
    }
    return "FAILED";
}

namespace catalog_detail {

inline void put_move(std::string& out, const move_task& m) {
    put_str(out, m._account);
    put_str(out, m._name);
    put_le(out, m._started_ms);
    put_u8(out, static_cast<std::uint8_t>(m._status));
    put_str(out, m._source_arn);
    put_str(out, m._destination_arn);
    put_le(out, m._rate);
    put_le(out, m._moved);
    put_le(out, m._to_move);
    put_str(out, m._failure);
}

[[nodiscard]] inline auto get_move(reader& r, move_task& m) -> bool {
    std::uint8_t st = 0;
    if (!r.str(m._account) || !r.str(m._name) || !r.le(m._started_ms) || !r.u8(st) ||
        st > static_cast<std::uint8_t>(move_task::state::failed) || !r.str(m._source_arn) ||
        !r.str(m._destination_arn) || !r.le(m._rate) || !r.le(m._moved) || !r.le(m._to_move) ||
        !r.str(m._failure)) {
        return false;
    }
    m._status = static_cast<move_task::state>(st);
    return true;
}

}  // namespace catalog_detail

[[nodiscard]] inline auto encode_move_task(const move_task& m) -> std::string {
    std::string out;
    catalog_detail::put_u8(out, catalog_detail::k_record_format);
    catalog_detail::put_move(out, m);
    return out;
}

[[nodiscard]] inline auto decode_move_task(std::string_view in) -> std::optional<move_task> {
    catalog_detail::reader r(in);
    std::uint8_t format = 0;
    move_task m;
    if (!r.u8(format) || format != catalog_detail::k_record_format ||
        !catalog_detail::get_move(r, m) || !r.done()) {
        return std::nullopt;
    }
    return m;
}

struct catalog_command {
    enum class kind : std::uint8_t {
        /// CreateQueue: `_settings`, `_tags`, `_partitions`; answered
        /// `exists` with the stored record when the name is taken with the
        /// same settings, `name_exists` when with others.
        create = 1,
        /// SetQueueAttributes, AddPermission, RemovePermission: replaces
        /// the settings when the record is still at `_expected_version`.
        set_settings = 2,
        /// TagQueue: adds or replaces `_tags`.
        tag = 3,
        /// UntagQueue: removes `_tag_keys`; a key not present is ignored.
        untag = 4,
        /// DeleteQueue: removes the record and starts the name's cooldown.
        /// The reply carries the record so the front end drops its
        /// partitions.
        delete_ = 5,
        /// PurgeQueue: accepted at most once per cooldown; the reply
        /// carries the record so the front end purges its partitions.
        purge = 6,
        /// StartMessageMoveTask on queue `_name`: `_move` (started now);
        /// `move_in_progress` while another of the queue's tasks is active.
        /// The oldest finished tasks beyond `k_max_move_tasks` go.
        move_start = 7,
        /// The worker's progress on task `_move._started_ms`: adds
        /// `_move._moved`, and takes `_move._status` and `_move._failure`
        /// when the status is not running. Only an active task changes.
        move_update = 8,
        /// CancelMessageMoveTask: a running task becomes cancelling (the
        /// worker then cancels it); `does_not_exist` for any other.
        move_cancel = 9,
        /// A standard queue's send rate grew: its partition count rises to
        /// `_partitions` (never falls, never past `k_max_partitions`; FIFO
        /// queues never grow). New sends spread over all of them.
        grow = 10,
    };

    kind _op = kind::create;
    std::string _account;
    std::string _name;
    /// The leader's clock: creation and modification times and cooldowns
    /// are judged against it.
    std::uint64_t _now_ms = 0;
    queue_settings _settings;
    std::map<std::string, std::string> _tags;
    std::vector<std::string> _tag_keys;
    std::uint16_t _partitions = 1;
    std::uint64_t _expected_version = 0;
    /// create: how long after a deletion the name stays refused.
    /// purge: how long after a purge another is refused.
    std::uint64_t _cooldown_ms = 0;
    /// The move_* kinds' task.
    move_task _move;

    friend auto operator==(const catalog_command&, const catalog_command&) -> bool = default;
};

struct catalog_result {
    enum class status : std::uint8_t {
        ok = 0,
        /// create: the queue exists with the same settings (SQS answers
        /// with its URL, as for a new queue).
        exists = 1,
        /// create: the queue exists with other settings.
        name_exists = 2,
        /// create: a queue of the name was deleted within the cooldown.
        deleted_recently = 3,
        does_not_exist = 4,
        /// set_settings: the record changed since the front end read it.
        conflict = 5,
        /// tag: the queue would have more than `k_max_queue_tags` tags.
        too_many_tags = 6,
        /// purge: the previous purge is within the cooldown.
        purge_in_progress = 7,
        /// The entry did not decode, or is for a range this group does
        /// not hold.
        malformed = 8,
        /// move_start: another task of the queue is active.
        move_in_progress = 9,
    };

    status _outcome = status::ok;
    /// The record after the change (or as found, for `exists`; as it was,
    /// for delete and purge).
    std::optional<queue_record> _record;
    /// The move_* kinds: the task after the change.
    std::optional<move_task> _move;

    friend auto operator==(const catalog_result&, const catalog_result&) -> bool = default;
};

/// Whether `entry` is a catalog entry rather than a partition entry.
[[nodiscard]] inline auto is_catalog_entry(std::string_view entry) -> bool {
    return !entry.empty() &&
           static_cast<std::uint8_t>(entry.front()) == catalog_detail::k_command_format;
}

[[nodiscard]] inline auto encode_catalog_command(const catalog_command& c) -> std::string {
    using namespace catalog_detail;
    std::string out;
    put_u8(out, k_command_format);
    put_u8(out, static_cast<std::uint8_t>(c._op));
    put_str(out, c._account);
    put_str(out, c._name);
    put_le(out, c._now_ms);
    put_settings(out, c._settings);
    put_tags(out, c._tags);
    put_strings(out, c._tag_keys);
    put_le(out, c._partitions);
    put_le(out, c._expected_version);
    put_le(out, c._cooldown_ms);
    put_move(out, c._move);
    return out;
}

[[nodiscard]] inline auto decode_catalog_command(std::string_view in)
    -> std::optional<catalog_command> {
    using namespace catalog_detail;
    reader r(in);
    std::uint8_t format = 0;
    std::uint8_t op = 0;
    catalog_command c;
    if (!r.u8(format) || format != k_command_format || !r.u8(op) || op < 1 || op > 10) {
        return std::nullopt;
    }
    c._op = static_cast<catalog_command::kind>(op);
    if (!r.str(c._account) || !r.str(c._name) || !r.le(c._now_ms) ||
        !get_settings(r, c._settings) || !get_tags(r, c._tags) || !get_strings(r, c._tag_keys) ||
        !r.le(c._partitions) || !r.le(c._expected_version) || !r.le(c._cooldown_ms) ||
        !get_move(r, c._move) || !r.done()) {
        return std::nullopt;
    }
    return c;
}

[[nodiscard]] inline auto encode_catalog_result(const catalog_result& c) -> std::string {
    using namespace catalog_detail;
    std::string out;
    put_u8(out, k_result_format);
    put_u8(out, static_cast<std::uint8_t>(c._outcome));
    put_u8(out, c._record ? 1 : 0);
    if (c._record) {
        put_record(out, *c._record);
    }
    put_u8(out, c._move ? 1 : 0);
    if (c._move) {
        put_move(out, *c._move);
    }
    return out;
}

[[nodiscard]] inline auto decode_catalog_result(std::string_view in)
    -> std::optional<catalog_result> {
    using namespace catalog_detail;
    reader r(in);
    std::uint8_t format = 0;
    std::uint8_t outcome = 0;
    bool has_record = false;
    catalog_result c;
    if (!r.u8(format) || format != k_result_format || !r.u8(outcome) || outcome > 9 ||
        !r.boolean(has_record)) {
        return std::nullopt;
    }
    c._outcome = static_cast<catalog_result::status>(outcome);
    if (has_record) {
        queue_record q;
        if (!get_record(r, q)) {
            return std::nullopt;
        }
        c._record = std::move(q);
    }
    bool has_move = false;
    if (!r.boolean(has_move)) {
        return std::nullopt;
    }
    if (has_move) {
        move_task m;
        if (!get_move(r, m)) {
            return std::nullopt;
        }
        c._move = std::move(m);
    }
    if (!r.done()) {
        return std::nullopt;
    }
    return c;
}

/// Rewrites the leader clock (`now_ms`) of an encoded catalog or partition
/// entry in place, so the node that proposes an entry stamps it with its
/// own clock even when another node built it (a forwarded proposal):
/// times in committed entries are the proposing leader's (Requirement
/// 5.4). False, and `entry` unchanged, when it is neither kind or too short.
[[nodiscard]] inline auto stamp_now(std::vector<std::byte>& entry, std::uint64_t now_ms) -> bool {
    const auto u8 = [&](std::size_t i) { return std::to_integer<std::uint8_t>(entry[i]); };
    std::size_t at = 0;
    if (entry.size() >= 2 && u8(0) == catalog_detail::k_command_format) {
        // format, op, account and name as length-prefixed strings.
        at = 2;
        for (int field = 0; field < 2; ++field) {
            if (entry.size() < at + 4) {
                return false;
            }
            std::size_t n = 0;
            for (std::size_t i = 0; i < 4; ++i) {
                n |= static_cast<std::size_t>(u8(at + i)) << (8 * i);
            }
            at += 4;
            if (entry.size() - at < n) {
                return false;
            }
            at += n;
        }
    } else if (!entry.empty() && u8(0) == command_detail::k_command_format) {
        // format, op, then the target: queue id, partition, fifo, retention.
        at = 1 + 1 + 8 + 2 + 1 + 4;
    } else {
        return false;
    }
    if (entry.size() < at + 8) {
        return false;
    }
    for (std::size_t i = 0; i < 8; ++i) {
        entry[at + i] = static_cast<std::byte>((now_ms >> (8 * i)) & 0xFFU);
    }
    return true;
}

}  // namespace kythira::sqs
