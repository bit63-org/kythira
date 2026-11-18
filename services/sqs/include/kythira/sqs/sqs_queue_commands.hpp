// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_queue_commands.hpp
/// @brief The Raft entries of the SQS queue state machine and their replies
///        (`.kiro/specs/sqs-compatible-queues/` task 2).
///
/// Every change to a queue partition is one `queue_command`, proposed by a
/// front end to the group that holds the partition's routing key and
/// applied by `sqs_queue_state_machine`. The command carries what `apply()`
/// needs from the queue's catalog record (FIFO or standard, retention), so
/// a group needs no catalog lookup and replicas cannot disagree about a
/// setting they read at different times. It also carries the leader's
/// clock reading, `now_ms`: every deadline (delay, visibility, retention,
/// deduplication window) is judged against it, never against a replica's
/// clock (Requirement 5.4).
///
/// The front end owns everything a client sees on the wire: message ids
/// (it generates them, so `apply()` stays deterministic), MD5 digests
/// (computed over plaintext before sealing, design "Encryption at the front
/// end"), attribute encodings, receipt-handle tokens and deduplication keys
/// (an explicit `MessageDeduplicationId` or the SHA-256 of the body,
/// prefixed by the group id when the queue deduplicates per group). The
/// state machine stores those as opaque strings.
///
/// Both forms are versioned binary encodings: a format byte, then the
/// fields in declaration order, integers little-endian and strings as a
/// 32-bit length and their bytes. Decoding is bounded and never throws; a
/// malformed entry yields `std::nullopt`.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs {

/// Which queue partition a command is for, and what `apply()` needs from
/// the queue's catalog record.
struct queue_target {
    /// Never reused: a queue created again after deletion gets a new id and
    /// so a new key range, which no old message is in (Requirement 4.2).
    std::uint64_t queue_id = 0;
    std::uint16_t partition = 0;
    bool fifo = false;
    /// `MessageRetentionPeriod` in seconds (60 s to 14 days).
    std::uint32_t retention_s = 345'600;

    friend auto operator==(const queue_target&, const queue_target&) -> bool = default;
};

/// One message of a send or send batch.
struct send_entry {
    /// The batch entry's `Id`, echoed in the reply; empty for `SendMessage`.
    std::string entry_id;
    /// The front end's message id (a UUID).
    std::string message_id;
    /// The body as stored: plaintext, or ciphertext on an encrypted queue.
    std::string body;
    /// The encoded message attributes and system attributes, opaque here.
    std::string attributes;
    std::string system_attributes;
    std::string md5_of_body;
    std::string md5_of_attributes;
    std::string md5_of_system_attributes;
    /// The message's delay: its `DelaySeconds`, else the queue's.
    std::uint32_t delay_s = 0;
    /// FIFO queues (and fair standard queues): the message group.
    std::string group_id;
    /// FIFO queues: the deduplication key (see the file comment).
    std::string dedup_key;
    /// FIFO queues: the client's `MessageDeduplicationId` as sent, or the
    /// body digest it was derived from, returned by receives.
    std::string dedup_id;

    friend auto operator==(const send_entry&, const send_entry&) -> bool = default;
};

/// A message to delete or whose visibility to change, named by what its
/// receipt handle carries (`sqs_receipts.hpp` checks the token's HMAC and
/// decodes it before the command is proposed).
struct receipt_ref {
    std::string entry_id;
    std::uint64_t sequence = 0;
    std::uint64_t receive_sequence = 0;
    /// `ChangeMessageVisibility`: the new timeout, counted from `now_ms`.
    std::uint32_t visibility_timeout_s = 0;

    friend auto operator==(const receipt_ref&, const receipt_ref&) -> bool = default;
};

struct queue_command {
    enum class kind : std::uint8_t {
        send = 1,
        receive = 2,
        delete_ = 3,
        change_visibility = 4,
        /// `PurgeQueue`: every message of the partition goes; sequence
        /// counters and deduplication records stay.
        purge = 5,
        /// The queue was deleted: the partition's whole key range goes.
        drop = 6,
        /// Housekeeping only (delays and visibility timeouts that ended,
        /// retention, deduplication records). The leader proposes one when
        /// a partition's earliest deadline passes, so the moment a message
        /// becomes visible again is a committed fact (design "Long polling
        /// without polling").
        tick = 7,
    };

    kind op = kind::tick;
    queue_target target;
    /// The leader's clock when it proposed the entry, in Unix milliseconds.
    std::uint64_t now_ms = 0;
    std::vector<send_entry> sends;
    std::vector<receipt_ref> receipts;
    /// Receive: how many messages at most (1-10) and the visibility timeout
    /// they get.
    std::uint32_t max_messages = 1;
    std::uint32_t visibility_timeout_s = 30;

    friend auto operator==(const queue_command&, const queue_command&) -> bool = default;
};

/// A received message, with everything the front end needs to build the
/// `Message` element and its receipt handle.
struct received_message {
    std::uint64_t sequence = 0;
    std::uint64_t receive_sequence = 0;
    /// When this receive's visibility timeout ends.
    std::uint64_t visible_at_ms = 0;
    std::string message_id;
    std::string body;
    std::string attributes;
    std::string system_attributes;
    std::string md5_of_body;
    std::string md5_of_attributes;
    std::string md5_of_system_attributes;
    std::string group_id;
    std::string dedup_id;
    std::uint64_t sent_ms = 0;
    std::uint64_t first_receive_ms = 0;
    std::uint32_t receive_count = 0;

    friend auto operator==(const received_message&, const received_message&) -> bool = default;
};

/// What one batch entry came to.
struct entry_result {
    enum class status : std::uint8_t {
        ok = 0,
        /// Send: a FIFO message whose deduplication key was seen within the
        /// window. Accepted, not enqueued; `message_id` and `sequence` are
        /// the original's, as SQS answers.
        duplicate = 1,
        /// Delete: the handle is not from the message's latest receive, or
        /// the message is gone. SQS accepts such a delete and does nothing.
        stale = 2,
        /// Change visibility: the message exists and the handle is its
        /// latest, but it is not in flight (`MessageNotInflight`).
        not_inflight = 3,
        /// Change visibility: the handle is stale or the message is gone
        /// (`ReceiptHandleIsInvalid`).
        invalid_receipt = 4,
        /// Change visibility: the new deadline would pass 12 hours after
        /// the receive (`InvalidParameterValue`).
        timeout_too_long = 5,
    };

    std::string entry_id;
    status outcome = status::ok;
    std::string message_id;
    std::uint64_t sequence = 0;

    friend auto operator==(const entry_result&, const entry_result&) -> bool = default;
};

struct queue_result {
    enum class status : std::uint8_t {
        ok = 0,
        /// The entry could not be decoded, or names a partition outside the
        /// group's range. Nothing changed but the applied index.
        malformed = 1,
    };

    status outcome = status::ok;
    std::vector<entry_result> entries;
    std::vector<received_message> messages;

    friend auto operator==(const queue_result&, const queue_result&) -> bool = default;
};

namespace command_detail {

inline constexpr std::uint8_t k_command_format = 1;
inline constexpr std::uint8_t k_result_format = 1;
/// Bounds on decoded entries: ten entries per batch (SQS's limit) with
/// headroom, and strings no longer than a 1 MiB message plus attributes.
inline constexpr std::size_t k_max_entries = 64;
inline constexpr std::size_t k_max_string = 4U * 1024U * 1024U;

inline void put_u8(std::string& out, std::uint8_t v) {
    out.push_back(static_cast<char>(v));
}

template<typename T> inline void put_le(std::string& out, T v) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<char>((static_cast<std::uint64_t>(v) >> (8 * i)) & 0xFFU));
    }
}

inline void put_str(std::string& out, std::string_view s) {
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(s.size()));
    out.append(s);
}

/// A bounded reader: every get fails, and stays failed, past the end.
class reader {
public:
    explicit reader(std::string_view in) : _in(in) {}

    template<typename T> auto le(T& v) -> bool {
        if (!_ok || _in.size() < sizeof(T)) {
            return _ok = false;
        }
        std::uint64_t x = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            x |= static_cast<std::uint64_t>(static_cast<unsigned char>(_in[i])) << (8 * i);
        }
        v = static_cast<T>(x);
        _in.remove_prefix(sizeof(T));
        return true;
    }

    auto u8(std::uint8_t& v) -> bool { return le(v); }

    auto boolean(bool& v) -> bool {
        std::uint8_t b = 0;
        if (!le(b) || b > 1) {
            return _ok = false;
        }
        v = b == 1;
        return true;
    }

    auto str(std::string& s) -> bool {
        std::uint32_t n = 0;
        if (!le(n) || n > k_max_string || _in.size() < n) {
            return _ok = false;
        }
        s.assign(_in.substr(0, n));
        _in.remove_prefix(n);
        return true;
    }

    auto count(std::size_t& n) -> bool {
        std::uint32_t v = 0;
        if (!le(v) || v > k_max_entries) {
            return _ok = false;
        }
        n = v;
        return true;
    }

    [[nodiscard]] auto ok() const -> bool { return _ok; }
    [[nodiscard]] auto done() const -> bool { return _ok && _in.empty(); }

private:
    std::string_view _in;
    bool _ok = true;
};

inline void put_target(std::string& out, const queue_target& t) {
    put_le(out, t.queue_id);
    put_le(out, t.partition);
    put_u8(out, t.fifo ? 1 : 0);
    put_le(out, t.retention_s);
}

inline auto get_target(reader& r, queue_target& t) -> bool {
    return r.le(t.queue_id) && r.le(t.partition) && r.boolean(t.fifo) && r.le(t.retention_s);
}

}  // namespace command_detail

[[nodiscard]] inline auto encode_queue_command(const queue_command& c) -> std::string {
    using namespace command_detail;
    std::string out;
    put_u8(out, k_command_format);
    put_u8(out, static_cast<std::uint8_t>(c.op));
    put_target(out, c.target);
    put_le(out, c.now_ms);
    put_le(out, c.max_messages);
    put_le(out, c.visibility_timeout_s);
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(c.sends.size()));
    for (const auto& s : c.sends) {
        for (const auto* f :
             {&s.entry_id, &s.message_id, &s.body, &s.attributes, &s.system_attributes,
              &s.md5_of_body, &s.md5_of_attributes, &s.md5_of_system_attributes}) {
            put_str(out, *f);
        }
        put_le(out, s.delay_s);
        put_str(out, s.group_id);
        put_str(out, s.dedup_key);
        put_str(out, s.dedup_id);
    }
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(c.receipts.size()));
    for (const auto& r : c.receipts) {
        put_str(out, r.entry_id);
        put_le(out, r.sequence);
        put_le(out, r.receive_sequence);
        put_le(out, r.visibility_timeout_s);
    }
    return out;
}

[[nodiscard]] inline auto decode_queue_command(std::string_view in)
    -> std::optional<queue_command> {
    using namespace command_detail;
    reader r(in);
    queue_command c;
    std::uint8_t format = 0;
    std::uint8_t op = 0;
    if (!r.u8(format) || format != k_command_format || !r.u8(op) ||
        op < static_cast<std::uint8_t>(queue_command::kind::send) ||
        op > static_cast<std::uint8_t>(queue_command::kind::tick)) {
        return std::nullopt;
    }
    c.op = static_cast<queue_command::kind>(op);
    std::size_t n = 0;
    if (!get_target(r, c.target) || !r.le(c.now_ms) || !r.le(c.max_messages) ||
        !r.le(c.visibility_timeout_s) || !r.count(n)) {
        return std::nullopt;
    }
    c.sends.resize(n);
    for (auto& s : c.sends) {
        for (auto* f : {&s.entry_id, &s.message_id, &s.body, &s.attributes, &s.system_attributes,
                        &s.md5_of_body, &s.md5_of_attributes, &s.md5_of_system_attributes}) {
            r.str(*f);
        }
        r.le(s.delay_s);
        r.str(s.group_id);
        r.str(s.dedup_key);
        r.str(s.dedup_id);
    }
    if (!r.count(n)) {
        return std::nullopt;
    }
    c.receipts.resize(n);
    for (auto& x : c.receipts) {
        r.str(x.entry_id);
        r.le(x.sequence);
        r.le(x.receive_sequence);
        r.le(x.visibility_timeout_s);
    }
    if (!r.done()) {
        return std::nullopt;
    }
    return c;
}

[[nodiscard]] inline auto encode_queue_result(const queue_result& q) -> std::string {
    using namespace command_detail;
    std::string out;
    put_u8(out, k_result_format);
    put_u8(out, static_cast<std::uint8_t>(q.outcome));
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(q.entries.size()));
    for (const auto& e : q.entries) {
        put_str(out, e.entry_id);
        put_u8(out, static_cast<std::uint8_t>(e.outcome));
        put_str(out, e.message_id);
        put_le(out, e.sequence);
    }
    put_le<std::uint32_t>(out, static_cast<std::uint32_t>(q.messages.size()));
    for (const auto& m : q.messages) {
        put_le(out, m.sequence);
        put_le(out, m.receive_sequence);
        put_le(out, m.visible_at_ms);
        for (const auto* f :
             {&m.message_id, &m.body, &m.attributes, &m.system_attributes, &m.md5_of_body,
              &m.md5_of_attributes, &m.md5_of_system_attributes, &m.group_id, &m.dedup_id}) {
            put_str(out, *f);
        }
        put_le(out, m.sent_ms);
        put_le(out, m.first_receive_ms);
        put_le(out, m.receive_count);
    }
    return out;
}

[[nodiscard]] inline auto decode_queue_result(std::string_view in) -> std::optional<queue_result> {
    using namespace command_detail;
    reader r(in);
    queue_result q;
    std::uint8_t format = 0;
    std::uint8_t outcome = 0;
    std::size_t n = 0;
    if (!r.u8(format) || format != k_result_format || !r.u8(outcome) ||
        outcome > static_cast<std::uint8_t>(queue_result::status::malformed) || !r.count(n)) {
        return std::nullopt;
    }
    q.outcome = static_cast<queue_result::status>(outcome);
    q.entries.resize(n);
    for (auto& e : q.entries) {
        std::uint8_t s = 0;
        r.str(e.entry_id);
        if (!r.u8(s) || s > static_cast<std::uint8_t>(entry_result::status::timeout_too_long)) {
            return std::nullopt;
        }
        e.outcome = static_cast<entry_result::status>(s);
        r.str(e.message_id);
        r.le(e.sequence);
    }
    if (!r.count(n)) {
        return std::nullopt;
    }
    q.messages.resize(n);
    for (auto& m : q.messages) {
        r.le(m.sequence);
        r.le(m.receive_sequence);
        r.le(m.visible_at_ms);
        for (auto* f :
             {&m.message_id, &m.body, &m.attributes, &m.system_attributes, &m.md5_of_body,
              &m.md5_of_attributes, &m.md5_of_system_attributes, &m.group_id, &m.dedup_id}) {
            r.str(*f);
        }
        r.le(m.sent_ms);
        r.le(m.first_receive_ms);
        r.le(m.receive_count);
    }
    if (!r.done()) {
        return std::nullopt;
    }
    return q;
}

}  // namespace kythira::sqs
