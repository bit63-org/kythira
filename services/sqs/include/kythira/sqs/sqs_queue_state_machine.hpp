// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_queue_state_machine.hpp
/// @brief The replicated state of SQS queue partitions
///        (`.kiro/specs/sqs-compatible-queues/` task 2, Requirements 4.2,
///        4.3, 5.2, 5.4-5.7).
///
/// `sqs_queue_state_machine` is a `persistent_staged_state_machine`: a
/// group's queue partitions stay in the node's `kv_engine` under the
/// group's key range, it snapshots by checkpoint manifest, and it splits
/// and merges by handing out ranges at partition boundaries, never by
/// copying messages.
///
/// Key layout, all in the `data` column family, under a partition's
/// routing key `q/<queue id, 16 hex>/<partition, 4 hex>/`:
///
/// | Suffix | Value | What |
/// |---|---|---|
/// | `c` | counters | next sequence, next receive sequence, visible / in-flight / delayed counts |
/// | `m/<seq>` | message | the message and its delivery state |
/// | `a/<seq>` | empty | standard queues: visible messages, oldest first |
/// | `p/<at>/<seq>` | empty | delayed and in-flight messages, by when they become visible |
/// | `r/<at>/<seq>` | empty | every message, by when retention deletes it |
/// | `g/<group>\0<seq>` | empty | FIFO queues: each group's messages in order |
/// | `h/<seq>/<group>` | empty | FIFO queues: groups whose first message is visible, by that
/// message | | `d/<key>` | dedup | FIFO queues: deduplication records | | `e/<at>/<key>` | empty |
/// deduplication records, by expiry |
///
/// Sequences and times are 16 hex digits, so keys sort numerically.
///
/// The same state machine applies the queue catalog (`sqs_catalog.hpp`),
/// whose keys sort before every partition and whose entries carry a format
/// byte of their own; the split veto keeps the catalog in one group.
///
/// A receive is a committed entry (design "A receive is a write"): `apply()`
/// first runs the partition's housekeeping at the entry's `now_ms` (moving
/// messages whose delay or visibility timeout ended to visible, deleting
/// messages past retention and deduplication records past their window,
/// each bounded per entry), then picks messages, marks them in flight until
/// `now + timeout`, bumps their receive counts and gives each the
/// partition's next receive sequence, which its receipt handle names. A
/// delete or visibility change is honoured only for the message's latest
/// receive (Requirement 5.5).
///
/// A standard queue hands out visible messages oldest first. A FIFO queue
/// hands out a group's messages in order, and a group is blocked while its
/// first message is in flight (Requirement 5.6): `h/` holds exactly the
/// groups whose first message is visible, so a receive reads only groups it
/// can serve. Deduplication records are replicated state, so the window
/// holds across leader changes (Requirement 5.7).
///
/// The approximate counts of Requirement 4.3 are kept by every transition
/// and are exact as of the partition's last applied entry. A message whose
/// timeout ends between entries is counted in flight until the next entry,
/// which is the approximation SQS documents.

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_queue_commands.hpp>

#include <raft/memory_kv_engine.hpp>
#include <raft/persistent_state_machine.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

// ---------------------------------------------------------------------------
// Key layout
// ---------------------------------------------------------------------------

namespace queue_keys {

inline constexpr std::size_t k_partition_prefix_bytes = 2 + 16 + 1 + 4 + 1;

inline auto hex(std::uint64_t v, int digits) -> std::string {
    static constexpr char k_digits[] = "0123456789abcdef";
    std::string out(static_cast<std::size_t>(digits), '0');
    for (int i = digits - 1; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = k_digits[v & 0xFU];
        v >>= 4;
    }
    return out;
}

inline auto hex16(std::uint64_t v) -> std::string {
    return hex(v, 16);
}

[[nodiscard]] inline auto parse_hex(std::string_view s) -> std::optional<std::uint64_t> {
    if (s.empty() || s.size() > 16) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= static_cast<std::uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= static_cast<std::uint64_t>(c - 'a' + 10);
        } else {
            return std::nullopt;
        }
    }
    return v;
}

/// The routing key of a queue partition, which is also the prefix of every
/// key the partition owns and the only place a group may be split.
[[nodiscard]] inline auto partition_prefix(std::uint64_t queue_id, std::uint16_t partition)
    -> std::string {
    return "q/" + hex16(queue_id) + "/" + hex(partition, 4) + "/";
}

[[nodiscard]] inline auto partition_prefix(const queue_target& t) -> std::string {
    return partition_prefix(t.queue_id, t.partition);
}

/// The first key after every key of a queue: the next queue id's prefix.
/// Queue id 2^64-1 is never allocated.
[[nodiscard]] inline auto queue_end(std::uint64_t queue_id) -> std::string {
    return "q/" + hex16(queue_id + 1) + "/";
}

/// The range of every partition of one queue.
[[nodiscard]] inline auto queue_range(std::uint64_t queue_id) -> kythira::key_range {
    return kythira::key_range{"q/" + hex16(queue_id) + "/", queue_end(queue_id)};
}

/// Whether `key` is exactly a partition's routing key.
[[nodiscard]] inline auto is_partition_prefix(std::string_view key) -> bool {
    return key.size() == k_partition_prefix_bytes && key.starts_with("q/") && key[18] == '/' &&
           key[23] == '/' && parse_hex(key.substr(2, 16)) && parse_hex(key.substr(19, 4));
}

/// The routing key `key` falls under, if any.
[[nodiscard]] inline auto partition_of(std::string_view key) -> std::optional<std::string> {
    if (key.size() < k_partition_prefix_bytes ||
        !is_partition_prefix(key.substr(0, k_partition_prefix_bytes))) {
        return std::nullopt;
    }
    return std::string(key.substr(0, k_partition_prefix_bytes));
}

/// The half-open range of keys starting with `prefix`.
[[nodiscard]] inline auto prefix_range(std::string prefix) -> kythira::key_range {
    std::string end = prefix;
    while (!end.empty() && static_cast<unsigned char>(end.back()) == 0xFFU) {
        end.pop_back();
    }
    if (end.empty()) {
        return kythira::key_range{std::move(prefix), std::nullopt};
    }
    end.back() = static_cast<char>(static_cast<unsigned char>(end.back()) + 1);
    return kythira::key_range{std::move(prefix), std::move(end)};
}

}  // namespace queue_keys

// ---------------------------------------------------------------------------
// Stored records
// ---------------------------------------------------------------------------

/// A message as stored at `m/<seq>`.
struct stored_message {
    enum class state : std::uint8_t {
        visible = 0,
        /// Its delay has not ended (`at_ms`).
        delayed = 1,
        /// Received; invisible until `at_ms`.
        in_flight = 2,
    };

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
    state status = state::visible;
    /// When a delayed or in-flight message becomes visible; 0 if visible.
    std::uint64_t at_ms = 0;
    std::uint64_t expire_ms = 0;
    std::uint32_t receive_count = 0;
    std::uint64_t receive_sequence = 0;
    std::uint64_t first_receive_ms = 0;
    std::uint64_t last_receive_ms = 0;
    /// The queue it was moved from, on a dead-letter queue (its ARN).
    std::string dead_letter_source;

    friend auto operator==(const stored_message&, const stored_message&) -> bool = default;
};

/// A partition's counters, at `c`.
struct partition_counters {
    std::uint64_t next_sequence = 1;
    std::uint64_t next_receive = 1;
    std::uint64_t visible = 0;
    std::uint64_t in_flight = 0;
    std::uint64_t delayed = 0;

    friend auto operator==(const partition_counters&, const partition_counters&) -> bool = default;
};

/// The approximate counts of a queue partition (Requirement 4.3).
struct partition_counts {
    std::uint64_t visible = 0;
    std::uint64_t not_visible = 0;
    std::uint64_t delayed = 0;

    friend auto operator==(const partition_counts&, const partition_counts&) -> bool = default;
};

namespace record_detail {

using command_detail::put_le;
using command_detail::put_str;
using command_detail::put_u8;
using command_detail::reader;

inline constexpr std::uint8_t k_message_format = 1;
inline constexpr std::uint8_t k_counters_format = 1;
inline constexpr std::uint8_t k_dedup_format = 1;

[[nodiscard]] inline auto encode_message(const stored_message& m) -> std::string {
    std::string out;
    put_u8(out, k_message_format);
    for (const auto* f :
         {&m.message_id, &m.body, &m.attributes, &m.system_attributes, &m.md5_of_body,
          &m.md5_of_attributes, &m.md5_of_system_attributes, &m.group_id, &m.dedup_id}) {
        put_str(out, *f);
    }
    put_le(out, m.sent_ms);
    put_u8(out, static_cast<std::uint8_t>(m.status));
    put_le(out, m.at_ms);
    put_le(out, m.expire_ms);
    put_le(out, m.receive_count);
    put_le(out, m.receive_sequence);
    put_le(out, m.first_receive_ms);
    put_le(out, m.last_receive_ms);
    put_str(out, m.dead_letter_source);
    return out;
}

[[nodiscard]] inline auto decode_message(std::string_view in) -> std::optional<stored_message> {
    reader r(in);
    stored_message m;
    std::uint8_t format = 0;
    std::uint8_t status = 0;
    if (!r.u8(format) || format != k_message_format) {
        return std::nullopt;
    }
    for (auto* f : {&m.message_id, &m.body, &m.attributes, &m.system_attributes, &m.md5_of_body,
                    &m.md5_of_attributes, &m.md5_of_system_attributes, &m.group_id, &m.dedup_id}) {
        r.str(*f);
    }
    r.le(m.sent_ms);
    if (!r.u8(status) || status > static_cast<std::uint8_t>(stored_message::state::in_flight)) {
        return std::nullopt;
    }
    m.status = static_cast<stored_message::state>(status);
    r.le(m.at_ms);
    r.le(m.expire_ms);
    r.le(m.receive_count);
    r.le(m.receive_sequence);
    r.le(m.first_receive_ms);
    r.le(m.last_receive_ms);
    r.str(m.dead_letter_source);
    if (!r.done()) {
        return std::nullopt;
    }
    return m;
}

[[nodiscard]] inline auto encode_counters(const partition_counters& c) -> std::string {
    std::string out;
    put_u8(out, k_counters_format);
    put_le(out, c.next_sequence);
    put_le(out, c.next_receive);
    put_le(out, c.visible);
    put_le(out, c.in_flight);
    put_le(out, c.delayed);
    return out;
}

[[nodiscard]] inline auto decode_counters(std::string_view in)
    -> std::optional<partition_counters> {
    reader r(in);
    partition_counters c;
    std::uint8_t format = 0;
    if (!r.u8(format) || format != k_counters_format || !r.le(c.next_sequence) ||
        !r.le(c.next_receive) || !r.le(c.visible) || !r.le(c.in_flight) || !r.le(c.delayed) ||
        !r.done()) {
        return std::nullopt;
    }
    return c;
}

struct dedup_record {
    std::uint64_t expire_ms = 0;
    std::uint64_t sequence = 0;
    std::string message_id;
};

[[nodiscard]] inline auto encode_dedup(const dedup_record& d) -> std::string {
    std::string out;
    put_u8(out, k_dedup_format);
    put_le(out, d.expire_ms);
    put_le(out, d.sequence);
    put_str(out, d.message_id);
    return out;
}

[[nodiscard]] inline auto decode_dedup(std::string_view in) -> std::optional<dedup_record> {
    reader r(in);
    dedup_record d;
    std::uint8_t format = 0;
    if (!r.u8(format) || format != k_dedup_format || !r.le(d.expire_ms) || !r.le(d.sequence) ||
        !r.str(d.message_id) || !r.done()) {
        return std::nullopt;
    }
    return d;
}

inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    std::transform(s.begin(), s.end(), out.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return out;
}

inline auto to_string(const std::vector<std::byte>& b) -> std::string {
    std::string out(b.size(), '\0');
    std::transform(b.begin(), b.end(), out.begin(),
                   [](std::byte c) { return static_cast<char>(c); });
    return out;
}

}  // namespace record_detail

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// The state machine of one group of queue partitions. `Engine` is any
/// `kv_engine`: unit tests use `memory_kv_engine`, production RocksDB.
template<kythira::kv_engine Engine = kythira::memory_kv_engine, typename LogIndex = std::uint64_t>
class sqs_queue_state_machine {
public:
    using engine_type = Engine;

    /// SQS's limits that `apply()` enforces itself.
    static constexpr std::uint64_t k_max_visibility_ms = 12ULL * 3600 * 1000;
    static constexpr std::uint64_t k_dedup_window_ms = 5ULL * 60 * 1000;
    static constexpr std::uint32_t k_max_receive_batch = 10;
    /// How much housekeeping one entry does per kind (promotions, retention
    /// deletions, expired deduplication records). Bounded so an entry's
    /// batch stays small; the rest is done by the next entries, and the
    /// leader's ticks keep coming while any is due.
    static constexpr std::size_t k_housekeeping_limit = 128;
    /// Message groups a standard queue's receive considers at once (fair
    /// queues): the rotation goes on from there on the next receive.
    static constexpr std::size_t k_max_fair_groups = 1024;

    // -- persistent_state_machine ------------------------------------------

    auto open(engine_type& engine, const kythira::key_range& range) -> void {
        _engine = &engine;
        _range = range;
        _ring.clear();
        _applied = 0;
        if (const auto v = _engine->get(kythira::column_family::meta, _range.start)) {
            command_detail::reader r(*v);
            std::uint64_t index = 0;
            if (r.le(index) && r.done()) {
                _applied = static_cast<LogIndex>(index);
            }
        }
        _durable_floor = _applied;
        discard_staged();
    }

    /// Called once per queue entry this replica commits, after its batch
    /// reached the engine: the partition, and whether it now has visible
    /// messages. Long polls park on the first (`sqs_long_poll.hpp`); the
    /// leader's tick worker (`sqs_workers.hpp`) re-reads its deadlines on
    /// every call, since an entry may have added an earlier one. Runs on
    /// the applying thread, so it must not call back into the cluster.
    using availability_listener = std::function<void(const queue_target&, bool visible)>;

    auto set_availability_listener(availability_listener listener) -> void {
        _listener = std::move(listener);
    }

    auto apply(const std::vector<std::byte>& entry, LogIndex index) -> std::vector<std::byte> {
        if (index <= _applied) {
            return {};
        }
        kythira::write_batch batch;
        auto out = stage(entry, batch);
        commit_staged(batch, index);
        return out;
    }

    // -- persistent_staged_state_machine --------------------------------------

    /// Stages one command's effects into `batch` and returns its encoded
    /// `queue_result`. A later `stage` of the same entry reads what earlier
    /// ones staged.
    auto stage(const std::vector<std::byte>& entry, kythira::write_batch& batch)
        -> std::vector<std::byte> {
        _batch = &batch;
        const auto text = record_detail::to_string(entry);
        if (is_catalog_entry(text)) {
            auto out = record_detail::to_bytes(encode_catalog_result(run_catalog(text)));
            _batch = nullptr;
            return out;
        }
        queue_result result;
        const auto c = decode_queue_command(text);
        if (!c || !_range.contains(queue_keys::partition_prefix(c->target))) {
            result.outcome = queue_result::status::malformed;
        } else {
            result = run(*c);
            if (_listener && c->op != queue_command::kind::drop) {
                _events.emplace_back(c->target, counts(c->target).visible > 0);
            }
        }
        _batch = nullptr;
        return record_detail::to_bytes(encode_queue_result(result));
    }

    /// Writes `batch` with the applied index `index`.
    auto commit_staged(kythira::write_batch& batch, LogIndex index) -> void {
        put_applied_at(batch, _range.start, index);
        const auto seq = engine().write(batch);
        auto events = std::move(_events);
        discard_staged();
        _applied = index;
        _ring.emplace_back(index, seq);
        trim_ring();
        if (_listener) {
            for (const auto& [target, visible] : events) {
                _listener(target, visible);
            }
        }
    }

    /// Forgets what was staged; nothing reached the engine.
    auto discard_staged() -> void {
        _overlay.clear();
        _erased.clear();
        _events.clear();
    }

    /// Engine keys are partition keys already.
    [[nodiscard]] auto key_prefix() const -> const std::string& {
        static const std::string none;
        return none;
    }

    [[nodiscard]] auto applied_index() const -> LogIndex { return _applied; }

    [[nodiscard]] auto durable_applied_index() const -> LogIndex {
        const auto durable = engine().durable_sequence();
        LogIndex best = _durable_floor;
        for (const auto& [index, seq] : _ring) {
            if (seq > durable) {
                break;
            }
            best = index;
        }
        return best;
    }

    auto checkpoint(const std::filesystem::path& dir) -> kythira::snapshot_manifest {
        return engine().checkpoint(_range, dir);
    }

    auto ingest(const std::filesystem::path& dir, const kythira::snapshot_manifest& manifest,
                LogIndex index) -> void {
        engine().ingest(_range, dir, manifest);
        _applied = index;
        _durable_floor = index;
        _ring.clear();
        discard_staged();
    }

    auto drop() -> void { engine().drop(_range); }

    // -- persistent_splittable_state_machine --------------------------------

    /// Narrows this group to the part below the first cut and returns the
    /// child ranges. Every cut must be a partition's routing key, so a
    /// partition is never split across groups; each child's applied index
    /// is written at its start in the same batch.
    auto split_at(const std::vector<std::string>& keys) -> std::vector<kythira::key_range> {
        std::vector<std::string> cuts = keys;
        std::ranges::sort(cuts);
        cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
        std::erase_if(cuts, [&](const std::string& k) { return !_range.contains(k); });
        if (cuts.empty()) {
            return {};
        }
        if (cuts.front() == _range.start) {
            throw std::invalid_argument("sqs_queue_state_machine: split at the range start");
        }
        for (const auto& k : cuts) {
            if (!can_split_at(k)) {
                throw std::invalid_argument(
                    "sqs_queue_state_machine: split inside a queue partition");
            }
        }
        std::vector<kythira::key_range> children;
        kythira::write_batch batch;
        for (std::size_t i = 0; i < cuts.size(); ++i) {
            children.push_back(kythira::key_range{
                cuts[i],
                i + 1 < cuts.size() ? std::optional<std::string>(cuts[i + 1]) : _range.end});
            put_applied_at(batch, cuts[i], _applied);
        }
        engine().write(batch);
        _range.end = cuts.front();
        return children;
    }

    /// Widens this group over an adjacent range of the same engine.
    auto adopt(const kythira::key_range& range) -> void {
        if (_range.contains(range)) {
            return;
        }
        kythira::write_batch batch;
        if (_range.end.has_value() && range.start == *_range.end) {
            batch.erase(kythira::column_family::meta, range.start);
            _range.end = range.end;
        } else if (range.end.has_value() && *range.end == _range.start) {
            batch.erase(kythira::column_family::meta, _range.start);
            _range.start = range.start;
        } else {
            throw std::invalid_argument(
                "sqs_queue_state_machine: adopt of a range that is not adjacent");
        }
        put_applied_at(batch, _range.start, _applied);
        engine().write(batch);
    }

    [[nodiscard]] auto range() const -> const kythira::key_range& { return _range; }

    /// The split veto: a group is cut only at a partition's routing key.
    [[nodiscard]] static auto can_split_at(const std::string& key) -> bool {
        return queue_keys::is_partition_prefix(key);
    }

    /// Bytes of the group's partitions, and up to `max` cuts that divide
    /// them evenly by bytes, at partition routing keys. Leader-only and
    /// advisory, for the host's size policy.
    [[nodiscard]] auto approximate_size_bytes() const -> std::size_t {
        std::size_t total = 0;
        engine().scan(kythira::column_family::data, _range, kythira::scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          total += k.size() + v.size();
                          return true;
                      });
        return total;
    }

    [[nodiscard]] auto suggest_split_keys(std::size_t max) const -> std::vector<std::string> {
        std::vector<std::string> out;
        if (max == 0 || _engine == nullptr) {
            return out;
        }
        std::vector<std::pair<std::string, std::size_t>> parts;
        std::size_t total = 0;
        engine().scan(kythira::column_family::data, _range, kythira::scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          const auto p = queue_keys::partition_of(k);
                          if (!p) {
                              return true;
                          }
                          if (parts.empty() || parts.back().first != *p) {
                              parts.emplace_back(*p, 0);
                          }
                          parts.back().second += k.size() + v.size();
                          total += k.size() + v.size();
                          return true;
                      });
        const auto step = std::max<std::size_t>(total / (max + 1), 1);
        std::size_t acc = 0;
        std::size_t next = step;
        for (const auto& [p, bytes] : parts) {
            if (out.size() < max && acc >= next && p > _range.start) {
                out.push_back(p);
                while (next <= acc) {
                    next += step;
                }
            }
            acc += bytes;
        }
        return out;
    }

    // -- reads ------------------------------------------------------------------

    /// The approximate counts of one partition, as of the last applied entry.
    [[nodiscard]] auto counts(const queue_target& t) const -> partition_counts {
        const auto c = load_counters(queue_keys::partition_prefix(t));
        return partition_counts{c.visible, c.in_flight, c.delayed};
    }

    [[nodiscard]] auto counters(const queue_target& t) const -> partition_counters {
        return load_counters(queue_keys::partition_prefix(t));
    }

    /// One stored message, for tests and diagnostics.
    [[nodiscard]] auto message(const queue_target& t, std::uint64_t sequence) const
        -> std::optional<stored_message> {
        return load_message(queue_keys::partition_prefix(t), sequence);
    }

    /// The earliest moment anything of the partition is due (a delay or
    /// visibility timeout ending, a retention deletion, a deduplication
    /// record expiring), or nullopt when nothing is pending. The leader
    /// proposes a `tick` then (task 5).
    [[nodiscard]] auto next_deadline(const queue_target& t) const -> std::optional<std::uint64_t> {
        const auto p = queue_keys::partition_prefix(t);
        std::optional<std::uint64_t> best;
        for (const char* sub : {"p/", "r/", "e/"}) {
            scan_prefix(p + sub, [&](std::string_view k, std::string_view) {
                if (const auto at = queue_keys::parse_hex(k.substr(p.size() + 2, 16))) {
                    best = best ? std::min(*best, *at) : *at;
                }
                return false;
            });
        }
        return best;
    }

    /// The catalog record of queue `name` of `account`, as of the last
    /// applied entry.
    [[nodiscard]] auto find_queue(std::string_view account, std::string_view name) const
        -> std::optional<queue_record> {
        return load_record(catalog_keys::queue(account, name));
    }

    /// Up to `max` queues of `account` whose names start with `prefix` and
    /// sort after `after` (ListQueues' `NextToken`), in name order.
    [[nodiscard]] auto list_queues(std::string_view account, std::string_view prefix,
                                   std::string_view after, std::size_t max) const
        -> std::vector<queue_record> {
        std::vector<queue_record> out;
        const auto base = catalog_keys::queues_prefix(account);
        scan_prefix(base + std::string(prefix), [&](std::string_view k, std::string_view v) {
            if (k.substr(base.size()) <= after) {
                return true;
            }
            if (out.size() >= max) {
                return false;
            }
            auto q = decode_queue_record(v);
            if (!q) {
                throw kythira::persistent_storage_error(
                    "sqs_queue_state_machine: corrupt queue record");
            }
            out.push_back(std::move(*q));
            return true;
        });
        return out;
    }

    /// Queue `name`'s move tasks, newest first.
    [[nodiscard]] auto move_tasks(std::string_view account, std::string_view name) const
        -> std::vector<move_task> {
        std::vector<move_task> out;
        scan_prefix(catalog_keys::moves_of(account, name),
                    [&](std::string_view, std::string_view v) {
                        if (auto m = decode_move_task(v)) {
                            out.push_back(std::move(*m));
                        }
                        return true;
                    });
        std::reverse(out.begin(), out.end());
        return out;
    }

    /// Every running or cancelling move task (the worker's list).
    [[nodiscard]] auto active_move_tasks() const -> std::vector<move_task> {
        std::vector<move_task> out;
        scan_prefix(catalog_keys::moves_prefix(), [&](std::string_view, std::string_view v) {
            if (auto m = decode_move_task(v); m && m->active()) {
                out.push_back(std::move(*m));
            }
            return true;
        });
        return out;
    }

    /// Up to `max` visible messages of a partition, oldest first, with
    /// what a move needs: sequence, group and dead-letter source.
    [[nodiscard]] auto visible_messages(const queue_target& t, std::size_t max) const
        -> std::vector<std::pair<std::uint64_t, stored_message>> {
        std::vector<std::pair<std::uint64_t, stored_message>> out;
        const auto p = queue_keys::partition_prefix(t);
        scan_prefix(p + "m/", [&](std::string_view k, std::string_view) {
            if (out.size() >= max) {
                return false;
            }
            if (const auto seq = queue_keys::parse_hex(k.substr(p.size() + 2))) {
                if (auto m = load_message(p, *seq); m && m->status == state::visible) {
                    out.emplace_back(*seq, std::move(*m));
                }
            }
            return true;
        });
        return out;
    }

    /// Every queue of every account this replica's range holds, in key
    /// order, until `visit` returns false (the tick worker's walk).
    template<typename Visit> auto for_each_queue(Visit&& visit) const -> void {
        scan_prefix(catalog_keys::prefix() + "queues/", [&](std::string_view, std::string_view v) {
            auto q = decode_queue_record(v);
            if (!q) {
                throw kythira::persistent_storage_error(
                    "sqs_queue_state_machine: corrupt queue record");
            }
            return visit(*q);
        });
    }

    [[nodiscard]] auto engine() const -> engine_type& {
        if (_engine == nullptr) {
            throw std::logic_error("sqs_queue_state_machine: not open");
        }
        return *_engine;
    }

private:
    using state = stored_message::state;

    // -- staged reads and writes ---------------------------------------------
    //
    // Reads see the batch being staged: `_overlay` holds every key this
    // entry put (a value) or erased (nullopt), and `_erased` the ranges it
    // erased, so a later step of the same entry reads what an earlier one
    // wrote.

    [[nodiscard]] auto read(const std::string& key) const -> std::optional<std::string> {
        if (const auto it = _overlay.find(key); it != _overlay.end()) {
            return it->second;
        }
        if (erased(key)) {
            return std::nullopt;
        }
        return engine().get(kythira::column_family::data, key);
    }

    [[nodiscard]] auto erased(std::string_view key) const -> bool {
        return std::ranges::any_of(_erased,
                                   [&](const kythira::key_range& r) { return r.contains(key); });
    }

    auto put(const std::string& key, std::string value) -> void {
        _batch->put(kythira::column_family::data, key, value);
        _overlay[key] = std::move(value);
    }

    auto erase(const std::string& key) -> void {
        _batch->erase(kythira::column_family::data, key);
        _overlay[key] = std::nullopt;
    }

    auto erase_prefix(const std::string& prefix) -> void {
        auto r = queue_keys::prefix_range(prefix);
        _batch->erase_range(kythira::column_family::data, r);
        std::erase_if(_overlay, [&](const auto& kv) { return r.contains(kv.first); });
        _erased.push_back(std::move(r));
    }

    /// Visits the keys under `prefix` in order, merging staged writes over
    /// the engine. The visitor returns false to stop.
    template<typename Visit>
    auto scan_prefix(const std::string& prefix, Visit&& visit) const -> void {
        const auto r = queue_keys::prefix_range(prefix);
        auto ov = _overlay.lower_bound(prefix);
        const auto ov_in = [&] { return ov != _overlay.end() && r.contains(ov->first); };
        bool stopped = false;
        engine().scan(kythira::column_family::data, r, kythira::scan_direction::forward,
                      [&](std::string_view k, std::string_view v) {
                          while (ov_in() && ov->first < k) {
                              if (ov->second && !visit(std::string_view(ov->first), *ov->second)) {
                                  stopped = true;
                                  return false;
                              }
                              ++ov;
                          }
                          if (ov_in() && ov->first == k) {
                              const auto& staged = ov->second;
                              ++ov;
                              if (staged && !visit(k, std::string_view(*staged))) {
                                  stopped = true;
                                  return false;
                              }
                              return true;
                          }
                          if (erased(k)) {
                              return true;
                          }
                          if (!visit(k, v)) {
                              stopped = true;
                              return false;
                          }
                          return true;
                      });
        while (!stopped && ov_in()) {
            if (ov->second && !visit(std::string_view(ov->first), *ov->second)) {
                return;
            }
            ++ov;
        }
    }

    // -- records ----------------------------------------------------------------

    [[nodiscard]] auto load_counters(const std::string& p) const -> partition_counters {
        if (const auto v = read(p + "c")) {
            if (auto c = record_detail::decode_counters(*v)) {
                return *c;
            }
            throw kythira::persistent_storage_error("sqs_queue_state_machine: corrupt counters");
        }
        return {};
    }

    [[nodiscard]] auto load_message(const std::string& p, std::uint64_t seq) const
        -> std::optional<stored_message> {
        const auto v = read(p + "m/" + queue_keys::hex16(seq));
        if (!v) {
            return std::nullopt;
        }
        auto m = record_detail::decode_message(*v);
        if (!m) {
            throw kythira::persistent_storage_error("sqs_queue_state_machine: corrupt message");
        }
        return m;
    }

    static auto timed_key(const std::string& p, const char* sub, std::uint64_t at,
                          std::uint64_t seq) -> std::string {
        return p + sub + queue_keys::hex16(at) + "/" + queue_keys::hex16(seq);
    }

    static auto group_key(const std::string& p, const std::string& group, std::uint64_t seq)
        -> std::string {
        std::string k = p + "g/" + group;
        k.push_back('\0');
        return k + queue_keys::hex16(seq);
    }

    static auto group_prefix(const std::string& p, const std::string& group) -> std::string {
        std::string k = p + "g/" + group;
        k.push_back('\0');
        return k;
    }

    static auto head_key(const std::string& p, std::uint64_t seq, const std::string& group)
        -> std::string {
        return p + "h/" + queue_keys::hex16(seq) + "/" + group;
    }

    /// A standard queue's visible messages, by message group (fair
    /// queues; ungrouped messages are the group ""): `f/<group>\0<seq>`,
    /// with `n/<group>` counting them.
    static auto fair_prefix(const std::string& p, const std::string& group) -> std::string {
        std::string k = p + "f/" + group;
        k.push_back('\0');
        return k;
    }

    auto fair_add(const std::string& p, const std::string& group, std::uint64_t seq) -> void {
        put(fair_prefix(p, group) + queue_keys::hex16(seq), {});
        const auto key = p + "n/" + group;
        put_u64(key, read_u64(key).value_or(0) + 1);
    }

    auto fair_remove(const std::string& p, const std::string& group, std::uint64_t seq) -> void {
        erase(fair_prefix(p, group) + queue_keys::hex16(seq));
        const auto key = p + "n/" + group;
        const auto n = read_u64(key).value_or(0);
        if (n <= 1) {
            erase(key);
        } else {
            put_u64(key, n - 1);
        }
    }

    /// The first message of a FIFO group, if the group has any.
    [[nodiscard]] auto group_head(const std::string& p, const std::string& group) const
        -> std::optional<std::uint64_t> {
        std::optional<std::uint64_t> head;
        const auto gp = group_prefix(p, group);
        scan_prefix(gp, [&](std::string_view k, std::string_view) {
            head = queue_keys::parse_hex(k.substr(gp.size()));
            return false;
        });
        return head;
    }

    auto store(const std::string& p, std::uint64_t seq, const stored_message& m) -> void {
        put(p + "m/" + queue_keys::hex16(seq), record_detail::encode_message(m));
    }

    static auto count_of(partition_counters& c, state s) -> std::uint64_t& {
        switch (s) {
            case state::visible:
                return c.visible;
            case state::delayed:
                return c.delayed;
            case state::in_flight:
                return c.in_flight;
        }
        return c.visible;
    }

    /// Moves a message to `next` (with `at` for delayed and in-flight),
    /// keeping its index entries and the counts in step.
    auto transition(const queue_target& t, const std::string& p, partition_counters& c,
                    std::uint64_t seq, stored_message& m, state next, std::uint64_t at) -> void {
        // Leave the old state's index.
        if (m.status == state::visible) {
            if (!t.fifo) {
                fair_remove(p, m.group_id, seq);
            } else if (group_head(p, m.group_id) == seq) {
                erase(head_key(p, seq, m.group_id));
            }
        } else {
            erase(timed_key(p, "p/", m.at_ms, seq));
        }
        auto& from = count_of(c, m.status);
        from = from > 0 ? from - 1 : 0;
        // Enter the new one.
        m.status = next;
        m.at_ms = next == state::visible ? 0 : at;
        ++count_of(c, next);
        if (next == state::visible) {
            if (!t.fifo) {
                fair_add(p, m.group_id, seq);
            } else if (group_head(p, m.group_id) == seq) {
                put(head_key(p, seq, m.group_id), {});
            }
        } else {
            put(timed_key(p, "p/", m.at_ms, seq), {});
        }
        store(p, seq, m);
    }

    /// Removes a message and every index entry it has. On a FIFO queue, the
    /// group's next message becomes its head, and is listed in `h/` if
    /// visible.
    auto remove(const queue_target& t, const std::string& p, partition_counters& c,
                std::uint64_t seq, const stored_message& m) -> void {
        if (m.status == state::visible) {
            if (!t.fifo) {
                fair_remove(p, m.group_id, seq);
            }
        } else {
            erase(timed_key(p, "p/", m.at_ms, seq));
        }
        auto& n = count_of(c, m.status);
        n = n > 0 ? n - 1 : 0;
        erase(timed_key(p, "r/", m.expire_ms, seq));
        erase(p + "m/" + queue_keys::hex16(seq));
        if (t.fifo) {
            const bool was_head = group_head(p, m.group_id) == seq;
            erase(group_key(p, m.group_id, seq));
            if (was_head) {
                erase(head_key(p, seq, m.group_id));
                if (const auto next = group_head(p, m.group_id)) {
                    const auto nm = load_message(p, *next);
                    if (nm && nm->status == state::visible) {
                        put(head_key(p, *next, m.group_id), {});
                    }
                }
            }
        }
    }

    // -- housekeeping -------------------------------------------------------

    auto housekeeping(const queue_target& t, const std::string& p, partition_counters& c,
                      std::uint64_t now) -> void {
        // Delays and visibility timeouts that ended.
        std::vector<std::uint64_t> due;
        scan_prefix(p + "p/", [&](std::string_view k, std::string_view) {
            const auto at = queue_keys::parse_hex(k.substr(p.size() + 2, 16));
            if (!at || *at > now || due.size() == k_housekeeping_limit) {
                return false;
            }
            if (const auto seq = queue_keys::parse_hex(k.substr(p.size() + 2 + 17))) {
                due.push_back(*seq);
            }
            return true;
        });
        for (const auto seq : due) {
            if (auto m = load_message(p, seq)) {
                transition(t, p, c, seq, *m, state::visible, 0);
            }
        }
        // Retention.
        due.clear();
        scan_prefix(p + "r/", [&](std::string_view k, std::string_view) {
            const auto at = queue_keys::parse_hex(k.substr(p.size() + 2, 16));
            if (!at || *at > now || due.size() == k_housekeeping_limit) {
                return false;
            }
            if (const auto seq = queue_keys::parse_hex(k.substr(p.size() + 2 + 17))) {
                due.push_back(*seq);
            }
            return true;
        });
        for (const auto seq : due) {
            if (const auto m = load_message(p, seq)) {
                remove(t, p, c, seq, *m);
            }
        }
        // Deduplication records past their window.
        std::vector<std::string> expired;
        scan_prefix(p + "e/", [&](std::string_view k, std::string_view) {
            const auto at = queue_keys::parse_hex(k.substr(p.size() + 2, 16));
            if (!at || *at > now || expired.size() == k_housekeeping_limit) {
                return false;
            }
            expired.emplace_back(k);
            return true;
        });
        for (const auto& k : expired) {
            const auto dedup = k.substr(p.size() + 2 + 17);
            erase(k);
            // A key re-sent after expiry has a newer record; keep it.
            if (const auto v = read(p + "d/" + dedup)) {
                const auto d = record_detail::decode_dedup(*v);
                if (!d || d->expire_ms <= now) {
                    erase(p + "d/" + dedup);
                }
            }
        }
    }

    // -- catalog --------------------------------------------------------------

    [[nodiscard]] auto load_record(const std::string& key) const -> std::optional<queue_record> {
        const auto v = read(key);
        if (!v) {
            return std::nullopt;
        }
        auto q = decode_queue_record(*v);
        if (!q) {
            throw kythira::persistent_storage_error(
                "sqs_queue_state_machine: corrupt queue record");
        }
        return q;
    }

    [[nodiscard]] auto read_u64(const std::string& key) const -> std::optional<std::uint64_t> {
        const auto v = read(key);
        if (!v) {
            return std::nullopt;
        }
        command_detail::reader r(*v);
        std::uint64_t x = 0;
        if (!r.le(x) || !r.done()) {
            throw kythira::persistent_storage_error("sqs_queue_state_machine: corrupt catalog");
        }
        return x;
    }

    auto put_u64(const std::string& key, std::uint64_t v) -> void {
        std::string out;
        command_detail::put_le(out, v);
        put(key, std::move(out));
    }

    auto run_catalog(std::string_view text) -> catalog_result {
        using status = catalog_result::status;
        catalog_result out;
        const auto c = decode_catalog_command(text);
        if (!c || !catalog_keys::valid_account(c->_account) || c->_name.empty() ||
            c->_name.find('\0') != std::string::npos || !_range.contains(catalog_keys::next_id()) ||
            !_range.contains(catalog_keys::queue(c->_account, c->_name))) {
            out._outcome = status::malformed;
            return out;
        }
        const auto key = catalog_keys::queue(c->_account, c->_name);
        auto rec = load_record(key);
        if (c->_op == catalog_command::kind::create) {
            if (rec) {
                out._outcome =
                    rec->_settings == c->_settings ? status::exists : status::name_exists;
                out._record = std::move(rec);
                return out;
            }
            const auto gone = catalog_keys::deleted(c->_account, c->_name);
            if (const auto at = read_u64(gone)) {
                if (c->_now_ms < *at + c->_cooldown_ms) {
                    out._outcome = status::deleted_recently;
                    return out;
                }
                erase(gone);
            }
            if (c->_tags.size() > k_max_queue_tags) {
                out._outcome = status::too_many_tags;
                return out;
            }
            const auto id = read_u64(catalog_keys::next_id()).value_or(1);
            put_u64(catalog_keys::next_id(), id + 1);
            queue_record q;
            q._id = id;
            q._account = c->_account;
            q._name = c->_name;
            q._settings = c->_settings;
            q._tags = c->_tags;
            q._created_ms = q._modified_ms = c->_now_ms;
            q._version = 1;
            q._partitions = std::max<std::uint16_t>(c->_partitions, 1);
            put(key, encode_queue_record(q));
            out._record = std::move(q);
            return out;
        }
        if (c->_op == catalog_command::kind::move_update ||
            c->_op == catalog_command::kind::move_cancel) {
            return run_move_change(*c);
        }
        if (!rec) {
            out._outcome = status::does_not_exist;
            return out;
        }
        if (c->_op == catalog_command::kind::move_start) {
            return run_move_start(*c);
        }
        auto& q = *rec;
        switch (c->_op) {
            case catalog_command::kind::set_settings: {
                if (q._version != c->_expected_version) {
                    out._outcome = status::conflict;
                    out._record = std::move(rec);
                    return out;
                }
                auto next = c->_settings;
                next._fifo = q._settings._fifo;  // fixed at creation
                if (next != q._settings) {
                    q._settings = std::move(next);
                    q._modified_ms = c->_now_ms;
                }
                break;
            }
            case catalog_command::kind::tag: {
                auto tags = q._tags;
                for (const auto& [k, v] : c->_tags) {
                    tags[k] = v;
                }
                if (tags.size() > k_max_queue_tags) {
                    out._outcome = status::too_many_tags;
                    return out;
                }
                q._tags = std::move(tags);
                break;
            }
            case catalog_command::kind::untag:
                for (const auto& k : c->_tag_keys) {
                    q._tags.erase(k);
                }
                break;
            case catalog_command::kind::delete_:
                erase(key);
                erase_prefix(catalog_keys::moves_of(c->_account, c->_name));
                put_u64(catalog_keys::deleted(c->_account, c->_name), c->_now_ms);
                out._record = std::move(rec);
                return out;
            case catalog_command::kind::grow:
                if (q._settings._fifo || c->_partitions <= q._partitions) {
                    out._record = std::move(rec);
                    return out;  // nothing to do: ok, unchanged
                }
                q._partitions = std::min(c->_partitions, k_max_partitions);
                break;
            case catalog_command::kind::purge:
                if (q._last_purge_ms != 0 && c->_now_ms < q._last_purge_ms + c->_cooldown_ms) {
                    out._outcome = status::purge_in_progress;
                    return out;
                }
                q._last_purge_ms = c->_now_ms;
                break;
            default:
                out._outcome = status::malformed;
                return out;
        }
        ++q._version;
        put(key, encode_queue_record(q));
        out._record = std::move(rec);
        return out;
    }

    auto run_move_start(const catalog_command& c) -> catalog_result {
        catalog_result out;
        std::vector<std::pair<std::string, move_task>> tasks;
        scan_prefix(catalog_keys::moves_of(c._account, c._name),
                    [&](std::string_view k, std::string_view v) {
                        if (auto m = decode_move_task(v)) {
                            tasks.emplace_back(std::string(k), std::move(*m));
                        }
                        return true;
                    });
        for (const auto& [k, m] : tasks) {
            if (m.active()) {
                out._outcome = catalog_result::status::move_in_progress;
                out._move = m;
                return out;
            }
        }
        // Room for the new one: the oldest (all finished) go.
        for (std::size_t i = 0; i + k_max_move_tasks <= tasks.size(); ++i) {
            erase(tasks[i].first);
        }
        auto m = c._move;
        m._account = c._account;
        m._name = c._name;
        m._started_ms = c._now_ms;
        m._status = move_task::state::running;
        m._moved = 0;
        m._failure.clear();
        put(catalog_keys::move(c._account, c._name, m._started_ms), encode_move_task(m));
        out._move = std::move(m);
        return out;
    }

    auto run_move_change(const catalog_command& c) -> catalog_result {
        catalog_result out;
        const auto key = catalog_keys::move(c._account, c._name, c._move._started_ms);
        const auto v = read(key);
        auto m = v ? decode_move_task(*v) : std::nullopt;
        if (!m || !m->active() ||
            (c._op == catalog_command::kind::move_cancel &&
             m->_status != move_task::state::running)) {
            out._outcome = catalog_result::status::does_not_exist;
            out._move = std::move(m);
            return out;
        }
        if (c._op == catalog_command::kind::move_cancel) {
            m->_status = move_task::state::cancelling;
        } else {
            m->_moved += c._move._moved;
            if (c._move._to_move > 0) {
                m->_to_move = c._move._to_move;
            }
            if (c._move._status != move_task::state::running) {
                m->_status = c._move._status;
                m->_failure = c._move._failure;
            }
        }
        put(key, encode_move_task(*m));
        out._move = std::move(m);
        return out;
    }

    // -- commands -----------------------------------------------------------

    auto run(const queue_command& c) -> queue_result {
        const auto& t = c.target;
        const auto p = queue_keys::partition_prefix(t);
        queue_result out;
        if (c.op == queue_command::kind::drop) {
            erase_prefix(p);
            return out;
        }
        auto counters = load_counters(p);
        if (c.op == queue_command::kind::purge) {
            for (const char* sub : {"m/", "f/", "n/", "c/", "p/", "r/", "g/", "h/"}) {
                erase_prefix(p + sub);
            }
            counters.visible = counters.in_flight = counters.delayed = 0;
            put(p + "c", record_detail::encode_counters(counters));
            return out;
        }
        housekeeping(t, p, counters, c.now_ms);
        switch (c.op) {
            case queue_command::kind::send:
                for (const auto& s : c.sends) {
                    out.entries.push_back(send(t, p, counters, c.now_ms, s));
                }
                break;
            case queue_command::kind::receive:
                out.messages = receive(t, p, counters, c);
                break;
            case queue_command::kind::delete_:
                for (const auto& r : c.receipts) {
                    out.entries.push_back(delete_message(t, p, counters, r));
                }
                break;
            case queue_command::kind::change_visibility:
                for (const auto& r : c.receipts) {
                    out.entries.push_back(change_visibility(t, p, counters, c.now_ms, r));
                }
                break;
            case queue_command::kind::move:
                for (const auto& mv : c.moves) {
                    out.entries.push_back(move_one(t, p, counters, mv, c.now_ms));
                }
                break;
            default:
                break;
        }
        put(p + "c", record_detail::encode_counters(counters));
        return out;
    }

    auto send(const queue_target& t, const std::string& p, partition_counters& c, std::uint64_t now,
              const send_entry& s) -> entry_result {
        entry_result r{s.entry_id, entry_result::status::ok, s.message_id, 0};
        if (t.fifo && !s.dedup_key.empty()) {
            if (const auto v = read(p + "d/" + s.dedup_key)) {
                const auto d = record_detail::decode_dedup(*v);
                if (d && d->expire_ms > now) {
                    r.outcome = entry_result::status::duplicate;
                    r.message_id = d->message_id;
                    r.sequence = d->sequence;
                    return r;
                }
            }
        }
        const auto seq = c.next_sequence++;
        r.sequence = seq;
        stored_message m;
        m.message_id = s.message_id;
        m.body = s.body;
        m.attributes = s.attributes;
        m.system_attributes = s.system_attributes;
        m.md5_of_body = s.md5_of_body;
        m.md5_of_attributes = s.md5_of_attributes;
        m.md5_of_system_attributes = s.md5_of_system_attributes;
        m.group_id = s.group_id;
        m.dedup_id = s.dedup_id;
        m.sent_ms = now;
        m.expire_ms = now + std::uint64_t{t.retention_s} * 1000;
        put(timed_key(p, "r/", m.expire_ms, seq), {});
        if (t.fifo) {
            put(group_key(p, s.group_id, seq), {});
            if (!s.dedup_key.empty()) {
                const auto expire = now + k_dedup_window_ms;
                put(p + "d/" + s.dedup_key,
                    record_detail::encode_dedup({expire, seq, s.message_id}));
                put(p + "e/" + queue_keys::hex16(expire) + "/" + s.dedup_key, {});
            }
        }
        if (s.delay_s > 0) {
            m.status = state::delayed;
            m.at_ms = now + std::uint64_t{s.delay_s} * 1000;
            ++c.delayed;
            put(timed_key(p, "p/", m.at_ms, seq), {});
        } else {
            m.status = state::visible;
            ++c.visible;
            if (!t.fifo) {
                fair_add(p, s.group_id, seq);
            } else if (group_head(p, s.group_id) == seq) {
                put(head_key(p, seq, s.group_id), {});
            }
        }
        store(p, seq, m);
        return r;
    }

    auto deliver(const std::string& p, partition_counters& c, std::uint64_t seq, stored_message& m,
                 std::uint64_t now, std::uint64_t deadline, const queue_target& t)
        -> received_message {
        const auto receive_seq = c.next_receive++;
        m.receive_count += 1;
        m.receive_sequence = receive_seq;
        if (m.first_receive_ms == 0) {
            m.first_receive_ms = now;
        }
        m.last_receive_ms = now;
        transition(t, p, c, seq, m, state::in_flight, deadline);
        return received_message{seq,
                                receive_seq,
                                deadline,
                                m.message_id,
                                m.body,
                                m.attributes,
                                m.system_attributes,
                                m.md5_of_body,
                                m.md5_of_attributes,
                                m.md5_of_system_attributes,
                                m.group_id,
                                m.dedup_id,
                                m.sent_ms,
                                m.first_receive_ms,
                                m.receive_count,
                                m.dead_letter_source};
    }

    /// Whether `m`, about to be received, has been received as often as
    /// the redrive policy allows, and its dead-letter partition is in this
    /// group's range (one entry moves it; across groups it would take a
    /// transaction, which task 12 brings, so until then it stays).
    [[nodiscard]] auto dead_letter_due(const queue_command& cmd, const stored_message& m,
                                       std::uint64_t seq) const -> bool {
        if (!cmd.redrive || cmd.redrive->max_receive_count == 0 ||
            m.receive_count < cmd.redrive->max_receive_count ||
            cmd.redrive->dlq.queue_id == cmd.target.queue_id) {
            return false;
        }
        auto d = cmd.redrive->dlq;
        d.partition = dead_letter_partition(*cmd.redrive, m.group_id, seq);
        return _range.contains(queue_keys::partition_prefix(d));
    }

    /// Moves `m` from this partition to its dead-letter partition, in the
    /// entry being staged, so it is in exactly one queue at every point
    /// (Requirement 7.1). It keeps its id, body, attributes, digests and
    /// sent time; its receive count starts again, as on SQS.
    auto move_to_dead_letter(const queue_target& t, const std::string& p, partition_counters& c,
                             std::uint64_t seq, const stored_message& m, const redrive_target& r,
                             std::uint64_t now) -> void {
        auto d = r.dlq;
        d.partition = dead_letter_partition(r, m.group_id, seq);
        transfer(t, p, c, seq, m, d, r.source_arn, now);
    }

    /// Moves `m` from partition `p` to partition `d` (of another queue) in
    /// the entry being staged, keeping its id, body, attributes, digests
    /// and sent time, with `dead_letter_source` as its source.
    auto transfer(const queue_target& t, const std::string& p, partition_counters& c,
                  std::uint64_t seq, const stored_message& m, const queue_target& d,
                  const std::string& dead_letter_source, std::uint64_t now) -> void {
        const auto dp = queue_keys::partition_prefix(d);
        remove(t, p, c, seq, m);
        auto dc = load_counters(dp);
        housekeeping(d, dp, dc, now);
        send_entry e;
        e.message_id = m.message_id;
        e.body = m.body;
        e.attributes = m.attributes;
        e.system_attributes = m.system_attributes;
        e.md5_of_body = m.md5_of_body;
        e.md5_of_attributes = m.md5_of_attributes;
        e.md5_of_system_attributes = m.md5_of_system_attributes;
        e.group_id = m.group_id;
        e.dedup_id = m.dedup_id;  // no dedup_key: a move is never a duplicate
        const auto sent = send(d, dp, dc, now, e);
        if (auto moved = load_message(dp, sent.sequence)) {
            moved->sent_ms = m.sent_ms;
            moved->dead_letter_source = dead_letter_source;
            store(dp, sent.sequence, *moved);
        }
        put(dp + "c", record_detail::encode_counters(dc));
        if (_listener) {
            _events.emplace_back(d, dc.visible > 0);
        }
    }

    auto receive(const queue_target& t, const std::string& p, partition_counters& c,
                 const queue_command& cmd) -> std::vector<received_message> {
        std::vector<received_message> out;
        const auto want = std::clamp<std::uint32_t>(cmd.max_messages, 1, k_max_receive_batch);
        const auto timeout_ms = std::min<std::uint64_t>(
            std::uint64_t{cmd.visibility_timeout_s} * 1000, k_max_visibility_ms);
        const auto deadline = cmd.now_ms + timeout_ms;
        if (!t.fifo) {
            const auto picked = fair_pick(p, want);
            for (const auto seq : picked) {
                if (auto m = load_message(p, seq)) {
                    if (dead_letter_due(cmd, *m, seq)) {
                        move_to_dead_letter(t, p, c, seq, *m, *cmd.redrive, cmd.now_ms);
                        continue;
                    }
                    out.push_back(deliver(p, c, seq, *m, cmd.now_ms, deadline, t));
                }
            }
            return out;
        }
        // FIFO: the oldest available groups first; from each, its visible
        // messages in order until one is not, so the group stays blocked
        // behind what is in flight.
        std::vector<std::pair<std::uint64_t, std::string>> heads;
        scan_prefix(p + "h/", [&](std::string_view k, std::string_view) {
            const auto rest = k.substr(p.size() + 2);
            if (const auto seq = queue_keys::parse_hex(rest.substr(0, 16));
                seq && rest.size() > 17) {
                heads.emplace_back(*seq, std::string(rest.substr(17)));
            }
            return heads.size() < want;
        });
        for (const auto& [head, group] : heads) {
            if (out.size() == want) {
                break;
            }
            std::vector<std::uint64_t> run;
            const auto gp = group_prefix(p, group);
            scan_prefix(gp, [&](std::string_view k, std::string_view) {
                const auto seq = queue_keys::parse_hex(k.substr(gp.size()));
                if (!seq) {
                    return false;
                }
                const auto m = load_message(p, *seq);
                if (!m || m->status != state::visible) {
                    return false;
                }
                run.push_back(*seq);
                return out.size() + run.size() < want;
            });
            for (const auto seq : run) {
                if (auto m = load_message(p, seq)) {
                    if (dead_letter_due(cmd, *m, seq)) {
                        move_to_dead_letter(t, p, c, seq, *m, *cmd.redrive, cmd.now_ms);
                        continue;
                    }
                    out.push_back(deliver(p, c, seq, *m, cmd.now_ms, deadline, t));
                }
            }
        }
        return out;
    }

    /// Up to `want` visible messages of a standard partition, oldest first
    /// within each message group, taking one from each group in turn
    /// (fair queues, Requirement 5.8): a group with a deep backlog takes
    /// one place per round, so a quiet group's message waits for one
    /// round, not for the backlog. The turn goes on from the group served
    /// last (`c/`), so with more groups than places every group is reached.
    /// A queue without message groups has the one group "": oldest first.
    auto fair_pick(const std::string& p, std::uint32_t want) -> std::vector<std::uint64_t> {
        std::vector<std::string> groups;
        scan_prefix(p + "n/", [&](std::string_view k, std::string_view) {
            groups.emplace_back(k.substr(p.size() + 2));
            return groups.size() < k_max_fair_groups;
        });
        std::vector<std::uint64_t> picked;
        if (groups.empty()) {
            return picked;
        }
        // Rotate to the group after the one served last.
        if (const auto last = read(p + "c/"); last && groups.size() > 1) {
            const auto it = std::upper_bound(groups.begin(), groups.end(), *last);
            std::rotate(groups.begin(), it == groups.end() ? groups.begin() : it, groups.end());
        }
        std::vector<std::vector<std::uint64_t>> runs(groups.size());
        // At most `want` groups can be served, each at most `want` times.
        for (std::size_t g = 0; g < groups.size() && g < want; ++g) {
            const auto fp = fair_prefix(p, groups[g]);
            scan_prefix(fp, [&](std::string_view k, std::string_view) {
                if (const auto seq = queue_keys::parse_hex(k.substr(fp.size()))) {
                    runs[g].push_back(*seq);
                }
                return runs[g].size() < want;
            });
        }
        std::size_t last_group = 0;
        for (std::size_t round = 0; picked.size() < want; ++round) {
            bool any = false;
            for (std::size_t g = 0; g < runs.size() && picked.size() < want; ++g) {
                if (round < runs[g].size()) {
                    picked.push_back(runs[g][round]);
                    last_group = g;
                    any = true;
                }
            }
            if (!any) {
                break;
            }
        }
        if (groups.size() > 1) {
            put(p + "c/", groups[last_group]);
        }
        return picked;
    }

    auto move_one(const queue_target& t, const std::string& p, partition_counters& c,
                  const move_entry& mv, std::uint64_t now) -> entry_result {
        entry_result e{{}, entry_result::status::stale, {}, mv.sequence};
        auto d = mv.dest;
        const auto m = load_message(p, mv.sequence);
        if (!m || m->status != state::visible || d.queue_id == t.queue_id) {
            return e;
        }
        const auto n = std::max<std::uint16_t>(mv.dest_partitions, 1);
        d.partition =
            static_cast<std::uint16_t>((d.fifo ? group_hash(m->group_id) : mv.sequence) % n);
        if (!_range.contains(queue_keys::partition_prefix(d))) {
            return e;  // across groups: a transaction, with task 12
        }
        e.outcome = entry_result::status::ok;
        e.message_id = m->message_id;
        transfer(t, p, c, mv.sequence, *m, d, {}, now);
        return e;
    }

    auto delete_message(const queue_target& t, const std::string& p, partition_counters& c,
                        const receipt_ref& r) -> entry_result {
        entry_result e{r.entry_id, entry_result::status::ok, {}, r.sequence};
        const auto m = load_message(p, r.sequence);
        if (!m || m->receive_sequence != r.receive_sequence || r.receive_sequence == 0) {
            e.outcome = entry_result::status::stale;
            return e;
        }
        e.message_id = m->message_id;
        remove(t, p, c, r.sequence, *m);
        return e;
    }

    auto change_visibility(const queue_target& t, const std::string& p, partition_counters& c,
                           std::uint64_t now, const receipt_ref& r) -> entry_result {
        entry_result e{r.entry_id, entry_result::status::ok, {}, r.sequence};
        auto m = load_message(p, r.sequence);
        if (!m || m->receive_sequence != r.receive_sequence || r.receive_sequence == 0) {
            e.outcome = entry_result::status::invalid_receipt;
            return e;
        }
        e.message_id = m->message_id;
        if (m->status != state::in_flight) {
            e.outcome = entry_result::status::not_inflight;
            return e;
        }
        const auto deadline = now + std::uint64_t{r.visibility_timeout_s} * 1000;
        if (deadline > m->last_receive_ms + k_max_visibility_ms) {
            e.outcome = entry_result::status::timeout_too_long;
            return e;
        }
        if (r.visibility_timeout_s == 0) {
            transition(t, p, c, r.sequence, *m, state::visible, 0);
        } else {
            transition(t, p, c, r.sequence, *m, state::in_flight, deadline);
        }
        return e;
    }

    // -- applied index -----------------------------------------------------

    static auto put_applied_at(kythira::write_batch& batch, const std::string& at, LogIndex index)
        -> void {
        std::string v;
        command_detail::put_le<std::uint64_t>(v, static_cast<std::uint64_t>(index));
        batch.put(kythira::column_family::meta, at, std::move(v));
    }

    auto trim_ring() -> void {
        const auto durable = engine().durable_sequence();
        while (_ring.size() > 1 && _ring[1].second <= durable) {
            _durable_floor = _ring.front().first;
            _ring.pop_front();
        }
    }

    engine_type* _engine = nullptr;
    kythira::key_range _range;
    LogIndex _applied{};
    LogIndex _durable_floor{};
    std::deque<std::pair<LogIndex, kythira::engine_sequence>> _ring;
    kythira::write_batch* _batch = nullptr;
    std::map<std::string, std::optional<std::string>, std::less<>> _overlay;
    std::vector<kythira::key_range> _erased;
    availability_listener _listener;
    /// What the entries staged since the last commit did, for `_listener`.
    std::vector<std::pair<queue_target, bool>> _events;
};

}  // namespace kythira::sqs
