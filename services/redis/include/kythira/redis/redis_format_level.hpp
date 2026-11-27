// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_format_level.hpp
/// The Redis format level and the format gate
/// (.kiro/specs/redis-general-data-types/ task 2, design Component 8,
/// Requirement 14.3-14.5).
///
/// A binary's format level is the newest log and snapshot format it reads:
/// level 2 is records `0x01`-`0x07`, level 3 adds the format-`0x03` records
/// (`exec`, `range_delete`, `format_gate`, `remove_members`). A group writes
/// the newer formats only after a `format_gate{level}` entry has applied on
/// it, and `KYTHIRA.FORMAT UPGRADE` proposes that gate only once every node
/// reports a level at least as high, so no replica is ever handed an entry it
/// cannot read.
///
/// What a state machine does with each record, shared by every store:
///
/// - a record whose version byte is above this binary's level, or a gate
///   naming a higher level, throws `redis_format_too_new`. The Raft core's
///   default `halt` policy then stops applying the group's log, with the
///   message in its log, rather than skipping the entry: an old binary
///   started on a new data directory fails loudly (Requirement 14.4);
/// - a gate raises the group's level, one way (Requirement 14.5);
/// - a format-`0x03` record other than a gate, met before the group's gate,
///   is refused: it changes nothing and its apply result says so. Only a bug
///   can propose one, since front ends check the level first.

#include <kythira/redis/redis_kv_commands.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace kythira {

/// The newest Redis format level this binary reads and writes.
inline constexpr std::uint16_t k_redis_format_level = 3;

/// The level the format-`0x03` records and the typed-value commands need.
inline constexpr std::uint16_t k_redis_typed_values_level = 3;

/// The level before any gate: records `0x01`-`0x07`, which every binary
/// since the redis-compatible-kv spec reads.
inline constexpr std::uint16_t k_redis_base_format_level = 2;
/// The phase 1 task that shipped `KYTHIRA.FORMAT`: commands of this task
/// and earlier are served also by a node built without the data types.
inline constexpr std::uint8_t k_redis_format_gate_task = 2;

/// The reply a front end gives a command that needs a level the cluster has
/// not reached (Requirement 14.3).
inline constexpr std::string_view k_redis_format_gate_error =
    "ERR this cluster has not enabled typed values yet (KYTHIRA.FORMAT)";

/// The reply on a store that holds only strings, the disk-backed build
/// cache (`KYTHIRA_CACHE_PERSISTENCE=file`), to every command that needs
/// more than a plain string write (Requirement 13.3). That store never
/// passes the gate, so its log and snapshot formats never change.
inline constexpr std::string_view k_redis_string_only_store_error =
    "ERR this command needs KYTHIRA_CACHE_PERSISTENCE=memory or engine";

/// A log entry or snapshot this binary is too old to read.
class redis_format_too_new : public std::runtime_error {
public:
    explicit redis_format_too_new(std::uint16_t needed)
        : std::runtime_error("this log needs Redis format level " + std::to_string(needed) +
                             "; run a newer build (this one reads up to level " +
                             std::to_string(k_redis_format_level) + ")"),
          _needed(needed) {}

    [[nodiscard]] auto needed() const noexcept -> std::uint16_t { return _needed; }

private:
    std::uint16_t _needed;
};

/// An `exec` record naming a command this build does not apply. Like a
/// newer format it halts the group's apply instead of being skipped, since
/// a replica that skipped it would diverge from one that applied it.
class redis_unknown_command_id : public std::runtime_error {
public:
    explicit redis_unknown_command_id(std::uint16_t id)
        : std::runtime_error("this log has an exec record for command id " + std::to_string(id) +
                             ", which this build does not apply; run a newer build"),
          _id(id) {}

    [[nodiscard]] auto id() const noexcept -> std::uint16_t { return _id; }

private:
    std::uint16_t _id;
};

/// The format level a log record needs, from its version byte: 2 for
/// `0x01`/`0x02`, otherwise the version byte itself (`0x03` is level 3).
/// An empty buffer needs nothing.
[[nodiscard]] constexpr auto redis_record_level(std::span<const std::byte> record) noexcept
    -> std::uint16_t {
    if (record.empty()) {
        return 0;
    }
    const auto version = static_cast<std::uint8_t>(record[0]);
    return version <= redis_kv_format_version_2 ? k_redis_base_format_level : version;
}

/// Throws `redis_format_too_new` when `record` needs a level above this
/// binary's. Every store calls it before decoding an entry.
inline auto require_redis_record_level(std::span<const std::byte> record) -> void {
    if (const auto needed = redis_record_level(record); needed > k_redis_format_level) {
        throw redis_format_too_new(needed);
    }
}

/// What applying a format-`0x03` record did, as its apply result byte.
enum class redis_v3_apply_status : std::uint8_t {
    unchanged = 0,
    changed = 1,
    /// A typed record before the group's gate (a bug upstream).
    refused_before_gate = 2,
};

/// Applies the parts of a format-`0x03` record every store shares: the gate,
/// and the refusal before it. `SM` provides `format_level()` and
/// `enable_format(level)`. Returns the status, or `nullopt` when the record
/// is a typed record after the gate, which the store applies itself (tasks
/// 3 onwards; until then such a record changes nothing).
///
/// @throws redis_format_too_new for a gate above this binary's level.
/// @throws redis_kv_codec_error for a malformed record.
template<typename SM>
auto apply_redis_v3_common(SM& sm, const redis_kv_v3_command& record)
    -> std::optional<redis_v3_apply_status> {
    if (const auto* gate = std::get_if<redis_kv_format_gate_command>(&record)) {
        if (gate->_level > k_redis_format_level) {
            throw redis_format_too_new(gate->_level);
        }
        // A gate below the first gated level asks for nothing new.
        if (gate->_level < k_redis_typed_values_level || gate->_level <= sm.format_level()) {
            return redis_v3_apply_status::unchanged;
        }
        sm.enable_format(gate->_level);
        return redis_v3_apply_status::changed;
    }
    if (sm.format_level() < k_redis_typed_values_level) {
        return redis_v3_apply_status::refused_before_gate;
    }
    return std::nullopt;
}

/// The apply result bytes for a status.
[[nodiscard]] inline auto redis_v3_apply_result(redis_v3_apply_status s) -> std::vector<std::byte> {
    return {static_cast<std::byte>(s)};
}

}  // namespace kythira
