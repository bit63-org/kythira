// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_kv_commands.hpp
/// @brief Binary log-entry codec for the Redis-compatible KV state machine
///        (.kiro/specs/redis-compatible-kv/ design Component 2).
///
/// Every command the gateway proposes to a shard is one of these records;
/// `redis_kv_state_machine::apply` decodes nothing else. The format is a
/// hand-rolled big-endian layout rather than JSON/CBOR because the value is
/// an opaque compiler artefact: base64-ing an 8 MiB object file to go through
/// a text serializer would cost more than the whole Raft round trip.
///
///     byte 0        format version, always 0x01
///     byte 1        opcode
///     u32 BE        key length
///     key bytes
///     payload       per opcode, below
///
///     set   (0x01)  u64 BE expire_at_ms (0 = never), u32 BE value len, value
///     del   (0x02)  (no payload)
///     sweep (0x03)  key is empty; u32 BE count, then count x
///                   { u32 BE keylen, key, u64 BE expire_at_ms }
///     evict (0x04)  key is empty; u32 BE count, then count x { u32 BE keylen, key }
///
/// Format version 0x02 (.kiro/specs/disk-backed-build-cache/ design Component
/// 2) adds three opcodes for the disk-backed store. Opcodes 0x01-0x04 keep
/// version 0x01, so a log written by the in-memory gateway decodes unchanged
/// and the in-memory gateway's entries stay byte-identical; 0x05-0x07 are
/// valid only under version 0x02.
///
///     put_chunk (0x05)  key is the key being uploaded (routing only);
///                       32-byte sha256; u32 BE len; bytes
///     commit    (0x06)  key; u64 BE expire_at_ms; u64 BE total_len;
///                       32-byte value sha256; u32 BE n; n x 32-byte chunk sha256
///     touch     (0x07)  key is empty; u32 BE count, then count x { u32 BE keylen, key }
///
/// `put_chunk` carries the uploading key, where design.md's layout left it
/// empty: `multi_raft` routes every proposal by `redis_kv_partitioner`, and an
/// empty routing key is refused by cross-shard admission, so a chunk must name
/// the shard its `commit` will land in. `touch` is never proposed through the
/// log (it travels on the forwarding link as an advisory batch); the opcode is
/// reserved here so the format stays one namespace.
///
/// Format version 0x03 (.kiro/specs/redis-general-data-types/ design
/// Component 2) carries every command added by that spec in one general
/// record, so a new command adds a registry id, not a record layout
/// (Requirement 14.1). Like versions 0x01 and 0x02, a 0x03 record starts with
/// the version byte, the opcode and the length-prefixed routing key, so
/// `redis_kv_command_key` reads every format the same way; the design's
/// layout follows that header. Opcodes 0x08-0x0B are valid only under 0x03.
/// They decode into `redis_kv_v3_command` (`decode_redis_kv_v3_command`), not
/// into `redis_kv_command`, so a state machine that has not passed the
/// format gate still refuses a 0x03 record as an unknown version.
///
///     exec           (0x08)  key is the first key argument (routing; empty
///                            for a command without keys); u16 BE command id
///                            (redis_command_ids.hpp); u64 BE now_ms, the
///                            leader's command time; u8 policy bits; u32 BE
///                            argc, then argc x { u32 BE len, bytes }; u32 BE
///                            mutable-key bitmap length, bitmap
///     range_delete   (0x09)  key is a key inside the group (routing); u32 BE
///                            lo len, lo; u32 BE hi len, hi; u32 BE max keys
///     format_gate    (0x0A)  key is a key inside the group (routing); u16 BE
///                            level
///     remove_members (0x0B)  key is the collection; u32 BE n, then
///                            n x { u32 BE len, member }
///
/// Opcode 0x0C (`script`) is reserved for phase 2 and refused until then.
///
/// Big-endian throughout matches `default_shard_key_codec` so the byte order
/// in a log dump is the byte order in a shard-map dump.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira {

inline constexpr std::uint8_t redis_kv_format_version = 0x01;
/// The version byte of `put_chunk`, `commit` and `touch` records.
inline constexpr std::uint8_t redis_kv_format_version_2 = 0x02;
/// The version byte of the records the general data types add
/// (`exec`, `range_delete`, `format_gate`, `remove_members`).
inline constexpr std::uint8_t redis_kv_format_version_3 = 0x03;

/// A SHA-256, as the chunk store names chunks.
using redis_kv_sha256 = std::array<std::byte, 32>;

enum class redis_kv_opcode : std::uint8_t {
    set = 0x01,
    del = 0x02,
    sweep = 0x03,
    evict = 0x04,
    put_chunk = 0x05,
    commit = 0x06,
    touch = 0x07,
    exec = 0x08,
    range_delete = 0x09,
    format_gate = 0x0A,
    remove_members = 0x0B,
    /// Reserved for phase 2 scripts; no record uses it yet.
    script = 0x0C,
};

struct redis_kv_set_command {
    std::string _key;
    std::vector<std::byte> _value;
    /// Absolute wall-clock deadline in ms since the Unix epoch; 0 = never.
    /// The gateway resolves `SETEX seconds` into this on the leader before
    /// proposing, so `apply` never consults a clock.
    std::uint64_t _expire_at_ms = 0;
};

struct redis_kv_del_command {
    std::string _key;
};

/// One expired key named by the leader's sweep. `apply` deletes it only if the
/// stored deadline still equals `_expire_at_ms`: a concurrent SET that
/// replaced the value (and its deadline) between the sweep being proposed and
/// applied must survive.
struct redis_kv_sweep_entry {
    std::string _key;
    std::uint64_t _expire_at_ms = 0;
};

struct redis_kv_sweep_command {
    std::vector<redis_kv_sweep_entry> _entries;
};

struct redis_kv_evict_command {
    std::vector<std::string> _keys;
};

/// One chunk of a value being uploaded to the disk-backed store. `apply`
/// stores it and holds it as pending until a `commit` names it or the orphan
/// grace period passes.
struct redis_kv_put_chunk_command {
    /// The key whose upload this chunk belongs to. Routing only: the chunk is
    /// stored by hash, and `apply` does not look at the key.
    std::string _key;
    redis_kv_sha256 _sha{};
    std::vector<std::byte> _bytes;
};

/// Bind `_key` to the value made of `_chunks`, in order. A key becomes
/// visible only when this is applied (Requirement 3.2).
struct redis_kv_commit_command {
    std::string _key;
    std::uint64_t _expire_at_ms = 0;
    std::uint64_t _total_len = 0;
    /// SHA-256 of the whole value: what a reader checks the reassembled
    /// bytes against, and the HTTP `ETag` (Requirement 3.7).
    redis_kv_sha256 _value_sha{};
    std::vector<redis_kv_sha256> _chunks;
};

/// Keys a follower served, for the leader's LRU (Requirement 6.2). Advisory;
/// never proposed through the log.
struct redis_kv_touch_command {
    std::vector<std::string> _keys;
};

/// Policy bits of an `exec` record (design Component 4).
namespace redis_kv_exec_policy {
/// The immutable-value rule was on when the command was proposed.
inline constexpr std::uint8_t immutable_rule = 0x01;
/// Every bit above the known ones must be zero.
inline constexpr std::uint8_t known_bits = immutable_rule;
}  // namespace redis_kv_exec_policy

/// One command of the general data types, with every input `apply()` needs:
/// the registry id, the leader's command time (Requirement 2.1), and the
/// RESP arguments after normalisation (relative TTLs made absolute, aliases
/// resolved). `_args` excludes the command name, which `_command_id`
/// replaces.
struct redis_kv_exec_command {
    /// Routing only: the command's first key, or empty when it has none.
    std::string _key;
    std::uint16_t _command_id = 0;
    std::uint64_t _now_ms = 0;
    std::uint8_t _policy = 0;
    std::vector<std::string> _args;
    /// One bit per key argument, in key order, least significant bit first:
    /// set when that key is in a mutable prefix (Requirement 5).
    std::vector<std::byte> _mutable_keys;

    auto operator==(const redis_kv_exec_command&) const -> bool = default;
};

/// Delete every key in `[_lo, _hi)` on the group, at most `_max_keys` of them
/// in this entry (prefix delete and flush, design Component 7). An empty
/// `_hi` is the end of the keyspace.
struct redis_kv_range_delete_command {
    std::string _key;
    std::string _lo;
    std::string _hi;
    std::uint32_t _max_keys = 0;

    auto operator==(const redis_kv_range_delete_command&) const -> bool = default;
};

/// Turn on format `_level` for the group from this entry on (design
/// Component 8). One-way.
struct redis_kv_format_gate_command {
    std::string _key;
    std::uint16_t _level = 0;

    auto operator==(const redis_kv_format_gate_command&) const -> bool = default;
};

/// Remove exactly these members from the collection at `_key`: `SPOP` with
/// the members the leader picked, so replicas need no random choice.
struct redis_kv_remove_members_command {
    std::string _key;
    std::vector<std::string> _members;

    auto operator==(const redis_kv_remove_members_command&) const -> bool = default;
};

using redis_kv_v3_command =
    std::variant<redis_kv_exec_command, redis_kv_range_delete_command, redis_kv_format_gate_command,
                 redis_kv_remove_members_command>;

using redis_kv_command =
    std::variant<redis_kv_set_command, redis_kv_del_command, redis_kv_sweep_command,
                 redis_kv_evict_command, redis_kv_put_chunk_command, redis_kv_commit_command,
                 redis_kv_touch_command>;

class redis_kv_codec_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace redis_kv_detail {

inline auto put_u32(std::vector<std::byte>& out, std::uint32_t v) -> void {
    out.push_back(static_cast<std::byte>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::byte>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(v & 0xFF));
}

inline auto put_u64(std::vector<std::byte>& out, std::uint64_t v) -> void {
    put_u32(out, static_cast<std::uint32_t>(v >> 32));
    put_u32(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
}

inline auto put_u16(std::vector<std::byte>& out, std::uint16_t v) -> void {
    out.push_back(static_cast<std::byte>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(v & 0xFF));
}

inline auto put_bytes(std::vector<std::byte>& out, std::span<const std::byte> bytes) -> void {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

inline auto put_string(std::vector<std::byte>& out, std::string_view s) -> void {
    put_bytes(out, std::as_bytes(std::span<const char>(s.data(), s.size())));
}

/// Cursor over an input buffer; every read is bounds-checked and a short
/// buffer is a `redis_kv_codec_error`, never undefined behaviour.
class reader {
public:
    explicit reader(std::span<const std::byte> data) : _data(data) {}

    auto u8() -> std::uint8_t {
        need(1);
        return static_cast<std::uint8_t>(_data[_pos++]);
    }

    auto u16() -> std::uint16_t {
        need(2);
        const auto hi = static_cast<std::uint16_t>(_data[_pos++]);
        const auto lo = static_cast<std::uint16_t>(_data[_pos++]);
        return static_cast<std::uint16_t>((hi << 8) | lo);
    }

    auto u32() -> std::uint32_t {
        need(4);
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8) | static_cast<std::uint32_t>(_data[_pos++]);
        }
        return v;
    }

    auto u64() -> std::uint64_t {
        auto hi = static_cast<std::uint64_t>(u32());
        auto lo = static_cast<std::uint64_t>(u32());
        return (hi << 32) | lo;
    }

    auto bytes(std::size_t n) -> std::span<const std::byte> {
        need(n);
        auto out = _data.subspan(_pos, n);
        _pos += n;
        return out;
    }

    auto string(std::size_t n) -> std::string {
        auto b = bytes(n);
        return std::string(reinterpret_cast<const char*>(b.data()), b.size());
    }

    [[nodiscard]] auto remaining() const noexcept -> std::size_t { return _data.size() - _pos; }

private:
    auto need(std::size_t n) const -> void {
        if (_data.size() - _pos < n) {
            throw redis_kv_codec_error("truncated redis kv command");
        }
    }

    std::span<const std::byte> _data;
    std::size_t _pos = 0;
};

inline auto put_header(std::vector<std::byte>& out, redis_kv_opcode op, std::string_view key)
    -> void {
    if (key.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("key too long to encode");
    }
    const auto code = static_cast<std::uint8_t>(op);
    out.push_back(static_cast<std::byte>(code >= 0x08   ? redis_kv_format_version_3
                                         : code >= 0x05 ? redis_kv_format_version_2
                                                        : redis_kv_format_version));
    out.push_back(static_cast<std::byte>(op));
    put_u32(out, static_cast<std::uint32_t>(key.size()));
    put_string(out, key);
}

/// `u32 BE len, bytes`, refusing a string too long for the length field.
inline auto put_lp_string(std::vector<std::byte>& out, std::string_view s) -> void {
    if (s.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("string too long to encode");
    }
    put_u32(out, static_cast<std::uint32_t>(s.size()));
    put_string(out, s);
}

/// A `u32 BE n` followed by n length-prefixed strings. Every string is at
/// least four bytes on the wire, so a count the remaining buffer cannot hold
/// is refused before anything is allocated.
inline auto read_lp_strings(reader& in, const char* what) -> std::vector<std::string> {
    const auto n = in.u32();
    if (static_cast<std::size_t>(n) > in.remaining() / 4) {
        throw redis_kv_codec_error(std::string(what) + " count exceeds buffer");
    }
    std::vector<std::string> out;
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        out.push_back(in.string(in.u32()));
    }
    return out;
}

}  // namespace redis_kv_detail

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_set_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._value.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("value too long to encode");
    }
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size() + 8 + 4 + c._value.size());
    put_header(out, redis_kv_opcode::set, c._key);
    put_u64(out, c._expire_at_ms);
    put_u32(out, static_cast<std::uint32_t>(c._value.size()));
    put_bytes(out, c._value);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_del_command& c)
    -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size());
    redis_kv_detail::put_header(out, redis_kv_opcode::del, c._key);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_sweep_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._entries.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("too many sweep entries to encode");
    }
    std::vector<std::byte> out;
    put_header(out, redis_kv_opcode::sweep, {});
    put_u32(out, static_cast<std::uint32_t>(c._entries.size()));
    for (const auto& e : c._entries) {
        if (e._key.size() > 0xFFFFFFFFu) {
            throw redis_kv_codec_error("key too long to encode");
        }
        put_u32(out, static_cast<std::uint32_t>(e._key.size()));
        put_string(out, e._key);
        put_u64(out, e._expire_at_ms);
    }
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_evict_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._keys.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("too many evict entries to encode");
    }
    std::vector<std::byte> out;
    put_header(out, redis_kv_opcode::evict, {});
    put_u32(out, static_cast<std::uint32_t>(c._keys.size()));
    for (const auto& k : c._keys) {
        if (k.size() > 0xFFFFFFFFu) {
            throw redis_kv_codec_error("key too long to encode");
        }
        put_u32(out, static_cast<std::uint32_t>(k.size()));
        put_string(out, k);
    }
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_put_chunk_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._bytes.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("chunk too long to encode");
    }
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size() + 32 + 4 + c._bytes.size());
    put_header(out, redis_kv_opcode::put_chunk, c._key);
    put_bytes(out, c._sha);
    put_u32(out, static_cast<std::uint32_t>(c._bytes.size()));
    put_bytes(out, c._bytes);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_commit_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._chunks.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("too many chunks to encode");
    }
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size() + 8 + 8 + 32 + 4 + (32 * c._chunks.size()));
    put_header(out, redis_kv_opcode::commit, c._key);
    put_u64(out, c._expire_at_ms);
    put_u64(out, c._total_len);
    put_bytes(out, c._value_sha);
    put_u32(out, static_cast<std::uint32_t>(c._chunks.size()));
    for (const auto& sha : c._chunks) {
        put_bytes(out, sha);
    }
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_touch_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._keys.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("too many touch entries to encode");
    }
    std::vector<std::byte> out;
    put_header(out, redis_kv_opcode::touch, {});
    put_u32(out, static_cast<std::uint32_t>(c._keys.size()));
    for (const auto& k : c._keys) {
        if (k.size() > 0xFFFFFFFFu) {
            throw redis_kv_codec_error("key too long to encode");
        }
        put_u32(out, static_cast<std::uint32_t>(k.size()));
        put_string(out, k);
    }
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_command& c)
    -> std::vector<std::byte> {
    return std::visit([](const auto& v) { return encode_redis_kv_command(v); }, c);
}

/// Decode one record. Rejects truncated buffers, trailing bytes, unknown
/// versions and unknown opcodes — a state machine that tolerated any of
/// those would diverge silently across replicas.
[[nodiscard]] inline auto decode_redis_kv_command(std::span<const std::byte> data)
    -> redis_kv_command {
    using namespace redis_kv_detail;
    reader in(data);
    auto version = in.u8();
    if (version != redis_kv_format_version && version != redis_kv_format_version_2) {
        throw redis_kv_codec_error("unknown redis kv command format version " +
                                   std::to_string(version));
    }
    auto op = in.u8();
    // Each opcode has exactly one version: 0x01-0x04 under 0x01, 0x05-0x07
    // under 0x02. A record that pairs them otherwise was not written by this
    // codec.
    if ((op >= 0x05) != (version == redis_kv_format_version_2)) {
        throw redis_kv_codec_error("redis kv opcode " + std::to_string(op) +
                                   " under format version " + std::to_string(version));
    }
    auto key_len = in.u32();
    auto key = in.string(key_len);

    redis_kv_command result;
    switch (static_cast<redis_kv_opcode>(op)) {
        case redis_kv_opcode::set: {
            redis_kv_set_command c;
            c._key = std::move(key);
            c._expire_at_ms = in.u64();
            auto value_len = in.u32();
            auto v = in.bytes(value_len);
            c._value.assign(v.begin(), v.end());
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::del: {
            result = redis_kv_del_command{std::move(key)};
            break;
        }
        case redis_kv_opcode::sweep: {
            if (!key.empty()) {
                throw redis_kv_codec_error("sweep record carries a key");
            }
            redis_kv_sweep_command c;
            auto count = in.u32();
            // Each entry is at least 12 bytes, so a count that cannot fit in
            // the buffer is rejected before any allocation.
            if (static_cast<std::size_t>(count) > in.remaining() / 12) {
                throw redis_kv_codec_error("sweep count exceeds buffer");
            }
            c._entries.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                redis_kv_sweep_entry e;
                auto n = in.u32();
                e._key = in.string(n);
                e._expire_at_ms = in.u64();
                c._entries.push_back(std::move(e));
            }
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::evict: {
            if (!key.empty()) {
                throw redis_kv_codec_error("evict record carries a key");
            }
            redis_kv_evict_command c;
            auto count = in.u32();
            if (static_cast<std::size_t>(count) > in.remaining() / 4) {
                throw redis_kv_codec_error("evict count exceeds buffer");
            }
            c._keys.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                auto n = in.u32();
                c._keys.push_back(in.string(n));
            }
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::put_chunk: {
            redis_kv_put_chunk_command c;
            c._key = std::move(key);
            auto sha = in.bytes(32);
            std::copy(sha.begin(), sha.end(), c._sha.begin());
            auto n = in.u32();
            auto b = in.bytes(n);
            c._bytes.assign(b.begin(), b.end());
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::commit: {
            redis_kv_commit_command c;
            c._key = std::move(key);
            c._expire_at_ms = in.u64();
            c._total_len = in.u64();
            auto sha = in.bytes(32);
            std::copy(sha.begin(), sha.end(), c._value_sha.begin());
            auto n = in.u32();
            if (static_cast<std::size_t>(n) > in.remaining() / 32) {
                throw redis_kv_codec_error("commit chunk count exceeds buffer");
            }
            c._chunks.resize(n);
            for (auto& chunk : c._chunks) {
                auto b = in.bytes(32);
                std::copy(b.begin(), b.end(), chunk.begin());
            }
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::touch: {
            if (!key.empty()) {
                throw redis_kv_codec_error("touch record carries a key");
            }
            redis_kv_touch_command c;
            auto count = in.u32();
            if (static_cast<std::size_t>(count) > in.remaining() / 4) {
                throw redis_kv_codec_error("touch count exceeds buffer");
            }
            c._keys.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                auto n = in.u32();
                c._keys.push_back(in.string(n));
            }
            result = std::move(c);
            break;
        }
        default:
            throw redis_kv_codec_error("unknown redis kv opcode " + std::to_string(op));
    }
    if (in.remaining() != 0) {
        throw redis_kv_codec_error("trailing bytes after redis kv command");
    }
    return result;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_exec_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if ((c._policy & ~redis_kv_exec_policy::known_bits) != 0) {
        throw redis_kv_codec_error("exec record with unknown policy bits");
    }
    if (c._args.size() > 0xFFFFFFFFu || c._mutable_keys.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("exec record too large to encode");
    }
    std::vector<std::byte> out;
    std::size_t size = 2 + 4 + c._key.size() + 2 + 8 + 1 + 4 + 4 + c._mutable_keys.size();
    for (const auto& a : c._args) {
        size += 4 + a.size();
    }
    out.reserve(size);
    put_header(out, redis_kv_opcode::exec, c._key);
    put_u16(out, c._command_id);
    put_u64(out, c._now_ms);
    out.push_back(static_cast<std::byte>(c._policy));
    put_u32(out, static_cast<std::uint32_t>(c._args.size()));
    for (const auto& a : c._args) {
        put_lp_string(out, a);
    }
    put_u32(out, static_cast<std::uint32_t>(c._mutable_keys.size()));
    put_bytes(out, c._mutable_keys);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_range_delete_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size() + 4 + c._lo.size() + 4 + c._hi.size() + 4);
    put_header(out, redis_kv_opcode::range_delete, c._key);
    put_lp_string(out, c._lo);
    put_lp_string(out, c._hi);
    put_u32(out, c._max_keys);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_format_gate_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    std::vector<std::byte> out;
    out.reserve(2 + 4 + c._key.size() + 2);
    put_header(out, redis_kv_opcode::format_gate, c._key);
    put_u16(out, c._level);
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_remove_members_command& c)
    -> std::vector<std::byte> {
    using namespace redis_kv_detail;
    if (c._members.size() > 0xFFFFFFFFu) {
        throw redis_kv_codec_error("too many members to encode");
    }
    std::vector<std::byte> out;
    put_header(out, redis_kv_opcode::remove_members, c._key);
    put_u32(out, static_cast<std::uint32_t>(c._members.size()));
    for (const auto& m : c._members) {
        put_lp_string(out, m);
    }
    return out;
}

[[nodiscard]] inline auto encode_redis_kv_command(const redis_kv_v3_command& c)
    -> std::vector<std::byte> {
    return std::visit([](const auto& v) { return encode_redis_kv_command(v); }, c);
}

/// True when `data` is a format-0x03 record (by its version byte alone).
[[nodiscard]] inline auto is_redis_kv_v3_record(std::span<const std::byte> data) noexcept -> bool {
    return !data.empty() && static_cast<std::uint8_t>(data[0]) == redis_kv_format_version_3;
}

/// Decode one format-0x03 record, with the same strictness as
/// `decode_redis_kv_command`: truncation, trailing bytes, another version,
/// an opcode outside 0x08-0x0B (including the reserved `script`) and unknown
/// policy bits are all errors.
[[nodiscard]] inline auto decode_redis_kv_v3_command(std::span<const std::byte> data)
    -> redis_kv_v3_command {
    using namespace redis_kv_detail;
    reader in(data);
    const auto version = in.u8();
    if (version != redis_kv_format_version_3) {
        throw redis_kv_codec_error("not a format 0x03 redis kv record (version " +
                                   std::to_string(version) + ")");
    }
    const auto op = in.u8();
    auto key = in.string(in.u32());

    redis_kv_v3_command result;
    switch (static_cast<redis_kv_opcode>(op)) {
        case redis_kv_opcode::exec: {
            redis_kv_exec_command c;
            c._key = std::move(key);
            c._command_id = in.u16();
            c._now_ms = in.u64();
            c._policy = in.u8();
            if ((c._policy & ~redis_kv_exec_policy::known_bits) != 0) {
                throw redis_kv_codec_error("exec record with unknown policy bits");
            }
            c._args = read_lp_strings(in, "exec argument");
            const auto bitmap = in.bytes(in.u32());
            c._mutable_keys.assign(bitmap.begin(), bitmap.end());
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::range_delete: {
            redis_kv_range_delete_command c;
            c._key = std::move(key);
            c._lo = in.string(in.u32());
            c._hi = in.string(in.u32());
            c._max_keys = in.u32();
            result = std::move(c);
            break;
        }
        case redis_kv_opcode::format_gate: {
            result = redis_kv_format_gate_command{std::move(key), in.u16()};
            break;
        }
        case redis_kv_opcode::remove_members: {
            redis_kv_remove_members_command c;
            c._key = std::move(key);
            c._members = read_lp_strings(in, "remove_members member");
            result = std::move(c);
            break;
        }
        default:
            throw redis_kv_codec_error("redis kv opcode " + std::to_string(op) +
                                       " under format version 3");
    }
    if (in.remaining() != 0) {
        throw redis_kv_codec_error("trailing bytes after redis kv command");
    }
    return result;
}

/// The routing key of a record without decoding its payload: the header key
/// for `set`/`del` and every format-0x03 record, the first entry's key for
/// `sweep`/`evict` (which the
/// leader builds from one shard, so any entry routes the same). Returns an
/// empty string for a record it cannot read; `multi_raft`'s cross-shard
/// admission then rejects the proposal instead of misrouting it.
[[nodiscard]] inline auto redis_kv_command_key(std::span<const std::byte> data) -> std::string {
    using namespace redis_kv_detail;
    try {
        reader in(data);
        const auto version = in.u8();
        if (version != redis_kv_format_version && version != redis_kv_format_version_2 &&
            version != redis_kv_format_version_3) {
            return {};
        }
        auto op = static_cast<redis_kv_opcode>(in.u8());
        auto key = in.string(in.u32());
        if (version == redis_kv_format_version_3) {
            // Every 0x03 record routes by its header key.
            return key;
        }
        if (op == redis_kv_opcode::set || op == redis_kv_opcode::del ||
            op == redis_kv_opcode::put_chunk || op == redis_kv_opcode::commit) {
            return key;
        }
        if (op == redis_kv_opcode::sweep || op == redis_kv_opcode::evict ||
            op == redis_kv_opcode::touch) {
            if (in.u32() == 0) {
                return {};
            }
            return in.string(in.u32());
        }
    } catch (const redis_kv_codec_error&) {
    }
    return {};
}

/// Satisfies `kythira::partitioner<std::string>` for `multi_raft_config::partitioner`.
struct redis_kv_partitioner {
    [[nodiscard]] auto key_of(const std::vector<std::byte>& command) const -> std::string {
        return redis_kv_command_key(command);
    }
};

/// Peek at the opcode without decoding the payload; used by the gateway's
/// audit/trace logging so that an 8 MiB value is never copied for a log line.
[[nodiscard]] inline auto peek_redis_kv_opcode(std::span<const std::byte> data)
    -> std::optional<redis_kv_opcode> {
    if (data.size() < 2) {
        return std::nullopt;
    }
    const auto version = static_cast<std::uint8_t>(data[0]);
    auto op = static_cast<std::uint8_t>(data[1]);
    if (version == redis_kv_format_version) {
        if (op < 0x01 || op > 0x04) {
            return std::nullopt;
        }
    } else if (version == redis_kv_format_version_2) {
        if (op < 0x05 || op > 0x07) {
            return std::nullopt;
        }
    } else if (version == redis_kv_format_version_3) {
        if (op < 0x08 || op > 0x0B) {
            return std::nullopt;
        }
    } else {
        return std::nullopt;
    }
    return static_cast<redis_kv_opcode>(op);
}

}  // namespace kythira
