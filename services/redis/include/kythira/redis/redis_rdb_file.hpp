// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_rdb_file.hpp
/// @brief Whole-file RDB reading and writing: the header, every opcode, the
///        CRC64 trailer and a version table, as a streaming pull reader and
///        push writer over byte sources and sinks
///        (.kiro/specs/redis-migration-tooling/ task 1, design Component 1;
///        Requirements 2.1-2.4).
///
/// ## What this layer does and does not decode
///
/// The reader walks the whole file and hands out one record at a time:
/// `AUX` fields, `SELECTDB`, `RESIZEDB`, `SLOT_INFO`, Valkey's
/// `SLOT_IMPORT`, `FUNCTION2` libraries, module `AUX` data, keys, and the
/// end of the file. A key comes out as its database, name, expiry, LRU idle
/// time or LFU counter, its RDB type byte and its **payload**: the exact
/// bytes of the value's serialization after the type byte. That is the body
/// of a `DUMP` reply without its 2-byte version and CRC footer, so the value
/// codec of `redis-general-data-types` task 43 (`redis_rdb.hpp`) plugs in as
/// `decode(type, payload)` and `encode(value) -> (type, payload)` without
/// touching the file framing. String payloads are decoded here already
/// (`rdb_decode_string_payload`), since keys need the same code.
///
/// To find where a value ends the reader still has to walk its structure
/// (a list is a count of nodes, a stream is listpacks plus groups, consumers
/// and pending entries, a module value is a sequence of typed fields ending
/// in an EOF mark). It walks without interpreting listpack, ziplist or
/// intset blobs and without decompressing LZF strings inside values, so a
/// payload is the server's bytes, unchanged.
///
/// ## Memory
///
/// The reader holds a fixed 64 KiB buffer and one record. It never sizes an
/// allocation from a length in the file: strings grow as their bytes arrive,
/// so a corrupt length runs out of input instead of exhausting memory, and
/// an LZF length larger than the compressed bytes can produce is refused
/// first. Memory is therefore bounded by the largest single value plus the
/// buffer (Requirement 2.3), and `rdb_reader_options` can cap both.
///
/// ## Versions and dialects
///
/// RDB 11 is the last version Redis and Valkey share (Redis 7.2, Valkey 7.2
/// to 8.1). After it they diverge and reuse the same numbers: Redis 7.4 to
/// 8.4 write `REDIS0012`, where types 22-25 are hashes with field
/// expiration; Valkey 9.0 writes `VALKEY080`, where type 22 is its own hash
/// with field expiration (Valkey treats 12-79 as foreign). So a format is
/// the pair (magic, version), `rdb_format`, and whether a type byte is
/// allowed, and what it means, depends on both. `rdb_targets` names each
/// reference server and the format it reads and writes.
///
/// ## Sources and sinks
///
/// `rdb_byte_source` and `rdb_byte_sink` are the only I/O. This header
/// provides memory, file descriptor (files and sockets), file path,
/// length-limited (a `$<len>` PSYNC transfer), ranged-read (object-store
/// `GET` with `Range`, through a callable) and part-upload (object-store
/// multipart upload, through a callable) adapters. The object-store
/// clients themselves are wired by the import and export tasks.

#include <kythira/redis/redis_rdb_crc64.hpp>
#include <kythira/redis/redis_rdb_lzf.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace kythira {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

enum class rdb_error_kind : std::uint8_t {
    /// The input ended inside a record or before the EOF opcode.
    truncated,
    /// A length, opcode or field is not valid RDB.
    corrupt,
    /// The magic or version is not one Kythira reads.
    unsupported_version,
    /// A type byte the file's format does not define (or one Kythira
    /// refuses, such as pre-release module values).
    unsupported_type,
    /// The CRC64 trailer does not match the file (Requirement 2.1: a
    /// mismatch fails the job).
    checksum_mismatch,
    /// A configured limit (`rdb_reader_options`) was exceeded.
    limit_exceeded,
    /// The source or sink failed (an errno-carrying I/O error).
    io,
};

[[nodiscard]] constexpr auto to_string(rdb_error_kind k) noexcept -> std::string_view {
    switch (k) {
        case rdb_error_kind::truncated:
            return "truncated";
        case rdb_error_kind::corrupt:
            return "corrupt";
        case rdb_error_kind::unsupported_version:
            return "unsupported_version";
        case rdb_error_kind::unsupported_type:
            return "unsupported_type";
        case rdb_error_kind::checksum_mismatch:
            return "checksum_mismatch";
        case rdb_error_kind::limit_exceeded:
            return "limit_exceeded";
        case rdb_error_kind::io:
            return "io";
    }
    return "unknown";
}

/// The only exception the reader and writer throw for bad input or I/O.
class rdb_error : public std::runtime_error {
public:
    rdb_error(rdb_error_kind kind, std::uint64_t offset, const std::string& what)
        : std::runtime_error("RDB " + std::string(to_string(kind)) + " at byte " +
                             std::to_string(offset) + ": " + what),
          _kind(kind),
          _offset(offset) {}

    [[nodiscard]] auto kind() const noexcept -> rdb_error_kind { return _kind; }
    /// Byte offset in the file at which the problem was found.
    [[nodiscard]] auto offset() const noexcept -> std::uint64_t { return _offset; }

private:
    rdb_error_kind _kind;
    std::uint64_t _offset;
};

// ---------------------------------------------------------------------------
// Formats, types, opcodes and the version table
// ---------------------------------------------------------------------------

/// The magic string at the start of the file. `DUMP` payloads have none.
enum class rdb_magic : std::uint8_t {
    redis,   ///< "REDIS" + 4 digits
    valkey,  ///< "VALKEY" + 3 digits (Valkey 9.0 and later)
};

/// A file format: magic plus version number.
struct rdb_format {
    rdb_magic _magic = rdb_magic::redis;
    std::uint16_t _version = 11;

    friend constexpr auto operator==(const rdb_format&, const rdb_format&) -> bool = default;
};

/// Oldest and newest versions the reader accepts (Requirement 2.1: RDB 9 to
/// 12, plus Valkey 9's 80).
inline constexpr std::uint16_t rdb_min_read_version = 9;
inline constexpr std::uint16_t rdb_max_redis_version = 12;
inline constexpr std::uint16_t rdb_valkey_version = 80;

/// The 9-byte header for a format.
[[nodiscard]] inline auto rdb_header_bytes(rdb_format f) -> std::string {
    std::array<char, 16> buf{};
    if (f._magic == rdb_magic::redis) {
        std::snprintf(buf.data(), buf.size(), "REDIS%04u",
                      static_cast<unsigned>(f._version % 10000U));
    } else {
        std::snprintf(buf.data(), buf.size(), "VALKEY%03u",
                      static_cast<unsigned>(f._version % 1000U));
    }
    return {buf.data(), 9};
}

/// Whether the reader accepts a format.
[[nodiscard]] constexpr auto rdb_format_supported(rdb_format f) noexcept -> bool {
    if (f._magic == rdb_magic::redis) {
        return f._version >= rdb_min_read_version && f._version <= rdb_max_redis_version;
    }
    return f._version == rdb_valkey_version;
}

/// RDB value type bytes. 0-21 mean the same in every dialect; 22-25 are
/// dialect-specific (see `rdb_type_known`).
namespace rdb_type {
inline constexpr std::uint8_t string = 0;
inline constexpr std::uint8_t list = 1;
inline constexpr std::uint8_t set = 2;
inline constexpr std::uint8_t zset = 3;
inline constexpr std::uint8_t hash = 4;
inline constexpr std::uint8_t zset_2 = 5;
inline constexpr std::uint8_t module_pre_ga = 6;
inline constexpr std::uint8_t module_2 = 7;
inline constexpr std::uint8_t hash_zipmap = 9;
inline constexpr std::uint8_t list_ziplist = 10;
inline constexpr std::uint8_t set_intset = 11;
inline constexpr std::uint8_t zset_ziplist = 12;
inline constexpr std::uint8_t hash_ziplist = 13;
inline constexpr std::uint8_t list_quicklist = 14;
inline constexpr std::uint8_t stream_listpacks = 15;
inline constexpr std::uint8_t hash_listpack = 16;
inline constexpr std::uint8_t zset_listpack = 17;
inline constexpr std::uint8_t list_quicklist_2 = 18;
inline constexpr std::uint8_t stream_listpacks_2 = 19;
inline constexpr std::uint8_t set_listpack = 20;
inline constexpr std::uint8_t stream_listpacks_3 = 21;
// Redis RDB 12 (7.4+): hashes with field expiration.
inline constexpr std::uint8_t redis_hash_metadata_pre_ga = 22;
inline constexpr std::uint8_t redis_hash_listpack_ex_pre_ga = 23;
inline constexpr std::uint8_t redis_hash_metadata = 24;
inline constexpr std::uint8_t redis_hash_listpack_ex = 25;
// Valkey RDB 80 (9.0+): hash with per-field expiry.
inline constexpr std::uint8_t valkey_hash_2 = 22;
}  // namespace rdb_type

/// Opcodes that are not value types.
namespace rdb_opcode {
inline constexpr std::uint8_t slot_import = 243;  ///< Valkey 9.0+
inline constexpr std::uint8_t slot_info = 244;    ///< Redis 7.4+, read by Valkey 8+
inline constexpr std::uint8_t function2 = 245;
inline constexpr std::uint8_t function_pre_ga = 246;
inline constexpr std::uint8_t module_aux = 247;
inline constexpr std::uint8_t idle = 248;
inline constexpr std::uint8_t freq = 249;
inline constexpr std::uint8_t aux = 250;
inline constexpr std::uint8_t resizedb = 251;
inline constexpr std::uint8_t expiretime_ms = 252;
inline constexpr std::uint8_t expiretime = 253;
inline constexpr std::uint8_t selectdb = 254;
inline constexpr std::uint8_t eof = 255;
}  // namespace rdb_opcode

/// Field opcodes inside a module value or module `AUX` record.
namespace rdb_module_opcode {
inline constexpr std::uint64_t eof = 0;
inline constexpr std::uint64_t sint = 1;
inline constexpr std::uint64_t uint = 2;
inline constexpr std::uint64_t float_ = 3;
inline constexpr std::uint64_t double_ = 4;
inline constexpr std::uint64_t string = 5;
}  // namespace rdb_module_opcode

/// Whether `type` is a value type in format `f` (what the format's own
/// servers load). Pre-release module values (6) are never accepted; Redis
/// refuses them too.
[[nodiscard]] constexpr auto rdb_type_known(rdb_format f, std::uint8_t type) noexcept -> bool {
    using namespace rdb_type;
    if (!rdb_format_supported(f)) {
        return false;
    }
    const std::uint16_t v = f._magic == rdb_magic::valkey ? 11 : f._version;
    switch (type) {
        case string:
        case list:
        case set:
        case zset:
        case hash:
        case hash_zipmap:
        case list_ziplist:
        case set_intset:
        case zset_ziplist:
        case hash_ziplist:
            return true;
        case zset_2:
        case module_2:
            return v >= 8;
        case list_quicklist:
            return v >= 7;
        case stream_listpacks:
            return v >= 9;
        case hash_listpack:
        case zset_listpack:
        case list_quicklist_2:
        case stream_listpacks_2:
            return v >= 10;
        case set_listpack:
        case stream_listpacks_3:
            return v >= 11;
        case 22:
            return f._magic == rdb_magic::valkey || f._version >= 12;
        case 23:
        case 24:
        case 25:
            return f._magic == rdb_magic::redis && f._version >= 12;
        default:
            return false;
    }
}

/// Whether the servers reading format `f` load a value of `type` written
/// by a server of format `from`: the type byte must exist in both and mean
/// the same thing. 0-21 do wherever both know them; 22-25 only within one
/// dialect.
[[nodiscard]] constexpr auto rdb_type_portable(rdb_format from, rdb_format to,
                                               std::uint8_t type) noexcept -> bool {
    if (!rdb_type_known(from, type) || !rdb_type_known(to, type)) {
        return false;
    }
    if (type >= 22) {
        return from._magic == to._magic;
    }
    return true;
}

/// Short name of a type byte in a format, for refusal reports.
[[nodiscard]] constexpr auto rdb_type_name(rdb_format f, std::uint8_t type) noexcept
    -> std::string_view {
    switch (type) {
        case 0:
            return "string";
        case 1:
            return "list";
        case 2:
            return "set";
        case 3:
            return "zset";
        case 4:
            return "hash";
        case 5:
            return "zset_2";
        case 6:
            return "module_pre_ga";
        case 7:
            return "module_2";
        case 9:
            return "hash_zipmap";
        case 10:
            return "list_ziplist";
        case 11:
            return "set_intset";
        case 12:
            return "zset_ziplist";
        case 13:
            return "hash_ziplist";
        case 14:
            return "list_quicklist";
        case 15:
            return "stream_listpacks";
        case 16:
            return "hash_listpack";
        case 17:
            return "zset_listpack";
        case 18:
            return "list_quicklist_2";
        case 19:
            return "stream_listpacks_2";
        case 20:
            return "set_listpack";
        case 21:
            return "stream_listpacks_3";
        case 22:
            return f._magic == rdb_magic::valkey ? "valkey_hash_2" : "redis_hash_metadata_pre_ga";
        case 23:
            return "redis_hash_listpack_ex_pre_ga";
        case 24:
            return "redis_hash_metadata";
        case 25:
            return "redis_hash_listpack_ex";
        default:
            return "unknown";
    }
}

/// One reference server and the format it writes (and is the newest it
/// reads). Redis 7.2 to 8.4 and Valkey 7.2 to 9.0 are the versions the
/// migration specs pin; `redis-7.0` is the oldest the reader is tested
/// against by construction.
struct rdb_target {
    std::string_view _name;
    rdb_format _format;
};

inline constexpr std::array<rdb_target, 10> rdb_targets{{
    {"redis-7.0", {rdb_magic::redis, 10}},
    {"redis-7.2", {rdb_magic::redis, 11}},
    {"redis-7.4", {rdb_magic::redis, 12}},
    {"redis-8.0", {rdb_magic::redis, 12}},
    {"redis-8.2", {rdb_magic::redis, 12}},
    {"redis-8.4", {rdb_magic::redis, 12}},
    {"valkey-7.2", {rdb_magic::redis, 11}},
    {"valkey-8.0", {rdb_magic::redis, 11}},
    {"valkey-8.1", {rdb_magic::redis, 11}},
    {"valkey-9.0", {rdb_magic::valkey, 80}},
}};

/// Look a target up by name (`redis-8.4`, `valkey-9.0`, ...).
[[nodiscard]] constexpr auto rdb_find_target(std::string_view name) noexcept
    -> std::optional<rdb_format> {
    for (const auto& t : rdb_targets) {
        if (t._name == name) {
            return t._format;
        }
    }
    return std::nullopt;
}

/// Name of a module type from the 64-bit id in `MODULE_2` values and module
/// `AUX` records: nine 6-bit characters in the high 54 bits, the module's
/// encoding version in the low 10.
[[nodiscard]] inline auto rdb_module_type_name(std::uint64_t module_id) -> std::string {
    static constexpr std::string_view charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string name(9, ' ');
    std::uint64_t id = module_id >> 10U;
    for (int j = 8; j >= 0; --j) {
        name[static_cast<std::size_t>(j)] = charset[id & 63U];
        id >>= 6U;
    }
    return name;
}

[[nodiscard]] constexpr auto rdb_module_encoding_version(std::uint64_t module_id) noexcept
    -> std::uint64_t {
    return module_id & 1023U;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

struct rdb_aux {
    std::string _key;
    std::string _value;
    friend auto operator==(const rdb_aux&, const rdb_aux&) -> bool = default;
};

struct rdb_select_db {
    std::uint64_t _db = 0;
    friend auto operator==(const rdb_select_db&, const rdb_select_db&) -> bool = default;
};

struct rdb_resize_db {
    std::uint64_t _db_size = 0;
    std::uint64_t _expires_size = 0;
    friend auto operator==(const rdb_resize_db&, const rdb_resize_db&) -> bool = default;
};

/// Cluster-mode per-slot sizing hint (Redis 7.4+).
struct rdb_slot_info {
    std::uint64_t _slot = 0;
    std::uint64_t _size = 0;
    std::uint64_t _expires_size = 0;
    friend auto operator==(const rdb_slot_info&, const rdb_slot_info&) -> bool = default;
};

/// Valkey 9 atomic slot migration in progress: a job name and slot ranges.
struct rdb_slot_import {
    std::string _job;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> _ranges;
    friend auto operator==(const rdb_slot_import&, const rdb_slot_import&) -> bool = default;
};

/// One `FUNCTION2` library: its source code, `#!<engine> name=<lib>` first.
struct rdb_function {
    std::string _code;
    friend auto operator==(const rdb_function&, const rdb_function&) -> bool = default;
};

/// Module data outside the keyspace. `_body` is the module's annotated
/// fields after the `when` value, without the closing EOF mark.
struct rdb_module_aux {
    std::uint64_t _module_id = 0;
    std::uint64_t _when = 0;
    std::string _body;
    friend auto operator==(const rdb_module_aux&, const rdb_module_aux&) -> bool = default;
};

/// One key.
struct rdb_key {
    std::uint64_t _db = 0;
    std::string _key;
    /// RDB type byte; its meaning depends on the file's `rdb_format`.
    std::uint8_t _type = rdb_type::string;
    /// Serialized value after the type byte (a `DUMP` body without footer).
    std::string _payload;
    /// Absolute expiry in Unix milliseconds. Second-precision expiries from
    /// old files are converted on read; the writer always writes ms.
    std::optional<std::int64_t> _expire_ms;
    /// LRU idle seconds (maxmemory-policy *-lru) or LFU counter (*-lfu).
    std::optional<std::uint64_t> _idle_seconds;
    std::optional<std::uint8_t> _lfu_freq;
    friend auto operator==(const rdb_key&, const rdb_key&) -> bool = default;
};

/// End of file. `_checksum` is the stored trailer (0 when the writer had
/// checksums off, in which case nothing was verified).
struct rdb_eof {
    std::uint64_t _checksum = 0;
    friend auto operator==(const rdb_eof&, const rdb_eof&) -> bool = default;
};

using rdb_record = std::variant<rdb_aux, rdb_select_db, rdb_resize_db, rdb_slot_info,
                                rdb_slot_import, rdb_function, rdb_module_aux, rdb_key, rdb_eof>;

// ---------------------------------------------------------------------------
// Byte sources
// ---------------------------------------------------------------------------

/// Where the reader pulls bytes from. `read_some` blocks until at least one
/// byte is available or the input has ended (returns 0), and throws
/// `rdb_error` (kind `io`) on failure.
class rdb_byte_source {
public:
    virtual ~rdb_byte_source() = default;
    rdb_byte_source() = default;
    rdb_byte_source(const rdb_byte_source&) = delete;
    auto operator=(const rdb_byte_source&) -> rdb_byte_source& = delete;
    [[nodiscard]] virtual auto read_some(std::span<std::uint8_t> out) -> std::size_t = 0;
};

/// Bytes already in memory (tests, `DUMP` payloads, small files).
class rdb_memory_source final : public rdb_byte_source {
public:
    explicit rdb_memory_source(std::span<const std::uint8_t> bytes) : _bytes(bytes) {}
    explicit rdb_memory_source(std::string_view bytes)
        : _bytes(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()) {}

    [[nodiscard]] auto read_some(std::span<std::uint8_t> out) -> std::size_t override {
        const std::size_t n = std::min(out.size(), _bytes.size() - _pos);
        std::copy_n(_bytes.data() + _pos, n, out.data());
        _pos += n;
        return n;
    }

private:
    std::span<const std::uint8_t> _bytes;
    std::size_t _pos = 0;
};

/// A file descriptor: a regular file, a pipe or a connected socket (the
/// replication link). Does not own the descriptor.
class rdb_fd_source : public rdb_byte_source {
public:
    explicit rdb_fd_source(int fd) : _fd(fd) {}

    [[nodiscard]] auto read_some(std::span<std::uint8_t> out) -> std::size_t override {
        if (out.empty()) {
            return 0;
        }
        for (;;) {
            const ::ssize_t n = ::read(_fd, out.data(), out.size());
            if (n >= 0) {
                return static_cast<std::size_t>(n);
            }
            if (errno != EINTR) {
                throw rdb_error(rdb_error_kind::io, 0,
                                std::string("read: ") + std::system_category().message(errno));
            }
        }
    }

protected:
    int _fd;
};

/// A local file opened by path (owns the descriptor).
class rdb_file_source final : public rdb_fd_source {
public:
    explicit rdb_file_source(const std::string& path)
        : rdb_fd_source(::open(path.c_str(), O_RDONLY | O_CLOEXEC)) {
        if (_fd < 0) {
            throw rdb_error(rdb_error_kind::io, 0,
                            "open " + path + ": " + std::system_category().message(errno));
        }
    }
    ~rdb_file_source() override {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
};

/// At most `limit` bytes of another source: a disk-to-socket PSYNC transfer
/// announces `$<len>` and then sends exactly that many bytes of RDB.
class rdb_limited_source final : public rdb_byte_source {
public:
    rdb_limited_source(rdb_byte_source& inner, std::uint64_t limit) : _inner(inner), _left(limit) {}

    [[nodiscard]] auto read_some(std::span<std::uint8_t> out) -> std::size_t override {
        if (_left == 0 || out.empty()) {
            return 0;
        }
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), _left));
        const std::size_t n = _inner.read_some(out.first(want));
        _left -= n;
        return n;
    }

    [[nodiscard]] auto remaining() const noexcept -> std::uint64_t { return _left; }

private:
    rdb_byte_source& _inner;
    std::uint64_t _left;
};

/// Ranged reads through a callable, for object stores: `fetch(offset, len)`
/// returns up to `len` bytes starting at `offset` (a `GET` with
/// `Range: bytes=offset-(offset+len-1)`), fewer only at the end of the
/// object, and an empty string past it. One fetch per `chunk` bytes keeps
/// request count and memory both bounded.
template<typename Fetch> class rdb_ranged_source final : public rdb_byte_source {
public:
    explicit rdb_ranged_source(Fetch fetch, std::size_t chunk = 8U * 1024U * 1024U)
        : _fetch(std::move(fetch)), _chunk(std::max<std::size_t>(chunk, 1)) {}

    [[nodiscard]] auto read_some(std::span<std::uint8_t> out) -> std::size_t override {
        if (out.empty()) {
            return 0;
        }
        if (_pos == _buf.size()) {
            if (_ended) {
                return 0;
            }
            _buf = _fetch(_offset, _chunk);
            _pos = 0;
            _offset += _buf.size();
            if (_buf.size() < _chunk) {
                _ended = true;
            }
            if (_buf.empty()) {
                return 0;
            }
        }
        const std::size_t n = std::min(out.size(), _buf.size() - _pos);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(_buf.data()) + _pos, n, out.data());
        _pos += n;
        return n;
    }

private:
    Fetch _fetch;
    std::size_t _chunk;
    std::string _buf;
    std::size_t _pos = 0;
    std::uint64_t _offset = 0;
    bool _ended = false;
};

// ---------------------------------------------------------------------------
// Byte sinks
// ---------------------------------------------------------------------------

/// Where the writer pushes bytes. `finish()` is called once after the
/// trailer; it is where a file is synced or the last part uploaded.
class rdb_byte_sink {
public:
    virtual ~rdb_byte_sink() = default;
    rdb_byte_sink() = default;
    rdb_byte_sink(const rdb_byte_sink&) = delete;
    auto operator=(const rdb_byte_sink&) -> rdb_byte_sink& = delete;
    virtual void write(std::span<const std::uint8_t> bytes) = 0;
    virtual void finish() {}
};

/// Appends to a string.
class rdb_string_sink final : public rdb_byte_sink {
public:
    void write(std::span<const std::uint8_t> bytes) override {
        _out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    [[nodiscard]] auto str() const noexcept -> const std::string& { return _out; }
    [[nodiscard]] auto take() noexcept -> std::string { return std::move(_out); }

private:
    std::string _out;
};

/// A file descriptor (file, pipe or socket). Does not own it; `finish()`
/// does not sync (a socket cannot be synced).
class rdb_fd_sink : public rdb_byte_sink {
public:
    explicit rdb_fd_sink(int fd) : _fd(fd) {}

    void write(std::span<const std::uint8_t> bytes) override {
        while (!bytes.empty()) {
            const ::ssize_t n = ::write(_fd, bytes.data(), bytes.size());
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw rdb_error(rdb_error_kind::io, 0,
                                std::string("write: ") + std::system_category().message(errno));
            }
            bytes = bytes.subspan(static_cast<std::size_t>(n));
        }
    }

protected:
    int _fd;
};

/// A local file created (or truncated) at a path, synced on `finish()`.
class rdb_file_sink final : public rdb_fd_sink {
public:
    explicit rdb_file_sink(const std::string& path)
        : rdb_fd_sink(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)) {
        if (_fd < 0) {
            throw rdb_error(rdb_error_kind::io, 0,
                            "open " + path + ": " + std::system_category().message(errno));
        }
    }
    ~rdb_file_sink() override {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    void finish() override {
        if (::fsync(_fd) != 0) {
            throw rdb_error(rdb_error_kind::io, 0,
                            std::string("fsync: ") + std::system_category().message(errno));
        }
    }
};

/// Object-store multipart upload through a callable: `upload(part_number,
/// bytes)` uploads one part (numbered from 1). Every part but the last is
/// exactly `part_size` bytes (S3's minimum is 5 MiB; the default is 8 MiB),
/// so memory is one part. Completing or aborting the upload is the
/// caller's, after `finish()` returns or throws.
template<typename Upload> class rdb_part_sink final : public rdb_byte_sink {
public:
    explicit rdb_part_sink(Upload upload, std::size_t part_size = 8U * 1024U * 1024U)
        : _upload(std::move(upload)), _part_size(std::max<std::size_t>(part_size, 1)) {
        _buf.reserve(std::min<std::size_t>(_part_size, 1U << 20U));
    }

    void write(std::span<const std::uint8_t> bytes) override {
        while (!bytes.empty()) {
            const std::size_t n = std::min(bytes.size(), _part_size - _buf.size());
            _buf.append(reinterpret_cast<const char*>(bytes.data()), n);
            bytes = bytes.subspan(n);
            if (_buf.size() == _part_size) {
                emit();
            }
        }
    }

    void finish() override {
        if (!_buf.empty() || _parts == 0) {
            emit();
        }
    }

    [[nodiscard]] auto parts() const noexcept -> std::size_t { return _parts; }

private:
    void emit() {
        ++_parts;
        _upload(_parts, std::string_view{_buf});
        _buf.clear();
    }

    Upload _upload;
    std::size_t _part_size;
    std::string _buf;
    std::size_t _parts = 0;
};

// ---------------------------------------------------------------------------
// Length and string encodings (shared with the value codec)
// ---------------------------------------------------------------------------

namespace rdb_detail {

inline constexpr std::uint8_t len_6bit = 0;
inline constexpr std::uint8_t len_14bit = 1;
inline constexpr std::uint8_t len_32bit = 0x80;
inline constexpr std::uint8_t len_64bit = 0x81;
inline constexpr std::uint8_t len_encval = 3;
inline constexpr std::uint8_t enc_int8 = 0;
inline constexpr std::uint8_t enc_int16 = 1;
inline constexpr std::uint8_t enc_int32 = 2;
inline constexpr std::uint8_t enc_lzf = 3;

/// Append an RDB length.
inline void put_length(std::string& out, std::uint64_t len) {
    if (len < (1U << 6U)) {
        out.push_back(static_cast<char>(len));
    } else if (len < (1U << 14U)) {
        out.push_back(static_cast<char>((len_14bit << 6U) | (len >> 8U)));
        out.push_back(static_cast<char>(len & 0xffU));
    } else if (len <= std::numeric_limits<std::uint32_t>::max()) {
        out.push_back(static_cast<char>(len_32bit));
        for (int s = 24; s >= 0; s -= 8) {
            out.push_back(static_cast<char>((len >> static_cast<unsigned>(s)) & 0xffU));
        }
    } else {
        out.push_back(static_cast<char>(len_64bit));
        for (int s = 56; s >= 0; s -= 8) {
            out.push_back(static_cast<char>((len >> static_cast<unsigned>(s)) & 0xffU));
        }
    }
}

inline void put_le(std::string& out, std::uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) {
        out.push_back(static_cast<char>((v >> (8U * static_cast<unsigned>(i))) & 0xffU));
    }
}

/// The integer a string encodes if Redis would store it integer-encoded:
/// at most 11 characters, the canonical decimal form of an int32 (no
/// leading zeros or plus sign, no "-0").
[[nodiscard]] inline auto as_int_encodable(std::string_view s) noexcept
    -> std::optional<std::int32_t> {
    if (s.empty() || s.size() > 11) {
        return std::nullopt;
    }
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size() ||
        v < std::numeric_limits<std::int32_t>::min() ||
        v > std::numeric_limits<std::int32_t>::max()) {
        return std::nullopt;
    }
    std::array<char, 24> buf{};
    const auto r = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    if (std::string_view(buf.data(), static_cast<std::size_t>(r.ptr - buf.data())) != s) {
        return std::nullopt;
    }
    return static_cast<std::int32_t>(v);
}

/// Append an RDB string the way Redis's rdbSaveRawString does: integer
/// encoding when the string is a small canonical integer, then LZF when
/// `compress` is on, the string is longer than 20 bytes and compression
/// saves at least 4 bytes, otherwise length plus raw bytes.
inline void put_string(std::string& out, std::string_view s, bool compress = true) {
    if (const auto iv = as_int_encodable(s)) {
        const std::int32_t v = *iv;
        if (v >= -(1 << 7) && v <= (1 << 7) - 1) {
            out.push_back(static_cast<char>((len_encval << 6U) | enc_int8));
            put_le(out, static_cast<std::uint32_t>(v), 1);
        } else if (v >= -(1 << 15) && v <= (1 << 15) - 1) {
            out.push_back(static_cast<char>((len_encval << 6U) | enc_int16));
            put_le(out, static_cast<std::uint32_t>(v), 2);
        } else {
            out.push_back(static_cast<char>((len_encval << 6U) | enc_int32));
            put_le(out, static_cast<std::uint32_t>(v), 4);
        }
        return;
    }
    if (compress && s.size() > 20) {
        if (auto c = rdb_lzf_compress(s, 4)) {
            out.push_back(static_cast<char>((len_encval << 6U) | enc_lzf));
            put_length(out, c->size());
            put_length(out, s.size());
            out.append(*c);
            return;
        }
    }
    put_length(out, s.size());
    out.append(s);
}

/// Pull-side cursor over a source: buffered, CRC-tracking, and optionally
/// copying every byte it consumes into a capture string (a value payload).
class cursor {
public:
    cursor(rdb_byte_source& src, std::uint64_t max_capture)
        : _src(src), _buf(64U * 1024U), _max_capture(max_capture) {}

    [[nodiscard]] auto offset() const noexcept -> std::uint64_t { return _offset; }

    [[noreturn]] void fail(rdb_error_kind kind, const std::string& what) const {
        throw rdb_error(kind, _offset, what);
    }

    auto byte() -> std::uint8_t {
        if (_pos == _end) {
            refill();
        }
        const std::uint8_t b = _buf[_pos++];
        ++_offset;
        if (_capture != nullptr) {
            capture_bytes(&b, 1);
        }
        return b;
    }

    /// Consume `n` bytes, appending them to `out` if given.
    void bytes(std::uint64_t n, std::string* out) {
        while (n > 0) {
            if (_pos == _end) {
                refill();
            }
            const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(n, _end - _pos));
            if (out != nullptr) {
                out->append(reinterpret_cast<const char*>(_buf.data() + _pos), take);
            }
            if (_capture != nullptr) {
                capture_bytes(_buf.data() + _pos, take);
            }
            _pos += take;
            _offset += take;
            n -= take;
        }
    }

    void skip(std::uint64_t n) { bytes(n, nullptr); }

    auto le(int n) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < n; ++i) {
            v |= std::uint64_t{byte()} << (8U * static_cast<unsigned>(i));
        }
        return v;
    }

    /// An RDB length. `encoded` is set when the top bits say a special
    /// string encoding follows (the return value is then the encoding).
    auto length(bool* encoded = nullptr) -> std::uint64_t {
        if (encoded != nullptr) {
            *encoded = false;
        }
        const std::uint8_t b = byte();
        const unsigned kind = (b & 0xc0U) >> 6U;
        if (kind == len_encval) {
            if (encoded != nullptr) {
                *encoded = true;
            }
            return b & 0x3fU;
        }
        if (kind == len_6bit) {
            return b & 0x3fU;
        }
        if (kind == len_14bit) {
            return (std::uint64_t{b & 0x3fU} << 8U) | byte();
        }
        if (b == len_32bit || b == len_64bit) {
            const int n = b == len_32bit ? 4 : 8;
            std::uint64_t v = 0;
            for (int i = 0; i < n; ++i) {
                v = (v << 8U) | byte();
            }
            return v;
        }
        fail(rdb_error_kind::corrupt, "unknown length encoding");
    }

    /// A string, decoded (integer forms printed, LZF decompressed).
    auto string(std::uint64_t max_len) -> std::string {
        bool encoded = false;
        const std::uint64_t len = length(&encoded);
        if (encoded) {
            switch (len) {
                case enc_int8:
                    return std::to_string(static_cast<std::int8_t>(le(1)));
                case enc_int16:
                    return std::to_string(static_cast<std::int16_t>(le(2)));
                case enc_int32:
                    return std::to_string(static_cast<std::int32_t>(le(4)));
                case enc_lzf: {
                    const std::uint64_t clen = length();
                    const std::uint64_t ulen = length();
                    if (ulen > max_len) {
                        fail(rdb_error_kind::limit_exceeded,
                             "string longer than the configured limit");
                    }
                    if (ulen > clen * rdb_lzf_max_ratio) {
                        fail(rdb_error_kind::corrupt,
                             "LZF length larger than its input can produce");
                    }
                    std::string packed;
                    bytes(clen, &packed);
                    auto plain = rdb_lzf_decompress(
                        {reinterpret_cast<const std::uint8_t*>(packed.data()), packed.size()},
                        static_cast<std::size_t>(ulen));
                    if (!plain) {
                        fail(rdb_error_kind::corrupt, "invalid LZF data");
                    }
                    return std::move(*plain);
                }
                default:
                    fail(rdb_error_kind::corrupt, "unknown string encoding");
            }
        }
        if (len > max_len) {
            fail(rdb_error_kind::limit_exceeded, "string longer than the configured limit");
        }
        std::string s;
        bytes(len, &s);
        return s;
    }

    /// Consume a string without decoding it.
    void skip_string() {
        bool encoded = false;
        const std::uint64_t len = length(&encoded);
        if (!encoded) {
            skip(len);
            return;
        }
        switch (len) {
            case enc_int8:
                skip(1);
                return;
            case enc_int16:
                skip(2);
                return;
            case enc_int32:
                skip(4);
                return;
            case enc_lzf: {
                const std::uint64_t clen = length();
                const std::uint64_t ulen = length();
                if (ulen > clen * rdb_lzf_max_ratio) {
                    fail(rdb_error_kind::corrupt, "LZF length larger than its input can produce");
                }
                skip(clen);
                return;
            }
            default:
                fail(rdb_error_kind::corrupt, "unknown string encoding");
        }
    }

    void start_capture(std::string* out) { _capture = out; }
    void stop_capture() { _capture = nullptr; }

    /// Fold every byte consumed so far into the CRC and stop tracking it
    /// (called right after the EOF opcode; the trailer is not covered).
    auto finish_crc() -> std::uint64_t {
        fold_crc();
        _crc_frozen = true;
        return _crc;
    }

private:
    void capture_bytes(const std::uint8_t* p, std::size_t n) {
        if (_capture->size() + n > _max_capture) {
            fail(rdb_error_kind::limit_exceeded, "value larger than the configured limit");
        }
        _capture->append(reinterpret_cast<const char*>(p), n);
    }

    void fold_crc() {
        if (!_crc_frozen && _pos > _crc_mark) {
            _crc = rdb_crc64(
                _crc, std::span<const std::uint8_t>(_buf.data() + _crc_mark, _pos - _crc_mark));
        }
        _crc_mark = _pos;
    }

    void refill() {
        fold_crc();
        _pos = _end = 0;
        _crc_mark = 0;
        _end = _src.read_some(_buf);
        if (_end == 0) {
            fail(rdb_error_kind::truncated, "unexpected end of input");
        }
    }

    rdb_byte_source& _src;
    std::vector<std::uint8_t> _buf;
    std::size_t _pos = 0;
    std::size_t _end = 0;
    std::size_t _crc_mark = 0;
    std::uint64_t _offset = 0;
    std::uint64_t _crc = 0;
    bool _crc_frozen = false;
    std::string* _capture = nullptr;
    std::uint64_t _max_capture;
};

/// Walk a module's annotated fields up to and including the EOF mark.
inline void skim_module_fields(cursor& c) {
    for (;;) {
        const std::uint64_t op = c.length();
        switch (op) {
            case rdb_module_opcode::eof:
                return;
            case rdb_module_opcode::sint:
            case rdb_module_opcode::uint:
                (void)c.length();
                break;
            case rdb_module_opcode::float_:
                c.skip(4);
                break;
            case rdb_module_opcode::double_:
                c.skip(8);
                break;
            case rdb_module_opcode::string:
                c.skip_string();
                break;
            default:
                c.fail(rdb_error_kind::corrupt, "unknown module field opcode");
        }
    }
}

/// Walk one value of `type` in format `f`, consuming exactly its bytes.
inline void skim_value(cursor& c, rdb_format f, std::uint8_t type) {
    using namespace rdb_type;
    if (!rdb_type_known(f, type)) {
        c.fail(rdb_error_kind::unsupported_type,
               "type " + std::to_string(type) + " is not defined in this RDB version");
    }
    switch (type) {
        case string:
        case hash_zipmap:
        case list_ziplist:
        case set_intset:
        case zset_ziplist:
        case hash_ziplist:
        case hash_listpack:
        case zset_listpack:
        case set_listpack:
            c.skip_string();
            return;
        case list:
        case set:
        case list_quicklist: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                c.skip_string();
            }
            return;
        }
        case list_quicklist_2: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                const std::uint64_t container = c.length();
                if (container != 1 && container != 2) {
                    c.fail(rdb_error_kind::corrupt, "invalid quicklist container");
                }
                c.skip_string();
            }
            return;
        }
        case zset: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                c.skip_string();
                const std::uint8_t dlen = c.byte();
                if (dlen < 253) {
                    c.skip(dlen);
                }
            }
            return;
        }
        case zset_2: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                c.skip_string();
                c.skip(8);
            }
            return;
        }
        case hash: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                c.skip_string();
                c.skip_string();
            }
            return;
        }
        case stream_listpacks:
        case stream_listpacks_2:
        case stream_listpacks_3: {
            for (std::uint64_t n = c.length(); n > 0; --n) {
                c.skip_string();  // master ID (16 bytes)
                c.skip_string();  // listpack
            }
            (void)c.length();  // length
            (void)c.length();  // last id ms
            (void)c.length();  // last id seq
            if (type >= stream_listpacks_2) {
                for (int i = 0; i < 5; ++i) {
                    (void)c.length();  // first id, max deleted id, entries added
                }
            }
            for (std::uint64_t groups = c.length(); groups > 0; --groups) {
                c.skip_string();   // name
                (void)c.length();  // last delivered ms
                (void)c.length();  // last delivered seq
                if (type >= stream_listpacks_2) {
                    (void)c.length();  // entries read
                }
                for (std::uint64_t pel = c.length(); pel > 0; --pel) {
                    c.skip(16);        // id
                    c.skip(8);         // delivery time
                    (void)c.length();  // delivery count
                }
                for (std::uint64_t consumers = c.length(); consumers > 0; --consumers) {
                    c.skip_string();  // name
                    c.skip(8);        // seen time
                    if (type >= stream_listpacks_3) {
                        c.skip(8);  // active time
                    }
                    for (std::uint64_t pel = c.length(); pel > 0; --pel) {
                        c.skip(16);
                    }
                }
            }
            return;
        }
        case module_2: {
            (void)c.length();  // module id
            skim_module_fields(c);
            return;
        }
        default:
            break;
    }
    if (f._magic == rdb_magic::valkey && type == valkey_hash_2) {
        for (std::uint64_t n = c.length(); n > 0; --n) {
            c.skip_string();
            c.skip_string();
            c.skip(8);  // field expiry ms (-1: none)
        }
        return;
    }
    switch (type) {
        case redis_hash_metadata:
        case redis_hash_metadata_pre_ga: {
            if (type == redis_hash_metadata) {
                c.skip(8);  // minimum expiry
            }
            for (std::uint64_t n = c.length(); n > 0; --n) {
                (void)c.length();  // ttl
                c.skip_string();
                c.skip_string();
            }
            return;
        }
        case redis_hash_listpack_ex:
            c.skip(8);  // minimum expiry
            c.skip_string();
            return;
        case redis_hash_listpack_ex_pre_ga:
            c.skip_string();
            return;
        default:
            break;
    }
    c.fail(rdb_error_kind::unsupported_type, "type " + std::to_string(type) + " is not supported");
}

}  // namespace rdb_detail

// ---------------------------------------------------------------------------
// String payloads (the first value codec; task 43 adds the rest)
// ---------------------------------------------------------------------------

/// The value of a type-0 payload. Throws `rdb_error` if it is not exactly
/// one RDB string.
[[nodiscard]] inline auto rdb_decode_string_payload(
    std::string_view payload, std::uint64_t max_len = std::numeric_limits<std::uint64_t>::max())
    -> std::string {
    rdb_memory_source src(payload);
    rdb_detail::cursor c(src, 0);
    std::string s = c.string(max_len);
    if (c.offset() != payload.size()) {
        throw rdb_error(rdb_error_kind::corrupt, c.offset(), "bytes after the string payload");
    }
    return s;
}

/// A type-0 payload for `value`, encoded as Redis would (integer form for
/// small canonical integers, LZF when `compress` and it pays).
[[nodiscard]] inline auto rdb_encode_string_payload(std::string_view value, bool compress = true)
    -> std::string {
    std::string out;
    rdb_detail::put_string(out, value, compress);
    return out;
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

struct rdb_reader_options {
    /// Fail on a CRC mismatch (Requirement 2.1). Off only for diagnostics.
    bool _verify_checksum = true;
    /// Longest key, `AUX` field, function or slot-import job name. Redis's
    /// own key limit is 512 MiB.
    std::uint64_t _max_string_bytes = 512ULL * 1024ULL * 1024ULL;
    /// Largest value payload (and module `AUX` body).
    std::uint64_t _max_value_bytes = std::numeric_limits<std::uint64_t>::max();
};

/// Pull parser. Construct it over a source (the header is read and checked
/// at once), then call `next()` until it returns nullopt; the record before
/// that is always `rdb_eof`, and by then the checksum has been verified.
class rdb_reader {
public:
    explicit rdb_reader(rdb_byte_source& src, rdb_reader_options options = {})
        : _cursor(src, options._max_value_bytes), _options(options) {
        std::string magic;
        _cursor.bytes(5, &magic);
        if (magic == "REDIS") {
            std::string digits;
            _cursor.bytes(4, &digits);
            _format = {rdb_magic::redis, parse_digits(digits)};
        } else if (magic == "VALKE") {
            std::string rest;
            _cursor.bytes(4, &rest);
            if (rest[0] != 'Y') {
                _cursor.fail(rdb_error_kind::unsupported_version, "not an RDB file");
            }
            _format = {rdb_magic::valkey, parse_digits(rest.substr(1))};
        } else {
            _cursor.fail(rdb_error_kind::unsupported_version, "not an RDB file");
        }
        if (!rdb_format_supported(_format)) {
            _cursor.fail(rdb_error_kind::unsupported_version,
                         "RDB version " + std::to_string(_format._version) + " with magic " +
                             (_format._magic == rdb_magic::redis ? "REDIS" : "VALKEY") +
                             " is not supported");
        }
    }

    [[nodiscard]] auto format() const noexcept -> rdb_format { return _format; }
    /// Bytes consumed so far.
    [[nodiscard]] auto offset() const noexcept -> std::uint64_t { return _cursor.offset(); }

    /// The next record, or nullopt once `rdb_eof` has been returned.
    [[nodiscard]] auto next() -> std::optional<rdb_record> {
        if (_done) {
            return std::nullopt;
        }
        std::optional<std::int64_t> expire_ms;
        std::optional<std::uint64_t> idle;
        std::optional<std::uint8_t> freq;
        for (;;) {
            const std::uint8_t op = _cursor.byte();
            switch (op) {
                case rdb_opcode::expiretime_ms:
                    expire_ms = static_cast<std::int64_t>(_cursor.le(8));
                    continue;
                case rdb_opcode::expiretime:
                    expire_ms =
                        static_cast<std::int64_t>(static_cast<std::int32_t>(_cursor.le(4))) * 1000;
                    continue;
                case rdb_opcode::idle:
                    idle = _cursor.length();
                    continue;
                case rdb_opcode::freq:
                    freq = _cursor.byte();
                    continue;
                default:
                    break;
            }
            if (op >= rdb_opcode::slot_import && (expire_ms || idle || freq)) {
                _cursor.fail(rdb_error_kind::corrupt,
                             "expiry or LRU/LFU data not followed by a key");
            }
            switch (op) {
                case rdb_opcode::eof:
                    return read_eof();
                case rdb_opcode::selectdb:
                    _db = _cursor.length();
                    return rdb_select_db{_db};
                case rdb_opcode::resizedb: {
                    rdb_resize_db r;
                    r._db_size = _cursor.length();
                    r._expires_size = _cursor.length();
                    return r;
                }
                case rdb_opcode::slot_info: {
                    rdb_slot_info r;
                    r._slot = _cursor.length();
                    r._size = _cursor.length();
                    r._expires_size = _cursor.length();
                    return r;
                }
                case rdb_opcode::slot_import: {
                    if (_format._magic != rdb_magic::valkey) {
                        _cursor.fail(rdb_error_kind::corrupt, "SLOT_IMPORT outside a Valkey file");
                    }
                    rdb_slot_import r;
                    r._job = _cursor.string(_options._max_string_bytes);
                    for (std::uint64_t n = _cursor.length(); n > 0; --n) {
                        const std::uint64_t first = _cursor.length();
                        const std::uint64_t last = _cursor.length();
                        r._ranges.emplace_back(first, last);
                    }
                    return r;
                }
                case rdb_opcode::aux: {
                    rdb_aux r;
                    r._key = _cursor.string(_options._max_string_bytes);
                    r._value = _cursor.string(_options._max_string_bytes);
                    return r;
                }
                case rdb_opcode::function2:
                    return rdb_function{_cursor.string(_options._max_string_bytes)};
                case rdb_opcode::function_pre_ga:
                    _cursor.fail(rdb_error_kind::unsupported_type,
                                 "pre-release function format (Redis 7.0 RC) is not supported");
                case rdb_opcode::module_aux: {
                    rdb_module_aux r;
                    r._module_id = _cursor.length();
                    if (_cursor.length() != rdb_module_opcode::uint) {
                        _cursor.fail(rdb_error_kind::corrupt, "bad module AUX when opcode");
                    }
                    r._when = _cursor.length();
                    _cursor.start_capture(&r._body);
                    rdb_detail::skim_module_fields(_cursor);
                    _cursor.stop_capture();
                    // The EOF mark is the single byte 0 (a 6-bit length).
                    r._body.pop_back();
                    return r;
                }
                default:
                    break;
            }
            if (op >= rdb_opcode::slot_import) {
                _cursor.fail(rdb_error_kind::corrupt, "unknown opcode " + std::to_string(op));
            }
            if (op == rdb_type::module_pre_ga) {
                _cursor.fail(rdb_error_kind::unsupported_type,
                             "pre-release module format is not supported");
            }
            if (!is_value_type(op)) {
                _cursor.fail(rdb_error_kind::unsupported_type,
                             "type " + std::to_string(op) + " is not defined in this RDB version");
            }
            rdb_key k;
            k._db = _db;
            k._type = op;
            k._expire_ms = expire_ms;
            k._idle_seconds = idle;
            k._lfu_freq = freq;
            k._key = _cursor.string(_options._max_string_bytes);
            _cursor.start_capture(&k._payload);
            rdb_detail::skim_value(_cursor, _format, op);
            _cursor.stop_capture();
            return k;
        }
    }

private:
    [[nodiscard]] auto is_value_type(std::uint8_t t) const noexcept -> bool {
        return t != rdb_type::module_pre_ga && rdb_type_known(_format, t);
    }

    auto parse_digits(std::string_view d) -> std::uint16_t {
        unsigned v = 0;
        const auto [ptr, ec] = std::from_chars(d.data(), d.data() + d.size(), v);
        if (ec != std::errc{} || ptr != d.data() + d.size()) {
            _cursor.fail(rdb_error_kind::unsupported_version, "bad RDB version digits");
        }
        return static_cast<std::uint16_t>(v);
    }

    auto read_eof() -> rdb_record {
        const std::uint64_t computed = _cursor.finish_crc();
        rdb_eof e;
        if (_format._version >= 5) {
            e._checksum = _cursor.le(8);
            if (_options._verify_checksum && e._checksum != 0 && e._checksum != computed) {
                _cursor.fail(rdb_error_kind::checksum_mismatch,
                             "CRC64 trailer does not match the file");
            }
        }
        _done = true;
        return e;
    }

    rdb_detail::cursor _cursor;
    rdb_reader_options _options;
    rdb_format _format;
    std::uint64_t _db = 0;
    bool _done = false;
};

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

struct rdb_writer_options {
    /// Write the CRC64 trailer (otherwise 0, as with `rdbchecksum no`).
    bool _checksum = true;
    /// LZF-compress keys and other framing strings longer than 20 bytes
    /// (`rdbcompression yes`). Payloads are written as given.
    bool _compress = true;
};

/// Push encoder. The constructor writes the header; `finish()` writes the
/// EOF opcode and trailer and finishes the sink. Records that the target
/// format cannot hold are refused: `key()` returns false for a type the
/// target does not define (Requirement 2.2: the caller reports it), and
/// the other calls throw `rdb_error` (kind `unsupported_type`).
class rdb_writer {
public:
    rdb_writer(rdb_byte_sink& sink, rdb_format format, rdb_writer_options options = {})
        : _sink(sink), _format(format), _options(options) {
        if (!rdb_format_supported(format)) {
            throw rdb_error(rdb_error_kind::unsupported_version, 0,
                            "cannot write RDB version " + std::to_string(format._version));
        }
        _buf.reserve(buffer_bytes * 2);
        _buf = rdb_header_bytes(format);
    }

    rdb_writer(const rdb_writer&) = delete;
    auto operator=(const rdb_writer&) -> rdb_writer& = delete;

    [[nodiscard]] auto format() const noexcept -> rdb_format { return _format; }

    /// Whether `type` can be written in this file's format.
    [[nodiscard]] auto accepts(std::uint8_t type) const noexcept -> bool {
        return type != rdb_type::module_pre_ga && rdb_type_known(_format, type);
    }

    void aux(std::string_view key, std::string_view value) {
        _buf.push_back(static_cast<char>(rdb_opcode::aux));
        rdb_detail::put_string(_buf, key, _options._compress);
        rdb_detail::put_string(_buf, value, _options._compress);
        maybe_flush();
    }

    void select_db(std::uint64_t db) {
        _buf.push_back(static_cast<char>(rdb_opcode::selectdb));
        rdb_detail::put_length(_buf, db);
    }

    void resize_db(std::uint64_t db_size, std::uint64_t expires_size) {
        _buf.push_back(static_cast<char>(rdb_opcode::resizedb));
        rdb_detail::put_length(_buf, db_size);
        rdb_detail::put_length(_buf, expires_size);
    }

    /// Cluster per-slot sizing hint; only RDB 12 (Redis 7.4+) and Valkey 80
    /// readers skip it, older readers would fail.
    void slot_info(std::uint64_t slot, std::uint64_t size, std::uint64_t expires_size) {
        if (_format._magic != rdb_magic::valkey && _format._version < 12) {
            refuse("SLOT_INFO");
        }
        _buf.push_back(static_cast<char>(rdb_opcode::slot_info));
        rdb_detail::put_length(_buf, slot);
        rdb_detail::put_length(_buf, size);
        rdb_detail::put_length(_buf, expires_size);
    }

    void slot_import(const rdb_slot_import& s) {
        if (_format._magic != rdb_magic::valkey) {
            refuse("SLOT_IMPORT");
        }
        _buf.push_back(static_cast<char>(rdb_opcode::slot_import));
        rdb_detail::put_string(_buf, s._job, _options._compress);
        rdb_detail::put_length(_buf, s._ranges.size());
        for (const auto& [first, last] : s._ranges) {
            rdb_detail::put_length(_buf, first);
            rdb_detail::put_length(_buf, last);
        }
        maybe_flush();
    }

    void function(std::string_view code) {
        if (_format._magic == rdb_magic::redis && _format._version < 10) {
            refuse("FUNCTION2");
        }
        _buf.push_back(static_cast<char>(rdb_opcode::function2));
        rdb_detail::put_string(_buf, code, _options._compress);
        maybe_flush();
    }

    void module_aux(const rdb_module_aux& m) {
        _buf.push_back(static_cast<char>(rdb_opcode::module_aux));
        rdb_detail::put_length(_buf, m._module_id);
        rdb_detail::put_length(_buf, rdb_module_opcode::uint);
        rdb_detail::put_length(_buf, m._when);
        append(m._body);
        rdb_detail::put_length(_buf, rdb_module_opcode::eof);
        maybe_flush();
    }

    /// Write one key into the current database (call `select_db` first;
    /// `k._db` is not consulted). Returns false, writing nothing, when the
    /// target format does not define `k._type`.
    [[nodiscard]] auto key(const rdb_key& k) -> bool { return key(k, _format); }

    /// The same for a key read from a file of format `from`: also refused
    /// when the type byte means something else in the target's dialect
    /// (Redis 7.4+ and Valkey 9 both use 22 for different hashes).
    [[nodiscard]] auto key(const rdb_key& k, rdb_format from) -> bool {
        if (!accepts(k._type) || !rdb_type_portable(from, _format, k._type)) {
            return false;
        }
        if (k._expire_ms) {
            _buf.push_back(static_cast<char>(rdb_opcode::expiretime_ms));
            rdb_detail::put_le(_buf, static_cast<std::uint64_t>(*k._expire_ms), 8);
        }
        if (k._idle_seconds) {
            _buf.push_back(static_cast<char>(rdb_opcode::idle));
            rdb_detail::put_length(_buf, *k._idle_seconds);
        }
        if (k._lfu_freq) {
            _buf.push_back(static_cast<char>(rdb_opcode::freq));
            _buf.push_back(static_cast<char>(*k._lfu_freq));
        }
        _buf.push_back(static_cast<char>(k._type));
        rdb_detail::put_string(_buf, k._key, _options._compress);
        append(k._payload);
        maybe_flush();
        return true;
    }

    /// Write any record the reader produces (keys go to the current
    /// database; `rdb_eof` finishes the file). Returns false only for a key
    /// the target refuses. `from` is the format the record was read from.
    auto write(const rdb_record& r) -> bool { return write(r, _format); }

    auto write(const rdb_record& r, rdb_format from) -> bool {
        return std::visit(
            [this, from](const auto& v) -> bool {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, rdb_aux>) {
                    aux(v._key, v._value);
                } else if constexpr (std::is_same_v<T, rdb_select_db>) {
                    select_db(v._db);
                } else if constexpr (std::is_same_v<T, rdb_resize_db>) {
                    resize_db(v._db_size, v._expires_size);
                } else if constexpr (std::is_same_v<T, rdb_slot_info>) {
                    slot_info(v._slot, v._size, v._expires_size);
                } else if constexpr (std::is_same_v<T, rdb_slot_import>) {
                    slot_import(v);
                } else if constexpr (std::is_same_v<T, rdb_function>) {
                    function(v._code);
                } else if constexpr (std::is_same_v<T, rdb_module_aux>) {
                    module_aux(v);
                } else if constexpr (std::is_same_v<T, rdb_key>) {
                    return key(v, from);
                } else {
                    finish();
                }
                return true;
            },
            r);
    }

    /// EOF opcode, trailer, flush, `sink.finish()`. Idempotent.
    void finish() {
        if (_finished) {
            return;
        }
        _buf.push_back(static_cast<char>(rdb_opcode::eof));
        flush();
        rdb_detail::put_le(_buf, _options._checksum ? _crc : 0, 8);
        flush_raw();
        _sink.finish();
        _finished = true;
    }

    /// Bytes handed to the sink plus those still buffered.
    [[nodiscard]] auto bytes_written() const noexcept -> std::uint64_t {
        return _written + _buf.size();
    }

private:
    static constexpr std::size_t buffer_bytes = 64U * 1024U;

    [[noreturn]] void refuse(std::string_view what) const {
        throw rdb_error(rdb_error_kind::unsupported_type, bytes_written(),
                        std::string(what) + " cannot be written in RDB version " +
                            std::to_string(_format._version));
    }

    void append(std::string_view bytes) {
        if (_buf.size() + bytes.size() <= buffer_bytes) {
            _buf.append(bytes);
            return;
        }
        flush();
        _crc = rdb_crc64(_crc, bytes);
        _sink.write({reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
        _written += bytes.size();
    }

    void maybe_flush() {
        if (_buf.size() >= buffer_bytes) {
            flush();
        }
    }

    void flush() {
        _crc = rdb_crc64(_crc, _buf);
        flush_raw();
    }

    void flush_raw() {
        if (_buf.empty()) {
            return;
        }
        _sink.write({reinterpret_cast<const std::uint8_t*>(_buf.data()), _buf.size()});
        _written += _buf.size();
        _buf.clear();
    }

    rdb_byte_sink& _sink;
    rdb_format _format;
    rdb_writer_options _options;
    std::string _buf;
    std::uint64_t _crc = 0;
    std::uint64_t _written = 0;
    bool _finished = false;
};

}  // namespace kythira
