// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_index_records.hpp
/// @brief What the object index keeps in the node's `kv_engine`, and how it
///        is encoded (.kiro/specs/s3-compatible-storage/ task 4, design
///        "Index layout").
///
/// | Key space | Key | Value |
/// |---|---|---|
/// | Catalog | `\0meta/s3/bucket/<name>` | `bucket_descriptor` |
/// | Bucket ids | `\0meta/s3/next-bucket-id` | the next id, never reused (Requirement 6.3) |
/// | Object | `s3/o/<bucket id>/<key>\0<~stamp>` | `object_version`: a manifest or a delete marker
/// | | Upload | `s3/u/<bucket id>/<key>\0<~stamp>` | `upload_record` with its parts | | Refcount |
/// `s3/c/<sha256>` | `refcount_record` | | Zero index | `s3/z/<zero since ms><sha256>` | empty:
/// chunks whose count is zero, oldest first |
///
/// The design's table writes `o/`, `u/` and `c/`; the `s3/` in front keeps
/// them apart from other modules' key spaces when the modules share one
/// engine on a co-located node (the HSM module already uses `c/`, the
/// ledger `l/`). `<bucket id>` and the stamps are 8 big-endian bytes;
/// `~stamp` is the stamp's complement, so a key's versions (and uploads)
/// sort newest first right after the key, and a listing is one forward
/// scan. Object keys may not contain NUL, which separates a key from its
/// stamp; S3 keys are UTF-8 text and the gateway refuses `%00`.
///
/// Records are a small tagged binary encoding (`detail::writer` and
/// `detail::reader`): a format byte, then fields in order, integers
/// big-endian, strings and lists length-prefixed. A record from a newer
/// format fails to decode loudly rather than being misread.

#include <raft/chunk_store.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

class index_format_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

namespace detail {

class writer {
public:
    auto u8(std::uint8_t v) -> writer& {
        _out.push_back(static_cast<char>(v));
        return *this;
    }
    auto u32(std::uint32_t v) -> writer& {
        for (int s = 24; s >= 0; s -= 8) {
            _out.push_back(static_cast<char>((v >> static_cast<unsigned>(s)) & 0xFFU));
        }
        return *this;
    }
    auto u64(std::uint64_t v) -> writer& {
        for (int s = 56; s >= 0; s -= 8) {
            _out.push_back(static_cast<char>((v >> static_cast<unsigned>(s)) & 0xFFU));
        }
        return *this;
    }
    auto boolean(bool v) -> writer& { return u8(v ? 1 : 0); }
    auto str(std::string_view s) -> writer& {
        u32(static_cast<std::uint32_t>(s.size()));
        _out.append(s);
        return *this;
    }
    auto sha(const chunk_sha& s) -> writer& {
        _out.append(reinterpret_cast<const char*>(s.data()), s.size());
        return *this;
    }
    auto opt_str(const std::optional<std::string>& s) -> writer& {
        boolean(s.has_value());
        if (s) {
            str(*s);
        }
        return *this;
    }
    auto map(const std::map<std::string, std::string>& m) -> writer& {
        u32(static_cast<std::uint32_t>(m.size()));
        for (const auto& [k, v] : m) {
            str(k);
            str(v);
        }
        return *this;
    }
    [[nodiscard]] auto take() -> std::string { return std::move(_out); }

private:
    std::string _out;
};

class reader {
public:
    explicit reader(std::string_view in) : _in(in) {}

    auto u8() -> std::uint8_t {
        need(1);
        return static_cast<std::uint8_t>(_in[_p++]);
    }
    auto u32() -> std::uint32_t {
        need(4);
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_in[_p++]);
        }
        return v;
    }
    auto u64() -> std::uint64_t {
        need(8);
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8U) | static_cast<std::uint8_t>(_in[_p++]);
        }
        return v;
    }
    auto boolean() -> bool { return u8() != 0; }
    auto str() -> std::string {
        const auto n = u32();
        need(n);
        std::string s(_in.substr(_p, n));
        _p += n;
        return s;
    }
    auto sha() -> chunk_sha {
        chunk_sha s{};
        need(s.size());
        for (auto& b : s) {
            b = static_cast<std::byte>(_in[_p++]);
        }
        return s;
    }
    auto opt_str() -> std::optional<std::string> {
        if (boolean()) {
            return str();
        }
        return std::nullopt;
    }
    auto map() -> std::map<std::string, std::string> {
        std::map<std::string, std::string> m;
        const auto n = u32();
        for (std::uint32_t i = 0; i < n; ++i) {
            auto k = str();
            m.emplace(std::move(k), str());
        }
        return m;
    }
    void expect_format(std::uint8_t format, std::string_view what) {
        if (u8() != format) {
            throw index_format_error("s3 index: unknown " + std::string(what) + " format");
        }
    }
    void done(std::string_view what) const {
        if (_p != _in.size()) {
            throw index_format_error("s3 index: trailing bytes in " + std::string(what));
        }
    }

private:
    void need(std::size_t n) const {
        if (_in.size() - _p < n) {
            throw index_format_error("s3 index: truncated record");
        }
    }

    std::string_view _in;
    std::size_t _p = 0;
};

inline void put_be64(std::string& out, std::uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) {
        out.push_back(static_cast<char>((v >> static_cast<unsigned>(s)) & 0xFFU));
    }
}

[[nodiscard]] inline auto get_be64(std::string_view in) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v = (v << 8U) | static_cast<std::uint8_t>(in[i]);
    }
    return v;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

namespace keys {

inline constexpr std::string_view catalog_prefix{"\0meta/s3/", 9};
inline constexpr std::string_view bucket_prefix{"\0meta/s3/bucket/", 16};
inline constexpr std::string_view next_bucket_id{"\0meta/s3/next-bucket-id", 23};
inline constexpr std::string_view object_space = "s3/o/";
inline constexpr std::string_view upload_space = "s3/u/";
inline constexpr std::string_view refcount_space = "s3/c/";
inline constexpr std::string_view zero_space = "s3/z/";
/// Tombstones of deleted chunks, by deletion time, for their purge.
inline constexpr std::string_view tombstone_space = "s3/t/";
/// Chunks marked collecting and not yet deleted from the blob stores, so a
/// sweeper that stopped between the two picks them up again.
inline constexpr std::string_view pending_space = "s3/p/";

/// The smallest key above every key starting with `prefix`; nullopt when
/// none exists (all 0xFF).
[[nodiscard]] inline auto prefix_end(std::string prefix) -> std::optional<std::string> {
    while (!prefix.empty() && static_cast<unsigned char>(prefix.back()) == 0xFF) {
        prefix.pop_back();
    }
    if (prefix.empty()) {
        return std::nullopt;
    }
    prefix.back() = static_cast<char>(static_cast<unsigned char>(prefix.back()) + 1);
    return prefix;
}

[[nodiscard]] inline auto bucket(std::string_view name) -> std::string {
    return std::string(bucket_prefix) + std::string(name);
}

/// `s3/o/<id>/` or `s3/u/<id>/`.
[[nodiscard]] inline auto bucket_space(std::string_view space, std::uint64_t bucket_id)
    -> std::string {
    std::string out(space);
    detail::put_be64(out, bucket_id);
    out.push_back('/');
    return out;
}

/// Every version (or upload) of `key`: `<space><id>/<key>\0`.
[[nodiscard]] inline auto key_prefix(std::string_view space, std::uint64_t bucket_id,
                                     std::string_view key) -> std::string {
    auto out = bucket_space(space, bucket_id);
    out.append(key);
    out.push_back('\0');
    return out;
}

/// One version (or upload) of `key`.
[[nodiscard]] inline auto versioned(std::string_view space, std::uint64_t bucket_id,
                                    std::string_view key, std::uint64_t stamp) -> std::string {
    auto out = key_prefix(space, bucket_id, key);
    detail::put_be64(out, ~stamp);
    return out;
}

/// The object key and stamp of a versioned key under `bucket_space`.
struct split_key {
    std::string key;
    std::uint64_t stamp = 0;
};

[[nodiscard]] inline auto split(std::string_view full, std::size_t space_len) -> split_key {
    if (full.size() < space_len + 9 || full[full.size() - 9] != '\0') {
        throw index_format_error("s3 index: malformed versioned key");
    }
    split_key out;
    out.key.assign(full.substr(space_len, full.size() - space_len - 9));
    out.stamp = ~detail::get_be64(full.substr(full.size() - 8));
    return out;
}

[[nodiscard]] inline auto refcount(const chunk_sha& sha) -> std::string {
    std::string out(refcount_space);
    out.append(reinterpret_cast<const char*>(sha.data()), sha.size());
    return out;
}

[[nodiscard]] inline auto zero(std::uint64_t since_ms, const chunk_sha& sha) -> std::string {
    std::string out(zero_space);
    detail::put_be64(out, since_ms);
    out.append(reinterpret_cast<const char*>(sha.data()), sha.size());
    return out;
}

[[nodiscard]] inline auto tombstone(std::uint64_t deleted_ms, const chunk_sha& sha) -> std::string {
    std::string out(tombstone_space);
    detail::put_be64(out, deleted_ms);
    out.append(reinterpret_cast<const char*>(sha.data()), sha.size());
    return out;
}

[[nodiscard]] inline auto pending(const chunk_sha& sha) -> std::string {
    std::string out(pending_space);
    out.append(reinterpret_cast<const char*>(sha.data()), sha.size());
    return out;
}

}  // namespace keys

/// Version ids and upload ids are a stamp as 16 hex digits: opaque to
/// clients, and a direct key lookup for the index. `null` is S3's id of
/// the version an unversioned or suspended bucket writes.
inline constexpr std::string_view null_version_id = "null";

[[nodiscard]] inline auto stamp_id(std::uint64_t stamp) -> std::string {
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = hex[stamp & 0xFU];
        stamp >>= 4U;
    }
    return out;
}

[[nodiscard]] inline auto parse_stamp_id(std::string_view id) -> std::optional<std::uint64_t> {
    if (id.size() != 16) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : id) {
        int d = -1;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        }
        if (d < 0) {
            return std::nullopt;
        }
        v = (v << 4U) | static_cast<std::uint64_t>(d);
    }
    return v;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

enum class versioning_state : std::uint8_t {
    unversioned = 0,
    enabled = 1,
    suspended = 2,
};

/// A bucket in the catalog.
struct bucket_descriptor {
    std::string name;
    /// Never reused, so a recreated bucket sees no old object
    /// (Requirement 6.3).
    std::uint64_t id = 0;
    /// The owning account.
    std::string owner;
    std::string region;
    std::uint64_t created_ms = 0;
    versioning_state versioning = versioning_state::unversioned;
    bool object_lock = false;
    /// Bucket sub-resources stored as sent (`policy`, `cors`, `lifecycle`,
    /// `tagging`, ...), by sub-resource name (Requirement 6.1).
    std::map<std::string, std::string> config;

    friend auto operator==(const bucket_descriptor&, const bucket_descriptor&) -> bool = default;
};

/// One chunk of an object or part, in body order.
struct chunk_ref {
    chunk_sha sha{};
    std::uint64_t size = 0;

    friend auto operator==(const chunk_ref&, const chunk_ref&) -> bool = default;
};

/// What a write stores about an object's bytes and metadata. The front end
/// fills it; the index keeps it as given, except that it never trusts the
/// sizes (the manifest's sum is the size).
struct object_content {
    std::vector<chunk_ref> manifest;
    std::string etag;  ///< as S3 quotes it, without the quotes
    std::string content_type;
    std::string storage_class = "STANDARD";
    /// `x-amz-meta-*`, names lower-cased without the prefix.
    std::map<std::string, std::string> user_metadata;
    /// Other stored headers (Content-Encoding, Cache-Control, checksums,
    /// SSE parameters, tagging, ...), by lower-cased header name.
    std::map<std::string, std::string> system_metadata;
    /// Parts of a multipart object, for `partNumber` reads and the ETag
    /// form; empty for a single PUT. Sizes in part order.
    std::vector<std::uint64_t> part_sizes;

    [[nodiscard]] auto size() const noexcept -> std::uint64_t {
        std::uint64_t n = 0;
        for (const auto& c : manifest) {
            n += c.size;
        }
        return n;
    }

    friend auto operator==(const object_content&, const object_content&) -> bool = default;
};

/// One version of a key: content, or a delete marker.
struct object_version {
    std::string key;
    std::uint64_t stamp = 0;
    /// `stamp_id(stamp)`, or `null` for the version an unversioned or
    /// suspended bucket writes.
    bool null_version = false;
    bool delete_marker = false;
    std::uint64_t last_modified_ms = 0;
    std::string owner;
    object_content content;  ///< empty for a delete marker

    [[nodiscard]] auto version_id() const -> std::string {
        return null_version ? std::string(null_version_id) : stamp_id(stamp);
    }

    friend auto operator==(const object_version&, const object_version&) -> bool = default;
};

/// One uploaded part.
struct part_record {
    std::uint32_t number = 0;
    std::string etag;
    std::uint64_t last_modified_ms = 0;
    std::vector<chunk_ref> manifest;
    std::map<std::string, std::string> checksums;

    [[nodiscard]] auto size() const noexcept -> std::uint64_t {
        std::uint64_t n = 0;
        for (const auto& c : manifest) {
            n += c.size;
        }
        return n;
    }

    friend auto operator==(const part_record&, const part_record&) -> bool = default;
};

/// A multipart upload in progress.
struct upload_record {
    std::string key;
    std::uint64_t stamp = 0;
    std::uint64_t initiated_ms = 0;
    std::string owner;
    /// Content type, metadata and storage class for the completed object;
    /// its manifest stays empty.
    object_content content;
    std::map<std::uint32_t, part_record> parts;

    [[nodiscard]] auto upload_id() const -> std::string { return stamp_id(stamp); }

    friend auto operator==(const upload_record&, const upload_record&) -> bool = default;
};

/// How many manifests (object versions and upload parts) name a chunk, and
/// since when the count has been zero.
/// Where an unreferenced chunk is on its way out (Requirements 10.3, 10.4).
enum class chunk_state : std::uint8_t {
    live = 0,
    /// Handed to a sweeper to delete: nothing may reference it now.
    collecting = 1,
    /// Deleted from the blob stores at `deleted_ms`: only a write that
    /// stored its bytes after that may reference it again.
    deleted = 2,
};

struct refcount_record {
    std::uint64_t count = 0;
    std::uint64_t zero_since_ms = 0;
    chunk_state state = chunk_state::live;
    std::uint64_t deleted_ms = 0;

    friend auto operator==(const refcount_record&, const refcount_record&) -> bool = default;
};

// ---- encode / decode --------------------------------------------------------

namespace codec {

inline constexpr std::uint8_t bucket_format = 1;
inline constexpr std::uint8_t version_format = 1;
inline constexpr std::uint8_t upload_format = 1;
inline constexpr std::uint8_t refcount_format = 1;

inline void write_manifest(detail::writer& w, const std::vector<chunk_ref>& m) {
    w.u32(static_cast<std::uint32_t>(m.size()));
    for (const auto& c : m) {
        w.sha(c.sha).u64(c.size);
    }
}

[[nodiscard]] inline auto read_manifest(detail::reader& r) -> std::vector<chunk_ref> {
    std::vector<chunk_ref> m(r.u32());
    for (auto& c : m) {
        c.sha = r.sha();
        c.size = r.u64();
    }
    return m;
}

inline void write_content(detail::writer& w, const object_content& c) {
    write_manifest(w, c.manifest);
    w.str(c.etag).str(c.content_type).str(c.storage_class);
    w.map(c.user_metadata).map(c.system_metadata);
    w.u32(static_cast<std::uint32_t>(c.part_sizes.size()));
    for (const auto s : c.part_sizes) {
        w.u64(s);
    }
}

[[nodiscard]] inline auto read_content(detail::reader& r) -> object_content {
    object_content c;
    c.manifest = read_manifest(r);
    c.etag = r.str();
    c.content_type = r.str();
    c.storage_class = r.str();
    c.user_metadata = r.map();
    c.system_metadata = r.map();
    c.part_sizes.resize(r.u32());
    for (auto& s : c.part_sizes) {
        s = r.u64();
    }
    return c;
}

[[nodiscard]] inline auto encode(const bucket_descriptor& b) -> std::string {
    detail::writer w;
    w.u8(bucket_format).str(b.name).u64(b.id).str(b.owner).str(b.region).u64(b.created_ms);
    w.u8(static_cast<std::uint8_t>(b.versioning)).boolean(b.object_lock).map(b.config);
    return w.take();
}

[[nodiscard]] inline auto decode_bucket(std::string_view in) -> bucket_descriptor {
    detail::reader r(in);
    r.expect_format(bucket_format, "bucket");
    bucket_descriptor b;
    b.name = r.str();
    b.id = r.u64();
    b.owner = r.str();
    b.region = r.str();
    b.created_ms = r.u64();
    const auto v = r.u8();
    if (v > 2) {
        throw index_format_error("s3 index: bad versioning state");
    }
    b.versioning = static_cast<versioning_state>(v);
    b.object_lock = r.boolean();
    b.config = r.map();
    r.done("bucket");
    return b;
}

[[nodiscard]] inline auto encode(const object_version& v) -> std::string {
    detail::writer w;
    w.u8(version_format).str(v.key).u64(v.stamp).boolean(v.null_version);
    w.boolean(v.delete_marker).u64(v.last_modified_ms).str(v.owner);
    write_content(w, v.content);
    return w.take();
}

[[nodiscard]] inline auto decode_version(std::string_view in) -> object_version {
    detail::reader r(in);
    r.expect_format(version_format, "object version");
    object_version v;
    v.key = r.str();
    v.stamp = r.u64();
    v.null_version = r.boolean();
    v.delete_marker = r.boolean();
    v.last_modified_ms = r.u64();
    v.owner = r.str();
    v.content = read_content(r);
    r.done("object version");
    return v;
}

[[nodiscard]] inline auto encode(const upload_record& u) -> std::string {
    detail::writer w;
    w.u8(upload_format).str(u.key).u64(u.stamp).u64(u.initiated_ms).str(u.owner);
    write_content(w, u.content);
    w.u32(static_cast<std::uint32_t>(u.parts.size()));
    for (const auto& [n, p] : u.parts) {
        w.u32(n).str(p.etag).u64(p.last_modified_ms);
        write_manifest(w, p.manifest);
        w.map(p.checksums);
    }
    return w.take();
}

[[nodiscard]] inline auto decode_upload(std::string_view in) -> upload_record {
    detail::reader r(in);
    r.expect_format(upload_format, "upload");
    upload_record u;
    u.key = r.str();
    u.stamp = r.u64();
    u.initiated_ms = r.u64();
    u.owner = r.str();
    u.content = read_content(r);
    const auto n = r.u32();
    for (std::uint32_t i = 0; i < n; ++i) {
        part_record p;
        p.number = r.u32();
        p.etag = r.str();
        p.last_modified_ms = r.u64();
        p.manifest = read_manifest(r);
        p.checksums = r.map();
        u.parts.emplace(p.number, std::move(p));
    }
    r.done("upload");
    return u;
}

[[nodiscard]] inline auto encode(const refcount_record& c) -> std::string {
    detail::writer w;
    w.u8(refcount_format)
        .u64(c.count)
        .u64(c.zero_since_ms)
        .u8(static_cast<std::uint8_t>(c.state))
        .u64(c.deleted_ms);
    return w.take();
}

[[nodiscard]] inline auto decode_refcount(std::string_view in) -> refcount_record {
    detail::reader r(in);
    r.expect_format(refcount_format, "refcount");
    refcount_record c;
    c.count = r.u64();
    c.zero_since_ms = r.u64();
    const auto state = r.u8();
    if (state > static_cast<std::uint8_t>(chunk_state::deleted)) {
        throw index_format_error("s3 index: unknown chunk state");
    }
    c.state = static_cast<chunk_state>(state);
    c.deleted_ms = r.u64();
    r.done("refcount");
    return c;
}

}  // namespace codec

}  // namespace kythira::s3
