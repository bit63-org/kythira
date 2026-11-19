// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_avro.hpp
/// @brief Apache Avro object container files, written and read, for the
///        channel S3 Tables destination (`.kiro/specs/kinesis-compatible-
///        streams/` task 19, Requirement 18.3).
///
/// Iceberg keeps its manifests and manifest lists as Avro container files,
/// and Avro is one of the data file formats S3 Tables accepts, so one codec
/// covers everything a channel commit writes. Values are `boost::json`
/// trees walked against the schema's JSON:
///
/// | Avro | JSON value |
/// |---|---|
/// | null | null |
/// | boolean | bool |
/// | int, long | int64 (uint64 accepted when it fits) |
/// | float, double | double (integers accepted) |
/// | string | string |
/// | bytes, fixed | string holding the raw bytes |
/// | enum | the symbol, a string |
/// | array, map | array, object |
/// | record | object by field name; a missing field takes its default |
/// | union | the value; null picks the "null" branch, anything else the first branch that accepts
/// it |
///
/// Logical types (`date`, `timestamp-micros`, ...) are their underlying
/// type here; the caller converts. Named types may be referred to by name
/// after their definition, as the specification allows.
///
/// Codecs: `null`, `deflate` (zlib, when the build found it), `snappy`
/// (`kinesis_snappy.hpp`, with the CRC-32 trailer Avro adds) and
/// `zstandard` (libzstd, when found). The writer's sync marker is derived
/// from the schema and a caller-chosen seed, so the same records written
/// again give the same bytes: a retried channel batch overwrites its own
/// file with an identical one.

#include <kythira/kinesis/kinesis_snappy.hpp>

#include <boost/json.hpp>

#include <openssl/sha.h>

#ifdef KYTHIRA_KINESIS_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis::avro {

/// A value that does not match its schema, or bytes that are not an Avro
/// file.
class avro_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace detail {

inline auto put_long(std::string& out, std::int64_t v) -> void {
    auto z = (static_cast<std::uint64_t>(v) << 1U) ^ static_cast<std::uint64_t>(v >> 63);
    while (z >= 0x80U) {
        out.push_back(static_cast<char>((z & 0x7FU) | 0x80U));
        z >>= 7U;
    }
    out.push_back(static_cast<char>(z));
}

inline auto put_bytes(std::string& out, std::string_view b) -> void {
    put_long(out, static_cast<std::int64_t>(b.size()));
    out.append(b);
}

template<typename T> auto put_le(std::string& out, T v) -> void {
    std::array<char, sizeof(T)> raw{};
    std::memcpy(raw.data(), &v, sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        std::ranges::reverse(raw);
    }
    out.append(raw.data(), raw.size());
}

struct reader {
    std::string_view _in;
    std::size_t _at = 0;

    [[nodiscard]] auto done() const -> bool { return _at >= _in.size(); }

    auto byte() -> unsigned char {
        if (_at >= _in.size()) {
            throw avro_error("Avro data ends early.");
        }
        return static_cast<unsigned char>(_in[_at++]);
    }

    auto take(std::size_t n) -> std::string_view {
        if (n > _in.size() - _at) {
            throw avro_error("Avro data ends early.");
        }
        const auto out = _in.substr(_at, n);
        _at += n;
        return out;
    }

    auto get_long() -> std::int64_t {
        std::uint64_t z = 0;
        unsigned shift = 0;
        for (;;) {
            const auto b = byte();
            if (shift > 63) {
                throw avro_error("Avro varint is too long.");
            }
            z |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
            if ((b & 0x80U) == 0) {
                break;
            }
            shift += 7;
        }
        return static_cast<std::int64_t>(z >> 1U) ^ -static_cast<std::int64_t>(z & 1U);
    }

    auto get_bytes() -> std::string_view {
        const auto n = get_long();
        if (n < 0) {
            throw avro_error("Avro length is negative.");
        }
        return take(static_cast<std::size_t>(n));
    }

    template<typename T> auto get_le() -> T {
        const auto raw = take(sizeof(T));
        std::array<char, sizeof(T)> b{};
        std::memcpy(b.data(), raw.data(), sizeof(T));
        if constexpr (std::endian::native == std::endian::big) {
            std::ranges::reverse(b);
        }
        T v{};
        std::memcpy(&v, b.data(), sizeof(T));
        return v;
    }
};

/// Named types seen so far, for references by name.
using names = std::map<std::string, const boost::json::value*>;

[[nodiscard]] inline auto type_name(const boost::json::value& schema) -> std::string {
    if (schema.is_string()) {
        return std::string(schema.as_string());
    }
    if (schema.is_object()) {
        if (const auto* t = schema.as_object().if_contains("type");
            t != nullptr && t->is_string()) {
            return std::string(t->as_string());
        }
    }
    return {};
}

[[nodiscard]] inline auto resolve(const boost::json::value& schema, names& seen)
    -> const boost::json::value& {
    if (schema.is_string()) {
        const auto n = std::string(schema.as_string());
        if (const auto it = seen.find(n); it != seen.end()) {
            return *it->second;
        }
        return schema;
    }
    if (schema.is_object()) {
        const auto& o = schema.as_object();
        const auto t = type_name(schema);
        if ((t == "record" || t == "enum" || t == "fixed") && o.contains("name")) {
            auto n = std::string(o.at("name").as_string());
            if (const auto* ns = o.if_contains("namespace");
                ns != nullptr && ns->is_string() && n.find('.') == std::string::npos) {
                seen.emplace(std::string(ns->as_string()) + "." + n, &schema);
            }
            seen.emplace(std::move(n), &schema);
        }
        // `{"type": "long", "logicalType": ...}` is its type.
        if (const auto* inner = o.if_contains("type");
            inner != nullptr && !inner->is_string() && t.empty()) {
            return resolve(*inner, seen);
        }
    }
    return schema;
}

[[nodiscard]] inline auto as_int64(const boost::json::value& v, std::string_view what)
    -> std::int64_t {
    if (v.is_int64()) {
        return v.as_int64();
    }
    if (v.is_uint64() && v.as_uint64() <= static_cast<std::uint64_t>(INT64_MAX)) {
        return static_cast<std::int64_t>(v.as_uint64());
    }
    throw avro_error("Avro " + std::string(what) + " needs an integer.");
}

[[nodiscard]] inline auto as_double(const boost::json::value& v, std::string_view what) -> double {
    if (v.is_double()) {
        return v.as_double();
    }
    if (v.is_int64()) {
        return static_cast<double>(v.as_int64());
    }
    if (v.is_uint64()) {
        return static_cast<double>(v.as_uint64());
    }
    throw avro_error("Avro " + std::string(what) + " needs a number.");
}

// NOLINTNEXTLINE(misc-no-recursion): schemas nest.
[[nodiscard]] inline auto accepts(const boost::json::value& schema, const boost::json::value& v,
                                  names& seen) -> bool {
    const auto& s = resolve(schema, seen);
    if (s.is_array()) {
        for (const auto& b : s.as_array()) {
            if (accepts(b, v, seen)) {
                return true;
            }
        }
        return false;
    }
    const auto t = type_name(s);
    if (t == "null") {
        return v.is_null();
    }
    if (t == "boolean") {
        return v.is_bool();
    }
    if (t == "int" || t == "long") {
        return v.is_int64() || v.is_uint64();
    }
    if (t == "float" || t == "double") {
        return v.is_number();
    }
    if (t == "string" || t == "bytes" || t == "fixed" || t == "enum") {
        return v.is_string();
    }
    if (t == "array") {
        return v.is_array();
    }
    if (t == "map" || t == "record") {
        return v.is_object();
    }
    return false;
}

// NOLINTNEXTLINE(misc-no-recursion): schemas nest.
inline auto encode(std::string& out, const boost::json::value& schema, const boost::json::value& v,
                   names& seen) -> void {
    const auto& s = resolve(schema, seen);
    if (s.is_array()) {
        const auto& branches = s.as_array();
        for (std::size_t i = 0; i < branches.size(); ++i) {
            const bool is_null = type_name(branches[i]) == "null";
            if ((v.is_null() && is_null) ||
                (!v.is_null() && !is_null && accepts(branches[i], v, seen))) {
                put_long(out, static_cast<std::int64_t>(i));
                encode(out, branches[i], v, seen);
                return;
            }
        }
        throw avro_error("No branch of an Avro union takes the value " + boost::json::serialize(v) +
                         ".");
    }
    const auto t = type_name(s);
    if (t == "null") {
        if (!v.is_null()) {
            throw avro_error("Avro null needs null.");
        }
    } else if (t == "boolean") {
        if (!v.is_bool()) {
            throw avro_error("Avro boolean needs a bool.");
        }
        out.push_back(v.as_bool() ? '\1' : '\0');
    } else if (t == "int") {
        const auto n = as_int64(v, "int");
        if (n < INT32_MIN || n > INT32_MAX) {
            throw avro_error("Avro int out of range.");
        }
        put_long(out, n);
    } else if (t == "long") {
        put_long(out, as_int64(v, "long"));
    } else if (t == "float") {
        put_le(out, static_cast<float>(as_double(v, "float")));
    } else if (t == "double") {
        put_le(out, as_double(v, "double"));
    } else if (t == "string" || t == "bytes") {
        if (!v.is_string()) {
            throw avro_error("Avro " + t + " needs a string.");
        }
        put_bytes(out, v.as_string());
    } else if (t == "fixed") {
        const auto size =
            static_cast<std::size_t>(s.as_object().at("size").to_number<std::int64_t>());
        if (!v.is_string() || v.as_string().size() != size) {
            throw avro_error("Avro fixed needs exactly " + std::to_string(size) + " bytes.");
        }
        out.append(v.as_string());
    } else if (t == "enum") {
        const auto& symbols = s.as_object().at("symbols").as_array();
        for (std::size_t i = 0; i < symbols.size(); ++i) {
            if (v.is_string() && symbols[i].as_string() == v.as_string()) {
                put_long(out, static_cast<std::int64_t>(i));
                return;
            }
        }
        throw avro_error("Avro enum has no symbol " + boost::json::serialize(v) + ".");
    } else if (t == "array") {
        if (!v.is_array()) {
            throw avro_error("Avro array needs an array.");
        }
        const auto& items = s.as_object().at("items");
        if (!v.as_array().empty()) {
            put_long(out, static_cast<std::int64_t>(v.as_array().size()));
            for (const auto& item : v.as_array()) {
                encode(out, items, item, seen);
            }
        }
        put_long(out, 0);
    } else if (t == "map") {
        if (!v.is_object()) {
            throw avro_error("Avro map needs an object.");
        }
        const auto& values = s.as_object().at("values");
        if (!v.as_object().empty()) {
            put_long(out, static_cast<std::int64_t>(v.as_object().size()));
            for (const auto& [k, item] : v.as_object()) {
                put_bytes(out, k);
                encode(out, values, item, seen);
            }
        }
        put_long(out, 0);
    } else if (t == "record") {
        if (!v.is_object()) {
            throw avro_error("Avro record needs an object.");
        }
        for (const auto& f : s.as_object().at("fields").as_array()) {
            const auto& field = f.as_object();
            const auto name = field.at("name").as_string();
            if (const auto* fv = v.as_object().if_contains(name)) {
                encode(out, field.at("type"), *fv, seen);
            } else if (const auto* d = field.if_contains("default")) {
                encode(out, field.at("type"), *d, seen);
            } else {
                encode(out, field.at("type"), boost::json::value(nullptr), seen);
            }
        }
    } else {
        throw avro_error("Unknown Avro type '" + t + "'.");
    }
}

// NOLINTNEXTLINE(misc-no-recursion): schemas nest.
[[nodiscard]] inline auto decode(reader& in, const boost::json::value& schema, names& seen)
    -> boost::json::value {
    const auto& s = resolve(schema, seen);
    if (s.is_array()) {
        const auto i = in.get_long();
        const auto& branches = s.as_array();
        if (i < 0 || static_cast<std::size_t>(i) >= branches.size()) {
            throw avro_error("Avro union branch out of range.");
        }
        return decode(in, branches[static_cast<std::size_t>(i)], seen);
    }
    const auto t = type_name(s);
    if (t == "null") {
        return nullptr;
    }
    if (t == "boolean") {
        return in.byte() != 0;
    }
    if (t == "int" || t == "long") {
        return in.get_long();
    }
    if (t == "float") {
        return static_cast<double>(in.get_le<float>());
    }
    if (t == "double") {
        return in.get_le<double>();
    }
    if (t == "string" || t == "bytes") {
        const auto b = in.get_bytes();
        return boost::json::string(b);
    }
    if (t == "fixed") {
        const auto size =
            static_cast<std::size_t>(s.as_object().at("size").to_number<std::int64_t>());
        return boost::json::string(in.take(size));
    }
    if (t == "enum") {
        const auto i = in.get_long();
        const auto& symbols = s.as_object().at("symbols").as_array();
        if (i < 0 || static_cast<std::size_t>(i) >= symbols.size()) {
            throw avro_error("Avro enum index out of range.");
        }
        return symbols[static_cast<std::size_t>(i)];
    }
    if (t == "array" || t == "map") {
        const bool is_map = t == "map";
        const auto& item = s.as_object().at(is_map ? "values" : "items");
        boost::json::array arr;
        boost::json::object obj;
        for (;;) {
            auto n = in.get_long();
            if (n == 0) {
                break;
            }
            if (n < 0) {
                n = -n;
                (void)in.get_long();  // the block's size in bytes
            }
            for (std::int64_t i = 0; i < n; ++i) {
                if (is_map) {
                    const auto k = in.get_bytes();
                    obj[k] = decode(in, item, seen);
                } else {
                    arr.push_back(decode(in, item, seen));
                }
            }
        }
        if (is_map) {
            return obj;
        }
        return arr;
    }
    if (t == "record") {
        boost::json::object obj;
        for (const auto& f : s.as_object().at("fields").as_array()) {
            const auto& field = f.as_object();
            obj[field.at("name").as_string()] = decode(in, field.at("type"), seen);
        }
        return obj;
    }
    throw avro_error("Unknown Avro type '" + t + "'.");
}

[[nodiscard]] inline auto crc32(std::string_view in) -> std::uint32_t {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            auto c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1U) != 0 ? 0xEDB88320U ^ (c >> 1U) : c >> 1U;
            }
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t c = 0xFFFFFFFFU;
    for (const auto ch : in) {
        c = table[(c ^ static_cast<unsigned char>(ch)) & 0xFFU] ^ (c >> 8U);
    }
    return c ^ 0xFFFFFFFFU;
}

[[nodiscard]] inline auto deflate_raw(std::string_view in) -> std::optional<std::string> {
#ifdef KYTHIRA_KINESIS_HAS_ZLIB
    z_stream z{};
    if (deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return std::nullopt;
    }
    std::string out(deflateBound(&z, static_cast<uLong>(in.size())), '\0');
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT
    z.avail_in = static_cast<uInt>(in.size());
    z.next_out = reinterpret_cast<Bytef*>(out.data());
    z.avail_out = static_cast<uInt>(out.size());
    const auto rc = deflate(&z, Z_FINISH);
    const auto n = z.total_out;
    deflateEnd(&z);
    if (rc != Z_STREAM_END) {
        return std::nullopt;
    }
    out.resize(n);
    return out;
#else
    (void)in;
    return std::nullopt;
#endif
}

[[nodiscard]] inline auto inflate_raw(std::string_view in) -> std::optional<std::string> {
#ifdef KYTHIRA_KINESIS_HAS_ZLIB
    z_stream z{};
    if (inflateInit2(&z, -15) != Z_OK) {
        return std::nullopt;
    }
    std::string out;
    std::array<char, 65536> buf{};
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT
    z.avail_in = static_cast<uInt>(in.size());
    int rc = Z_OK;
    while (rc == Z_OK) {
        z.next_out = reinterpret_cast<Bytef*>(buf.data());
        z.avail_out = static_cast<uInt>(buf.size());
        rc = inflate(&z, Z_NO_FLUSH);
        out.append(buf.data(), buf.size() - z.avail_out);
        if (rc == Z_BUF_ERROR && z.avail_in == 0) {
            break;
        }
    }
    inflateEnd(&z);
    if (rc != Z_STREAM_END) {
        return std::nullopt;
    }
    return out;
#else
    (void)in;
    return std::nullopt;
#endif
}

}  // namespace detail

/// Whether this build can write and read `codec`.
[[nodiscard]] inline auto has_codec(std::string_view codec) -> bool {
    if (codec == "null" || codec == "snappy") {
        return true;
    }
#ifdef KYTHIRA_KINESIS_HAS_ZLIB
    if (codec == "deflate") {
        return true;
    }
#endif
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    if (codec == "zstandard") {
        return true;
    }
#endif
    return false;
}

/// `block` compressed with `codec`; throws when this build cannot.
[[nodiscard]] inline auto compress_block(std::string_view codec, std::string_view block)
    -> std::string {
    if (codec == "null") {
        return std::string(block);
    }
    if (codec == "snappy") {
        auto out = snappy::compress(block);
        const auto crc = detail::crc32(block);
        for (int shift = 24; shift >= 0; shift -= 8) {
            out.push_back(static_cast<char>((crc >> static_cast<unsigned>(shift)) & 0xFFU));
        }
        return out;
    }
    if (codec == "deflate") {
        if (auto out = detail::deflate_raw(block)) {
            return std::move(*out);
        }
    }
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    if (codec == "zstandard") {
        std::string out(ZSTD_compressBound(block.size()), '\0');
        const auto n = ZSTD_compress(out.data(), out.size(), block.data(), block.size(), 3);
        if (ZSTD_isError(n) == 0U) {
            out.resize(n);
            return out;
        }
    }
#endif
    throw avro_error("This build cannot write the Avro codec '" + std::string(codec) + "'.");
}

[[nodiscard]] inline auto decompress_block(std::string_view codec, std::string_view block)
    -> std::string {
    if (codec == "null") {
        return std::string(block);
    }
    if (codec == "snappy") {
        if (block.size() < 4) {
            throw avro_error("Avro snappy block has no checksum.");
        }
        auto out = snappy::decompress(block.substr(0, block.size() - 4));
        if (!out) {
            throw avro_error("Avro snappy block does not decompress.");
        }
        std::uint32_t crc = 0;
        for (std::size_t i = block.size() - 4; i < block.size(); ++i) {
            crc = (crc << 8U) | static_cast<unsigned char>(block[i]);
        }
        if (crc != detail::crc32(*out)) {
            throw avro_error("Avro snappy block fails its checksum.");
        }
        return std::move(*out);
    }
    if (codec == "deflate") {
        if (auto out = detail::inflate_raw(block)) {
            return std::move(*out);
        }
        throw avro_error("Avro deflate block does not decompress.");
    }
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    if (codec == "zstandard") {
        const auto size = ZSTD_getFrameContentSize(block.data(), block.size());
        if (size != ZSTD_CONTENTSIZE_ERROR && size != ZSTD_CONTENTSIZE_UNKNOWN) {
            std::string out(size, '\0');
            const auto n = ZSTD_decompress(out.data(), out.size(), block.data(), block.size());
            if (ZSTD_isError(n) == 0U && n == size) {
                return out;
            }
        }
        throw avro_error("Avro zstandard block does not decompress.");
    }
#endif
    throw avro_error("This build cannot read the Avro codec '" + std::string(codec) + "'.");
}

/// One datum, encoded against `schema`.
[[nodiscard]] inline auto encode(const boost::json::value& schema, const boost::json::value& v)
    -> std::string {
    std::string out;
    detail::names seen;
    detail::encode(out, schema, v, seen);
    return out;
}

/// Writes one container file. Records are buffered and written as blocks of
/// about `_block_bytes`.
class file_writer {
public:
    /// `metadata` goes in the header beside `avro.schema` and `avro.codec`;
    /// `seed` picks the sync marker (the same seed and schema, the same
    /// marker).
    file_writer(boost::json::value schema, std::string codec,
                std::map<std::string, std::string> metadata, std::string_view seed)
        : _schema(std::move(schema)), _codec(std::move(codec)) {
        if (!has_codec(_codec)) {
            throw avro_error("This build cannot write the Avro codec '" + _codec + "'.");
        }
        const auto schema_text = boost::json::serialize(_schema);
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
        const auto basis = schema_text + "\n" + std::string(seed);
        SHA256(reinterpret_cast<const unsigned char*>(basis.data()), basis.size(), digest.data());
        std::memcpy(_sync.data(), digest.data(), _sync.size());
        _out = std::string("Obj\x01", 4);
        metadata["avro.schema"] = schema_text;
        metadata["avro.codec"] = _codec;
        detail::put_long(_out, static_cast<std::int64_t>(metadata.size()));
        for (const auto& [k, v] : metadata) {
            detail::put_bytes(_out, k);
            detail::put_bytes(_out, v);
        }
        detail::put_long(_out, 0);
        _out.append(_sync.data(), _sync.size());
    }

    auto append(const boost::json::value& v) -> void {
        detail::names seen;
        detail::encode(_block, _schema, v, seen);
        ++_count;
        ++_total;
        if (_block.size() >= _block_bytes) {
            flush();
        }
    }

    [[nodiscard]] auto records() const -> std::uint64_t { return _total; }

    /// The whole file; the writer is spent.
    [[nodiscard]] auto finish() -> std::string {
        flush();
        return std::move(_out);
    }

private:
    boost::json::value _schema;
    std::string _codec;
    std::array<char, 16> _sync{};
    std::string _out;
    std::string _block;
    std::int64_t _count = 0;
    std::uint64_t _total = 0;
    std::size_t _block_bytes = std::size_t{1} << 20U;

    auto flush() -> void {
        if (_count == 0) {
            return;
        }
        const auto body = compress_block(_codec, _block);
        detail::put_long(_out, _count);
        detail::put_long(_out, static_cast<std::int64_t>(body.size()));
        _out.append(body);
        _out.append(_sync.data(), _sync.size());
        _block.clear();
        _count = 0;
    }
};

struct file {
    boost::json::value _schema;
    std::map<std::string, std::string> _metadata;
    std::vector<boost::json::value> _records;
};

/// Reads a whole container file; throws `avro_error`.
[[nodiscard]] inline auto read_file(std::string_view bytes) -> file {
    detail::reader in{bytes};
    if (in.take(4) != std::string_view("Obj\x01", 4)) {
        throw avro_error("Not an Avro container file.");
    }
    file out;
    for (;;) {
        auto n = in.get_long();
        if (n == 0) {
            break;
        }
        if (n < 0) {
            n = -n;
            (void)in.get_long();
        }
        for (std::int64_t i = 0; i < n; ++i) {
            auto k = std::string(in.get_bytes());
            out._metadata[std::move(k)] = std::string(in.get_bytes());
        }
    }
    const auto sync = in.take(16);
    const auto schema = out._metadata.find("avro.schema");
    if (schema == out._metadata.end()) {
        throw avro_error("Avro file has no schema.");
    }
    try {
        out._schema = boost::json::parse(schema->second);
    } catch (const std::exception&) {
        throw avro_error("Avro file's schema is not JSON.");
    }
    const auto c = out._metadata.find("avro.codec");
    const std::string codec = c == out._metadata.end() ? "null" : c->second;
    while (!in.done()) {
        const auto count = in.get_long();
        const auto block = decompress_block(codec, in.get_bytes());
        if (in.take(16) != sync) {
            throw avro_error("Avro block is not followed by the file's sync marker.");
        }
        detail::reader b{block};
        detail::names seen;
        for (std::int64_t i = 0; i < count; ++i) {
            out._records.push_back(detail::decode(b, out._schema, seen));
        }
    }
    return out;
}

}  // namespace kythira::kinesis::avro
