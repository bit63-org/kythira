// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_parquet.hpp
/// @brief Apache Parquet data files for the channel S3 Tables destination
///        (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement
///        18.3).
///
/// S3 Tables' `CompressionType` (`NONE`, `SNAPPY`, `ZSTD`) is Parquet's,
/// and Parquet is the one data file format every Iceberg reader takes
/// (pyiceberg and DuckDB read no Avro data files), so channel data files
/// are Parquet. The writer covers what a channel needs and no more:
///
/// - one row group, one data page (v1) per column, PLAIN values, RLE
///   definition and repetition levels;
/// - columns from an Iceberg schema: boolean, int, long, float, double,
///   date, time, timestamp, timestamptz, string, binary, uuid, and struct
///   and list of them (lists in the standard three-level form), each
///   carrying its Iceberg field id so readers match columns by id;
/// - `UNCOMPRESSED`, `SNAPPY` (`kinesis_snappy.hpp`) and `ZSTD` (libzstd).
///
/// Rows are the converted rows of `kinesis_iceberg.hpp`'s `to_row`
/// (timestamps in microseconds, dates in days, binary and uuid as raw
/// bytes, structs keyed by Avro-safe names). Column statistics are not
/// written. The footer is Thrift's compact protocol, written here by hand
/// for the handful of structures Parquet's metadata needs.

#include <kythira/kinesis/kinesis_snappy.hpp>

#include <boost/json.hpp>

#ifdef KYTHIRA_KINESIS_HAS_ZSTD
#include <zstd.h>
#endif

#include <algorithm>
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

namespace kythira::kinesis::parquet {

class parquet_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Thrift compact protocol, write side.
class compact_writer {
public:
    enum type : std::uint8_t {
        t_true = 1,
        t_false = 2,
        t_byte = 3,
        t_i16 = 4,
        t_i32 = 5,
        t_i64 = 6,
        t_double = 7,
        t_binary = 8,
        t_list = 9,
        t_struct = 12,
    };

    auto field_i32(std::int16_t id, std::int32_t v) -> compact_writer& {
        header(id, t_i32);
        varint(zigzag(v));
        return *this;
    }
    auto field_i64(std::int16_t id, std::int64_t v) -> compact_writer& {
        header(id, t_i64);
        varint(zigzag(v));
        return *this;
    }
    auto field_bool(std::int16_t id, bool v) -> compact_writer& {
        header(id, v ? t_true : t_false);
        return *this;
    }
    auto field_binary(std::int16_t id, std::string_view v) -> compact_writer& {
        header(id, t_binary);
        binary(v);
        return *this;
    }
    auto begin_struct(std::int16_t id) -> compact_writer& {
        header(id, t_struct);
        _last.push_back(0);
        return *this;
    }
    auto end_struct() -> compact_writer& {
        _out.push_back('\0');
        _last.pop_back();
        return *this;
    }
    /// A list field of `n` elements of `elem`; structs follow with
    /// begin_element()/end_struct(), i32s with element_i32(), strings with
    /// element_binary().
    auto begin_list(std::int16_t id, type elem, std::size_t n) -> compact_writer& {
        header(id, t_list);
        if (n < 15) {
            _out.push_back(static_cast<char>((n << 4U) | elem));
        } else {
            _out.push_back(static_cast<char>(0xF0U | elem));
            varint(n);
        }
        return *this;
    }
    auto begin_element() -> compact_writer& {
        _last.push_back(0);
        return *this;
    }
    auto element_i32(std::int32_t v) -> compact_writer& {
        varint(zigzag(v));
        return *this;
    }
    auto element_binary(std::string_view v) -> compact_writer& {
        binary(v);
        return *this;
    }
    /// The top-level struct's stop byte; the bytes so far.
    [[nodiscard]] auto finish() -> std::string {
        _out.push_back('\0');
        return std::move(_out);
    }

private:
    std::string _out;
    std::vector<std::int16_t> _last{0};

    static auto zigzag(std::int64_t v) -> std::uint64_t {
        return (static_cast<std::uint64_t>(v) << 1U) ^ static_cast<std::uint64_t>(v >> 63);
    }
    auto varint(std::uint64_t v) -> void {
        while (v >= 0x80U) {
            _out.push_back(static_cast<char>((v & 0x7FU) | 0x80U));
            v >>= 7U;
        }
        _out.push_back(static_cast<char>(v));
    }
    auto binary(std::string_view v) -> void {
        varint(v.size());
        _out.append(v);
    }
    auto header(std::int16_t id, type t) -> void {
        const auto delta = id - _last.back();
        if (delta > 0 && delta <= 15) {
            _out.push_back(static_cast<char>((delta << 4) | t));
        } else {
            _out.push_back(static_cast<char>(t));
            varint(zigzag(id));
        }
        _last.back() = id;
    }
};

namespace detail {

enum physical : std::int32_t {
    p_boolean = 0,
    p_int32 = 1,
    p_int64 = 2,
    p_float = 4,
    p_double = 5,
    p_byte_array = 6,
    p_fixed = 7,
};

enum repetition : std::int32_t {
    required = 0,
    optional = 1,
    repeated = 2
};

/// One node of the Parquet schema, built from the Iceberg schema.
struct node {
    std::string _name;
    repetition _rep = required;
    std::int64_t _field_id = -1;
    /// Leaves: the physical type and logical annotation.
    std::optional<physical> _physical;
    std::string _logical;  // string, date, time, timestamp, timestamptz, uuid, list
    std::vector<node> _children;
    /// Leaves: index into the column list.
    std::size_t _leaf = 0;
    int _max_def = 0;
    int _max_rep = 0;
    /// Groups: `list` for the LIST-annotated outer group.
    bool _is_list = false;
    /// Struct children's keys in the converted row.
    std::string _row_key;
};

struct column {
    std::vector<std::string> _path;
    physical _type = p_int32;
    int _max_def = 0;
    int _max_rep = 0;
    std::vector<std::uint32_t> _defs;
    std::vector<std::uint32_t> _reps;
    std::string _values;
    std::int64_t _non_null = 0;
    bool _bits_pending = false;
    std::uint8_t _bit_byte = 0;
    int _bit_count = 0;
};

[[nodiscard]] inline auto row_key(std::string_view name) -> std::string {
    // kinesis_iceberg.hpp's avro_name: rows are keyed the same way.
    std::string out;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const auto c = static_cast<unsigned char>(name[i]);
        const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        const bool digit = c >= '0' && c <= '9';
        if (letter || (digit && i > 0)) {
            out.push_back(static_cast<char>(c));
        } else if (digit) {
            out.push_back('_');
            out.push_back(static_cast<char>(c));
        } else {
            static constexpr std::string_view hex = "0123456789ABCDEF";
            out += "_x";
            if (c >= 16) {
                out.push_back(hex[c >> 4U]);
            }
            out.push_back(hex[c & 15U]);
        }
    }
    return out.empty() ? std::string("_") : out;
}

[[nodiscard]] inline auto mid_path(std::vector<std::string> path) -> std::vector<std::string> {
    path.push_back("list");
    return path;
}

// NOLINTNEXTLINE(misc-no-recursion): types nest.
inline auto build(node& n, const boost::json::value& type, int def, int rep,
                  std::vector<std::string> path, std::vector<column>& columns) -> void {
    if (n._rep == optional || n._rep == repeated) {
        ++def;
    }
    if (n._rep == repeated) {
        ++rep;
    }
    path.push_back(n._name);
    n._max_def = def;
    n._max_rep = rep;
    if (type.is_string()) {
        const std::string t(type.as_string());
        static const std::map<std::string, std::pair<physical, std::string>> leaves{
            {"boolean", {p_boolean, ""}},
            {"int", {p_int32, ""}},
            {"long", {p_int64, ""}},
            {"float", {p_float, ""}},
            {"double", {p_double, ""}},
            {"date", {p_int32, "date"}},
            {"time", {p_int64, "time"}},
            {"timestamp", {p_int64, "timestamp"}},
            {"timestamptz", {p_int64, "timestamptz"}},
            {"string", {p_byte_array, "string"}},
            {"binary", {p_byte_array, ""}},
            {"uuid", {p_fixed, "uuid"}},
        };
        const auto it = leaves.find(t);
        if (it == leaves.end()) {
            throw parquet_error("No Parquet column for the Iceberg type " + t + ".");
        }
        n._physical = it->second.first;
        n._logical = it->second.second;
        n._leaf = columns.size();
        columns.push_back(column{
            ._path = std::move(path), ._type = it->second.first, ._max_def = def, ._max_rep = rep});
        return;
    }
    const auto& o = type.as_object();
    const std::string kind(o.at("type").as_string());
    if (kind == "struct") {
        for (const auto& f : o.at("fields").as_array()) {
            const auto& field = f.as_object();
            node child;
            child._name = std::string(field.at("name").as_string());
            child._row_key = row_key(child._name);
            child._rep = field.at("required").as_bool() ? required : optional;
            child._field_id = field.at("id").to_number<std::int64_t>();
            build(child, field.at("type"), def, rep, path, columns);
            n._children.push_back(std::move(child));
        }
        return;
    }
    if (kind == "list") {
        n._is_list = true;
        n._logical = "list";
        node mid;
        mid._name = "list";
        mid._rep = repeated;
        node element;
        element._name = "element";
        element._rep = o.at("element-required").as_bool() ? required : optional;
        element._field_id = o.at("element-id").to_number<std::int64_t>();
        build(mid, boost::json::object{{"type", "struct"}, {"fields", boost::json::array{}}}, def,
              rep, path, columns);
        // `mid` holds exactly the element; build it under mid's levels.
        build(element, o.at("element"), mid._max_def, mid._max_rep, mid_path(path), columns);
        mid._children.push_back(std::move(element));
        n._children.push_back(std::move(mid));
        return;
    }
    throw parquet_error("No Parquet column for the Iceberg type " + kind + ".");
}

inline auto put_value(column& c, const boost::json::value& v) -> void {
    auto le = [&c](auto x) {
        char raw[sizeof(x)];
        std::memcpy(raw, &x, sizeof(x));
        if constexpr (std::endian::native == std::endian::big) {
            std::reverse(raw, raw + sizeof(x));
        }
        c._values.append(raw, sizeof(x));
    };
    switch (c._type) {
        case p_boolean:
            if (v.as_bool()) {
                c._bit_byte |= static_cast<std::uint8_t>(1U << static_cast<unsigned>(c._bit_count));
            }
            if (++c._bit_count == 8) {
                c._values.push_back(static_cast<char>(c._bit_byte));
                c._bit_byte = 0;
                c._bit_count = 0;
            }
            break;
        case p_int32:
            le(static_cast<std::int32_t>(v.as_int64()));
            break;
        case p_int64:
            le(v.as_int64());
            break;
        case p_float:
            le(static_cast<float>(v.to_number<double>()));
            break;
        case p_double:
            le(v.to_number<double>());
            break;
        case p_byte_array: {
            const auto s = std::string_view(v.as_string());
            le(static_cast<std::uint32_t>(s.size()));
            c._values.append(s);
            break;
        }
        case p_fixed:
            c._values.append(v.as_string());
            break;
    }
    ++c._non_null;
}

// NOLINTNEXTLINE(misc-no-recursion): leaves under a null all get the null.
inline auto put_nulls(const node& n, std::uint32_t rep, std::uint32_t def,
                      std::vector<column>& columns) -> void {
    if (n._physical) {
        columns[n._leaf]._defs.push_back(def);
        columns[n._leaf]._reps.push_back(rep);
        return;
    }
    for (const auto& c : n._children) {
        put_nulls(c, rep, def, columns);
    }
}

// NOLINTNEXTLINE(misc-no-recursion): Dremel shredding walks the schema.
inline auto shred(const node& n, const boost::json::value* v, std::uint32_t rep,
                  std::vector<column>& columns) -> void {
    const bool absent = v == nullptr || v->is_null();
    if (absent) {
        if (n._rep == required) {
            throw parquet_error("Required column '" + n._name + "' is null.");
        }
        // Defined down to this node's parent.
        put_nulls(n, rep, static_cast<std::uint32_t>(n._max_def - 1), columns);
        return;
    }
    if (n._physical) {
        auto& c = columns[n._leaf];
        c._defs.push_back(static_cast<std::uint32_t>(n._max_def));
        c._reps.push_back(rep);
        put_value(c, *v);
        return;
    }
    if (n._is_list) {
        const auto& mid = n._children.front();
        const auto& items = v->as_array();
        if (items.empty()) {
            put_nulls(mid, rep, static_cast<std::uint32_t>(n._max_def), columns);
            return;
        }
        for (std::size_t i = 0; i < items.size(); ++i) {
            const auto r = i == 0 ? rep : static_cast<std::uint32_t>(mid._max_rep);
            shred(mid._children.front(), &items[i], r, columns);
        }
        return;
    }
    for (const auto& c : n._children) {
        shred(c, v->as_object().if_contains(c._row_key), rep, columns);
    }
}

[[nodiscard]] inline auto bit_width(int max_level) -> int {
    int w = 0;
    while ((1 << w) <= max_level) {
        ++w;
    }
    return w;
}

/// RLE runs only (the hybrid encoding's bit-packed runs are optional).
[[nodiscard]] inline auto rle(const std::vector<std::uint32_t>& levels, int width) -> std::string {
    std::string out;
    const auto bytes = static_cast<std::size_t>((width + 7) / 8);
    std::size_t i = 0;
    while (i < levels.size()) {
        std::size_t j = i;
        while (j < levels.size() && levels[j] == levels[i]) {
            ++j;
        }
        auto header = static_cast<std::uint64_t>(j - i) << 1U;
        while (header >= 0x80U) {
            out.push_back(static_cast<char>((header & 0x7FU) | 0x80U));
            header >>= 7U;
        }
        out.push_back(static_cast<char>(header));
        for (std::size_t b = 0; b < bytes; ++b) {
            out.push_back(static_cast<char>((levels[i] >> (8 * b)) & 0xFFU));
        }
        i = j;
    }
    return out;
}

inline auto put_u32_le(std::string& out, std::uint32_t v) -> void {
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((v >> (8U * i)) & 0xFFU));
    }
}

// NOLINTNEXTLINE(misc-no-recursion): schema elements in depth-first order.
inline auto schema_elements(compact_writer& w, const node& n, bool root) -> void {
    w.begin_element();
    if (n._physical) {
        w.field_i32(1, *n._physical);
        if (*n._physical == p_fixed) {
            w.field_i32(2, 16);
        }
    }
    if (!root) {
        w.field_i32(3, n._rep);
    }
    w.field_binary(4, n._name);
    if (!n._physical) {
        w.field_i32(5, static_cast<std::int32_t>(n._children.size()));
    }
    // converted_type
    if (n._logical == "string") {
        w.field_i32(6, 0);  // UTF8
    } else if (n._logical == "list") {
        w.field_i32(6, 3);  // LIST
    } else if (n._logical == "date") {
        w.field_i32(6, 6);  // DATE
    } else if (n._logical == "time") {
        w.field_i32(6, 8);  // TIME_MICROS
    } else if (n._logical == "timestamptz") {
        w.field_i32(6, 10);  // TIMESTAMP_MICROS (UTC-adjusted only)
    }
    if (n._field_id >= 0) {
        w.field_i32(9, static_cast<std::int32_t>(n._field_id));
    }
    // logicalType (a union: one field set)
    if (!n._logical.empty()) {
        w.begin_struct(10);
        if (n._logical == "string") {
            w.begin_struct(1).end_struct();
        } else if (n._logical == "list") {
            w.begin_struct(3).end_struct();
        } else if (n._logical == "date") {
            w.begin_struct(6).end_struct();
        } else if (n._logical == "time" || n._logical == "timestamp" ||
                   n._logical == "timestamptz") {
            w.begin_struct(n._logical == "time" ? 7 : 8);
            w.field_bool(1, n._logical == "timestamptz");
            w.begin_struct(2).begin_struct(2).end_struct().end_struct();  // MICROS
            w.end_struct();
        } else if (n._logical == "uuid") {
            w.begin_struct(14).end_struct();
        }
        w.end_struct();
    }
    w.end_struct();
    for (const auto& c : n._children) {
        schema_elements(w, c, false);
    }
}

[[nodiscard]] inline auto count_nodes(const node& n) -> std::size_t {
    std::size_t k = 1;
    for (const auto& c : n._children) {
        k += count_nodes(c);
    }
    return k;
}

}  // namespace detail

/// Whether this build can write `codec` (`UNCOMPRESSED`, `SNAPPY`, `ZSTD`).
[[nodiscard]] inline auto has_codec(std::string_view codec) -> bool {
    if (codec == "UNCOMPRESSED" || codec == "SNAPPY") {
        return true;
    }
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
    return codec == "ZSTD";
#else
    return false;
#endif
}

/// A whole Parquet file of `rows` (converted rows) of the Iceberg schema
/// `schema`, compressed with `codec`; throws `parquet_error`.
[[nodiscard]] inline auto write_file(const boost::json::object& schema,
                                     const std::vector<boost::json::object>& rows,
                                     std::string_view codec,
                                     const std::map<std::string, std::string>& metadata = {})
    -> std::string {
    std::int32_t codec_id = 0;
    if (codec == "SNAPPY") {
        codec_id = 1;
    } else if (codec == "ZSTD") {
        codec_id = 6;
    } else if (codec != "UNCOMPRESSED") {
        throw parquet_error("Unknown Parquet codec " + std::string(codec) + ".");
    }
    if (!has_codec(codec)) {
        throw parquet_error("This build cannot write Parquet " + std::string(codec) + ".");
    }
    detail::node root;
    root._name = "table";
    std::vector<detail::column> columns;
    detail::build(root, boost::json::object{{"type", "struct"}, {"fields", schema.at("fields")}}, 0,
                  0, {}, columns);
    // The root is not a path segment.
    for (auto& c : columns) {
        c._path.erase(c._path.begin());
    }
    for (const auto& r : rows) {
        const boost::json::value row(r);
        for (const auto& c : root._children) {
            detail::shred(c, row.as_object().if_contains(c._row_key), 0, columns);
        }
    }

    std::string out = "PAR1";
    struct chunk {
        std::int64_t _offset;
        std::int64_t _compressed;
        std::int64_t _uncompressed;
    };
    std::vector<chunk> chunks;
    std::int64_t total_uncompressed = 0;
    for (auto& c : columns) {
        if (c._bit_count > 0) {
            c._values.push_back(static_cast<char>(c._bit_byte));
            c._bit_count = 0;
        }
        std::string body;
        if (c._max_rep > 0) {
            const auto r = detail::rle(c._reps, detail::bit_width(c._max_rep));
            detail::put_u32_le(body, static_cast<std::uint32_t>(r.size()));
            body += r;
        }
        if (c._max_def > 0) {
            const auto d = detail::rle(c._defs, detail::bit_width(c._max_def));
            detail::put_u32_le(body, static_cast<std::uint32_t>(d.size()));
            body += d;
        }
        body += c._values;
        std::string page;
        if (codec_id == 1) {
            page = snappy::compress(body);
        } else if (codec_id == 6) {
#ifdef KYTHIRA_KINESIS_HAS_ZSTD
            page.resize(ZSTD_compressBound(body.size()));
            const auto n = ZSTD_compress(page.data(), page.size(), body.data(), body.size(), 3);
            if (ZSTD_isError(n) != 0U) {
                throw parquet_error("ZSTD failed to compress a Parquet page.");
            }
            page.resize(n);
#endif
        } else {
            page = body;
        }
        compact_writer h;
        h.field_i32(1, 0)  // DATA_PAGE
            .field_i32(2, static_cast<std::int32_t>(body.size()))
            .field_i32(3, static_cast<std::int32_t>(page.size()))
            .begin_struct(5)
            .field_i32(1, static_cast<std::int32_t>(c._defs.size()))
            .field_i32(2, 0)  // PLAIN
            .field_i32(3, 3)  // RLE
            .field_i32(4, 3)  // RLE
            .end_struct();
        const auto header = h.finish();
        const auto offset = static_cast<std::int64_t>(out.size());
        out += header;
        out += page;
        chunks.push_back(
            chunk{._offset = offset,
                  ._compressed = static_cast<std::int64_t>(header.size() + page.size()),
                  ._uncompressed = static_cast<std::int64_t>(header.size() + body.size())});
        total_uncompressed += chunks.back()._uncompressed;
    }

    compact_writer m;
    m.field_i32(1, 1);
    m.begin_list(2, compact_writer::t_struct, detail::count_nodes(root));
    detail::schema_elements(m, root, true);
    m.field_i64(3, static_cast<std::int64_t>(rows.size()));
    m.begin_list(4, compact_writer::t_struct, 1).begin_element();
    m.begin_list(1, compact_writer::t_struct, columns.size());
    for (std::size_t i = 0; i < columns.size(); ++i) {
        const auto& c = columns[i];
        m.begin_element().field_i64(2, chunks[i]._offset).begin_struct(3);
        m.field_i32(1, c._type);
        m.begin_list(2, compact_writer::t_i32, 2).element_i32(0).element_i32(3);
        m.begin_list(3, compact_writer::t_binary, c._path.size());
        for (const auto& p : c._path) {
            m.element_binary(p);
        }
        m.field_i32(4, codec_id)
            .field_i64(5, static_cast<std::int64_t>(c._defs.size()))
            .field_i64(6, chunks[i]._uncompressed)
            .field_i64(7, chunks[i]._compressed)
            .field_i64(9, chunks[i]._offset)
            .end_struct()
            .end_struct();
    }
    m.field_i64(2, total_uncompressed).field_i64(3, static_cast<std::int64_t>(rows.size()));
    m.end_struct();
    if (!metadata.empty()) {
        m.begin_list(5, compact_writer::t_struct, metadata.size());
        for (const auto& [k, v] : metadata) {
            m.begin_element().field_binary(1, k).field_binary(2, v).end_struct();
        }
    }
    m.field_binary(6, "kythira-kinesis-channel");
    const auto footer = m.finish();
    out += footer;
    detail::put_u32_le(out, static_cast<std::uint32_t>(footer.size()));
    out += "PAR1";
    return out;
}

}  // namespace kythira::kinesis::parquet
