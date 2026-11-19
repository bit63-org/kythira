// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file kinesis_iceberg.hpp
/// @brief Apache Iceberg table format pieces a channel append needs
///        (`.kiro/specs/kinesis-compatible-streams/` task 19, Requirement
///        18.3): reading table metadata, turning JSON records into rows of
///        the table's schema, partition transforms, and the Avro schemas and
///        records of data files, manifests and manifest lists (format
///        version 2), and the REST catalog's commit request.
///
/// What a channel writes, per batch:
///
/// 1. one Avro data file per partition the batch's rows fall in, under the
///    table's `location` + `data/`;
/// 2. one manifest listing those files as ADDED, its entries inheriting the
///    snapshot's sequence number;
/// 3. a manifest list holding that manifest and every manifest of the
///    parent snapshot;
/// 4. a commit (`add-snapshot`, `set-snapshot-ref main`) that requires
///    `main` still to be the parent, so of two writers only one wins and
///    the other rebuilds its manifest list on the new parent.
///
/// Column types: boolean, int, long, float, double, string, binary (base64
/// in JSON), date, time, timestamp, timestamptz, uuid, and struct and list
/// of those. decimal, fixed, map and the v3 types are refused with a reason
/// naming the column, which sets the channel to FAILED.
///
/// JSON forms: dates as `"2026-11-19"` or days since the epoch; times as
/// `"12:30:00.5"` or microseconds since midnight; timestamps as ISO 8601
/// (`timestamptz` takes `Z` or an offset, and reads a bare time as UTC;
/// `timestamp` refuses an offset) or milliseconds since the epoch. A
/// column missing from a record, or JSON null, is null; a required column
/// that is null, or a value of the wrong type, sends the record to the
/// dead-letter location. Record fields with no column are ignored.
///
/// Partition transforms: identity, year, month, day, hour, bucket[N],
/// truncate[W] and void, on top-level columns.

#include <kythira/kinesis/kinesis_avro.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kinesis::iceberg {

/// The table cannot be written by a channel (an unsupported column type or
/// transform, a format version other than 2): the channel is FAILED with
/// this message.
class table_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// One record does not fit the table: it goes to the dead-letter location
/// with this message.
class record_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

namespace detail {

[[nodiscard]] inline auto obj(const boost::json::value& v, std::string_view what)
    -> const boost::json::object& {
    if (!v.is_object()) {
        throw table_error("Iceberg " + std::string(what) + " is not an object.");
    }
    return v.as_object();
}

[[nodiscard]] inline auto int_of(const boost::json::object& o, std::string_view k) -> std::int64_t {
    const auto* v = o.if_contains(k);
    if (v == nullptr || !(v->is_int64() || v->is_uint64())) {
        throw table_error("Iceberg metadata has no integer '" + std::string(k) + "'.");
    }
    return v->to_number<std::int64_t>();
}

[[nodiscard]] inline auto str_of(const boost::json::object& o, std::string_view k) -> std::string {
    const auto* v = o.if_contains(k);
    if (v == nullptr || !v->is_string()) {
        throw table_error("Iceberg metadata has no string '" + std::string(k) + "'.");
    }
    return std::string(v->as_string());
}

/// Floor division, for days and hours before the epoch.
[[nodiscard]] inline auto floor_div(std::int64_t a, std::int64_t b) -> std::int64_t {
    const auto q = a / b;
    return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

}  // namespace detail

/// A table's current state, from a `LoadTableResult`'s `metadata`.
struct table_metadata {
    int _format_version = 0;
    std::string _uuid;
    /// `s3://bucket/path`, without a trailing slash.
    std::string _location;
    std::int64_t _last_sequence_number = 0;
    /// `last-updated-ms`: a catalog refuses a commit whose snapshot is older
    /// than the table's last change (Iceberg allows a minute of skew).
    std::int64_t _last_updated_ms = 0;
    std::optional<std::int64_t> _main_snapshot;
    /// The current schema (`current-schema-id`).
    boost::json::object _schema;
    std::int64_t _schema_id = 0;
    /// The default partition spec.
    boost::json::object _spec;
    std::int64_t _spec_id = 0;
    /// Every snapshot still in the metadata, as given.
    boost::json::array _snapshots;

    [[nodiscard]] auto snapshot(std::int64_t id) const -> const boost::json::object* {
        for (const auto& s : _snapshots) {
            if (s.is_object() && s.as_object().contains("snapshot-id") &&
                s.as_object().at("snapshot-id").to_number<std::int64_t>() == id) {
                return &s.as_object();
            }
        }
        return nullptr;
    }

    /// The snapshot whose summary carries `key` = `value`, if one is still
    /// in the metadata.
    [[nodiscard]] auto snapshot_with(std::string_view key, std::string_view value) const
        -> const boost::json::object* {
        for (const auto& s : _snapshots) {
            if (!s.is_object()) {
                continue;
            }
            const auto* summary = s.as_object().if_contains("summary");
            if (summary == nullptr || !summary->is_object()) {
                continue;
            }
            const auto* v = summary->as_object().if_contains(key);
            if (v != nullptr && v->is_string() && v->as_string() == value) {
                return &s.as_object();
            }
        }
        return nullptr;
    }

    /// The value of summary `key` in the first snapshot whose value starts
    /// with `prefix`, if any.
    [[nodiscard]] auto summary_with_prefix(std::string_view key, std::string_view prefix) const
        -> std::optional<std::string> {
        for (const auto& s : _snapshots) {
            if (!s.is_object()) {
                continue;
            }
            const auto* summary = s.as_object().if_contains("summary");
            if (summary == nullptr || !summary->is_object()) {
                continue;
            }
            const auto* v = summary->as_object().if_contains(key);
            if (v != nullptr && v->is_string() &&
                std::string_view(v->as_string()).starts_with(prefix)) {
                return std::string(v->as_string());
            }
        }
        return std::nullopt;
    }
};

[[nodiscard]] inline auto parse_metadata(const boost::json::value& v) -> table_metadata {
    namespace d = detail;
    const auto& m = d::obj(v, "table metadata");
    table_metadata t;
    t._format_version = static_cast<int>(d::int_of(m, "format-version"));
    if (t._format_version != 2) {
        throw table_error("Iceberg format version " + std::to_string(t._format_version) +
                          " is not supported; channels write format version 2 tables.");
    }
    t._uuid = d::str_of(m, "table-uuid");
    t._location = d::str_of(m, "location");
    while (t._location.ends_with('/')) {
        t._location.pop_back();
    }
    t._last_sequence_number = d::int_of(m, "last-sequence-number");
    if (const auto* u = m.if_contains("last-updated-ms"); u != nullptr && u->is_int64()) {
        t._last_updated_ms = u->as_int64();
    }
    t._schema_id = d::int_of(m, "current-schema-id");
    bool found = false;
    if (const auto* schemas = m.if_contains("schemas"); schemas != nullptr && schemas->is_array()) {
        for (const auto& s : schemas->as_array()) {
            if (s.is_object() && s.as_object().contains("schema-id") &&
                s.as_object().at("schema-id").to_number<std::int64_t>() == t._schema_id) {
                t._schema = s.as_object();
                found = true;
            }
        }
    }
    if (!found) {
        throw table_error("Iceberg metadata has no current schema.");
    }
    t._spec_id = d::int_of(m, "default-spec-id");
    found = false;
    if (const auto* specs = m.if_contains("partition-specs");
        specs != nullptr && specs->is_array()) {
        for (const auto& s : specs->as_array()) {
            if (s.is_object() && s.as_object().contains("spec-id") &&
                s.as_object().at("spec-id").to_number<std::int64_t>() == t._spec_id) {
                t._spec = s.as_object();
                found = true;
            }
        }
    }
    if (!found) {
        throw table_error("Iceberg metadata has no default partition spec.");
    }
    // `refs.main` when present; `current-snapshot-id` otherwise (-1 or null
    // is none).
    if (const auto* refs = m.if_contains("refs"); refs != nullptr && refs->is_object()) {
        if (const auto* main = refs->as_object().if_contains("main");
            main != nullptr && main->is_object()) {
            t._main_snapshot = d::int_of(main->as_object(), "snapshot-id");
        }
    }
    if (!t._main_snapshot) {
        if (const auto* c = m.if_contains("current-snapshot-id");
            c != nullptr && c->is_number() && c->to_number<std::int64_t>() >= 0) {
            t._main_snapshot = c->to_number<std::int64_t>();
        }
    }
    if (const auto* s = m.if_contains("snapshots"); s != nullptr && s->is_array()) {
        t._snapshots = s->as_array();
    }
    return t;
}

/// `s3://bucket/key` split; nullopt for any other scheme (`s3a`/`s3n` are
/// read as S3 too, as Iceberg's S3FileIO does).
[[nodiscard]] inline auto split_s3_uri(std::string_view uri)
    -> std::optional<std::pair<std::string, std::string>> {
    for (const std::string_view scheme : {"s3://", "s3a://", "s3n://"}) {
        if (uri.starts_with(scheme)) {
            uri.remove_prefix(scheme.size());
            const auto slash = uri.find('/');
            if (slash == 0) {
                return std::nullopt;
            }
            if (slash == std::string_view::npos) {
                return std::pair{std::string(uri), std::string()};
            }
            return std::pair{std::string(uri.substr(0, slash)), std::string(uri.substr(slash + 1))};
        }
    }
    return std::nullopt;
}

// ── schema to Avro ─────────────────────────────────────────────────────────

/// An Iceberg name made a valid Avro name, as Iceberg's Java writer does:
/// a leading digit gets a `_`, and any other character not allowed becomes
/// `_x` and its hex code. Readers match columns by field id, not name.
[[nodiscard]] inline auto avro_name(std::string_view name) -> std::string {
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
            char hex[8];
            (void)std::snprintf(hex, sizeof(hex), "_x%X", c);
            out += hex;
        }
    }
    return out.empty() ? std::string("_") : out;
}

namespace detail {

[[nodiscard]] inline auto primitive_name(const boost::json::value& type) -> std::string {
    return type.is_string() ? std::string(type.as_string()) : std::string();
}

[[nodiscard]] inline auto nullable(boost::json::value t, bool required) -> boost::json::value {
    if (required) {
        return t;
    }
    return boost::json::array{"null", std::move(t)};
}

// NOLINTNEXTLINE(misc-no-recursion): types nest.
[[nodiscard]] inline auto avro_type(const boost::json::value& type, std::string_view column)
    -> boost::json::value {
    const auto p = primitive_name(type);
    if (p == "boolean" || p == "int" || p == "long" || p == "float" || p == "double" ||
        p == "string") {
        return boost::json::value(p);
    }
    if (p == "binary") {
        return "bytes";
    }
    if (p == "date") {
        return boost::json::object{{"type", "int"}, {"logicalType", "date"}};
    }
    if (p == "time") {
        return boost::json::object{{"type", "long"}, {"logicalType", "time-micros"}};
    }
    if (p == "timestamp" || p == "timestamptz") {
        return boost::json::object{{"type", "long"},
                                   {"logicalType", "timestamp-micros"},
                                   {"adjust-to-utc", p == "timestamptz"}};
    }
    if (p == "uuid") {
        return boost::json::object{{"type", "fixed"},
                                   {"name", "uuid_" + avro_name(column)},
                                   {"size", 16},
                                   {"logicalType", "uuid"}};
    }
    if (type.is_object()) {
        const auto& o = type.as_object();
        const auto kind = str_of(o, "type");
        if (kind == "struct") {
            boost::json::array fields;
            std::int64_t first_id = 0;
            for (const auto& f : o.at("fields").as_array()) {
                const auto& field = f.as_object();
                const auto id = int_of(field, "id");
                if (first_id == 0) {
                    first_id = id;
                }
                const bool required = field.at("required").as_bool();
                boost::json::object af{
                    {"name", avro_name(str_of(field, "name"))},
                    {"type",
                     nullable(avro_type(field.at("type"), str_of(field, "name")), required)},
                    {"field-id", id}};
                if (!required) {
                    af["default"] = nullptr;
                }
                fields.push_back(std::move(af));
            }
            return boost::json::object{{"type", "record"},
                                       {"name", "r" + std::to_string(first_id)},
                                       {"fields", std::move(fields)}};
        }
        if (kind == "list") {
            const auto element_required = o.at("element-required").as_bool();
            return boost::json::object{
                {"type", "array"},
                {"items", nullable(avro_type(o.at("element"), column), element_required)},
                {"element-id", int_of(o, "element-id")}};
        }
    }
    throw table_error("Column '" + std::string(column) + "' has the type " +
                      boost::json::serialize(type) + ", which a Kythira channel cannot write yet.");
}

}  // namespace detail

/// The Avro schema of rows of `schema` (an Iceberg schema object); throws
/// `table_error` naming a column a channel cannot write.
[[nodiscard]] inline auto data_file_schema(const boost::json::object& schema)
    -> boost::json::value {
    boost::json::object as_struct{{"type", "struct"}, {"fields", schema.at("fields")}};
    auto record = detail::avro_type(as_struct, "");
    record.as_object()["name"] = "kythira_channel_row";
    return record;
}

/// Throws `table_error` naming the first column a channel cannot write.
inline auto check_columns(const boost::json::object& schema) -> void {
    (void)data_file_schema(schema);
}

// ── JSON records to rows ───────────────────────────────────────────────────

namespace detail {

[[nodiscard]] inline auto digits(std::string_view s, std::size_t at, std::size_t n)
    -> std::optional<std::int64_t> {
    if (at + n > s.size()) {
        return std::nullopt;
    }
    std::int64_t v = 0;
    for (std::size_t i = at; i < at + n; ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return std::nullopt;
        }
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

[[nodiscard]] inline auto days_of(std::string_view s) -> std::optional<std::int64_t> {
    if (s.size() < 10 || s[4] != '-' || s[7] != '-') {
        return std::nullopt;
    }
    const auto y = digits(s, 0, 4);
    const auto m = digits(s, 5, 2);
    const auto d = digits(s, 8, 2);
    if (!y || !m || !d) {
        return std::nullopt;
    }
    const std::chrono::year_month_day ymd{std::chrono::year{static_cast<int>(*y)},
                                          std::chrono::month{static_cast<unsigned>(*m)},
                                          std::chrono::day{static_cast<unsigned>(*d)}};
    if (!ymd.ok()) {
        return std::nullopt;
    }
    return std::chrono::sys_days{ymd}.time_since_epoch().count();
}

/// `HH:MM[:SS[.fraction]]` to microseconds; `used` gets the characters read.
[[nodiscard]] inline auto micros_of_time(std::string_view s, std::size_t& used)
    -> std::optional<std::int64_t> {
    const auto h = digits(s, 0, 2);
    const auto mi = digits(s, 3, 2);
    if (!h || !mi || s.size() < 5 || s[2] != ':' || *h > 23 || *mi > 59) {
        return std::nullopt;
    }
    std::int64_t sec = 0;
    std::int64_t frac = 0;
    used = 5;
    if (s.size() > 5 && s[5] == ':') {
        const auto se = digits(s, 6, 2);
        if (!se || *se > 60) {
            return std::nullopt;
        }
        sec = *se;
        used = 8;
        if (s.size() > 8 && s[8] == '.') {
            used = 9;
            std::int64_t scale = 100000;
            while (used < s.size() && s[used] >= '0' && s[used] <= '9') {
                frac += (s[used] - '0') * scale;
                scale /= 10;
                ++used;
            }
            if (used == 9) {
                return std::nullopt;
            }
        }
    }
    return ((*h * 60 + *mi) * 60 + sec) * 1'000'000 + frac;
}

/// ISO 8601 to microseconds since the epoch, UTC.
[[nodiscard]] inline auto micros_of_timestamp(std::string_view s, bool with_zone)
    -> std::optional<std::int64_t> {
    const auto days = days_of(s);
    if (!days || s.size() < 16 || (s[10] != 'T' && s[10] != ' ')) {
        return std::nullopt;
    }
    std::size_t used = 0;
    const auto t = micros_of_time(s.substr(11), used);
    if (!t) {
        return std::nullopt;
    }
    auto rest = s.substr(11 + used);
    std::int64_t offset_minutes = 0;
    if (!rest.empty()) {
        if (!with_zone) {
            return std::nullopt;
        }
        if (rest == "Z" || rest == "z") {
            rest = {};
        } else if ((rest[0] == '+' || rest[0] == '-') && rest.size() == 6 && rest[3] == ':') {
            const auto oh = digits(rest, 1, 2);
            const auto om = digits(rest, 4, 2);
            if (!oh || !om) {
                return std::nullopt;
            }
            offset_minutes = (*oh * 60 + *om) * (rest[0] == '-' ? -1 : 1);
        } else {
            return std::nullopt;
        }
    }
    return *days * 86'400'000'000 + *t - offset_minutes * 60'000'000;
}

[[nodiscard]] inline auto base64_decode(std::string_view in) -> std::optional<std::string> {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+' || c == '-') {
            return 62;
        }
        if (c == '/' || c == '_') {
            return 63;
        }
        return -1;
    };
    while (!in.empty() && in.back() == '=') {
        in.remove_suffix(1);
    }
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (const auto c : in) {
        const auto v = value(c);
        if (v < 0) {
            return std::nullopt;
        }
        acc = (acc << 6U) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> static_cast<unsigned>(bits)) & 0xFFU));
        }
    }
    return out;
}

[[nodiscard]] inline auto uuid_bytes(std::string_view s) -> std::optional<std::string> {
    std::string out;
    std::string hex;
    for (const auto c : s) {
        if (c != '-') {
            hex.push_back(c);
        }
    }
    if (hex.size() != 32 || s.size() != 36) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < 32; i += 2) {
        unsigned v = 0;
        for (std::size_t k = i; k < i + 2; ++k) {
            const auto c = hex[k];
            v <<= 4U;
            if (c >= '0' && c <= '9') {
                v |= static_cast<unsigned>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                v |= static_cast<unsigned>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                v |= static_cast<unsigned>(c - 'A' + 10);
            } else {
                return std::nullopt;
            }
        }
        out.push_back(static_cast<char>(v));
    }
    return out;
}

[[nodiscard]] inline auto bad(std::string_view column, std::string_view type,
                              const boost::json::value& v) -> record_error {
    return record_error("Column '" + std::string(column) + "' (" + std::string(type) +
                        ") cannot hold " + boost::json::serialize(v) + ".");
}

[[nodiscard]] inline auto integral(const boost::json::value& v) -> std::optional<std::int64_t> {
    if (v.is_int64()) {
        return v.as_int64();
    }
    if (v.is_uint64() && v.as_uint64() <= static_cast<std::uint64_t>(INT64_MAX)) {
        return static_cast<std::int64_t>(v.as_uint64());
    }
    if (v.is_double()) {
        const auto d = v.as_double();
        if (d == static_cast<double>(static_cast<std::int64_t>(d))) {
            return static_cast<std::int64_t>(d);
        }
    }
    return std::nullopt;
}

// NOLINTNEXTLINE(misc-no-recursion): types nest.
[[nodiscard]] inline auto convert(const boost::json::value& type, const boost::json::value& v,
                                  std::string_view column) -> boost::json::value {
    const auto p = primitive_name(type);
    if (p == "boolean") {
        if (!v.is_bool()) {
            throw bad(column, p, v);
        }
        return v;
    }
    if (p == "int" || p == "long") {
        const auto n = integral(v);
        if (!n || (p == "int" && (*n < INT32_MIN || *n > INT32_MAX))) {
            throw bad(column, p, v);
        }
        return *n;
    }
    if (p == "float" || p == "double") {
        if (!v.is_number()) {
            throw bad(column, p, v);
        }
        return v.to_number<double>();
    }
    if (p == "string") {
        if (!v.is_string()) {
            throw bad(column, p, v);
        }
        return v;
    }
    if (p == "binary") {
        if (!v.is_string()) {
            throw bad(column, p, v);
        }
        auto b = base64_decode(v.as_string());
        if (!b) {
            throw bad(column, p, v);
        }
        return boost::json::string(*b);
    }
    if (p == "date") {
        if (const auto n = integral(v); n && *n >= INT32_MIN && *n <= INT32_MAX) {
            return *n;
        }
        if (v.is_string()) {
            if (const auto d = days_of(v.as_string()); d && v.as_string().size() == 10) {
                return *d;
            }
        }
        throw bad(column, p, v);
    }
    if (p == "time") {
        if (const auto n = integral(v); n && *n >= 0 && *n < 86'400'000'000) {
            return *n;
        }
        if (v.is_string()) {
            std::size_t used = 0;
            if (const auto t = micros_of_time(v.as_string(), used);
                t && used == v.as_string().size()) {
                return *t;
            }
        }
        throw bad(column, p, v);
    }
    if (p == "timestamp" || p == "timestamptz") {
        if (const auto n = integral(v)) {
            return *n * 1000;  // milliseconds since the epoch
        }
        if (v.is_string()) {
            if (const auto t = micros_of_timestamp(v.as_string(), p == "timestamptz")) {
                return *t;
            }
        }
        throw bad(column, p, v);
    }
    if (p == "uuid") {
        if (v.is_string()) {
            if (auto b = uuid_bytes(v.as_string())) {
                return boost::json::string(*b);
            }
        }
        throw bad(column, p, v);
    }
    if (type.is_object()) {
        const auto& o = type.as_object();
        const auto kind = str_of(o, "type");
        if (kind == "struct") {
            if (!v.is_object()) {
                throw bad(column, "struct", v);
            }
            boost::json::object row;
            for (const auto& f : o.at("fields").as_array()) {
                const auto& field = f.as_object();
                const auto name = str_of(field, "name");
                const auto* fv = v.as_object().if_contains(name);
                const bool required = field.at("required").as_bool();
                const auto path = column.empty() ? name : std::string(column) + "." + name;
                if (fv == nullptr || fv->is_null()) {
                    if (required) {
                        throw record_error("Required column '" + path + "' is missing.");
                    }
                    row[avro_name(name)] = nullptr;
                } else {
                    row[avro_name(name)] = convert(field.at("type"), *fv, path);
                }
            }
            return row;
        }
        if (kind == "list") {
            if (!v.is_array()) {
                throw bad(column, "list", v);
            }
            const bool element_required = o.at("element-required").as_bool();
            boost::json::array out;
            for (const auto& e : v.as_array()) {
                if (e.is_null()) {
                    if (element_required) {
                        throw record_error("List '" + std::string(column) +
                                           "' cannot hold null elements.");
                    }
                    out.emplace_back(nullptr);
                } else {
                    out.push_back(convert(o.at("element"), e, column));
                }
            }
            return out;
        }
    }
    throw table_error("Column '" + std::string(column) + "' has an unsupported type.");
}

}  // namespace detail

/// A JSON record as a row of `schema`, ready for `data_file_schema`;
/// throws `record_error` when it does not fit.
[[nodiscard]] inline auto to_row(const boost::json::object& schema,
                                 const boost::json::value& record) -> boost::json::object {
    if (!record.is_object()) {
        throw record_error("The record is not a JSON object.");
    }
    const boost::json::object as_struct{{"type", "struct"}, {"fields", schema.at("fields")}};
    return detail::convert(as_struct, record, "").as_object();
}

// ── partition transforms ───────────────────────────────────────────────────

namespace detail {

[[nodiscard]] inline auto murmur3_32(std::string_view data) -> std::int32_t {
    constexpr std::uint32_t c1 = 0xcc9e2d51U;
    constexpr std::uint32_t c2 = 0x1b873593U;
    std::uint32_t h = 0;
    const auto n = data.size();
    std::size_t i = 0;
    auto rotl = [](std::uint32_t x, unsigned r) { return (x << r) | (x >> (32U - r)); };
    for (; i + 4 <= n; i += 4) {
        std::uint32_t k =
            static_cast<unsigned char>(data[i]) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 1])) << 8U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 2])) << 16U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 3])) << 24U);
        k *= c1;
        k = rotl(k, 15);
        k *= c2;
        h ^= k;
        h = rotl(h, 13);
        h = h * 5 + 0xe6546b64U;
    }
    std::uint32_t k = 0;
    switch (n & 3U) {
        case 3:
            k ^= static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 2])) << 16U;
            [[fallthrough]];
        case 2:
            k ^= static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 1])) << 8U;
            [[fallthrough]];
        case 1:
            k ^= static_cast<unsigned char>(data[i]);
            k *= c1;
            k = rotl(k, 15);
            k *= c2;
            h ^= k;
            break;
        default:
            break;
    }
    h ^= static_cast<std::uint32_t>(n);
    h ^= h >> 16U;
    h *= 0x85ebca6bU;
    h ^= h >> 13U;
    h *= 0xc2b2ae35U;
    h ^= h >> 16U;
    return static_cast<std::int32_t>(h);
}

[[nodiscard]] inline auto le64(std::int64_t v) -> std::string {
    std::string out(8, '\0');
    for (unsigned i = 0; i < 8; ++i) {
        out[i] = static_cast<char>((static_cast<std::uint64_t>(v) >> (8U * i)) & 0xFFU);
    }
    return out;
}

[[nodiscard]] inline auto le32(std::int32_t v) -> std::string {
    std::string out(4, '\0');
    for (unsigned i = 0; i < 4; ++i) {
        out[i] = static_cast<char>((static_cast<std::uint32_t>(v) >> (8U * i)) & 0xFFU);
    }
    return out;
}

[[nodiscard]] inline auto bracket_arg(std::string_view t, std::string_view name)
    -> std::optional<std::int64_t> {
    if (!t.starts_with(name) || t.size() < name.size() + 3 || t[name.size()] != '[' ||
        t.back() != ']') {
        return std::nullopt;
    }
    const auto inner = t.substr(name.size() + 1, t.size() - name.size() - 2);
    const auto v = digits(inner, 0, inner.size());
    if (!v || *v <= 0 || *v > INT32_MAX) {
        return std::nullopt;
    }
    return v;
}

/// Years, months or days from a date (days) or a timestamp (microseconds).
[[nodiscard]] inline auto date_part(std::string_view unit, std::string_view source_type,
                                    std::int64_t v) -> std::int64_t {
    const bool is_date = source_type == "date";
    const auto days = is_date ? v : floor_div(v, 86'400'000'000);
    if (unit == "day") {
        return days;
    }
    if (unit == "hour") {
        return is_date ? days * 24 : floor_div(v, 3'600'000'000);
    }
    const std::chrono::year_month_day ymd{std::chrono::sys_days{std::chrono::days{days}}};
    const auto years = static_cast<int>(ymd.year()) - 1970;
    if (unit == "year") {
        return years;
    }
    return std::int64_t{years} * 12 + static_cast<unsigned>(ymd.month()) - 1;
}

}  // namespace detail

/// One field of a partition spec, bound to its source column.
struct partition_field {
    std::int64_t _field_id = 0;
    std::string _name;
    std::string _transform;
    std::int64_t _source_id = 0;
    /// The source column's name and Iceberg type.
    std::string _source_name;
    boost::json::value _source_type;
    /// The partition value's Iceberg type.
    std::string _result_type;
};

/// The table's default spec, bound to its schema; throws `table_error` for
/// a transform or source a channel cannot apply.
[[nodiscard]] inline auto bind_spec(const table_metadata& t) -> std::vector<partition_field> {
    std::vector<partition_field> out;
    for (const auto& f : t._spec.at("fields").as_array()) {
        const auto& o = f.as_object();
        partition_field p;
        p._field_id = detail::int_of(o, "field-id");
        p._name = detail::str_of(o, "name");
        p._transform = detail::str_of(o, "transform");
        p._source_id = detail::int_of(o, "source-id");
        for (const auto& c : t._schema.at("fields").as_array()) {
            if (c.as_object().at("id").to_number<std::int64_t>() == p._source_id) {
                p._source_name = detail::str_of(c.as_object(), "name");
                p._source_type = c.as_object().at("type");
            }
        }
        if (p._source_name.empty()) {
            throw table_error("Partition field '" + p._name +
                              "' does not take a top-level column, which a Kythira channel "
                              "cannot partition by yet.");
        }
        const auto st = detail::primitive_name(p._source_type);
        const bool temporal = st == "date" || st == "timestamp" || st == "timestamptz";
        if (p._transform == "identity") {
            if (st.empty() || st == "float" || st == "double") {
                throw table_error("Partition field '" + p._name + "': identity on " +
                                  boost::json::serialize(p._source_type) + " is not supported.");
            }
            p._result_type = st;
        } else if (p._transform == "year" || p._transform == "month" || p._transform == "day") {
            if (!temporal) {
                throw table_error("Partition field '" + p._name + "': " + p._transform +
                                  " needs a date or timestamp column.");
            }
            p._result_type = p._transform == "day" ? "date" : "int";
        } else if (p._transform == "hour") {
            if (st != "timestamp" && st != "timestamptz") {
                throw table_error("Partition field '" + p._name +
                                  "': hour needs a timestamp column.");
            }
            p._result_type = "int";
        } else if (detail::bracket_arg(p._transform, "bucket")) {
            if (st.empty() || st == "boolean" || st == "float" || st == "double") {
                throw table_error("Partition field '" + p._name + "': bucket on " +
                                  boost::json::serialize(p._source_type) + " is not supported.");
            }
            p._result_type = "int";
        } else if (detail::bracket_arg(p._transform, "truncate")) {
            if (st != "int" && st != "long" && st != "string" && st != "binary") {
                throw table_error("Partition field '" + p._name +
                                  "': truncate needs an int, long, string or binary column.");
            }
            p._result_type = st;
        } else if (p._transform == "void") {
            p._result_type = st.empty() ? "int" : st;
        } else {
            throw table_error("Partition field '" + p._name + "' uses the transform '" +
                              p._transform + "', which a Kythira channel cannot apply.");
        }
        out.push_back(std::move(p));
    }
    return out;
}

/// The partition value of `row` (a converted row) for `f`, or null.
[[nodiscard]] inline auto partition_value(const partition_field& f, const boost::json::object& row)
    -> boost::json::value {
    const auto* v = row.if_contains(avro_name(f._source_name));
    if (v == nullptr || v->is_null() || f._transform == "void") {
        return nullptr;
    }
    const auto st = detail::primitive_name(f._source_type);
    if (f._transform == "identity") {
        return *v;
    }
    if (f._transform == "year" || f._transform == "month" || f._transform == "day" ||
        f._transform == "hour") {
        return detail::date_part(f._transform, st, v->as_int64());
    }
    if (const auto n = detail::bracket_arg(f._transform, "bucket")) {
        std::string bytes;
        if (st == "int" || st == "long" || st == "date" || st == "time" || st == "timestamp" ||
            st == "timestamptz") {
            bytes = detail::le64(v->as_int64());
        } else {
            // string (UTF-8), binary and uuid (big-endian bytes) hash as held.
            bytes = std::string(v->as_string());
        }
        const auto h = detail::murmur3_32(bytes) & INT32_MAX;
        return static_cast<std::int64_t>(h % *n);
    }
    if (const auto w = detail::bracket_arg(f._transform, "truncate")) {
        if (st == "int" || st == "long") {
            const auto x = v->as_int64();
            return x - (((x % *w) + *w) % *w);
        }
        const auto s = std::string_view(v->as_string());
        if (st == "binary") {
            return boost::json::string(s.substr(0, static_cast<std::size_t>(*w)));
        }
        // Code points, not bytes.
        std::size_t at = 0;
        for (std::int64_t k = 0; k < *w && at < s.size(); ++k) {
            ++at;
            while (at < s.size() && (static_cast<unsigned char>(s[at]) & 0xC0U) == 0x80U) {
                ++at;
            }
        }
        return boost::json::string(s.substr(0, at));
    }
    return nullptr;
}

[[nodiscard]] inline auto partition_avro_type(const partition_field& f) -> boost::json::value {
    if (f._result_type == "date") {
        return boost::json::object{{"type", "int"}, {"logicalType", "date"}};
    }
    if (f._transform == "identity") {
        return detail::avro_type(f._source_type, f._source_name);
    }
    return detail::avro_type(boost::json::value(f._result_type), f._name);
}

/// The `partition` record of a manifest entry for `spec`.
[[nodiscard]] inline auto partition_schema(const std::vector<partition_field>& spec)
    -> boost::json::value {
    boost::json::array fields;
    for (const auto& f : spec) {
        fields.push_back(
            boost::json::object{{"name", avro_name(f._name)},
                                {"type", detail::nullable(partition_avro_type(f), false)},
                                {"default", nullptr},
                                {"field-id", f._field_id}});
    }
    return boost::json::object{{"type", "record"}, {"name", "r102"}, {"fields", std::move(fields)}};
}

/// Iceberg's single-value binary form of a partition value, for manifest
/// list bounds; nullopt for a type it does not cover here.
[[nodiscard]] inline auto single_value(std::string_view type, const boost::json::value& v)
    -> std::optional<std::string> {
    if (type == "int" || type == "date") {
        return detail::le32(static_cast<std::int32_t>(v.as_int64()));
    }
    if (type == "long" || type == "time" || type == "timestamp" || type == "timestamptz") {
        return detail::le64(v.as_int64());
    }
    if (type == "boolean") {
        return std::string(1, v.as_bool() ? '\1' : '\0');
    }
    if (type == "string" || type == "binary" || type == "uuid") {
        return std::string(v.as_string());
    }
    return std::nullopt;
}

/// A path segment for a partition value: `name=value`, escaped.
[[nodiscard]] inline auto partition_path(const std::vector<partition_field>& spec,
                                         const boost::json::array& values) -> std::string {
    std::string out;
    for (std::size_t i = 0; i < spec.size(); ++i) {
        std::string text = "null";
        const auto& v = values[i];
        if (v.is_int64()) {
            text = std::to_string(v.as_int64());
        } else if (v.is_bool()) {
            text = v.as_bool() ? "true" : "false";
        } else if (v.is_string()) {
            text.clear();
            static constexpr std::string_view hex = "0123456789ABCDEF";
            for (const auto ch : v.as_string()) {
                const auto c = static_cast<unsigned char>(ch);
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '-' || c == '_' || c == '.') {
                    text.push_back(static_cast<char>(c));
                } else {
                    text.push_back('%');
                    text.push_back(hex[c >> 4U]);
                    text.push_back(hex[c & 15U]);
                }
            }
        }
        out += avro_name(spec[i]._name) + "=" + text + "/";
    }
    return out;
}

// ── manifests ──────────────────────────────────────────────────────────────

/// The v2 `manifest_entry` schema with `partition` as given.
[[nodiscard]] inline auto manifest_entry_schema(boost::json::value partition)
    -> boost::json::value {
    using boost::json::array;
    using boost::json::object;
    auto opt = [](boost::json::value t) { return array{"null", std::move(t)}; };
    object data_file{
        {"type", "record"},
        {"name", "r2"},
        {"fields",
         array{
             object{{"name", "content"}, {"type", "int"}, {"field-id", 134}},
             object{{"name", "file_path"}, {"type", "string"}, {"field-id", 100}},
             object{{"name", "file_format"}, {"type", "string"}, {"field-id", 101}},
             object{{"name", "partition"}, {"type", std::move(partition)}, {"field-id", 102}},
             object{{"name", "record_count"}, {"type", "long"}, {"field-id", 103}},
             object{{"name", "file_size_in_bytes"}, {"type", "long"}, {"field-id", 104}},
             object{{"name", "key_metadata"},
                    {"type", opt("bytes")},
                    {"default", nullptr},
                    {"field-id", 131}},
             object{
                 {"name", "split_offsets"},
                 {"type", opt(object{{"type", "array"}, {"items", "long"}, {"element-id", 133}})},
                 {"default", nullptr},
                 {"field-id", 132}},
             object{{"name", "sort_order_id"},
                    {"type", opt("int")},
                    {"default", nullptr},
                    {"field-id", 140}},
         }}};
    return object{
        {"type", "record"},
        {"name", "manifest_entry"},
        {"fields",
         array{
             object{{"name", "status"}, {"type", "int"}, {"field-id", 0}},
             object{{"name", "snapshot_id"},
                    {"type", opt("long")},
                    {"default", nullptr},
                    {"field-id", 1}},
             object{{"name", "sequence_number"},
                    {"type", opt("long")},
                    {"default", nullptr},
                    {"field-id", 3}},
             object{{"name", "file_sequence_number"},
                    {"type", opt("long")},
                    {"default", nullptr},
                    {"field-id", 4}},
             object{{"name", "data_file"}, {"type", std::move(data_file)}, {"field-id", 2}},
         }}};
}

/// The v2 `manifest_file` schema of a manifest list.
[[nodiscard]] inline auto manifest_list_schema() -> boost::json::value {
    using boost::json::array;
    using boost::json::object;
    auto opt = [](boost::json::value t) { return array{"null", std::move(t)}; };
    object summary{
        {"type", "record"},
        {"name", "r508"},
        {"fields", array{
                       object{{"name", "contains_null"}, {"type", "boolean"}, {"field-id", 509}},
                       object{{"name", "contains_nan"},
                              {"type", opt("boolean")},
                              {"default", nullptr},
                              {"field-id", 518}},
                       object{{"name", "lower_bound"},
                              {"type", opt("bytes")},
                              {"default", nullptr},
                              {"field-id", 510}},
                       object{{"name", "upper_bound"},
                              {"type", opt("bytes")},
                              {"default", nullptr},
                              {"field-id", 511}},
                   }}};
    return object{
        {"type", "record"},
        {"name", "manifest_file"},
        {"fields", array{
                       object{{"name", "manifest_path"}, {"type", "string"}, {"field-id", 500}},
                       object{{"name", "manifest_length"}, {"type", "long"}, {"field-id", 501}},
                       object{{"name", "partition_spec_id"}, {"type", "int"}, {"field-id", 502}},
                       object{{"name", "content"}, {"type", "int"}, {"field-id", 517}},
                       object{{"name", "sequence_number"}, {"type", "long"}, {"field-id", 515}},
                       object{{"name", "min_sequence_number"}, {"type", "long"}, {"field-id", 516}},
                       object{{"name", "added_snapshot_id"}, {"type", "long"}, {"field-id", 503}},
                       object{{"name", "added_files_count"}, {"type", "int"}, {"field-id", 504}},
                       object{{"name", "existing_files_count"}, {"type", "int"}, {"field-id", 505}},
                       object{{"name", "deleted_files_count"}, {"type", "int"}, {"field-id", 506}},
                       object{{"name", "added_rows_count"}, {"type", "long"}, {"field-id", 512}},
                       object{{"name", "existing_rows_count"}, {"type", "long"}, {"field-id", 513}},
                       object{{"name", "deleted_rows_count"}, {"type", "long"}, {"field-id", 514}},
                       object{{"name", "partitions"},
                              {"type", opt(object{{"type", "array"},
                                                  {"items", std::move(summary)},
                                                  {"element-id", 508}})},
                              {"default", nullptr},
                              {"field-id", 507}},
                       object{{"name", "key_metadata"},
                              {"type", opt("bytes")},
                              {"default", nullptr},
                              {"field-id", 519}},
                   }}};
}

/// One data file a batch wrote.
struct data_file {
    std::string _path;
    boost::json::array _partition;
    std::int64_t _records = 0;
    std::int64_t _bytes = 0;
};

/// A manifest of `files`, all ADDED by `snapshot_id`, their sequence
/// numbers inherited from the snapshot that commits it.
[[nodiscard]] inline auto write_manifest(const table_metadata& t,
                                         const std::vector<partition_field>& spec,
                                         const std::vector<data_file>& files,
                                         std::int64_t snapshot_id, std::string_view seed)
    -> std::string {
    boost::json::array spec_fields;
    for (const auto& f : t._spec.at("fields").as_array()) {
        spec_fields.push_back(f);
    }
    const auto schema = manifest_entry_schema(partition_schema(spec));
    avro::file_writer w(schema, "deflate",
                        {{"schema", boost::json::serialize(t._schema)},
                         {"schema-id", std::to_string(t._schema_id)},
                         {"partition-spec", boost::json::serialize(spec_fields)},
                         {"partition-spec-id", std::to_string(t._spec_id)},
                         {"format-version", "2"},
                         {"content", "data"}},
                        seed);
    for (const auto& f : files) {
        boost::json::object partition;
        for (std::size_t i = 0; i < spec.size(); ++i) {
            partition[avro_name(spec[i]._name)] = f._partition[i];
        }
        w.append(boost::json::object{
            {"status", 1},
            {"snapshot_id", snapshot_id},
            {"sequence_number", nullptr},
            {"file_sequence_number", nullptr},
            {"data_file", boost::json::object{{"content", 0},
                                              {"file_path", f._path},
                                              {"file_format", "PARQUET"},
                                              {"partition", std::move(partition)},
                                              {"record_count", f._records},
                                              {"file_size_in_bytes", f._bytes},
                                              {"key_metadata", nullptr},
                                              {"split_offsets", nullptr},
                                              {"sort_order_id", nullptr}}}});
    }
    return w.finish();
}

/// The manifest list entry for a manifest of `files` added at `sequence`.
[[nodiscard]] inline auto manifest_list_entry(const std::vector<partition_field>& spec,
                                              const std::vector<data_file>& files, std::string path,
                                              std::int64_t length, std::int64_t spec_id,
                                              std::int64_t snapshot_id, std::int64_t sequence)
    -> boost::json::object {
    std::int64_t rows = 0;
    for (const auto& f : files) {
        rows += f._records;
    }
    boost::json::array summaries;
    for (std::size_t i = 0; i < spec.size(); ++i) {
        bool has_null = false;
        std::optional<boost::json::value> lo;
        std::optional<boost::json::value> hi;
        auto less = [](const boost::json::value& a, const boost::json::value& b) {
            if (a.is_int64()) {
                return a.as_int64() < b.as_int64();
            }
            if (a.is_string()) {
                return std::string_view(a.as_string()) < std::string_view(b.as_string());
            }
            return !a.as_bool() && b.as_bool();
        };
        for (const auto& f : files) {
            const auto& v = f._partition[i];
            if (v.is_null()) {
                has_null = true;
                continue;
            }
            if (!lo || less(v, *lo)) {
                lo = v;
            }
            if (!hi || less(*hi, v)) {
                hi = v;
            }
        }
        const auto& type = spec[i]._result_type;
        boost::json::object s{{"contains_null", has_null},
                              {"contains_nan", false},
                              {"lower_bound", nullptr},
                              {"upper_bound", nullptr}};
        if (lo) {
            if (auto b = single_value(type, *lo)) {
                s["lower_bound"] = boost::json::string(*b);
            }
            if (auto b = single_value(type, *hi)) {
                s["upper_bound"] = boost::json::string(*b);
            }
        }
        summaries.push_back(std::move(s));
    }
    return boost::json::object{{"manifest_path", std::move(path)},
                               {"manifest_length", length},
                               {"partition_spec_id", spec_id},
                               {"content", 0},
                               {"sequence_number", sequence},
                               {"min_sequence_number", sequence},
                               {"added_snapshot_id", snapshot_id},
                               {"added_files_count", static_cast<std::int64_t>(files.size())},
                               {"existing_files_count", 0},
                               {"deleted_files_count", 0},
                               {"added_rows_count", rows},
                               {"existing_rows_count", 0},
                               {"deleted_rows_count", 0},
                               {"partitions", std::move(summaries)},
                               {"key_metadata", nullptr}};
}

/// A manifest list: `first`, then the parent's entries as they were.
[[nodiscard]] inline auto write_manifest_list(const boost::json::object& first,
                                              const std::vector<boost::json::value>& parent,
                                              std::int64_t snapshot_id,
                                              std::optional<std::int64_t> parent_id,
                                              std::int64_t sequence, std::string_view seed)
    -> std::string {
    avro::file_writer w(manifest_list_schema(), "deflate",
                        {{"snapshot-id", std::to_string(snapshot_id)},
                         {"parent-snapshot-id", parent_id ? std::to_string(*parent_id) : "null"},
                         {"sequence-number", std::to_string(sequence)},
                         {"format-version", "2"}},
                        seed);
    w.append(first);
    for (const auto& e : parent) {
        w.append(e);
    }
    return w.finish();
}

/// Normalizes a parent manifest list entry to the v2 schema (a writer may
/// use v1 names such as `added_data_files_count`, or leave optional fields
/// out); throws `table_error` when it lacks what v2 requires.
[[nodiscard]] inline auto normalize_list_entry(const boost::json::value& v) -> boost::json::value {
    const auto& o = detail::obj(v, "manifest list entry");
    boost::json::object out;
    auto pick = [&](std::initializer_list<std::string_view> names) -> boost::json::value {
        for (const auto n : names) {
            if (const auto* x = o.if_contains(n)) {
                return *x;
            }
        }
        return nullptr;
    };
    out["manifest_path"] = pick({"manifest_path"});
    out["manifest_length"] = pick({"manifest_length"});
    out["partition_spec_id"] = pick({"partition_spec_id"});
    auto content = pick({"content"});
    out["content"] = content.is_null() ? boost::json::value(0) : content;
    out["sequence_number"] = pick({"sequence_number"});
    out["min_sequence_number"] = pick({"min_sequence_number"});
    out["added_snapshot_id"] = pick({"added_snapshot_id"});
    out["added_files_count"] = pick({"added_files_count", "added_data_files_count"});
    out["existing_files_count"] = pick({"existing_files_count", "existing_data_files_count"});
    out["deleted_files_count"] = pick({"deleted_files_count", "deleted_data_files_count"});
    out["added_rows_count"] = pick({"added_rows_count"});
    out["existing_rows_count"] = pick({"existing_rows_count"});
    out["deleted_rows_count"] = pick({"deleted_rows_count"});
    out["partitions"] = pick({"partitions"});
    out["key_metadata"] = pick({"key_metadata"});
    for (const auto* k :
         {"manifest_path", "manifest_length", "partition_spec_id", "sequence_number",
          "min_sequence_number", "added_snapshot_id", "added_files_count", "existing_files_count",
          "deleted_files_count", "added_rows_count", "existing_rows_count", "deleted_rows_count"}) {
        if (out[k].is_null()) {
            throw table_error(std::string("A manifest list entry of the parent snapshot has no ") +
                              k + "; only format version 2 manifest lists can be appended to.");
        }
    }
    return out;
}

/// The REST catalog's `CommitTableRequest` adding `snapshot` on top of the
/// table's `main` as `t` saw it.
[[nodiscard]] inline auto commit_request(const table_metadata& t, std::string_view ns,
                                         std::string_view table, boost::json::object snapshot)
    -> boost::json::object {
    const auto id = snapshot.at("snapshot-id");
    boost::json::object ref_req{{"type", "assert-ref-snapshot-id"}, {"ref", "main"}};
    ref_req["snapshot-id"] =
        t._main_snapshot ? boost::json::value(*t._main_snapshot) : boost::json::value(nullptr);
    return boost::json::object{
        {"identifier", boost::json::object{{"namespace", boost::json::array{ns}}, {"name", table}}},
        {"requirements",
         boost::json::array{boost::json::object{{"type", "assert-table-uuid"}, {"uuid", t._uuid}},
                            std::move(ref_req)}},
        {"updates", boost::json::array{boost::json::object{{"action", "add-snapshot"},
                                                           {"snapshot", std::move(snapshot)}},
                                       boost::json::object{{"action", "set-snapshot-ref"},
                                                           {"ref-name", "main"},
                                                           {"type", "branch"},
                                                           {"snapshot-id", id}}}}};
}

}  // namespace kythira::kinesis::iceberg
