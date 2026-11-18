// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_query.hpp
/// @brief SNS's query-protocol inputs, read from a decoded form
///        (`.kiro/specs/sns-compatible-notifications/` Requirement 3.1).
///
/// Core's `aws_query::form` decodes the body and reads `Name.member.N`
/// lists. SNS adds three shapes the wire evidence (tests/evidence/) shows
/// every client sending:
///
///   maps         `Attributes.entry.N.key` / `.value` (topic and
///                subscription attributes)
///   attributes   `MessageAttributes.entry.N.Name` / `.Value.DataType` /
///                `.Value.StringValue` / `.Value.BinaryValue` (base64)
///   batches      `PublishBatchRequestEntries.member.N.<Field>`, each entry
///                a parameter set of its own, with its own maps inside
///
/// So that a batch entry is read with the same functions as a whole
/// request, everything here works on a `params` view: a parameter map and
/// a prefix. Clients order parameters differently (the Go SDK sorts them),
/// so nothing depends on order, and indexes need not be dense: N is a
/// position, entries come back sorted by it, and a gap is not an error, as
/// on SNS. An index that is not a positive number, a field the shape does
/// not have, or one of a pair missing is `InvalidParameter`.

#include <kythira/sns/sns_errors.hpp>

#include <raft/aws_query_protocol.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::sns {

using param_map = std::map<std::string, std::string, std::less<>>;

/// A result or the error to answer with. (Not std::expected, which the
/// clang 18 static-analysis toolchain lacks.)
template<typename T> class query_result {
public:
    query_result(T v) : _v(std::move(v)) {}          // NOLINT(google-explicit-constructor)
    query_result(sns_error e) : _v(std::move(e)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const -> bool { return _v.index() == 0; }
    explicit operator bool() const { return has_value(); }
    [[nodiscard]] auto value() -> T& { return std::get<0>(_v); }
    [[nodiscard]] auto value() const -> const T& { return std::get<0>(_v); }
    [[nodiscard]] auto operator*() -> T& { return value(); }
    [[nodiscard]] auto operator*() const -> const T& { return value(); }
    [[nodiscard]] auto operator->() -> T* { return &value(); }
    [[nodiscard]] auto operator->() const -> const T* { return &value(); }
    [[nodiscard]] auto error() const -> const sns_error& { return std::get<1>(_v); }

private:
    std::variant<T, sns_error> _v;
};

/// One message attribute (`MessageAttributeValue`).
struct message_attribute {
    std::string _data_type;
    std::optional<std::string> _string_value;
    std::optional<std::string> _binary_value;  ///< decoded bytes

    friend auto operator==(const message_attribute&, const message_attribute&) -> bool = default;
};

using message_attributes = std::map<std::string, message_attribute, std::less<>>;
using tag_list = std::vector<std::pair<std::string, std::string>>;

namespace query_detail {

[[nodiscard]] inline auto parse_position(std::string_view s) -> std::optional<std::size_t> {
    if (s.empty() || s.front() == '0') {
        return std::nullopt;
    }
    std::size_t n = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
    if (ec != std::errc{} || p != s.data() + s.size()) {
        return std::nullopt;
    }
    return n;
}

[[nodiscard]] inline auto b64_value(char c) -> int {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

}  // namespace query_detail

/// Standard base64 (RFC 4648 section 4) with padding, as the SDKs send
/// `BinaryValue`. Empty for anything else.
[[nodiscard]] inline auto base64_decode(std::string_view in) -> std::optional<std::string> {
    if (in.size() % 4 != 0) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        std::uint32_t acc = 0;
        int pad = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char c = in[i + j];
            if (c == '=') {
                // Padding only in the last group's last two places.
                if (i + 4 != in.size() || j < 2) {
                    return std::nullopt;
                }
                ++pad;
                acc <<= 6U;
                continue;
            }
            const int v = query_detail::b64_value(c);
            if (v < 0 || pad > 0) {
                return std::nullopt;
            }
            acc = (acc << 6U) | static_cast<std::uint32_t>(v);
        }
        out.push_back(static_cast<char>((acc >> 16U) & 0xFFU));
        if (pad < 2) {
            out.push_back(static_cast<char>((acc >> 8U) & 0xFFU));
        }
        if (pad < 1) {
            out.push_back(static_cast<char>(acc & 0xFFU));
        }
    }
    return out;
}

[[nodiscard]] inline auto base64_encode(std::string_view in) -> std::string {
    static constexpr std::string_view k =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < in.size(); i += 3) {
        std::uint32_t acc = static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16U;
        if (i + 1 < in.size()) {
            acc |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8U;
        }
        if (i + 2 < in.size()) {
            acc |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 2]));
        }
        out.push_back(k[(acc >> 18U) & 0x3FU]);
        out.push_back(k[(acc >> 12U) & 0x3FU]);
        out.push_back(i + 1 < in.size() ? k[(acc >> 6U) & 0x3FU] : '=');
        out.push_back(i + 2 < in.size() ? k[acc & 0x3FU] : '=');
    }
    return out;
}

/// A request's parameters, or one batch entry's: the map and the prefix
/// every name is read under.
class params {
public:
    explicit params(const param_map& all, std::string prefix = {})
        : _all(&all), _prefix(std::move(prefix)) {}

    [[nodiscard]] auto get(std::string_view name) const -> std::optional<std::string_view> {
        const auto it = _all->find(_prefix + std::string(name));
        if (it == _all->end()) {
            return std::nullopt;
        }
        return std::string_view(it->second);
    }

    [[nodiscard]] auto contains(std::string_view name) const -> bool {
        return get(name).has_value();
    }

    /// A required parameter: absent or empty is `InvalidParameter`.
    [[nodiscard]] auto required(std::string_view name) const -> query_result<std::string_view> {
        const auto v = get(name);
        if (!v || v->empty()) {
            return invalid_parameter(name);
        }
        return *v;
    }

    /// The parameters named `<name>.<field>`, with `<field>` (everything
    /// after the dot) as key.
    [[nodiscard]] auto under(std::string_view name) const
        -> std::vector<std::pair<std::string_view, std::string_view>> {
        const auto lead = _prefix + std::string(name) + ".";
        std::vector<std::pair<std::string_view, std::string_view>> out;
        for (auto it = _all->lower_bound(lead); it != _all->end() && it->first.starts_with(lead);
             ++it) {
            out.emplace_back(std::string_view(it->first).substr(lead.size()), it->second);
        }
        return out;
    }

    /// The entries of `<name>.<list>.N.<field>`, by position N, each a
    /// field-to-value map. `fields` empty accepts any field (a batch entry,
    /// whose fields are themselves structured).
    [[nodiscard]] auto structs(std::string_view name, std::string_view list,
                               const std::set<std::string, std::less<>>& fields) const
        -> query_result<std::map<std::size_t, param_map>> {
        std::map<std::size_t, param_map> out;
        const std::string lead = std::string(list) + ".";
        for (const auto& [rest, value] : under(name)) {
            if (!rest.starts_with(lead)) {
                return invalid_parameter(name);
            }
            const auto tail = rest.substr(lead.size());
            const auto dot = tail.find('.');
            if (dot == std::string_view::npos) {
                return invalid_parameter(name);
            }
            const auto pos = query_detail::parse_position(tail.substr(0, dot));
            const auto field = tail.substr(dot + 1);
            if (!pos || field.empty() || (!fields.empty() && !fields.contains(field))) {
                return invalid_parameter(name);
            }
            out[*pos].emplace(std::string(field), std::string(value));
        }
        return out;
    }

    /// `<name>.member.N` values in position order.
    [[nodiscard]] auto list(std::string_view name) const -> query_result<std::vector<std::string>> {
        std::map<std::size_t, std::string> by_pos;
        for (const auto& [rest, value] : under(name)) {
            if (!rest.starts_with("member.")) {
                return invalid_parameter(name);
            }
            const auto pos = query_detail::parse_position(rest.substr(7));
            if (!pos) {
                return invalid_parameter(name);
            }
            by_pos.emplace(*pos, std::string(value));
        }
        std::vector<std::string> out;
        out.reserve(by_pos.size());
        for (auto& [_, v] : by_pos) {
            out.push_back(std::move(v));
        }
        return out;
    }

    /// A string-to-string map (`Attributes.entry.N.key/value`). A key given
    /// twice is `InvalidParameter`.
    [[nodiscard]] auto string_map(std::string_view name) const -> query_result<param_map> {
        static const std::set<std::string, std::less<>> fields{"key", "value"};
        auto entries = structs(name, "entry", fields);
        if (!entries) {
            return entries.error();
        }
        param_map out;
        for (auto& [_, e] : *entries) {
            const auto k = e.find("key");
            if (k == e.end() || k->second.empty()) {
                return invalid_parameter(name, "Attribute name is required");
            }
            const auto v = e.find("value");
            if (!out.emplace(k->second, v == e.end() ? std::string() : v->second).second) {
                return invalid_parameter(name, "Duplicate attribute name " + k->second);
            }
        }
        return out;
    }

    /// `Tags.member.N.Key/Value`, in position order. Validation of keys and
    /// values (lengths, `aws:` prefix) is the tagging handler's.
    [[nodiscard]] auto tags(std::string_view name = "Tags") const -> query_result<tag_list> {
        static const std::set<std::string, std::less<>> fields{"Key", "Value"};
        auto entries = structs(name, "member", fields);
        if (!entries) {
            return entries.error();
        }
        tag_list out;
        for (auto& [_, e] : *entries) {
            const auto k = e.find("Key");
            if (k == e.end()) {
                return invalid_parameter(name, "Tag key is required");
            }
            const auto v = e.find("Value");
            out.emplace_back(k->second, v == e.end() ? std::string() : v->second);
        }
        return out;
    }

    /// `MessageAttributes.entry.N.Name` and `.Value.{DataType, StringValue,
    /// BinaryValue}`. Checked here: a name and a data type are present, the
    /// data type is String, Number or Binary (with an optional `.custom`
    /// suffix), and the value matches it (binary types carry valid base64,
    /// the others a string). SNS's further checks (name characters, sizes)
    /// are the publish handler's.
    [[nodiscard]] auto message_attrs(std::string_view name = "MessageAttributes") const
        -> query_result<message_attributes> {
        static const std::set<std::string, std::less<>> fields{
            "Name", "Value.DataType", "Value.StringValue", "Value.BinaryValue"};
        auto entries = structs(name, "entry", fields);
        if (!entries) {
            return entries.error();
        }
        message_attributes out;
        for (auto& [_, e] : *entries) {
            const auto n = e.find("Name");
            if (n == e.end() || n->second.empty()) {
                return invalid_parameter(name, "Message attribute name is required");
            }
            const auto t = e.find("Value.DataType");
            if (t == e.end() || t->second.empty()) {
                return invalid_parameter_value("The message attribute '" + n->second +
                                               "' must contain non-empty message attribute type.");
            }
            message_attribute a;
            a._data_type = t->second;
            const auto base = std::string_view(a._data_type).substr(0, a._data_type.find('.'));
            const auto s = e.find("Value.StringValue");
            const auto b = e.find("Value.BinaryValue");
            if (base == "Binary") {
                if (b == e.end() || s != e.end()) {
                    return invalid_parameter_value("The message attribute '" + n->second +
                                                   "' with type 'Binary' must use field 'Binary'.");
                }
                auto bytes = base64_decode(b->second);
                if (!bytes) {
                    return invalid_parameter_value("The message attribute '" + n->second +
                                                   "' has an invalid binary value.");
                }
                a._binary_value = std::move(*bytes);
            } else if (base == "String" || base == "Number") {
                if (s == e.end() || b != e.end()) {
                    return invalid_parameter_value("The message attribute '" + n->second +
                                                   "' with type '" + std::string(base) +
                                                   "' must use field 'String'.");
                }
                a._string_value = s->second;
            } else {
                return invalid_parameter_value("The message attribute '" + n->second +
                                               "' has an invalid message attribute type, the set "
                                               "of supported type prefixes is Binary, Number, "
                                               "and String.");
            }
            if (!out.emplace(n->second, std::move(a)).second) {
                return invalid_parameter(name, "Duplicate message attribute name " + n->second);
            }
        }
        return out;
    }

    /// The entries of a batch (`<name>.member.N.*`), each a `params` view
    /// over the same map, in position order. Checks SNS's batch rules in
    /// its order: no entries is EmptyBatchRequest, more than `max_entries`
    /// TooManyEntriesInBatchRequest, an `Id` missing or not 1-80
    /// alphanumerics, hyphens and underscores InvalidBatchEntryId, and two
    /// entries with one Id BatchEntryIdsNotDistinct.
    [[nodiscard]] auto batch(std::string_view name, std::size_t max_entries) const
        -> query_result<std::vector<params>> {
        std::set<std::size_t> positions;
        const std::string lead = "member.";
        for (const auto& [rest, _] : under(name)) {
            const auto dot = rest.find('.', lead.size());
            const auto pos =
                rest.starts_with(lead) && dot != std::string_view::npos
                    ? query_detail::parse_position(rest.substr(lead.size(), dot - lead.size()))
                    : std::nullopt;
            if (!pos) {
                return invalid_parameter(name);
            }
            positions.insert(*pos);
        }
        if (positions.empty()) {
            return model_error("EmptyBatchRequestException",
                               "The batch request doesn't contain any entries.");
        }
        if (positions.size() > max_entries) {
            return model_error("TooManyEntriesInBatchRequestException",
                               "The batch request contains more entries than permissible.");
        }
        std::vector<params> out;
        std::set<std::string, std::less<>> ids;
        for (const auto p : positions) {
            params entry(*_all, _prefix + std::string(name) + ".member." + std::to_string(p) + ".");
            const auto id = entry.get("Id");
            if (!id || !valid_batch_id(*id)) {
                return model_error("InvalidBatchEntryIdException",
                                   "The Id of a batch entry in a batch request doesn't abide by "
                                   "the specification.");
            }
            if (!ids.emplace(*id).second) {
                return model_error("BatchEntryIdsNotDistinctException",
                                   "Two or more batch entries in the request have the same Id.");
            }
            out.push_back(std::move(entry));
        }
        return out;
    }

    [[nodiscard]] auto prefix() const -> const std::string& { return _prefix; }

private:
    const param_map* _all;
    std::string _prefix;

    [[nodiscard]] static auto valid_batch_id(std::string_view id) -> bool {
        return !id.empty() && id.size() <= 80 &&
               std::all_of(id.begin(), id.end(), [](unsigned char c) {
                   return std::isalnum(c) != 0 || c == '-' || c == '_';
               });
    }
};

}  // namespace kythira::sns
