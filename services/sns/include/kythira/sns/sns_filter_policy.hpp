// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_filter_policy.hpp
/// @brief Subscription filter policies (`.kiro/specs/sns-compatible-notifications/`
///        task 5, Requirement 6.2).
///
/// A subscription's `FilterPolicy` decides which messages reach it. With
/// `FilterPolicyScope` `MessageAttributes` (the default) the policy's keys
/// name message attributes; with `MessageBody` the body is parsed as JSON
/// and the policy may nest objects to reach inside it. Within a policy:
///
/// - every key must match (AND), and a key matches when any one of its
///   conditions does (OR);
/// - `"$or": [{...}, {...}]` matches when any branch does, at any level;
/// - a value that is an array (a `String.Array` attribute, or a JSON array
///   in the body) matches when any of its elements does.
///
/// Conditions are a string, number, boolean or `null` to match exactly,
/// or one of the operators `prefix`, `suffix`, `equals-ignore-case`,
/// `wildcard`, `anything-but` (values, or a `prefix`/`suffix`), `numeric`
/// (one comparison, or a lower then an upper bound), `exists` and `cidr`.
///
/// Typing follows SNS: a `Number` attribute matches numeric conditions
/// only, a `String` attribute string conditions only, and a `Binary`
/// attribute is ignored, as if absent. `anything-but` needs the key to be
/// present. Numbers compare to SNS's five decimal places.
///
/// `parse` checks the grammar and SNS's limits (five keys on any path
/// through `$or`, 150 combinations, 256 KiB) and answers the
/// `InvalidParameter` SNS answers. The reason strings follow SNS's where
/// they are known; task 12's recordings settle the rest.

#include <kythira/sns/sns_errors.hpp>
#include <kythira/sns/sns_message.hpp>
#include <kythira/sns/sns_query.hpp>

#include <boost/json.hpp>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sns {

enum class filter_scope : std::uint8_t {
    message_attributes,
    message_body
};

/// The scope a subscription's `FilterPolicyScope` names; anything but
/// `MessageBody` is the default, `MessageAttributes`.
[[nodiscard]] inline auto parse_filter_scope(std::string_view s) -> filter_scope {
    return s == "MessageBody" ? filter_scope::message_body : filter_scope::message_attributes;
}

inline constexpr std::size_t k_max_filter_policy_bytes = 256 * 1024;
inline constexpr std::size_t k_max_filter_policy_keys = 5;
inline constexpr std::size_t k_max_filter_policy_combinations = 150;
/// Numbers in a policy lie within plus or minus one billion.
inline constexpr double k_max_filter_number = 1e9;

namespace filter_detail {

enum class numeric_op : std::uint8_t {
    eq,
    lt,
    le,
    gt,
    ge
};

struct ip_range {
    int _family = AF_INET;
    std::array<unsigned char, 16> _net{};
    unsigned _bits = 0;
};

enum class kind : std::uint8_t {
    string_value,
    number_value,
    boolean_value,
    null_value,
    prefix,
    suffix,
    equals_ignore_case,
    wildcard,
    anything_but,
    numeric,
    exists,
    cidr,
};

enum class but : std::uint8_t {
    values,
    prefix,
    suffix
};

struct condition {
    kind _kind = kind::null_value;
    std::string _text{};
    double _number = 0;
    bool _flag = false;
    std::vector<std::pair<numeric_op, double>> _range{};
    but _but = but::values;
    std::vector<std::string> _strings{};
    std::vector<double> _numbers{};
    ip_range _ip{};
};

struct field {
    /// The attribute name, or the keys down into the body.
    std::vector<std::string> _path{};
    std::vector<condition> _conditions{};
};

struct node {
    std::vector<field> _fields{};
    /// Each `$or`: one branch must match.
    std::vector<std::vector<node>> _ors{};
};

/// Thrown inside `parse` with the reason, caught at its edge.
struct policy_error {
    std::string _reason;
    /// A nested object under attribute scope, which SNS words apart.
    bool _nested = false;
};

[[nodiscard]] inline auto as_number(const boost::json::value& v) -> std::optional<double> {
    if (v.is_int64()) {
        return static_cast<double>(v.get_int64());
    }
    if (v.is_uint64()) {
        return static_cast<double>(v.get_uint64());
    }
    if (v.is_double()) {
        return v.get_double();
    }
    return std::nullopt;
}

/// SNS compares numbers to five decimal places.
[[nodiscard]] inline auto same_number(double a, double b) -> bool {
    constexpr double scale = 1e5;
    if (std::fabs(a) <= k_max_filter_number && std::fabs(b) <= k_max_filter_number) {
        return std::llround(a * scale) == std::llround(b * scale);
    }
    return a == b;
}

[[nodiscard]] inline auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

/// `*` matches any run of characters; `\*` and `\\` are literal.
[[nodiscard]] inline auto wildcard_match(std::string_view pattern, std::string_view s) -> bool {
    struct token {
        char _c;
        bool _star;
    };
    std::vector<token> p;
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] == '\\' && i + 1 < pattern.size()) {
            p.push_back({pattern[++i], false});
        } else {
            p.push_back({pattern[i], pattern[i] == '*'});
        }
    }
    std::size_t pi = 0;
    std::size_t si = 0;
    std::size_t star = std::string_view::npos;
    std::size_t mark = 0;
    while (si < s.size()) {
        if (pi < p.size() && !p[pi]._star && p[pi]._c == s[si]) {
            ++pi;
            ++si;
        } else if (pi < p.size() && p[pi]._star) {
            star = pi++;
            mark = si;
        } else if (star != std::string_view::npos) {
            pi = star + 1;
            si = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi]._star) {
        ++pi;
    }
    return pi == p.size();
}

[[nodiscard]] inline auto parse_ip(std::string_view text, int& family,
                                   std::array<unsigned char, 16>& out) -> bool {
    const std::string s(text);
    if (inet_pton(AF_INET, s.c_str(), out.data()) == 1) {
        family = AF_INET;
        return true;
    }
    if (inet_pton(AF_INET6, s.c_str(), out.data()) == 1) {
        family = AF_INET6;
        return true;
    }
    return false;
}

[[nodiscard]] inline auto in_range(const ip_range& r, std::string_view text) -> bool {
    int family = 0;
    std::array<unsigned char, 16> a{};
    if (!parse_ip(text, family, a) || family != r._family) {
        return false;
    }
    const unsigned full = r._bits / 8;
    const unsigned rest = r._bits % 8;
    if (!std::equal(a.begin(), a.begin() + full, r._net.begin())) {
        return false;
    }
    if (rest == 0) {
        return true;
    }
    const auto mask = static_cast<unsigned char>(0xFFU << (8 - rest));
    return (a.at(full) & mask) == (r._net.at(full) & mask);
}

[[nodiscard]] inline auto check(const condition& c, const boost::json::value& v) -> bool {
    const auto* str = v.if_string();
    const auto num = as_number(v);
    switch (c._kind) {
        case kind::string_value:
            return str != nullptr && *str == c._text;
        case kind::number_value:
            return num && same_number(*num, c._number);
        case kind::boolean_value:
            return v.is_bool() && v.get_bool() == c._flag;
        case kind::null_value:
            return v.is_null();
        case kind::prefix:
            return str != nullptr && std::string_view(*str).starts_with(c._text);
        case kind::suffix:
            return str != nullptr && std::string_view(*str).ends_with(c._text);
        case kind::equals_ignore_case:
            return str != nullptr && iequals(*str, c._text);
        case kind::wildcard:
            return str != nullptr && wildcard_match(c._text, *str);
        case kind::anything_but:
            if (c._but == but::prefix) {
                return str == nullptr || !std::string_view(*str).starts_with(c._text);
            }
            if (c._but == but::suffix) {
                return str == nullptr || !std::string_view(*str).ends_with(c._text);
            }
            if (str != nullptr) {
                return std::find(c._strings.begin(), c._strings.end(), std::string_view(*str)) ==
                       c._strings.end();
            }
            if (num) {
                return std::none_of(c._numbers.begin(), c._numbers.end(),
                                    [&](double n) { return same_number(n, *num); });
            }
            return true;
        case kind::numeric:
            return num && std::all_of(c._range.begin(), c._range.end(), [&](const auto& op) {
                       switch (op.first) {
                           case numeric_op::eq:
                               return same_number(*num, op.second);
                           case numeric_op::lt:
                               return *num < op.second && !same_number(*num, op.second);
                           case numeric_op::le:
                               return *num <= op.second || same_number(*num, op.second);
                           case numeric_op::gt:
                               return *num > op.second && !same_number(*num, op.second);
                           case numeric_op::ge:
                               return *num >= op.second || same_number(*num, op.second);
                       }
                       return false;
                   });
        case kind::cidr:
            return str != nullptr && in_range(c._ip, *str);
        case kind::exists:
            return false;  // decided on the whole key, in match_field
    }
    return false;
}

using leaves = std::span<const boost::json::value* const>;
using lookup_fn =
    std::function<bool(const std::vector<std::string>&, const std::function<bool(leaves)>&)>;

[[nodiscard]] inline auto match_field(const field& f, leaves found) -> bool {
    return std::any_of(f._conditions.begin(), f._conditions.end(), [&](const condition& c) {
        if (c._kind == kind::exists) {
            return c._flag == !found.empty();
        }
        return std::any_of(found.begin(), found.end(),
                           [&](const boost::json::value* v) { return check(c, *v); });
    });
}

[[nodiscard]] inline auto match_node(const node& n, const lookup_fn& lookup) -> bool {
    for (const auto& f : n._fields) {
        if (!lookup(f._path, [&](leaves found) { return match_field(f, found); })) {
            return false;
        }
    }
    return std::all_of(n._ors.begin(), n._ors.end(), [&](const std::vector<node>& branches) {
        return std::any_of(branches.begin(), branches.end(),
                           [&](const node& b) { return match_node(b, lookup); });
    });
}

/// Adds `v`, or each element of an array (recursively), as leaves.
/// Objects are not leaves.
inline void flatten(const boost::json::value& v, std::vector<const boost::json::value*>& out) {
    if (const auto* a = v.if_array()) {
        for (const auto& e : *a) {
            flatten(e, out);
        }
    } else if (!v.is_object()) {
        out.push_back(&v);
    }
}

/// The values at `path` inside `root`, stepping through arrays of objects.
[[nodiscard]] inline auto at_path(const boost::json::value& root,
                                  const std::vector<std::string>& path)
    -> std::vector<const boost::json::value*> {
    std::vector<const boost::json::value*> here{&root};
    for (const auto& key : path) {
        std::vector<const boost::json::value*> next;
        const std::function<void(const boost::json::value&)> step =
            [&](const boost::json::value& v) {
                if (const auto* o = v.if_object()) {
                    if (const auto* child = o->if_contains(key)) {
                        next.push_back(child);
                    }
                } else if (const auto* a = v.if_array()) {
                    for (const auto& e : *a) {
                        step(e);
                    }
                }
            };
        for (const auto* v : here) {
            step(*v);
        }
        here = std::move(next);
    }
    std::vector<const boost::json::value*> out;
    for (const auto* v : here) {
        flatten(*v, out);
    }
    return out;
}

/// The value an attribute shows a policy, or null when the policy should
/// see it as absent (Binary, or a value that does not parse as its type).
[[nodiscard]] inline auto attribute_value(const message_attribute& a)
    -> std::optional<boost::json::value> {
    const std::string_view type = a._data_type;
    const auto base = type.substr(0, type.find('.'));
    if (!a._string_value) {
        return std::nullopt;
    }
    const std::string_view s = *a._string_value;
    if (type == "String.Array") {
        boost::system::error_code ec;
        auto v = boost::json::parse(s, ec);
        if (ec || !v.is_array()) {
            return std::nullopt;
        }
        return v;
    }
    if (base == "String") {
        return boost::json::value(boost::json::string(s));
    }
    if (base == "Number") {
        double d = 0;
        const auto* first = s.data();
        const auto* last = first + s.size();
        if (!s.empty() && *first == '+') {
            ++first;
        }
        const auto [end, ec] = std::from_chars(first, last, d);
        if (ec != std::errc{} || end != last) {
            return std::nullopt;
        }
        return boost::json::value(d);
    }
    return std::nullopt;
}

// ---- parsing --------------------------------------------------------------

[[noreturn]] inline void fail(std::string reason) {
    throw policy_error{std::move(reason)};
}

[[nodiscard]] inline auto policy_number(const boost::json::value& v, std::string_view what)
    -> double {
    const auto n = as_number(v);
    if (!n) {
        fail("Value of " + std::string(what) + " must be numeric");
    }
    if (std::fabs(*n) > k_max_filter_number) {
        fail("Numeric values must be between -1000000000 and 1000000000");
    }
    return *n;
}

[[nodiscard]] inline auto string_operand(const boost::json::value& v, std::string_view op)
    -> std::string {
    if (!v.is_string()) {
        fail(std::string(op) + " match pattern must be a string");
    }
    return std::string(v.get_string());
}

[[nodiscard]] inline auto parse_numeric(const boost::json::value& v) -> condition {
    const auto* a = v.if_array();
    if (a == nullptr || a->empty()) {
        fail("Value of numeric must be an array.");
    }
    if (a->size() % 2 != 0 || a->size() > 4) {
        fail("Too many elements in numeric expression");
    }
    condition c;
    c._kind = kind::numeric;
    for (std::size_t i = 0; i < a->size(); i += 2) {
        const auto& opv = (*a)[i];
        if (!opv.is_string()) {
            fail("Value of numeric must be an array of operators and numbers.");
        }
        const std::string_view name = opv.get_string();
        numeric_op op{};
        if (name == "=") {
            op = numeric_op::eq;
        } else if (name == "<") {
            op = numeric_op::lt;
        } else if (name == "<=") {
            op = numeric_op::le;
        } else if (name == ">") {
            op = numeric_op::gt;
        } else if (name == ">=") {
            op = numeric_op::ge;
        } else {
            fail("Unrecognized numeric range operator: " + std::string(name));
        }
        c._range.emplace_back(op, policy_number((*a)[i + 1], name));
    }
    if (c._range.size() == 2) {
        const auto [lo_op, lo] = c._range[0];
        const auto [hi_op, hi] = c._range[1];
        if (lo_op != numeric_op::gt && lo_op != numeric_op::ge) {
            fail("Bad numeric range operator: " + std::string((*a)[0].get_string()));
        }
        if (hi_op != numeric_op::lt && hi_op != numeric_op::le) {
            fail("Bad numeric range operator: " + std::string((*a)[2].get_string()));
        }
        if (!(lo < hi)) {
            fail("Bottom must be less than top");
        }
    }
    return c;
}

[[nodiscard]] inline auto parse_anything_but(const boost::json::value& v) -> condition {
    condition c;
    c._kind = kind::anything_but;
    const auto add = [&c](const boost::json::value& e) {
        if (e.is_string()) {
            c._strings.emplace_back(e.get_string());
        } else if (as_number(e)) {
            c._numbers.push_back(policy_number(e, "anything-but"));
        } else {
            fail("Value of anything-but must be an array or single string/number value.");
        }
    };
    if (const auto* o = v.if_object()) {
        if (o->size() != 1) {
            fail("Value of anything-but must be an array or single string/number value.");
        }
        const auto& [key, operand] = *o->begin();
        if (key == "prefix") {
            c._but = but::prefix;
        } else if (key == "suffix") {
            c._but = but::suffix;
        } else {
            fail("Unsupported anything-but pattern: " + std::string(key));
        }
        c._text = string_operand(operand, key);
        return c;
    }
    if (const auto* a = v.if_array()) {
        if (a->empty()) {
            fail("Empty arrays are not allowed");
        }
        for (const auto& e : *a) {
            add(e);
        }
        return c;
    }
    add(v);
    return c;
}

[[nodiscard]] inline auto parse_cidr(const boost::json::value& v) -> condition {
    const auto text = string_operand(v, "cidr");
    const auto slash = text.find('/');
    if (slash == std::string::npos || text.find('/', slash + 1) != std::string::npos) {
        fail("Malformed CIDR, one '/' required");
    }
    condition c;
    c._kind = kind::cidr;
    if (!parse_ip(std::string_view(text).substr(0, slash), c._ip._family, c._ip._net)) {
        fail("Nonstandard IP address: " + text.substr(0, slash));
    }
    const std::string_view bits = std::string_view(text).substr(slash + 1);
    unsigned n = 0;
    const auto [end, ec] = std::from_chars(bits.data(), bits.data() + bits.size(), n);
    const unsigned max = c._ip._family == AF_INET ? 32 : 128;
    if (bits.empty() || ec != std::errc{} || end != bits.data() + bits.size() || n > max) {
        fail("Malformed CIDR, mask bits must be an integer");
    }
    c._ip._bits = n;
    return c;
}

[[nodiscard]] inline auto parse_condition(const boost::json::value& v) -> condition {
    condition c;
    if (v.is_string()) {
        c._kind = kind::string_value;
        c._text = std::string(v.get_string());
        return c;
    }
    if (as_number(v)) {
        c._kind = kind::number_value;
        c._number = policy_number(v, "match value");
        return c;
    }
    if (v.is_bool()) {
        c._kind = kind::boolean_value;
        c._flag = v.get_bool();
        return c;
    }
    if (v.is_null()) {
        c._kind = kind::null_value;
        return c;
    }
    const auto* o = v.if_object();
    if (o == nullptr) {
        fail("Match value must be String, number, true, false, or null");
    }
    if (o->size() != 1) {
        fail("Only one key allowed in match expression");
    }
    const auto& [key, operand] = *o->begin();
    if (key == "prefix" || key == "suffix" || key == "equals-ignore-case" || key == "wildcard") {
        c._text = string_operand(operand, key);
        if (key == "prefix") {
            c._kind = kind::prefix;
        } else if (key == "suffix") {
            c._kind = kind::suffix;
        } else if (key == "equals-ignore-case") {
            c._kind = kind::equals_ignore_case;
        } else {
            if (c._text.find("**") != std::string::npos) {
                fail("Consecutive wildcard characters at pos " +
                     std::to_string(c._text.find("**") + 1));
            }
            c._kind = kind::wildcard;
        }
        return c;
    }
    if (key == "anything-but") {
        return parse_anything_but(operand);
    }
    if (key == "numeric") {
        return parse_numeric(operand);
    }
    if (key == "exists") {
        if (!operand.is_bool()) {
            fail("exists match pattern must be either true or false.");
        }
        c._kind = kind::exists;
        c._flag = operand.get_bool();
        return c;
    }
    if (key == "cidr") {
        return parse_cidr(operand);
    }
    fail("Unrecognized match type " + std::string(key));
}

inline void parse_object(const boost::json::object& o, const std::vector<std::string>& prefix,
                         filter_scope scope, node& out) {
    if (o.empty()) {
        fail("Empty objects are not allowed");
    }
    for (const auto& [key, v] : o) {
        if (key == "$or") {
            const auto* branches = v.if_array();
            if (branches == nullptr || branches->size() < 2) {
                fail("Value of $or must be an array of at least two objects");
            }
            std::vector<node> group;
            for (const auto& b : *branches) {
                if (!b.is_object()) {
                    fail("Value of $or must be an array of at least two objects");
                }
                node n;
                parse_object(b.get_object(), prefix, scope, n);
                group.push_back(std::move(n));
            }
            out._ors.push_back(std::move(group));
            continue;
        }
        auto path = prefix;
        path.emplace_back(key);
        if (const auto* a = v.if_array()) {
            if (a->empty()) {
                fail("Empty arrays are not allowed");
            }
            field f;
            f._path = std::move(path);
            for (const auto& e : *a) {
                f._conditions.push_back(parse_condition(e));
            }
            out._fields.push_back(std::move(f));
        } else if (const auto* child = v.if_object()) {
            if (scope == filter_scope::message_attributes) {
                throw policy_error{{}, true};
            }
            parse_object(*child, path, scope, out);
        } else {
            fail("\"" + std::string(key) + "\" must be an object or an array");
        }
    }
}

/// Combinations SNS counts: the product of each key's values, with each
/// `$or` contributing the sum of its branches. Saturates.
[[nodiscard]] inline auto combinations(const node& n) -> std::size_t {
    constexpr std::size_t cap = std::numeric_limits<std::uint32_t>::max();
    std::size_t total = 1;
    const auto times = [&](std::size_t k) { total = std::min(cap, total * std::min(cap, k)); };
    for (const auto& f : n._fields) {
        times(f._conditions.size());
    }
    for (const auto& group : n._ors) {
        std::size_t sum = 0;
        for (const auto& b : group) {
            sum = std::min(cap, sum + combinations(b));
        }
        times(sum);
    }
    return total;
}

/// The most keys any one path through the `$or`s tests.
[[nodiscard]] inline auto keys(const node& n) -> std::size_t {
    std::size_t total = n._fields.size();
    for (const auto& group : n._ors) {
        std::size_t most = 0;
        for (const auto& b : group) {
            most = std::max(most, keys(b));
        }
        total += most;
    }
    return total;
}

}  // namespace filter_detail

class filter_policy {
public:
    /// Parses `text` for `scope`, or answers SNS's `InvalidParameter`.
    [[nodiscard]] static auto parse(std::string_view text, filter_scope scope)
        -> query_result<filter_policy> {
        const auto bad = [](std::string_view reason) {
            return model_error("InvalidParameterException",
                               "Invalid parameter: FilterPolicy: " + std::string(reason));
        };
        if (text.size() > k_max_filter_policy_bytes) {
            return bad("Filter policy is too long");
        }
        boost::system::error_code ec;
        const auto v = boost::json::parse(text, ec);
        if (ec) {
            return bad("failed to parse JSON");
        }
        if (!v.is_object()) {
            return bad("Filter policy must be a JSON object");
        }
        filter_policy p;
        p._scope = scope;
        if (v.get_object().empty()) {
            return p;  // `{}` lets every message through
        }
        try {
            filter_detail::parse_object(v.get_object(), {}, scope, p._root);
        } catch (const filter_detail::policy_error& e) {
            if (e._nested) {
                return model_error("InvalidParameterException",
                                   "Invalid parameter: Filter policy scope MessageAttributes "
                                   "does not support nested filter policy");
            }
            return bad(e._reason);
        }
        if (filter_detail::keys(p._root) > k_max_filter_policy_keys) {
            return bad("Filter policy can not have more than 5 keys");
        }
        if (filter_detail::combinations(p._root) > k_max_filter_policy_combinations) {
            return bad("Filter policy is too complex");
        }
        return p;
    }

    [[nodiscard]] auto scope() const -> filter_scope { return _scope; }
    [[nodiscard]] auto combinations() const -> std::size_t {
        return filter_detail::combinations(_root);
    }

    /// Attribute scope: whether these message attributes pass.
    [[nodiscard]] auto matches_attributes(const message_attributes& attrs) const -> bool {
        return filter_detail::match_node(
            _root, [&attrs](const std::vector<std::string>& path,
                            const std::function<bool(filter_detail::leaves)>& fn) {
                std::vector<const boost::json::value*> found;
                std::optional<boost::json::value> value;
                if (path.size() == 1) {
                    if (const auto it = attrs.find(path.front()); it != attrs.end()) {
                        value = filter_detail::attribute_value(it->second);
                    }
                }
                if (value) {
                    filter_detail::flatten(*value, found);
                }
                return fn(found);
            });
    }

    /// Payload scope: whether this body passes. A body that is not a JSON
    /// object never does.
    [[nodiscard]] auto matches_body(std::string_view body) const -> bool {
        boost::system::error_code ec;
        const auto root = boost::json::parse(body, ec);
        if (ec || !root.is_object()) {
            return false;
        }
        return filter_detail::match_node(
            _root, [&root](const std::vector<std::string>& path,
                           const std::function<bool(filter_detail::leaves)>& fn) {
                const auto found = filter_detail::at_path(root, path);
                return fn(found);
            });
    }

    /// Whether `m` passes, in this policy's scope. Payload scope reads the
    /// `Message` as published. ASSUMPTION for task 12's recordings: a
    /// `MessageStructure=json` message is filtered on that whole JSON
    /// object, not on one protocol's member.
    [[nodiscard]] auto matches(const published_message& m) const -> bool {
        return _scope == filter_scope::message_body ? matches_body(m._message)
                                                    : matches_attributes(m._attributes);
    }

private:
    filter_scope _scope = filter_scope::message_attributes;
    filter_detail::node _root{};
};

}  // namespace kythira::sns
