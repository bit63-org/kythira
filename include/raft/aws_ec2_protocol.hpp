// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file aws_ec2_protocol.hpp
/// @brief The Amazon EC2 query protocol (`.kiro/specs/ec2-compatible-api/`
///        Requirement 3.1, design "EC2 query protocol").
///
/// EC2 speaks a dialect of the AWS Query protocol. This header sits beside
/// `aws_query_protocol.hpp` and reuses its form decoder, XML writer and
/// marker sealer; it differs where EC2 differs:
///
///  - Lists flatten as `Name.N` with no `.member`, at any depth:
///    `InstanceId.2`, `Filter.1.Value.2`, `TagSpecification.2.Tag.1.Key`,
///    `BlockDeviceMapping.1.Ebs.VolumeSize`. `params` reads them back as
///    lists of values (`list`) or of nested parameter sets (`structs`).
///  - Answers are `<ActionResponse xmlns=".../2016-11-15/">` with
///    `<requestId>` first and lists as `<item>` elements
///    (`response_xml`).
///  - Errors are `<Response><Errors><Error><Code/><Message/></Error>
///    </Errors><RequestID/></Response>` (`error_xml`), with the HTTP status
///    EC2 gives each code (`http_status`).
///
/// The shapes of the common inputs (filters, tags, tag specifications,
/// `MaxResults`) are decoded here too, because every `Describe*` and every
/// create takes them the same way (Requirements 4.4, 4.5).
///
/// Plain functions over strings with no Raft or EC2-module dependency, like
/// the query codec. Every decoder of client input returns a `result`: the
/// value, or the EC2 error code and message to answer with. Nothing here
/// throws on client input. The wire facts come from the recorded clients in
/// `services/ec2/tests/evidence/`.

#include <raft/aws_query_protocol.hpp>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::aws_ec2 {

/// The query protocol's `Version` parameter EC2 answers to.
inline constexpr std::string_view api_version = "2016-11-15";
/// The namespace of every EC2 answer. The model's `xmlNamespace` lacks the
/// trailing slash; the service sends it with one.
inline constexpr std::string_view xml_namespace = "http://ec2.amazonaws.com/doc/2016-11-15/";

/// An EC2 error: the `<Code>` and `<Message>` of the answer.
struct error {
    std::string code;
    std::string message;

    friend auto operator==(const error&, const error&) -> bool = default;
};

/// A decoded value, or the error to answer with.
template<class T> class result {
public:
    // Implicit on purpose: a decoder returns either a value or an error.
    result(T value) : _v(std::move(value)) {}  // NOLINT(google-explicit-constructor)
    result(error e) : _v(std::move(e)) {}      // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const -> bool { return _v.index() == 0; }
    explicit operator bool() const { return has_value(); }
    [[nodiscard]] auto value() const& -> const T& { return std::get<0>(_v); }
    [[nodiscard]] auto value() && -> T { return std::get<0>(std::move(_v)); }
    [[nodiscard]] auto operator*() const& -> const T& { return value(); }
    [[nodiscard]] auto operator->() const -> const T* { return &std::get<0>(_v); }
    [[nodiscard]] auto err() const -> const error& { return std::get<1>(_v); }

private:
    std::variant<T, error> _v;
};

namespace codes {
inline constexpr std::string_view malformed_query = "MalformedQueryString";
inline constexpr std::string_view missing_action = "MissingAction";
inline constexpr std::string_view missing_parameter = "MissingParameter";
inline constexpr std::string_view no_such_version = "NoSuchVersion";
inline constexpr std::string_view invalid_action = "InvalidAction";
inline constexpr std::string_view invalid_parameter_value = "InvalidParameterValue";
inline constexpr std::string_view invalid_parameter_combination = "InvalidParameterCombination";
inline constexpr std::string_view invalid_pagination_token = "InvalidPaginationToken";
inline constexpr std::string_view unknown_parameter = "UnknownParameter";
inline constexpr std::string_view unsupported_operation = "UnsupportedOperation";
inline constexpr std::string_view dry_run_operation = "DryRunOperation";
inline constexpr std::string_view unauthorized_operation = "UnauthorizedOperation";
inline constexpr std::string_view auth_failure = "AuthFailure";
inline constexpr std::string_view idempotent_parameter_mismatch = "IdempotentParameterMismatch";
inline constexpr std::string_view request_limit_exceeded = "RequestLimitExceeded";
inline constexpr std::string_view internal_error = "InternalError";
inline constexpr std::string_view unavailable = "Unavailable";
}  // namespace codes

/// The HTTP status EC2 answers an error code with. EC2 uses 400 for nearly
/// every client error; the exceptions are listed. Task 19's recorded EC2
/// responses confirm or correct this table.
[[nodiscard]] constexpr auto http_status(std::string_view code) -> unsigned {
    struct entry {
        std::string_view code;
        unsigned status;
    };
    constexpr entry table[] = {
        {"AuthFailure", 401},
        {"Blocked", 403},
        {"DryRunOperation", 412},
        {"InsufficientAddressCapacity", 500},
        {"InsufficientCapacity", 500},
        {"InsufficientInstanceCapacity", 500},
        {"InsufficientReservedInstanceCapacity", 500},
        {"InternalError", 500},
        {"InternalFailure", 500},
        {"RequestLimitExceeded", 503},
        {"ServiceUnavailable", 503},
        {"Unavailable", 503},
        {"UnauthorizedOperation", 403},
    };
    for (const auto& e : table) {
        if (e.code == code) {
            return e.status;
        }
    }
    return 400;
}

/// A server-side error a client should retry (the SDKs retry 5xx and
/// `RequestLimitExceeded`).
[[nodiscard]] constexpr auto retryable(std::string_view code) -> bool {
    return http_status(code) >= 500;
}

[[nodiscard]] inline auto make_error(std::string_view code, std::string message) -> error {
    return error{std::string(code), std::move(message)};
}

/// An EC2 request's parameters, or one nested structure of them.
///
/// A name is the full dotted wire name (`Filter.1.Value.2`); `sub` and
/// `structs` give a view with a prefix stripped, so the same accessors read
/// the nested fields (`Ebs.VolumeSize` inside `BlockDeviceMapping.1`).
class params {
public:
    using map_type = std::map<std::string, std::string, std::less<>>;

    params() = default;
    explicit params(map_type m) : _params(std::move(m)) {}

    /// A form body or GET query string. `MalformedQueryString` when it is
    /// not a well-formed form or names a parameter twice.
    [[nodiscard]] static auto parse(std::string_view body) -> result<params> {
        auto f = aws_query::form::parse(body);
        if (!f) {
            return make_error(codes::malformed_query,
                              "The query string is malformed or names a parameter twice.");
        }
        return params(f->params());
    }

    [[nodiscard]] auto get(std::string_view name) const -> std::optional<std::string_view> {
        const auto it = _params.find(name);
        if (it == _params.end()) {
            return std::nullopt;
        }
        return std::string_view(it->second);
    }

    [[nodiscard]] auto contains(std::string_view name) const -> bool {
        return _params.find(name) != _params.end();
    }

    /// True when `name` is given as a value or as the prefix of a nested
    /// one (`Ebs` for `Ebs.VolumeSize`, `InstanceId` for `InstanceId.1`).
    [[nodiscard]] auto has(std::string_view name) const -> bool {
        if (contains(name)) {
            return true;
        }
        const auto prefix = std::string(name) + '.';
        const auto it = _params.lower_bound(prefix);
        return it != _params.end() && it->first.starts_with(prefix);
    }

    [[nodiscard]] auto empty() const -> bool { return _params.empty(); }
    [[nodiscard]] auto size() const -> std::size_t { return _params.size(); }
    [[nodiscard]] auto all() const -> const map_type& { return _params; }

    /// The parameters under `name.`, with that prefix stripped.
    [[nodiscard]] auto sub(std::string_view name) const -> params {
        const auto prefix = std::string(name) + '.';
        map_type out;
        for (auto it = _params.lower_bound(prefix);
             it != _params.end() && it->first.starts_with(prefix); ++it) {
            out.emplace(it->first.substr(prefix.size()), it->second);
        }
        return params(std::move(out));
    }

    /// `name.N` values in index order. Empty when the list is absent. An
    /// index that is not a positive number, or an entry with fields
    /// (`name.N.x`), is `InvalidParameterValue`. Indices may skip numbers;
    /// only their order counts.
    [[nodiscard]] auto list(std::string_view name) const -> result<std::vector<std::string>> {
        std::map<std::size_t, std::string> by_index;
        if (contains(name)) {
            return bad_list(name);
        }
        const auto inner = sub(name);
        for (const auto& [rest, value] : inner.all()) {
            if (rest.find('.') != std::string::npos) {
                return bad_list(name);
            }
            const auto idx = aws_query::detail::parse_index(rest);
            if (!idx) {
                return bad_list(name);
            }
            by_index.emplace(*idx, value);
        }
        std::vector<std::string> out;
        out.reserve(by_index.size());
        for (auto& [_, v] : by_index) {
            out.push_back(std::move(v));
        }
        return out;
    }

    /// `name.N.*` structures in index order, each as its own parameters
    /// (`name.N.` stripped). A bare `name.N` value or a bad index is
    /// `InvalidParameterValue`.
    [[nodiscard]] auto structs(std::string_view name) const -> result<std::vector<params>> {
        std::map<std::size_t, map_type> by_index;
        if (contains(name)) {
            return bad_list(name);
        }
        const auto inner = sub(name);
        for (const auto& [rest, value] : inner.all()) {
            const auto dot = rest.find('.');
            if (dot == std::string::npos || dot + 1 == rest.size()) {
                return bad_list(name);
            }
            const auto idx = aws_query::detail::parse_index(std::string_view(rest).substr(0, dot));
            if (!idx) {
                return bad_list(name);
            }
            by_index[*idx].emplace(rest.substr(dot + 1), value);
        }
        std::vector<params> out;
        out.reserve(by_index.size());
        for (auto& [_, m] : by_index) {
            out.emplace_back(std::move(m));
        }
        return out;
    }

    /// `true` or `false`, as every recorded client sends booleans. Absent is
    /// `std::nullopt`; anything else is `InvalidParameterValue`.
    [[nodiscard]] auto boolean(std::string_view name) const -> result<std::optional<bool>> {
        const auto v = get(name);
        if (!v) {
            return std::optional<bool>{};
        }
        if (*v == "true") {
            return std::optional<bool>{true};
        }
        if (*v == "false") {
            return std::optional<bool>{false};
        }
        return make_error(codes::invalid_parameter_value,
                          "Value (" + std::string(*v) + ") for parameter " + std::string(name) +
                              " is invalid. Expected: 'true' or 'false'.");
    }

    /// A whole number in `[lo, hi]`. Absent is `std::nullopt`.
    [[nodiscard]] auto integer(std::string_view name, std::int64_t lo, std::int64_t hi) const
        -> result<std::optional<std::int64_t>> {
        const auto v = get(name);
        if (!v) {
            return std::optional<std::int64_t>{};
        }
        std::int64_t n = 0;
        const auto [p, ec] = std::from_chars(v->data(), v->data() + v->size(), n);
        if (v->empty() || ec != std::errc{} || p != v->data() + v->size() || n < lo || n > hi) {
            return make_error(codes::invalid_parameter_value,
                              "Value (" + std::string(*v) + ") for parameter " + std::string(name) +
                                  " is invalid. Expected a whole number from " +
                                  std::to_string(lo) + " to " + std::to_string(hi) + ".");
        }
        return std::optional<std::int64_t>{n};
    }

    /// The parameters as a form body, names sorted (so `parse(encode())`
    /// gives the same parameters back).
    [[nodiscard]] auto encode() const -> std::string {
        std::string out;
        for (const auto& [k, v] : _params) {
            if (!out.empty()) {
                out += '&';
            }
            out += aws_query::url_encode(k);
            out += '=';
            out += aws_query::url_encode(v);
        }
        return out;
    }

    friend auto operator==(const params&, const params&) -> bool = default;

private:
    [[nodiscard]] static auto bad_list(std::string_view name) -> error {
        return make_error(codes::invalid_parameter_value,
                          "The list parameter " + std::string(name) + " must be numbered " +
                              std::string(name) + ".1, " + std::string(name) + ".2, ...");
    }

    map_type _params;
};

/// The parts of a request every action shares.
struct request {
    std::string action;
    std::string version;
    params args;
};

/// `Action` and `Version` of a decoded request. A missing `Action` is
/// `MissingAction`, a missing `Version` `MissingParameter`, and any version
/// but 2016-11-15 `NoSuchVersion`. Whether the action exists is the front
/// end's question (`InvalidAction`), since it holds the operation table.
[[nodiscard]] inline auto read_request(params p) -> result<request> {
    const auto action = p.get("Action");
    if (!action || action->empty()) {
        return make_error(codes::missing_action, "The request must contain the parameter Action.");
    }
    const auto version = p.get("Version");
    if (!version || version->empty()) {
        return make_error(codes::missing_parameter,
                          "The request must contain the parameter Version.");
    }
    if (*version != api_version) {
        return make_error(codes::no_such_version, "The requested version (" +
                                                      std::string(*version) +
                                                      ") of service AmazonEC2 does not exist");
    }
    return request{std::string(*action), std::string(*version), std::move(p)};
}

/// One `Filter.N`: a name and its values (Requirement 4.5).
struct filter {
    std::string name;
    std::vector<std::string> values;

    friend auto operator==(const filter&, const filter&) -> bool = default;
};

/// `Filter.N.Name` with `Filter.N.Value.M`. A filter without a name, or a
/// field other than `Name` and `Value.M`, is `InvalidParameterValue`. A
/// filter with no values matches nothing, as on EC2, so it is kept.
[[nodiscard]] inline auto filters(const params& p, std::string_view name = "Filter")
    -> result<std::vector<filter>> {
    auto entries = p.structs(name);
    if (!entries) {
        return entries.err();
    }
    std::vector<filter> out;
    out.reserve(entries->size());
    for (const auto& e : *entries) {
        const auto n = e.get("Name");
        if (!n || n->empty()) {
            return make_error(codes::invalid_parameter_value,
                              "Each " + std::string(name) + " must have a Name.");
        }
        for (const auto& [field, _] : e.all()) {
            if (field != "Name" && !field.starts_with("Value.")) {
                return make_error(codes::invalid_parameter_value,
                                  "Unknown field " + field + " in " + std::string(name) + ".");
            }
        }
        auto values = e.list("Value");
        if (!values) {
            return values.err();
        }
        out.push_back(filter{std::string(*n), std::move(values).value()});
    }
    return out;
}

/// One tag. A tag sent without a value (`Tag.N.Key` alone, as every
/// recorded client sends one) has none, which `DeleteTags` reads as "any
/// value" and `CreateTags` as the empty value.
struct tag {
    std::string key;
    std::optional<std::string> value;

    friend auto operator==(const tag&, const tag&) -> bool = default;
};

/// `name.N.Key` with an optional `name.N.Value`. A tag without a key is
/// `InvalidParameterValue`; EC2's limits (keys and values, tags per
/// resource, the `aws:` prefix) are the front end's.
[[nodiscard]] inline auto tags(const params& p, std::string_view name = "Tag")
    -> result<std::vector<tag>> {
    auto entries = p.structs(name);
    if (!entries) {
        return entries.err();
    }
    std::vector<tag> out;
    out.reserve(entries->size());
    for (const auto& e : *entries) {
        const auto k = e.get("Key");
        if (!k) {
            return make_error(codes::invalid_parameter_value,
                              "Each " + std::string(name) + " must have a Key.");
        }
        for (const auto& [field, _] : e.all()) {
            if (field != "Key" && field != "Value") {
                return make_error(codes::invalid_parameter_value,
                                  "Unknown field " + field + " in " + std::string(name) + ".");
            }
        }
        const auto v = e.get("Value");
        out.push_back(tag{std::string(*k), v ? std::optional<std::string>(*v) : std::nullopt});
    }
    return out;
}

/// One `TagSpecification.N`: the tags for one kind of resource a create
/// makes (Requirement 4.4).
struct tag_specification {
    std::string resource_type;
    std::vector<tag> tags;

    friend auto operator==(const tag_specification&, const tag_specification&) -> bool = default;
};

/// `TagSpecification.N.ResourceType` with `TagSpecification.N.Tag.M`. A
/// specification without a resource type, or two for the same type, is
/// `InvalidParameterValue`.
[[nodiscard]] inline auto tag_specifications(const params& p,
                                             std::string_view name = "TagSpecification")
    -> result<std::vector<tag_specification>> {
    auto entries = p.structs(name);
    if (!entries) {
        return entries.err();
    }
    std::vector<tag_specification> out;
    out.reserve(entries->size());
    for (const auto& e : *entries) {
        const auto type = e.get("ResourceType");
        if (!type || type->empty()) {
            return make_error(codes::invalid_parameter_value,
                              "Each " + std::string(name) + " must have a ResourceType.");
        }
        for (const auto& s : out) {
            if (s.resource_type == *type) {
                return make_error(codes::invalid_parameter_value,
                                  "The resource type " + std::string(*type) +
                                      " is named by more than one tag specification.");
            }
        }
        for (const auto& [field, _] : e.all()) {
            if (field != "ResourceType" && !field.starts_with("Tag.")) {
                return make_error(codes::invalid_parameter_value,
                                  "Unknown field " + field + " in " + std::string(name) + ".");
            }
        }
        auto t = tags(e, "Tag");
        if (!t) {
            return t.err();
        }
        out.push_back(tag_specification{std::string(*type), std::move(t).value()});
    }
    return out;
}

/// `MaxResults` in `[lo, hi]`, the range each `Describe*` documents;
/// absent is `std::nullopt` (the operation answers everything, or its own
/// default page).
[[nodiscard]] inline auto max_results(const params& p, std::int64_t lo, std::int64_t hi)
    -> result<std::optional<std::int64_t>> {
    return p.integer("MaxResults", lo, hi);
}

/// Opens a `NextToken` sealed by `aws_query::marker_sealer` for `context`
/// (the action and what scopes the list). Absent is `std::nullopt`; a token
/// this list did not issue is `InvalidPaginationToken`.
[[nodiscard]] inline auto open_next_token(const params& p, const aws_query::marker_sealer& sealer,
                                          std::string_view context)
    -> result<std::optional<std::string>> {
    const auto t = p.get("NextToken");
    if (!t) {
        return std::optional<std::string>{};
    }
    auto last = sealer.open(context, *t);
    if (!last) {
        return make_error(codes::invalid_pagination_token,
                          "The specified pagination token is not valid.");
    }
    return last;
}

/// EC2's time stamps: ISO 8601 in UTC with milliseconds
/// (`2026-11-27T00:00:00.000Z`).
[[nodiscard]] inline auto timestamp(std::chrono::system_clock::time_point t) -> std::string {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch());
    const auto secs = std::chrono::floor<std::chrono::seconds>(ms);
    const auto frac = (ms - secs).count();
    const std::time_t tt = secs.count();
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];  // NOLINT(cppcoreguidelines-avoid-c-arrays)
    const auto n = std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
    std::string out(buf, n);
    out += '.';
    out += static_cast<char>('0' + (frac / 100) % 10);
    out += static_cast<char>('0' + (frac / 10) % 10);
    out += static_cast<char>('0' + frac % 10);
    out += 'Z';
    return out;
}

/// A `<tag>` list of `<item>` elements, written by `item` for each element
/// of `range`. EC2 writes an empty list as an empty element, never omits
/// it, and the recorded SDKs read both.
template<class Range, class Fn>
auto item_list(aws_query::xml_writer& w, std::string_view tag_name, const Range& range, Fn&& item)
    -> aws_query::xml_writer& {
    w.open(tag_name);
    for (const auto& e : range) {
        w.open("item");
        item(w, e);
        w.close();
    }
    return w.close();
}

/// `<tagSet>` of `<item><key/><value/></item>`, as every resource carries
/// its tags in describes.
template<class Range>
auto tag_set(aws_query::xml_writer& w, const Range& key_values) -> aws_query::xml_writer& {
    return item_list(w, "tagSet", key_values, [](aws_query::xml_writer& x, const auto& kv) {
        x.element("key", kv.first).element("value", kv.second);
    });
}

/// `<?xml ...?><{Action}Response xmlns=...><requestId/>body</{Action}Response>`.
/// `body` is the answer's fields, already written; an action with no
/// result answers `<return>true</return>`, which `return_true` gives.
[[nodiscard]] inline auto response_xml(std::string_view action, std::string_view request_id,
                                       std::string_view body) -> std::string {
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<";
    out += action;
    out += "Response xmlns=\"";
    out += xml_namespace;
    out += "\"><requestId>";
    out += aws_query::xml_escape(request_id);
    out += "</requestId>";
    out += body;
    out += "</";
    out += action;
    out += "Response>";
    return out;
}

inline constexpr std::string_view return_true = "<return>true</return>";

/// EC2's error document. The status to send is `http_status(code)`.
[[nodiscard]] inline auto error_xml(std::string_view code, std::string_view message,
                                    std::string_view request_id) -> std::string {
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response><Errors><Error><Code>";
    out += aws_query::xml_escape(code);
    out += "</Code><Message>";
    out += aws_query::xml_escape(message);
    out += "</Message></Error></Errors><RequestID>";
    out += aws_query::xml_escape(request_id);
    out += "</RequestID></Response>";
    return out;
}

[[nodiscard]] inline auto error_xml(const error& e, std::string_view request_id) -> std::string {
    return error_xml(e.code, e.message, request_id);
}

/// What `DryRun=true` answers when authorization and validation pass
/// (Requirement 3.4).
[[nodiscard]] inline auto dry_run_success() -> error {
    return make_error(codes::dry_run_operation,
                      "Request would have succeeded, but DryRun flag is set.");
}

}  // namespace kythira::aws_ec2
