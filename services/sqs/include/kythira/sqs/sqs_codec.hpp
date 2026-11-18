// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_codec.hpp
/// @brief SQS's two wire protocols over one model
///        (`.kiro/specs/sqs-compatible-queues/` Requirement 3.1).
///
/// Every SQS request is parsed into the same `boost::json::object` in the
/// JSON model's names, validated by core's `shape_validator`, and handled
/// once; the answer goes back in the protocol of the request.
///
///  - AWS JSON 1.0 (`application/x-amz-json-1.0`, `X-Amz-Target:
///    AmazonSQS.<Op>`): core's `aws_json::codec`.
///  - AWS query (`application/x-www-form-urlencoded` POST, or GET with a
///    query string; `Action=<Op>`): the form is read through the query
///    names of `model/sqs_query_names.hpp` (`Attribute.1.Name`,
///    `MessageAttribute.1.Value.StringValue`,
///    `SendMessageBatchRequestEntry.1.Id`) and answered in XML with the
///    same names (`<ReceiveMessageResult><Message>...`). Scalars arrive as
///    text and are converted to the model's kinds before validation, so a
///    bad number fails exactly as it would in JSON. A query request may
///    name its queue by the request path (`POST /123456789012/orders`, as
///    older SDKs do) instead of `QueueUrl`; the codec fills `QueueUrl` from
///    the configured endpoint and the path.
///
/// Unknown members and parameters are ignored, so a newer client's extra
/// field never fails a request (SQS's documented forward compatibility;
/// unverified until task 13's recordings).

#include <kythira/sqs/model/sqs_model.hpp>
#include <kythira/sqs/model/sqs_query_names.hpp>
#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_query_protocol.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

enum class sqs_protocol : std::uint8_t {
    json,
    query,
};

/// The request fields the codec reads. Views into the transport's request;
/// they must outlive the call.
struct sqs_request_view {
    std::string_view method{};
    std::string_view path{};          ///< without the query string
    std::string_view query_string{};  ///< after '?', empty when absent
    std::string_view content_type{};  ///< empty when absent
    std::string_view target{};        ///< X-Amz-Target, empty when absent
    bool query_mode = false;          ///< `x-amzn-query-mode: true`
    std::string_view body{};
};

/// A request that framed, parsed and validated.
struct sqs_parsed_request {
    const aws_json::operation* op = nullptr;
    boost::json::object input{};
};

struct sqs_codec_options {
    /// `scheme://host[:port]` that queue URLs are minted on, for a query
    /// request that names its queue by path.
    std::string endpoint{};
    aws_json::request_limits limits{};
};

class sqs_codec {
public:
    explicit sqs_codec(sqs_codec_options options)
        : _options(std::move(options)),
          _json(sqs_model::k_model, aws_json::codec_options{
                                        .style = sqs_error_style(),
                                        .ids = aws_json::request_id_style::uuid,
                                        .limits = _options.limits,
                                        .unknown_members = aws_json::unknown_member_policy::ignore,
                                    }) {
        const auto& m = sqs_model::k_model;
        _names.resize(m.members.size(), nullptr);
        for (const auto& s : m.shapes) {
            if (s.kind != aws_json::shape_kind::structure) {
                continue;
            }
            for (std::uint32_t i = 0; i < s.count; ++i) {
                _names[s.first + i] = sqs_query::find_member(s.name, m.members[s.first + i].name);
            }
        }
    }

    [[nodiscard]] auto json_codec() const noexcept -> const aws_json::codec& { return _json; }
    [[nodiscard]] static auto model() noexcept -> const aws_json::service_model& {
        return sqs_model::k_model;
    }

    /// Query when the body is a form or the request is a GET; JSON
    /// otherwise (which includes a request no protocol accepts: it is
    /// answered with JSON's UnknownOperationException).
    [[nodiscard]] static auto protocol_of(const sqs_request_view& req) -> sqs_protocol {
        if (req.method == "GET") {
            return sqs_protocol::query;
        }
        auto ct = req.content_type;
        if (const auto semi = ct.find(';'); semi != std::string_view::npos) {
            ct = ct.substr(0, semi);
        }
        while (!ct.empty() && (ct.back() == ' ' || ct.back() == '\t')) {
            ct.remove_suffix(1);
        }
        constexpr std::string_view k_form = "application/x-www-form-urlencoded";
        const bool form = ct.size() == k_form.size() &&
                          std::equal(ct.begin(), ct.end(), k_form.begin(), [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) == b;
                          });
        return form ? sqs_protocol::query : sqs_protocol::json;
    }

    /// Frame, parse and validate. On failure, the error to answer with (in
    /// `protocol_of(req)`).
    [[nodiscard]] auto parse(const sqs_request_view& req) const
        -> aws_json::result<sqs_parsed_request> {
        if (protocol_of(req) == sqs_protocol::json) {
            return parse_json(req);
        }
        const auto text = req.method == "GET" ? req.query_string : req.body;
        if (text.size() > _options.limits.max_body_bytes) {
            return make_error(k_too_large_error,
                              "Request body of " + std::to_string(text.size()) +
                                  " bytes exceeds the limit of " +
                                  std::to_string(_options.limits.max_body_bytes) + " bytes");
        }
        auto f = aws_query::form::parse(text);
        if (!f) {
            return make_error(k_serialization_error, "The request body is not a well-formed form.");
        }
        const auto action = f->get("Action");
        if (!action) {
            return make_error(k_missing_action_error, "The request must contain an Action.");
        }
        const auto* op = model().find_operation(*action);
        if (op == nullptr) {
            return make_error(k_unknown_operation_error, "The action " + std::string(*action) +
                                                             " is not valid for this endpoint.");
        }
        boost::json::object input;
        if (op->input != aws_json::no_shape) {
            auto converted = form_to_json(*f, op->input);
            if (!converted.has_value()) {
                return converted.error();
            }
            input = std::move(*converted);
            fill_queue_url(req.path, op->input, input);
        }
        if (auto e = validate(*op, input)) {
            return std::move(*e);
        }
        return sqs_parsed_request{op, std::move(input)};
    }

    /// A 200 answer carrying `output`, in the protocol of `req`.
    [[nodiscard]] auto respond(const sqs_request_view& req, const aws_json::operation& op,
                               const boost::json::object& output, std::string request_id) const
        -> aws_json::http_response {
        if (protocol_of(req) == sqs_protocol::json) {
            return _json.respond(output, std::move(request_id));
        }
        aws_json::http_response r;
        r.status = 200;
        // An action with an output shape always answers with its Result
        // element, even an empty one: botocore looks the wrapper up by
        // name, so a ReceiveMessage that found nothing must still carry
        // <ReceiveMessageResult/>.
        const bool has_output = op.output != aws_json::no_shape;
        const auto result = has_output ? json_to_xml(op.output, output) : std::string();
        r.body = aws_query::response_xml(op.name, sqs_query::k_xml_namespace, result, request_id,
                                         has_output);
        r.headers.emplace_back("Content-Type", "text/xml");
        r.headers.emplace_back("x-amzn-RequestId", std::move(request_id));
        return r;
    }

    /// An error answer, in the protocol of `req`.
    [[nodiscard]] auto respond(const sqs_request_view& req, const aws_json::error& e,
                               std::string request_id) const -> aws_json::http_response {
        const auto q = to_query(e);
        if (protocol_of(req) == sqs_protocol::json) {
            auto r = _json.respond(e, std::move(request_id));
            if (req.query_mode) {
                r.headers.emplace_back("x-amzn-query-error",
                                       q.code + (q.sender ? ";Sender" : ";Receiver"));
            }
            return r;
        }
        aws_json::http_response r;
        r.status = e.status;
        r.body = aws_query::error_xml(sqs_query::k_xml_namespace, q.sender, q.code,
                                      e.message.value_or(""), request_id);
        r.headers.emplace_back("Content-Type", "text/xml");
        r.headers.emplace_back("x-amzn-RequestId", std::move(request_id));
        return r;
    }

    [[nodiscard]] auto new_request_id() const -> std::string { return _json.new_request_id(); }

    /// The JSON object a query form means for structure `shape`, before
    /// validation. Public for the evidence replay test.
    [[nodiscard]] auto form_to_json(const aws_query::form& f, std::uint32_t shape) const
        -> aws_json::result<boost::json::object> {
        boost::json::value out;
        if (auto e = read_structure(f, shape, "", out)) {
            return std::move(*e);
        }
        return std::move(out.as_object());
    }

    /// The XML a structure `shape` value reads as inside its Result
    /// element. Members the shape does not declare are left out.
    [[nodiscard]] auto json_to_xml(std::uint32_t shape, const boost::json::object& value) const
        -> std::string {
        aws_query::xml_writer w;
        write_members(w, shape, value);
        return w.str();
    }

private:
    using form_params = std::map<std::string, std::string, std::less<>>;
    using failure = std::optional<aws_json::error>;

    /// Members validated as a list of strings instead of by their model
    /// shape. ReceiveMessage's `AttributeNames` is modeled as queue
    /// attribute names, but every SDK sends message system attribute names
    /// in it (`SentTimestamp`, `MessageGroupId`; boto3 and the Java SDK in
    /// the task 1 evidence), which SQS accepts: it predates
    /// `MessageSystemAttributeNames`. The handler checks the names.
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 1> k_lenient{{
        {"ReceiveMessage", "AttributeNames"},
    }};

    /// Validates `input` against `op`'s input shape, with `k_lenient`'s
    /// members lifted out for the duration and checked by type only.
    [[nodiscard]] auto validate(const aws_json::operation& op, boost::json::object& input) const
        -> failure {
        if (op.input == aws_json::no_shape) {
            return std::nullopt;
        }
        std::vector<std::pair<std::string_view, boost::json::value>> lifted;
        for (const auto& [name, member] : k_lenient) {
            if (op.name != name) {
                continue;
            }
            if (auto* v = input.if_contains(member)) {
                const bool strings =
                    v->is_array() &&
                    std::all_of(v->get_array().begin(), v->get_array().end(),
                                [](const boost::json::value& e) { return e.is_string(); });
                if (!strings) {
                    return make_error(k_validation_error,
                                      "1 validation error detected: Value at '" +
                                          std::string(member) +
                                          "' failed to satisfy constraint: Member must be a "
                                          "list of strings");
                }
                lifted.emplace_back(member, std::move(*v));
                input.erase(member);
            }
        }
        const boost::json::value whole(input);
        auto e = _json.validator().validate(op.input, whole, _json.options().style);
        for (auto& [member, v] : lifted) {
            input[member] = std::move(v);
        }
        return e;
    }

    /// A JSON 1.0 request: core's framing (size, target, body), then
    /// `validate`.
    [[nodiscard]] auto parse_json(const sqs_request_view& req) const
        -> aws_json::result<sqs_parsed_request> {
        const auto& style = _json.options().style;
        if (req.body.size() > _options.limits.max_body_bytes) {
            return make_error(k_too_large_error,
                              "Request body of " + std::to_string(req.body.size()) +
                                  " bytes exceeds the limit of " +
                                  std::to_string(_options.limits.max_body_bytes) + " bytes");
        }
        const auto* op = _json.resolve_target(aws_json::http_request_view{
            .method = req.method,
            .path = req.path,
            .content_type = req.content_type,
            .target = req.target,
            .body = req.body,
        });
        if (op == nullptr) {
            aws_json::error e;
            e.type = style.unknown_operation_type;
            return e;
        }
        boost::json::value body = boost::json::object{};
        if (!req.body.empty()) {
            boost::json::parse_options po;
            po.max_depth = _options.limits.max_depth;
            boost::system::error_code ec;
            body = boost::json::parse(req.body, ec, {}, po);
            if (ec || !body.is_object()) {
                return make_error(k_serialization_error,
                                  ec == boost::json::error::too_deep
                                      ? "Request nesting exceeds the maximum depth"
                                      : "Unable to parse the request body as a JSON object");
            }
        }
        auto input = std::move(body.as_object());
        if (auto e = validate(*op, input)) {
            return std::move(*e);
        }
        return sqs_parsed_request{op, std::move(input)};
    }

    [[nodiscard]] auto shape(std::uint32_t i) const -> const aws_json::shape& {
        return model().shapes[i];
    }

    /// The query names of member `index` of the model. Every structure
    /// member has an entry (the generator covers them all); the fallback
    /// is for exception shapes, which are never read from a form.
    [[nodiscard]] auto names(std::uint32_t index) const -> sqs_query::member_names {
        if (const auto* n = _names[index]) {
            return *n;
        }
        const auto& m = model().members[index];
        return {"", m.name, m.name, "member", "key", "value", false};
    }

    /// The positive indices under `base.` in index order.
    [[nodiscard]] static auto indices(const form_params& params, const std::string& base)
        -> std::optional<std::vector<std::size_t>> {
        const auto prefix = base + ".";
        std::vector<std::size_t> out;
        for (auto it = params.lower_bound(prefix);
             it != params.end() && it->first.starts_with(prefix); ++it) {
            auto rest = std::string_view(it->first).substr(prefix.size());
            rest = rest.substr(0, rest.find('.'));
            const auto idx = parse_index(rest);
            if (!idx) {
                return std::nullopt;
            }
            out.push_back(*idx);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    [[nodiscard]] static auto parse_index(std::string_view s) -> std::optional<std::size_t> {
        std::size_t v = 0;
        if (s.empty() || s.front() == '0') {
            return std::nullopt;
        }
        const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (ec != std::errc{} || p != s.data() + s.size()) {
            return std::nullopt;
        }
        return v;
    }

    [[nodiscard]] static auto bad_value(std::string_view param, std::string_view value,
                                        std::string_view reason) -> aws_json::error {
        return make_error(k_validation_error, "Value " + std::string(value) + " for parameter " +
                                                  std::string(param) +
                                                  " is invalid. Reason: " + std::string(reason));
    }

    [[nodiscard]] static auto bad_index(std::string_view param) -> aws_json::error {
        return make_error(k_validation_error, "Parameter " + std::string(param) +
                                                  " has an index that is not a "
                                                  "positive whole number.");
    }

    /// Reads the value of shape `s` at parameter `path` into `out`; leaves
    /// `out` null when nothing is there.
    [[nodiscard]] auto read_value(const aws_query::form& f, std::uint32_t s,
                                  const std::string& path, const std::string& item,
                                  const std::string& key, const std::string& value, bool flattened,
                                  boost::json::value& out) const -> failure {
        const auto& sh = shape(s);
        const auto& params = f.params();
        switch (sh.kind) {
            case aws_json::shape_kind::structure:
                return read_structure(f, s, path + ".", out);
            case aws_json::shape_kind::list: {
                const auto base = flattened ? path : path + "." + item;
                const auto idx = indices(params, base);
                if (!idx) {
                    return bad_index(base);
                }
                if (idx->empty()) {
                    return std::nullopt;
                }
                boost::json::array arr;
                for (const auto i : *idx) {
                    boost::json::value v;
                    // A list element has no names of its own: SQS's lists hold
                    // strings, blobs and structures, none of them lists or maps.
                    if (auto e = read_value(f, sh.element, base + "." + std::to_string(i), "member",
                                            "key", "value", false, v)) {
                        return e;
                    }
                    if (!v.is_null()) {
                        arr.push_back(std::move(v));
                    }
                }
                out = std::move(arr);
                return std::nullopt;
            }
            case aws_json::shape_kind::map: {
                const auto base = flattened ? path : path + ".entry";
                const auto idx = indices(params, base);
                if (!idx) {
                    return bad_index(base);
                }
                if (idx->empty()) {
                    return std::nullopt;
                }
                boost::json::object obj;
                for (const auto i : *idx) {
                    const auto entry = base + "." + std::to_string(i);
                    const auto k = f.get(entry + "." + key);
                    if (!k) {
                        return make_error(
                            k_missing_parameter_error,
                            "The request must contain the parameter " + entry + "." + key + ".");
                    }
                    boost::json::value v;
                    if (auto e = read_value(f, sh.element, entry + "." + value, "member", "key",
                                            "value", false, v)) {
                        return e;
                    }
                    if (v.is_null()) {
                        return make_error(
                            k_missing_parameter_error,
                            "The request must contain the parameter " + entry + "." + value + ".");
                    }
                    obj[*k] = std::move(v);
                }
                out = std::move(obj);
                return std::nullopt;
            }
            default:
                break;
        }
        const auto text = f.get(path);
        if (!text) {
            return std::nullopt;
        }
        switch (sh.kind) {
            case aws_json::shape_kind::boolean:
                if (*text == "true") {
                    out = true;
                } else if (*text == "false") {
                    out = false;
                } else {
                    return bad_value(path, *text, "Must be true or false.");
                }
                return std::nullopt;
            case aws_json::shape_kind::integer:
            case aws_json::shape_kind::long_: {
                std::int64_t n = 0;
                const auto [p, ec] = std::from_chars(text->data(), text->data() + text->size(), n);
                const bool narrow = sh.kind == aws_json::shape_kind::integer &&
                                    (n < std::numeric_limits<std::int32_t>::min() ||
                                     n > std::numeric_limits<std::int32_t>::max());
                if (text->empty() || ec != std::errc{} || p != text->data() + text->size() ||
                    narrow) {
                    return bad_value(path, *text, "Must be a whole number.");
                }
                out = n;
                return std::nullopt;
            }
            case aws_json::shape_kind::float_:
            case aws_json::shape_kind::double_:
            case aws_json::shape_kind::timestamp: {
                double d = 0;
                const auto [p, ec] = std::from_chars(text->data(), text->data() + text->size(), d);
                if (text->empty() || ec != std::errc{} || p != text->data() + text->size()) {
                    return bad_value(path, *text, "Must be a number.");
                }
                out = d;
                return std::nullopt;
            }
            default:  // string and blob (base64 text in both protocols)
                out = boost::json::string(*text);
                return std::nullopt;
        }
    }

    [[nodiscard]] auto read_structure(const aws_query::form& f, std::uint32_t s,
                                      const std::string& prefix, boost::json::value& out) const
        -> failure {
        const auto& sh = shape(s);
        boost::json::object obj;
        for (std::uint32_t i = 0; i < sh.count; ++i) {
            const auto index = sh.first + i;
            const auto& m = model().members[index];
            const auto n = names(index);
            const bool flat_list = n.flattened && shape(m.shape).kind == aws_json::shape_kind::list;
            const auto path = prefix + std::string(flat_list ? n.item : n.name);
            boost::json::value v;
            if (auto e = read_value(f, m.shape, path, std::string(n.item), std::string(n.key),
                                    std::string(n.value), n.flattened, v)) {
                return e;
            }
            if (!v.is_null()) {
                obj[m.name] = std::move(v);
            }
        }
        // A structure with nothing in it is absent, unless it is the
        // request itself.
        if (!obj.empty() || prefix.empty()) {
            out = std::move(obj);
        }
        return std::nullopt;
    }

    void fill_queue_url(std::string_view path, std::uint32_t input,
                        boost::json::object& obj) const {
        if (path.empty() || path == "/" || obj.contains("QueueUrl")) {
            return;
        }
        const auto members = model().members_of(shape(input));
        if (std::none_of(members.begin(), members.end(),
                         [](const aws_json::member& m) { return m.name == "QueueUrl"; })) {
            return;
        }
        obj["QueueUrl"] = _options.endpoint + std::string(path);
    }

    static void write_scalar(aws_query::xml_writer& w, std::string_view tag,
                             const boost::json::value& v) {
        if (v.is_string()) {
            w.element(tag, v.get_string());
        } else if (v.is_bool()) {
            w.boolean(tag, v.get_bool());
        } else if (v.is_int64()) {
            w.element(tag, std::to_string(v.get_int64()));
        } else if (v.is_uint64()) {
            w.element(tag, std::to_string(v.get_uint64()));
        } else if (v.is_double()) {
            w.element(tag, boost::json::serialize(v));
        }
    }

    void write_value(aws_query::xml_writer& w, std::uint32_t s, std::string_view tag,
                     const sqs_query::member_names& n, const boost::json::value& v) const {
        const auto& sh = shape(s);
        switch (sh.kind) {
            case aws_json::shape_kind::structure:
                if (v.is_object()) {
                    w.open(tag);
                    write_members(w, s, v.get_object());
                    w.close();
                }
                return;
            case aws_json::shape_kind::list: {
                if (!v.is_array()) {
                    return;
                }
                const sqs_query::member_names plain{"", "", "", "member", "key", "value", false};
                if (n.flattened) {
                    for (const auto& e : v.get_array()) {
                        write_value(w, sh.element, n.item, plain, e);
                    }
                } else {
                    w.open(tag);
                    for (const auto& e : v.get_array()) {
                        write_value(w, sh.element, n.item, plain, e);
                    }
                    w.close();
                }
                return;
            }
            case aws_json::shape_kind::map: {
                if (!v.is_object()) {
                    return;
                }
                const sqs_query::member_names plain{"", "", "", "member", "key", "value", false};
                if (!n.flattened) {
                    w.open(tag);
                }
                for (const auto& kv : v.get_object()) {
                    w.open(n.flattened ? tag : std::string_view("entry"));
                    w.element(n.key, kv.key());
                    write_value(w, sh.element, n.value, plain, kv.value());
                    w.close();
                }
                if (!n.flattened) {
                    w.close();
                }
                return;
            }
            default:
                write_scalar(w, tag, v);
        }
    }

    void write_members(aws_query::xml_writer& w, std::uint32_t s,
                       const boost::json::object& obj) const {
        const auto& sh = shape(s);
        for (std::uint32_t i = 0; i < sh.count; ++i) {
            const auto index = sh.first + i;
            const auto& m = model().members[index];
            const auto* v = obj.if_contains(m.name);
            if (v == nullptr || v->is_null()) {
                continue;
            }
            const auto n = names(index);
            write_value(w, m.shape, n.name, n, *v);
        }
    }

    sqs_codec_options _options;
    aws_json::codec _json;
    std::vector<const sqs_query::member_names*> _names;  // parallel to the model's members
};

}  // namespace kythira::sqs
