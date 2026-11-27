// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_post_policy.hpp
/// @brief Browser POST uploads: the multipart/form-data body, the policy
///        document and its SigV4 signature (.kiro/specs/s3-compatible-storage/
///        task 6, Requirement 4.3).
///
/// **The form.** `form_reader` parses the body as it arrives. The fields
/// before the `file` field are kept (at most 20 KB of them, S3's
/// `MaxPostPreDataLengthExceeded`); the file's bytes go to the caller as
/// they arrive, and fields after the file are ignored, as S3 ignores them.
/// Once `fields_complete()` the form is known, so the caller authenticates
/// and checks the policy before storing a byte of the file.
///
/// **The signature.** A form with a `policy` is signed: `x-amz-algorithm`
/// `AWS4-HMAC-SHA256`, `x-amz-credential`, `x-amz-date` and
/// `x-amz-signature`, the hex HMAC of the base64 policy under the
/// credential's signing key. That is a SigV4 signature whose string to
/// sign is the policy, so it goes through the same key resolution and
/// `sigv4::verify` as header signatures, by way of a claim built from the
/// form (`aws_claim_resolver` is required). A form with neither a policy
/// nor a signature is anonymous, for a bucket whose policy lets anyone
/// write. SigV2 forms (`AWSAccessKeyId`, `signature`) are refused as SigV2
/// is everywhere else.
///
/// **The policy.** `expiration` (ISO 8601, UTC) must not have passed, and
/// every condition must hold: `{"field": "value"}` and `["eq", "$field",
/// "value"]` exactly, `["starts-with", "$field", "prefix"]` by prefix (each
/// comma-separated value for `Content-Type`), and `["content-length-range",
/// min, max]` once the file's size is known. `bucket` is matched against
/// the request's bucket. Every form field but `policy`, `x-amz-signature`,
/// `file` and `x-ignore-*` must be named by some condition, or the upload
/// is refused for its extra fields. Field names match without regard to
/// case. The policy's conditions bound the upload; whether the signer may
/// write there at all is still the access check's (`s3_access.hpp`), with
/// `s3:authType` `POST`.

#include <kythira/s3/s3_auth.hpp>

#include <raft/aws_json_protocol.hpp>
#include <raft/aws_request_authorizer.hpp>
#include <raft/aws_rest_xml_protocol.hpp>
#include <raft/sigv4_verifier.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

[[nodiscard]] inline auto malformed_post() -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        400, "MalformedPOSTRequest",
        "The body of your POST request is not well-formed multipart/form-data.");
}

[[nodiscard]] inline auto post_field_missing(std::string_view field) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(
        400, "InvalidArgument",
        "Bucket POST must contain a field named '" + std::string(field) +
            "'.  If it is specified, please check the order of the fields.");
}

[[nodiscard]] inline auto policy_refused(std::string why) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(403, "AccessDenied",
                                      "Invalid according to Policy: " + std::move(why));
}

[[nodiscard]] inline auto invalid_policy_document(std::string why) -> aws_rest_xml::error {
    return aws_rest_xml::errors::make(400, "InvalidPolicyDocument",
                                      "Invalid Policy: " + std::move(why));
}

// ---------------------------------------------------------------------------
// The form
// ---------------------------------------------------------------------------

/// The fields of a POST form, as far as `form_reader` keeps them.
struct post_form {
    /// Fields before the file, in order, names as sent.
    std::vector<std::pair<std::string, std::string>> fields;
    /// The file part's `filename` and `Content-Type`.
    std::string filename;
    std::string file_content_type;

    /// The first field named `name`, without regard to case.
    [[nodiscard]] auto get(std::string_view name) const -> std::optional<std::string> {
        for (const auto& [k, v] : fields) {
            if (aws_rest_xml::detail::iequals(k, name)) {
                return v;
            }
        }
        return std::nullopt;
    }

    /// The object key: the `key` field with `${filename}` replaced by the
    /// file's name, as S3 does.
    [[nodiscard]] auto object_key() const -> std::optional<std::string> {
        auto key = get("key");
        if (!key) {
            return std::nullopt;
        }
        static constexpr std::string_view token = "${filename}";
        for (auto at = key->find(token); at != std::string::npos;
             at = key->find(token, at + filename.size())) {
            key->replace(at, token.size(), filename);
        }
        return key;
    }
};

struct form_limits {
    std::size_t max_field_bytes = 20 * 1024;  ///< everything before the file
    std::size_t max_part_header_bytes = 8 * 1024;
};

namespace post_detail {

[[nodiscard]] inline auto trim(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

/// A header's `;`-separated parameter (`name="x"`), unquoted.
[[nodiscard]] inline auto parameter(std::string_view value, std::string_view name)
    -> std::optional<std::string> {
    std::size_t i = value.find(';');
    while (i != std::string_view::npos && i < value.size()) {
        ++i;
        while (i < value.size() && (value[i] == ' ' || value[i] == '\t')) {
            ++i;
        }
        const auto eq = value.find('=', i);
        if (eq == std::string_view::npos) {
            return std::nullopt;
        }
        const auto key = trim(value.substr(i, eq - i));
        std::string v;
        std::size_t j = eq + 1;
        if (j < value.size() && value[j] == '"') {
            for (++j; j < value.size() && value[j] != '"'; ++j) {
                if (value[j] == '\\' && j + 1 < value.size()) {
                    ++j;
                }
                v += value[j];
            }
            j = value.find(';', j);
        } else {
            const auto end = value.find(';', j);
            v = std::string(trim(value.substr(j, end == std::string_view::npos ? end : end - j)));
            j = end;
        }
        if (aws_rest_xml::detail::iequals(key, name)) {
            return v;
        }
        i = j;
    }
    return std::nullopt;
}

}  // namespace post_detail

/// The boundary of a `multipart/form-data` Content-Type, or nothing when
/// the request is not one.
[[nodiscard]] inline auto form_boundary(std::string_view content_type)
    -> std::optional<std::string> {
    const auto semi = content_type.find(';');
    const auto type = post_detail::trim(content_type.substr(0, semi));
    if (!aws_rest_xml::detail::iequals(type, "multipart/form-data")) {
        return std::nullopt;
    }
    auto b = post_detail::parameter(content_type, "boundary");
    if (!b || b->empty() || b->size() > 70) {
        return std::nullopt;
    }
    return b;
}

/// A streaming `multipart/form-data` parser for POST uploads.
class form_reader {
public:
    enum class status : std::uint8_t {
        fields,  ///< still reading the fields before the file
        file,    ///< the form is known; file bytes are flowing
        done,    ///< the closing boundary was read
        failed,
    };

    explicit form_reader(std::string_view boundary, form_limits limits = {})
        : _delim("\r\n--" + std::string(boundary)), _limits(limits), _buf("\r\n") {}

    /// Consume `in`; file bytes are appended to `file_out`.
    auto feed(std::string_view in, std::string& file_out) -> status {
        if (_status == status::failed || _status == status::done) {
            return _status;
        }
        _buf.append(in);
        while (step(file_out)) {
        }
        return _status;
    }

    /// The body ended.
    auto finish() -> status {
        if (_status == status::failed) {
            return _status;
        }
        if (_status != status::done) {
            fail(_saw_file || _status == status::file ? malformed_post() : no_file());
        } else if (!_saw_file) {
            fail(no_file());
        }
        return _status;
    }

    [[nodiscard]] auto state() const noexcept -> status { return _status; }
    /// The form is known (the file part has begun).
    [[nodiscard]] auto fields_complete() const noexcept -> bool { return _saw_file; }
    [[nodiscard]] auto form() const noexcept -> const post_form& { return _form; }
    [[nodiscard]] auto error() const -> const aws_rest_xml::error& { return *_error; }
    [[nodiscard]] auto file_bytes() const noexcept -> std::uint64_t { return _file_bytes; }

private:
    enum class at : std::uint8_t {
        preamble,
        after_delim,
        headers,
        body,
        epilogue
    };
    enum class part : std::uint8_t {
        field,
        file,
        ignored
    };

    static auto no_file() -> aws_rest_xml::error {
        return aws_rest_xml::errors::make(400, "InvalidArgument",
                                          "POST requires exactly one file upload per request.");
    }

    void fail(aws_rest_xml::error e) {
        _error = std::move(e);
        _status = status::failed;
        _buf.clear();
    }

    /// One step of the parse; false when more input is needed or it ended.
    auto step(std::string& file_out) -> bool {
        switch (_at) {
            case at::preamble: {
                const auto d = _buf.find(_delim);
                if (d == std::string::npos) {
                    if (_buf.size() > 64 * 1024) {
                        fail(malformed_post());
                        return false;
                    }
                    return false;
                }
                _buf.erase(0, d + _delim.size());
                _at = at::after_delim;
                return true;
            }
            case at::after_delim: {
                if (_buf.size() < 2) {
                    return false;
                }
                if (_buf.starts_with("--")) {
                    _at = at::epilogue;
                    _status = status::done;
                    _buf.clear();
                    return false;
                }
                // Transport padding (spaces, tabs) may follow a boundary.
                const auto crlf = _buf.find("\r\n");
                if (crlf == std::string::npos) {
                    if (_buf.size() > 256) {
                        fail(malformed_post());
                    }
                    return false;
                }
                if (!post_detail::trim(std::string_view(_buf).substr(0, crlf)).empty()) {
                    fail(malformed_post());
                    return false;
                }
                _buf.erase(0, crlf);  // keep the CRLF: headers start after it
                _at = at::headers;
                return true;
            }
            case at::headers: {
                const auto end = _buf.find("\r\n\r\n");
                if (end == std::string::npos) {
                    if (_buf.size() > _limits.max_part_header_bytes) {
                        fail(malformed_post());
                    }
                    return false;
                }
                if (end > _limits.max_part_header_bytes) {
                    fail(malformed_post());
                    return false;
                }
                const std::string headers = _buf.substr(2, end > 2 ? end - 2 : 0);
                _buf.erase(0, end + 4);
                if (!begin_part(headers)) {
                    return false;
                }
                _at = at::body;
                return true;
            }
            case at::body: {
                const auto d = _buf.find(_delim);
                const bool whole = d != std::string::npos;
                const std::size_t keep = _delim.size() - 1;
                const std::size_t n =
                    whole ? d : (_buf.size() > keep ? _buf.size() - keep : std::size_t{0});
                if (n > 0 && !take(std::string_view(_buf).substr(0, n), file_out)) {
                    return false;
                }
                if (!whole) {
                    _buf.erase(0, n);
                    return false;
                }
                _buf.erase(0, d + _delim.size());
                if (_part == part::field) {
                    _form.fields.emplace_back(std::move(_name), std::move(_value));
                    _name.clear();
                    _value.clear();
                }
                _at = at::after_delim;
                return true;
            }
            case at::epilogue:
                _buf.clear();
                return false;
        }
        return false;
    }

    auto begin_part(std::string_view headers) -> bool {
        std::optional<std::string> name;
        std::string filename;
        std::string content_type;
        while (!headers.empty()) {
            const auto eol = headers.find("\r\n");
            const auto line = headers.substr(0, eol);
            headers = eol == std::string_view::npos ? std::string_view{} : headers.substr(eol + 2);
            const auto colon = line.find(':');
            if (colon == std::string_view::npos) {
                fail(malformed_post());
                return false;
            }
            const auto key = post_detail::trim(line.substr(0, colon));
            const auto value = post_detail::trim(line.substr(colon + 1));
            if (aws_rest_xml::detail::iequals(key, "Content-Disposition")) {
                const auto type = post_detail::trim(value.substr(0, value.find(';')));
                if (!aws_rest_xml::detail::iequals(type, "form-data")) {
                    fail(malformed_post());
                    return false;
                }
                name = post_detail::parameter(value, "name");
                filename = post_detail::parameter(value, "filename").value_or("");
            } else if (aws_rest_xml::detail::iequals(key, "Content-Type")) {
                content_type = std::string(value);
            }
        }
        if (!name) {
            fail(malformed_post());
            return false;
        }
        if (_saw_file) {
            _part = part::ignored;  // S3 ignores fields after the file
        } else if (aws_rest_xml::detail::iequals(*name, "file")) {
            _part = part::file;
            _saw_file = true;
            _form.filename = std::move(filename);
            _form.file_content_type = std::move(content_type);
            _status = status::file;
        } else {
            _part = part::field;
            _name = std::move(*name);
            _field_bytes += _name.size();
            if (_field_bytes > _limits.max_field_bytes) {
                fail(too_large());
                return false;
            }
        }
        return true;
    }

    static auto too_large() -> aws_rest_xml::error {
        return aws_rest_xml::errors::make(
            400, "MaxPostPreDataLengthExceeded",
            "Your POST request fields preceding the upload file were too large.");
    }

    auto take(std::string_view data, std::string& file_out) -> bool {
        switch (_part) {
            case part::field:
                _field_bytes += data.size();
                if (_field_bytes > _limits.max_field_bytes) {
                    fail(too_large());
                    return false;
                }
                _value.append(data);
                return true;
            case part::file:
                _file_bytes += data.size();
                file_out.append(data);
                return true;
            case part::ignored:
                return true;
        }
        return true;
    }

    std::string _delim;
    form_limits _limits;
    std::string _buf;
    at _at = at::preamble;
    part _part = part::ignored;
    status _status = status::fields;
    bool _saw_file = false;
    std::string _name;
    std::string _value;
    std::size_t _field_bytes = 0;
    std::uint64_t _file_bytes = 0;
    post_form _form;
    std::optional<aws_rest_xml::error> _error;
};

// ---------------------------------------------------------------------------
// The policy document
// ---------------------------------------------------------------------------

struct post_condition {
    enum class kind : std::uint8_t {
        eq,
        starts_with,
        content_length_range
    };
    kind op = kind::eq;
    std::string field;  ///< lower case, without `$`
    std::string value;
    std::uint64_t min = 0;
    std::uint64_t max = 0;
};

struct post_policy {
    std::chrono::sys_time<std::chrono::milliseconds> expiration{};
    std::vector<post_condition> conditions;
};

namespace post_detail {

/// `2026-11-18T12:00:00Z` or `2026-11-18T12:00:00.000Z`.
[[nodiscard]] inline auto parse_iso8601(std::string_view s)
    -> std::optional<std::chrono::sys_time<std::chrono::milliseconds>> {
    const auto num = [&](std::size_t at, std::size_t len) -> int {
        if (at + len > s.size()) {
            return -1;
        }
        int v = 0;
        for (std::size_t i = at; i < at + len; ++i) {
            if (s[i] < '0' || s[i] > '9') {
                return -1;
            }
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    if (s.size() < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s.back() != 'Z') {
        return std::nullopt;
    }
    const int y = num(0, 4);
    const int mo = num(5, 2);
    const int d = num(8, 2);
    const int h = num(11, 2);
    const int mi = num(14, 2);
    const int sec = num(17, 2);
    int ms = 0;
    if (s.size() != 20) {
        if (s[19] != '.' || s.size() < 22 || s.size() > 30) {
            return std::nullopt;
        }
        const auto frac = s.substr(20, s.size() - 21);
        for (std::size_t i = 0; i < frac.size(); ++i) {
            if (frac[i] < '0' || frac[i] > '9') {
                return std::nullopt;
            }
            if (i < 3) {
                ms = ms * 10 + (frac[i] - '0');
            }
        }
        for (std::size_t i = frac.size(); i < 3; ++i) {
            ms *= 10;
        }
    }
    if (y < 0 || mo < 1 || d < 1 || h < 0 || h > 23 || mi < 0 || mi > 59 || sec < 0 || sec > 60) {
        return std::nullopt;
    }
    const std::chrono::year_month_day ymd{std::chrono::year(y),
                                          std::chrono::month(static_cast<unsigned>(mo)),
                                          std::chrono::day(static_cast<unsigned>(d))};
    if (!ymd.ok()) {
        return std::nullopt;
    }
    return std::chrono::sys_days(ymd) + std::chrono::hours(h) + std::chrono::minutes(mi) +
           std::chrono::seconds(sec) + std::chrono::milliseconds(ms);
}

[[nodiscard]] inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    for (auto& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

[[nodiscard]] inline auto field_name(const boost::json::value& v) -> std::optional<std::string> {
    if (!v.is_string() || v.as_string().empty() || v.as_string()[0] != '$') {
        return std::nullopt;
    }
    return lower(std::string_view(v.as_string()).substr(1));
}

[[nodiscard]] inline auto to_u64(const boost::json::value& v) -> std::optional<std::uint64_t> {
    if (v.is_uint64()) {
        return v.as_uint64();
    }
    if (v.is_int64() && v.as_int64() >= 0) {
        return static_cast<std::uint64_t>(v.as_int64());
    }
    if (v.is_string() && !v.as_string().empty() && v.as_string().size() <= 19) {
        std::uint64_t n = 0;
        for (char c : v.as_string()) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            n = n * 10 + static_cast<std::uint64_t>(c - '0');
        }
        return n;
    }
    return std::nullopt;
}

}  // namespace post_detail

/// The policy document (already base64-decoded).
[[nodiscard]] inline auto parse_post_policy(std::string_view json)
    -> aws_rest_xml::result<post_policy> {
    boost::system::error_code ec;
    const auto v = boost::json::parse(json, ec);
    if (ec || !v.is_object()) {
        return invalid_policy_document("Invalid JSON.");
    }
    const auto& o = v.as_object();
    post_policy p;
    const auto* exp = o.if_contains("expiration");
    if (exp == nullptr || !exp->is_string()) {
        return invalid_policy_document("Policy missing expiration.");
    }
    auto when = post_detail::parse_iso8601(std::string_view(exp->as_string()));
    if (!when) {
        return invalid_policy_document("Invalid 'expiration' value: '" +
                                       std::string(exp->as_string()) + "'");
    }
    p.expiration = *when;
    const auto* conds = o.if_contains("conditions");
    if (conds == nullptr || !conds->is_array()) {
        return invalid_policy_document("Policy missing conditions.");
    }
    for (const auto& c : conds->as_array()) {
        post_condition pc;
        if (c.is_object()) {
            const auto& co = c.as_object();
            if (co.size() != 1 || !co.begin()->value().is_string()) {
                return invalid_policy_document("Invalid simple condition: " +
                                               boost::json::serialize(c));
            }
            pc.field = post_detail::lower(std::string_view(co.begin()->key()));
            pc.value = std::string(co.begin()->value().as_string());
        } else if (c.is_array() && c.as_array().size() == 3 && c.as_array()[0].is_string()) {
            const auto& a = c.as_array();
            const auto op = post_detail::lower(std::string_view(a[0].as_string()));
            if (op == "content-length-range") {
                const auto lo = post_detail::to_u64(a[1]);
                const auto hi = post_detail::to_u64(a[2]);
                if (!lo || !hi || *lo > *hi) {
                    return invalid_policy_document("Invalid content-length-range: " +
                                                   boost::json::serialize(c));
                }
                pc.op = post_condition::kind::content_length_range;
                pc.min = *lo;
                pc.max = *hi;
            } else if (op == "eq" || op == "starts-with") {
                auto f = post_detail::field_name(a[1]);
                if (!f || !a[2].is_string()) {
                    return invalid_policy_document("Invalid condition: " +
                                                   boost::json::serialize(c));
                }
                pc.op = op == "eq" ? post_condition::kind::eq : post_condition::kind::starts_with;
                pc.field = std::move(*f);
                pc.value = std::string(a[2].as_string());
            } else {
                return invalid_policy_document("Invalid condition: " + boost::json::serialize(c));
            }
        } else {
            return invalid_policy_document("Invalid condition: " + boost::json::serialize(c));
        }
        p.conditions.push_back(std::move(pc));
    }
    return p;
}

namespace post_detail {

[[nodiscard]] inline auto describe(const post_condition& c) -> std::string {
    switch (c.op) {
        case post_condition::kind::eq:
            return R"(["eq", "$)" + c.field + R"(", ")" + c.value + R"("])";
        case post_condition::kind::starts_with:
            return R"(["starts-with", "$)" + c.field + R"(", ")" + c.value + R"("])";
        case post_condition::kind::content_length_range:
            return R"(["content-length-range", )" + std::to_string(c.min) + ", " +
                   std::to_string(c.max) + "]";
    }
    return {};
}

/// Fields that need no condition.
[[nodiscard]] inline auto exempt(std::string_view lower_name) -> bool {
    return lower_name == "policy" || lower_name == "x-amz-signature" || lower_name == "file" ||
           lower_name.starts_with("x-ignore-");
}

}  // namespace post_detail

/// Whether the form satisfies the policy at `now` (all but the length,
/// which `check_post_length` checks once the file is in).
[[nodiscard]] inline auto check_post_policy(const post_policy& p, const post_form& form,
                                            std::string_view bucket,
                                            std::chrono::system_clock::time_point now)
    -> std::optional<aws_rest_xml::error> {
    if (now > p.expiration) {
        return policy_refused("Policy expired.");
    }
    for (const auto& c : p.conditions) {
        if (c.op == post_condition::kind::content_length_range) {
            continue;
        }
        const std::string actual =
            c.field == "bucket" ? std::string(bucket) : form.get(c.field).value_or("");
        bool ok = false;
        if (c.op == post_condition::kind::eq) {
            ok = actual == c.value;
        } else if (c.field == "content-type") {
            ok = true;
            std::string_view rest = actual;
            do {
                const auto comma = rest.find(',');
                const auto item = post_detail::trim(rest.substr(0, comma));
                ok = ok && item.starts_with(c.value);
                rest =
                    comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            } while (!rest.empty());
        } else {
            ok = actual.starts_with(c.value);
        }
        if (!ok) {
            return policy_refused("Policy Condition failed: " + post_detail::describe(c));
        }
    }
    std::string extra;
    for (const auto& [name, value] : form.fields) {
        const auto n = post_detail::lower(name);
        if (post_detail::exempt(n)) {
            continue;
        }
        const bool named = std::ranges::any_of(p.conditions, [&](const post_condition& c) {
            return c.op != post_condition::kind::content_length_range && c.field == n;
        });
        if (!named) {
            extra += extra.empty() ? "" : ", ";
            extra += name;
        }
    }
    if (!extra.empty()) {
        return policy_refused("Extra input fields: " + extra);
    }
    return std::nullopt;
}

/// The file's size against the policy's `content-length-range`, if any.
[[nodiscard]] inline auto check_post_length(const post_policy& p, std::uint64_t size)
    -> std::optional<aws_rest_xml::error> {
    for (const auto& c : p.conditions) {
        if (c.op != post_condition::kind::content_length_range) {
            continue;
        }
        if (size < c.min) {
            return aws_rest_xml::errors::make(
                400, "EntityTooSmall",
                "Your proposed upload is smaller than the minimum allowed size");
        }
        if (size > c.max) {
            return aws_rest_xml::errors::make(
                400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size");
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// What a POST form established: who signed it and the policy that bounds
/// it (none when anonymous), and the key it names.
struct post_request {
    authenticated auth;
    std::optional<post_policy> policy;
    std::string key;
};

/// Authenticate a POST form for `bucket` and check its policy (all but
/// the length). `now` is the clock the policy's expiration is judged by.
template<aws_auth::aws_request_authorizer A>
[[nodiscard]] auto authenticate_post(A& authorizer, const post_form& form, std::string_view bucket,
                                     const sigv4::service_rules& rules,
                                     std::chrono::system_clock::time_point now)
    -> aws_rest_xml::result<post_request> {
    post_request out;
    auto key = form.object_key();
    if (!key || key->empty()) {
        return post_field_missing("key");
    }
    out.key = std::move(*key);

    const auto policy_b64 = form.get("policy");
    const auto signature = form.get("x-amz-signature");
    if (!signature && (form.get("AWSAccessKeyId") || form.get("signature"))) {
        return unsupported_signature();
    }
    if (!policy_b64 && !signature) {
        return out;  // anonymous
    }
    if (!policy_b64) {
        return post_field_missing("policy");
    }
    for (std::string_view f : {"x-amz-algorithm", "x-amz-credential", "x-amz-date"}) {
        if (!form.get(f)) {
            return post_field_missing(f);
        }
    }
    if (!signature) {
        return post_field_missing("x-amz-signature");
    }
    const auto algorithm = *form.get("x-amz-algorithm");
    if (algorithm == "AWS4-ECDSA-P256-SHA256") {
        return unsupported_signature();
    }
    if (algorithm != "AWS4-HMAC-SHA256") {
        return aws_rest_xml::errors::make(400, "InvalidArgument",
                                          "Unsupported x-amz-algorithm: " + algorithm);
    }

    // The credential: AKID/date/region/s3/aws4_request.
    const auto credential = *form.get("x-amz-credential");
    std::vector<std::string> parts;
    for (std::size_t i = 0;;) {
        const auto slash = credential.find('/', i);
        parts.push_back(credential.substr(i, slash == std::string::npos ? slash : slash - i));
        if (slash == std::string::npos) {
            break;
        }
        i = slash + 1;
    }
    const auto bad_credential = [&](std::string why) {
        return aws_rest_xml::errors::make(
            400, "InvalidArgument", "Invalid credential: " + credential + ". " + std::move(why));
    };
    if (parts.size() != 5 || parts[0].empty() || parts[4] != "aws4_request") {
        return bad_credential("Expected AKID/date/region/service/aws4_request.");
    }
    if (parts[3] != rules.service) {
        return bad_credential("The service must be '" + rules.service + "'.");
    }
    if (!rules.regions.empty() &&
        std::ranges::find(rules.regions, parts[2]) == rules.regions.end()) {
        return bad_credential("The region '" + parts[2] + "' is wrong.");
    }
    const auto amz_date = *form.get("x-amz-date");
    const auto when = sigv4::detail::parse_amz_date(amz_date);
    if (!when || !amz_date.starts_with(parts[1])) {
        return aws_rest_xml::errors::make(400, "InvalidArgument",
                                          "X-Amz-Date must be yyyyMMdd'T'HHmmss'Z' and match the "
                                          "credential's date.");
    }

    // The policy, before the (costlier) key resolution.
    const auto decoded = aws_json::base64_decode(*policy_b64);
    if (!decoded) {
        return invalid_policy_document("Policy is not valid base64.");
    }
    auto policy = parse_post_policy(std::string_view(reinterpret_cast<const char*>(decoded->data()),
                                                     decoded->size()));  // NOLINT
    if (!policy) {
        return policy.error();
    }

    sigv4::claim c;
    c.access_key_id = parts[0];
    c.scope = {parts[1], parts[2], parts[3]};
    c.amz_date = amz_date;
    c.timestamp = *when;
    c.signature = post_detail::lower(*signature);
    c.security_token = form.get("x-amz-security-token");
    c.payload = sigv4::payload_mode::unsigned_payload;
    c.payload_hash = "UNSIGNED-PAYLOAD";
    c.string_to_sign = *policy_b64;
    if constexpr (aws_auth::aws_claim_resolver<A>) {
        auto r = authorizer.resolve(c, rules.protocol);
        if (!r) {
            return to_error(r.error());
        }
        if (!sigv4::verify(c, r->key)) {
            return to_error(sigv4::signature_mismatch(rules.protocol));
        }
        out.auth.who = r->who;
    } else {
        return aws_rest_xml::errors::make(
            501, "NotImplemented",
            "POST uploads need an authorizer that can resolve signing keys.");
    }
    if (auto e = check_post_policy(*policy, form, bucket, now)) {
        return *e;
    }
    out.auth.kind = auth_kind::post;
    out.auth.signature_age_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - c.timestamp).count();
    out.auth.claim = std::move(c);
    out.policy = std::move(*policy);
    return out;
}

}  // namespace kythira::s3
