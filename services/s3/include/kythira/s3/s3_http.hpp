// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_http.hpp
/// @brief The request and response the front end's handlers see
///        (.kiro/specs/s3-compatible-storage/ task 7).
///
/// A request arrives authenticated and routed, with its body as a pull
/// source of the bytes the signature vouches for (`payload_reader`'s
/// output), so a 5 GB PUT streams into the data path without being held.
/// A response is a status, headers and either a small body (XML) or a
/// body producer that streams object bytes to the listener's sink. The
/// listener (task 16, or a test) owns the sockets on both ends.

#include <kythira/s3/s3_routes.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::s3 {

using header_list = std::vector<std::pair<std::string, std::string>>;

/// The first header named `name`, without regard to case.
[[nodiscard]] inline auto find_header(const header_list& h, std::string_view name)
    -> std::optional<std::string> {
    for (const auto& [k, v] : h) {
        if (aws_rest_xml::detail::iequals(k, name)) {
            return v;
        }
    }
    return std::nullopt;
}

/// Pulls the next bytes of a body into `out` (appending). Returns false
/// once the body is done, or the error that ended it.
using body_source = std::function<aws_rest_xml::result<bool>(std::string& out)>;

/// A body that is already in memory.
[[nodiscard]] inline auto memory_body(std::string bytes) -> body_source {
    auto state = std::make_shared<std::pair<std::string, bool>>(std::move(bytes), false);
    return [state](std::string& out) -> aws_rest_xml::result<bool> {
        if (state->second) {
            return false;
        }
        out.append(state->first);
        state->second = true;
        state->first.clear();
        return true;
    };
}

/// Read a whole (small) body, refusing one over `limit` bytes with
/// `too_large`.
[[nodiscard]] inline auto read_all(const body_source& src, std::size_t limit,
                                   const aws_rest_xml::error& too_large)
    -> aws_rest_xml::result<std::string> {
    std::string out;
    if (!src) {
        return out;
    }
    for (;;) {
        auto more = src(out);
        if (!more) {
            return more.error();
        }
        if (out.size() > limit) {
            return too_large;
        }
        if (!*more) {
            return out;
        }
    }
}

/// What a handler sees of a request.
struct s3_request {
    std::string method;
    const aws_rest_xml::route* operation = nullptr;
    aws_rest_xml::resource resource;
    aws_rest_xml::query query;
    header_list headers;
    body_source body;
    /// The body's trailers (`x-amz-checksum-*` of an `aws-chunked` body),
    /// once `body` has reported its end; none when not set.
    std::function<header_list()> trailers;
    /// From the connection, for condition keys and logs.
    std::string source_ip;
    bool secure_transport = true;
    std::string request_id;

    [[nodiscard]] auto header(std::string_view name) const -> std::optional<std::string> {
        return find_header(headers, name);
    }
    [[nodiscard]] auto op() const -> std::string_view {
        return operation != nullptr ? std::string_view(operation->name) : std::string_view{};
    }
};

/// Writes body bytes to the client; false when the client is gone.
using body_sink = std::function<bool(std::span<const std::byte>)>;

/// Streams a response body; an error after the first byte can only cut the
/// connection, as on S3.
using body_producer = std::function<std::optional<aws_rest_xml::error>(const body_sink&)>;

struct s3_response {
    unsigned status = 200;
    header_list headers;
    std::string body;
    /// Set instead of `body` for object bytes.
    body_producer stream;
    /// The length `stream` will produce (Content-Length).
    std::uint64_t stream_length = 0;

    auto set(std::string name, std::string value) -> s3_response& {
        headers.emplace_back(std::move(name), std::move(value));
        return *this;
    }
    [[nodiscard]] auto header(std::string_view name) const -> std::optional<std::string> {
        return find_header(headers, name);
    }
};

/// A response carrying an XML document.
[[nodiscard]] inline auto xml_response(std::string body, unsigned status = 200) -> s3_response {
    s3_response r;
    r.status = status;
    r.body = std::move(body);
    r.set("Content-Type", "application/xml");
    return r;
}

/// S3's error response for `e` (no body for HEAD, as on S3).
[[nodiscard]] inline auto error_response(const aws_rest_xml::error& e, std::string_view request_id,
                                         bool head = false) -> s3_response {
    s3_response r;
    r.status = e.status;
    if (!head) {
        r.body = aws_rest_xml::error_xml(e, request_id);
        r.set("Content-Type", "application/xml");
    }
    return r;
}

}  // namespace kythira::s3
