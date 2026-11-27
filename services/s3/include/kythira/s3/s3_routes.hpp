// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_routes.hpp
/// @brief S3's route table for the REST-XML router
///        (.kiro/specs/s3-compatible-storage/ task 3, Requirement 4.1).
///
/// Every operation of the pinned model (`model/operations.hpp`) becomes an
/// `aws_rest_xml::route`, so a model upgrade changes routing with no hand
/// edits. Two operations are never routed, because only another endpoint
/// tells them apart from an ordinary request: ListDirectoryBuckets is
/// `GET /` on an S3 Express zonal endpoint (here it is ListBuckets), and
/// WriteGetObjectResponse is answered on an Object Lambda host. Both are
/// out of scope in `doc/unsupported.md`.
///
/// `tests/s3_routing_test.cpp` routes every request the seven recorded
/// clients sent (`tests/evidence/data/`) and checks it reaches the
/// operation the recording names.

#include <kythira/s3/model/operations.hpp>
#include <raft/aws_rest_xml_protocol.hpp>

#include <array>
#include <cstddef>
#include <string_view>
#include <utility>

namespace kythira::s3 {

namespace detail {

[[nodiscard]] constexpr auto to_route(const model::operation_info& op) -> aws_rest_xml::route {
    return {op._name,           op._method,           op._request_uri,
            op._required_query, op._required_headers, op._deprecated};
}

template<std::size_t... I>
[[nodiscard]] constexpr auto make_routes(std::index_sequence<I...> /*unused*/)
    -> std::array<aws_rest_xml::route, sizeof...(I)> {
    return {{to_route(model::operations[I])...}};
}

}  // namespace detail

/// The model's operations as routes, in the model table's order.
inline constexpr auto routes =
    detail::make_routes(std::make_index_sequence<model::operations.size()>{});

/// The router over `routes`, built once.
[[nodiscard]] inline auto router() -> const aws_rest_xml::router& {
    static const aws_rest_xml::router r(routes, {"ListDirectoryBuckets", "WriteGetObjectResponse"});
    return r;
}

/// The addressing check and the router together: the operation a request
/// names, with its bucket and key, or the S3 error to answer with.
struct routed_request {
    const aws_rest_xml::route* operation = nullptr;
    aws_rest_xml::resource resource;
    aws_rest_xml::query query;
};

/// `target` is the request target as sent (path and query); `has_header`
/// answers for the request's headers, case-insensitively.
[[nodiscard]] inline auto route_request(std::string_view method, std::string_view host,
                                        std::string_view target,
                                        const aws_rest_xml::addressing_config& addressing,
                                        const aws_rest_xml::router::header_fn& has_header)
    -> aws_rest_xml::result<routed_request> {
    const auto qmark = target.find('?');
    auto resource = aws_rest_xml::parse_resource(host, target.substr(0, qmark), addressing);
    if (!resource) {
        return resource.error();
    }
    auto query = aws_rest_xml::parse_query(
        qmark == std::string_view::npos ? std::string_view{} : target.substr(qmark + 1));
    if (!query) {
        return query.error();
    }
    auto op = router().match(method, aws_rest_xml::kind_of(*resource), *query, has_header);
    if (!op) {
        return op.error();
    }
    return routed_request{*op, std::move(*resource), std::move(*query)};
}

}  // namespace kythira::s3
