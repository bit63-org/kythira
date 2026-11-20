// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_cors.hpp
/// @brief `PutBucketCors`, `GetBucketCors` and `DeleteBucketCors`
///        (.kiro/specs/s3-compatible-storage/ task 15, Requirement 6.1).
///
/// The configuration model and matching are `s3_cors_rules.hpp`'s; the
/// preflight (`OPTIONS`) and the `Access-Control-*` headers on other
/// answers are `s3_service.hpp`'s, since a preflight is never
/// authenticated and so never reaches a handler.

#include <kythira/s3/s3_buckets.hpp>
#include <kythira/s3/s3_context.hpp>
#include <kythira/s3/s3_cors_rules.hpp>
#include <kythira/s3/s3_http.hpp>
#include <kythira/s3/s3_object_lock.hpp>

#include <raft/aws_rest_xml_protocol.hpp>

#include <optional>
#include <string>

namespace kythira::s3 {

template<metadata_access M>
[[nodiscard]] auto put_bucket_cors(handler_context<M>& ctx, const s3_request& req,
                                   const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!lock_detail::has_integrity_header(req.headers)) {
        return cors_detail::invalid_request(
            "Missing required header for this request: Content-MD5");
    }
    auto body = bucket_detail::document(ctx, req);
    if (!body) {
        return body.error();
    }
    auto c = parse_cors_configuration(*body);
    if (!c) {
        return c.error();
    }
    if (auto e = bucket_detail::store(ctx, b, "cors", cors_xml(*c))) {
        return *e;
    }
    return s3_response{};
}

template<metadata_access M>
[[nodiscard]] auto get_bucket_cors(handler_context<M>& /*ctx*/, const s3_request& /*req*/,
                                   const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (!b.cors) {
        auto e = aws_rest_xml::errors::make(404, "NoSuchCORSConfiguration",
                                            "The CORS configuration does not exist");
        e.extra.emplace_back("BucketName", b.client_name);
        return e;
    }
    return xml_response(cors_xml(*b.cors));
}

template<metadata_access M>
[[nodiscard]] auto delete_bucket_cors(handler_context<M>& ctx, const s3_request& /*req*/,
                                      const authenticated& /*auth*/, bucket_state& b)
    -> handler_result {
    if (auto e = bucket_detail::store(ctx, b, "cors", std::nullopt)) {
        return *e;
    }
    return bucket_detail::no_content();
}

}  // namespace kythira::s3
