// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_errors.hpp
/// @brief SQS errors in both protocols (`.kiro/specs/sqs-compatible-queues/`
///        Requirement 2.2, 3.1).
///
/// Handlers raise one `aws_json::error`; the codec renders it in the
/// request's protocol:
///
///  - JSON 1.0: `{"__type": "com.amazonaws.sqs#QueueDoesNotExist",
///    "message": ...}`. SQS is `awsQueryCompatible`, so when the request
///    carries `x-amzn-query-mode: true` (every SDK that speaks JSON to SQS
///    sends it, task 1 evidence) the answer also carries
///    `x-amzn-query-error: AWS.SimpleQueueService.NonExistentQueue;Sender`,
///    the query code SDKs map back to the exception they always threw.
///  - query: `<ErrorResponse><Error><Type>Sender</Type>
///    <Code>AWS.SimpleQueueService.NonExistentQueue</Code>...`.
///
/// Modeled errors take their query code and HTTP status from the query-era
/// model (`model/sqs_query_names.hpp`); the status is the same in both
/// protocols. Errors the protocol layer raises itself (an unknown action,
/// a constraint violation, an unreadable body) are AWS's common errors,
/// listed in `k_protocol_errors`. The JSON `__type` of those and the query
/// codes of the exceptions added after SQS moved to JSON are unverified
/// until recorded against real SQS (task 13); a difference is corrected in
/// that table or in the generator's override table, nowhere else.

#include <kythira/sqs/model/sqs_query_names.hpp>

#include <raft/aws_json_protocol.hpp>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::sqs {

inline constexpr std::string_view k_error_namespace = "com.amazonaws.sqs#";

/// An error the protocol layer raises, in both protocols.
struct protocol_error {
    std::string_view json_type;
    std::string_view query_code;
    unsigned status = 400;
    bool sender = true;
};

inline constexpr protocol_error k_validation_error{"com.amazon.coral.validate#ValidationException",
                                                   "InvalidParameterValue", 400, true};
inline constexpr protocol_error k_missing_parameter_error{"com.amazonaws.sqs#MissingParameter",
                                                          "MissingParameter", 400, true};
inline constexpr protocol_error k_serialization_error{
    "com.amazon.coral.service#SerializationException", "MalformedQueryString", 400, true};
inline constexpr protocol_error k_unknown_operation_error{
    "com.amazon.coral.service#UnknownOperationException", "InvalidAction", 400, true};
inline constexpr protocol_error k_missing_action_error{"com.amazonaws.sqs#MissingAction",
                                                       "MissingAction", 400, true};
inline constexpr protocol_error k_internal_error{"com.amazon.coral.service#InternalFailure",
                                                 "InternalFailure", 500, false};
inline constexpr protocol_error k_too_large_error{
    "com.amazon.coral.service#RequestEntityTooLargeException", "RequestEntityTooLarge", 413, true};
inline constexpr protocol_error k_access_denied_error{
    "com.amazon.coral.service#AccessDeniedException", "AccessDenied", 403, true};

/// Every protocol error, for the JSON-type-to-query-code lookup.
inline constexpr std::array k_protocol_errors{
    k_validation_error,        k_missing_parameter_error, k_serialization_error,
    k_unknown_operation_error, k_missing_action_error,    k_internal_error,
    k_too_large_error,         k_access_denied_error,
};

/// The query codes of the authentication errors core's SigV4 verifier
/// words for JSON services (`sigv4::error_protocol::json`), for the
/// `x-amzn-query-error` header of a query-compatible JSON client. A query
/// request is authenticated with the query wording to begin with.
inline constexpr std::array<std::pair<std::string_view, std::string_view>, 4> k_auth_query_codes{{
    {"ExpiredTokenException", "ExpiredToken"},
    {"IncompleteSignatureException", "IncompleteSignature"},
    {"InvalidSignatureException", "SignatureDoesNotMatch"},
    {"UnrecognizedClientException", "InvalidClientTokenId"},
}};

/// The core codec's style for SQS: modeled errors under
/// `com.amazonaws.sqs#`, protocol errors as `k_protocol_errors` names them.
[[nodiscard]] inline auto sqs_error_style() -> aws_json::error_style {
    aws_json::error_style s;
    s.service_prefix = std::string(k_error_namespace);
    s.validation_type = std::string(k_validation_error.json_type);
    s.serialization_type = std::string(k_serialization_error.json_type);
    s.serialization_message_key = "message";
    s.unknown_operation_type = std::string(k_unknown_operation_error.json_type);
    s.internal_type = std::string(k_internal_error.json_type);
    s.too_large_type = std::string(k_too_large_error.json_type);
    return s;
}

/// A protocol error with `message`.
[[nodiscard]] inline auto make_error(const protocol_error& p, std::string message)
    -> aws_json::error {
    aws_json::error e;
    e.status = p.status;
    e.type = std::string(p.json_type);
    e.message = std::move(message);
    return e;
}

/// A modeled error: exception shape `shape` of the SQS model, with its
/// HTTP status from the query-era model. A name that is not an exception
/// shape of the model is a programming error and throws.
[[nodiscard]] inline auto modeled_error(std::string_view shape, std::string message)
    -> aws_json::error {
    const auto* q = sqs_query::find_error(shape);
    if (q == nullptr) {
        throw std::invalid_argument("sqs: no exception shape " + std::string(shape));
    }
    aws_json::error e;
    e.status = q->status;
    e.type = std::string(k_error_namespace) + std::string(shape);
    e.message = std::move(message);
    return e;
}

/// `QueueDoesNotExist`, with SQS's text.
[[nodiscard]] inline auto queue_does_not_exist() -> aws_json::error {
    return modeled_error("QueueDoesNotExist", "The specified queue does not exist.");
}

/// `InternalFailure` (HTTP 500), with no detail.
[[nodiscard]] inline auto internal_failure() -> aws_json::error {
    return make_error(k_internal_error, "We encountered an internal error. Please try again.");
}

/// How an error reads in the query protocol.
struct query_view {
    std::string code;
    bool sender = true;
};

/// The query code and fault side of `e`: a modeled error's from the
/// query-era model, a protocol error's from `k_protocol_errors`, a JSON
/// authentication error's from `k_auth_query_codes`, anything else by the
/// part of its type after `#` (a Sender fault below HTTP 500).
[[nodiscard]] inline auto to_query(const aws_json::error& e) -> query_view {
    const std::string_view type = e.type;
    if (type.starts_with(k_error_namespace)) {
        if (const auto* q = sqs_query::find_error(type.substr(k_error_namespace.size()))) {
            return {std::string(q->code), q->sender};
        }
    }
    for (const auto& p : k_protocol_errors) {
        if (p.json_type == type) {
            return {std::string(p.query_code), p.sender};
        }
    }
    for (const auto& [json, query] : k_auth_query_codes) {
        if (json == type) {
            return {std::string(query), true};
        }
    }
    const auto hash = type.rfind('#');
    return {std::string(hash == std::string_view::npos ? type : type.substr(hash + 1)),
            e.status < 500};
}

}  // namespace kythira::sqs
