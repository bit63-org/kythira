// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_errors.hpp
/// @brief SNS's errors as the query protocol answers them
///        (`.kiro/specs/sns-compatible-notifications/` Requirement 2.2,
///        3.1).
///
/// An `sns_error` is what a front-end step or a handler refuses with: the
/// `<Code>`, the message, the HTTP status and the fault type. The modelled
/// errors take their code, status and fault from the generated
/// `error_shapes` (by shape name, so a typo fails at compile time through
/// `model_error`'s constexpr lookup). The few that are not in the model are
/// the query protocol's own (MissingAction, InvalidAction,
/// MalformedQueryString) and SigV4's, which arrive as `sigv4::aws_error`.
///
/// Messages follow SNS's forms where they are known: a parameter fault is
/// `Invalid parameter: <Name>` with an optional ` Reason: <why>`, the form
/// SNS uses across CreateTopic, Subscribe and Publish. Wording that differs
/// on real SNS is corrected from recordings (task 12), never by changing a
/// code or status.

#include <kythira/sns/sns_operations.hpp>

#include <raft/aws_query_protocol.hpp>
#include <raft/sigv4_verifier.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace kythira::sns {

struct sns_error {
    std::string _code;
    std::string _message;
    std::uint16_t _status = 400;
    bool _sender_fault = true;

    friend auto operator==(const sns_error&, const sns_error&) -> bool = default;
};

/// The index of a modelled error shape, or `error_shapes.size()` when the
/// model has no such shape.
[[nodiscard]] constexpr auto error_index(std::string_view shape) -> std::size_t {
    for (std::size_t i = 0; i < error_shapes.size(); ++i) {
        if (error_shapes.at(i)._shape == shape) {
            return i;
        }
    }
    return error_shapes.size();
}

/// The operation of the pinned model named `name`, or nullptr. The table is
/// sorted by name.
[[nodiscard]] constexpr auto find_operation(std::string_view name) -> const operation_info* {
    std::size_t lo = 0;
    std::size_t hi = operations.size();
    while (lo < hi) {
        const auto mid = lo + ((hi - lo) / 2);
        const auto& op = operations.at(mid);
        if (op._name == name) {
            return &op;
        }
        if (op._name < name) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return nullptr;
}

/// A modelled error by shape name. Throws `std::invalid_argument` for a
/// shape the model lacks; in a constant expression that is a compile
/// error.
[[nodiscard]] inline auto model_error(std::string_view shape, std::string message) -> sns_error {
    const auto i = error_index(shape);
    if (i == error_shapes.size()) {
        throw std::invalid_argument("no such SNS error shape: " + std::string(shape));
    }
    const auto& e = error_shapes.at(i);
    return {std::string(e._code), std::move(message), e._http_status, e._sender_fault};
}

/// `InvalidParameter`: `Invalid parameter: <name>`, and ` Reason: <reason>`
/// when there is one.
[[nodiscard]] inline auto invalid_parameter(std::string_view name, std::string_view reason = {})
    -> sns_error {
    std::string m = "Invalid parameter: ";
    m += name;
    if (!reason.empty()) {
        m += " Reason: ";
        m += reason;
    }
    return model_error("InvalidParameterException", std::move(m));
}

/// `ParameterValueInvalid` (the model's InvalidParameterValueException).
[[nodiscard]] inline auto invalid_parameter_value(std::string message) -> sns_error {
    return model_error("InvalidParameterValueException", std::move(message));
}

[[nodiscard]] inline auto not_found(std::string message) -> sns_error {
    return model_error("NotFoundException", std::move(message));
}

[[nodiscard]] inline auto authorization_error(std::string message) -> sns_error {
    return model_error("AuthorizationErrorException", std::move(message));
}

[[nodiscard]] inline auto throttled(std::string message = "Rate exceeded") -> sns_error {
    return model_error("ThrottledException", std::move(message));
}

/// A failure that is not the caller's: lost leadership, no quorum, a
/// commit that did not finish in time. Retryable (FIFO dedup makes a
/// retried publish safe).
[[nodiscard]] inline auto internal_error() -> sns_error {
    return model_error("InternalErrorException", "Internal Error");
}

/// The query protocol's own refusals, not in the model.
[[nodiscard]] inline auto missing_action() -> sns_error {
    return {"MissingAction", "Missing Action", 400, true};
}

[[nodiscard]] inline auto invalid_action(std::string_view action) -> sns_error {
    return {"InvalidAction",
            "Could not find operation " + std::string(action) + " for version " +
                std::string(api_version),
            400, true};
}

[[nodiscard]] inline auto malformed_query(std::string message) -> sns_error {
    return {"MalformedQueryString", std::move(message), 400, true};
}

/// A request body past the gateway's limit.
[[nodiscard]] inline auto request_too_large() -> sns_error {
    return {"RequestEntityTooLarge", "Request body is too large", 413, true};
}

/// A SigV4 refusal (IncompleteSignature, InvalidClientTokenId,
/// SignatureDoesNotMatch, RequestExpired, ...), in the query protocol's
/// words already.
[[nodiscard]] inline auto from_sigv4(const sigv4::aws_error& e) -> sns_error {
    return {e.code, e.message, static_cast<std::uint16_t>(e.http_status), e.http_status < 500};
}

/// The `ErrorResponse` document.
[[nodiscard]] inline auto error_document(const sns_error& e, std::string_view request_id)
    -> std::string {
    return aws_query::error_xml(xml_namespace, e._sender_fault, e._code, e._message, request_id);
}

}  // namespace kythira::sns
