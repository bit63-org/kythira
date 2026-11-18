// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AWS KMS's errors (.kiro/specs/kms-compatible-api/ design "Error
// handling"): bare JSON 1.1 names, KMSInternalException for a handler that
// failed or an HSM that is sealed or unreachable, and the catalog's
// statuses mapped to the exception AWS answers for each.

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_keys.hpp>

#include <raft/aws_json_protocol.hpp>

#include <string>

namespace kythira::kms {

[[nodiscard]] inline auto kms_error_style() -> aws_json::error_style {
    auto s = aws_json::error_style::bare();
    s.internal_type = "KMSInternalException";
    return s;
}

[[nodiscard]] inline auto kms_error(std::string_view type, std::string message,
                                    unsigned status = 400) -> aws_json::error {
    return kms_error_style().modeled(type, std::move(message), status);
}

[[nodiscard]] inline auto validation_error(std::string message) -> aws_json::error {
    return kms_error("ValidationException", std::move(message));
}

[[nodiscard]] inline auto not_found(std::string message) -> aws_json::error {
    return kms_error("NotFoundException", std::move(message));
}

[[nodiscard]] inline auto invalid_arn(std::string message) -> aws_json::error {
    return kms_error("InvalidArnException", std::move(message));
}

[[nodiscard]] inline auto invalid_state(std::string message) -> aws_json::error {
    return kms_error("KMSInvalidStateException", std::move(message));
}

[[nodiscard]] inline auto unsupported(std::string message) -> aws_json::error {
    return kms_error("UnsupportedOperationException", std::move(message));
}

[[nodiscard]] inline auto internal_error(std::string message = "Internal service failure.")
    -> aws_json::error {
    return kms_error("KMSInternalException", std::move(message), 500);
}

/// The catalog could not be reached in time: no leader answered, or a
/// write's outcome is unknown.
[[nodiscard]] inline auto dependency_timeout() -> aws_json::error {
    return kms_error("DependencyTimeoutException",
                     "The KMS catalog did not answer in time. Retry the request.", 503);
}

/// The exception AWS answers for a catalog status; `rejected` is the
/// caller's to word, so this gives a generic validation error for it.
[[nodiscard]] inline auto catalog_error(catalog_status s, std::string_view what)
    -> aws_json::error {
    switch (s) {
        case catalog_status::not_found:
            return not_found(std::string(what) + " does not exist");
        case catalog_status::already_exists:
            return kms_error("AlreadyExistsException", std::string(what) + " already exists");
        case catalog_status::invalid_state:
            return invalid_state(std::string(what) + " is not in a state that allows this");
        case catalog_status::limit_exceeded:
            return kms_error("LimitExceededException",
                             "The request was rejected because a quota was exceeded");
        case catalog_status::stale_lease:
            // Only a background job's fenced command gets this; a request
            // never should.
            return internal_error();
        case catalog_status::rejected:
        case catalog_status::ok:
            break;
    }
    return validation_error("The request was rejected for " + std::string(what));
}

/// The exception for a key operation's outcome (key_jobs).
[[nodiscard]] inline auto outcome_error(const key_result& r, std::string_view what)
    -> aws_json::error {
    switch (r.outcome) {
        case key_outcome::catalog:
            return catalog_error(r.status, what);
        case key_outcome::unsupported:
            return unsupported("The HSM does not support this key spec");
        case key_outcome::unavailable:
            return internal_error("The HSM is sealed or unreachable");
        case key_outcome::failed:
        case key_outcome::ok:
            break;
    }
    return internal_error();
}

}  // namespace kythira::kms
