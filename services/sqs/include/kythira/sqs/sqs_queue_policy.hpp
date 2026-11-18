// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_queue_policy.hpp
/// @brief Queue policies as `AddPermission` and `RemovePermission` edit them
///        (`.kiro/specs/sqs-compatible-queues/` Requirement 3.3).
///
/// A queue's policy is its `Policy` attribute, an IAM policy document the
/// authorizer evaluates with the caller's identity policies (the front end
/// passes it as the request's resource policy). `SetQueueAttributes`
/// replaces it whole; `AddPermission` and `RemovePermission` edit it one
/// labelled statement at a time, as SQS does:
///
///     {"Version": "2012-10-17", "Id": "<queue arn>/SQSDefaultPolicy",
///      "Statement": [{"Sid": "<label>", "Effect": "Allow",
///                     "Principal": {"AWS": ["arn:aws:iam::<account>:root"]},
///                     "Action": ["SQS:SendMessage"],
///                     "Resource": "<queue arn>"}]}
///
/// The action names SQS lets a queue share are the message actions and
/// the metadata reads (`k_shareable_actions`) or `*`. Granting an action
/// also grants its batch form, which the front end authorizes as the
/// single-entry action anyway. The errors and their texts are SQS's
/// (`InvalidParameterValue`, `OverLimit`).

#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::sqs {

/// The actions `AddPermission` may grant, besides `*`.
inline constexpr std::array<std::string_view, 8> k_shareable_actions{
    "ChangeMessageVisibility",    "DeleteMessage", "GetQueueAttributes", "GetQueueUrl",
    "ListDeadLetterSourceQueues", "PurgeQueue",    "ReceiveMessage",     "SendMessage",
};

/// SQS's cap on the statements of one queue policy.
inline constexpr std::size_t k_max_policy_statements = 20;

namespace policy_detail {

[[nodiscard]] inline auto invalid(std::string_view param, std::string_view value,
                                  std::string_view reason) -> aws_json::error {
    return make_error(k_validation_error, "Value " + std::string(value) + " for parameter " +
                                              std::string(param) +
                                              " is invalid. Reason: " + std::string(reason));
}

[[nodiscard]] inline auto valid_label(std::string_view label) -> bool {
    return !label.empty() && label.size() <= 80 &&
           std::all_of(label.begin(), label.end(), [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_';
           });
}

[[nodiscard]] inline auto valid_account(std::string_view a) -> bool {
    return a.size() == 12 &&
           std::all_of(a.begin(), a.end(), [](char c) { return c >= '0' && c <= '9'; });
}

/// The policy document, or a fresh one when `policy` is empty.
[[nodiscard]] inline auto open_policy(std::string_view policy, std::string_view queue_arn)
    -> std::optional<boost::json::object> {
    if (policy.empty()) {
        boost::json::object doc;
        doc["Version"] = "2012-10-17";
        doc["Id"] = std::string(queue_arn) + "/SQSDefaultPolicy";
        doc["Statement"] = boost::json::array{};
        return doc;
    }
    boost::system::error_code ec;
    auto v = boost::json::parse(policy, ec);
    if (ec || !v.is_object()) {
        return std::nullopt;
    }
    auto& doc = v.as_object();
    auto* st = doc.if_contains("Statement");
    if (st == nullptr) {
        doc["Statement"] = boost::json::array{};
    } else if (st->is_object()) {
        // A single statement may be written as an object.
        boost::json::array one;
        one.push_back(std::move(*st));
        doc["Statement"] = std::move(one);
    } else if (!st->is_array()) {
        return std::nullopt;
    }
    return std::move(doc);
}

[[nodiscard]] inline auto has_label(const boost::json::array& statements, std::string_view label)
    -> bool {
    return std::any_of(statements.begin(), statements.end(), [label](const boost::json::value& s) {
        const auto* sid = s.is_object() ? s.get_object().if_contains("Sid") : nullptr;
        return sid != nullptr && sid->is_string() && sid->get_string() == label;
    });
}

}  // namespace policy_detail

/// `policy` with a statement `label` granting `actions` on `queue_arn` to
/// `accounts`, serialized; or the error SQS answers with.
[[nodiscard]] inline auto add_permission(std::string_view policy, std::string_view queue_arn,
                                         std::string_view partition, std::string_view label,
                                         const std::vector<std::string>& accounts,
                                         const std::vector<std::string>& actions)
    -> aws_json::result<std::string> {
    using namespace policy_detail;
    if (!valid_label(label)) {
        return invalid("Label", label,
                       "Can only include alphanumeric characters, hyphens, or underscores. 1 to "
                       "80 in length");
    }
    if (accounts.empty()) {
        return make_error(k_missing_parameter_error,
                          "The request must contain the parameter AWSAccountIds.");
    }
    if (actions.empty()) {
        return make_error(k_missing_parameter_error,
                          "The request must contain the parameter Actions.");
    }
    boost::json::array principals;
    for (const auto& a : accounts) {
        if (!valid_account(a)) {
            return invalid("AWSAccountId", a, "An AWS account ID must be 12 digits.");
        }
        principals.emplace_back("arn:" + std::string(partition) + ":iam::" + a + ":root");
    }
    boost::json::array granted;
    for (const auto& a : actions) {
        if (a != "*" && std::find(k_shareable_actions.begin(), k_shareable_actions.end(), a) ==
                            k_shareable_actions.end()) {
            return invalid("ActionName", a,
                           "Please refer to the appropriate WSDL for a list of valid actions.");
        }
        granted.emplace_back("SQS:" + a);
    }
    auto doc = open_policy(policy, queue_arn);
    if (!doc) {
        return invalid("Policy", "", "The queue's policy is not a valid policy document.");
    }
    auto& statements = doc->at("Statement").as_array();
    if (has_label(statements, label)) {
        return invalid("Label", label, "Already exists.");
    }
    if (statements.size() >= k_max_policy_statements) {
        return modeled_error("OverLimit", "Policy statement limit of " +
                                              std::to_string(k_max_policy_statements) +
                                              " has been exceeded.");
    }
    boost::json::object st;
    st["Sid"] = std::string(label);
    st["Effect"] = "Allow";
    st["Principal"] =
        boost::json::object{{"AWS", principals.size() == 1 ? boost::json::value(principals[0])
                                                           : boost::json::value(principals)}};
    st["Action"] =
        granted.size() == 1 ? boost::json::value(granted[0]) : boost::json::value(granted);
    st["Resource"] = std::string(queue_arn);
    statements.push_back(std::move(st));
    return boost::json::serialize(*doc);
}

/// `policy` without statement `label`, serialized; empty when no statement
/// is left (the queue then has no policy). Or the error SQS answers with.
[[nodiscard]] inline auto remove_permission(std::string_view policy, std::string_view queue_arn,
                                            std::string_view label)
    -> aws_json::result<std::string> {
    using namespace policy_detail;
    auto doc = policy.empty() ? std::nullopt : open_policy(policy, queue_arn);
    if (!doc || !has_label(doc->at("Statement").as_array(), label)) {
        return invalid("Label", label, "can't find label.");
    }
    auto& statements = doc->at("Statement").as_array();
    statements.erase(
        std::remove_if(statements.begin(), statements.end(),
                       [label](const boost::json::value& s) {
                           const auto* sid =
                               s.is_object() ? s.get_object().if_contains("Sid") : nullptr;
                           return sid != nullptr && sid->is_string() && sid->get_string() == label;
                       }),
        statements.end());
    if (statements.empty()) {
        return std::string();
    }
    return boost::json::serialize(*doc);
}

}  // namespace kythira::sqs
