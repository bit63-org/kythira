// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_topic_policy.hpp
/// @brief Topic and subscription ARNs, topic names, and topic access
///        policies (`.kiro/specs/sns-compatible-notifications/`
///        Requirement 3.2, 4.1).
///
/// A topic's `Policy` attribute is an ordinary resource policy: the front
/// end hands it to the authorizer with each request on the topic, and the
/// authorizer (IAM, or nothing with static keys) evaluates it together
/// with the caller's identity policies. This file owns the documents
/// themselves:
///
/// - `default_topic_policy`: the policy SNS gives a new topic. It allows
///   every principal (`"AWS": "*"`) eight topic actions under
///   `AWS:SourceOwner` equal to the topic's account. SNS supplies
///   `aws:SourceOwner` as the caller's account for direct calls, so the
///   default lets the owner account in and keeps every other account out;
///   the front end supplies the key the same way.
/// - `add_permission` / `remove_permission`: AddPermission and
///   RemovePermission, which add or drop one labelled statement.
/// - `check_topic_policy`: what SetTopicAttributes and CreateTopic accept
///   as `Policy` before it is stored: a JSON object no larger than SNS's
///   30 KiB with a statement list. Statement grammar beyond that is the
///   IAM policy checker's, through the authorizer, as for every resource
///   policy.
///
/// Documents are written compactly with members in SNS's order, so
/// GetTopicAttributes returns what SNS would, byte for byte.

#include <kythira/sns/sns_actions.hpp>
#include <kythira/sns/sns_errors.hpp>

#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::sns {

/// SNS's limit on a topic policy, in bytes.
inline constexpr std::size_t k_max_topic_policy_bytes = 30U * 1024U;
/// The longest topic name, `.fifo` included.
inline constexpr std::size_t k_max_topic_name = 256;
inline constexpr std::string_view k_fifo_suffix = ".fifo";

/// The parts of a topic ARN, `arn:<partition>:sns:<region>:<account>:<name>`.
struct topic_arn_parts {
    std::string _partition;
    std::string _region;
    std::string _account;
    std::string _name;

    friend auto operator==(const topic_arn_parts&, const topic_arn_parts&) -> bool = default;
};

/// A valid topic name: 1 to 256 characters of letters, digits, hyphens and
/// underscores, ending in `.fifo` for a FIFO topic (and only then).
[[nodiscard]] inline auto valid_topic_name(std::string_view name, bool fifo) -> bool {
    if (name.empty() || name.size() > k_max_topic_name) {
        return false;
    }
    if (fifo != name.ends_with(k_fifo_suffix)) {
        return false;
    }
    if (fifo) {
        name.remove_suffix(k_fifo_suffix.size());
        if (name.empty()) {
            return false;
        }
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-' || c == '_';
    });
}

namespace policy_detail {

/// Splits `arn` at its first `n - 1` colons; nullopt when it has fewer.
template<std::size_t N>
[[nodiscard]] auto split_arn(std::string_view arn)
    -> std::optional<std::array<std::string_view, N>> {
    std::array<std::string_view, N> parts{};
    for (std::size_t i = 0; i + 1 < N; ++i) {
        const auto colon = arn.find(':');
        if (colon == std::string_view::npos) {
            return std::nullopt;
        }
        parts.at(i) = arn.substr(0, colon);
        arn.remove_prefix(colon + 1);
    }
    parts.at(N - 1) = arn;
    return parts;
}

[[nodiscard]] inline auto valid_account(std::string_view a) -> bool {
    return a.size() == 12 &&
           std::all_of(a.begin(), a.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

}  // namespace policy_detail

/// The parts of a topic ARN, or nullopt when `arn` is not one (wrong
/// service, bad account, a name SNS would not create).
[[nodiscard]] inline auto parse_topic_arn(std::string_view arn) -> std::optional<topic_arn_parts> {
    const auto p = policy_detail::split_arn<6>(arn);
    if (!p || (*p)[0] != "arn" || (*p)[1].empty() || (*p)[2] != "sns" || (*p)[3].empty() ||
        !policy_detail::valid_account((*p)[4])) {
        return std::nullopt;
    }
    const auto name = (*p)[5];
    if (!valid_topic_name(name, name.ends_with(k_fifo_suffix))) {
        return std::nullopt;
    }
    return topic_arn_parts{std::string((*p)[1]), std::string((*p)[3]), std::string((*p)[4]),
                           std::string(name)};
}

/// The topic ARN inside a subscription ARN (`<topic arn>:<subscription
/// id>`), or nullopt when `arn` is not a subscription ARN. Authorization
/// of subscription operations is on the topic, as on SNS.
[[nodiscard]] inline auto topic_of_subscription(std::string_view arn)
    -> std::optional<std::string> {
    const auto colon = arn.rfind(':');
    if (colon == std::string_view::npos || colon + 1 == arn.size()) {
        return std::nullopt;
    }
    const auto id = arn.substr(colon + 1);
    if (!std::all_of(id.begin(), id.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0 || c == '-'; })) {
        return std::nullopt;
    }
    const auto topic = arn.substr(0, colon);
    if (!parse_topic_arn(topic)) {
        return std::nullopt;
    }
    return std::string(topic);
}

/// The eight actions the default policy allows, in SNS's order.
inline constexpr std::array<std::string_view, 8> k_default_policy_actions{
    "SNS:GetTopicAttributes",
    "SNS:SetTopicAttributes",
    "SNS:AddPermission",
    "SNS:RemovePermission",
    "SNS:DeleteTopic",
    "SNS:Subscribe",
    "SNS:ListSubscriptionsByTopic",
    "SNS:Publish"};

/// The policy SNS gives a topic it creates without one.
[[nodiscard]] inline auto default_topic_policy(std::string_view topic_arn, std::string_view account)
    -> std::string {
    boost::json::array actions;
    for (const auto a : k_default_policy_actions) {
        actions.emplace_back(a);
    }
    boost::json::object statement;
    statement["Sid"] = "__default_statement_ID";
    statement["Effect"] = "Allow";
    statement["Principal"] = boost::json::object{{"AWS", "*"}};
    statement["Action"] = std::move(actions);
    statement["Resource"] = topic_arn;
    statement["Condition"] =
        boost::json::object{{"StringEquals", boost::json::object{{"AWS:SourceOwner", account}}}};
    boost::json::object policy;
    policy["Version"] = "2008-10-17";
    policy["Id"] = "__default_policy_ID";
    policy["Statement"] = boost::json::array{std::move(statement)};
    return boost::json::serialize(policy);
}

/// A policy document or the error to refuse it with.
class policy_result {
public:
    policy_result(std::string doc) : _v(std::move(doc)) {}  // NOLINT(google-explicit-constructor)
    policy_result(sns_error e) : _v(std::move(e)) {}        // NOLINT(google-explicit-constructor)

    [[nodiscard]] auto has_value() const -> bool { return _v.index() == 0; }
    explicit operator bool() const { return has_value(); }
    [[nodiscard]] auto value() const -> const std::string& { return std::get<0>(_v); }
    [[nodiscard]] auto operator*() const -> const std::string& { return value(); }
    [[nodiscard]] auto error() const -> const sns_error& { return std::get<1>(_v); }

private:
    std::variant<std::string, sns_error> _v;
};

namespace policy_detail {

[[nodiscard]] inline auto policy_error(std::string_view why) -> sns_error {
    return invalid_parameter("Policy", "Policy Error: " + std::string(why));
}

/// The parsed document, or the error. Checks the size, that it is an
/// object, and that `Statement` is an object or an array of objects.
[[nodiscard]] inline auto parse_policy(std::string_view doc)
    -> std::variant<boost::json::object, sns_error> {
    if (doc.size() > k_max_topic_policy_bytes) {
        return policy_error("exceeded maximum policy size of " +
                            std::to_string(k_max_topic_policy_bytes) + " bytes");
    }
    boost::system::error_code ec;
    auto v = boost::json::parse(doc, ec);
    if (ec || !v.is_object()) {
        return policy_error("not a JSON object");
    }
    auto& o = v.as_object();
    auto* s = o.if_contains("Statement");
    if (s == nullptr) {
        return policy_error("null");
    }
    if (s->is_object()) {
        *s = boost::json::array{*s};
    }
    if (!s->is_array() || !std::all_of(s->as_array().begin(), s->as_array().end(),
                                       [](const boost::json::value& e) { return e.is_object(); })) {
        return policy_error("Statement is not a list of objects");
    }
    return std::move(o);
}

[[nodiscard]] inline auto has_sid(const boost::json::array& statements, std::string_view sid)
    -> bool {
    return std::any_of(statements.begin(), statements.end(), [sid](const boost::json::value& s) {
        const auto* v = s.as_object().if_contains("Sid");
        return v != nullptr && v->is_string() && v->as_string() == sid;
    });
}

/// The topic actions AddPermission may grant: every `sns` action whose
/// resource is a topic.
[[nodiscard]] inline auto topic_actions() -> const std::set<std::string, std::less<>>& {
    static const auto out = [] {
        std::set<std::string, std::less<>> s;
        for (const auto& a : sns_actions().actions) {
            if (a.resource_templates != std::vector<std::string>{"*"}) {
                s.emplace(a.name);
            }
        }
        return s;
    }();
    return out;
}

[[nodiscard]] inline auto valid_label(std::string_view label) -> bool {
    return !label.empty() && label.size() <= 80 &&
           std::all_of(label.begin(), label.end(), [](unsigned char c) {
               return std::isalnum(c) != 0 || c == '-' || c == '_';
           });
}

}  // namespace policy_detail

/// `Policy` as CreateTopic and SetTopicAttributes take it: the document,
/// unchanged, or InvalidParameter.
[[nodiscard]] inline auto check_topic_policy(std::string_view doc) -> policy_result {
    auto parsed = policy_detail::parse_policy(doc);
    if (const auto* e = std::get_if<sns_error>(&parsed)) {
        return *e;
    }
    return std::string(doc);
}

/// AddPermission: `policy` with a statement `label` allowing `accounts`
/// (account ids, as `arn:<partition>:iam::<id>:root`) the `actions`
/// (names without the prefix, `Publish`) on `topic_arn`. A single account
/// or action is written as a string, several as a list, as SNS writes
/// them.
[[nodiscard]] inline auto add_permission(std::string_view policy, std::string_view topic_arn,
                                         std::string_view partition, std::string_view label,
                                         const std::vector<std::string>& accounts,
                                         const std::vector<std::string>& actions) -> policy_result {
    if (!policy_detail::valid_label(label)) {
        return invalid_parameter("Label");
    }
    if (accounts.empty()) {
        return invalid_parameter("AWSAccountId");
    }
    if (actions.empty()) {
        return invalid_parameter("ActionName");
    }
    auto parsed = policy_detail::parse_policy(policy);
    if (const auto* e = std::get_if<sns_error>(&parsed)) {
        return *e;
    }
    auto& doc = std::get<boost::json::object>(parsed);
    auto& statements = doc["Statement"].as_array();
    if (policy_detail::has_sid(statements, label)) {
        return invalid_parameter("Statement", "Already exists");
    }
    boost::json::array principals;
    for (const auto& a : accounts) {
        if (!policy_detail::valid_account(a)) {
            return invalid_parameter("AWSAccountId");
        }
        principals.emplace_back("arn:" + std::string(partition) + ":iam::" + a + ":root");
    }
    boost::json::array granted;
    for (const auto& a : actions) {
        if (!policy_detail::topic_actions().contains(a)) {
            return invalid_parameter("Policy statement action out of service scope!");
        }
        granted.emplace_back("SNS:" + a);
    }
    boost::json::object statement;
    statement["Sid"] = label;
    statement["Effect"] = "Allow";
    statement["Principal"] = boost::json::object{
        {"AWS", principals.size() == 1 ? principals[0] : boost::json::value(principals)}};
    statement["Action"] = granted.size() == 1 ? granted[0] : boost::json::value(granted);
    statement["Resource"] = topic_arn;
    statements.emplace_back(std::move(statement));
    auto out = boost::json::serialize(doc);
    if (out.size() > k_max_topic_policy_bytes) {
        return policy_detail::policy_error("exceeded maximum policy size of " +
                                           std::to_string(k_max_topic_policy_bytes) + " bytes");
    }
    return out;
}

/// RemovePermission: `policy` without the statement `label`.
[[nodiscard]] inline auto remove_permission(std::string_view policy, std::string_view label)
    -> policy_result {
    auto parsed = policy_detail::parse_policy(policy);
    if (const auto* e = std::get_if<sns_error>(&parsed)) {
        return *e;
    }
    auto& doc = std::get<boost::json::object>(parsed);
    auto& statements = doc["Statement"].as_array();
    const auto before = statements.size();
    statements.erase(std::remove_if(statements.begin(), statements.end(),
                                    [label](const boost::json::value& s) {
                                        const auto* v = s.as_object().if_contains("Sid");
                                        return v != nullptr && v->is_string() &&
                                               v->as_string() == label;
                                    }),
                     statements.end());
    if (statements.size() == before) {
        return invalid_parameter("Label", "No such statement");
    }
    return boost::json::serialize(doc);
}

}  // namespace kythira::sns
