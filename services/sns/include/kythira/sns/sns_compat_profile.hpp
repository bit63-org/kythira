// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sns_compat_profile.hpp
/// @brief The AWS-behaviour switches and SNS's documented limits
///        (`.kiro/specs/sns-compatible-notifications/` Requirement 2.2,
///        2.3).
///
/// The default profile, `aws`, is SNS's behaviour for every switch, in
/// every deployment. A cluster sets switches in its config; a topic
/// overrides them with tags `kythira:compat:<switch>`, and the topic's value
/// wins. No switch changes an error code, message or status.
///
///   switch             AWS value  other value
///   throttling         on         off        account publish rate, API rates
///   message-size       aws        <bytes>    the largest message a topic takes
///   count-limits       aws        relaxed    topics, subscriptions, pending
///                                            subscriptions, filter policies
///   fifo-throughput    aws        relaxed    FIFO per-topic and per-group rates
///   signing-cert-host  aws        <host>     the host of SigningCertURL
///
/// Names and values are matched case-insensitively (a host is lower-cased).
/// An unknown switch or value is an error, so a typo in a tag fails at
/// CreateTopic or TagResource instead of silently keeping SNS's behaviour.
///
/// `sns_limits` gives the numbers a profile means, from the AWS General
/// Reference "Amazon SNS endpoints and quotas" page (read 2026-11-18): per
/// region publish rates and the regional API tiers, the account and topic
/// counts, and the message size, which on SNS is the topic's
/// `MaximumMessageSize` attribute (256 KiB by default, at most 1 MiB, the
/// pinned model's documentation says the same). With `message-size` set to
/// a byte count, that count is the topic's limit whatever the attribute
/// says, up to `k_max_relaxed_message_bytes`.

#include <kythira/sns/sns_errors.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sns {

inline constexpr std::string_view k_compat_tag_prefix = "kythira:compat:";

/// SNS's message size: the default and the most `MaximumMessageSize` may
/// set.
inline constexpr std::size_t k_default_message_bytes = 262'144;
inline constexpr std::size_t k_max_message_bytes = 1'048'576;
/// The bounds of `message-size` as a byte count. The ceiling keeps a
/// PublishBatch of ten such messages inside one Raft entry.
inline constexpr std::size_t k_min_relaxed_message_bytes = 1'024;
inline constexpr std::size_t k_max_relaxed_message_bytes = 16U * 1'048'576U;

struct sns_compat_profile {
    bool _throttling = true;
    /// Empty: SNS's message size (the topic's attribute). Otherwise the
    /// size every message on the topic may reach.
    std::optional<std::size_t> _message_bytes;
    bool _aws_count_limits = true;
    bool _aws_fifo_throughput = true;
    /// Empty: SNS's `sns.<region>.amazonaws.com`.
    std::string _signing_cert_host;

    friend auto operator==(const sns_compat_profile&, const sns_compat_profile&) -> bool = default;

    /// The switches set away from SNS's behaviour, by name, for metrics and
    /// the topic's Kythira attributes.
    [[nodiscard]] auto relaxed() const -> std::vector<std::string_view> {
        std::vector<std::string_view> out;
        if (!_throttling) {
            out.emplace_back("throttling");
        }
        if (_message_bytes) {
            out.emplace_back("message-size");
        }
        if (!_aws_count_limits) {
            out.emplace_back("count-limits");
        }
        if (!_aws_fifo_throughput) {
            out.emplace_back("fifo-throughput");
        }
        if (!_signing_cert_host.empty()) {
            out.emplace_back("signing-cert-host");
        }
        return out;
    }

    /// Sets one switch by name and value. Returns false (and changes
    /// nothing) for an unknown switch or a value it does not take.
    [[nodiscard]] auto set(std::string_view name, std::string_view value) -> bool {
        const auto n = lower(name);
        const auto v = lower(value);
        const auto pick = [&v](bool& field, std::string_view aws, std::string_view other) {
            if (v == aws) {
                field = true;
                return true;
            }
            if (v == other) {
                field = false;
                return true;
            }
            return false;
        };
        if (n == "throttling") {
            return pick(_throttling, "on", "off");
        }
        if (n == "count-limits") {
            return pick(_aws_count_limits, "aws", "relaxed");
        }
        if (n == "fifo-throughput") {
            return pick(_aws_fifo_throughput, "aws", "relaxed");
        }
        if (n == "message-size") {
            if (v == "aws") {
                _message_bytes.reset();
                return true;
            }
            std::size_t bytes = 0;
            const auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), bytes);
            if (ec != std::errc{} || p != v.data() + v.size() ||
                bytes < k_min_relaxed_message_bytes || bytes > k_max_relaxed_message_bytes) {
                return false;
            }
            _message_bytes = bytes;
            return true;
        }
        if (n == "signing-cert-host") {
            if (v == "aws") {
                _signing_cert_host.clear();
                return true;
            }
            if (!valid_host(v)) {
                return false;
            }
            _signing_cert_host = v;
            return true;
        }
        return false;
    }

private:
    [[nodiscard]] static auto lower(std::string_view s) -> std::string {
        std::string out(s);
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    /// A DNS name, optionally with a port: labels of letters, digits and
    /// hyphens, not starting or ending with a hyphen.
    [[nodiscard]] static auto valid_host(std::string_view h) -> bool {
        if (const auto colon = h.rfind(':'); colon != std::string_view::npos) {
            const auto port = h.substr(colon + 1);
            unsigned p = 0;
            const auto [end, ec] = std::from_chars(port.data(), port.data() + port.size(), p);
            if (ec != std::errc{} || end != port.data() + port.size() || p == 0 || p > 65535) {
                return false;
            }
            h = h.substr(0, colon);
        }
        if (h.empty() || h.size() > 253) {
            return false;
        }
        std::size_t start = 0;
        while (start <= h.size()) {
            const auto dot = h.find('.', start);
            const auto label = h.substr(
                start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
            if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-' ||
                !std::all_of(label.begin(), label.end(),
                             [](unsigned char c) { return std::isalnum(c) != 0 || c == '-'; })) {
                return false;
            }
            if (dot == std::string_view::npos) {
                break;
            }
            start = dot + 1;
        }
        return true;
    }
};

namespace compat_detail {

[[nodiscard]] inline auto bad_switch(std::string_view name, std::string_view value) -> sns_error {
    return invalid_parameter("Tags", "Unknown Kythira compatibility setting " + std::string(name) +
                                         "=" + std::string(value));
}

[[nodiscard]] inline auto switch_of(std::string_view tag_key) -> std::optional<std::string_view> {
    if (tag_key.size() > k_compat_tag_prefix.size() && tag_key.starts_with(k_compat_tag_prefix)) {
        return tag_key.substr(k_compat_tag_prefix.size());
    }
    return std::nullopt;
}

}  // namespace compat_detail

/// The cluster's profile from its config (`switch = value` pairs), starting
/// from `aws`; nullopt names the first bad pair through `bad`.
[[nodiscard]] inline auto cluster_profile(
    const std::vector<std::pair<std::string, std::string>>& settings, std::string* bad = nullptr)
    -> std::optional<sns_compat_profile> {
    sns_compat_profile p;
    for (const auto& [name, value] : settings) {
        if (!p.set(name, value)) {
            if (bad != nullptr) {
                *bad = name + "=" + value;
            }
            return std::nullopt;
        }
    }
    return p;
}

/// Checks a topic's tags for compatibility settings it cannot take, for
/// CreateTopic and TagResource. Other tags are not looked at.
[[nodiscard]] inline auto check_compat_tags(
    const std::vector<std::pair<std::string, std::string>>& tags) -> std::optional<sns_error> {
    sns_compat_profile scratch;
    for (const auto& [key, value] : tags) {
        if (auto name = compat_detail::switch_of(key); name && !scratch.set(*name, value)) {
            return compat_detail::bad_switch(key, value);
        }
    }
    return std::nullopt;
}

/// The profile one topic runs with: the cluster's, overlaid with the
/// topic's `kythira:compat:*` tags. Tags `check_compat_tags` would refuse
/// cannot be on a topic; any that are (from an older release) are skipped.
[[nodiscard]] inline auto resolve_profile(
    const sns_compat_profile& cluster,
    const std::vector<std::pair<std::string, std::string>>& topic_tags) -> sns_compat_profile {
    auto p = cluster;
    for (const auto& [key, value] : topic_tags) {
        if (auto name = compat_detail::switch_of(key)) {
            auto trial = p;
            if (trial.set(*name, value)) {
                p = trial;
            }
        }
    }
    return p;
}

/// SNS's regional tiers for the publish rate and the soft-throttled APIs.
enum class region_tier : std::uint8_t {
    us_east_1,  ///< US East (N. Virginia)
    large,      ///< US West (Oregon), Europe (Ireland)
    medium,     ///< Ohio, N. California, Mumbai, Seoul, Singapore, Sydney, Tokyo, Frankfurt
    small,      ///< every other region
};

[[nodiscard]] constexpr auto tier_of(std::string_view region) -> region_tier {
    if (region == "us-east-1") {
        return region_tier::us_east_1;
    }
    if (region == "us-west-2" || region == "eu-west-1") {
        return region_tier::large;
    }
    constexpr std::array<std::string_view, 8> medium{
        "us-east-2",      "us-west-1",      "ap-south-1",     "ap-northeast-2",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-central-1"};
    for (const auto r : medium) {
        if (r == region) {
            return region_tier::medium;
        }
    }
    return region_tier::small;
}

/// The numbers a profile means in one region. Zero means unlimited (a
/// relaxed switch).
class sns_limits {
public:
    sns_limits(sns_compat_profile profile, std::string region)
        : _p(std::move(profile)), _region(std::move(region)), _tier(tier_of(_region)) {}

    [[nodiscard]] auto profile() const -> const sns_compat_profile& { return _p; }

    /// The largest message (or batch payload) a topic takes, given its
    /// `MaximumMessageSize` attribute when it has one.
    [[nodiscard]] auto max_message_bytes(std::optional<std::size_t> topic_attribute) const
        -> std::size_t {
        if (_p._message_bytes) {
            return *_p._message_bytes;
        }
        return std::min(topic_attribute.value_or(k_default_message_bytes), k_max_message_bytes);
    }

    /// Messages published per second per account (Publish and PublishBatch
    /// entries together).
    [[nodiscard]] auto publish_per_second(bool fifo) const -> std::uint32_t {
        if (!_p._throttling) {
            return 0;
        }
        switch (_tier) {
            case region_tier::us_east_1:
                return 30'000;
            case region_tier::large:
                return 9'000;
            case region_tier::medium:
                return fifo ? 3'000 : 1'500;
            case region_tier::small:
                return fifo ? 3'000 : 300;
        }
        return 300;
    }

    /// An API's transactions per second per account; 0 for the ones SNS
    /// does not limit separately (Publish and PublishBatch, which
    /// `publish_per_second` covers) and when throttling is off.
    [[nodiscard]] auto api_per_second(std::string_view operation) const -> std::uint32_t {
        if (!_p._throttling) {
            return 0;
        }
        struct fixed {
            std::string_view _op;
            std::uint32_t _tps;
        };
        // The hard limits, the same in every region.
        static constexpr std::array<fixed, 23> hard{{
            {"AddPermission", 10},
            {"CheckIfPhoneNumberIsOptedOut", 50},
            {"CreateSMSSandboxPhoneNumber", 1},
            {"DeleteSMSSandboxPhoneNumber", 1},
            {"GetSMSAttributes", 20},
            {"GetSMSSandboxAccountStatus", 10},
            {"ListEndpointsByPlatformApplication", 30},
            {"ListOriginationNumbers", 1},
            {"ListPhoneNumbersOptedOut", 10},
            {"ListPlatformApplications", 15},
            {"ListSMSSandboxPhoneNumbers", 1},
            {"ListSubscriptions", 30},
            {"ListSubscriptionsByTopic", 30},
            {"ListTagsForResource", 10},
            {"ListTopics", 30},
            {"OptInPhoneNumber", 20},
            {"RemovePermission", 10},
            {"SetSMSAttributes", 1},
            {"Subscribe", 100},
            {"TagResource", 10},
            {"Unsubscribe", 100},
            {"UntagResource", 10},
            {"VerifySMSSandboxPhoneNumber", 1},
        }};
        for (const auto& f : hard) {
            if (f._op == operation) {
                return f._tps;
            }
        }
        if (operation == "PutDataProtectionPolicy") {
            return 1;
        }
        if (operation == "Publish" || operation == "PublishBatch") {
            return 0;
        }
        // The regional tier: ConfirmSubscription, CreateTopic, DeleteTopic,
        // the attribute calls and the platform calls.
        switch (_tier) {
            case region_tier::us_east_1:
                return 3'000;
            case region_tier::large:
                return 900;
            case region_tier::medium:
                return 150;
            case region_tier::small:
                return 30;
        }
        return 30;
    }

    [[nodiscard]] auto topics_per_account(bool fifo) const -> std::uint64_t {
        return _p._aws_count_limits ? (fifo ? 1'000U : 100'000U) : 0U;
    }

    [[nodiscard]] auto subscriptions_per_topic(bool fifo) const -> std::uint64_t {
        return _p._aws_count_limits ? (fifo ? 100U : 12'500'000U) : 0U;
    }

    [[nodiscard]] auto pending_subscriptions_per_account() const -> std::uint64_t {
        return _p._aws_count_limits ? 5'000U : 0U;
    }

    [[nodiscard]] auto filter_policies_per_topic() const -> std::uint64_t {
        return _p._aws_count_limits ? 200U : 0U;
    }

    [[nodiscard]] auto filter_policies_per_account() const -> std::uint64_t {
        return _p._aws_count_limits ? 10'000U : 0U;
    }

    /// FIFO throughput with `FifoThroughputScope` Topic: messages and bytes
    /// per second per topic.
    [[nodiscard]] auto fifo_topic_messages_per_second() const -> std::uint32_t {
        return _p._aws_fifo_throughput ? 3'000U : 0U;
    }
    [[nodiscard]] auto fifo_topic_bytes_per_second() const -> std::uint64_t {
        return _p._aws_fifo_throughput ? 20'000'000U : 0U;
    }
    /// Per message group, either scope.
    [[nodiscard]] auto fifo_group_messages_per_second() const -> std::uint32_t {
        return _p._aws_fifo_throughput ? 300U : 0U;
    }

    /// Entries in one PublishBatch: ten, whatever the profile, since it is
    /// part of the API.
    [[nodiscard]] static constexpr auto batch_entries() -> std::size_t { return 10; }

    /// The host of `SigningCertURL`.
    [[nodiscard]] auto signing_cert_host() const -> std::string {
        return _p._signing_cert_host.empty() ? "sns." + _region + ".amazonaws.com"
                                             : _p._signing_cert_host;
    }

private:
    sns_compat_profile _p;
    std::string _region;
    region_tier _tier;
};

}  // namespace kythira::sns
