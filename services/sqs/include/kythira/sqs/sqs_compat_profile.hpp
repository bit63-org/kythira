// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_compat_profile.hpp
/// @brief The AWS-behaviour switches (`.kiro/specs/sqs-compatible-queues/`
///        Requirement 2.2, 2.3).
///
/// `sqs_compat_profile` holds one value per limit an operator may move.
/// The default, profile `aws`, is SQS's value for every switch, in every
/// deployment. A cluster sets switches in its config; a queue overrides
/// them with tags `kythira:compat:<switch>`, and the queue's value wins.
/// No switch changes an error code, message shape or status: a request
/// past a moved limit fails exactly as it would past SQS's.
///
///   switch             AWS value   range          what it bounds
///   message-size       1048576     1024-16777216  body + attributes, bytes
///   retention-min      60          1-1209600      MessageRetentionPeriod floor, s
///   retention-max      1209600     60-31536000    MessageRetentionPeriod ceiling, s
///   batch-size         10          1-100          entries per batch request
///   inflight-standard  120000      1-10000000     in-flight messages, standard
///   inflight-fifo      120000      1-10000000     in-flight messages, FIFO
///   fifo-throughput    on          on | off       FIFO per-queue/group rates
///   long-poll-max      20          0-300          WaitTimeSeconds ceiling, s
///   delete-cooldown    60          0-3600         recreate after DeleteQueue, s
///   purge-cooldown     60          0-3600         between PurgeQueue calls, s
///
/// Every numeric switch also takes `aws`, which sets SQS's value. Names
/// and `aws`/`on`/`off` are matched case-insensitively. An unknown switch
/// or a value out of range is an error, so a typo in a tag fails at
/// `CreateQueue` or `TagQueue` instead of silently keeping SQS's value.

#include <kythira/sqs/sqs_errors.hpp>

#include <raft/aws_json_protocol.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

inline constexpr std::string_view k_compat_tag_prefix = "kythira:compat:";

struct sqs_compat_profile {
    std::uint32_t _max_message_bytes = 1048576;
    std::uint32_t _min_retention_s = 60;
    std::uint32_t _max_retention_s = 1209600;
    std::uint32_t _max_batch_entries = 10;
    std::uint32_t _max_inflight_standard = 120000;
    std::uint32_t _max_inflight_fifo = 120000;
    bool _fifo_throughput_limits = true;
    std::uint32_t _max_wait_s = 20;
    std::uint32_t _delete_cooldown_s = 60;
    std::uint32_t _purge_cooldown_s = 60;

    friend auto operator==(const sqs_compat_profile&, const sqs_compat_profile&) -> bool = default;

    /// The switches set away from SQS's value, by name, for the queue's
    /// Kythira extension attribute and for metrics.
    [[nodiscard]] auto relaxed() const -> std::vector<std::string_view> {
        const sqs_compat_profile aws;
        std::vector<std::string_view> out;
        for (const auto& s : k_switches) {
            if (s.number != nullptr ? this->*s.number != aws.*s.number
                                    : this->*s.flag != aws.*s.flag) {
                out.push_back(s.name);
            }
        }
        return out;
    }

    /// Sets one switch by name and value. Returns false (and changes
    /// nothing) for an unknown switch or a value it does not take. A
    /// change that would leave retention-min above retention-max is
    /// refused too.
    [[nodiscard]] auto set(std::string_view name, std::string_view value) -> bool {
        const auto n = lower(name);
        const auto v = lower(value);
        const sqs_compat_profile aws;
        for (const auto& s : k_switches) {
            if (s.name != n) {
                continue;
            }
            if (s.flag != nullptr) {
                if (v != "on" && v != "off") {
                    return false;
                }
                this->*s.flag = v == "on";
                return true;
            }
            std::uint32_t x = aws.*s.number;
            if (v != "aws") {
                const auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), x);
                if (v.empty() || ec != std::errc{} || p != v.data() + v.size() || x < s.min ||
                    x > s.max) {
                    return false;
                }
            }
            auto trial = *this;
            trial.*s.number = x;
            if (trial._min_retention_s > trial._max_retention_s) {
                return false;
            }
            *this = trial;
            return true;
        }
        return false;
    }

private:
    struct switch_info {
        std::string_view name;
        std::uint32_t sqs_compat_profile::* number = nullptr;
        bool sqs_compat_profile::* flag = nullptr;
        std::uint32_t min = 0;
        std::uint32_t max = 0;
    };

    static constexpr std::array<switch_info, 10> k_switches{{
        {"message-size", &sqs_compat_profile::_max_message_bytes, nullptr, 1024, 16777216},
        {"retention-min", &sqs_compat_profile::_min_retention_s, nullptr, 1, 1209600},
        {"retention-max", &sqs_compat_profile::_max_retention_s, nullptr, 60, 31536000},
        {"batch-size", &sqs_compat_profile::_max_batch_entries, nullptr, 1, 100},
        {"inflight-standard", &sqs_compat_profile::_max_inflight_standard, nullptr, 1, 10000000},
        {"inflight-fifo", &sqs_compat_profile::_max_inflight_fifo, nullptr, 1, 10000000},
        {"fifo-throughput", nullptr, &sqs_compat_profile::_fifo_throughput_limits, 0, 0},
        {"long-poll-max", &sqs_compat_profile::_max_wait_s, nullptr, 0, 300},
        {"delete-cooldown", &sqs_compat_profile::_delete_cooldown_s, nullptr, 0, 3600},
        {"purge-cooldown", &sqs_compat_profile::_purge_cooldown_s, nullptr, 0, 3600},
    }};

    [[nodiscard]] static auto lower(std::string_view s) -> std::string {
        std::string out(s);
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }
};

namespace detail {

[[nodiscard]] inline auto bad_switch(std::string_view name, std::string_view value)
    -> aws_json::error {
    return make_error(k_validation_error, "Unknown Kythira compatibility setting " +
                                              std::string(name) + "=" + std::string(value));
}

[[nodiscard]] inline auto compat_switch_of(std::string_view tag_key)
    -> std::optional<std::string_view> {
    if (tag_key.size() > k_compat_tag_prefix.size() && tag_key.starts_with(k_compat_tag_prefix)) {
        return tag_key.substr(k_compat_tag_prefix.size());
    }
    return std::nullopt;
}

}  // namespace detail

/// The cluster's profile from its config (`switch = value` pairs), starting
/// from `aws`.
[[nodiscard]] inline auto cluster_profile(
    const std::vector<std::pair<std::string, std::string>>& settings)
    -> aws_json::result<sqs_compat_profile> {
    sqs_compat_profile p;
    for (const auto& [name, value] : settings) {
        if (!p.set(name, value)) {
            return detail::bad_switch(name, value);
        }
    }
    return p;
}

/// Checks a queue's tags for compatibility settings it cannot take, for
/// `CreateQueue` and `TagQueue`, starting from the cluster's profile (so
/// retention bounds are checked against what the queue would run with).
/// Other tags are not looked at.
[[nodiscard]] inline auto check_compat_tags(
    const sqs_compat_profile& cluster, const std::vector<std::pair<std::string, std::string>>& tags)
    -> std::optional<aws_json::error> {
    auto scratch = cluster;
    for (const auto& [key, value] : tags) {
        if (auto name = detail::compat_switch_of(key); name && !scratch.set(*name, value)) {
            return detail::bad_switch(key, value);
        }
    }
    return std::nullopt;
}

/// The profile one queue runs with: the cluster's, overlaid with the
/// queue's `kythira:compat:*` tags. Tags `check_compat_tags` would refuse
/// cannot be on a queue; any that are (from an older release) are skipped.
[[nodiscard]] inline auto resolve_profile(
    const sqs_compat_profile& cluster,
    const std::vector<std::pair<std::string, std::string>>& queue_tags) -> sqs_compat_profile {
    auto p = cluster;
    for (const auto& [key, value] : queue_tags) {
        if (auto name = detail::compat_switch_of(key)) {
            auto trial = p;
            if (trial.set(*name, value)) {
                p = trial;
            }
        }
    }
    return p;
}

}  // namespace kythira::sqs
