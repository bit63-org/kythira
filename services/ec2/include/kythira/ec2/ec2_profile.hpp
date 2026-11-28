// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_profile.hpp
/// @brief The `aws` profile and the switches set per cluster and per
///        account (`.kiro/specs/ec2-compatible-api/` Requirements 2.2 and
///        2.3).
///
/// The default profile, `aws`, is EC2's behaviour for every switch. A
/// cluster sets switches in its config; an account overrides them, and the
/// account's value wins. No switch changes an error code, message or
/// status: a quota reached is EC2's error for that quota, whatever the
/// quota's value.
///
///   switch                  AWS value  other value
///   throttling              on         off       request and resource buckets
///                                                (`ec2_throttle.hpp`)
///   instance-quota          aws        <count>   running and pending instances
///   vcpu-quota              aws        <count>   their vCPUs
///   volume-quota            aws        <count>   volumes
///   volume-capacity-quota   aws        <GiB>     volume capacity, per volume type
///   snapshot-quota          aws        <count>   snapshots
///   terminated-retention    aws        <seconds> how long `Describe*` shows a
///                                                terminated instance
///   client-token-retention  aws        <seconds> how long a ClientToken
///                                                returns its first result
///
/// The `aws` values, from the Service Quotas defaults for EC2 and EBS
/// (read 2026-11-27): 5 vCPUs of on-demand standard instances (quota
/// L-1216C47A; accounts usually hold a higher applied value, which an
/// operator sets as `vcpu-quota`), 50 TiB per EBS volume type (L-7A658B76
/// and its siblings), 100,000 snapshots per region (L-309BACF6). EC2 has no
/// instance-count or volume-count quota, so their `aws` value is none.
/// Terminated instances stay visible to `Describe*` for about an hour, as
/// on EC2. EC2 documents no exact ClientToken retention; Kythira keeps a
/// token 24 hours, so a client retrying across a day-long outage still gets
/// its first answer.
///
/// Names and values are matched case-insensitively. An unknown switch or a
/// value it does not take is refused, so a typo fails at configuration
/// instead of silently keeping EC2's behaviour.

#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace kythira::ec2 {

/// The `aws` values (see the file comment).
inline constexpr std::uint64_t k_aws_vcpu_quota = 5;
inline constexpr std::uint64_t k_aws_volume_capacity_gib = 50U * 1024U;
inline constexpr std::uint64_t k_aws_snapshot_quota = 100'000;
inline constexpr std::chrono::seconds k_aws_terminated_retention{3600};
inline constexpr std::chrono::seconds k_aws_client_token_retention{24 * 3600};

struct ec2_profile {
    bool _throttling = true;
    /// nullopt: no quota (EC2 has none).
    std::optional<std::uint64_t> _instance_quota;
    std::uint64_t _vcpu_quota = k_aws_vcpu_quota;
    /// nullopt: no quota (EC2 has none).
    std::optional<std::uint64_t> _volume_quota;
    std::uint64_t _volume_capacity_gib = k_aws_volume_capacity_gib;
    std::uint64_t _snapshot_quota = k_aws_snapshot_quota;
    std::chrono::seconds _terminated_retention = k_aws_terminated_retention;
    std::chrono::seconds _client_token_retention = k_aws_client_token_retention;

    friend auto operator==(const ec2_profile&, const ec2_profile&) -> bool = default;

    /// The switches set away from EC2's behaviour, by name, for metrics and
    /// logs.
    [[nodiscard]] auto relaxed() const -> std::vector<std::string_view> {
        const ec2_profile aws;
        std::vector<std::string_view> out;
        if (_throttling != aws._throttling) {
            out.emplace_back("throttling");
        }
        if (_instance_quota != aws._instance_quota) {
            out.emplace_back("instance-quota");
        }
        if (_vcpu_quota != aws._vcpu_quota) {
            out.emplace_back("vcpu-quota");
        }
        if (_volume_quota != aws._volume_quota) {
            out.emplace_back("volume-quota");
        }
        if (_volume_capacity_gib != aws._volume_capacity_gib) {
            out.emplace_back("volume-capacity-quota");
        }
        if (_snapshot_quota != aws._snapshot_quota) {
            out.emplace_back("snapshot-quota");
        }
        if (_terminated_retention != aws._terminated_retention) {
            out.emplace_back("terminated-retention");
        }
        if (_client_token_retention != aws._client_token_retention) {
            out.emplace_back("client-token-retention");
        }
        return out;
    }

    /// Sets one switch by name and value (`aws` restores EC2's value).
    /// Returns false, changing nothing, for an unknown switch or a value it
    /// does not take.
    [[nodiscard]] auto set(std::string_view name, std::string_view value) -> bool {
        const auto n = lower(name);
        const auto v = lower(value);
        const bool aws = v == "aws";
        if (n == "throttling") {
            if (v == "on" || v == "off") {
                _throttling = v == "on";
                return true;
            }
            return false;
        }
        const auto count = aws ? std::optional<std::uint64_t>{} : number(v);
        if (!aws && !count) {
            return false;
        }
        if (n == "instance-quota") {
            _instance_quota = count;
        } else if (n == "vcpu-quota") {
            _vcpu_quota = count.value_or(k_aws_vcpu_quota);
        } else if (n == "volume-quota") {
            _volume_quota = count;
        } else if (n == "volume-capacity-quota") {
            _volume_capacity_gib = count.value_or(k_aws_volume_capacity_gib);
        } else if (n == "snapshot-quota") {
            _snapshot_quota = count.value_or(k_aws_snapshot_quota);
        } else if (n == "terminated-retention") {
            _terminated_retention = count ? std::chrono::seconds(static_cast<std::int64_t>(*count))
                                          : k_aws_terminated_retention;
        } else if (n == "client-token-retention") {
            _client_token_retention = count
                                          ? std::chrono::seconds(static_cast<std::int64_t>(*count))
                                          : k_aws_client_token_retention;
        } else {
            return false;
        }
        return true;
    }

private:
    [[nodiscard]] static auto lower(std::string_view s) -> std::string {
        std::string out(s);
        for (auto& c : out) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return out;
    }

    /// A whole number, at most ten digits (a retention of 300 years, more
    /// instances than a region holds), so the seconds never overflow.
    [[nodiscard]] static auto number(std::string_view s) -> std::optional<std::uint64_t> {
        if (s.empty() || s.size() > 10) {
            return std::nullopt;
        }
        std::uint64_t out = 0;
        const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
        if (ec != std::errc{} || end != s.data() + s.size()) {
            return std::nullopt;
        }
        return out;
    }
};

/// The cluster's profile and the accounts that override it.
class ec2_profiles {
public:
    ec2_profiles() = default;
    explicit ec2_profiles(ec2_profile cluster) : _cluster(cluster) {}

    [[nodiscard]] auto cluster() const -> const ec2_profile& { return _cluster; }

    /// The profile an account's requests meet: the cluster's, with the
    /// account's switches on top.
    [[nodiscard]] auto for_account(std::string_view account) const -> const ec2_profile& {
        const auto it = _accounts.find(account);
        return it == _accounts.end() ? _cluster : it->second;
    }

    /// Reads one config line: `<switch> = <value>` for the cluster, or
    /// `account.<12 digits>.<switch> = <value>` for an account, whose other
    /// switches stay the cluster's. Blank lines and `#` comments are
    /// skipped. Returns false, changing nothing, for anything else.
    ///
    /// Cluster lines must come before account lines that rely on them: an
    /// account's profile copies the cluster's when its first line is read.
    [[nodiscard]] auto apply(std::string_view line) -> bool {
        const auto trim = [](std::string_view s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) {
                s.remove_prefix(1);
            }
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) {
                s.remove_suffix(1);
            }
            return s;
        };
        line = trim(line);
        if (line.empty() || line.front() == '#') {
            return true;
        }
        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            return false;
        }
        auto name = trim(line.substr(0, eq));
        const auto value = trim(line.substr(eq + 1));
        if (!name.starts_with("account.")) {
            return _cluster.set(name, value);
        }
        name.remove_prefix(8);
        const auto dot = name.find('.');
        const auto account = name.substr(0, dot);
        if (dot == std::string_view::npos || account.size() != 12 ||
            account.find_first_not_of("0123456789") != std::string_view::npos) {
            return false;
        }
        auto p = for_account(account);
        if (!p.set(name.substr(dot + 1), value)) {
            return false;
        }
        _accounts.insert_or_assign(std::string(account), p);
        return true;
    }

private:
    ec2_profile _cluster;
    std::map<std::string, ec2_profile, std::less<>> _accounts;
};

}  // namespace kythira::ec2
