// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_throttle.hpp
/// @brief EC2's request and resource throttling
///        (`.kiro/specs/ec2-compatible-api/` Requirements 2.2 and 2.3).
///
/// EC2 throttles each account with token buckets, from the EC2 Developer
/// Guide's "Request throttling for the Amazon EC2 API" (read 2026-11-27):
///
///   bucket                                       capacity  refill/s
///   non-mutating (Describe*, List*, Search*,          100        20
///     Get*)
///   unfiltered and unpaginated non-mutating            50        10
///     (seven describes asked with no filter, IDs
///     or MaxResults)
///   mutating (everything else)                         50         5
///   resource-intensive (nine actions)                  50         5
///   uncategorized (one bucket per action)            per action, below
///
/// plus the filtered-describe buckets of DescribeInstances,
/// DescribeInstanceStatus, DescribeImages and DescribeVolumes, and the
/// resource buckets that meter instances rather than calls: RunInstances
/// 1000 instances refilling at 2/s, StartInstances 1000 at 2/s,
/// StopInstances and TerminateInstances 1000 at 20/s. A request takes one
/// token from its request bucket and, for those four, one token per
/// instance from its resource bucket; either empty is `RequestLimitExceeded`
/// (HTTP 503), which every SDK retries with backoff. The console bucket is
/// left out: Kythira cannot tell the console's calls from anyone else's.
///
/// Buckets live in memory on the node that serves the call, like Kinesis's
/// control-plane buckets: a client that sticks to one endpoint (every SDK
/// does) meets EC2's rates exactly, and one that spreads its calls over N
/// gateways can reach N times them. They start full and are dropped after
/// ten idle minutes, by which time every bucket has refilled (the slowest,
/// 50 tokens at 0.1/s, takes 500 s), so memory follows the active accounts
/// and a dropped bucket comes back exactly as it would have been. The
/// `throttling` switch off (`ec2_profile`) admits everything.

#include <raft/aws_ec2_protocol.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace kythira::ec2 {

struct bucket_rate {
    double _capacity = 0;
    double _refill_per_second = 0;

    friend auto operator==(const bucket_rate&, const bucket_rate&) -> bool = default;
};

inline constexpr bucket_rate k_non_mutating{100, 20};
inline constexpr bucket_rate k_unfiltered_non_mutating{50, 10};
inline constexpr bucket_rate k_mutating{50, 5};
inline constexpr bucket_rate k_resource_intensive{50, 5};

namespace throttle_detail {

struct named_rate {
    std::string_view _name;
    bucket_rate _rate;
};

// clang-format off

/// The uncategorized actions, each with its own bucket, sorted by name.
inline constexpr std::array<named_rate, 123> k_uncategorized{{
    {"AcceptVpcEndpointConnections", {10, 1}},
    {"AdvertiseByoipCidr", {1, 0.1}},
    {"AssignIpv6Addresses", {100, 5}},
    {"AssignPrivateIpAddresses", {100, 5}},
    {"AssignPrivateNatGatewayAddress", {10, 1}},
    {"AssociateCapacityReservationBillingOwner", {1, 0.5}},
    {"AssociateEnclaveCertificateIamRole", {10, 1}},
    {"AssociateIamInstanceProfile", {100, 5}},
    {"AssociateNatGatewayAddress", {10, 1}},
    {"AttachVerifiedAccessTrustProvider", {10, 2}},
    {"AuthorizeClientVpnIngress", {5, 2}},
    {"CancelDeclarativePoliciesReport", {1, 1}},
    {"CopyImage", {100, 1}},
    {"CreateClientVpnRoute", {5, 2}},
    {"CreateCoipCidr", {5, 1}},
    {"CreateCoipPool", {5, 1}},
    {"CreateDefaultSubnet", {1, 1}},
    {"CreateDefaultVpc", {1, 1}},
    {"CreateLaunchTemplateVersion", {100, 5}},
    {"CreateNatGateway", {10, 1}},
    {"CreateNetworkInterface", {100, 5}},
    {"CreateRestoreImageTask", {50, 0.1}},
    {"CreateSnapshot", {100, 5}},
    {"CreateSnapshots", {100, 5}},
    {"CreateSpotDatafeedSubscription", {50, 3}},
    {"CreateStoreImageTask", {50, 0.1}},
    {"CreateSubnetCidrReservation", {5, 1}},
    {"CreateTags", {100, 10}},
    {"CreateVerifiedAccessEndpoint", {20, 4}},
    {"CreateVerifiedAccessGroup", {10, 2}},
    {"CreateVerifiedAccessInstance", {10, 2}},
    {"CreateVerifiedAccessTrustProvider", {10, 2}},
    {"CreateVolume", {100, 5}},
    {"CreateVpcEndpoint", {4, 0.3}},
    {"CreateVpcEndpointServiceConfiguration", {10, 1}},
    {"DeleteClientVpnRoute", {5, 2}},
    {"DeleteCoipCidr", {5, 1}},
    {"DeleteCoipPool", {5, 1}},
    {"DeleteCoipPoolPermission", {5, 1}},
    {"DeleteNatGateway", {10, 1}},
    {"DeleteNetworkInterface", {100, 5}},
    {"DeleteQueuedReservedInstances", {5, 5}},
    {"DeleteSnapshot", {100, 5}},
    {"DeleteSpotDatafeedSubscription", {50, 3}},
    {"DeleteSubnetCidrReservation", {5, 1}},
    {"DeleteTags", {100, 10}},
    {"DeleteVerifiedAccessEndpoint", {20, 4}},
    {"DeleteVerifiedAccessGroup", {10, 2}},
    {"DeleteVerifiedAccessInstance", {10, 2}},
    {"DeleteVerifiedAccessTrustProvider", {10, 2}},
    {"DeleteVolume", {100, 5}},
    {"DeleteVpcEndpointServiceConfigurations", {10, 1}},
    {"DeleteVpcEndpoints", {4, 0.3}},
    {"DeprovisionByoipCidr", {1, 0.1}},
    {"DeregisterImage", {100, 5}},
    {"DescribeAggregateIdFormat", {10, 10}},
    {"DescribeByoipCidrs", {1, 0.5}},
    {"DescribeCapacityBlockExtensionOfferings", {10, 0.15}},
    {"DescribeCapacityBlockOfferings", {10, 0.15}},
    {"DescribeDeclarativePoliciesReports", {5, 5}},
    {"DescribeHostReservationOfferings", {100, 20}},
    {"DescribeHostReservations", {100, 20}},
    {"DescribeIdFormat", {10, 10}},
    {"DescribeIdentityIdFormat", {10, 10}},
    {"DescribeInstanceTopology", {5, 2}},
    {"DescribeMovingAddresses", {1, 1}},
    {"DescribePrincipalIdFormat", {10, 10}},
    {"DescribeReservedInstancesOfferings", {10, 10}},
    {"DescribeSecurityGroupReferences", {20, 5}},
    {"DescribeSpotDatafeedSubscription", {100, 13}},
    {"DescribeSpotFleetInstances", {100, 5}},
    {"DescribeSpotFleetRequestHistory", {100, 5}},
    {"DescribeSpotFleetRequests", {50, 3}},
    {"DescribeStaleSecurityGroups", {20, 5}},
    {"DescribeStoreImageTasks", {50, 0.5}},
    {"DescribeVerifiedAccessInstanceLoggingConfigurations", {10, 2}},
    {"DetachVerifiedAccessTrustProvider", {10, 2}},
    {"DisableFastLaunch", {5, 2}},
    {"DisableImageBlockPublicAccess", {1, 0.1}},
    {"DisableSnapshotBlockPublicAccess", {1, 0.1}},
    {"DisassociateCapacityReservationBillingOwner", {1, 0.5}},
    {"DisassociateEnclaveCertificateIamRole", {10, 1}},
    {"DisassociateIamInstanceProfile", {100, 5}},
    {"DisassociateNatGatewayAddress", {10, 1}},
    {"EnableFastLaunch", {5, 2}},
    {"EnableImageBlockPublicAccess", {1, 0.1}},
    {"EnableSnapshotBlockPublicAccess", {1, 0.1}},
    {"GetAssociatedEnclaveCertificateIamRoles", {10, 1}},
    {"GetDeclarativePoliciesReportSummary", {5, 5}},
    {"GetHostReservationPurchasePreview", {50, 5}},
    {"GetManagedResourceVisibility", {50, 15}},
    {"ModifyImageAttribute", {100, 5}},
    {"ModifyInstanceMetadataDefaults", {2, 2}},
    {"ModifyInstanceMetadataOptions", {100, 5}},
    {"ModifyLaunchTemplate", {100, 5}},
    {"ModifyManagedResourceVisibility", {1, 1}},
    {"ModifyNetworkInterfaceAttribute", {100, 5}},
    {"ModifySnapshotAttribute", {100, 5}},
    {"ModifyVerifiedAccessEndpoint", {20, 4}},
    {"ModifyVerifiedAccessEndpointPolicy", {20, 4}},
    {"ModifyVerifiedAccessGroup", {10, 2}},
    {"ModifyVerifiedAccessGroupPolicy", {20, 4}},
    {"ModifyVerifiedAccessInstance", {10, 2}},
    {"ModifyVerifiedAccessInstanceLoggingConfiguration", {10, 2}},
    {"ModifyVerifiedAccessTrustProvider", {10, 2}},
    {"ModifyVpcEndpoint", {4, 0.3}},
    {"ModifyVpcEndpointServiceConfiguration", {10, 1}},
    {"MoveAddressToVpc", {1, 1}},
    {"ProvisionByoipCidr", {1, 0.1}},
    {"PurchaseCapacityBlock", {10, 0.15}},
    {"PurchaseCapacityBlockExtension", {10, 0.15}},
    {"PurchaseHostReservation", {50, 5}},
    {"PurchaseReservedInstancesOffering", {5, 5}},
    {"RejectVpcEndpointConnections", {10, 1}},
    {"RestoreAddressToClassic", {1, 1}},
    {"RevokeClientVpnIngress", {5, 2}},
    {"RunInstances", {5, 2}},
    {"StartDeclarativePoliciesReport", {1, 1}},
    {"StartInstances", {5, 2}},
    {"TerminateInstances", {100, 5}},
    {"UnassignPrivateIpAddresses", {100, 5}},
    {"UnassignPrivateNatGatewayAddress", {10, 1}},
    {"WithdrawByoipCidr", {1, 0.1}},
}};

/// The resource-intensive actions, sorted.
inline constexpr std::array<std::string_view, 9> k_resource_intensive_actions{{
    "AcceptVpcPeeringConnection", "AuthorizeSecurityGroupIngress", "CancelSpotInstanceRequests",
    "CreateKeyPair", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection",
    "RejectVpcPeeringConnection", "RequestSpotInstances", "RevokeSecurityGroupIngress",
}};

/// The describes with a smaller bucket when asked with no filter, IDs or
/// MaxResults, sorted.
inline constexpr std::array<std::string_view, 7> k_unfiltered{{
    "DescribeInstanceStatus", "DescribeInstances", "DescribeNetworkInterfaces",
    "DescribeSecurityGroups", "DescribeSnapshots", "DescribeSpotInstanceRequests",
    "DescribeVolumes",
}};

/// The resource buckets, sorted.
inline constexpr std::array<named_rate, 4> k_resource_rates{{
    {"RunInstances", {1000, 2}},
    {"StartInstances", {1000, 2}},
    {"StopInstances", {1000, 20}},
    {"TerminateInstances", {1000, 20}},
}};

// clang-format on

template<class Table>
[[nodiscard]] constexpr auto find_rate(const Table& t, std::string_view name)
    -> std::optional<bucket_rate> {
    const auto* it =
        std::lower_bound(t.begin(), t.end(), name,
                         [](const named_rate& e, std::string_view n) { return e._name < n; });
    if (it != t.end() && it->_name == name) {
        return it->_rate;
    }
    return std::nullopt;
}

template<std::size_t N>
[[nodiscard]] constexpr auto contains(const std::array<std::string_view, N>& t,
                                      std::string_view name) -> bool {
    return std::binary_search(t.begin(), t.end(), name);
}

[[nodiscard]] constexpr auto non_mutating(std::string_view op) -> bool {
    return op.starts_with("Describe") || op.starts_with("List") || op.starts_with("Search") ||
           op.starts_with("Get");
}

/// The ID list a filtered describe counts: InstanceId for the instance
/// describes.
[[nodiscard]] inline auto id_count(const aws_ec2::params& p, std::string_view list) -> std::size_t {
    const auto ids = p.list(list);
    return ids ? ids->size() : 0;
}

}  // namespace throttle_detail

/// Which bucket a request meets: its key (a category, or the action for an
/// uncategorized action or a filtered describe) and the bucket's rate.
struct request_bucket {
    std::string _key;
    bucket_rate _rate;

    friend auto operator==(const request_bucket&, const request_bucket&) -> bool = default;
};

/// The request bucket for `operation` asked with `p`.
[[nodiscard]] inline auto request_bucket_for(std::string_view operation, const aws_ec2::params& p)
    -> request_bucket {
    using throttle_detail::contains;
    using throttle_detail::find_rate;
    using throttle_detail::id_count;
    using throttle_detail::k_uncategorized;
    using throttle_detail::k_unfiltered;
    const std::string op(operation);
    if (const auto r = find_rate(k_uncategorized, operation)) {
        return {op, *r};
    }
    if (contains(throttle_detail::k_resource_intensive_actions, operation)) {
        return {"resource-intensive", k_resource_intensive};
    }
    if (!throttle_detail::non_mutating(operation)) {
        return {"mutating", k_mutating};
    }
    const bool filtered = !p.sub("Filter").empty();
    const bool paged = p.contains("MaxResults");
    if (operation == "DescribeImages" || operation == "DescribeVolumes") {
        const auto ids = id_count(p, operation == "DescribeImages" ? "ImageId" : "VolumeId");
        if (filtered || paged || ids > 0) {
            return {op + ":filtered", {100, 100}};
        }
    }
    if (operation == "DescribeInstances" || operation == "DescribeInstanceStatus") {
        const auto ids = id_count(p, "InstanceId");
        if (ids == 1) {
            return {op + ":single-id", {500, 500}};
        }
        if (ids > 1) {
            return {op + ":multiple-ids", {250, 250}};
        }
        if (paged) {
            return {op + ":paged", {100, 100}};
        }
        if (filtered) {
            return {op + ":filtered", {100, 100}};
        }
    }
    if (contains(k_unfiltered, operation) && !filtered && !paged) {
        return {"unfiltered-non-mutating", k_unfiltered_non_mutating};
    }
    return {"non-mutating", k_non_mutating};
}

/// The instances a request asks its resource bucket for: RunInstances's
/// MaxCount (what EC2 could launch), the InstanceId list of the others; 0
/// for every other operation.
[[nodiscard]] inline auto resource_tokens(std::string_view operation, const aws_ec2::params& p)
    -> std::size_t {
    if (!throttle_detail::find_rate(throttle_detail::k_resource_rates, operation)) {
        return 0;
    }
    if (operation == "RunInstances") {
        const auto n = p.integer("MaxCount", 1, 1'000'000);
        return n && *n ? static_cast<std::size_t>(**n) : 1;
    }
    return std::max<std::size_t>(throttle_detail::id_count(p, "InstanceId"), 1);
}

/// The buckets of every account this node serves.
class ec2_throttle {
public:
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    explicit ec2_throttle(clock_fn clock = [] { return std::chrono::steady_clock::now(); })
        : _clock(std::move(clock)) {}

    /// Admits `operation` for `account` or answers RequestLimitExceeded.
    /// Both buckets are checked before either is charged, so a refusal
    /// costs nothing.
    [[nodiscard]] auto admit(std::string_view account, std::string_view operation,
                             const aws_ec2::params& p) -> std::optional<aws_ec2::error> {
        const auto req = request_bucket_for(operation, p);
        const auto res_rate =
            throttle_detail::find_rate(throttle_detail::k_resource_rates, operation);
        const auto res_tokens = static_cast<double>(resource_tokens(operation, p));
        const auto now = _clock();
        const std::scoped_lock lock(_mutex);
        sweep(now);
        auto& rb = fill(bucket_of(account, req._key, req._rate), req._rate, now);
        bucket* resb = nullptr;
        if (res_rate) {
            resb = &fill(bucket_of(account, std::string(operation) + ":resource", *res_rate),
                         *res_rate, now);
        }
        if (rb._tokens < 1 || (resb != nullptr && resb->_tokens < res_tokens)) {
            return aws_ec2::make_error(aws_ec2::codes::request_limit_exceeded,
                                       "Request limit exceeded.");
        }
        rb._tokens -= 1;
        if (resb != nullptr) {
            resb->_tokens -= res_tokens;
        }
        return std::nullopt;
    }

    /// The buckets held now (for tests and metrics).
    [[nodiscard]] auto buckets() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        return _buckets.size();
    }

private:
    struct bucket {
        double _tokens = 0;
        std::chrono::steady_clock::time_point _at;
    };

    using key = std::pair<std::string, std::string>;

    clock_fn _clock;
    mutable std::mutex _mutex;
    std::map<key, bucket, std::less<>> _buckets;
    std::chrono::steady_clock::time_point _last_sweep;

    auto bucket_of(std::string_view account, const std::string& name, const bucket_rate& rate)
        -> bucket& {
        auto [it, fresh] = _buckets.try_emplace(key{std::string(account), name});
        if (fresh) {
            it->second._tokens = rate._capacity;
            it->second._at = _clock();
        }
        return it->second;
    }

    static auto fill(bucket& b, const bucket_rate& rate, std::chrono::steady_clock::time_point now)
        -> bucket& {
        const std::chrono::duration<double> dt = now - b._at;
        if (dt.count() > 0) {
            b._tokens = std::min(rate._capacity, b._tokens + dt.count() * rate._refill_per_second);
            b._at = now;
        }
        return b;
    }

    // Once a minute, drops the buckets idle ten minutes (full by then; see
    // the file comment).
    void sweep(std::chrono::steady_clock::time_point now) {
        constexpr auto idle = std::chrono::minutes(1);
        if (now - _last_sweep < idle) {
            return;
        }
        _last_sweep = now;
        std::erase_if(_buckets, [&](const auto& kv) { return now - kv.second._at >= idle * 10; });
    }
};

}  // namespace kythira::ec2
