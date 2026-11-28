// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file ec2_region.hpp
/// @brief The region, its availability zones and the instance-type catalog,
///        and the describes served from them: `DescribeRegions`,
///        `DescribeAvailabilityZones` and `DescribeInstanceTypes`
///        (`.kiro/specs/ec2-compatible-api/` task 4, Requirement 2.4).
///
/// A Kythira EC2 endpoint serves one region; its zones are the
/// antikythera availability zones the operator configures. Instance types
/// come from a configured catalog that maps each name to whole cores, 1 GiB
/// pages and the device functions it carries. The default catalog names
/// Kythira types (`k1.small` and up); an operator may alias AWS names
/// (`alias t3.micro k1.small`) so tools that hard-code them run unchanged,
/// and an alias describes as itself with its target's shape.
///
/// The catalog's text form, one entry per line (`#` comments):
///
///   type <name> cores=<n> memory=<GiB> [arch=x86_64|arm64]
///        [devices=<function>:<count>,...]
///   alias <aws-name> <type>
///
/// Each describe takes its name list, `Filter.N` with the filters EC2
/// documents for it that Kythira can answer (others are refused as
/// unsupported, never silently ignored), and, for DescribeInstanceTypes,
/// `MaxResults` (5 to 100) with a sealed `NextToken`.

#include <kythira/ec2/ec2_filters.hpp>
#include <kythira/ec2/ec2_front_end.hpp>

#include <raft/aws_ec2_protocol.hpp>
#include <raft/aws_query_protocol.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace kythira::ec2 {

struct availability_zone {
    std::string _name;  // us-east-1a
    std::string _id;    // use1-az1
};

struct region_config {
    std::string _name = "us-east-1";
    /// The endpoint DescribeRegions reports.
    std::string _endpoint = "ec2.us-east-1.amazonaws.com";
    std::vector<availability_zone> _zones = {{"us-east-1a", "use1-az1"}};
};

struct device_count {
    std::string _function;
    std::uint32_t _count = 0;

    friend auto operator==(const device_count&, const device_count&) -> bool = default;
};

struct instance_type {
    std::string _name;
    std::uint32_t _cores = 0;
    std::uint32_t _memory_gib = 0;
    std::string _arch = "x86_64";
    std::vector<device_count> _devices;

    friend auto operator==(const instance_type&, const instance_type&) -> bool = default;
};

/// The instance-type catalog: Kythira's types and the AWS names aliased
/// to them.
class instance_type_catalog {
public:
    /// The default catalog: whole cores and 1 GiB pages, 2 GiB per core
    /// for the general types and 8 GiB per core for the memory type.
    [[nodiscard]] static auto defaults() -> instance_type_catalog {
        instance_type_catalog c;
        for (const auto& t : std::vector<instance_type>{{"k1.small", 1, 2, "x86_64", {}},
                                                        {"k1.medium", 2, 4, "x86_64", {}},
                                                        {"k1.large", 4, 8, "x86_64", {}},
                                                        {"k1.xlarge", 8, 16, "x86_64", {}},
                                                        {"k1.2xlarge", 16, 32, "x86_64", {}},
                                                        {"k1m.large", 4, 32, "x86_64", {}}}) {
            c._types.emplace(t._name, t);
        }
        return c;
    }

    /// Reads the text form; nullopt with `error` set on a bad line.
    [[nodiscard]] static auto parse(std::string_view text, std::string* error = nullptr)
        -> std::optional<instance_type_catalog> {
        instance_type_catalog c;
        std::istringstream in{std::string(text)};
        std::string line;
        int number = 0;
        const auto fail = [&](const std::string& why) -> std::optional<instance_type_catalog> {
            if (error != nullptr) {
                *error = "line " + std::to_string(number) + ": " + why;
            }
            return std::nullopt;
        };
        std::vector<std::tuple<int, std::string, std::string>> aliases;
        while (std::getline(in, line)) {
            ++number;
            if (const auto hash = line.find('#'); hash != std::string::npos) {
                line.erase(hash);
            }
            std::istringstream words(line);
            std::string kind;
            if (!(words >> kind)) {
                continue;
            }
            if (kind == "alias") {
                std::string from;
                std::string to;
                std::string extra;
                if (!(words >> from >> to) || (words >> extra)) {
                    return fail("alias takes a name and a type");
                }
                aliases.emplace_back(number, from, to);
                continue;
            }
            if (kind != "type") {
                return fail("unknown entry '" + kind + "'");
            }
            instance_type t;
            if (!(words >> t._name)) {
                return fail("type needs a name");
            }
            std::string field;
            while (words >> field) {
                const auto eq = field.find('=');
                if (eq == std::string::npos) {
                    return fail("expected key=value, got '" + field + "'");
                }
                const auto key = field.substr(0, eq);
                const auto value = field.substr(eq + 1);
                if (key == "cores" || key == "memory") {
                    auto n = number_of(value);
                    if (!n || *n == 0) {
                        return fail(key + " must be a positive whole number");
                    }
                    (key == "cores" ? t._cores : t._memory_gib) = *n;
                } else if (key == "arch") {
                    if (value != "x86_64" && value != "arm64") {
                        return fail("arch is x86_64 or arm64");
                    }
                    t._arch = value;
                } else if (key == "devices") {
                    std::istringstream list(value);
                    std::string one;
                    while (std::getline(list, one, ',')) {
                        const auto colon = one.find(':');
                        const auto n = colon == std::string::npos
                                           ? std::nullopt
                                           : number_of(one.substr(colon + 1));
                        if (!n || colon == 0) {
                            return fail("devices are <function>:<count>");
                        }
                        t._devices.push_back({one.substr(0, colon), *n});
                    }
                } else {
                    return fail("unknown field '" + key + "'");
                }
            }
            if (t._cores == 0 || t._memory_gib == 0) {
                return fail("type " + t._name + " needs cores and memory");
            }
            if (!c._types.emplace(t._name, t).second) {
                return fail("type " + t._name + " listed twice");
            }
        }
        for (const auto& [at, from, to] : aliases) {
            number = at;
            if (c._types.contains(from) || c._aliases.contains(from)) {
                return fail("alias " + from + " names an existing type");
            }
            if (!c._types.contains(to)) {
                return fail("alias " + from + " names unknown type " + to);
            }
            c._aliases.emplace(from, to);
        }
        if (c._types.empty()) {
            return fail("no types");
        }
        return c;
    }

    /// The type `name` names, directly or as an alias, as `name` describes
    /// it.
    [[nodiscard]] auto find(std::string_view name) const -> std::optional<instance_type> {
        if (const auto it = _types.find(name); it != _types.end()) {
            return it->second;
        }
        if (const auto a = _aliases.find(name); a != _aliases.end()) {
            auto t = _types.at(a->second);
            t._name = a->first;
            return t;
        }
        return std::nullopt;
    }

    /// Every type and alias, sorted by name.
    [[nodiscard]] auto all() const -> std::vector<instance_type> {
        std::map<std::string, instance_type, std::less<>> out(_types.begin(), _types.end());
        for (const auto& [from, _] : _aliases) {
            out.emplace(from, *find(from));
        }
        std::vector<instance_type> v;
        v.reserve(out.size());
        for (auto& [_, t] : out) {
            v.push_back(std::move(t));
        }
        return v;
    }

private:
    std::map<std::string, instance_type, std::less<>> _types;
    std::map<std::string, std::string, std::less<>> _aliases;

    [[nodiscard]] static auto number_of(std::string_view s) -> std::optional<std::uint32_t> {
        std::uint32_t n = 0;
        const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
        if (ec != std::errc{} || end != s.data() + s.size()) {
            return std::nullopt;
        }
        return n;
    }
};

namespace region_detail {

[[nodiscard]] inline auto names(const aws_ec2::params& p, std::string_view list)
    -> aws_ec2::result<std::vector<std::string>> {
    if (p.contains(list)) {
        return std::vector<std::string>{std::string(*p.get(list))};
    }
    return p.list(list);
}

/// A describe with no resource: authorized on `*` by the front end.
[[nodiscard]] inline auto no_resources(call_context&, const aws_ec2::params&)
    -> aws_ec2::result<authz_plan> {
    return authz_plan{};
}

[[nodiscard]] inline auto join(const std::vector<std::string>& v) -> std::string {
    std::string out;
    for (const auto& s : v) {
        out += out.empty() ? "" : ", ";
        out += s;
    }
    return out;
}

}  // namespace region_detail

/// The three describes served from the region and the type catalog.
/// `sealer` seals DescribeInstanceTypes's page tokens.
class region_service {
public:
    region_service(region_config region, instance_type_catalog types,
                   std::shared_ptr<const aws_query::marker_sealer> sealer)
        : _region(std::move(region)), _types(std::move(types)), _sealer(std::move(sealer)) {}

    template<class FrontEnd> void register_with(FrontEnd& fe) {
        fe.on("DescribeRegions",
              {region_detail::no_resources,
               [this](call_context& ctx, const aws_ec2::params& p) { return regions(ctx, p); }});
        fe.on("DescribeAvailabilityZones",
              {region_detail::no_resources,
               [this](call_context& ctx, const aws_ec2::params& p) { return zones(ctx, p); }});
        fe.on("DescribeInstanceTypes",
              {region_detail::no_resources,
               [this](call_context& ctx, const aws_ec2::params& p) { return types(ctx, p); }});
    }

    [[nodiscard]] auto regions(call_context&, const aws_ec2::params& p) const
        -> aws_ec2::result<std::string> {
        const auto fs = filter_set::read(p, {"endpoint", "opt-in-status", "region-name"});
        if (!fs) {
            return fs.err();
        }
        const auto wanted = region_detail::names(p, "RegionName");
        if (!wanted) {
            return wanted.err();
        }
        for (const auto& n : *wanted) {
            if (n != _region._name) {
                return aws_ec2::make_error(aws_ec2::codes::invalid_parameter_value,
                                           "Invalid region: " + n);
            }
        }
        if (const auto all = p.boolean("AllRegions"); !all) {
            return all.err();
        }
        const auto fields = [this](std::string_view name) -> std::vector<std::string> {
            if (name == "endpoint") {
                return {_region._endpoint};
            }
            if (name == "region-name") {
                return {_region._name};
            }
            return {"opt-in-not-required"};
        };
        aws_query::xml_writer w;
        w.open("regionInfo");
        if (fs->matches(fields, {})) {
            w.open("item")
                .element("regionName", _region._name)
                .element("regionEndpoint", _region._endpoint)
                .element("optInStatus", "opt-in-not-required")
                .close();
        }
        w.close();
        return w.str();
    }

    [[nodiscard]] auto zones(call_context&, const aws_ec2::params& p) const
        -> aws_ec2::result<std::string> {
        const auto fs =
            filter_set::read(p, {"group-name", "message", "network-border-group", "opt-in-status",
                                 "region-name", "state", "zone-id", "zone-name", "zone-type"});
        if (!fs) {
            return fs.err();
        }
        const auto by_name = region_detail::names(p, "ZoneName");
        const auto by_id = region_detail::names(p, "ZoneId");
        if (!by_name) {
            return by_name.err();
        }
        if (!by_id) {
            return by_id.err();
        }
        if (const auto all = p.boolean("AllAvailabilityZones"); !all) {
            return all.err();
        }
        std::vector<std::string> unknown;
        for (const auto& n : *by_name) {
            if (std::none_of(_region._zones.begin(), _region._zones.end(),
                             [&](const auto& z) { return z._name == n; })) {
                unknown.push_back(n);
            }
        }
        for (const auto& n : *by_id) {
            if (std::none_of(_region._zones.begin(), _region._zones.end(),
                             [&](const auto& z) { return z._id == n; })) {
                unknown.push_back(n);
            }
        }
        if (!unknown.empty()) {
            return aws_ec2::make_error(
                aws_ec2::codes::invalid_parameter_value,
                "Invalid availability zone: [" + region_detail::join(unknown) + "]");
        }
        aws_query::xml_writer w;
        w.open("availabilityZoneInfo");
        for (const auto& z : _region._zones) {
            const bool listed =
                (by_name->empty() && by_id->empty()) ||
                std::find(by_name->begin(), by_name->end(), z._name) != by_name->end() ||
                std::find(by_id->begin(), by_id->end(), z._id) != by_id->end();
            const auto fields = [&](std::string_view name) -> std::vector<std::string> {
                if (name == "zone-name") {
                    return {z._name};
                }
                if (name == "zone-id") {
                    return {z._id};
                }
                if (name == "state") {
                    return {"available"};
                }
                if (name == "zone-type") {
                    return {"availability-zone"};
                }
                if (name == "opt-in-status") {
                    return {"opt-in-not-required"};
                }
                if (name == "message") {
                    return {};
                }
                return {_region._name};  // region-name, group-name, network-border-group
            };
            if (!listed || !fs->matches(fields, {})) {
                continue;
            }
            w.open("item")
                .element("optInStatus", "opt-in-not-required")
                .raw("<messageSet/>")
                .element("regionName", _region._name)
                .element("zoneName", z._name)
                .element("zoneId", z._id)
                .element("groupName", _region._name)
                .element("networkBorderGroup", _region._name)
                .element("zoneType", "availability-zone")
                .element("zoneState", "available")
                .close();
        }
        w.close();
        return w.str();
    }

    [[nodiscard]] auto types(call_context& ctx, const aws_ec2::params& p) const
        -> aws_ec2::result<std::string> {
        const auto fs =
            filter_set::read(p, {"bare-metal", "current-generation", "instance-type",
                                 "memory-info.size-in-mib", "processor-info.supported-architecture",
                                 "vcpu-info.default-cores", "vcpu-info.default-vcpus"});
        if (!fs) {
            return fs.err();
        }
        const auto wanted = region_detail::names(p, "InstanceType");
        if (!wanted) {
            return wanted.err();
        }
        std::vector<std::string> unknown;
        for (const auto& n : *wanted) {
            if (!_types.find(n)) {
                unknown.push_back(n);
            }
        }
        if (!unknown.empty()) {
            return aws_ec2::make_error("InvalidInstanceType",
                                       "The following supplied instance types do not exist: [" +
                                           region_detail::join(unknown) + "]");
        }
        const auto context = page_context(ctx._operation, ctx._principal.account);
        const auto req = read_page(p, *_sealer, context, 5, 100);
        if (!req) {
            return req.err();
        }
        std::vector<std::pair<std::string, instance_type>> items;
        for (auto& t : _types.all()) {
            if (!wanted->empty() &&
                std::find(wanted->begin(), wanted->end(), t._name) == wanted->end()) {
                continue;
            }
            const auto fields = [&t](std::string_view name) -> std::vector<std::string> {
                if (name == "instance-type") {
                    return {t._name};
                }
                if (name == "vcpu-info.default-vcpus" || name == "vcpu-info.default-cores") {
                    return {std::to_string(t._cores)};
                }
                if (name == "memory-info.size-in-mib") {
                    return {std::to_string(std::uint64_t{t._memory_gib} * 1024U)};
                }
                if (name == "processor-info.supported-architecture") {
                    return {t._arch};
                }
                if (name == "current-generation") {
                    return {"true"};
                }
                return {"false"};  // bare-metal
            };
            if (fs->matches(fields, {})) {
                items.emplace_back(t._name, std::move(t));
            }
        }
        const auto pg = paginate(items, *req, *_sealer, context);
        aws_query::xml_writer w;
        aws_ec2::item_list(w, "instanceTypeSet", pg._items, [](auto& x, const instance_type& t) {
            const auto cores = std::to_string(t._cores);
            x.element("instanceType", t._name)
                .boolean("currentGeneration", true)
                .boolean("freeTierEligible", false)
                .raw("<supportedUsageClasses><item>on-demand</item></supportedUsageClasses>")
                .raw("<supportedRootDeviceTypes><item>ebs</item></supportedRootDeviceTypes>")
                .raw(
                    "<supportedVirtualizationTypes><item>hvm</item>"
                    "</supportedVirtualizationTypes>")
                .boolean("bareMetal", false)
                .element("hypervisor", "kvm")
                .open("processorInfo")
                .open("supportedArchitectures")
                .element("item", t._arch)
                .close()
                .close()
                .open("vCpuInfo")
                .element("defaultVCpus", cores)
                .element("defaultCores", cores)
                .element("defaultThreadsPerCore", "1")
                .close()
                .open("memoryInfo")
                .element("sizeInMiB", std::to_string(std::uint64_t{t._memory_gib} * 1024U))
                .close()
                .boolean("instanceStorageSupported", false)
                .boolean("hibernationSupported", false)
                .boolean("burstablePerformanceSupported", false)
                .boolean("dedicatedHostsSupported", false)
                .boolean("autoRecoverySupported", false);
        });
        w.raw(next_token_xml(pg._next_token));
        return w.str();
    }

private:
    region_config _region;
    instance_type_catalog _types;
    std::shared_ptr<const aws_query::marker_sealer> _sealer;
};

}  // namespace kythira::ec2
