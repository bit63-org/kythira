// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file layer_roles.hpp
/// @brief The layers a service node can run, and sets of them
///        (.kiro/specs/kinesis-independent-layers/ design "Roles per node,
///        not a cluster mode"; shared by the DynamoDB, KMS and HSM
///        independent-layers specs).
///
/// A node runs any non-empty subset of four roles: `gateway` (client
/// protocol, SigV4), `front_end` (the service API over the data layer),
/// `data` (Raft replicas) and `segments` (record segment volumes). A node
/// with every role is co-located, the default. The names here are the ones
/// configuration (`KINESIS_ROLES`, `KYTHIRA_DYNAMODB_ROLES`, ...) and layer
/// identities (`layer_identity.hpp`) use.

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kythira::layers {

/// One layer a node can run. The values are bits of a `role_set`.
enum class role : std::uint8_t {
    gateway = 1U << 0U,
    front_end = 1U << 1U,
    data = 1U << 2U,
    segments = 1U << 3U,
};

inline constexpr std::array<role, 4> every_role = {role::gateway, role::front_end, role::data,
                                                   role::segments};

/// The name a role has in configuration and in the SAN URI.
[[nodiscard]] constexpr auto role_name(role r) noexcept -> std::string_view {
    switch (r) {
        case role::gateway:
            return "gateway";
        case role::front_end:
            return "front_end";
        case role::data:
            return "data";
        case role::segments:
            return "segments";
    }
    return "";
}

/// The role named `name`; `nullopt` for anything else (names are exact and
/// lower-case).
[[nodiscard]] constexpr auto parse_role(std::string_view name) noexcept -> std::optional<role> {
    for (const auto r : every_role) {
        if (role_name(r) == name) {
            return r;
        }
    }
    return std::nullopt;
}

/// A set of roles, printed in a fixed order so equal sets print equally.
class role_set {
public:
    constexpr role_set() noexcept = default;
    constexpr role_set(std::initializer_list<role> roles) noexcept {
        for (const auto r : roles) {
            add(r);
        }
    }

    /// Every role: what a co-located node runs.
    [[nodiscard]] static constexpr auto all() noexcept -> role_set {
        return role_set{role::gateway, role::front_end, role::data, role::segments};
    }

    /// Parses "gateway,front_end" (commas, no spaces). Throws
    /// `std::invalid_argument` naming an unknown or repeated role, or an
    /// empty element. The empty string is the empty set.
    [[nodiscard]] static auto parse(std::string_view text) -> role_set {
        role_set out;
        if (text.empty()) {
            return out;
        }
        std::size_t start = 0;
        for (;;) {
            const auto comma = text.find(',', start);
            const auto name = text.substr(
                start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
            const auto r = parse_role(name);
            if (!r) {
                throw std::invalid_argument("unknown layer role \"" + std::string(name) +
                                            "\" (expected gateway, front_end, data or segments)");
            }
            if (out.has(*r)) {
                throw std::invalid_argument("layer role \"" + std::string(name) +
                                            "\" is listed twice");
            }
            out.add(*r);
            if (comma == std::string_view::npos) {
                return out;
            }
            start = comma + 1;
        }
    }

    constexpr void add(role r) noexcept { _bits |= static_cast<std::uint8_t>(r); }
    constexpr void remove(role r) noexcept {
        _bits &= static_cast<std::uint8_t>(~static_cast<std::uint8_t>(r));
    }
    [[nodiscard]] constexpr auto has(role r) const noexcept -> bool {
        return (_bits & static_cast<std::uint8_t>(r)) != 0;
    }
    /// Whether this set shares at least one role with `other`.
    [[nodiscard]] constexpr auto intersects(role_set other) const noexcept -> bool {
        return (_bits & other._bits) != 0;
    }
    /// Whether every role of `other` is in this set.
    [[nodiscard]] constexpr auto contains(role_set other) const noexcept -> bool {
        return (_bits & other._bits) == other._bits;
    }
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return _bits == 0; }
    [[nodiscard]] constexpr auto bits() const noexcept -> std::uint8_t { return _bits; }

    /// "gateway,front_end,data,segments" order; empty for the empty set.
    [[nodiscard]] auto to_string() const -> std::string {
        std::string out;
        for (const auto r : every_role) {
            if (has(r)) {
                if (!out.empty()) {
                    out.push_back(',');
                }
                out.append(role_name(r));
            }
        }
        return out;
    }

    friend constexpr auto operator==(role_set, role_set) noexcept -> bool = default;
    friend constexpr auto operator|(role_set a, role_set b) noexcept -> role_set {
        role_set out;
        out._bits = static_cast<std::uint8_t>(a._bits | b._bits);
        return out;
    }

private:
    std::uint8_t _bits = 0;
};

}  // namespace kythira::layers
