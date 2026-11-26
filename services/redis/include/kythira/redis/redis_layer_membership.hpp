// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_layer_membership.hpp
/// @brief The pieces of Redis layer membership that know nothing about the
///        gateway (.kiro/specs/redis-general-data-types/ task 18,
///        Requirement 20; design Component 7 "SCAN cursors").
///
/// A gateway finds the front ends it calls in one of three places, read
/// through `layers::member_directory` (include/raft/layer_membership.hpp):
///
///  - the layer membership group, when the node is told its voters
///    (`KYTHIRA_REDIS_MEMBERSHIP`): every gateway and front end announces
///    itself there, reports its load, and follows the drain state an
///    operator or the capacity loop sets;
///  - DNS discovery (`KYTHIRA_REDIS_FRONT_ENDS_DNS`): every address a name
///    resolves to is a front end, re-resolved on an interval;
///  - configuration (`KYTHIRA_REDIS_FRONT_ENDS`).
///
/// This header has what those need and can be tested alone: the member
/// list's bytes on the internal link, the load a node reports, DNS
/// resolution of every address, and the `SCAN` cursor layout that names
/// the front end which issued a cursor.

#include <raft/layer_membership.hpp>

#include <boost/json.hpp>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::redis_membership {

// ---- SCAN cursors -----------------------------------------------------------

/// A cursor is `(front-end index : 14) | (cursor id : 50)`; 0 is "start" and
/// "done" (design Component 7).
inline constexpr unsigned k_cursor_id_bits = 50;
inline constexpr std::uint32_t k_max_front_end_index = (1U << 14) - 1;
inline constexpr std::uint64_t k_max_cursor_id = (std::uint64_t{1} << k_cursor_id_bits) - 1;

struct cursor_parts {
    std::uint32_t front_end_index = 0;
    std::uint64_t id = 0;

    friend auto operator==(const cursor_parts&, const cursor_parts&) -> bool = default;
};

/// The cursor for `id` issued by front end `index`, or nullopt when either
/// does not fit (index 1..16383, id 1..2^50-1).
[[nodiscard]] constexpr auto pack_cursor(std::uint32_t index, std::uint64_t id) noexcept
    -> std::optional<std::uint64_t> {
    if (index == 0 || index > k_max_front_end_index || id == 0 || id > k_max_cursor_id) {
        return std::nullopt;
    }
    return (std::uint64_t{index} << k_cursor_id_bits) | id;
}

/// The issuer and id of a cursor; nullopt for 0 and for a cursor with no
/// issuer or no id, which no front end hands out.
[[nodiscard]] constexpr auto unpack_cursor(std::uint64_t cursor) noexcept
    -> std::optional<cursor_parts> {
    const auto index = static_cast<std::uint32_t>(cursor >> k_cursor_id_bits);
    const auto id = cursor & k_max_cursor_id;
    if (index == 0 || id == 0) {
        return std::nullopt;
    }
    return cursor_parts{index, id};
}

/// The front-end index a node takes when none is configured: its node id,
/// when that is a number that fits; else 0 (it issues no cursor another
/// front end can find).
[[nodiscard]] inline auto default_front_end_index(std::string_view node_id) -> std::uint32_t {
    if (node_id.empty() || node_id.size() > 5) {
        return 0;
    }
    std::uint32_t v = 0;
    for (const char c : node_id) {
        if (c < '0' || c > '9') {
            return 0;
        }
        v = v * 10 + static_cast<std::uint32_t>(c - '0');
    }
    return v <= k_max_front_end_index ? v : 0;
}

/// The address of the serving front end that took `index`, if any.
[[nodiscard]] inline auto front_end_address(const std::vector<layers::layer_member>& members,
                                            std::uint32_t index) -> std::optional<std::string> {
    if (index == 0) {
        return std::nullopt;
    }
    for (const auto& m : members) {
        if (m.index == index && m.roles.has(layers::role::front_end)) {
            return m.address;
        }
    }
    return std::nullopt;
}

// ---- the member list on the internal link -------------------------------------

/// `KYTHIRA.MEMBERS LIST`'s answer: a JSON array of members.
[[nodiscard]] inline auto encode_members(const std::vector<layers::layer_member>& members)
    -> std::string {
    boost::json::array out;
    for (const auto& m : members) {
        out.push_back(layers::layer_membership_core::member_to_json(m));
    }
    return boost::json::serialize(out);
}

/// The members in `KYTHIRA.MEMBERS LIST`'s answer; nullopt when it does not
/// parse, so a damaged answer is never taken for an empty layer.
[[nodiscard]] inline auto decode_members(std::string_view bytes)
    -> std::optional<std::vector<layers::layer_member>> {
    try {
        const auto v = boost::json::parse(bytes);
        std::vector<layers::layer_member> out;
        for (const auto& m : v.as_array()) {
            out.push_back(layers::layer_membership_core::member_from_json(m.as_object()));
        }
        return out;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ---- load ------------------------------------------------------------------------

/// The CPU seconds this process has used (user + system), from
/// /proc/self/stat; nullopt where there is no such file.
[[nodiscard]] inline auto process_cpu_seconds() -> std::optional<double> {
    std::ifstream in("/proc/self/stat");
    std::string line;
    if (!in || !std::getline(in, line)) {
        return std::nullopt;
    }
    // The command name is in parentheses and may hold spaces: count fields
    // from the last ')'. utime and stime are fields 14 and 15, so the 12th
    // and 13th after it.
    const auto close = line.rfind(')');
    if (close == std::string::npos) {
        return std::nullopt;
    }
    std::istringstream rest(line.substr(close + 1));
    std::string field;
    double utime = 0;
    double stime = 0;
    for (int i = 1; i <= 13 && rest >> field; ++i) {
        if (i == 12) {
            utime = std::stod(field);
        } else if (i == 13) {
            stime = std::stod(field);
        }
    }
    const auto ticks = ::sysconf(_SC_CLK_TCK);
    if (ticks <= 0) {
        return std::nullopt;
    }
    return (utime + stime) / static_cast<double>(ticks);
}

/// What a node reports to the group (Requirement 20.3): connections as open
/// streams, commands per second, bytes sent per second, and its share of the
/// machine's CPUs, each measured since the previous sample.
class load_meter {
public:
    struct counters {
        std::uint64_t connections = 0;
        std::uint64_t commands = 0;
        std::uint64_t bytes_out = 0;
        /// CPU seconds used so far, or nullopt where it cannot be read.
        std::optional<double> cpu_seconds;
    };

    [[nodiscard]] auto sample(const counters& now, std::chrono::steady_clock::time_point at)
        -> layers::layer_load {
        layers::layer_load out;
        out.open_streams = now.connections;
        if (_last) {
            const auto secs = std::chrono::duration<double>(at - _last_at).count();
            if (secs > 0) {
                out.requests_per_second =
                    static_cast<double>(now.commands - std::min(now.commands, _last->commands)) /
                    secs;
                out.bytes_served_per_second = static_cast<std::uint64_t>(
                    static_cast<double>(now.bytes_out - std::min(now.bytes_out, _last->bytes_out)) /
                    secs);
                if (now.cpu_seconds && _last->cpu_seconds) {
                    const auto cpus = std::max<long>(1, ::sysconf(_SC_NPROCESSORS_ONLN));
                    out.cpu = std::clamp((*now.cpu_seconds - *_last->cpu_seconds) /
                                             (secs * static_cast<double>(cpus)),
                                         0.0, 1.0);
                }
            }
        }
        _last = now;
        _last_at = at;
        return out;
    }

private:
    std::optional<counters> _last;
    std::chrono::steady_clock::time_point _last_at{};
};

// ---- DNS discovery ---------------------------------------------------------------

/// Splits "host:port" (or "[v6]:port"); nullopt without a port.
[[nodiscard]] inline auto split_host_port(std::string_view text)
    -> std::optional<std::pair<std::string, std::string>> {
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size()) {
        return std::nullopt;
    }
    auto host = text.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return std::pair{std::string(host), std::string(text.substr(colon + 1))};
}

/// Every address `host:port` resolves to, as "ip:port" ("[ip]:port" for
/// IPv6), sorted and without duplicates; empty when it does not resolve.
[[nodiscard]] inline auto resolve_all(std::string_view host_port) -> std::vector<std::string> {
    std::vector<std::string> out;
    const auto parts = split_host_port(host_port);
    if (!parts) {
        return out;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(parts->first.c_str(), parts->second.c_str(), &hints, &res) != 0) {
        return out;
    }
    for (auto* p = res; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
            if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) {
                out.push_back(std::string(buf) + ":" + parts->second);
            }
        } else if (p->ai_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(p->ai_addr);
            if (::inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != nullptr) {
                out.push_back("[" + std::string(buf) + "]:" + parts->second);
            }
        }
    }
    ::freeaddrinfo(res);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

/// Front ends found by DNS, as members of a configuration directory.
[[nodiscard]] inline auto discovered_front_ends(const std::vector<std::string>& addresses)
    -> std::vector<layers::layer_member> {
    std::vector<layers::layer_member> out;
    out.reserve(addresses.size());
    for (const auto& a : addresses) {
        layers::layer_member m;
        m.id = a;
        m.address = a;
        m.roles = layers::role_set{layers::role::front_end};
        out.push_back(std::move(m));
    }
    return out;
}

}  // namespace kythira::redis_membership
