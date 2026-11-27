// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_admin_answer.hpp
/// @brief What a node-provided admin command (`KYTHIRA.EVACUATE`, task 19
///        of .kiro/specs/redis-general-data-types/) answers the gateway,
///        which writes it in the caller's protocol.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira {

/// An error (its first line, with its code), `+OK`, one bulk string (the
/// internal forms other nodes read), or lines (an array of bulk strings).
struct redis_admin_answer {
    enum class kind : std::uint8_t {
        lines,
        bulk,
        error,
        ok
    };
    kind _kind = kind::lines;
    std::vector<std::string> _lines;

    static auto error(std::string e) -> redis_admin_answer { return {kind::error, {std::move(e)}}; }
    static auto bulk(std::string b) -> redis_admin_answer { return {kind::bulk, {std::move(b)}}; }
    static auto ok() -> redis_admin_answer { return {kind::ok, {}}; }
};

/// What a node without `data` answers another node's internal
/// `KYTHIRA.EVACUATE ... LOCAL`: it holds no replica, so it has no part in
/// an evacuation and must not hold one back.
inline constexpr std::string_view k_evacuate_no_data = "NODATA this node holds no data";

}  // namespace kythira
