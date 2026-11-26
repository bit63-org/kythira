// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0
#pragma once

/// @file redis_admin_answer.hpp
/// @brief What a node-provided admin command (`KYTHIRA.EVACUATE`, task 19
///        of .kiro/specs/redis-general-data-types/) answers the gateway,
///        which writes it in the caller's protocol.

#include <cstdint>
#include <string>
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

}  // namespace kythira
