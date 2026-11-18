// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_server_identity.hpp
/// How the gateway names itself in `HELLO` and `INFO server`
/// (.kiro/specs/redis-general-data-types/ Requirement 1.5-1.6).
///
/// Kythira identifies itself as Kythira, the way Valkey does: `server` /
/// `server_name` say `kythira`, and `kythira_version` carries the build's
/// own version. `redis_version` (INFO) and `version` (HELLO) are a plain
/// `major.minor.patch` compatibility level instead, the Redis release whose
/// command set the build implements for its target clients. Clients such as
/// Lettuce and StackExchange.Redis parse that field to gate features, and a
/// vendor suffix (the old `7.0.0-kythira`) breaks their parsers, so it is
/// never allowed one.

#include <raft/build_version.hpp>

#include <cstddef>
#include <string_view>

namespace kythira {

/// The compatibility level this build reports unless
/// `KYTHIRA_REDIS_COMPAT_VERSION` overrides it. Raise it when the command
/// tables reach a later Redis release's command set for the target clients.
inline constexpr std::string_view k_redis_compat_version = "7.0.0";

/// True when `v` is exactly `major.minor.patch`: three non-empty runs of
/// ASCII digits separated by dots, nothing before or after. This is the
/// only shape `redis_version` may take (Requirement 1.5).
[[nodiscard]] constexpr auto is_plain_redis_version(std::string_view v) noexcept -> bool {
    std::size_t parts = 0;
    std::size_t digits = 0;
    for (const char c : v) {
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c == '.' && digits > 0 && parts < 2) {
            ++parts;
            digits = 0;
        } else {
            return false;
        }
    }
    return parts == 2 && digits > 0;
}

static_assert(is_plain_redis_version(k_redis_compat_version));

}  // namespace kythira
