// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_multi_key_exec.hpp
/// Multi-key writes whose keys share one group, as one `exec` record
/// (.kiro/specs/redis-general-data-types/ task 6, Requirement 6.1, design
/// Component 5). The front end routes every key first: one group gives one
/// record carrying every key, several give a multi-Raft transaction (or
/// `-CROSSSLOT` without transactions). The record goes through
/// `submit_multi_key_command`, which refuses it when a split moved a key
/// away between routing and submission, and the front end plans again.
///
/// | command id  | arguments after the name   | reply                       |
/// |-------------|----------------------------|-----------------------------|
/// | `DEL`       | key [key ...]              | keys removed                |
/// | `UNLINK`    | key [key ...]              | keys removed                |
/// | `RENAME`    | src dst                    | OK, or `ERR no such key`    |
/// | `RENAMENX`  | src dst                    | 1 or 0                      |
/// | `COPY`      | src dst [REPLACE]          | 1 or 0                      |
/// | `MSETNX`    | key value [key value ...]  | 1 or 0                      |
///
/// `SMOVE` and `SINTERSTORE`/`SUNIONSTORE`/`SDIFFSTORE` plan the same way;
/// redis_set_exec.hpp applies them.
///
/// `RENAME` and `COPY` carry the source's deadline to the destination, as
/// Redis does. Under the immutable-value rule (Requirement 5.2) `RENAME`
/// changes both keys (it takes the source away and may replace the
/// destination), so it needs the mutable bit of the source, and of the
/// destination when that exists; `COPY REPLACE` needs the destination's
/// when it exists. Creating keys (`COPY` to a new key, `MSETNX`) and `DEL`
/// stay allowed.

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>
#include <kythira/redis/redis_value.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kythira {

/// The positions in an `exec` record's arguments that are keys, in order:
/// the order of the mutable-key bitmap and of the routing check.
[[nodiscard]] inline auto redis_exec_key_positions(redis_command_id id,
                                                   const std::vector<std::string>& args)
    -> std::vector<std::size_t> {
    std::vector<std::size_t> out;
    switch (id) {
        case redis_command_id::del:
        case redis_command_id::unlink:
            for (std::size_t i = 0; i < args.size(); ++i) {
                out.push_back(i);
            }
            break;
        case redis_command_id::rename:
        case redis_command_id::renamenx:
        case redis_command_id::copy:
            for (std::size_t i = 0; i < 2 && i < args.size(); ++i) {
                out.push_back(i);
            }
            break;
        case redis_command_id::msetnx:
            for (std::size_t i = 0; i < args.size(); i += 2) {
                out.push_back(i);
            }
            break;
        case redis_command_id::lmove:
        case redis_command_id::smove:
            // src dst max-bytes max-count member
            for (std::size_t i = 0; i < 2 && i < args.size(); ++i) {
                out.push_back(i);
            }
            break;
        case redis_command_id::lmpop: {
            // numkeys key [key ...] LEFT|RIGHT count
            const auto n = args.empty() ? std::nullopt : redis_string_detail::parse_u64(args[0]);
            for (std::size_t i = 1; n && i <= *n && i < args.size(); ++i) {
                out.push_back(i);
            }
            break;
        }
        case redis_command_id::sinterstore:
        case redis_command_id::sunionstore:
        case redis_command_id::sdiffstore:
            // dst max-bytes max-count src [src ...]
            if (!args.empty()) {
                out.push_back(0);
            }
            for (std::size_t i = 3; i < args.size(); ++i) {
                out.push_back(i);
            }
            break;
        default:
            if (!args.empty()) {
                out.push_back(0);
            }
            break;
    }
    return out;
}

/// The keys of an `exec` record, in bitmap order.
[[nodiscard]] inline auto redis_exec_keys(redis_command_id id, const std::vector<std::string>& args)
    -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto i : redis_exec_key_positions(id, args)) {
        out.push_back(args[i]);
    }
    return out;
}

/// Applies one multi-key `exec` record at command time `t`. `Store` is the
/// interface `apply_redis_string_exec` takes. Returns `nullopt` for a
/// command id this file does not apply.
template<typename Store>
auto apply_redis_multi_key_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_string_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    if (id != redis_command_id::del && id != redis_command_id::unlink &&
        id != redis_command_id::rename && id != redis_command_id::renamenx &&
        id != redis_command_id::copy && id != redis_command_id::msetnx) {
        return std::nullopt;
    }
    const auto& a = c._args;
    const auto syntax = [] { return redis_reply::error(std::string(k_syntax)); };
    const auto conflict = [] { return redis_reply::error(std::string(k_conflict)); };
    const auto live = [&](const std::string& key) {
        auto e = store.find(key);
        if (e && e->_expire_at_ms != 0 && e->_expire_at_ms <= t) {
            e = nullptr;
        }
        return e;
    };

    if (id == redis_command_id::del || id == redis_command_id::unlink) {
        if (a.empty()) {
            return syntax();
        }
        std::int64_t removed = 0;
        for (const auto& key : a) {
            const bool was_live = live(key) != nullptr;
            // An expired entry goes too, uncounted, as Redis's lazy expiry
            // deletes it on the lookup.
            if (store.erase(key) && was_live) {
                ++removed;
            }
        }
        return redis_reply::integer(removed);
    }

    if (id == redis_command_id::msetnx) {
        if (a.empty() || a.size() % 2 != 0) {
            return syntax();
        }
        for (std::size_t i = 0; i < a.size(); i += 2) {
            if (live(a[i])) {
                return redis_reply::integer(0);
            }
        }
        for (std::size_t i = 0; i < a.size(); i += 2) {
            store.put(a[i], to_bytes(a[i + 1]), 0);
        }
        return redis_reply::integer(1);
    }

    // RENAME, RENAMENX, COPY: src dst [REPLACE]
    if (a.size() < 2 || (id != redis_command_id::copy && a.size() != 2) ||
        (id == redis_command_id::copy && a.size() > 3) || (a.size() == 3 && a[2] != "REPLACE")) {
        return syntax();
    }
    const auto& src = a[0];
    const auto& dst = a[1];
    const auto from = live(src);
    if (id == redis_command_id::copy) {
        if (src == dst) {
            return redis_reply::error("ERR source and destination objects are the same");
        }
        if (!from) {
            return redis_reply::integer(0);
        }
        const auto to = live(dst);
        if (to) {
            if (a.size() != 3) {
                return redis_reply::integer(0);
            }
            if (!may_mutate_key(c, 1)) {
                return conflict();
            }
        }
        redis_store_put_copy(store, dst, *from, from->_expire_at_ms);
        return redis_reply::integer(1);
    }
    if (!from) {
        return redis_reply::error("ERR no such key");
    }
    if (src == dst) {
        return id == redis_command_id::rename ? redis_reply::simple("OK") : redis_reply::integer(0);
    }
    const auto to = live(dst);
    if (id == redis_command_id::renamenx && to) {
        return redis_reply::integer(0);
    }
    if (!may_mutate_key(c, 0) || (to && !may_mutate_key(c, 1))) {
        return conflict();
    }
    // `from` is a handle, so it outlives the erase; the copy keeps the
    // value's type and deadline (Requirement 3.7).
    (void)store.erase(src);
    redis_store_put_copy(store, dst, *from, from->_expire_at_ms);
    return id == redis_command_id::rename ? redis_reply::simple("OK") : redis_reply::integer(1);
}

}  // namespace kythira
