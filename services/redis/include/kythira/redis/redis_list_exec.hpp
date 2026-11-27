// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_list_exec.hpp
/// Lists, without blocking, as `exec` records apply them and as reads see
/// them (.kiro/specs/redis-general-data-types/ task 9, Requirement 12).
///
/// | command id | arguments after the name                                   | reply              |
/// |------------|------------------------------------------------------------|--------------------|
/// | `LPUSH`    | key max-bytes max-count element [...]                      | new length         |
/// | `RPUSH`    | key max-bytes max-count element [...]                      | new length         |
/// | `LPUSHX`   | key max-bytes max-count element [...]                      | new length or 0    |
/// | `RPUSHX`   | key max-bytes max-count element [...]                      | new length or 0    |
/// | `LPOP`     | key with-count(0\|1) count                                 | element(s) or nil  |
/// | `RPOP`     | key with-count(0\|1) count                                 | element(s) or nil  |
/// | `LSET`     | key index element max-bytes                                | OK                 |
/// | `LINSERT`  | key BEFORE\|AFTER pivot element max-bytes max-count        | length, -1 or 0    |
/// | `LREM`     | key count element                                          | removed            |
/// | `LTRIM`    | key start stop                                             | OK                 |
/// | `LMOVE`    | src dst LEFT\|RIGHT LEFT\|RIGHT max-bytes max-count        | element or nil     |
/// | `LMPOP`    | numkeys key [...] LEFT\|RIGHT count                        | [key, elements]    |
///
/// `RPOPLPUSH` arrives as `LMOVE src dst RIGHT LEFT`. `LMOVE` and `LMPOP`
/// name several keys and go through the multi-key planner
/// (redis_multi_key_exec.hpp). Every index is an `int64` as the client sent
/// it, counted from the end when negative, as in Redis.
///
/// Type errors, empty lists deleting their key, limits, deadlines and the
/// immutable-value rule work as for hashes (redis_hash_exec.hpp).

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_hash_exec.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>
#include <kythira/redis/redis_value.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace kythira {

namespace redis_list_detail {

[[nodiscard]] inline auto is_list_write(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::lpush:
        case redis_command_id::rpush:
        case redis_command_id::lpushx:
        case redis_command_id::rpushx:
        case redis_command_id::lpop:
        case redis_command_id::rpop:
        case redis_command_id::lset:
        case redis_command_id::linsert:
        case redis_command_id::lrem:
        case redis_command_id::ltrim:
        case redis_command_id::lmove:
        case redis_command_id::lmpop:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline auto is_list_read(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::llen:
        case redis_command_id::lindex:
        case redis_command_id::lrange:
        case redis_command_id::lpos:
            return true;
        default:
            return false;
    }
}

/// Redis's range normalisation (`LRANGE`, `LTRIM`): the inclusive index
/// range `start..stop` of a list of `len`, or nullopt when it is empty.
[[nodiscard]] inline auto normalise_range(std::int64_t start, std::int64_t stop, std::size_t len)
    -> std::optional<std::pair<std::size_t, std::size_t>> {
    const auto n = static_cast<std::int64_t>(len);
    if (start < 0) {
        start = std::max<std::int64_t>(0, n + start);
    }
    if (stop < 0) {
        stop = n + stop;
    }
    if (start > stop || start >= n) {
        return std::nullopt;
    }
    stop = std::min(stop, n - 1);
    return std::pair{static_cast<std::size_t>(start), static_cast<std::size_t>(stop)};
}

/// One index counted from the end when negative; nullopt when outside.
[[nodiscard]] inline auto normalise_index(std::int64_t i, std::size_t len)
    -> std::optional<std::size_t> {
    const auto n = static_cast<std::int64_t>(len);
    if (i < 0) {
        i += n;
    }
    if (i < 0 || i >= n) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(i);
}

}  // namespace redis_list_detail

/// Applies one list `exec` record at command time `t`. `Store` is the
/// interface `apply_redis_hash_exec` takes. Returns `nullopt` for a command
/// id this file does not apply.
template<typename Store>
auto apply_redis_list_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_string_detail;
    using namespace redis_list_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    if (!is_list_write(id)) {
        return std::nullopt;
    }
    const auto& a = c._args;
    const auto syntax = [] { return redis_reply::error(std::string(k_syntax)); };
    const auto wrongtype = [] { return redis_reply::error(std::string(k_redis_wrongtype)); };
    const auto conflict = [] { return redis_reply::error(std::string(k_conflict)); };
    const auto live = [&](const std::string& key) {
        auto e = store.find(key);
        if (e && e->_expire_at_ms != 0 && e->_expire_at_ms <= t) {
            e = nullptr;
        }
        return e;
    };
    using handle_type = decltype(live(std::string{}));
    using entry_type = std::remove_cvref_t<decltype(*std::declval<handle_type>())>;
    const auto is_list = [](const handle_type& e) {
        return !e || redis_entry_type(*e) == redis_value_type::list;
    };
    const redis_list none;
    const auto list_of = [&](const handle_type& e) -> const redis_list& {
        return e ? *e->_list : none;
    };
    const auto install = [&](const std::string& key, redis_list next, std::uint64_t expire) {
        if (next.empty()) {
            (void)store.erase(key);
            return;
        }
        auto e = std::make_shared<entry_type>();
        e->_type = redis_value_type::list;
        e->_expire_at_ms = expire;
        e->_list = std::make_shared<const redis_list>(std::move(next));
        store.put_entry(key, std::move(e));
    };
    const auto over_limits = [](const redis_list& l, std::uint64_t max_bytes,
                                std::uint64_t max_count) -> std::optional<redis_reply> {
        if (l.size() > max_count) {
            return redis_hash_detail::limit_error(max_count, "elements");
        }
        if (l.bytes() > max_bytes) {
            return redis_hash_detail::limit_error(max_bytes, "bytes");
        }
        return std::nullopt;
    };
    const auto bulk_array = [](std::vector<std::string> items) {
        std::vector<redis_reply> out;
        out.reserve(items.size());
        for (auto& i : items) {
            out.push_back(redis_reply::bulk(std::move(i)));
        }
        return redis_reply::array(std::move(out));
    };
    if (a.empty()) {
        return syntax();
    }

    switch (id) {
        case redis_command_id::lpush:
        case redis_command_id::rpush:
        case redis_command_id::lpushx:
        case redis_command_id::rpushx: {
            if (a.size() < 4) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[1]);
            const auto max_count = parse_u64(a[2]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            const bool only_existing =
                id == redis_command_id::lpushx || id == redis_command_id::rpushx;
            if (only_existing && !e) {
                return redis_reply::integer(0);
            }
            const bool left = id == redis_command_id::lpush || id == redis_command_id::lpushx;
            redis_list next = list_of(e);
            for (std::size_t i = 3; i < a.size(); ++i) {
                if (left) {
                    next.push_front(a[i]);
                } else {
                    next.push_back(a[i]);
                }
            }
            if (auto over = over_limits(next, *max_bytes, *max_count)) {
                return over;
            }
            if (e && !may_mutate_key(c, 0)) {
                return conflict();
            }
            const auto len = static_cast<std::int64_t>(next.size());
            install(a[0], std::move(next), e ? e->_expire_at_ms : 0);
            return redis_reply::integer(len);
        }
        case redis_command_id::lpop:
        case redis_command_id::rpop: {
            if (a.size() != 3 || (a[1] != "0" && a[1] != "1")) {
                return syntax();
            }
            const bool with_count = a[1] == "1";
            const auto count = parse_u64(a[2]);
            if (!count) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            if (!e) {
                return with_count ? redis_reply::null_array() : redis_reply::null();
            }
            if (with_count && *count == 0) {
                return redis_reply::array({});
            }
            if (!may_mutate_key(c, 0)) {
                return conflict();
            }
            redis_list next = *e->_list;
            std::vector<std::string> popped;
            const auto n = with_count ? std::min<std::uint64_t>(*count, next.size()) : 1;
            for (std::uint64_t i = 0; i < n; ++i) {
                popped.push_back(id == redis_command_id::lpop ? next.pop_front() : next.pop_back());
            }
            install(a[0], std::move(next), e->_expire_at_ms);
            if (!with_count) {
                return redis_reply::bulk(std::move(popped.front()));
            }
            return bulk_array(std::move(popped));
        }
        case redis_command_id::lset: {
            if (a.size() != 4) {
                return syntax();
            }
            const auto index = parse_int64(a[1]);
            const auto max_bytes = parse_u64(a[3]);
            if (!index || !max_bytes) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            if (!e) {
                return redis_reply::error("ERR no such key");
            }
            const auto at = normalise_index(*index, e->_list->size());
            if (!at) {
                return redis_reply::error("ERR index out of range");
            }
            if (e->_list->at(*at) == a[2]) {
                return redis_reply::simple("OK");
            }
            redis_list next = *e->_list;
            next.set(*at, a[2]);
            if (next.bytes() > *max_bytes) {
                return redis_hash_detail::limit_error(*max_bytes, "bytes");
            }
            if (!may_mutate_key(c, 0)) {
                return conflict();
            }
            install(a[0], std::move(next), e->_expire_at_ms);
            return redis_reply::simple("OK");
        }
        case redis_command_id::linsert: {
            if (a.size() != 6 || (a[1] != "BEFORE" && a[1] != "AFTER")) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[4]);
            const auto max_count = parse_u64(a[5]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            if (!e) {
                return redis_reply::integer(0);
            }
            std::optional<std::size_t> pivot;
            e->_list->visit(0, e->_list->size() - 1, [&](std::size_t i, const std::string& v) {
                if (v == a[2]) {
                    pivot = i;
                    return false;
                }
                return true;
            });
            if (!pivot) {
                return redis_reply::integer(-1);
            }
            redis_list next = *e->_list;
            next.insert(a[1] == "BEFORE" ? *pivot : *pivot + 1, a[3]);
            if (auto over = over_limits(next, *max_bytes, *max_count)) {
                return over;
            }
            if (!may_mutate_key(c, 0)) {
                return conflict();
            }
            const auto len = static_cast<std::int64_t>(next.size());
            install(a[0], std::move(next), e->_expire_at_ms);
            return redis_reply::integer(len);
        }
        case redis_command_id::lrem: {
            if (a.size() != 3) {
                return syntax();
            }
            const auto count = parse_int64(a[1]);
            if (!count) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            if (!e) {
                return redis_reply::integer(0);
            }
            const auto& l = *e->_list;
            // The indexes to remove, in increasing order.
            std::vector<std::size_t> hits;
            const auto limit = *count == 0  ? l.size()
                               : *count > 0 ? static_cast<std::size_t>(*count)
                                            : static_cast<std::size_t>(-(*count + 1)) + 1;
            const auto match = [&](std::size_t i, const std::string& v) {
                if (v == a[2]) {
                    hits.push_back(i);
                }
                return hits.size() < limit;
            };
            if (*count < 0) {
                l.visit_backwards(match);
                std::ranges::reverse(hits);
            } else {
                l.visit(0, l.size() - 1, match);
            }
            if (hits.empty()) {
                return redis_reply::integer(0);
            }
            if (!may_mutate_key(c, 0)) {
                return conflict();
            }
            redis_list next = l;
            std::size_t h = 0;
            next.retain([&](std::size_t i, const std::string&) {
                if (h < hits.size() && hits[h] == i) {
                    ++h;
                    return false;
                }
                return true;
            });
            install(a[0], std::move(next), e->_expire_at_ms);
            return redis_reply::integer(static_cast<std::int64_t>(hits.size()));
        }
        case redis_command_id::ltrim: {
            if (a.size() != 3) {
                return syntax();
            }
            const auto start = parse_int64(a[1]);
            const auto stop = parse_int64(a[2]);
            if (!start || !stop) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_list(e)) {
                return wrongtype();
            }
            if (!e) {
                return redis_reply::simple("OK");
            }
            const auto range = normalise_range(*start, *stop, e->_list->size());
            if (range && range->first == 0 && range->second + 1 == e->_list->size()) {
                return redis_reply::simple("OK");
            }
            if (!may_mutate_key(c, 0)) {
                return conflict();
            }
            redis_list next = *e->_list;
            next.retain([&](std::size_t i, const std::string&) {
                return range && i >= range->first && i <= range->second;
            });
            install(a[0], std::move(next), e->_expire_at_ms);
            return redis_reply::simple("OK");
        }
        case redis_command_id::lmove: {
            if (a.size() != 6 || (a[2] != "LEFT" && a[2] != "RIGHT") ||
                (a[3] != "LEFT" && a[3] != "RIGHT")) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[4]);
            const auto max_count = parse_u64(a[5]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            const auto from = live(a[0]);
            if (!is_list(from)) {
                return wrongtype();
            }
            if (!from) {
                return redis_reply::null();
            }
            const bool same = a[0] == a[1];
            const auto to = same ? from : live(a[1]);
            if (!is_list(to)) {
                return wrongtype();
            }
            redis_list src = *from->_list;
            auto v = a[2] == "LEFT" ? src.pop_front() : src.pop_back();
            redis_list dst = same ? src : list_of(to);
            if (a[3] == "LEFT") {
                dst.push_front(v);
            } else {
                dst.push_back(v);
            }
            if (auto over = over_limits(dst, *max_bytes, *max_count)) {
                return over;
            }
            if (!may_mutate_key(c, 0) || (!same && to && !may_mutate_key(c, 1))) {
                return conflict();
            }
            if (!same) {
                install(a[0], std::move(src), from->_expire_at_ms);
            }
            install(a[1], std::move(dst), to ? to->_expire_at_ms : 0);
            return redis_reply::bulk(std::move(v));
        }
        case redis_command_id::lmpop: {
            const auto numkeys = parse_u64(a[0]);
            if (!numkeys || *numkeys == 0 || a.size() != *numkeys + 3) {
                return syntax();
            }
            const auto& dir = a[*numkeys + 1];
            const auto count = parse_u64(a[*numkeys + 2]);
            if ((dir != "LEFT" && dir != "RIGHT") || !count || *count == 0) {
                return syntax();
            }
            for (std::size_t k = 0; k < *numkeys; ++k) {
                const auto& key = a[1 + k];
                const auto e = live(key);
                if (!is_list(e)) {
                    return wrongtype();
                }
                if (!e) {
                    continue;
                }
                if (!may_mutate_key(c, k)) {
                    return conflict();
                }
                redis_list next = *e->_list;
                std::vector<std::string> popped;
                const auto n = std::min<std::uint64_t>(*count, next.size());
                for (std::uint64_t i = 0; i < n; ++i) {
                    popped.push_back(dir == "LEFT" ? next.pop_front() : next.pop_back());
                }
                install(key, std::move(next), e->_expire_at_ms);
                return redis_reply::array({redis_reply::bulk(key), bulk_array(std::move(popped))});
            }
            return redis_reply::null_array();
        }
        default:
            return std::nullopt;
    }
}

/// The read of `id` on a list (`list` null when absent). `args` are the
/// arguments after the key in the front end's normal form: `LINDEX index`,
/// `LRANGE start stop`, `LPOS element rank count maxlen with-count(0|1)`.
[[nodiscard]] inline auto evaluate_redis_list_read(const redis_list* list, redis_command_id id,
                                                   std::span<const std::string> args)
    -> std::optional<redis_reply> {
    using namespace redis_list_detail;
    using redis_string_detail::parse_int64;
    const redis_list none;
    const redis_list& l = list != nullptr ? *list : none;
    const auto syntax = [] { return redis_reply::error("ERR syntax error"); };
    switch (id) {
        case redis_command_id::llen:
            return redis_reply::integer(static_cast<std::int64_t>(l.size()));
        case redis_command_id::lindex: {
            // As lindexCommand: the key and its type first, then the index,
            // so a missing key answers nil whatever the index says.
            if (list == nullptr) {
                return redis_reply::null();
            }
            const auto i = args.empty() ? std::nullopt : parse_int64(args[0]);
            if (!i) {
                return redis_reply::error("ERR value is not an integer or out of range");
            }
            const auto at = normalise_index(*i, l.size());
            return at ? redis_reply::bulk(l.at(*at)) : redis_reply::null();
        }
        case redis_command_id::lrange: {
            const auto start = args.size() == 2 ? parse_int64(args[0]) : std::nullopt;
            const auto stop = args.size() == 2 ? parse_int64(args[1]) : std::nullopt;
            if (!start || !stop) {
                return syntax();
            }
            std::vector<redis_reply> out;
            if (const auto range = normalise_range(*start, *stop, l.size())) {
                out.reserve(range->second - range->first + 1);
                l.visit(range->first, range->second, [&](std::size_t, const std::string& v) {
                    out.push_back(redis_reply::bulk(v));
                    return true;
                });
            }
            return redis_reply::array(std::move(out));
        }
        case redis_command_id::lpos: {
            if (args.size() != 5) {
                return syntax();
            }
            const auto rank = parse_int64(args[1]);
            const auto count = parse_int64(args[2]);
            const auto maxlen = parse_int64(args[3]);
            if (!rank || *rank == 0 || !count || *count < 0 || !maxlen || *maxlen < 0) {
                return syntax();
            }
            const bool with_count = args[4] == "1";
            const auto want = *count == 0 ? l.size() : static_cast<std::size_t>(*count);
            auto skip = static_cast<std::uint64_t>(*rank > 0 ? *rank - 1 : -(*rank + 1));
            std::uint64_t scanned = 0;
            std::vector<redis_reply> found;
            const auto match = [&](std::size_t i, const std::string& v) {
                if (*maxlen != 0 && scanned++ >= static_cast<std::uint64_t>(*maxlen)) {
                    return false;
                }
                if (v == args[0]) {
                    if (skip > 0) {
                        --skip;
                    } else {
                        found.push_back(redis_reply::integer(static_cast<std::int64_t>(i)));
                    }
                }
                return found.size() < (with_count ? want : 1);
            };
            if (!l.empty()) {
                if (*rank < 0) {
                    l.visit_backwards(match);
                } else {
                    l.visit(0, l.size() - 1, match);
                }
            }
            if (with_count) {
                return redis_reply::array(std::move(found));
            }
            return found.empty() ? redis_reply::null() : std::move(found.front());
        }
        default:
            return std::nullopt;
    }
}

/// `OBJECT ENCODING` of a list: what Redis 7.2 would choose under its
/// default `list-max-listpack-size -2`, a listpack while the encoded list
/// stays within 8 KiB. The size is estimated as a listpack lays elements out
/// (each element plus its encoding and back-length bytes, about two for the
/// short elements this applies to). Redis converts back to a listpack only
/// when a list shrinks to half the limit, a history this does not keep, so
/// a list that grew past 8 KiB and shrank to between 4 and 8 KiB reads
/// `listpack` here and `quicklist` in Redis.
[[nodiscard]] inline auto redis_list_encoding(const redis_list& l) -> std::string {
    constexpr std::size_t k_listpack_limit = 8192;
    constexpr std::size_t k_listpack_header = 7;  // total bytes, count, end byte
    std::size_t estimate = k_listpack_header;
    bool small = true;
    l.visit(0, l.empty() ? 0 : l.size() - 1, [&](std::size_t, const std::string& e) {
        estimate += e.size() + (e.size() < 64 ? 2 : e.size() < 4096 ? 3 : 6);
        small = estimate <= k_listpack_limit;
        return small;
    });
    return small ? "listpack" : "quicklist";
}

}  // namespace kythira
