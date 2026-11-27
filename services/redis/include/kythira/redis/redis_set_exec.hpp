// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_set_exec.hpp
/// Sets as `exec` records apply them and as reads see them
/// (.kiro/specs/redis-general-data-types/ task 8, Requirements 9 and 11).
///
/// | command id     | arguments after the name                          | reply             |
/// |----------------|---------------------------------------------------|-------------------|
/// | `SADD`         | key max-bytes max-count member [...]              | members added     |
/// | `SREM`         | key member [...]                                  | members removed   |
/// | `SPOP`         | key with-count(0\|1) member [...]                 | removed member(s) |
/// | `SMOVE`        | src dst max-bytes max-count member                | 1 or 0            |
/// | `SINTERSTORE`  | dst max-bytes max-count src [src ...]             | members stored    |
/// | `SUNIONSTORE`  | dst max-bytes max-count src [src ...]             | members stored    |
/// | `SDIFFSTORE`   | dst max-bytes max-count src [src ...]             | members stored    |
///
/// `SPOP` never picks in `apply()` (Requirement 9.5): the leader's front end
/// picks the members from the set it reads and proposes them; `apply()`
/// removes each only if it is still there, so a pop racing another write
/// answers with what it actually removed. Without a count the reply is the
/// member or nil; with one, an array.
///
/// `SMOVE` and the `*STORE` forms name several keys, so they go through the
/// multi-key planner (redis_multi_key_exec.hpp): keys in one group make one
/// record; collections do not cross groups until typed values join
/// transactions (task 11). A `*STORE` replaces its destination whatever it
/// held, as in Redis, and deletes it when the result is empty.
///
/// Type errors, empty sets deleting their key, limits and the
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
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace kythira {

namespace redis_set_detail {

[[nodiscard]] inline auto is_set_write(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::sadd:
        case redis_command_id::srem:
        case redis_command_id::spop:
        case redis_command_id::smove:
        case redis_command_id::sinterstore:
        case redis_command_id::sunionstore:
        case redis_command_id::sdiffstore:
            return true;
        default:
            return false;
    }
}

/// Single-key set reads the data side evaluates. `SINTER`, `SUNION`,
/// `SDIFF` and `SINTERCARD` gather their keys on the front end.
[[nodiscard]] inline auto is_set_read(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::sismember:
        case redis_command_id::smismember:
        case redis_command_id::smembers:
        case redis_command_id::scard:
        case redis_command_id::srandmember:
            return true;
        default:
            return false;
    }
}

/// The set algebra of `SINTER`, `SUNION` and `SDIFF` over sets in order
/// (absent keys are empty sets), in byte order. `limit` stops an
/// intersection early (`SINTERCARD`; 0: no limit).
[[nodiscard]] inline auto combine(redis_command_id id, const std::vector<const redis_set*>& sets,
                                  std::size_t limit = 0) -> std::vector<std::string> {
    std::vector<std::string> out;
    if (sets.empty()) {
        return out;
    }
    const redis_set empty;
    const auto at = [&](std::size_t i) -> const redis_set& {
        return sets[i] != nullptr ? *sets[i] : empty;
    };
    switch (id) {
        case redis_command_id::sinter:
        case redis_command_id::sinterstore:
        case redis_command_id::sintercard: {
            // Walk the smallest set, probing the others.
            std::size_t smallest = 0;
            for (std::size_t i = 1; i < sets.size(); ++i) {
                if (at(i).size() < at(smallest).size()) {
                    smallest = i;
                }
            }
            at(smallest).for_each([&](const std::string& m) {
                if (limit != 0 && out.size() >= limit) {
                    return;
                }
                for (std::size_t i = 0; i < sets.size(); ++i) {
                    if (i != smallest && !at(i).contains(m)) {
                        return;
                    }
                }
                out.push_back(m);
            });
            return out;
        }
        case redis_command_id::sunion:
        case redis_command_id::sunionstore: {
            for (std::size_t i = 0; i < sets.size(); ++i) {
                std::vector<std::string> merged;
                std::vector<std::string> next;
                at(i).for_each([&](const std::string& m) { next.push_back(m); });
                std::ranges::set_union(out, next, std::back_inserter(merged));
                out = std::move(merged);
            }
            return out;
        }
        case redis_command_id::sdiff:
        case redis_command_id::sdiffstore: {
            at(0).for_each([&](const std::string& m) {
                for (std::size_t i = 1; i < sets.size(); ++i) {
                    if (at(i).contains(m)) {
                        return;
                    }
                }
                out.push_back(m);
            });
            return out;
        }
        default:
            return out;
    }
}

}  // namespace redis_set_detail

/// Applies one set `exec` record at command time `t`. `Store` is the
/// interface `apply_redis_hash_exec` takes. Returns `nullopt` for a command
/// id this file does not apply.
template<typename Store>
auto apply_redis_set_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_string_detail;
    using namespace redis_set_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    if (!is_set_write(id)) {
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
    const auto is_set = [](const handle_type& e) {
        return !e || redis_entry_type(*e) == redis_value_type::set;
    };
    const redis_set empty;
    const auto members_of = [&](const handle_type& e) -> const redis_set& {
        return e ? *e->_set : empty;
    };
    // Installs `next` under `key` with `expire` (or deletes the key when it
    // emptied).
    const auto install = [&](const std::string& key, redis_set next, std::uint64_t expire) {
        if (next.empty()) {
            (void)store.erase(key);
            return;
        }
        auto e = std::make_shared<entry_type>();
        e->_type = redis_value_type::set;
        e->_expire_at_ms = expire;
        e->_set = std::make_shared<const redis_set>(std::move(next));
        store.put_entry(key, std::move(e));
    };
    const auto over_limits = [](const redis_set& s, std::uint64_t max_bytes,
                                std::uint64_t max_count) -> std::optional<redis_reply> {
        if (s.size() > max_count) {
            return redis_hash_detail::limit_error(max_count, "elements");
        }
        if (s.bytes() > max_bytes) {
            return redis_hash_detail::limit_error(max_bytes, "bytes");
        }
        return std::nullopt;
    };

    if (a.empty()) {
        return syntax();
    }

    switch (id) {
        case redis_command_id::sadd: {
            if (a.size() < 4) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[1]);
            const auto max_count = parse_u64(a[2]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            const auto e = live(a[0]);
            if (!is_set(e)) {
                return wrongtype();
            }
            redis_set next = members_of(e);
            std::int64_t added = 0;
            for (std::size_t i = 3; i < a.size(); ++i) {
                bool is_new = false;
                next = next.with(a[i], is_new);
                added += is_new ? 1 : 0;
            }
            if (added == 0) {
                return redis_reply::integer(0);
            }
            if (auto over = over_limits(next, *max_bytes, *max_count)) {
                return over;
            }
            if (e && !may_mutate_key(c, 0)) {
                return conflict();
            }
            install(a[0], std::move(next), e ? e->_expire_at_ms : 0);
            return redis_reply::integer(added);
        }
        case redis_command_id::srem:
        case redis_command_id::spop: {
            const bool pop = id == redis_command_id::spop;
            if (a.size() < 2 || (pop && a[1] != "0" && a[1] != "1")) {
                return syntax();
            }
            const bool with_count = pop && a[1] == "1";
            const auto e = live(a[0]);
            if (!is_set(e)) {
                return wrongtype();
            }
            redis_set next = members_of(e);
            std::vector<redis_reply> popped;
            std::int64_t removed = 0;
            for (std::size_t i = pop ? 2 : 1; i < a.size(); ++i) {
                bool gone = false;
                next = next.without(a[i], gone);
                if (gone) {
                    ++removed;
                    popped.push_back(redis_reply::bulk(a[i]));
                }
            }
            const auto reply = [&]() -> redis_reply {
                if (!pop) {
                    return redis_reply::integer(removed);
                }
                if (with_count) {
                    // A set in RESP3, as Redis replies to SPOP with a count.
                    return redis_reply::set(std::move(popped));
                }
                return popped.empty() ? redis_reply::null() : std::move(popped.front());
            };
            if (removed != 0) {
                if (!may_mutate_key(c, 0)) {
                    return conflict();
                }
                install(a[0], std::move(next), e->_expire_at_ms);
            }
            return reply();
        }
        case redis_command_id::smove: {
            if (a.size() != 5) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[2]);
            const auto max_count = parse_u64(a[3]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            const auto from = live(a[0]);
            const auto to = live(a[1]);
            // As smoveCommand: a missing source answers 0 before either
            // key's type is checked.
            if (!from) {
                return redis_reply::integer(0);
            }
            if (!is_set(from) || !is_set(to)) {
                return wrongtype();
            }
            const auto& member = a[4];
            if (!from->_set->contains(member)) {
                return redis_reply::integer(0);
            }
            if (a[0] == a[1]) {
                return redis_reply::integer(1);
            }
            bool gone = false;
            auto src = members_of(from).without(member, gone);
            bool added = false;
            auto dst = members_of(to).with(member, added);
            if (added) {
                if (auto over = over_limits(dst, *max_bytes, *max_count)) {
                    return over;
                }
            }
            if (!may_mutate_key(c, 0) || (to && added && !may_mutate_key(c, 1))) {
                return conflict();
            }
            install(a[0], std::move(src), from->_expire_at_ms);
            if (added) {
                install(a[1], std::move(dst), to ? to->_expire_at_ms : 0);
            }
            return redis_reply::integer(1);
        }
        case redis_command_id::sinterstore:
        case redis_command_id::sunionstore:
        case redis_command_id::sdiffstore: {
            if (a.size() < 4) {
                return syntax();
            }
            const auto max_bytes = parse_u64(a[1]);
            const auto max_count = parse_u64(a[2]);
            if (!max_bytes || !max_count) {
                return syntax();
            }
            std::vector<handle_type> holds;
            std::vector<const redis_set*> sets;
            for (std::size_t i = 3; i < a.size(); ++i) {
                auto e = live(a[i]);
                if (!is_set(e)) {
                    return wrongtype();
                }
                sets.push_back(e ? e->_set.get() : nullptr);
                holds.push_back(std::move(e));
            }
            auto result = redis_set::from_sorted(combine(id, sets));
            if (auto over = over_limits(result, *max_bytes, *max_count)) {
                return over;
            }
            const auto dst = live(a[0]);
            const auto count = static_cast<std::int64_t>(result.size());
            const bool unchanged =
                dst && redis_entry_type(*dst) == redis_value_type::set && dst->_expire_at_ms == 0 &&
                dst->_set->size() == result.size() &&
                std::ranges::equal(combine(redis_command_id::sunion, {dst->_set.get()}),
                                   combine(redis_command_id::sunion, {&result}));
            if (dst && !unchanged && !may_mutate_key(c, 0)) {
                return conflict();
            }
            if (!dst && result.empty()) {
                return redis_reply::integer(0);
            }
            if (!unchanged) {
                install(a[0], std::move(result), 0);
            }
            return redis_reply::integer(count);
        }
        default:
            return std::nullopt;
    }
}

/// The read of `id` on a set (`set` null when absent). `args` are the
/// arguments after the key, checked by the front end.
[[nodiscard]] inline auto evaluate_redis_set_read(const redis_set* set, redis_command_id id,
                                                  std::span<const std::string> args)
    -> std::optional<redis_reply> {
    const redis_set empty;
    const redis_set& s = set != nullptr ? *set : empty;
    switch (id) {
        case redis_command_id::sismember:
            return redis_reply::integer(!args.empty() && s.contains(args[0]) ? 1 : 0);
        case redis_command_id::smismember: {
            std::vector<redis_reply> out;
            out.reserve(args.size());
            for (const auto& m : args) {
                out.push_back(redis_reply::integer(s.contains(m) ? 1 : 0));
            }
            return redis_reply::array(std::move(out));
        }
        case redis_command_id::scard:
            return redis_reply::integer(static_cast<std::int64_t>(s.size()));
        case redis_command_id::smembers: {
            std::vector<redis_reply> out;
            out.reserve(s.size());
            s.for_each([&](const std::string& m) { out.push_back(redis_reply::bulk(m)); });
            return redis_reply::set(std::move(out));
        }
        case redis_command_id::srandmember: {
            auto& engine = redis_hash_detail::random_engine();
            if (args.empty()) {
                if (s.empty()) {
                    return redis_reply::null();
                }
                std::uniform_int_distribution<std::size_t> pick(0, s.size() - 1);
                return redis_reply::bulk(s.at(pick(engine)));
            }
            const auto count = redis_string_detail::parse_int64(args[0]);
            if (!count) {
                return redis_reply::error("ERR value is not an integer or out of range");
            }
            if (*count < -(std::numeric_limits<std::int64_t>::max() / 2)) {
                return redis_reply::error("ERR value is out of range");
            }
            std::vector<redis_reply> out;
            if (*count < 0) {
                if (!s.empty()) {
                    std::uniform_int_distribution<std::size_t> pick(0, s.size() - 1);
                    const auto n = static_cast<std::size_t>(-*count);
                    out.reserve(n);
                    for (std::size_t i = 0; i < n; ++i) {
                        out.push_back(redis_reply::bulk(s.at(pick(engine))));
                    }
                }
            } else if (static_cast<std::uint64_t>(*count) >= s.size()) {
                s.for_each([&](const std::string& m) { out.push_back(redis_reply::bulk(m)); });
            } else {
                std::vector<const std::string*> all;
                all.reserve(s.size());
                s.for_each([&](const std::string& m) { all.push_back(&m); });
                std::vector<const std::string*> picked;
                std::ranges::sample(all, std::back_inserter(picked),
                                    static_cast<std::ptrdiff_t>(*count), engine);
                std::ranges::shuffle(picked, engine);
                for (const auto* m : picked) {
                    out.push_back(redis_reply::bulk(*m));
                }
            }
            return redis_reply::array(std::move(out));
        }
        default:
            return std::nullopt;
    }
}

/// `OBJECT ENCODING` of a set: what Redis 7.2 would choose under its
/// defaults, an `intset` for at most `set-max-intset-entries 512` integers,
/// else a `listpack` for at most `set-max-listpack-entries 128` members of
/// at most `set-max-listpack-value 64` bytes, else a `hashtable`.
[[nodiscard]] inline auto redis_set_encoding(const redis_set& s) -> std::string {
    if (s.size() > 512) {
        return "hashtable";
    }
    bool integers = true;
    bool short_members = true;
    s.for_each([&](const std::string& m) {
        integers = integers && redis_string_detail::parse_int64(m).has_value();
        short_members = short_members && m.size() <= 64;
    });
    if (integers) {
        return "intset";
    }
    return s.size() <= 128 && short_members ? "listpack" : "hashtable";
}

}  // namespace kythira
