// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_hash_exec.hpp
/// Hashes as `exec` records apply them and as reads see them
/// (.kiro/specs/redis-general-data-types/ task 7, Requirements 9 and 10).
///
/// Writes, decided in `apply()` like the string family:
///
/// | command id     | arguments after the name                      | reply          |
/// |----------------|-----------------------------------------------|----------------|
/// | `HSET`         | key max-bytes max-count field value [...]     | fields added   |
/// | `HMSET`        | key max-bytes max-count field value [...]     | OK             |
/// | `HSETNX`       | key max-bytes max-count field value           | 1 or 0         |
/// | `HINCRBY`      | key max-bytes max-count field delta           | new integer    |
/// | `HINCRBYFLOAT` | key max-bytes max-count field increment       | new value      |
/// | `HDEL`         | key field [field ...]                         | fields removed |
///
/// `max-bytes` and `max-count` are the front end's configured collection
/// limits (Requirement 9.4), carried in the record so every replica refuses
/// the same write. A write that would leave the hash above either answers
/// `ERR collection exceeds the configured maximum of N bytes` (or
/// `elements`) and changes nothing. A hash emptied by `HDEL` deletes its key
/// (Requirement 9.2); a field change keeps the key's deadline
/// (Requirement 4.4).
///
/// A key holding another type answers `WRONGTYPE` and changes nothing
/// (Requirement 9.1). Under the immutable-value rule a write that changes an
/// existing hash needs the key's mutable bit; creating a hash, and a write
/// that changes nothing, stay allowed.
///
/// Reads are a pure function of the entry, so the front end takes the entry
/// handle under the node lock and evaluates after releasing it: the hash is
/// immutable once published, and `HGETALL` never copies it under the lock
/// (Requirement 10.2). `evaluate_redis_read` is the one entry point for a
/// typed read: it answers `TYPE`, `OBJECT ENCODING` and the expiry reads for
/// every type, sends string reads to `evaluate_redis_string_read`, and
/// answers `WRONGTYPE` for a read of the wrong type.

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_float128.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_string_exec.hpp>
#include <kythira/redis/redis_string_read.hpp>
#include <kythira/redis/redis_value.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace kythira {

namespace redis_hash_detail {

[[nodiscard]] inline auto is_hash_write(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::hset:
        case redis_command_id::hmset:
        case redis_command_id::hsetnx:
        case redis_command_id::hincrby:
        case redis_command_id::hincrbyfloat:
        case redis_command_id::hdel:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline auto is_hash_read(redis_command_id id) noexcept -> bool {
    switch (id) {
        case redis_command_id::hget:
        case redis_command_id::hmget:
        case redis_command_id::hexists:
        case redis_command_id::hlen:
        case redis_command_id::hstrlen:
        case redis_command_id::hkeys:
        case redis_command_id::hvals:
        case redis_command_id::hgetall:
        case redis_command_id::hrandfield:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline auto limit_error(std::uint64_t limit, std::string_view unit) -> redis_reply {
    return redis_reply::error("ERR collection exceeds the configured maximum of " +
                              std::to_string(limit) + " " + std::string(unit));
}

/// The node-local generator `HRANDFIELD` picks with (Requirement 9.5: never
/// in `apply()`).
[[nodiscard]] inline auto random_engine() -> std::mt19937_64& {
    thread_local std::mt19937_64 engine{std::random_device{}()};
    return engine;
}

}  // namespace redis_hash_detail

/// Applies one hash `exec` record at command time `t`. `Store` is the
/// interface `apply_redis_string_exec` takes plus
/// `put_entry(key, std::shared_ptr<entry>)`, which installs a whole entry.
/// Returns `nullopt` for a command id this file does not apply.
template<typename Store>
auto apply_redis_hash_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    using namespace redis_string_detail;
    using namespace redis_hash_detail;
    const auto id = static_cast<redis_command_id>(c._command_id);
    if (!is_hash_write(id)) {
        return std::nullopt;
    }
    const auto& a = c._args;
    const auto syntax = [] { return redis_reply::error(std::string(k_syntax)); };
    if (a.empty()) {
        return syntax();
    }
    const std::string& key = a[0];
    auto live = store.find(key);
    if (live && live->_expire_at_ms != 0 && live->_expire_at_ms <= t) {
        live = nullptr;
    }
    using entry_type = std::remove_cvref_t<decltype(*live)>;
    if (live && redis_entry_type(*live) != redis_value_type::hash) {
        return redis_reply::error(std::string(k_redis_wrongtype));
    }
    const redis_hash empty;
    const redis_hash& current = live ? *live->_hash : empty;
    // Installs `next` (or deletes the key when it emptied), keeping the
    // deadline; refuses a change the immutable rule forbids.
    const auto install = [&](redis_hash next) -> std::optional<redis_reply> {
        if (live && !may_mutate_key(c, 0)) {
            return redis_reply::error(std::string(k_conflict));
        }
        if (next.empty()) {
            (void)store.erase(key);
            return std::nullopt;
        }
        auto e = std::make_shared<entry_type>();
        e->_type = redis_value_type::hash;
        e->_expire_at_ms = live ? live->_expire_at_ms : 0;
        e->_hash = std::make_shared<const redis_hash>(std::move(next));
        store.put_entry(key, std::move(e));
        return std::nullopt;
    };

    if (id == redis_command_id::hdel) {
        if (a.size() < 2) {
            return syntax();
        }
        redis_hash next = current;
        std::int64_t removed = 0;
        for (std::size_t i = 1; i < a.size(); ++i) {
            bool gone = false;
            next = next.without(a[i], gone);
            removed += gone ? 1 : 0;
        }
        if (removed != 0) {
            if (auto refused = install(std::move(next))) {
                return refused;
            }
        }
        return redis_reply::integer(removed);
    }

    // Every other write: key max-bytes max-count field value [...]
    if (a.size() < 5 || (a.size() - 3) % 2 != 0) {
        return syntax();
    }
    const auto max_bytes = parse_u64(a[1]);
    const auto max_count = parse_u64(a[2]);
    if (!max_bytes || !max_count) {
        return syntax();
    }
    const auto within_limits = [&](const redis_hash& h) -> std::optional<redis_reply> {
        if (h.size() > *max_count) {
            return limit_error(*max_count, "elements");
        }
        if (h.bytes() > *max_bytes) {
            return limit_error(*max_bytes, "bytes");
        }
        return std::nullopt;
    };
    // Commits `next` when it differs from the current hash; `reply` is the
    // answer on success.
    const auto commit = [&](redis_hash next, bool changed, redis_reply reply) -> redis_reply {
        if (!changed) {
            return reply;
        }
        if (auto over = within_limits(next)) {
            return *over;
        }
        if (auto refused = install(std::move(next))) {
            return *refused;
        }
        return reply;
    };

    switch (id) {
        case redis_command_id::hset:
        case redis_command_id::hmset: {
            redis_hash next = current;
            std::int64_t added = 0;
            bool changed = false;
            for (std::size_t i = 3; i < a.size(); i += 2) {
                const auto* old = next.find(a[i]);
                if (old && *old == a[i + 1]) {
                    continue;
                }
                bool is_new = false;
                next = next.with(a[i], a[i + 1], is_new);
                added += is_new ? 1 : 0;
                changed = true;
            }
            return commit(std::move(next), changed,
                          id == redis_command_id::hmset ? redis_reply::simple("OK")
                                                        : redis_reply::integer(added));
        }
        case redis_command_id::hsetnx: {
            if (a.size() != 5) {
                return syntax();
            }
            if (current.find(a[3]) != nullptr) {
                return redis_reply::integer(0);
            }
            bool is_new = false;
            return commit(current.with(a[3], a[4], is_new), true, redis_reply::integer(1));
        }
        case redis_command_id::hincrby: {
            if (a.size() != 5) {
                return syntax();
            }
            const auto delta = parse_int64(a[4]);
            if (!delta) {
                return redis_reply::error(std::string(k_not_integer));
            }
            std::int64_t value = 0;
            if (const auto* old = current.find(a[3])) {
                const auto parsed = parse_int64(*old);
                if (!parsed) {
                    return redis_reply::error("ERR hash value is not an integer");
                }
                value = *parsed;
            }
            if ((*delta > 0 && value > std::numeric_limits<std::int64_t>::max() - *delta) ||
                (*delta < 0 && value < std::numeric_limits<std::int64_t>::min() - *delta)) {
                return redis_reply::error(std::string(k_overflow));
            }
            const auto result = value + *delta;
            auto text = std::to_string(result);
            const auto* old = current.find(a[3]);
            const bool changed = old == nullptr || *old != text;
            bool is_new = false;
            return commit(changed ? current.with(a[3], std::move(text), is_new) : current, changed,
                          redis_reply::integer(result));
        }
        case redis_command_id::hincrbyfloat: {
            if (a.size() != 5) {
                return syntax();
            }
            const auto incr = parse_redis_float128(a[4]);
            if (!incr) {
                return redis_reply::error(std::string(k_not_float));
            }
            redis_float128_native value{};
            const auto* old = current.find(a[3]);
            if (old) {
                const auto parsed = parse_redis_float128(*old);
                if (!parsed) {
                    return redis_reply::error("ERR hash value is not a float");
                }
                value = *parsed;
            }
            const redis_float128_native result = value + *incr;
            if (!is_finite_redis_float128(result)) {
                return redis_reply::error("ERR increment would produce NaN or Infinity");
            }
            auto text = format_redis_float128(result);
            const bool changed = old == nullptr || *old != text;
            bool is_new = false;
            return commit(changed ? current.with(a[3], text, is_new) : current, changed,
                          redis_reply::bulk(text));
        }
        default:
            return std::nullopt;
    }
}

/// The read of `id` on a hash entry (`entry->_hash` set) or an absent key
/// (`hash` null). `args` are the arguments after the key, already checked
/// for arity and integers by the front end.
[[nodiscard]] inline auto evaluate_redis_hash_read(const redis_hash* hash, redis_command_id id,
                                                   std::span<const std::string> args)
    -> std::optional<redis_reply> {
    const redis_hash empty;
    const redis_hash& h = hash != nullptr ? *hash : empty;
    switch (id) {
        case redis_command_id::hget: {
            if (args.size() != 1) {
                return redis_reply::error("ERR syntax error");
            }
            const auto* v = h.find(args[0]);
            return v != nullptr ? redis_reply::bulk(*v) : redis_reply::null();
        }
        case redis_command_id::hmget: {
            std::vector<redis_reply> out;
            out.reserve(args.size());
            for (const auto& f : args) {
                const auto* v = h.find(f);
                out.push_back(v != nullptr ? redis_reply::bulk(*v) : redis_reply::null());
            }
            return redis_reply::array(std::move(out));
        }
        case redis_command_id::hexists:
            return redis_reply::integer(!args.empty() && h.find(args[0]) != nullptr ? 1 : 0);
        case redis_command_id::hlen:
            return redis_reply::integer(static_cast<std::int64_t>(h.size()));
        case redis_command_id::hstrlen: {
            const auto* v = args.empty() ? nullptr : h.find(args[0]);
            return redis_reply::integer(v != nullptr ? static_cast<std::int64_t>(v->size()) : 0);
        }
        case redis_command_id::hkeys:
        case redis_command_id::hvals:
        case redis_command_id::hgetall: {
            std::vector<redis_reply> out;
            out.reserve(id == redis_command_id::hgetall ? h.size() * 2 : h.size());
            h.for_each([&](const std::string& f, const std::string& v) {
                if (id != redis_command_id::hvals) {
                    out.push_back(redis_reply::bulk(f));
                }
                if (id != redis_command_id::hkeys) {
                    out.push_back(redis_reply::bulk(v));
                }
            });
            return id == redis_command_id::hgetall ? redis_reply::map(std::move(out))
                                                   : redis_reply::array(std::move(out));
        }
        case redis_command_id::hrandfield: {
            // HRANDFIELD key [count [WITHVALUES]]. With values, each pick is a
            // [field, value] pair (RESP3's shape); the front end flattens it
            // for RESP2, as Redis does.
            if (args.empty()) {
                if (h.empty()) {
                    return redis_reply::null();
                }
                std::uniform_int_distribution<std::size_t> pick(0, h.size() - 1);
                auto n = pick(redis_hash_detail::random_engine());
                for (const auto& c : h.chunks()) {
                    if (n < c->size()) {
                        return redis_reply::bulk((*c)[n].first);
                    }
                    n -= c->size();
                }
                return redis_reply::null();
            }
            const auto count = redis_string_detail::parse_int64(args[0]);
            const bool with_values = args.size() > 1;
            if (!count || (args.size() > 1 && args[1] != "WITHVALUES") || args.size() > 2) {
                return redis_reply::error("ERR syntax error");
            }
            if (*count < -(std::numeric_limits<std::int64_t>::max() / 2)) {
                return redis_reply::error("ERR value is out of range");
            }
            std::vector<const redis_hash::entry*> all;
            all.reserve(h.size());
            for (const auto& c : h.chunks()) {
                for (const auto& e : *c) {
                    all.push_back(&e);
                }
            }
            std::vector<const redis_hash::entry*> picked;
            auto& engine = redis_hash_detail::random_engine();
            if (*count < 0) {
                if (!all.empty()) {
                    std::uniform_int_distribution<std::size_t> pick(0, all.size() - 1);
                    const auto n = static_cast<std::size_t>(-*count);
                    picked.reserve(n);
                    for (std::size_t i = 0; i < n; ++i) {
                        picked.push_back(all[pick(engine)]);
                    }
                }
            } else if (static_cast<std::uint64_t>(*count) >= all.size()) {
                picked = std::move(all);
            } else {
                std::ranges::sample(all, std::back_inserter(picked),
                                    static_cast<std::ptrdiff_t>(*count), engine);
                std::ranges::shuffle(picked, engine);
            }
            std::vector<redis_reply> out;
            out.reserve(picked.size());
            for (const auto* e : picked) {
                if (with_values) {
                    out.push_back(redis_reply::array(
                        {redis_reply::bulk(e->first), redis_reply::bulk(e->second)}));
                } else {
                    out.push_back(redis_reply::bulk(e->first));
                }
            }
            return redis_reply::array(std::move(out));
        }
        default:
            return std::nullopt;
    }
}

/// `OBJECT ENCODING` of a hash: what Redis 7 would choose under its default
/// `hash-max-listpack-entries 128` / `hash-max-listpack-value 64`.
[[nodiscard]] inline auto redis_hash_encoding(const redis_hash& h) -> std::string {
    if (h.size() > 128) {
        return "hashtable";
    }
    bool small = true;
    h.for_each([&](const std::string& f, const std::string& v) {
        small = small && f.size() <= 64 && v.size() <= 64;
    });
    return small ? "listpack" : "hashtable";
}

/// `HRANDFIELD ... WITHVALUES` for RESP2: the [field, value] pairs
/// flattened into one array, as Redis replies to a RESP2 client.
[[nodiscard]] inline auto redis_flatten_pairs(redis_reply r) -> redis_reply {
    if (r._kind != redis_reply_kind::array) {
        return r;
    }
    std::vector<redis_reply> flat;
    flat.reserve(r._elements.size() * 2);
    for (auto& e : r._elements) {
        if (e._kind == redis_reply_kind::array) {
            for (auto& x : e._elements) {
                flat.push_back(std::move(x));
            }
        } else {
            flat.push_back(std::move(e));
        }
    }
    return redis_reply::array(std::move(flat));
}

}  // namespace kythira
