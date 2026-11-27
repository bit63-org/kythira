// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_install_exec.hpp
/// The record a transaction commits for a key a typed command changed
/// (.kiro/specs/redis-general-data-types/ task 11, Requirement 13.4, design
/// Component 5 "Transactions with typed commands").
///
/// Inside `MULTI`/`EXEC`, and for a multi-key command whose keys live in
/// several groups, the front end evaluates each command with the same
/// appliers `apply()` runs (`redis_*_exec.hpp`), against the transaction's
/// view of each key: what the transaction has read, with its own earlier
/// writes on top. The reply is known then. What it commits for each key it
/// changed is the resulting value, so the commit installs exactly what was
/// evaluated and never evaluates anything again:
///
/// - a deletion: the `del` record;
/// - a string: the `set` record, as `SET` in a transaction always was;
/// - a collection: an `exec` record of `KYTHIRA.INSTALL`, whose arguments
///   are the whole value:
///
/// | command id        | arguments                                         | reply |
/// |-------------------|---------------------------------------------------|-------|
/// | `KYTHIRA.INSTALL` | key type expire-at-ms element [element ...]       | OK    |
///
/// `type` is `string`, `hash`, `set` or `list`; the elements are the value
/// (a string's bytes; a hash's field and value pairs, fields in byte order;
/// a set's members in byte order; a list's elements in order). A deadline
/// at or before the command time deletes the key, as `SET ... PXAT` does.
/// The command has a registry id like any other, so the record format is
/// unchanged (Requirement 14.1); no client can send it.
///
/// Under snapshot isolation the commit is the write's version, so the
/// installed value shares nothing with the version before it: an intent
/// crosses the log as bytes. Chunk sharing between versions comes from
/// commands applied in place (design Component 6); a transaction's values
/// are bounded by the transaction layer's command size.

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_reply.hpp>
#include <kythira/redis/redis_value.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira {

/// The `KYTHIRA.INSTALL` arguments that install `e` at `key`. `e` must hold a
/// value: a deletion commits as a `del` record.
template<typename Entry>
[[nodiscard]] auto make_redis_install_args(const std::string& key, const Entry& e)
    -> std::vector<std::string> {
    const auto type = redis_entry_type(e);
    std::vector<std::string> out{key, std::string(redis_value_type_name(type)),
                                 std::to_string(e._expire_at_ms)};
    switch (type) {
        case redis_value_type::string:
            out.emplace_back(reinterpret_cast<const char*>(e._value.data()), e._value.size());
            break;
        case redis_value_type::hash:
            out.reserve(out.size() + 2 * e._hash->size());
            e._hash->for_each([&](const std::string& f, const std::string& v) {
                out.push_back(f);
                out.push_back(v);
            });
            break;
        case redis_value_type::set:
            out.reserve(out.size() + e._set->size());
            e._set->for_each([&](const std::string& m) { out.push_back(m); });
            break;
        case redis_value_type::list:
            out.reserve(out.size() + e._list->size());
            e._list->visit(0, e._list->size() - 1, [&](std::size_t, const std::string& v) {
                out.push_back(v);
                return true;
            });
            break;
    }
    return out;
}

/// Applies a `KYTHIRA.INSTALL` record at command time `t`. `Store` is the
/// interface the other appliers take. Returns `nullopt` for any other
/// command id. A malformed record (only a bug can propose one) answers an
/// error and changes nothing.
template<typename Store>
auto apply_redis_install_exec(Store& store, const redis_kv_exec_command& c, std::uint64_t t)
    -> std::optional<redis_reply> {
    if (static_cast<redis_command_id>(c._command_id) != redis_command_id::kythira_install) {
        return std::nullopt;
    }
    const auto& a = c._args;
    const auto malformed = [] {
        return redis_reply::error("ERR malformed KYTHIRA.INSTALL record");
    };
    if (a.size() < 4) {
        return malformed();
    }
    const std::string& key = a[0];
    std::uint64_t expire = 0;
    if (std::from_chars(a[2].data(), a[2].data() + a[2].size(), expire).ec != std::errc{} ||
        std::to_string(expire) != a[2]) {
        return malformed();
    }
    using entry_type = std::remove_cvref_t<decltype(*store.find(key))>;
    auto e = std::make_shared<entry_type>();
    e->_expire_at_ms = expire;
    const auto first = a.begin() + 3;
    if (a[1] == "string") {
        if (a.size() != 4) {
            return malformed();
        }
        e->_value.resize(a[3].size());
        for (std::size_t i = 0; i < a[3].size(); ++i) {
            e->_value[i] = static_cast<std::byte>(a[3][i]);
        }
    } else if (a[1] == "hash") {
        if ((a.size() - 3) % 2 != 0) {
            return malformed();
        }
        std::vector<redis_hash::entry> fields;
        fields.reserve((a.size() - 3) / 2);
        for (auto it = first; it != a.end(); it += 2) {
            if (!fields.empty() && fields.back().first >= *it) {
                return malformed();
            }
            fields.emplace_back(*it, *(it + 1));
        }
        e->_type = redis_value_type::hash;
        e->_hash = std::make_shared<const redis_hash>(redis_hash::from_sorted(std::move(fields)));
    } else if (a[1] == "set") {
        std::vector<std::string> members(first, a.end());
        for (std::size_t i = 1; i < members.size(); ++i) {
            if (members[i - 1] >= members[i]) {
                return malformed();
            }
        }
        e->_type = redis_value_type::set;
        e->_set = std::make_shared<const redis_set>(redis_set::from_sorted(std::move(members)));
    } else if (a[1] == "list") {
        e->_type = redis_value_type::list;
        e->_list = std::make_shared<const redis_list>(
            redis_list::from_elements(std::vector<std::string>(first, a.end())));
    } else {
        return malformed();
    }
    if (expire != 0 && expire <= t) {
        (void)store.erase(key);
    } else {
        store.put_entry(key, std::move(e));
    }
    return redis_reply::simple("OK");
}

}  // namespace kythira
