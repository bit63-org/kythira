// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_txn_view.hpp
/// Typed commands inside a transaction (.kiro/specs/redis-general-data-types/
/// task 11, Requirement 13.4, design Component 5).
///
/// - `redis_txn_view`: a store over a transaction's reads. A read goes to
///   the transaction (so it joins its read set, waits on intents and, under
///   snapshot isolation, reads at the start timestamp) once per key; every
///   write stays in the view. The appliers run against it unchanged.
/// - `redis_txn_write_record`: what the commit proposes for one key the
///   view changed: `del`, `set` (a string), or `KYTHIRA.INSTALL` (a
///   collection, redis_install_exec.hpp).

#include <kythira/redis/redis_command_ids.hpp>
#include <kythira/redis/redis_exec_appliers.hpp>
#include <kythira/redis/redis_install_exec.hpp>
#include <kythira/redis/redis_kv_commands.hpp>
#include <kythira/redis/redis_kv_state_machine.hpp>
#include <kythira/redis/redis_value.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira {

/// A store over a transaction: committed state as the transaction reads it,
/// with the transaction's own writes on top.
class redis_txn_view {
public:
    using entry_handle = std::shared_ptr<const redis_kv_value_entry>;
    /// The committed entry for a key as the transaction reads it (null when
    /// absent). It may throw; the view then remembers the failure, so a
    /// handler that turns exceptions into replies cannot hide it.
    using reader = std::function<entry_handle(const std::string&)>;

    explicit redis_txn_view(reader read) : _read(std::move(read)) {}

    [[nodiscard]] auto find(const std::string& key) -> entry_handle {
        if (auto it = _mine.find(key); it != _mine.end()) {
            return it->second;
        }
        if (auto it = _seen.find(key); it != _seen.end()) {
            return it->second;
        }
        try {
            auto e = _read(key);
            _seen.emplace(key, e);
            return e;
        } catch (...) {
            if (!_failure) {
                _failure = std::current_exception();
            }
            throw;
        }
    }
    auto put(const std::string& key, std::vector<std::byte> value, std::uint64_t expire_at_ms)
        -> void {
        auto e = std::make_shared<redis_kv_value_entry>();
        e->_value = std::move(value);
        e->_expire_at_ms = expire_at_ms;
        _mine.insert_or_assign(key, std::move(e));
    }
    auto put_entry(const std::string& key, entry_handle e) -> void {
        _mine.insert_or_assign(key, std::move(e));
    }
    /// Whether the key held anything. Erasing what is not there writes
    /// nothing, so it takes no lock at the commit.
    auto erase(const std::string& key) -> bool {
        if (!find(key)) {
            return false;
        }
        _mine.insert_or_assign(key, nullptr);
        return true;
    }

    /// Each key the transaction changed, and its value (null: deleted).
    [[nodiscard]] auto writes() const -> const std::map<std::string, entry_handle>& {
        return _mine;
    }
    /// The first read that threw, if any: the transaction cannot commit.
    [[nodiscard]] auto failure() const -> std::exception_ptr { return _failure; }

private:
    reader _read;
    std::map<std::string, entry_handle> _seen;
    std::map<std::string, entry_handle> _mine;
    std::exception_ptr _failure;
};

/// The record committing `e` at `key` at command time `now_ms` (null `e`: a
/// deletion). A string keeps the `set` record a transaction always wrote,
/// so a string-only transaction stays readable before the format gate.
inline auto redis_txn_write_record(const std::string& key, const redis_txn_view::entry_handle& e,
                                   std::uint64_t now_ms) -> std::vector<std::byte> {
    if (!e) {
        return encode_redis_kv_command(redis_kv_del_command{key});
    }
    if (redis_entry_type(*e) == redis_value_type::string) {
        redis_kv_set_command set;
        set._key = key;
        set._value = e->_value;
        set._expire_at_ms = e->_expire_at_ms;
        return encode_redis_kv_command(set);
    }
    return encode_redis_kv_command(
        make_redis_exec_record(key, static_cast<std::uint16_t>(redis_command_id::kythira_install),
                               make_redis_install_args(key, *e), now_ms, false, false));
}

}  // namespace kythira
