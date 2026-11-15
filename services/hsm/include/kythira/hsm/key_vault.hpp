// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What an unsealed node holds (requirement 4, design "Two key layers under
// the master key"): the master key, and the token keys opened with it,
// all in the secure arena. Sealing wipes both. Nothing here is replicated
// or written anywhere; every node unseals on its own.
//
// The vault accepts an MK only when its check value matches the one the
// catalog records, so a wrong combination of shares is refused before it
// can open anything. It remembers the MK generation it was unsealed at; a
// token key sealed under another generation (a rekey this node has not
// caught up with) does not open, and the caller answers CKR_DEVICE_ERROR.
// It also remembers the catalog's seal epoch: enforce() seals a vault the
// catalog has since sealed (a `seal` command) or rekeyed past, so every
// node drops its keys once it applies either entry (requirement 4.7).
//
// Keys never leave the vault: callers pass a function that gets a view of
// the key under the vault's lock, so a seal() waits for every use in
// flight and nothing keeps a copy afterwards.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/key_store.hpp>
#include <kythira/hsm/secret_bytes.hpp>
#include <kythira/hsm/shamir.hpp>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <type_traits>
#include <utility>

namespace kythira::hsm {

enum class unseal_result : std::uint8_t {
    unsealed,
    /// The MK's check value is not the catalog's: wrong or mixed shares.
    wrong_key,
    /// The catalog has not been initialized.
    not_initialized,
};

class key_vault {
public:
    key_vault() = default;
    key_vault(const key_vault&) = delete;
    auto operator=(const key_vault&) -> key_vault& = delete;
    key_vault(key_vault&&) = delete;
    auto operator=(key_vault&&) -> key_vault& = delete;
    ~key_vault() = default;

    [[nodiscard]] auto sealed() const -> bool {
        const std::shared_lock lock(_mutex);
        return _mk.empty();
    }

    /// Bumped by every unseal and seal, so caches built on the keys can
    /// tell that they belong to an earlier unseal.
    [[nodiscard]] auto epoch() const noexcept -> std::uint64_t {
        return _epoch.load(std::memory_order_acquire);
    }

    /// The MK generation this node was unsealed at (0 while sealed).
    [[nodiscard]] auto generation() const -> std::uint32_t {
        const std::shared_lock lock(_mutex);
        return _generation;
    }

    /// Takes `mk` if its check value is the catalog's. A node that is
    /// already unsealed is re-unsealed with the new key (a rekey).
    auto unseal(secret_bytes mk, const std::optional<catalog_record>& catalog) -> unseal_result {
        if (!catalog) {
            return unseal_result::not_initialized;
        }
        if (mk.size() != sealing_key_size ||
            !constant_time_equal(key_check_value(mk.view()), catalog->mk_check)) {
            return unseal_result::wrong_key;
        }
        const std::unique_lock lock(_mutex);
        _tks.clear();
        _mk = std::move(mk);
        _generation = catalog->generation;
        _seal_epoch = catalog->seal_epoch;
        _epoch.fetch_add(1, std::memory_order_acq_rel);
        return unseal_result::unsealed;
    }

    /// Seals the vault when `catalog` no longer matches the one it was
    /// unsealed under: sealed since (a newer seal epoch), rekeyed (another
    /// generation, so the MK opens no token key), or gone. True when it
    /// sealed.
    auto enforce(const std::optional<catalog_record>& catalog) -> bool {
        const auto current = [&] {
            return _mk.empty() || (catalog && catalog->generation == _generation &&
                                   catalog->seal_epoch == _seal_epoch);
        };
        {
            const std::shared_lock lock(_mutex);
            if (current()) {
                return false;
            }
        }
        const std::unique_lock lock(_mutex);
        if (current()) {
            return false;  // unsealed again in between, under this catalog
        }
        wipe_locked();
        return true;
    }

    /// Wipes the MK and every token key (requirement 4.7).
    auto seal() -> void {
        const std::unique_lock lock(_mutex);
        wipe_locked();
    }

    /// Calls `f(mk)` with the master key; CKR_DEVICE_ERROR while sealed.
    template<typename F>
    [[nodiscard]] auto with_master_key(F&& f) const
        -> ck_result<std::invoke_result_t<F, std::span<const std::uint8_t>>> {
        const std::shared_lock lock(_mutex);
        if (_mk.empty()) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return std::forward<F>(f)(_mk.view());
    }

    /// Calls `f(tk)` with the token key `entry` seals, opening and caching
    /// it on first use. CKR_DEVICE_ERROR while sealed, when the entry is
    /// sealed under another MK generation, or when it does not open
    /// (corruption or tampering; design "Error handling").
    template<typename F>
    [[nodiscard]] auto with_token_key(const token_entry& entry, F&& f)
        -> ck_result<std::invoke_result_t<F, std::span<const std::uint8_t>>> {
        {
            const std::shared_lock lock(_mutex);
            if (_mk.empty() || entry.generation != _generation) {
                return unexpected(CKR_DEVICE_ERROR);
            }
            if (const auto it = _tks.find(entry.token_id);
                it != _tks.end() && it->second.sealed == entry.sealed_tk) {
                return std::forward<F>(f)(it->second.key.view());
            }
        }
        const std::unique_lock lock(_mutex);
        if (_mk.empty() || entry.generation != _generation) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        auto tk = open_token_key(_mk.view(), entry);
        if (!tk) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        auto& slot = _tks[entry.token_id];
        slot.sealed = entry.sealed_tk;
        slot.key = std::move(*tk);
        return std::forward<F>(f)(slot.key.view());
    }

    /// Drops a token's cached key (the token was deleted).
    auto forget(std::uint64_t token_id) -> void {
        const std::unique_lock lock(_mutex);
        _tks.erase(token_id);
    }

private:
    auto wipe_locked() -> void {
        _tks.clear();
        _mk.wipe();
        _generation = 0;
        _seal_epoch = 0;
        _epoch.fetch_add(1, std::memory_order_acq_rel);
    }

    struct cached_tk {
        sealed_bytes sealed;
        secret_bytes key;
    };

    mutable std::shared_mutex _mutex;
    secret_bytes _mk;
    std::uint32_t _generation{0};
    std::uint64_t _seal_epoch{0};
    std::map<std::uint64_t, cached_tk> _tks;
    std::atomic<std::uint64_t> _epoch{0};
};

}  // namespace kythira::hsm
