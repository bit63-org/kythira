// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Operator unseal (.kiro/specs/virtual-hsm/ task 7, requirement 4.3): k
// operators each hand one share to a node, which keeps the partial set in
// memory only and combines it once k have arrived. The set is discarded
// when the first share is older than the timeout, so a share entered and
// forgotten does not wait for whoever comes next.
//
// Each share is checked on arrival, before it is kept: its checksum (by
// decoding it), its k and n against the catalog's, and its MK check value
// against the catalog's, so a share from another split or an old one from
// before a rekey is refused at once with a clear reason instead of making
// the final combination fail. A combination that still fails (shares that
// pass every check but do not belong together cannot happen without
// forging the check value, so this is belt and braces) clears the set.
//
// Node unseal (requirement 4.4) is task 8 and adds its share sources here.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/key_vault.hpp>
#include <kythira/hsm/shamir.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::hsm {

enum class share_outcome : std::uint8_t {
    /// Kept; more are needed.
    accepted,
    /// The k-th share: the node is unsealed.
    unsealed,
    /// Not a share (bad encoding or checksum).
    malformed,
    /// A share of another split: its check value, k or n is not the
    /// catalog's (a typo'd share is `malformed`; this is a real share of
    /// the wrong master key, often one from before a rekey).
    wrong_split,
    /// A share with this index is already held.
    duplicate,
    /// The node is already unsealed.
    already_unsealed,
    /// The catalog has not been initialized.
    not_initialized,
    /// The k shares did not combine into the catalog's master key; the
    /// held shares were discarded.
    wrong_key,
};

[[nodiscard]] inline auto share_outcome_message(share_outcome o) -> std::string_view {
    switch (o) {
        case share_outcome::accepted:
            return "share accepted";
        case share_outcome::unsealed:
            return "unsealed";
        case share_outcome::malformed:
            return "not a valid share (bad encoding or checksum)";
        case share_outcome::wrong_split:
            return "the share belongs to another master key (perhaps one from before a rekey)";
        case share_outcome::duplicate:
            return "a share with this index was already entered";
        case share_outcome::already_unsealed:
            return "this node is already unsealed";
        case share_outcome::not_initialized:
            return "the HSM is not initialized";
        case share_outcome::wrong_key:
            return "the shares did not combine into the master key; enter them again";
    }
    return "unknown";
}

struct unseal_progress {
    bool sealed = true;
    /// Shares held toward the next unseal.
    std::size_t received = 0;
    /// Shares needed (the catalog's k; 0 before initialization).
    std::uint8_t needed = 0;
};

class operator_unseal {
public:
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    explicit operator_unseal(
        key_vault& vault, std::chrono::seconds timeout = std::chrono::minutes{10},
        clock_fn now = [] { return std::chrono::steady_clock::now(); })
        : _vault(&vault), _timeout(timeout), _now(std::move(now)) {}

    /// Takes one share in its text form ("khs1-..."). `catalog` is this
    /// node's replica, read after a catalog barrier so it is current.
    auto submit(std::string_view text, const std::optional<catalog_record>& catalog)
        -> share_outcome {
        if (!catalog) {
            return share_outcome::not_initialized;
        }
        const std::scoped_lock lock(_mutex);
        expire_locked();
        if (!_vault->sealed()) {
            _held.clear();
            return share_outcome::already_unsealed;
        }
        auto share = shamir_decode_text(text);
        if (!share) {
            return share_outcome::malformed;
        }
        if (share->k != catalog->k || share->n != catalog->n ||
            !constant_time_equal(share->check_value, catalog->mk_check)) {
            return share_outcome::wrong_split;
        }
        for (const auto& held : _held) {
            if (held.index == share->index) {
                return share_outcome::duplicate;
            }
        }
        if (_held.empty()) {
            _first = _now();
        }
        _held.push_back(std::move(*share));
        if (_held.size() < catalog->k) {
            return share_outcome::accepted;
        }
        auto mk = shamir_combine(_held);
        _held.clear();
        if (!mk || _vault->unseal(std::move(*mk), catalog) != unseal_result::unsealed) {
            return share_outcome::wrong_key;
        }
        return share_outcome::unsealed;
    }

    /// Discards the held shares.
    auto reset() -> void {
        const std::scoped_lock lock(_mutex);
        _held.clear();
    }

    /// Discards the held shares once the first is older than the timeout.
    auto expire() -> void {
        const std::scoped_lock lock(_mutex);
        expire_locked();
    }

    [[nodiscard]] auto progress(const std::optional<catalog_record>& catalog) -> unseal_progress {
        const std::scoped_lock lock(_mutex);
        expire_locked();
        return {_vault->sealed(), _held.size(), catalog ? catalog->k : std::uint8_t{0}};
    }

private:
    auto expire_locked() -> void {
        if (!_held.empty() && _now() - _first >= _timeout) {
            _held.clear();
        }
    }

    key_vault* _vault;
    std::chrono::seconds _timeout;
    clock_fn _now;
    std::mutex _mutex;
    std::vector<shamir_share> _held;
    std::chrono::steady_clock::time_point _first{};
};

}  // namespace kythira::hsm
