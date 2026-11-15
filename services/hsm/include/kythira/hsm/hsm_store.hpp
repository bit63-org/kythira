// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What the session layer needs from the replicated key store, as an
// interface: hsm_host implements it on the node's multi-raft host, and the
// unit tests on state machines they apply to directly. Keeping the session
// layer behind it is what lets every PKCS#11 rule be tested without a
// cluster.
//
// Reads are of this node's replica and may lag the leader. Anything that
// must not act on a stale replica (using a key, requirement 3.4 and 3.5)
// calls read_barrier() first: it returns once this replica has applied
// everything the group had committed when it was called, which is a
// read-index round. When that cannot be had (no quorum, no leader, a
// timeout), it fails with CKR_DEVICE_ERROR and the caller answers that,
// never a stale result (design "Error handling").
//
// Proposals answer the state machine's reply, or CKR_DEVICE_ERROR when the
// entry could not be committed. A command built on a replica that lagged
// is still safe to propose: the state machines refuse a taken handle or a
// stale version (CKR_FUNCTION_REJECTED), so nothing is overwritten.

#include <kythira/hsm/attributes.hpp>
#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace kythira::hsm {

class hsm_store {
public:
    hsm_store() = default;
    hsm_store(const hsm_store&) = delete;
    auto operator=(const hsm_store&) -> hsm_store& = delete;
    hsm_store(hsm_store&&) = delete;
    auto operator=(hsm_store&&) -> hsm_store& = delete;
    virtual ~hsm_store() = default;

    // -- The catalog, as this replica has it ---------------------------------

    [[nodiscard]] virtual auto catalog() const -> std::optional<catalog_record> = 0;
    [[nodiscard]] virtual auto tokens() const -> std::vector<token_entry> = 0;
    [[nodiscard]] virtual auto token(std::uint64_t token_id) const
        -> std::optional<token_entry> = 0;
    [[nodiscard]] virtual auto may_open(std::string_view identity, std::uint64_t token_id) const
        -> bool = 0;

    // -- A token group, as this replica has it -------------------------------

    /// Whether this node hosts the token's group yet (it is created on
    /// every member once the catalog names the token).
    [[nodiscard]] virtual auto hosts(std::uint64_t token_id) const -> bool = 0;
    [[nodiscard]] virtual auto token_record_of(std::uint64_t token_id) const
        -> std::optional<token_record> = 0;
    [[nodiscard]] virtual auto object(std::uint64_t token_id, std::uint64_t handle) const
        -> std::optional<object_record> = 0;
    [[nodiscard]] virtual auto objects(std::uint64_t token_id) const
        -> std::vector<object_record> = 0;

    // -- Writes and barriers -------------------------------------------------

    virtual auto propose_catalog(std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> = 0;
    virtual auto propose_token(std::uint64_t token_id, std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> = 0;
    /// Waits until this replica has applied what the token's group had
    /// committed when called.
    virtual auto read_barrier(std::uint64_t token_id) -> ck_result<void> = 0;
};

}  // namespace kythira::hsm
