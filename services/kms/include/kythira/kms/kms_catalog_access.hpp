// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// How KMS handlers and jobs reach the catalog
// (.kiro/specs/kms-independent-layers/ task 1, Requirements 3.1-3.3).
//
// The KMS catalog is one Raft group on the data layer. A node that holds
// a replica (the `data` role) reads it in-process; a front end on its own
// reads it over the data-layer API (kms_catalog_api.hpp).
// Handlers and jobs are written once for both, against two interfaces:
//
//  - `kms_catalog_reader`: the catalog's queries, each answering a value
//    (a record, a list, a count), never a reference into the replica, so
//    an implementation may fetch each answer from elsewhere.
//  - `kms_catalog_access`: where a reader comes from, and the two things
//    every operation does around it: a read barrier (the read-index point
//    the KMS design requires before a cryptographic operation or any
//    other read) and a proposal.
//
// `local_catalog_access` is the co-located implementation: the reader
// answers from this node's replica as it is when asked, the barrier waits
// until the replica has applied what the catalog had committed, and a
// proposal goes through the node's host (which forwards to the leader).
// Nothing a co-located node does changes (Requirement 1.2).
//
// The handler templates (kms_api.hpp, kms_crypto_api.hpp,
// kms_signing_api.hpp, kms_grants_api.hpp) and key_jobs are instantiated
// with `kms_catalog_reader` in the module; `api_deps_from` and
// `crypto_deps_from` fill their catalog members from an access, so a
// layout differs only in the access the module builds.

#include <kythira/kms/kms_catalog.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// The KMS catalog's queries (kms_catalog_state_machine's reads). Every
/// answer is a value; an implementation that cannot answer throws
/// kms_catalog_unreachable, which handlers map to KMSInternalException
/// (independent-layers Requirement 4.3), never to "not found".
class kms_catalog_reader {
public:
    kms_catalog_reader() = default;
    kms_catalog_reader(const kms_catalog_reader&) = default;
    auto operator=(const kms_catalog_reader&) -> kms_catalog_reader& = default;
    kms_catalog_reader(kms_catalog_reader&&) = default;
    auto operator=(kms_catalog_reader&&) -> kms_catalog_reader& = default;
    virtual ~kms_catalog_reader() = default;

    // -- Keys ------------------------------------------------------------------

    [[nodiscard]] virtual auto key(std::string_view key_id) const -> std::optional<key_record> = 0;
    /// Whether `key_id` was a key and was destroyed.
    [[nodiscard]] virtual auto tombstoned(std::string_view key_id) const -> bool = 0;
    /// Up to `limit` of the account's key ids after `after` (exclusive), in
    /// id order.
    [[nodiscard]] virtual auto keys(std::string_view account, std::string_view after = {},
                                    std::size_t limit = SIZE_MAX) const
        -> std::vector<std::string> = 0;
    [[nodiscard]] virtual auto versions(std::string_view key_id) const
        -> std::vector<key_version> = 0;
    [[nodiscard]] virtual auto version(std::string_view key_id, std::uint32_t v) const
        -> std::optional<key_version> = 0;
    [[nodiscard]] virtual auto tags(std::string_view key_id) const -> tag_map = 0;

    // -- Aliases ---------------------------------------------------------------

    [[nodiscard]] virtual auto alias(std::string_view account, std::string_view name) const
        -> std::optional<alias_record> = 0;
    /// The account's aliases in name order, or only `key_id`'s.
    [[nodiscard]] virtual auto aliases(std::string_view account, std::string_view key_id = {}) const
        -> std::vector<alias_record> = 0;

    // -- Grants ----------------------------------------------------------------

    [[nodiscard]] virtual auto grant(std::string_view key_id, std::string_view grant_id) const
        -> std::optional<grant_record> = 0;
    [[nodiscard]] virtual auto grants(std::string_view key_id) const
        -> std::vector<grant_record> = 0;

    // -- Accounts --------------------------------------------------------------

    [[nodiscard]] virtual auto counts(std::string_view account) const -> account_counts = 0;
    [[nodiscard]] virtual auto limits(std::string_view account) const -> account_limits = 0;

    // -- What the jobs work from -------------------------------------------------

    /// The job lease record (independent-layers task 2).
    [[nodiscard]] virtual auto lease() const -> job_lease = 0;

    [[nodiscard]] virtual auto creating_keys() const -> std::vector<key_record> = 0;
    [[nodiscard]] virtual auto due_deletions(std::uint64_t now_ms) const
        -> std::vector<key_record> = 0;
    [[nodiscard]] virtual auto due_rotations(std::uint64_t now_ms) const
        -> std::vector<key_record> = 0;

    // -- Conveniences over the queries -------------------------------------------

    /// The key `ref` names in `account`: a key id, or an alias name
    /// (`alias/...`). Key and alias ARNs are the handlers' to take apart,
    /// because only they know the request's partition and region.
    [[nodiscard]] auto resolve(std::string_view account, std::string_view ref) const
        -> std::optional<key_record> {
        if (ref.starts_with("alias/")) {
            const auto a = alias(account, ref);
            return a ? key(a->key_id) : std::nullopt;
        }
        return key(ref);
    }

    /// The key's grants whose grantee is `grantee`.
    [[nodiscard]] auto grants_for(std::string_view key_id, std::string_view grantee) const
        -> std::vector<grant_record> {
        auto all = grants(key_id);
        std::erase_if(all, [&](const grant_record& g) { return g.grantee_principal != grantee; });
        return all;
    }

    /// The key's policy, or nullopt when there is no such key.
    [[nodiscard]] auto policy(std::string_view key_id) const -> std::optional<std::string> {
        auto k = key(key_id);
        return k ? std::optional<std::string>(std::move(k->policy)) : std::nullopt;
    }
};

/// The catalog could not answer a query (a remote reader lost the data
/// layer): the request fails, it is never answered as if nothing existed.
class kms_catalog_unreachable : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Where handlers and jobs get the catalog from, in one layout.
class kms_catalog_access {
public:
    kms_catalog_access() = default;
    kms_catalog_access(const kms_catalog_access&) = delete;
    auto operator=(const kms_catalog_access&) -> kms_catalog_access& = delete;
    kms_catalog_access(kms_catalog_access&&) = delete;
    auto operator=(kms_catalog_access&&) -> kms_catalog_access& = delete;
    virtual ~kms_catalog_access() = default;

    /// Waits until reads see everything the catalog had committed when
    /// called (a read-index point). False when that cannot be reached in
    /// the access's budget; the caller answers an error and reads nothing.
    [[nodiscard]] virtual auto barrier() -> bool = 0;

    /// The catalog's queries, or null while the catalog is not open here.
    /// Reads made after a successful barrier() see at least what it saw.
    [[nodiscard]] virtual auto reader() const -> std::shared_ptr<const kms_catalog_reader> = 0;

    /// Proposes a catalog command and answers its status.
    /// @throws when no leader answered or the outcome is unknown (the
    ///         host's kms_unavailable for a co-located node).
    virtual auto propose(const std::vector<std::byte>& command) -> catalog_status = 0;

    /// barrier() then reader(): null when either fails.
    [[nodiscard]] auto consistent() -> std::shared_ptr<const kms_catalog_reader> {
        return barrier() ? reader() : nullptr;
    }
};

/// A reader over a catalog replica held in-process: every query is the
/// replica's own, as it is when asked.
template<typename Catalog> class local_catalog_reader final : public kms_catalog_reader {
public:
    explicit local_catalog_reader(std::shared_ptr<const Catalog> replica)
        : _replica(std::move(replica)) {
        if (!_replica) {
            throw std::invalid_argument("local_catalog_reader: no replica");
        }
    }

    [[nodiscard]] auto replica() const -> const std::shared_ptr<const Catalog>& { return _replica; }

    [[nodiscard]] auto key(std::string_view key_id) const -> std::optional<key_record> override {
        return _replica->key(key_id);
    }
    [[nodiscard]] auto tombstoned(std::string_view key_id) const -> bool override {
        return _replica->tombstoned(key_id);
    }
    [[nodiscard]] auto keys(std::string_view account, std::string_view after,
                            std::size_t limit) const -> std::vector<std::string> override {
        return _replica->keys(account, after, limit);
    }
    [[nodiscard]] auto versions(std::string_view key_id) const
        -> std::vector<key_version> override {
        return _replica->versions(key_id);
    }
    [[nodiscard]] auto version(std::string_view key_id, std::uint32_t v) const
        -> std::optional<key_version> override {
        return _replica->version(key_id, v);
    }
    [[nodiscard]] auto tags(std::string_view key_id) const -> tag_map override {
        return _replica->tags(key_id);
    }
    [[nodiscard]] auto alias(std::string_view account, std::string_view name) const
        -> std::optional<alias_record> override {
        return _replica->alias(account, name);
    }
    [[nodiscard]] auto aliases(std::string_view account, std::string_view key_id) const
        -> std::vector<alias_record> override {
        return _replica->aliases(account, key_id);
    }
    [[nodiscard]] auto grant(std::string_view key_id, std::string_view grant_id) const
        -> std::optional<grant_record> override {
        return _replica->grant(key_id, grant_id);
    }
    [[nodiscard]] auto grants(std::string_view key_id) const -> std::vector<grant_record> override {
        return _replica->grants(key_id);
    }
    [[nodiscard]] auto counts(std::string_view account) const -> account_counts override {
        return _replica->counts(account);
    }
    [[nodiscard]] auto limits(std::string_view account) const -> account_limits override {
        return _replica->limits(account);
    }
    [[nodiscard]] auto lease() const -> job_lease override { return _replica->lease(); }
    [[nodiscard]] auto creating_keys() const -> std::vector<key_record> override {
        return _replica->creating_keys();
    }
    [[nodiscard]] auto due_deletions(std::uint64_t now_ms) const
        -> std::vector<key_record> override {
        return _replica->due_deletions(now_ms);
    }
    [[nodiscard]] auto due_rotations(std::uint64_t now_ms) const
        -> std::vector<key_record> override {
        return _replica->due_rotations(now_ms);
    }

private:
    std::shared_ptr<const Catalog> _replica;
};

/// The co-located access: this node's replica, its host's barrier and
/// proposals. Built from three functions so the module (over
/// basic_kms_host) and the in-process tests (over a bare state machine)
/// share it.
template<typename Catalog> class local_catalog_access final : public kms_catalog_access {
public:
    struct functions {
        /// This node's replica, or null before the catalog opens.
        std::function<std::shared_ptr<const Catalog>()> replica;
        std::function<bool()> barrier;
        std::function<catalog_status(const std::vector<std::byte>&)> propose;
    };

    explicit local_catalog_access(functions f) : _f(std::move(f)) {
        if (!_f.replica || !_f.barrier || !_f.propose) {
            throw std::invalid_argument("local_catalog_access: every function is required");
        }
    }

    /// Over a basic_kms_host (kms_host.hpp), which must outlive the access.
    template<typename KmsHost> [[nodiscard]] static auto over_host(KmsHost& host) -> functions {
        return functions{
            .replica = [&host] { return host.catalog(); },
            .barrier = [&host] { return host.barrier(); },
            .propose = [&host](const std::vector<std::byte>& c) { return host.propose(c); },
        };
    }

    [[nodiscard]] auto barrier() -> bool override { return _f.barrier(); }

    [[nodiscard]] auto reader() const -> std::shared_ptr<const kms_catalog_reader> override {
        auto replica = _f.replica();
        if (!replica) {
            return nullptr;
        }
        // The replica is opened once and kept, so one reader serves every
        // request; a new replica (the group reopened) gets a new reader.
        const std::scoped_lock lock(_mutex);
        if (!_reader || _reader->replica() != replica) {
            _reader = std::make_shared<const local_catalog_reader<Catalog>>(std::move(replica));
        }
        return _reader;
    }

    auto propose(const std::vector<std::byte>& command) -> catalog_status override {
        return _f.propose(command);
    }

private:
    functions _f;
    mutable std::mutex _mutex;
    mutable std::shared_ptr<const local_catalog_reader<Catalog>> _reader;
};

/// The compatibility switch of Requirement 4.2 (KYTHIRA_KMS_BOUNDED_
/// STALENESS_MS): a read-index point reached at most `bound` ago serves
/// a request's barrier, so a busy front end pays one round trip per bound
/// rather than per request, and answers may be up to `bound` behind, as
/// AWS documents its KMS to be. Off (bound 0) it adds nothing.
///
/// - A barrier that fails is never covered by an older one: a front end
///   that cannot reach the catalog answers an error once the bound has
///   passed (Requirement 4.3), never a cached answer beyond it.
/// - A proposal through this access forgets the point, so this front end
///   reads its own writes.
/// - The jobs and the job lease use the inner access: they read at a
///   fresh point whatever the switch says.
class bounded_staleness_access final : public kms_catalog_access {
public:
    using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

    bounded_staleness_access(
        kms_catalog_access& inner, std::chrono::milliseconds bound,
        clock_fn clock = [] { return std::chrono::steady_clock::now(); })
        : _inner(inner), _bound(bound), _clock(std::move(clock)) {
        if (bound.count() < 0 || !_clock) {
            throw std::invalid_argument("bounded_staleness_access: negative bound or no clock");
        }
    }

    [[nodiscard]] auto barrier() -> bool override {
        if (_bound.count() == 0) {
            return _inner.barrier();
        }
        const auto now = _clock();
        {
            const std::scoped_lock lock(_mutex);
            if (_point && now - *_point < _bound) {
                return true;
            }
        }
        if (!_inner.barrier()) {
            return false;
        }
        const std::scoped_lock lock(_mutex);
        // The point is when the round started: what it saw is at least
        // that fresh.
        if (!_point || *_point < now) {
            _point = now;
        }
        return true;
    }

    [[nodiscard]] auto reader() const -> std::shared_ptr<const kms_catalog_reader> override {
        return _inner.reader();
    }

    auto propose(const std::vector<std::byte>& command) -> catalog_status override {
        {
            const std::scoped_lock lock(_mutex);
            _point.reset();
        }
        return _inner.propose(command);
    }

    [[nodiscard]] auto bound() const noexcept -> std::chrono::milliseconds { return _bound; }

private:
    kms_catalog_access& _inner;
    std::chrono::milliseconds _bound;
    clock_fn _clock;
    std::mutex _mutex;
    std::optional<std::chrono::steady_clock::time_point> _point;
};

/// Fills a handler's or job's dependency struct (api_deps, crypto_deps,
/// managed_deps over kms_catalog_reader) from `access`: `catalog` answers
/// the reader, and where the struct has them, `barrier` and `propose` go
/// through the access. `access` must outlive the handlers.
template<typename Deps> auto fill_catalog_deps(Deps& deps, kms_catalog_access& access) -> void {
    if constexpr (requires { deps.barrier; }) {
        deps.catalog = [&access] { return access.reader(); };
        deps.barrier = [&access] { return access.barrier(); };
    } else {
        // managed_deps has no barrier: its catalog is read after one.
        deps.catalog = [&access] { return access.consistent(); };
    }
    if constexpr (requires { deps.propose; }) {
        deps.propose = [&access](const std::vector<std::byte>& c) { return access.propose(c); };
    }
}

}  // namespace kythira::kms
