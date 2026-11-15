// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Key creation and the leader's key jobs (.kiro/specs/kms-compatible-api/
// task 5, design "Metadata in the KMS, material in the HSM", Requirements
// 3.4, 4.1, 4.5, 9.2-9.4): the steps that span the catalog and the HSM and
// so must survive a leader dying between them.
//
// Creating a key is two steps. The catalog records the key as Creating
// with a fresh id; the HSM makes a backing key labelled with it; the
// catalog records the handle and Enabled. A leader that dies between the
// steps leaves Creating, and the sweep settles it after a grace period:
// a backing key with the label means the HSM step happened, so the sweep
// records it; none means the client's CreateKey failed (it got an error
// or a timeout), so the sweep destroys the entry rather than let a key
// the client never saw appear later. The design allowed making the
// material instead; destroying keeps a retried CreateKey from leaving two
// keys behind.
//
// A rotation generates version n+1 on the HSM first and then commits it,
// and a deletion destroys the backing keys first and then commits the
// tombstone. Both find their own earlier work by label, so each is
// idempotent across leader changes (9.3). A backing key no catalog entry
// accounts for (a rotation that never committed, a deletion whose commit
// failed) is destroyed by the sweep once it has been seen orphaned for
// the grace period.
//
// The catalog is reached through `propose` (a Raft write, returning the
// command's status, or throwing when no leader answered) and read from
// the local replica, which on the leader is current.

#include <kythira/kms/kms_backing.hpp>
#include <kythira/kms/kms_catalog.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace kythira::kms {

/// What a key operation that needs the HSM ends in, for the API's errors.
enum class key_outcome : std::uint8_t {
    ok,
    catalog,      // the catalog refused; see the status
    unavailable,  // the HSM is sealed or unreachable: KMSInternalException
    unsupported,  // the module lacks the mechanism: UnsupportedOperationException
    failed,       // the HSM failed otherwise: KMSInternalException
};

struct key_result {
    key_outcome outcome = key_outcome::ok;
    catalog_status status = catalog_status::ok;

    [[nodiscard]] auto ok() const -> bool { return outcome == key_outcome::ok; }
};

[[nodiscard]] inline auto outcome_of(const backing_error& e) -> key_outcome {
    switch (e.which()) {
        case backing_error::kind::unavailable:
            return key_outcome::unavailable;
        case backing_error::kind::unsupported:
            return key_outcome::unsupported;
        default:
            return key_outcome::failed;
    }
}

/// What one pass of the leader's jobs did, for metrics and tests.
struct job_report {
    std::size_t completed = 0;  // Creating keys whose backing key was found
    std::size_t abandoned = 0;  // Creating keys destroyed
    std::size_t rotated = 0;
    std::size_t deleted = 0;
    std::size_t orphans_destroyed = 0;
    std::size_t failures = 0;  // HSM or catalog failures; retried next pass
};

template<typename Catalog> class key_jobs {
public:
    using propose_fn = std::function<catalog_status(const std::vector<std::byte>&)>;
    using clock_fn = std::function<std::uint64_t()>;  // milliseconds since the epoch

    key_jobs(const Catalog& catalog, backing_store& hsm, propose_fn propose, clock_fn clock,
             std::chrono::milliseconds grace = std::chrono::minutes(5))
        : _catalog(&catalog),
          _hsm(&hsm),
          _propose(std::move(propose)),
          _clock(std::move(clock)),
          _grace(static_cast<std::uint64_t>(grace.count())) {}

    /// CreateKey's two steps. `k` carries the id, account, spec, usage,
    /// description, policy and manager; the state and dates are the
    /// catalog's.
    auto create_key(key_record k, const tag_map& tags) -> key_result {
        k.creation_ms = _clock();
        if (const auto s = _propose(make_create_key_command(k, tags)); s != catalog_status::ok) {
            return {key_outcome::catalog, s};
        }
        std::uint64_t handle = 0;
        try {
            handle = _hsm->generate(k.key_id, 1, k.spec, k.usage);
        } catch (const backing_error& e) {
            // Nothing was made: give the id up now rather than wait for
            // the sweep. If this proposal fails too, the sweep does it.
            (void)try_propose(make_destroy_key_command(k.key_id, _clock()));
            return {outcome_of(e), catalog_status::ok};
        }
        const auto s = _propose(make_complete_key_command(k.key_id, handle, _clock()));
        if (s != catalog_status::ok) {
            return {key_outcome::catalog, s};
        }
        return {};
    }

    /// RotateKeyOnDemand (and the scheduled rotation): version n+1 on the
    /// HSM, then in the catalog.
    auto rotate(std::string_view key_id, rotation_type type) -> key_result {
        const auto k = _catalog->key(key_id);
        if (!k) {
            return {key_outcome::catalog, catalog_status::not_found};
        }
        if (!is_symmetric(k->spec)) {
            return {key_outcome::catalog, catalog_status::rejected};
        }
        if (k->state != key_state::enabled) {
            return {key_outcome::catalog, catalog_status::invalid_state};
        }
        const auto v = k->current_version + 1;
        std::uint64_t handle = 0;
        try {
            // A rotation an earlier leader started and did not commit
            // left its backing key: use it rather than make another.
            if (auto found = _hsm->find(key_id, v)) {
                handle = *found;
            } else {
                handle = _hsm->generate(key_id, v, k->spec, k->usage);
            }
        } catch (const backing_error& e) {
            return {outcome_of(e), catalog_status::ok};
        }
        const auto s = _propose(make_add_version_command(key_id, v, handle, type, _clock()));
        if (s != catalog_status::ok) {
            return {key_outcome::catalog, s};
        }
        return {};
    }

    /// One pass of every job: settle Creating keys, rotate what is due,
    /// destroy what is due, and destroy orphaned backing keys.
    auto run_once() -> job_report {
        job_report r;
        const auto now = _clock();
        for (const auto& k : _catalog->creating_keys()) {
            if (k.creation_ms + _grace > now) {
                continue;
            }
            try {
                if (auto found = _hsm->find(k.key_id, 1)) {
                    count(try_propose(make_complete_key_command(k.key_id, *found, now)),
                          r.completed, r);
                } else {
                    count(try_propose(make_destroy_key_command(k.key_id, now)), r.abandoned, r);
                }
            } catch (const backing_error&) {
                ++r.failures;
            }
        }
        for (const auto& k : _catalog->due_rotations(now)) {
            // rotate() proposes directly, so a lost leader throws; that
            // must not end the pass before the deletions and the sweep.
            bool ok = false;
            try {
                ok = rotate(k.key_id, rotation_type::automatic).ok();
            } catch (const std::exception&) {
                ok = false;  // the next pass retries, reusing the HSM key
            }
            if (ok) {
                ++r.rotated;
            } else {
                ++r.failures;
            }
        }
        for (const auto& k : _catalog->due_deletions(now)) {
            try {
                for (const auto& v : _catalog->versions(k.key_id)) {
                    _hsm->destroy(k.key_id, v.version);
                }
                count(try_propose(make_destroy_key_command(k.key_id, now)), r.deleted, r);
            } catch (const backing_error&) {
                ++r.failures;
            }
        }
        sweep_orphans(now, r);
        return r;
    }

private:
    auto try_propose(const std::vector<std::byte>& c) -> std::optional<catalog_status> {
        try {
            return _propose(c);
        } catch (const std::exception&) {
            return std::nullopt;  // no leader answered; the next pass retries
        }
    }

    static auto count(std::optional<catalog_status> s, std::size_t& done, job_report& r) -> void {
        if (s == catalog_status::ok) {
            ++done;
        } else {
            ++r.failures;
        }
    }

    // A backing key is accounted for when its key is live and has that
    // version, or is Creating and it is version 1. A tombstoned key's are
    // left over from a deletion and go at once; any other is destroyed
    // once it has been orphaned for the grace period, because a rotation
    // in flight makes version n+1 before the catalog records it.
    auto sweep_orphans(std::uint64_t now, job_report& r) -> void {
        std::vector<backing_ref> refs;
        try {
            refs = _hsm->list();
        } catch (const backing_error&) {
            ++r.failures;
            return;
        }
        std::set<backing_ref> orphans;
        for (const auto& ref : refs) {
            if (accounted_for(ref)) {
                continue;
            }
            const bool gone = _catalog->tombstoned(ref.key_id);
            auto [it, fresh] = _first_orphaned.try_emplace(ref, now);
            if (gone || it->second + _grace <= now) {
                try {
                    _hsm->destroy(ref.key_id, ref.version);
                    ++r.orphans_destroyed;
                    _first_orphaned.erase(it);
                } catch (const backing_error&) {
                    ++r.failures;
                }
                continue;
            }
            orphans.insert(ref);
        }
        // Forget refs that are no longer orphaned (their commit landed).
        std::erase_if(_first_orphaned, [&](const auto& e) { return !orphans.contains(e.first); });
    }

    [[nodiscard]] auto accounted_for(const backing_ref& ref) const -> bool {
        const auto k = _catalog->key(ref.key_id);
        if (!k) {
            return false;
        }
        if (k->state == key_state::creating) {
            return ref.version == 1;
        }
        return _catalog->version(ref.key_id, ref.version).has_value();
    }

    const Catalog* _catalog;
    backing_store* _hsm;
    propose_fn _propose;
    clock_fn _clock;
    std::uint64_t _grace;
    std::map<backing_ref, std::uint64_t> _first_orphaned;
};

}  // namespace kythira::kms
