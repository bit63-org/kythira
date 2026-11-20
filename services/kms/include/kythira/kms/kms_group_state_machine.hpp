// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS catalog as a multi_raft group's state machine
// (.kiro/specs/kms-compatible-api/ task 5).
//
// multi_raft builds a group's state machine from a factory and moves it
// into the node, so this type is a cheap handle: every copy shares one
// kms_catalog_state_machine, opened on the catalog's range of the node's
// engine. Every handle built from one context records the catalog there
// when it opens, so kms_host and the leader's jobs read the catalog
// without taking a Raft node's lock (the engine's reads are thread-safe,
// as the HSM's hosts rely on too).
//
// The KMS owns one group and it never splits or merges: the split policy
// hooks report no size and no split keys and veto every key, and a split
// or merge that reaches apply anyway throws.

#include <kythira/kms/kms_catalog.hpp>

#include <raft/persistent_state_machine.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

/// The catalog group's engine namespace.
inline constexpr std::string_view catalog_namespace = "kms/";

template<kythira::kv_engine Engine> class kms_group_state_machine {
public:
    using engine_type = Engine;
    using catalog_type = kms_catalog_state_machine<Engine>;

    /// The catalog's range: every key under catalog_namespace.
    [[nodiscard]] static auto catalog_range() -> kythira::key_range {
        return catalog_type(std::string(catalog_namespace)).engine_range();
    }

    /// What every handle on the node shares: the open catalog, and the
    /// split and merge veto counter.
    struct context {
        std::atomic<std::uint64_t> vetoes{0};

        /// The catalog open here, or null before the group opens.
        [[nodiscard]] auto catalog() const -> std::shared_ptr<const catalog_type> {
            const std::lock_guard lock(mutex);
            return open;
        }

        mutable std::mutex mutex;
        std::shared_ptr<catalog_type> open;
    };

    kms_group_state_machine() : kms_group_state_machine(nullptr) {}

    explicit kms_group_state_machine(std::shared_ptr<context> ctx)
        : _ctx(ctx ? std::move(ctx) : std::make_shared<context>()),
          _state(std::make_shared<state>()) {}

    // -- persistent_state_machine --------------------------------------------

    auto open(engine_type& engine, const kythira::key_range& range) -> void {
        if (range != catalog_range()) {
            throw std::invalid_argument("kms: range [" + range.start + ", " +
                                        range.end.value_or("") + ") is not the catalog");
        }
        auto c = std::make_shared<catalog_type>(std::string(catalog_namespace));
        c->open(engine, range);
        _state->sm = c;
        _state->range = range;
        const std::lock_guard lock(_ctx->mutex);
        _ctx->open = std::move(c);
    }

    auto apply(const std::vector<std::byte>& command, std::uint64_t index)
        -> std::vector<std::byte> {
        return sm().apply(command, index);
    }

    [[nodiscard]] auto applied_index() const -> std::uint64_t { return sm().applied_index(); }

    [[nodiscard]] auto durable_applied_index() const -> std::uint64_t {
        return sm().durable_applied_index();
    }

    /// Forwarded, so the Raft node finds it and can make the engine durable
    /// before compacting the log. Without it the node's `requires` check is
    /// false, the durable index never moves on an engine that only syncs when
    /// asked, and the log is never compacted (doc/memory_profiling.md).
    auto sync_durable() -> void { sm().sync_durable(); }

    auto checkpoint(const std::filesystem::path& dir) -> kythira::snapshot_manifest {
        return sm().checkpoint(dir);
    }

    auto ingest(const std::filesystem::path& dir, const kythira::snapshot_manifest& manifest,
                std::uint64_t index) -> void {
        sm().ingest(dir, manifest, index);
    }

    auto drop() -> void {
        sm().drop();
        const std::lock_guard lock(_ctx->mutex);
        if (_ctx->open == _state->sm) {
            _ctx->open.reset();
        }
    }

    // -- persistent_splittable_state_machine: always vetoed ------------------

    auto split_at(const std::vector<std::string>& /*keys*/) -> std::vector<kythira::key_range> {
        _ctx->vetoes.fetch_add(1, std::memory_order_relaxed);
        throw std::logic_error("kms: the catalog never splits");
    }

    auto adopt(const kythira::key_range& /*range*/) -> void {
        _ctx->vetoes.fetch_add(1, std::memory_order_relaxed);
        throw std::logic_error("kms: the catalog never merges");
    }

    [[nodiscard]] auto range() const -> const kythira::key_range& { return _state->range; }

    // -- split_policy_state_machine: never a reason or a place to split ------

    [[nodiscard]] auto approximate_size_bytes() const -> std::size_t { return 0; }
    [[nodiscard]] auto approximate_key_count() const -> std::size_t { return 0; }
    auto suggest_split_keys(std::size_t /*max*/) -> std::vector<std::string> { return {}; }
    [[nodiscard]] auto can_split_at(const std::string& /*key*/) const -> bool {
        _ctx->vetoes.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    [[nodiscard]] auto shared_context() const -> const std::shared_ptr<context>& { return _ctx; }

private:
    struct state {
        std::shared_ptr<catalog_type> sm;
        kythira::key_range range;
    };

    [[nodiscard]] auto sm() const -> catalog_type& {
        if (!_state->sm) {
            throw std::logic_error("kms: group state machine used before open");
        }
        return *_state->sm;
    }

    std::shared_ptr<context> _ctx;
    std::shared_ptr<state> _state;
};

}  // namespace kythira::kms
