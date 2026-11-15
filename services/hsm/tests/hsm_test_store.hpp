// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An hsm_store for unit tests: the catalog and token state machines on one
// memory engine, applied to directly with a counter standing in for the
// Raft log. Hooks let a test fail the barrier or proposals, and act as
// another node between a call's start and its read-index round.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_store.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace kythira::hsm::test {

class direct_store final : public hsm_store {
public:
    direct_store() { _catalog.open(_engine, _catalog.engine_range()); }

    [[nodiscard]] auto catalog() const -> std::optional<catalog_record> override {
        return _catalog.catalog();
    }
    [[nodiscard]] auto tokens() const -> std::vector<token_entry> override {
        return _catalog.tokens();
    }
    [[nodiscard]] auto token(std::uint64_t id) const -> std::optional<token_entry> override {
        return _catalog.token(id);
    }
    [[nodiscard]] auto may_open(std::string_view identity, std::uint64_t id) const
        -> bool override {
        return _catalog.may_open(identity, id);
    }
    [[nodiscard]] auto hosts(std::uint64_t id) const -> bool override {
        const std::lock_guard lock(_mutex);
        return _tokens.contains(id);
    }
    [[nodiscard]] auto token_record_of(std::uint64_t id) const
        -> std::optional<token_record> override {
        auto* t = group(id);
        return t == nullptr ? std::nullopt : t->token();
    }
    [[nodiscard]] auto object(std::uint64_t id, std::uint64_t handle) const
        -> std::optional<object_record> override {
        auto* t = group(id);
        return t == nullptr ? std::nullopt : t->object(handle);
    }
    [[nodiscard]] auto objects(std::uint64_t id) const -> std::vector<object_record> override {
        std::vector<object_record> out;
        if (auto* t = group(id)) {
            t->for_each_object([&](const object_record& o) {
                out.push_back(o);
                return true;
            });
        }
        return out;
    }

    auto propose_catalog(std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        if (fail_proposals) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        log.push_back(command);
        auto reply = _catalog.apply(command, ++_index);
        // Every member hosts every token group once the catalog names it.
        for (const auto& t : _catalog.tokens()) {
            ensure_group(t.token_id);
        }
        return reply;
    }

    auto propose_token(std::uint64_t id, std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        if (fail_proposals) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        auto* t = group(id);
        if (t == nullptr) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        log.push_back(command);
        ++proposals;
        return t->apply(command, ++_index);
    }

    auto read_barrier(std::uint64_t id) -> ck_result<void> override {
        ++barriers;
        if (before_barrier) {
            auto hook = std::move(before_barrier);
            before_barrier = nullptr;
            hook();
        }
        if (fail_barrier || group(id) == nullptr) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return {};
    }

    /// Applies a token command as if another node had proposed it.
    auto apply_elsewhere(std::uint64_t id, const std::vector<std::byte>& command)
        -> std::vector<std::byte> {
        return group(id)->apply(command, ++_index);
    }

    auto engine() -> kythira::memory_kv_engine& { return _engine; }

    bool fail_barrier = false;
    bool fail_proposals = false;
    std::function<void()> before_barrier;
    std::uint64_t barriers = 0;
    std::uint64_t proposals = 0;
    std::vector<std::vector<std::byte>> log;

private:
    using token_sm = token_state_machine<>;

    auto ensure_group(std::uint64_t id) -> void {
        const std::lock_guard lock(_mutex);
        if (_tokens.contains(id)) {
            return;
        }
        auto sm = std::make_unique<token_sm>("t/" + std::to_string(id) + "/", id);
        sm->open(_engine, sm->engine_range());
        _tokens.emplace(id, std::move(sm));
    }

    [[nodiscard]] auto group(std::uint64_t id) const -> token_sm* {
        const std::lock_guard lock(_mutex);
        const auto it = _tokens.find(id);
        return it == _tokens.end() ? nullptr : it->second.get();
    }

    kythira::memory_kv_engine _engine;
    hsm_catalog_state_machine<> _catalog{"c/"};
    mutable std::mutex _mutex;
    std::map<std::uint64_t, std::unique_ptr<token_sm>> _tokens;
    std::uint64_t _index = 0;
};

}  // namespace kythira::hsm::test
