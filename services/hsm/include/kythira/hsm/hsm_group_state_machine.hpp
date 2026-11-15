// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// One state machine type for every group of the HSM module
// (.kiro/specs/virtual-hsm/ task 6c).
//
// multi_raft builds every group's state machine from one factory and one
// type, then opens it on the group's range of the node's engine. The HSM
// runs two kinds of group, so this type is a handle that decides what it
// is when it is opened:
//
//   c/...          the catalog (hsm_catalog_state_machine)
//   t/<id>/...     token <id>'s group (token_state_machine)
//
// Any other range is a configuration error and open() throws. Token ids
// are written in decimal, so the namespaces are prefix-free ("t/1/" is not
// a prefix of "t/10/") and the ranges never overlap.
//
// The handle is cheap to copy and every copy shares one state machine, as
// multi_raft moves the factory's value into the node. Every handle built
// from one context records what it opened there, so hsm_host reads the
// catalog and each token by range without taking a Raft node's lock.
//
// HSM groups never split or merge: the split policy hooks report no size
// and no split keys and veto every key, and a split or merge that reaches
// apply anyway throws. vetoes() counts both, for the node's metrics.

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <raft/persistent_state_machine.hpp>

#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

namespace kythira::hsm {

/// The catalog group's engine namespace.
inline constexpr std::string_view catalog_namespace = "c/";

/// Token `token_id`'s engine namespace.
[[nodiscard]] inline auto token_namespace(std::uint64_t token_id) -> std::string {
    return "t/" + std::to_string(token_id) + "/";
}

/// The token id a range belongs to, when it is a token group's range.
[[nodiscard]] inline auto token_id_of_range(const kythira::key_range& range)
    -> std::optional<std::uint64_t> {
    const std::string_view start = range.start;
    if (!start.starts_with("t/") || !start.ends_with('/') || start.size() < 4) {
        return std::nullopt;
    }
    const auto digits = start.substr(2, start.size() - 3);
    std::uint64_t id = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), id);
    if (ec != std::errc{} || end != digits.data() + digits.size() || id == 0 ||
        token_namespace(id) != start) {
        return std::nullopt;  // leading zeros, signs and junk are not ours
    }
    return id;
}

template<kythira::kv_engine Engine> class hsm_group_state_machine {
public:
    using engine_type = Engine;
    using catalog_type = hsm_catalog_state_machine<Engine>;
    using token_type = token_state_machine<Engine>;
    using opened = std::variant<std::shared_ptr<catalog_type>, std::shared_ptr<token_type>>;

    /// The catalog's range: every key under catalog_namespace.
    [[nodiscard]] static auto catalog_range() -> kythira::key_range {
        return catalog_type(std::string(catalog_namespace)).engine_range();
    }

    /// Token `token_id`'s range.
    [[nodiscard]] static auto token_range(std::uint64_t token_id) -> kythira::key_range {
        return token_type(token_namespace(token_id), token_id).engine_range();
    }

    /// What every group on the node shares: the open groups by range start,
    /// whom else to tell when a group opens or drops, and the veto counter.
    struct context {
        std::function<void(const kythira::key_range&, const opened&)> on_open{};
        std::function<void(const kythira::key_range&)> on_drop{};
        std::atomic<std::uint64_t> vetoes{0};

        /// The state machine open on `range` here, if any.
        [[nodiscard]] auto find(const kythira::key_range& range) const -> std::optional<opened> {
            const std::lock_guard lock(mutex);
            const auto it = groups.find(range.start);
            return it == groups.end() ? std::nullopt : std::optional<opened>(it->second);
        }

        mutable std::mutex mutex;
        std::map<std::string, opened> groups;
    };

    hsm_group_state_machine() : hsm_group_state_machine(nullptr) {}

    explicit hsm_group_state_machine(std::shared_ptr<context> ctx)
        : _ctx(ctx ? std::move(ctx) : std::make_shared<context>()),
          _state(std::make_shared<state>()) {}

    // -- persistent_state_machine --------------------------------------------

    auto open(engine_type& engine, const kythira::key_range& range) -> void {
        if (range == catalog_range()) {
            auto c = std::make_shared<catalog_type>(std::string(catalog_namespace));
            c->open(engine, range);
            _state->sm = c;
        } else if (const auto id = token_id_of_range(range); id && range == token_range(*id)) {
            auto t = std::make_shared<token_type>(token_namespace(*id), *id);
            t->open(engine, range);
            _state->sm = t;
        } else {
            throw std::invalid_argument("hsm: range [" + range.start + ", " +
                                        range.end.value_or("") +
                                        ") is neither the catalog nor a token");
        }
        _state->range = range;
        {
            const std::lock_guard lock(_ctx->mutex);
            _ctx->groups.insert_or_assign(range.start, *_state->sm);
        }
        if (_ctx->on_open) {
            _ctx->on_open(range, *_state->sm);
        }
    }

    auto apply(const std::vector<std::byte>& command, std::uint64_t index)
        -> std::vector<std::byte> {
        return visit([&](auto& sm) { return sm.apply(command, index); });
    }

    [[nodiscard]] auto applied_index() const -> std::uint64_t {
        return visit([](const auto& sm) { return sm.applied_index(); });
    }

    [[nodiscard]] auto durable_applied_index() const -> std::uint64_t {
        return visit([](const auto& sm) { return sm.durable_applied_index(); });
    }

    auto checkpoint(const std::filesystem::path& dir) -> kythira::snapshot_manifest {
        return visit([&](auto& sm) { return sm.checkpoint(dir); });
    }

    auto ingest(const std::filesystem::path& dir, const kythira::snapshot_manifest& manifest,
                std::uint64_t index) -> void {
        visit([&](auto& sm) { sm.ingest(dir, manifest, index); });
    }

    auto drop() -> void {
        visit([](auto& sm) { sm.drop(); });
        {
            const std::lock_guard lock(_ctx->mutex);
            _ctx->groups.erase(_state->range.start);
        }
        if (_ctx->on_drop) {
            _ctx->on_drop(_state->range);
        }
    }

    // -- persistent_splittable_state_machine: always vetoed ------------------

    auto split_at(const std::vector<std::string>& /*keys*/) -> std::vector<kythira::key_range> {
        _ctx->vetoes.fetch_add(1, std::memory_order_relaxed);
        throw std::logic_error("hsm: groups never split");
    }

    auto adopt(const kythira::key_range& /*range*/) -> void {
        _ctx->vetoes.fetch_add(1, std::memory_order_relaxed);
        throw std::logic_error("hsm: groups never merge");
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

    // -- For the node --------------------------------------------------------

    [[nodiscard]] auto get() const -> const std::optional<opened>& { return _state->sm; }
    [[nodiscard]] auto shared_context() const -> const std::shared_ptr<context>& { return _ctx; }

private:
    struct state {
        std::optional<opened> sm;
        kythira::key_range range;
    };

    template<typename Fn> auto visit(Fn&& fn) const -> decltype(auto) {
        if (!_state->sm) {
            throw std::logic_error("hsm: group state machine used before open");
        }
        return std::visit([&](const auto& p) -> decltype(auto) { return fn(*p); }, *_state->sm);
    }

    std::shared_ptr<context> _ctx;
    std::shared_ptr<state> _state;
};

}  // namespace kythira::hsm
