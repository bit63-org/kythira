// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HSM's replicated store on the node's multi-raft host
// (.kiro/specs/virtual-hsm/ task 6c): hsm_store for the session layer,
// with no transport of its own, so the in-process tests run it on a
// message fabric and hsm_module runs it on the node's listener.
//
//  - Groups. The catalog is local group 0 and token t is local group t
//    (token ids start at 1), each offset by `group_base` to give the host's
//    group id, as the ledger's groups are. Every member votes in every
//    group: the catalog is small and a token's load is mostly reads served
//    by any replica, so there is no placement to decide. Each member
//    creates a token's group once its catalog replica names the token,
//    and destroys it once the catalog records the token as deleted (the
//    catalog keeps a tombstone, so a replica that missed the delete still
//    sees it, and the id is never reused). reconcile() does this; the
//    maintenance thread runs it every pass, and a proposal to the catalog
//    runs it at once.
//  - Writes. multi_raft has no proposal forwarding, and a PKCS#11 client
//    may reach any member. A member that does not lead the group sends the
//    proposal to the leader it knows through `forwarder::propose`; the
//    leader submits it and answers the state machine's reply. A leader
//    that is not the leader any more answers not_leader, and since nothing
//    was submitted the member tries again; any other failure (a commit
//    timeout, a lost connection) may have committed, so it answers
//    CKR_DEVICE_ERROR rather than risk applying a login failure twice.
//  - Read barriers. Only a leader can run a read-index round. A member that
//    does not lead asks the leader through `forwarder::read_index`; the
//    leader runs the round and answers its applied index, and the member
//    waits until it has applied that far. A member cut off from the leader
//    answers CKR_DEVICE_ERROR once the timeout passes, never a stale read
//    (design "Error handling").
//
// The multi_raft config must build its state machines from context():
//
//   auto ctx = host_type::make_context();
//   cfg.state_machine_factory = [ctx](const auto&) { return group_sm(ctx); };
//   cfg.automatic_split_merge_enabled = false;  // HSM groups never move

#include <kythira/hsm/catalog_state_machine.hpp>
#include <kythira/hsm/hsm_group_state_machine.hpp>
#include <kythira/hsm/hsm_store.hpp>
#include <kythira/hsm/token_state_machine.hpp>

#include <raft/completion_exceptions.hpp>
#include <raft/group_storage.hpp>
#include <raft/shard_exceptions.hpp>
#include <raft/shard_types.hpp>

#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace kythira::hsm {

/// Counters for the module's metrics.
struct hsm_host_stats {
    std::uint64_t groups_created = 0;
    std::uint64_t groups_destroyed = 0;
    std::uint64_t proposals_forwarded = 0;
    std::uint64_t read_indexes_forwarded = 0;
    std::uint64_t proposals_served = 0;
    std::uint64_t read_indexes_served = 0;
    /// Tokens whose id falls outside the module's group space.
    std::uint64_t tokens_out_of_space = 0;
    std::uint64_t split_merge_vetoes = 0;
    /// Replica lag (task 14): how many entries this replica was behind the
    /// leader's applied index the last time a forwarded read or proposal
    /// waited for it, and the time spent waiting in all.
    std::uint64_t replica_lag_entries = 0;
    std::uint64_t replica_wait_us = 0;
};

/// A leader's answer to a forwarded proposal or read-index request.
template<typename NodeId> struct forward_reply {
    enum class status : std::uint8_t {
        ok,
        /// This node does not lead the group: nothing was submitted.
        not_leader,
        /// The request failed and may or may not have taken effect.
        unavailable,
    };
    status result = status::unavailable;
    /// The state machine's reply to a proposal.
    std::vector<std::byte> reply;
    /// The leader's applied index after the round or the proposal's apply:
    /// the member waits until it has applied as far before answering.
    std::uint64_t index = 0;
    /// With not_leader: the leader this node knows of, if any.
    std::optional<NodeId> leader;
};

template<typename Host, kythira::kv_engine Engine> class basic_hsm_host final : public hsm_store {
public:
    using host_type = Host;
    using engine_type = Engine;
    using node_id_type = typename Host::node_id_type;
    using descriptor_type = typename Host::descriptor_type;
    using group_id_type = std::remove_cvref_t<decltype(std::declval<descriptor_type>()._group_id)>;
    using group_sm = hsm_group_state_machine<Engine>;
    using catalog_sm = typename group_sm::catalog_type;
    using token_sm = typename group_sm::token_type;
    using reply_type = forward_reply<node_id_type>;

    static_assert(std::integral<group_id_type>, "HSM group ids are integers");

    /// How a member reaches the leader of a group. Each call blocks until
    /// the leader answers; a transport failure answers `unavailable`.
    struct forwarder {
        std::function<reply_type(const node_id_type& leader, std::uint64_t local_group,
                                 const std::vector<std::byte>& command)>
            propose;
        std::function<reply_type(const node_id_type& leader, std::uint64_t local_group)> read_index;
    };

    struct options {
        /// Every member, this node included: the voters of every group.
        std::vector<node_id_type> members;
        /// Added to every local group id to give the host's: 0 stand-alone,
        /// the first id of the module's group space in a composite node.
        group_id_type group_base = 0;
        /// The last host group id the module owns; tokens beyond it are
        /// not hosted (the admin API refuses to create them).
        group_id_type group_last = std::numeric_limits<group_id_type>::max();
        /// The whole budget of one proposal or read barrier, forwarding and
        /// waiting for a leader included.
        std::chrono::milliseconds propose_timeout{5000};
        /// Pause between maintenance passes.
        std::chrono::milliseconds maintenance_interval{200};
        /// Pause between attempts while there is no leader to reach.
        std::chrono::milliseconds retry_interval{20};
        forwarder forward;
    };

    /// The context every group state machine on this node is built from.
    static auto make_context() -> std::shared_ptr<typename group_sm::context> {
        return std::make_shared<typename group_sm::context>();
    }

    basic_hsm_host(Host& host, std::shared_ptr<typename group_sm::context> ctx, options opts)
        : _host(&host), _ctx(std::move(ctx)), _opts(std::move(opts)) {}

    basic_hsm_host(const basic_hsm_host&) = delete;
    auto operator=(const basic_hsm_host&) -> basic_hsm_host& = delete;
    basic_hsm_host(basic_hsm_host&&) = delete;
    auto operator=(basic_hsm_host&&) -> basic_hsm_host& = delete;

    ~basic_hsm_host() override { stop(); }

    /// The host's group id for local group `local` (0 the catalog, else a
    /// token id).
    [[nodiscard]] auto host_group(std::uint64_t local) const -> group_id_type {
        return _opts.group_base + static_cast<group_id_type>(local);
    }

    /// Whether token `token_id` has a group id in the module's space.
    [[nodiscard]] auto fits(std::uint64_t token_id) const -> bool {
        return token_id != 0 &&
               token_id <= static_cast<std::uint64_t>(_opts.group_last - _opts.group_base);
    }

    // -- Lifecycle -----------------------------------------------------------

    /// Create the catalog group here (every member does, at every start),
    /// then the token groups the catalog replica already names.
    auto bootstrap() -> void {
        const auto g = host_group(0);
        if (!_host->has_group(g)) {
            _host->create_group(descriptor_for(g, group_sm::catalog_range()));
        }
        reconcile();
    }

    /// Start the maintenance thread.
    auto start() -> void {
        const std::lock_guard lock(_run_mutex);
        if (_worker.joinable()) {
            return;
        }
        _stopping = false;
        _worker = std::thread([this] { maintenance_loop(); });
    }

    auto stop() -> void {
        {
            const std::lock_guard lock(_run_mutex);
            _stopping = true;
        }
        _run_cv.notify_all();
        if (_worker.joinable()) {
            _worker.join();
        }
    }

    /// Create the groups of tokens the catalog names and this node does not
    /// host yet, and destroy the groups of deleted tokens.
    auto reconcile() -> void {
        const auto cat = catalog_if_open();
        if (!cat) {
            return;
        }
        const std::lock_guard lock(_reconcile_mutex);
        for (const auto& t : cat->tokens()) {
            if (!fits(t.token_id)) {
                count(&hsm_host_stats::tokens_out_of_space);
                continue;
            }
            const auto g = host_group(t.token_id);
            if (_host->has_group(g)) {
                continue;
            }
            try {
                _host->create_group(descriptor_for(g, group_sm::token_range(t.token_id)));
                count(&hsm_host_stats::groups_created);
            } catch (const kythira::shard_exception&) {
                // Tombstoned or raced with a peer's message: nothing to do.
            }
        }
        for (const auto id : cat->deleted_tokens()) {
            if (!fits(id)) {
                continue;
            }
            const auto g = host_group(id);
            if (_host->has_group(g) && _host->destroy_group(g, kythira::tombstone_reason::admin)) {
                count(&hsm_host_stats::groups_destroyed);
            }
        }
    }

    // -- hsm_store: reads of this replica ------------------------------------

    [[nodiscard]] auto catalog() const -> std::optional<catalog_record> override {
        const auto c = catalog_if_open();
        return c ? c->catalog() : std::nullopt;
    }

    [[nodiscard]] auto tokens() const -> std::vector<token_entry> override {
        const auto c = catalog_if_open();
        return c ? c->tokens() : std::vector<token_entry>{};
    }

    [[nodiscard]] auto token(std::uint64_t token_id) const -> std::optional<token_entry> override {
        const auto c = catalog_if_open();
        return c ? c->token(token_id) : std::nullopt;
    }

    [[nodiscard]] auto may_open(std::string_view identity, std::uint64_t token_id) const
        -> bool override {
        const auto c = catalog_if_open();
        return c && c->may_open(identity, token_id);
    }

    /// Every binding of the catalog replica, as (identity, token).
    [[nodiscard]] auto bindings() const -> std::vector<std::pair<std::string, std::uint64_t>> {
        const auto c = catalog_if_open();
        return c ? c->bindings() : std::vector<std::pair<std::string, std::uint64_t>>{};
    }

    [[nodiscard]] auto hosts(std::uint64_t token_id) const -> bool override {
        return token_if_open(token_id) != nullptr;
    }

    [[nodiscard]] auto token_record_of(std::uint64_t token_id) const
        -> std::optional<token_record> override {
        const auto t = token_if_open(token_id);
        return t ? t->token() : std::nullopt;
    }

    [[nodiscard]] auto object(std::uint64_t token_id, std::uint64_t handle) const
        -> std::optional<object_record> override {
        const auto t = token_if_open(token_id);
        return t ? t->object(handle) : std::nullopt;
    }

    [[nodiscard]] auto objects(std::uint64_t token_id) const
        -> std::vector<object_record> override {
        std::vector<object_record> out;
        if (const auto t = token_if_open(token_id)) {
            t->for_each_object([&](const object_record& o) {
                out.push_back(o);
                return true;
            });
        }
        return out;
    }

    // -- hsm_store: writes and barriers --------------------------------------

    auto propose_catalog(std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        auto r = propose(0, command);
        if (r) {
            reconcile();  // a new or deleted token's group, here at once
        }
        return r;
    }

    auto propose_token(std::uint64_t token_id, std::vector<std::byte> command)
        -> ck_result<std::vector<std::byte>> override {
        if (!fits(token_id)) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return propose(token_id, command);
    }

    auto read_barrier(std::uint64_t token_id) -> ck_result<void> override {
        if (!fits(token_id)) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        return barrier(token_id);
    }

    /// A read barrier on the catalog group (unseal checks the catalog
    /// record a leader has, not a lagging replica's).
    auto catalog_barrier() -> ck_result<void> { return barrier(0); }

    // -- The leader's side of forwarding -------------------------------------

    /// Submit a member's proposal to local group `local_group`, which this
    /// node must lead; never forwarded again, so a stale hint cannot loop.
    auto serve_propose(std::uint64_t local_group, const std::vector<std::byte>& command)
        -> reply_type {
        using not_leader = kythira::shard_not_leader_exception<group_id_type, node_id_type>;
        reply_type out;
        if (local_group != 0 && !fits(local_group)) {
            return out;
        }
        const auto g = host_group(local_group);
        auto* node = _host->group_node(g);
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        count(&hsm_host_stats::proposals_served);
        try {
            auto f =
                _host->submit_command(g, kythira::shard_epoch{}, command, _opts.propose_timeout);
            out.reply = std::move(f).get();
            out.index = static_cast<std::uint64_t>(node->last_applied_index());
            out.result = reply_type::status::ok;
        } catch (const not_leader& e) {
            out.result = reply_type::status::not_leader;
            out.leader = e.leader_hint();
        } catch (const std::exception&) {
            out.result = reply_type::status::unavailable;
        }
        return out;
    }

    /// Run a read-index round on local group `local_group`, which this node
    /// must lead, and answer the index applied after it.
    auto serve_read_index(std::uint64_t local_group) -> reply_type {
        reply_type out;
        if (local_group != 0 && !fits(local_group)) {
            return out;
        }
        auto* node = _host->group_node(host_group(local_group));
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        count(&hsm_host_stats::read_indexes_served);
        try {
            std::ignore = node->read_state(_opts.propose_timeout).get();
            out.index = static_cast<std::uint64_t>(node->last_applied_index());
            out.result = reply_type::status::ok;
        } catch (const std::exception&) {
            out.result = node->is_leader() ? reply_type::status::unavailable
                                           : reply_type::status::not_leader;
        }
        return out;
    }

    // -- For the module ------------------------------------------------------

    [[nodiscard]] auto stats() const -> hsm_host_stats {
        const std::lock_guard lock(_mutex);
        auto s = _stats;
        s.split_merge_vetoes = _ctx->vetoes.load(std::memory_order_relaxed);
        return s;
    }

    /// The catalog replica's crypto member list (empty until seeded).
    [[nodiscard]] auto crypto_members() const -> std::vector<std::string> {
        const auto c = catalog_if_open();
        return c ? c->crypto_members() : std::vector<std::string>{};
    }

    /// Whether this node leads local group `local_group`.
    [[nodiscard]] auto leads(std::uint64_t local_group) const -> bool {
        const auto* node = _host->group_node(host_group(local_group));
        return node != nullptr && node->is_leader();
    }

private:
    using clock = std::chrono::steady_clock;

    [[nodiscard]] auto descriptor_for(group_id_type g, const kythira::key_range& range) const
        -> descriptor_type {
        descriptor_type d{};
        d._group_id = g;
        d._range = kythira::shard_range<std::string>{range.start, range.end};
        d._epoch = kythira::shard_epoch{};
        d._voters = _opts.members;
        return d;
    }

    [[nodiscard]] auto catalog_if_open() const -> std::shared_ptr<catalog_sm> {
        const auto found = _ctx->find(group_sm::catalog_range());
        if (!found) {
            return nullptr;
        }
        const auto* p = std::get_if<std::shared_ptr<catalog_sm>>(&*found);
        return p == nullptr ? nullptr : *p;
    }

    [[nodiscard]] auto token_if_open(std::uint64_t token_id) const -> std::shared_ptr<token_sm> {
        if (!fits(token_id)) {
            return nullptr;
        }
        const auto found = _ctx->find(group_sm::token_range(token_id));
        if (!found) {
            return nullptr;
        }
        const auto* p = std::get_if<std::shared_ptr<token_sm>>(&*found);
        return p == nullptr ? nullptr : *p;
    }

    [[nodiscard]] static auto remaining(clock::time_point deadline) -> std::chrono::milliseconds {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now());
        return std::max(left, std::chrono::milliseconds{1});
    }

    /// Propose `command` to local group `local`, here when this node leads
    /// it and through the leader otherwise.
    auto propose(std::uint64_t local, const std::vector<std::byte>& command)
        -> ck_result<std::vector<std::byte>> {
        using not_leader = kythira::shard_not_leader_exception<group_id_type, node_id_type>;
        const auto g = host_group(local);
        const auto deadline = clock::now() + _opts.propose_timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(g);
            if (node == nullptr) {
                reconcile();  // the catalog may name it now
                continue;
            }
            if (node->is_leader()) {
                try {
                    auto f = _host->submit_command(g, kythira::shard_epoch{}, command,
                                                   remaining(deadline));
                    return std::move(f).get();
                } catch (const not_leader&) {
                    continue;  // lost it before submitting: nothing went in
                } catch (const std::exception&) {
                    // A commit timeout or a leadership lost after the entry
                    // went in: it may still commit.
                    return unexpected(CKR_DEVICE_ERROR);
                }
            }
            const auto leader = node->known_leader();
            if (!leader || *leader == _host->node_id() || !_opts.forward.propose) {
                continue;
            }
            count(&hsm_host_stats::proposals_forwarded);
            auto r = call_forwarder([&] { return _opts.forward.propose(*leader, local, command); });
            if (r.result == reply_type::status::ok) {
                // Read your writes: what the caller does next reads this
                // replica, so wait until it has applied the entry too. The
                // entry committed either way, so a timeout still answers
                // its reply; the next barrier catches the replica up.
                std::ignore = wait_applied(g, r.index, deadline);
                return std::move(r.reply);
            }
            if (r.result == reply_type::status::unavailable) {
                return unexpected(CKR_DEVICE_ERROR);
            }
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

    /// Wait until this replica of local group `local` has applied what the
    /// group had committed when called.
    auto barrier(std::uint64_t local) -> ck_result<void> {
        const auto g = host_group(local);
        const auto deadline = clock::now() + _opts.propose_timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(g);
            if (node == nullptr) {
                reconcile();
                continue;
            }
            if (node->is_leader()) {
                try {
                    std::ignore = node->read_state(remaining(deadline)).get();
                    return {};
                } catch (const std::exception&) {
                    if (node->is_leader()) {
                        return unexpected(CKR_DEVICE_ERROR);  // no quorum
                    }
                    continue;
                }
            }
            const auto leader = node->known_leader();
            if (!leader || *leader == _host->node_id() || !_opts.forward.read_index) {
                continue;
            }
            count(&hsm_host_stats::read_indexes_forwarded);
            const auto r = call_forwarder([&] { return _opts.forward.read_index(*leader, local); });
            if (r.result == reply_type::status::unavailable) {
                return unexpected(CKR_DEVICE_ERROR);
            }
            if (r.result == reply_type::status::not_leader) {
                continue;
            }
            // Caught up once this replica has applied the leader's index.
            return wait_applied(g, r.index, deadline);
        }
        return unexpected(CKR_DEVICE_ERROR);
    }

    /// Wait until this replica of group `g` has applied `index`.
    auto wait_applied(group_id_type g, std::uint64_t index, clock::time_point deadline)
        -> ck_result<void> {
        const auto started = clock::now();
        bool first = true;
        for (;; std::this_thread::sleep_for(std::chrono::milliseconds{1})) {
            auto* n = _host->group_node(g);
            if (n == nullptr) {
                return unexpected(CKR_DEVICE_ERROR);  // destroyed meanwhile
            }
            const auto applied = static_cast<std::uint64_t>(n->last_applied_index());
            if (first) {
                const std::lock_guard lock(_mutex);
                _stats.replica_lag_entries = index > applied ? index - applied : 0;
                first = false;
            }
            if (applied >= index) {
                const std::lock_guard lock(_mutex);
                _stats.replica_wait_us += static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - started)
                        .count());
                return {};
            }
            if (clock::now() >= deadline) {
                return unexpected(CKR_DEVICE_ERROR);
            }
        }
    }

    template<typename F> static auto call_forwarder(F&& f) -> reply_type {
        try {
            return std::forward<F>(f)();
        } catch (const std::exception&) {
            return reply_type{};  // unavailable
        }
    }

    auto pause() const -> void { std::this_thread::sleep_for(_opts.retry_interval); }

    auto maintenance_loop() -> void {
        std::unique_lock lock(_run_mutex);
        while (!_stopping) {
            lock.unlock();
            try {
                reconcile();
            } catch (const std::exception&) {
                // A group being torn down underneath: the next pass retries.
            }
            lock.lock();
            _run_cv.wait_for(lock, _opts.maintenance_interval, [this] { return _stopping; });
        }
    }

    auto count(std::uint64_t hsm_host_stats::* field) const -> void {
        const std::lock_guard lock(_mutex);
        ++(_stats.*field);
    }

    Host* _host;
    std::shared_ptr<typename group_sm::context> _ctx;
    options _opts;

    mutable std::mutex _mutex;
    mutable hsm_host_stats _stats;
    std::mutex _reconcile_mutex;

    std::mutex _run_mutex;
    std::condition_variable _run_cv;
    bool _stopping = false;
    std::thread _worker;
};

}  // namespace kythira::hsm
