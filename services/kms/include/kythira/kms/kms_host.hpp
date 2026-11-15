// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The KMS catalog on the node's multi-raft host
// (.kiro/specs/kms-compatible-api/ task 5, design "Metadata in the KMS,
// material in the HSM"), with no transport of its own: the in-process
// tests run it on a message fabric and kms_module runs it on the node's
// listener.
//
//  - The group. The catalog is the module's one group, host group id
//    `group` (0 stand-alone, the first id of the module's space in a
//    composite node). Every member votes in it and creates it at every
//    start.
//  - Writes. multi_raft has no proposal forwarding, and a KMS request may
//    reach any member. A member that does not lead sends the proposal to
//    the leader it knows through `forwarder::propose`; the leader submits
//    it and answers the catalog's reply. A leader that is not the leader
//    any more answers not_leader, and since nothing was submitted the
//    member tries again; any other failure may have committed, so propose
//    throws kms_unavailable rather than guess.
//  - Read barriers. A member that does not lead asks the leader for a
//    read-index round through `forwarder::read_index` and waits until it
//    has applied as far, so a read after a barrier is never stale. A
//    member cut off from the leader fails the barrier once the timeout
//    passes.
//
// The multi_raft config must build its state machines from the context:
//
//   auto ctx = kms_host::make_context();
//   cfg.state_machine_factory = [ctx](const auto&) { return group_sm(ctx); };
//   cfg.automatic_split_merge_enabled = false;  // the catalog never moves

#include <kythira/kms/kms_catalog.hpp>
#include <kythira/kms/kms_group_state_machine.hpp>

#include <raft/shard_exceptions.hpp>
#include <raft/shard_types.hpp>

#include <algorithm>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::kms {

/// No leader answered a proposal in time, or the proposal may have
/// committed without an answer: KMSInternalException (or
/// DependencyTimeoutException) to a client, a retry to the jobs.
class kms_unavailable : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// A leader's answer to a forwarded proposal or read-index request.
template<typename NodeId> struct forward_reply {
    enum class status : std::uint8_t {
        ok,
        /// This node does not lead the catalog: nothing was submitted.
        not_leader,
        /// The request failed and may or may not have taken effect.
        unavailable,
    };
    status result = status::unavailable;
    /// The catalog's reply to a proposal.
    std::vector<std::byte> reply;
    /// The leader's applied index after the round or the proposal's apply.
    std::uint64_t index = 0;
    /// With not_leader: the leader this node knows of, if any.
    std::optional<NodeId> leader;
};

/// Counters for the module's metrics.
struct kms_host_stats {
    std::uint64_t proposals_forwarded = 0;
    std::uint64_t read_indexes_forwarded = 0;
    std::uint64_t proposals_served = 0;
    std::uint64_t read_indexes_served = 0;
    std::uint64_t split_merge_vetoes = 0;
};

template<typename Host, kythira::kv_engine Engine> class basic_kms_host {
public:
    using host_type = Host;
    using engine_type = Engine;
    using node_id_type = typename Host::node_id_type;
    using descriptor_type = typename Host::descriptor_type;
    using group_id_type = std::remove_cvref_t<decltype(std::declval<descriptor_type>()._group_id)>;
    using group_sm = kms_group_state_machine<Engine>;
    using catalog_type = typename group_sm::catalog_type;
    using reply_type = forward_reply<node_id_type>;

    static_assert(std::integral<group_id_type>, "KMS group ids are integers");

    /// How a member reaches the catalog's leader. Each call blocks until
    /// the leader answers; a transport failure answers `unavailable`.
    struct forwarder {
        std::function<reply_type(const node_id_type& leader, const std::vector<std::byte>& command)>
            propose;
        std::function<reply_type(const node_id_type& leader)> read_index;
    };

    struct options {
        /// Every member, this node included: the catalog's voters.
        std::vector<node_id_type> members;
        /// The catalog's host group id.
        group_id_type group = 0;
        /// The whole budget of one proposal or read barrier, forwarding and
        /// waiting for a leader included.
        std::chrono::milliseconds propose_timeout{5000};
        /// Pause between attempts while there is no leader to reach.
        std::chrono::milliseconds retry_interval{20};
        forwarder forward;
    };

    static auto make_context() -> std::shared_ptr<typename group_sm::context> {
        return std::make_shared<typename group_sm::context>();
    }

    basic_kms_host(Host& host, std::shared_ptr<typename group_sm::context> ctx, options opts)
        : _host(&host), _ctx(std::move(ctx)), _opts(std::move(opts)) {}

    /// Create the catalog group here (every member does, at every start).
    auto bootstrap() -> void {
        if (!_host->has_group(_opts.group)) {
            descriptor_type d{};
            d._group_id = _opts.group;
            const auto range = group_sm::catalog_range();
            d._range = kythira::shard_range<std::string>{range.start, range.end};
            d._epoch = kythira::shard_epoch{};
            d._voters = _opts.members;
            _host->create_group(d);
        }
    }

    /// This replica of the catalog, or null before the group opens.
    [[nodiscard]] auto catalog() const -> std::shared_ptr<const catalog_type> {
        return _ctx->catalog();
    }

    /// Whether this node leads the catalog.
    [[nodiscard]] auto leads() const -> bool {
        const auto* node = _host->group_node(_opts.group);
        return node != nullptr && node->is_leader();
    }

    /// Propose `command` to the catalog, here when this node leads it and
    /// through the leader otherwise, and answer the catalog's status.
    /// @throws kms_unavailable when no leader answered within the budget,
    ///         or the command may have committed without an answer.
    auto propose(const std::vector<std::byte>& command) -> catalog_status {
        return catalog_reply_status(propose_reply(command));
    }

    /// Wait until this replica has applied what the catalog had committed
    /// when called. False when no leader answered within the budget.
    [[nodiscard]] auto barrier() -> bool {
        const auto deadline = clock::now() + _opts.propose_timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(_opts.group);
            if (node == nullptr) {
                continue;
            }
            if (node->is_leader()) {
                try {
                    std::ignore = node->read_state(remaining(deadline)).get();
                    return true;
                } catch (const std::exception&) {
                    if (node->is_leader()) {
                        return false;  // no quorum
                    }
                    continue;
                }
            }
            const auto leader = node->known_leader();
            if (!leader || *leader == _host->node_id() || !_opts.forward.read_index) {
                continue;
            }
            count(&kms_host_stats::read_indexes_forwarded);
            const auto r = call_forwarder([&] { return _opts.forward.read_index(*leader); });
            if (r.result == reply_type::status::unavailable) {
                return false;
            }
            if (r.result == reply_type::status::ok) {
                return wait_applied(r.index, deadline);
            }
        }
        return false;
    }

    // -- The leader's side of forwarding -------------------------------------

    /// Submit a member's proposal, which this node must lead; never
    /// forwarded again, so a stale hint cannot loop.
    auto serve_propose(const std::vector<std::byte>& command) -> reply_type {
        using not_leader = kythira::shard_not_leader_exception<group_id_type, node_id_type>;
        reply_type out;
        auto* node = _host->group_node(_opts.group);
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        count(&kms_host_stats::proposals_served);
        try {
            auto f = _host->submit_command(_opts.group, kythira::shard_epoch{}, command,
                                           _opts.propose_timeout);
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

    /// Run a read-index round, which this node must lead, and answer the
    /// index applied after it.
    auto serve_read_index() -> reply_type {
        reply_type out;
        auto* node = _host->group_node(_opts.group);
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        count(&kms_host_stats::read_indexes_served);
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

    [[nodiscard]] auto stats() const -> kms_host_stats {
        const std::lock_guard lock(_mutex);
        auto s = _stats;
        s.split_merge_vetoes = _ctx->vetoes.load(std::memory_order_relaxed);
        return s;
    }

private:
    using clock = std::chrono::steady_clock;

    [[nodiscard]] static auto remaining(clock::time_point deadline) -> std::chrono::milliseconds {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now());
        return std::max(left, std::chrono::milliseconds{1});
    }

    auto propose_reply(const std::vector<std::byte>& command) -> std::vector<std::byte> {
        using not_leader = kythira::shard_not_leader_exception<group_id_type, node_id_type>;
        const auto deadline = clock::now() + _opts.propose_timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(_opts.group);
            if (node == nullptr) {
                continue;
            }
            if (node->is_leader()) {
                try {
                    auto f = _host->submit_command(_opts.group, kythira::shard_epoch{}, command,
                                                   remaining(deadline));
                    return std::move(f).get();
                } catch (const not_leader&) {
                    continue;  // lost it before submitting: nothing went in
                } catch (const std::exception& e) {
                    // A commit timeout or a leadership lost after the entry
                    // went in: it may still commit.
                    throw kms_unavailable(std::string("kms: proposal outcome unknown: ") +
                                          e.what());
                }
            }
            const auto leader = node->known_leader();
            if (!leader || *leader == _host->node_id() || !_opts.forward.propose) {
                continue;
            }
            count(&kms_host_stats::proposals_forwarded);
            auto r = call_forwarder([&] { return _opts.forward.propose(*leader, command); });
            if (r.result == reply_type::status::ok) {
                // Read your writes: wait until this replica has applied the
                // entry. It committed either way, so a timeout still
                // answers its reply; the next barrier catches up.
                std::ignore = wait_applied(r.index, deadline);
                return std::move(r.reply);
            }
            if (r.result == reply_type::status::unavailable) {
                throw kms_unavailable("kms: the catalog leader did not answer");
            }
        }
        throw kms_unavailable("kms: no catalog leader answered before the deadline");
    }

    auto wait_applied(std::uint64_t index, clock::time_point deadline) -> bool {
        for (;; std::this_thread::sleep_for(std::chrono::milliseconds{1})) {
            auto* n = _host->group_node(_opts.group);
            if (n == nullptr) {
                return false;
            }
            if (static_cast<std::uint64_t>(n->last_applied_index()) >= index) {
                return true;
            }
            if (clock::now() >= deadline) {
                return false;
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

    auto count(std::uint64_t kms_host_stats::* field) const -> void {
        const std::lock_guard lock(_mutex);
        ++(_stats.*field);
    }

    Host* _host;
    std::shared_ptr<typename group_sm::context> _ctx;
    options _opts;
    mutable std::mutex _mutex;
    mutable kms_host_stats _stats;
};

}  // namespace kythira::kms
