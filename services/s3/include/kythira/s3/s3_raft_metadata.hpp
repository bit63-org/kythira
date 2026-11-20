// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file s3_raft_metadata.hpp
/// @brief The object index on Raft: `metadata_access` over a `multi_raft`
///        group (.kiro/specs/s3-compatible-storage/ task 16a;
///        Requirements 10.1, 14.2, 14.6, 14.7).
///
/// Every metadata node runs a `multi_raft` host whose index group runs
/// `s3_index_state_machine` on the node's engine (RocksDB in the daemon),
/// so a manifest is committed through Raft (10.1) and the index, the
/// change log and the workers' cursors survive a restart. Until task 18
/// spreads the key space over groups there is one group, over the whole
/// engine, and every metadata node votes in it.
///
///  - **Writes.** `multi_raft` never forwards. A member that leads the
///    group submits the entry; one that does not sends it to the leader it
///    knows (`forwarder::propose`), and the leader submits it and answers
///    what applying it produced. A "not the leader" answer means nothing
///    was submitted, so the member tries again; any other failure (a commit
///    timeout, a lost connection) may have committed, so it throws
///    `metadata_unavailable`, which the pipeline answers with 503 (a client
///    retrying a 503 is what S3 allows for: every entry is idempotent or
///    makes a new version).
///  - **Reads.** Each read first takes a read barrier: the leader runs a
///    read-index round; a follower asks the leader for one
///    (`forwarder::read_index`) and waits until its replica has applied as
///    far. Then it reads its own replica. So every member answers every
///    read at or after every write acknowledged before it (Requirement
///    7.2), and a member cut off from the leader throws
///    `metadata_unavailable` once the timeout passes, never a stale read.
///  - **Change log.** Every replica appends the group's change records to
///    its own segment store as it applies. A replica installing a snapshot
///    fetches the active segment the snapshot names from a peer
///    (`make_change_log_fetcher`, `forwarder::segment`).
///  - **Leadership.** `leads()` gates the leader-side workers
///    (`worker_runner`) and is the leader hint a metadata server's caller
///    may use; any member serves the metadata routes, forwarding as above.
///
/// **Wire between members** (`group_server`, `make_group_forwarder`), on
/// the internal listener, metadata nodes only (`internal_route_rules()`):
///
/// | Request | Answer |
/// |---|---|
/// | `POST /_kythira/s3/group/v1/propose`, the encoded entry | status, index, leader, the result |
/// | `POST /_kythira/s3/group/v1/read_index` | status, index, leader |
/// | `POST /_kythira/s3/group/v1/segment`, stream, first sequence, length | the segment's bytes, or
/// 404 |
///
/// Bodies start with a format byte and use the index's record encoding.
///
/// The multi_raft config builds its state machines with
/// `make_state_machine` and disables automatic split and merge (the index
/// group never moves until task 18).

#include <kythira/s3/s3_index_records.hpp>
#include <kythira/s3/s3_index_state_machine.hpp>
#include <kythira/s3/s3_metadata.hpp>
#include <kythira/s3/s3_roles.hpp>

#include <raft/persistent_state_machine.hpp>
#include <raft/segment_store.hpp>
#include <raft/shard_exceptions.hpp>
#include <raft/shard_types.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::s3 {

/// A leader's answer to a forwarded proposal or read-index round.
template<typename NodeId> struct group_reply {
    enum class status : std::uint8_t {
        ok = 0,
        /// This node does not lead the group: nothing was submitted.
        not_leader = 1,
        /// The request failed and may or may not have taken effect.
        unavailable = 2,
    };
    status result = status::unavailable;
    /// The leader's applied index after the round or the entry's apply.
    std::uint64_t index = 0;
    /// With not_leader: the leader this node knows of, if any.
    std::optional<NodeId> leader;
    /// A proposal's encoded `index_result`.
    std::vector<std::byte> reply;
};

/// How a member reaches another. Each call blocks until it answers; a
/// transport failure answers `unavailable` (or no bytes, for a segment).
template<typename NodeId> struct group_forwarder {
    std::function<group_reply<NodeId>(const NodeId& leader, const std::vector<std::byte>& command)>
        propose;
    std::function<group_reply<NodeId>(const NodeId& leader)> read_index;
    std::function<std::optional<std::vector<std::byte>>(
        const NodeId& peer, const std::string& stream, std::uint64_t first_seq,
        std::uint64_t length)>
        segment;
};

/// A change log fetcher for `s3_index_state_machine::set_change_log`: the
/// segment from the first of `peers` (this node left out) whose bytes
/// match it, installed into `store`; throws when none has it.
template<typename NodeId>
[[nodiscard]] auto make_change_log_fetcher(segment_store* store, std::vector<NodeId> peers,
                                           NodeId self, group_forwarder<NodeId> forward)
    -> std::function<void(const record_segment_descriptor&)> {
    std::erase(peers, self);
    return [store, peers = std::move(peers),
            forward = std::move(forward)](const record_segment_descriptor& d) {
        if (store == nullptr) {
            return;
        }
        if (!forward.segment) {
            throw std::runtime_error("s3 change log: no way to fetch a segment from a peer");
        }
        // fetch_segment names peers by string; here the string is the
        // peer's position in `peers`.
        std::vector<std::string> names;
        names.reserve(peers.size());
        for (std::size_t i = 0; i < peers.size(); ++i) {
            names.push_back(std::to_string(i));
        }
        const auto ok = store->fetch_segment(
            d, names,
            [&](const std::string& peer, const std::string& stream, std::uint64_t first,
                std::uint64_t length) -> std::optional<std::vector<std::byte>> {
                try {
                    return forward.segment(peers.at(std::stoul(peer)), stream, first, length);
                } catch (const std::exception&) {
                    return std::nullopt;
                }
            });
        if (!ok) {
            throw std::runtime_error("s3 change log: no peer has segment " +
                                     std::to_string(d._first_seq) + " of " + d._stream);
        }
    };
}

/// Counters for logs and tests.
struct raft_metadata_stats {
    std::uint64_t proposals_forwarded = 0;
    std::uint64_t read_indexes_forwarded = 0;
    std::uint64_t proposals_served = 0;
    std::uint64_t read_indexes_served = 0;
    std::uint64_t segments_served = 0;
    std::uint64_t unavailable = 0;
};

/// `metadata_access` (and `change_log_access`) over the index group on
/// `Host`, a `multi_raft` whose state machine is
/// `s3_index_state_machine<Engine>`.
template<typename Host> class raft_metadata {
public:
    using host_type = Host;
    using node_id_type = typename Host::node_id_type;
    using descriptor_type = typename Host::descriptor_type;
    using group_id_type = std::remove_cvref_t<decltype(std::declval<descriptor_type>()._group_id)>;
    using reply_type = group_reply<node_id_type>;
    using forwarder = group_forwarder<node_id_type>;

    struct options {
        /// Every metadata node, this one included: the group's voters.
        std::vector<node_id_type> members;
        /// The index group's id on the host (the module's first id).
        group_id_type group{};
        /// The whole budget of one call, forwarding and waiting for a
        /// leader included.
        std::chrono::milliseconds timeout{5000};
        /// Pause between attempts while there is no leader to reach.
        std::chrono::milliseconds retry_interval{20};
        forwarder forward;
        /// This node's change log store (segments served to peers).
        segment_store* change_log = nullptr;
    };

    /// The state machine for the host's `state_machine_factory`. `fetch`
    /// comes from `make_change_log_fetcher`.
    template<typename Engine>
    [[nodiscard]] static auto make_state_machine(
        index_options o, segment_store* change_log,
        std::function<void(const record_segment_descriptor&)> fetch)
        -> s3_index_state_machine<Engine> {
        s3_index_state_machine<Engine> sm(o);
        sm.set_change_log(change_log, std::move(fetch));
        return sm;
    }

    raft_metadata(Host& host, options o) : _host(&host), _opts(std::move(o)) {
        if (_opts.members.empty()) {
            throw std::invalid_argument("s3 raft metadata: needs the group's members");
        }
    }

    raft_metadata(const raft_metadata&) = delete;
    auto operator=(const raft_metadata&) -> raft_metadata& = delete;
    raft_metadata(raft_metadata&&) = delete;
    auto operator=(raft_metadata&&) -> raft_metadata& = delete;
    ~raft_metadata() = default;

    /// Creates the index group here (every member does, at every start;
    /// a restarted member reopens its replica from the engine and log).
    void bootstrap() {
        if (!_host->has_group(_opts.group)) {
            descriptor_type d{};
            d._group_id = _opts.group;
            d._range = shard_range<std::string>{"", std::nullopt};
            d._epoch = shard_epoch{};
            d._voters = _opts.members;
            _host->create_group(d);
        }
    }

    /// Whether this node leads the index group now.
    [[nodiscard]] auto leads() const -> bool {
        const auto* n = _host->group_node(_opts.group);
        return n != nullptr && n->is_leader();
    }

    /// The leader this node knows of, if any.
    [[nodiscard]] auto leader() const -> std::optional<node_id_type> {
        const auto* n = _host->group_node(_opts.group);
        if (n == nullptr) {
            return std::nullopt;
        }
        if (n->is_leader()) {
            return _host->node_id();
        }
        return n->known_leader();
    }

    [[nodiscard]] auto group() const noexcept -> group_id_type { return _opts.group; }

    [[nodiscard]] auto stats() const -> raft_metadata_stats {
        return {_forwarded.load(),       _barriers_forwarded.load(), _served.load(),
                _barriers_served.load(), _segments_served.load(),    _unavailable.load()};
    }

    // ---- metadata_access ------------------------------------------------

    auto propose(const index_command& c) -> index_result {
        return codec::decode_result(submit(codec::encode(c)));
    }

    [[nodiscard]] auto bucket(std::string_view name) const -> std::optional<bucket_descriptor> {
        return read([&](const auto& sm) { return sm.bucket(name); });
    }
    [[nodiscard]] auto list_buckets(std::string_view owner) const
        -> std::vector<bucket_descriptor> {
        return read([&](const auto& sm) { return sm.list_buckets(owner); });
    }
    [[nodiscard]] auto version(std::uint64_t bucket_id, std::string_view key,
                               const std::optional<std::string>& version_id) const
        -> std::optional<object_version> {
        return read([&](const auto& sm) { return sm.version(bucket_id, key, version_id); });
    }
    [[nodiscard]] auto list_objects(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view delimiter, std::string_view marker,
                                    std::size_t max_keys) const -> object_listing {
        return read([&](const auto& sm) {
            return sm.list_objects(bucket_id, prefix, delimiter, marker, max_keys);
        });
    }
    [[nodiscard]] auto list_versions(std::uint64_t bucket_id, std::string_view prefix,
                                     std::string_view delimiter, std::string_view key_marker,
                                     std::string_view version_id_marker, std::size_t max_keys) const
        -> version_listing {
        return read([&](const auto& sm) {
            return sm.list_versions(bucket_id, prefix, delimiter, key_marker, version_id_marker,
                                    max_keys);
        });
    }
    [[nodiscard]] auto upload(std::uint64_t bucket_id, std::string_view key,
                              std::string_view upload_id) const -> std::optional<upload_record> {
        return read([&](const auto& sm) { return sm.upload(bucket_id, key, upload_id); });
    }
    [[nodiscard]] auto list_uploads(std::uint64_t bucket_id, std::string_view prefix,
                                    std::string_view key_marker, std::string_view upload_id_marker,
                                    std::size_t max) const
        -> std::pair<std::vector<upload_record>, bool> {
        return read([&](const auto& sm) {
            return sm.list_uploads(bucket_id, prefix, key_marker, upload_id_marker, max);
        });
    }

    // ---- the workers' reads ---------------------------------------------

    [[nodiscard]] auto refcount(const chunk_sha& sha) const -> std::optional<refcount_record> {
        return read([&](const auto& sm) { return sm.refcount(sha); });
    }
    [[nodiscard]] auto pending_deletions(std::size_t max) const -> std::vector<chunk_sha> {
        return read([&](const auto& sm) { return sm.pending_deletions(max); });
    }
    [[nodiscard]] auto pending_restores(std::size_t max) const -> std::vector<pending_restore> {
        return read([&](const auto& sm) { return sm.pending_restores(max); });
    }
    [[nodiscard]] auto tier_garbage_list(std::size_t max) const -> std::vector<tier_garbage_entry> {
        return read([&](const auto& sm) { return sm.tier_garbage_list(max); });
    }
    [[nodiscard]] auto change_cursor(std::string_view consumer) const -> std::uint64_t {
        return read([&](const auto& sm) { return sm.change_cursor(consumer); });
    }
    [[nodiscard]] auto read_changes(std::uint64_t after, std::size_t max) const
        -> std::vector<sequenced_change> {
        return read([&](const auto& sm) { return sm.read_changes(after, max); });
    }

    /// Calls `f(state_machine)` on this replica with no barrier, for tests
    /// that look underneath; nothing when the group is not open here.
    template<typename F> auto inspect(F&& f) const {
        return _host->with_group_state_machine(
            _opts.group, [&](auto& sm, const descriptor_type&) { return f(std::as_const(sm)); });
    }

    // ---- the leader's side of forwarding ----------------------------------

    /// Submits a member's entry, which this node must lead; never
    /// forwarded again, so a stale hint cannot loop.
    auto serve_propose(const std::vector<std::byte>& command) -> reply_type {
        reply_type out;
        auto* node = _host->group_node(_opts.group);
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        ++_served;
        try {
            auto f = _host->submit_command(_opts.group, shard_epoch{}, command, _opts.timeout);
            out.reply = std::move(f).get();
            out.index = static_cast<std::uint64_t>(node->last_applied_index());
            out.result = reply_type::status::ok;
        } catch (const not_leader_type& e) {
            out.result = reply_type::status::not_leader;
            out.leader = e.leader_hint();
        } catch (const std::exception&) {
            out.result = reply_type::status::unavailable;
        }
        return out;
    }

    /// Runs a read-index round, which this node must lead, and answers the
    /// index applied after it.
    auto serve_read_index() -> reply_type {
        reply_type out;
        auto* node = _host->group_node(_opts.group);
        if (node == nullptr || !node->is_leader()) {
            out.result = reply_type::status::not_leader;
            out.leader = node == nullptr ? std::nullopt : node->known_leader();
            return out;
        }
        ++_barriers_served;
        try {
            std::ignore = node->read_state(_opts.timeout).get();
            out.index = static_cast<std::uint64_t>(node->last_applied_index());
            out.result = reply_type::status::ok;
        } catch (const std::exception&) {
            out.result = node->is_leader() ? reply_type::status::unavailable
                                           : reply_type::status::not_leader;
        }
        return out;
    }

    /// A change log segment's bytes for a peer installing a snapshot.
    [[nodiscard]] auto serve_segment(const std::string& stream, std::uint64_t first_seq,
                                     std::uint64_t length) const
        -> std::optional<std::vector<std::byte>> {
        if (_opts.change_log == nullptr) {
            return std::nullopt;
        }
        auto out = _opts.change_log->read_segment_bytes(stream, first_seq, length);
        if (out) {
            ++_segments_served;
        }
        return out;
    }

private:
    using clock = std::chrono::steady_clock;
    using not_leader_type = shard_not_leader_exception<group_id_type, node_id_type>;

    [[nodiscard]] static auto remaining(clock::time_point deadline) -> std::chrono::milliseconds {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now());
        return std::max(left, std::chrono::milliseconds{1});
    }

    [[noreturn]] void unavailable(const std::string& what) const {
        ++_unavailable;
        throw metadata_unavailable("s3 index group: " + what);
    }

    void pause() const { std::this_thread::sleep_for(_opts.retry_interval); }

    /// The entry's encoded result, applied by the leader.
    auto submit(const std::vector<std::byte>& command) -> std::vector<std::byte> {
        const auto deadline = clock::now() + _opts.timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(_opts.group);
            if (node == nullptr) {
                continue;
            }
            if (node->is_leader()) {
                try {
                    auto f = _host->submit_command(_opts.group, shard_epoch{}, command,
                                                   remaining(deadline));
                    return std::move(f).get();
                } catch (const not_leader_type&) {
                    continue;  // lost it before submitting: nothing went in
                } catch (const std::exception& e) {
                    unavailable(std::string("the entry may or may not have committed: ") +
                                e.what());
                }
            }
            const auto to = node->known_leader();
            if (!to || *to == _host->node_id() || !_opts.forward.propose) {
                continue;
            }
            ++_forwarded;
            auto r = call([&] { return _opts.forward.propose(*to, command); });
            if (r.result == reply_type::status::ok) {
                return std::move(r.reply);
            }
            if (r.result == reply_type::status::unavailable) {
                unavailable("the leader did not answer; the entry may or may not have committed");
            }
        }
        unavailable("no leader answered in time");
    }

    /// Waits until this replica has applied what the group had committed
    /// when called.
    void barrier() const {
        const auto deadline = clock::now() + _opts.timeout;
        for (; clock::now() < deadline; pause()) {
            auto* node = _host->group_node(_opts.group);
            if (node == nullptr) {
                continue;
            }
            if (node->is_leader()) {
                try {
                    std::ignore = node->read_state(remaining(deadline)).get();
                    return;
                } catch (const std::exception&) {
                    if (node->is_leader()) {
                        unavailable("no quorum for a read");
                    }
                    continue;
                }
            }
            const auto to = node->known_leader();
            if (!to || *to == _host->node_id() || !_opts.forward.read_index) {
                continue;
            }
            ++_barriers_forwarded;
            const auto r = call([&] { return _opts.forward.read_index(*to); });
            if (r.result == reply_type::status::unavailable) {
                unavailable("the leader did not answer a read barrier");
            }
            if (r.result == reply_type::status::not_leader) {
                continue;
            }
            wait_applied(r.index, deadline);
            return;
        }
        unavailable("no leader answered a read barrier in time");
    }

    void wait_applied(std::uint64_t index, clock::time_point deadline) const {
        for (;; std::this_thread::sleep_for(std::chrono::milliseconds{1})) {
            auto* n = _host->group_node(_opts.group);
            if (n == nullptr) {
                unavailable("the group closed here");
            }
            if (static_cast<std::uint64_t>(n->last_applied_index()) >= index) {
                return;
            }
            if (clock::now() >= deadline) {
                unavailable("this replica did not catch up in time");
            }
        }
    }

    template<typename F> auto read(F&& f) const {
        barrier();
        auto out = _host->with_group_state_machine(
            _opts.group, [&](auto& sm, const descriptor_type&) { return f(std::as_const(sm)); });
        if (!out) {
            unavailable("the group is not open here");
        }
        return std::move(*out);
    }

    template<typename F> static auto call(F&& f) -> reply_type {
        try {
            return std::forward<F>(f)();
        } catch (const std::exception&) {
            return reply_type{};  // unavailable
        }
    }

    Host* _host;
    options _opts;
    mutable std::atomic<std::uint64_t> _forwarded{0};
    mutable std::atomic<std::uint64_t> _barriers_forwarded{0};
    std::atomic<std::uint64_t> _served{0};
    std::atomic<std::uint64_t> _barriers_served{0};
    mutable std::atomic<std::uint64_t> _segments_served{0};
    mutable std::atomic<std::uint64_t> _unavailable{0};
};

// ---------------------------------------------------------------------------
// The wire between members
// ---------------------------------------------------------------------------

namespace group_wire {

inline constexpr std::uint8_t format = 1;

[[nodiscard]] inline auto to_string(std::span<const std::byte> b) -> std::string {
    return {reinterpret_cast<const char*>(b.data()), b.size()};  // NOLINT
}

[[nodiscard]] inline auto to_bytes(std::string_view s) -> std::vector<std::byte> {
    std::vector<std::byte> out(s.size());
    std::ranges::transform(s, out.begin(), [](char c) { return static_cast<std::byte>(c); });
    return out;
}

[[nodiscard]] inline auto encode_reply(std::uint8_t status, std::uint64_t index,
                                       const std::optional<std::string>& leader,
                                       std::span<const std::byte> reply) -> std::string {
    detail::writer w;
    w.u8(format).u8(status).u64(index).opt_str(leader).str(to_string(reply));
    return w.take();
}

}  // namespace group_wire

/// Serves the group routes on the internal listener.
template<typename Host> class group_server {
public:
    using node_id_type = typename raft_metadata<Host>::node_id_type;

    group_server(raft_metadata<Host>& meta, std::function<std::string(const node_id_type&)> name)
        : _meta(meta), _name(std::move(name)) {}

    [[nodiscard]] static auto owns(std::string_view target) -> bool {
        return target.starts_with(group_route_prefix);
    }

    [[nodiscard]] auto handle(std::string_view method, std::string_view target,
                              std::string_view body) -> std::pair<unsigned, std::string> {
        if (!owns(target)) {
            return {404, "not a group route"};
        }
        auto call = target.substr(group_route_prefix.size());
        call = call.substr(0, call.find('?'));
        if (method != "POST") {
            return {405, "group calls are POST"};
        }
        try {
            detail::reader r(body);
            r.expect_format(group_wire::format, "group request");
            if (call == "propose") {
                const auto command = r.str();
                r.done("propose");
                return {200, answer(_meta.serve_propose(group_wire::to_bytes(command)))};
            }
            if (call == "read_index") {
                r.done("read_index");
                return {200, answer(_meta.serve_read_index())};
            }
            if (call == "segment") {
                const auto stream = r.str();
                const auto first = r.u64();
                const auto length = r.u64();
                r.done("segment");
                auto bytes = _meta.serve_segment(stream, first, length);
                if (!bytes) {
                    return {404, "no such segment here"};
                }
                return {200, group_wire::to_string(*bytes)};
            }
            return {404, "unknown group call " + std::string(call)};
        } catch (const index_format_error& e) {
            return {400, e.what()};
        } catch (const std::exception& e) {
            return {500, e.what()};
        }
    }

private:
    [[nodiscard]] auto answer(const typename raft_metadata<Host>::reply_type& r) const
        -> std::string {
        std::optional<std::string> leader;
        if (r.leader) {
            leader = _name(*r.leader);
        }
        return group_wire::encode_reply(static_cast<std::uint8_t>(r.result), r.index, leader,
                                        r.reply);
    }

    raft_metadata<Host>& _meta;
    std::function<std::string(const node_id_type&)> _name;
};

/// Sends one request to a member: (member, target, body) to the status and
/// body, or nothing when the exchange failed.
template<typename NodeId>
using member_send = std::function<std::optional<std::pair<unsigned, std::string>>(
    const NodeId& to, const std::string& target, const std::string& body)>;

/// The forwarder over the group routes. `parse` reads a leader hint back
/// into a node id (nothing for one it does not know).
template<typename NodeId>
[[nodiscard]] auto make_group_forwarder(
    member_send<NodeId> send, std::function<std::optional<NodeId>(std::string_view)> parse)
    -> group_forwarder<NodeId> {
    using reply = group_reply<NodeId>;
    auto decode = [parse](const std::optional<std::pair<unsigned, std::string>>& res) -> reply {
        reply out;
        if (!res || res->first != 200) {
            return out;  // unavailable
        }
        detail::reader r(res->second);
        r.expect_format(group_wire::format, "group answer");
        const auto status = r.u8();
        if (status > 2) {
            return out;
        }
        out.result = static_cast<typename reply::status>(status);
        out.index = r.u64();
        if (const auto leader = r.opt_str()) {
            out.leader = parse(*leader);
        }
        out.reply = group_wire::to_bytes(r.str());
        r.done("group answer");
        return out;
    };
    auto target = [](std::string_view call) {
        return std::string(group_route_prefix) + std::string(call);
    };
    group_forwarder<NodeId> f;
    f.propose = [send, decode, target](const NodeId& to, const std::vector<std::byte>& command) {
        detail::writer w;
        w.u8(group_wire::format).str(group_wire::to_string(command));
        return decode(send(to, target("propose"), w.take()));
    };
    f.read_index = [send, decode, target](const NodeId& to) {
        detail::writer w;
        w.u8(group_wire::format);
        return decode(send(to, target("read_index"), w.take()));
    };
    f.segment = [send, target](const NodeId& to, const std::string& stream, std::uint64_t first,
                               std::uint64_t length) -> std::optional<std::vector<std::byte>> {
        detail::writer w;
        w.u8(group_wire::format).str(stream).u64(first).u64(length);
        auto res = send(to, target("segment"), w.take());
        if (!res || res->first != 200) {
            return std::nullopt;
        }
        return group_wire::to_bytes(res->second);
    };
    return f;
}

}  // namespace kythira::s3
