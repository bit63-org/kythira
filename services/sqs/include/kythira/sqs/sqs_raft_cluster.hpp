// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_raft_cluster.hpp
/// @brief `queue_cluster` over a `multi_raft` host
///        (`.kiro/specs/sqs-compatible-queues/` task 4).
///
/// - `propose` stamps the entry with this node's clock and submits it to
///   the group owning the key. When this replica is not the leader, the
///   entry goes to the leader through the forwarder (`sqs_forward.hpp`),
///   which stamps it again with the leader's clock; without a leader hint
///   or a forwarder it fails as unavailable and the client retries.
/// - `propose_local` is what the forwarding endpoint calls: it never
///   forwards again, so a leadership change mid-flight cannot bounce an
///   entry around the cluster.
/// - `read` runs on this node's replica of the owning group (a replica
///   read: possibly behind the leader by the entries in flight, which the
///   handlers tolerate: their reads pick partitions and fill attributes,
///   and every decision that races is `apply()`'s).
///
/// The host must outlive this object. `Host` is a `kythira::multi_raft`
/// whose state machine is an `sqs_queue_state_machine`.

#include <kythira/sqs/sqs_catalog.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/shard_exceptions.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kythira::sqs {

template<typename Host> class raft_queue_cluster {
public:
    using node_id_type = typename Host::node_id_type;
    using group_id_type = typename Host::group_id_type;
    using state_machine_type = typename Host::state_machine_type;
    using clock_fn = std::function<std::uint64_t()>;
    /// Sends `entry` for `key` to `leader`; what `apply()` returned there,
    /// or nullopt when the leader could not be reached or did not commit.
    using forwarder = std::function<std::optional<std::vector<std::byte>>(
        const node_id_type& leader, const std::string& key, const std::vector<std::byte>& entry)>;

    raft_queue_cluster(Host& host, forwarder forward,
                       std::chrono::milliseconds timeout = std::chrono::seconds{5},
                       clock_fn clock = system_clock_ms)
        : _host(host), _forward(std::move(forward)), _timeout(timeout), _clock(std::move(clock)) {}

    auto propose(const std::string& key, std::vector<std::byte> entry)
        -> std::optional<std::vector<std::byte>> {
        return submit(key, std::move(entry), true);
    }

    auto propose_local(const std::string& key, std::vector<std::byte> entry)
        -> std::optional<std::vector<std::byte>> {
        return submit(key, std::move(entry), false);
    }

    auto read(const std::string& key, const std::function<void(const state_machine_type&)>& f)
        -> bool {
        const auto d = _host.resolve(key);
        if (!d) {
            return false;
        }
        const auto done =
            _host.with_group_state_machine(d->_group_id, [&f](auto& sm, const auto& /*d*/) {
                f(sm);
                return true;
            });
        return done.value_or(false);
    }

    [[nodiscard]] auto now_ms() -> std::uint64_t { return _clock(); }

    [[nodiscard]] auto forwarded_count() const -> std::uint64_t { return _forwarded; }

    [[nodiscard]] static auto system_clock_ms() -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

private:
    Host& _host;
    forwarder _forward;
    std::chrono::milliseconds _timeout;
    clock_fn _clock;
    std::atomic<std::uint64_t> _forwarded{0};

    auto submit(const std::string& key, std::vector<std::byte> entry, bool may_forward)
        -> std::optional<std::vector<std::byte>> {
        if (!stamp_now(entry, _clock())) {
            return std::nullopt;
        }
        try {
            return _host.submit_command(key, entry, _timeout).get();
        } catch (const shard_not_leader_exception<group_id_type, node_id_type>& e) {
            if (!may_forward || !_forward || !e.leader_hint() ||
                *e.leader_hint() == _host.node_id()) {
                return std::nullopt;
            }
            ++_forwarded;
            return _forward(*e.leader_hint(), key, entry);
        } catch (const std::exception&) {
            // Unrouted key, no local replica, timeout: all "not now" to the
            // client, which retries.
            return std::nullopt;
        }
    }
};

}  // namespace kythira::sqs
