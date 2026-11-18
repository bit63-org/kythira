// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_remote_cluster.hpp
/// @brief The data layer seen from a node without the data role, and from
///        one with it (`.kiro/specs/sqs-compatible-queues/` task 10,
///        Requirement 11.2).
///
/// Three `queue_cluster`s, chosen per node and then per call:
///
/// - **local**: `raft_queue_cluster` (or `local_queue_cluster`), the node
///   holds a replica of every group it serves. Co-located nodes use it and
///   serve everything in-process (Requirement 11.6).
/// - **remote**: `remote_queue_cluster`, for a front end without the data
///   role. A proposal goes to a data node's propose endpoint
///   (`sqs_forward.hpp`); a data node that does not lead answers 503
///   without forwarding again, so the remote cluster tries the data nodes
///   in turn, starting from the one that last accepted, which is the
///   leader until leadership moves. A query (`POST /_kythira/sqs/v1/query`)
///   goes the same way: only the leader answers it (a follower's replica
///   may not yet hold a write the caller just made), so a front end reads
///   its own writes.
///   It holds no replica, so `read` answers false and the leader-side
///   workers never run over it.
/// - **hybrid**: `hybrid_queue_cluster`, what `sqs_node` gives its
///   handlers whatever the roles: each call runs locally when this node
///   holds the key's group and goes to the data layer when it does not, so
///   a node that holds some groups serves the rest too. Without a remote
///   side it is the local cluster; without a local side, the remote one.
///
/// Calls are authenticated as forwarding is: the HMAC header under the
/// cluster's forwarding secret, or (over TLS) the caller's layer identity,
/// which the data node's route guard checks (`sqs_layers.hpp`). The
/// transport is a function so tests run the remote cluster against an
/// in-process handler.

#include <kythira/sqs/sqs_data_access.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_queue_state_machine.hpp>

#include <raft/memory_kv_engine.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

/// One internal POST: base URL, path, extra headers, body to status and
/// body, or nullopt when the exchange failed.
using data_transport = std::function<std::optional<std::pair<unsigned, std::string>>(
    const std::string& base_url, const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers, std::string body)>;

/// `queue_cluster` over the data nodes' internal endpoints.
class remote_queue_cluster {
public:
    /// Names the state machine for `queue_cluster`'s `read` signature only:
    /// a remote cluster holds none.
    using state_machine_type = sqs_queue_state_machine<memory_kv_engine>;
    using clock_fn = std::function<std::uint64_t()>;
    using wall_clock_fn = std::function<std::chrono::system_clock::time_point()>;

    /// @param data_endpoints Base URLs of the data nodes' SQS listeners.
    /// @param forward_secret Signs every call; empty when the transport
    ///        authenticates with a client certificate instead.
    remote_queue_cluster(
        std::vector<std::string> data_endpoints, std::string forward_secret,
        data_transport transport, clock_fn clock = system_clock_ms,
        wall_clock_fn wall = [] { return std::chrono::system_clock::now(); })
        : _endpoints(std::move(data_endpoints)),
          _secret(std::move(forward_secret)),
          _transport(std::move(transport)),
          _clock(std::move(clock)),
          _wall(std::move(wall)) {
        if (_endpoints.empty()) {
            throw std::invalid_argument("remote_queue_cluster: no data endpoints");
        }
    }

    auto propose(const std::string& key, std::vector<std::byte> entry)
        -> std::optional<std::vector<std::byte>> {
        const auto body = forward::encode_body(forward::proposal{key, std::move(entry)});
        auto answer = call(std::string(forward::k_path), body, _leader);
        if (!answer) {
            return std::nullopt;
        }
        std::vector<std::byte> out;
        out.reserve(answer->size());
        for (const char c : *answer) {
            out.push_back(static_cast<std::byte>(c));
        }
        return out;
    }

    auto query(const data_query& q) -> std::optional<data_answer> {
        const auto answer = call(std::string(data_wire::k_query_path), encode_query(q), _leader);
        if (!answer) {
            return std::nullopt;
        }
        return decode_answer(*answer);
    }

    /// No replica here.
    auto read(const std::string& /*key*/,
              const std::function<void(const state_machine_type&)>& /*f*/) -> bool {
        return false;
    }

    [[nodiscard]] auto now_ms() -> std::uint64_t { return _clock(); }

    [[nodiscard]] auto endpoints() const -> std::vector<std::string> {
        const std::lock_guard lock(_endpoints_mutex);
        return _endpoints;
    }

    /// Adds a data node (an evacuation's target, `sqs_evacuate.hpp`); one
    /// already known is left alone. Safe while calls run.
    void add_endpoint(const std::string& url) {
        const std::lock_guard lock(_endpoints_mutex);
        if (std::find(_endpoints.begin(), _endpoints.end(), url) == _endpoints.end()) {
            _endpoints.push_back(url);
        }
    }

    [[nodiscard]] static auto system_clock_ms() -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    }

private:
    mutable std::mutex _endpoints_mutex;
    std::vector<std::string> _endpoints;
    std::string _secret;
    data_transport _transport;
    clock_fn _clock;
    wall_clock_fn _wall;
    /// The data node that last accepted a call: where the next one starts.
    std::atomic<std::size_t> _leader{0};

    /// POSTs `body` to `path` on each data node in turn from `start`; the
    /// first 200's body. A 503 (not leader, not committed) or a failed
    /// exchange moves on; anything else is final, as every node would
    /// refuse the same call.
    auto call(const std::string& path, const std::string& body, std::atomic<std::size_t>& start)
        -> std::optional<std::string> {
        std::vector<std::pair<std::string, std::string>> headers;
        if (!_secret.empty()) {
            headers.emplace_back(std::string(forward::k_header),
                                 forward::sign(_secret, body, _wall()));
        }
        const auto endpoints = this->endpoints();
        const auto first = start.load() % endpoints.size();
        for (std::size_t i = 0; i < endpoints.size(); ++i) {
            const auto at = (first + i) % endpoints.size();
            const auto r = _transport(endpoints[at], path, headers, body);
            if (!r || r->first == 503) {
                continue;
            }
            if (r->first != 200) {
                return std::nullopt;
            }
            start.store(at);
            return r->second;
        }
        return std::nullopt;
    }
};

/// The cluster a node's handlers use, whatever its roles: each call runs on
/// this node's replica when it holds the key's group, on the data layer
/// when it does not. Either side may be absent: a co-located node with no
/// remote side serves everything in-process (Requirement 11.6), and a front
/// end without the data role has no local side.
template<typename Local> class hybrid_queue_cluster {
public:
    using state_machine_type = typename Local::state_machine_type;

    /// @param local This node's replicas; nullptr without the data role.
    /// @param remote The data layer; nullptr when this node holds every
    ///        group it is asked about.
    /// @param holds Whether this node holds a replica of the group owning a
    ///        key (a `multi_raft` host's `resolve`, say); ignored without
    ///        `local`.
    hybrid_queue_cluster(Local* local, remote_queue_cluster* remote,
                         std::function<bool(const std::string&)> holds)
        : _local(local), _remote(remote), _holds(std::move(holds)) {
        if (_local == nullptr && _remote == nullptr) {
            throw std::invalid_argument("hybrid_queue_cluster: neither a local nor a remote side");
        }
    }

    auto propose(const std::string& key, std::vector<std::byte> entry)
        -> std::optional<std::vector<std::byte>> {
        if (here(key)) {
            return _local->propose(key, std::move(entry));
        }
        return _remote != nullptr ? _remote->propose(key, std::move(entry)) : std::nullopt;
    }

    auto query(const data_query& q) -> std::optional<data_answer> {
        if (here(query_key(q))) {
            if (auto a = _local->query(q)) {
                return a;
            }
        }
        return _remote != nullptr ? _remote->query(q) : std::nullopt;
    }

    auto read(const std::string& key, const std::function<void(const state_machine_type&)>& f)
        -> bool {
        return _local != nullptr && _local->read(key, f);
    }

    [[nodiscard]] auto now_ms() -> std::uint64_t {
        return _local != nullptr ? _local->now_ms() : _remote->now_ms();
    }

private:
    Local* _local;
    remote_queue_cluster* _remote;
    std::function<bool(const std::string&)> _holds;

    [[nodiscard]] auto here(const std::string& key) const -> bool {
        return _local != nullptr && (_remote == nullptr || _holds(key));
    }
};

}  // namespace kythira::sqs
