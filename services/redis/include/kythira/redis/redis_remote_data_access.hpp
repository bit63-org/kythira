// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file redis_remote_data_access.hpp
/// @brief The data layer from a node that holds no replica of a key's group
///        (.kiro/specs/redis-general-data-types/ Requirement 18.4, design
///        Component 9 "Membership and routing", task 16).
///
/// `redis_remote_data_access` is the other half of `redis_data_access.hpp`:
/// the same data-layer operations, made as `KYTHIRA.DATA` calls
/// (redis_data_wire.hpp) to data nodes over the forward link. It keeps the
/// shared route cache (`include/raft/route_cache.hpp`): routes are fetched
/// from any data node with `KYTHIRA.DATA ROUTES`, a write goes to the
/// route's leader hint first and then the other voters, and each refusal
/// corrects the cache (not leader with a hint, a stale epoch with the
/// current route, an unknown group, an unreachable node).
///
/// Data nodes are named by `host:port` addresses, which the cache resolves
/// with `net_resolve` when it uses them; the seeds come from
/// `KYTHIRA_REDIS_DATA_NODES` or the layer membership group, never static
/// IPs.
///
/// Proposals raise what the host's `submit_command` raises
/// (`key_locked_exception`, `unrouted_key_exception`,
/// `shard_not_leader_exception`), so the caller handles a local and a
/// remote proposal the same way.

#include <kythira/redis/redis_data_wire.hpp>
#include <kythira/redis/resp_protocol.hpp>
#include <raft/route_cache.hpp>
#include <raft/shard_exceptions.hpp>
#include <raft/txn_envelope.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace kythira {

/// One RESP reply from a peer, as far as the data-layer API needs: a bulk
/// string's bytes, or why there is none.
struct redis_peer_answer {
    enum class kind : std::uint8_t {
        bulk,
        /// An error reply; `text` is its message without the `-`.
        error,
        /// Anything else, or a reply that could not be parsed.
        other,
    };
    kind _kind = kind::other;
    std::string _text;
};

/// Parses one complete RESP2 reply for the data-layer API.
[[nodiscard]] inline auto parse_redis_peer_answer(std::string_view reply) -> redis_peer_answer {
    const auto crlf = reply.find("\r\n");
    if (reply.empty() || crlf == std::string_view::npos) {
        return {};
    }
    if (reply[0] == '-') {
        return {redis_peer_answer::kind::error, std::string(reply.substr(1, crlf - 1))};
    }
    if (reply[0] == '$') {
        std::size_t n = 0;
        const auto* first = reply.data() + 1;
        const auto* last = reply.data() + crlf;
        if (std::from_chars(first, last, n).ec != std::errc{} || reply.size() < crlf + 2 + n + 2) {
            return {};
        }
        return {redis_peer_answer::kind::bulk, std::string(reply.substr(crlf + 2, n))};
    }
    return {};
}

template<typename GroupId, typename NodeId> class redis_remote_data_access {
public:
    using cache_type = route_cache<GroupId, std::string, NodeId>;
    using route_type = typename cache_type::descriptor_type;
    using routes_payload = redis_data_wire::routes_payload<GroupId, NodeId>;

    /// Sends `argv` to the node listening at `address` (`host:port`) over
    /// the forward link and returns its whole RESP reply; `nullopt` when it
    /// could not be reached in time.
    using call_fn = std::function<std::optional<std::string>(const std::string& address,
                                                             const std::vector<std::string>& argv)>;

    struct options {
        /// How long a proposal keeps trying other targets and refreshing
        /// routes before it gives up.
        std::chrono::milliseconds timeout{5000};
        /// Pause between rounds when every target refused.
        std::chrono::milliseconds retry_pause{10};
        route_cache_options cache{};
    };

    /// @param seeds Data-node addresses to ask for routes when no known node
    ///        answers (`KYTHIRA_REDIS_DATA_NODES`).
    redis_remote_data_access(std::vector<std::string> seeds, call_fn call, options opts = {})
        : _call(std::move(call)),
          _opts(opts),
          _cache(
              std::move(seeds),
              [this](const std::string& address, const shard_range<std::string>& range) {
                  return fetch_routes(address, range);
              },
              opts.cache) {}

    redis_remote_data_access(const redis_remote_data_access&) = delete;
    auto operator=(const redis_remote_data_access&) -> redis_remote_data_access& = delete;
    redis_remote_data_access(redis_remote_data_access&&) = delete;
    auto operator=(redis_remote_data_access&&) -> redis_remote_data_access& = delete;
    ~redis_remote_data_access() = default;

    // ── routing (KYTHIRA.DATA ROUTE/ROUTES) ─────────────────────────────────

    /// The route of `key`, from the cache or, when it has none, from any data
    /// node. `nullopt` when no data node answered.
    [[nodiscard]] auto route(const std::string& key) -> std::optional<route_type> {
        return _cache.ensure(key);
    }
    [[nodiscard]] auto group_of(const std::string& key) -> std::optional<GroupId> {
        if (auto r = route(key)) {
            return r->_group_id;
        }
        return std::nullopt;
    }
    /// The node a command for `key` goes to first: the route's leader hint,
    /// else its first voter that is not suspect.
    [[nodiscard]] auto leader_of(const std::string& key) -> std::optional<NodeId> {
        if (!route(key)) {
            return std::nullopt;
        }
        auto targets = _cache.write_targets(key);
        if (targets.empty()) {
            return std::nullopt;
        }
        return targets.front();
    }
    [[nodiscard]] auto cache() noexcept -> cache_type& { return _cache; }

    // ── proposals (KYTHIRA.DATA PROPOSE) ────────────────────────────────────

    /// Proposes `entry`, whose routing key is `key`, to the group's leader
    /// and returns the state machine's result bytes.
    ///
    /// Each data node either applies it or refuses it; a refusal is never
    /// forwarded again (Requirement 18.3), so this call makes the hops: to
    /// the leader hint, then the other voters, learning from every refusal,
    /// and refreshing routes when the cache has none, until `timeout`.
    ///
    /// @throws key_locked_exception<std::string> a transaction holds the key
    /// @throws unrouted_key_exception<std::string> no group owns the key
    /// @throws shard_not_leader_exception no data node took it in time
    /// @throws std::runtime_error the proposal timed out on the data node
    ///         (it may still commit) or the data node failed it
    auto propose(const std::string& key, const std::vector<std::byte>& entry,
                 std::chrono::milliseconds timeout) -> std::vector<std::byte> {
        const auto deadline = std::chrono::steady_clock::now() + std::min(timeout, _opts.timeout);
        const std::string entry_text(reinterpret_cast<const char*>(entry.data()), entry.size());
        std::optional<GroupId> last_group;
        for (;;) {
            if (auto r = _cache.ensure(key)) {
                last_group = r->_group_id;
                if (auto result = propose_round(key, *r, entry_text, timeout)) {
                    return std::move(*result);
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                throw shard_not_leader_exception<GroupId, NodeId>(last_group.value_or(GroupId{}),
                                                                  std::nullopt);
            }
            std::this_thread::sleep_for(_opts.retry_pause);
        }
    }

private:
    /// One pass over `r`'s write targets. The result bytes when one applied
    /// the entry; `nullopt` to go round again (the cache has learned
    /// something, or nobody answered).
    auto propose_round(const std::string& key, const route_type& r, const std::string& entry,
                       std::chrono::milliseconds timeout) -> std::optional<std::vector<std::byte>> {
        const std::vector<std::string> argv{"KYTHIRA.DATA",
                                            "PROPOSE",
                                            std::to_string(static_cast<std::uint64_t>(r._group_id)),
                                            std::to_string(r._epoch._version),
                                            std::to_string(r._epoch._conf_version),
                                            entry};
        (void)timeout;  // the data node applies its own command timeout
        for (const auto& target : _cache.write_targets(key)) {
            const auto address = _cache.address_of(target);
            if (!address) {
                continue;
            }
            const auto reply = _call(*address, argv);
            if (!reply) {
                _cache.on_connection_failure(target);
                continue;
            }
            const auto answer = parse_redis_peer_answer(*reply);
            if (answer._kind != redis_peer_answer::kind::bulk) {
                // A node that does not speak the data-layer API (an old
                // build) or refused the call: try another.
                _cache.on_connection_failure(target);
                continue;
            }
            auto outcome = redis_data_wire::decode_propose<GroupId, NodeId>(answer._text);
            if (!outcome) {
                _cache.on_connection_failure(target);
                continue;
            }
            using status = redis_data_wire::propose_status;
            switch (outcome->status) {
                case status::ok: {
                    std::vector<std::byte> out(outcome->payload.size());
                    std::transform(outcome->payload.begin(), outcome->payload.end(), out.begin(),
                                   [](char c) { return static_cast<std::byte>(c); });
                    return out;
                }
                case status::not_leader:
                    _cache.on_not_leader(r._group_id, outcome->leader);
                    if (outcome->leader && *outcome->leader != target) {
                        return std::nullopt;  // the hint goes first next round
                    }
                    continue;
                case status::stale_route:
                    learn(outcome->routes);
                    return std::nullopt;
                case status::unknown_group:
                    _cache.on_unknown_group(r._group_id);
                    return std::nullopt;
                case status::key_locked:
                    throw key_locked_exception<std::string>(outcome->locked_key, outcome->holder,
                                                            outcome->primary);
                case status::unrouted:
                    throw unrouted_key_exception<std::string>(key);
                case status::timeout:
                    throw std::runtime_error("redis data layer: the proposal timed out on node " +
                                             *address + "; it may still commit");
                case status::failed:
                    throw std::runtime_error("redis data layer: node " + *address +
                                             " failed the proposal: " + outcome->payload);
            }
        }
        return std::nullopt;
    }

    void learn(const routes_payload& routes) {
        typename cache_type::routes_reply reply;
        reply.routes = routes.routes;
        reply.addresses = routes.addresses;
        for (const auto& d : routes.routes) {
            _cache.on_stale_epoch(d);
        }
        (void)_cache.learn(reply);
    }

    auto fetch_routes(const std::string& address, const shard_range<std::string>& range)
        -> std::optional<typename cache_type::routes_reply> {
        const auto reply =
            _call(address, {"KYTHIRA.DATA", "ROUTES", redis_data_wire::encode_range(range)});
        if (!reply) {
            return std::nullopt;
        }
        const auto answer = parse_redis_peer_answer(*reply);
        if (answer._kind != redis_peer_answer::kind::bulk) {
            return std::nullopt;
        }
        auto routes = redis_data_wire::decode_routes<GroupId, NodeId>(answer._text);
        if (!routes) {
            return std::nullopt;
        }
        typename cache_type::routes_reply out;
        out.routes = std::move(routes->routes);
        out.addresses = std::move(routes->addresses);
        return out;
    }

    call_fn _call;
    options _opts;
    cache_type _cache;
};

}  // namespace kythira
