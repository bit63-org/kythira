// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// How an HSM member reaches the leader of a group over the network
// (.kiro/specs/virtual-hsm/ task 6d): hsm_host's forwarder, carried as two
// HTTPS requests on the module's API listener.
//
//   POST /v1/peer/propose/<local group>      body: the command
//   POST /v1/peer/read-index/<local group>   body: empty
//   POST /v1/peer/store-read/<local group>   body: a store_read_request
//
// The first two answer 200 with an encoded forward_reply (status, applied
// index, the known leader's id as text, the state machine's reply); the
// third, the store API for crypto nodes outside the groups
// (store_api.hpp), answers an encoded store_read_answer. All answer 403
// to a caller that is neither a member nor a store client, 400 to a
// malformed request.
//
// Store clients (.kiro/specs/hsm-independent-layers/ Requirement 7.2) are
// the crypto nodes that are not members: they may propose and read, as a
// member's session layer does, but are not members, so the share routes
// (node_unseal.hpp) stay closed to them.
//
// A peer's proposal can change any token (a PIN, an object), so only the
// other members may send one: the listener asks for client certificates,
// and serve() answers only a verified certificate whose URI or DNS SAN is
// one of the members' identities. The client presents this node's
// certificate and checks that the leader's chains to the members' CA and
// names the host dialled. Plaintext is for tests only and must be asked
// for on both sides.

#include <kythira/hsm/codec.hpp>
#include <kythira/hsm/hsm_host.hpp>
#include <kythira/hsm/mtls_client.hpp>
#include <kythira/hsm/store_api.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/ssl.h>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kythira::hsm {

inline constexpr std::string_view peer_propose_path = "/v1/peer/propose/";
inline constexpr std::string_view peer_read_index_path = "/v1/peer/read-index/";

/// A forward_reply on the wire, with the leader's id as text.
[[nodiscard]] inline auto encode_forward_reply(const forward_reply<std::string>& r) -> std::string {
    byte_writer w;
    w.u8(1).u8(static_cast<std::uint8_t>(r.result)).u64(r.index).u8(r.leader ? 1 : 0);
    w.str(r.leader.value_or(std::string()));
    const auto* p = reinterpret_cast<const std::uint8_t*>(r.reply.data());
    w.bytes(std::span<const std::uint8_t>(p, r.reply.size()));
    return w.take_string();
}

/// The reply in `body`; `unavailable` when it does not decode.
[[nodiscard]] inline auto decode_forward_reply(std::string_view body)
    -> forward_reply<std::string> {
    using reply = forward_reply<std::string>;
    reply out;
    try {
        byte_reader r(body);
        if (r.u8() != 1) {
            return reply{};
        }
        const auto status = r.u8();
        if (status > static_cast<std::uint8_t>(reply::status::unavailable)) {
            return reply{};
        }
        out.result = static_cast<reply::status>(status);
        out.index = r.u64();
        const bool has_leader = r.u8() != 0;
        auto leader = r.str();
        if (has_leader) {
            out.leader = std::move(leader);
        }
        const auto bytes = r.bytes();
        out.reply.resize(bytes.size());
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            out.reply[i] = std::byte{bytes[i]};
        }
        r.finish();
    } catch (const std::exception&) {
        return reply{};
    }
    return out;
}

/// `reply` with its leader written by `to_text`.
template<typename NodeId, typename ToText>
[[nodiscard]] auto to_wire(const forward_reply<NodeId>& reply, ToText&& to_text)
    -> forward_reply<std::string> {
    forward_reply<std::string> out;
    out.result = static_cast<typename forward_reply<std::string>::status>(reply.result);
    out.index = reply.index;
    out.reply = reply.reply;
    if (reply.leader) {
        out.leader = std::forward<ToText>(to_text)(*reply.leader);
    }
    return out;
}

/// `reply` with its leader read by `from_text` (nothing when it does not
/// parse: the member then waits for its own view of the leader).
template<typename NodeId, typename FromText>
[[nodiscard]] auto from_wire(const forward_reply<std::string>& reply, FromText&& from_text)
    -> forward_reply<NodeId> {
    forward_reply<NodeId> out;
    out.result = static_cast<typename forward_reply<NodeId>::status>(reply.result);
    out.index = reply.index;
    out.reply = reply.reply;
    if (reply.leader) {
        out.leader = std::forward<FromText>(from_text)(*reply.leader);
    }
    return out;
}

/// The local group id at the end of `target` after `prefix`.
[[nodiscard]] inline auto peer_group_of(std::string_view target, std::string_view prefix)
    -> std::optional<std::uint64_t> {
    if (!target.starts_with(prefix)) {
        return std::nullopt;
    }
    const auto digits = target.substr(prefix.size());
    std::uint64_t g = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), g);
    if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size()) {
        return std::nullopt;
    }
    return g;
}

/// Who may send peer requests.
/// The node-mode share routes (task 8, served by node_unseal.hpp).
inline constexpr std::string_view peer_share_route = "/v1/peer/share";
inline constexpr std::string_view peer_share_request_route = "/v1/peer/share-request";
/// A crypto node's seal state, for endpoint relays' health checks
/// (hsm-independent-layers Requirement 6.2): GET answers "unsealed" or
/// "sealed".
inline constexpr std::string_view peer_health_route = "/v1/peer/health";

struct peer_policy {
    /// The members' certificate identities (a URI or DNS SAN each).
    std::set<std::string> identities;
    /// Accept peer requests on a plaintext listener (tests only).
    bool allow_plaintext = false;
    /// Crypto nodes outside the groups that may use the store API
    /// (propose, read-index, store-read) but nothing else. Last, so the
    /// existing aggregate initializers keep their meaning.
    std::set<std::string> store_clients;
};

/// What the listener knows of a caller: the verified certificate's SANs.
struct peer_caller {
    bool tls = false;
    bool verified = false;
    std::vector<std::string> uri_sans;
    std::vector<std::string> dns_sans;
};

/// Whether `caller` presents one of `identities` under `policy`.
[[nodiscard]] inline auto presents_one_of(const peer_policy& policy,
                                          const std::set<std::string>& identities,
                                          const peer_caller& caller) -> bool {
    if (!caller.tls) {
        return policy.allow_plaintext;
    }
    if (!caller.verified) {
        return false;
    }
    for (const auto* sans : {&caller.uri_sans, &caller.dns_sans}) {
        for (const auto& san : *sans) {
            if (identities.contains(san)) {
                return true;
            }
        }
    }
    return false;
}

/// Whether `caller` is a member under `policy`.
[[nodiscard]] inline auto is_member(const peer_policy& policy, const peer_caller& caller) -> bool {
    return presents_one_of(policy, policy.identities, caller);
}

/// Whether `caller` may use the store API: a member or a store client.
[[nodiscard]] inline auto may_use_store(const peer_policy& policy, const peer_caller& caller)
    -> bool {
    return is_member(policy, caller) || presents_one_of(policy, policy.store_clients, caller);
}

/// An answer to a peer request: the HTTP status and body.
struct peer_answer {
    unsigned status = 0;
    std::string body;
};

/// The health route on a crypto node; nothing for other targets. Any
/// caller with a verified certificate from the cluster's CA may ask (or
/// anyone on a plaintext listener the policy allows): whether a node is
/// sealed is no secret, since a sealed node answers every PKCS#11 call
/// CKR_DEVICE_ERROR anyway, and the relay asking is no member.
[[nodiscard]] inline auto serve_health_peer(const peer_policy& policy, const peer_caller& caller,
                                            std::string_view method, std::string_view target,
                                            bool sealed) -> std::optional<peer_answer> {
    if (target != peer_health_route) {
        return std::nullopt;
    }
    if (caller.tls ? !caller.verified : !policy.allow_plaintext) {
        return peer_answer{403, "a verified client certificate is required"};
    }
    if (method != "GET") {
        return peer_answer{405, "GET only"};
    }
    return peer_answer{200, sealed ? "sealed" : "unsealed"};
}

/// Answers a peer request on `host`, or nothing when `target` is not a
/// peer path. `to_text` writes the host's node ids.
template<typename HsmHost, typename ToText>
[[nodiscard]] auto serve_peer(HsmHost& host, const peer_policy& policy, const peer_caller& caller,
                              std::string_view method, std::string_view target,
                              std::string_view body, ToText&& to_text)
    -> std::optional<peer_answer> {
    const bool propose = target.starts_with(peer_propose_path);
    const bool store_read = target.starts_with(peer_store_read_path);
    if (!propose && !store_read && !target.starts_with(peer_read_index_path)) {
        return std::nullopt;
    }
    if (!may_use_store(policy, caller)) {
        return peer_answer{403, "not a member"};
    }
    const auto prefix = propose      ? peer_propose_path
                        : store_read ? peer_store_read_path
                                     : peer_read_index_path;
    const auto group = peer_group_of(target, prefix);
    if (method != "POST" || !group) {
        return peer_answer{400, "malformed peer request"};
    }
    if (store_read) {
        const auto request = store_read_request::decode(body);
        if (!request) {
            return peer_answer{400, "malformed store read"};
        }
        return peer_answer{200, encode_store_read_answer(serve_store_read(host, *group, *request))};
    }
    if (propose) {
        std::vector<std::byte> cmd(body.size());
        for (std::size_t i = 0; i < body.size(); ++i) {
            cmd[i] = static_cast<std::byte>(body[i]);
        }
        return peer_answer{200, encode_forward_reply(to_wire(host.serve_propose(*group, cmd),
                                                             std::forward<ToText>(to_text)))};
    }
    return peer_answer{200, encode_forward_reply(to_wire(host.serve_read_index(*group),
                                                         std::forward<ToText>(to_text)))};
}

/// One blocking request per call to another member's listener. Every
/// failure answers `unavailable`: the caller does not know whether a
/// proposal took effect.
class peer_client {
public:
    explicit peer_client(peer_client_config config) : _client(std::move(config)) {}
    /// Forward `command` to local group `group` on the member at `base_url`
    /// ("https://host:port").
    [[nodiscard]] auto propose(std::string_view base_url, std::uint64_t group,
                               const std::vector<std::byte>& command) const
        -> forward_reply<std::string> {
        std::string body(command.size(), '\0');
        for (std::size_t i = 0; i < command.size(); ++i) {
            body[i] = static_cast<char>(command[i]);
        }
        return post(base_url, std::string(peer_propose_path) + std::to_string(group),
                    std::move(body));
    }

    [[nodiscard]] auto read_index(std::string_view base_url, std::uint64_t group) const
        -> forward_reply<std::string> {
        return post(base_url, std::string(peer_read_index_path) + std::to_string(group), {});
    }

    /// A store read of local group `group` on the store member at
    /// `base_url` (store_api.hpp): the encoded answer, or nothing when the
    /// member is unreachable or refuses.
    [[nodiscard]] auto store_read(std::string_view base_url, std::uint64_t group,
                                  std::string request) const -> std::optional<std::string> {
        auto res = _client.request(
            "POST", base_url, std::string(peer_store_read_path) + std::to_string(group),
            std::move(request), "application/octet-stream", "kythira-hsm-peer");
        if (!res || res->first != 200) {
            return std::nullopt;
        }
        return std::move(res->second);
    }

    /// Whether the crypto node at `base_url` is unsealed: nothing when it
    /// does not answer the health route.
    [[nodiscard]] auto unsealed(std::string_view base_url) const -> std::optional<bool> {
        const auto res = _client.request("GET", base_url, std::string(peer_health_route), {},
                                         "text/plain", "kythira-hsm-relay");
        if (!res || res->first != 200) {
            return std::nullopt;
        }
        return res->second == "unsealed";
    }

    /// Hands a node-mode share (binary form) to the member at `base_url`
    /// (task 8); true once it is stored there.
    [[nodiscard]] auto deliver_share(std::string_view base_url, std::string share) const -> bool {
        const auto res =
            _client.request("POST", base_url, std::string(peer_share_route), std::move(share),
                            "application/octet-stream", "kythira-hsm-peer");
        return res && res->first == 200;
    }

    /// The member's share of the key with check value `check` (binary
    /// form), or nothing when it is unreachable, refuses or holds none.
    [[nodiscard]] auto request_share(std::string_view base_url,
                                     std::span<const std::uint8_t, 8> check) const
        -> std::optional<std::string> {
        auto res = _client.request("POST", base_url, std::string(peer_share_request_route),
                                   std::string(check.begin(), check.end()),
                                   "application/octet-stream", "kythira-hsm-peer");
        if (!res || res->first != 200) {
            return std::nullopt;
        }
        return std::move(res->second);
    }

private:
    [[nodiscard]] auto post(std::string_view base_url, const std::string& target,
                            std::string body) const -> forward_reply<std::string> {
        const auto res = _client.request("POST", base_url, target, std::move(body),
                                         "application/octet-stream", "kythira-hsm-peer");
        if (!res || res->first != 200) {
            return {};
        }
        try {
            return decode_forward_reply(res->second);
        } catch (const std::exception&) {
            return {};
        }
    }

    mtls_client _client;
};

}  // namespace kythira::hsm
