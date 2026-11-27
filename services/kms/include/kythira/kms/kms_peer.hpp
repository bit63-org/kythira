// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// How a KMS member reaches the catalog's leader over the network
// (.kiro/specs/kms-compatible-api/ task 12): kms_host's forwarder, carried
// as two HTTPS requests on the module's API listener, the same listener
// AWS clients use.
//
//   POST /v1/kms/peer/propose      body: the catalog command
//   POST /v1/kms/peer/read-index   body: empty
//
// Both answer 200 with an encoded forward_reply (status, applied index,
// the known leader's id as text, the catalog's reply), 403 to a caller
// that is not a member, 400 to a malformed request. AWS clients never
// reach these paths: the KMS API is POST / with an X-Amz-Target header.
//
// A proposal can change any key's metadata, so only the other members may
// send one: the listener asks for (but does not require) client
// certificates, and serve_peer() answers only a verified certificate
// whose URI or DNS SAN is one of the members' identities. The client
// presents this node's certificate and checks that the leader's chains to
// the members' CA and names the host dialled. Plaintext is for tests only
// and must be asked for on both sides. The virtual HSM forwards the same
// way (services/hsm/include/kythira/hsm/hsm_peer.hpp).

#include <kythira/kms/kms_codec.hpp>
#include <kythira/kms/kms_host.hpp>

#include <raft/layer_identity_uri.hpp>
#include <raft/layer_roles.hpp>
#include <raft/mtls_https_client.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::kms {

inline constexpr std::string_view peer_propose_path = "/v1/kms/peer/propose";
inline constexpr std::string_view peer_read_index_path = "/v1/kms/peer/read-index";

/// A forward_reply on the wire, with the leader's id as text.
[[nodiscard]] inline auto encode_forward_reply(const forward_reply<std::string>& r) -> std::string {
    byte_writer w;
    w.u8(1).u8(static_cast<std::uint8_t>(r.result)).u64(r.index).boolean(r.leader.has_value());
    w.str(r.leader.value_or(std::string()));
    w.u32(static_cast<std::uint32_t>(r.reply.size()));
    for (const auto b : r.reply) {
        w.u8(static_cast<std::uint8_t>(b));
    }
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
        const bool has_leader = r.boolean();
        auto leader = r.str();
        if (has_leader) {
            out.leader = std::move(leader);
        }
        const auto n = r.u32();
        if (n > body.size()) {
            return reply{};
        }
        out.reply.resize(n);
        for (auto& b : out.reply) {
            b = std::byte{r.u8()};
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

/// Who may call a node's internal routes: the peer, catalog and front-end
/// APIs.
///
/// Two kinds of caller are known (.kiro/specs/kms-independent-layers/
/// Requirement 9). A certificate carrying a KMS layer identity of this
/// cluster (`kythira://kms/<cluster>/<node id>?roles=...`,
/// raft/layer_identity.hpp) is held to its roles, route by route: the
/// peer API takes `data`, the catalog API `front_end` and `data`, the
/// front-end call `gateway`. A certificate with no such identity whose
/// SAN is listed in `identities` (KYTHIRA_KMS_PEER_IDENTITIES) is a
/// member trusted as every layer, as before layer identities existed, so
/// a deployment that lists its nodes keeps working; listing a layer
/// identity's URI never widens what its roles allow.
struct peer_policy {
    /// The members' certificate identities (a URI or DNS SAN each).
    std::set<std::string> identities;
    /// Accept peer requests on a plaintext listener (tests only).
    bool allow_plaintext = false;
    /// The cluster named in this KMS's layer identities.
    std::string cluster = "default";
};

/// What the listener knows of a caller: the verified certificate's SANs.
struct peer_caller {
    bool tls = false;
    bool verified = false;
    std::vector<std::string> uri_sans;
    std::vector<std::string> dns_sans;
};

/// The routes each layer may call (Requirement 9.2).
inline constexpr kythira::layers::role_set peer_route_roles{kythira::layers::role::data};
inline constexpr kythira::layers::role_set catalog_route_roles{kythira::layers::role::front_end,
                                                               kythira::layers::role::data};
inline constexpr kythira::layers::role_set front_end_call_roles{kythira::layers::role::gateway};
inline constexpr kythira::layers::role_set front_end_health_roles{kythira::layers::role::gateway,
                                                                  kythira::layers::role::front_end};

/// Whether `caller` may call a route open to `allowed` under `policy`.
[[nodiscard]] inline auto admits(const peer_policy& policy, const peer_caller& caller,
                                 kythira::layers::role_set allowed) -> bool {
    if (!caller.tls) {
        return policy.allow_plaintext;
    }
    if (!caller.verified) {
        return false;
    }
    if (const auto id = kythira::layers::find_identity(caller.uri_sans, "kms", policy.cluster)) {
        return id->roles.intersects(allowed);
    }
    for (const auto* sans : {&caller.uri_sans, &caller.dns_sans}) {
        for (const auto& san : *sans) {
            if (policy.identities.contains(san)) {
                return true;
            }
        }
    }
    return false;
}

/// Whether `caller` is a data-layer member under `policy`: who may use
/// the peer routes.
[[nodiscard]] inline auto is_member(const peer_policy& policy, const peer_caller& caller) -> bool {
    return admits(policy, caller, peer_route_roles);
}

/// An answer to a peer request: the HTTP status and body.
struct peer_answer {
    unsigned status = 0;
    std::string body;
};

/// Whether `target` (path, optionally with a query) is a peer path.
[[nodiscard]] inline auto is_peer_path(std::string_view target) -> bool {
    return target.starts_with("/v1/kms/peer/");
}

/// Answers a peer request on `host`, or nothing when `target` is not a
/// peer path. `to_text` writes the host's node ids.
template<typename KmsHost, typename ToText>
[[nodiscard]] auto serve_peer(KmsHost& host, const peer_policy& policy, const peer_caller& caller,
                              std::string_view method, std::string_view target,
                              std::string_view body, ToText&& to_text)
    -> std::optional<peer_answer> {
    if (!is_peer_path(target)) {
        return std::nullopt;
    }
    if (!is_member(policy, caller)) {
        return peer_answer{403, "not a member"};
    }
    if (method != "POST" || (target != peer_propose_path && target != peer_read_index_path)) {
        return peer_answer{400, "malformed peer request"};
    }
    if (target == peer_propose_path) {
        std::vector<std::byte> cmd(body.size());
        for (std::size_t i = 0; i < body.size(); ++i) {
            cmd[i] = static_cast<std::byte>(body[i]);
        }
        return peer_answer{200, encode_forward_reply(to_wire(host.serve_propose(cmd),
                                                             std::forward<ToText>(to_text)))};
    }
    return peer_answer{
        200, encode_forward_reply(to_wire(host.serve_read_index(), std::forward<ToText>(to_text)))};
}

/// One blocking request per call to another member's listener. Every
/// failure answers `unavailable`: the caller does not know whether a
/// proposal took effect.
class peer_client {
public:
    explicit peer_client(kythira::mtls::client_config config) : _client(std::move(config)) {}

    /// Forward `command` to the member at `base_url` ("https://host:port").
    [[nodiscard]] auto propose(std::string_view base_url,
                               const std::vector<std::byte>& command) const
        -> forward_reply<std::string> {
        std::string body(command.size(), '\0');
        for (std::size_t i = 0; i < command.size(); ++i) {
            body[i] = static_cast<char>(command[i]);
        }
        return post(base_url, std::string(peer_propose_path), std::move(body));
    }

    [[nodiscard]] auto read_index(std::string_view base_url) const -> forward_reply<std::string> {
        return post(base_url, std::string(peer_read_index_path), {});
    }

private:
    [[nodiscard]] auto post(std::string_view base_url, const std::string& target,
                            std::string body) const -> forward_reply<std::string> {
        const auto res = _client.request("POST", base_url, target, std::move(body),
                                         "application/octet-stream", "kythira-kms-peer");
        if (!res || res->first != 200) {
            return {};
        }
        return decode_forward_reply(res->second);
    }

    kythira::mtls::client _client;
};

}  // namespace kythira::kms
