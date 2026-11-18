// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file sqs_layers.hpp
/// @brief Which layer may call which internal route
///        (`.kiro/specs/sqs-compatible-queues/` task 10, Requirement 11.4).
///
/// Over TLS a node's certificate may carry a layer identity
/// (`raft/layer_identity.hpp`): `kythira://sqs/<cluster>/<node>?roles=...`.
/// The internal routes are open to these roles:
///
/// | route | called by | open to |
/// |---|---|---|
/// | `/_kythira/sqs/v1/propose` | front ends and followers, on a group's leader | front_end, data |
/// | `/_kythira/sqs/v1/query` | front ends, on a data node | front_end, data |
/// | `/_kythira/sqs/v1/availability` | front ends, on a data node | front_end, data |
/// | `/_kythira/sqs/v1/call` | gateways, on a front end | gateway |
///
/// A caller whose verified certificate names an identity of this cluster
/// is held to its roles: a front end's certificate cannot make a gateway's
/// authenticated call, which names any principal it likes. A caller with no
/// identity (a co-located cluster's certificates that predate identities,
/// or a plaintext development cluster) proves the forwarding secret
/// instead and holds `data` alone over TLS, so it reaches what replicas
/// call each other on and never `/call`. On plaintext the secret opens
/// every route: plaintext is for development, and a split-layer cluster
/// on it has no other way to tell its layers apart.

#include <kythira/sqs/sqs_availability.hpp>
#include <kythira/sqs/sqs_data_access.hpp>
#include <kythira/sqs/sqs_forward.hpp>
#include <kythira/sqs/sqs_gateway.hpp>
#include <kythira/sqs/sqs_listener.hpp>

#include <raft/layer_identity.hpp>

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::sqs {

/// The service part of an SQS node's layer identity.
inline constexpr std::string_view k_identity_service = "sqs";

/// The internal routes and the roles each is open to.
[[nodiscard]] inline auto internal_routes() -> std::vector<layers::route_rule> {
    using layers::role;
    const layers::role_set replicas{role::front_end, role::data};
    return {
        {.path_prefix = std::string(forward::k_path), .allowed = replicas},
        {.path_prefix = std::string(data_wire::k_query_path), .allowed = replicas},
        {.path_prefix = std::string(k_availability_path), .allowed = replicas},
        {.path_prefix = std::string(k_call_path), .allowed = layers::role_set{role::gateway}},
    };
}

/// The guard over this node's internal routes for identities of `cluster`;
/// `forward_secret` (may be empty: none accepted) stands in for an
/// identity as described above.
[[nodiscard]] inline auto internal_route_guard(
    std::string cluster, std::string forward_secret,
    std::function<std::chrono::system_clock::time_point()> clock = [] {
        return std::chrono::system_clock::now();
    }) -> layers::route_guard {
    layers::route_guard_options o;
    o.service = std::string(k_identity_service);
    o.cluster = std::move(cluster);
    o.rules = internal_routes();
    if (!forward_secret.empty()) {
        o.forward_secret = [secret = std::move(forward_secret),
                            clock = std::move(clock)](const https::request& req) {
            const auto header = req[forward::k_header];
            return forward::verify(secret, std::string_view(header.data(), header.size()),
                                   req.body(), clock());
        };
    }
    return layers::route_guard(std::move(o));
}

/// The listener's peer check (`sqs_listener::set_peer_check`) over TLS: the
/// guard's verdict, except that a caller with no identity of this cluster
/// that proves the forwarding secret holds `data`, over TLS as on
/// plaintext.
[[nodiscard]] inline auto identity_peer_check(layers::route_guard guard) -> peer_check_fn {
    return [guard = std::move(guard)](const https::request& req,
                                      const https::request_context& ctx) -> std::string {
        auto v = guard.check(req, ctx);
        if (v.permitted()) {
            return {};
        }
        if (v.kind == layers::verdict_kind::no_identity && ctx.tls) {
            // The guard asks for the secret only on plaintext; ask here.
            const auto& o = guard.options();
            const auto* rule =
                guard.rule_for(std::string_view(req.target().data(), req.target().size()));
            if (rule != nullptr && o.forward_secret && o.forward_secret(req)) {
                if (rule->allowed.has(layers::role::data)) {
                    return {};
                }
                return "the forward secret may not call " + rule->path_prefix + " (needs " +
                       rule->allowed.to_string() + ")";
            }
        }
        return v.reason;
    };
}

}  // namespace kythira::sqs
