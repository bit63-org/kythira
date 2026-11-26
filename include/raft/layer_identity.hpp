// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file layer_identity.hpp
/// @brief Who a node is to the other layers of a service, and which internal
///        routes each layer may call (.kiro/specs/kinesis-independent-layers/
///        task 3, design "Authentication between layers", Requirement 7).
///
/// A service whose layers can run on separate nodes (gateway, front end,
/// data, segment store) authenticates every call between them with mutual
/// TLS. The node's certificate carries a *layer identity* as a URI SAN:
///
/// ```
/// kythira://<service>/<cluster>/<node id>?roles=<role>,<role>...
/// ```
///
/// for example `kythira://kinesis/prod-east/7?roles=front_end,data`. Kythira's
/// certificate authority issues it (`add_layer_identity` puts the URI into
/// the `csr_signing_options` an `issuing_tls_material_source` sends), or the
/// operator supplies a certificate that holds it.
///
/// A server checks callers with a `layer_route_guard`: each internal route
/// prefix names the roles that may call it, and the guard refuses a call
/// whose verified client certificate names no identity of this service and
/// cluster, names roles outside the route's set, or has been revoked. A path
/// matched by no rule is not an internal route and passes untouched, so the
/// guard can sit in front of a listener that also serves the public API.
///
/// Co-located clusters that run without TLS keep today's HMAC forward
/// secret: a caller that proves it (the `forward_secret` hook) on a
/// plaintext connection is treated as holding the `data` role and nothing
/// else, so it reaches what data nodes call each other on and no route that
/// needs another layer's identity (Requirement 7.4).
///
/// Certificates rotate without restart through the Beast server's
/// `tls_source` (`beast_https_server.hpp`): each publish builds a new TLS
/// context for the next handshake. An expired certificate fails OpenSSL's
/// verification at the handshake; a revoked one is refused by the guard's
/// `revoked` hook on its next request (Requirement 7.5).
///
/// Nothing here knows about Kinesis: the service is a name, and the four
/// roles (`layer_roles.hpp`) are the layers the independent-layers specs
/// share (DynamoDB, KMS and HSM reuse this header).

#include <raft/beast_https_server.hpp>
#include <raft/certificate_authority.hpp>
#include <raft/layer_identity_uri.hpp>
#include <raft/layer_roles.hpp>
#include <raft/tls_material_source.hpp>

#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::layers {

/// Adds `id`'s SAN URI to the options a CSR is signed with, and asks for a
/// certificate usable on both sides of a connection: a node is a server to
/// the layer above it and a client of the layer below.
inline void add_layer_identity(::raft::testing::csr_signing_options& options, const identity& id) {
    options.uri_names.push_back(id.to_uri());
    options.server_auth = true;
    options.client_auth = true;
}

/// The identity in the leaf of a PEM chain (a node's own material, or a
/// server certificate a client was shown). `nullopt` if the chain does not
/// parse or names no single identity of `service` and `cluster`.
[[nodiscard]] inline auto identity_of_certificate(const std::string& chain_pem,
                                                  std::string_view service,
                                                  std::string_view cluster)
    -> std::optional<identity> {
    auto cert = tls_material_detail::read_certificate(chain_pem);
    if (!cert) {
        return std::nullopt;
    }
    return find_identity(https::detail::uri_sans(cert.get()), service, cluster);
}

/// The identity this node presents, from its current TLS material.
[[nodiscard]] inline auto identity_of(const tls_material& m, std::string_view service,
                                      std::string_view cluster) -> std::optional<identity> {
    if (m.certificate_chain_pem.empty()) {
        return std::nullopt;
    }
    return identity_of_certificate(m.certificate_chain_pem, service, cluster);
}

/// One internal route: requests whose path starts with `path_prefix` may be
/// made only by a caller holding at least one of `allowed`.
struct route_rule {
    std::string path_prefix;
    role_set allowed;
};

struct route_guard_options {
    std::string service;
    std::string cluster;
    /// The internal routes. The longest matching prefix decides; a path no
    /// rule matches is not internal and passes.
    std::vector<route_rule> rules;
    /// The co-located HMAC forward secret check: true when `req` carries a
    /// valid proof. Asked only for a plaintext request with no verified
    /// identity; a caller that passes it holds `data` alone. Empty means
    /// no forward secret is accepted.
    std::function<bool(const https::request& req)> forward_secret;
    /// True when the certificate with this serial (lower-case hex, as the
    /// server reports it) has been revoked. Empty means none has.
    std::function<bool(std::string_view serial_hex)> revoked;
};

/// Why a request was let through or refused.
enum class verdict_kind : std::uint8_t {
    /// No rule matched: not an internal route.
    not_internal,
    /// A verified identity with an allowed role.
    allowed,
    /// The forward secret, on a route open to `data`.
    allowed_forward_secret,
    /// No verified identity of this service and cluster, and no accepted
    /// forward secret.
    no_identity,
    /// An identity, but none of its roles may call the route.
    wrong_role,
    /// The certificate has been revoked.
    revoked,
};

struct verdict {
    verdict_kind kind = verdict_kind::not_internal;
    /// The caller, when it presented an identity of this cluster.
    std::optional<identity> caller;
    /// What the caller holds (the identity's roles, or `data` for the
    /// forward secret).
    role_set roles;
    /// For a refusal: a reason safe to send back.
    std::string reason;

    [[nodiscard]] auto permitted() const noexcept -> bool {
        return kind == verdict_kind::not_internal || kind == verdict_kind::allowed ||
               kind == verdict_kind::allowed_forward_secret;
    }
};

/// Checks callers of a server's internal routes against their layer
/// identities. Thread-safe: `check` only reads.
class route_guard {
public:
    explicit route_guard(route_guard_options options) : _options(std::move(options)) {
        if (!valid_identity_part(_options.service) || !valid_identity_part(_options.cluster)) {
            throw std::invalid_argument("route_guard: service and cluster must be valid parts");
        }
        for (const auto& r : _options.rules) {
            if (r.path_prefix.empty() || r.path_prefix.front() != '/') {
                throw std::invalid_argument("route_guard: a rule's prefix must start with '/'");
            }
            if (r.allowed.empty()) {
                throw std::invalid_argument("route_guard: rule \"" + r.path_prefix +
                                            "\" allows no role");
            }
        }
    }

    [[nodiscard]] auto options() const noexcept -> const route_guard_options& { return _options; }

    /// The rule that governs `target` (its path, query ignored), if any.
    [[nodiscard]] auto rule_for(std::string_view target) const -> const route_rule* {
        const auto path = target.substr(0, target.find('?'));
        const route_rule* best = nullptr;
        for (const auto& r : _options.rules) {
            if (path.starts_with(r.path_prefix) &&
                (best == nullptr || r.path_prefix.size() > best->path_prefix.size())) {
                best = &r;
            }
        }
        return best;
    }

    [[nodiscard]] auto check(const https::request& req, const https::request_context& ctx) const
        -> verdict {
        verdict v;
        const auto* rule = rule_for(std::string_view(req.target().data(), req.target().size()));
        if (rule == nullptr) {
            return v;
        }
        if (ctx.client_verified) {
            v.caller = find_identity(ctx.client_uri_sans, _options.service, _options.cluster);
        }
        if (v.caller) {
            if (_options.revoked && _options.revoked(ctx.client_serial_hex)) {
                v.kind = verdict_kind::revoked;
                v.reason = "the caller's certificate has been revoked";
                return v;
            }
            v.roles = v.caller->roles;
            if (v.roles.intersects(rule->allowed)) {
                v.kind = verdict_kind::allowed;
            } else {
                v.kind = verdict_kind::wrong_role;
                v.reason = "role " + v.roles.to_string() + " may not call " + rule->path_prefix +
                           " (needs " + rule->allowed.to_string() + ")";
            }
            return v;
        }
        if (!ctx.tls && _options.forward_secret && _options.forward_secret(req)) {
            v.roles = role_set{role::data};
            if (rule->allowed.has(role::data)) {
                v.kind = verdict_kind::allowed_forward_secret;
            } else {
                v.kind = verdict_kind::wrong_role;
                v.reason = "the forward secret may not call " + rule->path_prefix + " (needs " +
                           rule->allowed.to_string() + ")";
            }
            return v;
        }
        v.kind = verdict_kind::no_identity;
        v.reason = "no layer identity of " + _options.service + "/" + _options.cluster;
        return v;
    }

    /// `next` behind a copy of this guard: a refused call gets a 403 with
    /// the reason and never reaches `next`.
    [[nodiscard]] auto wrap(https::handler next) const -> https::handler {
        return [guard = *this, next = std::move(next)](const https::request& req,
                                                       const https::request_context& ctx) {
            auto v = guard.check(req, ctx);
            if (!v.permitted()) {
                auto res = https::detail::plain_reply(403, v.reason + "\n");
                res.version(req.version());
                res.keep_alive(req.keep_alive());
                return res;
            }
            return next(req, ctx);
        };
    }

private:
    route_guard_options _options;
};

}  // namespace kythira::layers
