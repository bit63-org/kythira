// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file hsm_roles.hpp
/// @brief The virtual HSM's layers on one node: `KYTHIRA_HSM_ROLES`, what
///        each set may run, and the start-time check
///        (.kiro/specs/hsm-independent-layers/ task 1, Requirements 1.1 and
///        2.1-2.5).
///
/// A node runs a non-empty subset of three roles:
///
/// | HSM role   | runs                                                    |
/// |------------|---------------------------------------------------------|
/// | `endpoint` | the L4 relay (`endpoint_relay.hpp`) in front of crypto   |
/// | `crypto`   | wire server, session layer, key vault, unseal, shares    |
/// | `store`    | the catalog and token Raft groups: ciphertext only       |
///
/// Unset, a node runs all three, exactly as before (Requirement 1.1).
///
/// The set is a `kythira::layers::role_set`, so layer identities
/// (`layer_identity.hpp`) and `/healthz` carry it like every other
/// service's. The shared core has four role bits; the HSM's three names map
/// onto them by position in the stack: `endpoint` is `gateway`, `crypto` is
/// `front_end`, `store` is `data`. `segments` is never set on an HSM node.
/// So an HSM crypto node's certificate reads
/// `kythira://hsm/<cluster>/<node>?roles=front_end`, and `hsm_role_names`
/// prints it back as `crypto` for operators.

#include <raft/layer_roles.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kythira::hsm {

using kythira::layers::role;
using kythira::layers::role_set;

/// The shared role bit each HSM role uses.
inline constexpr role endpoint_role = role::gateway;
inline constexpr role crypto_role = role::front_end;
inline constexpr role store_role = role::data;

/// The service name in an HSM node's layer identity.
inline constexpr std::string_view hsm_layer_service = "hsm";

/// Every HSM role: what a co-located node runs.
[[nodiscard]] constexpr auto all_hsm_roles() noexcept -> role_set {
    return role_set{endpoint_role, crypto_role, store_role};
}

/// The HSM name of a shared role bit; empty for `segments`.
[[nodiscard]] constexpr auto hsm_role_name(role r) noexcept -> std::string_view {
    switch (r) {
        case role::gateway:
            return "endpoint";
        case role::front_end:
            return "crypto";
        case role::data:
            return "store";
        case role::segments:
            return "";
    }
    return "";
}

/// "endpoint,crypto,store" order, HSM names; empty for the empty set.
[[nodiscard]] inline auto hsm_role_names(role_set roles) -> std::string {
    std::string out;
    for (const auto r : {endpoint_role, crypto_role, store_role}) {
        if (roles.has(r)) {
            if (!out.empty()) {
                out.push_back(',');
            }
            out.append(hsm_role_name(r));
        }
    }
    return out;
}

/// Parses `KYTHIRA_HSM_ROLES`: `,`-separated HSM role names, blanks
/// ignored. Throws `std::invalid_argument` naming an unknown or repeated
/// role, or a value that names none.
[[nodiscard]] inline auto parse_hsm_roles(std::string_view text) -> role_set {
    role_set out;
    std::string name;
    const auto take = [&] {
        if (name.empty()) {
            throw std::invalid_argument(
                "KYTHIRA_HSM_ROLES has an empty element (expected endpoint, crypto or store)");
        }
        std::optional<role> r;
        for (const auto candidate : {endpoint_role, crypto_role, store_role}) {
            if (hsm_role_name(candidate) == name) {
                r = candidate;
            }
        }
        if (!r) {
            throw std::invalid_argument("KYTHIRA_HSM_ROLES: unknown role \"" + name +
                                        "\" (expected endpoint, crypto or store)");
        }
        if (out.has(*r)) {
            throw std::invalid_argument("KYTHIRA_HSM_ROLES: role \"" + name + "\" is listed twice");
        }
        out.add(*r);
        name.clear();
    };
    bool any = false;
    for (const char ch : text) {
        if (ch == ' ' || ch == '\t') {
            continue;
        }
        any = true;
        if (ch == ',') {
            take();
        } else {
            name.push_back(ch);
        }
    }
    if (!any) {
        throw std::invalid_argument(
            "KYTHIRA_HSM_ROLES is set but names no role (endpoint, crypto, store; unset runs "
            "all three)");
    }
    take();
    return out;
}

/// What each layer may run on a node with `roles` (Requirement 2.2-2.4).
/// The module asks these rather than testing bits, so the rules live here.
struct hsm_role_plan {
    role_set roles = all_hsm_roles();

    /// A key vault, operator and node unseal, a share and the share routes,
    /// and the wire listeners (Requirement 2.2).
    [[nodiscard]] constexpr auto runs_crypto() const noexcept -> bool {
        return roles.has(crypto_role);
    }
    /// Membership of the HSM's groups, the engine and the Raft log
    /// (Requirement 2.3).
    [[nodiscard]] constexpr auto runs_store() const noexcept -> bool {
        return roles.has(store_role);
    }
    /// The crypto layer reads through `remote_hsm_store` because this node
    /// holds no replica.
    [[nodiscard]] constexpr auto uses_remote_store() const noexcept -> bool {
        return runs_crypto() && !runs_store();
    }
    /// The client listeners relay to crypto nodes and answer nothing here
    /// (Requirement 2.4). A node with both `endpoint` and `crypto` serves
    /// its clients itself, as a co-located node does today.
    [[nodiscard]] constexpr auto relays_clients() const noexcept -> bool {
        return roles.has(endpoint_role) && !runs_crypto();
    }
    [[nodiscard]] constexpr auto co_located() const noexcept -> bool {
        return roles == all_hsm_roles();
    }
};

/// The settings the start-time check looks at, filled from the node's
/// configuration.
struct hsm_role_inputs {
    role_set roles = all_hsm_roles();
    /// Store members' peer URLs a crypto-only node reads through
    /// (KYTHIRA_HSM_API_URLS, which lists the groups' members).
    bool has_store_urls = false;
    /// Crypto nodes an endpoint-only node relays to.
    bool has_relay_backends = false;
    /// A peer listener with client certificates: what crypto and store
    /// nodes on different hosts talk over.
    bool has_peer_tls = false;
    /// The node holds this cluster's Raft peers (it would join the groups).
    bool has_raft_peers = false;
};

/// Why `in.roles` cannot run with these settings, or `nullopt`
/// (Requirement 2.5). The node stops at start with the text.
[[nodiscard]] inline auto check_hsm_roles(const hsm_role_inputs& in) -> std::optional<std::string> {
    if (in.roles.empty()) {
        return std::string("KYTHIRA_HSM_ROLES names no role");
    }
    if (in.roles.has(role::segments)) {
        return std::string("KYTHIRA_HSM_ROLES: the HSM has no segments layer");
    }
    const hsm_role_plan plan{in.roles};
    if (plan.co_located()) {
        return std::nullopt;
    }
    const auto named = "KYTHIRA_HSM_ROLES=" + hsm_role_names(in.roles) + ": ";
    if (plan.uses_remote_store()) {
        if (!in.has_store_urls) {
            return named +
                   "a crypto node without the store role reads through the store members; "
                   "list them in KYTHIRA_HSM_API_URLS";
        }
        if (!in.has_peer_tls) {
            return named +
                   "a crypto node reaches store members over mutual TLS; set the peer "
                   "certificate and CA";
        }
    }
    if (plan.relays_clients() && !in.has_relay_backends) {
        return named +
               "an endpoint without the crypto role relays to crypto nodes; set "
               "KYTHIRA_HSM_RELAY_BACKENDS";
    }
    if (plan.runs_store() && !in.has_raft_peers) {
        return named + "a store node is a member of the HSM's groups; set KYTHIRA_PEERS";
    }
    if (plan.runs_store() && !plan.runs_crypto() && !in.has_peer_tls) {
        return named +
               "a store node apart from crypto serves the store API over mutual TLS; set the "
               "peer certificate and CA";
    }
    return std::nullopt;
}

}  // namespace kythira::hsm
