// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file layer_identity_uri.hpp
/// @brief A layer identity URI and how to find one in a certificate, without
///        the HTTPS server, certificate authority or TLS material source that
///        `layer_identity.hpp` brings (.kiro/specs/kinesis-independent-layers/
///        Requirement 7; redis-general-data-types Requirement 19).
///
/// ```
/// kythira://<service>/<cluster>/<node id>?roles=<role>,<role>...
/// ```
///
/// A service whose internal link is not HTTP (the Redis forward link speaks
/// RESP) reads its callers' identities with this header alone; the route
/// guard and certificate issuing stay in `layer_identity.hpp`, which
/// includes this one.

#include <raft/layer_roles.hpp>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::layers {

/// The URI scheme of a layer identity.
inline constexpr std::string_view identity_scheme = "kythira://";

/// Whether `part` may be a service, cluster or node id in the SAN URI:
/// 1..128 of RFC 3986's unreserved characters, so nothing needs escaping and
/// no part can carry a '/', '?' or '&' into the next.
[[nodiscard]] constexpr auto valid_identity_part(std::string_view part) noexcept -> bool {
    if (part.empty() || part.size() > 128) {
        return false;
    }
    return std::ranges::all_of(part, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_' || c == '~';
    });
}

/// A node's identity to the other layers of one service in one cluster.
struct identity {
    std::string service;
    std::string cluster;
    std::string node_id;
    role_set roles;

    /// The SAN URI. Throws `std::invalid_argument` when a part is not a
    /// `valid_identity_part` or the role set is empty (a node with no role
    /// has nothing to call or serve).
    [[nodiscard]] auto to_uri() const -> std::string {
        for (const auto& [what, part] :
             {std::pair<std::string_view, std::string_view>{"service", service},
              {"cluster", cluster},
              {"node id", node_id}}) {
            if (!valid_identity_part(part)) {
                throw std::invalid_argument(
                    "layer identity: the " + std::string(what) + " \"" + std::string(part) +
                    "\" must be 1-128 letters, digits, '-', '.', '_' or '~'");
            }
        }
        if (roles.empty()) {
            throw std::invalid_argument("layer identity: needs at least one role");
        }
        std::string out(identity_scheme);
        out += service;
        out += '/';
        out += cluster;
        out += '/';
        out += node_id;
        out += "?roles=";
        out += roles.to_string();
        return out;
    }

    /// Parses a SAN URI written by `to_uri`. `nullopt` for any other URI,
    /// including one with an unknown role or extra query parameters: a
    /// certificate whose identity this node cannot read in full grants
    /// nothing.
    [[nodiscard]] static auto parse_uri(std::string_view uri) -> std::optional<identity> {
        if (!uri.starts_with(identity_scheme)) {
            return std::nullopt;
        }
        uri.remove_prefix(identity_scheme.size());
        const auto q = uri.find('?');
        if (q == std::string_view::npos) {
            return std::nullopt;
        }
        const auto path = uri.substr(0, q);
        const auto query = uri.substr(q + 1);
        constexpr std::string_view roles_key = "roles=";
        if (!query.starts_with(roles_key) || query.find('&') != std::string_view::npos) {
            return std::nullopt;
        }
        const auto s1 = path.find('/');
        if (s1 == std::string_view::npos) {
            return std::nullopt;
        }
        const auto s2 = path.find('/', s1 + 1);
        if (s2 == std::string_view::npos || path.find('/', s2 + 1) != std::string_view::npos) {
            return std::nullopt;
        }
        identity out;
        out.service = std::string(path.substr(0, s1));
        out.cluster = std::string(path.substr(s1 + 1, s2 - s1 - 1));
        out.node_id = std::string(path.substr(s2 + 1));
        if (!valid_identity_part(out.service) || !valid_identity_part(out.cluster) ||
            !valid_identity_part(out.node_id)) {
            return std::nullopt;
        }
        try {
            out.roles = role_set::parse(query.substr(roles_key.size()));
        } catch (const std::invalid_argument&) {
            return std::nullopt;
        }
        if (out.roles.empty()) {
            return std::nullopt;
        }
        return out;
    }

    friend auto operator==(const identity&, const identity&) -> bool = default;
};

/// The one identity of `service` and `cluster` among `uris`. `nullopt` when
/// there is none, or more than one: a certificate naming two identities of
/// the same cluster is ambiguous and grants nothing.
[[nodiscard]] inline auto find_identity(const std::vector<std::string>& uris,
                                        std::string_view service, std::string_view cluster)
    -> std::optional<identity> {
    std::optional<identity> found;
    for (const auto& u : uris) {
        auto id = identity::parse_uri(u);
        if (!id || id->service != service || id->cluster != cluster) {
            continue;
        }
        if (found) {
            return std::nullopt;
        }
        found = std::move(id);
    }
    return found;
}

/// The URI SANs of `cert`; empty for null or none.
[[nodiscard]] inline auto certificate_uri_sans(X509* cert) -> std::vector<std::string> {
    std::vector<std::string> out;
    if (cert == nullptr) {
        return out;
    }
    auto* names =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr) {
        return out;
    }
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        if (gn->type != GEN_URI) {
            continue;
        }
        const ASN1_STRING* text = gn->d.uniformResourceIdentifier;
        out.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(text)),
                         static_cast<std::size_t>(ASN1_STRING_length(text)));
    }
    GENERAL_NAMES_free(names);
    return out;
}

/// The identity of `service` and `cluster` in the first certificate of a PEM
/// chain, if exactly one is there.
[[nodiscard]] inline auto identity_in_pem(std::string_view chain_pem, std::string_view service,
                                          std::string_view cluster) -> std::optional<identity> {
    BIO* bio = BIO_new_mem_buf(chain_pem.data(), static_cast<int>(chain_pem.size()));
    if (bio == nullptr) {
        return std::nullopt;
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (cert == nullptr) {
        return std::nullopt;
    }
    auto id = find_identity(certificate_uri_sans(cert), service, cluster);
    X509_free(cert);
    return id;
}

}  // namespace kythira::layers
