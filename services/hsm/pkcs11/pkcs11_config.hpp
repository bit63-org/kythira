// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// libkythira_pkcs11.so's configuration (.kiro/specs/virtual-hsm/ task 10,
// requirement 5.2): the file KYTHIRA_PKCS11_CONF names. One setting per
// line, `name = value`; `#` starts a comment.
//
//   socket    = /run/kythira/hsm.sock      a node's Unix socket, tried first
//   endpoint  = hsm-1.example:9444         a node's client listener; repeat,
//   endpoint  = hsm-2.example:9444         or list them comma separated
//   cert      = /etc/app/hsm-client.pem    the client certificate chain and
//   key       = /etc/app/hsm-client.key    key (needed for any endpoint)
//   ca        = /etc/app/hsm-ca.pem        the CA the nodes' certificates
//                                          chain to
//   timeout_s = 30                         each read or write on the wire
//
// The library connects to the first of these that answers, and after a
// failure to the next (requirement 5.5).

#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace kythira::hsm::pkcs11lib {

struct endpoint {
    /// A Unix socket path, or empty for TLS to host:port.
    std::string socket_path;
    std::string host;
    std::uint16_t port = 0;

    auto operator==(const endpoint&) const -> bool = default;
};

struct library_config {
    std::vector<endpoint> endpoints;
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    std::uint32_t timeout_s = 30;
};

namespace config_detail {

inline auto trim(std::string_view s) -> std::string_view {
    const auto first = s.find_first_not_of(" \t\r");
    if (first == std::string_view::npos) {
        return {};
    }
    return s.substr(first, s.find_last_not_of(" \t\r") - first + 1);
}

/// host:port or [v6]:port; nothing when it is neither.
inline auto parse_host_port(std::string_view text) -> std::optional<endpoint> {
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size()) {
        return std::nullopt;
    }
    endpoint e;
    std::string_view host = text.substr(0, colon);
    if (host.starts_with('[') && host.ends_with(']')) {
        host = host.substr(1, host.size() - 2);
    }
    const auto port = text.substr(colon + 1);
    if (host.empty() || port.size() > 5 ||
        port.find_first_not_of("0123456789") != std::string_view::npos) {
        return std::nullopt;
    }
    const auto n = std::stoul(std::string(port));
    if (n == 0 || n > 65535) {
        return std::nullopt;
    }
    e.host = std::string(host);
    e.port = static_cast<std::uint16_t>(n);
    return e;
}

}  // namespace config_detail

/// The configuration in `text`, or the first error, naming its line.
/// Sockets come before endpoints, each in the order given.
inline auto parse_config(std::string_view text, std::string* error)
    -> std::optional<library_config> {
    using config_detail::trim;
    library_config c;
    std::vector<endpoint> sockets;
    std::vector<endpoint> tls;
    std::istringstream in{std::string(text)};
    std::string raw;
    int number = 0;
    const auto fail = [&](const std::string& why) -> std::optional<library_config> {
        if (error != nullptr) {
            *error = "line " + std::to_string(number) + ": " + why;
        }
        return std::nullopt;
    };
    while (std::getline(in, raw)) {
        ++number;
        std::string_view line = raw;
        line = trim(line.substr(0, line.find('#')));
        if (line.empty()) {
            continue;
        }
        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            return fail("expected name = value");
        }
        const auto name = trim(line.substr(0, eq));
        const auto value = trim(line.substr(eq + 1));
        if (value.empty()) {
            return fail(std::string(name) + " has no value");
        }
        if (name == "socket") {
            endpoint e;
            e.socket_path = std::string(value);
            sockets.push_back(std::move(e));
        } else if (name == "endpoint") {
            std::string_view rest = value;
            while (!rest.empty()) {
                const auto comma = rest.find(',');
                const auto item = trim(rest.substr(0, comma));
                rest =
                    comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
                if (item.empty()) {
                    continue;
                }
                auto e = config_detail::parse_host_port(item);
                if (!e) {
                    return fail("endpoint " + std::string(item) + " is not host:port");
                }
                tls.push_back(std::move(*e));
            }
        } else if (name == "cert") {
            c.cert_path = std::string(value);
        } else if (name == "key") {
            c.key_path = std::string(value);
        } else if (name == "ca") {
            c.ca_path = std::string(value);
        } else if (name == "timeout_s") {
            if (value.size() > 6 ||
                value.find_first_not_of("0123456789") != std::string_view::npos ||
                std::stoul(std::string(value)) == 0) {
                return fail("timeout_s is a positive number of seconds");
            }
            c.timeout_s = static_cast<std::uint32_t>(std::stoul(std::string(value)));
        } else {
            return fail("unknown setting " + std::string(name));
        }
    }
    if (sockets.empty() && tls.empty()) {
        number = 0;
        return fail("no socket and no endpoint");
    }
    if (!tls.empty() && (c.cert_path.empty() || c.key_path.empty() || c.ca_path.empty())) {
        number = 0;
        return fail("an endpoint needs cert, key and ca");
    }
    c.endpoints = std::move(sockets);
    c.endpoints.insert(c.endpoints.end(), tls.begin(), tls.end());
    return c;
}

/// Reads and parses the file at `path`.
inline auto load_config(const std::string& path, std::string* error)
    -> std::optional<library_config> {
    std::ifstream f(path);
    if (!f) {
        if (error != nullptr) {
            *error = "cannot read " + path;
        }
        return std::nullopt;
    }
    std::ostringstream text;
    text << f.rdbuf();
    return parse_config(text.str(), error);
}

}  // namespace kythira::hsm::pkcs11lib
