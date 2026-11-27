// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file forward_link.hpp
/// @brief How one `dynamodb_gateway_node` hands a `raft_backend` op to
///        another (`.kiro/specs/dynamodb-compatible-api/` task 7).
///
/// `raft_backend` runs an op on the node that leads its group, and reaches
/// that node through a forwarder. Between gateways the forwarder is an HTTP
/// POST of the op's bytes to the peer gateway's own listener at
/// `k_forward_path`; the answer is the response body.
///
/// Peers authenticate with a shared secret: the request carries the time in
/// milliseconds and `hex(HMAC-SHA256(secret, time "\n" body))`, and the
/// receiver refuses a missing or wrong MAC, or a time more than
/// `k_forward_skew` from its own clock, so a captured request cannot be
/// replayed later. The link uses TLS whenever the gateways do; the MAC
/// guards the endpoint either way, so it is never open to SDK clients.

#include <raft/bounded_resolver.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <vector>
#include <utility>

namespace kythira::dynamodb {

/// Where peers send ops.
inline constexpr std::string_view k_forward_path = "/_kythira/dynamodb/forward";
/// Where strong voters send ops for the strong host's groups (task 27),
/// which may come from another region; signed with the strong secret.
inline constexpr std::string_view k_strong_forward_path = "/_kythira/dynamodb/strong-forward";
inline constexpr std::string_view k_forward_time_header = "X-Kythira-Forward-Time";
inline constexpr std::string_view k_forward_mac_header = "X-Kythira-Forward-Mac";
/// How far a request's time may be from the receiver's clock.
inline constexpr std::chrono::milliseconds k_forward_skew{60000};
/// The shortest secret the gateway accepts.
inline constexpr std::size_t k_min_forward_secret = 16;

/// `hex(HMAC-SHA256(secret, time "\n" body))`.
[[nodiscard]] inline auto forward_mac(std::string_view secret, std::uint64_t time_ms,
                                      std::string_view body) -> std::string {
    std::string message = std::to_string(time_ms);
    message.push_back('\n');
    message.append(body);
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(message.data()),  // NOLINT
         message.size(), mac.data(), &len);
    static constexpr std::string_view k_hex = "0123456789abcdef";
    std::string out;
    out.reserve(std::size_t{len} * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(k_hex[mac[i] >> 4U]);
        out.push_back(k_hex[mac[i] & 0x0FU]);
    }
    return out;
}

/// Whether a forwarded request's time and MAC are good at `now_ms`.
[[nodiscard]] inline auto forward_authentic(std::string_view secret, std::string_view time_text,
                                            std::string_view mac, std::string_view body,
                                            std::uint64_t now_ms) -> bool {
    if (secret.empty() || time_text.empty() || time_text.size() > 20) {
        return false;
    }
    std::uint64_t t = 0;
    for (const char c : time_text) {
        if (c < '0' || c > '9') {
            return false;
        }
        t = t * 10 + static_cast<std::uint64_t>(c - '0');
    }
    const auto skew = static_cast<std::uint64_t>(k_forward_skew.count());
    if ((t > now_ms ? t - now_ms : now_ms - t) > skew) {
        return false;
    }
    const auto want = forward_mac(secret, t, body);
    return want.size() == mac.size() && CRYPTO_memcmp(want.data(), mac.data(), want.size()) == 0;
}

/// A peer gateway's listener.
struct forward_peer {
    std::string host;
    std::uint16_t port = 0;
};

struct forward_client_config {
    std::string secret;
    /// Speak HTTPS to peers (whenever the gateways serve HTTPS).
    bool tls = true;
    /// PEM bundle peers' certificates chain to; empty uses the system's.
    std::string ca_path;
    std::chrono::milliseconds timeout{20000};
    /// The peers' endpoint: `k_forward_path`, or `k_strong_forward_path`
    /// for the strong host.
    std::string path{k_forward_path};
};

/// Sends ops to peer gateways, one connection per op. Thread-safe: it holds
/// no connection between calls.
class forward_client {
public:
    /// `peers` maps a node id's text to its gateway.
    forward_client(forward_client_config config, std::map<std::string, forward_peer> peers)
        : _config(std::move(config)), _peers(std::move(peers)) {}

    /// The peer's answer, or nothing when it cannot be reached or refuses.
    [[nodiscard]] auto send(const std::string& node, const std::string& op) const
        -> std::optional<std::string> {
        const auto it = _peers.find(node);
        if (it == _peers.end()) {
            return std::nullopt;
        }
        return send_to(it->second, op);
    }

    /// The same, to a gateway named by address rather than by node id (a
    /// front end without the data role, which knows data nodes only by the
    /// addresses their routes name).
    [[nodiscard]] auto send_to(const forward_peer& peer, const std::string& op) const
        -> std::optional<std::string> {
        try {
            return _config.tls ? exchange_tls(peer, op) : exchange_plain(peer, op);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

private:
    using request = boost::beast::http::request<boost::beast::http::string_body>;
    using response = boost::beast::http::response<boost::beast::http::string_body>;

    [[nodiscard]] auto make_request(const forward_peer& peer, const std::string& op) const
        -> request {
        namespace http = boost::beast::http;
        const auto now =
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count());
        request req{http::verb::post, _config.path, 11};
        req.set(http::field::host, peer.host + ":" + std::to_string(peer.port));
        req.set(http::field::content_type, "application/octet-stream");
        req.set(k_forward_time_header, std::to_string(now));
        req.set(k_forward_mac_header, forward_mac(_config.secret, now, op));
        req.body() = op;
        req.prepare_payload();
        return req;
    }

    [[nodiscard]] static auto answer(const response& res) -> std::optional<std::string> {
        if (res.result() != boost::beast::http::status::ok) {
            return std::nullopt;
        }
        return res.body();
    }

    /// Connects `stream` to `peer` through the bounded resolver, not
    /// Asio's. Asio's resolver is a bare getaddrinfo() on every op, and
    /// under rootless Podman aardvark-dns can sit on a lookup for tens of
    /// seconds: while it forwards some other container's name upstream it
    /// answers nothing else on the network, peer gateways' names included
    /// (bounded_resolver.hpp has the measurements). Every forward then
    /// fails until the stall clears, and `raft_backend` reports "no leader
    /// answered before the deadline" even when the leader is healthy. The
    /// Podman conformance run of 2026-11-14 shows that symptom: Terraform's
    /// first PutItem took 41 s and answered two 500s, which never happened
    /// under Docker, whose DNS does not stall. The bounded resolver
    /// hands out the last answer at once and refreshes it in the
    /// background, and is told when a dial fails so a peer that moved is
    /// looked up again rather than dialled at its old address.
    void connect(boost::beast::tcp_stream& stream, const forward_peer& peer) const {
        const auto service = std::to_string(peer.port);
        const auto dialled_at = std::chrono::steady_clock::now();
        const auto addresses =
            net_resolve::resolve(peer.host, service, SOCK_STREAM, _config.timeout);
        if (!addresses || addresses->empty()) {
            throw std::runtime_error("peer gateway " + peer.host + " did not resolve");
        }
        std::vector<boost::asio::ip::tcp::endpoint> endpoints;
        endpoints.reserve(addresses->size());
        for (const auto& a : *addresses) {
            boost::asio::ip::tcp::endpoint ep;
            if (a.len > ep.capacity()) {
                continue;
            }
            std::memcpy(ep.data(), &a.addr, a.len);
            ep.resize(a.len);
            endpoints.push_back(ep);
        }
        try {
            stream.connect(endpoints);
        } catch (...) {
            net_resolve::mark_unreachable(peer.host, service, SOCK_STREAM, dialled_at);
            throw;
        }
    }

    [[nodiscard]] auto exchange_plain(const forward_peer& peer, const std::string& op) const
        -> std::optional<std::string> {
        namespace beast = boost::beast;
        namespace http = beast::http;
        boost::asio::io_context ioc;
        beast::tcp_stream stream(ioc);
        stream.expires_after(_config.timeout);
        connect(stream, peer);
        http::write(stream, make_request(peer, op));
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(k_max_answer_bytes);
        http::read(stream, buffer, parser);
        beast::error_code ec;
        (void)stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        return answer(parser.get());
    }

    [[nodiscard]] auto exchange_tls(const forward_peer& peer, const std::string& op) const
        -> std::optional<std::string> {
        namespace beast = boost::beast;
        namespace http = beast::http;
        namespace ssl = boost::asio::ssl;
        boost::asio::io_context ioc;
        ssl::context ctx(ssl::context::tls_client);
        if (_config.ca_path.empty()) {
            ctx.set_default_verify_paths();
        } else {
            ctx.load_verify_file(_config.ca_path);
        }
        ctx.set_verify_mode(ssl::verify_peer);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
        if (SSL_set_tlsext_host_name(stream.native_handle(), peer.host.c_str()) != 1) {
            return std::nullopt;
        }
        stream.set_verify_callback(ssl::host_name_verification(peer.host));
        beast::get_lowest_layer(stream).expires_after(_config.timeout);
        connect(beast::get_lowest_layer(stream), peer);
        stream.handshake(ssl::stream_base::client);
        http::write(stream, make_request(peer, op));
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(k_max_answer_bytes);
        http::read(stream, buffer, parser);
        // The answer is already read; a peer that drops the connection
        // without close_notify costs nothing here, so the result is ignored.
        beast::error_code ec;
        (void)stream.shutdown(ec);
        return answer(parser.get());
    }

    /// A page carries at most about 1 MiB of items; leave room.
    static constexpr std::uint64_t k_max_answer_bytes = std::uint64_t{32} << 20U;

    forward_client_config _config;
    std::map<std::string, forward_peer> _peers;
};

}  // namespace kythira::dynamodb
