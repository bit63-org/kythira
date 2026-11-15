// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// How an HSM member reaches the leader of a group over the network
// (.kiro/specs/virtual-hsm/ task 6d): hsm_host's forwarder, carried as two
// HTTPS requests on the module's API listener.
//
//   POST /v1/peer/propose/<local group>      body: the command
//   POST /v1/peer/read-index/<local group>   body: empty
//
// Both answer 200 with an encoded forward_reply (status, applied index,
// the known leader's id as text, the state machine's reply), or 403 to a
// caller that is not a member, 400 to a malformed request.
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
struct peer_policy {
    /// The members' certificate identities (a URI or DNS SAN each).
    std::set<std::string> identities;
    /// Accept peer requests on a plaintext listener (tests only).
    bool allow_plaintext = false;
};

/// What the listener knows of a caller: the verified certificate's SANs.
struct peer_caller {
    bool tls = false;
    bool verified = false;
    std::vector<std::string> uri_sans;
    std::vector<std::string> dns_sans;
};

/// Whether `caller` is a member under `policy`.
[[nodiscard]] inline auto is_member(const peer_policy& policy, const peer_caller& caller) -> bool {
    if (!caller.tls) {
        return policy.allow_plaintext;
    }
    if (!caller.verified) {
        return false;
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

/// An answer to a peer request: the HTTP status and body.
struct peer_answer {
    unsigned status = 0;
    std::string body;
};

/// Answers a peer request on `host`, or nothing when `target` is not a
/// peer path. `to_text` writes the host's node ids.
template<typename HsmHost, typename ToText>
[[nodiscard]] auto serve_peer(HsmHost& host, const peer_policy& policy, const peer_caller& caller,
                              std::string_view method, std::string_view target,
                              std::string_view body, ToText&& to_text)
    -> std::optional<peer_answer> {
    const bool propose = target.starts_with(peer_propose_path);
    if (!propose && !target.starts_with(peer_read_index_path)) {
        return std::nullopt;
    }
    if (!is_member(policy, caller)) {
        return peer_answer{403, "not a member"};
    }
    const auto group = peer_group_of(target, propose ? peer_propose_path : peer_read_index_path);
    if (method != "POST" || !group) {
        return peer_answer{400, "malformed peer request"};
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

struct peer_client_config {
    /// This node's certificate chain and key, presented to the leader.
    std::string cert_path;
    std::string key_path;
    /// The CA the members' certificates chain to.
    std::string ca_path;
    /// Dial plain HTTP (tests only, with the listener's allow_plaintext).
    bool plaintext = false;
    /// The whole exchange: dial, handshake, write, read. A forwarded
    /// proposal waits for its commit, so this exceeds the propose timeout.
    std::chrono::milliseconds timeout{7000};
    std::uint64_t max_body_bytes = std::uint64_t{16} << 20U;
};

/// One blocking request per call to another member's listener. Every
/// failure answers `unavailable`: the caller does not know whether a
/// proposal took effect.
class peer_client {
public:
    explicit peer_client(peer_client_config config) : _config(std::move(config)) {}

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

private:
    struct endpoint {
        bool tls = true;
        std::string host;
        std::string port;
    };

    /// "https://host:port" or "http://host:port", with "[v6]" hosts.
    [[nodiscard]] static auto parse(std::string_view url) -> std::optional<endpoint> {
        endpoint e;
        if (url.starts_with("https://")) {
            url.remove_prefix(8);
        } else if (url.starts_with("http://")) {
            e.tls = false;
            url.remove_prefix(7);
        } else {
            return std::nullopt;
        }
        while (url.ends_with('/')) {
            url.remove_suffix(1);
        }
        std::string_view host;
        std::string_view port;
        if (url.starts_with('[')) {
            const auto close = url.find(']');
            if (close == std::string_view::npos || close + 1 >= url.size() ||
                url[close + 1] != ':') {
                return std::nullopt;
            }
            host = url.substr(1, close - 1);
            port = url.substr(close + 2);
        } else {
            const auto colon = url.rfind(':');
            if (colon == std::string_view::npos) {
                return std::nullopt;
            }
            host = url.substr(0, colon);
            port = url.substr(colon + 1);
        }
        if (host.empty() || port.empty() ||
            port.find_first_not_of("0123456789") != std::string_view::npos) {
            return std::nullopt;
        }
        e.host = host;
        e.port = port;
        return e;
    }

    [[nodiscard]] auto post(std::string_view base_url, const std::string& target,
                            std::string body) const -> forward_reply<std::string> {
        const auto e = parse(base_url);
        if (!e || e->tls == _config.plaintext) {
            return {};  // a plaintext URL needs plaintext asked for, and the reverse
        }
        try {
            namespace http = boost::beast::http;
            http::request<http::string_body> req{http::verb::post, target, 11};
            req.set(http::field::host, e->host + ":" + e->port);
            req.set(http::field::user_agent, "kythira-hsm-peer");
            req.set(http::field::content_type, "application/octet-stream");
            req.body() = std::move(body);
            req.prepare_payload();
            const auto res = e->tls ? exchange_tls(*e, req) : exchange_plain(*e, req);
            if (!res || res->first != 200) {
                return {};
            }
            return decode_forward_reply(res->second);
        } catch (const std::exception&) {
            return {};
        }
    }

    template<typename Stream, typename Request>
    [[nodiscard]] auto send(Stream& stream, const Request& req) const
        -> std::optional<std::pair<unsigned, std::string>> {
        namespace http = boost::beast::http;
        boost::beast::error_code ec;
        http::write(stream, req, ec);
        if (ec) {
            return std::nullopt;
        }
        boost::beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(_config.max_body_bytes);
        http::read(stream, buffer, parser, ec);
        if (ec) {
            return std::nullopt;
        }
        auto res = parser.release();
        return std::pair{res.result_int(), std::move(res.body())};
    }

    template<typename Request>
    [[nodiscard]] auto exchange_plain(const endpoint& e, const Request& req) const
        -> std::optional<std::pair<unsigned, std::string>> {
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::resolver resolver(ioc);
        boost::beast::tcp_stream stream(ioc);
        stream.expires_after(_config.timeout);
        boost::beast::error_code ec;
        const auto endpoints = resolver.resolve(e.host, e.port, ec);
        if (ec) {
            return std::nullopt;
        }
        stream.connect(endpoints, ec);
        if (ec) {
            return std::nullopt;
        }
        auto out = send(stream, req);
        (void)stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        return out;
    }

    template<typename Request>
    [[nodiscard]] auto exchange_tls(const endpoint& e, const Request& req) const
        -> std::optional<std::pair<unsigned, std::string>> {
        namespace ssl = boost::asio::ssl;
        ssl::context ctx(ssl::context::tls_client);
        ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                        ssl::context::no_sslv3 | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);
        SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
        if (_config.ca_path.empty() || _config.cert_path.empty() || _config.key_path.empty()) {
            return std::nullopt;  // members authenticate both ways, always
        }
        ctx.load_verify_file(_config.ca_path);
        ctx.use_certificate_chain_file(_config.cert_path);
        ctx.use_private_key_file(_config.key_path, ssl::context::pem);
        ctx.set_verify_mode(ssl::verify_peer);
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::resolver resolver(ioc);
        boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);
        if (SSL_set_tlsext_host_name(stream.native_handle(), e.host.c_str()) != 1) {
            return std::nullopt;
        }
        stream.set_verify_callback(ssl::host_name_verification(e.host));
        auto& lowest = boost::beast::get_lowest_layer(stream);
        lowest.expires_after(_config.timeout);
        boost::beast::error_code ec;
        const auto endpoints = resolver.resolve(e.host, e.port, ec);
        if (ec) {
            return std::nullopt;
        }
        lowest.connect(endpoints, ec);
        if (ec) {
            return std::nullopt;
        }
        (void)stream.handshake(ssl::stream_base::client, ec);
        if (ec) {
            return std::nullopt;
        }
        auto out = send(stream, req);
        (void)stream.shutdown(ec);
        return out;
    }

    peer_client_config _config;
};

}  // namespace kythira::hsm
