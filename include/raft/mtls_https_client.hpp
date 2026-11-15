// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

/// @file mtls_https_client.hpp
/// @brief One blocking HTTPS request with a client certificate: how a
///        member of a module's cluster forwards to its leader (the virtual
///        HSM's hsm_peer.hpp, the KMS's kms_peer.hpp) and how an operator
///        tool reaches a node's API. TLS 1.3 only; the server's certificate
///        must chain to `ca_path` and name the host dialled. Plain HTTP is
///        for tests and must be asked for. It depends on Boost.Beast and
///        OpenSSL only, so a command line does not pull in the Raft host.
///
/// Moved here from services/hsm/ (virtual-hsm task 6d) when the KMS needed
/// the same client (kms-compatible-api task 12).

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/ssl.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kythira::mtls {

struct client_config {
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
    /// Present `cert_path` and `key_path`. Off for a client that
    /// authenticates otherwise (SigV4 to an AWS-style listener), which
    /// still verifies the server against `ca_path`.
    bool client_certificate = true;
};

/// One blocking HTTPS request per call, with this side's certificate:
/// TLS 1.3 only, the server's certificate checked against `ca_path` and
/// the host dialled.
class client {
public:
    explicit client(client_config config) : _config(std::move(config)) {}

    /// The status and body, or nothing when the exchange failed (bad URL,
    /// no connection, a handshake or I/O error, a timeout). `base_url` is
    /// "https://host:port" ("http://" only with `plaintext`).
    [[nodiscard]] auto request(std::string_view method, std::string_view base_url,
                               const std::string& target, std::string body,
                               std::string_view content_type, std::string_view agent) const
        -> std::optional<std::pair<unsigned, std::string>> {
        return request(method, base_url, target, std::move(body), content_type, agent, {});
    }

    /// The same, with `headers` added to the request (`Host`,
    /// `Content-Type` and `User-Agent` are set from the other arguments).
    [[nodiscard]] auto request(
        std::string_view method, std::string_view base_url, const std::string& target,
        std::string body, std::string_view content_type, std::string_view agent,
        const std::vector<std::pair<std::string, std::string>>& headers) const
        -> std::optional<std::pair<unsigned, std::string>> {
        const auto e = parse(base_url);
        if (!e || e->tls == _config.plaintext) {
            return std::nullopt;  // a plaintext URL needs plaintext asked for, and the reverse
        }
        try {
            namespace http = boost::beast::http;
            http::request<http::string_body> req{http::string_to_verb(method), target, 11};
            req.set(http::field::host, e->host + ":" + e->port);
            req.set(http::field::user_agent, agent);
            req.set(http::field::content_type, content_type);
            for (const auto& [name, value] : headers) {
                req.set(name, value);
            }
            req.body() = std::move(body);
            req.prepare_payload();
            return e->tls ? exchange_tls(*e, req) : exchange_plain(*e, req);
        } catch (const std::exception&) {
            return std::nullopt;
        }
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
        if (_config.ca_path.empty() || (_config.client_certificate &&
                                        (_config.cert_path.empty() || _config.key_path.empty()))) {
            return std::nullopt;  // the server is always verified; members both ways
        }
        ctx.load_verify_file(_config.ca_path);
        if (_config.client_certificate) {
            ctx.use_certificate_chain_file(_config.cert_path);
            ctx.use_private_key_file(_config.key_path, ssl::context::pem);
        }
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

    client_config _config;
};

}  // namespace kythira::mtls
