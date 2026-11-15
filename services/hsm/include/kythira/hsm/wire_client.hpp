// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The client side of the wire protocol (.kiro/specs/virtual-hsm/ task 9):
// a connection to a node over mutual TLS 1.3 or a Unix socket, and
// wire_client, whose calls are native_client's, each one request. The
// PKCS#11 library (task 10) is built on these; so are the tests.
//
// It depends on OpenSSL and the protocol header only, not on the session
// layer, so the library stays small. A call whose exchange fails (the
// connection broke, a timeout, an unreadable answer) answers
// CKR_DEVICE_ERROR and sets transport_failed(), which the library uses to
// reconnect and re-login (requirement 5.5).

#include <kythira/hsm/wire.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::hsm::wire {

struct tls_client_config {
    std::string host;
    std::uint16_t port = 9444;
    /// The client's certificate chain and key: its identity.
    std::string cert_path;
    std::string key_path;
    /// The CA the node's certificate chains to; the certificate must also
    /// name `host` (a DNS or IP SAN).
    std::string ca_path;
    /// The OpenSSL library context the connection's TLS runs in; null for
    /// the process default. libkythira_pkcs11.so passes its own, so the
    /// host application's OpenSSL configuration (which may load
    /// pkcs11-provider over this very library) never reaches it.
    OSSL_LIB_CTX* libctx = nullptr;
};

/// One connection to a node.
class connection {
public:
    /// Each read and write may take this long; an operation that waits for
    /// a Raft commit (key generation, a destroy) needs a few seconds.
    static constexpr std::chrono::seconds default_timeout{30};

    explicit connection(std::unique_ptr<stream> s,
                        std::uint32_t max_frame_bytes = default_max_frame_bytes)
        : _stream(std::move(s)), _max_frame_bytes(max_frame_bytes) {}

    /// Connects to a node's Unix socket; nothing when it cannot.
    [[nodiscard]] static auto unix_socket(const std::string& path,
                                          std::chrono::seconds timeout = default_timeout)
        -> std::unique_ptr<connection> {
        sockaddr_un addr{};
        if (path.empty() || path.size() >= sizeof addr.sun_path) {
            return nullptr;
        }
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return nullptr;
        }
        set_timeouts(fd, timeout);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
            ::close(fd);
            return nullptr;
        }
        return std::make_unique<connection>(std::make_unique<fd_stream>(fd));
    }

    /// Connects to a node's TLS listener and completes the handshake;
    /// nothing when the node cannot be reached or its certificate is not
    /// the CA's for `host`.
    [[nodiscard]] static auto tls(const tls_client_config& config,
                                  std::chrono::seconds timeout = default_timeout)
        -> std::unique_ptr<connection> {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
            SSL_CTX_new_ex(config.libctx, nullptr, TLS_client_method()), &SSL_CTX_free);
        if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_load_verify_locations(ctx.get(), config.ca_path.c_str(), nullptr) != 1 ||
            SSL_CTX_use_certificate_chain_file(ctx.get(), config.cert_path.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx.get(), config.key_path.c_str(), SSL_FILETYPE_PEM) !=
                1 ||
            SSL_CTX_check_private_key(ctx.get()) != 1) {
            ERR_clear_error();
            return nullptr;
        }
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        const int fd = dial(config.host, config.port, timeout);
        if (fd < 0) {
            return nullptr;
        }
        SSL* ssl = SSL_new(ctx.get());
        if (ssl == nullptr || !name_peer(ssl, config.host) || !attach_socket(ssl, fd) ||
            SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK) {
            ERR_clear_error();
            if (ssl != nullptr) {
                SSL_free(ssl);
            }
            ::close(fd);
            return nullptr;
        }
        return std::make_unique<connection>(std::make_unique<tls_stream>(ssl, fd));
    }

    /// Sends one request and reads its response; nothing when either
    /// fails, after which the connection is useless.
    auto round_trip(std::span<const std::byte> request) -> std::optional<std::vector<std::byte>> {
        if (!_stream || !write_frame(*_stream, request)) {
            _stream.reset();
            return std::nullopt;
        }
        auto response = read_frame(*_stream, _max_frame_bytes);
        if (!response) {
            _stream.reset();
        }
        return response;
    }

    [[nodiscard]] auto open() const noexcept -> bool { return _stream != nullptr; }

private:
    static void set_timeouts(int fd, std::chrono::seconds t) {
        timeval tv{};
        tv.tv_sec = static_cast<decltype(tv.tv_sec)>(t.count());
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    /// A connected TCP socket to the first address of `host` that
    /// answers, or -1. Linux bounds connect() by SO_SNDTIMEO.
    static auto dial(const std::string& host, std::uint16_t port, std::chrono::seconds timeout)
        -> int {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* found = nullptr;
        if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &found) != 0) {
            return -1;
        }
        const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(found, &freeaddrinfo);
        for (const addrinfo* a = found; a != nullptr; a = a->ai_next) {
            const int fd = ::socket(a->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0) {
                continue;
            }
            set_timeouts(fd, timeout);
            const int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
                return fd;
            }
            ::close(fd);
        }
        return -1;
    }

    /// The name the node's certificate must carry: an IP SAN for an
    /// address, else a DNS SAN (also sent as SNI).
    static auto name_peer(SSL* ssl, const std::string& host) -> bool {
        in6_addr probe{};
        const bool is_ip = ::inet_pton(AF_INET, host.c_str(), &probe) == 1 ||
                           ::inet_pton(AF_INET6, host.c_str(), &probe) == 1;
        if (is_ip) {
            return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host.c_str()) == 1;
        }
        return SSL_set1_host(ssl, host.c_str()) == 1 &&
               SSL_set_tlsext_host_name(ssl, host.c_str()) == 1;
    }

    std::unique_ptr<stream> _stream;
    std::uint32_t _max_frame_bytes;
};

}  // namespace kythira::hsm::wire

namespace kythira::hsm {

/// What hello answers.
struct wire_hello {
    std::uint8_t version = 0;
    std::uint32_t max_frame_bytes = 0;
    /// The identity the node authenticated this connection as.
    std::string identity;
};

/// native_client's calls over the wire. Not thread-safe: one call at a
/// time, as one connection carries one call at a time.
class wire_client {
public:
    using bytes = std::vector<std::uint8_t>;
    /// Sends a request and returns its response, or nothing on failure.
    using round_trip_fn =
        std::function<std::optional<std::vector<std::byte>>(std::span<const std::byte>)>;

    explicit wire_client(round_trip_fn round_trip) : _round_trip(std::move(round_trip)) {}

    /// Over a connection, which the client keeps.
    explicit wire_client(std::unique_ptr<wire::connection> c)
        : _connection(std::move(c)), _round_trip([this](std::span<const std::byte> req) {
              return _connection ? _connection->round_trip(req) : std::nullopt;
          }) {}

    wire_client(const wire_client&) = delete;
    auto operator=(const wire_client&) -> wire_client& = delete;
    wire_client(wire_client&&) = delete;
    auto operator=(wire_client&&) -> wire_client& = delete;
    ~wire_client() = default;

    /// True once an exchange has failed; every later call fails too.
    [[nodiscard]] auto transport_failed() const noexcept -> bool { return _failed; }

    auto hello() -> ck_result<wire_hello> {
        auto req = wire::request(wire::op::hello);
        return call<wire_hello>(req, [](byte_reader& r) {
            wire_hello h;
            h.version = r.u8();
            h.max_frame_bytes = r.u32();
            h.identity = r.str();
            return h;
        });
    }

    auto get_slot_list() -> ck_result<std::vector<CK_SLOT_ID>> {
        auto req = wire::request(wire::op::get_slot_list);
        return call<std::vector<CK_SLOT_ID>>(req,
                                             [](byte_reader& r) { return wire::get_ulongs(r); });
    }
    auto get_token_info(CK_SLOT_ID slot) -> ck_result<token_info> {
        auto req = wire::request(wire::op::get_token_info);
        req.u64(slot);
        return call<token_info>(req, [](byte_reader& r) { return wire::get_token_info(r); });
    }
    auto init_token(CK_SLOT_ID slot, std::string_view so_pin, std::string_view label)
        -> ck_result<void> {
        auto req = wire::request(wire::op::init_token);
        req.u64(slot).str(so_pin).str(label);
        return call<void>(req);
    }

    auto open_session(CK_SLOT_ID slot, CK_FLAGS flags) -> ck_result<CK_SESSION_HANDLE> {
        auto req = wire::request(wire::op::open_session);
        req.u64(slot).u64(flags);
        return call<CK_SESSION_HANDLE>(req, read_handle);
    }
    auto close_session(CK_SESSION_HANDLE s) -> ck_result<void> {
        return simple(wire::op::close_session, s);
    }
    auto close_all_sessions(CK_SLOT_ID slot) -> ck_result<void> {
        return simple(wire::op::close_all_sessions, slot);
    }
    auto get_session_info(CK_SESSION_HANDLE s) -> ck_result<session_info> {
        auto req = wire::request(wire::op::get_session_info);
        req.u64(s);
        return call<session_info>(req, [](byte_reader& r) { return wire::get_session_info(r); });
    }

    auto login(CK_SESSION_HANDLE s, CK_USER_TYPE user, std::string_view pin) -> ck_result<void> {
        auto req = wire::request(wire::op::login);
        req.u64(s).u64(user).str(pin);
        return call<void>(req);
    }
    auto logout(CK_SESSION_HANDLE s) -> ck_result<void> { return simple(wire::op::logout, s); }
    auto init_pin(CK_SESSION_HANDLE s, std::string_view pin) -> ck_result<void> {
        auto req = wire::request(wire::op::init_pin);
        req.u64(s).str(pin);
        return call<void>(req);
    }
    auto set_pin(CK_SESSION_HANDLE s, std::string_view old_pin, std::string_view new_pin)
        -> ck_result<void> {
        auto req = wire::request(wire::op::set_pin);
        req.u64(s).str(old_pin).str(new_pin);
        return call<void>(req);
    }

    auto generate_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto req = wire::request(wire::op::generate_key);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        wire::put_attributes(req, tmpl);
        return call<CK_OBJECT_HANDLE>(req, read_handle);
    }
    auto generate_key_pair(CK_SESSION_HANDLE s, const CK_MECHANISM& m,
                           const attribute_map& public_tmpl, const attribute_map& private_tmpl)
        -> ck_result<std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>> {
        auto req = wire::request(wire::op::generate_key_pair);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        wire::put_attributes(req, public_tmpl);
        wire::put_attributes(req, private_tmpl);
        return call<std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>>(req, [](byte_reader& r) {
            const auto pub = static_cast<CK_OBJECT_HANDLE>(r.u64());
            const auto priv = static_cast<CK_OBJECT_HANDLE>(r.u64());
            return std::pair{pub, priv};
        });
    }
    auto destroy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o) -> ck_result<void> {
        auto req = wire::request(wire::op::destroy_object);
        req.u64(s).u64(o);
        return call<void>(req);
    }
    auto get_attribute_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o,
                             std::span<const CK_ATTRIBUTE_TYPE> types)
        -> ck_result<std::vector<attribute_value>> {
        auto req = wire::request(wire::op::get_attribute_value);
        req.u64(s).u64(o);
        wire::put_ulongs(req, types);
        return call<std::vector<attribute_value>>(
            req, [](byte_reader& r) { return wire::get_attribute_values(r); });
    }
    auto set_attribute_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, const attribute_map& changes)
        -> ck_result<void> {
        auto req = wire::request(wire::op::set_attribute_value);
        req.u64(s).u64(o);
        wire::put_attributes(req, changes);
        return call<void>(req);
    }
    auto create_object(CK_SESSION_HANDLE s, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto req = wire::request(wire::op::create_object);
        req.u64(s);
        wire::put_attributes(req, tmpl);
        return call<CK_OBJECT_HANDLE>(req, read_handle);
    }
    auto copy_object(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto req = wire::request(wire::op::copy_object);
        req.u64(s).u64(o);
        wire::put_attributes(req, tmpl);
        return call<CK_OBJECT_HANDLE>(req, read_handle);
    }
    auto wrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE wrapping_key,
                  CK_OBJECT_HANDLE key) -> ck_result<bytes> {
        auto req = wire::request(wire::op::wrap_key);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        req.u64(wrapping_key).u64(key);
        return call<bytes>(req, read_bytes);
    }
    auto unwrap_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE unwrapping_key,
                    std::span<const std::uint8_t> wrapped, const attribute_map& tmpl)
        -> ck_result<CK_OBJECT_HANDLE> {
        auto req = wire::request(wire::op::unwrap_key);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        req.u64(unwrapping_key).bytes(wrapped);
        wire::put_attributes(req, tmpl);
        return call<CK_OBJECT_HANDLE>(req, read_handle);
    }
    auto derive_key(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE base_key,
                    const attribute_map& tmpl) -> ck_result<CK_OBJECT_HANDLE> {
        auto req = wire::request(wire::op::derive_key);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        req.u64(base_key);
        wire::put_attributes(req, tmpl);
        return call<CK_OBJECT_HANDLE>(req, read_handle);
    }
    auto find_objects_init(CK_SESSION_HANDLE s, const attribute_map& tmpl) -> ck_result<void> {
        auto req = wire::request(wire::op::find_objects_init);
        req.u64(s);
        wire::put_attributes(req, tmpl);
        return call<void>(req);
    }
    auto find_objects(CK_SESSION_HANDLE s, std::size_t max)
        -> ck_result<std::vector<CK_OBJECT_HANDLE>> {
        auto req = wire::request(wire::op::find_objects);
        req.u64(s).u64(max);
        return call<std::vector<CK_OBJECT_HANDLE>>(
            req, [](byte_reader& r) { return wire::get_ulongs(r); });
    }
    auto session_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) -> ck_result<void> {
        auto req = wire::request(wire::op::session_cancel);
        req.u64(s).u64(flags);
        return call<void>(req);
    }
    auto find_objects_final(CK_SESSION_HANDLE s) -> ck_result<void> {
        return simple(wire::op::find_objects_final, s);
    }

    auto sign_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return op_init(wire::op::sign_init, s, m, key);
    }
    auto sign(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return data_call<bytes>(wire::op::sign, s, data);
    }
    auto sign_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return data_call<void>(wire::op::sign_update, s, data);
    }
    auto sign_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        auto req = wire::request(wire::op::sign_final);
        req.u64(s);
        return call<bytes>(req, read_bytes);
    }

    auto verify_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return op_init(wire::op::verify_init, s, m, key);
    }
    auto verify(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data,
                std::span<const std::uint8_t> signature) -> ck_result<void> {
        auto req = wire::request(wire::op::verify);
        req.u64(s).bytes(data).bytes(signature);
        return call<void>(req);
    }
    auto verify_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return data_call<void>(wire::op::verify_update, s, data);
    }
    auto verify_final(CK_SESSION_HANDLE s, std::span<const std::uint8_t> signature)
        -> ck_result<void> {
        auto req = wire::request(wire::op::verify_final);
        req.u64(s).bytes(signature);
        return call<void>(req);
    }

    auto encrypt_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return op_init(wire::op::encrypt_init, s, m, key);
    }
    auto encrypt(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return data_call<bytes>(wire::op::encrypt, s, data);
    }
    auto encrypt_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<void> {
        return data_call<void>(wire::op::encrypt_update, s, data);
    }
    auto encrypt_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        auto req = wire::request(wire::op::encrypt_final);
        req.u64(s);
        return call<bytes>(req, read_bytes);
    }

    auto decrypt_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        return op_init(wire::op::decrypt_init, s, m, key);
    }
    /// The plaintext is the caller's to wipe.
    auto decrypt(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return data_call<bytes>(wire::op::decrypt, s, data);
    }
    auto decrypt_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<void> {
        return data_call<void>(wire::op::decrypt_update, s, data);
    }
    auto decrypt_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        auto req = wire::request(wire::op::decrypt_final);
        req.u64(s);
        return call<bytes>(req, read_bytes);
    }

    auto digest_init(CK_SESSION_HANDLE s, const CK_MECHANISM& m) -> ck_result<void> {
        auto req = wire::request(wire::op::digest_init);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        return call<void>(req);
    }
    auto digest(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<bytes> {
        return data_call<bytes>(wire::op::digest, s, data);
    }
    auto digest_update(CK_SESSION_HANDLE s, std::span<const std::uint8_t> data) -> ck_result<void> {
        return data_call<void>(wire::op::digest_update, s, data);
    }
    auto digest_final(CK_SESSION_HANDLE s) -> ck_result<bytes> {
        auto req = wire::request(wire::op::digest_final);
        req.u64(s);
        return call<bytes>(req, read_bytes);
    }

    auto generate_random(CK_SESSION_HANDLE s, std::size_t length) -> ck_result<bytes> {
        auto req = wire::request(wire::op::generate_random);
        req.u64(s).u64(length);
        return call<bytes>(req, read_bytes);
    }

    auto get_mechanism_list(CK_SLOT_ID slot) -> ck_result<std::vector<CK_MECHANISM_TYPE>> {
        auto req = wire::request(wire::op::get_mechanism_list);
        req.u64(slot);
        return call<std::vector<CK_MECHANISM_TYPE>>(
            req, [](byte_reader& r) { return wire::get_ulongs(r); });
    }
    auto get_mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE type)
        -> ck_result<CK_MECHANISM_INFO> {
        auto req = wire::request(wire::op::get_mechanism_info);
        req.u64(slot).u64(type);
        return call<CK_MECHANISM_INFO>(req, [](byte_reader& r) {
            CK_MECHANISM_INFO i{};
            i.ulMinKeySize = static_cast<CK_ULONG>(r.u64());
            i.ulMaxKeySize = static_cast<CK_ULONG>(r.u64());
            i.flags = static_cast<CK_FLAGS>(r.u64());
            return i;
        });
    }

private:
    static auto read_handle(byte_reader& r) -> CK_ULONG { return static_cast<CK_ULONG>(r.u64()); }
    static auto read_bytes(byte_reader& r) -> bytes { return r.bytes(); }

    auto simple(wire::op o, CK_ULONG arg) -> ck_result<void> {
        auto req = wire::request(o);
        req.u64(arg);
        return call<void>(req);
    }

    auto op_init(wire::op o, CK_SESSION_HANDLE s, const CK_MECHANISM& m, CK_OBJECT_HANDLE key)
        -> ck_result<void> {
        auto req = wire::request(o);
        req.u64(s);
        if (const auto rv = wire::put_mechanism(req, m); rv != CKR_OK) {
            return unexpected(rv);
        }
        req.u64(key);
        return call<void>(req);
    }

    template<class T>
    auto data_call(wire::op o, CK_SESSION_HANDLE s, std::span<const std::uint8_t> data)
        -> ck_result<T> {
        auto req = wire::request(o);
        req.reserve(data.size() + 32);
        req.u64(s).bytes(data);
        if constexpr (std::is_void_v<T>) {
            return call<void>(req);
        } else {
            return call<T>(req, read_bytes);
        }
    }

    template<class T, class Parse = std::nullptr_t>
    auto call(byte_writer& req, Parse parse = nullptr) -> ck_result<T> {
        if (_failed) {
            return unexpected(CKR_DEVICE_ERROR);
        }
        std::optional<std::vector<std::byte>> got;
        {
            const wire::wiped_buffer request(req.take());
            got = _round_trip(request.bytes);
        }
        if (!got) {
            _failed = true;
            return unexpected(CKR_DEVICE_ERROR);
        }
        const wire::wiped_buffer response(std::move(*got));
        try {
            byte_reader r(response.bytes);
            const auto rv = static_cast<CK_RV>(r.u64());
            if (rv != CKR_OK) {
                return unexpected(rv);
            }
            if constexpr (std::is_void_v<T>) {
                r.finish();
                return {};
            } else {
                T value = parse(r);
                r.finish();
                return value;
            }
        } catch (const std::invalid_argument&) {
            _failed = true;
            return unexpected(CKR_DEVICE_ERROR);
        }
    }

    std::unique_ptr<wire::connection> _connection;
    round_trip_fn _round_trip;
    bool _failed = false;
};

}  // namespace kythira::hsm
