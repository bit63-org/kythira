// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The node side of the client wire protocol (.kiro/specs/virtual-hsm/
// task 9, requirements 2.4 and 8.1-8.3): a mutual TLS 1.3 listener and a
// Unix socket, each connection one PKCS#11 application on this node's
// session layer.
//
// Who a connection is. Over TLS, the client's certificate must chain to
// the configured CA; its identity is the certificate's first URI SAN, or
// its first DNS SAN when it has no URI. A certificate with neither is
// refused. Over the Unix socket, the peer's uid (SO_PEERCRED) must be in
// the allow list, which names the identity that uid acts as; any other
// uid is refused. The identity is what the catalog's bindings name, so a
// connection sees only the tokens bound to it, any other token answering
// CKR_TOKEN_NOT_PRESENT whether or not it exists (the session layer's
// rule), and still needs the token's PIN to log in.
//
// Each connection has its own thread (a PKCS#11 client holds a connection
// for its whole life and makes one call at a time on it), up to
// max_connections; past that a new connection is closed at once. A
// connection idle for idle_timeout is closed, and the client library
// reconnects. A malformed request answers CKR_ARGUMENTS_BAD; a frame
// over the limit ends the connection.

#include <kythira/hsm/mechanisms.hpp>
#include <kythira/hsm/native_client.hpp>
#include <kythira/hsm/session_layer.hpp>
#include <kythira/hsm/wire.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace kythira::hsm {

// --- Dispatch ----------------------------------------------------------------

namespace wire_detail {

inline auto answer(CK_RV rv) -> std::vector<std::byte> {
    byte_writer w;
    w.u64(rv);
    return w.take();
}

inline auto answer(const ck_result<void>& r) -> std::vector<std::byte> {
    return answer(r ? CKR_OK : r.error());
}

template<class T, class Put>
auto answer(const ck_result<T>& r, Put put, std::size_t reserve = 0) -> std::vector<std::byte> {
    if (!r) {
        return answer(r.error());
    }
    byte_writer w;
    w.reserve(reserve);
    w.u64(CKR_OK);
    put(w, *r);
    return w.take();
}

inline auto put_handle(byte_writer& w, CK_ULONG h) -> void {
    w.u64(h);
}

inline auto put_data(byte_writer& w, const std::vector<std::uint8_t>& b) -> void {
    w.bytes(b);
}

/// A template argument, or the CK_RV to answer.
inline auto read_template(byte_reader& r) -> ck_result<attribute_map> {
    return wire::get_attributes(r);
}

}  // namespace wire_detail

/// Answers one request for `client`, the connection's application.
/// `identity` is what hello reports; `max_frame_bytes` bounds the replies
/// a request may ask for (random bytes, object handles).
inline auto wire_dispatch(native_client& client, std::string_view identity,
                          std::span<const std::byte> request, std::uint32_t max_frame_bytes)
    -> std::vector<std::byte> {
    using wire::op;
    using wire_detail::answer;
    using wire_detail::put_data;
    using wire_detail::put_handle;
    const std::size_t max_reply = max_frame_bytes > 64 ? max_frame_bytes - 64 : 0;
    try {
        byte_reader r(request);
        if (r.u8() != wire::protocol_version) {
            // Another protocol version: no call of this one can be read.
            return answer(CKR_DEVICE_ERROR);
        }
        const auto o = static_cast<op>(r.u32());
        wire::mechanism_params mech;
        // Reads the mechanism argument; false (with `rv` set) when it is
        // refused.
        CK_RV mech_rv = CKR_OK;
        auto read_mech = [&] {
            mech_rv = mech.read(r);
            return mech_rv == CKR_OK;
        };
        auto handle = [&] { return static_cast<CK_ULONG>(r.u64()); };
        switch (o) {
            case op::hello: {
                r.finish();
                byte_writer w;
                w.u64(CKR_OK).u8(wire::protocol_version).u32(max_frame_bytes).str(identity);
                return w.take();
            }
            case op::get_slot_list: {
                r.finish();
                byte_writer w;
                w.u64(CKR_OK);
                wire::put_ulongs(w, client.get_slot_list());
                return w.take();
            }
            case op::get_token_info: {
                const auto slot = handle();
                r.finish();
                return answer(client.get_token_info(slot), [](byte_writer& w, const token_info& t) {
                    wire::put_token_info(w, t);
                });
            }
            case op::init_token: {
                const auto slot = handle();
                auto pin = r.str();
                const auto label = r.str();
                r.finish();
                auto rv = answer(client.init_token(slot, pin, label));
                OPENSSL_cleanse(pin.data(), pin.size());
                return rv;
            }
            case op::open_session: {
                const auto slot = handle();
                const auto flags = handle();
                r.finish();
                return answer(client.open_session(slot, flags), put_handle);
            }
            case op::close_session: {
                const auto s = handle();
                r.finish();
                return answer(client.close_session(s));
            }
            case op::close_all_sessions: {
                const auto slot = handle();
                r.finish();
                return answer(client.close_all_sessions(slot));
            }
            case op::get_session_info: {
                const auto s = handle();
                r.finish();
                return answer(
                    client.get_session_info(s),
                    [](byte_writer& w, const session_info& i) { wire::put_session_info(w, i); });
            }
            case op::login: {
                const auto s = handle();
                const auto user = handle();
                auto pin = r.str();
                r.finish();
                auto rv = answer(client.login(s, user, pin));
                OPENSSL_cleanse(pin.data(), pin.size());
                return rv;
            }
            case op::logout: {
                const auto s = handle();
                r.finish();
                return answer(client.logout(s));
            }
            case op::init_pin: {
                const auto s = handle();
                auto pin = r.str();
                r.finish();
                auto rv = answer(client.init_pin(s, pin));
                OPENSSL_cleanse(pin.data(), pin.size());
                return rv;
            }
            case op::set_pin: {
                const auto s = handle();
                auto old_pin = r.str();
                auto new_pin = r.str();
                r.finish();
                auto rv = answer(client.set_pin(s, old_pin, new_pin));
                OPENSSL_cleanse(old_pin.data(), old_pin.size());
                OPENSSL_cleanse(new_pin.data(), new_pin.size());
                return rv;
            }
            case op::generate_key: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.generate_key(s, mech.get(), *t), put_handle);
            }
            case op::generate_key_pair: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                auto pub = wire_detail::read_template(r);
                auto priv = wire_detail::read_template(r);
                r.finish();
                if (!pub || !priv) {
                    return answer(!pub ? pub.error() : priv.error());
                }
                return answer(
                    client.generate_key_pair(s, mech.get(), *pub, *priv),
                    [](byte_writer& w, const auto& pair) { w.u64(pair.first).u64(pair.second); });
            }
            case op::destroy_object: {
                const auto s = handle();
                const auto obj = handle();
                r.finish();
                return answer(client.destroy_object(s, obj));
            }
            case op::get_attribute_value: {
                const auto s = handle();
                const auto obj = handle();
                const auto types = wire::get_ulongs(r);
                r.finish();
                return answer(client.get_attribute_value(s, obj, types),
                              [](byte_writer& w, const std::vector<attribute_value>& v) {
                                  wire::put_attribute_values(w, v);
                              });
            }
            case op::set_attribute_value: {
                const auto s = handle();
                const auto obj = handle();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.set_attribute_value(s, obj, *t));
            }
            case op::create_object: {
                const auto s = handle();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.create_object(s, *t), put_handle);
            }
            case op::copy_object: {
                const auto s = handle();
                const auto obj = handle();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.copy_object(s, obj, *t), put_handle);
            }
            case op::wrap_key: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                const auto wrapping = handle();
                const auto key = handle();
                r.finish();
                return answer(client.wrap_key(s, mech.get(), wrapping, key), put_data);
            }
            case op::unwrap_key: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                const auto unwrapping = handle();
                const auto wrapped = r.bytes();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.unwrap_key(s, mech.get(), unwrapping, wrapped, *t),
                              put_handle);
            }
            case op::derive_key: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                const auto base = handle();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.derive_key(s, mech.get(), base, *t), put_handle);
            }
            case op::find_objects_init: {
                const auto s = handle();
                auto t = wire_detail::read_template(r);
                r.finish();
                if (!t) {
                    return answer(t.error());
                }
                return answer(client.find_objects_init(s, *t));
            }
            case op::find_objects: {
                const auto s = handle();
                const auto max = r.u64();
                r.finish();
                const auto bounded = std::min<std::uint64_t>(max, max_reply / 8);
                return answer(client.find_objects(s, static_cast<std::size_t>(bounded)),
                              [](byte_writer& w, const std::vector<CK_OBJECT_HANDLE>& v) {
                                  wire::put_ulongs(w, v);
                              });
            }
            case op::find_objects_final: {
                const auto s = handle();
                r.finish();
                return answer(client.find_objects_final(s));
            }
            case op::sign_init:
            case op::verify_init:
            case op::encrypt_init:
            case op::decrypt_init: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                const auto key = handle();
                r.finish();
                const auto& m = mech.get();
                switch (o) {
                    case op::sign_init:
                        return answer(client.sign_init(s, m, key));
                    case op::verify_init:
                        return answer(client.verify_init(s, m, key));
                    case op::encrypt_init:
                        return answer(client.encrypt_init(s, m, key));
                    default:
                        return answer(client.decrypt_init(s, m, key));
                }
            }
            case op::digest_init: {
                const auto s = handle();
                if (!read_mech()) {
                    return answer(mech_rv);
                }
                r.finish();
                return answer(client.digest_init(s, mech.get()));
            }
            case op::sign:
            case op::encrypt:
            case op::digest:
            case op::decrypt:
            case op::sign_update:
            case op::verify_update:
            case op::encrypt_update:
            case op::decrypt_update:
            case op::digest_update: {
                const auto s = handle();
                auto data = r.bytes();
                r.finish();
                std::vector<std::byte> out;
                switch (o) {
                    case op::sign:
                        out = answer(client.sign(s, data), put_data);
                        break;
                    case op::encrypt:
                        out = answer(client.encrypt(s, data), put_data);
                        break;
                    case op::digest:
                        out = answer(client.digest(s, data), put_data);
                        break;
                    case op::decrypt:
                        out = answer(
                            client.decrypt(s, data),
                            [](byte_writer& w, const secret_bytes& p) { w.bytes(p.view()); },
                            data.size() + 16);
                        break;
                    case op::sign_update:
                        out = answer(client.sign_update(s, data));
                        break;
                    case op::verify_update:
                        out = answer(client.verify_update(s, data));
                        break;
                    case op::encrypt_update:
                        out = answer(client.encrypt_update(s, data));
                        break;
                    case op::decrypt_update:
                        out = answer(client.decrypt_update(s, data));
                        break;
                    default:
                        out = answer(client.digest_update(s, data));
                        break;
                }
                wire::wipe(data);
                return out;
            }
            case op::verify: {
                const auto s = handle();
                auto data = r.bytes();
                const auto signature = r.bytes();
                r.finish();
                auto out = answer(client.verify(s, data, signature));
                wire::wipe(data);
                return out;
            }
            case op::sign_final:
            case op::encrypt_final:
            case op::digest_final: {
                const auto s = handle();
                r.finish();
                return answer(o == op::sign_final      ? client.sign_final(s)
                              : o == op::encrypt_final ? client.encrypt_final(s)
                                                       : client.digest_final(s),
                              put_data);
            }
            case op::decrypt_final: {
                const auto s = handle();
                r.finish();
                auto result = client.decrypt_final(s);
                const std::size_t n = result ? result->size() : 0;
                return answer(
                    result, [](byte_writer& w, const secret_bytes& p) { w.bytes(p.view()); },
                    n + 16);
            }
            case op::verify_final: {
                const auto s = handle();
                const auto signature = r.bytes();
                r.finish();
                return answer(client.verify_final(s, signature));
            }
            case op::generate_random: {
                const auto s = handle();
                const auto length = r.u64();
                r.finish();
                if (length > max_reply) {
                    return answer(CKR_ARGUMENTS_BAD);
                }
                return answer(client.generate_random(s, static_cast<std::size_t>(length)), put_data,
                              static_cast<std::size_t>(length) + 16);
            }
            case op::get_mechanism_list: {
                // The same list for every slot, so the answer says nothing
                // about which tokens exist.
                (void)handle();
                r.finish();
                std::vector<CK_ULONG> types;
                for (const auto& e : supported_mechanisms()) {
                    types.push_back(e.type);
                }
                byte_writer w;
                w.u64(CKR_OK);
                wire::put_ulongs(w, types);
                return w.take();
            }
            case op::get_mechanism_info: {
                (void)handle();
                const auto type = handle();
                r.finish();
                return answer(mechanism_info(type), [](byte_writer& w, const CK_MECHANISM_INFO& i) {
                    w.u64(i.ulMinKeySize).u64(i.ulMaxKeySize).u64(i.flags);
                });
            }
        }
        return answer(CKR_FUNCTION_NOT_SUPPORTED);
    } catch (const std::invalid_argument&) {
        return answer(CKR_ARGUMENTS_BAD);
    } catch (const std::length_error&) {
        return answer(CKR_ARGUMENTS_BAD);
    } catch (const std::bad_alloc&) {
        return answer(CKR_HOST_MEMORY);
    }
}

// --- Listeners ---------------------------------------------------------------

struct wire_server_config {
    /// The mutual TLS listener; off when `tls_port` is unset.
    std::optional<std::uint16_t> tls_port{9444};
    std::string bind_address{"0.0.0.0"};
    std::string cert_path;
    std::string key_path;
    /// The CA client certificates must chain to.
    std::string ca_path;
    /// The Unix socket; none when empty. It is made mode 0666: the allow
    /// list, not the file's mode, decides who is served.
    std::string socket_path;
    /// uid -> the identity that uid's connections act as.
    std::map<std::uint32_t, std::string> socket_allow;
    std::size_t max_connections{256};
    std::chrono::seconds idle_timeout{3600};
    std::chrono::seconds handshake_timeout{10};
    std::uint32_t max_frame_bytes{wire::default_max_frame_bytes};
};

/// The identity a client certificate names: its first URI SAN, else its
/// first DNS SAN.
inline auto certificate_identity(X509* cert) -> std::optional<std::string> {
    if (cert == nullptr) {
        return std::nullopt;
    }
    auto* names =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr) {
        return std::nullopt;
    }
    std::optional<std::string> uri;
    std::optional<std::string> dns;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* n = sk_GENERAL_NAME_value(names, i);
        const bool is_uri = n->type == GEN_URI;
        if ((is_uri && !uri) || (n->type == GEN_DNS && !dns)) {
            const ASN1_IA5STRING* s = is_uri ? n->d.uniformResourceIdentifier : n->d.dNSName;
            std::string text(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                             static_cast<std::size_t>(ASN1_STRING_length(s)));
            if (text.find('\0') == std::string::npos && !text.empty()) {
                (is_uri ? uri : dns) = std::move(text);
            }
        }
    }
    GENERAL_NAMES_free(names);
    return uri ? uri : dns;
}

class wire_server {
public:
    using log_fn = std::function<void(bool warning, std::string_view message)>;

    struct counters {
        std::uint64_t accepted = 0;
        /// Over max_connections, a failed handshake, no identity, or a
        /// uid not in the allow list.
        std::uint64_t refused = 0;
        std::uint64_t requests = 0;
    };

    wire_server(std::shared_ptr<session_layer> layer, wire_server_config config, log_fn log = {})
        : _layer(std::move(layer)), _config(std::move(config)), _log(std::move(log)) {}

    wire_server(const wire_server&) = delete;
    auto operator=(const wire_server&) -> wire_server& = delete;
    wire_server(wire_server&&) = delete;
    auto operator=(wire_server&&) -> wire_server& = delete;
    ~wire_server() { stop(); }

    /// Binds the listeners and starts accepting. Throws std::runtime_error
    /// naming what failed (a certificate, a bind, the socket path).
    void start() {
        if (::pipe2(_wake.data(), O_CLOEXEC) != 0) {
            throw std::system_error(errno, std::generic_category(), "hsm wire: pipe");
        }
        if (_config.tls_port) {
            _ctx = make_server_context();
            _tls_fd = listen_tcp();
        }
        if (!_config.socket_path.empty()) {
            _unix_fd = listen_unix();
        }
        _running = true;
        _acceptor = std::thread([this] { accept_loop(); });
    }

    /// Stops accepting, ends every connection (a call in progress finishes
    /// first) and removes the socket file.
    void stop() {
        if (!_running.exchange(false)) {
            return;
        }
        const char byte = 0;
        [[maybe_unused]] const auto woke = ::write(_wake[1], &byte, 1);
        if (_acceptor.joinable()) {
            _acceptor.join();
        }
        {
            const std::scoped_lock lock(_mutex);
            for (const auto& c : _connections) {
                if (c->fd >= 0) {
                    ::shutdown(c->fd, SHUT_RDWR);
                }
            }
        }
        for (const auto& c : _connections) {
            if (c->thread.joinable()) {
                c->thread.join();
            }
        }
        _connections.clear();
        for (int* fd : {&_tls_fd, &_unix_fd, &_wake[0], &_wake[1]}) {
            if (*fd >= 0) {
                ::close(*fd);
                *fd = -1;
            }
        }
        if (!_config.socket_path.empty()) {
            ::unlink(_config.socket_path.c_str());
        }
        if (_ctx != nullptr) {
            SSL_CTX_free(_ctx);
            _ctx = nullptr;
        }
    }

    /// The TLS listener's port (tests bind port 0).
    [[nodiscard]] auto tls_port() const -> std::uint16_t { return _bound_port; }

    [[nodiscard]] auto active_connections() const -> std::size_t {
        const std::scoped_lock lock(_mutex);
        return static_cast<std::size_t>(std::count_if(_connections.begin(), _connections.end(),
                                                      [](const auto& c) { return !c->done; }));
    }

    [[nodiscard]] auto stats() const -> counters {
        const std::scoped_lock lock(_mutex);
        return _counters;
    }

private:
    struct connection {
        std::thread thread;
        /// The socket while it is open; -1 once the thread is closing it,
        /// so stop() never shuts down a reused descriptor.
        int fd = -1;
        bool done = false;
    };

    void say(bool warning, const std::string& message) const {
        if (_log) {
            _log(warning, message);
        }
    }

    [[nodiscard]] auto make_server_context() const -> SSL_CTX* {
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (ctx == nullptr) {
            throw std::runtime_error("hsm wire: no TLS context");
        }
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> guard(ctx, &SSL_CTX_free);
        if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
            SSL_CTX_use_certificate_chain_file(ctx, _config.cert_path.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, _config.key_path.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            throw std::runtime_error("hsm wire: cannot load the certificate " + _config.cert_path +
                                     " and key " + _config.key_path);
        }
        if (SSL_CTX_load_verify_locations(ctx, _config.ca_path.c_str(), nullptr) != 1) {
            throw std::runtime_error("hsm wire: cannot load the client CA " + _config.ca_path);
        }
        if (auto* names = SSL_load_client_CA_file(_config.ca_path.c_str())) {
            SSL_CTX_set_client_CA_list(ctx, names);
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(ctx, 0);
        return guard.release();
    }

    auto listen_tcp() -> int {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
        addrinfo* found = nullptr;
        const auto port = std::to_string(*_config.tls_port);
        if (::getaddrinfo(_config.bind_address.c_str(), port.c_str(), &hints, &found) != 0 ||
            found == nullptr) {
            throw std::runtime_error("hsm wire: bad bind address " + _config.bind_address);
        }
        const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(found, &freeaddrinfo);
        const int fd = ::socket(found->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            throw std::system_error(errno, std::generic_category(), "hsm wire: socket");
        }
        const int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (::bind(fd, found->ai_addr, found->ai_addrlen) != 0 || ::listen(fd, 128) != 0) {
            const int e = errno;
            ::close(fd);
            throw std::system_error(
                e, std::generic_category(),
                "hsm wire: cannot listen on " + _config.bind_address + ":" + port);
        }
        sockaddr_storage bound{};
        socklen_t len = sizeof bound;
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
            _bound_port = ntohs(bound.ss_family == AF_INET6
                                    ? reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port
                                    : reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
        }
        return fd;
    }

    auto listen_unix() -> int {
        sockaddr_un addr{};
        if (_config.socket_path.size() >= sizeof addr.sun_path) {
            throw std::runtime_error("hsm wire: socket path too long: " + _config.socket_path);
        }
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, _config.socket_path.c_str(), _config.socket_path.size() + 1);
        // A socket left by an earlier run is removed; any other file is not.
        struct stat st{};
        if (::lstat(_config.socket_path.c_str(), &st) == 0) {
            if (!S_ISSOCK(st.st_mode)) {
                throw std::runtime_error("hsm wire: " + _config.socket_path +
                                         " exists and is not a socket");
            }
            ::unlink(_config.socket_path.c_str());
        }
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            throw std::system_error(errno, std::generic_category(), "hsm wire: socket");
        }
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 ||
            ::chmod(_config.socket_path.c_str(), 0666) != 0 || ::listen(fd, 128) != 0) {
            const int e = errno;
            ::close(fd);
            throw std::system_error(e, std::generic_category(),
                                    "hsm wire: cannot listen on " + _config.socket_path);
        }
        return fd;
    }

    void accept_loop() {
        std::vector<pollfd> fds;
        for (int fd : {_wake[0], _tls_fd, _unix_fd}) {
            if (fd >= 0) {
                fds.push_back({fd, POLLIN, 0});
            }
        }
        while (_running.load()) {
            const int n = ::poll(fds.data(), fds.size(), 1000);
            reap();
            if (n <= 0) {
                continue;
            }
            for (const auto& p : fds) {
                if ((p.revents & POLLIN) == 0 || p.fd == _wake[0]) {
                    continue;
                }
                const int fd = ::accept4(p.fd, nullptr, nullptr, SOCK_CLOEXEC);
                if (fd < 0) {
                    continue;
                }
                admit(fd, p.fd == _tls_fd);
            }
        }
    }

    /// Joins the threads of connections that have ended.
    void reap() {
        std::vector<std::shared_ptr<connection>> ended;
        {
            const std::scoped_lock lock(_mutex);
            for (auto it = _connections.begin(); it != _connections.end();) {
                if ((*it)->done) {
                    ended.push_back(*it);
                    it = _connections.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& c : ended) {
            if (c->thread.joinable()) {
                c->thread.join();
            }
        }
    }

    void admit(int fd, bool tls) {
        std::shared_ptr<connection> c;
        {
            const std::scoped_lock lock(_mutex);
            const auto live = static_cast<std::size_t>(std::count_if(
                _connections.begin(), _connections.end(), [](const auto& x) { return !x->done; }));
            if (live >= _config.max_connections) {
                ++_counters.refused;
                ::close(fd);
                say(true, "hsm wire: refused a connection: max_connections reached");
                return;
            }
            c = std::make_shared<connection>();
            c->fd = fd;
            _connections.push_back(c);
        }
        c->thread = std::thread([this, c, tls] { serve(*c, tls); });
    }

    static void set_timeouts(int fd, std::chrono::seconds t) {
        timeval tv{};
        tv.tv_sec = static_cast<decltype(tv.tv_sec)>(t.count());
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    /// One connection, on its own thread.
    void serve(connection& c, bool tls) {
        const int fd = c.fd;
        std::unique_ptr<wire::stream> s;
        std::optional<std::string> identity;
        if (tls) {
            set_timeouts(fd, _config.handshake_timeout);
            const int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            SSL* ssl = SSL_new(_ctx);
            if (ssl != nullptr && wire::attach_socket(ssl, fd) && SSL_accept(ssl) == 1) {
                X509* peer = SSL_get1_peer_certificate(ssl);
                identity = certificate_identity(peer);
                X509_free(peer);
                if (!identity) {
                    say(true, "hsm wire: refused a client certificate with no URI or DNS SAN");
                }
            }
            ERR_clear_error();
            if (ssl != nullptr) {
                // The stream owns the SSL; this thread closes the
                // descriptor itself, after stop() can no longer see it.
                s = std::make_unique<wire::tls_stream>(ssl, -1);
            }
        } else {
            ucred cred{};
            socklen_t len = sizeof cred;
            if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
                const auto it = _config.socket_allow.find(static_cast<std::uint32_t>(cred.uid));
                if (it != _config.socket_allow.end()) {
                    identity = it->second;
                } else {
                    say(true, "hsm wire: refused uid " + std::to_string(cred.uid) +
                                  " on the socket: not in the allow list");
                }
            }
            s = std::make_unique<wire::fd_stream>(fd, false);
        }
        {
            const std::scoped_lock lock(_mutex);
            if (identity) {
                ++_counters.accepted;
            } else {
                ++_counters.refused;
            }
        }
        if (identity) {
            set_timeouts(fd, _config.idle_timeout);
            run(*s, *identity);
        }
        s.reset();  // close_notify while the descriptor is still open
        {
            const std::scoped_lock lock(_mutex);
            c.fd = -1;
        }
        ::close(fd);
        const std::scoped_lock lock(_mutex);
        c.done = true;
    }

    void run(wire::stream& s, const std::string& identity) {
        native_client client(*_layer, identity);
        while (_running.load()) {
            auto frame = wire::read_frame(s, _config.max_frame_bytes);
            if (!frame) {
                return;
            }
            const wire::wiped_buffer request(std::move(*frame));
            const wire::wiped_buffer response(
                wire_dispatch(client, identity, request.bytes, _config.max_frame_bytes));
            {
                const std::scoped_lock lock(_mutex);
                ++_counters.requests;
            }
            if (!wire::write_frame(s, response.bytes)) {
                return;
            }
        }
    }

    std::shared_ptr<session_layer> _layer;
    wire_server_config _config;
    log_fn _log;
    SSL_CTX* _ctx = nullptr;
    int _tls_fd = -1;
    int _unix_fd = -1;
    std::array<int, 2> _wake{-1, -1};
    std::uint16_t _bound_port = 0;
    std::atomic<bool> _running{false};
    std::thread _acceptor;
    mutable std::mutex _mutex;
    std::list<std::shared_ptr<connection>> _connections;
    counters _counters;
};

}  // namespace kythira::hsm
